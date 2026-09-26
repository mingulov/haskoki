{- | ML-DSA recipe: the tenth shape-group recipe.

One header mechanism, @CKM_ML_DSA@, with the optional
@CK_SIGN_ADDITIONAL_CONTEXT@ parameter shape —
@mldsa-params\/1@: a hedge word plus a context string. The
struct is OPTIONAL (OASIS v3.2 §ML-DSA Signature: no
parameter means @CKH_HEDGE_PREFERRED@ with an empty context —
the opposite of EdDSA): missing parameters decode to the
default and validate. All three hedge variants serve
(preferred and required ride the provider default, proven
hedged by probe — the provider exposes no force-hedge
param; deterministic sets the provider @deterministic@ int
param), and contexts of 0..255 bytes serve (the FIPS 204
bound); hedge words past 2 and longer contexts refuse at the
recipe (@CKR_ARGUMENTS_BAD@ at init).

The parameter set is NOT in the mechanism parameters: it
rides the key (@CKA_PARAMETER_SET@ on the object, the
algorithm OID in the DER), and keygen
(@CKM_ML_DSA_KEY_PAIR_GEN@) takes no parameter — the set
comes from the public-key template (OASIS v3.2
§ML-DSA key pair generation).

This module owns the group's canonical codec, parameter
validation, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'mldsaCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces ML-DSA parameters via
  'mldsaRecipeFor' + 'mldsaParamsValid' (empty passes);
* 'Haskoki.FFI.NativeParams' translates caller-native
  @CK_SIGN_ADDITIONAL_CONTEXT@ images onto 'encodeMldsaParams';
* 'Haskoki.Engine.Driver.mldsaSpecFor' maps the covered
  (mechanism, params, key) triple to its backend
  'Haskoki.Engine.Backend.SigSpec' (the level label comes
  from 'mldsaLevelOfDer', defaulting to ML-DSA-44 — key
  shape is the backend's call); RecipeMlDsaSpec pins the
  mapping against this table;
* the synthetic backend's per-level constructions and the
  libcrypto interop vectors execute the bindings pinned here
  (SyntheticSpec, OpenSSLSpec).

Deferred family members (not recipes, named gaps):
@CKM_HASH_ML_DSA@ plus the 10 hash-specific variants (the
pinned provider refuses an explicit digest for ML-DSA — no
DIY domain separation; see mechanisms.json honesty notes),
@CKM_ML_DSA_EXTERNAL_MU@\/@CKM_ML_DSA_EXTERNAL_MU_GEN@
(absent from the OASIS 3.2 header — out of scope).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.MlDsa
  ( MldsaHedge (..)
  , MldsaRecipe (..)
  , mldsaRecipes
  , mldsaRecipeFor
  , mldsaCodec
  , mldsaCodecFor
  , encodeMldsaParams
  , decodeMldsaParams
  , mldsaParamsValid
  , mldsaLevelOfDer
  , hedgeOfWord
  , wordOfHedge
  ) where

import Data.Bits ((.&.), shiftL, shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (find)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Word (Word8)

import Haskoki.Der (mldsaTable)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The ML-DSA hedge variants (@CK_HEDGE_TYPE@: 0 preferred, 1
-- required, 2 deterministic-required).
data MldsaHedge
  = HedgePreferred
  | HedgeRequired
  | HedgeDeterministic
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | One ML-DSA recipe: the mechanism name (pure ML-DSA binds no
-- digest — the level implies the parameters).
data MldsaRecipe = MldsaRecipe
  { rmlName :: !MechanismName
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: the hedge word plus
-- the context string.
mldsaCodec :: ParameterCodec
mldsaCodec = ParameterCodec "mldsa-params" 1

-- | The codec for one recipe row (uniform across the group).
mldsaCodecFor :: MldsaRecipe -> ParameterCodec
mldsaCodecFor _ = mldsaCodec

-- | Encode one 8-byte big-endian word.
encodeWord64 :: Int -> ByteString
encodeWord64 n = BS.pack [byte s | s <- [56, 48 .. 0]]
  where
    byte :: Int -> Word8
    byte s = fromIntegral ((n `shiftR` s) .&. 0xff)

-- | Decode one 8-byte big-endian word.
decodeWord64 :: ByteString -> Maybe Int
decodeWord64 bs
  | BS.length bs /= 8 = Nothing
  | otherwise = Just (BS.foldl' (\a b -> a `shiftL` 8 + fromIntegral b) 0 bs)

-- | The hedge variant for a canonical word (0/1/2); anything
-- else is unmapped ('Nothing').
hedgeOfWord :: Int -> Maybe MldsaHedge
hedgeOfWord 0 = Just HedgePreferred
hedgeOfWord 1 = Just HedgeRequired
hedgeOfWord 2 = Just HedgeDeterministic
hedgeOfWord _ = Nothing

-- | The canonical word for a hedge variant.
wordOfHedge :: MldsaHedge -> Int
wordOfHedge HedgePreferred = 0
wordOfHedge HedgeRequired = 1
wordOfHedge HedgeDeterministic = 2

-- | Encode ML-DSA parameters (total; validation is strict): the
-- hedge word (0/1/2) plus the length-prefixed context string.
encodeMldsaParams :: MldsaHedge -> ByteString -> ByteString
encodeMldsaParams hedge ctx =
  encodeWord64 (wordOfHedge hedge)
    <> encodeWord64 (BS.length ctx) <> ctx

-- | Decode ML-DSA parameters: empty decodes to the default
-- (preferred, empty context — the struct is optional, so
-- missing parameters mean pure, never refusal); truncation,
-- overrun lengths, non-0/1/2 hedge words, and trailing bytes
-- all fail (never a crash, never a partial read).
decodeMldsaParams :: ByteString -> Maybe (MldsaHedge, ByteString)
decodeMldsaParams bs
  | BS.null bs = Just (HedgePreferred, BS.empty)
  | otherwise = do
      let (w0, r0) = BS.splitAt 8 bs
          (w1, r1) = BS.splitAt 8 r0
      hw <- decodeWord64 w0
      cLen <- decodeWord64 w1
      hedge <- hedgeOfWord hw
      let (ctx, rest) = BS.splitAt cLen r1
      if BS.length ctx /= cLen || not (BS.null rest)
        then Nothing
        else pure (hedge, ctx)

-- | ML-DSA parameter validation: any hedge variant with a
-- context of at most 255 bytes (the FIPS 204 bound). Missing
-- parameters validate (empty decodes to the default);
-- overlong contexts and unmapped hedge words are honest
-- refusals — the pinned provider serves neither.
mldsaParamsValid :: MldsaRecipe -> ByteString -> Bool
mldsaParamsValid _ params = case decodeMldsaParams params of
  Just (_, ctx) -> BS.length ctx <= 255
  Nothing -> False

-- | The single covered mechanism.
mldsaRecipes :: [MldsaRecipe]
mldsaRecipes =
  [ MldsaRecipe "CKM_ML_DSA"
  ]

-- | Resolve a mechanism id to its ML-DSA recipe, if covered.
mldsaRecipeFor :: MechanismId -> Maybe MldsaRecipe
mldsaRecipeFor mid =
  case [ r | r <- mldsaRecipes
           , MechanismId (mustGeneratedId (rmlName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing

-- | The ML-DSA level for DER key bytes: the first
-- 'Haskoki.Der.mldsaTable' OID found as a substring, table order
-- (the ECDSA precedent: 'ecdsaCurveOfDer').
mldsaLevelOfDer :: ByteString -> Maybe Text
mldsaLevelOfDer der = case find hit mldsaTable of
  Just (name, _, _, _, _, _) -> Just (TE.decodeUtf8 name)
  Nothing -> Nothing
  where
    hit (_, oid, _, _, _, _) = oid `BS.isInfixOf` der
