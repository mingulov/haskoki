{- | SLH-DSA recipe: the eleventh shape-group recipe.

One header mechanism, @CKM_SLH_DSA@, with the optional
@CK_SIGN_ADDITIONAL_CONTEXT@ parameter shape —
@slhdsa-params\/1@: a hedge word plus a context string. The
struct is OPTIONAL (OASIS v3.2 §SLH-DSA Signature: no
parameter means @CKH_HEDGE_PREFERRED@ with an empty context —
the ML-DSA mirror): missing parameters decode to the default
and validate. All three hedge variants serve (preferred and
required ride the provider default, proven hedged by probe —
the provider exposes no force-hedge param; deterministic sets
the provider @deterministic@ int param), and contexts of
0..255 bytes serve (the FIPS 205 bound); hedge words past 2
and longer contexts refuse at the recipe (@CKR_ARGUMENTS_BAD@
at init).

The parameter set is NOT in the mechanism parameters: it
rides the key (@CKA_PARAMETER_SET@ on the object, the
algorithm OID in the DER), and keygen
(@CKM_SLH_DSA_KEY_PAIR_GEN@) takes no parameter — the set
comes from the public-key template (OASIS v3.2
§SLH-DSA key pair generation).

This module owns the group's canonical codec, parameter
validation, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'slhdsaCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces SLH-DSA parameters via
  'slhdsaRecipeFor' + 'slhdsaParamsValid' (empty passes);
* 'Haskoki.FFI.NativeParams' translates caller-native
  @CK_SIGN_ADDITIONAL_CONTEXT@ images onto 'encodeSlhdsaParams';
* 'Haskoki.Engine.Driver.slhdsaSpecFor' maps the covered
  (mechanism, params, key) triple to its backend
  'Haskoki.Engine.Backend.SigSpec' (the set label comes
  from 'slhdsaLevelOfDer', defaulting to SLH-DSA-SHA2-128s —
  key shape is the backend's call); RecipeSlhDsaSpec pins the
  mapping against this table;
* the synthetic backend's per-set constructions and the
  libcrypto interop vectors execute the bindings pinned here
  (SyntheticSpec, OpenSSLSpec).

Deferred family members (not recipes, named gaps):
@CKM_HASH_SLH_DSA@ plus the 11 hash-specific variants (the
pinned provider refuses an explicit digest for SLH-DSA — no
DIY domain separation; see mechanisms.json honesty notes).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.SlhDsa
  ( SlhdsaHedge (..)
  , SlhdsaRecipe (..)
  , slhdsaRecipes
  , slhdsaRecipeFor
  , slhdsaCodec
  , slhdsaCodecFor
  , encodeSlhdsaParams
  , decodeSlhdsaParams
  , slhdsaParamsValid
  , slhdsaLevelOfDer
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

import Haskoki.Der (slhdsaTable)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The SLH-DSA hedge variants (@CK_HEDGE_TYPE@: 0 preferred, 1
-- required, 2 deterministic-required).
data SlhdsaHedge
  = SlhPreferred
  | SlhRequired
  | SlhDeterministic
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | One SLH-DSA recipe: the mechanism name (pure SLH-DSA binds no
-- digest — the set implies the parameters).
data SlhdsaRecipe = SlhdsaRecipe
  { rslName :: !MechanismName
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: the hedge word plus
-- the context string.
slhdsaCodec :: ParameterCodec
slhdsaCodec = ParameterCodec "slhdsa-params" 1

-- | The codec for one recipe row (uniform across the group).
slhdsaCodecFor :: SlhdsaRecipe -> ParameterCodec
slhdsaCodecFor _ = slhdsaCodec

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
hedgeOfWord :: Int -> Maybe SlhdsaHedge
hedgeOfWord 0 = Just SlhPreferred
hedgeOfWord 1 = Just SlhRequired
hedgeOfWord 2 = Just SlhDeterministic
hedgeOfWord _ = Nothing

-- | The canonical word for a hedge variant.
wordOfHedge :: SlhdsaHedge -> Int
wordOfHedge SlhPreferred = 0
wordOfHedge SlhRequired = 1
wordOfHedge SlhDeterministic = 2

-- | Encode SLH-DSA parameters (total; validation is strict): the
-- hedge word (0/1/2) plus the length-prefixed context string.
encodeSlhdsaParams :: SlhdsaHedge -> ByteString -> ByteString
encodeSlhdsaParams hedge ctx =
  encodeWord64 (wordOfHedge hedge)
    <> encodeWord64 (BS.length ctx) <> ctx

-- | Decode SLH-DSA parameters: empty decodes to the default
-- (preferred, empty context — the struct is optional, so
-- missing parameters mean pure, never refusal); truncation,
-- overrun lengths, non-0/1/2 hedge words, and trailing bytes
-- all fail (never a crash, never a partial read).
decodeSlhdsaParams :: ByteString -> Maybe (SlhdsaHedge, ByteString)
decodeSlhdsaParams bs
  | BS.null bs = Just (SlhPreferred, BS.empty)
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

-- | SLH-DSA parameter validation: any hedge variant with a
-- context of at most 255 bytes (the FIPS 205 bound). Missing
-- parameters validate (empty decodes to the default);
-- overlong contexts and unmapped hedge words are honest
-- refusals — the pinned provider serves neither.
slhdsaParamsValid :: SlhdsaRecipe -> ByteString -> Bool
slhdsaParamsValid _ params = case decodeSlhdsaParams params of
  Just (_, ctx) -> BS.length ctx <= 255
  Nothing -> False

-- | The single covered mechanism.
slhdsaRecipes :: [SlhdsaRecipe]
slhdsaRecipes =
  [ SlhdsaRecipe "CKM_SLH_DSA"
  ]

-- | Resolve a mechanism id to its SLH-DSA recipe, if covered.
slhdsaRecipeFor :: MechanismId -> Maybe SlhdsaRecipe
slhdsaRecipeFor mid =
  case [ r | r <- slhdsaRecipes
           , MechanismId (mustGeneratedId (rslName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing

-- | The SLH-DSA set for DER key bytes: the first
-- 'Haskoki.Der.slhdsaTable' OID found as a substring, table order
-- (the ECDSA precedent: 'ecdsaCurveOfDer').
slhdsaLevelOfDer :: ByteString -> Maybe Text
slhdsaLevelOfDer der = case find hit slhdsaTable of
  Just (name, _, _, _, _, _) -> Just (TE.decodeUtf8 name)
  Nothing -> Nothing
  where
    hit (_, oid, _, _, _, _) = oid `BS.isInfixOf` der
