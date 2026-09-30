{- | EdDSA recipe: the ninth shape-group recipe.

One header mechanism, @CKM_EDDSA@, with the pure-EdDSA
parameter shape — @eddsa-params\/1@: a prehash flag plus a
context string. The struct is optional (OASIS Table 42:
pure params Not Required; the rc2 oracle registry marks
@param_required=False@): missing parameters decode to pure,
and of the explicit combinations only pure (phFlag clear,
empty context — the only combination the pinned provider
serves) validates.
Non-pure combinations translate to the canonical image and
refuse at the recipe (@CKR_ARGUMENTS_BAD@ at init);
@CKM_XEDDSA@ is not a recipe (no provider equivalent — a
named gap, see mechanisms.json honesty notes).

This module owns the group's canonical codec, parameter
validation, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'eddsaCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces EdDSA parameters via
  'eddsaRecipeFor' + 'eddsaParamsValid';
* 'Haskoki.FFI.NativeParams' translates caller-native
  @CK_EDDSA_PARAMS@ images onto 'encodeEddsaParams';
* 'Haskoki.Engine.Driver.eddsaSpecFor' maps the covered
  (mechanism, params, key) triple to its backend
  'Haskoki.Engine.Backend.SigSpec' (the curve label comes
  from 'eddsaCurveOfDer', defaulting like ECDSA — the RSA
  precedent: the driver checks (mechanism, params), key
  shape is the backend's call); RecipeEddsaSpec pins the
  mapping against this table;
* the synthetic backend's per-curve constructions and the
  libcrypto interop vectors execute the bindings pinned here
  (SyntheticSpec, OpenSSLSpec).

Deferred family members (not recipes, named gaps):
@CKM_XEDDSA@ (no 4.0.2 provider signature entry),
@CKM_ML_DSA@\/@CKM_HASH_ML_DSA@ (later slice) — see
mechanisms.json honesty notes.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Eddsa
  ( EddsaRecipe (..)
  , eddsaRecipes
  , eddsaRecipeFor
  , eddsaCodec
  , eddsaCodecFor
  , encodeEddsaParams
  , decodeEddsaParams
  , eddsaParamsValid
  , eddsaCurveOfDer
  ) where

import Data.Bits ((.&.), shiftL, shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (find)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Word (Word8)

import Haskoki.Der (edwardsTable)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One EdDSA recipe: the mechanism name (pure EdDSA binds no
-- digest — the curve implies the hash).
data EddsaRecipe = EddsaRecipe
  { redName :: !MechanismName
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: the prehash flag plus
-- the context string.
eddsaCodec :: ParameterCodec
eddsaCodec = ParameterCodec "eddsa-params" 1

-- | The codec for one recipe row (uniform across the group).
eddsaCodecFor :: EddsaRecipe -> ParameterCodec
eddsaCodecFor _ = eddsaCodec

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

-- | Encode EdDSA parameters (total; validation is strict): the
-- prehash flag word (0 pure, 1 prehash) plus the
-- length-prefixed context string.
encodeEddsaParams :: Bool -> ByteString -> ByteString
encodeEddsaParams ph ctx =
  encodeWord64 (if ph then 1 else 0)
    <> encodeWord64 (BS.length ctx) <> ctx

-- | Decode EdDSA parameters: empty decodes to pure (NULL
-- means pure per OASIS Table 42); truncation, overrun
-- lengths, non-0/1 flag words, and trailing bytes all fail
-- (never a crash, never a partial read).
decodeEddsaParams :: ByteString -> Maybe (Bool, ByteString)
decodeEddsaParams bs
  | BS.null bs = Just (False, BS.empty)
  | otherwise = do
      let (w0, r0) = BS.splitAt 8 bs
          (w1, r1) = BS.splitAt 8 r0
      ph <- decodeWord64 w0
      cLen <- decodeWord64 w1
      if ph /= 0 && ph /= 1
        then Nothing
        else do
          let (ctx, rest) = BS.splitAt cLen r1
          if BS.length ctx /= cLen || not (BS.null rest)
            then Nothing
            else pure (ph == 1, ctx)

-- | EdDSA parameter validation: pure only (flag clear,
-- empty context), explicit or NULL. Prehash and context are
-- honest refusals — the pinned provider serves neither.
eddsaParamsValid :: EddsaRecipe -> ByteString -> Bool
eddsaParamsValid _ params = case decodeEddsaParams params of
  Just (False, ctx) -> BS.null ctx
  _ -> False

-- | The single covered mechanism.
eddsaRecipes :: [EddsaRecipe]
eddsaRecipes =
  [ EddsaRecipe "CKM_EDDSA"
  ]

-- | Resolve a mechanism id to its EdDSA recipe, if covered.
eddsaRecipeFor :: MechanismId -> Maybe EddsaRecipe
eddsaRecipeFor mid =
  case [ r | r <- eddsaRecipes
           , MechanismId (mustGeneratedId (redName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing

-- | The Edwards curve for DER key bytes: the first
-- 'Haskoki.Der.edwardsTable' OID found as a substring, table order
-- (the ECDSA precedent: 'ecdsaCurveOfDer').
eddsaCurveOfDer :: ByteString -> Maybe Text
eddsaCurveOfDer der = case find hit edwardsTable of
  Just (name, _, _, _) -> Just (TE.decodeUtf8 name)
  Nothing -> Nothing
  where
    hit (_, oid, _, _) = oid `BS.isInfixOf` der
