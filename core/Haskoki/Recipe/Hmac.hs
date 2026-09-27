{- | HMAC-shape recipe: the second shape-group recipe.

Twenty-six header mechanisms share two parameter shapes over the
thirteen digest algorithms: plain @CKM_*_HMAC@ (empty mechanism
parameters, full-width tag) and @CKM_*_HMAC_GENERAL@
(@CK_MAC_GENERAL_PARAMS@: the desired tag length in bytes, tag
truncated to that length). This module owns the group's canonical
codecs, parameter validation, output widths, and mechanism table.
Pure core only.

The @mac-general\/1@ codec carries the length as 8-byte
caller-native little-endian: @CK_MAC_GENERAL_PARAMS@ is a
@CK_ULONG@, and @CK_ULONG@ is platform-native (little-endian on
every platform this design targets; the same convention as
'Haskoki.FFI.Standard.decodeULongLE' for attribute values). An
earlier big-endian revision refused every real caller's
truncated-tag init (the oracle packs a native @CK_ULONG@);
RecipeHmacSpec pins the encoding byte-for-byte.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'hmacCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces per-mechanism HMAC
  parameters via 'hmacRecipeFor' + 'hmacParamsValid';
* 'Haskoki.Engine.Driver.hmacSpecFor' maps covered (mechanism,
  params) pairs to backend 'Haskoki.Engine.Backend.MacSpec's;
  RecipeHmacSpec pins the mapping against this table;
* the synthetic backend's per-algorithm widths and the libcrypto
  KATs execute the widths pinned here (SyntheticSpec, OpenSSLSpec).

Deferred family members (not recipes, named gaps): @CKM_BLAKE2B_*@
(output-length parameter semantics need the base-spec prose; see
source-issues.json GAP-BLAKE2B, shared with the digest holdouts),
@CKM_MD2_HMAC@\/@CKM_MD2_HMAC_GENERAL@ and
@CKM_RIPEMD128_HMAC@\/@CKM_RIPEMD128_HMAC_GENERAL@ (no EVP in the
pinned provider), @CKM_GOSTR3411_HMAC@ (needs an engine, no
provider), @CKM_SHA512_T_HMAC@\/@CKM_SHA512_T_HMAC_GENERAL@
(t-parameter codec pending), @CKM_PBA_SHA1_WITH_SHA1_HMAC@ (a PBA
constructor, not the HMAC shape), and the non-HMAC MACs (CBC-MAC
and protocol-MAC sub-shapes, no engine entry yet).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Hmac
  ( HmacRecipe (..)
  , hmacRecipes
  , hmacRecipeFor
  , hmacPlainCodec
  , hmacGeneralCodec
  , hmacCodecFor
  , encodeMacGeneral
  , decodeMacGeneral
  , hmacParamsValid
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One HMAC recipe: the mechanism name, the full tag width in
-- bytes, whether it takes the GENERAL length parameter, and the
-- per-digest key type name (@CKK_*_HMAC@) the Init key-type matrix
-- permits alongside @CKK_GENERIC_SECRET@.
data HmacRecipe = HmacRecipe
  { hrName :: !MechanismName
  , hrOutLen :: !Int
  , hrGeneral :: !Bool
  , hrKeyType :: !MechanismName
  } deriving (Eq, Show)

-- | The group's canonical parameter codecs: plain HMAC mechanisms
-- take empty mechanism parameters; GENERAL mechanisms take the
-- 8-byte caller-native (little-endian) tag length.
hmacPlainCodec :: ParameterCodec
hmacPlainCodec = ParameterCodec "no-params" 1

hmacGeneralCodec :: ParameterCodec
hmacGeneralCodec = ParameterCodec "mac-general" 1

-- | The codec for one recipe row.
hmacCodecFor :: HmacRecipe -> ParameterCodec
hmacCodecFor r
  | hrGeneral r = hmacGeneralCodec
  | otherwise = hmacPlainCodec

-- | Encode a GENERAL tag length (8-byte caller-native
-- little-endian, the in-memory @CK_ULONG@ shape).
encodeMacGeneral :: Int -> ByteString
encodeMacGeneral n = BS.pack [byte s | s <- [0, 8 .. 56]]
  where
    byte :: Int -> Word8
    byte s = fromIntegral ((n `shiftR` s) .&. 0xff)

-- | Strict decode: exactly 8 bytes, no trailing input, decoded
-- caller-native little-endian (the in-memory @CK_ULONG@ shape).
decodeMacGeneral :: ByteString -> Maybe Int
decodeMacGeneral bs
  | BS.length bs /= 8 = Nothing
  | otherwise = Just (BS.foldr (\b a -> a `shiftL` 8 + fromIntegral b) 0 bs)

-- | HMAC parameter validation: plain rows accept empty parameters
-- only; GENERAL rows accept an in-range length (@1 .. full width@).
hmacParamsValid :: HmacRecipe -> ByteString -> Bool
hmacParamsValid r params
  | hrGeneral r = case decodeMacGeneral params of
      Just n -> n >= 1 && n <= hrOutLen r
      Nothing -> False
  | otherwise = BS.null params

-- | All twenty-eight covered mechanisms with their tag widths:
-- each of the fourteen digest algorithms in plain and GENERAL
-- form (BLAKE2B-512 only — see 'Haskoki.Recipe.Digest').
hmacRecipes :: [HmacRecipe]
hmacRecipes = concatMap expand stems
  where
    expand :: (MechanismName, Int, MechanismName) -> [HmacRecipe]
    expand (stem, width, keyType) =
      [ HmacRecipe ("CKM_" <> stem <> "_HMAC") width False keyType
      , HmacRecipe ("CKM_" <> stem <> "_HMAC_GENERAL") width True keyType
      ]
    stems :: [(MechanismName, Int, MechanismName)]
    stems =
      [ ("BLAKE2B_512", 64, "CKK_BLAKE2B_512_HMAC")
      , ("SHA224", 28, "CKK_SHA224_HMAC")
      , ("SHA256", 32, "CKK_SHA256_HMAC")
      , ("SHA384", 48, "CKK_SHA384_HMAC")
      , ("SHA512", 64, "CKK_SHA512_HMAC")
      , ("SHA512_224", 28, "CKK_SHA512_224_HMAC")
      , ("SHA512_256", 32, "CKK_SHA512_256_HMAC")
      , ("SHA3_224", 28, "CKK_SHA3_224_HMAC")
      , ("SHA3_256", 32, "CKK_SHA3_256_HMAC")
      , ("SHA3_384", 48, "CKK_SHA3_384_HMAC")
      , ("SHA3_512", 64, "CKK_SHA3_512_HMAC")
      , ("SHA_1", 20, "CKK_SHA_1_HMAC")
      , ("MD5", 16, "CKK_MD5_HMAC")
      , ("RIPEMD160", 20, "CKK_RIPEMD160_HMAC")
      ]

-- | Resolve a mechanism id to its HMAC recipe, if covered.
hmacRecipeFor :: MechanismId -> Maybe HmacRecipe
hmacRecipeFor mid =
  case [ r | r <- hmacRecipes
           , MechanismId (mustGeneratedId (hrName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
