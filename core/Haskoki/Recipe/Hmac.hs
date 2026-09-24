{- | HMAC-shape recipe: the second shape-group recipe.

Twenty-six header mechanisms share two parameter shapes over the
thirteen digest algorithms: plain @CKM_*_HMAC@ (empty mechanism
parameters, full-width tag) and @CKM_*_HMAC_GENERAL@
(@CK_MAC_GENERAL_PARAMS@: the desired tag length in bytes, tag
truncated to that length). This module owns the group's canonical
codecs, parameter validation, output widths, and mechanism table.
Pure core only.

The @mac-general\/1@ codec carries the length as 8-byte big-endian:
the width honors @CK_ULONG@ on the pinned LP64 platform, the byte
order honors the codebase length-encoding convention (cf. the
snapshot version's 'Haskoki.Engine.Synthetic' 32-bit lengths);
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
-- bytes, and whether it takes the GENERAL length parameter.
data HmacRecipe = HmacRecipe
  { hrName :: !MechanismName
  , hrOutLen :: !Int
  , hrGeneral :: !Bool
  } deriving (Eq, Show)

-- | The group's canonical parameter codecs: plain HMAC mechanisms
-- take empty mechanism parameters; GENERAL mechanisms take the
-- 8-byte big-endian tag length.
hmacPlainCodec :: ParameterCodec
hmacPlainCodec = ParameterCodec "no-params" 1

hmacGeneralCodec :: ParameterCodec
hmacGeneralCodec = ParameterCodec "mac-general" 1

-- | The codec for one recipe row.
hmacCodecFor :: HmacRecipe -> ParameterCodec
hmacCodecFor r
  | hrGeneral r = hmacGeneralCodec
  | otherwise = hmacPlainCodec

-- | Encode a GENERAL tag length (8-byte big-endian).
encodeMacGeneral :: Int -> ByteString
encodeMacGeneral n = BS.pack [byte s | s <- [56, 48 .. 0]]
  where
    byte :: Int -> Word8
    byte s = fromIntegral ((n `shiftR` s) .&. 0xff)

-- | Strict decode: exactly 8 bytes, no trailing input.
decodeMacGeneral :: ByteString -> Maybe Int
decodeMacGeneral bs
  | BS.length bs /= 8 = Nothing
  | otherwise = Just (BS.foldl' (\a b -> a `shiftL` 8 + fromIntegral b) 0 bs)

-- | HMAC parameter validation: plain rows accept empty parameters
-- only; GENERAL rows accept an in-range length (@1 .. full width@).
hmacParamsValid :: HmacRecipe -> ByteString -> Bool
hmacParamsValid r params
  | hrGeneral r = case decodeMacGeneral params of
      Just n -> n >= 1 && n <= hrOutLen r
      Nothing -> False
  | otherwise = BS.null params

-- | All twenty-six covered mechanisms with their tag widths: each
-- of the thirteen digest algorithms in plain and GENERAL form.
hmacRecipes :: [HmacRecipe]
hmacRecipes = concatMap expand stems
  where
    expand :: (MechanismName, Int) -> [HmacRecipe]
    expand (stem, width) =
      [ HmacRecipe ("CKM_" <> stem <> "_HMAC") width False
      , HmacRecipe ("CKM_" <> stem <> "_HMAC_GENERAL") width True
      ]
    stems :: [(MechanismName, Int)]
    stems =
      [ ("SHA224", 28)
      , ("SHA256", 32)
      , ("SHA384", 48)
      , ("SHA512", 64)
      , ("SHA512_224", 28)
      , ("SHA512_256", 32)
      , ("SHA3_224", 28)
      , ("SHA3_256", 32)
      , ("SHA3_384", 48)
      , ("SHA3_512", 64)
      , ("SHA_1", 20)
      , ("MD5", 16)
      , ("RIPEMD160", 20)
      ]

-- | Resolve a mechanism id to its HMAC recipe, if covered.
hmacRecipeFor :: MechanismId -> Maybe HmacRecipe
hmacRecipeFor mid =
  case [ r | r <- hmacRecipes
           , MechanismId (mustGeneratedId (hrName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
