{- | RSA-PSS recipe: the fifth shape-group recipe.

Ten header mechanisms share the salted parameter shape —
@pss-params\/1@: the hash code, the MGF1 hash code, and the salt
length, three 8-byte big-endian words (the width honors @CK_ULONG@
on the pinned LP64 platform, the byte order honors the codebase
length-encoding convention; RecipePssSpec pins the encoding
byte-for-byte). Digest-bound rows (@CKM_*_RSA_PKCS_PSS@) fix the
hash through the recipe; the generic @CKM_RSA_PKCS_PSS@ row takes
any recipe digest. Salt lengths cover @0..64@ (every digest-length
salt for the bound digests; larger salts are a named gap, never
silently accepted).

The digest codes are a codebase wire convention (documented here,
pinned by the golden test), not PKCS#11 numeric ids: MD5 = 1,
SHA_1 = 2, SHA224 = 3, SHA256 = 4, SHA384 = 5, SHA512 = 6,
SHA3_224 = 7, SHA3_256 = 8, SHA3_384 = 9, SHA3_512 = 10,
RIPEMD160 = 11.

This module owns the group's canonical codec, parameter
validation, digest bindings, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'rsaPssCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces PSS parameters via
  'rsaPssRecipeFor' + 'rsaPssParamsValid';
* 'Haskoki.Engine.Driver.rsaPssSpecFor' maps covered (mechanism,
  params) pairs to backend 'Haskoki.Engine.Backend.SigSpec's;
  RecipePssSpec pins the mapping against this table;
* the synthetic backend's per-digest constructions and the
  libcrypto interop vectors execute the bindings pinned here
  (SyntheticSpec, OpenSSLSpec).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.RsaPss
  ( RsaPssRecipe (..)
  , rsaPssRecipes
  , rsaPssRecipeFor
  , rsaPssCodec
  , rsaPssCodecFor
  , encodePssParams
  , decodePssParams
  , rsaPssParamsValid
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Word (Word8)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One PSS recipe: the mechanism name and the bound digest stem
-- (@Nothing@ for the generic @CKM_RSA_PKCS_PSS@ row).
data RsaPssRecipe = RsaPssRecipe
  { rpName :: !MechanismName
  , rpDigestStem :: !(Maybe Text)
  } deriving (Eq, Show)

-- | The group's canonical parameter codec.
rsaPssCodec :: ParameterCodec
rsaPssCodec = ParameterCodec "pss-params" 1

-- | The codec for one recipe row (uniform across the group).
rsaPssCodecFor :: RsaPssRecipe -> ParameterCodec
rsaPssCodecFor _ = rsaPssCodec

-- | Digest stems onto wire codes (the codebase convention; unknown
-- stems never encode).
pssDigestCode :: Text -> Maybe Int
pssDigestCode stem
  | stem == "MD5" = Just 1
  | stem == "SHA_1" = Just 2
  | stem == "SHA224" = Just 3
  | stem == "SHA256" = Just 4
  | stem == "SHA384" = Just 5
  | stem == "SHA512" = Just 6
  | stem == "SHA3_224" = Just 7
  | stem == "SHA3_256" = Just 8
  | stem == "SHA3_384" = Just 9
  | stem == "SHA3_512" = Just 10
  | stem == "RIPEMD160" = Just 11
  | otherwise = Nothing

-- | Wire codes back onto digest stems.
pssCodeDigest :: Int -> Maybe Text
pssCodeDigest code
  | code == 1 = Just "MD5"
  | code == 2 = Just "SHA_1"
  | code == 3 = Just "SHA224"
  | code == 4 = Just "SHA256"
  | code == 5 = Just "SHA384"
  | code == 6 = Just "SHA512"
  | code == 7 = Just "SHA3_224"
  | code == 8 = Just "SHA3_256"
  | code == 9 = Just "SHA3_384"
  | code == 10 = Just "SHA3_512"
  | code == 11 = Just "RIPEMD160"
  | otherwise = Nothing

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

-- | Encode PSS parameters (unknown stems encode as code 0, which
-- never validates: encoding is total, validation is strict).
encodePssParams :: Text -> Text -> Int -> ByteString
encodePssParams digest mgf salt =
  encodeWord64 (code digest) <> encodeWord64 (code mgf) <> encodeWord64 salt
  where
    code stem = case pssDigestCode stem of
      Just c -> c
      Nothing -> 0

-- | Strict decode: exactly 24 bytes, table codes only. The salt
-- length decodes unbounded here; the recipe bounds it.
decodePssParams :: ByteString -> Maybe (Text, Text, Int)
decodePssParams bs = do
  let (w1, r1) = BS.splitAt 8 bs
      (w2, w3) = BS.splitAt 8 r1
  c1 <- decodeWord64 w1
  c2 <- decodeWord64 w2
  salt <- decodeWord64 w3
  d <- pssCodeDigest c1
  m <- pssCodeDigest c2
  pure (d, m, salt)

-- | Maximum accepted salt length: covers every digest-length salt
-- for the bound digests (up to SHA-512's 64).
pssMaxSalt :: Int
pssMaxSalt = 64

-- | PSS parameter validation: strict 24-byte decoding, the bound
-- digest (generic rows take any recipe digest), a table MGF, and a
-- salt in @0..64@.
rsaPssParamsValid :: RsaPssRecipe -> ByteString -> Bool
rsaPssParamsValid r params = case decodePssParams params of
  Just (d, _m, salt) ->
    salt >= 0 && salt <= pssMaxSalt && case rpDigestStem r of
      Nothing -> True
      Just stem -> d == stem
  Nothing -> False

-- | All ten covered mechanisms with their digest bindings.
rsaPssRecipes :: [RsaPssRecipe]
rsaPssRecipes =
  [ RsaPssRecipe "CKM_RSA_PKCS_PSS" Nothing
  , RsaPssRecipe "CKM_SHA1_RSA_PKCS_PSS" (Just "SHA_1")
  , RsaPssRecipe "CKM_SHA224_RSA_PKCS_PSS" (Just "SHA224")
  , RsaPssRecipe "CKM_SHA256_RSA_PKCS_PSS" (Just "SHA256")
  , RsaPssRecipe "CKM_SHA384_RSA_PKCS_PSS" (Just "SHA384")
  , RsaPssRecipe "CKM_SHA512_RSA_PKCS_PSS" (Just "SHA512")
  , RsaPssRecipe "CKM_SHA3_224_RSA_PKCS_PSS" (Just "SHA3_224")
  , RsaPssRecipe "CKM_SHA3_256_RSA_PKCS_PSS" (Just "SHA3_256")
  , RsaPssRecipe "CKM_SHA3_384_RSA_PKCS_PSS" (Just "SHA3_384")
  , RsaPssRecipe "CKM_SHA3_512_RSA_PKCS_PSS" (Just "SHA3_512")
  ]

-- | Resolve a mechanism id to its PSS recipe, if covered.
rsaPssRecipeFor :: MechanismId -> Maybe RsaPssRecipe
rsaPssRecipeFor mid =
  case [ r | r <- rsaPssRecipes
           , MechanismId (mustGeneratedId (rpName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
