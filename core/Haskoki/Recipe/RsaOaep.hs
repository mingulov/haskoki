{- | RSA-OAEP recipe: the sixth shape-group recipe.

One header mechanism (@CKM_RSA_PKCS_OAEP@) with the labeled
parameter shape — @oaep-params\/1@: the hash code, the MGF1 hash
code (two 8-byte big-endian words, same width and byte order
convention as the PSS codec), and the trailing label bytes
(possibly empty). The digest codes are the same codebase wire
convention as 'Haskoki.Recipe.RsaPss' (MD5 = 1 through
RIPEMD160 = 11).

This module owns the group's canonical codec, parameter
validation, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the behavior descriptor from
  'rsaOaepCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces OAEP parameters via
  'rsaOaepRecipeFor' + 'rsaOaepParamsValid' and refuses padded
  cipher specs for the RSA row (PKCS#7 framing must never cover an
  asymmetric operation);
* 'Haskoki.Engine.Driver.rsaOaepParamsFor' maps the covered
  (mechanism, params) pair to backend 'Haskoki.Engine.Backend.OaepParams';
  RecipeOaepSpec pins the mapping;
* the synthetic backend's labeled construction and the libcrypto
  interop vectors execute the params pinned here (SyntheticSpec,
  OpenSSLSpec).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.RsaOaep
  ( RsaOaepRecipe (..)
  , rsaOaepRecipes
  , rsaOaepRecipeFor
  , rsaOaepCodec
  , rsaOaepCodecFor
  , encodeOaepParams
  , decodeOaepParams
  , rsaOaepParamsValid
  , oaepDigestCode
  , oaepCodeDigest
  , oaepDigestWidth
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Word (Word8)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The single OAEP recipe row.
data RsaOaepRecipe = RsaOaepRecipe
  { roName :: !MechanismName
  } deriving (Eq, Show)

-- | The group's canonical parameter codec.
rsaOaepCodec :: ParameterCodec
rsaOaepCodec = ParameterCodec "oaep-params" 1

-- | The codec for one recipe row (uniform across the group).
rsaOaepCodecFor :: RsaOaepRecipe -> ParameterCodec
rsaOaepCodecFor _ = rsaOaepCodec

-- | Digest stems onto wire codes (shared convention with the PSS
-- codec; unknown stems never encode).
oaepDigestCode :: Text -> Maybe Int
oaepDigestCode stem
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
oaepCodeDigest :: Int -> Maybe Text
oaepCodeDigest code
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

-- | Encode OAEP parameters (unknown stems encode as code 0, which
-- never validates: encoding is total, validation is strict).
encodeOaepParams :: Text -> Text -> ByteString -> ByteString
encodeOaepParams digest mgf label =
  encodeWord64 (code digest) <> encodeWord64 (code mgf) <> label
  where
    code stem = case oaepDigestCode stem of
      Just c -> c
      Nothing -> 0

-- | Strict decode: at least the 16-byte header, table codes only,
-- the remainder is the label (possibly empty).
decodeOaepParams :: ByteString -> Maybe (Text, Text, ByteString)
decodeOaepParams bs = do
  let (w1, r1) = BS.splitAt 8 bs
      (w2, label) = BS.splitAt 8 r1
  c1 <- decodeWord64 w1
  c2 <- decodeWord64 w2
  d <- oaepCodeDigest c1
  m <- oaepCodeDigest c2
  pure (d, m, label)

-- | OAEP parameter validation: strict decoding with table codes.
rsaOaepParamsValid :: RsaOaepRecipe -> ByteString -> Bool
rsaOaepParamsValid _ params = case decodeOaepParams params of
  Just _ -> True
  Nothing -> False

-- | Output width of an OAEP digest stem ('Nothing' for unknown
-- stems, which never validate). The wrap planner bounds payloads
-- by the main hash width (mLen <= k - 2*hLen - 2); the MGF width
-- never enters the bound.
oaepDigestWidth :: Text -> Maybe Int
oaepDigestWidth stem
  | stem == "MD5" = Just 16
  | stem == "SHA_1" = Just 20
  | stem == "SHA224" = Just 28
  | stem == "SHA256" = Just 32
  | stem == "SHA384" = Just 48
  | stem == "SHA512" = Just 64
  | stem == "SHA3_224" = Just 28
  | stem == "SHA3_256" = Just 32
  | stem == "SHA3_384" = Just 48
  | stem == "SHA3_512" = Just 64
  | stem == "RIPEMD160" = Just 20
  | otherwise = Nothing

-- | The single covered mechanism.
rsaOaepRecipes :: [RsaOaepRecipe]
rsaOaepRecipes = [RsaOaepRecipe "CKM_RSA_PKCS_OAEP"]

-- | Resolve a mechanism id to its OAEP recipe, if covered.
rsaOaepRecipeFor :: MechanismId -> Maybe RsaOaepRecipe
rsaOaepRecipeFor mid =
  case [ r | r <- rsaOaepRecipes
           , MechanismId (mustGeneratedId (roName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
