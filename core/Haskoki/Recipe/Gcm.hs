{- | AES-GCM mechanism recipe.

Canonical @gcm-params/1@ image: tag length (u64be), IV length
(u64be), IV, AAD (the remainder). Tag lengths are the NIST
SP 800-38D approved widths (32, 64, 96, 104, 112, 120, 128
bits); the IV is caller-supplied, 1..64 bytes (the generated-IV
convention never translates: it passes through and is refused
downstream). Encoding is total; validation is strict.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Gcm
  ( GcmRecipe (..)
  , gcmRecipes
  , gcmRecipeFor
  , gcmCodec
  , gcmCodecFor
  , encodeGcmParams
  , decodeGcmParams
  , gcmParamsValid
  , gcmTagLens
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The single GCM recipe row.
data GcmRecipe = GcmRecipe
  { gcmName :: !MechanismName
  } deriving (Eq, Show)

-- | The recipe rows (AES-GCM only).
gcmRecipes :: [GcmRecipe]
gcmRecipes = [GcmRecipe "CKM_AES_GCM"]

-- | The group's canonical parameter codec.
gcmCodec :: ParameterCodec
gcmCodec = ParameterCodec "gcm-params" 1

-- | The codec for one recipe row (uniform across the group).
gcmCodecFor :: GcmRecipe -> ParameterCodec
gcmCodecFor _ = gcmCodec

-- | Recipe row by mechanism id.
gcmRecipeFor :: MechanismId -> Maybe GcmRecipe
gcmRecipeFor (MechanismId m)
  | m == mustGeneratedId "CKM_AES_GCM" = Just (GcmRecipe "CKM_AES_GCM")
  | otherwise = Nothing

-- | Approved tag widths in bytes.
gcmTagLens :: [Int]
gcmTagLens = [4, 8, 12, 13, 14, 15, 16]

-- | Maximum caller IV in bytes (96-bit nonces and every sane
-- explicit IV; absurd lengths refuse).
gcmIvMax :: Int
gcmIvMax = 64

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

-- | Encode GCM parameters: tag length, IV length, IV, AAD.
encodeGcmParams :: ByteString -> ByteString -> Int -> ByteString
encodeGcmParams iv aad tagLen =
  encodeWord64 tagLen <> encodeWord64 (BS.length iv) <> iv <> aad

-- | Decode GCM parameters: @(iv, aad, tagLen)@. 'Nothing' on
-- truncation or negative lengths (which cannot encode).
decodeGcmParams :: ByteString -> Maybe (ByteString, ByteString, Int)
decodeGcmParams bs = do
  let (wTag, r1) = BS.splitAt 8 bs
  let (wIv, r2) = BS.splitAt 8 r1
  tagLen <- decodeWord64 wTag
  ivLen <- decodeWord64 wIv
  if ivLen < 0 || BS.length r2 < ivLen
    then Nothing
    else let (iv, aad) = BS.splitAt ivLen r2
         in Just (iv, aad, tagLen)

-- | Validate canonical parameters: the image decodes, the tag
-- width is approved, and the IV is caller-supplied in range.
gcmParamsValid :: GcmRecipe -> ByteString -> Bool
gcmParamsValid _ bs = case decodeGcmParams bs of
  Just (iv, _, tagLen) ->
    tagLen `elem` gcmTagLens
      && BS.length iv >= 1
      && BS.length iv <= gcmIvMax
  Nothing -> False
