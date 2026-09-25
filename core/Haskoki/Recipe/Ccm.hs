{- | AES-CCM mechanism recipe.

Canonical @ccm-params/1@ image: tag length (u64be), nonce length
(u64be), data length (u64be), nonce, AAD (the remainder). Nonce
is 7..13 bytes and tag widths are the NIST SP 800-38C approved
even widths (4, 6, 8, 10, 12, 14, 16 bytes); the data length
('ulDataLen') rides the image and is enforced as an
operation-time precondition against the input. Encoding is
total; validation is strict.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Ccm
  ( CcmRecipe (..)
  , ccmRecipes
  , ccmRecipeFor
  , ccmCodec
  , ccmCodecFor
  , encodeCcmParams
  , decodeCcmParams
  , ccmParamsValid
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The single CCM recipe row.
data CcmRecipe = CcmRecipe
  { ccmName :: !MechanismName
  } deriving (Eq, Show)

-- | The recipe rows (AES-CCM only).
ccmRecipes :: [CcmRecipe]
ccmRecipes = [CcmRecipe "CKM_AES_CCM"]

-- | The group's canonical parameter codec.
ccmCodec :: ParameterCodec
ccmCodec = ParameterCodec "ccm-params" 1

-- | The codec for one recipe row (uniform across the group).
ccmCodecFor :: CcmRecipe -> ParameterCodec
ccmCodecFor _ = ccmCodec

-- | Recipe row by mechanism id.
ccmRecipeFor :: MechanismId -> Maybe CcmRecipe
ccmRecipeFor (MechanismId m)
  | m == mustGeneratedId "CKM_AES_CCM" = Just (CcmRecipe "CKM_AES_CCM")
  | otherwise = Nothing

-- | Approved tag widths in bytes (SP 800-38C: even, 4..16).
ccmTagLens :: [Int]
ccmTagLens = [4, 6, 8, 10, 12, 14, 16]

-- | Caller nonce bounds in bytes (SP 800-38C: 7..13).
ccmNonceMin :: Int
ccmNonceMin = 7

ccmNonceMax :: Int
ccmNonceMax = 13

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

-- | Encode CCM parameters: tag length, nonce length, data
-- length, nonce, AAD.
encodeCcmParams :: ByteString -> ByteString -> Int -> Int -> ByteString
encodeCcmParams nonce aad tagLen dataLen =
  encodeWord64 tagLen <> encodeWord64 (BS.length nonce)
    <> encodeWord64 dataLen <> nonce <> aad

-- | Decode CCM parameters: @(nonce, aad, tagLen, dataLen)@.
-- 'Nothing' on truncation or negative lengths (which cannot
-- encode).
decodeCcmParams :: ByteString -> Maybe (ByteString, ByteString, Int, Int)
decodeCcmParams bs = do
  let (wTag, r1) = BS.splitAt 8 bs
  let (wNonce, r2) = BS.splitAt 8 r1
  let (wData, r3) = BS.splitAt 8 r2
  tagLen <- decodeWord64 wTag
  nonceLen <- decodeWord64 wNonce
  dataLen <- decodeWord64 wData
  if nonceLen < 0 || dataLen < 0 || BS.length r3 < nonceLen
    then Nothing
    else let (nonce, aad) = BS.splitAt nonceLen r3
         in Just (nonce, aad, tagLen, dataLen)

-- | Validate canonical parameters: the image decodes, the tag
-- width is approved, and the nonce is caller-supplied in range.
-- The data length is an operation-time precondition (checked
-- against the input in the driver), not a recipe refusal.
ccmParamsValid :: CcmRecipe -> ByteString -> Bool
ccmParamsValid _ bs = case decodeCcmParams bs of
  Just (nonce, _, tagLen, _) ->
    tagLen `elem` ccmTagLens
      && BS.length nonce >= ccmNonceMin
      && BS.length nonce <= ccmNonceMax
  Nothing -> False
