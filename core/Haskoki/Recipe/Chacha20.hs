{- | ChaCha20 stream + ChaCha20-Poly1305 AEAD mechanism recipe.

Two rows, two codecs:

* @CKM_CHACHA20_POLY1305@ takes the canonical
  @chacha20poly1305-params/1@ image: tag length (u64be, always
  16 — the Poly1305 tag is fixed), nonce length (u64be, always
  12 — the IETF 96-bit nonce), nonce, AAD (the remainder).
* @CKM_CHACHA20@ takes the canonical @chacha20-params/1@
  image: initial block counter (u64be, the full 32-bit space),
  nonce length (u64be, always 12), nonce.

Encoding is total; validation is strict.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Chacha20
  ( Chacha20Recipe (..)
  , chachaRecipes
  , chachaRecipeFor
  , chachaPolyCodec
  , chachaStreamCodec
  , chachaCodecFor
  , encodeChachaPolyParams
  , decodeChachaPolyParams
  , chachaPolyParamsValid
  , encodeChachaStreamParams
  , decodeChachaStreamParams
  , encodeChachaIv
  , decodeChachaIv
  , chachaStreamParamsValid
  , chachaParamsValid
  , chachaMaxCounter
  , chachaPolyTagLen
  , chachaNonceLen
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One ChaCha20 recipe row.
data Chacha20Recipe = Chacha20Recipe
  { chachaName :: !MechanismName
  } deriving (Eq, Show)

-- | The recipe rows (AEAD + raw stream).
chachaRecipes :: [Chacha20Recipe]
chachaRecipes =
  [ Chacha20Recipe "CKM_CHACHA20_POLY1305"
  , Chacha20Recipe "CKM_CHACHA20"
  ]

-- | The AEAD parameter codec.
chachaPolyCodec :: ParameterCodec
chachaPolyCodec = ParameterCodec "chacha20poly1305-params" 1

-- | The raw-stream parameter codec.
chachaStreamCodec :: ParameterCodec
chachaStreamCodec = ParameterCodec "chacha20-params" 1

-- | The codec for one recipe row.
chachaCodecFor :: Chacha20Recipe -> ParameterCodec
chachaCodecFor r
  | chachaName r == "CKM_CHACHA20_POLY1305" = chachaPolyCodec
  | otherwise = chachaStreamCodec

-- | Recipe row by mechanism id.
chachaRecipeFor :: MechanismId -> Maybe Chacha20Recipe
chachaRecipeFor (MechanismId m)
  | m == mustGeneratedId "CKM_CHACHA20_POLY1305" =
      Just (Chacha20Recipe "CKM_CHACHA20_POLY1305")
  | m == mustGeneratedId "CKM_CHACHA20" =
      Just (Chacha20Recipe "CKM_CHACHA20")
  | otherwise = Nothing

-- | The fixed Poly1305 tag width in bytes.
chachaPolyTagLen :: Int
chachaPolyTagLen = 16

-- | The IETF 96-bit nonce width in bytes (both rows).
chachaNonceLen :: Int
chachaNonceLen = 12

-- | Maximum servable initial block counter (raw stream): the
-- full 32-bit space — the counter rides the IV natively, so no
-- framing bound applies.
chachaMaxCounter :: Int
chachaMaxCounter = 4294967295

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

-- | Encode AEAD parameters: tag length, nonce length, nonce, AAD.
encodeChachaPolyParams :: ByteString -> ByteString -> Int -> ByteString
encodeChachaPolyParams nonce aad tagLen =
  encodeWord64 tagLen <> encodeWord64 (BS.length nonce) <> nonce <> aad

-- | Decode AEAD parameters: @(nonce, aad, tagLen)@. 'Nothing' on
-- truncation or negative lengths (which cannot encode).
decodeChachaPolyParams :: ByteString -> Maybe (ByteString, ByteString, Int)
decodeChachaPolyParams bs = do
  let (wTag, r1) = BS.splitAt 8 bs
  let (wNonce, r2) = BS.splitAt 8 r1
  tagLen <- decodeWord64 wTag
  nonceLen <- decodeWord64 wNonce
  if nonceLen < 0 || BS.length r2 < nonceLen
    then Nothing
    else let (nonce, aad) = BS.splitAt nonceLen r2
         in Just (nonce, aad, tagLen)

-- | Validate canonical AEAD parameters: the image decodes, the
-- tag is the fixed 16 bytes, and the nonce is the IETF 12.
chachaPolyParamsValid :: Chacha20Recipe -> ByteString -> Bool
chachaPolyParamsValid _ bs = case decodeChachaPolyParams bs of
  Just (nonce, _, tagLen) ->
    tagLen == chachaPolyTagLen
      && BS.length nonce == chachaNonceLen
  Nothing -> False

-- | Encode raw-stream parameters: counter, nonce length, nonce.
encodeChachaStreamParams :: Int -> ByteString -> ByteString
encodeChachaStreamParams counter nonce =
  encodeWord64 counter <> encodeWord64 (BS.length nonce) <> nonce

-- | Decode raw-stream parameters: @(counter, nonce)@. 'Nothing'
-- on truncation, negative lengths, or trailing garbage (the
-- stream image is exact-length).
decodeChachaStreamParams :: ByteString -> Maybe (Int, ByteString)
decodeChachaStreamParams bs = do
  let (wCtr, r1) = BS.splitAt 8 bs
  let (wNonce, r2) = BS.splitAt 8 r1
  counter <- decodeWord64 wCtr
  nonceLen <- decodeWord64 wNonce
  if nonceLen < 0 || BS.length r2 /= nonceLen
    then Nothing
    else Just (counter, r2)

-- | Encode the backend ChaCha20 IV framing: the 4-byte
-- little-endian initial block counter plus the 12-byte nonce
-- (the 16 bytes 'cipherIvLen' pins for 'C_CHACHA20', exactly the
-- IV layout @EVP_chacha20@ takes — CLI-probed against
-- RFC 8439 section 2.4.2).
encodeChachaIv :: Int -> ByteString -> ByteString
encodeChachaIv counter nonce = encodeWord32LE counter <> nonce

-- | Decode the backend ChaCha20 IV framing: @(counter, nonce)@.
-- 'Nothing' unless the image is exactly 16 bytes.
decodeChachaIv :: ByteString -> Maybe (Int, ByteString)
decodeChachaIv bs = do
  let (wCtr, nonce) = BS.splitAt 4 bs
  counter <- decodeWord32LE wCtr
  if BS.length nonce == chachaNonceLen
    then Just (counter, nonce)
    else Nothing

-- | Encode one 4-byte little-endian word.
encodeWord32LE :: Int -> ByteString
encodeWord32LE n = BS.pack [byte s | s <- [0, 8, 16, 24]]
  where
    byte :: Int -> Word8
    byte s = fromIntegral ((n `shiftR` s) .&. 0xff)

-- | Decode one 4-byte little-endian word.
decodeWord32LE :: ByteString -> Maybe Int
decodeWord32LE bs
  | BS.length bs /= 4 = Nothing
  | otherwise = Just (sum [fromIntegral b `shiftL` s | (b, s) <- zip (BS.unpack bs) [0, 8, 16, 24]])

-- | Validate canonical raw-stream parameters: the image decodes
-- exactly, the counter is in bound, and the nonce is the IETF 12.
chachaStreamParamsValid :: Chacha20Recipe -> ByteString -> Bool
chachaStreamParamsValid _ bs = case decodeChachaStreamParams bs of
  Just (counter, nonce) ->
    counter >= 0
      && counter <= chachaMaxCounter
      && BS.length nonce == chachaNonceLen
  Nothing -> False

-- | Validate canonical parameters for either row.
chachaParamsValid :: Chacha20Recipe -> ByteString -> Bool
chachaParamsValid r bs
  | chachaName r == "CKM_CHACHA20_POLY1305" = chachaPolyParamsValid r bs
  | otherwise = chachaStreamParamsValid r bs
