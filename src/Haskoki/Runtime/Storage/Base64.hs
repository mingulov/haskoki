{- | Detached base64 (RFC 4648, strict).
-}
module Haskoki.Runtime.Storage.Base64
  ( encodeBase64
  , decodeBase64
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

-- ---------------------------------------------------------------------------
-- Base64 (RFC 4648, strict)
-- ---------------------------------------------------------------------------

-- | Base64 alphabet.
b64Alphabet :: String
b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

-- | Encode bytes as base64 text.
encodeBase64 :: ByteString -> String
encodeBase64 bs = go (BS.unpack bs)
  where
    go :: [Word8] -> String
    go [] = []
    go [a] =
      let n = (fromIntegral a :: Int) `shiftL` 16
      in [at (n `shiftR` 18), at ((n `shiftR` 12) .&. 0x3F), '=', '=']
    go [a, b] =
      let n = ((fromIntegral a :: Int) `shiftL` 16) + ((fromIntegral b :: Int) `shiftL` 8)
      in [at (n `shiftR` 18), at ((n `shiftR` 12) .&. 0x3F), at ((n `shiftR` 6) .&. 0x3F), '=']
    go (a : b : c : rest) =
      let n = ((fromIntegral a :: Int) `shiftL` 16)
            + ((fromIntegral b :: Int) `shiftL` 8)
            + (fromIntegral c :: Int)
      in [ at (n `shiftR` 18)
         , at ((n `shiftR` 12) .&. 0x3F)
         , at ((n `shiftR` 6) .&. 0x3F)
         , at (n .&. 0x3F)
         ] ++ go rest
    at :: Int -> Char
    at i = b64Alphabet !! i

-- | Strict base64 decode: canonical padding only, no whitespace,
-- no trailing characters.
decodeBase64 :: String -> Maybe ByteString
decodeBase64 s
  | length s `mod` 4 /= 0 = Nothing
  | otherwise = BS.pack <$> go s
  where
    go :: String -> Maybe [Word8]
    go [] = Just []
    go [a, b, '=', '='] = do
      x <- val a
      y <- val b
      if y .&. 0xF /= 0
        then Nothing
        else Just [fromIntegral ((x `shiftL` 2) + (y `shiftR` 4))]
    go [a, b, c, '='] = do
      x <- val a
      y <- val b
      z <- val c
      if z .&. 0x3 /= 0
        then Nothing
        else Just
          [ fromIntegral ((x `shiftL` 2) + (y `shiftR` 4))
          , fromIntegral (((y .&. 0xF) `shiftL` 4) + (z `shiftR` 2))
          ]
    go (a : b : c : d : rest) = do
      x <- val a
      y <- val b
      z <- val c
      w <- val d
      more <- go rest
      Just
        ( fromIntegral ((x `shiftL` 2) + (y `shiftR` 4))
        : fromIntegral (((y .&. 0xF) `shiftL` 4) + (z `shiftR` 2))
        : fromIntegral (((z .&. 0x3) `shiftL` 6) + w)
        : more
        )
    go _ = Nothing
    val :: Char -> Maybe Int
    val c = lookup c (zip b64Alphabet [0 ..])
