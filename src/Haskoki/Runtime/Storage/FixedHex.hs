{- | Detached fixed hex for full-width unsigned quantities.
-}
module Haskoki.Runtime.Storage.FixedHex
  ( hexDigit
  , hexVal
  , encodeHex16
  , decodeHex16
  ) where

import Data.Bits ( shiftR, (.&.))
import Data.Char (chr, isHexDigit, ord)
import Data.Word ( Word64)

-- ---------------------------------------------------------------------------
-- Fixed hex for full-width unsigned quantities
-- ---------------------------------------------------------------------------

-- | One hex digit, lowercase.
hexDigit :: Int -> Char
hexDigit n
  | n >= 0 && n <= 9 = chr (ord '0' + n)
  | otherwise = chr (ord 'a' + n - 10)

-- | One hex digit value (either case on decode).
hexVal :: Char -> Int
hexVal c
  | c >= '0' && c <= '9' = ord c - ord '0'
  | c >= 'a' && c <= 'f' = ord c - ord 'a' + 10
  | otherwise = ord c - ord 'A' + 10

-- | Encode a non-negative 'Int' as 16 lowercase hex characters
-- (8-byte big-endian). Negative inputs are rejected by the caller
-- contract; encoding masks to the low 64 bits regardless.
encodeHex16 :: Int -> String
encodeHex16 n =
  [ hexDigit (fromIntegral ((w `shiftR` s) .&. 0xF)) | s <- [60, 56 .. 0] ]
  where
    w :: Word64
    w = fromIntegral n

-- | Decode exactly 16 hex characters into a non-negative 'Int';
-- anything else (wrong length, non-hex, out of 'Int' range) fails.
decodeHex16 :: String -> Maybe Int
decodeHex16 s
  | length s == 16
  , all isHexDigit s =
      let w = foldl (\acc c -> acc * 16 + fromIntegral (hexVal c)) 0 s :: Word64
      in if w > fromIntegral (maxBound :: Int) then Nothing else Just (fromIntegral w)
  | otherwise = Nothing
