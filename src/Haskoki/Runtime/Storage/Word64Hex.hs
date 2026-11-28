{- | Detached full-width Word64 hex.
-}
module Haskoki.Runtime.Storage.Word64Hex
  ( encodeHexWord64
  , decodeHexWord64
  ) where

import Data.Bits (shiftR, (.&.))
import Data.Char (isHexDigit)
import Data.Word (Word64)
import Haskoki.Runtime.Storage.FixedHex

-- ---------------------------------------------------------------------------
-- Full-width Word64 hex (persistent job ids use the whole domain)
-- ---------------------------------------------------------------------------

-- | Encode a 'Word64' as 16 lowercase hex characters.
encodeHexWord64 :: Word64 -> String
encodeHexWord64 w =
  [hexDigit (fromIntegral ((w `shiftR` s) .&. 0xF)) | s <- [60, 56 .. 0]]

-- | Decode exactly 16 hex characters into a 'Word64'; anything
-- else fails.
decodeHexWord64 :: String -> Maybe Word64
decodeHexWord64 s
  | length s == 16
  , all isHexDigit s =
      Just (foldl (\acc c -> acc * 16 + fromIntegral (hexVal c)) 0 s)
  | otherwise = Nothing
