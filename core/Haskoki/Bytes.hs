{- | Canonical big-endian integer framing.

The one home for the @u16be@\/@u32be@\/@u64be@ encoders and the
'foldBE' decoder, previously copied per module (div\/mod form in
'Int', shift form in 'Word16'\/'Word32'\/'Word64', and day-one
local copies in tests). Callers converting from a 'Word'
type do so at the boundary with 'fromIntegral': for 16\/32
bits the conversion is exact, and for 64 bits the mod-2^64
wrap matches the shift form bit for bit (pinned by the
equivalence properties in @CodecProps@, full-range
'QuickCheck' over every form, negatives included).

Pure leaf: @base@ and @bytestring@ only.
-}
module Haskoki.Bytes
  ( u16be
  , u32be
  , u64be
  , foldBE
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

-- | 2-byte big-endian framing.
u16be :: Int -> ByteString
u16be n = BS.pack
  [ fromIntegral (n `div` 256 `mod` 256)
  , fromIntegral (n `mod` 256)
  ]

-- | 4-byte big-endian framing.
u32be :: Int -> ByteString
u32be n = BS.pack
  [ fromIntegral (n `div` 16777216 `mod` 256)
  , fromIntegral (n `div` 65536 `mod` 256)
  , fromIntegral (n `div` 256 `mod` 256)
  , fromIntegral (n `mod` 256)
  ]

-- | 8-byte big-endian framing.
u64be :: Int -> ByteString
u64be n = BS.pack
  [ fromIntegral (n `div` 72057594037927936 `mod` 256)
  , fromIntegral (n `div` 281474976710656 `mod` 256)
  , fromIntegral (n `div` 1099511627776 `mod` 256)
  , fromIntegral (n `div` 4294967296 `mod` 256)
  , fromIntegral (n `div` 16777216 `mod` 256)
  , fromIntegral (n `div` 65536 `mod` 256)
  , fromIntegral (n `div` 256 `mod` 256)
  , fromIntegral (n `mod` 256)
  ]

-- | Big-endian fold computed in 'Integer' so large values never wrap.
foldBE :: ByteString -> Integer
foldBE = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0
