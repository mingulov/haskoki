{- | Async completion records and codecs.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Async.Completion
  ( Completion (..)
  , encodeCompletion
  , decodeCompletion
  , foldBE
  , u32be
  ) where

import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word32)
import Haskoki.Object (decodeHandle, encodeHandle)
import Haskoki.Output (maxOutputBytes)
import Haskoki.Types
  ( ExternalHandle
  )

-- ---------------------------------------------------------------------------
-- Completion records and codecs
-- ---------------------------------------------------------------------------

-- | One delivered completion: exact bytes (sign\/digest), one
-- handle (generated key), or two handles (generated pair).
data Completion
  = CompBytes !ByteString
  | CompOneHandle !ExternalHandle
  | CompTwoHandles !ExternalHandle !ExternalHandle
  deriving (Eq, Show)

-- | Canonical completion bytes: @tag:u8 body@. @0x01@ carries bytes
-- with a @u32BE@ length; @0x02@\/@0x03@ carry one\/two canonical
-- 8-byte handles ('encodeHandle'). Encode sides only ever emit
-- exact frames.
encodeCompletion :: Completion -> ByteString
encodeCompletion (CompBytes bs) =
  BS.pack [0x01] <> u32be (fromIntegral (BS.length bs)) <> bs
encodeCompletion (CompOneHandle h) =
  BS.pack [0x02] <> encodeHandle h
encodeCompletion (CompTwoHandles h1 h2) =
  BS.pack [0x03] <> encodeHandle h1 <> encodeHandle h2

-- | Strict completion decode: exact-length frames only. Bad tags,
-- short or trailing bytes, and byte lengths past 'maxOutputBytes'
-- all reject; handles must be canonical 8-byte frames.
decodeCompletion :: ByteString -> Maybe Completion
decodeCompletion bs = case BS.uncons bs of
  Just (0x01, rest)
    | BS.length rest >= 4 ->
        let (bLen, payload) = BS.splitAt 4 rest
            n = foldBE bLen
        in if n > toInteger maxOutputBytes
          then Nothing
          else if fromInteger n /= BS.length payload
            then Nothing
            else Just (CompBytes payload)
  Just (0x02, rest)
    | BS.length rest == 8 -> CompOneHandle <$> decodeHandle rest
  Just (0x03, rest)
    | BS.length rest == 16 ->
        CompTwoHandles <$> decodeHandle (BS.take 8 rest)
          <*> decodeHandle (BS.drop 8 rest)
  _ -> Nothing

-- | Big-endian fold computed in 'Integer' so large values never wrap.
foldBE :: ByteString -> Integer
foldBE = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | Big-endian 32-bit frame.
u32be :: Word32 -> ByteString
u32be w = BS.pack
  [ fromIntegral ((w `shiftR` 24) .&. 0xFF)
  , fromIntegral ((w `shiftR` 16) .&. 0xFF)
  , fromIntegral ((w `shiftR` 8) .&. 0xFF)
  , fromIntegral (w .&. 0xFF)
  ]
