{- | Native encode side: typed write sets land in bounded caller
buffers.

Every write resolves its nested path against the bound buffers,
encodes its payload ('Nothing' for out-of-range scalars, which the
planner already rejects), and checks capacity before copying: a
short buffer reports 'CKR_BUFFER_TOO_SMALL' and touches nothing.
A write with no bound buffer, or an unencodable payload, reports
'CKR_GENERAL_ERROR' and touches nothing. Length answers poke the
caller's length word, rejecting null.
-}
module Haskoki.FFI.Encode
  ( BoundBuffer (..)
  , EncodeReport (..)
  , encodeWrites
  , encodeLength
  , nativeToWrite
  ) where

import qualified Data.ByteString as BS
import Data.ByteString.Unsafe (unsafeUseAsCString)
import Data.Word (Word8, Word64)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (poke)

import Haskoki.Outcome (NativeOutput (..))
import Haskoki.Output (TypedWrite (..), WritePayload (..), typedWriteBytes)
import Haskoki.Request (OutputRegion (..))
import Haskoki.Types (ReturnCode (..))

-- | One bound caller buffer: the nested path it serves, the write
-- pointer, and its capacity in bytes.
data BoundBuffer = BoundBuffer
  { bbPath :: ![String]
  , bbPtr :: !(Ptr Word8)
  , bbCapacity :: !Word64
  }

-- | One write's report: the path, bytes actually written, and the
-- per-write code.
data EncodeReport = EncodeReport
  { erPath :: ![String]
  , erWritten :: !Word64
  , erCode :: !ReturnCode
  } deriving (Eq, Show)

-- | Apply typed writes to their bound buffers, in order, one report
-- per write. Copies are bounded by the buffer's capacity and never
-- partial: anything that does not fit reports short with zero
-- bytes written.
encodeWrites :: [BoundBuffer] -> [TypedWrite] -> IO [EncodeReport]
encodeWrites bufs = mapM encodeOne
  where
    encodeOne :: TypedWrite -> IO EncodeReport
    encodeOne w = case typedWriteBytes w of
      Nothing -> pure (EncodeReport (twPath w) 0 CKR_GENERAL_ERROR)
      Just bs -> case lookup (twPath w) [(bbPath b, b) | b <- bufs] of
        Nothing -> pure (EncodeReport (twPath w) 0 CKR_GENERAL_ERROR)
        Just b ->
          let n = BS.length bs
          in if fromIntegral n > bbCapacity b
            then pure (EncodeReport (twPath w) 0 CKR_BUFFER_TOO_SMALL)
            else do
              unsafeUseAsCString bs $ \src -> copyBytes (bbPtr b) (castPtr src) n
              pure (EncodeReport (twPath w) (fromIntegral n) CKR_OK)

-- | Answer a length word (size queries, short-buffer retries).
-- A null pointer rejects with 'CKR_ARGUMENTS_BAD'.
encodeLength :: Ptr CULong -> Word64 -> IO ReturnCode
encodeLength ptr v
  | ptr == nullPtr = pure CKR_ARGUMENTS_BAD
  | otherwise = poke ptr (CULong (fromIntegral v)) >> pure CKR_OK

-- | Rebuild a typed write from a commit output for 'encodeWrites'.
-- Only byte regions round-trip; anything else is an internal
-- mismatch the caller reports loudly.
nativeToWrite :: NativeOutput -> Maybe TypedWrite
nativeToWrite (NativeOutput region bs) = case region of
  RegionBytes name _ -> Just (TypedWrite [name] region (PayloadBytes bs))
  _ -> Nothing
