{- | Native decode side: caller pointers become normalized,
address-free values.

Null-versus-present is the load-bearing distinction: a null buffer
pointer decodes to a size-query intent whatever the length word
reads, while a live pointer decodes to a bounded buffer. Input
bytes are copied into owned 'ByteString's under 'maxInputBytes';
the bound is checked before any dereference.
-}
module Haskoki.FFI.Decode
  ( DecodeError (..)
  , maxInputBytes
  , decodeIntent
  , decodeInputBytes
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8, Word64)
import Foreign.Marshal.Array (peekArray)
import Foreign.Ptr (Ptr, nullPtr)

import Haskoki.Request (OutputIntent (..))

-- | Bound on any single decoded input (16 MiB, matching
-- 'Haskoki.Output.maxOutputBytes'). Lengths past this bound reject
-- before any pointer is dereferenced.
maxInputBytes :: Word64
maxInputBytes = 16 * 1024 * 1024

-- | Input-decoding failure: a null pointer carrying a nonzero
-- length, or a length past 'maxInputBytes'.
data DecodeError
  = DecodeNullInput !Word64
  | DecodeTooLarge !Word64
  deriving (Eq, Show)

-- | Decode a caller's output-buffer half: null means a size query,
-- live means a buffer of the given capacity. Pure: no dereference.
decodeIntent :: Ptr a -> Word64 -> OutputIntent
decodeIntent ptr cap
  | ptr == nullPtr = IntentNull
  | otherwise = IntentBuffer cap

-- | Copy @len@ input bytes into owned storage. The bound is checked
-- first (a huge length rejects even from null); null-with-zero is
-- empty; null-with-length rejects.
decodeInputBytes :: Ptr Word8 -> Word64 -> IO (Either DecodeError ByteString)
decodeInputBytes ptr len
  | len > maxInputBytes = pure (Left (DecodeTooLarge len))
  | ptr == nullPtr =
      if len == 0
        then pure (Right BS.empty)
        else pure (Left (DecodeNullInput len))
  | otherwise = Right . BS.pack <$> peekArray (fromIntegral len) ptr
