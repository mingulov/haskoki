{- | Key-output codecs: handles, wrapped blobs and KEM ciphertext
plan through the output machinery, and caller buffers decode
into owned bytes with length checks.

Handles always plan one exact scalar write (they carry no intent);
byte outputs plan size-query, short-buffer (with the required
length) and exact intents through 'planOutputs'. KEM ciphertext is
length-checked against the mechanism's length BEFORE any planning,
like the generated-IV writeback: a wrong-length value rejects with
'CKR_ARGUMENTS_BAD' instead of planning a short write.

Decode reuses 'Haskoki.FFI.Decode.decodeInputBytes' (the bound is
checked before any dereference, null-with-zero is empty,
null-with-length rejects) and adds the exact-length rule for KEM
ciphertext.
-}
module Haskoki.FFI.KeyOutputs
  ( KeyOutputError (..)
  , planHandleWriteback
  , planWrappedWriteback
  , planCiphertextWriteback
  , decodeWrappedInput
  , decodeKemCiphertext
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8, Word64)
import Foreign.Ptr (Ptr)

import Haskoki.FFI.Decode (DecodeError (..), decodeInputBytes)
import Haskoki.Output
  ( DataSource (..)
  , OpDisposition (..)
  , OutputPlan (..)
  , RegionOutcome (..)
  , ResultDisposition (..)
  , planOutputs
  )
import Haskoki.Request (OutputIntent, OutputRegion (..))
import Haskoki.Types (ExternalHandle, ReturnCode (..))

-- | Key-output failures: caller-memory faults shared with the byte
-- decoder, plus the KEM exact-length rule (wanted, got).
data KeyOutputError
  = KeyOutputBadPointer !Word64
  | KeyOutputTooLarge !Word64
  | KeyOutputLengthMismatch !Int !Int
  deriving (Eq, Show)

fromDecode :: DecodeError -> KeyOutputError
fromDecode err = case err of
  DecodeNullInput n -> KeyOutputBadPointer n
  DecodeTooLarge n -> KeyOutputTooLarge n

-- | Plan one handle writeback: handles carry no intent, so the write
-- is always exact.
planHandleWriteback :: String -> ExternalHandle -> OutputPlan
planHandleWriteback name h = planOutputs
  [RegionOutcome (RegionHandle name) (Right (SourceHandle h))]

-- | Plan one wrapped-blob writeback: size-query, short-buffer (with
-- the required length) and exact intents per the caller's intent.
planWrappedWriteback :: String -> ByteString -> OutputIntent -> OutputPlan
planWrappedWriteback name blob intent = planOutputs
  [RegionOutcome (RegionBytes name intent) (Right (SourceBytes blob))]

-- | Plan one KEM-ciphertext writeback: the blob must be exactly the
-- mechanism's ciphertext length, else the call rejects with
-- 'CKR_ARGUMENTS_BAD' before any planning.
planCiphertextWriteback :: String -> Int -> ByteString -> OutputIntent -> OutputPlan
planCiphertextWriteback name wanted ct intent
  | BS.length ct /= wanted = OutputPlan
      { opCode = CKR_ARGUMENTS_BAD
      , opWrites = []
      , opLengths = []
      , opDispositions = [ResultDisposition [name] CKR_ARGUMENTS_BAD OpKeep]
      , opReasons =
          [ "ciphertext length " ++ show (BS.length ct)
            ++ " mismatches mechanism length " ++ show wanted
          ]
      }
  | otherwise = planOutputs
      [RegionOutcome (RegionBytes name intent) (Right (SourceBytes ct))]

-- | Decode one caller's wrapped-blob input into owned bytes.
decodeWrappedInput :: Ptr Word8 -> Word64 -> IO (Either KeyOutputError ByteString)
decodeWrappedInput ptr len = do
  eBytes <- decodeInputBytes ptr len
  pure $ case eBytes of
    Left e -> Left (fromDecode e)
    Right bs -> Right bs

-- | Decode one caller's KEM ciphertext into owned bytes: the length
-- must be exactly the mechanism's ciphertext length.
decodeKemCiphertext :: Int -> Ptr Word8 -> Word64 -> IO (Either KeyOutputError ByteString)
decodeKemCiphertext wanted ptr len = do
  eBytes <- decodeInputBytes ptr len
  pure $ case eBytes of
    Left e -> Left (fromDecode e)
    Right bs
      | BS.length bs /= wanted -> Left (KeyOutputLengthMismatch wanted (BS.length bs))
      | otherwise -> Right bs
