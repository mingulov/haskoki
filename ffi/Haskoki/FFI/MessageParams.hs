{- | Message parameter codecs: caller pointers become normalized
per-message parameters and AAD, and generated nonces \/ detached
tags plan nested writeback through the output machinery.

Decode reuses 'Haskoki.FFI.Decode.decodeInputBytes' (the bound is
checked before any dereference, null-with-zero is empty,
null-with-length rejects) and adds the family AAD rule: cipher
families bind AAD, sign\/verify families reject it, mirroring the
core parameter check.

Writeback plans are pure 'OutputPlan's over nested regions
(@struct\/nonce@, @struct\/tag@): a wrong-length value rejects
with 'CKR_ARGUMENTS_BAD' before any planning; otherwise
size-query, short-buffer (with the required length), and exact
intents plan through 'planOutputs'. The encode side
("Haskoki.FFI.Encode") applies them to bound caller buffers.
-}
module Haskoki.FFI.MessageParams
  ( MsgParams (..)
  , MsgParamError (..)
  , decodeMessageParams
  , splitTag
  , planNonceWriteback
  , planTagWriteback
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8, Word64)
import Foreign.Ptr (Ptr)

import Haskoki.FFI.Decode (DecodeError (..), decodeInputBytes)
import Haskoki.Operation (MsgFamily (..))
import Haskoki.Operation.Message (familyAad)
import Haskoki.Output
  ( DataSource (..)
  , OpDisposition (..)
  , OutputPlan (..)
  , RegionOutcome (..)
  , ResultDisposition (..)
  , planOutputs
  )
import Haskoki.Request (OutputIntent, OutputRegion (..))
import Haskoki.Types (ReturnCode (..))

-- | Normalized per-message parameters: the opaque parameter block
-- (typically a nonce or IV) plus the AEAD associated data.
data MsgParams = MsgParams
  { mpParams :: !ByteString
  , mpAad :: !ByteString
  } deriving (Eq, Show)

-- | Message-parameter failures: caller-memory faults shared with
-- the byte decoder, the family AAD rule, and short tag blobs.
data MsgParamError
  = MsgParamBadPointer !Word64
  | MsgParamTooLarge !Word64
  | MsgParamAadRejected
  | MsgParamShortTag
  deriving (Eq, Show)

fromDecode :: DecodeError -> MsgParamError
fromDecode err = case err of
  DecodeNullInput n -> MsgParamBadPointer n
  DecodeTooLarge n -> MsgParamTooLarge n

-- | Decode one call's per-message parameter block and AAD half
-- into owned bytes. Lengths are bound-checked before any
-- dereference; nonzero AAD for a family without an AAD channel
-- rejects.
decodeMessageParams
  :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64
  -> IO (Either MsgParamError MsgParams)
decodeMessageParams fam pPtr pLen aPtr aLen = do
  eParams <- decodeInputBytes pPtr pLen
  eAad <- decodeInputBytes aPtr aLen
  pure $ case (eParams, eAad) of
    (Left e, _) -> Left (fromDecode e)
    (_, Left e) -> Left (fromDecode e)
    (Right params, Right aad)
      | not (familyAad fam) && not (BS.null aad) -> Left MsgParamAadRejected
      | otherwise -> Right (MsgParams params aad)

-- | Split a trailing tag off a @ciphertext \|\| tag@ blob. The
-- comparison runs in 'Integer' so a gigantic tag length rejects
-- instead of wrapping the split point.
splitTag :: Word64 -> ByteString -> Either MsgParamError (ByteString, ByteString)
splitTag tagLen blob
  | toInteger (BS.length blob) < toInteger tagLen = Left MsgParamShortTag
  | otherwise = Right (BS.splitAt (BS.length blob - fromIntegral tagLen) blob)

-- | Plan one generated-value writeback into a nested params field:
-- @struct@ names the params block, @field@ the leaf, @wanted@ the
-- mechanism's exact length. A wrong-length value rejects with
-- 'CKR_ARGUMENTS_BAD' before any planning.
planFieldWriteback :: String -> String -> Word64 -> ByteString -> OutputIntent -> OutputPlan
planFieldWriteback struct field wanted bytes intent
  | fromIntegral (BS.length bytes) /= wanted = OutputPlan
      { opCode = CKR_ARGUMENTS_BAD
      , opWrites = []
      , opLengths = []
      , opDispositions = [ResultDisposition [struct, field] CKR_ARGUMENTS_BAD OpKeep]
      , opReasons =
          [ field ++ " length " ++ show (BS.length bytes)
            ++ " mismatches mechanism length " ++ show wanted
          ]
      }
  | otherwise = planOutputs
      [ RegionOutcome
          (RegionNested struct [RegionBytes field intent])
          (Right (SourceNested [(field, SourceBytes bytes)]))
      ]

-- | Plan a generated-nonce writeback into the params block.
planNonceWriteback :: String -> Word64 -> ByteString -> OutputIntent -> OutputPlan
planNonceWriteback struct = planFieldWriteback struct "nonce"

-- | Plan a detached-tag writeback into the params block.
planTagWriteback :: String -> Word64 -> ByteString -> OutputIntent -> OutputPlan
planTagWriteback struct = planFieldWriteback struct "tag"
