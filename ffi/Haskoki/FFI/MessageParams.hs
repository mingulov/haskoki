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
  , decodeMessageInitFrame
  , decodeMessageBeginFrame
  , decodeMessageCipherFrame
  , decodeMessageSignFrame
  , decodeMessageVerifyFrame
  , decodeMessageCipherNextFrame
  , decodeMessageSignNextFrame
  , decodeMessageVerifyNextFrame
  , splitTag
  , planNonceWriteback
  , planTagWriteback
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8, Word64)
import Foreign.C.Types (CULong)
import Foreign.Ptr (Ptr, nullPtr)

import Haskoki.FFI.Decode (DecodeError (..), decodeInputBytes)
import Haskoki.FFI.NativeParams (normalizeMechParams)
import Haskoki.Operation (MsgFamily (..))
import Haskoki.Operation.Codec (encodeInitInput, encodeMsgBegin, encodeMsgOneShot, encodeMsgNext)
import Haskoki.Operation.Message (MsgBegin (..), MsgOneShot (..), MsgNext (..), familyAad)
import Haskoki.Operation.State (msgFamilyOp)
import Haskoki.Output
  ( DataSource (..)
  , OpDisposition (..)
  , OutputPlan (..)
  , RegionOutcome (..)
  , ResultDisposition (..)
  , planOutputs
  )
import Haskoki.Registry (MechanismId (..))
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

copyMessageBytes :: Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
copyMessageBytes p n = fmap (either (Left . fromDecode) Right) (decodeInputBytes p n)

bindMessage :: IO (Either MsgParamError a) -> (a -> IO (Either MsgParamError b)) -> IO (Either MsgParamError b)
bindMessage action next = action >>= either (pure . Left) next

decodeMessageInitFrame :: MsgFamily -> CULong -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageInitFrame fam mech p n = bindMessage (copyMessageBytes p n) $ \raw -> do
  let mid = MechanismId (fromIntegral mech)
  params <- normalizeMechParams mid p n raw
  pure (Right (encodeInitInput mid [msgFamilyOp fam] False params))

decodeMessageBeginFrame :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageBeginFrame fam p pn a an =
  bindMessage (decodeMessageParams fam p pn a an) $ \mp ->
    pure (Right (encodeMsgBegin (MsgBegin (mpParams mp) (mpAad mp))))

decodeMessageCipherFrame :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageCipherFrame fam p pn a an d dn =
  bindMessage (decodeMessageParams fam p pn a an) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \input ->
    pure (Right (encodeMsgOneShot (MsgOneShotCipher (mpParams mp) (mpAad mp) input)))

decodeMessageSignFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageSignFrame p pn d dn =
  bindMessage (decodeMessageParams MsgSign p pn nullPtr 0) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \input ->
    pure (Right (encodeMsgOneShot (MsgOneShotSign (mpParams mp) input)))

decodeMessageVerifyFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageVerifyFrame p pn d dn w wn =
  bindMessage (decodeMessageParams MsgVerify p pn nullPtr 0) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \input ->
  bindMessage (copyMessageBytes w wn) $ \witness ->
    pure (Right (encodeMsgOneShot (MsgOneShotVerify (mpParams mp) input witness)))

decodeMessageCipherNextFrame :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Bool -> IO (Either MsgParamError ByteString)
decodeMessageCipherNextFrame fam p pn d dn end =
  bindMessage (decodeMessageParams fam p pn nullPtr 0) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \part ->
    pure (Right (encodeMsgNext (MsgNextCipher (mpParams mp) part end)))

decodeMessageSignNextFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Bool -> IO (Either MsgParamError ByteString)
decodeMessageSignNextFrame p pn d dn end =
  bindMessage (decodeMessageParams MsgSign p pn nullPtr 0) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \part ->
    pure (Right (encodeMsgNext (MsgNextSign (mpParams mp) part end)))

decodeMessageVerifyNextFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageVerifyNextFrame p pn d dn w wn =
  bindMessage (decodeMessageParams MsgVerify p pn nullPtr 0) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \part ->
  bindMessage (copyMessageBytes w wn) $ \bytes ->
    let witness = if w == nullPtr then Nothing else Just bytes
    in pure (Right (encodeMsgNext (MsgNextVerify (mpParams mp) part witness)))

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
