{- | Request codecs for operation routing (pure).

'Request' carries one opaque input blob; these codecs frame the
structured arguments the operation planners need. Integers are
big-endian; lengths are exact (a short blob rejects, trailing bytes
belong to the documented tail field). Input blobs are already
bounded by 'Haskoki.FFI.Decode.maxInputBytes', so narrowing a
'ByteString' length to 32 bits is exact.

@
init:      mech:u64 permits:u16 flags:u8 params:bytes
verify1:   dlen:u32 data:dlen sig:bytes
begin:     plen:u32 params:plen aad:bytes
next:      tag:u8 ...
  cipher\/sign: plen:u32 params:plen end:u8 part:bytes
  verify:      plen:u32 params:plen wflag:u8 [wlen:u32 witness:wlen] part:bytes
oneshot:   tag:u8 ...
  cipher: plen:u32 params:plen alen:u32 aad:alen input:bytes
  sign:   plen:u32 params:plen input:bytes
  verify: plen:u32 params:plen wlen:u32 witness:wlen input:bytes
@

Permit bits: 0 sign, 1 verify, 2 encrypt, 3 decrypt, 4
sign-recover, 5 verify-recover; bits 6-15 are reserved and must be
zero. Flag bit 0 is always-authenticate; bits 1-7 are reserved and
must be zero. Next\/one-shot tags: 0 cipher, 1 sign, 2 verify, and
decoding is gated on the message family.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.Codec
  ( encodeInitInput
  , decodeInitInput
  , cipherShapeFor
  , encodeVerifyInput
  , decodeVerifyInput
  , encodeMsgBegin
  , decodeMsgBegin
  , encodeMsgNext
  , decodeMsgNext
  , encodeMsgOneShot
  , decodeMsgOneShot
  , encodeCancelInput
  , decodeCancelInput
  ) where

import Control.Monad (guard)
import Data.Bits (shiftL, shiftR, testBit, (.&.), (.|.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (sort)
import Data.Word (Word16, Word32, Word64, Word8)

import Haskoki.Operation.Message (MsgBegin (..), MsgNext (..), MsgOneShot (..))
import Haskoki.Operation.State (CipherSpec (..), MsgFamily (..))
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Registry.Generated
  ( ckm_AES_CBC
  , ckm_AES_CBC_PAD
  , ckm_AES_CCM
  , ckm_AES_CFB1
  , ckm_AES_CFB128
  , ckm_AES_CFB8
  , ckm_AES_CTR
  , ckm_AES_CTS
  , ckm_AES_ECB
  , ckm_AES_OFB
  , ckm_AES_KEY_WRAP
  , ckm_AES_KEY_WRAP_PAD
  , ckm_AES_KEY_WRAP_KWP
  , ckm_AES_GCM
  , ckm_ARIA_CBC
  , ckm_ARIA_ECB
  , ckm_CAMELLIA_CBC
  , ckm_CAMELLIA_ECB
  , ckm_DES3_CBC
  , ckm_DES3_ECB
  , ckm_RSA_PKCS_OAEP
  )

-- ---------------------------------------------------------------------------
-- Integer framing
-- ---------------------------------------------------------------------------

oneByte :: Word64 -> Int -> Word8
oneByte w s = fromIntegral ((w `shiftR` s) .&. 0xFF)

u16be :: Word16 -> ByteString
u16be w = BS.pack [oneByte (fromIntegral w) 8, oneByte (fromIntegral w) 0]

u32be :: Word32 -> ByteString
u32be w = BS.pack
  [ oneByte (fromIntegral w) 24
  , oneByte (fromIntegral w) 16
  , oneByte (fromIntegral w) 8
  , oneByte (fromIntegral w) 0
  ]

u64be :: Word64 -> ByteString
u64be w = BS.pack
  [ oneByte w 56
  , oneByte w 48
  , oneByte w 40
  , oneByte w 32
  , oneByte w 24
  , oneByte w 16
  , oneByte w 8
  , oneByte w 0
  ]

takeN :: Int -> ByteString -> Maybe (ByteString, ByteString)
takeN n bs
  | BS.length bs < n = Nothing
  | otherwise = Just (BS.splitAt n bs)

foldBE :: ByteString -> Word64
foldBE = BS.foldl' (\acc b -> (acc `shiftL` 8) .|. fromIntegral b) 0

takeU8 :: ByteString -> Maybe (Word8, ByteString)
takeU8 bs = case BS.uncons bs of
  Nothing -> Nothing
  Just (b, rest) -> Just (b, rest)

takeU16 :: ByteString -> Maybe (Word16, ByteString)
takeU16 bs = do
  (h, rest) <- takeN 2 bs
  pure (fromIntegral (foldBE h), rest)

takeU32 :: ByteString -> Maybe (Word32, ByteString)
takeU32 bs = do
  (h, rest) <- takeN 4 bs
  pure (fromIntegral (foldBE h), rest)

takeU64 :: ByteString -> Maybe (Word64, ByteString)
takeU64 bs = do
  (h, rest) <- takeN 8 bs
  pure (foldBE h, rest)

checkLen :: Int -> ByteString -> Maybe ()
checkLen n bs
  | BS.length bs < n = Nothing
  | otherwise = Just ()

lenPrefix :: ByteString -> ByteString
lenPrefix p = u32be (fromIntegral (BS.length p)) <> p

takeLenPrefixed :: ByteString -> Maybe (ByteString, ByteString)
takeLenPrefixed bs = do
  (n32, rest0) <- takeU32 bs
  let n = fromIntegral n32
  _ <- checkLen n rest0
  pure (BS.splitAt n rest0)

asFlag :: Word8 -> Maybe Bool
asFlag 0 = Just False
asFlag 1 = Just True
asFlag _ = Nothing

-- ---------------------------------------------------------------------------
-- Init arguments
-- ---------------------------------------------------------------------------

-- | Permit bit assignment (see the module header).
permitBits :: [(Operation, Int)]
permitBits =
  [ (OpSign, 0)
  , (OpVerify, 1)
  , (OpEncrypt, 2)
  , (OpDecrypt, 3)
  , (OpSignRecover, 4)
  , (OpVerifyRecover, 5)
  ]

-- | Frame init arguments: mechanism, key permits, the
-- always-authenticate mark, and opaque mechanism parameters.
encodeInitInput :: MechanismId -> [Operation] -> Bool -> ByteString -> ByteString
encodeInitInput mech permits auth params =
  u64be (unMechanismId mech) <> u16be bits <> BS.singleton flag <> params
  where
    flag = if auth then 1 else 0
    bits = foldr (.|.) 0
      [ (1 :: Word16) `shiftL` n | op <- permits, (o, n) <- permitBits, o == op ]

-- | Parse framed init arguments. Reserved bits must be zero;
-- permits decode in canonical ascending order.
decodeInitInput :: ByteString -> Maybe (MechanismId, [Operation], Bool, ByteString)
decodeInitInput bs = do
  (m64, r1) <- takeU64 bs
  (p16, r2) <- takeU16 r1
  (flags, params) <- takeU8 r2
  guard (p16 .&. 0xFFC0 == 0 && flags .&. 0xFE == 0)
  let ops = sort [op | (op, n) <- permitBits, testBit p16 n]
  pure (MechanismId m64, ops, flags .&. 1 == 1, params)

-- | Cipher shape for a mechanism id. Only reviewed behavior-backed
-- cipher mechanisms carry a shape here (the @CKA_*@ mechanism-info
-- seam is the key manager's scope); anything else is not routable.
-- The id resolves
-- through the generated table (no hand-typed numerics).
-- PAD shares the CBC block with planner-side PKCS#7
-- framing; ECB is the unpadded block with empty params (both rows
-- behavior+real tested; the recipe, driver and finish paths
-- already cover them -- only this gate was missing).
-- The remaining recipe-backed block ciphers (Triple-DES
-- 8-byte blocks, ARIA/Camellia 16-byte blocks; same rationale --
-- every row behavior+real tested with backend KATs). CTR is the
-- unit-width stream shape (any input length, no padding); KWP rows
-- share the unit width (any length >= 1) while KW takes the 8-byte
-- wrap quantum.
-- RSA-OAEP carries the unpadded vestigial width: the operation layer
-- refuses padded specs for OAEP ('Haskoki.Operation.checkShape')
-- and the length bound lives in the backend, so the width never
-- frames bytes (the 'allocateSingle' ShapePlain fallback convention).
cipherShapeFor :: MechanismId -> Maybe CipherSpec
cipherShapeFor (MechanismId m)
  | m == ckm_AES_CBC = Just (CipherSpec 16 False)
  | m == ckm_AES_CBC_PAD = Just (CipherSpec 16 True)
  | m == ckm_AES_CTR = Just (CipherSpec 1 False)
  | m == ckm_AES_CTS = Just (CipherSpec 16 False)
  | m == ckm_AES_CFB128 = Just (CipherSpec 16 False)
  | m == ckm_AES_CFB8 = Just (CipherSpec 16 False)
  | m == ckm_AES_CFB1 = Just (CipherSpec 16 False)
  | m == ckm_AES_OFB = Just (CipherSpec 16 False)
  | m == ckm_AES_KEY_WRAP = Just (CipherSpec 8 False)
  | m == ckm_AES_KEY_WRAP_PAD = Just (CipherSpec 1 False)
  | m == ckm_AES_KEY_WRAP_KWP = Just (CipherSpec 1 False)
  | m == ckm_AES_ECB = Just (CipherSpec 16 False)
  | m == ckm_DES3_CBC = Just (CipherSpec 8 False)
  | m == ckm_DES3_ECB = Just (CipherSpec 8 False)
  | m == ckm_ARIA_CBC = Just (CipherSpec 16 False)
  | m == ckm_ARIA_ECB = Just (CipherSpec 16 False)
  | m == ckm_CAMELLIA_CBC = Just (CipherSpec 16 False)
  | m == ckm_CAMELLIA_ECB = Just (CipherSpec 16 False)
  | m == ckm_RSA_PKCS_OAEP = Just (CipherSpec 16 False)
  | m == ckm_AES_GCM = Just (CipherSpec 1 False)
  | m == ckm_AES_CCM = Just (CipherSpec 1 False)
  | otherwise = Nothing

-- ---------------------------------------------------------------------------
-- Verify one-shot arguments
-- ---------------------------------------------------------------------------

-- | Frame a verify one-shot: the data plus the witness signature.
encodeVerifyInput :: ByteString -> ByteString -> ByteString
encodeVerifyInput dat sig =
  u32be (fromIntegral (BS.length dat)) <> dat <> sig

-- | Parse a framed verify one-shot.
decodeVerifyInput :: ByteString -> Maybe (ByteString, ByteString)
decodeVerifyInput bs = do
  (n32, rest0) <- takeU32 bs
  let n = fromIntegral n32
  _ <- checkLen n rest0
  pure (BS.splitAt n rest0)

-- | Frame session-cancel flags: the CKF_* selector mask as u32be.
encodeCancelInput :: Word32 -> ByteString
encodeCancelInput = u32be

-- | Parse framed session-cancel flags: exactly four bytes, nothing
-- else. A new function id with no legacy byte-carrying callers, so
-- there is no empty-input compat arm — short or long input is
-- malformed.
decodeCancelInput :: ByteString -> Maybe Word32
decodeCancelInput bs = do
  (flags, rest) <- takeU32 bs
  guard (BS.null rest)
  pure flags

-- ---------------------------------------------------------------------------
-- Message arguments
-- ---------------------------------------------------------------------------

-- | Frame a message-begin: per-message parameters plus AAD.
encodeMsgBegin :: MsgBegin -> ByteString
encodeMsgBegin (MsgBegin params aad) = lenPrefix params <> aad

-- | Parse a framed message-begin.
decodeMsgBegin :: ByteString -> Maybe MsgBegin
decodeMsgBegin bs = do
  (params, aad) <- takeLenPrefixed bs
  pure (MsgBegin params aad)

-- | Frame a message-next part.
encodeMsgNext :: MsgNext -> ByteString
encodeMsgNext next = case next of
  MsgNextCipher params part end ->
    BS.singleton 0 <> lenPrefix params <> BS.singleton (if end then 1 else 0) <> part
  MsgNextSign params part end ->
    BS.singleton 1 <> lenPrefix params <> BS.singleton (if end then 1 else 0) <> part
  MsgNextVerify params part mw ->
    BS.singleton 2 <> lenPrefix params <> wit <> part
    where
      wit = case mw of
        Nothing -> BS.singleton 0
        Just w -> BS.singleton 1 <> lenPrefix w

-- | Parse a framed message-next part, gated on the family: a
-- cipher-tagged blob decodes under either cipher family, sign under
-- sign, verify under verify; anything else rejects.
decodeMsgNext :: MsgFamily -> ByteString -> Maybe MsgNext
decodeMsgNext fam bs = do
  (tag, r0) <- takeU8 bs
  case tag of
    0 | fam == MsgEncrypt || fam == MsgDecrypt -> do
      (params, r1) <- takeLenPrefixed r0
      (e, part) <- takeU8 r1
      end <- asFlag e
      pure (MsgNextCipher params part end)
    1 | fam == MsgSign -> do
      (params, r1) <- takeLenPrefixed r0
      (e, part) <- takeU8 r1
      end <- asFlag e
      pure (MsgNextSign params part end)
    2 | fam == MsgVerify -> do
      (params, r1) <- takeLenPrefixed r0
      (wflag, r2) <- takeU8 r1
      case wflag of
        0 -> pure (MsgNextVerify params r2 Nothing)
        1 -> do
          (w, part) <- takeLenPrefixed r2
          pure (MsgNextVerify params part (Just w))
        _ -> Nothing
    _ -> Nothing

-- | Frame a one-shot message.
encodeMsgOneShot :: MsgOneShot -> ByteString
encodeMsgOneShot one = case one of
  MsgOneShotCipher params aad input ->
    BS.singleton 0 <> lenPrefix params <> lenPrefix aad <> input
  MsgOneShotSign params input ->
    BS.singleton 1 <> lenPrefix params <> input
  MsgOneShotVerify params input witness ->
    BS.singleton 2 <> lenPrefix params <> lenPrefix witness <> input

-- | Parse a framed one-shot message, gated on the family.
decodeMsgOneShot :: MsgFamily -> ByteString -> Maybe MsgOneShot
decodeMsgOneShot fam bs = do
  (tag, r0) <- takeU8 bs
  case tag of
    0 | fam == MsgEncrypt || fam == MsgDecrypt -> do
      (params, r1) <- takeLenPrefixed r0
      (aad, input) <- takeLenPrefixed r1
      pure (MsgOneShotCipher params aad input)
    1 | fam == MsgSign -> do
      (params, input) <- takeLenPrefixed r0
      pure (MsgOneShotSign params input)
    2 | fam == MsgVerify -> do
      (params, r1) <- takeLenPrefixed r0
      (witness, input) <- takeLenPrefixed r1
      pure (MsgOneShotVerify params input witness)
    _ -> Nothing
