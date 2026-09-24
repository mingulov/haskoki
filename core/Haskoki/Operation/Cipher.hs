{- | Cipher operation lifecycle (pure).

Multipart sequencing over one encrypt or decrypt slot: updates
buffer purely and plan no crypto; the final plans a single 'FxCipher'
effect. Padding is decided in the pure layer with real PKCS#7
framing: an encrypt final pads before the effect input is fixed, a
decrypt final strips after the driver answers. Every plan-time deny
(ragged one-shot/final, one-shot over buffered input) terminates the
slot — spec: every error other than BUFFER_TOO_SMALL terminates —
as do a corrupt pad and a ragged driver answer at finish time.
-}
module Haskoki.Operation.Cipher
  ( planCipherUpdate
  , planCipherOneShot
  , planCipherFinal
  , finishCipher
  , pkcs7Pad
  , pkcs7Unpad
  ) where

import Control.Monad (guard)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

import Haskoki.Model (SessionState)
import Haskoki.Operation
  ( CipherDir (..)
  , CipherSpec (..)
  , CryptoEffect (..)
  , CryptoResult (..)
  , DataGate (..)
  , SessionOps
  , SlotCommon
  , SlotKind (..)
  , StepDeny (..)
  , StepOutcome (..)
  , appendBuffered
  , TypedError (..)
  , interpretError
  , denyOutcome
  , isUnframedCipher
  , mkDeny
  , gateDataCall
  , insertOp
  , lookupSingle
  , removeSingle
  , setStaged
  , stageBytes
  , stagedOf
  , activeCipher
  , bufferedOf
  , commonKey
  , commonMech
  , commonParams
  , mkActiveCipher
  )
import Haskoki.Registry (MechanismId)
import Haskoki.Request (OutputIntent)
import Haskoki.Types (ReturnCode (..))

-- ---------------------------------------------------------------------------
-- PKCS#7 framing
-- ---------------------------------------------------------------------------

-- | Pad to a multiple of the block width, always adding at least one
-- byte. 'Nothing' for block widths outside the PKCS#7 byte range.
pkcs7Pad :: Int -> ByteString -> Maybe ByteString
pkcs7Pad block bs
  | block < 1 || block > 255 = Nothing
  | otherwise = Just (bs <> BS.replicate n (fromIntegral n))
  where
    n = block - (BS.length bs `mod` block)

-- | Strip PKCS#7 padding, checking the framing strictly: non-empty
-- block-aligned input, a pad length in @1..block@, and every pad byte
-- equal to the length. Anything else is 'Nothing'.
pkcs7Unpad :: Int -> ByteString -> Maybe ByteString
pkcs7Unpad block bs = do
  guard (block >= 1 && block <= 255)
  let len = BS.length bs
  guard (len > 0 && len `mod` block == 0)
  let padByte = BS.index bs (len - 1)
      n = fromIntegral padByte
  guard (n >= 1 && n <= min block len)
  let (plain, pad) = BS.splitAt (len - n) bs
  guard (BS.all (== padByte) pad)
  pure plain

-- ---------------------------------------------------------------------------
-- Slot validation
-- ---------------------------------------------------------------------------

-- | Resolve a cipher slot: the kind must be a cipher kind, the slot
-- must hold a cipher operation, and the direction must match.
withCipherSlot
  :: SessionOps -> SlotKind -> Either StepDeny (CipherDir, SlotCommon, CipherSpec)
withCipherSlot ops kind = do
  dir <- case kind of
    SlotEncrypt -> Right DirEncrypt
    SlotDecrypt -> Right DirDecrypt
    _ -> Left (mkDeny CKR_ARGUMENTS_BAD "not a cipher slot")
  active <- case lookupSingle ops kind of
    Nothing -> Left (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "no cipher operation is active in this slot")
    Just a -> Right a
  case activeCipher active of
    Just (dir', sc, spec)
      | dir' == dir -> Right (dir, sc, spec)
      | otherwise -> Left (mkDeny CKR_GENERAL_ERROR
          "cipher slot holds the wrong direction")
    Nothing -> Left (mkDeny CKR_GENERAL_ERROR
      "cipher slot holds a foreign operation")

-- | The effect input for an encrypt step: padded bytes, or the raw
-- buffer when unpadded (which must already be block-aligned; the
-- denial keeps the slot so later updates can repair it).
-- Asymmetric rows ('isUnframedCipher') skip framing entirely: the
-- backend owns their length bound.
encryptInput :: MechanismId -> CipherSpec -> ByteString -> Either StepDeny ByteString
encryptInput mech spec buf
  | isUnframedCipher mech = Right buf
  | csPad spec = case pkcs7Pad (csBlock spec) buf of
      Just padded -> Right padded
      Nothing -> Left (mkDeny CKR_GENERAL_ERROR
        "cipher shape escapes the PKCS#7 range")
  | BS.length buf `mod` csBlock spec == 0 = Right buf
  | otherwise = Left (mkDeny CKR_DATA_LEN_RANGE
      "unpadded encrypt needs block-aligned input")

-- ---------------------------------------------------------------------------
-- Planners
-- ---------------------------------------------------------------------------

-- | Plan one cipher update: buffer the part. No crypto is planned.
planCipherUpdate
  :: SessionOps -> SessionState -> SlotKind -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
planCipherUpdate ops st kind part = case withCipherSlot ops kind of
  Left d -> (ops, st, denyOutcome d)
  Right (dir, sc, spec) -> case stagedOf sc of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "cipher operation is finalized; retry the staged output instead"))
    Nothing -> case gateDataCall st sc of
      GateDeny d term ->
        (if term then removeSingle kind ops else ops, st, denyOutcome d)
      GateOk st' sc' -> case appendBuffered sc' part of
        Left d -> (removeSingle kind ops, st', denyOutcome d)
        Right sc'' ->
          ( insertOp (mkActiveCipher dir sc'' spec) ops
          , st'
          , StepOutcome CKR_OK [] Nothing
              ["buffered " ++ show (BS.length part)
                ++ " bytes (" ++ show (BS.length (bufferedOf sc''))
                ++ " total)"] [] Nothing
          )

-- | Plan a cipher one-shot over the full input. Allowed only before
-- any update. One-shot denies terminate the slot (spec: every error
-- other than BUFFER_TOO_SMALL terminates); a re-init, not a final,
-- follows a denied one-shot.
planCipherOneShot
  :: SessionOps -> SessionState -> SlotKind -> String -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
planCipherOneShot ops st kind _name input = case withCipherSlot ops kind of
  Left d -> (ops, st, denyOutcome d)
  Right (dir, sc, spec) -> case stagedOf sc of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "cipher operation is finalized; retry the staged output instead"))
    Nothing
      | not (BS.null (bufferedOf sc)) ->
          (removeSingle kind ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
            "multipart input already buffered; re-init to continue"))
      | otherwise -> case gateDataCall st sc of
          GateDeny d term ->
            (if term then removeSingle kind ops else ops, st, denyOutcome d)
          GateOk st' sc' -> case dir of
            DirEncrypt -> case encryptInput (commonMech sc') spec input of
              Left d -> (removeSingle kind ops, st', denyOutcome d)
              Right padded -> runOneShot ops st' kind dir sc' spec input padded
            DirDecrypt -> runOneShot ops st' kind dir sc' spec input input
  where
    runOneShot o s k d sc' spec raw effectInput =
      case appendBuffered sc' raw of
        Left deny -> (removeSingle k o, s, denyOutcome deny)
        Right sc'' ->
          ( insertOp (mkActiveCipher d sc'' spec) o
          , s
          , StepOutcome CKR_OK
              [FxCipher d (commonMech sc'') (commonKey sc'') (commonParams sc'') effectInput]
              Nothing
              ["cipher one-shot planned over " ++ show (BS.length raw) ++ " bytes"] [] Nothing
          )

-- | Plan a cipher final: one effect over the buffered input (padded
-- first for encrypt). The buffer is retained until the finisher runs.
planCipherFinal
  :: SessionOps -> SessionState -> SlotKind -> String
  -> (SessionOps, SessionState, StepOutcome)
planCipherFinal ops st kind _name = case withCipherSlot ops kind of
  Left d -> (ops, st, denyOutcome d)
  Right (dir, sc, spec) -> case stagedOf sc of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "cipher operation is finalized; retry the staged output instead"))
    Nothing -> case gateDataCall st sc of
      GateDeny d term ->
        (if term then removeSingle kind ops else ops, st, denyOutcome d)
      GateOk st' sc' -> case dir of
        DirEncrypt -> case encryptInput (commonMech sc') spec (bufferedOf sc') of
          Left d -> (removeSingle kind ops, st', denyOutcome d)
          Right padded ->
            ( insertOp (mkActiveCipher dir sc' spec) ops
            , st'
            , StepOutcome CKR_OK
                [FxCipher dir (commonMech sc') (commonKey sc') (commonParams sc') padded]
                Nothing
                ["cipher final planned over "
                  ++ show (BS.length (bufferedOf sc')) ++ " bytes"] [] Nothing
            )
        DirDecrypt ->
          ( insertOp (mkActiveCipher dir sc' spec) ops
          , st'
          , StepOutcome CKR_OK
              [FxCipher dir (commonMech sc') (commonKey sc') (commonParams sc') (bufferedOf sc')]
              Nothing
              ["cipher final planned over "
                ++ show (BS.length (bufferedOf sc')) ++ " bytes"] [] Nothing
          )

-- | Finish a planned cipher final or one-shot. Encrypt stages the
-- driver bytes; decrypt strips padding (padded) or checks alignment
-- (unpadded). Corrupt pads, ragged answers, verdict-shaped results,
-- and crypto failures all terminate the slot.
finishCipher
  :: SessionOps -> SlotKind -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
finishCipher ops kind name result intent = case withCipherSlot ops kind of
  Left d -> (ops, denyOutcome d)
  Right (dir, sc, spec) -> case stagedOf sc of
    Just _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
      "cipher output already staged; use retry"))
    Nothing ->
      let stageRaw bytes =
            let (staged, plan, freed) = stageBytes name bytes intent
            in if freed
              then (removeSingle kind ops
                   , StepOutcome CKR_OK [] (Just plan) ["cipher step complete"] [] Nothing)
              else ( insertOp
                       (mkActiveCipher dir (setStaged staged sc) spec) ops
                   , StepOutcome CKR_BUFFER_TOO_SMALL [] (Just plan)
                       ["cipher output staged; retry with the reported length"] [] Nothing)
      in case result of
        GotBytes raw -> case dir of
          DirEncrypt -> stageRaw raw
          DirDecrypt
            | isUnframedCipher (commonMech sc) -> stageRaw raw
            | csPad spec -> case pkcs7Unpad (csBlock spec) raw of
                Just plain -> stageRaw plain
                Nothing ->
                  ( removeSingle kind ops
                  , denyOutcome (mkDeny CKR_ENCRYPTED_DATA_INVALID
                      "decrypt padding check failed")
                  )
            | BS.length raw `mod` csBlock spec == 0 -> stageRaw raw
            | otherwise ->
                ( removeSingle kind ops
                , denyOutcome (mkDeny CKR_ENCRYPTED_DATA_LEN_RANGE
                    "unpadded decrypt answer is not block-aligned")
                )
        GotValid _ ->
          ( removeSingle kind ops
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a cipher step with a verdict"))
        GotResource _ ->
          ( removeSingle kind ops
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a cipher step with a resource"))
        -- Unreachable via 'toCrypto' (which never produces
        -- 'GotUnit'); loud failure if the driver protocol is ever
        -- violated.
        GotUnit ->
          ( removeSingle kind ops
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a cipher step with a feed unit"))
        GotCryptoError err ->
          ( removeSingle kind ops
          , denyOutcome (mkDeny (interpretError (TyCrypto err))
              ("cipher crypto failed: " ++ show err)))
