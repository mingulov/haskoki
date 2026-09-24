{- | Message operation lifecycle (pure).

Outer message contexts plus the inner per-message lifecycle, on top
of the classic operation slots. A message init occupies the family's
classic slot ('initMessageOperation'), so message and classic inits
conflict exactly like two classic inits. Within one outer context
any number of messages run: one-shot (@C_XxxMessage@) or multipart
(@C_XxxMessageBegin@ then @C_XxxMessageNext@ one or more times),
each ended correctly, until the outer final (@C_MessageXxxFinal@)
frees the slot.

Dispositions follow PKCS#11 v3.0 sections 5.9\/5.11\/5.14\/5.16, and
differ deliberately from classic-final semantics: a failed message
terminates the MESSAGE and the outer context survives, so the next
message begins without a re-init. Only the outer final frees the
slot. Short-buffered message output stages on the outer common and
replays through 'retryMessageStaged', which likewise keeps the
slot; the classic 'retryStaged' refuses message slots.

Per-family codecs: cipher families bind per-message parameters and
AAD into 'FxMessageCipher'; sign\/verify carry parameters only
(their C signatures have no AAD channel) and end their multipart
messages through the output convention (signature requested\/
witness supplied) rather than an end flag.
-}
module Haskoki.Operation.Message
  ( MsgBegin (..)
  , MsgNext (..)
  , MsgOneShot (..)
  , familyAad
  , lookupMessage
  , messageBuffered
  , planMessageBegin
  , planMessageNext
  , planMessageOneShot
  , finishMessage
  , retryMessageStaged
  , finalizeMessage
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

import Haskoki.Model (SessionState)
import Haskoki.Operation
  ( CipherDir (..)
  , CipherSpec (..)
  , CryptoEffect (..)
  , CryptoResult (..)
  , DataGate (..)
  , MsgFamily (..)
  , MsgInner (..)
  , MsgState (..)
  , SessionOps
  , SlotKind (..)
  , StagedOutput (..)
  , StepDeny (..)
  , StepOutcome (..)
  , TypedError (..)
  , interpretError
  , denyOutcome
  , isUnframedCipher
  , mkDeny
  , gateDataCall
  , insertOp
  , lookupSingle
  , maxBuffered
  , msgFamilyKind
  , removeSingle
  , setStaged
  , stageBytes
  , stagedOf
  , activeMessage
  , commonKey
  , commonMech
  , mkActiveMessage
  , resetToBuffered
  )
import Haskoki.Operation.Cipher (pkcs7Pad, pkcs7Unpad)
import Haskoki.Output (OpDisposition (..), OutputPlan (..), ResultDisposition (..), planOneShot)
import Haskoki.Request (OutputIntent)
import Haskoki.Types (ReturnCode (..))

-- ---------------------------------------------------------------------------
-- Per-message codecs
-- ---------------------------------------------------------------------------

-- | One message-begin: per-message parameters (typically a nonce or
-- IV) plus the AEAD associated data. Sign\/verify families reject
-- nonempty AAD: their C signatures carry no AAD channel.
data MsgBegin = MsgBegin
  { mbParams :: !ByteString
  , mbAad :: !ByteString
  } deriving (Eq, Show)

-- | One message-next part. Cipher families signal the last part
-- with an end flag (@CKF_END_OF_MESSAGE@); sign families signal it
-- by requesting the signature (@pulSignatureLen@ non-null); verify
-- families signal it by supplying the witness (@pSignature@
-- non-null, hence 'mnWitness').
data MsgNext
  = MsgNextCipher
      { mnParams :: !ByteString
      , mnPart :: !ByteString
      , mnEnd :: !Bool
      }
  | MsgNextSign
      { mnParams :: !ByteString
      , mnPart :: !ByteString
      , mnEnd :: !Bool
      }
  | MsgNextVerify
      { mnParams :: !ByteString
      , mnPart :: !ByteString
      , mnWitness :: !(Maybe ByteString)
      }
  deriving (Eq, Show)

-- | One one-shot message: the whole input plus, for verify, the
-- witness. A one-shot begins and terminates a message within the
-- call and is refused in the middle of a multipart message.
data MsgOneShot
  = MsgOneShotCipher
      { moParams :: !ByteString
      , moAad :: !ByteString
      , moInput :: !ByteString
      }
  | MsgOneShotSign
      { moParams :: !ByteString
      , moInput :: !ByteString
      }
  | MsgOneShotVerify
      { moParams :: !ByteString
      , moInput :: !ByteString
      , moWitness :: !ByteString
      }
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- Slot access
-- ---------------------------------------------------------------------------

-- | The active outer message context in one slot, if any.
lookupMessage :: SessionOps -> SlotKind -> Maybe MsgState
lookupMessage ops kind = case lookupSingle ops kind of
  Just active -> activeMessage active
  Nothing -> Nothing

-- | Buffered inner bytes of the open message in one slot, if a
-- message context is active there ('Just 0' while idle).
messageBuffered :: SessionOps -> SlotKind -> Maybe Int
messageBuffered ops kind = case lookupMessage ops kind of
  Nothing -> Nothing
  Just ms -> Just $ case msInner ms of
    MsgIdle -> 0
    MsgOpen _ _ buf -> BS.length buf

-- | Resolve the family's outer context: the slot must hold a
-- message operation of exactly this family. A classic-occupied
-- slot reports the message process as uninitialized (it is: only
-- a message init starts one).
withMessageSlot
  :: SessionOps -> MsgFamily -> Either StepDeny MsgState
withMessageSlot ops fam = case lookupSingle ops kind of
  Nothing -> Left (mkDeny CKR_OPERATION_NOT_INITIALIZED
    "no message operation is active in this slot")
  Just active -> case activeMessage active of
    Just ms
      | msFamily ms == fam -> Right ms
      | otherwise -> Left (mkDeny CKR_GENERAL_ERROR
          "message slot holds the wrong family")
    Nothing -> Left (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "slot holds a classic operation; message calls need a message init")
  where kind = msgFamilyKind fam

-- | Install an outer context back into its family slot.
storeMessage :: SessionOps -> MsgState -> SessionOps
storeMessage ops ms = insertOp (mkActiveMessage ms) ops

-- | Abort the open message: the inner state idles WITHOUT counting
-- a delivery, and the outer context survives. Every message error
-- funnels through here or its no-mutation denies; only the outer
-- final frees the slot.
abortMessage :: MsgState -> MsgState
abortMessage ms = ms { msInner = MsgIdle }

-- | Conclude a fully delivered message: idle the inner state and
-- count the delivery. Short-buffer staging does not conclude.
deliverMessage :: MsgState -> MsgState
deliverMessage ms = ms { msInner = MsgIdle, msMessages = msMessages ms + 1 }

-- | Whether the family carries an AAD channel on its C signatures.
-- Single source for the family AAD rule: the FFI parameter
-- codecs import this predicate instead of mirroring it.
familyAad :: MsgFamily -> Bool
familyAad fam = case fam of
  MsgEncrypt -> True
  MsgDecrypt -> True
  MsgSign -> False
  MsgVerify -> False

-- | AAD policy: cipher families bind any bounded AAD into the
-- planned effect; sign\/verify have no AAD channel and reject it.
checkAad :: MsgFamily -> ByteString -> Either StepDeny ()
checkAad fam aad
  | familyAad fam = Right ()
  | BS.null aad = Right ()
  | otherwise = case fam of
      MsgSign -> Left (mkDeny CKR_ARGUMENTS_BAD
        "sign messages carry no associated data")
      _ -> Left (mkDeny CKR_ARGUMENTS_BAD
        "verify messages carry no associated data")

-- | Per-call parameters override when present: a nonempty 'MsgNext'
-- parameter block replaces the stored one, an empty block keeps it.
nextParams :: ByteString -> ByteString -> ByteString
nextParams stored incoming
  | BS.null incoming = stored
  | otherwise = incoming

-- | Gate one message data call on the outer auth state. A grantless
-- first call on a pending slot terminates the whole outer context
-- (classic late-grant semantics: a later grant finds nothing to
-- spend on); a premature grant denies without consuming.
gateMessage
  :: SessionOps -> SessionState -> MsgState
  -> Either (SessionOps, SessionState, StepOutcome) (SessionOps, SessionState, MsgState)
gateMessage ops st ms =
  let kind = msgFamilyKind (msFamily ms)
  in case gateDataCall st (msCommon ms) of
    GateDeny d term ->
      Left (if term then removeSingle kind ops else ops, st, denyOutcome d)
    GateOk st' sc' -> Right (ops, st', ms { msCommon = sc' })

-- ---------------------------------------------------------------------------
-- Begin
-- ---------------------------------------------------------------------------

-- | Begin one multipart message. The outer context must be idle
-- (no open message, no staged output); argument checks run before
-- the auth gate so a doomed call consumes no grant.
planMessageBegin
  :: SessionOps -> SessionState -> MsgFamily -> MsgBegin
  -> (SessionOps, SessionState, StepOutcome)
planMessageBegin ops st fam begin = case withMessageSlot ops fam of
  Left d -> (ops, st, denyOutcome d)
  Right ms -> case stagedOf (msCommon ms) of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
      "message output staged; retry it before beginning"))
    Nothing -> case msInner ms of
      MsgOpen {} -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
        "a message is already open"))
      MsgIdle -> case checkAad fam (mbAad begin) of
        Left d -> (ops, st, denyOutcome d)
        Right ()
          | BS.length (mbParams begin) > maxBuffered
              || BS.length (mbAad begin) > maxBuffered ->
              (ops, st, denyOutcome (mkDeny CKR_ARGUMENTS_BAD
                "message parameters exceed the buffer bound"))
          | otherwise -> case gateMessage ops st ms of
              Left denied -> denied
              Right (o, s, ms') ->
                ( storeMessage o (ms' { msInner = MsgOpen
                    { miParams = mbParams begin
                    , miAad = mbAad begin
                    , miBuffered = BS.empty
                    } })
                , s
                , StepOutcome CKR_OK [] Nothing ["message begun"] [] Nothing
                )

-- ---------------------------------------------------------------------------
-- Next
-- ---------------------------------------------------------------------------

-- | Feed one message part, continuing or ending the open message.
-- Intermediate parts buffer purely and plan no crypto; the ending
-- part plans the single effect over the concatenation. Any error
-- terminates the open message (the outer context survives) except
-- a ragged unpadded encrypt ending, which keeps the message open
-- so further parts can repair the alignment.
planMessageNext
  :: SessionOps -> SessionState -> MsgFamily -> MsgNext
  -> (SessionOps, SessionState, StepOutcome)
planMessageNext ops st fam next = case (fam, next) of
  (MsgEncrypt, MsgNextCipher params part end) ->
    runCipherNext ops st fam DirEncrypt params part end
  (MsgDecrypt, MsgNextCipher params part end) ->
    runCipherNext ops st fam DirDecrypt params part end
  (MsgSign, MsgNextSign params part end) ->
    runSignNext ops st fam params part end
  (MsgVerify, MsgNextVerify params part witness) ->
    runVerifyNext ops st fam params part witness
  _ -> (ops, st, denyOutcome (mkDeny CKR_ARGUMENTS_BAD
    "per-message codec mismatches the family"))

-- | Cipher next for one direction: buffer the part, or plan the
-- single end effect (padded first for encrypt).
runCipherNext
  :: SessionOps -> SessionState -> MsgFamily -> CipherDir
  -> ByteString -> ByteString -> Bool
  -> (SessionOps, SessionState, StepOutcome)
runCipherNext ops st fam dir params part end = case withMessageSlot ops fam of
  Left d -> (ops, st, denyOutcome d)
  Right ms -> case stagedOf (msCommon ms) of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
      "message output staged; retry it before continuing"))
    Nothing -> case msInner ms of
      MsgIdle -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "no message is open; begin one first"))
      MsgOpen storedPa storedAad buf -> case gateMessage ops st ms of
        Left denied -> denied
        Right (o, s, ms') ->
          let pa = nextParams storedPa params
              buf' = buf <> part
          in if BS.length buf' > maxBuffered
            then ( storeMessage o (abortMessage ms')
                 , s
                 , denyOutcome (mkDeny CKR_ARGUMENTS_BAD
                     "multipart input exceeds the buffer bound"))
            else runEnd o s ms' pa storedAad buf'
  where
    runEnd o s ms' pa aad buf'
      | not end =
          ( storeMessage o (ms' { msInner = MsgOpen pa aad buf' })
          , s
          , StepOutcome CKR_OK [] Nothing
              ["buffered " ++ show (BS.length part)
                ++ " bytes (" ++ show (BS.length buf') ++ " total)"] [] Nothing
          )
      | otherwise = case (dir, msCipher ms') of
          (DirEncrypt, Just spec)
            -- Asymmetric rows skip framing: the backend owns
            -- their length bound.
            | isUnframedCipher (commonMech (msCommon ms')) ->
                ( storeMessage o (ms' { msInner = MsgOpen pa aad buf' })
                , s
                , StepOutcome CKR_OK
                    [FxMessageCipher dir (commonMech sc) (commonKey sc) pa aad buf']
                    Nothing
                    ["message end planned over "
                      ++ show (BS.length buf') ++ " bytes"] [] Nothing
                )
            | csPad spec -> case pkcs7Pad (csBlock spec) buf' of
                Nothing ->
                  ( storeMessage o (abortMessage ms')
                  , s
                  , denyOutcome (mkDeny CKR_GENERAL_ERROR
                      "cipher shape escapes the PKCS#7 range"))
                Just padded ->
                  ( storeMessage o (ms' { msInner = MsgOpen pa aad buf' })
                  , s
                  , StepOutcome CKR_OK
                      [FxMessageCipher dir (commonMech sc) (commonKey sc) pa aad padded]
                      Nothing
                      ["message end planned over "
                        ++ show (BS.length buf') ++ " bytes"] [] Nothing
                  )
            | BS.length buf' `mod` csBlock spec /= 0 ->
                ( storeMessage o (ms' { msInner = MsgOpen pa aad buf' })
                , s
                , denyOutcome (mkDeny CKR_DATA_LEN_RANGE
                    "unpadded encrypt needs block-aligned input"))
            | otherwise ->
                ( storeMessage o (ms' { msInner = MsgOpen pa aad buf' })
                , s
                , StepOutcome CKR_OK
                    [FxMessageCipher dir (commonMech sc) (commonKey sc) pa aad buf']
                    Nothing
                    ["message end planned over "
                      ++ show (BS.length buf') ++ " bytes"] [] Nothing
                )
          (DirDecrypt, Just _) ->
            ( storeMessage o (ms' { msInner = MsgOpen pa aad buf' })
            , s
            , StepOutcome CKR_OK
                [FxMessageCipher dir (commonMech sc) (commonKey sc) pa aad buf']
                Nothing
                ["message end planned over "
                  ++ show (BS.length buf') ++ " bytes"] [] Nothing
            )
          _ ->
            ( storeMessage o (abortMessage ms')
            , s
            , denyOutcome (mkDeny CKR_GENERAL_ERROR
                "message cipher lacks its block shape"))
      where sc = msCommon ms'

-- | Sign next: buffer the part, or plan the single end effect over
-- the concatenation. The end signal is the signature request
-- (@pulSignatureLen@ non-null), carried here as the end flag.
runSignNext
  :: SessionOps -> SessionState -> MsgFamily
  -> ByteString -> ByteString -> Bool
  -> (SessionOps, SessionState, StepOutcome)
runSignNext ops st fam params part end = case withMessageSlot ops fam of
  Left d -> (ops, st, denyOutcome d)
  Right ms -> case stagedOf (msCommon ms) of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
      "message output staged; retry it before continuing"))
    Nothing -> case msInner ms of
      MsgIdle -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "no message is open; begin one first"))
      MsgOpen storedPa _ buf -> case gateMessage ops st ms of
        Left denied -> denied
        Right (o, s, ms') ->
          let pa = nextParams storedPa params
              buf' = buf <> part
              sc = msCommon ms'
          in if BS.length buf' > maxBuffered
            then ( storeMessage o (abortMessage ms')
                 , s
                 , denyOutcome (mkDeny CKR_ARGUMENTS_BAD
                     "multipart input exceeds the buffer bound"))
            else
              ( storeMessage o (ms' { msInner = MsgOpen pa BS.empty buf' })
              , s
              , if end
                then StepOutcome CKR_OK
                  [FxMessageSign (commonMech sc) (commonKey sc) pa buf']
                  Nothing
                  ["message end planned over "
                    ++ show (BS.length buf') ++ " bytes"] [] Nothing
                else StepOutcome CKR_OK [] Nothing
                  ["buffered " ++ show (BS.length part)
                    ++ " bytes (" ++ show (BS.length buf') ++ " total)"] [] Nothing
              )

-- | Verify next: buffer the part, or plan the single end effect
-- over the concatenation plus the supplied witness. An empty
-- witness is invalid without an effect, before the gate (classic
-- mirror): the message ends, the slot survives.
runVerifyNext
  :: SessionOps -> SessionState -> MsgFamily
  -> ByteString -> ByteString -> Maybe ByteString
  -> (SessionOps, SessionState, StepOutcome)
runVerifyNext ops st fam params part witness = case withMessageSlot ops fam of
  Left d -> (ops, st, denyOutcome d)
  Right ms -> case stagedOf (msCommon ms) of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
      "message output staged; retry it before continuing"))
    Nothing -> case msInner ms of
      MsgIdle -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "no message is open; begin one first"))
      MsgOpen storedPa _ buf -> case witness of
        Just wit | BS.null wit ->
          ( storeMessage ops (abortMessage ms)
          , st
          , StepOutcome CKR_SIGNATURE_INVALID [] Nothing ["empty signature"] [] Nothing)
        _ -> case gateMessage ops st ms of
          Left denied -> denied
          Right (o, s, ms') ->
            let pa = nextParams storedPa params
                buf' = buf <> part
            in if BS.length buf' > maxBuffered
              then ( storeMessage o (abortMessage ms')
                   , s
                   , denyOutcome (mkDeny CKR_ARGUMENTS_BAD
                       "multipart input exceeds the buffer bound"))
              else case witness of
                Nothing ->
                  ( storeMessage o (ms' { msInner = MsgOpen pa BS.empty buf' })
                  , s
                  , StepOutcome CKR_OK [] Nothing
                      ["buffered " ++ show (BS.length part)
                        ++ " bytes (" ++ show (BS.length buf') ++ " total)"] [] Nothing
                  )
                Just wit ->
                  ( storeMessage o (ms' { msInner = MsgOpen pa BS.empty buf' })
                  , s
                  , StepOutcome CKR_OK
                      [FxMessageVerify (commonMech (msCommon ms')) (commonKey (msCommon ms'))
                        pa buf' wit]
                      Nothing
                      ["message end planned over "
                        ++ show (BS.length buf') ++ " bytes"] [] Nothing
                  )

-- ---------------------------------------------------------------------------
-- One-shot
-- ---------------------------------------------------------------------------

-- | Run one whole message in a single call. Refused while a
-- multipart message is open or staged; otherwise the message opens
-- pending its finish and the single effect plans immediately.
planMessageOneShot
  :: SessionOps -> SessionState -> MsgFamily -> String -> MsgOneShot
  -> (SessionOps, SessionState, StepOutcome)
planMessageOneShot ops st fam _name one = case (fam, one) of
  (MsgEncrypt, MsgOneShotCipher params aad input) ->
    runCipherOneShot ops st fam DirEncrypt params aad input
  (MsgDecrypt, MsgOneShotCipher params aad input) ->
    runCipherOneShot ops st fam DirDecrypt params aad input
  (MsgSign, MsgOneShotSign params input) ->
    runSignOneShot ops st fam params input
  (MsgVerify, MsgOneShotVerify params input witness) ->
    runVerifyOneShot ops st fam params input witness
  _ -> (ops, st, denyOutcome (mkDeny CKR_ARGUMENTS_BAD
    "per-message codec mismatches the family"))

-- | Cipher one-shot: the input becomes the buffered message the
-- single planned effect runs over. A ragged unpadded encrypt input
-- denies on an idle context (no message opens); an oversize input
-- denies likewise, since the one-shot message begins and
-- terminates within the call.
runCipherOneShot
  :: SessionOps -> SessionState -> MsgFamily -> CipherDir
  -> ByteString -> ByteString -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
runCipherOneShot ops st fam dir params aad input = case withMessageSlot ops fam of
  Left d -> (ops, st, denyOutcome d)
  Right ms -> case stagedOf (msCommon ms) of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
      "message output staged; retry it before a one-shot"))
    Nothing -> case msInner ms of
      MsgOpen {} -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
        "cannot run a one-shot in the middle of a multipart message"))
      MsgIdle -> case checkAad fam aad of
        Left d -> (ops, st, denyOutcome d)
        Right ()
          | BS.length params > maxBuffered
              || BS.length aad > maxBuffered
              || BS.length input > maxBuffered ->
              (ops, st, denyOutcome (mkDeny CKR_ARGUMENTS_BAD
                "one-shot message exceeds the buffer bound"))
          | otherwise -> case gateMessage ops st ms of
              Left denied -> denied
              Right (o, s, ms') -> case (dir, msCipher ms') of
                (DirEncrypt, Just spec)
                  -- Asymmetric rows skip framing: the backend
                  -- owns their length bound.
                  | isUnframedCipher (commonMech (msCommon ms')) ->
                      planEffect o s ms' input
                  | csPad spec -> case pkcs7Pad (csBlock spec) input of
                      Nothing ->
                        (o, s, denyOutcome (mkDeny CKR_GENERAL_ERROR
                          "cipher shape escapes the PKCS#7 range"))
                      Just padded -> planEffect o s ms' padded
                  | BS.length input `mod` csBlock spec /= 0 ->
                      (o, s, denyOutcome (mkDeny CKR_DATA_LEN_RANGE
                        "unpadded encrypt needs block-aligned input"))
                  | otherwise -> planEffect o s ms' input
                (DirDecrypt, Just _) -> planEffect o s ms' input
                _ -> (o, s, denyOutcome (mkDeny CKR_GENERAL_ERROR
                  "message cipher lacks its block shape"))
  where
    planEffect o s ms' effectInput =
      ( storeMessage o (ms' { msInner = MsgOpen params aad input })
      , s
      , StepOutcome CKR_OK
          [FxMessageCipher dir (commonMech sc) (commonKey sc) params aad effectInput]
          Nothing
          ["message one-shot planned over "
            ++ show (BS.length input) ++ " bytes"] [] Nothing
      )
      where sc = msCommon ms'

-- | Sign one-shot: the input becomes the buffered message the
-- single planned effect signs.
runSignOneShot
  :: SessionOps -> SessionState -> MsgFamily -> ByteString -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
runSignOneShot ops st fam params input = case withMessageSlot ops fam of
  Left d -> (ops, st, denyOutcome d)
  Right ms -> case stagedOf (msCommon ms) of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
      "message output staged; retry it before a one-shot"))
    Nothing -> case msInner ms of
      MsgOpen {} -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
        "cannot run a one-shot in the middle of a multipart message"))
      MsgIdle
        | BS.length params > maxBuffered || BS.length input > maxBuffered ->
            (ops, st, denyOutcome (mkDeny CKR_ARGUMENTS_BAD
              "one-shot message exceeds the buffer bound"))
        | otherwise -> case gateMessage ops st ms of
            Left denied -> denied
            Right (o, s, ms') ->
              let sc = msCommon ms'
              in ( storeMessage o (ms' { msInner = MsgOpen params BS.empty input })
                 , s
                 , StepOutcome CKR_OK
                     [FxMessageSign (commonMech sc) (commonKey sc) params input]
                     Nothing
                     ["message one-shot planned over "
                       ++ show (BS.length input) ++ " bytes"] [] Nothing
                 )

-- | Verify one-shot: the single effect over the input plus the
-- witness. An empty witness is invalid without an effect, before
-- the gate: nothing opens, nothing mutates.
runVerifyOneShot
  :: SessionOps -> SessionState -> MsgFamily
  -> ByteString -> ByteString -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
runVerifyOneShot ops st fam params input witness = case withMessageSlot ops fam of
  Left d -> (ops, st, denyOutcome d)
  Right ms -> case stagedOf (msCommon ms) of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
      "message output staged; retry it before a one-shot"))
    Nothing -> case msInner ms of
      MsgOpen {} -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
        "cannot run a one-shot in the middle of a multipart message"))
      MsgIdle
        | BS.null witness ->
            ( ops
            , st
            , StepOutcome CKR_SIGNATURE_INVALID [] Nothing ["empty signature"] [] Nothing)
        | BS.length params > maxBuffered || BS.length input > maxBuffered ->
            (ops, st, denyOutcome (mkDeny CKR_ARGUMENTS_BAD
              "one-shot message exceeds the buffer bound"))
        | otherwise -> case gateMessage ops st ms of
            Left denied -> denied
            Right (o, s, ms') ->
              let sc = msCommon ms'
              in ( storeMessage o (ms' { msInner = MsgOpen params BS.empty input })
                 , s
                 , StepOutcome CKR_OK
                     [FxMessageVerify (commonMech sc) (commonKey sc) params input witness]
                     Nothing
                     ["message one-shot planned over "
                       ++ show (BS.length input) ++ " bytes"] [] Nothing
                 )

-- ---------------------------------------------------------------------------
-- Finish and retry
-- ---------------------------------------------------------------------------

-- | Finish a planned message end or one-shot. Bytes stage through
-- the output planner (a short buffer stages for the message retry
-- and does NOT end the message); any crypto failure or
-- driver-protocol violation terminates the message while the outer
-- context survives for the next message.
finishMessage
  :: MsgFamily -> SessionOps -> SlotKind -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
finishMessage fam ops kind name result intent
  | kind /= msgFamilyKind fam =
      (ops, denyOutcome (mkDeny CKR_ARGUMENTS_BAD
        "slot kind mismatches the message family"))
  | otherwise = case withMessageSlot ops fam of
      Left d -> (ops, denyOutcome d)
      Right ms -> case fam of
        MsgEncrypt -> runFinishBytes ops ms name result intent
        MsgDecrypt -> runFinishDecrypt ops ms name result intent
        MsgSign -> runFinishBytes ops ms name result intent
        MsgVerify -> runFinishVerify ops ms name result

-- | Finish a bytes-producing message (encrypt in slice A): stage
-- the driver bytes, or terminate the message on any failure.
runFinishBytes
  :: SessionOps -> MsgState -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
runFinishBytes ops ms name result intent = case stagedOf (msCommon ms) of
  Just _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
    "message output already staged; use retry"))
  Nothing -> case msInner ms of
    MsgIdle -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "no message output pending"))
    MsgOpen {} -> case result of
      GotBytes out ->
        let (staged, plan, freed) = stageBytes name out intent
            sc = msCommon ms
        in if freed
          then ( storeMessage ops (deliverMessage (ms { msCommon = sc }))
               , StepOutcome CKR_OK [] (Just plan) ["message complete"] [] Nothing)
          else ( storeMessage ops
                   (ms { msCommon = setStaged staged sc })
               , StepOutcome CKR_BUFFER_TOO_SMALL [] (Just plan)
                   ["message output staged; retry with the reported length"] [] Nothing)
      GotValid _ ->
        ( storeMessage ops (abortMessage ms)
        , denyOutcome (mkDeny CKR_GENERAL_ERROR
            "driver answered a message step with a verdict"))
      GotResource _ ->
        ( storeMessage ops (abortMessage ms)
        , denyOutcome (mkDeny CKR_GENERAL_ERROR
            "driver answered a message step with a resource"))
      -- Unreachable via 'toCrypto'; loud on violation.
      GotUnit ->
        ( storeMessage ops (abortMessage ms)
        , denyOutcome (mkDeny CKR_GENERAL_ERROR
            "driver answered a message step with a feed unit"))
      GotCryptoError err ->
        ( storeMessage ops (abortMessage ms)
        , denyOutcome (mkDeny (interpretError (TyCrypto err))
            ("message crypto failed: " ++ show err)))

-- | Finish a decrypt message: strip padding (padded) or check
-- alignment (unpadded), then stage. Corrupt pads, ragged answers,
-- verdict-shaped results, and crypto failures all terminate the
-- message while the outer context survives.
runFinishDecrypt
  :: SessionOps -> MsgState -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
runFinishDecrypt ops ms name result intent = case stagedOf (msCommon ms) of
  Just _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
    "message output already staged; use retry"))
  Nothing -> case msInner ms of
    MsgIdle -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "no message output pending"))
    MsgOpen {} -> case msCipher ms of
      Nothing ->
        ( storeMessage ops (abortMessage ms)
        , denyOutcome (mkDeny CKR_GENERAL_ERROR
            "message cipher lacks its block shape"))
      Just spec -> case result of
        GotBytes raw
          -- Asymmetric rows stage the answer raw.
          | isUnframedCipher (commonMech (msCommon ms)) -> stagePlain raw
          | csPad spec -> case pkcs7Unpad (csBlock spec) raw of
              Just plain -> stagePlain plain
              Nothing ->
                ( storeMessage ops (abortMessage ms)
                , denyOutcome (mkDeny CKR_ENCRYPTED_DATA_INVALID
                    "decrypt padding check failed")
                )
          | BS.length raw `mod` csBlock spec == 0 -> stagePlain raw
          | otherwise ->
              ( storeMessage ops (abortMessage ms)
              , denyOutcome (mkDeny CKR_ENCRYPTED_DATA_LEN_RANGE
                  "unpadded decrypt answer is not block-aligned")
              )
        GotValid _ ->
          ( storeMessage ops (abortMessage ms)
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a message step with a verdict"))
        GotResource _ ->
          ( storeMessage ops (abortMessage ms)
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a message step with a resource"))
        -- Unreachable via 'toCrypto'; loud on violation.
        GotUnit ->
          ( storeMessage ops (abortMessage ms)
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a message step with a feed unit"))
        GotCryptoError err ->
          ( storeMessage ops (abortMessage ms)
          , denyOutcome (mkDeny (interpretError (TyCrypto err))
              ("message crypto failed: " ++ show err)))
  where
    stagePlain plain =
      let (staged, plan, freed) = stageBytes name plain intent
          sc = msCommon ms
      in if freed
        then ( storeMessage ops (deliverMessage (ms { msCommon = sc }))
             , StepOutcome CKR_OK [] (Just plan) ["message complete"] [] Nothing)
        else ( storeMessage ops
                 (ms { msCommon = setStaged staged sc })
             , StepOutcome CKR_BUFFER_TOO_SMALL [] (Just plan)
                 ["message output staged; retry with the reported length"] [] Nothing)

-- | A terminating plan with no output bytes, for verification
-- verdicts: the code plus a single terminating disposition.
verdictPlan :: String -> ReturnCode -> String -> OutputPlan
verdictPlan name code why = OutputPlan
  { opCode = code
  , opWrites = []
  , opLengths = []
  , opDispositions = [ResultDisposition [name] code OpTerminate]
  , opReasons = [why]
  }

-- | Finish a verify message. A valid witness completes, a mismatch
-- reports 'CKR_SIGNATURE_INVALID' (both counted deliveries), and
-- bytes where a verdict belongs are a driver-protocol violation;
-- every path terminates the message while the outer context
-- survives.
runFinishVerify
  :: SessionOps -> MsgState -> String -> CryptoResult
  -> (SessionOps, StepOutcome)
runFinishVerify ops ms name result = case stagedOf (msCommon ms) of
  Just _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
    "message output already staged; use retry"))
  Nothing -> case msInner ms of
    MsgIdle -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "no message output pending"))
    MsgOpen {} -> case result of
      GotValid True ->
        ( storeMessage ops (deliverMessage ms)
        , StepOutcome CKR_OK [] (Just (verdictPlan name CKR_OK "verify valid"))
            ["verify valid"] [] Nothing)
      GotValid False ->
        ( storeMessage ops (deliverMessage ms)
        , StepOutcome CKR_SIGNATURE_INVALID []
            (Just (verdictPlan name CKR_SIGNATURE_INVALID "signature mismatch"))
            ["signature mismatch"] [] Nothing)
      GotBytes _ ->
        ( storeMessage ops (abortMessage ms)
        , denyOutcome (mkDeny CKR_GENERAL_ERROR
            "driver answered a verify step with bytes"))
      GotResource _ ->
        ( storeMessage ops (abortMessage ms)
        , denyOutcome (mkDeny CKR_GENERAL_ERROR
            "driver answered a verify step with a resource"))
      -- Unreachable via 'toCrypto'; loud on violation.
      GotUnit ->
        ( storeMessage ops (abortMessage ms)
        , denyOutcome (mkDeny CKR_GENERAL_ERROR
            "driver answered a verify step with a feed unit"))
      GotCryptoError err ->
        ( storeMessage ops (abortMessage ms)
        , denyOutcome (mkDeny (interpretError (TyCrypto err))
            ("message crypto failed: " ++ show err)))

-- | Retry a staged message output with a fresh intent. Success
-- concludes the message (counted) and keeps the outer context; a
-- still-short buffer keeps the staged bytes again.
retryMessageStaged
  :: MsgFamily -> SessionOps -> SlotKind -> OutputIntent
  -> (SessionOps, StepOutcome)
retryMessageStaged fam ops kind intent
  | kind /= msgFamilyKind fam =
      (ops, denyOutcome (mkDeny CKR_ARGUMENTS_BAD
        "slot kind mismatches the message family"))
  | otherwise = case withMessageSlot ops fam of
      Left d -> (ops, denyOutcome d)
      Right ms -> case stagedOf (msCommon ms) of
        Nothing -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
          "slot holds no staged message output"))
        Just staged ->
          let (st', plan) = planOneShot (stState staged)
                (stName staged) (stBytes staged) intent
              sc = msCommon ms
          in case opCode plan of
            CKR_OK ->
              ( storeMessage ops
                  (deliverMessage (ms { msCommon = resetToBuffered sc }))
              , StepOutcome CKR_OK [] (Just plan) ["message retry complete"] [] Nothing
              )
            _ ->
              ( storeMessage ops
                  (ms { msCommon = setStaged (Just (staged { stState = st' })) sc })
              , StepOutcome (opCode plan) [] (Just plan)
                  ["retry still short; staged output retained"] [] Nothing
              )

-- ---------------------------------------------------------------------------
-- Outer final
-- ---------------------------------------------------------------------------

-- | Finalize the outer message process. The context must be idle:
-- finalizing with an open or staged message is rejected WITHOUT
-- mutation, so the message and the context both survive. An idle
-- context frees its slot.
finalizeMessage :: MsgFamily -> SessionOps -> (SessionOps, StepOutcome)
finalizeMessage fam ops = case withMessageSlot ops fam of
  Left d -> (ops, denyOutcome d)
  Right ms -> case stagedOf (msCommon ms) of
    Just _ -> (ops, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
      "a message output is still staged; retry it before finalizing"))
    Nothing -> case msInner ms of
      MsgOpen {} -> (ops, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
        "a message is still open; end it before finalizing"))
      MsgIdle ->
        ( removeSingle (msgFamilyKind fam) ops
        , StepOutcome CKR_OK [] Nothing ["message process finalized"] [] Nothing
        )
