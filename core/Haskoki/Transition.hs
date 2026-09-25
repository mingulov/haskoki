{- | Pure transitions: plan, finish, publish.

Binding signatures (architecture section 5):

@
planCall
  :: Rules -> Model -> Request -> PlanResult
finishEffect
  :: Rules -> Model -> Reservation -> EngineResult
  -> Either Rejection PreparedCommit
publishDelta
  :: Model -> StateDelta -> Either ModelFault Model
@
-}
module Haskoki.Transition
  ( planCall
  , planDecoded
  , finishEffect
  , publishDelta
  , reservationStale
  , toCryptoError
  -- | Exposed for the white-box scope pin (the silent-step
  -- arm is unreachable for foreign functions through 'planCall',
  -- by construction).
  , packStep
  -- | Exposed for the finisher-coverage pin: the regression
  -- test asserts the exact Just-set over all 'FunctionId's.
  , runFinisher
  ) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map

import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , lookupObject
  , lookupSession
  , lookupTokenAuth
  , nextRevision
  , sessionsOnSlot
  )
import Haskoki.Outcome
  ( BackendFailure (..)
  , CryptoStep (..)
  , DeltaOp (..)
  , EffectRequest (EffectCrypto)
  , EngineResult (..)
  , ModelFault (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , Reservation (..)
  , ResourceRelease (..)
  , RevisionDep (..)
  , StateDelta (..)
  )
import Haskoki.Object
  ( objectPrivate
  , objectToken
  , parseTemplate
  , parseWanted
  , planCopyObject
  , planCreateObject
  , planDestroyObject
  , planFindObjects
  , planGetAttributes
  , planSetAttributes
  )
import Haskoki.Operation
  ( CipherSpec
  , CryptoEffect (..)
  , CryptoError (..)
  , CryptoResult (..)
  , DigestStream (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , MsgFamily (..)
  , OpEnv (..)
  , SessionOps
  , SlotKind (..)
  , StepOutcome (..)
  , activeDigest
  , commonOf
  , emptySessionOps
  , initMessageOperation
  , initOperation
  , lookupSingle
  , msgFamilyKind
  , msgFamilyOp
  , retryStaged
  , stagedOf
  , streamOf
  )
import Haskoki.Operation.Cipher
  ( finishCipher
  , planCipherFinal
  , planCipherOneShot
  , planCipherUpdate
  )
import Haskoki.Operation.Codec
  ( cipherShapeFor
  , decodeInitInput
  , decodeMsgBegin
  , decodeMsgNext
  , decodeMsgOneShot
  , decodeVerifyInput
  )
import Haskoki.Operation.Digest
  ( finishDigest
  , finishDigestFeed
  , finishDigestInit
  , planDigestFinal
  , planDigestOneShot
  , planDigestUpdate
  )
import Haskoki.Operation.Message
  ( finalizeMessage
  , finishMessage
  , planMessageBegin
  , planMessageNext
  , planMessageOneShot
  , retryMessageStaged
  )
import Haskoki.Operation.Signature
  ( finishSign
  , finishVerify
  , planSignFinal
  , planSignOneShot
  , planSignUpdate
  , planVerifyFinal
  , planVerifyOneShot
  , planVerifyUpdate
  )
import Haskoki.Output (OutputPlan (..), TypedWrite (..), typedWriteBytes)
import Haskoki.Registry (MechanismId, Operation (..))
import Haskoki.Request
  ( DecodedRequest (..)
  , FunctionId (..)
  , InitFunction (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  , initFunctionId
  )
import qualified Haskoki.Request as Req (initOperation)
import Haskoki.Rules (Rules (..))
import Haskoki.Session
  ( ActiveLogin (..)
  , AdmitDeny (..)
  , LoginKind (..)
  , LoginOutcome (..)
  , SessionLogin (..)
  , TokenAuth (taLogin)
  , admitCode
  , admitObjects
  , admitSession
  , closeSessionAuth
  , denyCode
  , loginAttempt
  , logoutToken
  , parseLoginArgs
  , parseOpenArgs
  )
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

-- | Plan one call against the model. Session-scoped functions with an
-- unknown session reject with no fabricated output and no mutation.
-- Lifecycle calls (open/close/login/logout) commit immediately: they
-- are pure state transitions with no engine effect.
planCall :: Rules -> Model -> Request -> PlanResult
planCall rules model req = case reqFunction req of
  F_GetInfo -> Immediate okEmpty
  F_GetSlotList -> Immediate okEmpty
  F_GetSessionInfo -> withSession $ \_st -> Immediate okEmpty
  F_OpenSession -> planOpenSession rules model req
  F_CloseSession -> withSession $ \st -> planCloseSession model st
  F_Login -> withSession $ \st -> planLogin rules model req st
  F_Logout -> withSession $ \st -> planLogout model st
  -- Legacy-bytes compat decode (see F_CreateObject).
  F_DigestInit -> withSession $ planInitCompat rules model req InitDigest
  F_Digest -> withSession $ planRetryable req SlotDigest
    (\ops st -> planDigestOneShot ops st "" (reqInput req))
    (retryFor SlotDigest)
  F_SignInit -> withSession $ planInitCompat rules model req InitSign
  F_Sign -> withSession $ planRetryable req SlotSign
    (\ops st -> planSignOneShot ops st "" (reqInput req))
    (retryFor SlotSign)
  F_DigestUpdate -> withSession $ planData req SlotDigest $ \ops st ->
    planDigestUpdate ops st (reqInput req)
  F_DigestFinal -> withSession $ planRetryable req SlotDigest
    (\ops st -> planDigestFinal ops st "")
    (retryFor SlotDigest)
  F_SignUpdate -> withSession $ planData req SlotSign $ \ops st ->
    planSignUpdate ops st (reqInput req)
  F_SignFinal -> withSession $ planRetryable req SlotSign
    (\ops st -> planSignFinal ops st "")
    (retryFor SlotSign)
  F_VerifyInit -> withSession $ planInitCompat rules model req InitVerify
  F_Verify -> withSession $ \st -> case decodeVerifyInput (reqInput req) of
    Nothing -> badArgs "malformed verify input"
    Just (dat, sig) -> planOutput req SlotVerify
      (\ops s -> planVerifyOneShot ops s "" dat sig) st
  F_VerifyUpdate -> withSession $ planData req SlotVerify $ \ops st ->
    planVerifyUpdate ops st (reqInput req)
  F_VerifyFinal -> withSession $ planOutput req SlotVerify $ \ops st ->
    planVerifyFinal ops st "" (reqInput req)
  F_EncryptInit -> withSession $ planInitCompat rules model req InitEncrypt
  F_Encrypt -> withSession $ planRetryable req SlotEncrypt
    (\ops st -> planCipherOneShot ops st SlotEncrypt "" (reqInput req))
    (retryFor SlotEncrypt)
  F_EncryptUpdate -> withSession $ planData req SlotEncrypt $ \ops st ->
    planCipherUpdate ops st SlotEncrypt (reqInput req)
  F_EncryptFinal -> withSession $ planRetryable req SlotEncrypt
    (\ops st -> planCipherFinal ops st SlotEncrypt "")
    (retryFor SlotEncrypt)
  F_DecryptInit -> withSession $ planInitCompat rules model req InitDecrypt
  F_Decrypt -> withSession $ planRetryable req SlotDecrypt
    (\ops st -> planCipherOneShot ops st SlotDecrypt "" (reqInput req))
    (retryFor SlotDecrypt)
  F_DecryptUpdate -> withSession $ planData req SlotDecrypt $ \ops st ->
    planCipherUpdate ops st SlotDecrypt (reqInput req)
  F_DecryptFinal -> withSession $ planRetryable req SlotDecrypt
    (\ops st -> planCipherFinal ops st SlotDecrypt "")
    (retryFor SlotDecrypt)
  F_MessageEncryptInit -> withSession $ planMessageInit rules model req MsgEncrypt
  F_MessageDecryptInit -> withSession $ planMessageInit rules model req MsgDecrypt
  F_MessageSignInit -> withSession $ planMessageInit rules model req MsgSign
  F_MessageVerifyInit -> withSession $ planMessageInit rules model req MsgVerify
  F_EncryptMessage -> withSession $ planMsgOneShot req MsgEncrypt
  F_DecryptMessage -> withSession $ planMsgOneShot req MsgDecrypt
  F_SignMessage -> withSession $ planMsgOneShot req MsgSign
  F_VerifyMessage -> withSession $ planMsgOneShot req MsgVerify
  F_EncryptMessageBegin -> withSession $ planMsgBegin req MsgEncrypt
  F_DecryptMessageBegin -> withSession $ planMsgBegin req MsgDecrypt
  F_SignMessageBegin -> withSession $ planMsgBegin req MsgSign
  F_VerifyMessageBegin -> withSession $ planMsgBegin req MsgVerify
  F_EncryptMessageNext -> withSession $ planMsgNext req MsgEncrypt
  F_DecryptMessageNext -> withSession $ planMsgNext req MsgDecrypt
  F_SignMessageNext -> withSession $ planMsgNext req MsgSign
  F_VerifyMessageNext -> withSession $ planMsgNext req MsgVerify
  F_MessageEncryptFinal -> withSession $ planMsgFinal req MsgEncrypt
  F_MessageDecryptFinal -> withSession $ planMsgFinal req MsgDecrypt
  F_MessageSignFinal -> withSession $ planMsgFinal req MsgSign
  F_MessageVerifyFinal -> withSession $ planMsgFinal req MsgVerify
  -- Legacy-bytes compat decode — the ONE decode of
  -- 'reqInput' for byte-carrying callers (a genuine representation
  -- boundary); admission now runs after decode (parse-first:
  -- full store + malformed bytes refuses ARGUMENTS_BAD, fail-safe
  -- either way).
  F_CreateObject -> withSession $ \st ->
    case parseTemplate (reqInput req) of
      Nothing -> badArgs "malformed create-object template"
      Just tmpl -> planDecoded rules model (DRCreateObject (ssId st) tmpl)
  F_DestroyObject -> withSession $ \st -> case reqHandle req of
    Nothing -> badArgs "destroy requires an object handle"
    Just h -> planDestroyObject model st h
  -- Legacy-bytes compat decode (see F_CreateObject);
  -- decode precedes admission (parse-first).
  F_CopyObject -> withSession $ \st ->
    case (reqHandle req, parseTemplate (reqInput req)) of
      (Just h, Just tmpl) -> planDecoded rules model (DRCopyObject (ssId st) h tmpl)
      (Nothing, _) -> badArgs "copy requires an object handle"
      (_, Nothing) -> badArgs "malformed copy-object template"
  -- Legacy-bytes compat decode (see F_CreateObject).
  F_FindObjects -> withSession $ \st -> case parseTemplate (reqInput req) of
    Nothing -> badArgs "malformed find template"
    Just tmpl -> planDecoded rules model (DRFindObjects (ssId st) tmpl)
  -- Legacy-bytes compat decode (see F_CreateObject).
  F_GetAttributeValue -> withSession $ \st ->
    case (reqHandle req, parseWanted (reqInput req)) of
      (Just h, Just wanted) -> planDecoded rules model (DRGetAttributeValue (ssId st) h wanted)
      (Nothing, _) -> badArgs "get-attributes requires an object handle"
      (_, Nothing) -> badArgs "malformed wanted-attribute list"
  -- Legacy-bytes compat decode (see F_CreateObject);
  -- decode precedes admission (parse-first).
  F_SetAttributeValue -> withSession $ \st ->
    case (reqHandle req, parseTemplate (reqInput req)) of
      (Just h, Just tmpl) -> planDecoded rules model (DRSetAttributeValue (ssId st) h tmpl)
      (Nothing, _) -> badArgs "set-attributes requires an object handle"
      (_, Nothing) -> badArgs "malformed set-attributes template"
  where
    withSession :: (SessionState -> PlanResult) -> PlanResult
    withSession k = case reqSession req of
      Nothing -> missingSession
      Just sid -> case lookupSession model sid of
        Nothing -> missingSession
        Just st -> k st
    okEmpty :: PreparedCommit
    okEmpty = PreparedCommit
      { pcCode = CKR_OK
      , pcDelta = StateDelta []
      , pcPersist = []
      , pcOutputs = []
      , pcReleases = []
      , pcReasons = []
      }

-- | Reject for an unknown session (shared by 'planCall' and
-- 'planDecoded'): no fabricated output, no mutation.
missingSession :: PlanResult
missingSession = Reject Rejection
  { rejCode = CKR_SESSION_HANDLE_INVALID
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = ["unknown session"]
  }

-- | Reject malformed arguments (shared by 'planCall' and
-- 'planDecoded'): malformed requests never touch state.
badArgs :: String -> PlanResult
badArgs why = Reject Rejection
  { rejCode = CKR_ARGUMENTS_BAD
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = [why]
  }

-- | Reject an admission denial (shared by 'planCall' and
-- 'planDecoded').
admissionDenied :: AdmitDeny -> PlanResult
admissionDenied deny = Reject Rejection
  { rejCode = admitCode deny
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = ["admission denied: " ++ show deny]
  }

-- | Run a decoded step against a known session id: unknown
-- sessions reject exactly as 'planCall' would.
withSessionSid :: Model -> SessionId -> (SessionState -> PlanResult) -> PlanResult
withSessionSid model sid k = case lookupSession model sid of
  Nothing -> missingSession
  Just st -> k st

-- | Plan one decoded request: the domain payload arrives
-- already decoded and validated, so this entry never parses
-- 'reqInput' — byte decoding happens only at genuine
-- representation boundaries (the FFI frame decoders, the wire
-- codecs, and 'planCall''s legacy-bytes compat arms). Session
-- lookup precedes admission, exactly as in 'planCall'.
planDecoded :: Rules -> Model -> DecodedRequest -> PlanResult
planDecoded rules model dreq = case dreq of
  DRCreateObject sid tmpl -> withSessionSid model sid $ \st ->
    case admitObjects rules (Map.size (mObjects model)) 1 of
      Left deny -> admissionDenied deny
      Right () -> planCreateObject model st tmpl
  DRCopyObject sid h tmpl -> withSessionSid model sid $ \st ->
    case admitObjects rules (Map.size (mObjects model)) 1 of
      Left deny -> admissionDenied deny
      Right () -> planCopyObject model st h tmpl
  DRFindObjects sid tmpl -> withSessionSid model sid $ \st ->
    planFindObjects model st tmpl
  DRGetAttributeValue sid h wanted -> withSessionSid model sid $ \st ->
    planGetAttributes model st h wanted
  DRSetAttributeValue sid h tmpl -> withSessionSid model sid $ \st ->
    planSetAttributes model st h tmpl
  -- Plan a classic init from decoded arguments: validate against
  -- the registry, capabilities, and key binding, and persist the
  -- slot immediately. A denied init allocates nothing, so its
  -- delta is empty. Digest inits allocate the backend
  -- stream through an effect instead: the finisher records the
  -- resource on the slot.
  DRInit sid ifunc mkey mech permits auth params ->
    withSessionSid model sid $ \st ->
      let op = Req.initOperation ifunc
          func = initFunctionId ifunc
      in case cipherShapeArg op mech of
        Nothing -> Reject Rejection
          { rejCode = CKR_MECHANISM_INVALID
          , rejOutputs = []
          , rejDelta = StateDelta []
          , rejReleases = []
          , rejReasons = ["no cipher shape for mechanism"]
          }
        Just cshape ->
          let key = fmap (\h -> KeyPolicy h permits auth) mkey
              args = InitArgs op mech params key cshape Nothing
              env = OpEnv (rulesRegistry rules) (rulesCaps rules) model
              (ops', outcome) = initOperation env (ssOps st) st args
          in if ioCode outcome /= CKR_OK
            then Reject Rejection
              { rejCode = ioCode outcome
              , rejOutputs = []
              , rejDelta = StateDelta []
              , rejReleases = []
              , rejReasons = ioReasons outcome
              }
            else if op == OpDigest
              then Execute
                (Reservation
                  { resOperation = "digest"
                  , resDeps = [DepSession (ssId st) (ssRevision st) (ssGeneration st)]
                  , resResource = Nothing
                  , resStep = Just (CryptoStep func SlotDigest ""
                      (IntentBuffer 0) ops' st)
                  })
                (EffectCrypto (FxDigestInit mech))
              else Immediate PreparedCommit
                { pcCode = CKR_OK
                , pcDelta = StateDelta [DeltaSetSessionOps (ssId st) ops']
                , pcPersist = []
                , pcOutputs = []
                , pcReleases = []
                , pcReasons = ioReasons outcome
                }

-- | Legacy-bytes compat for one classic init shape: the
-- ONE decode of 'reqInput' for byte-carrying callers, then dispatch
-- to 'planDecoded'. The request handle (if any) rides through
-- untouched, exactly as the original init planner read it.
planInitCompat :: Rules -> Model -> Request -> InitFunction -> SessionState -> PlanResult
planInitCompat rules model req ifunc st = case decodeInitInput (reqInput req) of
  Nothing -> badArgs "malformed init arguments"
  Just (mech, permits, auth, params) ->
    planDecoded rules model (DRInit (ssId st) ifunc (reqHandle req) mech permits auth params)

-- | Plan OpenSession: decode @(slot, read-only)@ from the input,
-- admit against token presence, the session bound, and the SO/RO
-- exclusion, then commit the open immediately. The new session id is
-- allocated deterministically from the model counter.
planOpenSession :: Rules -> Model -> Request -> PlanResult
planOpenSession rules model req =
  case parseOpenArgs (reqInput req) of
    Nothing -> badArgs "malformed open-session arguments"
    Just (slot, readOnly) ->
      let mAuth = lookupTokenAuth model slot
          openCount = Map.size (mSessions model)
      in case admitSession rules mAuth openCount readOnly of
        Left deny -> Reject Rejection
          { rejCode = admitCode deny
          , rejOutputs = []
          , rejDelta = StateDelta []
          , rejReleases = []
          , rejReasons = ["admission denied: " ++ show deny]
          }
        Right () ->
          let sid = SessionId (mNextSession model)
          in Immediate PreparedCommit
            { pcCode = CKR_OK
            , pcDelta = StateDelta [DeltaOpenSession sid slot readOnly]
            , pcPersist = []
            , pcOutputs = []
            , pcReleases = []
            , pcReasons = ["opened session " ++ show sid]
            }

-- | Releases for the session's live digest stream, if any
-- (closing a session mid-stream drains its backend context
-- instead of leaking it).
streamReleases :: SessionOps -> [ResourceRelease]
streamReleases ops = case lookupSingle ops SlotDigest of
  Just active -> case activeDigest active of
    Just sc -> case streamOf sc of
      Just ds -> [ReleaseEngineResource (dsResource ds)]
      Nothing -> []
    Nothing -> []
  Nothing -> []

-- | Plan CloseSession: remove the session and destroy its session
-- objects (ownership, not visibility, decides destruction); when it
-- is the last session on its slot, the token logs out
-- (last-session-close logout rule) in the same atomic delta.
planCloseSession :: Model -> SessionState -> PlanResult
planCloseSession model st =
  let slot = ssSlot st
      remaining = length (sessionsOnSlot model slot) - 1
      closeOp = DeltaCloseSession (ssId st)
      ops = case lookupTokenAuth model slot of
        Nothing -> [closeOp]
        Just auth -> closeOp : logoutOps
          where
            auth' = closeSessionAuth auth remaining
            logoutOps
              | auth' /= auth = [DeltaSetTokenAuth slot auth']
              | otherwise = []
      destroys =
        [ DeltaDestroyObject oid
        | (oid, ost) <- Map.toAscList (mObjects model)
        , osOwner ost == Just (ssId st)
        ]
  in Immediate PreparedCommit
    { pcCode = CKR_OK
    , pcDelta = StateDelta (ops ++ destroys)
    , pcPersist = []
    , pcOutputs = []
    , pcReleases = streamReleases (ssOps st)
    , pcReasons = ["closed session " ++ show (ssId st)]
    }

-- | Plan Login: decode @(kind, principal, PIN verdict)@, run the
-- attempt, and commit. A denied attempt still persists its counter
-- movement (a rejection carrying a state delta); a token-wide grant
-- updates every session on the slot so a login through A is visible
-- through B, while a context grant touches only the calling session.
planLogin :: Rules -> Model -> Request -> SessionState -> PlanResult
planLogin rules model req st =
  case parseLoginArgs (reqInput req) of
    Nothing -> badArgs "malformed login arguments"
    Just (kind, mName, pin) ->
      let slot = ssSlot st
      in case lookupTokenAuth model slot of
        Nothing -> Reject Rejection
          { rejCode = CKR_TOKEN_NOT_PRESENT
          , rejOutputs = []
          , rejDelta = StateDelta []
          , rejReleases = []
          , rejReasons = ["no token in slot"]
          }
        Just auth ->
          let roExists = any ssReadOnly (sessionsOnSlot model slot)
          in case loginAttempt rules auth roExists kind mName pin of
            LoginDenied deny auth' -> Reject Rejection
              { rejCode = denyCode deny
              , rejOutputs = []
              , rejDelta = StateDelta (counterOps slot auth auth')
              , rejReleases = []
              , rejReasons = ["login denied: " ++ show deny]
              }
            LoginGranted auth' granted ->
              let others = case kind of
                    LoginAsContext -> [ssId st]
                    _ -> map ssId (sessionsOnSlot model slot)
                  ops = DeltaSetTokenAuth slot auth'
                    : map (`DeltaSetSessionLogin` granted) others
              in Immediate PreparedCommit
                { pcCode = CKR_OK
                , pcDelta = StateDelta ops
                , pcPersist = []
                , pcOutputs = []
                , pcReleases = []
                , pcReasons = ["login granted: " ++ show kind]
                }
  where
    counterOps slot before after
      | before /= after = [DeltaSetTokenAuth slot after]
      | otherwise = []

-- | Plan Logout: clear the token login, return every session on
-- the slot to public, and stale-mark every handle bound to a live
-- private object on the slot. Invalidated handles never resurrect:
-- a later login mints fresh bindings through discovery. Logging
-- out a public token rejects with 'CKR_USER_NOT_LOGGED_IN' and no
-- mutation.
planLogout :: Model -> SessionState -> PlanResult
planLogout model st =
  let slot = ssSlot st
  in case lookupTokenAuth model slot of
    Nothing -> Reject Rejection
      { rejCode = CKR_TOKEN_NOT_PRESENT
      , rejOutputs = []
      , rejDelta = StateDelta []
      , rejReleases = []
      , rejReasons = ["no token in slot"]
      }
    Just auth -> case logoutToken auth of
      (_, False) -> Reject Rejection
        { rejCode = CKR_USER_NOT_LOGGED_IN
        , rejOutputs = []
        , rejDelta = StateDelta []
        , rejReleases = []
        , rejReasons = ["token not logged in"]
        }
      (auth', True) ->
        let ops = DeltaSetTokenAuth slot auth'
              : map ((`DeltaSetSessionLogin` LoginPublic) . ssId)
                    (sessionsOnSlot model slot)
              ++ map DeltaBumpHandle (privateHandlesOnSlot model slot)
        in Immediate PreparedCommit
          { pcCode = CKR_OK
          , pcDelta = StateDelta ops
          , pcPersist = []
          , pcOutputs = []
          , pcReleases = []
          , pcReasons = ["logout"]
          }

-- | Handles bound to live private objects on a slot, ascending.
privateHandlesOnSlot :: Model -> SlotId -> [ExternalHandle]
privateHandlesOnSlot model slot =
  [ h
  | (h, b) <- Map.toAscList (mHandles model)
  , Just ost <- [Map.lookup (hbObject b) (mObjects model)]
  , osSlot ost == slot
  , objectPrivate ost
  ]

-- ---------------------------------------------------------------------------
-- Operation routing
-- ---------------------------------------------------------------------------

-- | Reject a malformed routed call. Malformed requests never touch state.
rejectArgs :: String -> PlanResult
rejectArgs why = Reject Rejection
  { rejCode = CKR_ARGUMENTS_BAD
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = [why]
  }

-- | The reservation label for a routed step.
opName :: FunctionId -> String
opName fid = case fid of
  F_Digest -> "digest"
  F_DigestInit -> "digest"
  F_DigestUpdate -> "digest"
  F_DigestFinal -> "digest"
  F_Sign -> "sign"
  F_SignFinal -> "sign"
  F_Verify -> "verify"
  F_VerifyFinal -> "verify"
  F_Encrypt -> "encrypt"
  F_EncryptFinal -> "encrypt"
  F_Decrypt -> "decrypt"
  F_DecryptFinal -> "decrypt"
  F_EncryptMessage -> "message"
  F_DecryptMessage -> "message"
  F_SignMessage -> "message"
  F_VerifyMessage -> "message"
  F_EncryptMessageNext -> "message"
  F_DecryptMessageNext -> "message"
  F_SignMessageNext -> "message"
  F_VerifyMessageNext -> "message"
  _ -> "call"

-- | The single byte output region a data call must describe.
singleOutput :: Request -> Maybe (String, OutputIntent)
singleOutput req = case reqRegions req of
  [RegionBytes name intent] -> Just (name, intent)
  _ -> Nothing

-- | Run one pure planner step and pack the outcome: denies reject
-- (persisting any termination), effect-free successes commit
-- immediately, single-effect successes execute with a pinned step.
planData
  :: Request
  -> SlotKind
  -> (SessionOps -> SessionState -> (SessionOps, SessionState, StepOutcome))
  -> SessionState
  -> PlanResult
planData req kind step st =
  let (ops', st', outcome) = step (ssOps st) st
  in packStep req st kind ops' st' outcome

-- | 'planData' for calls producing output: malformed region
-- descriptions reject before planning, so they never touch state.
planOutput
  :: Request
  -> SlotKind
  -> (SessionOps -> SessionState -> (SessionOps, SessionState, StepOutcome))
  -> SessionState
  -> PlanResult
planOutput req kind step st = case singleOutput req of
  Nothing -> rejectArgs "data calls need exactly one byte output region"
  Just _ -> planData req kind step st

-- | 'planOutput' for one-shot and final calls: when the slot holds
-- staged output, the call is a retry with a fresh intent (PKCS#11
-- recall semantics); otherwise the normal step runs. Arguments
-- decode before the staged check, so malformed recalls reject
-- instead of retrying.
planRetryable
  :: Request
  -> SlotKind
  -> (SessionOps -> SessionState -> (SessionOps, SessionState, StepOutcome))
  -> (SessionOps -> OutputIntent -> (SessionOps, StepOutcome))
  -> SessionState
  -> PlanResult
planRetryable req kind step retry st = case singleOutput req of
  Nothing -> rejectArgs "data calls need exactly one byte output region"
  Just (_, intent)
    | slotStaged (ssOps st) kind ->
        let (ops', outcome) = retry (ssOps st) intent
        in packStep req st kind ops' st outcome
    | otherwise -> planData req kind step st

-- | Whether the slot holds staged output awaiting a retry.
slotStaged :: SessionOps -> SlotKind -> Bool
slotStaged ops kind = case lookupSingle ops kind of
  Just active -> case stagedOf (commonOf active) of
    Just _ -> True
    Nothing -> False
  Nothing -> False

-- | A kind-pinned classic retry for 'planRetryable'.
retryFor :: SlotKind -> SessionOps -> OutputIntent -> (SessionOps, StepOutcome)
retryFor kind ops intent = retryStaged ops kind intent

-- | A family-pinned message retry for 'planRetryable'.
retryMsgFor :: MsgFamily -> SessionOps -> OutputIntent -> (SessionOps, StepOutcome)
retryMsgFor fam ops intent = retryMessageStaged fam ops (msgFamilyKind fam) intent

-- | Pack one planner step into a plan. See 'planData'.
packStep
  :: Request -> SessionState -> SlotKind -> SessionOps -> SessionState
  -> StepOutcome -> PlanResult
packStep req st kind ops' st' outcome
  | soCode outcome /= CKR_OK = Reject Rejection
      { rejCode = soCode outcome
      , rejOutputs = []
      , rejDelta = StateDelta (opsDelta ++ loginDelta)
      , rejReleases = soReleases outcome
      , rejReasons = soReasons outcome
      }
  | otherwise = case soEffects outcome of
      [] -> case soPlan outcome of
        Just plan -> case planToOutputs plan of
          Just outs -> Immediate PreparedCommit
            { pcCode = CKR_OK
            , pcDelta = StateDelta (opsDelta ++ loginDelta)
            , pcPersist = []
            , pcOutputs = outs
            , pcReleases = soReleases outcome
            , pcReasons = soReasons outcome
            }
          Nothing -> Reject Rejection
            { rejCode = CKR_GENERAL_ERROR
            , rejOutputs = []
            , rejDelta = StateDelta (opsDelta ++ loginDelta)
            , rejReleases = []
            , rejReasons = ["unencodable output plan"]
            }
        Nothing -> Immediate PreparedCommit
          { pcCode = CKR_OK
          , pcDelta = StateDelta (opsDelta ++ loginDelta)
          , pcPersist = []
          , pcOutputs = []
          , pcReleases = soReleases outcome
          , pcReasons = soReasons outcome
          }
      [fx] -> case singleOutput req of
        -- Silent steps (digest init/update) carry no output region:
        -- the step pins a dummy intent and produces no bytes. The
        -- silent path is SCOPED to the digest streaming shapes;
        -- any other regionless single effect refuses
        -- instead of silently executing, carrying the outcome's
        -- releases (draining a phantom rid is a no-op; dropping a
        -- real one would leak).
        Nothing
          | reqFunction req == F_DigestInit
              || reqFunction req == F_DigestUpdate -> Execute
              (Reservation
                { resOperation = opName (reqFunction req)
                , resDeps = [DepSession (ssId st) (ssRevision st) (ssGeneration st)]
                , resResource = Nothing
                , resStep = Just (CryptoStep (reqFunction req) kind ""
                    (IntentBuffer 0) ops' st')
                })
              (EffectCrypto fx)
          | otherwise -> Reject Rejection
              { rejCode = CKR_ARGUMENTS_BAD
              , rejOutputs = []
              , rejDelta = StateDelta (opsDelta ++ loginDelta)
              , rejReleases = soReleases outcome
              , rejReasons = ["data calls need exactly one byte output region"]
              }
        Just (name, intent) -> Execute
          (Reservation
            { resOperation = opName (reqFunction req)
            , resDeps = [DepSession (ssId st) (ssRevision st) (ssGeneration st)]
            , resResource = Nothing
            , resStep = Just (CryptoStep (reqFunction req) kind name intent ops' st')
            })
          (EffectCrypto fx)
      _ -> Reject Rejection
        { rejCode = CKR_GENERAL_ERROR
        , rejOutputs = []
        , rejDelta = StateDelta (opsDelta ++ loginDelta)
        , rejReleases = []
        , rejReasons = ["planner emitted multiple effects"]
        }
  where
    opsDelta = [DeltaSetSessionOps (ssId st) ops' | ops' /= ssOps st]
    loginDelta =
      [DeltaSetSessionLogin (ssId st) (ssLogin st') | ssLogin st' /= ssLogin st]

-- | The init cipher shape for an operation: cipher ops resolve their
-- mechanism shape, anything else takes none.
cipherShapeArg :: Operation -> MechanismId -> Maybe (Maybe CipherSpec)
cipherShapeArg o m
  | o == OpEncrypt || o == OpDecrypt = fmap Just (cipherShapeFor m)
  | otherwise = Just Nothing

-- | Plan a message init: like the classic 'DRInit' arm against the family's
-- classic counterpart, recording the message operation tag.
planMessageInit :: Rules -> Model -> Request -> MsgFamily -> SessionState -> PlanResult
planMessageInit rules model req fam st = case decodeInitInput (reqInput req) of
  Nothing -> rejectArgs "malformed init arguments"
  Just (mech, permits, auth, params) ->
    let cop = msgFamilyOp fam
    in case cipherShapeArg cop mech of
      Nothing -> Reject Rejection
        { rejCode = CKR_MECHANISM_INVALID
        , rejOutputs = []
        , rejDelta = StateDelta []
        , rejReleases = []
        , rejReasons = ["no cipher shape for mechanism"]
        }
      Just cshape ->
        let key = fmap (\h -> KeyPolicy h permits auth) (reqHandle req)
            args = InitArgs cop mech params key cshape Nothing
            env = OpEnv (rulesRegistry rules) (rulesCaps rules) model
            (ops', outcome) = initMessageOperation fam env (ssOps st) st args
        in if ioCode outcome == CKR_OK
          then Immediate PreparedCommit
            { pcCode = CKR_OK
            , pcDelta = StateDelta [DeltaSetSessionOps (ssId st) ops']
            , pcPersist = []
            , pcOutputs = []
            , pcReleases = []
            , pcReasons = ioReasons outcome
            }
          else Reject Rejection
            { rejCode = ioCode outcome
            , rejOutputs = []
            , rejDelta = StateDelta []
            , rejReleases = []
            , rejReasons = ioReasons outcome
            }

-- | Plan a message-begin: decode the per-message parameters and open
-- the inner message.
planMsgBegin :: Request -> MsgFamily -> SessionState -> PlanResult
planMsgBegin req fam st = case decodeMsgBegin (reqInput req) of
  Nothing -> rejectArgs "malformed message-begin arguments"
  Just b -> planData req (msgFamilyKind fam)
    (\ops s -> planMessageBegin ops s fam b) st

-- | Plan a message-next part: decode and step the open message,
-- executing when the message concludes with output.
planMsgNext :: Request -> MsgFamily -> SessionState -> PlanResult
planMsgNext req fam st = case decodeMsgNext fam (reqInput req) of
  Nothing -> rejectArgs "malformed message-next arguments"
  Just n -> planRetryable req (msgFamilyKind fam)
    (\ops s -> planMessageNext ops s fam n) (retryMsgFor fam) st

-- | Plan a one-shot message: decode and run the whole message,
-- executing its single effect.
planMsgOneShot :: Request -> MsgFamily -> SessionState -> PlanResult
planMsgOneShot req fam st = case decodeMsgOneShot fam (reqInput req) of
  Nothing -> rejectArgs "malformed one-shot message arguments"
  Just o -> planRetryable req (msgFamilyKind fam)
    (\ops s -> planMessageOneShot ops s fam "" o) (retryMsgFor fam) st

-- | Plan a message final: conclude the outer context and free its slot.
planMsgFinal :: Request -> MsgFamily -> SessionState -> PlanResult
planMsgFinal req fam st =
  let (ops', outcome) = finalizeMessage fam (ssOps st)
  in packStep req st (msgFamilyKind fam) ops' st outcome

-- | Flatten a finisher's output plan into native outputs. 'Nothing'
-- when a payload is unencodable (the planner rejects those before
-- producing writes, so this only fires on internal mismatch).
planToOutputs :: OutputPlan -> Maybe [NativeOutput]
planToOutputs plan = traverse toOut (opWrites plan)
  where
    toOut w = NativeOutput (twRegion w) <$> typedWriteBytes w

-- | Finish an effect: validate the reservation dependencies against
-- the current model, then convert the engine result into a commit or
-- a rejection. A stale dependency rejects; it never retries the
-- native effect.
finishEffect
  :: Rules -> Model -> Reservation -> EngineResult
  -> Either Rejection PreparedCommit
finishEffect _rules model res result =
  case reservationStale model res of
    Just stale -> Left Rejection
      { rejCode = CKR_GENERAL_ERROR
      , rejOutputs = []
      , rejDelta = StateDelta []
      , rejReleases = staleReleases result
      , rejReasons = ["stale reservation: " ++ show stale]
      }
    Nothing -> case resStep res of
      Nothing -> legacy result
      Just step -> finishStep model step result
  where
    legacy :: EngineResult -> Either Rejection PreparedCommit
    legacy (EngineFail f) = Left (failureRejection f)
    legacy (EngineOkBytes bs) = Right PreparedCommit
      { pcCode = CKR_OK
      , pcDelta = StateDelta []
      , pcPersist = []
      , pcOutputs = []
      , pcReleases = []
      , pcReasons = ["engine ok: " ++ show (BS.length bs) ++ " bytes"]
      }
    legacy (EngineOkValid v) = Left (failureRejection
      (BackendBadParam "finish" ("verdict without a crypto step: " ++ show v)))
    legacy (EngineOkResource rid) = Right PreparedCommit
      { pcCode = CKR_OK
      , pcDelta = StateDelta []
      , pcPersist = []
      , pcOutputs = []
      -- Attach the rid (the stale-orphan precedent) —
      -- the commit-application site drains it instead of leaking it.
      , pcReleases = [ReleaseEngineResource rid]
      , pcReasons = ["engine resource: " ++ show rid]
      }
    failureRejection :: BackendFailure -> Rejection
    failureRejection f = Rejection
      { rejCode = CKR_GENERAL_ERROR
      , rejOutputs = []
      , rejDelta = StateDelta []
      , rejReleases = []
      , rejReasons = ["backend failure: " ++ show f]
      }

-- | Releases for a stale finish: a resource answer whose
-- reservation went stale is an orphan the backend allocated but no
-- slot recorded, so it drains instead of leaking. Bytes and
-- verdict answers allocate nothing.
staleReleases :: EngineResult -> [ResourceRelease]
staleReleases (EngineOkResource rid) = [ReleaseEngineResource rid]
staleReleases _ = []

-- | Finish a pinned crypto step: answer the planned effect through
-- the family's finisher and pack the commit or rejection. Staged
-- output (including short-buffer and signature-mismatch codes)
-- commits with its delta; plan-less denies reject carrying theirs.
finishStep :: Model -> CryptoStep -> EngineResult -> Either Rejection PreparedCommit
finishStep model step result = case runFinisher step (toCrypto result) of
  Nothing -> Left (stepRejection CKR_GENERAL_ERROR (csOps step) []
    ["no finisher for " ++ show (csFunction step)])
  Just (ops'', outcome) -> case soPlan outcome of
    Just plan -> case planToOutputs plan of
      Nothing -> Left (stepRejection CKR_GENERAL_ERROR ops'' []
        ("unencodable output plan" : soReasons outcome))
      Just outs -> Right PreparedCommit
        { pcCode = soCode outcome
        , pcDelta = StateDelta (stepDelta ops'')
        , pcPersist = []
        , pcOutputs = outs
        , pcReleases = soReleases outcome
        , pcReasons = soReasons outcome
        }
    Nothing
      | soCode outcome == CKR_OK -> Right PreparedCommit
          { pcCode = CKR_OK
          , pcDelta = StateDelta (stepDelta ops'')
          , pcPersist = []
          , pcOutputs = []
          , pcReleases = soReleases outcome
          , pcReasons = soReasons outcome
          }
      | otherwise -> Left (stepRejection (soCode outcome) ops''
          (soReleases outcome) (soReasons outcome))
  where
    stepRejection code ops'' releases reasons = Rejection
      { rejCode = code
      , rejOutputs = []
      , rejDelta = StateDelta (stepDelta ops'')
      , rejReleases = releases
      , rejReasons = reasons
      }
    stepDelta ops'' =
      [DeltaSetSessionOps sid ops'' | Just ops'' /= fmap ssOps mst]
      ++ [DeltaSetSessionLogin sid planned | fmap ssLogin mst /= Just planned]
      where
        sid = ssId (csSession step)
        planned = ssLogin (csSession step)
        mst = lookupSession model sid

-- | Interpret an engine answer as the driver's crypto answer.
-- Finishers expecting bytes or verdicts treat a resource as a
-- driver-protocol violation and fail the step loudly.
toCrypto :: EngineResult -> CryptoResult
toCrypto result = case result of
  EngineOkBytes bs -> GotBytes bs
  EngineOkValid v -> GotValid v
  EngineOkResource rid -> GotResource rid
  EngineFail f -> GotCryptoError (toCryptoError f)

-- | Map a typed backend failure onto the planner's crypto errors.
-- Total and category-preserving: each failure maps to its
-- mirror crypto error with fields intact, never string soup. Every
-- case keeps the code its collapse produced.
toCryptoError :: BackendFailure -> CryptoError
toCryptoError f = case f of
  BackendUnsupported o w -> CryptoUnsupported o w
  BackendBadParam o w -> CryptoBadParam o w
  BackendBadKey o w -> CryptoBadKey o w
  BackendAuthFailed o -> CryptoAuthFailed o
  BackendInvalidState o w -> CryptoInvalidState o w
  BackendNative o c w -> CryptoNative o c w
  BackendResourceGone o r -> CryptoResourceGone o r

-- | Run the finishing function pinned by the step.
runFinisher :: CryptoStep -> CryptoResult -> Maybe (SessionOps, StepOutcome)
runFinisher step res = case csFunction step of
  F_Digest -> go finishDigest
  F_DigestInit -> go finishDigestInit
  F_DigestUpdate -> go finishDigestFeed
  F_DigestFinal -> go finishDigest
  F_Sign -> go finishSign
  F_SignFinal -> go finishSign
  F_Verify -> go finishVerify
  F_VerifyFinal -> go finishVerify
  F_Encrypt -> go finishCipher
  F_EncryptFinal -> go finishCipher
  F_Decrypt -> go finishCipher
  F_DecryptFinal -> go finishCipher
  F_EncryptMessage -> goMsg MsgEncrypt
  F_DecryptMessage -> goMsg MsgDecrypt
  F_SignMessage -> goMsg MsgSign
  F_VerifyMessage -> goMsg MsgVerify
  F_EncryptMessageNext -> goMsg MsgEncrypt
  F_DecryptMessageNext -> goMsg MsgDecrypt
  F_SignMessageNext -> goMsg MsgSign
  F_VerifyMessageNext -> goMsg MsgVerify
  -- Exhaustive runFinisher — every 'FunctionId' has an
  -- explicit arm; functions without a finishing leg map to
  -- 'Nothing' (no wildcard). A new constructor fails validation
  -- via -Werror=incomplete-patterns, forcing an
  -- explicit arm choice here. Callers handle 'Nothing'
  -- (see 'finishStep').
  F_GetInfo -> Nothing
  F_GetSlotList -> Nothing
  F_GetSessionInfo -> Nothing
  F_OpenSession -> Nothing
  F_CloseSession -> Nothing
  F_Login -> Nothing
  F_Logout -> Nothing
  F_SignInit -> Nothing
  F_CreateObject -> Nothing
  F_DestroyObject -> Nothing
  F_CopyObject -> Nothing
  F_FindObjects -> Nothing
  F_GetAttributeValue -> Nothing
  F_SetAttributeValue -> Nothing
  F_SignUpdate -> Nothing
  F_VerifyInit -> Nothing
  F_VerifyUpdate -> Nothing
  F_EncryptInit -> Nothing
  F_EncryptUpdate -> Nothing
  F_DecryptInit -> Nothing
  F_DecryptUpdate -> Nothing
  F_MessageEncryptInit -> Nothing
  F_MessageDecryptInit -> Nothing
  F_MessageSignInit -> Nothing
  F_MessageVerifyInit -> Nothing
  F_EncryptMessageBegin -> Nothing
  F_DecryptMessageBegin -> Nothing
  F_SignMessageBegin -> Nothing
  F_VerifyMessageBegin -> Nothing
  F_MessageEncryptFinal -> Nothing
  F_MessageDecryptFinal -> Nothing
  F_MessageSignFinal -> Nothing
  F_MessageVerifyFinal -> Nothing
  where
    go fin = Just (fin (csOps step) (csKind step) (csName step) res (csIntent step))
    goMsg fam = Just
      (finishMessage fam (csOps step) (csKind step) (csName step) res (csIntent step))

-- | The first reservation dependency the model no longer satisfies,
-- if any. The runtime uses this for explicit invalidation checks.
reservationStale :: Model -> Reservation -> Maybe RevisionDep
reservationStale model res = firstStaleDep model (resDeps res)

-- | Find the first reservation dependency the model no longer
-- satisfies, if any.
firstStaleDep :: Model -> [RevisionDep] -> Maybe RevisionDep
firstStaleDep _model [] = Nothing
firstStaleDep model (d : ds) = case d of
  DepSession sid rev gen -> case lookupSession model sid of
    Nothing -> Just d
    Just st
      | ssRevision st /= rev || ssGeneration st /= gen -> Just d
      | otherwise -> firstStaleDep model ds
  DepObject oid rev -> case lookupObject model oid of
    Nothing -> Just d
    Just ost
      | osRevision ost /= rev -> Just d
      | otherwise -> firstStaleDep model ds

-- | Publish a state delta: apply every op in order, atomically. Any
-- failure aborts the whole delta and reports the fault; partial
-- application is not observable.
publishDelta :: Model -> StateDelta -> Either ModelFault Model
publishDelta model (StateDelta ops) = go model ops
  where
    go :: Model -> [DeltaOp] -> Either ModelFault Model
    go m [] = Right m
    go m (op : rest) = case applyOp m op of
      Left fault -> Left fault
      Right m' -> go m' rest

-- | Stale-mark one binding when its object is destroyed: the
-- binding is retained with a bumped generation so the handle faults
-- deterministically (and can never alias a recreated object).
staleIfTarget :: ObjectId -> HandleBinding -> HandleBinding
staleIfTarget oid b
  | hbObject b == oid =
      let Generation g = hbGeneration b
      in b { hbGeneration = Generation (g + 1) }
  | otherwise = b

-- | Apply one delta op.
applyOp :: Model -> DeltaOp -> Either ModelFault Model
applyOp m op = case op of
  DeltaTouchSession sid -> case lookupSession m sid of
    Nothing -> Left (FaultUnknownSession sid)
    Just _st -> Right m
  DeltaCloseSession sid -> case Map.lookup sid (mSessions m) of
    Nothing -> Left (FaultUnknownSession sid)
    Just _ -> Right m { mSessions = Map.delete sid (mSessions m) }
  DeltaBumpGeneration sid gen -> case lookupSession m sid of
    Nothing -> Left (FaultUnknownSession sid)
    Just st -> Right m
      { mSessions = Map.insert sid (st { ssGeneration = gen }) (mSessions m) }
  DeltaCreateObject oid -> case Map.lookup oid (mObjects m) of
    Just _ -> Left (FaultDuplicateObject oid)
    Nothing ->
      let ost = ObjectState
            { osId = oid
            , osRevision = Revision 1
            , osGeneration = Generation 1
            , osAttrs = Map.empty
            , osOwner = Nothing
            , osSlot = SlotId 0
            }
      in Right m { mObjects = Map.insert oid ost (mObjects m) }
  DeltaDestroyObject oid -> case Map.lookup oid (mObjects m) of
    Nothing -> Left (FaultUnknownObject oid)
    Just _ -> Right m
      { mObjects = Map.delete oid (mObjects m)
      , mHandles = Map.map (staleIfTarget oid) (mHandles m)
      }
  DeltaCreateObjectFull oid attrs owner slot -> case Map.lookup oid (mObjects m) of
    Just _ -> Left (FaultDuplicateObject oid)
    Nothing ->
      let (rev, m1) = nextRevision m
          ost = ObjectState
            { osId = oid
            , osRevision = rev
            , osGeneration = Generation 1
            , osAttrs = attrs
            , osOwner = owner
            , osSlot = slot
            }
      in Right m1
        { mObjects = Map.insert oid ost (mObjects m1)
        , mNextObject = max (mNextObject m1) (unObjectId oid + 1)
        }
  DeltaSetAttributes oid over -> case Map.lookup oid (mObjects m) of
    Nothing -> Left (FaultUnknownObject oid)
    Just ost ->
      let (rev, m1) = nextRevision m
          merged = Map.union over (osAttrs ost)
          ost' = ost { osAttrs = merged, osRevision = rev }
          -- Token promotion moves ownership off the session; the
          -- planner only ever flips token false->true, so the
          -- owner never moves back here.
          owner' = if objectToken ost' then Nothing else osOwner ost
      in Right m1 { mObjects = Map.insert oid (ost' { osOwner = owner' }) (mObjects m1) }
  DeltaBindHandle h oid -> case Map.lookup oid (mObjects m) of
    Nothing -> Left (FaultUnknownObject oid)
    Just ost
      | Map.member h (mHandles m) -> Left (FaultDuplicateHandle h)
      | otherwise -> Right m
          { mHandles = Map.insert h (HandleBinding oid (osGeneration ost)) (mHandles m)
          , mNextHandle = max (mNextHandle m) (unExternalHandle h + 1)
          }
  DeltaBumpHandle h -> case Map.lookup h (mHandles m) of
    Nothing -> Left (FaultUnknownHandle h)
    Just b ->
      let Generation g = hbGeneration b
      in Right m
        { mHandles = Map.insert h (b { hbGeneration = Generation (g + 1) }) (mHandles m) }
  DeltaOpenSession sid slot readOnly
    | Map.member sid (mSessions m) -> Left (FaultDuplicateSession sid)
    | otherwise -> case Map.lookup slot (mTokenAuth m) of
        Nothing -> Left (FaultUnknownSlot slot)
        Just auth ->
          -- Login state is per token: a session opened after login
          -- observes the token login, not a public snapshot.
          let (rev, m1) = nextRevision m
              st = SessionState
                { ssId = sid
                , ssSlot = slot
                , ssRevision = rev
                , ssGeneration = Generation 1
                , ssReadOnly = readOnly
                , ssLogin = case taLogin auth of
                    Just AuthUser -> LoginUser
                    Just AuthSO -> LoginSO
                    Nothing -> LoginPublic
                , ssOps = emptySessionOps
                }
          in Right m1
            { mSessions = Map.insert sid st (mSessions m1)
            , mNextSession = max (mNextSession m1) (unSessionId sid + 1)
            }
  DeltaSetSessionLogin sid login -> case lookupSession m sid of
    Nothing -> Left (FaultUnknownSession sid)
    Just st -> Right m
      { mSessions = Map.insert sid (st { ssLogin = login }) (mSessions m) }
  DeltaSetTokenAuth slot auth -> case Map.lookup slot (mTokenAuth m) of
    Nothing -> Left (FaultUnknownSlot slot)
    Just _ -> Right m
      { mTokenAuth = Map.insert slot auth (mTokenAuth m) }
  DeltaSetSessionOps sid ops -> case lookupSession m sid of
    Nothing -> Left (FaultUnknownSession sid)
    Just st ->
      let (rev, m1) = nextRevision m
      in Right m1
        { mSessions = Map.insert sid
            (st { ssOps = ops, ssRevision = rev }) (mSessions m1)
        }
