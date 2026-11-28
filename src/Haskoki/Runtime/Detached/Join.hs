{- | Detached join (rejoin).
-}
module Haskoki.Runtime.Detached.Join
  ( JoinRequest (..)
  , JoinOutcome (..)
  , joinPolicyName
  , joinCode
  , joinJob
  ) where

import Control.Concurrent.STM (readTVarIO)
import Control.Exception
  ( mask
  , mask_
  , onException
  )
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Unique (newUnique)
import Data.Word (Word64)
import Haskoki.CallWork (checkedCallWork)
import Haskoki.Model (Model, SessionState (..), lookupSession, lookupTokenAuth)
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , planGenerateKey
  , planGenerateKeyPair
  )
import Haskoki.Outcome
  ( EffectRequest (..)
  , PlanResult (..)
  , Rejection (..)
  , Reservation (..)
  , RevisionDep (..)
  )
import Haskoki.Output (maxOutputBytes)
import Haskoki.Request
  ( FunctionId (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  )
import Haskoki.Runtime.Async
  ( AsyncTable
  , AsyncWork (..)
  , JobFunction (..)
  , JobRequest (..)
  , JobSnapState (..)
  , StartDeny (..)
  , asyncTableId
  , cancelJob
  , isAsyncSession
  , jobSnapshotState
  , snapshotJob
  , startJob
  , startSeededJob
  , usdtSeededReady
  )
import Haskoki.Runtime.Attach
  ( Attachment (..)
  )
import Haskoki.Runtime.Lifecycle (Env, envRules, snapshotModel)
import Haskoki.Rules (Rules)
import Haskoki.Session (SessionLogin (..), TokenAuth (..))
import qualified Haskoki.Runtime.Storage as S
import Haskoki.Runtime.Storage
  ( JobBody (..)
  , JobExecState (..)
  , JobRecord (..)
  , Store (..)
  , StoreError (..)
  , TokenRecord (..)
  )
import Haskoki.Transition (planCall)
import Haskoki.Types
  ( Generation (..)
  , JobId (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  )
import Haskoki.Runtime.Detached.Attachments
import Haskoki.Runtime.Detached.Context
import Haskoki.Runtime.Detached.Detach
import Haskoki.Runtime.Detached.JoinComplete
import Haskoki.Runtime.Detached.Recipes

-- ---------------------------------------------------------------------------
-- Join (rejoin)
-- ---------------------------------------------------------------------------

-- | One rejoin request: the persistent id, the caller's function
-- identity, the target session, and the NEW caller storage capacity.
data JoinRequest = JoinRequest
  { jqPid :: !Word64
  , jqFunction :: !JobFunction
  , jqSession :: !SessionId
  , jqCapacity :: !Word64
  } deriving (Eq, Show)

-- | One rejoin outcome. Only 'JoinOk' attaches storage; every other
-- outcome leaves the durable job intact (except the self-healing
-- terminal resolutions, which only confirm what the live table
-- already decided).
data JoinOutcome
  = JoinOk !JobId
  | JoinUnknown
  | JoinWrongFunction { jwExpected :: !JobFunction, jwGot :: !JobFunction }
  | JoinUnknownVersion { juRecipe :: !String }
  | JoinStaleGeneration { jgRecord :: !Generation, jgCurrent :: !Generation }
  | JoinBadSession
  | JoinSessionNotAsync
  | JoinAuthRequired
  | JoinIncompatible { jiReason :: !String }
  | JoinShort { jsNeeded :: !Word64 }
  | JoinAlreadyAttached { jaPolicy :: !String }
  | JoinTerminal !JobExecState
  | JoinDenied !StartDeny
  | JoinStore !StoreError
  deriving (Eq, Show)

-- | The named competing-join policy. PKCS#11 3.2 is silent on
-- repeat\/competing joins; this facility decides explicitly: the
-- FIRST attachment wins and competitors are refused typed, with no
-- duplicated engine work and no resurrection of delivered jobs.
-- Pinned by the @HASKOKI-JOIN-FIRST-WINS@ source-decision test.
joinPolicyName :: String
joinPolicyName = "HASKOKI-JOIN-FIRST-WINS"

-- | Source-backed code for a rejoin outcome.
joinCode :: JoinOutcome -> ReturnCode
joinCode out = case out of
  JoinOk _ -> CKR_PENDING
  JoinUnknown -> CKR_SAVED_STATE_INVALID
  JoinWrongFunction {} -> CKR_ARGUMENTS_BAD
  JoinUnknownVersion {} -> CKR_SAVED_STATE_INVALID
  JoinStaleGeneration {} -> CKR_SAVED_STATE_INVALID
  JoinBadSession -> CKR_SESSION_HANDLE_INVALID
  JoinSessionNotAsync -> CKR_SESSION_ASYNC_NOT_SUPPORTED
  JoinAuthRequired -> CKR_USER_NOT_LOGGED_IN
  JoinIncompatible {} -> CKR_OPERATION_NOT_INITIALIZED
  JoinShort {} -> CKR_BUFFER_TOO_SMALL
  JoinAlreadyAttached {} -> CKR_OPERATION_ACTIVE
  JoinTerminal s -> terminalJoinCode s
  JoinDenied deny -> denyCode deny
  JoinStore _ -> CKR_GENERAL_ERROR

-- | Terminal rejoin codes: delivered is a stale-id use, canceled
-- reports its winner, failed reports generally.
terminalJoinCode :: JobExecState -> ReturnCode
terminalJoinCode JobDelivered = CKR_ARGUMENTS_BAD
terminalJoinCode JobCanceled = CKR_FUNCTION_CANCELED
terminalJoinCode JobFailed = CKR_GENERAL_ERROR
terminalJoinCode JobQueued = CKR_GENERAL_ERROR
terminalJoinCode JobReady = CKR_GENERAL_ERROR

-- | Submit-denial codes (mirrors the async export mapping).
denyCode :: StartDeny -> ReturnCode
denyCode StartSessionNotAsync = CKR_SESSION_ASYNC_NOT_SUPPORTED
denyCode StartOverCapacity = CKR_HOST_MEMORY
denyCode StartBadCapacity = CKR_ARGUMENTS_BAD
denyCode StartIncompatibleWork = CKR_ARGUMENTS_BAD

-- | Rejoin a detached job: validate (id, function, token
-- identity\/generation, version, session, auth, capacity — in that
-- order, before attaching anything), replay the recipe against the
-- current model for a fresh reservation, start the live job (seeded
-- when the record holds a prepared result), record the attachment,
-- and report the new live job. At most one active attachment per
-- persistent job, ever.
joinJob :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> IO JoinOutcome
joinJob dc env table req = do
  eJobs <- storeLoadJobs (dcStore dc)
  case eJobs of
    Left err -> pure (JoinStore err)
    Right jobs -> case [r | r <- jobs, jrPersistentId r == jqPid req] of
      [] -> pure JoinUnknown
      (rec : _) -> joinRecord dc env table req rec

-- | The rejoin body for one durable record.
joinRecord :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> JobRecord -> IO JoinOutcome
joinRecord dc env table req rec = do
  mGate <- attachmentGate dc table (jqPid req) rec
  case mGate of
    Just blocked -> pure blocked
    Nothing -> do
      mFunc <- checkFunction req rec
      case mFunc of
        Just refused -> pure refused
        Nothing -> do
          let recFunc = mustFunction rec
          eTok <- checkToken dc rec
          case eTok of
            Left refused -> pure refused
            Right () -> joinValidated dc env table req rec recFunc

-- | The one-active-attachment gate: terminal stays terminal, live
-- actives and in-progress claims refuse competitors under the
-- named policy, and actives whose live job already died without
-- the wrappers self-heal to the terminal state the table decided.
-- An active owned by another table refuses WITHOUT resolving its
-- local job id in this (wrong) table. 'Nothing' means the id is
-- free to attach. This gate is advisory — the atomic claim in
-- 'joinRecipe' is the arbiter that decides genuinely simultaneous
-- joins.
attachmentGate
  :: DetachCtx -> AsyncTable -> Word64 -> JobRecord -> IO (Maybe JoinOutcome)
attachmentGate dc table pid rec = do
  mAtt <- lookupAttachment dc pid
  case mAtt of
    Just (AttTerminal s) -> pure (Just (JoinTerminal s))
    Just (AttClaim _ _ _ _) ->
      pure (Just (JoinAlreadyAttached joinPolicyName))
    Just (AttActive owner jid)
      | owner /= asyncTableId table ->
          pure (Just (JoinAlreadyAttached joinPolicyName))
      | otherwise -> do
          mSnap <- snapshotJob table jid
          case mSnap of
            Just snap | snapLive (jobSnapshotState snap) ->
              pure (Just (JoinAlreadyAttached joinPolicyName))
            other -> do
              let st = case other of
                    Just snap -> case jobSnapshotState snap of
                      SnapTerminal t -> execStateOf t
                      _ -> JobCanceled
                    Nothing -> JobCanceled
              _ <- markState dc pid rec st
              pure (Just (JoinTerminal st))
    Just AttIdle -> pure Nothing
    Nothing -> case jrState rec of
      JobDelivered -> healTerminal JobDelivered
      JobCanceled -> healTerminal JobCanceled
      JobFailed -> healTerminal JobFailed
      JobQueued -> pure Nothing
      JobReady -> pure Nothing
  where
    healTerminal :: JobExecState -> IO (Maybe JoinOutcome)
    healTerminal st = do
      setTerminal dc pid st
      pure (Just (JoinTerminal st))

-- | Whether a snapshot state is still live (attachable against).
snapLive :: JobSnapState -> Bool
snapLive (SnapTerminal _) = False
snapLive _ = True

-- | Check the durable function name against the caller's identity.
checkFunction :: JoinRequest -> JobRecord -> IO (Maybe JoinOutcome)
checkFunction req rec = case nameJobFunction (S.jrFunction rec) of
  Nothing -> pure (Just (JoinUnknownVersion (S.jrFunction rec)))
  Just recFunc
    | recFunc /= jqFunction req ->
        pure (Just (JoinWrongFunction recFunc (jqFunction req)))
    | otherwise -> pure Nothing

-- | The record's function (checked present by 'checkFunction').
mustFunction :: JobRecord -> JobFunction
mustFunction rec = case nameJobFunction (S.jrFunction rec) of
  Just f -> f
  Nothing -> JobDigest

-- | Check token identity/generation against the stored token
-- record: the record must name this context's home token (an
-- id homed elsewhere is unknown to this join, even at an equal
-- generation) at the current generation. Identity and generation
-- only — the stored record carries no login (durable state never
-- persists the active login), so authentication reads the live
-- model in 'joinValidated' instead. Runs before session, body,
-- capacity, claim, replan, and start.
checkToken :: DetachCtx -> JobRecord -> IO (Either JoinOutcome ())
checkToken dc rec = do
  eToks <- storeLoadTokens (dcStore dc)
  case eToks of
    Left err -> pure (Left (JoinStore err))
    Right toks -> case [t | (t, _) <- toks, trId t == dcToken dc] of
      [] -> pure (Left (JoinStore
        (StoreRevisionConflict "home token is gone")))
      (trec : _)
        | jrToken rec /= dcToken dc ->
            pure (Left JoinUnknown)
        | trGeneration trec /= jrTokenGeneration rec ->
            pure (Left (JoinStaleGeneration
              (jrTokenGeneration rec) (trGeneration trec)))
        | otherwise -> pure (Right ())

-- | Session, auth, body, capacity, replan, and start — after the
-- attachment gate, function check, and token check all pass.
joinValidated
  :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> JobRecord
  -> JobFunction -> IO JoinOutcome
joinValidated dc env table req rec recFunc = do
  m <- snapshotModel env
  case lookupSession m (jqSession req) of
    Nothing -> pure JoinBadSession
    Just st
      | ssSlot st /= dcSlot dc -> pure JoinBadSession
      | otherwise -> do
          async <- isAsyncSession table (jqSession req)
          if not async
            then pure JoinSessionNotAsync
            else if authBlocked (lookupTokenAuth m (dcSlot dc)) st
              then pure JoinAuthRequired
              else joinBody dc env table req rec recFunc st

-- | Auth rule: a token with an active login admits only
-- authenticated joins; a public session must log in first. The
-- login comes from the LIVE model snapshot (durable token
-- records carry no login, so the stored record cannot answer):
-- a missing live entry means no login exists, and admits.
authBlocked :: Maybe TokenAuth -> SessionState -> Bool
authBlocked liveAuth st = case liveAuth of
  Nothing -> False
  Just auth -> case taLogin auth of
    Nothing -> False
    Just _ -> ssLogin st == LoginPublic

-- | Decode the record body (recipe or prepared result) and continue.
joinBody
  :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> JobRecord
  -> JobFunction -> SessionState -> IO JoinOutcome
joinBody dc env table req rec recFunc st = case jrBody rec of
  JobPending name params -> case decodeRecipe name params of
    Nothing -> pure (JoinUnknownVersion name)
    Just recipe
      | recipeFunction recipe /= recFunc ->
          pure (JoinWrongFunction recFunc (recipeFunction recipe))
      | otherwise -> joinRecipe dc env table req st recFunc recipe Nothing
  JobResult code body
    | code /= CKR_OK -> do
        _ <- markState dc (jqPid req) rec JobFailed
        pure (JoinTerminal JobFailed)
    | otherwise -> case decodeResultBody body of
        Nothing -> pure (JoinUnknownVersion "haskoki-result/v1")
        Just (recipe, result)
          | recipeFunction recipe /= recFunc ->
              pure (JoinWrongFunction recFunc (recipeFunction recipe))
          | otherwise ->
              joinRecipe dc env table req st recFunc recipe (Just result)

-- | A recipe's function family.
recipeFunction :: Recipe -> JobFunction
recipeFunction (RecipeCall f _ _ _) = f
recipeFunction RecipeGenKey {} = JobGenKey
recipeFunction RecipeGenKeyPair {} = JobGenKeyPair

-- | Capacity check (BEFORE attaching anything), atomic claim,
-- recipe replay against the current model, live start, and claim
-- commit. Only the claim decides between simultaneous joins.
joinRecipe
  :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> SessionState
  -> JobFunction -> Recipe -> Maybe ByteString -> IO JoinOutcome
joinRecipe dc env table req st recFunc recipe mSeed = do
  let need = case mSeed of
        Just result -> fromIntegral (BS.length result)
        Nothing -> recipeCapacity recipe
      cap = jqCapacity req
  if cap == 0 || cap > maxOutputBytes
    then pure (JoinDenied StartBadCapacity)
    else if cap < need
      then pure (JoinShort need)
      else joinClaimed dc env table req st recFunc recipe mSeed

-- | The lost-claim outcome: re-read the winner's state so a
-- concurrently terminalized id reports its terminal fate;
-- anything still live (active or a rival claim, including a
-- claim that rolled back between our attempt and this re-read)
-- reports the existing already-attached refusal.
claimLost :: DetachCtx -> Word64 -> IO JoinOutcome
claimLost dc pid = do
  mAtt <- lookupAttachment dc pid
  case mAtt of
    Just (AttTerminal s) -> pure (JoinTerminal s)
    _ -> pure (JoinAlreadyAttached joinPolicyName)

-- | Claim, replan, start, and attach as one protected
-- transfer. The claim is acquired masked and the rollback
-- handler is installed before anything interruptible runs, so
-- no kill can strand a claim between acquisition and
-- protection. A replan or start refusal rolls back ONLY our
-- claim attempt (the durable job is untouched and a retry may
-- claim again). The start runs masked inside a second mask —
-- its acquisition is one retry-free STM step plus a fresh
-- lock, so it never blocks — and cleanup owns the fresh id
-- before anything runs restored again: from the STM commit
-- through the attachment commit the transfer is either masked
-- or covered by cleanup, so an interruption after the live
-- start but before the commit retires the newly created
-- unregistered job and rolls the claim back — no live job
-- ever strands without an attachment decision and no claim
-- ever sticks. The TEST-ONLY hook runs restored inside that
-- transfer window (a no-op unless a test sets it); the commit
-- itself and the outcome return run masked, so a kill can
-- neither split the commit nor strand cleanup. Retirement
-- racing the transfer rolls the claim back first, so the
-- commit takes the uncommitted arm and the fresh job retires
-- the same way.
joinClaimed
  :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> SessionState
  -> JobFunction -> Recipe -> Maybe ByteString -> IO JoinOutcome
joinClaimed dc env table req st recFunc recipe mSeed =
  let tid = asyncTableId table
      sid = jqSession req
      pid = jqPid req
  in mask $ \restore -> do
    uniq <- newUnique
    mPrior <- tryClaim dc pid tid sid uniq
    case mPrior of
      Nothing -> claimLost dc pid
      Just prior ->
        let rollback = rollbackClaim dc pid tid sid uniq prior
        in flip onException rollback $ restore $ do
          m <- snapshotModel env
          case replanRecipe (envRules env) m st recFunc recipe of
            Left reason -> rollback >> pure (JoinIncompatible reason)
            Right work -> mask $ \restoreStart -> do
              let jr = JobRequest
                    { jrSession = jqSession req
                    , jrFunction = recFunc
                    , jrWork = work
                    , jrTicks = recipeTicks recipe
                    , jrCapacity = jqCapacity req
                    }
              -- Masked: a kill must not land between the STM
              -- insert and cleanup ownership of the fresh id.
              started <- case mSeed of
                Nothing -> startJob table jr
                Just result -> startSeededJob table jr result
              case started of
                Left deny -> rollback >> pure (JoinDenied deny)
                Right jid -> do
                  hook <- readTVarIO (dcJoinHook dc)
                  committed <- (restoreStart hook >> commitClaim dc pid tid sid uniq jid)
                    `onException` mask_ (retireFresh table jid >> rollback)
                  if committed
                    then do
                      -- The committed claim owns the seeded
                      -- attachment's first ready; unseeded jobs run
                      -- the normal claim/hold path instead.
                      case mSeed of
                        Just _ -> usdtSeededReady table jid
                        Nothing -> pure ()
                      pure (JoinOk jid)
                    else do
                      mask_ (retireFresh table jid >> rollback)
                      pure (JoinAlreadyAttached joinPolicyName)
  where
    -- | Retire a freshly started but unregistered job: it has no
    -- attachment and no owner yet, so cancel it outright. Fresh
    -- and table-local: no other thread can hold its lease, so the
    -- masked cancel cannot block.
    retireFresh :: AsyncTable -> JobId -> IO ()
    retireFresh tbl jid = do
      _ <- cancelJob tbl jid
      pure ()

-- | A recipe's original attached capacity (the conservative pending
-- need: the replayed result may run up to its first bound).
recipeCapacity :: Recipe -> Word64
recipeCapacity (RecipeCall _ _ cap _) = cap
recipeCapacity (RecipeGenKey _ cap _ _ _) = cap
recipeCapacity (RecipeGenKeyPair _ cap _ _ _ _ _) = cap

-- | A recipe's remaining schedule.
recipeTicks :: Recipe -> Int
recipeTicks (RecipeCall _ ticks _ _) = ticks
recipeTicks (RecipeGenKey ticks _ _ _ _) = ticks
recipeTicks (RecipeGenKeyPair ticks _ _ _ _ _ _) = ticks

-- | Replay a recipe against the current model: re-plan the original
-- submission for a FRESH reservation and refuse anything that does
-- not reproduce the detached effect exactly (mechanism, key,
-- params, input). Session-owned template objects remap to the
-- joining session; old handles are never trusted.
replanRecipe :: Rules -> Model -> SessionState -> JobFunction -> Recipe -> Either String AsyncWork
replanRecipe rules m st recFunc recipe = case recipe of
  RecipeCall func _ _ fx
    | func == recFunc -> case (recFunc, callInput fx) of
        (JobSign, Just input) -> replanCall F_Sign input fx
        (JobDigest, Just input) -> replanCall F_Digest input fx
        _ -> Left "recipe/function incoherence"
    | otherwise -> Left "recipe/function incoherence"
  RecipeGenKey _ _ fx tmpl owned
    | recFunc == JobGenKey -> case fx of
        FxGenerateKey mech params _ -> case planGenerateKey rules m st mech params (Map.toList tmpl) of
          KeyEffect (PwGenerateKey k) fx'
            | fx' == fx -> Right (WorkKey (joinReservation st)
                (PwGenerateKey k { poOwner = joinOwner owned }) fx')
            | otherwise -> Left "key plan does not reproduce the detached effect"
          KeyEffect _ _ -> Left "key plan shape drift"
          KeyDenied d -> Left ("key plan denied: " ++ kdReason d)
          KeyImmediate _ -> Left "key plan is immediate"
        _ -> Left "recipe/function incoherence"
    | otherwise -> Left "recipe/function incoherence"
  RecipeGenKeyPair _ _ fx pub priv pubOwned privOwned
    | recFunc == JobGenKeyPair -> case fx of
        FxGenerateKey mech _ _ ->
          case planGenerateKeyPair rules m st mech (Map.toList pub) (Map.toList priv) of
            KeyEffect (PwGeneratePair pubK privK) fx'
              | fx' == fx -> Right (WorkKey (joinReservation st)
                  (PwGeneratePair pubK { poOwner = joinOwner pubOwned }
                    privK { poOwner = joinOwner privOwned }) fx')
              | otherwise -> Left "key plan does not reproduce the detached effect"
            KeyEffect _ _ -> Left "key plan shape drift"
            KeyDenied d -> Left ("key plan denied: " ++ kdReason d)
            KeyImmediate _ -> Left "key plan is immediate"
        _ -> Left "recipe/function incoherence"
    | otherwise -> Left "recipe/function incoherence"
  where
    sid = ssId st
    -- | The replayable input of a call effect (digest\/sign only).
    callInput :: CryptoEffect -> Maybe ByteString
    callInput (FxDigest _ input) = Just input
    callInput (FxSign _ _ _ input) = Just input
    callInput _ = Nothing
    -- | Re-plan one call submission; the planned effect must equal
    -- the detached one exactly, and the re-planned pair must check
    -- as coherent call work (unreachable through the planner —
    -- every produced execution checks — so a mismatch here is an
    -- internal breach, refused loudly with no job submitted).
    replanCall :: FunctionId -> ByteString -> CryptoEffect -> Either String AsyncWork
    replanCall fid input fx =
      let req = Request Pkcs11_3_2 fid (Just sid) Nothing input
            [RegionBytes "async-join" (IntentBuffer maxOutputBytes)]
      in case planCall rules m req of
        Execute res (EffectCrypto fx')
          | fx' /= fx -> Left "session operation does not match the detached recipe"
          | otherwise -> case checkedCallWork sid res (EffectCrypto fx') of
              Left mm -> Left ("re-planned call work is incoherent: " ++ show mm)
              Right cw -> Right (WorkCall cw)
        Reject rej -> Left ("plan rejected: " ++ show (rejCode rej))
        Immediate _ -> Left "plan is immediate (operation is not pending on this session)"
    -- | Remap a session-owned template object to the joining
    -- session; token objects keep no owner.
    joinOwner :: Bool -> Maybe SessionId
    joinOwner True = Just sid
    joinOwner False = Nothing

-- | A fresh reservation pinning the joining session's revisions.
joinReservation :: SessionState -> Reservation
joinReservation st = Reservation "async-join"
  [DepSession (ssId st) (ssRevision st) (ssGeneration st)] Nothing Nothing
