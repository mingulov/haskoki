{- | Async job lifecycle operations.
-}
module Haskoki.Runtime.Async.Operations
  ( startJob
  , startSeededJob
  , startFixtureJob
  , callCompletion
  , cancelJob
  , ReapEligibility (..)
  , reapEligibility
  , reapJob
  , pollJob
  , completeJob
  ) where

import Control.Concurrent.MVar
  (newMVar)
import Control.Concurrent.STM
  ( atomically
  , readTVar
  , readTVarIO
  , writeTVar
  )
import Control.Exception
  ( AsyncException (..)
  , SomeException
  , fromException
  , mask
  , mask_
  , throwIO
  , try
  )
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust)
import qualified Data.Set as Set
import Data.Word (Word64)
import Haskoki.CallWork
  ( CallFamily (..)
  , callWorkEffect
  , callWorkFamily
  , callWorkReservation
  , checkedCallWork
  )
import Haskoki.Engine.Driver (encodeResult)
import Haskoki.Model (lookupSession)
import Haskoki.Object (decodeHandle)
import Haskoki.Operation (TypedError (..), interpretError, keptCause)
import Haskoki.Operation.Effect
  ( CryptoError
  , CryptoResult (..)
  )
import Haskoki.Operation.KeyManagement
  ( PendingWork (..)
  , finishWork
  , keyPairCompatible
  )
import Haskoki.Outcome
  ( NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , Reservation (..)
  , ResourceRelease
  , StateDelta (..)
  )
import Haskoki.Output (maxOutputBytes)
import Haskoki.Request (FunctionId (..), OutputRegion (..))
import Haskoki.Runtime.Lifecycle (Env, checkReservation, envRules, envTracer, publish, snapshotModel)
import Haskoki.Runtime.Trace (emitKeptJobFailure)
import Haskoki.Runtime.Usdt (Disposition (..), JobPhase (..),
  newUsdtOpId)
import Haskoki.ReturnCode.Generated (returnCodeToRV)
import Haskoki.Transition (finishEffect)
import Haskoki.Types
  ( JobId (..)
  , ReturnCode (..)
  , SessionId
  )
import Haskoki.Runtime.Async.Jobs
import Haskoki.Runtime.Async.Completion
import Haskoki.Runtime.Async.Outcomes
import Haskoki.Runtime.Async.Table
import Haskoki.Runtime.Async.Lease

-- ---------------------------------------------------------------------------
-- Operations
-- ---------------------------------------------------------------------------

-- | Submit a job. Work/result compatibility, call-work coherence,
-- outer-function coherence, enablement, attached-capacity bounds,
-- and live capacity are all validated BEFORE pending, in one
-- transaction with the id allocation, so every refusal consumes no
-- id and leaves the table unchanged. Check order: holdability,
-- call coherence, outer coherence, session, attached capacity,
-- live capacity. Terminal tombstones never count toward live
-- capacity (reap them with 'reapJob').
startJob :: AsyncTable -> JobRequest -> IO (Either StartDeny JobId)
startJob table req = startJobChecked table req (JobPending (jrTicks req)) True

-- | Submit a job that is already ready: rejoin of a detached
-- ready result seeds the held bytes so completion delivers without
-- re-running the effect. Validation is identical to 'startJob'
-- (same order, same no-allocation-on-refusal); only the initial
-- state differs.
startSeededJob :: AsyncTable -> JobRequest -> ByteString -> IO (Either StartDeny JobId)
startSeededJob table req bs = startJobChecked table req (JobReady (GotBytes bs)) True

-- | TEST-ONLY fixture admission: the coherence gates are skipped so
-- hand-built fixtures submit; holdability, session, capacity and
-- live gates still apply. Production never calls this.
startFixtureJob :: AsyncTable -> JobRequest -> IO (Either StartDeny JobId)
startFixtureJob table req =
  startJobChecked table req (JobPending (jrTicks req)) False

-- | Shared submit: validate, allocate the id, and insert the job in
-- the given initial state, all in one transaction. The static
-- work/result compatibility check runs first (a misconstructed
-- job is refused however healthy the table is); then call-work
-- coherence ('callWorkAdmissible'); then outer-function coherence
-- ('jobFunctionCoherent'); then session, attached capacity, live
-- capacity, as before. The flag enables the coherence gates:
-- normal submission passes 'True', the fixture entrypoint 'False'.
startJobChecked :: AsyncTable -> JobRequest -> JobState -> Bool -> IO (Either StartDeny JobId)
startJobChecked table req initial checkCoherence
  | not (effectHoldable (workEffect (jrWork req))) =
      pure (Left StartIncompatibleWork)
  | checkCoherence, not (callWorkAdmissible (jrSession req) (jrWork req)) =
      pure (Left StartIncompatibleWork)
  | checkCoherence, not (jobFunctionCoherent (jrFunction req) (jrWork req)) =
      pure (Left StartIncompatibleWork)
  | otherwise = do
      lock <- newMVar ()
      -- Op id first: gaps on refusal are harmless (uniqueness is
      -- what matters); the id rides every later transition event.
      mOpId <- newUsdtOpId
      res <- atomically $ do
        async <- readTVar (atAsync table)
        jobs <- readTVar (atJobs table)
        if jbSessionOf req `Set.notMember` async
          then pure (Left StartSessionNotAsync)
          else if jrCapacity req == 0 || jrCapacity req > maxOutputBytes
            then pure (Left StartBadCapacity)
            else if liveCount jobs >= atMax table
              then pure (Left StartOverCapacity)
              else do
                n <- readTVar (atNext table)
                writeTVar (atNext table) (n + 1)
                let job = Job
                      { jbSession = jbSessionOf req
                      , jbFunction = jrFunction req
                      , jbWork = jrWork req
                      , jbCapacity = jrCapacity req
                      , jbState = initial
                      , jbEpoch = 0
                      , jbLock = lock
                      , jbUsdt = mOpId
                      }
                -- Forced: see the forcing invariant on 'commitStep'.
                let jobs' = Map.insert (JobId n) job jobs
                jobs' `seq` writeTVar (atJobs table) jobs'
                pure (Right (JobId n, job))
      case res of
        Right (jid, job) -> do
          usdtJobPhase table jid job PhaseAccepted 0 False
          pure (Right jid)
        Left deny -> pure (Left deny)
  where
    jbSessionOf :: JobRequest -> SessionId
    jbSessionOf = jrSession
    liveCount :: Map JobId Job -> Int
    liveCount = length . filter isLive . Map.elems
    isLive :: Job -> Bool
    isLive job = case jbState job of
      JobTerminal _ -> False
      _ -> True

-- | Submit-time call-work admissibility: the carried triple must
-- re-check under the submitting session (step presence, step/session
-- identity, the function/slot family, effect compatibility — first
-- failure reports, before any id is consumed). Key pairs keep their
-- existing contract: submit admits them and the drive refuses
-- incoherent ones ('pairRefusal'), unchanged.
callWorkAdmissible :: SessionId -> AsyncWork -> Bool
callWorkAdmissible sid (WorkCall w) =
  case checkedCallWork sid (callWorkReservation w) (callWorkEffect w) of
    Right _ -> True
    Left _ -> False
callWorkAdmissible _ (WorkKey _ _ _) = True

-- | Submit-time outer-function coherence: the stored 'JobFunction'
-- must serve the inner work's family — sign work under 'JobSign',
-- digest work under 'JobDigest' (families from 'callWorkFamily'),
-- single-key work under 'JobGenKey', pair work under 'JobGenKeyPair'.
-- Key matching is PendingWork-shape based and effect-blind: inner
-- key/effect coherence stays a drive-time refusal, unchanged. All
-- eight outer arms are explicit (no wildcard), and each inner
-- 'PendingWork' case covers all 13 shapes explicitly: a new function
-- or work shape breaks the build here. Non-keygen shapes pair with
-- no outer and refuse.
jobFunctionCoherent :: JobFunction -> AsyncWork -> Bool
jobFunctionCoherent JobSign (WorkCall w) =
  callWorkFamily w == FamilySign
jobFunctionCoherent JobSign (WorkKey {}) = False
jobFunctionCoherent JobDigest (WorkCall w) =
  callWorkFamily w == FamilyDigest
jobFunctionCoherent JobDigest (WorkKey {}) = False
jobFunctionCoherent JobGenKey (WorkCall _) = False
jobFunctionCoherent JobGenKey (WorkKey _ pw _) = case pw of
  PwGenerateKey _ -> True
  PwGenerateKeyIv _ _ -> True
  PwGeneratePair _ _ -> False
  PwEncaps _ _ _ -> False
  PwDecaps _ -> False
  PwBlobOut _ -> False
  PwUnwrap _ -> False
  PwUnwrapRaw _ -> False
  PwUnwrapPad8 _ -> False
  PwUnwrapTail _ _ _ -> False
  PwDerive _ _ -> False
  PwDeriveIv _ _ _ -> False
  PwDerivePub _ _ -> False
jobFunctionCoherent JobGenKeyPair (WorkCall _) = False
jobFunctionCoherent JobGenKeyPair (WorkKey _ pw _) = case pw of
  PwGenerateKey _ -> False
  PwGenerateKeyIv _ _ -> False
  PwGeneratePair _ _ -> True
  PwEncaps _ _ _ -> False
  PwDecaps _ -> False
  PwBlobOut _ -> False
  PwUnwrap _ -> False
  PwUnwrapRaw _ -> False
  PwUnwrapPad8 _ -> False
  PwUnwrapTail _ _ _ -> False
  PwDerive _ _ -> False
  PwDeriveIv _ _ _ -> False
  PwDerivePub _ _ -> False

-- | Poll a job. A wrong-function poll is refused with the job
-- untouched; a correct-function poll on a pending job counts down,
-- and the last poll drives the effect into a held owned result and
-- reports ready. No poll path touches the result sink. Stale
-- revisions fail the drive before any effect runs.
pollJob
  :: EffectRunner -> Env -> AsyncTable -> JobFunction -> JobId -> IO PollOutcome
pollJob run env table func jid = withJobLock table jid PollUnknown $ \job ->
  -- The job arrives current under the held lease ('withJobLock'
  -- reloaded it; a job missing there already took 'PollUnknown'),
  -- so the countdown routes through 'stepJob' against one
  -- consistent record; a rejection carries the state that refused
  -- the tick, which decides drive versus observe.
  if jbFunction job /= func
    then pure (PollWrongFunction (jbFunction job) func)
    else case stepJob EvTick (jbState job) (jbEpoch job) of
      Right s -> case stepState s of
        JobPending m -> do
          commitStep table jid s
          pure (PollPending m)
        _ -> pure (PollTerminal (TermFailed CKR_GENERAL_ERROR
          "stepJob EvTick breached its contract"))
      Left (JobReject _ st) -> case st of
        JobPending _ -> driveJob run env table jid job
        JobRunning -> pure (PollPending 0)
        JobReady _ -> pure PollReady
        JobTerminal t -> pure (PollTerminal t)

-- | Drive a runnable job: refuse finisher-incoherent key pairs
-- ('pairRefusal') and stale revisions without running the
-- effect, else claim running, run the effect outside STM, then
-- hold the owned result (ready) or record the failure. Bytes hold;
-- anything else fails loudly, never silently.
--
-- Ownership rule R1: the claim-to-verdict transfer is exception-safe.
-- The claim
-- commits masked; the runner runs restored (killable). A sync throw
-- terminalizes the job and answers 'PollTerminal'; an async kill
-- terminalizes first, then rethrows (cancellation preserved after
-- cleanup). Never a permanently running job.
-- | The pre-execution refusal for a finisher-incoherent key
-- pair, if any. Call work checks at submit instead
-- ('callWorkAdmissible', before any id is consumed), so every
-- call job tabled through normal submission already coheres by
-- drive time; key work refuses here through 'keyPairCompatible'
-- before any effect runs. Both 'Show' instances redact secrets.
pairRefusal :: AsyncWork -> Maybe String
pairRefusal (WorkKey _ pw fx)
  | not (keyPairCompatible pw fx) =
      Just ("internal: incoherent key pair cannot execute: " ++ show pw ++ " / " ++ show fx)
pairRefusal _ = Nothing

driveJob :: EffectRunner -> Env -> AsyncTable -> JobId -> Job -> IO PollOutcome
driveJob run env table jid job
  | Just msg <- pairRefusal (jbWork job) =
      failDrive (EvFail CKR_GENERAL_ERROR msg) (jbState job) (jbEpoch job)
        (TermFailed CKR_GENERAL_ERROR msg)
  | otherwise = do
  stale <- checkReservation env (workReservation (jbWork job))
  case stale of
    Just dep ->
      let msg = "stale reservation: " ++ show dep
      in failDrive (EvFail CKR_GENERAL_ERROR msg) (jbState job) (jbEpoch job)
        (TermFailed CKR_GENERAL_ERROR msg)
    Nothing ->
      case stepJob EvClaim (jbState job) (jbEpoch job) of
        Left _ -> pure (PollTerminal (TermFailed CKR_GENERAL_ERROR
          "stepJob EvClaim breached its contract"))
        Right claimed -> mask $ \restore -> do
          commitStep table jid claimed
          usdtJobPhase table jid job PhaseClaimed 0 False
          r <- try (restore (run (workEffect (jbWork job))))
          case r of
            Right res -> holdDrive res (stepState claimed) (stepEpoch claimed)
            Left e -> case (fromException e :: Maybe AsyncException) of
              Just ae ->
                let msg = "drive interrupted: " ++ show ae
                in failDrive (EvFail CKR_GENERAL_ERROR msg)
                    (stepState claimed) (stepEpoch claimed)
                    (TermFailed CKR_GENERAL_ERROR msg)
                  >> throwIO ae
              Nothing ->
                let msg = "drive threw: " ++ show (e :: SomeException)
                in failDrive (EvFail CKR_GENERAL_ERROR msg)
                    (stepState claimed) (stepEpoch claimed)
                    (TermFailed CKR_GENERAL_ERROR msg)
  where
    -- Hold the effect answer: bytes go ready, anything else fails.
    -- The claim verdict's state and epoch thread in, exactly as the
    -- old direct writes computed them.
    holdDrive :: CryptoResult -> JobState -> Word64 -> IO PollOutcome
    holdDrive res st e =
      let holdStep = case stepJob (EvHold res) st e of
            Right s -> do
              commitStep table jid s
              usdtJobPhase table jid job PhaseReady 0 False
              pure PollReady
            Left _ -> pure (PollTerminal (TermFailed CKR_GENERAL_ERROR
              "stepJob EvHold breached its contract"))
      in case res of
        GotBytes _ -> holdStep
        -- A unit-held answer holds like bytes (the
        -- distinction survives the hold; delivery encodes it as
        -- empty bytes).
        GotUnit -> holdStep
        GotValid _ -> failDrive
          (EvFail CKR_GENERAL_ERROR "verdict answer to a bytes job") st e
          (TermFailed CKR_GENERAL_ERROR "verdict answer to a bytes job")
        GotResource _ -> failDrive
          (EvFail CKR_GENERAL_ERROR "resource answer to a bytes job") st e
          (TermFailed CKR_GENERAL_ERROR "resource answer to a bytes job")
        GotCryptoError err -> do
          let fid = jobExactFid job
              code = interpretError fid (TyCrypto err)
          out <- failDrive (EvFail code (show err)) st e
            (TermFailed code (show err))
          emitDriveCause env table jid fid err code
          pure out
    -- Fail a drive step through 'stepJob', reporting the coded reason.
    failDrive :: JobEvent -> JobState -> Word64 -> TerminalState -> IO PollOutcome
    failDrive ev st e t = case stepJob ev st e of
      Right s -> do
        commitStep table jid s
        let code = case ev of
              EvFail c _ -> c
              _ -> CKR_GENERAL_ERROR
            w = returnCodeToRV code
        usdtJobPhase table jid job PhaseFailed w True
        usdtAsyncEnd job w DispFailedPublish
        pure (PollTerminal t)
      Left _ -> pure (PollTerminal (TermFailed CKR_GENERAL_ERROR
        "stepJob EvFail breached its contract"))

-- | Emit a driven crypto failure's kept cause through the env
-- tracer, if the cell kept it general. Called once per job:
-- only the driving poll reaches the failure branch (terminal
-- jobs short-circuit; later polls and completes observe).
emitDriveCause :: Env -> AsyncTable -> JobId -> FunctionId -> CryptoError -> ReturnCode -> IO ()
emitDriveCause env table jid fid err code =
  case keptCause fid (GotCryptoError err) code of
    Just cause -> do
      mTr <- readTVarIO (envTracer env)
      case mTr of
        Just tr -> emitKeptJobFailure tr (asyncTableId table) jid cause
        Nothing -> pure ()
    Nothing -> pure ()

-- | Complete a job. Wrong-function and pending jobs report with
-- the sink untouched; ready jobs publish their commit, go
-- terminal, then deliver the canonical completion exactly once.
-- Short buffers report their sizing with the result held.
completeJob
  :: Env -> AsyncTable -> JobFunction -> JobId -> Delivery
  -> (ResourceRelease -> IO ()) -> IO CompleteOutcome
completeJob env table func jid del release =
  withJobLock table jid CompleteUnknown $ \job ->
    -- The job arrives current under the held lease ('withJobLock'
    -- reloaded it; a job missing there already took
    -- 'CompleteUnknown').
    if jbFunction job /= func
      then pure (CompleteWrongFunction (jbFunction job) func)
      else case jbState job of
        JobTerminal t -> pure (CompleteAlready t)
        JobPending n -> pure (CompletePending n)
        JobRunning -> pure (CompletePending 0)
        -- Bytes-like held answers (bytes or unit) complete;
        -- the held shape flows to the finishers, collapsing only at
        -- 'encodeResult'.
        JobReady h | isBytesLike h -> case jbWork job of
          WorkCall w -> callComplete env table jid job del
            (callWorkReservation w) h release
          WorkKey _ pw _ -> keyComplete env table jid job del pw h release
        -- A held non-bytes result is a data-shape failure, not a
        -- transition decision: the shape is read here, the failure
        -- commits through 'stepJob' against the current record.
        JobReady other ->
          let why = "non-bytes held result: " ++ heldTag (jobExactFid job) other
          in case stepJob (EvFail CKR_GENERAL_ERROR why)
              (jbState job) (jbEpoch job) of
            Right s -> do
              commitStep table jid s
              let w = returnCodeToRV CKR_GENERAL_ERROR
              usdtJobPhase table jid job PhaseFailed w True
              usdtAsyncEnd job w DispFailedPublish
              pure (CompleteAlready (TermFailed CKR_GENERAL_ERROR why))
            Left _ -> pure (CompleteAlready (TermFailed CKR_GENERAL_ERROR
              "stepJob EvFail breached its contract"))
  where
    heldTag :: FunctionId -> CryptoResult -> String
    heldTag _ (GotBytes _) = "bytes"
    heldTag _ (GotValid _) = "verdict"
    heldTag _ (GotResource _) = "resource"
    heldTag _ GotUnit = "unit"
    heldTag fid (GotCryptoError e) = show (interpretError fid (TyCrypto e))

-- | The byte-payload length a completion would deliver: the raw
-- bytes for 'CompBytes', zero for handle shapes (handles land in
-- the result struct's handle fields, never in a byte buffer — only
-- @ulValue@ sizes, like @CK_ASYNC_DATA@).
deliveryNeed :: Completion -> Word64
deliveryNeed (CompBytes bs) = fromIntegral (BS.length bs)
deliveryNeed (CompOneHandle _) = 0
deliveryNeed (CompTwoHandles _ _) = 0

-- | Bytes-like held answers: bytes carry their payload, a
-- unit answer delivers as empty bytes (the completion codec has no
-- unit shape — wire-identical to the pre-change held-empty-bytes
-- behavior). 'Nothing' for verdict, resource, and error holdings.
heldBytesLike :: CryptoResult -> Maybe ByteString
heldBytesLike (GotBytes bs) = Just bs
heldBytesLike GotUnit = Just BS.empty
heldBytesLike _ = Nothing

-- | Whether a held answer may complete ('heldBytesLike' admits it).
isBytesLike :: CryptoResult -> Bool
isBytesLike = isJust . heldBytesLike

-- | Commit-then-deliver with pre-commit sizing: when the result
-- payload fits both the attached capacity and the caller's buffer,
-- publish the commit, drain its releases, go terminal, and write
-- exactly once; otherwise report the payload sizing with no
-- publish, no drain, no state change, no epoch move, and no payload
-- write. The held result survives for a roomier retry without
-- re-running the effect (the retry drains on delivery).
commitAndTryDeliver
  :: Env -> AsyncTable -> JobId -> Job -> Delivery
  -> StateDelta -> [ResourceRelease] -> (ResourceRelease -> IO ())
  -> Completion -> IO CompleteOutcome
commitAndTryDeliver env table jid job del delta releases release completion = do
  let need = deliveryNeed completion
  if need > jbCapacity job || need > dCapacity del
    then do
      dReportNeeded del need
      pure (CompleteShort need)
    else do
      pr <- publish env delta
      case pr of
        -- A faulted publish still drains the commit's
        -- releases exactly once — releases free engine resources
        -- that exist independent of the model commit, so skipping
        -- the drain would orphan them until backend close (the
        -- stale-orphan precedent; frees are idempotent takes, so
        -- no double free). The job still fails terminal with the
        -- sink untouched.
        Left fault -> do
          mapM_ release releases
          failJob table jid job CKR_GENERAL_ERROR (show fault)
        -- Delivery commits through 'stepJob' against the live
        -- record re-read under the held lease (still the ready job
        -- the complete step dispatched on: no other lease-holder can
        -- have touched it, and eviction only removes terminal
        -- jobs). State and epoch come from that one re-read.
        -- Releases drain AFTER the successful publish, like every
        -- other commit-application site; a short completion drains
        -- nothing, while a faulted publish still drains the
        -- commit's releases exactly once (see above).
        Right () -> mask_ $ do
          mapM_ release releases
          cur <- readJob table jid
          -- Missing at this re-read: unknown, exactly as if the
          -- owner reaped it. Nothing was written yet: the write
          -- follows a successful step below.
          case cur of
            Nothing -> pure CompleteUnknown
            Just j -> case stepJob (EvDeliver completion)
              (jbState j) (jbEpoch j) of
              Right s -> do
                -- Ownership rules R5\/R6: the write precedes the commit, so a
                -- throwing sink leaves 'Ready' (recoverable, retry
                -- re-finishes). The masked tail delays kills past the
                -- commit for its non-blocking stretches
                -- (exactly-once write); a kill in a BLOCKED sink
                -- still lands (blocking calls stay killable under
                -- 'mask_') with the job 'Ready'. Sync throws
                -- propagate at once — masking only delays
                -- other-thread kills in non-blocking code.
                dWrite del (encodeCompletion completion)
                commitStep table jid s
                usdtJobPhase table jid j PhaseDelivered 0 False
                usdtAsyncEnd j (returnCodeToRV CKR_OK) DispDelivered
                pure (CompleteDelivered completion)
              Left _ -> pure (CompleteAlready (TermFailed CKR_GENERAL_ERROR
                "stepJob EvDeliver breached its contract"))

-- | Read a call completion out of a finisher's outputs.
--
-- Aux-output scope ruling (rebind hole, rule-with-criteria):
-- IN — zero outputs (legacy commits deliver the engine bytes) and
-- exactly one 'RegionBytes' output (delivers its bytes). OUT (loud
-- 'Nothing' — the caller fails the job, never silently drops or
-- partially delivers): 2+ outputs of any regions (no per-function
-- join semantics exist — concatenate? first-wins? per-region
-- routing? — and no async-path finisher emits them);
-- 'RegionHandle' on call paths (handles complete only via key
-- paths: 'keyCompletion' admits 1 handle for 'JobGenKey', 2 for
-- 'JobGenKeyPair'); 'RegionScalar'\/'RegionNested' anywhere (the
-- completion codec encodes bytes + 1\/2 handles only). Rationale:
-- one delivery carries exactly one payload shape; adding rebind
-- would need a producer (none exists), per-family join semantics
-- (specified nowhere), and a multi-shape completion plus FFI
-- delivery change (C ABI surface) — cost and risk without a
-- producer, so OUT. Revisit if a finisher starts emitting
-- multi-output: the loud failure points here.
callCompletion :: ByteString -> [NativeOutput] -> Maybe Completion
callCompletion bs [] = Just (CompBytes bs)
callCompletion _ [NativeOutput (RegionBytes _ _) out] = Just (CompBytes out)
callCompletion _ _ = Nothing

-- | Complete a call job: finish the held answer against a fresh
-- snapshot (stale reservations reject here, before any publish),
-- publish the commit, then deliver sized. Legacy commits (no
-- finisher outputs) deliver the engine bytes; a single byte output
-- delivers its exact bytes; anything else fails loudly. Every
-- published finish drains its releases through the caller-supplied
-- interpreter, so a consumed stream cannot leak.
callComplete
  :: Env -> AsyncTable -> JobId -> Job -> Delivery
  -> Reservation -> CryptoResult -> (ResourceRelease -> IO ())
  -> IO CompleteOutcome
callComplete env table jid job del res held release = do
  m <- snapshotModel env
  case finishEffect (envRules env) m res (encodeResult held) of
    Left rej -> do
      _ <- publish env (rejDelta rej)
      mapM_ release (rejReleases rej)
      failJob table jid job (rejCode rej) (unwords (rejReasons rej))
    Right pc
      | pcCode pc /= CKR_OK -> do
          _ <- publish env (pcDelta pc)
          mapM_ release (pcReleases pc)
          failJob table jid job (pcCode pc) (unwords (pcReasons pc))
      | otherwise -> case heldBytesLike held of
          Just bs -> case callCompletion bs (pcOutputs pc) of
            Just completion ->
              commitAndTryDeliver env table jid job del
                (pcDelta pc) (pcReleases pc) release completion
            Nothing -> failJob table jid job CKR_GENERAL_ERROR
              "call completion is not single bytes"
          -- Unreachable: 'completeJob' admits only bytes-like
          -- held answers; loud failure if that ever breaks.
          Nothing -> failJob table jid job CKR_GENERAL_ERROR
            "non-bytes held result reached callComplete"

-- | Fail a job from a complete step: terminal with the coded
-- reason, epoch bumped, sink untouched.
failJob
  :: AsyncTable -> JobId -> Job -> ReturnCode -> String -> IO CompleteOutcome
failJob table jid job code reason =
  case stepJob (EvFail code reason) (jbState job) (jbEpoch job) of
    Right s -> do
      commitStep table jid s
      let w = returnCodeToRV code
      usdtJobPhase table jid job PhaseFailed w True
      usdtAsyncEnd job w DispFailedPublish
      pure (CompleteAlready (TermFailed code reason))
    Left _ -> pure (CompleteAlready (TermFailed CKR_GENERAL_ERROR
      "stepJob EvFail breached its contract"))

-- | Complete a key job: finish the held answer against a fresh
-- model snapshot, validate the handle shape BEFORE publishing, then
-- commit-then-deliver. A gone session, a finisher rejection, or a
-- shape mismatch fails with nothing published and nothing written.
keyComplete
  :: Env -> AsyncTable -> JobId -> Job -> Delivery
  -> PendingWork -> CryptoResult -> (ResourceRelease -> IO ())
  -> IO CompleteOutcome
keyComplete env table jid job del pw held release = do
  m <- snapshotModel env
  case lookupSession m (jbSession job) of
    Nothing -> failJob table jid job
      CKR_GENERAL_ERROR "async session is gone"
    Just st -> case finishWork m st pw held of
      Immediate pc -> case keyCompletion (jbFunction job) (pcOutputs pc) of
        Nothing -> failJob table jid job CKR_GENERAL_ERROR
          "key completion shape mismatch"
        Just completion ->
          commitAndTryDeliver env table jid job del
            (pcDelta pc) (pcReleases pc) release completion
      Reject rej -> do
        _ <- publish env (rejDelta rej)
        mapM_ release (rejReleases rej)
        failJob table jid job (rejCode rej)
          (unwords (rejReasons rej))
      Execute _ _ -> failJob table jid job CKR_GENERAL_ERROR
        "key finisher emitted an effect"

-- | Read a key completion out of a finisher's outputs: exactly one
-- handle for 'JobGenKey', exactly two for 'JobGenKeyPair'. Anything
-- else is an internal mismatch the caller reports loudly.
keyCompletion :: JobFunction -> [NativeOutput] -> Maybe Completion
keyCompletion JobGenKey [NativeOutput (RegionHandle _) bs] =
  CompOneHandle <$> decodeHandle bs
keyCompletion JobGenKeyPair
  [NativeOutput (RegionHandle _) b1, NativeOutput (RegionHandle _) b2] =
    CompTwoHandles <$> decodeHandle b1 <*> decodeHandle b2
keyCompletion _ _ = Nothing

-- | Cancel a job: any live state goes terminal-canceled with no
-- engine work past the cancel and no sink contact. Terminal jobs
-- report the winner's state.
cancelJob :: AsyncTable -> JobId -> IO CancelOutcome
cancelJob table jid = withJobLock table jid CancelUnknown $ \job ->
  -- Cancel routes through 'stepJob' against the current record
  -- ('withJobLock' reloaded it; a job missing there already took
  -- 'CancelUnknown'); a rejection carries the terminal state the
  -- caller observes.
  case stepJob EvCancel (jbState job) (jbEpoch job) of
    Right s -> do
      commitStep table jid s
      usdtJobPhase table jid job PhaseCanceled 0 False
      usdtAsyncEnd job (returnCodeToRV CKR_FUNCTION_CANCELED) DispAbandoned
      pure CancelOk
    Left (JobReject _ (JobTerminal t)) -> pure (CancelAlready t)
    Left _ -> pure (CancelAlready (TermFailed CKR_GENERAL_ERROR
      "stepJob EvCancel breached its contract"))

-- | Whether a job state may be reaped.
--
-- Retention\/expiry ruling (rule-with-criteria): retention
-- bound — DUAL: at most 'maxRetainedTombstones' terminal
-- tombstones per table AND at most 'maxRetainedBytes' retained
-- bytes; every commit past either bound evicts the oldest
-- (lowest-id) terminal tombstones first, so repeated jobs
-- cannot grow provider memory without bound — by count or by
-- bytes (tombstones retain full inputs plus completion
-- payloads, so a count cap alone still admits tens of GiB).
-- The live cap counts LIVE ONLY (tombstones never block
-- submits; delivered tombstones retain their completion
-- payload until evicted or reaped). Who reaps when — the job
-- OWNER via manual terminal-only 'reapJob' (synchronous, under
-- the job lease) for eager release, plus automatic
-- oldest-first eviction on commit; no background reaper
-- (discipline: no background threads). Cancel-after-detach —
-- 'CancelUnknown' at the source (revoked from the table);
-- cancel routes to the table that HOLDS the job, which
-- post-revoke is the rejoin-side table ('joinJob' side), never
-- the source. Why caps, not reap-on-read: reaping on read
-- cannot bound fire-and-forget workloads (nothing re-reads, so
-- nothing is reaped) and would change every delivered job's
-- re-read outcome; the caps keep observe semantics exact for
-- all retained jobs (an evicted job observes unknown, exactly
-- as if the owner had reaped it). Why DUAL: inputs are
-- attacker-sized and outputs run to 16 MiB, so the count cap
-- alone still admits tens of GiB; the byte budget prices every
-- retained payload byte (see 'retainedBytes') while the count
-- cap backstops the many-small case the suites pin.
--
-- Eviction invariant: eviction removes only terminal tombstones,
-- never the just-committed job and never a live job — so it can
-- never resurrect a job, break a pending delivery, or change a
-- live job's cancelability ('CancelOk' still wins on live; a
-- concurrent loser still observes the winner). An EVICTED
-- elder's later cancel observes 'CancelUnknown' rather than
-- 'CancelAlready' — exactly as if the owner had reaped it
-- (reaping and eviction agree on unknown). A poll\/complete that
-- admitted its lease before the eviction and re-reads after it
-- likewise observes unknown — never a fabricated terminal.
data ReapEligibility = EligibleTerminal | BlockedLive
  deriving (Eq, Show)

-- | The reaping rule: terminal tombstones drop, live states stay.
reapEligibility :: JobState -> ReapEligibility
reapEligibility (JobTerminal _) = EligibleTerminal
reapEligibility _ = BlockedLive

-- | Reap a terminal job's tombstone under its lease. Live jobs
-- report 'ReapLive' with the job untouched; unknown ids report
-- 'ReapUnknown'.
reapJob :: AsyncTable -> JobId -> IO ReapOutcome
reapJob table jid = withJobLock table jid ReapUnknown $ \job ->
  -- The job arrives current under the held lease (a job missing
  -- there already took 'ReapUnknown').
  case reapEligibility (jbState job) of
    EligibleTerminal -> do
      atomically $ do
        jobs <- readTVar (atJobs table)
        -- Forced: see the forcing invariant on 'commitStep'.
        let jobs' = Map.delete jid jobs
        jobs' `seq` writeTVar (atJobs table) jobs'
      pure Reaped
    BlockedLive -> pure ReapLive
