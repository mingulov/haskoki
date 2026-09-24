{- | Attached asynchronous execution: logical scheduling, attached
jobs, and exact completion delivery.

A job is submitted on an async-enabled session with a planned unit
of work (a 'Reservation' plus its 'EffectRequest', the common plan
currency), an explicit completion schedule (polls before runnable),
and an attached output capacity. The logical executor runs the
effect into an owned result once the schedule elapses (poll-driven;
no background threads, no wall-clock sleeps), holds it, and the
completion step publishes the prepared commit and delivers the
completion record exactly once.

State machine per job (execution dimension; attachment stays
attached — detach\/rejoin belongs to the detached-jobs layer):

@
Pending ticks --poll--> Pending (ticks-1) | Running --drive--> Ready result
Ready --complete--> Delivered    Pending\/Running\/Ready --cancel--> Canceled
drive\/complete failure --> Failed
@

Discipline (architecture sections 6-8, design 07):

* Delivery lease: one 'MVar' per job guards poll\/complete\/cancel.
  The winner's critical section covers effect execution, commit
  publication, and delivery; losers block briefly, then observe the
  winner's terminal state and write nothing. Cancellation can never
  steal a commit, and two completions can never deliver twice.
* STM transactions coordinate @TVar@ state only: job-table reads
  and writes. Effect execution, publication (gate), and delivery
  (caller sinks) run outside 'atomically'.
* Pending paths never touch the result sink: not polled-pending,
  not complete-while-pending, not drive (which holds, not
  delivers). The sink fires exactly once, on the winning complete.
* Epochs: every terminal transition bumps the job's cancellation
  epoch, so arbitration order is observable per job.
* Synchronous sessions stay synchronous structurally: the sync
  plan\/publish path never consults the job table, and jobs exist
  only for sessions that explicitly requested async.

Ownership Contract (stated here; implemented by the async paths,
reconciled by the Publication\/Delivery section below):

* R1 drive: the claim ('JobRunning') is owned by the driving thread
  under the job lease. A sync runner throw terminalizes the job
  ('EvFail') and answers 'PollTerminal'; an async kill terminalizes
  first, then rethrows (cancellation preserved after cleanup). The
  lease backstop ('withJobLock') repairs any residual 'JobRunning'
  to failed on exception escape. Observable: never a permanently
  running job.
* R5 publish\/deliver: sizing-check, then publish, then a MASKED
  tail of drain-releases, delivery-write, and 'EvDeliver' commit —
  the write precedes the commit, so a throwing sink leaves 'Ready'.
  Short reports sizing with everything untouched; a faulted publish
  fails terminal with the sink untouched. Every finish drains its
  releases exactly once — on success, on rejection, AND on faulted
  publish (releases free resources that exist independent of
  the commit; skipping would orphan until backend close).
* R6 delivery failure is RECOVERABLE: a sync sink throw propagates
  with the job 'Ready' (retry re-finishes and re-publishes); a kill
  before the commit leaves 'Ready', a kill in the tail's
  non-blocking stretches is delayed past the commit (exactly-once
  write), and a kill in a BLOCKED sink lands (blocking calls stay
  killable under 'mask_') with the job still
  'Ready'. Sinks must be short and atomic; release interpreters
  must not throw.
* Detach composition: detach leases ('beginDetach' \/
  'withDetachLease') keep their masked take-to-handoff and
  commit\/abort pairing untouched; this contract adds no second
  lease — drive\/deliver repair runs INSIDE the job lease the
  detach protocol already coordinates with.
* Scope flags: aux-output rebind and expiry\/GC
  are ruled below; until then single-bytes-or-fail and manual
  'reapJob' stand.

Publication\/Delivery Contract (reconciles Standard
'publishCommit' with the async paths; stream ordering kept):

* Short-buffer retry: sizing-check first; short reports the need
  with no publish, no drain, no state change — the held result
  survives and the roomier retry drains exactly once on delivery.
* Publication failure: terminal-failed with the sink untouched;
  every finish drains its releases exactly once — on success, on
  rejection, AND on faulted publish (releases free resources that
  exist independent of the commit; frees are idempotent takes).
* Delivery failure: recoverable (R6) — the job stays 'Ready' and
  the retry re-finishes; op-state retries re-land and deliver,
  keygen retries mint fresh handles (first-published set
  orphaned — documented caveat).

Covered public entry paths (66 FFI exports surveyed 2026-09-23;
funnels: Standard\/Async\/Exports 'publishCommit' \/
'publishRejection' + job ops below):

* Async job ops (rules R1\/R5\/R6): 'haskoki_hs_async_start\/poll\/
  complete\/cancel', 'async_close' (cancels live jobs), 'async_join'
  (rejoin) and 'async_get_id' (detach) via the composed
  'joinJob'\/'detachJob' leases.
* Sync commit funnels (drain-always-once + fault rules): every
  plan+publish path — all 'haskoki_std_*' session\/object\/find\/
  login\/crypto\/keygen\/wrap\/derive entries (via
  'runCryptoPlan\/Silent\/Buffered\/Query\/Update',
  'runKeyPlan', 'runWrapPlan', 'runKeyedInit', or direct funnel
  sites), 'haskoki_hs_async_open\/open_on\/digest_init\/start'
  (Async funnel: proof sessions, init plan, start leg), and
  'haskoki_hs_crypto_open\/digest_init\/digest' (Exports funnel).
* OUT — read-only snapshots: 'std_get_slot_list\/get_session_info\/
  token_live\/token_label\/slot_present' (no mutation).
* OUT — cursor-local: 'std_find\/find_final' (instance 'IORef' only).
* OUT — backend-direct: 'std_generate_random\/seed_random'
  (backend RNG, no model commit).
* OUT — lifecycle alloc\/free: 'std_open\/close',
  'haskoki_hs_crypto_close' (instance + 'closeBackend', no commit).
* OUT — storage: 'async_store_open\/close' (file IO; storage contract).
* OUT — separate contracts: 'instance_open/close' (lifecycle driver),
  'haskoki_wait_for_slot_event'\/'haskoki_control' (control-events
  driver).
* Legacy (not live): 'commitAndDeliver' keeps its old
  no-drain-on-fault shape; test-only, out of this contract.

-}
module Haskoki.Runtime.Async
  ( -- * Jobs and functions
    JobFunction (..)
  , AsyncWork (..)
  , JobRequest (..)
  , StartDeny (..)
    -- * Completion records and codecs
  , Completion (..)
  , encodeCompletion
  , decodeCompletion
    -- * Outcomes
  , TerminalState (..)
  , JobState (..)
  , JobEvent (..)
  , JobReject (..)
  , JobStep
  , stepJob
  , stepState
  , stepEpoch
  , PollOutcome (..)
  , CompleteOutcome (..)
  , CancelOutcome (..)
  , ReapOutcome (..)
  , Delivery (..)
  , EffectRunner
    -- * Table
  , AsyncTable
  , newAsyncTable
  , enableAsyncSession
  , isAsyncSession
  , tableStats
  , deliveredCount
  , JobView (..)
  , inspectJob
  , jobReadyNeed
  , jobFunctionOf
  , sessionJobs
    -- * Detach support (snapshots, leases, seeded starts)
  , JobSnapshot
  , jobSnapshotFunction
  , jobSnapshotWork
  , jobSnapshotState
  , jobSnapshotTicks
  , jobSnapshotCapacity
  , jobSnapshotSession
  , jobSnapshotEpoch
  , JobSnapState (..)
  , snapshotJob
  , DetachLease
  , beginDetach
  , leaseSnapshot
  , commitDetachRevoke
  , abortDetach
  , LeaseView (..)
  , withDetachLease
  , leaseLockHeld
  , startSeededJob
    -- * Operations
  , startJob
  , effectHoldable
  , pollJob
  , completeJob
  , cancelJob
  , reapJob
    -- * Scope classifiers (pure; see the rebind\/expiry rulings below)
  , callCompletion
  , ReapEligibility (..)
  , reapEligibility
    -- * Simulation bridge (scheduler advance)
  , advanceTicks
  ) where

import Control.Concurrent.MVar
  (MVar, newMVar, putMVar, takeMVar, tryTakeMVar, withMVar)
import Control.Concurrent.STM
  ( TVar
  , atomically
  , newTVarIO
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
  , onException
  , throwIO
  , try
  , uninterruptibleMask_
  )
import Control.Monad (unless)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust, listToMaybe)
import Data.Set (Set)
import qualified Data.Set as Set
import qualified Data.Text as T
import Data.Word (Word32, Word64)

import Haskoki.Engine.Driver (encodeResult)
import Haskoki.Model (lookupSession)
import Haskoki.Object (decodeHandle, encodeHandle)
import Haskoki.Operation (TypedError (..), interpretError)
import Haskoki.Operation.Effect
  ( CryptoEffect (..)
  , CryptoResult (..)
  )
import Haskoki.Operation.KeyManagement (PendingWork, finishWork, keyPairCompatible)
import Haskoki.Outcome
  ( EffectRequest (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , Reservation
  , ResourceRelease
  , StateDelta (..)
  )
import Haskoki.Output (maxOutputBytes)
import Haskoki.Registry.Generated (generatedInventory)
import Haskoki.Registry.Types (MechanismId (..))
import Haskoki.Request (OutputRegion (..))
import Haskoki.Runtime.Lifecycle (Env, checkReservation, envRules, publish, snapshotModel)
import Haskoki.Transition (finishEffect)
import Haskoki.Types
  ( ExternalHandle
  , JobId (..)
  , ReturnCode (..)
  , SessionId
  , redactShown
  )

-- ---------------------------------------------------------------------------
-- Jobs and functions
-- ---------------------------------------------------------------------------

-- | Which function family a job belongs to. Pollers name the family
-- they serve; a mismatch is a typed refusal and the job is left
-- intact. Constructor order is stable (the FFI code mapping keys
-- off it): append, never reorder.
data JobFunction
  = JobSign
  | JobDigest
  | JobGenKey
  | JobGenKeyPair
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | One planned unit of async work: the reservation that guards its
-- commit plus the effect the drive step runs. 'WorkCall' finishes
-- through the call finisher; 'WorkKey' through the key finisher.
data AsyncWork
  = WorkCall !Reservation !EffectRequest
  | WorkKey !Reservation !PendingWork !CryptoEffect
  deriving (Eq, Show)

-- | The effect a drive step runs for a job.
workEffect :: AsyncWork -> CryptoEffect
workEffect (WorkCall _ (EffectCrypto fx)) = fx
workEffect (WorkKey _ _ fx) = fx

-- | The reservation that guards a job's commit. The drive step
-- refuses to run against stale revisions; the complete step
-- re-validates through its finisher before publishing.
workReservation :: AsyncWork -> Reservation
workReservation (WorkCall res _) = res
workReservation (WorkKey res _ _) = res

-- | A submit request: session, function, planned work, polls before
-- runnable, and attached byte-payload capacity (bounds byte
-- results; handle results carry no byte payload).
data JobRequest = JobRequest
  { jrSession :: !SessionId
  , jrFunction :: !JobFunction
  , jrWork :: !AsyncWork
  , jrTicks :: !Int
  , jrCapacity :: !Word64
  } deriving (Eq, Show)

-- | Why submission was refused. Refusals allocate nothing: no job
-- id is consumed and the table is unchanged.
data StartDeny
  = StartSessionNotAsync
  | StartOverCapacity
  | StartBadCapacity
  | StartIncompatibleWork
  deriving (Eq, Show)

-- | Whether an effect can produce an answer the job can hold:
-- the work/result compatibility rule. Every completion
-- gates on bytes-like holdings ('isBytesLike'), so only
-- bytes- and unit-producing effects hold; resource-producing
-- allocation ('FxDigestInit') and verdict-producing verification
-- ('FxVerify', 'FxMessageVerify') never can. Recovery effects
-- hold by their natural bytes shape (a driver that cannot run
-- them refuses loudly at drive time — defense in depth,
-- unchanged). 'startJobWith' refuses unholdable work at submit.
effectHoldable :: CryptoEffect -> Bool
-- Exhaustive, not fail-open — every constructor has an
-- explicit arm (no wildcard). A new effect fails validation via
-- -Werror=incomplete-patterns, forcing an explicit
-- holdability verdict here; the holdability battery pins every
-- verdict against silent flips.
effectHoldable (FxDigestInit _) = False
effectHoldable (FxVerify _ _ _ _ _) = False
effectHoldable (FxMessageVerify _ _ _ _ _) = False
effectHoldable (FxDigest _ _) = True
effectHoldable (FxDigestFeed _ _) = True
effectHoldable (FxDigestConsume _) = True
effectHoldable (FxCipher _ _ _ _ _) = True
effectHoldable (FxSign _ _ _ _) = True
effectHoldable (FxSignRecover _ _ _ _ _) = True
effectHoldable (FxVerifyRecover _ _ _ _ _) = True
effectHoldable (FxMessageCipher _ _ _ _ _ _) = True
effectHoldable (FxMessageSign _ _ _ _) = True
effectHoldable (FxGenerateKey _ _ _) = True
effectHoldable (FxWrap _ _ _ _) = True
effectHoldable (FxUnwrap _ _ _ _) = True
effectHoldable (FxAuthWrap _ _ _ _) = True
effectHoldable (FxAuthUnwrap _ _ _ _) = True
effectHoldable (FxDerive _ _ _ _ _) = True
effectHoldable (FxKemEncaps _ _ _ _) = True
effectHoldable (FxKemDecaps _ _ _ _) = True

-- ---------------------------------------------------------------------------
-- Completion records and codecs
-- ---------------------------------------------------------------------------

-- | One delivered completion: exact bytes (sign\/digest), one
-- handle (generated key), or two handles (generated pair).
data Completion
  = CompBytes !ByteString
  | CompOneHandle !ExternalHandle
  | CompTwoHandles !ExternalHandle !ExternalHandle
  deriving (Eq, Show)

-- | Canonical completion bytes: @tag:u8 body@. @0x01@ carries bytes
-- with a @u32BE@ length; @0x02@\/@0x03@ carry one\/two canonical
-- 8-byte handles ('encodeHandle'). Encode sides only ever emit
-- exact frames.
encodeCompletion :: Completion -> ByteString
encodeCompletion (CompBytes bs) =
  BS.pack [0x01] <> u32be (fromIntegral (BS.length bs)) <> bs
encodeCompletion (CompOneHandle h) =
  BS.pack [0x02] <> encodeHandle h
encodeCompletion (CompTwoHandles h1 h2) =
  BS.pack [0x03] <> encodeHandle h1 <> encodeHandle h2

-- | Strict completion decode: exact-length frames only. Bad tags,
-- short or trailing bytes, and byte lengths past 'maxOutputBytes'
-- all reject; handles must be canonical 8-byte frames.
decodeCompletion :: ByteString -> Maybe Completion
decodeCompletion bs = case BS.uncons bs of
  Just (0x01, rest)
    | BS.length rest >= 4 ->
        let (bLen, payload) = BS.splitAt 4 rest
            n = foldBE bLen
        in if n > toInteger maxOutputBytes
          then Nothing
          else if fromInteger n /= BS.length payload
            then Nothing
            else Just (CompBytes payload)
  Just (0x02, rest)
    | BS.length rest == 8 -> CompOneHandle <$> decodeHandle rest
  Just (0x03, rest)
    | BS.length rest == 16 ->
        CompTwoHandles <$> decodeHandle (BS.take 8 rest)
          <*> decodeHandle (BS.drop 8 rest)
  _ -> Nothing

-- | Big-endian fold computed in 'Integer' so large values never wrap.
foldBE :: ByteString -> Integer
foldBE = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | Big-endian 32-bit frame.
u32be :: Word32 -> ByteString
u32be w = BS.pack
  [ fromIntegral ((w `shiftR` 24) .&. 0xFF)
  , fromIntegral ((w `shiftR` 16) .&. 0xFF)
  , fromIntegral ((w `shiftR` 8) .&. 0xFF)
  , fromIntegral (w .&. 0xFF)
  ]

-- ---------------------------------------------------------------------------
-- Outcomes
-- ---------------------------------------------------------------------------

-- | A job's terminal state. Losers observe this (never partial
-- output): delivered completions, cancellation, or a coded failure.
data TerminalState
  = TermDelivered !Completion
  | TermCanceled
  | TermFailed !ReturnCode !String
  deriving (Eq, Show)

-- | One poll's outcome. Pending polls (and the drive that turns the
-- last poll ready) never touch the result sink.
data PollOutcome
  = PollPending { poTicksLeft :: !Int }
  | PollReady
  | PollTerminal !TerminalState
  | PollUnknown
  | PollWrongFunction { pwExpected :: !JobFunction, pwGot :: !JobFunction }
  deriving (Eq, Show)

-- | One complete's outcome. Delivery happens only on the winning
-- 'CompleteDelivered'; every other outcome writes nothing (short
-- buffers report their sizing through 'dReportNeeded').
data CompleteOutcome
  = CompletePending { coTicksLeft :: !Int }
  | CompleteDelivered { coCompletion :: !Completion }
  | CompleteAlready !TerminalState
  | CompleteUnknown
  | CompleteWrongFunction { cwExpected :: !JobFunction, cwGot :: !JobFunction }
  | CompleteShort { coNeeded :: !Word64 }
  deriving (Eq, Show)

-- | One cancel's outcome. Cancel wins only out of a live state;
-- otherwise the caller observes the winner's terminal state.
data CancelOutcome
  = CancelOk
  | CancelAlready !TerminalState
  | CancelUnknown
  deriving (Eq, Show)

-- | One reap's outcome: terminal tombstones drop, live jobs and
-- unknown ids report without touching the table.
data ReapOutcome
  = Reaped
  | ReapLive
  | ReapUnknown
  deriving (Eq, Show)

-- | The attached delivery sink: caller byte-payload capacity, the
-- exact-frame write (fires at most once, on the winning complete),
-- and the sizing report for short buffers.
data Delivery = Delivery
  { dCapacity :: !Word64
  , dWrite :: !(ByteString -> IO ())
  , dReportNeeded :: !(Word64 -> IO ())
  }

-- | The effect interpreter a drive step runs through. Model tests
-- pass stubs; engine and FFI layers pass the production driver.
type EffectRunner = CryptoEffect -> IO CryptoResult

-- ---------------------------------------------------------------------------
-- Table
-- ---------------------------------------------------------------------------

-- | Live execution state. Terminal jobs stay in the map as
-- tombstones so late polls\/completions observe the winner.
data JobState
  = JobPending !Int
  | JobRunning
  | JobReady !CryptoResult
  | JobTerminal !TerminalState
  deriving (Eq, Show)

-- | One attached job: identity, plan, schedule, live state,
-- cancellation epoch, and the delivery lease. The lease is
-- 'MVar'-held outside STM; every transaction below touches only
-- the table @TVar@s.
data Job = Job
  { jbSession :: !SessionId
  , jbFunction :: !JobFunction
  , jbWork :: !AsyncWork
  , jbCapacity :: !Word64
  , jbState :: !JobState
  , jbEpoch :: !Word64
  , jbLock :: !(MVar ())
  }

-- ---------------------------------------------------------------------------
-- Closed transitions
-- ---------------------------------------------------------------------------

-- | The closed job-transition vocabulary: every 'JobState' change in
-- this module routes through 'stepJob', and illegal transitions are
-- rejected in exactly that one place. Countdown and claim steps
-- keep the epoch; hold, deliver, fail, and cancel bump it by one.
data JobEvent
  = EvTick
  | EvClaim
  | EvHold !CryptoResult
  | EvDeliver !Completion
  | EvFail !ReturnCode !String
  | EvCancel
  deriving (Eq, Show)

-- | A rejected transition: the event plus the state that refused
-- it. Sites map rejections to their observe-outcomes; they never
-- re-decide legality.
data JobReject = JobReject !JobEvent !JobState
  deriving (Eq, Show)

-- | A committable transition verdict. The constructor is private:
-- only 'stepJob' builds verdicts, so no site can forge a state
-- change. Verdicts are readable ('stepState', 'stepEpoch') and
-- committable ('commitStep').
newtype JobStep = JobStep (JobState, Word64)
  deriving (Eq, Show)

-- | The state a verdict commits.
stepState :: JobStep -> JobState
stepState (JobStep (st, _)) = st

-- | The epoch a verdict commits.
stepEpoch :: JobStep -> Word64
stepEpoch (JobStep (_, e)) = e

-- | The single total job transition: legal event/state pairs step
-- to a committable verdict, illegal pairs reject. Total over the
-- whole event/state matrix (see @JobStepSpec@).
stepJob :: JobEvent -> JobState -> Word64 -> Either JobReject JobStep
stepJob ev st e = case ev of
  EvTick -> case st of
    JobPending n
      | n > 1 -> Right (JobStep (JobPending (n - 1), e))
      | otherwise -> Left (JobReject ev st)
    _ -> Left (JobReject ev st)
  EvClaim -> case st of
    JobPending _ -> Right (JobStep (JobRunning, e))
    _ -> Left (JobReject ev st)
  EvHold res -> case st of
    JobRunning -> Right (JobStep (JobReady res, e + 1))
    _ -> Left (JobReject ev st)
  EvDeliver c -> case st of
    JobReady _ -> Right (JobStep (JobTerminal (TermDelivered c), e + 1))
    _ -> Left (JobReject ev st)
  EvFail code why -> case st of
    JobTerminal _ -> Left (JobReject ev st)
    _ -> Right (JobStep (JobTerminal (TermFailed code why), e + 1))
  EvCancel -> case st of
    JobTerminal _ -> Left (JobReject ev st)
    _ -> Right (JobStep (JobTerminal TermCanceled, e + 1))

-- | The attached-job table: live jobs plus tombstones, the next
-- job id, the live-job capacity, and the async-enabled sessions.
data AsyncTable = AsyncTable
  { atJobs :: !(TVar (Map JobId Job))
  , atNext :: !(TVar Int)
  , atMax :: !Int
  , atAsync :: !(TVar (Set SessionId))
  }

-- | A fresh table with the given live-job capacity.
newAsyncTable :: Int -> IO AsyncTable
newAsyncTable cap = AsyncTable
  <$> newTVarIO Map.empty
  <*> newTVarIO 0
  <*> pure cap
  <*> newTVarIO Set.empty

-- | Request asynchronous service for a session. Idempotent;
-- sessions never enabled stay synchronous no matter the async
-- load elsewhere.
enableAsyncSession :: AsyncTable -> SessionId -> IO ()
enableAsyncSession table sid = atomically $ do
  async <- readTVar (atAsync table)
  writeTVar (atAsync table) (Set.insert sid async)

-- | Whether a session is async-enabled. Lock-free read; rejoin
-- validation uses it for target-session compatibility.
isAsyncSession :: AsyncTable -> SessionId -> IO Bool
isAsyncSession table sid =
  Set.member sid <$> readTVarIO (atAsync table)

-- | Table census: @(live, terminal tombstones, next job id)@. The
-- next id proves refusals allocate nothing.
tableStats :: AsyncTable -> IO (Int, Int, Int)
tableStats table = do
  jobs <- readTVarIO (atJobs table)
  nextId <- readTVarIO (atNext table)
  let states = map jbState (Map.elems jobs)
      live = length [() | s <- states, isLive s]
      term = length states - live
  pure (live, term, nextId)
  where
    isLive :: JobState -> Bool
    isLive (JobTerminal _) = False
    isLive _ = True

-- | Count of jobs in the delivered terminal state (stress-test
-- invariant hook; lock-free read, additive: no behavior change).
deliveredCount :: AsyncTable -> IO Int
deliveredCount table = do
  jobs <- readTVarIO (atJobs table)
  pure (length [() | job <- Map.elems jobs, isDelivered (jbState job)])
  where
    isDelivered :: JobState -> Bool
    isDelivered (JobTerminal (TermDelivered _)) = True
    isDelivered _ = False

-- | A job's diagnostic view: cancellation epoch and, while
-- pending, polls left before the drive.
data JobView = JobView
  { jvEpoch :: !Word64
  , jvTicksLeft :: !(Maybe Int)
  } deriving (Eq, Show)

-- | Inspect a job's epoch and schedule. Lock-free read; 'Nothing'
-- for unknown or reaped jobs.
inspectJob :: AsyncTable -> JobId -> IO (Maybe JobView)
inspectJob table jid = do
  jobs <- readTVarIO (atJobs table)
  pure $ do
    job <- Map.lookup jid jobs
    let ticks = case jbState job of
          JobPending n -> Just n
          _ -> Nothing
    pure JobView { jvEpoch = jbEpoch job, jvTicksLeft = ticks }

-- | A ready job's held payload need, for null-value sizing probes.
-- Lock-free read; 'Nothing' unless the job is ready with bytes.
-- Key-handle readiness reports @Just 0@ (no byte payload).
jobReadyNeed :: AsyncTable -> JobId -> IO (Maybe Word64)
jobReadyNeed table jid = do
  jobs <- readTVarIO (atJobs table)
  pure $ case Map.lookup jid jobs of
    Just job -> case jbState job of
      JobReady (GotBytes bs) ->
        Just (fromIntegral (BS.length bs))
      -- A unit-held job needs no byte payload (preserves the
      -- pre-change held-empty-bytes answer exactly).
      JobReady GotUnit -> Just 0
      _ -> Nothing
    Nothing -> Nothing

-- | A job's function family, for side-effect-free poller checks.
-- Lock-free read; 'Nothing' for unknown jobs.
jobFunctionOf :: AsyncTable -> JobId -> IO (Maybe JobFunction)
jobFunctionOf table jid = do
  jobs <- readTVarIO (atJobs table)
  pure (jbFunction <$> Map.lookup jid jobs)

-- | Every job id owned by a session, live or tombstone, in id
-- order. Lock-free diagnostic read.
sessionJobs :: AsyncTable -> SessionId -> IO [JobId]
sessionJobs table sid = do
  jobs <- readTVarIO (atJobs table)
  pure [jid | (jid, job) <- Map.toAscList jobs, jbSession job == sid]

-- ---------------------------------------------------------------------------
-- Operations
-- ---------------------------------------------------------------------------

-- | Submit a job. Work/result compatibility, enablement,
-- attached-capacity bounds, and live capacity are all validated
-- BEFORE pending, in one transaction with the id allocation, so
-- every refusal consumes no id and leaves the table unchanged.
-- Check order: compatibility, session, attached capacity, live
-- capacity. Terminal tombstones never count toward live capacity
-- (reap them with 'reapJob').
startJob :: AsyncTable -> JobRequest -> IO (Either StartDeny JobId)
startJob table req = startJobWith table req (JobPending (jrTicks req))

-- | Submit a job that is already ready: rejoin of a detached
-- ready result seeds the held bytes so completion delivers without
-- re-running the effect. Validation is identical to 'startJob'
-- (same order, same no-allocation-on-refusal); only the initial
-- state differs.
startSeededJob :: AsyncTable -> JobRequest -> ByteString -> IO (Either StartDeny JobId)
startSeededJob table req bs = startJobWith table req (JobReady (GotBytes bs))

-- | Shared submit: validate, allocate the id, and insert the job in
-- the given initial state, all in one transaction. The static
-- work/result compatibility check runs first (a misconstructed
-- job is refused however healthy the table is); then session,
-- attached capacity, live capacity, as before.
startJobWith :: AsyncTable -> JobRequest -> JobState -> IO (Either StartDeny JobId)
startJobWith table req initial
  | not (effectHoldable (workEffect (jrWork req))) =
      pure (Left StartIncompatibleWork)
  | otherwise = do
      lock <- newMVar ()
      atomically $ do
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
                      }
                writeTVar (atJobs table) (Map.insert (JobId n) job jobs)
                pure (Right (JobId n))
  where
    jbSessionOf :: JobRequest -> SessionId
    jbSessionOf = jrSession
    liveCount :: Map JobId Job -> Int
    liveCount = length . filter isLive . Map.elems
    isLive :: Job -> Bool
    isLive job = case jbState job of
      JobTerminal _ -> False
      _ -> True

-- | Poll a job. A wrong-function poll is refused with the job
-- untouched; a correct-function poll on a pending job counts down,
-- and the last poll drives the effect into a held owned result and
-- reports ready. No poll path touches the result sink. Stale
-- revisions fail the drive before any effect runs.
pollJob
  :: EffectRunner -> Env -> AsyncTable -> JobFunction -> JobId -> IO PollOutcome
pollJob run env table func jid = withJobLock table jid PollUnknown $ \job -> do
  cur <- readJob table jid
  case cur of
    Just j | jbFunction j /= func ->
      pure (PollWrongFunction (jbFunction j) func)
    Nothing -> pure (PollTerminal (TermFailed CKR_GENERAL_ERROR "lost job"))
    -- The countdown routes through 'stepJob' (fresh state, lock-time
    -- epoch, exactly as before); a rejection carries the state that
    -- refused the tick, which decides drive versus observe.
    Just j -> case stepJob EvTick (jbState j) (jbEpoch job) of
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
-- pair, if any. Call work has no static pairing to
-- check (its finisher consumes the driver answer, not the
-- effect); key work refuses through 'keyPairCompatible' before
-- any effect runs. Both 'Show' instances redact secrets.
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
        GotCryptoError err -> failDrive
          (EvFail (interpretError (TyCrypto err)) (show err)) st e
          (TermFailed (interpretError (TyCrypto err)) (show err))
    -- Fail a drive step through 'stepJob', reporting the coded reason.
    failDrive :: JobEvent -> JobState -> Word64 -> TerminalState -> IO PollOutcome
    failDrive ev st e t = case stepJob ev st e of
      Right s -> do
        commitStep table jid s
        pure (PollTerminal t)
      Left _ -> pure (PollTerminal (TermFailed CKR_GENERAL_ERROR
        "stepJob EvFail breached its contract"))

-- | Complete a job. Wrong-function and pending jobs report with
-- the sink untouched; ready jobs publish their commit, go
-- terminal, then deliver the canonical completion exactly once.
-- Short buffers report their sizing with the result held.
completeJob
  :: Env -> AsyncTable -> JobFunction -> JobId -> Delivery
  -> (ResourceRelease -> IO ()) -> IO CompleteOutcome
completeJob env table func jid del release =
  withJobLock table jid CompleteUnknown $ \job -> do
    cur <- readJob table jid
    case cur of
      Just j | jbFunction j /= func ->
        pure (CompleteWrongFunction (jbFunction j) func)
      _ -> case orLost cur of
        JobTerminal t -> pure (CompleteAlready t)
        JobPending n -> pure (CompletePending n)
        JobRunning -> pure (CompletePending 0)
        -- Bytes-like held answers (bytes or unit) complete;
        -- the held shape flows to the finishers, collapsing only at
        -- 'encodeResult'.
        JobReady h | isBytesLike h -> case jbWork job of
          WorkCall res _ -> callComplete env table jid job del res h release
          WorkKey _ pw _ -> keyComplete env table jid job del pw h release
        -- A held non-bytes result is a data-shape failure, not a
        -- transition decision: the shape is read here, the failure
        -- commits through 'stepJob' (fresh state, lock-time epoch,
        -- exactly as before).
        JobReady other ->
          let why = "non-bytes held result: " ++ heldTag other
          in case stepJob (EvFail CKR_GENERAL_ERROR why)
              (orLost cur) (jbEpoch job) of
            Right s -> do
              commitStep table jid s
              pure (CompleteAlready (TermFailed CKR_GENERAL_ERROR why))
            Left _ -> pure (CompleteAlready (TermFailed CKR_GENERAL_ERROR
              "stepJob EvFail breached its contract"))
  where
    heldTag :: CryptoResult -> String
    heldTag (GotBytes _) = "bytes"
    heldTag (GotValid _) = "verdict"
    heldTag (GotResource _) = "resource"
    heldTag GotUnit = "unit"
    heldTag (GotCryptoError e) = show (interpretError (TyCrypto e))

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
        -- Delivery commits through 'stepJob' against the live state
        -- (re-read under the held lease: still the ready job the
        -- complete step dispatched on) with the lock-time epoch,
        -- exactly as before. Releases drain AFTER the successful
        -- publish, like every other commit-application
        -- site; a short completion drains nothing, while a faulted
        -- publish still drains the commit's releases exactly once
        -- (see above).
        Right () -> mask_ $ do
          mapM_ release releases
          cur <- readJob table jid
          case stepJob (EvDeliver completion)
            (orLost cur) (jbEpoch job) of
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
cancelJob table jid = withJobLock table jid CancelUnknown $ \job -> do
  cur <- readJob table jid
  case cur of
    -- Cancel routes through 'stepJob' (fresh state, lock-time
    -- epoch, exactly as before); a rejection carries the terminal
    -- state the caller observes.
    Just j -> case stepJob EvCancel (jbState j) (jbEpoch job) of
      Right s -> do
        commitStep table jid s
        pure CancelOk
      Left (JobReject _ (JobTerminal t)) -> pure (CancelAlready t)
      Left _ -> pure (CancelAlready (TermFailed CKR_GENERAL_ERROR
        "stepJob EvCancel breached its contract"))
    Nothing -> pure CancelUnknown

-- | Whether a job state may be reaped.
--
-- Retention\/expiry ruling (rule-with-criteria): retention
-- bound — tombstones are UNBOUNDED until reaped (no count\/age cap;
-- the live cap counts LIVE ONLY, so tombstones never block
-- submits; delivered tombstones retain their completion payload
-- until reaped). Who reaps when — the job OWNER via manual
-- terminal-only 'reapJob' (synchronous, under the job lease); no
-- background reaper (discipline: no background threads). Current
-- wiring gap (honest finding): no production caller wires
-- 'reapJob' — production tombstones accumulate until process end;
-- wiring reap to a destroy\/close path needs an FFI surface
-- decision (follow-up, out of contract scope). Cancel-after-detach —
-- 'CancelUnknown' at the source (revoked from the table); cancel
-- routes to the table that HOLDS the job, which post-revoke is the
-- rejoin-side table ('joinJob' side), never the source. Why not a
-- bounded policy now: eviction-on-submit is pointless (tombstones
-- don't block submits), age\/count caps need a reaper thread
-- (forbidden) or FFI surface (undecided), and cross-table
-- cancel-after-detach routing needs Detached-module surgery —
-- scope explosion with success-path risk, so rule over implement.
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
reapJob table jid = withJobLock table jid ReapUnknown $ \_ -> do
  cur <- readJob table jid
  case cur of
    Just j -> case reapEligibility (jbState j) of
      EligibleTerminal -> do
        atomically $ do
          jobs <- readTVar (atJobs table)
          writeTVar (atJobs table) (Map.delete jid jobs)
        pure Reaped
      BlockedLive -> pure ReapLive
    Nothing -> pure ReapUnknown

-- ---------------------------------------------------------------------------
-- Lease helpers (STM touches job-table TVars only)
-- ---------------------------------------------------------------------------

-- | Run under a job's delivery lease. Unknown jobs take the
-- default without locking.
--
-- Ownership rule R1 backstop: an exception escaping a lease body with the job
-- still claimed ('JobRunning') repairs the claim to failed (masked,
-- best-effort), then rethrows. Stable states (pending\/ready\/
-- terminal) are untouched — in particular a delivery throw leaves
-- 'Ready' (R6 recoverable). Lock release and state repair composed.
withJobLock
  :: AsyncTable -> JobId -> a -> (Job -> IO a) -> IO a
withJobLock table jid def k = do
  mj <- readTVarIO (atJobs table) >>= pure . Map.lookup jid
  case mj of
    Nothing -> pure def
    Just job -> withMVar (jbLock job) (const (repairing (k job)))
  where
    repairing body = body `onException` mask_ (do
      cur <- readJob table jid
      case cur of
        Just j -> case jbState j of
          JobRunning -> case stepJob
            (EvFail CKR_GENERAL_ERROR "lease escape while running")
            JobRunning (jbEpoch j) of
              Right s -> commitStep table jid s
              Left _ -> pure ()
          _ -> pure ()
        Nothing -> pure ())

-- | Re-read a job under its lease.
readJob :: AsyncTable -> JobId -> IO (Maybe Job)
readJob table jid =
  readTVarIO (atJobs table) >>= pure . Map.lookup jid

-- | The state of a re-read job, defaulting to a failed terminal
-- when the job is lost (unreachable under a held lease:
-- revocation takes the same lock — the long-standing default, kept
-- verbatim).
orLost :: Maybe Job -> JobState
orLost = maybe (JobTerminal (TermFailed CKR_GENERAL_ERROR "lost job")) jbState

-- | Commit a 'stepJob' verdict for a job in one short
-- transaction. The only state writer: every transition site
-- commits a verdict, never a hand-built state.
commitStep :: AsyncTable -> JobId -> JobStep -> IO ()
commitStep table jid s = atomically $ do
  jobs <- readTVar (atJobs table)
  case Map.lookup jid jobs of
    Nothing -> pure ()
    Just job -> writeTVar (atJobs table)
      (Map.insert jid job { jbState = stepState s, jbEpoch = stepEpoch s } jobs)

-- ---------------------------------------------------------------------------
-- Detach support
-- ---------------------------------------------------------------------------

-- | A job's detach-relevant state, copied out of the table. Ready
-- snapshots carry the held bytes (for pointer-free result records);
-- verdict and error holdings report their tag instead — detach
-- prepares result records for bytes only.
data JobSnapState
  = SnapPending !Int
  | SnapRunning
  | SnapReady !ByteString
  | SnapHeld !String
  | SnapTerminal !TerminalState
  deriving (Eq)

-- | 'Show' redacts held result bytes: a ready snapshot
-- may hold a ready-but-unfinished keygen answer, so 'SnapReady'
-- renders its kind and length only ('redactShown'). All other
-- states render normally. Explicit inspection pattern-matches
-- the exported constructors (never 'Show').
instance Show JobSnapState where
  show (SnapPending n) = "SnapPending " ++ show n
  show SnapRunning = "SnapRunning"
  show (SnapReady bs) = "SnapReady " ++ redactShown "bytes" (BS.length bs)
  show (SnapHeld tag) = "SnapHeld " ++ show tag
  show (SnapTerminal t) = "SnapTerminal " ++ show t

-- | A job snapshot: identity, planned work, state, attached
-- capacity, owning session, and cancellation epoch. Snapshots are
-- plain data: no locks, no pointers, safe to persist from.
data JobSnapshot = JobSnapshot
  { jsFunction :: !JobFunction
  , jsWork :: !AsyncWork
  , jsState :: !JobSnapState
  , jsCapacity :: !Word64
  , jsSession :: !SessionId
  , jsEpoch :: !Word64
  } deriving (Eq, Show)

-- | Snapshot accessors (the constructor stays private so snapshots
-- only ever come from the table).
jobSnapshotFunction :: JobSnapshot -> JobFunction
jobSnapshotFunction = jsFunction

-- | The planned work (the recipe source).
jobSnapshotWork :: JobSnapshot -> AsyncWork
jobSnapshotWork = jsWork

-- | The copied execution state.
jobSnapshotState :: JobSnapshot -> JobSnapState
jobSnapshotState = jsState

-- | Polls left while pending ('Nothing' otherwise).
jobSnapshotTicks :: JobSnapshot -> Maybe Int
jobSnapshotTicks snap = case jsState snap of
  SnapPending n -> Just n
  _ -> Nothing

-- | The attached byte-payload capacity.
jobSnapshotCapacity :: JobSnapshot -> Word64
jobSnapshotCapacity = jsCapacity

-- | The owning session.
jobSnapshotSession :: JobSnapshot -> SessionId
jobSnapshotSession = jsSession

-- | The cancellation epoch.
jobSnapshotEpoch :: JobSnapshot -> Word64
jobSnapshotEpoch = jsEpoch

-- | Copy a job out of the table. Lock-free read; 'Nothing' for
-- unknown or reaped jobs.
snapshotJob :: AsyncTable -> JobId -> IO (Maybe JobSnapshot)
snapshotJob table jid = do
  jobs <- readTVarIO (atJobs table)
  pure (toSnapshot <$> Map.lookup jid jobs)

-- | Project a live job onto its snapshot.
toSnapshot :: Job -> JobSnapshot
toSnapshot job = JobSnapshot
  { jsFunction = jbFunction job
  , jsWork = jbWork job
  , jsState = case jbState job of
      JobPending n -> SnapPending n
      JobRunning -> SnapRunning
      JobReady (GotBytes bs) -> SnapReady bs
      -- A unit holding snapshots as empty-ready (rejoin
      -- seeds empty bytes — identical to the pre-change
      -- held-empty-bytes behavior).
      JobReady GotUnit -> SnapReady BS.empty
      JobReady (GotValid _) -> SnapHeld "verdict"
      JobReady (GotResource _) -> SnapHeld "resource"
      JobReady (GotCryptoError e) -> SnapHeld (show (interpretError (TyCrypto e)))
      JobTerminal t -> SnapTerminal t
  , jsCapacity = jbCapacity job
  , jsSession = jbSession job
  , jsEpoch = jbEpoch job
  }

-- | A held attachment-change lease: the job's delivery lease taken
-- for detach, plus the snapshot read under it. While the lease is
-- held, no poll\/complete\/cancel on this job can run, so record
-- preparation sees a stable job and revocation cannot race a
-- delivery. Exactly one of 'commitDetachRevoke' \/ 'abortDetach'
-- must run to release it. New code MUST NOT pair these by hand:
-- use 'withDetachLease', which owns the pairing structurally;
-- the raw operations stay exported only for the legacy callers
-- kept in the test suite ('DetachedSpec', 'SimStressSpec').
data DetachLease = DetachLease
  { dlTable :: !AsyncTable
  , dlJob :: !JobId
  , dlLock :: !(MVar ())
  , dlSnapshot :: !JobSnapshot
  }

-- | Take a job's lease for detach and snapshot it. 'Nothing' for
-- unknown jobs (including jobs reaped while waiting for the lease);
-- otherwise the caller holds the lease until commit or abort.
--
-- Masking contract: the FULL take-to-handoff path runs
-- masked. The wait for a contested lock stays killable — a blocking
-- 'takeMVar' is interruptible even under 'mask_' — but a take that
-- succeeds never re-enters an unmasked state before the lease is
-- handed off, so no async exception can strand the lock between the
-- take and the handoff ("raises implies holds nothing": an exception
-- escaping 'beginDetach' was raised while blocked in the wait and
-- holds nothing; the post-take section never blocks). Callers still
-- release a returned lease exactly once.
beginDetach :: AsyncTable -> JobId -> IO (Maybe DetachLease)
beginDetach table jid = mask_ $ do
  mj <- readTVarIO (atJobs table) >>= pure . Map.lookup jid
  case mj of
    Nothing -> pure Nothing
    Just job -> do
      -- Masked take: killable while blocked (interruptible wait),
      -- unkillable once held (no window before the handoff).
      takeMVar (jbLock job)
      -- Holding the lock, still masked: the handoff never blocks,
      -- so no async exception can surface before the lease exists.
      uninterruptibleMask_ $ do
        cur <- readTVarIO (atJobs table) >>= pure . Map.lookup jid
        case cur of
          Nothing -> do
            putMVar (jbLock job) ()
            pure Nothing
          Just jobNow -> pure (Just DetachLease
            { dlTable = table
            , dlJob = jid
            , dlLock = jbLock job
            , dlSnapshot = toSnapshot jobNow
            })

-- | The snapshot read under a held lease.
leaseSnapshot :: DetachLease -> JobSnapshot
leaseSnapshot = dlSnapshot

-- | Revoke the leased job: remove it from the table (no admitted
-- poll\/complete\/cancel can reach it afterwards — late callers
-- observe unknown) and release the lease. One-shot: the lease is
-- spent.
--
-- Masking contract: the revoke-then-release pair is
-- uninterruptible, so a kill can neither orphan the lock on a
-- revoked job nor surface between the two steps — an exception
-- escaping 'commitDetachRevoke' still leaves a clean state
-- (revoked AND released).
commitDetachRevoke :: DetachLease -> IO ()
commitDetachRevoke dl = uninterruptibleMask_ $ do
  atomically $ do
    jobs <- readTVar (atJobs (dlTable dl))
    writeTVar (atJobs (dlTable dl)) (Map.delete (dlJob dl) jobs)
  putMVar (dlLock dl) ()

-- | Release a held lease with the job untouched. One-shot.
abortDetach :: DetachLease -> IO ()
abortDetach dl = uninterruptibleMask_ (putMVar (dlLock dl) ())

-- | The scoped view of a held detach lease: the snapshot read
-- under it plus the idempotent commit action. The release side is
-- owned by 'withDetachLease', never by the body.
data LeaseView = LeaseView
  { lvSnapshot :: !JobSnapshot
  , lvCommit :: !(IO ())
  }

-- | Run a body with a job's detach lease held. 'Nothing' for
-- unknown jobs. Otherwise the body observes the snapshot and may
-- commit (revoking the job; committing twice is a quiet no-op);
-- when the body returns or throws without committing, the lease is
-- released with the job untouched. A dropped lease cannot wedge:
-- the abort runs masked on every exit path, so exactly one of
-- commit\/abort releases each acquired lease by construction.
withDetachLease
  :: AsyncTable -> JobId -> (Maybe LeaseView -> IO a) -> IO a
withDetachLease table jid body = mask $ \restore -> do
  mLease <- beginDetach table jid
  case mLease of
    Nothing -> restore (body Nothing)
    Just lease -> do
      committedRef <- newIORef False
      let view = LeaseView
            { lvSnapshot = leaseSnapshot lease
            , lvCommit = uninterruptibleMask_ $ do
                done <- readIORef committedRef
                unless done $ do
                  commitDetachRevoke lease
                  writeIORef committedRef True
            }
      r <- restore (body (Just view)) `onException` abortUnless committedRef lease
      abortUnless committedRef lease
      pure r
  where
    abortUnless :: IORef Bool -> DetachLease -> IO ()
    abortUnless ref lease = uninterruptibleMask_ $ do
      done <- readIORef ref
      unless done (abortDetach lease)

-- | Non-blocking lease probe (diagnostic affordance in the
-- 'Haskoki.Runtime.Lifecycle.gateBusy' precedent): 'True' while
-- the lease's lock is held. The take\/put pair runs masked so the
-- token cannot leak; a racing holder only waits out the probe.
leaseLockHeld :: DetachLease -> IO Bool
leaseLockHeld dl = mask_ $ do
  m <- tryTakeMVar (dlLock dl)
  case m of
    Nothing -> pure True
    Just () -> putMVar (dlLock dl) () >> pure False

-- ---------------------------------------------------------------------------
-- Simulation bridge (scheduler advance)
-- ---------------------------------------------------------------------------

-- | Decrement every pending job's ticks by the base advance plus its
-- schedule boost, saturating at 1: the last tick ALWAYS drives
-- through the poll path — advance never executes effects, checks
-- reservations, delivers, or fails a job. Unconfigured runs (empty
-- schedule) apply the base advance only; the poll path itself is
-- untouched. Returns @(advanced, saturated-at-1)@.
advanceTicks :: AsyncTable -> Int -> [(String, Int)] -> IO (Int, Int)
advanceTicks table base sched = atomically $ do
  jobs <- readTVar (atJobs table)
  let (counts, jobs') = Map.mapAccum step (0, 0) jobs
  writeTVar (atJobs table) jobs'
  pure counts
  where
    step :: (Int, Int) -> Job -> ((Int, Int), Job)
    step (adv, sat) job = case jbState job of
      JobPending t
        | t > 1 ->
            let t' = max 1 (t - base - scheduleBoost sched job)
                dec = t - t'
                -- Countdowns tick through 'stepJob' one tick at a
                -- time; a zero or negative advance is not a
                -- countdown (the caller guards base >= 1 and boosts
                -- >= 0, so this arm only fires on direct misuse) and
                -- writes the saturated target exactly as before.
                (st', e') = if dec > 0
                  then applyTicks dec (JobPending t) (jbEpoch job)
                  else (JobPending t', jbEpoch job)
            in ((adv + 1, if t' == 1 then sat + 1 else sat)
               , job { jbState = st', jbEpoch = e' })
      _ -> ((adv, sat), job)

-- | Apply @n@ countdown ticks through 'stepJob', stopping early if
-- a tick rejects (defensive: the countdown vocabulary keeps the
-- epoch, and callers only tick pending jobs with ticks left, so
-- the loop always runs to completion and the epoch never moves).
applyTicks :: Int -> JobState -> Word64 -> (JobState, Word64)
applyTicks n st e
  | n <= 0 = (st, e)
  | otherwise = case stepJob EvTick st e of
      Right s -> applyTicks (n - 1) (stepState s) (stepEpoch s)
      Left _ -> (st, e)

-- | Extra ticks a job earns from the delay schedule. Precedence:
-- exact CKM mechanism name wins over the job-function tag, which
-- wins over the @"*"@ wildcard; within one key the LAST file entry
-- wins. Unknown names match nothing.
scheduleBoost :: [(String, Int)] -> Job -> Int
scheduleBoost sched job =
  case (byMech, byFunc, byWild) of
    (Just t, _, _) -> t
    (_, Just t, _) -> t
    (_, _, Just t) -> t
    _ -> 0
  where
    look key = listToMaybe [t | (k, t) <- reverse sched, k == key]
    byMech = effectMech (workEffect (jbWork job)) >>= mechNameOf >>= look
    byFunc = look (funcTag (jbFunction job))
    byWild = look "*"

-- | The mechanism an effect names, if any. Stream feed/consume
-- steps name a backend context instead of a mechanism.
effectMech :: CryptoEffect -> Maybe MechanismId
effectMech fx = case fx of
  FxDigest m _ -> Just m
  FxDigestInit m -> Just m
  FxDigestFeed {} -> Nothing
  FxDigestConsume {} -> Nothing
  FxCipher _ m _ _ _ -> Just m
  FxSign m _ _ _ -> Just m
  FxVerify m _ _ _ _ -> Just m
  FxSignRecover m _ _ _ _ -> Just m
  FxVerifyRecover m _ _ _ _ -> Just m
  FxMessageCipher _ m _ _ _ _ -> Just m
  FxMessageSign m _ _ _ -> Just m
  FxMessageVerify m _ _ _ _ -> Just m
  FxGenerateKey m _ _ -> Just m
  FxWrap m _ _ _ -> Just m
  FxUnwrap m _ _ _ -> Just m
  FxAuthWrap m _ _ _ -> Just m
  FxAuthUnwrap m _ _ _ -> Just m
  FxDerive m _ _ _ _ -> Just m
  FxKemEncaps m _ _ _ -> Just m
  FxKemDecaps m _ _ _ -> Just m

-- | The schedule key for a job function family.
funcTag :: JobFunction -> String
funcTag JobSign = "sign"
funcTag JobDigest = "digest"
funcTag JobGenKey = "genkey"
funcTag JobGenKeyPair = "genkeypair"

-- | Canonical CKM name for a mechanism id, if it is one.
mechNameOf :: MechanismId -> Maybe String
mechNameOf (MechanismId w) =
  listToMaybe [T.unpack name | (i, name, _) <- generatedInventory, i == w]
