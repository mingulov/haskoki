{- | Async the job table and closed transitions.
-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Haskoki.Runtime.Async.Table
  ( usdtJobPhase
  , usdtAsyncEnd
  , usdtSeededReady
  , JobEvent (..)
  , JobReject (..)
  , JobStep
  , stepState
  , stepEpoch
  , stepJob
  , TableIdExhausted
  , tableSaltFor
  , AsyncTable
  , newAsyncTable
  , tryNewAsyncTable
  , asyncTableId
  , asyncTableSalt
  , atJobs
  , atNext
  , atMax
  , atAsync
  , atGate
  , enableAsyncSession
  , disableAsyncSession
  , isAsyncSession
  , enabledSessionCount
  , tableStats
  , deliveredCount
  , JobView (..)
  , inspectJob
  , jobReadyNeed
  , jobFunctionOf
  , sessionJobs
  , readJob
  , TableClose (..)
  , Teardown (..)
  , Closer (..)
  ) where

import Control.Concurrent.STM
  ( TVar
  , atomically
  , newTVarIO
  , readTVar
  , readTVarIO
  , writeTVar
  )
import Control.Exception
  ( Exception
  , throwIO
  )
import Data.Int (Int64)
import qualified Data.ByteString as BS
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Word (Word32, Word64)
import Haskoki.Operation.Effect
  ( CryptoResult (..)
  )
import Haskoki.Registry.Types (MechanismId (..))
import Haskoki.Request (FunctionId (..))
import Haskoki.Runtime.Attach (AsyncTableId (..))
import Haskoki.Runtime.Usdt (Disposition (..), JobPhase (..),
  emitJobState, emitOperationEnd, functionCode, fxMechOf,
  OpMode (..))
import Haskoki.Types
  ( JobId (..)
  , ReturnCode (..)
  , SessionId
  )
import Haskoki.Runtime.Async.Jobs
import Haskoki.Runtime.Async.Completion

-- ---------------------------------------------------------------------------
-- Table
-- ---------------------------------------------------------------------------

-- | The representative C function of a job family, for USDT
-- attribution (async contributes private events only).
jobFunctionFunc :: JobFunction -> FunctionId
jobFunctionFunc JobDigest = F_Digest
jobFunctionFunc JobSign = F_Sign
jobFunctionFunc JobGenKey = F_GenerateKey
jobFunctionFunc JobGenKeyPair = F_GenerateKeyPair

-- | Emit one job_state event for a committed transition. Skipped
-- when the job carries no op id (allocation failed at accept).
usdtJobPhase :: AsyncTable -> JobId -> Job -> JobPhase -> Word32 -> Bool
  -> IO ()
usdtJobPhase table (JobId n) job phase ckr ckrValid =
  case jbUsdt job of
    Nothing -> pure ()
    Just op ->
      let AsyncTableId t = asyncTableId table
      in emitJobState (fromIntegral t) (fromIntegral n) op True
        phase ckr ckrValid

-- | Terminal async outcome: private end (async contributes no pk
-- contexts). Func/mech from the job's function and work effect.
usdtAsyncEnd :: Job -> Word32 -> Disposition -> IO ()
usdtAsyncEnd job ckr disp =
  case jbUsdt job of
    Nothing -> pure ()
    Just op -> do
      let func = jobFunctionFunc (jbFunction job)
      case fxMechOf (workEffect (jbWork job)) of
        Just (MechanismId w) ->
          emitOperationEnd op (functionCode func) w True ckr
            disp ModeAsync
        Nothing ->
          emitOperationEnd op (functionCode func) 0 False ckr
            disp ModeAsync

-- | Emit the first ready of a seeded (rejoin) attachment. The
-- detached claim winner calls this after 'commitClaim'. The seeded
-- insert itself emits Accepted like any admission (a rejoin is a
-- genuine new-table admission under a fresh op id); only the source
-- op's handoff pair (at revoke) ties the two lifecycles together.
usdtSeededReady :: AsyncTable -> JobId -> IO ()
usdtSeededReady table jid = do
  mJob <- readJob table jid
  case mJob of
    Just job -> usdtJobPhase table jid job PhaseReady 0 False
    Nothing -> pure ()

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
-- committable (@commitStep@).
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

-- | The table allocator refused: the process already holds 2^32-1
-- tables, so no distinct nonzero 32-bit salt remains for another
-- one ('tryNewAsyncTable' reports this as 'Nothing';
-- 'newAsyncTable' throws it). Reaching the bound takes 2^32-1
-- table creations in one process; the counter saturates rather
-- than wrapping or reusing an identity.
data TableIdExhausted = TableIdExhausted
  deriving (Show)

instance Exception TableIdExhausted

-- | Process-wide table-identity mint: C-owned surface state (the
-- former Haskell global counter is gone with its import). Hands out
-- table indices 0, 1, ... one atomic step per mint; past 2^32-1
-- tables it refuses (-1) instead of wrapping or reusing an identity
-- (see 'tableSaltFor'), leaving the counter untouched, so
-- identities never wrap and salts never repeat.
foreign import ccall unsafe "haskoki_table_mint_next"
  c_tableMintNext :: IO Int64

-- | The exact handle salt for the n-th table (0-based): n+1, so the
-- first table salts 1 (never zero) and every salt is nonzero and
-- distinct while it fits 32 bits. 'Nothing' past 2^32-1 tables
-- (index 2^32-1 and beyond, or negative): no distinct nonzero
-- salt remains, so the allocator must refuse. Pure, so the
-- boundary pins directly without minting tables.
tableSaltFor :: Int -> Maybe Word32
tableSaltFor n
  | toInteger n >= 0 && toInteger n < 0xFFFFFFFF = Just (fromIntegral n + 1)
  | otherwise = Nothing

-- | Mint the next table identity with its exact salt (single
-- atomic step in the C-owned mint). 'Nothing' past 2^32-1 tables:
-- the counter is left untouched, so a refused mint allocates
-- nothing and consumes no identity a later mint could observe.
mintTableId :: IO (Maybe (AsyncTableId, Word32))
mintTableId = do
  n <- c_tableMintNext
  let i = fromIntegral n :: Int
  pure $ case tableSaltFor i of
    Nothing -> Nothing
    Just salt -> Just (AsyncTableId i, salt)

-- | The attached-job table: live jobs plus tombstones, the next
-- job id, the live-job capacity, the async-enabled sessions, the
-- table's process-local identity, its exact handle salt, and its
-- close-admission gate @(live borrowers, close phase)@: export
-- calls admitted through the context boundary hold one borrower
-- each across the whole call, and close claims the gate and waits
-- the borrowers out before draining anything. The raw table
-- methods ('startJob', 'pollJob', 'completeJob', 'cancelJob', and
-- the rest) take no context admission, so their callers serialize
-- use with destruction: hold a borrower across the call
-- ('enterTableUse'\/'exitTableUse'), or bound the call by the
-- owning context's lifetime.
data AsyncTable = AsyncTable
  { atJobs :: !(TVar (Map JobId Job))
  , atNext :: !(TVar Int)
  , atMax :: !Int
  , atAsync :: !(TVar (Set SessionId))
  , atId :: !AsyncTableId
  , atSalt :: !Word32
  , atGate :: !(TVar (Int, TableClose))
  }

-- | A fresh table with the given live-job capacity, a fresh
-- process-local identity, and its exact handle salt. Throws
-- 'TableIdExhausted' past 2^32-1 tables (see 'tryNewAsyncTable'
-- for the explicit refusal); a refusal allocates nothing.
newAsyncTable :: Int -> IO AsyncTable
newAsyncTable cap =
  tryNewAsyncTable cap >>= maybe (throwIO TableIdExhausted) pure

-- | A fresh table like 'newAsyncTable', with allocator refusal as
-- 'Nothing' past 2^32-1 tables instead of an exception. The FFI
-- open entries report refusal as NULL, like every other open
-- failure.
tryNewAsyncTable :: Int -> IO (Maybe AsyncTable)
tryNewAsyncTable cap = do
  mTid <- mintTableId
  case mTid of
    Nothing -> pure Nothing
    Just (tid, salt) ->
      Just <$> (AsyncTable
        <$> newTVarIO Map.empty
        <*> newTVarIO 0
        <*> pure cap
        <*> newTVarIO Set.empty
        <*> pure tid
        <*> pure salt
        <*> newTVarIO (0, TableOpen))

-- | A table's process-local identity (stable for the table's life).
asyncTableId :: AsyncTable -> AsyncTableId
asyncTableId = atId

-- | A table's exact handle salt (nonzero, distinct per table,
-- stable for the table's life). The FFI handle codec packs this
-- salt with the job id, so equal numeric job ids on distinct
-- tables always admit distinct tokens.
asyncTableSalt :: AsyncTable -> Word32
asyncTableSalt = atSalt

-- | Request asynchronous service for a session. Idempotent;
-- sessions never enabled stay synchronous no matter the async
-- load elsewhere.
enableAsyncSession :: AsyncTable -> SessionId -> IO ()
enableAsyncSession table sid = atomically $ do
  async <- readTVar (atAsync table)
  writeTVar (atAsync table) (Set.insert sid async)

-- | Withdraw asynchronous service from a session. Idempotent:
-- withdrawing a session that was never enabled (or was already
-- withdrawn) is a quiet no-op. Callers invoke it only after the
-- session's successful retirement (close or removal publication),
-- so a rollback — a refused close, a faulted publish — leaves the
-- enabled set untouched.
disableAsyncSession :: AsyncTable -> SessionId -> IO ()
disableAsyncSession table sid = atomically $ do
  async <- readTVar (atAsync table)
  writeTVar (atAsync table) (Set.delete sid async)

-- | Whether a session is async-enabled. Lock-free read; rejoin
-- validation uses it for target-session compatibility.
isAsyncSession :: AsyncTable -> SessionId -> IO Bool
isAsyncSession table sid =
  Set.member sid <$> readTVarIO (atAsync table)

-- | Count of async-enabled sessions. Lock-free test\/diagnostic
-- census: retirement paths keep it equal to the live async
-- sessions, and rollback paths leave it unchanged.
enabledSessionCount :: AsyncTable -> IO Int
enabledSessionCount table =
  Set.size <$> readTVarIO (atAsync table)

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

-- | Re-read a job under its lease. A missing job means a
-- third-party commit evicted it between lease admission and this
-- re-read (eviction takes no lease): callers report unknown,
-- exactly as if the owner reaped it — never a fabricated state.
readJob :: AsyncTable -> JobId -> IO (Maybe Job)
readJob table jid =
  readTVarIO (atJobs table) >>= pure . Map.lookup jid

-- | Close phase of a table's admission gate: open, closing (with
-- the teardown and closer state), or closed. Phases move only
-- forward once teardown starts: a release before teardown reopens
-- the gate, while a release past teardown begin leaves the table
-- closing without a closer, so a retry resumes teardown instead
-- of readmitting a partially destroyed context.
data TableClose
  = TableOpen
  | TableClosing !Teardown !Closer
  | TableClosed
  deriving (Eq, Show)

-- | Whether the winning closer started tearing the table down.
data Teardown
  = TeardownPending
  | TeardownStarted
  deriving (Eq, Show)

-- | Whether the closing table currently has a closer running
-- teardown for it.
data Closer
  = CloserActive
  | CloserAbsent
  deriving (Eq, Show)
