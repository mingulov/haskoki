{- | Scoped detach leases, structural half.

The scoped combinator ('withDetachLease' \/ 'LeaseView' \/
'leaseLockHeld'): mask discipline, auto-abort unless committed,
idempotent commit.

Scope pins (combinator behavior):

* unknown jobs run the body with 'Nothing';
* a body that returns without committing leaves the job present
  and the lock free (a dropped lease cannot wedge);
* a throwing body aborts the lease (lock free afterwards);
* 'lvCommit' revokes the job; committing twice is a quiet no-op;
* the view snapshot equals the raw 'leaseSnapshot' (semantics kept).

'caseRawCommitReleases' pins the raw commit over the
'leaseLockHeld' seam (a lock-state probe in the 'gateBusy'
precedent): revoke plus release, observably.

'caseKillDuringCommitNeverWedges' pins the requirement on the
commit path directly: a kill racing a combinator commit leaves no
wedge on any timing. The victim commits through 'withDetachLease'
under one in-flight kill per iteration; main then probes with a
100ms 'beginDetach' (kept-and-free or revoked: fine; timeout: a
wedge, FAIL). Every outcome is clean by construction —
killed pre-commit aborts (job kept, lock free), killed
mid\/post-commit already revoked (lock free) — so this case is
deterministic, not statistical.

What this case does NOT do, deliberately: catch a torn
revoke-STM\/release pair behaviorally. That gap is a straight
primop sequence (STM-commit return into 'putMVar' on evaluated
args) with no safe point inside, so no 'throwTo' can land in it
either way — three probe shapes (single kill, un-gated spray,
gated spray) all pass identically with the masking present AND
with it fault-removed (fault-injection logs: ~6000 commits,
~50 in-commit kills, 0 tears either way). The commit masking is therefore pinned by
construction plus the deterministic flag tests here
('caseCommit' would wedge without the committed flag,
'caseCommitIdempotent' pins the quiet second commit); this kill
case additionally goes live automatically if a future refactor
ever opens a hittable window on the path. The same-masking
take-to-handoff window IS hittable and IS pinned live by
'LeaseWedgeSpec' (genuine wedge counts).

Rendezvous discipline matches 'LeaseWedgeSpec': 'try' OUTSIDE
'restore' (the reversed order lets a pending kill escape past the
handler and kill the victim),
kill-retried victim puts, 10s 'System.Timeout' backstops on every
join ('assertFailure' on expiry).
-}
{-# LANGUAGE OverloadedStrings #-}
module LeaseScopeSpec (spec) where

import Control.Concurrent
  ( MVar
  , forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  )
import Control.Exception (Exception, SomeException, mask, throwIO, try)
import Control.Monad (forM_)
import Data.IORef (modifyIORef', newIORef, readIORef)
import Data.Maybe (isJust)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.CallWork (mkFixtureCallWork)
import Haskoki.Model (Model (..))
import Haskoki.Operation (CryptoEffect (..))
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Outcome
  ( EffectRequest (..)
  , EngineResult (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Reservation (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request (FunctionId (..), Request (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.Async
  ( AsyncTable
  , AsyncWork (..)
  , CancelOutcome (..)
  , JobFunction (..)
  , JobRequest (..)
  , LeaseView (..)
  , abortDetach
  , asyncTableId
  , beginDetach
  , cancelJob
  , commitDetachRevoke
  , enableAsyncSession
  , jobSnapshotTicks
  , leaseLockHeld
  , leaseSnapshot
  , newAsyncTable
  , snapshotJob
  , startFixtureJob
  , withDetachLease
  )
import Haskoki.Runtime.Detached
  ( AttachmentView (..)
  , DetachCtx
  , DetachOutcome (..)
  , JoinOutcome (..)
  , JoinRequest (..)
  , detachJob
  , inspectAttachment
  , joinJob
  , joinPolicyName
  , openDetached
  )
import Haskoki.Runtime.Lifecycle
  ( Env
  , defaultInitArgs
  , initialize
  , newEnv
  , publish
  , seatToken
  , snapshotModel
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , JobExecState (..)
  , JobRecord (..)
  , Store (..)
  , StoreDelta (..)
  , TokenRecord (..)
  , emptyDelta
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Transition (finishEffect, planCall)
import Haskoki.Types
  ( EngineResourceId (..)
  , Generation (..)
  , JobId (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

spec :: TestTree
spec = testGroup "Scoped detach leases"
  [ testCase "unknown job runs body with Nothing" caseUnknown
  , testCase "dropped lease keeps job, frees lock" caseDropped
  , testCase "throwing body aborts the lease" caseThrowing
  , testCase "commit revokes the job" caseCommit
  , testCase "commit is idempotent" caseCommitIdempotent
  , testCase "view snapshot matches raw snapshot" caseSnapshotKept
  , testCase "raw commit releases the lock" caseRawCommitReleases
  , testCase "kill during commit never wedges"
      caseKillDuringCommitNeverWedges
  , testCase "rival-table join refuses; leased job undisturbed"
      caseRivalTableJoinRefuses
  ]

sid1 :: SessionId
sid1 = SessionId 1

digestRequest :: SessionId -> Int -> JobRequest
digestRequest sid ticks = JobRequest
  { jrSession = sid
  , jrFunction = JobDigest
  , jrWork = WorkCall (mkFixtureCallWork sid
      (Reservation "lease-scope" [] Nothing Nothing)
      (EffectCrypto (FxDigest (MechanismId 0x250) "abc")))
  , jrTicks = ticks
  , jrCapacity = 64
  }

-- | Body throw used to prove abort-on-throw.
data Boom = Boom deriving (Show)

instance Exception Boom

mkJob :: IO (AsyncTable, JobId)
mkJob = do
  table <- newAsyncTable 8
  enableAsyncSession table sid1
  ej <- startFixtureJob table (digestRequest sid1 2)
  case ej of
    Left deny -> assertFailure ("job submit refused: " ++ show deny)
    Right j -> pure (table, j)

caseUnknown :: IO ()
caseUnknown = do
  table <- newAsyncTable 8
  enableAsyncSession table sid1
  saw <- withDetachLease table (JobId 999) $ \mV -> pure (isJust mV)
  assertEqual "unknown job gives Nothing" False saw

caseDropped :: IO ()
caseDropped = do
  (table, j0) <- mkJob
  snap0 <- withDetachLease table j0 $ \mV -> case mV of
    Nothing -> assertFailure "combinator missed a live job"
    Just v -> pure (lvSnapshot v)
  msnap <- snapshotJob table j0
  assertEqual "dropped lease keeps the job" (Just snap0) msnap
  mProbe <- timeout 5000000 (beginDetach table j0)
  case mProbe of
    Nothing -> assertFailure "dropped lease wedged the lock"
    Just Nothing -> assertFailure "job vanished"
    Just (Just l) -> abortDetach l

caseThrowing :: IO ()
caseThrowing = do
  (table, j0) <- mkJob
  e <- try (withDetachLease table j0 $ \_ -> throwIO Boom)
    :: IO (Either Boom ())
  case e of
    Left Boom -> pure ()
    Right _ -> assertFailure "body throw was swallowed"
  mProbe <- timeout 5000000 (beginDetach table j0)
  case mProbe of
    Nothing -> assertFailure "thrown lease wedged the lock"
    Just Nothing -> assertFailure "job vanished"
    Just (Just l) -> abortDetach l

caseCommit :: IO ()
caseCommit = do
  (table, j0) <- mkJob
  withDetachLease table j0 $ \mV -> case mV of
    Nothing -> assertFailure "combinator missed a live job"
    Just v -> lvCommit v
  msnap <- snapshotJob table j0
  assertEqual "committed job revoked" Nothing msnap
  mProbe <- timeout 5000000 (beginDetach table j0)
  case mProbe of
    Just Nothing -> pure ()
    Nothing -> assertFailure "begin blocked on a revoked job"
    Just (Just l) -> do
      abortDetach l
      assertFailure "revoked job still detachable"

caseCommitIdempotent :: IO ()
caseCommitIdempotent = do
  (table, j0) <- mkJob
  withDetachLease table j0 $ \mV -> case mV of
    Nothing -> assertFailure "combinator missed a live job"
    Just v -> lvCommit v >> lvCommit v
  msnap <- snapshotJob table j0
  assertEqual "double commit still revoked" Nothing msnap

caseSnapshotKept :: IO ()
caseSnapshotKept = do
  (table, j0) <- mkJob
  snapView <- withDetachLease table j0 $ \mV -> case mV of
    Nothing -> assertFailure "combinator missed a live job"
    Just v -> pure (lvSnapshot v)
  mRaw <- beginDetach table j0
  case mRaw of
    Nothing -> assertFailure "raw begin missed a live job"
    Just l -> do
      assertEqual "view snapshot matches raw" snapView (leaseSnapshot l)
      abortDetach l

caseRawCommitReleases :: IO ()
caseRawCommitReleases = do
  (table, j0) <- mkJob
  mL <- beginDetach table j0
  case mL of
    Nothing -> assertFailure "raw begin missed a live job"
    Just l -> do
      commitDetachRevoke l
      held <- leaseLockHeld l
      assertEqual "raw commit releases the lock" False held
      msnap <- snapshotJob table j0
      assertEqual "raw commit revokes" Nothing msnap

-- ---------------------------------------------------------------------------
-- Kill-during-commit characterization (needs 'withDetachLease')
-- ---------------------------------------------------------------------------

-- | Iterations (fresh job each — a commit revokes).
nKillIters :: Int
nKillIters = 200

-- | Victim-side put that survives a kill landing while blocked.
putRetry :: MVar a -> a -> IO ()
putRetry mv x = do
  e <- try (putMVar mv x)
  case (e :: Either SomeException ()) of
    Left _ -> putRetry mv x
    Right () -> pure ()

caseKillDuringCommitNeverWedges :: IO ()
caseKillDuringCommitNeverWedges = do
  table <- newAsyncTable 512
  enableAsyncSession table sid1
  jids <- mapM
    (\_ -> do
      ej <- startFixtureJob table (digestRequest sid1 2)
      case ej of
        Left deny -> assertFailure ("job submit refused: " ++ show deny)
        Right j -> pure j
    )
    [1 .. nKillIters :: Int]
  ready <- newEmptyMVar
  done <- newEmptyMVar
  let victimLoop = mask $ \restore -> forM_ jids $ \jid -> do
        putRetry ready ()
        -- 'try' OUTSIDE 'restore': a pending kill is always caught.
        -- The combinator owns the pairing, so the victim needs no
        -- abort logic of its own on any path.
        _ <- try (restore (withDetachLease table jid commitBody))
          :: IO (Either SomeException ())
        putRetry done ()
      commitBody mV = case mV of
        Nothing -> pure ()
        Just v -> lvCommit v
  victimTid <- forkIO victimLoop
  wedged <- newIORef (0 :: Int)
  forM_ jids $ \jid -> do
    mReady <- timeout 10000000 (takeMVar ready)
    case mReady of
      Nothing -> assertFailure "wedge detected: victim stalled"
      Just () -> pure ()
    killThread victimTid
    mDone <- timeout 10000000 (takeMVar done)
    case mDone of
      Nothing -> assertFailure "wedge detected: iteration never reported"
      Just () -> pure ()
    -- Killed pre-commit: job kept, lock free. Killed mid/post:
    -- revoked. A timeout is a wedge: FAIL.
    mProbe <- timeout 100000 (beginDetach table jid)
    case mProbe of
      Nothing -> modifyIORef' wedged (+ 1)
      Just Nothing -> pure ()
      Just (Just l) -> do
        msnap <- snapshotJob table jid
        case msnap of
          Nothing -> abortDetach l >> assertFailure "job vanished mid-probe"
          Just _ -> abortDetach l
  nW <- readIORef wedged
  assertEqual "no kill-during-commit wedged" 0 nW

-- ---------------------------------------------------------------------------
-- Join claims against held detach leases
-- ---------------------------------------------------------------------------

-- | One model world for lease/detach interplay: a memory store
-- with the home token, one detach context, one initialized env
-- with a seated token and one digest-initialized session. Tables
-- stay with the caller — several tables share this world.
mkLeaseWorld :: IO (Store, DetachCtx, Env, SessionId)
mkLeaseWorld = do
  world <- newMemoryWorld
  eStore <- openMemoryStore world
  store <- case eStore of
    Right s -> pure s
    Left err -> assertFailure ("world open failed: " ++ show err)
  let tok = TokenRecord
        { trId = TokenId 1
        , trSlot = SlotId 0
        , trGeneration = Generation 0
        , trLabel = "lease-test"
        , trAuth = tokenAuthNew
        }
  res <- storeCommit store emptyDelta { sdPutTokens = [tok] }
  case res of
    Committed -> pure ()
    other -> assertFailure ("token seat failed: " ++ show other)
  eDc <- openDetached store (TokenId 1)
  dc <- case eDc of
    Right c -> pure c
    Left err -> assertFailure ("openDetached failed: " ++ show err)
  env <- newEnv defaultRules
  ini <- initialize env defaultInitArgs
  case ini of
    OutcomeOk () -> pure ()
    OutcomeErr c -> assertFailure ("init failed: " ++ show c)
  seatToken env (SlotId 0) >>= assertEqual "seat ok" (Right ())
  m0 <- snapshotModel env
  let sid = SessionId (mNextSession m0)
      openReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []
  case planCall defaultRules m0 openReq of
    Immediate pc -> do
      pr <- publish env (pcDelta pc)
      case pr of
        Right () -> pure ()
        Left f -> assertFailure ("open publish failed: " ++ show f)
    other -> assertFailure ("open did not plan immediate: " ++ show other)
  m2 <- snapshotModel env
  let initReq = Request Pkcs11_3_2 F_DigestInit (Just sid) Nothing
        (encodeInitInput (MechanismId 0x250) [] False "") []
  case planCall defaultRules m2 initReq of
    Execute eff (EffectCrypto _) -> do
      m3 <- snapshotModel env
      case finishEffect defaultRules m3 eff
          (EngineOkResource (EngineResourceId 31)) of
        Left rej -> assertFailure ("digest-init finish rejected: " ++ show rej)
        Right pc -> do
          pr <- publish env (pcDelta pc)
          case pr of
            Right () -> pure ()
            Left f -> assertFailure ("digest-init publish failed: " ++ show f)
    other -> assertFailure ("digest-init did not plan execute: " ++ show other)
  pure (store, dc, env, sid)

-- | Rival-table join refusal: table A holds the live
-- attachment under a held detach lease while table B holds a
-- terminal job at the SAME numeric id. The join of the pid on B
-- refuses already-attached WITHOUT resolving A's job id in B's
-- table (no wrong-table lookup, no lease contact, no durable
-- write); the lease aborts cleanly and A's job is intact.
caseRivalTableJoinRefuses :: IO ()
caseRivalTableJoinRefuses = do
  (store, dc, env, sid) <- mkLeaseWorld
  tableA <- newAsyncTable 8
  tableB <- newAsyncTable 8
  enableAsyncSession tableA sid
  enableAsyncSession tableB sid
  let tidA = asyncTableId tableA
      tidB = asyncTableId tableB
  assertBool "table identities distinct" (tidA /= tidB)
  -- A: start, detach, join back (active JobId 1).
  eA0 <- startFixtureJob tableA (digestRequest sid 1)
  jA0 <- case eA0 of
    Right j -> pure j
    Left deny -> assertFailure ("A start denied: " ++ show deny)
  eDet <- detachJob dc tableA jA0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("A detach failed: " ++ show other)
  eJoinA <- joinJob dc env tableA JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sid
    , jqCapacity = 64
    }
  jA <- case eJoinA of
    JoinOk j -> pure j
    other -> assertFailure ("A join failed: " ++ show other)
  -- B: two jobs, second canceled — a terminal job at the same
  -- numeric id as A's live attachment.
  eB0 <- startFixtureJob tableB (digestRequest sid 1)
  case eB0 of
    Right _ -> pure ()
    Left deny -> assertFailure ("B start denied: " ++ show deny)
  eB1 <- startFixtureJob tableB (digestRequest sid 1)
  jB1 <- case eB1 of
    Right j -> pure j
    Left deny -> assertFailure ("B start denied: " ++ show deny)
  assertEqual "numeric collision" jA jB1
  eCancel <- cancelJob tableB jB1
  case eCancel of
    CancelOk -> pure ()
    other -> assertFailure ("B cancel failed: " ++ show other)
  -- Hold A's detach lease across the rival join.
  mLease <- beginDetach tableA jA
  lease <- case mLease of
    Just l -> pure l
    Nothing -> assertFailure "begin missed A's live job"
  mRival <- timeout 10000000
    (joinJob dc env tableB JoinRequest
      { jqPid = pid
      , jqFunction = JobDigest
      , jqSession = sid
      , jqCapacity = 64
      })
  rival <- case mRival of
    Nothing -> assertFailure "rival join wedged on the lease"
    Just r -> pure r
  assertEqual "rival refused first-wins"
    (JoinAlreadyAttached joinPolicyName) rival
  -- The lease never saw contact: abort is clean, job intact.
  abortDetach lease
  mSnap <- snapshotJob tableA jA
  case mSnap of
    Nothing -> assertFailure "A's job vanished"
    Just snap -> assertEqual "A's ticks intact" (Just 1) (jobSnapshotTicks snap)
  mLease2 <- beginDetach tableA jA
  case mLease2 of
    Nothing -> assertFailure "A's job unleasable after abort"
    Just l2 -> abortDetach l2
  -- No wrong-table self-heal: durable record still queued,
  -- attachment still A's active.
  av <- inspectAttachment dc pid
  assertEqual "A still active" (Just (AvActive jA)) av
  eJobs <- storeLoadJobs store
  jobs <- case eJobs of
    Right js -> pure js
    Left err -> assertFailure ("loadJobs failed: " ++ show err)
  case [r | r <- jobs, jrPersistentId r == pid] of
    [rec] -> assertEqual "record still queued" JobQueued (jrState rec)
    other -> assertFailure ("expected one record, got " ++ show (length other))
  storeClose store
