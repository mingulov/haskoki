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
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Operation (CryptoEffect (..))
import Haskoki.Outcome (EffectRequest (..), Reservation (..))
import Haskoki.Registry (MechanismId (..))
import Haskoki.Runtime.Async
  ( AsyncTable
  , AsyncWork (..)
  , JobFunction (..)
  , JobRequest (..)
  , LeaseView (..)
  , abortDetach
  , beginDetach
  , commitDetachRevoke
  , enableAsyncSession
  , leaseLockHeld
  , leaseSnapshot
  , newAsyncTable
  , snapshotJob
  , startJob
  , withDetachLease
  )
import Haskoki.Types (JobId (..), SessionId (..))

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
  ]

sid1 :: SessionId
sid1 = SessionId 1

digestRequest :: SessionId -> Int -> JobRequest
digestRequest sid ticks = JobRequest
  { jrSession = sid
  , jrFunction = JobDigest
  , jrWork = WorkCall
      (Reservation "lease-scope" [] Nothing Nothing)
      (EffectCrypto (FxDigest (MechanismId 0x250) "abc"))
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
  ej <- startJob table (digestRequest sid1 2)
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
      ej <- startJob table (digestRequest sid1 2)
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
