{- | FfiAsync Retirement: retirement, close-tail and reclaim probes.
-}
{-# LANGUAGE OverloadedStrings #-}
module FfiAsync.Retirement
  ( caseUnknownKeyRefusesWithoutAdmission
  , caseHookOnlyRefusesAfterHook
  , caseCloseUnknownNullsSlotOnly
  , caseCloseTailThrowResumesOnRetry
  , caseCloseTailFreeThrowResumesOnRetry
  , caseValueCloseKilledInLeaseWaitResumes
  , caseBlockWaitRejectsOtherReasons
  , caseStoreThrowInRetirementStillCloses
  , caseCommitThrowReportsOnlyUncommitted
  , caseNullClosesAreSilent
  , caseRepeatedCloseFreesOnce
  , caseFailedStoreCloseKeepsBoxSlot
  , caseBoxCloseKilledInLockWaitKeepsBox
  , caseBoxCloseStepParksBeforeTransfer
  , caseCtxCloseStepParksBeforeTransfer
  , caseResidueRetryInterruptedPutsBack
  , caseStandaloneChurnLeavesNoOrphans
  , caseJoinedCleanupReopensSameStore
  , caseJoinedCleanupReopensSameSqliteStore
  ) where


import Control.Concurrent
  ( MVar
  , forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  , tryPutMVar
  , tryTakeMVar
  )
import Control.Exception
  ( AsyncException (..)
  , SomeException
  , finally
  , fromException
  , mask_
  , throwIO
  , try
  )
import qualified Data.ByteString as BS
import Data.IORef (atomicModifyIORef', newIORef, readIORef, writeIORef)
import Foreign.C.String (withCString)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (castPtr, nullPtr, wordPtrToPtr)
import Foreign.StablePtr
  ( StablePtr
  , castPtrToStablePtr
  , deRefStablePtr
  , freeStablePtr
  , newStablePtr
  )
import Foreign.Storable (peek, poke)
import GHC.Conc (BlockReason (..))
import System.FilePath ((</>))
import System.Timeout (timeout)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)

import OwnershipCounters (assertZero)
import StormBudget (stormScaleBudget)
import FfiAsync.Fixtures
import AcquisitionCounters
import Haskoki.FFI.Async
  ( AcquireStep (..)
  , AsyncAcquisition (..)
  , AsyncCtx (..)
  , JobHandle
  , allocJobHandle
  , asyncAcquisition
  , asyncCloseCtx
  , asyncLiveHandles
  , closeCtxSlotWith
  , closeStoreBoxSlotWith
  , haskokiAsyncClose
  , haskokiAsyncStart
  , haskokiAsyncStoreClose
  , haskokiAsyncStoreOpenWith
  , newResidueOwner
  , openAsyncCtxOnWith
  , openAsyncCtxWith
  , openStoreBoxWith
  , registerFixtureCtx
  , residueCount
  , resolveJobHandle
  , retireCtx
  , setEnterTestHook
  , StoreBox (..)
  )
import Haskoki.Runtime.Async
  ( CancelOutcome (..)
  , Closer (..)
  , JobFunction (..)
  , TableClose (..)
  , Teardown (..)
  , TerminalState (..)
  , asyncTableId
  , cancelJob
  , inspectTableClose
  , inspectTableGate
  , tableStats
  , withDetachLease
  )
import Haskoki.Runtime.Config
  ( defaultConfig
  )
import Haskoki.Runtime.Detached
  ( AttachmentView (..)
  , DetachOutcome (..)
  , JoinOutcome (..)
  , JoinRequest (..)
  , detachJob
  , inspectAttachment
  , joinJob
  , retireLiveTableFor
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , FaultInjector (..)
  , FaultPoint (..)
  , JobExecState (..)
  , JobRecord (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , emptyDelta
  , noFaults
  , scriptedFaults
  )
import Haskoki.Runtime.Storage.Memory
  ( newMemoryWorld
  , openMemoryStore
  )
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Types (SessionId (..))


-- | An unknown registry key refuses without admission: a valid
-- pointer to a fixture context that is never registered, driven
-- through the job-start export, reports the same code as a retired
-- tombstone, leaves the out-pointer untouched, and mints no job.
-- No-dereference holds by construction: 'enterCtx' admits through
-- the registry before any dereference.
caseUnknownKeyRefusesWithoutAdmission :: IO ()
caseUnknownKeyRefusesWithoutAdmission = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  spTomb <- newStablePtr ctx
  registerFixtureCtx spTomb (acTable ctx)
  retireCtx spTomb
  (spUnknown, colliders) <- freshAbsentKey ctx
  let sess = CULong (fromIntegral (unSessionId (acSession ctx)))
      startOn sp pHandleOut = BS.useAsCString "abc" $ \p ->
        haskokiAsyncStart sp sess 2 (castPtr p) 3 32 1 pHandleOut
  (do
    rvTomb <- alloca $ \pHandleOut -> do
      poke pHandleOut nullJob
      rv <- startOn spTomb pHandleOut
      hOut <- peek pHandleOut
      assertBool "tombstone mints no handle" (isNull hOut)
      pure rv
    assertEqual "tombstone refuses" rvGeneral rvTomb
    (liveTomb, _, _) <- tableStats (acTable ctx)
    assertZero "live_jobs" "tombstone mints no job" liveTomb
    let sentinel = castPtrToStablePtr (wordPtrToPtr 0xa5a5a5a5) :: StablePtr JobHandle
    (rvUnknown, hUnknown) <- alloca $ \pHandleOut -> do
      poke pHandleOut sentinel
      rv <- startOn spUnknown pHandleOut
      hOut <- peek pHandleOut
      pure (rv, hOut)
    assertEqual "unknown refuses like the tombstone" rvTomb rvUnknown
    assertBool "unknown leaves the out-pointer untouched" (hUnknown == sentinel)
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "unknown mints no job" liveAfter
    assertEqual "no terminal minted" 0 termAfter
    assertEqual "no id consumed" 0 nextAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "no handles" nLive
    ) `finally`
      (freeStablePtr spUnknown >> mapM_ freeStablePtr colliders
        >> freeStablePtr spTomb >> asyncCloseCtx ctx)

-- | A hook-only registry key refuses after its hook: arming a hook
-- on a never-registered key parks the hook without admitting, the
-- export fires the hook once and then refuses like a tombstone,
-- minting no job.
caseHookOnlyRefusesAfterHook :: IO ()
caseHookOnlyRefusesAfterHook = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  (spHook, colliders) <- freshAbsentKey ctx
  fired <- newEmptyMVar
  setEnterTestHook spHook (Just (putMVar fired ()))
  let sess = CULong (fromIntegral (unSessionId (acSession ctx)))
      startOn pHandleOut = BS.useAsCString "abc" $ \p ->
        haskokiAsyncStart spHook sess 2 (castPtr p) 3 32 1 pHandleOut
  (do
    (rv, hOut) <- alloca $ \pHandleOut -> do
      poke pHandleOut nullJob
      r <- startOn pHandleOut
      h <- peek pHandleOut
      pure (r, h)
    mFired <- timeout 10000000 (takeMVar fired)
    case mFired of
      Nothing -> assertFailure "entry hook never fired"
      Just () -> pure ()
    mSecond <- tryTakeMVar fired
    case mSecond of
      Nothing -> pure ()
      Just () -> assertFailure "entry hook fired twice for one call"
    assertEqual "hook-only refuses" rvGeneral rv
    assertBool "hook-only mints no handle" (isNull hOut)
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "hook-only mints no job" liveAfter
    assertEqual "no terminal minted" 0 termAfter
    assertEqual "no id consumed" 0 nextAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "no handles" nLive
    ) `finally`
      (setEnterTestHook spHook Nothing >> freeStablePtr spHook
        >> mapM_ freeStablePtr colliders >> asyncCloseCtx ctx)

-- | Closing an unknown key reclaims the slot only: the slot nulls,
-- the table gate stays open with no borrowers, and the backend
-- stays open. Pins the slot-reclaim path.
caseCloseUnknownNullsSlotOnly :: IO ()
caseCloseUnknownNullsSlotOnly = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  (spUnknown, colliders) <- freshAbsentKey ctx
  (counting, readCounts) <- countingAcquisition
  (spExport, colliders2) <- freshAbsentKey ctx
  (do
    alloca $ \pSlot -> do
      poke pSlot spUnknown
      closeCtxSlotWith counting pSlot
      after <- peek pSlot
      assertBool "slot nulled" (isNull after)
    gate <- inspectTableGate (acTable ctx)
    assertEqual "gate stays open" (0, False) gate
    c <- readCounts
    assertEqual "backend stays open" 0 (acBackendCloses c)
    assertEqual "no retirement" 0 (acRetirements c)
    assertEqual "no context free" 0 (acCtxFrees c)
    alloca $ \pSlot -> do
      poke pSlot spExport
      haskokiAsyncClose pSlot
      after <- peek pSlot
      assertBool "export slot nulled" (isNull after)
    gate2 <- inspectTableGate (acTable ctx)
    assertEqual "gate still open" (0, False) gate2
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no jobs" liveAfter
    assertEqual "no terminal minted" 0 termAfter
    assertEqual "no id consumed" 0 nextAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "no handles" nLive
    ) `finally`
      (freeStablePtr spUnknown >> mapM_ freeStablePtr colliders
        >> freeStablePtr spExport >> mapM_ freeStablePtr colliders2
        >> asyncCloseCtx ctx)

-- | A throw in the pointer tail leaves a resumable gate: the first
-- close runs its drain, then its retire throws, so the slot stays
-- set with teardown started and no closer; the retry re-runs the
-- idempotent drain, retires and frees exactly once, and nulls the
-- slot. Before the tail ran first, the throw stranded a closed gate
-- with a live entry and pointer no retry could reclaim.
caseCloseTailThrowResumesOnRetry :: IO ()
caseCloseTailThrowResumesOnRetry = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  h <- allocJobHandle ctx j0
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  (counting, readCounts) <- countingAcquisition
  armed <- newIORef True
  let throwing = counting
        { aaRetireCtx = \sp' -> do
            fire <- atomicModifyIORef' armed (\on -> (False, on))
            if fire
              then throwIO (userError "injected retire throw")
              else aaRetireCtx counting sp'
        }
  alloca $ \pSlot -> do
    poke pSlot sp
    r <- try (closeCtxSlotWith throwing pSlot) :: IO (Either SomeException ())
    case r of
      Left _ -> pure ()
      Right () -> assertFailure "throwing retire returned normally"
    mid <- peek pSlot
    assertBool "slot still set after the throw" (not (isNull mid))
    closeMid <- inspectTableClose (acTable ctx)
    assertEqual "gate resumable after the throw"
      (TableClosing TeardownStarted CloserAbsent) closeMid
    closeCtxSlotWith throwing pSlot
    after <- peek pSlot
    assertBool "retry nulled the slot" (isNull after)
    closeAfter <- inspectTableClose (acTable ctx)
    assertEqual "retry closed the gate" TableClosed closeAfter
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "closed, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "retry drained the handle" nLive
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live jobs" liveAfter
    assertEqual "one terminal job" 1 termAfter
    assertEqual "one job minted" 1 nextAfter
    c <- readCounts
    assertEqual "retired once on the retry" 1 (acRetirements c)
    assertEqual "context freed once on the retry" 1 (acCtxFrees c)
    assertEqual "backend close ran on both attempts" 2 (acBackendCloses c)
    mStale <- resolveJobHandle ctx h
    assertEqual "handle retired" Nothing mStale
    cout <- cancelJob (acTable ctx) j0
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("job not canceled, got " ++ show other)
    haskokiAsyncClose pSlot
    after2 <- peek pSlot
    assertBool "slot stays nulled" (isNull after2)
    awaitNoPendingReclaims
    awaitReclaimBalanced

-- | A throw in the pointer free leaves a resumable gate: the
-- first close retires, then its free throws, so the slot stays
-- set with teardown started and no closer; the retry retires the
-- live entry the throw arm re-registered, frees exactly once,
-- and nulls the slot.
caseCloseTailFreeThrowResumesOnRetry :: IO ()
caseCloseTailFreeThrowResumesOnRetry = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  h <- allocJobHandle ctx j0
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  (counting, readCounts) <- countingAcquisition
  armed <- newIORef True
  let throwing = counting
        { aaFreeCtxPtr = \sp' -> do
            fire <- atomicModifyIORef' armed (\on -> (False, on))
            if fire
              then throwIO (userError "injected free throw")
              else aaFreeCtxPtr counting sp'
        }
  alloca $ \pSlot -> do
    poke pSlot sp
    r <- try (closeCtxSlotWith throwing pSlot) :: IO (Either SomeException ())
    case r of
      Left _ -> pure ()
      Right () -> assertFailure "throwing free returned normally"
    mid <- peek pSlot
    assertBool "slot still set after the throw" (not (isNull mid))
    closeMid <- inspectTableClose (acTable ctx)
    assertEqual "gate resumable after the throw"
      (TableClosing TeardownStarted CloserAbsent) closeMid
    closeCtxSlotWith throwing pSlot
    after <- peek pSlot
    assertBool "retry nulled the slot" (isNull after)
    closeAfter <- inspectTableClose (acTable ctx)
    assertEqual "retry closed the gate" TableClosed closeAfter
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "closed, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "retry drained the handle" nLive
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live jobs" liveAfter
    assertEqual "one terminal job" 1 termAfter
    assertEqual "one job minted" 1 nextAfter
    c <- readCounts
    assertEqual "retired on both attempts" 2 (acRetirements c)
    assertEqual "context freed once on the retry" 1 (acCtxFrees c)
    assertEqual "backend close ran on both attempts" 2 (acBackendCloses c)
    mStale <- resolveJobHandle ctx h
    assertEqual "handle retired" Nothing mStale
    cout <- cancelJob (acTable ctx) j0
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("job not canceled, got " ++ show other)
    haskokiAsyncClose pSlot
    after2 <- peek pSlot
    assertBool "slot stays nulled" (isNull after2)
    awaitNoPendingReclaims
    awaitReclaimBalanced

-- | A value-level close killed while the drain waits on a job
-- lease resumes and closes: the sibling holds a detach lease on
-- the one live job, the closer parks in the cancel behind it, and
-- after the kill and the release the retry cancels the job,
-- drains its handle and marks the table closed. A further close
-- is a silent no-op. This pins the resume path through the
-- value-level close, which carries no pointer steps.
caseValueCloseKilledInLeaseWaitResumes :: IO ()
caseValueCloseKilledInLeaseWaitResumes = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  h <- allocJobHandle ctx j0
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  sibDone <- newEmptyMVar
  _ <- forkIO $ do
    r <- try (withDetachLease (acTable ctx) j0
      (\_ -> putMVar entered () >> takeMVar proceed))
    putMVar sibDone (r :: Either SomeException ())
  (do
    within10s "sibling takes the lease" (takeMVar entered)
    closedDone <- newEmptyMVar
    closerTid <- forkIO $ do
      r <- try (asyncCloseCtx ctx)
      putMVar closedDone (r :: Either SomeException ())
    awaitBlocked BlockedOnMVar closerTid
    closeBefore <- inspectTableClose (acTable ctx)
    assertEqual "first closer holds the claim"
      (TableClosing TeardownStarted CloserActive) closeBefore
    within10s "second value close returns" (asyncCloseCtx ctx)
    closeAfterSecond <- inspectTableClose (acTable ctx)
    assertEqual "second closer changes nothing" closeBefore closeAfterSecond
    -- The kill goes from a forked thread: the throw only queues
    -- against a parked closer, and the issuer would wedge behind
    -- an undeliverable kill instead of reaching the join.
    _ <- forkIO (killThread closerTid)
    mClosed <- timeout stormScaleBudget (takeMVar closedDone)
    case mClosed of
      Nothing -> do
        putMVar proceed ()
        _ <- within10s "sibling joins after release" (takeMVar sibDone)
        _ <- within10s "closer joins after release" (takeMVar closedDone)
        assertFailure "kill not delivered (>300s)"
      Just (Left e)
        | fromException e == Just ThreadKilled -> pure ()
        | otherwise -> assertFailure ("closer leaked: " ++ show e)
      Just (Right ()) ->
        assertFailure "kill swallowed: value close returned normally"
    gateMid <- inspectTableGate (acTable ctx)
    assertEqual "stays closing with no closer" (0, True) gateMid
    closeMid <- inspectTableClose (acTable ctx)
    assertEqual "teardown started, closer absent"
      (TableClosing TeardownStarted CloserAbsent) closeMid
    (liveMid, _, _) <- tableStats (acTable ctx)
    assertEqual "the cancel never ran" 1 liveMid
    nLiveMid <- asyncLiveHandles ctx
    assertEqual "the handle is still live" 1 nLiveMid
    putMVar proceed ()
    sibRes <- within10s "sibling joins" (takeMVar sibDone)
    case sibRes of
      Right () -> pure ()
      Left e -> assertFailure ("sibling failed: " ++ show e)
    asyncCloseCtx ctx
    closeAfter <- inspectTableClose (acTable ctx)
    assertEqual "retry closed the gate" TableClosed closeAfter
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "closed, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "retry drained the handle" nLive
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live jobs" liveAfter
    assertEqual "one terminal job" 1 termAfter
    assertEqual "one job minted" 1 nextAfter
    mStale <- resolveJobHandle ctx h
    assertEqual "handle retired" Nothing mStale
    cout <- cancelJob (acTable ctx) j0
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("job not canceled, got " ++ show other)
    asyncCloseCtx ctx
    closeAgain <- inspectTableClose (acTable ctx)
    assertEqual "close after teardown is a silent no-op" TableClosed closeAgain)
    `finally` (tryPutMVar proceed () >> pure ())

-- | The block wait rejects other block reasons: a thread parked on
-- an MVar never satisfies a wait for an STM park, so the bounded
-- wait fails instead of returning early on the wrong reason.
caseBlockWaitRejectsOtherReasons :: IO ()
caseBlockWaitRejectsOtherReasons = do
  mv <- newEmptyMVar
  parked <- forkIO (takeMVar mv)
  (do
    awaitBlockedFor (stormScaleBudget `div` 1000) BlockedOnMVar parked
    r <- try (awaitBlockedFor 200 BlockedOnSTM parked) :: IO (Either SomeException ())
    case r of
      Left _ -> pure ()
      Right () -> assertFailure "wait returned on the wrong block reason")
    `finally` killThread parked

-- | A Store throw during retirement still closes and keeps the
-- record joinable: the job load throws instead of answering Left,
-- so retirement marks the joined attachment terminal in memory
-- while the durable row stands untouched. The close completes;
-- then a fresh box and context over the same world rejoin the job
-- exactly once. Before the throw mapped onto the failed-load arm,
-- every close attempt died at the same point and held the context.
caseStoreThrowInRetirementStillCloses :: IO ()
caseStoreThrowInRetirementStillCloses = do
  (world, plain) <- mkFfiStoreWith noFaults
  armed <- newIORef False
  let throwing = plain
        { storeLoadJobs = do
            on <- readIORef armed
            if on
              then throwIO (userError "injected load throw")
              else storeLoadJobs plain
        }
  dc <- mkFfiDetached throwing
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  eDet <- detachJob dc (acTable ctx) j0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  eJoin <- joinJob dc (acEnv ctx) (acTable ctx) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = acSession ctx
    , jqCapacity = 32
    }
  jB <- case eJoin of
    JoinOk j -> pure j
    other -> assertFailure ("join failed: " ++ show other)
  h <- allocJobHandle ctx jB
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    writeIORef armed True
    haskokiAsyncClose pSlot
    writeIORef armed False
    after <- peek pSlot
    assertBool "close completed" (isNull after)
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "closed, no borrowers" (0, True) gateAfter
    av <- inspectAttachment dc pid
    assertEqual "attachment terminal in memory" (Just (AvTerminal JobCanceled)) av
    jobs <- loadFfiJobs throwing
    case jobs of
      [rec] -> do
        assertEqual "durable record id" pid (jrPersistentId rec)
        assertEqual "durable record untouched" JobQueued (jrState rec)
      other -> assertFailure ("expected one row, got " ++ show other)
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "close drained the handle" nLive
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live jobs" liveAfter
    assertEqual "one terminal job" 1 termAfter
    assertEqual "two jobs minted" 2 nextAfter
    mStale <- resolveJobHandle ctx h
    assertEqual "handle retired" Nothing mStale
  storeClose throwing
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do
    eBox <- openStoreBoxWith acq nullPtr
    box <- case eBox of
      Right b -> pure b
      Left _ -> assertFailure "box reopen failed"
    eCtx <- openAsyncCtxOnWith acq defaultConfig box
    spCtx <- case eCtx of
      Right s -> pure s
      Left _ -> assertFailure "context reopen failed"
    ctx2 <- deRefStablePtr spCtx
    dc2 <- case acDetach ctx2 of
      Just d -> pure d
      Nothing -> assertFailure "reopened context has no detach view"
    initFfiDigestSession (acEnv ctx2) (acSession ctx2)
    let rejoin = joinJob dc2 (acEnv ctx2) (acTable ctx2) JoinRequest
          { jqPid = pid
          , jqFunction = JobDigest
          , jqSession = acSession ctx2
          , jqCapacity = 32
          }
    eJoin2 <- rejoin
    j2 <- case eJoin2 of
      JoinOk j -> pure j
      other -> assertFailure ("rejoin failed: " ++ show other)
    eJoin3 <- rejoin
    case eJoin3 of
      JoinAlreadyAttached _ -> pure ()
      other -> assertFailure ("second rejoin not refused: " ++ show other)
    av2 <- inspectAttachment dc2 pid
    assertEqual "rejoined attachment active" (Just (AvActive j2)) av2
    alloca $ \pCtx -> do
      poke pCtx spCtx
      closeCtxSlotWith acq pCtx
      afterCtx <- peek pCtx
      assertBool "context slot nulled" (isNull afterCtx)
    alloca $ \pBox -> do
      poke pBox box
      closeStoreBoxSlotWith acq pBox
      afterBox <- peek pBox
      assertBool "box slot nulled" (isNull afterBox)
    c <- readCounts
    (refused, why) <- memoryReopenRefused world
    assertBalanced ("memory world reopen: " ++ why) c
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | A commit throw mid-loop reports only the uncommitted rows: with
-- two active joins on one table and a Store that throws on its
-- second commit, retirement commits the first row clean, marks both
-- attachments terminal in memory, and reports the throw only for
-- the second row; the second row stays durable-queued. The close
-- then drains and the slot nulls.
caseCommitThrowReportsOnlyUncommitted :: IO ()
caseCommitThrowReportsOnlyUncommitted = do
  (_world, plain) <- mkFfiStoreWith noFaults
  armed <- newIORef False
  countRef <- newIORef (0 :: Int)
  let throwing = plain
        { storeCommit = \delta -> do
            on <- readIORef armed
            if on
              then do
                n <- atomicModifyIORef' countRef (\c -> (c + 1, c + 1))
                if n == 2
                  then throwIO (userError "injected commit throw")
                  else storeCommit plain delta
              else storeCommit plain delta
        }
  dc <- mkFfiDetached throwing
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  j1 <- startFfiDigest ctx "def" 32 1
  eDet0 <- detachJob dc (acTable ctx) j0 JobDigest
  pid0 <- case eDet0 of
    DetachOk p -> pure p
    other -> assertFailure ("first detach failed: " ++ show other)
  eDet1 <- detachJob dc (acTable ctx) j1 JobDigest
  pid1 <- case eDet1 of
    DetachOk p -> pure p
    other -> assertFailure ("second detach failed: " ++ show other)
  let joinOn pid = joinJob dc (acEnv ctx) (acTable ctx) JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = acSession ctx
        , jqCapacity = 32
        }
  eJoin0 <- joinOn pid0
  jB0 <- case eJoin0 of
    JoinOk j -> pure j
    other -> assertFailure ("first join failed: " ++ show other)
  eJoin1 <- joinOn pid1
  jB1 <- case eJoin1 of
    JoinOk j -> pure j
    other -> assertFailure ("second join failed: " ++ show other)
  h0 <- allocJobHandle ctx jB0
  h1 <- allocJobHandle ctx jB1
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    writeIORef armed True
    writeIORef countRef 0
    retired <- retireLiveTableFor dc (asyncTableId (acTable ctx))
    writeIORef armed False
    case retired of
      [(p0, e0), (p1, e1)] -> do
        assertEqual "first row is the first join" pid0 p0
        assertEqual "first row committed clean" Nothing e0
        assertEqual "second row is the second join" pid1 p1
        case e1 of
          Just (StoreIO _) -> pure ()
          other -> assertFailure ("second row must carry the throw, got " ++ show other)
      other -> assertFailure ("expected two rows, got " ++ show other)
    av0 <- inspectAttachment dc pid0
    assertEqual "first attachment terminal" (Just (AvTerminal JobCanceled)) av0
    av1 <- inspectAttachment dc pid1
    assertEqual "second attachment terminal" (Just (AvTerminal JobCanceled)) av1
    jobs <- loadFfiJobs throwing
    let stateOf q = [jrState r | r <- jobs, jrPersistentId r == q]
    assertEqual "first row durable canceled" [JobCanceled] (stateOf pid0)
    assertEqual "second row durable queued" [JobQueued] (stateOf pid1)
    haskokiAsyncClose pSlot
    after <- peek pSlot
    assertBool "close nulled the slot" (isNull after)
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "closed, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "close drained the handles" nLive
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live jobs" liveAfter
    assertEqual "two terminals" 2 termAfter
    assertEqual "four jobs minted" 4 nextAfter
    mStale0 <- resolveJobHandle ctx h0
    assertEqual "first handle retired" Nothing mStale0
    mStale1 <- resolveJobHandle ctx h1
    assertEqual "second handle retired" Nothing mStale1

-- Standalone ownership: close accounting, slot state and fresh reopen

-- | A null slot and a null slot pointer close silently: the counting
-- closes over a null pointer and over a null-holding slot move no
-- counter, and the one export-level close over a null-holding slot
-- returns without touching it.
caseNullClosesAreSilent :: IO ()
caseNullClosesAreSilent = do
  (counting, readCounts) <- countingAcquisition
  closeCtxSlotWith counting nullPtr
  alloca $ \pSlot -> do
    poke pSlot (castPtrToStablePtr nullPtr)
    closeCtxSlotWith counting pSlot
    after <- peek pSlot
    assertBool "null context slot unchanged" (isNull after)
  closeStoreBoxSlotWith counting nullPtr
  alloca $ \pBox -> do
    poke pBox (castPtrToStablePtr nullPtr)
    closeStoreBoxSlotWith counting pBox
    afterBox <- peek pBox
    assertBool "null box slot unchanged" (isNull afterBox)
  alloca $ \pSlot -> do
    poke pSlot (castPtrToStablePtr nullPtr)
    haskokiAsyncClose pSlot
    afterExport <- peek pSlot
    assertBool "export leaves the null slot unchanged" (isNull afterExport)
  c <- readCounts
  assertEqual "no store close" 0 (acStoreCloses c)
  assertEqual "no backend close" 0 (acBackendCloses c)
  assertEqual "no context free" 0 (acCtxFrees c)
  assertEqual "no box free" 0 (acBoxFrees c)
  assertEqual "no retirement" 0 (acRetirements c)
  assertBalanced "silent closes" c

-- | A repeated context close frees and retires once: the first of
-- three counting closes nulls the slot, and the two that follow are
-- silent no-ops.
caseRepeatedCloseFreesOnce :: IO ()
caseRepeatedCloseFreesOnce = do
  (counting, readCounts) <- countingAcquisition
  eCtx <- openAsyncCtxWith counting defaultConfig
  sp <- case eCtx of
    Right s -> pure s
    Left _ -> assertFailure "context open failed"
  ctx <- deRefStablePtr sp
  alloca $ \pSlot -> do
    poke pSlot sp
    closeCtxSlotWith counting pSlot
    after <- peek pSlot
    assertBool "first close nulled the slot" (isNull after)
    closeCtxSlotWith counting pSlot
    closeCtxSlotWith counting pSlot
    afterThird <- peek pSlot
    assertBool "slot stays nulled" (isNull afterThird)
  closeAfter <- inspectTableClose (acTable ctx)
  assertEqual "gate closed" TableClosed closeAfter
  nLive <- asyncLiveHandles ctx
  assertZero "live_handles" "no live handles" nLive
  (liveAfter, _, _) <- tableStats (acTable ctx)
  assertZero "live_jobs" "no live jobs" liveAfter
  c <- readCounts
  assertEqual "context freed once" 1 (acCtxFrees c)
  assertEqual "retired once" 1 (acRetirements c)
  assertEqual "backend closed once" 1 (acBackendCloses c)
  assertBalanced "repeated close" c

-- | A failed store close keeps the box slot until a retry succeeds:
-- with one close fault armed, the first close throws, frees no box,
-- and keeps the lock (the world still refuses a reopen); the retry
-- nulls the slot and the world reopens.
caseFailedStoreCloseKeepsBoxSlot :: IO ()
caseFailedStoreCloseKeepsBoxSlot = do
  world <- newMemoryWorld
  inj <- scriptedFaults [FaultClose]
  (tracked, opened) <- trackOpened (memoryStoreThrough world inj asyncAcquisition)
  (counting, readCounts) <- countingAcquisitionOver tracked
  (do
    eBox <- openStoreBoxWith counting nullPtr
    box <- case eBox of
      Right b -> pure b
      Left _ -> assertFailure "store box open failed"
    alloca $ \pBox -> do
      poke pBox box
      r <- try (closeStoreBoxSlotWith counting pBox) :: IO (Either SomeException ())
      case r of
        Left e -> case fromException e of
          Just (StoreIO _) -> pure ()
          _ -> assertFailure ("first close threw, but not the injected failure: " ++ show e)
        Right () -> assertFailure "first close with an armed fault returned normally"
      mid <- peek pBox
      assertBool "failed close keeps the slot" (mid == box)
      cMid <- readCounts
      assertEqual "failed close frees no box" 0 (acBoxFrees cMid)
      held <- openMemoryStore world
      case held of
        Left (StoreSecondWriter _) -> pure ()
        Left e -> assertFailure ("reopen refused, but not by the held lock: " ++ show e)
        Right st -> storeClose st >> assertFailure "reopen succeeded while the lock is held"
      closeStoreBoxSlotWith counting pBox
      after <- peek pBox
      assertBool "retry nulled the slot" (isNull after)
    c <- readCounts
    assertEqual "box freed once on the retry" 1 (acBoxFrees c)
    (refused, why) <- memoryReopenRefused world
    assertBalanced ("memory world reopen: " ++ why) c
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | A store box close killed in the lock wait keeps the box: a
-- sibling parks holding the commit lock, the forked export closer
-- parks behind it in the close wait, and after the kill the slot is
-- intact; once the sibling releases, the store still serves, the
-- retry closes, and the world reopens.
caseBoxCloseKilledInLockWaitKeepsBox :: IO ()
caseBoxCloseKilledInLockWaitKeepsBox = do
  world <- newMemoryWorld
  armed <- newIORef False
  arrived <- newEmptyMVar
  hold <- newEmptyMVar
  let inj = FaultInjector
        { fiFire = \p ->
            if p == FaultBeforeCommit
              then do
                fire <- atomicModifyIORef' armed (\on -> (False, on))
                if fire
                  then putMVar arrived () >> takeMVar hold >> pure False
                  else pure False
              else pure False
        , fiOnMasked = pure ()
        , fiOnResult = \_ -> pure ()
        }
  (tracked, opened) <- trackOpened (memoryStoreThrough world inj asyncAcquisition)
  (counting, readCounts) <- countingAcquisitionOver tracked
  (do
    eBox <- openStoreBoxWith counting nullPtr
    box <- case eBox of
      Right b -> pure b
      Left _ -> assertFailure "store box open failed"
    -- Arm only after the open: seating the home token commits
    -- through the same probe.
    writeIORef armed True
    boxStore <- sbStore <$> deRefStablePtr box
    alloca $ \pBox -> do
      poke pBox box
      sibDone <- newEmptyMVar
      _ <- forkIO $ do
        r <- try (storeCommit boxStore emptyDelta { sdPutMeta = [("sibling-hold", "1")] })
        putMVar sibDone (r :: Either SomeException CommitResult)
      closerRef <- newIORef (Nothing :: Maybe (MVar (Either SomeException ())))
      (do
        within10s "sibling parks holding the commit lock" (takeMVar arrived)
        closedDone <- newEmptyMVar
        closerTid <- mask_ $ do
          tid <- forkIO $ do
            r <- try (haskokiAsyncStoreClose pBox)
            putMVar closedDone (r :: Either SomeException ())
          writeIORef closerRef (Just closedDone)
          pure tid
        awaitBlocked BlockedOnMVar closerTid
        midSlot <- peek pBox
        assertBool "slot intact while the closer parks" (midSlot == box)
        -- The kill goes from a forked thread: the throw only
        -- queues against a parked closer, and the issuer would wedge
        -- behind an undeliverable kill instead of reaching the join.
        _ <- forkIO (killThread closerTid)
        mClosed <- timeout stormScaleBudget (takeMVar closedDone)
        case mClosed of
          Nothing -> do
            -- The release lets the parked pair unwind on its own (the
            -- sibling commits, the closer runs to its pending kill),
            -- so join both before failing: the closer must never
            -- write into the slot after its frame returns.
            putMVar hold ()
            _ <- within10s "sibling joins after release" (takeMVar sibDone)
            _ <- within10s "closer joins after release" (takeMVar closedDone)
            writeIORef closerRef Nothing
            assertFailure "kill not delivered (>300s)"
          Just (Right ()) -> writeIORef closerRef Nothing
          Just (Left e) -> do
            writeIORef closerRef Nothing
            assertFailure ("closer leaked: " ++ show e)
        killed <- peek pBox
        assertBool "slot intact after the kill" (killed == box)
        putMVar hold ()
        sibRes <- within10s "sibling joins" (takeMVar sibDone)
        case sibRes of
          Right Committed -> pure ()
          other -> assertFailure ("sibling commit failed: " ++ show other)
        -- The killed close never ran its tail: the handle still
        -- serves, which is the open-handle observation.
        eToks <- storeLoadTokens boxStore
        case eToks of
          Right _ -> pure ()
          Left e -> assertFailure ("store stopped serving after the killed close: " ++ show e)
        closeStoreBoxSlotWith counting pBox
        after <- peek pBox
        assertBool "retry nulled the slot" (isNull after)
        haskokiAsyncStoreClose pBox
        afterSecond <- peek pBox
        assertBool "slot stays nulled" (isNull afterSecond))
        `finally` (do
          _ <- tryPutMVar hold ()
          mDone <- readIORef closerRef
          case mDone of
            Nothing -> pure ()
            Just done -> do
              _ <- within10s "closer joins after release" (takeMVar done)
              pure ())
    c <- readCounts
    assertEqual "box freed once on the retry" 1 (acBoxFrees c)
    assertEqual "store closed once on the retry" 1 (acStoreCloses c)
    (refused, why) <- memoryReopenRefused world
    assertBalanced ("memory world reopen: " ++ why) c
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | A box close parked at its close step holds the box: with the
-- step armed, the forked close parks before the transfer with the
-- box still live and the slot set; a kill there keeps the slot,
-- and the retry closes and the world reopens. A tail that freed
-- before the park fails the park asserts.
caseBoxCloseStepParksBeforeTransfer :: IO ()
caseBoxCloseStepParksBeforeTransfer = do
  world <- newMemoryWorld
  arrived <- newEmptyMVar
  hold <- newEmptyMVar
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (counting, readCounts) <- countingAcquisitionOver tracked
  let parked = counting { aaCloseStep = putMVar arrived () >> takeMVar hold }
  (do
    eBox <- openStoreBoxWith counting nullPtr
    box <- case eBox of
      Right b -> pure b
      Left _ -> assertFailure "store box open failed"
    alloca $ \pBox -> do
      poke pBox box
      closedDone <- newEmptyMVar
      closerTid <- forkIO $ do
        r <- try (closeStoreBoxSlotWith parked pBox)
        putMVar closedDone (r :: Either SomeException ())
      closerRef <- newIORef (Just closedDone)
      (do
        within10s "closer parks at the close step" (takeMVar arrived)
        cPark <- readCounts
        assertEqual "box alive at the park" 0 (acBoxFrees cPark)
        midSlot <- peek pBox
        assertBool "slot set at the park" (midSlot == box)
        -- The kill goes from a forked thread: the throw only
        -- queues against a parked closer, and the issuer would wedge
        -- behind an undeliverable kill instead of reaching the join.
        _ <- forkIO (killThread closerTid)
        mClosed <- timeout stormScaleBudget (takeMVar closedDone)
        case mClosed of
          Nothing -> do
            putMVar hold ()
            _ <- within10s "closer joins after release" (takeMVar closedDone)
            writeIORef closerRef Nothing
            assertFailure "kill not delivered (>300s)"
          Just (Right ()) -> do
            writeIORef closerRef Nothing
            assertFailure "kill swallowed: close returned normally"
          Just (Left e) -> case fromException e of
            Just ThreadKilled -> writeIORef closerRef Nothing
            _ -> do
              writeIORef closerRef Nothing
              assertFailure ("closer leaked: " ++ show e)
        killed <- peek pBox
        assertBool "slot intact after the kill" (killed == box)
        cKill <- readCounts
        assertEqual "kill freed no box" 0 (acBoxFrees cKill)
        closeStoreBoxSlotWith counting pBox
        after <- peek pBox
        assertBool "retry nulled the slot" (isNull after)
        haskokiAsyncStoreClose pBox
        afterSecond <- peek pBox
        assertBool "slot stays nulled" (isNull afterSecond))
        `finally` (do
          _ <- tryPutMVar hold ()
          mDone <- readIORef closerRef
          case mDone of
            Nothing -> pure ()
            Just done -> do
              _ <- within10s "closer joins after release" (takeMVar done)
              pure ())
    c <- readCounts
    assertEqual "box freed once on the retry" 1 (acBoxFrees c)
    assertEqual "one store open" 1 (acStoreOpens c)
    -- The parked closer ran its Store close before the park, and the
    -- retry runs it again over the closed handle: two closes, one
    -- open. Every other counter balances.
    assertEqual "store closed twice across the kill" 2 (acStoreCloses c)
    let ctxt = " (" ++ show c ++ ")"
    assertZero "backend_opens_minus_closes" ("backend opens minus closes" ++ ctxt)
      (acBackendOpens c - acBackendCloses c)
    assertZero "ctx_allocs_minus_frees" ("context allocs minus frees" ++ ctxt)
      (acCtxAllocs c - acCtxFrees c)
    assertZero "box_allocs_minus_frees" ("box allocs minus frees" ++ ctxt)
      (acBoxAllocs c - acBoxFrees c)
    assertZero "registrations_minus_retirements"
      ("registrations minus retirements" ++ ctxt)
      (acRegistrations c - acRetirements c)
    (refused, why) <- memoryReopenRefused world
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | A context close parked at its close step holds the context: with
-- the step armed, the forked close parks after the drain with
-- nothing retired or freed, the slot set, and the gate closing with
-- its closer active; a kill there releases the claim without
-- teardown, and the retry retires, frees and nulls exactly once. A
-- tail that retired or freed before the park fails the park asserts.
caseCtxCloseStepParksBeforeTransfer :: IO ()
caseCtxCloseStepParksBeforeTransfer = do
  world <- newMemoryWorld
  arrived <- newEmptyMVar
  hold <- newEmptyMVar
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (counting, readCounts) <- countingAcquisitionOver tracked
  let parked = counting { aaCloseStep = putMVar arrived () >> takeMVar hold }
  (do
    eBox <- openStoreBoxWith counting nullPtr
    box <- case eBox of
      Right b -> pure b
      Left _ -> assertFailure "store box open failed"
    eCtx <- openAsyncCtxOnWith counting defaultConfig box
    sp <- case eCtx of
      Right s -> pure s
      Left _ -> assertFailure "context open failed"
    ctx <- deRefStablePtr sp
    alloca $ \pCtx -> do
      poke pCtx sp
      closedDone <- newEmptyMVar
      (closerTid, closerRef) <- mask_ $ do
        tid <- forkIO $ do
          r <- try (closeCtxSlotWith parked pCtx)
          putMVar closedDone (r :: Either SomeException ())
        ref <- newIORef (Just closedDone)
        pure (tid, ref)
      (do
        within10s "closer parks at the close step" (takeMVar arrived)
        cPark <- readCounts
        assertEqual "no retirement at the park" 0 (acRetirements cPark)
        assertEqual "no context free at the park" 0 (acCtxFrees cPark)
        midSlot <- peek pCtx
        assertBool "slot set at the park" (midSlot == sp)
        closePark <- inspectTableClose (acTable ctx)
        assertEqual "teardown started, closer active"
          (TableClosing TeardownStarted CloserActive) closePark
        -- The kill goes from a forked thread: the throw only
        -- queues against a parked closer, and the issuer would wedge
        -- behind an undeliverable kill instead of reaching the join.
        _ <- forkIO (killThread closerTid)
        mClosed <- timeout stormScaleBudget (takeMVar closedDone)
        case mClosed of
          Nothing -> do
            putMVar hold ()
            _ <- within10s "closer joins after release" (takeMVar closedDone)
            writeIORef closerRef Nothing
            assertFailure "kill not delivered (>300s)"
          Just (Right ()) -> do
            writeIORef closerRef Nothing
            assertFailure "kill swallowed: close returned normally"
          Just (Left e) -> case fromException e of
            Just ThreadKilled -> writeIORef closerRef Nothing
            _ -> do
              writeIORef closerRef Nothing
              assertFailure ("closer leaked: " ++ show e)
        killed <- peek pCtx
        assertBool "slot intact after the kill" (killed == sp)
        closeMid <- inspectTableClose (acTable ctx)
        assertEqual "teardown started, closer absent"
          (TableClosing TeardownStarted CloserAbsent) closeMid
        cKill <- readCounts
        assertEqual "kill retired nothing" 0 (acRetirements cKill)
        assertEqual "kill freed nothing" 0 (acCtxFrees cKill)
        closeCtxSlotWith counting pCtx
        after <- peek pCtx
        assertBool "retry nulled the slot" (isNull after)
        haskokiAsyncClose pCtx
        afterSecond <- peek pCtx
        assertBool "slot stays nulled" (isNull afterSecond))
        `finally` (do
          _ <- tryPutMVar hold ()
          mDone <- readIORef closerRef
          case mDone of
            Nothing -> pure ()
            Just done -> do
              _ <- within10s "closer joins after release" (takeMVar done)
              pure ())
      alloca $ \pBox -> do
        poke pBox box
        closeStoreBoxSlotWith counting pBox
        afterBox <- peek pBox
        assertBool "box slot nulled" (isNull afterBox))
    `finally` releaseOpened opened
  c <- readCounts
  assertEqual "retired once on the retry" 1 (acRetirements c)
  assertEqual "context freed once on the retry" 1 (acCtxFrees c)
  assertEqual "box freed once" 1 (acBoxFrees c)
  assertEqual "one store open" 1 (acStoreOpens c)
  assertEqual "store closed once" 1 (acStoreCloses c)
  -- The parked closer ran its backend close before the park, and the
  -- retry runs it again over the closed env: two closes, one open.
  assertEqual "one backend open" 1 (acBackendOpens c)
  assertEqual "backend closed twice across the kill" 2 (acBackendCloses c)
  let ctxt = " (" ++ show c ++ ")"
  assertZero "ctx_allocs_minus_frees" ("context allocs minus frees" ++ ctxt)
    (acCtxAllocs c - acCtxFrees c)
  assertZero "box_allocs_minus_frees" ("box allocs minus frees" ++ ctxt)
    (acBoxAllocs c - acBoxFrees c)
  assertZero "registrations_minus_retirements"
    ("registrations minus retirements" ++ ctxt)
    (acRegistrations c - acRetirements c)
  (refused, why) <- memoryReopenRefused world
  assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused

-- | An interrupted residue retry puts back every entry it has not
-- closed: two residue Stores on a private owner, a retry parked in
-- the first close, a kill there — the count stands at two — and the
-- next retry closes both and both worlds reopen. A retry that
-- dropped the put-back loses the entries and fails the count.
caseResidueRetryInterruptedPutsBack :: IO ()
caseResidueRetryInterruptedPutsBack = do
  world1 <- newMemoryWorld
  world2 <- newMemoryWorld
  armed <- newIORef True
  arrived <- newEmptyMVar
  hold <- newEmptyMVar
  owner <- newResidueOwner
  let failing world = do
        (counting, _) <- countingAcquisitionOver asyncAcquisition
          { aaOpenStore = \_ -> do
              r <- openMemoryStore world
              pure $ case r of
                Right st -> Right st
                  { storeClose = do
                      on <- readIORef armed
                      if on
                        then throwIO (StoreIO "close refused while armed")
                        else storeClose st
                  }
                Left _ -> Left ()
          , aaStep = \s ->
              if s == AfterTokenSetup then throwIO (userError "primary") else pure ()
          }
        pure counting { aaResidue = owner }
  acq1 <- failing world1
  acq2 <- failing world2
  sp1 <- haskokiAsyncStoreOpenWith acq1 nullPtr
  assertBool "first failing open reports NULL" (isNull sp1)
  sp2 <- haskokiAsyncStoreOpenWith acq2 nullPtr
  assertBool "second failing open reports NULL" (isNull sp2)
  queued <- residueCount owner
  assertEqual "two residues queued on the private owner" 2 queued
  (held1, _) <- memoryReopenRefused world1
  assertEqual "first residue keeps its lock" 1 held1
  (held2, _) <- memoryReopenRefused world2
  assertEqual "second residue keeps its lock" 1 held2
  (retryBase, _) <- countingAcquisitionOver asyncAcquisition
  let parked = retryBase
        { aaResidue = owner
        , aaCloseStore = \st -> do
            putMVar arrived ()
            takeMVar hold
            aaCloseStore retryBase st
        }
      plain = retryBase { aaResidue = owner }
  alloca $ \pNull -> do
    poke pNull (castPtrToStablePtr nullPtr)
    done <- newEmptyMVar
    tid <- forkIO $ do
      r <- try (closeCtxSlotWith parked pNull)
      putMVar done (r :: Either SomeException ())
    (do
      within10s "retrier parks in the first close" (takeMVar arrived)
      mid <- residueCount owner
      assertEqual "retry holds both entries in flight" 0 mid
      _ <- forkIO (killThread tid)
      mDone <- timeout stormScaleBudget (takeMVar done)
      case mDone of
        Nothing -> do
          putMVar hold ()
          _ <- within10s "retrier joins after release" (takeMVar done)
          assertFailure "kill not delivered (>300s)"
        Just (Right ()) ->
          assertFailure "kill swallowed: retry returned normally"
        Just (Left e) -> case fromException e of
          Just ThreadKilled -> pure ()
          _ -> assertFailure ("retrier leaked: " ++ show e)
      afterKill <- residueCount owner
      assertEqual "killed retry puts back both entries" 2 afterKill)
      `finally` (tryPutMVar hold () >> pure ())
  writeIORef armed False
  alloca $ \pNull -> do
    poke pNull (castPtrToStablePtr nullPtr)
    closeCtxSlotWith plain pNull
  left <- residueCount owner
  assertZero "residue_count" "retry closed both entries" left
  (refused1, why1) <- memoryReopenRefused world1
  assertZero "store_reopen_refused" ("first world reopen: " ++ why1) refused1
  (refused2, why2) <- memoryReopenRefused world2
  assertZero "store_reopen_refused" ("second world reopen: " ++ why2) refused2

-- | Standalone churn leaves no orphan roots or native envs: fifty
-- rounds of a box open, two contexts on it, one killed
-- third-context acquisition cycling through the on-box steps, and
-- the closes. Registrations balance retirements, allocs balance
-- frees, reclamation drains, and the gate holds no env.
caseStandaloneChurnLeavesNoOrphans :: IO ()
caseStandaloneChurnLeavesNoOrphans = withOwnGate $ \g -> do
  world <- newMemoryWorld
  (tracked, opened) <- trackOpened
    (gatedBackendSteps g (memoryStoreSteps world asyncAcquisition))
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do
    let steps = [AfterStoreReload, AfterBackendOpen, AfterSessionOpen, AfterCtxAlloc]
    mapM_ (\i -> do
      eBox <- openStoreBoxWith acq nullPtr
      box <- case eBox of
        Right b -> pure b
        Left _ -> assertFailure ("round " ++ show i ++ ": box open failed")
      eC1 <- openAsyncCtxOnWith acq defaultConfig box
      c1 <- case eC1 of
        Right s -> pure s
        Left _ -> assertFailure ("round " ++ show i ++ ": first context open failed")
      eC2 <- openAsyncCtxOnWith acq defaultConfig box
      c2 <- case eC2 of
        Right s -> pure s
        Left _ -> assertFailure ("round " ++ show i ++ ": second context open failed")
      killVictimAt (parkAt (steps !! (i `mod` length steps))) acq
        (\a -> openAsyncCtxOnWith a defaultConfig box)
      alloca $ \pCtx -> do
        poke pCtx c1
        closeCtxSlotWith acq pCtx
        afterFirst <- peek pCtx
        assertBool ("round " ++ show i ++ ": first context slot nulled") (isNull afterFirst)
      alloca $ \pCtx -> do
        poke pCtx c2
        closeCtxSlotWith acq pCtx
        afterSecond <- peek pCtx
        assertBool ("round " ++ show i ++ ": second context slot nulled") (isNull afterSecond)
      alloca $ \pBox -> do
        poke pBox box
        closeStoreBoxSlotWith acq pBox
        afterBox <- peek pBox
        assertBool ("round " ++ show i ++ ": box slot nulled") (isNull afterBox)) [0 .. 49 :: Int]
    c <- readCounts
    (refused, why) <- memoryReopenRefused world
    assertBalanced ("memory world reopen: " ++ why) c
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused
    awaitNoPendingReclaims
    awaitReclaimBalanced
    envOut <- c_ownGateEnvOutstanding g
    assertZero "env_outstanding" "native envs left on the gate" envOut
    envDf <- c_ownEnvDoublefree
    assertZero "env_doublefree" "no native double free" envDf)
    `finally` releaseOpened opened

-- | Joined cleanup lets the same store reopen: the shared
-- detach-kill-close-reopen-rejoin skeleton over a memory world. The
-- same world reopens and the detached job rejoins exactly once.
caseJoinedCleanupReopensSameStore :: IO ()
caseJoinedCleanupReopensSameStore = do
  world <- newMemoryWorld
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do
    ctx2 <- joinedCleanupReopen acq (\a -> openStoreBoxWith a nullPtr)
    nLive <- asyncLiveHandles ctx2
    assertZero "live_handles" "no live handles" nLive
    (liveAfter, _, _) <- tableStats (acTable ctx2)
    assertZero "live_jobs" "no live jobs" liveAfter
    c <- readCounts
    (refused, why) <- memoryReopenRefused world
    assertBalanced ("memory world reopen: " ++ why) c
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | Joined cleanup lets the same SQLite store reopen: the shared
-- detach-kill-close-reopen-rejoin skeleton over a SQLite path. The
-- same path reopens and the detached job rejoins exactly once.
caseJoinedCleanupReopensSameSqliteStore :: IO ()
caseJoinedCleanupReopensSameSqliteStore = withPrivateDir $ \dir -> do
  let path = dir </> "store.sqlite"
  (counting, readCounts) <- countingAcquisition
  (acq, opened) <- trackOpened counting
  (do
    ctx2 <- joinedCleanupReopen acq (\a -> withCString path (openStoreBoxWith a))
    nLive <- asyncLiveHandles ctx2
    assertZero "live_handles" "no live handles" nLive
    (liveAfter, _, _) <- tableStats (acTable ctx2)
    assertZero "live_jobs" "no live jobs" liveAfter
    c <- readCounts
    r <- openSQLiteStore path
    (refused, why) <- case r of
      Right st -> storeClose st >> pure (0 :: Int, "reopened")
      Left e -> pure (1, show e)
    assertBalanced ("sqlite reopen: " ++ why) c
    assertZero "store_reopen_refused" ("sqlite reopen: " ++ why) refused)
    `finally` releaseOpened opened
