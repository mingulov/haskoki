{- | FfiAsync Standalone: standalone acquisition and box/context kill probes
(a kill at each acquisition step).
-}
{-# LANGUAGE OverloadedStrings #-}
module FfiAsync.Standalone
  ( caseRegistryRootsReclaim
  , caseReclaimOverlappingReuse
  , caseBoxKilledAfterStoreOpen
  , caseBoxKilledAfterTokenSetup
  , caseBoxKilledDuringTokenLoad
  , caseSqliteBoxKilledAfterTokenSetup
  , caseCtxKilledAfterBackendOpen
  , caseCtxKilledAfterSessionOpen
  , caseCtxKilledAfterCtxAlloc
  , caseStoreBoundKilledAfterReload
  , caseExportResidueRecoveredByNextOpen
  , caseCloserKilledInStoreWait
  , caseCloserKilledInLeaseWait
  , caseCloserKilledInBackendGateWait
  , caseStoreFailureInRetirement
  , caseTableClosePhasesMoveOnlyForward
  ) where


import Control.Concurrent
  ( MVar
  , forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  , tryPutMVar
  )
import Control.Exception
  ( SomeException
  , finally
  , mask_
  , throwIO
  , try
  )
import Data.ByteString (ByteString)
import Data.IORef (atomicModifyIORef', newIORef, readIORef, writeIORef)
import Foreign.C.String (withCString)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (nullPtr)
import Foreign.StablePtr
  ( deRefStablePtr
  , freeStablePtr
  , newStablePtr
  )
import Foreign.Storable (peek, poke)
import GHC.Conc (BlockReason (..))
import System.FilePath ((</>))
import System.Timeout (timeout)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)

import qualified Haskoki.Engine.Backend as B
import OwnershipCounters (assertZero)
import StormBudget (stormScaleBudget)
import FfiAsync.Fixtures
import AcquisitionCounters
import Haskoki.Engine.OpenSSL4
  ( digestOneShotGated
  )
import Haskoki.FFI.Async
  ( AcquireStep (..)
  , AsyncAcquisition (..)
  , AsyncCtx (..)
  , allocJobHandle
  , asyncAcquisition
  , asyncLiveHandles
  , ctxAcquireBorrowTest
  , ctxPendingReclaims
  , ctxReleaseBorrowTest
  , closeCtxSlotWith
  , closeStoreBoxSlotWith
  , haskokiAsyncCancel
  , haskokiAsyncClose
  , haskokiAsyncStoreClose
  , haskokiAsyncStoreOpen
  , haskokiAsyncStoreOpenWith
  , openAsyncCtxOnWith
  , openAsyncCtxWith
  , openStoreBoxWith
  , registerBorrowedCtx
  , registerFixtureCtx
  , residueAnomalies
  , residueCount
  , resolveJobHandle
  , retireCtx
  , setEnterTestHook
  )
import Haskoki.Runtime.Async
  ( CancelOutcome (..)
  , Closer (..)
  , JobFunction (..)
  , TableClose (..)
  , Teardown (..)
  , TerminalState (..)
  , beginTableTeardown
  , cancelJob
  , claimTableClose
  , enterTableUse
  , finishTableClose
  , inspectTableClose
  , inspectTableGate
  , releaseTableClose
  , tableStats
  , tryNewAsyncTable
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
  )
import Haskoki.Runtime.Storage.Memory
  ( newMemoryWorld
  , openMemoryStore
  )
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)


-- | Registry roots reclaim across churn: repeated owned
-- register/retire cycles, borrowed register/retire cycles, and
-- hook replacement/clear cycles leave no reclamation backlog once
-- joined — every displaced root frees through its retire or its
-- last release instead of standing retained.
caseRegistryRootsReclaim :: IO ()
caseRegistryRootsReclaim = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  mapM_ (\_ -> do
    sp <- newStablePtr ctx
    registerFixtureCtx sp (acTable ctx)
    retireCtx sp
    freeStablePtr sp) [1 .. 50 :: Int]
  mapM_ (\_ -> do
    sp <- newStablePtr ctx
    registerBorrowedCtx sp (acTable ctx)
    retireCtx sp
    freeStablePtr sp) [1 .. 50 :: Int]
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  mapM_ (\_ -> do
    setEnterTestHook sp (Just (pure ()))
    setEnterTestHook sp Nothing) [1 .. 50 :: Int]
  retireCtx sp
  freeStablePtr sp
  awaitNoPendingReclaims
  awaitReclaimBalanced

-- | Stacked displacements preserve every root: hold one borrow,
-- retire, reuse the same key, and retire again before releasing —
-- both displaced roots queue instead of the second stranding the
-- first. The held borrow pins at least two queued roots; the
-- release drains both, and the accounting balances.
caseReclaimOverlappingReuse :: IO ()
caseReclaimOverlappingReuse = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  ctxAcquireBorrowTest sp
  retireCtx sp
  registerFixtureCtx sp (acTable ctx)
  retireCtx sp
  p <- ctxPendingReclaims
  assertBool ("two stacked roots queued, saw " ++ show p) (p >= 2)
  ctxReleaseBorrowTest sp
  freeStablePtr sp
  awaitNoPendingReclaims
  awaitReclaimBalanced

caseBoxKilledAfterStoreOpen :: IO ()
caseBoxKilledAfterStoreOpen = boxKilledMemory (parkAt AfterStoreOpen)

caseBoxKilledAfterTokenSetup :: IO ()
caseBoxKilledAfterTokenSetup = boxKilledMemory (parkAt AfterTokenSetup)

caseBoxKilledDuringTokenLoad :: IO ()
caseBoxKilledDuringTokenLoad = boxKilledMemory parkInTokenLoad

caseSqliteBoxKilledAfterTokenSetup :: IO ()
caseSqliteBoxKilledAfterTokenSetup = withPrivateDir $ \dir -> do
  let path = dir </> "store.sqlite"
  (counting, readCounts) <- countingAcquisition
  (acq, opened) <- trackOpened counting
  (do withCString path $ \cPath ->
        killVictimAt (parkAt AfterTokenSetup) acq (\a -> openStoreBoxWith a cPath)
      c <- readCounts
      r <- openSQLiteStore path
      (refused, why) <- case r of
        Right st -> storeClose st >> pure (0 :: Int, "reopened")
        Left e -> pure (1, show e)
      assertBalanced ("sqlite reopen: " ++ why) c
      assertZero "store_reopen_refused" ("sqlite reopen: " ++ why) refused)
    `finally` releaseOpened opened

caseCtxKilledAfterBackendOpen :: IO ()
caseCtxKilledAfterBackendOpen = ctxKilledGated AfterBackendOpen

caseCtxKilledAfterSessionOpen :: IO ()
caseCtxKilledAfterSessionOpen = ctxKilledGated AfterSessionOpen

caseCtxKilledAfterCtxAlloc :: IO ()
caseCtxKilledAfterCtxAlloc = ctxKilledGated AfterCtxAlloc

-- | A store-bound open killed after its reload holds nothing of its
-- own: the box stays usable for the next open, and closing both
-- balances every counter.
caseStoreBoundKilledAfterReload :: IO ()
caseStoreBoundKilledAfterReload = do
  world <- newMemoryWorld
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do eBox <- openStoreBoxWith acq nullPtr
      box <- case eBox of
        Right b -> pure b
        Left _ -> assertFailure "store box open failed"
      killVictimAt (parkAt AfterStoreReload) acq
        (\a -> openAsyncCtxOnWith a defaultConfig box)
      eCtx <- openAsyncCtxOnWith acq defaultConfig box
      ctx <- case eCtx of
        Right sp -> pure sp
        Left _ -> assertFailure "open on the same box failed"
      alloca $ \pCtx -> do
        poke pCtx ctx
        closeCtxSlotWith acq pCtx
        after <- peek pCtx
        assertBool "context slot nulled" (isNull after)
      alloca $ \pBox -> do
        poke pBox box
        closeStoreBoxSlotWith acq pBox
        after <- peek pBox
        assertBool "box slot nulled" (isNull after)
      c <- readCounts
      (refused, why) <- memoryReopenRefused world
      assertBalanced ("memory world reopen: " ++ why) c
      assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | The C export cannot hand a residue back: a synchronous primary
-- whose two cleanup closes fail reports NULL and queues the Store on
-- the process owner (the C-owned cell), which keeps its lock. The
-- next open through the real export retries the close first: the
-- count drains to zero and the world reopens.
caseExportResidueRecoveredByNextOpen :: IO ()
caseExportResidueRecoveredByNextOpen = do
  world <- newMemoryWorld
  armed <- newIORef True
  (counting, readCounts) <- countingAcquisitionOver asyncAcquisition
    { aaOpenStore = \_ -> do
        r <- openMemoryStore world
        pure $ case r of
          -- Every close fails while armed, so a concurrent drainer in
          -- this process cannot close the residue before the asserts.
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
  let processOwner = aaResidue asyncAcquisition
      acq = counting { aaResidue = processOwner }
  -- Re-enable the close on every exit, so a failure here never
  -- leaves an unclosable Store in the process cell.
  (sp, queued, held, heldWhy) <-
    (do sp <- haskokiAsyncStoreOpenWith acq nullPtr
        queued <- residueCount processOwner
        (held, heldWhy) <- memoryReopenRefused world
        pure (sp, queued, held, heldWhy))
      `finally` writeIORef armed False
  box <- haskokiAsyncStoreOpen nullPtr
  alloca $ \pBox -> do
    poke pBox box
    haskokiAsyncStoreClose pBox
  left <- awaitResidueDrained processOwner
  (refused, why) <- memoryReopenRefused world
  c <- readCounts
  let note = " (" ++ show c ++ "; queued=" ++ show queued ++ ", held: " ++ heldWhy ++ ")"
  assertBool ("export reports NULL" ++ note) (isNull sp)
  assertEqual ("residue queued on the process owner" ++ note) 1 queued
  assertEqual ("the residue keeps its lock" ++ note) 1 held
  assertBool ("the next open through the real export" ++ note) (not (isNull box))
  assertZero "residue_count" ("residue left after the next open" ++ note) left
  assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused
  assertZero "box_allocs_minus_frees" ("box allocs minus frees" ++ note)
    (acBoxAllocs c - acBoxFrees c)
  assertZero "registrations_minus_retirements"
    ("registrations minus retirements" ++ note)
    (acRegistrations c - acRetirements c)
  anomalies <- residueAnomalies
  assertZero "residue_anomalies" "process residue cell protocol slips" anomalies

-- Standalone ownership: a closer killed past the borrower drain
--
-- Common shape: a registered context with zero borrowers, a sibling
-- holding one resource the drain needs, and a forked export close
-- that parks in the resulting wait. A second close while the first
-- is parked returns at once with the gate unchanged. Main kills the
-- first closer and joins it under the storm-scale budget; afterwards the gate
-- still reports closing with no borrowers, a call through the slot
-- refuses, and releasing the sibling plus a retry completes the
-- close exactly once. When the kill is not delivered, the test
-- releases the sibling and joins it before failing, so the suite
-- never wedges behind the parked pair.

-- | A closer killed while the drain waits on the Store lock stays
-- closing and a retry completes: the sibling commits a meta key
-- through an injector that parks once with the commit lock held,
-- the closer parks in retirement behind it, and after the kill and
-- the release the retry retires the joined attachment, cancels its
-- job, closes the backend once and nulls the slot.
caseCloserKilledInStoreWait :: IO ()
caseCloserKilledInStoreWait = do
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
  (_, store) <- mkFfiStoreWith inj
  dc <- mkFfiDetached store
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
  (counting, readCounts) <- countingAcquisition
  -- Arm only after setup: detach reserves through the same probe.
  writeIORef armed True
  alloca $ \pSlot -> do
    poke pSlot sp
    sibDone <- newEmptyMVar
    _ <- forkIO $ do
      r <- try (storeCommit store emptyDelta { sdPutMeta = [("sibling-hold", "1")] })
      putMVar sibDone (r :: Either SomeException CommitResult)
    closerRef <- newIORef (Nothing :: Maybe (MVar (Either SomeException ())))
    (do
      within10s "sibling parks holding the commit lock" (takeMVar arrived)
      closedDone <- newEmptyMVar
      closerTid <- mask_ $ do
        tid <- forkIO $ do
          r <- try (haskokiAsyncClose pSlot)
          putMVar closedDone (r :: Either SomeException ())
        writeIORef closerRef (Just closedDone)
        pure tid
      awaitBlocked BlockedOnMVar closerTid
      gateBefore <- inspectTableGate (acTable ctx)
      assertEqual "first closer holds the claim" (0, True) gateBefore
      closeBefore <- inspectTableClose (acTable ctx)
      assertEqual "first closer started teardown"
        (TableClosing TeardownStarted CloserActive) closeBefore
      within10s "second closer returns" (closeCtxSlotWith asyncAcquisition pSlot)
      gateAfterSecond <- inspectTableGate (acTable ctx)
      assertEqual "second closer changes nothing" gateBefore gateAfterSecond
      closeAfterSecond <- inspectTableClose (acTable ctx)
      assertEqual "second closer leaves the phase" closeBefore closeAfterSecond
      midSlot <- peek pSlot
      assertBool "slot still set" (not (isNull midSlot))
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
      gateMid <- inspectTableGate (acTable ctx)
      assertEqual "stays closing with no closer" (0, True) gateMid
      closeMid <- inspectTableClose (acTable ctx)
      assertEqual "teardown started, closer absent"
        (TableClosing TeardownStarted CloserAbsent) closeMid
      midSlot2 <- peek pSlot
      assertBool "slot still set after the kill" (not (isNull midSlot2))
      rvRefused <- haskokiAsyncCancel sp nullJob
      assertEqual "call through the closing slot refuses" rvGeneral rvRefused
      (liveMid, _, _) <- tableStats (acTable ctx)
      assertEqual "retirement never ran" 1 liveMid
      avMid <- inspectAttachment dc pid
      assertEqual "attachment still active" (Just (AvActive jB)) avMid
      putMVar hold ()
      sibRes <- within10s "sibling joins" (takeMVar sibDone)
      case sibRes of
        Right Committed -> pure ()
        other -> assertFailure ("sibling commit failed: " ++ show other)
      closeCtxSlotWith counting pSlot
      after <- peek pSlot
      assertBool "retry nulled the slot" (isNull after)
      gateAfter <- inspectTableGate (acTable ctx)
      assertEqual "closed, no borrowers" (0, True) gateAfter
      av <- inspectAttachment dc pid
      assertEqual "attachment terminal" (Just (AvTerminal JobCanceled)) av
      jobs <- loadFfiJobs store
      assertEqual "one durable row" 1 (length jobs)
      case [r | r <- jobs, jrPersistentId r == pid] of
        [rec] -> assertEqual "record canceled" JobCanceled (jrState rec)
        other -> assertFailure ("expected one record, got " ++ show other)
      nLive <- asyncLiveHandles ctx
      assertZero "live_handles" "retry drained the handle" nLive
      (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
      assertZero "live_jobs" "no live jobs" liveAfter
      assertEqual "one terminal job" 1 termAfter
      assertEqual "two jobs minted" 2 nextAfter
      c <- readCounts
      assertEqual "backend closed once on the retry" 1 (acBackendCloses c)
      assertEqual "retired once on the retry" 1 (acRetirements c)
      assertEqual "context freed once on the retry" 1 (acCtxFrees c)
      mStale <- resolveJobHandle ctx h
      assertEqual "handle retired" Nothing mStale
      cout <- cancelJob (acTable ctx) jB
      case cout of
        CancelAlready TermCanceled -> pure ()
        other -> assertFailure ("job not canceled, got " ++ show other)
      haskokiAsyncClose pSlot
      after2 <- peek pSlot
      assertBool "slot stays nulled" (isNull after2))
      `finally` (do
        _ <- tryPutMVar hold ()
        mDone <- readIORef closerRef
        case mDone of
          Nothing -> pure ()
          Just done -> do
            _ <- within10s "closer joins after release" (takeMVar done)
            pure ())

-- | A closer killed while the drain waits on a job lease cancels
-- exactly once on retry: the sibling holds a detach lease on the
-- one live job, the closer parks in the cancel behind it, and after
-- the kill and the release the retry cancels the job, drains its
-- handle and nulls the slot.
caseCloserKilledInLeaseWait :: IO ()
caseCloserKilledInLeaseWait = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  h <- allocJobHandle ctx j0
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  (counting, readCounts) <- countingAcquisition
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  alloca $ \pSlot -> do
    poke pSlot sp
    sibDone <- newEmptyMVar
    _ <- forkIO $ do
      r <- try (withDetachLease (acTable ctx) j0
        (\_ -> putMVar entered () >> takeMVar proceed))
      putMVar sibDone (r :: Either SomeException ())
    closerRef <- newIORef (Nothing :: Maybe (MVar (Either SomeException ())))
    (do
      within10s "sibling takes the lease" (takeMVar entered)
      closedDone <- newEmptyMVar
      closerTid <- mask_ $ do
        tid <- forkIO $ do
          r <- try (haskokiAsyncClose pSlot)
          putMVar closedDone (r :: Either SomeException ())
        writeIORef closerRef (Just closedDone)
        pure tid
      awaitBlocked BlockedOnMVar closerTid
      gateBefore <- inspectTableGate (acTable ctx)
      assertEqual "first closer holds the claim" (0, True) gateBefore
      closeBefore <- inspectTableClose (acTable ctx)
      assertEqual "first closer started teardown"
        (TableClosing TeardownStarted CloserActive) closeBefore
      within10s "second closer returns" (closeCtxSlotWith asyncAcquisition pSlot)
      gateAfterSecond <- inspectTableGate (acTable ctx)
      assertEqual "second closer changes nothing" gateBefore gateAfterSecond
      closeAfterSecond <- inspectTableClose (acTable ctx)
      assertEqual "second closer leaves the phase" closeBefore closeAfterSecond
      midSlot <- peek pSlot
      assertBool "slot still set" (not (isNull midSlot))
      -- The kill goes from a forked thread: the throw only
      -- queues against a parked closer, and the issuer would wedge
      -- behind an undeliverable kill instead of reaching the join.
      _ <- forkIO (killThread closerTid)
      mClosed <- timeout stormScaleBudget (takeMVar closedDone)
      case mClosed of
        Nothing -> do
          putMVar proceed ()
          _ <- within10s "sibling joins after release" (takeMVar sibDone)
          _ <- within10s "closer joins after release" (takeMVar closedDone)
          writeIORef closerRef Nothing
          assertFailure "kill not delivered (>300s)"
        Just (Right ()) -> writeIORef closerRef Nothing
        Just (Left e) -> do
          writeIORef closerRef Nothing
          assertFailure ("closer leaked: " ++ show e)
      gateMid <- inspectTableGate (acTable ctx)
      assertEqual "stays closing with no closer" (0, True) gateMid
      closeMid <- inspectTableClose (acTable ctx)
      assertEqual "teardown started, closer absent"
        (TableClosing TeardownStarted CloserAbsent) closeMid
      midSlot2 <- peek pSlot
      assertBool "slot still set after the kill" (not (isNull midSlot2))
      rvRefused <- haskokiAsyncCancel sp nullJob
      assertEqual "call through the closing slot refuses" rvGeneral rvRefused
      (liveMid, _, _) <- tableStats (acTable ctx)
      assertEqual "the cancel never ran" 1 liveMid
      nLiveMid <- asyncLiveHandles ctx
      assertEqual "the handle is still live" 1 nLiveMid
      putMVar proceed ()
      sibRes <- within10s "sibling joins" (takeMVar sibDone)
      case sibRes of
        Right () -> pure ()
        Left e -> assertFailure ("sibling failed: " ++ show e)
      closeCtxSlotWith counting pSlot
      after <- peek pSlot
      assertBool "retry nulled the slot" (isNull after)
      gateAfter <- inspectTableGate (acTable ctx)
      assertEqual "closed, no borrowers" (0, True) gateAfter
      nLive <- asyncLiveHandles ctx
      assertZero "live_handles" "retry drained the handle" nLive
      (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
      assertZero "live_jobs" "no live jobs" liveAfter
      assertEqual "one terminal job" 1 termAfter
      assertEqual "one job minted" 1 nextAfter
      c <- readCounts
      assertEqual "backend closed once on the retry" 1 (acBackendCloses c)
      assertEqual "retired once on the retry" 1 (acRetirements c)
      assertEqual "context freed once on the retry" 1 (acCtxFrees c)
      mStale <- resolveJobHandle ctx h
      assertEqual "handle retired" Nothing mStale
      cout <- cancelJob (acTable ctx) j0
      case cout of
        CancelAlready TermCanceled -> pure ()
        other -> assertFailure ("job not canceled, got " ++ show other)
      haskokiAsyncClose pSlot
      after2 <- peek pSlot
      assertBool "slot stays nulled" (isNull after2))
      `finally` (do
        _ <- tryPutMVar proceed ()
        mDone <- readIORef closerRef
        case mDone of
          Nothing -> pure ()
          Just done -> do
            _ <- within10s "closer joins after release" (takeMVar done)
            pure ())

-- | A closer killed while the drain waits on the backend gate frees
-- the native env exactly once on retry: the sibling parks a gated
-- digest in its checkpoint holding the env gate, the closer parks
-- in the backend close behind it, and after the kill and a
-- proceed-verdict release the retry closes the backend, which
-- destroys the one env with no double free.
caseCloserKilledInBackendGateWait :: IO ()
caseCloserKilledInBackendGateWait = withOwnGate $ \g -> do
  (tracked, opened) <- trackOpened (gatedBackendSteps g asyncAcquisition)
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do
    eCtx <- openAsyncCtxWith acq defaultConfig
    sp <- case eCtx of
      Right s -> pure s
      Left _ -> assertFailure "context open failed"
    ctx <- deRefStablePtr sp
    c_ownGateArmCheckpoint g 2
    alloca $ \pSlot -> do
      poke pSlot sp
      sibDone <- newEmptyMVar
      _ <- forkIO $ do
        r <- try (digestOneShotGated g (acBackend ctx) B.D_SHA256 "hello")
        putMVar sibDone (r :: Either SomeException (B.EngineResult ByteString))
      closerRef <- newIORef (Nothing :: Maybe (MVar (Either SomeException ())))
      (do
        awaitOwnParked g
        closedDone <- newEmptyMVar
        closerTid <- mask_ $ do
          tid <- forkIO $ do
            r <- try (haskokiAsyncClose pSlot)
            putMVar closedDone (r :: Either SomeException ())
          writeIORef closerRef (Just closedDone)
          pure tid
        awaitBlocked BlockedOnMVar closerTid
        gateBefore <- inspectTableGate (acTable ctx)
        assertEqual "first closer holds the claim" (0, True) gateBefore
        closeBefore <- inspectTableClose (acTable ctx)
        assertEqual "first closer started teardown"
          (TableClosing TeardownStarted CloserActive) closeBefore
        within10s "second closer returns" (closeCtxSlotWith asyncAcquisition pSlot)
        gateAfterSecond <- inspectTableGate (acTable ctx)
        assertEqual "second closer changes nothing" gateBefore gateAfterSecond
        closeAfterSecond <- inspectTableClose (acTable ctx)
        assertEqual "second closer leaves the phase" closeBefore closeAfterSecond
        midSlot <- peek pSlot
        assertBool "slot still set" (not (isNull midSlot))
        -- The kill goes from a forked thread: the throw only
        -- queues against a parked closer, and the issuer would wedge
        -- behind an undeliverable kill instead of reaching the join.
        _ <- forkIO (killThread closerTid)
        mClosed <- timeout stormScaleBudget (takeMVar closedDone)
        case mClosed of
          Nothing -> do
            c_ownGateRelease g 0
            _ <- within10s "sibling joins after release" (takeMVar sibDone)
            _ <- within10s "closer joins after release" (takeMVar closedDone)
            writeIORef closerRef Nothing
            assertFailure "kill not delivered (>300s)"
          Just (Right ()) -> writeIORef closerRef Nothing
          Just (Left e) -> do
            writeIORef closerRef Nothing
            assertFailure ("closer leaked: " ++ show e)
        gateMid <- inspectTableGate (acTable ctx)
        assertEqual "stays closing with no closer" (0, True) gateMid
        closeMid <- inspectTableClose (acTable ctx)
        assertEqual "teardown started, closer absent"
          (TableClosing TeardownStarted CloserAbsent) closeMid
        midSlot2 <- peek pSlot
        assertBool "slot still set after the kill" (not (isNull midSlot2))
        rvRefused <- haskokiAsyncCancel sp nullJob
        assertEqual "call through the closing slot refuses" rvGeneral rvRefused
        envMid <- c_ownGateEnvOutstanding g
        assertEqual "the backend close never ran" 1 envMid
        c_ownGateRelease g 0
        sibRes <- within10s "sibling joins" (takeMVar sibDone)
        case sibRes of
          Right (B.EngineOk _) -> pure ()
          other -> assertFailure ("sibling digest failed: " ++ show other)
        closeCtxSlotWith acq pSlot
        after <- peek pSlot
        assertBool "retry nulled the slot" (isNull after)
        gateAfter <- inspectTableGate (acTable ctx)
        assertEqual "closed, no borrowers" (0, True) gateAfter
        envOut <- c_ownGateEnvOutstanding g
        assertZero "env_outstanding" "native env freed once" envOut
        envDf <- c_ownEnvDoublefree
        assertZero "env_doublefree" "no native double free" envDf
        nLive <- asyncLiveHandles ctx
        assertZero "live_handles" "no live handles" nLive
        (liveAfter, _, _) <- tableStats (acTable ctx)
        assertZero "live_jobs" "no live jobs" liveAfter
        c <- readCounts
        assertBalanced "backend gate retry" c
        haskokiAsyncClose pSlot
        after2 <- peek pSlot
        assertBool "slot stays nulled" (isNull after2))
        `finally` (do
          c_ownGateRelease g 0
          mDone <- readIORef closerRef
          case mDone of
            Nothing -> pure ()
            Just done -> do
              _ <- within10s "closer joins after release" (takeMVar done)
              pure ()))
    `finally` releaseOpened opened

-- | A Store failure during retirement still closes and keeps the
-- record joinable: the detach view sits over a Store whose job load
-- fails, so retirement marks the joined attachment terminal in
-- memory while the durable row stands untouched. The close
-- completes; then a fresh box and context over the same world
-- rejoin the job exactly once.
caseStoreFailureInRetirement :: IO ()
caseStoreFailureInRetirement = do
  (world, plain) <- mkFfiStoreWith noFaults
  armed <- newIORef False
  let failing = plain
        { storeLoadJobs = do
            on <- readIORef armed
            if on
              then pure (Left (StoreIO "injected load failure"))
              else storeLoadJobs plain
        }
  dc <- mkFfiDetached failing
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
    jobs <- loadFfiJobs failing
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
  storeClose failing
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

-- | Table close phases move only forward after teardown starts: a
-- claim released before teardown reopens the gate, while a claim
-- released past teardown begin stays closing without a closer —
-- never back to open. Entry refuses once closing, a retrying claim
-- resumes, a racing second claim loses, teardown begin is
-- idempotent, and finish closes for good.
caseTableClosePhasesMoveOnlyForward :: IO ()
caseTableClosePhasesMoveOnlyForward = do
  mTable <- tryNewAsyncTable 8
  table <- case mTable of
    Just t -> pure t
    Nothing -> assertFailure "table allocator refused"
  opened <- inspectTableClose table
  assertEqual "gate fresh" TableOpen opened
  first <- claimTableClose table
  assertBool "first claim wins" first
  releaseTableClose table
  reopened <- inspectTableClose table
  assertEqual "release before teardown reopens" TableOpen reopened
  claimed <- claimTableClose table
  assertBool "claim wins again" claimed
  began <- beginTableTeardown table
  assertBool "teardown begins" began
  releaseTableClose table
  closing <- inspectTableClose table
  assertEqual "release past teardown stays closing"
    (TableClosing TeardownStarted CloserAbsent) closing
  admitted <- enterTableUse table
  assertBool "entry refuses once closing" (not admitted)
  resumed <- claimTableClose table
  assertBool "retrying claim resumes" resumed
  racing <- claimTableClose table
  assertBool "racing second claim loses" (not racing)
  beganAgain <- beginTableTeardown table
  assertBool "teardown begin is idempotent" beganAgain
  resumedState <- inspectTableClose table
  assertEqual "idempotent begin changes nothing"
    (TableClosing TeardownStarted CloserActive) resumedState
  finishTableClose table
  closed <- inspectTableClose table
  assertEqual "finish closes" TableClosed closed
  afterClose <- claimTableClose table
  assertBool "claim after close loses" (not afterClose)
  (liveAfter, _, _) <- tableStats table
  assertZero "live_jobs" "no live jobs" liveAfter
