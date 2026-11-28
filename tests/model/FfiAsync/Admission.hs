{- | FfiAsync Admission: admission, borrowed views and entry/close races.
-}
{-# LANGUAGE OverloadedStrings #-}
module FfiAsync.Admission
  ( caseCloseOneKeepsOther
  , caseCloseWaitsForEntered
  , caseAdmittedCallsRun
  , caseEnterCloseRace
  , caseBorrowedStart
  , caseOwnedToBorrowedReuse
  , caseEnterBarrierCloseTombstones
  , caseRetireClearsHook
  , caseSessionCloseDefersViewFree
  , caseInstanceCloseDefersViewFree
  , caseOpenRollbackDefersViewFree
  ) where


import Control.Concurrent
  ( forkIO
  , newEmptyMVar
  , putMVar
  , takeMVar
  , tryTakeMVar
  )
import Control.Exception
  ( SomeException
  , bracket
  , bracket_
  , finally
  , try
  )
import qualified Data.ByteString as BS
import Data.IORef (modifyIORef', newIORef, readIORef, writeIORef)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (castPtr, nullFunPtr, nullPtr)
import Foreign.StablePtr
  ( StablePtr
  , castStablePtrToPtr
  , freeStablePtr
  , newStablePtr
  )
import Foreign.Storable (peek, poke)
import GHC.Conc (BlockReason (..))
import System.Timeout (timeout)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)

import OwnershipCounters (assertZero)
import FfiAsync.Fixtures
import Haskoki.FFI.Async
  ( AsyncAcquisition (..)
  , AsyncCtx (..)
  , allocJobHandle
  , asyncAcquisition
  , asyncCloseCtx
  , asyncLiveHandles
  , ctxAcquireBorrowTest
  , ctxInspectEntryTest
  , ctxReleaseBorrowTest
  , closeCtxSlotWith
  , haskokiAsyncCancel
  , haskokiAsyncClose
  , haskokiAsyncJoin
  , haskokiAsyncStart
  , registerBorrowedCtx
  , registerFixtureCtx
  , resolveJobHandle
  , retireCtx
  , setEnterTestHook
  )
import Haskoki.FFI.Standard
  ( SessionOpenPoint (..)
  , haskokiStdClose
  , haskokiStdCloseSession
  , haskokiStdOpenSessionWithNotifyWithKey
  , openStdInstance
  , stdRvOf
  )
import Haskoki.Runtime.Async
  ( CompleteOutcome (..)
  , Completion (..)
  , Delivery (..)
  , JobFunction (..)
  , PollOutcome (..)
  , asyncTableId
  , asyncTableSalt
  , inspectTableGate
  , pollJob
  , tableStats
  )
import Haskoki.Runtime.Config
  ( defaultConfig
  )
import Haskoki.Runtime.Detached
  ( AttachmentView (..)
  , DetachOutcome (..)
  , JoinOutcome (..)
  , JoinRequest (..)
  , JoinedComplete (..)
  , completeJoined
  , detachJob
  , inspectAttachment
  , inspectReverse
  , joinJob
  , setJoinTestHook
  )
import Haskoki.Runtime.Storage
  ( JobExecState (..)
  , JobRecord (..)
  )
import Haskoki.Types
  ( JobId (..)
  , ReturnCode ( CKR_GENERAL_ERROR, CKR_OK)
  , SessionId (..)
  )


-- | Close-one/keep-other through the private FFI surface: two
-- hand-built store-bound contexts share one detach context; A
-- detaches, B joins with a live native handle, A closes — and
-- B's attachment, handle, reverse entry, and delivery all
-- survive. Closing B afterwards drains exactly its own state.
caseCloseOneKeepsOther :: IO ()
caseCloseOneKeepsOther = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctxA <- mkFfiGen dc
  ctxB <- mkFfiGen dc
  let tidA = asyncTableId (acTable ctxA)
      tidB = asyncTableId (acTable ctxB)
  assertBool "table identities distinct" (tidA /= tidB)
  let saltA = asyncTableSalt (acTable ctxA)
      saltB = asyncTableSalt (acTable ctxB)
  assertBool "salts nonzero" (saltA /= 0 && saltB /= 0)
  assertBool "table salts distinct" (saltA /= saltB)
  -- A starts and detaches; both contexts allocate from job zero.
  jA0 <- startFfiDigest ctxA "abc" 32 1
  assertEqual "A starts at zero" (JobId 0) jA0
  eDet <- detachJob dc (acTable ctxA) jA0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  -- B joins: its first live job is job zero too.
  eJoin <- joinJob dc (acEnv ctxB) (acTable ctxB) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = acSession ctxB
    , jqCapacity = 32
    }
  jB <- case eJoin of
    JoinOk j -> pure j
    other -> assertFailure ("join failed: " ++ show other)
  assertEqual "B joins at zero" (JobId 0) jB
  hB <- allocJobHandle ctxB jB
  mB0 <- resolveJobHandle ctxB hB
  assertEqual "B handle resolves" (Just jB) mB0
  -- Exactness pin at the store-bound level: both contexts hold
  -- numeric job zero under distinct exact salts, so B's handle
  -- must stay stale on A while live on B. The companion admission
  -- on A is registry only (the live set never consults table
  -- liveness), admitted solely to pin token distinctness across
  -- the equal job ids.
  mCross <- resolveJobHandle ctxA hB
  assertEqual "B handle stale on A" Nothing mCross
  hA <- allocJobHandle ctxA jA0
  assertBool "equal job ids admit distinct tokens"
    (castStablePtrToPtr hA /= castStablePtrToPtr hB)
  mA0 <- resolveJobHandle ctxA hA
  assertEqual "A handle resolves" (Just jA0) mA0
  nLiveB0 <- asyncLiveHandles ctxB
  assertEqual "B one live handle" 1 nLiveB0
  revB <- inspectReverse dc tidB jB
  assertEqual "B reverse resolves" (Just pid) revB
  av0 <- inspectAttachment dc pid
  assertEqual "B active" (Just (AvActive jB)) av0
  -- Close A: B keeps everything.
  asyncCloseCtx ctxA
  nLiveA <- asyncLiveHandles ctxA
  assertZero "live_handles" "A drained" nLiveA
  av1 <- inspectAttachment dc pid
  assertEqual "B still active after A closed" (Just (AvActive jB)) av1
  mB1 <- resolveJobHandle ctxB hB
  assertEqual "B handle survives" (Just jB) mB1
  nLiveB1 <- asyncLiveHandles ctxB
  assertEqual "B live set intact" 1 nLiveB1
  -- B drives and delivers exactly once.
  runs <- newIORef 0
  p <- pollJob (countingRunner runs) (acEnv ctxB) (acTable ctxB) JobDigest jB
  assertEqual "B ready" PollReady p
  writes <- newIORef []
  needed <- newIORef []
  let del = Delivery
        { dCapacity = 32
        , dWrite = \bs -> modifyIORef' writes (++ [bs])
        , dReportNeeded = \n -> modifyIORef' needed (++ [n])
        }
  jc <- completeJoined dc (acEnv ctxB) (acTable ctxB) JobDigest jB del (\_ -> pure ())
  assertEqual "B mark clean" Nothing (jcMarkError jc)
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "B bytes" cannedFfiDigest bs
    other -> assertFailure ("expected B delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "B one write" 1 (length got)
  nNeed <- readIORef needed
  assertEqual "no sizing reports" [] nNeed
  nRuns <- readIORef runs
  assertEqual "B one engine run" 1 nRuns
  jobs <- loadFfiJobs store
  case [r | r <- jobs, jrPersistentId r == pid] of
    [rec] -> assertEqual "record delivered" JobDelivered (jrState rec)
    other -> assertFailure ("expected one record, got " ++ show other)
  -- Close B: its handle drains; the delivered attachment stands.
  asyncCloseCtx ctxB
  nLiveB2 <- asyncLiveHandles ctxB
  assertZero "live_handles" "B drained" nLiveB2
  av2 <- inspectAttachment dc pid
  assertEqual "B delivered terminal" (Just (AvTerminal JobDelivered)) av2

-- Close admission (borrowers drain before teardown)


-- | Close waits for an entered caller: a join admitted through
-- the export parks in the join-transfer window with its borrower
-- held, a racing close provably blocks on the gate, and only
-- after the release does the join complete and the close drain
-- its just-published handle. Afterwards the gate stands retired
-- with no borrowers, the committed join retired canceled, and
-- the slot stays nulled across a second close. Pre-fix the
-- closer never waited: it tore the context down while the
-- joiner was still inside.
caseCloseWaitsForEntered :: IO ()
caseCloseWaitsForEntered = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  eDet <- detachJob dc (acTable ctx) j0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  done <- newEmptyMVar
  setJoinTestHook dc (putMVar entered () >> takeMVar proceed)
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  let sess = CULong (fromIntegral (unSessionId (acSession ctx)))
  _ <- forkIO $ do
    r <- try $ alloca $ \pHandleOut -> alloca $ \pNeedOut -> do
      poke pHandleOut nullJob
      haskokiAsyncJoin sp (CULong pid) 2 sess 32 pHandleOut pNeedOut
    putMVar done (r :: Either SomeException CULong)
  mEntered <- timeout 10000000 (takeMVar entered)
  case mEntered of
    Nothing -> assertFailure "joiner never entered the transfer window"
    Just () -> pure ()
  gateMid <- inspectTableGate (acTable ctx)
  assertEqual "one borrower, not retired" (1, False) gateMid
  alloca $ \pSlot -> do
    poke pSlot sp
    closedDone <- newEmptyMVar
    closerTid <- forkIO $ do
      r <- try (haskokiAsyncClose pSlot)
      putMVar closedDone (r :: Either SomeException ())
    awaitBlocked BlockedOnSTM closerTid
    preRel <- tryTakeMVar closedDone
    case preRel of
      Nothing -> pure ()
      Just _ -> assertFailure "close finished before release (drain ran without the gate)"
    putMVar proceed ()
    mDone <- timeout 10000000 (takeMVar done)
    jr <- case mDone of
      Nothing -> assertFailure "joiner never reported after release"
      Just x -> pure x
    case jr of
      Right rv -> assertEqual "join completed through the wait" rvPending rv
      Left e -> assertFailure ("joiner failed: " ++ show e)
    mClosed <- timeout 10000000 (takeMVar closedDone)
    case mClosed of
      Nothing -> assertFailure "closer never reported after release"
      Just (Right ()) -> pure ()
      Just (Left e) -> assertFailure ("closer failed: " ++ show e)
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "retired, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "close drained the published handle" nLive
    av <- inspectAttachment dc pid
    assertEqual "committed join retired canceled" (Just (AvTerminal JobCanceled)) av
    jobs <- loadFfiJobs store
    case [r | r <- jobs, jrPersistentId r == pid] of
      [rec] -> assertEqual "record canceled" JobCanceled (jrState rec)
      other -> assertFailure ("expected one record, got " ++ show other)
    after <- peek pSlot
    assertBool "slot nulled" (castStablePtrToPtr after == nullPtr)
    haskokiAsyncClose pSlot
    after2 <- peek pSlot
    assertBool "slot stays nulled" (castStablePtrToPtr after2 == nullPtr)

-- | Admitted calls run normally through the gate, and close
-- retires it: start admits and publishes, cancel retires, the
-- value-level close claims and drains, and a later entry through
-- the still-valid pointer is refused without allocating
-- anything. The refused start proves the gate (not the slot
-- nulling) refuses it: the pointer was never freed.
caseAdmittedCallsRun :: IO ()
caseAdmittedCallsRun = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  let sess = CULong (fromIntegral (unSessionId (acSession ctx)))
      startOn pHandleOut = BS.useAsCString "abc" $ \p ->
        haskokiAsyncStart sp sess 2 (castPtr p) 3 32 1 pHandleOut
  gate0 <- inspectTableGate (acTable ctx)
  assertEqual "gate fresh" (0, False) gate0
  h <- alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- startOn pHandleOut
    assertEqual "start pending" rvPending rv
    hOut <- peek pHandleOut
    assertBool "handle live" (castStablePtrToPtr hOut /= nullPtr)
    pure hOut
  m0 <- resolveJobHandle ctx h
  assertEqual "handle resolves" (Just (JobId 0)) m0
  gate1 <- inspectTableGate (acTable ctx)
  assertEqual "borrower released" (0, False) gate1
  rvCancel <- haskokiAsyncCancel sp h
  assertEqual "cancel ok" rvOK rvCancel
  m1 <- resolveJobHandle ctx h
  assertEqual "handle retired" Nothing m1
  (live1, term1, next1) <- tableStats (acTable ctx)
  assertEqual "job canceled" (0, 1, 1) (live1, term1, next1)
  asyncCloseCtx ctx
  gate2 <- inspectTableGate (acTable ctx)
  assertEqual "close claimed" (0, True) gate2
  nLive <- asyncLiveHandles ctx
  assertZero "live_handles" "drained" nLive
  hAfter <- alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- startOn pHandleOut
    assertEqual "post-close start refused" rvGeneral rv
    peek pHandleOut
  assertBool "no handle on refusal" (castStablePtrToPtr hAfter == nullPtr)
  (live2, term2, next2) <- tableStats (acTable ctx)
  assertEqual "refusal allocated nothing" (0, 1, 1) (live2, term2, next2)
  retireCtx sp
  freeStablePtr sp

-- | Concurrent entry races a slot-close cleanly: four workers
-- admit and release through the export while the owner closes
-- underneath them. Admission runs before any dereference, so no
-- worker can observe a freed pointer — every call either admits
-- (typed handle refusal) or refuses at the retired gate, and the
-- close still completes teardown exactly once. Before
-- pre-dereference admission, a worker between its null check and
-- its dereference could resume after the close freed the
-- pointer.
caseEnterCloseRace :: IO ()
caseEnterCloseRace = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    entered <- newEmptyMVar
    dones <- mapM (const newEmptyMVar) [1 .. 4 :: Int]
    let racer done = forkIO $ do
          r <- try $ do
            putMVar entered ()
            mapM_ (const (probeOnce sp)) [1 .. 200 :: Int]
          putMVar done (r :: Either SomeException ())
    mapM_ racer dones
    mapM_ (const (takeMVar entered)) [1 .. 4 :: Int]
    haskokiAsyncClose pSlot
    outs <- mapM (timeout 10000000 . takeMVar) dones
    case sequence outs of
      Nothing -> assertFailure "racer wedged past its backstop"
      Just rs -> mapM_ checkOk rs
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "retired, no borrowers" (0, True) gateAfter
    after <- peek pSlot
    assertBool "slot nulled" (isNull after)
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "no live handles" nLive
  where
    probeOnce :: StablePtr AsyncCtx -> IO ()
    probeOnce sp = do
      rv <- haskokiAsyncCancel sp nullJob
      if rv == rvBad || rv == rvGeneral
        then pure ()
        else assertFailure ("untyped race outcome: " ++ show rv)
    checkOk :: Either SomeException () -> IO ()
    checkOk (Right ()) = pure ()
    checkOk (Left e) = assertFailure ("racer failed: " ++ show e)

-- | Borrowed-view contract: a borrowed view registers admit-only at
-- creation (the Standard surface assembles one view per session and
-- retires it at session close, outside this module's ownership).
-- Start admits and publishes, cancel retires, and closing through
-- the slot reclaims the slot while tearing nothing down — the view
-- stays registered and admittable. The value-level close claims and
-- drains, and release retires the registration.
caseBorrowedStart :: IO ()
caseBorrowedStart = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerBorrowedCtx sp (acTable ctx)
  let sess = CULong (fromIntegral (unSessionId (acSession ctx)))
  h <- alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- BS.useAsCString "abc" $ \p ->
      haskokiAsyncStart sp sess 2 (castPtr p) 3 32 1 pHandleOut
    assertEqual "borrowed start pending" rvPending rv
    hOut <- peek pHandleOut
    assertBool "handle live" (castStablePtrToPtr hOut /= nullPtr)
    pure hOut
  gate1 <- inspectTableGate (acTable ctx)
  assertEqual "borrower released" (0, False) gate1
  rvCancel <- haskokiAsyncCancel sp h
  assertEqual "borrowed cancel ok" rvOK rvCancel
  alloca $ \pSlot -> do
    poke pSlot sp
    haskokiAsyncClose pSlot
    after <- peek pSlot
    assertBool "slot reclaimed" (isNull after)
  gateStill <- inspectTableGate (acTable ctx)
  assertEqual "slot close tore nothing down" (0, False) gateStill
  rvAdmitted <- haskokiAsyncCancel sp nullJob
  assertEqual "borrowed still admitted past the slot close" rvBad rvAdmitted
  asyncCloseCtx ctx
  nLive <- asyncLiveHandles ctx
  assertZero "live_handles" "drained" nLive
  retireCtx sp
  freeStablePtr sp

-- | Owned-to-borrowed index reuse: the borrowed view registers over
-- the tombstone its freed index carries and admits — start pending,
-- cancel ok. The retired controls pin while their pointer stays
-- allocated (its index reserved, unreusable by anyone): a retired
-- owned value refuses, and releasing the borrowed view retires it
-- so the stale borrowed value refuses too.
caseOwnedToBorrowedReuse :: IO ()
caseOwnedToBorrowedReuse = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  -- Retired-owned control: retire while allocated, assert, free.
  -- The live index cannot be reused underneath the assertion.
  owned <- mkFfiGen dc
  spOwned <- newStablePtr owned
  registerFixtureCtx spOwned (acTable owned)
  retireCtx spOwned
  rvStale <- haskokiAsyncCancel spOwned nullJob
  assertEqual "retired owned refuses" rvGeneral rvStale
  freeStablePtr spOwned
  asyncCloseCtx owned
  -- Reuse flow: a slot-closed owned index hands to a borrowed view.
  borrowed <- mkFfiGen dc
  spBorrowed <- reuseBorrowed dc borrowed 100
  let sess = CULong (fromIntegral (unSessionId (acSession borrowed)))
  h <- alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- BS.useAsCString "abc" $ \p ->
      haskokiAsyncStart spBorrowed sess 2 (castPtr p) 3 32 1 pHandleOut
    assertEqual "borrowed start on the reused index admits" rvPending rv
    hOut <- peek pHandleOut
    assertBool "handle live" (castStablePtrToPtr hOut /= nullPtr)
    pure hOut
  rvCancel <- haskokiAsyncCancel spBorrowed h
  assertEqual "borrowed cancel ok" rvOK rvCancel
  -- Retired-borrowed control: retire while allocated, assert, free.
  retireCtx spBorrowed
  rvStaleBorrowed <- haskokiAsyncCancel spBorrowed nullJob
  assertEqual "retired borrowed refuses" rvGeneral rvStaleBorrowed
  freeStablePtr spBorrowed
  asyncCloseCtx borrowed
  awaitNoPendingReclaims

-- | Deterministic pre-lookup barrier: a caller parks after its
-- null check and before its registry lookup while the owner
-- closes the context completely underneath it. On release the
-- caller meets the tombstone and refuses typed — it never
-- dereferences the freed pointer. Before tombstones, a caller
-- resuming after the close fell through to a dereference of the
-- freed pointer. The hook is scoped to this pointer and reset
-- under 'finally', so parallel tests never observe it. The close
-- runs over an acquisition that defers its pointer free into
-- 'freedRef': the value stays allocated (hence unreusable by any
-- other group) until the assertion completes, then frees whatever
-- the outcome — the pin-while-allocated shape of
-- 'caseOwnedToBorrowedReuse'.
caseEnterBarrierCloseTombstones :: IO ()
caseEnterBarrierCloseTombstones = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    entered <- newEmptyMVar
    proceed <- newEmptyMVar
    done <- newEmptyMVar
    freedRef <- newIORef []
    let acq = asyncAcquisition { aaFreeCtxPtr = \fp -> modifyIORef' freedRef (fp :) }
    setEnterTestHook sp (Just (putMVar entered () >> takeMVar proceed))
    (do
      _ <- forkIO $ do
        r <- try (haskokiAsyncCancel sp nullJob)
        putMVar done (r :: Either SomeException CULong)
      mEntered <- timeout 10000000 (takeMVar entered)
      case mEntered of
        Nothing -> assertFailure "caller never parked pre-lookup"
        Just () -> pure ()
      closeCtxSlotWith acq pSlot
      after <- peek pSlot
      assertBool "close completed under the parked caller" (isNull after)
      gateMid <- inspectTableGate (acTable ctx)
      assertEqual "retired, no borrowers" (0, True) gateMid
      putMVar proceed ()
      mDone <- timeout 10000000 (takeMVar done)
      r <- case mDone of
        Nothing -> assertFailure "caller never reported after release"
        Just x -> pure x
      case r of
        Right rv -> assertEqual "parked caller refused by tombstone" rvGeneral rv
        Left e -> assertFailure ("caller failed: " ++ show e)
      ) `finally` (readIORef freedRef >>= mapM_ freeStablePtr >> setEnterTestHook sp Nothing)

-- | Retiring clears the entry hook in the same step as the
-- tombstone: arm a hook, retire, then re-register the same
-- pointer live and drive a call through it — the stale hook must
-- not fire (its signal would surface in the rendezvous cell
-- below). Registration preserves a live hook by design, so only
-- the retire-time clear stands between the predecessor's hook
-- and the new owner's calls.
caseRetireClearsHook :: IO ()
caseRetireClearsHook = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  fired <- newEmptyMVar
  setEnterTestHook sp (Just (putMVar fired ()))
  retireCtx sp
  registerFixtureCtx sp (acTable ctx)
  rv <- haskokiAsyncCancel sp nullJob
  assertEqual "re-registered pointer admits" rvBad rv
  mFired <- tryTakeMVar fired
  case mFired of
    Nothing -> pure ()
    Just () -> assertFailure "stale entry hook fired after retire"
  retireCtx sp
  freeStablePtr sp
  awaitNoPendingReclaims

-- | Session close retires the borrowed view but defers its pointer
-- free behind the entry's borrow count: with a borrow held across
-- the close, the retired entry keeps both roots (the displaced
-- table and the view pointer itself) queued until the release.
caseSessionCloseDefersViewFree :: IO ()
caseSessionCloseDefersViewFree =
  bracket openStdSessionView (\(inst, _, _) -> haskokiStdClose inst) $
    \(inst, h, view) -> do
      bracket_ (ctxAcquireBorrowTest view) (ctxReleaseBorrowTest view) $ do
        setup <- ctxInspectEntryTest view
        assertEqual "view live under the held borrow" (2, 1, 0) setup
        haskokiStdCloseSession inst h
          >>= assertEqual "session closed" (stdRvOf CKR_OK)
        mid <- ctxInspectEntryTest view
        assertEqual "retired view keeps its roots queued under the borrow"
          (3, 1, 2) mid
      awaitNoPendingReclaims

-- | Instance close releases every session view the same way: the
-- retired entry keeps both roots queued while a borrow stands.
caseInstanceCloseDefersViewFree :: IO ()
caseInstanceCloseDefersViewFree = do
  (inst, _, view) <- openStdSessionView
  bracket_ (ctxAcquireBorrowTest view) (ctxReleaseBorrowTest view) $ do
    setup <- ctxInspectEntryTest view
    assertEqual "view live under the held borrow" (2, 1, 0) setup
    haskokiStdClose inst
    mid <- ctxInspectEntryTest view
    assertEqual "retired view keeps its roots queued under the borrow"
      (3, 1, 2) mid
  awaitNoPendingReclaims

-- | The open-session rollback releases its never-installed view the
-- same way: the seam observer holds a borrow on the view key, the
-- injected fault runs the rollback, and the retired entry keeps
-- both roots queued until the release.
caseOpenRollbackDefersViewFree :: IO ()
caseOpenRollbackDefersViewFree = do
  inst <- openStdInstance defaultConfig
  assertBool "instance opened" (castStablePtrToPtr inst /= nullPtr)
  keyRef <- newIORef Nothing
  let observe BeforeBorrowedViewInstall (Just view) = do
        writeIORef keyRef (Just view)
        ctxAcquireBorrowTest view
        ioError (userError "injected rollback")
      observe _ _ = pure ()
  flip finally (haskokiStdClose inst) $ alloca $ \pSession -> do
    haskokiStdOpenSessionWithNotifyWithKey observe inst 0 0 0 nullPtr nullFunPtr pSession
      >>= assertEqual "injected open fault fenced" (stdRvOf CKR_GENERAL_ERROR)
    mView <- readIORef keyRef
    view <- case mView of
      Nothing -> assertFailure "seam reached the view-install point"
      Just v -> pure v
    (do
      mid <- ctxInspectEntryTest view
      assertEqual "rolled-back view keeps its roots queued under the borrow"
        (3, 1, 2) mid
      ) `finally` ctxReleaseBorrowTest view
    awaitNoPendingReclaims
