{- | FfiAsync Handoff: submit/join transfers and kill-cancel probes.
-}
{-# LANGUAGE OverloadedStrings #-}
module FfiAsync.Handoff
  ( caseSubmitKillCancelsFresh
  , caseSubmitKeyFunctionRefuses
  , caseHandoffKillCancelsJoin
  , caseHandoffPublishes
  , caseJoinAcquireKillAfterCommit
  , caseJoinAcquirePublishes
  , caseCloseKillRetryCompletes
  , caseJoinAcquireKillDuringAcquire
  ) where


import Control.Concurrent
  ( forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  )
import Control.Exception
  ( AsyncException (..)
  , SomeException
  , fromException
  , try
  )
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (nullPtr)
import Foreign.StablePtr
  ( castStablePtrToPtr
  , newStablePtr
  )
import Foreign.Storable (peek, poke)
import GHC.Conc (BlockReason (..))
import System.Timeout (timeout)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)

import OwnershipCounters (assertZero)
import FfiAsync.Fixtures
import Haskoki.FFI.Async
  ( AsyncCtx (..)
  , allocJobHandle
  , asyncCloseCtx
  , asyncLiveHandles
  , haskokiAsyncClose
  , joinAcquireTransfer
  , joinTransfer
  , registerFixtureCtx
  , resolveJobHandle
  , rvOf
  , submitTransfer
  )
import Haskoki.Runtime.Async
  ( CancelOutcome (..)
  , JobFunction (..)
  , JobRequest (..)
  , TerminalState (..)
  , cancelJob
  , enterTableUse
  , exitTableUse
  , inspectTableGate
  , tableStats
  )
import Haskoki.Runtime.Detached
  ( AttachmentView (..)
  , DetachOutcome (..)
  , JoinOutcome (..)
  , JoinRequest (..)
  , detachJob
  , inspectAttachment
  , joinJob
  , setJoinTestHook
  )
import Haskoki.Runtime.Storage
  ( JobExecState (..)
  , JobRecord (..)
  , Store (..)
  )
import Haskoki.Types
  ( JobId (..)
  , ReturnCode (CKR_ARGUMENTS_BAD)
  )


-- | A kill landing in the submit transfer window cancels the
-- fresh unregistered job and nulls the out-pointer: the parked
-- submitter dies 'ThreadKilled', no live orphan strands, and
-- close drains clean. Pre-fix the fresh job stayed live with no
-- handle, and the handle-only drain missed it.
caseSubmitKillCancelsFresh :: IO ()
caseSubmitKillCancelsFresh = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  jobReq <- planFfiDigest ctx "abc" 32 1
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  done <- newEmptyMVar
  alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    submitterTid <- forkIO $ do
      r <- try (submitTransfer
        (putMVar entered () >> takeMVar proceed) ctx jobReq pHandleOut)
      putMVar done (r :: Either SomeException CULong)
    mEntered <- timeout 10000000 (takeMVar entered)
    case mEntered of
      Nothing -> assertFailure "submitter never entered the transfer window"
      Just () -> pure ()
    (liveMid, _termMid, nextMid) <- tableStats (acTable ctx)
    assertEqual "fresh job started" 1 liveMid
    let freshJid = JobId (nextMid - 1)
    killThread submitterTid
    mDone <- timeout 10000000 (takeMVar done)
    r <- case mDone of
      Nothing -> assertFailure "submitter never reported after kill"
      Just x -> pure x
    case r of
      Left e -> case fromException e of
        Just ThreadKilled -> pure ()
        Just other -> assertFailure ("expected ThreadKilled, got async " ++ show other)
        Nothing -> assertFailure ("expected ThreadKilled, got " ++ show e)
      Right rv -> assertFailure ("kill swallowed, transfer returned " ++ show rv)
    hAfter <- peek pHandleOut
    assertBool "out-pointer nulled" (castStablePtrToPtr hAfter == nullPtr)
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "no handle admitted" nLive
    (liveAfter, termAfter, _nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live orphan" liveAfter
    assertEqual "one canceled tombstone" 1 termAfter
    cout <- cancelJob (acTable ctx) freshJid
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("fresh job not canceled, got " ++ show other)
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains clean" nLive2

caseSubmitKeyFunctionRefuses :: IO ()
caseSubmitKeyFunctionRefuses = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  digestReq <- planFfiDigest ctx "abc" 32 1
  -- Rebuild (not record-update): 'jrFunction' also belongs to
  -- 'JobRecord', so an update is ambiguous here.
  let badReq = case digestReq of
        JobRequest sid _func work ticks cap ->
          JobRequest sid JobGenKey work ticks cap
  before <- tableStats (acTable ctx)
  alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- submitTransfer (pure ()) ctx badReq pHandleOut
    assertEqual "key-function submit refuses"
      (rvOf CKR_ARGUMENTS_BAD) rv
    hAfter <- peek pHandleOut
    assertBool "no handle on refusal"
      (castStablePtrToPtr hAfter == nullPtr)
  after <- tableStats (acTable ctx)
  assertEqual "refusal consumes nothing" before after
  nLive <- asyncLiveHandles ctx
  assertZero "live_handles" "no handle admitted" nLive
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains clean" nLive2
  (liveEnd, _, _) <- tableStats (acTable ctx)
  assertZero "live_jobs" "no live orphan" liveEnd

-- | A kill landing in the join handoff window cancels the fresh
-- join through the detach wrapper: the committed attachment
-- resolves canceled (durably), the out-pointer nulls, and no
-- live orphan strands. The persistent id is consumed by the
-- cancel — the commit is the point of no return; a kill before
-- it rolls the claim back instead.
caseHandoffKillCancelsJoin :: IO ()
caseHandoffKillCancelsJoin = do
  store <- mkFfiStore
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
  jid <- case eJoin of
    JoinOk j -> pure j
    other -> assertFailure ("join failed: " ++ show other)
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  done <- newEmptyMVar
  alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    publisherTid <- forkIO $ do
      r <- try (joinTransfer
        (putMVar entered () >> takeMVar proceed) ctx jid pHandleOut)
      putMVar done (r :: Either SomeException CULong)
    mEntered <- timeout 10000000 (takeMVar entered)
    case mEntered of
      Nothing -> assertFailure "publisher never entered the handoff window"
      Just () -> pure ()
    avMid <- inspectAttachment dc pid
    assertEqual "join committed, unregistered" (Just (AvActive jid)) avMid
    nLiveMid <- asyncLiveHandles ctx
    assertZero "live_handles" "no handle yet" nLiveMid
    killThread publisherTid
    mDone <- timeout 10000000 (takeMVar done)
    r <- case mDone of
      Nothing -> assertFailure "publisher never reported after kill"
      Just x -> pure x
    case r of
      Left e -> case fromException e of
        Just ThreadKilled -> pure ()
        Just other -> assertFailure ("expected ThreadKilled, got async " ++ show other)
        Nothing -> assertFailure ("expected ThreadKilled, got " ++ show e)
      Right rv -> assertFailure ("kill swallowed, handoff returned " ++ show rv)
    hAfter <- peek pHandleOut
    assertBool "out-pointer nulled" (castStablePtrToPtr hAfter == nullPtr)
    cout <- cancelJob (acTable ctx) jid
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("fresh join not canceled, got " ++ show other)
    avAfter <- inspectAttachment dc pid
    assertEqual "attachment canceled" (Just (AvTerminal JobCanceled)) avAfter
    jobs <- loadFfiJobs store
    case [rec | rec <- jobs, jrPersistentId rec == pid] of
      [rec] -> assertEqual "record canceled" JobCanceled (jrState rec)
      other -> assertFailure ("expected one record, got " ++ show other)
  (liveAfter, _termAfter, _nextAfter) <- tableStats (acTable ctx)
  assertZero "live_jobs" "no live orphan" liveAfter
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains clean" nLive2

-- | The join handoff without interruption publishes a live
-- handle: pending with the out-pointer set, resolving to the
-- fresh join, and the attachment stays active until close
-- drains it.
caseHandoffPublishes :: IO ()
caseHandoffPublishes = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
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
  jid <- case eJoin of
    JoinOk j -> pure j
    other -> assertFailure ("join failed: " ++ show other)
  h <- alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- joinTransfer (pure ()) ctx jid pHandleOut
    assertEqual "handoff pending" rvPending rv
    hOut <- peek pHandleOut
    assertBool "handle live" (castStablePtrToPtr hOut /= nullPtr)
    pure hOut
  m0 <- resolveJobHandle ctx h
  assertEqual "handle resolves" (Just jid) m0
  av <- inspectAttachment dc pid
  assertEqual "attachment active" (Just (AvActive jid)) av
  nLive <- asyncLiveHandles ctx
  assertEqual "one live handle" 1 nLive
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains the handle" nLive2
  storeClose _store

-- Combined acquisition, owned teardown, pre-dereference admission

-- | A kill landing after the join acquisition commits but before
-- the handle publishes cancels the fresh join through the detach
-- wrapper: the committed attachment resolves canceled (durably),
-- the out-pointer nulls, and no live orphan strands. The
-- mid-window attachment read proves the kill lands strictly
-- post-commit — before the combined acquisition, a kill there
-- left the committed attachment with no handle.
caseJoinAcquireKillAfterCommit :: IO ()
caseJoinAcquireKillAfterCommit = do
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
  alloca $ \pHandleOut -> alloca $ \pNeedOut -> do
    poke pHandleOut nullJob
    poke pNeedOut 0
    acquirerTid <- forkIO $ do
      r <- try (joinAcquireTransfer
        (putMVar entered () >> takeMVar proceed) dc ctx JoinRequest
          { jqPid = pid
          , jqFunction = JobDigest
          , jqSession = acSession ctx
          , jqCapacity = 32
          } pHandleOut pNeedOut)
      putMVar done (r :: Either SomeException CULong)
    mEntered <- timeout 10000000 (takeMVar entered)
    case mEntered of
      Nothing -> assertFailure "acquirer never entered the handoff window"
      Just () -> pure ()
    jidMid <- do
      avMid <- inspectAttachment dc pid
      case avMid of
        Just (AvActive j) -> pure j
        other -> assertFailure ("join not committed, got " ++ show other)
    nLiveMid <- asyncLiveHandles ctx
    assertZero "live_handles" "no handle yet" nLiveMid
    killThread acquirerTid
    mDone <- timeout 10000000 (takeMVar done)
    r <- case mDone of
      Nothing -> assertFailure "acquirer never reported after kill"
      Just x -> pure x
    case r of
      Left e -> case fromException e of
        Just ThreadKilled -> pure ()
        Just other -> assertFailure ("expected ThreadKilled, got async " ++ show other)
        Nothing -> assertFailure ("expected ThreadKilled, got " ++ show e)
      Right rv -> assertFailure ("kill swallowed, acquire returned " ++ show rv)
    hAfter <- peek pHandleOut
    assertBool "out-pointer nulled" (castStablePtrToPtr hAfter == nullPtr)
    cout <- cancelJob (acTable ctx) jidMid
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("fresh join not canceled, got " ++ show other)
    avAfter <- inspectAttachment dc pid
    assertEqual "attachment canceled" (Just (AvTerminal JobCanceled)) avAfter
    jobs <- loadFfiJobs store
    case [rec | rec <- jobs, jrPersistentId rec == pid] of
      [rec] -> assertEqual "record canceled" JobCanceled (jrState rec)
      other -> assertFailure ("expected one record, got " ++ show other)
  (liveAfter, _termAfter, _nextAfter) <- tableStats (acTable ctx)
  assertZero "live_jobs" "no live orphan" liveAfter
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains clean" nLive2

-- | The combined acquisition without interruption publishes a
-- live handle: pending with the out-pointer set and the need
-- out-pointer untouched, resolving to the fresh join, and the
-- attachment stays active until close drains it.
caseJoinAcquirePublishes :: IO ()
caseJoinAcquirePublishes = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  eDet <- detachJob dc (acTable ctx) j0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  (h, need) <- alloca $ \pHandleOut -> alloca $ \pNeedOut -> do
    poke pHandleOut nullJob
    poke pNeedOut 0
    rv <- joinAcquireTransfer (pure ()) dc ctx JoinRequest
      { jqPid = pid
      , jqFunction = JobDigest
      , jqSession = acSession ctx
      , jqCapacity = 32
      } pHandleOut pNeedOut
    assertEqual "acquire pending" rvPending rv
    hOut <- peek pHandleOut
    assertBool "handle live" (castStablePtrToPtr hOut /= nullPtr)
    needOut <- peek pNeedOut
    pure (hOut, needOut)
  assertEqual "need untouched on success" 0 need
  m0 <- resolveJobHandle ctx h
  jid <- case m0 of
    Just j -> pure j
    Nothing -> assertFailure "handle does not resolve"
  av <- inspectAttachment dc pid
  assertEqual "attachment active" (Just (AvActive jid)) av
  nLive <- asyncLiveHandles ctx
  assertEqual "one live handle" 1 nLive
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains the handle" nLive2

-- | Interrupting the winning slot-close releases its claim
-- instead of stranding retired-but-undrained: the gate reopens
-- with the borrower still counted, the slot stays set, and a
-- retrying close re-claims and completes — draining the live
-- handle, canceling the job, and nulling the slot. A third close
-- is a silent no-op. Before the ownership transfer, the
-- interrupted close left the gate retired with no owner, and the
-- retry skipped teardown while nulling the slot.
caseCloseKillRetryCompletes :: IO ()
caseCloseKillRetryCompletes = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  h <- allocJobHandle ctx j0
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    admitted <- enterTableUse (acTable ctx)
    assertBool "borrower admitted" admitted
    closedDone <- newEmptyMVar
    closerTid <- forkIO $ do
      r <- try (haskokiAsyncClose pSlot)
      putMVar closedDone (r :: Either SomeException ())
    awaitBlocked BlockedOnSTM closerTid
    killThread closerTid
    mClosed <- timeout 10000000 (takeMVar closedDone)
    case mClosed of
      Nothing -> assertFailure "closer never reported after kill"
      Just (Right ()) -> pure ()
      Just (Left e) -> assertFailure ("closer leaked: " ++ show e)
    gateMid <- inspectTableGate (acTable ctx)
    assertEqual "kill released the claim" (1, False) gateMid
    mid <- peek pSlot
    assertBool "slot still set (teardown incomplete)" (not (isNull mid))
    exitTableUse (acTable ctx)
    haskokiAsyncClose pSlot
    after <- peek pSlot
    assertBool "retry nulled the slot" (isNull after)
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "retired, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "retry drained the handle" nLive
    mStale <- resolveJobHandle ctx h
    assertEqual "handle retired" Nothing mStale
    cout <- cancelJob (acTable ctx) j0
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("job not canceled, got " ++ show other)
    haskokiAsyncClose pSlot
    after3 <- peek pSlot
    assertBool "slot stays nulled" (isNull after3)

-- | A kill landing inside the acquisition — after the fresh job
-- starts but before its claim commits — retires the fresh
-- unregistered job, rolls the claim back, and nulls the
-- out-pointer: the parked acquirer dies 'ThreadKilled', the
-- durable job stands untouched and joinable, and a retry
-- acquires cleanly. The acquisition runs masked end to end, so
-- the pure commit boundary itself admits no kill; this window is
-- the closest injectable point on the acquisition side of it.
caseJoinAcquireKillDuringAcquire :: IO ()
caseJoinAcquireKillDuringAcquire = do
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
  alloca $ \pHandleOut -> alloca $ \pNeedOut -> do
    poke pHandleOut nullJob
    poke pNeedOut 0
    acquirerTid <- forkIO $ do
      r <- try (joinAcquireTransfer (pure ()) dc ctx JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = acSession ctx
        , jqCapacity = 32
        } pHandleOut pNeedOut)
      putMVar done (r :: Either SomeException CULong)
    mEntered <- timeout 10000000 (takeMVar entered)
    case mEntered of
      Nothing -> assertFailure "acquirer never entered the acquisition window"
      Just () -> pure ()
    (liveMid, _termMid, nextMid) <- tableStats (acTable ctx)
    assertEqual "fresh job started" 1 liveMid
    let freshJid = JobId (nextMid - 1)
    avMid <- inspectAttachment dc pid
    assertEqual "claim uncommitted" (Just AvIdle) avMid
    nLiveMid <- asyncLiveHandles ctx
    assertZero "live_handles" "no handle yet" nLiveMid
    killThread acquirerTid
    mDone <- timeout 10000000 (takeMVar done)
    r <- case mDone of
      Nothing -> assertFailure "acquirer never reported after kill"
      Just x -> pure x
    case r of
      Left e -> case fromException e of
        Just ThreadKilled -> pure ()
        Just other -> assertFailure ("expected ThreadKilled, got async " ++ show other)
        Nothing -> assertFailure ("expected ThreadKilled, got " ++ show e)
      Right rv -> assertFailure ("kill swallowed, acquire returned " ++ show rv)
    hAfter <- peek pHandleOut
    assertBool "out-pointer nulled" (castStablePtrToPtr hAfter == nullPtr)
    needAfter <- peek pNeedOut
    assertEqual "need untouched" 0 needAfter
    avAfter <- inspectAttachment dc pid
    assertEqual "claim rolled back" (Just AvIdle) avAfter
    (liveAfter, _termAfter, _nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live orphan" liveAfter
    cout <- cancelJob (acTable ctx) freshJid
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("fresh job not canceled, got " ++ show other)
    jobs <- loadFfiJobs store
    case [rec | rec <- jobs, jrPersistentId rec == pid] of
      [rec] -> assertEqual "record untouched" JobQueued (jrState rec)
      other -> assertFailure ("expected one record, got " ++ show other)
    -- The rolled-back claim frees the id: a retry acquires cleanly.
    setJoinTestHook dc (pure ())
    rvRetry <- joinAcquireTransfer (pure ()) dc ctx JoinRequest
      { jqPid = pid
      , jqFunction = JobDigest
      , jqSession = acSession ctx
      , jqCapacity = 32
      } pHandleOut pNeedOut
    assertEqual "retry pending" rvPending rvRetry
    hRetry <- peek pHandleOut
    assertBool "retry handle live" (castStablePtrToPtr hRetry /= nullPtr)
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains clean" nLive2
