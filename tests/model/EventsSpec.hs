{- | Slot-event + notification-callback contract suite.

Bounded waitable queue, blocking wakeup, finalize wakeup, no-event
mode, token removal with in-flight async work, session notify
delivery/cancellation, and the one reentrant query.
-}
{-# LANGUAGE OverloadedStrings #-}
module EventsSpec (spec) where

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import qualified Data.ByteString as BS
import Data.IORef (newIORef, readIORef, modifyIORef')
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Outcome (EffectRequest (..), Reservation (..))
import Haskoki.Registry (MechanismId (..))
import Haskoki.Runtime.Async
import Haskoki.Runtime.Events
import Haskoki.Runtime.Lifecycle (newGate, withGate)
import Haskoki.Types (SessionId (..), SlotId (..))

spec :: TestTree
spec = testGroup "Events"
  [ testCase "blocking waiter wakes on posted event" caseWakeup
  , testCase "bound enforced: drop-oldest + counter" caseDropOldest
  , testCase "drop-newest policy honored + reported" caseDropNewest
  , testCase "finalize wakes ALL waiters source-correct" caseFinalizeWakes
  , testCase "DON'T_BLOCK returns NO_EVENT when empty" caseNoEvent
  , testCase "token removal quiesces in-flight work" caseRemoveQuiesce
  , testCase "notify delivered; close cancels; no late call" caseNotifyCancel
  , testCase "reentrant snapshot works under held gate" caseReentrant
  , testCase "in-callback gated call rejected, no deadlock" caseReentryRejected
  ]

sid1 :: SessionId
sid1 = SessionId 1

mkReg :: Int -> IO (TokenRegistry, AsyncTable, EventQueue)
mkReg bound = do
  eq <- newEventQueue bound DropOldest
  at <- newAsyncTable 16
  reg <- newTokenRegistry eq at
  pure (reg, at, eq)

signReq :: SessionId -> Int -> JobRequest
signReq sid ticks = JobRequest
  { jrSession = sid
  , jrFunction = JobSign
  , jrWork = WorkCall
      (Reservation "events-test" [] Nothing Nothing)
      (EffectCrypto (FxSign (MechanismId 0x251) Nothing BS.empty "hello"))
  , jrTicks = ticks
  , jrCapacity = 64
  }

-- | The waiter rendezvous replaces the old 50ms sleep.
-- Queue semantics carry determinism (a posted event is never lost,
-- whether the waiter has parked or not); the handshake only proves
-- the waiter thread started, and the timeout fails LOUDLY instead of
-- hanging forever. Every assertion below is unchanged.
caseWakeup :: IO ()
caseWakeup = do
  (reg, _, eq) <- mkReg 8
  ready <- newEmptyMVar
  got <- newEmptyMVar
  _ <- forkIO ((putMVar ready () >> waitSlotEvent eq) >>= putMVar got)
  _ <- takeMVar ready
  r <- insertToken reg (SlotId 0)
  mW <- timeout 5000000 (takeMVar got)
  w <- maybe (assertFailure "waiter never woke (5s guard)") pure mW
  case (r, w) of
    (Inserted g, WaitEvent ev) -> do
      assertEqual "slot" (SlotId 0) (evSlot ev)
      assertBool "present" (evPresent ev)
      assertEqual "generation" g (evGeneration ev)
      assertEqual "wait code is CKR_OK" 0x00000000 (waitCode w)
    other -> assertFailure ("wakeup mismatch: " ++ show other)

caseDropOldest :: IO ()
caseDropOldest = do
  (_, _, eq) <- mkReg 2
  postSlotEvent eq (SlotEvent (SlotId 0) True 1)
  postSlotEvent eq (SlotEvent (SlotId 1) True 2)
  postSlotEvent eq (SlotEvent (SlotId 2) True 3)
  d <- droppedEvents eq
  depth <- eventDepth eq
  assertEqual "one drop counted" 1 d
  assertEqual "bound held" 2 depth
  w1 <- tryWaitSlotEvent eq
  w2 <- tryWaitSlotEvent eq
  assertEqual "oldest dropped" (WaitEvent (SlotEvent (SlotId 1) True 2)) w1
  assertEqual "newest kept" (WaitEvent (SlotEvent (SlotId 2) True 3)) w2
  rep <- eventBound eq
  assertEqual "bound reported" (2, DropOldest) rep

caseDropNewest :: IO ()
caseDropNewest = do
  eq <- newEventQueue 1 DropNewest
  postSlotEvent eq (SlotEvent (SlotId 0) True 1)
  postSlotEvent eq (SlotEvent (SlotId 9) True 2)
  d <- droppedEvents eq
  w <- tryWaitSlotEvent eq
  assertEqual "one drop counted" 1 d
  assertEqual "oldest kept" (WaitEvent (SlotEvent (SlotId 0) True 1)) w
  rep <- eventBound eq
  assertEqual "policy reported" (1, DropNewest) rep

caseFinalizeWakes :: IO ()
caseFinalizeWakes = do
  (_, _, eq) <- mkReg 8
  ready <- newEmptyMVar
  m1 <- newEmptyMVar
  m2 <- newEmptyMVar
  _ <- forkIO ((putMVar ready () >> waitSlotEvent eq) >>= putMVar m1)
  _ <- forkIO ((putMVar ready () >> waitSlotEvent eq) >>= putMVar m2)
  -- Both waiters started (two rendezvous on one MVar).
  _ <- takeMVar ready
  _ <- takeMVar ready
  finalizeEvents eq
  mW1 <- timeout 5000000 (takeMVar m1)
  w1 <- maybe (assertFailure "waiter 1 never woke (5s guard)") pure mW1
  mW2 <- timeout 5000000 (takeMVar m2)
  w2 <- maybe (assertFailure "waiter 2 never woke (5s guard)") pure mW2
  assertEqual "waiter 1 finalized" WaitFinalized w1
  assertEqual "waiter 2 finalized" WaitFinalized w2
  assertEqual "source-correct code" 0x00000190 (waitCode WaitFinalized)
  -- post-finalize waits fail immediately, never block
  w3 <- waitSlotEvent eq
  assertEqual "post-finalize wait" WaitFinalized w3

caseNoEvent :: IO ()
caseNoEvent = do
  (_, _, eq) <- mkReg 8
  w <- tryWaitSlotEvent eq
  assertEqual "empty nonblocking" WaitNoEvent w
  assertEqual "CKR_NO_EVENT" 0x00000008 (waitCode WaitNoEvent)

caseRemoveQuiesce :: IO ()
caseRemoveQuiesce = do
  (reg, at, _) <- mkReg 8
  enableAsyncSession at sid1
  registerSessionSlot reg sid1 (SlotId 0)
  _ <- insertToken reg (SlotId 0)
  eJid <- startJob at (signReq sid1 100)
  jid <- case eJid of
    Left deny -> assertFailure ("start must succeed: " ++ show deny)
    Right j -> pure j
  out <- removeToken reg (SlotId 0)
  case out of
    Removed _ n -> assertEqual "one job canceled" 1 n
    other -> assertFailure ("remove mismatch: " ++ show other)
  present <- tokenPresent reg (SlotId 0)
  assertBool "token gone" (not present)
  -- No use-after-remove: the job is a canceled tombstone now.
  k <- cancelJob at jid
  case k of
    CancelAlready TermCanceled -> pure ()
    other -> assertFailure ("expected canceled tombstone, got: " ++ show other)

caseNotifyCancel :: IO ()
caseNotifyCancel = do
  (reg, _, _) <- mkReg 8
  calls <- newIORef (0 :: Int)
  registerNotify reg sid1 (\_ _ _ -> modifyIORef' calls (+ 1))
  n1 <- dispatchSessionEvent reg sid1 "session-event"
  assertEqual "one delivery" 1 n1
  closeSessionNotifies reg sid1
  n2 <- dispatchSessionEvent reg sid1 "session-event"
  assertEqual "no delivery after close" 0 n2
  c <- readIORef calls
  assertEqual "no late invocation" 1 c

caseReentrant :: IO ()
caseReentrant = do
  (reg, _, _) <- mkReg 8
  _ <- insertToken reg (SlotId 0)
  gate <- newGate
  got <- newEmptyMVar
  registerNotify reg sid1 (\ctx _ _ -> reentrantSlotSnapshot ctx >>= putMVar got)
  -- Hold the model gate in this thread while the callback fires: the
  -- reentrant query must still succeed (it never takes the gate).
  _ <- withGate gate (dispatchSessionEvent reg sid1 "tick")
  snap <- takeMVar got
  assertBool "snapshot sees slot 0 present" ((SlotId 0, True) `elem` snap)

caseReentryRejected :: IO ()
caseReentryRejected = do
  (reg, _, _) <- mkReg 8
  verdict <- newEmptyMVar
  registerNotify reg sid1 (\ctx _ _ -> requestGatedCall ctx >>= putMVar verdict)
  _ <- dispatchSessionEvent reg sid1 "tick"
  v <- takeMVar verdict
  case v of
    Left (ReentryRejected _) -> pure ()
    Right () -> assertFailure "gated call from callback must be rejected"
