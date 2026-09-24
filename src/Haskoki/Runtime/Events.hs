{- | Waitable slot events, token presence, and session notification
callbacks (@C_WaitForSlotEvent@ semantics).

* 'EventQueue' is bounded ('defaultEventBound' = 1024): overflow
  follows the named 'OverflowPolicy' ('DropOldest' default) and every
  drop increments 'droppedEvents'. Blocking waiters sleep in STM and
  wake on post; 'finalizeEvents' wakes ALL waiters with the
  source-correct @CKR_CRYPTOKI_NOT_INITIALIZED@; the nonblocking poll
  reports 'WaitNoEvent' (@CKR_NO_EVENT@) when empty.
* 'TokenRegistry' seats presence per slot and quiesces in-flight
  async work on removal: every job on the removed slot's sessions is
  canceled before the removal event posts, so no completion can run
  against removed state (no use-after-remove).
* Session notify callbacks fire on session-relevant events;
  'closeSessionNotifies' cancels them (no late invocation after it
  returns). The ONE supported reentrant query is
  'reentrantSlotSnapshot': it never takes the model gate. Any other
  in-callback gated call is rejected with 'ReentryRejected'.

STM discipline: transactions coordinate @TVar@s only; callbacks and
job cancellation run outside 'atomically'.
-}
module Haskoki.Runtime.Events
  ( SlotEvent (..)
  , OverflowPolicy (..)
  , defaultEventBound
  , EventQueue
  , newEventQueue
  , postSlotEvent
  , waitSlotEvent
  , tryWaitSlotEvent
  , WaitOutcome (..)
  , waitCode
  , finalizeEvents
  , eventDepth
  , droppedEvents
  , eventBound
  , TokenRegistry
  , newTokenRegistry
  , registerSessionSlot
  , InsertOutcome (..)
  , insertToken
  , RemoveOutcome (..)
  , removeToken
  , registryAsync
  , tokenPresent
  , tokenGeneration
  , registryEvents
  , NotifyEvent
  , CallbackCtx
  , registerNotify
  , closeSessionNotifies
  , dispatchSessionEvent
  , reentrantSlotSnapshot
  , ReentryDeny (..)
  , requestGatedCall
  ) where

import Control.Concurrent.MVar (MVar, newMVar, withMVar)
import Control.Concurrent.STM
  ( TVar
  , atomically
  , newTVarIO
  , readTVar
  , retry
  , writeTVar
  )
import Control.Monad (forM_)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Word (Word32, Word64)

import Haskoki.Runtime.Async (AsyncTable, CancelOutcome (..), cancelJob, sessionJobs)
import Haskoki.Types (SessionId, SlotId)

-- ---------------------------------------------------------------------------
-- Slot events
-- ---------------------------------------------------------------------------

-- | One slot-state change: token arrival (@True@) or departure.
data SlotEvent = SlotEvent
  { evSlot :: !SlotId
  , evPresent :: !Bool
  , evGeneration :: !Word64
  } deriving (Eq, Show)

-- | What a full queue does with the next post. Both policies count
-- the loss in 'droppedEvents'. 'DropOldest' is the default: a
-- lagging consumer re-syncs to the LATEST token state.
data OverflowPolicy
  = DropOldest
  | DropNewest
  deriving (Eq, Show)

-- | §3 default: 1024 queued slot events.
defaultEventBound :: Int
defaultEventBound = 1024

-- | The bounded waitable queue.
data EventQueue = EventQueue
  { eqBound :: !Int
  , eqPolicy :: !OverflowPolicy
  , eqPending :: !(TVar (Seq SlotEvent))
  , eqDropped :: !(TVar Int)
  , eqFinalized :: !(TVar Bool)
  }

-- | A fresh queue with the given bound and policy.
newEventQueue :: Int -> OverflowPolicy -> IO EventQueue
newEventQueue bound policy = EventQueue bound policy
  <$> newTVarIO Seq.empty
  <*> newTVarIO 0
  <*> newTVarIO False

-- | Post an event: enqueue within the bound (else apply the overflow
-- policy and count the drop) and wake waiters. Posts after finalize
-- are dropped and counted — finalized state never regrows a queue.
postSlotEvent :: EventQueue -> SlotEvent -> IO ()
postSlotEvent eq ev = atomically $ do
  finalized <- readTVar (eqFinalized eq)
  if finalized
    then do
      d <- readTVar (eqDropped eq)
      writeTVar (eqDropped eq) (d + 1)
    else do
      q <- readTVar (eqPending eq)
      if Seq.length q < eqBound eq
        then writeTVar (eqPending eq) (q Seq.|> ev)
        else do
          d <- readTVar (eqDropped eq)
          writeTVar (eqDropped eq) (d + 1)
          case eqPolicy eq of
            DropOldest -> case Seq.viewl q of
              _ Seq.:< rest -> writeTVar (eqPending eq) (rest Seq.|> ev)
              Seq.EmptyL -> writeTVar (eqPending eq) (q Seq.|> ev)
            DropNewest -> pure ()

-- | How a wait resolved.
data WaitOutcome
  = WaitEvent !SlotEvent
  | WaitNoEvent
  | WaitFinalized
  deriving (Eq, Show)

-- | Source-correct @CK_RV@ for each outcome: @CKR_OK@,
-- @CKR_NO_EVENT@ (@0x08@), @CKR_CRYPTOKI_NOT_INITIALIZED@ (@0x190@).
waitCode :: WaitOutcome -> Word32
waitCode (WaitEvent _) = 0x00000000
waitCode WaitNoEvent = 0x00000008
waitCode WaitFinalized = 0x00000190

-- | Blocking wait: the head event, or 'WaitFinalized' once the queue
-- finalizes. Sleeps in STM (@retry@); no polling, no threads.
waitSlotEvent :: EventQueue -> IO WaitOutcome
waitSlotEvent eq = atomically $ do
  q <- readTVar (eqPending eq)
  case Seq.viewl q of
    ev Seq.:< rest -> do
      writeTVar (eqPending eq) rest
      pure (WaitEvent ev)
    Seq.EmptyL -> do
      finalized <- readTVar (eqFinalized eq)
      if finalized
        then pure WaitFinalized
        else retry

-- | Nonblocking poll (@CKF_DONT_BLOCK@): the head event, or
-- 'WaitNoEvent' immediately when empty. An empty FINALIZED queue
-- reports 'WaitFinalized' on both paths (coherent drained-tail
-- semantics).
tryWaitSlotEvent :: EventQueue -> IO WaitOutcome
tryWaitSlotEvent eq = atomically $ do
  q <- readTVar (eqPending eq)
  case Seq.viewl q of
    ev Seq.:< rest -> do
      writeTVar (eqPending eq) rest
      pure (WaitEvent ev)
    Seq.EmptyL -> do
      finalized <- readTVar (eqFinalized eq)
      pure (if finalized then WaitFinalized else WaitNoEvent)

-- | Finalize: wake ALL waiters with 'WaitFinalized'. Idempotent.
finalizeEvents :: EventQueue -> IO ()
finalizeEvents eq = atomically (writeTVar (eqFinalized eq) True)

-- | Current queue depth (diagnostic; races with posters by design).
eventDepth :: EventQueue -> IO Int
eventDepth eq = Seq.length <$> atomically (readTVar (eqPending eq))

-- | Total drops (overflow + post-finalize posts).
droppedEvents :: EventQueue -> IO Int
droppedEvents eq = atomically (readTVar (eqDropped eq))

-- | The configured (bound, policy): configurable + reported.
eventBound :: EventQueue -> IO (Int, OverflowPolicy)
eventBound eq = pure (eqBound eq, eqPolicy eq)

-- ---------------------------------------------------------------------------
-- Token presence + in-flight quiesce
-- ---------------------------------------------------------------------------

-- | Presence, generations, session affinity, notify callbacks, and the
-- async table needed to quiesce in-flight work on removal.
data TokenRegistry = TokenRegistry
  { trEvents :: !EventQueue
  , trAsync :: !AsyncTable
  , trPresence :: !(TVar (Map SlotId Bool))
  , trGeneration :: !(TVar (Map SlotId Word64))
  , trAffinity :: !(TVar (Map SessionId SlotId))
  , trNotify :: !(TVar (Map SessionId [NotifyCb]))
  , trNotifyLock :: !(MVar ())
  }

-- | A session notification callback. It receives the callback context
-- (the ONLY capability available in-callback), the session, and the
-- event name. Callbacks never run holding the model gate.
type NotifyCb = CallbackCtx -> SessionId -> NotifyEvent -> IO ()

-- | Session-relevant event names (opaque strings by design).
type NotifyEvent = String

-- | The in-callback capability: exposes exactly the one reentrant
-- query ('reentrantSlotSnapshot'). There is no constructor outside
-- this module and no gate handle inside it, so in-callback gated
-- calls are rejected by construction ('requestGatedCall').
data CallbackCtx = CallbackCtx
  { ccPresence :: !(TVar (Map SlotId Bool))
  }

-- | A fresh registry over the given queue and async table.
newTokenRegistry :: EventQueue -> AsyncTable -> IO TokenRegistry
newTokenRegistry eq at = TokenRegistry eq at
  <$> newTVarIO Map.empty
  <*> newTVarIO Map.empty
  <*> newTVarIO Map.empty
  <*> newTVarIO Map.empty
  <*> newMVar ()

-- | Record which slot a session lives on (drives removal quiesce).
registerSessionSlot :: TokenRegistry -> SessionId -> SlotId -> IO ()
registerSessionSlot reg sid slot =
  atomically $ do
    aff <- readTVar (trAffinity reg)
    writeTVar (trAffinity reg) (Map.insert sid slot aff)

-- | The registry's event queue (for waiters).
registryEvents :: TokenRegistry -> EventQueue
registryEvents = trEvents

-- | The registry's async table (for the scheduler-advance
-- bridge: the table rides with the registry).
registryAsync :: TokenRegistry -> AsyncTable
registryAsync = trAsync

-- | How an insert resolved (generation included for control checks).
data InsertOutcome
  = Inserted !Word64
  | InsertAlreadyPresent !Word64
  deriving (Eq, Show)

-- | Seat a token: mark present, bump the slot generation, post the
-- arrival event. Idempotent (re-insert reports the live generation).
insertToken :: TokenRegistry -> SlotId -> IO InsertOutcome
insertToken reg slot = do
  gen <- atomically $ do
    pres <- readTVar (trPresence reg)
    gens <- readTVar (trGeneration reg)
    case Map.lookup slot pres of
      Just True -> pure (Left (Map.findWithDefault 0 slot gens))
      _ -> do
        let g = Map.findWithDefault 0 slot gens + 1
        writeTVar (trPresence reg) (Map.insert slot True pres)
        writeTVar (trGeneration reg) (Map.insert slot g gens)
        pure (Right g)
  case gen of
    Left g -> pure (InsertAlreadyPresent g)
    Right g -> do
      postSlotEvent (trEvents reg) (SlotEvent slot True g)
      pure (Inserted g)

-- | How a removal resolved (canceled-job count included).
data RemoveOutcome
  = Removed !Word64 !Int
  | RemoveNotPresent
  deriving (Eq, Show)

-- | Remove a token: quiesce in-flight work FIRST (cancel every job
-- on the slot's sessions), then mark removed, bump the generation,
-- and post the departure event. Cancellation runs outside STM; the
-- event posts only after the cancels land, so no completion can
-- observe removed state (no use-after-remove).
removeToken :: TokenRegistry -> SlotId -> IO RemoveOutcome
removeToken reg slot = do
  mJobs <- atomically $ do
    pres <- readTVar (trPresence reg)
    case Map.lookup slot pres of
      Just True -> do
        aff <- readTVar (trAffinity reg)
        let sids = [sid | (sid, s) <- Map.toList aff, s == slot]
        writeTVar (trPresence reg) (Map.insert slot False pres)
        gens <- readTVar (trGeneration reg)
        let g = Map.findWithDefault 0 slot gens + 1
        writeTVar (trGeneration reg) (Map.insert slot g gens)
        pure (Just (g, sids))
      _ -> pure Nothing
  case mJobs of
    Nothing -> pure RemoveNotPresent
    Just (g, sids) -> do
      canceled <- quiesce sids
      postSlotEvent (trEvents reg) (SlotEvent slot False g)
      pure (Removed g canceled)
  where
    quiesce sids = do
      counts <- mapM cancelSession sids
      pure (sum counts)
    cancelSession sid = do
      jids <- sessionJobs (trAsync reg) sid
      outs <- mapM (cancelJob (trAsync reg)) jids
      pure (length [() | CancelOk <- outs])

-- | Current presence (defaults absent).
tokenPresent :: TokenRegistry -> SlotId -> IO Bool
tokenPresent reg slot =
  Map.findWithDefault False slot <$> atomically (readTVar (trPresence reg))

-- | Current slot generation (0 = never seated).
tokenGeneration :: TokenRegistry -> SlotId -> IO Word64
tokenGeneration reg slot =
  Map.findWithDefault 0 slot <$> atomically (readTVar (trGeneration reg))

-- ---------------------------------------------------------------------------
-- Notification callbacks
-- ---------------------------------------------------------------------------

-- | Register a notify callback for a session.
registerNotify :: TokenRegistry -> SessionId -> NotifyCb -> IO ()
registerNotify reg sid cb = atomically $ do
  m <- readTVar (trNotify reg)
  writeTVar (trNotify reg) (Map.insertWith (++) sid [cb] m)

-- | Cancel a session's callbacks. Runs under the notify lock, so no
-- callback can be mid-dispatch when this returns: no late invocation
-- after close returns, by construction.
closeSessionNotifies :: TokenRegistry -> SessionId -> IO ()
closeSessionNotifies reg sid =
  withMVar (trNotifyLock reg) $ \_ -> atomically $ do
    m <- readTVar (trNotify reg)
    writeTVar (trNotify reg) (Map.delete sid m)

-- | Fire a session-relevant event at the session's callbacks.
-- Dispatch holds the notify lock (serialized with close); callbacks
-- run outside STM with only the 'CallbackCtx' capability. Returns
-- the delivery count.
dispatchSessionEvent :: TokenRegistry -> SessionId -> NotifyEvent -> IO Int
dispatchSessionEvent reg sid evName =
  withMVar (trNotifyLock reg) $ \_ -> do
    cbs <- atomically $ do
      m <- readTVar (trNotify reg)
      pure (Map.findWithDefault [] sid m)
    let ctx = CallbackCtx (trPresence reg)
    forM_ cbs (\cb -> cb ctx sid evName)
    pure (length cbs)

-- | THE ONE supported reentrant query: token presence per slot,
-- callable from inside a notification callback WITHOUT holding the
-- model gate (it touches only the presence @TVar@). Safe under a
-- held gate: it never blocks on one.
reentrantSlotSnapshot :: CallbackCtx -> IO [(SlotId, Bool)]
reentrantSlotSnapshot ctx =
  Map.toList <$> atomically (readTVar (ccPresence ctx))

-- | Why an in-callback gated call was refused.
data ReentryDeny
  = ReentryRejected !String
  deriving (Eq, Show)

-- | Any gated call attempted through the callback context is
-- rejected: callbacks carry no gate handle, so the rejection is
-- total (no deadlock possible — nothing ever waits). The callback
-- that needs provider state uses 'reentrantSlotSnapshot'.
requestGatedCall :: CallbackCtx -> IO (Either ReentryDeny ())
requestGatedCall _ =
  pure (Left (ReentryRejected "gated calls are rejected inside notification callbacks; use reentrantSlotSnapshot"))
