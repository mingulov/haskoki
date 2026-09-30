-- | Interval-local serving presence and coalesced slot indications.
--
-- This leaf owns no sessions, async jobs, callbacks or native resources.
-- Serving mutations belong to the lifecycle publication coordinator, which
-- can compose 'publishPresenceSTM' with its model write in one transaction.
module Haskoki.Runtime.SlotEvents
  ( SlotEvents
  , SlotDefinition (..)
  , SlotSnapshot (..)
  , WaitMode (..)
  , SlotWait (..)
  , SlotConfigError (..)
  , PresenceError (..)
  , PresenceChange (..)
  , NotificationPoint (..)
  , NotificationHooks
  , newSlotEvents
  , newSlotEventsWith
  , snapshotSlots
  , snapshotSlotsSTM
  , publishPresenceSTM
  , waitSlot
  , closeSlotEvents
  , observeSlotEvents
  ) where

import Control.Concurrent.STM (STM, TVar, atomically, newTVarIO, readTVar, retry, writeTVar)
import qualified Data.Map.Strict as Map
import qualified Data.Sequence as Seq
import Data.Word (Word64)

import Haskoki.Outcome (ModelFault)
import Haskoki.Types (SlotId)

data SlotDefinition = SlotDefinition
  { sdSlot :: !SlotId
  , sdRemovable :: !Bool
  } deriving (Eq, Show)

data SlotSnapshot = SlotSnapshot
  { ssSlotId :: !SlotId
  , ssRemovable :: !Bool
  , ssPresent :: !Bool
  , ssPresenceEpoch :: !Word64
  } deriving (Eq, Show)

data WaitMode = Block | DontBlock
  deriving (Eq, Show)

data SlotWait = SlotReady !SlotId | SlotNoEvent | SlotWaitClosed
  deriving (Eq, Show)

data SlotConfigError = DuplicateSlot | TooManyPendingSlots | InvalidEventBound
  deriving (Eq, Show)

data PresenceError
  = PresenceUnknownSlot
  | PresenceFixedSlot
  | PresenceEpochExhausted
  | PresenceClosed
  | PresenceModelFault !ModelFault
  deriving (Eq, Show)

data PresenceChange = PresenceUnchanged !Word64 | PresenceChanged !Word64
  deriving (Eq, Show)

data NotificationPoint
  = WaitCaptured
  | WaitBeforeRetry
  | WaitDecisionCommitted !SlotWait
  | RemovalPrepublication
  | CloseCommitted
  deriving (Eq, Show)

type NotificationHooks = NotificationPoint -> IO ()

-- The pending bit and order are private and always written together. The
-- catalog never changes, so one entry per flagged slot bounds the queue by
-- the admitted catalog size, without a drop policy or a publication failure.
data SlotState = SlotState
  { slotSnapshot :: !SlotSnapshot
  , slotPending :: !Bool
  }

data ServiceState = ServiceState
  { serviceSlots :: !(Map.Map SlotId SlotState)
  , servicePending :: !(Seq.Seq SlotId)
  , serviceClosed :: !Bool
  }

data SlotEvents = SlotEvents
  { eventsState :: !(TVar ServiceState)
  , eventsObserve :: !NotificationHooks
  }

newSlotEvents :: Int -> [SlotDefinition] -> IO (Either SlotConfigError SlotEvents)
newSlotEvents = newSlotEventsWith (const (pure ())) 0

-- | Constructor injection is internal to Haskell fixtures. Production uses
-- epoch zero and no-op observations through 'newSlotEvents'.
newSlotEventsWith
  :: NotificationHooks -> Word64 -> Int -> [SlotDefinition]
  -> IO (Either SlotConfigError SlotEvents)
newSlotEventsWith hooks epoch bound definitions
  | bound <= 0 = pure (Left InvalidEventBound)
  | Map.size slots /= length definitions = pure (Left DuplicateSlot)
  | Map.size slots > bound = pure (Left TooManyPendingSlots)
  | otherwise = do
      state <- newTVarIO (ServiceState slots Seq.empty False)
      pure (Right (SlotEvents state hooks))
  where
    slots = Map.fromList
      [ (sdSlot definition, SlotState
          (SlotSnapshot (sdSlot definition) (sdRemovable definition) True epoch) False)
      | definition <- definitions
      ]

snapshotSlots :: SlotEvents -> IO [SlotSnapshot]
snapshotSlots = atomically . snapshotSlotsSTM

-- | Atomic, ascending, and non-acknowledging, including after close.
snapshotSlotsSTM :: SlotEvents -> STM [SlotSnapshot]
snapshotSlotsSTM hub = map slotSnapshot . Map.elems . serviceSlots <$> readTVar (eventsState hub)

-- | Validate every refusal before any write. In particular, returning Left
-- does not rely on STM rollback: callers may inspect it and still commit
-- their surrounding transaction. Cleanup and observations belong outside.
publishPresenceSTM
  :: SlotEvents -> SlotId -> Bool -> STM (Either PresenceError PresenceChange)
publishPresenceSTM hub slot present = do
  state <- readTVar (eventsState hub)
  if serviceClosed state
    then pure (Left PresenceClosed)
    else case Map.lookup slot (serviceSlots state) of
      Nothing -> pure (Left PresenceUnknownSlot)
      Just entry
        | not present && not (ssRemovable snapshot) -> pure (Left PresenceFixedSlot)
        | present == ssPresent snapshot -> pure (Right (PresenceUnchanged epoch))
        | epoch == maxBound -> pure (Left PresenceEpochExhausted)
        | otherwise -> do
            let nextEpoch = epoch + 1
                nextEntry = SlotState (snapshot { ssPresent = present, ssPresenceEpoch = nextEpoch }) True
                pending = if slotPending entry
                  then servicePending state
                  else servicePending state Seq.|> slot
            writeTVar (eventsState hub) state
              { serviceSlots = Map.insert slot nextEntry (serviceSlots state)
              , servicePending = pending
              }
            pure (Right (PresenceChanged nextEpoch))
        where
          snapshot = slotSnapshot entry
          epoch = ssPresenceEpoch snapshot

-- Nothing means an open, empty service; a committed decision always checks
-- closed before pending and acknowledges the chosen flag in this transaction.
decideWaitSTM :: SlotEvents -> STM (Maybe SlotWait)
decideWaitSTM hub = do
  state <- readTVar (eventsState hub)
  if serviceClosed state
    then pure (Just SlotWaitClosed)
    else case Seq.viewl (servicePending state) of
      Seq.EmptyL -> pure Nothing
      slot Seq.:< rest -> do
        writeTVar (eventsState hub) state
          { serviceSlots = Map.adjust (\entry -> entry { slotPending = False }) slot (serviceSlots state)
          , servicePending = rest
          }
        pure (Just (SlotReady slot))

waitSlot :: SlotEvents -> WaitMode -> IO SlotWait
waitSlot hub mode = do
  observeSlotEvents hub WaitCaptured
  observed <- atomically (decideWaitSTM hub)
  decision <- case observed of
    Just ready -> pure ready
    Nothing -> case mode of
      DontBlock -> pure SlotNoEvent
      Block -> do
        -- This is an observation, not proof that a waiter has parked. The
        -- second transaction rechecks closure and pending flags so a change
        -- during the observer cannot be missed. Only STM retry blocks.
        observeSlotEvents hub WaitBeforeRetry
        atomically $ do
          rechecked <- decideWaitSTM hub
          maybe retry pure rechecked
  observeSlotEvents hub (WaitDecisionCommitted decision)
  pure decision

-- | Close and discard all pending flags atomically, retaining last presence.
-- A decision already committed by a waiter remains that waiter's result.
closeSlotEvents :: SlotEvents -> IO ()
closeSlotEvents hub = do
  atomically $ do
    state <- readTVar (eventsState hub)
    writeTVar (eventsState hub) state
      { serviceClosed = True
      , servicePending = Seq.empty
      , serviceSlots = Map.map (\entry -> entry { slotPending = False }) (serviceSlots state)
      }
  observeSlotEvents hub CloseCommitted

observeSlotEvents :: SlotEvents -> NotificationPoint -> IO ()
observeSlotEvents = eventsObserve
