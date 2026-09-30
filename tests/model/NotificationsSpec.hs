module NotificationsSpec (spec) where

import Control.Concurrent.STM (atomically)
import Control.Monad (foldM, forM_, replicateM)
import Data.IORef (modifyIORef', newIORef, readIORef, writeIORef)
import Data.List (sort, sortOn)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Word (Word64)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, assertEqual, assertFailure, testCase)

import Haskoki.Runtime.SlotEvents
import Haskoki.Types (SlotId (..))

spec :: TestTree
spec = testGroup "Notifications/T-N01"
  [ testCase "caseServingInitialCore" caseServingInitialCore
  , testCase "caseServingCoalesces" caseServingCoalesces
  , testCase "caseServingBound" caseServingBound
  , testCase "caseServingClosedFirst" caseServingClosedFirst
  , testCase "caseServingReferenceTraces" caseServingReferenceTraces
  ]

slotA, slotB :: SlotId
slotA = SlotId 1
slotB = SlotId 2

catalog :: [SlotDefinition]
catalog = [SlotDefinition slotB True, SlotDefinition slotA True]

opened :: IO (Either SlotConfigError SlotEvents) -> IO SlotEvents
opened action = action >>= either (fail . show) pure

fresh :: IO SlotEvents
fresh = opened (newSlotEvents 2 catalog)

publish :: SlotEvents -> SlotId -> Bool -> IO (Either PresenceError PresenceChange)
publish hub slot present = atomically (publishPresenceSTM hub slot present)

snapshots :: String -> SlotEvents -> [SlotSnapshot] -> Assertion
snapshots label hub expected = do
  snapshotSlots hub >>= assertEqual (label ++ ": IO snapshot") expected
  atomically (snapshotSlotsSTM hub) >>= assertEqual (label ++ ": STM snapshot") expected

-- Catches fabricated initial flags, unsorted catalogs, read acknowledgments,
-- idempotent increments, fixed-slot mutation, and a lost pre-retry transition.
caseServingInitialCore :: Assertion
caseServingInitialCore = do
  hub <- opened (newSlotEvents 2 [SlotDefinition slotB False, SlotDefinition slotA True])
  let initial = [SlotSnapshot slotA True True 0, SlotSnapshot slotB False True 0]
  snapshots "initially present, epoch zero, ascending" hub initial
  waitSlot hub DontBlock >>= assertEqual "initial flags clear" SlotNoEvent
  publish hub slotA True >>= assertEqual "present is idempotent" (Right (PresenceUnchanged 0))
  publish hub slotB True >>= assertEqual "fixed insertion is idempotent" (Right (PresenceUnchanged 0))
  publish hub slotB False >>= assertEqual "fixed removal refused" (Left PresenceFixedSlot)
  publish hub (SlotId 99) False >>= assertEqual "unknown removal refused" (Left PresenceUnknownSlot)
  publish hub (SlotId 99) True >>= assertEqual "unknown insertion refused" (Left PresenceUnknownSlot)
  snapshots "refusals and idempotence leave state intact" hub initial
  waitSlot hub DontBlock >>= assertEqual "refusals and idempotence set no flag" SlotNoEvent

  -- The hook runs IO (including STM) before the blocking transaction rechecks.
  -- A timeout contains a lost-wakeup defect; it does not schedule publication.
  points <- newIORef []
  beforeRetry <- newIORef (pure ())
  let hooks point = do
        modifyIORef' points (++ [point])
        case point of
          WaitBeforeRetry -> readIORef beforeRetry >>= id
          _ -> pure ()
  hooked <- opened (newSlotEventsWith hooks 0 2 catalog)
  writeIORef beforeRetry $ do
    publish hooked slotA False >>= assertEqual "hook publication" (Right (PresenceChanged 1))
  timeout 2000000 (waitSlot hooked Block) >>= assertEqual "recheck sees hook publication" (Just (SlotReady slotA))
  readIORef points >>= assertEqual "observers follow committed decision"
    [WaitCaptured, WaitBeforeRetry, WaitDecisionCommitted (SlotReady slotA)]
  observeSlotEvents hooked RemovalPrepublication
  readIORef points >>= assertEqual "explicit coordinator observation"
    [WaitCaptured, WaitBeforeRetry, WaitDecisionCommitted (SlotReady slotA), RemovalPrepublication]

-- Catches edge FIFO, moving an already pending slot, and forgetting to clear
-- the acknowledged flag so that a later transition cannot append it again.
caseServingCoalesces :: Assertion
caseServingCoalesces = do
  hub <- fresh
  forM_ [(False, 1), (True, 2), (False, 3)] $ \(present, epoch) ->
    publish hub slotA present >>= assertEqual "real transition epoch" (Right (PresenceChanged epoch))
  publish hub slotA False >>= assertEqual "absent is idempotent" (Right (PresenceUnchanged 3))
  snapshots "remove/insert/remove coalesces" hub
    [SlotSnapshot slotA True False 3, SlotSnapshot slotB True True 0]
  waitSlot hub DontBlock >>= assertEqual "reads did not acknowledge A" (SlotReady slotA)
  waitSlot hub DontBlock >>= assertEqual "one flag for three transitions" SlotNoEvent
  publish hub slotA False >>= assertEqual "idempotence after acknowledgment" (Right (PresenceUnchanged 3))
  waitSlot hub DontBlock >>= assertEqual "idempotence does not reappend" SlotNoEvent

  ordered <- fresh
  publish ordered slotA False >>= assertEqual "A first pending" (Right (PresenceChanged 1))
  publish ordered slotB False >>= assertEqual "B second pending" (Right (PresenceChanged 1))
  publish ordered slotA True >>= assertEqual "pending A changes again" (Right (PresenceChanged 2))
  snapshots "reads preserve both flags" ordered
    [SlotSnapshot slotA True True 2, SlotSnapshot slotB True False 1]
  waitSlot ordered DontBlock >>= assertEqual "A keeps first position" (SlotReady slotA)
  publish ordered slotA False >>= assertEqual "consumed A changes" (Right (PresenceChanged 3))
  waitSlot ordered Block >>= assertEqual "pending B precedes reappended A" (SlotReady slotB)
  waitSlot ordered DontBlock >>= assertEqual "A reappended once" (SlotReady slotA)
  waitSlot ordered DontBlock >>= assertEqual "all flags acknowledged" SlotNoEvent

-- Catches unchecked catalogs, clamped/dropped pending flags, wrapping epochs,
-- and an exhausted publication that partially writes presence or pending state.
caseServingBound :: Assertion
caseServingBound = do
  let refused label expected action = do
        result <- action
        case result of
          Left actual -> assertEqual label expected actual
          Right _ -> assertFailure (label ++ ": unexpectedly opened")
  refused "duplicate IDs" DuplicateSlot
    (newSlotEvents 2 [SlotDefinition slotA True, SlotDefinition slotA False])
  refused "zero bound" InvalidEventBound (newSlotEvents 0 [])
  refused "negative bound" InvalidEventBound (newSlotEvents (-1) catalog)
  refused "bound below catalog size" TooManyPendingSlots (newSlotEvents 1 catalog)
  empty <- opened (newSlotEvents 1 [])
  snapshots "empty catalog" empty []
  waitSlot empty DontBlock >>= assertEqual "empty catalog poll" SlotNoEvent
  let slots = map SlotId [1..16]
  full <- opened (newSlotEvents 16 [SlotDefinition slot True | slot <- reverse slots])
  forM_ slots $ \slot ->
    publish full slot False >>= assertEqual "all 16 admitted" (Right (PresenceChanged 1))
  snapshots "all 16 retained" full [SlotSnapshot slot True False 1 | slot <- slots]
  replicateM 16 (waitSlot full DontBlock) >>= assertEqual "16/16 pending, no loss" (map SlotReady slots)
  waitSlot full DontBlock >>= assertEqual "exactly 16 flags" SlotNoEvent

  let penultimate = maxBound - 1 :: Word64
  exhausted <- opened (newSlotEventsWith (const (pure ())) penultimate 2 catalog)
  publish exhausted slotA False >>= assertEqual "last epoch transition" (Right (PresenceChanged maxBound))
  publish exhausted slotA True >>= assertEqual "no wrap while pending" (Left PresenceEpochExhausted)
  publish exhausted slotA False >>= assertEqual "live max epoch idempotence" (Right (PresenceUnchanged maxBound))
  snapshots "refusal retains last presence and epoch" exhausted
    [SlotSnapshot slotA True False maxBound, SlotSnapshot slotB True True penultimate]
  waitSlot exhausted DontBlock >>= assertEqual "refusal retains the existing flag" (SlotReady slotA)
  publish exhausted slotA True >>= assertEqual "no wrap after acknowledgment" (Left PresenceEpochExhausted)
  publish exhausted slotA False >>= assertEqual "max idempotence after acknowledgment" (Right (PresenceUnchanged maxBound))
  waitSlot exhausted DontBlock >>= assertEqual "refusal creates no flag" SlotNoEvent

-- Catches queue-before-close inspection, fabricated removal on close, and
-- accepting any publication (even idempotence) on a closed interval.
caseServingClosedFirst :: Assertion
caseServingClosedFirst = do
  forM_ [False, True] $ \nonempty -> do
    hub <- fresh
    if nonempty
      then do
        publish hub slotA False >>= assertEqual "pending A before close" (Right (PresenceChanged 1))
        publish hub slotB False >>= assertEqual "pending B before close" (Right (PresenceChanged 1))
      else pure ()
    let lastSnapshot = [SlotSnapshot slot True (not nonempty) (if nonempty then 1 else 0) | slot <- [slotA, slotB]]
    closeSlotEvents hub
    closeSlotEvents hub
    snapshots "close retains last snapshot" hub lastSnapshot
    forM_ [DontBlock, Block, DontBlock, Block] $ \mode ->
      timeout 2000000 (waitSlot hub mode) >>= assertEqual "zero closed-tail successes" (Just SlotWaitClosed)
    forM_ [slotA, slotB, SlotId 99] $ \slot ->
      forM_ [False, True] $ \present ->
        publish hub slot present >>= assertEqual "closed refuses every publication" (Left PresenceClosed)
    snapshots "closed refusals leave snapshot intact" hub lastSnapshot

  beforeRetry <- newIORef (pure ())
  closedSnapshot <- newIORef []
  let hooks point = case point of
        WaitBeforeRetry -> readIORef beforeRetry >>= id
        CloseCommitted -> modifyIORef' closedSnapshot (++ [point])
        _ -> pure ()
  hub <- opened (newSlotEventsWith hooks 0 2 catalog)
  writeIORef beforeRetry (closeSlotEvents hub)
  timeout 2000000 (waitSlot hub Block) >>= assertEqual "recheck sees hook close" (Just SlotWaitClosed)
  readIORef closedSnapshot >>= assertEqual "close observer runs after commit" [CloseCommitted]

data Input = InsertA | RemoveA | InsertB | RemoveB | Poll | Snapshot | Close
  deriving (Eq, Show)

inputName :: Input -> String
inputName input = case input of
  InsertA -> "insertA"
  RemoveA -> "removeA"
  InsertB -> "insertB"
  RemoveB -> "removeB"
  Poll -> "poll"
  Snapshot -> "snapshot"
  Close -> "close"

data Observation
  = Publication (Either PresenceError PresenceChange)
  | Polled SlotWait
  | Inspected [SlotSnapshot]
  | Closed
  deriving (Eq, Show)

-- Independent oracle: presence plus a mathematical set of first-pending
-- sequence tags. No implementation queue, flags, or helper is reused.
data Reference = Reference
  { refPresence :: Map.Map SlotId (Bool, Word64)
  , refPending :: Set.Set (Integer, SlotId)
  , refSequence :: Integer
  , refClosed :: Bool
  }

referenceInitial :: Reference
referenceInitial = Reference (Map.fromList [(slotA, (True, 0)), (slotB, (True, 0))]) Set.empty 0 False

referenceSnapshot :: Reference -> [SlotSnapshot]
referenceSnapshot model =
  [SlotSnapshot slot True present epoch | (slot, (present, epoch)) <- Map.toAscList (refPresence model)]

referenceStep :: Reference -> Input -> (Reference, Observation)
referenceStep model input = case input of
  InsertA -> presence slotA True
  RemoveA -> presence slotA False
  InsertB -> presence slotB True
  RemoveB -> presence slotB False
  Snapshot -> (model, Inspected (referenceSnapshot model))
  Close -> (model { refClosed = True, refPending = Set.empty }, Closed)
  Poll
    | refClosed model -> (model, Polled SlotWaitClosed)
    | otherwise -> case Set.minView (refPending model) of
        Nothing -> (model, Polled SlotNoEvent)
        Just ((_, slot), rest) -> (model { refPending = rest }, Polled (SlotReady slot))
  where
    presence slot present
      | refClosed model = (model, Publication (Left PresenceClosed))
      | otherwise = case Map.lookup slot (refPresence model) of
          Nothing -> (model, Publication (Left PresenceUnknownSlot))
          Just (previous, epoch)
            | previous == present -> (model, Publication (Right (PresenceUnchanged epoch)))
            | epoch == maxBound -> (model, Publication (Left PresenceEpochExhausted))
            | otherwise ->
                let next = refSequence model + 1
                    pending = if any ((== slot) . snd) (Set.toList (refPending model))
                      then refPending model
                      else Set.insert (next, slot) (refPending model)
                in ( model { refPresence = Map.insert slot (present, epoch + 1) (refPresence model)
                           , refPending = pending, refSequence = next }
                   , Publication (Right (PresenceChanged (epoch + 1))) )

actualStep :: SlotEvents -> Input -> IO Observation
actualStep hub input = case input of
  InsertA -> Publication <$> publish hub slotA True
  RemoveA -> Publication <$> publish hub slotA False
  InsertB -> Publication <$> publish hub slotB True
  RemoveB -> Publication <$> publish hub slotB False
  Poll -> Polled <$> waitSlot hub DontBlock
  Snapshot -> Inspected <$> snapshotSlots hub
  Close -> closeSlotEvents hub >> pure Closed

-- Catches combinations of coalescing, reads, idempotence and close that the
-- concrete examples miss; every command result and every snapshot is checked.
caseServingReferenceTraces :: Assertion
caseServingReferenceTraces = do
  let alphabet = sortOn inputName [InsertA, RemoveA, InsertB, RemoveB, Poll, Snapshot, Close]
      traces = replicateM 4 alphabet
      named = map (map inputName) traces
  assertEqual "exactly 2401 length-four traces" 2401 (length traces)
  assertEqual "lexical trace order" (sort named) named
  assertEqual "no duplicate traces" 2401 (Set.size (Set.fromList named))
  forM_ (zip [1 :: Int ..] traces) $ \(number, inputs) -> do
    hub <- fresh
    let label step = "trace " ++ show number ++ " " ++ show (map inputName inputs) ++ ", step " ++ show step
    snapshots (label (0 :: Int)) hub (referenceSnapshot referenceInitial)
    _ <- foldM (\model (step, input) -> do
      let (next, expected) = referenceStep model input
      actualStep hub input >>= assertEqual (label step ++ ": result") expected
      snapshots (label step) hub (referenceSnapshot next)
      pure next) referenceInitial (zip [1 :: Int ..] inputs)
    pure ()
  putStrLn "T-N01 reference traces: 2401/2401 (length four, lexical order)"
