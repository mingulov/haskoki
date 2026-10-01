{-# LANGUAGE OverloadedStrings #-}
module NotificationsSpec (spec) where

import Control.Concurrent (forkIO, forkFinally, myThreadId, killThread, yield)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar, readMVar, tryReadMVar)
import Control.Concurrent.STM (atomically, newTQueueIO, readTQueue, writeTQueue, newTVarIO, readTVar, modifyTVar', check)
import Control.Exception (SomeException, bracket, try)
import Control.Monad (foldM, forM_, replicateM, replicateM_)
import Data.IORef (atomicModifyIORef', modifyIORef', newIORef, readIORef, writeIORef)
import Data.List (sort, sortOn)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Word (Word64)
import Data.Bits (finiteBitSize, shiftL)
import Foreign.C.Types (CULong)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Array (peekArray, pokeArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr, deRefStablePtr)
import Foreign.Storable (peek, poke, sizeOf)
import System.Directory (createDirectoryIfMissing, removeFile)
import System.Environment (lookupEnv, setEnv, unsetEnv)
import System.Timeout (timeout)
import GHC.Conc (threadStatus, ThreadStatus (..), BlockReason (..))
import Test.Tasty (TestTree, testGroup, after, DependencyType (AllFinish))
import Test.Tasty.HUnit (Assertion, assertBool, assertEqual, assertFailure, testCase)

import qualified Data.ByteString.Char8 as BS
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.FFI.Standard
import Haskoki.FFI.Instance
import Haskoki.Model
import Haskoki.Object (resolveHandle)
import Haskoki.Outcome
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.Async (newAsyncTable)
import Haskoki.Runtime.Config (Config (..), ControlCfg (..), TokensCfg (..), TraceCfg (..), defaultConfig)
import Haskoki.Runtime.Control
import Haskoki.Runtime.Events (OverflowPolicy (DropOldest), newEventQueue, newTokenRegistry)
import qualified Haskoki.Runtime.Lifecycle as Life
import Haskoki.Runtime.SlotEvents
import Haskoki.Session (ActiveLogin (..), SessionLogin (..), TokenAuth (..), tokenAuthNew)
import Haskoki.Transition (publishDelta)
import Haskoki.Types (SlotId (..), SessionId (..), ObjectId (..), ExternalHandle (..), Generation (..))

spec :: TestTree
spec = testGroup "Notifications"
  [ testGroup "T-N01"
  [ testCase "caseServingInitialCore" caseServingInitialCore
  , testCase "caseServingCoalesces" caseServingCoalesces
  , testCase "caseServingBound" caseServingBound
  , testCase "caseServingClosedFirst" caseServingClosedFirst
  , testCase "caseServingReferenceTraces" caseServingReferenceTraces
  ]
  , testGroup "T-N03"
    [ testCase "casePresencePublication" casePresencePublication
    , testCase "casePresenceHandleRetirement" casePresenceHandleRetirement
    , testCase "casePresenceGenerationAtomicity" casePresenceGenerationAtomicity
    ]
  , testGroup "T-N04"
    [ testCase "caseServingSlotBoundary" caseServingSlotBoundary
    -- ConfigSpec is the only other HASKOKI_CONFIG writer in the model suite.
    -- Order this real-cell fixture after it; no production constructor seam.
    , after AllFinish "/no per-call env reads after resolve/" $
        testCase "caseServingWaitOutput" caseServingWaitOutput
    , testCase "caseServingFilteredGrowth" caseServingFilteredGrowth
    , testCase "caseServingTokenRequired" caseServingTokenRequired
    ]
  , testGroup "T-N05"
    [ testCase "caseServingWaitCompetition" caseServingWaitCompetition ]
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

-- Catches broadcast/duplicate claims, losing a second pending slot, a poll
-- retrying, and a losing blocker returning early. Observe actual BlockedOnSTM,
-- not just the pre-retry hook; timeouts contain failures and never publish.
caseServingWaitCompetition :: Assertion
caseServingWaitCompetition = forM_ [0, 2] $ \pollers -> forM_ [1, 2] $ \flags -> do
  roles <- newIORef Map.empty
  retrySeen <- newTQueueIO
  pollCaptured <- newTQueueIO
  releasePolls <- newEmptyMVar
  decisions <- newTVarIO []
  let boundedWait label action = timeout 2000000 action >>= maybe (assertFailure label) pure
      parked tid = boundedWait "loser did not park in STM" $ let
        loop = threadStatus tid >>= \state -> case state of
          ThreadBlocked BlockedOnSTM -> pure ()
          ThreadRunning -> yield >> loop
          _ -> assertFailure ("unexpected waiter state: " ++ show state)
        in loop
      hook point = do
        tid <- myThreadId
        role <- Map.lookup tid <$> readIORef roles
        case point of
          WaitCaptured | role == Just DontBlock -> do
            atomically (writeTQueue pollCaptured ())
            readMVar releasePolls
          WaitBeforeRetry -> do
            assertEqual "poll never enters retry" (Just Block) role
            atomically (writeTQueue retrySeen ())
          WaitDecisionCommitted result -> atomically (modifyTVar' decisions (++ [(tid, result)]))
          _ -> pure ()
  bracket (opened (newSlotEventsWith hook 0 2 catalog)) closeSlotEvents $ \hub -> do
    let spawn mode = do
          done <- newEmptyMVar
          tid <- forkFinally (do
            self <- myThreadId
            atomicModifyIORef' roles (\m -> (Map.insert self mode m, ()))
            waitSlot hub mode) (putMVar done)
          pure (tid, done)
        cleanup workers = closeSlotEvents hub >> mapM_ (killThread . fst) workers
        join (_, done) = do
          result <- boundedWait "bounded waiter join" (readMVar done)
          either (assertFailure . show) pure (result :: Either SomeException SlotWait)
    bracket (replicateM 2 (spawn Block)) cleanup $ \blockers -> do
      replicateM_ 2 (boundedWait "pre-retry observation" (atomically (readTQueue retrySeen)))
      mapM_ (parked . fst) blockers
      bracket (replicateM pollers (spawn DontBlock)) cleanup $ \polls -> do
        replicateM_ pollers (boundedWait "poll capture" (atomically (readTQueue pollCaptured)))
        atomically (mapM (\slot -> publishPresenceSTM hub slot False) (take flags [slotA, slotB]))
          >>= assertEqual "publish exactly the requested flags" (replicate flags (Right (PresenceChanged 1)))
        putMVar releasePolls ()
        polled <- mapM join polls
        winners <- boundedWait "one committed success per flag" $ atomically $ do
          seen <- readTVar decisions
          let ready = [(tid, slot) | (tid, SlotReady slot) <- seen]
          check (length ready >= flags)
          pure ready
        assertEqual "exact number of claims" flags (length winners)
        assertEqual "each distinct flag claimed once" (take flags [slotA, slotB]) (sort (map snd winners))
        let losers = filter (\(tid, _) -> tid `notElem` map fst winners) blockers
        forM_ losers $ \worker@(_, done) -> do
          parked (fst worker)
          tryReadMVar done >>= assertBool "parked loser remains undecided" . maybe True (const False)
        closeSlotEvents hub
        blocked <- mapM join blockers
        let outcomes = blocked ++ polled
        assertEqual "no duplicate slot across all callers" (take flags [slotA, slotB])
          (sort [slot | SlotReady slot <- outcomes])
        assertEqual "all undecided blockers closed" (length losers) (length (filter (== SlotWaitClosed) blocked))
        assertEqual "block never returns no-event" 0 (length (filter (== SlotNoEvent) blocked))
        assertBool "polls decide without retry" (all (/= SlotWaitClosed) polled)
        waitSlot hub DontBlock >>= assertEqual "no closed tail" SlotWaitClosed
        putStrLn ("T-N05 competition flags=" ++ show flags ++ " pollers=" ++ show pollers
          ++ " successes=" ++ show flags ++ " duplicates=0 parked-losers=" ++ show (length losers)
          ++ " poll-retries=0 bounded-joins=" ++ show (2 + pollers))

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

-- T-N03: a split publication, a write on a Left arm, or a stale binding
-- revived by a later generation all violate these independently built states.
rightOrFail :: Show e => Either e a -> IO a
rightOrFail = either (assertFailure . show) pure

presenceEnv :: IO Life.Env
presenceEnv = do
  env <- Life.newEnv defaultRules
  forM_ [slotA, slotB] $ \slot -> Life.seatToken env slot >>= rightOrFail
  Life.publish env (StateDelta [DeltaOpenSession (SessionId 1) slotA False,
    DeltaOpenSession (SessionId 2) slotB False]) >>= rightOrFail
  pure env

casePresencePublication :: Assertion
casePresencePublication = do
  env <- presenceEnv
  hub <- fresh
  before <- Life.snapshotPresence env hub
  let invalid = StateDelta [DeltaCloseSession (SessionId 1), DeltaCloseSession (SessionId 999)]
      retire = StateDelta [DeltaCloseSession (SessionId 1)]
  Life.publishPresence env hub invalid slotA False >>= assertEqual "model fault publishes neither half"
    (Left (PresenceModelFault (FaultUnknownSession (SessionId 999))))
  Life.snapshotPresence env hub >>= assertEqual "one STM snapshot unchanged" before
  waitSlot hub DontBlock >>= assertEqual "model failure posts nothing" SlotNoEvent
  forM_ ["unknown", "fixed", "exhausted", "closed"] $ \kind -> do
    e <- presenceEnv
    h <- opened (newSlotEventsWith (const (pure ()))
      (if kind == "exhausted" then maxBound else 0) 2
      [SlotDefinition slotA (kind /= "fixed"), SlotDefinition slotB True])
    if kind == "closed" then closeSlotEvents h else pure ()
    snap <- Life.snapshotPresence e h
    let slot = if kind == "unknown" then SlotId 999 else slotA
        err = case kind of
          "unknown" -> PresenceUnknownSlot
          "fixed" -> PresenceFixedSlot
          "exhausted" -> PresenceEpochExhausted
          _ -> PresenceClosed
    Life.publishPresence e h retire slot False >>= assertEqual (kind ++ " refusal") (Left err)
    Life.snapshotPresence e h >>= assertEqual (kind ++ " preserves both TVars") snap
    waitSlot h DontBlock >>= assertEqual (kind ++ " has no false indication")
      (if kind == "closed" then SlotWaitClosed else SlotNoEvent)
  Life.publishPresence env hub retire slotA False >>= assertEqual "combined retirement"
    (Right (PresenceChanged 1))
  (removed, rows) <- Life.snapshotPresence env hub
  assertEqual "one observation sees closed session" [SessionId 2] (Map.keys (mSessions removed))
  assertEqual "same observation sees absence" [SlotSnapshot slotA True False 1, SlotSnapshot slotB True True 0] rows
  waitSlot hub DontBlock >>= assertEqual "one publication event" (SlotReady slotA)

  -- Concurrent readers exercise the joint snapshot while the marker and hub
  -- alternate. The marker is a session login, avoiding reused session IDs.
  e <- presenceEnv
  h <- fresh
  Life.publish e (StateDelta [DeltaSetSessionLogin (SessionId 1) LoginUser]) >>= rightOrFail
  start <- newEmptyMVar
  done <- newEmptyMVar
  _ <- forkIO $ do
    r <- try $ do
      readMVar start
      forM_ [1 .. 400 :: Int] $ \n -> do
        let present = even n
        Life.publishPresence e h (StateDelta [DeltaSetSessionLogin (SessionId 1)
          (if present then LoginUser else LoginPublic)]) slotA present >>= rightOrFail
    putMVar done (r :: Either SomeException ())
  putMVar start ()
  forM_ [1 .. 800 :: Int] $ \_ -> do
    (m, slots) <- Life.snapshotPresence e h
    let login = ssLogin <$> lookupSession m (SessionId 1)
        present = [ssPresent s | s <- slots, ssSlotId s == slotA]
    assertBool "never observe half-publication" ((login, present) `elem`
      [(Just LoginUser, [True]), (Just LoginPublic, [False])])
  timeout 2000000 (takeMVar done) >>= maybe (assertFailure "publication writer stuck") rightOrFail
  putStrLn "T-N03 casePresencePublication: half_publications=0 checked_refusals=5"

casePresenceHandleRetirement :: Assertion
casePresenceHandleRetirement = do
  let a = SessionId 1; b = SessionId 2; other = SessionId 3
      tok = ObjectId 1; obj = ObjectId 2; unrelated = ObjectId 3
      old = ExternalHandle 1; sessionHandle = ExternalHandle 2; otherHandle = ExternalHandle 3
      auth = tokenAuthNew { taLogin = Just AuthUser, taPrincipal = Just "retained",
        taUserAttempts = 2, taSoAttempts = 1, taSoLocked = True, taAuthEpoch = 7 }
  m <- rightOrFail $ publishDelta (addToken (addToken emptyModel slotA) slotB) $ StateDelta
    [ DeltaOpenSession a slotA False, DeltaOpenSession b slotA False, DeltaOpenSession other slotB False
    , DeltaSetTokenAuth slotA auth, DeltaSetSessionLogin a LoginUser, DeltaSetSessionLogin b LoginUser
    , DeltaCreateObjectFull tok (Map.singleton AttrToken (ValBool True)) Nothing slotA
    , DeltaCreateObjectFull obj Map.empty (Just a) slotA
    , DeltaCreateObjectFull unrelated Map.empty (Just other) slotB
    , DeltaBindHandle old tok, DeltaBindHandle sessionHandle obj, DeltaBindHandle otherHandle unrelated
    ]
  (delta, sessions, releases) <- rightOrFail (prepareStdRemoval defaultRules m slotA)
  assertEqual "all target sessions" [a,b] sessions
  assertEqual "no invented releases" [] releases
  assertBool "permanent deletion, never bump for removal"
    (DeltaUnbindHandle old `elem` unStateDelta delta && not (any isBump (unStateDelta delta)))
  retired <- rightOrFail (publishDelta m delta)
  assertEqual "only unrelated session remains" [other] (Map.keys (mSessions retired))
  assertEqual "park token, destroy session object" [tok, unrelated] (Map.keys (mObjects retired))
  assertEqual "remove all target bindings" [otherHandle] (Map.keys (mHandles retired))
  assertEqual "token object unchanged" (lookupObject m tok) (lookupObject retired tok)
  afterAuth <- maybe (assertFailure "token auth was deleted") pure (lookupTokenAuth retired slotA)
  assertEqual "active login reset" Nothing (taLogin afterAuth)
  assertEqual "auth metadata retained" (taUserAttempts auth, taSoAttempts auth, taSoLocked auth)
    (taUserAttempts afterAuth, taSoAttempts afterAuth, taSoLocked afterAuth)
  assertEqual "monotonic counters unchanged by retirement"
    (mNextSession m, mNextObject m, mNextHandle m)
    (mNextSession retired, mNextObject retired, mNextHandle retired)
  assertEqual "missing unbind is idempotent" (Right retired)
    (publishDelta retired (StateDelta [DeltaUnbindHandle old, DeltaUnbindHandle old]))
  -- Reinsertion/rediscovery gets fresh IDs. Force the object generation to the
  -- old bump value as well: a tombstone-only removal would revive old here.
  let freshHandle = ExternalHandle (mNextHandle retired)
      changed = retired { mObjects = Map.adjust (\o -> o { osGeneration = Generation 2 }) tok (mObjects retired) }
  rediscovered <- rightOrFail $ publishDelta changed $ StateDelta
    [DeltaOpenSession (SessionId (mNextSession retired)) slotA False,
     DeltaBindHandle freshHandle tok, DeltaSetAttributes tok (Map.singleton AttrLabel (ValBytes "new"))]
  assertEqual "old token handle cannot revive" Nothing (resolveHandle rediscovered old)
  assertEqual "old session object handle stays stale" Nothing (resolveHandle rediscovered sessionHandle)
  assertBool "new token handle works" (resolveHandle rediscovered freshHandle /= Nothing)
  assertBool "no handle recycling" (freshHandle > otherHandle)
  putStrLn "T-N03 casePresenceHandleRetirement: stale_handles=2 recycled_ids=0 parked_tokens=1"
  where
    isBump (DeltaBumpHandle _) = True
    isBump _ = False

controlRequest :: String -> [(String, Json)] -> BS.ByteString
controlRequest cmd args = renderJson (JObj [("schema_version", JNum 1), ("command", JStr cmd), ("arguments", JObj args)])

newPresenceControl :: Word64 -> IO () -> Bool -> PresenceOwner -> IO ControlState
newPresenceControl seed allocation enabled owner = do
  queue <- newEventQueue 8 DropOldest
  table <- newAsyncTable 8
  reg <- newTokenRegistry queue table
  ctl <- newControlStateWith seed allocation defaultConfig reg table enabled False
  bindPresenceOwner ctl (Just owner)
  pure ctl

casePresenceGenerationAtomicity :: Assertion
casePresenceGenerationAtomicity = do
  hub <- fresh
  env <- presenceEnv
  calls <- newIORef (0 :: Int)
  allocations <- newIORef (0 :: Int)
  let owner = PresenceOwner (snapshotSlots hub) $ \slot present -> do
        modifyIORef' calls (+1)
        fmap (fmap (\change -> (change, 0))) (Life.publishPresence env hub (StateDelta []) slot present)
      req = controlRequest "token.remove" [("slot", JNum 1), ("expected_generation", JNum 0)]
      view ctl = (,,) <$> Life.snapshotPresence env hub <*> controlGeneration ctl <*> readIORef calls
  ctl <- newPresenceControl 0 (modifyIORef' allocations (+1)) True owner
  dispatchControl ctl (error "query parsed request") Nothing >>= assertEqual "query executes nothing" (0, BS.empty, 65536)
  dispatchControl ctl (error "short buffer parsed request") (Just 65535) >>= assertEqual "short executes nothing" (0x150, BS.empty, 65536)
  readIORef calls >>= assertEqual "zero owner calls" 0
  readIORef allocations >>= assertEqual "no reply allocation on query/short" 0
  before <- view ctl
  forM_ ["malformed", controlRequest "unknown" [], controlRequest "token.remove" [("slot", JNum 99)],
      controlRequest "token.remove" [("slot", JNum 1), ("expected_generation", JNum 1)]] $ \bad -> do
    -- An unknown slot reaches owner validation but still changes neither half.
    (rv, bytes, len) <- dispatchControl ctl bad (Just 65536)
    assertEqual "checked failure RV" 0x07 rv
    assertBool "bounded error envelope" (len == fromIntegral (BS.length bytes) && len <= 65536)
    (m, g, _) <- view ctl
    let (original, originalG, _) = before
    assertEqual "all model/presence state retained" original m
    assertEqual "generation retained" originalG g
    waitSlot hub DontBlock >>= assertEqual "checked control failure emits no event" SlotNoEvent
  disabled <- newPresenceControl 0 (pure ()) False owner
  exhausted <- newPresenceControl maxBound (pure ()) True owner
  forM_ [disabled, exhausted] $ \c -> do
    beforeCalls <- readIORef calls
    (rv, _, _) <- dispatchControl c (controlRequest "token.remove" [("slot", JNum 1)]) (Just 65536)
    assertEqual "disabled/exhausted refuse before owner" 7 rv
    readIORef calls >>= assertEqual "no cleanup claim" beforeCalls
  controlGeneration exhausted >>= assertEqual "generation never wraps" maxBound
  start <- newEmptyMVar
  answers <- replicateM 2 newEmptyMVar
  forM_ answers $ \answer -> do
    _ <- forkIO $ do
      readMVar start
      r <- try (dispatchControl ctl req (Just 65536))
      putMVar answer (r :: Either SomeException (Word64, BS.ByteString, Word64))
    pure ()
  putMVar start ()
  results <- mapM (\answer -> timeout 2000000 (takeMVar answer) >>= maybe (assertFailure "dispatch deadlock") rightOrFail) answers
  assertEqual "one accepted mutation, one stale generation" [0,7] (sort [rv | (rv,_,_) <- results])
  controlGeneration ctl >>= assertEqual "one accepted command" 1
  snapshotSlots hub >>= assertEqual "one changed presence epoch"
    [SlotSnapshot slotA True False 1, SlotSnapshot slotB True True 0]
  (rv, _, _) <- dispatchControl ctl (controlRequest "token.remove" [("slot", JNum 1), ("expected_generation", JNum 1)]) (Just 65536)
  assertEqual "accepted idempotent removal" 0 rv
  controlGeneration ctl >>= assertEqual "idempotence counts a command" 2
  snapshotSlots hub >>= assertEqual "idempotence does not count an epoch"
    [SlotSnapshot slotA True False 1, SlotSnapshot slotB True True 0]
  waitSlot hub DontBlock >>= assertEqual "one pending flag" (SlotReady slotA)
  waitSlot hub DontBlock >>= assertEqual "no idempotence flag" SlotNoEvent
  forM_ [(PresenceClosed, 0x190), (PresenceModelFault (FaultInternal "injected"), 0x06)] $ \(err, want) -> do
    c <- newPresenceControl 0 (pure ()) True (owner { ownerSetPresence = \_ _ -> pure (Left err) })
    (code, _, _) <- dispatchControl c req (Just 65536)
    assertEqual "typed operational failure" want code
    controlGeneration c >>= assertEqual "operational refusal doesn't bump" 0
  assertEqual "typed boundary mapping" [7,0x190,6]
    (map controlFailureRV [ControlInvalid "bad", ControlUnavailable, ControlPublishFault (FaultInternal "bad")])
  refused <- newPresenceControl 0 (ioError (userError "reply allocation")) True owner
  beforeClaim <- view refused
  failed <- try (dispatchControl refused req (Just 65536)) :: IO (Either SomeException (Word64, BS.ByteString, Word64))
  assertBool "allocation fault observed" (case failed of Left _ -> True; _ -> False)
  view refused >>= assertEqual "allocation refused before claim" beforeClaim
  -- A response's echo must be checked before a mutation; an oversized echo
  -- cannot turn a successful mutation into BUFFER_TOO_SMALL afterward.
  let huge = renderJson (JObj [("schema_version", JNum 1), ("command", JStr "token.insert"),
        ("arguments", JObj [("slot", JNum 1)]), ("correlation_id", JStr (replicate 65536 'x'))])
  snap <- view ctl
  (largeRV, largeBody, largeLen) <- dispatchControl ctl huge (Just 65536)
  assertEqual "oversized request refuses" 7 largeRV
  assertBool "refusal envelope bounded" (BS.length largeBody <= 65536 && largeLen <= 65536)
  view ctl >>= assertEqual "oversized echo mutates nothing" snap
  putStrLn "T-N03 casePresenceGenerationAtomicity: accepted=1 stale=1 idempotent_commands=1 allocation_claims=0"


-- T-N04 exercises the actual Haskell adapters. The independent native probes
-- own C guard/lock ordering; these cases catch wrong serving snapshots, private
-- FIFO routing, speculative output writes and resurrection of retired handles.
boundaryConfig :: Bool -> Config
boundaryConfig removable = defaultConfig
  { cfgControl = (cfgControl defaultConfig) { ccTestEnabled = removable }
  , cfgTokens = TokensCfg [("haskoki-demo", "5678", "1234"), ("second", "5678", "1234")]
  , cfgTrace = (cfgTrace defaultConfig) { tcEnabled = False }
  }

withBoundary :: Bool -> (StablePtr StdInstance -> StdInstance -> IO a) -> IO a
withBoundary removable action =
  bracket (openStdInstance (boundaryConfig removable)) haskokiStdClose $ \ctx -> do
    assertBool "boundary fixture opens" (castStablePtrToPtr ctx /= nullPtr)
    deRefStablePtr ctx >>= action ctx

sentinel :: CULong
sentinel = 0xa5a5a5a5a5a5a5a5

-- Full allocation comparisons include both guards and every unused output word.
withWords :: Int -> (Ptr CULong -> IO [CULong] -> IO a) -> IO a
withWords n action = allocaBytes ((n + 2) * sizeOf sentinel) $ \raw -> do
  let wordsPtr = castPtr raw :: Ptr CULong
      output = wordsPtr `plusPtr` sizeOf sentinel
  pokeArray wordsPtr (replicate (n + 2) sentinel)
  action output (peekArray (n + 2) wordsPtr)

changePresence :: StdInstance -> Int -> Bool -> Assertion
changePresence inst slot present = do
  result <- setStdTokenPresence inst (SlotId slot) present
  case result of
    Right (PresenceChanged _, 0) -> pure ()
    _ -> assertFailure ("presence transition: " ++ show result)

caseServingSlotBoundary :: Assertion
caseServingSlotBoundary = forM_ [False, True] $ \removable ->
  withBoundary removable $ \ctx inst -> withWords 2 $ \out inspect -> withWords 1 $ \count countBytes -> do
    haskokiStdGetSlotList ctx 0 out nullPtr >>= assertEqual "null count" 7
    inspect >>= assertEqual "null count preserves full allocation" (replicate 4 sentinel)
    haskokiStdGetSlotList ctx 0 nullPtr count >>= assertEqual "count query ignores input" 0
    countBytes >>= assertEqual "count only" [sentinel, 2, sentinel]
    forM_ [0, 1] $ \cap -> do
      poke count cap
      haskokiStdGetSlotList ctx 0 out count >>= assertEqual "short list" 0x150
      inspect >>= assertEqual "short array unchanged" (replicate 4 sentinel)
      countBytes >>= assertEqual "short updates count only" [sentinel, 2, sentinel]
    haskokiStdGetSlotList ctx 0 out count >>= assertEqual "adequate full list" 0
    inspect >>= assertEqual "ascending full list and canaries" [sentinel, 0, 1, sentinel]
    forM_ [1, 2, 255] $ \truth -> do
      haskokiStdGetSlotList ctx truth nullPtr count >>= assertEqual "nonzero CK_BBOOL" 0
      peek count >>= assertEqual "both initially present" 2
    withWords 1 $ \flags flagBytes -> do
      haskokiStdGetSlotFlags ctx 99 nullPtr >>= assertEqual "unknown before null" 3
      haskokiStdGetSlotFlags ctx 99 flags >>= assertEqual "unknown slot" 3
      flagBytes >>= assertEqual "unknown flags untouched" [sentinel, sentinel, sentinel]
      haskokiStdGetSlotFlags ctx 0 nullPtr >>= assertEqual "known null output" 7
      haskokiStdGetSlotFlags ctx 0 flags >>= assertEqual "known flags" 0
      flagBytes >>= assertEqual "present/removable, hardware clear"
        [sentinel, if removable then 3 else 1, sentinel]
      if removable then do
        changePresence inst 0 False
        haskokiStdGetSlotFlags ctx 0 flags >>= assertEqual "empty slot is valid" 0
        flagBytes >>= assertEqual "removable only" [sentinel, 2, sentinel]
        haskokiStdGetSlotFlags ctx 0 nullPtr >>= assertEqual "empty null flags" 7
        waitSlot (siSlots inst) DontBlock >>= assertEqual "slot reads never acknowledge" (SlotReady (SlotId 0))
      else pure ()
      closeSlotEvents (siSlots inst)
      poke flags sentinel
      poke count sentinel
      haskokiStdGetSlotFlags ctx 0 flags >>= assertEqual "closed flags" 0x190
      haskokiStdGetSlotFlags ctx 99 nullPtr >>= assertEqual "closed before slot/pointer" 0x190
      haskokiStdGetSlotList ctx 0 out count >>= assertEqual "closed list" 0x190
      haskokiStdGetSlotList ctx 0 nullPtr nullPtr >>= assertEqual "closed before count" 0x190
      flagBytes >>= assertEqual "closed flags untouched" [sentinel, sentinel, sentinel]
      countBytes >>= assertEqual "closed count untouched" [sentinel, sentinel, sentinel]

caseServingWaitOutput :: Assertion
caseServingWaitOutput = do
  createDirectoryIfMissing True "/tmp/haskoki-notifications"
  let path = "/tmp/haskoki-notifications/model-wait-config.toml"
  bracket (lookupEnv "HASKOKI_CONFIG")
    (\old -> maybe (unsetEnv "HASKOKI_CONFIG") (setEnv "HASKOKI_CONFIG") old) $ \_ ->
    bracket (writeFile path (unlines
      [ "schema_version = 1", "[control]", "test_enabled = true"
      , "[trace]", "enabled = false"
      ])) (const (removeFile path)) $ \_ -> do
      setEnv "HASKOKI_CONFIG" path
      bracket haskokiInstanceOpen haskokiInstanceClose $ \cell -> do
        assertBool "real cell opens" (castStablePtrToPtr cell /= nullPtr)
        Just ops <- readLiveInstance cell
        bracket (haskokiStdOpen cell) haskokiStdClose $ \ctx -> do
          assertBool "standard borrows real cell" (castStablePtrToPtr ctx /= nullPtr)
          inst <- deRefStablePtr ctx
          withWords 1 $ \out inspect -> do
            haskokiWaitForSlotEvent cell 1 out >>= assertEqual "empty poll" 8
            inspect >>= assertEqual "no event preserves all bytes" [sentinel, sentinel, sentinel]
            changePresence inst 0 False
            haskokiWaitForSlotEvent cell 1 nullPtr >>= assertEqual "null output no claim" 7
            forM_ [2, 3, 1 `shiftL` (finiteBitSize sentinel - 1)] $ \flags -> do
              haskokiWaitForSlotEvent cell flags out >>= assertEqual "native-width unknown flags" 7
              inspect >>= assertEqual "invalid wait preserves all bytes" [sentinel, sentinel, sentinel]
            haskokiWaitForSlotEvent cell 1 out >>= assertEqual "pending absent slot poll" 0
            inspect >>= assertEqual "one output word" [sentinel, 0, sentinel]
            poke out sentinel
            haskokiWaitForSlotEvent cell 1 out >>= assertEqual "one consumption" 8
            inspect >>= assertEqual "empty again unchanged" [sentinel, sentinel, sentinel]
            closeSlotEvents (instSlots ops)
            forM_ [0, 1] $ \flags -> do
              haskokiWaitForSlotEvent cell flags out >>= assertEqual "closed shared service" 0x190
              inspect >>= assertEqual "closed service unchanged" [sentinel, sentinel, sentinel]
            haskokiInstanceClose cell
            haskokiWaitForSlotEvent cell 3 nullPtr >>= assertEqual "closed cell lifecycle first" 0x190

caseServingFilteredGrowth :: Assertion
caseServingFilteredGrowth = withBoundary True $ \ctx inst ->
  withWords 2 $ \out inspect -> withWords 1 $ \count countBytes -> do
    haskokiStdGetSlotList ctx 2 nullPtr count >>= assertEqual "initial query" 0
    peek count >>= assertEqual "initial count 2" 2
    changePresence inst 0 False
    haskokiStdGetSlotList ctx 0 nullPtr count >>= assertEqual "full query while empty" 0
    peek count >>= assertEqual "full count retains empty slot" 2
    haskokiStdGetSlotList ctx 2 nullPtr count >>= assertEqual "filtered query" 0
    peek count >>= assertEqual "filtered count 1" 1
    haskokiStdGetSlotList ctx 2 out count >>= assertEqual "filtered fetch" 0
    inspect >>= assertEqual "only present slot" [sentinel, 1, sentinel, sentinel]
    pokeArray out [sentinel, sentinel]
    changePresence inst 0 True
    haskokiStdGetSlotList ctx 2 out count >>= assertEqual "growth needs retry" 0x150
    inspect >>= assertEqual "short growth preserves entire array" (replicate 4 sentinel)
    countBytes >>= assertEqual "filtered count grows to 2" [sentinel, 2, sentinel]
    haskokiStdGetSlotList ctx 2 out count >>= assertEqual "growth retry" 0
    inspect >>= assertEqual "ascending retry" [sentinel, 0, 1, sentinel]
    waitSlot (siSlots inst) DontBlock >>= assertEqual "queries/fetches never consume coalesced event" (SlotReady (SlotId 0))
    waitSlot (siSlots inst) DontBlock >>= assertEqual "exactly one pending slot" SlotNoEvent

caseServingTokenRequired :: Assertion
caseServingTokenRequired = withBoundary True $ \ctx inst -> withWords 6 $ \out inspect -> do
  haskokiStdOpenSession ctx 0 0 out >>= assertEqual "open old session" 0
  old <- peek out
  changePresence inst 0 False
  pokeArray out (replicate 6 sentinel)
  forM_ [(99, 3), (0, 0xe0)] $ \(slot, expected) -> do
    haskokiStdSlotPresent ctx slot >>= assertEqual "token-required existence/presence" expected
    forM_ [nullPtr, castPtr out] $ \label ->
      haskokiStdTokenLabel ctx slot label >>= assertEqual "label before output shape" expected
    forM_ [nullPtr, out] $ \scalar ->
      haskokiStdTokenLive ctx slot scalar scalar scalar scalar scalar scalar
        >>= assertEqual "token scalars before output shape" expected
    haskokiStdOpenSession ctx slot 0 out >>= assertEqual "open token required" expected
    inspect >>= assertEqual "every token refusal preserves whole allocation" (replicate 8 sentinel)
  haskokiStdCloseAllSessions ctx 0 >>= assertEqual "empty close all succeeds" 0
  haskokiStdCloseAllSessions ctx 99 >>= assertEqual "unknown close all" 3
  waitSlot (siSlots inst) DontBlock >>= assertEqual "only removal produced" (SlotReady (SlotId 0))
  waitSlot (siSlots inst) DontBlock >>= assertEqual "close all not a producer" SlotNoEvent
  changePresence inst 0 True
  haskokiStdGetSessionInfo ctx old out out out out >>= assertEqual "retired info after reinsertion" 0xb3
  haskokiStdSessionCancel ctx old 0 >>= assertEqual "retired cancel after reinsertion" 0xb3
  haskokiStdCloseSession ctx old >>= assertEqual "retired close after reinsertion" 0xb3
  inspect >>= assertEqual "retired session outputs untouched" (replicate 8 sentinel)
  haskokiStdOpenSession ctx 0 0 out >>= assertEqual "new session admitted" 0
  new <- peek out
  assertBool "session handle never resurrected" (new /= old)
  haskokiStdCloseAllSessions ctx 0 >>= assertEqual "close new sessions" 0
  waitSlot (siSlots inst) DontBlock >>= assertEqual "only insertion produced" (SlotReady (SlotId 0))
  waitSlot (siSlots inst) DontBlock >>= assertEqual "session operations produce nothing" SlotNoEvent
  closeSlotEvents (siSlots inst)
  pokeArray out (replicate 6 sentinel)
  haskokiStdTokenLabel ctx 0 (castPtr out) >>= assertEqual "closed label" 0x190
  haskokiStdTokenLive ctx 0 out out out out out out >>= assertEqual "closed token scalars" 0x190
  haskokiStdSlotPresent ctx 0 >>= assertEqual "closed token check" 0x190
  haskokiStdOpenSession ctx 0 0 out >>= assertEqual "closed admission" 0x190
  haskokiStdCloseAllSessions ctx 0 >>= assertEqual "closed close all" 0x190
  inspect >>= assertEqual "closed outputs unchanged" (replicate 8 sentinel)
