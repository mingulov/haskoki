{- | Threaded stress proofs.

N Haskell threads drive mixed job\/registry\/event\/store load against
shared handles; the suite asserts CONSERVATION invariants (stable
under scheduling nondeterminism), never interleavings:

* every started job is exactly-once terminal (starts == tombstones,
  delivered == completed, the sink fires exactly once per job);
* the store commit chain is contiguous (@ssCommits == 1+N*M@, the
  committed object set is exact: no lost update, no duplicate);
* no live session aliases a closed one (closed sessions read back
  absent; their reservations go stale);
* no deadlock\/crash\/resurrection (every worker join is
  timeout-guarded and worker failures propagate fast and LOUD).

Tuning: @HASKOKI_SIM_N@\/@HASKOKI_SIM_M@ (threads x iterations);
the pinned defaults (4x25) keep @cabal test@ fast while the C proof
(@tests\/c\/sim_threaded.c@) carries the heavy native load.
-}
{-# LANGUAGE OverloadedStrings #-}
module SimStressSpec (spec) where

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, takeMVar)
import Control.Exception (SomeException, bracket, try)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.List (sort)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust)
import System.Directory
  ( createDirectory
  , doesDirectoryExist
  , getTemporaryDirectory
  , removeDirectoryRecursive
  )
import System.Environment (lookupEnv)
import System.FilePath ((</>))
import System.Timeout (timeout)
import Text.Read (readMaybe)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model, SessionState (..), lookupSession)
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoResult (..))
import Haskoki.Outcome
  ( DeltaOp (..)
  , EffectRequest (..)
  , Reservation (..)
  , RevisionDep (..)
  , StateDelta (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.Async
  ( AsyncTable
  , AsyncWork (..)
  , CompleteOutcome (..)
  , Completion (..)
  , Delivery (..)
  , EffectRunner
  , JobFunction (..)
  , JobRequest (..)
  , PollOutcome (..)
  , abortDetach
  , beginDetach
  , completeJob
  , deliveredCount
  , enableAsyncSession
  , newAsyncTable
  , pollJob
  , startJob
  , tableStats
  )
import Haskoki.Runtime.Events
  ( EventQueue
  , InsertOutcome (..)
  , OverflowPolicy (DropOldest)
  , RemoveOutcome (..)
  , TokenRegistry
  , WaitOutcome (..)
  , droppedEvents
  , insertToken
  , newEventQueue
  , newTokenRegistry
  , registerSessionSlot
  , removeToken
  , tokenGeneration
  , tokenPresent
  , tryWaitSlotEvent
  )
import Haskoki.Runtime.Lifecycle
  ( Env
  , checkReservation
  , newEnv
  , publish
  , seatToken
  , snapshotModel
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , Store (..)
  , StoreDelta (..)
  , StoreStats (..)
  , TokenRecord (..)
  , defaultLimits
  , emptyDelta
  , noFaults
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStoreWith)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStoreWith)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Types
  ( Generation (..)
  , JobId (..)
  , ObjectId (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

spec :: TestTree
spec = testGroup "Sim stress"
  [ testCase "jobs: every start exactly-once terminal under threads" caseJobsConserve
  , testCase "registry: mixed insert/remove/event-wait conserves" caseRegistryConserve
  , testCase "store/memory: N x M threaded commits conserve" caseStoreMemory
  , testCase "store/sqlite: N x M threaded commits conserve" caseStoreSQLite
  , testCase "sessions: close leaves no live alias" caseSessionsClose
  ]

-- ---------------------------------------------------------------------------
-- Harness
-- ---------------------------------------------------------------------------

-- | Stress dimensions from the environment (pinned defaults 4x25,
-- clamped to sane bounds).
simParams :: IO (Int, Int)
simParams = do
  n <- envInt "HASKOKI_SIM_N" 4 1 16
  m <- envInt "HASKOKI_SIM_M" 25 1 200
  pure (n, m)

envInt :: String -> Int -> Int -> Int -> IO Int
envInt name def lo hi = do
  mV <- lookupEnv name
  pure $ case mV >>= readMaybe of
    Just n -> max lo (min hi n)
    Nothing -> def

-- | Fork N workers, await all: worker failures propagate fast with
-- the worker's message; a worker that never finishes fails LOUDLY
-- (deadlock\/stranding surfaces as an assertion, never a hang).
runWorkers :: Int -> (Int -> IO ()) -> IO ()
runWorkers n action = do
  dones <- mapM spawn [0 .. n - 1]
  mapM_ await (zip [0 ..] dones)
  where
    spawn :: Int -> IO (MVar (Either SomeException ()))
    spawn t = do
      v <- newEmptyMVar
      _ <- forkIO (try (action t) >>= putMVar v)
      pure v
    await :: (Int, MVar (Either SomeException ())) -> IO ()
    await (t, v) = do
      mOut <- timeout (60 * 1000000) (takeMVar v)
      case mOut of
        Nothing -> assertFailure ("worker " ++ show t ++ " timed out: deadlock or stranding")
        Just (Left e) -> assertFailure ("worker " ++ show t ++ " failed: " ++ show e)
        Just (Right ()) -> pure ()

-- | Canned effect answer (64 bytes, matching the attached capacity).
cannedSig :: ByteString
cannedSig = BS.replicate 64 0x51

-- | Counting stub runner: records invocations, answers canned bytes.
countingRunner :: IORef Int -> EffectRunner
countingRunner ref _fx = do
  atomicModifyIORef' ref (\c -> (c + 1, ()))
  pure (GotBytes cannedSig)

-- | A sign job request on a session with the given schedule.
signRequest :: SessionId -> Int -> JobRequest
signRequest sid ticks = JobRequest
  { jrSession = sid
  , jrFunction = JobSign
  , jrWork = WorkCall
      (Reservation "stress-sign" [] Nothing Nothing)
      (EffectCrypto (FxSign (MechanismId 0x251) Nothing BS.empty "hello"))
  , jrTicks = ticks
  , jrCapacity = 64
  }

-- | A delivery that counts sink writes into a shared counter.
countingDelivery :: IORef Int -> Delivery
countingDelivery ref = Delivery
  { dCapacity = 64
  , dWrite = \_ -> atomicModifyIORef' ref (\c -> (c + 1, ()))
  , dReportNeeded = \_ -> pure ()
  }

-- | Poll until ready, with a loud iteration bound (never an
-- unbounded loop).
pollTillReady :: EffectRunner -> Env -> AsyncTable -> JobId -> IO ()
pollTillReady run env table jid = go (0 :: Int)
  where
    go k
      | k > 10000 = assertFailure "poll loop exceeded 10000 iterations"
      | otherwise = do
          out <- pollJob run env table JobSign jid
          case out of
            PollReady -> pure ()
            PollPending _ -> go (k + 1)
            other -> assertFailure ("unexpected poll outcome: " ++ show other)

-- | Unwrap a 'Maybe' or fail the test with context.
expectJust :: String -> Maybe a -> IO a
expectJust ctx = maybe (assertFailure ("missing: " ++ ctx)) pure

-- ---------------------------------------------------------------------------
-- Jobs
-- ---------------------------------------------------------------------------

-- | N threads x M sequential start\/poll\/complete cycles against one
-- shared table+env (every 5th start detours through a
-- begin\/abort-detach lease): every start lands exactly-once
-- terminal, the sink fires exactly once per job.
caseJobsConserve :: IO ()
caseJobsConserve = do
  (n, m) <- simParams
  table <- newAsyncTable 64
  env <- newEnv defaultRules
  writes <- newIORef 0
  runs <- newIORef 0
  starts <- newIORef 0
  let sids = [SessionId (200 + t) | t <- [0 .. n - 1]]
  mapM_ (enableAsyncSession table) sids
  runWorkers n $ \t -> do
    let sid = sids !! t
        run = countingRunner runs
        del = countingDelivery writes
    mapM_ (jobOne table env m starts sid run del t) [0 .. m - 1]
  nStarts <- readIORef starts
  nWrites <- readIORef writes
  nRuns <- readIORef runs
  (live, term, nextId) <- tableStats table
  nDelivered <- deliveredCount table
  assertEqual "every start accepted" (n * m) nStarts
  assertEqual "no live job left" 0 live
  assertEqual "every start exactly-once terminal" (n * m) term
  assertEqual "job ids contiguous" (n * m) nextId
  assertEqual "every terminal is a delivery" (n * m) nDelivered
  assertEqual "sink fired exactly once per job" (n * m) nWrites
  assertEqual "effect ran exactly once per job" (n * m) nRuns

-- | One worker iteration: start, detach-lease detour each 5th job,
-- poll to ready, complete with delivery.
jobOne
  :: AsyncTable -> Env -> Int -> IORef Int -> SessionId
  -> EffectRunner -> Delivery -> Int -> Int -> IO ()
jobOne table env m starts sid run del t i = do
  eJid <- startJob table (signRequest sid (1 + (t * m + i) `mod` 3))
  jid <- case eJid of
    Left deny -> assertFailure ("start refused: " ++ show deny)
    Right j -> pure j
  atomicModifyIORef' starts (\c -> (c + 1, ()))
  if i `mod` 5 == 4
    then do
      mLease <- beginDetach table jid
      case mLease of
        Nothing -> assertFailure "detach lease missing for a live job"
        Just lease -> abortDetach lease
    else pure ()
  pollTillReady run env table jid
  out <- completeJob env table JobSign jid del (\_ -> pure ())
  case out of
    CompleteDelivered (CompBytes _) -> pure ()
    other -> assertFailure ("expected delivery, got: " ++ show other)

-- ---------------------------------------------------------------------------
-- Registry + events
-- ---------------------------------------------------------------------------

-- | N threads x M insert\/remove cycles on disjoint slots (each
-- iteration seats one async job on the thread's session so removal
-- quiesce cancels exactly one job): removals report exact quiesce
-- counts, every posted event drains exactly once, nothing drops, and
-- every touched slot ends absent at generation 2.
caseRegistryConserve :: IO ()
caseRegistryConserve = do
  (n, m) <- simParams
  eq <- newEventQueue (2 * n * m + 64) DropOldest
  at <- newAsyncTable 64
  reg <- newTokenRegistry eq at
  let sids = [SessionId (100 + t) | t <- [0 .. n - 1]]
  mapM_ (enableAsyncSession at) sids
  runWorkers n $ \t -> do
    let sid = sids !! t
    mapM_ (regOne at reg m sid t) [0 .. m - 1]
  drained <- drainEvents eq 0
  dropped <- droppedEvents eq
  assertEqual "every posted event drains exactly once" (2 * n * m) drained
  assertEqual "nothing dropped" 0 dropped
  mapM_ (assertSlotQuiet reg m) [0 .. n - 1]

-- | One registry worker iteration on a thread-private slot: seat a
-- quiesce job, insert (fresh, generation 1), remove (generation 2,
-- exactly the one job canceled).
regOne :: AsyncTable -> TokenRegistry -> Int -> SessionId -> Int -> Int -> IO ()
regOne at reg m sid t i = do
  let slot = SlotId (t * m + i)
  registerSessionSlot reg sid slot
  eJid <- startJob at (signRequest sid 100)
  case eJid of
    Left deny -> assertFailure ("quiesce-job start refused: " ++ show deny)
    Right _ -> pure ()
  ins <- insertToken reg slot
  case ins of
    Inserted 1 -> pure ()
    other -> assertFailure ("expected fresh insert gen 1, got: " ++ show other)
  out <- removeToken reg slot
  case out of
    Removed 2 1 -> pure ()
    other -> assertFailure ("expected quiesce of exactly one job, got: " ++ show other)

-- | Every touched slot of one thread ends absent at generation 2.
assertSlotQuiet :: TokenRegistry -> Int -> Int -> IO ()
assertSlotQuiet reg m t =
  mapM_ (oneSlot reg) [t * m .. t * m + m - 1]

-- | One slot ends absent at generation 2.
oneSlot :: TokenRegistry -> Int -> IO ()
oneSlot reg s = do
  present <- tokenPresent reg (SlotId s)
  assertBool ("slot " ++ show s ++ " absent at end") (not present)
  gen <- tokenGeneration reg (SlotId s)
  assertEqual ("slot " ++ show s ++ " generation 2") 2 (fromIntegral gen :: Int)

-- | Drain the queue nonblockingly, counting events (bounded: the
-- queue only shrinks here, so the loop terminates).
drainEvents :: EventQueue -> Int -> IO Int
drainEvents eq acc = do
  w <- tryWaitSlotEvent eq
  case w of
    WaitEvent _ -> drainEvents eq (acc + 1)
    WaitNoEvent -> pure acc
    WaitFinalized -> assertFailure "queue finalized mid-drain"

-- ---------------------------------------------------------------------------
-- Store
-- ---------------------------------------------------------------------------

-- | N x M threaded commits against one shared memory handle.
caseStoreMemory :: IO ()
caseStoreMemory = do
  world <- newMemoryWorld
  eStore <- openMemoryStoreWith world defaultLimits noFaults
  store <- either (assertFailure . show) pure eStore
  caseStoreCommits store
  storeClose store

-- | N x M threaded commits against one shared SQLite handle.
caseStoreSQLite :: IO ()
caseStoreSQLite =
  withStressSQLite caseStoreCommits

-- | N threads x M commits of disjoint objects against one shared
-- handle: the commit chain is contiguous and the committed set exact.
caseStoreCommits :: Store -> IO ()
caseStoreCommits store = do
  (n, m) <- simParams
  tok <- seedStressStore store
  let tid = trId tok
  runWorkers n $ \t ->
    mapM_ (storeOne store tid t m) [0 .. m - 1]
  stats <- storeStats store
  assertEqual "commit chain contiguous" (1 + n * m) (ssCommits stats)
  eLoaded <- storeLoadTokens store
  loaded <- either (assertFailure . show) pure eLoaded
  let oids = sort [unObjectId (orId o) | (_, os) <- loaded, o <- os]
      expected = sort ([1, 2] ++ [1000 + t * m + i | t <- [0 .. n - 1], i <- [0 .. m - 1]])
  assertEqual "committed object set exact" expected oids

-- | One store worker iteration: commit one disjoint object.
storeOne :: Store -> TokenId -> Int -> Int -> Int -> IO ()
storeOne store tid t m i = do
  r <- storeCommit store emptyDelta
    { sdPutObjects = [ObjectPut Nothing (stressObject tid (1000 + t * m + i))] }
  case r of
    Committed -> pure ()
    other -> assertFailure ("commit refused: " ++ show other)

-- | Seed one token with two objects; the seed is commit #1.
seedStressStore :: Store -> IO TokenRecord
seedStressStore store = do
  let tok = TokenRecord (TokenId 7) (SlotId 0) (Generation 1) "stress-token" tokenAuthNew
  r <- storeCommit store emptyDelta
    { sdPutTokens = [tok]
    , sdPutObjects =
        [ ObjectPut Nothing (stressObject (TokenId 7) 1)
        , ObjectPut Nothing (stressObject (TokenId 7) 2)
        ]
    }
  assertEqual "seed commit" Committed r
  pure tok

-- | Hand-built stress object with a distinct id and label.
stressObject :: TokenId -> Int -> ObjectRecord
stressObject tok n = ObjectRecord
  { orId = ObjectId n
  , orToken = tok
  , orClass = 3
  , orKeyType = Nothing
  , orAttrs = Map.fromList
      [(AttrClass, ValULong 3), (AttrLabel, ValBytes (BC8.pack ("stress-" ++ show n)))]
  , orMaterialEncoding = "none"
  , orMaterial = Nothing
  , orRevision = Revision 1
  }

-- | Fresh SQLite file identity per case, cleaned up afterwards.
withStressSQLite :: (Store -> IO ()) -> IO ()
withStressSQLite use =
  bracket (makeStressTempDir "haskoki-sim-stress") removeDirectoryRecursive $ \dir -> do
    eStore <- openSQLiteStoreWith (dir </> "store.db") defaultLimits noFaults
    store <- either (assertFailure . show) pure eStore
    use store
    storeClose store

-- | A fresh scratch directory (numeric suffix scan; single-process).
makeStressTempDir :: String -> IO FilePath
makeStressTempDir stem = do
  base <- getTemporaryDirectory
  tryNames base stem (0 :: Int)
  where
    tryNames base prefix n
      | n > 10000 = ioError (userError ("makeStressTempDir: exhausted names for " ++ prefix))
      | otherwise = do
          let dir = base </> (prefix ++ "-" ++ show n)
          exists <- doesDirectoryExist dir
          if exists
            then tryNames base prefix (n + 1)
            else createDirectory dir >> pure dir

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

-- | N sessions open on one env; N threads each close their own: every
-- session reads back absent, every pinned reservation goes stale, and
-- no close resurrects another session.
caseSessionsClose :: IO ()
caseSessionsClose = do
  (n, _) <- simParams
  env <- newEnv defaultRules
  eSeat <- seatToken env (SlotId 0)
  case eSeat of
    Left deny -> assertFailure ("seat refused: " ++ show deny)
    Right () -> pure ()
  let sids = [SessionId (300 + t) | t <- [0 .. n - 1]]
  eOpen <- publish env (StateDelta [DeltaOpenSession sid (SlotId 0) False | sid <- sids])
  case eOpen of
    Left fault -> assertFailure ("open failed: " ++ show fault)
    Right () -> pure ()
  m <- snapshotModel env
  reservations <- mapM (pinReservation m) sids
  runWorkers n $ \t -> do
    eClose <- publish env (StateDelta [DeltaCloseSession (sids !! t)])
    case eClose of
      Left fault -> assertFailure ("close failed: " ++ show fault)
      Right () -> pure ()
  mAfter <- snapshotModel env
  mapM_ (assertClosed mAfter) sids
  stale <- mapM (checkReservation env) reservations
  assertEqual "every reservation stale after close"
    (replicate n True) (map isJust stale)

-- | Pin a reservation to an open session.
pinReservation :: Model -> SessionId -> IO Reservation
pinReservation m sid = do
  st <- expectJust ("session " ++ show sid) (lookupSession m sid)
  pure (Reservation "stress-session"
    [DepSession sid (ssRevision st) (ssGeneration st)] Nothing Nothing)

-- | A closed session reads back absent (never resurrected).
assertClosed :: Model -> SessionId -> IO ()
assertClosed m sid = case lookupSession m sid of
  Nothing -> pure ()
  Just _ -> assertFailure ("session still live after close: " ++ show sid)
