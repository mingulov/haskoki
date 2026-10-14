{- | Multi-session store proofs.

Two sessions share one store handle with interleaved commits (no lost
updates); revision conflicts surface as the typed
'StoreRevisionConflict' error, never silent overwrites. Close
serializes with use: a close issued against an in-flight
commit or a queued load waits instead of tearing the handle, and
a failed close retains ownership, refuses new operations, and
reports, until a retry closes for real. Both backends run the
same cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module MultiSessionSpec (spec) where

import qualified Data.Map.Strict as Map
import Data.ByteString (ByteString)
import Data.List (isInfixOf, sort, sortOn)
import System.Directory (removeDirectoryRecursive)
import System.FilePath ((</>))
import System.IO (hPutStrLn, stderr)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Control.Concurrent (ThreadId, forkFinally, killThread, threadDelay)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, readMVar, takeMVar)
import Control.Exception (AsyncException (..), SomeException, bracket, finally, fromException, throwIO, try)
import Control.Monad (replicateM, when)
import Data.IORef (atomicModifyIORef', newIORef)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( addToken
  , emptyModel
  , lookupObject
  , lookupSession
  )
import Haskoki.Outcome (DeltaOp (..), StateDelta (..))
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , FaultInjector (..)
  , FaultPoint (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , StoreLimits
  , TokenRecord (..)
  , defaultLimits
  , emptyDelta
  , noFaults
  , objectToRecord
  , planSlotMoves
  , reserveRestoredIds
  , scriptedFaults
  , withMaskHook
  , withResultHook
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStoreWith)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStoreWith)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( Generation (..)
  , ObjectId (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )
import StoreSpec (expectCreated, expectInspect, expectJust, expectRight, makeTempDir, seedStore)

-- | Open a store on the case identity with the given limits and faults.
type OpenWith = StoreLimits -> FaultInjector -> IO (Either StoreError Store)

spec :: TestTree
spec = testGroup "Multi-session store"
  [ testGroup "memory"
      [ testCase "interleaved commits lose no updates" $
          withMemoryIdentity testInterleaved
      , testCase "revision conflict is typed, never a silent overwrite" $
          withMemoryIdentity testConflict
      , testCase "commit in flight serializes with close" $
          withMemoryIdentity testCommitCloseBarrier
      , testCase "queued load serializes with close" $
          withMemoryIdentity testLoadCloseBarrier
      , testCase "failed close retains ownership and retry succeeds" $
          withMemoryIdentity testFailedCloseRetains
      , testCase "throwing close probe never strands the handle" $
          withMemoryIdentity testCloseProbeThrows
      , testCase "killed close never strands the handle" $
          withMemoryIdentity testCloseKillDuringProbe
      , testCase "concurrent reservations never share an id" $
          withMemoryIdentity testConcurrentReserve
      , testCase "concurrent moves to one slot serialize" $
          withMemoryIdentity testConcurrentMove
      ]
  , testGroup "sqlite"
      [ testCase "interleaved commits lose no updates" $
          withSQLiteIdentity testInterleaved
      , testCase "revision conflict is typed, never a silent overwrite" $
          withSQLiteIdentity testConflict
      , testCase "commit in flight serializes with close" $
          withSQLiteIdentity testCommitCloseBarrier
      , testCase "queued load serializes with close" $
          withSQLiteIdentity testLoadCloseBarrier
      , testCase "failed close retains ownership and retry succeeds" $
          withSQLiteIdentity testFailedCloseRetains
      , testCase "throwing close probe never strands the handle" $
          withSQLiteIdentity testCloseProbeThrows
      , testCase "killed close never strands the handle" $
          withSQLiteIdentity testCloseKillDuringProbe
      , testCase "concurrent reservations never share an id" $
          withSQLiteIdentity testConcurrentReserve
      , testCase "concurrent moves to one slot serialize" $
          withSQLiteIdentity testConcurrentMove
      ]
  , testCase "commit tests observe death deterministically (no busy-spin)" caseNoBusySpin
  ]

-- | Barrier rendezvous bound: 5 seconds, matching the commit
-- suite's guards.
rendezvousTimeout :: Int
rendezvousTimeout = 5000000

-- | Run a worker with 'forkFinally' outcome capture (the commit
-- suite's 'withWorker' idiom, repeated because that helper is
-- private to its module). Every exit path cancels a still-live
-- worker and joins the outcome with bounded waits, so a stuck
-- worker cannot leak past the case. The body observes the outcome
-- with 'readMVar' (leaving it for the bounded join); the join
-- only blocks when the worker never reported.
withWorker
  :: IO ()
  -> ((ThreadId, MVar (Either SomeException ())) -> IO a)
  -> IO a
withWorker action use = do
  outcomeVar <- newEmptyMVar
  tid <- forkFinally action (putMVar outcomeVar)
  use (tid, outcomeVar) `finally` release tid outcomeVar
  where
    release tid outcomeVar = do
      _ <- timeout rendezvousTimeout (killThread tid)
      mJoined <- timeout rendezvousTimeout (takeMVar outcomeVar)
      case mJoined of
        Just _ -> pure ()
        Nothing -> hPutStrLn stderr
          "withWorker: worker join timed out after kill (5s guard)"

-- | Run several workers with 'withWorker' nesting, collecting
-- their outcome cells for the body.
withWorkers :: [IO ()] -> ([MVar (Either SomeException ())] -> IO a) -> IO a
withWorkers actions use = go actions []
  where
    go [] outcomes = use (reverse outcomes)
    go (act : rest) outcomes =
      withWorker act $ \(_, outcome) -> go rest (outcome : outcomes)

-- | Open a store on the case identity, closing the handle when the
-- body exits on any path (handle hygiene: a failing assertion
-- mid-case must not leak a live handle into fixture cleanup).
-- Sits outside the worker scopes, so workers are joined before
-- the store and directory cleanup runs. Explicit closes inside
-- the body stay — they are the behavior under test — and the
-- bracket close is an idempotent no-op after them.
withOpenStore :: OpenWith -> StoreLimits -> FaultInjector -> (Store -> IO a) -> IO a
withOpenStore openWith lim inj =
  bracket (openWith lim inj >>= either (assertFailure . show) pure) storeClose

-- | Fresh memory identity per case.
withMemoryIdentity :: (OpenWith -> IO ()) -> IO ()
withMemoryIdentity use = do
  world <- newMemoryWorld
  use (\lim inj -> openMemoryStoreWith world lim inj)

-- | Fresh SQLite file identity per case, cleaned up afterwards.
withSQLiteIdentity :: (OpenWith -> IO ()) -> IO ()
withSQLiteIdentity use =
  bracket (makeTempDir "haskoki-multisession-test") removeDirectoryRecursive $ \dir ->
    use (\lim inj -> openSQLiteStoreWith (dir </> "store.db") lim inj)

-- | Two sessions plan through one store handle with interleaved
-- commits: plan A via session 1, plan B via session 2, commit A,
-- commit B. Both land; nothing is lost.
testInterleaved :: OpenWith -> IO ()
testInterleaved openWith = do
  eStore <- openWith defaultLimits noFaults
  store <- either (assertFailure . show) pure eStore
  (tok, recs) <- seedStore store
  let slot = SlotId 0
      tid = trId tok
  mSeated <- expectRight "seat+open-two" (publishDelta (addToken emptyModel slot)
    (StateDelta [ DeltaOpenSession (SessionId 1) slot False
                , DeltaOpenSession (SessionId 2) slot False
                ]))
  let mReserved = reserveRestoredIds (map orId recs) mSeated
  st1 <- expectJust "session 1" (lookupSession mReserved (SessionId 1))
  _st2 <- expectJust "session 2" (lookupSession mReserved (SessionId 2))
  (mA, _, oidA) <- expectCreated mReserved st1 (tmplFor "interleave-a")
  st2AfterA <- expectJust "session 2 survives A" (lookupSession mA (SessionId 2))
  (mB, _, oidB) <- expectCreated mA st2AfterA (tmplFor "interleave-b")
  assertBool "distinct objects" (oidA /= oidB)
  ostA <- expectJust "object A" (lookupObject mB oidA)
  ostB <- expectJust "object B" (lookupObject mB oidB)
  rA <- storeCommit store emptyDelta
    { sdPutObjects = [ObjectPut Nothing (objectToRecord tid ostA)] }
  assertEqual "commit A" Committed rA
  rB <- storeCommit store emptyDelta
    { sdPutObjects = [ObjectPut Nothing (objectToRecord tid ostB)] }
  assertEqual "commit B" Committed rB
  eLoaded <- storeLoadTokens store
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "no lost updates" 4 (countObjects loaded)
  assertBool "A durable" (objectPresent oidA loaded)
  assertBool "B durable" (objectPresent oidB loaded)
  storeClose store

-- | Guarded writes against stale or missing revisions refuse with the
-- typed 'StoreRevisionConflict' error and land nothing; the
-- correctly-guarded write commits.
testConflict :: OpenWith -> IO ()
testConflict openWith = do
  eStore <- openWith defaultLimits noFaults
  store <- either (assertFailure . show) pure eStore
  (_, recs) <- seedStore store
  victim <- case recs of
    (r : _) -> pure r
    [] -> assertFailure "seed produced no objects"
  let badRev = Revision (unRevision (orRevision victim) + 1000)
      overwrite = victim
        { orAttrs = Map.insert AttrLabel (ValBytes "sneaky") (orAttrs victim) }
  refused <- storeCommit store emptyDelta
    { sdPutObjects = [ObjectPut (Just badRev) overwrite] }
  case refused of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected StoreRevisionConflict, got: " ++ show other)
  -- A guarded write to a missing object conflicts too (never an
  -- upsert through the guard).
  ghost <- storeCommit store emptyDelta
    { sdPutObjects =
        [ObjectPut (Just (Revision 1)) (victim { orId = ObjectId 9999 })] }
  case ghost of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected missing-object conflict, got: " ++ show other)
  -- No silent overwrite: the durable record is still the original.
  eLoaded <- storeLoadTokens store
  loaded <- either (assertFailure . show) pure eLoaded
  case [o | (_, os) <- loaded, o <- os, orId o == orId victim] of
    [o] -> assertEqual "original content intact" (orAttrs victim) (orAttrs o)
    _ -> assertFailure "victim missing or duplicated after refused commits"
  -- The correctly-guarded write commits.
  ok <- storeCommit store emptyDelta
    { sdPutObjects = [ObjectPut (Just (orRevision victim)) overwrite] }
  assertEqual "guarded write commits" Committed ok
  storeClose store

-- | The async-mask commit case must observe thread death through a
-- deterministic death signal, never the old 'waitDeath' busy-spin
-- (whose @timeout 10000 (pure ())@ waits nothing: @pure ()@
-- resolves instantly, so the spin can miss under load).
caseNoBusySpin :: IO ()
caseNoBusySpin = do
  body <- readFile "tests/storage/CommitSpec.hs"
  let hits =
        [n | (n, ln) <- zip [1 :: Int ..] (lines body), "timeout 10000" `isInfixOf` ln]
  case hits of
    [] -> pure ()
    _ -> assertFailure ("CommitSpec still busy-spins on lines: " ++ show hits)

-- | Token-object template with a distinct label.
tmplFor :: ByteString -> [(AttributeType, AttributeValue)]
tmplFor label =
  [ (AttrClass, ValULong 3)
  , (AttrToken, ValBool True)
  , (AttrLabel, ValBytes label)
  , (AttrValue, ValBytes "interleave-bytes")
  ]

-- | Count stored objects across tokens.
countObjects :: [(TokenRecord, [ObjectRecord])] -> Int
countObjects = sum . map (length . snd)

-- | Whether an object id is present in loaded state.
objectPresent :: ObjectId -> [(TokenRecord, [ObjectRecord])] -> Bool
objectPresent oid = any (any ((== oid) . orId) . snd)

-- | Reservations from racing threads serialize store-wide:
-- every id hands out exactly once, with no gaps and no shares.
testConcurrentReserve :: OpenWith -> IO ()
testConcurrentReserve openWith =
  withOpenStore openWith defaultLimits noFaults $ \store -> do
    resultVars <- replicateM nWorkers newEmptyMVar
    let worker var =
          replicateM perWorker (storeReserveJobId store) >>= putMVar var
    withWorkers (map worker resultVars) $ \_outcomes -> do
      mBatches <- mapM (timeout rendezvousTimeout . takeMVar) resultVars
      batches <- case sequence mBatches of
        Nothing -> assertFailure "reserve worker timed out"
        Just bs -> pure bs
      pids <- mapM (expectRight "reserve") (concat batches)
      assertEqual "every id exactly once" [1 .. fromIntegral total] (sort pids)
  where
    nWorkers = 8
    perWorker = 5
    total = nWorkers * perWorker

-- | A close issued while a commit sits inside the masked
-- region waits for the commit — it never slips past and shuts
-- the handle beneath it. The barrier commit lands whole, later
-- uses fail closed, and the identity reopens with the commit
-- durable.
testCommitCloseBarrier :: OpenWith -> IO ()
testCommitCloseBarrier openWith =
  withOpenStore openWith defaultLimits noFaults $ \sClean -> do
    (tok, _) <- seedStore sClean
    storeClose sClean
    enteredVar <- newEmptyMVar
    releaseVar <- newEmptyMVar
    resultVar <- newEmptyMVar
    inj0 <- scriptedFaults []
    let inj = withResultHook (putMVar resultVar) (withMaskHook hook inj0)
        hook = putMVar enteredVar () >> takeMVar releaseVar
    withOpenStore openWith defaultLimits inj $ \store -> do
      docs <- expectInspect store
      assertBool "seeded docs inspect before close" (not (null docs))
      let delta = emptyDelta { sdPutMeta = [("m4-commit-barrier", "1")] }
      commitVar <- newEmptyMVar
      withWorker (storeCommit store delta >>= putMVar commitVar) $ \(_, _) -> do
        mEntered <- timeout rendezvousTimeout (takeMVar enteredVar)
        case mEntered of
          Nothing -> assertFailure "commit never entered the masked region (5s guard)"
          Just () -> pure ()
        assertStillOwned openWith
        closeStarted <- newEmptyMVar
        withWorker (putMVar closeStarted () >> storeClose store) $ \(_, closeOutcome) -> do
          mStarted <- timeout rendezvousTimeout (takeMVar closeStarted)
          case mStarted of
            Nothing -> assertFailure "close worker never started (5s guard)"
            Just () -> pure ()
          -- The close provably entered 'storeClose' while the commit
          -- holds the handle lock: it must still be blocked.
          mEarly <- timeout 100000 (readMVar closeOutcome)
          case mEarly of
            Just _ -> assertFailure "close slipped past an in-flight commit"
            Nothing -> pure ()
          putMVar releaseVar ()
          mRes <- timeout rendezvousTimeout (takeMVar resultVar)
          res <- maybe (assertFailure "commit result hook never fired (5s guard)") pure mRes
          assertEqual "barrier commit result" Committed res
          mCommit <- timeout rendezvousTimeout (takeMVar commitVar)
          case mCommit of
            Just Committed -> pure ()
            other -> assertFailure ("barrier commit lost: " ++ show other)
          mClosed <- timeout rendezvousTimeout (readMVar closeOutcome)
          case mClosed of
            Just (Right ()) -> pure ()
            Just (Left e) -> assertFailure ("close worker died: " ++ show e)
            Nothing -> assertFailure "close never completed after release (5s guard)"
          assertClosed store tok
    withOpenStore openWith defaultLimits noFaults $ \re -> do
      eMeta <- storeLoadMeta re
      meta <- either (assertFailure . show) pure eMeta
      assertEqual "barrier commit durable" (Just "1") (lookup "m4-commit-barrier" meta)
      storeClose re

-- | A load issued while a commit sits inside the masked
-- region queues behind it, and a close issued in between queues
-- too — every outcome is well-defined. The load either serves
-- the whole seed or reports the closed handle (never torn data,
-- never an exception), the commit lands, the close completes,
-- and later loads fail closed.
testLoadCloseBarrier :: OpenWith -> IO ()
testLoadCloseBarrier openWith =
  withOpenStore openWith defaultLimits noFaults $ \sClean -> do
    (tok, seedRecs) <- seedStore sClean
    storeClose sClean
    enteredVar <- newEmptyMVar
    releaseVar <- newEmptyMVar
    inj0 <- scriptedFaults []
    let inj = withMaskHook hook inj0
        hook = putMVar enteredVar () >> takeMVar releaseVar
    withOpenStore openWith defaultLimits inj $ \store -> do
      let delta = emptyDelta { sdPutMeta = [("m4-load-barrier", "1")] }
      commitVar <- newEmptyMVar
      withWorker (storeCommit store delta >>= putMVar commitVar) $ \(_, _) -> do
        mEntered <- timeout rendezvousTimeout (takeMVar enteredVar)
        case mEntered of
          Nothing -> assertFailure "commit never entered the masked region (5s guard)"
          Just () -> pure ()
        assertStillOwned openWith
        loadVar <- newEmptyMVar
        loadStarted <- newEmptyMVar
        withWorker (putMVar loadStarted () >> (storeLoadTokens store >>= putMVar loadVar)) $ \(_, _) -> do
          mLStarted <- timeout rendezvousTimeout (takeMVar loadStarted)
          case mLStarted of
            Nothing -> assertFailure "loader never started (5s guard)"
            Just () -> pure ()
          -- Positioning pause (not an assertion): let the loader reach
          -- the handle lock ahead of the close. If it loses the race
          -- the classified outcome below still holds.
          threadDelay 50000
          closeStarted <- newEmptyMVar
          withWorker (putMVar closeStarted () >> storeClose store) $ \(_, closeOutcome) -> do
            mStarted <- timeout rendezvousTimeout (takeMVar closeStarted)
            case mStarted of
              Nothing -> assertFailure "close worker never started (5s guard)"
              Just () -> pure ()
            mEarly <- timeout 100000 (readMVar closeOutcome)
            case mEarly of
              Just _ -> assertFailure "close slipped past an in-flight commit"
              Nothing -> pure ()
            putMVar releaseVar ()
            mCommit <- timeout rendezvousTimeout (takeMVar commitVar)
            case mCommit of
              Just Committed -> pure ()
              other -> assertFailure ("barrier commit lost: " ++ show other)
            mLoad <- timeout rendezvousTimeout (takeMVar loadVar)
            case mLoad of
              Just (Right loaded) -> assertWholeSeed tok seedRecs loaded
              Just (Left (StoreIO _)) -> pure ()
              Just (Left err) -> assertFailure ("queued load misdiagnosed: " ++ show err)
              Nothing -> assertFailure "queued load never answered (5s guard)"
            mClosed <- timeout rendezvousTimeout (readMVar closeOutcome)
            case mClosed of
              Just (Right ()) -> pure ()
              Just (Left e) -> assertFailure ("close worker died: " ++ show e)
              Nothing -> assertFailure "close never completed after release (5s guard)"
            assertClosed store tok
    -- Hammer phase: a hundred racing loads against a racing close
    -- classify cleanly (whole seed or closed diagnosis), never
    -- tear and never escape as an exception.
    withOpenStore openWith defaultLimits noFaults $ \re -> do
      eLoaded <- storeLoadTokens re
      loaded <- either (assertFailure . show) pure eLoaded
      assertWholeSeed tok seedRecs loaded
      loadVars <- replicateM 4 newEmptyMVar
      let loader var = replicateM 25 (storeLoadTokens re) >>= putMVar var
      -- No head start: the close races the spinning loaders
      -- immediately, maximizing the overlap window (the suite
      -- runs threaded, so the loaders truly run in parallel).
      -- Mixed batches are the common observation; the assertion
      -- stays distribution-neutral, classifying every
      -- outcome.
      withWorkers (map loader loadVars) $ \_ -> do
        storeClose re
        outcomes <- mapM (timeout rendezvousTimeout . takeMVar) loadVars
        case sequence outcomes of
          Nothing -> assertFailure "hammer loader join timed out (5s guard)"
          Just batches -> mapM_ (mapM_ (classifyHammer tok seedRecs)) batches
    withOpenStore openWith defaultLimits noFaults $ \re2 -> do
      eLoaded2 <- storeLoadTokens re2
      loaded2 <- either (assertFailure . show) pure eLoaded2
      assertWholeSeed tok seedRecs loaded2
      storeClose re2

-- | A failed close (an injected 'FaultClose') reports by
-- throwing the typed failure, retains ownership and guards,
-- refuses new operations exactly like a closed handle — and a
-- later close retries for real. The next owner can never enter
-- around the surviving handle.
testFailedCloseRetains :: OpenWith -> IO ()
testFailedCloseRetains openWith = do
  inj <- scriptedFaults [FaultClose]
  withOpenStore openWith defaultLimits inj $ \store -> do
    (tok, seedRecs) <- seedStore store
    eFirst <- try (storeClose store)
    case eFirst of
      Left e -> case fromException e of
        Just (StoreIO msg)
          | "close failed" `isInfixOf` msg -> pure ()
        _ -> assertFailure ("close misreported failure: " ++ show (e :: SomeException))
      Right () -> assertFailure "failed close did not report"
    -- Poisoned, not usable: new operations refuse ...
    assertClosed store tok
    -- ... while the handle still owns the identity.
    eSecond <- openWith defaultLimits noFaults
    case eSecond of
      Right s2 -> do
        storeClose s2
        assertFailure "failed close released ownership"
      Left (StoreSecondWriter _) -> pure ()
      Left other -> assertFailure
        ("wrong error while failed-close handle holds: " ++ show other)
    -- The retry closes for real.
    storeClose store
    assertClosed store tok
  withOpenStore openWith defaultLimits noFaults $ \re -> do
    eLoaded <- storeLoadTokens re
    loaded <- either (assertFailure . show) pure eLoaded
    assertWholeSeed tok seedRecs loaded
    storeClose re

-- | An exception thrown from the close fault probe never
-- strands the handle: the first close propagates the probe
-- error, the handle stays usable and still owns the identity,
-- and the retry closes for real.
testCloseProbeThrows :: OpenWith -> IO ()
testCloseProbeThrows openWith = do
  armedVar <- newIORef True
  let inj = noFaults { fiFire = fire }
      fire FaultClose = do
        armed <- atomicModifyIORef' armedVar (\armed -> (False, armed))
        if armed then throwIO (userError "m4-boom") else pure False
      fire _ = pure False
  withOpenStore openWith defaultLimits inj $ \store -> do
    (tok, _) <- seedStore store
    eClose <- try (storeClose store)
    case eClose of
      Left e
        | "m4-boom" `isInfixOf` show (e :: SomeException) -> pure ()
      Left e -> assertFailure ("close threw foreign error: " ++ show (e :: SomeException))
      Right () -> assertFailure "throwing close probe did not propagate"
    -- The handle is unstranded: the first probe runs bounded (a
    -- stranded flag would hang here past the guard), then the
    -- handle serves and still owns the identity.
    mLoaded <- timeout rendezvousTimeout (storeLoadTokens store)
    loaded <- case mLoaded of
      Nothing -> assertFailure "handle stranded by throwing close probe (5s guard)"
      Just eLoaded -> either (assertFailure . show) pure eLoaded
    assertBool "seed token served after throwing close"
      (any ((== trId tok) . trId . fst) loaded)
    r <- storeCommit store emptyDelta { sdPutMeta = [("m4-throw-retry", "1")] }
    assertEqual "commit served after throwing close" Committed r
    eSecond <- openWith defaultLimits noFaults
    case eSecond of
      Right s2 -> do
        storeClose s2
        assertFailure "throwing close released ownership"
      Left (StoreSecondWriter _) -> pure ()
      Left other -> assertFailure
        ("wrong error while throwing-close handle holds: " ++ show other)
    -- The probe is spent: the retry closes for real.
    storeClose store
    assertClosed store tok
  withOpenStore openWith defaultLimits noFaults $ \re -> do
    eMeta <- storeLoadMeta re
    meta <- either (assertFailure . show) pure eMeta
    assertEqual "probe durable across throw retry" (Just "1") (lookup "m4-throw-retry" meta)
    storeClose re

-- | Killing a close blocked in its fault probe never strands
-- the handle: the victim dies observed, the handle stays usable
-- and still owns the identity, and the retry (after releasing
-- the probe) closes for real.
testCloseKillDuringProbe :: OpenWith -> IO ()
testCloseKillDuringProbe openWith = do
  enteredVar <- newEmptyMVar
  releaseVar <- newEmptyMVar
  armedVar <- newIORef True
  -- Only the first close probe blocks (that is the victim's
  -- window); every later probe — the in-body retry and any
  -- failure-path bracket cleanup — answers immediately, so no
  -- exit path can hang in the probe.
  let inj = noFaults { fiFire = fire }
      fire FaultClose = do
        first <- atomicModifyIORef' armedVar (\armed -> (False, armed))
        when first $ do
          putMVar enteredVar ()
          takeMVar releaseVar
        pure False
      fire _ = pure False
  withOpenStore openWith defaultLimits inj $ \store -> do
    (tok, _) <- seedStore store
    withWorker (storeClose store) $ \(tid, outcome) -> do
      mEntered <- timeout rendezvousTimeout (takeMVar enteredVar)
      case mEntered of
        Nothing -> assertFailure "close never reached its probe (5s guard)"
        Just () -> pure ()
      killThread tid
      mOutcome <- timeout rendezvousTimeout (readMVar outcome)
      case mOutcome of
        Just (Left e)
          | isKill e -> pure ()
        other -> assertFailure ("close victim not observed killed: " ++ show other)
      -- The victim died inside the probe: the first probe runs
      -- bounded (a stranded flag would hang here past the guard),
      -- then the handle serves and still owns the identity.
      mLoaded <- timeout rendezvousTimeout (storeLoadTokens store)
      loaded <- case mLoaded of
        Nothing -> assertFailure "handle stranded by killed close (5s guard)"
        Just eLoaded -> either (assertFailure . show) pure eLoaded
      assertBool "seed token served after killed close"
        (any ((== trId tok) . trId . fst) loaded)
      r <- storeCommit store emptyDelta { sdPutMeta = [("m4-kill-retry", "1")] }
      assertEqual "commit served after killed close" Committed r
      eSecond <- openWith defaultLimits noFaults
      case eSecond of
        Right s2 -> do
          storeClose s2
          assertFailure "killed close released ownership"
        Left (StoreSecondWriter _) -> pure ()
        Left other -> assertFailure
          ("wrong error while killed-close handle holds: " ++ show other)
      -- The probe is spent after its first blocking round: the
      -- retry closes for real.
      storeClose store
      assertClosed store tok
  withOpenStore openWith defaultLimits noFaults $ \re -> do
    eMeta <- storeLoadMeta re
    meta <- either (assertFailure . show) pure eMeta
    assertEqual "probe durable across kill retry" (Just "1") (lookup "m4-kill-retry" meta)
    storeClose re

-- | Whether an outcome is an observed async kill.
isKill :: SomeException -> Bool
isKill e = case fromException e of
  Just ThreadKilled -> True
  _ -> False

-- | A non-open handle fails closed on every world-touching
-- operation with exactly 'StoreIO "store is closed"' (commits
-- and resets wrap it in 'NotCommitted'), while the live-handle
-- diagnostics stay readable. Applies identically to cleanly
-- closed and close-failed handles. The reset arguments are
-- never consulted (refusal precedes the generation check), so
-- the seed token doubles as the replacement.
assertClosed :: Store -> TokenRecord -> IO ()
assertClosed store tok = do
  eToks <- storeLoadTokens store
  case eToks of
    Left (StoreIO msg) | msg == "store is closed" -> pure ()
    other -> assertFailure ("expected closed load refusal, got: " ++ show other)
  eJobs <- storeLoadJobs store
  case eJobs of
    Left (StoreIO msg) | msg == "store is closed" -> pure ()
    other -> assertFailure ("expected closed jobs refusal, got: " ++ show other)
  eMeta <- storeLoadMeta store
  case eMeta of
    Left (StoreIO msg) | msg == "store is closed" -> pure ()
    other -> assertFailure ("expected closed meta refusal, got: " ++ show other)
  eDocs <- storeInspect store
  case eDocs of
    Left (StoreIO msg) | msg == "store is closed" -> pure ()
    other -> assertFailure ("expected closed inspect refusal, got: " ++ show other)
  eReload <- storeReload store
  case eReload of
    Left (StoreIO msg) | msg == "store is closed" -> pure ()
    other -> assertFailure ("expected closed reload refusal, got: " ++ show other)
  rCommit <- storeCommit store emptyDelta
  case rCommit of
    NotCommitted (StoreIO msg) | msg == "store is closed" -> pure ()
    other -> assertFailure ("expected closed commit refusal, got: " ++ show other)
  rReset <- storeResetToken store (trId tok) (trGeneration tok) tok
  case rReset of
    NotCommitted (StoreIO msg) | msg == "store is closed" -> pure ()
    other -> assertFailure ("expected closed reset refusal, got: " ++ show other)
  _ <- storeStats store
  _ <- storeQuarantined store
  pure ()

-- | While an admitted commit is pending, no new handle can
-- become active on the identity: the owner still holds it.
assertStillOwned :: OpenWith -> IO ()
assertStillOwned openWith = do
  eRival <- openWith defaultLimits noFaults
  case eRival of
    Right sRival -> do
      storeClose sRival
      assertFailure "new handle entered around a pending commit"
    Left (StoreSecondWriter _) -> pure ()
    Left other -> assertFailure ("wrong error around pending commit: " ++ show other)

-- | The loaded state is exactly the seed: one token with its two
-- children, id-ordered comparison so backend row order cannot
-- matter.
assertWholeSeed :: TokenRecord -> [ObjectRecord] -> [(TokenRecord, [ObjectRecord])] -> IO ()
assertWholeSeed tok seedRecs loaded = case loaded of
  [(t, os)]
    | t == tok && sortOn orId os == sortOn orId seedRecs -> pure ()
    | otherwise -> assertFailure "queued load served torn seed data"
  _ -> assertFailure ("expected one seed token, got: " ++ show (length loaded))

-- | One hammered load classifies cleanly: the whole seed or the
-- closed diagnosis — never torn data, never another error.
classifyHammer
  :: TokenRecord
  -> [ObjectRecord]
  -> Either StoreError [(TokenRecord, [ObjectRecord])]
  -> IO ()
classifyHammer tok seedRecs eLoaded = case eLoaded of
  Right loaded -> assertWholeSeed tok seedRecs loaded
  Left (StoreIO _) -> pure ()
  Left err -> assertFailure ("hammer load misdiagnosed: " ++ show err)

-- | Seed three positional tokens (demo/ops/audit at slots
-- 0/1/2 with ids 1/2/3), each owning one labeled object.
seedMoveThree :: Store -> IO [TokenRecord]
seedMoveThree store = do
  let s0 = SlotId 0
      s1 = SlotId 1
      s2 = SlotId 2
  mSeated <- expectRight "mv seat+open" (publishDelta
    (addToken (addToken (addToken emptyModel s0) s1) s2)
    (StateDelta [ DeltaOpenSession (SessionId 1) s0 False
                , DeltaOpenSession (SessionId 2) s1 False
                , DeltaOpenSession (SessionId 3) s2 False
                ]))
  st0 <- expectJust "mv session 0" (lookupSession mSeated (SessionId 1))
  st1 <- expectJust "mv session 1" (lookupSession mSeated (SessionId 2))
  st2 <- expectJust "mv session 2" (lookupSession mSeated (SessionId 3))
  (m1, _, oid1) <- expectCreated mSeated st0 (tmplFor "mv-demo")
  (m2, _, oid2) <- expectCreated m1 st1 (tmplFor "mv-ops")
  (m3, _, oid3) <- expectCreated m2 st2 (tmplFor "mv-audit")
  ost1 <- expectJust "mv object 1" (lookupObject m3 oid1)
  ost2 <- expectJust "mv object 2" (lookupObject m3 oid2)
  ost3 <- expectJust "mv object 3" (lookupObject m3 oid3)
  let toks =
        [ TokenRecord (TokenId 1) s0 (Generation 1) "haskoki-demo" tokenAuthNew
        , TokenRecord (TokenId 2) s1 (Generation 1) "haskoki-ops" tokenAuthNew
        , TokenRecord (TokenId 3) s2 (Generation 1) "haskoki-audit" tokenAuthNew
        ]
  result <- storeCommit store emptyDelta
    { sdPutTokens = toks
    , sdPutObjects =
        [ ObjectPut Nothing (objectToRecord (TokenId 1) ost1)
        , ObjectPut Nothing (objectToRecord (TokenId 2) ost2)
        , ObjectPut Nothing (objectToRecord (TokenId 3) ost3)
        ]
    }
  assertEqual "mv seed commit" Committed result
  pure toks

-- | Two sessions racing the same free slot serialize at the
-- commit: both move plans validate against the pre-move
-- layout, exactly one commit lands, and the loser refuses
-- with the typed slot conflict instead of displacing the
-- winner. Objects stay under their owners throughout.
testConcurrentMove :: OpenWith -> IO ()
testConcurrentMove openWith =
  withOpenStore openWith defaultLimits noFaults $ \store -> do
    _ <- seedMoveThree store
    loaded <- storeLoadTokens store >>= expectRight "load tokens"
    let stored = [t | (t, _) <- loaded]
    planA <- case planSlotMoves [(TokenId 2, SlotId 7)] stored of
      Left refusal -> assertFailure ("plan A must validate: " ++ show refusal)
      Right delta -> pure delta
    planB <- case planSlotMoves [(TokenId 3, SlotId 7)] stored of
      Left refusal -> assertFailure ("plan B must validate: " ++ show refusal)
      Right delta -> pure delta
    varA <- newEmptyMVar
    varB <- newEmptyMVar
    withWorkers
      [ storeCommit store planA >>= putMVar varA
      , storeCommit store planB >>= putMVar varB
      ] $ \_ -> do
        mA <- timeout rendezvousTimeout (takeMVar varA)
        mB <- timeout rendezvousTimeout (takeMVar varB)
        (rA, rB) <- case (mA, mB) of
          (Just a, Just b) -> pure (a, b)
          _ -> assertFailure "move worker timed out"
        assertBool "exactly one move lands" ((rA == Committed) /= (rB == Committed))
        case (rA, rB) of
          (Committed, NotCommitted (StoreRevisionConflict _)) -> pure ()
          (NotCommitted (StoreRevisionConflict _), Committed) -> pure ()
          _ -> assertFailure
            ("loser must refuse with the typed slot conflict: " ++ show (rA, rB))
        reloaded <- storeLoadTokens store >>= expectRight "reload tokens"
        let at7 = [trId t | (t, _) <- reloaded, trSlot t == SlotId 7]
            owned m = sort [(orToken oo, orId oo) | (_, os) <- m, oo <- os]
        assertEqual "one winner at slot 7" 1 (length at7)
        assertEqual "objects keep their owners" (owned loaded) (owned reloaded)
