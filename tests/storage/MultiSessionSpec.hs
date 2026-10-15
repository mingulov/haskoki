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
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.ByteString (ByteString)
import Data.List (isInfixOf, sort, sortOn)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr, deRefStablePtr)
import Foreign.Storable (peek, poke)
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
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef, writeIORef)
import Data.Text (Text)
import qualified Database.SQLite3 as S

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.FFI.Standard
  ( StdAcquisition (..)
  , StdInstance (..)
  , StdStore (..)
  , haskokiStdClose
  , haskokiStdCloseSession
  , haskokiStdGetSessionInfo
  , haskokiStdInitPin
  , haskokiStdInitToken
  , haskokiStdLogin
  , haskokiStdLogout
  , haskokiStdOpenSession
  , haskokiStdSetPin
  , openStdInstanceWith
  , openStdStoreWith
  , stdAcquisition
  , stdRvOf
  )
import Haskoki.Model
  ( addToken
  , emptyModel
  , lookupObject
  , lookupSession
  )
import Haskoki.Outcome (DeltaOp (..), StateDelta (..))
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , CredentialRecord (..)
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
import Haskoki.Runtime.Config
  ( Config (..)
  , StorageCfg (..)
  , StorageKind (..)
  , defaultConfig
  , parseConfig
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStoreWith)
import Haskoki.Runtime.Storage.SQLite
  ( SQLiteTestHooks (..)
  , noSQLiteTestHooks
  , openSQLiteStore
  , openSQLiteStoreWith
  , openSQLiteStoreWithHooks
  )
import SQLiteSeams
  ( CommitSeam (..)
  , TxnSeam (..)
  , assertTablesEqual
  , commitsSinceMark
  , dumpTables
  , failTokenUpsert
  , installCommitSeam
  , installTxnSeam
  , markCommits
  , newCommitSeam
  , newTxnSeam
  )
import Haskoki.Session (TokenAuth (..), tokenAuthNew)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )
import StoreSpec
  ( awaitHolderExit
  , expectCreated
  , expectInspect
  , expectJust
  , expectRight
  , makeTempDir
  , releaseHolder
  , seedStore
  , spawnHolderEnv
  )

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
  , testCase "login lockout persists across close, reopen, and a second process" caseLoginLockoutDurable
  , testCase "failed durable auth write fails the login closed" caseLoginFailClosed
  , testCase "unknown-but-landed login reconciles and serves on" caseLoginUnknownLanded
  , testCase "landed login publishes despite reload failure" caseLoginReloadFailsLanded
  , testCase "per-token lockout is independent and durable" caseLoginTokenIndependent
  , testCase "changed PIN persists across close and reopen" caseSetPinDurable
  , testCase "SO InitPIN recovers a locked-out user" caseInitPinRecovery
  , testCase "InitToken resets the token and unsets the user PIN" caseInitTokenResets
  , testCase "refused PIN change preserves the credential" caseSetPinRefusedPreserves
  , testCase "public read/write session changes the user PIN" caseSetPinPublic
  , testCase "read-only sessions refuse provisioning" caseProvisionReadOnly
  , testCase "failed provisioning write dirties the view, login fails closed" caseProvisionDirty
  , testGroup "non-home InitToken store failure (sqlite seams)"
      [ testCase "injected body failure keeps the old credential, label and generation" caseInitTokenBodyFailure
      , testCase "injected cleanup failure quarantines the connection until reopen" caseInitTokenCleanupFailure
      , testCase "injected unknown COMMIT keeps the token quarantined, never replays" caseInitTokenCommitUnknown
      ]
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

-- ---------------------------------------------------------------------------
-- Durable login across processes
-- ---------------------------------------------------------------------------

-- | End-to-end durable authentication over one SQLite file. Wrong
-- user PINs consume retries that survive finalize/reinitialize
-- ('haskokiStdClose' plus 'openStdInstance'); a correct login
-- resets them; the third strike locks the role; a reopened
-- session is never restored authenticated; and a second OS
-- process observes the same counters and lockout while the SO
-- role stays independent. A raw store read after each restart
-- pins the durable counters behind the observed return codes.
caseLoginLockoutDurable :: IO ()
caseLoginLockoutDurable =
  bracket (makeTempDir "haskoki-auth-test") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
        doneFile = dir </> "done"
        readyFile = dir </> "ready"
        resultFile = dir </> "probe.out"
    -- Phase A: strike, reset, log out, strike again, then an
    -- SO login left standing across the close. The logout keeps
    -- the reset counters (logout is transient-only) while
    -- freeing the token for the next attempt.
    withAuthInstance path $ \ctx -> do
      h <- openAuthSession ctx
      loginAs ctx h 1 "0000" >>= assertEqual "strike 1" (stdRvOf CKR_PIN_INCORRECT)
      loginAs ctx h 1 "1234" >>= assertEqual "reset login" (CULong 0)
      haskokiStdLogout ctx h >>= assertEqual "reset logout" (CULong 0)
      loginAs ctx h 1 "0000" >>= assertEqual "strike 1 again" (stdRvOf CKR_PIN_INCORRECT)
      loginAs ctx h 0 "5678" >>= assertEqual "SO login" (CULong 0)
    -- Phase B: reinitialize. The session opens public (the SO
    -- login was never restored); two more user strikes lock the
    -- role, proving the pre-lockout count survived the restart.
    withAuthInstance path $ \ctx -> do
      h <- openAuthSession ctx
      sessionLoginOf ctx h >>= assertEqual "reopened session public" (CULong 0)
      loginAs ctx h 1 "0000" >>= assertEqual "strike 2" (stdRvOf CKR_PIN_INCORRECT)
      loginAs ctx h 1 "0000" >>= assertEqual "strike 3 locks" (stdRvOf CKR_PIN_LOCKED)
    authAfterB <- readTokenAuth path
    assertEqual "user strikes" 3 (taUserAttempts authAfterB)
    assertEqual "user locked" True (taUserLocked authAfterB)
    assertEqual "SO settled" 0 (taSoAttempts authAfterB)
    -- Phase C: a second OS process observes the lockout, then
    -- exercises the independent SO role.
    reaped <- newIORef False
    bracket
      (spawnHolderEnv
        [ ("HASKOKI_HOLDER_MODE", "auth-probe")
        , ("HASKOKI_AUTH_SCRIPT", "info,u-good,s-bad,s-good,logout")
        , ("HASKOKI_AUTH_RESULT", resultFile)
        ]
        path doneFile readyFile)
      (releaseHolder reaped)
      $ \ph -> do
        awaitHolderExit reaped ph "auth probe"
        out <- readFile resultFile
        let CULong incorrect = stdRvOf CKR_PIN_INCORRECT
            CULong locked = stdRvOf CKR_PIN_LOCKED
        assertEqual "probe lines"
          [ "info=0"
          , "u-good=" ++ show locked
          , "s-bad=" ++ show incorrect
          , "s-good=0"
          , "logout=0"
          ]
          (lines out)
    -- Phase D: reinitialize again. The user lockout held; the SO
    -- role serves and logs out normally.
    withAuthInstance path $ \ctx -> do
      h <- openAuthSession ctx
      loginAs ctx h 1 "1234" >>= assertEqual "user still locked" (stdRvOf CKR_PIN_LOCKED)
      loginAs ctx h 0 "5678" >>= assertEqual "SO login" (CULong 0)
      sessionLoginOf ctx h >>= assertEqual "session SO" (CULong 2)
      haskokiStdLogout ctx h >>= assertEqual "SO logout" (CULong 0)
      sessionLoginOf ctx h >>= assertEqual "session public" (CULong 0)
    authAfterD <- readTokenAuth path
    assertEqual "SO settled after good login" 0 (taSoAttempts authAfterD)
    assertEqual "user lock held" True (taUserLocked authAfterD)

-- | Open a serving instance over the database path (home
-- catalog, SQLite store), closing it on exit.
withAuthInstance :: FilePath -> (StablePtr StdInstance -> IO a) -> IO a
withAuthInstance = withAuthInstanceOn stdAcquisition

-- | 'withAuthInstance' over injected acquisition steps (fault
-- wrappers observe or rewrite the opened store's commits).
withAuthInstanceOn
  :: StdAcquisition -> FilePath -> (StablePtr StdInstance -> IO a) -> IO a
withAuthInstanceOn sa path = withAuthInstanceOnCfg sa sqliteCfg
  where
    sqliteCfg = defaultConfig
      { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True }

-- | 'withAuthInstanceOn' over an explicit config (multi-token
-- catalogs).
withAuthInstanceOnCfg
  :: StdAcquisition -> Config -> (StablePtr StdInstance -> IO a) -> IO a
withAuthInstanceOnCfg sa cfg = bracket openIt haskokiStdClose
  where
    openIt = do
      ctx <- openStdInstanceWith sa cfg
      assertBool "instance opens" (castStablePtrToPtr ctx /= nullPtr)
      pure ctx

-- | Open one read/write session on slot 0 (fails unless OK).
openAuthSession :: StablePtr StdInstance -> IO CULong
openAuthSession ctx = openAuthSessionOn ctx 0

-- | Open one read/write session on the given slot (fails unless OK).
openAuthSessionOn :: StablePtr StdInstance -> CULong -> IO CULong
openAuthSessionOn ctx slot =
  alloca $ \(phSession :: Ptr CULong) -> do
    poke phSession (CULong 0)
    rv <- haskokiStdOpenSession ctx slot (CULong 0) phSession
    assertEqual "open rv" (CULong 0) rv
    peek phSession

-- | Log in with the given role word (0 SO, 1 user) and PIN bytes.
loginAs :: StablePtr StdInstance -> CULong -> CULong -> String -> IO CULong
loginAs ctx h userType pinStr =
  BS.useAsCStringLen (BC8.pack pinStr) $ \(cstr, len) ->
    haskokiStdLogin ctx h userType (castPtr cstr) (fromIntegral len)

-- | Read one session's provider-local login code (0 public, 1
-- user, 2 SO, 3 context grant; fails unless the info call is OK).
sessionLoginOf :: StablePtr StdInstance -> CULong -> IO CULong
sessionLoginOf ctx h =
  alloca $ \(pSlot :: Ptr CULong) ->
  alloca $ \(pRO :: Ptr CULong) ->
  alloca $ \(pLogin :: Ptr CULong) ->
  alloca $ \(pDevErr :: Ptr CULong) -> do
    rv <- haskokiStdGetSessionInfo ctx h pSlot pRO pLogin pDevErr
    assertEqual "session-info rv" (CULong 0) rv
    peek pLogin

-- | Read the home token's durable auth straight from the file
-- (fails unless exactly one token row is stored).
readTokenAuth :: FilePath -> IO TokenAuth
readTokenAuth path = do
  eSt <- openSQLiteStore path
  st <- either (assertFailure . show) pure eSt
  eLoaded <- storeLoadTokens st
  loaded <- either (assertFailure . show) pure eLoaded
  storeClose st
  case loaded of
    [(tok, _)] -> pure (trAuth tok)
    _ -> assertFailure "expected exactly one token row"

-- | A durable auth write that does not land fails the login
-- with @CKR_GENERAL_ERROR@ (@0x05@) instead of the denial code:
-- the counters never moved, so answering @CKR_PIN_INCORRECT@
-- would spend an attempt the store never recorded. A grant on
-- settled counters still succeeds (transient-only, bypassing
-- the broken store), and the raw counters stay settled.
caseLoginFailClosed :: IO ()
caseLoginFailClosed =
  bracket (makeTempDir "haskoki-auth-failclosed") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    -- Seed the file with a clean open first: the failing
    -- acquisition must not break the seed commit itself.
    withAuthInstance path $ \_ -> pure ()
    withAuthInstanceOn failingAcquisition path $ \ctx -> do
      h <- openAuthSession ctx
      loginAs ctx h 1 "0000" >>= assertEqual "failed write fails closed" (CULong 0x05)
      loginAs ctx h 1 "1234" >>= assertEqual "settled grant bypasses" (CULong 0)
      sessionLoginOf ctx h >>= assertEqual "session user" (CULong 1)
      haskokiStdLogout ctx h >>= assertEqual "logout" (CULong 0)
    auth <- readTokenAuth path
    assertEqual "counters never moved" 0 (taUserAttempts auth)
    assertEqual "unlocked" False (taUserLocked auth)

-- | Acquisition whose store refuses every commit without
-- effect: the login path's fail-closed leg.
failingAcquisition :: StdAcquisition
failingAcquisition = stdAcquisition
  { saOpenStore = \env cfg -> do
      eStore <- saOpenStore stdAcquisition env cfg
      case eStore of
        Left err -> pure (Left err)
        Right mStore -> pure (Right (fmap wrapStd mStore))
  }
  where
    wrapStd ss = ss { stdStore = (stdStore ss)
      { storeCommit = \_ -> pure (NotCommitted (StoreIO "injected auth failure")) } }

-- | An auth write that lands but reports unknown reconciles
-- through the serving instance, against REAL backend faults
-- (ambiguous commit plus verification failure, so the backend
-- quarantines for real): the denial code still answers, the
-- inline reload clears the quarantine (pinned live: removing
-- the recovery reload wedges the next write instead), the next
-- attempt serves normally, and the raw counters show both
-- strikes — the attempt counted exactly once, never replayed.
caseLoginUnknownLanded :: IO ()
caseLoginUnknownLanded =
  bracket (makeTempDir "haskoki-auth-unknown") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    withAuthInstance path $ \_ -> pure ()
    inj <- scriptedFaults [FaultAmbiguousCommit, FaultVerifyReload]
    withAuthInstanceOn (realUnknownAcquisition inj) path $ \ctx -> do
      h <- openAuthSession ctx
      loginAs ctx h 1 "0000" >>= assertEqual "unknown still incorrect" (stdRvOf CKR_PIN_INCORRECT)
      liveQuarantine ctx >>= assertEqual "reload cleared quarantine" []
      loginAs ctx h 1 "0000" >>= assertEqual "second strike" (stdRvOf CKR_PIN_INCORRECT)
    auth <- readTokenAuth path
    assertEqual "both strikes durable, never replayed" 2 (taUserAttempts auth)

-- | Acquisition whose store opens with a scripted fault
-- injector through the production open path
-- ('openStdStoreWith'): injected faults exercise the real
-- backend commit protocol under the serving instance.
realUnknownAcquisition :: FaultInjector -> StdAcquisition
realUnknownAcquisition inj = stdAcquisition
  { saOpenStore = \env cfg ->
      openStdStoreWith (\p -> openSQLiteStoreWith p defaultLimits inj) env cfg
  }

-- | Read the serving instance's live quarantine list (fails
-- unless the instance holds a store).
liveQuarantine :: StablePtr StdInstance -> IO [TokenId]
liveQuarantine ctx = do
  inst <- deRefStablePtr ctx
  case siStore inst of
    Nothing -> assertFailure "expected a stored instance"
    Just ss -> map fst <$> storeQuarantined (stdStore ss)

-- | A landed write still publishes when its recovery reload
-- fails: the reload already proved durable holds the delta, so
-- the reconciled model is the authority-matching state. The
-- first commit lands-for-real but reports unknown while the
-- first reload fails outright; both logins still answer their
-- denial codes and both strikes land exactly once.
caseLoginReloadFailsLanded :: IO ()
caseLoginReloadFailsLanded =
  bracket (makeTempDir "haskoki-auth-reloadfail") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    withAuthInstance path $ \_ -> pure ()
    once <- newIORef True
    reloadOnce <- newIORef True
    withAuthInstanceOn (lyingAcquisition once reloadOnce) path $ \ctx -> do
      h <- openAuthSession ctx
      loginAs ctx h 1 "0000" >>= assertEqual "landed answers" (stdRvOf CKR_PIN_INCORRECT)
      loginAs ctx h 1 "0000" >>= assertEqual "second strike" (stdRvOf CKR_PIN_INCORRECT)
    auth <- readTokenAuth path
    assertEqual "both strikes durable" 2 (taUserAttempts auth)

-- | Acquisition whose store commits the first delta for real
-- but reports it unknown, and whose first reload fails
-- outright; everything after reports honestly.
lyingAcquisition :: IORef Bool -> IORef Bool -> StdAcquisition
lyingAcquisition once reloadOnce = stdAcquisition
  { saOpenStore = \env cfg -> do
      eStore <- saOpenStore stdAcquisition env cfg
      case eStore of
        Left err -> pure (Left err)
        Right mStore -> pure (Right (fmap wrapStd mStore))
  }
  where
    wrapStd ss = ss { stdStore = (stdStore ss)
      { storeCommit = lyingCommit (storeCommit (stdStore ss))
      , storeReload = lyingReload (storeReload (stdStore ss)) } }
    lyingCommit backing delta = do
      fire <- atomicModifyIORef' once (\b -> (False, b))
      res <- backing delta
      if fire
        then pure (CommitUnknown (StoreIO "injected ambiguity"))
        else pure res
    lyingReload backing = do
      fire <- atomicModifyIORef' reloadOnce (\b -> (False, b))
      if fire
        then pure (Left (StoreIO "injected reload failure"))
        else backing

-- | Retry state is per token: strikes and lockout on slot 0
-- never disturb slot 1, and the slot-0 lockout survives a
-- close/reopen boundary while slot 1 keeps serving.
caseLoginTokenIndependent :: IO ()
caseLoginTokenIndependent =
  bracket (makeTempDir "haskoki-auth-tokens") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    cfg <- twoTokenConfig path
    withAuthInstanceOnCfg stdAcquisition cfg $ \ctx -> do
      s0 <- openAuthSessionOn ctx 0
      s1 <- openAuthSessionOn ctx 1
      loginAs ctx s0 1 "0000" >>= assertEqual "slot-0 strike 1" (stdRvOf CKR_PIN_INCORRECT)
      loginAs ctx s0 1 "0000" >>= assertEqual "slot-0 strike 2" (stdRvOf CKR_PIN_INCORRECT)
      loginAs ctx s1 1 "2345" >>= assertEqual "slot-1 unaffected" (CULong 0)
      haskokiStdLogout ctx s1 >>= assertEqual "slot-1 logout" (CULong 0)
      loginAs ctx s0 1 "0000" >>= assertEqual "slot-0 strike 3 locks" (stdRvOf CKR_PIN_LOCKED)
      loginAs ctx s1 1 "2345" >>= assertEqual "slot-1 still fine" (CULong 0)
    withAuthInstanceOnCfg stdAcquisition cfg $ \ctx -> do
      s0 <- openAuthSessionOn ctx 0
      s1 <- openAuthSessionOn ctx 1
      loginAs ctx s0 1 "1234" >>= assertEqual "slot-0 lockout durable" (stdRvOf CKR_PIN_LOCKED)
      loginAs ctx s1 1 "2345" >>= assertEqual "slot-1 serves" (CULong 0)

-- | Call InitPIN on a session with a Haskell-string PIN.
callInitPin :: StablePtr StdInstance -> CULong -> String -> IO CULong
callInitPin ctx h pinStr =
  BS.useAsCStringLen (BC8.pack pinStr) $ \(cstr, len) ->
    haskokiStdInitPin ctx h (castPtr cstr) (fromIntegral len)

-- | Call SetPIN on a session with Haskell-string old/new PINs.
callSetPin :: StablePtr StdInstance -> CULong -> String -> String -> IO CULong
callSetPin ctx h oldStr newStr =
  BS.useAsCStringLen (BC8.pack oldStr) $ \(cOld, lenOld) ->
    BS.useAsCStringLen (BC8.pack newStr) $ \(cNew, lenNew) ->
      haskokiStdSetPin ctx h (castPtr cOld) (fromIntegral lenOld)
        (castPtr cNew) (fromIntegral lenNew)

-- | Call InitToken on a slot with a Haskell-string SO PIN and
-- label (the label pads to the fixed 32 C bytes here, as the
-- C caller would).
callInitToken :: StablePtr StdInstance -> CULong -> String -> String -> IO CULong
callInitToken ctx slot pinStr labelStr =
  BS.useAsCStringLen (BC8.pack pinStr) $ \(cPin, lenPin) ->
    BS.useAsCStringLen (BC8.pack (take 32 (labelStr ++ repeat ' '))) $ \(cLabel, _) ->
      haskokiStdInitToken ctx slot (castPtr cPin) (fromIntegral lenPin) (castPtr cLabel)

-- | Read the live instance's stored credentials (no second
-- handle: the instance's own store answers).
liveCredentials :: StablePtr StdInstance -> IO [CredentialRecord]
liveCredentials ctx = do
  inst <- deRefStablePtr ctx
  case siStore inst of
    Nothing -> assertFailure "expected a stored instance" >> pure []
    Just ss -> do
      eCreds <- storeLoadCredentials (stdStore ss)
      either (assertFailure . show) pure eCreds

-- | A user PIN change persists across close and reopen: the
-- old PIN refuses, the new PIN serves.
caseSetPinDurable :: IO ()
caseSetPinDurable =
  bracket (makeTempDir "haskoki-setpin-durable") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    withAuthInstance path $ \ctx -> do
      h <- openAuthSession ctx
      loginAs ctx h 1 "1234" >>= assertEqual "user login" (CULong 0)
      callSetPin ctx h "1234" "9999" >>= assertEqual "set-pin" (CULong 0)
      sessionLoginOf ctx h >>= assertEqual "still logged in" (CULong 1)
      haskokiStdLogout ctx h >>= assertEqual "logout" (CULong 0)
    withAuthInstance path $ \ctx -> do
      h <- openAuthSession ctx
      loginAs ctx h 1 "1234" >>= assertEqual "old PIN refused" (stdRvOf CKR_PIN_INCORRECT)
      loginAs ctx h 1 "9999" >>= assertEqual "new PIN serves" (CULong 0)

-- | SO recovery: after the user locks out, an SO login plus
-- InitPIN sets a fresh user PIN, clears the lock, and resets
-- the counter; the user serves again on the new PIN.
caseInitPinRecovery :: IO ()
caseInitPinRecovery =
  bracket (makeTempDir "haskoki-initpin-recovery") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    withAuthInstance path $ \ctx -> do
      h <- openAuthSession ctx
      loginAs ctx h 1 "0000" >>= assertEqual "strike 1" (stdRvOf CKR_PIN_INCORRECT)
      loginAs ctx h 1 "0000" >>= assertEqual "strike 2" (stdRvOf CKR_PIN_INCORRECT)
      loginAs ctx h 1 "0000" >>= assertEqual "strike 3 locks" (stdRvOf CKR_PIN_LOCKED)
      loginAs ctx h 0 "5678" >>= assertEqual "SO login" (CULong 0)
      callInitPin ctx h "5555" >>= assertEqual "init-pin" (CULong 0)
      haskokiStdLogout ctx h >>= assertEqual "SO logout" (CULong 0)
      loginAs ctx h 1 "5555" >>= assertEqual "user serves again" (CULong 0)
    auth <- readTokenAuth path
    assertEqual "attempts reset" 0 (taUserAttempts auth)
    assertEqual "lock cleared" False (taUserLocked auth)

-- | InitToken resets its token: fresh auth, the new SO PIN,
-- the same label still reconciling, and an uninitialized user
-- PIN (user login answers @CKR_USER_PIN_NOT_INITIALIZED@
-- until the SO runs InitPIN). The full lifecycle then
-- persists across a reopen.
caseInitTokenResets :: IO ()
caseInitTokenResets =
  bracket (makeTempDir "haskoki-inittoken-resets") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    withAuthInstance path $ \ctx -> do
      h <- openAuthSession ctx
      loginAs ctx h 1 "0000" >>= assertEqual "strike 1" (stdRvOf CKR_PIN_INCORRECT)
      loginAs ctx h 1 "0000" >>= assertEqual "strike 2" (stdRvOf CKR_PIN_INCORRECT)
      loginAs ctx h 1 "0000" >>= assertEqual "strike 3 locks" (stdRvOf CKR_PIN_LOCKED)
      haskokiStdCloseSession ctx h >>= assertEqual "close session" (CULong 0)
      callInitToken ctx 0 "5678" "haskoki-demo" >>= assertEqual "init-token" (CULong 0)
      h2 <- openAuthSession ctx
      loginAs ctx h2 1 "1234" >>= assertEqual "user PIN uninitialized" (CULong 0x102)
      loginAs ctx h2 0 "5678" >>= assertEqual "SO PIN serves" (CULong 0)
      -- rotation is via SO SetPIN: re-init authorizes, never rotates
      callSetPin ctx h2 "5678" "7777" >>= assertEqual "SO PIN rotates" (CULong 0)
      haskokiStdLogout ctx h2 >>= assertEqual "SO logout" (CULong 0)
      loginAs ctx h2 0 "7777" >>= assertEqual "rotated SO PIN serves" (CULong 0)
      callInitPin ctx h2 "8888" >>= assertEqual "init-pin" (CULong 0)
      haskokiStdLogout ctx h2 >>= assertEqual "SO logout" (CULong 0)
      loginAs ctx h2 1 "8888" >>= assertEqual "user serves on new PIN" (CULong 0)
    auth <- readTokenAuth path
    assertEqual "attempts fresh" 0 (taUserAttempts auth)
    assertEqual "unlocked" False (taUserLocked auth)
    withAuthInstance path $ \ctx -> do
      h <- openAuthSession ctx
      loginAs ctx h 1 "8888" >>= assertEqual "lifecycle survives reopen" (CULong 0)

-- | A refused PIN change (wrong old PIN) preserves the stored
-- credential byte-exact while consuming one attempt: the
-- strike counts, the PIN does not move.
caseSetPinRefusedPreserves :: IO ()
caseSetPinRefusedPreserves =
  bracket (makeTempDir "haskoki-setpin-refused") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    withAuthInstance path $ \ctx -> do
      h <- openAuthSession ctx
      loginAs ctx h 1 "1234" >>= assertEqual "user login" (CULong 0)
      callSetPin ctx h "1234" "9999" >>= assertEqual "set-pin" (CULong 0)
      before <- liveCredentials ctx
      assertEqual "one credential row" 1 (length before)
      callSetPin ctx h "0000" "1111" >>= assertEqual "wrong old PIN refused"
        (stdRvOf CKR_PIN_INCORRECT)
      after <- liveCredentials ctx
      assertEqual "credential preserved" before after
    auth <- readTokenAuth path
    assertEqual "strike consumed" 1 (taUserAttempts auth)

-- | Open one read-only session on slot 0 (fails unless OK).
openAuthSessionRO :: StablePtr StdInstance -> IO CULong
openAuthSessionRO ctx =
  alloca $ \(phSession :: Ptr CULong) -> do
    poke phSession (CULong 0)
    rv <- haskokiStdOpenSession ctx (CULong 0) (CULong 1) phSession
    assertEqual "open read-only session" (CULong 0) rv
    peek phSession

-- | The old PIN authenticates: a public read/write session
-- changes the user PIN without logging in (the reference
-- session-state rule), and the new PIN serves afterwards.
caseSetPinPublic :: IO ()
caseSetPinPublic =
  bracket (makeTempDir "haskoki-setpin-public") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    withAuthInstance path $ \ctx -> do
      h <- openAuthSession ctx
      sessionLoginOf ctx h >>= assertEqual "session public" (CULong 0)
      callSetPin ctx h "1234" "31337" >>= assertEqual "public set-pin" (CULong 0)
      sessionLoginOf ctx h >>= assertEqual "session still public" (CULong 0)
      loginAs ctx h 1 "31337" >>= assertEqual "new PIN serves" (CULong 0)

-- | Read-only sessions refuse provisioning: SetPIN answers
-- @CKR_SESSION_READ_ONLY@ even logged in, and InitPIN answers
-- @CKR_USER_NOT_LOGGED_IN@ on any non-SO session (a read-only
-- session can never be an SO session: opening one while the SO
-- is logged in refuses, and the SO cannot log in while one is
-- open). No refusal consumes an attempt.
caseProvisionReadOnly :: IO ()
caseProvisionReadOnly =
  bracket (makeTempDir "haskoki-provision-ro") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    withAuthInstance path $ \ctx -> do
      rw <- openAuthSession ctx
      ro <- openAuthSessionRO ctx
      loginAs ctx ro 1 "1234" >>= assertEqual "user login on read-only" (CULong 0)
      callSetPin ctx ro "1234" "9999" >>= assertEqual "logged-in read-only refuses"
        (stdRvOf CKR_SESSION_READ_ONLY)
      callInitPin ctx ro "9999" >>= assertEqual "InitPIN on read-only refuses"
        (stdRvOf CKR_USER_NOT_LOGGED_IN)
      callInitPin ctx rw "9999" >>= assertEqual "InitPIN on public session refuses"
        (stdRvOf CKR_USER_NOT_LOGGED_IN)
    auth <- readTokenAuth path
    assertEqual "no user strike" 0 (taUserAttempts auth)
    assertEqual "no SO strike" 0 (taSoAttempts auth)

-- | A failed provisioning write settles the serving view: the
-- re-sync attempt fails here (the store handle is closed), so
-- the slot marks dirty, and a later login — even one whose
-- settled counters would bypass the store — fails closed with
-- @CKR_GENERAL_ERROR@ instead of authenticating against a
-- possibly stale view.
caseProvisionDirty :: IO ()
caseProvisionDirty =
  bracket (makeTempDir "haskoki-provision-dirty") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    withAuthInstance path $ \ctx -> do
      h <- openAuthSession ctx
      inst <- deRefStablePtr ctx
      case siStore inst of
        Nothing -> assertFailure "expected a stored instance"
        Just ss -> storeClose (stdStore ss)
      callSetPin ctx h "1234" "9999" >>= assertEqual "set-pin fails closed"
        (CULong 0x05)
      loginAs ctx h 1 "1234" >>= assertEqual "login fails closed on dirty view"
        (CULong 0x05)

-- | A two-token SQLite config over the path (positional
-- identities: slot 0 demo, slot 1 ops, with distinct PINs).
twoTokenConfig :: FilePath -> IO Config
twoTokenConfig path = case parseConfig (unlines
  [ "schema_version = 1"
  , "[tokens]"
  , "labels = [\"haskoki-demo\", \"haskoki-ops\"]"
  , "so_pins = [\"5678\", \"6789\"]"
  , "user_pins = [\"1234\", \"2345\"]"
  ]) of
    Left err -> assertFailure ("two-token config must parse: " ++ show err)
    Right cfg -> pure (cfg { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True })

-- ---------------------------------------------------------------------------
-- Public non-home InitToken under store failure (AC-01)
-- ---------------------------------------------------------------------------

-- These cases drive 'haskokiStdInitToken' — the implementation the
-- exported @haskoki_std_init_token@ symbol (and so the C ABI's
-- C_InitToken) runs — on slot 1 of a two-token SQLite instance,
-- opened through the production acquisition path
-- ('openStdStoreWith') over a hooked store: the test-only seams
-- act on the store's own connection inside the real InitToken
-- commit. Preconditions are the granted shape: the existing SO PIN
-- (6789), no sessions on the slot, a bounded relabel
-- (@ops-relabelled@). Each stimulus is labelled injected.

-- | The test-only hooks: the transaction-control and commit
-- seams install on the first commit (the open-time commits run
-- through them unstimulated), and an armed stimulus fires once,
-- immediately before the next @BEGIN IMMEDIATE@.
data InitTokenSeams = InitTokenSeams
  { itArmed :: IORef (Maybe (S.Database -> IO ()))
  , itTxn :: TxnSeam
  , itCommit :: CommitSeam
  }

newInitTokenSeams :: IO InitTokenSeams
newInitTokenSeams = InitTokenSeams <$> newIORef Nothing <*> newTxnSeam <*> newCommitSeam

-- | Acquisition over the hooked opener (production open flow).
seamAcquisition :: InitTokenSeams -> StdAcquisition
seamAcquisition seams = stdAcquisition
  { saOpenStore = \env cfg ->
      openStdStoreWith (\p -> openSQLiteStoreWithHooks p defaultLimits noFaults hooks) env cfg
  }
  where
    hooks = noSQLiteTestHooks
      { sthBeforeBegin = \db -> do
          installTxnSeam (itTxn seams) db
          installCommitSeam (itCommit seams) db
          stimulus <- atomicModifyIORef' (itArmed seams) (\m -> (Nothing, m))
          maybe (pure ()) ($ db) stimulus
          markCommits (itCommit seams)
      }

-- | Run one public call with the stimulus armed, returning its
-- code, the transaction-control statements it prepared, and how
-- many commits reached the commit point during it.
armedCall :: InitTokenSeams -> (S.Database -> IO ()) -> IO CULong -> IO (CULong, [Text], Int)
armedCall seams stimulus call = do
  ops0 <- length <$> readIORef (tsLog (itTxn seams))
  markCommits (itCommit seams)
  writeIORef (itArmed seams) (Just stimulus)
  rv <- call
  ops <- drop ops0 . reverse <$> readIORef (tsLog (itTxn seams))
  calls <- commitsSinceMark (itCommit seams)
  pure (rv, ops, calls)

-- | Seed the two-token store: slot 1's user PIN is provisioned to
-- 4242 (a durable credential row next to SO PIN 6789), then a
-- plain open\/close settles any open-time writes.
seedNonHome :: Config -> IO ()
seedNonHome cfg = do
  withAuthInstanceOnCfg stdAcquisition cfg $ \ctx -> do
    h <- openAuthSessionOn ctx 1
    callSetPin ctx h "2345" "4242" >>= assertEqual "provision slot-1 user PIN" (CULong 0)
    haskokiStdCloseSession ctx h >>= assertEqual "close session" (CULong 0)
  withAuthInstanceOnCfg stdAcquisition cfg $ \_ -> pure ()

-- | Slot 1's durable token row and credential rows, read from the
-- closed file.
slotOneDurable :: FilePath -> IO (TokenRecord, [CredentialRecord])
slotOneDurable path = do
  st <- openSQLiteStore path >>= expectRight "open raw"
  loaded <- storeLoadTokens st >>= expectRight "load tokens"
  creds <- storeLoadCredentials st >>= expectRight "load credentials"
  storeClose st
  case [t | (t, _) <- loaded, trSlot t == SlotId 1] of
    [t] -> pure (t, [c | c <- creds, crToken c == trId t])
    other -> assertFailure ("expected one slot-1 token row, got: " ++ show other)

-- | The durable state is wholly the seeded one: every raw row
-- equal, slot 1's token (label @haskoki-ops@, generation) and
-- credential (SO 6789, user 4242) unchanged, and a fresh instance
-- serves the old user and SO PINs on slot 1.
assertNonHomeOld :: Config -> FilePath -> [(Text, [[S.SQLData]])] -> (TokenRecord, [CredentialRecord]) -> IO ()
assertNonHomeOld cfg path before (tokBefore, credBefore) = do
  after <- dumpTables path
  assertTablesEqual before after
  (tokAfter, credAfter) <- slotOneDurable path
  assertEqual "slot-1 label unchanged" "haskoki-ops" (trLabel tokAfter)
  assertEqual "slot-1 token row (label, generation, auth) unchanged" tokBefore tokAfter
  assertEqual "slot-1 credential unchanged" credBefore credAfter
  assertEqual "the old user PIN is the stored one" [Just (BC8.pack "4242")] (map crUserPin credAfter)
  withAuthInstanceOnCfg stdAcquisition cfg $ \ctx -> do
    h <- openAuthSessionOn ctx 1
    loginAs ctx h 1 "4242" >>= assertEqual "old user PIN serves after reopen" (CULong 0)
    haskokiStdLogout ctx h >>= assertEqual "logout" (CULong 0)
    loginAs ctx h 0 "6789" >>= assertEqual "old SO PIN serves after reopen" (CULong 0)

-- | Injected @RAISE(ROLLBACK)@ at the token upsert (sequencing
-- only): SQLite rolls the whole InitToken transaction back
-- natively, no later group runs, no cleanup statement runs, and
-- the call fails with @CKR_GENERAL_ERROR@. The serving view stays
-- the old one, nothing is quarantined, and after reopen the old
-- user credential, label and generation are unchanged.
caseInitTokenBodyFailure :: IO ()
caseInitTokenBodyFailure =
  bracket (makeTempDir "haskoki-inittoken-body") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    cfg <- twoTokenConfig path
    seedNonHome cfg
    durableBefore <- slotOneDurable path
    before <- dumpTables path
    seams <- newInitTokenSeams
    withAuthInstanceOnCfg (seamAcquisition seams) cfg $ \ctx -> do
      (rv, ops, commits) <- armedCall seams (failTokenUpsert "ROLLBACK")
        (callInitToken ctx 1 "6789" "ops-relabelled")
      assertEqual "forced body failure fails the call" (CULong 0x05) rv
      assertEqual "rolled back natively: no cleanup statement" ["BEGIN"] ops
      assertEqual "nothing reached the commit point" 0 commits
      liveQuarantine ctx >>= assertEqual "a proven rollback quarantines nothing" []
      h <- openAuthSessionOn ctx 1
      loginAs ctx h 1 "4242" >>= assertEqual "the live view still serves the old user PIN" (CULong 0)
      haskokiStdLogout ctx h >>= assertEqual "logout" (CULong 0)
    assertNonHomeOld cfg path before durableBefore

-- | Injected cleanup failure: a still-active body ABORT, then the
-- ROLLBACK denied, so the InitToken write transaction stays open
-- on the store connection. The call fails with
-- @CKR_GENERAL_ERROR@; the whole connection is quarantined (both
-- tokens) and refuses loads, so the open transaction is never
-- reconciled as "landed" nor served: a slot-1 login fails closed.
-- Closing the instance rolls the transaction back natively, and
-- the reopened store holds the whole old state.
caseInitTokenCleanupFailure :: IO ()
caseInitTokenCleanupFailure =
  bracket (makeTempDir "haskoki-inittoken-cleanup") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    cfg <- twoTokenConfig path
    seedNonHome cfg
    durableBefore@(tokBefore, _) <- slotOneDurable path
    before <- dumpTables path
    seams <- newInitTokenSeams
    let stimulus db = failTokenUpsert "ABORT" db >> writeIORef (tsDeny (itTxn seams)) ["ROLLBACK"]
    withAuthInstanceOnCfg (seamAcquisition seams) cfg $ \ctx -> do
      (rv, ops, commits) <- armedCall seams stimulus (callInitToken ctx 1 "6789" "ops-relabelled")
      assertEqual "cleanup failure fails the call" (CULong 0x05) rv
      assertEqual "the ROLLBACK was denied" ["BEGIN", "ROLLBACK:denied"] ops
      assertEqual "nothing reached the commit point" 0 commits
      quarantined <- sort <$> liveQuarantine ctx
      assertEqual "the whole connection is quarantined (both tokens)" 2 (length quarantined)
      assertBool "the slot-1 token is quarantined" (trId tokBefore `elem` quarantined)
      h <- openAuthSessionOn ctx 1
      loginAs ctx h 1 "4242" >>= assertEqual "slot-1 login fails closed" (CULong 0x05)
    assertNonHomeOld cfg path before durableBefore

-- | Injected unknown COMMIT: the commit hook turns the InitToken
-- COMMIT into a rollback, so COMMIT fails with the connection
-- back in autocommit — an outcome the store cannot establish. The
-- call fails with @CKR_GENERAL_ERROR@ after exactly one COMMIT
-- (never reissued, no ROLLBACK). The slot-1 token stays
-- quarantined: the serving view re-syncs from durable truth (the
-- old user PIN serves on settled counters), but writes touching
-- the token — a SetPIN, a repeated InitToken — fail closed
-- without reaching the store. After reopen the whole old state
-- holds, and the same InitToken then succeeds (the stimulus alone
-- failed it).
caseInitTokenCommitUnknown :: IO ()
caseInitTokenCommitUnknown =
  bracket (makeTempDir "haskoki-inittoken-unknown") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "auth.db"
    cfg <- twoTokenConfig path
    seedNonHome cfg
    durableBefore@(tokBefore, _) <- slotOneDurable path
    before <- dumpTables path
    seams <- newInitTokenSeams
    let failCommit _ = writeIORef (csFailNext (itCommit seams)) True
    withAuthInstanceOnCfg (seamAcquisition seams) cfg $ \ctx -> do
      (rv, ops, commits) <- armedCall seams failCommit (callInitToken ctx 1 "6789" "ops-relabelled")
      assertEqual "unknown COMMIT fails the call" (CULong 0x05) rv
      assertEqual "one BEGIN, one COMMIT, no ROLLBACK" ["BEGIN", "COMMIT"] ops
      assertEqual "the COMMIT reached the commit point once (never replayed)" 1 commits
      liveQuarantine ctx >>= assertEqual "the slot-1 token stays quarantined" [trId tokBefore]
      h <- openAuthSessionOn ctx 1
      loginAs ctx h 1 "4242" >>= assertEqual "durable-truth view serves the old user PIN" (CULong 0)
      haskokiStdLogout ctx h >>= assertEqual "logout" (CULong 0)
      (rvSet, opsSet, commitsSet) <- armedCall seams (\_ -> pure ())
        (callSetPin ctx h "4242" "9999")
      assertEqual "a write on the quarantined token fails closed" (CULong 0x05) rvSet
      assertEqual "the refused write ran no transaction" [] opsSet
      assertEqual "the refused write reached no commit" 0 commitsSet
      haskokiStdCloseSession ctx h >>= assertEqual "close session" (CULong 0)
      (rvAgain, opsAgain, commitsAgain) <- armedCall seams (\_ -> pure ())
        (callInitToken ctx 1 "6789" "ops-relabelled")
      assertEqual "a repeated InitToken fails closed" (CULong 0x05) rvAgain
      assertEqual "the repeat ran no transaction" [] opsAgain
      assertEqual "the repeat reached no commit" 0 commitsAgain
      liveQuarantine ctx >>= assertEqual "quarantine retained" [trId tokBefore]
    assertNonHomeOld cfg path before durableBefore
    withAuthInstanceOnCfg stdAcquisition cfg $ \ctx ->
      callInitToken ctx 1 "6789" "ops-relabelled" >>= assertEqual "control: the same InitToken succeeds" (CULong 0)
