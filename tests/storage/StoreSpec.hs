{- | Store contract suite.

Persist token objects, close, reload from the
same store identity, and obtain the SAME logical data with FRESH
handles. Handles are minted by the live model, never resurrected
from disk: the stored encoding carries no handle field at all (the
object-document key set pins that), and the reloaded objects bind
whatever handles the new generation's counters hand out.

The suite is parameterized over the backend opener so Memory and
SQLite satisfy the SAME contract ('contractSpec'). Backend-specific
fixtures (a 'MemoryWorld' vs a SQLite file path) supply the shared
store identity across the close/reopen boundary.
-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
module StoreSpec
  ( spec
  , contractSpec
  , Opener (..)
  , holderMain
  , makeTempDir
  , expectRight
  , expectJust
  , expectCreated
  , seedStore
  , demoJobPending
  , demoJobResult
  ) where

import Control.Concurrent (forkIO, killThread, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, takeMVar, tryPutMVar)
import Control.Exception (bracket, bracket_, onException)
import Control.Monad (when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.Char (isSpace)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.List (isInfixOf, isPrefixOf, sort)
import Data.Maybe (mapMaybe)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import Data.Word (Word64)
import Foreign.C.Types (CInt (..))
import System.Directory (createDirectory, doesDirectoryExist, doesFileExist, getTemporaryDirectory, removeDirectoryRecursive, removeFile, renameFile)
import System.Environment (getExecutablePath, lookupEnv, setEnv, unsetEnv)
import System.Exit (ExitCode (..))
import System.FilePath (takeDirectory, (</>))
import System.IO.Error (catchIOError)
import System.Posix.Files (createSymbolicLink, fileExist, fileMode, getFileStatus, setFileMode)
import System.Posix.IO (OpenMode (..), closeFd, defaultFileFlags, openFd)
import System.Posix.Process (exitImmediately, forkProcess, getParentProcessID, getProcessID, getProcessStatus)
import System.Posix.Signals (sigKILL, signalProcess)
import System.Posix.Types (Fd, FileMode, ProcessID)
import System.Process (CreateProcess (..), ProcessHandle, createProcess, getPid, getProcessExitCode, proc)
import System.Timeout (timeout)
import Test.Tasty (DependencyType (AllFinish), TestTree, after, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState
  , addToken
  , emptyModel
  , lookupObject
  , lookupSession
  )
import Haskoki.Object (decodeHandle, planCreateObject)
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , StateDelta (..)
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , JobBody (..)
  , JobExecState (..)
  , JobRecord (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , StoredDoc (..)
  , TokenRecord (..)
  , docTopKeys
  , emptyDelta
  , objectToRecord
  , reserveRestoredIds
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStore)
import Haskoki.Runtime.Storage.SQLite (PidLiveness (..), ProcProbe (..), livenessFromProbes, openSQLiteStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

-- | How to open a store for one contract run: a label, an action
-- that opens the CURRENT identity (the same world/file across the
-- close/reopen boundary of a single test), and a release action.
data Opener = Opener
  { openerLabel :: String
  , openCurrent :: IO (Either StoreError Store)
  , openerClose :: IO ()
  }

-- | Run one case against a freshly made opener, always releasing it.
withOpener :: IO Opener -> (Opener -> IO ()) -> IO ()
withOpener mkOpener = bracket mkOpener openerClose

-- | Fresh memory identity per case.
memoryOpener :: IO Opener
memoryOpener = do
  world <- newMemoryWorld
  pure (Opener "memory" (openMemoryStore world) (pure ()))

-- | Fresh SQLite file identity per case, cleaned up afterwards.
sqliteOpener :: IO Opener
sqliteOpener = do
  dir <- makeTempDir "haskoki-storage-test"
  let path = dir </> "store.db"
  pure (Opener "sqlite" (openSQLiteStore path) (removeDirectoryRecursive dir))

-- | Make a fresh scratch directory: pid-suffixed with exists-retry
-- (no new dependencies; concurrent runs cannot collide).
makeTempDir :: String -> IO FilePath
makeTempDir prefix = do
  base <- getTemporaryDirectory
  pid <- getProcessID
  tryNames base (prefix ++ "-" ++ show pid ++ "-") (0 :: Int)
  where
    tryNames :: FilePath -> String -> Int -> IO FilePath
    tryNames base stem n
      | n > 10000 = ioError (userError ("makeTempDir: exhausted names for " ++ stem))
      | otherwise = do
          let dir = base </> (stem ++ show n)
          (createDirectory dir >> pure dir) `catchIOError` \_ -> do
            exists <- doesDirectoryExist dir
            if exists then tryNames base stem (n + 1) else ioError (userError ("makeTempDir: cannot create " ++ dir))

-- | Both backends run the shared contract, plus sqlite-only cases.
spec :: TestTree
spec = testGroup "store contract"
  [ contractSpec "memory" memoryOpener
  , contractSpec "sqlite" sqliteOpener
  , testGroup "sqlite-only"
      [ testCase "garbage file is rejected without rewrite" testGarbageRejected
      , testCase "future schema version rejected without rewrite" testFutureVersionRejected
      , testCase "corrupt records diagnosed" testCorruptDiagnosed
      , testCase "raw columns contain no pointers or handles" testRawColumnsClean
      , testCase "live schema matches spec/storage-schema.sql" testSchemaShape
      , testCase "stale lock takeable; masked proc and held flock refuse" testOwnershipGuards
      , testCase "ppid-0 liveness mapping" testLivenessMapping
      , testCase "lock deletion cannot fork a live owner" testUnlinkRefuses
      , testCase "owner close keeps a replacement lock" testCloseKeepsReplacement
      -- The proc-root tests mutate HASKOKI_PROC_ROOT process-wide,
      -- the pause tests mutate HASKOKI_OPEN_PAUSE process-wide, and
      -- the ownership-guards / kill-retry tests consult the real
      -- /proc (their stale-takeover phases); chain them so they
      -- never run concurrently with each other. (The
      -- unlink/replacement tests neither mutate the env nor consult
      -- liveness, so they stay parallel.)
      , after AllFinish "/stale lock takeable; masked proc and held flock refuse/" $
          testCase "unreadable proc root refuses cleanly" testProcUnreadableRefuses
      , after AllFinish "/unreadable proc root refuses cleanly/" $
          testCase "partially masked proc refuses as unknowable" testProcPartialMaskRefuses
      , after AllFinish "/partially masked proc refuses as unknowable/" $
          testCase "fresh open guards the database before init" testFreshGuardBeforeInit
      , after AllFinish "/fresh open guards the database before init/" $
          testCase "database swapped during open aborts" testSwappedDbAborts
      , after AllFinish "/database swapped during open aborts/" $
          testCase "cancellation during db-guard retry releases the sidecar" testKillDuringDbRetry
      , after AllFinish "/cancellation during db-guard retry releases the sidecar/" $
          testCase "selective owner hiding refuses safely" testSelectiveHideRefuses
      , after AllFinish "/selective owner hiding refuses safely/" $
          testCase "pause binds to the intended opener" testPauseBindsToIntendedOpener
      , after AllFinish "/pause binds to the intended opener/" $
          testCase "lock naming pid 0 is takeable without probing" testPidZeroTakeable
      ]
  ]

-- | The shared backend contract. Every backend runs every case here.
contractSpec :: String -> IO Opener -> TestTree
contractSpec label mkOpener = testGroup label
  [ testCase "persist-close-reload keeps logical data, mints fresh handles" $
      withOpener mkOpener (testPersistReloadFresh . openCurrent)
  , testCase "second writer fails explicitly" $
      withOpener mkOpener testSecondWriter
  , testCase "close/reopen preserves stored bytes exactly" $
      withOpener mkOpener testBytePreservation
  , testCase "empty store loads empty" $
      withOpener mkOpener testEmptyLoadsEmpty
  , testCase "revision conflict refuses the whole delta atomically" $
      withOpener mkOpener testRevisionAtomic
  , testCase "job records round-trip with recipe or result" $
      withOpener mkOpener testJobsRoundTrip
  , testCase "reset kills old generation ids" $
      withOpener mkOpener testResetKillsOldIds
  , testCase "puts referencing missing tokens refuse" $
      withOpener mkOpener testMissingTokenRefs
  , testCase "stored bytes contain no pointers or handles" $
      withOpener mkOpener testNoPointerBytes
  , testCase "second token on one slot refuses" $
      withOpener mkOpener testSlotUnique
  ]

-- | Acceptance 1: the same logical token objects across a
-- close/reopen boundary, bound to fresh handles in the new
-- generation. The new generation provokes counter divergence the
-- way a real restart does (a transient session object binds first),
-- so identical handle values would prove resurrection.
testPersistReloadFresh :: IO (Either StoreError Store) -> IO ()
testPersistReloadFresh openCurrent = do
  eStore1 <- openCurrent
  store1 <- either (assertFailure . show) pure eStore1
  let slot = SlotId 0
      tmpl1 =
        [ (AttrClass, ValULong 3)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "first")
        , (AttrValue, ValBytes "payload-one")
        ]
      tmpl2 =
        [ (AttrClass, ValULong 4)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "second")
        , (AttrValue, ValBytes "payload-two")
        ]
  mSeated <- expectRight "seat+open" (publishDelta (addToken emptyModel slot)
    (StateDelta [DeltaOpenSession (SessionId 1) slot False]))
  st <- expectJust "session 1" (lookupSession mSeated (SessionId 1))
  -- Generation 1 is a lived-in process: a transient session object
  -- binds first, so the token objects take handles 2 and 3.
  (m0, hT, _) <- expectCreated mSeated st
    [(AttrClass, ValULong 3), (AttrLabel, ValBytes "gen1-transient")]
  (m1, h1, oid1) <- expectCreated m0 st tmpl1
  (m2, h2, oid2) <- expectCreated m1 st tmpl2
  assertEqual "gen-1 handle history" [ExternalHandle 1, ExternalHandle 2, ExternalHandle 3] [hT, h1, h2]
  ost1 <- expectJust "object 1" (lookupObject m2 oid1)
  ost2 <- expectJust "object 2" (lookupObject m2 oid2)
  let tok = TokenRecord
        { trId = TokenId 1
        , trSlot = slot
        , trGeneration = Generation 1
        , trLabel = "demo-token-1"
        , trAuth = tokenAuthNew
        }
      delta = emptyDelta
        { sdPutTokens = [tok]
        , sdPutObjects =
            [ ObjectPut Nothing (objectToRecord (TokenId 1) ost1)
            , ObjectPut Nothing (objectToRecord (TokenId 1) ost2)
            ]
        }
  result1 <- storeCommit store1 delta
  assertEqual "initial commit" Committed result1
  -- The stored encoding carries no handle: pin the exact key set.
  docs <- storeInspect store1
  let objDocs = [d | d <- docs, docTable d == "objects"]
  assertEqual "two object docs" 2 (length objDocs)
  mapM_ assertObjectDocKeys objDocs
  mapM_ (assertBool "no handle leakage in stored bytes" . noHandleBytes . docJson) docs
  storeClose store1
  -- Generation 2: a fresh model (as after finalize/reinit) whose
  -- counters provably diverge, then reload and rebind.
  eStore2 <- openCurrent
  store2 <- either (assertFailure . show) pure eStore2
  eLoaded <- storeLoadTokens store2
  loaded <- either (assertFailure . show) pure eLoaded
  case loaded of
    [(tok2, objs2)] -> do
      assertEqual "token label survives" "demo-token-1" (trLabel tok2)
      assertEqual "token generation survives" (Generation 1) (trGeneration tok2)
      assertEqual "both objects survive" 2 (length objs2)
      let attrs2 = map orAttrs objs2
      assertBool "first attrs survive" (osAttrs ost1 `elem` attrs2)
      assertBool "second attrs survive" (osAttrs ost2 `elem` attrs2)
      assertEqual "object ids stable" [oid1, oid2] (map orId objs2)
      -- Generation 2 re-seats at init (before serving calls), so
      -- the live counters mint handles 1 and 2 for the restored
      -- objects: pairwise distinct from generation 1's 2 and 3.
      -- Object ids stay stable; handles never do.
      mNew <- expectRight "reseat+open" (publishDelta (addToken emptyModel slot)
        (StateDelta [DeltaOpenSession (SessionId 1) slot False]))
      let hNew = [ExternalHandle (mNextHandle mNew), ExternalHandle (mNextHandle mNew + 1)]
          rebinds = zipWith DeltaBindHandle hNew (map orId objs2)
          creates =
            [ DeltaCreateObjectFull (orId o) (orAttrs o) Nothing slot
            | o <- objs2
            ]
      assertEqual "live counters mint 1,2" [ExternalHandle 1, ExternalHandle 2] hNew
      mBound <- expectRight "rebind" (publishDelta mNew (StateDelta (creates ++ rebinds)))
      assertBool "handles are fresh, not resurrected"
        (and (zipWith (/=) [h1, h2] hNew))
      assertBool "rebound objects resolve"
        (all (resolves mBound) hNew)
      -- The restored id space is reserved, so later allocations
      -- never collide with it.
      stNew <- expectJust "new session 1" (lookupSession mBound (SessionId 1))
      let mReserved = reserveRestoredIds (map orId objs2) mBound
      (mFinal, hAfter, oidAfter) <- expectCreated mReserved stNew
        [(AttrClass, ValULong 3), (AttrLabel, ValBytes "post-reseat")]
      assertEqual "post-reseat object id advances" (ObjectId 4) oidAfter
      assertEqual "post-reseat handle advances" (ExternalHandle 3) hAfter
      assertBool "post-reseat object resolves" (resolves mFinal hAfter)
    _ -> assertFailure ("expected one token, got: " ++ show (length loaded))
  storeClose store2

-- | Unwrap an 'Either' or fail the test with context.
expectRight :: Show e => String -> Either e a -> IO a
expectRight ctx = either (\e -> assertFailure (ctx ++ ": " ++ show e)) pure

-- | Unwrap a 'Maybe' or fail the test with context.
expectJust :: String -> Maybe a -> IO a
expectJust ctx = maybe (assertFailure ("missing: " ++ ctx)) pure

-- | Acceptance 2 (ownership): a second concurrent open of the same
-- identity fails with an explicit second-writer diagnosis — never
-- a stale-cache shadow. Closing releases ownership.
testSecondWriter :: Opener -> IO ()
testSecondWriter o = do
  e1 <- openCurrent o
  s1 <- either (\e -> assertFailure ("first open: " ++ show e)) pure e1
  e2 <- openCurrent o
  case e2 of
    Right s2 -> do
      storeClose s2
      storeClose s1
      assertFailure "second concurrent open succeeded"
    Left (StoreSecondWriter _) -> pure ()
    Left other -> do
      storeClose s1
      assertFailure ("wrong error for second writer: " ++ show other)
  storeClose s1
  e3 <- openCurrent o
  s3 <- either (\e -> assertFailure ("reopen after close: " ++ show e)) pure e3
  storeClose s3

-- | Acceptance 2 (no silent refixture): the stored bytes before and
-- after a close/reopen boundary are identical.
testBytePreservation :: Opener -> IO ()
testBytePreservation o = do
  e1 <- openCurrent o
  s1 <- either (\e -> assertFailure ("open: " ++ show e)) pure e1
  _ <- seedStore s1
  docsBefore <- storeInspect s1
  assertBool "seeded docs are non-empty" (not (null docsBefore))
  storeClose s1
  e2 <- openCurrent o
  s2 <- either (\e -> assertFailure ("reopen: " ++ show e)) pure e2
  docsAfter <- storeInspect s2
  storeClose s2
  assertEqual "stored bytes survive close/reopen"
    (map show docsBefore) (map show docsAfter)

-- | Acceptance 2 (empty init): a fresh identity opens and loads
-- empty (SQLite initializes its schema transactionally).
testEmptyLoadsEmpty :: Opener -> IO ()
testEmptyLoadsEmpty o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  eLoaded <- storeLoadTokens s
  loaded <- either (\e -> assertFailure ("load: " ++ show e)) pure eLoaded
  assertEqual "fresh store is empty" [] loaded
  storeClose s

-- | Acceptance 4 (atomic multi-object transaction): a delta with
-- one stale expected revision refuses ENTIRELY — the innocent
-- put does not land either. The control (correct expectations)
-- commits both.
testRevisionAtomic :: Opener -> IO ()
testRevisionAtomic o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  (tok, recs) <- seedStore s
  recB <- case recs of
    [_, b] -> pure b
    _ -> assertFailure "seed must hold two objects"
  recC <- freshObject (trId tok)
  let badDelta = emptyDelta
        { sdPutObjects =
            [ ObjectPut Nothing recC
            , ObjectPut (Just (Revision 424242)) recB
            ]
        }
  bad <- storeCommit s badDelta
  case bad of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected revision conflict, got: " ++ show other)
  eLoaded <- storeLoadTokens s
  loaded <- either (\e -> assertFailure ("load: " ++ show e)) pure eLoaded
  let objs = concatMap snd loaded
  assertEqual "nothing landed" recs objs
  let goodDelta = emptyDelta
        { sdPutObjects =
            [ ObjectPut Nothing recC
            , ObjectPut (Just (orRevision recB)) recB
            ]
        }
  good <- storeCommit s goodDelta
  assertEqual "correct expectations commit" Committed good
  eLoaded2 <- storeLoadTokens s
  loaded2 <- either (\e -> assertFailure ("load: " ++ show e)) pure eLoaded2
  assertEqual "both land" 3 (length (concatMap snd loaded2))
  storeClose s

-- | Build a fresh object record (naturally 'ObjectId 3': two
-- dummies consumed first) via a scratch model.
freshObject :: TokenId -> IO ObjectRecord
freshObject tok = do
  let slot = SlotId 0
      dummy = [(AttrClass, ValULong 3), (AttrLabel, ValBytes "dummy")]
      tmplC =
        [ (AttrClass, ValULong 3)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "third")
        , (AttrValue, ValBytes "third-bytes")
        ]
  mSeated <- expectRight "seat+open" (publishDelta (addToken emptyModel slot)
    (StateDelta [DeltaOpenSession (SessionId 1) slot False]))
  st <- expectJust "session" (lookupSession mSeated (SessionId 1))
  (m1, _, _) <- expectCreated mSeated st dummy
  (m2, _, _) <- expectCreated m1 st dummy
  (m3, _, oidC) <- expectCreated m2 st tmplC
  assertEqual "fresh id" (ObjectId 3) oidC
  ostC <- expectJust "fresh object" (lookupObject m3 oidC)
  pure (objectToRecord tok ostC)

-- | SQLite-only: a garbage file is rejected with a diagnosis and
-- its bytes are left untouched (never silently replaced).
testGarbageRejected :: IO ()
testGarbageRejected = do
  bracket (makeTempDir "haskoki-storage-garbage") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    BS.writeFile path (BS.pack [116, 104, 105, 115, 32, 110, 111, 116, 32, 97, 32, 100, 98, 0, 1, 2])
    before <- BS.readFile path
    eStore <- openSQLiteStore path
    case eStore of
      Right s -> do
        storeClose s
        assertFailure "garbage file opened as a store"
      Left _ -> pure ()
    bytesAfter <- BS.readFile path
    assertEqual "garbage bytes untouched" before bytesAfter

-- | Acceptance 4 (wrong schema): a future schema version is
-- rejected with its versions diagnosed, the bytes untouched, and
-- no lock stranded.
testFutureVersionRejected :: IO ()
testFutureVersionRejected =
  bracket (makeTempDir "haskoki-storage-version") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("seed open: " ++ show e)) pure e0
    _ <- seedStore s0
    storeClose s0
    rawExec path (T.pack "UPDATE store_meta SET value = '999' WHERE key = 'schema_version'")
    before <- BS.readFile path
    e1 <- openSQLiteStore path
    case e1 of
      Right s -> do
        storeClose s
        assertFailure "future schema version opened"
      Left (StoreSchemaVersion expected found) -> do
        assertEqual "expected version" 1 expected
        assertEqual "found version" "999" found
      Left other -> assertFailure ("wrong error: " ++ show other)
    bytesAfter <- BS.readFile path
    assertEqual "bytes untouched" before bytesAfter
    lockLeft <- doesFileExist (path ++ ".lock")
    assertBool "no stranded lock" (not lockLeft)

-- | Acceptance 4 (corrupt records): garbage in each decodable
-- surface diagnoses 'StoreCorrupt' at load (open itself stays
-- lazy and succeeds).
testCorruptDiagnosed :: IO ()
testCorruptDiagnosed = do
  mapM_ runSurface
    [ ("token doc", "UPDATE tokens SET record_json = '{broken'")
    , ("attrs doc", "UPDATE objects SET attributes_json = 'nope' WHERE object_id = '0000000000000001'")
    , ("object id", "UPDATE objects SET object_id = 'zzz' WHERE object_id = '0000000000000001'")
    , ("material encoding", "UPDATE objects SET material_encoding = 'evil/v9' WHERE object_id = '0000000000000002'")
    ]
  where
    runSurface :: (String, String) -> IO ()
    runSurface (label, sql) =
      bracket (makeTempDir "haskoki-storage-corrupt") removeDirectoryRecursive $ \dir -> do
        let path = dir </> "store.db"
        e0 <- openSQLiteStore path
        s0 <- either (\e -> assertFailure ("seed open: " ++ show e)) pure e0
        _ <- seedStore s0
        storeClose s0
        rawExec path (T.pack sql)
        e1 <- openSQLiteStore path
        s1 <- either (\e -> assertFailure (label ++ " open: " ++ show e)) pure e1
        eLoaded <- storeLoadTokens s1
        case eLoaded of
          Left (StoreCorrupt _) -> pure ()
          Left other -> assertFailure (label ++ ": wrong error: " ++ show other)
          Right _ -> assertFailure (label ++ ": corrupt record loaded")
        storeClose s1

-- | Run one raw statement against a closed database file.
rawExec :: FilePath -> T.Text -> IO ()
rawExec path sql = do
  db <- S.open (T.pack path)
  S.exec db sql
  S.close db

-- | Acceptance 5 (detached-job records): a pending recipe and a
-- prepared result both round-trip byte-exact across close/reopen.
testJobsRoundTrip :: Opener -> IO ()
testJobsRoundTrip o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  (tok, _) <- seedStore s
  let j1 = demoJobPending 1 (trId tok) (trGeneration tok)
      j2 = demoJobResult 2 (trId tok) (trGeneration tok)
  r <- storeCommit s emptyDelta { sdPutJobs = [j1, j2] }
  assertEqual "jobs commit" Committed r
  docs <- storeInspect s
  let jobDocs = [d | d <- docs, docTable d == "detached_jobs"]
  assertEqual "two job docs" 2 (length jobDocs)
  mapM_ assertJobDocKeys jobDocs
  storeClose s
  eStore2 <- openCurrent o
  s2 <- either (\e -> assertFailure ("reopen: " ++ show e)) pure eStore2
  eJobs <- storeLoadJobs s2
  jobs <- either (\e -> assertFailure ("load jobs: " ++ show e)) pure eJobs
  assertEqual "jobs round-trip" [j1, j2] jobs
  storeClose s2

-- | The exact canonical key set of a job document.
assertJobDocKeys :: StoredDoc -> IO ()
assertJobDocKeys d =
  assertEqual ("job doc keys: " ++ docKey d)
    [ "body"
    , "format_version"
    , "function"
    , "persistent_id"
    , "state"
    , "token_generation"
    , "token_id"
    ]
    (docTopKeys (docJson d))

-- | Acceptance 5 (generation validation, record side): reset
-- replaces the token, removes its objects AND jobs atomically,
-- and kills the old generation's ids — while the new generation
-- stays writable.
testResetKillsOldIds :: Opener -> IO ()
testResetKillsOldIds o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  (tok, _) <- seedStore s
  let gen1 = trGeneration tok
  rJobs <- storeCommit s emptyDelta
    { sdPutJobs =
        [ demoJobPending 10 (trId tok) gen1
        , demoJobResult 11 (trId tok) gen1
        ]
    }
  assertEqual "jobs seed" Committed rJobs
  let replacement = tok { trGeneration = Generation 2, trLabel = "seed-token-gen2" }
  rr <- storeResetToken s (trId tok) gen1 replacement
  assertEqual "reset commits" Committed rr
  eLoaded <- storeLoadTokens s
  loaded <- either (\e -> assertFailure ("load: " ++ show e)) pure eLoaded
  case loaded of
    [(tok2, objs2)] -> do
      assertEqual "generation bumped" (Generation 2) (trGeneration tok2)
      assertEqual "objects removed" [] objs2
    _ -> assertFailure ("expected one token, got: " ++ show (length loaded))
  eJobs <- storeLoadJobs s
  jobs <- either (\e -> assertFailure ("load jobs: " ++ show e)) pure eJobs
  assertEqual "jobs removed" [] jobs
  -- Old generation ids are dead.
  stale <- storeCommit s emptyDelta
    { sdPutJobs = [demoJobPending 12 (trId tok) gen1] }
  case stale of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected generation refusal, got: " ++ show other)
  -- Current generation works.
  fresh <- storeCommit s emptyDelta
    { sdPutJobs = [demoJobPending 12 (trId tok) (Generation 2)] }
  assertEqual "new generation writable" Committed fresh
  -- Reset with a stale expectation refuses.
  rr2 <- storeResetToken s (trId tok) gen1 replacement
  case rr2 of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected stale reset refusal, got: " ++ show other)
  -- Reset of a missing token refuses.
  rr3 <- storeResetToken s (TokenId 99) (Generation 1) replacement
  case rr3 of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected missing reset refusal, got: " ++ show other)
  storeClose s

-- | Referential validation: object and job puts naming a missing
-- token refuse; a token created in the SAME delta satisfies refs.
testMissingTokenRefs :: Opener -> IO ()
testMissingTokenRefs o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  _ <- seedStore s
  recGhost <- freshObject (TokenId 99)
  bad <- storeCommit s emptyDelta
    { sdPutObjects = [ObjectPut Nothing recGhost] }
  case bad of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected object refusal, got: " ++ show other)
  badJ <- storeCommit s emptyDelta
    { sdPutJobs = [demoJobPending 20 (TokenId 99) (Generation 1)] }
  case badJ of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected job refusal, got: " ++ show other)
  let newTok = TokenRecord
        { trId = TokenId 100
        , trSlot = SlotId 1
        , trGeneration = Generation 1
        , trLabel = "late-token"
        , trAuth = tokenAuthNew
        }
  recNew <- freshObject (TokenId 100)
  ok <- storeCommit s emptyDelta
    { sdPutTokens = [newTok]
    , sdPutObjects = [ObjectPut Nothing recNew]
    , sdPutJobs = [demoJobPending 21 (TokenId 100) (Generation 1)]
    }
  assertEqual "same-delta refs commit" Committed ok
  storeClose s

-- | Acceptance 5 (encoding fixtures): no stored document mentions
-- pointers, handles, callbacks, or native contexts, and the only
-- bare JSON number is @format_version@.
testNoPointerBytes :: Opener -> IO ()
testNoPointerBytes o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  (tok, _) <- seedStore s
  r <- storeCommit s emptyDelta
    { sdPutJobs =
        [ demoJobPending 30 (trId tok) (trGeneration tok)
        , demoJobResult 31 (trId tok) (trGeneration tok)
        ]
    }
  assertEqual "jobs commit" Committed r
  docs <- storeInspect s
  assertBool "docs non-empty" (not (null docs))
  mapM_ checkDoc docs
  storeClose s
  where
    checkDoc d = do
      assertBool ("clean bytes: " ++ docTable d ++ "/" ++ docKey d)
        (cleanBytes (docJson d))
      assertBool ("numbers only as format_version: " ++ docKey d)
        (numbersClean (docJson d))

-- | SQLite-only: the same fixture scan over the RAW column values
-- read through an independent driver session (not our inspect).
testRawColumnsClean :: IO ()
testRawColumnsClean =
  bracket (makeTempDir "haskoki-storage-rawscan") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    eStore <- openSQLiteStore path
    s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
    (tok, _) <- seedStore s
    r <- storeCommit s emptyDelta
      { sdPutJobs =
          [ demoJobPending 40 (trId tok) (trGeneration tok)
          , demoJobResult 41 (trId tok) (trGeneration tok)
          ]
      }
    assertEqual "jobs commit" Committed r
    storeClose s
    db <- S.open (T.pack path)
    tokDocs <- rawTexts db (T.pack "SELECT record_json FROM tokens")
    attrDocs <- rawTexts db (T.pack "SELECT attributes_json FROM objects")
    matDocs <- rawTexts db (T.pack "SELECT material_encoding FROM objects")
    jobDocs <- rawTexts db (T.pack "SELECT record_json FROM detached_jobs")
    blobs <- rawBlobs db (T.pack "SELECT material_blob FROM objects WHERE material_blob IS NOT NULL")
    S.close db
    let texts = tokDocs ++ attrDocs ++ matDocs ++ jobDocs ++ blobs
    assertBool "raw columns non-empty" (not (null texts))
    mapM_ (\t -> assertBool ("raw clean: " ++ take 40 t) (cleanBytes t)) texts
    mapM_ (\t -> assertBool ("raw numbers: " ++ take 40 t) (numbersClean t))
      (tokDocs ++ attrDocs ++ jobDocs)

-- | Read one text column from every row of a raw query.
rawTexts :: S.Database -> T.Text -> IO [String]
rawTexts db sql =
  bracket (S.prepare db sql) S.finalize collect
  where
    collect stmt = do
      r <- S.step stmt
      case r of
        S.Done -> pure []
        S.Row -> do
          cols <- S.columns stmt
          rest <- collect stmt
          pure ([T.unpack t | S.SQLText t <- cols] ++ rest)

-- | Read one blob column from every row of a raw query.
rawBlobs :: S.Database -> T.Text -> IO [String]
rawBlobs db sql =
  bracket (S.prepare db sql) S.finalize collect
  where
    collect stmt = do
      r <- S.step stmt
      case r of
        S.Done -> pure []
        S.Row -> do
          cols <- S.columns stmt
          rest <- collect stmt
          pure ([BC8.unpack b | S.SQLBlob b <- cols] ++ rest)

-- | The package root, resolved CWD-independently (same
-- funnel-cwd hardening as the model suite: walk up from the test
-- binary's own directory to haskoki.cabal).
storePackageRoot :: IO FilePath
storePackageRoot = do
  exeDir <- takeDirectory <$> getExecutablePath
  ascend exeDir
  where
    ascend dir = do
      here <- doesFileExist (dir </> "haskoki.cabal")
      if here
        then pure dir
        else let parent = takeDirectory dir
             in if parent == dir
                  then assertFailure "schema-shape: haskoki.cabal not found"
                  else ascend parent

-- | Normalize DDL for comparison: collapse whitespace runs and
-- drop spaces adjacent to parens/commas. Sound here because no
-- quoted literal in either schema text contains a space (pinned
-- implicitly: any such literal would break the equality below).
normDDL :: String -> String
normDDL s = [c | (prev, c, next) <- triples (' ' : collapsed ++ " "), keep prev c next]
  where
    collapsed = unwords (words s)
    triples (a : b : c : rest) = (a, b, c) : triples (b : c : rest)
    triples _ = []
    keep prev c next = c /= ' ' || not (prev `elem` punct || next `elem` punct)
    punct = "()," :: String

-- | Split spec SQL text into statements: drop `--` comment lines,
-- split on `;`, drop empties.
specStatements :: String -> [String]
specStatements text =
  [ t
  | chunk <- splitOn ';' noComments
  , let t = trim chunk
  , not (null t)
  ]
  where
    noComments = unlines
      [l | l <- lines text, not ("--" `isPrefixOf` dropWhile isSpace l)]
    trim = reverse . dropWhile isSpace . reverse . dropWhile isSpace
    splitOn _ [] = [[]]
    splitOn d (c : cs)
      | c == d = [] : splitOn d cs
      | otherwise = case splitOn d cs of
          [] -> [[c]]
          (h : t) -> (c : h) : t

-- | The live SQLite schema (tables + indexes, read back
-- from sqlite_master of a fresh store) equals the readable
-- reference spec/storage-schema.sql modulo whitespace.
testSchemaShape :: IO ()
testSchemaShape = do
  mOut <- timeout (120 * 1000000) $ do
    root <- storePackageRoot
    specText <- readFile (root </> "spec/storage-schema.sql")
    let specDDLs = sort
          [ normDDL s
          | s <- specStatements specText
          , "CREATE TABLE" `isPrefixOf` s || "CREATE INDEX" `isPrefixOf` s
          ]
        specPragmas =
          [ s
          | s <- specStatements specText
          , "PRAGMA" `isPrefixOf` s
          ]
    assertEqual "spec table+index count" 6 (length specDDLs)
    assertEqual "spec pragma count" 4 (length specPragmas)
    bracket (makeTempDir "haskoki-storage-schema") removeDirectoryRecursive $ \dir -> do
      let path = dir </> "store.db"
      eStore <- openSQLiteStore path
      s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
      storeClose s
      db <- S.open (T.pack path)
      liveDDLs <- sort . map normDDL <$> rawTexts db
        (T.pack "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")
      S.close db
      assertEqual "live schema equals spec/storage-schema.sql" specDDLs liveDDLs
  case mOut of
    Just () -> pure ()
    Nothing -> assertFailure "schema-shape wedged (120s timeout)"

-- | Ownership guards (one case, sequential phases — the masked-proc
-- phase mutates @HASKOKI_PROC_ROOT@ process-wide, so the phases must
-- not run concurrently with each other): a stale-pid lock with no
-- holder is still takeable and the taken-over store keeps its data
-- (no fail-closed overreach); a second open with owner liveness
-- unknowable is refused; and a stale-pid lock whose kernel lock is
-- held is refused until the holder goes away.
testOwnershipGuards :: IO ()
testOwnershipGuards = do
  staleTakeable
  heldFlockRefuses
  maskedProcRefuses

-- | Variant guard: a lock naming a provably-dead pid, with no
-- kernel-lock holder, is taken over; the lock is re-owned and the
-- seeded data survives the takeover.
staleTakeable :: IO ()
staleTakeable =
  bracket (makeTempDir "haskoki-storage-stale") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("stale seed open: " ++ show e)) pure e0
    _ <- seedStore s0
    storeClose s0
    deadPid <- reapedPid
    writeFile (path ++ ".lock") (show deadPid ++ "\n")
    e1 <- openSQLiteStore path
    s1 <- either (\e -> assertFailure ("stale takeover failed: " ++ show e)) pure e1
    me <- getProcessID
    content <- readFile (path ++ ".lock")
    assertEqual "stale: lock re-owned by taker" (show me ++ "\n") content
    eLoaded <- storeLoadTokens s1
    loaded <- either (\e -> assertFailure ("stale load after takeover: " ++ show e)) pure eLoaded
    assertEqual "stale: seeded token survives takeover" 1 (length loaded)
    storeClose s1

-- | Kernel guard: a stale-pid lock whose file is @flock@-held (a
-- live-but-hidden owner from the store's point of view) refuses the
-- takeover with 'StoreSecondWriter'; once the holder goes away the
-- same lock is takeable.
heldFlockRefuses :: IO ()
heldFlockRefuses =
  bracket (makeTempDir "haskoki-storage-held") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("held seed open: " ++ show e)) pure e0
    storeClose s0
    deadPid <- reapedPid
    writeFile (path ++ ".lock") (show deadPid ++ "\n")
    bracket (openFd (path ++ ".lock") ReadOnly defaultFileFlags) closeFd $ \holderFd -> do
      held <- testTryFlock holderFd
      assertBool "held: test holder took the kernel lock" held
      e1 <- openSQLiteStore path
      case e1 of
        Right s1 -> do
          storeClose s1
          assertFailure "held: takeover succeeded despite held kernel lock (state fork)"
        Left (StoreSecondWriter _) -> pure ()
        Left other -> assertFailure ("held: wrong error for held lock: " ++ show other)
    e2 <- openSQLiteStore path
    s2 <- either (\e -> assertFailure ("held: takeover after release failed: " ++ show e)) pure e2
    storeClose s2

-- | Fail-closed guard: with @\/proc@ masked (via @HASKOKI_PROC_ROOT@,
-- deterministically empty), a second open against a live owner in
-- ANOTHER process is refused with the unknowable-liveness
-- 'StoreSecondWriter' instead of forking. The owner must be a
-- separate process: a same-process second open is refused by the
-- same-process guard before liveness is ever consulted, so it can
-- never pin the fail-closed path (and its message carries no
-- "unknowable" on either base or patch).
maskedProcRefuses :: IO ()
maskedProcRefuses =
  bracket (makeTempDir "haskoki-storage-masked") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-emptyproc") removeDirectoryRecursive $ \emptyProc -> do
      reaped <- newIORef False
      let path = dir </> "store.db"
          doneFile = dir </> "holder.done"
          readyFile = dir </> "holder.ready"
      bracket (spawnHolder path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
        holderPid <- spawnedPid ph "masked"
        awaitLockOwner path holderPid
        awaitDone readyFile (6000 :: Int)
        withProcRoot emptyProc $ do
          e2 <- openSQLiteStore path
          case e2 of
            Right s2 -> do
              storeClose s2
              assertFailure "masked: second open succeeded with liveness unknowable (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("masked: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("masked: wrong error for unknowable liveness: " ++ show other)
        writeFile doneFile "done\n"
        awaitHolderExit reaped ph "masked"
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("masked reopen after close: " ++ show e)) pure e3
        storeClose s3

-- | The lock holder: runs in a spawned child process (see
-- 'spawnHolder'), opens the store (becoming its live owner),
-- signals readiness only once the open has fully completed (the
-- pid names the lock before schema init finishes, so the lock
-- alone cannot gate a racing second open), waits for the parent's
-- done file, then closes and exits. Never returns to test code;
-- uses 'exitImmediately' to avoid flushing the parent's stdio
-- buffers.
holderMain :: FilePath -> FilePath -> FilePath -> IO ()
holderMain path doneFile readyFile = do
  e <- openSQLiteStore path
  case e of
    Left _ -> exitImmediately (ExitFailure 1)
    Right s -> do
      writeFile readyFile "ready\n"
      awaitDone doneFile (6000 :: Int)
      storeClose s
      exitImmediately ExitSuccess

-- | Poll for the done file (10ms steps, bounded so a stuck parent
-- cannot wedge the suite past the tasty timeout).
awaitDone :: FilePath -> Int -> IO ()
awaitDone _ 0 = pure ()
awaitDone doneFile n = do
  done <- fileExist doneFile
  if done then pure () else threadDelay 10000 >> awaitDone doneFile (n - 1)

-- | Poll until the lock names the holder child (10s cap); the
-- holder is live from then on.
awaitLockOwner :: FilePath -> ProcessID -> IO ()
awaitLockOwner path holderPid = do
  let want = BC8.pack (show holderPid ++ "\n")
      go = do
        content <- catchIOError (BS.readFile (path ++ ".lock")) (\_ -> pure BS.empty)
        if content == want then pure () else threadDelay 10000 >> go
  mOk <- timeout 10000000 go
  case mOk of
    Just () -> pure ()
    Nothing -> assertFailure "masked: holder child did not take the lock"

-- | Spawn a holder child as a FRESH OS process (the test binary
-- re-invoked with @--holder@), never 'forkProcess': a forked child
-- would inherit the parent's open guard fds (the same open file
-- description — the parent's close then cannot release the kernel
-- locks while the child lives, poisoning concurrent tests with
-- spurious refusals) and forking a multithreaded RTS while another
-- thread is inside SQLite can wedge the child forever. The spawned
-- child starts with only stdio fds (@close_fds@) and a clean
-- address space.
spawnHolder :: FilePath -> FilePath -> FilePath -> IO ProcessHandle
spawnHolder path doneFile readyFile = do
  exe <- getExecutablePath
  (_, _, _, ph) <- createProcess ((proc exe ["--holder", path, doneFile, readyFile]) { close_fds = True })
  pure ph

-- | The spawned child's pid for the lock-ownership handshake;
-- fails fast when the child already exited before handshaking.
spawnedPid :: ProcessHandle -> String -> IO ProcessID
spawnedPid ph tag = do
  mPid <- getPid ph
  case mPid of
    Just pid -> pure pid
    Nothing -> assertFailure (tag ++ ": holder child exited before handshake")

-- | Claim the exactly-once right to reap a holder child: True
-- for the first claimer (it owns signal+reap), False once the
-- child has been reaped. A reaped numeric pid may be recycled by
-- an unrelated process, so it must never be signaled again.
claimReap :: IORef Bool -> IO Bool
claimReap ref = atomicModifyIORef' ref (\done -> (True, not done))

-- | Bounded wait on a holder child (10ms non-blocking polls), so
-- a wedged child cannot hang the suite. Nothing on timeout; every
-- error is swallowed on the release path.
waitBounded :: ProcessHandle -> Int -> IO (Maybe ExitCode)
waitBounded _ 0 = pure Nothing
waitBounded ph n = do
  mSt <- catchIOError (getProcessExitCode ph) (\_ -> pure Nothing)
  case mSt of
    Just st -> pure (Just st)
    Nothing -> threadDelay 10000 >> waitBounded ph (n - 1)

-- | Bracket release for a holder child: exactly-once SIGKILL plus
-- a bounded wait. A no-op when the body already reaped the child.
-- The kill targets only our own unreaped child (its pid cannot be
-- recycled before we reap it), never a recycled numeric pid.
-- Every failure is swallowed: the release must not mask the test
-- verdict.
releaseHolder :: IORef Bool -> ProcessHandle -> IO ()
releaseHolder reaped ph = do
  ours <- claimReap reaped
  when ours $ do
    catchIOError (getPid ph >>= maybe (pure ()) (signalProcess sigKILL)) (\_ -> pure ())
    _ <- waitBounded ph 500
    pure ()

-- | Bounded join on a holder child (10s cap) with checked exit
-- status; marks the child reaped so the bracket release skips it.
awaitHolderExit :: IORef Bool -> ProcessHandle -> String -> IO ()
awaitHolderExit reaped ph tag = do
  mSt <- waitBounded ph 1000
  case mSt of
    Nothing -> assertFailure (tag ++ ": holder child did not exit within 10s")
    Just st -> do
      _ <- claimReap reaped
      case st of
        ExitSuccess -> pure ()
        other -> assertFailure (tag ++ ": holder child failed: " ++ show other)

-- | Run with a path's mode overridden, restoring it afterwards
-- (a denied mode must never strand an undeletable fixture, even
-- when the action throws).
withFileMode :: FilePath -> FileMode -> IO a -> IO a
withFileMode p mode action = do
  st <- getFileStatus p
  bracket_ (setFileMode p mode) (setFileMode p (fileMode st)) action

-- | Run with @HASKOKI_PROC_ROOT@ overridden, restoring it afterwards.
withProcRoot :: FilePath -> IO a -> IO a
withProcRoot root action =
  bracket (lookupEnv "HASKOKI_PROC_ROOT")
          (\prev -> maybe (unsetEnv "HASKOKI_PROC_ROOT") (setEnv "HASKOKI_PROC_ROOT") prev)
          (\_ -> setEnv "HASKOKI_PROC_ROOT" root >> action)

-- | Run with @HASKOKI_OPEN_PAUSE@ (pause directory) and
-- @HASKOKI_OPEN_PAUSE_PATH@ (intended opener's database path)
-- overridden, restoring both afterwards. The path binding keeps
-- unrelated parallel SQLite creators from pausing on our handshake.
withOpenPause :: FilePath -> FilePath -> IO a -> IO a
withOpenPause dir want action =
  bracket (lookupEnv "HASKOKI_OPEN_PAUSE")
          (\prev -> maybe (unsetEnv "HASKOKI_OPEN_PAUSE") (setEnv "HASKOKI_OPEN_PAUSE") prev)
          (\_ -> setEnv "HASKOKI_OPEN_PAUSE" dir >> inner)
  where
    inner =
      bracket (lookupEnv "HASKOKI_OPEN_PAUSE_PATH")
              (\prev -> maybe (unsetEnv "HASKOKI_OPEN_PAUSE_PATH") (setEnv "HASKOKI_OPEN_PAUSE_PATH") prev)
              (\_ -> setEnv "HASKOKI_OPEN_PAUSE_PATH" want >> action)

-- | Unlink guard: deleting a live owner's lock path must not let
-- a second opener take over by creating and flocking a different
-- inode — exclusion is anchored to the database identity as well
-- as the sidecar, so the replacement lock's sidecar flock
-- succeeding still refuses at the database guard.
testUnlinkRefuses :: IO ()
testUnlinkRefuses =
  bracket (makeTempDir "haskoki-storage-unlink") removeDirectoryRecursive $ \dir -> do
    reaped <- newIORef False
    let path = dir </> "store.db"
        lockPath = path ++ ".lock"
        doneFile = dir </> "holder.done"
        readyFile = dir </> "holder.ready"
    bracket (spawnHolder path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
      holderPid <- spawnedPid ph "unlink"
      awaitLockOwner path holderPid
      awaitDone readyFile (6000 :: Int)
      removeFile lockPath
      e2 <- openSQLiteStore path
      case e2 of
        Right s2 -> do
          storeClose s2
          assertFailure "unlink: second open took over after lock deletion (state fork)"
        Left (StoreSecondWriter msg) ->
          assertBool ("unlink: expected database-anchored refusal, got: " ++ msg)
            ("database" `isInfixOf` msg)
        Left other ->
          assertFailure ("unlink: wrong error after lock deletion: " ++ show other)
      writeFile doneFile "done\n"
      awaitHolderExit reaped ph "unlink"

-- | Owned-inode release: a replacement lock planted at the path
-- after a live owner's lock was deleted is NOT the owner's, so
-- the owner's close must leave it byte-identical (unlink only the
-- owned inode).
testCloseKeepsReplacement :: IO ()
testCloseKeepsReplacement =
  bracket (makeTempDir "haskoki-storage-replace") removeDirectoryRecursive $ \dir -> do
    reaped <- newIORef False
    let path = dir </> "store.db"
        lockPath = path ++ ".lock"
        doneFile = dir </> "holder.done"
        readyFile = dir </> "holder.ready"
    bracket (spawnHolder path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
      holderPid <- spawnedPid ph "replace"
      awaitLockOwner path holderPid
      awaitDone readyFile (6000 :: Int)
      removeFile lockPath
      writeFile lockPath "replacement-marker\n"
      writeFile doneFile "done\n"
      awaitHolderExit reaped ph "replace"
      content <- readFile lockPath
      assertEqual "replace: owner close deleted a replacement lock"
        "replacement-marker\n" content

-- | Probe-error guard: a @\/proc@ root the opener cannot read
-- (@EACCES@) fails closed with a clean 'StoreSecondWriter', never
-- an uncaught 'IOException' — even when the named owner is dead
-- (death cannot be proven, so no takeover).
testProcUnreadableRefuses :: IO ()
testProcUnreadableRefuses =
  bracket (makeTempDir "haskoki-storage-noproc") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-denied") removeDirectoryRecursive $ \denied -> do
      let path = dir </> "store.db"
      e0 <- openSQLiteStore path
      s0 <- either (\e -> assertFailure ("noproc seed open: " ++ show e)) pure e0
      storeClose s0
      deadPid <- reapedPid
      writeFile (path ++ ".lock") (show deadPid ++ "\n")
      withFileMode denied 0o000 $
        withProcRoot denied $ do
          e1 <- openSQLiteStore path
          case e1 of
            Right s1 -> do
              storeClose s1
              assertFailure "noproc: takeover succeeded with liveness unknowable (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("noproc: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("noproc: wrong error for unreadable proc: " ++ show other)

-- | Partial-mask guard: a @\/proc@ view that shows @self@ but
-- hides our own pid, or whose owner entry ERRORS on stat (a
-- self-loop symlink: ELOOP for every runner, root included),
-- cannot prove death — so a second open against a live owner is
-- refused as unknowable, never misread as dead.
testProcPartialMaskRefuses :: IO ()
testProcPartialMaskRefuses =
  bracket (makeTempDir "haskoki-storage-pmask") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-fakeproc") removeDirectoryRecursive $ \fakeProc -> do
      reaped <- newIORef False
      me <- getProcessID
      ppid <- getParentProcessID
      let path = dir </> "store.db"
          doneFile = dir </> "holder.done"
          readyFile = dir </> "holder.ready"
      bracket (spawnHolder path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
        holderPid <- spawnedPid ph "pmask"
        awaitLockOwner path holderPid
        awaitDone readyFile (6000 :: Int)
        writeFile (fakeProc </> "self") ""
        withProcRoot fakeProc $ do
          e1 <- openSQLiteStore path
          case e1 of
            Right s1 -> do
              storeClose s1
              assertFailure "pmask: second open succeeded with a partial proc view (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("pmask: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("pmask: wrong error for partial proc view: " ++ show other)
        writeFile (fakeProc </> show me) ""
        -- The parent witness must be present so phase 2 still pins
        -- the owner-entry error (not the parent's absence).
        writeFile (fakeProc </> show ppid) ""
        -- The owner entry must ERROR on stat (not merely be absent)
        -- while self+own-pid stay visible. A self-loop symlink stats
        -- as ELOOP for every runner; a chmod-000 construction would
        -- be bypassed as root (CI runs as root), misreading the live
        -- owner as dead.
        createSymbolicLink (show holderPid) (fakeProc </> show holderPid)
        withProcRoot fakeProc $ do
          e2 <- openSQLiteStore path
          case e2 of
            Right s2 -> do
              storeClose s2
              assertFailure "pmask: second open succeeded with owner entry denied (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("pmask: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("pmask: wrong error for denied owner entry: " ++ show other)
        writeFile doneFile "done\n"
        awaitHolderExit reaped ph "pmask"
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("pmask reopen after close: " ++ show e)) pure e3
        storeClose s3

-- | Fresh-guard test (finding 1): the database guard is held before
-- any SQLite work on the fresh-create path. A is forked and pauses
-- after creating+guarding the database (via @HASKOKI_OPEN_PAUSE@);
-- its sidecar is deleted (the finding's interleaving); B's open
-- must refuse at the database guard — never take over — and A's
-- resume must complete harmlessly. Then A owns alone and the store
-- reopens cleanly. In-process threads contend on @flock@ exactly
-- like processes (separate opens), so no spawn is needed.
testFreshGuardBeforeInit :: IO ()
testFreshGuardBeforeInit =
  bracket (makeTempDir "haskoki-storage-freshg") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-pause") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          lockPath = path ++ ".lock"
          pausedFile = pauseDir </> "paused"
          goFile = pauseDir </> "go"
      withOpenPause pauseDir path $ do
        resVar <- newEmptyMVar
        _ <- forkIO $ do
          e <- openSQLiteStore path
          _ <- tryPutMVar resVar e
          pure ()
        awaitDone pausedFile (300 :: Int)
        paused <- doesFileExist pausedFile
        assertBool "freshg: opener did not pause (seam not honored?)" paused
        -- The interleaving: A loses its sidecar while paused.
        removeFile lockPath
        e2 <- openSQLiteStore path
        case e2 of
          Right s2 -> do
            storeClose s2
            assertFailure "freshg: second open took over a paused fresh init (state fork)"
          Left (StoreSecondWriter msg) ->
            assertBool ("freshg: expected database-anchored refusal, got: " ++ msg)
              ("database" `isInfixOf` msg)
          Left other ->
            assertFailure ("freshg: wrong error during paused fresh init: " ++ show other)
        writeFile goFile "go\n"
        mA <- timeout (30 * 1000000) (takeMVar resVar)
        eA <- case mA of
          Nothing -> assertFailure "freshg: paused opener wedged after release"
          Just e -> pure e
        sA <- either (\e -> assertFailure ("freshg: paused opener failed: " ++ show e)) pure eA
        storeClose sA
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("freshg reopen after close: " ++ show e)) pure e3
        eLoaded <- storeLoadTokens s3
        _ <- either (\e -> assertFailure ("freshg load after close: " ++ show e)) pure eLoaded
        storeClose s3

-- | Swap-abort test (finding 1): if the database path no longer
-- names the guarded inode when SQLite opens it, the open aborts
-- with "replaced" instead of initializing another file — and the
-- planted file is left byte-identical. (The planted store is
-- created outside the pause env: it must not pause itself.)
testSwappedDbAborts :: IO ()
testSwappedDbAborts =
  bracket (makeTempDir "haskoki-storage-swap") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-pause") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          plantSrc = dir </> "plant.db"
          movedAside = dir </> "moved-aside.db"
          pausedFile = pauseDir </> "paused"
          goFile = pauseDir </> "go"
      ePlant <- openSQLiteStore plantSrc
      plant <- either (\e -> assertFailure ("swap plant open: " ++ show e)) pure ePlant
      _ <- seedStore plant
      storeClose plant
      plantBytes <- BS.readFile plantSrc
      withOpenPause pauseDir path $ do
        resVar <- newEmptyMVar
        _ <- forkIO $ do
          e <- openSQLiteStore path
          _ <- tryPutMVar resVar e
          pure ()
        awaitDone pausedFile (300 :: Int)
        paused <- doesFileExist pausedFile
        assertBool "swap: opener did not pause (seam not honored?)" paused
        renameFile path movedAside
        renameFile plantSrc path
        writeFile goFile "go\n"
        mA <- timeout (30 * 1000000) (takeMVar resVar)
        eA <- case mA of
          Nothing -> assertFailure "swap: paused opener wedged after release"
          Just e -> pure e
        case eA of
          Right sA -> do
            storeClose sA
            assertFailure "swap: opener initialized a swapped-in database"
          Left (StoreIO msg) ->
            assertBool ("swap: expected replaced-database refusal, got: " ++ msg)
              ("replaced" `isInfixOf` msg)
          Left other ->
            assertFailure ("swap: wrong error for swapped database: " ++ show other)
        afterBytes <- BS.readFile path
        assertEqual "swap: planted database modified" plantBytes afterBytes
        aside <- doesFileExist movedAside
        assertBool "swap: paused opener's file went missing" aside
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("swap reopen planted: " ++ show e)) pure e3
        eLoaded <- storeLoadTokens s3
        loaded <- either (\e -> assertFailure ("swap load planted: " ++ show e)) pure eLoaded
        assertEqual "swap: planted token survives" 1 (length loaded)
        storeClose s3

-- | Async-cleanup test (finding 2): killing a thread blocked in the
-- database-guard retry (flock-retry delays are interruptible even
-- under mask) must release the already-owned sidecar — never
-- strand a live-pid lock that wedges later opens. Each iteration
-- deterministically enters the retry window (the parent holds the
-- database flock, so every try fails over ~45ms); the kill lands
-- ~10ms in. A missed kill (the opener refused first) still
-- asserts the clean end-state; the hit counter proves the window
-- was entered at least once.
testKillDuringDbRetry :: IO ()
testKillDuringDbRetry =
  bracket (makeTempDir "haskoki-storage-killr") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
        lockPath = path ++ ".lock"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("killr seed open: " ++ show e)) pure e0
    storeClose s0
    me <- getProcessID
    hits <- newIORef (0 :: Int)
    let awaitOwnPid = do
          let want = BC8.pack (show me ++ "\n")
              go = do
                content <- catchIOError (BS.readFile lockPath) (\_ -> pure BS.empty)
                if content == want then pure () else threadDelay 1000 >> go
          mOk <- timeout 10000000 go
          case mOk of
            Just () -> pure ()
            Nothing -> assertFailure "killr: opener did not reach the db-guard retry"
        loop 0 = pure ()
        loop n = do
          deadPid <- reapedPid
          writeFile lockPath (show deadPid ++ "\n")
          bracket (openFd path ReadOnly defaultFileFlags) closeFd $ \holdFd -> do
            held <- testTryFlock holdFd
            assertBool "killr: parent could not hold the database flock" held
            resVar <- newEmptyMVar
            tid <- forkIO $ do
              e <- (openSQLiteStore path) `onException`
                (tryPutMVar resVar False >> pure ())
              case e of
                Right s -> storeClose s
                Left _ -> pure ()
              _ <- tryPutMVar resVar True
              pure ()
            awaitOwnPid
            threadDelay 10000
            killThread tid
            mOut <- timeout (5 * 1000000) (takeMVar resVar)
            case mOut of
              Nothing -> assertFailure "killr: opener wedged after kill"
              Just False -> atomicModifyIORef' hits (\h -> (h + 1, ()))
              Just True -> pure ()
          absent <- not <$> doesFileExist lockPath
          assertBool "killr: kill stranded the sidecar lock" absent
          eRe <- openSQLiteStore path
          sRe <- either (\e -> assertFailure ("killr: reopen wedged after kill: " ++ show e)) pure eRe
          storeClose sRe
          loop (n - 1)
    loop (20 :: Int)
    nHits <- readIORef hits
    assertBool "killr: no mid-window kill observed (vacuous?)" (nHits >= 1)

-- | Selective-hiding test (finding 3): a @\/proc@ view showing
-- @self@ and our own pid but hiding the live owner's entry with
-- @ENOENT@ cannot prove death — the parent witness (always a live
-- process) is absent, so the open refuses as unknowable. A
-- surgical filter hiding ONLY the owner is
-- @\/proc@-indistinguishable from a dead owner and falls through
-- to the kernel-lock backstop, which still refuses.
testSelectiveHideRefuses :: IO ()
testSelectiveHideRefuses =
  bracket (makeTempDir "haskoki-storage-selhide") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-fakeproc") removeDirectoryRecursive $ \fakeProc -> do
      reaped <- newIORef False
      me <- getProcessID
      ppid <- getParentProcessID
      let path = dir </> "store.db"
          doneFile = dir </> "holder.done"
          readyFile = dir </> "holder.ready"
      bracket (spawnHolder path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
        holderPid <- spawnedPid ph "selhide"
        awaitLockOwner path holderPid
        awaitDone readyFile (6000 :: Int)
        -- Phase A: self + own pid visible, live owner hidden
        -- (ENOENT), parent witness absent -> unknowable.
        writeFile (fakeProc </> "self") ""
        writeFile (fakeProc </> show me) ""
        withProcRoot fakeProc $ do
          e1 <- openSQLiteStore path
          case e1 of
            Right s1 -> do
              storeClose s1
              assertFailure "selhide: second open succeeded with owner hidden (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("selhide: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("selhide: wrong error for hidden owner: " ++ show other)
        -- Phase B: the surgical residual — parent witness present,
        -- only the live owner hidden -> takeover attempted, kernel
        -- lock backstop refuses.
        writeFile (fakeProc </> show ppid) ""
        withProcRoot fakeProc $ do
          e2 <- openSQLiteStore path
          case e2 of
            Right s2 -> do
              storeClose s2
              assertFailure "selhide: second open took over a live owner (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("selhide: expected kernel-lock refusal, got: " ++ msg)
                ("kernel lock held" `isInfixOf` msg)
            Left other ->
              assertFailure ("selhide: wrong error for surgical hiding: " ++ show other)
        writeFile doneFile "done\n"
        awaitHolderExit reaped ph "selhide"
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("selhide reopen after close: " ++ show e)) pure e3
        storeClose s3

-- | Pause-isolation test (finding 3): with the pause seam armed
-- for one intended database path, a fresh-create open of a
-- DIFFERENT path must not pause. (Before path binding, any parallel
-- SQLite creator — contract/commit tests, inherited-env holders —
-- paused on the same handshake file and could satisfy the
-- controller's handshake before the intended opener paused.)
testPauseBindsToIntendedOpener :: IO ()
testPauseBindsToIntendedOpener =
  bracket (makeTempDir "haskoki-storage-pausebind") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-pause") removeDirectoryRecursive $ \pauseDir -> do
      let intended = dir </> "intended.db"
          other = dir </> "other.db"
      withOpenPause pauseDir intended $ do
        resVar <- newEmptyMVar
        _ <- forkIO $ do
          e <- openSQLiteStore other
          _ <- tryPutMVar resVar e
          pure ()
        mDone <- timeout (5 * 1000000) (takeMVar resVar)
        eOther <- case mDone of
          Nothing -> assertFailure "pausebind: unrelated fresh open paused (seam leaked across openers)"
          Just e -> pure e
        sOther <- either (\e -> assertFailure ("pausebind: unrelated open failed: " ++ show e)) pure eOther
        storeClose sOther
        pausedExists <- doesFileExist (pauseDir </> "paused")
        assertBool "pausebind: pause seam fired for an unintended opener" (not pausedExists)

-- | Pid-0 test (finding 2): a lock naming pid 0 is takeable WITHOUT
-- probing @\/proc\/0@ — pid 0 is never a userspace owner (owners
-- write @getProcessID@), so the entry is dead by rule while the
-- kernel backstop still confirms. The fake proc root even contains
-- a @0@ entry: any probe would read Present (alive) and refuse, so
-- success proves no probe happened.
testPidZeroTakeable :: IO ()
testPidZeroTakeable =
  bracket (makeTempDir "haskoki-storage-pidzero") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-fakeproc") removeDirectoryRecursive $ \fakeProc -> do
      me <- getProcessID
      ppid <- getParentProcessID
      let path = dir </> "store.db"
      e0 <- openSQLiteStore path
      s0 <- either (\e -> assertFailure ("pidzero seed open: " ++ show e)) pure e0
      _ <- seedStore s0
      storeClose s0
      writeFile (path ++ ".lock") "0\n"
      writeFile (fakeProc </> "self") ""
      writeFile (fakeProc </> show me) ""
      writeFile (fakeProc </> show ppid) ""
      writeFile (fakeProc </> "0") ""
      withProcRoot fakeProc $ do
        e1 <- openSQLiteStore path
        s1 <- either (\e -> assertFailure ("pidzero takeover failed: " ++ show e)) pure e1
        content <- readFile (path ++ ".lock")
        assertEqual "pidzero: lock re-owned by taker" (show me ++ "\n") content
        eLoaded <- storeLoadTokens s1
        loaded <- either (\e -> assertFailure ("pidzero load after takeover: " ++ show e)) pure eLoaded
        assertEqual "pidzero: seeded token survives takeover" 1 (length loaded)
        storeClose s1

-- | Liveness-mapping unit test (finding 2): the pure verdict
-- table over synthetic probe results, pinning the namespace-local
-- ppid-0 rule (parent witness inapplicable, stale recovery works)
-- without forking into a PID namespace — plus the fail-closed rows
-- the @\/proc@-fixture tests rely on.
testLivenessMapping :: IO ()
testLivenessMapping = do
  let t = assertEqual "liveness mapping"
  -- The ppid-0 rule (parent probe Nothing: no /proc/0 probe taken).
  t PidDead $ livenessFromProbes ProbePresent ProbePresent Nothing ProbeAbsent
  t PidAlive $ livenessFromProbes ProbePresent ProbePresent Nothing ProbePresent
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent Nothing ProbeUnknown
  -- The parent witness still gates when the ppid is namespace-local.
  t PidDead $ livenessFromProbes ProbePresent ProbePresent (Just ProbePresent) ProbeAbsent
  t PidAlive $ livenessFromProbes ProbePresent ProbePresent (Just ProbePresent) ProbePresent
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent (Just ProbePresent) ProbeUnknown
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent (Just ProbeAbsent) ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent (Just ProbeUnknown) ProbeAbsent
  -- Self/own gating fails closed regardless of the parent row.
  t PidUnknown $ livenessFromProbes ProbeAbsent ProbePresent Nothing ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbeUnknown ProbePresent (Just ProbePresent) ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbePresent ProbeAbsent Nothing ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbePresent ProbeUnknown (Just ProbePresent) ProbeAbsent

-- | A provably-dead pid: fork a child that exits immediately, reap
-- it, and confirm @\/proc@ has no entry (a reused pid is retried).
reapedPid :: IO Int
reapedPid = go (0 :: Int)
  where
    go n
      | n > 50 = assertFailure "could not reap a dead pid"
      | otherwise = do
          pid <- forkProcess (exitImmediately ExitSuccess)
          _ <- getProcessStatus True False pid
          alive <- fileExist ("/proc/" ++ show (fromIntegral pid :: Int))
          if alive then go (n + 1) else pure (fromIntegral pid)

foreign import ccall unsafe "sys/file.h flock" test_c_flock :: CInt -> CInt -> IO CInt

-- | The test's own kernel-lock hold: an independent @flock@ import
-- (not the library's), so the held-lock phase proves the guard
-- interacts at the kernel level. @6 = LOCK_EX|LOCK_NB@ (Linux ABI).
testTryFlock :: Fd -> IO Bool
testTryFlock fd = (== 0) <$> test_c_flock (fromIntegral fd) 6

-- | Reject any bytes mentioning pointers, handles, callbacks, or
-- native crypto contexts.
cleanBytes :: String -> Bool
cleanBytes s = not (any (`isInfixOf` s) banned)
  where
    banned =
      [ "Ptr"
      , "callback"
      , "Callback"
      , "CALLBACK"
      , "EVP_"
      , "evp_"
      , "FunPtr"
      , "nullFunPtr"
      , "handle"
      , "Handle"
      , "HANDLE"
      , "struct"
      , "0x7f"
      , "0x55"
      , "0X"
      ]

-- | The only bare JSON number permitted is @\"format_version\":1@;
-- every other digit must sit inside a string.
numbersClean :: String -> Bool
numbersClean s = go False False (stripFmt s)
  where
    stripFmt [] = []
    stripFmt t@(c : cs)
      | "\"format_version\":1" `isPrefixOf` t = stripFmt (drop 18 t)
      | otherwise = c : stripFmt cs
    go _ _ [] = True
    go inStr esc (c : cs)
      | inStr && esc = go True False cs
      | inStr && c == '\\' = go True True cs
      | inStr && c == '"' = go False False cs
      | inStr = go True False cs
      | c == '"' = go True False cs
      | c >= '0' && c <= '9' = False
      | otherwise = go False False cs

-- | Schema parity: at most one token per slot (the SQLite
-- @UNIQUE(slot_key)@, mirrored by the memory backend).
testSlotUnique :: Opener -> IO ()
testSlotUnique o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  _ <- seedStore s
  let twin = TokenRecord
        { trId = TokenId 8
        , trSlot = SlotId 0
        , trGeneration = Generation 1
        , trLabel = "twin"
        , trAuth = tokenAuthNew
        }
  bad <- storeCommit s emptyDelta { sdPutTokens = [twin] }
  case bad of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected slot refusal, got: " ++ show other)
  ok <- storeCommit s emptyDelta { sdPutTokens = [twin { trSlot = SlotId 1 }] }
  assertEqual "free slot commits" Committed ok
  storeClose s

-- | A pending-recipe job fixture: deterministic recipe plus owned
-- parameter bytes (replayable after restart, no live context).
demoJobPending :: Word64 -> TokenId -> Generation -> JobRecord
demoJobPending pid tok gen = JobRecord
  { jrPersistentId = pid
  , jrToken = tok
  , jrTokenGeneration = gen
  , jrFunction = "C_Digest"
  , jrState = JobQueued
  , jrBody = JobPending "sha256-owned-input/v1" (BS.pack (map fromIntegral [1 .. 32 :: Int]))
  }

-- | A prepared-result job fixture: verdict plus fully owned
-- result bytes (deliverable without any live context).
demoJobResult :: Word64 -> TokenId -> Generation -> JobRecord
demoJobResult pid tok gen = JobRecord
  { jrPersistentId = pid
  , jrToken = tok
  , jrTokenGeneration = gen
  , jrFunction = "C_Sign"
  , jrState = JobReady
  , jrBody = JobResult CKR_OK (BS.pack (map fromIntegral [101 .. 140 :: Int]))
  }

-- | Seed one token with two token objects; return the records.
seedStore :: Store -> IO (TokenRecord, [ObjectRecord])
seedStore store = do
  let slot = SlotId 0
      tmplA =
        [ (AttrClass, ValULong 3)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "seed-a")
        , (AttrValue, ValBytes "seed-bytes-a")
        ]
      tmplB =
        [ (AttrClass, ValULong 4)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "seed-b")
        ]
  mSeated <- expectRight "seed seat+open" (publishDelta (addToken emptyModel slot)
    (StateDelta [DeltaOpenSession (SessionId 1) slot False]))
  st <- expectJust "seed session" (lookupSession mSeated (SessionId 1))
  (m1, _, oid1) <- expectCreated mSeated st tmplA
  (m2, _, oid2) <- expectCreated m1 st tmplB
  ost1 <- expectJust "seed object 1" (lookupObject m2 oid1)
  ost2 <- expectJust "seed object 2" (lookupObject m2 oid2)
  let tok = TokenRecord
        { trId = TokenId 7
        , trSlot = slot
        , trGeneration = Generation 1
        , trLabel = "seed-token"
        , trAuth = tokenAuthNew
        }
  result <- storeCommit store emptyDelta
    { sdPutTokens = [tok]
    , sdPutObjects =
        [ ObjectPut Nothing (objectToRecord (TokenId 7) ost1)
        , ObjectPut Nothing (objectToRecord (TokenId 7) ost2)
        ]
    }
  assertEqual "seed commit" Committed result
  pure (tok, [objectToRecord (TokenId 7) ost1, objectToRecord (TokenId 7) ost2])

-- | Plan + publish one creation; return the model, handle, and id.
expectCreated
  :: Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle, ObjectId)
expectCreated m st tmpl = case planCreateObject m st tmpl of
  Immediate pc -> case publishDelta m (pcDelta pc) of
    Left fault -> assertFailure ("publish failed: " ++ show fault)
    Right m' -> case mapMaybe (decodeHandle . outBytes) (pcOutputs pc) of
      [h] -> pure (m', h, ObjectId (mNextObject' m))
      _ -> assertFailure "expected exactly one handle output"
  _ -> assertFailure "expected Immediate creation plan"

-- | Read the model's next-object counter (the id just allocated).
mNextObject' :: Model -> Int
mNextObject' = mNextObject

-- | The exact canonical key set of an object document. No handle,
-- no pointer, no out-of-band field may appear.
assertObjectDocKeys :: StoredDoc -> IO ()
assertObjectDocKeys d =
  assertEqual ("object doc keys: " ++ docKey d)
    [ "attrs"
    , "class"
    , "format_version"
    , "key_type"
    , "material"
    , "material_encoding"
    , "object_id"
    , "revision"
    , "token_id"
    ]
    (docTopKeys (docJson d))

-- | Reject any stored bytes mentioning handles/pointers.
noHandleBytes :: String -> Bool
noHandleBytes s =
  not (any (`isInfixOf` s) ["handle", "Handle", "HANDLE", "Ptr", "0x7f", "0x55"])

-- | A handle resolves when its binding names a live object.
resolves :: Model -> ExternalHandle -> Bool
resolves m h = case Map.lookup h (mHandles m) of
  Nothing -> False
  Just b -> case lookupObject m (hbObject b) of
    Nothing -> False
    Just ost -> hbGeneration b == osGeneration ost
