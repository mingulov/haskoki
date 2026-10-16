{-# LANGUAGE OverloadedStrings #-}
{- | Shared storage-test fixtures: scratch directories, read-only raw
views of a store file (never a migrating or recovering open), the
committed released-binary stores, and redaction assertions.
-}
module StoreFixtures
  ( makeTempDir, storePackageRoot, rawExec, rawTexts, roTexts, withScratch
  , openReconciled, closeAcquired
  , copyReleasedFixture, readManifest, loadConfigOrFail
  , fixtureLabels, fixtureSo, fixtureUser, fixturePins, assertNoPins
  , withFileMode, reapedPid
  , StoreState (..), captureState, assertUnchanged, makeSchemaStore
  , writeStoreConfig, expectStdNeedsMigration, fixtureToken
  , spawnedPid, claimReap, waitBounded, releaseHolder, awaitHolderExit
  , pragmaInt
  ) where

import Control.Concurrent (threadDelay)
import Control.Exception (bracket, bracket_)
import Control.Monad (when)
import qualified Data.ByteString as BS
import Data.IORef (IORef, atomicModifyIORef', newIORef)
import Data.List (isInfixOf, isPrefixOf, sort)
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import System.Directory (createDirectory, doesFileExist, getTemporaryDirectory, removeDirectoryRecursive)
import System.Environment (getExecutablePath)
import System.Exit (ExitCode (..))
import System.FilePath (takeDirectory, (</>))
import System.IO.Error (catchIOError, isAlreadyExistsError)
import System.Posix.Files (fileExist, fileMode, getFileStatus, setFileMode)
import System.Posix.Process (getProcessID)
import System.Posix.Signals (sigKILL, signalProcess)
import System.Posix.Types (FileMode, ProcessID)
import System.Process (ProcessHandle, createProcess, getPid, getProcessExitCode, proc, CreateProcess (..))
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)

import Haskoki.FFI.Standard (StdStore (..), StdStoreError (..), openStdStore)
import Haskoki.Runtime.Config
import Haskoki.Runtime.Lifecycle (newEnv, rulesFromConfig)
import Haskoki.Runtime.Storage
  ( CommitResult (..), CredentialRecord, StoreDelta (..), StoreError (..), TokenRecord (..)
  , emptyDelta, storeClose, storeCommit
  )
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Types (Generation (..), SlotId (..), TokenId (..))

-- | Run with a fresh scratch directory, removed afterwards.
withScratch :: String -> (FilePath -> IO a) -> IO a
withScratch prefix = bracket (makeTempDir prefix) removeDirectoryRecursive

-- | Rows of one text column through a READ-ONLY connection: never
-- creates the file, never rolls back a journal, never migrates.
roTexts :: FilePath -> T.Text -> IO [String]
roTexts path sql =
  bracket (S.open2 (T.pack path) [S.SQLOpenReadOnly] S.SQLVFSDefault) S.close
    (\db -> rawTexts db sql)

fixtureLabels, fixtureSo, fixtureUser, fixturePins :: [String]
fixtureLabels = ["haskoki-demo", "haskoki-ops"]
fixtureSo = ["58213946", "69324057"]
fixtureUser = ["12873465", "23984576"]
-- | Every PIN value any test uses (fixture, in-band, test-only).
fixturePins = fixtureSo ++ fixtureUser ++ ["34095687", "45106798", "70435168", "81546279"]

-- | Fail if any PIN value occurs in an output text.
assertNoPins :: String -> String -> IO ()
assertNoPins ctx text =
  mapM_ (\p -> assertBool (ctx ++ ": output carries a PIN value") (not (p `isInfixOf` text)))
    fixturePins

-- | Copy a committed released-binary store into a scratch directory
-- (mode 0600) and write its config from the template, pointing at
-- the copy. Returns (store path, config path). The committed file is
-- only read.
copyReleasedFixture :: String -> FilePath -> IO (FilePath, FilePath)
copyReleasedFixture tag dir = do
  root <- storePackageRoot
  let stores = root </> "tests" </> "fixtures" </> "stores"
      store = dir </> "store.sqlite"
      cfgPath = dir </> "config.toml"
  BS.readFile (stores </> tag </> "store.sqlite") >>= BS.writeFile store
  setFileMode store 0o600
  tmpl <- readFile (stores </> "config.toml.in")
  writeFile cfgPath (T.unpack (T.replace "@STORE@" (T.pack store) (T.pack tmpl)))
  pure (store, cfgPath)

-- | @key: value@ lines of a fixture manifest.
readManifest :: FilePath -> IO [(String, String)]
readManifest path = do
  body <- readFile path
  pure [ (k, drop 2 rest) | l <- lines body, let (k, rest) = break (== ':') l, ": " `isPrefixOf` rest ]

loadConfigOrFail :: FilePath -> IO Config
loadConfigOrFail p = loadConfigFile p >>= either (assertFailure . show) pure

-- | Make a fresh scratch directory: pid-suffixed, retrying the next name
-- on an already-exists error (no new dependencies; concurrent runs cannot collide).
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
          -- Decide from the error itself: a concurrent test may create and
          -- already remove the same name, so a later existence check races.
          (createDirectory dir >> pure dir) `catchIOError` \e ->
            if isAlreadyExistsError e
              then tryNames base stem (n + 1)
              else ioError (userError ("makeTempDir: cannot create " ++ dir ++ ": " ++ show e))

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
                  then assertFailure "haskoki.cabal not found above the test binary"
                  else ascend parent

-- | Run one raw statement against a closed database file.
rawExec :: FilePath -> T.Text -> IO ()
rawExec path sql = do
  db <- S.open (T.pack path)
  S.exec db sql
  S.close db

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

-- | Open the store file at the path through the production
-- acquisition (the same 'openStdStore' the instance open
-- threads): typed reconciliation errors, no assembly.
openReconciled :: FilePath -> Config -> IO (Either StdStoreError (Maybe StdStore))
openReconciled path cfg = do
  env <- newEnv (rulesFromConfig cfg)
  openStdStore env cfg { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True }

-- | Close an acquired store handle, if any.
closeAcquired :: Maybe StdStore -> IO ()
closeAcquired Nothing = pure ()
closeAcquired (Just ss) = storeClose (stdStore ss)

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

-- | A provably-dead pid: spawn a fresh process with no inherited
-- store descriptors, reap it, and confirm @\/proc@ has no entry
-- (a reused pid is retried). A raw fork can keep another parallel
-- test's database guard locked after that test closes its store.
reapedPid :: IO Int
reapedPid = go (0 :: Int)
  where
    go n
      | n > 50 = assertFailure "could not reap a dead pid"
      | otherwise = do
          reaped <- newIORef False
          bracket spawnReaper (releaseHolder reaped) $ \ph -> do
            pid <- spawnedPid ph "dead-pid"
            awaitHolderExit reaped ph "dead-pid"
            alive <- fileExist ("/proc/" ++ show (fromIntegral pid :: Int))
            if alive then go (n + 1) else pure (fromIntegral pid)
    spawnReaper :: IO ProcessHandle
    spawnReaper = do
      (_, _, _, ph) <- createProcess ((proc "/bin/true" []) { close_fds = True })
      pure ph

-- | Everything a refused open must leave as it was. Credential
-- documents carry base64 PINs: compare them, never print them.
data StoreState = StoreState
  { ssBytes :: !BS.ByteString
  , ssSchema :: ![String]
  , ssTables :: ![String]
  , ssCredentials :: ![(String, String)]
  , ssLockPresent :: !Bool
  , ssJournalPresent :: !Bool
  }

captureState :: FilePath -> IO StoreState
captureState path = do
  bytes <- BS.readFile path
  schema <- roTexts path "SELECT value FROM store_meta WHERE key = 'schema_version'"
  tables <- sort <$> roTexts path "SELECT name FROM sqlite_master WHERE type = 'table'"
  ids <- if "credentials" `elem` tables
    then roTexts path "SELECT token_id FROM credentials ORDER BY token_id" else pure []
  docs <- if "credentials" `elem` tables
    then roTexts path "SELECT record_json FROM credentials ORDER BY token_id" else pure []
  lock <- doesFileExist (path ++ ".lock")
  journal <- doesFileExist (path ++ "-journal")
  pure (StoreState bytes schema tables (zip ids docs) lock journal)

-- | The store at the path is exactly as captured: raw bytes, schema
-- marker, table set and credential authority; the transient sidecar
-- lock and any journal are gone.
assertUnchanged :: String -> StoreState -> FilePath -> IO ()
assertUnchanged ctx before path = do
  after <- captureState path
  assertBool (ctx ++ ": database bytes unchanged") (ssBytes before == ssBytes after)
  assertEqual (ctx ++ ": schema marker unchanged") (ssSchema before) (ssSchema after)
  assertEqual (ctx ++ ": tables unchanged") (ssTables before) (ssTables after)
  assertBool (ctx ++ ": credential rows unchanged") (ssCredentials before == ssCredentials after)
  assertBool (ctx ++ ": no lock left behind") (not (ssLockPresent after))
  assertBool (ctx ++ ": no journal left behind") (not (ssJournalPresent after))

fixtureToken :: Int -> Int -> String -> TokenRecord
fixtureToken tid slot label =
  TokenRecord (TokenId (fromIntegral tid)) (SlotId (fromIntegral slot)) (Generation 0) label tokenAuthNew

-- | Build a store file at a given schema through the PRODUCTION
-- encoders: a fresh schema-3 store, the given rows committed, then
-- the marker moved down (schema 1 also drops the credentials table,
-- which is exactly the version-1 shape).
makeSchemaStore :: Int -> FilePath -> [TokenRecord] -> [CredentialRecord] -> IO ()
makeSchemaStore v path toks creds = do
  e <- openSQLiteStore path
  s <- either (assertFailure . show) pure e
  r <- storeCommit s emptyDelta { sdPutTokens = toks, sdPutCredentials = creds }
  storeClose s
  assertEqual "fixture rows commit" Committed r
  case v of
    1 -> do
      assertBool "a schema-1 store has no credential rows" (null creds)
      rawExec path "DROP TABLE credentials"
      rawExec path "UPDATE store_meta SET value = '1' WHERE key = 'schema_version'"
    2 -> rawExec path "UPDATE store_meta SET value = '2' WHERE key = 'schema_version'"
    3 -> pure ()
    _ -> assertFailure "makeSchemaStore: schema 1, 2 or 3"

-- | Write a config file naming a store and a token catalog; returns
-- the config path.
writeStoreConfig :: FilePath -> FilePath -> [String] -> [String] -> [String] -> IO FilePath
writeStoreConfig cfgPath store labels sos users = do
  writeFile cfgPath $ unlines
    [ "schema_version = 1", "profile = \"real-crypto\""
    , "[storage]", "kind = \"sqlite\"", "path = " ++ show store
    , "[engine]", "kind = \"openssl\"", "allow_synthetic_fallback = false"
    , "private_library_context = true"
    , "[trace]", "enabled = false"
    , "[tokens]", "labels = " ++ show labels, "so_pins = " ++ show sos
    , "user_pins = " ++ show users
    ]
  pure cfgPath

expectStdNeedsMigration :: Int -> Either StdStoreError (Maybe StdStore) -> IO ()
expectStdNeedsMigration found r = case r of
  Left (StdStoreSQLite (StoreNeedsMigration f t)) -> do
    assertEqual "found schema" found f
    assertEqual "target schema" 3 t
  Left other -> assertFailure ("refused for the wrong reason: " ++ show other)
  Right acq -> closeAcquired acq >> assertFailure "an old-schema store opened"

-- | The single integer a pragma returns, read on an open handle.
pragmaInt :: S.Database -> T.Text -> IO Int
pragmaInt db sql = bracket (S.prepare db sql) S.finalize $ \stmt -> do
  _ <- S.step stmt
  cols <- S.columns stmt
  case cols of
    [S.SQLInteger n] -> pure (fromIntegral n)
    other -> assertFailure ("pragma " ++ T.unpack sql ++ ": " ++ show other)
