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
  , spawnedPid, claimReap, waitBounded, releaseHolder, awaitHolderExit
  ) where

import Control.Concurrent (threadDelay)
import Control.Exception (bracket, bracket_)
import Control.Monad (when)
import qualified Data.ByteString as BS
import Data.IORef (IORef, atomicModifyIORef', newIORef)
import Data.List (isInfixOf, isPrefixOf)
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
import Test.Tasty.HUnit (assertBool, assertFailure)

import Haskoki.FFI.Standard (StdStore (..), StdStoreError, openStdStore)
import Haskoki.Runtime.Config
import Haskoki.Runtime.Lifecycle (newEnv, rulesFromConfig)
import Haskoki.Runtime.Storage (storeClose)

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
fixturePins = fixtureSo ++ fixtureUser ++ ["34095687", "45106798"]

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
