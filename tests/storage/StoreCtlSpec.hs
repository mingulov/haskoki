{-# LANGUAGE OverloadedStrings #-}
{- | CLI store subcommands (hermetic temp dirs).

@store check@ diagnoses a store without writing; @store inspect@ reads a SQLite store offline; @store reset@ refuses a
live (lock-held) store and resets an offline one only with the
confirm flag. Never mutates a live store.
-}
module StoreCtlSpec (spec, relChildMain) where

import Control.Concurrent (forkIO, isEmptyMVar, myThreadId, newEmptyMVar, putMVar, takeMVar, threadDelay, throwTo)
import Control.Exception (AsyncException (..), bracket, catch, throwIO, toException, try)
import Control.Monad (unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.List (isInfixOf, isPrefixOf, isSuffixOf)
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import GHC.IO.Handle (hDuplicate, hDuplicateTo)
import System.IO (BufferMode (..), IOMode (..), hClose, hFlush, hGetBuffering, hSetBuffering, openFile, stdout)
import System.IO.Error (isEOFError)
import Foreign.C.String (withCString)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (nullPtr)
import Foreign.StablePtr (castStablePtrToPtr)
import Foreign.Storable (poke)
import System.Directory (createDirectory, createDirectoryIfMissing, doesDirectoryExist, doesFileExist, listDirectory, removeFile, renameFile)
import System.Environment (getExecutablePath)
import System.Exit (ExitCode (..))
import System.FilePath ((</>))
import System.Posix.Files (createNamedPipe, createSymbolicLink, removeLink)
import System.Posix.IO (OpenMode (..), closeFd, defaultFileFlags, openFd)
import System.Posix.IO.ByteString (fdRead)
import System.Posix.User (getEffectiveUserID)
import System.Process (CreateProcess (..), createProcess, proc, terminateProcess, waitForProcess)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Ctl (CtlExit (..), ResetHooks (..), ctlHelp, noResetHooks, resetStoreWith, runCtl)
import Haskoki.Ctl.Store (renderCheckUnexpectedFailure, renderUnexpectedFailure, storeCheckCommand, storeMigrateCommandWith)
import Haskoki.Runtime.Storage.Preflight (MigrateHooks (..), backupCandidates, noMigrateHooks)
import Haskoki.FFI.Async (haskokiAsyncStoreClose, haskokiAsyncStoreOpen)
import Haskoki.FFI.Standard (openStdStore)
import Haskoki.Runtime.Catalog (asyncHomeEntry)
import Haskoki.Runtime.Lifecycle (newEnv, rulesFromConfig)
import Haskoki.Runtime.Storage (CommitResult (..), CredentialRecord (..), Store (..), StoreError (..), emptyDelta)
import Haskoki.Runtime.Storage.SQLite (MigrationHooks (..), noMigrationHooks, openSQLiteStore)
import Haskoki.Types (TokenId (..))

import StoreFixtures

spec :: TestTree
spec = testGroup "Store commands"
  [ testCase "inspect reads an offline store" caseInspect
  , testCase "reset refuses a live store" caseResetLive
  , testCase "reset refuses a kernel-held store whose lock was removed" caseResetRefusesKernelHeld
  , testCase "reset takes over a stale pid-1 lock with no holder" caseResetStalePid1
  , testCase "reset takes over a stale empty lock with no holder" caseResetStaleEmpty
  , testCase "reset takes over a stale garbage lock with no holder" caseResetStaleGarbage
  , testCase "reset: a replaced database fails and keeps the sidecar" caseResetDbReplacedKeepsSidecar
  , testCase "reset: a denied database removal fails and keeps the sidecar" caseResetDbRemoveDeniedKeepsSidecar
  , testCase "reset needs the confirm flag" caseResetConfirm
  , testCase "reset clears an offline store with the flag" caseResetOffline
  , testCase "check: a current store is ok (exit 0)" caseCheckOk
  , testCase "check: a v0.4 store needs migration (exit 1), unchanged" caseCheckMigrationRequired
  , testCase "check: a drifted catalog is refused (exit 1), unchanged" caseCheckIdentityRefused
  , testCase "check: a live owner is refused and keeps serving" caseCheckLive
  , testCase "check: a missing store is refused, nothing created" caseCheckMissing
  , testCase "check: another store's config is refused" caseCheckConfigMismatch
  , testCase "check: a hot journal is refused" caseCheckJournal
  , testCase "check: a cold journal names store migrate" caseCheckJournalCold
  , testCase "check: a newer schema is refused" caseCheckUnsupported
  , testCase "check: usage errors exit 2" caseCheckUsage
  , testCase "check: no output carries a PIN" caseCheckNoPins
  , testCase "check: broken config output carries no PIN" (caseCheckConfigNoPins "broken.toml" "[tokens]\nso_pins = [\"58213946\"\nlabels = 7\n")
  , testCase "check: mistyped value output carries no PIN" (caseCheckConfigNoPins "badval.toml" "[tokens]\nso_pins = 58213946\nuser_pins = [\"12873465\"]\n")
  , testCase "check: --async-home plans an async-created store" caseCheckAsyncHome
  , testCase "check: --async-home plans the v0.4 async shape" caseCheckAsyncHomeV04
  , testCase "check: --async-home as a flag value is a usage error" caseCheckAsyncHomeValue
  , testCase "check: a -wal or -shm file is refused" caseCheckWalShm
  , testCase "check: a foreign WAL through a symlink refuses and writes no shm" caseCheckSymlinkWal
  , testCase "check: a hot journal through a symlink names the journal" caseCheckSymlinkHotJournal
  , testCase "migrate: a foreign WAL through a symlink refuses, keeping the credential" caseMigrateSymlinkWal
  , testCase "migrate: a bare symlink migrates the target" caseMigrateSymlinkBare
  , testCase "migrate: a failure after the clear still reports the clearing" caseMigrateCliReportsClearOnFailure
  , testCase "migrate: a backup that fails verification is removed" caseMigrateBadBackupRemoved
  , testCase "check: a FIFO store is refused without hanging" caseCheckFifoStore
  , testCase "migrate: a FIFO store is refused without hanging" caseMigrateFifoStore
  , testCase "check: a FIFO lock is refused without hanging" caseCheckFifoLock
  , testCase "check: a symlinked lock is refused without following it" caseCheckSymlinkLock
  , testCase "check: an oversized lock without a pid line is unreadable" caseCheckOversizedLock
  , testCase "migrate: a v0.4 store migrates (exit 0) and then checks ok" caseMigrateCliV04
  , testCase "migrate: a current store needs nothing (exit 0)" caseMigrateCliNotNeeded
  , testCase "migrate: a drifted catalog refuses (exit 1), nothing written" caseMigrateCliRefusesDrift
  , testCase "migrate: a live owner refuses (exit 1)" caseMigrateCliLive
  , testCase "migrate: a hot journal refuses (exit 1), both files untouched" caseMigrateCliJournal
  , testCase "migrate: a hot journal header refuses (exit 1), both files untouched" caseMigrateCliJournalHot
  , testCase "migrate: a -wal file refuses (exit 1), everything untouched" caseMigrateCliWal
  , testCase "migrate: a -shm file refuses (exit 1), everything untouched" caseMigrateCliShm
  , testCase "migrate: a cold journal plus a -wal refuses (exit 1), everything untouched" caseMigrateCliColdWal
  , testCase "migrate: a current store with a cold journal needs nothing, journal untouched" caseMigrateCliSchema3Cold
  , testCase "check: a symlinked, FIFO or device journal is refused without hanging" caseCheckNonRegularJournal
  , testCase "migrate: --async-home as a flag value is a usage error" caseMigrateCliAsyncHomeValue
  , testCase "migrate: a missing backup dir refuses (exit 1), nothing written" caseMigrateCliMissingBackupDir
  , testCase "migrate: an unwritable backup dir refuses (exit 1), nothing written" caseMigrateCliUnwritableBackupDir
  , testCase "migrate: a wrong config refuses (exit 1), nothing written" caseMigrateCliWrongConfig
  , testCase "migrate: --async-home migrates a v0.4 async-created store, then the async open serves" caseMigrateCliAsyncHome
  , testCase "migrate: usage errors exit 2" caseMigrateCliUsage
  , testCase "migrate: no output or receipt carries a PIN" caseMigrateCliNoPins
  , testCase "migrate: an unexpected failure is a fixed redacted line" caseMigrateUnexpectedRedacted
  , testCase "check: an unexpected failure is a fixed tagged line with the type only" caseCheckUnexpectedTagged
  , testCase "migrate: an interrupt after planning is exit 130, never migrate-failed" caseMigrateInterrupt130
  , testCase "migrate: a sync failure after planning keeps a tag distinct from migrate-failed" caseMigrateSyncFailureDistinctTag
  , testCase "migrate: an unknown COMMIT outcome uses the migrate-commit-unknown tag" caseMigrateCommitUnknownTag
  , testCase "migrate: a non-interrupt async exception is rethrown, not reported" caseMigrateAsyncRethrown
  , testCase "check: an interrupt is exit 130, never store-unreadable" caseCheckInterrupt130
  , testCase "check: a relative path through an absolute symlink reaches the target" caseCheckRelativeThroughAbsoluteLink
  , testCase "check: a relative path with dotdot through an absolute symlink reaches the target" caseCheckRelativeDotDotThroughAbsoluteLink
  , testCase "migrate: a relative path through an absolute symlink migrates the target" caseMigrateRelativeThroughAbsoluteLink
  , testCase "open: a relative storage.path through an absolute symlink serves the target" caseOpenRelativeThroughAbsoluteLink
  , testCase "open: a relative storage.path never serves a mirrored directory" caseOpenRelativeThroughAbsoluteLinkMirror
  , testCase "check: a dangling symlink refuses, creating nothing at the target" caseCheckDanglingLink
  , testCase "migrate: a dangling symlink refuses, creating nothing at the target" caseMigrateDanglingLink
  , testCase "open: a dangling symlink refuses, creating nothing at the target" caseOpenDanglingLink
  , testCase "check: a missing store under a symlinked parent reports the resolved path" caseCheckMissingUnderSymlinkedDir
  , testCase "migrate: a missing store under a symlinked parent refuses, writing nothing" caseMigrateMissingUnderSymlinkedDir
  , testCase "open: a missing store under a symlinked parent is created and served" caseOpenMissingUnderSymlinkedDir
  , testCase "migrate: the backup-dir guard follows a symlink to the real store dir" caseMigrateSymlinkBackupDir
  , testCase "inspect: through a symlink, a live owner at the target reads live" caseInspectSymlinkLive
  , testCase "inspect: through a symlink, an offline store names the target" caseInspectSymlinkOffline
  , testCase "reset: through a symlink, a live owner at the target refuses" caseResetSymlinkLive
  , testCase "reset: through a symlink, an offline store removes the target" caseResetSymlinkOffline
  , testCase "reset: through a symlink, the dangling link is reported" caseResetSymlinkWarnsDangling
  , testCase "reset: a plain reset reports nothing on stderr" caseResetOfflineQuietStderr
  , testCase "migrate: after a clear, backup-exists stays honest about the store" caseMigrateClearBackupExistsHonest
  , testCase "migrate: after a clear, backup-failed stays honest about the store" caseMigrateClearBackupFailedHonest
  , testCase "migrate: after a clear, a failed transaction stays honest about the store" caseMigrateClearTxnFailedHonest
  , testCase "migrate: the clearing is on stdout before the backup verifies" caseMigrateClearRecordedAtClearTime
  , testCase "migrate: a backup that fails its read-back is removed" caseMigrateBackupReadbackFailureRemoved
  , testCase "check: with a cold journal, an identity refusal takes precedence" caseCheckColdJournalIdentityRefused
  , testCase "help lists check and migrate" caseHelpListsStoreCommands
  ]

withStoreFile :: (FilePath -> IO a) -> IO a
withStoreFile = bracket (makeTempDir "store-ctl") dropDir
  where
    dropDir _ = pure ()

seedDb :: FilePath -> IO FilePath
seedDb dir = do
  let db = dir </> "demo-token.sqlite"
  eSt <- openSQLiteStore db
  case eSt of
    Left err -> fail ("seed open failed: " ++ show err)
    Right st -> do
      _ <- storeCommit st emptyDelta
      storeClose st
      pure db

caseInspect :: IO ()
caseInspect = withStoreFile $ \dir -> do
  db <- seedDb dir
  r <- runCtl ["store", "inspect", "--path", db]
  assertEqual "inspect exits 0" 0 (ceCode r)
  assertBool "reports offline" ("offline" `elem` words (ceOut r))

caseResetLive :: IO ()
caseResetLive = withStoreFile $ \dir -> do
  let db = dir </> "live.sqlite"
  eSt <- openSQLiteStore db
  case eSt of
    Left err -> fail ("open failed: " ++ show err)
    Right st -> do
      r <- runCtl ["store", "reset", "--path", db, "--confirm-demo-reset"]
      storeClose st
      assertBool "live store refused" (ceCode r /= 0)
      assertBool "names the lock" ("live" `elem` words (ceOut r ++ ceErr r))
      stillThere <- doesFileExist db
      assertBool "live db untouched" stillThere

-- | Reset refuses a live store even after its sidecar lock is
-- removed by hand: the database kernel guard is still held, so the
-- store is live although /proc sees no pid.
caseResetRefusesKernelHeld :: IO ()
caseResetRefusesKernelHeld = withStoreFile $ \dir -> do
  let db = dir </> "live.sqlite"
  eSt <- openSQLiteStore db
  case eSt of
    Left err -> fail ("open failed: " ++ show err)
    Right st -> do
      removeLink (db ++ ".lock")
      r <- runCtl ["store", "reset", "--path", db, "--confirm-demo-reset"]
      storeClose st
      assertBool "kernel-held store refused" (ceCode r /= 0)
      assertBool "names reset-refused" ("reset-refused:" `isPrefixOf` ceErr r)
      stillThere <- doesFileExist db
      assertBool "live db untouched" stillThere

-- | Reset takes over a stale lock with no holder, like the open
-- and migrate paths: a pid-1 sidecar left by a killed container, an
-- empty file, or garbage refuses nothing once the kernel lock is
-- free, and both the store and the sidecar are removed.
caseResetStalePid1 :: IO ()
caseResetStalePid1 = caseResetStaleLock "1\n"

caseResetStaleEmpty :: IO ()
caseResetStaleEmpty = caseResetStaleLock ""

caseResetStaleGarbage :: IO ()
caseResetStaleGarbage = caseResetStaleLock "garbage\n"

caseResetStaleLock :: String -> IO ()
caseResetStaleLock content = withScratch "store-ctl" $ \dir -> do
  db <- seedDb dir
  writeFile (db ++ ".lock") content
  r <- runCtl ["store", "reset", "--path", db, "--confirm-demo-reset"]
  assertEqual "stale lock resets" 0 (ceCode r)
  gone <- doesFileExist db
  assertBool "db removed" (not gone)
  lockGone <- doesFileExist (db ++ ".lock")
  assertBool "stale lock removed" (not lockGone)

-- | A database swapped for a stranger file after ownership is taken
-- is not removed: reset fails, the sidecar stays in place, and the
-- stranger file is untouched. The hook performs the swap inside the
-- owned window, deterministically.
caseResetDbReplacedKeepsSidecar :: IO ()
caseResetDbReplacedKeepsSidecar = withScratch "store-ctl" $ \dir -> do
  db <- seedDb dir
  writeFile (db ++ ".lock") "1\n"
  origBytes <- BS.readFile db
  let swapped = db ++ ".orig"
      hooks = ResetHooks { rhBeforeRemove = renameFile db swapped >> createDirectory db }
  r <- resetStoreWith hooks db True
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "failed tag" ("reset-failed:" `isPrefixOf` ceErr r)
  lockStillThere <- doesFileExist (db ++ ".lock")
  assertBool "sidecar kept" lockStillThere
  strangerThere <- doesDirectoryExist db
  assertBool "stranger directory untouched" strangerThere
  BS.readFile swapped >>= assertEqual "original bytes kept" origBytes
  assertBool "names the replacement" ("replaced during reset" `isInfixOf` ceErr r)

-- | A database removal the filesystem denies fails the reset and
-- keeps the sidecar in place, with the reason in the report.
caseResetDbRemoveDeniedKeepsSidecar :: IO ()
caseResetDbRemoveDeniedKeepsSidecar = withScratch "store-ctl" $ \dir -> do
  db <- seedDb dir
  writeFile (db ++ ".lock") "1\n"
  euid <- getEffectiveUserID
  if euid == 0
    then putStrLn "skipped the denied database removal: mode 0555 does not deny root"
    else withFileMode dir 0o555 $ do
      r <- resetStoreWith noResetHooks db True
      assertEqual "exit 1" 1 (ceCode r)
      assertBool "failed tag with reason" (("reset-failed: cannot remove " ++ db ++ ": ") `isPrefixOf` ceErr r)
      lockStillThere <- doesFileExist (db ++ ".lock")
      assertBool "sidecar kept" lockStillThere
      dbStillThere <- doesFileExist db
      assertBool "database kept" dbStillThere

caseResetConfirm :: IO ()
caseResetConfirm = withStoreFile $ \dir -> do
  db <- seedDb dir
  r <- runCtl ["store", "reset", "--path", db]
  assertBool "no flag, no reset" (ceCode r /= 0)
  stillThere <- doesFileExist db
  assertBool "db untouched" stillThere

caseResetOffline :: IO ()
caseResetOffline = withStoreFile $ \dir -> do
  db <- seedDb dir
  r <- runCtl ["store", "reset", "--path", db, "--confirm-demo-reset"]
  assertEqual "reset exits 0" 0 (ceCode r)
  gone <- doesFileExist db
  assertBool "offline db removed" (not gone)

check :: FilePath -> FilePath -> IO CtlExit
check store cfg = runCtl ["store", "check", "--path", store, "--config", cfg]

caseCheckOk :: IO ()
caseCheckOk = withScratch "ctl-check" $ \dir -> do
  let store = dir </> "store.sqlite"
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  openReconciled store cfg >>= either (assertFailure . show) closeAcquired
  r <- check store cfgPath
  assertEqual "exit 0" 0 (ceCode r)
  assertBool "verdict ok" ("verdict: ok" `isInfixOf` ceOut r)
  assertEqual "quiet stderr" "" (ceErr r)

caseCheckMigrationRequired :: IO ()
caseCheckMigrationRequired = withScratch "ctl-check" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  before <- captureState store
  r <- check store cfgPath
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "plan printed" ("credentials-absent: 0000000000000001" `isInfixOf` ceOut r)
  assertBool "verdict" ("verdict: migration-required" `isInfixOf` ceOut r)
  assertBool "tag" ("store-migration-required:" `isPrefixOf` ceErr r)
  assertUnchanged "check" before store

caseCheckIdentityRefused :: IO ()
caseCheckIdentityRefused = withScratch "ctl-check" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  cfgPath <- writeStoreConfig (dir </> "d.toml") store ["haskoki-demo", "haskoki-ops-renamed"] fixtureSo fixtureUser
  before <- captureState store
  r <- check store cfgPath
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-identity-refused:" `isPrefixOf` ceErr r)
  assertBool "names both labels" ("haskoki-ops-renamed" `isInfixOf` ceErr r && "\"haskoki-ops\"" `isInfixOf` ceErr r)
  assertUnchanged "check" before store

caseCheckLive :: IO ()
caseCheckLive = withScratch "ctl-check" $ \dir -> do
  let store = dir </> "store.sqlite"
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  e <- openSQLiteStore store
  s <- either (assertFailure . show) pure e
  lockBefore <- BS.readFile (store ++ ".lock")
  r <- check store cfgPath
  BS.readFile (store ++ ".lock") >>= assertEqual "owner lock untouched" lockBefore
  c <- storeCommit s emptyDelta
  storeClose s
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-live:" `isPrefixOf` ceErr r)
  assertEqual "owner kept serving" Committed c

caseCheckMissing :: IO ()
caseCheckMissing = withScratch "ctl-check" $ \dir -> do
  let store = dir </> "absent.sqlite"
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  r <- check store cfgPath
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-missing:" `isPrefixOf` ceErr r)
  assertBool "not reported as in use" (not ("in use" `isInfixOf` ceErr r))
  created <- (||) <$> doesFileExist store <*> doesFileExist (store ++ ".lock")
  assertBool "nothing created" (not created)

caseCheckConfigMismatch :: IO ()
caseCheckConfigMismatch = withScratch "ctl-check" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  other <- writeStoreConfig (dir </> "o.toml") (dir </> "original.sqlite") fixtureLabels fixtureSo fixtureUser
  before <- captureState store
  r <- check store other
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("config-mismatch:" `isPrefixOf` ceErr r)
  assertUnchanged "check" before store

caseCheckJournal :: IO ()
caseCheckJournal = withScratch "ctl-check" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  BS.writeFile (store ++ "-journal") "interrupted"
  r <- check store cfgPath
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-journal-present:" `isPrefixOf` ceErr r)

-- A cold journal (nonzero, zeroed header: SQLite itself treats it as
-- not hot) is a distinct refusal whose remedy names store migrate.
caseCheckJournalCold :: IO ()
caseCheckJournalCold = withScratch "ctl-check" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  dbBytes <- BS.readFile store
  BS.writeFile (store ++ "-journal") (BS.replicate 512 0)
  jBytes <- BS.readFile (store ++ "-journal")
  r <- check store cfgPath
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-journal-cold:" `isPrefixOf` ceErr r)
  assertBool "remedy names store migrate" ("store migrate" `isInfixOf` ceErr r)
  BS.readFile (store ++ "-journal") >>= \b -> assertBool "journal untouched" (b == jBytes)
  BS.readFile store >>= \b -> assertBool "store untouched" (b == dbBytes)

caseCheckUnsupported :: IO ()
caseCheckUnsupported = withScratch "ctl-check" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  rawExec store "UPDATE store_meta SET value = '4' WHERE key = 'schema_version'"
  r <- check store cfgPath
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-unsupported-version:" `isPrefixOf` ceErr r)

caseCheckUsage :: IO ()
caseCheckUsage = mapM_ one
  [ ["store", "check"]
  , ["store", "check", "--path", "a"]
  , ["store", "check", "--path", "a", "--config"]
  , ["store", "check", "--path", "a", "--config", "b", "--extra", "c"]
  , ["store", "check", "--path", "a", "--path", "b", "--config", "c"]
  , ["store", "check", "--path", "a", "--config", "b", "--async-home", "--async-home"]
  ]
  where
    one args = do
      r <- runCtl args
      assertEqual (unwords args) 2 (ceCode r)
      assertBool (unwords args ++ ": store-check usage on stderr")
        ("store check: " `isPrefixOf` ceErr r || "usage: haskoki-ctl store check " `isPrefixOf` ceErr r)
      assertBool (unwords args ++ ": usage text names the command")
        ("usage: haskoki-ctl store check --path FILE --config FILE [--async-home]" `isInfixOf` ceErr r)
      assertEqual (unwords args ++ ": nothing on stdout") "" (ceOut r)

caseCheckConfigNoPins :: FilePath -> String -> IO ()
caseCheckConfigNoPins name body = withScratch "ctl-check" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  writeFile (dir </> name) body
  r <- check store (dir </> name)
  assertEqual "exit 1" 1 (ceCode r)
  assertNoPins name (ceOut r ++ ceErr r)

caseCheckNoPins :: IO ()
caseCheckNoPins = withScratch "ctl-check" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  drift <- writeStoreConfig (dir </> "d.toml") store ["haskoki-demo", "haskoki-ops-renamed"] fixtureSo fixtureUser
  writeFile (dir </> "broken.toml") "[tokens]\nso_pins = [\"58213946\"\nlabels = 7\n"
  writeFile (dir </> "badval.toml") "[tokens]\nso_pins = 58213946\nuser_pins = [\"12873465\"]\n"
  rs <- mapM (check store) [cfgPath, drift, dir </> "broken.toml", dir </> "badval.toml"]
  mapM_ (\r -> assertNoPins "check output" (ceOut r ++ ceErr r)) rs
  assertBool "config error is a kind and line"
    ("config-invalid: line " `isPrefixOf` ceErr (rs !! 2))
  assertEqual "mistyped PIN key is named, its value is not"
    "config-invalid: invalid value for tokens.so_pins\n" (ceErr (rs !! 3))

-- A store created through the async open carries the async home label
-- and plans under --async-home; the standard catalog refuses it.
caseCheckAsyncHome :: IO ()
caseCheckAsyncHome = withScratch "ctl-check" $ \dir -> do
  let store = dir </> "async.sqlite"
  withCString store $ \cPath -> alloca $ \slot -> do
    box <- haskokiAsyncStoreOpen cPath
    poke slot box
    haskokiAsyncStoreClose slot
  labels <- roTexts store "SELECT record_json FROM tokens"
  assertBool "home label is haskoki-async" (any ("haskoki-async" `isInfixOf`) labels)
  cfgPath <- writeStoreConfig (dir </> "c.toml") store ["haskoki-demo"] ["5678"] ["1234"]
  before <- captureState store
  plain <- check store cfgPath
  assertEqual "no flag: exit 1" 1 (ceCode plain)
  assertBool "no flag: identity refusal" ("store-identity-refused:" `isPrefixOf` ceErr plain)
  r <- runCtl ["store", "check", "--path", store, "--config", cfgPath, "--async-home"]
  assertEqual "flag: exit 0" 0 (ceCode r)
  assertBool "flag: verdict ok" ("verdict: ok" `isInfixOf` ceOut r)
  assertNoPins "async check" (ceOut plain ++ ceErr plain ++ ceOut r ++ ceErr r)
  assertUnchanged "check" before store

caseCheckAsyncHomeV04 :: IO ()
caseCheckAsyncHomeV04 = withScratch "ctl-check" $ \dir -> do
  let store = dir </> "async2.sqlite"
  makeSchemaStore 2 store [fixtureToken 1 0 "haskoki-async"] []
  cfgPath <- writeStoreConfig (dir </> "c.toml") store ["haskoki-demo"] ["5678"] ["1234"]
  plain <- check store cfgPath
  assertEqual "no flag: exit 1" 1 (ceCode plain)
  assertBool "no flag: identity refusal" ("store-identity-refused:" `isPrefixOf` ceErr plain)
  r <- runCtl ["store", "check", "--async-home", "--path", store, "--config", cfgPath]
  assertEqual "flag: exit 1" 1 (ceCode r)
  assertBool "plan" ("actions: freeze-credentials 0000000000000001; set-schema-version 2->3" `isInfixOf` ceOut r)
  assertBool "tag" ("store-migration-required:" `isPrefixOf` ceErr r)
  assertNoPins "async v0.4 check" (ceOut plain ++ ceErr plain ++ ceOut r ++ ceErr r)

-- --async-home is only a standalone switch: where a flag value is
-- expected it is a usage error, never silently the switch and never
-- the value.
caseCheckAsyncHomeValue :: IO ()
caseCheckAsyncHomeValue = withScratch "ctl-check" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let usage = "usage: haskoki-ctl store check --path FILE --config FILE [--async-home]"
      one args = do
        r <- runCtl args
        assertEqual (unwords args) 2 (ceCode r)
        assertBool (unwords args ++ ": usage on stderr") (usage `isInfixOf` ceErr r)
        assertEqual (unwords args ++ ": nothing on stdout") "" (ceOut r)
  one ["store", "check", "--path", store, "--config", "--async-home", cfgPath]
  one ["store", "check", "--path", "--async-home", store, "--config", cfgPath]

-- The store is rollback-journal only, so a -wal or -shm file can only
-- come from foreign tooling: the check refuses it like a journal. A
-- zero-byte leftover is ignored, as zero-byte journals are.
caseCheckWalShm :: IO ()
caseCheckWalShm = do
  withScratch "ctl-check" $ \dir -> do
    (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
    BS.writeFile (store ++ "-wal") "foreign write-ahead log"
    r <- check store cfgPath
    assertEqual "wal: exit 1" 1 (ceCode r)
    assertBool "wal: tag" ("store-foreign-sidecar:" `isPrefixOf` ceErr r)
  withScratch "ctl-check" $ \dir -> do
    (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
    BS.writeFile (store ++ "-shm") "foreign shared memory"
    r <- check store cfgPath
    assertEqual "shm: exit 1" 1 (ceCode r)
    assertBool "shm: tag" ("store-foreign-sidecar:" `isPrefixOf` ceErr r)
  withScratch "ctl-check" $ \dir -> do
    (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
    BS.writeFile (store ++ "-wal") ""
    r <- check store cfgPath
    assertEqual "empty wal: exit 1" 1 (ceCode r)
    assertBool "empty wal: ignored" ("verdict: migration-required" `isInfixOf` ceOut r)

-- A foreign WAL beside the real file is refused through a symlink:
-- the guard follows the link to the real file's sidecars, the store
-- bytes are unchanged, and no -shm appears at either name.
caseCheckSymlinkWal :: IO ()
caseCheckSymlinkWal = withScratch "ctl-check" $ \dir -> do
  (link, cfgPath, real) <- withSymlinkedFixture "v0.4.0.0" dir
  plantForeignWal real "meta"
  dbBefore <- BS.readFile real
  wBefore <- BS.readFile (real ++ "-wal")
  r <- check link cfgPath
  assertEqual "exit 1" 1 (ceCode r)
  assertEqual "no plan printed" "" (ceOut r)
  assertBool "tag" ("store-foreign-sidecar:" `isPrefixOf` ceErr r)
  BS.readFile real >>= \b -> assertBool "store untouched" (b == dbBefore)
  BS.readFile (real ++ "-wal") >>= \b -> assertBool "wal untouched" (b == wBefore)
  shmReal <- doesFileExist (real ++ "-shm")
  shmLink <- doesFileExist (link ++ "-shm")
  assertBool "no -shm at the real path" (not shmReal)
  assertBool "no -shm at the link name" (not shmLink)

-- A hot journal beside the real file is named as the journal
-- through a symlink, not reported as an unreadable store.
caseCheckSymlinkHotJournal :: IO ()
caseCheckSymlinkHotJournal = withScratch "ctl-check" $ \dir -> do
  (link, cfgPath, real) <- withSymlinkedFixture "v0.4.0.0" dir
  dbBefore <- BS.readFile real
  BS.writeFile (real ++ "-journal")
    (BS.pack [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7] <> BS.replicate 504 0)
  jBefore <- BS.readFile (real ++ "-journal")
  r <- check link cfgPath
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag names the journal" ("store-journal-present:" `isPrefixOf` ceErr r)
  BS.readFile (real ++ "-journal") >>= \b -> assertBool "journal untouched" (b == jBefore)
  BS.readFile real >>= \b -> assertBool "store untouched" (b == dbBefore)

caseHelpListsStoreCommands :: IO ()
caseHelpListsStoreCommands = do
  assertBool "check line" ("haskoki-ctl store check --path FILE --config FILE [--async-home]" `isInfixOf` ctlHelp)
  assertBool "flag explained" ("--async-home" `isInfixOf` ctlHelp)
  assertBool "migrate line"
    ("haskoki-ctl store migrate --path FILE --config FILE --backup-dir DIR [--async-home]" `isInfixOf` ctlHelp)

migrateCli :: FilePath -> FilePath -> FilePath -> IO CtlExit
migrateCli store cfg backups = runCtl ["store", "migrate", "--path", store, "--config", cfg, "--backup-dir", backups]

caseMigrateCliV04 :: IO ()
caseMigrateCliV04 = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  r <- migrateCli store cfgPath backups
  assertEqual "exit 0" 0 (ceCode r)
  assertBool "done" ("migrate-done" `elem` lines (ceOut r))
  assertBool "frozen" ("frozen-credentials: 0000000000000001" `elem` lines (ceOut r))
  assertBool "preserved" ("preserved-credentials: 0000000000000002" `elem` lines (ceOut r))
  assertEqual "quiet stderr" "" (ceErr r)
  c <- runCtl ["store", "check", "--path", store, "--config", cfgPath]
  assertEqual "check ok afterwards" 0 (ceCode c)

caseMigrateCliNotNeeded :: IO ()
caseMigrateCliNotNeeded = withScratch "ctl-migrate" $ \dir -> do
  let store = dir </> "store.sqlite"; backups = dir </> "backups"
  createDirectory backups
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  openReconciled store cfg >>= either (assertFailure . show) closeAcquired
  r <- migrateCli store cfgPath backups
  assertEqual "exit 0" 0 (ceCode r)
  assertBool "not needed" ("migrate-not-needed:" `isPrefixOf` ceOut r)
  listDirectory backups >>= assertEqual "no backup" []

caseMigrateCliRefusesDrift :: IO ()
caseMigrateCliRefusesDrift = withScratch "ctl-migrate" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  cfgPath <- writeStoreConfig (dir </> "d.toml") store ["haskoki-demo", "haskoki-ops-renamed"] fixtureSo fixtureUser
  before <- captureState store
  r <- migrateCli store cfgPath backups
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-identity-refused:" `isPrefixOf` ceErr r)
  assertUnchanged "refused migrate" before store
  listDirectory backups >>= assertEqual "no backup" []

caseMigrateCliLive :: IO ()
caseMigrateCliLive = withScratch "ctl-migrate" $ \dir -> do
  let store = dir </> "store.sqlite"; backups = dir </> "backups"
  createDirectory backups
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  e <- openSQLiteStore store
  s <- either (assertFailure . show) pure e
  lockBefore <- BS.readFile (store ++ ".lock")
  before <- captureState store
  r <- migrateCli store cfgPath backups
  BS.readFile (store ++ ".lock") >>= assertEqual "owner lock untouched" lockBefore
  c <- storeCommit s emptyDelta
  storeClose s
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-live:" `isPrefixOf` ceErr r)
  assertEqual "owner kept serving" Committed c
  assertUnchanged "refused migrate" before store
  listDirectory backups >>= assertEqual "no backup" []

caseMigrateCliJournal :: IO ()
caseMigrateCliJournal = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  dbBytes <- BS.readFile store
  BS.writeFile (store ++ "-journal") "interrupted"
  jBytes <- BS.readFile (store ++ "-journal")
  r <- migrateCli store cfgPath backups
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-journal-present:" `isPrefixOf` ceErr r)
  BS.readFile (store ++ "-journal") >>= \b -> assertBool "journal untouched" (b == jBytes)
  BS.readFile store >>= \b -> assertBool "store untouched" (b == dbBytes)
  listDirectory backups >>= assertEqual "no backup" []

-- A hot journal header (SQLite's magic) stays refused: only a cold
-- journal is ever cleared.
caseMigrateCliJournalHot :: IO ()
caseMigrateCliJournalHot = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  dbBytes <- BS.readFile store
  BS.writeFile (store ++ "-journal")
    (BS.pack [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7] <> BS.replicate 504 0)
  jBytes <- BS.readFile (store ++ "-journal")
  r <- migrateCli store cfgPath backups
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-journal-present:" `isPrefixOf` ceErr r)
  BS.readFile (store ++ "-journal") >>= \b -> assertBool "journal untouched" (b == jBytes)
  BS.readFile store >>= \b -> assertBool "store untouched" (b == dbBytes)
  listDirectory backups >>= assertEqual "no backup" []

-- The store is rollback-journal only, so a -wal file can only come
-- from foreign tooling: migration refuses it like a journal.
caseMigrateCliWal :: IO ()
caseMigrateCliWal = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  dbBytes <- BS.readFile store
  BS.writeFile (store ++ "-wal") "foreign write-ahead log"
  wBytes <- BS.readFile (store ++ "-wal")
  r <- migrateCli store cfgPath backups
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-foreign-sidecar:" `isPrefixOf` ceErr r)
  BS.readFile (store ++ "-wal") >>= \b -> assertBool "wal untouched" (b == wBytes)
  BS.readFile store >>= \b -> assertBool "store untouched" (b == dbBytes)
  listDirectory backups >>= assertEqual "no backup" []

-- Likewise for a -shm file.
caseMigrateCliShm :: IO ()
caseMigrateCliShm = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  dbBytes <- BS.readFile store
  BS.writeFile (store ++ "-shm") "foreign shared memory"
  sBytes <- BS.readFile (store ++ "-shm")
  r <- migrateCli store cfgPath backups
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-foreign-sidecar:" `isPrefixOf` ceErr r)
  BS.readFile (store ++ "-shm") >>= \b -> assertBool "shm untouched" (b == sBytes)
  BS.readFile store >>= \b -> assertBool "store untouched" (b == dbBytes)
  listDirectory backups >>= assertEqual "no backup" []

-- Migrating through a symlink must not merge a foreign WAL sitting
-- beside the real file: the run refuses, the file keeps its bytes
-- (a read-only query would see through the WAL, so the credential
-- check reads the file bytes: the original token-2 SO PIN stays and
-- the WAL's replacement never lands), and the WAL stays in place
-- for the operator.
caseMigrateSymlinkWal :: IO ()
caseMigrateSymlinkWal = withScratch "ctl-migrate" $ \dir -> do
  (link, cfgPath, real) <- withSymlinkedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
      originalSo = "NjkzMjQwNTc="    -- token 2's v0.4 SO PIN, base64
      foreignSo = "MTExMTExMTE="     -- the WAL's replacement value
  createDirectory backups
  plantForeignWal real "credential"
  dbBefore <- BS.readFile real
  wBefore <- BS.readFile (real ++ "-wal")
  assertBool "the WAL carries the replacement" (foreignSo `BS.isInfixOf` wBefore)
  assertBool "the file starts without it" (not (foreignSo `BS.isInfixOf` dbBefore))
  r <- migrateCli link cfgPath backups
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-foreign-sidecar:" `isPrefixOf` ceErr r)
  dbAfter <- BS.readFile real
  assertBool "store untouched" (dbAfter == dbBefore)
  assertBool "original credential still filed" (originalSo `BS.isInfixOf` dbAfter)
  assertBool "foreign credential never filed" (not (foreignSo `BS.isInfixOf` dbAfter))
  BS.readFile (real ++ "-wal") >>= \b -> assertBool "wal untouched" (b == wBefore)
  shmLeft <- doesFileExist (real ++ "-shm")
  assertBool "no -shm created" (not shmLeft)
  listDirectory backups >>= assertEqual "no backup" []

-- A bare symlink is a legitimate store path: check plans it and
-- migrate moves the real file, leaving no lock at either name.
caseMigrateSymlinkBare :: IO ()
caseMigrateSymlinkBare = withScratch "ctl-migrate" $ \dir -> do
  (link, cfgPath, real) <- withSymlinkedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  c <- check link cfgPath
  assertEqual "check exit 1" 1 (ceCode c)
  assertBool "plan" ("verdict: migration-required" `isInfixOf` ceOut c)
  r <- migrateCli link cfgPath backups
  assertEqual "migrate exit 0" 0 (ceCode r)
  assertBool "done" ("migrate-done" `elem` lines (ceOut r))
  roTexts real "SELECT value FROM store_meta WHERE key = 'schema_version'"
    >>= assertEqual "real file migrated" ["3"]
  lockLink <- doesFileExist (link ++ ".lock")
  lockReal <- doesFileExist (real ++ ".lock")
  assertBool "no lock at the link" (not lockLink)
  assertBool "no lock at the target" (not lockReal)

-- Every outcome after a clear reports it on stdout: here the
-- backup digest fails after the cold journal is gone, and the
-- failure output still carries the clearing line.
caseMigrateCliReportsClearOnFailure :: IO ()
caseMigrateCliReportsClearOnFailure = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  BS.writeFile (store ++ "-journal") (BS.replicate 512 0)
  let failing = noMigrateHooks { mhDigest = \_ -> pure (Left "SHA-256 engine unavailable: test") }
  (code, out, err) <- storeMigrateCommandWith failing
    ["--path", store, "--config", cfgPath, "--backup-dir", backups]
  assertEqual "exit 1" 1 code
  assertBool "tag" ("migrate-backup-failed:" `isPrefixOf` err)
  assertBool "clearing reported" ("cold-journal-removed: yes" `elem` lines out)
  gone <- not <$> doesFileExist (store ++ "-journal")
  assertBool "journal removed" gone

-- A backup that fails verification is removed, never left behind
-- for a later restore to trust: the hook swaps the just-created
-- file under the writer so the byte readback differs.
caseMigrateBadBackupRemoved :: IO ()
caseMigrateBadBackupRemoved = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  let swap = noMigrateHooks { mhAfterCreate = \p -> removeLink p >> BS.writeFile p "bogus" }
  (code, _, err) <- storeMigrateCommandWith swap
    ["--path", store, "--config", cfgPath, "--backup-dir", backups]
  assertEqual "exit 1" 1 code
  assertBool "tag" ("migrate-backup-failed:" `isPrefixOf` err)
  listDirectory backups >>= assertEqual "bad backup removed" []

-- A FIFO at the store path is refused by lstat, never opened: the
-- held writer only keeps a regression from hanging the suite (an
-- open would read its garbage instead of blocking).
caseCheckFifoStore :: IO ()
caseCheckFifoStore = withScratch "ctl-check" $ \dir -> do
  let store = dir </> "store.sqlite"
  createNamedPipe store 0o600
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  withFifoWriter store "not a database file, only pipe garbage" $ do
    r <- check store cfgPath
    assertEqual "exit 1" 1 (ceCode r)
    assertEqual "no plan printed" "" (ceOut r)
    assertBool "tag" ("store-unreadable:" `isPrefixOf` ceErr r)
    assertBool "names non-regular" ("not a regular file" `isInfixOf` ceErr r)

-- Likewise for migrate: no backup, nothing written beside the FIFO.
caseMigrateFifoStore :: IO ()
caseMigrateFifoStore = withScratch "ctl-migrate" $ \dir -> do
  let store = dir </> "store.sqlite"; backups = dir </> "backups"
  createNamedPipe store 0o600
  createDirectory backups
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  withFifoWriter store "not a database file, only pipe garbage" $ do
    r <- migrateCli store cfgPath backups
    assertEqual "exit 1" 1 (ceCode r)
    assertBool "tag" ("store-unreadable:" `isPrefixOf` ceErr r)
    assertBool "names non-regular" ("not a regular file" `isInfixOf` ceErr r)
    listDirectory backups >>= assertEqual "no backup" []

-- A FIFO at the lock path is refused by lstat: the writer offers a
-- dead pid, which an open would accept and plan from.
caseCheckFifoLock :: IO ()
caseCheckFifoLock = withScratch "ctl-check" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  createNamedPipe (store ++ ".lock") 0o600
  withFifoWriter (store ++ ".lock") "999999999\n" $ do
    r <- check store cfgPath
    assertEqual "exit 1" 1 (ceCode r)
    assertEqual "no plan printed" "" (ceOut r)
    assertBool "tag" ("store-live:" `isPrefixOf` ceErr r)
    assertBool "names non-regular" ("not a regular file" `isInfixOf` ceErr r)

-- A symlink at the lock path is refused, never followed: the link
-- target offers pid 1 (alive), which a follow would report as the
-- holder instead.
caseCheckSymlinkLock :: IO ()
caseCheckSymlinkLock = withScratch "ctl-check" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let fifo = dir </> "target.fifo"
  createNamedPipe fifo 0o600
  createSymbolicLink fifo (store ++ ".lock")
  withFifoWriter fifo "1\n" $ do
    r <- check store cfgPath
    assertEqual "exit 1" 1 (ceCode r)
    assertEqual "no plan printed" "" (ceOut r)
    assertBool "tag" ("store-live:" `isPrefixOf` ceErr r)
    assertBool "names non-regular" ("not a regular file" `isInfixOf` ceErr r)

-- A lock far beyond a pid line, without one, reads as unreadable:
-- the read is capped and the pid line must be complete.
caseCheckOversizedLock :: IO ()
caseCheckOversizedLock = withScratch "ctl-check" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  BS.writeFile (store ++ ".lock") (BS.replicate 4096 0x78)
  r <- check store cfgPath
  assertEqual "exit 1" 1 (ceCode r)
  assertEqual "no plan printed" "" (ceOut r)
  assertBool "tag" ("store-live:" `isPrefixOf` ceErr r)
  assertBool "unreadable" ("unreadable" `isInfixOf` ceErr r)

-- A cold journal must not bypass the -wal refusal: check names the
-- -wal (not the cold journal) and migrate refuses with every byte
-- untouched, before any SQLite connection opens.
caseMigrateCliColdWal :: IO ()
caseMigrateCliColdWal = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"; journal = store ++ "-journal"; wal = store ++ "-wal"
  createDirectory backups
  dbBefore <- BS.readFile store
  BS.writeFile journal (BS.replicate 512 0)
  BS.writeFile wal "foreign write-ahead log"
  jBefore <- BS.readFile journal
  wBefore <- BS.readFile wal
  c <- runCtl ["store", "check", "--path", store, "--config", cfgPath]
  assertEqual "check refuses" 1 (ceCode c)
  assertBool "check names the wal" ("store-foreign-sidecar:" `isPrefixOf` ceErr c)
  assertBool "check does not report cold" (not ("store-journal-cold:" `isPrefixOf` ceErr c))
  m <- migrateCli store cfgPath backups
  assertEqual "migrate refuses" 1 (ceCode m)
  assertBool "migrate names the wal" ("store-foreign-sidecar:" `isPrefixOf` ceErr m)
  BS.readFile store >>= \b -> assertBool "store untouched" (b == dbBefore)
  BS.readFile journal >>= \b -> assertBool "journal untouched" (b == jBefore)
  BS.readFile wal >>= \b -> assertBool "wal untouched" (b == wBefore)
  listDirectory backups >>= assertEqual "no backup" []
  shmLeft <- doesFileExist (store ++ "-shm")
  assertBool "no -shm created" (not shmLeft)

-- A current store with a cold journal is openable: the check
-- exits 0 with the harmless-journal line (the serving open takes
-- the store and the next write reuses the file), while migrate
-- still needs nothing and leaves the journal untouched.
caseMigrateCliSchema3Cold :: IO ()
caseMigrateCliSchema3Cold = withScratch "ctl-migrate" $ \dir -> do
  let store = dir </> "store.sqlite"; backups = dir </> "backups"; journal = store ++ "-journal"
  createDirectory backups
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  openReconciled store cfg >>= either (assertFailure . show) closeAcquired
  dbBefore <- BS.readFile store
  BS.writeFile journal (BS.replicate 512 0)
  jBefore <- BS.readFile journal
  c <- runCtl ["store", "check", "--path", store, "--config", cfgPath]
  assertEqual "check accepts the cold journal on a current store" 0 (ceCode c)
  assertBool "verdict ok" ("verdict: ok" `isInfixOf` ceOut c)
  assertBool "journal line" ("journal: cold (harmless; reused by the next write)" `elem` lines (ceOut c))
  assertEqual "quiet stderr" "" (ceErr c)
  m <- migrateCli store cfgPath backups
  assertEqual "migrate needs nothing" 0 (ceCode m)
  assertBool "not needed" ("migrate-not-needed:" `isPrefixOf` ceOut m)
  BS.readFile journal >>= \b -> assertBool "journal untouched" (b == jBefore)
  BS.readFile store >>= \b -> assertBool "store untouched" (b == dbBefore)
  listDirectory backups >>= assertEqual "no backup" []

-- A journal that is not a regular file (a symlink, FIFO or device)
-- is refused without opening it: opening would hang on a FIFO or
-- misclassify a device. Each FIFO probe holds a writer first, so a
-- regression that opens the journal reads zeros (cold, the wrong
-- refusal) and fails instead of hanging the suite; the timeout is
-- only a backstop. A device read is interruptible, so the /dev/zero
-- probe keeps the timeout alone.
caseCheckNonRegularJournal :: IO ()
caseCheckNonRegularJournal = withScratch "ctl-check" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let journal = store ++ "-journal"
      runCheck = runCtl ["store", "check", "--path", store, "--config", cfgPath]
      zeros = BS.replicate 512 0
  let fifo = dir </> "fifo"
  createNamedPipe fifo 0o600
  createSymbolicLink fifo journal
  mc <- withFifoWriter fifo zeros (timeout 5000000 runCheck)
  case mc of
    Nothing -> assertFailure "check hung on a symlinked FIFO journal"
    Just c -> do
      assertEqual "symlink FIFO: exit 1" 1 (ceCode c)
      assertBool "symlink FIFO: refused as present, not cold"
        ("store-journal-present:" `isPrefixOf` ceErr c)
  removeFile journal
  createNamedPipe journal 0o600
  mf <- withFifoWriter journal zeros (timeout 5000000 runCheck)
  case mf of
    Nothing -> assertFailure "check hung on a FIFO journal"
    Just f -> do
      assertEqual "FIFO: exit 1" 1 (ceCode f)
      assertBool "FIFO: refused" ("store-journal-present:" `isPrefixOf` ceErr f)
  removeFile journal
  createSymbolicLink "/dev/zero" journal
  mz <- timeout 5000000 runCheck
  case mz of
    Nothing -> assertFailure "check hung on a symlinked device journal"
    Just z -> do
      assertEqual "device symlink: exit 1" 1 (ceCode z)
      assertBool "device symlink: refused as present, not cold"
        ("store-journal-present:" `isPrefixOf` ceErr z)
  stillThere <- doesFileExist journal
  assertBool "the symlink was not unlinked" stillThere

-- --async-home is only a standalone switch: where a flag value is
-- expected it is a usage error, never silently the switch and never
-- the value.
caseMigrateCliAsyncHomeValue :: IO ()
caseMigrateCliAsyncHomeValue = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  before <- captureState store
  r <- runCtl ["store", "migrate", "--path", store, "--config", "--async-home", cfgPath, "--backup-dir", backups]
  assertEqual "exit 2" 2 (ceCode r)
  assertBool "usage on stderr"
    ("usage: haskoki-ctl store migrate --path FILE --config FILE --backup-dir DIR [--async-home]" `isInfixOf` ceErr r)
  assertEqual "nothing on stdout" "" (ceOut r)
  assertUnchanged "usage error" before store
  listDirectory backups >>= assertEqual "no backup" []

-- A missing backup directory is refused through migrate with nothing
-- written anywhere.
caseMigrateCliMissingBackupDir :: IO ()
caseMigrateCliMissingBackupDir = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups" -- never created
  before <- captureState store
  r <- migrateCli store cfgPath backups
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("migrate-unsafe-backup-dir:" `isPrefixOf` ceErr r)
  assertUnchanged "refused migrate" before store
  created <- doesFileExist backups
  assertBool "backup dir not created" (not created)

-- An unwritable backup directory is refused through migrate with
-- nothing written.
caseMigrateCliUnwritableBackupDir :: IO ()
caseMigrateCliUnwritableBackupDir = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  before <- captureState store
  euid <- getEffectiveUserID
  if euid == 0
    then putStrLn "skipped the unwritable backup dir: mode 0555 does not deny root"
    else withFileMode backups 0o555 $ do
      r <- migrateCli store cfgPath backups
      assertEqual "exit 1" 1 (ceCode r)
      assertBool "tag" ("migrate-unsafe-backup-dir:" `isPrefixOf` ceErr r)
  assertUnchanged "refused migrate" before store
  listDirectory backups >>= assertEqual "no backup" []

-- A config that names another store, or one that does not parse, is
-- refused through migrate with nothing written.
caseMigrateCliWrongConfig :: IO ()
caseMigrateCliWrongConfig = withScratch "ctl-migrate" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  other <- writeStoreConfig (dir </> "o.toml") (dir </> "original.sqlite") fixtureLabels fixtureSo fixtureUser
  writeFile (dir </> "broken.toml") "[tokens]\nso_pins = [\"58213946\"\nlabels = 7\n"
  before <- captureState store
  m <- migrateCli store other backups
  assertEqual "mismatch: exit 1" 1 (ceCode m)
  assertBool "mismatch: tag" ("config-mismatch:" `isPrefixOf` ceErr m)
  b <- migrateCli store (dir </> "broken.toml") backups
  assertEqual "broken: exit 1" 1 (ceCode b)
  assertBool "broken: tag" ("config-invalid:" `isPrefixOf` ceErr b)
  assertNoPins "wrong config" (ceOut m ++ ceErr m ++ ceOut b ++ ceErr b)
  assertUnchanged "refused migrate" before store
  listDirectory backups >>= assertEqual "no backup" []

-- A v0.4-shape store the async open created (home label, no
-- credential row) refuses under the standard catalog and migrates
-- under --async-home, freezing the async home PINs (not the
-- config's); the async open then serves the migrated store.
caseMigrateCliAsyncHome :: IO ()
caseMigrateCliAsyncHome = withScratch "ctl-migrate" $ \dir -> do
  let store = dir </> "async2.sqlite"; backups = dir </> "backups"
      (label, so, user) = asyncHomeEntry
  createDirectory backups
  makeSchemaStore 2 store [fixtureToken 1 0 label] []
  cfgPath <- writeStoreConfig (dir </> "c.toml") store ["haskoki-demo"] ["58213946"] ["12873465"]
  before <- captureState store
  plain <- migrateCli store cfgPath backups
  assertEqual "no flag: exit 1" 1 (ceCode plain)
  assertBool "no flag: identity refusal" ("store-identity-refused:" `isPrefixOf` ceErr plain)
  assertUnchanged "refused migrate" before store
  listDirectory backups >>= assertEqual "no backup" []
  r <- runCtl ["store", "migrate", "--async-home", "--path", store, "--config", cfgPath, "--backup-dir", backups]
  assertEqual "flag: exit 0" 0 (ceCode r)
  assertBool "done" ("migrate-done" `elem` lines (ceOut r))
  assertBool "frozen" ("frozen-credentials: 0000000000000001" `elem` lines (ceOut r))
  assertBool "preserved" ("preserved-credentials: none" `elem` lines (ceOut r))
  assertEqual "quiet stderr" "" (ceErr r)
  e <- openSQLiteStore store
  s <- either (assertFailure . show) pure e
  creds <- storeLoadCredentials s
  storeClose s
  assertEqual "async home PINs frozen"
    (Right [CredentialRecord (TokenId 1) (BC8.pack so) (Just (BC8.pack user))]) creds
  box <- withCString store haskokiAsyncStoreOpen
  assertBool "async open serves the migrated store" (castStablePtrToPtr box /= nullPtr)
  alloca $ \slot -> poke slot box >> haskokiAsyncStoreClose slot
  c <- runCtl ["store", "check", "--path", store, "--config", cfgPath, "--async-home"]
  assertEqual "check ok afterwards" 0 (ceCode c)
  mapM_ (assertNoPins "async migrate")
    [ceOut plain ++ ceErr plain, ceOut r ++ ceErr r, ceOut c ++ ceErr c]

caseMigrateCliUsage :: IO ()
caseMigrateCliUsage = mapM_ one
  [ ["store", "migrate", "--path", "a", "--config", "b"]
  , ["store", "migrate", "--path", "a", "--config", "b", "--backup-dir"]
  , ["store", "migrate", "--path", "a", "--config", "b", "--backup-dir", "c", "--force"]
  , ["store", "migrate", "--path", "a", "--config", "b", "--backup-dir", "c", "--async-home", "--async-home"]
  ]
  where
    one args = do
      r <- runCtl args
      assertEqual (unwords args) 2 (ceCode r)
      assertBool (unwords args ++ ": store-migrate usage on stderr")
        ("store migrate: " `isPrefixOf` ceErr r || "usage: haskoki-ctl store migrate " `isPrefixOf` ceErr r)
      assertBool (unwords args ++ ": usage text names the command")
        ("usage: haskoki-ctl store migrate --path FILE --config FILE --backup-dir DIR [--async-home]" `isInfixOf` ceErr r)
      assertEqual (unwords args ++ ": nothing on stdout") "" (ceOut r)

caseMigrateCliNoPins :: IO ()
caseMigrateCliNoPins = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  drift <- writeStoreConfig (dir </> "d.toml") store ["haskoki-demo", "haskoki-ops-renamed"] fixtureSo fixtureUser
  r1 <- migrateCli store drift backups
  r2 <- migrateCli store cfgPath backups
  r3 <- migrateCli store cfgPath backups
  receipts <- filter (".receipt" `isSuffixOf`) <$> listDirectory backups
  texts <- mapM (readFile . (backups </>)) receipts
  assertEqual "r1 refused" 1 (ceCode r1)
  assertEqual "r2 migrated" 0 (ceCode r2)
  assertEqual "r3 not needed" 0 (ceCode r3)
  assertBool "a receipt was written" (not (null receipts))
  mapM_ (\r -> assertNoPins "migrate output" (ceOut r ++ ceErr r)) [r1, r2, r3]
  mapM_ (assertNoPins "receipt") texts

-- An unexpected exception through migrate prints a fixed tagged line
-- with the exception type only: no raw message text ever reaches
-- operator output, so no PIN of any shape can survive.
caseMigrateUnexpectedRedacted :: IO ()
caseMigrateUnexpectedRedacted = do
  let (tag, detail) = renderUnexpectedFailure (toException (userError "boom 58213946"))
  assertEqual "tag" "migrate-unexpected" tag
  assertBool "fixed shape" ("unexpected failure: " `isPrefixOf` detail)
  assertBool "names the exception type" ("IOException" `isInfixOf` detail)
  assertBool "no raw message" (not ("boom" `isInfixOf` detail))
  assertBool "no PIN" (not ("58213946" `isInfixOf` detail))
  assertBool "names the next step" ("run store check before anything else" `isInfixOf` detail)
  assertBool "single line" (not ('\n' `elem` detail))
  assertNoPins "unexpected failure" (tag ++ ": " ++ detail)
  let (_, alpha) = renderUnexpectedFailure (toException (userError "auth ab12CD34"))
  assertBool "no alphanumeric message" (not ("ab12CD34" `isInfixOf` alpha))
  assertNoPins "alphanumeric failure" alpha
  let (_, store) = renderUnexpectedFailure (toException (StoreIO "disk 58213946"))
  assertBool "store type" ("StoreError" `isInfixOf` store)
  assertBool "no store message" (not ("disk" `isInfixOf` store))
  assertNoPins "store failure" store

-- An unexpected exception through check prints a fixed tagged line
-- with the exception type only, never the raw message.
caseCheckUnexpectedTagged :: IO ()
caseCheckUnexpectedTagged = do
  let (tag, detail) = renderCheckUnexpectedFailure (toException (userError "boom 58213946"))
  assertEqual "tag" "store-unreadable" tag
  assertBool "fixed shape" ("unexpected failure: " `isPrefixOf` detail)
  assertBool "names the exception type" ("IOException" `isInfixOf` detail)
  assertBool "no raw message" (not ("boom" `isInfixOf` detail))
  assertBool "no PIN" (not ("58213946" `isInfixOf` detail))
  assertBool "single line" (not ('\n' `elem` detail))
  assertNoPins "unexpected check failure" (tag ++ ": " ++ detail)
  let (_, alpha) = renderCheckUnexpectedFailure (toException (userError "auth ab12CD34"))
  assertBool "no alphanumeric message" (not ("ab12CD34" `isInfixOf` alpha))

-- A true async interrupt during migrate is exit 130 with the fixed
-- interrupted line: never migrate-failed, which means "rolled back;
-- the store was not changed". The hook only synchronises: a second
-- thread throws, so the exception arrives the way SIGINT delivers
-- it (a 'throwIO' would be a synchronous raise, not an interrupt).
caseMigrateInterrupt130 :: IO ()
caseMigrateInterrupt130 = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  me <- myThreadId
  fired <- newEmptyMVar
  _ <- forkIO (takeMVar fired >> throwTo me UserInterrupt)
  let interrupted = noMigrateHooks { mhAfterPlan = putMVar fired () }
  (code, _, err) <- storeMigrateCommandWith interrupted
    ["--path", store, "--config", cfgPath, "--backup-dir", backups]
  assertEqual "exit 130" 130 code
  assertEqual "interrupted line"
    "migrate-interrupted: store state unknown; run store check\n" err

-- A synchronous failure the plan did not foresee keeps a tag of its
-- own: migrate-failed is reserved for a rolled-back transaction.
caseMigrateSyncFailureDistinctTag :: IO ()
caseMigrateSyncFailureDistinctTag = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  let failing = noMigrateHooks { mhAfterPlan = throwIO (userError "boom") }
  (code, _, err) <- storeMigrateCommandWith failing
    ["--path", store, "--config", cfgPath, "--backup-dir", backups]
  assertEqual "exit 1" 1 code
  assertBool "distinct tag" ("migrate-unexpected:" `isPrefixOf` err)
  assertBool "not migrate-failed" (not ("migrate-failed:" `isPrefixOf` err))

-- An unknown COMMIT outcome reaches the operator under its own
-- tag: the store may already be at schema 3, so the rolled-back
-- tag (which promises the store was not changed) must not appear.
caseMigrateCommitUnknownTag :: IO ()
caseMigrateCommitUnknownTag = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.3.1.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  let commitEarly = noMigrateHooks
        { mhSQLite = noMigrationHooks { mgBeforeCommit = \db -> S.exec db "COMMIT" } }
  (code, _, err) <- storeMigrateCommandWith commitEarly
    ["--path", store, "--config", cfgPath, "--backup-dir", backups]
  assertEqual "exit 1" 1 code
  assertBool "distinct unknown-outcome tag" ("migrate-commit-unknown:" `isPrefixOf` err)
  assertBool "no unchanged claim" (not ("was not changed" `isInfixOf` err))
  assertBool "says COMMIT failed" ("COMMIT failed" `isInfixOf` err)
  assertBool "says outcome unknown" ("outcome is unknown" `isInfixOf` err)
  assertBool "backup kept" ("Backup kept at" `isInfixOf` err)

-- An async exception that is not an interrupt propagates out of the
-- migrate command instead of being reported as a store outcome. The
-- kill arrives from a second thread, the way 'killThread' delivers
-- it (a 'throwIO' would be a synchronous raise).
caseMigrateAsyncRethrown :: IO ()
caseMigrateAsyncRethrown = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  me <- myThreadId
  fired <- newEmptyMVar
  proceed <- newEmptyMVar
  _ <- forkIO (takeMVar fired >> throwTo me ThreadKilled)
  -- The hook parks the migrate after the plan until the killer's
  -- throw lands: the kill is delivered while the migrate is
  -- provably in flight (no timing margin), and the parked hook
  -- cannot complete first, so the outcome is always 'Left'. The
  -- park carries an explicit 30 s backstop (a safety net, not a
  -- tuning knob): a lost kill fails loudly here instead of
  -- relying on RTS deadlock detection.
  let killing = noMigrateHooks
        { mhAfterPlan = putMVar fired () >> do
            mR <- timeout 30000000 (takeMVar proceed)
            case mR of
              Nothing -> assertFailure "migrate killer never delivered ThreadKilled"
              Just () -> pure ()
        }
  r <- try (storeMigrateCommandWith killing
    ["--path", store, "--config", cfgPath, "--backup-dir", backups])
    :: IO (Either AsyncException (Int, String, String))
  case r of
    Left ThreadKilled -> pure ()
    Left other -> assertFailure ("wrong async exception: " ++ show other)
    Right outcome -> assertFailure ("swallowed ThreadKilled: " ++ show outcome)

-- An interrupt during check is exit 130 with the fixed interrupted
-- line: never store-unreadable. The worker runs the command back to
-- back while the parent pounds it with interrupts; a throw that
-- lands between runs is retried, and only the command's own handler
-- can produce the 130, so the first 130 proves the wiring. (A
-- queued-then-unmasked interrupt cannot work instead: GHC raises
-- pending exceptions at the unmask point, before any inner handler
-- installs.)
caseCheckInterrupt130 :: IO ()
caseCheckInterrupt130 = withScratch "ctl-check" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  ready <- newEmptyMVar
  resVar <- newEmptyMVar
  let args = ["--path", store, "--config", cfgPath]
      loop = do
        r <- (Right <$> storeCheckCommand args) `catch` \e -> case e :: AsyncException of
          UserInterrupt -> pure (Left ())
          _ -> throwIO e
        case r of
          Right triple@(130, _, _) -> putMVar resVar triple
          _ -> loop
  tid <- forkIO (putMVar ready () >> loop)
  takeMVar ready
  mR <- timeout 10000000 $ do
    let pound = do
          done <- not <$> isEmptyMVar resVar
          unless done $ throwTo tid UserInterrupt >> threadDelay 500 >> pound
    pound
    takeMVar resVar
  case mR of
    Nothing -> assertFailure "check worker never reported an interrupt"
    Just (code, _, err) -> do
      assertEqual "exit 130" 130 code
      assertEqual "interrupted line"
        "check-interrupted: no verdict; rerun store check\n" err

-- | The @--rel-child@ body: run one store operation with a relative
-- path from THIS process's working directory (the parent spawns us
-- with @cwd@ set, so no test ever changes the suite's own
-- directory) and report the outcome to a result file as a 'show'n
-- tuple the parent reads back. @mode@ is @check@, @migrate@ or
-- @open@; @backups@ is used only by @migrate@.
relChildMain :: String -> FilePath -> FilePath -> FilePath -> FilePath -> IO ()
relChildMain mode relpath cfgPath backups result = do
  body <- case mode of
    "check" -> do
      CtlExit code out err <- runCtl ["store", "check", "--path", relpath, "--config", cfgPath]
      pure (show (code, out, err))
    "migrate" -> do
      CtlExit code out err <-
        runCtl ["store", "migrate", "--path", relpath, "--config", cfgPath, "--backup-dir", backups]
      pure (show (code, out, err))
    "open" -> show <$> openRelStore cfgPath
    _ -> pure (show (False, "unknown rel-child mode: " ++ mode))
  writeFile result body

-- | The serving open of the config's own storage path (the same
-- 'openStdStore' the instance open threads), closed at once.
openRelStore :: FilePath -> IO (Bool, String)
openRelStore cfgPath = do
  cfg <- loadConfigOrFail cfgPath
  env <- newEnv (rulesFromConfig cfg)
  eSt <- openStdStore env cfg
  case eSt of
    Left err -> pure (False, show err)
    Right mSt -> closeAcquired mSt >> pure (True, "opened")

-- | Spawn this test binary as a @--rel-child@ with its working
-- directory set to @workdir@. Bounded: a wedged child is killed at
-- 30s and fails loudly instead of hanging the suite.
runRelChild :: FilePath -> [String] -> IO ()
runRelChild workdir args = do
  exe <- getExecutablePath
  (_, _, _, ph) <- createProcess ((proc exe ("--rel-child" : args)) { cwd = Just workdir, close_fds = True })
  mCode <- timeout 30000000 (waitForProcess ph)
  case mCode of
    Nothing -> do
      terminateProcess ph
      _ <- waitForProcess ph
      assertFailure "rel child timed out after 30s"
    Just code -> assertEqual "rel child exit" ExitSuccess code

-- | Read back a @--rel-child@ result file (a 'show'n tuple).
readRelChild :: Read a => FilePath -> IO a
readRelChild result = do
  body <- readFile result
  case reads body of
    [(v, "")] -> pure v
    _ -> assertFailure ("unparseable rel-child result: " ++ body)

-- A relative --path through an absolute symlink resolves to the
-- absolute target: the mangling that drops the leading slash
-- reports the target as missing instead of planning it.
caseCheckRelativeThroughAbsoluteLink :: IO ()
caseCheckRelativeThroughAbsoluteLink = withScratch "ctl-rel" $ \dir -> do
  let realDir = dir </> "real"; workdir = dir </> "cwd"; result = dir </> "result.txt"
  createDirectory realDir
  (realStore, _) <- copyReleasedFixture "v0.4.0.0" realDir
  createDirectory workdir
  createSymbolicLink realStore (workdir </> "store.sqlite")
  cfgPath <- writeStoreConfig (dir </> "config.toml") "store.sqlite" fixtureLabels fixtureSo fixtureUser
  dbBefore <- BS.readFile realStore
  runRelChild workdir ["check", "store.sqlite", cfgPath, "-", result]
  (code, out, err) <- readRelChild result :: IO (Int, String, String)
  assertEqual "exit 1" 1 code
  assertBool "plan names migration" ("verdict: migration-required" `isInfixOf` out)
  assertBool "tag" ("store-migration-required:" `isPrefixOf` err)
  BS.readFile realStore >>= \b -> assertBool "store untouched" (b == dbBefore)

-- A relative path with dotdot after an absolute symlink still
-- resolves against the absolute target, not against the mangled
-- relative spelling.
caseCheckRelativeDotDotThroughAbsoluteLink :: IO ()
caseCheckRelativeDotDotThroughAbsoluteLink = withScratch "ctl-rel" $ \dir -> do
  let workdir = dir </> "cwd"; realDir = workdir </> "realdir"; result = dir </> "result.txt"
      relpath = "./pd/../pd/store.sqlite"
  createDirectory workdir
  createDirectory realDir
  (realStore, _) <- copyReleasedFixture "v0.4.0.0" realDir
  createSymbolicLink realDir (workdir </> "pd")
  cfgPath <- writeStoreConfig (dir </> "config.toml") relpath fixtureLabels fixtureSo fixtureUser
  dbBefore <- BS.readFile realStore
  runRelChild workdir ["check", relpath, cfgPath, "-", result]
  (code, out, err) <- readRelChild result :: IO (Int, String, String)
  assertEqual "exit 1" 1 code
  assertBool "plan names migration" ("verdict: migration-required" `isInfixOf` out)
  assertBool "tag" ("store-migration-required:" `isPrefixOf` err)
  BS.readFile realStore >>= \b -> assertBool "store untouched" (b == dbBefore)

-- A relative --path through an absolute symlink migrates the real
-- file: the receipt names the absolute target.
caseMigrateRelativeThroughAbsoluteLink :: IO ()
caseMigrateRelativeThroughAbsoluteLink = withScratch "ctl-rel" $ \dir -> do
  let realDir = dir </> "real"; workdir = dir </> "cwd"; backups = dir </> "backups"
      result = dir </> "result.txt"
  createDirectory realDir
  (realStore, _) <- copyReleasedFixture "v0.4.0.0" realDir
  createDirectory workdir
  createDirectory backups
  createSymbolicLink realStore (workdir </> "store.sqlite")
  cfgPath <- writeStoreConfig (dir </> "config.toml") "store.sqlite" fixtureLabels fixtureSo fixtureUser
  runRelChild workdir ["migrate", "store.sqlite", cfgPath, backups, result]
  (code, out, err) <- readRelChild result :: IO (Int, String, String)
  assertEqual "exit 0" 0 code
  assertEqual "quiet stderr" "" err
  assertBool "done" ("migrate-done" `elem` lines out)
  assertBool "receipt names the target" (("store: " ++ realStore) `elem` lines out)
  roTexts realStore "SELECT value FROM store_meta WHERE key = 'schema_version'"
    >>= assertEqual "real file migrated" ["3"]

-- The serving open with a relative storage.path through an absolute
-- symlink serves the target: the mangled spelling refuses a config
-- the release serves.
caseOpenRelativeThroughAbsoluteLink :: IO ()
caseOpenRelativeThroughAbsoluteLink = withScratch "ctl-rel" $ \dir -> do
  let realDir = dir </> "real"; workdir = dir </> "cwd"; result = dir </> "result.txt"
      realStore = realDir </> "store.sqlite"
  createDirectory realDir
  seedCfg <- writeStoreConfig (dir </> "seed.toml") realStore fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail seedCfg
  openReconciled realStore cfg >>= either (assertFailure . show) closeAcquired
  createDirectory workdir
  createSymbolicLink realStore (workdir </> "store.sqlite")
  relCfg <- writeStoreConfig (dir </> "config.toml") "store.sqlite" fixtureLabels fixtureSo fixtureUser
  dbBefore <- BS.readFile realStore
  runRelChild workdir ["open", "-", relCfg, "-", result]
  (ok, note) <- readRelChild result :: IO (Bool, String)
  assertBool ("serving open refused: " ++ note) ok
  BS.readFile realStore >>= \b -> assertBool "store untouched" (b == dbBefore)

-- The worst case: the mangled relative directory exists under the
-- working directory. The serving open must still serve the real
-- store, never create or serve a store at the mangled path.
caseOpenRelativeThroughAbsoluteLinkMirror :: IO ()
caseOpenRelativeThroughAbsoluteLinkMirror = withScratch "ctl-rel" $ \dir -> do
  let realDir = dir </> "real"; workdir = dir </> "cwd"; result = dir </> "result.txt"
      mirrorBase = workdir </> dropWhile (== '/') realDir
      realStore = realDir </> "store.sqlite"
  createDirectory realDir
  seedCfg <- writeStoreConfig (dir </> "seed.toml") realStore fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail seedCfg
  openReconciled realStore cfg >>= either (assertFailure . show) closeAcquired
  createDirectory workdir
  createSymbolicLink realStore (workdir </> "store.sqlite")
  createDirectoryIfMissing True mirrorBase
  relCfg <- writeStoreConfig (dir </> "config.toml") "store.sqlite" fixtureLabels fixtureSo fixtureUser
  runRelChild workdir ["open", "-", relCfg, "-", result]
  (ok, note) <- readRelChild result :: IO (Bool, String)
  assertBool ("serving open refused: " ++ note) ok
  mirrorLeft <- doesFileExist (mirrorBase </> "store.sqlite")
  assertBool "no store created at the mangled path" (not mirrorLeft)
  roTexts realStore "SELECT value FROM store_meta WHERE key = 'schema_version'"
    >>= assertEqual "real store still served" ["3"]

-- A dangling store symlink refuses as missing: the error names the
-- resolved target, and nothing is created there.
caseCheckDanglingLink :: IO ()
caseCheckDanglingLink = withScratch "ctl-dangling" $ \dir -> do
  let realDir = dir </> "real"; target = realDir </> "store.sqlite"; link = dir </> "link.sqlite"
  createDirectory realDir
  createSymbolicLink target link
  cfgPath <- writeStoreConfig (dir </> "c.toml") link fixtureLabels fixtureSo fixtureUser
  r <- check link cfgPath
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-missing:" `isPrefixOf` ceErr r)
  assertBool "names the resolved target" (("no store file at " ++ target) `isInfixOf` ceErr r)
  targetLeft <- doesFileExist target
  lockLeft <- doesFileExist (target ++ ".lock")
  assertBool "nothing created at the target" (not targetLeft)
  assertBool "no lock at the target" (not lockLeft)

-- A dangling store symlink refuses before ownership: no backup, no
-- lock, nothing at the target.
caseMigrateDanglingLink :: IO ()
caseMigrateDanglingLink = withScratch "ctl-dangling" $ \dir -> do
  let realDir = dir </> "real"; target = realDir </> "store.sqlite"; link = dir </> "link.sqlite"
      backups = dir </> "backups"
  createDirectory realDir
  createDirectory backups
  createSymbolicLink target link
  cfgPath <- writeStoreConfig (dir </> "c.toml") link fixtureLabels fixtureSo fixtureUser
  r <- migrateCli link cfgPath backups
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-unreadable:" `isPrefixOf` ceErr r)
  assertBool "names the missing target" (("no store file at " ++ target) `isInfixOf` ceErr r)
  targetLeft <- doesFileExist target
  lockLeft <- doesFileExist (target ++ ".lock")
  assertBool "nothing created at the target" (not targetLeft)
  assertBool "no lock at the target" (not lockLeft)
  listDirectory backups >>= assertEqual "no backup" []

-- The serving open never creates a store at a link target: a
-- dangling symlink refuses, leaving the target absent.
caseOpenDanglingLink :: IO ()
caseOpenDanglingLink = withScratch "ctl-dangling" $ \dir -> do
  let realDir = dir </> "real"; target = realDir </> "store.sqlite"; link = dir </> "link.sqlite"
  createDirectory realDir
  createSymbolicLink target link
  cfgPath <- writeStoreConfig (dir </> "c.toml") link fixtureLabels fixtureSo fixtureUser
  (ok, note) <- openRelStore cfgPath
  assertBool ("serving open must refuse a dangling link, but opened: " ++ note) (not ok)
  targetLeft <- doesFileExist target
  lockLeft <- doesFileExist (target ++ ".lock")
  assertBool "nothing created at the target" (not targetLeft)
  assertBool "no lock at the target" (not lockLeft)

-- A missing store under a symlinked parent directory is a missing
-- store, not a dangling link: check reports it at the resolved path
-- and creates nothing.
caseCheckMissingUnderSymlinkedDir :: IO ()
caseCheckMissingUnderSymlinkedDir = withScratch "ctl-symdir" $ \dir -> do
  let realDir = dir </> "realdir"; via = dir </> "pd"
      target = realDir </> "store.sqlite"; path = via </> "store.sqlite"
  createDirectory realDir
  createSymbolicLink realDir via
  cfgPath <- writeStoreConfig (dir </> "c.toml") path fixtureLabels fixtureSo fixtureUser
  r <- check path cfgPath
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-missing:" `isPrefixOf` ceErr r)
  assertBool "names the resolved target" (("no store file at " ++ target) `isInfixOf` ceErr r)
  targetLeft <- doesFileExist target
  lockLeft <- doesFileExist (target ++ ".lock")
  assertBool "nothing created at the target" (not targetLeft)
  assertBool "no lock at the target" (not lockLeft)

-- A missing store under a symlinked parent directory refuses the
-- migration before ownership: no backup, no lock, nothing created.
caseMigrateMissingUnderSymlinkedDir :: IO ()
caseMigrateMissingUnderSymlinkedDir = withScratch "ctl-symdir" $ \dir -> do
  let realDir = dir </> "realdir"; via = dir </> "pd"
      target = realDir </> "store.sqlite"; path = via </> "store.sqlite"
      backups = dir </> "backups"
  createDirectory realDir
  createDirectory backups
  createSymbolicLink realDir via
  cfgPath <- writeStoreConfig (dir </> "c.toml") path fixtureLabels fixtureSo fixtureUser
  r <- migrateCli path cfgPath backups
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("store-unreadable:" `isPrefixOf` ceErr r)
  assertBool "names the missing target" (("no store file at " ++ target) `isInfixOf` ceErr r)
  targetLeft <- doesFileExist target
  lockLeft <- doesFileExist (target ++ ".lock")
  assertBool "nothing created at the target" (not targetLeft)
  assertBool "no lock at the target" (not lockLeft)
  listDirectory backups >>= assertEqual "no backup" []

-- A first start under a symlinked parent directory creates the
-- store at the resolved path and serves it: the link is in an
-- ancestor directory, not at the store's own final component.
caseOpenMissingUnderSymlinkedDir :: IO ()
caseOpenMissingUnderSymlinkedDir = withScratch "ctl-symdir" $ \dir -> do
  let realDir = dir </> "realdir"; via = dir </> "pd"
      target = realDir </> "store.sqlite"; path = via </> "store.sqlite"
  createDirectory realDir
  createSymbolicLink realDir via
  cfgPath <- writeStoreConfig (dir </> "c.toml") path fixtureLabels fixtureSo fixtureUser
  (ok, note) <- openRelStore cfgPath
  assertBool ("serving open must create a fresh store under a symlinked parent, but refused: " ++ note) ok
  targetLeft <- doesFileExist target
  assertBool "store created at the resolved path" targetLeft
  roTexts target "SELECT value FROM store_meta WHERE key = 'schema_version'"
    >>= assertEqual "fresh store serves schema 3" ["3"]

-- The backup-dir guard compares against the resolved store path: a
-- backup dir beside the real file refuses even when --path names a
-- link from elsewhere.
caseMigrateSymlinkBackupDir :: IO ()
caseMigrateSymlinkBackupDir = withScratch "ctl-migrate" $ \dir -> do
  (link, cfgPath, real) <- withSymlinkedFixture "v0.4.0.0" dir
  let realDir = dir </> "real"
  dbBefore <- BS.readFile real
  r <- migrateCli link cfgPath realDir
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "tag" ("migrate-unsafe-backup-dir:" `isPrefixOf` ceErr r)
  BS.readFile real >>= \b -> assertBool "store untouched" (b == dbBefore)
  leftovers <- filter (\f -> ".bak" `isSuffixOf` f || ".receipt" `isSuffixOf` f)
    <$> listDirectory realDir
  assertEqual "no backup beside the store" [] leftovers

-- Through a symlink, inspect reads the lock beside the target: a
-- live owner there reads live, not offline.
caseInspectSymlinkLive :: IO ()
caseInspectSymlinkLive = withScratch "store-ctl" $ \dir -> do
  let realDir = dir </> "real"; real = realDir </> "store.sqlite"; link = dir </> "link.sqlite"
  createDirectory realDir
  eSt <- openSQLiteStore real
  case eSt of
    Left err -> fail ("open failed: " ++ show err)
    Right st -> do
      createSymbolicLink real link
      r <- runCtl ["store", "inspect", "--path", link]
      c <- storeCommit st emptyDelta
      storeClose st
      assertEqual "inspect exits 0" 0 (ceCode r)
      assertBool "names the target" (("store: " ++ real) `elem` lines (ceOut r))
      assertBool "reports live" ("lock: live" `isInfixOf` ceOut r)
      assertEqual "owner kept serving" Committed c

-- Through a symlink, an offline inspect still works and names the
-- resolved target.
caseInspectSymlinkOffline :: IO ()
caseInspectSymlinkOffline = withScratch "store-ctl" $ \dir -> do
  let realDir = dir </> "real"; real = realDir </> "store.sqlite"; link = dir </> "link.sqlite"
  createDirectory realDir
  eSt <- openSQLiteStore real
  case eSt of
    Left err -> fail ("open failed: " ++ show err)
    Right st -> storeClose st
  createSymbolicLink real link
  r <- runCtl ["store", "inspect", "--path", link]
  assertEqual "inspect exits 0" 0 (ceCode r)
  assertBool "names the target" (("store: " ++ real) `elem` lines (ceOut r))
  assertBool "reports offline" ("lock: offline" `isInfixOf` ceOut r)

-- Through a symlink, reset refuses while the target's owner is
-- live: neither the link nor the target is touched.
caseResetSymlinkLive :: IO ()
caseResetSymlinkLive = withScratch "store-ctl" $ \dir -> do
  let realDir = dir </> "real"; real = realDir </> "store.sqlite"; link = dir </> "link.sqlite"
  createDirectory realDir
  eSt <- openSQLiteStore real
  case eSt of
    Left err -> fail ("open failed: " ++ show err)
    Right st -> do
      createSymbolicLink real link
      lockBefore <- BS.readFile (real ++ ".lock")
      r <- runCtl ["store", "reset", "--path", link, "--confirm-demo-reset"]
      BS.readFile (real ++ ".lock") >>= assertEqual "owner lock untouched" lockBefore
      c <- storeCommit st emptyDelta
      storeClose st
      assertEqual "exit 1" 1 (ceCode r)
      assertBool "refused live" ("reset-refused:" `isPrefixOf` ceErr r)
      assertEqual "owner kept serving" Committed c
      linkLeft <- doesFileExist link
      realLeft <- doesFileExist real
      assertBool "link untouched" linkLeft
      assertBool "target untouched" realLeft

-- Through a symlink, resetting an offline store removes the target
-- (and its lock); the operator's symlink is left dangling, so the
-- next open fails closed instead of serving a fresh store.
caseResetSymlinkOffline :: IO ()
caseResetSymlinkOffline = withScratch "store-ctl" $ \dir -> do
  let realDir = dir </> "real"; real = realDir </> "store.sqlite"; link = dir </> "link.sqlite"
  createDirectory realDir
  eSt <- openSQLiteStore real
  case eSt of
    Left err -> fail ("open failed: " ++ show err)
    Right st -> storeClose st
  createSymbolicLink real link
  r <- runCtl ["store", "reset", "--path", link, "--confirm-demo-reset"]
  assertEqual "reset exits 0" 0 (ceCode r)
  assertEqual "names the target" ("reset: " ++ real ++ " removed (offline)\n") (ceOut r)
  realLeft <- doesFileExist real
  lockLeft <- doesFileExist (real ++ ".lock")
  assertBool "target removed" (not realLeft)
  assertBool "target lock removed" (not lockLeft)
  entries <- listDirectory dir
  assertBool "symlink left dangling" ("link.sqlite" `elem` entries)

-- Resetting through a store symlink reports that the link now
-- dangles and the next start refuses; the next serving open through
-- the link does refuse.
caseResetSymlinkWarnsDangling :: IO ()
caseResetSymlinkWarnsDangling = withScratch "store-ctl" $ \dir -> do
  let realDir = dir </> "real"; real = realDir </> "store.sqlite"; link = dir </> "link.sqlite"
  createDirectory realDir
  eSt <- openSQLiteStore real
  case eSt of
    Left err -> fail ("open failed: " ++ show err)
    Right st -> storeClose st
  createSymbolicLink real link
  cfgPath <- writeStoreConfig (dir </> "c.toml") link fixtureLabels fixtureSo fixtureUser
  r <- runCtl ["store", "reset", "--path", link, "--confirm-demo-reset"]
  assertEqual "reset exits 0" 0 (ceCode r)
  assertBool "tag" ("reset-dangling-link:" `isPrefixOf` ceErr r)
  assertBool "names the link" (link `isInfixOf` ceErr r)
  assertBool "next start refuses" ("the next start refuses" `isInfixOf` ceErr r)
  (ok, note) <- openRelStore cfgPath
  assertBool ("serving open through the dangling link must refuse, but opened: " ++ note) (not ok)
  assertBool "refusal is the dangling link" ("dangling" `isInfixOf` note)

-- A reset that removes the operator's own path leaves no link
-- behind, so there is nothing to report on stderr.
caseResetOfflineQuietStderr :: IO ()
caseResetOfflineQuietStderr = withStoreFile $ \dir -> do
  db <- seedDb dir
  r <- runCtl ["store", "reset", "--path", db, "--confirm-demo-reset"]
  assertEqual "reset exits 0" 0 (ceCode r)
  assertEqual "quiet stderr" "" (ceErr r)

-- Hooks with a fixed clock, so every backup name is known up front.
epochClock :: MigrateHooks
epochClock = noMigrateHooks { mhClock = pure 1700000000 }

-- After clearing a cold journal, an exhausted backup namespace must
-- not claim nothing was written: the database is unchanged, but the
-- journal is gone.
caseMigrateClearBackupExistsHonest :: IO ()
caseMigrateClearBackupExistsHonest = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"; journal = store ++ "-journal"
  createDirectory backups
  BS.writeFile journal (BS.replicate 512 0)
  mapM_ (\c -> writeFile c "taken") (backupCandidates store backups 2 1700000000)
  (code, out, err) <- storeMigrateCommandWith epochClock
    ["--path", store, "--config", cfgPath, "--backup-dir", backups]
  assertEqual "exit 1" 1 code
  assertBool "tag" ("migrate-backup-exists:" `isPrefixOf` err)
  assertBool "clearing reported" ("cold-journal-removed: yes" `elem` lines out)
  gone <- not <$> doesFileExist journal
  assertBool "journal removed" gone
  assertBool "no nothing-written claim" (not ("nothing was written" `isInfixOf` err))
  assertBool "database unchanged" ("the store database was not changed" `isInfixOf` err)
  assertBool "names the clearing" ("cold journal was removed" `isInfixOf` err)

-- After clearing a cold journal, a backup failure must not claim
-- the store was unchanged: the database is, but the journal is gone.
caseMigrateClearBackupFailedHonest :: IO ()
caseMigrateClearBackupFailedHonest = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"; journal = store ++ "-journal"
  createDirectory backups
  BS.writeFile journal (BS.replicate 512 0)
  let failing = noMigrateHooks { mhDigest = \_ -> pure (Left "SHA-256 engine unavailable: test") }
  (code, out, err) <- storeMigrateCommandWith failing
    ["--path", store, "--config", cfgPath, "--backup-dir", backups]
  assertEqual "exit 1" 1 code
  assertBool "tag" ("migrate-backup-failed:" `isPrefixOf` err)
  assertBool "clearing reported" ("cold-journal-removed: yes" `elem` lines out)
  gone <- not <$> doesFileExist journal
  assertBool "journal removed" gone
  assertBool "no store-unchanged claim" (not ("; the store was not changed" `isInfixOf` err))
  assertBool "database unchanged" ("the store database was not changed" `isInfixOf` err)
  assertBool "names the clearing" ("cold journal was removed" `isInfixOf` err)

-- After clearing a cold journal, a rolled-back transaction must not
-- claim the store was unchanged either: the backup is still kept.
caseMigrateClearTxnFailedHonest :: IO ()
caseMigrateClearTxnFailedHonest = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.3.1.0" dir
  let backups = dir </> "backups"; journal = store ++ "-journal"
  createDirectory backups
  BS.writeFile journal (BS.replicate 512 0)
  let full = noMigrateHooks { mhSQLite = noMigrationHooks { mgAfterBegin = \db -> do
        n <- pragmaInt db "PRAGMA page_count"
        S.exec db (T.pack ("PRAGMA max_page_count = " ++ show n)) } }
  (code, out, err) <- storeMigrateCommandWith full
    ["--path", store, "--config", cfgPath, "--backup-dir", backups]
  assertEqual "exit 1" 1 code
  assertBool "tag" ("migrate-failed:" `isPrefixOf` err)
  assertBool "clearing reported" ("cold-journal-removed: yes" `elem` lines out)
  gone <- not <$> doesFileExist journal
  assertBool "journal removed" gone
  assertBool "no store-unchanged claim" (not ("; the store was not changed" `isInfixOf` err))
  assertBool "database unchanged" ("the store database was not changed" `isInfixOf` err)
  assertBool "backup kept" ("Backup kept at" `isInfixOf` err)

-- | Run an action with the process stdout redirected to a file
-- (block-buffered, so only flushed bytes land there), restoring the
-- original stdout afterwards.
withStdoutToFile :: FilePath -> IO a -> IO a
withStdoutToFile file act = bracket acquire release (const act)
  where
    acquire = do
      hFlush stdout
      mode <- hGetBuffering stdout
      backup <- hDuplicate stdout
      h <- openFile file WriteMode
      hDuplicateTo h stdout
      hSetBuffering stdout (BlockBuffering (Just 65536))
      pure (backup, h, mode)
    release (backup, h, mode) = do
      hFlush stdout
      hDuplicateTo backup stdout
      hSetBuffering stdout mode
      hClose backup
      hClose h

-- | Snapshot a file's current bytes through a fresh POSIX
-- descriptor. A second System.IO open would fail on GHC's file
-- lock while the capture handle holds the file for writing; the
-- raw descriptor takes no lock and reads only flushed bytes (the
-- snapshot never flushes stdout itself, so an unflushed record
-- stays invisible).
snapshotFile :: FilePath -> IO String
snapshotFile path =
  bracket (openFd path ReadOnly defaultFileFlags) closeFd drain
  where
    drain fd = go []
      where
        go acc = do
          eBs <- try (fdRead fd 65536) :: IO (Either IOError BS.ByteString)
          case eBs of
            Left e | isEOFError e -> pure (BC8.unpack (BS.concat (reverse acc)))
            Left e -> ioError e
            Right bs -> go (bs : acc)

-- The clearing is recorded on stdout the moment it happens, not
-- only in the end-of-run output: a hook that runs after the backup
-- (still mid-run) already sees the flushed line in the captured
-- stdout. Without the immediate record, a kill after the clear
-- leaves no trace of it.
caseMigrateClearRecordedAtClearTime :: IO ()
caseMigrateClearRecordedAtClearTime = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"; journal = store ++ "-journal"; capture = dir </> "stdout.log"
  createDirectory backups
  BS.writeFile journal (BS.replicate 512 0)
  seenRef <- newIORef ""
  let hooks = noMigrateHooks
        { mhAfterBackup = snapshotFile capture >>= writeIORef seenRef }
  (code, out, err) <- withStdoutToFile capture $
    storeMigrateCommandWith hooks ["--path", store, "--config", cfgPath, "--backup-dir", backups]
  seen <- readIORef seenRef
  assertEqual ("exit 0; stderr: " ++ err) 0 code
  assertBool "clearing reported at the end" ("cold-journal-removed: yes" `elem` lines out)
  assertBool ("clearing already on stdout mid-run; seen: " ++ seen) ("cold-journal-removed: yes" `isInfixOf` seen)

-- A backup that cannot even be read back is removed like any other
-- unverified backup: the hook swaps the just-created file for a
-- dangling symlink, which the O_NOFOLLOW read-back refuses.
caseMigrateBackupReadbackFailureRemoved :: IO ()
caseMigrateBackupReadbackFailureRemoved = withScratch "ctl-migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  let dangling = noMigrateHooks
        { mhAfterCreate = \p -> removeLink p >> createSymbolicLink (dir </> "no-such-target") p }
  (code, _, err) <- storeMigrateCommandWith dangling
    ["--path", store, "--config", cfgPath, "--backup-dir", backups]
  assertEqual "exit 1" 1 code
  assertBool "tag" ("migrate-backup-failed:" `isPrefixOf` err)
  assertBool "names the read-back" ("cannot read back the backup" `isInfixOf` err)
  listDirectory backups >>= assertEqual "unreadable backup removed" []

-- A cold journal must not hide an identity refusal: on a current
-- store with a drifted catalog, check reports the identity refusal
-- (like migrate does), with the plan on stdout.
caseCheckColdJournalIdentityRefused :: IO ()
caseCheckColdJournalIdentityRefused = withScratch "ctl-check" $ \dir -> do
  let store = dir </> "store.sqlite"; journal = store ++ "-journal"; backups = dir </> "backups"
  createDirectory backups
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  openReconciled store cfg >>= either (assertFailure . show) closeAcquired
  BS.writeFile journal (BS.replicate 512 0)
  drift <- writeStoreConfig (dir </> "d.toml") store ["haskoki-demo", "haskoki-ops-renamed"] fixtureSo fixtureUser
  dbBefore <- BS.readFile store
  jBefore <- BS.readFile journal
  r <- check store drift
  assertEqual "exit 1" 1 (ceCode r)
  assertBool "identity refusal takes precedence" ("store-identity-refused:" `isPrefixOf` ceErr r)
  assertBool "plan printed" ("verdict: identity-refused" `isInfixOf` ceOut r)
  m <- migrateCli store drift backups
  assertEqual "migrate refuses" 1 (ceCode m)
  assertBool "migrate agrees" ("store-identity-refused:" `isPrefixOf` ceErr m)
  BS.readFile store >>= \b -> assertBool "store untouched" (b == dbBefore)
  BS.readFile journal >>= \b -> assertBool "journal untouched" (b == jBefore)
  listDirectory backups >>= assertEqual "no backup" []
