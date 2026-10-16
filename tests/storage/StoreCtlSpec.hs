{-# LANGUAGE OverloadedStrings #-}
{- | CLI store subcommands (hermetic temp dirs).

@store check@ diagnoses a store without writing; @store inspect@ reads a SQLite store offline; @store reset@ refuses a
live (lock-held) store and resets an offline one only with the
confirm flag. Never mutates a live store.
-}
module StoreCtlSpec (spec) where

import Control.Exception (bracket)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.List (isInfixOf, isPrefixOf, isSuffixOf)
import Foreign.C.String (withCString)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (nullPtr)
import Foreign.StablePtr (castStablePtrToPtr)
import Foreign.Storable (poke)
import System.Directory (createDirectory, doesFileExist, listDirectory)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Ctl (CtlExit (..), ctlHelp, runCtl)
import Haskoki.FFI.Async (haskokiAsyncStoreClose, haskokiAsyncStoreOpen)
import Haskoki.Runtime.Catalog (asyncHomeEntry)
import Haskoki.Runtime.Storage (CommitResult (..), CredentialRecord (..), Store (..), emptyDelta)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Types (TokenId (..))

import StoreFixtures

spec :: TestTree
spec = testGroup "Store commands"
  [ testCase "inspect reads an offline store" caseInspect
  , testCase "reset refuses a live store" caseResetLive
  , testCase "reset needs the confirm flag" caseResetConfirm
  , testCase "reset clears an offline store with the flag" caseResetOffline
  , testCase "check: a current store is ok (exit 0)" caseCheckOk
  , testCase "check: a v0.4 store needs migration (exit 1), unchanged" caseCheckMigrationRequired
  , testCase "check: a drifted catalog is refused (exit 1), unchanged" caseCheckIdentityRefused
  , testCase "check: a live owner is refused and keeps serving" caseCheckLive
  , testCase "check: a missing store is refused, nothing created" caseCheckMissing
  , testCase "check: another store's config is refused" caseCheckConfigMismatch
  , testCase "check: a hot journal is refused" caseCheckJournal
  , testCase "check: a newer schema is refused" caseCheckUnsupported
  , testCase "check: usage errors exit 2" caseCheckUsage
  , testCase "check: no output carries a PIN" caseCheckNoPins
  , testCase "check: broken config output carries no PIN" (caseCheckConfigNoPins "broken.toml" "[tokens]\nso_pins = [\"58213946\"\nlabels = 7\n")
  , testCase "check: mistyped value output carries no PIN" (caseCheckConfigNoPins "badval.toml" "[tokens]\nso_pins = 58213946\nuser_pins = [\"12873465\"]\n")
  , testCase "check: --async-home plans an async-created store" caseCheckAsyncHome
  , testCase "check: --async-home plans the v0.4 async shape" caseCheckAsyncHomeV04
  , testCase "migrate: a v0.4 store migrates (exit 0) and then checks ok" caseMigrateCliV04
  , testCase "migrate: a current store needs nothing (exit 0)" caseMigrateCliNotNeeded
  , testCase "migrate: a drifted catalog refuses (exit 1), nothing written" caseMigrateCliRefusesDrift
  , testCase "migrate: a live owner refuses (exit 1)" caseMigrateCliLive
  , testCase "migrate: a hot journal refuses (exit 1), both files untouched" caseMigrateCliJournal
  , testCase "migrate: --async-home migrates a v0.4 async-created store, then the async open serves" caseMigrateCliAsyncHome
  , testCase "migrate: usage errors exit 2" caseMigrateCliUsage
  , testCase "migrate: no output or receipt carries a PIN" caseMigrateCliNoPins
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
