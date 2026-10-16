{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
{- | Store preflight, explicit migration and recovery (AC-05):
released-binary fixtures, refused opens that write nothing, the
read-only snapshot and plan, the owned migration, and recovery.
-}
module PreflightSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import qualified Data.Map.Strict as Map
import Control.Exception (IOException, bracket, throwIO, try)
import Data.Bits ((.&.))
import Data.IORef (atomicModifyIORef', newIORef, readIORef)
import Data.List (isInfixOf, isSuffixOf, nub, sort)
import qualified Database.SQLite3 as S
import Foreign.C.Types (CInt (..))
import qualified Data.Text as T
import System.Directory (createDirectory, doesFileExist, listDirectory, removeFile)
import System.FilePath ((</>))
import System.Posix.Files (createSymbolicLink, fileMode, getFileStatus, modificationTime)
import System.Posix.IO (OpenMode (ReadOnly), closeFd, defaultFileFlags, openFd)
import System.Posix.User (getEffectiveUserID)
import Test.Tasty (DependencyType (AllFinish), TestTree, after, testGroup)
import Test.Tasty.HUnit (HUnitFailure, assertBool, assertEqual, assertFailure, testCase)

import Haskoki.FFI.Standard (StdStoreError (..))
import Haskoki.Runtime.Storage
  (CommitResult (..), CredentialRecord (..), IdentityRefusal (..), StoreError (..), TokenRecord (..), Store (..), emptyDelta)
import Haskoki.Types (SlotId (..), TokenId (..))
import Haskoki.Runtime.Catalog (asyncHomeConfig, asyncHomeEntry, homeCatalogEntry, identityCatalog)
import Haskoki.Runtime.Config (Config (..), StorageCfg (..), StorageKind (..))

import Haskoki.Runtime.Storage.Preflight
  ( MigrateError (..), MigrateHooks (..), MigrateOutcome (..), MigrationOp (..), MigrationReceipt (..)
  , PlanVerdict (..), PreflightRefusal (..), StoreOpenPlan (..)
  , backupCandidates, checkStoreOpen, configSelectsStore, migrateStore, migrateStoreWith
  , noMigrateHooks, planVerdict, renderMigrateError, renderPlan, renderReceipt, renderStoreRefusal
  , sha256Hex )
import Haskoki.Runtime.Storage.SQLite
  (MigrationHooks (..), OwnerState (..), SQLiteMigration (..), StoreSnapshot (..), migrateOwned, noMigrationHooks, openSQLiteStore, probeOwner, readStoreSnapshot, withOwnedStoreFile)

import StoreFixtures

spec :: TestTree
spec = testGroup "Store preflight"
  [ testGroup "released fixtures"
      [ testCase "sha-256 is the standard digest" caseSha256Vector
      , testCase "v0.3.1.0 fixture matches its manifest" (caseFixtureManifest "v0.3.1.0")
      , testCase "v0.4.0.0 fixture matches its manifest" (caseFixtureManifest "v0.4.0.0")
      , testCase "v0.3.1.0 manifest names the committed generator and template" (caseManifestGenerator "v0.3.1.0")
      , testCase "v0.4.0.0 manifest names the committed generator and template" (caseManifestGenerator "v0.4.0.0")
      ]
  , testGroup "refused open"
      [ testCase "v0.3.1.0 store refuses unchanged under its own config" (caseOldStoreRefuses "v0.3.1.0" 1 False)
      , testCase "v0.3.1.0 store refuses unchanged under a drifted config" (caseOldStoreRefuses "v0.3.1.0" 1 True)
      , testCase "v0.4.0.0 store refuses unchanged under its own config" (caseOldStoreRefuses "v0.4.0.0" 2 False)
      , testCase "v0.4.0.0 store refuses unchanged under a drifted config" (caseOldStoreRefuses "v0.4.0.0" 2 True)
      , testCase "an empty schema-1 store refuses unchanged" caseEmptyV1Refuses
      , testCase "a fully provisioned schema-2 store refuses unchanged" caseProvisionedV2Refuses
      , testCase "schema 1 with a credentials table is corrupt, unchanged" caseV1WithCredentialsCorrupt
      , testCase "unknown schema versions refuse unchanged" caseUnknownVersionsRefuse
      , testCase "schema-3 rowless tokens still name their ids" caseV3RowlessNamesIds
      ]
  , testGroup "snapshot"
      [ testCase "snapshot reads a released store without writing" caseSnapshotReadsFixture
      , testCase "snapshot never creates a missing store" caseSnapshotNeverCreates
      , testCase "snapshot reads a store in a read-only directory" caseSnapshotReadOnlyDir
      , testCase "snapshot refuses a hot journal, touching nothing" caseSnapshotRefusesJournal
      , testCase "snapshot diagnoses garbage and corrupt records" caseSnapshotDiagnoses
      , testCase "owner probe: absent and in-process live" caseProbeAbsentAndLive
      , after AllFinish "/death after reservation leaves a gap, never reuse/" $
          testCase "owner probe: stale lock reported and left in place" caseProbeStaleLeftInPlace
      , testCase "owner probe: unreadable lock is live" caseProbeUnreadableLive
      ]
  , testGroup "plan"
      [ testCase "v0.4.0.0 plan: freeze the rowless token, move to 3" casePlanV04
      , testCase "v0.3.1.0 plan: create the table, freeze both, move to 3" casePlanV031
      , testCase "a current provisioned store is openable" casePlanCurrentOpenable
      , testCase "a drifted catalog is an identity refusal" casePlanDrift
      , testCase "configured but unstored tokens are seeds, not migration" casePlanSeeds
      , testCase "plan rendering carries ids, never PINs" casePlanRedacted
      , testCase "config must select the same sqlite file" caseConfigSelects
      , testCase "schema-3 rowless tokens plan a freeze with no version move" casePlanV3Rowless
      , testCase "a v0.4 async-created store plans a freeze and a move under the async home catalog" casePlanAsyncV04
      , testCase "a schema-3 async-created store is openable under the async home catalog" casePlanAsyncSeededV3
      , testCase "the async home entry is the async label with the home PINs" caseAsyncHomeEntry
      , testCase "check on a missing path says there is no store" casePlanMissingPath
      , testCase "check on a store held by another fd is refused as live" casePlanLiveOwner
      , testCase "store-full has its own refusal tag" caseStoreFullTag
      , testCase "the redaction check matches PINs at digit boundaries" caseNoPinsDigitBoundary
      ]
  , testGroup "owned migration"
      [ testCase "schema 1 migrates: table, rows, marker; nothing else moves" caseOwnedMigratesV1
      , testCase "schema 2 migrates; an existing row is kept byte-exact" caseOwnedMigratesV2KeepsRow
      , testCase "a v0.4 async-created store migrates under the async plan" caseOwnedMigratesAsync
      , testCase "schema 3 freezes rows with the marker unchanged" caseOwnedFreezesAtV3
      , testCase "a freeze over an existing row aborts the whole migration" caseOwnedRefusesReplacingRow
      , testCase "a moved schema marker aborts unchanged" caseOwnedSchemaMoved
      , testCase "a crash before commit rolls back and releases ownership" caseOwnedCrashRollsBack
      , testCase "a full disk rolls back unchanged" caseOwnedFullDisk
      , testCase "ownership is refused while an owner is live" caseOwnedRefusesLive
      , testCase "ownership never creates a store file" caseOwnedNeverCreates
      ]
  , testGroup "migrate"
      [ testCase "v0.4.0.0: freeze the rowless token, keep the in-band row" caseMigrateV04
      , testCase "v0.3.1.0: freeze both tokens" caseMigrateV031
      , testCase "schema 3: freeze the rowless token, marker stays 3" caseMigrateSchema3Rowless
      , testCase "a v0.4 async-created store migrates under the async home catalog" caseMigrateAsyncV04
      , testCase "a current store needs nothing and gets no backup" caseMigrateNotNeeded
      , testCase "a drifted catalog refuses before any write" caseMigrateRefusesIdentityDrift
      , testCase "another store's config refuses before any write" caseMigrateRefusesConfigMismatch
      , testCase "unsafe backup directories refuse before any write" caseMigrateUnsafeBackupDirs
      , testCase "a live owner refuses before any write" caseMigrateLiveOwner
      , testCase "a hot journal refuses before ownership, both files untouched" caseMigrateHotJournal
      , testCase "a zero-byte journal is ignored" caseMigrateZeroByteJournal
      , testCase "a store changed after the plan refuses" caseMigrateStoreChanged
      , testCase "an existing backup name is never overwritten" caseMigrateNeverOverwrites
      , testCase "all 100 backup names taken refuses" caseMigrateBackupNamesExhausted
      , testCase "a hashing failure refuses before any write" caseMigrateHashFailure
      , testCase "the clock is read once: backup name and receipt agree" caseMigrateClockOnce
      , testCase "a failed transaction keeps the store and the backup" caseMigrateTxnFailureKeepsStore
      , testCase "appended catalog tokens are left to the next open" caseMigrateLeavesSeedsToOpen
      , testCase "naming: candidate backup names" caseBackupCandidates
      , testCase "migrate errors render tags and paths, never PINs" caseMigrateErrorRender
      ]
  ]

caseSha256Vector :: IO ()
caseSha256Vector = do
  r <- sha256Hex "abc"
  assertEqual "FIPS 180-2 vector"
    (Right "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") r

-- | The committed store is byte-for-byte the one the manifest
-- describes, and its read-only shape matches the recorded shape.
caseFixtureManifest :: String -> IO ()
caseFixtureManifest tag = withScratch "fixture-manifest" $ \dir -> do
  root <- storePackageRoot
  manifest <- readManifest (root </> "tests" </> "fixtures" </> "stores" </> tag </> "manifest.txt")
  (store, _) <- copyReleasedFixture tag dir
  digest <- sha256Hex =<< BS.readFile store
  assertEqual "store digest" (fmap Right (lookup "store-sha256" manifest)) (Just digest)
  schema <- roTexts store "SELECT value FROM store_meta WHERE key = 'schema_version'"
  assertEqual "schema" (fmap words (lookup "schema-version" manifest)) (Just schema)
  toks <- roTexts store "SELECT token_id FROM tokens ORDER BY token_id"
  assertEqual "tokens" (fmap words (lookup "tokens" manifest)) (Just toks)
  tables <- roTexts store "SELECT name FROM sqlite_master WHERE type = 'table'"
  creds <- if "credentials" `elem` tables
    then roTexts store "SELECT token_id FROM credentials ORDER BY token_id"
    else pure []
  let want = fmap (\v -> if v == "none" then [] else words v) (lookup "credentials" manifest)
  assertEqual "credential rows" want (Just creds)
  case lookup "release-tag" manifest of
    Just t | t == tag -> pure ()
    other -> assertFailure ("manifest names the wrong release: " ++ show other)

-- | A released old store, opened through the production acquisition
-- with its own or a drifted config, refuses as migration-required
-- and leaves bytes, schema, tables and credential authority intact.
caseOldStoreRefuses :: String -> Int -> Bool -> IO ()
caseOldStoreRefuses tag found drifted = withScratch "refused-open" $ \dir -> do
  (store, cfgPath0) <- copyReleasedFixture tag dir
  cfgPath <- if drifted
    then writeStoreConfig (dir </> "drift.toml") store
           ["haskoki-demo", "haskoki-ops-renamed"] fixtureSo fixtureUser
    else pure cfgPath0
  cfg <- loadConfigOrFail cfgPath
  before <- captureState store
  r <- openReconciled store cfg
  expectStdNeedsMigration found r
  assertUnchanged (tag ++ " after a refused open") before store

caseEmptyV1Refuses :: IO ()
caseEmptyV1Refuses = withScratch "refused-open" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 1 store [] []
  cfgPath <- writeStoreConfig (dir </> "c.toml") store ["haskoki-demo"] ["58213946"] ["12873465"]
  cfg <- loadConfigOrFail cfgPath
  before <- captureState store
  openReconciled store cfg >>= expectStdNeedsMigration 1
  assertUnchanged "empty schema-1 store" before store

caseProvisionedV2Refuses :: IO ()
caseProvisionedV2Refuses = withScratch "refused-open" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 2 store [fixtureToken 1 0 "haskoki-demo"]
    [CredentialRecord (TokenId 1) "58213946" (Just "12873465")]
  cfgPath <- writeStoreConfig (dir </> "c.toml") store ["haskoki-demo"] ["58213946"] ["12873465"]
  cfg <- loadConfigOrFail cfgPath
  before <- captureState store
  openReconciled store cfg >>= expectStdNeedsMigration 2
  assertUnchanged "provisioned schema-2 store" before store

caseV1WithCredentialsCorrupt :: IO ()
caseV1WithCredentialsCorrupt = withScratch "refused-open" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 2 store [fixtureToken 1 0 "haskoki-demo"] []
  rawExec store "UPDATE store_meta SET value = '1' WHERE key = 'schema_version'"
  before <- captureState store
  r <- openSQLiteStore store
  case r of
    Left (StoreCorrupt _) -> pure ()
    Left other -> assertFailure ("wrong refusal: " ++ show other)
    Right s -> storeClose s >> assertFailure "a schema-1 file with credentials opened"
  assertUnchanged "schema-1 file with a credentials table" before store

caseUnknownVersionsRefuse :: IO ()
caseUnknownVersionsRefuse = mapM_ one ["0", "4", "999", "two"]
  where
    one v = withScratch "refused-open" $ \dir -> do
      let store = dir </> "store.db"
      makeSchemaStore 3 store [fixtureToken 1 0 "haskoki-demo"] []
      rawExec store (T.pack ("UPDATE store_meta SET value = '" ++ v ++ "' WHERE key = 'schema_version'"))
      before <- captureState store
      r <- openSQLiteStore store
      case r of
        Left (StoreSchemaVersion 3 found) -> assertEqual "found version" v found
        Left other -> assertFailure (v ++ ": wrong refusal: " ++ show other)
        Right s -> storeClose s >> assertFailure (v ++ ": opened")
      assertUnchanged ("schema " ++ v) before store

caseV3RowlessNamesIds :: IO ()
caseV3RowlessNamesIds = withScratch "refused-open" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 3 store [fixtureToken 1 0 "haskoki-demo"] []
  cfgPath <- writeStoreConfig (dir </> "c.toml") store ["haskoki-demo"] ["58213946"] ["12873465"]
  cfg <- loadConfigOrFail cfgPath
  before <- captureState store
  r <- openReconciled store cfg
  case r of
    Left (StdStoreMigrationRequired ids) -> assertEqual "legacy ids" [TokenId 1] ids
    Left other -> assertFailure ("wrong refusal: " ++ show other)
    Right acq -> closeAcquired acq >> assertFailure "rowless store opened"
  assertUnchanged "schema-3 rowless store" before store

-- | The manifest's generator and template digests name the files in
-- the tree, so an edit to either cannot leave a stale record.
caseManifestGenerator :: String -> IO ()
caseManifestGenerator tag = do
  root <- storePackageRoot
  manifest <- readManifest (root </> "tests" </> "fixtures" </> "stores" </> tag </> "manifest.txt")
  gen <- sha256Hex =<< BS.readFile (root </> "scripts" </> "make-store-fixtures.sh")
  assertEqual "generator digest" (fmap Right (lookup "generator-sha256" manifest)) (Just gen)
  tmpl <- sha256Hex =<< BS.readFile (root </> "tests" </> "fixtures" </> "stores" </> "config.toml.in")
  assertEqual "template digest" (fmap Right (lookup "config-template-sha256" manifest)) (Just tmpl)

caseSnapshotReadsFixture :: IO ()
caseSnapshotReadsFixture = withScratch "snapshot" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  before <- captureState store
  st0 <- getFileStatus store
  r <- readStoreSnapshot store
  snap <- either (assertFailure . show) pure r
  assertEqual "schema" 2 (snapSchema snap)
  assertEqual "tokens" [TokenId 1, TokenId 2] (map trId (snapTokens snap))
  assertEqual "credential holders" [TokenId 2] (snapCredentialTokens snap)
  assertEqual "objects" 2 (snapObjectCount snap)
  assertUnchanged "snapshot" before store
  st1 <- getFileStatus store
  assertEqual "mtime unchanged" (modificationTime st0) (modificationTime st1)

caseSnapshotNeverCreates :: IO ()
caseSnapshotNeverCreates = withScratch "snapshot" $ \dir -> do
  let store = dir </> "absent.db"
  r <- readStoreSnapshot store
  case r of
    Left (StoreIO _) -> pure ()
    other -> assertFailure ("wrong result: " ++ show other)
  absent <- not <$> doesFileExist store
  noLock <- not <$> doesFileExist (store ++ ".lock")
  assertBool "no file created" absent
  assertBool "no lock created" noLock

-- | The serving open needs to create its sidecar, so it fails in a
-- read-only directory; the snapshot, which never takes ownership or
-- writes, still reads.
caseSnapshotReadOnlyDir :: IO ()
caseSnapshotReadOnlyDir = withScratch "snapshot" $ \dir -> do
  let sub = dir </> "ro"
  createDirectory sub
  (store, _) <- copyReleasedFixture "v0.4.0.0" sub
  withFileMode store 0o444 $ withFileMode sub 0o555 $ do
    r <- readStoreSnapshot store
    assertEqual "snapshot reads" (Right 2) (snapSchema <$> r)
    o <- openSQLiteStore store
    case o of
      Left _ -> pure ()
      Right s -> storeClose s >> assertFailure "owning open succeeded in a read-only directory"

caseSnapshotRefusesJournal :: IO ()
caseSnapshotRefusesJournal = withScratch "snapshot" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  BS.writeFile (store ++ "-journal") "\217\213\5\249 interrupted"
  dbBefore <- BS.readFile store
  jBefore <- BS.readFile (store ++ "-journal")
  r <- readStoreSnapshot store
  assertEqual "refused" (Left (StoreJournalPresent (store ++ "-journal"))) (snapSchema <$> r)
  BS.readFile store >>= assertEqual "db untouched" dbBefore
  BS.readFile (store ++ "-journal") >>= assertEqual "journal untouched" jBefore

caseSnapshotDiagnoses :: IO ()
caseSnapshotDiagnoses = withScratch "snapshot" $ \dir -> do
  let garbage = dir </> "garbage.db"
  BS.writeFile garbage (BS.replicate 4096 0x41)
  rg <- readStoreSnapshot garbage
  case rg of
    Left (StoreIO _) -> pure ()
    other -> assertFailure ("garbage: " ++ show other)
  let store = dir </> "store.db"
  makeSchemaStore 3 store [fixtureToken 1 0 "haskoki-demo"] []
  rawExec store "UPDATE tokens SET record_json = '{broken'"
  rc <- readStoreSnapshot store
  case rc of
    Left (StoreCorrupt _) -> pure ()
    other -> assertFailure ("corrupt token: " ++ show other)

caseProbeAbsentAndLive :: IO ()
caseProbeAbsentAndLive = withScratch "probe" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 3 store [] []
  probeOwner store >>= assertEqual "offline" OwnerAbsent
  e <- openSQLiteStore store
  s <- either (assertFailure . show) pure e
  lockBefore <- BS.readFile (store ++ ".lock")
  p <- probeOwner store
  case p of
    OwnerLive _ -> pure ()
    other -> assertFailure ("held store not live: " ++ show other)
  BS.readFile (store ++ ".lock") >>= assertEqual "owner lock untouched" lockBefore
  r <- storeCommit s emptyDelta
  assertEqual "owner keeps serving" Committed r
  storeClose s

caseProbeStaleLeftInPlace :: IO ()
caseProbeStaleLeftInPlace = withScratch "probe" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 3 store [] []
  pid <- reapedPid
  writeFile (store ++ ".lock") (show pid ++ "\n")
  before <- BS.readFile (store ++ ".lock")
  probeOwner store >>= assertEqual "stale" (OwnerStale pid)
  BS.readFile (store ++ ".lock") >>= assertEqual "stale lock left in place" before

caseProbeUnreadableLive :: IO ()
caseProbeUnreadableLive = withScratch "probe" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 3 store [] []
  euid <- getEffectiveUserID
  if euid == 0
    then putStrLn "skipped: chmod 000 does not deny root"
    else do
      dead <- reapedPid
      writeFile (store ++ ".lock") (show dead ++ "\n")
      p <- withFileMode (store ++ ".lock") 0o000 (probeOwner store)
      case p of
        OwnerLive _ -> pure ()
        other -> assertFailure ("unreadable lock not live: " ++ show other)

fixturePlan :: String -> FilePath -> IO (FilePath, FilePath, StoreOpenPlan)
fixturePlan tag dir = do
  (store, cfgPath) <- copyReleasedFixture tag dir
  cfg <- loadConfigOrFail cfgPath
  r <- checkStoreOpen store cfg
  plan <- either (assertFailure . show) pure r
  pure (store, cfgPath, plan)

casePlanV04 :: IO ()
casePlanV04 = withScratch "plan" $ \dir -> do
  (store, _, plan) <- fixturePlan "v0.4.0.0" dir
  assertEqual "schema" 2 (sopSchema plan)
  assertEqual "rowless" [TokenId 1] (sopAbsentCredentials plan)
  assertEqual "holders" [TokenId 2] (sopCredentialTokens plan)
  assertEqual "ops" [OpFreezeCredentials [TokenId 1], OpSetSchemaVersion 2 3] (sopOps plan)
  assertEqual "verdict" VerdictMigrationRequired (planVerdict plan)
  lockAbsent <- not <$> doesFileExist (store ++ ".lock")
  assertBool "check created no lock" lockAbsent

casePlanV031 :: IO ()
casePlanV031 = withScratch "plan" $ \dir -> do
  (_, _, plan) <- fixturePlan "v0.3.1.0" dir
  assertEqual "ops"
    [ OpCreateCredentialsTable, OpFreezeCredentials [TokenId 1, TokenId 2]
    , OpSetSchemaVersion 1 3 ] (sopOps plan)

casePlanCurrentOpenable :: IO ()
casePlanCurrentOpenable = withScratch "plan" $ \dir -> do
  let store = dir </> "store.db"
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  openReconciled store cfg >>= either (assertFailure . show) closeAcquired
  r <- checkStoreOpen store cfg
  plan <- either (assertFailure . show) pure r
  assertEqual "no ops" [] (sopOps plan)
  assertEqual "openable" VerdictOpenable (planVerdict plan)

casePlanDrift :: IO ()
casePlanDrift = withScratch "plan" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  cfgPath <- writeStoreConfig (dir </> "d.toml") store ["haskoki-demo", "haskoki-ops-renamed"] fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  r <- checkStoreOpen store cfg
  plan <- either (assertFailure . show) pure r
  case planVerdict plan of
    VerdictIdentityRefused (RefuseLabelChanged (TokenId 2) _ "haskoki-ops" "haskoki-ops-renamed") -> pure ()
    other -> assertFailure ("wrong verdict: " ++ show other)
  assertEqual "ops still required"
    [OpFreezeCredentials [TokenId 1], OpSetSchemaVersion 2 3] (sopOps plan)

casePlanSeeds :: IO ()
casePlanSeeds = withScratch "plan" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  cfgPath <- writeStoreConfig (dir </> "s.toml") store
    (fixtureLabels ++ ["haskoki-audit"]) (fixtureSo ++ ["70435168"]) (fixtureUser ++ ["81546279"])
  cfg <- loadConfigOrFail cfgPath
  r <- checkStoreOpen store cfg
  plan <- either (assertFailure . show) pure r
  assertEqual "seed id 3" (Right [TokenId 3]) (sopIdentity plan)
  assertEqual "freeze only the stored rowless token"
    [OpFreezeCredentials [TokenId 1], OpSetSchemaVersion 2 3] (sopOps plan)

casePlanRedacted :: IO ()
casePlanRedacted = withScratch "plan" $ \dir -> do
  (_, _, plan) <- fixturePlan "v0.4.0.0" dir
  let out = renderPlan plan
  assertNoPins "renderPlan" out
  assertNoPins "show plan" (show plan)
  assertBool "names the rowless id" ("credentials-absent: 0000000000000001" `isInfixOf` out)
  assertBool "names the verdict" ("verdict: migration-required" `isInfixOf` out)

caseConfigSelects :: IO ()
caseConfigSelects = withScratch "plan" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  cfg <- loadConfigOrFail cfgPath
  configSelectsStore store cfg >>= assertEqual "same string" (Right ())
  createSymbolicLink store (dir </> "alias.sqlite")
  configSelectsStore (dir </> "alias.sqlite") cfg >>= assertEqual "same inode" (Right ())
  other <- writeStoreConfig (dir </> "o.toml") (dir </> "other.sqlite") fixtureLabels fixtureSo fixtureUser
  cfgO <- loadConfigOrFail other
  r <- configSelectsStore store cfgO
  assertEqual "different file" (Left (ConfigPathMismatch (dir </> "other.sqlite") store)) r
  configSelectsStore store cfg { cfgStorage = (cfgStorage cfg) { scKind = StorageMemory } }
    >>= assertEqual "memory" (Left ConfigNotSQLite)

-- A supported migrate input: the marker is already 3, so only the
-- rows are frozen and no version move is planned.
casePlanV3Rowless :: IO ()
casePlanV3Rowless = withScratch "plan" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 3 store [fixtureToken 1 0 "haskoki-demo", fixtureToken 2 1 "haskoki-ops"]
    [CredentialRecord (TokenId 2) "69324057" (Just "23984576")]
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  r <- checkStoreOpen store cfg
  plan <- either (assertFailure . show) pure r
  assertEqual "schema" 3 (sopSchema plan)
  assertEqual "ops" [OpFreezeCredentials [TokenId 1]] (sopOps plan)
  assertEqual "verdict" VerdictMigrationRequired (planVerdict plan)
  assertNoPins "renderPlan" (renderPlan plan)

-- A store the v0.4 async open created: one token labelled
-- haskoki-async and, in that build, no credential row (its open
-- committed the token alone). The parser's slot-0 anchor keeps any
-- loaded config from naming that label, so the plan runs under the
-- async home catalog; the standard catalog refuses on identity.
casePlanAsyncV04 :: IO ()
casePlanAsyncV04 = withScratch "plan" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 2 store [fixtureToken 1 0 "haskoki-async"] []
  std <- writeStoreConfig (dir </> "s.toml") store ["haskoki-demo"] ["5678"] ["1234"]
  cfg <- loadConfigOrFail std
  checkStoreOpen store cfg >>= either (assertFailure . show) (\p ->
    case planVerdict p of
      VerdictIdentityRefused (RefuseLabelChanged (TokenId 1) _ "haskoki-async" "haskoki-demo") -> pure ()
      other -> assertFailure ("standard config: wrong verdict: " ++ show other))
  r <- checkStoreOpen store (asyncHomeConfig cfg)
  plan <- either (assertFailure . show) pure r
  assertEqual "rowless" [TokenId 1] (sopAbsentCredentials plan)
  assertEqual "ops" [OpFreezeCredentials [TokenId 1], OpSetSchemaVersion 2 3] (sopOps plan)
  assertEqual "verdict" VerdictMigrationRequired (planVerdict plan)
  assertNoPins "renderPlan" (renderPlan plan)

-- A store this build's async open creates: schema 3 with the home
-- credential row seeded, so nothing to migrate.
casePlanAsyncSeededV3 :: IO ()
casePlanAsyncSeededV3 = withScratch "plan" $ \dir -> do
  let store = dir </> "store.db"
      (_, so, user) = homeCatalogEntry
  makeSchemaStore 3 store [fixtureToken 1 0 "haskoki-async"]
    [CredentialRecord (TokenId 1) (BC8.pack so) (Just (BC8.pack user))]
  std <- writeStoreConfig (dir </> "s.toml") store ["haskoki-demo"] ["5678"] ["1234"]
  cfg <- loadConfigOrFail std
  r <- checkStoreOpen store (asyncHomeConfig cfg)
  plan <- either (assertFailure . show) pure r
  assertEqual "no ops" [] (sopOps plan)
  assertEqual "verdict" VerdictOpenable (planVerdict plan)
  checkStoreOpen store cfg >>= either (assertFailure . show) (\p ->
    case planVerdict p of
      VerdictIdentityRefused (RefuseLabelChanged {}) -> pure ()
      other -> assertFailure ("standard config: wrong verdict: " ++ show other))

caseAsyncHomeEntry :: IO ()
caseAsyncHomeEntry = withScratch "plan" $ \dir -> do
  let (label, so, user) = asyncHomeEntry
      (_, hso, huser) = homeCatalogEntry
  assertEqual "label" "haskoki-async" label
  assertEqual "pins" (hso, huser) (so, user)
  cfgPath <- writeStoreConfig (dir </> "c.toml") (dir </> "s.db") fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  assertEqual "catalog" [(SlotId 0, (TokenId 1, "haskoki-async"))]
    (Map.toList (identityCatalog (asyncHomeConfig cfg)))

casePlanMissingPath :: IO ()
casePlanMissingPath = withScratch "plan" $ \dir -> do
  let store = dir </> "absent.db"
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  r <- checkStoreOpen store cfg
  case r of
    Left (StoreIO m) -> assertBool "names the missing store" ("no store file" `isInfixOf` m)
    other -> assertFailure ("wrong result: " ++ show (fmap sopPath other))
  exists <- doesFileExist store
  assertBool "check created nothing" (not exists)

foreign import ccall unsafe "flock" c_flockT :: CInt -> CInt -> IO CInt

casePlanLiveOwner :: IO ()
casePlanLiveOwner = withScratch "plan" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  cfg <- loadConfigOrFail cfgPath
  bracket (openFd store ReadOnly defaultFileFlags) closeFd $ \fd -> do
    rc <- c_flockT (fromIntegral fd) 2 -- LOCK_EX
    assertEqual "test holds the db lock" 0 rc
    r <- checkStoreOpen store cfg
    case r of
      Left (StoreSecondWriter m) -> assertBool "says in use" ("in use" `isInfixOf` m)
      other -> assertFailure ("wrong result: " ++ show (fmap sopPath other))

caseStoreFullTag :: IO ()
caseStoreFullTag = do
  assertEqual "store-full" "store-full" (fst (renderStoreRefusal (StoreFull "disk full")))
  assertEqual "io" "store-unreadable" (fst (renderStoreRefusal (StoreIO "x")))

v1Tokens :: [TokenRecord]
v1Tokens = [fixtureToken 1 0 "haskoki-demo", fixtureToken 2 1 "haskoki-ops"]

frozen :: [CredentialRecord]
frozen =
  [ CredentialRecord (TokenId 1) "58213946" (Just "12873465")
  , CredentialRecord (TokenId 2) "69324057" (Just "23984576") ]

runOwned :: FilePath -> SQLiteMigration -> MigrationHooks -> IO (Either StoreError ())
runOwned store mig hooks = do
  r <- withOwnedStoreFile store (\o -> migrateOwned o mig hooks)
  pure (either Left id r)

caseOwnedMigratesV1 :: IO ()
caseOwnedMigratesV1 = withScratch "owned" $ \dir -> do
  let store = dir </> "store.db"; fresh = dir </> "fresh.db"
  makeSchemaStore 1 store v1Tokens []
  rawExec store "INSERT INTO store_meta(key, value) VALUES ('p6-migration-marker', 'kept')"
  objBefore <- roTexts store "SELECT object_id FROM objects ORDER BY object_id"
  runOwned store (SQLiteMigration 1 frozen) noMigrationHooks >>= assertEqual "migrated" (Right ())
  roTexts store "SELECT value FROM store_meta WHERE key = 'schema_version'" >>= assertEqual "marker" ["3"]
  roTexts store "SELECT value FROM store_meta WHERE key = 'p6-migration-marker'" >>= assertEqual "meta kept" ["kept"]
  roTexts store "SELECT object_id FROM objects ORDER BY object_id" >>= assertEqual "objects kept" objBefore
  lockLeft <- doesFileExist (store ++ ".lock")
  assertBool "ownership released" (not lockLeft)
  makeSchemaStore 3 fresh [] []
  let ddl p = sort <$> roTexts p "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
  m <- ddl store
  f <- ddl fresh
  assertEqual "migrated schema equals fresh" f m
  e <- openSQLiteStore store
  s <- either (assertFailure . show) pure e
  creds <- storeLoadCredentials s
  storeClose s
  assertBool "frozen rows load" (creds == Right frozen)

caseOwnedMigratesV2KeepsRow :: IO ()
caseOwnedMigratesV2KeepsRow = withScratch "owned" $ \dir -> do
  let store = dir </> "store.db"
      kept = CredentialRecord (TokenId 2) "69324057" (Just "34095687")
  makeSchemaStore 2 store v1Tokens [kept]
  docBefore <- roTexts store "SELECT record_json FROM credentials WHERE token_id = '0000000000000002'"
  runOwned store (SQLiteMigration 2 (take 1 frozen)) noMigrationHooks >>= assertEqual "migrated" (Right ())
  docAfter <- roTexts store "SELECT record_json FROM credentials WHERE token_id = '0000000000000002'"
  assertBool "existing row byte-exact" (docBefore == docAfter)
  roTexts store "SELECT token_id FROM credentials ORDER BY token_id"
    >>= assertEqual "both rows" ["0000000000000001", "0000000000000002"]

caseOwnedMigratesAsync :: IO ()
caseOwnedMigratesAsync = withScratch "owned" $ \dir -> do
  let store = dir </> "store.db"
      (label, so, user) = asyncHomeEntry
      row = CredentialRecord (TokenId 1) (BC8.pack so) (Just (BC8.pack user))
  makeSchemaStore 2 store [fixtureToken 1 0 label] []
  runOwned store (SQLiteMigration 2 [row]) noMigrationHooks >>= assertEqual "migrated" (Right ())
  roTexts store "SELECT value FROM store_meta WHERE key = 'schema_version'" >>= assertEqual "marker" ["3"]
  e <- openSQLiteStore store
  s <- either (assertFailure . show) pure e
  creds <- storeLoadCredentials s
  storeClose s
  assertEqual "async home credentials read back" (Right [row]) creds

caseOwnedFreezesAtV3 :: IO ()
caseOwnedFreezesAtV3 = withScratch "owned" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 3 store v1Tokens []
  runOwned store (SQLiteMigration 3 frozen) noMigrationHooks >>= assertEqual "frozen" (Right ())
  roTexts store "SELECT value FROM store_meta WHERE key = 'schema_version'" >>= assertEqual "marker" ["3"]
  roTexts store "SELECT token_id FROM credentials ORDER BY token_id"
    >>= assertEqual "rows" ["0000000000000001", "0000000000000002"]

caseOwnedRefusesReplacingRow :: IO ()
caseOwnedRefusesReplacingRow = withScratch "owned" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 2 store v1Tokens [CredentialRecord (TokenId 2) "69324057" (Just "34095687")]
  before <- captureState store
  r <- runOwned store (SQLiteMigration 2 frozen) noMigrationHooks
  case r of
    Left (StoreIO msg) | "UNIQUE" `isInfixOf` msg || "constraint" `isInfixOf` msg -> pure ()
    other -> assertFailure ("not the constraint refusal: " ++ show other)
  assertUnchanged "aborted migration" before store

caseOwnedSchemaMoved :: IO ()
caseOwnedSchemaMoved = withScratch "owned" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 2 store v1Tokens []
  before <- captureState store
  r <- runOwned store (SQLiteMigration 1 frozen) noMigrationHooks
  case r of
    Left (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("wrong result: " ++ show other)
  assertUnchanged "schema moved" before store

caseOwnedCrashRollsBack :: IO ()
caseOwnedCrashRollsBack = withScratch "owned" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 1 store v1Tokens []
  before <- captureState store
  let crash = noMigrationHooks { mgBeforeCommit = \_ -> throwIO (userError "simulated crash") }
  r <- try (runOwned store (SQLiteMigration 1 frozen) crash) :: IO (Either IOException (Either StoreError ()))
  case r of
    Left _ -> pure ()
    Right other -> assertFailure ("crash did not propagate: " ++ show other)
  assertUnchanged "crashed migration" before store
  again <- runOwned store (SQLiteMigration 1 frozen) noMigrationHooks
  assertEqual "ownership was released; retry migrates" (Right ()) again

caseOwnedFullDisk :: IO ()
caseOwnedFullDisk = withScratch "owned" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 1 store v1Tokens []
  -- the schema-1 fixture dropped a table: compact so the file has no
  -- free pages and any new table must grow it
  rawExec store "VACUUM"
  before <- captureState store
  let full = noMigrationHooks { mgAfterBegin = \db -> do
        n <- pragmaInt db "PRAGMA page_count"
        S.exec db (T.pack ("PRAGMA max_page_count = " ++ show (n + 1))) }
  r <- runOwned store (SQLiteMigration 1 frozen) full
  case r of
    Left (StoreFull _) -> pure ()
    other -> assertFailure ("wrong result: " ++ show other)
  assertUnchanged "full disk" before store

caseOwnedRefusesLive :: IO ()
caseOwnedRefusesLive = withScratch "owned" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 3 store v1Tokens []
  e <- openSQLiteStore store
  s <- either (assertFailure . show) pure e
  r <- withOwnedStoreFile store (\_ -> pure ())
  storeClose s
  case r of
    Left (StoreSecondWriter _) -> pure ()
    other -> assertFailure ("live owner not refused: " ++ show other)

caseOwnedNeverCreates :: IO ()
caseOwnedNeverCreates = withScratch "owned" $ \dir -> do
  let store = dir </> "absent.db"
  r <- withOwnedStoreFile store (\_ -> pure ())
  case r of
    Left (StoreIO _) -> pure ()
    other -> assertFailure ("wrong result: " ++ show other)
  created <- (||) <$> doesFileExist store <*> doesFileExist (store ++ ".lock")
  assertBool "nothing created" (not created)

-- | The redaction check counts a PIN only as a whole number: no
-- digit directly before or after it.
caseNoPinsDigitBoundary :: IO ()
caseNoPinsDigitBoundary = do
  r <- try (assertNoPins "self-test" "x1234y") :: IO (Either HUnitFailure ())
  assertBool "a bounded PIN is detected" (either (const True) (const False) r)
  assertNoPins "self-test" "a-512345-b"
  assertNoPins "self-test" "/tmp/migrate-9582139460-0/store.sqlite"
  edge <- try (assertNoPins "self-test" "58213946") :: IO (Either HUnitFailure ())
  assertBool "a PIN filling the text is detected" (either (const True) (const False) edge)

fixedClock :: MigrateHooks
fixedClock = noMigrateHooks { mhClock = pure 1700000000 }

listBackups :: FilePath -> IO [FilePath]
listBackups d = sort <$> listDirectory d

migrateFixture :: String -> FilePath -> IO (FilePath, FilePath, FilePath, MigrationReceipt, BS.ByteString)
migrateFixture tag dir = do
  (store, cfgPath) <- copyReleasedFixture tag dir
  let backups = dir </> "backups"
  createDirectory backups
  pre <- BS.readFile store
  cfg <- loadConfigOrFail cfgPath
  r <- migrateStoreWith fixedClock store cfg backups
  receipt <- case r of
    Right (Migrated rc) -> pure rc
    other -> assertFailure ("migration failed: " ++ show other)
  pure (store, cfgPath, backups, receipt, pre)

caseMigrateV04 :: IO ()
caseMigrateV04 = withScratch "migrate" $ \dir -> do
  (store, cfgPath, backups, rc, pre) <- migrateFixture "v0.4.0.0" dir
  assertEqual "from" 2 (mrFrom rc)
  assertEqual "to" 3 (mrTo rc)
  assertEqual "frozen" [TokenId 1] (mrFrozen rc)
  assertEqual "preserved" [TokenId 2] (mrPreserved rc)
  assertEqual "backup name" (backups </> "store.sqlite.pre-migrate.schema2.1700000000.bak") (mrBackup rc)
  assertEqual "receipt name" (mrBackup rc ++ ".receipt") (mrReceipt rc)
  assertEqual "epoch" 1700000000 (mrEpoch rc)
  assertEqual "backup bytes" (BS.length pre) (mrBackupBytes rc)
  BS.readFile (mrBackup rc) >>= \b -> assertBool "backup equals the pre-migration bytes" (b == pre)
  sha256Hex pre >>= assertEqual "receipt digest" (Right (mrBackupSha256 rc))
  receiptText <- readFile (mrReceipt rc)
  assertEqual "receipt file is the rendering" (renderReceipt rc) receiptText
  assertBool "receipt names the digest" (("backup-sha256: " ++ mrBackupSha256 rc) `isInfixOf` receiptText)
  assertBool "receipt names the frozen id" ("frozen-credentials: 0000000000000001" `isInfixOf` receiptText)
  assertBool "receipt names the kept id" ("preserved-credentials: 0000000000000002" `isInfixOf` receiptText)
  assertNoPins "receipt" receiptText
  assertNoPins "show receipt" (show rc)
  mode <- fileMode <$> getFileStatus (mrReceipt rc)
  assertEqual "receipt is private" 0o600 (mode .&. 0o777)
  bmode <- fileMode <$> getFileStatus (mrBackup rc)
  assertEqual "backup is private" 0o600 (bmode .&. 0o777)
  listBackups backups >>= assertEqual "exactly the backup and its receipt"
    ["store.sqlite.pre-migrate.schema2.1700000000.bak", "store.sqlite.pre-migrate.schema2.1700000000.bak.receipt"]
  roTexts store "SELECT value FROM store_meta WHERE key = 'schema_version'" >>= assertEqual "marker" ["3"]
  -- durable authority: token 1 frozen from config, token 2 keeps its in-band PIN
  e <- openSQLiteStore store
  s <- either (assertFailure . show) pure e
  creds <- storeLoadCredentials s
  storeClose s
  assertBool "credential rows"
    (creds == Right [ CredentialRecord (TokenId 1) "58213946" (Just "12873465")
                    , CredentialRecord (TokenId 2) "69324057" (Just "34095687") ])
  cfg <- loadConfigOrFail cfgPath
  openReconciled store cfg >>= either (assertFailure . show) closeAcquired
  lockLeft <- doesFileExist (store ++ ".lock")
  assertBool "ownership released" (not lockLeft)

caseMigrateV031 :: IO ()
caseMigrateV031 = withScratch "migrate" $ \dir -> do
  (store, cfgPath, backups, rc, _) <- migrateFixture "v0.3.1.0" dir
  assertEqual "from" 1 (mrFrom rc)
  assertEqual "frozen" [TokenId 1, TokenId 2] (mrFrozen rc)
  assertEqual "preserved" [] (mrPreserved rc)
  assertEqual "backup name" (backups </> "store.sqlite.pre-migrate.schema1.1700000000.bak") (mrBackup rc)
  readFile (mrReceipt rc) >>= \t -> assertBool "nothing preserved" ("preserved-credentials: none" `isInfixOf` t)
  cfg <- loadConfigOrFail cfgPath
  openReconciled store cfg >>= either (assertFailure . show) closeAcquired

-- A supported migrate input: the marker is already 3, so the
-- migration only freezes the rowless token's credentials.
caseMigrateSchema3Rowless :: IO ()
caseMigrateSchema3Rowless = withScratch "migrate" $ \dir -> do
  let store = dir </> "store.sqlite"; backups = dir </> "backups"
      kept = CredentialRecord (TokenId 2) "69324057" (Just "34095687")
  createDirectory backups
  makeSchemaStore 3 store [fixtureToken 1 0 "haskoki-demo", fixtureToken 2 1 "haskoki-ops"] [kept]
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  r <- migrateStoreWith fixedClock store cfg backups
  rc <- case r of
    Right (Migrated rc) -> pure rc
    other -> assertFailure ("migration failed: " ++ show other)
  assertEqual "from" 3 (mrFrom rc)
  assertEqual "to" 3 (mrTo rc)
  assertEqual "frozen" [TokenId 1] (mrFrozen rc)
  assertEqual "preserved" [TokenId 2] (mrPreserved rc)
  assertEqual "backup name" (backups </> "store.sqlite.pre-migrate.schema3.1700000000.bak") (mrBackup rc)
  readFile (mrReceipt rc) >>= \t -> assertBool "schema-from 3" ("schema-from: 3\n" `isInfixOf` t)
  roTexts store "SELECT value FROM store_meta WHERE key = 'schema_version'" >>= assertEqual "marker" ["3"]
  e <- openSQLiteStore store
  s <- either (assertFailure . show) pure e
  creds <- storeLoadCredentials s
  storeClose s
  assertBool "rows frozen, in-band row kept"
    (creds == Right [CredentialRecord (TokenId 1) "58213946" (Just "12873465"), kept])
  openReconciled store cfg >>= either (assertFailure . show) closeAcquired

-- A store the v0.4 async open created (label haskoki-async, no
-- credential row) migrates end to end under the async home catalog,
-- freezing the async home PINs.
caseMigrateAsyncV04 :: IO ()
caseMigrateAsyncV04 = withScratch "migrate" $ \dir -> do
  let store = dir </> "store.sqlite"; backups = dir </> "backups"
      (label, so, user) = asyncHomeEntry
  createDirectory backups
  makeSchemaStore 2 store [fixtureToken 1 0 label] []
  cfgPath <- writeStoreConfig (dir </> "c.toml") store ["haskoki-demo"] ["58213946"] ["12873465"]
  cfg <- loadConfigOrFail cfgPath
  before <- captureState store
  std <- migrateStore store cfg backups
  case std of
    Left (MigrateIdentityRefused (RefuseLabelChanged (TokenId 1) _ "haskoki-async" "haskoki-demo")) -> pure ()
    other -> assertFailure ("standard catalog: " ++ show other)
  expectRefusedClean store backups before
  r <- migrateStoreWith fixedClock store (asyncHomeConfig cfg) backups
  rc <- case r of
    Right (Migrated rc) -> pure rc
    other -> assertFailure ("migration failed: " ++ show other)
  assertEqual "from" 2 (mrFrom rc)
  assertEqual "frozen" [TokenId 1] (mrFrozen rc)
  assertEqual "preserved" [] (mrPreserved rc)
  assertNoPins "receipt" (renderReceipt rc)
  roTexts store "SELECT value FROM store_meta WHERE key = 'schema_version'" >>= assertEqual "marker" ["3"]
  e <- openSQLiteStore store
  s <- either (assertFailure . show) pure e
  creds <- storeLoadCredentials s
  storeClose s
  assertBool "async home PINs frozen"
    (creds == Right [CredentialRecord (TokenId 1) (BC8.pack so) (Just (BC8.pack user))])
  checkStoreOpen store (asyncHomeConfig cfg) >>= either (assertFailure . show)
    (assertEqual "openable after migration" VerdictOpenable . planVerdict)

caseMigrateNotNeeded :: IO ()
caseMigrateNotNeeded = withScratch "migrate" $ \dir -> do
  let store = dir </> "store.sqlite"; backups = dir </> "backups"
  createDirectory backups
  cfgPath <- writeStoreConfig (dir </> "c.toml") store fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  openReconciled store cfg >>= either (assertFailure . show) closeAcquired
  before <- captureState store
  migrateStore store cfg backups >>= assertEqual "not needed" (Right MigrateNotNeeded)
  listBackups backups >>= assertEqual "no backup" []
  assertUnchanged "not needed" before store

-- | Shared: a refused migration wrote nothing anywhere.
expectRefusedClean :: FilePath -> FilePath -> StoreState -> IO ()
expectRefusedClean store backups before = do
  assertUnchanged "refused migration" before store
  listBackups backups >>= assertEqual "backup dir untouched" []

caseMigrateRefusesIdentityDrift :: IO ()
caseMigrateRefusesIdentityDrift = withScratch "migrate" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  cfgPath <- writeStoreConfig (dir </> "d.toml") store ["haskoki-demo", "haskoki-ops-renamed"] fixtureSo fixtureUser
  cfg <- loadConfigOrFail cfgPath
  before <- captureState store
  r <- migrateStore store cfg backups
  case r of
    Left (MigrateIdentityRefused (RefuseLabelChanged (TokenId 2) _ _ _)) -> pure ()
    other -> assertFailure ("wrong result: " ++ show other)
  expectRefusedClean store backups before

caseMigrateRefusesConfigMismatch :: IO ()
caseMigrateRefusesConfigMismatch = withScratch "migrate" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  other <- writeStoreConfig (dir </> "o.toml") (dir </> "original.sqlite") fixtureLabels fixtureSo fixtureUser
  cfg <- loadConfigOrFail other
  before <- captureState store
  r <- migrateStore store cfg backups
  case r of
    Left (MigrateConfig (ConfigPathMismatch _ _)) -> pure ()
    bad -> assertFailure ("wrong result: " ++ show bad)
  expectRefusedClean store backups before

caseMigrateUnsafeBackupDirs :: IO ()
caseMigrateUnsafeBackupDirs = withScratch "migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  cfg <- loadConfigOrFail cfgPath
  let real = dir </> "real"; aFile = dir </> "a-file"; link = dir </> "link"; ro = dir </> "ro"
  createDirectory real
  writeFile aFile "x"
  createSymbolicLink real link
  createDirectory ro
  before <- captureState store
  let expectUnsafe d = do
        r <- migrateStore store cfg d
        case r of
          Left (MigrateUnsafeBackupDir _ _) -> pure ()
          other -> assertFailure (d ++ ": " ++ show other)
  mapM_ expectUnsafe [dir </> "missing", aFile, link, dir]
  euid <- getEffectiveUserID
  if euid == 0
    then putStrLn "skipped the read-only directory: mode 0555 does not deny root"
    else withFileMode ro 0o555 (expectUnsafe ro)
  assertUnchanged "unsafe backup dirs" before store
  listBackups real >>= assertEqual "nothing written through the link" []
  listBackups ro >>= assertEqual "nothing written in ro" []
  readFile aFile >>= assertEqual "the file is untouched" "x"
  listBackups dir >>= assertEqual "nothing new beside the store"
    ["a-file", "config.toml", "link", "real", "ro", "store.sqlite"]

caseMigrateLiveOwner :: IO ()
caseMigrateLiveOwner = withScratch "migrate" $ \dir -> do
  let store = dir </> "store.sqlite"; backups = dir </> "backups"
  createDirectory backups
  makeSchemaStore 2 store [fixtureToken 1 0 "haskoki-demo"] []
  rawExec store "UPDATE store_meta SET value = '3' WHERE key = 'schema_version'"
  e <- openSQLiteStore store   -- schema 3 now: the serving open accepts it
  s <- either (assertFailure . show) pure e
  rawExec store "UPDATE store_meta SET value = '2' WHERE key = 'schema_version'"
  cfgPath <- writeStoreConfig (dir </> "c.toml") store ["haskoki-demo"] ["58213946"] ["12873465"]
  cfg <- loadConfigOrFail cfgPath
  r <- migrateStore store cfg backups
  storeClose s
  case r of
    Left (MigrateStore (StoreSecondWriter _)) -> pure ()
    other -> assertFailure ("live owner not refused: " ++ show other)
  listBackups backups >>= assertEqual "no backup" []
  roTexts store "SELECT value FROM store_meta WHERE key = 'schema_version'" >>= assertEqual "unmigrated" ["2"]

-- The owned transaction does not refuse a hot journal itself (its
-- SQLite open would roll it back); the read-only recheck refuses
-- first, before ownership, and leaves both files as they were.
caseMigrateHotJournal :: IO ()
caseMigrateHotJournal = withScratch "migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"; journal = store ++ "-journal"
  createDirectory backups
  cfg <- loadConfigOrFail cfgPath
  BS.writeFile journal "\217\213\5\249 interrupted"
  dbBefore <- BS.readFile store
  jBefore <- BS.readFile journal
  planned <- newIORef False
  let watch = fixedClock { mhAfterPlan = atomicModifyIORef' planned (const (True, ())) }
  r <- migrateStoreWith watch store cfg backups
  assertEqual "refused" (Left (MigrateStore (StoreJournalPresent journal))) r
  readIORef planned >>= assertBool "refused by the unowned check, before ownership" . not
  BS.readFile store >>= \b -> assertBool "db untouched" (b == dbBefore)
  BS.readFile journal >>= \j -> assertBool "journal untouched" (j == jBefore)
  listBackups backups >>= assertEqual "no backup" []
  lockLeft <- doesFileExist (store ++ ".lock")
  assertBool "no lock left" (not lockLeft)
  assertEqual "tag" "store-journal-present"
    (fst (renderMigrateError (MigrateStore (StoreJournalPresent journal))))
  -- a journal that appears after the plan: the owned recheck refuses
  -- it before the backup and before any SQLite write open
  removeFile journal
  let late = fixedClock { mhAfterPlan = BS.writeFile journal jBefore }
  r2 <- migrateStoreWith late store cfg backups
  assertEqual "late journal refused" (Left (MigrateStore (StoreJournalPresent journal))) r2
  BS.readFile store >>= \b -> assertBool "db untouched (late)" (b == dbBefore)
  BS.readFile journal >>= \j -> assertBool "journal untouched (late)" (j == jBefore)
  listBackups backups >>= assertEqual "no backup (late)" []

-- A zero-byte leftover journal is not hot (SQLite ignores it), so it
-- does not block the migration.
caseMigrateZeroByteJournal :: IO ()
caseMigrateZeroByteJournal = withScratch "migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  cfg <- loadConfigOrFail cfgPath
  BS.writeFile (store ++ "-journal") BS.empty
  r <- migrateStoreWith fixedClock store cfg backups
  case r of
    Right (Migrated rc) -> assertEqual "frozen" [TokenId 1] (mrFrozen rc)
    other -> assertFailure ("zero-byte journal blocked the migration: " ++ show other)
  roTexts store "SELECT value FROM store_meta WHERE key = 'schema_version'" >>= assertEqual "marker" ["3"]

caseMigrateStoreChanged :: IO ()
caseMigrateStoreChanged = withScratch "migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  cfg <- loadConfigOrFail cfgPath
  let poke = noMigrateHooks { mhAfterPlan = rawExec store "INSERT INTO store_meta(key, value) VALUES ('poke', '1')" }
  r <- migrateStoreWith poke store cfg backups
  assertEqual "changed store refused" (Left MigrateStoreChanged) r
  listBackups backups >>= assertEqual "no backup" []
  roTexts store "SELECT value FROM store_meta WHERE key = 'schema_version'" >>= assertEqual "unmigrated" ["2"]
  lockLeft <- doesFileExist (store ++ ".lock")
  assertBool "ownership released" (not lockLeft)

caseMigrateNeverOverwrites :: IO ()
caseMigrateNeverOverwrites = withScratch "migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
      taken = backups </> "store.sqlite.pre-migrate.schema2.1700000000.bak"
      orphan = backups </> "store.sqlite.pre-migrate.schema2.1700000000-1.bak.receipt"
  createDirectory backups
  writeFile taken "keep"
  writeFile orphan "keep receipt"
  cfg <- loadConfigOrFail cfgPath
  r <- migrateStoreWith fixedClock store cfg backups
  case r of
    Right (Migrated rc) ->
      assertEqual "next free name (a taken receipt name skips its backup name too)"
        (backups </> "store.sqlite.pre-migrate.schema2.1700000000-2.bak") (mrBackup rc)
    other -> assertFailure (show other)
  readFile taken >>= assertEqual "existing file untouched" "keep"
  readFile orphan >>= assertEqual "existing receipt untouched" "keep receipt"

-- Every one of the 100 names is taken (by a backup or by a receipt):
-- refuse, write nothing, change nothing.
caseMigrateBackupNamesExhausted :: IO ()
caseMigrateBackupNamesExhausted = withScratch "migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
      names = backupCandidates store backups 2 1700000000
  createDirectory backups
  mapM_ (\(k, c) -> writeFile (if even k then c else c ++ ".receipt") "taken") (zip [0 :: Int ..] names)
  existing <- listBackups backups
  assertEqual "100 names taken" 100 (length existing)
  cfg <- loadConfigOrFail cfgPath
  before <- captureState store
  r <- migrateStoreWith fixedClock store cfg backups
  case r of
    Left err@(MigrateBackupExists first) -> do
      assertEqual "names the first candidate" (backups </> "store.sqlite.pre-migrate.schema2.1700000000.bak") first
      assertEqual "tag" "migrate-backup-exists" (fst (renderMigrateError err))
    other -> assertFailure ("wrong result: " ++ show other)
  assertUnchanged "names exhausted" before store
  listBackups backups >>= assertEqual "backup dir unchanged" existing

-- No real-to-synthetic fallback: without a digest there is no backup
-- and no migration.
caseMigrateHashFailure :: IO ()
caseMigrateHashFailure = withScratch "migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  cfg <- loadConfigOrFail cfgPath
  before <- captureState store
  let noDigest = fixedClock { mhDigest = \_ -> pure (Left "SHA-256 engine unavailable: test") }
  r <- migrateStoreWith noDigest store cfg backups
  case r of
    Left err@(MigrateBackupFailed why) -> do
      assertBool "names the hashing failure" ("SHA-256 engine unavailable" `isInfixOf` why)
      assertEqual "tag" "migrate-backup-failed" (fst (renderMigrateError err))
    other -> assertFailure ("wrong result: " ++ show other)
  expectRefusedClean store backups before

-- One clock read per migration: the backup name and the receipt
-- epoch come from the same reading.
caseMigrateClockOnce :: IO ()
caseMigrateClockOnce = withScratch "migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  cfg <- loadConfigOrFail cfgPath
  ticks <- newIORef (1700000000 :: Integer)
  let ticking = noMigrateHooks { mhClock = atomicModifyIORef' ticks (\t -> (t + 7, t)) }
  r <- migrateStoreWith ticking store cfg backups
  rc <- case r of
    Right (Migrated rc) -> pure rc
    other -> assertFailure ("migration failed: " ++ show other)
  assertEqual "epoch" 1700000000 (mrEpoch rc)
  assertEqual "backup name carries the same epoch"
    (backups </> "store.sqlite.pre-migrate.schema2.1700000000.bak") (mrBackup rc)
  readIORef ticks >>= assertEqual "read exactly once" 1700000007

caseMigrateTxnFailureKeepsStore :: IO ()
caseMigrateTxnFailureKeepsStore = withScratch "migrate" $ \dir -> do
  (store, cfgPath) <- copyReleasedFixture "v0.3.1.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  cfg <- loadConfigOrFail cfgPath
  before <- captureState store
  let full = fixedClock { mhSQLite = noMigrationHooks { mgAfterBegin = \db -> do
        n <- pragmaInt db "PRAGMA page_count"
        S.exec db (T.pack ("PRAGMA max_page_count = " ++ show n)) } }
  r <- migrateStoreWith full store cfg backups
  bak <- case r of
    Left (MigrateTxnFailed b (StoreFull _)) -> pure b
    other -> assertFailure ("wrong result: " ++ show other)
  assertUnchanged "failed transaction" before store
  BS.readFile bak >>= \b -> assertBool "backup kept and complete" (b == ssBytes before)
  receipts <- filter (".receipt" `isSuffixOf`) <$> listBackups backups
  assertEqual "no receipt" [] receipts
  r2 <- migrateStoreWith fixedClock store cfg backups
  case r2 of
    Right (Migrated rc) -> assertBool "a new backup name" (mrBackup rc /= bak)
    other -> assertFailure ("retry: " ++ show other)

caseMigrateLeavesSeedsToOpen :: IO ()
caseMigrateLeavesSeedsToOpen = withScratch "migrate" $ \dir -> do
  (store, _) <- copyReleasedFixture "v0.4.0.0" dir
  let backups = dir </> "backups"
  createDirectory backups
  cfgPath <- writeStoreConfig (dir </> "s.toml") store
    (fixtureLabels ++ ["haskoki-audit"]) (fixtureSo ++ ["70435168"]) (fixtureUser ++ ["81546279"])
  cfg <- loadConfigOrFail cfgPath
  r <- migrateStore store cfg backups
  case r of
    Right (Migrated rc) -> assertEqual "frozen only stored rowless" [TokenId 1] (mrFrozen rc)
    other -> assertFailure (show other)
  roTexts store "SELECT token_id FROM tokens ORDER BY token_id"
    >>= assertEqual "migrate created no token" ["0000000000000001", "0000000000000002"]
  openReconciled store cfg >>= either (assertFailure . show) closeAcquired
  roTexts store "SELECT token_id FROM credentials ORDER BY token_id"
    >>= assertEqual "the open seeded token 3 with its row"
          ["0000000000000001", "0000000000000002", "0000000000000003"]

caseBackupCandidates :: IO ()
caseBackupCandidates = do
  let cs = backupCandidates "/srv/t/token.sqlite" "/b" 2 1700000000
  assertEqual "count" 100 (length cs)
  case cs of
    (c0 : c1 : _) -> do
      assertEqual "first" "/b/token.sqlite.pre-migrate.schema2.1700000000.bak" c0
      assertEqual "second" "/b/token.sqlite.pre-migrate.schema2.1700000000-1.bak" c1
    _ -> assertFailure "fewer than two candidates"
  assertEqual "last" ["/b/token.sqlite.pre-migrate.schema2.1700000000-99.bak"] (drop 99 cs)
  assertEqual "distinct" 100 (length (nub cs))

caseMigrateErrorRender :: IO ()
caseMigrateErrorRender = do
  let bak = "/b/store.sqlite.pre-migrate.schema2.1700000000.bak"
      cases =
        [ (MigrateConfig ConfigNoPath, "config-mismatch")
        , (MigrateUnsafeBackupDir "/b" "is not writable", "migrate-unsafe-backup-dir")
        , (MigrateStore (StoreNeedsMigration 2 3), "store-migration-required")
        , (MigrateIdentityRefused (RefuseLabelChanged (TokenId 2) (SlotId 1) "haskoki-ops" "x"), "store-identity-refused")
        , (MigrateStoreChanged, "migrate-store-changed")
        , (MigrateBackupExists bak, "migrate-backup-exists")
        , (MigrateBackupFailed "cannot write", "migrate-backup-failed")
        , (MigrateTxnFailed bak (StoreFull "disk full"), "migrate-failed")
        , (MigrateVerifyFailed bak "schema marker not advanced", "migrate-verify-failed")
        , (MigrateReceiptFailed bak "disk full", "migrate-receipt-failed")
        ]
  mapM_ (\(err, tag) -> do
          let (t, detail) = renderMigrateError err
          assertEqual ("tag of " ++ show err) tag t
          assertNoPins ("render of " ++ show err) detail
          assertNoPins "show" (show err)) cases
  mapM_ (\err -> assertBool ("names the backup: " ++ show err) (bak `isInfixOf` snd (renderMigrateError err)))
    [MigrateTxnFailed bak (StoreFull "disk full"), MigrateVerifyFailed bak "x", MigrateReceiptFailed bak "x"]
