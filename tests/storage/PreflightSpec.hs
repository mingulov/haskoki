{-# LANGUAGE OverloadedStrings #-}
{- | Store preflight, explicit migration and recovery (AC-05):
released-binary fixtures, refused opens that write nothing, the
read-only snapshot and plan, the owned migration, and recovery.
-}
module PreflightSpec (spec) where

import qualified Data.ByteString as BS
import Data.List (isInfixOf)
import qualified Data.Text as T
import System.Directory (createDirectory, doesFileExist)
import System.FilePath ((</>))
import System.Posix.Files (createSymbolicLink)
import System.Posix.Files (getFileStatus, modificationTime)
import Test.Tasty (DependencyType (AllFinish), TestTree, after, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.FFI.Standard (StdStoreError (..))
import Haskoki.Runtime.Storage
  (CommitResult (..), CredentialRecord (..), IdentityRefusal (..), StoreError (..), TokenRecord (..), emptyDelta, storeClose, storeCommit)
import Haskoki.Types (TokenId (..))
import Haskoki.Runtime.Config (Config (..), StorageCfg (..), StorageKind (..))
import Haskoki.Runtime.Storage.Preflight
  ( MigrationOp (..), PlanVerdict (..), PreflightRefusal (..), StoreOpenPlan (..)
  , checkStoreOpen, configSelectsStore, planVerdict, renderPlan, renderStoreRefusal, sha256Hex )
import Haskoki.Runtime.Storage.SQLite
  (OwnerState (..), StoreSnapshot (..), openSQLiteStore, probeOwner, readStoreSnapshot)

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
      , testCase "an async-created store is not migration-required" casePlanAsyncCreated
      , testCase "store-full has its own refusal tag" caseStoreFullTag
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
  writeFile (store ++ ".lock") "1\n"
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

-- A store the async open created (home label haskoki-async, the
-- home credential row seeded in the same commit) has its rows, so no
-- freeze or version move is planned. Against the standard catalog
-- (slot 0 must be haskoki-demo) the verdict is an identity refusal,
-- never migration-required.
casePlanAsyncCreated :: IO ()
casePlanAsyncCreated = withScratch "plan" $ \dir -> do
  let store = dir </> "store.db"
  makeSchemaStore 3 store [fixtureToken 1 0 "haskoki-async"]
    [CredentialRecord (TokenId 1) "5678" (Just "1234")]
  std <- writeStoreConfig (dir </> "s.toml") store ["haskoki-demo"] ["5678"] ["1234"]
  cfg <- loadConfigOrFail std
  r <- checkStoreOpen store cfg
  plan <- either (assertFailure . show) pure r
  assertEqual "no absent credentials" [] (sopAbsentCredentials plan)
  assertEqual "no ops" [] (sopOps plan)
  case planVerdict plan of
    VerdictIdentityRefused (RefuseLabelChanged (TokenId 1) _ "haskoki-async" "haskoki-demo") -> pure ()
    other -> assertFailure ("wrong verdict: " ++ show other)

caseStoreFullTag :: IO ()
caseStoreFullTag = do
  assertEqual "store-full" "store-full" (fst (renderStoreRefusal (StoreFull "disk full")))
  assertEqual "io" "store-unreadable" (fst (renderStoreRefusal (StoreIO "x")))
