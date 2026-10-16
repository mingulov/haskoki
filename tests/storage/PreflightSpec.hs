{-# LANGUAGE OverloadedStrings #-}
{- | Store preflight, explicit migration and recovery (AC-05):
released-binary fixtures, refused opens that write nothing, the
read-only snapshot and plan, the owned migration, and recovery.
-}
module PreflightSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Text as T
import System.Directory (createDirectory, doesFileExist)
import System.FilePath ((</>))
import System.Posix.Files (getFileStatus, modificationTime)
import Test.Tasty (DependencyType (AllFinish), TestTree, after, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.FFI.Standard (StdStoreError (..))
import Haskoki.Runtime.Storage
  (CommitResult (..), CredentialRecord (..), StoreError (..), TokenRecord (..), emptyDelta, storeClose, storeCommit)
import Haskoki.Types (TokenId (..))
import Haskoki.Runtime.Storage.Preflight (sha256Hex)
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
