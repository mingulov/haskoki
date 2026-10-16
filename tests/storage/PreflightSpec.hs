{-# LANGUAGE OverloadedStrings #-}
{- | Store preflight, explicit migration and recovery (AC-05):
released-binary fixtures, refused opens that write nothing, the
read-only snapshot and plan, the owned migration, and recovery.
-}
module PreflightSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Text as T
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.FFI.Standard (StdStoreError (..))
import Haskoki.Runtime.Storage (CredentialRecord (..), StoreError (..), storeClose)
import Haskoki.Types (TokenId (..))
import Haskoki.Runtime.Storage.Preflight (sha256Hex)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)

import StoreFixtures

spec :: TestTree
spec = testGroup "Store preflight"
  [ testGroup "released fixtures"
      [ testCase "sha-256 is the standard digest" caseSha256Vector
      , testCase "v0.3.1.0 fixture matches its manifest" (caseFixtureManifest "v0.3.1.0")
      , testCase "v0.4.0.0 fixture matches its manifest" (caseFixtureManifest "v0.4.0.0")
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
