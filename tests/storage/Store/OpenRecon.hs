{- | Store standard open reconciliation cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module Store.OpenRecon
  ( caseOpenAcceptsMoved
  , caseOpenAppendSeedsOne
  , caseOpenDowngradeRefuses
  , caseOpenIdentityRefusalPrecedesMigration
  , caseOpenInterruptedRefuses
  , caseOpenLegacyRefusesMigrationRequired
  , caseOpenMixedLegacyNamesOnlyLegacy
  , caseOpenPinEditIgnoredAfterSeed
  , caseOpenRemovalRefuses
  , caseOpenReorderRefuses
  , caseOpenSchema1IdentityRefusalWithoutWrite
  , caseOpenSchema1LegacyRefusesWithoutWrite
  , caseOpenSeedCredentialFailureLeavesNoToken
  , caseOpenSeedFailsAtomically
  , caseOpenSeedsFresh
  , caseProjectionUsesReconciledLayout
  ) where

import Control.Exception (bracket)
import qualified Data.ByteString.Char8 as BC8
import Data.List (isInfixOf, sort)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import System.Directory (removeDirectoryRecursive)
import System.FilePath ( (</>))
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( ObjectState (..)
  , addToken
  , emptyModel
  , lookupObject
  , lookupSession
  )
import Haskoki.Object (planCreateObject)
import Haskoki.Outcome
  ( DeltaOp (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , StateDelta (..)
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , CredentialRecord (..)
  , FaultPoint (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , ReconcilePlan (..)
  , Store (..)
  , StoreDelta (..)
  , StoredDoc (..)
  , TokenRecord (..)
  , defaultLimits
  , emptyDelta
  , noFaults
  , planSlotMoves
  , reconcileIdentities
  , scriptedFaults
  )
import StoreFixtures
  ( assertUnchanged, captureState, closeAcquired
  , expectStdNeedsMigration, makeTempDir, openReconciled
  
   )
import Haskoki.FFI.Standard
  ( ObjectProjection (..)
  , StdStore (..)
  , StdStoreError (..)
  , buildObjectProjection
  , openStdStoreWith
  )
import Haskoki.Runtime.Catalog (desiredTokens, identityCatalog)
import Haskoki.Runtime.Config
  ( Config (..)
  , StorageCfg (..)
  , StorageKind (..)
  )
import Haskoki.Runtime.Lifecycle (newEnv, rulesFromConfig)
import Haskoki.Runtime.Storage.SQLite (SQLiteTestHooks (..), noSQLiteTestHooks, openSQLiteStore, openSQLiteStoreWith, openSQLiteStoreWithHooks)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( Generation (..)
  , ObjectId (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )
import Store.Contract
import Store.Fixtures

-- | Run a case against a scratch SQLite file, cleaned up
-- afterwards.
withOpenFile :: (FilePath -> IO a) -> IO a
withOpenFile use =
  bracket (makeTempDir "haskoki-open-reconcile") removeDirectoryRecursive $ \dir ->
    use (dir </> "store.db")

-- | Hand-built object fixture: one minimal token object
-- shape per token (attributes stay minimal; ownership is what
-- the open cases pin).
openObject :: TokenId -> ObjectId -> ObjectRecord
openObject tok oid = ObjectRecord
  { orId = oid
  , orToken = tok
  , orClass = 3
  , orKeyType = Nothing
  , orAttrs = Map.fromList [(AttrClass, ValULong 3)]
  , orMaterialEncoding = "none"
  , orMaterial = Nothing
  , orRevision = Revision 1
  }

-- | Seed a three-token file: tokens through the production
-- open itself (fresh-file seeding path), then one object per
-- token through a backend commit.
seedOpenSeeded :: FilePath -> IO ()
seedOpenSeeded path = do
  cfg <- parseCatalog positionalDoc
  eAcq <- openReconciled path cfg
  case eAcq of
    Left err -> assertFailure ("fresh open must seed: " ++ show err)
    Right mAcq -> closeAcquired mAcq
  eStore <- openSQLiteStore path
  s <- either (assertFailure . show) pure eStore
  result <- storeCommit s emptyDelta
    { sdPutObjects =
        [ ObjectPut Nothing (openObject (TokenId 1) (ObjectId 1))
        , ObjectPut Nothing (openObject (TokenId 2) (ObjectId 2))
        , ObjectPut Nothing (openObject (TokenId 3) (ObjectId 3))
        ]
    }
  storeClose s
  assertEqual "open seed objects commit" Committed result

-- | Inspect the exact bytes of a closed file.
fileBytes :: FilePath -> IO [(String, String, String)]
fileBytes path = do
  eStore <- openSQLiteStore path
  s <- either (assertFailure . show) pure eStore
  docs <- expectInspect s
  storeClose s
  pure [(docTable d, docKey d, docJson d) | d <- docs]

-- | Load every token with its objects from a closed file.
fileLoaded :: FilePath -> IO [(TokenRecord, [ObjectRecord])]
fileLoaded path = do
  eStore <- openSQLiteStore path
  s <- either (assertFailure . show) pure eStore
  loaded <- expectLoaded s
  storeClose s
  pure loaded

-- | A fresh file seeds positionally through the production
-- open: three tokens with generation zero and fresh auth,
-- and the reconciled layout the instance would publish
-- through.
caseOpenSeedsFresh :: IO ()
caseOpenSeedsFresh = withOpenFile $ \path -> do
  cfg <- parseCatalog positionalDoc
  eAcq <- openReconciled path cfg
  acquired <- case eAcq of
    Left err -> assertFailure ("fresh open must seed: " ++ show err)
    Right mAcq -> pure mAcq
  case acquired of
    Nothing -> assertFailure "sqlite open must acquire a store"
    Just ss -> do
      assertEqual "reconciled layout is positional"
        [(SlotId 0, TokenId 1), (SlotId 1, TokenId 2), (SlotId 2, TokenId 3)]
        (Map.toAscList (stdTokenIds ss))
      closeAcquired acquired
  loaded <- fileLoaded path
  assertEqual "three tokens seeded" 3 (length loaded)
  assertEqual "seeded labels" threeLabels [trLabel t | (t, _) <- loaded]
  assertEqual "seed generations" [Generation 0, Generation 0, Generation 0]
    [trGeneration t | (t, _) <- loaded]
  assertEqual "seed auths" [tokenAuthNew, tokenAuthNew, tokenAuthNew]
    [trAuth t | (t, _) <- loaded]
  creds <- fileCredentials path
  assertEqual "one durable credential per seeded token, from the catalog"
    [ (TokenId 1, "5678", Just "1234")
    , (TokenId 2, "6789", Just "2345")
    , (TokenId 3, "7890", Just "3456") ]
    creds

-- | A seed whose commit fails before it lands leaves the file
-- with neither token rows nor credential rows (tokens and
-- credentials ride one delta), and a clean reopen seeds both.
caseOpenSeedFailsAtomically :: IO ()
caseOpenSeedFailsAtomically = withOpenFile $ \path -> do
  cfg <- parseCatalog positionalDoc
  inj <- scriptedFaults [FaultBeforeCommit]
  env <- newEnv (rulesFromConfig cfg)
  let cfgServe = cfg { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True False }
  eAcq <- openStdStoreWith (\p -> openSQLiteStoreWith (scAllowEnvSeams (cfgStorage cfgServe)) p defaultLimits inj) env cfgServe
  case eAcq of
    Left StdStoreCommit -> pure ()
    Left err -> assertFailure ("faulted seed failed for the wrong reason: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "faulted seed commit accepted"
  loaded <- fileLoaded path
  assertEqual "no token rows after the failed seed" 0 (length loaded)
  creds <- fileCredentials path
  assertEqual "no credential rows after the failed seed" [] creds
  eAgain <- openReconciled path cfg
  case eAgain of
    Left err -> assertFailure ("clean reopen must seed: " ++ show err)
    Right mAcq -> closeAcquired mAcq
  loadedAgain <- fileLoaded path
  assertEqual "clean reopen seeds three tokens" 3 (length loadedAgain)
  credsAgain <- fileCredentials path
  assertEqual "clean reopen seeds three credentials"
    [TokenId 1, TokenId 2, TokenId 3] [tid | (tid, _, _) <- credsAgain]

-- | The seed is one transaction: a credential insert failing
-- inside it (an injected TEMP trigger on the store's own
-- connection, after the token rows are written in the same
-- transaction) rolls the token rows back too, so no token without
-- its credential persists. A seed split into a token commit and a
-- credential commit would leave the tokens here.
caseOpenSeedCredentialFailureLeavesNoToken :: IO ()
caseOpenSeedCredentialFailureLeavesNoToken = withOpenFile $ \path -> do
  cfg <- parseCatalog positionalDoc
  env <- newEnv (rulesFromConfig cfg)
  let failCredentialInsert db = S.exec db (T.pack (concat
        [ "CREATE TEMP TRIGGER IF NOT EXISTS haskoki_test_fail_credential_insert"
        , " BEFORE INSERT ON main.credentials"
        , " BEGIN SELECT RAISE(ABORT, 'haskoki-test: injected credential insert failure'); END" ]))
      hooks = noSQLiteTestHooks { sthBeforeBegin = failCredentialInsert }
  let cfgServe = cfg { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True False }
  eAcq <- openStdStoreWith (\p -> openSQLiteStoreWithHooks (scAllowEnvSeams (cfgStorage cfgServe)) p defaultLimits noFaults hooks) env cfgServe
  case eAcq of
    Left StdStoreCommit -> pure ()
    Left err -> assertFailure ("faulted seed failed for the wrong reason: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "seed with a failing credential insert accepted"
  loaded <- fileLoaded path
  assertEqual "no token rows after the failed credential insert" 0 (length loaded)
  creds <- fileCredentials path
  assertEqual "no credential rows after the failed credential insert" [] creds

-- | Appending one catalog entry to a seeded store seeds exactly
-- that token and its credential; the existing rows stay as they
-- were.
caseOpenAppendSeedsOne :: IO ()
caseOpenAppendSeedsOne = withOpenFile $ \path -> do
  seedOpenSeeded path
  credsBefore <- fileCredentials path
  assertEqual "seeded store holds three credentials" 3 (length credsBefore)
  cfgAppended <- parseCatalog (catalogDoc
    (threeLabels ++ ["haskoki-extra"]) (threeSo ++ ["8901"])
    (threeUser ++ ["4567"]) [])
  eAcq <- openReconciled path cfgAppended
  case eAcq of
    Left err -> assertFailure ("appended catalog refused: " ++ show err)
    Right mAcq -> closeAcquired mAcq
  loaded <- fileLoaded path
  assertEqual "one token appended"
    [(TokenId 4, SlotId 3, "haskoki-extra")]
    [(trId t, trSlot t, trLabel t) | (t, _) <- loaded, trId t == TokenId 4]
  assertEqual "four tokens in all" 4 (length loaded)
  credsAfter <- fileCredentials path
  assertEqual "existing credentials untouched" credsBefore
    [c | c@(tid, _, _) <- credsAfter, tid /= TokenId 4]
  assertEqual "one credential appended, from the catalog"
    [(TokenId 4, "8901", Just "4567")]
    [c | c@(tid, _, _) <- credsAfter, tid == TokenId 4]

-- | Which stored user PIN reaches which objects: per catalog slot
-- in order, the durable credential row of the token seated there
-- and that token's objects. Row-based: the configured PINs play
-- no part.
rowReach :: FilePath -> Config -> [(TokenRecord, [ObjectRecord])] -> IO [(String, TokenId, [ObjectId])]
rowReach path cfg loaded = do
  creds <- fileCredentials path
  pure
    [ (userPin, tid, sort [orId o | o <- objs])
    | (slot, (tid, _)) <- Map.toAscList (identityCatalog cfg)
    , Just (t, objs) <- [lookup tid byId]
    , trSlot t == slot
    , (ctid, _, Just userPin) <- creds
    , ctid == tid
    ]
  where
    byId = [(trId t, (t, os)) | (t, os) <- loaded]

-- | Every credential row of a closed file, by token, PINs as
-- text.
fileCredentials :: FilePath -> IO [(TokenId, String, Maybe String)]
fileCredentials path = do
  eStore <- openSQLiteStore path
  s <- either (assertFailure . show) pure eStore
  eCreds <- storeLoadCredentials s
  storeClose s
  creds <- either (assertFailure . show) pure eCreds
  pure (sort [ (crToken c, BC8.unpack (crSoPin c), BC8.unpack <$> crUserPin c)
             | c <- creds ])

-- | Commit the catalog's fresh token rows through the raw
-- backend, with no credential rows: the shape of a store
-- written before durable credentials were seeded.
seedLegacyTokens :: FilePath -> Config -> IO ()
seedLegacyTokens path cfg = do
  loaded <- fileLoaded path
  plan <- case reconcileIdentities (desiredTokens cfg) [t | (t, _) <- loaded] of
    Left refusal -> assertFailure ("legacy seed must plan: " ++ show refusal)
    Right plan -> pure plan
  r <- commitFile path emptyDelta { sdPutTokens = planSeeds plan }
  assertEqual "legacy token rows commit" Committed r

-- | Expect the open to refuse as migration-required naming
-- exactly the given tokens, and leave the file byte-exact.
expectMigrationRequired :: FilePath -> Config -> [TokenId] -> IO ()
expectMigrationRequired path cfg want = do
  bytesBefore <- fileBytes path
  eAcq <- openReconciled path cfg
  case eAcq of
    Left (StdStoreMigrationRequired got) ->
      assertEqual "refusal names exactly the legacy tokens" want got
    Left err -> assertFailure ("legacy open refused for the wrong reason: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "legacy store opened without credentials"
  bytesAfter <- fileBytes path
  assertEqual "refused legacy open preserves bytes exactly" bytesBefore bytesAfter

-- | Stored tokens with no credential row refuse at the
-- production open as migration-required, naming every such
-- token; nothing is written and no credential is invented
-- from the catalog.
caseOpenLegacyRefusesMigrationRequired :: IO ()
caseOpenLegacyRefusesMigrationRequired = withOpenFile $ \path -> do
  cfg <- parseCatalog positionalDoc
  seedLegacyTokens path cfg
  expectMigrationRequired path cfg [TokenId 1, TokenId 2, TokenId 3]
  creds <- fileCredentials path
  assertEqual "no credential invented from the catalog" [] creds

-- | One provisioned token and one legacy token: the refusal
-- names only the legacy token.
caseOpenMixedLegacyNamesOnlyLegacy :: IO ()
caseOpenMixedLegacyNamesOnlyLegacy = withOpenFile $ \path -> do
  cfgOne <- parseCatalog (catalogDoc ["haskoki-demo"] ["5678"] ["1234"] [])
  eAcq <- openReconciled path cfgOne
  case eAcq of
    Left err -> assertFailure ("fresh open must seed: " ++ show err)
    Right mAcq -> closeAcquired mAcq
  cfgTwo <- parseCatalog (catalogDoc
    ["haskoki-demo", "haskoki-ops"] ["5678", "6789"] ["1234", "2345"] [])
  seedLegacyTokens path cfgTwo
  expectMigrationRequired path cfgTwo [TokenId 2]
  creds <- fileCredentials path
  assertEqual "the provisioned credential is untouched"
    [(TokenId 1, "5678", Just "1234")] creds

-- | A legacy store opened under a reordered catalog reports
-- the identity refusal, not the missing credentials.
caseOpenIdentityRefusalPrecedesMigration :: IO ()
caseOpenIdentityRefusalPrecedesMigration = withOpenFile $ \path -> do
  cfg <- parseCatalog positionalDoc
  seedLegacyTokens path cfg
  bytesBefore <- fileBytes path
  cfgSwap <- parseCatalog swappedDoc
  eAcq <- openReconciled path cfgSwap
  case eAcq of
    Left (StdStoreIdentityRefusal msg) ->
      assertBool "refusal names the explicit move" ("planSlotMoves" `isInfixOf` msg)
    Left err -> assertFailure ("identity drift refused for the wrong reason: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "reordered legacy open accepted"
  bytesAfter <- fileBytes path
  assertEqual "refused open preserves bytes exactly" bytesBefore bytesAfter

-- | The catalog's fresh token rows (what an open of an empty
-- store would seed).
catalogSeeds :: Config -> IO [TokenRecord]
catalogSeeds cfg = case reconcileIdentities (desiredTokens cfg) [] of
  Left refusal -> assertFailure ("empty-store plan refused: " ++ show refusal)
  Right plan -> pure (planSeeds plan)

-- | AC-04/AC-05 on a schema-1 store: a version-1 file holding the
-- catalog's tokens refuses as migration-required BEFORE identity
-- and before any write: bytes, marker, tables and credential
-- authority stay, with no lock or journal left behind.
caseOpenSchema1LegacyRefusesWithoutWrite :: IO ()
caseOpenSchema1LegacyRefusesWithoutWrite = withOpenFile $ \path -> do
  cfg <- parseCatalog positionalDoc
  seedSchema1 path =<< catalogSeeds cfg
  before <- captureState path
  openReconciled path cfg >>= expectStdNeedsMigration 1
  assertUnchanged "schema-1 legacy store" before path

-- | Identity drift on a schema-1 store: the schema refusal precedes
-- identity, so the verdict is migration-required and the open
-- writes nothing.
caseOpenSchema1IdentityRefusalWithoutWrite :: IO ()
caseOpenSchema1IdentityRefusalWithoutWrite = withOpenFile $ \path -> do
  cfg <- parseCatalog positionalDoc
  seedSchema1 path =<< catalogSeeds cfg
  before <- captureState path
  cfgSwap <- parseCatalog swappedDoc
  openReconciled path cfgSwap >>= expectStdNeedsMigration 1
  assertUnchanged "schema-1 store under a drifted catalog" before path

-- | A reordered catalog refuses at the production open with
-- the actionable message; the file survives byte-exact and
-- the original catalog still opens afterwards.
caseOpenReorderRefuses :: IO ()
caseOpenReorderRefuses = withOpenFile $ \path -> do
  seedOpenSeeded path
  cfgSteady <- parseCatalog positionalDoc
  loadedSteady <- fileLoaded path
  reachBefore <- rowReach path cfgSteady loadedSteady
  bytesBefore <- fileBytes path
  cfgSwap <- parseCatalog swappedDoc
  eAcq <- openReconciled path cfgSwap
  case eAcq of
    Left (StdStoreIdentityRefusal msg) ->
      assertBool "refusal names the explicit move"
        ("planSlotMoves" `isInfixOf` msg)
    Left err -> assertFailure ("reorder refused for the wrong reason: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "reordered open accepted"
  bytesAfter <- fileBytes path
  assertEqual "refused open preserves bytes exactly" bytesBefore bytesAfter
  eAgain <- openReconciled path cfgSteady
  case eAgain of
    Left err -> assertFailure ("steady reopen refused after refusal: " ++ show err)
    Right mAcq -> closeAcquired mAcq
  loadedAgain <- fileLoaded path
  reachAgain <- rowReach path cfgSteady loadedAgain
  assertEqual "mapping intact after refused open" reachBefore reachAgain

-- | A removed entry refuses at the production open: the
-- durable token is never pruned, its objects survive, and
-- the file survives byte-exact.
caseOpenRemovalRefuses :: IO ()
caseOpenRemovalRefuses = withOpenFile $ \path -> do
  seedOpenSeeded path
  bytesBefore <- fileBytes path
  cfgShrunk <- parseCatalog (catalogDoc
    ["haskoki-demo", "haskoki-ops"] ["5678", "6789"] ["1234", "2345"] [])
  eAcq <- openReconciled path cfgShrunk
  case eAcq of
    Left (StdStoreIdentityRefusal msg) ->
      assertBool "refusal rules out pruning" ("never pruned" `isInfixOf` msg)
    Left err -> assertFailure ("removal refused for the wrong reason: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "removal open accepted"
  bytesAfter <- fileBytes path
  assertEqual "refused removal preserves bytes exactly" bytesBefore bytesAfter
  reloaded <- fileLoaded path
  case [os | (t, os) <- reloaded, trId t == TokenId 3] of
    [objs] -> assertEqual "audit keeps its object" 1 (length objs)
    _ -> assertFailure "audit token missing after refused removal"

-- | After an explicit swap committed underneath, the
-- production open accepts the matching pinned catalog and
-- hands the instance the moved layout, with the credentials
-- following the identities to their objects.
caseOpenAcceptsMoved :: IO ()
caseOpenAcceptsMoved = withOpenFile $ \path -> do
  seedOpenSeeded path
  loaded <- fileLoaded path
  swap <- case planSlotMoves [(TokenId 2, SlotId 2), (TokenId 3, SlotId 1)] [t | (t, _) <- loaded] of
    Left refusal -> assertFailure ("swap must plan: " ++ show refusal)
    Right delta -> pure delta
  rSwap <- commitFile path swap
  assertEqual "swap commits" Committed rSwap
  cfgSwap <- parseCatalog swappedDoc
  eAcq <- openReconciled path cfgSwap
  acquired <- case eAcq of
    Left err -> assertFailure ("moved open refused: " ++ show err)
    Right mAcq -> pure mAcq
  case acquired of
    Nothing -> assertFailure "sqlite open must acquire a store"
    Just ss -> do
      assertEqual "reconciled layout follows the move"
        [(SlotId 0, TokenId 1), (SlotId 1, TokenId 3), (SlotId 2, TokenId 2)]
        (Map.toAscList (stdTokenIds ss))
      closeAcquired acquired
  loadedAfter <- fileLoaded path
  reach <- rowReach path cfgSwap loadedAfter
  let objsOf tid = sort [orId o | (_, os) <- loadedAfter, o <- os, orToken o == tid]
  assertEqual "credentials follow identities through the open"
    [ ("1234", TokenId 1, objsOf (TokenId 1))
    , ("3456", TokenId 3, objsOf (TokenId 3))
    , ("2345", TokenId 2, objsOf (TokenId 2))
    ]
    reach

-- | An interrupted move refuses at the production open under
-- both the old and the target catalog; completing the
-- remaining legs explicitly lets the target catalog open.
caseOpenInterruptedRefuses :: IO ()
caseOpenInterruptedRefuses = withOpenFile $ \path -> do
  seedOpenSeeded path
  loaded <- fileLoaded path
  move <- case planSlotMoves [(TokenId 2, SlotId 7)] [t | (t, _) <- loaded] of
    Left refusal -> assertFailure ("first leg must plan: " ++ show refusal)
    Right delta -> pure delta
  rMove <- commitFile path move
  assertEqual "first leg commits" Committed rMove
  bytesMid <- fileBytes path
  cfgOld <- parseCatalog positionalDoc
  eOld <- openReconciled path cfgOld
  case eOld of
    Left (StdStoreIdentityRefusal msg) ->
      assertBool "old open names the drifted slot" (show (SlotId 7) `isInfixOf` msg)
    Left err -> assertFailure ("interrupted state misrefused the old catalog: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "interrupted state opened under the old catalog"
  cfgTarget <- parseCatalog swappedDoc
  eTarget <- openReconciled path cfgTarget
  case eTarget of
    Left (StdStoreIdentityRefusal _) -> pure ()
    Left err -> assertFailure ("interrupted state misrefused the target catalog: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "interrupted state opened under the target catalog"
  bytesRefused <- fileBytes path
  assertEqual "refused opens preserve the mid-state exactly" bytesMid bytesRefused
  loadedMid <- fileLoaded path
  rest <- case planSlotMoves [(TokenId 3, SlotId 1), (TokenId 2, SlotId 2)] [t | (t, _) <- loadedMid] of
    Left refusal -> assertFailure ("remaining legs must plan: " ++ show refusal)
    Right delta -> pure delta
  rRest <- commitFile path rest
  assertEqual "remaining legs commit" Committed rRest
  eDone <- openReconciled path cfgTarget
  case eDone of
    Left err -> assertFailure ("completed layout refused: " ++ show err)
    Right mAcq -> closeAcquired mAcq

-- | A positional downgrade over a moved store refuses at the
-- production open; the matching pinned catalog still opens.
caseOpenDowngradeRefuses :: IO ()
caseOpenDowngradeRefuses = withOpenFile $ \path -> do
  seedOpenSeeded path
  loaded <- fileLoaded path
  swap <- case planSlotMoves [(TokenId 2, SlotId 2), (TokenId 3, SlotId 1)] [t | (t, _) <- loaded] of
    Left refusal -> assertFailure ("swap must plan: " ++ show refusal)
    Right delta -> pure delta
  rSwap <- commitFile path swap
  assertEqual "swap commits" Committed rSwap
  bytesBefore <- fileBytes path
  cfgLegacy <- parseCatalog positionalDoc
  eLegacy <- openReconciled path cfgLegacy
  case eLegacy of
    Left (StdStoreIdentityRefusal _) -> pure ()
    Left err -> assertFailure ("downgrade refused for the wrong reason: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "positional downgrade opened over a moved store"
  bytesAfter <- fileBytes path
  assertEqual "refused downgrade preserves bytes exactly" bytesBefore bytesAfter
  cfgPinned <- parseCatalog swappedDoc
  ePinned <- openReconciled path cfgPinned
  case ePinned of
    Left err -> assertFailure ("pinned catalog refused after downgrade refusal: " ++ show err)
    Right mAcq -> closeAcquired mAcq

-- | A config PIN edit after the seed changes nothing durable:
-- the reopen with the edited user PIN writes no bytes, and the
-- seeded credential rows keep the original PINs, which keep
-- reaching the same objects.
caseOpenPinEditIgnoredAfterSeed :: IO ()
caseOpenPinEditIgnoredAfterSeed = withOpenFile $ \path -> do
  seedOpenSeeded path
  loaded <- fileLoaded path
  cfg <- parseCatalog positionalDoc
  reachBefore <- rowReach path cfg loaded
  assertEqual "three credentials served" 3 (length reachBefore)
  credsBefore <- fileCredentials path
  cfgRotated <- parseCatalog (catalogDoc threeLabels threeSo ["1234", "9999", "3456"] [])
  bytesBefore <- fileBytes path
  eAcq <- openReconciled path cfgRotated
  case eAcq of
    Left err -> assertFailure ("PIN edit refused: " ++ show err)
    Right mAcq -> closeAcquired mAcq
  bytesAfter <- fileBytes path
  assertEqual "a PIN edit writes nothing" bytesBefore bytesAfter
  credsAfter <- fileCredentials path
  assertEqual "stored credentials keep the seeded PINs" credsBefore credsAfter
  loadedAfter <- fileLoaded path
  reachAfter <- rowReach path cfgRotated loadedAfter
  assertEqual "PINs unchanged by the edit" ["1234", "2345", "3456"]
    [pin | (pin, _, _) <- reachAfter]
  assertEqual "the same PINs reach the same objects" reachBefore reachAfter

-- | The durable publication path resolves serving slots
-- through the reconciled layout: a real creation delta for a
-- slot-1 object projects under the moved identity with the
-- swapped map and under the legacy identity with the
-- positional map. Reverting the projection to slot-plus-one
-- fails the first assertion.
caseProjectionUsesReconciledLayout :: IO ()
caseProjectionUsesReconciledLayout = do
  mSeated <- expectRight "proj seat+open" (publishDelta
    (addToken (addToken emptyModel (SlotId 0)) (SlotId 1))
    (StateDelta [DeltaOpenSession (SessionId 1) (SlotId 1) False]))
  st <- expectJust "proj session" (lookupSession mSeated (SessionId 1))
  pc <- case planCreateObject mSeated st (idTmpl "proj-moved") of
    Immediate p -> pure p
    _ -> assertFailure "expected Immediate creation plan"
  mAfter <- expectRight "proj publish" (publishDelta mSeated (pcDelta pc))
  let oid = ObjectId (mNextObject' mSeated)
  ost <- expectJust "proj object" (lookupObject mAfter oid)
  assertEqual "object created on slot 1" (SlotId 1) (osSlot ost)
  let swapped = Map.fromList [(SlotId 0, TokenId 1), (SlotId 1, TokenId 3)]
      positional = Map.fromList [(SlotId 0, TokenId 1), (SlotId 1, TokenId 2)]
      tokensOf proj = [orToken (opRecord p) | p <- sdPutObjects (projDelta proj)]
  assertEqual "reconciled layout attributes the moved identity"
    [TokenId 3] (tokensOf (buildObjectProjection swapped mSeated mAfter (pcDelta pc)))
  assertEqual "positional layout attributes the legacy identity"
    [TokenId 2] (tokensOf (buildObjectProjection positional mSeated mAfter (pcDelta pc)))
