{- | Commit-protocol suite.

Each case simulates the runtime rule: the in-memory model delta
publishes if and only if the store reports 'Committed'
('decidePublication'). Durable and model state must agree whenever
a token is servable; any uncertainty quarantines the token until
an authoritative reload resolves it.

* Pre-commit failure: rollback, durable and model success
  unpublished, no commit counted.
* Ambiguous commit: the observed outcome is discarded and a
  reload/reconcile decides; the PKCS#11 operation is NEVER
  reissued (exactly one durable commit, exactly one verification
  reload).
* Ambiguous + verification failure: 'CommitUnknown', the token
  quarantines, commits touching it refuse, and an authoritative
  reload clears the quarantine and reconciles publication.
* Post-commit failure: durable truth is 'Committed' but the token
  quarantines until reload resolves it.
* The commit region runs masked: both commit probes observe
  'MaskedInterruptible'.
* SQLite body failure (SQLite only): the first failed statement
  of the transaction body stops every later delta group — after
  an injected @RAISE(ROLLBACK)@ (sequencing only), a
  still-active statement ABORT, and a genuine page-cap
  @SQLITE_FULL@ that SQLite answers by rolling the whole
  transaction back — and every logical table is unchanged on
  reopen.
* SQLite COMMIT and cleanup failure (SQLite only): a genuine
  @SQLITE_BUSY@ COMMIT with the transaction still active rolls
  back to an exact 'NotCommitted'; an injected COMMIT failure
  after the transaction ended is 'CommitUnknown' with the token
  quarantined and the COMMIT never reissued; an injected ROLLBACK
  denial that leaves the transaction open quarantines the whole
  connection until a rolling-back reload or a close; and a
  partial ambiguous-verification reload is unknown, never
  "absent".
* Interruption is honestly scoped: a kill delivered after the
  commit result is determined is observed as 'ThreadKilled' via
  outcome capture while the captured 'Committed' result stays
  durable whole, and ordinary completion fails the cancellation
  assertion. Forcing an exception pending inside every native SQL
  window is explicitly out of scope.
-}
{-# LANGUAGE OverloadedStrings #-}
module CommitSpec (spec) where

import Control.Concurrent
  ( MVar
  , ThreadId
  , forkFinally
  , killThread
  , newEmptyMVar
  , putMVar
  , readMVar
  , takeMVar
  , throwTo
  )
import Control.Exception
  ( AsyncException (..)
  , MaskingState (..)
  , SomeException
  , bracket
  , finally
  , fromException
  , getMaskingState
  )
import Control.Monad (when)
import Data.ByteString (ByteString)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.List (isInfixOf, sort, sortOn)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import Database.SQLite3.Direct (getAutoCommit)
import System.Directory (removeDirectoryRecursive)
import System.FilePath ((</>))
import System.IO (hPutStrLn, stderr)
import System.Timeout (timeout)
import GHC.Clock (getMonotonicTime)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase, testCaseInfo)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), SessionState, addToken, emptyModel, lookupObject)
import Haskoki.Object (planCreateObject)
import Haskoki.Outcome (DeltaOp (..), PlanResult (..), PreparedCommit (..), StateDelta (..))
import Data.Word (Word64)
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , CredentialRecord (..)
  , DesiredToken (..)
  , FaultInjector (..)
  , FaultPoint (..)
  , IdentityRefusal (..)
  , JobRecord (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , PublicationAdvice (..)
  , Reconcile (..)
  , ReconcilePlan (..)
  , Store (..)
  , StoreDelta (..)
  , StoreDeltaClass (..)
  , StoreError (..)
  , StoreLimits (..)
  , StoreStats (..)
  , StoredDoc (..)
  , TokenRecord (..)
  , coverDeletedJobIds
  , decidePublication
  , decodeTokenRecord
  , defaultLimits
  , deltaClasses
  , emptyDelta
  , encodeHexWord64
  , encodeObjectRecord
  , encodeTokenRecord
  , jobIdCounterKey
  , nextJobReservation
  , noFaults
  , objectToRecord
  , planSlotMoves
  , reconcileIdentities
  , reconcileReload
  , renderIdentityRefusal
  , reserveRestoredIds
  , scrubDeltaAuth
  , scrubTokenAuth
  , scriptedFaults
  , withMaskHook
  , withResultHook
  )
import Haskoki.FFI.Standard (authPutsOf, projectAuthPuts)
import Haskoki.Runtime.Catalog (identityCatalog)
import Haskoki.Runtime.Config (Config (..), parseConfig)
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStoreWith)
import Haskoki.Runtime.Storage.SQLite (SQLiteTestHooks (..), openSQLiteStoreWith, openSQLiteStoreWithHooks)
import SQLiteSeams
  ( CommitSeam (..)
  , TxnSeam (..)
  , assertTablesEqual
  , dumpTables
  , failTokenUpsert
  , injectedMarker
  , commitsSinceMark
  , installCommitSeam
  , installTxnSeam
  , installWriteLog
  , laterTables
  , loggedTables
  , markCommits
  , newCommitSeam
  , newTxnSeam
  , queryInt
  , queryText
  , withSharedReadLock
  )
import Haskoki.Session (ActiveLogin (..), TokenAuth (..), tokenAuthNew)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( Generation (..)
  , ObjectId (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )
import StoreSpec (demoJobPending, demoJobResult, expectInspect, expectJust, expectRight, makeTempDir, seedStore)

-- | Open a store on the case identity with the given limits and faults.
type OpenWith = StoreLimits -> FaultInjector -> IO (Either StoreError Store)

spec :: TestTree
spec = testGroup "commit protocol"
  [ testGroup "decisions"
      [ testCase "publication advice follows classification" testAdvice
      , testCase "reload reconciliation compares full records" testReconcile
      , testCase "reservation step reconciles without lowering" testNextJobReservation
      , testCase "durable delta classification names every list" testDeltaClasses
      , testCase "auth codec persists counters, never the session" testAuthCodec
      , testCase "scrubbed puts reconcile present" testScrubbedReconcile
      , testCase "auth projection commits durable moves only" testAuthProjection
      , testCase "unchanged auth skips the projection load" testAuthPutsSkipLoad
      ]
  , testGroup "memory" (protocolCases withMemoryIdentity)
  , testGroup "sqlite" (protocolCases withSQLiteIdentity)
  , testGroup "limits-memory" (limitCases withMemoryIdentity)
  , testGroup "limits-sqlite" (limitCases withSQLiteIdentity)
  , testGroup "identity-memory" (identityCases withMemoryIdentity)
  , testGroup "identity-sqlite" (identityCases withSQLiteIdentity)
  , testGroup "body-failure-sqlite" bodyFailureCases
  , testGroup "commit-failure-sqlite" commitFailureCases
  ]

-- | Fresh memory identity per case.
withMemoryIdentity :: (OpenWith -> IO ()) -> IO ()
withMemoryIdentity use = do
  world <- newMemoryWorld
  use (\lim inj -> openMemoryStoreWith world lim inj)

-- | Fresh SQLite file identity per case, cleaned up afterwards.
withSQLiteIdentity :: (OpenWith -> IO ()) -> IO ()
withSQLiteIdentity use =
  bracket (makeTempDir "haskoki-commit-test") removeDirectoryRecursive $ \dir ->
    use (\lim inj -> openSQLiteStoreWith (dir </> "store.db") lim inj)

-- | The protocol cases every backend runs.
protocolCases :: ((OpenWith -> IO ()) -> IO ()) -> [TestTree]
protocolCases withIdentity =
  [ testCase "pre-commit failure rolls back, unpublished" $
      withIdentity testPreCommitRollback
  , testCase "ambiguous commit verifies via reload, never reissues" $
      withIdentity testAmbiguousVerifies
  , testCase "ambiguous plus verify failure quarantines until reload" $
      withIdentity testAmbiguousUnknown
  , testCase "post-commit failure quarantines a committed token" $
      withIdentity testPostCommitQuarantine
  , testCase "commit regions run masked" $
      withIdentity testCommitMasking
  , testCase "kill after commit result is observed, commit survives" $
      withIdentity testCommitInterruption
  , testCase "ordinary completion fails the cancellation assertion" $
      withIdentity testCompletionControl
  , testCase "injected full disk is a clean error" $
      withIdentity testFullDisk
  , testCase "reset respects quarantine" $
      withIdentity testResetQuarantine
  , testCase "ambiguous token refresh preserves children" $
      withIdentity testAmbiguousTokenRefresh
  , testCase "ambiguous reservation reconciles present" $
      withIdentity testReserveAmbiguousPresent
  , testCase "ambiguous reservation with failed verification quarantines and fails" $
      withIdentity testReserveAmbiguousUnknown
  , testCase "reservation honors pre-commit and capacity faults" $
      withIdentity testReserveFaults
  , testCase "failed job insert leaves a gap, never a reuse" $
      withIdentity testReserveInsertGap
  , testCase "ambiguous delete with stale counter reconciles committed" $
      withIdentity testAmbiguousDeleteStaleCounter
  , testCase "unapplied delete with stale counter stays not committed" $
      withIdentity testUnappliedDeleteStaleCounter
  , testCase "ambiguous duplicate meta reconciles committed" $
      withIdentity testAmbiguousDuplicateMeta
  , testCase "auth-only pre-commit failure keeps live and persisted counters" $
      withIdentity testAuthPreCommit
  , testCase "auth-only ambiguous commit lands once, never replays" $
      withIdentity testAuthAmbiguous
  , testCase "auth-only ambiguous plus verify failure resolves on reload" $
      withIdentity testAuthAmbiguousUnknown
  , testCase "auth-only post-commit failure quarantines until reload, reopen clean" $
      withIdentity testAuthPostCommit
  , testCase "credential pre-commit failure keeps persisted rows" $
      withIdentity testCredentialPreCommit
  , testCase "credential post-commit failure quarantines until reload" $
      withIdentity testCredentialPostCommit
  , testCase "quarantined token refuses credential writes" $
      withIdentity testCredentialQuarantine
  ]

-- | The pre-commit limit cases every backend runs.
limitCases :: ((OpenWith -> IO ()) -> IO ()) -> [TestTree]
limitCases withIdentity =
  [ testCase "object count limit enforced" $
      withIdentity testLimitObjects
  , testCase "per-record limit enforced" $
      withIdentity testLimitRecord
  , testCase "total bytes limit enforced" $
      withIdentity testLimitTotal
  , testCase "job cap enforced" $
      withIdentity testLimitJobs
  ]

-- ---------------------------------------------------------------------------
-- Pure decisions
-- ---------------------------------------------------------------------------

-- | Classification drives publication: only 'Committed' publishes;
-- 'CommitUnknown' reloads first.
testAdvice :: IO ()
testAdvice = do
  assertEqual "committed publishes" PublishDelta (decidePublication Committed)
  assertEqual "refused publishes nothing" PublishNothing
    (decidePublication (NotCommitted (StoreIO "x")))
  assertEqual "unknown reloads first" ReloadFirst
    (decidePublication (CommitUnknown (StoreIO "x")))

-- | Reconciliation compares full records: wrong content or a
-- surviving drop-target both read absent.
testReconcile :: IO ()
testReconcile = do
  let tok = demoToken (TokenId 1)
      rec = demoObject (TokenId 1) (ObjectId 2)
      delta = emptyDelta
        { sdPutTokens = [tok]
        , sdPutObjects = [ObjectPut Nothing rec]
        , sdDropObjects = [ObjectId 9]
        }
  assertEqual "exact reload reconciles present" ReconciledPresent
    (reconcileReload delta [(tok, [rec])])
  assertEqual "missing put reconciles absent" ReconciledAbsent
    (reconcileReload delta [(tok, [])])
  assertEqual "surviving drop-target reconciles absent" ReconciledAbsent
    (reconcileReload delta [(tok, [rec, demoObject (TokenId 1) (ObjectId 9)])])
  assertEqual "altered content reconciles absent" ReconciledAbsent
    (reconcileReload delta [(tok { trLabel = "changed" }, [rec])])

-- | Delta classification is exhaustive with no catch-all: the
-- empty delta names nothing, each singleton delta names exactly
-- its own list, and the full delta pins the whole
-- @[minBound .. maxBound]@ class set, so a new delta list
-- without a classifier arm fails here instead of classifying
-- silently. An auth-only change is 'DeltaTokensPut': a real
-- write class, never a bypass.
testDeltaClasses :: IO ()
testDeltaClasses = do
  let tok = demoToken (TokenId 1)
      rec = demoObject (TokenId 1) (ObjectId 2)
      job = demoJobPending 9 (TokenId 1) (Generation 1)
  assertEqual "empty names nothing" [] (deltaClasses emptyDelta)
  assertEqual "token puts" [DeltaTokensPut]
    (deltaClasses emptyDelta { sdPutTokens = [tok] })
  assertEqual "token drops" [DeltaTokensDrop]
    (deltaClasses emptyDelta { sdDropTokens = [TokenId 1] })
  assertEqual "object puts" [DeltaObjectsPut]
    (deltaClasses emptyDelta { sdPutObjects = [ObjectPut Nothing rec] })
  assertEqual "object drops" [DeltaObjectsDrop]
    (deltaClasses emptyDelta { sdDropObjects = [ObjectId 2] })
  assertEqual "job puts" [DeltaJobsPut]
    (deltaClasses emptyDelta { sdPutJobs = [job] })
  assertEqual "job drops" [DeltaJobsDrop]
    (deltaClasses emptyDelta { sdDropJobs = [9] })
  assertEqual "meta puts" [DeltaMetaPut]
    (deltaClasses emptyDelta { sdPutMeta = [("mark", "1")] })
  assertEqual "credential puts" [DeltaCredentialsPut]
    (deltaClasses emptyDelta { sdPutCredentials = [demoCred] })
  assertEqual "credential drops" [DeltaCredentialsDrop]
    (deltaClasses emptyDelta { sdDropCredentials = [TokenId 1] })
  let full = emptyDelta
        { sdPutTokens = [tok]
        , sdDropTokens = [TokenId 2]
        , sdPutObjects = [ObjectPut Nothing rec]
        , sdDropObjects = [ObjectId 3]
        , sdPutJobs = [job]
        , sdDropJobs = [10]
        , sdPutMeta = [("mark", "1")]
        , sdPutCredentials = [demoCred]
        , sdDropCredentials = [TokenId 2]
        }
  assertEqual "full delta pins every class"
    [minBound .. maxBound] (deltaClasses full)
  where
    demoCred = CredentialRecord (TokenId 1) "so-pin" (Just "user-pin")

-- | The token codec persists retry counters and lock flags only:
-- the encoded bytes carry no login, principal, or epoch, and the
-- decoded auth is transient-cleared with the durable half
-- intact. Legacy transient keys from an older writer decode to
-- the same cleared form (tolerated, never restored); a document
-- missing a durable key, or carrying a malformed durable value,
-- refuses.
testAuthCodec :: IO ()
testAuthCodec = do
  let full = tokenAuthNew
        { taLogin = Just AuthUser
        , taPrincipal = Just "alice"
        , taAuthEpoch = 7
        , taUserAttempts = 2
        , taSoAttempts = 1
        , taUserLocked = True
        }
      tok = (demoToken (TokenId 1)) { trAuth = full }
      doc = encodeTokenRecord tok
  assertBool "no login key" (not ("\"login\"" `isInfixOf` doc))
  assertBool "no principal key" (not ("principal" `isInfixOf` doc))
  assertBool "no epoch key" (not ("auth_epoch" `isInfixOf` doc))
  assertBool "no principal bytes" (not ("alice" `isInfixOf` doc))
  tok' <- expectJust "durable doc decodes" (decodeTokenRecord doc)
  assertEqual "transient cleared, durable kept"
    (tokenAuthNew { taUserAttempts = 2, taSoAttempts = 1, taUserLocked = True })
    (trAuth tok')
  let legacy = "{\"auth\":{\"auth_epoch\":\"0000000000000007\",\"login\":\"user\","
        ++ "\"principal\":\"mallory\",\"so_attempts\":\"0000000000000001\","
        ++ "\"so_locked\":false,\"user_attempts\":\"0000000000000002\","
        ++ "\"user_locked\":true},\"format_version\":1,"
        ++ "\"generation\":\"0000000000000001\",\"label\":\"demo\","
        ++ "\"slot\":\"0000000000000000\",\"token_id\":\"0000000000000001\"}"
  legacy' <- expectJust "legacy doc decodes" (decodeTokenRecord legacy)
  assertEqual "legacy transient ignored, counters kept"
    (tokenAuthNew { taUserAttempts = 2, taSoAttempts = 1, taUserLocked = True })
    (trAuth legacy')
  let complete =
        "{\"auth\":{\"so_attempts\":\"0000000000000001\",\"so_locked\":false,"
        ++ "\"user_attempts\":\"0000000000000002\",\"user_locked\":true},"
        ++ "\"format_version\":1,\"generation\":\"0000000000000001\","
        ++ "\"label\":\"demo\",\"slot\":\"0000000000000000\","
        ++ "\"token_id\":\"0000000000000001\"}"
  -- The complete durable-only doc decodes; the refusal fixtures
  -- below drop and corrupt one durable key each.
  _ <- expectJust "complete durable doc decodes" (decodeTokenRecord complete)
  let dropped =
        "{\"auth\":{\"so_attempts\":\"0000000000000001\",\"so_locked\":false,"
        ++ "\"user_locked\":true},\"format_version\":1,"
        ++ "\"generation\":\"0000000000000001\",\"label\":\"demo\","
        ++ "\"slot\":\"0000000000000000\",\"token_id\":\"0000000000000001\"}"
  assertEqual "missing durable key refuses" Nothing (decodeTokenRecord dropped)
  let corrupt =
        "{\"auth\":{\"so_attempts\":\"nope\",\"so_locked\":false,"
        ++ "\"user_attempts\":\"0000000000000002\",\"user_locked\":true},"
        ++ "\"format_version\":1,\"generation\":\"0000000000000001\","
        ++ "\"label\":\"demo\",\"slot\":\"0000000000000000\","
        ++ "\"token_id\":\"0000000000000001\"}"
  assertEqual "malformed durable value refuses" Nothing (decodeTokenRecord corrupt)

-- | Reconciliation compares scrubbed token puts: the scrubbed
-- put reconciles present against the scrubbed load, while the
-- same put with its transient half attached reconciles absent.
-- This pins why the projection scrubs before issuing: an
-- unscrubbed auth-only write could never verify after an
-- ambiguous commit.
testScrubbedReconcile :: IO ()
testScrubbedReconcile = do
  let full = (demoToken (TokenId 1))
        { trAuth = tokenAuthNew
            { taLogin = Just AuthUser
            , taPrincipal = Just "alice"
            , taAuthEpoch = 4
            , taUserAttempts = 2
            }
        }
      scrubbed = scrubTokenAuth full
  assertEqual "scrubbed put reconciles present" ReconciledPresent
    (reconcileReload emptyDelta { sdPutTokens = [scrubbed] } [(scrubbed, [])])
  assertEqual "unscrubbed put reconciles absent" ReconciledAbsent
    (reconcileReload emptyDelta { sdPutTokens = [full] } [(scrubbed, [])])
  assertEqual "scrubbed delta reconciles present" ReconciledPresent
    (reconcileReload (scrubDeltaAuth emptyDelta { sdPutTokens = [full] })
      [(scrubbed, [])])

-- | The authentication projection commits durable moves only: a
-- counter move becomes a token put carrying the cleared
-- post-state over the stored row; a transient-only move (login
-- granted on settled counters, logout-shaped epoch bump)
-- projects to no puts; and a moved slot with no stored row
-- fails closed ('Nothing'). The comparison reads the pre\/post
-- model maps directly, so the projection needs no delta-op
-- shape to find a durable move.
testAuthProjection :: IO ()
testAuthProjection = do
  m0 <- expectRight "seat" (publishDelta (addToken emptyModel (SlotId 0)) (StateDelta []))
  let withAuth a = m0 { mTokenAuth = Map.singleton (SlotId 0) a }
      stored = (demoToken (TokenId 1)) { trSlot = SlotId 0 }
      ids = Map.singleton (SlotId 0) (TokenId 1)
      loaded = [(stored, [])]
      moved = tokenAuthNew { taUserAttempts = 1 }
      granted = tokenAuthNew
        { taLogin = Just AuthUser
        , taPrincipal = Just "alice"
        , taAuthEpoch = 1
        }
      resetGrant = tokenAuthNew
        { taLogin = Just AuthUser
        , taPrincipal = Just "alice"
        , taAuthEpoch = 2
        }
  case projectAuthPuts ids loaded (withAuth tokenAuthNew) (withAuth moved) of
    Just [put] -> do
      assertEqual "same row" (trId stored) (trId put)
      assertEqual "same slot" (trSlot stored) (trSlot put)
      assertEqual "durable carried, transient cleared" moved (trAuth put)
    other -> assertFailure ("counter move must put once, got: " ++ show other)
  assertEqual "fresh grant projects nothing" (Just [])
    (projectAuthPuts ids loaded (withAuth tokenAuthNew) (withAuth granted))
  case projectAuthPuts ids loaded (withAuth moved) (withAuth resetGrant) of
    Just [put] -> assertEqual "reset grant puts cleared counters"
      tokenAuthNew (trAuth put)
    other -> assertFailure ("reset grant must put once, got: " ++ show other)
  assertEqual "unchanged models project nothing" (Just [])
    (projectAuthPuts ids [] (withAuth moved) (withAuth moved))
  assertEqual "missing row fails closed" Nothing
    (projectAuthPuts ids [] (withAuth tokenAuthNew) (withAuth moved))

-- | The loader skips its read when durable auth is unchanged:
-- even against a closed store (whose load would fail), an
-- unchanged step projects to no puts without touching the
-- handle.
testAuthPutsSkipLoad :: IO ()
testAuthPutsSkipLoad = do
  world <- newMemoryWorld
  eStore <- openMemoryStoreWith world defaultLimits noFaults
  s <- either (assertFailure . show) pure eStore
  storeClose s
  m0 <- expectRight "seat" (publishDelta (addToken emptyModel (SlotId 0)) (StateDelta []))
  let same = m0 { mTokenAuth = Map.singleton (SlotId 0) tokenAuthNew }
  r <- authPutsOf s Map.empty m0 same
  assertEqual "unchanged step skips the load" (Right []) r

-- | The shared reservation step: absent marks start at 1,
-- stored jobs reconcile the mark upward without lowering,
-- corrupt marks fail closed, and exhaustion refuses before wrap.
testNextJobReservation :: IO ()
testNextJobReservation = do
  assertEqual "absent mark starts at 1"
    (Right (1, encodeHexWord64 2)) (nextJobReservation Nothing [])
  assertEqual "stored mark serves"
    (Right (7, encodeHexWord64 8))
    (nextJobReservation (Just (encodeHexWord64 7)) [3])
  assertEqual "jobs reconcile upward"
    (Right (42, encodeHexWord64 43))
    (nextJobReservation (Just (encodeHexWord64 2)) [41])
  assertEqual "mark never lowers"
    (Right (100, encodeHexWord64 101))
    (nextJobReservation (Just (encodeHexWord64 100)) [41])
  case nextJobReservation (Just "bogus") [] of
    Left (StoreCorrupt _) -> pure ()
    other -> assertFailure ("expected StoreCorrupt, got: " ++ show other)
  let nearMax = maxBound - 1 :: Word64
  assertEqual "next-to-last hands out"
    (Right (nearMax, encodeHexWord64 maxBound))
    (nextJobReservation (Just (encodeHexWord64 nearMax)) [])
  case nextJobReservation (Just (encodeHexWord64 maxBound)) [] of
    Left (StoreFull _) -> pure ()
    other -> assertFailure ("expected StoreFull, got: " ++ show other)
  case nextJobReservation Nothing [maxBound] of
    Left (StoreFull _) -> pure ()
    other -> assertFailure ("expected StoreFull, got: " ++ show other)
  assertEqual "deleted pids fold into the mark"
    (Just (encodeHexWord64 42))
    (coverDeletedJobIds (Just (encodeHexWord64 1)) [41])
  assertEqual "empty doomed set leaves the mark alone"
    (Just (encodeHexWord64 7))
    (coverDeletedJobIds (Just (encodeHexWord64 7)) [])
  assertEqual "empty doomed set keeps the key absent"
    Nothing
    (coverDeletedJobIds Nothing [])
  assertEqual "cover saturates instead of wrapping"
    (Just (encodeHexWord64 maxBound))
    (coverDeletedJobIds (Just (encodeHexWord64 5)) [maxBound])
  assertEqual "corrupt mark stays corrupt under deletion"
    (Just "bogus")
    (coverDeletedJobIds (Just "bogus") [41])

-- ---------------------------------------------------------------------------
-- Protocol cases
-- ---------------------------------------------------------------------------

-- | Pre-commit injection: nothing durable changes, the model does
-- not publish, and no commit is counted.
testPreCommitRollback :: OpenWith -> IO ()
testPreCommitRollback openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, recs) <- seedStore sClean
  storeClose sClean
  inj <- scriptedFaults [FaultBeforeCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  (mBefore, sdelta, mdelta, oid) <- planObject sFaulty (trId tok)
  result <- storeCommit sFaulty sdelta
  case result of
    NotCommitted _ -> pure ()
    other -> assertFailure ("expected NotCommitted, got: " ++ show other)
  mFinal <- publishOn result mBefore mdelta
  assertBool "model unpublished" (lookupObject mFinal oid == Nothing)
  eLoaded <- storeLoadTokens sFaulty
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "durable unpublished" 2 (countObjects loaded)
  assertEqual "seed records intact" recs (concatMap snd loaded)
  stats <- storeStats sFaulty
  assertEqual "no commit counted" 0 (ssCommits stats)
  storeClose sFaulty

-- | Ambiguous injection: the commit lands exactly once and a
-- verification reload confirms it; nothing is ever reissued.
testAmbiguousVerifies :: OpenWith -> IO ()
testAmbiguousVerifies openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  storeClose sClean
  inj <- scriptedFaults [FaultAmbiguousCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  (mBefore, sdelta, mdelta, oid) <- planObject sFaulty (trId tok)
  result <- storeCommit sFaulty sdelta
  assertEqual "ambiguous resolves committed" Committed result
  mFinal <- publishOn result mBefore mdelta
  stats <- storeStats sFaulty
  assertEqual "exactly one durable commit" 1 (ssCommits stats)
  assertEqual "exactly one verification reload" 1 (ssVerifyReloads stats)
  eLoaded <- storeLoadTokens sFaulty
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "durable shows the object" 3 (countObjects loaded)
  assertBool "model published" (lookupObject mFinal oid /= Nothing)
  assertBool "model and durable agree" (objectPresent oid loaded)
  storeClose sFaulty

-- | Ambiguous plus verification failure: 'CommitUnknown', the token
-- quarantines (commits touching it refuse), and an authoritative
-- reload clears the quarantine and reconciles publication.
testAmbiguousUnknown :: OpenWith -> IO ()
testAmbiguousUnknown openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  storeClose sClean
  inj <- scriptedFaults [FaultAmbiguousCommit, FaultVerifyReload]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  (mBefore, sdelta, mdelta, oid) <- planObject sFaulty (trId tok)
  result <- storeCommit sFaulty sdelta
  case result of
    CommitUnknown _ -> pure ()
    other -> assertFailure ("expected CommitUnknown, got: " ++ show other)
  assertEqual "unknown reloads first" ReloadFirst (decidePublication result)
  mHeld <- publishOn result mBefore mdelta
  assertBool "model held back" (lookupObject mHeld oid == Nothing)
  quarantined <- storeQuarantined sFaulty
  assertEqual "token quarantined" [trId tok] (map fst quarantined)
  -- Commits touching the quarantined token refuse without effect.
  (mBefore2, sdelta2, _, _) <- planObject sFaulty (trId tok)
  _ <- pure mBefore2
  refused <- storeCommit sFaulty sdelta2
  case refused of
    NotCommitted (StoreQuarantined tid _) -> assertEqual "quarantined token" (trId tok) tid
    other -> assertFailure ("expected quarantine refusal, got: " ++ show other)
  -- Authoritative reload resolves: the injected commit had landed,
  -- so reconciliation now publishes.
  eReload <- storeReload sFaulty
  _ <- either (assertFailure . show) pure eReload
  quarantinedAfter <- storeQuarantined sFaulty
  assertEqual "quarantine cleared" [] quarantinedAfter
  eLoaded <- storeLoadTokens sFaulty
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "reload reconciles present" ReconciledPresent (reconcileReload sdelta loaded)
  mFinal <- expectRight "late publish" (publishDelta mBefore mdelta)
  _ <- pure mFinal
  stats <- storeStats sFaulty
  assertEqual "one verification attempted" 1 (ssVerifyReloads stats)
  assertBool "quarantine counted" (ssQuarantines stats >= 1)
  storeClose sFaulty

-- | Post-commit injection: durable truth is 'Committed' but the
-- token quarantines until an authoritative reload resolves it.
testPostCommitQuarantine :: OpenWith -> IO ()
testPostCommitQuarantine openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  storeClose sClean
  inj <- scriptedFaults [FaultAfterCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  (mBefore, sdelta, mdelta, oid) <- planObject sFaulty (trId tok)
  result <- storeCommit sFaulty sdelta
  assertEqual "post-commit failure still committed" Committed result
  quarantined <- storeQuarantined sFaulty
  assertEqual "token quarantined" [trId tok] (map fst quarantined)
  -- The runtime publishes on Committed, but must not serve the
  -- quarantined token until reload resolves it.
  mFinal <- publishOn result mBefore mdelta
  assertBool "model published" (lookupObject mFinal oid /= Nothing)
  eLoaded <- storeLoadTokens sFaulty
  loaded <- either (assertFailure . show) pure eLoaded
  assertBool "durable has the object" (objectPresent oid loaded)
  eReload <- storeReload sFaulty
  _ <- either (assertFailure . show) pure eReload
  quarantinedAfter <- storeQuarantined sFaulty
  assertEqual "reload clears quarantine" [] quarantinedAfter
  -- The store serves the token again.
  (mBefore2, sdelta2, _, oid2) <- planObjectOn (trId tok) mFinal
  _ <- pure (mBefore2, oid2)
  again <- storeCommit sFaulty sdelta2
  assertEqual "commit works after reload" Committed again
  storeClose sFaulty

-- | Seed one durable job on the token for the auth fault cases,
-- so every case pins objects AND jobs intact beside the auth
-- write.
seedAuthJob :: Store -> TokenRecord -> IO ()
seedAuthJob s tok = do
  rJobs <- storeCommit s emptyDelta
    { sdPutJobs = [demoJobPending 10 (trId tok) (trGeneration tok)] }
  assertEqual "job seed" Committed rJobs

-- | Read one token's loaded auth (fails unless exactly one row).
loadedAuth :: Store -> TokenId -> IO TokenAuth
loadedAuth s tid = do
  eLoaded <- storeLoadTokens s
  loaded <- either (assertFailure . show) pure eLoaded
  case [trAuth t | (t, _) <- loaded, trId t == tid] of
    [a] -> pure a
    _ -> assertFailure "token row missing after auth commit"

-- | Auth-only pre-commit injection: the counter write rolls
-- back, live and persisted counters agree on the old value, no
-- commit is counted, and objects plus jobs are intact.
testAuthPreCommit :: OpenWith -> IO ()
testAuthPreCommit openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, recs) <- seedStore sClean
  seedAuthJob sClean tok
  storeClose sClean
  inj <- scriptedFaults [FaultBeforeCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  let bumped = tok { trAuth = (trAuth tok) { taUserAttempts = 1 } }
  result <- storeCommit sFaulty emptyDelta { sdPutTokens = [bumped] }
  case result of
    NotCommitted _ -> pure ()
    other -> assertFailure ("expected NotCommitted, got: " ++ show other)
  auth <- loadedAuth sFaulty (trId tok)
  assertEqual "persisted counters unmoved" (trAuth tok) auth
  eLoaded <- storeLoadTokens sFaulty
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "seed records intact" recs (concatMap snd loaded)
  eJobs <- storeLoadJobs sFaulty
  jobs <- either (assertFailure . show) pure eJobs
  assertEqual "job intact" 1 (length jobs)
  stats <- storeStats sFaulty
  assertEqual "no commit counted" 0 (ssCommits stats)
  storeClose sFaulty

-- | Auth-only ambiguous injection: the counter write lands
-- exactly once and the verification reload confirms it; nothing
-- is ever reissued. The loaded counters show the single bump
-- beside intact objects and jobs.
testAuthAmbiguous :: OpenWith -> IO ()
testAuthAmbiguous openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, recs) <- seedStore sClean
  seedAuthJob sClean tok
  storeClose sClean
  inj <- scriptedFaults [FaultAmbiguousCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  let bumped = tok { trAuth = (trAuth tok) { taUserAttempts = 2 } }
  result <- storeCommit sFaulty emptyDelta { sdPutTokens = [bumped] }
  assertEqual "ambiguous auth write resolves committed" Committed result
  stats <- storeStats sFaulty
  assertEqual "exactly one durable commit" 1 (ssCommits stats)
  assertEqual "exactly one verification reload" 1 (ssVerifyReloads stats)
  auth <- loadedAuth sFaulty (trId tok)
  assertEqual "single bump durable" 2 (taUserAttempts auth)
  eLoaded <- storeLoadTokens sFaulty
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "seed records intact" recs (concatMap snd loaded)
  eJobs <- storeLoadJobs sFaulty
  jobs <- either (assertFailure . show) pure eJobs
  assertEqual "job intact" 1 (length jobs)
  storeClose sFaulty

-- | Auth-only ambiguous plus verification failure:
-- 'CommitUnknown', the token quarantines, and an authoritative
-- reload clears the quarantine and reconciles the auth write
-- present. A fresh handle then reopens clean ('during reopen'):
-- no quarantine, durable counters in place, login never
-- restored.
testAuthAmbiguousUnknown :: OpenWith -> IO ()
testAuthAmbiguousUnknown openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, recs) <- seedStore sClean
  seedAuthJob sClean tok
  storeClose sClean
  inj <- scriptedFaults [FaultAmbiguousCommit, FaultVerifyReload]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  let bumped = tok { trAuth = (trAuth tok) { taUserAttempts = 2 } }
      sdelta = emptyDelta { sdPutTokens = [bumped] }
  result <- storeCommit sFaulty sdelta
  case result of
    CommitUnknown _ -> pure ()
    other -> assertFailure ("expected CommitUnknown, got: " ++ show other)
  assertEqual "unknown reloads first" ReloadFirst (decidePublication result)
  quarantined <- storeQuarantined sFaulty
  assertEqual "token quarantined" [trId tok] (map fst quarantined)
  eReload <- storeReload sFaulty
  _ <- either (assertFailure . show) pure eReload
  quarantinedAfter <- storeQuarantined sFaulty
  assertEqual "quarantine cleared" [] quarantinedAfter
  eLoaded <- storeLoadTokens sFaulty
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "reload reconciles auth write present" ReconciledPresent
    (reconcileReload sdelta loaded)
  auth <- loadedAuth sFaulty (trId tok)
  assertEqual "bump durable" 2 (taUserAttempts auth)
  assertEqual "seed records intact" recs (concatMap snd loaded)
  storeClose sFaulty
  eReopen <- openWith defaultLimits noFaults
  sReopen <- either (assertFailure . show) pure eReopen
  quarantinedReopen <- storeQuarantined sReopen
  assertEqual "fresh handle starts clean" [] quarantinedReopen
  authReopen <- loadedAuth sReopen (trId tok)
  assertEqual "counters survive reopen" 2 (taUserAttempts authReopen)
  assertEqual "login never restored" Nothing (taLogin authReopen)
  storeClose sReopen

-- | Auth-only post-commit injection: durable truth is
-- 'Committed' but the token quarantines until an authoritative
-- reload resolves it; the store then serves the token again,
-- and a close/reopen boundary keeps the counters with a clean
-- handle.
testAuthPostCommit :: OpenWith -> IO ()
testAuthPostCommit openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, recs) <- seedStore sClean
  seedAuthJob sClean tok
  storeClose sClean
  inj <- scriptedFaults [FaultAfterCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  let bumped = tok { trAuth = (trAuth tok) { taUserAttempts = 2 } }
  result <- storeCommit sFaulty emptyDelta { sdPutTokens = [bumped] }
  assertEqual "post-commit auth write still committed" Committed result
  quarantined <- storeQuarantined sFaulty
  assertEqual "token quarantined" [trId tok] (map fst quarantined)
  auth <- loadedAuth sFaulty (trId tok)
  assertEqual "bump durable" 2 (taUserAttempts auth)
  eReload <- storeReload sFaulty
  _ <- either (assertFailure . show) pure eReload
  quarantinedAfter <- storeQuarantined sFaulty
  assertEqual "reload clears quarantine" [] quarantinedAfter
  let bumpedAgain = bumped { trAuth = (trAuth bumped) { taUserAttempts = 3 } }
  again <- storeCommit sFaulty emptyDelta { sdPutTokens = [bumpedAgain] }
  assertEqual "auth write works after reload" Committed again
  authAgain <- loadedAuth sFaulty (trId tok)
  assertEqual "second bump durable" 3 (taUserAttempts authAgain)
  eLoaded <- storeLoadTokens sFaulty
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "seed records intact" recs (concatMap snd loaded)
  eJobs <- storeLoadJobs sFaulty
  jobs <- either (assertFailure . show) pure eJobs
  assertEqual "job intact" 1 (length jobs)
  storeClose sFaulty
  eReopen <- openWith defaultLimits noFaults
  sReopen <- either (assertFailure . show) pure eReopen
  authReopen <- loadedAuth sReopen (trId tok)
  assertEqual "counters survive reopen" 3 (taUserAttempts authReopen)
  assertEqual "login never restored" Nothing (taLogin authReopen)
  assertEqual "epoch never restored" 0 (taAuthEpoch authReopen)
  storeClose sReopen

-- | Read one token's loaded credential (fails unless exactly one row).
loadedCredential :: Store -> TokenId -> IO CredentialRecord
loadedCredential s tid = do
  eCreds <- storeLoadCredentials s
  creds <- either (assertFailure . show) pure eCreds
  case [c | c <- creds, crToken c == tid] of
    [c] -> pure c
    _ -> assertFailure "credential row missing after credential commit"

-- | Credential pre-commit injection: the PIN write rolls back,
-- the persisted credential keeps the old value, no commit is
-- counted, and objects plus jobs are intact.
testCredentialPreCommit :: OpenWith -> IO ()
testCredentialPreCommit openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, recs) <- seedStore sClean
  seedAuthJob sClean tok
  let before = CredentialRecord (trId tok) "so-pin-1" (Just "user-pin-1")
  rSeed <- storeCommit sClean emptyDelta { sdPutCredentials = [before] }
  assertEqual "credential seed" Committed rSeed
  storeClose sClean
  inj <- scriptedFaults [FaultBeforeCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  let rotated = CredentialRecord (trId tok) "so-pin-1" (Just "user-pin-2")
  result <- storeCommit sFaulty emptyDelta { sdPutCredentials = [rotated] }
  case result of
    NotCommitted _ -> pure ()
    other -> assertFailure ("expected NotCommitted, got: " ++ show other)
  kept <- loadedCredential sFaulty (trId tok)
  assertEqual "persisted credential unmoved" before kept
  eLoaded <- storeLoadTokens sFaulty
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "seed records intact" recs (concatMap snd loaded)
  eJobs <- storeLoadJobs sFaulty
  jobs <- either (assertFailure . show) pure eJobs
  assertEqual "job intact" 1 (length jobs)
  storeClose sFaulty

-- | Credential post-commit injection: durable truth is
-- 'Committed' but the token quarantines until an authoritative
-- reload resolves it; the new PIN is durable throughout.
testCredentialPostCommit :: OpenWith -> IO ()
testCredentialPostCommit openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  let before = CredentialRecord (trId tok) "so-pin-1" (Just "user-pin-1")
  rSeed <- storeCommit sClean emptyDelta { sdPutCredentials = [before] }
  assertEqual "credential seed" Committed rSeed
  storeClose sClean
  inj <- scriptedFaults [FaultAfterCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  let rotated = CredentialRecord (trId tok) "so-pin-2" (Just "user-pin-2")
  result <- storeCommit sFaulty emptyDelta { sdPutCredentials = [rotated] }
  assertEqual "post-commit credential write still committed" Committed result
  quarantined <- storeQuarantined sFaulty
  assertEqual "token quarantined" [trId tok] (map fst quarantined)
  landed <- loadedCredential sFaulty (trId tok)
  assertEqual "rotated PIN durable" rotated landed
  eReload <- storeReload sFaulty
  _ <- either (assertFailure . show) pure eReload
  quarantinedAfter <- storeQuarantined sFaulty
  assertEqual "reload clears quarantine" [] quarantinedAfter
  again <- storeCommit sFaulty emptyDelta { sdPutCredentials = [before] }
  assertEqual "credential write works after reload" Committed again
  storeClose sFaulty

-- | A quarantined token refuses credential writes with the
-- quarantine diagnosis (the credential table joins the
-- affected-token coverage); reload clears the way.
testCredentialQuarantine :: OpenWith -> IO ()
testCredentialQuarantine openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  let before = CredentialRecord (trId tok) "so-pin-1" (Just "user-pin-1")
  rSeed <- storeCommit sClean emptyDelta { sdPutCredentials = [before] }
  assertEqual "credential seed" Committed rSeed
  storeClose sClean
  inj <- scriptedFaults [FaultAfterCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  let bumped = tok { trAuth = (trAuth tok) { taUserAttempts = 1 } }
  qr <- storeCommit sFaulty emptyDelta { sdPutTokens = [bumped] }
  assertEqual "quarantining write committed" Committed qr
  quarantined <- storeQuarantined sFaulty
  assertEqual "token quarantined" [trId tok] (map fst quarantined)
  let rotated = CredentialRecord (trId tok) "so-pin-2" (Just "user-pin-2")
  refused <- storeCommit sFaulty emptyDelta { sdPutCredentials = [rotated] }
  case refused of
    NotCommitted (StoreQuarantined _ _) -> pure ()
    other -> assertFailure ("expected quarantine refusal, got: " ++ show other)
  kept <- loadedCredential sFaulty (trId tok)
  assertEqual "quarantined write persisted nothing" before kept
  eReload <- storeReload sFaulty
  _ <- either (assertFailure . show) pure eReload
  admitted <- storeCommit sFaulty emptyDelta { sdPutCredentials = [rotated] }
  assertEqual "credential write works after reload" Committed admitted
  storeClose sFaulty

-- | Bounded rendezvous for every cross-thread wait in the
-- interruption cases: 5 seconds, matching the pre-split guards.
rendezvousTimeout :: Int
rendezvousTimeout = 5000000

-- | Whether a worker outcome is an observed async kill -- and not
-- ordinary completion or some other death.
isObservedKill :: Either SomeException () -> Bool
isObservedKill (Left e) = case fromException e of
  Just ThreadKilled -> True
  _ -> False
isObservedKill (Right ()) = False

-- | Run a worker with 'forkFinally' outcome capture. The fork happens
-- BEFORE any masking: forking inside 'bracket' acquisition would run
-- the worker masked (acquisition is masked and 'forkFinally' restores
-- that masked state into the worker), but the post-commit rendezvous
-- must run unmasked, in the caller's state. Every exit path -- pass
-- or failure -- cancels a still-live worker and joins the outcome
-- with bounded waits, so a stuck worker cannot leak past the case.
-- The body observes the outcome with 'readMVar' (leaving it for the
-- bounded join to drain instantly); the join only blocks when the
-- worker never reported. Release is best-effort hygiene with a
-- last-resort stderr breadcrumb: every body wait already fails with
-- its own diagnostic before release can time out, so release never
-- raises (it must not mask the body's report). Join failure is
-- defense-in-depth only: the worker path holds no uninterruptible
-- operations ('mask_'-only commit regions plus interruptible waits;
-- the backend's single 'unsafe' FFI call is a non-blocking open-path
-- flock), so cancellation is always deliverable and the join always
-- succeeds; blocking teardown on confirmed completion instead would
-- turn a bounded failure into a potential suite hang.
withWorker
  :: IO ()
  -> ((ThreadId, MVar (Either SomeException ())) -> IO a)
  -> IO a
withWorker action use = do
  outcomeVar <- newEmptyMVar
  tid <- forkFinally action (putMVar outcomeVar)
  use (tid, outcomeVar) `finally` release tid outcomeVar
  where
    release tid outcomeVar = do
      _ <- timeout rendezvousTimeout (killThread tid)
      mJoined <- timeout rendezvousTimeout (takeMVar outcomeVar)
      case mJoined of
        Just _ -> pure ()
        Nothing -> hPutStrLn stderr
          "withWorker: worker join timed out after kill (5s guard)"

-- | The store still serves after the interruption: either a fresh
-- same-identity handle opens cleanly, or the victim itself commits
-- again (its one-shot hooks were drained and only refill inert
-- cells). Leaves closing to the caller.
assertStoreUsable :: OpenWith -> Store -> TokenRecord -> Model -> IO ()
assertStoreUsable openWith victim tok mBefore = do
  eClean2 <- openWith defaultLimits noFaults
  case eClean2 of
    Right s2 -> storeClose s2
    Left _ -> do
      -- Same-identity open still owned by victim: use victim.
      (mBefore2, sdelta2, _, _) <- planObjectOn (trId tok) mBefore
      _ <- pure mBefore2
      r2 <- timeout rendezvousTimeout (storeCommit victim sdelta2)
      case r2 of
        Just Committed -> pure ()
        other -> assertFailure ("store unusable after kill: " ++ show other)

-- | The expected durable record for a planned creation: re-derive
-- the scratch-model object state from the plan outputs and encode it
-- exactly as the commit under test does.
expectedRecord :: TokenId -> Model -> StateDelta -> ObjectId -> IO ObjectRecord
expectedRecord tok mBefore mdelta oid = do
  mScratch <- expectRight "scratch publish" (publishDelta mBefore mdelta)
  ost <- expectJust "fresh object" (lookupObject mScratch oid)
  pure (objectToRecord tok ost)

-- | The durable delta is whole: the seed token is byte-exact, every
-- seed child is preserved byte-exact, and the committed object lands
-- as the complete expected record. Children compare ordered by id so
-- backend row order cannot matter.
assertWholeDurable
  :: TokenRecord -> [ObjectRecord] -> ObjectRecord
  -> [(TokenRecord, [ObjectRecord])] -> IO ()
assertWholeDurable tok seedRecs expectedRec loaded = case loaded of
  [(tokAfter, objsAfter)] -> do
    assertEqual "seed token whole" tok tokAfter
    assertEqual "children whole"
      (sortOn orId (seedRecs ++ [expectedRec]))
      (sortOn orId objsAfter)
  _ -> assertFailure ("expected one token, got: " ++ show (length loaded))

-- | Both commit probes run inside the masked region: 'fiOnMasked'
-- fires on entry and 'fiOnResult' fires with the determined result
-- while still masked. Each hook records 'getMaskingState' without
-- blocking (a bare state read plus a 'putMVar' into a fresh empty
-- cell); the case then requires the intended 'MaskedInterruptible'
-- state at both probes, the 'Committed' result, and durable whole
-- state. A scratch revision with the production mask removed must
-- fail this case (remote mutant control, never merged).
testCommitMasking :: OpenWith -> IO ()
testCommitMasking openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, seedRecs) <- seedStore sClean
  storeClose sClean
  maskedVar <- newEmptyMVar
  resultVar <- newEmptyMVar
  inj0 <- scriptedFaults []
  let inj = withResultHook recordResult (withMaskHook recordMasked inj0)
      recordMasked = getMaskingState >>= putMVar maskedVar
      recordResult r = do
        st <- getMaskingState
        putMVar resultVar (r, st)
  eStore <- openWith defaultLimits inj
  store <- either (assertFailure . show) pure eStore
  let runCase = do
        (mBefore, sdelta, mdelta, oid) <- planObject store (trId tok)
        expectedRec <- expectedRecord (trId tok) mBefore mdelta oid
        result <- storeCommit store sdelta
        assertEqual "commit result" Committed result
        mMasked <- timeout rendezvousTimeout (takeMVar maskedVar)
        maskedState <- maybe
          (assertFailure "masked-entry hook never fired (5s guard)") pure mMasked
        assertEqual "masked-entry state" MaskedInterruptible maskedState
        mHooked <- timeout rendezvousTimeout (takeMVar resultVar)
        (hookedResult, resultState) <- maybe
          (assertFailure "result hook never fired (5s guard)") pure mHooked
        assertEqual "hooked result agrees" Committed hookedResult
        assertEqual "result-hook state" MaskedInterruptible resultState
        eLoaded <- storeLoadTokens store
        loaded <- either (assertFailure . show) pure eLoaded
        assertWholeDurable tok seedRecs expectedRec loaded
        stats <- storeStats store
        assertEqual "one commit counted" 1 (ssCommits stats)
  runCase `finally` storeClose store

-- | A kill delivered after the commit result is determined is
-- observed as 'ThreadKilled' while the captured 'Committed' result
-- stays durable whole.
--
-- Schedule: the worker commits, then reports its masking state and
-- waits at a post-commit rendezvous OUTSIDE the masked region (a
-- 'takeMVar' inside 'mask_' is still interruptible and would change
-- what is being tested). The controller waits for the result hook --
-- which fires while still masked, so the result is determined before
-- injection -- then takes the worker's rendezvous report, requiring
-- 'Unmasked'. That handshake proves the worker is alive and blocked
-- at the rendezvous when the kill lands; the controller then requires
-- the actual 'forkFinally' outcome to be 'ThreadKilled'. The kill is
-- honestly described as injection after the result: this case does
-- not claim to have forced an exception pending inside every native
-- SQL window.
testCommitInterruption :: OpenWith -> IO ()
testCommitInterruption openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, seedRecs) <- seedStore sClean
  storeClose sClean
  resultVar <- newEmptyMVar
  releaseVar <- newEmptyMVar
  workerMaskVar <- newEmptyMVar
  inj0 <- scriptedFaults []
  let inj = withResultHook (putMVar resultVar) inj0
  eVictim <- openWith defaultLimits inj
  victim <- either (assertFailure . show) pure eVictim
  let runCase = do
        (mBefore, sdelta, mdelta, oid) <- planObject victim (trId tok)
        expectedRec <- expectedRecord (trId tok) mBefore mdelta oid
        let workerBody = do
              _ <- storeCommit victim sdelta
              st <- getMaskingState
              putMVar workerMaskVar st
              takeMVar releaseVar
            runWorker tid outcomeVar = do
              mResult <- timeout rendezvousTimeout (takeMVar resultVar)
              result <- maybe (assertFailure "commit result never reported (5s guard)") pure mResult
              assertEqual "commit survived to its result" Committed result
              mWorkerMask <- timeout rendezvousTimeout (takeMVar workerMaskVar)
              workerMask <- maybe
                (assertFailure "worker never reached the rendezvous (5s guard)") pure mWorkerMask
              assertEqual "rendezvous runs unmasked" Unmasked workerMask
              mThrown <- timeout rendezvousTimeout (throwTo tid ThreadKilled)
              case mThrown of
                Nothing -> assertFailure "kill delivery stuck (5s guard)"
                Just () -> pure ()
              mOutcome <- timeout rendezvousTimeout (readMVar outcomeVar)
              outcome <- maybe (assertFailure "worker outcome never reported (5s guard)") pure mOutcome
              assertBool ("expected observed ThreadKilled, got: " ++ show outcome)
                (isObservedKill outcome)
              eLoaded <- storeLoadTokens victim
              loaded <- either (assertFailure . show) pure eLoaded
              assertWholeDurable tok seedRecs expectedRec loaded
              stats <- storeStats victim
              assertEqual "one commit counted" 1 (ssCommits stats)
              assertStoreUsable openWith victim tok mBefore
        withWorker workerBody $ \(tid, outcomeVar) -> runWorker tid outcomeVar
  runCase `finally` storeClose victim

-- | Worker-completed-before-injection control: the same schedule as
-- 'testCommitInterruption', except the controller releases the
-- worker instead of killing it. Ordinary completion MUST fail the
-- cancellation assertion, and a late kill to the already completed
-- worker changes nothing -- the controller cannot throw to an
-- already dead worker and still pass.
testCompletionControl :: OpenWith -> IO ()
testCompletionControl openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, seedRecs) <- seedStore sClean
  storeClose sClean
  resultVar <- newEmptyMVar
  releaseVar <- newEmptyMVar
  workerMaskVar <- newEmptyMVar
  inj0 <- scriptedFaults []
  let inj = withResultHook (putMVar resultVar) inj0
  eVictim <- openWith defaultLimits inj
  victim <- either (assertFailure . show) pure eVictim
  let runCase = do
        (mBefore, sdelta, mdelta, oid) <- planObject victim (trId tok)
        expectedRec <- expectedRecord (trId tok) mBefore mdelta oid
        let workerBody = do
              _ <- storeCommit victim sdelta
              st <- getMaskingState
              putMVar workerMaskVar st
              takeMVar releaseVar
            runWorker tid outcomeVar = do
              mResult <- timeout rendezvousTimeout (takeMVar resultVar)
              result <- maybe (assertFailure "commit result never reported (5s guard)") pure mResult
              assertEqual "commit result captured" Committed result
              mWorkerMask <- timeout rendezvousTimeout (takeMVar workerMaskVar)
              workerMask <- maybe
                (assertFailure "worker never reached the rendezvous (5s guard)") pure mWorkerMask
              assertEqual "rendezvous runs unmasked" Unmasked workerMask
              -- Ordinary completion: release the worker, do not kill it.
              putMVar releaseVar ()
              mOutcome <- timeout rendezvousTimeout (readMVar outcomeVar)
              outcome <- maybe (assertFailure "worker outcome never reported (5s guard)") pure mOutcome
              case outcome of
                Right () -> pure ()
                Left e -> assertFailure ("control worker unexpectedly died: " ++ show e)
              assertBool "ordinary completion must fail the cancellation assertion"
                (not (isObservedKill outcome))
              -- Late injection after completion changes nothing.
              mThrown <- timeout rendezvousTimeout (throwTo tid ThreadKilled)
              case mThrown of
                Nothing -> assertFailure "late kill delivery stuck (5s guard)"
                Just () -> pure ()
              mOutcome2 <- timeout rendezvousTimeout (readMVar outcomeVar)
              outcome2 <- maybe (assertFailure "worker outcome lost (5s guard)") pure mOutcome2
              assertBool "late kill must not fabricate cancellation"
                (not (isObservedKill outcome2))
              eLoaded <- storeLoadTokens victim
              loaded <- either (assertFailure . show) pure eLoaded
              assertWholeDurable tok seedRecs expectedRec loaded
              stats <- storeStats victim
              assertEqual "one commit counted" 1 (ssCommits stats)
        withWorker workerBody $ \(tid, outcomeVar) -> runWorker tid outcomeVar
  runCase `finally` storeClose victim

-- | Injected full disk: a clean 'NotCommitted' with no durable
-- or model effect, and the store stays healthy afterwards. The
-- injection refuses BEFORE the transaction starts, so it proves
-- pre-transaction refusal only; a native SQLITE_FULL inside the
-- transaction body is covered by the SQLite-only
-- @body-failure-sqlite@ group (page-capped connection).
testFullDisk :: OpenWith -> IO ()
testFullDisk openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  storeClose sClean
  inj <- scriptedFaults [FaultFullDisk]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  (mBefore, sdelta, mdelta, oid) <- planObject sFaulty (trId tok)
  result <- storeCommit sFaulty sdelta
  case result of
    NotCommitted (StoreFull _) -> pure ()
    other -> assertFailure ("expected full-disk refusal, got: " ++ show other)
  mFinal <- publishOn result mBefore mdelta
  assertBool "model unpublished" (lookupObject mFinal oid == Nothing)
  eLoaded <- storeLoadTokens sFaulty
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "durable unchanged" 2 (countObjects loaded)
  stats <- storeStats sFaulty
  assertEqual "no commit counted" 0 (ssCommits stats)
  -- The fault was one-shot: the store serves clean commits after.
  (_, sdelta2, _, _) <- planObject sFaulty (trId tok)
  again <- storeCommit sFaulty sdelta2
  assertEqual "store healthy after" Committed again
  storeClose sFaulty

-- | Object-count limit: the third object refuses at a cap of two
-- (with nothing landing) and commits at a cap of three.
testLimitObjects :: OpenWith -> IO ()
testLimitObjects openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  storeClose sClean
  eTight <- openWith defaultLimits { limMaxObjects = 2 } noFaults
  sTight <- either (assertFailure . show) pure eTight
  (_, sdelta, _, oid) <- planObject sTight (trId tok)
  refused <- storeCommit sTight sdelta
  case refused of
    NotCommitted (StoreLimit _) -> pure ()
    other -> assertFailure ("expected limit refusal, got: " ++ show other)
  eLoaded <- storeLoadTokens sTight
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "nothing landed" 2 (countObjects loaded)
  assertBool "object absent" (not (objectPresent oid loaded))
  storeClose sTight
  eRoomy <- openWith defaultLimits { limMaxObjects = 3 } noFaults
  sRoomy <- either (assertFailure . show) pure eRoomy
  (_, sdelta2, _, _) <- planObject sRoomy (trId tok)
  ok <- storeCommit sRoomy sdelta2
  assertEqual "cap of three commits" Committed ok
  storeClose sRoomy

-- | Per-record limit: a record one byte over refuses; the exact
-- size commits.
testLimitRecord :: OpenWith -> IO ()
testLimitRecord openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  storeClose sClean
  eProbe <- openWith defaultLimits noFaults
  sProbe <- either (assertFailure . show) pure eProbe
  (_, sdelta, _, oid) <- planObject sProbe (trId tok)
  rec <- case sdPutObjects sdelta of
    [ObjectPut _ r] -> pure r
    _ -> assertFailure "expected one object put"
  let size = length (encodeObjectRecord rec)
  storeClose sProbe
  assertBool "non-trivial record" (size > 16)
  eTight <- openWith defaultLimits { limMaxRecordBytes = size - 1 } noFaults
  sTight <- either (assertFailure . show) pure eTight
  refused <- storeCommit sTight sdelta
  case refused of
    NotCommitted (StoreLimit _) -> pure ()
    other -> assertFailure ("expected limit refusal, got: " ++ show other)
  eLoaded <- storeLoadTokens sTight
  loaded <- either (assertFailure . show) pure eLoaded
  assertBool "object absent" (not (objectPresent oid loaded))
  storeClose sTight
  eRoomy <- openWith defaultLimits { limMaxRecordBytes = size } noFaults
  sRoomy <- either (assertFailure . show) pure eRoomy
  ok <- storeCommit sRoomy sdelta
  assertEqual "exact size commits" Committed ok
  storeClose sRoomy

-- | Total-bytes limit: one byte over the projected total refuses;
-- the exact total commits.
testLimitTotal :: OpenWith -> IO ()
testLimitTotal openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  before <- expectInspect sClean
  storeClose sClean
  let currentBytes = sum (map (length . docJson) before)
  eProbe <- openWith defaultLimits noFaults
  sProbe <- either (assertFailure . show) pure eProbe
  (_, sdelta, _, oid) <- planObject sProbe (trId tok)
  rec <- case sdPutObjects sdelta of
    [ObjectPut _ r] -> pure r
    _ -> assertFailure "expected one object put"
  let projected = currentBytes + length (encodeObjectRecord rec)
  storeClose sProbe
  eTight <- openWith defaultLimits { limMaxTotalBytes = projected - 1 } noFaults
  sTight <- either (assertFailure . show) pure eTight
  refused <- storeCommit sTight sdelta
  case refused of
    NotCommitted (StoreLimit _) -> pure ()
    other -> assertFailure ("expected limit refusal, got: " ++ show other)
  eLoaded <- storeLoadTokens sTight
  loaded <- either (assertFailure . show) pure eLoaded
  assertBool "object absent" (not (objectPresent oid loaded))
  storeClose sTight
  eRoomy <- openWith defaultLimits { limMaxTotalBytes = projected } noFaults
  sRoomy <- either (assertFailure . show) pure eRoomy
  ok <- storeCommit sRoomy sdelta
  assertEqual "exact total commits" Committed ok
  storeClose sRoomy

-- | Reset runs the same protocol as commit: while its token is
-- quarantined it refuses, and after reload it succeeds.
testResetQuarantine :: OpenWith -> IO ()
testResetQuarantine openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  storeClose sClean
  inj <- scriptedFaults [FaultAfterCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  (_, sdelta, _, _) <- planObject sFaulty (trId tok)
  planted <- storeCommit sFaulty sdelta
  assertEqual "planted commit" Committed planted
  quarantined <- storeQuarantined sFaulty
  assertEqual "token quarantined" [trId tok] (map fst quarantined)
  let replacement = tok { trGeneration = Generation 2 }
  refused <- storeResetToken sFaulty (trId tok) (trGeneration tok) replacement
  case refused of
    NotCommitted (StoreQuarantined tid _) -> assertEqual "quarantined token" (trId tok) tid
    other -> assertFailure ("expected quarantine refusal, got: " ++ show other)
  eReload <- storeReload sFaulty
  _ <- either (assertFailure . show) pure eReload
  ok <- storeResetToken sFaulty (trId tok) (trGeneration tok) replacement
  assertEqual "reset works after reload" Committed ok
  storeClose sFaulty

-- | C2: a token refresh that commits ambiguously still verifies
-- via reload (exactly one durable commit, exactly one
-- verification reload) and preserves every owned object and job
-- byte-exact.
testAmbiguousTokenRefresh :: OpenWith -> IO ()
testAmbiguousTokenRefresh openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, recs) <- seedStore sClean
  let jobs =
        [ demoJobPending 60 (trId tok) (trGeneration tok)
        , demoJobResult 61 (trId tok) (trGeneration tok)
        ]
  rJobs <- storeCommit sClean emptyDelta { sdPutJobs = jobs }
  assertEqual "jobs seed" Committed rJobs
  storeClose sClean
  inj <- scriptedFaults [FaultAmbiguousCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  let tok' = tok { trLabel = "seed-token-relabeled" }
  result <- storeCommit sFaulty emptyDelta { sdPutTokens = [tok'] }
  assertEqual "ambiguous refresh resolves committed" Committed result
  stats <- storeStats sFaulty
  assertEqual "exactly one durable commit" 1 (ssCommits stats)
  assertEqual "exactly one verification reload" 1 (ssVerifyReloads stats)
  eLoaded <- storeLoadTokens sFaulty
  loaded <- either (assertFailure . show) pure eLoaded
  case loaded of
    [(t2, objs2)] -> do
      assertEqual "token refreshed" tok' t2
      assertEqual "objects preserved" recs objs2
    _ -> assertFailure ("expected one token, got: " ++ show (length loaded))
  eJobs <- storeLoadJobs sFaulty
  jobsAfter <- either (assertFailure . show) pure eJobs
  assertEqual "jobs preserved" jobs jobsAfter
  storeClose sFaulty

-- | Ambiguous delete-plus-stale-counter: dropping legacy job 41
-- while repeating counter 1 durably deletes the job and advances
-- the mark to 42 (deletion coverage), so reconciliation reports
-- 'Committed' — the verdict agrees with the durable effect,
-- never the raw request. The deleted id is never re-minted.
testAmbiguousDeleteStaleCounter :: OpenWith -> IO ()
testAmbiguousDeleteStaleCounter openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  let gen = trGeneration tok
  seeded <- storeCommit sClean emptyDelta
    { sdPutJobs = [demoJobPending 41 (trId tok) gen] }
  assertEqual "legacy job seed" Committed seeded
  marked <- storeCommit sClean emptyDelta
    { sdPutMeta = [(jobIdCounterKey, encodeHexWord64 1)] }
  assertEqual "legacy mark seed" Committed marked
  storeClose sClean
  inj <- scriptedFaults [FaultAmbiguousCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  result <- storeCommit sFaulty emptyDelta
    { sdDropJobs = [41]
    , sdPutMeta = [(jobIdCounterKey, encodeHexWord64 1)]
    }
  assertEqual "ambiguous delete-plus-counter resolves committed" Committed result
  stats <- storeStats sFaulty
  assertEqual "exactly one durable commit" 1 (ssCommits stats)
  assertEqual "exactly one verification reload" 1 (ssVerifyReloads stats)
  eJobs <- storeLoadJobs sFaulty
  jobs <- either (assertFailure . show) pure eJobs
  assertEqual "job durably deleted" [] jobs
  mark <- loadCounter sFaulty
  assertEqual "coverage advanced the mark" (Just (encodeHexWord64 42)) mark
  eNext <- storeReserveJobId sFaulty
  next <- either (assertFailure . show) pure eNext
  assertEqual "deleted id never re-minted" 42 next
  storeClose sFaulty

-- | Control: the same delete-plus-stale-counter shape that
-- genuinely does not apply (pre-commit fault) still reports
-- 'NotCommitted', with the job row and the mark untouched.
testUnappliedDeleteStaleCounter :: OpenWith -> IO ()
testUnappliedDeleteStaleCounter openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  let gen = trGeneration tok
  seeded <- storeCommit sClean emptyDelta
    { sdPutJobs = [demoJobPending 41 (trId tok) gen] }
  assertEqual "legacy job seed" Committed seeded
  marked <- storeCommit sClean emptyDelta
    { sdPutMeta = [(jobIdCounterKey, encodeHexWord64 1)] }
  assertEqual "legacy mark seed" Committed marked
  storeClose sClean
  inj <- scriptedFaults [FaultBeforeCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  result <- storeCommit sFaulty emptyDelta
    { sdDropJobs = [41]
    , sdPutMeta = [(jobIdCounterKey, encodeHexWord64 1)]
    }
  case result of
    NotCommitted _ -> pure ()
    other -> assertFailure ("expected NotCommitted, got: " ++ show other)
  stats <- storeStats sFaulty
  assertEqual "no commit counted" 0 (ssCommits stats)
  eJobs <- storeLoadJobs sFaulty
  jobs <- either (assertFailure . show) pure eJobs
  assertEqual "job row untouched" [41] (map jrPersistentId jobs)
  mark <- loadCounter sFaulty
  assertEqual "mark untouched" (Just (encodeHexWord64 1)) mark
  storeClose sFaulty

-- | Ambiguous conflicting duplicate meta puts reconcile
-- committed against the stored effect: exactly one of the two
-- values lands (backend put order decides), the commit is never
-- reissued, and the verdict agrees that it applied.
testAmbiguousDuplicateMeta :: OpenWith -> IO ()
testAmbiguousDuplicateMeta openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  _ <- seedStore sClean
  storeClose sClean
  inj <- scriptedFaults [FaultAmbiguousCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  result <- storeCommit sFaulty emptyDelta
    { sdPutMeta = [("probe", "a"), ("probe", "b")] }
  assertEqual "ambiguous duplicate meta resolves committed" Committed result
  stats <- storeStats sFaulty
  assertEqual "exactly one durable commit" 1 (ssCommits stats)
  assertEqual "exactly one verification reload" 1 (ssVerifyReloads stats)
  eMeta <- storeLoadMeta sFaulty
  meta <- either (assertFailure . show) pure eMeta
  assertBool "one duplicate value stored"
    (lookup "probe" meta `elem` [Just "a", Just "b"])
  storeClose sFaulty

-- | Read the durable job-id mark ('Nothing' = the key is absent).
loadCounter :: Store -> IO (Maybe String)
loadCounter s = do
  eMeta <- storeLoadMeta s
  meta <- either (assertFailure . show) pure eMeta
  pure (lookup jobIdCounterKey meta)

-- | An ambiguous reservation reconciles present: the id is
-- durable, exactly one commit and one verification reload are
-- counted, and the next reservation advances (never a reuse).
testReserveAmbiguousPresent :: OpenWith -> IO ()
testReserveAmbiguousPresent openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  _ <- seedStore sClean
  storeClose sClean
  inj <- scriptedFaults [FaultAmbiguousCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  ePid <- storeReserveJobId sFaulty
  pid <- either (assertFailure . show) pure ePid
  assertEqual "ambiguous reservation reconciles present" 1 pid
  stats <- storeStats sFaulty
  assertEqual "exactly one durable commit" 1 (ssCommits stats)
  assertEqual "exactly one verification reload" 1 (ssVerifyReloads stats)
  mark <- loadCounter sFaulty
  assertEqual "mark advanced" (Just (encodeHexWord64 2)) mark
  eNext <- storeReserveJobId sFaulty
  next <- either (assertFailure . show) pure eNext
  assertEqual "never a reuse" 2 next
  storeClose sFaulty

-- | An ambiguous reservation with failed verification fails
-- closed: no id is returned, the handle quarantines until an
-- authoritative reload, and later reservations mint fresh ids
-- with no phantom records.
testReserveAmbiguousUnknown :: OpenWith -> IO ()
testReserveAmbiguousUnknown openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  storeClose sClean
  inj <- scriptedFaults [FaultAmbiguousCommit, FaultVerifyReload]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  ePid <- storeReserveJobId sFaulty
  case ePid of
    Left _ -> pure ()
    Right pid -> assertFailure ("unresolved reservation must fail, got: " ++ show pid)
  q <- storeQuarantined sFaulty
  assertBool "handle quarantined" (not (null q))
  assertBool "seed token quarantined" (trId tok `elem` map fst q)
  stats <- storeStats sFaulty
  assertBool "quarantine counted" (ssQuarantines stats >= 1)
  assertEqual "no commit counted" 0 (ssCommits stats)
  eReload <- storeReload sFaulty
  either (assertFailure . show) pure eReload
  q2 <- storeQuarantined sFaulty
  assertEqual "reload clears" [] q2
  eNext <- storeReserveJobId sFaulty
  next <- either (assertFailure . show) pure eNext
  eAfter <- storeReserveJobId sFaulty
  after <- either (assertFailure . show) pure eAfter
  assertBool "fresh ids distinct" (next /= after)
  eJobs <- storeLoadJobs sFaulty
  jobs <- either (assertFailure . show) pure eJobs
  assertEqual "no phantom records" [] jobs
  storeClose sFaulty

-- | Reservation honors the pre-commit and capacity faults: each
-- fails clean with the mark untouched, and the next call serves.
testReserveFaults :: OpenWith -> IO ()
testReserveFaults openWith = do
  eStore <- openWith defaultLimits noFaults
  store <- either (assertFailure . show) pure eStore
  _ <- seedStore store
  storeClose store
  injPre <- scriptedFaults [FaultBeforeCommit]
  ePre <- openWith defaultLimits injPre
  sPre <- either (assertFailure . show) pure ePre
  eRefused <- storeReserveJobId sPre
  case eRefused of
    Left (StoreIO _) -> pure ()
    other -> assertFailure ("expected StoreIO, got: " ++ show other)
  first <- storeReserveJobId sPre >>= expectRight "reserve after pre-commit fault"
  assertEqual "nothing burned" 1 first
  storeClose sPre
  injFull <- scriptedFaults [FaultFullDisk]
  eFull <- openWith defaultLimits injFull
  sFull <- either (assertFailure . show) pure eFull
  eDisk <- storeReserveJobId sFull
  case eDisk of
    Left (StoreFull _) -> pure ()
    other -> assertFailure ("expected StoreFull, got: " ++ show other)
  second <- storeReserveJobId sFull >>= expectRight "reserve after full-disk fault"
  assertEqual "nothing burned" 2 second
  mark <- loadCounter sFull
  assertEqual "mark advanced once per success" (Just (encodeHexWord64 3)) mark
  storeClose sFull

-- | A failed job insert leaves a gap: the burned reservation is
-- never re-minted, and the burned id names no record.
testReserveInsertGap :: OpenWith -> IO ()
testReserveInsertGap openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  burned <- storeReserveJobId sClean >>= expectRight "reserve"
  storeClose sClean
  inj <- scriptedFaults [FaultBeforeCommit]
  eFaulty <- openWith defaultLimits inj
  sFaulty <- either (assertFailure . show) pure eFaulty
  failed <- storeCommit sFaulty emptyDelta
    { sdPutJobs = [demoJobPending burned (trId tok) (trGeneration tok)] }
  case failed of
    NotCommitted _ -> pure ()
    other -> assertFailure ("expected NotCommitted, got: " ++ show other)
  storeClose sFaulty
  eFinal <- openWith defaultLimits noFaults
  sFinal <- either (assertFailure . show) pure eFinal
  next <- storeReserveJobId sFinal >>= expectRight "reserve after gap"
  assertEqual "gap, never a reuse" (burned + 1) next
  landed <- storeCommit sFinal emptyDelta
    { sdPutJobs = [demoJobPending next (trId tok) (trGeneration tok)] }
  assertEqual "insert lands" Committed landed
  eJobs <- storeLoadJobs sFinal
  jobs <- either (assertFailure . show) pure eJobs
  assertEqual "burned id names no record" [next] (map jrPersistentId jobs)
  storeClose sFinal

-- | Job cap: the third job refuses at a cap of two and commits
-- at a cap of three.
testLimitJobs :: OpenWith -> IO ()
testLimitJobs openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  let gen = trGeneration tok
  seeded <- storeCommit sClean emptyDelta
    { sdPutJobs =
        [ demoJobPending 50 (trId tok) gen
        , demoJobResult 51 (trId tok) gen
        ]
    }
  assertEqual "jobs seed" Committed seeded
  storeClose sClean
  eTight <- openWith defaultLimits { limMaxJobs = 2 } noFaults
  sTight <- either (assertFailure . show) pure eTight
  refused <- storeCommit sTight emptyDelta
    { sdPutJobs = [demoJobPending 52 (trId tok) gen] }
  case refused of
    NotCommitted (StoreLimit _) -> pure ()
    other -> assertFailure ("expected limit refusal, got: " ++ show other)
  eJobs <- storeLoadJobs sTight
  jobs <- either (assertFailure . show) pure eJobs
  assertEqual "nothing landed" 2 (length jobs)
  storeClose sTight
  eRoomy <- openWith defaultLimits { limMaxJobs = 3 } noFaults
  sRoomy <- either (assertFailure . show) pure eRoomy
  ok <- storeCommit sRoomy emptyDelta
    { sdPutJobs = [demoJobPending 52 (trId tok) gen] }
  assertEqual "cap of three commits" Committed ok
  storeClose sRoomy

-- ---------------------------------------------------------------------------
-- Runtime simulation helpers
-- ---------------------------------------------------------------------------

-- | Plan one object creation against a scratch model seated like the
-- store: return the pre-publish model, the store delta, the model
-- delta, and the fresh id.
planObject :: Store -> TokenId -> IO (Model, StoreDelta, StateDelta, ObjectId)
planObject store tok = do
  mSeeded <- seedModel store
  planObjectOn tok mSeeded

-- | Plan one object creation against a given model.
planObjectOn :: TokenId -> Model -> IO (Model, StoreDelta, StateDelta, ObjectId)
planObjectOn tok model = do
  let tmpl =
        [ (AttrClass, ValULong 3)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "commit-case")
        , (AttrValue, ValBytes "commit-bytes")
        ]
  st <- expectJust "case session" (lookupSessionOf model)
  case planCreateObject model st tmpl of
    Immediate pc -> do
      let oid = ObjectId (mNextObject model)
      mScratch <- expectRight "scratch publish" (publishDelta model (pcDelta pc))
      ost <- expectJust "fresh object" (lookupObject mScratch oid)
      let sdelta = emptyDelta
            { sdPutObjects = [ObjectPut Nothing (objectToRecord tok ost)] }
      pure (model, sdelta, pcDelta pc, oid)
    other -> assertFailure ("plan did not commit: " ++ show other)

-- | Rebuild a scratch model matching the store: token seated and
-- one session open on slot 0, allocation counters reserved past
-- the stored objects so fresh plans never collide with them.
seedModel :: Store -> IO Model
seedModel store = do
  eLoaded <- storeLoadTokens store
  loaded <- either (assertFailure . show) pure eLoaded
  let slot = SlotId 0
  m0 <- expectRight "seat+open" (publishDelta (addToken emptyModel slot)
    (StateDelta [DeltaOpenSession (SessionId 1) slot False]))
  pure (reserveRestoredIds [orId o | (_, objs) <- loaded, o <- objs] m0)

-- | The runtime publication rule: publish the model delta if and
-- only if the store committed.
publishOn :: CommitResult -> Model -> StateDelta -> IO Model
publishOn result mBefore mdelta = case decidePublication result of
  PublishDelta -> expectRight "runtime publish" (publishDelta mBefore mdelta)
  _ -> pure mBefore

-- | Look up the case session (session 1).
lookupSessionOf :: Model -> Maybe SessionState
lookupSessionOf m = Map.lookup (SessionId 1) (mSessions m)

-- | Count stored objects across tokens.
countObjects :: [(TokenRecord, [ObjectRecord])] -> Int
countObjects = sum . map (length . snd)

-- | Whether an object id is present in loaded state.
objectPresent :: ObjectId -> [(TokenRecord, [ObjectRecord])] -> Bool
objectPresent oid = any (any ((== oid) . orId) . snd)

-- | Hand-built token fixture.
demoToken :: TokenId -> TokenRecord
demoToken tid = TokenRecord
  { trId = tid
  , trSlot = SlotId 0
  , trGeneration = Generation 1
  , trLabel = "demo"
  , trAuth = tokenAuthNew
  }

-- | Hand-built object fixture.
demoObject :: TokenId -> ObjectId -> ObjectRecord
demoObject tok oid = ObjectRecord
  { orId = oid
  , orToken = tok
  , orClass = 3
  , orKeyType = Nothing
  , orAttrs = Map.fromList [(AttrClass, ValULong 3)]
  , orMaterialEncoding = "none"
  , orMaterial = Nothing
  , orRevision = Revision 1
  }

-- ---------------------------------------------------------------------------
-- Identity upgrade fixtures
-- ---------------------------------------------------------------------------

-- | The identity-upgrade cases every backend runs: legacy
-- stores reopen byte-identical under matching catalogs,
-- interrupted move sequences refuse until completed, and
-- positional downgrades over moved stores refuse. These
-- fixtures pin the no-mutation-of-old-stores behavior the
-- explicit move operation builds on; the same scenarios
-- through the production open live in StoreSpec's
-- standard-open group.
identityCases :: ((OpenWith -> IO ()) -> IO ()) -> [TestTree]
identityCases withIdentity =
  [ testCase "legacy store reopens byte-identical under matching config" $
      withIdentity testLegacyReopenStable
  , testCase "interrupted move sequence refuses until completed" $
      withIdentity testInterruptedMoveRefuses
  , testCase "positional downgrade over a moved store refuses" $
      withIdentity testDowngradeRefuses
  ]

-- | A @[tokens]@ document with the given parallel arrays (an
-- empty id list omits the @token_ids@ key).
tokensDoc :: [String] -> [String] -> [String] -> [String] -> String
tokensDoc labels soPins userPins ids = unlines $
  [ "schema_version = 1"
  , "[tokens]"
  , "labels = " ++ show labels
  , "so_pins = " ++ show soPins
  , "user_pins = " ++ show userPins
  ] ++ ["token_ids = " ++ show ids | not (null ids)]

-- | The legacy positional three-token document.
legacyThreeDoc :: String
legacyThreeDoc = tokensDoc
  ["haskoki-demo", "haskoki-ops", "haskoki-audit"]
  ["5678", "6789", "7890"]
  ["1234", "2345", "3456"]
  []

-- | The same catalog with pinned positional ids.
pinnedThreeDoc :: String
pinnedThreeDoc = tokensDoc
  ["haskoki-demo", "haskoki-ops", "haskoki-audit"]
  ["5678", "6789", "7890"]
  ["1234", "2345", "3456"]
  ["1", "2", "3"]

-- | The swapped pinned document: audit at slot 1, ops at
-- slot 2, each with its own PINs.
swapThreeDoc :: String
swapThreeDoc = tokensDoc
  ["haskoki-demo", "haskoki-audit", "haskoki-ops"]
  ["5678", "7890", "6789"]
  ["1234", "3456", "2345"]
  ["1", "3", "2"]

-- | Parse a catalog document or fail the case.
parseUpgrade :: String -> IO Config
parseUpgrade body = case parseConfig body of
  Left err -> assertFailure ("catalog must parse: " ++ show err)
  Right cfg -> pure cfg

-- | Desired tokens from a config, in slot order.
desiredUpgrade :: Config -> [DesiredToken]
desiredUpgrade cfg =
  [ DesiredToken slot tid label
  | (slot, (tid, label)) <- Map.toAscList (identityCatalog cfg)
  ]

-- | Open the case identity with default limits and no faults.
openClean :: OpenWith -> IO Store
openClean open = open defaultLimits noFaults >>= expectRight "open"

-- | Load every token with its objects or fail the case.
loadedOf :: Store -> IO [(TokenRecord, [ObjectRecord])]
loadedOf s = storeLoadTokens s >>= expectRight "load tokens"

-- | Exact stored bytes: table, key, and full document per row.
bytesOf :: Store -> IO [(String, String, String)]
bytesOf s = do
  docs <- expectInspect s
  pure [(docTable d, docKey d, docJson d) | d <- docs]

-- | Seed a legacy positional store: identities positional,
-- generation one, each token owning one object.
seedIdentityThree :: Store -> IO [TokenRecord]
seedIdentityThree store = do
  let toks =
        [ (demoToken (TokenId 1)) { trSlot = SlotId 0, trLabel = "haskoki-demo" }
        , (demoToken (TokenId 2)) { trSlot = SlotId 1, trLabel = "haskoki-ops" }
        , (demoToken (TokenId 3)) { trSlot = SlotId 2, trLabel = "haskoki-audit" }
        ]
      objs =
        [ demoObject (TokenId 1) (ObjectId 1)
        , demoObject (TokenId 2) (ObjectId 2)
        , demoObject (TokenId 3) (ObjectId 3)
        ]
  result <- storeCommit store emptyDelta
    { sdPutTokens = toks
    , sdPutObjects = [ObjectPut Nothing o | o <- objs]
    }
  assertEqual "upg seed commit" Committed result
  pure toks

-- | A legacy positional store (seeded the way older releases
-- wrote: positional identities, no pinned catalog) closes and
-- reopens byte-identical under both the matching legacy
-- catalog and the matching pinned catalog. The steady
-- reconcile plans nothing: reopening never mutates an old
-- store.
testLegacyReopenStable :: OpenWith -> IO ()
testLegacyReopenStable open = do
  s1 <- openClean open
  _ <- seedIdentityThree s1
  bytesSeeded <- bytesOf s1
  storeClose s1
  s2 <- openClean open
  bytesReopened <- bytesOf s2
  assertEqual "close/reopen preserves legacy bytes exactly" bytesSeeded bytesReopened
  loaded <- loadedOf s2
  cfgLegacy <- parseUpgrade legacyThreeDoc
  case reconcileIdentities (desiredUpgrade cfgLegacy) [t | (t, _) <- loaded] of
    Left refusal ->
      assertFailure ("legacy steady state refused: " ++ renderIdentityRefusal refusal)
    Right plan -> assertEqual "legacy steady state plans nothing" [] (planSeeds plan)
  cfgPinned <- parseUpgrade pinnedThreeDoc
  case reconcileIdentities (desiredUpgrade cfgPinned) [t | (t, _) <- loaded] of
    Left refusal ->
      assertFailure ("pinned steady state refused: " ++ renderIdentityRefusal refusal)
    Right plan -> assertEqual "pinned steady state plans nothing" [] (planSeeds plan)
  bytesFinal <- bytesOf s2
  assertEqual "steady reconciles write nothing" bytesSeeded bytesFinal
  storeClose s2

-- | An interrupted move sequence (one leg committed, the rest
-- never issued) reopens refused under BOTH the old and the
-- target catalog: the mid-state matches neither endpoint, so
-- the operator completes the remaining legs explicitly and
-- only then reconciles clean.
testInterruptedMoveRefuses :: OpenWith -> IO ()
testInterruptedMoveRefuses open = do
  s1 <- openClean open
  _ <- seedIdentityThree s1
  loaded <- loadedOf s1
  move <- case planSlotMoves [(TokenId 2, SlotId 7)] [t | (t, _) <- loaded] of
    Left refusal -> assertFailure ("first leg must plan: " ++ show refusal)
    Right delta -> pure delta
  rMove <- storeCommit s1 move
  assertEqual "first leg commits" Committed rMove
  storeClose s1
  -- The crash window: reopen with only the first leg durable.
  s2 <- openClean open
  bytesMid <- bytesOf s2
  loadedMid <- loadedOf s2
  let storedMid = [t | (t, _) <- loadedMid]
  cfgOld <- parseUpgrade legacyThreeDoc
  case reconcileIdentities (desiredUpgrade cfgOld) storedMid of
    Left (RefuseSlotChanged tid _ _ _) ->
      assertEqual "old catalog sees drifted id 2" (TokenId 2) tid
    other -> assertFailure
      ("interrupted state must refuse the old catalog: " ++ show other)
  cfgTarget <- parseUpgrade swapThreeDoc
  case reconcileIdentities (desiredUpgrade cfgTarget) storedMid of
    Left (RefuseSlotChanged _ _ _ _) -> pure ()
    other -> assertFailure
      ("interrupted state must refuse the target catalog: " ++ show other)
  bytesRefused <- bytesOf s2
  assertEqual "refused reopens preserve the mid-state exactly" bytesMid bytesRefused
  -- Complete the reroute explicitly: audit to slot 1, ops home
  -- to slot 2.
  rest <- case planSlotMoves [(TokenId 3, SlotId 1), (TokenId 2, SlotId 2)] storedMid of
    Left refusal -> assertFailure ("remaining legs must plan: " ++ show refusal)
    Right delta -> pure delta
  rRest <- storeCommit s2 rest
  assertEqual "remaining legs commit" Committed rRest
  loadedDone <- loadedOf s2
  case reconcileIdentities (desiredUpgrade cfgTarget) [t | (t, _) <- loadedDone] of
    Left refusal ->
      assertFailure ("completed layout refused: " ++ renderIdentityRefusal refusal)
    Right plan -> assertEqual "completed layout is steady" [] (planSeeds plan)
  storeClose s2

-- | A positional downgrade (dropping @token_ids@) over a moved
-- store refuses: the legacy reading would seat the wrong
-- credential over moved objects, so the reconciler refuses
-- and the bytes survive exactly.
testDowngradeRefuses :: OpenWith -> IO ()
testDowngradeRefuses open = do
  s <- openClean open
  _ <- seedIdentityThree s
  loaded <- loadedOf s
  swap <- case planSlotMoves [(TokenId 2, SlotId 2), (TokenId 3, SlotId 1)] [t | (t, _) <- loaded] of
    Left refusal -> assertFailure ("swap must plan: " ++ show refusal)
    Right delta -> pure delta
  rSwap <- storeCommit s swap
  assertEqual "swap commits" Committed rSwap
  storeClose s
  s2 <- openClean open
  loadedMoved <- loadedOf s2
  bytesBefore <- bytesOf s2
  cfgLegacy <- parseUpgrade legacyThreeDoc
  case reconcileIdentities (desiredUpgrade cfgLegacy) [t | (t, _) <- loadedMoved] of
    Left (RefuseSlotChanged tid _ _ _) ->
      assertEqual "downgrade hits id 2" (TokenId 2) tid
    other -> assertFailure ("positional downgrade must refuse: " ++ show other)
  bytesAfter <- bytesOf s2
  assertEqual "refused downgrade preserves bytes exactly" bytesBefore bytesAfter
  storeClose s2

-- ---------------------------------------------------------------------------
-- SQLite transaction-body failure (AC-01)
-- ---------------------------------------------------------------------------

-- | SQLite-only: once one transaction-body statement fails, no
-- later delta group executes. Every case stimulates a real
-- statement failure on the store's OWN connection
-- ('SQLiteTestHooks'), inside the real commit transaction, and
-- records the native transaction state the failure left
-- ('getAutoCommit' at the failure: 'True' means SQLite already
-- rolled the whole transaction back, so any later statement would
-- run — and commit — on its own in autocommit mode).
--
-- * The injected @RAISE(ROLLBACK)@ case proves group SEQUENCING
--   only: it reaches SQLite's whole-transaction rollback branch
--   deterministically, but it is not a capacity failure.
-- * The @RAISE(ABORT)@ control fails one statement with the
--   transaction still active (the explicit-rollback branch).
-- * The genuine case caps @max_page_count@ on the store's
--   connection over the review's packed token layout (small
--   token rows, staged token upsert) within a bounded layout
--   search, and must reach SQLite's automatic-rollback branch
--   with a native @SQLITE_FULL@.
bodyFailureCases :: [TestTree]
bodyFailureCases =
  [ testCaseInfo "caseBodyFailureStopsFollowingGroups: injected RAISE(ROLLBACK) at the token upsert (sequencing only)"
      caseBodyFailureStopsFollowingGroups
  , testCaseInfo "statement ABORT with the transaction still active stops later groups"
      caseBodyAbortStopsFollowingGroups
  , testCaseInfo "genuine page-cap FULL on the packed token layout stops later groups"
      caseGenuineFullStopsFollowingGroups
  ]

-- | What the hooks observed on the store's own connection.
data BodyProbe = BodyProbe
  { bpWrites :: IORef [String]
    -- ^ row writes (@table:op@), most recent first
  , bpAutoCommit :: IORef (Maybe Bool)
    -- ^ native autocommit state right after the body failure
  , bpCommitAutoCommit :: IORef (Maybe Bool)
    -- ^ native autocommit state right after a failed COMMIT
  , bpVersion :: IORef String
    -- ^ the linked SQLite library version
  , bpTxn :: TxnSeam
    -- ^ every BEGIN/COMMIT/ROLLBACK prepared (and any denial)
  , bpCommit :: CommitSeam
    -- ^ commits reaching the commit point (and any forced failure)
  }

newBodyProbe :: IO BodyProbe
newBodyProbe = BodyProbe <$> newIORef [] <*> newIORef Nothing <*> newIORef Nothing
  <*> newIORef "unread" <*> newTxnSeam <*> newCommitSeam

-- | The transaction-control statements prepared so far, in order.
txnOps :: BodyProbe -> IO [Text]
txnOps probe = reverse <$> readIORef (tsLog (bpTxn probe))

-- | Hooks that record the linked version, install the write log
-- on the given tables plus the transaction-control and commit
-- seams, then apply the case's stimulus — all on the store's
-- connection, immediately before @BEGIN IMMEDIATE@ — and capture
-- the native autocommit state at the body or COMMIT failure,
-- before any cleanup.
probeHooks :: BodyProbe -> [Text] -> (S.Database -> IO ()) -> SQLiteTestHooks
probeHooks probe logged stimulus = SQLiteTestHooks
  { sthBeforeBegin = \db -> do
      writeIORef (bpVersion probe) =<< queryText db "SELECT sqlite_version()"
      installWriteLog (bpWrites probe) logged db
      installTxnSeam (bpTxn probe) db
      installCommitSeam (bpCommit probe) db
      stimulus db
      markCommits (bpCommit probe)
  , sthAfterBodyFailure = \db ->
      writeIORef (bpAutoCommit probe) . Just =<< getAutoCommit db
  , sthAfterCommitFailure = \db ->
      writeIORef (bpCommitAutoCommit probe) . Just =<< getAutoCommit db
  , sthAfterRollbackFailure = \_ -> pure ()
  }

-- | The injected RAISE(ROLLBACK) regression (sequencing only).
caseBodyFailureStopsFollowingGroups :: IO String
caseBodyFailureStopsFollowingGroups = injectedBodyFailure "ROLLBACK" True

-- | The still-active statement-ABORT control.
caseBodyAbortStopsFollowingGroups :: IO String
caseBodyAbortStopsFollowingGroups = injectedBodyFailure "ABORT" False

-- | Seed the mixed fixture (token, two objects, one queued job, a
-- provisioned credential, a probe meta row), then commit an
-- InitToken-shaped mixed delta whose token upsert (group 5)
-- fails through the injected trigger. Groups 1 and 2 (object and
-- job drops) run before it; groups 8, 9 and 10 (credential put
-- clearing the user PIN, meta put, deleted-job mark coverage)
-- must never run. Asserts the classification, the native branch,
-- every durable row after close, the exact statement-boundary
-- write log, the reopen state, and — as a control — that the
-- identical delta commits on an unhooked handle.
injectedBodyFailure :: Text -> Bool -> IO String
injectedBodyFailure kind expectAutoCommit =
  bracket (makeTempDir "haskoki-body-failure") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    MixedFixture tok delta docsBefore <- seedMixedFixture path []
    let tid = trId tok
    before <- dumpTables path
    probe <- newBodyProbe
    s <- openSQLiteStoreWithHooks path defaultLimits noFaults (probeHooks probe loggedTables (failTokenUpsert kind))
      >>= expectRight "open hooked"
    result <- storeCommit s delta
    case result of
      NotCommitted (StoreIO msg) | T.unpack injectedMarker `isInfixOf` msg -> pure ()
      other -> assertFailure ("expected the injected NotCommitted, got: " ++ show other)
    autoAt <- readIORef (bpAutoCommit probe)
    assertEqual "native autocommit at the failure (True = SQLite rolled back already)"
      (Just expectAutoCommit) autoAt
    stats <- storeStats s
    assertEqual "no commit counted" 0 (ssCommits stats)
    quarantined <- storeQuarantined s
    assertEqual "clean refusal quarantines nothing" [] quarantined
    docsSame <- expectInspect s
    storeClose s
    after <- dumpTables path
    assertTablesEqual before after
    assertEqual "same handle read the old state (no open transaction)" docsBefore docsSame
    writes <- reverse <$> readIORef (bpWrites probe)
    assertEqual "groups 1, 2 and token staging ran; nothing after the failed upsert"
      ["objects:delete", "detached_jobs:delete", "tokens:update"] writes
    -- The cleanup follows the native state: no ROLLBACK statement
    -- at all once SQLite has rolled back itself (one would only
    -- fail with "no transaction is active", now an unknown
    -- outcome), the explicit ROLLBACK while still active.
    ops <- txnOps probe
    assertEqual "transaction-control statements"
      (if expectAutoCommit then ["BEGIN"] else ["BEGIN", "ROLLBACK"]) ops
    -- Reopen: the old token, credential and meta survive, and the
    -- identical delta commits on an unhooked handle (the failure
    -- was the stimulus alone, and every later group's write is
    -- observable when it does land).
    sR <- openSQLiteStoreWith path defaultLimits noFaults >>= expectRight "reopen"
    assertEqual "reopen keeps the provisioned user PIN"
      [Just "user-pin-7"] =<< userPinsOf sR tid
    assertEqual "reopen keeps the old token" [tok] =<< tokensWithId sR tid
    assertEqual "reopen keeps the old meta" (Just "old") =<< metaOf sR "probe"
    assertEqual "reopen keeps the dropped job" [41] . map jrPersistentId
      =<< (storeLoadJobs sR >>= expectRight "reopen jobs")
    commitOk sR "control: the identical delta commits unhooked" delta
    assertEqual "control clears the user PIN" [Nothing] =<< userPinsOf sR tid
    assertEqual "control writes the meta" (Just "new") =<< metaOf sR "probe"
    storeClose sR
    version <- readIORef (bpVersion probe)
    pure ("SQLite " ++ version ++ "; injected RAISE(" ++ T.unpack kind
      ++ "); autocommit at failure " ++ show autoAt ++ "; writes " ++ show writes
      ++ "; transaction statements " ++ show ops)

-- | The seeded mixed fixture: the target token, the
-- InitToken-shaped delta over it, and the store's inspected
-- documents after seeding.
data MixedFixture = MixedFixture TokenRecord StoreDelta [StoredDoc]

-- | Seed the mixed fixture on a closed store file (token, two
-- objects, queued job 41, a provisioned credential, a probe meta
-- row, plus any bystander tokens) and build the InitToken-shaped
-- delta: object drop (g1), job drop (g2), relabel plus generation
-- bump (g5), credential clearing the user PIN (g8), meta put (g9)
-- and the deleted-job mark coverage (g10).
seedMixedFixture :: FilePath -> [TokenRecord] -> IO MixedFixture
seedMixedFixture path bystanders = do
  s0 <- openSQLiteStoreWith path defaultLimits noFaults >>= expectRight "open seed"
  (tok, objs) <- seedStore s0
  let tid = trId tok
  dropped <- case objs of
    o : _ -> pure (orId o)
    [] -> assertFailure "seed has no objects"
  commitOk s0 "seed job" emptyDelta { sdPutJobs = [demoJobPending 41 tid (trGeneration tok)] }
  commitOk s0 "seed credential" emptyDelta { sdPutCredentials = [mixedCredential tid (Just "user-pin-7")] }
  commitOk s0 "seed meta" emptyDelta { sdPutMeta = [("probe", "old")] }
  mapM_ (\b -> commitOk s0 "seed bystander" emptyDelta { sdPutTokens = [b] }) bystanders
  docs <- expectInspect s0
  storeClose s0
  pure (MixedFixture tok emptyDelta
    { sdDropObjects = [dropped]
    , sdDropJobs = [41]
    , sdPutTokens = [tok { trLabel = "relabelled-token", trGeneration = Generation 2 }]
    , sdPutCredentials = [mixedCredential tid Nothing]
    , sdPutMeta = [("probe", "new")]
    } docs)

-- | Reopen the closed file unhooked and require the fixture's
-- old state: provisioned user PIN, old token, old meta, job 41.
assertMixedOld :: FilePath -> TokenRecord -> IO ()
assertMixedOld path tok = do
  let tid = trId tok
  sR <- openSQLiteStoreWith path defaultLimits noFaults >>= expectRight "reopen"
  assertEqual "reopen keeps the provisioned user PIN"
    [Just "user-pin-7"] =<< userPinsOf sR tid
  assertEqual "reopen keeps the old token" [tok] =<< tokensWithId sR tid
  assertEqual "reopen keeps the old meta" (Just "old") =<< metaOf sR "probe"
  assertEqual "reopen keeps the dropped job" [41] . map jrPersistentId
    =<< (storeLoadJobs sR >>= expectRight "reopen jobs")
  storeClose sR

-- | The fixture credential: a fixed SO PIN and the given user PIN.
mixedCredential :: TokenId -> Maybe ByteString -> CredentialRecord
mixedCredential tid = CredentialRecord tid "so-pin-7"

-- | Commit and require 'Committed'.
commitOk :: Store -> String -> StoreDelta -> IO ()
commitOk s ctx delta = assertEqual ctx Committed =<< storeCommit s delta

-- | The stored user PINs of one token's credential rows.
userPinsOf :: Store -> TokenId -> IO [Maybe ByteString]
userPinsOf s tid = do
  creds <- storeLoadCredentials s >>= expectRight "load credentials"
  pure [crUserPin c | c <- creds, crToken c == tid]

-- | The stored token records with one id.
tokensWithId :: Store -> TokenId -> IO [TokenRecord]
tokensWithId s tid = do
  loaded <- storeLoadTokens s >>= expectRight "load tokens"
  pure [t | (t, _) <- loaded, trId t == tid]

-- | One stored meta value.
metaOf :: Store -> String -> IO (Maybe String)
metaOf s key = lookup key <$> (storeLoadMeta s >>= expectRight "load meta")

-- | Which native branch a page-capped commit reached.
data FullBranch
  = FullRoom
    -- ^ the delta fit the existing pages and committed
  | FullStillActive
    -- ^ @SQLITE_FULL@ with the transaction still active
  | FullAutoRolledBack
    -- ^ @SQLITE_FULL@ after SQLite rolled the transaction back
  | FullAtCommit
    -- ^ @SQLITE_FULL@ from the COMMIT itself (the body completed)
  deriving (Eq, Show)

-- | The bounded packed-layout search: the review's layout first
-- (14 token rows, 13-byte filler labels), then nearby row counts
-- and filler lengths. 3 x 13 = 39 layouts at most.
packedLayouts :: [(Int, Int)]
packedLayouts = [(c, f) | f <- [13, 9, 17], c <- 14 : [c' | c' <- [8 .. 20], c' /= 14]]

-- | The genuine-FULL regression: walk 'packedLayouts' until one
-- reaches SQLite's automatic-rollback branch with a native
-- @SQLITE_FULL@ (every FULL on the way — either branch — must
-- already satisfy the same invariants). Reaching no
-- automatic-rollback layout within the bound fails, recording
-- every branch reached.
caseGenuineFullStopsFollowingGroups :: IO String
caseGenuineFullStopsFollowingGroups = go [] packedLayouts
  where
    go seen [] = assertFailure
      ("no bounded packed layout reached SQLite's automatic rollback; reached: "
        ++ show (reverse seen))
    go seen (layout : rest) = do
      (branch, record) <- runPackedLayout layout
      case branch of
        FullAutoRolledBack -> pure (record ++ "; layouts tried before: " ++ show (reverse seen))
        _ -> go ((layout, branch) : seen) rest

-- | One packed layout: @count@ small token rows on slots
-- @0 .. count-1@ (slot 0 @haskoki-demo@, the target on slot 1
-- labelled @target@, the rest distinct filler labels), the
-- target's provisioned credential and a meta row. A hooked
-- handle caps @max_page_count@ at the current page count on its
-- own connection, then commits the InitToken-shaped delta: a
-- relabelled (32-byte label), generation-bumped target (token
-- staging then upsert), its credential with the user PIN
-- cleared, and a meta put.
runPackedLayout :: (Int, Int) -> IO (FullBranch, String)
runPackedLayout (count, filler) =
  bracket (makeTempDir "haskoki-genuine-full") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
        tokens = [packedToken n | n <- [0 .. count - 1]]
        packedToken n = TokenRecord
          { trId = TokenId (fromIntegral n + 1)
          , trSlot = SlotId n
          , trGeneration = Generation 1
          , trLabel = packedLabel n
          , trAuth = tokenAuthNew
          }
        packedLabel n
          | n == 0 = "haskoki-demo"
          | n == 1 = "target"
          | otherwise = take filler (show n ++ "-" ++ replicate filler 'a')
        target = packedToken 1
        tid = trId target
        cred = CredentialRecord tid "5678"
        delta = emptyDelta
          { sdPutTokens = [target { trLabel = replicate 32 'B', trGeneration = Generation 2 }]
          , sdPutCredentials = [cred Nothing]
          , sdPutMeta = [("probe", "2")]
          }
    s0 <- openSQLiteStoreWith path defaultLimits noFaults >>= expectRight "open packed"
    commitOk s0 "seed packed layout" emptyDelta
      { sdPutTokens = tokens
      , sdPutCredentials = [cred (Just "1234")]
      , sdPutMeta = [("probe", "1")]
      }
    docsBefore <- expectInspect s0
    storeClose s0
    before <- dumpTables path
    probe <- newBodyProbe
    pagesRef <- newIORef 0
    let capPages db = do
          pages <- queryInt db "PRAGMA main.page_count"
          writeIORef pagesRef pages
          S.exec db (T.pack ("PRAGMA main.max_page_count = " ++ show pages))
    s <- openSQLiteStoreWithHooks path defaultLimits noFaults (probeHooks probe laterTables capPages)
      >>= expectRight "open capped"
    result <- storeCommit s delta
    autoAt <- readIORef (bpAutoCommit probe)
    commitAutoAt <- readIORef (bpCommitAutoCommit probe)
    writes <- reverse <$> readIORef (bpWrites probe)
    pages <- readIORef pagesRef
    version <- readIORef (bpVersion probe)
    let record branch = "SQLite " ++ version ++ "; layout " ++ show count ++ " tokens, filler "
          ++ show filler ++ "; page cap " ++ show pages ++ "; " ++ show branch
          ++ "; result " ++ show result ++ "; writes " ++ show writes
    case result of
      Committed -> do
        storeClose s
        pure (FullRoom, record FullRoom)
      _ | Just _ <- commitAutoAt -> do
        -- FULL from the COMMIT itself: its own branch, recorded
        -- and searched past (the body-failure invariants do not
        -- apply); the classification must still follow the
        -- native state — never a clean refusal with the
        -- transaction gone, never an unquarantined unknown.
        quarantined <- storeQuarantined s
        stats <- storeStats s
        ops <- txnOps probe
        storeClose s
        assertEqual "no commit counted" 0 (ssCommits stats)
        case (result, commitAutoAt) of
          (NotCommitted (StoreFull _), Just False) -> do
            assertEqual "transaction-control statements" ["BEGIN", "COMMIT", "ROLLBACK"] ops
            after <- dumpTables path
            assertTablesEqual before after
          (CommitUnknown _, Just True) -> do
            assertEqual "transaction-control statements" ["BEGIN", "COMMIT"] ops
            assertEqual "unknown COMMIT outcome quarantines the target" [tid] (map fst quarantined)
          _ -> assertFailure ("COMMIT-time FULL misclassified: " ++ record FullAtCommit)
        pure (FullAtCommit, record FullAtCommit)
      NotCommitted (StoreFull _) -> do
        branch <- case autoAt of
          Just True -> pure FullAutoRolledBack
          Just False -> pure FullStillActive
          Nothing -> assertFailure ("FULL with neither failure hook fired: " ++ record FullRoom)
        quarantined <- storeQuarantined s
        stats <- storeStats s
        assertEqual "no commit counted" 0 (ssCommits stats)
        docsSame <- expectInspect s
        storeClose s
        after <- dumpTables path
        assertTablesEqual before after
        assertEqual ("no later group wrote: " ++ record branch) [] writes
        assertEqual "clean refusal quarantines nothing" [] quarantined
        assertEqual "same handle read the old state (no open transaction)" docsBefore docsSame
        ops <- txnOps probe
        assertEqual "transaction-control statements"
          (if branch == FullAutoRolledBack then ["BEGIN"] else ["BEGIN", "ROLLBACK"]) ops
        sR <- openSQLiteStoreWith path defaultLimits noFaults >>= expectRight "reopen packed"
        assertEqual "reopen keeps the provisioned user PIN" [Just "1234"] =<< userPinsOf sR tid
        assertEqual "reopen keeps the old target token" [target] =<< tokensWithId sR tid
        commitOk sR "control: the identical delta commits uncapped" delta
        assertEqual "control clears the user PIN" [Nothing] =<< userPinsOf sR tid
        storeClose sR
        pure (branch, record branch)
      other -> assertFailure ("expected Committed or StoreFull under the page cap, got: " ++ show other)

-- ---------------------------------------------------------------------------
-- SQLite COMMIT and cleanup failure (AC-01, issue #18)
-- ---------------------------------------------------------------------------

-- | SQLite-only: a failed COMMIT or a failed cleanup is classified
-- from the native transaction state alone, never by replaying
-- anything.
--
-- * Genuine: a second connection holds a SHARED lock, so the real
--   COMMIT returns @SQLITE_BUSY@ after the store's own 5s busy
--   timeout with the transaction still active; the ROLLBACK
--   succeeds and the result is an exact 'NotCommitted' with the
--   whole old state.
-- * Injected (commit hook): COMMIT fails after SQLite has ended
--   the transaction, so the outcome cannot be established:
--   'CommitUnknown', the affected token stays quarantined until an
--   authoritative reload, and the COMMIT is never reissued.
-- * Injected (authorizer denial): the ROLLBACK — after a
--   still-active body ABORT, or after a denied COMMIT — never
--   runs, so a write transaction stays open on the connection:
--   'CommitUnknown' and the WHOLE connection quarantines (loads,
--   commits and reservations refuse) until a reload that does
--   roll back, or a close (which rolls back natively).
-- * The same for a job-id reservation.
-- * Ambiguous verification (post-success flag; classification
--   only, not COMMIT-error evidence): a reload matching neither
--   the delta nor a proven pre-state is unknown, never "absent".
commitFailureCases :: [TestTree]
commitFailureCases =
  [ testCaseInfo "caseCommitBusyRollsBackWholeDelta: genuine SQLITE_BUSY at COMMIT under a held read lock"
      caseCommitBusyRollsBackWholeDelta
  , testCaseInfo "injected commit-hook COMMIT failure after the transaction ended is unknown and quarantined"
      caseCommitOutcomeUnknownQuarantines
  , testCaseInfo "injected ROLLBACK denial after a still-active body ABORT quarantines the connection until close"
      (caseCleanupFailureQuarantinesConnection False)
  , testCaseInfo "injected COMMIT and ROLLBACK denial quarantines the connection until a rolling-back reload"
      (caseCleanupFailureQuarantinesConnection True)
  , testCaseInfo "injected failed ROLLBACK that ends the transaction is unknown with per-token quarantine"
      caseRollbackErrorEndsTxnQuarantinesTokens
  , testCaseInfo "injected reservation COMMIT and ROLLBACK denial quarantines the connection"
      caseReserveCleanupFailureQuarantines
  , testCase "ambiguous verification: a partial reload is unknown, never absent (post-success flag; classification only)"
      casePartialReloadIsUnknown
  ]

-- | Every row write of the fixture delta's whole body, in order:
-- the body completed before the COMMIT step.
fullBodyWrites :: [String]
fullBodyWrites =
  [ "objects:delete", "detached_jobs:delete", "tokens:update", "tokens:update"
  , "credentials:insert", "store_meta:insert", "store_meta:insert"
  ]

-- | The genuine COMMIT-BUSY regression: the whole InitToken-shaped
-- body runs, the COMMIT waits out the busy timeout against the
-- reader's SHARED lock and fails with the transaction still
-- active, and the explicit ROLLBACK restores the whole old state:
-- an exact 'NotCommitted', nothing quarantined, the same handle
-- reads the old state (no open transaction), every table is
-- byte-identical after close, and the reopened store holds the
-- old token, credential, meta and job.
caseCommitBusyRollsBackWholeDelta :: IO String
caseCommitBusyRollsBackWholeDelta =
  bracket (makeTempDir "haskoki-commit-busy") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    MixedFixture tok delta docsBefore <- seedMixedFixture path []
    before <- dumpTables path
    probe <- newBodyProbe
    s <- openSQLiteStoreWithHooks path defaultLimits noFaults (probeHooks probe loggedTables (\_ -> pure ()))
      >>= expectRight "open hooked"
    t0 <- getMonotonicTime
    mResult <- timeout (30 * 1000000) (withSharedReadLock path (storeCommit s delta))
    t1 <- getMonotonicTime
    result <- maybe (assertFailure "the contended COMMIT did not return within 30s") pure mResult
    case result of
      NotCommitted (StoreIO msg) | "ErrorBusy" `isInfixOf` msg, "COMMIT" `isInfixOf` msg -> pure ()
      other -> assertFailure ("expected NotCommitted from the busy COMMIT, got: " ++ show other)
    assertEqual "the body completed (no body failure)" Nothing =<< readIORef (bpAutoCommit probe)
    commitAuto <- readIORef (bpCommitAutoCommit probe)
    assertEqual "COMMIT failed with the transaction still active" (Just False) commitAuto
    assertBool ("the COMMIT waited out the store's 5s busy timeout, took " ++ show (t1 - t0) ++ "s")
      (t1 - t0 >= 4.5)
    writes <- reverse <$> readIORef (bpWrites probe)
    assertEqual "the whole body ran once" fullBodyWrites writes
    ops <- txnOps probe
    assertEqual "BEGIN, the busy COMMIT, then the explicit ROLLBACK" ["BEGIN", "COMMIT", "ROLLBACK"] ops
    calls <- commitsSinceMark (bpCommit probe)
    assertEqual "the busy COMMIT never reached the commit point" 0 calls
    stats <- storeStats s
    assertEqual "no commit counted" 0 (ssCommits stats)
    assertEqual "a proven rollback quarantines nothing" [] =<< storeQuarantined s
    docsSame <- expectInspect s
    assertEqual "same handle reads the old state (no open transaction)" docsBefore docsSame
    storeClose s
    after <- dumpTables path
    assertTablesEqual before after
    assertMixedOld path tok
    sR <- openSQLiteStoreWith path defaultLimits noFaults >>= expectRight "reopen control"
    commitOk sR "control: the identical delta commits uncontended" delta
    storeClose sR
    version <- readIORef (bpVersion probe)
    pure ("SQLite " ++ version ++ "; genuine SQLITE_BUSY at COMMIT after " ++ show (t1 - t0)
      ++ "s; autocommit at COMMIT failure " ++ show commitAuto ++ "; result " ++ show result
      ++ "; transaction statements " ++ show ops)

-- | The injected unknown-COMMIT case: the commit hook turns the
-- COMMIT into a rollback, so COMMIT reports an error with the
-- connection already back in autocommit — the native facts of a
-- commit that may or may not have landed. The store must report
-- 'CommitUnknown', run no ROLLBACK and no second COMMIT, and keep
-- the affected token quarantined (commits touching it refuse)
-- until an authoritative reload resolves it.
caseCommitOutcomeUnknownQuarantines :: IO String
caseCommitOutcomeUnknownQuarantines =
  bracket (makeTempDir "haskoki-commit-unknown") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    MixedFixture tok delta docsBefore <- seedMixedFixture path []
    let tid = trId tok
    before <- dumpTables path
    probe <- newBodyProbe
    let failCommit _ = writeIORef (csFailNext (bpCommit probe)) True
    s <- openSQLiteStoreWithHooks path defaultLimits noFaults (probeHooks probe loggedTables failCommit)
      >>= expectRight "open hooked"
    result <- storeCommit s delta
    case result of
      CommitUnknown (StoreIO msg) | "COMMIT" `isInfixOf` msg -> pure ()
      other -> assertFailure ("expected CommitUnknown from the failed COMMIT, got: " ++ show other)
    assertEqual "unknown reloads first" ReloadFirst (decidePublication result)
    commitAuto <- readIORef (bpCommitAutoCommit probe)
    assertEqual "the failed COMMIT ended the transaction" (Just True) commitAuto
    ops <- txnOps probe
    assertEqual "no ROLLBACK and no second COMMIT" ["BEGIN", "COMMIT"] ops
    assertEqual "the COMMIT reached the commit point exactly once" 1
      =<< commitsSinceMark (bpCommit probe)
    writes <- reverse <$> readIORef (bpWrites probe)
    assertEqual "the whole body ran once" fullBodyWrites writes
    stats <- storeStats s
    assertEqual "no commit counted" 0 (ssCommits stats)
    assertEqual "one quarantine event" 1 (ssQuarantines stats)
    assertEqual "the affected token is quarantined" [tid] . map fst =<< storeQuarantined s
    refused <- storeCommit s delta
    case refused of
      NotCommitted (StoreQuarantined t _) -> assertEqual "quarantined token" tid t
      other -> assertFailure ("expected a quarantine refusal, got: " ++ show other)
    assertEqual "the refusal ran no transaction" ["BEGIN", "COMMIT"] =<< txnOps probe
    -- Resolution: the connection is clean (autocommit), so an
    -- authoritative reload reads the true durable state — here the
    -- old one, since the hook rolled the commit back.
    _ <- storeReload s >>= expectRight "reload"
    assertEqual "reload resolves the quarantine" [] =<< storeQuarantined s
    assertEqual "durable state is the old one" docsBefore =<< expectInspect s
    storeClose s
    after <- dumpTables path
    assertTablesEqual before after
    assertMixedOld path tok
    pure ("injected commit hook; autocommit at COMMIT failure " ++ show commitAuto
      ++ "; result " ++ show result ++ "; transaction statements " ++ show ops)

-- | The injected cleanup-failure cases: the ROLLBACK is denied
-- (after a still-active body ABORT, or after a denied COMMIT), so
-- the write transaction stays open on the store's connection. The
-- store must report 'CommitUnknown' with the cleanup error,
-- quarantine every token (the bystander too) and refuse loads,
-- commits, reservations and a still-failing reload — anything
-- read or written there would see or commit the open
-- transaction. The body variant resolves by close (SQLite rolls
-- the open transaction back natively); the COMMIT variant lifts
-- the denial and resolves through a reload that rolls back.
caseCleanupFailureQuarantinesConnection :: Bool -> IO String
caseCleanupFailureQuarantinesConnection atCommit =
  bracket (makeTempDir "haskoki-cleanup-failure") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
        bystander = TokenRecord
          { trId = TokenId 77
          , trSlot = SlotId 5
          , trGeneration = Generation 1
          , trLabel = "bystander"
          , trAuth = tokenAuthNew
          }
    MixedFixture tok delta docsBefore <- seedMixedFixture path [bystander]
    let tid = trId tok
    before <- dumpTables path
    probe <- newBodyProbe
    armed <- newIORef True
    let deny ops = writeIORef (tsDeny (bpTxn probe)) ops
        -- One shot: only the first commit on the handle is stimulated.
        stimulus db = do
          fire <- readIORef armed
          writeIORef armed False
          when fire $
            if atCommit
              then deny ["COMMIT", "ROLLBACK"]
              else failTokenUpsert "ABORT" db >> deny ["ROLLBACK"]
    s <- openSQLiteStoreWithHooks path defaultLimits noFaults (probeHooks probe loggedTables stimulus)
      >>= expectRight "open hooked"
    result <- storeCommit s delta
    case result of
      CommitUnknown (StoreIO msg) | "ROLLBACK" `isInfixOf` msg, "not authorized" `isInfixOf` msg -> pure ()
      other -> assertFailure ("expected CommitUnknown naming the failed ROLLBACK, got: " ++ show other)
    autoAt <- readIORef (if atCommit then bpCommitAutoCommit probe else bpAutoCommit probe)
    assertEqual "the transaction was still active at the failure" (Just False) autoAt
    ops <- txnOps probe
    assertEqual "transaction-control statements"
      (if atCommit then ["BEGIN", "COMMIT:denied", "ROLLBACK:denied"] else ["BEGIN", "ROLLBACK:denied"]) ops
    assertEqual "nothing reached the commit point" 0 =<< commitsSinceMark (bpCommit probe)
    stats <- storeStats s
    assertEqual "no commit counted" 0 (ssCommits stats)
    assertEqual "every token quarantined (connection scope)" (sort [tid, trId bystander])
      . sort . map fst =<< storeQuarantined s
    let connRefusal ctx e = case e of
          StoreIO m | "connection quarantined" `isInfixOf` m -> pure ()
          other -> assertFailure (ctx ++ ": expected the connection refusal, got: " ++ show other)
    storeLoadTokens s >>= either (connRefusal "load tokens") (\_ -> assertFailure "load served an open transaction")
    storeLoadCredentials s >>= either (connRefusal "load credentials") (\_ -> assertFailure "credential load served")
    storeInspect s >>= either (connRefusal "inspect") (\_ -> assertFailure "inspect served")
    bystanderCommit <- storeCommit s emptyDelta { sdPutTokens = [bystander { trLabel = "moved" }] }
    case bystanderCommit of
      NotCommitted e -> connRefusal "bystander commit" e
      other -> assertFailure ("bystander commit must refuse, got: " ++ show other)
    storeReserveJobId s >>= either (connRefusal "reserve") (\_ -> assertFailure "reservation served")
    assertEqual "refusals ran no transaction statement" ops =<< txnOps probe
    storeReload s >>= either (connRefusal "reload while the ROLLBACK is still denied")
      (\_ -> assertFailure "reload cleared a connection whose transaction is still open")
    assertEqual "the reload retried the ROLLBACK (still denied)" (ops ++ ["ROLLBACK:denied"]) =<< txnOps probe
    assertEqual "quarantine retained" 2 . length =<< storeQuarantined s
    if atCommit
      then do
        deny []
        _ <- storeReload s >>= expectRight "reload once the ROLLBACK can run"
        assertEqual "the reload rolled the open transaction back" (ops ++ ["ROLLBACK:denied", "ROLLBACK"]) =<< txnOps probe
        assertEqual "resolved: quarantine cleared" [] =<< storeQuarantined s
        assertEqual "durable state is the old one" docsBefore =<< expectInspect s
        commitOk s "the resolved connection commits" emptyDelta { sdPutMeta = [("probe", "old")] }
        storeClose s
      else storeClose s
    after <- dumpTables path
    assertTablesEqual before after
    assertMixedOld path tok
    pure ("injected " ++ (if atCommit then "COMMIT+ROLLBACK" else "body ABORT + ROLLBACK")
      ++ " denial; autocommit at failure " ++ show autoAt ++ "; result " ++ show result
      ++ "; transaction statements " ++ show ops)

-- | The reservation analogue: COMMIT and ROLLBACK denied leave
-- the mark-advance transaction open, so the reservation fails,
-- the connection quarantines (every token) and later reservations
-- refuse until a reload rolls back; the durable mark never moved,
-- and a fresh handle then reserves normally.
caseReserveCleanupFailureQuarantines :: IO String
caseReserveCleanupFailureQuarantines =
  bracket (makeTempDir "haskoki-reserve-cleanup") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    s0 <- openSQLiteStoreWith path defaultLimits noFaults >>= expectRight "open seed"
    (tok, _) <- seedStore s0
    markBefore <- metaOf s0 jobIdCounterKey
    storeClose s0
    probe <- newBodyProbe
    let deny ops = writeIORef (tsDeny (bpTxn probe)) ops
    s <- openSQLiteStoreWithHooks path defaultLimits noFaults
      (probeHooks probe laterTables (\_ -> deny ["COMMIT", "ROLLBACK"]))
      >>= expectRight "open hooked"
    failed <- storeReserveJobId s
    case failed of
      Left (StoreIO msg) | "ROLLBACK" `isInfixOf` msg -> pure ()
      other -> assertFailure ("expected the reservation to fail naming the ROLLBACK, got: " ++ show other)
    ops <- txnOps probe
    assertEqual "transaction-control statements" ["BEGIN", "COMMIT:denied", "ROLLBACK:denied"] ops
    assertEqual "every token quarantined" [trId tok] . map fst =<< storeQuarantined s
    storeReserveJobId s >>= either (\_ -> pure ()) (\pid -> assertFailure ("reserved " ++ show pid ++ " on an open transaction"))
    storeLoadMeta s >>= either (\_ -> pure ()) (\_ -> assertFailure "meta load served an open transaction")
    deny []
    _ <- storeReload s >>= expectRight "reload once the ROLLBACK can run"
    assertEqual "resolved: quarantine cleared" [] =<< storeQuarantined s
    assertEqual "the durable mark never moved" markBefore =<< metaOf s jobIdCounterKey
    storeClose s
    sC <- openSQLiteStoreWith path defaultLimits noFaults >>= expectRight "control"
    control <- storeReserveJobId sC >>= expectRight "control reserve"
    storeClose sC
    pure ("injected reservation COMMIT+ROLLBACK denial; " ++ show failed ++ "; transaction statements "
      ++ show ops ++ "; control reserves " ++ show control)

-- | Ambiguous-verification classification: the delta lands, then
-- (inside the post-success ambiguity flag, before the reload) a
-- plain second connection reverts only its meta row, so the
-- reload matches neither the delta nor the pre-state. That must
-- be 'CommitUnknown' with the token quarantined — never
-- 'NotCommitted' "delta absent". This proves the classification
-- only: a post-success flag is not COMMIT-error evidence.
casePartialReloadIsUnknown :: IO ()
casePartialReloadIsUnknown =
  bracket (makeTempDir "haskoki-partial-reload") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    s0 <- openSQLiteStoreWith path defaultLimits noFaults >>= expectRight "open seed"
    (tok, _) <- seedStore s0
    commitOk s0 "seed meta" emptyDelta { sdPutMeta = [("probe", "old")] }
    storeClose s0
    armed <- newIORef True
    let revertMetaOnly = bracket (S.open (T.pack path)) S.close $ \db ->
          S.exec db "UPDATE store_meta SET value = 'old' WHERE key = 'probe'"
        inj = noFaults
          { fiFire = \p -> case p of
              FaultAmbiguousCommit -> do
                fire <- readIORef armed
                writeIORef armed False
                if fire then revertMetaOnly >> pure True else pure False
              _ -> pure False
          }
        relabelled = tok { trLabel = "partially-landed" }
    s <- openSQLiteStoreWith path defaultLimits inj >>= expectRight "open"
    result <- storeCommit s emptyDelta { sdPutTokens = [relabelled], sdPutMeta = [("probe", "new")] }
    case result of
      CommitUnknown _ -> pure ()
      other -> assertFailure ("a partial reload must be unknown, got: " ++ show other)
    assertEqual "the token is quarantined" [trId tok] . map fst =<< storeQuarantined s
    stats <- storeStats s
    assertEqual "no commit counted" 0 (ssCommits stats)
    assertEqual "one verification reload" 1 (ssVerifyReloads stats)
    storeClose s
    sR <- openSQLiteStoreWith path defaultLimits noFaults >>= expectRight "reopen"
    assertEqual "the token half is durable" [relabelled] =<< tokensWithId sR (trId tok)
    assertEqual "the meta half is not" (Just "old") =<< metaOf sR "probe"
    storeClose sR

-- | The ROLLBACK-error-that-ends-the-transaction branch. SQLite
-- 3.45.0 offers no in-process primitive for it (a ROLLBACK that
-- fails while running still ends the transaction, but only an I\/O
-- fault makes it fail), so the seam composes the native facts:
-- after a still-active body ABORT the ROLLBACK is denied (it fails
-- at prepare and never runs), and the after-ROLLBACK-failure hook
-- then ends the transaction with its own real ROLLBACK on the same
-- connection before the store re-reads the native state. The
-- store sees a ROLLBACK error with the transaction over, so it
-- must report 'CommitUnknown' naming both errors and quarantine
-- only the affected token: the connection is clean, so loads
-- serve (the old state) and the bystander stays servable, while
-- commits touching the token refuse until a reload resolves.
caseRollbackErrorEndsTxnQuarantinesTokens :: IO String
caseRollbackErrorEndsTxnQuarantinesTokens =
  bracket (makeTempDir "haskoki-rollback-error-ended") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
        bystander = TokenRecord
          { trId = TokenId 77
          , trSlot = SlotId 5
          , trGeneration = Generation 1
          , trLabel = "bystander"
          , trAuth = tokenAuthNew
          }
    MixedFixture tok delta docsBefore <- seedMixedFixture path [bystander]
    let tid = trId tok
    before <- dumpTables path
    probe <- newBodyProbe
    armed <- newIORef True
    let deny ops = writeIORef (tsDeny (bpTxn probe)) ops
        stimulus db = do
          fire <- readIORef armed
          writeIORef armed False
          when fire (failTokenUpsert "ABORT" db >> deny ["ROLLBACK"])
        endTxn db = deny [] >> S.exec db "ROLLBACK"
        hooks = (probeHooks probe loggedTables stimulus) { sthAfterRollbackFailure = endTxn }
    s <- openSQLiteStoreWithHooks path defaultLimits noFaults hooks >>= expectRight "open hooked"
    result <- storeCommit s delta
    case result of
      CommitUnknown (StoreIO msg) | "ROLLBACK" `isInfixOf` msg, "not authorized" `isInfixOf` msg -> pure ()
      other -> assertFailure ("expected CommitUnknown naming the failed ROLLBACK, got: " ++ show other)
    assertEqual "the transaction was still active at the body failure" (Just False)
      =<< readIORef (bpAutoCommit probe)
    ops <- txnOps probe
    assertEqual "the denied ROLLBACK, then the seam's own ending ROLLBACK"
      ["BEGIN", "ROLLBACK:denied", "ROLLBACK"] ops
    stats <- storeStats s
    assertEqual "no commit counted" 0 (ssCommits stats)
    assertEqual "only the affected token is quarantined" [tid] . map fst =<< storeQuarantined s
    assertEqual "the clean connection serves the old state" docsBefore =<< expectInspect s
    refused <- storeCommit s delta
    case refused of
      NotCommitted (StoreQuarantined t _) -> assertEqual "quarantined token" tid t
      other -> assertFailure ("expected a quarantine refusal, got: " ++ show other)
    _ <- storeReload s >>= expectRight "reload"
    assertEqual "reload resolves the quarantine" [] =<< storeQuarantined s
    storeClose s
    after <- dumpTables path
    assertTablesEqual before after
    assertMixedOld path tok
    pure ("injected ROLLBACK denial + seam-ended transaction; result " ++ show result
      ++ "; transaction statements " ++ show ops)
