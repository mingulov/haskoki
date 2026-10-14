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
import Data.List (isInfixOf, sortOn)
import qualified Data.Map.Strict as Map
import System.Directory (removeDirectoryRecursive)
import System.FilePath ((</>))
import System.IO (hPutStrLn, stderr)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), SessionState, addToken, emptyModel, lookupObject)
import Haskoki.Object (planCreateObject)
import Haskoki.Outcome (DeltaOp (..), PlanResult (..), PreparedCommit (..), StateDelta (..))
import Data.Word (Word64)
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , CredentialRecord (..)
  , DesiredToken (..)
  , FaultInjector
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
import Haskoki.Runtime.Storage.SQLite (openSQLiteStoreWith)
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
    NotCommitted (StoreQuarantined _) -> pure ()
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
-- or model effect, and the store stays healthy afterwards. (A
-- real full disk surfaces through the same 'StoreFull'
-- classification; filling a disk portably is not testable.)
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
