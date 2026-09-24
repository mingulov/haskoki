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
* The commit-to-publication path is masked against ordinary async
  exceptions: a kill delivered mid-commit neither interrupts the
  durable commit nor strands the store unusable; it lands after.
-}
{-# LANGUAGE OverloadedStrings #-}
module CommitSpec (spec) where

import Control.Concurrent (forkIO, newEmptyMVar, putMVar, takeMVar, throwTo)
import Control.Exception (AsyncException (..))
import Control.Exception (bracket, finally)
import qualified Data.Map.Strict as Map
import System.Directory (removeDirectoryRecursive)
import System.FilePath ((</>))
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), SessionState, addToken, emptyModel, lookupObject)
import Haskoki.Object (planCreateObject)
import Haskoki.Outcome (DeltaOp (..), PlanResult (..), PreparedCommit (..), StateDelta (..))
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , FaultInjector
  , FaultPoint (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , PublicationAdvice (..)
  , Reconcile (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , StoreLimits (..)
  , StoreStats (..)
  , StoredDoc (..)
  , TokenRecord (..)
  , decidePublication
  , defaultLimits
  , emptyDelta
  , encodeObjectRecord
  , noFaults
  , objectToRecord
  , reconcileReload
  , reserveRestoredIds
  , scriptedFaults
  , withMaskHook
  , withResultHook
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStoreWith)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStoreWith)
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
import StoreSpec (demoJobPending, demoJobResult, expectJust, expectRight, makeTempDir, seedStore)

-- | Open a store on the case identity with the given limits and faults.
type OpenWith = StoreLimits -> FaultInjector -> IO (Either StoreError Store)

spec :: TestTree
spec = testGroup "commit protocol"
  [ testGroup "decisions"
      [ testCase "publication advice follows classification" testAdvice
      , testCase "reload reconciliation compares full records" testReconcile
      ]
  , testGroup "memory" (protocolCases withMemoryIdentity)
  , testGroup "sqlite" (protocolCases withSQLiteIdentity)
  , testGroup "limits-memory" (limitCases withMemoryIdentity)
  , testGroup "limits-sqlite" (limitCases withSQLiteIdentity)
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
  , testCase "commit is masked against async kill" $
      withIdentity testAsyncMasked
  , testCase "injected full disk is a clean error" $
      withIdentity testFullDisk
  , testCase "reset respects quarantine" $
      withIdentity testResetQuarantine
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

-- | A kill delivered inside the masked commit region neither
-- interrupts the durable commit nor strands the store: the commit
-- completes, the kill lands after, and the store stays usable.
--
-- Death is observed through a deterministic 'finally'
-- death-signal, never the old 'waitDeath' busy-spin (whose
-- microsecond-timeout of a pure action waited nothing). Every
-- assertion keeps its original intent.
testAsyncMasked :: OpenWith -> IO ()
testAsyncMasked openWith = do
  eClean <- openWith defaultLimits noFaults
  sClean <- either (assertFailure . show) pure eClean
  (tok, _) <- seedStore sClean
  storeClose sClean
  entered <- newEmptyMVar
  resultVar <- newEmptyMVar
  died <- newEmptyMVar
  inj0 <- scriptedFaults []
  let inj = withResultHook (putMVar resultVar) (withMaskHook (putMVar entered ()) inj0)
  eVictim <- openWith defaultLimits inj
  victim <- either (assertFailure . show) pure eVictim
  (mBefore, sdelta, _, oid) <- planObject victim (trId tok)
  _ <- pure mBefore
  tid <- forkIO (((storeCommit victim sdelta >> pure ()) `finally` putMVar died ()))
  mEntered <- timeout 5000000 (takeMVar entered)
  case mEntered of
    Nothing -> assertFailure "committer never entered the masked region"
    Just () -> pure ()
  throwTo tid ThreadKilled
  mResult <- timeout 5000000 (takeMVar resultVar)
  result <- maybe (assertFailure "kill interrupted the commit") pure mResult
  assertEqual "commit survived the kill" Committed result
  mDied <- timeout 5000000 (takeMVar died)
  case mDied of
    Nothing -> assertFailure "kill never landed after the commit (5s guard)"
    Just () -> pure ()
  -- The durable delta is whole and the store stays usable.
  eLoaded <- storeLoadTokens victim
  loaded <- either (assertFailure . show) pure eLoaded
  assertBool "committed object durable" (objectPresent oid loaded)
  stats <- storeStats victim
  assertEqual "one commit counted" 1 (ssCommits stats)
  eClean2 <- openWith defaultLimits noFaults
  case eClean2 of
    Right s2 -> storeClose s2 >> storeClose victim
    Left _ -> do
      -- Same-identity open still owned by victim: use victim.
      (mBefore2, sdelta2, _, _) <- planObjectOn (trId tok) mBefore
      _ <- pure mBefore2
      -- Victim's injector hooks are spent one-shot signals; a plain
      -- commit through it must still work (hooks are inert now).
      r2 <- timeout 5000000 (storeCommit victim sdelta2)
      case r2 of
        Just Committed -> storeClose victim
        other -> assertFailure ("store unusable after kill: " ++ show other)

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
  before <- storeInspect sClean
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
