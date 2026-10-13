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
import Data.List (sortOn)
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
import StoreSpec (demoJobPending, demoJobResult, expectInspect, expectJust, expectRight, makeTempDir, seedStore)

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
