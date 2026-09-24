{- | Ownership fault-injection probes (exception/ownership semantics).

Investigation FIRST: each probe demonstrates a failure mode with a
failing test at controlled barriers (MVar rendezvous + 'System.Timeout'
guards, never timing-hope). The bug pins stay as regression pins:
they must pass with the implementation, which IS the
implementation proof. Characterization pins (passing before and
after) guard the behavior the implementation preserves.

Probes:

* throwing runner (sync): a runner throw must terminalize the job —
  otherwise it strands 'JobRunning' (later polls see pending).
* killed runner (async): a kill at a barrier inside the runner must
  terminalize the job AND preserve cancellation ('ThreadKilled').
* sequential update\/release contract (synthetic backend): update ok,
  release, update gone. Already passing; the CONCURRENT borrow-vs-close
  window is not reproducible through the public API (no controllable
  barrier inside the window) and is recorded as an honest
  not-reproducible note here.
* interrupted delivery: a kill\/throw at the delivery write must not
  strand Delivered-without-bytes — the commit must follow the write.
* drain-before-write order: the commit drains releases before the
  delivery write (publish-then-drain order, preserved). Passing throughout.
* failing sink: a throwing delivery sink must leave the job
  recoverable (Ready) with the exception propagated — previously
  Delivered committed first, so the retry observed a phantom
  delivery.
-}
{-# LANGUAGE OverloadedStrings #-}
module OwnershipSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Concurrent
  ( MVar
  , forkIO
  , killThread
  , newEmptyMVar
  , newMVar
  , putMVar
  , takeMVar
  , tryTakeMVar
  )
import Control.Exception
  ( AsyncException (..)
  , SomeException
  , fromException
  , mask_
  , throwIO
  , try
  )
import Data.IORef (IORef, modifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import Data.Word (Word32, Word64)
import Foreign.Ptr (nullPtr)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import qualified Haskoki.Engine.Backend as B
import Haskoki.Engine.Driver (encodeResult, runEffect, toCryptoError)
import Haskoki.Engine.OpenSSL4
  ( lookupRegistry
  , takeRegistry
  , withBorrowedRegistry
  )
import Haskoki.Engine.Synthetic (Synthetic (..))
import Haskoki.Model (Model (..), SessionState (..), lookupSession)
import Haskoki.Operation.KeyManagement
  ( KeyPlan (..)
  , aesKeyGenMech
  , ckkAes
  , ckoSecretKey
  , encodeKeyPair
  , planGenerateKey
  )
import Haskoki.Operation (CryptoEffect (..), CryptoError (..), CryptoResult (..))
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Outcome
  ( DeltaOp (..)
  , EffectRequest (..)
  , EngineResult (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Reservation (..)
  , ResourceRelease (..)
  , RevisionDep (..)
  , StateDelta (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request
  ( FunctionId (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.Async
  ( AsyncTable
  , AsyncWork (..)
  , CancelOutcome (..)
  , CompleteOutcome (..)
  , Completion (..)
  , Delivery (..)
  , JobFunction (..)
  , JobRequest (..)
  , JobState (..)
  , JobView (..)
  , PollOutcome (..)
  , ReapEligibility (..)
  , ReapOutcome (..)
  , StartDeny (..)
  , TerminalState (..)
  , beginDetach
  , callCompletion
  , cancelJob
  , commitDetachRevoke
  , completeJob
  , enableAsyncSession
  , inspectJob
  , newAsyncTable
  , pollJob
  , reapEligibility
  , reapJob
  , startJob
  , tableStats
  )
import Haskoki.Runtime.Lifecycle
  ( Env
  , defaultInitArgs
  , initialize
  , newEnv
  , publish
  , seatToken
  , snapshotModel
  )
import Haskoki.Transition (finishEffect, planCall)
import Haskoki.Types
  ( EngineResourceId (..)
  , ExternalHandle (..)
  , ObjectId (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Ownership"
  [ testGroup "probes"
    [ testCase "throwing runner terminalizes the job"
        (guarded "throwing-runner" caseThrowingRunner)
    , testCase "killed runner terminalizes the job; cancellation preserved"
        (guarded "killed-runner" caseKilledRunner)
    , testCase "sequential update/release contract (synthetic)"
        (guarded "seq-update-release" caseSeqUpdateRelease)
    , testCase "interrupted delivery: terminal implies written"
        (guarded "interrupted-delivery" caseInterruptedDelivery)
    , testCase "commit drains before the delivery write"
        (guarded "drain-before-write" caseDrainBeforeWrite)
    , testCase "failing sink stays recoverable"
        (guarded "failing-sink" caseFailingSink)
    ]
  , testGroup "lease protocol"
    [ testCase "borrow holds the lock across use"
        (guarded "borrow-holds-lock" caseBorrowHoldsLock)
    , testCase "take waits for in-flight borrow"
        (guarded "take-waits" caseTakeWaitsForBorrow)
    , testCase "kill inside borrow restores the lock"
        (guarded "kill-in-borrow" caseKillInBorrowRestores)
    , testCase "snapshot lookup sees immutable values"
        (guarded "snapshot-lookup" caseSnapshotLookup)
    , testCase "kill during blocked sink stays recoverable"
        (guarded "kill-blocked-sink" caseKillDuringBlockedSink)
    ]
  , testGroup "publication contract"
    [ testCase "faulted publish drains releases, fails terminal, sink untouched"
        (guarded "faulted-publish-drains" caseFaultedPublishDrains)
    , testCase "keygen delivery failure retries with fresh handles"
        (guarded "keygen-delivery-retry" caseKeygenDeliveryRetry)
    ]
  , testGroup "typed driver"
    [ testCase "feed answer keeps unit shape"
        (guarded "feed-unit-shape" caseFeedUnitShape)
    , testCase "verify answer stays verdict-typed"
        (guarded "verify-verdict" caseVerifyVerdict)
    , testCase "driver error categories preserved"
        (guarded "driver-error-cats" caseDriverErrorCats)
    ]
  , testGroup "aux-output scope"
    [ testCase "call completion admits engine bytes and single bytes"
        (guarded "call-completion-in" caseCallCompletionIn)
    , testCase "call completion rejects multi and handle shapes"
        (guarded "call-completion-out" caseCallCompletionOut)
    ]
  , testGroup "retention scope"
    [ testCase "reap eligibility admits terminal only"
        (guarded "reap-eligibility" caseReapEligibilityMatrix)
    , testCase "tombstones accumulate until reaped; live cap unaffected"
        (guarded "tombstone-census" caseTombstoneCensus)
    , testCase "cancel after detach is unknown"
        (guarded "cancel-after-detach" caseCancelAfterDetach)
    ]
  ]

-- | No-wedge guard: every probe body runs under a 10s 'timeout'.
guarded :: String -> IO () -> IO ()
guarded name body = do
  r <- timeout 10000000 body
  case r of
    Nothing -> assertFailure ("wedged (>10s): " ++ name)
    Just () -> pure ()

sid1 :: SessionId
sid1 = SessionId 1

cannedSig :: ByteString
cannedSig = BS.replicate 64 0x51

signRequest :: SessionId -> Int -> JobRequest
signRequest sid ticks = JobRequest
  { jrSession = sid
  , jrFunction = JobSign
  , jrWork = WorkCall
      (Reservation "async-sign-test" [] Nothing Nothing)
      (EffectCrypto (FxSign (MechanismId 0x251) Nothing BS.empty "hello"))
  , jrTicks = ticks
  , jrCapacity = 64
  }

mkTable :: IO (AsyncTable, Env)
mkTable = do
  table <- newAsyncTable 8
  env <- newEnv defaultRules
  enableAsyncSession table sid1
  pure (table, env)

newCapture :: IO (IORef [ByteString], IORef [Word64])
newCapture = (,) <$> newIORef [] <*> newIORef []

captureDelivery :: Word64 -> IORef [ByteString] -> IORef [Word64] -> Delivery
captureDelivery cap writes needed = Delivery
  { dCapacity = cap
  , dWrite = \bs -> modifyIORef' writes (++ [bs])
  , dReportNeeded = \n -> modifyIORef' needed (++ [n])
  }

countingRunner :: IORef Int -> CryptoEffect -> IO CryptoResult
countingRunner ref _fx = do
  modifyIORef' ref (+ 1)
  pure (GotBytes cannedSig)

isTerminalPoll :: PollOutcome -> Bool
isTerminalPoll (PollTerminal _) = True
isTerminalPoll _ = False

-- | Sync half: a throwing runner must terminalize the job.
-- Previously the claim committed, the throw skipped the hold, and
-- the job stranded 'JobRunning' (re-poll observed 'PollPending 0').
caseThrowingRunner :: IO ()
caseThrowingRunner = do
  (table, env) <- mkTable
  runs <- newIORef 0
  Right j0 <- startJob table (signRequest sid1 1)
  let boom _ = throwIO (userError "runner boom")
  _ <- try (pollJob boom env table JobSign j0)
    :: IO (Either SomeException PollOutcome)
  p2 <- pollJob (countingRunner runs) env table JobSign j0
  assertBool ("runner throw must terminalize the job, re-poll saw "
    ++ show p2) (isTerminalPoll p2)
  stFinal <- inspectJob table j0
  assertEqual "epoch: claim kept, fail bumped" (Just 1) (fmap jvEpoch stFinal)

-- | Async half: a kill at a barrier inside the runner must
-- terminalize the job, and the victim must still die 'ThreadKilled'
-- (cancellation preserved after cleanup).
caseKilledRunner :: IO ()
caseKilledRunner = do
  (table, env) <- mkTable
  runs <- newIORef 0
  Right j0 <- startJob table (signRequest sid1 1)
  entered <- newEmptyMVar
  release <- newEmptyMVar
  let gated _ = do
        putMVar entered ()
        _ <- takeMVar release
        pure (GotBytes cannedSig)
  done <- newEmptyMVar
  tid <- forkIO (try (pollJob gated env table JobSign j0) >>= putMVar done)
  takeMVar entered
  killThread tid
  -- The victim must die WITHOUT the barrier release: it was parked
  -- at a controlled rendezvous, so the kill lands deterministically.
  r <- takeMVar done :: IO (Either SomeException PollOutcome)
  case r of
    Left e -> case fromException e of
      Just ThreadKilled -> pure ()
      _ -> assertFailure ("expected ThreadKilled, got " ++ show e)
    Right oc -> assertFailure ("expected kill, poll returned " ++ show oc)
  p2 <- pollJob (countingRunner runs) env table JobSign j0
  assertBool ("killed runner must terminalize the job, re-poll saw "
    ++ show p2) (isTerminalPoll p2)

-- | Sequential characterization (synthetic backend, passing
-- throughout): update succeeds while registered, release drops the entry,
-- update-after-release answers ResourceGone. The CONCURRENT
-- borrow-vs-close window has no controllable barrier through the
-- public API and is recorded not-reproducible here; the borrowing
-- lease closes it structurally.
caseSeqUpdateRelease :: IO ()
caseSeqUpdateRelease = do
  eEnv <- B.openBackend "0" :: IO (B.EngineResult (B.BackendEnv Synthetic))
  be <- case eEnv of
    B.EngineOk env -> pure env
    B.EngineFail err -> assertFailure ("synthetic open failed: " ++ show err)
  eRid <- B.digestInit be B.D_SHA256
  rid <- case eRid of
    B.EngineOk r -> pure r
    B.EngineFail err -> assertFailure ("synthetic init failed: " ++ show err)
  u1 <- B.digestUpdate be rid "hello"
  case u1 of
    B.EngineOk () -> pure ()
    B.EngineFail err -> assertFailure ("update failed: " ++ show err)
  B.releaseResource be rid
  u2 <- B.digestUpdate be rid "hello"
  case u2 of
    B.EngineFail (B.BackendResourceGone _ _) -> pure ()
    other -> assertFailure ("expected ResourceGone, got " ++ show other)

-- | Interruption AT the delivery write. The sink throws
-- 'ThreadKilled' synchronously to itself — the exact program point
-- where an async kill would land, fully deterministic, no threads.
-- Previously Delivered committed BEFORE writing, so the job
-- stranded Delivered-without-bytes; the implementation writes
-- before committing (masked tail), so the throw leaves Ready and
-- the retry delivers once.
caseInterruptedDelivery :: IO ()
caseInterruptedDelivery = do
  (table, env) <- mkTable
  runs <- newIORef 0
  Right j0 <- startJob table (signRequest sid1 1)
  p <- pollJob (countingRunner runs) env table JobSign j0
  assertEqual "drive ready" PollReady p
  writes <- newIORef ([] :: [ByteString])
  _needed <- newIORef ([] :: [Word64])
  let killer = Delivery
        { dCapacity = 64
        , dWrite = \_ -> throwIO ThreadKilled
        , dReportNeeded = \_ -> pure ()
        }
  r <- try (completeJob env table JobSign j0 killer (\_ -> pure ()))
    :: IO (Either SomeException CompleteOutcome)
  case r of
    Left e -> case fromException e of
      Just ThreadKilled -> pure ()
      _ -> assertFailure ("expected ThreadKilled, got " ++ show e)
    Right oc -> assertFailure ("expected throw, complete returned " ++ show oc)
  (writes2, needed2) <- newCapture
  let roomy = captureDelivery 64 writes2 needed2
  c2 <- completeJob env table JobSign j0 roomy (\_ -> pure ())
  got1 <- readIORef writes
  got2 <- readIORef writes2
  case c2 of
    CompleteDelivered (CompBytes bs) -> do
      assertEqual "retry delivers the held bytes" cannedSig bs
      assertEqual "killer wrote nothing" [] got1
      assertEqual "exactly one delivery write" 1 (length got2)
    other -> assertFailure ("retry must deliver after an interrupted write, got "
      ++ show other ++ " (killer writes: " ++ show (length got1) ++ ")")

-- | Order characterization (passing throughout): on a completion
-- carrying a release, the drain runs BEFORE the delivery write
-- (publish-then-drain order the implementation preserves across its
-- commit/write reorder). No drain-before-publish path exists —
-- the review-rev ordering difference is already reconciled
-- (see the Publication/Delivery contract in 'Haskoki.Runtime.Async').
caseDrainBeforeWrite :: IO ()
caseDrainBeforeWrite = do
  (env, _, st) <- openEnvSession
  let sid = ssId st
      rid = EngineResourceId 21
      digest = BS.replicate 32 0xAB
  m2 <- snapshotModel env
  let initReq = Request Pkcs11_3_2 F_DigestInit (Just sid) Nothing
        (encodeInitInput sha256Mech [] False BS.empty) []
  case planCall defaultRules m2 initReq of
    Execute resI (EffectCrypto _) -> do
      m3 <- snapshotModel env
      case finishEffect defaultRules m3 resI (EngineOkResource rid) of
        Left rej -> assertFailure ("init finish rejected: " ++ show rej)
        Right pc -> do
          pr <- publish env (pcDelta pc)
          case pr of
            Right () -> pure ()
            Left f -> assertFailure ("init publish failed: " ++ show f)
    other -> assertFailure ("init did not plan execute: " ++ show other)
  table <- newAsyncTable 8
  enableAsyncSession table sid
  m4 <- snapshotModel env
  let finReq = Request Pkcs11_3_2 F_DigestFinal (Just sid) Nothing BS.empty
        [RegionBytes "digest" (IntentBuffer 64)]
  j0 <- case planCall defaultRules m4 finReq of
    Execute resF eff -> do
      let jr = JobRequest
            { jrSession = sid
            , jrFunction = JobDigest
            , jrWork = WorkCall resF eff
            , jrTicks = 1
            , jrCapacity = 64
            }
      started <- startJob table jr
      case started of
        Right jid -> pure jid
        Left deny -> assertFailure ("final start denied: " ++ show deny)
    other -> assertFailure ("final did not plan execute: " ++ show other)
  p <- pollJob (\_fx -> pure (GotBytes digest)) env table JobDigest j0
  assertEqual "drive ready" PollReady p
  order <- newIORef ([] :: [String])
  writes <- newIORef []
  needed <- newIORef []
  let del = Delivery
        { dCapacity = 64
        , dWrite = \bs -> do
            modifyIORef' order (++ ["write"])
            modifyIORef' writes (++ [bs])
        , dReportNeeded = \_ -> pure ()
        }
      release r = modifyIORef' order (++ ["drain:" ++ show r])
  c <- completeJob env table JobDigest j0 del release
  case c of
    CompleteDelivered (CompBytes bs) -> assertEqual "bytes" digest bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  got <- readIORef order
  assertEqual "drain before write"
    ["drain:" ++ show (ReleaseEngineResource rid), "write"] got
  _ <- readIORef needed
  pure ()

-- | A throwing delivery sink must leave the job recoverable
-- (Ready) with the exception propagated — previously Delivered
-- committed first, so the retry observed a phantom delivery
-- instead of delivering.
caseFailingSink :: IO ()
caseFailingSink = do
  (table, env) <- mkTable
  runs <- newIORef 0
  Right j0 <- startJob table (signRequest sid1 1)
  p <- pollJob (countingRunner runs) env table JobSign j0
  assertEqual "drive ready" PollReady p
  let flaky = Delivery
        { dCapacity = 64
        , dWrite = \_ -> throwIO (userError "sink boom")
        , dReportNeeded = \_ -> pure ()
        }
  r <- try (completeJob env table JobSign j0 flaky (\_ -> pure ()))
    :: IO (Either SomeException CompleteOutcome)
  case r of
    Left _ -> pure ()
    Right oc -> assertFailure ("expected sink throw, got " ++ show oc)
  (writes, needed) <- newCapture
  let roomy = captureDelivery 64 writes needed
  c2 <- completeJob env table JobSign j0 roomy (\_ -> pure ())
  got <- readIORef writes
  case c2 of
    CompleteDelivered (CompBytes bs) -> do
      assertEqual "retry delivers the held bytes" cannedSig bs
      assertEqual "exactly one delivery write" 1 (length got)
    other -> assertFailure ("retry must deliver after a failing sink, got "
      ++ show other)

-- | Non-blocking lock probe (the 'leaseLockHeld' precedent): the
-- take\/put pair runs masked so the token cannot leak.
lockHeld :: MVar a -> IO Bool
lockHeld mv = mask_ $ do
  m <- tryTakeMVar mv
  case m of
    Nothing -> pure True
    Just v -> putMVar mv v >> pure False

-- | Rule R4: a borrow holds the registry lock across the whole use.
caseBorrowHoldsLock :: IO ()
caseBorrowHoldsLock = do
  reg <- newMVar (Map.singleton (1 :: Word32) ("handle-value" :: String))
  entered <- newEmptyMVar
  release <- newEmptyMVar
  done <- newEmptyMVar
  _ <- forkIO (withBorrowedRegistry reg 1 (\mh -> do
    putMVar entered ()
    takeMVar release
    pure mh) >>= putMVar done)
  takeMVar entered
  held <- lockHeld reg
  assertBool "borrow holds the lock across use" held
  putMVar release ()
  mh <- takeMVar done
  assertEqual "borrowed value" (Just "handle-value") mh
  heldAfter <- lockHeld reg
  assertBool "lock released after use" (not heldAfter)

-- | Rule R4: a take (final\/release\/close) waits for permitted
-- in-flight use instead of freeing under it.
caseTakeWaitsForBorrow :: IO ()
caseTakeWaitsForBorrow = do
  reg <- newMVar (Map.singleton (1 :: Word32) nullPtr)
  entered <- newEmptyMVar
  release <- newEmptyMVar
  borrowDone <- newEmptyMVar
  _ <- forkIO (withBorrowedRegistry reg 1 (\mh -> do
    putMVar entered ()
    takeMVar release
    pure mh) >>= putMVar borrowDone)
  takeMVar entered
  attempting <- newEmptyMVar
  takeDone <- newEmptyMVar
  _ <- forkIO (do
    putMVar attempting ()
    takeRegistry reg (EngineResourceId 1) >>= putMVar takeDone)
  takeMVar attempting
  early <- tryTakeMVar takeDone
  assertEqual "take waits for in-flight borrow" Nothing early
  putMVar release ()
  _ <- takeMVar borrowDone
  taken <- takeMVar takeDone
  assertBool "take got the entry" (taken == Just nullPtr)

-- | Rule R4: a kill inside a borrow restores the lock with the entry
-- intact (borrows never consume), and cancellation is preserved.
caseKillInBorrowRestores :: IO ()
caseKillInBorrowRestores = do
  reg <- newMVar (Map.singleton (1 :: Word32) ("handle-value" :: String))
  entered <- newEmptyMVar
  release <- newEmptyMVar
  done <- newEmptyMVar
  tid <- forkIO (try (withBorrowedRegistry reg 1 (\_ -> do
    putMVar entered ()
    _ <- takeMVar release
    pure ())) >>= putMVar done)
  takeMVar entered
  killThread tid
  r <- takeMVar done :: IO (Either SomeException ())
  case r of
    Left e -> case fromException e of
      Just ThreadKilled -> pure ()
      _ -> assertFailure ("expected ThreadKilled, got " ++ show e)
    Right _ -> assertFailure "expected kill, borrow returned"
  held <- lockHeld reg
  assertBool "lock restored after kill" (not held)
  mh <- lookupRegistry reg 1
  assertEqual "entry intact after kill" (Just "handle-value") mh

-- | Rule R4: snapshot lookup serves immutable values (present and
-- missing). Native handles must borrow instead (see above).
caseSnapshotLookup :: IO ()
caseSnapshotLookup = do
  reg <- newMVar (Map.singleton (7 :: Word32) ("material" :: String))
  mh <- lookupRegistry reg 7
  assertEqual "present" (Just "material") mh
  miss <- lookupRegistry reg 8
  assertEqual "absent" (Nothing :: Maybe String) miss

-- | Rule R6: a true cross-thread kill landing in a BLOCKED
-- delivery sink lands (blocking calls stay killable under 'mask_',
-- the detach precedent) with the job still 'Ready': the victim dies
-- 'ThreadKilled', nothing is written, and the retry delivers
-- exactly once. Implementation-only pin: before the fix the
-- commit preceded the write, so a kill in the
-- sink stranded Delivered-without-bytes — the
-- interruption-at-delivery probe pins that defect with a
-- deterministic synchronous throw instead).
caseKillDuringBlockedSink :: IO ()
caseKillDuringBlockedSink = do
  (table, env) <- mkTable
  runs <- newIORef 0
  Right j0 <- startJob table (signRequest sid1 1)
  p <- pollJob (countingRunner runs) env table JobSign j0
  assertEqual "drive ready" PollReady p
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  writes <- newIORef ([] :: [ByteString])
  let gated = Delivery
        { dCapacity = 64
        , dWrite = \bs -> do
            putMVar entered ()
            _ <- takeMVar proceed
            modifyIORef' writes (++ [bs])
        , dReportNeeded = \_ -> pure ()
        }
  done <- newEmptyMVar
  tid <- forkIO (try (completeJob env table JobSign j0 gated (\_ -> pure ()))
    >>= putMVar done)
  takeMVar entered
  killThread tid
  -- The barrier is never released: the victim dies parked in it
  -- (deterministic — no racer), the write never runs, the commit
  -- never runs, the job stays 'Ready'.
  r <- takeMVar done :: IO (Either SomeException CompleteOutcome)
  case r of
    Left e -> case fromException e of
      Just ThreadKilled -> pure ()
      _ -> assertFailure ("expected ThreadKilled, got " ++ show e)
    Right oc -> assertFailure ("expected kill, complete returned " ++ show oc)
  got <- readIORef writes
  assertEqual "killed write wrote nothing" 0 (length got)
  (writes2, needed2) <- newCapture
  c2 <- completeJob env table JobSign j0
    (captureDelivery 64 writes2 needed2) (\_ -> pure ())
  case c2 of
    CompleteDelivered (CompBytes bs) -> do
      assertEqual "retry delivers the held bytes" cannedSig bs
      got2 <- readIORef writes2
      assertEqual "exactly one delivery write" 1 (length got2)
    other -> assertFailure ("retry must deliver after a killed sink, got "
      ++ show other)

-- | A faulted publish drains the commit's releases exactly
-- once (an orphaned engine resource must not survive the commit),
-- fails the job terminal, and touches neither the sink nor the
-- sizing report.
--
-- Arrival mechanism (documented forgery): the reservation's
-- revision deps are cleared, so the stale-check cannot preempt the
-- publish fault — the real arrival is a concurrent close racing
-- snapshot-then-publish (timing, untestable); the code under test
-- ('commitAndTryDeliver''s fault arm) is identical either way. The
-- session itself is REALLY closed ('DeltaCloseSession'), so the
-- fault is genuine, not forged.
caseFaultedPublishDrains :: IO ()
caseFaultedPublishDrains = do
  (env, _, st) <- openEnvSession
  let sid = ssId st
      rid = EngineResourceId 21
      digest = BS.replicate 32 0xAB
  m2 <- snapshotModel env
  let initReq = Request Pkcs11_3_2 F_DigestInit (Just sid) Nothing
        (encodeInitInput sha256Mech [] False BS.empty) []
  case planCall defaultRules m2 initReq of
    Execute resI (EffectCrypto _) -> do
      m3 <- snapshotModel env
      case finishEffect defaultRules m3 resI (EngineOkResource rid) of
        Left rej -> assertFailure ("init finish rejected: " ++ show rej)
        Right pc -> do
          pr <- publish env (pcDelta pc)
          case pr of
            Right () -> pure ()
            Left f -> assertFailure ("init publish failed: " ++ show f)
    other -> assertFailure ("init did not plan execute: " ++ show other)
  table <- newAsyncTable 8
  enableAsyncSession table sid
  m4 <- snapshotModel env
  let finReq = Request Pkcs11_3_2 F_DigestFinal (Just sid) Nothing BS.empty
        [RegionBytes "digest" (IntentBuffer 64)]
  j0 <- case planCall defaultRules m4 finReq of
    Execute resF eff -> do
      let jr = JobRequest
            { jrSession = sid
            , jrFunction = JobDigest
            , jrWork = WorkCall resF { resDeps = [] } eff
            , jrTicks = 1
            , jrCapacity = 64
            }
      started <- startJob table jr
      case started of
        Right jid -> pure jid
        Left deny -> assertFailure ("final start denied: " ++ show deny)
    other -> assertFailure ("final did not plan execute: " ++ show other)
  p <- pollJob (\_fx -> pure (GotBytes digest)) env table JobDigest j0
  assertEqual "drive ready" PollReady p
  -- Really close the session: the completion's finish succeeds
  -- (finishers are session-blind) but its delta faults at publish.
  closed <- publish env (StateDelta [DeltaCloseSession sid])
  case closed of
    Right () -> pure ()
    Left f -> assertFailure ("close failed: " ++ show f)
  (writes, needed) <- newCapture
  drains <- newIORef []
  c <- completeJob env table JobDigest j0 (captureDelivery 64 writes needed)
    (\r -> modifyIORef' drains (++ [r]))
  gotDrains <- readIORef drains
  assertEqual "faulted publish drains exactly once"
    [ReleaseEngineResource rid] gotDrains
  case c of
    CompleteAlready (TermFailed code _) ->
      assertEqual "fault code" CKR_GENERAL_ERROR code
    other -> assertFailure ("expected terminal failure, got " ++ show other)
  gotWrites <- readIORef writes
  assertEqual "sink untouched" [] gotWrites
  gotNeeded <- readIORef needed
  assertEqual "no sizing report" [] gotNeeded

-- | Delivery-failure pin for handle completions: a throwing
-- sink on a keygen job leaves 'Ready'; the retry re-finishes
-- against the fresh model, mints FRESH handles (the finisher
-- allocates from the live counters), and delivers exactly once.
-- The first-published set is orphaned (published, never delivered)
-- — the documented keygen delivery-failure caveat.
caseKeygenDeliveryRetry :: IO ()
caseKeygenDeliveryRetry = do
  (env, m0, st) <- openEnvSession
  table <- newAsyncTable 8
  let sid = ssId st
  enableAsyncSession table sid
  let pre = mNextHandle m0
      privMat = BS.replicate 32 0x4B
  (pw, fx) <- case planGenerateKey defaultRules m0 st aesKeyGenMech (aesTmpl 32) of
    KeyEffect pw0 fx0 -> pure (pw0, fx0)
    other -> assertFailure ("genkey is not an effect: " ++ show other)
  let req = JobRequest
        { jrSession = sid
        , jrFunction = JobGenKey
        , jrWork = WorkKey (keyReservation st "async-genkey") pw fx
        , jrTicks = 1
        , jrCapacity = 9
        }
  Right j0 <- startJob table req
  p <- pollJob (\_ -> pure (GotBytes (encodeKeyPair privMat Nothing)))
    env table JobGenKey j0
  assertEqual "genkey ready" PollReady p
  let flaky = Delivery
        { dCapacity = 9
        , dWrite = \_ -> throwIO (userError "sink boom")
        , dReportNeeded = \_ -> pure ()
        }
  r <- try (completeJob env table JobGenKey j0 flaky (\_ -> pure ()))
    :: IO (Either SomeException CompleteOutcome)
  case r of
    Left _ -> pure ()
    Right oc -> assertFailure ("expected sink throw, got " ++ show oc)
  (writes, needed) <- newCapture
  c2 <- completeJob env table JobGenKey j0
    (captureDelivery 9 writes needed) (\_ -> pure ())
  wantH <- case c2 of
    CompleteDelivered (CompOneHandle h) -> pure h
    other -> assertFailure ("retry must deliver, got " ++ show other)
  assertEqual "retry mints fresh handles" (ExternalHandle (pre + 1)) wantH
  got <- readIORef writes
  assertEqual "exactly one delivery write" 1 (length got)
  m1 <- snapshotModel env
  assertEqual "first set orphaned, second delivered"
    2 (length (Map.elems (mObjects m1)))

keyReservation :: SessionState -> String -> Reservation
keyReservation st op = Reservation op
  [DepSession (ssId st) (ssRevision st) (ssGeneration st)] Nothing Nothing

aesTmpl :: Int -> [(AttributeType, AttributeValue)]
aesTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkAes)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  ]

-- | S5a IN-matrix: zero outputs deliver the engine bytes (legacy
-- commits); exactly one 'RegionBytes' output delivers its bytes.
caseCallCompletionIn :: IO ()
caseCallCompletionIn = do
  assertEqual "legacy empty outputs deliver engine bytes"
    (Just (CompBytes "eng")) (callCompletion "eng" [])
  assertEqual "single bytes output delivers its bytes"
    (Just (CompBytes "out"))
    (callCompletion "eng" [NativeOutput (RegionBytes "r" IntentNull) "out"])

-- | S5a OUT-matrix: multi-output, handle, scalar, and nested shapes
-- are rejected (loud 'Nothing' — the caller fails the job, never
-- silently drops or partially delivers).
caseCallCompletionOut :: IO ()
caseCallCompletionOut = do
  let bytesOut = NativeOutput (RegionBytes "r" IntentNull) "out"
      handleOut = NativeOutput (RegionHandle "k") "h"
      scalarOut = NativeOutput (RegionScalar "s") "s"
      nestedOut = NativeOutput (RegionNested "n" []) "n"
  assertEqual "two bytes outputs rejected"
    Nothing (callCompletion "eng" [bytesOut, bytesOut])
  assertEqual "handle output on call path rejected"
    Nothing (callCompletion "eng" [handleOut])
  assertEqual "scalar output rejected"
    Nothing (callCompletion "eng" [scalarOut])
  assertEqual "nested output rejected"
    Nothing (callCompletion "eng" [nestedOut])
  assertEqual "mixed bytes+handle rejected"
    Nothing (callCompletion "eng" [bytesOut, handleOut])

-- | S5b rule matrix: terminal tombstones are reaping-eligible,
-- every live state is blocked.
caseReapEligibilityMatrix :: IO ()
caseReapEligibilityMatrix = do
  assertEqual "terminal eligible"
    EligibleTerminal (reapEligibility (JobTerminal TermCanceled))
  assertEqual "pending blocked"
    BlockedLive (reapEligibility (JobPending 3))
  assertEqual "running blocked"
    BlockedLive (reapEligibility JobRunning)
  assertEqual "ready blocked"
    BlockedLive (reapEligibility (JobReady (GotBytes "x")))

-- | S5b retention pin: tombstones accumulate unbounded until the
-- owner reaps them, and the live cap counts live jobs only — full
-- tombstones never block submits.
caseTombstoneCensus :: IO ()
caseTombstoneCensus = do
  table <- newAsyncTable 2
  _env <- newEnv defaultRules
  enableAsyncSession table sid1
  Right j0 <- startJob table (signRequest sid1 1)
  Right j1 <- startJob table (signRequest sid1 1)
  rFull <- startJob table (signRequest sid1 1)
  case rFull of
    Left StartOverCapacity -> pure ()
    other -> assertFailure ("expected over-capacity, got " ++ show other)
  k0 <- cancelJob table j0
  assertEqual "cancel wins" CancelOk k0
  k1 <- cancelJob table j1
  assertEqual "cancel wins" CancelOk k1
  (live, tomb, _) <- tableStats table
  assertEqual "no live left" 0 live
  assertEqual "two tombstones retained" 2 tomb
  Right j2 <- startJob table (signRequest sid1 1)
  Right _j3 <- startJob table (signRequest sid1 1)
  rFull2 <- startJob table (signRequest sid1 1)
  case rFull2 of
    Left StartOverCapacity -> pure ()
    other -> assertFailure ("expected over-capacity, got " ++ show other)
  (live2, tomb2, _) <- tableStats table
  assertEqual "live at cap" 2 live2
  assertEqual "tombstones unbounded until reaped" 2 tomb2
  rp <- reapJob table j0
  assertEqual "owner reaps terminal" Reaped rp
  rl <- reapJob table j2
  assertEqual "live untouched" ReapLive rl

-- | S5b detach pin: after detach-revoke the source table holds
-- nothing, so cancel (and poll) report unknown — cancel routes to
-- the table that holds the job, which post-revoke is the
-- rejoin-side table, never the source.
caseCancelAfterDetach :: IO ()
caseCancelAfterDetach = do
  (table, env) <- mkTable
  runs <- newIORef 0
  Right j0 <- startJob table (signRequest sid1 1)
  mLease <- beginDetach table j0
  case mLease of
    Nothing -> assertFailure "detach found no job"
    Just lease -> commitDetachRevoke lease
  k <- cancelJob table j0
  assertEqual "cancel after detach is unknown" CancelUnknown k
  p <- pollJob (countingRunner runs) env table JobSign j0
  assertEqual "poll after detach is unknown" PollUnknown p

openSynthetic :: IO (B.BackendEnv Synthetic)
openSynthetic = do
  eEnv <- B.openBackend "0" :: IO (B.EngineResult (B.BackendEnv Synthetic))
  case eEnv of
    B.EngineOk env -> pure env
    B.EngineFail err -> assertFailure ("synthetic open failed: " ++ show err)

-- | A feed answer must keep its unit shape through the
-- driver helpers — collapsing early to 'GotBytes BS.empty' would
-- be indistinguishable from a genuine empty-bytes answer. The
-- helper-level distinction is preserved while 'encodeResult'
-- collapses byte-identically (the ONLY collapse point).
caseFeedUnitShape :: IO ()
caseFeedUnitShape = do
  be <- openSynthetic
  eRid <- B.digestInit be B.D_SHA256
  rid <- case eRid of
    B.EngineOk r -> pure r
    B.EngineFail err -> assertFailure ("synthetic init failed: " ++ show err)
  feedRes <- runEffect be (const Nothing) (FxDigestFeed rid "hello")
  assertBool ("feed answer keeps unit shape, got " ++ show feedRes)
    (feedRes /= GotBytes BS.empty)
  -- The compat collapse stays byte-identical on both sides.
  assertEqual "collapse is empty bytes"
    (EngineOkBytes BS.empty) (encodeResult feedRes)
  assertEqual "collapse matches genuine empty bytes"
    (encodeResult (GotBytes BS.empty)) (encodeResult feedRes)

-- | Preservation pin: verify answers stay
-- verdict-typed through the driver helpers.
caseVerifyVerdict :: IO ()
caseVerifyVerdict = do
  be <- openSynthetic
  let resolve = const (Just (B.KeyBytes (BS.replicate 32 0xAA)))
  res <- runEffect be resolve
    (FxVerify (MechanismId 0x251) (Just (ObjectId 0)) BS.empty "hello" "badtag")
  case res of
    GotValid _ -> pure ()
    other -> assertFailure ("verify must stay verdict-typed, got " ++ show other)

-- | Preservation pin: 'toCryptoError' keeps
-- every backend-error category across the typed-driver change.
caseDriverErrorCats :: IO ()
caseDriverErrorCats = do
  let rid = EngineResourceId 9
  assertEqual "unsupported"
    (CryptoUnsupported "o" "w") (toCryptoError (B.BackendUnsupported "o" "w"))
  assertEqual "badparam"
    (CryptoBadParam "o" "w") (toCryptoError (B.BackendBadParam "o" "w"))
  assertEqual "badkey"
    (CryptoBadKey "o" "w") (toCryptoError (B.BackendBadKey "o" "w"))
  assertEqual "authfailed"
    (CryptoAuthFailed "o") (toCryptoError (B.BackendAuthFailed "o"))
  assertEqual "invalidstate"
    (CryptoInvalidState "o" "w") (toCryptoError (B.BackendInvalidState "o" "w"))
  assertEqual "native"
    (CryptoNative "o" 3 "w") (toCryptoError (B.BackendNative "o" 3 "w"))
  assertEqual "resourcegone"
    (CryptoResourceGone "o" rid) (toCryptoError (B.BackendResourceGone "o" rid))

sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

openEnvSession :: IO (Env, Model, SessionState)
openEnvSession = do
  env <- newEnv defaultRules
  ini <- initialize env defaultInitArgs
  case ini of
    OutcomeOk () -> pure ()
    OutcomeErr c -> assertFailure ("init failed: " ++ show c)
  seatToken env (SlotId 0) >>= assertEqual "seat ok" (Right ())
  m0 <- snapshotModel env
  let sid = SessionId (mNextSession m0)
      req = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []
  case planCall defaultRules m0 req of
    Immediate pc -> do
      pr <- publish env (pcDelta pc)
      case pr of
        Right () -> pure ()
        Left f -> assertFailure ("open publish failed: " ++ show f)
    other -> assertFailure ("open did not plan immediate: " ++ show other)
  m1 <- snapshotModel env
  case lookupSession m1 sid of
    Just st -> pure (env, m1, st)
    Nothing -> assertFailure "seed session missing"
