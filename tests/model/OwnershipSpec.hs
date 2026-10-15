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
* handle registry: job handles are pure key tokens over the
  per-context live set — resolution decodes the key and checks
  membership without dereferencing, so retirement racing
  resolution refuses stale instead of dangling. Probes hammer
  resolve-vs-retire, admission storms, kill storms over admission,
  close-drain vs in-flight cancel/resolve (the no-inversion pin:
  an inversion would wedge under the timeout guard), and
  foreign\/bogus handles (per-context authority: never admitted
  here, never resolved here).
* lifetime gate: every OpenSSL execute path races its close
  (one-shot\/init\/update\/final\/release\/import\/export) with
  typed outcomes only; simultaneous closes stay total;
  deterministic parked-checkpoint proofs show close waiting for an
  admitted borrower and for the take-to-consume window, and
  interruption cleanup releasing the gate for a blocked closer; a
  kill while blocked in close preserves the gate (ThreadKilled,
  gate intact, close still functions).
-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
module OwnershipSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Concurrent
  ( MVar
  , ThreadId
  , forkFinally
  , forkIO
  , forkIOWithUnmask
  , killThread
  , newEmptyMVar
  , newMVar
  , putMVar
  , readMVar
  , takeMVar
  , threadDelay
  , tryTakeMVar
  )
import GHC.Conc (BlockReason (..), ThreadStatus (..), threadStatus)
import Control.Exception
  ( AsyncException (..)
  , IOException
  , SomeException
  , allowInterrupt
  , bracket
  , finally
  , fromException
  , mask_
  , throwIO
  , try
  , uninterruptibleMask_
  )
import Control.Monad (replicateM, replicateM_, when)
import System.Environment (lookupEnv)
import System.IO (hFlush, stdout)
import Data.IORef (IORef, atomicModifyIORef', modifyIORef', newIORef, readIORef, writeIORef)
import Data.List (isInfixOf)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Word (Word32, Word64)
import Foreign.C.Types (CInt (..), CLong (..), CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, nullPtr, wordPtrToPtr)
import Foreign.StablePtr (StablePtr, castPtrToStablePtr, castStablePtrToPtr, deRefStablePtr)
import Foreign.Storable (peek)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import qualified Haskoki.Engine.Backend as B
import Haskoki.Engine.Driver (encodeResult, runEffect, toCryptoError)
import Haskoki.Engine.OpenSSL4
  ( OpenSSL4 (..)
  , TestGate
  , digestFinalGated
  , digestInitGated
  , digestOneShotGated
  , digestXofGated
  , generateKeyECGated
  , lookupRegistry
  , openBackendGated
  , takeRegistry
  , withBorrowedRegistry
  )
import Haskoki.Engine.Synthetic (Synthetic (..))
import Haskoki.FFI.Async
  ( AsyncCtx (..)
  , JobHandle
  , allocJobHandle
  , asyncCloseCtx
  , asyncLiveHandles
  , decodeJobHandle
  , encodeJobHandle
  , freeJobHandle
  , resolveJobHandle
  )
import Haskoki.FFI.Standard
  ( StdInstance (..)
  , haskokiStdClose
  , haskokiStdCloseSession
  , haskokiStdOpenSessionWithAsync
  , openStdInstance
  , openStdInstanceWithSlots
  , setStdTokenPresence
  , stdAcquisition
  , stdRvOf
  )
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
  , asyncTableId
  , asyncTableSalt
  , beginDetach
  , callCompletion
  , cancelJob
  , commitDetachRevoke
  , completeJob
  , enableAsyncSession
  , enabledSessionCount
  , inspectJob
  , isAsyncSession
  , newAsyncTable
  , pollJob
  , reapEligibility
  , reapJob
  , startJob
  , tableSaltFor
  , tableStats
  , tryNewAsyncTable
  )
import Haskoki.Runtime.Detached
  ( AttachmentView (..)
  , DetachCtx
  , DetachOutcome (..)
  , JoinOutcome (..)
  , JoinRequest (..)
  , cancelJoined
  , detachJob
  , inspectAttachment
  , inspectReverse
  , joinJob
  , joinPolicyName
  , openDetached
  , retireLiveTable
  , retireLiveTableFor
  )
import Haskoki.Runtime.Config (Config (..), ControlCfg (..), defaultConfig)
import Haskoki.Runtime.Lifecycle
  ( Env
  , defaultInitArgs
  , initialize
  , newEnv
  , publish
  , seatToken
  , snapshotModel
  )
import Haskoki.Runtime.SlotEvents
  ( NotificationPoint (..)
  , PresenceChange (..)
  , PresenceError (..)
  , SlotDefinition (..)
  , newSlotEventsWith
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , JobExecState (JobCanceled)
  , JobRecord (..)
  , Store (..)
  , StoreDelta (..)
  , TokenRecord (..)
  , emptyDelta
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Transition (finishEffect, planCall)
import Haskoki.Types
  ( EngineResourceId (..)
  , ExternalHandle (..)
  , Generation (..)
  , JobId (..)
  , ObjectId (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
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
    , testCase "cancel while waiting for the lease dies killed; lease intact"
        (guarded "cancel-waiting-lease" caseCancelWhileWaitingForLease)
    ]
  , testGroup "lifetime gate"
    [ testCase "one-shot vs close stays typed"
        (guarded "gate-race-oneshot" caseGateRaceOneShot)
    , testCase "init vs close stays typed"
        (guarded "gate-race-init" caseGateRaceInit)
    , testCase "update vs close stays typed"
        (guarded "gate-race-update" (caseGateRaceUpdate (ctrTag "m2-lifetime-gate" "gate-race-update")))
    , testCase "final vs close stays typed"
        (guarded "gate-race-final" (caseGateRaceFinal (ctrTag "m2-lifetime-gate" "gate-race-final")))
    , testCase "release vs close frees once"
        (guarded "gate-race-release" (caseGateRaceRelease (ctrTag "m2-lifetime-gate" "gate-race-release")))
    , testCase "import vs close stays typed"
        (guarded "gate-race-import" caseGateRaceImportClose)
    , testCase "export vs close stays typed"
        (guarded "gate-race-export" caseGateRaceExportClose)
    , testCase "simultaneous close stays total"
        (guarded "gate-simultaneous-close" (caseGateSimultaneousClose (ctrTag "m2-lifetime-gate" "gate-simultaneous-close")))
    , testCase "close waits for an admitted borrower"
        (guarded "gate-close-waits-borrow" (caseGateCloseWaitsForBorrow (ctrTag "m2-lifetime-gate" "gate-close-waits-borrow")))
    , testCase "close waits through the take-to-consume window"
        (guarded "gate-close-waits-final" (caseGateCloseWaitsForFinal (ctrTag "m2-lifetime-gate" "gate-close-waits-final")))
    , testCase "interruption cleanup releases the gate for close"
        (guarded "gate-close-after-interrupt" (caseGateCloseAfterInterrupt (ctrTag "m2-lifetime-gate" "gate-close-after-interrupt")))
    , testCase "cancel while closing preserves the gate"
        (guarded "gate-cancel-closing" (caseGateCancelWhileClosing (ctrTag "m2-lifetime-gate" "gate-cancel-closing")))
    ]
  , testGroup "native ownership transfers"
    [ testCase "gated copy fault frees the output (sync)"
        (guarded "gated-copy-fault" (caseGatedCopyFaultSync (ctrTag "m1-native-transfers" "gated-copy-fault")))
    , testCase "parked copy dies ThreadKilled with zero outstanding"
        (guarded "gated-copy-park" (caseGatedCopyParkKill (ctrTag "m1-native-transfers" "gated-copy-park")))
    , testCase "pair fault between copies frees both"
        (guarded "gated-pair-between" (caseGatedPairBetweenFault (ctrTag "m1-native-transfers" "gated-pair-between")))
    , testCase "consuming final plus copy fault frees once (sync)"
        (guarded "gated-final-fault" (caseGatedFinalFaultSync (ctrTag "m1-native-transfers" "gated-final-fault")))
    , testCase "consuming final plus kill at copy frees once"
        (guarded "gated-final-park" (caseGatedFinalParkKill (ctrTag "m1-native-transfers" "gated-final-park")))
    , testCase "alloc fault before adoption fails clean"
        (guarded "gated-adoption-alloc" (caseGatedAdoptionAllocFail (ctrTag "m1-native-transfers" "gated-adoption-alloc")))
    , testCase "load fault before adoption frees the live env"
        (guarded "gated-adoption-load" (caseGatedAdoptionLoadFault (ctrTag "m1-native-transfers" "gated-adoption-load")))
    , testCase "parked pre-adoption load dies ThreadKilled, env freed"
        (guarded "gated-adoption-park" (caseGatedAdoptionParkKill (ctrTag "m1-native-transfers" "gated-adoption-park")))
    , testCase "alloc fault in digest init fails typed"
        (guarded "gated-init-alloc" (caseGatedInitAllocFail (ctrTag "m1-native-transfers" "gated-init-alloc")))
    , testCase "alloc fault in one-shot digest answers NOMEM"
        (guarded "gated-digest-alloc" (caseGatedDigestAllocFail (ctrTag "m1-native-transfers" "gated-digest-alloc")))
    , testCase "gated normal paths match production, zero outstanding"
        (guarded "gated-normal-zero" (caseGatedNormalZero (ctrTag "m1-native-transfers" "gated-normal-zero")))
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
  , testGroup "handle registry"
    [ testCase "key codec roundtrips; salts distinguish"
        (guarded "handle-key-codec" caseHandleKeyCodec)
    , testCase "deterministic retire-then-use stays typed"
        (guarded "handle-retire-then-use" caseHandleRetireThenUse)
    , testCase "deterministic resolve-then-close stays typed"
        (guarded "handle-resolve-then-close" caseHandleResolveThenClose)
    , testCase "resolve-vs-retire race stays typed"
        (guarded "handle-resolve-retire" caseHandleResolveRetire)
    , testCase "admission storm stays consistent"
        (guarded "handle-admission-storm" caseHandleAdmissionStorm)
    , testCase "kill storm over admission retires clean"
        (guarded "handle-kill-storm" caseHandleKillStorm)
    , testCase "close-drain vs in-flight stays typed"
        (guarded "handle-close-race" caseHandleCloseRace)
    , testCase "foreign and bogus handles stay stale"
        (guarded "handle-foreign-stale" caseHandleForeignStale)
    , testCase "table salts are stable and distinguish contexts"
        (guarded "handle-salt-stable" caseHandleSaltStable)
    , testCase "table salts are exact, nonzero, and stable"
        (guarded "table-salt-exact" caseTableSaltExact)
    , testCase "table salt mint refuses past the 32-bit bound"
        (guarded "table-salt-bound" caseTableSaltBound)
    ]
  , testGroup "attachment claims"
    [ testCase "table identities are unique and stable"
        (guarded "claim-table-id-unique" caseTableIdUnique)
    , testCase "scoped retire is exact and idempotent"
        (guarded "claim-scoped-retire" caseScopedRetireExactlyOnce)
    , testCase "rival refusal preserves the owner's cancel"
        (guarded "claim-rival-refusal" caseRivalRefusalPreservesOwner)
    , testCase "session churn and removal retire async enablement"
        (guarded "retire-churn-removal" caseSessionRetirementAccounting)
    , testCase "failed close and removal leave enablement intact"
        (guarded "retire-rollback" caseRetirementRollback)
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
  (pw, fx) <- case planGenerateKey defaultRules m0 st aesKeyGenMech BS.empty (aesTmpl 32) of
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

-- ---------------------------------------------------------------------------
-- Native ownership transfers
-- ---------------------------------------------------------------------------
-- The decisive fault battery for the native transfer gaps: each case
-- routes one operation through a per-test C gate object (created here
-- via test-local FFI; production paths pass NULL and never consult
-- hook state) and asserts native destruction counts (the destroy
-- paths note the -1 themselves, so the counters prove the native
-- free ran), the primary exception, and exactly-once consumption.
-- Fault arms are per-test, so parallel suites cannot cross-trigger;
-- the only shared state is the digest/env live-sets, whose counters
-- are identically zero under the fixed transfer. The sync-fault
-- marker ("hsk_ossl4_test_copy_fault") distinguishes the conditional
-- synchronous checkpoint failure from an ordinary 'ThreadKilled'.
-- Kill-mode protocol: a parked checkpoint is a plain safe foreign
-- call, so it cannot be killed out from under the gate mutex.
-- 'killThread' blocks until delivery, so the kill is issued from a
-- forked killer (proven entered via a status barrier — see
-- 'withKillWorker') while the victim is parked and delivered at
-- the Haskell level after the release, which is exactly the
-- cleanup ordering the transfer guarantees.

foreign import ccall unsafe "hsk_ossl4_test_gate_new" c_gateNew
  :: IO (Ptr TestGate)
foreign import ccall unsafe "hsk_ossl4_test_gate_free" c_gateFree
  :: Ptr TestGate -> IO ()
foreign import ccall unsafe "hsk_ossl4_test_gate_arm_checkpoint" c_gateArmCheckpoint
  :: Ptr TestGate -> CInt -> IO ()
foreign import ccall unsafe "hsk_ossl4_test_gate_arm_alloc_fail" c_gateArmAllocFail
  :: Ptr TestGate -> IO ()
foreign import ccall unsafe "hsk_ossl4_test_gate_parked" c_gateParked
  :: Ptr TestGate -> IO CInt
foreign import ccall unsafe "hsk_ossl4_test_gate_release" c_gateRelease
  :: Ptr TestGate -> CInt -> IO ()
foreign import ccall unsafe "hsk_ossl4_test_gate_buf_outstanding" c_gateBufOutstanding
  :: Ptr TestGate -> IO CLong
foreign import ccall unsafe "hsk_ossl4_test_gate_digest_outstanding" c_gateDigestOutstanding
  :: Ptr TestGate -> IO CLong
foreign import ccall unsafe "hsk_ossl4_test_gate_env_outstanding" c_gateEnvOutstanding
  :: Ptr TestGate -> IO CLong
foreign import ccall unsafe "hsk_ossl4_test_digest_doublefree" c_digestDoublefree
  :: IO CLong
foreign import ccall unsafe "hsk_ossl4_test_digest_untracked" c_digestUntracked
  :: IO CLong
foreign import ccall unsafe "hsk_ossl4_test_env_doublefree" c_envDoublefree
  :: IO CLong
foreign import ccall unsafe "hsk_ossl4_test_env_untracked" c_envUntracked
  :: IO CLong

withGate :: (Ptr TestGate -> IO a) -> IO a
withGate = bracket acquire release
  where
    acquire = do
      g <- c_gateNew
      if g == nullPtr
        then assertFailure "test gate allocation failed"
        else pure g
    -- Release-then-free on every exit (harmless with nobody
    -- parked). Kill-mode cases run their worker inside
    -- 'withKillWorker', whose cleanup joins the worker first, so
    -- every gate user has returned before the free on every exit
    -- — including a timeout or a failed assertion mid-test.
    release g = c_gateRelease g 0 >> c_gateFree g

-- | Run a gate-using op in a worker that is released, killed, and
-- joined on EVERY exit. The body receives the done-'MVar' and the
-- killer-firing action, and reads the result with 'readMVar'
-- (non-consuming — the cleanup owns the consuming take, so the
-- join happens exactly once).
--
-- Why a forked killer plus a barrier: 'killThread' blocks until
-- the exception is delivered, and a worker parked in a safe
-- foreign call cannot receive until the release lets the call
-- return — so the releasing thread must not issue the kill
-- itself (that deadlocks). The killer is therefore a separate
-- thread; firing forks it and then waits until its status is
-- 'ThreadBlocked' — against a parked worker 'killThread' cannot
-- return, so blocked proves entry, and entry-before-release is
-- then a fact rather than a scheduling hope (a ready-'MVar'
-- alone cannot order this on multiple capabilities). The kill is
-- delivered at the Haskell level after the release, which is
-- exactly the cleanup-before-delivery ordering the transfer
-- guarantees.
--
-- Masking: the worker is forked with 'forkIOWithUnmask' (a plain
-- 'forkIO' inside 'bracket' would inherit the masked state and
-- the kill would pend forever): 'try' installs its handler while
-- still masked and only the op runs unmasked, while the result
-- publication stays masked — so the done-'MVar' is filled on
-- every path and the join below always returns. (The mirrored
-- 'unmask (try op)' would deliver a queued kill after unmasking
-- but before the handler installs, skipping the publication and
-- hanging the join.) The trailing 'allowInterrupt' is the
-- guaranteed delivery point for a kill still pending when a
-- fully-masked op (like the consuming final) returns: without it
-- the worker could publish 'Right' into the masked tail with
-- 'ThreadKilled' still pending, misclassifying cancellation as
-- success.
withKillWorker :: Ptr TestGate -> IO a
  -> (MVar (Either SomeException a) -> IO () -> IO b) -> IO b
withKillWorker g op body = do
  done <- newEmptyMVar
  killerDone <- newEmptyMVar
  let fire tid = do
        ktid <- forkIO (killThread tid >> putMVar killerDone ())
        awaitBlocked ktid
      -- Release (wakes any parked waiter, and latches for a
      -- worker that polls after it, so no release is ever lost),
      -- kill (vacuous once done), join (the worker puts on every
      -- path, so this always returns). Uninterruptible: 'killThread'
      -- stays interruptible even under 'bracket's mask, so a plain
      -- masked cleanup could be aborted by a timeout before the
      -- join — every operation here is bounded, so deferring the
      -- timeout past the join is safe. The killer needs no join
      -- for gate safety (it never touches the gate) and exits on
      -- its own once its 'killThread' resolves; the best-effort
      -- drain is hygiene only (the killer may never have fired).
      cleanup tid = uninterruptibleMask_ $ do
        c_gateRelease g 1
        killThread tid
        _ <- takeMVar done
        _ <- tryTakeMVar killerDone
        pure ()
  bracket
    (forkIOWithUnmask $ \unmask -> do
      r <- try (unmask op <* allowInterrupt)
      putMVar done r)
    cleanup
    (\tid -> body done (fire tid))

-- | Barrier for the forked killer: against a parked worker its
-- 'killThread' must block, so 'ThreadBlocked' proves entry —
-- after this returns, the kill is strictly pending and the
-- release cannot slip through first. Bounded like 'awaitParked'.
awaitBlocked :: ThreadId -> IO ()
awaitBlocked ktid = go (200 :: Int)
  where
    go n
      | n <= 0 = assertFailure "killer never blocked in killThread"
      | otherwise = do
          st <- threadStatus ktid
          case st of
            ThreadBlocked _ -> pure ()
            _ -> threadDelay 1000 >> go (n - 1)

-- | Barrier for a closer blocked on the lifetime gate: accepts ONLY
-- 'BlockedOnMVar' — a foreign-call or exception block must never
-- satisfy a gate-wait proof. Bounded like 'awaitBlocked'.
awaitMVarBlocked :: ThreadId -> IO ()
awaitMVarBlocked ctid = go (200 :: Int)
  where
    go n
      | n <= 0 = assertFailure "closer never blocked on the gate MVar"
      | otherwise = do
          st <- threadStatus ctid
          case st of
            ThreadBlocked BlockedOnMVar -> pure ()
            _ -> threadDelay 1000 >> go (n - 1)

withRealBackend :: (B.BackendEnv OpenSSL4 -> IO a) -> IO a
withRealBackend action = do
  r <- B.openBackend "provider=default"
    :: IO (B.EngineResult (B.BackendEnv OpenSSL4))
  case r of
    B.EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    B.EngineOk env -> action env `finally` B.closeBackend env

isCopyFault :: SomeException -> Bool
isCopyFault e = case fromException e :: Maybe IOException of
  Just ioe -> "hsk_ossl4_test_copy_fault" `isInfixOf` show ioe
  Nothing -> False

assertCopyFault :: Either SomeException a -> IO ()
assertCopyFault (Right _) =
  assertFailure "expected the injected copy fault, the op succeeded"
assertCopyFault (Left e) = case fromException e :: Maybe AsyncException of
  Just ThreadKilled ->
    assertFailure ("expected the sync copy fault, got ThreadKilled: " ++ show e)
  _ -> assertBool ("expected the copy-fault marker, got: " ++ show e)
    (isCopyFault e)

assertThreadKilled :: Either SomeException a -> IO ()
assertThreadKilled (Right _) =
  assertFailure "expected ThreadKilled, the op returned"
assertThreadKilled (Left e) = case fromException e :: Maybe AsyncException of
  Just ThreadKilled -> pure ()
  _ -> assertFailure ("expected ThreadKilled, got: " ++ show e)

-- | Rendezvous for the park scenarios: the victim parks in the
-- checkpoint deterministically (straight-line code past the arm),
-- so this either observes the park or fails bounded (never
-- timing-hope, and the outer 'guarded' backstops the whole case).
awaitParked :: Ptr TestGate -> IO ()
awaitParked g = go (200 :: Int)
  where
    go n
      | n <= 0 = assertFailure "victim never parked in the checkpoint"
      | otherwise = do
          p <- c_gateParked g
          if p /= 0 then pure () else threadDelay 5000 >> go (n - 1)

-- | Tag of one gated case's counter line: the matrix case id (the
-- driver's table key) and the test label.
data CtrTag = CtrTag String String

ctrTag :: String -> String -> CtrTag
ctrTag = CtrTag

-- | Print one @OWNERSHIP-COUNTERS case=<id> test=<label> k=v ...@
-- line, only when HASKOKI_OWNERSHIP_COUNTERS=1 (ruling 5; precedent
-- DURABILITY). Printed before the assertions so a failing value is
-- still visible. One flushed 'putStr' so parallel tasty threads
-- interleave whole lines only.
emitCounters :: CtrTag -> [(String, CLong)] -> IO ()
emitCounters (CtrTag c t) kvs = do
  on <- lookupEnv "HASKOKI_OWNERSHIP_COUNTERS"
  when (on == Just "1") $ do
    putStr ("OWNERSHIP-COUNTERS case=" ++ c ++ " test=" ++ t
            ++ concatMap (\(k, v) -> " " ++ k ++ "=" ++ show v) kvs ++ "\n")
    hFlush stdout

assertOutstandingZero :: CtrTag -> Ptr TestGate -> IO ()
assertOutstandingZero ctr g = do
  b <- c_gateBufOutstanding g
  d <- c_gateDigestOutstanding g
  e <- c_gateEnvOutstanding g
  emitCounters ctr [("bufs", b), ("digests", d), ("envs", e)]
  assertEqual "no stranded buffers" 0 b
  assertEqual "no stranded digests" 0 d
  assertEqual "no stranded envs" 0 e

-- | The digest live-set counters are identically zero under the
-- fixed transfer, so these assert without cross-test quiescence.
assertDigestCountersClean :: CtrTag -> IO ()
assertDigestCountersClean ctr = do
  df <- c_digestDoublefree
  du <- c_digestUntracked
  emitCounters ctr [("digest_doublefree", df), ("digest_untracked", du)]
  assertEqual "no digest double-free" 0 df
  assertEqual "complete digest tracking" 0 du

-- | The env live-set twin: identically zero under the fixed
-- transfer (no double-free, complete tracking).
assertEnvCountersClean :: CtrTag -> IO ()
assertEnvCountersClean ctr = do
  ef <- c_envDoublefree
  eu <- c_envUntracked
  emitCounters ctr [("env_doublefree", ef), ("env_untracked", eu)]
  assertEqual "no env double-free" 0 ef
  assertEqual "complete env tracking" 0 eu

expectGatedOk :: Show a => String -> B.EngineResult a -> IO a
expectGatedOk label r = case r of
  B.EngineOk a -> pure a
  B.EngineFail err ->
    assertFailure (label ++ ": expected EngineOk, got " ++ show err)

-- | Sync fault before the output copy: the primary exception is the
-- injected fault (not cancellation) and the native buffer is freed.
caseGatedCopyFaultSync :: CtrTag -> IO ()
caseGatedCopyFaultSync ctr = withGate $ \g -> withRealBackend $ \env -> do
  c_gateArmCheckpoint g 1
  r <- try (digestOneShotGated g env B.D_SHA256 "hello")
    :: IO (Either SomeException (B.EngineResult ByteString))
  assertCopyFault r
  assertOutstandingZero ctr g

-- | Async kill issued at the copy checkpoint: the parked safe call
-- cannot be killed out from under the gate mutex, so the forked
-- killer's 'killThread' blocks until the release lets the call
-- return — cancellation is preserved and the registered buffer is
-- freed exactly once, before delivery.
caseGatedCopyParkKill :: CtrTag -> IO ()
caseGatedCopyParkKill ctr = withGate $ \g -> withRealBackend $ \env -> do
  c_gateArmCheckpoint g 2
  withKillWorker g (digestOneShotGated g env B.D_SHA256 "hello") $ \done fire -> do
    awaitParked g
    fire
    c_gateRelease g 0
    r <- readMVar done
      :: IO (Either SomeException (B.EngineResult ByteString))
    assertThreadKilled r
    assertOutstandingZero ctr g

-- | Sync fault between the pair copies: cleanup for BOTH halves was
-- registered before either copy, so both are freed.
caseGatedPairBetweenFault :: CtrTag -> IO ()
caseGatedPairBetweenFault ctr = withGate $ \g -> withRealBackend $ \env -> do
  c_gateArmCheckpoint g 3
  r <- try (generateKeyECGated g env
      (B.EcSpec { B.ecCurve = "P-256", B.ecEncoding = "DER" }))
    :: IO (Either SomeException
        (B.EngineResult (B.KeyMaterial, Maybe B.KeyMaterial)))
  assertCopyFault r
  assertOutstandingZero ctr g

-- | Sync fault after the final's C consumption: post-call cleanup
-- owns only the output buffer (no second handle free), and the
-- primary exception is the injected fault.
caseGatedFinalFaultSync :: CtrTag -> IO ()
caseGatedFinalFaultSync ctr = withGate $ \g -> withRealBackend $ \env -> do
  rid <- expectGatedOk "gated init" =<< digestInitGated g env B.D_SHA256
  expectGatedOk "update" =<< B.digestUpdate env rid "hello"
  c_gateArmCheckpoint g 1
  r <- try (digestFinalGated g env rid)
    :: IO (Either SomeException (B.EngineResult ByteString))
  assertCopyFault r
  assertOutstandingZero ctr g
  assertDigestCountersClean ctr

-- | Async kill issued at the final's copy checkpoint: cancellation
-- preserved, output freed, handle consumed exactly once.
caseGatedFinalParkKill :: CtrTag -> IO ()
caseGatedFinalParkKill ctr = withGate $ \g -> withRealBackend $ \env -> do
  rid <- expectGatedOk "gated init" =<< digestInitGated g env B.D_SHA256
  expectGatedOk "update" =<< B.digestUpdate env rid "hello"
  c_gateArmCheckpoint g 2
  withKillWorker g (digestFinalGated g env rid) $ \done fire -> do
    awaitParked g
    fire
    c_gateRelease g 0
    r <- readMVar done
      :: IO (Either SomeException (B.EngineResult ByteString))
    assertThreadKilled r
    assertOutstandingZero ctr g
    assertDigestCountersClean ctr

-- | Alloc fault at env construction: the open fails typed (nothing
-- adopted, nothing to free) and the one-shot arm is spent, so a
-- second open succeeds on the healthy backend.
caseGatedAdoptionAllocFail :: CtrTag -> IO ()
caseGatedAdoptionAllocFail ctr = withGate $ \g -> do
  c_gateArmAllocFail g
  r <- openBackendGated g "provider=default"
    :: IO (B.EngineResult (B.BackendEnv OpenSSL4))
  case r of
    B.EngineFail _ -> pure ()
    B.EngineOk env ->
      B.closeBackend env >> assertFailure "adoption alloc-fail still opened"
  assertOutstandingZero ctr g
  assertEnvCountersClean ctr
  r2 <- openBackendGated g "provider=default"
    :: IO (B.EngineResult (B.BackendEnv OpenSSL4))
  case r2 of
    B.EngineOk env2 -> B.closeBackend env2
    B.EngineFail err ->
      assertFailure ("second open must succeed: " ++ show err)

-- | Sync checkpoint fault at the pre-adoption provider load: the
-- live env is freed on the failure path (never adopted), the open
-- fails typed, and no env strands.
caseGatedAdoptionLoadFault :: CtrTag -> IO ()
caseGatedAdoptionLoadFault ctr = withGate $ \g -> do
  c_gateArmCheckpoint g 1
  r <- openBackendGated g "provider=default"
    :: IO (B.EngineResult (B.BackendEnv OpenSSL4))
  case r of
    B.EngineFail _ -> pure ()
    B.EngineOk env ->
      B.closeBackend env >> assertFailure "load-faulted open still opened"
  assertOutstandingZero ctr g
  assertEnvCountersClean ctr

-- | Async kill issued at the pre-adoption load checkpoint: the
-- forked killer's 'killThread' blocks until the fault-verdict
-- release lets the load return — deterministically 'ThreadKilled'
-- (early delivery unwinds via the pre-adoption 'onException',
-- late delivery lands after the masked failure cleanup) with the
-- live env freed exactly once either way.
caseGatedAdoptionParkKill :: CtrTag -> IO ()
caseGatedAdoptionParkKill ctr = withGate $ \g -> do
  c_gateArmCheckpoint g 2
  withKillWorker g (openBackendGated g "provider=default") $ \done fire -> do
    awaitParked g
    fire
    c_gateRelease g 1
    r <- readMVar done
      :: IO (Either SomeException (B.EngineResult (B.BackendEnv OpenSSL4)))
    assertThreadKilled r
    assertOutstandingZero ctr g
    assertEnvCountersClean ctr

-- | Alloc fault at digest init: typed failure, nothing registered.
caseGatedInitAllocFail :: CtrTag -> IO ()
caseGatedInitAllocFail ctr = withGate $ \g -> withRealBackend $ \env -> do
  c_gateArmAllocFail g
  r <- digestInitGated g env B.D_SHA256
  case r of
    B.EngineFail _ -> pure ()
    B.EngineOk rid -> B.releaseResource env rid
      >> assertFailure "init alloc-fail still allocated"
  assertOutstandingZero ctr g

-- | Alloc fault at the one-shot output: the shim answers NOMEM and
-- the backend reports it typed.
caseGatedDigestAllocFail :: CtrTag -> IO ()
caseGatedDigestAllocFail ctr = withGate $ \g -> withRealBackend $ \env -> do
  c_gateArmAllocFail g
  r <- digestOneShotGated g env B.D_SHA256 "hello"
  case r of
    B.EngineFail (B.BackendNative _ code _) ->
      assertEqual "NOMEM code" (-4) code
    _ -> assertFailure ("expected a NOMEM native failure, got " ++ show r)
  assertOutstandingZero ctr g

-- | Characterization: unarmed gated paths match production bytes
-- (plain, sized, XOF, multipart, pair) and leave zero outstanding.
-- The gate observes without perturbing; the sized/XOF legs compare
-- against production either way (served or refused alike).
caseGatedNormalZero :: CtrTag -> IO ()
caseGatedNormalZero ctr = withGate $ \g -> withRealBackend $ \env -> do
  prod <- expectGatedOk "prod digest" =<< B.digestOneShot env B.D_SHA256 "abc"
  gated <- expectGatedOk "gated digest"
    =<< digestOneShotGated g env B.D_SHA256 "abc"
  assertEqual "gated matches production" prod gated
  assertEqual "sha256 abc (FIPS 180-4)" sha256abc gated
  prodSized <- B.digestOneShot env B.D_BLAKE2B256 "abc"
  gatedSized <- digestOneShotGated g env B.D_BLAKE2B256 "abc"
  assertEqual "gated sized matches production" prodSized gatedSized
  prodXof <- B.digestXof env B.D_SHAKE128 "abc" 32
  gatedXof <- digestXofGated g env B.D_SHAKE128 "abc" 32
  assertEqual "gated xof matches production" prodXof gatedXof
  rid <- expectGatedOk "gated init" =<< digestInitGated g env B.D_SHA256
  expectGatedOk "update" =<< B.digestUpdate env rid "abc"
  fin <- expectGatedOk "gated final" =<< digestFinalGated g env rid
  assertEqual "multipart equals one-shot" gated fin
  kg <- generateKeyECGated g env
    (B.EcSpec { B.ecCurve = "P-256", B.ecEncoding = "DER" })
  case kg of
    B.EngineOk (B.KeyDer priv, Just (B.KeyDer pub)) -> do
      assertBool "priv half non-empty" (not (BS.null priv))
      assertBool "pub half non-empty" (not (BS.null pub))
    _ -> assertFailure ("EC keygen shape: " ++ show kg)
  assertOutstandingZero ctr g
  assertDigestCountersClean ctr

sha256abc :: ByteString
sha256abc = BS.pack
  [ 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea
  , 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23
  , 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c
  , 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
  ]

-- ---------------------------------------------------------------------------
-- Lifetime gate
-- ---------------------------------------------------------------------------

-- | Race one op against close on an open backend: the op runs under
-- the exclusive lifetime gate, so its outcome is either the
-- pre-close answer or 'B.BackendInvalidState' — never a crash,
-- never a wedge. The start rendezvous sharpens the race; every
-- assertion accepts both orders (never timing-hope).
raceWithCloseOn :: B.BackendEnv OpenSSL4 -> IO () -> IO ()
raceWithCloseOn env op = do
  start <- newEmptyMVar
  opDone <- newEmptyMVar
  closeDone <- newEmptyMVar
  _ <- forkIO (takeMVar start >> try op >>= putMVar opDone)
  _ <- forkIO (takeMVar start >> try (B.closeBackend env) >>= putMVar closeDone)
  putMVar start ()
  putMVar start ()
  r1 <- takeMVar opDone :: IO (Either SomeException ())
  r2 <- takeMVar closeDone :: IO (Either SomeException ())
  assertWorkerOk r1
  assertWorkerOk r2

-- | One-shot vs close: bytes or InvalidState, typed either way.
caseGateRaceOneShot :: IO ()
caseGateRaceOneShot = replicateM_ 15 $ withRealBackend $ \env ->
  raceWithCloseOn env $ do
    r <- B.digestOneShot env B.D_SHA256 "hello"
    case r of
      B.EngineOk _ -> pure ()
      B.EngineFail (B.BackendInvalidState _ _) -> pure ()
      other -> assertFailure ("one-shot vs close must stay typed, got " ++ show other)

-- | Init vs close: a fresh id (released after the win — release is
-- total even when close drained first) or InvalidState.
caseGateRaceInit :: IO ()
caseGateRaceInit = replicateM_ 15 $ withRealBackend $ \env ->
  raceWithCloseOn env $ do
    r <- B.digestInit env B.D_SHA256
    case r of
      B.EngineOk rid -> B.releaseResource env rid
      B.EngineFail (B.BackendInvalidState _ _) -> pure ()
      other -> assertFailure ("init vs close must stay typed, got " ++ show other)

-- | Update vs close on a live id: unit or InvalidState. Pre-gate
-- this borrowed a handle close could free mid-call; the gate
-- serializes the two, and the counters pin no double-free.
caseGateRaceUpdate :: CtrTag -> IO ()
caseGateRaceUpdate ctr = replicateM_ 15 $ withRealBackend $ \env -> do
  rid <- expectGatedOk "init" =<< B.digestInit env B.D_SHA256
  raceWithCloseOn env $ do
    r <- B.digestUpdate env rid "hello"
    case r of
      B.EngineOk () -> pure ()
      B.EngineFail (B.BackendInvalidState _ _) -> pure ()
      other -> assertFailure ("update vs close must stay typed, got " ++ show other)
  assertDigestCountersClean ctr

-- | Final vs close on a fed id: bytes or InvalidState, the handle
-- consumed exactly once either way.
caseGateRaceFinal :: CtrTag -> IO ()
caseGateRaceFinal ctr = replicateM_ 15 $ withRealBackend $ \env -> do
  rid <- expectGatedOk "init" =<< B.digestInit env B.D_SHA256
  expectGatedOk "update" =<< B.digestUpdate env rid "hello"
  raceWithCloseOn env $ do
    r <- B.digestFinal env rid
    case r of
      B.EngineOk _ -> pure ()
      B.EngineFail (B.BackendInvalidState _ _) -> pure ()
      other -> assertFailure ("final vs close must stay typed, got " ++ show other)
  assertDigestCountersClean ctr

-- | Release vs close: both take the gate, so the take-to-free and
-- the close drain cannot overlap — exactly one frees the handle.
caseGateRaceRelease :: CtrTag -> IO ()
caseGateRaceRelease ctr = replicateM_ 15 $ withRealBackend $ \env -> do
  rid <- expectGatedOk "init" =<< B.digestInit env B.D_SHA256
  raceWithCloseOn env (B.releaseResource env rid)
  assertDigestCountersClean ctr

-- | Simultaneous closes serialize into one drain: every closer
-- returns, the backend reads closed after, native sets stay clean.
caseGateSimultaneousClose :: CtrTag -> IO ()
caseGateSimultaneousClose ctr = withRealBackend $ \env -> do
  done <- newEmptyMVar
  let closer = B.closeBackend env >> putMVar done ()
  replicateM_ 16 (forkIO closer)
  replicateM_ 16 (takeMVar done)
  r <- B.digestOneShot env B.D_SHA256 "hello"
  case r of
    B.EngineFail (B.BackendInvalidState _ _) -> pure ()
    other -> assertFailure ("post-close one-shot must be InvalidState, got " ++ show other)
  assertEnvCountersClean ctr
  assertDigestCountersClean ctr

-- | Fork a backend closer joined on EVERY exit (the inner-bracket
-- twin of 'withKillWorker'): the body observes the result with
-- 'readMVar' (non-consuming); the cleanup owns the consuming take,
-- so the join happens exactly once even when the body dies early.
-- The cleanup is uninterruptible (a timeout mid-teardown must not
-- strand the join — every operation here is bounded): the kill
-- lands in the gate wait (prompt 'ThreadKilled', gate untouched)
-- or defers past the bounded uninterruptible drain, and the
-- publication is guaranteed (the handler installs masked, exactly
-- like 'withKillWorker').
withJoinedCloser :: B.BackendEnv OpenSSL4
  -> (MVar (Either SomeException ()) -> ThreadId -> IO b) -> IO b
withJoinedCloser env body = do
  closerDone <- newEmptyMVar
  let spawn = forkIOWithUnmask $ \unmask -> do
        r <- try (unmask (B.closeBackend env))
        putMVar closerDone r
      cleanup tid = uninterruptibleMask_ $ do
        killThread tid
        _ <- takeMVar closerDone
        pure ()
  bracket spawn cleanup (\tid -> body closerDone tid)

-- | Import vs close: a fresh reference or InvalidState. Registry
-- insertion takes the gate, so the outcome is typed either way;
-- wins are kept and must read drained after the race close (a
-- post-drain insertion would strand a live entry — the sequential
-- post-close refusal is pinned in OpenSSLSpec).
caseGateRaceImportClose :: IO ()
caseGateRaceImportClose = replicateM_ 15 $ withRealBackend $ \env -> do
  resVar <- newEmptyMVar
  raceWithCloseOn env $ do
    r <- B.importKey env (B.KeyBytes "import-race-key-material")
    putMVar resVar r
    case r of
      B.EngineOk _ -> pure ()
      B.EngineFail (B.BackendInvalidState _ _) -> pure ()
      other -> assertFailure ("import vs close must stay typed, got " ++ show other)
  rr <- takeMVar resVar
  case rr of
    B.EngineOk ref -> do
      s <- B.resourceSaveability env (B.keyRefId ref)
      case s of
        B.ResourceUnsaveable (B.UnsaveableGone _) -> pure ()
        other -> assertFailure ("won import must drain at close, got " ++ show other)
    B.EngineFail (B.BackendInvalidState _ _) -> pure ()
    other -> assertFailure ("import vs close must stay typed, got " ++ show other)

-- | Export vs close on a live reference: bytes or InvalidState.
caseGateRaceExportClose :: IO ()
caseGateRaceExportClose = replicateM_ 15 $ withRealBackend $ \env -> do
  ref <- expectGatedOk "import" =<< B.importKey env (B.KeyBytes "export-race-key-material")
  raceWithCloseOn env $ do
    r <- B.exportKey env ref
    case r of
      B.EngineOk _ -> pure ()
      B.EngineFail (B.BackendInvalidState _ _) -> pure ()
      other -> assertFailure ("export vs close must stay typed, got " ++ show other)

-- | Close waits for an admitted borrower: the parked one-shot holds
-- the gate (the park is inside the gated FFI call, so past
-- admission by construction), the closer provably blocks
-- ('awaitBlocked'), the release lets the op finish first with
-- correct bytes, and only then does the closer drain. The blocked
-- proof plus undisturbed bytes is the deterministic
-- close-waits-for-use ordering (no timing-hope).
caseGateCloseWaitsForBorrow :: CtrTag -> IO ()
caseGateCloseWaitsForBorrow ctr = withGate $ \g -> withRealBackend $ \env -> do
  c_gateArmCheckpoint g 2
  withKillWorker g (digestOneShotGated g env B.D_SHA256 "abc") $ \opDone _fire -> do
    awaitParked g
    withJoinedCloser env $ \closerDone closerTid -> do
      awaitMVarBlocked closerTid
      -- The gate is still held (no release yet), so the closer is
      -- still waiting: a finished close here would prove the drain
      -- ran without the gate.
      preRel <- tryTakeMVar closerDone
      case preRel of
        Nothing -> pure ()
        Just _ -> assertFailure "close finished before release (drain ran without the gate)"
      c_gateRelease g 0
      ro <- readMVar opDone :: IO (Either SomeException (B.EngineResult ByteString))
      case ro of
        Right (B.EngineOk bs) -> assertEqual "parked op bytes" sha256abc bs
        other -> assertFailure ("parked op must complete, got " ++ show other)
      rc <- readMVar closerDone :: IO (Either SomeException ())
      assertWorkerOk rc
      r <- B.digestOneShot env B.D_SHA256 "hello"
      case r of
        B.EngineFail (B.BackendInvalidState _ _) -> pure ()
        other -> assertFailure ("post-close one-shot must be InvalidState, got " ++ show other)
    assertOutstandingZero ctr g
    assertEnvCountersClean ctr
    assertDigestCountersClean ctr

-- | Close waits through the take-to-consume window: the final takes
-- the handle, then parks at its copy checkpoint holding the gate,
-- and the closer provably blocks; the release lets the final
-- deliver first (matching the pre-captured production digest),
-- then the closer drains. The consumed id reads InvalidState
-- after (the closed check precedes the registry lookup).
caseGateCloseWaitsForFinal :: CtrTag -> IO ()
caseGateCloseWaitsForFinal ctr = withGate $ \g -> withRealBackend $ \env -> do
  prod <- expectGatedOk "prod digest" =<< B.digestOneShot env B.D_SHA256 "hello"
  rid <- expectGatedOk "gated init" =<< digestInitGated g env B.D_SHA256
  expectGatedOk "update" =<< B.digestUpdate env rid "hello"
  c_gateArmCheckpoint g 2
  withKillWorker g (digestFinalGated g env rid) $ \opDone _fire -> do
    awaitParked g
    withJoinedCloser env $ \closerDone closerTid -> do
      awaitMVarBlocked closerTid
      -- The gate is still held (no release yet), so the closer is
      -- still waiting: a finished close here would prove the drain
      -- ran without the gate.
      preRel <- tryTakeMVar closerDone
      case preRel of
        Nothing -> pure ()
        Just _ -> assertFailure "close finished before release (drain ran without the gate)"
      c_gateRelease g 0
      ro <- readMVar opDone :: IO (Either SomeException (B.EngineResult ByteString))
      case ro of
        Right (B.EngineOk bs) -> assertEqual "final equals one-shot" prod bs
        other -> assertFailure ("parked final must complete, got " ++ show other)
      rc <- readMVar closerDone :: IO (Either SomeException ())
      assertWorkerOk rc
      r <- B.digestFinal env rid
      case r of
        B.EngineFail (B.BackendInvalidState _ _) -> pure ()
        other -> assertFailure ("post-close final must be InvalidState, got " ++ show other)
    assertOutstandingZero ctr g
    assertEnvCountersClean ctr
    assertDigestCountersClean ctr

-- | Interruption cleanup releases the gate: the parked one-shot is
-- killed (forked killer plus release, the 'withKillWorker'
-- protocol), the worker dies 'ThreadKilled', and the closer —
-- provably blocked — proceeds through the freed gate and drains.
caseGateCloseAfterInterrupt :: CtrTag -> IO ()
caseGateCloseAfterInterrupt ctr = withGate $ \g -> withRealBackend $ \env -> do
  c_gateArmCheckpoint g 2
  withKillWorker g (digestOneShotGated g env B.D_SHA256 "abc") $ \opDone fire -> do
    awaitParked g
    withJoinedCloser env $ \closerDone closerTid -> do
      awaitMVarBlocked closerTid
      -- The gate is still held (no release yet), so the closer is
      -- still waiting: a finished close here would prove the drain
      -- ran without the gate.
      preRel <- tryTakeMVar closerDone
      case preRel of
        Nothing -> pure ()
        Just _ -> assertFailure "close finished before release (drain ran without the gate)"
      fire
      c_gateRelease g 0
      ro <- readMVar opDone :: IO (Either SomeException (B.EngineResult ByteString))
      assertThreadKilled ro
      rc <- readMVar closerDone :: IO (Either SomeException ())
      assertWorkerOk rc
      r <- B.digestOneShot env B.D_SHA256 "hello"
      case r of
        B.EngineFail (B.BackendInvalidState _ _) -> pure ()
        other -> assertFailure ("post-close one-shot must be InvalidState, got " ++ show other)
    assertOutstandingZero ctr g
    assertEnvCountersClean ctr
    assertDigestCountersClean ctr

-- | Cancel while closing: a gated op parked in its checkpoint holds
-- the env gate, so the closer provably blocks on the gate (status
-- barrier via 'awaitBlocked', never timing-hope). Killing the
-- closer aborts the wait with the gate untouched — the victim dies
-- 'ThreadKilled', the parked op still completes after the release,
-- and close still functions (a lost gate would wedge here under
-- the outer 'guarded' timeout). Both workers bracket their
-- teardown ('withKillWorker' outside, 'withJoinedCloser' inside),
-- so every exit releases and joins both before the backend close
-- and the C gate free.
caseGateCancelWhileClosing :: CtrTag -> IO ()
caseGateCancelWhileClosing ctr = withGate $ \g -> withRealBackend $ \env -> do
  c_gateArmCheckpoint g 2
  withKillWorker g (digestOneShotGated g env B.D_SHA256 "abc") $ \opDone _fire -> do
    awaitParked g
    withJoinedCloser env $ \closerDone closerTid -> do
      awaitMVarBlocked closerTid
      -- The gate is still held (no release yet), so the closer is
      -- still waiting: a finished close here would prove the drain
      -- ran without the gate.
      preRel <- tryTakeMVar closerDone
      case preRel of
        Nothing -> pure ()
        Just _ -> assertFailure "close finished before release (drain ran without the gate)"
      killThread closerTid
      rc <- readMVar closerDone :: IO (Either SomeException ())
      assertThreadKilled rc
      c_gateRelease g 0
      ro <- readMVar opDone :: IO (Either SomeException (B.EngineResult ByteString))
      case ro of
        Right (B.EngineOk bs) -> assertEqual "parked op bytes" sha256abc bs
        other -> assertFailure ("parked op must complete, got " ++ show other)
      B.closeBackend env
      r <- B.digestOneShot env B.D_SHA256 "hello"
      case r of
        B.EngineFail (B.BackendInvalidState _ _) -> pure ()
        other -> assertFailure ("post-close one-shot must be InvalidState, got " ++ show other)
    assertOutstandingZero ctr g
    assertEnvCountersClean ctr
    assertDigestCountersClean ctr

-- ---------------------------------------------------------------------------
-- Handle registry
-- ---------------------------------------------------------------------------

-- | A worker-level async context: private job table, default rules,
-- production OpenSSL backend, empty live set, no detach state. Reads
-- no environment (unlike `haskokiAsyncOpen`), so these probes stay
-- race-free under the suite's parallel runner.
mkM3Ctx :: IO AsyncCtx
mkM3Ctx = do
  mTable <- tryNewAsyncTable 8
  table <- case mTable of
    Just t -> pure t
    Nothing -> assertFailure "table allocator refused"
  env <- newEnv defaultRules
  enableAsyncSession table sid1
  eBe <- B.openBackend "provider=default"
    :: IO (B.EngineResult (B.BackendEnv OpenSSL4))
  be <- case eBe of
    B.EngineOk b -> pure b
    B.EngineFail err -> assertFailure ("openssl open failed: " ++ show err)
  live <- newIORef Set.empty
  pure (AsyncCtx env be sid1 table live Nothing)

-- | The worker half of a cancel entry: resolve, then cancel and
-- retire. Mirrors `haskokiAsyncCancel` without the export boundary.
cancelMimic :: AsyncCtx -> StablePtr JobHandle -> IO ()
cancelMimic ctx h = do
  m <- resolveJobHandle ctx h
  case m of
    Nothing -> pure ()
    Just j -> do
      _ <- cancelJob (acTable ctx) j
      freeJobHandle ctx h

assertWorkerOk :: Either SomeException () -> IO ()
assertWorkerOk (Right ()) = pure ()
assertWorkerOk (Left e) = assertFailure ("worker failed: " ++ show e)

-- | Key codec contract: NULL decodes to nothing; small ids
-- roundtrip (including 0 and the 32-bit maximum); distinct salts
-- distinguish identical job ids; ids past the 32-bit codec expose
-- only their low 32 bits (the submission entries refuse those ids
-- before admission — see 'jobIdExhausted' — so truncation is
-- unreachable for admitted handles).
caseHandleKeyCodec :: IO ()
caseHandleKeyCodec = do
  let nullHandle = castPtrToStablePtr nullPtr :: StablePtr JobHandle
  assertEqual "null decodes nothing" Nothing (decodeJobHandle nullHandle)
  assertEqual "roundtrip zero"
    (Just (JobId 0)) (decodeJobHandle (encodeJobHandle 1 (JobId 0)))
  assertEqual "roundtrip max32"
    (Just (JobId 0xFFFFFFFF))
    (decodeJobHandle (encodeJobHandle 1 (JobId 0xFFFFFFFF)))
  assertBool "salts distinguish"
    (castStablePtrToPtr (encodeJobHandle 1 (JobId 0))
      /= castStablePtrToPtr (encodeJobHandle 3 (JobId 0)))
  assertEqual "high bits truncated"
    (Just (JobId 0))
    (decodeJobHandle (encodeJobHandle 1 (JobId 0x100000000)))

-- | Deterministic lookup-window reproduction (no threads): resolve
-- a live handle, retire it (the racing terminal path), then act on
-- the owned id exactly as an entry would after its own
-- resolution. Every post-retirement step is typed — the id is a
-- pure value, not a loan, so there is no freed-pointer access.
caseHandleRetireThenUse :: IO ()
caseHandleRetireThenUse = do
  ctx <- mkM3Ctx
  Right j0 <- startJob (acTable ctx) (signRequest sid1 1000000)
  h <- allocJobHandle ctx j0
  m <- resolveJobHandle ctx h
  assertEqual "live resolves" (Just j0) m
  freeJobHandle ctx h
  mStale <- resolveJobHandle ctx h
  assertEqual "retired resolves stale" Nothing mStale
  out <- cancelJob (acTable ctx) j0
  assertEqual "owned id still cancels" CancelOk out
  nLive <- asyncLiveHandles ctx
  assertEqual "no live handles" 0 nLive
  asyncCloseCtx ctx

-- | Deterministic close-window reproduction (no threads): resolve
-- a live handle, close the context around it, then resolve again
-- and act on the previously owned id. The drain retires and
-- cancels; the owned id reports its terminal state typed.
caseHandleResolveThenClose :: IO ()
caseHandleResolveThenClose = do
  ctx <- mkM3Ctx
  Right j0 <- startJob (acTable ctx) (signRequest sid1 1000000)
  h <- allocJobHandle ctx j0
  m <- resolveJobHandle ctx h
  assertEqual "live resolves" (Just j0) m
  asyncCloseCtx ctx
  mStale <- resolveJobHandle ctx h
  assertEqual "closed resolves stale" Nothing mStale
  out <- cancelJob (acTable ctx) j0
  case out of
    CancelAlready _ -> pure ()
    other -> assertFailure ("expected CancelAlready, got " ++ show other)
  nLive <- asyncLiveHandles ctx
  assertEqual "no live handles" 0 nLive

-- | Resolution racing retirement: four workers resolve one handle
-- while the owner cycles retirement and re-admission around them
-- (entered rendezvous first, then no further gates, so the
-- owner's registry operations genuinely overlap in-flight
-- resolutions under any fair schedule). Every outcome is typed —
-- the job id or stale — however the operations interleave. A
-- dereference-based resolver fails here (check-then-deref vs
-- freeing retire); the key lookup cannot dangle by construction.
caseHandleResolveRetire :: IO ()
caseHandleResolveRetire = do
  ctx <- mkM3Ctx
  Right j0 <- startJob (acTable ctx) (signRequest sid1 1000000)
  h <- allocJobHandle ctx j0
  entered <- replicateM 4 newEmptyMVar
  dones <- replicateM 4 newEmptyMVar
  let checkResolve = do
        m <- resolveJobHandle ctx h
        assertBool "resolve typed" (m == Just j0 || m == Nothing)
      worker enter done = forkIO $ do
        r <- try $ do
          putMVar enter ()
          replicateM_ 500 checkResolve
        putMVar done (r :: Either SomeException ())
  mapM_ (uncurry worker) (zip entered dones)
  mapM_ takeMVar entered
  replicateM_ 50 (freeJobHandle ctx h >> allocJobHandle ctx j0)
  freeJobHandle ctx h
  donesOut <- mapM takeMVar dones
  mapM_ assertWorkerOk donesOut
  mFinal <- resolveJobHandle ctx h
  assertEqual "retired handle stale" Nothing mFinal
  nLive <- asyncLiveHandles ctx
  assertEqual "no live handles" 0 nLive
  asyncCloseCtx ctx

-- | Admission storm: four workers admit\/resolve\/retire their own
-- jobs 200 times each over the shared live set. Every admitted
-- handle resolves immediately; the set drains to zero.
caseHandleAdmissionStorm :: IO ()
caseHandleAdmissionStorm = do
  ctx <- mkM3Ctx
  Right ja <- startJob (acTable ctx) (signRequest sid1 1000000)
  Right jb <- startJob (acTable ctx) (signRequest sid1 1000000)
  Right jc <- startJob (acTable ctx) (signRequest sid1 1000000)
  Right jd <- startJob (acTable ctx) (signRequest sid1 1000000)
  dones <- replicateM 4 newEmptyMVar
  let worker jid done = forkIO $ do
        r <- try $ replicateM_ 200 $ do
          h <- allocJobHandle ctx jid
          m <- resolveJobHandle ctx h
          assertEqual "admitted handle resolves" (Just jid) m
          freeJobHandle ctx h
        putMVar done (r :: Either SomeException ())
  mapM_ (uncurry worker) (zip [ja, jb, jc, jd] dones)
  donesOut <- mapM takeMVar dones
  mapM_ assertWorkerOk donesOut
  nLive <- asyncLiveHandles ctx
  assertEqual "storm drains to zero" 0 nLive
  asyncCloseCtx ctx

-- | Kill storm over admission: two workers admit\/resolve\/retire in
-- a loop while the owner fires 64 kills at them (entered
-- rendezvous first, so the victims are provably inside the loop
-- when the storm starts). Per-iteration 'try' catches mid-iteration
-- kills and continues, rethrowing anything else so assertion
-- failures stay loud; a kill between iterations aborts that worker
-- early (tolerated 'ThreadKilled'). Every recorded handle either
-- retired or still resolves to its own job — never to a wrong
-- job — and close drains everything to zero, including handles
-- orphaned between admission and recording (an expected kill
-- outcome, not corruption). Scheduling may strand kills after a
-- fast worker finishes, so assertions are prefix-tolerant; the
-- mask placement itself is review-verified.
caseHandleKillStorm :: IO ()
caseHandleKillStorm = do
  ctx <- mkM3Ctx
  Right ja <- startJob (acTable ctx) (signRequest sid1 1000000)
  Right jb <- startJob (acTable ctx) (signRequest sid1 1000000)
  recorded <- newIORef ([] :: [StablePtr JobHandle])
  entered <- replicateM 2 newEmptyMVar
  dones <- replicateM 2 newEmptyMVar
  let iter jid = do
        h <- allocJobHandle ctx jid
        atomicModifyIORef' recorded (\hs -> (h : hs, ()))
        m <- resolveJobHandle ctx h
        assertEqual "admitted handle resolves" (Just jid) m
        freeJobHandle ctx h
      -- forkFinally reports under its own mask, so no kill can
      -- land between the work finishing and the report: 'done' is
      -- always filled exactly once.
      spawn jid enter done = forkFinally
        (putMVar enter () >> replicateM_ 100 (catchIter (iter jid)))
        (putMVar done)
      catchIter body = do
        r <- try body :: IO (Either SomeException ())
        case r of
          Right () -> pure ()
          Left e -> case fromException e of
            Just ThreadKilled -> pure ()
            _ -> throwIO e
  tids <- mapM (\(jid, enter, done) -> spawn jid enter done)
    (zip3 [ja, jb] entered dones)
  mapM_ takeMVar entered
  mapM_ killThread (concat (replicate 32 tids))
  results <- mapM takeMVar dones
  mapM_ checkWorker results
  hs <- readIORef recorded
  mapM_ (checkRecorded ctx ja jb) hs
  asyncCloseCtx ctx
  nLive <- asyncLiveHandles ctx
  assertEqual "close drains storm" 0 nLive
  -- The storm never cancels jobs (handles only), so retired jobs
  -- may still be pending: cancel them explicitly before the census.
  _ <- cancelJob (acTable ctx) ja
  _ <- cancelJob (acTable ctx) jb
  (liveJobs, _, _) <- tableStats (acTable ctx)
  assertEqual "storm jobs cancel clean" 0 liveJobs
  where
    checkWorker (Right ()) = pure ()
    checkWorker (Left e) = case fromException e of
      Just ThreadKilled -> pure ()
      _ -> assertFailure ("worker failed: " ++ show e)
    checkRecorded c first second h = do
      m <- resolveJobHandle c h
      assertBool "recorded handle resolves to its own job or stale"
        (m == Just first || m == Just second || m == Nothing)

-- | Close-drain racing in-flight cancel\/resolve: four workers mimic
-- the cancel entry over four admitted handles while the owner
-- closes around them (entered rendezvous first, then no further
-- gates, so the drain genuinely overlaps in-flight worker
-- operations under any fair schedule). The no-inversion pin: the
-- registry path takes no locks and every job operation runs after
-- its resolution, so nothing here can wedge — termination under
-- the timeout guard IS the assertion, plus a zero census (no live
-- handles, no live jobs) afterwards. Workers never touch the
-- backend, so closing it mid-storm is safe for them.
caseHandleCloseRace :: IO ()
caseHandleCloseRace = do
  ctx <- mkM3Ctx
  Right j0 <- startJob (acTable ctx) (signRequest sid1 1000000)
  Right j1 <- startJob (acTable ctx) (signRequest sid1 1000000)
  Right j2 <- startJob (acTable ctx) (signRequest sid1 1000000)
  Right j3 <- startJob (acTable ctx) (signRequest sid1 1000000)
  handles <- mapM (allocJobHandle ctx) [j0, j1, j2, j3]
  entered <- replicateM 4 newEmptyMVar
  dones <- replicateM 4 newEmptyMVar
  let worker h enter done = forkIO $ do
        r <- try $ do
          putMVar enter ()
          replicateM_ 200 (cancelMimic ctx h)
        putMVar done (r :: Either SomeException ())
  mapM_ (\(h, enter, done) -> worker h enter done)
    (zip3 handles entered dones)
  mapM_ takeMVar entered
  asyncCloseCtx ctx
  donesOut <- mapM takeMVar dones
  mapM_ assertWorkerOk donesOut
  nLive <- asyncLiveHandles ctx
  assertEqual "no live handles" 0 nLive
  (liveJobs, _, _) <- tableStats (acTable ctx)
  assertEqual "no live jobs" 0 liveJobs

-- | Per-context authority: a handle admitted on one context stays
-- stale on another, while staying live on its own; bogus and null
-- tokens stay stale everywhere without touching anything. Both
-- contexts admit their own first job, so both tables hold the same
-- numeric job id under distinct exact salts: each handle must
-- resolve only on its own context, and the two admitted tokens
-- must differ despite the equal job ids (equal tokens here would
-- alias one context's job onto the other).
caseHandleForeignStale :: IO ()
caseHandleForeignStale = do
  ctxA <- mkM3Ctx
  ctxB <- mkM3Ctx
  assertBool "table identities distinct"
    (asyncTableId (acTable ctxA) /= asyncTableId (acTable ctxB))
  Right jA <- startJob (acTable ctxA) (signRequest sid1 1000000)
  Right jB <- startJob (acTable ctxB) (signRequest sid1 1000000)
  assertEqual "same numeric job id" jA jB
  hA <- allocJobHandle ctxA jA
  hB <- allocJobHandle ctxB jB
  assertBool "equal job ids admit distinct tokens"
    (castStablePtrToPtr hA /= castStablePtrToPtr hB)
  mAB <- resolveJobHandle ctxB hA
  assertEqual "A-handle stale on B" Nothing mAB
  mBA <- resolveJobHandle ctxA hB
  assertEqual "B-handle stale on A" Nothing mBA
  mA <- resolveJobHandle ctxA hA
  assertEqual "own handle live on A" (Just jA) mA
  mB <- resolveJobHandle ctxB hB
  assertEqual "own handle live on B" (Just jB) mB
  let bogus = castPtrToStablePtr (wordPtrToPtr 0xDEAD) :: StablePtr JobHandle
  mBogus <- resolveJobHandle ctxA bogus
  assertEqual "bogus handle stale" Nothing mBogus
  mNull <- resolveJobHandle ctxA (castPtrToStablePtr nullPtr)
  assertEqual "null handle stale" Nothing mNull
  nA <- asyncLiveHandles ctxA
  nB <- asyncLiveHandles ctxB
  assertEqual "A owns one handle" 1 nA
  assertEqual "B owns one handle" 1 nB
  asyncCloseCtx ctxA
  asyncCloseCtx ctxB

-- | Salt stability pin: re-admitting one job on one table yields
-- the identical token (the salt is stable per table), while a
-- second table admitting the same numeric job id yields a distinct
-- token by its distinct exact salt. Same-context resolution stays
-- live after re-admission.
caseHandleSaltStable :: IO ()
caseHandleSaltStable = do
  ctxA <- mkM3Ctx
  ctxB <- mkM3Ctx
  Right jA <- startJob (acTable ctxA) (signRequest sid1 1000000)
  Right jB <- startJob (acTable ctxB) (signRequest sid1 1000000)
  assertEqual "same numeric job id" jA jB
  hA1 <- allocJobHandle ctxA jA
  freeJobHandle ctxA hA1
  hA2 <- allocJobHandle ctxA jA
  assertEqual "re-admission is token-identical"
    (castStablePtrToPtr hA1) (castStablePtrToPtr hA2)
  hB <- allocJobHandle ctxB jB
  assertBool "second context admits a distinct token"
    (castStablePtrToPtr hB /= castStablePtrToPtr hA2)
  mA <- resolveJobHandle ctxA hA2
  assertEqual "own handle live on A" (Just jA) mA
  mB <- resolveJobHandle ctxB hB
  assertEqual "own handle live on B" (Just jB) mB
  mAB <- resolveJobHandle ctxB hA2
  assertEqual "A-handle stale on B" Nothing mAB
  asyncCloseCtx ctxA
  asyncCloseCtx ctxB

-- | Exact per-table salts: distinct tables carry distinct nonzero
-- salts, each stable for its table's life.
caseTableSaltExact :: IO ()
caseTableSaltExact = do
  t1 <- newAsyncTable 8
  t2 <- newAsyncTable 8
  let s1 = asyncTableSalt t1
      s2 = asyncTableSalt t2
  assertBool "salts nonzero" (s1 /= 0 && s2 /= 0)
  assertBool "distinct tables, distinct salts" (s1 /= s2)
  assertEqual "salt stable" s1 (asyncTableSalt t1)
  many <- mapM (const (newAsyncTable 8)) [1 .. 128 :: Int]
  let salts = map asyncTableSalt many
  assertBool "128 fresh tables, all salts nonzero" (all (/= 0) salts)
  assertEqual "128 fresh tables, 128 salts" 128 (Set.size (Set.fromList salts))

-- | Salt-mint boundary: the n-th table (0-based) salts n+1, so the
-- first table salts 1 (never zero) and the last admissible index
-- salts the 32-bit maximum; past 2^32-1 tables the mint refuses
-- ('Nothing') instead of wrapping or reusing a salt.
caseTableSaltBound :: IO ()
caseTableSaltBound = do
  assertEqual "first table salts 1" (Just 1) (tableSaltFor 0)
  assertEqual "second table salts 2" (Just 2) (tableSaltFor 1)
  assertEqual "last index salts maxBound" (Just maxBound) (tableSaltFor 0xFFFFFFFE)
  assertEqual "past 2^32-1 tables refuses" Nothing (tableSaltFor 0xFFFFFFFF)
  assertEqual "far past refuses" Nothing (tableSaltFor 0x100000000)
  assertEqual "negative refuses" Nothing (tableSaltFor (-1))

-- ---------------------------------------------------------------------------
-- Attachment-claim ownership
-- ---------------------------------------------------------------------------

-- | A hand-planned digest submit (no model planning): the detach
-- source. Rejoin replays the recipe against the real model, so
-- the world below still carries a digest-initialized session.
digestHandRequest :: SessionId -> Int -> JobRequest
digestHandRequest sid ticks = JobRequest
  { jrSession = sid
  , jrFunction = JobDigest
  , jrWork = WorkCall
      (Reservation "m5-claim-test" [] Nothing Nothing)
      (EffectCrypto (FxDigest (MechanismId 0x250) "abc"))
  , jrTicks = ticks
  , jrCapacity = 64
  }

-- | One model world for claim-ownership probes: a memory store
-- with the home token, one detach context, one initialized env
-- with a seated token and one digest-initialized session. Tables
-- stay with the caller — several tables share this world.
mkM5World :: IO (Store, DetachCtx, Env, SessionId)
mkM5World = do
  world <- newMemoryWorld
  eStore <- openMemoryStore world
  store <- case eStore of
    Right s -> pure s
    Left err -> assertFailure ("world open failed: " ++ show err)
  let tok = TokenRecord
        { trId = TokenId 1
        , trSlot = SlotId 0
        , trGeneration = Generation 0
        , trLabel = "m5-test"
        , trAuth = tokenAuthNew
        }
  res <- storeCommit store emptyDelta { sdPutTokens = [tok] }
  case res of
    Committed -> pure ()
    other -> assertFailure ("token seat failed: " ++ show other)
  eDc <- openDetached store (TokenId 1)
  dc <- case eDc of
    Right c -> pure c
    Left err -> assertFailure ("openDetached failed: " ++ show err)
  env <- newEnv defaultRules
  ini <- initialize env defaultInitArgs
  case ini of
    OutcomeOk () -> pure ()
    OutcomeErr c -> assertFailure ("init failed: " ++ show c)
  seatToken env (SlotId 0) >>= assertEqual "seat ok" (Right ())
  m0 <- snapshotModel env
  let sid = SessionId (mNextSession m0)
      openReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []
  case planCall defaultRules m0 openReq of
    Immediate pc -> do
      pr <- publish env (pcDelta pc)
      case pr of
        Right () -> pure ()
        Left f -> assertFailure ("open publish failed: " ++ show f)
    other -> assertFailure ("open did not plan immediate: " ++ show other)
  m2 <- snapshotModel env
  let initReq = Request Pkcs11_3_2 F_DigestInit (Just sid) Nothing
        (encodeInitInput (MechanismId 0x250) [] False "") []
  case planCall defaultRules m2 initReq of
    Execute res (EffectCrypto _) -> do
      m3 <- snapshotModel env
      case finishEffect defaultRules m3 res
          (EngineOkResource (EngineResourceId 51)) of
        Left rej -> assertFailure ("digest-init finish rejected: " ++ show rej)
        Right pc -> do
          pr <- publish env (pcDelta pc)
          case pr of
            Right () -> pure ()
            Left f -> assertFailure ("digest-init publish failed: " ++ show f)
    other -> assertFailure ("digest-init did not plan execute: " ++ show other)
  pure (store, dc, env, sid)

loadJobsM5 :: Store -> IO [JobRecord]
loadJobsM5 store = do
  eJobs <- storeLoadJobs store
  case eJobs of
    Right jobs -> pure jobs
    Left err -> assertFailure ("loadJobs failed: " ++ show err)

-- | Table identities are minted uniquely per table and stable
-- for the table's life.
caseTableIdUnique :: IO ()
caseTableIdUnique = do
  t1 <- newAsyncTable 8
  t2 <- newAsyncTable 8
  assertBool "distinct tables, distinct ids"
    (asyncTableId t1 /= asyncTableId t2)
  assertEqual "identity stable" (asyncTableId t1) (asyncTableId t1)
  many <- mapM (const (newAsyncTable 8)) [1 .. 128 :: Int]
  let ids = map asyncTableId many
  assertEqual "128 fresh tables, 128 identities" 128 (Set.size (Set.fromList ids))

-- | Scoped retirement is exact and idempotent: retiring A twice
-- reports A's attachment once and nothing the second time; the
-- durable records carry exactly one cancel each; B retires
-- separately with its own single entry.
caseScopedRetireExactlyOnce :: IO ()
caseScopedRetireExactlyOnce = do
  (store, dc, env, sid) <- mkM5World
  tableA <- newAsyncTable 8
  tableB <- newAsyncTable 8
  tableS <- newAsyncTable 8
  enableAsyncSession tableA sid
  enableAsyncSession tableB sid
  enableAsyncSession tableS sid
  let tidA = asyncTableId tableA
      tidB = asyncTableId tableB
  assertBool "table identities distinct" (tidA /= tidB)
  Right s0 <- startJob tableS (digestHandRequest sid 1)
  DetachOk pid1 <- detachJob dc tableS s0 JobDigest
  Right s1 <- startJob tableS (digestHandRequest sid 1)
  DetachOk pid2 <- detachJob dc tableS s1 JobDigest
  let joinOn table pid = joinJob dc env table JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = sid
        , jqCapacity = 64
        }
  JoinOk jA <- joinOn tableA pid1
  JoinOk jB <- joinOn tableB pid2
  revA <- inspectReverse dc tidA jA
  assertEqual "A reverse resolves" (Just pid1) revA
  revB <- inspectReverse dc tidB jB
  assertEqual "B reverse resolves" (Just pid2) revB
  rA1 <- retireLiveTableFor dc tidA
  assertEqual "A retires once" [(pid1, Nothing)] rA1
  rA2 <- retireLiveTableFor dc tidA
  assertEqual "A retire idempotent" [] rA2
  rB1 <- retireLiveTableFor dc tidB
  assertEqual "B retires separately" [(pid2, Nothing)] rB1
  jobs <- loadJobsM5 store
  let stateOf p = [jrState r | r <- jobs, jrPersistentId r == p]
  assertEqual "pid1 canceled" [JobCanceled] (stateOf pid1)
  assertEqual "pid2 canceled" [JobCanceled] (stateOf pid2)
  av1 <- inspectAttachment dc pid1
  assertEqual "pid1 terminal" (Just (AvTerminal JobCanceled)) av1
  av2 <- inspectAttachment dc pid2
  assertEqual "pid2 terminal" (Just (AvTerminal JobCanceled)) av2
  rNone <- retireLiveTable dc
  assertEqual "whole-context retire finds nothing left" [] rNone
  storeClose store

-- | A rival-table refusal disturbs nothing: the owner's cancel
-- still wins and resolves the durable record; the rival's table
-- holds no trace of the contested id.
caseRivalRefusalPreservesOwner :: IO ()
caseRivalRefusalPreservesOwner = do
  (store, dc, env, sid) <- mkM5World
  tableA <- newAsyncTable 8
  tableB <- newAsyncTable 8
  tableS <- newAsyncTable 8
  enableAsyncSession tableA sid
  enableAsyncSession tableB sid
  enableAsyncSession tableS sid
  Right s0 <- startJob tableS (digestHandRequest sid 1)
  DetachOk pid <- detachJob dc tableS s0 JobDigest
  let joinOn table = joinJob dc env table JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = sid
        , jqCapacity = 64
        }
  JoinOk jA <- joinOn tableA
  rival <- joinOn tableB
  assertEqual "rival refused" (JoinAlreadyAttached joinPolicyName) rival
  censusB <- tableStats tableB
  assertEqual "rival table untouched" (0, 0, 0) censusB
  (cout, cerr) <- cancelJoined dc tableA jA
  assertEqual "owner cancel wins" CancelOk cout
  assertEqual "owner mark clean" Nothing cerr
  again <- joinOn tableA
  assertEqual "canceled never rejoins" (JoinTerminal JobCanceled) again
  jobs <- loadJobsM5 store
  case [r | r <- jobs, jrPersistentId r == pid] of
    [rec] -> assertEqual "record canceled" JobCanceled (jrState rec)
    other -> assertFailure ("expected one record, got " ++ show other)
  storeClose store

-- ---------------------------------------------------------------------------
-- Session retirement accounting (enablement follows the model)
-- ---------------------------------------------------------------------------

-- | Open one Standard session on slot 0, returning its handle.
openStdSession :: StablePtr StdInstance -> Bool -> IO CULong
openStdSession ctx async = alloca $ \out -> do
  haskokiStdOpenSessionWithAsync ctx 0 0 (if async then 1 else 0) out
    >>= assertEqual "open session" (stdRvOf CKR_OK)
  peek out

-- | A C session handle as a model session id.
sidOf :: CULong -> SessionId
sidOf (CULong h) = SessionId (fromIntegral h)

-- | Live model sessions, in id order.
liveSessions :: StdInstance -> IO [SessionId]
liveSessions inst = Map.keys . mSessions <$> snapshotModel (siEnv inst)

-- | 'defaultConfig' with removable slots: presence tests need
-- control test commands enabled (the default seats fixed slots,
-- whose removal refuses 'PresenceFixedSlot').
removableConfig :: Config
removableConfig = defaultConfig
  { cfgControl = (cfgControl defaultConfig) { ccTestEnabled = True } }

-- | Open\/close churn plus token removal keep the enabled set equal
-- to the live async sessions: each close disables exactly the
-- retired session, and removal disables every session on the slot.
caseSessionRetirementAccounting :: IO ()
caseSessionRetirementAccounting =
  bracket (openStdInstance removableConfig) haskokiStdClose $ \ctx -> do
    assertBool "instance opened" (castStablePtrToPtr ctx /= nullPtr)
    inst <- deRefStablePtr ctx
    let table = siAsyncTable inst
    h1 <- openStdSession ctx True
    h2 <- openStdSession ctx False
    h3 <- openStdSession ctx True
    let s1 = sidOf h1
        s2 = sidOf h2
        s3 = sidOf h3
    liveSessions inst >>= assertEqual "three live sessions" [s1, s2, s3]
    enabledSessionCount table >>= assertEqual "two enabled" 2
    isAsyncSession table s1 >>= assertEqual "first async" True
    isAsyncSession table s2 >>= assertEqual "second sync" False
    isAsyncSession table s3 >>= assertEqual "third async" True
    -- Churn: closing the first async session disables exactly it.
    haskokiStdCloseSession ctx h1 >>= assertEqual "close ok" (stdRvOf CKR_OK)
    liveSessions inst >>= assertEqual "close retires one" [s2, s3]
    enabledSessionCount table >>= assertEqual "close disables one" 1
    isAsyncSession table s1 >>= assertEqual "retired reads sync" False
    isAsyncSession table s3 >>= assertEqual "survivor stays async" True
    -- Churn more: open and close another async session.
    h4 <- openStdSession ctx True
    enabledSessionCount table >>= assertEqual "reopen counts" 2
    haskokiStdCloseSession ctx h4 >>= assertEqual "close ok" (stdRvOf CKR_OK)
    enabledSessionCount table >>= assertEqual "second close disables" 1
    -- Token removal retires every remaining session and disables all.
    setStdTokenPresence inst (SlotId 0) False >>= assertEqual "removal retires"
      (Right (PresenceChanged 1, 0))
    liveSessions inst >>= assertEqual "no live sessions" []
    enabledSessionCount table >>= assertEqual "removal disables all" 0
    isAsyncSession table s3 >>= assertEqual "removed reads sync" False

-- | Failed closes and failed removals retire nothing: unknown
-- handles refuse, unknown slots refuse, a repeated removal is a
-- no-op, and a removal whose publish faults rolls back — the live
-- sessions and the enabled set are unchanged on every path. The
-- late fault is forced deterministically: a presence hook closes
-- one session at the model level between removal preparation and
-- publication, so the prepared delta no longer applies.
caseRetirementRollback :: IO ()
caseRetirementRollback = do
  bracket (openStdInstance removableConfig) haskokiStdClose $ \ctx -> do
    assertBool "instance opened" (castStablePtrToPtr ctx /= nullPtr)
    inst <- deRefStablePtr ctx
    let table = siAsyncTable inst
    h1 <- openStdSession ctx True
    h2 <- openStdSession ctx False
    let s1 = sidOf h1
        s2 = sidOf h2
    -- Failed close: an unknown handle refuses with nothing retired.
    haskokiStdCloseSession ctx 999999 >>= assertEqual "unknown close refuses"
      (stdRvOf CKR_SESSION_HANDLE_INVALID)
    liveSessions inst >>= assertEqual "failed close retires nothing" [s1, s2]
    enabledSessionCount table >>= assertEqual "failed close disables nothing" 1
    isAsyncSession table s1 >>= assertEqual "live session stays async" True
    -- Failed removal: an unknown slot refuses before any publish.
    setStdTokenPresence inst (SlotId 99) False >>= assertEqual "unknown slot refuses"
      (Left PresenceUnknownSlot)
    liveSessions inst >>= assertEqual "failed removal retires nothing" [s1, s2]
    enabledSessionCount table >>= assertEqual "failed removal disables nothing" 1
    -- Real removal retires everything; repeating it publishes
    -- nothing and disables nothing further.
    setStdTokenPresence inst (SlotId 0) False >>= assertEqual "removal retires"
      (Right (PresenceChanged 1, 0))
    liveSessions inst >>= assertEqual "removal retires all" []
    enabledSessionCount table >>= assertEqual "removal disables all" 0
    setStdTokenPresence inst (SlotId 0) False >>= assertEqual "repeat removal no-ops"
      (Right (PresenceUnchanged 1, 0))
    liveSessions inst >>= assertEqual "repeat retires nothing" []
    enabledSessionCount table >>= assertEqual "repeat disables nothing" 0
  -- Forced late fault: the hook retires one session behind the
  -- removal's back after preparation, so publication faults and
  -- the whole removal rolls back with enablement intact.
  envRef <- newIORef Nothing
  let hook RemovalPrepublication = do
        mEnv <- readIORef envRef
        case mEnv of
          Nothing -> pure ()
          Just env -> do
            m <- snapshotModel env
            case Map.keys (mSessions m) of
              sid : _ -> do
                r <- publish env (StateDelta [DeltaCloseSession sid])
                case r of
                  Right () -> pure ()
                  Left f -> assertFailure ("hook close faulted: " ++ show f)
              [] -> pure ()
      hook _ = pure ()
  eSlots <- newSlotEventsWith hook 0 2 [SlotDefinition (SlotId 0) True]
  slots <- case eSlots of
    Right s -> pure s
    Left err -> assertFailure ("slot events refused: " ++ show err)
  bracket (openStdInstanceWithSlots stdAcquisition removableConfig slots)
      haskokiStdClose $ \ctx -> do
    assertBool "instance opened" (castStablePtrToPtr ctx /= nullPtr)
    inst <- deRefStablePtr ctx
    writeIORef envRef (Just (siEnv inst))
    let table = siAsyncTable inst
    h1 <- openStdSession ctx True
    h2 <- openStdSession ctx True
    let s1 = sidOf h1
        s2 = sidOf h2
    enabledSessionCount table >>= assertEqual "two enabled" 2
    r <- setStdTokenPresence inst (SlotId 0) False
    case r of
      Left (PresenceModelFault _) -> pure ()
      other -> assertFailure ("expected publish rollback, got " ++ show other)
    liveSessions inst >>= assertEqual "rollback keeps the survivor" [s2]
    enabledSessionCount table >>= assertEqual "rollback disables nothing" 2
    isAsyncSession table s1 >>= assertEqual "hook-closed stays enabled" True
    isAsyncSession table s2 >>= assertEqual "survivor stays enabled" True
    -- The slot is still present: new sessions still open.
    h3 <- openStdSession ctx False
    liveSessions inst >>= assertEqual "slot still serves" [s2, sidOf h3]

-- ---------------------------------------------------------------------------
-- Lease waits (cancellation at the delivery lease)
-- ---------------------------------------------------------------------------

-- | A cancel issued while the drive holds the lease waits on it:
-- killing the waiter aborts the wait with 'ThreadKilled' and the
-- lease intact — the drive still publishes Ready and the job
-- still completes exactly once.
caseCancelWhileWaitingForLease :: IO ()
caseCancelWhileWaitingForLease = do
  (table, env) <- mkTable
  (writes, needed) <- newCapture
  let del = captureDelivery 64 writes needed
      golden = BS.pack [0x01, 0x00, 0x00, 0x00, 0x40] <> cannedSig
  entered <- newEmptyMVar
  release <- newEmptyMVar
  let gated _ = do
        putMVar entered ()
        takeMVar release
        pure (GotBytes cannedSig)
  Right j0 <- startJob table (signRequest sid1 1)
  polled <- newEmptyMVar
  _ <- forkIO (pollJob gated env table JobSign j0 >>= putMVar polled)
  takeMVar entered
  outcome <- newEmptyMVar
  waiter <- forkIO (try (cancelJob table j0) >>= putMVar outcome)
  -- Prove the waiter reached the lease before killing it: it is
  -- blocked on the delivery MVar (past 'try', inside the wait),
  -- so the kill deterministically aborts the wait.
  awaitMVarBlocked waiter
  killThread waiter
  r <- takeMVar outcome
  case r of
    Left e -> case fromException e of
      Just ThreadKilled -> pure ()
      _ -> assertFailure ("waiter must die ThreadKilled, got " ++ show e)
    Right _ -> assertFailure "killed waiter must not report an outcome"
  -- The lease survived: the drive publishes and the job delivers.
  putMVar release ()
  takeMVar polled >>= assertEqual "drive publishes ready" PollReady
  c <- completeJob env table JobSign j0 del (\_ -> pure ())
  case c of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "delivered bytes" cannedSig bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  readIORef writes >>= assertEqual "exactly one write" [golden]
  readIORef needed >>= assertEqual "no sizing reports" []
  stFinal <- inspectJob table j0
  assertEqual "epoch: hold + deliver" (Just 2) (fmap jvEpoch stFinal)
