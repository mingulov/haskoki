{- | Detached jobs: GetID (detach) + Join (rejoin) over the
attached table and the durable store.

The detach lease ('beginDetach' / 'commitDetachRevoke' /
'abortDetach'), GetID durability-before-success plus
revocation-before-success, and failure-preserves-attachment.
-}
{-# LANGUAGE OverloadedStrings #-}
module DetachedSpec (spec) where

import Control.Concurrent
  ( MVar
  , forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  )
import Control.Exception (AsyncException (..), SomeException, fromException, try)
import Control.Monad (forM_)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.IORef (IORef, newIORef, modifyIORef', readIORef, writeIORef)
import Data.List (nub, sort)
import Data.Word (Word64)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import OwnershipCounters (assertZero, counted)
import Haskoki.Operation (CryptoEffect (..), CryptoResult (..))
import Haskoki.Model (Model (..), SessionState (..), lookupSession, lookupTokenAuth)
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Outcome
  ( DeltaOp (..)
  , EffectRequest (..)
  , EngineResult (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , StateDelta (..)
  )
import Haskoki.Output (maxOutputBytes)
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
  , PollOutcome (..)
  , StartDeny (..)
  , TerminalState (..)
  , abortDetach
  , asyncTableId
  , beginDetach
  , cancelJob
  , commitDetachRevoke
  , enableAsyncSession
  , isAsyncSession
  , leaseSnapshot
  , jobSnapshotFunction
  , jobSnapshotTicks
  , newAsyncTable
  , pollJob
  , startJob
  , startSeededJob
  , tableStats
  )
import Haskoki.Runtime.Detached
  ( AttachmentView (..)
  , DetachCtx
  , DetachOutcome (..)
  , JoinOutcome (..)
  , JoinRequest (..)
  , JoinedComplete (..)
  , cancelJoined
  , completeJoined
  , detachCode
  , detachJob
  , detachStats
  , inspectAttachment
  , inspectReverse
  , joinJob
  , joinPolicyName
  , markJobOpaque
  , openDetached
  , retireLiveTable
  , retireLiveTableFor
  , setJoinTestHook
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
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , FaultPoint (..)
  , JobBody (..)
  , JobExecState (..)
  , JobRecord (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , StoreStats (..)
  , TokenRecord (..)
  , defaultLimits
  , emptyDelta
  , encodeHexWord64
  , jobIdCounterKey
  , scriptedFaults
  )
import Haskoki.Runtime.Storage.Memory
  ( MemoryWorld
  , newMemoryWorld
  , openMemoryStore
  , openMemoryStoreWith
  )
import Haskoki.Session
  ( ActiveLogin (..)
  , SessionLogin (..)
  , TokenAuth (..)
  , tokenAuthNew
  )
import Haskoki.Transition (finishEffect, planCall)
import Haskoki.Types
  ( EngineResourceId (..)
  , Generation (..)
  , JobId (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

spec :: TestTree
spec = testGroup "Detached jobs"
  [ testCase "FIRST: detach pending digest is durable and revoked" (counted "m5-detached-jobs" "first-detach-pending-digest-is-durable-and-revoked" (caseFirstDetach))
  , testCase "detach lease abort preserves the live job" (counted "m5-detached-jobs" "detach-lease-abort-preserves-the-live-job" (caseLeaseAbort))
  , testCase "detach lease revoke removes exactly one job" (counted "m5-detached-jobs" "detach-lease-revoke-removes-exactly-one-job" (caseLeaseRevoke))
  , testCase "detach refusals preserve state" (counted "m5-detached-jobs" "detach-refusals-preserve-state" (caseDetachRefusals))
  , testCase "detach store failure preserves the live attachment" (counted "m5-detached-jobs" "detach-store-failure-preserves-the-live-attachment" (caseDetachStoreFailure))
  , testCase "seeded start validates like start" (counted "m5-detached-jobs" "seeded-start-validates-like-start" (caseSeededValidates))
  , testCase "rejoin delivers exactly once after restart" (counted "m5-detached-jobs" "rejoin-delivers-exactly-once-after-restart" (caseRejoinHappy))
  , testCase "detach ready: join delivers without re-running" (counted "m5-detached-jobs" "detach-ready-join-delivers-without-re-running" (caseRejoinReady))
  , testCase "wrong-function join rejected; job intact" (counted "m5-detached-jobs" "wrong-function-join-rejected-job-intact" (caseJoinWrongFunction))
  , testCase "undersized join leaves the durable job intact" (counted "m5-detached-jobs" "undersized-join-leaves-the-durable-job-intact" (caseJoinShort))
  , testCase "HASKOKI-JOIN-FIRST-WINS: competing join refused" (counted "m5-detached-jobs" "haskoki-join-first-wins-competing-join-refused" (caseJoinFirstWins))
  , testCase "delivered jobs never rejoin" (counted "m5-detached-jobs" "delivered-jobs-never-rejoin" (caseJoinAfterDelivered))
  , testCase "canceled joins stay canceled" (counted "m5-detached-jobs" "canceled-joins-stay-canceled" (caseJoinAfterCancel))
  , testCase "token reset kills old ids" (counted "m5-detached-jobs" "token-reset-kills-old-ids" (caseJoinStaleGeneration))
  , testCase "unknown recipe version rejected" (counted "m5-detached-jobs" "unknown-recipe-version-rejected" (caseJoinUnknownVersion))
  , testCase "join validates session and capacity" (counted "m5-detached-jobs" "join-validates-session-and-capacity" (caseJoinSessionCapacity))
  , testCase "join requires a matching initialized session" (counted "m5-detached-jobs" "join-requires-a-matching-initialized-session" (caseJoinIncompatible))
  , testCase "auth: logged-in token rejects a public join" (counted "m5-detached-jobs" "auth-logged-in-token-rejects-a-public-join" (caseJoinAuthRequired))
  , testCase "opaque native work is unsaveable; attachment kept" (counted "m5-detached-jobs" "opaque-native-work-is-unsaveable-attachment-kept" (caseOpaqueUnsaveable))
  , testCase "retireLiveTable cancels active attachments" (counted "m5-detached-jobs" "retirelivetable-cancels-active-attachments" (caseRetireCancels))
  , testCase "ambiguous commit reconciles present: durable wins" (counted "m5-detached-jobs" "ambiguous-commit-reconciles-present-durable-wins" (caseAmbiguousPresent))
  , testCase "ambiguous insertion reconciles present at the detach layer" (counted "m5-detached-jobs" "ambiguous-insertion-reconciles-present-at-the-detach-layer" (caseAmbiguousInsertPresent))
  , testCase "ambiguous commit reconciles absent: kept live" (counted "m5-detached-jobs" "ambiguous-commit-reconciles-absent-kept-live" (caseAmbiguousAbsent))
  , testCase "simultaneous two-session joins admit exactly one" (counted "m5-detached-jobs" "simultaneous-two-session-joins-admit-exactly-one" (caseJoinRaceTwoSessions))
  , testCase "colliding job zero resolves per table" (counted "m5-detached-jobs" "colliding-job-zero-resolves-per-table" (caseJoinRaceTwoTables))
  , testCase "scoped retire closes one table, keeps the other" (counted "m5-detached-jobs" "scoped-retire-closes-one-table-keeps-the-other" (caseRetireScopedKeepsOther))
  , testCase "start refusal rolls the claim back" (counted "m5-detached-jobs" "start-refusal-rolls-the-claim-back" (caseJoinStartRefusalRollsBack))
  , testCase "interruption after start retires the fresh job" (counted "m5-detached-jobs" "interruption-after-start-retires-the-fresh-job" (caseJoinInterruptionRollsBack))
  , testCase "two contexts on one store mint distinct ids" (counted "m5-detached-jobs" "two-contexts-on-one-store-mint-distinct-ids" (caseTwoContextsDistinctIds))
  , testCase "two tokens share the store-wide counter" (counted "m5-detached-jobs" "two-tokens-share-the-store-wide-counter" (caseTwoTokensStoreWideCounter))
  , testCase "stale pre-reset id never names new work" (counted "m5-detached-jobs" "stale-pre-reset-id-never-names-new-work" (caseStaleIdNeverReused))
  , testCase "failed insertion burns its id, never reuses it" (counted "m5-detached-jobs" "failed-insertion-burns-its-id-never-reuses-it" (caseFailedInsertBurnsId))
  , testCase "token mismatch refuses before replan" (counted "m5-detached-jobs" "token-mismatch-refuses-before-replan" (caseTokenMismatchBeforeReplan))
  , testCase "retire rolls a racing claim back; the join cannot commit" (counted "m5-detached-jobs" "retire-rolls-a-racing-claim-back-the-join-cannot-commit" (caseRetireRollsBackClaim))
  , testCase "retired table refuses a late claim; siblings keep joining" (counted "m5-detached-jobs" "retired-table-refuses-a-late-claim-siblings-keep-joining" (caseRetiredTableRefusesLateClaim))
  , testCase "two contexts: second join of a queued id is refused" (counted "m5-detached-jobs" "two-contexts-second-join-of-a-queued-id-is-refused" (caseTwoContextsQueuedRefused))
  , testCase "two contexts: second join of a ready id is refused" (counted "m5-detached-jobs" "two-contexts-second-join-of-a-ready-id-is-refused" (caseTwoContextsReadyRefused))
  , testCase "two contexts: a parked transfer refuses the other context" (counted "m5-detached-jobs" "two-contexts-a-parked-transfer-refuses-the-other-context" (caseTwoContextsParkedTransfer))
  , testCase "two contexts: simultaneous joins admit exactly one" (counted "m5-detached-jobs" "two-contexts-simultaneous-joins-admit-exactly-one" (caseTwoContextsJoinRace))
  , testCase "loser cannot retire or cancel the winner" (counted "m5-detached-jobs" "loser-cannot-retire-or-cancel-the-winner" (caseLoserCannotRetireOrCancel))
  ]

tokHome :: TokenId
tokHome = TokenId 1

slotHome :: SlotId
slotHome = SlotId 0

sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

cannedDigest :: ByteString
cannedDigest = BS.replicate 32 0xD1

countingRunner :: IORef Int -> CryptoEffect -> IO CryptoResult
countingRunner ref _fx = do
  modifyIORef' ref (+ 1)
  pure (GotBytes cannedDigest)

-- | A live provider generation: initialized env, seated token, one open
-- session with digest initialized, one async-enabled table.
data LiveGen = LiveGen
  { lgEnv :: !Env
  , lgTable :: !AsyncTable
  , lgSession :: !SessionState
  }

openLiveGen :: IO LiveGen
openLiveGen = openLiveGenCap 8

openLiveGenCap :: Int -> IO LiveGen
openLiveGenCap cap = do
  env <- newEnv defaultRules
  ini <- initialize env defaultInitArgs
  case ini of
    OutcomeOk () -> pure ()
    OutcomeErr c -> assertFailure ("init failed: " ++ show c)
  seatToken env slotHome >>= assertEqual "seat ok" (Right ())
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
  m1 <- snapshotModel env
  st <- case lookupSession m1 sid of
    Just s -> pure s
    Nothing -> assertFailure "seed session missing"
  let initReq = Request Pkcs11_3_2 F_DigestInit (Just sid) Nothing
        (encodeInitInput sha256Mech [] False BS.empty) []
  m2 <- snapshotModel env
  case planCall defaultRules m2 initReq of
    Execute res (EffectCrypto _) -> do
      m3 <- snapshotModel env
      case finishEffect defaultRules m3 res
          (EngineOkResource (EngineResourceId 21)) of
        Left rej -> assertFailure ("digest-init finish rejected: " ++ show rej)
        Right pc -> do
          pr <- publish env (pcDelta pc)
          case pr of
            Right () -> pure ()
            Left f -> assertFailure ("digest-init publish failed: " ++ show f)
    other -> assertFailure ("digest-init did not plan execute: " ++ show other)
  table <- newAsyncTable cap
  enableAsyncSession table sid
  isAsync <- isAsyncSession table sid
  assertEqual "session async-enabled" True isAsync
  pure LiveGen { lgEnv = env, lgTable = table, lgSession = st }

-- | Start a real planned digest job (the recipe source for detach).
startDigestJob :: LiveGen -> ByteString -> Word64 -> Int -> IO JobId
startDigestJob gen input cap ticks = do
  m <- snapshotModel (lgEnv gen)
  let sid = ssId (lgSession gen)
      req = Request Pkcs11_3_2 F_Digest (Just sid) Nothing input
        [RegionBytes "async" (IntentBuffer maxOutputBytes)]
  case planCall defaultRules m req of
    Execute res eff -> do
      let jr = JobRequest
            { jrSession = sid
            , jrFunction = JobDigest
            , jrWork = WorkCall res eff
            , jrTicks = ticks
            , jrCapacity = cap
            }
      started <- startJob (lgTable gen) jr
      case started of
        Right jid -> pure jid
        Left deny -> assertFailure ("digest start denied: " ++ show deny)
    other -> assertFailure ("digest did not plan execute: " ++ show other)

-- | A memory world with the home token record seated (generation 0).
mkWorld :: IO (MemoryWorld, Store)
mkWorld = do
  world <- newMemoryWorld
  eStore <- openMemoryStore world
  store <- case eStore of
    Right s -> pure s
    Left err -> assertFailure ("world open failed: " ++ show err)
  let tok = TokenRecord
        { trId = tokHome
        , trSlot = slotHome
        , trGeneration = Generation 0
        , trLabel = "detach-test"
        , trAuth = tokenAuthNew
        }
  res <- storeCommit store emptyDelta { sdPutTokens = [tok] }
  case res of
    Committed -> pure (world, store)
    other -> assertFailure ("token seat failed: " ++ show other)

mkDetached :: Store -> IO DetachCtx
mkDetached store = do
  eDc <- openDetached store tokHome
  case eDc of
    Right dc -> pure dc
    Left err -> assertFailure ("openDetached failed: " ++ show err)

loadJobs :: Store -> IO [JobRecord]
loadJobs store = do
  eJobs <- storeLoadJobs store
  case eJobs of
    Right jobs -> pure jobs
    Left err -> assertFailure ("loadJobs failed: " ++ show err)

-- | Open a second session on a live generation's env, digest-
-- initialized (so it can replay digest recipes) and async-enabled
-- on the generation's table. Returns the fresh session state.
openSecondSession :: LiveGen -> IO SessionState
openSecondSession gen = do
  m <- snapshotModel (lgEnv gen)
  let sid = SessionId (mNextSession m)
      openReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []
  case planCall defaultRules m openReq of
    Immediate pc -> do
      pr <- publish (lgEnv gen) (pcDelta pc)
      case pr of
        Right () -> pure ()
        Left f -> assertFailure ("second open publish failed: " ++ show f)
    other -> assertFailure ("second open did not plan immediate: " ++ show other)
  m2 <- snapshotModel (lgEnv gen)
  st <- case lookupSession m2 sid of
    Just s -> pure s
    Nothing -> assertFailure "second session missing"
  let initReq = Request Pkcs11_3_2 F_DigestInit (Just sid) Nothing
        (encodeInitInput sha256Mech [] False BS.empty) []
  m3 <- snapshotModel (lgEnv gen)
  case planCall defaultRules m3 initReq of
    Execute res (EffectCrypto _) -> do
      m4 <- snapshotModel (lgEnv gen)
      case finishEffect defaultRules m4 res
          (EngineOkResource (EngineResourceId 22)) of
        Left rej -> assertFailure ("second digest-init finish rejected: " ++ show rej)
        Right pc -> do
          pr <- publish (lgEnv gen) (pcDelta pc)
          case pr of
            Right () -> pure ()
            Left f -> assertFailure ("second digest-init publish failed: " ++ show f)
    other -> assertFailure ("second digest-init did not plan execute: " ++ show other)
  enableAsyncSession (lgTable gen) sid
  pure st

-- | No-wedge join for race workers: a lock inversion would hang the
-- take, so the 10s backstop fails loudly instead of wedging the suite.
joinBounded :: String -> MVar a -> IO a
joinBounded name mv = do
  r <- timeout 10000000 (takeMVar mv)
  case r of
    Nothing -> assertFailure ("wedged (>10s): " ++ name)
    Just v -> pure v

-- | Simultaneous-join rounds: the exactly-one-winner property
-- holds on every round under every interleaving (the atomic
-- claim decides), so the loop exercises overlap rather than
-- betting on it.
nJoinRaceRounds :: Int
nJoinRaceRounds = 50

-- FIRST TEST: GetID on a pending job. The persistent id is returned
-- only after the record is durable AND the old native binding is
-- revoked: the old job id goes unknown and the store holds exactly
-- one queued pointer-free recipe record.
caseFirstDetach :: IO ()
caseFirstDetach = do
  (world, store) <- mkWorld
  _ <- pure world
  gen <- openLiveGen
  dc <- mkDetached store
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 2
  out <- detachJob dc (lgTable gen) j0 JobDigest
  pid <- case out of
    DetachOk p -> pure p
    other -> assertFailure ("expected DetachOk, got " ++ show other)
  assertEqual "first persistent id" 1 pid
  -- Old binding revoked: the live table no longer knows the job.
  p <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest j0
  assertEqual "old job revoked" PollUnknown p
  nRuns <- readIORef runs
  assertEqual "detach runs no engine work" 0 nRuns
  -- Durable record: exactly one queued recipe, no result bytes yet.
  jobs <- loadJobs store
  rec <- case jobs of
    [r] -> pure r
    other -> assertFailure ("expected one durable job, got " ++ show (length other))
  assertEqual "record pid" pid (jrPersistentId rec)
  assertEqual "record token" tokHome (jrToken rec)
  assertEqual "record generation" (Generation 0) (jrTokenGeneration rec)
  assertEqual "record state" JobQueued (jrState rec)
  case jrBody rec of
    JobPending name params -> do
      assertEqual "call recipe name" "haskoki-call/v1" name
      assertBool "recipe carries params" (not (BS.null params))
    JobResult {} -> assertFailure "pending detach must store a recipe"
  -- Attachment registry: detached, awaiting join.
  av <- inspectAttachment dc pid
  assertEqual "attachment idle" (Just AvIdle) av
  storeClose store

assertBool :: String -> Bool -> IO ()
assertBool _ True = pure ()
assertBool msg False = assertFailure msg

caseLeaseAbort :: IO ()
caseLeaseAbort = do
  gen <- openLiveGen
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 2
  mLease <- beginDetach (lgTable gen) j0
  lease <- case mLease of
    Just l -> pure l
    Nothing -> assertFailure "beginDetach missed a live job"
  let snap = leaseSnapshot lease
  assertEqual "snapshot function" JobDigest (jobSnapshotFunction snap)
  assertEqual "snapshot ticks" (Just 2) (jobSnapshotTicks snap)
  abortDetach lease
  -- Aborted lease: the job is untouched and still schedulable.
  p1 <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest j0
  assertEqual "poll after abort" (PollPending 1) p1

caseLeaseRevoke :: IO ()
caseLeaseRevoke = do
  gen <- openLiveGen
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 2
  j1 <- startDigestJob gen "def" 32 2
  mLease <- beginDetach (lgTable gen) j0
  case mLease of
    Just lease -> commitDetachRevoke lease
    Nothing -> assertFailure "beginDetach missed a live job"
  p0 <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest j0
  assertEqual "revoked job unknown" PollUnknown p0
  p1 <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest j1
  assertEqual "sibling job intact" (PollPending 1) p1
  -- Revoke is one-shot: the lease is spent, the job is gone.
  mAgain <- beginDetach (lgTable gen) j0
  case mAgain of
    Nothing -> pure ()
    Just _ -> assertFailure "revoked job still leasable"

caseDetachRefusals :: IO ()
caseDetachRefusals = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  dc <- mkDetached store
  runs <- newIORef 0
  let run = countingRunner runs
  j0 <- startDigestJob gen "abc" 32 2
  -- Unknown job.
  u <- detachJob dc (lgTable gen) (JobId 77) JobDigest
  assertEqual "detach unknown" DetachUnknown u
  -- Wrong function: refused, job intact.
  w <- detachJob dc (lgTable gen) j0 JobSign
  assertEqual "detach wrong function"
    (DetachWrongFunction JobDigest JobSign) w
  p <- pollJob run (lgEnv gen) (lgTable gen) JobDigest j0
  assertEqual "job intact after wrong-function detach" (PollPending 1) p
  -- Terminal job: refused with the winner's state.
  j1 <- startDigestJob gen "abc" 32 5
  _ <- cancelJob (lgTable gen) j1
  t <- detachJob dc (lgTable gen) j1 JobDigest
  assertEqual "detach canceled" (DetachAlready TermCanceled) t
  -- Correct detach still works after the refusals.
  ok <- detachJob dc (lgTable gen) j0 JobDigest
  case ok of
    DetachOk _ -> pure ()
    other -> assertFailure ("expected DetachOk, got " ++ show other)
  storeClose store

-- Detach failure (a faulted durable commit — the scripted fault
-- lands on the reservation, the first of the two commits)
-- preserves the old live attachment: the job still polls, no
-- record is stored, and the failed reservation burns no id.
caseDetachStoreFailure :: IO ()
caseDetachStoreFailure = do
  world <- newMemoryWorld
  eClean <- openMemoryStore world
  clean <- case eClean of
    Right s -> pure s
    Left err -> assertFailure ("clean open failed: " ++ show err)
  let tok = TokenRecord
        { trId = tokHome
        , trSlot = slotHome
        , trGeneration = Generation 0
        , trLabel = "detach-test"
        , trAuth = tokenAuthNew
        }
  res <- storeCommit clean emptyDelta { sdPutTokens = [tok] }
  case res of
    Committed -> pure ()
    other -> assertFailure ("token seat failed: " ++ show other)
  storeClose clean
  inj <- scriptedFaults [FaultBeforeCommit]
  eFaulty <- openMemoryStoreWith world defaultLimits inj
  faulty <- case eFaulty of
    Right s -> pure s
    Left err -> assertFailure ("faulty open failed: " ++ show err)
  gen <- openLiveGen
  dc <- mkDetached faulty
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 2
  out <- detachJob dc (lgTable gen) j0 JobDigest
  case out of
    DetachStore _ -> pure ()
    other -> assertFailure ("expected DetachStore, got " ++ show other)
  p <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest j0
  assertEqual "live job preserved" (PollPending 1) p
  jobs <- loadJobs faulty
  assertEqual "no durable record on failure" 0 (length jobs)
  ePid <- storeReserveJobId faulty
  assertEqual "failed reservation burns nothing" (Right 1) ePid
  storeClose faulty

-- | Reopen a memory world: close the old handle, open a fresh one
-- over the same durable state (the in-process restart).
reopenWorld :: MemoryWorld -> Store -> IO Store
reopenWorld world old = do
  storeClose old
  eStore <- openMemoryStore world
  case eStore of
    Right s -> pure s
    Left err -> assertFailure ("world reopen failed: " ++ show err)

-- | Captured delivery writes.
newCapture :: IO (Delivery, IORef [ByteString])
newCapture = do
  ref <- newIORef []
  pure (Delivery
    { dCapacity = 32
    , dWrite = \bs -> modifyIORef' ref (++ [bs])
    , dReportNeeded = \_ -> pure ()
    }, ref)

-- Detach pending, restart the world, rejoin on a fresh provider
-- generation, and deliver exactly once. The attach is recorded
-- before completion can use the new binding.
caseRejoinHappy :: IO ()
caseRejoinHappy = do
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  dcA <- mkDetached storeA
  _ <- pure dcA
  runs <- newIORef 0
  let run = countingRunner runs
  j0 <- startDigestJob genA "abc" 32 2
  DetachOk pid <- detachJob dcA (lgTable genA) j0 JobDigest
  -- Restart: new store handle, new provider generation, same world.
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  dcB <- mkDetached storeB
  let sidB = ssId (lgSession genB)
      req = JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = sidB
        , jqCapacity = 32
        }
  out <- joinJob dcB (lgEnv genB) (lgTable genB) req
  jid <- case out of
    JoinOk j -> pure j
    other -> assertFailure ("expected JoinOk, got " ++ show other)
  av <- inspectAttachment dcB pid
  assertEqual "attach recorded before completion" (Just (AvActive jid)) av
  -- The rejoined job drives its replayed recipe exactly once.
  p1 <- pollJob run (lgEnv genB) (lgTable genB) JobDigest jid
  assertEqual "rejoin poll 1 pending" (PollPending 1) p1
  p2 <- pollJob run (lgEnv genB) (lgTable genB) JobDigest jid
  assertEqual "rejoin poll 2 ready" PollReady p2
  (del, writes) <- newCapture
  jc <- completeJoined dcB (lgEnv genB) (lgTable genB) JobDigest jid del (\_ -> pure ())
  assertEqual "durable mark clean" Nothing (jcMarkError jc)
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "delivered replay bytes" cannedDigest bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "exactly one write" 1 (length got)
  nRuns <- readIORef runs
  assertEqual "effect ran once across detach+rejoin" 1 nRuns
  -- Durable record resolved delivered; attachment terminal.
  jobs <- loadJobs storeB
  case [r | r <- jobs, jrPersistentId r == pid] of
    [rec] -> assertEqual "record delivered" JobDelivered (jrState rec)
    other -> assertFailure ("expected one record, got " ++ show other)
  avFinal <- inspectAttachment dcB pid
  assertEqual "attachment terminal" (Just (AvTerminal JobDelivered)) avFinal
  storeClose storeB

-- A ready detach stores the prepared result; the rejoin seeds it and
-- delivers WITHOUT polling or re-running the effect.
caseRejoinReady :: IO ()
caseRejoinReady = do
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  dcA <- mkDetached storeA
  runs <- newIORef 0
  let run = countingRunner runs
  j0 <- startDigestJob genA "abc" 32 1
  p <- pollJob run (lgEnv genA) (lgTable genA) JobDigest j0
  assertEqual "drive ready" PollReady p
  DetachOk pid <- detachJob dcA (lgTable genA) j0 JobDigest
  jobsA <- loadJobs storeA
  case [r | r <- jobsA, jrPersistentId r == pid] of
    [rec] -> do
      assertEqual "record ready" JobReady (jrState rec)
      case jrBody rec of
        JobResult code bs -> do
          assertEqual "result code" CKR_OK code
          -- Framed recipe + result (byte-exactness is proven by the
          -- seeded delivery below, not by frame internals).
          assertBool "result body framed" (not (BS.null bs))
        JobPending {} -> assertFailure "ready detach must store a result"
    other -> assertFailure ("expected one record, got " ++ show other)
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  dcB <- mkDetached storeB
  let req = JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = ssId (lgSession genB)
        , jqCapacity = 32
        }
  JoinOk jid <- joinJob dcB (lgEnv genB) (lgTable genB) req
  (del, writes) <- newCapture
  jc <- completeJoined dcB (lgEnv genB) (lgTable genB) JobDigest jid del (\_ -> pure ())
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "seeded bytes delivered" cannedDigest bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "exactly one write" 1 (length got)
  nRuns <- readIORef runs
  assertEqual "effect never re-ran" 1 nRuns
  storeClose storeB

-- Wrong-function join is rejected with the durable job intact: the
-- correct function still joins afterwards.
caseJoinWrongFunction :: IO ()
caseJoinWrongFunction = do
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  dcA <- mkDetached storeA
  j0 <- startDigestJob genA "abc" 32 1
  DetachOk pid <- detachJob dcA (lgTable genA) j0 JobDigest
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  dcB <- mkDetached storeB
  let sidB = ssId (lgSession genB)
  bad <- joinJob dcB (lgEnv genB) (lgTable genB) JoinRequest
    { jqPid = pid
    , jqFunction = JobSign
    , jqSession = sidB
    , jqCapacity = 32
    }
  assertEqual "wrong-function join refused"
    (JoinWrongFunction JobDigest JobSign) bad
  good <- joinJob dcB (lgEnv genB) (lgTable genB) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sidB
    , jqCapacity = 32
    }
  case good of
    JoinOk _ -> pure ()
    other -> assertFailure ("retry join failed: " ++ show other)
  storeClose storeB

-- An undersized new buffer reports its sizing with the durable job
-- intact for a roomier retry. (Ready result: 32 bytes; ask for 8.)
caseJoinShort :: IO ()
caseJoinShort = do
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  dcA <- mkDetached storeA
  runs <- newIORef 0
  j0 <- startDigestJob genA "abc" 32 1
  _ <- pollJob (countingRunner runs) (lgEnv genA) (lgTable genA) JobDigest j0
  DetachOk pid <- detachJob dcA (lgTable genA) j0 JobDigest
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  dcB <- mkDetached storeB
  let sidB = ssId (lgSession genB)
  short <- joinJob dcB (lgEnv genB) (lgTable genB) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sidB
    , jqCapacity = 8
    }
  assertEqual "undersized join sizes" (JoinShort 32) short
  -- Durable job intact: no attachment, record still ready.
  av <- inspectAttachment dcB pid
  assertEqual "no attachment after short join" Nothing av
  jobs <- loadJobs storeB
  case [r | r <- jobs, jrPersistentId r == pid] of
    [rec] -> assertEqual "record still ready" JobReady (jrState rec)
    other -> assertFailure ("expected one record, got " ++ show other)
  good <- joinJob dcB (lgEnv genB) (lgTable genB) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sidB
    , jqCapacity = 32
    }
  case good of
    JoinOk _ -> pure ()
    other -> assertFailure ("retry join failed: " ++ show other)
  storeClose storeB

-- NAMED SOURCE DECISION (HASKOKI-JOIN-FIRST-WINS): the PKCS#11 3.2
-- standard is silent on repeat/competing joins, so this facility
-- resolves them explicitly — the first attachment wins, competitors
-- are refused with the job intact, and no engine work is duplicated.
caseJoinFirstWins :: IO ()
caseJoinFirstWins = do
  assertEqual "policy name pinned" "HASKOKI-JOIN-FIRST-WINS" joinPolicyName
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  dcA <- mkDetached storeA
  j0 <- startDigestJob genA "abc" 32 1
  DetachOk pid <- detachJob dcA (lgTable genA) j0 JobDigest
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  dcB <- mkDetached storeB
  let sidB = ssId (lgSession genB)
      req = JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = sidB
        , jqCapacity = 32
        }
  JoinOk j1 <- joinJob dcB (lgEnv genB) (lgTable genB) req
  rival <- joinJob dcB (lgEnv genB) (lgTable genB) req
  assertEqual "competing join refused"
    (JoinAlreadyAttached joinPolicyName) rival
  -- The winner still drives and delivers exactly once; the rival
  -- caused no second live job and no second engine run.
  runs <- newIORef 0
  p <- pollJob (countingRunner runs) (lgEnv genB) (lgTable genB) JobDigest j1
  assertEqual "winner ready" PollReady p
  (del, writes) <- newCapture
  jc <- completeJoined dcB (lgEnv genB) (lgTable genB) JobDigest j1 del (\_ -> pure ())
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "winner bytes" cannedDigest bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "exactly one write" 1 (length got)
  nRuns <- readIORef runs
  assertEqual "no duplicated engine work" 1 nRuns
  storeClose storeB

-- A delivered job never rejoins: clean typed error, record retained,
-- never recompleted.
caseJoinAfterDelivered :: IO ()
caseJoinAfterDelivered = do
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  dcA <- mkDetached storeA
  j0 <- startDigestJob genA "abc" 32 1
  DetachOk pid <- detachJob dcA (lgTable genA) j0 JobDigest
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  dcB <- mkDetached storeB
  let req = JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = ssId (lgSession genB)
        , jqCapacity = 32
        }
  JoinOk j1 <- joinJob dcB (lgEnv genB) (lgTable genB) req
  runs <- newIORef 0
  _ <- pollJob (countingRunner runs) (lgEnv genB) (lgTable genB) JobDigest j1
  (del, _) <- newCapture
  jc <- completeJoined dcB (lgEnv genB) (lgTable genB) JobDigest j1 del (\_ -> pure ())
  case jcOutcome jc of
    CompleteDelivered _ -> pure ()
    other -> assertFailure ("expected delivery, got " ++ show other)
  again <- joinJob dcB (lgEnv genB) (lgTable genB) req
  assertEqual "delivered never rejoins" (JoinTerminal JobDelivered) again
  nRuns <- readIORef runs
  assertEqual "never recompleted" 1 nRuns
  jobs <- loadJobs storeB
  assertEqual "record retained" 1
    (length [r | r <- jobs, jrPersistentId r == pid])
  storeClose storeB

-- Canceling a joined job resolves the durable record canceled; the
-- job never rejoins afterwards.
caseJoinAfterCancel :: IO ()
caseJoinAfterCancel = do
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  dcA <- mkDetached storeA
  j0 <- startDigestJob genA "abc" 32 5
  DetachOk pid <- detachJob dcA (lgTable genA) j0 JobDigest
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  dcB <- mkDetached storeB
  let req = JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = ssId (lgSession genB)
        , jqCapacity = 32
        }
  JoinOk j1 <- joinJob dcB (lgEnv genB) (lgTable genB) req
  (cout, cerr) <- cancelJoined dcB (lgTable genB) j1
  assertEqual "cancel wins" CancelOk cout
  assertEqual "cancel mark clean" Nothing cerr
  again <- joinJob dcB (lgEnv genB) (lgTable genB) req
  assertEqual "canceled never rejoins" (JoinTerminal JobCanceled) again
  jobs <- loadJobs storeB
  case [r | r <- jobs, jrPersistentId r == pid] of
    [rec] -> assertEqual "record canceled" JobCanceled (jrState rec)
    other -> assertFailure ("expected one record, got " ++ show other)
  storeClose storeB

-- Token reset bumps the generation: old persistent ids die with a
-- typed stale-generation refusal.
caseJoinStaleGeneration :: IO ()
caseJoinStaleGeneration = do
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  dcA <- mkDetached storeA
  j0 <- startDigestJob genA "abc" 32 1
  DetachOk pid <- detachJob dcA (lgTable genA) j0 JobDigest
  -- Reset the token (generation 0 -> 1) WITHOUT dropping the job:
  -- reset drops jobs atomically, so re-seat the job record at the
  -- old generation to model a stale id surviving a backup restore.
  let replacement = TokenRecord
        { trId = tokHome
        , trSlot = slotHome
        , trGeneration = Generation 1
        , trLabel = "detach-test"
        , trAuth = tokenAuthNew
        }
  rr <- storeResetToken storeA tokHome (Generation 0) replacement
  case rr of
    Committed -> pure ()
    other -> assertFailure ("reset failed: " ++ show other)
  jobsAfterReset <- loadJobs storeA
  assertEqual "reset drops jobs" 0 (length jobsAfterReset)
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  dcB <- mkDetached storeB
  stale <- joinJob dcB (lgEnv genB) (lgTable genB) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = ssId (lgSession genB)
    , jqCapacity = 32
    }
  -- The reset dropped the record, so the id is unknown; the
  -- generation check fires when the record survives (see below).
  assertEqual "dropped id unknown" JoinUnknown stale
  -- Re-seat the old-generation record (backup-restore shape) and
  -- confirm the generation check itself.
  jobsNow <- loadJobs storeB
  _ <- pure jobsNow
  let staleRec = JobRecord
        { jrPersistentId = 41
        , jrToken = tokHome
        , jrTokenGeneration = Generation 0
        , jrFunction = "digest"
        , jrState = JobQueued
        , jrBody = JobPending "haskoki-call/v1" "bogus-but-shaped"
        }
  res <- storeCommit storeB emptyDelta { sdPutJobs = [staleRec] }
  case res of
    NotCommitted _ -> pure ()
    -- The store itself enforces generation match on job puts, so a
    -- stale record cannot even be written: both layers agree that
    -- reset kills old ids. Either outcome proves the point.
    Committed -> do
      genOut <- joinJob dcB (lgEnv genB) (lgTable genB) JoinRequest
        { jqPid = 41
        , jqFunction = JobDigest
        , jqSession = ssId (lgSession genB)
        , jqCapacity = 32
        }
      assertEqual "stale generation refused"
        (JoinStaleGeneration (Generation 0) (Generation 1)) genOut
    CommitUnknown err ->
      assertFailure ("unexpected ambiguous reset-seat: " ++ show err)
  storeClose storeB

-- Unknown recipe/format versions reject typed; the record is intact.
caseJoinUnknownVersion :: IO ()
caseJoinUnknownVersion = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  dc <- mkDetached store
  let rec = JobRecord
        { jrPersistentId = 7
        , jrToken = tokHome
        , jrTokenGeneration = Generation 0
        , jrFunction = "digest"
        , jrState = JobQueued
        , jrBody = JobPending "bogus/v9" "xx"
        }
  res <- storeCommit store emptyDelta { sdPutJobs = [rec] }
  case res of
    Committed -> pure ()
    other -> assertFailure ("hand-commit failed: " ++ show other)
  out <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
    { jqPid = 7
    , jqFunction = JobDigest
    , jqSession = ssId (lgSession gen)
    , jqCapacity = 32
    }
  assertEqual "unknown version refused" (JoinUnknownVersion "bogus/v9") out
  jobs <- loadJobs store
  assertEqual "record intact" 1 (length jobs)
  storeClose store

-- Join validates the target session (exists, home slot, async) and
-- the requested capacity before attaching anything.
caseJoinSessionCapacity :: IO ()
caseJoinSessionCapacity = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  dc <- mkDetached store
  j0 <- startDigestJob gen "abc" 32 1
  DetachOk pid <- detachJob dc (lgTable gen) j0 JobDigest
  let sid = ssId (lgSession gen)
  -- Unknown session.
  badSess <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = SessionId 999
    , jqCapacity = 32
    }
  assertEqual "unknown session refused" JoinBadSession badSess
  -- Known but sync-only session: open a second session, do not
  -- enable it for async.
  m <- snapshotModel (lgEnv gen)
  let sid2 = SessionId (mNextSession m)
      openReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []
  case planCall defaultRules m openReq of
    Immediate pc -> do
      pr <- publish (lgEnv gen) (pcDelta pc)
      case pr of
        Right () -> pure ()
        Left f -> assertFailure ("second open failed: " ++ show f)
    other -> assertFailure ("second open did not plan: " ++ show other)
  syncOnly <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sid2
    , jqCapacity = 32
    }
  assertEqual "sync-only session refused" JoinSessionNotAsync syncOnly
  -- Zero capacity.
  zeroCap <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sid
    , jqCapacity = 0
    }
  assertEqual "zero capacity refused" (JoinDenied StartBadCapacity) zeroCap
  -- Unknown persistent id.
  unknownPid <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
    { jqPid = 12345
    , jqFunction = JobDigest
    , jqSession = sid
    , jqCapacity = 32
    }
  assertEqual "unknown pid refused" JoinUnknown unknownPid
  -- Nothing attached by any refusal.
  av <- inspectAttachment dc pid
  assertEqual "still idle" (Just AvIdle) av
  storeClose store

-- The target session must carry a matching initialized operation:
-- a bare session cannot replay a digest recipe.
caseJoinIncompatible :: IO ()
caseJoinIncompatible = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  dc <- mkDetached store
  j0 <- startDigestJob gen "abc" 32 1
  DetachOk pid <- detachJob dc (lgTable gen) j0 JobDigest
  -- A second session, async-enabled but digest-cold.
  m <- snapshotModel (lgEnv gen)
  let sid2 = SessionId (mNextSession m)
      openReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []
  case planCall defaultRules m openReq of
    Immediate pc -> do
      pr <- publish (lgEnv gen) (pcDelta pc)
      case pr of
        Right () -> pure ()
        Left f -> assertFailure ("second open failed: " ++ show f)
    other -> assertFailure ("second open did not plan: " ++ show other)
  enableAsyncSession (lgTable gen) sid2
  out <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sid2
    , jqCapacity = 32
    }
  case out of
    JoinIncompatible _ -> pure ()
    other -> assertFailure ("expected JoinIncompatible, got " ++ show other)
  av <- inspectAttachment dc pid
  assertEqual "still idle" (Just AvIdle) av
  -- The refused replan rolled its claim back: no reverse entry,
  -- and the good session joins cleanly afterwards.
  rev <- inspectReverse dc (asyncTableId (lgTable gen)) (JobId 1)
  assertEqual "no reverse entry after refused replan" Nothing rev
  retry <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = ssId (lgSession gen)
    , jqCapacity = 32
    }
  case retry of
    JoinOk _ -> pure ()
    other -> assertFailure ("retry after incompatible failed: " ++ show other)
  storeClose store

-- A token with an active login admits only authenticated joins: the
-- fresh public session is told to authenticate first. The login
-- lives in the LIVE model (durable token records carry no
-- login); the stored record pins that contract by staying
-- login-free. Once the session itself logs in, the same join is
-- admitted.
caseJoinAuthRequired :: IO ()
caseJoinAuthRequired = do
  world <- newMemoryWorld
  eStore <- openMemoryStore world
  store <- case eStore of
    Right s -> pure s
    Left err -> assertFailure ("open failed: " ++ show err)
  let tok = TokenRecord
        { trId = tokHome
        , trSlot = slotHome
        , trGeneration = Generation 0
        , trLabel = "detach-test"
        , trAuth = tokenAuthNew
        }
  res <- storeCommit store emptyDelta { sdPutTokens = [tok] }
  case res of
    Committed -> pure ()
    other -> assertFailure ("token seat failed: " ++ show other)
  eToks <- storeLoadTokens store
  case eToks of
    Right toks -> case [t | (t, _) <- toks, trId t == tokHome] of
      [t] -> assertEqual "stored record carries no login"
        Nothing (taLogin (trAuth t))
      _ -> assertFailure "home token record missing"
    Left err -> assertFailure ("token load failed: " ++ show err)
  gen <- openLiveGen
  assertEqual "fresh session is public" LoginPublic (ssLogin (lgSession gen))
  eLogin <- publish (lgEnv gen)
    (StateDelta [DeltaSetTokenAuth slotHome (tokenAuthNew { taLogin = Just AuthUser })])
  case eLogin of
    Right () -> pure ()
    Left f -> assertFailure ("live login failed: " ++ show f)
  mLive <- snapshotModel (lgEnv gen)
  case lookupTokenAuth mLive slotHome of
    Just auth -> assertEqual "live login established"
      (Just AuthUser) (taLogin auth)
    Nothing -> assertFailure "live token missing"
  dc <- mkDetached store
  j0 <- startDigestJob gen "abc" 32 1
  DetachOk pid <- detachJob dc (lgTable gen) j0 JobDigest
  out <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = ssId (lgSession gen)
    , jqCapacity = 32
    }
  assertEqual "public join refused" JoinAuthRequired out
  eSession <- publish (lgEnv gen)
    (StateDelta [DeltaSetSessionLogin (ssId (lgSession gen)) LoginUser])
  case eSession of
    Right () -> pure ()
    Left f -> assertFailure ("session login failed: " ++ show f)
  retry <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = ssId (lgSession gen)
    , jqCapacity = 32
    }
  case retry of
    JoinOk _ -> pure ()
    other -> assertFailure ("logged-in join failed: " ++ show other)
  storeClose store

-- Adapter-flagged opaque work takes the permitted unsaveable
-- outcome: no record, no revocation, job still live.
caseOpaqueUnsaveable :: IO ()
caseOpaqueUnsaveable = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  dc <- mkDetached store
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 2
  markJobOpaque dc j0 "live EVP_MD_CTX (test double)"
  out <- detachJob dc (lgTable gen) j0 JobDigest
  case out of
    DetachUnsaveable reason ->
      assertEqual "reason carried" "live EVP_MD_CTX (test double)" reason
    other -> assertFailure ("expected DetachUnsaveable, got " ++ show other)
  assertEqual "unsaveable code" CKR_STATE_UNSAVEABLE (detachCode out)
  p <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest j0
  assertEqual "attachment preserved" (PollPending 1) p
  jobs <- loadJobs store
  assertEqual "no record stored" 0 (length jobs)
  -- The mark is consumed: a retry detaches normally.
  ok <- detachJob dc (lgTable gen) j0 JobDigest
  case ok of
    DetachOk _ -> pure ()
    other -> assertFailure ("retry failed: " ++ show other)
  storeClose store

-- Retiring the live table (provider close) cancels every active
-- attachment durably: rejoin is refused and the record is canceled.
caseRetireCancels :: IO ()
caseRetireCancels = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  dc <- mkDetached store
  j0 <- startDigestJob gen "abc" 32 5
  DetachOk pid <- detachJob dc (lgTable gen) j0 JobDigest
  let req = JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = ssId (lgSession gen)
        , jqCapacity = 32
        }
  JoinOk _ <- joinJob dc (lgEnv gen) (lgTable gen) req
  retired <- retireLiveTable dc
  assertEqual "one retired attachment" [(pid, Nothing)] retired
  again <- joinJob dc (lgEnv gen) (lgTable gen) req
  assertEqual "retired never rejoins" (JoinTerminal JobCanceled) again
  jobs <- loadJobs store
  case [r | r <- jobs, jrPersistentId r == pid] of
    [rec] -> assertEqual "record canceled" JobCanceled (jrState rec)
    other -> assertFailure ("expected one record, got " ++ show other)
  storeClose store

-- Ambiguous durable commits reload and reconcile: detach runs
-- two commits (reservation, then insertion) and the script
-- faults both; each reconciles present (the backend applied
-- before verification), so detach succeeds exactly once — one
-- record, old binding gone, nothing duplicated. Real fault
-- injection, no fakes.
caseAmbiguousPresent :: IO ()
caseAmbiguousPresent = do
  world <- newMemoryWorld
  eClean <- openMemoryStore world
  clean <- case eClean of
    Right s -> pure s
    Left err -> assertFailure ("clean open failed: " ++ show err)
  let tok = TokenRecord
        { trId = tokHome
        , trSlot = slotHome
        , trGeneration = Generation 0
        , trLabel = "detach-test"
        , trAuth = tokenAuthNew
        }
  res <- storeCommit clean emptyDelta { sdPutTokens = [tok] }
  case res of
    Committed -> pure ()
    other -> assertFailure ("token seat failed: " ++ show other)
  storeClose clean
  inj <- scriptedFaults [FaultAmbiguousCommit, FaultAmbiguousCommit]
  eFaulty <- openMemoryStoreWith world defaultLimits inj
  faulty <- case eFaulty of
    Right s -> pure s
    Left err -> assertFailure ("faulty open failed: " ++ show err)
  gen <- openLiveGen
  dc <- mkDetached faulty
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 2
  out <- detachJob dc (lgTable gen) j0 JobDigest
  pid <- case out of
    DetachOk p -> pure p
    other -> assertFailure ("expected DetachOk, got " ++ show other)
  -- Exactly-once across the ambiguity: one durable record, no live
  -- job left to double-deliver.
  jobs <- loadJobs faulty
  case jobs of
    [rec] -> assertEqual "the reconciled record" pid (jrPersistentId rec)
    other -> assertFailure ("expected one record, got " ++ show (length other))
  p <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest j0
  assertEqual "old binding revoked" PollUnknown p
  -- And the reconciled record rejoins normally.
  av <- inspectAttachment dc pid
  assertEqual "attachment idle" (Just AvIdle) av
  storeClose faulty

-- A clean reservation followed by an unknown-but-durable
-- insertion: the insert really lands, only its outcome is
-- hidden, so the detach layer reloads and reconciles present —
-- exactly once, with the old binding revoked. (A shared fault
-- script cannot stage this shape: its entries match in any
-- probe order, so a verification fault would be consumed by
-- the reservation's own probe first. The Store record itself
-- is scripted instead; the reload-then-decide logic is what is
-- pinned.)
caseAmbiguousInsertPresent :: IO ()
caseAmbiguousInsertPresent = do
  (_world, backing) <- mkWorld
  gen <- openLiveGen
  let fake = backing
        { storeCommit = \delta -> do
            res <- storeCommit backing delta
            case res of
              Committed -> pure (CommitUnknown (StoreIO "scripted ambiguity"))
              other -> pure other
        }
  dc <- mkDetached fake
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 2
  out <- detachJob dc (lgTable gen) j0 JobDigest
  pid <- case out of
    DetachOk p -> pure p
    other -> assertFailure ("expected DetachOk, got " ++ show other)
  jobs <- loadJobs backing
  case jobs of
    [rec] -> assertEqual "the reconciled record" pid (jrPersistentId rec)
    other -> assertFailure ("expected one record, got " ++ show (length other))
  p <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest j0
  assertEqual "old binding revoked" PollUnknown p
  av <- inspectAttachment dc pid
  assertEqual "attachment idle" (Just AvIdle) av
  storeClose backing

-- The other reconcile branch, via a scripted store: the commit
-- outcome is unknown AND the reload shows nothing was written, so
-- detach reports the store failure with the live attachment
-- preserved. (No backend produces this shape on demand — the memory
-- backend applies before it can go ambiguous — so the Store record
-- itself is scripted; the reload-then-decide logic is what is pinned.
-- The reservation is pinned explicitly: a fixed scripted id, so
-- the test never depends on the backing store's live counter.)
caseAmbiguousAbsent :: IO ()
caseAmbiguousAbsent = do
  (_world, backing) <- mkWorld
  gen <- openLiveGen
  captured <- newIORef (emptyDelta :: StoreDelta)
  let fake = backing
        { storeReserveJobId = pure (Right 42)
        , storeCommit = \delta -> do
            modifyIORef' captured (const delta)
            pure (CommitUnknown (StoreIO "scripted ambiguity"))
        , storeLoadJobs = pure (Right [])
        , storeReload = pure (Right ())
        }
  dc <- mkDetached fake
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 2
  out <- detachJob dc (lgTable gen) j0 JobDigest
  case out of
    DetachStore _ -> pure ()
    other -> assertFailure ("expected DetachStore, got " ++ show other)
  p <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest j0
  assertEqual "live job preserved" (PollPending 1) p
  delta <- readIORef captured
  assertEqual "one commit attempted" 1 (length (sdPutJobs delta))
  case sdPutJobs delta of
    [rec] -> assertEqual "scripted reservation id used" 42 (jrPersistentId rec)
    _ -> assertFailure "expected exactly one captured job put"
  storeClose backing

-- Seeded starts share startJob validation: bad capacities refuse
-- without allocating, and the seed lands ready.
caseSeededValidates :: IO ()
caseSeededValidates = do
  gen <- openLiveGen
  m <- snapshotModel (lgEnv gen)
  let sid = ssId (lgSession gen)
      req = Request Pkcs11_3_2 F_Digest (Just sid) Nothing "abc"
        [RegionBytes "async" (IntentBuffer maxOutputBytes)]
  (res, eff) <- case planCall defaultRules m req of
    Execute r e -> pure (r, e)
    other -> assertFailure ("digest did not plan execute: " ++ show other)
  let badReq = JobRequest
        { jrSession = sid
        , jrFunction = JobDigest
        , jrWork = WorkCall res eff
        , jrTicks = 0
        , jrCapacity = 0
        }
  bad <- startSeededJob (lgTable gen) badReq cannedDigest
  assertEqual "seeded zero-capacity refused" (Left StartBadCapacity) bad
  let goodReq = badReq { jrCapacity = 32 }
  good <- startSeededJob (lgTable gen) goodReq cannedDigest
  jid <- case good of
    Right j -> pure j
    Left deny -> assertFailure ("seeded start denied: " ++ show deny)
  assertEqual "refusal allocated nothing" (JobId 0) jid
  runs <- newIORef 0
  p <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest jid
  assertEqual "seeded job ready" PollReady p
  nRuns <- readIORef runs
  assertEqual "seed runs no engine work" 0 nRuns

-- Simultaneous joins from two sessions (one table, one
-- context): a barrier releases both joiners at once; exactly one
-- creates the live attachment and the loser takes the existing
-- already-attached refusal — on every round, under every
-- interleaving. Runner and output counts prove no duplicated
-- engine work.
caseJoinRaceTwoSessions :: IO ()
caseJoinRaceTwoSessions = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  dc <- mkDetached store
  let tid = asyncTableId (lgTable gen)
  runs <- newIORef 0
  forM_ [1 .. nJoinRaceRounds :: Int] $ \_ -> do
    -- Fresh join sessions per round: each round's winning
    -- complete consumes its session's digest operation, while
    -- the source session only ever plans and detaches (never
    -- publishes) and stays replayable across rounds.
    stA <- openSecondSession gen
    stB <- openSecondSession gen
    let sidA = ssId stA
        sidB = ssId stB
    j0 <- startDigestJob gen "abc" 32 1
    DetachOk pid <- detachJob dc (lgTable gen) j0 JobDigest
    go <- newEmptyMVar
    out1 <- newEmptyMVar
    out2 <- newEmptyMVar
    let racer sid out = forkIO $ do
          takeMVar go
          r <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
            { jqPid = pid
            , jqFunction = JobDigest
            , jqSession = sid
            , jqCapacity = 32
            }
          putMVar out r
    _ <- racer sidA out1
    _ <- racer sidB out2
    putMVar go ()
    putMVar go ()
    r1 <- joinBounded "join racer 1" out1
    r2 <- joinBounded "join racer 2" out2
    jWin <- case (r1, r2) of
      (JoinOk j, JoinAlreadyAttached p) -> do
        assertEqual "named policy" joinPolicyName p
        pure j
      (JoinAlreadyAttached p, JoinOk j) -> do
        assertEqual "named policy" joinPolicyName p
        pure j
      _ -> assertFailure ("race must split winner/loser, got " ++ show (r1, r2))
    -- Exactly one live attachment, reverse-resolving to this pid.
    av <- inspectAttachment dc pid
    assertEqual "one live attachment" (Just (AvActive jWin)) av
    rev <- inspectReverse dc tid jWin
    assertEqual "reverse resolves the winner" (Just pid) rev
    -- The winner drives and delivers exactly once.
    p <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest jWin
    assertEqual "winner ready" PollReady p
    (del, writes) <- newCapture
    jc <- completeJoined dc (lgEnv gen) (lgTable gen) JobDigest jWin del (\_ -> pure ())
    case jcOutcome jc of
      CompleteDelivered (CompBytes bs) ->
        assertEqual "winner bytes" cannedDigest bs
      other -> assertFailure ("expected delivery, got " ++ show other)
    got <- readIORef writes
    assertEqual "exactly one write" 1 (length got)
  nRuns <- readIORef runs
  assertEqual "one engine run per round" nJoinRaceRounds nRuns
  census <- tableStats (lgTable gen)
  assertEqual "round census" (0, nJoinRaceRounds, 2 * nJoinRaceRounds) census
  storeClose store

-- Two tables (two provider generations, one shared store and
-- detach context) race one persistent id; the loser then joins a
-- second id on its own table. Both tables' first live jobs are
-- job zero — the reverse map and the completion marks resolve
-- each table's zero to its own persistent id.
caseJoinRaceTwoTables :: IO ()
caseJoinRaceTwoTables = do
  (_world, store) <- mkWorld
  genS <- openLiveGen
  genA <- openLiveGen
  genB <- openLiveGen
  dc <- mkDetached store
  let tidA = asyncTableId (lgTable genA)
      tidB = asyncTableId (lgTable genB)
  assertBool "table identities distinct" (tidA /= tidB)
  -- The source detaches twice; the join targets stay fresh so
  -- both allocate their first live job as job zero.
  s0 <- startDigestJob genS "abc" 32 1
  DetachOk pid1 <- detachJob dc (lgTable genS) s0 JobDigest
  s1 <- startDigestJob genS "abc" 32 1
  DetachOk pid2 <- detachJob dc (lgTable genS) s1 JobDigest
  assertBool "persistent ids distinct" (pid1 /= pid2)
  -- Race pid1 across the two tables.
  go <- newEmptyMVar
  outA <- newEmptyMVar
  outB <- newEmptyMVar
  let racer gen out = forkIO $ do
        takeMVar go
        r <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
          { jqPid = pid1
          , jqFunction = JobDigest
          , jqSession = ssId (lgSession gen)
          , jqCapacity = 32
          }
        putMVar out r
  _ <- racer genA outA
  _ <- racer genB outB
  putMVar go ()
  putMVar go ()
  rA <- joinBounded "table-A joiner" outA
  rB <- joinBounded "table-B joiner" outB
  (genW, genL, jW) <- case (rA, rB) of
    (JoinOk j, JoinAlreadyAttached _) -> pure (genA, genB, j)
    (JoinAlreadyAttached _, JoinOk j) -> pure (genB, genA, j)
    _ -> assertFailure ("cross-table race must split, got " ++ show (rA, rB))
  assertEqual "winner takes job zero" (JobId 0) jW
  -- The loser joins the second id on its own table: job zero
  -- collides numerically and must still resolve per table.
  outL <- joinJob dc (lgEnv genL) (lgTable genL) JoinRequest
    { jqPid = pid2
    , jqFunction = JobDigest
    , jqSession = ssId (lgSession genL)
    , jqCapacity = 32
    }
  jL <- case outL of
    JoinOk j -> pure j
    other -> assertFailure ("loser-table join failed: " ++ show other)
  assertEqual "loser takes job zero too" (JobId 0) jL
  revW <- inspectReverse dc (asyncTableId (lgTable genW)) jW
  assertEqual "winner reverse" (Just pid1) revW
  revL <- inspectReverse dc (asyncTableId (lgTable genL)) jL
  assertEqual "loser reverse" (Just pid2) revL
  census <- detachStats dc
  assertEqual "two live attachments" (2, 0, 0) census
  -- Each table completes through its own binding: two engine
  -- runs, two single deliveries, marks on the right records.
  runs <- newIORef 0
  let drive gen j = do
        p <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest j
        assertEqual "joined ready" PollReady p
        (del, writes) <- newCapture
        jc <- completeJoined dc (lgEnv gen) (lgTable gen) JobDigest j del (\_ -> pure ())
        assertEqual "mark clean" Nothing (jcMarkError jc)
        case jcOutcome jc of
          CompleteDelivered (CompBytes bs) ->
            assertEqual "replay bytes" cannedDigest bs
          other -> assertFailure ("expected delivery, got " ++ show other)
        got <- readIORef writes
        assertEqual "one write each" 1 (length got)
  drive genW jW
  drive genL jL
  nRuns <- readIORef runs
  assertEqual "two engine runs total" 2 nRuns
  jobs <- loadJobs store
  let stateOf p = [jrState r | r <- jobs, jrPersistentId r == p]
  assertEqual "pid1 delivered" [JobDelivered] (stateOf pid1)
  assertEqual "pid2 delivered" [JobDelivered] (stateOf pid2)
  storeClose store

-- Scoped retirement: retiring table A cancels only A's
-- attachments; table B's active join keeps working and delivers.
caseRetireScopedKeepsOther :: IO ()
caseRetireScopedKeepsOther = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  let sid = ssId (lgSession gen)
  tableA <- newAsyncTable 8
  tableB <- newAsyncTable 8
  enableAsyncSession tableA sid
  enableAsyncSession tableB sid
  let tidA = asyncTableId tableA
      tidB = asyncTableId tableB
  assertBool "table identities distinct" (tidA /= tidB)
  dc <- mkDetached store
  -- Source jobs live on the generation's own table.
  j0 <- startDigestJob gen "abc" 32 1
  DetachOk pid1 <- detachJob dc (lgTable gen) j0 JobDigest
  j1 <- startDigestJob gen "abc" 32 1
  DetachOk pid2 <- detachJob dc (lgTable gen) j1 JobDigest
  let joinOn table pid = joinJob dc (lgEnv gen) table JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = sid
        , jqCapacity = 32
        }
  JoinOk jA <- joinOn tableA pid1
  JoinOk jB <- joinOn tableB pid2
  assertEqual "A takes job zero" (JobId 0) jA
  assertEqual "B takes job zero" (JobId 0) jB
  av1 <- inspectAttachment dc pid1
  assertEqual "pid1 active" (Just (AvActive jA)) av1
  av2 <- inspectAttachment dc pid2
  assertEqual "pid2 active" (Just (AvActive jB)) av2
  -- Retire A: only pid1 resolves canceled.
  retiredA <- retireLiveTableFor dc tidA
  assertEqual "only A retired" [(pid1, Nothing)] retiredA
  av1r <- inspectAttachment dc pid1
  assertEqual "pid1 terminal" (Just (AvTerminal JobCanceled)) av1r
  av2r <- inspectAttachment dc pid2
  assertEqual "pid2 still active" (Just (AvActive jB)) av2r
  againA <- joinOn tableA pid1
  assertEqual "retired never rejoins" (JoinTerminal JobCanceled) againA
  -- B is unaffected: it drives and delivers exactly once.
  runs <- newIORef 0
  p <- pollJob (countingRunner runs) (lgEnv gen) tableB JobDigest jB
  assertEqual "B ready" PollReady p
  (del, writes) <- newCapture
  jc <- completeJoined dc (lgEnv gen) tableB JobDigest jB del (\_ -> pure ())
  assertEqual "B mark clean" Nothing (jcMarkError jc)
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "B bytes" cannedDigest bs
    other -> assertFailure ("expected B delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "B one write" 1 (length got)
  nRuns <- readIORef runs
  assertEqual "B one engine run" 1 nRuns
  -- The durable records agree: pid1 canceled, pid2 delivered.
  jobs <- loadJobs store
  let stateOf q = [jrState r | r <- jobs, jrPersistentId r == q]
  assertEqual "pid1 canceled" [JobCanceled] (stateOf pid1)
  assertEqual "pid2 delivered" [JobDelivered] (stateOf pid2)
  -- Whole-context retirement now finds nothing left to retire.
  retiredNone <- retireLiveTable dc
  assertEqual "nothing left" [] retiredNone
  storeClose store

-- A start refusal under a held claim (the table filled after
-- validation) rolls back only the claim: the attachment is idle
-- again, no reverse entry exists, no job id was consumed, and a
-- retry after freeing the slot joins cleanly.
caseJoinStartRefusalRollsBack :: IO ()
caseJoinStartRefusalRollsBack = do
  (_world, store) <- mkWorld
  gen <- openLiveGenCap 1
  dc <- mkDetached store
  let sid = ssId (lgSession gen)
      table = lgTable gen
      tid = asyncTableId table
  j0 <- startDigestJob gen "abc" 32 1
  DetachOk pid <- detachJob dc table j0 JobDigest
  -- Fill the single live slot after the detach freed it.
  jFill <- startDigestJob gen "abc" 32 1
  (live0, _term0, next0) <- tableStats table
  assertEqual "table full" 1 live0
  out <- joinJob dc (lgEnv gen) table JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sid
    , jqCapacity = 32
    }
  assertEqual "start refused over capacity"
    (JoinDenied StartOverCapacity) out
  av <- inspectAttachment dc pid
  assertEqual "claim rolled back to idle" (Just AvIdle) av
  rev <- inspectReverse dc tid (JobId next0)
  assertEqual "no reverse entry" Nothing rev
  (live1, _term1, next1) <- tableStats table
  assertEqual "refusal consumed no id" next0 next1
  assertEqual "still exactly the filler live" 1 live1
  -- Free the slot; the retry joins and delivers.
  cout <- cancelJob table jFill
  assertEqual "filler canceled" CancelOk cout
  JoinOk j1 <- joinJob dc (lgEnv gen) table JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sid
    , jqCapacity = 32
    }
  runs <- newIORef 0
  p <- pollJob (countingRunner runs) (lgEnv gen) table JobDigest j1
  assertEqual "retry ready" PollReady p
  (del, writes) <- newCapture
  jc <- completeJoined dc (lgEnv gen) table JobDigest j1 del (\_ -> pure ())
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "retry bytes" cannedDigest bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "one write" 1 (length got)
  nRuns <- readIORef runs
  assertEqual "one engine run" 1 nRuns
  storeClose store

-- Interruption after the live start but before the attachment
-- commit: the TEST-ONLY hook parks the joiner inside the
-- transfer window, a kill lands there deterministically, and the
-- transfer retires the fresh unregistered job plus rolls the
-- claim back — no live orphan, no stuck claim, durable job
-- intact, rejoin clean.
caseJoinInterruptionRollsBack :: IO ()
caseJoinInterruptionRollsBack = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  dc <- mkDetached store
  let sid = ssId (lgSession gen)
      table = lgTable gen
      tid = asyncTableId table
  j0 <- startDigestJob gen "abc" 32 1
  DetachOk pid <- detachJob dc table j0 JobDigest
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  done <- newEmptyMVar
  setJoinTestHook dc (putMVar entered () >> takeMVar proceed)
  joinerTid <- forkIO $ do
    r <- try (joinJob dc (lgEnv gen) table JoinRequest
      { jqPid = pid
      , jqFunction = JobDigest
      , jqSession = sid
      , jqCapacity = 32
      })
    putMVar done (r :: Either SomeException JoinOutcome)
  -- The joiner is parked inside the transfer window: its live
  -- job started, its commit not yet run.
  mEntered <- timeout 10000000 (takeMVar entered)
  case mEntered of
    Nothing -> assertFailure "joiner never entered the transfer window"
    Just () -> pure ()
  (liveMid, _termMid, nextMid) <- tableStats table
  assertEqual "fresh job started" 1 liveMid
  let freshJid = JobId (nextMid - 1)
  killThread joinerTid
  mDone <- timeout 10000000 (takeMVar done)
  r <- case mDone of
    Nothing -> assertFailure "joiner never reported after kill"
    Just x -> pure x
  case r of
    Left e -> case fromException e of
      Just ThreadKilled -> pure ()
      Just other -> assertFailure ("expected ThreadKilled, got async " ++ show other)
      Nothing -> assertFailure ("expected ThreadKilled, got " ++ show e)
    Right out -> assertFailure ("kill swallowed, join returned " ++ show out)
  -- Claim rolled back; fresh job retired; nothing registered.
  av <- inspectAttachment dc pid
  assertEqual "claim rolled back" (Just AvIdle) av
  rev <- inspectReverse dc tid freshJid
  assertEqual "fresh job unregistered" Nothing rev
  (liveAfter, termAfter, _nextAfter) <- tableStats table
  assertZero "live_jobs" "no live orphan" liveAfter
  assertEqual "one retired tombstone" 1 termAfter
  cout <- cancelJob table freshJid
  case cout of
    CancelAlready TermCanceled -> pure ()
    other -> assertFailure ("fresh job not canceled, got " ++ show other)
  jobs <- loadJobs store
  case [rec | rec <- jobs, jrPersistentId rec == pid] of
    [rec] -> assertEqual "durable job intact" JobQueued (jrState rec)
    other -> assertFailure ("expected one record, got " ++ show other)
  -- The rejoin succeeds and delivers exactly once.
  setJoinTestHook dc (pure ())
  JoinOk j1 <- joinJob dc (lgEnv gen) table JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sid
    , jqCapacity = 32
    }
  runs <- newIORef 0
  p <- pollJob (countingRunner runs) (lgEnv gen) table JobDigest j1
  assertEqual "rejoin ready" PollReady p
  (del, writes) <- newCapture
  jc <- completeJoined dc (lgEnv gen) table JobDigest j1 del (\_ -> pure ())
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "rejoin bytes" cannedDigest bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "one write" 1 (length got)
  nRuns <- readIORef runs
  assertEqual "one engine run" 1 nRuns
  storeClose store

-- | Open a detach context homed to an arbitrary token.
mkDetachedFor :: Store -> TokenId -> IO DetachCtx
mkDetachedFor store tok = do
  eDc <- openDetached store tok
  case eDc of
    Right dc -> pure dc
    Left err -> assertFailure ("openDetached failed: " ++ show err)

-- | Seat a second token (id 2, slot 1, generation 0) next to the
-- home token; return its record.
seatSecondToken :: Store -> IO TokenRecord
seatSecondToken store = do
  let tok = TokenRecord
        { trId = TokenId 2
        , trSlot = SlotId 1
        , trGeneration = Generation 0
        , trLabel = "detach-test-2"
        , trAuth = tokenAuthNew
        }
  res <- storeCommit store emptyDelta { sdPutTokens = [tok] }
  case res of
    Committed -> pure tok
    other -> assertFailure ("second token seat failed: " ++ show other)

-- | Read the durable job-id mark ('Nothing' = the key is absent).
loadCounter :: Store -> IO (Maybe String)
loadCounter store = do
  eMeta <- storeLoadMeta store
  meta <- case eMeta of
    Right m -> pure m
    Left err -> assertFailure ("loadMeta failed: " ++ show err)
  pure (lookup jobIdCounterKey meta)

-- Two contexts over one store handle mint distinct ids: the
-- store-wide reservation serializes them, so sequential detaches
-- through sibling contexts hand out 1 then 2 with both records
-- durable.
caseTwoContextsDistinctIds :: IO ()
caseTwoContextsDistinctIds = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  dcA <- mkDetached store
  dcB <- mkDetached store
  j0 <- startDigestJob gen "abc" 32 2
  j1 <- startDigestJob gen "def" 32 2
  DetachOk pidA <- detachJob dcA (lgTable gen) j0 JobDigest
  DetachOk pidB <- detachJob dcB (lgTable gen) j1 JobDigest
  assertEqual "sibling contexts share one counter" [1, 2] (sort [pidA, pidB])
  assertEqual "no shared id" 2 (length (nub [pidA, pidB]))
  jobs <- loadJobs store
  assertEqual "both records durable" [1, 2] (sort (map jrPersistentId jobs))
  mark <- loadCounter store
  assertEqual "mark advanced past both" (Just (encodeHexWord64 3)) mark
  storeClose store

-- Two tokens on one store share the same store-wide counter:
-- detaches through per-token contexts never collide, and each
-- record stays homed to its own token.
caseTwoTokensStoreWideCounter :: IO ()
caseTwoTokensStoreWideCounter = do
  (_world, store) <- mkWorld
  tok2 <- seatSecondToken store
  gen <- openLiveGen
  dcA <- mkDetached store
  dcB <- mkDetachedFor store (trId tok2)
  j0 <- startDigestJob gen "abc" 32 2
  j1 <- startDigestJob gen "def" 32 2
  DetachOk pidA <- detachJob dcA (lgTable gen) j0 JobDigest
  DetachOk pidB <- detachJob dcB (lgTable gen) j1 JobDigest
  assertEqual "tokens share one counter" [1, 2] (sort [pidA, pidB])
  jobs <- loadJobs store
  case ( [r | r <- jobs, jrPersistentId r == pidA]
       , [r | r <- jobs, jrPersistentId r == pidB] ) of
    ([ra], [rb]) -> do
      assertEqual "first record homed" tokHome (jrToken ra)
      assertEqual "second record homed" (trId tok2) (jrToken rb)
    other -> assertFailure ("expected two records, got " ++ show other)
  storeClose store

-- Detach, reset, reopen, detach again: reset drops the job rows
-- but keeps the high-water mark, so the new detach mints a fresh
-- id and the stale pre-reset id names nothing — never new work.
caseStaleIdNeverReused :: IO ()
caseStaleIdNeverReused = do
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  dcA <- mkDetached storeA
  j0 <- startDigestJob genA "abc" 32 1
  DetachOk pid1 <- detachJob dcA (lgTable genA) j0 JobDigest
  let replacement = TokenRecord
        { trId = tokHome
        , trSlot = slotHome
        , trGeneration = Generation 1
        , trLabel = "detach-test"
        , trAuth = tokenAuthNew
        }
  rr <- storeResetToken storeA tokHome (Generation 0) replacement
  case rr of
    Committed -> pure ()
    other -> assertFailure ("reset failed: " ++ show other)
  dropped <- loadJobs storeA
  assertEqual "reset drops job rows" [] dropped
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  dcB <- mkDetached storeB
  j1 <- startDigestJob genB "def" 32 1
  DetachOk pid2 <- detachJob dcB (lgTable genB) j1 JobDigest
  assertEqual "mark kept across reset" 2 pid2
  stale <- joinJob dcB (lgEnv genB) (lgTable genB) JoinRequest
    { jqPid = pid1
    , jqFunction = JobDigest
    , jqSession = ssId (lgSession genB)
    , jqCapacity = 32
    }
  assertEqual "stale id names nothing" JoinUnknown stale
  jobs <- loadJobs storeB
  assertEqual "only the new record exists" [pid2] (map jrPersistentId jobs)
  storeClose storeB

-- A failed insertion burns its reservation: the detach reports
-- the store failure with the live job preserved, the next
-- detach mints the following id (a gap, never a reuse), and
-- the burned id names no record.
caseFailedInsertBurnsId :: IO ()
caseFailedInsertBurnsId = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  armed <- newIORef True
  let flaky = store
        { storeCommit = \delta -> do
            arm <- readIORef armed
            if arm && not (null (sdPutJobs delta))
              then do
                writeIORef armed False
                pure (NotCommitted (StoreIO "scripted insert failure"))
              else storeCommit store delta
        }
  dc <- mkDetached flaky
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 2
  j1 <- startDigestJob gen "def" 32 2
  out <- detachJob dc (lgTable gen) j0 JobDigest
  case out of
    DetachStore _ -> pure ()
    other -> assertFailure ("expected DetachStore, got " ++ show other)
  p <- pollJob (countingRunner runs) (lgEnv gen) (lgTable gen) JobDigest j0
  assertEqual "live job preserved" (PollPending 1) p
  mark <- loadCounter store
  assertEqual "reservation burned before the failed insert"
    (Just (encodeHexWord64 2)) mark
  DetachOk pid2 <- detachJob dc (lgTable gen) j1 JobDigest
  assertEqual "gap, never a reuse" 2 pid2
  jobs <- loadJobs store
  assertEqual "burned id names no record" [2] (map jrPersistentId jobs)
  storeClose store

-- A token-identity mismatch refuses before any replan, even
-- at an equal generation: the record names the second token
-- at generation 0 (as does the home token) and carries an
-- unknown recipe version (which would refuse as
-- 'JoinUnknownVersion' if the body ran first). The join
-- reports the id unknown to this home token, with nothing
-- claimed and the record intact.
caseTokenMismatchBeforeReplan :: IO ()
caseTokenMismatchBeforeReplan = do
  (_world, store) <- mkWorld
  tok2 <- seatSecondToken store
  gen <- openLiveGen
  dc <- mkDetached store
  let rec = JobRecord
        { jrPersistentId = 41
        , jrToken = trId tok2
        , jrTokenGeneration = Generation 0
        , jrFunction = "digest"
        , jrState = JobQueued
        , jrBody = JobPending "bogus/v9" "xx"
        }
  res <- storeCommit store emptyDelta { sdPutJobs = [rec] }
  case res of
    Committed -> pure ()
    other -> assertFailure ("hand-commit failed: " ++ show other)
  out <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
    { jqPid = 41
    , jqFunction = JobDigest
    , jqSession = ssId (lgSession gen)
    , jqCapacity = 32
    }
  assertEqual "token mismatch refuses first" JoinUnknown out
  av <- inspectAttachment dc 41
  assertEqual "nothing claimed" Nothing av
  jobs <- loadJobs store
  assertEqual "record intact" 1 (length jobs)
  storeClose store

-- Retirement racing a claimed join rolls the claim back: the
-- joiner parks in the transfer window (claimed and started,
-- pre-commit), the table retires, and the late commit is
-- refused — the fresh job retires, the durable job stands
-- untouched, the retired table cannot claim again, and a
-- sibling table still joins and delivers exactly once. Pre-fix
-- the commit succeeded after retirement and published a live
-- binding the drain had already missed.
caseRetireRollsBackClaim :: IO ()
caseRetireRollsBackClaim = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  dc <- mkDetached store
  let sid = ssId (lgSession gen)
      table = lgTable gen
      tid = asyncTableId table
  j0 <- startDigestJob gen "abc" 32 1
  DetachOk pid <- detachJob dc table j0 JobDigest
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  done <- newEmptyMVar
  setJoinTestHook dc (putMVar entered () >> takeMVar proceed)
  _ <- forkIO $ do
    r <- try (joinJob dc (lgEnv gen) table JoinRequest
      { jqPid = pid
      , jqFunction = JobDigest
      , jqSession = sid
      , jqCapacity = 32
      })
    putMVar done (r :: Either SomeException JoinOutcome)
  mEntered <- timeout 10000000 (takeMVar entered)
  case mEntered of
    Nothing -> assertFailure "joiner never entered the transfer window"
    Just () -> pure ()
  (liveMid, _termMid, nextMid) <- tableStats table
  assertEqual "fresh job started" 1 liveMid
  let freshJid = JobId (nextMid - 1)
  -- Retire while the joiner parks: no actives, one claim rolled
  -- back, and the table records its retirement.
  retired <- retireLiveTableFor dc tid
  assertEqual "no actives to retire" [] retired
  avMid <- inspectAttachment dc pid
  assertEqual "claim rolled back to idle" (Just AvIdle) avMid
  putMVar proceed ()
  mDone <- timeout 10000000 (takeMVar done)
  r <- case mDone of
    Nothing -> assertFailure "joiner never reported after retire"
    Just x -> pure x
  case r of
    Right out -> assertEqual "late commit refused"
      (JoinAlreadyAttached joinPolicyName) out
    Left e -> assertFailure ("joiner failed: " ++ show e)
  rev <- inspectReverse dc tid freshJid
  assertEqual "fresh job unregistered" Nothing rev
  (liveAfter, termAfter, _nextAfter) <- tableStats table
  assertZero "live_jobs" "no live orphan" liveAfter
  assertEqual "one retired tombstone" 1 termAfter
  cout <- cancelJob table freshJid
  case cout of
    CancelAlready TermCanceled -> pure ()
    other -> assertFailure ("fresh job not canceled, got " ++ show other)
  jobs <- loadJobs store
  case [rec | rec <- jobs, jrPersistentId rec == pid] of
    [rec] -> assertEqual "durable job intact" JobQueued (jrState rec)
    other -> assertFailure ("expected one record, got " ++ show other)
  -- The retired table cannot claim again; a sibling generation
  -- still joins the untouched record and delivers exactly once.
  again <- joinJob dc (lgEnv gen) table JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sid
    , jqCapacity = 32
    }
  assertEqual "retired table cannot reclaim"
    (JoinAlreadyAttached joinPolicyName) again
  setJoinTestHook dc (pure ())
  tableB <- newAsyncTable 8
  enableAsyncSession tableB sid
  JoinOk j1 <- joinJob dc (lgEnv gen) tableB JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = sid
    , jqCapacity = 32
    }
  runs <- newIORef 0
  p <- pollJob (countingRunner runs) (lgEnv gen) tableB JobDigest j1
  assertEqual "sibling ready" PollReady p
  (del, writes) <- newCapture
  jc <- completeJoined dc (lgEnv gen) tableB JobDigest j1 del (\_ -> pure ())
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "sibling bytes" cannedDigest bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "one write" 1 (length got)
  nRuns <- readIORef runs
  assertEqual "one engine run" 1 nRuns
  storeClose store

-- A retired table refuses a late claim on an untouched record,
-- while a sibling table joins it normally: retirement pins the
-- table, not the record. Fully sequential — no rendezvous.
caseRetiredTableRefusesLateClaim :: IO ()
caseRetiredTableRefusesLateClaim = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  let sid = ssId (lgSession gen)
  tableA <- newAsyncTable 8
  tableB <- newAsyncTable 8
  enableAsyncSession tableA sid
  enableAsyncSession tableB sid
  let tidA = asyncTableId tableA
      tidB = asyncTableId tableB
  assertBool "table identities distinct" (tidA /= tidB)
  dc <- mkDetached store
  j0 <- startDigestJob gen "abc" 32 1
  DetachOk pid1 <- detachJob dc (lgTable gen) j0 JobDigest
  j1 <- startDigestJob gen "abc" 32 1
  DetachOk pid2 <- detachJob dc (lgTable gen) j1 JobDigest
  let joinOn table pid = joinJob dc (lgEnv gen) table JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = sid
        , jqCapacity = 32
        }
  JoinOk _ <- joinOn tableA pid1
  retiredA <- retireLiveTableFor dc tidA
  assertEqual "A retires its active" [(pid1, Nothing)] retiredA
  lateA <- joinOn tableA pid2
  assertEqual "retired table cannot claim"
    (JoinAlreadyAttached joinPolicyName) lateA
  av2 <- inspectAttachment dc pid2
  assertEqual "untouched record still idle" (Just AvIdle) av2
  JoinOk jB <- joinOn tableB pid2
  avB <- inspectAttachment dc pid2
  assertEqual "sibling active" (Just (AvActive jB)) avB
  revB <- inspectReverse dc tidB jB
  assertEqual "sibling reverse resolves" (Just pid2) revB
  storeClose store

-- ---------------------------------------------------------------------------
-- Cross-context exclusivity (one claim authority per open store)
-- ---------------------------------------------------------------------------

-- | Two detach contexts over ONE store handle plus two tables
-- sharing one live generation's env and source session: table A
-- is the generation's own table, table B a fresh sibling with
-- the source session async-enabled.
data TwoCtx = TwoCtx
  { tcStore :: !Store
  , tcGen :: !LiveGen
  , tcDcA :: !DetachCtx
  , tcDcB :: !DetachCtx
  , tcTableB :: !AsyncTable
  }

mkTwoCtx :: IO TwoCtx
mkTwoCtx = do
  (_world, store) <- mkWorld
  gen <- openLiveGen
  dcA <- mkDetached store
  dcB <- mkDetached store
  tableB <- newAsyncTable 8
  enableAsyncSession tableB (ssId (lgSession gen))
  pure TwoCtx
    { tcStore = store
    , tcGen = gen
    , tcDcA = dcA
    , tcDcB = dcB
    , tcTableB = tableB
    }

-- | A digest join of one persistent id on a session.
digestJoin :: Word64 -> SessionId -> JoinRequest
digestJoin pid sid = JoinRequest
  { jqPid = pid
  , jqFunction = JobDigest
  , jqSession = sid
  , jqCapacity = 32
  }

-- | Complete a joined job through its own context and table,
-- asserting one clean delivery of the canned digest and exactly
-- one captured write.
deliverOnce :: DetachCtx -> LiveGen -> AsyncTable -> JobId -> IO ()
deliverOnce dc gen table jid = do
  (del, writes) <- newCapture
  jc <- completeJoined dc (lgEnv gen) table JobDigest jid del (\_ -> pure ())
  assertEqual "durable mark clean" Nothing (jcMarkError jc)
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "delivered digest" cannedDigest bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "exactly one write" 1 (length got)

-- | The durable state of one persistent id.
durableState :: Store -> Word64 -> IO JobExecState
durableState store pid = do
  jobs <- loadJobs store
  case [jrState r | r <- jobs, jrPersistentId r == pid] of
    [st] -> pure st
    other -> assertFailure ("expected one record, got " ++ show other)

-- Two contexts over one store, a queued id: context A joins on
-- table A; context B's join of the SAME id on table B is refused
-- under the named policy, starts nothing in table B, and sees
-- A's active binding. A then runs and delivers exactly once.
-- Pre-fix each context kept its own attachment map, so B's join
-- also returned JoinOk and started a second live job.
caseTwoContextsQueuedRefused :: IO ()
caseTwoContextsQueuedRefused = do
  tc <- mkTwoCtx
  let gen = tcGen tc
      tableA = lgTable gen
      tableB = tcTableB tc
      sid = ssId (lgSession gen)
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 1
  DetachOk pid <- detachJob (tcDcA tc) tableA j0 JobDigest
  outA <- joinJob (tcDcA tc) (lgEnv gen) tableA (digestJoin pid sid)
  jA <- case outA of
    JoinOk j -> pure j
    other -> assertFailure ("context A join failed: " ++ show other)
  outB <- joinJob (tcDcB tc) (lgEnv gen) tableB (digestJoin pid sid)
  assertEqual "second context refused"
    (JoinAlreadyAttached joinPolicyName) outB
  statsB <- tableStats tableB
  assertEqual "loser table started nothing" (0, 0, 0) statsB
  avB <- inspectAttachment (tcDcB tc) pid
  assertEqual "loser sees the winner's binding" (Just (AvActive jA)) avB
  p <- pollJob (countingRunner runs) (lgEnv gen) tableA JobDigest jA
  assertEqual "winner ready" PollReady p
  deliverOnce (tcDcA tc) gen tableA jA
  nRuns <- readIORef runs
  assertEqual "exactly one engine run" 1 nRuns
  durableState (tcStore tc) pid >>= assertEqual "record delivered" JobDelivered
  avEnd <- inspectAttachment (tcDcB tc) pid
  assertEqual "both views see the terminal fate"
    (Just (AvTerminal JobDelivered)) avEnd
  storeClose (tcStore tc)

-- The same for a ready (prepared-result) row: A's seeded join
-- wins, B is refused with no start, and the engine ran only
-- once (before the detach).
caseTwoContextsReadyRefused :: IO ()
caseTwoContextsReadyRefused = do
  tc <- mkTwoCtx
  let gen = tcGen tc
      tableA = lgTable gen
      tableB = tcTableB tc
      sid = ssId (lgSession gen)
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 1
  p0 <- pollJob (countingRunner runs) (lgEnv gen) tableA JobDigest j0
  assertEqual "drive ready" PollReady p0
  DetachOk pid <- detachJob (tcDcA tc) tableA j0 JobDigest
  durableState (tcStore tc) pid >>= assertEqual "record ready" JobReady
  outA <- joinJob (tcDcA tc) (lgEnv gen) tableA (digestJoin pid sid)
  jA <- case outA of
    JoinOk j -> pure j
    other -> assertFailure ("context A join failed: " ++ show other)
  outB <- joinJob (tcDcB tc) (lgEnv gen) tableB (digestJoin pid sid)
  assertEqual "second context refused"
    (JoinAlreadyAttached joinPolicyName) outB
  statsB <- tableStats tableB
  assertEqual "loser table started nothing" (0, 0, 0) statsB
  avB <- inspectAttachment (tcDcB tc) pid
  assertEqual "loser sees the winner's binding" (Just (AvActive jA)) avB
  deliverOnce (tcDcA tc) gen tableA jA
  nRuns <- readIORef runs
  assertEqual "engine ran once, before the detach" 1 nRuns
  durableState (tcStore tc) pid >>= assertEqual "record delivered" JobDelivered
  storeClose (tcStore tc)

-- Barrier: context A parks inside its transfer window (claimed
-- and started, pre-commit); context B's join of the same id is
-- refused and starts nothing in table B. Released, A commits
-- and delivers exactly once.
caseTwoContextsParkedTransfer :: IO ()
caseTwoContextsParkedTransfer = do
  tc <- mkTwoCtx
  let gen = tcGen tc
      tableA = lgTable gen
      tableB = tcTableB tc
      sid = ssId (lgSession gen)
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 1
  DetachOk pid <- detachJob (tcDcA tc) tableA j0 JobDigest
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  done <- newEmptyMVar
  setJoinTestHook (tcDcA tc) (putMVar entered () >> takeMVar proceed)
  _ <- forkIO $ do
    r <- try (joinJob (tcDcA tc) (lgEnv gen) tableA (digestJoin pid sid))
    putMVar done (r :: Either SomeException JoinOutcome)
  mEntered <- timeout 10000000 (takeMVar entered)
  case mEntered of
    Nothing -> assertFailure "context A never entered the transfer window"
    Just () -> pure ()
  outB <- joinJob (tcDcB tc) (lgEnv gen) tableB (digestJoin pid sid)
  statsB <- tableStats tableB
  avMid <- inspectAttachment (tcDcB tc) pid
  -- Release A before asserting, so a failure never strands it.
  putMVar proceed ()
  assertEqual "parked claim refuses the other context"
    (JoinAlreadyAttached joinPolicyName) outB
  assertEqual "no start in the loser table" (0, 0, 0) statsB
  assertEqual "claim projects to idle" (Just AvIdle) avMid
  rA <- joinBounded "parked context A joiner" done
  jA <- case rA of
    Right (JoinOk j) -> pure j
    Right other -> assertFailure ("context A join failed: " ++ show other)
    Left e -> assertFailure ("context A joiner threw: " ++ show e)
  setJoinTestHook (tcDcA tc) (pure ())
  p <- pollJob (countingRunner runs) (lgEnv gen) tableA JobDigest jA
  assertEqual "winner ready" PollReady p
  deliverOnce (tcDcA tc) gen tableA jA
  nRuns <- readIORef runs
  assertEqual "exactly one engine run" 1 nRuns
  storeClose (tcStore tc)

-- Simultaneous joins of one id through two contexts (each on
-- its own table): exactly one wins on every round, the loser's
-- table starts nothing, both contexts see the one binding, and
-- the winner delivers exactly once through its own context.
caseTwoContextsJoinRace :: IO ()
caseTwoContextsJoinRace = do
  tc <- mkTwoCtx
  let gen = tcGen tc
      tableA = lgTable gen
      tableB = tcTableB tc
  runs <- newIORef 0
  forM_ [1 .. nJoinRaceRounds :: Int] $ \_ -> do
    -- A fresh join session per round (the winning complete
    -- consumes its digest operation), async on both tables.
    st <- openSecondSession gen
    let sid = ssId st
    enableAsyncSession tableB sid
    j0 <- startDigestJob gen "abc" 32 1
    DetachOk pid <- detachJob (tcDcA tc) tableA j0 JobDigest
    statsA0 <- tableStats tableA
    statsB0 <- tableStats tableB
    go <- newEmptyMVar
    outA <- newEmptyMVar
    outB <- newEmptyMVar
    let racer dc table out = forkIO $ do
          takeMVar go
          r <- joinJob dc (lgEnv gen) table (digestJoin pid sid)
          putMVar out r
    _ <- racer (tcDcA tc) tableA outA
    _ <- racer (tcDcB tc) tableB outB
    putMVar go ()
    putMVar go ()
    rA <- joinBounded "context A racer" outA
    rB <- joinBounded "context B racer" outB
    (dcW, tableW, jW, tableL, statsL0) <- case (rA, rB) of
      (JoinOk j, JoinAlreadyAttached p) -> do
        assertEqual "named policy" joinPolicyName p
        pure (tcDcA tc, tableA, j, tableB, statsB0)
      (JoinAlreadyAttached p, JoinOk j) -> do
        assertEqual "named policy" joinPolicyName p
        pure (tcDcB tc, tableB, j, tableA, statsA0)
      _ -> assertFailure ("race must split winner/loser, got " ++ show (rA, rB))
    statsL <- tableStats tableL
    assertEqual "loser table started nothing" statsL0 statsL
    avA <- inspectAttachment (tcDcA tc) pid
    avB <- inspectAttachment (tcDcB tc) pid
    assertEqual "context A sees the one binding" (Just (AvActive jW)) avA
    assertEqual "context B sees the one binding" (Just (AvActive jW)) avB
    p <- pollJob (countingRunner runs) (lgEnv gen) tableW JobDigest jW
    assertEqual "winner ready" PollReady p
    deliverOnce dcW gen tableW jW
  nRuns <- readIORef runs
  assertEqual "one engine run per round" nJoinRaceRounds nRuns
  storeClose (tcStore tc)

-- The refused context can neither retire nor cancel the
-- winner: whole-context and scoped retirement through it find
-- nothing it served, a cancel of the winner's local job id on
-- its own table is unknown with no durable mark, the winner's
-- binding and reverse entry stand, and the durable row stays
-- queued until the winner delivers.
caseLoserCannotRetireOrCancel :: IO ()
caseLoserCannotRetireOrCancel = do
  tc <- mkTwoCtx
  let gen = tcGen tc
      tableA = lgTable gen
      tableB = tcTableB tc
      tidA = asyncTableId tableA
      sid = ssId (lgSession gen)
      dcA = tcDcA tc
      dcB = tcDcB tc
  runs <- newIORef 0
  j0 <- startDigestJob gen "abc" 32 1
  DetachOk pid <- detachJob dcA tableA j0 JobDigest
  outA <- joinJob dcA (lgEnv gen) tableA (digestJoin pid sid)
  jA <- case outA of
    JoinOk j -> pure j
    other -> assertFailure ("context A join failed: " ++ show other)
  outB <- joinJob dcB (lgEnv gen) tableB (digestJoin pid sid)
  assertEqual "second context refused"
    (JoinAlreadyAttached joinPolicyName) outB
  commits0 <- ssCommits <$> storeStats (tcStore tc)
  whole <- retireLiveTable dcB
  assertEqual "loser whole-context retire finds nothing" [] whole
  scoped <- retireLiveTableFor dcB tidA
  assertEqual "loser cannot retire the winner's table" [] scoped
  (cout, merr) <- cancelJoined dcB tableB jA
  assertEqual "winner's job is unknown to the loser table" CancelUnknown cout
  assertEqual "no durable mark" Nothing merr
  commits1 <- ssCommits <$> storeStats (tcStore tc)
  assertEqual "loser wrote nothing durable" commits0 commits1
  avA <- inspectAttachment dcA pid
  assertEqual "winner stays active" (Just (AvActive jA)) avA
  revA <- inspectReverse dcA tidA jA
  assertEqual "winner reverse entry stands" (Just pid) revA
  durableState (tcStore tc) pid >>= assertEqual "row stays queued" JobQueued
  p <- pollJob (countingRunner runs) (lgEnv gen) tableA JobDigest jA
  assertEqual "winner ready" PollReady p
  deliverOnce dcA gen tableA jA
  nRuns <- readIORef runs
  assertEqual "exactly one engine run" 1 nRuns
  durableState (tcStore tc) pid >>= assertEqual "record delivered" JobDelivered
  storeClose (tcStore tc)
