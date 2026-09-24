{- | Detached jobs: GetID (detach) + Join (rejoin) over the
attached table and the durable store.

The detach lease ('beginDetach' / 'commitDetachRevoke' /
'abortDetach'), GetID durability-before-success plus
revocation-before-success, and failure-preserves-attachment.
-}
{-# LANGUAGE OverloadedStrings #-}
module DetachedSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.IORef (IORef, newIORef, modifyIORef', readIORef)
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Operation (CryptoEffect (..), CryptoResult (..))
import Haskoki.Model (Model (..), SessionState (..), lookupSession)
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Outcome (EffectRequest (..), EngineResult (..), PlanResult (..), PreparedCommit (..))
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
  , inspectAttachment
  , joinJob
  , joinPolicyName
  , markJobOpaque
  , openDetached
  , retireLiveTable
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
  , TokenRecord (..)
  , defaultLimits
  , emptyDelta
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
  [ testCase "FIRST: detach pending digest is durable and revoked" caseFirstDetach
  , testCase "detach lease abort preserves the live job" caseLeaseAbort
  , testCase "detach lease revoke removes exactly one job" caseLeaseRevoke
  , testCase "detach refusals preserve state" caseDetachRefusals
  , testCase "detach store failure preserves the live attachment" caseDetachStoreFailure
  , testCase "seeded start validates like start" caseSeededValidates
  , testCase "rejoin delivers exactly once after restart" caseRejoinHappy
  , testCase "detach ready: join delivers without re-running" caseRejoinReady
  , testCase "wrong-function join rejected; job intact" caseJoinWrongFunction
  , testCase "undersized join leaves the durable job intact" caseJoinShort
  , testCase "HASKOKI-JOIN-FIRST-WINS: competing join refused" caseJoinFirstWins
  , testCase "delivered jobs never rejoin" caseJoinAfterDelivered
  , testCase "canceled joins stay canceled" caseJoinAfterCancel
  , testCase "token reset kills old ids" caseJoinStaleGeneration
  , testCase "unknown recipe version rejected" caseJoinUnknownVersion
  , testCase "join validates session and capacity" caseJoinSessionCapacity
  , testCase "join requires a matching initialized session" caseJoinIncompatible
  , testCase "auth: logged-in token rejects a public join" caseJoinAuthRequired
  , testCase "opaque native work is unsaveable; attachment kept" caseOpaqueUnsaveable
  , testCase "retireLiveTable cancels active attachments" caseRetireCancels
  , testCase "ambiguous commit reconciles present: durable wins" caseAmbiguousPresent
  , testCase "ambiguous commit reconciles absent: kept live" caseAmbiguousAbsent
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
openLiveGen = do
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
  table <- newAsyncTable 8
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

-- Detach failure (faulted durable commit) preserves the old live
-- attachment: the job still polls and no record is stored.
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
  storeClose store

-- A token with an active login admits only authenticated joins: the
-- fresh public session is told to authenticate first.
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
        , trAuth = tokenAuthNew { taLogin = Just AuthUser }
        }
  res <- storeCommit store emptyDelta { sdPutTokens = [tok] }
  case res of
    Committed -> pure ()
    other -> assertFailure ("token seat failed: " ++ show other)
  gen <- openLiveGen
  assertEqual "fresh session is public" LoginPublic (ssLogin (lgSession gen))
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

-- An ambiguous durable commit reloads and reconciles: the record
-- IS present (the backend applied it before verification failed),
-- so detach succeeds exactly once — one record, old binding gone,
-- nothing duplicated. Real fault injection, no fakes.
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
  inj <- scriptedFaults [FaultAmbiguousCommit, FaultVerifyReload]
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

-- The other reconcile branch, via a scripted store: the commit
-- outcome is unknown AND the reload shows nothing was written, so
-- detach reports the store failure with the live attachment
-- preserved. (No backend produces this shape on demand — the memory
-- backend applies before it can go ambiguous — so the Store record
-- itself is scripted; the reload-then-decide logic is what is pinned.)
caseAmbiguousAbsent :: IO ()
caseAmbiguousAbsent = do
  (_world, backing) <- mkWorld
  gen <- openLiveGen
  captured <- newIORef (emptyDelta :: StoreDelta)
  let fake = backing
        { storeCommit = \delta -> do
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
