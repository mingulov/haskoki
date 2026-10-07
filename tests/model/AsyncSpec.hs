{- | Attached asynchronous execution: logical scheduling, attached
jobs, and exact completion delivery.

Start an async sign, poll pending
with unchanged result canaries, then complete exactly once.
Double-complete and complete-after-cancel are rejected; canaries
stay intact until delivery.
-}
{-# LANGUAGE OverloadedStrings #-}
module AsyncSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Concurrent (forkIO, newEmptyMVar, putMVar, takeMVar, threadDelay, tryTakeMVar)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef, modifyIORef', writeIORef)
import qualified Data.Map.Strict as Map
import Data.Word (Word64, Word8)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Foreign.Ptr (plusPtr)
import System.Mem (performGC)
import System.Mem.Weak (Weak, deRefWeak, mkWeak)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), SessionState (..), lookupSession)
import Haskoki.Object (encodeHandle)
import Haskoki.Operation (CryptoEffect (..), CryptoError (..), CryptoResult (..), StepOutcome (..))
import Haskoki.Operation.Cipher (finishCipherUpdate, planCipherUpdate)
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Operation.KeyManagement
  ( KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , aesKeyGenMech
  , ckkAes
  , ckkMlKem
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , encodeKeyPair
  , keyBytesOf
  , planGenerateKey
  , planGenerateKeyPair
  )
import Haskoki.Operation.Kem (mlKemKeyPairGenMech)
import Haskoki.Operation.State
  ( CipherDir (..)
  , CipherSpec (..)
  , OpAuth (..)
  , SessionOps
  , SlotKind (..)
  , bufferedOf
  , chainIvOf
  , commonOf
  , emptySessionOps
  , insertOp
  , lookupSingle
  , mkActiveCipher
  , mkActiveSign
  , mkSlotCommon
  , setBuffered
  )
import Haskoki.Outcome
  ( CryptoStep (..)
  , EffectRequest (..)
  , EngineResult (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Reservation (..)
  , ResourceRelease (..)
  , RevisionDep (..)
  )
import Haskoki.Output (maxOutputBytes)
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Request (FunctionId (..), OutputIntent (..), OutputRegion (..), Request (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Runtime.Async
  ( CompleteOutcome (..)
  , Completion (..)
  , Delivery (..)
  , JobFunction (..)
  , JobRequest (..)
  , JobView (..)
  , AsyncWork (..)
  , PollOutcome (..)
  , CancelOutcome (..)
  , ReapOutcome (..)
  , StartDeny (..)
  , TerminalState (..)
  , AsyncTable
  , cancelJob
  , completeJob
  , decodeCompletion
  , enableAsyncSession
  , encodeCompletion
  , inspectJob
  , maxRetainedBytes
  , maxRetainedTombstones
  , newAsyncTable
  , pollJob
  , reapJob
  , retainedBytes
  , sessionJobs
  , startJob
  , tableStats
  )
import Haskoki.Runtime.Lifecycle
  ( Env
  , defaultInitArgs
  , initialize
  , invalidateSession
  , newEnv
  , publish
  , seatToken
  , snapshotModel
  )
import Haskoki.Transition (finishEffect, planCall)
import Haskoki.Types
  ( EngineResourceId (..)
  , ExternalHandle (..)
  , Generation (..)
  , JobId (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Attached async"
  [ testCase "async sign: pending polls keep canaries; complete delivers once" caseFirstTest
  , testCase "cancel wins: engine never runs; complete-after-cancel rejected" caseCancelWins
  , testCase "complete wins: late cancel loses and writes nothing" caseCompleteWins
  , testCase "start on sync-only session refused without allocating" caseSessionGate
  , testCase "drive error fails the job; nothing delivered" caseDriveError
  , testCase "completion codecs round-trip all three shapes" caseCodecRoundTrip
  , testCase "completion decode rejects adversarial frames" caseCodecAdversarial
  , testCase "wrong-function polling rejected; job intact" caseWrongFunction
  , testCase "one-handle job delivers a generated key" caseGenKey
  , testCase "two-handle job delivers a generated pair" caseGenKeyPair
  , testCase "over-capacity refuses before pending" caseCapacity
  , testCase "attached capacity bounds enforced at submit" caseBadCapacity
  , testCase "reap drops tombstones; live jobs survive" caseReap
  , testCase "sync sessions stay synchronous under async storm" caseSyncStaysSync
  , testCase "short buffers size without delivering or re-running" caseShortBuffer
  , testCase "handle completions need no byte buffer" caseHandleNoBuffer
  , testCase "stale drive fails before running the effect" caseDriveStale
  , testCase "stale complete fails without publishing" caseCompleteStale
  , testCase "complete of a closed session fails cleanly" caseClosedSession
  , testCase "cancel during drive waits, then wins" caseCancelDuringDrive
  , testCase "concurrent complete vs cancel: exactly one winner" caseConcurrentWinner
  , testCase "drain after publish: short drains nothing, deliver drains once" caseDrainAfterPublish
  , testCase "retention bound: N delivered digests keep at most cap tombstones" caseRetentionBound
  , testCase "capped store: delivery + retry + cancel semantics unchanged" caseCappedSemantics
  , testCase "byte retention bound: N max-size digests keep bytes within budget" caseByteRetentionBound
  , testCase "byte budget clears suite-shaped fills with headroom" caseByteBudgetHeadroom
  , testCase "byte accounting prices every retained field" caseByteAccountingFields
  , testCase "byte-evicted store: delivery + retry + cancel semantics unchanged" caseByteEvictionSemantics
  , testCase "retained cipher slices are independent copies" caseCipherSlicesIndependent
  , testCase "committed eviction reclaims without a later table read" caseCommitReclaimsWithoutRead
  , testCase "eviction race under count trigger observes winner-or-unknown" caseEvictionRaceCount
  , testCase "eviction race under byte trigger observes winner-or-unknown" caseEvictionRaceBytes
  ]

sid1 :: SessionId
sid1 = SessionId 1

-- | Canned 64-byte "signature" the stub runner returns.
cannedSig :: ByteString
cannedSig = BS.replicate 64 0x51

-- | Hand-derived golden: tag 0x01 (bytes), u32BE length 64, payload.
goldenBytes :: ByteString
goldenBytes = BS.pack [0x01, 0x00, 0x00, 0x00, 0x40] <> cannedSig

-- | A planned async sign: hand-built reservation (no pinned deps) and
-- an HMAC-shaped sign effect. The stub runner answers it.
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

-- | Captured delivery writes + sizing reports.
data Capture = Capture
  { capWrites :: !(IORef [ByteString])
  , capNeeded :: !(IORef [Word64])
  }

newCapture :: IO Capture
newCapture = Capture <$> newIORef [] <*> newIORef []

captureDelivery :: Word64 -> Capture -> Delivery
captureDelivery cap c = Delivery
  { dCapacity = cap
  , dWrite = \bs -> modifyIORef' (capWrites c) (++ [bs])
  , dReportNeeded = \n -> modifyIORef' (capNeeded c) (++ [n])
  }

writesOf :: Capture -> IO [ByteString]
writesOf = readIORef . capWrites

-- | Counting stub runner: records invocations, answers canned bytes.
countingRunner :: IORef Int -> CryptoEffect -> IO CryptoResult
countingRunner ref _fx = do
  modifyIORef' ref (+ 1)
  pure (GotBytes cannedSig)

mkTable :: IO (AsyncTable, Env)
mkTable = do
  table <- newAsyncTable 8
  env <- newEnv defaultRules
  enableAsyncSession table sid1
  pure (table, env)

assertWrites :: String -> Capture -> [ByteString] -> IO ()
assertWrites msg c want = do
  got <- writesOf c
  assertEqual msg want got

caseFirstTest :: IO ()
caseFirstTest = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
  runs <- newIORef 0
  let run = countingRunner runs
  Right j0 <- startJob table (signRequest sid1 2)
  assertEqual "first job id" (JobId 0) j0
  -- Poll 1 of 2: pending, canaries (zero writes) intact.
  p1 <- pollJob run env table JobSign j0
  assertEqual "poll 1 pending" (PollPending 1) p1
  assertWrites "no write on pending poll" cap []
  -- Complete while pending: pending outcome, nothing written, no advance.
  c0 <- completeJob env table JobSign j0 del (\_ -> pure ())
  assertEqual "complete while pending" (CompletePending 1) c0
  assertWrites "no write on pending complete" cap []
  st0 <- inspectJob table j0
  assertEqual "no advance on pending complete" (Just (Just 1)) (fmap jvTicksLeft st0)
  -- Poll 2 of 2: drives the effect, holds the result, still no write.
  p2 <- pollJob run env table JobSign j0
  assertEqual "poll 2 ready" PollReady p2
  assertWrites "drive writes nothing" cap []
  nRuns <- readIORef runs
  assertEqual "effect ran once at drive" 1 nRuns
  -- Complete delivers the golden bytes exactly once.
  c1 <- completeJob env table JobSign j0 del (\_ -> pure ())
  case c1 of
    CompleteDelivered (CompBytes bs) -> assertEqual "delivered bytes" cannedSig bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  assertWrites "exactly one write" cap [goldenBytes]
  -- Double-complete and late cancel both lose; still one write.
  c2 <- completeJob env table JobSign j0 del (\_ -> pure ())
  case c2 of
    CompleteAlready (TermDelivered (CompBytes bs)) ->
      assertEqual "loser observes winner bytes" cannedSig bs
    other -> assertFailure ("expected already-delivered, got " ++ show other)
  k1 <- cancelJob table j0
  case k1 of
    CancelAlready (TermDelivered _) -> pure ()
    other -> assertFailure ("expected cancel-after-deliver loss, got " ++ show other)
  assertWrites "losers write nothing" cap [goldenBytes]
  nRuns2 <- readIORef runs
  assertEqual "effect still ran once" 1 nRuns2
  stFinal <- inspectJob table j0
  assertEqual "epoch: drive + deliver" (Just 2) (fmap jvEpoch stFinal)

caseCancelWins :: IO ()
caseCancelWins = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
  runs <- newIORef 0
  let run = countingRunner runs
  Right j0 <- startJob table (signRequest sid1 5)
  k <- cancelJob table j0
  assertEqual "cancel wins" CancelOk k
  p <- pollJob run env table JobSign j0
  assertEqual "poll sees cancel" (PollTerminal TermCanceled) p
  c <- completeJob env table JobSign j0 del (\_ -> pure ())
  assertEqual "complete-after-cancel rejected"
    (CompleteAlready TermCanceled) c
  assertWrites "cancel path writes nothing" cap []
  nRuns <- readIORef runs
  assertEqual "engine never ran" 0 nRuns
  stFinal <- inspectJob table j0
  assertEqual "epoch: cancel" (Just 1) (fmap jvEpoch stFinal)

caseCompleteWins :: IO ()
caseCompleteWins = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
  runs <- newIORef 0
  let run = countingRunner runs
  Right j0 <- startJob table (signRequest sid1 1)
  p <- pollJob run env table JobSign j0
  assertEqual "drive ready" PollReady p
  c <- completeJob env table JobSign j0 del (\_ -> pure ())
  case c of
    CompleteDelivered _ -> pure ()
    other -> assertFailure ("expected delivery, got " ++ show other)
  k <- cancelJob table j0
  case k of
    CancelAlready (TermDelivered (CompBytes bs)) ->
      assertEqual "late cancel observes winner bytes" cannedSig bs
    other -> assertFailure ("expected cancel loss, got " ++ show other)
  assertWrites "late cancel writes nothing" cap [goldenBytes]

caseSessionGate :: IO ()
caseSessionGate = do
  table <- newAsyncTable 8
  let req = signRequest (SessionId 99) 1
  r <- startJob table req
  assertEqual "sync-only session refused" (Left StartSessionNotAsync) r
  (_, _, nextId) <- tableStats table
  assertEqual "refusal allocates nothing" 0 nextId
  enableAsyncSession table (SessionId 99)
  r2 <- startJob table req
  case r2 of
    Right (JobId 0) -> pure ()
    other -> assertFailure ("expected JobId 0 after enable, got " ++ show other)

caseDriveError :: IO ()
caseDriveError = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
  let badRun _ = pure (GotCryptoError (CryptoFailed "boom"))
  Right j0 <- startJob table (signRequest sid1 1)
  p <- pollJob badRun env table JobSign j0
  case p of
    PollTerminal (TermFailed code _) ->
      assertEqual "mapped code" CKR_GENERAL_ERROR code
    other -> assertFailure ("expected terminal failure, got " ++ show other)
  c <- completeJob env table JobSign j0 del (\_ -> pure ())
  case c of
    CompleteAlready (TermFailed code _) ->
      assertEqual "loser observes failure code" CKR_GENERAL_ERROR code
    other -> assertFailure ("expected already-failed, got " ++ show other)
  assertWrites "failed job writes nothing" cap []
  stFinal <- inspectJob table j0
  assertEqual "epoch: fail" (Just 1) (fmap jvEpoch stFinal)
  -- A verdict-shaped answer to a bytes job is a loud failure, not bytes.
  Right j1 <- startJob table (signRequest sid1 1)
  p1 <- pollJob (\_ -> pure (GotValid True)) env table JobSign j1
  case p1 of
    PollTerminal (TermFailed code _) ->
      assertEqual "verdict mapped" CKR_GENERAL_ERROR code
    other -> assertFailure ("expected verdict failure, got " ++ show other)
  assertWrites "verdict failure writes nothing" cap []

-- ---------------------------------------------------------------------------
-- Completion codecs, wrong-function polling, handle jobs
-- ---------------------------------------------------------------------------

digestRequest :: SessionId -> Int -> JobRequest
digestRequest sid ticks = JobRequest
  { jrSession = sid
  , jrFunction = JobDigest
  , jrWork = WorkCall
      (Reservation "async-digest-test" [] Nothing Nothing)
      (EffectCrypto (FxDigest (MechanismId 0x250) "abc"))
  , jrTicks = ticks
  , jrCapacity = 64
  }

caseCodecRoundTrip :: IO ()
caseCodecRoundTrip = do
  assertEqual "bytes golden decodes"
    (Just (CompBytes cannedSig)) (decodeCompletion goldenBytes)
  assertEqual "bytes golden encodes" goldenBytes (encodeCompletion (CompBytes cannedSig))
  assertEqual "short bytes frame"
    (BS.pack [0x01, 0x00, 0x00, 0x00, 0x03] <> "abc")
    (encodeCompletion (CompBytes "abc"))
  let h7 = ExternalHandle 7
      frame1 = BS.pack [0x02] <> encodeHandle h7
  assertEqual "one-handle golden" 9 (BS.length frame1)
  assertEqual "one-handle encodes" frame1 (encodeCompletion (CompOneHandle h7))
  assertEqual "one-handle decodes" (Just (CompOneHandle h7)) (decodeCompletion frame1)
  let h3 = ExternalHandle 3
      h9 = ExternalHandle 9
      frame2 = BS.pack [0x03] <> encodeHandle h3 <> encodeHandle h9
  assertEqual "two-handle golden" 17 (BS.length frame2)
  assertEqual "two-handle encodes" frame2 (encodeCompletion (CompTwoHandles h3 h9))
  assertEqual "two-handle decodes"
    (Just (CompTwoHandles h3 h9)) (decodeCompletion frame2)
  assertEqual "empty bytes accepted"
    (Just (CompBytes BS.empty))
    (decodeCompletion (BS.pack [0x01, 0x00, 0x00, 0x00, 0x00]))

caseCodecAdversarial :: IO ()
caseCodecAdversarial = do
  let bad =
        [ BS.empty
        , BS.pack [0x00]
        , BS.pack [0x04]
        , BS.pack [0x01, 0x00, 0x00]
        , BS.pack [0x01, 0x00, 0x00, 0x00, 0x03] <> "ab"
        , goldenBytes <> BS.pack [0x00]
        , BS.pack [0x02]
        , BS.pack [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        , BS.pack [0x02] <> encodeHandle (ExternalHandle 1) <> BS.pack [0x00]
        , BS.pack [0x03] <> encodeHandle (ExternalHandle 1)
        , BS.pack [0x03]
            <> encodeHandle (ExternalHandle 1)
            <> encodeHandle (ExternalHandle 2)
            <> BS.pack [0x00]
        ]
  mapM_ (\bs -> assertEqual ("reject " ++ show (BS.length bs)) Nothing (decodeCompletion bs)) bad
  -- An over-bound length rejects even with a full payload behind it.
  let huge = BS.pack [0x01, 0x01, 0x00, 0x00, 0x01]
        <> BS.replicate (fromIntegral maxOutputBytes + 1) 0xAA
  assertEqual "over-bound length rejects" Nothing (decodeCompletion huge)

caseWrongFunction :: IO ()
caseWrongFunction = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
  runs <- newIORef 0
  let run = countingRunner runs
  Right j0 <- startJob table (signRequest sid1 2)
  -- Poll a sign job with the digest poller: typed refusal, job intact.
  p1 <- pollJob run env table JobDigest j0
  assertEqual "wrong poller refused"
    (PollWrongFunction JobSign JobDigest) p1
  st0 <- inspectJob table j0
  assertEqual "wrong poll does not advance" (Just (Just 2)) (fmap jvTicksLeft st0)
  assertEqual "wrong poll keeps epoch" (Just 0) (fmap jvEpoch st0)
  c0 <- completeJob env table JobDigest j0 del (\_ -> pure ())
  assertEqual "wrong completer refused"
    (CompleteWrongFunction JobSign JobDigest) c0
  assertWrites "wrong-function paths write nothing" cap []
  -- A wrong poll on the last tick drives nothing.
  Right j1 <- startJob table (signRequest sid1 1)
  p2 <- pollJob run env table JobDigest j1
  assertEqual "wrong poll on last tick refused"
    (PollWrongFunction JobSign JobDigest) p2
  nRuns <- readIORef runs
  assertEqual "wrong poll never drives" 0 nRuns
  -- The job is intact: the correct flow still delivers.
  p3 <- pollJob run env table JobSign j1
  assertEqual "correct poll ready" PollReady p3
  c1 <- completeJob env table JobSign j1 del (\_ -> pure ())
  case c1 of
    CompleteDelivered (CompBytes bs) -> assertEqual "bytes" cannedSig bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  -- The reverse direction: a digest job polled with the sign poller.
  Right j2 <- startJob table (digestRequest sid1 1)
  p4 <- pollJob run env table JobSign j2
  assertEqual "reverse wrong poller refused"
    (PollWrongFunction JobDigest JobSign) p4
  -- Unknown jobs have no function to mismatch.
  p5 <- pollJob run env table JobSign (JobId 987)
  assertEqual "unknown poll" PollUnknown p5
  c5 <- completeJob env table JobSign (JobId 987) del (\_ -> pure ())
  assertEqual "unknown complete" CompleteUnknown c5

-- | An initialized Env with one seated token and one open session.
-- | Releases drain after a successful publish, like every other
-- commit-application site. A short completion publishes nothing,
-- so it drains nothing; the roomy retry publishes once and drains
-- exactly once; losers drain nothing (previously the short drained
-- before publishing).
caseDrainAfterPublish :: IO ()
caseDrainAfterPublish = do
  (env, _, st) <- openEnvSession
  let sid = ssId st
      rid = EngineResourceId 21
      digest = BS.replicate 32 0xAB
  -- Live digest stream: init plans Execute, the hand Resource
  -- answer records the stream, publish seats it.
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
  -- Digest-final job: the finish carries the stream release on the
  -- success commit.
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
  PollReady <- pollJob (\_fx -> pure (GotBytes digest)) env table JobDigest j0
  cap <- newCapture
  let tiny = captureDelivery 8 cap
      roomy = captureDelivery 64 cap
  shortDrains <- newIORef []
  fullDrains <- newIORef []
  lateDrains <- newIORef []
  cShort <- completeJob env table JobDigest j0 tiny
    (\r -> modifyIORef' shortDrains (++ [r]))
  assertEqual "short reports sizing" (CompleteShort 32) cShort
  cFull <- completeJob env table JobDigest j0 roomy
    (\r -> modifyIORef' fullDrains (++ [r]))
  case cFull of
    CompleteDelivered (CompBytes bs) -> assertEqual "bytes" digest bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  cLate <- completeJob env table JobDigest j0 roomy
    (\r -> modifyIORef' lateDrains (++ [r]))
  case cLate of
    CompleteAlready (TermDelivered _) -> pure ()
    other -> assertFailure ("expected already-delivered, got " ++ show other)
  gotShort <- readIORef shortDrains
  assertEqual "short drains nothing" [] gotShort
  gotFull <- readIORef fullDrains
  assertEqual "deliver drains exactly once" [ReleaseEngineResource rid] gotFull
  gotLate <- readIORef lateDrains
  assertEqual "losers drain nothing" [] gotLate
  where
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
  , (AttrEncrypt, ValBool True)
  , (AttrDecrypt, ValBool True)
  ]

kemPubTmpl :: [(AttributeType, AttributeValue)]
kemPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkMlKem)
  , (AttrKemAlg, ValULong 768)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool False)
  , (AttrEncapsulate, ValBool True)
  ]

kemPrivTmpl :: [(AttributeType, AttributeValue)]
kemPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkMlKem)
  , (AttrKemAlg, ValULong 768)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrDecapsulate, ValBool True)
  ]

caseGenKey :: IO ()
caseGenKey = do
  (env, m0, st) <- openEnvSession
  table <- newAsyncTable 8
  enableAsyncSession table (ssId st)
  cap <- newCapture
  let del = captureDelivery 9 cap
      pre = mNextHandle m0
      privMat = BS.replicate 32 0x4B
  (pw, fx) <- case planGenerateKey defaultRules m0 st aesKeyGenMech BS.empty (aesTmpl 32) of
    KeyEffect pw0 fx0 -> pure (pw0, fx0)
    other -> assertFailure ("genkey is not an effect: " ++ show other)
  let req = JobRequest
        { jrSession = ssId st
        , jrFunction = JobGenKey
        , jrWork = WorkKey (keyReservation st "async-genkey") pw fx
        , jrTicks = 1
        , jrCapacity = 9
        }
  Right j0 <- startJob table req
  p <- pollJob (\_ -> pure (GotBytes (encodeKeyPair privMat Nothing))) env table JobGenKey j0
  assertEqual "genkey ready" PollReady p
  c <- completeJob env table JobGenKey j0 del (\_ -> pure ())
  wantH <- case c of
    CompleteDelivered (CompOneHandle h) -> pure h
    other -> assertFailure ("expected one-handle delivery, got " ++ show other)
  assertEqual "handle allocates from the model counter" (ExternalHandle pre) wantH
  assertWrites "one-handle frame"
    cap [BS.pack [0x02] <> encodeHandle wantH]
  m1 <- snapshotModel env
  case lookupSession m1 (ssId st) of
    Nothing -> assertFailure "session lost"
    Just _ -> pure ()
  let found = Map.elems (mObjects m1)
  assertEqual "one object published" 1 (length found)
  case found of
    [o] -> assertEqual "stored material" (Just privMat) (keyBytesOf o)
    _ -> assertFailure "expected exactly one object"

caseGenKeyPair :: IO ()
caseGenKeyPair = do
  (env, m0, st) <- openEnvSession
  table <- newAsyncTable 8
  enableAsyncSession table (ssId st)
  cap <- newCapture
  let del = captureDelivery 17 cap
      pre = mNextHandle m0
      privMat = BS.replicate 32 0x50
      pubMat = BS.replicate 16 0x55
  (pw, fx) <- case planGenerateKeyPair defaultRules m0 st mlKemKeyPairGenMech kemPubTmpl kemPrivTmpl of
    KeyEffect pw0 fx0 -> pure (pw0, fx0)
    other -> assertFailure ("genkeypair is not an effect: " ++ show other)
  let req = JobRequest
        { jrSession = ssId st
        , jrFunction = JobGenKeyPair
        , jrWork = WorkKey (keyReservation st "async-genkeypair") pw fx
        , jrTicks = 1
        , jrCapacity = 17
        }
  Right j0 <- startJob table req
  let run _ = pure (GotBytes (encodeKeyPair privMat (Just pubMat)))
  p <- pollJob run env table JobGenKeyPair j0
  assertEqual "genkeypair ready" PollReady p
  c <- completeJob env table JobGenKeyPair j0 del (\_ -> pure ())
  (pubH, privH) <- case c of
    CompleteDelivered (CompTwoHandles a b) -> pure (a, b)
    other -> assertFailure ("expected two-handle delivery, got " ++ show other)
  assertEqual "public handle" (ExternalHandle pre) pubH
  assertEqual "private handle" (ExternalHandle (pre + 1)) privH
  assertWrites "two-handle frame"
    cap [BS.pack [0x03] <> encodeHandle pubH <> encodeHandle privH]
  m1 <- snapshotModel env
  let found = Map.elems (mObjects m1)
  assertEqual "two objects published" 2 (length found)

-- ---------------------------------------------------------------------------
-- Submit-time capacity, reap, sync isolation
-- ---------------------------------------------------------------------------

caseCapacity :: IO ()
caseCapacity = do
  table <- newAsyncTable 2
  enableAsyncSession table sid1
  Right j0 <- startJob table (signRequest sid1 5)
  Right j1 <- startJob table (signRequest sid1 5)
  assertEqual "ids allocate in order" [JobId 0, JobId 1] [j0, j1]
  r <- startJob table (signRequest sid1 5)
  assertEqual "third start over capacity" (Left StartOverCapacity) r
  (live, term, nextId) <- tableStats table
  assertEqual "live count" 2 live
  assertEqual "no tombstones" 0 term
  assertEqual "refusal consumes no id" 2 nextId
  -- Terminal jobs free live capacity but keep their tombstones.
  CancelOk <- cancelJob table j0
  Right j2 <- startJob table (signRequest sid1 5)
  assertEqual "post-cancel id" (JobId 2) j2
  (live2, term2, nextId2) <- tableStats table
  assertEqual "live after recycle" 2 live2
  assertEqual "tombstone retained" 1 term2
  assertEqual "next id" 3 nextId2
  _ <- pure j1
  pure ()

caseBadCapacity :: IO ()
caseBadCapacity = do
  table <- newAsyncTable 8
  enableAsyncSession table sid1
  let bad0 = (signRequest sid1 1) { jrCapacity = 0 }
      badHuge = (signRequest sid1 1) { jrCapacity = maxOutputBytes + 1 }
  r0 <- startJob table bad0
  assertEqual "zero capacity refused" (Left StartBadCapacity) r0
  rHuge <- startJob table badHuge
  assertEqual "over-bound capacity refused" (Left StartBadCapacity) rHuge
  (_, _, nextId) <- tableStats table
  assertEqual "bad-capacity refusals allocate nothing" 0 nextId
  let okEdge = (signRequest sid1 1) { jrCapacity = maxOutputBytes }
  Right j0 <- startJob table okEdge
  assertEqual "bound edge accepted" (JobId 0) j0

caseReap :: IO ()
caseReap = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
  runs <- newIORef 0
  let run = countingRunner runs
  Right j0 <- startJob table (signRequest sid1 5)
  rLive <- reapJob table j0
  assertEqual "live job not reaped" ReapLive rLive
  p <- pollJob run env table JobSign j0
  assertEqual "reap attempt left job live" (PollPending 4) p
  CancelOk <- cancelJob table j0
  rTomb <- reapJob table j0
  assertEqual "tombstone reaped" Reaped rTomb
  p2 <- pollJob run env table JobSign j0
  assertEqual "reaped job unknown" PollUnknown p2
  st <- inspectJob table j0
  assertEqual "reaped job uninspectable" Nothing st
  rAgain <- reapJob table j0
  assertEqual "double reap unknown" ReapUnknown rAgain
  rMissing <- reapJob table (JobId 4242)
  assertEqual "missing reap unknown" ReapUnknown rMissing
  (live, term, _) <- tableStats table
  assertEqual "no live" 0 live
  assertEqual "no tombstones" 0 term
  _ <- pure (del, cap)
  pure ()

-- | Open two sessions on a fresh initialized Env.
openTwoSessions :: IO (Env, SessionState, SessionState)
openTwoSessions = do
  env <- newEnv defaultRules
  ini <- initialize env defaultInitArgs
  case ini of
    OutcomeOk () -> pure ()
    OutcomeErr c -> assertFailure ("init failed: " ++ show c)
  seatToken env (SlotId 0) >>= assertEqual "seat ok" (Right ())
  m0 <- snapshotModel env
  let openReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []
  m1 <- case planCall defaultRules m0 openReq of
    Immediate pc -> do
      pr <- publish env (pcDelta pc)
      case pr of
        Right () -> snapshotModel env
        Left f -> assertFailure ("open A failed: " ++ show f)
    other -> assertFailure ("open A did not plan: " ++ show other)
  m2 <- case planCall defaultRules m1 openReq of
    Immediate pc -> do
      pr <- publish env (pcDelta pc)
      case pr of
        Right () -> snapshotModel env
        Left f -> assertFailure ("open B failed: " ++ show f)
    other -> assertFailure ("open B did not plan: " ++ show other)
  case (lookupSession m2 (SessionId 1), lookupSession m2 (SessionId 2)) of
    (Just stA, Just stB) -> pure (env, stA, stB)
    _ -> assertFailure "sessions missing after open"

initSyncDigest :: Env -> SessionId -> IO ()
initSyncDigest env sid = do
  m <- snapshotModel env
  let req = Request Pkcs11_3_2 F_DigestInit (Just sid) Nothing
        (encodeInitInput (MechanismId 0x250) [] False BS.empty) []
  case planCall defaultRules m req of
    Execute res (EffectCrypto _) -> do
      m2 <- snapshotModel env
      case finishEffect defaultRules m2 res
          (EngineOkResource (EngineResourceId 23)) of
        Left rej -> assertFailure ("digest init rejected: " ++ show rej)
        Right pc -> do
          pr <- publish env (pcDelta pc)
          case pr of
            Right () -> pure ()
            Left f -> assertFailure ("digest init publish failed: " ++ show f)
    other -> assertFailure ("digest init did not plan: " ++ show other)

syncDigestPlan :: Env -> SessionId -> IO PlanResult
syncDigestPlan env sid = do
  m <- snapshotModel env
  let req = Request Pkcs11_3_2 F_Digest (Just sid) Nothing "abc"
        [RegionBytes "digest" (IntentBuffer 32)]
  pure (planCall defaultRules m req)

caseSyncStaysSync :: IO ()
caseSyncStaysSync = do
  (env, stA, stB) <- openTwoSessions
  table <- newAsyncTable 4
  enableAsyncSession table (ssId stA)
  initSyncDigest env (ssId stB)
  planPre <- syncDigestPlan env (ssId stB)
  case planPre of
    Execute _ _ -> pure ()
    other -> assertFailure ("sync digest should plan Execute, got " ++ show other)
  -- Aggressive async storm on A: all states, refusals, recycles.
  cap <- newCapture
  let del = captureDelivery 64 cap
  runs <- newIORef 0
  let run = countingRunner runs
      storm = do
            Right d0 <- startJob table (digestRequest (ssId stA) 3)
            Right d1 <- startJob table (digestRequest (ssId stA) 1)
            Right d2 <- startJob table (digestRequest (ssId stA) 1)
            Right d3 <- startJob table (digestRequest (ssId stA) 1)
            rFull <- startJob table (digestRequest (ssId stA) 1)
            assertEqual "storm over-capacity" (Left StartOverCapacity) rFull
            PollPending 2 <- pollJob run env table JobDigest d0
            PollReady <- pollJob run env table JobDigest d1
            CancelOk <- cancelJob table d2
            CompleteDelivered _ <- completeJob env table JobDigest d1 del (\_ -> pure ())
            PollTerminal TermCanceled <- pollJob run env table JobDigest d2
            Right d4 <- startJob table (digestRequest (ssId stA) 1)
            CancelOk <- cancelJob table d4
            PollReady <- pollJob run env table JobDigest d3
            CompleteDelivered _ <- completeJob env table JobDigest d3 del (\_ -> pure ())
            PollPending 1 <- pollJob run env table JobDigest d0
            CancelOk <- cancelJob table d0
            pure ()
  storm
  planPost <- syncDigestPlan env (ssId stB)
  assertEqual "sync plan identical after storm" planPre planPost
  -- And identical to a pristine environment's plan.
  (env2, _, stB2) <- openTwoSessions
  initSyncDigest env2 (ssId stB2)
  planFresh <- syncDigestPlan env2 (ssId stB2)
  assertEqual "sync plan matches pristine env" planPre planFresh
  -- The sync session owns no jobs; the async session owns tombstones only.
  jobsB <- sessionJobs table (ssId stB)
  assertEqual "sync session has no jobs" [] jobsB
  jobsA <- sessionJobs table (ssId stA)
  assertEqual "async session job ids" 5 (length jobsA)
  (live, term, _) <- tableStats table
  assertEqual "storm leaves no live jobs" 0 live
  assertEqual "storm tombstones" 5 term

-- ---------------------------------------------------------------------------
-- Delivery sizing, staleness, lease arbitration
-- ---------------------------------------------------------------------------

-- | A sign job pinned to a real session revision (for stale tests).
pinnedSignRequest :: SessionState -> Int -> Word64 -> JobRequest
pinnedSignRequest st ticks cap = JobRequest
  { jrSession = ssId st
  , jrFunction = JobSign
  , jrWork = WorkCall
      (keyReservation st "async-sign-pinned")
      (EffectCrypto (FxSign (MechanismId 0x251) Nothing BS.empty "hello"))
  , jrTicks = ticks
  , jrCapacity = cap
  }

frameLen :: ByteString -> Word64
frameLen = fromIntegral . BS.length

caseShortBuffer :: IO ()
caseShortBuffer = do
  (table, env) <- mkTable
  cap <- newCapture
  runs <- newIORef 0
  let run = countingRunner runs
      tiny = captureDelivery 8 cap
      roomy = captureDelivery 64 cap
      need = 64
  assertEqual "golden frame length" 69 (frameLen goldenBytes)
  Right j0 <- startJob table (signRequest sid1 1)
  PollReady <- pollJob run env table JobSign j0
  -- Short delivery buffer: sizing reported, result held, nothing written.
  cShort <- completeJob env table JobSign j0 tiny (\_ -> pure ())
  assertEqual "short reports sizing" (CompleteShort need) cShort
  needed <- readIORef (capNeeded cap)
  assertEqual "sizing callback" [need] needed
  assertWrites "short writes no payload" cap []
  pStill <- pollJob run env table JobSign j0
  assertEqual "short keeps job ready" PollReady pStill
  stReady <- inspectJob table j0
  assertEqual "short keeps epoch" (Just 1) (fmap jvEpoch stReady)
  -- Retry with room: delivers without re-running the effect.
  cFull <- completeJob env table JobSign j0 roomy (\_ -> pure ())
  case cFull of
    CompleteDelivered (CompBytes bs) -> assertEqual "bytes" cannedSig bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  assertWrites "retry delivers once" cap [goldenBytes]
  nRuns <- readIORef runs
  assertEqual "effect ran once across retries" 1 nRuns
  -- Attached capacity binds too: an under-declared job sizes forever.
  Right j1 <- startJob table ((signRequest sid1 1) { jrCapacity = 9 })
  PollReady <- pollJob run env table JobSign j1
  cAttached <- completeJob env table JobSign j1 roomy (\_ -> pure ())
  assertEqual "attached cap binds" (CompleteShort need) cAttached
  assertWrites "attached-short writes nothing" cap [goldenBytes]

caseDriveStale :: IO ()
caseDriveStale = do
  (env, m0, st) <- openEnvSession
  table <- newAsyncTable 8
  enableAsyncSession table (ssId st)
  cap <- newCapture
  let del = captureDelivery 69 cap
  runs <- newIORef 0
  let run = countingRunner runs
  Right j0 <- startJob table (pinnedSignRequest st 1 69)
  -- Invalidate the pinned revision before the drive.
  invalidateSession env (ssId st)
  p <- pollJob run env table JobSign j0
  case p of
    PollTerminal (TermFailed code _) ->
      assertEqual "stale code" CKR_GENERAL_ERROR code
    other -> assertFailure ("expected stale failure, got " ++ show other)
  nRuns <- readIORef runs
  assertEqual "stale drive runs no effect" 0 nRuns
  c <- completeJob env table JobSign j0 del (\_ -> pure ())
  case c of
    CompleteAlready (TermFailed code _) ->
      assertEqual "loser observes stale" CKR_GENERAL_ERROR code
    other -> assertFailure ("expected already-failed, got " ++ show other)
  assertWrites "stale job writes nothing" cap []
  stFinal <- inspectJob table j0
  assertEqual "epoch: stale fail" (Just 1) (fmap jvEpoch stFinal)
  _ <- pure m0
  pure ()

caseCompleteStale :: IO ()
caseCompleteStale = do
  (env, m0, st) <- openEnvSession
  table <- newAsyncTable 8
  enableAsyncSession table (ssId st)
  cap <- newCapture
  let del = captureDelivery 69 cap
  runs <- newIORef 0
  let run = countingRunner runs
  Right j0 <- startJob table (pinnedSignRequest st 1 69)
  PollReady <- pollJob run env table JobSign j0
  -- The model moves between drive and complete: the commit must fail.
  invalidateSession env (ssId st)
  c <- completeJob env table JobSign j0 del (\_ -> pure ())
  case c of
    CompleteAlready (TermFailed code _) ->
      assertEqual "complete-time stale code" CKR_GENERAL_ERROR code
    other -> assertFailure ("expected stale failure, got " ++ show other)
  assertWrites "stale complete writes nothing" cap []
  nRuns <- readIORef runs
  assertEqual "effect ran once (at drive)" 1 nRuns
  stFinal <- inspectJob table j0
  assertEqual "epoch: drive + stale fail" (Just 2) (fmap jvEpoch stFinal)
  _ <- pure m0
  pure ()

caseHandleNoBuffer :: IO ()
caseHandleNoBuffer = do
  -- Handle completions carry no byte payload: zero buffer capacity
  -- and minimal attached capacity still deliver exactly once.
  (env, m0, st) <- openEnvSession
  table <- newAsyncTable 8
  enableAsyncSession table (ssId st)
  cap <- newCapture
  let nobuf = captureDelivery 0 cap
      privMat = BS.replicate 32 0x4B
  (pw, fx) <- case planGenerateKey defaultRules m0 st aesKeyGenMech BS.empty (aesTmpl 32) of
    KeyEffect pw0 fx0 -> pure (pw0, fx0)
    other -> assertFailure ("genkey is not an effect: " ++ show other)
  let req = JobRequest
        { jrSession = ssId st
        , jrFunction = JobGenKey
        , jrWork = WorkKey (keyReservation st "async-genkey-nobuf") pw fx
        , jrTicks = 1
        , jrCapacity = 1
        }
  Right j0 <- startJob table req
  let run _ = pure (GotBytes (encodeKeyPair privMat Nothing))
  PollReady <- pollJob run env table JobGenKey j0
  c <- completeJob env table JobGenKey j0 nobuf (\_ -> pure ())
  case c of
    CompleteDelivered (CompOneHandle _) -> pure ()
    other -> assertFailure ("expected key delivery, got " ++ show other)
  needed <- readIORef (capNeeded cap)
  assertEqual "no sizing for handles" [] needed
  m2 <- snapshotModel env
  assertEqual "published exactly once" 1 (Map.size (mObjects m2))

closeRequest :: SessionId -> Request
closeRequest sid = Request Pkcs11_3_2 F_CloseSession (Just sid) Nothing BS.empty []

caseClosedSession :: IO ()
caseClosedSession = do
  (env, m0, st) <- openEnvSession
  table <- newAsyncTable 8
  enableAsyncSession table (ssId st)
  cap <- newCapture
  let del = captureDelivery 9 cap
      privMat = BS.replicate 32 0x4B
  (pw, fx) <- case planGenerateKey defaultRules m0 st aesKeyGenMech BS.empty (aesTmpl 32) of
    KeyEffect pw0 fx0 -> pure (pw0, fx0)
    other -> assertFailure ("genkey is not an effect: " ++ show other)
  let req = JobRequest
        { jrSession = ssId st
        , jrFunction = JobGenKey
        , jrWork = WorkKey (keyReservation st "async-genkey-close") pw fx
        , jrTicks = 1
        , jrCapacity = 9
        }
  Right j0 <- startJob table req
  let run _ = pure (GotBytes (encodeKeyPair privMat Nothing))
  PollReady <- pollJob run env table JobGenKey j0
  -- Close the session between drive and complete.
  m1 <- snapshotModel env
  case planCall defaultRules m1 (closeRequest (ssId st)) of
    Immediate pc -> do
      pr <- publish env (pcDelta pc)
      case pr of
        Right () -> pure ()
        Left f -> assertFailure ("close publish failed: " ++ show f)
    other -> assertFailure ("close did not plan: " ++ show other)
  c <- completeJob env table JobGenKey j0 del (\_ -> pure ())
  case c of
    CompleteAlready (TermFailed code _) ->
      assertEqual "closed-session code" CKR_GENERAL_ERROR code
    other -> assertFailure ("expected closed-session failure, got " ++ show other)
  assertWrites "closed session writes nothing" cap []
  m2 <- snapshotModel env
  assertEqual "nothing published" 0 (Map.size (mObjects m2))

caseCancelDuringDrive :: IO ()
caseCancelDuringDrive = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
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
  -- The drive holds the lease inside the effect: a racing cancel
  -- cannot complete until the drive leaves the lease.
  canceled <- newEmptyMVar
  _ <- forkIO (cancelJob table j0 >>= putMVar canceled)
  early <- tryTakeMVar canceled
  assertEqual "cancel cannot win mid-drive" Nothing early
  putMVar release ()
  p <- takeMVar polled
  k <- takeMVar canceled
  assertEqual "drive finished ready" PollReady p
  assertEqual "cancel wins after drive" CancelOk k
  c <- completeJob env table JobSign j0 del (\_ -> pure ())
  assertEqual "complete-after-cancel rejected"
    (CompleteAlready TermCanceled) c
  assertWrites "canceled drive delivers nothing" cap []

caseConcurrentWinner :: IO ()
caseConcurrentWinner = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
  runs <- newIORef 0
  let run = countingRunner runs
  Right j0 <- startJob table (signRequest sid1 1)
  PollReady <- pollJob run env table JobSign j0
  doneC <- newEmptyMVar
  doneK <- newEmptyMVar
  _ <- forkIO (completeJob env table JobSign j0 del (\_ -> pure ()) >>= putMVar doneC)
  _ <- forkIO (cancelJob table j0 >>= putMVar doneK)
  c <- takeMVar doneC
  k <- takeMVar doneK
  writes <- writesOf cap
  case (c, k) of
    (CompleteDelivered (CompBytes bs), CancelAlready (TermDelivered _)) -> do
      assertEqual "winner bytes" cannedSig bs
      assertEqual "one write" [goldenBytes] writes
    (CompleteAlready TermCanceled, CancelOk) ->
      assertEqual "no write" [] writes
    other -> assertFailure ("inconsistent arbitration: " ++ show other)
  nRuns <- readIORef runs
  assertEqual "effect ran once" 1 nRuns
  stFinal <- inspectJob table j0
  assertEqual "epoch: drive + terminal" (Just 2) (fmap jvEpoch stFinal)

-- ---------------------------------------------------------------------------
-- Terminal-record retention bound (FINAL-19)
-- ---------------------------------------------------------------------------

-- | Expected retention ceiling under test.
retentionCap :: Int
retentionCap = maxRetainedTombstones

-- | Start, drive, and deliver one digest; every delivery carries the
-- canned bytes exactly once.
deliverOneDigest
  :: AsyncTable -> Env -> (CryptoEffect -> IO CryptoResult) -> Delivery -> Int -> IO ()
deliverOneDigest table env run del _ = do
  eJid <- startJob table (digestRequest sid1 1)
  jid <- case eJid of
    Right j -> pure j
    Left deny -> assertFailure ("digest start denied: " ++ show deny)
  p <- pollJob run env table JobDigest jid
  case p of
    PollReady -> pure ()
    other -> assertFailure ("expected ready, got " ++ show other)
  c <- completeJob env table JobDigest jid del (\_ -> pure ())
  case c of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "digest delivery bytes" cannedSig bs
    other -> assertFailure ("expected delivery, got " ++ show other)

caseRetentionBound :: IO ()
caseRetentionBound = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
      n = retentionCap + 64
  runs <- newIORef 0
  let run = countingRunner runs
  mapM_ (deliverOneDigest table env run del) [1 .. n]
  nRuns <- readIORef runs
  assertEqual "every digest drove its effect once" n nRuns
  writes <- writesOf cap
  assertEqual "every digest delivered exactly once" n (length writes)
  (live, term, nextId) <- tableStats table
  assertEqual "no live jobs left" 0 live
  assertEqual "tombstones bounded by the retention cap" retentionCap term
  assertEqual "job ids contiguous" n nextId
  -- Oldest-first eviction: the first jobs observe unknown, like
  -- reaped ones, while the newest delivery still observes its winner.
  pOld <- pollJob run env table JobDigest (JobId 0)
  assertEqual "evicted job polls unknown" PollUnknown pOld
  cOld <- completeJob env table JobDigest (JobId 0) del (\_ -> pure ())
  assertEqual "evicted job completes unknown" CompleteUnknown cOld
  cNew <- completeJob env table JobDigest (JobId (n - 1)) del (\_ -> pure ())
  case cNew of
    CompleteAlready (TermDelivered (CompBytes bs)) ->
      assertEqual "newest winner bytes" cannedSig bs
    other -> assertFailure ("expected newest already-delivered, got " ++ show other)

-- | Start and immediately cancel one job (a cheap terminal record).
cancelOneJob :: AsyncTable -> Int -> IO ()
cancelOneJob table _ = do
  eJid <- startJob table (signRequest sid1 5)
  jid <- case eJid of
    Right j -> pure j
    Left deny -> assertFailure ("fill start denied: " ++ show deny)
  k <- cancelJob table jid
  case k of
    CancelOk -> pure ()
    other -> assertFailure ("expected cancel win, got " ++ show other)

caseCappedSemantics :: IO ()
caseCappedSemantics = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
      tiny = captureDelivery 8 cap
  runs <- newIORef 0
  let run = countingRunner runs
  -- Fill past the cap so eviction is active for everything below.
  mapM_ (cancelOneJob table) [1 .. retentionCap + 16]
  (live0, term0, _) <- tableStats table
  assertEqual "fill leaves no live jobs" 0 live0
  assertEqual "store is at the retention cap" retentionCap term0
  -- Delivery: exact bytes, exactly once, winner observable.
  Right jd <- startJob table (digestRequest sid1 1)
  pD <- pollJob run env table JobDigest jd
  assertEqual "capped poll ready" PollReady pD
  cD <- completeJob env table JobDigest jd del (\_ -> pure ())
  case cD of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "capped delivery bytes" cannedSig bs
    other -> assertFailure ("expected capped delivery, got " ++ show other)
  assertWrites "capped delivery writes once" cap [goldenBytes]
  cD2 <- completeJob env table JobDigest jd del (\_ -> pure ())
  case cD2 of
    CompleteAlready (TermDelivered (CompBytes bs)) ->
      assertEqual "capped loser observes winner" cannedSig bs
    other -> assertFailure ("expected capped already-delivered, got " ++ show other)
  assertWrites "capped loser writes nothing" cap [goldenBytes]
  -- Retry: short sizes without delivering, roomy retry delivers once
  -- without re-running the effect.
  runsBefore <- readIORef runs
  Right jr <- startJob table (digestRequest sid1 1)
  pR <- pollJob run env table JobDigest jr
  assertEqual "retry poll ready" PollReady pR
  cShort <- completeJob env table JobDigest jr tiny (\_ -> pure ())
  assertEqual "capped short sizes" (CompleteShort 64) cShort
  assertWrites "capped short writes nothing" cap [goldenBytes]
  cRetry <- completeJob env table JobDigest jr del (\_ -> pure ())
  case cRetry of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "capped retry bytes" cannedSig bs
    other -> assertFailure ("expected capped retry delivery, got " ++ show other)
  runsAfter <- readIORef runs
  assertEqual "capped retry runs the effect once" (runsBefore + 1) runsAfter
  -- Cancel: wins on live, terminal observes, re-cancel observes.
  Right jc <- startJob table (signRequest sid1 5)
  k <- cancelJob table jc
  assertEqual "capped cancel wins" CancelOk k
  pC <- pollJob run env table JobSign jc
  assertEqual "capped poll sees cancel" (PollTerminal TermCanceled) pC
  cC <- completeJob env table JobSign jc del (\_ -> pure ())
  assertEqual "capped complete-after-cancel rejected"
    (CompleteAlready TermCanceled) cC
  k2 <- cancelJob table jc
  assertEqual "capped re-cancel observes" (CancelAlready TermCanceled) k2
  assertWrites "capped cancel writes no payload" cap [goldenBytes, goldenBytes]
  -- The bound holds throughout: evicted elders are unknown, the
  -- store never exceeds the cap.
  pOld <- pollJob run env table JobSign (JobId 0)
  assertEqual "evicted fill job polls unknown" PollUnknown pOld
  kOld <- cancelJob table (JobId 0)
  assertEqual "evicted fill job cancels unknown" CancelUnknown kOld
  rOld <- reapJob table (JobId 0)
  assertEqual "evicted fill job reaps unknown" ReapUnknown rOld
  (liveF, termF, _) <- tableStats table
  assertEqual "no live jobs left" 0 liveF
  assertEqual "store still at the retention cap" retentionCap termF

-- ---------------------------------------------------------------------------
-- Byte-budget retention bound (FINAL-19 fix round 1: dual bound)
-- ---------------------------------------------------------------------------

-- | A planned async digest with a caller-sized input: the input is
-- attacker-sized (no submit-time input cap), so each tombstone
-- retains its full input until evicted or reaped.
bigDigestRequest :: SessionId -> Int -> ByteString -> JobRequest
bigDigestRequest sid ticks input = JobRequest
  { jrSession = sid
  , jrFunction = JobDigest
  , jrWork = WorkCall
      (Reservation "async-digest-test" [] Nothing Nothing)
      (EffectCrypto (FxDigest (MechanismId 0x250) input))
  , jrTicks = ticks
  , jrCapacity = 64
  }

-- | Start, drive, and deliver one caller-sized digest; every
-- delivery carries the canned bytes exactly once. Each job gets a
-- DISTINCT input allocation (no sharing between tombstones).
deliverOneBigDigest
  :: AsyncTable -> Env -> (CryptoEffect -> IO CryptoResult) -> Delivery -> Int -> Int -> IO ()
deliverOneBigDigest table env run del size i = do
  let input = BS.replicate size (fromIntegral i)
  eJid <- startJob table (bigDigestRequest sid1 1 input)
  jid <- case eJid of
    Right j -> pure j
    Left deny -> assertFailure ("big digest start denied: " ++ show deny)
  p <- pollJob run env table JobDigest jid
  case p of
    PollReady -> pure ()
    other -> assertFailure ("expected ready, got " ++ show other)
  c <- completeJob env table JobDigest jid del (\_ -> pure ())
  case c of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "big digest delivery bytes" cannedSig bs
    other -> assertFailure ("expected delivery, got " ++ show other)

caseByteRetentionBound :: IO ()
caseByteRetentionBound = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
      -- 16 x 8 MiB = 128 MiB of retained inputs on an unbounded
      -- tree: past any meaningful byte budget while far below the
      -- 4096 count cap, so only byte eviction can explain shrinkage.
      size = 8 * 1024 * 1024
      n = 16
  runs <- newIORef 0
  let run = countingRunner runs
  mapM_ (deliverOneBigDigest table env run del size) [1 .. n]
  nRuns <- readIORef runs
  assertEqual "every big digest drove its effect once" n nRuns
  writes <- writesOf cap
  assertEqual "every big digest delivered exactly once" n (length writes)
  (live, term, _) <- tableStats table
  assertEqual "no live jobs left" 0 live
  bytes <- retainedBytes table
  if bytes <= maxRetainedBytes
    then pure ()
    else assertFailure
      ("retained bytes exceed budget: " ++ show bytes
        ++ " > " ++ show (maxRetainedBytes :: Int))
  -- Exact eviction shape: each tombstone prices at 2048 + 17*48 +
  -- 8 MiB + 64 = 8391536 bytes; 7 fit in 64 MiB (58740752) but 8
  -- do not (67132288), so minimal-prefix oldest-first eviction
  -- keeps exactly the newest 7 (ids 9..15).
  assertEqual "byte eviction keeps the newest 7 of 16" 7 term
  -- Oldest-first eviction: the first job observes unknown while the
  -- newest delivery still observes its winner.
  pOld <- pollJob run env table JobDigest (JobId 0)
  assertEqual "evicted big job polls unknown" PollUnknown pOld
  pEdge <- pollJob run env table JobDigest (JobId 8)
  assertEqual "prefix-minimal edge evicted" PollUnknown pEdge
  cEdge <- completeJob env table JobDigest (JobId 9) del (\_ -> pure ())
  case cEdge of
    CompleteAlready (TermDelivered (CompBytes bs)) ->
      assertEqual "oldest retained winner bytes" cannedSig bs
    other -> assertFailure
      ("expected oldest-retained already-delivered, got " ++ show other)
  cNew <- completeJob env table JobDigest (JobId (n - 1)) del (\_ -> pure ())
  case cNew of
    CompleteAlready (TermDelivered (CompBytes bs)) ->
      assertEqual "newest big winner bytes" cannedSig bs
    other -> assertFailure ("expected newest already-delivered, got " ++ show other)

-- | The byte budget clears suite-shaped fills: the small-digest
-- fill is the heaviest suite shape (it prices above sim signs
-- and canceled signs), so pinning it bounds them all. The count
-- cap — never the byte budget — must bound small fills, and the
-- budget must stay within 8x of the suite worst case (a
-- meaningful bound, not a decoration).
caseByteBudgetHeadroom :: IO ()
caseByteBudgetHeadroom = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
      n = retentionCap + 64
  runs <- newIORef 0
  let run = countingRunner runs
  mapM_ (deliverOneDigest table env run del) [1 .. n]
  (live, term, _) <- tableStats table
  assertEqual "no live jobs left" 0 live
  assertEqual "count cap (not the byte budget) bounds small fills"
    retentionCap term
  bytes <- retainedBytes table
  if bytes <= maxRetainedBytes
    then pure ()
    else assertFailure
      ("suite-shaped fill exceeds byte budget: " ++ show bytes)
  if bytes > maxRetainedBytes `div` 8
    then pure ()
    else assertFailure
      ("byte budget exceeds 8x the suite-shaped worst case: " ++ show bytes)

-- | Start and immediately cancel one job built from the given
-- request: a cheap terminal record that retains its full work.
cancelOneRequest :: AsyncTable -> JobRequest -> IO ()
cancelOneRequest table req = do
  eJid <- startJob table req
  jid <- case eJid of
    Right j -> pure j
    Left deny -> assertFailure ("field probe start denied: " ++ show deny)
  k <- cancelJob table jid
  case k of
    CancelOk -> pure ()
    other -> assertFailure ("expected cancel win, got " ++ show other)

-- | Retained bytes of a fresh table holding 4 canceled jobs built
-- from the given request. Cancellation retains the full work
-- with no delivery, so field-coverage deltas need no model
-- state and no finisher.
canceledBytes :: JobRequest -> IO Int
canceledBytes req = do
  (table, _) <- mkTable
  mapM_ (\_ -> cancelOneRequest table req) [1 .. 4 :: Int]
  retainedBytes table

-- | The byte ruler prices every retained field: exact deltas
-- when exactly one field varies (shape fixed, so allowances and
-- overhead cancel). One case per ByteString-bearing effect
-- field (input, params, AAD, signature — including the
-- input-less 'FxVerifyRecover' arm), plus template bytes,
-- completion payloads, and pinned snapshot bytes.
caseByteAccountingFields :: IO ()
caseByteAccountingFields = do
  let mechS = MechanismId 0x251
      fxReq fx = JobRequest
        { jrSession = sid1
        , jrFunction = JobSign
        , jrWork = WorkCall
            (Reservation "field-probe" [] Nothing Nothing)
            (EffectCrypto fx)
        , jrTicks = 1
        , jrCapacity = 64
        }
      base = FxSign mechS Nothing BS.empty "hello"
  bInBase <- canceledBytes (fxReq base)
  bInBig <- canceledBytes
    (fxReq (FxSign mechS Nothing BS.empty (BS.replicate 1024 0x41)))
  assertEqual "input bytes priced" (4 * 1019) (bInBig - bInBase)
  bParams <- canceledBytes
    (fxReq (FxSign mechS Nothing (BS.replicate 1024 0x41) "hello"))
  assertEqual "params bytes priced" (4 * 1024) (bParams - bInBase)
  bAadBase <- canceledBytes
    (fxReq (FxMessageCipher DirEncrypt mechS Nothing BS.empty BS.empty "hi"))
  bAad <- canceledBytes (fxReq
    (FxMessageCipher DirEncrypt mechS Nothing BS.empty (BS.replicate 1024 0x41) "hi"))
  assertEqual "AAD bytes priced" (4 * 1024) (bAad - bAadBase)
  bSigBase <- canceledBytes
    (fxReq (FxVerifyRecover mechS Nothing BS.empty BS.empty 0))
  bSig <- canceledBytes (fxReq
    (FxVerifyRecover mechS Nothing BS.empty (BS.replicate 1024 0x41) 0))
  assertEqual "signature bytes priced" (4 * 1024) (bSig - bSigBase)
  -- Resourceless shapes price their (absent) payloads at zero.
  bConsume <- canceledBytes (fxReq (FxDigestConsume (EngineResourceId 7)))
  bEmptyDigest <- canceledBytes
    (fxReq (FxDigest (MechanismId 0x250) BS.empty))
  assertEqual "empty payloads price identically" bEmptyDigest bConsume
  -- Template bytes: one entry each, so the per-entry allowance
  -- cancels and the delta is pure payload.
  let keyReq tmpl = JobRequest
        { jrSession = sid1
        , jrFunction = JobGenKey
        , jrWork = WorkKey
            (Reservation "field-probe" [] Nothing Nothing)
            (PwGenerateKey (PendingObject tmpl Nothing (SlotId 0)))
            (FxGenerateKey (MechanismId 0x108) BS.empty BS.empty)
        , jrTicks = 1
        , jrCapacity = 64
        }
      tmpl1 = Map.singleton AttrLabel (ValBytes (BS.replicate 1024 0x41))
      tmpl2 = Map.singleton AttrLabel (ValBytes (BS.replicate 2048 0x41))
  bTmpl1 <- canceledBytes (keyReq tmpl1)
  bTmpl2 <- canceledBytes (keyReq tmpl2)
  assertEqual "template bytes priced" (4 * 1024) (bTmpl2 - bTmpl1)
  -- Completion payloads: 64-byte vs 128-byte stub answers.
  -- Both sides share one roomy request shape (attached capacity
  -- 256 covers the 128-byte delivery), so only the payload varies.
  let roomySign = (signRequest sid1 1) { jrCapacity = 256 }
      deliverSign t e run d want = do
        ej <- startJob t roomySign
        jid <- case ej of
          Left deny -> assertFailure ("completion probe denied: " ++ show deny)
          Right j -> pure j
        p <- pollJob run e t JobSign jid
        case p of
          PollReady -> pure ()
          other -> assertFailure ("completion probe not ready: " ++ show other)
        co <- completeJob e t JobSign jid d (\_ -> pure ())
        case co of
          CompleteDelivered (CompBytes bs) ->
            assertEqual "completion probe bytes" want bs
          other -> assertFailure ("completion probe no delivery: " ++ show other)
      deliveredBytes answer = do
        (t, e) <- mkTable
        c <- newCapture
        let d = captureDelivery 256 c
        mapM_ (\_ -> deliverSign t e
          (\_ -> pure (GotBytes answer)) d answer) [1 .. 4 :: Int]
        retainedBytes t
  bComp64 <- deliveredBytes cannedSig
  bComp128 <- deliveredBytes (BS.replicate 128 0x42)
  assertEqual "completion bytes priced" (4 * 64) (bComp128 - bComp64)
  -- Pinned snapshots: one sign slot with empty params, so each
  -- snapshot prices at 256 (structural) + buffered; both the
  -- post-plan ops and the session state pin it (x2).
  let snapOps bufLen = insertOp
        (mkActiveSign (setBuffered (BS.replicate bufLen 0x43)
          (mkSlotCommon (MechanismId 0x251) OpSign Nothing BS.empty AuthNone)))
        emptySessionOps
      snapSession ops = SessionState
        { ssId = sid1
        , ssSlot = SlotId 0
        , ssRevision = Revision 0
        , ssGeneration = Generation 0
        , ssReadOnly = False
        , ssLogin = LoginPublic
        , ssOps = ops
        }
      snapReq ops = JobRequest
        { jrSession = sid1
        , jrFunction = JobSign
        , jrWork = WorkCall
            (Reservation "field-probe" [] Nothing (Just (CryptoStep
              F_Sign SlotSign "" (IntentBuffer 0) ops (snapSession ops))))
            (EffectCrypto base)
        , jrTicks = 1
        , jrCapacity = 64
        }
  bSnap100 <- canceledBytes (snapReq (snapOps 100))
  assertEqual "snapshot bytes priced" (4 * 2 * (256 + 100)) (bSnap100 - bInBase)
  bSnap200 <- canceledBytes (snapReq (snapOps 200))
  assertEqual "snapshot payload delta priced"
    (4 * 2 * 100) (bSnap200 - bSnap100)

-- | Delivery + retry + cancel semantics under BYTE eviction (the
-- F-3 variant re-verified with the byte bound as the active
-- evictor): fill past the byte budget with max-size jobs, then
-- exercise all three against the byte-capped store.
caseByteEvictionSemantics :: IO ()
caseByteEvictionSemantics = do
  (table, env) <- mkTable
  capFill <- newCapture
  let delFill = captureDelivery 64 capFill
      size = 8 * 1024 * 1024
  runs <- newIORef 0
  let run = countingRunner runs
  -- Fill past the BYTE budget (16 x 8 MiB); the count cap (4096)
  -- cannot explain any shrinkage here.
  mapM_ (deliverOneBigDigest table env run delFill size) [1 .. 16]
  (live0, term0, _) <- tableStats table
  bytes0 <- retainedBytes table
  assertEqual "fill leaves no live jobs" 0 live0
  if bytes0 <= maxRetainedBytes
    then pure ()
    else assertFailure
      ("byte fill exceeds budget: " ++ show bytes0)
  assertEqual "byte fill keeps 7" 7 term0
  -- Fresh capture for the semantics phases below.
  cap <- newCapture
  let del = captureDelivery 64 cap
      tiny = captureDelivery 8 cap
  -- Delivery: exact bytes, exactly once, winner observable.
  Right jd <- startJob table (digestRequest sid1 1)
  pD <- pollJob run env table JobDigest jd
  assertEqual "byte-capped poll ready" PollReady pD
  cD <- completeJob env table JobDigest jd del (\_ -> pure ())
  case cD of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "byte-capped delivery bytes" cannedSig bs
    other -> assertFailure ("expected byte-capped delivery, got " ++ show other)
  assertWrites "byte-capped delivery writes once" cap [goldenBytes]
  cD2 <- completeJob env table JobDigest jd del (\_ -> pure ())
  case cD2 of
    CompleteAlready (TermDelivered (CompBytes bs)) ->
      assertEqual "byte-capped loser observes winner" cannedSig bs
    other -> assertFailure
      ("expected byte-capped already-delivered, got " ++ show other)
  assertWrites "byte-capped loser writes nothing" cap [goldenBytes]
  -- Retry: short sizes without delivering, roomy retry delivers once
  -- without re-running the effect.
  runsBefore <- readIORef runs
  Right jr <- startJob table (digestRequest sid1 1)
  pR <- pollJob run env table JobDigest jr
  assertEqual "retry poll ready" PollReady pR
  cShort <- completeJob env table JobDigest jr tiny (\_ -> pure ())
  assertEqual "byte-capped short sizes" (CompleteShort 64) cShort
  assertWrites "byte-capped short writes nothing" cap [goldenBytes]
  cRetry <- completeJob env table JobDigest jr del (\_ -> pure ())
  case cRetry of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "byte-capped retry bytes" cannedSig bs
    other -> assertFailure
      ("expected byte-capped retry delivery, got " ++ show other)
  runsAfter <- readIORef runs
  assertEqual "byte-capped retry runs the effect once"
    (runsBefore + 1) runsAfter
  -- Cancel: wins on live, terminal observes, re-cancel observes.
  Right jc <- startJob table (signRequest sid1 5)
  k <- cancelJob table jc
  assertEqual "byte-capped cancel wins" CancelOk k
  pC <- pollJob run env table JobSign jc
  assertEqual "byte-capped poll sees cancel" (PollTerminal TermCanceled) pC
  cC <- completeJob env table JobSign jc del (\_ -> pure ())
  assertEqual "byte-capped complete-after-cancel rejected"
    (CompleteAlready TermCanceled) cC
  k2 <- cancelJob table jc
  assertEqual "byte-capped re-cancel observes" (CancelAlready TermCanceled) k2
  assertWrites "byte-capped cancel writes no payload"
    cap [goldenBytes, goldenBytes]
  -- The byte bound holds throughout: evicted elders are unknown,
  -- the small jobs fit beside the 7 big ones without further
  -- eviction (58.7 MiB + ~9 KiB stays within budget).
  pOld <- pollJob run env table JobDigest (JobId 0)
  assertEqual "evicted big job polls unknown" PollUnknown pOld
  kOld <- cancelJob table (JobId 0)
  assertEqual "evicted big job cancels unknown" CancelUnknown kOld
  rOld <- reapJob table (JobId 0)
  assertEqual "evicted big job reaps unknown" ReapUnknown rOld
  (liveF, termF, _) <- tableStats table
  bytesF <- retainedBytes table
  assertEqual "no live jobs left" 0 liveF
  assertEqual "store holds 7 big + 3 small" 10 termF
  if bytesF <= maxRetainedBytes
    then pure ()
    else assertFailure
      ("byte-capped store exceeds budget: " ++ show bytesF)

-- ---------------------------------------------------------------------------
-- Fix round 2 / finding 1: retained slices keep their backing alive
-- ---------------------------------------------------------------------------

-- | Backing-store aliasing oracle, INDEPENDENT of 'retainedBytes':
-- 'True' iff 'small' starts 'offset' bytes into 'big''s live
-- storage (read-only pointer comparison; both inputs stay alive
-- for the comparison). A retained slice aliasing a large backing
-- allocation keeps the whole allocation alive while the ruler
-- prices only the slice length, so aliasing here is the retention
-- violation itself — observed at the heap layout, not via the
-- ruler asserting about itself.
aliasingAt :: ByteString -> ByteString -> Int -> IO Bool
aliasingAt big small offset =
  unsafeUseAsCStringLen big $ \(bigPtr, _) ->
    unsafeUseAsCStringLen small $ \(smallPtr, _) ->
      pure (smallPtr == bigPtr `plusPtr` offset)

cbcMech :: MechanismId
cbcMech = MechanismId 0x1082

-- | A padded-CBC slot with an empty buffer (hand-built: with
-- 'AuthNone' and a public session the data gate passes, so no
-- init flow is needed).
cbcSlotOps :: CipherDir -> Operation -> SessionOps
cbcSlotOps dir op = insertOp
  (mkActiveCipher dir
    (mkSlotCommon cbcMech op Nothing (BS.replicate 16 0) AuthNone)
    (CipherSpec 16 True))
  emptySessionOps

-- | Every small cipher bytestring a slot retains (CBC tails,
-- decrypt chains, retained update suffixes) must be an
-- independent copy: async snapshots pin slot state, so a slice
-- would keep a whole multi-MiB backing allocation alive behind a
-- 16-byte ruler price. The oracle is backing-store aliasing (see
-- 'aliasingAt'), never the ruler.
caseCipherSlicesIndependent :: IO ()
caseCipherSlicesIndependent = do
  let mib = 1024 * 1024
      st = SessionState
        { ssId = sid1
        , ssSlot = SlotId 0
        , ssRevision = Revision 0
        , ssGeneration = Generation 0
        , ssReadOnly = False
        , ssLogin = LoginPublic
        , ssOps = emptySessionOps
        }
  -- (1) Encrypt-update finish: the CBC tail of a 1 MiB driver
  -- answer must be an independent copy.
  let raw = BS.replicate mib 0xAB
      (opsE, finE) = finishCipherUpdate
        (cbcSlotOps DirEncrypt OpEncrypt) SlotEncrypt "cbc-tail"
        (GotBytes raw) (IntentBuffer (4 * fromIntegral mib))
  assertEqual "encrypt finish ok" CKR_OK (soCode finE)
  scE <- case lookupSingle opsE SlotEncrypt of
    Just active -> pure (commonOf active)
    Nothing -> assertFailure "encrypt slot gone after finish"
  tailE <- case chainIvOf scE of
    Just t | BS.length t == 16 -> pure t
    other -> assertFailure
      ("expected 16-byte chain tail, got " ++ show (fmap BS.length other))
  assertEqual "tail bytes are the answer tail"
    (BS.drop (mib - 16) raw) tailE
  aliasedE <- aliasingAt raw tailE (mib - 16)
  assertBool "CBC finish tail must not alias the driver answer"
    (not aliasedE)
  -- (2) Decrypt-update plan over 1 MiB: the plan-time chain and
  -- the retained suffix must not alias the planned input's
  -- storage. Both slice the fresh full buffer, so the oracle
  -- compares against the co-sliced stream bytes (same backing):
  -- adjacency proves sharing, separation proves independence.
  let big = BS.replicate mib 0xCD
      (opsP, _, updP) = planCipherUpdate
        (cbcSlotOps DirDecrypt OpDecrypt) st SlotDecrypt big Nothing
  assertEqual "decrypt plan ok" CKR_OK (soCode updP)
  stream <- case soEffects updP of
    [FxCipher DirDecrypt _ _ _ input] -> pure input
    other -> assertFailure
      ("expected one decrypt effect, got " ++ show (length other))
  scP <- case lookupSingle opsP SlotDecrypt of
    Just active -> pure (commonOf active)
    Nothing -> assertFailure "decrypt slot gone after plan"
  let retained = bufferedOf scP
  assertBool "retained suffix nonempty" (not (BS.null retained))
  assertEqual "retained bytes are the input tail"
    (BS.drop (mib - BS.length retained) big) retained
  adjRet <- aliasingAt stream retained (BS.length stream)
  assertBool "retained suffix must not alias the planned input"
    (not adjRet)
  chainP <- case chainIvOf scP of
    Just c | not (BS.null c) -> pure c
    _ -> assertFailure "expected decrypt chain block"
  assertEqual "chain bytes are the stream tail"
    (BS.drop (BS.length stream - BS.length chainP) stream) chainP
  adjChain <- aliasingAt stream chainP
    (BS.length stream - BS.length chainP)
  assertBool "decrypt chain must not alias the planned input"
    (not adjChain)
  -- (3) Snapshot pinning: the finished ops embed in a real
  -- submitted job's reservation snapshot (both the post-plan ops
  -- and the session state pin them), and the pinned tail is that
  -- same independent copy.
  let snapReq = JobRequest
        { jrSession = sid1
        , jrFunction = JobDigest
        , jrWork = WorkCall
            (Reservation "tail-snap" [] Nothing (Just (CryptoStep
              F_Digest SlotEncrypt "" (IntentBuffer 0) opsE
              (st { ssOps = opsE }))))
            (EffectCrypto (FxDigest (MechanismId 0x250) "abc"))
        , jrTicks = 1
        , jrCapacity = 64
        }
  (tableSnap, _) <- mkTable
  cancelOneRequest tableSnap snapReq
  pinTail <- case lookupSingle opsE SlotEncrypt of
    Just active -> case chainIvOf (commonOf active) of
      Just t -> pure t
      Nothing -> assertFailure "pinned tail lost its chain"
    Nothing -> assertFailure "pinned tail lost its slot"
  aliasedPin <- aliasingAt raw pinTail (mib - 16)
  assertBool "snapshot-pinned tail must not alias the driver answer"
    (not aliasedPin)

-- ---------------------------------------------------------------------------
-- Fix round 2 / finding 2: commits must not retain the pre-eviction map
-- ---------------------------------------------------------------------------

-- | Submit and immediately cancel one independently-oversized
-- digest, answering a weak pointer to its input payload. The
-- payload's only strong reference after this returns is the
-- table's tombstone (canceled jobs retain their full work), so
-- the weak pointer observes exactly what the table retains.
submitCanceledBig :: AsyncTable -> Int -> Word8 -> IO (Weak ())
submitCanceledBig table size fill = do
  let input = BS.replicate size fill
  w <- mkWeak input () Nothing
  eJid <- startJob table (bigDigestRequest sid1 5 input)
  jid <- case eJid of
    Right j -> pure j
    Left deny -> assertFailure ("oversized start denied: " ++ show deny)
  k <- cancelJob table jid
  case k of
    CancelOk -> pure ()
    other -> assertFailure ("expected cancel win, got " ++ show other)
  pure w

-- | Committed eviction reclaims without a later table read:
-- cancel two independently-oversized jobs, then idle — no poll,
-- complete, stats, or byte census, since any table read would
-- force a lazy prune and conceal the violation — collect, and
-- prove the evicted elder's payload is gone while the single
-- oversized-job exception keeps the newest. The oracle is object
-- reachability ('Weak' + 'performGC'), never a table read.
caseCommitReclaimsWithoutRead :: IO ()
caseCommitReclaimsWithoutRead = do
  (table, _) <- mkTable
  let size = 65 * 1024 * 1024
  wOld <- submitCanceledBig table size 0x41
  _ <- submitCanceledBig table size 0x42
  -- Oracle first: NO atJobs read may precede it — any read
  -- would force a lazy prune and conceal the violation. Collect
  -- twice with allocation churn between: the churn recycles
  -- dead frames from the submit phase that might otherwise hold
  -- a transient GC root to the evicted payload, so the oracle
  -- observes only table reachability.
  performGC
  churnDeadRoots
  performGC
  mOld <- deRefWeak wOld
  -- Liveness pin (post-observation): the jobs map must be used
  -- after the GC, else the whole table is dead at 'performGC'
  -- and both payloads collect vacuously. IO ordering guarantees
  -- this read — and any forcing it performs — happens strictly
  -- after the oracle above, so it cannot conceal anything.
  (live, term, _) <- tableStats table
  assertEqual "eviction left exactly the newest tombstone" (0, 1) (live, term)
  assertEqual "evicted oversized payload reclaimed without a table read"
    Nothing mOld
  -- Newest-retention oracle (post-observation table read): the newest
  -- payload is proven retained by MEASURED BYTES, never by heap-object
  -- identity — a 'Weak' observation of the newest input is
  -- instrumentation-fragile (transient-root survival differs under
  -- -fhpc: the identity assert failed 3/3 instrumented runs while
  -- (live, term) == (0, 1) and the elder oracle held), while the exact
  -- byte ruler is layout-independent. The 65 MiB payload alone exceeds
  -- the 64 MiB budget; with exactly one tombstone left and the elder
  -- proven reclaimed above, bytes over budget ⟹ the single
  -- oversized-job exception retains the newest.
  bytes <- retainedBytes table
  assertBool ("single oversized-job exception retains the newest: "
    ++ show bytes ++ " bytes") (bytes > maxRetainedBytes)

-- | Allocate garbage through fresh deep call depth, recycling
-- dead stack slots left by the submit phase (see
-- 'caseCommitReclaimsWithoutRead').
churnDeadRoots :: IO ()
churnDeadRoots = deep (0 :: Int) >> pure ()
  where
    deep :: Int -> IO Int
    deep n
      | n >= 5000 = pure n
      | otherwise = do
          m <- deep (n + 1)
          let bs = BS.replicate 64 (fromIntegral (m + n))
          pure (m + BS.length bs)

-- ---------------------------------------------------------------------------
-- Fix round 2 / finding 3: eviction must not fabricate observations
-- ---------------------------------------------------------------------------

numRaceSpinners :: Int
numRaceSpinners = 16

isWinnerOrUnknownPoll :: PollOutcome -> Bool
isWinnerOrUnknownPoll (PollTerminal (TermDelivered (CompBytes bs))) = bs == cannedSig
isWinnerOrUnknownPoll PollUnknown = True
isWinnerOrUnknownPoll _ = False

isWinnerOrUnknownComplete :: CompleteOutcome -> Bool
isWinnerOrUnknownComplete (CompleteAlready (TermDelivered (CompBytes bs))) =
  bs == cannedSig
isWinnerOrUnknownComplete CompleteUnknown = True
isWinnerOrUnknownComplete _ = False

-- | Race harness: 'fill' leaves the victim (JobId 0, delivered)
-- as the oldest terminal at the trigger edge; 'evict' performs
-- one terminal commit that evicts it. Spinner observers hammer
-- the victim across the eviction (their lease queue stretches
-- every admission-to-reread window, so eviction lands mid-window
-- with near certainty); every observation must be the winner or
-- unknown — never a fabricated terminal. Spinner threads never
-- assert: they record outcomes for the main thread to classify.
raceEvictionObservation :: AsyncTable -> Env -> Delivery -> IO () -> IO () -> IO ()
raceEvictionObservation table env del fill evict = do
  let run = const (pure (GotBytes cannedSig))
  fill
  stopRef <- newIORef False
  outcomeRef <- newIORef []
  dones <- mapM (\_ -> newEmptyMVar) [1 .. numRaceSpinners]
  let spin done = do
        let loop = do
              p <- pollJob run env table JobDigest (JobId 0)
              c <- completeJob env table JobDigest (JobId 0) del (\_ -> pure ())
              atomicModifyIORef' outcomeRef (\xs -> ((p, c) : xs, ()))
              stop <- readIORef stopRef
              if stop then pure () else loop
        loop
        putMVar done ()
  mapM_ (forkIO . spin) dones
  threadDelay 100000
  evict
  writeIORef stopRef True
  mapM_ takeMVar dones
  outcomes <- readIORef outcomeRef
  assertBool "spinners observed the race" (not (null outcomes))
  let bad = [(p, c) | (p, c) <- outcomes
                    , not (isWinnerOrUnknownPoll p)
                      || not (isWinnerOrUnknownComplete c)]
  assertEqual "every raced observation is winner-or-unknown" [] bad
  -- Deterministic post-race: the victim is long evicted.
  pFinal <- pollJob run env table JobDigest (JobId 0)
  assertEqual "evicted victim polls unknown" PollUnknown pFinal
  cFinal <- completeJob env table JobDigest (JobId 0) del (\_ -> pure ())
  assertEqual "evicted victim completes unknown" CompleteUnknown cFinal

-- | Observation race under the COUNT trigger: the victim plus
-- 4095 canceled jobs pin the table at the cap; one more
-- delivered digest evicts the victim mid-observation.
caseEvictionRaceCount :: IO ()
caseEvictionRaceCount = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
      run0 = const (pure (GotBytes cannedSig))
  raceEvictionObservation table env del
    (do deliverOneDigest table env run0 del 0
        mapM_ (cancelOneJob table) [1 .. retentionCap - 1])
    (deliverOneDigest table env run0 del 999999)

-- | Observation race under the BYTE trigger: the victim plus 7
-- max-size digests sit just under budget; one more max-size
-- digest evicts the victim mid-observation.
caseEvictionRaceBytes :: IO ()
caseEvictionRaceBytes = do
  (table, env) <- mkTable
  cap <- newCapture
  let del = captureDelivery 64 cap
      run0 = const (pure (GotBytes cannedSig))
      size = 8 * 1024 * 1024
  raceEvictionObservation table env del
    (do deliverOneDigest table env run0 del 0
        mapM_ (deliverOneBigDigest table env run0 del size) [1 .. 7])
    (deliverOneBigDigest table env run0 del size 8)

