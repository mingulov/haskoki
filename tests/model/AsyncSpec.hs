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
import Control.Concurrent (forkIO, newEmptyMVar, putMVar, takeMVar, tryTakeMVar)
import Data.IORef (IORef, newIORef, readIORef, modifyIORef')
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), SessionState (..), lookupSession)
import Haskoki.Object (encodeHandle)
import Haskoki.Operation (CryptoEffect (..), CryptoError (..), CryptoResult (..))
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Operation.KeyManagement
  ( KeyPlan (..)
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
import Haskoki.Outcome
  ( EffectRequest (..)
  , EngineResult (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Reservation (..)
  , ResourceRelease (..)
  , RevisionDep (..)
  )
import Haskoki.Output (maxOutputBytes)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request (FunctionId (..), OutputIntent (..), OutputRegion (..), Request (..))
import Haskoki.Rules (defaultRules)
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
  , newAsyncTable
  , pollJob
  , reapJob
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
  , JobId (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
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
  (pw, fx) <- case planGenerateKey defaultRules m0 st aesKeyGenMech (aesTmpl 32) of
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
  (pw, fx) <- case planGenerateKey defaultRules m0 st aesKeyGenMech (aesTmpl 32) of
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
  (pw, fx) <- case planGenerateKey defaultRules m0 st aesKeyGenMech (aesTmpl 32) of
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
