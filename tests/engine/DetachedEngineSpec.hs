{- | Detached-job engine proofs: every synthetic persistable workflow detaches
and rejoins, real-adapter opaque contexts take the permitted typed
unsaveable outcome, and the SQLite file store survives close\/reopen.
-}
{-# LANGUAGE OverloadedStrings #-}
module DetachedEngineSpec (spec) where

import Control.Concurrent.MVar (MVar)
import Control.Exception (bracket, finally)
import Control.Monad (forM_, replicateM, when)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.IORef (IORef, newIORef, modifyIORef', readIORef, writeIORef)
import qualified Data.Map.Strict as Map
import Data.List (isInfixOf)
import Data.Word (Word64, Word8)
import EnvLock (withEnvLock)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Array (peekArray, pokeArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.StablePtr (StablePtr, castPtrToStablePtr, castStablePtrToPtr, deRefStablePtr, newStablePtr, freeStablePtr)
import Foreign.Storable (peek, poke, peekByteOff, pokeByteOff)
import System.Directory
  ( createDirectory
  , createDirectoryIfMissing
  , doesDirectoryExist
  , getTemporaryDirectory
  , removeDirectoryRecursive
  )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (releaseResource)
  , EngineResult (..)
  , KeyMaterial (..)
  , closeBackend
  , openBackend
  )
import Haskoki.Engine.Driver (KeyResolver, runEffect)
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.Engine.Synthetic (Synthetic (..))
import Haskoki.FFI.Async
  ( AsyncCtx (..)
  , AsyncData
  , JobHandle
  , StoreBox
  , asyncLiveHandles
  , haskokiAsyncClose
  , haskokiAsyncComplete
  , haskokiAsyncDigestInit
  , haskokiAsyncGetId
  , haskokiAsyncJoin
  , haskokiAsyncOpen
  , haskokiAsyncOpenOn
  , haskokiAsyncPoll
  , haskokiAsyncStart
  , haskokiAsyncStoreClose
  , haskokiAsyncStoreOpen
  )
import Haskoki.FFI.Standard
  ( StdAcquisition (..), StdAsyncBinding (..), StdInstance (..), StdStore (..)
  , haskokiStdAsyncComplete, haskokiStdAsyncGetId, haskokiStdAsyncJoin
  , haskokiStdClose, haskokiStdCloseSession, haskokiStdSessionCancel
  , haskokiStdDigest, haskokiStdDigestInit, haskokiStdOpenSessionWithAsync
  , lookupStdAsyncBinding, openStdInstanceWith, stdAcquisition, stdRvOf
  )
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState (..)
  , lookupObject
  , lookupSession
  , lookupTokenAuth
  )
import Haskoki.Object (encodeHandle)
import Haskoki.Operation (CryptoEffect (..), CryptoResult (..))
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Operation.KeyManagement
  ( KeyPlan (..)
  , aesKeyGenMech
  , ckkAes
  , ckkMlKem
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , planGenerateKey
  , planGenerateKeyPair
  )
import Haskoki.Operation.Kem (mlKemKeyPairGenMech)
import Haskoki.Outcome
  ( DeltaOp (..)
  , EffectRequest (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Reservation (..)
  , ResourceRelease (..)
  , RevisionDep (..)
  , StateDelta (..)
  )
import qualified Haskoki.Outcome as O
import Haskoki.Output (maxOutputBytes)
import Haskoki.Registry (MechanismId (..), Operation (..))
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
  , CompleteOutcome (..)
  , Completion (..)
  , Delivery (..)
  , JobFunction (..)
  , JobRequest (..)
  , PollOutcome (..)
  , enableAsyncSession
  , deliveredCount
  , sessionJobs
  , tableStats
  , newAsyncTable
  , pollJob
  , startJob
  )
import Haskoki.Runtime.Config (resolveFrom)
import Haskoki.Runtime.Detached
  ( AttachmentView (..)
  , DetachCtx
  , DetachOutcome (..)
  , JoinOutcome (..)
  , JoinRequest (..)
  , JoinedComplete (..)
  , completeJoined
  , detachCode
  , detachJob
  , inspectAttachment
  , joinJob
  , markJobOpaque
  , openDetached
  )
import Haskoki.Runtime.Lifecycle
  ( Env
  , defaultInitArgs
  , initialize
  , newEnv
  , publish
  , restoreStoreState
  , seatToken
  , snapshotModel
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , JobBody (..)
  , JobExecState (..)
  , JobRecord (..)
  , ObjectRecord (..)
  , Store (..)
  , StoreError (..)
  , StoreDelta (..)
  , StoredDoc (..)
  , TokenRecord (..)
  , docTopKeys
  , emptyDelta
  )
import Haskoki.Runtime.Storage.Memory
  ( MemoryWorld
  , newMemoryWorld
  , openMemoryStore
  )
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Session (ActiveLogin (..), TokenAuth (..), tokenAuthNew)
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
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

spec :: MVar () -> TestTree
spec envLock = testGroup "Detached engine"
  [ testCase "synthetic digest detaches and rejoins" caseSynthDigest
  , testCase "synthetic hmac sign detaches and rejoins" caseSynthSign
  , testCase "synthetic genkey detaches; rejoin mints fresh" caseSynthGenKey
  , testCase "synthetic genkeypair detaches and rejoins" caseSynthGenKeyPair
  , testCase "OpenSSL4 opaque: unsaveable typed, KAT kept" caseNativeUnsaveable
  , testCase "SQLite file store survives close and reopen" caseSQLiteReopen
  , testCase "durable job docs carry no addresses" caseNoAddresses
  , testCase "FFI detach: get_id, close, reopen, join, KAT" (caseFfiDetachRejoin envLock)
  , testCase "FFI detach without a store fails typed" (caseFfiNoStore envLock)
  , testCase "FFI join refusals are typed" (caseFfiJoinRefusals envLock)
  , testCase "caseAsyncJoinBoundary" (caseAsyncJoinBoundary envLock)
  , testCase "caseAsyncReadyJoinCapacity" (caseAsyncReadyJoinCapacity envLock)
  , testCase "caseAsyncOpaqueSurface" (caseAsyncOpaqueSurface envLock)
  , testCase "restoreStoreState reloads tokens and objects" caseRestoreStoreState
  ]

tokHome :: TokenId
tokHome = TokenId 1

slotHome :: SlotId
slotHome = SlotId 0

sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

hmacMech :: MechanismId
hmacMech = MechanismId 0x251

hmacOid :: ObjectId
hmacOid = ObjectId 21

hmacHandle :: ExternalHandle
hmacHandle = ExternalHandle 201

hmacKey1 :: ByteString
hmacKey1 = BS.replicate 20 0x0b

keyResolver :: KeyResolver
keyResolver oid
  | oid == hmacOid = Just (KeyBytes hmacKey1)
  | otherwise = Nothing

-- | FIPS 180-4: SHA-256("abc").
sha256Abc :: ByteString
sha256Abc = BS.pack
  [ 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde
  , 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c
  , 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
  ]

withSynth :: (BackendEnv Synthetic -> IO ()) -> IO ()
withSynth action = do
  r <- openBackend "7" :: IO (EngineResult (BackendEnv Synthetic))
  case r of
    EngineOk be -> action be >> closeBackend be
    EngineFail err -> assertFailure ("synthetic open failed: " ++ show err)

withNative :: (BackendEnv OpenSSL4 -> IO ()) -> IO ()
withNative action = do
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case r of
    EngineOk be -> action be >> closeBackend be
    EngineFail err -> assertFailure ("native open failed: " ++ show err)

-- | One live provider generation: initialized env, seated token, one
-- open session, one async-enabled table.
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
  table <- newAsyncTable 8
  enableAsyncSession table sid
  pure LiveGen { lgEnv = env, lgTable = table, lgSession = st }

runImmediate :: Env -> Request -> String -> IO ()
runImmediate env req what = do
  m <- snapshotModel env
  case planCall defaultRules m req of
    Immediate pc -> do
      pr <- publish env (pcDelta pc)
      case pr of
        Right () -> pure ()
        Left f -> assertFailure (what ++ " publish failed: " ++ show f)
    other -> assertFailure (what ++ " did not plan immediate: " ++ show other)

digestInit :: LiveGen -> IO ()
digestInit gen = do
  let sid = ssId (lgSession gen)
      req = Request Pkcs11_3_2 F_DigestInit (Just sid) Nothing
        (encodeInitInput sha256Mech [] False BS.empty) []
  m <- snapshotModel (lgEnv gen)
  case planCall defaultRules m req of
    Execute res (EffectCrypto _) -> do
      m2 <- snapshotModel (lgEnv gen)
      case finishEffect defaultRules m2 res
          (O.EngineOkResource (EngineResourceId 29)) of
        Left rej -> assertFailure ("digest-init rejected: " ++ show rej)
        Right pc -> do
          pr <- publish (lgEnv gen) (pcDelta pc)
          case pr of
            Right () -> pure ()
            Left f -> assertFailure ("digest-init publish failed: " ++ show f)
    other -> assertFailure ("digest-init did not plan execute: " ++ show other)

-- | Drain one committed release through a backend.
drainOne :: CryptoBackend b => BackendEnv b -> ResourceRelease -> IO ()
drainOne be (ReleaseEngineResource rid) = releaseResource be rid

-- | Seed the HMAC key object + handle (mirrors the E2E seed shape).
seedHmacKey :: LiveGen -> IO ()
seedHmacKey gen = do
  let attrs = Map.fromList
        [(AttrClass, ValULong 4), (AttrPrivate, ValBool False)]
      delta = StateDelta
        [ DeltaCreateObjectFull hmacOid attrs Nothing slotHome
        , DeltaBindHandle hmacHandle hmacOid
        ]
  pr <- publish (lgEnv gen) delta
  case pr of
    Right () -> pure ()
    Left f -> assertFailure ("hmac seed failed: " ++ show f)

signInit :: LiveGen -> IO ()
signInit gen = do
  let sid = ssId (lgSession gen)
      req = Request Pkcs11_3_2 F_SignInit (Just sid) (Just hmacHandle)
        (encodeInitInput hmacMech [OpSign] False BS.empty) []
  runImmediate (lgEnv gen) req "sign-init"

startPlannedCall :: LiveGen -> JobFunction -> FunctionId -> ByteString -> Word64 -> Int -> IO JobId
startPlannedCall gen jfunc fid input cap ticks = do
  m <- snapshotModel (lgEnv gen)
  let sid = ssId (lgSession gen)
      req = Request Pkcs11_3_2 fid (Just sid) Nothing input
        [RegionBytes "async" (IntentBuffer maxOutputBytes)]
  case planCall defaultRules m req of
    Execute res eff -> do
      let jr = JobRequest
            { jrSession = sid
            , jrFunction = jfunc
            , jrWork = WorkCall res eff
            , jrTicks = ticks
            , jrCapacity = cap
            }
      started <- startJob (lgTable gen) jr
      case started of
        Right jid -> pure jid
        Left deny -> assertFailure ("start denied: " ++ show deny)
    other -> assertFailure ("call did not plan execute: " ++ show other)

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
        , trLabel = "detach-engine"
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

reopenWorld :: MemoryWorld -> Store -> IO Store
reopenWorld world old = do
  storeClose old
  eStore <- openMemoryStore world
  case eStore of
    Right s -> pure s
    Left err -> assertFailure ("world reopen failed: " ++ show err)

loadJobs :: Store -> IO [JobRecord]
loadJobs store = do
  eJobs <- storeLoadJobs store
  case eJobs of
    Right jobs -> pure jobs
    Left err -> assertFailure ("loadJobs failed: " ++ show err)

newCapture :: Word64 -> IO (Delivery, IORef [ByteString])
newCapture cap = do
  ref <- newIORef []
  pure (Delivery
    { dCapacity = cap
    , dWrite = \bs -> modifyIORef' ref (++ [bs])
    , dReportNeeded = \_ -> pure ()
    }, ref)

detachOk :: DetachCtx -> LiveGen -> JobId -> JobFunction -> IO Word64
detachOk dc gen jid func = do
  out <- detachJob dc (lgTable gen) jid func
  case out of
    DetachOk pid -> pure pid
    other -> assertFailure ("expected DetachOk, got " ++ show other)

joinOk :: DetachCtx -> LiveGen -> Word64 -> JobFunction -> Word64 -> IO JobId
joinOk dc gen pid func cap = do
  out <- joinJob dc (lgEnv gen) (lgTable gen) JoinRequest
    { jqPid = pid
    , jqFunction = func
    , jqSession = ssId (lgSession gen)
    , jqCapacity = cap
    }
  case out of
    JoinOk jid -> pure jid
    other -> assertFailure ("expected JoinOk, got " ++ show other)

driveReady :: (CryptoEffect -> IO CryptoResult) -> LiveGen -> JobFunction -> JobId -> IO ()
driveReady run gen func jid = do
  p <- pollJob run (lgEnv gen) (lgTable gen) func jid
  case p of
    PollReady -> pure ()
    PollPending _ -> driveReady run gen func jid
    other -> assertFailure ("expected ready, got " ++ show other)

-- Synthetic digest over the real synthetic backend: detach pending,
-- restart, rejoin, and deliver the backend's own bytes exactly once.
caseSynthDigest :: IO ()
caseSynthDigest = withSynth $ \be -> do
  let run fx = runEffect be keyResolver fx
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  digestInit genA
  dcA <- mkDetached storeA
  j0 <- startPlannedCall genA JobDigest F_Digest "abc" 32 1
  pid <- detachOk dcA genA j0 JobDigest
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  digestInit genB
  dcB <- mkDetached storeB
  j1 <- joinOk dcB genB pid JobDigest 32
  -- The backend's own answer is the oracle for the replayed bytes.
  want <- run (FxDigest sha256Mech "abc")
  wantBs <- case want of
    GotBytes bs -> pure bs
    other -> assertFailure ("synthetic digest failed: " ++ show other)
  driveReady run genB JobDigest j1
  (del, writes) <- newCapture 32
  jc <- completeJoined dcB (lgEnv genB) (lgTable genB) JobDigest j1 del
    (drainOne be)
  assertEqual "mark clean" Nothing (jcMarkError jc)
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "synthetic digest bytes" wantBs bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "exactly one write" 1 (length got)
  storeClose storeB

-- Synthetic HMAC sign: the key handle is re-seeded on the new
-- generation (token-object reload), the recipe replays against it,
-- and the tag verifies against the backend's own answer.
caseSynthSign :: IO ()
caseSynthSign = withSynth $ \be -> do
  let run fx = runEffect be keyResolver fx
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  seedHmacKey genA
  signInit genA
  dcA <- mkDetached storeA
  j0 <- startPlannedCall genA JobSign F_Sign "Hi There" 32 1
  pid <- detachOk dcA genA j0 JobSign
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  seedHmacKey genB
  signInit genB
  dcB <- mkDetached storeB
  j1 <- joinOk dcB genB pid JobSign 32
  want <- run (FxSign hmacMech (Just hmacOid) BS.empty "Hi There")
  wantBs <- case want of
    GotBytes bs -> pure bs
    other -> assertFailure ("synthetic sign failed: " ++ show other)
  driveReady run genB JobSign j1
  (del, writes) <- newCapture 32
  jc <- completeJoined dcB (lgEnv genB) (lgTable genB) JobSign j1 del
    (drainOne be)
  assertEqual "mark clean" Nothing (jcMarkError jc)
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "synthetic tag bytes" wantBs bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "exactly one write" 1 (length got)
  storeClose storeB

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

-- Synthetic AES keygen: detach pending, restart, rejoin (the
-- session-owned template remaps to the joining session), and deliver
-- a FRESH handle minted by the current provider generation.
caseSynthGenKey :: IO ()
caseSynthGenKey = withSynth $ \be -> do
  let run fx = runEffect be keyResolver fx
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  dcA <- mkDetached storeA
  mA <- snapshotModel (lgEnv genA)
  (pw, fx) <- case planGenerateKey defaultRules mA (lgSession genA) aesKeyGenMech BS.empty (aesTmpl 32) of
    KeyEffect pw0 fx0 -> pure (pw0, fx0)
    other -> assertFailure ("genkey is not an effect: " ++ show other)
  let reqA = JobRequest
        { jrSession = ssId (lgSession genA)
        , jrFunction = JobGenKey
        , jrWork = WorkKey (keyReservation (lgSession genA) "detach-genkey") pw fx
        , jrTicks = 1
        , jrCapacity = 9
        }
  Right j0 <- startJob (lgTable genA) reqA
  pid <- detachOk dcA genA j0 JobGenKey
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  dcB <- mkDetached storeB
  j1 <- joinOk dcB genB pid JobGenKey 9
  av <- inspectAttachment dcB pid
  assertEqual "attach recorded" (Just (AvActive j1)) av
  driveReady run genB JobGenKey j1
  (del, writes) <- newCapture 9
  jc <- completeJoined dcB (lgEnv genB) (lgTable genB) JobGenKey j1 del
    (drainOne be)
  assertEqual "mark clean" Nothing (jcMarkError jc)
  h <- case jcOutcome jc of
    CompleteDelivered (CompOneHandle x) -> pure x
    other -> assertFailure ("expected one-handle delivery, got " ++ show other)
  -- Fresh generation, fresh counter: the handle is minted here, not
  -- restored from the old process's table.
  assertEqual "fresh handle" (ExternalHandle 1) h
  got <- readIORef writes
  assertEqual "one-handle frame" [BS.pack [0x02] <> encodeHandle h] got
  storeClose storeB

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

-- Synthetic ML-KEM pair generation across a detach boundary.
caseSynthGenKeyPair :: IO ()
caseSynthGenKeyPair = withSynth $ \be -> do
  let run fx = runEffect be keyResolver fx
  (world, storeA) <- mkWorld
  genA <- openLiveGen
  dcA <- mkDetached storeA
  mA <- snapshotModel (lgEnv genA)
  (pw, fx) <- case planGenerateKeyPair defaultRules mA (lgSession genA)
    mlKemKeyPairGenMech kemPubTmpl kemPrivTmpl of
    KeyEffect pw0 fx0 -> pure (pw0, fx0)
    other -> assertFailure ("genkeypair is not an effect: " ++ show other)
  let reqA = JobRequest
        { jrSession = ssId (lgSession genA)
        , jrFunction = JobGenKeyPair
        , jrWork = WorkKey (keyReservation (lgSession genA) "detach-genkeypair") pw fx
        , jrTicks = 1
        , jrCapacity = 17
        }
  Right j0 <- startJob (lgTable genA) reqA
  pid <- detachOk dcA genA j0 JobGenKeyPair
  storeB <- reopenWorld world storeA
  genB <- openLiveGen
  dcB <- mkDetached storeB
  j1 <- joinOk dcB genB pid JobGenKeyPair 17
  driveReady run genB JobGenKeyPair j1
  (del, writes) <- newCapture 17
  jc <- completeJoined dcB (lgEnv genB) (lgTable genB) JobGenKeyPair j1 del
    (drainOne be)
  assertEqual "mark clean" Nothing (jcMarkError jc)
  (pubH, privH) <- case jcOutcome jc of
    CompleteDelivered (CompTwoHandles a b) -> pure (a, b)
    other -> assertFailure ("expected two-handle delivery, got " ++ show other)
  assertEqual "fresh public handle" (ExternalHandle 1) pubH
  assertEqual "fresh private handle" (ExternalHandle 2) privH
  got <- readIORef writes
  assertEqual "two-handle frame"
    [BS.pack [0x03] <> encodeHandle pubH <> encodeHandle privH] got
  storeClose storeB

-- Real-adapter opaque context (OpenSSL4-backed): detach reports the
-- PERMITTED typed unsaveable outcome — never a crash, never a
-- serialized address — and the live job still completes with exact
-- KAT bytes through the native backend.
caseNativeUnsaveable :: IO ()
caseNativeUnsaveable = withNative $ \be -> do
  let run fx = runEffect be keyResolver fx
  (_world, store) <- mkWorld
  gen <- openLiveGen
  digestInit gen
  dc <- mkDetached store
  j0 <- startPlannedCall gen JobDigest F_Digest "abc" 32 1
  markJobOpaque dc j0 "live EVP_MD_CTX in the native adapter"
  out <- detachJob dc (lgTable gen) j0 JobDigest
  case out of
    DetachUnsaveable reason ->
      assertEqual "reason" "live EVP_MD_CTX in the native adapter" reason
    other -> assertFailure ("expected DetachUnsaveable, got " ++ show other)
  assertEqual "permitted code" CKR_STATE_UNSAVEABLE (detachCode out)
  jobs <- loadJobs store
  assertEqual "nothing serialized" 0 (length jobs)
  docs <- storeInspect store
  let jobDocs = [d | d <- docs, docTable d == "detached_jobs"]
  assertEqual "no job documents" 0 (length jobDocs)
  -- The preserved job drives natively and delivers KAT bytes.
  driveReady run gen JobDigest j0
  (del, writes) <- newCapture 32
  jc <- completeJoined dc (lgEnv gen) (lgTable gen) JobDigest j0 del
    (drainOne be)
  assertEqual "non-joined mark clean" Nothing (jcMarkError jc)
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "SHA-256 KAT" sha256Abc bs
    other -> assertFailure ("expected KAT delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "exactly one write" 1 (length got)
  storeClose store

-- The SQLite file store carries a detached job across close/reopen
-- in this process (the two-OS-process proof is the C restart test).
caseSQLiteReopen :: IO ()
caseSQLiteReopen = do
  base <- getTemporaryDirectory
  let dir = base ++ "/sqlite-reopen"
  exists <- doesDirectoryExist dir
  if exists then removeDirectoryRecursive dir else pure ()
  createDirectory dir
  let path = dir ++ "/jobs.db"
  eA <- openSQLiteStore path
  storeA <- case eA of
    Right s -> pure s
    Left err -> assertFailure ("sqlite open failed: " ++ show err)
  let tok = TokenRecord
        { trId = tokHome
        , trSlot = slotHome
        , trGeneration = Generation 0
        , trLabel = "detach-sqlite"
        , trAuth = tokenAuthNew
        }
  res <- storeCommit storeA emptyDelta { sdPutTokens = [tok] }
  case res of
    Committed -> pure ()
    other -> assertFailure ("token seat failed: " ++ show other)
  genA <- openLiveGen
  digestInit genA
  dcA <- mkDetached storeA
  let stub _ = pure (GotBytes (BS.replicate 32 0xE7))
  j0 <- startPlannedCall genA JobDigest F_Digest "abc" 32 2
  pid <- detachOk dcA genA j0 JobDigest
  assertEqual "first persistent id" 1 pid
  storeClose storeA
  -- Reopen the same file: the record and token survive.
  eB <- openSQLiteStore path
  storeB <- case eB of
    Right s -> pure s
    Left err -> assertFailure ("sqlite reopen failed: " ++ show err)
  genB <- openLiveGen
  digestInit genB
  dcB <- mkDetached storeB
  j1 <- joinOk dcB genB pid JobDigest 32
  driveReady stub genB JobDigest j1
  (del, writes) <- newCapture 32
  jc <- completeJoined dcB (lgEnv genB) (lgTable genB) JobDigest j1 del
    (\_ -> pure ())
  assertEqual "mark clean" Nothing (jcMarkError jc)
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "stub bytes" (BS.replicate 32 0xE7) bs
    other -> assertFailure ("expected delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "exactly one write" 1 (length got)
  jobs <- loadJobs storeB
  case [r | r <- jobs, jrPersistentId r == pid] of
    [rec] -> assertEqual "record delivered" JobDelivered (jrState rec)
    other -> assertFailure ("expected one record, got " ++ show other)
  storeClose storeB
  removeDirectoryRecursive dir

-- Every durable job document (one per workflow + a ready result) has
-- the pinned key set and no address-like content anywhere.
caseNoAddresses :: IO ()
caseNoAddresses = withSynth $ \be -> do
  let run fx = runEffect be keyResolver fx
  (_world, store) <- mkWorld
  gen <- openLiveGen
  digestInit gen
  seedHmacKey gen
  signInit gen
  dc <- mkDetached store
  -- One pending record per workflow.
  jDigest <- startPlannedCall gen JobDigest F_Digest "abc" 32 1
  _ <- detachOk dc gen jDigest JobDigest
  jSign <- startPlannedCall gen JobSign F_Sign "Hi There" 32 1
  _ <- detachOk dc gen jSign JobSign
  m <- snapshotModel (lgEnv gen)
  (pwK, fxK) <- case planGenerateKey defaultRules m (lgSession gen) aesKeyGenMech BS.empty (aesTmpl 32) of
    KeyEffect pw0 fx0 -> pure (pw0, fx0)
    other -> assertFailure ("genkey is not an effect: " ++ show other)
  let reqK = JobRequest
        { jrSession = ssId (lgSession gen)
        , jrFunction = JobGenKey
        , jrWork = WorkKey (keyReservation (lgSession gen) "scan-genkey") pwK fxK
        , jrTicks = 1
        , jrCapacity = 9
        }
  Right jKey <- startJob (lgTable gen) reqK
  _ <- detachOk dc gen jKey JobGenKey
  (pwP, fxP) <- case planGenerateKeyPair defaultRules m (lgSession gen)
    mlKemKeyPairGenMech kemPubTmpl kemPrivTmpl of
    KeyEffect pw0 fx0 -> pure (pw0, fx0)
    other -> assertFailure ("genkeypair is not an effect: " ++ show other)
  let reqP = JobRequest
        { jrSession = ssId (lgSession gen)
        , jrFunction = JobGenKeyPair
        , jrWork = WorkKey (keyReservation (lgSession gen) "scan-genkeypair") pwP fxP
        , jrTicks = 1
        , jrCapacity = 17
        }
  Right jPair <- startJob (lgTable gen) reqP
  _ <- detachOk dc gen jPair JobGenKeyPair
  -- Plus one ready result.
  jReady <- startPlannedCall gen JobDigest F_Digest "ready" 32 1
  driveReady run gen JobDigest jReady
  _ <- detachOk dc gen jReady JobDigest
  docs <- storeInspect store
  let jobDocs = [d | d <- docs, docTable d == "detached_jobs"]
  assertEqual "five job documents" 5 (length jobDocs)
  let wantKeys =
        [ "body"
        , "format_version"
        , "function"
        , "persistent_id"
        , "state"
        , "token_generation"
        , "token_id"
        ]
      badNeedles = ["0x", "Ptr", "StablePtr", "FunPtr", "EVP_", "0X", "addr"]
  mapM_ (checkDoc wantKeys badNeedles) jobDocs
  -- Bodies decode strictly: pending recipes and framed results.
  jobs <- loadJobs store
  let bodies = map jrBody jobs
      pending = [() | JobPending {} <- bodies]
      results = [() | JobResult {} <- bodies]
  assertEqual "four recipes" 4 (length pending)
  assertEqual "one result" 1 (length results)
  storeClose store
  where
    checkDoc :: [String] -> [String] -> StoredDoc -> IO ()
    checkDoc wantKeys needles d = do
      assertEqual ("job doc keys: " ++ docKey d) wantKeys (docTopKeys (docJson d))
      mapM_ (checkNeedle d) needles
    checkNeedle :: StoredDoc -> String -> IO ()
    checkNeedle d needle
      | needle `isInfixOf` docJson d =
          assertFailure ("job doc " ++ docKey d ++ " contains " ++ show needle)
      | otherwise = pure ()

-- ---------------------------------------------------------------------------
-- FFI surface (Haskell-driven; the C proof is tests/c + the script)
-- ---------------------------------------------------------------------------

rvOK, rvBad, rvGeneral, rvPending, rvSavedInvalid :: CULong
rvOK = CULong 0x0
rvBad = CULong 0x07
rvGeneral = CULong 0x05
rvPending = CULong 0x204
rvSavedInvalid = CULong 0x160

nullStable :: StablePtr a
nullStable = castPtrToStablePtr nullPtr

isLiveStable :: StablePtr a -> Bool
isLiveStable p = castStablePtrToPtr p /= nullPtr

closeCtxSlot :: StablePtr AsyncCtx -> IO ()
closeCtxSlot ctx = alloca $ \slot -> do
  poke slot ctx
  haskokiAsyncClose slot
  after <- peek slot
  assertEqual "close nulls the slot" True (not (isLiveStable after))

closeBoxSlot :: StablePtr StoreBox -> IO ()
closeBoxSlot box = alloca $ \slot -> do
  poke slot box
  haskokiAsyncStoreClose slot
  after <- peek slot
  assertEqual "store close nulls the slot" True (not (isLiveStable after))

ctxSession :: StablePtr AsyncCtx -> IO CULong
ctxSession ctx = do
  c <- deRefStablePtr ctx
  pure (CULong (fromIntegral (unSessionId (acSession c))))

ffiDigestInit :: StablePtr AsyncCtx -> CULong -> IO CULong
ffiDigestInit ctx sess =
  haskokiAsyncDigestInit ctx sess (CULong 0x250) nullPtr 0

ffiStartDigest :: StablePtr AsyncCtx -> CULong -> ByteString -> Word64 -> Word64
  -> IO (CULong, StablePtr JobHandle)
ffiStartDigest ctx sess input cap ticks = alloca $ \hSlot -> do
  poke hSlot nullStable
  rv <- BS.useAsCString input $ \p ->
    haskokiAsyncStart ctx sess 2 (castPtr p) (CULong (fromIntegral (BS.length input)))
      (CULong cap) (CULong ticks) hSlot
  job <- peek hSlot
  pure (rv, job)

-- Full detach generation turnover through the exports: store open,
-- open_on, init, start, get_id, close (finalize), open_on again
-- (reinitialize), join, poll, complete — KAT bytes, fresh handle.
caseFfiDetachRejoin :: MVar () -> IO ()
caseFfiDetachRejoin envLock = do
  box <- haskokiAsyncStoreOpen nullPtr
  assertEqual "store opens" True (isLiveStable box)
  ctx1 <- withEnvLock envLock (haskokiAsyncOpenOn box)
  assertEqual "ctx1 opens" True (isLiveStable ctx1)
  sess1 <- ctxSession ctx1
  rvInit <- ffiDigestInit ctx1 sess1
  assertEqual "init ok" rvOK rvInit
  (rvStart, job1) <- ffiStartDigest ctx1 sess1 "abc" 32 1
  assertEqual "start pending" rvPending rvStart
  assertEqual "job1 live" True (isLiveStable job1)
  pid <- alloca $ \pidOut -> do
    rv <- haskokiAsyncGetId ctx1 job1 2 pidOut
    assertEqual "get_id ok" rvOK rv
    peek pidOut
  assertEqual "persistent id" 1 pid
  rvStale <- haskokiAsyncPoll ctx1 job1 2
  assertEqual "old handle stale" rvBad rvStale
  c1 <- deRefStablePtr ctx1
  nLive <- asyncLiveHandles c1
  assertEqual "no live handles after detach" 0 nLive
  closeCtxSlot ctx1
  -- Generation 2 on the same store.
  ctx2 <- withEnvLock envLock (haskokiAsyncOpenOn box)
  assertEqual "ctx2 opens" True (isLiveStable ctx2)
  sess2 <- ctxSession ctx2
  rvInit2 <- ffiDigestInit ctx2 sess2
  assertEqual "re-init ok" rvOK rvInit2
  job2 <- alloca $ \hSlot -> alloca $ \needOut -> do
    poke hSlot nullStable
    poke needOut (0 :: Word64)
    rv <- haskokiAsyncJoin ctx2 (CULong pid) 2 sess2 32 hSlot needOut
    assertEqual "join pending" rvPending rv
    peek hSlot
  assertEqual "job2 live" True (isLiveStable job2)
  -- Freshness = registered in the NEW context's live set (the old
  -- handle is stale above). Pointer inequality would be bogus here:
  -- the RTS may reuse a freed StablePtr slot in one process.
  c2 <- deRefStablePtr ctx2
  nLive2 <- asyncLiveHandles c2
  assertEqual "job2 lives in generation 2" 1 nLive2
  rvPoll <- haskokiAsyncPoll ctx2 job2 2
  assertEqual "joined ready" rvOK rvPoll
  (n, bytes) <- allocaBytes 40 $ \pRes -> allocaBytes 32 $ \pBuf -> do
    pokeByteOff pRes 8 pBuf
    poke (castPtr pRes `plusPtr` 16 :: Ptr CULong) (CULong 32)
    rv <- haskokiAsyncComplete ctx2 job2 2 (castPtr pRes :: Ptr AsyncData)
    assertEqual "complete ok" rvOK rv
    CULong got <- peek (castPtr pRes `plusPtr` 16 :: Ptr CULong)
    taken <- peekArray (fromIntegral got) (pBuf :: Ptr Word8)
    pure (got, taken)
  assertEqual "KAT length" 32 n
  assertEqual "KAT bytes" (BS.unpack sha256Abc) bytes
  closeCtxSlot ctx2
  closeBoxSlot box

-- A context with no bound store cannot detach or join: durability is
-- unavailable, so both report typed failures with null outputs.
caseFfiNoStore :: MVar () -> IO ()
caseFfiNoStore envLock = do
  ctx <- withEnvLock envLock haskokiAsyncOpen
  assertEqual "ctx opens" True (isLiveStable ctx)
  sess <- ctxSession ctx
  rvInit <- ffiDigestInit ctx sess
  assertEqual "init ok" rvOK rvInit
  (rvStart, job) <- ffiStartDigest ctx sess "abc" 32 1
  assertEqual "start pending" rvPending rvStart
  alloca $ \pidOut -> do
    poke pidOut (99 :: Word64)
    rv <- haskokiAsyncGetId ctx job 2 pidOut
    assertEqual "get_id without store" rvGeneral rv
    z <- peek pidOut
    assertEqual "pid zeroed on failure" 0 z
  alloca $ \hSlot -> alloca $ \needOut -> do
    poke hSlot nullStable
    rv <- haskokiAsyncJoin ctx 1 2 sess 32 hSlot needOut
    assertEqual "join without store" rvGeneral rv
    h <- peek hSlot
    assertEqual "handle null on failure" True (not (isLiveStable h))
  -- The job itself is untouched by the refusals.
  rvPoll <- haskokiAsyncPoll ctx job 2
  assertEqual "job still live" rvOK rvPoll
  closeCtxSlot ctx

-- Join refusals through the exports: unknown ids and wrong functions
-- are typed, and the durable job survives them.
caseFfiJoinRefusals :: MVar () -> IO ()
caseFfiJoinRefusals envLock = do
  box <- haskokiAsyncStoreOpen nullPtr
  ctx <- withEnvLock envLock (haskokiAsyncOpenOn box)
  sess <- ctxSession ctx
  rvInit <- ffiDigestInit ctx sess
  assertEqual "init ok" rvOK rvInit
  alloca $ \hSlot -> alloca $ \needOut -> do
    poke hSlot nullStable
    rv <- haskokiAsyncJoin ctx 77 2 sess 32 hSlot needOut
    assertEqual "unknown pid" rvSavedInvalid rv
    h <- peek hSlot
    assertEqual "handle null" True (not (isLiveStable h))
  (_, job) <- ffiStartDigest ctx sess "abc" 32 1
  pid <- alloca $ \pidOut -> do
    rv <- haskokiAsyncGetId ctx job 2 pidOut
    assertEqual "get_id ok" rvOK rv
    peek pidOut
  alloca $ \hSlot -> alloca $ \needOut -> do
    poke hSlot nullStable
    rv <- haskokiAsyncJoin ctx (CULong pid) 1 sess 32 hSlot needOut
    assertEqual "wrong function" rvBad rv
  (rvJoin, job2) <- alloca $ \hSlot -> alloca $ \needOut -> do
    poke hSlot nullStable
    rv <- haskokiAsyncJoin ctx (CULong pid) 2 sess 32 hSlot needOut
    h <- peek hSlot
    pure (rv, h)
  assertEqual "retry joins" rvPending rvJoin
  assertEqual "joined live" True (isLiveStable job2)
  closeCtxSlot ctx
  closeBoxSlot box

-- Provider reinit reloads token metadata and token objects from the
-- store into the fresh model (sessions/handles are never reloaded).
caseRestoreStoreState :: IO ()
caseRestoreStoreState = do
  env <- newEnv defaultRules
  ini <- initialize env defaultInitArgs
  case ini of
    OutcomeOk () -> pure ()
    OutcomeErr c -> assertFailure ("init failed: " ++ show c)
  let auth = tokenAuthNew
      trec = TokenRecord
        { trId = tokHome
        , trSlot = slotHome
        , trGeneration = Generation 3
        , trLabel = "reloaded"
        , trAuth = auth
        }
      attrs = Map.fromList [(AttrToken, ValBool True)]
      orec = ObjectRecord
        { orId = ObjectId 21
        , orToken = tokHome
        , orClass = 0
        , orKeyType = Nothing
        , orAttrs = attrs
        , orMaterialEncoding = "none"
        , orMaterial = Nothing
        , orRevision = Revision 5
        }
  restoreStoreState env [(trec, [orec])] >>= assertEqual "restore ok" (Right ())
  m <- snapshotModel env
  assertEqual "token auth reloaded" (Just auth) (lookupTokenAuth m slotHome)
  case lookupObject m (ObjectId 21) of
    Nothing -> assertFailure "object not reloaded"
    Just ost -> do
      assertEqual "attrs reloaded" attrs (osAttrs ost)
      assertEqual "token-owned" Nothing (osOwner ost)
      assertEqual "home slot" slotHome (osSlot ost)
      assertEqual "revision kept" (Revision 5) (osRevision ost)
  assertEqual "id space reserved" 22 (mNextObject m)

-- Standard detached transactions on its owned SQLite store. Fault wrappers
-- affect only this fixture's Store value; runtime policy is not replaced.
withSurfaceStore :: MVar () -> String -> (Store -> Store)
  -> (StablePtr StdInstance -> StdInstance -> Store -> DetachCtx -> IO a) -> IO a
withSurfaceStore envLock tag wrap action = do
  cfg <- withEnvLock envLock $ do
    let dir = "dist-release-evidence/async-routing/task-3/fixtures/detached-" ++ tag
        path = dir ++ "/config.toml"
    exists <- doesDirectoryExist dir
    when exists (removeDirectoryRecursive dir)
    createDirectoryIfMissing True dir
    writeFile path $ unlines
      [ "schema_version = 1", "profile = \"demo-maximal\""
      , "[tokens]", "labels = [\"haskoki-demo\", \"other\"]"
      , "so_pins = [\"5678\", \"6789\"]", "user_pins = [\"1234\", \"2345\"]"
      , "[storage]", "kind = \"sqlite\"", "path = \"" ++ dir ++ "/jobs.db\""
      ]
    resolveFrom (Just path) Nothing >>= either (assertFailure . show) pure
  let acquisition = stdAcquisition { saOpenStore = \env config -> do
        result <- saOpenStore stdAcquisition env config
        pure $ fmap (fmap (\ss -> ss { stdStore = wrap (stdStore ss) })) result }
  bracket (openStdInstanceWith acquisition cfg) haskokiStdClose $ \ctx -> do
    assertBool "Standard SQLite opened" (isLiveStable ctx)
    inst <- deRefStablePtr ctx
    ss <- maybe (assertFailure "missing Standard store") pure (siStore inst)
    dc <- maybe (assertFailure "missing Standard detach context") pure (siDetach inst)
    action ctx inst (stdStore ss) dc

surfaceName :: ByteString -> (Ptr Word8 -> IO a) -> IO a
surfaceName name action = BS.useAsCString name (action . castPtr)

surfaceRV :: String -> ReturnCode -> IO CULong -> IO ()
surfaceRV label code call = call >>= assertEqual (label ++ ": " ++ show code) (stdRvOf code)

surfaceOpen :: StablePtr StdInstance -> CULong -> Bool -> IO CULong
surfaceOpen ctx slot async = alloca $ \p -> do
  surfaceRV "open" CKR_OK (haskokiStdOpenSessionWithAsync ctx slot 0 (if async then 1 else 0) p)
  peek p

surfaceInit :: StablePtr StdInstance -> CULong -> IO ()
surfaceInit ctx h = surfaceRV "matching DigestInit" CKR_OK (haskokiStdDigestInit ctx h 0x250 nullPtr 0)

surfaceStart :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO ()
surfaceStart ctx h out cap = do
  surfaceInit ctx h
  alloca $ \len -> BS.useAsCString "abc" $ \input -> do
    poke len cap
    surfaceRV "start" CKR_PENDING (haskokiStdDigest ctx h (castPtr input) 3 out len)
    peek len >>= assertEqual "start preserves capacity word" cap

surfaceSid :: CULong -> SessionId
surfaceSid = SessionId . fromIntegral

surfaceView :: StdInstance -> CULong -> IO (StablePtr AsyncCtx, AsyncCtx)
surfaceView inst h = do
  views <- readIORef (siAsyncViews inst)
  view <- maybe (assertFailure "missing view") pure (Map.lookup (surfaceSid h) views)
  (view,) <$> deRefStablePtr view

surfaceBinding :: StdInstance -> CULong -> IO StdAsyncBinding
surfaceBinding inst h = do
  bindings <- readIORef (siAsyncBindings inst)
  maybe (assertFailure "missing binding") pure (lookupStdAsyncBinding (surfaceSid h) JobDigest bindings)

surfaceEmpty :: StdInstance -> CULong -> IO ()
surfaceEmpty inst h = do
  bindings <- readIORef (siAsyncBindings inst)
  assertBool "no binding/output address" (Map.notMember (surfaceSid h, JobDigest) bindings)
  (_, c) <- surfaceView inst h
  asyncLiveHandles c >>= assertEqual "no private handle" 0

surfaceDetach :: StablePtr StdInstance -> StdInstance -> CULong -> IO CULong
surfaceDetach ctx inst h = surfaceName "C_Digest" $ \name -> alloca $ \pid -> do
  old <- surfaceBinding inst h
  (view, _) <- surfaceView inst h
  poke pid 0xa5a5a5a5a5a5a5a5
  surfaceRV "durable GetID" CKR_OK (haskokiStdAsyncGetId ctx h name pid)
  value <- peek pid
  assertBool "nonzero persistent scalar" (value /= 0 && value /= 0xa5a5a5a5a5a5a5a5)
  surfaceEmpty inst h
  surfaceRV "revoked native handle" CKR_ARGUMENTS_BAD (haskokiAsyncPoll view (sabHandle old) 2)
  allocaBytes 40 $ \result -> do
    pokeArray (castPtr result) (replicate 40 (0xa5 :: Word8))
    surfaceRV "Complete after detach" CKR_OPERATION_NOT_INITIALIZED (haskokiStdAsyncComplete ctx h name result)
    peekArray 40 (castPtr result :: Ptr Word8) >>= assertEqual "revoked result untouched" (replicate 40 0xa5)
  poke pid 0xa5a5a5a5a5a5a5a5
  surfaceRV "GetID after detach" CKR_OPERATION_NOT_INITIALIZED (haskokiStdAsyncGetId ctx h name pid)
  peek pid >>= assertEqual "revoked GetID preserves sentinel" 0xa5a5a5a5a5a5a5a5
  pure value

surfaceJoin :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> IO CULong
surfaceJoin ctx h pid out cap = surfaceName "C_Digest" $ \name -> haskokiStdAsyncJoin ctx h name pid out cap

surfaceComplete :: StablePtr StdInstance -> CULong -> Ptr Word8 -> IO ()
surfaceComplete ctx h out = surfaceName "C_Digest" $ \name -> allocaBytes 40 $ \result -> do
  pokeArray (castPtr result) (replicate 40 (0xa5 :: Word8))
  first <- haskokiStdAsyncComplete ctx h name result
  if first == stdRvOf CKR_PENDING
    then surfaceRV "second completion" CKR_OK (haskokiStdAsyncComplete ctx h name result)
    else assertEqual "ready completion" (stdRvOf CKR_OK) first
  peekByteOff result 8 >>= assertEqual "joined output address" out
  (peekByteOff result 0 :: IO CULong) >>= assertEqual "public version" 0
  (peekByteOff result 16 :: IO CULong) >>= assertEqual "public length" 32
  peekArray 32 out >>= assertEqual "joined SHA-256 abc" (BS.unpack sha256Abc)

surfaceCanary :: Ptr Word8 -> Int -> IO ()
surfaceCanary ptr len = peekArray len ptr >>= assertEqual "entire payload remains canary" (replicate len 0xa5)

putRecord :: Store -> JobRecord -> IO ()
putRecord store rec = storeCommit store emptyDelta { sdPutJobs = [rec] } >>= assertEqual "seed controlled record" Committed

-- Normative spec section 4.2 (verbatim):
-- | Join condition after the applicable earlier checks | Existing result |
-- |---|---|
-- | Unknown id, unknown record/recipe version, or stale token generation | `CKR_SAVED_STATE_INVALID` |
-- | Known idle id for another function | `CKR_ARGUMENTS_BAD` |
-- | Same persistent id already attached | `CKR_OPERATION_ACTIVE` |
-- | Delivered persistent record | `CKR_ARGUMENTS_BAD` |
-- | Canceled persistent record | `CKR_FUNCTION_CANCELED` |
-- | Failed persistent record or store failure | `CKR_GENERAL_ERROR` |
-- | Invalid/wrong-slot target session | `CKR_SESSION_HANDLE_INVALID` |
-- | Target session not enabled for async | `CKR_SESSION_ASYNC_NOT_SUPPORTED` |
-- | Existing token/session authentication check refuses | `CKR_USER_NOT_LOGGED_IN` |
-- | Matching operation not initialized, or replay does not reproduce the effect | `CKR_OPERATION_NOT_INITIALIZED` |
-- | Capacity zero or above `maxOutputBytes` | `CKR_ARGUMENTS_BAD` |
-- | Positive capacity smaller than need | `CKR_BUFFER_TOO_SMALL` |
-- | Live table at capacity | `CKR_HOST_MEMORY` |
caseAsyncJoinBoundary :: MVar () -> IO ()
caseAsyncJoinBoundary envLock = do
  staleGeneration <- newIORef False
  authRequired <- newIORef False
  let generationFault store = store { storeLoadTokens = do
        stale <- readIORef staleGeneration
        auth <- readIORef authRequired
        loaded <- storeLoadTokens store
        pure $ fmap (map (\(tok, objects) ->
          (tok { trGeneration = if stale then Generation 999 else trGeneration tok
               , trAuth = if auth then (trAuth tok) { taLogin = Just AuthUser } else trAuth tok
               }, objects))) loaded }
  withSurfaceStore envLock "join-table" generationFault $ \ctx inst store dc ->
    allocaBytes 64 $ \old -> allocaBytes 64 $ \out -> do
      pokeArray old (replicate 64 0xa5)
      pokeArray out (replicate 64 0xa5)
      source <- surfaceOpen ctx 0 True
      target <- surfaceOpen ctx 0 True
      ordinary <- surfaceOpen ctx 0 False
      wrongSlot <- surfaceOpen ctx 1 True
      surfaceStart ctx source old 32
      pid <- surfaceDetach ctx inst source
      jobs <- loadJobs store
      original <- case jobs of [j] -> pure j; _ -> assertFailure "one fresh durable record"
      let refuse label h name ident cap code = do
            before <- tableStats (siAsyncTable inst)
            records <- loadJobs store
            surfaceName name $ \pName -> surfaceRV label code (haskokiStdAsyncJoin ctx h pName ident out cap)
            tableStats (siAsyncTable inst) >>= assertEqual (label ++ " allocates no job id") before
            when (h /= 999999) (surfaceEmpty inst h)
            loadJobs store >>= assertEqual (label ++ " preserves durable records") records
            surfaceCanary out 64
      surfaceInit ctx target
      refuse "unknown id" target "C_Digest" 999999 32 CKR_SAVED_STATE_INVALID
      refuse "unknown id before zero capacity" target "C_Digest" 999999 0 CKR_SAVED_STATE_INVALID
      refuse "idle other function" target "C_Sign" pid 32 CKR_ARGUMENTS_BAD
      forM_ [0,16777217] $ \cap -> refuse "invalid capacity" target "C_Digest" pid cap CKR_ARGUMENTS_BAD
      refuse "positive short" target "C_Digest" pid 31 CKR_BUFFER_TOO_SMALL
      refuse "invalid standard session" 999999 "C_Digest" pid 32 CKR_SESSION_HANDLE_INVALID
      refuse "ordinary session" ordinary "C_Digest" pid 32 CKR_SESSION_ASYNC_NOT_SUPPORTED
      refuse "ordinary non-home view has no store" wrongSlot "C_Digest" pid 32 CKR_GENERAL_ERROR
      writeIORef staleGeneration True
      refuse "stale token generation" target "C_Digest" pid 32 CKR_SAVED_STATE_INVALID
      writeIORef staleGeneration False
      -- Reach the worker's wrong-slot validation using a store-bound view,
      -- without changing Standard's home-slot binding rule.
      (_, wc) <- surfaceView inst wrongSlot
      let borrowed = wc { acDetach = Just dc }
      bracket (newStablePtr borrowed) freeStablePtr $ \v ->
        alloca $ \handle -> alloca $ \need -> do
          surfaceRV "wrong-slot worker validation" CKR_SESSION_HANDLE_INVALID
            (haskokiAsyncJoin v pid 2 wrongSlot 32 handle need)
          peek handle >>= assertBool "wrong-slot creates no handle" . not . isLiveStable
      (tv, _) <- surfaceView inst target
      alloca $ \handle -> alloca $ \need -> do
        surfaceRV "invalid-session worker validation" CKR_SESSION_HANDLE_INVALID
          (haskokiAsyncJoin tv pid 2 999999 32 handle need)
        peek handle >>= assertBool "invalid session creates no handle" . not . isLiveStable
      missing <- surfaceOpen ctx 0 True
      refuse "matching init mandatory" missing "C_Digest" pid 32 CKR_OPERATION_NOT_INITIALIZED
      surfaceRV "wrong replay init" CKR_OK (haskokiStdDigestInit ctx missing 0x270 nullPtr 0)
      refuse "replay effect mismatch" missing "C_Digest" pid 32 CKR_OPERATION_NOT_INITIALIZED
      -- Fresh ids avoid the context's terminal attachment cache. Unknown
      -- function/recipe/result versions are real store rows. A stale token
      -- generation uses the read wrapper above because commit correctly
      -- refuses to introduce a mismatched job/token generation pair.
      let variants =
            [ (original { jrPersistentId = 100, jrFunction = "future-function/v99" }, CKR_SAVED_STATE_INVALID)
            , (original { jrPersistentId = 101, jrBody = JobPending "future-recipe/v99" BS.empty }, CKR_SAVED_STATE_INVALID)
            , (original { jrPersistentId = 102, jrBody = JobResult CKR_OK "future-result/v99" }, CKR_SAVED_STATE_INVALID)
            , (original { jrPersistentId = 103, jrState = JobDelivered }, CKR_ARGUMENTS_BAD)
            , (original { jrPersistentId = 104, jrState = JobCanceled }, CKR_FUNCTION_CANCELED)
            , (original { jrPersistentId = 105, jrState = JobFailed }, CKR_GENERAL_ERROR)
            ]
      forM_ variants $ \(rec, code) -> do
        putRecord store rec
        refuse "controlled record disposition" target "C_Digest" (fromIntegral (jrPersistentId rec)) 32 code
      -- Read-side auth fixture avoids replacing SQLite's token row (which
      -- can cascade removal of its jobs) just to reach the auth check.
      writeIORef authRequired True
      refuse "existing auth rule" target "C_Digest" pid 32 CKR_USER_NOT_LOGGED_IN
      writeIORef authRequired False
      surfaceRV "retry attaches with public OK" CKR_OK (surfaceJoin ctx target pid out 32)
      surfaceCanary out 64
      competitor <- surfaceOpen ctx 0 True
      surfaceInit ctx competitor
      refuse "active id before wrong function" competitor "C_Sign" pid 32 CKR_OPERATION_ACTIVE
      refuse "active id before short capacity" competitor "C_Digest" pid 1 CKR_OPERATION_ACTIVE
      before <- tableStats (siAsyncTable inst)
      surfaceRV "occupied target before allocation" CKR_OPERATION_ACTIVE (surfaceJoin ctx target 999999 out 32)
      tableStats (siAsyncTable inst) >>= assertEqual "occupied target allocates no second handle" before
      (_, attached) <- surfaceView inst target
      asyncLiveHandles attached >>= assertEqual "one attached handle" 1
      -- Source cancel and close after revocation cannot resolve the new job.
      surfaceRV "source cancel after detach" CKR_OK (haskokiStdSessionCancel ctx source 0)
      surfaceRV "source close after detach" CKR_OK (haskokiStdCloseSession ctx source)
      surfaceCanary old 64
      surfaceRV "joined cancel" CKR_OK (haskokiStdSessionCancel ctx target 0x400)
      inspectAttachment dc (fromIntegral pid) >>= assertEqual "cancelJoined terminal fate" (Just (AvTerminal JobCanceled))
      refuse "later Join after cancel" competitor "C_Digest" pid 32 CKR_FUNCTION_CANCELED
      surfaceCanary out 64

  withSurfaceStore envLock "join-capacity-eight" id $ \ctx inst _ _ ->
    allocaBytes 32 $ \out -> do
      source <- surfaceOpen ctx 0 True
      surfaceStart ctx source out 32
      pid <- surfaceDetach ctx inst source
      target <- surfaceOpen ctx 0 True
      surfaceInit ctx target
      hs <- replicateM 8 (surfaceOpen ctx 0 True)
      forM_ hs $ \h -> surfaceStart ctx h out 32
      tableStats (siAsyncTable inst) >>= assertEqual "eight live jobs" (8,0,9)
      surfaceRV "full live table" CKR_HOST_MEMORY (surfaceJoin ctx target pid out 32)
      surfaceEmpty inst target
      tableStats (siAsyncTable inst) >>= assertEqual "refusal does not allocate" (8,0,9)
      first <- case hs of h:_ -> pure h; [] -> assertFailure "eight sessions required"
      surfaceRV "free one" CKR_OK (haskokiStdSessionCancel ctx first 0)
      surfaceRV "capacity refusal preserves retry" CKR_OK (surfaceJoin ctx target pid out 32)

  -- Store failure must reach the worker, and preserve the idle record.
  failLoad <- newIORef False
  let loadFault store = store { storeLoadJobs = do
        failing <- readIORef failLoad
        if failing then pure (Left (StoreIO "Join load injection")) else storeLoadJobs store }
  withSurfaceStore envLock "join-load-failure" loadFault $ \ctx inst store dc ->
    allocaBytes 32 $ \out -> do
      source <- surfaceOpen ctx 0 True
      surfaceStart ctx source out 32
      pid <- surfaceDetach ctx inst source
      target <- surfaceOpen ctx 0 True
      surfaceInit ctx target
      records <- loadJobs store
      writeIORef failLoad True
      surfaceRV "store failure" CKR_GENERAL_ERROR (surfaceJoin ctx target pid out 32)
      writeIORef failLoad False
      surfaceEmpty inst target
      loadJobs store >>= assertEqual "failure preserves durable record" records
      inspectAttachment dc (fromIntegral pid) >>= assertEqual "failure remains idle" (Just AvIdle)
      surfaceRV "store retry" CKR_OK (surfaceJoin ctx target pid out 32)

  -- Inject only after Join's precheck, while its store load is in flight.
  -- The ensuing private handle must be canceled if publication throws.
  publishTarget <- newIORef Nothing
  inject <- newIORef False
  let publicationFault store = store { storeLoadJobs = do
        enabled <- readIORef inject
        when enabled $ do
          writeIORef inject False
          readIORef publishTarget >>= mapM_ (\inst -> writeIORef (siAsyncBindings inst) (error "post-Join publication injection"))
        storeLoadJobs store }
  withSurfaceStore envLock "join-publication-failure" publicationFault $ \ctx inst _ dc ->
    allocaBytes 32 $ \out -> do
      source <- surfaceOpen ctx 0 True
      pokeArray out (replicate 32 0xa5)
      surfaceStart ctx source out 32
      pid <- surfaceDetach ctx inst source
      target <- surfaceOpen ctx 0 True
      surfaceInit ctx target
      writeIORef publishTarget (Just inst)
      writeIORef inject True
      surfaceRV "post-Join failure fenced" CKR_GENERAL_ERROR (surfaceJoin ctx target pid out 32)
        `finally` writeIORef (siAsyncBindings inst) Map.empty
      surfaceEmpty inst target
      tableStats (siAsyncTable inst) >>= assertEqual "joined job canceled before unwind" (0,1,2)
      inspectAttachment dc (fromIntegral pid) >>= assertEqual "failed publication cancels durable attachment" (Just (AvTerminal JobCanceled))
      surfaceCanary out 32

caseAsyncReadyJoinCapacity :: MVar () -> IO ()
caseAsyncReadyJoinCapacity envLock = do
  forM_ [False, True] $ \ready ->
    withSurfaceStore envLock (if ready then "ready-capacity" else "pending-capacity") id $ \ctx inst _ dc ->
    allocaBytes 64 $ \old -> allocaBytes 64 $ \out -> do
      pokeArray old (replicate 64 0xa5)
      pokeArray out (replicate 64 0xa5)
      source <- surfaceOpen ctx 0 True
      surfaceStart ctx source old 64
      when ready $ do
        (view, _) <- surfaceView inst source
        binding <- surfaceBinding inst source
        surfaceRV "first ready barrier" CKR_PENDING (haskokiAsyncPoll view (sabHandle binding) 2)
        surfaceRV "second ready barrier" CKR_OK (haskokiAsyncPoll view (sabHandle binding) 2)
      pid <- surfaceDetach ctx inst source
      surfaceRV "post-detach cancel" CKR_OK (haskokiStdSessionCancel ctx source 0)
      surfaceRV "post-detach close" CKR_OK (haskokiStdCloseSession ctx source)
      inspectAttachment dc (fromIntegral pid) >>= assertEqual "idle record survives source cleanup" (Just AvIdle)
      target <- surfaceOpen ctx 0 True
      surfaceInit ctx target
      let need = if ready then 32 else 64
          short = if ready then 31 else 32
      surfaceRV "public short capacity" CKR_BUFFER_TOO_SMALL (surfaceJoin ctx target pid out short)
      surfaceEmpty inst target
      (view, _) <- surfaceView inst target
      alloca $ \handle -> alloca $ \pNeed -> do
        poke pNeed 0xa5a5a5a5a5a5a5a5
        surfaceRV "private need evidence" CKR_BUFFER_TOO_SMALL (haskokiAsyncJoin view pid 2 target short handle pNeed)
        peek pNeed >>= assertEqual "pending capacity versus ready length" (fromIntegral need :: Word64)
        peek handle >>= assertBool "short has no handle" . not . isLiveStable
      surfaceEmpty inst target
      surfaceCanary out 64
      surfaceCanary old 64
      inspectAttachment dc (fromIntegral pid) >>= assertEqual "short preserves retryable idle" (Just AvIdle)
      surfaceRV "exact retry public OK" CKR_OK (surfaceJoin ctx target pid out need)
      binding <- surfaceBinding inst target
      assertEqual "capacity bound by value" (fromIntegral need) (sabCapacity binding)
      assertEqual "fresh output bound" out (sabOutput binding)
      surfaceCanary out 64
      surfaceComplete ctx target out
      surfaceEmpty inst target
      surfaceCanary (out `plusPtr` 32) 32
      surfaceCanary old 64
      deliveredCount (siAsyncTable inst) >>= assertEqual "joined delivered exactly once" 1
      surfaceRV "cancel after successful completion" CKR_OK (haskokiStdSessionCancel ctx target 0)
      surfaceRV "delivered cannot rejoin" CKR_ARGUMENTS_BAD (surfaceJoin ctx target pid out need)
      peekArray 32 out >>= assertEqual "cancel cannot undo joined bytes" (BS.unpack sha256Abc)

  -- Finalize an attached job while leaving an idle durable record intact.
  saved <- newIORef Nothing
  withSurfaceStore envLock "idle-finalize" id $ \ctx inst store dc -> allocaBytes 32 $ \out -> do
    source <- surfaceOpen ctx 0 True
    surfaceStart ctx source out 32
    pid <- surfaceDetach ctx inst source
    source2 <- surfaceOpen ctx 0 True
    surfaceStart ctx source2 out 32
    attachedPid <- surfaceDetach ctx inst source2
    target <- surfaceOpen ctx 0 True
    surfaceInit ctx target
    surfaceRV "join before finalize" CKR_OK (surfaceJoin ctx target attachedPid out 32)
    (_, c) <- surfaceView inst target
    -- Retain diagnostics, then reopen only the store after Standard closes
    -- to inspect durable cleanup. This is not the separate-process proof.
    writeIORef saved (Just (inst, c, dc, pid, attachedPid))
    loadJobs store >>= assertEqual "two durable records before finalize" 2 . length
  readIORef saved >>= \case
    Nothing -> assertFailure "missing finalize fixture"
    Just (inst, c, dc, idle, active) -> do
      asyncLiveHandles c >>= assertEqual "finalize frees joined handle" 0
      inspectAttachment dc (fromIntegral idle) >>= assertEqual "finalize preserves idle attachment" (Just AvIdle)
      inspectAttachment dc (fromIntegral active) >>= assertEqual "finalize cancels active attachment" (Just (AvTerminal JobCanceled))
      assertEqual "finalize clears all public bindings" 0 . Map.size =<< readIORef (siAsyncBindings inst)
      reopened <- openSQLiteStore "dist-release-evidence/async-routing/task-3/fixtures/detached-idle-finalize/jobs.db"
        >>= either (assertFailure . show) pure
      bracket (pure reopened) storeClose $ \store -> do
        jobs <- loadJobs store
        assertEqual "finalize durably preserves idle and cancels joined record"
          [(fromIntegral idle, JobQueued), (fromIntegral active, JobCanceled)]
          [(jrPersistentId rec, jrState rec) | rec <- jobs]

  -- Delivery-mark failure is distinct from successful SQLite recovery. The
  -- direct wrapper exposes jcMarkError; the public path preserves its existing
  -- verdict and in-memory once-only behavior, never a crash-safety guarantee.
  forM_ [False, True] $ \public -> do
    failMark <- newIORef False
    errors <- newIORef (0 :: Int)
    let markError = StoreIO "durable delivery mark injection"
        markFault store = store { storeCommit = \delta -> do
          enabled <- readIORef failMark
          if enabled && any ((== JobDelivered) . jrState) (sdPutJobs delta)
            then modifyIORef' errors (+ 1) >> pure (NotCommitted markError)
            else storeCommit store delta }
    withSurfaceStore envLock (if public then "public-mark-failure" else "jc-mark-failure") markFault $ \ctx inst store dc ->
      allocaBytes 32 $ \out -> do
        source <- surfaceOpen ctx 0 True
        surfaceStart ctx source out 32
        pid <- surfaceDetach ctx inst source
        target <- surfaceOpen ctx 0 True
        surfaceInit ctx target
        surfaceRV "join for mark failure" CKR_OK (surfaceJoin ctx target pid out 32)
        (view, _) <- surfaceView inst target
        binding <- surfaceBinding inst target
        surfaceRV "mark fixture countdown" CKR_PENDING (haskokiAsyncPoll view (sabHandle binding) 2)
        surfaceRV "mark fixture ready" CKR_OK (haskokiAsyncPoll view (sabHandle binding) 2)
        ids <- sessionJobs (siAsyncTable inst) (surfaceSid target)
        jid <- case ids of [j] -> pure j; _ -> assertFailure "single joined runtime id"
        writeIORef failMark True
        if public then surfaceComplete ctx target out else do
          (sink, writes) <- newCapture 32
          jc <- completeJoined dc (siEnv inst) (siAsyncTable inst) JobDigest jid sink (drainOne (siBackend inst))
          assertEqual "jcMarkError recorded" (Just markError) (jcMarkError jc)
          assertEqual "delivery survives failed mark" (CompleteDelivered (CompBytes sha256Abc)) (jcOutcome jc)
          assertEqual "one in-memory payload write" 1 . length =<< readIORef writes
          putStrLn ("Task 3 fault evidence: jcMarkError=" ++ show (jcMarkError jc) ++ "; no crash-safety claim")
        readIORef errors >>= assertEqual "failed mark attempted once" 1
        deliveredCount (siAsyncTable inst) >>= assertEqual "one in-memory delivery" 1
        inspectAttachment dc (fromIntegral pid) >>= assertEqual "memory terminal despite mark failure" (Just (AvTerminal JobDelivered))
        records <- loadJobs store
        assertEqual "durable mark still queued" [JobQueued] (map jrState records)
        surfaceRV "in-memory terminal prevents repeat Join" CKR_ARGUMENTS_BAD (surfaceJoin ctx source pid out 32)
        when public $ surfaceName "C_Digest" $ \name -> allocaBytes 40 $ \result ->
          surfaceRV "repeat public completion" CKR_OPERATION_NOT_INITIALIZED (haskokiStdAsyncComplete ctx target name result)
        writeIORef failMark False

caseAsyncOpaqueSurface :: MVar () -> IO ()
caseAsyncOpaqueSurface envLock = do
  withSurfaceStore envLock "opaque" id $ \ctx inst store dc -> allocaBytes 32 $ \out -> do
    pokeArray out (replicate 32 0xa5)
    source <- surfaceOpen ctx 0 True
    surfaceStart ctx source out 32
    binding <- surfaceBinding inst source
    (view, c) <- surfaceView inst source
    alloca $ \pid -> do
      forM_ [1, 999] $ \function -> do
        poke pid 0xa5a5a5a5a5a5a5a5
        surfaceRV "private numeric wrong-function GetID" CKR_ARGUMENTS_BAD (haskokiAsyncGetId view (sabHandle binding) function pid)
        peek pid >>= assertEqual "numeric refusal zeros id" (0 :: Word64)
        asyncLiveHandles c >>= assertEqual "numeric refusal retains live job" 1
    -- Obtain the runtime id only through sessionJobs. Never cast or inspect
    -- the opaque native handle's representation, even while it is live.
    ids <- sessionJobs (siAsyncTable inst) (surfaceSid source)
    jid <- case ids of [j] -> pure j; _ -> assertFailure "fresh single-job session required"
    markJobOpaque dc jid "opaque native adapter fixture"
    surfaceName "C_Digest" $ \name -> alloca $ \pid -> do
      poke pid 0xa5a5a5a5a5a5a5a5
      surfaceRV "opaque public GetID" CKR_STATE_UNSAVEABLE (haskokiStdAsyncGetId ctx source name pid)
      peek pid >>= assertEqual "unsaveable id zero" 0
    loadJobs store >>= assertEqual "zero new durable records" []
    asyncLiveHandles c >>= assertEqual "opaque refusal keeps handle" 1
    after <- surfaceBinding inst source
    assertBool "opaque binding unchanged" ((sabHandle binding, sabOutput binding, sabCapacity binding)
      == (sabHandle after, sabOutput after, sabCapacity after))
    surfaceCanary out 32
    surfaceComplete ctx source out

  forM_ [False, True] $ \missingHome -> do
    inject <- newIORef False
    let failure store = store
          { storeLoadTokens = do
              active <- readIORef inject
              if active && missingHome then pure (Right []) else storeLoadTokens store
          , storeCommit = \delta -> do
              active <- readIORef inject
              if active && not missingHome && not (null (sdPutJobs delta))
                then pure (NotCommitted (StoreIO "GetID commit injection"))
                else storeCommit store delta
          }
    withSurfaceStore envLock (if missingHome then "missing-home" else "detach-store-failure") failure $ \ctx inst store _ ->
      allocaBytes 32 $ \out -> surfaceName "C_Digest" (\name -> do
        source <- surfaceOpen ctx 0 True
        surfaceStart ctx source out 32
        binding <- surfaceBinding inst source
        writeIORef inject True
        alloca $ \pid -> do
          poke pid 0xa5a5a5a5a5a5a5a5
          surfaceRV "GetID store refusal" (if missingHome then CKR_TOKEN_NOT_PRESENT else CKR_GENERAL_ERROR)
            (haskokiStdAsyncGetId ctx source name pid)
          peek pid >>= assertEqual "store refusal zeros id" 0
        writeIORef inject False
        after <- surfaceBinding inst source
        assertBool "store refusal preserves live binding" (sabHandle binding == sabHandle after)
        loadJobs store >>= assertEqual "failure creates no durable record" []
        surfaceComplete ctx source out)
