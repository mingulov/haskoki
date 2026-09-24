{- | Detached-job engine proofs: every synthetic persistable workflow detaches
and rejoins, real-adapter opaque contexts take the permitted typed
unsaveable outcome, and the SQLite file store survives close\/reopen.
-}
{-# LANGUAGE OverloadedStrings #-}
module DetachedEngineSpec (spec) where

import Control.Concurrent.MVar (MVar)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.IORef (IORef, newIORef, modifyIORef', readIORef)
import qualified Data.Map.Strict as Map
import Data.List (isInfixOf)
import Data.Word (Word64, Word8)
import EnvLock (withEnvLock)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Array (peekArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.StablePtr (StablePtr, castPtrToStablePtr, castStablePtrToPtr, deRefStablePtr)
import Foreign.Storable (peek, poke, pokeByteOff)
import System.Directory
  ( createDirectory
  , doesDirectoryExist
  , getTemporaryDirectory
  , removeDirectoryRecursive
  )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

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
  , newAsyncTable
  , pollJob
  , startJob
  )
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
  (pw, fx) <- case planGenerateKey defaultRules mA (lgSession genA) aesKeyGenMech (aesTmpl 32) of
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
  (pwK, fxK) <- case planGenerateKey defaultRules m (lgSession gen) aesKeyGenMech (aesTmpl 32) of
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
