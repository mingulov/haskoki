{-# LANGUAGE OverloadedStrings #-}
module NotificationsEngineSpec (spec) where

import Control.Concurrent (ThreadId, isCurrentThreadBound, runInBoundThread, forkFinally, killThread, myThreadId, throwTo, yield)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, readMVar, takeMVar, tryReadMVar)
import Control.Concurrent.STM (atomically, newTQueueIO, readTQueue, writeTQueue)
import Control.Exception (SomeException, AsyncException (ThreadKilled), MaskingState (..), bracket, evaluate, try, mask, getMaskingState, fromException)
import Control.Monad (forM_, replicateM, replicateM_, when)
import qualified Data.ByteString as Bytes
import qualified Data.ByteString.Char8 as BS
import Data.IORef (IORef, atomicModifyIORef', modifyIORef', newIORef, readIORef, writeIORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing)
import EnvLock (withEnvLock)
import Data.Word (Word64, Word8)
import Foreign.C.Types (CInt (..), CULong (..))
import Foreign.C.String (CString, withCString)
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Array (peekArray, pokeArray)
import Foreign.Ptr (FunPtr, Ptr, castPtr, nullFunPtr, nullPtr, plusPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr, deRefStablePtr, newStablePtr, freeStablePtr)
import Foreign.Storable (peek, poke, sizeOf)
import GHC.Conc (threadStatus, ThreadStatus (..), BlockReason (..))
import System.Directory (createDirectoryIfMissing, doesFileExist, getCurrentDirectory, removeFile)
import System.Environment (lookupEnv, setEnv, unsetEnv)
import System.Mem.StableName (makeStableName)
import System.IO (hFlush, hClose, openBinaryTempFile, stdout)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend (BackendError (..), EngineResult (..), CryptoBackend (..), ResourceSaveability (..), UnsaveableReason (..))
import Haskoki.Engine.Driver (drainReleases)
import Haskoki.FFI.Async (AsyncCtx (..), asyncLiveHandles)
import Haskoki.FFI.Exports (returnCodeToRV)
import Haskoki.FFI.Instance
import Haskoki.FFI.Standard
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Model
import Haskoki.Object (resolveHandle)
import Haskoki.Outcome (EffectRequest (..), Reservation (..), StateDelta (..), DeltaOp (..), ResourceRelease (..), ModelFault (..))
import Haskoki.Registry (MechanismId (..))
import Haskoki.Runtime.Async
import Haskoki.Runtime.Config
import Haskoki.Runtime.Control
import Haskoki.Runtime.Events (insertToken, tokenPresent)
import Haskoki.Runtime.SlotEvents
import Haskoki.Runtime.Lifecycle (snapshotModel, snapshotPresence, envRules, publish, newEnv)
import qualified Haskoki.Runtime.Storage as Store
import Haskoki.Session (AdmitDeny (..), TokenAuth (..), SessionLogin (..))
import Haskoki.Types (ReturnCode (..), SessionId (..), SlotId (..), ExternalHandle (..), ObjectId (..), JobId)

spec :: MVar () -> TestTree
spec envLock = testGroup "Notifications"
  [ testGroup "T-N02"
  [ testCase "caseServingInitialSnapshot" (bounded (caseServingInitialSnapshot envLock))
  , testCase "caseServingAcquisitionUnwind" (bounded caseServingAcquisitionUnwind)
  , testCase "caseServingConfigLimits" (bounded caseServingConfigLimits)
  , testCase "caseServingControlOwnership" (bounded (caseServingControlOwnership envLock))
  ]
  , testGroup "T-N03"
    [ testCase "caseRemovalOwnsActualJobs" (bounded caseRemovalOwnsActualJobs)
    , testCase "casePresenceCleanupFault" (bounded (casePresenceCleanupFault envLock))
    , testCase "casePresenceStoreLedger" (bounded casePresenceStoreLedger)
    ]
  , testGroup "T-N06"
    [ testCase "caseNativeNotifyAssociation" (bounded caseNativeNotifyAssociation)
    , testCase "caseNativeNotifyRetirement" (bounded caseNativeNotifyRetirement)
    , testCase "caseNativeNotifyGuard" (bounded caseNativeNotifyGuard)
    ]
  , testGroup "T-N05"
    [ testCase "caseServingFinalizeOrder" (bounded caseServingFinalizeOrder)
    , testCase "caseServingMaskedHandoff" (bounded caseServingMaskedHandoff)
    ]
  ]

bounded :: Assertion -> Assertion
bounded action = timeout 20000000 action >>= maybe (assertFailure "notifications case exceeded 20s") pure

isNull :: StablePtr a -> Bool
isNull p = castStablePtrToPtr p == nullPtr

cfgTwo :: Bool -> Config
cfgTwo removable = defaultConfig
  { cfgControl = (cfgControl defaultConfig) { ccTestEnabled = removable }
  , cfgTokens = TokensCfg [("haskoki-demo", "5678", "1234"), ("second", "5678", "1234")]
  , cfgLimits = (cfgLimits defaultConfig) { limEvents = 2, limJobs = 32 }
  }

initial :: Bool -> [SlotSnapshot]
initial removable = [SlotSnapshot (SlotId 0) removable True 0, SlotSnapshot (SlotId 1) removable True 0]

request :: String -> [(String, Json)] -> BS.ByteString
request command args = renderJson (JObj [("schema_version", JNum 1), ("command", JStr command), ("arguments", JObj args)])

status :: ControlState -> [(String, Json)] -> IO [Json]
status ctl args = do
  (rv, bytes, _) <- dispatchControl ctl (request "status" args) (Just responseBudget)
  assertEqual "bound status succeeds" (fromIntegral (returnCodeToRV CKR_OK)) rv
  case parseJson bytes of
    Right (JObj fields) -> case lookup "presence" fields of
      Just (JArr rows) -> pure rows
      _ -> assertFailure "missing presence array"
    other -> assertFailure ("invalid status: " ++ show other)

row :: Integer -> Bool -> Integer -> Json
row slot present epoch = JObj [("slot", JNum slot), ("present", JBool present), ("generation", JNum epoch)]

withServing :: MVar () -> Bool -> IO a -> IO a
withServing envLock removable action = withEnvLock envLock $ do
  createDirectoryIfMissing True "/tmp/haskoki-notifications"
  let path = "/tmp/haskoki-notifications/engine-config.toml"
  bracket (lookupEnv "HASKOKI_CONFIG")
    (\old -> maybe (unsetEnv "HASKOKI_CONFIG") (setEnv "HASKOKI_CONFIG") old) $ \_ -> do
      writeFile path (unlines ["schema_version = 1", "[control]", "test_enabled = " ++ if removable then "true" else "false", "[tokens]", "labels = [\"haskoki-demo\", \"second\"]", "so_pins = [\"5678\", \"5678\"]", "user_pins = [\"1234\", \"1234\"]", "[limits]", "events = 2", "jobs = 32"])
      setEnv "HASKOKI_CONFIG" path
      action

-- Catches a second environment resolution or hub, startup indications, changed
-- provisioning, and accidental use of Instance's configurable private table.
caseServingInitialSnapshot :: MVar () -> Assertion
caseServingInitialSnapshot envLock = do
  forM_ [False, True] $ \removable -> withServing envLock removable $
    bracket haskokiInstanceOpen haskokiInstanceClose $ \cell -> do
      assertBool "authoritative config opens" (not (isNull cell))
      Just ops <- readLiveInstance cell
      setEnv "HASKOKI_CONFIG" "/tmp/haskoki-notifications/missing-config.toml"
      bracket (haskokiStdOpen cell) haskokiStdClose $ \sp -> do
        assertBool "Standard borrows resolved config despite invalid current env" (not (isNull sp))
        std <- deRefStablePtr sp
        a <- evaluate (instSlots ops) >>= makeStableName
        b <- evaluate (siSlots std) >>= makeStableName
        assertBool "one shared hub identity" (a == b)
        assertEqual "two actual catalog entries" [SlotId 0, SlotId 1] (Map.keys (siCatalog std))
        assertEqual "initial presence and epochs" (initial removable) =<< snapshotSlots (siSlots std)
        assertEqual "no startup indications" SlotNoEvent =<< waitSlot (instSlots ops) DontBlock
        assertBool "memory retains no store" (isNothing (siStore std))
        assertEqual "status catalog matches" [row 0 True 0, row 1 True 0] =<< status (instControl ops) []
        assertCapacity8 std
        if removable then do
          assertEqual "test-local shared transition" (Right (PresenceChanged 1))
            =<< atomically (publishPresenceSTM (siSlots std) (SlotId 1) False)
          assertEqual "Instance observes the same transition" [SlotSnapshot (SlotId 0) True True 0, SlotSnapshot (SlotId 1) True False 1]
            =<< snapshotSlots (instSlots ops)
          assertEqual "Control borrows the same epoch" [row 1 False 1]
            =<< status (instControl ops) [("offset", JNum 1), ("limit", JNum 1)]
          assertEqual "shared pending indication" (SlotReady (SlotId 1)) =<< waitSlot (instSlots ops) DontBlock
        else assertEqual "fixed slots refuse removal" (Left PresenceFixedSlot)
          =<< atomically (publishPresenceSTM (siSlots std) (SlotId 1) False)
  -- SQLite success/reopen: a single acquisition of each native owner per open,
  -- the existing store is borrowed and startup never replays a flag.
  let path = "/tmp/haskoki-notifications/engine-initial.db"
      cfg = (cfgTwo True) { cfgStorage = (cfgStorage defaultConfig) { scKind = StorageSQLite, scPath = Just path } }
  createDirectoryIfMissing True "/tmp/haskoki-notifications"
  bracket (removeDB path) (const (removeDB path)) $ \_ -> forM_ [1, 2 :: Int] $ \_ -> do
    ops <- buildInstance cfg
    counts <- newIORef ([] :: [String])
    let note x = modifyIORef' counts (++ [x])
        sa = counted note
    bracket (openStdInstanceWithSlots sa cfg (instSlots ops)) haskokiStdClose $ \sp -> do
      assertBool "SQLite opens/reopens" (not (isNull sp))
      std <- deRefStablePtr sp
      assertBool "SQLite has its one store" (not (isNothing (siStore std)))
      assertEqual "SQLite catalog fully seated" 2 (Map.size (siCatalog std))
      assertEqual "SQLite initial snapshot" (initial True) =<< snapshotSlots (siSlots std)
      assertEqual "SQLite startup flags clear" SlotNoEvent =<< waitSlot (siSlots std) DontBlock
      assertEqual "one backend and store acquisition" ["store+", "backend+"] =<< readIORef counts
    assertEqual "one close per acquired resource" ["store+", "backend+", "backend-", "store-"] =<< readIORef counts

assertCapacity8 :: StdInstance -> Assertion
assertCapacity8 std = do
  let table = siAsyncTable std
      sid = SessionId 919
      req = JobRequest sid JobSign (WorkCall (Reservation "T-N02" [] Nothing Nothing)
              (EffectCrypto (FxSign (MechanismId 0x251) Nothing BS.empty "abc"))) 2 64
  enableAsyncSession table sid
  accepted <- replicateM 8 (startJob table req)
  assertEqual "eight Standard jobs admitted" 8 (length [j | Right j <- accepted])
  assertEqual "ninth Standard job refused (private limit is 32)" (Left StartOverCapacity) =<< startJob table req
  assertEqual "refusal allocates no job" (8, 0, 8) =<< tableStats table

counted :: (String -> IO ()) -> StdAcquisition
counted note = stdAcquisition
  { saOpenStore = \env cfg -> do
      r <- saOpenStore stdAcquisition env cfg
      case r of Right _ -> note "store+"; Left _ -> pure ()
      pure r
  , saCloseStore = \s -> note "store-" >> saCloseStore stdAcquisition s
  , saOpenBackend = do
      r <- saOpenBackend stdAcquisition
      case r of EngineOk _ -> note "backend+"; EngineFail _ -> pure ()
      pure r
  , saCloseBackend = \be -> note "backend-" >> saCloseBackend stdAcquisition be
  }

removeDB :: FilePath -> IO ()
removeDB path = forM_ [path, path ++ "-wal", path ++ "-shm"] $ \p -> do
  exists <- doesFileExist p
  if exists then removeFile p else pure ()

-- Catches missed/double unwind, binding retained after failed publication,
-- open services after refusal, and failure state poisoning the next open.
caseServingAcquisitionUnwind :: Assertion
caseServingAcquisitionUnwind = do
  createDirectoryIfMissing True "/tmp/haskoki-notifications"
  forM_ ["store", "backend", "assembly", "binding"] $ \stage -> do
    let path = "/tmp/haskoki-notifications/unwind-" ++ stage ++ ".db"
        cfg = (cfgTwo True) { cfgStorage = (cfgStorage defaultConfig) { scKind = StorageSQLite, scPath = Just path } }
    bracket (removeDB path) (const (removeDB path)) $ \_ -> do
      ops <- buildInstance cfg
      counts <- newIORef ([] :: [String])
      let note x = modifyIORef' counts (++ [x])
          base = counted note
          owner std = PresenceOwner (snapshotSlots (siSlots std)) (\_ _ -> pure (Left PresenceFixedSlot))
          sa = base
            { saOpenStore = if stage == "store" then \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull)) else saOpenStore base
            , saOpenBackend = if stage == "backend" then pure (EngineFail (BackendUnsupported "T-N02" "injected")) else saOpenBackend base
            , saAssemble = if stage == "assembly" then \_ -> ioError (userError "assembly") else saAssemble base
            , saBindPresenceOwner = \std -> do
                bindPresenceOwner (instControl ops) (Just (owner std))
                ioError (userError "binding after install")
            , saUnbindPresenceOwner = bindPresenceOwner (instControl ops) Nothing
            }
      sp <- openStdInstanceWithSlots sa cfg (instSlots ops)
      assertBool (stage ++ " refuses") (isNull sp)
      assertEqual (stage ++ " service closed") SlotWaitClosed =<< waitSlot (instSlots ops) DontBlock
      (rv, _, _) <- dispatchControl (instControl ops) (request "status" []) (Just responseBudget)
      assertEqual (stage ++ " no owner remains") (fromIntegral (returnCodeToRV CKR_ARGUMENTS_BAD)) rv
      let want = case stage of
            "store" -> []
            "backend" -> ["store+", "store-"]
            _ -> ["store+", "backend+", "backend-", "store-"]
      assertEqual (stage ++ " releases exactly once") want =<< readIORef counts
      bracket (openStdInstance cfg) haskokiStdClose $ \retry -> assertBool (stage ++ " retry succeeds") (not (isNull retry))

-- Catches event-bound clamping and silent catalog truncation. Limits supplied
-- as resolved Config also exercise admission below the parser boundary.
caseServingConfigLimits :: Assertion
caseServingConfigLimits = do
  forM_ [0, 1] $ \bound -> do
    let cfg = (cfgTwo True) { cfgLimits = (cfgLimits (cfgTwo True)) { limEvents = bound } }
    bad <- try (buildInstance cfg) :: IO (Either SomeException Instance)
    assertBool "Instance refuses insufficient event bound" (case bad of Left _ -> True; Right _ -> False)
    sp <- openStdInstance cfg
    assertBool "Standard proof refuses insufficient event bound" (isNull sp)
  let small = (cfgTwo True) { cfgLimits = (cfgLimits (cfgTwo True)) { limSlots = 1 } }
  bad <- try (buildInstance small) :: IO (Either SomeException Instance)
  assertBool "Instance refuses catalog beyond slot limit" (case bad of Left _ -> True; Right _ -> False)
  sp <- openStdInstance small
  assertBool "Standard refuses whole catalog instead of truncating" (isNull sp)
  bracket (openStdInstance (cfgTwo True)) haskokiStdClose $ \ok -> do
    assertBool "catalog-sized event bound accepted" (not (isNull ok))
    std <- deRefStablePtr ok
    forM_ [SlotId 0, SlotId 1] $ \slot -> do
      r <- atomically (publishPresenceSTM (siSlots std) slot False)
      assertEqual "each slot can remain pending" (Right (PresenceChanged 1)) r
    assertEqual "first slot retained" (SlotReady (SlotId 0)) =<< waitSlot (siSlots std) DontBlock
    assertEqual "second slot retained" (SlotReady (SlotId 1)) =<< waitSlot (siSlots std) DontBlock
    assertEqual "no truncation/drop" SlotNoEvent =<< waitSlot (siSlots std) DontBlock

-- Catches implicit legacy-registry fallback and hooks outliving Standard.
caseServingControlOwnership :: MVar () -> Assertion
caseServingControlOwnership envLock = withServing envLock True $
  bracket haskokiInstanceOpen haskokiInstanceClose $ \cell -> do
    Just ops <- readLiveInstance cell
    _ <- insertToken (instRegistry ops) (SlotId 99)
    (unbound, _, _) <- dispatchControl (instControl ops) (request "status" []) (Just responseBudget)
    assertEqual "unpublished Control has no fallback owner" (fromIntegral (returnCodeToRV CKR_ARGUMENTS_BAD)) unbound
    bracket (haskokiStdOpen cell) haskokiStdClose $ \sp -> do
      assertBool "serving open" (not (isNull sp))
      assertEqual "status ignores populated private registry" [row 0 True 0, row 1 True 0] =<< status (instControl ops) []
      assertEqual "status pagination ends at catalog" [] =<< status (instControl ops) [("offset", JNum 2)]
      forM_ ["token.insert", "token.remove"] $ \cmd -> forM_ [99] $ \slot -> do
        (rv, _, _) <- dispatchControl (instControl ops) (request cmd [("slot", JNum slot)]) (Just responseBudget)
        assertEqual "unknown serving slot refuses" (fromIntegral (returnCodeToRV CKR_ARGUMENTS_BAD)) rv
      assertEqual "refusal does not advance generation" 0 =<< controlGeneration (instControl ops)
      assertEqual "refusal does not alter presence" (initial True) =<< snapshotSlots (instSlots ops)
      assertEqual "refusal produces no serving flag" SlotNoEvent =<< waitSlot (instSlots ops) DontBlock
      (inserted, _, _) <- dispatchControl (instControl ops) (request "token.insert" [("slot", JNum 0)]) (Just responseBudget)
      assertEqual "known serving idempotence uses owner" 0 inserted
      assertEqual "accepted idempotence counts a command" 1 =<< controlGeneration (instControl ops)
      assertEqual "idempotence retains serving epoch" (initial True) =<< snapshotSlots (instSlots ops)
      assertEqual "private registry untouched" True =<< tokenPresent (instRegistry ops) (SlotId 99)
    (closed, _, _) <- dispatchControl (instControl ops) (request "status" []) (Just responseBudget)
    assertEqual "Standard close clears borrowed owner" (fromIntegral (returnCodeToRV CKR_ARGUMENTS_BAD)) closed

-- T-N03 fixtures use the actual Standard table, native output bindings, two
-- real OpenSSL streams, and SQLite's existing detach/join workers.
data StoreLedger = StoreLedger
  { acquisitionCommits :: Int, asyncCommits :: Int, presenceCommits :: Int
  , resetCalls :: Int, reloadCalls :: Int, tokenLoads :: Int, jobLoads :: Int
  } deriving (Eq, Show)

emptyLedger :: StoreLedger
emptyLedger = StoreLedger 0 0 0 0 0 0 0

ledgerAcquisition :: IORef StoreLedger -> StdAcquisition
ledgerAcquisition ledger = stdAcquisition
  { saOpenStore = \env cfg -> do
      result <- saOpenStore stdAcquisition env cfg
      case result of
        Right (Just ss) -> do
          let store = stdStore ss
          stats <- Store.storeStats store
          modifyIORef' ledger (\x -> x { acquisitionCommits = Store.ssCommits stats })
          let countedStore = store
                { Store.storeLoadTokens = modifyIORef' ledger (\x -> x { tokenLoads = tokenLoads x + 1 }) >> Store.storeLoadTokens store
                , Store.storeLoadJobs = modifyIORef' ledger (\x -> x { jobLoads = jobLoads x + 1 }) >> Store.storeLoadJobs store
                , Store.storeCommit = \delta -> do
                    modifyIORef' ledger $ \x -> if null (Store.sdPutJobs delta) && null (Store.sdDropJobs delta)
                      then x { presenceCommits = presenceCommits x + 1 }
                      else x { asyncCommits = asyncCommits x + 1 }
                    Store.storeCommit store delta
                , Store.storeResetToken = \token gen rec -> do
                    modifyIORef' ledger (\x -> x { resetCalls = resetCalls x + 1 })
                    Store.storeResetToken store token gen rec
                , Store.storeReload = modifyIORef' ledger (\x -> x { reloadCalls = reloadCalls x + 1 }) >> Store.storeReload store
                }
          pure (Right (Just (ss { stdStore = countedStore })))
        _ -> pure result
  }

data RemovalFixture = RemovalFixture
  { rfPtr :: StablePtr StdInstance, rfStd :: StdInstance
  , rfSessions :: [CULong], rfJobs :: [JobId], rfViews :: [AsyncCtx]
  , rfIdle :: Word64, rfJoined :: Word64, rfBuffers :: [Ptr Word8]
  , rfLedger :: IORef StoreLedger
  }

mustRight :: Show e => Either e a -> IO a
mustRight = either (assertFailure . show) pure

sidOf :: CULong -> SessionId
sidOf (CULong h) = SessionId (fromIntegral h)

openSession :: StablePtr StdInstance -> CULong -> Bool -> IO CULong
openSession ctx slot async = alloca $ \out -> do
  poke out 0xa5a5a5a5a5a5a5a5
  haskokiStdOpenSessionWithAsync ctx slot 0 (if async then 1 else 0) out >>= assertEqual "open actual Standard session" 0
  peek out

withName :: (Ptr Word8 -> IO a) -> IO a
withName action = BS.useAsCString "C_Digest" (action . castPtr)

startDigest :: StablePtr StdInstance -> CULong -> Ptr Word8 -> IO ()
startDigest ctx h output = do
  haskokiStdDigestInit ctx h 0x250 nullPtr 0 >>= assertEqual "actual DigestInit" 0
  alloca $ \len -> BS.useAsCStringLen "abc" $ \(input, n) -> do
    poke len 32
    haskokiStdDigest ctx h (castPtr input) (fromIntegral n) output len >>= assertEqual "actual attached submission" (stdRvOf CKR_PENDING)
    peek len >>= assertEqual "submission does not write length" 32

withRemovalFixture :: String -> NotificationHooks -> Word64 -> Bool -> (RemovalFixture -> IO a) -> IO a
withRemovalFixture tag hooks epoch removable action = do
  createDirectoryIfMissing True "/tmp/haskoki-notifications"
  let path = "/tmp/haskoki-notifications/n03-" ++ tag ++ ".db"
      cfg = (cfgTwo removable) { cfgStorage = (cfgStorage defaultConfig) { scKind = StorageSQLite, scPath = Just path } }
  bracket (removeDB path) (const (removeDB path)) $ \_ -> allocaBytes 192 $ \buffers -> do
    pokeArray buffers (replicate 192 (0xa5 :: Word8))
    ledger <- newIORef emptyLedger
    hub <- newSlotEventsWith hooks epoch 2 [SlotDefinition (SlotId 0) removable, SlotDefinition (SlotId 1) removable] >>= mustRight
    bracket (openStdInstanceWithSlots (ledgerAcquisition ledger) cfg hub) haskokiStdClose $ \ctx -> do
      assertBool "SQLite fixture opens" (not (isNull ctx))
      inst <- deRefStablePtr ctx
      attached <- openSession ctx 0 True
      joined <- openSession ctx 0 True
      idle <- openSession ctx 0 True
      streamA <- openSession ctx 0 False
      streamB <- openSession ctx 0 False
      other <- openSession ctx 1 True
      let sessions = [attached, joined, idle, streamA, streamB, other]
          aBuf = buffers; jBuf = buffers `plusPtr` 64; otherBuf = buffers `plusPtr` 128
      startDigest ctx attached aBuf
      startDigest ctx joined jBuf
      joinedId <- withName $ \name -> alloca $ \out -> do
        haskokiStdAsyncGetId ctx joined name out >>= assertEqual "detach before Join" 0
        peek out
      withName $ \name -> haskokiStdAsyncJoin ctx joined name joinedId jBuf 32 >>= assertEqual "real joined attachment" 0
      startDigest ctx idle jBuf
      idleId <- withName $ \name -> alloca $ \out -> do
        haskokiStdAsyncGetId ctx idle name out >>= assertEqual "idle detached record" 0
        peek out
      startDigest ctx other otherBuf
      forM_ [streamA, streamB] $ \h -> do
        haskokiStdDigestInit ctx h 0x250 nullPtr 0 >>= assertEqual "stream init" 0
        BS.useAsCStringLen "abc" $ \(input, n) ->
          haskokiStdDigestUpdate ctx h (castPtr input) (fromIntegral n) >>= assertEqual "real multipart stream" 0
      BS.useAsCStringLen "1234" $ \(pin, n) ->
        haskokiStdLogin ctx streamA 1 (castPtr pin) (fromIntegral n) >>= assertEqual "login actual slot" 0
      -- Ordinary-object durability is unchanged; these are model records on
      -- the actual Standard owner, as produced by object publication.
      publish (siEnv inst) (StateDelta
        [ DeltaCreateObjectFull (ObjectId 901) Map.empty (Just (sidOf streamA)) (SlotId 0)
        , DeltaCreateObjectFull (ObjectId 902) (Map.singleton AttrToken (ValBool True)) Nothing (SlotId 0)
        , DeltaCreateObjectFull (ObjectId 903) (Map.singleton AttrToken (ValBool True)) Nothing (SlotId 1)
        , DeltaBindHandle (ExternalHandle 901) (ObjectId 901)
        , DeltaBindHandle (ExternalHandle 902) (ObjectId 902)
        , DeltaBindHandle (ExternalHandle 903) (ObjectId 903)
        ]) >>= mustRight
      Bytes.useAsCStringLen (Bytes.replicate 8 0) $ \(frame, n) ->
        forM_ [streamA, other] $ \h -> haskokiStdFindInit ctx h (castPtr frame) (fromIntegral n) >>= assertEqual "actual find cursor" 0
      views <- readIORef (siAsyncViews inst)
      contexts <- mapM (\h -> maybe (assertFailure "missing view") deRefStablePtr (Map.lookup (sidOf h) views)) sessions
      jobs <- mapM (\h -> do
        ids <- sessionJobs (siAsyncTable inst) (sidOf h)
        -- Detached originals may remain as tombstones; the highest job ID is
        -- the current attached job, including the new joined attachment.
        case reverse ids of j : _ -> pure j; [] -> assertFailure "missing actual job") [attached,joined,other]
      action (RemovalFixture ctx inst sessions jobs contexts (fromIntegral idleId) (fromIntegral joinedId) [aBuf,jBuf,otherBuf] ledger)

fixtureStore :: RemovalFixture -> Store.Store
fixtureStore f = case siStore (rfStd f) of Just ss -> stdStore ss; Nothing -> error "SQLite fixture lost store"

jobRecords :: RemovalFixture -> IO [Store.JobRecord]
jobRecords f = Store.storeLoadJobs (fixtureStore f) >>= mustRight

idleRecord :: RemovalFixture -> IO Store.JobRecord
idleRecord f = do
  records <- jobRecords f
  case filter ((== rfIdle f) . Store.jrPersistentId) records of
    [record] -> pure record
    _ -> assertFailure "idle detached record lost"

assertRetired :: RemovalFixture -> Assertion
assertRetired f = do
  let inst = rfStd f; other = last (rfSessions f)
  (m, slots) <- snapshotPresence (siEnv inst) (siSlots inst)
  assertEqual "all target sessions retired" [sidOf other] (Map.keys (mSessions m))
  assertEqual "atomic absence" [SlotSnapshot (SlotId 0) True False 1, SlotSnapshot (SlotId 1) True True 0] slots
  assertEqual "target notification pairs retired" [sidOf other] . Map.keys =<< readIORef (siNotify inst)
  assertEqual "target views freed" [sidOf other] . Map.keys =<< readIORef (siAsyncViews inst)
  assertEqual "target bindings gone" [(sidOf other,JobDigest)] . Map.keys =<< readIORef (siAsyncBindings inst)
  assertEqual "target cursors gone, other cursor retained" [sidOf other] . Map.keys =<< readIORef (siFind inst)
  mapM asyncLiveHandles (rfViews f) >>= assertEqual "only unrelated attachment remains" [0,0,0,0,0,1]
  assertEqual "session object destroyed" Nothing (lookupObject m (ObjectId 901))
  assertBool "token object parked" (lookupObject m (ObjectId 902) /= Nothing)
  assertEqual "target handles permanently deleted" [ExternalHandle 903] (Map.keys (mHandles m))
  assertEqual "active login reset" (Just Nothing) (taLogin <$> lookupTokenAuth m (SlotId 0))
  forM_ (take 2 (rfBuffers f)) $ \p -> peekArray 64 p >>= assertEqual "no later bytes or tail writes" (replicate 64 0xa5)

caseRemovalOwnsActualJobs :: Assertion
caseRemovalOwnsActualJobs = withRemovalFixture "jobs" (const (pure ())) 0 True $ \f -> do
  let inst = rfStd f
  before <- snapshotModel (siEnv inst)
  idle <- idleRecord f
  tokens <- Store.storeLoadTokens (fixtureStore f) >>= mustRight
  ctl <- buildInstance (cfgTwo True)
  let owner = PresenceOwner (snapshotSlots (siSlots inst)) (setStdTokenPresence inst)
      state = (,,,,) <$> snapshotPresence (siEnv inst) (siSlots inst)
        <*> readIORef (siFind inst) <*> (Map.keys <$> readIORef (siAsyncBindings inst))
        <*> mapM (snapshotJob (siAsyncTable inst)) (rfJobs f) <*> readIORef (rfLedger f)
      seeded generation allocation enabled = do
        control <- newControlStateWith generation allocation (cfgTwo True)
          (instRegistry ctl) (instAsync ctl) enabled False
        bindPresenceOwner control (Just owner)
        pure control
  bindPresenceOwner (instControl ctl) (Just owner)
  baseline <- state
  forM_ ["malformed", request "token.remove" [("slot",JNum 99)],
      request "token.remove" [("slot",JNum 0),("expected_generation",JNum 1)]] $ \bad -> do
    (code,_,_) <- dispatchControl (instControl ctl) bad (Just 65536)
    assertEqual "control validation refuses before real-job cleanup" 7 code
    state >>= assertEqual "control validation preserves actual Standard state" baseline
  disabled <- seeded 0 (pure ()) False
  exhausted <- seeded maxBound (pure ()) True
  forM_ [disabled,exhausted] $ \control -> do
    (code,_,_) <- dispatchControl control (request "token.remove" [("slot",JNum 0)]) (Just 65536)
    assertEqual "disabled/exhausted refuse" 7 code
    state >>= assertEqual "no cancellation on disabled/exhausted" baseline
  allocation <- seeded 0 (ioError (userError "reply allocation refused")) True
  refused <- try (dispatchControl allocation (request "token.remove" [("slot",JNum 0)]) (Just 65536))
    :: IO (Either SomeException (Word64,BS.ByteString,Word64))
  assertBool "allocation refusal observed before claim" (case refused of Left _ -> True; _ -> False)
  state >>= assertEqual "allocation failure preserves jobs, buffers, model, hub and store" baseline
  (rv, body, _) <- dispatchControl (instControl ctl) (request "token.remove" [("slot",JNum 0)]) (Just 65536)
  assertEqual "serving removal control succeeds" 0 rv
  case parseJson body of
    Right (JObj fields) -> assertEqual "counts attached plus joined" (Just (JNum 2)) (lookup "jobs_canceled" fields)
    _ -> assertFailure "bad removal response"
  assertRetired f
  idleRecord f >>= assertEqual "idle detached unchanged" idle
  Store.storeLoadTokens (fixtureStore f) >>= mustRight >>= assertEqual "durable token identity/auth/generation unchanged" tokens
  after <- snapshotModel (siEnv inst)
  assertEqual "parked token object unchanged" (lookupObject before (ObjectId 902)) (lookupObject after (ObjectId 902))
  assertEqual "other-slot session unchanged" (lookupSession before (sidOf (last (rfSessions f))))
    (lookupSession after (sidOf (last (rfSessions f))))
  writes <- newIORef (0 :: Int)
  let delivery = Delivery 64 (const (modifyIORef' writes (+1))) (const (assertFailure "canceled job reports output length"))
  forM_ (take 2 (rfJobs f)) $ \jid -> do
    completeJob (siEnv inst) (siAsyncTable inst) JobDigest jid delivery (const (pure ()))
      >>= assertEqual "canceled worker cannot deliver" (CompleteAlready TermCanceled)
  readIORef writes >>= assertEqual "zero post-publication sink writes" 0
  withName $ \name -> allocaBytes 40 $ \result -> forM_ (take 2 (rfSessions f)) $ \h -> do
    pokeArray (castPtr result) (replicate 40 (0xa5 :: Word8))
    haskokiStdAsyncComplete (rfPtr f) h name result >>= assertEqual "old session cannot Complete" (stdRvOf CKR_SESSION_HANDLE_INVALID)
    peekArray 40 (castPtr result :: Ptr Word8) >>= assertEqual "whole completion struct untouched" (replicate 40 0xa5)
  waitSlot (siSlots inst) DontBlock >>= assertEqual "one indication" (SlotReady (SlotId 0))
  setStdTokenPresence inst (SlotId 0) True >>= assertEqual "reinsert same token" (Right (PresenceChanged 2,0))
  newSession <- openSession (rfPtr f) 0 False
  assertBool "session IDs never recycled" (newSession > maximum (rfSessions f))
  Bytes.useAsCStringLen (Bytes.replicate 8 0) $ \(frame,n) ->
    haskokiStdFindInit (rfPtr f) newSession (castPtr frame) (fromIntegral n) >>= assertEqual "rediscover parked token" 0
  rediscovered <- snapshotModel (siEnv inst)
  assertBool "new handle counter advanced" (mNextHandle rediscovered > mNextHandle before)
  forM_ [ExternalHandle 901, ExternalHandle 902] $ \h ->
    assertEqual "old handle still stale after rediscovery" Nothing (resolveHandle rediscovered h)
  publish (siEnv inst) (StateDelta [DeltaSetAttributes (ObjectId 902) (Map.singleton AttrLabel (ValBytes "changed"))]) >>= mustRight
  mutated <- snapshotModel (siEnv inst)
  assertEqual "old handle stays stale after mutation" Nothing (resolveHandle mutated (ExternalHandle 902))
  assertEqual "new session starts logged out" (Just LoginPublic) (ssLogin <$> lookupSession mutated (sidOf newSession))
  -- Complete the other slot through its actual FFI entry and verify the known
  -- digest plus unused tail; removal did not consume its worker or allocation.
  withName $ \name -> allocaBytes 40 $ \result -> do
    haskokiStdAsyncComplete (rfPtr f) (last (rfSessions f)) name result >>= assertEqual "other slot first poll" (stdRvOf CKR_PENDING)
    haskokiStdAsyncComplete (rfPtr f) (last (rfSessions f)) name result >>= assertEqual "other slot completes" 0
  peekArray 32 (last (rfBuffers f)) >>= assertEqual "other slot SHA256 abc"
    [0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad]
  peekArray 32 (last (rfBuffers f) `plusPtr` 32) >>= assertEqual "other slot tail" (replicate 32 (0xa5 :: Word8))
  putStrLn "T-N03 caseRemovalOwnsActualJobs: jobs_canceled=2 idle_effects=0 other_slot_effects=0 later_writes=0 leaked_views=0"

-- Faults before and after the linearization point have deliberately different
-- contracts. No Async policy is replaced by a notifications-specific worker.
casePresenceCleanupFault :: MVar () -> Assertion
casePresenceCleanupFault envLock = do
  failBefore <- newIORef True
  let hook RemovalPrepublication = do
        shouldFail <- readIORef failBefore
        when shouldFail (ioError (userError "precommit"))
      hook _ = pure ()
  withRemovalFixture "precommit" hook 0 True $ \f -> do
    let inst = rfStd f
    pairs <- readIORef (siNotify inst)
    before <- snapshotPresence (siEnv inst) (siSlots inst)
    assertControlFault envLock inst (setStdTokenPresence inst)
    snapshotPresence (siEnv inst) (siSlots inst) >>= assertEqual "precommit keeps model and presence" before
    readIORef (siNotify inst) >>= assertEqual "precommit retains all associations" pairs
    waitSlot (siSlots inst) DontBlock >>= assertEqual "no false event" SlotNoEvent
    mapM asyncLiveHandles (rfViews f) >>= assertEqual "already canceled jobs stay canceled" [0,0,0,0,0,1]
    writeIORef failBefore False
    setStdTokenPresence inst (SlotId 0) False >>= assertEqual "retry finishes retirement without recancel count" (Right (PresenceChanged 1,0))
    assertRetired f
  withRemovalFixture "postcommit" (const (pure ())) 0 True $ \f -> do
    let inst = rfStd f
    before <- snapshotModel (siEnv inst)
    (_,_,releases) <- mustRight (prepareStdRemoval (envRules (siEnv inst)) before (SlotId 0))
    -- Every target session ran DigestInit: three async-related initial
    -- contexts plus the two contexts fed by multipart DigestUpdate.
    assertEqual "five actual native contexts" 5 (length releases)
    firstRelease <- case releases of
      rel : _ -> pure rel
      [] -> assertFailure "fixture did not allocate native resources"
    attempted <- newIORef []
    let release rel = do
          modifyIORef' attempted (++[rel])
          drainReleases (siBackend inst) [rel]
          when (rel == firstRelease) (ioError (userError "postcommit release"))
    assertControlFault envLock inst (setStdTokenPresenceWith release inst)
    readIORef attempted >>= assertEqual "finally attempts every release" releases
    assertRetired f
    forM_ releases $ \(ReleaseEngineResource resource) -> do
      resourceSaveability (siBackend inst) resource >>= assertEqual "native resource no longer live" (ResourceUnsaveable (UnsaveableGone resource))
    waitSlot (siSlots inst) DontBlock >>= assertEqual "committed event retained after release failure" (SlotReady (SlotId 0))
    setStdTokenPresence inst (SlotId 0) False >>= assertEqual "absence is not revived" (Right (PresenceUnchanged 1,0))
  forM_ ["unknown", "fixed", "exhausted", "closed", "model"] $ \kind ->
    withRemovalFixture ("refused-" ++ kind) (const (pure ()))
      (if kind == "exhausted" then maxBound else 0) (kind /= "fixed") $ \f -> do
        let inst = rfStd f
        when (kind == "closed") (closeSlotEvents (siSlots inst))
        env <- if kind == "model" then newEnv (envRules (siEnv inst)) else pure (siEnv inst)
        let owner = inst { siEnv = env }
            slot = if kind == "unknown" then SlotId 99 else SlotId 0
            want = case kind of
              "unknown" -> PresenceUnknownSlot
              "fixed" -> PresenceFixedSlot
              "exhausted" -> PresenceEpochExhausted
              "closed" -> PresenceClosed
              _ -> PresenceModelFault (FaultUnknownSlot (SlotId 0))
        snap <- snapshotPresence env (siSlots inst)
        stats <- tableStats (siAsyncTable inst)
        views <- mapM asyncLiveHandles (rfViews f)
        ledger <- readIORef (rfLedger f)
        setStdTokenPresence owner slot False >>= assertEqual (kind ++ " typed preflight") (Left want)
        snapshotPresence env (siSlots inst) >>= assertEqual "checked failure publishes neither half" snap
        tableStats (siAsyncTable inst) >>= assertEqual "checked failure before cancellation" stats
        mapM asyncLiveHandles (rfViews f) >>= assertEqual "checked failure retains attachments" views
        readIORef (rfLedger f) >>= assertEqual "checked failure calls no store operation" ledger
  putStrLn "T-N03 casePresenceCleanupFault: precommit_events=0 recanceled=0 postcommit_events=1 releases_attempted=5 checked_cancellations=0"

-- Reach the existing foreign-export exception fence with the actual Standard
-- owner. Both faults return GENERAL_ERROR and leave reply storage untouched;
-- the assertions above distinguish their pre/post-publication state effects.
assertControlFault :: MVar () -> StdInstance
  -> (SlotId -> Bool -> IO (Either PresenceError (PresenceChange,Int))) -> Assertion
assertControlFault envLock inst change = withServing envLock True $
  bracket haskokiInstanceOpen haskokiInstanceClose $ \cell -> do
    Just ops <- readLiveInstance cell
    bindPresenceOwner (instControl ops) (Just (PresenceOwner (snapshotSlots (siSlots inst)) change))
    BS.useAsCStringLen (request "token.remove" [("slot",JNum 0)]) $ \(req, n) ->
      allocaBytes 65536 $ \response -> alloca $ \len -> do
        pokeArray response (replicate 65536 (0xa5 :: Word8))
        poke len 65536
        haskokiControl cell (castPtr req) (fromIntegral n) response len >>= assertEqual "outer unexpected-exception RV" 0x05
        peek len >>= assertEqual "exception preserves response length" 65536
        peekArray 65536 response >>= assertEqual "exception preserves entire response buffer" (replicate 65536 0xa5)

casePresenceStoreLedger :: Assertion
casePresenceStoreLedger = do
  withRemovalFixture "ledger" (const (pure ())) 0 True $ \f -> do
    let inst = rfStd f
    idle <- idleRecord f
    tokens <- Store.storeLoadTokens (fixtureStore f) >>= mustRight
    before <- readIORef (rfLedger f)
    setStdTokenPresence inst (SlotId 0) False >>= assertEqual "ledger remove" (Right (PresenceChanged 1,2))
    setStdTokenPresence inst (SlotId 0) True >>= assertEqual "ledger reinsert" (Right (PresenceChanged 2,0))
    after <- readIORef (rfLedger f)
    assertEqual "no reset calls" 0 (resetCalls after)
    assertEqual "no presence commits" 0 (presenceCommits after)
    assertEqual "no reloads" 0 (reloadCalls after)
    assertEqual "no presence token load" (tokenLoads before) (tokenLoads after)
    assertEqual "cancelJoined has its necessary durable write" 1 (asyncCommits after - asyncCommits before)
    assertEqual "cancelJoined reads its existing durable record" 1 (jobLoads after - jobLoads before)
    assertEqual "acquisition committed provisioning once" 1 (acquisitionCommits after)
    idleRecord f >>= assertEqual "idle record exact bytes/state retained" idle
    records <- jobRecords f
    assertEqual "joined durable record canceled" [Store.JobCanceled]
      [Store.jrState r | r <- records, Store.jrPersistentId r == rfJoined f]
    Store.storeLoadTokens (fixtureStore f) >>= mustRight >>= assertEqual "stored generations/auth never changed" tokens
    control <- buildInstance (cfgTwo True)
    bindPresenceOwner (instControl control) (Just (PresenceOwner (snapshotSlots (siSlots inst)) (setStdTokenPresence inst)))
    (rv, _, _) <- dispatchControl (instControl control) (request "token.insert" [("slot",JNum 0)]) (Just 65536)
    assertEqual "idempotent command accepted" 0 rv
    controlGeneration (instControl control) >>= assertEqual "control identity distinct from epoch" 1
    snapshotSlots (siSlots inst) >>= assertEqual "presence epoch distinct from stored generation"
      [SlotSnapshot (SlotId 0) True True 2, SlotSnapshot (SlotId 1) True True 0]
  -- Memory keeps its no-store limitation and still retires real sessions.
  bracket (openStdInstance (cfgTwo True)) haskokiStdClose $ \ctx -> do
    std <- deRefStablePtr ctx
    assertBool "memory has no new store" (isNothing (siStore std))
    _ <- openSession ctx 0 False
    setStdTokenPresence std (SlotId 0) False >>= assertEqual "memory retirement" (Right (PresenceChanged 1,0))
  putStrLn "T-N03 casePresenceStoreLedger: store_resets=0 presence_commits=0 presence_reloads=0 acquisition_commits=1 cancellation_async_commits=1 cancellation_job_loads=1"

-- T-N05 uses constructor-injected T-N01 hooks with a real retained cell and
-- Standard owner. No global root or process environment is needed by fixtures.
withWaitInterval
  :: NotificationHooks
  -> (StablePtr InstanceCell -> Instance -> IO () -> Assertion)
  -> Assertion
withWaitInterval hooks action = do
  let cfg = (cfgTwo True) { cfgTrace = (cfgTrace defaultConfig) { tcEnabled = False } }
  original <- buildInstance cfg
  closeSlotEvents (instSlots original)
  hub <- newSlotEventsWith hooks 0 2 [SlotDefinition (SlotId 0) True, SlotDefinition (SlotId 1) True]
    >>= either (assertFailure . show) pure
  bracket (newInstanceCell (original { instSlots = hub })) haskokiInstanceClose $ \cell -> do
    Just ops <- readLiveInstance cell
    std <- haskokiStdOpen cell
    assertBool "Standard borrows the fixture cell" (not (isNull std))
    stdLive <- newIORef True
    let close = do
          haskokiInstanceClose cell
          first <- atomicModifyIORef' stdLive (\live -> (False, live))
          when first (haskokiStdClose std)
    bracket (pure ()) (const close) $ \_ -> action cell ops close

waitBounded :: String -> IO a -> IO a
waitBounded label action = timeout 2000000 action >>= maybe (assertFailure label) pure

withWaitThread :: IO a -> ((ThreadId, MVar (Either SomeException a)) -> IO b) -> IO b
withWaitThread action k = do
  done <- newEmptyMVar
  bracket (forkFinally action (putMVar done)) killThread $ \tid -> k (tid, done)

joinWait :: (ThreadId, MVar (Either SomeException a)) -> IO a
joinWait (_, done) = waitBounded "bounded waiter join" (readMVar done) >>= either (assertFailure . show) pure

waitParked :: ThreadId -> Assertion
waitParked tid = waitBounded "waiter never entered STM retry" loop
  where
    loop = threadStatus tid >>= \state -> case state of
      ThreadBlocked BlockedOnSTM -> pure ()
      ThreadRunning -> yield >> loop
      _ -> assertFailure ("unexpected waiter state: " ++ show state)

waitSentinel :: CULong
waitSentinel = 0xa5a5a5a5a5a5a5a5

withWaitOutput :: (Ptr CULong -> IO [CULong] -> IO a) -> IO a
withWaitOutput action = allocaBytes (3 * sizeOf waitSentinel) $ \raw -> do
  let base = castPtr raw :: Ptr CULong
  pokeArray base (replicate 3 waitSentinel)
  action (base `plusPtr` sizeOf waitSentinel) (peekArray 3 base)

ffiWait :: StablePtr InstanceCell -> CULong -> IO (CULong, [CULong])
ffiWait cell flags = withWaitOutput $ \out inspect -> do
  rv <- haskokiWaitForSlotEvent cell flags out
  bytes <- inspect
  pure (rv, bytes)

closedWait :: (CULong, [CULong])
closedWait = (0x190, replicate 3 waitSentinel)

publishWaitFlag :: SlotEvents -> SlotId -> Assertion
publishWaitFlag hub slot = atomically (publishPresenceSTM hub slot False)
  >>= assertEqual "one real presence transition" (Right (PresenceChanged 1))

assertClosedOwner :: Instance -> Assertion
assertClosedOwner ops = do
  (rv, _, _) <- dispatchControl (instControl ops) (request "status" []) (Just responseBudget)
  assertEqual "closed cell unbinds serving owner" 7 rv

schedule :: Int -> String -> Assertion
schedule number label = putStrLn ("T-N05 schedule " ++ show number ++ " " ++ label ++ " PASS")

-- Catches queued-tail delivery, revocation of an owned decision, migration to
-- a reopened interval, and freeing a captured cell. The native subprobe below
-- also executes the real C Finalize state-lock refusal and teardown ordering.
caseServingFinalizeOrder :: Assertion
caseServingFinalizeOrder = do
  retrySeen <- newTQueueIO
  emptyClosed <- newEmptyMVar
  let emptyHook point = case point of
        WaitBeforeRetry -> atomically (writeTQueue retrySeen ())
        CloseCommitted -> do
          previous <- tryReadMVar emptyClosed
          when (isNothing previous) (putMVar emptyClosed ())
        _ -> pure ()
  withWaitInterval emptyHook $ \cell ops close ->
    withWaitThread (ffiWait cell 0) $ \a -> withWaitThread (ffiWait cell 0) $ \b -> do
      replicateM_ 2 (waitBounded "empty pre-retry" (atomically (readTQueue retrySeen)))
      mapM_ (waitParked . fst) [a, b]
      waitBounded "close must make blockers runnable" close
      waitBounded "empty close transaction observed" (readMVar emptyClosed)
      readLiveInstance cell >>= assertBool "empty cell retained, value removed" . isNothing
      assertClosedOwner ops
      mapM joinWait [a, b] >>= assertEqual "empty close wakes every blocker" [closedWait, closedWait]
      schedule 1 "empty-close"

  captured <- newTQueueIO
  resume <- newEmptyMVar
  closeSeen <- newEmptyMVar
  let captureHook point = case point of
        WaitCaptured -> atomically (writeTQueue captured ()) >> readMVar resume
        CloseCommitted -> do
          previous <- tryReadMVar closeSeen
          when (isNothing previous) (putMVar closeSeen ())
        _ -> pure ()
  withWaitInterval captureHook $ \cell ops close -> do
    mapM_ (publishWaitFlag (instSlots ops)) [SlotId 0, SlotId 1]
    withWaitThread (ffiWait cell 0) $ \a -> withWaitThread (ffiWait cell 1) $ \b -> do
      replicateM_ 2 (waitBounded "captured before queued close" (atomically (readTQueue captured)))
      close
      waitBounded "close transaction observed" (readMVar closeSeen)
      putMVar resume ()
      mapM joinWait [a, b] >>= assertEqual "close-first discards queued flags" [closedWait, closedWait]
      schedule 2 "queued-close-first"

  decided <- newEmptyMVar
  outputAllowed <- newEmptyMVar
  let decisionHook point = case point of
        WaitDecisionCommitted (SlotReady _) -> putMVar decided () >> readMVar outputAllowed
        _ -> pure ()
  withWaitInterval decisionHook $ \cell ops close -> withWaitOutput $ \out inspect -> do
    publishWaitFlag (instSlots ops) (SlotId 0)
    -- This barrier models descheduling only; no exception is injected at this
    -- interruptible test hook. The injection case below uses no blocking hook.
    withWaitThread (haskokiWaitForSlotEvent cell 0 out) $ \worker@(_, done) -> do
      waitBounded "event decision committed" (readMVar decided)
      waitBounded "Finalize cannot join a decided application thread" close
      tryReadMVar done >>= assertBool "decided thread still delayed" . isNothing
      inspect >>= assertEqual "output deliberately delayed" (replicate 3 waitSentinel)
      putMVar outputAllowed ()
      joinWait worker >>= assertEqual "owned OK survives later Finalize" 0
      inspect >>= assertEqual "exactly one normal output write" [waitSentinel, 0, waitSentinel]
      schedule 3 "claim-close-delayed-output"

  withWaitInterval (const (pure ())) $ \oldCell old closeOld -> do
    -- A C entrant has retained this exact cell but has not entered the FFI.
    let capturedCell = oldCell
    closeOld
    assertClosedOwner old
    withWaitInterval (const (pure ())) $ \newCell new _ -> do
      assertBool "fresh interval has a distinct, never reused cell" (castStablePtrToPtr oldCell /= castStablePtrToPtr newCell)
      ffiWait newCell 1 >>= assertEqual "reopen initially clear" (8, replicate 3 waitSentinel)
      publishWaitFlag (instSlots new) (SlotId 1)
      forM_ [0, 1] $ \flags -> ffiWait capturedCell flags >>= assertEqual "old cell cannot migrate" closedWait
      ffiWait newCell 1 >>= assertEqual "old cell never claimed new flag" (0, [waitSentinel, 1, waitSentinel])
      schedule 4 "retained-cell-after-reopen"

  hubCaptured <- newEmptyMVar
  enterDecision <- newEmptyMVar
  let retainedHook point = case point of
        WaitCaptured -> putMVar hubCaptured () >> readMVar enterDecision
        _ -> pure ()
  withWaitInterval retainedHook $ \oldCell _ closeOld ->
    withWaitThread (ffiWait oldCell 0) $ \worker -> do
      waitBounded "old service retained inside wait" (readMVar hubCaptured)
      closeOld
      withWaitInterval (const (pure ())) $ \newCell new _ -> do
        ffiWait newCell 1 >>= assertEqual "new hub initially clear" (8, replicate 3 waitSentinel)
        publishWaitFlag (instSlots new) (SlotId 0)
        putMVar enterDecision ()
        joinWait worker >>= assertEqual "retained old hub stays closed" closedWait
        ffiWait newCell 1 >>= assertEqual "no waiter migration" (0, [waitSentinel, 0, waitSentinel])
        schedule 5 "retained-hub-after-reopen"
  runFinalizeProbe
  putStrLn "T-N05 lifetime closed-tail-deliveries=0 waiter-migrations=0 freed-cell-dereferences=0 bounded-joins=complete"

-- Catches an uninterruptible empty retry or an unmasked claim/output window.
-- Native invalid output pointers are outside the handoff guarantee.
caseServingMaskedHandoff :: Assertion
caseServingMaskedHandoff = do
  retrySeen <- newEmptyMVar
  let emptyHook point = case point of
        WaitBeforeRetry -> putMVar retrySeen ()
        _ -> pure ()
  withWaitInterval emptyHook $ \cell ops _ -> withWaitThread (ffiWait cell 0) $ \worker -> do
    waitBounded "empty wait observed" (readMVar retrySeen)
    waitParked (fst worker)
    waitBounded "empty retry must remain interruptible" (throwTo (fst worker) ThreadKilled)
    joinWait worker >>= assertEqual "foreign fence preserves sentinel without claim" (5, replicate 3 waitSentinel)
    publishWaitFlag (instSlots ops) (SlotId 0)
    ffiWait cell 1 >>= assertEqual "exception leaves interval usable" (0, [waitSentinel, 0, waitSentinel])
    putStrLn "T-N05 mask empty-retry GENERAL_ERROR sentinel=unchanged interruptible=yes"

  maskSeen <- newIORef Nothing
  injectorDone <- newEmptyMVar
  outsideHandoff <- newEmptyMVar
  let handoffHook point = case point of
        WaitDecisionCommitted (SlotReady _) -> do
          state <- getMaskingState
          writeIORef maskSeen (Just state)
          assertEqual "claim-to-output is masked" MaskedInterruptible state
          target <- myThreadId
          sender <- forkFinally (throwTo target ThreadKilled) (putMVar injectorDone)
          -- Only scheduler yields and status reads: no interruptible MVar/STM
          -- wait inside the protected handoff. Bound the observation by work,
          -- because a timeout exception itself is deferred by the mask.
          let queued 0 = assertFailure "injector did not queue its exception"
              queued n = threadStatus sender >>= \status' -> case status' of
                ThreadBlocked BlockedOnException -> pure ()
                ThreadRunning -> yield >> queued (n - 1)
                _ -> assertFailure ("injector escaped protected handoff: " ++ show status')
          queued (100000 :: Int)
        _ -> pure ()
  withWaitInterval handoffHook $ \cell ops _ -> do
    publishWaitFlag (instSlots ops) (SlotId 1)
    withWaitThread (withWaitOutput $ \out inspect -> mask $ \restore -> do
      result <- try (restore (haskokiWaitForSlotEvent cell 0 out))
      bytes <- inspect
      -- A blocked throwTo sender need not have dispatched at one immediate
      -- allowInterrupt. If the call returned OK, wait for delivery OUTSIDE
      -- the protected handoff, after snapshotting the completed output. The
      -- bounded worker join contains a missing injection; no timer produces it.
      delivered <- case result of
        Right 0 -> try (restore (takeMVar outsideHandoff))
        _ -> pure (Right ())
      pure (result :: Either SomeException CULong, bytes, delivered :: Either SomeException ())) $ \worker -> do
        (result, bytes, delivered) <- joinWait worker
        readIORef maskSeen >>= assertEqual "observed real FFI mask" (Just MaskedInterruptible)
        assertEqual "queued exception cannot suppress the normal write" [waitSentinel, 1, waitSentinel] bytes
        case (result, delivered) of
          (Right 0, Left ex) -> assertEqual "delivery after normal return" (Just ThreadKilled) (fromException ex)
          (Right 5, Right ()) -> pure () -- The outer foreign fence caught it.
          (Left ex, Right ()) -> assertEqual "delivery outside protected handoff" (Just ThreadKilled) (fromException ex)
          other -> assertFailure ("exception must be delivered exactly once outside handoff: " ++ show other)
        waitBounded "injector bounded join" (readMVar injectorDone) >>= either (assertFailure . show) pure
        ffiWait cell 1 >>= assertEqual "committed flag acknowledged exactly once" (8, replicate 3 waitSentinel)
        putStrLn "T-N05 mask decided-handoff MaskedInterruptible injection=queued output=written delivery=outside"

-- The engine test keeps the native fixture durable in this file. It compiles
-- the real lifecycle/root translation units with mock Haskell resource edges;
-- no public module is loaded and no installed behavior is claimed. The same
-- bytes are used by the separately recorded run-finalize.sh red/green probe.
foreign import ccall safe "system" nativeSystem :: CString -> IO CInt

runFinalizeProbe :: Assertion
runFinalizeProbe = do
  createDirectoryIfMissing True "/tmp/haskoki-notifications"
  writeFile "/tmp/haskoki-notifications/finalize-probe.c" finalizeProbeSource
  let child :: String -> [String] -> Assertion
      child label argv = do
        putStrLn ("T-N05 child " ++ label ++ " argv=" ++ show argv)
        hFlush stdout
        result <- withCString (unwords (map quote argv)) nativeSystem
        putStrLn ("T-N05 child " ++ label ++ " exit=" ++ show result)
        assertEqual ("native Finalize " ++ label) 0 result
      quote :: String -> String
      quote s = "'" ++ concatMap (\c -> if c == '\'' then "'\\''" else [c]) s ++ "'"
  child "compile" ["cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
    "-ffunction-sections", "-fdata-sections", "-Icbits", "-Ispec/vendor",
    "/tmp/haskoki-notifications/finalize-probe.c", "cbits/standard_surface.c", "cbits/notify_guard.c",
    "-Wl,--gc-sections", "-lpthread", "-o", "/tmp/haskoki-notifications/finalize-probe"]
  -- Preserve the actual engine-built executable before Docker removes /tmp.
  cwd <- getCurrentDirectory
  let artifacts = cwd ++ "/dist-release-evidence/notifications/task-n05/native-probes"
  createDirectoryIfMissing True artifacts
  (artifact, handle) <- openBinaryTempFile artifacts "finalize-probe"
  Bytes.readFile "/tmp/haskoki-notifications/finalize-probe" >>= Bytes.hPut handle
  hClose handle
  writeFile (artifact ++ ".c") finalizeProbeSource
  putStrLn ("T-N05 native artifact=" ++ artifact)
  child "run" ["/tmp/haskoki-notifications/finalize-probe"]

finalizeProbeSource :: String
finalizeProbeSource = unlines
  [ "/* T-N05: real production C lifecycle/root paths, mock Haskell resource edges."
  , " * The durable source is embedded in NotificationsEngineSpec.hs. */"
  , "#include <stdio.h>"
  , "#include <stdlib.h>"
  , "#include \"function_tables.c\""
  , "#include \"control_entry.c\""
  , ""
  , "static int failures, hub_live, owner_live, backend_live, store_live, pending;"
  , "static int closed, released, refuse_lock, held, destroys;"
  , "static int cell_cookie, standard_cookie, mutex_cookie;"
  , "static char ledger[64];"
  , "static size_t used;"
  , ""
  , "static void check(int ok, const char *label) {"
  , "  if (!ok) { fprintf(stderr, \"FAIL %s\\n\", label); ++failures; }"
  , "}"
  , "static void note(char event) {"
  , "  check(used + 1 < sizeof ledger, \"bounded lifecycle ledger\");"
  , "  if (used + 1 < sizeof ledger) { ledger[used++] = event; ledger[used] = '\\0'; }"
  , "}"
  , "int haskoki_rts_ensure(void) { return 0; }"
  , "int haskoki_c_entry_ok(void) { return 1; }"
  , "void *haskoki_instance_open(void) {"
  , "  hub_live = 1; pending = 0;"
  , "  return &cell_cookie;"
  , "}"
  , "void *haskoki_std_open(void *cell) {"
  , "  check(cell == &cell_cookie && hub_live, \"Standard borrows live hub\");"
  , "  owner_live = backend_live = store_live = 1;"
  , "  return &standard_cookie;"
  , "}"
  , "void haskoki_instance_close(void *cell) {"
  , "  check(cell == &cell_cookie, \"close exact retained cell\");"
  , "  check(haskoki_instance_get() == NULL, \"unpublish root before cell close\");"
  , "  check(!g_have_negotiated || held, \"close under state lock\");"
  , "  hub_live = 0; pending = 0; ++closed; note('C');"
  , "  owner_live = 0; note('U');"
  , "  puts(\"T-N05 native close/unbind committed\");"
  , "}"
  , "void haskoki_std_close(void *std) {"
  , "  check(std == &standard_cookie && backend_live && store_live, \"release owned native resources once\");"
  , "  check(!hub_live && !owner_live && haskoki_instance_get() == NULL,"
  , "        \"close-before-teardown: Standard released before shared service close/unbind\");"
  , "  check(!g_have_negotiated || held, \"teardown under state lock\");"
  , "  backend_live = 0; note('B');"
  , "  store_live = 0; note('S'); ++released;"
  , "  puts(\"T-N05 native backend/store released\");"
  , "}"
  , "unsigned long haskoki_wait_for_slot_event(void *cell, unsigned long flags, unsigned long *slot) {"
  , "  (void)flags;"
  , "  check(cell == &cell_cookie, \"wait uses captured cell\");"
  , "  if (!hub_live) return CKR_CRYPTOKI_NOT_INITIALIZED;"
  , "  if (!pending) return 8;"
  , "  pending = 0; *slot = 0; return CKR_OK;"
  , "}"
  , "static CK_RV create_mutex(CK_VOID_PTR *out) { *out = &mutex_cookie; return CKR_OK; }"
  , "static CK_RV lock_mutex(CK_VOID_PTR mu) {"
  , "  check(mu == &mutex_cookie && !held, \"nonrecursive state lock\");"
  , "  if (refuse_lock) return CKR_CANT_LOCK;"
  , "  held = 1; return CKR_OK;"
  , "}"
  , "static CK_RV unlock_mutex(CK_VOID_PTR mu) {"
  , "  check(mu == &mutex_cookie && held, \"unlock held state lock\");"
  , "  held = 0; return CKR_OK;"
  , "}"
  , "static CK_RV destroy_mutex(CK_VOID_PTR mu) {"
  , "  check(mu == &mutex_cookie && !held, \"destroy unlocked mutex\");"
  , "  ++destroys; return CKR_OK;"
  , "}"
  , "static CK_C_INITIALIZE_ARGS args = {create_mutex, destroy_mutex, lock_mutex, unlock_mutex, 0, NULL};"
  , ""
  , "static void finish_interval(int negotiated) {"
  , "  int before = closed;"
  , "  used = 0; ledger[0] = '\\0';"
  , "  pending = 1;"
  , "  check(on_Finalize(NULL) == CKR_OK, \"Finalize successful close\");"
  , "  check(strcmp(ledger, \"CUBS\") == 0, \"close-before-teardown: exact close/unbind/backend/store order\");"
  , "  check(closed == before + 1 && closed == released, \"one close and release per interval\");"
  , "  check(!hub_live && !owner_live && !backend_live && !store_live && !pending,"
  , "        \"closed interval has no live owner or pending flag\");"
  , "  check(!live_interval() && !haskoki_instance_get() && !haskoki_std_get(), \"both roots unpublished\");"
  , "  check(!held && !g_have_negotiated, \"locking retired\");"
  , "  unsigned long slot = 0xa5a5a5a5a5a5a5a5UL;"
  , "  check(on_WaitForSlotEvent(1, &slot, NULL) == CKR_CRYPTOKI_NOT_INITIALIZED &&"
  , "        slot == 0xa5a5a5a5a5a5a5a5UL, \"closed wait leaves sentinel unchanged\");"
  , "  check(on_Finalize(NULL) == CKR_CRYPTOKI_NOT_INITIALIZED && closed == before + 1,"
  , "        \"repeated Finalize cannot release twice\");"
  , "  printf(\"T-N05 native order locking=%s ledger=%s\\n\", negotiated ? \"negotiated\" : \"internal\", ledger);"
  , "}"
  , "int main(void) {"
  , "  check(on_Initialize(NULL) == CKR_OK, \"internal initialization\");"
  , "  finish_interval(0);"
  , "  check(on_Initialize(&args) == CKR_OK, \"negotiated reopen\");"
  , "  unsigned long slot = 0xa5a5a5a5a5a5a5a5UL;"
  , "  check(on_WaitForSlotEvent(1, &slot, NULL) == 8 && slot == 0xa5a5a5a5a5a5a5a5UL,"
  , "        \"new interval starts clear\");"
  , "  int before_closed = closed, before_released = released, before_destroys = destroys;"
  , "  used = 0; ledger[0] = '\\0';"
  , "  refuse_lock = 1;"
  , "  check(on_Finalize(NULL) == CKR_CANT_LOCK, \"Finalize first returns CKR_CANT_LOCK\");"
  , "  check(live_interval() && haskoki_instance_get() == &cell_cookie &&"
  , "        haskoki_std_get() == &standard_cookie && hub_live && owner_live && backend_live && store_live,"
  , "        \"lock refusal restores liveness with same usable hub\");"
  , "  check(closed == before_closed && released == before_released && destroys == before_destroys && used == 0,"
  , "        \"lock refusal does not close/unbind/release/destroy\");"
  , "  pending = 1;"
  , "  check(on_WaitForSlotEvent(1, &slot, NULL) == CKR_OK && slot == 0,"
  , "        \"usable interval after lock refusal accepts one wait\");"
  , "  refuse_lock = 0;"
  , "  finish_interval(1);"
  , "  check(destroys == before_destroys + 1, \"successful retry retires negotiated mutex once\");"
  , "  if (!failures) puts(\"T-N05 schedule 6 state-lock-refusal-retry PASS\");"
  , "  printf(\"T-N05 native assertions: %s (%d failures)\\n\", failures ? \"FAIL\" : \"PASS\", failures);"
  , "  return failures ? 1 : 0;"
  , "}"
  ]


-- T-N06: these fail if pointers are discarded, installed after handle delivery,
-- stranded by admission/release failure, invoked on teardown, or lose TLS/thread.
foreign import ccall unsafe "&notifications_callback"
  notifyCallback :: FunPtr NativeNotify
foreign import ccall unsafe "notifications_reset"
  notifyReset :: CULong -> IO ()
foreign import ccall unsafe "notifications_read"
  notifyRead :: CULong -> IO CULong
foreign import ccall unsafe "notifications_cookie"
  notifyCookie :: IO (Ptr ())
foreign import ccall safe "notifications_invoke"
  notifyInvoke :: FunPtr NativeNotify -> CULong -> CULong -> Ptr () -> IO CULong
foreign import ccall unsafe "haskoki_in_notify"
  inNotify :: IO CInt

withNotifyInstance :: NotifyInvoker -> (StablePtr StdInstance -> StdInstance -> IO a) -> IO a
withNotifyInstance invoker action = do
  hub <- newSlotEvents 2 [SlotDefinition (SlotId 0) True, SlotDefinition (SlotId 1) True] >>= mustRight
  bracket (openStdInstanceWithNotify stdAcquisition (cfgTwo True) hub invoker) haskokiStdClose $ \ptr -> do
    assertBool "notification owner acquired" (not (isNull ptr))
    deRefStablePtr ptr >>= action ptr

openNotify :: StablePtr StdInstance -> CULong -> Ptr () -> FunPtr NativeNotify -> IO CULong
openNotify ptr slot cookie callback = alloca $ \out -> do
  poke out 0xa5a5a5a5a5a5a5a5
  haskokiStdOpenSessionWithNotify ptr slot 0 0 cookie callback out >>= assertEqual "notify session admitted" 0
  peek out

assertNotifyEmpty :: StdInstance -> Assertion
assertNotifyEmpty inst = do
  readIORef (siNotify inst) >>= assertBool "no leaked pairs" . Map.null
  readIORef (siAsyncViews inst) >>= assertBool "no leaked views" . Map.null
  readIORef (siAsyncBindings inst) >>= assertBool "no leaked bindings" . Map.null
  snapshotModel (siEnv inst) >>= assertBool "no leaked model sessions" . Map.null . mSessions

caseNativeNotifyAssociation :: Assertion
caseNativeNotifyAssociation = runInBoundThread $ allocaBytes 1 $ \cookie -> do
  notifyReset 0
  withNotifyInstance notifyInvoke $ \ptr inst -> do
    forM_ [(nullFunPtr,nullPtr),(nullFunPtr,cookie),(notifyCallback,nullPtr),(notifyCallback,cookie)] $ \(callback,application) -> do
      handle <- openNotify ptr 0 application callback
      pairs <- readIORef (siNotify inst)
      assertEqual "retains exact independent pointer pair before output" (Just (SessionNotify callback application)) (Map.lookup (sidOf handle) pairs)
      haskokiStdCloseSession ptr handle >>= assertEqual "shape closes" 0
      assertNotifyEmpty inst
    notifyRead 0 >>= assertEqual "open and close emit zero callbacks" 0
    allocaBytes 1 $ \otherCookie -> do
      a <- openNotify ptr 0 cookie notifyCallback
      b <- openNotify ptr 0 otherCookie notifyCallback
      assertBool "distinct actual handles and cookie addresses" (a /= b && cookie /= otherCookie)
      forM_ [(a,cookie),(b,otherCookie)] $ \(handle,application) -> do
        notifyReset 0
        surrenderDigest inst (sidOf handle) >>= assertEqual "explicit dispatcher continues" NotifyContinue
        notifyRead 0 >>= assertEqual "one explicit invocation" 1
        notifyRead 1 >>= assertEqual "actual admitted session" handle
        notifyRead 2 >>= assertEqual "numeric CKN_SURRENDER" 0
        notifyCookie >>= assertEqual "exact application address" application
      haskokiStdCloseAllSessions ptr 0 >>= assertEqual "both close" 0
      assertNotifyEmpty inst
    alloca $ \out -> do
      poke out 0xa5a5a5a5a5a5a5a5
      haskokiStdOpenSessionWithNotify ptr 99 0 1 cookie notifyCallback out >>= assertEqual "unknown slot refused" 3
      peek out >>= assertEqual "failed admission preserves sentinel" 0xa5a5a5a5a5a5a5a5
      assertNotifyEmpty inst
  forM_ [BeforeModelAdmission,AfterModelAdmission,BeforeNotifyRegistration,AfterNotifyRegistration,BeforeBorrowedViewInstall,AfterBorrowedViewInstall] $ \point ->
    withNotifyInstance notifyInvoke $ \ptr inst -> alloca $ \out -> do
      poke out 0xa5a5a5a5a5a5a5a5
      reached <- newIORef []
      let observe phase = do
            modifyIORef' reached (++ [phase])
            model <- snapshotModel (siEnv inst)
            let sessions = Map.keys (mSessions model)
            case phase of
              BeforeModelAdmission -> assertEqual "not yet admitted" [] sessions
              _ -> assertEqual "one admitted session" 1 (length sessions)
            pairs <- Map.size <$> readIORef (siNotify inst)
            views <- Map.size <$> readIORef (siAsyncViews inst)
            assertEqual "registry insertion phase" (if phase `elem` [AfterNotifyRegistration,BeforeBorrowedViewInstall,AfterBorrowedViewInstall] then 1 else 0) pairs
            assertEqual "view installation phase" (if phase == AfterBorrowedViewInstall then 1 else 0) views
            peek out >>= assertEqual "no early handle publication at any phase" 0xa5a5a5a5a5a5a5a5
            when (phase == point) (ioError (userError (show point)))
      haskokiStdOpenSessionWithNotifyWith observe ptr 0 0 1 cookie notifyCallback out >>= assertEqual "injected open fault fenced" 5
      readIORef reached >>= assertBool "fault point reached" . elem point
      peek out >>= assertEqual "rollback preserves handle sentinel" 0xa5a5a5a5a5a5a5a5
      assertNotifyEmpty inst
      -- The rolled-back session never retains explicit async admission.
      isAsyncSession (siAsyncTable inst) (SessionId 1) >>= assertEqual "rollback disables async session" False
      h <- openNotify ptr 0 cookie notifyCallback
      haskokiStdCloseSession ptr h >>= assertEqual "retry works" 0
      assertNotifyEmpty inst
  putStrLn "T-N06 association: shapes=4 distinct_pairs=2 rollback_points=6 leaked_pairs=0 leaked_views=0"

caseNativeNotifyRetirement :: Assertion
caseNativeNotifyRetirement = runInBoundThread $ allocaBytes 1 $ \cookie -> do
  notifyReset 0
  withNotifyInstance notifyInvoke $ \ptr inst -> do
    a <- openNotify ptr 0 cookie notifyCallback
    b <- openNotify ptr 0 cookie notifyCallback
    c <- openNotify ptr 1 cookie notifyCallback
    haskokiStdCloseSession ptr a >>= assertEqual "close-one" 0
    readIORef (siNotify inst) >>= assertEqual "one retired" [sidOf b,sidOf c] . Map.keys
    haskokiStdCloseAllSessions ptr 0 >>= assertEqual "close-all" 0
    readIORef (siNotify inst) >>= assertEqual "other slot retained" [sidOf c] . Map.keys
    setStdTokenPresence inst (SlotId 1) False >>= assertEqual "removal" (Right (PresenceChanged 1,0))
    assertNotifyEmpty inst
  -- A cursor cleanup failure after a committed close must still retire its
  -- callback and free its view, and close-all must continue to later sessions.
  forM_ [False,True] $ \closeAll -> withNotifyInstance notifyInvoke $ \ptr inst -> do
    a <- openNotify ptr 0 cookie notifyCallback
    b <- openNotify ptr 0 cookie notifyCallback
    badCursors <- newIORef (error "injected cursor cleanup failure")
    bracket (newStablePtr inst { siFind = badCursors }) freeStablePtr $ \faultPtr -> do
      (if closeAll then haskokiStdCloseAllSessions faultPtr 0 else haskokiStdCloseSession faultPtr a)
        >>= assertEqual "postcommit cleanup fault fenced" 5
      pairs <- readIORef (siNotify inst)
      assertEqual "failed close retires each committed association" (if closeAll then [] else [sidOf b]) (Map.keys pairs)
      views <- readIORef (siAsyncViews inst)
      assertEqual "failed close frees each committed borrowed view" (Map.keys pairs) (Map.keys views)
      when (not closeAll) (haskokiStdCloseSession ptr b >>= assertEqual "other session remains usable" 0)
      assertNotifyEmpty inst
  -- A failed owner-unbind must not strand registry/view cleanup at Finalize.
  forM_ [False,True] $ \failUnbind -> do
    retained <- newIORef Nothing
    hub <- newSlotEvents 2 [SlotDefinition (SlotId 0) True, SlotDefinition (SlotId 1) True] >>= mustRight
    let acquisition = stdAcquisition { saUnbindPresenceOwner = when failUnbind (ioError (userError "unbind fault")) }
    bracket (openStdInstanceWithNotify acquisition (cfgTwo True) hub notifyInvoke) haskokiStdClose $ \ptr -> do
      inst <- deRefStablePtr ptr
      writeIORef retained (Just inst)
      _ <- openNotify ptr 0 cookie notifyCallback
      _ <- openNotify ptr 1 cookie notifyCallback
      pure ()
    Just inst <- readIORef retained
    readIORef (siNotify inst) >>= assertBool "finalize (also failed cleanup) retires pairs" . Map.null
    readIORef (siAsyncViews inst) >>= assertBool "finalize (also failed cleanup) frees views" . Map.null
    surrenderDigest inst (SessionId 1) >>= assertEqual "retired callback cannot run" NotifyContinue
  -- Extend the real T-N03 postcommit release failure, using actual native resources.
  withRemovalFixture "notify-release" (const (pure ())) 0 True $ \f -> do
    let inst = rfStd f
    forM_ (rfSessions f) $ \handle -> registerSessionNotify inst (sidOf handle) (SessionNotify notifyCallback cookie)
    attempted <- newIORef (0 :: Int)
    outcome <- try (setStdTokenPresenceWith (\release -> do
      modifyIORef' attempted (+1)
      drainReleases (siBackend inst) [release]
      ioError (userError "release fault")) inst (SlotId 0) False)
      :: IO (Either SomeException (Either PresenceError (PresenceChange,Int)))
    assertBool "release failure observed" (case outcome of Left _ -> True; _ -> False)
    readIORef attempted >>= assertEqual "every release drained despite faults" 5
    assertRetired f
  notifyRead 0 >>= assertEqual "all retirement paths are silent" 0
  putStrLn "T-N06 retirement: close_one=pass close_all=pass removal=pass failed_cleanup=pass finalize=pass callbacks=0"

caseNativeNotifyGuard :: Assertion
caseNativeNotifyGuard = runInBoundThread $ allocaBytes 1 $ \cookie -> do
  forM_ [(0,NotifyContinue),(1,NotifyCancel),(7,NotifyFailed),(0xdead,NotifyFailed)] $ \(rv,want) -> do
    notifyReset rv
    dispatchSessionNotifyWith notifyInvoke (SessionId 71) (SessionNotify notifyCallback cookie) >>= assertEqual "typed callback result" want
    notifyRead 0 >>= assertEqual "exactly one callback" 1
    notifyRead 1 >>= assertEqual "session preserved" 71
    notifyRead 2 >>= assertEqual "event preserved" 0
    notifyCookie >>= assertEqual "cookie preserved" cookie
    forM_ [3,4,5] $ \field -> notifyRead field >>= assertEqual "caller thread, active TLS, restored TLS" 1
    notifyRead 6 >>= assertEqual "normal-return adapter fences its simulated failure" (if rv == 0xdead then 1 else 0)
    inNotify >>= assertEqual "no TLS leak" 0
  let throwing _ _ _ _ = ioError (userError "Haskell invoker failed before entering C")
  notifyReset 0
  withNotifyInstance throwing $ \ptr inst -> do
    handle <- openNotify ptr 0 cookie notifyCallback
    surrenderDigest inst (sidOf handle) >>= assertEqual "injected invoker exception fenced" NotifyFailed
    inNotify >>= assertEqual "throw before C leaves TLS clear" 0
    nullHandle <- openNotify ptr 0 cookie nullFunPtr
    surrenderDigest inst (sidOf nullHandle) >>= assertEqual "null callback bypasses throwing invoker" NotifyContinue
    notifyRead 0 >>= assertEqual "typed failure crosses no foreign callback wrapper" 0
  -- An unbound Haskell caller must also be bound for the invoker action.
  done <- newEmptyMVar
  _ <- forkFinally (dispatchSessionNotifyWith (\_ _ _ _ -> do
    bound <- isCurrentThreadBound
    assertBool "dispatcher binds an unbound caller" bound
    pure 0) (SessionId 1) (SessionNotify notifyCallback cookie)) (putMVar done)
  takeMVar done >>= either (assertFailure . show) (assertEqual "bound dispatcher" NotifyContinue)
  putStrLn "T-N06 dispatcher: decisions=4 typed_exception=pass same_thread=pass tls_restored=pass null_silent=pass"
