{-# LANGUAGE OverloadedStrings #-}
module NotificationsEngineSpec (spec) where

import Control.Concurrent.MVar (MVar)
import Control.Concurrent.STM (atomically)
import Control.Exception (SomeException, bracket, evaluate, try)
import Control.Monad (forM_, replicateM, when)
import qualified Data.ByteString as Bytes
import qualified Data.ByteString.Char8 as BS
import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing)
import EnvLock (withEnvLock)
import Data.Word (Word64, Word8)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Array (peekArray, pokeArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr, deRefStablePtr)
import Foreign.Storable (peek, poke)
import System.Directory (createDirectoryIfMissing, doesFileExist, removeFile)
import System.Environment (lookupEnv, setEnv, unsetEnv)
import System.Mem.StableName (makeStableName)
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
    before <- snapshotPresence (siEnv inst) (siSlots inst)
    assertControlFault envLock inst (setStdTokenPresence inst)
    snapshotPresence (siEnv inst) (siSlots inst) >>= assertEqual "precommit keeps model and presence" before
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
