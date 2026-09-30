{-# LANGUAGE OverloadedStrings #-}
module NotificationsEngineSpec (spec) where

import Control.Concurrent.MVar (MVar)
import Control.Concurrent.STM (atomically)
import Control.Exception (SomeException, bracket, evaluate, try)
import Control.Monad (forM_, replicateM)
import qualified Data.ByteString.Char8 as BS
import Data.IORef (modifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing)
import EnvLock (withEnvLock)
import Foreign.Ptr (nullPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr, deRefStablePtr)
import System.Directory (createDirectoryIfMissing, doesFileExist, removeFile)
import System.Environment (lookupEnv, setEnv, unsetEnv)
import System.Mem.StableName (makeStableName)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (BackendError (..), EngineResult (..))
import Haskoki.FFI.Instance
import Haskoki.FFI.Standard
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Outcome (EffectRequest (..), Reservation (..))
import Haskoki.Registry (MechanismId (..))
import Haskoki.Runtime.Async
import Haskoki.Runtime.Config
import Haskoki.Runtime.Control
import Haskoki.Runtime.Events (insertToken, tokenPresent)
import Haskoki.Runtime.SlotEvents
import Haskoki.Session (AdmitDeny (..))
import Haskoki.Types (ReturnCode (..), SessionId (..), SlotId (..))

spec :: MVar () -> TestTree
spec envLock = testGroup "Notifications/T-N02"
  [ testCase "caseServingInitialSnapshot" (bounded (caseServingInitialSnapshot envLock))
  , testCase "caseServingAcquisitionUnwind" (bounded caseServingAcquisitionUnwind)
  , testCase "caseServingConfigLimits" (bounded caseServingConfigLimits)
  , testCase "caseServingControlOwnership" (bounded (caseServingControlOwnership envLock))
  ]

bounded :: Assertion -> Assertion
bounded action = timeout 20000000 action >>= maybe (assertFailure "T-N02 exceeded 20s") pure

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
  assertEqual "bound status succeeds" CKR_OK rv
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
      assertEqual (stage ++ " no owner remains") CKR_ARGUMENTS_BAD rv
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
    assertEqual "unpublished Control has no fallback owner" CKR_ARGUMENTS_BAD unbound
    bracket (haskokiStdOpen cell) haskokiStdClose $ \sp -> do
      assertBool "serving open" (not (isNull sp))
      assertEqual "status ignores populated private registry" [row 0 True 0, row 1 True 0] =<< status (instControl ops) []
      assertEqual "status pagination ends at catalog" [] =<< status (instControl ops) [("offset", JNum 2)]
      forM_ ["token.insert", "token.remove"] $ \cmd -> forM_ [0, 99] $ \slot -> do
        (rv, _, _) <- dispatchControl (instControl ops) (request cmd [("slot", JNum slot)]) (Just responseBudget)
        assertEqual "serving mutation refuses until T-N03" CKR_ARGUMENTS_BAD rv
      assertEqual "refusal does not advance generation" 0 =<< controlGeneration (instControl ops)
      assertEqual "refusal does not alter presence" (initial True) =<< snapshotSlots (instSlots ops)
      assertEqual "refusal produces no serving flag" SlotNoEvent =<< waitSlot (instSlots ops) DontBlock
      assertEqual "private registry untouched" True =<< tokenPresent (instRegistry ops) (SlotId 99)
    (closed, _, _) <- dispatchControl (instControl ops) (request "status" []) (Just responseBudget)
    assertEqual "Standard close clears borrowed owner" CKR_ARGUMENTS_BAD closed
