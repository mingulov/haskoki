{- | Hook-injected acquisition leak probes, structural half.

Bracket-structured acquisition ('StdAcquisition' \/
'CryptoAcquisition' and the @*With@ opens) with injected
failure at every step.

Each probe fails exactly one acquisition step and asserts that
EVERYTHING acquired-so-far is released (counting wrappers over
the production defaults) and that the open reports NULL:

* failing initialize: no store\/backend acquisition attempted;
* failing store open: no backend acquisition attempted;
* failing backend: the acquired store is closed;
* failing seat (crypto open): no backend acquisition attempted.

Success probes pin the balanced-counts shape (opens counted, no
failure-path closes) and close cleanly.

Async-unwind probes (std + crypto) block the victim inside the
backend acquire at a deterministic rendezvous (the injected hook
signals @entered@, then blocks on @proceed@): main fires ONE kill
(the victim is provably blocked inside the open, so the
synchronous throw is always delivered there and always returns),
opens @proceed@, and joins on @res@. Both joins carry a 10s
'System.Timeout' backstop ('assertFailure' on expiry) per the
no-wedge rule. The kill aborts the open and unwinds what was
acquired (std: the store is released; crypto: the backend is
never acquired); a swallowed kill (open completes) FAILS the case.
A kill spray is deliberately NOT used here: prior attempts
wedged with one (first kill lands before the victim installs its
report handler).

The routed-crypto env pins live here (not in the model suite):
the model suite's @ConfigSpec@ mutates @HASKOKI_CONFIG@
process-wide, and each suite is its own process, so cross-suite
races are impossible. Within THIS suite the pins race the
env-reading opens (the "ctx2 opens" flake: tasty runs cases
in parallel threads over process-wide env), so both sides serialize
on the suite-wide @EnvLock.withEnvLock@ — writers via
@withConfigEnv@, readers at each open site.
-}
module FfiAcquireSpec (spec) where

import Control.Concurrent
  ( forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  , threadDelay
  )
import Control.Concurrent.MVar (MVar)
import Control.Exception
  ( IOException
  , SomeException
  , bracket
  , catch
  , try
  )
import Data.IORef (modifyIORef', newIORef, readIORef)
import EnvLock (withEnvLock)
import Foreign.Ptr (nullPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr)
import System.Directory (getTemporaryDirectory, removeFile)
import System.Environment (lookupEnv, setEnv, unsetEnv)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (BackendError (..), EngineResult (..))
import Haskoki.FFI.Exports
  ( CryptoAcquisition (..)
  , cryptoAcquisition
  , haskokiCryptoClose
  , haskokiCryptoOpen
  , openCryptoCtxWith
  )
import Haskoki.FFI.Standard
  ( StdAcquisition (..)
  , StdStoreError (..)
  , haskokiStdClose
  , haskokiStdOpen
  , openStdInstanceWith
  , stdAcquisition
  )
import Haskoki.FFI.Instance (haskokiInstanceClose, haskokiInstanceOpen)
import Haskoki.Runtime.Config
  ( Config (..)
  , StorageCfg (..)
  , StorageKind (..)
  , defaultConfig
  )
import Haskoki.Session (AdmitDeny (..))
import Haskoki.Types (Outcome (..), ReturnCode (..))

spec :: MVar () -> TestTree
spec envLock = testGroup "Acquisition hooks"
  [ testCase "std init failure acquires nothing" caseStdInitFail
  , testCase "std store failure opens no backend" caseStdStoreFail
  , testCase "std backend failure closes the store" caseStdBackendFail
  , testCase "std success counts balance" caseStdSuccess
  , testCase "crypto init failure acquires nothing" caseCryptoInitFail
  , testCase "crypto seat failure opens no backend" caseCryptoSeatFail
  , testCase "crypto backend failure acquires nothing" caseCryptoBackendFail
  , testCase "crypto success counts balance" caseCryptoSuccess
  , testCase "std async unwind releases the store" caseStdAsyncUnwind
  , testCase "crypto async unwind acquires no backend" caseCryptoAsyncUnwind
  , testCase "crypto open succeeds then closes" (caseCryptoEnvSuccess envLock)
  , testCase "crypto open garbage config is NULL" (caseCryptoEnvGarbage envLock)
  , testCase "crypto open vs concurrent garbage env" (caseEnvRaceRegression envLock)
  , testCase "crypto open dishonest config is NULL" (caseCryptoEnvDishonest envLock)
  , testCase "std open dishonest config is NULL" (caseStdEnvDishonest envLock)
  , testCase "Instance open dishonest config is NULL" (caseInstanceEnvDishonest envLock)
  ]

isNull :: StablePtr a -> Bool
isNull sp = castStablePtrToPtr sp == nullPtr

removeIfExists :: FilePath -> IO ()
removeIfExists path = catch (removeFile path) handler
  where
    handler :: IOException -> IO ()
    handler _ = pure ()

sqliteCfg :: FilePath -> Config
sqliteCfg path = defaultConfig
  { cfgStorage = (cfgStorage defaultConfig)
      { scKind = StorageSQLite
      , scPath = Just path
      }
  }

withTimeout :: String -> IO a -> IO a
withTimeout label action = do
  mR <- timeout 10000000 action
  case mR of
    Nothing -> assertFailure ("wedge detected: " ++ label)
    Just r -> pure r

injectedBackend :: EngineResult a
injectedBackend =
  EngineFail (BackendUnsupported "acquire-probe" "injected backend failure")

-- ---------------------------------------------------------------------------
-- Standard-surface acquisition
-- ---------------------------------------------------------------------------

caseStdInitFail :: IO ()
caseStdInitFail = do
  storeCalls <- newIORef (0 :: Int)
  backendCalls <- newIORef (0 :: Int)
  let sa = stdAcquisition
        { saInit = \_ -> pure (OutcomeErr CKR_GENERAL_ERROR)
        , saOpenStore = \e c -> do
            modifyIORef' storeCalls (+ 1)
            saOpenStore stdAcquisition e c
        , saOpenBackend = do
            modifyIORef' backendCalls (+ 1)
            saOpenBackend stdAcquisition
        }
  sp <- openStdInstanceWith sa defaultConfig
  assertBool "init failure is NULL" (isNull sp)
  assertEqual "no store acquisition" 0 =<< readIORef storeCalls
  assertEqual "no backend acquisition" 0 =<< readIORef backendCalls

caseStdStoreFail :: IO ()
caseStdStoreFail = do
  backendCalls <- newIORef (0 :: Int)
  let sa = stdAcquisition
        { saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
        , saOpenBackend = do
            modifyIORef' backendCalls (+ 1)
            saOpenBackend stdAcquisition
        }
  sp <- openStdInstanceWith sa defaultConfig
  assertBool "store failure is NULL" (isNull sp)
  assertEqual "no backend acquisition" 0 =<< readIORef backendCalls

caseStdBackendFail :: IO ()
caseStdBackendFail = do
  let path = "/tmp/haskoki-acquire-std.db"
  bracket (removeIfExists path) (\_ -> removeIfExists path) $ \_ -> do
    storeOpens <- newIORef (0 :: Int)
    storeCloses <- newIORef (0 :: Int)
    let sa = stdAcquisition
          { saOpenStore = \e c -> do
              modifyIORef' storeOpens (+ 1)
              saOpenStore stdAcquisition e c
          , saCloseStore = \m -> do
              modifyIORef' storeCloses (+ 1)
              saCloseStore stdAcquisition m
          , saOpenBackend = pure injectedBackend
          }
    sp <- openStdInstanceWith sa (sqliteCfg path)
    assertBool "backend failure is NULL" (isNull sp)
    assertEqual "store was acquired" 1 =<< readIORef storeOpens
    assertEqual "store was released" 1 =<< readIORef storeCloses

caseStdSuccess :: IO ()
caseStdSuccess = do
  storeOpens <- newIORef (0 :: Int)
  storeCloses <- newIORef (0 :: Int)
  backendOpens <- newIORef (0 :: Int)
  backendCloses <- newIORef (0 :: Int)
  let sa = stdAcquisition
        { saOpenStore = \e c -> do
            modifyIORef' storeOpens (+ 1)
            saOpenStore stdAcquisition e c
        , saCloseStore = \m -> do
            modifyIORef' storeCloses (+ 1)
            saCloseStore stdAcquisition m
        , saOpenBackend = do
            modifyIORef' backendOpens (+ 1)
            saOpenBackend stdAcquisition
        , saCloseBackend = \be -> do
            modifyIORef' backendCloses (+ 1)
            saCloseBackend stdAcquisition be
        }
  sp <- openStdInstanceWith sa defaultConfig
  assertBool "success is non-NULL" (not (isNull sp))
  assertEqual "one store acquisition" 1 =<< readIORef storeOpens
  assertEqual "one backend acquisition" 1 =<< readIORef backendOpens
  assertEqual "no failure-path store close" 0 =<< readIORef storeCloses
  assertEqual "no failure-path backend close" 0 =<< readIORef backendCloses
  haskokiStdClose sp

-- ---------------------------------------------------------------------------
-- Routed-crypto acquisition
-- ---------------------------------------------------------------------------

caseCryptoInitFail :: IO ()
caseCryptoInitFail = do
  seatCalls <- newIORef (0 :: Int)
  backendCalls <- newIORef (0 :: Int)
  let ca = cryptoAcquisition
        { caInit = \_ -> pure (OutcomeErr CKR_GENERAL_ERROR)
        , caSeat = \e s -> do
            modifyIORef' seatCalls (+ 1)
            caSeat cryptoAcquisition e s
        , caOpenBackend = do
            modifyIORef' backendCalls (+ 1)
            caOpenBackend cryptoAcquisition
        }
  sp <- openCryptoCtxWith ca defaultConfig
  assertBool "init failure is NULL" (isNull sp)
  assertEqual "no seating" 0 =<< readIORef seatCalls
  assertEqual "no backend acquisition" 0 =<< readIORef backendCalls

caseCryptoSeatFail :: IO ()
caseCryptoSeatFail = do
  backendCalls <- newIORef (0 :: Int)
  let ca = cryptoAcquisition
        { caSeat = \_ _ -> pure (Left AdmitTokensFull)
        , caOpenBackend = do
            modifyIORef' backendCalls (+ 1)
            caOpenBackend cryptoAcquisition
        }
  sp <- openCryptoCtxWith ca defaultConfig
  assertBool "seat failure is NULL" (isNull sp)
  assertEqual "no backend acquisition" 0 =<< readIORef backendCalls

caseCryptoBackendFail :: IO ()
caseCryptoBackendFail = do
  seatCalls <- newIORef (0 :: Int)
  let ca = cryptoAcquisition
        { caSeat = \e s -> do
            modifyIORef' seatCalls (+ 1)
            caSeat cryptoAcquisition e s
        , caOpenBackend = pure injectedBackend
        }
  sp <- openCryptoCtxWith ca defaultConfig
  assertBool "backend failure is NULL" (isNull sp)
  assertEqual "seat was attempted" 1 =<< readIORef seatCalls

caseCryptoSuccess :: IO ()
caseCryptoSuccess = do
  backendOpens <- newIORef (0 :: Int)
  backendCloses <- newIORef (0 :: Int)
  let ca = cryptoAcquisition
        { caOpenBackend = do
            modifyIORef' backendOpens (+ 1)
            caOpenBackend cryptoAcquisition
        , caCloseBackend = \be -> do
            modifyIORef' backendCloses (+ 1)
            caCloseBackend cryptoAcquisition be
        }
  sp <- openCryptoCtxWith ca defaultConfig
  assertBool "success is non-NULL" (not (isNull sp))
  assertEqual "one backend acquisition" 1 =<< readIORef backendOpens
  assertEqual "no failure-path backend close" 0 =<< readIORef backendCloses
  haskokiCryptoClose sp

-- ---------------------------------------------------------------------------
-- Async unwind (deterministic rendezvous inside the backend acquire)
-- ---------------------------------------------------------------------------

asSync :: IO a -> IO (Either SomeException a)
asSync = try

caseStdAsyncUnwind :: IO ()
caseStdAsyncUnwind = do
  let path = "/tmp/haskoki-acquire-unwind.db"
  bracket (removeIfExists path) (\_ -> removeIfExists path) $ \_ -> do
    entered <- newEmptyMVar
    proceed <- newEmptyMVar
    storeCloses <- newIORef (0 :: Int)
    res <- newEmptyMVar
    let sa = stdAcquisition
          { saOpenBackend = do
              putMVar entered ()
              takeMVar proceed
              saOpenBackend stdAcquisition
          , saCloseStore = \m -> do
              modifyIORef' storeCloses (+ 1)
              saCloseStore stdAcquisition m
          }
    victimTid <- forkIO $ do
      r <- asSync (openStdInstanceWith sa (sqliteCfg path))
      putMVar res r
    -- The victim is blocked inside the backend acquire with the
    -- SQLite store already acquired; the single kill is delivered
    -- there and the already-acquired store must unwind.
    withTimeout "std unwind victim never entered the backend acquire"
      (takeMVar entered)
    killThread victimTid
    putMVar proceed ()
    r <- withTimeout "std unwind open never reported after kill"
      (takeMVar res)
    nCloses <- readIORef storeCloses
    case r of
      Left _ -> assertEqual "store unwound on async" 1 nCloses
      Right _ -> assertFailure "async kill did not propagate (swallowed)"

caseCryptoAsyncUnwind :: IO ()
caseCryptoAsyncUnwind = do
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  backendOpens <- newIORef (0 :: Int)
  res <- newEmptyMVar
  let ca = cryptoAcquisition
        { caOpenBackend = do
            putMVar entered ()
            takeMVar proceed
            modifyIORef' backendOpens (+ 1)
            caOpenBackend cryptoAcquisition
        }
  victimTid <- forkIO $ do
    r <- asSync (openCryptoCtxWith ca defaultConfig)
    putMVar res r
  -- The victim is blocked inside the backend acquire; the single
  -- kill must abort the open before any backend is acquired.
  withTimeout "crypto unwind victim never entered the backend acquire"
    (takeMVar entered)
  killThread victimTid
  putMVar proceed ()
  r <- withTimeout "crypto unwind open never reported after kill"
    (takeMVar res)
  case r of
    Left _ ->
      assertEqual "backend never acquired after unwind" 0
        =<< readIORef backendOpens
    Right _ -> assertFailure "async kill did not propagate (swallowed)"

-- ---------------------------------------------------------------------------
-- Routed-crypto environment opens (pins)
-- ---------------------------------------------------------------------------

withConfigEnv :: MVar () -> Maybe String -> IO a -> IO a
withConfigEnv envLock mVal action =
  withEnvLock envLock $ bracket (lookupEnv "HASKOKI_CONFIG") restore $ \_ -> do
    case mVal of
      Nothing -> unsetEnv "HASKOKI_CONFIG"
      Just v -> setEnv "HASKOKI_CONFIG" v
    action
  where
    restore prev = maybe (unsetEnv "HASKOKI_CONFIG") (setEnv "HASKOKI_CONFIG") prev

caseCryptoEnvSuccess :: MVar () -> IO ()
caseCryptoEnvSuccess envLock = withConfigEnv envLock Nothing $ do
  sp <- haskokiCryptoOpen
  assertBool "crypto open succeeds" (not (isNull sp))
  haskokiCryptoClose sp

caseCryptoEnvGarbage :: MVar () -> IO ()
caseCryptoEnvGarbage envLock =
  withConfigEnv envLock (Just "/nonexistent-garbage.toml") $ do
    sp <- haskokiCryptoOpen
    assertBool "garbage config is NULL" (isNull sp)

-- | A dishonest-but-parseable config (here
-- control.enabled=false) refuses at every
-- native startup path with NULL — the honesty error fails the
-- resolve, and every open maps resolve failure to NULL.
dishonestToml :: String
dishonestToml = unlines
  [ "schema_version = 1"
  , "profile = \"demo-maximal\""
  , "[control]"
  , "enabled = false"
  ]

withDishonestEnv :: MVar () -> String -> (FilePath -> IO a) -> IO a
withDishonestEnv envLock tag action = withTimeout "dishonest open" $ do
  base <- getTemporaryDirectory
  let path = base ++ "/haskoki-dishonest-" ++ tag ++ ".toml"
  bracket (writeFile path dishonestToml >> pure path) removeIfExists $ \p ->
    withConfigEnv envLock (Just p) (action p)

caseCryptoEnvDishonest :: MVar () -> IO ()
caseCryptoEnvDishonest envLock = withDishonestEnv envLock "crypto" $ \_ -> do
  sp <- haskokiCryptoOpen
  assertBool "dishonest config is NULL" (isNull sp)

caseStdEnvDishonest :: MVar () -> IO ()
caseStdEnvDishonest envLock = withDishonestEnv envLock "std" $ \_ -> do
  sp <- haskokiStdOpen
  if isNull sp
    then pure ()
    else haskokiStdClose sp >> assertFailure "dishonest std open must be NULL"

caseInstanceEnvDishonest :: MVar () -> IO ()
caseInstanceEnvDishonest envLock = withDishonestEnv envLock "instance" $ \_ -> do
  sp <- haskokiInstanceOpen
  if isNull sp
    then pure ()
    else haskokiInstanceClose sp >> assertFailure "dishonest instance open must be NULL"

-- | A concurrent garbage-config writer must not
-- break a crypto open. The writer holds garbage a full second
-- after publishing it, so the reader's overlap with the dirty
-- window is deterministic, not a timing prayer; the reader blocks
-- on the env lock and opens only once the writer restores. Pre-fix
-- (unlocked) this fails deterministically through the
-- "ctx2 opens" mechanism.
caseEnvRaceRegression :: MVar () -> IO ()
caseEnvRaceRegression envLock = do
  entered <- newEmptyMVar
  bracket (forkIO (writer entered)) killThread $ \_ -> do
    withTimeout "env-race writer never published garbage"
      (takeMVar entered)
    sp <- withEnvLock envLock haskokiCryptoOpen
    assertBool "crypto open survives concurrent env write" (not (isNull sp))
    haskokiCryptoClose sp
  where
    writer entered =
      withConfigEnv envLock (Just "/nonexistent-garbage.toml") $ do
        putMVar entered ()
        threadDelay 1000000
