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

Standalone async probes ('AsyncAcquisition' and the async @*With@
helpers) throw a synchronous primary at one step and assert that the
cleanup closed everything the open held: the backend once, the
context pointer freed unregistered, the box's Store closed and
reopenable. A failed cleanup close is retried once and never replaces
the primary; two failed closes hand the Store back to the caller, or
queue it on the record's residue owner when no caller can receive it,
and the next standalone open or close retries it. Every record here
carries a private residue owner, so parallel cases never share one.

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
  ( AsyncException (ThreadKilled)
  , IOException
  , SomeException
  , bracket
  , catch
  , finally
  , fromException
  , throwIO
  , try
  )
import Control.Monad (replicateM_)
import Data.IORef (atomicModifyIORef', modifyIORef', newIORef, readIORef, writeIORef)
import EnvLock (withEnvLock)
import Foreign.C.String (peekCString, withCString)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, nullPtr)
import Foreign.StablePtr (StablePtr, castPtrToStablePtr, castStablePtrToPtr)
import Foreign.Storable (peek, poke)
import GHC.Clock (getMonotonicTimeNSec)
import System.Directory
  ( createDirectory
  , getTemporaryDirectory
  , removeDirectoryRecursive
  , removeFile
  )
import System.Environment (lookupEnv, setEnv, unsetEnv)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CryptoBackend (..)
  , EngineResult (..)
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.FFI.Async
  ( AcquireFailure (..)
  , AcquireStep (..)
  , AsyncAcquisition (..)
  , StoreBox
  , asyncAcquisition
  , closeCtxSlotWith
  , closeStoreBoxSlotWith
  , haskokiAsyncStoreOpenWith
  , newResidueOwner
  , openAsyncCtxOnWith
  , openAsyncCtxWith
  , openStoreBoxWith
  , residueCount
  )
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
import Haskoki.Runtime.Storage
  ( FaultInjector
  , FaultPoint (..)
  , Store (..)
  , StoreError
  , TokenRecord (..)
  , defaultLimits
  , noFaults
  , scriptedFaults
  )
import Haskoki.Runtime.Storage.Memory (MemoryWorld, newMemoryWorld, openMemoryStoreWith)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore, openSQLiteStoreWith)
import Haskoki.Session (AdmitDeny (..), tokenAuthNew)
import Haskoki.Types
  ( Generation (..)
  , Outcome (..)
  , ReturnCode (..)
  , SlotId (..)
  , TokenId (..)
  )

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
  , testCase "real openBackend kill-loop unwinds without wedge" caseRealOpenKillLoop
  , testCase "async init failure acquires nothing" caseAsyncInitFail
  , testCase "async backend failure allocates no context" caseAsyncBackendFail
  , testCase "async throw after backend open closes the backend once" caseAsyncThrowAfterBackend
  , testCase "async throw after pointer allocation frees it unregistered" caseAsyncThrowAfterCtxAlloc
  , testCase "async registration failure frees the pointer and closes the backend" caseAsyncRegisterFail
  , testCase "store-bound throw after backend open closes the backend" caseStoreBoundThrowAfterBackend
  , testCase "store box seat refusal closes the store" caseBoxSeatRefusal
  , testCase "store box refusal with a failing close hands back the store" caseBoxRefusalCloseFails
  , testCase "store box throw after token setup closes the store" caseBoxThrowAfterTokenSetup
  , testCase "store box cleanup failure retries once and keeps the primary" caseBoxCleanupRetry
  , testCase "store box double cleanup failure hands back the store" caseBoxDoubleCleanupFailure
  , testCase "killed open with a double cleanup failure queues the residue for the next close" caseResidueQueuedForClose
  , testCase "next open retries the queued residue and frees the lock" caseResidueRetriedByNextOpen
  , testCase "async success counts balance" caseAsyncSuccessBalance
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
  bracket haskokiInstanceOpen haskokiInstanceClose $ \cell -> do
    assertBool "authoritative config refuses dishonest cell" (isNull cell)
    sp <- haskokiStdOpen cell
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

-- | Adoption pin (no hooks): a victim looping the REAL
-- 'openBackend' dies 'ThreadKilled' when killed — the masked
-- adoption bracketing unwinds the raw env instead of wedging —
-- and a fresh open/close works after. The rendezvous sits inside
-- the tried region, so the kill always lands in 'try' (no silent
-- death, no wedge). Successful opens in the loop are deliberately
-- not closed (GC owns them; closing in the loop would race
-- close-gating work instead of pinning adoption). Leak-freedom under
-- faults is proven with per-test gates in OwnershipSpec: this
-- suite's KAT traffic shares the process, so no hook state is
-- armed here.
caseRealOpenKillLoop :: IO ()
caseRealOpenKillLoop = withTimeout "real-open-kill" $ do
  replicateM_ 3 trial
  r <- openBackend "provider=default"
    :: IO (EngineResult (BackendEnv OpenSSL4))
  case r of
    EngineFail err -> assertFailure ("post-test open failed: " ++ show err)
    EngineOk env -> closeBackend env
  where
    trial = do
      entered <- newEmptyMVar
      done <- newEmptyMVar
      tid <- forkIO (try (putMVar entered () >> loop) >>= putMVar done)
      takeMVar entered
      killThread tid
      r <- takeMVar done :: IO (Either SomeException ())
      case r of
        Left e -> case fromException e of
          Just ThreadKilled -> pure ()
          _ -> assertFailure ("expected ThreadKilled, got " ++ show e)
        Right () -> assertFailure "kill-loop victim must die, loop returned"
    loop = do
      _ <- openBackend "provider=default"
        :: IO (EngineResult (BackendEnv OpenSSL4))
      loop

-- ---------------------------------------------------------------------------
-- Standalone async acquisition (synchronous step failures)
-- ---------------------------------------------------------------------------

-- | Balance counters over one acquisition record (opens, closes,
-- pointer allocs and frees, registrations and retirements). Closes,
-- frees and retirements count only once they return.
--
-- Keep in sync with the copy in tests/model/FfiAsyncSpec.hs: suites
-- share only tests/support, so the helper is duplicated.
data AcqCounts = AcqCounts
  { acStoreOpens :: !Int
  , acStoreCloses :: !Int
  , acBackendOpens :: !Int
  , acBackendCloses :: !Int
  , acCtxAllocs :: !Int
  , acCtxFrees :: !Int
  , acBoxAllocs :: !Int
  , acBoxFrees :: !Int
  , acRegistrations :: !Int
  , acRetirements :: !Int
  }
  deriving (Show)

zeroCounts :: AcqCounts
zeroCounts = AcqCounts 0 0 0 0 0 0 0 0 0 0

-- | Counting wrapper over the given steps, with a private residue
-- owner (parallel cases never share one). Keep in sync with the copy
-- in tests/model/FfiAsyncSpec.hs.
countingAcquisitionOver
  :: AsyncAcquisition -> IO (AsyncAcquisition, IO AcqCounts)
countingAcquisitionOver base = do
  ref <- newIORef zeroCounts
  owner <- newResidueOwner
  let bump f = atomicModifyIORef' ref (\c -> (f c, ()))
      acq = base
        { aaOpenStore = \p -> do
            r <- aaOpenStore base p
            case r of
              Right _ -> bump (\c -> c { acStoreOpens = acStoreOpens c + 1 })
              Left _ -> pure ()
            pure r
        , aaCloseStore = \st -> do
            aaCloseStore base st
            bump (\c -> c { acStoreCloses = acStoreCloses c + 1 })
        , aaOpenBackend = do
            r <- aaOpenBackend base
            case r of
              EngineOk _ -> bump (\c -> c { acBackendOpens = acBackendOpens c + 1 })
              EngineFail _ -> pure ()
            pure r
        , aaCloseBackend = \be -> do
            aaCloseBackend base be
            bump (\c -> c { acBackendCloses = acBackendCloses c + 1 })
        , aaNewCtxPtr = \ctx -> do
            sp <- aaNewCtxPtr base ctx
            bump (\c -> c { acCtxAllocs = acCtxAllocs c + 1 })
            pure sp
        , aaFreeCtxPtr = \sp -> do
            aaFreeCtxPtr base sp
            bump (\c -> c { acCtxFrees = acCtxFrees c + 1 })
        , aaRegisterCtx = \sp table -> do
            aaRegisterCtx base sp table
            bump (\c -> c { acRegistrations = acRegistrations c + 1 })
        , aaRetireCtx = \sp -> do
            aaRetireCtx base sp
            bump (\c -> c { acRetirements = acRetirements c + 1 })
        , aaNewBoxPtr = \b -> do
            sp <- aaNewBoxPtr base b
            bump (\c -> c { acBoxAllocs = acBoxAllocs c + 1 })
            pure sp
        , aaFreeBoxPtr = \sp -> do
            aaFreeBoxPtr base sp
            bump (\c -> c { acBoxFrees = acBoxFrees c + 1 })
        , aaResidue = owner
        }
  pure (acq, readIORef ref)

-- | The synchronous primary every probe injects.
primaryError :: IOException
primaryError = userError "primary"

isPrimary :: SomeException -> Bool
isPrimary e = fromException e == Just primaryError

-- | Throw the primary at one step; every other step runs as before.
throwAt :: AcquireStep -> AsyncAcquisition -> AsyncAcquisition
throwAt step acq = acq
  { aaStep = \s -> if s == step then throwIO primaryError else aaStep acq s }

-- | A readable rendering of a typed open failure.
describeFailure :: Either AcquireFailure a -> String
describeFailure (Right _) = "Right"
describeFailure (Left AcquireRefused) = "Left AcquireRefused"
describeFailure (Left (AcquireThrew e)) = "Left (AcquireThrew " ++ show e ++ ")"
describeFailure (Left (AcquireResidue p c _)) =
  "Left (AcquireResidue " ++ show p ++ " " ++ show c ++ " <store>)"

-- | Assert the open failed with exactly the injected primary.
assertThrewPrimary :: String -> Either AcquireFailure a -> IO ()
assertThrewPrimary what r = case r of
  Left (AcquireThrew e) | isPrimary e -> pure ()
  _ -> assertFailure (what ++ ": expected AcquireThrew primary, got " ++ describeFailure r)

-- | Open the box's Store over a test-held memory world through the
-- given injector (shared across opens, so a script fires once).
memoryStoreThrough :: MemoryWorld -> FaultInjector -> AsyncAcquisition -> AsyncAcquisition
memoryStoreThrough world inj acq = acq
  { aaOpenStore = \_ ->
      either (const (Left ())) Right <$> openMemoryStoreWith world defaultLimits inj }

-- | Report a token that is not the async home token from the opened
-- Store's token load, so seating refuses.
foreignHomeToken :: AsyncAcquisition -> AsyncAcquisition
foreignHomeToken acq = acq
  { aaOpenStore = \p -> do
      r <- aaOpenStore acq p
      pure $ case r of
        Right st -> Right st { storeLoadTokens = pure (Right [(foreignToken, [])]) }
        Left e -> Left e
  }
  where
    foreignToken = TokenRecord
      { trId = TokenId 7
      , trSlot = SlotId 0
      , trGeneration = Generation 0
      , trLabel = "foreign"
      , trAuth = tokenAuthNew
      }

-- | Count every Store close attempt, including the ones that throw.
countCloseAttempts :: AsyncAcquisition -> IO (AsyncAcquisition, IO Int)
countCloseAttempts base = do
  ref <- newIORef (0 :: Int)
  let acq = base
        { aaCloseStore = \st -> do
            atomicModifyIORef' ref (\n -> (n + 1, ()))
            aaCloseStore base st
        }
  pure (acq, readIORef ref)

-- | Whether a memory world reopens (closing the probe handle).
memoryReopens :: MemoryWorld -> IO (Either String ())
memoryReopens world = do
  r <- openMemoryStoreWith world defaultLimits noFaults
  case r of
    Right st -> storeClose st >> pure (Right ())
    Left e -> pure (Left (show e))

assertReopens :: String -> MemoryWorld -> IO ()
assertReopens what world = do
  r <- memoryReopens world
  case r of
    Right () -> pure ()
    Left e -> assertFailure (what ++ ": memory world reopen refused: " ++ e)

-- | Close a context or box through a fresh slot.
closeViaSlot
  :: AsyncAcquisition -> StablePtr a
  -> (AsyncAcquisition -> Ptr (StablePtr a) -> IO ()) -> IO ()
closeViaSlot acq sp close = alloca $ \pSlot -> do
  poke pSlot sp
  close acq pSlot
  after <- peek pSlot
  assertBool "slot nulled" (isNull after)

-- | A fresh private directory under the temp root, removed on exit.
withPrivateDir :: (FilePath -> IO a) -> IO a
withPrivateDir = bracket create (\d -> removeDirectoryRecursive d `catch` ignoreIO)
  where
    ignoreIO :: IOException -> IO ()
    ignoreIO _ = pure ()
    create = do
      base <- getTemporaryDirectory
      let go :: Int -> IO FilePath
          go n = do
            t <- getMonotonicTimeNSec
            let d = base ++ "/haskoki-acquire-" ++ show t ++ "-" ++ show n
            r <- try (createDirectory d)
            case r of
              Right () -> pure d
              Left (e :: IOException)
                | n < 100 -> go (n + 1)
                | otherwise -> ioError e
      go 0

caseAsyncInitFail :: IO ()
caseAsyncInitFail = do
  (acq, readCounts) <- countingAcquisitionOver
    asyncAcquisition { aaInit = \_ -> throwIO primaryError }
  r <- openAsyncCtxWith acq defaultConfig
  assertThrewPrimary "init failure" r
  c <- readCounts
  assertEqual ("no backend open (" ++ show c ++ ")") 0 (acBackendOpens c)
  assertEqual ("no pointer alloc (" ++ show c ++ ")") 0 (acCtxAllocs c)

caseAsyncBackendFail :: IO ()
caseAsyncBackendFail = do
  (acq, readCounts) <- countingAcquisitionOver
    asyncAcquisition { aaOpenBackend = pure injectedBackend }
  r <- openAsyncCtxWith acq defaultConfig
  case r of
    Left AcquireRefused -> pure ()
    _ -> assertFailure ("expected AcquireRefused, got " ++ describeFailure r)
  c <- readCounts
  assertEqual ("no pointer alloc (" ++ show c ++ ")") 0 (acCtxAllocs c)
  assertEqual ("no registration (" ++ show c ++ ")") 0 (acRegistrations c)

caseAsyncThrowAfterBackend :: IO ()
caseAsyncThrowAfterBackend = do
  (acq, readCounts) <- countingAcquisitionOver asyncAcquisition
  r <- openAsyncCtxWith (throwAt AfterBackendOpen acq) defaultConfig
  c <- readCounts
  assertThrewPrimary ("throw after backend open (" ++ show c ++ ")") r
  assertEqual ("backend opened once (" ++ show c ++ ")") 1 (acBackendOpens c)
  assertEqual ("backend closed once (" ++ show c ++ ")") 1 (acBackendCloses c)

caseAsyncThrowAfterCtxAlloc :: IO ()
caseAsyncThrowAfterCtxAlloc = do
  (acq, readCounts) <- countingAcquisitionOver asyncAcquisition
  r <- openAsyncCtxWith (throwAt AfterCtxAlloc acq) defaultConfig
  c <- readCounts
  assertThrewPrimary ("throw after pointer allocation (" ++ show c ++ ")") r
  assertEqual ("pointer freed (" ++ show c ++ ")") 1 (acCtxFrees c)
  assertEqual ("never registered (" ++ show c ++ ")") 0 (acRegistrations c)
  assertEqual ("backend closed once (" ++ show c ++ ")") 1 (acBackendCloses c)

caseAsyncRegisterFail :: IO ()
caseAsyncRegisterFail = do
  (acq, readCounts) <- countingAcquisitionOver
    asyncAcquisition { aaRegisterCtx = \_ _ -> throwIO primaryError }
  r <- openAsyncCtxWith acq defaultConfig
  c <- readCounts
  assertThrewPrimary ("registration failure (" ++ show c ++ ")") r
  assertEqual ("pointer allocated (" ++ show c ++ ")") 1 (acCtxAllocs c)
  assertEqual ("pointer freed (" ++ show c ++ ")") 1 (acCtxFrees c)
  assertEqual ("backend closed once (" ++ show c ++ ")") 1 (acBackendCloses c)

caseStoreBoundThrowAfterBackend :: IO ()
caseStoreBoundThrowAfterBackend = do
  world <- newMemoryWorld
  (acq, readCounts) <- countingAcquisitionOver
    (memoryStoreThrough world noFaults asyncAcquisition)
  eBox <- openStoreBoxWith acq nullPtr
  box <- case eBox of
    Right b -> pure b
    Left _ -> assertFailure ("store box open: " ++ describeFailure eBox)
  (do r <- openAsyncCtxOnWith (throwAt AfterBackendOpen acq) defaultConfig box
      c <- readCounts
      assertThrewPrimary ("store-bound throw after backend open (" ++ show c ++ ")") r
      assertEqual ("backend closed once (" ++ show c ++ ")") 1 (acBackendCloses c)
      eCtx <- openAsyncCtxOnWith acq defaultConfig box
      case eCtx of
        Right sp -> closeViaSlot acq sp closeCtxSlotWith
        Left _ -> assertFailure ("reopen on the box: " ++ describeFailure eCtx))
    `finally` closeBoxQuietly acq box
  c <- readCounts
  assertEqual ("backend opens = closes (" ++ show c ++ ")") (acBackendOpens c) (acBackendCloses c)
  assertEqual ("store opens = closes (" ++ show c ++ ")") (acStoreOpens c) (acStoreCloses c)
  assertReopens "after the box closed" world

-- | Close a box slot, ignoring a close error (cleanup after asserts).
closeBoxQuietly :: AsyncAcquisition -> StablePtr StoreBox -> IO ()
closeBoxQuietly acq box = alloca $ \pSlot -> do
  poke pSlot box
  _ <- try (closeStoreBoxSlotWith acq pSlot) :: IO (Either SomeException ())
  pure ()

caseBoxSeatRefusal :: IO ()
caseBoxSeatRefusal = do
  world <- newMemoryWorld
  (acq, readCounts) <- countingAcquisitionOver
    (foreignHomeToken (memoryStoreThrough world noFaults asyncAcquisition))
  r <- openStoreBoxWith acq nullPtr
  c <- readCounts
  case r of
    Left AcquireRefused -> pure ()
    _ -> assertFailure ("expected AcquireRefused, got " ++ describeFailure r)
  assertEqual ("store closed once (" ++ show c ++ ")") 1 (acStoreCloses c)
  assertReopens "after the refusal" world

caseBoxRefusalCloseFails :: IO ()
caseBoxRefusalCloseFails = do
  world <- newMemoryWorld
  inj <- scriptedFaults [FaultClose, FaultClose]
  (acq, _) <- countingAcquisitionOver
    (foreignHomeToken (memoryStoreThrough world inj asyncAcquisition))
  r <- openStoreBoxWith acq nullPtr
  case r of
    Left (AcquireResidue Nothing cerr st) -> do
      assertBool ("cleanup error is the close failure: " ++ show cerr)
        (isStoreError cerr)
      storeClose st
      assertReopens "after the caller closed the handed-back store" world
    _ -> assertFailure ("expected AcquireResidue Nothing, got " ++ describeFailure r)
  n <- residueCount (aaResidue acq)
  assertEqual "nothing queued on the owner" 0 n

isStoreError :: SomeException -> Bool
isStoreError e = case (fromException e :: Maybe StoreError) of
  Just _ -> True
  Nothing -> False

caseBoxThrowAfterTokenSetup :: IO ()
caseBoxThrowAfterTokenSetup = do
  world <- newMemoryWorld
  (acq, readCounts) <- countingAcquisitionOver
    (memoryStoreThrough world noFaults asyncAcquisition)
  r <- openStoreBoxWith (throwAt AfterTokenSetup acq) nullPtr
  c <- readCounts
  assertThrewPrimary ("throw after token setup (" ++ show c ++ ")") r
  assertEqual ("store closed once (" ++ show c ++ ")") 1 (acStoreCloses c)
  assertEqual ("no box pointer (" ++ show c ++ ")") 0 (acBoxAllocs c)
  assertReopens "after the throw" world

caseBoxCleanupRetry :: IO ()
caseBoxCleanupRetry = do
  world <- newMemoryWorld
  inj <- scriptedFaults [FaultClose]
  (counting, _) <- countingAcquisitionOver
    (memoryStoreThrough world inj asyncAcquisition)
  (acq, readAttempts) <- countCloseAttempts counting
  r <- openStoreBoxWith (throwAt AfterTokenSetup acq) nullPtr
  attempts <- readAttempts
  assertThrewPrimary ("cleanup retry (attempts=" ++ show attempts ++ ")") r
  assertEqual "close attempts" 2 attempts
  assertReopens "after the retried close" world

caseBoxDoubleCleanupFailure :: IO ()
caseBoxDoubleCleanupFailure = do
  world <- newMemoryWorld
  inj <- scriptedFaults [FaultClose, FaultClose]
  (counting, _) <- countingAcquisitionOver
    (memoryStoreThrough world inj asyncAcquisition)
  (acq, readAttempts) <- countCloseAttempts counting
  r <- openStoreBoxWith (throwAt AfterTokenSetup acq) nullPtr
  attempts <- readAttempts
  case r of
    Left (AcquireResidue (Just p) cerr st) -> do
      assertBool ("primary kept: " ++ show p) (isPrimary p)
      assertBool ("cleanup error is the close failure: " ++ show cerr)
        (isStoreError cerr)
      assertEqual "close attempts" 2 attempts
      storeClose st
      assertReopens "after the caller closed the handed-back store" world
    _ -> assertFailure ("expected AcquireResidue (Just primary), got "
                        ++ describeFailure r ++ " after " ++ show attempts ++ " close attempts")
  n <- residueCount (aaResidue acq)
  assertEqual "nothing queued on the owner" 0 n

-- | An asynchronous primary (thrown at a step) whose two cleanup
-- closes fail: the open rethrows the primary unchanged, the Store
-- queues on the record's residue owner and keeps its lock, and the
-- next close through the record retries it and frees the lock.
caseResidueQueuedForClose :: IO ()
caseResidueQueuedForClose = do
  world <- newMemoryWorld
  inj <- scriptedFaults [FaultClose, FaultClose]
  (counting, _) <- countingAcquisitionOver
    (memoryStoreThrough world inj asyncAcquisition)
  let acq = counting
        { aaStep = \s -> if s == AfterTokenSetup then throwIO ThreadKilled else pure () }
  r <- try (openStoreBoxWith acq nullPtr)
  case r of
    Left e | fromException e == Just ThreadKilled -> pure ()
    Left e -> assertFailure ("expected the primary ThreadKilled, got " ++ show e)
    Right res -> assertFailure ("expected the primary to propagate, got " ++ describeFailure res)
  queued <- residueCount (aaResidue acq)
  assertEqual "residue queued" 1 queued
  held <- memoryReopens world
  assertBool "the residue keeps its lock" (either (const True) (const False) held)
  alloca $ \pSlot -> do
    poke pSlot (castPtrToStablePtr nullPtr :: StablePtr StoreBox)
    closeStoreBoxSlotWith acq pSlot
  left <- residueCount (aaResidue acq)
  assertEqual "residue closed by the next close" 0 left
  assertReopens "after the residue closed" world

-- | The export body cannot hand a residue back: a synchronous primary
-- whose two cleanup closes fail reports NULL and queues the Store on
-- the record's owner, holding its SQLite lock. The next open through
-- the record retries the close first, then opens the same path.
caseResidueRetriedByNextOpen :: IO ()
caseResidueRetriedByNextOpen = withPrivateDir $ \dir -> do
  let path = dir ++ "/store.sqlite"
  inj <- scriptedFaults [FaultClose, FaultClose]
  armed <- newIORef True
  (counting, _) <- countingAcquisitionOver asyncAcquisition
    { aaOpenStore = \cp -> do
        p <- peekCString cp
        either (const (Left ())) Right <$> openSQLiteStoreWith p defaultLimits inj
    }
  let acq = counting
        { aaStep = \s -> do
            on <- readIORef armed
            if on && s == AfterTokenSetup then throwIO primaryError else pure ()
        }
  sp <- withCString path (haskokiAsyncStoreOpenWith acq)
  assertBool "export body reports NULL" (isNull sp)
  queued <- residueCount (aaResidue acq)
  assertEqual "residue queued" 1 queued
  held <- sqliteReopens path
  assertBool ("the residue keeps its lock: " ++ show held) (isLeft held)
  writeIORef armed False
  eBox <- withCString path (openStoreBoxWith acq)
  left <- residueCount (aaResidue acq)
  case eBox of
    Right box -> closeViaSlot acq box closeStoreBoxSlotWith
    Left _ -> assertFailure ("next open on the same path: " ++ describeFailure eBox
                             ++ " (residue left " ++ show left ++ ")")
  assertEqual "residue closed by the next open" 0 left
  freed <- sqliteReopens path
  assertBool ("lock free after the box closed: " ++ show freed) (not (isLeft freed))
  where
    isLeft :: Either a b -> Bool
    isLeft = either (const True) (const False)

-- | Whether a SQLite path reopens (closing the probe handle).
sqliteReopens :: FilePath -> IO (Either String ())
sqliteReopens path = do
  r <- openSQLiteStore path
  case r of
    Right st -> storeClose st >> pure (Right ())
    Left e -> pure (Left (show e))

caseAsyncSuccessBalance :: IO ()
caseAsyncSuccessBalance = do
  (acq, readCounts) <- countingAcquisitionOver asyncAcquisition
  eBox <- openStoreBoxWith acq nullPtr
  box <- case eBox of
    Right b -> pure b
    Left _ -> assertFailure ("store box open: " ++ describeFailure eBox)
  eBare <- openAsyncCtxWith acq defaultConfig
  case eBare of
    Right sp -> closeViaSlot acq sp closeCtxSlotWith
    Left _ -> assertFailure ("bare open: " ++ describeFailure eBare)
  eOn <- openAsyncCtxOnWith acq defaultConfig box
  case eOn of
    Right sp -> closeViaSlot acq sp closeCtxSlotWith
    Left _ -> assertFailure ("store-bound open: " ++ describeFailure eOn)
  closeViaSlot acq box closeStoreBoxSlotWith
  c <- readCounts
  let what = " (" ++ show c ++ ")"
  assertEqual ("store opens = closes" ++ what) (acStoreOpens c) (acStoreCloses c)
  assertEqual ("backend opens = closes" ++ what) (acBackendOpens c) (acBackendCloses c)
  assertEqual ("context allocs = frees" ++ what) (acCtxAllocs c) (acCtxFrees c)
  assertEqual ("box allocs = frees" ++ what) (acBoxAllocs c) (acBoxFrees c)
  assertEqual ("registrations = retirements" ++ what) (acRegistrations c) (acRetirements c)
  assertEqual ("two contexts registered" ++ what) 2 (acRegistrations c)
