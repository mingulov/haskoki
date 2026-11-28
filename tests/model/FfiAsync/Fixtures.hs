{- | FfiAsync Fixtures: shared stores, contexts, gates and await helpers.
-}
{-# LANGUAGE OverloadedStrings #-}
module FfiAsync.Fixtures
  ( isNull
  , badSqliteCfg
  , zeroSlotCfg
  , oversizeCatalogCfg
  , cannedFfiDigest
  , countingRunner
  , mkFfiStore
  , mkFfiStoreWith
  , mkFfiDetached
  , initFfiDigestSession
  , mkFfiGen
  , startFfiDigest
  , loadFfiJobs
  , nullJob
  , awaitBlocked
  , awaitBlockedFor
  , planFfiDigest
  , reuseBorrowed
  , openStdSessionView
  , awaitNoPendingReclaims
  , awaitReclaimBalanced
  , parkAt
  , Opened (..)
  , trackOpened
  , releaseOpened
  , memoryStoreSteps
  , memoryStoreThrough
  , gatedBackendSteps
  , awaitOwnParked
  , withOwnGate
  , withPrivateDir
  , within10s
  , killVictimAt
  , parkInTokenLoad
  , assertBalanced
  , memoryReopenRefused
  , boxKilledMemory
  , ctxKilledGated
  , awaitResidueDrained
  , freshAbsentKey
  , joinedCleanupReopen
  , countingAcquisition
  , rvOK
  , rvPending
  , rvGeneral
  , rvBad
  , c_ownGateNew
  , c_ownGateFree
  , c_ownGateRelease
  , c_ownGateEnvOutstanding
  , c_ownGateArmCheckpoint
  , c_ownGateParked
  , c_ownEnvDoublefree
  , c_absentLookup
  , c_absentHookLookup
  , c_absentRelease
  ) where


import Control.Concurrent
  ( MVar
  , ThreadId
  , forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  , threadDelay
  , tryPutMVar
  )
import Control.Exception
  ( AsyncException (..)
  , IOException
  , SomeException
  , bracket
  , finally
  , fromException
  , mask_
  , try
  )
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map as Map
import Data.IORef (IORef, modifyIORef', newIORef, readIORef)
import qualified Data.Set as Set
import Data.Word (Word64)
import Foreign.C.Types (CInt (..), CLong (..), CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.StablePtr
  ( StablePtr
  , castPtrToStablePtr
  , castStablePtrToPtr
  , deRefStablePtr
  , freeStablePtr
  , newStablePtr
  )
import Foreign.Storable (peek, poke)
import GHC.Clock (getMonotonicTimeNSec)
import GHC.Conc (BlockReason (..), ThreadStatus (..), threadStatus)
import System.Directory
  ( createDirectory
  , getTemporaryDirectory
  , removeDirectoryRecursive
  )
import System.FilePath ((</>))
import System.Timeout (timeout)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)

import qualified Haskoki.Engine.Backend as B
import OwnershipCounters (assertZero)
import StormBudget (stormScaleBudget)
import AcquisitionCounters
import Haskoki.Engine.OpenSSL4
  ( OpenSSL4
  , TestGate
  , openBackendGated
  )
import Haskoki.FFI.Async
  ( AcquireFailure (..)
  , AcquireStep (..)
  , AsyncAcquisition (..)
  , AsyncCtx (..)
  , JobHandle
  , ResidueOwner
  , allocJobHandle
  , asyncAcquisition
  , ctxPendingReclaims
  , ctxReclaimStats
  , closeCtxSlotWith
  , closeStoreBoxSlotWith
  , haskokiAsyncClose
  , haskokiAsyncStoreClose
  , haskokiAsyncStoreOpen
  , openAsyncCtxOnWith
  , openAsyncCtxWith
  , openStoreBoxWith
  , registerBorrowedCtx
  , registerFixtureCtx
  , residueCount
  , resolveJobHandle
  , retireCtx
  , StoreBox (..)
  )
import Haskoki.FFI.Standard
  ( StdInstance (..)
  , haskokiStdOpenSession
  , openStdInstance
  , stdRvOf
  )
import Haskoki.CallWork (checkedCallWork)
import Haskoki.Model (Model (..))
import Haskoki.Operation (CryptoEffect (..), CryptoResult (..))
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Outcome
  ( EffectRequest (..)
  , EngineResult (..)
  , PlanResult (..)
  , PreparedCommit (..)
  )
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
  ( AsyncWork (..)
  , JobFunction (..)
  , JobRequest (..)
  , enableAsyncSession
  , startJob
  , tableStats
  , tryNewAsyncTable
  )
import Haskoki.Runtime.Config
  ( Config (..)
  , Limits (..)
  , StorageCfg (..)
  , StorageKind (..)
  , TokensCfg (..)
  , defaultConfig
  )
import Haskoki.Runtime.Detached
  ( AttachmentView (..)
  , DetachCtx
  , DetachOutcome (..)
  , JoinOutcome (..)
  , JoinRequest (..)
  , detachJob
  , inspectAttachment
  , joinJob
  , openDetached
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
  , FaultInjector (..)
  , JobRecord (..)
  , Store (..)
  , StoreDelta (..)
  , TokenRecord (..)
  , defaultLimits
  , emptyDelta
  )
import Haskoki.Runtime.Storage.Memory
  ( MemoryWorld
  , newMemoryWorld
  , openMemoryStore
  , openMemoryStoreWith
  )
import Haskoki.Session (tokenAuthNew)
import Haskoki.Transition (finishEffect, planCall)
import Haskoki.Types
  ( EngineResourceId (..)
  , Generation (..)
  , JobId (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode ( CKR_OK)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )


isNull :: StablePtr a -> Bool
isNull sp = castStablePtrToPtr sp == nullPtr

-- Config-injected failures (pins: always NULL)

badSqliteCfg :: Config
badSqliteCfg = defaultConfig
  { cfgStorage = (cfgStorage defaultConfig)
      { scKind = StorageSQLite
      , scPath = Just "/nonexistent-dir-xyz/store.db"
      }
  }

zeroSlotCfg :: Config
zeroSlotCfg = defaultConfig
  { cfgLimits = (cfgLimits defaultConfig) { limSlots = 0 } }

oversizeCatalogCfg :: Config
oversizeCatalogCfg = defaultConfig
  { cfgLimits = (cfgLimits defaultConfig) { limSlots = 2 }
  , cfgTokens = (cfgTokens defaultConfig)
      { tcEntries =
          [ ("tok-a", "0000", "1111")
          , ("tok-b", "0000", "2222")
          , ("tok-c", "0000", "3333")
          ]
      }
  }

-- Table-scoped close over a shared store (private FFI surface)

cannedFfiDigest :: ByteString
cannedFfiDigest = BS.replicate 32 0xD1

countingRunner :: IORef Int -> CryptoEffect -> IO CryptoResult
countingRunner ref _fx = do
  modifyIORef' ref (+ 1)
  pure (GotBytes cannedFfiDigest)

-- | A memory store with the home token record seated (generation 0).
mkFfiStore :: IO Store
mkFfiStore = do
  world <- newMemoryWorld
  eStore <- openMemoryStore world
  store <- case eStore of
    Right s -> pure s
    Left err -> assertFailure ("world open failed: " ++ show err)
  let tok = TokenRecord
        { trId = TokenId 1
        , trSlot = SlotId 0
        , trGeneration = Generation 0
        , trLabel = "ffi-test"
        , trAuth = tokenAuthNew
        }
  res <- storeCommit store emptyDelta { sdPutTokens = [tok] }
  case res of
    Committed -> pure store
    other -> assertFailure ("token seat failed: " ++ show other)

-- | A fresh world with the home token record seated (generation 0),
-- opened with the given fault injector.
mkFfiStoreWith :: FaultInjector -> IO (MemoryWorld, Store)
mkFfiStoreWith inj = do
  world <- newMemoryWorld
  eStore <- openMemoryStoreWith world defaultLimits inj
  store <- case eStore of
    Right s -> pure s
    Left err -> assertFailure ("world open failed: " ++ show err)
  let tok = TokenRecord
        { trId = TokenId 1
        , trSlot = SlotId 0
        , trGeneration = Generation 0
        , trLabel = "ffi-test"
        , trAuth = tokenAuthNew
        }
  res <- storeCommit store emptyDelta { sdPutTokens = [tok] }
  case res of
    Committed -> pure (world, store)
    other -> assertFailure ("token seat failed: " ++ show other)

mkFfiDetached :: Store -> IO DetachCtx
mkFfiDetached store = do
  eDc <- openDetached store (TokenId 1)
  case eDc of
    Right dc -> pure dc
    Left err -> assertFailure ("openDetached failed: " ++ show err)

-- | Digest-initialize one session (the canned mechanism), so a
-- later digest plans Execute on it. Shared by the hand-built
-- context below and by the reopened context that rejoins a
-- detached digest.
initFfiDigestSession :: Env -> SessionId -> IO ()
initFfiDigestSession env sid = do
  m2 <- snapshotModel env
  let initReq = Request Pkcs11_3_2 F_DigestInit (Just sid) Nothing
        (encodeInitInput (MechanismId 0x250) [] False "") []
  case planCall defaultRules m2 initReq of
    Execute res (EffectCrypto _) -> do
      m3 <- snapshotModel env
      case finishEffect defaultRules m3 res
          (EngineOkResource (EngineResourceId 41)) of
        Left rej -> assertFailure ("digest-init finish rejected: " ++ show rej)
        Right pc -> do
          pr <- publish env (pcDelta pc)
          case pr of
            Right () -> pure ()
            Left f -> assertFailure ("digest-init publish failed: " ++ show f)
    other -> assertFailure ("digest-init did not plan execute: " ++ show other)

-- | A worker-level store-bound async context: initialized env with
-- a seated token and one digest-initialized proof session, a live
-- backend, a fresh async-enabled table, and an empty live set —
-- bound to the shared detach context. Reads no environment
-- (unlike 'haskokiAsyncOpenOn'), so the case stays race-free
-- under the suite's parallel runner.
mkFfiGen :: DetachCtx -> IO AsyncCtx
mkFfiGen dc = do
  env <- newEnv defaultRules
  ini <- initialize env defaultInitArgs
  case ini of
    OutcomeOk () -> pure ()
    OutcomeErr c -> assertFailure ("init failed: " ++ show c)
  seatToken env (SlotId 0) >>= assertEqual "seat ok" (Right ())
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
  initFfiDigestSession env sid
  mTable <- tryNewAsyncTable 8
  table <- case mTable of
    Just t -> pure t
    Nothing -> assertFailure "table allocator refused"
  enableAsyncSession table sid
  eBe <- B.openBackend "provider=default"
    :: IO (B.EngineResult (B.BackendEnv OpenSSL4))
  be <- case eBe of
    B.EngineOk b -> pure b
    B.EngineFail err -> assertFailure ("openssl open failed: " ++ show err)
  live <- newIORef Set.empty
  pure (AsyncCtx env be sid table live (Just dc))

-- | Start a real planned digest job on a hand-built context.
startFfiDigest :: AsyncCtx -> ByteString -> Word64 -> Int -> IO JobId
startFfiDigest ctx input cap ticks = do
  m <- snapshotModel (acEnv ctx)
  let req = Request Pkcs11_3_2 F_Digest (Just (acSession ctx)) Nothing input
        [RegionBytes "async" (IntentBuffer maxOutputBytes)]
  case planCall defaultRules m req of
    Execute res eff -> do
      cw <- case checkedCallWork (acSession ctx) res eff of
        Right c -> pure c
        Left mm -> assertFailure ("digest pair must check: " ++ show mm)
      let jr = JobRequest
            { jrSession = acSession ctx
            , jrFunction = JobDigest
            , jrWork = WorkCall cw
            , jrTicks = ticks
            , jrCapacity = cap
            }
      started <- startJob (acTable ctx) jr
      case started of
        Right jid -> pure jid
        Left deny -> assertFailure ("digest start denied: " ++ show deny)
    other -> assertFailure ("digest did not plan execute: " ++ show other)

loadFfiJobs :: Store -> IO [JobRecord]
loadFfiJobs store = do
  eJobs <- storeLoadJobs store
  case eJobs of
    Right jobs -> pure jobs
    Left err -> assertFailure ("loadJobs failed: " ++ show err)

rvOK, rvPending, rvGeneral, rvBad :: CULong
rvOK = CULong 0x0
rvPending = CULong 0x204
rvGeneral = CULong 0x05
rvBad = CULong 0x07

-- | The null job token: every out-pointer starts here, and every
-- refusal leaves it here.
nullJob :: StablePtr JobHandle
nullJob = castPtrToStablePtr nullPtr

-- | Wait until a thread parks in its gate wait (a status
-- barrier, never timing): the closer provably blocks with the
-- expected block reason before the release, and any other block
-- reason keeps polling.
awaitBlocked :: BlockReason -> ThreadId -> IO ()
awaitBlocked = awaitBlockedFor (stormScaleBudget `div` 1000)

-- | 'awaitBlocked' with an explicit millisecond budget, so the
-- reason-rejection probe bounds its own wait.
awaitBlockedFor :: Int -> BlockReason -> ThreadId -> IO ()
awaitBlockedFor budget want tid = go budget
  where
    go n
      | n <= 0 = assertFailure
          ("closer never blocked with " ++ show want ++ " in its gate wait")
      | otherwise = do
          st <- threadStatus tid
          case st of
            ThreadBlocked got | got == want -> pure ()
            _ -> threadDelay 1000 >> go (n - 1)

-- Protected transfers (no stranded handoff)

-- | Plan a digest job on a hand-built context without starting
-- it, for driving the submit transfer directly.
planFfiDigest :: AsyncCtx -> ByteString -> Word64 -> Int -> IO JobRequest
planFfiDigest ctx input cap ticks = do
  m <- snapshotModel (acEnv ctx)
  let req = Request Pkcs11_3_2 F_Digest (Just (acSession ctx)) Nothing input
        [RegionBytes "async" (IntentBuffer maxOutputBytes)]
  case planCall defaultRules m req of
    Execute res eff -> do
      cw <- case checkedCallWork (acSession ctx) res eff of
        Right c -> pure c
        Left mm -> assertFailure ("digest pair must check: " ++ show mm)
      pure JobRequest
        { jrSession = acSession ctx
        , jrFunction = JobDigest
        , jrWork = WorkCall cw
        , jrTicks = ticks
        , jrCapacity = cap
        }
    other -> assertFailure ("digest did not plan execute: " ++ show other)

-- | Close a fresh owned context through its slot and immediately
-- reallocate the freed index for a borrowed view. The realloc
-- normally lands on the just-freed index; when a parallel worker's
-- allocation lands first, that attempt's view retires and frees and
-- the pair tries again within the bound. No assertion runs through
-- freed bits here: the retired controls pin while allocated.
reuseBorrowed :: DetachCtx -> AsyncCtx -> Int -> IO (StablePtr AsyncCtx)
reuseBorrowed _ _ 0 =
  assertFailure "freed index never came back within the bound"
reuseBorrowed dc borrowed n = do
  owned <- mkFfiGen dc
  spOwned <- newStablePtr owned
  registerFixtureCtx spOwned (acTable owned)
  let ownedBits = castStablePtrToPtr spOwned
  alloca $ \pSlot -> do
    poke pSlot spOwned
    haskokiAsyncClose pSlot
    after <- peek pSlot
    assertBool "slot nulled" (isNull after)
    spBorrowed <- newStablePtr borrowed
    registerBorrowedCtx spBorrowed (acTable borrowed)
    if castStablePtrToPtr spBorrowed == ownedBits
      then pure spBorrowed
      else do
        retireCtx spBorrowed
        freeStablePtr spBorrowed
        reuseBorrowed dc borrowed (n - 1)

-- | Open a live Standard session on the default config and return
-- the instance, the session handle and the installed borrowed-view
-- key. The caller owns the instance and closes it.
openStdSessionView :: IO (StablePtr StdInstance, CULong, StablePtr AsyncCtx)
openStdSessionView = do
  inst <- openStdInstance defaultConfig
  assertBool "instance opened" (castStablePtrToPtr inst /= nullPtr)
  h <- alloca $ \pSession -> do
    haskokiStdOpenSession inst 0 0 pSession
      >>= assertEqual "session opened" (stdRvOf CKR_OK)
    peek pSession
  views <- deRefStablePtr inst >>= readIORef . siAsyncViews
  case Map.lookup (SessionId (fromIntegral h)) views of
    Nothing -> assertFailure "borrowed view installed"
    Just view -> pure (inst, h, view)

-- | Poll the C reclamation backlog to quiescence (bounded):
-- borrows span adjacent lines only, so a live backlog drains
-- immediately and anything standing past the bound is stranded.
-- The table is process-wide and the suite runs cases in parallel,
-- hence the poll instead of a single read.
awaitNoPendingReclaims :: IO ()
awaitNoPendingReclaims = go (100 :: Int)
  where
    go n
      | n <= 0 = do
          p <- ctxPendingReclaims
          assertEqual "no stranded reclamation backlog" 0 p
      | otherwise = do
          p <- ctxPendingReclaims
          if p == 0 then pure () else threadDelay 1000 >> go (n - 1)

-- | Poll the displaced/taken/freed accounting to balance
-- (bounded): every displaced root is taken exactly once and freed
-- exactly once, so the three agree at quiescence. Parallel cases
-- share the counters, hence the poll instead of a single read.
awaitReclaimBalanced :: IO ()
awaitReclaimBalanced = go (100 :: Int)
  where
    go n = do
      (d, t, f) <- ctxReclaimStats
      if d == t && t == f
        then pure ()
        else if n <= 0
          then assertFailure ("reclamation imbalanced: " ++ show (d, t, f))
          else threadDelay 1000 >> go (n - 1)

-- | Park at one acquisition step: signal arrival, then block forever
-- (until killed). Every other step runs as before.
parkAt :: AcquireStep -> MVar () -> MVar () -> AsyncAcquisition -> AsyncAcquisition
parkAt step arrived hold acq = acq
  { aaStep = \s ->
      if s == step
        then putMVar arrived () >> takeMVar hold
        else aaStep acq s
  }

-- | Every Store and backend the record opens, kept so a case can
-- close what a killed open left behind once its assertions have
-- read the state (closes are idempotent).
data Opened = Opened
  { opStores :: !(IORef [Store])
  , opBackends :: !(IORef [B.BackendEnv OpenSSL4])
  }

-- | Record every Store and backend the given steps open.
trackOpened :: AsyncAcquisition -> IO (AsyncAcquisition, Opened)
trackOpened base = do
  stores <- newIORef []
  backends <- newIORef []
  let acq = base
        { aaOpenStore = \p -> do
            r <- aaOpenStore base p
            case r of
              Right st -> modifyIORef' stores (st :)
              Left _ -> pure ()
            pure r
        , aaOpenBackend = do
            r <- aaOpenBackend base
            case r of
              B.EngineOk be -> modifyIORef' backends (be :)
              B.EngineFail _ -> pure ()
            pure r
        }
  pure (acq, Opened stores backends)

-- | Close whatever the record opened (idempotent closes; a close
-- error is ignored, the assertions already ran).
releaseOpened :: Opened -> IO ()
releaseOpened o = do
  readIORef (opBackends o) >>= mapM_ (\be -> tryAny (B.closeBackend be))
  readIORef (opStores o) >>= mapM_ (\st -> tryAny (storeClose st))
  where
    tryAny :: IO () -> IO (Either SomeException ())
    tryAny = try

-- | Open the box's Store over a test-held memory world, so a reopen
-- of the same world is the lock probe.
memoryStoreSteps :: MemoryWorld -> AsyncAcquisition -> AsyncAcquisition
memoryStoreSteps world acq = acq
  { aaOpenStore = \_ -> either (const (Left ())) Right <$> openMemoryStore world }

-- | Open the box's Store over a test-held memory world through the
-- given injector (shared across opens, so a script fires once).
memoryStoreThrough :: MemoryWorld -> FaultInjector -> AsyncAcquisition -> AsyncAcquisition
memoryStoreThrough world inj acq = acq
  { aaOpenStore = \_ ->
      either (const (Left ())) Right <$> openMemoryStoreWith world defaultLimits inj }

-- | Open backends through a test gate, so native envs are counted
-- per gate.
gatedBackendSteps :: Ptr TestGate -> AsyncAcquisition -> AsyncAcquisition
gatedBackendSteps g acq = acq { aaOpenBackend = openBackendGated g "provider=default" }

foreign import ccall unsafe "hsk_ossl4_test_gate_new" c_ownGateNew
  :: IO (Ptr TestGate)
foreign import ccall unsafe "hsk_ossl4_test_gate_free" c_ownGateFree
  :: Ptr TestGate -> IO ()
foreign import ccall unsafe "hsk_ossl4_test_gate_release" c_ownGateRelease
  :: Ptr TestGate -> CInt -> IO ()
foreign import ccall unsafe "hsk_ossl4_test_gate_env_outstanding" c_ownGateEnvOutstanding
  :: Ptr TestGate -> IO CLong
foreign import ccall unsafe "hsk_ossl4_test_gate_arm_checkpoint" c_ownGateArmCheckpoint
  :: Ptr TestGate -> CInt -> IO ()
foreign import ccall unsafe "hsk_ossl4_test_gate_parked" c_ownGateParked
  :: Ptr TestGate -> IO CInt
foreign import ccall unsafe "hsk_ossl4_test_env_doublefree" c_ownEnvDoublefree
  :: IO CLong

foreign import ccall unsafe "haskoki_ctx_lookup_acquire" c_absentLookup
  :: Ptr () -> Ptr (Ptr ()) -> IO CInt
foreign import ccall unsafe "haskoki_ctx_hook_acquire" c_absentHookLookup
  :: Ptr () -> Ptr (Ptr ()) -> IO CInt
foreign import ccall unsafe "haskoki_ctx_release" c_absentRelease
  :: Ptr () -> IO ()

-- | Barrier for a sibling parked in a gate checkpoint: the park is
-- straight-line code past the arm, so this either observes it or
-- fails bounded.
awaitOwnParked :: Ptr TestGate -> IO ()
awaitOwnParked g = go (stormScaleBudget `div` 5000)
  where
    go n
      | n <= 0 = assertFailure "sibling never parked in the checkpoint"
      | otherwise = do
          p <- c_ownGateParked g
          if p /= 0 then pure () else threadDelay 5000 >> go (n - 1)

-- | A private test gate, released and freed on every exit. The body
-- closes every backend opened through it first ('releaseOpened'),
-- so no env outlives its gate.
withOwnGate :: (Ptr TestGate -> IO a) -> IO a
withOwnGate = bracket acquire release
  where
    acquire = do
      g <- c_ownGateNew
      if g == nullPtr
        then assertFailure "test gate allocation failed"
        else pure g
    release g = c_ownGateRelease g 0 >> c_ownGateFree g

-- | A fresh private directory under the temp root, removed on exit.
withPrivateDir :: (FilePath -> IO a) -> IO a
withPrivateDir = bracket create (\d -> try' (removeDirectoryRecursive d))
  where
    create = do
      base <- getTemporaryDirectory
      let go :: Int -> IO FilePath
          go n = do
            t <- getMonotonicTimeNSec
            let d = base </> ("haskoki-standalone-" ++ show t ++ "-" ++ show n)
            r <- try (createDirectory d)
            case r of
              Right () -> pure d
              Left (e :: IOException)
                | n < 100 -> go (n + 1)
                | otherwise -> ioError e
      go 0
    try' :: IO () -> IO ()
    try' act = do
      _ <- (try act :: IO (Either IOException ()))
      pure ()

-- | Storm-scale backstop on every wait: the shared 300 s
-- hang-detection budget ('stormScaleBudget'), never a timing
-- assumption. A join that never finishes still fails loudly.
within10s :: String -> IO a -> IO a
within10s what act = do
  r <- timeout stormScaleBudget act
  case r of
    Just a -> pure a
    Nothing -> assertFailure ("timed out: " ++ what)

-- | Run one open on an unmasked victim thread that parks at a point
-- reached through the given steps, kill it there, and join it. The
-- kill must abort the open.
killVictimAt
  :: (MVar () -> MVar () -> AsyncAcquisition -> AsyncAcquisition)
  -> AsyncAcquisition
  -> (AsyncAcquisition -> IO (Either AcquireFailure a))
  -> IO ()
killVictimAt park acq open = do
  arrived <- newEmptyMVar
  hold <- newEmptyMVar
  done <- newEmptyMVar
  victim <- forkIO $ do
    r <- try (open (park arrived hold acq))
    putMVar done r
  (do within10s "victim reaches the step" (takeMVar arrived)
      killThread victim
      r <- within10s "victim joins" (takeMVar done)
      case r of
        Left e | fromException e == Just ThreadKilled -> pure ()
        Left e -> assertFailure ("victim died with " ++ show e)
        Right (Right _) -> assertFailure "killed open returned a handle"
        Right (Left _) -> assertFailure "killed open returned a failure")
    `finally` (killThread victim >> tryPutMVar hold () >> pure ())

-- | Park inside the Store's token load (token initialization), not at
-- a step.
parkInTokenLoad :: MVar () -> MVar () -> AsyncAcquisition -> AsyncAcquisition
parkInTokenLoad arrived hold acq = acq
  { aaOpenStore = \p -> do
      r <- aaOpenStore acq p
      pure $ case r of
        Right st -> Right st
          { storeLoadTokens = putMVar arrived () >> takeMVar hold >> storeLoadTokens st }
        Left e -> Left e
  }

-- | The balance lines every standalone-ownership case asserts. The
-- labels carry the whole count record and the case's own
-- observation, so one failure shows every value.
assertBalanced :: String -> AcqCounts -> IO ()
assertBalanced note c = do
  let ctxt = " (" ++ show c ++ "; " ++ note ++ ")"
  assertZero "store_opens_minus_closes" ("store opens minus closes" ++ ctxt)
    (acStoreOpens c - acStoreCloses c)
  assertZero "backend_opens_minus_closes" ("backend opens minus closes" ++ ctxt)
    (acBackendOpens c - acBackendCloses c)
  assertZero "ctx_allocs_minus_frees" ("context allocs minus frees" ++ ctxt)
    (acCtxAllocs c - acCtxFrees c)
  assertZero "box_allocs_minus_frees" ("box allocs minus frees" ++ ctxt)
    (acBoxAllocs c - acBoxFrees c)
  assertZero "registrations_minus_retirements"
    ("registrations minus retirements" ++ ctxt)
    (acRegistrations c - acRetirements c)

-- | 0 when the memory world reopens (then closes the reopened
-- handle), 1 when it is still owned.
memoryReopenRefused :: MemoryWorld -> IO (Int, String)
memoryReopenRefused world = do
  r <- openMemoryStore world
  case r of
    Right st -> storeClose st >> pure (0, "reopened")
    Left e -> pure (1, show e)

-- | A box open over a memory world, killed at the given park point:
-- the Store must be closed and the world must reopen.
boxKilledMemory
  :: (MVar () -> MVar () -> AsyncAcquisition -> AsyncAcquisition) -> IO ()
boxKilledMemory park = do
  world <- newMemoryWorld
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do killVictimAt park acq (\a -> openStoreBoxWith a nullPtr)
      c <- readCounts
      (refused, why) <- memoryReopenRefused world
      assertBalanced ("memory world reopen: " ++ why) c
      assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | A bare context open over a gated backend, killed at the given
-- step: the backend must be closed and its native env destroyed.
ctxKilledGated :: AcquireStep -> IO ()
ctxKilledGated step = withOwnGate $ \g -> do
  (tracked, opened) <- trackOpened (gatedBackendSteps g asyncAcquisition)
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do killVictimAt (parkAt step) acq (\a -> openAsyncCtxWith a defaultConfig)
      c <- readCounts
      envOut <- c_ownGateEnvOutstanding g
      let note = "env_outstanding=" ++ show envOut
      assertBalanced note c
      assertZero "registrations" ("registrations (" ++ show c ++ ")")
        (acRegistrations c)
      assertZero "env_outstanding" "native envs left on the gate" envOut)
    `finally` releaseOpened opened

-- | Poll the residue count down to zero. A concurrent standalone open
-- or close elsewhere in this process may hold the entry mid-retry;
-- each further poll runs one more open and close through the real
-- exports, which retries it again. Gives up after the
-- storm-scale budget.
awaitResidueDrained :: ResidueOwner -> IO Int
awaitResidueDrained owner = go (0 :: Int)
  where
    go n = do
      k <- residueCount owner
      if k == 0 || n >= (stormScaleBudget `div` 5000)
        then pure k
        else do
          threadDelay 5000
          box <- haskokiAsyncStoreOpen nullPtr
          alloca $ \pBox -> do
            poke pBox box
            haskokiAsyncStoreClose pBox
          go (n + 1)

-- | Allocate a key the registry reads as absent with no hook. The
-- allocator may hand back a freed index whose tombstone still
-- stands, so colliding keys stay live while the search continues;
-- the fresh absent key returns with the colliders for the caller to
-- free. Bounded; parallel churn never exhausts it.
freshAbsentKey :: AsyncCtx -> IO (StablePtr AsyncCtx, [StablePtr AsyncCtx])
freshAbsentKey ctx = go (1000 :: Int) []
  where
    go 0 _ = assertFailure "no absent registry key within the bound"
    go n acc = mask_ $ do
      sp <- newStablePtr ctx
      let key = castPtr (castStablePtrToPtr sp)
      kind <- alloca $ \pOut -> c_absentLookup key pOut
      case kind of
        0 -> do
          hooked <- alloca $ \pHook -> c_absentHookLookup key pHook
          if hooked == 0
            then pure (sp, acc)
            else c_absentRelease key >> go (n - 1) (sp : acc)
        1 -> c_absentRelease key >> go (n - 1) (sp : acc)
        2 -> c_absentRelease key >> go (n - 1) (sp : acc)
        _ -> go (n - 1) (sp : acc)

-- | Open a box and a context on it, start and detach one job, kill a
-- second-context acquisition at pointer allocation, close both,
-- reopen the same identity, rejoin the detached job exactly once,
-- and close again. Returns the reopened context for the caller's
-- liveness asserts. The box opener names the identity (a memory
-- world or a SQLite path).
joinedCleanupReopen
  :: AsyncAcquisition
  -> (AsyncAcquisition -> IO (Either AcquireFailure (StablePtr StoreBox)))
  -> IO AsyncCtx
joinedCleanupReopen acq openBox = do
  eBox <- openBox acq
  box <- case eBox of
    Right b -> pure b
    Left _ -> assertFailure "store box open failed"
  eCtx <- openAsyncCtxOnWith acq defaultConfig box
  sp <- case eCtx of
    Right s -> pure s
    Left _ -> assertFailure "context open failed"
  ctx <- deRefStablePtr sp
  dc <- case acDetach ctx of
    Just d -> pure d
    Nothing -> assertFailure "context has no detach view"
  initFfiDigestSession (acEnv ctx) (acSession ctx)
  j0 <- startFfiDigest ctx "abc" 32 1
  eDet <- detachJob dc (acTable ctx) j0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  (liveDet, _, _) <- tableStats (acTable ctx)
  assertZero "live_jobs" "detach revoked the live job" liveDet
  killVictimAt (parkAt AfterCtxAlloc) acq
    (\a -> openAsyncCtxOnWith a defaultConfig box)
  alloca $ \pCtx -> do
    poke pCtx sp
    closeCtxSlotWith acq pCtx
    afterCtx <- peek pCtx
    assertBool "context slot nulled" (isNull afterCtx)
  alloca $ \pBox -> do
    poke pBox box
    closeStoreBoxSlotWith acq pBox
    afterBox <- peek pBox
    assertBool "box slot nulled" (isNull afterBox)
  eBox2 <- openBox acq
  box2 <- case eBox2 of
    Right b -> pure b
    Left _ -> assertFailure "box reopen failed"
  eCtx2 <- openAsyncCtxOnWith acq defaultConfig box2
  sp2 <- case eCtx2 of
    Right s -> pure s
    Left _ -> assertFailure "context reopen failed"
  ctx2 <- deRefStablePtr sp2
  dc2 <- case acDetach ctx2 of
    Just d -> pure d
    Nothing -> assertFailure "reopened context has no detach view"
  initFfiDigestSession (acEnv ctx2) (acSession ctx2)
  let rejoin = joinJob dc2 (acEnv ctx2) (acTable ctx2) JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = acSession ctx2
        , jqCapacity = 32
        }
  eJoin <- rejoin
  j2 <- case eJoin of
    JoinOk j -> pure j
    other -> assertFailure ("rejoin failed: " ++ show other)
  eJoin2 <- rejoin
  case eJoin2 of
    JoinAlreadyAttached _ -> pure ()
    other -> assertFailure ("second rejoin not refused: " ++ show other)
  av2 <- inspectAttachment dc2 pid
  assertEqual "rejoined attachment active" (Just (AvActive j2)) av2
  h2 <- allocJobHandle ctx2 j2
  alloca $ \pCtx -> do
    poke pCtx sp2
    closeCtxSlotWith acq pCtx
    afterCtx2 <- peek pCtx
    assertBool "reopened context slot nulled" (isNull afterCtx2)
  alloca $ \pBox -> do
    poke pBox box2
    closeStoreBoxSlotWith acq pBox
    afterBox2 <- peek pBox
    assertBool "reopened box slot nulled" (isNull afterBox2)
  mStale <- resolveJobHandle ctx2 h2
  assertEqual "handle retired" Nothing mStale
  pure ctx2

-- | Counting wrapper over the production acquisition steps, with a
-- private residue owner.
countingAcquisition :: IO (AsyncAcquisition, IO AcqCounts)
countingAcquisition = countingAcquisitionOver asyncAcquisition
