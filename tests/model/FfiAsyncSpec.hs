{- | FFI acquisition hygiene probes, behavioral half.

NULL pins for config-injected failures (bad SQLite path, refused
seating, oversize catalog), plus a non-poisoning pin (a failed
open never breaks the next open).

The async-window probe ('caseStdAsyncSlow'): async exceptions
delivered mid-open are rethrown from the inner opens (sync
failures stay NULL-identical; the @foreign export@ boundary keeps
its catch-all so no Haskell exception crosses into C), so the
mid-open kill aborts the open.

Probe shape (deliberately NOT a kill spray): the victim signals
@entered@ from inside a seconds-long open (a large memory catalog:
50k seatings, no files, no environment reads), main fires ONE
@killThread@ (the victim is provably alive and far from exit, so
the synchronous throw is always delivered mid-open and always
returns), then joins on @outcome@. Both joins carry a 10s
'System.Timeout' backstop ('assertFailure' on expiry) per the
no-wedge rule. Prior attempts wedged here with a masked-driver
kill spray: the first kill lands before the victim installs its
report handler, the victim dies silently, and the join blocks
forever (64\/64 kills returned,
@iters=0@, @outcome=Nothing@). The entered-rendezvous makes that
impossible: no kill precedes handler installation.

The structural half (hook-injected leak probes over the bracket
acquisition, plus the crypto-guard unwind probe) lives in the
engine suite (@FfiAcquireSpec@). Crypto cases live there (not
here) because this suite's @ConfigSpec@
mutates @HASKOKI_CONFIG@ process-wide and tasty runs cases in
parallel; the engine suite has no environment writers, so its
crypto probes are race-free.
-}
{-# LANGUAGE OverloadedStrings #-}
module FfiAsyncSpec (spec) where

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
  , tryTakeMVar
  )
import Control.Exception
  ( AsyncException (..)
  , IOException
  , SomeException
  , bracket
  , finally
  , fromException
  , throwIO
  , try
  )
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.IORef (IORef, atomicModifyIORef', modifyIORef', newIORef, readIORef, writeIORef)
import qualified Data.Set as Set
import Data.Word (Word64)
import Foreign.C.String (withCString)
import Foreign.C.Types (CInt (..), CLong (..), CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.StablePtr
  ( StablePtr
  , castPtrToStablePtr
  , castStablePtrToPtr
  , freeStablePtr
  , newStablePtr
  )
import Foreign.Storable (peek, poke)
import GHC.Clock (getMonotonicTimeNSec)
import GHC.Conc (ThreadStatus (..), threadStatus)
import System.Directory
  ( createDirectory
  , getTemporaryDirectory
  , removeDirectoryRecursive
  )
import System.FilePath ((</>))
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import qualified Haskoki.Engine.Backend as B
import OwnershipCounters (assertZero, counted)
import Haskoki.Engine.OpenSSL4 (OpenSSL4, TestGate, openBackendGated)
import Haskoki.FFI.Async
  ( AcquireFailure (..)
  , AcquireStep (..)
  , AsyncAcquisition (..)
  , AsyncCtx (..)
  , JobHandle
  , ResidueOwner
  , allocJobHandle
  , asyncAcquisition
  , asyncCloseCtx
  , asyncLiveHandles
  , ctxAcquireBorrowTest
  , ctxPendingReclaims
  , ctxReclaimStats
  , ctxReleaseBorrowTest
  , closeCtxSlotWith
  , closeStoreBoxSlotWith
  , haskokiAsyncCancel
  , haskokiAsyncClose
  , haskokiAsyncJoin
  , haskokiAsyncStart
  , haskokiAsyncStoreClose
  , haskokiAsyncStoreOpen
  , haskokiAsyncStoreOpenWith
  , joinAcquireTransfer
  , joinTransfer
  , newResidueOwner
  , openAsyncCtxOnWith
  , openAsyncCtxWith
  , openStoreBoxWith
  , registerBorrowedCtx
  , registerCtx
  , residueCount
  , resolveJobHandle
  , retireCtx
  , setEnterTestHook
  , submitTransfer
  )
import Haskoki.FFI.Standard (StdInstance, haskokiStdClose, openStdInstance)
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
  , CancelOutcome (..)
  , CompleteOutcome (..)
  , Completion (..)
  , Delivery (..)
  , JobFunction (..)
  , JobRequest (..)
  , PollOutcome (..)
  , TerminalState (..)
  , asyncTableId
  , asyncTableSalt
  , cancelJob
  , enableAsyncSession
  , enterTableUse
  , exitTableUse
  , inspectTableGate
  , pollJob
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
  , JoinedComplete (..)
  , completeJoined
  , detachJob
  , inspectAttachment
  , inspectReverse
  , joinJob
  , openDetached
  , setJoinTestHook
  )
import Haskoki.Runtime.Lifecycle
  ( defaultInitArgs
  , initialize
  , newEnv
  , publish
  , seatToken
  , snapshotModel
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , JobExecState (..)
  , JobRecord (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , TokenRecord (..)
  , emptyDelta
  )
import Haskoki.Runtime.Storage.Memory (MemoryWorld, newMemoryWorld, openMemoryStore)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Transition (finishEffect, planCall)
import Haskoki.Types
  ( EngineResourceId (..)
  , Generation (..)
  , JobId (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

spec :: TestTree
spec = testGroup "FFI acquisition"
  [ testCase "std open succeeds then closes" (counted "m3-ffi-acquisition" "std-open-succeeds-then-closes" (caseStdSuccess))
  , testCase "std open bad sqlite path is NULL" (counted "m3-ffi-acquisition" "std-open-bad-sqlite-path-is-null" (caseStdBadSqlite))
  , testCase "std open zero slots is NULL" (counted "m3-ffi-acquisition" "std-open-zero-slots-is-null" (caseStdZeroSlots))
  , testCase "std open oversize catalog is NULL" (counted "m3-ffi-acquisition" "std-open-oversize-catalog-is-null" (caseStdOversize))
  , testCase "std failed open does not poison the next" (counted "m3-ffi-acquisition" "std-failed-open-does-not-poison-the-next" (caseStdNonPoison))
  , testCase "std async kill aborts the open (none swallowed)" (counted "m3-ffi-acquisition" "std-async-kill-aborts-the-open-none-swallowed" (caseStdAsyncSlow))
  , testCase "close-one keeps the other context live" (counted "m3-ffi-acquisition" "close-one-keeps-the-other-context-live" (caseCloseOneKeepsOther))
  , testCase "close waits for an entered caller" (counted "m3-ffi-acquisition" "close-waits-for-an-entered-caller" (caseCloseWaitsForEntered))
  , testCase "admitted calls run; close retires the gate" (counted "m3-ffi-acquisition" "admitted-calls-run-close-retires-the-gate" (caseAdmittedCallsRun))
  , testCase "kill in the submit transfer cancels the fresh job" (counted "m3-ffi-acquisition" "kill-in-the-submit-transfer-cancels-the-fresh-job" (caseSubmitKillCancelsFresh))
  , testCase "kill in the join handoff cancels the fresh join" (counted "m3-ffi-acquisition" "kill-in-the-join-handoff-cancels-the-fresh-join" (caseHandoffKillCancelsJoin))
  , testCase "join handoff publishes a live handle" (counted "m3-ffi-acquisition" "join-handoff-publishes-a-live-handle" (caseHandoffPublishes))
  , testCase "kill after join commit cancels before publish" (counted "m3-ffi-acquisition" "kill-after-join-commit-cancels-before-publish" (caseJoinAcquireKillAfterCommit))
  , testCase "join acquire publishes a live handle" (counted "m3-ffi-acquisition" "join-acquire-publishes-a-live-handle" (caseJoinAcquirePublishes))
  , testCase "killed close releases; retry completes teardown" (counted "m3-ffi-acquisition" "killed-close-releases-retry-completes-teardown" (caseCloseKillRetryCompletes))
  , testCase "concurrent entry races close cleanly" (counted "m3-ffi-acquisition" "concurrent-entry-races-close-cleanly" (caseEnterCloseRace))
  , testCase "borrowed start works" (counted "m3-ffi-acquisition" "borrowed-start-works" (caseBorrowedStart))
  , testCase "owned close hands its index to a borrowed view" (counted "m3-ffi-acquisition" "owned-close-hands-its-index-to-a-borrowed-view" (caseOwnedToBorrowedReuse))
  , testCase "caller parked pre-lookup meets the tombstone" (counted "m3-ffi-acquisition" "caller-parked-pre-lookup-meets-the-tombstone" (caseEnterBarrierCloseTombstones))
  , testCase "retire clears the entry hook" (counted "m3-ffi-acquisition" "retire-clears-the-entry-hook" (caseRetireClearsHook))
  , testCase "registry roots reclaim across churn" (counted "m3-ffi-acquisition" "registry-roots-reclaim-across-churn" (caseRegistryRootsReclaim))
  , testCase "stacked displacements preserve every root" (counted "m3-ffi-acquisition" "stacked-displacements-preserve-every-root" (caseReclaimOverlappingReuse))
  , testCase "kill during acquire rolls back and nulls" (counted "m3-ffi-acquisition" "kill-during-acquire-rolls-back-and-nulls" (caseJoinAcquireKillDuringAcquire))
  , testGroup "standalone ownership"
      [ testCase "store box killed after store open closes the store" (counted "m3-standalone-ownership" "store-box-killed-after-store-open-closes-the-store" (caseBoxKilledAfterStoreOpen))
      , testCase "store box killed after token setup closes the store" (counted "m3-standalone-ownership" "store-box-killed-after-token-setup-closes-the-store" (caseBoxKilledAfterTokenSetup))
      , testCase "store box killed during token load closes the store" (counted "m3-standalone-ownership" "store-box-killed-during-token-load-closes-the-store" (caseBoxKilledDuringTokenLoad))
      , testCase "sqlite store box killed after token setup releases its lock" (counted "m3-standalone-ownership" "sqlite-store-box-killed-after-token-setup-releases-its-lock" (caseSqliteBoxKilledAfterTokenSetup))
      , testCase "context killed after backend open closes the backend" (counted "m3-standalone-ownership" "context-killed-after-backend-open-closes-the-backend" (caseCtxKilledAfterBackendOpen))
      , testCase "context killed after session open closes the backend" (counted "m3-standalone-ownership" "context-killed-after-session-open-closes-the-backend" (caseCtxKilledAfterSessionOpen))
      , testCase "context killed after pointer allocation frees it unregistered" (counted "m3-standalone-ownership" "context-killed-after-pointer-allocation-frees-it-unregistered" (caseCtxKilledAfterCtxAlloc))
      , testCase "store-bound context killed after reload leaves the box usable" (counted "m3-standalone-ownership" "store-bound-context-killed-after-reload-leaves-the-box-usable" (caseStoreBoundKilledAfterReload))
      , testCase "export store open residue is recovered by the next open" (counted "m3-standalone-ownership" "export-store-open-residue-is-recovered-by-the-next-open" (caseExportResidueRecoveredByNextOpen))
      ]
  ]

isNull :: StablePtr a -> Bool
isNull sp = castStablePtrToPtr sp == nullPtr

-- ---------------------------------------------------------------------------
-- Config-injected failures (pins: always NULL)
-- ---------------------------------------------------------------------------

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

caseStdSuccess :: IO ()
caseStdSuccess = do
  sp <- openStdInstance defaultConfig
  assertBool "memory open succeeds" (not (isNull sp))
  haskokiStdClose sp

caseStdBadSqlite :: IO ()
caseStdBadSqlite = do
  sp <- openStdInstance badSqliteCfg
  assertBool "bad sqlite path is NULL" (isNull sp)

caseStdZeroSlots :: IO ()
caseStdZeroSlots = do
  sp <- openStdInstance zeroSlotCfg
  assertBool "zero-slot seating refusal is NULL" (isNull sp)

caseStdOversize :: IO ()
caseStdOversize = do
  sp <- openStdInstance oversizeCatalogCfg
  assertBool "oversize catalog refusal is NULL" (isNull sp)

caseStdNonPoison :: IO ()
caseStdNonPoison = do
  bad <- openStdInstance badSqliteCfg
  assertBool "bad open is NULL" (isNull bad)
  good <- openStdInstance defaultConfig
  assertBool "next open succeeds" (not (isNull good))
  haskokiStdClose good

-- ---------------------------------------------------------------------------
-- Async injection (the kill aborts the open; previously it was
-- swallowed and the open completed)
-- ---------------------------------------------------------------------------

-- | A slow-but-successful open: 50k catalog seatings on the memory
-- backend (no files, no environment reads). The seating loop runs
-- ~100ms+, so a kill fired right after @entered@ is delivered
-- mid-open with a 100x+ margin — deterministically, without hooks.
-- The slot bound admits the whole catalog (seating must SUCCEED;
-- a refusal would fail fast and evaporate the slow window).
bigCatalogCfg :: Config
bigCatalogCfg = defaultConfig
  { cfgLimits = (cfgLimits defaultConfig) { limSlots = bigCatalogSeats + 8 }
  , cfgTokens = (cfgTokens defaultConfig)
      { tcEntries =
          [ ("tok-" ++ show i, "0000", "1111") | i <- [1 .. bigCatalogSeats] ]
      }
  }

bigCatalogSeats :: Int
bigCatalogSeats = 50000

caseStdAsyncSlow :: IO ()
caseStdAsyncSlow = do
  entered <- newEmptyMVar
  outcome <- newEmptyMVar
  victimTid <- forkIO $ do
    r <- try $ do
      putMVar entered ()
      openStdInstance bigCatalogCfg
    putMVar outcome (r :: Either SomeException (StablePtr StdInstance))
  mEntered <- timeout 10000000 (takeMVar entered)
  case mEntered of
    Nothing -> assertFailure "wedge detected: victim never entered the open"
    Just () -> pure ()
  -- Single kill: the victim is alive inside a ~100ms+ open, so this
  -- is delivered mid-open and returns (no spray, no exit race).
  killThread victimTid
  mOut <- timeout 10000000 (takeMVar outcome)
  case mOut of
    Nothing -> assertFailure "wedge detected: open never reported after kill"
    Just (Left _) -> pure ()
    Just (Right sp) -> do
      if isNull sp then pure () else haskokiStdClose sp
      assertFailure "async swallowed: kill mid-open did not abort the open"

-- ---------------------------------------------------------------------------
-- Table-scoped close over a shared store (private FFI surface)
-- ---------------------------------------------------------------------------

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

mkFfiDetached :: Store -> IO DetachCtx
mkFfiDetached store = do
  eDc <- openDetached store (TokenId 1)
  case eDc of
    Right dc -> pure dc
    Left err -> assertFailure ("openDetached failed: " ++ show err)

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
      let jr = JobRequest
            { jrSession = acSession ctx
            , jrFunction = JobDigest
            , jrWork = WorkCall res eff
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

-- | Close-one/keep-other through the private FFI surface: two
-- hand-built store-bound contexts share one detach context; A
-- detaches, B joins with a live native handle, A closes — and
-- B's attachment, handle, reverse entry, and delivery all
-- survive. Closing B afterwards drains exactly its own state.
caseCloseOneKeepsOther :: IO ()
caseCloseOneKeepsOther = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctxA <- mkFfiGen dc
  ctxB <- mkFfiGen dc
  let tidA = asyncTableId (acTable ctxA)
      tidB = asyncTableId (acTable ctxB)
  assertBool "table identities distinct" (tidA /= tidB)
  let saltA = asyncTableSalt (acTable ctxA)
      saltB = asyncTableSalt (acTable ctxB)
  assertBool "salts nonzero" (saltA /= 0 && saltB /= 0)
  assertBool "table salts distinct" (saltA /= saltB)
  -- A starts and detaches; both contexts allocate from job zero.
  jA0 <- startFfiDigest ctxA "abc" 32 1
  assertEqual "A starts at zero" (JobId 0) jA0
  eDet <- detachJob dc (acTable ctxA) jA0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  -- B joins: its first live job is job zero too.
  eJoin <- joinJob dc (acEnv ctxB) (acTable ctxB) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = acSession ctxB
    , jqCapacity = 32
    }
  jB <- case eJoin of
    JoinOk j -> pure j
    other -> assertFailure ("join failed: " ++ show other)
  assertEqual "B joins at zero" (JobId 0) jB
  hB <- allocJobHandle ctxB jB
  mB0 <- resolveJobHandle ctxB hB
  assertEqual "B handle resolves" (Just jB) mB0
  -- Exactness pin at the store-bound level: both contexts hold
  -- numeric job zero under distinct exact salts, so B's handle
  -- must stay stale on A while live on B. The companion admission
  -- on A is registry only (the live set never consults table
  -- liveness), admitted solely to pin token distinctness across
  -- the equal job ids.
  mCross <- resolveJobHandle ctxA hB
  assertEqual "B handle stale on A" Nothing mCross
  hA <- allocJobHandle ctxA jA0
  assertBool "equal job ids admit distinct tokens"
    (castStablePtrToPtr hA /= castStablePtrToPtr hB)
  mA0 <- resolveJobHandle ctxA hA
  assertEqual "A handle resolves" (Just jA0) mA0
  nLiveB0 <- asyncLiveHandles ctxB
  assertEqual "B one live handle" 1 nLiveB0
  revB <- inspectReverse dc tidB jB
  assertEqual "B reverse resolves" (Just pid) revB
  av0 <- inspectAttachment dc pid
  assertEqual "B active" (Just (AvActive jB)) av0
  -- Close A: B keeps everything.
  asyncCloseCtx ctxA
  nLiveA <- asyncLiveHandles ctxA
  assertZero "live_handles" "A drained" nLiveA
  av1 <- inspectAttachment dc pid
  assertEqual "B still active after A closed" (Just (AvActive jB)) av1
  mB1 <- resolveJobHandle ctxB hB
  assertEqual "B handle survives" (Just jB) mB1
  nLiveB1 <- asyncLiveHandles ctxB
  assertEqual "B live set intact" 1 nLiveB1
  -- B drives and delivers exactly once.
  runs <- newIORef 0
  p <- pollJob (countingRunner runs) (acEnv ctxB) (acTable ctxB) JobDigest jB
  assertEqual "B ready" PollReady p
  writes <- newIORef []
  needed <- newIORef []
  let del = Delivery
        { dCapacity = 32
        , dWrite = \bs -> modifyIORef' writes (++ [bs])
        , dReportNeeded = \n -> modifyIORef' needed (++ [n])
        }
  jc <- completeJoined dc (acEnv ctxB) (acTable ctxB) JobDigest jB del (\_ -> pure ())
  assertEqual "B mark clean" Nothing (jcMarkError jc)
  case jcOutcome jc of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "B bytes" cannedFfiDigest bs
    other -> assertFailure ("expected B delivery, got " ++ show other)
  got <- readIORef writes
  assertEqual "B one write" 1 (length got)
  nNeed <- readIORef needed
  assertEqual "no sizing reports" [] nNeed
  nRuns <- readIORef runs
  assertEqual "B one engine run" 1 nRuns
  jobs <- loadFfiJobs store
  case [r | r <- jobs, jrPersistentId r == pid] of
    [rec] -> assertEqual "record delivered" JobDelivered (jrState rec)
    other -> assertFailure ("expected one record, got " ++ show other)
  -- Close B: its handle drains; the delivered attachment stands.
  asyncCloseCtx ctxB
  nLiveB2 <- asyncLiveHandles ctxB
  assertZero "live_handles" "B drained" nLiveB2
  av2 <- inspectAttachment dc pid
  assertEqual "B delivered terminal" (Just (AvTerminal JobDelivered)) av2

-- ---------------------------------------------------------------------------
-- Close admission (borrowers drain before teardown)
-- ---------------------------------------------------------------------------

rvOK, rvPending, rvGeneral, rvBad :: CULong
rvOK = CULong 0x0
rvPending = CULong 0x204
rvGeneral = CULong 0x05
rvBad = CULong 0x07

-- | The null job token: every out-pointer starts here, and every
-- refusal leaves it here.
nullJob :: StablePtr JobHandle
nullJob = castPtrToStablePtr nullPtr

-- | Wait until a thread parks (a status barrier, never timing):
-- the closer provably blocks in its gate wait before the release.
awaitBlocked :: ThreadId -> IO ()
awaitBlocked tid = go (200 :: Int)
  where
    go n
      | n <= 0 = assertFailure "closer never blocked in its gate wait"
      | otherwise = do
          st <- threadStatus tid
          case st of
            ThreadBlocked _ -> pure ()
            _ -> threadDelay 1000 >> go (n - 1)

-- | Close waits for an entered caller: a join admitted through
-- the export parks in the join-transfer window with its borrower
-- held, a racing close provably blocks on the gate, and only
-- after the release does the join complete and the close drain
-- its just-published handle. Afterwards the gate stands retired
-- with no borrowers, the committed join retired canceled, and
-- the slot stays nulled across a second close. Pre-fix the
-- closer never waited: it tore the context down while the
-- joiner was still inside.
caseCloseWaitsForEntered :: IO ()
caseCloseWaitsForEntered = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  eDet <- detachJob dc (acTable ctx) j0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  done <- newEmptyMVar
  setJoinTestHook dc (putMVar entered () >> takeMVar proceed)
  sp <- newStablePtr ctx
  registerCtx sp (acTable ctx)
  let sess = CULong (fromIntegral (unSessionId (acSession ctx)))
  _ <- forkIO $ do
    r <- try $ alloca $ \pHandleOut -> alloca $ \pNeedOut -> do
      poke pHandleOut nullJob
      haskokiAsyncJoin sp (CULong pid) 2 sess 32 pHandleOut pNeedOut
    putMVar done (r :: Either SomeException CULong)
  mEntered <- timeout 10000000 (takeMVar entered)
  case mEntered of
    Nothing -> assertFailure "joiner never entered the transfer window"
    Just () -> pure ()
  gateMid <- inspectTableGate (acTable ctx)
  assertEqual "one borrower, not retired" (1, False) gateMid
  alloca $ \pSlot -> do
    poke pSlot sp
    closedDone <- newEmptyMVar
    closerTid <- forkIO $ do
      r <- try (haskokiAsyncClose pSlot)
      putMVar closedDone (r :: Either SomeException ())
    awaitBlocked closerTid
    preRel <- tryTakeMVar closedDone
    case preRel of
      Nothing -> pure ()
      Just _ -> assertFailure "close finished before release (drain ran without the gate)"
    putMVar proceed ()
    mDone <- timeout 10000000 (takeMVar done)
    jr <- case mDone of
      Nothing -> assertFailure "joiner never reported after release"
      Just x -> pure x
    case jr of
      Right rv -> assertEqual "join completed through the wait" rvPending rv
      Left e -> assertFailure ("joiner failed: " ++ show e)
    mClosed <- timeout 10000000 (takeMVar closedDone)
    case mClosed of
      Nothing -> assertFailure "closer never reported after release"
      Just (Right ()) -> pure ()
      Just (Left e) -> assertFailure ("closer failed: " ++ show e)
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "retired, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "close drained the published handle" nLive
    av <- inspectAttachment dc pid
    assertEqual "committed join retired canceled" (Just (AvTerminal JobCanceled)) av
    jobs <- loadFfiJobs store
    case [r | r <- jobs, jrPersistentId r == pid] of
      [rec] -> assertEqual "record canceled" JobCanceled (jrState rec)
      other -> assertFailure ("expected one record, got " ++ show other)
    after <- peek pSlot
    assertBool "slot nulled" (castStablePtrToPtr after == nullPtr)
    haskokiAsyncClose pSlot
    after2 <- peek pSlot
    assertBool "slot stays nulled" (castStablePtrToPtr after2 == nullPtr)

-- | Admitted calls run normally through the gate, and close
-- retires it: start admits and publishes, cancel retires, the
-- value-level close claims and drains, and a later entry through
-- the still-valid pointer is refused without allocating
-- anything. The refused start proves the gate (not the slot
-- nulling) refuses it: the pointer was never freed.
caseAdmittedCallsRun :: IO ()
caseAdmittedCallsRun = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerCtx sp (acTable ctx)
  let sess = CULong (fromIntegral (unSessionId (acSession ctx)))
      startOn pHandleOut = BS.useAsCString "abc" $ \p ->
        haskokiAsyncStart sp sess 2 (castPtr p) 3 32 1 pHandleOut
  gate0 <- inspectTableGate (acTable ctx)
  assertEqual "gate fresh" (0, False) gate0
  h <- alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- startOn pHandleOut
    assertEqual "start pending" rvPending rv
    hOut <- peek pHandleOut
    assertBool "handle live" (castStablePtrToPtr hOut /= nullPtr)
    pure hOut
  m0 <- resolveJobHandle ctx h
  assertEqual "handle resolves" (Just (JobId 0)) m0
  gate1 <- inspectTableGate (acTable ctx)
  assertEqual "borrower released" (0, False) gate1
  rvCancel <- haskokiAsyncCancel sp h
  assertEqual "cancel ok" rvOK rvCancel
  m1 <- resolveJobHandle ctx h
  assertEqual "handle retired" Nothing m1
  (live1, term1, next1) <- tableStats (acTable ctx)
  assertEqual "job canceled" (0, 1, 1) (live1, term1, next1)
  asyncCloseCtx ctx
  gate2 <- inspectTableGate (acTable ctx)
  assertEqual "close claimed" (0, True) gate2
  nLive <- asyncLiveHandles ctx
  assertZero "live_handles" "drained" nLive
  hAfter <- alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- startOn pHandleOut
    assertEqual "post-close start refused" rvGeneral rv
    peek pHandleOut
  assertBool "no handle on refusal" (castStablePtrToPtr hAfter == nullPtr)
  (live2, term2, next2) <- tableStats (acTable ctx)
  assertEqual "refusal allocated nothing" (0, 1, 1) (live2, term2, next2)
  retireCtx sp
  freeStablePtr sp

-- ---------------------------------------------------------------------------
-- Protected transfers (no stranded handoff)
-- ---------------------------------------------------------------------------

-- | Plan a digest job on a hand-built context without starting
-- it, for driving the submit transfer directly.
planFfiDigest :: AsyncCtx -> ByteString -> Word64 -> Int -> IO JobRequest
planFfiDigest ctx input cap ticks = do
  m <- snapshotModel (acEnv ctx)
  let req = Request Pkcs11_3_2 F_Digest (Just (acSession ctx)) Nothing input
        [RegionBytes "async" (IntentBuffer maxOutputBytes)]
  case planCall defaultRules m req of
    Execute res eff -> pure JobRequest
      { jrSession = acSession ctx
      , jrFunction = JobDigest
      , jrWork = WorkCall res eff
      , jrTicks = ticks
      , jrCapacity = cap
      }
    other -> assertFailure ("digest did not plan execute: " ++ show other)

-- | A kill landing in the submit transfer window cancels the
-- fresh unregistered job and nulls the out-pointer: the parked
-- submitter dies 'ThreadKilled', no live orphan strands, and
-- close drains clean. Pre-fix the fresh job stayed live with no
-- handle, and the handle-only drain missed it.
caseSubmitKillCancelsFresh :: IO ()
caseSubmitKillCancelsFresh = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  jobReq <- planFfiDigest ctx "abc" 32 1
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  done <- newEmptyMVar
  alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    submitterTid <- forkIO $ do
      r <- try (submitTransfer
        (putMVar entered () >> takeMVar proceed) ctx jobReq pHandleOut)
      putMVar done (r :: Either SomeException CULong)
    mEntered <- timeout 10000000 (takeMVar entered)
    case mEntered of
      Nothing -> assertFailure "submitter never entered the transfer window"
      Just () -> pure ()
    (liveMid, _termMid, nextMid) <- tableStats (acTable ctx)
    assertEqual "fresh job started" 1 liveMid
    let freshJid = JobId (nextMid - 1)
    killThread submitterTid
    mDone <- timeout 10000000 (takeMVar done)
    r <- case mDone of
      Nothing -> assertFailure "submitter never reported after kill"
      Just x -> pure x
    case r of
      Left e -> case fromException e of
        Just ThreadKilled -> pure ()
        Just other -> assertFailure ("expected ThreadKilled, got async " ++ show other)
        Nothing -> assertFailure ("expected ThreadKilled, got " ++ show e)
      Right rv -> assertFailure ("kill swallowed, transfer returned " ++ show rv)
    hAfter <- peek pHandleOut
    assertBool "out-pointer nulled" (castStablePtrToPtr hAfter == nullPtr)
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "no handle admitted" nLive
    (liveAfter, termAfter, _nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live orphan" liveAfter
    assertEqual "one canceled tombstone" 1 termAfter
    cout <- cancelJob (acTable ctx) freshJid
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("fresh job not canceled, got " ++ show other)
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains clean" nLive2

-- | A kill landing in the join handoff window cancels the fresh
-- join through the detach wrapper: the committed attachment
-- resolves canceled (durably), the out-pointer nulls, and no
-- live orphan strands. The persistent id is consumed by the
-- cancel — the commit is the point of no return; a kill before
-- it rolls the claim back instead.
caseHandoffKillCancelsJoin :: IO ()
caseHandoffKillCancelsJoin = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  eDet <- detachJob dc (acTable ctx) j0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  eJoin <- joinJob dc (acEnv ctx) (acTable ctx) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = acSession ctx
    , jqCapacity = 32
    }
  jid <- case eJoin of
    JoinOk j -> pure j
    other -> assertFailure ("join failed: " ++ show other)
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  done <- newEmptyMVar
  alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    publisherTid <- forkIO $ do
      r <- try (joinTransfer
        (putMVar entered () >> takeMVar proceed) ctx jid pHandleOut)
      putMVar done (r :: Either SomeException CULong)
    mEntered <- timeout 10000000 (takeMVar entered)
    case mEntered of
      Nothing -> assertFailure "publisher never entered the handoff window"
      Just () -> pure ()
    avMid <- inspectAttachment dc pid
    assertEqual "join committed, unregistered" (Just (AvActive jid)) avMid
    nLiveMid <- asyncLiveHandles ctx
    assertZero "live_handles" "no handle yet" nLiveMid
    killThread publisherTid
    mDone <- timeout 10000000 (takeMVar done)
    r <- case mDone of
      Nothing -> assertFailure "publisher never reported after kill"
      Just x -> pure x
    case r of
      Left e -> case fromException e of
        Just ThreadKilled -> pure ()
        Just other -> assertFailure ("expected ThreadKilled, got async " ++ show other)
        Nothing -> assertFailure ("expected ThreadKilled, got " ++ show e)
      Right rv -> assertFailure ("kill swallowed, handoff returned " ++ show rv)
    hAfter <- peek pHandleOut
    assertBool "out-pointer nulled" (castStablePtrToPtr hAfter == nullPtr)
    cout <- cancelJob (acTable ctx) jid
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("fresh join not canceled, got " ++ show other)
    avAfter <- inspectAttachment dc pid
    assertEqual "attachment canceled" (Just (AvTerminal JobCanceled)) avAfter
    jobs <- loadFfiJobs store
    case [rec | rec <- jobs, jrPersistentId rec == pid] of
      [rec] -> assertEqual "record canceled" JobCanceled (jrState rec)
      other -> assertFailure ("expected one record, got " ++ show other)
  (liveAfter, _termAfter, _nextAfter) <- tableStats (acTable ctx)
  assertZero "live_jobs" "no live orphan" liveAfter
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains clean" nLive2

-- | The join handoff without interruption publishes a live
-- handle: pending with the out-pointer set, resolving to the
-- fresh join, and the attachment stays active until close
-- drains it.
caseHandoffPublishes :: IO ()
caseHandoffPublishes = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  eDet <- detachJob dc (acTable ctx) j0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  eJoin <- joinJob dc (acEnv ctx) (acTable ctx) JoinRequest
    { jqPid = pid
    , jqFunction = JobDigest
    , jqSession = acSession ctx
    , jqCapacity = 32
    }
  jid <- case eJoin of
    JoinOk j -> pure j
    other -> assertFailure ("join failed: " ++ show other)
  h <- alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- joinTransfer (pure ()) ctx jid pHandleOut
    assertEqual "handoff pending" rvPending rv
    hOut <- peek pHandleOut
    assertBool "handle live" (castStablePtrToPtr hOut /= nullPtr)
    pure hOut
  m0 <- resolveJobHandle ctx h
  assertEqual "handle resolves" (Just jid) m0
  av <- inspectAttachment dc pid
  assertEqual "attachment active" (Just (AvActive jid)) av
  nLive <- asyncLiveHandles ctx
  assertEqual "one live handle" 1 nLive
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains the handle" nLive2
  storeClose _store

-- ---------------------------------------------------------------------------
-- Combined acquisition, owned teardown, pre-dereference admission
-- ---------------------------------------------------------------------------

-- | A kill landing after the join acquisition commits but before
-- the handle publishes cancels the fresh join through the detach
-- wrapper: the committed attachment resolves canceled (durably),
-- the out-pointer nulls, and no live orphan strands. The
-- mid-window attachment read proves the kill lands strictly
-- post-commit — before the combined acquisition, a kill there
-- left the committed attachment with no handle.
caseJoinAcquireKillAfterCommit :: IO ()
caseJoinAcquireKillAfterCommit = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  eDet <- detachJob dc (acTable ctx) j0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  done <- newEmptyMVar
  alloca $ \pHandleOut -> alloca $ \pNeedOut -> do
    poke pHandleOut nullJob
    poke pNeedOut 0
    acquirerTid <- forkIO $ do
      r <- try (joinAcquireTransfer
        (putMVar entered () >> takeMVar proceed) dc ctx JoinRequest
          { jqPid = pid
          , jqFunction = JobDigest
          , jqSession = acSession ctx
          , jqCapacity = 32
          } pHandleOut pNeedOut)
      putMVar done (r :: Either SomeException CULong)
    mEntered <- timeout 10000000 (takeMVar entered)
    case mEntered of
      Nothing -> assertFailure "acquirer never entered the handoff window"
      Just () -> pure ()
    jidMid <- do
      avMid <- inspectAttachment dc pid
      case avMid of
        Just (AvActive j) -> pure j
        other -> assertFailure ("join not committed, got " ++ show other)
    nLiveMid <- asyncLiveHandles ctx
    assertZero "live_handles" "no handle yet" nLiveMid
    killThread acquirerTid
    mDone <- timeout 10000000 (takeMVar done)
    r <- case mDone of
      Nothing -> assertFailure "acquirer never reported after kill"
      Just x -> pure x
    case r of
      Left e -> case fromException e of
        Just ThreadKilled -> pure ()
        Just other -> assertFailure ("expected ThreadKilled, got async " ++ show other)
        Nothing -> assertFailure ("expected ThreadKilled, got " ++ show e)
      Right rv -> assertFailure ("kill swallowed, acquire returned " ++ show rv)
    hAfter <- peek pHandleOut
    assertBool "out-pointer nulled" (castStablePtrToPtr hAfter == nullPtr)
    cout <- cancelJob (acTable ctx) jidMid
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("fresh join not canceled, got " ++ show other)
    avAfter <- inspectAttachment dc pid
    assertEqual "attachment canceled" (Just (AvTerminal JobCanceled)) avAfter
    jobs <- loadFfiJobs store
    case [rec | rec <- jobs, jrPersistentId rec == pid] of
      [rec] -> assertEqual "record canceled" JobCanceled (jrState rec)
      other -> assertFailure ("expected one record, got " ++ show other)
  (liveAfter, _termAfter, _nextAfter) <- tableStats (acTable ctx)
  assertZero "live_jobs" "no live orphan" liveAfter
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains clean" nLive2

-- | The combined acquisition without interruption publishes a
-- live handle: pending with the out-pointer set and the need
-- out-pointer untouched, resolving to the fresh join, and the
-- attachment stays active until close drains it.
caseJoinAcquirePublishes :: IO ()
caseJoinAcquirePublishes = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  eDet <- detachJob dc (acTable ctx) j0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  (h, need) <- alloca $ \pHandleOut -> alloca $ \pNeedOut -> do
    poke pHandleOut nullJob
    poke pNeedOut 0
    rv <- joinAcquireTransfer (pure ()) dc ctx JoinRequest
      { jqPid = pid
      , jqFunction = JobDigest
      , jqSession = acSession ctx
      , jqCapacity = 32
      } pHandleOut pNeedOut
    assertEqual "acquire pending" rvPending rv
    hOut <- peek pHandleOut
    assertBool "handle live" (castStablePtrToPtr hOut /= nullPtr)
    needOut <- peek pNeedOut
    pure (hOut, needOut)
  assertEqual "need untouched on success" 0 need
  m0 <- resolveJobHandle ctx h
  jid <- case m0 of
    Just j -> pure j
    Nothing -> assertFailure "handle does not resolve"
  av <- inspectAttachment dc pid
  assertEqual "attachment active" (Just (AvActive jid)) av
  nLive <- asyncLiveHandles ctx
  assertEqual "one live handle" 1 nLive
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains the handle" nLive2

-- | Interrupting the winning slot-close releases its claim
-- instead of stranding retired-but-undrained: the gate reopens
-- with the borrower still counted, the slot stays set, and a
-- retrying close re-claims and completes — draining the live
-- handle, canceling the job, and nulling the slot. A third close
-- is a silent no-op. Before the ownership transfer, the
-- interrupted close left the gate retired with no owner, and the
-- retry skipped teardown while nulling the slot.
caseCloseKillRetryCompletes :: IO ()
caseCloseKillRetryCompletes = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  h <- allocJobHandle ctx j0
  sp <- newStablePtr ctx
  registerCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    admitted <- enterTableUse (acTable ctx)
    assertBool "borrower admitted" admitted
    closedDone <- newEmptyMVar
    closerTid <- forkIO $ do
      r <- try (haskokiAsyncClose pSlot)
      putMVar closedDone (r :: Either SomeException ())
    awaitBlocked closerTid
    killThread closerTid
    mClosed <- timeout 10000000 (takeMVar closedDone)
    case mClosed of
      Nothing -> assertFailure "closer never reported after kill"
      Just (Right ()) -> pure ()
      Just (Left e) -> assertFailure ("closer leaked: " ++ show e)
    gateMid <- inspectTableGate (acTable ctx)
    assertEqual "kill released the claim" (1, False) gateMid
    mid <- peek pSlot
    assertBool "slot still set (teardown incomplete)" (not (isNull mid))
    exitTableUse (acTable ctx)
    haskokiAsyncClose pSlot
    after <- peek pSlot
    assertBool "retry nulled the slot" (isNull after)
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "retired, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "retry drained the handle" nLive
    mStale <- resolveJobHandle ctx h
    assertEqual "handle retired" Nothing mStale
    cout <- cancelJob (acTable ctx) j0
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("job not canceled, got " ++ show other)
    haskokiAsyncClose pSlot
    after3 <- peek pSlot
    assertBool "slot stays nulled" (isNull after3)

-- | Concurrent entry races a slot-close cleanly: four workers
-- admit and release through the export while the owner closes
-- underneath them. Admission runs before any dereference, so no
-- worker can observe a freed pointer — every call either admits
-- (typed handle refusal) or refuses at the retired gate, and the
-- close still completes teardown exactly once. Before
-- pre-dereference admission, a worker between its null check and
-- its dereference could resume after the close freed the
-- pointer.
caseEnterCloseRace :: IO ()
caseEnterCloseRace = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    entered <- newEmptyMVar
    dones <- mapM (const newEmptyMVar) [1 .. 4 :: Int]
    let racer done = forkIO $ do
          r <- try $ do
            putMVar entered ()
            mapM_ (const (probeOnce sp)) [1 .. 200 :: Int]
          putMVar done (r :: Either SomeException ())
    mapM_ racer dones
    mapM_ (const (takeMVar entered)) [1 .. 4 :: Int]
    haskokiAsyncClose pSlot
    outs <- mapM (timeout 10000000 . takeMVar) dones
    case sequence outs of
      Nothing -> assertFailure "racer wedged past its backstop"
      Just rs -> mapM_ checkOk rs
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "retired, no borrowers" (0, True) gateAfter
    after <- peek pSlot
    assertBool "slot nulled" (isNull after)
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "no live handles" nLive
  where
    probeOnce :: StablePtr AsyncCtx -> IO ()
    probeOnce sp = do
      rv <- haskokiAsyncCancel sp nullJob
      if rv == rvBad || rv == rvGeneral
        then pure ()
        else assertFailure ("untyped race outcome: " ++ show rv)
    checkOk :: Either SomeException () -> IO ()
    checkOk (Right ()) = pure ()
    checkOk (Left e) = assertFailure ("racer failed: " ++ show e)

-- | Borrowed-view contract: a borrowed view registers admit-only at
-- creation (the Standard surface assembles one view per session and
-- retires it at session close, outside this module's ownership).
-- Start admits and publishes, cancel retires, and closing through
-- the slot reclaims the slot while tearing nothing down — the view
-- stays registered and admittable. The value-level close claims and
-- drains, and release retires the registration.
caseBorrowedStart :: IO ()
caseBorrowedStart = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerBorrowedCtx sp (acTable ctx)
  let sess = CULong (fromIntegral (unSessionId (acSession ctx)))
  h <- alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- BS.useAsCString "abc" $ \p ->
      haskokiAsyncStart sp sess 2 (castPtr p) 3 32 1 pHandleOut
    assertEqual "borrowed start pending" rvPending rv
    hOut <- peek pHandleOut
    assertBool "handle live" (castStablePtrToPtr hOut /= nullPtr)
    pure hOut
  gate1 <- inspectTableGate (acTable ctx)
  assertEqual "borrower released" (0, False) gate1
  rvCancel <- haskokiAsyncCancel sp h
  assertEqual "borrowed cancel ok" rvOK rvCancel
  alloca $ \pSlot -> do
    poke pSlot sp
    haskokiAsyncClose pSlot
    after <- peek pSlot
    assertBool "slot reclaimed" (isNull after)
  gateStill <- inspectTableGate (acTable ctx)
  assertEqual "slot close tore nothing down" (0, False) gateStill
  rvAdmitted <- haskokiAsyncCancel sp nullJob
  assertEqual "borrowed still admitted past the slot close" rvBad rvAdmitted
  asyncCloseCtx ctx
  nLive <- asyncLiveHandles ctx
  assertZero "live_handles" "drained" nLive
  retireCtx sp
  freeStablePtr sp

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
  registerCtx spOwned (acTable owned)
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

-- | Owned-to-borrowed index reuse: the borrowed view registers over
-- the tombstone its freed index carries and admits — start pending,
-- cancel ok. The retired controls pin while their pointer stays
-- allocated (its index reserved, unreusable by anyone): a retired
-- owned value refuses, and releasing the borrowed view retires it
-- so the stale borrowed value refuses too.
caseOwnedToBorrowedReuse :: IO ()
caseOwnedToBorrowedReuse = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  -- Retired-owned control: retire while allocated, assert, free.
  -- The live index cannot be reused underneath the assertion.
  owned <- mkFfiGen dc
  spOwned <- newStablePtr owned
  registerCtx spOwned (acTable owned)
  retireCtx spOwned
  rvStale <- haskokiAsyncCancel spOwned nullJob
  assertEqual "retired owned refuses" rvGeneral rvStale
  freeStablePtr spOwned
  asyncCloseCtx owned
  -- Reuse flow: a slot-closed owned index hands to a borrowed view.
  borrowed <- mkFfiGen dc
  spBorrowed <- reuseBorrowed dc borrowed 100
  let sess = CULong (fromIntegral (unSessionId (acSession borrowed)))
  h <- alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- BS.useAsCString "abc" $ \p ->
      haskokiAsyncStart spBorrowed sess 2 (castPtr p) 3 32 1 pHandleOut
    assertEqual "borrowed start on the reused index admits" rvPending rv
    hOut <- peek pHandleOut
    assertBool "handle live" (castStablePtrToPtr hOut /= nullPtr)
    pure hOut
  rvCancel <- haskokiAsyncCancel spBorrowed h
  assertEqual "borrowed cancel ok" rvOK rvCancel
  -- Retired-borrowed control: retire while allocated, assert, free.
  retireCtx spBorrowed
  rvStaleBorrowed <- haskokiAsyncCancel spBorrowed nullJob
  assertEqual "retired borrowed refuses" rvGeneral rvStaleBorrowed
  freeStablePtr spBorrowed
  asyncCloseCtx borrowed
  awaitNoPendingReclaims

-- | Deterministic pre-lookup barrier: a caller parks after its
-- null check and before its registry lookup while the owner
-- closes the context completely underneath it. On release the
-- caller meets the tombstone and refuses typed — it never
-- dereferences the freed pointer. Before tombstones, a caller
-- resuming after the close fell through to a dereference of the
-- freed pointer. The hook is scoped to this pointer and reset
-- under 'finally', so parallel tests never observe it.
caseEnterBarrierCloseTombstones :: IO ()
caseEnterBarrierCloseTombstones = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    entered <- newEmptyMVar
    proceed <- newEmptyMVar
    done <- newEmptyMVar
    setEnterTestHook sp (Just (putMVar entered () >> takeMVar proceed))
    (do
      _ <- forkIO $ do
        r <- try (haskokiAsyncCancel sp nullJob)
        putMVar done (r :: Either SomeException CULong)
      mEntered <- timeout 10000000 (takeMVar entered)
      case mEntered of
        Nothing -> assertFailure "caller never parked pre-lookup"
        Just () -> pure ()
      haskokiAsyncClose pSlot
      after <- peek pSlot
      assertBool "close completed under the parked caller" (isNull after)
      gateMid <- inspectTableGate (acTable ctx)
      assertEqual "retired, no borrowers" (0, True) gateMid
      putMVar proceed ()
      mDone <- timeout 10000000 (takeMVar done)
      r <- case mDone of
        Nothing -> assertFailure "caller never reported after release"
        Just x -> pure x
      case r of
        Right rv -> assertEqual "parked caller refused by tombstone" rvGeneral rv
        Left e -> assertFailure ("caller failed: " ++ show e)
      ) `finally` setEnterTestHook sp Nothing

-- | Retiring clears the entry hook in the same step as the
-- tombstone: arm a hook, retire, then re-register the same
-- pointer live and drive a call through it — the stale hook must
-- not fire (its signal would surface in the rendezvous cell
-- below). Registration preserves a live hook by design, so only
-- the retire-time clear stands between the predecessor's hook
-- and the new owner's calls.
caseRetireClearsHook :: IO ()
caseRetireClearsHook = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerCtx sp (acTable ctx)
  fired <- newEmptyMVar
  setEnterTestHook sp (Just (putMVar fired ()))
  retireCtx sp
  registerCtx sp (acTable ctx)
  rv <- haskokiAsyncCancel sp nullJob
  assertEqual "re-registered pointer admits" rvBad rv
  mFired <- tryTakeMVar fired
  case mFired of
    Nothing -> pure ()
    Just () -> assertFailure "stale entry hook fired after retire"
  retireCtx sp
  freeStablePtr sp
  awaitNoPendingReclaims

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

-- | Registry roots reclaim across churn: repeated owned
-- register/retire cycles, borrowed register/retire cycles, and
-- hook replacement/clear cycles leave no reclamation backlog once
-- joined — every displaced root frees through its retire or its
-- last release instead of standing retained.
caseRegistryRootsReclaim :: IO ()
caseRegistryRootsReclaim = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  mapM_ (\_ -> do
    sp <- newStablePtr ctx
    registerCtx sp (acTable ctx)
    retireCtx sp
    freeStablePtr sp) [1 .. 50 :: Int]
  mapM_ (\_ -> do
    sp <- newStablePtr ctx
    registerBorrowedCtx sp (acTable ctx)
    retireCtx sp
    freeStablePtr sp) [1 .. 50 :: Int]
  sp <- newStablePtr ctx
  registerCtx sp (acTable ctx)
  mapM_ (\_ -> do
    setEnterTestHook sp (Just (pure ()))
    setEnterTestHook sp Nothing) [1 .. 50 :: Int]
  retireCtx sp
  freeStablePtr sp
  awaitNoPendingReclaims
  awaitReclaimBalanced

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

-- | Stacked displacements preserve every root: hold one borrow,
-- retire, reuse the same key, and retire again before releasing —
-- both displaced roots queue instead of the second stranding the
-- first. The held borrow pins at least two queued roots; the
-- release drains both, and the accounting balances.
caseReclaimOverlappingReuse :: IO ()
caseReclaimOverlappingReuse = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerCtx sp (acTable ctx)
  ctxAcquireBorrowTest sp
  retireCtx sp
  registerCtx sp (acTable ctx)
  retireCtx sp
  p <- ctxPendingReclaims
  assertBool ("two stacked roots queued, saw " ++ show p) (p >= 2)
  ctxReleaseBorrowTest sp
  freeStablePtr sp
  awaitNoPendingReclaims
  awaitReclaimBalanced

-- | A kill landing inside the acquisition — after the fresh job
-- starts but before its claim commits — retires the fresh
-- unregistered job, rolls the claim back, and nulls the
-- out-pointer: the parked acquirer dies 'ThreadKilled', the
-- durable job stands untouched and joinable, and a retry
-- acquires cleanly. The acquisition runs masked end to end, so
-- the pure commit boundary itself admits no kill; this window is
-- the closest injectable point on the acquisition side of it.
caseJoinAcquireKillDuringAcquire :: IO ()
caseJoinAcquireKillDuringAcquire = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  eDet <- detachJob dc (acTable ctx) j0 JobDigest
  pid <- case eDet of
    DetachOk p -> pure p
    other -> assertFailure ("detach failed: " ++ show other)
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  done <- newEmptyMVar
  setJoinTestHook dc (putMVar entered () >> takeMVar proceed)
  alloca $ \pHandleOut -> alloca $ \pNeedOut -> do
    poke pHandleOut nullJob
    poke pNeedOut 0
    acquirerTid <- forkIO $ do
      r <- try (joinAcquireTransfer (pure ()) dc ctx JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = acSession ctx
        , jqCapacity = 32
        } pHandleOut pNeedOut)
      putMVar done (r :: Either SomeException CULong)
    mEntered <- timeout 10000000 (takeMVar entered)
    case mEntered of
      Nothing -> assertFailure "acquirer never entered the acquisition window"
      Just () -> pure ()
    (liveMid, _termMid, nextMid) <- tableStats (acTable ctx)
    assertEqual "fresh job started" 1 liveMid
    let freshJid = JobId (nextMid - 1)
    avMid <- inspectAttachment dc pid
    assertEqual "claim uncommitted" (Just AvIdle) avMid
    nLiveMid <- asyncLiveHandles ctx
    assertZero "live_handles" "no handle yet" nLiveMid
    killThread acquirerTid
    mDone <- timeout 10000000 (takeMVar done)
    r <- case mDone of
      Nothing -> assertFailure "acquirer never reported after kill"
      Just x -> pure x
    case r of
      Left e -> case fromException e of
        Just ThreadKilled -> pure ()
        Just other -> assertFailure ("expected ThreadKilled, got async " ++ show other)
        Nothing -> assertFailure ("expected ThreadKilled, got " ++ show e)
      Right rv -> assertFailure ("kill swallowed, acquire returned " ++ show rv)
    hAfter <- peek pHandleOut
    assertBool "out-pointer nulled" (castStablePtrToPtr hAfter == nullPtr)
    needAfter <- peek pNeedOut
    assertEqual "need untouched" 0 needAfter
    avAfter <- inspectAttachment dc pid
    assertEqual "claim rolled back" (Just AvIdle) avAfter
    (liveAfter, _termAfter, _nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live orphan" liveAfter
    cout <- cancelJob (acTable ctx) freshJid
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("fresh job not canceled, got " ++ show other)
    jobs <- loadFfiJobs store
    case [rec | rec <- jobs, jrPersistentId rec == pid] of
      [rec] -> assertEqual "record untouched" JobQueued (jrState rec)
      other -> assertFailure ("expected one record, got " ++ show other)
    -- The rolled-back claim frees the id: a retry acquires cleanly.
    setJoinTestHook dc (pure ())
    rvRetry <- joinAcquireTransfer (pure ()) dc ctx JoinRequest
      { jqPid = pid
      , jqFunction = JobDigest
      , jqSession = acSession ctx
      , jqCapacity = 32
      } pHandleOut pNeedOut
    assertEqual "retry pending" rvPending rvRetry
    hRetry <- peek pHandleOut
    assertBool "retry handle live" (castStablePtrToPtr hRetry /= nullPtr)
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains clean" nLive2

-- ---------------------------------------------------------------------------
-- Standalone ownership: a kill at each acquisition step
-- ---------------------------------------------------------------------------

-- | Balance counters over one acquisition record (opens, closes,
-- pointer allocs and frees, registrations and retirements). Closes,
-- frees and retirements count only once they return.
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

-- | Counting wrapper over the production acquisition steps, with a
-- private residue owner.
countingAcquisition :: IO (AsyncAcquisition, IO AcqCounts)
countingAcquisition = countingAcquisitionOver asyncAcquisition

-- | Counting wrapper over the given steps, with a private residue
-- owner (parallel cases never share one).
--
-- Keep in sync with the copy in tests/engine/FfiAcquireSpec.hs: suites
-- share only tests/support, so the helper is duplicated.
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
              B.EngineOk _ -> bump (\c -> c { acBackendOpens = acBackendOpens c + 1 })
              B.EngineFail _ -> pure ()
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

-- | Ten-second backstop on every wait.
within10s :: String -> IO a -> IO a
within10s what act = do
  r <- timeout 10000000 act
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

caseBoxKilledAfterStoreOpen :: IO ()
caseBoxKilledAfterStoreOpen = boxKilledMemory (parkAt AfterStoreOpen)

caseBoxKilledAfterTokenSetup :: IO ()
caseBoxKilledAfterTokenSetup = boxKilledMemory (parkAt AfterTokenSetup)

caseBoxKilledDuringTokenLoad :: IO ()
caseBoxKilledDuringTokenLoad = boxKilledMemory parkInTokenLoad

caseSqliteBoxKilledAfterTokenSetup :: IO ()
caseSqliteBoxKilledAfterTokenSetup = withPrivateDir $ \dir -> do
  let path = dir </> "store.sqlite"
  (counting, readCounts) <- countingAcquisition
  (acq, opened) <- trackOpened counting
  (do withCString path $ \cPath ->
        killVictimAt (parkAt AfterTokenSetup) acq (\a -> openStoreBoxWith a cPath)
      c <- readCounts
      r <- openSQLiteStore path
      (refused, why) <- case r of
        Right st -> storeClose st >> pure (0 :: Int, "reopened")
        Left e -> pure (1, show e)
      assertBalanced ("sqlite reopen: " ++ why) c
      assertZero "store_reopen_refused" ("sqlite reopen: " ++ why) refused)
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

caseCtxKilledAfterBackendOpen :: IO ()
caseCtxKilledAfterBackendOpen = ctxKilledGated AfterBackendOpen

caseCtxKilledAfterSessionOpen :: IO ()
caseCtxKilledAfterSessionOpen = ctxKilledGated AfterSessionOpen

caseCtxKilledAfterCtxAlloc :: IO ()
caseCtxKilledAfterCtxAlloc = ctxKilledGated AfterCtxAlloc

-- | A store-bound open killed after its reload holds nothing of its
-- own: the box stays usable for the next open, and closing both
-- balances every counter.
caseStoreBoundKilledAfterReload :: IO ()
caseStoreBoundKilledAfterReload = do
  world <- newMemoryWorld
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do eBox <- openStoreBoxWith acq nullPtr
      box <- case eBox of
        Right b -> pure b
        Left _ -> assertFailure "store box open failed"
      killVictimAt (parkAt AfterStoreReload) acq
        (\a -> openAsyncCtxOnWith a defaultConfig box)
      eCtx <- openAsyncCtxOnWith acq defaultConfig box
      ctx <- case eCtx of
        Right sp -> pure sp
        Left _ -> assertFailure "open on the same box failed"
      alloca $ \pCtx -> do
        poke pCtx ctx
        closeCtxSlotWith acq pCtx
        after <- peek pCtx
        assertBool "context slot nulled" (isNull after)
      alloca $ \pBox -> do
        poke pBox box
        closeStoreBoxSlotWith acq pBox
        after <- peek pBox
        assertBool "box slot nulled" (isNull after)
      c <- readCounts
      (refused, why) <- memoryReopenRefused world
      assertBalanced ("memory world reopen: " ++ why) c
      assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | The C export cannot hand a residue back: a synchronous primary
-- whose two cleanup closes fail reports NULL and queues the Store on
-- the process owner (the C-owned cell), which keeps its lock. The
-- next open through the real export retries the close first: the
-- count drains to zero and the world reopens.
caseExportResidueRecoveredByNextOpen :: IO ()
caseExportResidueRecoveredByNextOpen = do
  world <- newMemoryWorld
  armed <- newIORef True
  (counting, readCounts) <- countingAcquisitionOver asyncAcquisition
    { aaOpenStore = \_ -> do
        r <- openMemoryStore world
        pure $ case r of
          -- Every close fails while armed, so a concurrent drainer in
          -- this process cannot close the residue before the asserts.
          Right st -> Right st
            { storeClose = do
                on <- readIORef armed
                if on
                  then throwIO (StoreIO "close refused while armed")
                  else storeClose st
            }
          Left _ -> Left ()
    , aaStep = \s ->
        if s == AfterTokenSetup then throwIO (userError "primary") else pure ()
    }
  let processOwner = aaResidue asyncAcquisition
      acq = counting { aaResidue = processOwner }
  sp <- haskokiAsyncStoreOpenWith acq nullPtr
  queued <- residueCount processOwner
  (held, heldWhy) <- memoryReopenRefused world
  writeIORef armed False
  box <- haskokiAsyncStoreOpen nullPtr
  alloca $ \pBox -> do
    poke pBox box
    haskokiAsyncStoreClose pBox
  left <- awaitResidueDrained processOwner
  (refused, why) <- memoryReopenRefused world
  c <- readCounts
  let note = " (" ++ show c ++ "; queued=" ++ show queued ++ ", held: " ++ heldWhy ++ ")"
  assertBool ("export reports NULL" ++ note) (isNull sp)
  assertEqual ("residue queued on the process owner" ++ note) 1 queued
  assertEqual ("the residue keeps its lock" ++ note) 1 held
  assertBool ("the next open through the real export" ++ note) (not (isNull box))
  assertZero "residue_count" ("residue left after the next open" ++ note) left
  assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused
  assertZero "box_allocs_minus_frees" ("box allocs minus frees" ++ note)
    (acBoxAllocs c - acBoxFrees c)
  assertZero "registrations_minus_retirements"
    ("registrations minus retirements" ++ note)
    (acRegistrations c - acRetirements c)

-- | Poll the residue count down to zero. A concurrent standalone open
-- or close elsewhere in this process may hold the entry mid-retry;
-- each further poll runs one more open and close through the real
-- exports, which retries it again. Gives up after about two seconds.
awaitResidueDrained :: ResidueOwner -> IO Int
awaitResidueDrained owner = go (0 :: Int)
  where
    go n = do
      k <- residueCount owner
      if k == 0 || n >= 400
        then pure k
        else do
          threadDelay 5000
          box <- haskokiAsyncStoreOpen nullPtr
          alloca $ \pBox -> do
            poke pBox box
            haskokiAsyncStoreClose pBox
          go (n + 1)
