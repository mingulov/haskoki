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
module FfiAsyncSpec (spec, commitPathWarmup) where

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
  , bracket_
  , finally
  , fromException
  , mask_
  , throwIO
  , try
  )
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map as Map
import Data.IORef (IORef, atomicModifyIORef', modifyIORef', newIORef, readIORef, writeIORef)
import qualified Data.Set as Set
import Data.Word (Word64)
import Foreign.C.String (withCString)
import Foreign.C.Types (CInt (..), CLong (..), CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullFunPtr, nullPtr, wordPtrToPtr)
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
import Test.Tasty (TestTree, inOrderTestGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import qualified Haskoki.Engine.Backend as B
import OwnershipCounters (assertZero, counted)
import StormBudget (stormScaleBudget)
import Haskoki.Engine.OpenSSL4
  ( OpenSSL4
  , TestGate
  , digestOneShotGated
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
  , asyncCloseCtx
  , asyncLiveHandles
  , ctxAcquireBorrowTest
  , ctxInspectEntryTest
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
  , registerFixtureCtx
  , residueAnomalies
  , residueCount
  , resolveJobHandle
  , retireCtx
  , rvOf
  , setEnterTestHook
  , StoreBox (..)
  , submitTransfer
  )
import Haskoki.FFI.Standard
  ( SessionOpenPoint (..)
  , StdInstance (..)
  , haskokiStdClose
  , haskokiStdCloseSession
  , haskokiStdOpenSession
  , haskokiStdOpenSessionWithNotifyWithKey
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
  , CancelOutcome (..)
  , Closer (..)
  , CompleteOutcome (..)
  , Completion (..)
  , Delivery (..)
  , JobFunction (..)
  , JobRequest (..)
  , PollOutcome (..)
  , TableClose (..)
  , Teardown (..)
  , TerminalState (..)
  , asyncTableId
  , asyncTableSalt
  , beginTableTeardown
  , cancelJob
  , claimTableClose
  , enableAsyncSession
  , enterTableUse
  , exitTableUse
  , finishTableClose
  , inspectTableClose
  , inspectTableGate
  , pollJob
  , releaseTableClose
  , startJob
  , tableStats
  , tryNewAsyncTable
  , withDetachLease
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
  , retireLiveTableFor
  , setJoinTestHook
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
  , FaultPoint (..)
  , JobExecState (..)
  , JobRecord (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , TokenRecord (..)
  , defaultLimits
  , emptyDelta
  , noFaults
  , scriptedFaults
  )
import Haskoki.Runtime.Storage.Memory
  ( MemoryWorld
  , newMemoryWorld
  , openMemoryStore
  , openMemoryStoreWith
  )
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Transition (finishEffect, planCall)
import Haskoki.Types
  ( EngineResourceId (..)
  , Generation (..)
  , JobId (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (CKR_ARGUMENTS_BAD, CKR_GENERAL_ERROR, CKR_OK)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

spec :: TestTree
-- Every case in this group runs alone, one at a time, under tasty's
-- 'inOrderTestGroup' (no lock value: the scheduler orders the
-- cases, so no worker idles holding one and wait time never counts
-- against a case's timeout; the dependency-group variant would
-- shield earlier cases from '-p' filtering and break the
-- ownership-matrix patterns, so this group uses the variant whose
-- filtering matches 'testGroup'). The RTS reuses freed 'StablePtr'
-- values, so
-- two parallel cases could observe the same pointer bits: a caller
-- parked before its lookup admitted to a new owner that registered
-- those bits live (wrong refusal code), a borrower census counting
-- a foreign caller, and fixture teardown that retires and frees
-- without the close-path drain freeing under another case's
-- admitted caller (use-after-free). Sequencing also removes the
-- concurrent first-evaluation races that coincided with the
-- commit-path BlackHole hangs. Two of those shapes were product
-- defects, fixed alongside: borrowed-view closes now defer their
-- free behind the entry's borrow count, and the provider pins one
-- RTS capability. The 'counted' wrapper on each case is unchanged
-- (child thread, labels, ownership counters). Sequencing covers
-- this group only: keys stay safe across groups because each case
-- holds its keys allocated through its assertions
-- (pin-while-allocated) and no other group parks callers or holds
-- test borrows. Do not parallelize this group without re-proving
-- every tombstone, census, reclaim and hang assertion under
-- parallel execution.
spec = inOrderTestGroup "FFI acquisition"
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
  , testCase "submit under a key function refuses without allocating" (counted "m3-ffi-acquisition" "submit-under-a-key-function-refuses-without-allocating" caseSubmitKeyFunctionRefuses)
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
  , testCase "session close defers the borrowed view free" (counted "m3-ffi-acquisition" "session-close-defers-the-borrowed-view-free" (caseSessionCloseDefersViewFree))
  , testCase "instance close defers the borrowed view free" (counted "m3-ffi-acquisition" "instance-close-defers-the-borrowed-view-free" (caseInstanceCloseDefersViewFree))
  , testCase "open rollback defers the borrowed view free" (counted "m3-ffi-acquisition" "open-rollback-defers-the-borrowed-view-free" (caseOpenRollbackDefersViewFree))
  , inOrderTestGroup "standalone ownership"
      [ testCase "store box killed after store open closes the store" (counted "m3-standalone-ownership" "store-box-killed-after-store-open-closes-the-store" (caseBoxKilledAfterStoreOpen))
      , testCase "store box killed after token setup closes the store" (counted "m3-standalone-ownership" "store-box-killed-after-token-setup-closes-the-store" (caseBoxKilledAfterTokenSetup))
      , testCase "store box killed during token load closes the store" (counted "m3-standalone-ownership" "store-box-killed-during-token-load-closes-the-store" (caseBoxKilledDuringTokenLoad))
      , testCase "sqlite store box killed after token setup releases its lock" (counted "m3-standalone-ownership" "sqlite-store-box-killed-after-token-setup-releases-its-lock" (caseSqliteBoxKilledAfterTokenSetup))
      , testCase "context killed after backend open closes the backend" (counted "m3-standalone-ownership" "context-killed-after-backend-open-closes-the-backend" (caseCtxKilledAfterBackendOpen))
      , testCase "context killed after session open closes the backend" (counted "m3-standalone-ownership" "context-killed-after-session-open-closes-the-backend" (caseCtxKilledAfterSessionOpen))
      , testCase "context killed after pointer allocation frees it unregistered" (counted "m3-standalone-ownership" "context-killed-after-pointer-allocation-frees-it-unregistered" (caseCtxKilledAfterCtxAlloc))
      , testCase "store-bound context killed after reload leaves the box usable" (counted "m3-standalone-ownership" "store-bound-context-killed-after-reload-leaves-the-box-usable" (caseStoreBoundKilledAfterReload))
      , testCase "export store open residue is recovered by the next open" (counted "m3-standalone-ownership" "export-store-open-residue-is-recovered-by-the-next-open" (caseExportResidueRecoveredByNextOpen))
      , testCase "closer killed in the store wait stays closing and retries" (counted "m3-standalone-ownership" "closer-killed-in-the-store-wait-stays-closing-and-retries" (caseCloserKilledInStoreWait))
      , testCase "closer killed in a job lease wait cancels once on retry" (counted "m3-standalone-ownership" "closer-killed-in-a-job-lease-wait-cancels-once-on-retry" (caseCloserKilledInLeaseWait))
      , testCase "closer killed in the backend gate wait frees the env once on retry" (counted "m3-standalone-ownership" "closer-killed-in-the-backend-gate-wait-frees-the-env-once-on-retry" (caseCloserKilledInBackendGateWait))
      , testCase "store failure in retirement still closes and keeps the record joinable" (counted "m3-standalone-ownership" "store-failure-in-retirement-still-closes-and-keeps-the-record-joinable" (caseStoreFailureInRetirement))
      , testCase "table close phases move only forward after teardown starts" (counted "m3-standalone-ownership" "table-close-phases-move-only-forward-after-teardown-starts" (caseTableClosePhasesMoveOnlyForward))
      , testCase "unknown registry key refuses without admission" (counted "m3-standalone-ownership" "unknown-registry-key-refuses-without-admission" (caseUnknownKeyRefusesWithoutAdmission))
      , testCase "hook-only registry key refuses after its hook" (counted "m3-standalone-ownership" "hook-only-registry-key-refuses-after-its-hook" (caseHookOnlyRefusesAfterHook))
      , testCase "close of an unknown key nulls the slot only" (counted "m3-standalone-ownership" "close-of-an-unknown-key-nulls-the-slot-only" (caseCloseUnknownNullsSlotOnly))
      , testCase "close with a throwing retire resumes on retry" (counted "m3-standalone-ownership" "close-with-a-throwing-retire-resumes-on-retry" (caseCloseTailThrowResumesOnRetry))
      , testCase "close with a throwing free resumes on retry" (counted "m3-standalone-ownership" "close-with-a-throwing-free-resumes-on-retry" (caseCloseTailFreeThrowResumesOnRetry))
      , testCase "store throw in retirement still closes and keeps the record joinable" (counted "m3-standalone-ownership" "store-throw-in-retirement-still-closes-and-keeps-the-record-joinable" (caseStoreThrowInRetirementStillCloses))
      , testCase "commit throw reports only the uncommitted rows" (counted "m3-standalone-ownership" "commit-throw-reports-only-the-uncommitted-rows" (caseCommitThrowReportsOnlyUncommitted))
      , testCase "value-level close killed in a lease wait resumes" (counted "m3-standalone-ownership" "value-level-close-killed-in-a-lease-wait-resumes" (caseValueCloseKilledInLeaseWaitResumes))
      , testCase "block wait rejects other block reasons" (counted "m3-standalone-ownership" "block-wait-rejects-other-block-reasons" (caseBlockWaitRejectsOtherReasons))
      , testCase "null slot and null pointer closes are silent" (counted "m3-standalone-ownership" "null-slot-and-null-pointer-closes-are-silent" (caseNullClosesAreSilent))
      , testCase "repeated context close frees and retires once" (counted "m3-standalone-ownership" "repeated-context-close-frees-and-retires-once" (caseRepeatedCloseFreesOnce))
      , testCase "failed store close keeps the box slot until a retry succeeds" (counted "m3-standalone-ownership" "failed-store-close-keeps-the-box-slot-until-a-retry-succeeds" (caseFailedStoreCloseKeepsBoxSlot))
      , testCase "store box close killed in the lock wait keeps the box" (counted "m3-standalone-ownership" "store-box-close-killed-in-the-lock-wait-keeps-the-box" (caseBoxCloseKilledInLockWaitKeepsBox))
      , testCase "box close step parks before the transfer" (counted "m3-standalone-ownership" "box-close-step-parks-before-the-transfer" (caseBoxCloseStepParksBeforeTransfer))
      , testCase "context close step parks before the transfer" (counted "m3-standalone-ownership" "context-close-step-parks-before-the-transfer" (caseCtxCloseStepParksBeforeTransfer))
      , testCase "interrupted residue retry puts back every entry" (counted "m3-standalone-ownership" "interrupted-residue-retry-puts-back-every-entry" (caseResidueRetryInterruptedPutsBack))
      , testCase "standalone churn leaves no orphan roots or native envs" (counted "m3-standalone-ownership" "standalone-churn-leaves-no-orphan-roots-or-native-envs" (caseStandaloneChurnLeavesNoOrphans))
      , testCase "joined cleanup lets the same store reopen" (counted "m3-standalone-ownership" "joined-cleanup-lets-the-same-store-reopen" (caseJoinedCleanupReopensSameStore))
      , testCase "joined cleanup lets the same sqlite store reopen" (counted "m3-standalone-ownership" "joined-cleanup-lets-the-same-sqlite-store-reopen" (caseJoinedCleanupReopensSameSqliteStore))
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
-- | GHC #27272 warm-up MITIGATION (not a fix), run once by the
-- model suite's 'Main' before tasty forks any worker: one
-- seat-token commit, single-threaded, so the commit-path constants
-- are values before any two workers can first-evaluate them
-- together (the orphaned-black-hole hang of the known upstream
-- runtime bug GHC #27272). This lowers the hang rate; it does not
-- fix the upstream bug.
commitPathWarmup :: IO ()
commitPathWarmup = mkFfiStore >> pure ()

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
  registerFixtureCtx sp (acTable ctx)
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
    awaitBlocked BlockedOnSTM closerTid
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
  registerFixtureCtx sp (acTable ctx)
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

caseSubmitKeyFunctionRefuses :: IO ()
caseSubmitKeyFunctionRefuses = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  digestReq <- planFfiDigest ctx "abc" 32 1
  -- Rebuild (not record-update): 'jrFunction' also belongs to
  -- 'JobRecord', so an update is ambiguous here.
  let badReq = case digestReq of
        JobRequest sid _func work ticks cap ->
          JobRequest sid JobGenKey work ticks cap
  before <- tableStats (acTable ctx)
  alloca $ \pHandleOut -> do
    poke pHandleOut nullJob
    rv <- submitTransfer (pure ()) ctx badReq pHandleOut
    assertEqual "key-function submit refuses"
      (rvOf CKR_ARGUMENTS_BAD) rv
    hAfter <- peek pHandleOut
    assertBool "no handle on refusal"
      (castStablePtrToPtr hAfter == nullPtr)
  after <- tableStats (acTable ctx)
  assertEqual "refusal consumes nothing" before after
  nLive <- asyncLiveHandles ctx
  assertZero "live_handles" "no handle admitted" nLive
  asyncCloseCtx ctx
  nLive2 <- asyncLiveHandles ctx
  assertZero "live_handles" "close drains clean" nLive2
  (liveEnd, _, _) <- tableStats (acTable ctx)
  assertZero "live_jobs" "no live orphan" liveEnd

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
  registerFixtureCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    admitted <- enterTableUse (acTable ctx)
    assertBool "borrower admitted" admitted
    closedDone <- newEmptyMVar
    closerTid <- forkIO $ do
      r <- try (haskokiAsyncClose pSlot)
      putMVar closedDone (r :: Either SomeException ())
    awaitBlocked BlockedOnSTM closerTid
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
  registerFixtureCtx sp (acTable ctx)
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
  registerFixtureCtx spOwned (acTable owned)
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
-- under 'finally', so parallel tests never observe it. The close
-- runs over an acquisition that defers its pointer free into
-- 'freedRef': the value stays allocated (hence unreusable by any
-- other group) until the assertion completes, then frees whatever
-- the outcome — the pin-while-allocated shape of
-- 'caseOwnedToBorrowedReuse'.
caseEnterBarrierCloseTombstones :: IO ()
caseEnterBarrierCloseTombstones = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    entered <- newEmptyMVar
    proceed <- newEmptyMVar
    done <- newEmptyMVar
    freedRef <- newIORef []
    let acq = asyncAcquisition { aaFreeCtxPtr = \fp -> modifyIORef' freedRef (fp :) }
    setEnterTestHook sp (Just (putMVar entered () >> takeMVar proceed))
    (do
      _ <- forkIO $ do
        r <- try (haskokiAsyncCancel sp nullJob)
        putMVar done (r :: Either SomeException CULong)
      mEntered <- timeout 10000000 (takeMVar entered)
      case mEntered of
        Nothing -> assertFailure "caller never parked pre-lookup"
        Just () -> pure ()
      closeCtxSlotWith acq pSlot
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
      ) `finally` (readIORef freedRef >>= mapM_ freeStablePtr >> setEnterTestHook sp Nothing)

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
  registerFixtureCtx sp (acTable ctx)
  fired <- newEmptyMVar
  setEnterTestHook sp (Just (putMVar fired ()))
  retireCtx sp
  registerFixtureCtx sp (acTable ctx)
  rv <- haskokiAsyncCancel sp nullJob
  assertEqual "re-registered pointer admits" rvBad rv
  mFired <- tryTakeMVar fired
  case mFired of
    Nothing -> pure ()
    Just () -> assertFailure "stale entry hook fired after retire"
  retireCtx sp
  freeStablePtr sp
  awaitNoPendingReclaims

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

-- | Session close retires the borrowed view but defers its pointer
-- free behind the entry's borrow count: with a borrow held across
-- the close, the retired entry keeps both roots (the displaced
-- table and the view pointer itself) queued until the release.
caseSessionCloseDefersViewFree :: IO ()
caseSessionCloseDefersViewFree =
  bracket openStdSessionView (\(inst, _, _) -> haskokiStdClose inst) $
    \(inst, h, view) -> do
      bracket_ (ctxAcquireBorrowTest view) (ctxReleaseBorrowTest view) $ do
        setup <- ctxInspectEntryTest view
        assertEqual "view live under the held borrow" (2, 1, 0) setup
        haskokiStdCloseSession inst h
          >>= assertEqual "session closed" (stdRvOf CKR_OK)
        mid <- ctxInspectEntryTest view
        assertEqual "retired view keeps its roots queued under the borrow"
          (3, 1, 2) mid
      awaitNoPendingReclaims

-- | Instance close releases every session view the same way: the
-- retired entry keeps both roots queued while a borrow stands.
caseInstanceCloseDefersViewFree :: IO ()
caseInstanceCloseDefersViewFree = do
  (inst, _, view) <- openStdSessionView
  bracket_ (ctxAcquireBorrowTest view) (ctxReleaseBorrowTest view) $ do
    setup <- ctxInspectEntryTest view
    assertEqual "view live under the held borrow" (2, 1, 0) setup
    haskokiStdClose inst
    mid <- ctxInspectEntryTest view
    assertEqual "retired view keeps its roots queued under the borrow"
      (3, 1, 2) mid
  awaitNoPendingReclaims

-- | The open-session rollback releases its never-installed view the
-- same way: the seam observer holds a borrow on the view key, the
-- injected fault runs the rollback, and the retired entry keeps
-- both roots queued until the release.
caseOpenRollbackDefersViewFree :: IO ()
caseOpenRollbackDefersViewFree = do
  inst <- openStdInstance defaultConfig
  assertBool "instance opened" (castStablePtrToPtr inst /= nullPtr)
  keyRef <- newIORef Nothing
  let observe BeforeBorrowedViewInstall (Just view) = do
        writeIORef keyRef (Just view)
        ctxAcquireBorrowTest view
        ioError (userError "injected rollback")
      observe _ _ = pure ()
  flip finally (haskokiStdClose inst) $ alloca $ \pSession -> do
    haskokiStdOpenSessionWithNotifyWithKey observe inst 0 0 0 nullPtr nullFunPtr pSession
      >>= assertEqual "injected open fault fenced" (stdRvOf CKR_GENERAL_ERROR)
    mView <- readIORef keyRef
    view <- case mView of
      Nothing -> assertFailure "seam reached the view-install point"
      Just v -> pure v
    (do
      mid <- ctxInspectEntryTest view
      assertEqual "rolled-back view keeps its roots queued under the borrow"
        (3, 1, 2) mid
      ) `finally` ctxReleaseBorrowTest view
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
    registerFixtureCtx sp (acTable ctx)
    retireCtx sp
    freeStablePtr sp) [1 .. 50 :: Int]
  mapM_ (\_ -> do
    sp <- newStablePtr ctx
    registerBorrowedCtx sp (acTable ctx)
    retireCtx sp
    freeStablePtr sp) [1 .. 50 :: Int]
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
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
  registerFixtureCtx sp (acTable ctx)
  ctxAcquireBorrowTest sp
  retireCtx sp
  registerFixtureCtx sp (acTable ctx)
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
--
-- Keep in sync with the copy in tests/engine/FfiAcquireSpec.hs.
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
  -- Re-enable the close on every exit, so a failure here never
  -- leaves an unclosable Store in the process cell.
  (sp, queued, held, heldWhy) <-
    (do sp <- haskokiAsyncStoreOpenWith acq nullPtr
        queued <- residueCount processOwner
        (held, heldWhy) <- memoryReopenRefused world
        pure (sp, queued, held, heldWhy))
      `finally` writeIORef armed False
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
  anomalies <- residueAnomalies
  assertZero "residue_anomalies" "process residue cell protocol slips" anomalies

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

-- ---------------------------------------------------------------------------
-- Standalone ownership: a closer killed past the borrower drain
-- ---------------------------------------------------------------------------
--
-- Common shape: a registered context with zero borrowers, a sibling
-- holding one resource the drain needs, and a forked export close
-- that parks in the resulting wait. A second close while the first
-- is parked returns at once with the gate unchanged. Main kills the
-- first closer and joins it under the storm-scale budget; afterwards the gate
-- still reports closing with no borrowers, a call through the slot
-- refuses, and releasing the sibling plus a retry completes the
-- close exactly once. When the kill is not delivered, the test
-- releases the sibling and joins it before failing, so the suite
-- never wedges behind the parked pair.

-- | A closer killed while the drain waits on the Store lock stays
-- closing and a retry completes: the sibling commits a meta key
-- through an injector that parks once with the commit lock held,
-- the closer parks in retirement behind it, and after the kill and
-- the release the retry retires the joined attachment, cancels its
-- job, closes the backend once and nulls the slot.
caseCloserKilledInStoreWait :: IO ()
caseCloserKilledInStoreWait = do
  armed <- newIORef False
  arrived <- newEmptyMVar
  hold <- newEmptyMVar
  let inj = FaultInjector
        { fiFire = \p ->
            if p == FaultBeforeCommit
              then do
                fire <- atomicModifyIORef' armed (\on -> (False, on))
                if fire
                  then putMVar arrived () >> takeMVar hold >> pure False
                  else pure False
              else pure False
        , fiOnMasked = pure ()
        , fiOnResult = \_ -> pure ()
        }
  (_, store) <- mkFfiStoreWith inj
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
  jB <- case eJoin of
    JoinOk j -> pure j
    other -> assertFailure ("join failed: " ++ show other)
  h <- allocJobHandle ctx jB
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  (counting, readCounts) <- countingAcquisition
  -- Arm only after setup: detach reserves through the same probe.
  writeIORef armed True
  alloca $ \pSlot -> do
    poke pSlot sp
    sibDone <- newEmptyMVar
    _ <- forkIO $ do
      r <- try (storeCommit store emptyDelta { sdPutMeta = [("sibling-hold", "1")] })
      putMVar sibDone (r :: Either SomeException CommitResult)
    closerRef <- newIORef (Nothing :: Maybe (MVar (Either SomeException ())))
    (do
      within10s "sibling parks holding the commit lock" (takeMVar arrived)
      closedDone <- newEmptyMVar
      closerTid <- mask_ $ do
        tid <- forkIO $ do
          r <- try (haskokiAsyncClose pSlot)
          putMVar closedDone (r :: Either SomeException ())
        writeIORef closerRef (Just closedDone)
        pure tid
      awaitBlocked BlockedOnMVar closerTid
      gateBefore <- inspectTableGate (acTable ctx)
      assertEqual "first closer holds the claim" (0, True) gateBefore
      closeBefore <- inspectTableClose (acTable ctx)
      assertEqual "first closer started teardown"
        (TableClosing TeardownStarted CloserActive) closeBefore
      within10s "second closer returns" (closeCtxSlotWith asyncAcquisition pSlot)
      gateAfterSecond <- inspectTableGate (acTable ctx)
      assertEqual "second closer changes nothing" gateBefore gateAfterSecond
      closeAfterSecond <- inspectTableClose (acTable ctx)
      assertEqual "second closer leaves the phase" closeBefore closeAfterSecond
      midSlot <- peek pSlot
      assertBool "slot still set" (not (isNull midSlot))
      -- The kill goes from a forked thread: the throw only
      -- queues against a parked closer, and the issuer would wedge
      -- behind an undeliverable kill instead of reaching the join.
      _ <- forkIO (killThread closerTid)
      mClosed <- timeout stormScaleBudget (takeMVar closedDone)
      case mClosed of
        Nothing -> do
          -- The release lets the parked pair unwind on its own (the
          -- sibling commits, the closer runs to its pending kill),
          -- so join both before failing: the closer must never
          -- write into the slot after its frame returns.
          putMVar hold ()
          _ <- within10s "sibling joins after release" (takeMVar sibDone)
          _ <- within10s "closer joins after release" (takeMVar closedDone)
          writeIORef closerRef Nothing
          assertFailure "kill not delivered (>300s)"
        Just (Right ()) -> writeIORef closerRef Nothing
        Just (Left e) -> do
          writeIORef closerRef Nothing
          assertFailure ("closer leaked: " ++ show e)
      gateMid <- inspectTableGate (acTable ctx)
      assertEqual "stays closing with no closer" (0, True) gateMid
      closeMid <- inspectTableClose (acTable ctx)
      assertEqual "teardown started, closer absent"
        (TableClosing TeardownStarted CloserAbsent) closeMid
      midSlot2 <- peek pSlot
      assertBool "slot still set after the kill" (not (isNull midSlot2))
      rvRefused <- haskokiAsyncCancel sp nullJob
      assertEqual "call through the closing slot refuses" rvGeneral rvRefused
      (liveMid, _, _) <- tableStats (acTable ctx)
      assertEqual "retirement never ran" 1 liveMid
      avMid <- inspectAttachment dc pid
      assertEqual "attachment still active" (Just (AvActive jB)) avMid
      putMVar hold ()
      sibRes <- within10s "sibling joins" (takeMVar sibDone)
      case sibRes of
        Right Committed -> pure ()
        other -> assertFailure ("sibling commit failed: " ++ show other)
      closeCtxSlotWith counting pSlot
      after <- peek pSlot
      assertBool "retry nulled the slot" (isNull after)
      gateAfter <- inspectTableGate (acTable ctx)
      assertEqual "closed, no borrowers" (0, True) gateAfter
      av <- inspectAttachment dc pid
      assertEqual "attachment terminal" (Just (AvTerminal JobCanceled)) av
      jobs <- loadFfiJobs store
      assertEqual "one durable row" 1 (length jobs)
      case [r | r <- jobs, jrPersistentId r == pid] of
        [rec] -> assertEqual "record canceled" JobCanceled (jrState rec)
        other -> assertFailure ("expected one record, got " ++ show other)
      nLive <- asyncLiveHandles ctx
      assertZero "live_handles" "retry drained the handle" nLive
      (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
      assertZero "live_jobs" "no live jobs" liveAfter
      assertEqual "one terminal job" 1 termAfter
      assertEqual "two jobs minted" 2 nextAfter
      c <- readCounts
      assertEqual "backend closed once on the retry" 1 (acBackendCloses c)
      assertEqual "retired once on the retry" 1 (acRetirements c)
      assertEqual "context freed once on the retry" 1 (acCtxFrees c)
      mStale <- resolveJobHandle ctx h
      assertEqual "handle retired" Nothing mStale
      cout <- cancelJob (acTable ctx) jB
      case cout of
        CancelAlready TermCanceled -> pure ()
        other -> assertFailure ("job not canceled, got " ++ show other)
      haskokiAsyncClose pSlot
      after2 <- peek pSlot
      assertBool "slot stays nulled" (isNull after2))
      `finally` (do
        _ <- tryPutMVar hold ()
        mDone <- readIORef closerRef
        case mDone of
          Nothing -> pure ()
          Just done -> do
            _ <- within10s "closer joins after release" (takeMVar done)
            pure ())

-- | A closer killed while the drain waits on a job lease cancels
-- exactly once on retry: the sibling holds a detach lease on the
-- one live job, the closer parks in the cancel behind it, and after
-- the kill and the release the retry cancels the job, drains its
-- handle and nulls the slot.
caseCloserKilledInLeaseWait :: IO ()
caseCloserKilledInLeaseWait = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  h <- allocJobHandle ctx j0
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  (counting, readCounts) <- countingAcquisition
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  alloca $ \pSlot -> do
    poke pSlot sp
    sibDone <- newEmptyMVar
    _ <- forkIO $ do
      r <- try (withDetachLease (acTable ctx) j0
        (\_ -> putMVar entered () >> takeMVar proceed))
      putMVar sibDone (r :: Either SomeException ())
    closerRef <- newIORef (Nothing :: Maybe (MVar (Either SomeException ())))
    (do
      within10s "sibling takes the lease" (takeMVar entered)
      closedDone <- newEmptyMVar
      closerTid <- mask_ $ do
        tid <- forkIO $ do
          r <- try (haskokiAsyncClose pSlot)
          putMVar closedDone (r :: Either SomeException ())
        writeIORef closerRef (Just closedDone)
        pure tid
      awaitBlocked BlockedOnMVar closerTid
      gateBefore <- inspectTableGate (acTable ctx)
      assertEqual "first closer holds the claim" (0, True) gateBefore
      closeBefore <- inspectTableClose (acTable ctx)
      assertEqual "first closer started teardown"
        (TableClosing TeardownStarted CloserActive) closeBefore
      within10s "second closer returns" (closeCtxSlotWith asyncAcquisition pSlot)
      gateAfterSecond <- inspectTableGate (acTable ctx)
      assertEqual "second closer changes nothing" gateBefore gateAfterSecond
      closeAfterSecond <- inspectTableClose (acTable ctx)
      assertEqual "second closer leaves the phase" closeBefore closeAfterSecond
      midSlot <- peek pSlot
      assertBool "slot still set" (not (isNull midSlot))
      -- The kill goes from a forked thread: the throw only
      -- queues against a parked closer, and the issuer would wedge
      -- behind an undeliverable kill instead of reaching the join.
      _ <- forkIO (killThread closerTid)
      mClosed <- timeout stormScaleBudget (takeMVar closedDone)
      case mClosed of
        Nothing -> do
          putMVar proceed ()
          _ <- within10s "sibling joins after release" (takeMVar sibDone)
          _ <- within10s "closer joins after release" (takeMVar closedDone)
          writeIORef closerRef Nothing
          assertFailure "kill not delivered (>300s)"
        Just (Right ()) -> writeIORef closerRef Nothing
        Just (Left e) -> do
          writeIORef closerRef Nothing
          assertFailure ("closer leaked: " ++ show e)
      gateMid <- inspectTableGate (acTable ctx)
      assertEqual "stays closing with no closer" (0, True) gateMid
      closeMid <- inspectTableClose (acTable ctx)
      assertEqual "teardown started, closer absent"
        (TableClosing TeardownStarted CloserAbsent) closeMid
      midSlot2 <- peek pSlot
      assertBool "slot still set after the kill" (not (isNull midSlot2))
      rvRefused <- haskokiAsyncCancel sp nullJob
      assertEqual "call through the closing slot refuses" rvGeneral rvRefused
      (liveMid, _, _) <- tableStats (acTable ctx)
      assertEqual "the cancel never ran" 1 liveMid
      nLiveMid <- asyncLiveHandles ctx
      assertEqual "the handle is still live" 1 nLiveMid
      putMVar proceed ()
      sibRes <- within10s "sibling joins" (takeMVar sibDone)
      case sibRes of
        Right () -> pure ()
        Left e -> assertFailure ("sibling failed: " ++ show e)
      closeCtxSlotWith counting pSlot
      after <- peek pSlot
      assertBool "retry nulled the slot" (isNull after)
      gateAfter <- inspectTableGate (acTable ctx)
      assertEqual "closed, no borrowers" (0, True) gateAfter
      nLive <- asyncLiveHandles ctx
      assertZero "live_handles" "retry drained the handle" nLive
      (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
      assertZero "live_jobs" "no live jobs" liveAfter
      assertEqual "one terminal job" 1 termAfter
      assertEqual "one job minted" 1 nextAfter
      c <- readCounts
      assertEqual "backend closed once on the retry" 1 (acBackendCloses c)
      assertEqual "retired once on the retry" 1 (acRetirements c)
      assertEqual "context freed once on the retry" 1 (acCtxFrees c)
      mStale <- resolveJobHandle ctx h
      assertEqual "handle retired" Nothing mStale
      cout <- cancelJob (acTable ctx) j0
      case cout of
        CancelAlready TermCanceled -> pure ()
        other -> assertFailure ("job not canceled, got " ++ show other)
      haskokiAsyncClose pSlot
      after2 <- peek pSlot
      assertBool "slot stays nulled" (isNull after2))
      `finally` (do
        _ <- tryPutMVar proceed ()
        mDone <- readIORef closerRef
        case mDone of
          Nothing -> pure ()
          Just done -> do
            _ <- within10s "closer joins after release" (takeMVar done)
            pure ())

-- | A closer killed while the drain waits on the backend gate frees
-- the native env exactly once on retry: the sibling parks a gated
-- digest in its checkpoint holding the env gate, the closer parks
-- in the backend close behind it, and after the kill and a
-- proceed-verdict release the retry closes the backend, which
-- destroys the one env with no double free.
caseCloserKilledInBackendGateWait :: IO ()
caseCloserKilledInBackendGateWait = withOwnGate $ \g -> do
  (tracked, opened) <- trackOpened (gatedBackendSteps g asyncAcquisition)
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do
    eCtx <- openAsyncCtxWith acq defaultConfig
    sp <- case eCtx of
      Right s -> pure s
      Left _ -> assertFailure "context open failed"
    ctx <- deRefStablePtr sp
    c_ownGateArmCheckpoint g 2
    alloca $ \pSlot -> do
      poke pSlot sp
      sibDone <- newEmptyMVar
      _ <- forkIO $ do
        r <- try (digestOneShotGated g (acBackend ctx) B.D_SHA256 "hello")
        putMVar sibDone (r :: Either SomeException (B.EngineResult ByteString))
      closerRef <- newIORef (Nothing :: Maybe (MVar (Either SomeException ())))
      (do
        awaitOwnParked g
        closedDone <- newEmptyMVar
        closerTid <- mask_ $ do
          tid <- forkIO $ do
            r <- try (haskokiAsyncClose pSlot)
            putMVar closedDone (r :: Either SomeException ())
          writeIORef closerRef (Just closedDone)
          pure tid
        awaitBlocked BlockedOnMVar closerTid
        gateBefore <- inspectTableGate (acTable ctx)
        assertEqual "first closer holds the claim" (0, True) gateBefore
        closeBefore <- inspectTableClose (acTable ctx)
        assertEqual "first closer started teardown"
          (TableClosing TeardownStarted CloserActive) closeBefore
        within10s "second closer returns" (closeCtxSlotWith asyncAcquisition pSlot)
        gateAfterSecond <- inspectTableGate (acTable ctx)
        assertEqual "second closer changes nothing" gateBefore gateAfterSecond
        closeAfterSecond <- inspectTableClose (acTable ctx)
        assertEqual "second closer leaves the phase" closeBefore closeAfterSecond
        midSlot <- peek pSlot
        assertBool "slot still set" (not (isNull midSlot))
        -- The kill goes from a forked thread: the throw only
        -- queues against a parked closer, and the issuer would wedge
        -- behind an undeliverable kill instead of reaching the join.
        _ <- forkIO (killThread closerTid)
        mClosed <- timeout stormScaleBudget (takeMVar closedDone)
        case mClosed of
          Nothing -> do
            c_ownGateRelease g 0
            _ <- within10s "sibling joins after release" (takeMVar sibDone)
            _ <- within10s "closer joins after release" (takeMVar closedDone)
            writeIORef closerRef Nothing
            assertFailure "kill not delivered (>300s)"
          Just (Right ()) -> writeIORef closerRef Nothing
          Just (Left e) -> do
            writeIORef closerRef Nothing
            assertFailure ("closer leaked: " ++ show e)
        gateMid <- inspectTableGate (acTable ctx)
        assertEqual "stays closing with no closer" (0, True) gateMid
        closeMid <- inspectTableClose (acTable ctx)
        assertEqual "teardown started, closer absent"
          (TableClosing TeardownStarted CloserAbsent) closeMid
        midSlot2 <- peek pSlot
        assertBool "slot still set after the kill" (not (isNull midSlot2))
        rvRefused <- haskokiAsyncCancel sp nullJob
        assertEqual "call through the closing slot refuses" rvGeneral rvRefused
        envMid <- c_ownGateEnvOutstanding g
        assertEqual "the backend close never ran" 1 envMid
        c_ownGateRelease g 0
        sibRes <- within10s "sibling joins" (takeMVar sibDone)
        case sibRes of
          Right (B.EngineOk _) -> pure ()
          other -> assertFailure ("sibling digest failed: " ++ show other)
        closeCtxSlotWith acq pSlot
        after <- peek pSlot
        assertBool "retry nulled the slot" (isNull after)
        gateAfter <- inspectTableGate (acTable ctx)
        assertEqual "closed, no borrowers" (0, True) gateAfter
        envOut <- c_ownGateEnvOutstanding g
        assertZero "env_outstanding" "native env freed once" envOut
        envDf <- c_ownEnvDoublefree
        assertZero "env_doublefree" "no native double free" envDf
        nLive <- asyncLiveHandles ctx
        assertZero "live_handles" "no live handles" nLive
        (liveAfter, _, _) <- tableStats (acTable ctx)
        assertZero "live_jobs" "no live jobs" liveAfter
        c <- readCounts
        assertBalanced "backend gate retry" c
        haskokiAsyncClose pSlot
        after2 <- peek pSlot
        assertBool "slot stays nulled" (isNull after2))
        `finally` (do
          c_ownGateRelease g 0
          mDone <- readIORef closerRef
          case mDone of
            Nothing -> pure ()
            Just done -> do
              _ <- within10s "closer joins after release" (takeMVar done)
              pure ()))
    `finally` releaseOpened opened

-- | A Store failure during retirement still closes and keeps the
-- record joinable: the detach view sits over a Store whose job load
-- fails, so retirement marks the joined attachment terminal in
-- memory while the durable row stands untouched. The close
-- completes; then a fresh box and context over the same world
-- rejoin the job exactly once.
caseStoreFailureInRetirement :: IO ()
caseStoreFailureInRetirement = do
  (world, plain) <- mkFfiStoreWith noFaults
  armed <- newIORef False
  let failing = plain
        { storeLoadJobs = do
            on <- readIORef armed
            if on
              then pure (Left (StoreIO "injected load failure"))
              else storeLoadJobs plain
        }
  dc <- mkFfiDetached failing
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
  jB <- case eJoin of
    JoinOk j -> pure j
    other -> assertFailure ("join failed: " ++ show other)
  h <- allocJobHandle ctx jB
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    writeIORef armed True
    haskokiAsyncClose pSlot
    writeIORef armed False
    after <- peek pSlot
    assertBool "close completed" (isNull after)
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "closed, no borrowers" (0, True) gateAfter
    av <- inspectAttachment dc pid
    assertEqual "attachment terminal in memory" (Just (AvTerminal JobCanceled)) av
    jobs <- loadFfiJobs failing
    case jobs of
      [rec] -> do
        assertEqual "durable record id" pid (jrPersistentId rec)
        assertEqual "durable record untouched" JobQueued (jrState rec)
      other -> assertFailure ("expected one row, got " ++ show other)
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "close drained the handle" nLive
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live jobs" liveAfter
    assertEqual "one terminal job" 1 termAfter
    assertEqual "two jobs minted" 2 nextAfter
    mStale <- resolveJobHandle ctx h
    assertEqual "handle retired" Nothing mStale
  storeClose failing
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do
    eBox <- openStoreBoxWith acq nullPtr
    box <- case eBox of
      Right b -> pure b
      Left _ -> assertFailure "box reopen failed"
    eCtx <- openAsyncCtxOnWith acq defaultConfig box
    spCtx <- case eCtx of
      Right s -> pure s
      Left _ -> assertFailure "context reopen failed"
    ctx2 <- deRefStablePtr spCtx
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
    eJoin2 <- rejoin
    j2 <- case eJoin2 of
      JoinOk j -> pure j
      other -> assertFailure ("rejoin failed: " ++ show other)
    eJoin3 <- rejoin
    case eJoin3 of
      JoinAlreadyAttached _ -> pure ()
      other -> assertFailure ("second rejoin not refused: " ++ show other)
    av2 <- inspectAttachment dc2 pid
    assertEqual "rejoined attachment active" (Just (AvActive j2)) av2
    alloca $ \pCtx -> do
      poke pCtx spCtx
      closeCtxSlotWith acq pCtx
      afterCtx <- peek pCtx
      assertBool "context slot nulled" (isNull afterCtx)
    alloca $ \pBox -> do
      poke pBox box
      closeStoreBoxSlotWith acq pBox
      afterBox <- peek pBox
      assertBool "box slot nulled" (isNull afterBox)
    c <- readCounts
    (refused, why) <- memoryReopenRefused world
    assertBalanced ("memory world reopen: " ++ why) c
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | Table close phases move only forward after teardown starts: a
-- claim released before teardown reopens the gate, while a claim
-- released past teardown begin stays closing without a closer —
-- never back to open. Entry refuses once closing, a retrying claim
-- resumes, a racing second claim loses, teardown begin is
-- idempotent, and finish closes for good.
caseTableClosePhasesMoveOnlyForward :: IO ()
caseTableClosePhasesMoveOnlyForward = do
  mTable <- tryNewAsyncTable 8
  table <- case mTable of
    Just t -> pure t
    Nothing -> assertFailure "table allocator refused"
  opened <- inspectTableClose table
  assertEqual "gate fresh" TableOpen opened
  first <- claimTableClose table
  assertBool "first claim wins" first
  releaseTableClose table
  reopened <- inspectTableClose table
  assertEqual "release before teardown reopens" TableOpen reopened
  claimed <- claimTableClose table
  assertBool "claim wins again" claimed
  began <- beginTableTeardown table
  assertBool "teardown begins" began
  releaseTableClose table
  closing <- inspectTableClose table
  assertEqual "release past teardown stays closing"
    (TableClosing TeardownStarted CloserAbsent) closing
  admitted <- enterTableUse table
  assertBool "entry refuses once closing" (not admitted)
  resumed <- claimTableClose table
  assertBool "retrying claim resumes" resumed
  racing <- claimTableClose table
  assertBool "racing second claim loses" (not racing)
  beganAgain <- beginTableTeardown table
  assertBool "teardown begin is idempotent" beganAgain
  resumedState <- inspectTableClose table
  assertEqual "idempotent begin changes nothing"
    (TableClosing TeardownStarted CloserActive) resumedState
  finishTableClose table
  closed <- inspectTableClose table
  assertEqual "finish closes" TableClosed closed
  afterClose <- claimTableClose table
  assertBool "claim after close loses" (not afterClose)
  (liveAfter, _, _) <- tableStats table
  assertZero "live_jobs" "no live jobs" liveAfter

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

-- | An unknown registry key refuses without admission: a valid
-- pointer to a fixture context that is never registered, driven
-- through the job-start export, reports the same code as a retired
-- tombstone, leaves the out-pointer untouched, and mints no job.
-- No-dereference holds by construction: 'enterCtx' admits through
-- the registry before any dereference.
caseUnknownKeyRefusesWithoutAdmission :: IO ()
caseUnknownKeyRefusesWithoutAdmission = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  spTomb <- newStablePtr ctx
  registerFixtureCtx spTomb (acTable ctx)
  retireCtx spTomb
  (spUnknown, colliders) <- freshAbsentKey ctx
  let sess = CULong (fromIntegral (unSessionId (acSession ctx)))
      startOn sp pHandleOut = BS.useAsCString "abc" $ \p ->
        haskokiAsyncStart sp sess 2 (castPtr p) 3 32 1 pHandleOut
  (do
    rvTomb <- alloca $ \pHandleOut -> do
      poke pHandleOut nullJob
      rv <- startOn spTomb pHandleOut
      hOut <- peek pHandleOut
      assertBool "tombstone mints no handle" (isNull hOut)
      pure rv
    assertEqual "tombstone refuses" rvGeneral rvTomb
    (liveTomb, _, _) <- tableStats (acTable ctx)
    assertZero "live_jobs" "tombstone mints no job" liveTomb
    let sentinel = castPtrToStablePtr (wordPtrToPtr 0xa5a5a5a5) :: StablePtr JobHandle
    (rvUnknown, hUnknown) <- alloca $ \pHandleOut -> do
      poke pHandleOut sentinel
      rv <- startOn spUnknown pHandleOut
      hOut <- peek pHandleOut
      pure (rv, hOut)
    assertEqual "unknown refuses like the tombstone" rvTomb rvUnknown
    assertBool "unknown leaves the out-pointer untouched" (hUnknown == sentinel)
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "unknown mints no job" liveAfter
    assertEqual "no terminal minted" 0 termAfter
    assertEqual "no id consumed" 0 nextAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "no handles" nLive
    ) `finally`
      (freeStablePtr spUnknown >> mapM_ freeStablePtr colliders
        >> freeStablePtr spTomb >> asyncCloseCtx ctx)

-- | A hook-only registry key refuses after its hook: arming a hook
-- on a never-registered key parks the hook without admitting, the
-- export fires the hook once and then refuses like a tombstone,
-- minting no job.
caseHookOnlyRefusesAfterHook :: IO ()
caseHookOnlyRefusesAfterHook = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  (spHook, colliders) <- freshAbsentKey ctx
  fired <- newEmptyMVar
  setEnterTestHook spHook (Just (putMVar fired ()))
  let sess = CULong (fromIntegral (unSessionId (acSession ctx)))
      startOn pHandleOut = BS.useAsCString "abc" $ \p ->
        haskokiAsyncStart spHook sess 2 (castPtr p) 3 32 1 pHandleOut
  (do
    (rv, hOut) <- alloca $ \pHandleOut -> do
      poke pHandleOut nullJob
      r <- startOn pHandleOut
      h <- peek pHandleOut
      pure (r, h)
    mFired <- timeout 10000000 (takeMVar fired)
    case mFired of
      Nothing -> assertFailure "entry hook never fired"
      Just () -> pure ()
    mSecond <- tryTakeMVar fired
    case mSecond of
      Nothing -> pure ()
      Just () -> assertFailure "entry hook fired twice for one call"
    assertEqual "hook-only refuses" rvGeneral rv
    assertBool "hook-only mints no handle" (isNull hOut)
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "hook-only mints no job" liveAfter
    assertEqual "no terminal minted" 0 termAfter
    assertEqual "no id consumed" 0 nextAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "no handles" nLive
    ) `finally`
      (setEnterTestHook spHook Nothing >> freeStablePtr spHook
        >> mapM_ freeStablePtr colliders >> asyncCloseCtx ctx)

-- | Closing an unknown key reclaims the slot only: the slot nulls,
-- the table gate stays open with no borrowers, and the backend
-- stays open. Pins the slot-reclaim path.
caseCloseUnknownNullsSlotOnly :: IO ()
caseCloseUnknownNullsSlotOnly = do
  _store <- mkFfiStore
  dc <- mkFfiDetached _store
  ctx <- mkFfiGen dc
  (spUnknown, colliders) <- freshAbsentKey ctx
  (counting, readCounts) <- countingAcquisition
  (spExport, colliders2) <- freshAbsentKey ctx
  (do
    alloca $ \pSlot -> do
      poke pSlot spUnknown
      closeCtxSlotWith counting pSlot
      after <- peek pSlot
      assertBool "slot nulled" (isNull after)
    gate <- inspectTableGate (acTable ctx)
    assertEqual "gate stays open" (0, False) gate
    c <- readCounts
    assertEqual "backend stays open" 0 (acBackendCloses c)
    assertEqual "no retirement" 0 (acRetirements c)
    assertEqual "no context free" 0 (acCtxFrees c)
    alloca $ \pSlot -> do
      poke pSlot spExport
      haskokiAsyncClose pSlot
      after <- peek pSlot
      assertBool "export slot nulled" (isNull after)
    gate2 <- inspectTableGate (acTable ctx)
    assertEqual "gate still open" (0, False) gate2
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no jobs" liveAfter
    assertEqual "no terminal minted" 0 termAfter
    assertEqual "no id consumed" 0 nextAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "no handles" nLive
    ) `finally`
      (freeStablePtr spUnknown >> mapM_ freeStablePtr colliders
        >> freeStablePtr spExport >> mapM_ freeStablePtr colliders2
        >> asyncCloseCtx ctx)

-- | A throw in the pointer tail leaves a resumable gate: the first
-- close runs its drain, then its retire throws, so the slot stays
-- set with teardown started and no closer; the retry re-runs the
-- idempotent drain, retires and frees exactly once, and nulls the
-- slot. Before the tail ran first, the throw stranded a closed gate
-- with a live entry and pointer no retry could reclaim.
caseCloseTailThrowResumesOnRetry :: IO ()
caseCloseTailThrowResumesOnRetry = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  h <- allocJobHandle ctx j0
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  (counting, readCounts) <- countingAcquisition
  armed <- newIORef True
  let throwing = counting
        { aaRetireCtx = \sp' -> do
            fire <- atomicModifyIORef' armed (\on -> (False, on))
            if fire
              then throwIO (userError "injected retire throw")
              else aaRetireCtx counting sp'
        }
  alloca $ \pSlot -> do
    poke pSlot sp
    r <- try (closeCtxSlotWith throwing pSlot) :: IO (Either SomeException ())
    case r of
      Left _ -> pure ()
      Right () -> assertFailure "throwing retire returned normally"
    mid <- peek pSlot
    assertBool "slot still set after the throw" (not (isNull mid))
    closeMid <- inspectTableClose (acTable ctx)
    assertEqual "gate resumable after the throw"
      (TableClosing TeardownStarted CloserAbsent) closeMid
    closeCtxSlotWith throwing pSlot
    after <- peek pSlot
    assertBool "retry nulled the slot" (isNull after)
    closeAfter <- inspectTableClose (acTable ctx)
    assertEqual "retry closed the gate" TableClosed closeAfter
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "closed, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "retry drained the handle" nLive
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live jobs" liveAfter
    assertEqual "one terminal job" 1 termAfter
    assertEqual "one job minted" 1 nextAfter
    c <- readCounts
    assertEqual "retired once on the retry" 1 (acRetirements c)
    assertEqual "context freed once on the retry" 1 (acCtxFrees c)
    assertEqual "backend close ran on both attempts" 2 (acBackendCloses c)
    mStale <- resolveJobHandle ctx h
    assertEqual "handle retired" Nothing mStale
    cout <- cancelJob (acTable ctx) j0
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("job not canceled, got " ++ show other)
    haskokiAsyncClose pSlot
    after2 <- peek pSlot
    assertBool "slot stays nulled" (isNull after2)
    awaitNoPendingReclaims
    awaitReclaimBalanced

-- | A throw in the pointer free leaves a resumable gate: the
-- first close retires, then its free throws, so the slot stays
-- set with teardown started and no closer; the retry retires the
-- live entry the throw arm re-registered, frees exactly once,
-- and nulls the slot.
caseCloseTailFreeThrowResumesOnRetry :: IO ()
caseCloseTailFreeThrowResumesOnRetry = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  h <- allocJobHandle ctx j0
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  (counting, readCounts) <- countingAcquisition
  armed <- newIORef True
  let throwing = counting
        { aaFreeCtxPtr = \sp' -> do
            fire <- atomicModifyIORef' armed (\on -> (False, on))
            if fire
              then throwIO (userError "injected free throw")
              else aaFreeCtxPtr counting sp'
        }
  alloca $ \pSlot -> do
    poke pSlot sp
    r <- try (closeCtxSlotWith throwing pSlot) :: IO (Either SomeException ())
    case r of
      Left _ -> pure ()
      Right () -> assertFailure "throwing free returned normally"
    mid <- peek pSlot
    assertBool "slot still set after the throw" (not (isNull mid))
    closeMid <- inspectTableClose (acTable ctx)
    assertEqual "gate resumable after the throw"
      (TableClosing TeardownStarted CloserAbsent) closeMid
    closeCtxSlotWith throwing pSlot
    after <- peek pSlot
    assertBool "retry nulled the slot" (isNull after)
    closeAfter <- inspectTableClose (acTable ctx)
    assertEqual "retry closed the gate" TableClosed closeAfter
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "closed, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "retry drained the handle" nLive
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live jobs" liveAfter
    assertEqual "one terminal job" 1 termAfter
    assertEqual "one job minted" 1 nextAfter
    c <- readCounts
    assertEqual "retired on both attempts" 2 (acRetirements c)
    assertEqual "context freed once on the retry" 1 (acCtxFrees c)
    assertEqual "backend close ran on both attempts" 2 (acBackendCloses c)
    mStale <- resolveJobHandle ctx h
    assertEqual "handle retired" Nothing mStale
    cout <- cancelJob (acTable ctx) j0
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("job not canceled, got " ++ show other)
    haskokiAsyncClose pSlot
    after2 <- peek pSlot
    assertBool "slot stays nulled" (isNull after2)
    awaitNoPendingReclaims
    awaitReclaimBalanced

-- | A value-level close killed while the drain waits on a job
-- lease resumes and closes: the sibling holds a detach lease on
-- the one live job, the closer parks in the cancel behind it, and
-- after the kill and the release the retry cancels the job,
-- drains its handle and marks the table closed. A further close
-- is a silent no-op. This pins the resume path through the
-- value-level close, which carries no pointer steps.
caseValueCloseKilledInLeaseWaitResumes :: IO ()
caseValueCloseKilledInLeaseWaitResumes = do
  store <- mkFfiStore
  dc <- mkFfiDetached store
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  h <- allocJobHandle ctx j0
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  sibDone <- newEmptyMVar
  _ <- forkIO $ do
    r <- try (withDetachLease (acTable ctx) j0
      (\_ -> putMVar entered () >> takeMVar proceed))
    putMVar sibDone (r :: Either SomeException ())
  (do
    within10s "sibling takes the lease" (takeMVar entered)
    closedDone <- newEmptyMVar
    closerTid <- forkIO $ do
      r <- try (asyncCloseCtx ctx)
      putMVar closedDone (r :: Either SomeException ())
    awaitBlocked BlockedOnMVar closerTid
    closeBefore <- inspectTableClose (acTable ctx)
    assertEqual "first closer holds the claim"
      (TableClosing TeardownStarted CloserActive) closeBefore
    within10s "second value close returns" (asyncCloseCtx ctx)
    closeAfterSecond <- inspectTableClose (acTable ctx)
    assertEqual "second closer changes nothing" closeBefore closeAfterSecond
    -- The kill goes from a forked thread: the throw only queues
    -- against a parked closer, and the issuer would wedge behind
    -- an undeliverable kill instead of reaching the join.
    _ <- forkIO (killThread closerTid)
    mClosed <- timeout stormScaleBudget (takeMVar closedDone)
    case mClosed of
      Nothing -> do
        putMVar proceed ()
        _ <- within10s "sibling joins after release" (takeMVar sibDone)
        _ <- within10s "closer joins after release" (takeMVar closedDone)
        assertFailure "kill not delivered (>300s)"
      Just (Left e)
        | fromException e == Just ThreadKilled -> pure ()
        | otherwise -> assertFailure ("closer leaked: " ++ show e)
      Just (Right ()) ->
        assertFailure "kill swallowed: value close returned normally"
    gateMid <- inspectTableGate (acTable ctx)
    assertEqual "stays closing with no closer" (0, True) gateMid
    closeMid <- inspectTableClose (acTable ctx)
    assertEqual "teardown started, closer absent"
      (TableClosing TeardownStarted CloserAbsent) closeMid
    (liveMid, _, _) <- tableStats (acTable ctx)
    assertEqual "the cancel never ran" 1 liveMid
    nLiveMid <- asyncLiveHandles ctx
    assertEqual "the handle is still live" 1 nLiveMid
    putMVar proceed ()
    sibRes <- within10s "sibling joins" (takeMVar sibDone)
    case sibRes of
      Right () -> pure ()
      Left e -> assertFailure ("sibling failed: " ++ show e)
    asyncCloseCtx ctx
    closeAfter <- inspectTableClose (acTable ctx)
    assertEqual "retry closed the gate" TableClosed closeAfter
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "closed, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "retry drained the handle" nLive
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live jobs" liveAfter
    assertEqual "one terminal job" 1 termAfter
    assertEqual "one job minted" 1 nextAfter
    mStale <- resolveJobHandle ctx h
    assertEqual "handle retired" Nothing mStale
    cout <- cancelJob (acTable ctx) j0
    case cout of
      CancelAlready TermCanceled -> pure ()
      other -> assertFailure ("job not canceled, got " ++ show other)
    asyncCloseCtx ctx
    closeAgain <- inspectTableClose (acTable ctx)
    assertEqual "close after teardown is a silent no-op" TableClosed closeAgain)
    `finally` (tryPutMVar proceed () >> pure ())

-- | The block wait rejects other block reasons: a thread parked on
-- an MVar never satisfies a wait for an STM park, so the bounded
-- wait fails instead of returning early on the wrong reason.
caseBlockWaitRejectsOtherReasons :: IO ()
caseBlockWaitRejectsOtherReasons = do
  mv <- newEmptyMVar
  parked <- forkIO (takeMVar mv)
  (do
    awaitBlockedFor (stormScaleBudget `div` 1000) BlockedOnMVar parked
    r <- try (awaitBlockedFor 200 BlockedOnSTM parked) :: IO (Either SomeException ())
    case r of
      Left _ -> pure ()
      Right () -> assertFailure "wait returned on the wrong block reason")
    `finally` killThread parked

-- | A Store throw during retirement still closes and keeps the
-- record joinable: the job load throws instead of answering Left,
-- so retirement marks the joined attachment terminal in memory
-- while the durable row stands untouched. The close completes;
-- then a fresh box and context over the same world rejoin the job
-- exactly once. Before the throw mapped onto the failed-load arm,
-- every close attempt died at the same point and held the context.
caseStoreThrowInRetirementStillCloses :: IO ()
caseStoreThrowInRetirementStillCloses = do
  (world, plain) <- mkFfiStoreWith noFaults
  armed <- newIORef False
  let throwing = plain
        { storeLoadJobs = do
            on <- readIORef armed
            if on
              then throwIO (userError "injected load throw")
              else storeLoadJobs plain
        }
  dc <- mkFfiDetached throwing
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
  jB <- case eJoin of
    JoinOk j -> pure j
    other -> assertFailure ("join failed: " ++ show other)
  h <- allocJobHandle ctx jB
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    writeIORef armed True
    haskokiAsyncClose pSlot
    writeIORef armed False
    after <- peek pSlot
    assertBool "close completed" (isNull after)
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "closed, no borrowers" (0, True) gateAfter
    av <- inspectAttachment dc pid
    assertEqual "attachment terminal in memory" (Just (AvTerminal JobCanceled)) av
    jobs <- loadFfiJobs throwing
    case jobs of
      [rec] -> do
        assertEqual "durable record id" pid (jrPersistentId rec)
        assertEqual "durable record untouched" JobQueued (jrState rec)
      other -> assertFailure ("expected one row, got " ++ show other)
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "close drained the handle" nLive
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live jobs" liveAfter
    assertEqual "one terminal job" 1 termAfter
    assertEqual "two jobs minted" 2 nextAfter
    mStale <- resolveJobHandle ctx h
    assertEqual "handle retired" Nothing mStale
  storeClose throwing
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do
    eBox <- openStoreBoxWith acq nullPtr
    box <- case eBox of
      Right b -> pure b
      Left _ -> assertFailure "box reopen failed"
    eCtx <- openAsyncCtxOnWith acq defaultConfig box
    spCtx <- case eCtx of
      Right s -> pure s
      Left _ -> assertFailure "context reopen failed"
    ctx2 <- deRefStablePtr spCtx
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
    eJoin2 <- rejoin
    j2 <- case eJoin2 of
      JoinOk j -> pure j
      other -> assertFailure ("rejoin failed: " ++ show other)
    eJoin3 <- rejoin
    case eJoin3 of
      JoinAlreadyAttached _ -> pure ()
      other -> assertFailure ("second rejoin not refused: " ++ show other)
    av2 <- inspectAttachment dc2 pid
    assertEqual "rejoined attachment active" (Just (AvActive j2)) av2
    alloca $ \pCtx -> do
      poke pCtx spCtx
      closeCtxSlotWith acq pCtx
      afterCtx <- peek pCtx
      assertBool "context slot nulled" (isNull afterCtx)
    alloca $ \pBox -> do
      poke pBox box
      closeStoreBoxSlotWith acq pBox
      afterBox <- peek pBox
      assertBool "box slot nulled" (isNull afterBox)
    c <- readCounts
    (refused, why) <- memoryReopenRefused world
    assertBalanced ("memory world reopen: " ++ why) c
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | A commit throw mid-loop reports only the uncommitted rows: with
-- two active joins on one table and a Store that throws on its
-- second commit, retirement commits the first row clean, marks both
-- attachments terminal in memory, and reports the throw only for
-- the second row; the second row stays durable-queued. The close
-- then drains and the slot nulls.
caseCommitThrowReportsOnlyUncommitted :: IO ()
caseCommitThrowReportsOnlyUncommitted = do
  (_world, plain) <- mkFfiStoreWith noFaults
  armed <- newIORef False
  countRef <- newIORef (0 :: Int)
  let throwing = plain
        { storeCommit = \delta -> do
            on <- readIORef armed
            if on
              then do
                n <- atomicModifyIORef' countRef (\c -> (c + 1, c + 1))
                if n == 2
                  then throwIO (userError "injected commit throw")
                  else storeCommit plain delta
              else storeCommit plain delta
        }
  dc <- mkFfiDetached throwing
  ctx <- mkFfiGen dc
  j0 <- startFfiDigest ctx "abc" 32 1
  j1 <- startFfiDigest ctx "def" 32 1
  eDet0 <- detachJob dc (acTable ctx) j0 JobDigest
  pid0 <- case eDet0 of
    DetachOk p -> pure p
    other -> assertFailure ("first detach failed: " ++ show other)
  eDet1 <- detachJob dc (acTable ctx) j1 JobDigest
  pid1 <- case eDet1 of
    DetachOk p -> pure p
    other -> assertFailure ("second detach failed: " ++ show other)
  let joinOn pid = joinJob dc (acEnv ctx) (acTable ctx) JoinRequest
        { jqPid = pid
        , jqFunction = JobDigest
        , jqSession = acSession ctx
        , jqCapacity = 32
        }
  eJoin0 <- joinOn pid0
  jB0 <- case eJoin0 of
    JoinOk j -> pure j
    other -> assertFailure ("first join failed: " ++ show other)
  eJoin1 <- joinOn pid1
  jB1 <- case eJoin1 of
    JoinOk j -> pure j
    other -> assertFailure ("second join failed: " ++ show other)
  h0 <- allocJobHandle ctx jB0
  h1 <- allocJobHandle ctx jB1
  sp <- newStablePtr ctx
  registerFixtureCtx sp (acTable ctx)
  alloca $ \pSlot -> do
    poke pSlot sp
    writeIORef armed True
    writeIORef countRef 0
    retired <- retireLiveTableFor dc (asyncTableId (acTable ctx))
    writeIORef armed False
    case retired of
      [(p0, e0), (p1, e1)] -> do
        assertEqual "first row is the first join" pid0 p0
        assertEqual "first row committed clean" Nothing e0
        assertEqual "second row is the second join" pid1 p1
        case e1 of
          Just (StoreIO _) -> pure ()
          other -> assertFailure ("second row must carry the throw, got " ++ show other)
      other -> assertFailure ("expected two rows, got " ++ show other)
    av0 <- inspectAttachment dc pid0
    assertEqual "first attachment terminal" (Just (AvTerminal JobCanceled)) av0
    av1 <- inspectAttachment dc pid1
    assertEqual "second attachment terminal" (Just (AvTerminal JobCanceled)) av1
    jobs <- loadFfiJobs throwing
    let stateOf q = [jrState r | r <- jobs, jrPersistentId r == q]
    assertEqual "first row durable canceled" [JobCanceled] (stateOf pid0)
    assertEqual "second row durable queued" [JobQueued] (stateOf pid1)
    haskokiAsyncClose pSlot
    after <- peek pSlot
    assertBool "close nulled the slot" (isNull after)
    gateAfter <- inspectTableGate (acTable ctx)
    assertEqual "closed, no borrowers" (0, True) gateAfter
    nLive <- asyncLiveHandles ctx
    assertZero "live_handles" "close drained the handles" nLive
    (liveAfter, termAfter, nextAfter) <- tableStats (acTable ctx)
    assertZero "live_jobs" "no live jobs" liveAfter
    assertEqual "two terminals" 2 termAfter
    assertEqual "four jobs minted" 4 nextAfter
    mStale0 <- resolveJobHandle ctx h0
    assertEqual "first handle retired" Nothing mStale0
    mStale1 <- resolveJobHandle ctx h1
    assertEqual "second handle retired" Nothing mStale1

-- ---------------------------------------------------------------------------
-- Standalone ownership: close accounting, slot state and fresh reopen
-- ---------------------------------------------------------------------------

-- | A null slot and a null slot pointer close silently: the counting
-- closes over a null pointer and over a null-holding slot move no
-- counter, and the one export-level close over a null-holding slot
-- returns without touching it.
caseNullClosesAreSilent :: IO ()
caseNullClosesAreSilent = do
  (counting, readCounts) <- countingAcquisition
  closeCtxSlotWith counting nullPtr
  alloca $ \pSlot -> do
    poke pSlot (castPtrToStablePtr nullPtr)
    closeCtxSlotWith counting pSlot
    after <- peek pSlot
    assertBool "null context slot unchanged" (isNull after)
  closeStoreBoxSlotWith counting nullPtr
  alloca $ \pBox -> do
    poke pBox (castPtrToStablePtr nullPtr)
    closeStoreBoxSlotWith counting pBox
    afterBox <- peek pBox
    assertBool "null box slot unchanged" (isNull afterBox)
  alloca $ \pSlot -> do
    poke pSlot (castPtrToStablePtr nullPtr)
    haskokiAsyncClose pSlot
    afterExport <- peek pSlot
    assertBool "export leaves the null slot unchanged" (isNull afterExport)
  c <- readCounts
  assertEqual "no store close" 0 (acStoreCloses c)
  assertEqual "no backend close" 0 (acBackendCloses c)
  assertEqual "no context free" 0 (acCtxFrees c)
  assertEqual "no box free" 0 (acBoxFrees c)
  assertEqual "no retirement" 0 (acRetirements c)
  assertBalanced "silent closes" c

-- | A repeated context close frees and retires once: the first of
-- three counting closes nulls the slot, and the two that follow are
-- silent no-ops.
caseRepeatedCloseFreesOnce :: IO ()
caseRepeatedCloseFreesOnce = do
  (counting, readCounts) <- countingAcquisition
  eCtx <- openAsyncCtxWith counting defaultConfig
  sp <- case eCtx of
    Right s -> pure s
    Left _ -> assertFailure "context open failed"
  ctx <- deRefStablePtr sp
  alloca $ \pSlot -> do
    poke pSlot sp
    closeCtxSlotWith counting pSlot
    after <- peek pSlot
    assertBool "first close nulled the slot" (isNull after)
    closeCtxSlotWith counting pSlot
    closeCtxSlotWith counting pSlot
    afterThird <- peek pSlot
    assertBool "slot stays nulled" (isNull afterThird)
  closeAfter <- inspectTableClose (acTable ctx)
  assertEqual "gate closed" TableClosed closeAfter
  nLive <- asyncLiveHandles ctx
  assertZero "live_handles" "no live handles" nLive
  (liveAfter, _, _) <- tableStats (acTable ctx)
  assertZero "live_jobs" "no live jobs" liveAfter
  c <- readCounts
  assertEqual "context freed once" 1 (acCtxFrees c)
  assertEqual "retired once" 1 (acRetirements c)
  assertEqual "backend closed once" 1 (acBackendCloses c)
  assertBalanced "repeated close" c

-- | A failed store close keeps the box slot until a retry succeeds:
-- with one close fault armed, the first close throws, frees no box,
-- and keeps the lock (the world still refuses a reopen); the retry
-- nulls the slot and the world reopens.
caseFailedStoreCloseKeepsBoxSlot :: IO ()
caseFailedStoreCloseKeepsBoxSlot = do
  world <- newMemoryWorld
  inj <- scriptedFaults [FaultClose]
  (tracked, opened) <- trackOpened (memoryStoreThrough world inj asyncAcquisition)
  (counting, readCounts) <- countingAcquisitionOver tracked
  (do
    eBox <- openStoreBoxWith counting nullPtr
    box <- case eBox of
      Right b -> pure b
      Left _ -> assertFailure "store box open failed"
    alloca $ \pBox -> do
      poke pBox box
      r <- try (closeStoreBoxSlotWith counting pBox) :: IO (Either SomeException ())
      case r of
        Left e -> case fromException e of
          Just (StoreIO _) -> pure ()
          _ -> assertFailure ("first close threw, but not the injected failure: " ++ show e)
        Right () -> assertFailure "first close with an armed fault returned normally"
      mid <- peek pBox
      assertBool "failed close keeps the slot" (mid == box)
      cMid <- readCounts
      assertEqual "failed close frees no box" 0 (acBoxFrees cMid)
      held <- openMemoryStore world
      case held of
        Left (StoreSecondWriter _) -> pure ()
        Left e -> assertFailure ("reopen refused, but not by the held lock: " ++ show e)
        Right st -> storeClose st >> assertFailure "reopen succeeded while the lock is held"
      closeStoreBoxSlotWith counting pBox
      after <- peek pBox
      assertBool "retry nulled the slot" (isNull after)
    c <- readCounts
    assertEqual "box freed once on the retry" 1 (acBoxFrees c)
    (refused, why) <- memoryReopenRefused world
    assertBalanced ("memory world reopen: " ++ why) c
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | A store box close killed in the lock wait keeps the box: a
-- sibling parks holding the commit lock, the forked export closer
-- parks behind it in the close wait, and after the kill the slot is
-- intact; once the sibling releases, the store still serves, the
-- retry closes, and the world reopens.
caseBoxCloseKilledInLockWaitKeepsBox :: IO ()
caseBoxCloseKilledInLockWaitKeepsBox = do
  world <- newMemoryWorld
  armed <- newIORef False
  arrived <- newEmptyMVar
  hold <- newEmptyMVar
  let inj = FaultInjector
        { fiFire = \p ->
            if p == FaultBeforeCommit
              then do
                fire <- atomicModifyIORef' armed (\on -> (False, on))
                if fire
                  then putMVar arrived () >> takeMVar hold >> pure False
                  else pure False
              else pure False
        , fiOnMasked = pure ()
        , fiOnResult = \_ -> pure ()
        }
  (tracked, opened) <- trackOpened (memoryStoreThrough world inj asyncAcquisition)
  (counting, readCounts) <- countingAcquisitionOver tracked
  (do
    eBox <- openStoreBoxWith counting nullPtr
    box <- case eBox of
      Right b -> pure b
      Left _ -> assertFailure "store box open failed"
    -- Arm only after the open: seating the home token commits
    -- through the same probe.
    writeIORef armed True
    boxStore <- sbStore <$> deRefStablePtr box
    alloca $ \pBox -> do
      poke pBox box
      sibDone <- newEmptyMVar
      _ <- forkIO $ do
        r <- try (storeCommit boxStore emptyDelta { sdPutMeta = [("sibling-hold", "1")] })
        putMVar sibDone (r :: Either SomeException CommitResult)
      closerRef <- newIORef (Nothing :: Maybe (MVar (Either SomeException ())))
      (do
        within10s "sibling parks holding the commit lock" (takeMVar arrived)
        closedDone <- newEmptyMVar
        closerTid <- mask_ $ do
          tid <- forkIO $ do
            r <- try (haskokiAsyncStoreClose pBox)
            putMVar closedDone (r :: Either SomeException ())
          writeIORef closerRef (Just closedDone)
          pure tid
        awaitBlocked BlockedOnMVar closerTid
        midSlot <- peek pBox
        assertBool "slot intact while the closer parks" (midSlot == box)
        -- The kill goes from a forked thread: the throw only
        -- queues against a parked closer, and the issuer would wedge
        -- behind an undeliverable kill instead of reaching the join.
        _ <- forkIO (killThread closerTid)
        mClosed <- timeout stormScaleBudget (takeMVar closedDone)
        case mClosed of
          Nothing -> do
            -- The release lets the parked pair unwind on its own (the
            -- sibling commits, the closer runs to its pending kill),
            -- so join both before failing: the closer must never
            -- write into the slot after its frame returns.
            putMVar hold ()
            _ <- within10s "sibling joins after release" (takeMVar sibDone)
            _ <- within10s "closer joins after release" (takeMVar closedDone)
            writeIORef closerRef Nothing
            assertFailure "kill not delivered (>300s)"
          Just (Right ()) -> writeIORef closerRef Nothing
          Just (Left e) -> do
            writeIORef closerRef Nothing
            assertFailure ("closer leaked: " ++ show e)
        killed <- peek pBox
        assertBool "slot intact after the kill" (killed == box)
        putMVar hold ()
        sibRes <- within10s "sibling joins" (takeMVar sibDone)
        case sibRes of
          Right Committed -> pure ()
          other -> assertFailure ("sibling commit failed: " ++ show other)
        -- The killed close never ran its tail: the handle still
        -- serves, which is the open-handle observation.
        eToks <- storeLoadTokens boxStore
        case eToks of
          Right _ -> pure ()
          Left e -> assertFailure ("store stopped serving after the killed close: " ++ show e)
        closeStoreBoxSlotWith counting pBox
        after <- peek pBox
        assertBool "retry nulled the slot" (isNull after)
        haskokiAsyncStoreClose pBox
        afterSecond <- peek pBox
        assertBool "slot stays nulled" (isNull afterSecond))
        `finally` (do
          _ <- tryPutMVar hold ()
          mDone <- readIORef closerRef
          case mDone of
            Nothing -> pure ()
            Just done -> do
              _ <- within10s "closer joins after release" (takeMVar done)
              pure ())
    c <- readCounts
    assertEqual "box freed once on the retry" 1 (acBoxFrees c)
    assertEqual "store closed once on the retry" 1 (acStoreCloses c)
    (refused, why) <- memoryReopenRefused world
    assertBalanced ("memory world reopen: " ++ why) c
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | A box close parked at its close step holds the box: with the
-- step armed, the forked close parks before the transfer with the
-- box still live and the slot set; a kill there keeps the slot,
-- and the retry closes and the world reopens. A tail that freed
-- before the park fails the park asserts.
caseBoxCloseStepParksBeforeTransfer :: IO ()
caseBoxCloseStepParksBeforeTransfer = do
  world <- newMemoryWorld
  arrived <- newEmptyMVar
  hold <- newEmptyMVar
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (counting, readCounts) <- countingAcquisitionOver tracked
  let parked = counting { aaCloseStep = putMVar arrived () >> takeMVar hold }
  (do
    eBox <- openStoreBoxWith counting nullPtr
    box <- case eBox of
      Right b -> pure b
      Left _ -> assertFailure "store box open failed"
    alloca $ \pBox -> do
      poke pBox box
      closedDone <- newEmptyMVar
      closerTid <- forkIO $ do
        r <- try (closeStoreBoxSlotWith parked pBox)
        putMVar closedDone (r :: Either SomeException ())
      closerRef <- newIORef (Just closedDone)
      (do
        within10s "closer parks at the close step" (takeMVar arrived)
        cPark <- readCounts
        assertEqual "box alive at the park" 0 (acBoxFrees cPark)
        midSlot <- peek pBox
        assertBool "slot set at the park" (midSlot == box)
        -- The kill goes from a forked thread: the throw only
        -- queues against a parked closer, and the issuer would wedge
        -- behind an undeliverable kill instead of reaching the join.
        _ <- forkIO (killThread closerTid)
        mClosed <- timeout stormScaleBudget (takeMVar closedDone)
        case mClosed of
          Nothing -> do
            putMVar hold ()
            _ <- within10s "closer joins after release" (takeMVar closedDone)
            writeIORef closerRef Nothing
            assertFailure "kill not delivered (>300s)"
          Just (Right ()) -> do
            writeIORef closerRef Nothing
            assertFailure "kill swallowed: close returned normally"
          Just (Left e) -> case fromException e of
            Just ThreadKilled -> writeIORef closerRef Nothing
            _ -> do
              writeIORef closerRef Nothing
              assertFailure ("closer leaked: " ++ show e)
        killed <- peek pBox
        assertBool "slot intact after the kill" (killed == box)
        cKill <- readCounts
        assertEqual "kill freed no box" 0 (acBoxFrees cKill)
        closeStoreBoxSlotWith counting pBox
        after <- peek pBox
        assertBool "retry nulled the slot" (isNull after)
        haskokiAsyncStoreClose pBox
        afterSecond <- peek pBox
        assertBool "slot stays nulled" (isNull afterSecond))
        `finally` (do
          _ <- tryPutMVar hold ()
          mDone <- readIORef closerRef
          case mDone of
            Nothing -> pure ()
            Just done -> do
              _ <- within10s "closer joins after release" (takeMVar done)
              pure ())
    c <- readCounts
    assertEqual "box freed once on the retry" 1 (acBoxFrees c)
    assertEqual "one store open" 1 (acStoreOpens c)
    -- The parked closer ran its Store close before the park, and the
    -- retry runs it again over the closed handle: two closes, one
    -- open. Every other counter balances.
    assertEqual "store closed twice across the kill" 2 (acStoreCloses c)
    let ctxt = " (" ++ show c ++ ")"
    assertZero "backend_opens_minus_closes" ("backend opens minus closes" ++ ctxt)
      (acBackendOpens c - acBackendCloses c)
    assertZero "ctx_allocs_minus_frees" ("context allocs minus frees" ++ ctxt)
      (acCtxAllocs c - acCtxFrees c)
    assertZero "box_allocs_minus_frees" ("box allocs minus frees" ++ ctxt)
      (acBoxAllocs c - acBoxFrees c)
    assertZero "registrations_minus_retirements"
      ("registrations minus retirements" ++ ctxt)
      (acRegistrations c - acRetirements c)
    (refused, why) <- memoryReopenRefused world
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | A context close parked at its close step holds the context: with
-- the step armed, the forked close parks after the drain with
-- nothing retired or freed, the slot set, and the gate closing with
-- its closer active; a kill there releases the claim without
-- teardown, and the retry retires, frees and nulls exactly once. A
-- tail that retired or freed before the park fails the park asserts.
caseCtxCloseStepParksBeforeTransfer :: IO ()
caseCtxCloseStepParksBeforeTransfer = do
  world <- newMemoryWorld
  arrived <- newEmptyMVar
  hold <- newEmptyMVar
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (counting, readCounts) <- countingAcquisitionOver tracked
  let parked = counting { aaCloseStep = putMVar arrived () >> takeMVar hold }
  (do
    eBox <- openStoreBoxWith counting nullPtr
    box <- case eBox of
      Right b -> pure b
      Left _ -> assertFailure "store box open failed"
    eCtx <- openAsyncCtxOnWith counting defaultConfig box
    sp <- case eCtx of
      Right s -> pure s
      Left _ -> assertFailure "context open failed"
    ctx <- deRefStablePtr sp
    alloca $ \pCtx -> do
      poke pCtx sp
      closedDone <- newEmptyMVar
      (closerTid, closerRef) <- mask_ $ do
        tid <- forkIO $ do
          r <- try (closeCtxSlotWith parked pCtx)
          putMVar closedDone (r :: Either SomeException ())
        ref <- newIORef (Just closedDone)
        pure (tid, ref)
      (do
        within10s "closer parks at the close step" (takeMVar arrived)
        cPark <- readCounts
        assertEqual "no retirement at the park" 0 (acRetirements cPark)
        assertEqual "no context free at the park" 0 (acCtxFrees cPark)
        midSlot <- peek pCtx
        assertBool "slot set at the park" (midSlot == sp)
        closePark <- inspectTableClose (acTable ctx)
        assertEqual "teardown started, closer active"
          (TableClosing TeardownStarted CloserActive) closePark
        -- The kill goes from a forked thread: the throw only
        -- queues against a parked closer, and the issuer would wedge
        -- behind an undeliverable kill instead of reaching the join.
        _ <- forkIO (killThread closerTid)
        mClosed <- timeout stormScaleBudget (takeMVar closedDone)
        case mClosed of
          Nothing -> do
            putMVar hold ()
            _ <- within10s "closer joins after release" (takeMVar closedDone)
            writeIORef closerRef Nothing
            assertFailure "kill not delivered (>300s)"
          Just (Right ()) -> do
            writeIORef closerRef Nothing
            assertFailure "kill swallowed: close returned normally"
          Just (Left e) -> case fromException e of
            Just ThreadKilled -> writeIORef closerRef Nothing
            _ -> do
              writeIORef closerRef Nothing
              assertFailure ("closer leaked: " ++ show e)
        killed <- peek pCtx
        assertBool "slot intact after the kill" (killed == sp)
        closeMid <- inspectTableClose (acTable ctx)
        assertEqual "teardown started, closer absent"
          (TableClosing TeardownStarted CloserAbsent) closeMid
        cKill <- readCounts
        assertEqual "kill retired nothing" 0 (acRetirements cKill)
        assertEqual "kill freed nothing" 0 (acCtxFrees cKill)
        closeCtxSlotWith counting pCtx
        after <- peek pCtx
        assertBool "retry nulled the slot" (isNull after)
        haskokiAsyncClose pCtx
        afterSecond <- peek pCtx
        assertBool "slot stays nulled" (isNull afterSecond))
        `finally` (do
          _ <- tryPutMVar hold ()
          mDone <- readIORef closerRef
          case mDone of
            Nothing -> pure ()
            Just done -> do
              _ <- within10s "closer joins after release" (takeMVar done)
              pure ())
      alloca $ \pBox -> do
        poke pBox box
        closeStoreBoxSlotWith counting pBox
        afterBox <- peek pBox
        assertBool "box slot nulled" (isNull afterBox))
    `finally` releaseOpened opened
  c <- readCounts
  assertEqual "retired once on the retry" 1 (acRetirements c)
  assertEqual "context freed once on the retry" 1 (acCtxFrees c)
  assertEqual "box freed once" 1 (acBoxFrees c)
  assertEqual "one store open" 1 (acStoreOpens c)
  assertEqual "store closed once" 1 (acStoreCloses c)
  -- The parked closer ran its backend close before the park, and the
  -- retry runs it again over the closed env: two closes, one open.
  assertEqual "one backend open" 1 (acBackendOpens c)
  assertEqual "backend closed twice across the kill" 2 (acBackendCloses c)
  let ctxt = " (" ++ show c ++ ")"
  assertZero "ctx_allocs_minus_frees" ("context allocs minus frees" ++ ctxt)
    (acCtxAllocs c - acCtxFrees c)
  assertZero "box_allocs_minus_frees" ("box allocs minus frees" ++ ctxt)
    (acBoxAllocs c - acBoxFrees c)
  assertZero "registrations_minus_retirements"
    ("registrations minus retirements" ++ ctxt)
    (acRegistrations c - acRetirements c)
  (refused, why) <- memoryReopenRefused world
  assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused

-- | An interrupted residue retry puts back every entry it has not
-- closed: two residue Stores on a private owner, a retry parked in
-- the first close, a kill there — the count stands at two — and the
-- next retry closes both and both worlds reopen. A retry that
-- dropped the put-back loses the entries and fails the count.
caseResidueRetryInterruptedPutsBack :: IO ()
caseResidueRetryInterruptedPutsBack = do
  world1 <- newMemoryWorld
  world2 <- newMemoryWorld
  armed <- newIORef True
  arrived <- newEmptyMVar
  hold <- newEmptyMVar
  owner <- newResidueOwner
  let failing world = do
        (counting, _) <- countingAcquisitionOver asyncAcquisition
          { aaOpenStore = \_ -> do
              r <- openMemoryStore world
              pure $ case r of
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
        pure counting { aaResidue = owner }
  acq1 <- failing world1
  acq2 <- failing world2
  sp1 <- haskokiAsyncStoreOpenWith acq1 nullPtr
  assertBool "first failing open reports NULL" (isNull sp1)
  sp2 <- haskokiAsyncStoreOpenWith acq2 nullPtr
  assertBool "second failing open reports NULL" (isNull sp2)
  queued <- residueCount owner
  assertEqual "two residues queued on the private owner" 2 queued
  (held1, _) <- memoryReopenRefused world1
  assertEqual "first residue keeps its lock" 1 held1
  (held2, _) <- memoryReopenRefused world2
  assertEqual "second residue keeps its lock" 1 held2
  (retryBase, _) <- countingAcquisitionOver asyncAcquisition
  let parked = retryBase
        { aaResidue = owner
        , aaCloseStore = \st -> do
            putMVar arrived ()
            takeMVar hold
            aaCloseStore retryBase st
        }
      plain = retryBase { aaResidue = owner }
  alloca $ \pNull -> do
    poke pNull (castPtrToStablePtr nullPtr)
    done <- newEmptyMVar
    tid <- forkIO $ do
      r <- try (closeCtxSlotWith parked pNull)
      putMVar done (r :: Either SomeException ())
    (do
      within10s "retrier parks in the first close" (takeMVar arrived)
      mid <- residueCount owner
      assertEqual "retry holds both entries in flight" 0 mid
      _ <- forkIO (killThread tid)
      mDone <- timeout stormScaleBudget (takeMVar done)
      case mDone of
        Nothing -> do
          putMVar hold ()
          _ <- within10s "retrier joins after release" (takeMVar done)
          assertFailure "kill not delivered (>300s)"
        Just (Right ()) ->
          assertFailure "kill swallowed: retry returned normally"
        Just (Left e) -> case fromException e of
          Just ThreadKilled -> pure ()
          _ -> assertFailure ("retrier leaked: " ++ show e)
      afterKill <- residueCount owner
      assertEqual "killed retry puts back both entries" 2 afterKill)
      `finally` (tryPutMVar hold () >> pure ())
  writeIORef armed False
  alloca $ \pNull -> do
    poke pNull (castPtrToStablePtr nullPtr)
    closeCtxSlotWith plain pNull
  left <- residueCount owner
  assertZero "residue_count" "retry closed both entries" left
  (refused1, why1) <- memoryReopenRefused world1
  assertZero "store_reopen_refused" ("first world reopen: " ++ why1) refused1
  (refused2, why2) <- memoryReopenRefused world2
  assertZero "store_reopen_refused" ("second world reopen: " ++ why2) refused2

-- | Standalone churn leaves no orphan roots or native envs: fifty
-- rounds of a box open, two contexts on it, one killed
-- third-context acquisition cycling through the on-box steps, and
-- the closes. Registrations balance retirements, allocs balance
-- frees, reclamation drains, and the gate holds no env.
caseStandaloneChurnLeavesNoOrphans :: IO ()
caseStandaloneChurnLeavesNoOrphans = withOwnGate $ \g -> do
  world <- newMemoryWorld
  (tracked, opened) <- trackOpened
    (gatedBackendSteps g (memoryStoreSteps world asyncAcquisition))
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do
    let steps = [AfterStoreReload, AfterBackendOpen, AfterSessionOpen, AfterCtxAlloc]
    mapM_ (\i -> do
      eBox <- openStoreBoxWith acq nullPtr
      box <- case eBox of
        Right b -> pure b
        Left _ -> assertFailure ("round " ++ show i ++ ": box open failed")
      eC1 <- openAsyncCtxOnWith acq defaultConfig box
      c1 <- case eC1 of
        Right s -> pure s
        Left _ -> assertFailure ("round " ++ show i ++ ": first context open failed")
      eC2 <- openAsyncCtxOnWith acq defaultConfig box
      c2 <- case eC2 of
        Right s -> pure s
        Left _ -> assertFailure ("round " ++ show i ++ ": second context open failed")
      killVictimAt (parkAt (steps !! (i `mod` length steps))) acq
        (\a -> openAsyncCtxOnWith a defaultConfig box)
      alloca $ \pCtx -> do
        poke pCtx c1
        closeCtxSlotWith acq pCtx
        afterFirst <- peek pCtx
        assertBool ("round " ++ show i ++ ": first context slot nulled") (isNull afterFirst)
      alloca $ \pCtx -> do
        poke pCtx c2
        closeCtxSlotWith acq pCtx
        afterSecond <- peek pCtx
        assertBool ("round " ++ show i ++ ": second context slot nulled") (isNull afterSecond)
      alloca $ \pBox -> do
        poke pBox box
        closeStoreBoxSlotWith acq pBox
        afterBox <- peek pBox
        assertBool ("round " ++ show i ++ ": box slot nulled") (isNull afterBox)) [0 .. 49 :: Int]
    c <- readCounts
    (refused, why) <- memoryReopenRefused world
    assertBalanced ("memory world reopen: " ++ why) c
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused
    awaitNoPendingReclaims
    awaitReclaimBalanced
    envOut <- c_ownGateEnvOutstanding g
    assertZero "env_outstanding" "native envs left on the gate" envOut
    envDf <- c_ownEnvDoublefree
    assertZero "env_doublefree" "no native double free" envDf)
    `finally` releaseOpened opened

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

-- | Joined cleanup lets the same store reopen: the shared
-- detach-kill-close-reopen-rejoin skeleton over a memory world. The
-- same world reopens and the detached job rejoins exactly once.
caseJoinedCleanupReopensSameStore :: IO ()
caseJoinedCleanupReopensSameStore = do
  world <- newMemoryWorld
  (tracked, opened) <- trackOpened (memoryStoreSteps world asyncAcquisition)
  (acq, readCounts) <- countingAcquisitionOver tracked
  (do
    ctx2 <- joinedCleanupReopen acq (\a -> openStoreBoxWith a nullPtr)
    nLive <- asyncLiveHandles ctx2
    assertZero "live_handles" "no live handles" nLive
    (liveAfter, _, _) <- tableStats (acTable ctx2)
    assertZero "live_jobs" "no live jobs" liveAfter
    c <- readCounts
    (refused, why) <- memoryReopenRefused world
    assertBalanced ("memory world reopen: " ++ why) c
    assertZero "store_reopen_refused" ("memory world reopen: " ++ why) refused)
    `finally` releaseOpened opened

-- | Joined cleanup lets the same SQLite store reopen: the shared
-- detach-kill-close-reopen-rejoin skeleton over a SQLite path. The
-- same path reopens and the detached job rejoins exactly once.
caseJoinedCleanupReopensSameSqliteStore :: IO ()
caseJoinedCleanupReopensSameSqliteStore = withPrivateDir $ \dir -> do
  let path = dir </> "store.sqlite"
  (counting, readCounts) <- countingAcquisition
  (acq, opened) <- trackOpened counting
  (do
    ctx2 <- joinedCleanupReopen acq (\a -> withCString path (openStoreBoxWith a))
    nLive <- asyncLiveHandles ctx2
    assertZero "live_handles" "no live handles" nLive
    (liveAfter, _, _) <- tableStats (acTable ctx2)
    assertZero "live_jobs" "no live jobs" liveAfter
    c <- readCounts
    r <- openSQLiteStore path
    (refused, why) <- case r of
      Right st -> storeClose st >> pure (0 :: Int, "reopened")
      Left e -> pure (1, show e)
    assertBalanced ("sqlite reopen: " ++ why) c
    assertZero "store_reopen_refused" ("sqlite reopen: " ++ why) refused)
    `finally` releaseOpened opened
