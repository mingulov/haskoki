{- | Attached-async FFI surface: attached job handles with poll\/complete
semantics over the 'Haskoki.Runtime.Async' table.

An 'AsyncCtx' is a caller-owned context (model environment, live
OpenSSL4 backend, one proof session, one job table, one live-handle
set), opened and closed like the crypto context. Jobs are opaque
'JobHandle' tokens: submission admits exactly one native handle,
and every terminal path (complete, cancel, drive-error, close-drain)
retires it. Late use of a retired handle is a typed stale
refusal, never a use-after-free (handles resolve through the
private key lookup; no handle is ever dereferenced).

Result delivery targets the pinned @CK_ASYNC_DATA@ layout (offsets
in @tests\/c\/layout_320.c@): byte completions land in the caller's
@pValue@ buffer with @ulValue@ sizing, handle completions land in
@hObject@\/@hAdditionalObject@ with the value buffer untouched.
Pending paths leave the whole struct unchanged; a null @pValue@
with a ready bytes job is a sizing probe (reports the need, holds
the result).

Function codes are explicit poller identity (1 = sign, 2 = digest);
This surface routes byte jobs only — key-template submission for handle jobs
is future work, and their struct delivery is covered at the sink
level. A wrong-function poller is refused with the job intact.

Detach and rejoin run over a process-level store. A 'StoreBox'
owns one durable store (memory world or SQLite file) plus its detach
state, OUTSIDE any provider generation's lifetime; contexts open on
it with 'haskokiAsyncOpenOn' (which reloads token metadata\/objects
into the fresh model). 'haskokiAsyncGetId' detaches a live job into
a persistent id (revoking the old handle); 'haskokiAsyncJoin'
reattaches a persistent id as a fresh live job. Closing a context
retires only its own table's attachments — sibling contexts on
the same store keep theirs. Contexts opened
without a store ('haskokiAsyncOpen') cannot detach or join — there
is nowhere durable to put the record — and report typed failures.

Concurrency (handle resolution under concurrent retirement).
Job handles are pure key tokens, not heap references: each handle
packs its table's exact salt (high 32 bits, nonzero) with its job id
(low 32 bits), and the per-context live set is the
admission\/retirement registry — admission inserts the key,
retirement deletes it, and resolution decodes the key and checks
membership, all without dereferencing any caller-supplied
pointer. A handle retired by a concurrent terminal path therefore
resolves stale (typed refusal), never dangling: there is no
check-then-deref window, no per-job 'StablePtr' allocation to
leak, and nothing to free. The salt keeps live handles distinct
across contexts sharing numeric job ids (fresh tables all start
at 0). Admission and retirement run masked single atomic steps;
resolution is a pure read. The registry path takes no locks, so
it cannot invert with the per-job delivery leases — every job
operation runs strictly after its resolution returns.

Standalone ownership (caller-owned contexts and store boxes).
Each standalone context and store box is owned by the caller
that opened it and is closed explicitly ('haskokiAsyncClose',
'haskokiAsyncStoreClose'). Close is cancellable at every
blocking wait but the bounded SQLite busy waits inside FFI calls:
a close canceled in the borrower wait reopens the context; one
canceled past it leaves the context owned by its slot in a closing
state that admits nothing, and the next close through the slot
resumes teardown where it stopped. A failed or
canceled box close likewise keeps its slot until a retry closes
for real. Callers close every context on a box — and join their
calls — before closing the box, and never close one slot
concurrently from two threads. The masked return of an open
helper is the ownership transfer point: a Haskell caller that
must not lose the pointer acquires under 'mask' (see
'openAsyncCtxWith'). A Store no caller can receive is recovered
by the next standalone open or close in the process; until then
its lock stays held (see 'ResidueOwner').
-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoki.FFI.Async
  ( AsyncCtx (..)
  , AsyncData
  , JobHandle
  , StoreBox (..)
  , AsyncAcquisition (..)
  , AcquireStep (..)
  , AcquireFailure (..)
  , ResidueOwner
  , newResidueOwner
  , residueCount
  , residueAnomalies
  , asyncAcquisition
  , openStoreBoxWith
  , openAsyncCtxWith
  , openAsyncCtxOnWith
  , closeCtxSlotWith
  , closeStoreBoxSlotWith
  , asyncLiveHandles
  , asyncCloseCtx
  , allocJobHandle
  , freeJobHandle
  , resolveJobHandle
  , encodeJobHandle
  , decodeJobHandle
  , registerFixtureCtx
  , registerBorrowedCtx
  , retireCtx
  , setEnterTestHook
  , ctxPendingReclaims
  , ctxReclaimStats
  , ctxAcquireBorrowTest
  , ctxReleaseBorrowTest
  , submitTransfer
  , joinTransfer
  , joinAcquireTransfer
  , rvOf
  , jobFunctionCode
  , codeJobFunction
  , decodeAsyncFunctionName
  , pokeCompletion
  , pokeNeed
  , haskokiAsyncOpen
  , haskokiAsyncOpenWith
  , haskokiAsyncClose
  , haskokiAsyncDigestInit
  , haskokiAsyncStart
  , haskokiAsyncPoll
  , haskokiAsyncComplete
  , haskokiAsyncCancel
  , haskokiAsyncStoreOpen
  , haskokiAsyncStoreOpenWith
  , haskokiAsyncStoreClose
  , haskokiAsyncOpenOn
  , haskokiAsyncOpenOnWith
  , haskokiAsyncGetId
  , haskokiAsyncJoin
  ) where

import Control.Exception
  ( SomeAsyncException
  , SomeException
  , catch
  , finally
  , fromException
  , mask
  , mask_
  , onException
  , throwIO
  , try
  , uninterruptibleMask_
  )
import Data.Bits ((.&.), (.|.), shiftL)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCString)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Word (Word32, Word8, Word64)
import Foreign.C.String (CString, peekCString)
import Foreign.C.Types (CInt (..), CULLong (..), CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr, ptrToWordPtr, wordPtrToPtr)
import Foreign.StablePtr
  ( StablePtr
  , castPtrToStablePtr
  , castStablePtrToPtr
  , deRefStablePtr
  , freeStablePtr
  , newStablePtr
  )
import Foreign.Storable (peek, poke, peekByteOff)

import Haskoki.CallWork (checkedCallWork)
import Haskoki.Engine.Backend (BackendEnv, CryptoBackend (..), EngineResult (..))
import Haskoki.Engine.Driver (drainReleases, encodeResult, runEffect)
import Haskoki.Engine.OpenSSL4 (OpenSSL4)
import Haskoki.FFI.Decode (decodeInputBytes)
import Haskoki.FFI.Exports (returnCodeToRV)
import Haskoki.Model (Model (..))
import Haskoki.Outcome
  ( EffectRequest (..)
  , ModelFault (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  )
import Haskoki.Output (maxOutputBytes)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request
  ( DecodedRequest (..)
  , FunctionId (..)
  , InitFunction (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  )
import Haskoki.Runtime.Catalog (asyncHomeEntry)
import Haskoki.Runtime.Async
  ( AsyncTable
  , AsyncWork (..)
  , CancelOutcome (..)
  , CompleteOutcome (..)
  , Completion (..)
  , Delivery (..)
  , EffectRunner
  , JobFunction (..)
  , JobRequest (..)
  , PollOutcome (..)
  , StartDeny (..)
  , asyncTableId
  , asyncTableSalt
  , awaitTableQuiescent
  , beginTableTeardown
  , claimTableClose
  , finishTableClose
  , releaseTableClose
  , enterTableUse
  , exitTableUse
  , jobFunctionOf
  , TerminalState (..)
  , cancelJob
  , completeJob
  , decodeCompletion
  , enableAsyncSession
  , jobReadyNeed
  , pollJob
  , startJob
  , tryNewAsyncTable
  )
import Haskoki.Runtime.Detached
  ( DetachCtx
  , DetachOutcome (..)
  , JoinOutcome (..)
  , JoinRequest (..)
  , JoinedComplete (..)
  , cancelJoined
  , completeJoined
  , detachCode
  , detachJob
  , joinCode
  , joinJob
  , openDetached
  , retireLiveTableFor
  )
import Haskoki.Runtime.Config (Config, newConfigCell, resolveOnce)
import Haskoki.Runtime.Lifecycle
  ( Env
  , defaultInitArgs
  , envRules
  , initialize
  , newEnv
  , publish
  , restoreStoreState
  , rulesFromConfig
  , seatToken
  , snapshotModel
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , CredentialRecord (..)
  , Store (..)
  , StoreDelta (..)
  , TokenRecord (..)
  , emptyDelta
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStore)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Transition (finishEffect, planCall, planDecoded)
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , JobId (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

-- ---------------------------------------------------------------------------
-- Context and handles
-- ---------------------------------------------------------------------------

-- | A caller-owned async context: environment, live backend, the one
-- proof session, the attached-job table, the live native-handle
-- set, and the optional detach state (present exactly when the
-- context opened on a process-level store). Fields are exported for
-- test inspection.
data AsyncCtx = AsyncCtx
  { acEnv :: !Env
  , acBackend :: !(BackendEnv OpenSSL4)
  , acSession :: !SessionId
  , acTable :: !AsyncTable
  , acLive :: !(IORef (Set (Ptr ())))
  , acDetach :: !(Maybe DetachCtx)
  }

-- | A caller-owned process-level store: one durable store (memory
-- world or SQLite file) plus its detach state. Outlives every
-- context opened on it; contexts come and go (finalize\/reinit,
-- process exit\/reopen) while the box keeps the durable truth.
-- Callers must close every context on a box (and join their calls)
-- before closing the box, and never close one box slot
-- concurrently from two threads: only a serialized box lifetime is
-- supported.
data StoreBox = StoreBox
  { sbStore :: !Store
  , sbDetach :: !DetachCtx
  }

-- | The home token of an async proof store.
storeHomeToken :: TokenId
storeHomeToken = TokenId 1

-- | The @CK_ASYNC_DATA@ shape, manipulated by pinned offsets.
data AsyncData

-- | One opaque native job token. The 'StablePtr' value is a pure
-- key token (context salt plus job id, never NULL for an admitted
-- handle), not a heap reference: nothing ever dereferences or
-- frees a job handle, so concurrent retirement cannot dangle a
-- resolution. The type is an empty phantom tag — handles are
-- admitted and resolved through the key codec below, never
-- through heap values.
data JobHandle

-- | Live-job table capacity per context.
ctxCapacity :: Int
ctxCapacity = 8

-- | The attached-format result version poked on delivery.
asyncVersion :: Word64
asyncVersion = 1

-- | Function code mapping (explicit poller identity).
jobFunctionCode :: JobFunction -> Word64
jobFunctionCode JobSign = 1
jobFunctionCode JobDigest = 2
jobFunctionCode JobGenKey = 3
jobFunctionCode JobGenKeyPair = 4

-- | Decode a function code. This surface submits byte jobs only; handle
-- codes decode (typed) but have no submission path yet.
codeJobFunction :: Word64 -> Maybe JobFunction
codeJobFunction 1 = Just JobSign
codeJobFunction 2 = Just JobDigest
codeJobFunction 3 = Just JobGenKey
codeJobFunction 4 = Just JobGenKeyPair
codeJobFunction _ = Nothing

-- | Decode an exact public byte-job selector, reading at most 32 bytes
-- and stopping at the first NUL. Structural guards validate the pointer.
decodeAsyncFunctionName :: Ptr Word8 -> IO (Either ReturnCode JobFunction)
decodeAsyncFunctionName ptr = go 0 []
  where
    go :: Int -> [Word8] -> IO (Either ReturnCode JobFunction)
    go offset bytes
      | offset >= 32 = pure (Left CKR_ARGUMENTS_BAD)
      | otherwise = do
          byte <- peekByteOff ptr offset
          if byte == 0
            then pure $ case BS.pack (reverse bytes) of
              "C_Sign" -> Right JobSign
              "C_Digest" -> Right JobDigest
              _ -> Left CKR_ARGUMENTS_BAD
            else go (offset + 1) (byte : bytes)

-- | Live native-handle count (test inspection).
asyncLiveHandles :: AsyncCtx -> IO Int
asyncLiveHandles ctx = Set.size <$> readIORef (acLive ctx)

-- ---------------------------------------------------------------------------
-- Export boundary helpers (mirroring Haskoki.FFI.Exports)
-- ---------------------------------------------------------------------------

toRV :: Word64 -> CULong
toRV = CULong

rvOf :: ReturnCode -> CULong
rvOf = CULong . fromIntegral . returnCodeToRV

guarded :: IO CULong -> IO CULong
guarded body = do
  r <- try body
  case r of
    Right rv -> pure rv
    Left (_ :: SomeException) -> pure (toRV 0x05)

guardedPtr :: IO (StablePtr a) -> IO (StablePtr a)
guardedPtr body = do
  r <- try body
  case r of
    Right p -> pure p
    Left (_ :: SomeException) -> pure (castPtrToStablePtr nullPtr)

guardedUnit :: IO () -> IO ()
guardedUnit body = do
  r <- try body
  case r of
    Right () -> pure ()
    Left (_ :: SomeException) -> pure ()

isNullStable :: StablePtr a -> Bool
isNullStable p = castStablePtrToPtr p == nullPtr

-- | Admit one export call against the table's close gate: the
-- null check, the registry admission, and the dereference run
-- masked as one entry step (no interruptible operation inside, so
-- no kill can split them), and the admitted borrower holds its
-- count across the whole call — close claims the gate and waits
-- the count out before it drains or frees anything. Null,
-- unknown, and retired contexts refuse identically, before
-- touching any state.
withCtx :: StablePtr AsyncCtx -> (AsyncCtx -> IO CULong) -> IO CULong
withCtx ctx k = guarded $ mask $ \restore -> do
  mC <- enterCtx ctx
  case mC of
    Nothing -> pure (toRV 0x05)
    Just c -> restore (k c) `finally` exitTableUse (acTable c)

-- | One registry entry: a live owned context behind its table, a
-- live borrowed view behind its table (admit-only: never teardown
-- authority), or a tombstone left by a closed one. Tombstones
-- persist until their pointer value is reused (the new owner
-- re-registers over its own tombstone): one small entry per close
-- keeps every owned and borrowed lifetime distinguishable without
-- dereferencing.
data CtxEntry
  = CtxLive !AsyncTable
  | CtxBorrowed !AsyncTable
  | CtxRetired

-- | Process-wide registry of async contexts, C-owned (see
-- @cbits/context_registry.c@): pointer bits to the context entry,
-- plus the TEST-ONLY per-pointer entry hooks. The opens
-- ('haskokiAsyncOpen', 'haskokiAsyncOpenOn') register before their
-- pointer escapes; the winning slot-close retires before it frees.
-- Borrowed views register at creation and retire at release the
-- same way. A live entry always names a live pointer; a tombstone
-- always refuses without dereferencing; an absent key (never
-- registered: a foreign value, or a hook-only park) refuses the
-- same way, before any dereference. A caller that uses a context
-- pointer after its close completed, and lands on a pointer value
-- the allocator has reused for a new live owner, is admitted to
-- the new owner (documented ABA: memory-safe, since the new owner's
-- close drains admitted borrowers, but the application used a
-- closed handle). A hook runs after its pointer's
-- null check and before its registry lookup — the exact interval
-- a racing close can complete in — so a barrier test parks a
-- caller there deterministically. Scoped per pointer (never
-- process-wide), so parallel tests never observe each other's
-- hooks; retirement clears the entry's hook in the same locked
-- step as the tombstone, so a reused pointer value can never fire
-- a stale hook. Production leaves every entry hookless, paying
-- one locked lookup per entry.
--
-- The Haskell side holds no process-wide cell: every accessor here
-- is one narrow call into the C table (the table-mint precedent).
-- Table and hook references cross as 'StablePtr's with borrower-safe
-- reclamation: a lookup that hands one out holds a borrow on its
-- entry, the caller dereferences and then releases (dereference
-- strictly before release, both adjacent to the lookup, under a
-- mask). Every displaced root queues on its entry, however many
-- displacements stack while borrows stand, and every accessor
-- drains taken roots below: a root frees only when its entry holds
-- no borrow, every root is preserved until freed, and nothing
-- stands retained past joined teardown.
--
-- Tests pin orphan-root freedom through the registration\/
-- retirement balance plus the reclaim polls
-- ('ctxPendingReclaims'\/'ctxReclaimStats', polled to balance by
-- @awaitNoPendingReclaims@ and @awaitReclaimBalanced@ in
-- @tests\/model\/FfiAsyncSpec.hs@): the balance covers
-- record-side roots, the polls cover every queued root
-- process-wide.
foreign import ccall unsafe "haskoki_ctx_register"
  c_ctxRegister :: Ptr () -> CInt -> StablePtr AsyncTable -> IO ()

foreign import ccall unsafe "haskoki_ctx_retire"
  c_ctxRetire :: Ptr () -> IO ()

foreign import ccall unsafe "haskoki_ctx_lookup_acquire"
  c_ctxLookupAcquire :: Ptr () -> Ptr (StablePtr AsyncTable) -> IO CInt

foreign import ccall unsafe "haskoki_ctx_hook_set"
  c_ctxHookSet :: Ptr () -> StablePtr (IO ()) -> IO ()

foreign import ccall unsafe "haskoki_ctx_hook_acquire"
  c_ctxHookAcquire :: Ptr () -> Ptr (StablePtr (IO ())) -> IO CInt

foreign import ccall unsafe "haskoki_ctx_release"
  c_ctxRelease :: Ptr () -> IO ()

foreign import ccall unsafe "haskoki_ctx_take_reclaimable"
  c_ctxTakeReclaimable :: Ptr (StablePtr ()) -> IO CInt

foreign import ccall unsafe "haskoki_ctx_note_freed"
  c_ctxNoteFreed :: CInt -> IO ()

foreign import ccall unsafe "haskoki_ctx_pending"
  c_ctxPending :: IO CInt

foreign import ccall unsafe "haskoki_ctx_stats"
  c_ctxStats :: Ptr CULLong -> Ptr CULLong -> Ptr CULLong -> IO ()

-- The process residue cell (C-owned, beside the registry; see
-- 'ResidueOwner'): one locked step per call, no callbacks.
foreign import ccall unsafe "haskoki_residue_reserve"
  c_residueReserve :: IO CInt

foreign import ccall unsafe "haskoki_residue_release"
  c_residueRelease :: IO ()

foreign import ccall unsafe "haskoki_residue_push"
  c_residuePush :: StablePtr Store -> IO CInt

foreign import ccall unsafe "haskoki_residue_take"
  c_residueTake :: Ptr (StablePtr Store) -> IO CInt

foreign import ccall unsafe "haskoki_residue_put_back"
  c_residuePutBack :: StablePtr Store -> IO ()

foreign import ccall unsafe "haskoki_residue_note_closed"
  c_residueNoteClosed :: CInt -> IO ()

foreign import ccall unsafe "haskoki_residue_count"
  c_residueCount :: IO CInt

foreign import ccall unsafe "haskoki_residue_anomalies"
  c_residueAnomalies :: IO CULLong

-- | Free one root the C table handed back for reclamation (a null
-- root means nothing to free). Roots are opaque addresses: table
-- and hook roots share one representation.
reclaimOne :: StablePtr a -> IO ()
reclaimOne s =
  if isNullStable s then pure () else freeStablePtr s

-- | Drain every reclaimable root: take each one whose entry holds
-- no borrow, free it, and report the batch. Masked throughout, so
-- no kill can strand a taken root between its take and its free.
drainReclaims :: IO ()
drainReclaims = mask_ $ alloca $ \pRoot -> go pRoot 0
  where
    go pRoot n = do
      more <- c_ctxTakeReclaimable pRoot
      if more == 0
        then if n == 0 then pure () else c_ctxNoteFreed n
        else do
          peek pRoot >>= reclaimOne
          go pRoot (n + 1)

-- | Release one borrowed-root hold, then drain: the release may
-- open its entry's queued roots for reclamation.
releaseCtxBorrow :: Ptr () -> IO ()
releaseCtxBorrow key = do
  c_ctxRelease key
  drainReclaims

-- | TEST-ONLY: live reclamation backlog — queued displaced roots.
-- Drains to zero at quiescence; anything standing past joined
-- teardown is stranded.
ctxPendingReclaims :: IO Int
ctxPendingReclaims = fromIntegral <$> c_ctxPending

-- | TEST-ONLY: independent displaced/taken/freed accounting —
-- every displaced root is taken exactly once and freed exactly
-- once, so the three balance at quiescence.
ctxReclaimStats :: IO (Word64, Word64, Word64)
ctxReclaimStats =
  alloca $ \pD -> alloca $ \pT -> alloca $ \pF -> do
    c_ctxStats pD pT pF
    d <- peek pD
    t <- peek pT
    f <- peek pF
    pure (fromIntegral d, fromIntegral t, fromIntegral f)

-- | The registry key of a context pointer: its bare bits, which
-- need no dereference to read.
ctxKey :: StablePtr AsyncCtx -> Ptr ()
ctxKey sp = castPtr (castStablePtrToPtr sp)

-- | TEST-ONLY: register a hand-built fixture context under its
-- pointer. Tests register their pointers this way before driving
-- them through the exports. No caller under @ffi/@ or @src/@ may
-- use this; production opens adopt through 'registerOwnedCtx'
-- (via 'adoptCtx').
registerFixtureCtx :: StablePtr AsyncCtx -> AsyncTable -> IO ()
registerFixtureCtx = registerOwnedCtx

-- | Register an owned context under its pointer: the production
-- adoption step ('aaRegisterCtx' of 'asyncAcquisition'), run masked
-- with the allocation, before the pointer escapes. Overwrites that
-- value's tombstone (left by an owned or borrowed close) when the
-- allocator reuses a freed pointer value, under the new owner's
-- table. All or nothing: only the root allocation can throw, and it
-- runs before the registry call, so a throw leaves the pointer
-- unregistered and the adoption cleanup frees it without a
-- retirement.
registerOwnedCtx :: StablePtr AsyncCtx -> AsyncTable -> IO ()
registerOwnedCtx sp table = mask_ $ do
  stable <- newStablePtr table
  c_ctxRegister (ctxKey sp) 1 stable
  drainReclaims

-- | Register a borrowed view under its pointer: admit-only, never
-- teardown authority — the view's table and backend stay owned by
-- Standard. The Standard surface calls this masked with the
-- allocation, before the pointer escapes, and retires at view
-- release. Overwrites that value's tombstone when the allocator
-- reuses a freed pointer value, so a valid borrowed view on a
-- recycled index admits while genuinely retired contexts stay
-- refused. Borrowed Standard views are internal and serialized by
-- the C state lock; concurrent direct borrowed-view use is not
-- offered.
registerBorrowedCtx :: StablePtr AsyncCtx -> AsyncTable -> IO ()
registerBorrowedCtx sp table = mask_ $ do
  stable <- newStablePtr table
  c_ctxRegister (ctxKey sp) 2 stable
  drainReclaims

-- | Retire a context's registration: the entry becomes a
-- tombstone that refuses without dereferencing, and the entry's
-- test hook (if any) clears in the same step. The winning
-- slot-close calls this after teardown and before it frees the
-- pointer, and borrowed-view release calls this before it frees
-- the view: retire strictly before free, so a caller resuming
-- after the close — even one that passed its null check before
-- it — meets the tombstone and refuses instead of dereferencing
-- a freed pointer.
retireCtx :: StablePtr AsyncCtx -> IO ()
retireCtx sp = mask_ $ do
  c_ctxRetire (ctxKey sp)
  drainReclaims

-- | TEST-ONLY: arm ('Just') or clear ('Nothing') a pointer's
-- entry hook. Production leaves every entry hookless, paying
-- one locked lookup per entry.
setEnterTestHook :: StablePtr AsyncCtx -> Maybe (IO ()) -> IO ()
setEnterTestHook sp mHook = mask_ $ case mHook of
  Just hook -> do
    stable <- newStablePtr hook
    c_ctxHookSet (ctxKey sp) stable
    drainReclaims
  Nothing -> do
    c_ctxHookSet (ctxKey sp) (castPtrToStablePtr nullPtr)
    drainReclaims

-- | TEST-ONLY: hold one borrow on a pointer's entry without
-- dereferencing, for deterministic overlap coverage. Pairs with
-- 'ctxReleaseBorrowTest'; production borrows always pair inside
-- the lookup they came from.
ctxAcquireBorrowTest :: StablePtr AsyncCtx -> IO ()
ctxAcquireBorrowTest sp = mask_ $ alloca $ \pTable -> do
  _ <- c_ctxLookupAcquire (ctxKey sp) pTable
  pure ()

-- | TEST-ONLY: release one borrow held by 'ctxAcquireBorrowTest',
-- then drain.
ctxReleaseBorrowTest :: StablePtr AsyncCtx -> IO ()
ctxReleaseBorrowTest sp = mask_ $ releaseCtxBorrow (ctxKey sp)

-- | Dereference one acquired live entry and release the borrow:
-- the StablePtr mapping is read strictly before the release, so
-- the root cannot free underneath the dereference.
derefAcquired :: Ptr () -> Ptr (StablePtr AsyncTable)
              -> (AsyncTable -> CtxEntry) -> IO (Maybe CtxEntry)
derefAcquired key pTable con = do
  stable <- peek pTable
  table <- deRefStablePtr stable
  releaseCtxBorrow key
  pure (Just (con table))

-- | Look up the entry behind a context pointer. A single locked
-- acquire plus a borrow release — safe on any pointer value,
-- including stale ones.
lookupCtxEntry :: StablePtr AsyncCtx -> IO (Maybe CtxEntry)
lookupCtxEntry sp = mask_ $ alloca $ \pTable -> do
  kind <- c_ctxLookupAcquire (ctxKey sp) pTable
  case kind of
    1 -> derefAcquired (ctxKey sp) pTable CtxLive
    2 -> derefAcquired (ctxKey sp) pTable CtxBorrowed
    3 -> pure (Just CtxRetired)
    _ -> pure Nothing

-- | Look up a pointer's TEST-ONLY entry hook, when armed. A single
-- locked acquire plus a borrow release — safe on any pointer value.
lookupEnterHook :: StablePtr AsyncCtx -> IO (Maybe (IO ()))
lookupEnterHook sp = mask_ $ alloca $ \pHook -> do
  found <- c_ctxHookAcquire (ctxKey sp) pHook
  if found == 0
    then pure Nothing
    else do
      stable <- peek pHook
      hook <- deRefStablePtr stable
      releaseCtxBorrow (ctxKey sp)
      pure (Just hook)

-- | Masked entry step for 'withCtx': null check, test hook,
-- externally reachable admission, then the dereference.
-- Admission consults the registry — reachable from the bare
-- pointer bits — BEFORE any dereference, so a concurrent
-- slot-close cannot free the pointer between the check and the
-- dereference: either this call admits first (and the close
-- waits it out before freeing), the close claims first (and this
-- call refuses at the gate without dereferencing), or the close
-- completes first (and this call meets the tombstone and refuses
-- without dereferencing). An absent or hook-only key refuses the
-- same way, before any dereference. A stale live-table reference
-- still refuses, because the claim flag persists past retirement.
-- Callers hold the mask; every step here is non-blocking except
-- a test-armed hook, so production entry never parks while
-- masked.
enterCtx :: StablePtr AsyncCtx -> IO (Maybe AsyncCtx)
enterCtx ctx
  | isNullStable ctx = pure Nothing
  | otherwise = do
      mHook <- lookupEnterHook ctx
      case mHook of
        Nothing -> pure ()
        Just hook -> hook
      mEntry <- lookupCtxEntry ctx
      case mEntry of
        Just (CtxLive table) -> do
          ok <- enterTableUse table
          if ok
            then Just <$> deRefStablePtr ctx
            else pure Nothing
        Just (CtxBorrowed table) -> do
          ok <- enterTableUse table
          if ok
            then Just <$> deRefStablePtr ctx
            else pure Nothing
        Just CtxRetired -> pure Nothing
        Nothing -> pure Nothing

-- | Encode a job id as its opaque handle token under the table's
-- exact salt: the high 32 bits carry the salt, the low 32 the
-- job id. The salt is always nonzero, so an admitted key is never
-- NULL. Job ids are table counters starting at 0 and never reused
-- within a table; the salt distinguishes live handles across
-- contexts sharing numeric job ids.
encodeJobHandle :: Word32 -> JobId -> StablePtr JobHandle
encodeJobHandle salt (JobId n) =
  castPtrToStablePtr (wordPtrToPtr key)
  where
    key = fromIntegral salt `shiftL` 32 .|. fromIntegral n

-- | Decode an opaque handle token. NULL decodes to 'Nothing';
-- every other value decodes totally — membership in the caller's
-- live set, checked by 'resolveJobHandle', is what admits or
-- refuses it. Decoding a foreign value (another context's live
-- key, a bogus integer) is pure and safe; it simply fails the
-- membership check of any context that did not admit it.
decodeJobHandle :: StablePtr JobHandle -> Maybe JobId
decodeJobHandle h
  | isNullStable h = Nothing
  | otherwise = Just (JobId (fromIntegral (key .&. 0xFFFFFFFF)))
  where
    key = ptrToWordPtr (castStablePtrToPtr h)

-- | Resolve a live job handle to its job id through the private
-- key lookup: decode plus a membership check against the caller's
-- own live set. No caller-supplied pointer is ever dereferenced,
-- so a handle retired concurrently resolves stale instead of
-- dangling. A pure read — there is no state to corrupt, hence no
-- masking.
resolveJobHandle :: AsyncCtx -> StablePtr JobHandle -> IO (Maybe JobId)
resolveJobHandle ctx h = case decodeJobHandle h of
  Nothing -> pure Nothing
  Just jid -> do
    live <- readIORef (acLive ctx)
    pure (if castStablePtrToPtr h `Set.member` live then Just jid else Nothing)

-- | Resolve a live job handle to its job id. Stale (retired or
-- foreign) tokens refuse without dereferencing. The continuation —
-- and with it the job-lease acquisition — runs strictly after
-- resolution returns, so the lock-free registry path never nests a
-- job operation.
withLiveJob
  :: AsyncCtx -> StablePtr JobHandle -> (JobId -> IO CULong) -> IO CULong
withLiveJob ctx h k
  | isNullStable h = pure (rvOf CKR_ARGUMENTS_BAD)
  | otherwise = do
      mJid <- resolveJobHandle ctx h
      case mJid of
        Nothing -> pure (rvOf CKR_ARGUMENTS_BAD)
        Just jid -> k jid

-- | Retire a job's native handle. Deletion is idempotent, so a
-- racing second terminal path simply deletes nothing; there is no
-- heap allocation behind a handle and nothing to free. Runs masked
-- as a single atomic step.
freeJobHandle :: AsyncCtx -> StablePtr JobHandle -> IO ()
freeJobHandle ctx h = mask_ $
  atomicModifyIORef' (acLive ctx) $ \live ->
    (Set.delete (castStablePtrToPtr h) live, ())

-- | Admit a job's native handle (submission success path only).
-- The salt is the table's exact minted salt (nonzero, distinct
-- per table, stable for the table's life — see 'asyncTableSalt');
-- key derivation is pure and infallible, so allocation cannot
-- leak, and the masked section holds no interruptible operation.
-- Job ids are never reused within a table, so an admitted key is
-- unique among the context's live handles, and distinct tables
-- admit distinct keys for equal numeric job ids. Callers refuse
-- job ids past the 32-bit codec before admitting (see
-- 'jobIdExhausted').
allocJobHandle :: AsyncCtx -> JobId -> IO (StablePtr JobHandle)
allocJobHandle ctx jid = mask_ $ do
  let salt = asyncTableSalt (acTable ctx)
      h = encodeJobHandle salt jid
  atomicModifyIORef' (acLive ctx) $ \live ->
    (Set.insert (castStablePtrToPtr h) live, ())
  pure h

-- | Whether a job id lies past the 32-bit handle codec and must be
-- refused before admission (the codec truncates high bits, so two
-- live jobs 2^32 apart would share a key). Table counters start at
-- 0 and grow by one per job; reaching the bound takes 2^32
-- submissions on one table.
jobIdExhausted :: JobId -> Bool
jobIdExhausted (JobId n) = toInteger n >= 0x100000000 || toInteger n < 0

termCode :: TerminalState -> ReturnCode
termCode (TermDelivered _) = CKR_OK
termCode TermCanceled = CKR_FUNCTION_CANCELED
termCode (TermFailed code _) = code

-- ---------------------------------------------------------------------------
-- Struct sink (pinned CK_ASYNC_DATA offsets, see tests/c/layout_320.c)
-- ---------------------------------------------------------------------------

offVersion, offValue, offValueLen, offObject, offObject2 :: Int
offVersion = 0
offValue = 8
offValueLen = 16
offObject = 24
offObject2 = 32

peekValuePtr :: Ptr AsyncData -> IO (Ptr Word8)
peekValuePtr pS = peekByteOff (castPtr pS) offValue

peekValueCap :: Ptr AsyncData -> IO Word64
peekValueCap pS = do
  CULong n <- peekByteOff (castPtr pS) offValueLen
  pure n

-- | Poke a sizing answer: the length field only.
pokeNeed :: Ptr AsyncData -> Word64 -> IO ()
pokeNeed pS need =
  poke (castPtr pS `plusPtr` offValueLen :: Ptr CULong) (CULong need)

-- | Poke a completion into the struct. Byte payloads copy into the
-- caller's @pValue@ (which the caller sized); handles land in the
-- object fields with the value buffer untouched. Every field is
-- deterministic after a delivery.
pokeCompletion :: Ptr AsyncData -> Completion -> IO ()
pokeCompletion pS completion = do
  poke (castPtr pS `plusPtr` offVersion :: Ptr CULong)
    (CULong asyncVersion)
  case completion of
    CompBytes bs -> do
      pV <- peekValuePtr pS
      unsafeUseAsCString bs $ \src ->
        copyBytes pV (castPtr src) (BS.length bs)
      poke (castPtr pS `plusPtr` offValueLen :: Ptr CULong)
        (CULong (fromIntegral (BS.length bs)))
      poke (castPtr pS `plusPtr` offObject :: Ptr CULong) (CULong 0)
      poke (castPtr pS `plusPtr` offObject2 :: Ptr CULong) (CULong 0)
    CompOneHandle (ExternalHandle h) -> do
      poke (castPtr pS `plusPtr` offObject :: Ptr CULong)
        (CULong (fromIntegral h))
      poke (castPtr pS `plusPtr` offObject2 :: Ptr CULong) (CULong 0)
      poke (castPtr pS `plusPtr` offValueLen :: Ptr CULong) (CULong 0)
    CompTwoHandles (ExternalHandle h1) (ExternalHandle h2) -> do
      poke (castPtr pS `plusPtr` offObject :: Ptr CULong)
        (CULong (fromIntegral h1))
      poke (castPtr pS `plusPtr` offObject2 :: Ptr CULong)
        (CULong (fromIntegral h2))
      poke (castPtr pS `plusPtr` offValueLen :: Ptr CULong) (CULong 0)

-- ---------------------------------------------------------------------------
-- Standalone acquisition seam
-- ---------------------------------------------------------------------------

-- | The points of a standalone open where a resource is held and
-- the next step can block or throw. 'aaStep' runs at each one.
data AcquireStep
  = AfterStoreOpen
    -- ^ the box's Store is open, token setup not yet run
  | AfterTokenSetup
    -- ^ the home token and detach state are ready, no box pointer yet
  | AfterStoreReload
    -- ^ a store-bound context reloaded its tokens, no backend yet
  | AfterBackendOpen
    -- ^ the backend is open, no proof session yet
  | AfterSessionOpen
    -- ^ the proof session is published, no job table yet
  | AfterCtxAlloc
    -- ^ the context pointer is allocated, not yet registered
  deriving (Eq, Show)

-- | Why a typed standalone open returned no handle.
data AcquireFailure
  = AcquireRefused
    -- ^ an explicit refusal (config, init, seating, store, backend,
    -- table allocator)
  | AcquireThrew !SomeException
    -- ^ a synchronous exception from a step, after the cleanup
    -- closed everything the open held (asynchronous ones propagate
    -- instead, after the same cleanup)
  | AcquireResidue !(Maybe SomeException) !SomeException !Store
    -- ^ the primary failure ('Nothing' for a refusal), the cleanup
    -- close error, and the Store the caller now owns: both cleanup
    -- closes failed, and its 'storeClose' retries the close

-- | Owner of the Stores whose cleanup closes failed twice with no
-- caller to receive them: the C exports (which can only report
-- NULL) and an asynchronous primary (which propagates). Reached
-- through 'aaResidue', so a test injects a private owner and never
-- shares the process instance. Every later standalone open and
-- close through a record retries the Stores on that record's owner
-- ('retryResidue') — save the value-level close ('asyncCloseCtx'),
-- a NULL-box open, and the config-failure refusals, which return
-- before the retry — so a residue's lock is recovered by the next
-- retrying open or close in the process; until then it stays held.
data ResidueOwner
  = ProcessResidue
    -- ^ the process instance, used by the production record: the
    -- C-owned residue cell beside the context registry
    -- (@cbits/context_registry.c@). It grows without a fixed bound
    -- and never drops a Store. A box open reserves its slot before
    -- it acquires the Store ('withResidueSlot'), so a later push
    -- always fits; when the cell cannot grow for the reservation,
    -- the open refuses ('AcquireRefused') holding nothing
  | PrivateResidue !(IORef [Store])
    -- ^ a private instance, injected by a test

-- | A fresh, empty private residue owner.
newResidueOwner :: IO ResidueOwner
newResidueOwner = PrivateResidue <$> newIORef []

-- | TEST-ONLY: the number of residue Stores queued on an owner.
-- The process cell also counts entries another thread holds
-- mid-retry; a private owner's in-flight entries are not counted,
-- because the retry takes the whole queue before closing any.
residueCount :: ResidueOwner -> IO Int
residueCount (PrivateResidue ref) = length <$> readIORef ref
residueCount ProcessResidue = fromIntegral <$> c_residueCount

-- | TEST-ONLY: protocol slips the process residue cell recorded (a
-- push or release without a reservation, a put-back with nothing in
-- flight, more closes noted than entries in flight). Zero in a
-- correct run.
residueAnomalies :: IO Word64
residueAnomalies = fromIntegral <$> c_residueAnomalies

-- | One residue slot, reserved on an owner before a box open
-- acquires its Store. At most one push consumes it; the open releases
-- it unconsumed when it ends. The flag is 'True' while the slot is
-- still reserved.
data ResidueSlot = ResidueSlot !ResidueOwner !(IORef Bool)

-- | Run a box open holding one reserved residue slot (masked by the
-- open). Fail closed: when the process cell cannot grow for the
-- reservation, the open refuses before it acquires anything, so a
-- later push can never fail for want of room.
withResidueSlot
  :: ResidueOwner -> (ResidueSlot -> IO (Either AcquireFailure a))
  -> IO (Either AcquireFailure a)
withResidueSlot owner body = do
  reserved <- case owner of
    PrivateResidue _ -> pure True
    ProcessResidue -> (/= 0) <$> c_residueReserve
  if not reserved
    then pure (Left AcquireRefused)
    else do
      held <- newIORef True
      let slot = ResidueSlot owner held
      body slot `finally` releaseUnused slot
  where
    releaseUnused (ResidueSlot o held) = do
      unused <- atomicModifyIORef' held (\h -> (False, h))
      case o of
        ProcessResidue | unused -> c_residueRelease
        _ -> pure ()

-- | Queue a Store no caller can receive on the slot's owner,
-- consuming the slot's reservation, so the push always fits. The
-- root allocation and the push run masked, so no kill can strand the
-- root between them. A second push through one slot (a protocol
-- slip) reserves afresh; if that cannot grow the cell, the Store
-- keeps its root but stays unreachable — a leaked root and lock —
-- rather than being dropped.
pushResidue :: ResidueSlot -> Store -> IO ()
pushResidue (ResidueSlot (PrivateResidue ref) held) st = do
  _ <- atomicModifyIORef' held (\h -> (False, h))
  atomicModifyIORef' ref (\q -> (st : q, ()))
pushResidue (ResidueSlot ProcessResidue held) st = mask_ $ do
  sp <- newStablePtr st
  wasHeld <- atomicModifyIORef' held (\h -> (False, h))
  reserved <- if wasHeld then pure True else (/= 0) <$> c_residueReserve
  if reserved
    then do
      _ <- c_residuePush sp
      pure ()
    else pure ()

-- | Retry every Store queued on the record's residue owner: one
-- close attempt each, through 'aaCloseStore'. A Store that closes
-- leaves the owner (its root is freed); one that fails stays queued
-- for the next retry. Runs masked and is interruptible only inside a
-- close; an interrupted retry puts back every entry it has not
-- closed before the exception propagates. Never uninterruptible.
retryResidue :: AsyncAcquisition -> IO ()
retryResidue acq = mask_ $ case aaResidue acq of
  PrivateResidue ref -> do
    queued <- atomicModifyIORef' ref (\q -> ([], q))
    retryEach (aaCloseStore acq) pure (\_ -> pure ())
      (\st -> atomicModifyIORef' ref (\q -> (st : q, ()))) queued
  ProcessResidue -> do
    roots <- alloca takeAll
    retryEach (aaCloseStore acq) deRefStablePtr
      (\sp -> freeStablePtr sp >> c_residueNoteClosed 1)
      c_residuePutBack roots
  where
    -- Take every queued root before trying any, so a put-back is
    -- never retaken in the same pass.
    takeAll :: Ptr (StablePtr Store) -> IO [StablePtr Store]
    takeAll pRoot = go []
      where
        go acc = do
          more <- c_residueTake pRoot
          if more == 0
            then pure (reverse acc)
            else do
              root <- peek pRoot
              go (root : acc)

-- | One close attempt per queued entry: report a closed entry, put a
-- failed one back, and on an interrupting exception put back the
-- rest before rethrowing it.
retryEach
  :: (Store -> IO ()) -> (a -> IO Store) -> (a -> IO ()) -> (a -> IO ())
  -> [a] -> IO ()
retryEach close storeOf closed putBack = go
  where
    go [] = pure ()
    go (x : rest) = do
      st <- storeOf x
      r <- try (close st)
      case r of
        Right () -> closed x >> go rest
        Left e
          | isAsyncException e -> mapM_ putBack (x : rest) >> throwIO e
          | otherwise -> putBack x >> go rest

-- | Injectable steps of the standalone opens and closes (the
-- 'Haskoki.FFI.Exports.CryptoAcquisition' precedent). Every
-- resource-creating and resource-releasing call of
-- 'openStoreBoxWith', 'openAsyncCtxWith', 'openAsyncCtxOnWith',
-- 'closeCtxSlotWith' and 'closeStoreBoxSlotWith' goes through this
-- record, so a probe counts or fails each one. 'aaStep' is
-- TEST-ONLY: production runs 'pure ()' at every 'AcquireStep', and
-- a test parks or throws there. 'aaCloseStep' is TEST-ONLY too:
-- production runs 'pure ()', and a test parks there to prove the
-- pointer transfer is the one uninterruptible step.
data AsyncAcquisition = AsyncAcquisition
  { aaInit :: !(Env -> IO (Outcome ()))
  , aaOpenBackend :: !(IO (EngineResult (BackendEnv OpenSSL4)))
  , aaCloseBackend :: !(BackendEnv OpenSSL4 -> IO ())
  , aaOpenStore :: !(CString -> IO (Either () Store))
  , aaCloseStore :: !(Store -> IO ())
  , aaNewCtxPtr :: !(AsyncCtx -> IO (StablePtr AsyncCtx))
  , aaFreeCtxPtr :: !(StablePtr AsyncCtx -> IO ())
  , aaRegisterCtx :: !(StablePtr AsyncCtx -> AsyncTable -> IO ())
  , aaRetireCtx :: !(StablePtr AsyncCtx -> IO ())
  , aaNewBoxPtr :: !(StoreBox -> IO (StablePtr StoreBox))
  , aaFreeBoxPtr :: !(StablePtr StoreBox -> IO ())
  , aaStep :: !(AcquireStep -> IO ())
  , aaCloseStep :: !(IO ())
  , aaResidue :: !ResidueOwner
  }

-- | Production acquisition steps.
asyncAcquisition :: AsyncAcquisition
asyncAcquisition = AsyncAcquisition
  { aaInit = \env -> initialize env defaultInitArgs
  , aaOpenBackend = openBackend "provider=default"
  , aaCloseBackend = closeBackend
  , aaOpenStore = openStoreByPath
  , aaCloseStore = storeClose
  , aaNewCtxPtr = newStablePtr
  , aaFreeCtxPtr = freeStablePtr
  , aaRegisterCtx = registerOwnedCtx
  , aaRetireCtx = retireCtx
  , aaNewBoxPtr = newStablePtr
  , aaFreeBoxPtr = freeStablePtr
  , aaStep = const (pure ())
  , aaCloseStep = pure ()
  , aaResidue = ProcessResidue
  }

-- | Sync-failure boundary for the typed opens: an unexpected
-- synchronous exception becomes 'AcquireThrew'; an asynchronous one
-- propagates, so a kill aborts the open instead of being swallowed.
-- The @foreign export@ boundaries keep their catch-all 'guardedPtr'.
guardedAcquire :: IO (Either AcquireFailure a) -> IO (Either AcquireFailure a)
guardedAcquire body = body `catch` \e ->
  if isAsyncException e
    then throwIO e
    else pure (Left (AcquireThrew e))

-- | Whether an exception is asynchronous (a kill, a timeout).
isAsyncException :: SomeException -> Bool
isAsyncException e = case (fromException e :: Maybe SomeAsyncException) of
  Just _ -> True
  Nothing -> False

-- | Close a Store an open still holds, after the open failed. A
-- failed close keeps the handle retriable ('HandleCloseFailed'), so a
-- throwing close is retried once. 'Nothing' when the Store closed;
-- otherwise the last close error, with the Store still open. The
-- close can block (a memory close waits for its commit lock, a SQLite
-- close for its connection guard and the process-level open-path
-- registry); the cleanup runs masked, so it stays interruptible
-- there. An interrupted close is not retried: its exception is
-- returned, and the caller queues the Store as residue.
closeStoreAfter :: AsyncAcquisition -> Store -> IO (Maybe SomeException)
closeStoreAfter acq st = attempt True
  where
    attempt retry = do
      r <- try (aaCloseStore acq st)
      case r of
        Right () -> pure Nothing
        Left e
          | retry && not (isAsyncException e) -> attempt False
          | otherwise -> pure (Just e)

-- | Close a backend an open still holds, after the open failed.
-- 'closeBackend' is idempotent, so a throwing close is retried once;
-- a second failure leaves the env to its 'ForeignPtr' finalizer.
-- Close errors never escape. 'Just' only when an attempt was
-- interrupted, carrying the interrupting exception.
closeBackendAfter :: AsyncAcquisition -> BackendEnv OpenSSL4 -> IO (Maybe SomeException)
closeBackendAfter acq be = attempt True
  where
    attempt retry = do
      r <- try (aaCloseBackend acq be)
      case r of
        Right () -> pure Nothing
        Left e
          | isAsyncException e -> pure (Just e)
          | retry -> attempt False
          | otherwise -> pure Nothing

-- | Hold a Store across the rest of a box open. On a refusal or an
-- exception from the body the Store closes ('closeStoreAfter')
-- before the failure is reported, and the cleanup never replaces
-- the primary: a refusal stays 'AcquireRefused', a synchronous
-- primary becomes 'AcquireThrew', an asynchronous primary is
-- rethrown unchanged. When both cleanup closes fail, a synchronous
-- primary or a refusal hands the Store back ('AcquireResidue');
-- with an asynchronous primary nobody can receive it, so it queues
-- on the open's reserved residue slot. A cleanup interrupted by a
-- kill queues the Store the same way and lets the kill propagate. On
-- success the Store's ownership passes to the body's result.
holdingStore
  :: AsyncAcquisition -> ResidueSlot -> Store
  -> IO (Either AcquireFailure a) -> IO (Either AcquireFailure a)
holdingStore acq slot store body = do
  r <- try body
  case r of
    Right ok@(Right _) -> pure ok
    Right (Left failure) -> release Nothing failure
    Left e -> release (Just e) (AcquireThrew e)
  where
    release mPrimary failure = do
      mErr <- closeStoreAfter acq store
      case (mPrimary, mErr) of
        (Just e, Nothing) | isAsyncException e -> throwIO e
        (Just e, Just _) | isAsyncException e -> queue >> throwIO e
        (_, Nothing) -> pure (Left failure)
        (_, Just cerr)
          | isAsyncException cerr -> queue >> throwIO cerr
          | otherwise -> pure (Left (AcquireResidue mPrimary cerr store))
    queue = pushResidue slot store

-- | Hold a backend across the rest of a context open. On a refusal
-- or an exception from the body the backend closes
-- ('closeBackendAfter') before the failure is reported, with the
-- same primary rules as 'holdingStore'; a cleanup interrupted by a
-- kill lets the kill propagate. On success the backend's ownership
-- passes to the body's result.
holdingBackend
  :: AsyncAcquisition -> BackendEnv OpenSSL4
  -> IO (Either AcquireFailure a) -> IO (Either AcquireFailure a)
holdingBackend acq be body = do
  r <- try body
  case r of
    Right ok@(Right _) -> pure ok
    Right failed -> closeBackendAfter acq be >>= settle failed
    Left e -> do
      interrupted <- closeBackendAfter acq be
      if isAsyncException e
        then throwIO e
        else settle (Left (AcquireThrew e)) interrupted
  where
    settle failed Nothing = pure failed
    settle _ (Just kill) = throwIO kill

-- | The NULL handle.
nullStable :: StablePtr a
nullStable = castPtrToStablePtr nullPtr

-- | Map a typed open result to the C contract: any failure is NULL.
fromAcquired :: Either AcquireFailure (StablePtr a) -> StablePtr a
fromAcquired = either (const nullStable) id

-- ---------------------------------------------------------------------------
-- Foreign exports
-- ---------------------------------------------------------------------------

foreign export ccall "haskoki_hs_async_open" haskokiAsyncOpen
  :: IO (StablePtr AsyncCtx)
foreign export ccall "haskoki_hs_async_close" haskokiAsyncClose
  :: Ptr (StablePtr AsyncCtx) -> IO ()
foreign export ccall "haskoki_hs_async_digest_init" haskokiAsyncDigestInit
  :: StablePtr AsyncCtx -> CULong -> CULong -> Ptr Word8 -> CULong -> IO CULong
foreign export ccall "haskoki_hs_async_start" haskokiAsyncStart
  :: StablePtr AsyncCtx -> CULong -> CULong -> Ptr Word8 -> CULong
  -> CULong -> CULong -> Ptr (StablePtr JobHandle) -> IO CULong
foreign export ccall "haskoki_hs_async_poll" haskokiAsyncPoll
  :: StablePtr AsyncCtx -> StablePtr JobHandle -> CULong -> IO CULong
foreign export ccall "haskoki_hs_async_complete" haskokiAsyncComplete
  :: StablePtr AsyncCtx -> StablePtr JobHandle -> CULong
  -> Ptr AsyncData -> IO CULong
foreign export ccall "haskoki_hs_async_cancel" haskokiAsyncCancel
  :: StablePtr AsyncCtx -> StablePtr JobHandle -> IO CULong
foreign export ccall "haskoki_hs_async_store_open" haskokiAsyncStoreOpen
  :: CString -> IO (StablePtr StoreBox)
foreign export ccall "haskoki_hs_async_store_close" haskokiAsyncStoreClose
  :: Ptr (StablePtr StoreBox) -> IO ()
foreign export ccall "haskoki_hs_async_open_on" haskokiAsyncOpenOn
  :: StablePtr StoreBox -> IO (StablePtr AsyncCtx)
foreign export ccall "haskoki_hs_async_get_id" haskokiAsyncGetId
  :: StablePtr AsyncCtx -> StablePtr JobHandle -> CULong
  -> Ptr Word64 -> IO CULong
foreign export ccall "haskoki_hs_async_join" haskokiAsyncJoin
  :: StablePtr AsyncCtx -> CULong -> CULong -> CULong -> CULong
  -> Ptr (StablePtr JobHandle) -> Ptr Word64 -> IO CULong

-- | Open an async context: fresh environment, provider init,
-- seated token, one proof session (async-enabled: the requested
-- asynchronous session), live backend, and an empty job table. Any
-- failure reports NULL.
haskokiAsyncOpen :: IO (StablePtr AsyncCtx)
haskokiAsyncOpen = haskokiAsyncOpenWith asyncAcquisition

-- | The body of 'haskokiAsyncOpen' over injected acquisition steps:
-- resolve the config, open through 'openAsyncCtxWith', and map every
-- failure (and any exception) to NULL.
haskokiAsyncOpenWith :: AsyncAcquisition -> IO (StablePtr AsyncCtx)
haskokiAsyncOpenWith acq = guardedPtr $ do
  cell <- newConfigCell
  eCfg <- resolveOnce cell
  case eCfg of
    Left _ -> pure nullStable
    Right cfg -> fromAcquired <$> openAsyncCtxWith acq cfg

-- | Open an async context from a RESOLVED config over injected
-- acquisition steps: retry the record's residue, then a fresh
-- environment, provider init, seated token, and the shared tail
-- ('finishAsyncOpen'). Runs masked: the openers stay interruptible
-- only where they block, and only 'aaStep' runs restored, after the
-- cleanup of everything held so far is installed. Refusals report
-- 'AcquireRefused', synchronous exceptions 'AcquireThrew';
-- asynchronous exceptions propagate after the cleanup. The masked
-- return is the ownership transfer point: a Haskell caller that
-- must not lose the pointer calls this under 'mask'.
openAsyncCtxWith
  :: AsyncAcquisition -> Config -> IO (Either AcquireFailure (StablePtr AsyncCtx))
openAsyncCtxWith acq cfg = guardedAcquire $ mask $ \restore -> do
  retryResidue acq
  env <- newEnv (rulesFromConfig cfg)
  ini <- aaInit acq env
  case ini of
    OutcomeErr _ -> pure (Left AcquireRefused)
    OutcomeOk () -> do
      eSeat <- seatToken env (SlotId 0)
      case eSeat of
        Left _ -> pure (Left AcquireRefused)
        Right () -> finishAsyncOpen acq restore env Nothing

-- | The shared tail of both context opens, run masked by the open:
-- live backend, one proof session, an empty job table, then the
-- pointer adoption ('adoptCtx'). Once the backend is open, every
-- refusal and exception closes it ('holdingBackend'). The context
-- binds the given detach state (a store-bound open) or none.
finishAsyncOpen
  :: AsyncAcquisition -> (IO () -> IO ()) -> Env -> Maybe DetachCtx
  -> IO (Either AcquireFailure (StablePtr AsyncCtx))
finishAsyncOpen acq restore env mDc = do
  m0 <- snapshotModel env
  let sid = SessionId (mNextSession m0)
  r <- aaOpenBackend acq
  case r of
    EngineFail _ -> pure (Left AcquireRefused)
    EngineOk be -> holdingBackend acq be $ do
      restore (aaStep acq AfterBackendOpen)
      case planCall (envRules env) m0 asyncOpenReq of
        Immediate pc -> do
          pr <- publishCommit env be pc
          case pr of
            Left _ -> pure (Left AcquireRefused)
            Right () -> do
              restore (aaStep acq AfterSessionOpen)
              mTable <- tryNewAsyncTable ctxCapacity
              case mTable of
                -- Table-allocator refusal (past 2^32-1 tables):
                -- refused like every other open failure, with the
                -- backend shut.
                Nothing -> pure (Left AcquireRefused)
                Just table -> do
                  enableAsyncSession table sid
                  live <- newIORef Set.empty
                  Right <$> adoptCtx acq restore (AsyncCtx env be sid table live mDc)
        _ -> pure (Left AcquireRefused)

-- | Adopt a built context, masked, before its pointer escapes:
-- allocate the pointer, run the test step restored, then register.
-- A throw from the step or from the registration frees the pointer
-- unregistered (registration is all or nothing, see
-- 'registerOwnedCtx') and propagates to the backend's cleanup. The
-- restored step is the one unmask point; production runs 'pure ()'
-- there, and the cleanup covers a kill delivered at it.
adoptCtx
  :: AsyncAcquisition -> (IO () -> IO ()) -> AsyncCtx -> IO (StablePtr AsyncCtx)
adoptCtx acq restore ctx = do
  sp <- aaNewCtxPtr acq ctx
  -- A synchronous free error never replaces the primary; an
  -- asynchronous one propagates.
  let freeUnregistered = do
        r <- try (aaFreeCtxPtr acq sp)
        case r of
          Left e | isAsyncException e -> throwIO e
          _ -> pure ()
  (restore (aaStep acq AfterCtxAlloc) >> aaRegisterCtx acq sp (acTable ctx))
    `onException` freeUnregistered
  pure sp

-- | The single proof-session open request of an async context.
asyncOpenReq :: Request
asyncOpenReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []

-- | Close a context through its handle slot: resolve the entry
-- through the registry (no dereference before the claim), and on
-- the winning claim wait out admitted borrowers, cancel every
-- live job, retire every live handle, shut the
-- backend, retire the entry to a tombstone, free the pointer,
-- and null the slot. The drain reruns idempotently, so a resumed
-- close re-cancels before it retires. The dereference runs only
-- after the winning claim, when no other thread can free the
-- pointer — racing closes never dereference. A racing second
-- close through the same slot claims nothing and returns without
-- touching the slot: the owner completes teardown and nulls it,
-- so the pointer frees exactly once. Close is cancellable at
-- every blocking wait but the bounded SQLite busy waits inside FFI
-- calls. A kill before teardown starts reopens the gate; a kill
-- past the borrower drain leaves the context owned by its slot
-- in a closing state that admits nothing, and the next close
-- through the slot resumes teardown where it stopped.
-- After killing a closer, join it — or loop until the slot is
-- null — before retrying: a retry issued while the killed closer
-- still unwinds claims nothing and returns silently with the
-- slot set. Closing a null slot is a
-- silent no-op, and closing a retired, borrowed, or
-- never-registered value reclaims the slot without teardown
-- (borrowed entries are released by their Standard owner, never
-- here), so close-through-the-slot stays idempotent by
-- construction. Context pointers must otherwise not be used after
-- close (@fclose@ parity with the crypto context): calls admitted
-- before the claim run to completion first, calls that lose the
-- claim or meet the tombstone are refused, and a pointer value
-- the allocator reuses names its new owner (callers must not
-- retain context values across close, exactly as with @fclose@).
haskokiAsyncClose :: Ptr (StablePtr AsyncCtx) -> IO ()
haskokiAsyncClose pSlot = guardedUnit (closeCtxSlotWith asyncAcquisition pSlot)

-- | The body of 'haskokiAsyncClose' over injected steps: retry the
-- record's residue first (every call, a null slot included), then
-- the backend close, the registry retirement and the pointer free
-- go through the record. Exceptions propagate; the export swallows
-- them.
closeCtxSlotWith :: AsyncAcquisition -> Ptr (StablePtr AsyncCtx) -> IO ()
closeCtxSlotWith acq pSlot = do
  retryResidue acq
  if pSlot == nullPtr
    then pure ()
    else mask_ $ do
      sp <- peek pSlot
      if isNullStable sp
        then pure ()
        else do
          mEntry <- lookupCtxEntry sp
          case mEntry of
            Just (CtxLive table) -> do
              first <- claimTableClose table
              if first
                then do
                  c <- deRefStablePtr sp
                  closeClaimedCtx acq c
                  transferCtxClose table (Just sp)
                    (aaRetireCtx acq sp
                      >> aaFreeCtxPtr acq sp
                      >> poke pSlot (castPtrToStablePtr nullPtr))
                else pure ()
            -- Retired (owned or borrowed, already closed), live
            -- borrowed (owned by Standard), or never registered
            -- (foreign): reclaim the caller's slot, teardown
            -- nothing. Borrowed entries never carry teardown
            -- authority here: their table and backend are shared.
            _ -> poke pSlot (castPtrToStablePtr nullPtr)

-- | The close worker: claim the table gate, wait out admitted
-- borrowers, then run the same drain the export runs after its
-- winning claim — retire this table's detach attachments (its
-- active joins resolve canceled, durably; sibling contexts on
-- the same store keep theirs), drain jobs and handles, shut the
-- backend. Only a winning claim drains — a resumed claim wins
-- again and drains too; a close that claims nothing is a silent
-- no-op. The claim and the teardown run under one
-- mask, so no kill can split the claim from the teardown
-- ownership it installs. Value-level teardown only: a
-- 'StablePtr' owner frees its own pointer separately. Exported
-- so tests assert drain state through the same worker the export
-- calls, over the production steps ('asyncAcquisition').
asyncCloseCtx :: AsyncCtx -> IO ()
asyncCloseCtx ctx = mask_ $ do
  first <- claimTableClose (acTable ctx)
  if first
    then do
      closeClaimedCtx asyncAcquisition ctx
      transferCtxClose (acTable ctx) Nothing (pure ())
    else pure ()

-- | The one context-close transfer, shared by the slot close and
-- the value-level close: run the pointer tail first (retire,
-- free, null the slot; the value-level close passes no pointer
-- steps), then mark the table closed. The transfer holds no lock,
-- takes no MVar and touches no Store, so it runs
-- uninterruptibly: no kill can split the drained table from its
-- closed mark. A synchronous throw in the tail releases the
-- claim instead of publishing the closed mark, so the gate stays
-- resumable and the retry re-runs the tail; the throw propagates
-- to the caller. The slot close passes its pointer so the throw
-- arm can re-register the entry the tail may have retired: a
-- retry keys off the registry, and without the entry it would
-- reclaim the slot while leaking the pointer. The re-register
-- runs through the production step, never injected, so the throw
-- arm stays total; a throwing tail step must report before
-- running its effect. The re-register bypasses the injected
-- record, so after a throw and retry the record's registrations
-- minus retirements is short by one (the free-throw shape shows
-- two retirements with no matching registration); balance asserts
-- on these paths must allow for that. A racing second close
-- during the throw arm can strand the entry under a fault double
-- only: when free throws after retire, a concurrent close that
-- reads the tombstone before compensation re-registers reclaims
-- its slot, and the re-registered live entry then has no slot
-- naming it. Production tail steps never throw, so this needs
-- both an injected throw and a racing closer. No canary test
-- plants an exception between the tail steps: the transfer is one
-- uninterruptible block with no interruptible operation inside,
-- verified by construction, and the TEST-ONLY close step
-- ('aaCloseStep') parks before it so the revert check covers the
-- ordering.
transferCtxClose
  :: AsyncTable -> Maybe (StablePtr AsyncCtx) -> IO () -> IO ()
transferCtxClose table mSp after = uninterruptibleMask_ $
  (after >> finishTableClose table)
    `onException` (compensate >> releaseTableClose table)
  where
    compensate = case mSp of
      Nothing -> pure ()
      Just sp -> registerOwnedCtx sp table

-- | Await admitted borrowers, mark teardown started, then drain
-- one claimed context. Runs only on the winning close claim (see
-- 'asyncCloseCtx' and 'haskokiAsyncClose'). An interruption aborts
-- the quiescence wait or the drain and releases the claim (masked,
-- so the release itself is atomic): before teardown begin the gate
-- reopens, past it the table stays closing without a closer, and a
-- retrying close re-claims and completes. Every drain step is
-- idempotent on re-run, and the backend close runs interruptibly,
-- so its gate wait is cancellable. The drain runs
-- masked-interruptible: the worker holds 'mask' across it, and
-- both close callers hold 'mask_', so the restored sections
-- deliver kills only at blocking waits (the quiescence wait, the
-- Store lock wait, the job lease waits, the backend gate wait) —
-- never between two non-blocking steps. Nothing here runs under
-- an uninterruptible mask: only the pointer transfer does.
closeClaimedCtx :: AsyncAcquisition -> AsyncCtx -> IO ()
closeClaimedCtx acq ctx = mask $ \restore -> do
  restore (awaitTableQuiescent (acTable ctx))
    `onException` mask_ (releaseTableClose (acTable ctx))
  _ <- beginTableTeardown (acTable ctx)
  restore (drainClaimedCtx acq ctx >> aaCloseStep acq)
    `onException` mask_ (releaseTableClose (acTable ctx))

-- | Drain one claimed context after its borrowers are gone:
-- retire this table's detach attachments, drain its live jobs
-- and handles, shut the backend. Runs only from
-- 'closeClaimedCtx', after a successful quiescence wait and a
-- started teardown, masked-interruptibly (see 'closeClaimedCtx'):
-- a kill lands at a blocking wait, leaves every step re-runnable,
-- and the retry resumes them. The backend closes
-- through the record.
drainClaimedCtx :: AsyncAcquisition -> AsyncCtx -> IO ()
drainClaimedCtx acq ctx = do
  case acDetach ctx of
    Nothing -> pure ()
    Just dc -> do
      _ <- retireLiveTableFor dc (asyncTableId (acTable ctx))
      pure ()
  live <- readIORef (acLive ctx)
  mapM_ drainOne (Set.toList live)
  aaCloseBackend acq (acBackend ctx)
  where
    drainOne :: Ptr () -> IO ()
    drainOne key = do
      let h = castPtrToStablePtr key :: StablePtr JobHandle
      -- Cancel-then-retire per key: the cancel lands first, so the
      -- retry order stays valid — a kill between the two would leave
      -- the job canceled but the key live, and the retry re-cancels
      -- (idempotent) before it retires. No interruptible point sits
      -- between the two steps, so under the masked drain the window
      -- never opens; the order is the standing idempotence argument.
      -- The job id comes from the pure key decode —
      -- nothing is dereferenced — and the retirement is an
      -- idempotent delete, so a racing terminal path simply wins
      -- or loses it.
      case decodeJobHandle h of
        Nothing -> pure ()
        Just jid -> do
          _ <- cancelJob (acTable ctx) jid
          pure ()
      freeJobHandle ctx h

-- | Publish a prepared commit, then drain its releases through the
-- backend (every commit-application site routes here, so
-- releases are impossible to forget). A faulted publish
-- still drains (drain-then-report) — releases free engine
-- resources that exist independent of the model commit.
publishCommit :: Env -> BackendEnv OpenSSL4 -> PreparedCommit -> IO (Either ModelFault ())
publishCommit env be pc = do
  pr <- publish env (pcDelta pc)
  case pr of
    -- Drain-then-report — a faulted publish still drains
    -- (same orphan analysis as 'commitAndTryDeliver''s fault arm:
    -- releases free resources that exist independent of the
    -- commit; frees are idempotent takes).
    Left fault -> do
      drainReleases be (pcReleases pc)
      pure (Left fault)
    Right () -> do
      drainReleases be (pcReleases pc)
      pure (Right ())

-- | Publish a rejection's termination, then drain its releases
-- through the backend (stale-alloc orphans ride
-- rejections). Plan-time rejections carry none.
publishRejection :: Env -> BackendEnv OpenSSL4 -> Rejection -> IO ()
publishRejection env be rej = do
  _ <- publish env (rejDelta rej)
  drainReleases be (rejReleases rej)

-- | The context session when the caller named it, else nothing.
checkSession :: AsyncCtx -> CULong -> Maybe SessionId
checkSession c (CULong h)
  | h == fromIntegral (unSessionId (acSession c)) = Just (acSession c)
  | otherwise = Nothing

-- | Routed digest init over the context session (mirrors the crypto
-- export; async digest jobs need an initialized slot).
haskokiAsyncDigestInit
  :: StablePtr AsyncCtx -> CULong -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiAsyncDigestInit ctx hSession (CULong mech) pParams (CULong paramsLen) =
  withCtx ctx $ \c -> case checkSession c hSession of
    Nothing -> pure (rvOf CKR_SESSION_HANDLE_INVALID)
    Just sid -> do
      eParams <- decodeInputBytes pParams paramsLen
      case eParams of
        Left _ -> pure (rvOf CKR_ARGUMENTS_BAD)
        Right params -> do
          m <- snapshotModel (acEnv c)
          -- Decoded init arguments straight to the
          -- planner (no init frame to re-parse).
          let dreq = DRInit sid InitDigest Nothing
                (MechanismId (fromIntegral mech)) [] False params
          case planDecoded (envRules (acEnv c)) m dreq of
            Immediate pc -> do
              pr <- publishCommit (acEnv c) (acBackend c) pc
              pure $ case pr of
                Left _ -> toRV 0x05
                Right () -> rvOf (pcCode pc)
            Reject rej -> do
              publishRejection (acEnv c) (acBackend c) rej
              pure (rvOf (rejCode rej))
            Execute res (EffectCrypto fx) -> do
              crypto <- runAsyncEffect c fx
              m2 <- snapshotModel (acEnv c)
              case finishEffect (envRules (acEnv c)) m2 res (encodeResult crypto) of
                Left rej -> do
                  publishRejection (acEnv c) (acBackend c) rej
                  pure (rvOf (rejCode rej))
                Right pc -> do
                  pr <- publishCommit (acEnv c) (acBackend c) pc
                  pure $ case pr of
                    Left _ -> toRV 0x05
                    Right () -> rvOf (pcCode pc)

-- | Submit an attached job. Accepted submissions report
-- @CKR_PENDING@ with a live handle; every refusal reports its typed
-- code with a null handle and no allocation.
haskokiAsyncStart
  :: StablePtr AsyncCtx -> CULong -> CULong -> Ptr Word8 -> CULong
  -> CULong -> CULong -> Ptr (StablePtr JobHandle) -> IO CULong
haskokiAsyncStart ctx hSession (CULong func) pData (CULong dataLen)
    (CULong cap) (CULong ticks) pHandleOut =
  withCtx ctx $ \c ->
    if pHandleOut == nullPtr
      then pure (rvOf CKR_ARGUMENTS_BAD)
      else case checkSession c hSession of
        Nothing -> refuse pHandleOut (rvOf CKR_SESSION_HANDLE_INVALID)
        Just sid -> case codeJobFunction func of
          Nothing -> refuse pHandleOut (rvOf CKR_ARGUMENTS_BAD)
          Just JobGenKey -> refuse pHandleOut (rvOf CKR_ARGUMENTS_BAD)
          Just JobGenKeyPair -> refuse pHandleOut (rvOf CKR_ARGUMENTS_BAD)
          Just jfunc -> do
            eInput <- decodeInputBytes pData dataLen
            case eInput of
              Left _ -> refuse pHandleOut (rvOf CKR_ARGUMENTS_BAD)
              Right input ->
                submitJob c sid jfunc input cap ticks pHandleOut

-- | Refuse a submission: null the handle out-pointer and report.
refuse :: Ptr (StablePtr JobHandle) -> CULong -> IO CULong
refuse pHandleOut code = do
  poke pHandleOut (castPtrToStablePtr nullPtr)
  pure code

-- | Plan and submit: only @Execute@ plans become jobs. Rejections
-- publish their termination and report their code; immediate plans
-- (sync recalls) publish and report with no job. Coherent executions
-- check their call work before submitting (a planner that pinned an
-- incoherent pair fails closed here, before any id is consumed).
-- The start-to-handle transfer runs protected (see
-- 'submitTransfer').
submitJob
  :: AsyncCtx -> SessionId -> JobFunction -> ByteString -> Word64 -> Word64
  -> Ptr (StablePtr JobHandle)
  -> IO CULong
submitJob c sid jfunc input cap ticks pHandleOut = do
  m <- snapshotModel (acEnv c)
  let fid = case jfunc of
        JobSign -> F_Sign
        JobDigest -> F_Digest
        JobGenKey -> F_Sign
        JobGenKeyPair -> F_Sign
      req = Request Pkcs11_3_2 fid (Just sid) Nothing input
        [RegionBytes "async" (IntentBuffer maxOutputBytes)]
  case planCall (envRules (acEnv c)) m req of
    Reject rej -> do
      publishRejection (acEnv c) (acBackend c) rej
      refuse pHandleOut (rvOf (rejCode rej))
    Immediate pc -> do
      _ <- publishCommit (acEnv c) (acBackend c) pc
      refuse pHandleOut (rvOf (pcCode pc))
    Execute res eff -> case checkedCallWork sid res eff of
      -- Unreachable through the planner (every produced execution
      -- checks — see the TransitionSpec coherence sweep): an
      -- incoherent pair is an internal breach, refused loudly with
      -- no submission and no id consumed.
      Left _ -> refuse pHandleOut (rvOf CKR_GENERAL_ERROR)
      Right cw -> do
        let jobReq = JobRequest
              { jrSession = sid
              , jrFunction = jfunc
              , jrWork = WorkCall cw
              , jrTicks = fromIntegral ticks
              , jrCapacity = cap
              }
        submitTransfer (pure ()) c jobReq pHandleOut

-- | Start one planned job and transfer its handle to the caller
-- as a single protected step: the start, the admission, and the
-- publication run masked, and the test-only hook runs restored
-- between the start and the admission — the interruption window
-- the transfer must survive. Production passes a no-op hook, so
-- a kill lands only after the handle is published (owned and
-- drainable); a kill inside the window cancels the fresh
-- unregistered job and nulls the out-pointer instead, so no
-- unreachable live job ever strands. An exhausted fresh id
-- cancels the same way.
submitTransfer
  :: IO () -> AsyncCtx -> JobRequest -> Ptr (StablePtr JobHandle)
  -> IO CULong
submitTransfer hook c jobReq pHandleOut = mask $ \restore -> do
  started <- startJob (acTable c) jobReq
  case started of
    Left deny -> refuse pHandleOut (rvOf (denyCode deny))
    Right jid
      | jobIdExhausted jid -> do
          -- The fresh job never had a handle: cancel it before
          -- refusing so the table holds no ghost.
          _ <- cancelJob (acTable c) jid
          refuse pHandleOut (rvOf CKR_HOST_MEMORY)
      | otherwise ->
          (restore hook >> admitAndPublish jid) `onException` abandon jid
  where
    admitAndPublish :: JobId -> IO CULong
    admitAndPublish jid = do
      h <- allocJobHandle c jid
      poke pHandleOut h
      pure (rvOf CKR_PENDING)
    abandon :: JobId -> IO ()
    abandon jid = mask_ $ do
      _ <- cancelJob (acTable c) jid
      poke pHandleOut (castPtrToStablePtr nullPtr)

-- | Map a submit refusal to its source-backed code.
denyCode :: StartDeny -> ReturnCode
denyCode StartSessionNotAsync = CKR_SESSION_ASYNC_NOT_SUPPORTED
denyCode StartOverCapacity = CKR_HOST_MEMORY
denyCode StartBadCapacity = CKR_ARGUMENTS_BAD
denyCode StartIncompatibleWork = CKR_ARGUMENTS_BAD

-- | Poll a job: pending while the schedule elapses, OK once ready,
-- the terminal code when this poll drives the failure. Stale
-- handles and wrong pollers refuse typed with the job intact.
haskokiAsyncPoll
  :: StablePtr AsyncCtx -> StablePtr JobHandle -> CULong -> IO CULong
haskokiAsyncPoll ctx h (CULong func) = withCtx ctx $ \c ->
  withLiveJob c h $ \jid -> case codeJobFunction func of
    Nothing -> pure (rvOf CKR_ARGUMENTS_BAD)
    Just jfunc -> do
      out <- pollJob (runAsyncEffect c) (acEnv c) (acTable c) jfunc jid
      case out of
        PollPending _ -> pure (rvOf CKR_PENDING)
        PollReady -> pure (rvOf CKR_OK)
        PollTerminal t -> do
          freeJobHandle c h
          pure (rvOf (termCode t))
        PollUnknown -> pure (rvOf CKR_ARGUMENTS_BAD)
        PollWrongFunction _ _ -> pure (rvOf CKR_ARGUMENTS_BAD)

-- | Complete a job into the caller's struct. Pending jobs report
-- pending with the struct untouched; ready jobs deliver exactly
-- once and retire the handle; short buffers size with the job held.
-- A null value pointer with a ready bytes job is a sizing probe.
-- Joined jobs complete through the detach wrapper so delivery marks
-- the durable record delivered.
haskokiAsyncComplete
  :: StablePtr AsyncCtx -> StablePtr JobHandle -> CULong
  -> Ptr AsyncData -> IO CULong
haskokiAsyncComplete ctx h (CULong func) pResult = withCtx ctx $ \c ->
  withLiveJob c h $ \jid ->
    if pResult == nullPtr
      then pure (rvOf CKR_ARGUMENTS_BAD)
      else case codeJobFunction func of
        Nothing -> pure (rvOf CKR_ARGUMENTS_BAD)
        Just jfunc -> do
          pValue <- peekValuePtr pResult
          if pValue == nullPtr
            then probeComplete c pResult jid jfunc
            else do
              cap <- peekValueCap pResult
              let del = Delivery
                    { dCapacity = cap
                    , dWrite = writeFrame pResult
                    , dReportNeeded = pokeNeed pResult
                    }
              out <- completeThrough c jfunc jid del
              case out of
                CompletePending _ -> pure (rvOf CKR_PENDING)
                CompleteDelivered _ -> do
                  freeJobHandle c h
                  pure (rvOf CKR_OK)
                CompleteAlready t -> do
                  freeJobHandle c h
                  pure (rvOf (termCode t))
                CompleteUnknown -> pure (rvOf CKR_ARGUMENTS_BAD)
                CompleteWrongFunction _ _ -> pure (rvOf CKR_ARGUMENTS_BAD)
                CompleteShort _ -> pure (rvOf CKR_BUFFER_TOO_SMALL)

-- | The null-value probe: lock-free peeks only, so probing never
-- ticks the schedule or drives the effect. A mismatched poller
-- refuses typed; a ready bytes job reports its sizing with the
-- result held; anything else reports pending with the struct
-- untouched. No state changes on any probe path.
probeComplete :: AsyncCtx -> Ptr AsyncData -> JobId -> JobFunction -> IO CULong
probeComplete c pResult jid jfunc = do
  mFunc <- jobFunctionOf (acTable c) jid
  case mFunc of
    Just actual | actual /= jfunc -> pure (rvOf CKR_ARGUMENTS_BAD)
    _ -> do
      mNeed <- jobReadyNeed (acTable c) jid
      case mNeed of
        Nothing -> pure (rvOf CKR_PENDING)
        Just need -> do
          pokeNeed pResult need
          pure (rvOf CKR_OK)

-- | The frame writer: decode the canonical completion and poke the
-- struct. Undecodable frames (impossible from the runtime encoder)
-- report loudly through the export boundary.
writeFrame :: Ptr AsyncData -> ByteString -> IO ()
writeFrame pResult frame = case decodeCompletion frame of
  Nothing -> ioError (userError "async: undecodable completion frame")
  Just completion -> pokeCompletion pResult completion

-- | Cancel a job: live jobs terminate and retire the handle; stale
-- handles refuse typed. Joined jobs cancel through the detach
-- wrapper so the durable record resolves canceled.
haskokiAsyncCancel :: StablePtr AsyncCtx -> StablePtr JobHandle -> IO CULong
haskokiAsyncCancel ctx h = withCtx ctx $ \c ->
  withLiveJob c h $ \jid -> do
    out <- cancelThrough c jid
    case out of
      CancelOk -> do
        freeJobHandle c h
        pure (rvOf CKR_OK)
      CancelAlready t -> do
        freeJobHandle c h
        pure (rvOf (termCode t))
      CancelUnknown -> pure (rvOf CKR_ARGUMENTS_BAD)

-- | The production effect runner over the context backend. Digest
-- jobs need no key material.
runAsyncEffect :: AsyncCtx -> EffectRunner
runAsyncEffect c fx = runEffect (acBackend c) (const Nothing) fx

-- ---------------------------------------------------------------------------
-- Detach routing: joined jobs resolve their durable records
-- ---------------------------------------------------------------------------

-- | Complete through the detach wrapper when the context has detach
-- state, else straight through the attached path. A durable-mark error cannot
-- change the delivery verdict (the bytes already landed); the
-- attachment is terminal in memory either way.
completeThrough :: AsyncCtx -> JobFunction -> JobId -> Delivery -> IO CompleteOutcome
completeThrough c jfunc jid del = case acDetach c of
  Nothing -> completeJob (acEnv c) (acTable c) jfunc jid del drain
  Just dc -> jcOutcome <$> completeJoined dc (acEnv c) (acTable c) jfunc jid del drain
  where
    drain rel = drainReleases (acBackend c) [rel]

-- | Cancel through the detach wrapper when the context has detach
-- state, else straight through the attached path.
cancelThrough :: AsyncCtx -> JobId -> IO CancelOutcome
cancelThrough c jid = case acDetach c of
  Nothing -> cancelJob (acTable c) jid
  Just dc -> fst <$> cancelJoined dc (acTable c) jid

-- ---------------------------------------------------------------------------
-- Process-level stores and detach entry points
-- ---------------------------------------------------------------------------

-- | Open a process-level store: a NULL or empty path opens a memory
-- world; otherwise the SQLite file at the path (single-writer
-- ownership, released by close). A fresh store seats the home token
-- (id 1, slot 0, generation 0); a non-empty store without the home
-- token is refused. Any failure reports NULL.
haskokiAsyncStoreOpen :: CString -> IO (StablePtr StoreBox)
haskokiAsyncStoreOpen = haskokiAsyncStoreOpenWith asyncAcquisition

-- | The body of 'haskokiAsyncStoreOpen' over injected acquisition
-- steps: open and map every failure (and any exception) to NULL. The
-- C caller cannot receive a residue, so a Store whose cleanup closes
-- both failed queues on the record's residue owner inside the masked
-- open ('QueueResidue').
haskokiAsyncStoreOpenWith :: AsyncAcquisition -> CString -> IO (StablePtr StoreBox)
haskokiAsyncStoreOpenWith acq cPath =
  guardedPtr (fromAcquired <$> openStoreBoxAs QueueResidue acq cPath)

-- | Who receives a Store whose two cleanup closes failed after a
-- synchronous primary or a refusal.
data ResidueReceiver
  = HandBackResidue
    -- ^ the caller, as 'AcquireResidue' (the typed helper)
  | QueueResidue
    -- ^ the record's residue owner; the caller sees the primary
    -- failure (the C export, which can only report NULL)

-- | Open a process-level store over injected acquisition steps:
-- retry the record's residue, then the Store, the home token and
-- detach state, and the box pointer. Runs masked like
-- 'openAsyncCtxWith'; once the Store is open, every refusal and
-- exception closes it ('holdingStore'). Refusals report
-- 'AcquireRefused', synchronous exceptions 'AcquireThrew', a double
-- cleanup-close failure 'AcquireResidue'; asynchronous exceptions
-- propagate after the cleanup.
openStoreBoxWith
  :: AsyncAcquisition -> CString -> IO (Either AcquireFailure (StablePtr StoreBox))
openStoreBoxWith = openStoreBoxAs HandBackResidue

-- | The box open behind 'openStoreBoxWith' and the export body. It
-- reserves a residue slot before it opens the Store
-- ('withResidueSlot'; a failed reservation refuses holding nothing),
-- so queueing a residue never fails.
openStoreBoxAs
  :: ResidueReceiver -> AsyncAcquisition -> CString
  -> IO (Either AcquireFailure (StablePtr StoreBox))
openStoreBoxAs receiver acq cPath = guardedAcquire $ mask $ \restore -> do
  retryResidue acq
  withResidueSlot (aaResidue acq) $ \slot -> do
    eStore <- aaOpenStore acq cPath
    case eStore of
      Left _ -> pure (Left AcquireRefused)
      Right store -> do
        r <- holdingStore acq slot store $ do
          restore (aaStep acq AfterStoreOpen)
          mDc <- ensureHomeToken store
          case mDc of
            Nothing -> pure (Left AcquireRefused)
            Just dc -> do
              restore (aaStep acq AfterTokenSetup)
              Right <$> aaNewBoxPtr acq (StoreBox store dc)
        case (receiver, r) of
          (QueueResidue, Left (AcquireResidue mPrimary _ st)) -> do
            pushResidue slot st
            pure (Left (maybe AcquireRefused AcquireThrew mPrimary))
          _ -> pure r

-- | Open the store named by the path pointer (NULL\/empty = memory).
openStoreByPath :: CString -> IO (Either () Store)
openStoreByPath cPath
  | cPath == nullPtr = openMemory
  | otherwise = do
      path <- peekCString cPath
      if null path then openMemory else sqlite path
  where
    openMemory = do
      world <- newMemoryWorld
      eStore <- openMemoryStore world
      pure $ case eStore of
        Left _ -> Left ()
        Right store -> Right store
    sqlite path = do
      eStore <- openSQLiteStore path
      pure $ case eStore of
        Left _ -> Left ()
        Right store -> Right store

-- | Ensure the home token and open detach state over the store.
-- 'Nothing' refuses (the caller closes the store).
ensureHomeToken :: Store -> IO (Maybe DetachCtx)
ensureHomeToken store = do
  eToks <- storeLoadTokens store
  case eToks of
    Left _ -> pure Nothing
    Right toks
      | any ((== storeHomeToken) . trId . fst) toks -> openDc
      | null toks -> do
          res <- storeCommit store
            emptyDelta { sdPutTokens = [homeToken], sdPutCredentials = [homeCredential] }
          case res of
            Committed -> openDc
            _ -> pure Nothing
      | otherwise -> pure Nothing
  where
    homeToken = TokenRecord
      { trId = storeHomeToken
      , trSlot = SlotId 0
      , trGeneration = Generation 0
      , trLabel = homeLabel
      , trAuth = tokenAuthNew
      }
    -- The home token's credential row seeds in the same transaction
    -- as the token, from the home catalog entry's PINs: a store this
    -- open creates is a complete schema-3 store.
    (homeLabel, homeSo, homeUser) = asyncHomeEntry
    homeCredential =
      CredentialRecord storeHomeToken (BC8.pack homeSo) (Just (BC8.pack homeUser))
    openDc = do
      eDc <- openDetached store storeHomeToken
      pure $ case eDc of
        Left _ -> Nothing
        Right dc -> Just dc

-- | Close a store through its handle slot: release single-writer
-- ownership, free the pointer, and null the slot. Idempotent by
-- construction, like context close. A failed or killed close keeps
-- the slot and the pointer, and a retry closes for real. Close
-- every context on the box — and join their calls — before
-- closing the box, and never close one slot concurrently from two
-- threads: only a serialized box lifetime is supported.
haskokiAsyncStoreClose :: Ptr (StablePtr StoreBox) -> IO ()
haskokiAsyncStoreClose pSlot =
  guardedUnit (closeStoreBoxSlotWith asyncAcquisition pSlot)

-- | The one store-box close transfer: free the box pointer, then
-- null the slot. Neither step blocks, so the transfer runs
-- uninterruptibly: no kill can split the freed box from its nulled
-- slot. No canary test plants an exception between the two steps:
-- the transfer is one uninterruptible block, verified by
-- construction, and the TEST-ONLY close step ('aaCloseStep') parks
-- before it so the revert check covers the ordering.
transferBoxClose
  :: AsyncAcquisition -> StablePtr StoreBox -> Ptr (StablePtr StoreBox) -> IO ()
transferBoxClose acq box pSlot =
  uninterruptibleMask_ (aaFreeBoxPtr acq box >> poke pSlot (castPtrToStablePtr nullPtr))

-- | The body of 'haskokiAsyncStoreClose' over injected steps: retry
-- the record's residue first (every call, a null slot included),
-- then close the Store interruptibly — a kill lands in the lock
-- wait — and transfer the box. The Store close and the box free go
-- through the record. A failed or killed close keeps the slot and
-- the pointer; only a returned close transfers. Exceptions
-- propagate; the export swallows them.
closeStoreBoxSlotWith :: AsyncAcquisition -> Ptr (StablePtr StoreBox) -> IO ()
closeStoreBoxSlotWith acq pSlot = do
  retryResidue acq
  if pSlot == nullPtr
    then pure ()
    else mask $ \restore -> do
      box <- peek pSlot
      if isNullStable box
        then pure ()
        else do
          b <- deRefStablePtr box
          restore (aaCloseStore acq (sbStore b))
          restore (aaCloseStep acq)
          transferBoxClose acq box pSlot

-- | Open a context on a process-level store: fresh environment,
-- provider init, token\/object reload from the store, one proof
-- session, live backend, and an empty job table bound to the box's
-- detach state. Any failure reports NULL.
haskokiAsyncOpenOn :: StablePtr StoreBox -> IO (StablePtr AsyncCtx)
haskokiAsyncOpenOn = haskokiAsyncOpenOnWith asyncAcquisition

-- | The body of 'haskokiAsyncOpenOn' over injected acquisition
-- steps: refuse a NULL box, resolve the config, open through
-- 'openAsyncCtxOnWith', and map every failure (and any exception)
-- to NULL.
haskokiAsyncOpenOnWith
  :: AsyncAcquisition -> StablePtr StoreBox -> IO (StablePtr AsyncCtx)
haskokiAsyncOpenOnWith acq box = guardedPtr $
  if isNullStable box
    then pure nullStable
    else do
      cell <- newConfigCell
      eCfg <- resolveOnce cell
      case eCfg of
        Left _ -> pure nullStable
        Right cfg -> fromAcquired <$> openAsyncCtxOnWith acq cfg box

-- | Open a context on a process-level store from a RESOLVED config
-- over injected acquisition steps: retry the record's residue, then
-- a fresh environment, provider init, token\/object reload from the
-- box's store, and the shared tail ('finishAsyncOpen') bound to the
-- box's detach state. Runs masked like 'openAsyncCtxWith'; the box's
-- Store stays the box's (nothing here closes it). The box must be
-- live (caller obligation); a NULL box refuses. Refusals report
-- 'AcquireRefused', synchronous exceptions 'AcquireThrew';
-- asynchronous exceptions propagate after the cleanup.
openAsyncCtxOnWith
  :: AsyncAcquisition -> Config -> StablePtr StoreBox
  -> IO (Either AcquireFailure (StablePtr AsyncCtx))
openAsyncCtxOnWith acq cfg box
  | isNullStable box = pure (Left AcquireRefused)
  | otherwise = guardedAcquire $ mask $ \restore -> do
      retryResidue acq
      b <- deRefStablePtr box
      env <- newEnv (rulesFromConfig cfg)
      ini <- aaInit acq env
      case ini of
        OutcomeErr _ -> pure (Left AcquireRefused)
        OutcomeOk () -> do
          eLoaded <- storeLoadTokens (sbStore b)
          case eLoaded of
            Left _ -> pure (Left AcquireRefused)
            Right loaded -> do
              eRestored <- restoreStoreState env loaded
              case eRestored of
                Left _ -> pure (Left AcquireRefused)
                Right () -> do
                  restore (aaStep acq AfterStoreReload)
                  finishAsyncOpen acq restore env (Just (sbDetach b))

-- | Detach a live job (GetID): on success the persistent id lands in
-- the out-pointer and the old native handle is retired (late use is
-- stale); on failure the id out-pointer is zeroed and the live job
-- is preserved. A null id out-pointer refuses without detaching, as
-- does a context with no bound store.
haskokiAsyncGetId
  :: StablePtr AsyncCtx -> StablePtr JobHandle -> CULong
  -> Ptr Word64 -> IO CULong
haskokiAsyncGetId ctx h (CULong func) pIdOut = withCtx ctx $ \c ->
  if pIdOut == nullPtr
    then pure (rvOf CKR_ARGUMENTS_BAD)
    else withLiveJob c h $ \jid -> case acDetach c of
      Nothing -> do
        poke pIdOut 0
        pure (rvOf CKR_GENERAL_ERROR)
      Just dc -> case codeJobFunction func of
        Nothing -> do
          poke pIdOut 0
          pure (rvOf CKR_ARGUMENTS_BAD)
        Just jfunc -> do
          out <- detachJob dc (acTable c) jid jfunc
          case out of
            DetachOk pid -> do
              poke pIdOut pid
              freeJobHandle c h
              pure (rvOf CKR_OK)
            other -> do
              poke pIdOut 0
              pure (rvOf (detachCode other))

-- | Rejoin a persistent id as a fresh live job. Success reports
-- @CKR_PENDING@ with a live handle; every refusal reports its typed
-- code with a null handle. An undersized capacity additionally
-- reports its sizing through the need out-pointer (which may be
-- NULL). A null handle out-pointer refuses without joining. The
-- acquisition and the handle handoff run under one protected
-- ownership protocol (see 'joinAcquireTransfer').
haskokiAsyncJoin
  :: StablePtr AsyncCtx -> CULong -> CULong -> CULong -> CULong
  -> Ptr (StablePtr JobHandle) -> Ptr Word64 -> IO CULong
haskokiAsyncJoin ctx (CULong pid) (CULong func) hSession (CULong cap)
    pHandleOut pNeedOut =
  withCtx ctx $ \c ->
    if pHandleOut == nullPtr
      then pure (rvOf CKR_ARGUMENTS_BAD)
      else case acDetach c of
        Nothing -> refuse pHandleOut (rvOf CKR_GENERAL_ERROR)
        Just dc -> case checkSession c hSession of
          Nothing -> refuse pHandleOut (rvOf CKR_SESSION_HANDLE_INVALID)
          Just sid -> case codeJobFunction func of
            Nothing -> refuse pHandleOut (rvOf CKR_ARGUMENTS_BAD)
            Just jfunc -> joinAcquireTransfer (pure ()) dc c JoinRequest
              { jqPid = pid
              , jqFunction = jfunc
              , jqSession = sid
              , jqCapacity = cap
              } pHandleOut pNeedOut

-- | Transfer a joined job's handle to the caller as a single
-- protected step: the test-only hook runs restored before the
-- admission, and the admission plus the publication run masked.
-- Production passes a no-op hook, so a kill lands only after the
-- handle is published (owned and drainable); a kill inside the
-- window cancels through the detach wrapper — the committed
-- attachment resolves canceled, durably — and nulls the
-- out-pointer instead, so no unreachable live job ever strands.
joinTransfer
  :: IO () -> AsyncCtx -> JobId -> Ptr (StablePtr JobHandle)
  -> IO CULong
joinTransfer hook c jid pHandleOut = mask $ \restore ->
  (restore hook >> admitAndPublish) `onException` abandon
  where
    admitAndPublish :: IO CULong
    admitAndPublish = do
      h <- allocJobHandle c jid
      poke pHandleOut h
      pure (rvOf CKR_PENDING)
    abandon :: IO ()
    abandon = mask_ $ do
      _ <- cancelThrough c jid
      poke pHandleOut (castPtrToStablePtr nullPtr)

-- | Acquire a join and transfer its handle to the caller under one
-- exception-safe ownership protocol: the acquisition runs masked
-- end to end (its inner restores inherit the mask, so a pending
-- kill waits out the pure commit boundary instead of landing
-- between the commit and the handoff's cleanup), and the
-- committed 'JoinOk' crosses to the handoff's cleanup ownership
-- while still masked — the first unmasking past the commit runs
-- under 'joinTransfer' (whose cleanup cancels through the detach
-- wrapper and nulls the out-pointer) rather than stranding a
-- committed attachment with no handle. Blocking points inside
-- the acquisition (test hooks) stay interruptible with the
-- acquisition's own cleanup installed, and a kill there only
-- nulls the untouched out-pointer on top of that cleanup. An
-- exhausted fresh id cancels through the detach wrapper the
-- same way; every other outcome refuses typed with a null
-- handle, reporting sizing through the need out-pointer (which
-- may be NULL) on the short path.
joinAcquireTransfer
  :: IO () -> DetachCtx -> AsyncCtx -> JoinRequest
  -> Ptr (StablePtr JobHandle) -> Ptr Word64 -> IO CULong
joinAcquireTransfer hook dc c req pHandleOut pNeedOut =
  mask_ $ do
    out <- joinJob dc (acEnv c) (acTable c) req
      `onException` mask_ (poke pHandleOut (castPtrToStablePtr nullPtr))
    case out of
      JoinOk jid
        | jobIdExhausted jid -> mask_ $ do
            -- Cancel through the detach wrapper so the durable
            -- attachment resolves canceled too; masked like the
            -- transfer so a kill cannot strand the fresh job
            -- mid-cancel.
            _ <- cancelThrough c jid
            refuse pHandleOut (rvOf CKR_HOST_MEMORY)
        | otherwise -> joinTransfer hook c jid pHandleOut
      JoinShort need -> do
        if pNeedOut /= nullPtr then poke pNeedOut need else pure ()
        refuse pHandleOut (rvOf CKR_BUFFER_TOO_SMALL)
      other -> refuse pHandleOut (rvOf (joinCode other))
