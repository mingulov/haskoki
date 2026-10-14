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
-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoki.FFI.Async
  ( AsyncCtx (..)
  , AsyncData
  , JobHandle
  , StoreBox (..)
  , asyncLiveHandles
  , asyncCloseCtx
  , allocJobHandle
  , freeJobHandle
  , resolveJobHandle
  , encodeJobHandle
  , decodeJobHandle
  , submitTransfer
  , joinTransfer
  , jobFunctionCode
  , codeJobFunction
  , decodeAsyncFunctionName
  , pokeCompletion
  , pokeNeed
  , haskokiAsyncOpen
  , haskokiAsyncClose
  , haskokiAsyncDigestInit
  , haskokiAsyncStart
  , haskokiAsyncPoll
  , haskokiAsyncComplete
  , haskokiAsyncCancel
  , haskokiAsyncStoreOpen
  , haskokiAsyncStoreClose
  , haskokiAsyncOpenOn
  , haskokiAsyncGetId
  , haskokiAsyncJoin
  ) where

import Control.Exception (SomeException, finally, mask, mask_, onException, try)
import Data.Bits ((.&.), (.|.), shiftL)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCString)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Word (Word32, Word8, Word64)
import Foreign.C.String (CString, peekCString)
import Foreign.C.Types (CULong (..))
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
  , claimTableClose
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
import Haskoki.Runtime.Config (newConfigCell, resolveOnce)
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
-- null check, the dereference, and the admission run masked as
-- one entry step (no interruptible operation inside, so no kill
-- can split them), and the admitted borrower holds its count
-- across the whole call — close retires the gate and waits the
-- count out before it drains or frees anything. Null and retired
-- contexts refuse identically, before touching any state.
withCtx :: StablePtr AsyncCtx -> (AsyncCtx -> IO CULong) -> IO CULong
withCtx ctx k = guarded $ mask $ \restore -> do
  mC <- enterCtx ctx
  case mC of
    Nothing -> pure (toRV 0x05)
    Just c -> restore (k c) `finally` exitTableUse (acTable c)

-- | Masked entry step for 'withCtx': null check, dereference,
-- admission. Callers hold the mask; every step here is
-- non-blocking, so entry never parks while masked.
enterCtx :: StablePtr AsyncCtx -> IO (Maybe AsyncCtx)
enterCtx ctx
  | isNullStable ctx = pure Nothing
  | otherwise = do
      c <- deRefStablePtr ctx
      ok <- enterTableUse (acTable c)
      pure (if ok then Just c else Nothing)

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
haskokiAsyncOpen = guardedPtr $ do
  cell <- newConfigCell
  eCfg <- resolveOnce cell
  case eCfg of
    Left _ -> pure (castPtrToStablePtr nullPtr)
    Right cfg -> do
      env <- newEnv (rulesFromConfig cfg)
      ini <- initialize env defaultInitArgs
      case ini of
        OutcomeErr _ -> pure (castPtrToStablePtr nullPtr)
        OutcomeOk () -> do
          eSeat <- seatToken env (SlotId 0)
          case eSeat of
            Left _ -> pure (castPtrToStablePtr nullPtr)
            Right () -> do
              m0 <- snapshotModel env
              let sid = SessionId (mNextSession m0)
              r <- openBackend "provider=default"
              case r of
                EngineFail _ -> pure (castPtrToStablePtr nullPtr)
                EngineOk be -> case planCall (envRules env) m0 openReq of
                  Immediate pc -> do
                    pr <- publishCommit env be pc
                    case pr of
                      Left _ -> closeBackend be >> pure (castPtrToStablePtr nullPtr)
                      Right () -> do
                        mTable <- tryNewAsyncTable ctxCapacity
                        case mTable of
                          Nothing ->
                            -- Table-allocator refusal (past 2^32-1
                            -- tables): NULL like every other open
                            -- failure, with the backend shut.
                            closeBackend be >> pure (castPtrToStablePtr nullPtr)
                          Just table -> do
                            enableAsyncSession table sid
                            live <- newIORef Set.empty
                            newStablePtr (AsyncCtx env be sid table live Nothing)
                  _ -> closeBackend be >> pure (castPtrToStablePtr nullPtr)
  where
    openReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []

-- | Close a context through its handle slot: the winning claim
-- retires the table gate, waits out admitted borrowers, cancels
-- every live job exactly once, retires every live handle, shuts
-- the backend, frees the pointer, and nulls the slot. A racing
-- second close through the same slot claims nothing and only
-- re-nulls the slot, so the pointer frees exactly once; closing
-- a null slot is a silent no-op, so close-through-the-slot stays
-- idempotent by construction. Context pointers must otherwise
-- not be used after close (@fclose@ parity with the crypto
-- context): calls admitted before the claim run to completion
-- first, and calls arriving after it are refused.
haskokiAsyncClose :: Ptr (StablePtr AsyncCtx) -> IO ()
haskokiAsyncClose pSlot = guardedUnit $
  if pSlot == nullPtr
    then pure ()
    else do
      ctx <- peek pSlot
      if isNullStable ctx
        then pure ()
        else do
          c <- deRefStablePtr ctx
          first <- claimTableClose (acTable c)
          if first
            then do
              closeClaimedCtx c
              freeStablePtr ctx
            else pure ()
          poke pSlot (castPtrToStablePtr nullPtr)

-- | The close worker: claim the table gate, wait out admitted
-- borrowers, then run the same drain the export runs after its
-- winning claim — retire this table's detach attachments (its
-- active joins resolve canceled, durably; sibling contexts on
-- the same store keep theirs), drain jobs and handles, shut the
-- backend. Only the winning claim drains; closes after teardown
-- are silent no-ops. Value-level teardown only: a 'StablePtr'
-- owner frees its own pointer separately. Exported so tests
-- assert drain state through the same worker the export calls.
asyncCloseCtx :: AsyncCtx -> IO ()
asyncCloseCtx ctx = do
  first <- claimTableClose (acTable ctx)
  if first
    then closeClaimedCtx ctx
    else pure ()

-- | Await admitted borrowers, then drain one claimed context.
-- Runs only on the winning close claim (see 'asyncCloseCtx' and
-- 'haskokiAsyncClose').
closeClaimedCtx :: AsyncCtx -> IO ()
closeClaimedCtx ctx = do
  awaitTableQuiescent (acTable ctx)
  case acDetach ctx of
    Nothing -> pure ()
    Just dc -> do
      _ <- retireLiveTableFor dc (asyncTableId (acTable ctx))
      pure ()
  live <- readIORef (acLive ctx)
  mapM_ drainOne (Set.toList live)
  closeBackend (acBackend ctx)
  where
    drainOne :: Ptr () -> IO ()
    drainOne key = do
      let h = castPtrToStablePtr key :: StablePtr JobHandle
      -- Retire-then-cancel per key, as before: retirement is
      -- idempotent, so a racing terminal path simply wins or loses
      -- the delete, and the job id comes from the pure key decode —
      -- nothing is dereferenced or freed.
      freeJobHandle ctx h
      case decodeJobHandle h of
        Nothing -> pure ()
        Just jid -> do
          _ <- cancelJob (acTable ctx) jid
          pure ()

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
      Right _ -> do
        let jobReq = JobRequest
              { jrSession = sid
              , jrFunction = jfunc
              , jrWork = WorkCall res eff
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
haskokiAsyncStoreOpen cPath = guardedPtr $ do
  eStore <- openStoreByPath cPath
  case eStore of
    Left _ -> pure (castPtrToStablePtr nullPtr)
    Right store -> do
      mDc <- ensureHomeToken store
      case mDc of
        Nothing -> do
          storeClose store
          pure (castPtrToStablePtr nullPtr)
        Just dc -> newStablePtr (StoreBox store dc)

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
            emptyDelta { sdPutTokens = [homeToken] }
          case res of
            Committed -> openDc
            _ -> pure Nothing
      | otherwise -> pure Nothing
  where
    homeToken = TokenRecord
      { trId = storeHomeToken
      , trSlot = SlotId 0
      , trGeneration = Generation 0
      , trLabel = "haskoki-async"
      , trAuth = tokenAuthNew
      }
    openDc = do
      eDc <- openDetached store storeHomeToken
      pure $ case eDc of
        Left _ -> Nothing
        Right dc -> Just dc

-- | Close a store through its handle slot: release single-writer
-- ownership, free the pointer, and null the slot. Idempotent by
-- construction, like context close.
haskokiAsyncStoreClose :: Ptr (StablePtr StoreBox) -> IO ()
haskokiAsyncStoreClose pSlot = guardedUnit $
  if pSlot == nullPtr
    then pure ()
    else do
      box <- peek pSlot
      if isNullStable box
        then pure ()
        else do
          b <- deRefStablePtr box
          storeClose (sbStore b)
          freeStablePtr box
          poke pSlot (castPtrToStablePtr nullPtr)

-- | Open a context on a process-level store: fresh environment,
-- provider init, token\/object reload from the store, one proof
-- session, live backend, and an empty job table bound to the box's
-- detach state. Any failure reports NULL.
haskokiAsyncOpenOn :: StablePtr StoreBox -> IO (StablePtr AsyncCtx)
haskokiAsyncOpenOn box = guardedPtr $
  if isNullStable box
    then pure (castPtrToStablePtr nullPtr)
    else do
      b <- deRefStablePtr box
      cell <- newConfigCell
      eCfg <- resolveOnce cell
      case eCfg of
        Left _ -> pure (castPtrToStablePtr nullPtr)
        Right cfg -> do
          env <- newEnv (rulesFromConfig cfg)
          ini <- initialize env defaultInitArgs
          case ini of
            OutcomeErr _ -> pure (castPtrToStablePtr nullPtr)
            OutcomeOk () -> do
              eLoaded <- storeLoadTokens (sbStore b)
              case eLoaded of
                Left _ -> pure (castPtrToStablePtr nullPtr)
                Right loaded -> do
                  eRestored <- restoreStoreState env loaded
                  case eRestored of
                    Left _ -> pure (castPtrToStablePtr nullPtr)
                    Right () -> do
                      m0 <- snapshotModel env
                      let sid = SessionId (mNextSession m0)
                      r <- openBackend "provider=default"
                      case r of
                        EngineFail _ -> pure (castPtrToStablePtr nullPtr)
                        EngineOk be -> case planCall (envRules env) m0 openReq of
                          Immediate pc -> do
                            pr <- publishCommit env be pc
                            case pr of
                              Left _ -> closeBackend be >> pure (castPtrToStablePtr nullPtr)
                              Right () -> do
                                mTable <- tryNewAsyncTable ctxCapacity
                                case mTable of
                                  Nothing ->
                                    -- Table-allocator refusal (past 2^32-1
                                    -- tables): NULL like every other open
                                    -- failure, with the backend shut.
                                    closeBackend be >> pure (castPtrToStablePtr nullPtr)
                                  Just table -> do
                                    enableAsyncSession table sid
                                    live <- newIORef Set.empty
                                    newStablePtr (AsyncCtx env be sid table live (Just (sbDetach b)))
                          _ -> closeBackend be >> pure (castPtrToStablePtr nullPtr)
  where
    openReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []

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
-- handle handoff runs protected (see 'joinTransfer').
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
            Just jfunc -> do
              out <- joinJob dc (acEnv c) (acTable c) JoinRequest
                { jqPid = pid
                , jqFunction = jfunc
                , jqSession = sid
                , jqCapacity = cap
                }
              case out of
                JoinOk jid
                  | jobIdExhausted jid -> mask_ $ do
                      -- Cancel through the detach wrapper so the
                      -- durable attachment resolves canceled too;
                      -- masked like the transfer so a kill cannot
                      -- strand the fresh job mid-cancel.
                      _ <- cancelThrough c jid
                      refuse pHandleOut (rvOf CKR_HOST_MEMORY)
                  | otherwise -> joinTransfer (pure ()) c jid pHandleOut
                JoinShort need -> do
                  if pNeedOut /= nullPtr then poke pNeedOut need else pure ()
                  refuse pHandleOut (rvOf CKR_BUFFER_TOO_SMALL)
                other -> refuse pHandleOut (rvOf (joinCode other))

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
