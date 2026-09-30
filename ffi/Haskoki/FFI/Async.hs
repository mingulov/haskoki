{- | Attached-async FFI surface: attached job handles with poll\/complete
semantics over the 'Haskoki.Runtime.Async' table.

An 'AsyncCtx' is a caller-owned context (model environment, live
OpenSSL4 backend, one proof session, one job table, one live-handle
set), opened and closed like the crypto context. Jobs are opaque
'JobHandle' tokens: submission allocates exactly one native handle,
and every terminal path (complete, cancel, drive-error, close-drain)
frees it exactly once. Late use of a freed handle is a typed stale
refusal, never a use-after-free (liveness is checked against the
handle set before any dereference).

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
reattaches a persistent id as a fresh live job. Contexts opened
without a store ('haskokiAsyncOpen') cannot detach or join — there
is nowhere durable to put the record — and report typed failures.
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

import Control.Exception (SomeException, try)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCString)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Word (Word8, Word64)
import Foreign.C.String (CString, peekCString)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.StablePtr
  ( StablePtr
  , castPtrToStablePtr
  , castStablePtrToPtr
  , deRefStablePtr
  , freeStablePtr
  , newStablePtr
  )
import Foreign.Storable (peek, poke, peekByteOff)

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
  , jobFunctionOf
  , TerminalState (..)
  , cancelJob
  , completeJob
  , decodeCompletion
  , enableAsyncSession
  , jobReadyNeed
  , newAsyncTable
  , pollJob
  , startJob
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
  , retireLiveTable
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

-- | One opaque native job token. Never dereferenced after its
-- terminal path frees it: every entry checks the live set first.
data JobHandle = JobHandle !JobId

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

withCtx :: StablePtr AsyncCtx -> (AsyncCtx -> IO CULong) -> IO CULong
withCtx ctx k = guarded $
  if isNullStable ctx
    then pure (toRV 0x05)
    else deRefStablePtr ctx >>= k

-- | Resolve a live job handle to its job id. Stale (freed or
-- foreign) tokens refuse without dereferencing.
withLiveJob
  :: AsyncCtx -> StablePtr JobHandle -> (JobId -> IO CULong) -> IO CULong
withLiveJob ctx h k
  | isNullStable h = pure (rvOf CKR_ARGUMENTS_BAD)
  | otherwise = do
      live <- readIORef (acLive ctx)
      if castStablePtrToPtr h `Set.notMember` live
        then pure (rvOf CKR_ARGUMENTS_BAD)
        else do
          JobHandle jid <- deRefStablePtr h
          k jid

-- | Free a job's native handle exactly once. The live-set delete
-- runs first so a racing second terminal path finds nothing to
-- free; only the set member dereferences and frees.
freeJobHandle :: AsyncCtx -> StablePtr JobHandle -> IO ()
freeJobHandle ctx h = do
  wasLive <- atomicModifyIORef' (acLive ctx) $ \live ->
    let key = castStablePtrToPtr h
    in if key `Set.member` live
      then (Set.delete key live, True)
      else (live, False)
  if wasLive then freeStablePtr h else pure ()

-- | Allocate a job's native handle (submission success path only).
allocJobHandle :: AsyncCtx -> JobId -> IO (StablePtr JobHandle)
allocJobHandle ctx jid = do
  h <- newStablePtr (JobHandle jid)
  atomicModifyIORef' (acLive ctx) $ \live ->
    (Set.insert (castStablePtrToPtr h) live, ())
  pure h

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
                        table <- newAsyncTable ctxCapacity
                        enableAsyncSession table sid
                        live <- newIORef Set.empty
                        newStablePtr (AsyncCtx env be sid table live Nothing)
                  _ -> closeBackend be >> pure (castPtrToStablePtr nullPtr)
  where
    openReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []

-- | Close a context through its handle slot: cancel every live
-- job exactly once, free every live handle exactly once, shut the
-- backend, free the pointer, and null the slot. Closing a null
-- slot is a silent no-op, so close-through-the-slot is idempotent
-- by construction (no use-after-free on any conforming path).
-- Context pointers must otherwise not be used after close
-- (@fclose@ parity with the crypto context).
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
          asyncCloseCtx c
          freeStablePtr ctx
          poke pSlot (castPtrToStablePtr nullPtr)

-- | The close worker: retire the detach attachments (active joins
-- resolve canceled, durably), drain jobs and handles, shut the
-- backend. Exported so tests assert drain state through the same
-- function the export calls.
asyncCloseCtx :: AsyncCtx -> IO ()
asyncCloseCtx ctx = do
  case acDetach ctx of
    Nothing -> pure ()
    Just dc -> do
      _ <- retireLiveTable dc
      pure ()
  live <- readIORef (acLive ctx)
  mapM_ drainOne (Set.toList live)
  closeBackend (acBackend ctx)
  where
    drainOne :: Ptr () -> IO ()
    drainOne key = do
      let h = castPtrToStablePtr (castPtr key) :: StablePtr JobHandle
      wasLive <- atomicModifyIORef' (acLive ctx) $ \s ->
        if key `Set.member` s
          then (Set.delete key s, True)
          else (s, False)
      if not wasLive
        then pure ()
        else do
          JobHandle jid <- deRefStablePtr h
          _ <- cancelJob (acTable ctx) jid
          freeStablePtr h

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
-- (sync recalls) publish and report with no job.
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
    Execute res eff -> do
      let jobReq = JobRequest
            { jrSession = sid
            , jrFunction = jfunc
            , jrWork = WorkCall res eff
            , jrTicks = fromIntegral ticks
            , jrCapacity = cap
            }
      started <- startJob (acTable c) jobReq
      case started of
        Left deny -> refuse pHandleOut (rvOf (denyCode deny))
        Right jid -> do
          h <- allocJobHandle c jid
          poke pHandleOut h
          pure (rvOf CKR_PENDING)

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
-- once and free the handle; short buffers size with the job held.
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

-- | Cancel a job: live jobs terminate and free the handle; stale
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
                                table <- newAsyncTable ctxCapacity
                                enableAsyncSession table sid
                                live <- newIORef Set.empty
                                newStablePtr (AsyncCtx env be sid table live (Just (sbDetach b)))
                          _ -> closeBackend be >> pure (castPtrToStablePtr nullPtr)
  where
    openReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []

-- | Detach a live job (GetID): on success the persistent id lands in
-- the out-pointer and the old native handle is freed (late use is
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
-- NULL). A null handle out-pointer refuses without joining.
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
                JoinOk jid -> do
                  h <- allocJobHandle c jid
                  poke pHandleOut h
                  pure (rvOf CKR_PENDING)
                JoinShort need -> do
                  if pNeedOut /= nullPtr then poke pNeedOut need else pure ()
                  refuse pHandleOut (rvOf CKR_BUFFER_TOO_SMALL)
                other -> refuse pHandleOut (rvOf (joinCode other))
