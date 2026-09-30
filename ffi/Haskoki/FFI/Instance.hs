{- | Native boundary: the owned provider instance behind
@C_WaitForSlotEvent@ and @HASKOKI_Control@.

The C side (@cbits\/control_entry.c@) holds one @StablePtr@ per init
interval: opened from @C_Initialize@ (config resolved once from
@HASKOKI_CONFIG@\/@HASKOKI_TRACE@), closed from @C_Finalize@ (which
finalizes the event queue first, waking ALL waiters). The handle
points at a single-shot liveness cell, never at the
instance directly, and is never freed — so every export can
re-validate it with a plain read, and use-after-close answers
@CKR_CRYPTOKI_NOT_INITIALIZED@ instead of touching freed memory.
No top-level mutable Haskell state: the instance handle crosses as
an explicit pointer, and the per-handle cell carries the
generation.

Blocking waits run on the calling bound thread; the threaded RTS
keeps other Haskell threads live. No Haskell-side threads are ever
spawned here.
-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Haskoki.FFI.Instance
  ( Instance (..)
  , InstanceCell
  , readLiveInstance
  , haskokiInstanceOpen
  , haskokiInstanceClose
  , haskokiWaitForSlotEvent
  , haskokiControl
  , buildInstance
  ) where

import Control.Exception (SomeException, mask_, onException, try)
import Control.Monad (when)
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS
import Data.Bits ((.&.))
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.Word (Word8, Word64)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.StablePtr
  ( StablePtr
  , castPtrToStablePtr
  , castStablePtrToPtr
  , deRefStablePtr
  , newStablePtr
  )
import Foreign.Storable (peek, poke)
import System.Posix.Process (getProcessID)

import Haskoki.FFI.Exports (returnCodeToRV)
import Haskoki.Runtime.Async (AsyncTable, newAsyncTable)
import Haskoki.Runtime.Catalog (effectiveCatalog)
import Haskoki.Runtime.SlotEvents (SlotEvents, SlotDefinition (..), newSlotEvents, closeSlotEvents)
import Haskoki.Runtime.Config
  ( Config (..)
  , ControlCfg (..)
  , Limits (..)
  , TraceCfg (..)
  , newConfigCell
  , resolveOnce
  )
import Haskoki.Runtime.Control
  ( ControlState
  , dispatchControl
  , bindPresenceOwner
  , newControlState
  , setControlTracer
  )
import Haskoki.Runtime.Events
  ( EventQueue
  , OverflowPolicy (DropOldest)
  , SlotEvent (evSlot)
  , TokenRegistry
  , WaitOutcome (..)
  , finalizeEvents
  , newEventQueue
  , newTokenRegistry
  , registryEvents
  , tryWaitSlotEvent
  , waitCode
  , waitSlotEvent
  )
import Haskoki.Runtime.Trace (Tracer, drainTracer, newTracer)
import Haskoki.Types (ReturnCode (..), SlotId (..))

-- ---------------------------------------------------------------------------
-- Instance
-- ---------------------------------------------------------------------------

-- | The owned provider instance: resolved config, slot-event queue,
-- presence registry, async table, control state, tracer.
data Instance = Instance
  { instConfig :: !Config
  , instSlots :: !SlotEvents
  , instEvents :: !EventQueue
  , instRegistry :: !TokenRegistry
  , instAsync :: !AsyncTable
  , instControl :: !ControlState
  , instTracer :: !Tracer
  }

-- | @CKF_DONT_BLOCK@ for @C_WaitForSlotEvent@: 1, pinned by
-- @spec\/vendor\/pkcs11.h@ (NOT 0x2 — that is
-- @CKF_OS_LOCKING_OK@; the C proof caught the mixup).
ckfDontBlock :: Word64
ckfDontBlock = 0x00000001

-- | Mandatory top-level exception boundary: no Haskell exception may
-- cross into C. Ordinary failure is @CKR_GENERAL_ERROR@.
guarded :: IO CULong -> IO CULong
guarded body = do
  r <- try body
  case r of
    Right rv -> pure rv
    Left (_ :: SomeException) -> pure (CULong 5)

-- ---------------------------------------------------------------------------
-- Liveness cell
-- ---------------------------------------------------------------------------

-- | The per-handle generation: @Just@ the owned instance while the
-- interval is live, @Nothing@ once closed. Open mints a fresh cell
-- per handle; close takes it exactly once (atomically).
newtype InstanceCell = InstanceCell (IORef (Maybe Instance))

-- | Borrow the live value during unpublished construction under the init lock,
-- or during a Control call under the state lock. Never reinterpret the cell.
readLiveInstance :: StablePtr InstanceCell -> IO (Maybe Instance)
readLiveInstance ptr
  | castStablePtrToPtr ptr == nullPtr = pure Nothing
  | otherwise = do
      InstanceCell live <- deRefStablePtr ptr
      readIORef live

-- | Handle discipline. The crash this closes is resolve-then-enter
-- across close (@deRefStablePtr@ racing @freeStablePtr@): C cannot
-- observe Haskell entry completion, so no C-side grace period is
-- sound under preemption, and splitting queue-finalize from the
-- release would need a new dynamic symbol (C ABI freeze). Hence the
-- per-handle cell instead of a global gate (of which this module
-- keeps none — see the 'FfiHygieneSpec' pin):
--
-- * the export handle points at the CELL, never at the instance;
-- * the slot is NEVER freed (this module imports no @freeStablePtr@
--   at all), so every slot value is unique forever and every
--   @deRefStablePtr@ is memory-safe by construction — a
--   value-identity gate over freed slots could not promise that
--   (the RTS reuses freed slots);
-- * close atomically takes the cell to @Nothing@, so exactly one
--   closer finalizes; entries read the cell and serve the held
--   value, or answer @CKR_CRYPTOKI_NOT_INITIALIZED@ on @Nothing@.
--
-- Two deliberate consequences. Retention: one slot plus one
-- (emptied) cell per init interval stays rooted — words, not the
-- instance graph, which close unroots for collection. Benign TOCTOU:
-- an entry that reads @Just@ just before close serves its held
-- (GC-alive) value — memory-safe, linearizing before the close;
-- cross-thread staleness of the plain read can only widen that same
-- benign window, never crash.
nullCell :: StablePtr InstanceCell
nullCell = castPtrToStablePtr nullPtr

-- | Open an owned instance: resolve the config once, size the queue
-- and tables from the §3 limits, wire control to the registry.
foreign export ccall "haskoki_instance_open" haskokiInstanceOpen
  :: IO (StablePtr InstanceCell)
foreign export ccall "haskoki_instance_close" haskokiInstanceClose
  :: StablePtr InstanceCell -> IO ()
foreign export ccall "haskoki_wait_for_slot_event" haskokiWaitForSlotEvent
  :: StablePtr InstanceCell -> CULong -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_control" haskokiControl
  :: StablePtr InstanceCell -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong
  -> IO CULong

-- | Open; NULL on any failure. A bad @HASKOKI_CONFIG@ fails the
-- open (the C layer then fails init loudly) — misspellings never
-- silently fall back to defaults.
haskokiInstanceOpen :: IO (StablePtr InstanceCell)
haskokiInstanceOpen = do
  r <- try openBody
  case r of
    Right ptr -> pure ptr
    Left (_ :: SomeException) -> pure nullCell
  where
    openBody = mask_ $ do
      cell <- newConfigCell
      eCfg <- resolveOnce cell
      case eCfg of
        Left _ -> pure nullCell
        Right cfg -> do
          inst <- buildInstance cfg
          (newIORef (Just inst) >>= newStablePtr . InstanceCell)
            `onException` closeSlotEvents (instSlots inst)

-- | Build an owned instance from an already-resolved config (the
-- environment-free half of 'haskokiInstanceOpen', extracted so
-- the config→wiring mapping is directly testable without
-- process-wide environment mutation).
buildInstance :: Config -> IO Instance
buildInstance cfg = mask_ $ do
  let catalog = effectiveCatalog cfg
      limits = cfgLimits cfg
  when (Map.size catalog > limSlots limits) $
    ioError (userError "serving catalog exceeds limits.slots")
  slots <- newSlotEvents (limEvents limits)
    [SlotDefinition slot (ccTestEnabled (cfgControl cfg)) | slot <- Map.keys catalog]
    >>= either (ioError . userError . show) pure
  (do
    -- These remain private scenario/proof services; serving presence never
    -- falls back to their FIFO or their separately sized async table.
    eq <- newEventQueue (max 8 (limEvents limits)) DropOldest
    at <- newAsyncTable (max 8 (limJobs limits))
    reg <- newTokenRegistry eq at
    let ctl = cfgControl cfg
    tr <- newTracer (max 8 (tcQueueLimit (cfgTrace cfg))) (fileSink cfg) False
    cs <- newControlState cfg reg at (ccTestEnabled ctl) False
    setControlTracer cs tr
    pure (Instance cfg slots eq reg at cs tr))
    `onException` closeSlotEvents slots

-- | Append-only trace sink (best effort; failures are counted by the
-- tracer, never thrown). @\{pid\}@ in the path expands to the pid.
fileSink :: Config -> BS.ByteString -> IO (Either String ())
fileSink cfg line
  | not (tcEnabled (cfgTrace cfg)) = pure (Right ())
  | otherwise = do
      pid <- getProcessID
      let path = expandPid (tcPath (cfgTrace cfg)) (fromIntegral pid)
      r <- try (BS.appendFile path (line <> BS.singleton 0x0A))
      case r of
        Right () -> pure (Right ())
        Left (ex :: SomeException) -> pure (Left (show ex))
  where
    expandPid [] _ = []
    expandPid ('{' : 'p' : 'i' : 'd' : '}' : rest) pid =
      show (pid :: Int) ++ expandPid rest pid
    expandPid (c : rest) pid = c : expandPid rest pid

-- | Close: atomically take the cell (exactly one closer wins),
-- then finalize the event queue FIRST (wakes ALL waiters with the
-- source-correct code) and drain the tracer on the taken value.
-- Idempotent on NULL AND on already-closed handles (a stale close
-- takes @Nothing@ and does nothing — never a touch of freed
-- memory), silent on failure (finalize has no error channel left).
-- The emptied cell and its slot stay rooted (words per interval);
-- the taken instance graph is unrooted for collection.
haskokiInstanceClose :: StablePtr InstanceCell -> IO ()
haskokiInstanceClose ptr = do
  r <- try closeBody
  case r of
    Right () -> pure ()
    Left (_ :: SomeException) -> pure ()
  where
    closeBody
      | castStablePtrToPtr ptr == nullPtr = pure ()
      | otherwise = do
          InstanceCell live <- deRefStablePtr ptr
          mInst <- atomicModifyIORef' live (\m -> (Nothing, m))
          case mInst of
            Nothing -> pure ()
            Just inst -> do
              bindPresenceOwner (instControl inst) Nothing
              closeSlotEvents (instSlots inst)
              finalizeEvents (instEvents inst)
              _ <- drainTracer (instTracer inst)
              pure ()

-- | Run against a live instance or report @CKR_GENERAL_ERROR@ on a
-- null one (unchanged). The @deRef@ is memory-safe by construction
-- (slots are never freed, hence never reused); a taken cell
-- (stale generation) answers @CKR_CRYPTOKI_NOT_INITIALIZED@ — the
-- same fail-fast the C layer gives unpublished handles — and a live
-- cell serves its held value.
withInstance :: StablePtr InstanceCell -> (Instance -> IO CULong) -> IO CULong
withInstance ptr k = guarded $ do
  if castStablePtrToPtr ptr == nullPtr
    then pure (CULong 5)
    else do
      mInst <- readLiveInstance ptr
      case mInst of
        Nothing -> pure (CULong 0x190)
        Just inst -> k inst

-- | Blocking (@flags == 0@) or @DON'T_BLOCK@ slot-event wait over the
-- instance queue. Returns the source-correct @CK_RV@ and, on an
-- event, the slot id through @pSlot@.
haskokiWaitForSlotEvent :: StablePtr InstanceCell -> CULong -> Ptr CULong -> IO CULong
haskokiWaitForSlotEvent ptr (CULong flags) pSlot = withInstance ptr $ \inst -> do
  if pSlot == nullPtr
    then pure (CULong 7)
    else do
      let queue = registryEvents (instRegistry inst)
      w <- if flags .&. ckfDontBlock /= 0
        then tryWaitSlotEvent queue
        else waitSlotEvent queue
      case w of
        WaitEvent ev -> do
          let SlotId n = evSlot ev
          poke pSlot (CULong (fromIntegral n))
          pure (CULong (fromIntegral (waitCode w)))
        _ -> pure (CULong (fromIntegral (waitCode w)))

-- | The @HASKOKI_Control@ body: budget convention first (null
-- response pointer = pure query; short capacity = required +
-- nothing executed), then dispatch once and copy the response.
haskokiControl
  :: StablePtr InstanceCell -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong
  -> IO CULong
haskokiControl ptr pReq (CULong reqLen) pResp pLen = withInstance ptr $ \inst -> do
  if pLen == nullPtr
    then pure (CULong 7)
    else if pReq == nullPtr && reqLen /= 0
      then pure (CULong 7)
      else do
        req <- if reqLen == 0
          then pure BS.empty
          else BS.packCStringLen (castPtr pReq, fromIntegral reqLen)
        mCap <- if pResp == nullPtr
          then pure Nothing
          else Just <$> (do CULong cap <- peek pLen; pure cap)
        (code, body, needed) <- dispatchControl (instControl inst) req mCap
        _ <- drainTracer (instTracer inst)
        let rv = CULong (fromIntegral (returnCodeToRV code))
        case mCap of
          Nothing -> do
            poke pLen (CULong (fromIntegral needed))
            pure rv
          Just cap -> case code of
            CKR_OK -> do
              writeBytes pResp body
              poke pLen (CULong (fromIntegral needed))
              pure rv
            CKR_BUFFER_TOO_SMALL -> do
              -- The required length is authoritative; the short
              -- diagnostic body is copied only if it fits.
              whenFits pResp cap body
              poke pLen (CULong (fromIntegral needed))
              pure rv
            _ -> do
              whenFits pResp cap body
              poke pLen (CULong (fromIntegral needed))
              pure rv
  where
    writeBytes dst bs =
      BS.useAsCStringLen bs $ \(src, len) -> copyBytes dst (castPtr src) len
    whenFits dst cap bs
      | fromIntegral (BS.length bs) <= cap = writeBytes dst bs
      | otherwise = pure ()
