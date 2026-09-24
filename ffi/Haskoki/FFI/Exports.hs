{- | FFI exports: routed crypto contexts for the loader proof
(the direct surface moved to C).

The direct symbols (@haskoki_initialize@, @haskoki_finalize@,
@haskoki_get_slot_list@) are implemented in C
(@cbits\/standard_surface.c@) over C-owned atomic liveness state —
no Haskell global remains (see @tests\/model\/FfiHygieneSpec.hs@,
which pins zero top-level mutable state tree-wide).
Metadata ('C_GetInfo'), mechanism advertisement, and the one-shot
SHA-256 slice are served from the C facade's static data \/
TEMPORARY adapter; the pure request\/outcome contracts
route everything past discovery.

Lifetimes (per @03-abi-and-runtime.md@ §5): the GHC RTS is
process-lifetime (started once by @cbits\/rts_bootstrap.c@, never shut
down). Finalization MUST NOT stop the RTS — there is deliberately
no @hs_exit@ anywhere in this package's own sources (see
@scripts\/test-loader.sh@ static checks).

State note: this module holds no top-level mutable state. Contexts
are caller-owned ('CryptoCtx' behind explicit 'StablePtr's);
no global may be added here.

The first routed crypto exports ('CryptoCtx' and the digest
pair) behind explicit caller-owned contexts instead of global
state. Full table-slot routing is later work; these prove the
Request -> Transition -> planner -> driver -> backend -> output
path across the real export boundary.
-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoki.FFI.Exports
  ( CryptoCtx
  , CryptoAcquisition (..)
  , cryptoAcquisition
  , haskokiCryptoOpen
  , openCryptoCtxWith
  , haskokiCryptoClose
  , haskokiCryptoDigestInit
  , haskokiCryptoDigest
  , returnCodeToRV
  ) where

import Control.Exception
  ( AsyncException
  , Exception (fromException)
  , SomeException
  , catch
  , mask
  , onException
  , throwIO
  , try
  )
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64, Word8)
import Foreign.C.Types (CULong (..))
import Foreign.Ptr (Ptr, nullPtr)
import Foreign.StablePtr
  ( StablePtr
  , castPtrToStablePtr
  , castStablePtrToPtr
  , deRefStablePtr
  , freeStablePtr
  , newStablePtr
  )
import Foreign.Storable (peek)

import Haskoki.Engine.Backend (BackendEnv, CryptoBackend (..))
import qualified Haskoki.Engine.Backend as B
import Haskoki.Engine.Driver (drainReleases, encodeResult, runEffect)
import Haskoki.Engine.OpenSSL4 (OpenSSL4)
import Haskoki.FFI.Decode (decodeInputBytes, decodeIntent)
import Haskoki.FFI.Encode
  ( BoundBuffer (..)
  , EncodeReport (..)
  , encodeLength
  , encodeWrites
  , nativeToWrite
  )
import Haskoki.Model (Model (..), SessionState (ssOps), lookupSession)
import Haskoki.Operation
  ( SlotKind (..)
  , StagedOutput (stBytes)
  , activeDigest
  , lookupSingle
  , stagedOf
  )
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request
  ( FunctionId (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  )
import Haskoki.Runtime.Config (Config, newConfigCell, resolveOnce)
import Haskoki.Session (AdmitDeny)
import Haskoki.Runtime.Lifecycle
  ( Env
  , defaultInitArgs
  , envRules
  , initialize
  , newEnv
  , publish
  , rulesFromConfig
  , seatToken
  , snapshotModel
  )
import Haskoki.Transition (finishEffect, planCall)
import Haskoki.Outcome
  ( EffectRequest (..)
  , ModelFault (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  )
import Haskoki.Output (TypedWrite (..))
import Haskoki.Types
  ( Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

-- Direct surface (C-owned). The @haskoki_initialize@ \/
-- @haskoki_finalize@ \/ @haskoki_get_slot_list@ symbols keep their C
-- ABI bit-for-bit but are implemented in @cbits\/standard_surface.c@
-- over C-owned atomic liveness state; no Haskell global remains.
-- Behavior matrix pinned by @tests\/c\/loader.c@ case @T00D@.

-- CK_RV mirrors (unsigned long values from PKCS#11 v2.40;
-- the generator produces these from byte-pinned headers).
ckrOK :: Word32
ckrOK = 0x00000000
ckrBufferTooSmall :: Word32
ckrBufferTooSmall = 0x00000150
ckrGeneralError :: Word32
ckrGeneralError = 0x00000005

toRV :: Word32 -> CULong
toRV = CULong . fromIntegral

-- | Run an export body with the mandatory top-level exception boundary
-- (§03.8): no Haskell exception may cross into C. Ordinary failure
-- surfaces as 'CKR_GENERAL_ERROR'.
guarded :: IO CULong -> IO CULong
guarded body = do
  r <- try body
  case r of
    Right rv -> pure rv
    Left (_ :: SomeException) -> pure (toRV ckrGeneralError)

-- ---------------------------------------------------------------------------
-- Routed crypto exports (digest proof path)
-- ---------------------------------------------------------------------------

-- | Pinned @CK_RV@ values (PKCS#11 v2.40) for every core return
-- code. The generator covers the C tables; the Haskell side
-- mirrors them here.
returnCodeToRV :: ReturnCode -> Word32
returnCodeToRV code = case code of
  CKR_OK -> 0x00000000
  CKR_HOST_MEMORY -> 0x00000002
  CKR_FUNCTION_CANCELED -> 0x00000050
  CKR_PENDING -> 0x00000204
  CKR_SESSION_ASYNC_NOT_SUPPORTED -> 0x00000205
  CKR_GENERAL_ERROR -> 0x00000005
  CKR_ARGUMENTS_BAD -> 0x00000007
  CKR_BUFFER_TOO_SMALL -> 0x00000150
  CKR_SESSION_HANDLE_INVALID -> 0x000000B3
  CKR_SESSION_COUNT -> 0x000000B1
  CKR_SESSION_READ_ONLY_EXISTS -> 0x000000B7
  CKR_SESSION_READ_ONLY -> 0x000000B5
  CKR_TOKEN_NOT_PRESENT -> 0x000000E0
  CKR_USER_ALREADY_LOGGED_IN -> 0x00000100
  CKR_USER_ANOTHER_ALREADY_LOGGED_IN -> 0x00000104
  CKR_USER_NOT_LOGGED_IN -> 0x00000101
  CKR_PIN_INCORRECT -> 0x000000A0
  CKR_PIN_LOCKED -> 0x000000A4
  CKR_CRYPTOKI_NOT_INITIALIZED -> 0x00000190
  CKR_CRYPTOKI_ALREADY_INITIALIZED -> 0x00000191
  CKR_OBJECT_HANDLE_INVALID -> 0x00000082
  CKR_ATTRIBUTE_SENSITIVE -> 0x00000011
  CKR_ATTRIBUTE_TYPE_INVALID -> 0x00000012
  CKR_TEMPLATE_INCOMPLETE -> 0x000000D0
  CKR_TEMPLATE_INCONSISTENT -> 0x000000D1
  CKR_MECHANISM_INVALID -> 0x00000070
  CKR_OPERATION_ACTIVE -> 0x00000090
  CKR_OPERATION_NOT_INITIALIZED -> 0x00000091
  CKR_SIGNATURE_INVALID -> 0x000000C0
  CKR_KEY_FUNCTION_NOT_PERMITTED -> 0x00000068
  CKR_KEY_TYPE_INCONSISTENT -> 0x00000063
  CKR_WRAPPING_KEY_TYPE_INCONSISTENT -> 0x00000115
  CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT -> 0x000000F2
  CKR_DATA_LEN_RANGE -> 0x00000021
  CKR_ENCRYPTED_DATA_INVALID -> 0x00000040
  CKR_ENCRYPTED_DATA_LEN_RANGE -> 0x00000041
  CKR_KEY_UNEXTRACTABLE -> 0x0000006A
  CKR_KEY_NOT_WRAPPABLE -> 0x00000069
  CKR_STATE_UNSAVEABLE -> 0x00000180
  CKR_SAVED_STATE_INVALID -> 0x00000160

rvOf :: ReturnCode -> CULong
rvOf = toRV . returnCodeToRV

-- | Opaque routed-crypto context: an 'Env' (model cell plus gate),
-- a live OpenSSL4 backend, and the proof session opened at
-- creation. Caller-owned: exactly one session lives here, and the
-- session argument of every call must name it; full session routing
-- arrives with the table slots.
data CryptoCtx = CryptoCtx
  { ccEnv :: !Env
  , ccBackend :: !(BackendEnv OpenSSL4)
  , ccSession :: !SessionId
  }

foreign export ccall "haskoki_hs_crypto_open" haskokiCryptoOpen
  :: IO (StablePtr CryptoCtx)
foreign export ccall "haskoki_hs_crypto_close" haskokiCryptoClose
  :: StablePtr CryptoCtx -> IO ()
foreign export ccall "haskoki_hs_crypto_digest_init" haskokiCryptoDigestInit
  :: StablePtr CryptoCtx -> CULong -> CULong -> Ptr Word8 -> CULong -> IO CULong
foreign export ccall "haskoki_hs_crypto_digest" haskokiCryptoDigest
  :: StablePtr CryptoCtx -> CULong -> Ptr Word8 -> CULong
  -> Ptr Word8 -> Ptr CULong -> IO CULong

-- | The null context: open failures report NULL, never a dangling pointer.
nullStable :: StablePtr a
nullStable = castPtrToStablePtr nullPtr

-- | Exception boundary for context-returning exports: failure is NULL.
guardedPtr :: IO (StablePtr a) -> IO (StablePtr a)
guardedPtr body = do
  r <- try body
  case r of
    Right p -> pure p
    Left (_ :: SomeException) -> pure nullStable

-- | Sync-failure boundary for the inner opens: an unexpected SYNC
-- exception becomes NULL (explicit sync failures already return
-- NULL directly); ASYNC exceptions propagate after the bracket
-- unwind, so a kill aborts the open instead of being swallowed
-- The @foreign export@ boundary ('haskokiCryptoOpen')
-- keeps its catch-all: no Haskell exception crosses into C.
guardedSyncPtr :: IO (StablePtr a) -> IO (StablePtr a)
guardedSyncPtr body = catch body $ \e ->
  case (fromException e :: Maybe AsyncException) of
    Just ae -> throwIO ae
    Nothing -> pure nullStable

-- | Exception boundary for unit exports: failure is silent (the
-- context is already unusable; there is no channel to report on).
guardedUnit :: IO () -> IO ()
guardedUnit body = do
  r <- try body
  case r of
    Right () -> pure ()
    Left (_ :: SomeException) -> pure ()

-- | Run against a live context or report a general error on a null
-- or dead one. No Haskell exception crosses into C.
withCtx :: StablePtr CryptoCtx -> (CryptoCtx -> IO CULong) -> IO CULong
withCtx ctx k = guarded $ do
  if castStablePtrToPtr ctx == nullPtr
    then pure (toRV ckrGeneralError)
    else deRefStablePtr ctx >>= k

-- | Injectable acquisition steps for the routed-crypto open
-- The production open threads 'cryptoAcquisition';
-- probes override steps to fail or count. The backend carries its
-- release on the post-acquire region ('finishCryptoOpen'),
-- structurally: a future step adds its release at its own acquire
-- site instead of relying on far-apart hand pairing.
data CryptoAcquisition = CryptoAcquisition
  { caInit :: !(Env -> IO (Outcome ()))
  , caSeat :: !(Env -> SlotId -> IO (Either AdmitDeny ()))
  , caOpenBackend :: !(IO (B.EngineResult (BackendEnv OpenSSL4)))
  , caCloseBackend :: !(BackendEnv OpenSSL4 -> IO ())
  }

-- | Production acquisition steps.
cryptoAcquisition :: CryptoAcquisition
cryptoAcquisition = CryptoAcquisition
  { caInit = \env -> initialize env defaultInitArgs
  , caSeat = seatToken
  , caOpenBackend = openBackend "provider=default"
  , caCloseBackend = closeBackend
  }

-- | Open a routed-crypto context: resolve the config, then open
-- over the production acquisition steps. Any failure reports NULL.
haskokiCryptoOpen :: IO (StablePtr CryptoCtx)
haskokiCryptoOpen = guardedPtr $ do
  cell <- newConfigCell
  eCfg <- resolveOnce cell
  case eCfg of
    Left _ -> pure nullStable
    Right cfg -> openCryptoCtxWith cryptoAcquisition cfg

-- | Open a routed-crypto context from a RESOLVED config over
-- injected acquisition steps: fresh 'Env', provider
-- initialization, token seating, one proof session, and a live
-- backend. The skeleton runs masked with each step restored; sync
-- failures report NULL, and async exceptions unwind through the
-- backend release and propagate (the @foreign export@ boundary
-- above still maps them to NULL for C).
openCryptoCtxWith
  :: CryptoAcquisition -> Config -> IO (StablePtr CryptoCtx)
openCryptoCtxWith ca cfg = guardedSyncPtr $ mask $ \restore -> do
  env <- newEnv (rulesFromConfig cfg)
  ini <- restore (caInit ca env)
  case ini of
    OutcomeErr _ -> pure nullStable
    OutcomeOk () -> do
      eSeat <- restore (caSeat ca env (SlotId 0))
      case eSeat of
        Left _ -> pure nullStable
        Right () -> do
          m0 <- snapshotModel env
          let sid = SessionId (mNextSession m0)
          r <- restore (caOpenBackend ca)
          case r of
            B.EngineFail _ -> pure nullStable
            B.EngineOk be -> restore (finishCryptoOpen ca env be m0 sid)

-- | Internal short-circuit: a post-backend step failed
-- synchronously while the backend is already acquired. Never
-- escapes the open (mapped to NULL after the single release);
-- async exceptions bypass it through the same release.
data AcquireFailed = AcquireFailed deriving (Show)

instance Exception AcquireFailed

-- | Plan and publish the proof session over an acquired backend.
-- Owns the backend release completely: explicit sync failures
-- short-circuit through 'AcquireFailed' (single close, then NULL),
-- and a throwing step (sync or async) closes exactly once via the
-- release pairing. Success keeps the backend in the new context.
finishCryptoOpen
  :: CryptoAcquisition -> Env -> BackendEnv OpenSSL4 -> Model -> SessionId
  -> IO (StablePtr CryptoCtx)
finishCryptoOpen ca env be m0 sid =
  (do
    case planCall (envRules env) m0 cryptoOpenReq of
      Immediate pc -> do
        pr <- publishCommit env be pc
        case pr of
          Left _ -> throwIO AcquireFailed
          Right () -> newStablePtr (CryptoCtx env be sid)
      _ -> throwIO AcquireFailed
  ) `onException` caCloseBackend ca be
    `catch` (\AcquireFailed -> pure nullStable)

-- | The single proof-session open request.
cryptoOpenReq :: Request
cryptoOpenReq = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []

-- | Close a context: shut the backend and free the pointer. Null is
-- a silent no-op.
haskokiCryptoClose :: StablePtr CryptoCtx -> IO ()
haskokiCryptoClose ctx = guardedUnit $
  if castStablePtrToPtr ctx == nullPtr
    then pure ()
    else do
      c <- deRefStablePtr ctx
      B.closeBackend (ccBackend c)
      freeStablePtr ctx

-- | Publish a prepared commit, then drain its releases through the
-- backend (every commit-application site routes here, so
-- releases are impossible to forget). A faulted publish
-- still drains (drain-then-report) — releases free engine
-- resources that exist independent of the model commit.
publishCommit :: Env -> BackendEnv OpenSSL4 -> PreparedCommit -> IO (Either ModelFault ())
publishCommit env be pc = do
  pr <- publish env (pcDelta pc)
  case pr of
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
checkSession :: CryptoCtx -> CULong -> Maybe SessionId
checkSession c (CULong h)
  | h == fromIntegral (unSessionId (ccSession c)) = Just (ccSession c)
  | otherwise = Nothing

-- | Routed @C_DigestInit@: decode the mechanism parameters, plan the
-- init against a model snapshot, and publish.
haskokiCryptoDigestInit
  :: StablePtr CryptoCtx -> CULong -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiCryptoDigestInit ctx hSession (CULong mech) pParams (CULong paramsLen) =
  withCtx ctx $ \c -> case checkSession c hSession of
    Nothing -> pure (rvOf CKR_SESSION_HANDLE_INVALID)
    Just sid -> do
      eParams <- decodeInputBytes pParams paramsLen
      case eParams of
        Left _ -> pure (rvOf CKR_ARGUMENTS_BAD)
        Right params -> do
          m <- snapshotModel (ccEnv c)
          let req = Request Pkcs11_3_2 F_DigestInit (Just sid) Nothing
                (encodeInitInput (MechanismId (fromIntegral mech)) [] False params) []
          case planCall (envRules (ccEnv c)) m req of
            Immediate pc -> do
              pr <- publishCommit (ccEnv c) (ccBackend c) pc
              pure $ case pr of
                Left _ -> toRV ckrGeneralError
                Right () -> rvOf (pcCode pc)
            Reject rej -> do
              publishRejection (ccEnv c) (ccBackend c) rej
              pure (rvOf (rejCode rej))
            Execute res (EffectCrypto fx) -> do
              crypto <- runEffect (ccBackend c) (const Nothing) fx
              m2 <- snapshotModel (ccEnv c)
              case finishEffect (envRules (ccEnv c)) m2 res (encodeResult crypto) of
                Left rej -> do
                  publishRejection (ccEnv c) (ccBackend c) rej
                  pure (rvOf (rejCode rej))
                Right pc -> do
                  pr <- publishCommit (ccEnv c) (ccBackend c) pc
                  pure $ case pr of
                    Left _ -> toRV ckrGeneralError
                    Right () -> rvOf (pcCode pc)

-- | Routed @C_Digest@: decode, plan, execute through the production
-- driver and the live backend, finish, publish, and encode. A NULL
-- output buffer is a size query; a short buffer reports its length
-- and the call recalls through the staged retry.
haskokiCryptoDigest
  :: StablePtr CryptoCtx -> CULong -> Ptr Word8 -> CULong
  -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiCryptoDigest ctx hSession pData (CULong dataLen) pDigest pDigestLen =
  withCtx ctx $ \c -> case checkSession c hSession of
    Nothing -> pure (rvOf CKR_SESSION_HANDLE_INVALID)
    Just sid
      | pDigestLen == nullPtr -> pure (rvOf CKR_ARGUMENTS_BAD)
      | otherwise -> do
          eInput <- decodeInputBytes pData dataLen
          case eInput of
            Left _ -> pure (rvOf CKR_ARGUMENTS_BAD)
            Right input
              | pDigest == nullPtr -> runQuery c sid input pDigestLen
              | otherwise -> do
                  CULong cap <- peek pDigestLen
                  runBuffered c sid input pDigest pDigestLen cap

-- | The buffered one-shot dialogue: plan against a snapshot;
-- rejects publish their termination; pure steps (staged recalls)
-- publish and encode; effects run through the driver and finish.
runBuffered
  :: CryptoCtx -> SessionId -> BS.ByteString
  -> Ptr Word8 -> Ptr CULong -> Word64 -> IO CULong
runBuffered c sid input pDigest pDigestLen cap = do
  m <- snapshotModel (ccEnv c)
  let intent = decodeIntent pDigest cap
      req = Request Pkcs11_3_2 F_Digest (Just sid) Nothing input
        [RegionBytes "digest" intent]
  case planCall (envRules (ccEnv c)) m req of
    Reject rej -> do
      publishRejection (ccEnv c) (ccBackend c) rej
      case rejCode rej of
        CKR_BUFFER_TOO_SMALL -> reportShortLength c sid pDigestLen
        _ -> pure (rvOf (rejCode rej))
    Immediate pc -> do
      pr <- publishCommit (ccEnv c) (ccBackend c) pc
      case pr of
        Left _ -> pure (toRV ckrGeneralError)
        Right () -> encodeCommit pDigest pDigestLen cap sid (ccEnv c) pc
    Execute res eff -> case eff of
      EffectCrypto fx -> do
        crypto <- runEffect (ccBackend c) (const Nothing) fx
        m2 <- snapshotModel (ccEnv c)
        case finishEffect (envRules (ccEnv c)) m2 res (encodeResult crypto) of
          Left rej -> do
            publishRejection (ccEnv c) (ccBackend c) rej
            case rejCode rej of
              CKR_BUFFER_TOO_SMALL -> reportShortLength c sid pDigestLen
              _ -> pure (rvOf (rejCode rej))
          Right pc -> do
            pr <- publishCommit (ccEnv c) (ccBackend c) pc
            case pr of
              Left _ -> pure (toRV ckrGeneralError)
              Right () -> encodeCommit pDigest pDigestLen cap sid (ccEnv c) pc

-- | Encode a digest commit: exact bytes land in the caller buffer
-- with their length; a short buffer reports the staged length from
-- live model state (the slot stays for the recall).
encodeCommit
  :: Ptr Word8 -> Ptr CULong -> Word64 -> SessionId -> Env
  -> PreparedCommit -> IO CULong
encodeCommit pDigest pDigestLen cap sid env pc
  | pcCode pc == CKR_BUFFER_TOO_SMALL = case pcOutputs pc of
      [] -> do
        m <- snapshotModel env
        case stagedDigestLen m sid of
          Nothing -> pure (toRV ckrGeneralError)
          Just n -> do
            _ <- encodeLength pDigestLen n
            pure (toRV ckrBufferTooSmall)
      _ -> pure (toRV ckrGeneralError)
  | pcCode pc /= CKR_OK = pure (rvOf (pcCode pc))
  | otherwise = case traverse nativeToWrite (pcOutputs pc) of
      Nothing -> pure (toRV ckrGeneralError)
      Just [] -> pure (toRV ckrGeneralError)
      Just writes -> do
        let bufs = [BoundBuffer (twPath w) pDigest cap | w <- writes]
        reps <- encodeWrites bufs writes
        if all ((== CKR_OK) . erCode) reps
          then do
            _ <- encodeLength pDigestLen (sum (map erWritten reps))
            pure (toRV ckrOK)
          else pure (toRV ckrGeneralError)

-- | The staged digest length from live model state, if the slot
-- holds staged output.
stagedDigestLen :: Model -> SessionId -> Maybe Word64
stagedDigestLen m sid = do
  st <- lookupSession m sid
  active <- lookupSingle (ssOps st) SlotDigest
  sc <- activeDigest active
  staged <- stagedOf sc
  pure (fromIntegral (BS.length (stBytes staged)))

-- | The size-query dialogue: run the one-shot against a zero
-- capacity so the finisher stages, then report the staged length
-- with the slot kept for the recall.
runQuery :: CryptoCtx -> SessionId -> BS.ByteString -> Ptr CULong -> IO CULong
runQuery c sid input pLen = do
  m <- snapshotModel (ccEnv c)
  let req = Request Pkcs11_3_2 F_Digest (Just sid) Nothing input
        [RegionBytes "digest" (IntentBuffer 0)]
  case planCall (envRules (ccEnv c)) m req of
    Reject rej -> do
      publishRejection (ccEnv c) (ccBackend c) rej
      case rejCode rej of
        CKR_BUFFER_TOO_SMALL -> reportQuery c sid pLen
        _ -> pure (rvOf (rejCode rej))
    Immediate pc -> do
      pr <- publishCommit (ccEnv c) (ccBackend c) pc
      case pr of
        Left _ -> pure (toRV ckrGeneralError)
        Right () -> reportQuery c sid pLen
    Execute res eff -> case eff of
      EffectCrypto fx -> do
        crypto <- runEffect (ccBackend c) (const Nothing) fx
        m2 <- snapshotModel (ccEnv c)
        case finishEffect (envRules (ccEnv c)) m2 res (encodeResult crypto) of
          Left rej -> do
            publishRejection (ccEnv c) (ccBackend c) rej
            case rejCode rej of
              CKR_BUFFER_TOO_SMALL -> reportQuery c sid pLen
              _ -> pure (rvOf (rejCode rej))
          Right pc
            | pcCode pc == CKR_BUFFER_TOO_SMALL -> do
                pr <- publishCommit (ccEnv c) (ccBackend c) pc
                case pr of
                  Left _ -> pure (toRV ckrGeneralError)
                  Right () -> reportQuery c sid pLen
            | otherwise -> do
                _ <- publishCommit (ccEnv c) (ccBackend c) pc
                pure (rvOf (pcCode pc))

-- | Report a query's staged length, keeping the slot for the
-- recall (a successful query does not terminate the one-shot).
reportQuery :: CryptoCtx -> SessionId -> Ptr CULong -> IO CULong
reportQuery c sid pLen = do
  m <- snapshotModel (ccEnv c)
  case lookupSession m sid of
    Nothing -> pure (toRV ckrGeneralError)
    Just _ -> case stagedDigestLen m sid of
      Nothing -> pure (toRV ckrGeneralError)
      Just n -> do
        _ <- encodeLength pLen n
        pure (toRV ckrOK)

-- | Report a plan-level short buffer: re-read the staged digest
-- length (a short retry keeps the slot). No staging: fail closed.
reportShortLength :: CryptoCtx -> SessionId -> Ptr CULong -> IO CULong
reportShortLength c sid pLen = do
  m <- snapshotModel (ccEnv c)
  case stagedDigestLen m sid of
    Nothing -> pure (toRV ckrGeneralError)
    Just n -> do
      _ <- encodeLength pLen n
      pure (toRV ckrBufferTooSmall)
