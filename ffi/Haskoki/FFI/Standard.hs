{- | Native boundary: the standard-surface instance behind the
routed PKCS#11 function tables.

The C side (@cbits\/standard_surface.c@) holds one @StablePtr
StdInstance@ per init interval: opened from @C_Initialize@ (fresh
'Env', provider init, token seating, live OpenSSL4 backend, empty
find cursors, optional SQLite store), closed from @C_Finalize@
(backend and store close, handle freed). No top-level mutable
Haskell state: the instance handle crosses as an explicit pointer
(the control-entry precedent), and every export re-validates it.

Engine policy (documented, no silent substitution):

* The crypto backend is always OpenSSL4 (established precedent:
  @HASKOKI_CONFIG@ @engine.kind@ is not consulted by the C
  surface). The advertised mechanism catalog is therefore exactly
  the @support.real == \"tested\"@ projection of
  @spec\/mechanisms.json@ (see @cbits\/mech_catalog.inc@).
* Tokens are provisioned at open from the @[tokens]@ catalog
  (slot = catalog index; 'effectiveCatalog'): every catalog slot
  is seated through the 'seatToken' admission, slot 0 is always
  the 'homeTokenLabel' token (an absent section serves exactly
  it, with the 'provisionedUserPin'\/'provisionedSoPin' PINs),
  and each catalog entry carries its own label plus user\/SO
  PINs (example-grade fixture material). There is no InitToken
  path (that entry stays honestly @NOT_SUPPORTED@);
  provisioning is documented in @docs\/demo-walkthrough.md@.
* Template arguments cross as template frames (see
  'parseTemplateFrame'): @count:u64le@ then @count@ records of
  @type:u64le, len:u64le, value:len bytes@. The C side packs them
  from caller @CK_ATTRIBUTE@ arrays
  (@cbits\/standard_surface.c@ @haskoki_std_pack_template@); all
  integers are native-order u64. Attribute-type ids resolve
  through the generated inventory ('Haskoki.Attribute.Generated')
  by numeric id -- no hand-typed @CKA_*@ numerics anywhere.
* Scalar projections ('sessionScalars', 'tokenScalars') return
  plain words; every @CK_STATE@\/@CKF_*@ spelling lives in C,
  resolved from the pinned headers.
* Persistence: @storage.kind=sqlite@ (with its required explicit
  path) opens the process store at open, reloads token state, and
  commits token-affecting publishes; @memory@ stays transient.
  The store is single-writer (a second concurrent open fails the
  @C_Initialize@ loudly -- never a silent fork of token state).

Blocking behavior: none of these exports block; the C state lock
serializes table calls. No Haskell-side threads are ever spawned
here.
-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoki.FFI.Standard
  ( -- * Instance
    StdStore (..)
  , StdInstance (..)
  , StdAsyncBinding (..)
  , StdStoreError (..)
  , StdAcquisition (..)
  , stdAcquisition
  , haskokiStdOpen
  , openStdInstance
  , openStdInstanceWith
  , openStdInstanceWithSlots
  , haskokiStdClose
  , withStdCtx
  , stdRvOf
    -- * Provisioning constants
  , homeTokenId
  , homeTokenLabel
  , provisionedUserPin
  , provisionedSoPin
  , tokenIdForSlot
    -- * Template frames (pure; tested by StandardSurfaceSpec)
  , FrameError (..)
  , maxTemplateAttrs
  , parseTemplateFrame
  , decodeNativeValue
    -- * Wire mappings (pure)
  , ecParamsFromWire
  , ecParamsToWire
    -- * Scalar projections (pure)
  , sessionScalars
  , tokenScalars
    -- * PIN comparison (pure)
  , pinsMatch
    -- * Async binding lookup (pure)
  , lookupStdAsyncBinding
  , haskokiStdAsyncComplete
  , haskokiStdAsyncGetId
  , haskokiStdAsyncJoin
  , haskokiStdTerminateSlot
    -- * slot list, sessions, session info, token liveness
  , haskokiStdGetSlotList
  , haskokiStdOpenSession
  , haskokiStdOpenSessionWithAsync
  , haskokiStdCloseSession
  , haskokiStdCloseAllSessions
  , haskokiStdSessionCancel
  , haskokiStdGetSessionInfo
  , haskokiStdGetSessionInfoWithAsync
  , haskokiStdTokenLive
  , haskokiStdTokenLabel
  , haskokiStdSlotPresent
    -- * objects (pure helpers + exports)
  , nativeEncodeAttr
  , nativeFromCanonical
  , frameErrorRV
  , beWord64
  , haskokiStdCreateObject
  , haskokiStdCopyObject
  , haskokiStdSetAttributeValue
  , haskokiStdDestroyObject
  , haskokiStdGetOneAttr
  , haskokiStdFindInit
  , haskokiStdFind
  , haskokiStdFindFinal
    -- * login/logout
  , haskokiStdLogin
  , haskokiStdLogout
    -- * crypto pipeline (shared) + digest
  , runCryptoPlan
  , runCryptoSilent
  , runCryptoSilentDecoded
  , runCryptoBuffered
  , runCryptoQuery
  , haskokiStdDigestInit
  , haskokiStdDigest
  , haskokiStdDigestUpdate
  , haskokiStdDigestKey
  , haskokiStdDigestFinal
    -- * key generation
  , runKeyPlan
  , haskokiStdGenerateKey
  , haskokiStdGenerateKeyPair
    -- * sign/verify
  , haskokiStdSignInit
  , haskokiStdSign
  , haskokiStdSignUpdate
  , haskokiStdSignFinal
  , haskokiStdVerifyInit
  , haskokiStdVerify
  , haskokiStdVerifyUpdate
  , haskokiStdVerifyFinal
    -- * message operations
  , haskokiStdMessageEncryptInit
  , haskokiStdMessageEncrypt
  , haskokiStdMessageEncryptBegin
  , haskokiStdMessageEncryptNext
  , haskokiStdMessageEncryptFinal
  , haskokiStdMessageDecryptInit
  , haskokiStdMessageDecrypt
  , haskokiStdMessageDecryptBegin
  , haskokiStdMessageDecryptNext
  , haskokiStdMessageDecryptFinal
  , haskokiStdMessageSignInit
  , haskokiStdMessageSign
  , haskokiStdMessageSignBegin
  , haskokiStdMessageSignNext
  , haskokiStdMessageSignFinal
  , haskokiStdMessageVerifyInit
  , haskokiStdMessageVerify
  , haskokiStdMessageVerifyBegin
  , haskokiStdMessageVerifyNext
  , haskokiStdMessageVerifyFinal
    -- * encrypt/decrypt
  , runCryptoUpdateBuffered
  , runCryptoUpdateQuery
  , haskokiStdEncryptInit
  , haskokiStdEncrypt
  , haskokiStdEncryptUpdate
  , haskokiStdEncryptFinal
  , haskokiStdDecryptInit
  , haskokiStdDecrypt
  , haskokiStdDecryptUpdate
  , haskokiStdDecryptFinal
    -- * random
  , haskokiStdGenerateRandom
    -- * wrap/unwrap/derive
  , runWrapPlan
  , haskokiStdWrapKey
  , haskokiStdUnwrapKey
  , haskokiStdDeriveHkdf
  , haskokiStdDeriveOpaque
  ) where

import Control.Exception
  ( AsyncException
  , Exception (fromException)
  , SomeException
  , catch
  , evaluate
  , finally
  , mask
  , mask_
  , onException
  , throwIO
  , try
  )
import Control.Monad (forM_, when, zipWithM_)
import Data.Bits (shiftL, shiftR, xor, (.&.), (.|.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Data.Char (ord)
import qualified Data.ByteString.Unsafe as BSU
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef, writeIORef)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Set as Set
import Data.Word (Word64, Word8)
import Foreign.C.Types (CULong (..))
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.StablePtr
  ( StablePtr
  , castPtrToStablePtr
  , castStablePtrToPtr
  , deRefStablePtr
  , freeStablePtr
  , newStablePtr
  )
import Foreign.Marshal.Array (pokeArray)
import Foreign.Marshal.Alloc (alloca, allocaBytesAligned)
import Foreign.Marshal.Utils (copyBytes, fillBytes)
import Foreign.Storable (alignment, sizeOf, peek, poke, peekByteOff, pokeByteOff)

import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , attributeTypeByName
  , maxAttributeBytes
  , shapeMatches
  )
import Haskoki.Attribute.Generated (attributeNameById)
import Haskoki.Der (curveTable, edwardsTable, montgomeryTable)
import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CryptoBackend (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , generateRandomMaxBytes
  , seedRandomMaxBytes
  )
import Haskoki.Engine.Driver (KeyResolver, drainReleases, encodeResult, runEffect)
import Haskoki.Engine.OpenSSL4 (OpenSSL4)
import Haskoki.FFI.Async
  ( AsyncCtx (..)
  , AsyncData
  , JobHandle
  , decodeAsyncFunctionName
  , haskokiAsyncCancel
  , haskokiAsyncComplete
  , haskokiAsyncGetId
  , haskokiAsyncJoin
  , haskokiAsyncPoll
  , haskokiAsyncStart
  , jobFunctionCode
  )
import Haskoki.FFI.Decode (decodeInputBytes)
import Haskoki.FFI.Encode
  ( BoundBuffer (..)
  , EncodeReport (..)
  , encodeLength
  , encodeWrites
  , nativeToWrite
  )
import Haskoki.FFI.Exports (returnCodeToRV)
import Haskoki.FFI.Instance (Instance (..), InstanceCell, readLiveInstance)
import Haskoki.Runtime.Catalog (effectiveCatalog, homeCatalogEntry)
import Haskoki.Runtime.Control (PresenceOwner (..), bindPresenceOwner)
import Haskoki.Runtime.SlotEvents
  ( SlotEvents, SlotDefinition (..), PresenceError (..), newSlotEvents
  , snapshotSlots, closeSlotEvents
  )
import Haskoki.FFI.MessageParams
  ( decodeMessageInitFrame
  , decodeMessageBeginFrame
  , decodeMessageCipherFrame
  , decodeMessageSignFrame
  , decodeMessageVerifyFrame
  , decodeMessageCipherNextFrame
  , decodeMessageSignNextFrame
  , decodeMessageVerifyNextFrame
  )
import Haskoki.FFI.NativeParams (DerivedKeySlot (..), KeyMatSlots (..), normalizeByteOpsConcatKeyParams, normalizeByteOpsExtractParams, normalizeByteOpsStringDataParams, normalizeDhPkcsParams, normalizeDhX942Params, normalizeEcdhParams, normalizeEncryptDataCbcParams, normalizeEncryptDataEcbParams, normalizeIke1ExtParams, normalizeIke1PrfParams, normalizeIkePrfParams, normalizeIkePrfPlusParams, normalizeMechParams, normalizePbkd2Params2, normalizeSp800KdfParams, normalizeTlsKdfExtParams, normalizeTlsKdfFreeParams, normalizeTlsKdfMasterParams, normalizeTlsKdfTls12MasterParams, normalizeTlsKeyMatParams, normalizeTls12KeyMatParams, normalizeTls12KeySafeParams, normalizeSsl3MasterParams, normalizeSsl3KeyMatParams, normalizeTlsPrfParams, normalizePbeParamsMaybeIv)
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState (..)
  , lookupSession
  , lookupTokenAuth
  , sessionsOnSlot
  )
import Haskoki.Object (maxTemplateEntries, objectVisible, resolveHandle)
import Haskoki.Operation
  ( CryptoEffect (..)
  , MsgFamily (..)
  , MsgState (..)
  , SlotKind (..)
  , StagedOutput (..)
  , activeCipher
  , bufferedOf
  , commonMech
  , commonOf
  , lookupSingle
  , msgFamilyKind
  , removeSingle
  , stagedOf
  )
import Haskoki.Operation.Cipher (cipherUpdateSplit)
import Haskoki.Operation.Codec (decodeMsgNext, encodeCancelInput, encodeVerifyInput)
import Haskoki.Operation.Message (MsgNext (..), lookupMessage)
import Haskoki.Operation.Derive
  ( encodeDeriveParams
  , encodeHkdfInfo
  , hkdfDataMech
  , hkdfDeriveMech
  , planDerive
  )
import Haskoki.Recipe.Dh (DhRecipe (..), dhRecipeFor)
import Haskoki.Recipe.Digest (DigestRecipe (drOutLen), digestRecipeFor)
import Haskoki.Recipe.Ecdh (ecdhRecipeFor)
import Haskoki.Recipe.EncryptData (EncryptDataRecipe (..), encryptDataRecipeFor)
import Haskoki.Recipe.Kdf (KdfRecipe (..), kdfRecipeFor)
import Haskoki.Recipe.Sp800108 (Sp800Recipe (..), sp800RecipeFor)
import Haskoki.Recipe.TlsKdf (TlsKdfKind (..), TlsKdfRecipe (..), tlsKdfRecipeFor)
import Haskoki.Recipe.ByteOps (ByteOpsKind (..), ByteOpsRecipe (..), byteOpsRecipeFor)
import Haskoki.Recipe.Ssl3 (Ssl3Kind (..), Ssl3Recipe (ssl3Kind), ssl3RecipeFor)
import Haskoki.Recipe.TlsKeyMat (TlsKeyMatKind (..), TlsKeyMatRecipe (tkmKind), tlsKeyMatRecipeFor)
import Haskoki.Recipe.Pbe (PbeKind, PbeRecipe (pbeKind), pbeIvLen, pbeRecipeFor)
import Haskoki.Recipe.Ike (IkeKind (..), IkeRecipe (..), ikeRecipeFor)
import Haskoki.Recipe.TlsPrf (tlsPrfRecipeFor)
import Haskoki.Recipe.PubPriv (pubPrivRecipeFor)
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , admitPending
  , ckoSecretKey
  , finishWork
  , keyBytesOf
  , keyPairCompatible
  , planGenerateKey
  , planGenerateKeyPair
  , planUnwrapKey
  , planWrapKey
  )
import Haskoki.Operation.Kem
  ( kemAlgOfKey
  , planKemDecaps
  , planKemEncaps
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , EffectRequest (..)
  , ModelFault (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Output (TypedWrite (..), maxOutputBytes)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request
  ( DecodedRequest (..)
  , FunctionId (..)
  , InitFunction (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  , initOperation
  )
import Haskoki.Rules (Rules (..))
import Haskoki.Runtime.Async
  ( AsyncTable
  , JobFunction (..)
  , enableAsyncSession
  , isAsyncSession
  , newAsyncTable
  )
import Haskoki.Runtime.Detached (DetachCtx, detachSlot, openDetached, retireLiveTable)
import Haskoki.Runtime.Config
  ( Config (..)
  , StorageCfg (..)
  , StorageKind (..)
  , ControlCfg (..)
  , Limits (..)
  )
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
  , StoreError
  , TokenRecord (..)
  , emptyDelta
  )
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Session
  ( AdmitDeny
  , SessionLogin (..)
  , TokenAuth (..)
  , tokenAuthNew
  )
import Haskoki.Transition (finishEffect, planCall, planDecoded)
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

-- ---------------------------------------------------------------------------
-- Provisioning constants
-- ---------------------------------------------------------------------------

-- | Home token id in the process store (the detached-path
-- convention; store files are single-provider).
homeTokenId :: TokenId
homeTokenId = TokenId 1

-- | Provisioned token label. The model carries no label (token
-- metadata lives outside 'TokenAuth'), so the C token-info record
-- and fresh-store token rows both use exactly this string.
homeTokenLabel :: String
homeTokenLabel = let (label, _, _) = homeCatalogEntry in label

-- | Provisioned user PIN. Fixed at open; there is no PIN-change
-- path on the C surface (InitPIN\/SetPIN stay honestly
-- unsupported), so every process provisioning this token agrees.
provisionedUserPin :: ByteString
provisionedUserPin = let (_, _, pin) = homeCatalogEntry in BC8.pack pin

-- | Provisioned security-officer PIN. Same fixity as the user PIN.
provisionedSoPin :: ByteString
provisionedSoPin = let (_, pin, _) = homeCatalogEntry in BC8.pack pin

-- | The stable store identity for a catalog slot: slot @i@ owns
-- @TokenId (i+1)@, so slot 0 keeps 'homeTokenId' and every slot is
-- unique by construction.
tokenIdForSlot :: SlotId -> TokenId
tokenIdForSlot (SlotId n) = TokenId (n + 1)

-- | Look up a slot's catalog entry (label, SO PIN, user PIN),
-- falling back to the home entry for instances without catalog
-- data (manually seated test instances).
catalogLookup :: StdInstance -> SlotId -> (String, String, String)
catalogLookup inst slot = Map.findWithDefault homeCatalogEntry slot (siCatalog inst)

-- ---------------------------------------------------------------------------
-- Instance
-- ---------------------------------------------------------------------------

-- | The open process store behind a SQLite-backed instance.
data StdStore = StdStore
  { stdStore :: !Store
  , stdToken :: !TokenId
  }

-- | The owned standard-surface instance: model environment, live
-- OpenSSL4 backend, per-session find cursors, the optional process
-- store, and the effective serving catalog (per-slot labels/PINs).
data StdInstance = StdInstance
  { siEnv :: !Env
  , siBackend :: !(BackendEnv OpenSSL4)
  , siFind :: !(IORef (Map SessionId [ExternalHandle]))
  , siStore :: !(Maybe StdStore)
  , siCatalog :: !(Map SlotId (String, String, String))
  , siSlots :: !SlotEvents
  , siUnbindPresenceOwner :: !(IO ())
  , siReleaseResources :: !(IO ())
  , siAsyncTable :: !AsyncTable
  , siDetach :: !(Maybe DetachCtx)
  , siAsyncViews :: !(IORef (Map SessionId (StablePtr AsyncCtx)))
  , siAsyncBindings :: !(IORef (Map (SessionId, JobFunction) StdAsyncBinding))
  }

-- | One caller-owned output allocation. Input bytes are copied by the worker;
-- neither its input pointer nor the caller's length-word address is retained.
data StdAsyncBinding = StdAsyncBinding
  { sabFunction :: !JobFunction
  , sabHandle :: !(StablePtr JobHandle)
  , sabOutput :: !(Ptr Word8)
  , sabCapacity :: !Word64
  }

foreign export ccall "haskoki_std_open" haskokiStdOpen
  :: StablePtr InstanceCell -> IO (StablePtr StdInstance)
foreign export ccall "haskoki_std_close" haskokiStdClose
  :: StablePtr StdInstance -> IO ()

-- | The null instance: open failures report NULL, never dangling.
nullStable :: StablePtr StdInstance
nullStable = castPtrToStablePtr nullPtr

-- | Exception boundary for instance-returning exports: failure is NULL.
guardedPtr :: IO (StablePtr StdInstance) -> IO (StablePtr StdInstance)
guardedPtr body = do
  r <- try body
  case r of
    Right p -> pure p
    Left (_ :: SomeException) -> pure nullStable

-- | Sync-failure boundary for the inner opens: an unexpected SYNC
-- exception becomes NULL (explicit sync failures already return
-- NULL directly); ASYNC exceptions propagate after the bracket
-- unwind, so a kill aborts the open instead of being swallowed
-- The @foreign export@ boundary ('haskokiStdOpen') keeps
-- its catch-all: no Haskell exception crosses into C.
guardedSyncPtr :: IO (StablePtr StdInstance) -> IO (StablePtr StdInstance)
guardedSyncPtr body = catch body $ \e ->
  case (fromException e :: Maybe AsyncException) of
    Just ae -> throwIO ae
    Nothing -> pure nullStable

-- | Exception boundary for unit exports: failure is silent (close
-- has no error channel left).
guardedUnit :: IO () -> IO ()
guardedUnit body = do
  r <- try body
  case r of
    Right () -> pure ()
    Left (_ :: SomeException) -> pure ()

-- | Mandatory top-level exception boundary for CK_RV exports: no
-- Haskell exception may cross into C. Ordinary failure surfaces as
-- 'CKR_GENERAL_ERROR'.
guardedRV :: IO CULong -> IO CULong
guardedRV body = do
  r <- try body
  case r of
    Right rv -> pure rv
    Left (_ :: SomeException) -> pure (CULong 5)

-- | Core return code to @CK_RV@.
stdRvOf :: ReturnCode -> CULong
stdRvOf = CULong . fromIntegral . returnCodeToRV

-- | Run against a live instance or report @CKR_GENERAL_ERROR@ on a
-- null or dead one. No Haskell exception crosses into C.
withStdCtx :: StablePtr StdInstance -> (StdInstance -> IO CULong) -> IO CULong
withStdCtx ctx k = guardedRV $ do
  if castStablePtrToPtr ctx == nullPtr
    then pure (CULong 5)
    else deRefStablePtr ctx >>= k

-- | Production acquisition borrows the already resolved config and hub from
-- the unpublished cell. The hooks capture the Haskell owner, never a StablePtr.
haskokiStdOpen :: StablePtr InstanceCell -> IO (StablePtr StdInstance)
haskokiStdOpen cell = guardedPtr $ do
  live <- readLiveInstance cell
  case live of
    Nothing -> pure nullStable
    Just ops -> openStdInstanceWithSlots
      stdAcquisition
        { saBindPresenceOwner = \inst -> bindPresenceOwner (instControl ops)
            (Just (PresenceOwner (snapshotSlots (siSlots inst))
              -- T-N03 supplies Standard's atomic retirement coordinator.
              (\_ _ -> pure (Left PresenceFixedSlot))))
        , saUnbindPresenceOwner = bindPresenceOwner (instControl ops) Nothing
        }
      (instConfig ops) (instSlots ops)

-- | Injectable acquisition steps for the standard-surface open
-- The production open threads 'stdAcquisition'; probes
-- override steps to fail or count. Every failure arm releases what
-- was acquired through the bracket pairing in 'openStdInstanceWith'
-- (structural: a future step adds its release at its own acquire
-- site instead of relying on far-apart hand pairing).
data StdAcquisition = StdAcquisition
  { saInit :: !(Env -> IO (Outcome ()))
  , saOpenStore :: !(Env -> Config -> IO (Either StdStoreError (Maybe StdStore)))
  , saCloseStore :: !(Maybe StdStore -> IO ())
  , saOpenBackend :: !(IO (EngineResult (BackendEnv OpenSSL4)))
  , saCloseBackend :: !(BackendEnv OpenSSL4 -> IO ())
  , saAssemble :: !(StdInstance -> IO (StablePtr StdInstance))
  , saBindPresenceOwner :: !(StdInstance -> IO ())
  , saUnbindPresenceOwner :: !(IO ())
  }

-- | Production acquisition steps.
stdAcquisition :: StdAcquisition
stdAcquisition = StdAcquisition
  { saInit = \env -> initialize env defaultInitArgs
  , saOpenStore = openStdStore
  , saCloseStore = closeStdStore
  , saOpenBackend = openBackend "provider=default"
  , saCloseBackend = closeBackend
  , saAssemble = newStablePtr
  , saBindPresenceOwner = const (pure ())
  , saUnbindPresenceOwner = pure ()
  }

-- | Open an owned instance from a RESOLVED config: fresh 'Env',
-- provider initialization, catalog provisioning (seat-all, or
-- store reload plus seat-and-commit of missing catalog slots), a
-- live OpenSSL4 backend, and empty find cursors. Any sync failure
-- closes what it opened and reports NULL (the C layer then fails
-- @C_Initialize@ loudly). Exported for catalog-driven
-- test opens.
openStdInstance :: Config -> IO (StablePtr StdInstance)
openStdInstance = openStdInstanceWith stdAcquisition

-- | 'openStdInstance' over injected acquisition steps. The skeleton
-- runs masked with each step restored; every acquired resource
-- carries its release on exactly the region where it is held but
-- unowned (sequential brackets, never nested-double): a throwing
-- backend acquire releases the store, an explicit backend refusal
-- closes the store under mask, and a throwing finish releases
-- backend plus store. Sync failures report NULL; async exceptions
-- unwind through the releases and propagate (the @foreign export@
-- boundary above still maps them to NULL for C).
openStdInstanceWith
  :: StdAcquisition -> Config -> IO (StablePtr StdInstance)
openStdInstanceWith sa cfg = guardedSyncPtr $ mask_ $ do
  let catalog = effectiveCatalog cfg
  when (Map.size catalog > limSlots (cfgLimits cfg)) $
    ioError (userError "serving catalog exceeds limits.slots")
  slots <- newSlotEvents (limEvents (cfgLimits cfg))
    [SlotDefinition slot (ccTestEnabled (cfgControl cfg)) | slot <- Map.keys catalog]
    >>= either (ioError . userError . show) pure
  openStdInstanceWithSlots sa cfg slots

-- | Acquire over an explicit service. Failed acquisition closes that service;
-- successful ownership carries the matching injected releases through close.
-- Each acquired resource has exactly one unwind region, including bind failure.
openStdInstanceWithSlots
  :: StdAcquisition -> Config -> SlotEvents -> IO (StablePtr StdInstance)
openStdInstanceWithSlots sa cfg slots = guardedSyncPtr $ mask $ \restore -> do
  let acquire = do
        env <- newEnv (rulesFromConfig cfg)
        ini <- restore (saInit sa env)
        case ini of
          OutcomeErr _ -> pure nullStable
          OutcomeOk () -> do
            eStore <- restore (saOpenStore sa env cfg)
            case eStore of
              Left _ -> pure nullStable
              Right mStore -> do
                r <- restore (saOpenBackend sa)
                  `onException` saCloseStore sa mStore
                case r of
                  EngineFail _ -> saCloseStore sa mStore >> pure nullStable
                  EngineOk be -> do
                    let release = saCloseBackend sa be `finally` saCloseStore sa mStore
                    (do
                      inst <- assembleStdInstance env be mStore cfg slots
                        (saUnbindPresenceOwner sa) release
                      ptr <- saAssemble sa inst
                      if castStablePtrToPtr ptr == nullPtr
                        then ioError (userError "standard assembly refused")
                        else do
                          saBindPresenceOwner sa inst `onException` freeStablePtr ptr
                          pure ptr)
                      `onException` (saUnbindPresenceOwner sa `finally` release)
  ptr <- acquire `onException` closeSlotEvents slots
  when (castStablePtrToPtr ptr == nullPtr) (closeSlotEvents slots)
  pure ptr

-- | Assemble under the acquisition mask. The detached context borrows the
-- existing store; its refusal unwinds in the caller's resource bracket.
assembleStdInstance
  :: Env -> BackendEnv OpenSSL4 -> Maybe StdStore -> Config -> SlotEvents
  -> IO () -> IO () -> IO StdInstance
assembleStdInstance env be mStore cfg slots unbind release = do
  cursors <- newIORef mempty
  table <- newAsyncTable 8
  detach <- case mStore of
    Nothing -> pure Nothing
    Just ss -> do
      opened <- openDetached (stdStore ss) (stdToken ss)
      case opened of
        Left deny -> ioError (userError ("standard detached context: " ++ show deny))
        Right dc -> pure (Just dc)
  views <- newIORef Map.empty
  bindings <- newIORef Map.empty
  pure (StdInstance env be cursors mStore (effectiveCatalog cfg)
    slots unbind release table detach views bindings)

-- | Seat every catalog slot in index order. The first refusal
-- (past the seating bound) fails the whole open loudly — catalogs
-- are never truncated silently.
seatAll :: Env -> [SlotId] -> IO (Either AdmitDeny ())
seatAll _ [] = pure (Right ())
seatAll env (slot : rest) = do
  eSeat <- seatToken env slot
  case eSeat of
    Left deny -> pure (Left deny)
    Right () -> seatAll env rest

-- | Resolve the process store from the configuration: memory stays
-- transient (seat every catalog slot); SQLite opens the store
-- file, reloads token state, refuses a catalog/store reload
-- mismatch (stored slots beyond the live catalog — see
-- 'StdStoreCatalogMismatch'), and seats plus commits each catalog
-- slot the store does not know yet (per-slot labels and stable
-- per-slot token ids). The config arrives resolved (the open
-- resolves once, up front); an unopenable store or a refused
-- seating fails the whole open loudly.
--
-- The store-open failure is TYPED (settling the untyped edge):
-- every consumer maps failures to NULL uniformly, and the
-- typed cases keep any future dispatch honest instead of matching
-- on message strings.
data StdStoreError
  = StdStoreSeating !AdmitDeny
  | StdStoreNoPath
  | StdStoreSQLite !StoreError
  | StdStoreReload !AdmitDeny
  | StdStoreCommit
  | StdStoreCatalogMismatch
  deriving (Eq, Show)

openStdStore :: Env -> Config -> IO (Either StdStoreError (Maybe StdStore))
openStdStore env cfg = case scKind (cfgStorage cfg) of
      StorageMemory -> do
        eSeat <- seatAll env (Map.keys catalog)
        case eSeat of
          Left deny -> pure (Left (StdStoreSeating deny))
          Right () -> pure (Right Nothing)
      StorageSQLite -> case scPath (cfgStorage cfg) of
        Nothing -> pure (Left StdStoreNoPath)
        Just path -> do
          eStore <- openSQLiteStore path
          case eStore of
            Left err -> pure (Left (StdStoreSQLite err))
            Right store -> do
              eLoaded <- storeLoadTokens store
              case eLoaded of
                Left err -> do
                  storeClose store
                  pure (Left (StdStoreSQLite err))
                Right loaded -> do
                  eRestored <- restoreStoreState env loaded
                  case eRestored of
                    Left deny -> do
                      storeClose store
                      pure (Left (StdStoreReload deny))
                    Right () -> do
                      m <- snapshotModel env
                      -- A shrunk catalog over a
                      -- reused store must never serve the stale
                      -- extra slots with home-fallback labels/PINs.
                      -- REFUSE (not prune: pruning would silently
                      -- drop operator token data; the loud refusal
                      -- forces explicit reconciliation), failing the
                      -- whole open.
                      let stored = Map.keys (mTokenAuth m)
                          extra =
                            [ slot
                            | slot <- stored
                            , Map.notMember slot catalog
                            ]
                      case extra of
                        (_ : _) -> do
                          storeClose store
                          pure (Left StdStoreCatalogMismatch)
                        [] -> do
                          let missing =
                                [ slot
                                | slot <- Map.keys catalog
                                , Map.notMember slot (mTokenAuth m)
                                ]
                          case missing of
                            [] -> pure (Right (Just (StdStore store homeTokenId)))
                            _ -> do
                              eSeat <- seatAll env missing
                              case eSeat of
                                Left deny -> do
                                  storeClose store
                                  pure (Left (StdStoreSeating deny))
                                Right () -> do
                                  res <- storeCommit store emptyDelta
                                    { sdPutTokens =
                                        [ TokenRecord (tokenIdForSlot slot) slot
                                            (Generation 0) label tokenAuthNew
                                        | slot <- missing
                                        , let (label, _, _) = catalogEntry slot
                                        ]
                                    }
                                  case res of
                                    Committed -> pure (Right (Just (StdStore store homeTokenId)))
                                    _ -> do
                                      storeClose store
                                      pure (Left StdStoreCommit)
  where
    catalog = effectiveCatalog cfg
    catalogEntry slot = Map.findWithDefault homeCatalogEntry slot catalog

-- | Close the process store, if any. Always succeeds (the close
-- path has no error channel).
closeStdStore :: Maybe StdStore -> IO ()
closeStdStore Nothing = pure ()
closeStdStore (Just ss) = storeClose (stdStore ss)

-- | Close: shut the backend and the process store, then release
-- the handle. Idempotent on NULL, silent on failure.
haskokiStdClose :: StablePtr StdInstance -> IO ()
haskokiStdClose ctx = guardedUnit $
  if castStablePtrToPtr ctx == nullPtr
    then pure ()
    else mask_ $ do
      inst <- deRefStablePtr ctx
      let closeOwned = siReleaseResources inst `finally` freeStablePtr ctx
      (siUnbindPresenceOwner inst `finally` do
        views <- readIORef (siAsyncViews inst)
        (do
          forM_ (Map.keys views) (cancelStdAsyncJobs inst)
          forM_ (siDetach inst) $ \dc -> do
            _ <- retireLiveTable dc
            pure ()) `finally` forM_ (Map.keys views) (freeStdAsyncView inst))
        `finally` closeOwned

-- | Borrowed views own only their StablePtr and live job handles. Their backend
-- and detached context are owned by Standard, so the proof close is never used.
cancelStdAsyncJobs :: StdInstance -> SessionId -> IO ()
cancelStdAsyncJobs inst sid = mask_ $ do
  views <- readIORef (siAsyncViews inst)
  forM_ (Map.lookup sid views) $ \view -> do
    c <- deRefStablePtr view
    handles <- Set.toList <$> readIORef (acLive c)
    forM_ handles $ \ptr -> do
      _ <- haskokiAsyncCancel view (castPtrToStablePtr ptr)
      pure ()
  atomicModifyIORef' (siAsyncBindings inst) $ \bindings ->
    (Map.filterWithKey (\(owner, _) _ -> owner /= sid) bindings, ())

freeStdAsyncView :: StdInstance -> SessionId -> IO ()
freeStdAsyncView inst sid = mask_ $ do
  view <- atomicModifyIORef' (siAsyncViews inst) $ \views ->
    (Map.delete sid views, Map.lookup sid views)
  forM_ view freeStablePtr

-- ---------------------------------------------------------------------------
-- Template frames (pure)
-- ---------------------------------------------------------------------------

-- | Bound on attributes per frame (alias of the pinned single
-- source of truth 'maxTemplateEntries' in core, which the in-process
-- codec enforces too; ConfigSpec pins the value).
-- Caller templates are small; the C packer enforces the same bound,
-- and this re-check closes the loop for any frame source.
-- @limits.attribute_entries@ does NOT drive this bound (reserved
-- key, disclosed in the capabilities report).
maxTemplateAttrs :: Word64
maxTemplateAttrs = fromIntegral maxTemplateEntries

-- | Template-frame faults: truncation (short header, short record,
-- value overrun, trailing bytes), count past 'maxTemplateAttrs',
-- an unknown attribute-type id, or a value that misses its owning
-- type's shape. Callers map truncation to @CKR_ARGUMENTS_BAD@,
-- unknown types to @CKR_ATTRIBUTE_TYPE_INVALID@, and bad values to
-- @CKR_TEMPLATE_INCONSISTENT@ (a wrongly shaped value contradicts
-- its type).
data FrameError
  = FrameTruncated
  | FrameTooManyAttrs
  | FrameUnknownType !Word64
  | FrameBadValue !AttributeType
  deriving (Eq, Show)

-- | Parse one template frame: @count:u64le@ then @count@ records of
-- @type:u64le, len:u64le, value:len bytes@. Consumption must be
-- exact (trailing bytes fail closed). Type ids resolve through
-- the generated inventory to names and then to the model
-- inventory; values decode in caller-native order (little-endian
-- @CK_ULONG@, one-byte @CK_BBOOL@, raw bytes).
parseTemplateFrame :: ByteString -> Either FrameError [(AttributeType, AttributeValue)]
parseTemplateFrame bs = case takeU64le bs of
  Nothing -> Left FrameTruncated
  Just (n, rest)
    | n > maxTemplateAttrs -> Left FrameTooManyAttrs
    | otherwise -> case takeRecords (fromIntegral n) rest of
        Nothing -> Left FrameTruncated
        Just (entries, trailing)
          | BS.null trailing -> mapM decodeEntry entries
          | otherwise -> Left FrameTruncated
  where
    takeRecords :: Int -> ByteString -> Maybe ([(Word64, ByteString)], ByteString)
    takeRecords 0 rest = Just ([], rest)
    takeRecords k rest = do
      (t, r1) <- takeU64le rest
      (len64, r2) <- takeU64le r1
      let len = fromIntegral len64
      if BS.length r2 < len
        then Nothing
        else do
          let (val, r3) = BS.splitAt len r2
          (more, r4) <- takeRecords (k - 1) r3
          pure ((t, val) : more, r4)
    decodeEntry :: (Word64, ByteString) -> Either FrameError (AttributeType, AttributeValue)
    decodeEntry (t, val) = case attributeNameById t >>= attributeTypeByName of
      Nothing -> Left (FrameUnknownType t)
      Just at -> case decodeNativeValue at val of
        Nothing -> Left (FrameBadValue at)
        Just v -> Right (at, v)

-- | Take one little-endian u64.
takeU64le :: ByteString -> Maybe (Word64, ByteString)
takeU64le bs
  | BS.length bs < 8 = Nothing
  | otherwise =
      let (h, rest) = BS.splitAt 8 bs
      in Just (foldr step 0 (BS.unpack h), rest)
  where
    step :: Word8 -> Word64 -> Word64
    step b acc = acc `shiftL` 8 .|. fromIntegral b

-- | Decode one caller-native attribute value against its owning
-- type's shape: booleans are one byte of 0x00\/0x01, unsigned
-- longs are 8-byte little-endian over the whole 'Word64' domain,
-- byte arrays are raw bytes bounded by 'maxAttributeBytes'.
-- 'AttrEcParams' additionally maps DER curve OIDs to engine curve
-- names ('ecParamsFromWire').
decodeNativeValue :: AttributeType -> ByteString -> Maybe AttributeValue
decodeNativeValue t bs
  | shapeMatches t (ValBool False) = case BS.unpack bs of
      [0] -> Just (ValBool False)
      [1] -> Just (ValBool True)
      _ -> Nothing
  | shapeMatches t (ValULong 0) = ValULong <$> decodeULongLE bs
  | BS.length bs > maxAttributeBytes = Nothing
  | t == AttrEcParams = Just (ValBytes (ecParamsFromWire bs))
  | otherwise = Just (ValBytes bs)

-- | 8-byte little-endian decoding; total over 8-byte inputs
-- (only wrong lengths reject). Platform-width conversions guard
-- at their own site (e.g. 'Haskoki.Object.decodeHandle').
decodeULongLE :: ByteString -> Maybe Word64
decodeULongLE bs
  | BS.length bs /= 8 = Nothing
  | otherwise = Just (foldr (\b acc -> acc `shiftL` 8 .|. fromIntegral b) 0 (BS.unpack bs))

-- ---------------------------------------------------------------------------
-- Wire mappings (pure)
-- ---------------------------------------------------------------------------

-- | Map @CKA_EC_PARAMS@ wire bytes to the engine curve name: the
-- DER object identifiers for the covered curves (RFC 5480 section
-- 2.1.1 for the SEC curves, RFC 5639 for brainpool, RFC 8410 for
-- the Edwards and Montgomery curves) become engine names; anything
-- else passes through for the engine to refuse. Derived from the
-- core 'Haskoki.Der.curveTable' plus 'Haskoki.Der.edwardsTable'
-- plus 'Haskoki.Der.montgomeryTable' (pinned both ways by
-- KeyImportSpec).
ecParamsFromWire :: ByteString -> ByteString
ecParamsFromWire bs = case lookup bs oidToName of
  Just name -> name
  Nothing -> bs
  where
    oidToName = [(oid, name) | (name, oid, _) <- curveTable]
      ++ [(oid, name) | (name, oid, _, _) <- edwardsTable]
      ++ [(oid, name) | (name, oid, _) <- montgomeryTable]

-- | Map an engine curve name back to @CKA_EC_PARAMS@ wire bytes
-- (the inverse of 'ecParamsFromWire' on the known curves;
-- anything else passes through).
ecParamsToWire :: ByteString -> ByteString
ecParamsToWire bs = case lookup bs nameToOid of
  Just oid -> oid
  Nothing -> bs
  where
    nameToOid = [(name, oid) | (name, oid, _) <- curveTable]
      ++ [(name, oid) | (name, oid, _, _) <- edwardsTable]
      ++ [(name, oid) | (name, oid, _) <- montgomeryTable]

-- ---------------------------------------------------------------------------
-- Scalar projections (pure)
-- ---------------------------------------------------------------------------

-- | Project a session onto C scalars: @(slot, readOnly, login,
-- deviceError)@. Login codes are provider-local (0 public, 1
-- user, 2 SO, 3 context grant); the C side maps them onto
-- @CK_STATE@. The device error is always zero (no device).
sessionScalars :: SessionState -> (Word64, Word64, Word64, Word64)
sessionScalars st =
  ( fromIntegral (unSlotId (ssSlot st))
  , if ssReadOnly st then 1 else 0
  , loginCode (ssLogin st)
  , 0
  )
  where
    loginCode LoginPublic = 0
    loginCode LoginUser = 1
    loginCode LoginSO = 2
    loginCode LoginContextUser = 3

-- | Project a slot's token liveness onto C scalars:
-- @(sessionCount, rwSessionCount, userLocked, soLocked,
-- userAttemptsRemaining, soAttemptsRemaining)@. A slot without a
-- token projects all zeros; the C side maps locks and remaining
-- attempts onto @CKF_*_PIN_*@ flags.
tokenScalars :: Rules -> Model -> SlotId -> (Word64, Word64, Word64, Word64, Word64, Word64)
tokenScalars rules m slot = case lookupTokenAuth m slot of
  Nothing -> (0, 0, 0, 0, 0, 0)
  Just auth ->
    let ss = sessionsOnSlot m slot
        limit = max 1 (rulesMaxPinAttempts rules)
    in ( fromIntegral (length ss)
       , fromIntegral (length (filter (not . ssReadOnly) ss))
       , if taUserLocked auth then 1 else 0
       , if taSoLocked auth then 1 else 0
       , fromIntegral (max 0 (limit - taUserAttempts auth))
       , fromIntegral (max 0 (limit - taSoAttempts auth)))

-- ---------------------------------------------------------------------------
-- PIN comparison (pure)
-- ---------------------------------------------------------------------------

-- | PIN equality. Lengths must agree — checked first, so a
-- length mismatch short-circuits — and every byte must agree
-- (the fold touches all paired bytes regardless of where a
-- content mismatch sits, so mismatch POSITION never leaks).
-- PIN-compare ruling (accepted, not full constant-time): the length
-- check leaks at most length-equality per attempt; attempts are
-- lockout-limited (wrong guesses count down to CKR_PIN_LOCKED),
-- the nanosecond delta sits at the end of a millisecond login
-- path, and a Haskell rewrite could not honestly promise machine
-- constant-time (laziness/GC). The old "Constant-time" label
-- overstated this; the code is unchanged.
pinsMatch :: ByteString -> ByteString -> Bool
pinsMatch a b =
  BS.length a == BS.length b
    && foldl' (\acc (x, y) -> acc .|. (x `xor` y)) 0 (BS.zip a b) == 0

-- | Select only the requested session and function, without invoking a worker.
lookupStdAsyncBinding
  :: SessionId -> JobFunction -> Map (SessionId, JobFunction) a -> Maybe a
lookupStdAsyncBinding sid function = Map.lookup (sid, function)

foreign export ccall "haskoki_std_async_complete" haskokiStdAsyncComplete
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr AsyncData -> IO CULong
foreign export ccall "haskoki_std_async_get_id" haskokiStdAsyncGetId
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_async_join" haskokiStdAsyncJoin
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong
  -> Ptr Word8 -> CULong -> IO CULong

-- The C state lock serializes these transactions. Resolve the authoritative
-- session before reading the bounded selector; never infer a function from a
-- different binding or persistent record.
withStdAsyncFunction
  :: StablePtr StdInstance -> CULong -> Ptr Word8
  -> (StdInstance -> SessionId -> JobFunction -> IO CULong) -> IO CULong
withStdAsyncFunction ctx h name action =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    decoded <- decodeAsyncFunctionName name
    either (pure . stdRvOf) (action inst sid) decoded

withStdAsyncBinding
  :: StdInstance -> SessionId -> JobFunction
  -> (StablePtr AsyncCtx -> StdAsyncBinding -> IO CULong) -> IO CULong
withStdAsyncBinding inst sid function action = do
  bindings <- readIORef (siAsyncBindings inst)
  case lookupStdAsyncBinding sid function bindings of
    Nothing -> pure (stdRvOf CKR_OPERATION_NOT_INITIALIZED)
    Just binding -> do
      views <- readIORef (siAsyncViews inst)
      maybe (pure ckrGeneralError) (\view -> action view binding) (Map.lookup sid views)

removeStdAsyncBinding :: StdInstance -> SessionId -> JobFunction -> IO ()
removeStdAsyncBinding inst sid function =
  atomicModifyIORef' (siAsyncBindings inst) $ \bindings ->
    (Map.delete (sid, function) bindings, ())

-- A worker may already have freed its opaque token. Membership is the only
-- permitted liveness test; cancellation goes through the worker (including
-- cancelJoined), never a native-token dereference in this adapter.
cancelStdAsyncHandle :: StablePtr AsyncCtx -> StablePtr JobHandle -> IO ()
cancelStdAsyncHandle view handle = do
  c <- deRefStablePtr view
  live <- readIORef (acLive c)
  when (Set.member (castStablePtrToPtr handle) live) $ do
    _ <- haskokiAsyncCancel view handle
    pure ()

cancelStdAsyncBinding :: StdInstance -> SessionId -> JobFunction -> IO ()
cancelStdAsyncBinding inst sid function = mask_ $ do
  _ <- withStdAsyncBinding inst sid function $ \view binding -> do
    cancelStdAsyncHandle view (sabHandle binding)
    pure ckrOk
  removeStdAsyncBinding inst sid function

haskokiStdAsyncComplete
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr AsyncData -> IO CULong
haskokiStdAsyncComplete ctx h name result =
  withStdAsyncFunction ctx h name $ \inst sid function ->
    withStdAsyncBinding inst sid function $ \view binding -> mask_ $
      if result == nullPtr then pure ckrArgsBad else
      allocaBytesAligned 40 (alignment (undefined :: CULong)) $ \private -> do
        fillBytes private 0 40
        pokeByteOff private 8 (sabOutput binding)
        pokeByteOff private 16 (CULong (sabCapacity binding))
        let handle = sabHandle binding
            code = CULong (jobFunctionCode (sabFunction binding))
            retire = do
              cancelStdAsyncHandle view handle
              removeStdAsyncBinding inst sid function
            terminal rv = do
              retire
              pokeByteOff result 8 (sabOutput binding)
              pure rv
        polled <- haskokiAsyncPoll view handle code
        if polled == stdRvOf CKR_PENDING then pure polled
        else if polled /= ckrOk then terminal polled
        else do
          completed <- haskokiAsyncComplete view handle code private
          if completed == ckrOk then do
            -- Every public field is output-only. The private worker's version
            -- one is deliberately translated to the public ABI version zero.
            copyBytes result private 40
            pokeByteOff result 0 (0 :: CULong)
            removeStdAsyncBinding inst sid function
            pure ckrOk
          else if completed == ckrBufferTooSmall then do
            need <- peekByteOff private 16 :: IO CULong
            pokeByteOff result 8 (sabOutput binding)
            pokeByteOff result 16 need
            pure completed
          else if completed == stdRvOf CKR_PENDING then pure completed
          else terminal completed

haskokiStdAsyncGetId
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdAsyncGetId ctx h name pId =
  withStdAsyncFunction ctx h name $ \inst sid function ->
    withStdAsyncBinding inst sid function $ \view binding -> mask_ $
      -- Supported ABI is LP64; never silently narrow a persistent scalar id.
      if sizeOf (undefined :: CULong) /= sizeOf (undefined :: Word64)
        then pure ckrGeneralError
        else do
          rv <- haskokiAsyncGetId view (sabHandle binding)
            (CULong (jobFunctionCode (sabFunction binding))) (castPtr pId)
          when (rv == ckrOk) (removeStdAsyncBinding inst sid function)
          pure rv

haskokiStdAsyncJoin
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong
  -> Ptr Word8 -> CULong -> IO CULong
haskokiStdAsyncJoin ctx h name pid output capacity =
  withStdAsyncFunction ctx h name $ \inst sid function -> mask_ $ do
    bindings <- readIORef (siAsyncBindings inst)
    case lookupStdAsyncBinding sid function bindings of
      Just _ -> pure (stdRvOf CKR_OPERATION_ACTIVE)
      Nothing -> do
        views <- readIORef (siAsyncViews inst)
        case Map.lookup sid views of
          Nothing -> pure ckrGeneralError
          Just view -> alloca $ \pHandle -> alloca $ \pNeed -> do
            poke pHandle (castPtrToStablePtr nullPtr)
            poke pNeed (0 :: Word64)
            rv <- haskokiAsyncJoin view pid (CULong (jobFunctionCode function)) h capacity pHandle pNeed
            handle <- peek pHandle
            c <- deRefStablePtr view
            live <- readIORef (acLive c)
            let isLive = Set.member (castStablePtrToPtr handle) live
                cancel = cancelStdAsyncHandle view handle
            if rv /= stdRvOf CKR_PENDING then cancel >> pure rv
            else if not isLive then pure ckrGeneralError
            else (do
              -- Reread after the worker: installation itself may fail. A
              -- failed handoff must not leave an untracked live attachment.
              current <- readIORef (siAsyncBindings inst)
              installed <- evaluate (Map.insert (sid, function)
                (StdAsyncBinding function handle output (fromIntegral capacity)) current)
              writeIORef (siAsyncBindings inst) installed
              pure ckrOk) `onException` cancel

-- ---------------------------------------------------------------------------
-- Publication
-- ---------------------------------------------------------------------------

-- | Publish a delta through the instance environment. A later
-- extension adds the process-store commit (store-first ordering);
-- until then it is the plain gate publication.
publishStd :: StdInstance -> StateDelta -> IO (Either ModelFault ())
publishStd inst delta = publish (siEnv inst) delta

-- | Publish a prepared commit, then drain its releases through the
-- instance backend (every commit-application site routes
-- here, so releases are impossible to forget). A faulted
-- publish still drains (drain-then-report) — releases free engine
-- resources that exist independent of the model commit.
publishCommit :: StdInstance -> PreparedCommit -> IO (Either ModelFault ())
publishCommit inst pc = do
  pr <- publishStd inst (pcDelta pc)
  case pr of
    -- Drain-then-report — a faulted publish still drains
    -- (same orphan analysis as 'commitAndTryDeliver''s fault arm:
    -- releases free resources that exist independent of the
    -- commit; frees are idempotent takes).
    Left fault -> do
      drainReleases (siBackend inst) (pcReleases pc)
      pure (Left fault)
    Right () -> do
      drainReleases (siBackend inst) (pcReleases pc)
      pure (Right ())

-- | Publish a rejection's termination, then drain its releases
-- through the instance backend (stale-alloc orphans ride
-- rejections). Plan-time rejections carry none.
publishRejection :: StdInstance -> Rejection -> IO ()
publishRejection inst rej = do
  _ <- publishStd inst (rejDelta rej)
  drainReleases (siBackend inst) (rejReleases rej)

-- | Drop one session's find cursor (close/logout paths).
clearCursor :: StdInstance -> SessionId -> IO ()
clearCursor inst sid =
  atomicModifyIORef' (siFind inst) (\m -> (Map.delete sid m, ()))

-- | Resolve a session for the object paths (create, copy, destroy,
-- set-attributes): unknown sessions report @SESSION_HANDLE_INVALID@
-- (exactly what planning would say). Read/write enforcement is
-- owner-aware and lives in the planners ('admitWritable'), which
-- see the target owner; this is transport only.
requireSession :: StdInstance -> SessionId -> IO (Either CULong ())
requireSession inst sid = do
  m <- snapshotModel (siEnv inst)
  case lookupSession m sid of
    Nothing -> pure (Left (stdRvOf CKR_SESSION_HANDLE_INVALID))
    Just _ -> pure (Right ())

-- ---------------------------------------------------------------------------
-- FFI-only CK_RV values (pinned by spec/vendor/pkcs11.h).
-- The pure core never produces these (it has no slot universe and
-- no serial/parallel distinction); the boundary owns them, with
-- the control-entry raw-code precedent.
-- ---------------------------------------------------------------------------

-- | @CKR_SLOT_ID_INVALID@ (0x03).
ckrSlotIdInvalid :: CULong
ckrSlotIdInvalid = CULong 0x03

-- | @CKR_ARGUMENTS_BAD@ (0x07).
ckrArgsBad :: CULong
ckrArgsBad = CULong 0x07

-- | @CKR_BUFFER_TOO_SMALL@ (0x150).
ckrBufferTooSmall :: CULong
ckrBufferTooSmall = CULong 0x150

-- | @CKR_GENERAL_ERROR@ (0x05).
ckrGeneralError :: CULong
ckrGeneralError = CULong 0x05

-- | @CKR_OK@ (0x00).
ckrOk :: CULong
ckrOk = CULong 0x00

-- | @CKR_TEMPLATE_INCONSISTENT@ (0xD1).
ckrTemplateInconsistent :: CULong
ckrTemplateInconsistent = CULong 0xD1

-- | @CKR_ATTRIBUTE_TYPE_INVALID@ (0x12).
ckrAttrTypeInvalid :: CULong
ckrAttrTypeInvalid = CULong 0x12

-- | @CKR_ATTRIBUTE_SENSITIVE@ (0x11).
ckrAttrSensitive :: CULong
ckrAttrSensitive = CULong 0x11

-- | @CKR_USER_TYPE_INVALID@ (0x103).
ckrUserTypeInvalid :: CULong
ckrUserTypeInvalid = CULong 0x103

-- ---------------------------------------------------------------------------
-- slot list, sessions, session info, token liveness
-- ---------------------------------------------------------------------------

foreign export ccall "haskoki_std_get_slot_list" haskokiStdGetSlotList
  :: StablePtr StdInstance -> Word8 -> Ptr CULong -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_open_session" haskokiStdOpenSessionWithAsync
  :: StablePtr StdInstance -> CULong -> CULong -> CULong -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_close_session" haskokiStdCloseSession
  :: StablePtr StdInstance -> CULong -> IO CULong
foreign export ccall "haskoki_std_close_all_sessions" haskokiStdCloseAllSessions
  :: StablePtr StdInstance -> CULong -> IO CULong
foreign export ccall "haskoki_std_session_cancel" haskokiStdSessionCancel
  :: StablePtr StdInstance -> CULong -> CULong -> IO CULong
foreign export ccall "haskoki_std_get_session_info" haskokiStdGetSessionInfoWithAsync
  :: StablePtr StdInstance -> CULong
  -> Ptr CULong -> Ptr CULong -> Ptr CULong -> Ptr CULong
  -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_token_live" haskokiStdTokenLive
  :: StablePtr StdInstance -> CULong
  -> Ptr CULong -> Ptr CULong -> Ptr CULong
  -> Ptr CULong -> Ptr CULong -> Ptr CULong -> IO CULong

-- | Serve the slot list from live model state: every seated slot
-- in index order, token-present exactly when the slot holds a
-- token (always, in a live interval: every seated slot holds its
-- catalog token). Size-query and short-buffer semantics per the
-- Direct contract. The token-present filter is vacuous by design:
-- it re-checks seated keys for membership, and every seated slot
-- holds a token, so the filtered list always equals the full
-- list (pinned by casePresentFiltering, counts and elements).
-- The two-phase shape is kept for the direct contract.
haskokiStdGetSlotList
  :: StablePtr StdInstance -> Word8 -> Ptr CULong -> Ptr CULong -> IO CULong
haskokiStdGetSlotList ctx tokenPresent pSlotList pCount =
  withStdCtx ctx $ \inst ->
    if pCount == nullPtr
      then pure ckrArgsBad
      else do
        m <- snapshotModel (siEnv inst)
        let seated = Map.keys (mTokenAuth m)
            ids
              | tokenPresent == 0 = seated
              | otherwise =
                  [ slot
                  | slot <- seated
                  , lookupTokenAuth m slot /= Nothing
                  ]
            want = fromIntegral (length ids) :: Word64
            outIds = [CULong (fromIntegral n) | SlotId n <- ids]
        if pSlotList == nullPtr
          then do
            poke pCount (CULong want)
            pure ckrOk
          else do
            CULong cap <- peek pCount
            if cap < want
              then do
                poke pCount (CULong want)
                pure ckrBufferTooSmall
              else do
                pokeArray pSlotList outIds
                poke pCount (CULong want)
                pure ckrOk

-- | Open a session on a seated slot (unseated slots refuse with
-- @SLOT_ID_INVALID@), read-only flag from the caller (the C side
-- owns @CKF_*@ spellings and enforces the serial mark). The new
-- handle allocates deterministically from the model counter.
haskokiStdOpenSession
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr CULong -> IO CULong
haskokiStdOpenSession ctx slot ro = haskokiStdOpenSessionWithAsync ctx slot ro 0

-- | The existing native session boundary also carries explicit async intent.
-- Prepare the borrowed view and registry update before admitting the session;
-- enable it only after successful model publication. No proof context is opened.
haskokiStdOpenSessionWithAsync
  :: StablePtr StdInstance -> CULong -> CULong -> CULong
  -> Ptr CULong -> IO CULong
haskokiStdOpenSessionWithAsync ctx (CULong slot) (CULong ro) (CULong async) phSession =
  withStdCtx ctx $ \inst ->
    if phSession == nullPtr
      then pure ckrArgsBad
      else do
        m0 <- snapshotModel (siEnv inst)
        case lookupTokenAuth m0 (SlotId (fromIntegral slot)) of
          Nothing -> pure ckrSlotIdInvalid
          Just _ -> do
            let sid = SessionId (mNextSession m0)
                req = Request Pkcs11_3_2 F_OpenSession Nothing Nothing
                  (BC8.pack ("slot=" ++ show slot ++ if ro == 0 then ",rw" else ",ro")) []
            case planCall (envRules (siEnv inst)) m0 req of
              Immediate pc
                | pcCode pc == CKR_OK -> mask_ $ do
                    live <- newIORef Set.empty
                    let detached = case siDetach inst of
                          Just dc | detachSlot dc == SlotId (fromIntegral slot) -> Just dc
                          _ -> Nothing
                    view <- newStablePtr (AsyncCtx (siEnv inst) (siBackend inst)
                      sid (siAsyncTable inst) live detached)
                    (do
                      views <- readIORef (siAsyncViews inst)
                      installed <- evaluate (Map.insert sid view views)
                      pr <- publishCommit inst pc
                      case pr of
                        Left _ -> freeStablePtr view >> pure ckrGeneralError
                        Right () -> do
                          when (async /= 0) (enableAsyncSession (siAsyncTable inst) sid)
                          writeIORef (siAsyncViews inst) installed
                          poke phSession (CULong (fromIntegral (unSessionId sid)))
                          pure ckrOk) `onException` do
                            -- Roll back an admitted session if a later allocation
                            -- fails; before publication this is a harmless no-op.
                            m <- snapshotModel (siEnv inst)
                            case lookupSession m sid of
                              Nothing -> pure ()
                              Just _ -> case planCall (envRules (siEnv inst)) m
                                  (Request Pkcs11_3_2 F_CloseSession (Just sid) Nothing BS.empty []) of
                                Immediate close -> do
                                  _ <- publishCommit inst close
                                  pure ()
                                _ -> pure ()
                            freeStablePtr view
                | otherwise -> do
                    pr <- publishCommit inst pc
                    pure $ either (const ckrGeneralError) (const (stdRvOf (pcCode pc))) pr
              Reject rej -> do
                publishRejection inst rej
                pure (stdRvOf (rejCode rej))
              Execute _ _ -> pure ckrGeneralError

-- | Close one session (unknown handles refuse; the engine also
-- destroys the session's objects and applies last-close logout).
haskokiStdCloseSession :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdCloseSession ctx (CULong h) =
  withStdCtx ctx $ \inst -> do
    m0 <- snapshotModel (siEnv inst)
    let req = Request Pkcs11_3_2 F_CloseSession (Just (SessionId (fromIntegral h)))
          Nothing BS.empty []
    case planCall (envRules (siEnv inst)) m0 req of
      Immediate pc -> do
        when (pcCode pc == CKR_OK) $
          cancelStdAsyncJobs inst (SessionId (fromIntegral h))
        pr <- publishCommit inst pc
        case pr of
          Left _ -> pure ckrGeneralError
          Right ()
            | pcCode pc == CKR_OK -> do
                clearCursor inst (SessionId (fromIntegral h))
                freeStdAsyncView inst (SessionId (fromIntegral h))
                pure ckrOk
            | otherwise -> pure (stdRvOf (pcCode pc))
      Reject rej -> do
        publishRejection inst rej
        pure (stdRvOf (rejCode rej))
      Execute _ _ -> pure ckrGeneralError

-- | Close every session on a seated slot (unseated slots refuse).
-- Each close plans against a fresh snapshot so last-close logout
-- fires exactly once, on the final close.
haskokiStdCloseAllSessions :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdCloseAllSessions ctx (CULong slot) =
  withStdCtx ctx $ \inst -> do
    m0 <- snapshotModel (siEnv inst)
    case lookupTokenAuth m0 slotId of
      Nothing -> pure ckrSlotIdInvalid
      Just _ -> do
        let sids = map ssId (sessionsOnSlot m0 slotId)
        forM_ sids $ \sid -> do
          m <- snapshotModel (siEnv inst)
          let req = Request Pkcs11_3_2 F_CloseSession (Just sid) Nothing BS.empty []
          case planCall (envRules (siEnv inst)) m req of
            Immediate pc -> do
              when (pcCode pc == CKR_OK) (cancelStdAsyncJobs inst sid)
              _ <- publishCommit inst pc
              clearCursor inst sid
              when (pcCode pc == CKR_OK) (freeStdAsyncView inst sid)
            Reject rej -> do
              publishRejection inst rej
              pure ()
            Execute _ _ -> pure ()
        pure ckrOk
  where
    slotId = SlotId (fromIntegral slot)

-- | Cancel a session's active operations under its CKF_* selector
-- mask (unknown handles refuse; the planner clears the selected
-- slots and drains a cancelled live digest stream). A zero mask or
-- the CKF_FIND_OBJECTS bit (0x40, pinned header) also drops the
-- session's find cursor: cancel-all means every session operation,
-- find included.
haskokiStdSessionCancel
  :: StablePtr StdInstance -> CULong -> CULong -> IO CULong
haskokiStdSessionCancel ctx (CULong h) (CULong flags) =
  withStdCtx ctx $ \inst -> do
    m0 <- snapshotModel (siEnv inst)
    let sid = SessionId (fromIntegral h)
        req = Request Pkcs11_3_2 F_SessionCancel (Just sid)
          Nothing (encodeCancelInput (fromIntegral flags)) []
    case planCall (envRules (siEnv inst)) m0 req of
      Immediate pc -> do
        -- CKF_DIGEST is 0x400 in the pinned header; zero selects all slots.
        when (pcCode pc == CKR_OK && (flags == 0 || flags .&. 0x400 /= 0)) $
          cancelStdAsyncBinding inst sid JobDigest
        pr <- publishCommit inst pc
        case pr of
          Left _ -> pure ckrGeneralError
          Right ()
            | pcCode pc == CKR_OK -> do
                -- CKF_FIND_OBJECTS is 0x40 in the pinned header.
                when (flags == 0 || flags .&. 0x40 /= 0) $
                  clearCursor inst sid
                pure ckrOk
            | otherwise -> pure (stdRvOf (pcCode pc))
      Reject rej -> do
        publishRejection inst rej
        pure (stdRvOf (rejCode rej))
      Execute _ _ -> pure ckrGeneralError

-- | Project one session onto the C scalars (see 'sessionScalars').
haskokiStdGetSessionInfo
  :: StablePtr StdInstance -> CULong
  -> Ptr CULong -> Ptr CULong -> Ptr CULong -> Ptr CULong -> IO CULong
haskokiStdGetSessionInfo ctx h pSlot pRO pLogin pDevErr = alloca $ \pAsync ->
  haskokiStdGetSessionInfoWithAsync ctx h pSlot pRO pLogin pDevErr pAsync

haskokiStdGetSessionInfoWithAsync
  :: StablePtr StdInstance -> CULong
  -> Ptr CULong -> Ptr CULong -> Ptr CULong -> Ptr CULong
  -> Ptr CULong -> IO CULong
haskokiStdGetSessionInfoWithAsync ctx (CULong h) pSlot pRO pLogin pDevErr pAsync =
  withStdCtx ctx $ \inst ->
    if pSlot == nullPtr || pRO == nullPtr || pLogin == nullPtr || pDevErr == nullPtr || pAsync == nullPtr
      then pure ckrArgsBad
      else do
        m <- snapshotModel (siEnv inst)
        case lookupSession m (SessionId (fromIntegral h)) of
          Nothing -> pure (stdRvOf CKR_SESSION_HANDLE_INVALID)
          Just st -> do
            let (slot, ro, login, devErr) = sessionScalars st
            poke pSlot (CULong slot)
            poke pRO (CULong ro)
            poke pLogin (CULong login)
            poke pDevErr (CULong devErr)
            async <- isAsyncSession (siAsyncTable inst) (ssId st)
            poke pAsync (if async then 1 else 0)
            pure ckrOk

-- | Project a seated slot's token liveness onto the C scalars
-- (see 'tokenScalars'; unseated slots refuse, checked before the
-- buffers).
haskokiStdTokenLive
  :: StablePtr StdInstance -> CULong
  -> Ptr CULong -> Ptr CULong -> Ptr CULong
  -> Ptr CULong -> Ptr CULong -> Ptr CULong -> IO CULong
haskokiStdTokenLive ctx (CULong slot)
    pSess pRw pUserLock pSoLock pUserRem pSoRem =
  withStdCtx ctx $ \inst -> do
    m <- snapshotModel (siEnv inst)
    case lookupTokenAuth m (SlotId (fromIntegral slot)) of
      Nothing -> pure ckrSlotIdInvalid
      Just _
        | pSess == nullPtr || pRw == nullPtr || pUserLock == nullPtr
          || pSoLock == nullPtr || pUserRem == nullPtr || pSoRem == nullPtr ->
            pure ckrArgsBad
        | otherwise -> do
            let (ns, nrw, ul, sl, ur, sr) =
                  tokenScalars (envRules (siEnv inst)) m (SlotId (fromIntegral slot))
            poke pSess (CULong ns)
            poke pRw (CULong nrw)
            poke pUserLock (CULong ul)
            poke pSoLock (CULong sl)
            poke pUserRem (CULong ur)
            poke pSoRem (CULong sr)
            pure ckrOk

foreign export ccall "haskoki_std_token_label" haskokiStdTokenLabel
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> IO CULong
foreign export ccall "haskoki_std_slot_present" haskokiStdSlotPresent
  :: StablePtr StdInstance -> CULong -> IO CULong

-- | Project a seated slot's token label onto the 32-byte
-- blank-padded @CK_TOKEN_INFO@ label field (the C side copies the
-- bytes verbatim). Unseated slots refuse with @SLOT_ID_INVALID@,
-- checked before the buffer (the "bad slots rejected first"
-- discipline).
haskokiStdTokenLabel :: StablePtr StdInstance -> CULong -> Ptr Word8 -> IO CULong
haskokiStdTokenLabel ctx (CULong slot) pOut =
  withStdCtx ctx $ \inst -> do
    m <- snapshotModel (siEnv inst)
    case lookupTokenAuth m sid of
      Nothing -> pure ckrSlotIdInvalid
      Just _
        | pOut == nullPtr -> pure ckrArgsBad
        | otherwise -> do
            let (label, _, _) = catalogLookup inst sid
            pokeArray pOut (padLabel32 label)
            pure ckrOk
  where
    sid = SlotId (fromIntegral slot)

-- | Blank-pad a catalog label to exactly 32 bytes (truncate past
-- 32; validation caps labels at 32 chars, ASCII in practice).
padLabel32 :: String -> [Word8]
padLabel32 label =
  take 32 (map (fromIntegral . ord) label ++ repeat 0x20)

-- | Report whether a slot is seated in this instance (@CKR_OK@) or
-- not (@SLOT_ID_INVALID@). Serves the C slot-info/mechanism
-- bodies, which carry no Haskell state of their own.
haskokiStdSlotPresent :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdSlotPresent ctx (CULong slot) =
  withStdCtx ctx $ \inst -> do
    m <- snapshotModel (siEnv inst)
    case lookupTokenAuth m (SlotId (fromIntegral slot)) of
      Nothing -> pure ckrSlotIdInvalid
      Just _ -> pure ckrOk

-- ---------------------------------------------------------------------------
-- objects
-- ---------------------------------------------------------------------------

foreign export ccall "haskoki_std_create_object" haskokiStdCreateObject
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr CULong
  -> IO CULong
foreign export ccall "haskoki_std_copy_object" haskokiStdCopyObject
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_set_attribute_value" haskokiStdSetAttributeValue
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> IO CULong
foreign export ccall "haskoki_std_destroy_object" haskokiStdDestroyObject
  :: StablePtr StdInstance -> CULong -> CULong -> IO CULong
foreign export ccall "haskoki_std_get_one_attr" haskokiStdGetOneAttr
  :: StablePtr StdInstance -> CULong -> CULong -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_find_init" haskokiStdFindInit
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
foreign export ccall "haskoki_std_find" haskokiStdFind
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr CULong -> Ptr CULong
  -> IO CULong
foreign export ccall "haskoki_std_find_final" haskokiStdFindFinal
  :: StablePtr StdInstance -> CULong -> IO CULong

-- | Encode a model attribute value in caller-native order
-- (little-endian @CK_ULONG@, one-byte @CK_BBOOL@, raw bytes;
-- @CKA_EC_PARAMS@ maps engine curve names back to DER OIDs). The
-- inverse of 'decodeNativeValue' on well-typed inputs.
nativeEncodeAttr :: AttributeType -> AttributeValue -> ByteString
nativeEncodeAttr t v = case v of
  ValBool b -> BS.singleton (if b then 1 else 0)
  ValULong w -> BS.pack (map (\s -> fromIntegral ((w `shiftR` (8 * s)) .&. 0xFF))
    ([0 .. 7] :: [Int]))
  ValBytes bs ->
    if t == AttrEcParams then ecParamsToWire bs else bs

-- | Convert one canonical engine output value (big-endian
-- @CK_ULONG@, one-byte booleans, raw bytes) to caller-native
-- order for its owning type. Anything off-shape fails closed.
nativeFromCanonical :: AttributeType -> ByteString -> Maybe ByteString
nativeFromCanonical t bs
  | shapeMatches t (ValBool False) =
      if BS.length bs == 1 then Just bs else Nothing
  | shapeMatches t (ValULong 0) =
      if BS.length bs == 8 then Just (BS.reverse bs) else Nothing
  | t == AttrEcParams = Just (ecParamsToWire bs)
  | otherwise = Just bs

-- | Map a template-frame fault onto its documented @CK_RV@:
-- truncation and count bounds are caller-memory faults
-- (@ARGUMENTS_BAD@), unknown type ids are
-- @ATTRIBUTE_TYPE_INVALID@, and wrongly shaped values contradict
-- their type (@TEMPLATE_INCONSISTENT@).
frameErrorRV :: FrameError -> CULong
frameErrorRV FrameTruncated = ckrArgsBad
frameErrorRV FrameTooManyAttrs = ckrArgsBad
frameErrorRV (FrameUnknownType _) = ckrAttrTypeInvalid
frameErrorRV (FrameBadValue _) = ckrTemplateInconsistent

-- | Decode one 8-byte big-endian word (engine handle/length
-- outputs); anything else fails closed.
beWord64 :: ByteString -> Maybe Word64
beWord64 bs
  | BS.length bs /= 8 = Nothing
  | otherwise = Just (BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 bs)

-- | Bound on frame bytes read from C (the packer caps its output
-- at 16 MiB plus record headers; anything past that from any
-- frame source fails closed before a single byte is read).
maxFrameBytes :: Word64
maxFrameBytes = 16777216 + 8 + 16 * 64

-- | Read and parse one template frame from C.
readFrame :: Ptr Word8 -> CULong -> IO (Either FrameError [(AttributeType, AttributeValue)])
readFrame p (CULong len)
  | p == nullPtr && len /= 0 = pure (Left FrameTruncated)
  | len > maxFrameBytes = pure (Left FrameTruncated)
  | otherwise = do
      bs <- BS.packCStringLen (castPtr p, fromIntegral len)
      pure (parseTemplateFrame bs)

-- | Decode the single handle output of a create/copy plan.
decodeOneHandle :: [NativeOutput] -> Maybe Word64
decodeOneHandle [NativeOutput _ bs] = beWord64 bs
decodeOneHandle _ = Nothing

-- | Decode the handle outputs of a find plan, in order.
decodeHandles :: [NativeOutput] -> Maybe [Word64]
decodeHandles = mapM $ \(NativeOutput _ bs) -> beWord64 bs

-- | Create an object from a template frame.
haskokiStdCreateObject
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr CULong
  -> IO CULong
haskokiStdCreateObject ctx (CULong h) pFrame (CULong frameLen) phObj =
  withStdCtx ctx $ \inst ->
    if phObj == nullPtr
      then pure ckrArgsBad
      else do
        eW <- requireSession inst (SessionId (fromIntegral h))
        case eW of
          Left rv -> pure rv
          Right () -> do
            eTmpl <- readFrame pFrame (CULong frameLen)
            case eTmpl of
              Left ferr -> pure (frameErrorRV ferr)
              Right entries -> do
                m0 <- snapshotModel (siEnv inst)
                -- The decoded frame goes straight to the
                -- planner — no re-encode into 'reqInput', no
                -- re-parse on the plan path.
                let dreq = DRCreateObject (SessionId (fromIntegral h)) entries
                case planDecoded (envRules (siEnv inst)) m0 dreq of
                  Immediate pc -> case decodeOneHandle (pcOutputs pc) of
                    Nothing -> pure ckrGeneralError
                    Just oh -> do
                      pr <- publishCommit inst pc
                      case pr of
                        Left _ -> pure ckrGeneralError
                        Right ()
                          | pcCode pc == CKR_OK -> do
                              poke phObj (CULong oh)
                              pure ckrOk
                          | otherwise -> pure (stdRvOf (pcCode pc))
                  Reject rej -> do
                    publishRejection inst rej
                    pure (stdRvOf (rejCode rej))
                  Execute _ _ -> pure ckrGeneralError

-- | Copy an object under a modifier frame.
haskokiStdCopyObject
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> Ptr CULong -> IO CULong
haskokiStdCopyObject ctx (CULong h) (CULong o) pFrame (CULong frameLen) phNew =
  withStdCtx ctx $ \inst ->
    if phNew == nullPtr
      then pure ckrArgsBad
      else do
        eW <- requireSession inst (SessionId (fromIntegral h))
        case eW of
          Left rv -> pure rv
          Right () -> do
            eTmpl <- readFrame pFrame (CULong frameLen)
            case eTmpl of
              Left ferr -> pure (frameErrorRV ferr)
              Right entries -> do
                m0 <- snapshotModel (siEnv inst)
                -- Decoded frame straight to the planner.
                let dreq = DRCopyObject (SessionId (fromIntegral h))
                      (ExternalHandle (fromIntegral o)) entries
                case planDecoded (envRules (siEnv inst)) m0 dreq of
                  Immediate pc -> case decodeOneHandle (pcOutputs pc) of
                    Nothing -> pure ckrGeneralError
                    Just oh -> do
                      pr <- publishCommit inst pc
                      case pr of
                        Left _ -> pure ckrGeneralError
                        Right ()
                          | pcCode pc == CKR_OK -> do
                              poke phNew (CULong oh)
                              pure ckrOk
                          | otherwise -> pure (stdRvOf (pcCode pc))
                  Reject rej -> do
                    publishRejection inst rej
                    pure (stdRvOf (rejCode rej))
                  Execute _ _ -> pure ckrGeneralError

-- | Set attributes on an object from a template frame. The plan
-- carries no outputs: success is the commit itself.
haskokiStdSetAttributeValue
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> IO CULong
haskokiStdSetAttributeValue ctx (CULong h) (CULong o) pFrame (CULong frameLen) =
  withStdCtx ctx $ \inst -> do
    eW <- requireSession inst (SessionId (fromIntegral h))
    case eW of
      Left rv -> pure rv
      Right () -> do
        eTmpl <- readFrame pFrame (CULong frameLen)
        case eTmpl of
          Left ferr -> pure (frameErrorRV ferr)
          Right entries -> do
            m0 <- snapshotModel (siEnv inst)
            -- Decoded frame straight to the planner.
            let dreq = DRSetAttributeValue (SessionId (fromIntegral h))
                  (ExternalHandle (fromIntegral o)) entries
            case planDecoded (envRules (siEnv inst)) m0 dreq of
              Immediate pc
                | not (null (pcOutputs pc)) -> pure ckrGeneralError
                | otherwise -> do
                    pr <- publishCommit inst pc
                    case pr of
                      Left _ -> pure ckrGeneralError
                      Right ()
                        | pcCode pc == CKR_OK -> pure ckrOk
                        | otherwise -> pure (stdRvOf (pcCode pc))
              Reject rej -> do
                publishRejection inst rej
                pure (stdRvOf (rejCode rej))
              Execute _ _ -> pure ckrGeneralError

-- | Destroy an object.
haskokiStdDestroyObject :: StablePtr StdInstance -> CULong -> CULong -> IO CULong
haskokiStdDestroyObject ctx (CULong h) (CULong o) =
  withStdCtx ctx $ \inst -> do
    eW <- requireSession inst (SessionId (fromIntegral h))
    case eW of
      Left rv -> pure rv
      Right () -> do
        m0 <- snapshotModel (siEnv inst)
        let req = Request Pkcs11_3_2 F_DestroyObject
              (Just (SessionId (fromIntegral h)))
              (Just (ExternalHandle (fromIntegral o))) BS.empty []
        case planCall (envRules (siEnv inst)) m0 req of
          Immediate pc -> do
            pr <- publishCommit inst pc
            case pr of
              Left _ -> pure ckrGeneralError
              Right ()
                | pcCode pc == CKR_OK -> pure ckrOk
                | otherwise -> pure (stdRvOf (pcCode pc))
          Reject rej -> do
            publishRejection inst rej
            pure (stdRvOf (rejCode rej))
          Execute _ _ -> pure ckrGeneralError

-- | Serve one attribute read: unknown type ids report
-- @ATTRIBUTE_TYPE_INVALID@ with length @-1@; sensitive and
-- object-missing attributes report their engine code with length
-- @-1@; otherwise size-query, exact-write, and short-buffer
-- semantics apply (short buffers report @BUFFER_TOO_SMALL@ with
-- the @CK_UNAVAILABLE_INFORMATION@ length sentinel, never the
-- needed length). Whole-call failures (bad session\/object)
-- leave the length word untouched.
haskokiStdGetOneAttr
  :: StablePtr StdInstance -> CULong -> CULong -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
haskokiStdGetOneAttr ctx (CULong h) (CULong o) (CULong ckaId) pValue pLen =
  withStdCtx ctx $ \inst ->
    if pLen == nullPtr
      then pure ckrArgsBad
      else case attributeNameById ckaId >>= attributeTypeByName of
        Nothing -> do
          poke pLen (CULong maxBound)
          pure ckrAttrTypeInvalid
        Just t -> do
          m0 <- snapshotModel (siEnv inst)
          -- Decoded wanted list straight to the planner.
          let dreq = DRGetAttributeValue (SessionId (fromIntegral h))
                (ExternalHandle (fromIntegral o)) [t]
          case planDecoded (envRules (siEnv inst)) m0 dreq of
            -- Immediate reads always carry OK plus exactly the
            -- one value (the engine rejects every other outcome).
            Immediate pc -> case (pcCode pc, pcOutputs pc) of
              (CKR_OK, [NativeOutput _ outBytes]) ->
                case nativeFromCanonical t outBytes of
                  Nothing -> pure ckrGeneralError
                  Just native -> do
                    pr <- publishCommit inst pc
                    case pr of
                      Left _ -> pure ckrGeneralError
                      Right () -> writeAttrBytes pValue pLen native
              (code, _) -> do
                _ <- publishCommit inst pc
                pure (stdRvOf code)
            -- The engine reports per-attribute faults (sensitive,
            -- object-missing) as rejections carrying the code: those
            -- still write the @-1@ length. Whole-call failures
            -- (bad session/object) leave the length word untouched.
            Reject rej
              | rejCode rej == CKR_ATTRIBUTE_SENSITIVE -> do
                  publishRejection inst rej
                  poke pLen (CULong maxBound)
                  pure ckrAttrSensitive
              | rejCode rej == CKR_ATTRIBUTE_TYPE_INVALID -> do
                  publishRejection inst rej
                  poke pLen (CULong maxBound)
                  pure ckrAttrTypeInvalid
              | otherwise -> do
                  publishRejection inst rej
                  pure (stdRvOf (rejCode rej))
            Execute _ _ -> pure ckrGeneralError
  where
    writeAttrBytes :: Ptr Word8 -> Ptr CULong -> ByteString -> IO CULong
    writeAttrBytes pv pl native = do
      let need = fromIntegral (BS.length native) :: Word64
      if pv == nullPtr
        then do
          poke pl (CULong need)
          pure ckrOk
        else do
          CULong cap <- peek pl
          if cap < need
            then do
              -- Short attribute buffers report CK_UNAVAILABLE_INFORMATION
              -- (-1), not the needed length (PKCS#11 size-guard rule).
              poke pl (CULong maxBound)
              pure ckrBufferTooSmall
            else do
              pokeArray pv (BS.unpack native)
              poke pl (CULong need)
              pure ckrOk

-- | Open a find cursor: a live cursor refuses re-init, then the
-- template plans a one-shot engine find whose handles are
-- stashed for 'haskokiStdFind'.
haskokiStdFindInit
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdFindInit ctx (CULong h) pFrame (CULong frameLen) =
  withStdCtx ctx $ \inst -> do
    let sid = SessionId (fromIntegral h)
    cursors <- readIORef (siFind inst)
    case Map.lookup sid cursors of
      Just _ -> pure (stdRvOf CKR_OPERATION_ACTIVE)
      Nothing -> do
        eTmpl <- readFrame pFrame (CULong frameLen)
        case eTmpl of
          Left ferr -> pure (frameErrorRV ferr)
          Right entries -> do
            m0 <- snapshotModel (siEnv inst)
            -- Decoded frame straight to the planner.
            let dreq = DRFindObjects sid entries
            case planDecoded (envRules (siEnv inst)) m0 dreq of
              Immediate pc -> case decodeHandles (pcOutputs pc) of
                Nothing -> pure ckrGeneralError
                Just hs -> do
                  pr <- publishCommit inst pc
                  case pr of
                    Left _ -> pure ckrGeneralError
                    Right ()
                      | pcCode pc == CKR_OK -> do
                          atomicModifyIORef' (siFind inst)
                            (\m -> (Map.insert sid (map (ExternalHandle . fromIntegral) hs) m, ()))
                          pure ckrOk
                      | otherwise -> pure (stdRvOf (pcCode pc))
              Reject rej -> do
                publishRejection inst rej
                pure (stdRvOf (rejCode rej))
              Execute _ _ -> pure ckrGeneralError

-- | Serve the next page of a find cursor.
haskokiStdFind
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr CULong -> Ptr CULong
  -> IO CULong
haskokiStdFind ctx (CULong h) (CULong maxCount) pHandles pCount =
  withStdCtx ctx $ \inst ->
    if pCount == nullPtr
      then pure ckrArgsBad
      else
        if pHandles == nullPtr && maxCount /= 0
          then pure ckrArgsBad
          else do
            let sid = SessionId (fromIntegral h)
            mHandles <- atomicModifyIORef' (siFind inst) $ \m ->
              case Map.lookup sid m of
                Nothing -> (m, Nothing)
                Just hs ->
                  let (page, rest) = splitAt (fromIntegral maxCount) hs
                  in (Map.insert sid rest m, Just page)
            case mHandles of
              Nothing -> pure (stdRvOf CKR_OPERATION_NOT_INITIALIZED)
              Just page -> do
                pokeArray pHandles (map (\(ExternalHandle w) -> CULong (fromIntegral w)) page)
                poke pCount (CULong (fromIntegral (length page)))
                pure ckrOk

-- | Close a find cursor (closing a non-open search refuses).
haskokiStdFindFinal :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdFindFinal ctx (CULong h) =
  withStdCtx ctx $ \inst -> do
    let sid = SessionId (fromIntegral h)
    wasOpen <- atomicModifyIORef' (siFind inst) $ \m ->
      case Map.lookup sid m of
        Nothing -> (m, False)
        Just _ -> (Map.delete sid m, True)
    if wasOpen
      then pure ckrOk
      else pure (stdRvOf CKR_OPERATION_NOT_INITIALIZED)

-- ---------------------------------------------------------------------------
-- login/logout
-- ---------------------------------------------------------------------------

foreign export ccall "haskoki_std_login" haskokiStdLogin
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> IO CULong
foreign export ccall "haskoki_std_logout" haskokiStdLogout
  :: StablePtr StdInstance -> CULong -> IO CULong

-- | Bound on PIN bytes read from C (provisioned PINs are 4 bytes;
-- anything past this bound fails closed before a byte is read).
maxPinBytes :: Word64
maxPinBytes = 65536

-- | Log in: the caller @CKU_*@ word selects the role (0 SO, 1
-- user, 2 context-specific acting for the user — anything else
-- is @USER_TYPE_INVALID@), the caller PIN is compared with a
-- position-constant xor fold with length short-circuit against
-- the session slot's catalog PIN (the provisioned PIN on slot 0;
-- accepted per the PIN-compare ruling, not machine constant-time), and the
-- verdict feeds the engine's attempt counting, lockout, and
-- session relabeling. Denials publish their counter moves.
haskokiStdLogin
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> IO CULong
haskokiStdLogin ctx (CULong h) (CULong userType) pPin (CULong pinLen) =
  withStdCtx ctx $ \inst ->
    case userType of
      0 -> loginAs inst "so" soPinOf
      1 -> loginAs inst "user" userPinOf
      2 -> loginAs inst "context" userPinOf
      _ -> pure ckrUserTypeInvalid
  where
    loginAs :: StdInstance -> ByteString -> ((String, String, String) -> ByteString) -> IO CULong
    loginAs inst who pick
      | pPin == nullPtr && pinLen /= 0 = pure ckrArgsBad
      | pinLen > maxPinBytes = pure ckrArgsBad
      | otherwise = do
          pin <- if pinLen == 0
            then pure BS.empty
            else BS.packCStringLen (castPtr pPin, fromIntegral pinLen)
          m0 <- snapshotModel (siEnv inst)
          let expected = case lookupSession m0 (SessionId (fromIntegral h)) of
                -- Unknown session: the plan refuses below, so the
                -- verdict is moot; compare against home.
                Nothing -> pick homeCatalogEntry
                Just st -> pick (catalogLookup inst (ssSlot st))
              verdict
                | pinsMatch pin expected = "ok"
                | otherwise = "bad"
          let req = Request Pkcs11_3_2 F_Login
                (Just (SessionId (fromIntegral h))) Nothing
                (who <> ":" <> verdict) []
          case planCall (envRules (siEnv inst)) m0 req of
            Immediate pc -> do
              pr <- publishCommit inst pc
              case pr of
                Left _ -> pure ckrGeneralError
                Right ()
                  | pcCode pc == CKR_OK -> pure ckrOk
                  | otherwise -> pure (stdRvOf (pcCode pc))
            Reject rej -> do
              publishRejection inst rej
              pure (stdRvOf (rejCode rej))
            Execute _ _ -> pure ckrGeneralError
    soPinOf (_, so, _) = BC8.pack so
    userPinOf (_, _, user) = BC8.pack user

-- | Log out (refused without a login): publishes the engine's
-- logout delta (session relabeling, private-handle
-- stale-marking) and drops the session's find cursor, whose
-- handles the logout may have killed.
haskokiStdLogout :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdLogout ctx (CULong h) =
  withStdCtx ctx $ \inst -> do
    m0 <- snapshotModel (siEnv inst)
    let sid = SessionId (fromIntegral h)
        req = Request Pkcs11_3_2 F_Logout (Just sid) Nothing BS.empty []
    case planCall (envRules (siEnv inst)) m0 req of
      Immediate pc -> do
        pr <- publishCommit inst pc
        case pr of
          Left _ -> pure ckrGeneralError
          Right ()
            | pcCode pc == CKR_OK -> do
                clearCursor inst sid
                pure ckrOk
            | otherwise -> pure (stdRvOf (pcCode pc))
      Reject rej -> do
        publishRejection inst rej
        pure (stdRvOf (rejCode rej))
      Execute _ _ -> pure ckrGeneralError

-- ---------------------------------------------------------------------------
-- shared crypto pipeline (the crypto dialogue, generalized over slots)
-- ---------------------------------------------------------------------------

-- | Resolve object key material from a snapshot (keys as raw
-- bytes; the driver interprets per recipe).
stdResolver :: Model -> KeyResolver
stdResolver m oid = KeyBytes <$> (keyBytesOf =<< Map.lookup oid (mObjects m))

-- | The staged output length for a classic slot, from live model
-- state (the recall length when a short buffer keeps the slot).
stagedLenFor :: SlotKind -> Model -> SessionId -> Maybe Word64
stagedLenFor kind m sid = do
  st <- lookupSession m sid
  active <- lookupSingle (ssOps st) kind
  staged <- stagedOf (commonOf active)
  pure (fromIntegral (BS.length (stBytes staged)))

-- | Plan-then-publish pipeline shared by every crypto call:
-- rejections publish their termination and report; Immediate
-- commits publish; Execute commits run the effect through the
-- instance backend with snapshot keys, finish against a fresh
-- snapshot, and publish. Returns the commit for output encoding,
-- or the CK_RV when there is nothing to encode.
runCryptoPlan :: StdInstance -> Model -> Request -> IO (Either CULong PreparedCommit)
runCryptoPlan inst m req = runCryptoPlanOn inst m (planCall (envRules (siEnv inst)) m req)

-- | The shared pipeline over an already-computed plan:
-- byte-carrying callers plan via 'planCall', decoded callers via
-- 'planDecoded'; everything downstream is identical.
runCryptoPlanOn :: StdInstance -> Model -> PlanResult -> IO (Either CULong PreparedCommit)
runCryptoPlanOn inst m planned = case planned of
  Reject rej -> do
    publishRejection inst rej
    pure (Left (stdRvOf (rejCode rej)))
  Immediate pc -> do
    pr <- publishCommit inst pc
    case pr of
      Left _ -> pure (Left ckrGeneralError)
      Right () -> pure (Right pc)
  Execute res (EffectCrypto fx) -> do
    crypto <- runEffect (siBackend inst) (stdResolver m) fx
    m2 <- snapshotModel (siEnv inst)
    case finishEffect (envRules (siEnv inst)) m2 res (encodeResult crypto) of
      Left rej -> do
        publishRejection inst rej
        pure (Left (stdRvOf (rejCode rej)))
      Right pc -> do
        pr <- publishCommit inst pc
        case pr of
          Left _ -> pure (Left ckrGeneralError)
          Right () -> pure (Right pc)

-- | Silent crypto dialogue (inits, updates): plan, publish, code.
-- Successful commits must be output-free (anything else fails
-- closed: these calls never produce bytes).
runCryptoSilent :: StdInstance -> Request -> IO CULong
runCryptoSilent inst req = do
  m <- snapshotModel (siEnv inst)
  epc <- runCryptoPlan inst m req
  encodeSilent epc

-- | Silent crypto dialogue over a decoded request:
-- identical to 'runCryptoSilent' past the plan step.
runCryptoSilentDecoded :: StdInstance -> DecodedRequest -> IO CULong
runCryptoSilentDecoded inst dreq = do
  m <- snapshotModel (siEnv inst)
  epc <- runCryptoPlanOn inst m (planDecoded (envRules (siEnv inst)) m dreq)
  encodeSilent epc

-- | Encode one silent dialogue outcome: byte-carrying and decoded
-- callers share this tail, so their codes agree by construction.
encodeSilent :: Either CULong PreparedCommit -> IO CULong
encodeSilent epc = case epc of
  Left rv -> pure rv
  Right pc
    | pcCode pc == CKR_OK && null (pcOutputs pc) -> pure ckrOk
    | pcCode pc == CKR_OK -> pure ckrGeneralError
    | otherwise -> pure (stdRvOf (pcCode pc))

-- | Encode a buffered one-shot/final commit: BUFFER_TOO_SMALL
-- with no outputs reports the staged length from live model
-- state (the slot stays for the recall); OK encodes the value
-- bytes into the caller buffer with their length; anything else
-- reports the code with caller buffers untouched.
encodeCryptoCommit
  :: StdInstance -> SessionId -> SlotKind -> Ptr Word8 -> Ptr CULong -> Word64
  -> PreparedCommit -> IO CULong
encodeCryptoCommit inst sid kind pOut pLen cap pc
  | pcCode pc == CKR_BUFFER_TOO_SMALL = case pcOutputs pc of
      [] -> do
        m <- snapshotModel (siEnv inst)
        case stagedLenFor kind m sid of
          Nothing -> pure ckrGeneralError
          Just n -> do
            _ <- encodeLength pLen n
            pure ckrBufferTooSmall
      _ -> pure ckrGeneralError
  | pcCode pc /= CKR_OK = pure (stdRvOf (pcCode pc))
  | otherwise = case traverse nativeToWrite (pcOutputs pc) of
      Nothing -> pure ckrGeneralError
      Just [] -> pure ckrGeneralError
      Just writes -> do
        let bufs = [BoundBuffer (twPath w) pOut cap | w <- writes]
        reps <- encodeWrites bufs writes
        if all ((== CKR_OK) . erCode) reps
          then do
            _ <- encodeLength pLen (sum (map erWritten reps))
            pure ckrOk
          else pure ckrGeneralError

-- | Report a size query: return the staged length with the slot
-- kept for the recall (a successful query does not terminate the
-- one-shot/final).
reportCryptoQuery :: StdInstance -> SessionId -> SlotKind -> Ptr CULong -> IO CULong
reportCryptoQuery inst sid kind pLen = do
  m <- snapshotModel (siEnv inst)
  case stagedLenFor kind m sid of
    Nothing -> pure ckrGeneralError
    Just n -> do
      _ <- encodeLength pLen n
      pure ckrOk

-- | Report a plan-level short buffer: re-read the staged length
-- from live model state (a short retry keeps the slot). No staging
-- means no retry was possible: fail closed.
reportShortLength :: StdInstance -> SessionId -> SlotKind -> Ptr CULong -> IO CULong
reportShortLength inst sid kind pLen = do
  m <- snapshotModel (siEnv inst)
  case stagedLenFor kind m sid of
    Nothing -> pure ckrGeneralError
    Just n -> do
      _ <- encodeLength pLen n
      pure ckrBufferTooSmall

-- | Buffered one-shot/final dialogue for a classic slot.
runCryptoBuffered
  :: StdInstance -> SessionId -> SlotKind -> FunctionId -> ByteString -> String
  -> Ptr Word8 -> Ptr CULong -> Word64 -> IO CULong
runCryptoBuffered inst sid kind func input regionName pOut pLen cap = do
  m <- snapshotModel (siEnv inst)
  let req = Request Pkcs11_3_2 func (Just sid) Nothing input
        [RegionBytes regionName (IntentBuffer cap)]
  epc <- runCryptoPlan inst m req
  case epc of
    Left rv
      | rv == ckrBufferTooSmall -> reportShortLength inst sid kind pLen
      | otherwise -> pure rv
    Right pc -> encodeCryptoCommit inst sid kind pOut pLen cap pc

-- | Size-query dialogue: run with the null intent so the
-- finisher stages (even an empty output), then report the staged
-- length with the slot kept for the recall.
runCryptoQuery
  :: StdInstance -> SessionId -> SlotKind -> FunctionId -> ByteString -> String
  -> Ptr CULong -> IO CULong
runCryptoQuery inst sid kind func input regionName pLen = do
  m <- snapshotModel (siEnv inst)
  let req = Request Pkcs11_3_2 func (Just sid) Nothing input
        [RegionBytes regionName IntentNull]
  epc <- runCryptoPlan inst m req
  case epc of
    Left rv
      | rv == ckrBufferTooSmall -> reportCryptoQuery inst sid kind pLen
      | otherwise -> pure rv
    Right pc
      | pcCode pc == CKR_BUFFER_TOO_SMALL -> reportCryptoQuery inst sid kind pLen
      | otherwise -> pure (stdRvOf (pcCode pc))

messageRegion :: MsgFamily -> String
messageRegion MsgEncrypt = "message-encrypt"
messageRegion MsgDecrypt = "message-decrypt"
messageRegion MsgSign = "message-sign"
messageRegion MsgVerify = "message-verify"

matchingMessageLength :: MsgFamily -> Model -> SessionId -> Maybe Word64
matchingMessageLength fam m sid = do
  st <- lookupSession m sid
  msg <- lookupMessage (ssOps st) (msgFamilyKind fam)
  if msFamily msg /= fam then Nothing else do
    staged <- stagedOf (msCommon msg)
    pure (fromIntegral (BS.length (stBytes staged)))

messageContinuation :: MsgFamily -> FunctionId -> ByteString -> Bool
messageContinuation fam func input = case (fam, func, decodeMsgNext fam input) of
  (MsgEncrypt, F_EncryptMessageNext, Just (MsgNextCipher _ _ False)) -> True
  (MsgDecrypt, F_DecryptMessageNext, Just (MsgNextCipher _ _ False)) -> True
  _ -> False

runMessageBuffered :: StdInstance -> SessionId -> MsgFamily -> FunctionId -> ByteString -> Ptr Word8 -> Ptr CULong -> Word64 -> IO CULong
runMessageBuffered inst sid fam func input pOut pLen cap = do
  m <- snapshotModel (siEnv inst)
  let kind = msgFamilyKind fam
      req = Request Pkcs11_3_2 func (Just sid) Nothing input
        [RegionBytes (messageRegion fam) (IntentBuffer cap)]
  result <- runCryptoPlan inst m req
  case result of
    Left rv
      | rv == ckrBufferTooSmall -> reportShortLength inst sid kind pLen
      | otherwise -> pure rv
    Right pc
      | pcCode pc == CKR_OK && null (pcOutputs pc) -> do
          _ <- encodeLength pLen 0
          pure ckrOk
      | otherwise -> encodeCryptoCommit inst sid kind pOut pLen cap pc

runMessageQuery :: StdInstance -> SessionId -> MsgFamily -> FunctionId -> ByteString -> Ptr CULong -> IO CULong
runMessageQuery inst sid fam func input pLen = do
  m <- snapshotModel (siEnv inst)
  let kind = msgFamilyKind fam
      req = Request Pkcs11_3_2 func (Just sid) Nothing input
        [RegionBytes (messageRegion fam) IntentNull]
      planned = planCall (envRules (siEnv inst)) m req
      report n = encodeLength pLen n >> pure ckrOk
      execute = do
        result <- runCryptoPlanOn inst m planned
        case result of
          Left rv
            | rv == ckrBufferTooSmall -> reportCryptoQuery inst sid kind pLen
            | otherwise -> pure rv
          Right pc
            | pcCode pc == CKR_BUFFER_TOO_SMALL -> reportCryptoQuery inst sid kind pLen
            | pcCode pc /= CKR_OK -> pure (stdRvOf (pcCode pc))
            | otherwise -> pure ckrGeneralError
  case planned of
    Reject _ -> execute
    Execute _ _ -> execute
    Immediate pc
      | pcCode pc /= CKR_OK -> pure (stdRvOf (pcCode pc))
      | Just n <- matchingMessageLength fam m sid -> report n
      | messageContinuation fam func input -> report 0
      | otherwise -> pure ckrGeneralError

messageBytes :: StdInstance -> SessionId -> MsgFamily -> FunctionId -> ByteString -> Ptr Word8 -> Ptr CULong -> IO CULong
messageBytes inst sid fam func frame pOut pLen
  | pLen == nullPtr = pure ckrArgsBad
  | pOut == nullPtr = runMessageQuery inst sid fam func frame pLen
  | otherwise = do
      cap <- fromIntegral <$> peek pLen
      runMessageBuffered inst sid fam func frame pOut pLen cap

-- | Resolve a session for the crypto dialogues (unknown handles
-- refuse exactly as planning would).
withStdSession :: StdInstance -> CULong -> (SessionId -> IO CULong) -> IO CULong
withStdSession inst (CULong h) k = do
  m <- snapshotModel (siEnv inst)
  case lookupSession m (SessionId (fromIntegral h)) of
    Nothing -> pure (stdRvOf CKR_SESSION_HANDLE_INVALID)
    Just st -> k (ssId st)

-- | Terminate one session op slot, if active. Shared by the
-- Haskell-side early refusals and the C NULL-argument guards (via
-- 'haskokiStdTerminateSlot'): input-decode failures never reach the
-- planner, but the spec terminates on every error other than
-- BUFFER_TOO_SMALL (only the successful length query keeps the
-- slot), so the FFI publishes the termination itself.
terminateSlot :: StdInstance -> SessionId -> SlotKind -> IO ()
terminateSlot inst sid kind = do
  when (kind == SlotDigest) (cancelStdAsyncBinding inst sid JobDigest)
  m <- snapshotModel (siEnv inst)
  case lookupSession m sid of
    Nothing -> pure ()
    Just st -> case lookupSingle (ssOps st) kind of
      Nothing -> pure ()
      Just _ -> do
        _ <- publishStd inst
          (StateDelta [DeltaSetSessionOps sid (removeSingle kind (ssOps st))])
        pure ()

-- | Refuse a crypto data call with ARGS_BAD after terminating the
-- session's active operation of this slot kind. With no active op
-- this is a plain refusal.
refuseArgsTerminate :: StdInstance -> SessionId -> SlotKind -> IO CULong
refuseArgsTerminate inst sid kind =
  terminateSlot inst sid kind >> pure ckrArgsBad

-- | Slot encoding shared with cbits/standard_surface.c
-- (HSK_SLOT_*): 0 digest, 1 sign, 2 verify, 3 encrypt, 4 decrypt.
decodeSlotKind :: Word64 -> Maybe SlotKind
decodeSlotKind 0 = Just SlotDigest
decodeSlotKind 1 = Just SlotSign
decodeSlotKind 2 = Just SlotVerify
decodeSlotKind 3 = Just SlotEncrypt
decodeSlotKind 4 = Just SlotDecrypt
decodeSlotKind _ = Nothing

foreign export ccall "haskoki_std_terminate_slot" haskokiStdTerminateSlot
  :: StablePtr StdInstance -> CULong -> CULong -> IO CULong

-- | Terminate one session op slot for the C NULL-argument guards
-- (unknown sessions and slot codes are silent no-ops). Always
-- reports OK: the caller already decided the refusal code.
haskokiStdTerminateSlot
  :: StablePtr StdInstance -> CULong -> CULong -> IO CULong
haskokiStdTerminateSlot ctx (CULong h) (CULong slot) =
  withStdCtx ctx $ \inst -> do
    case decodeSlotKind (fromIntegral slot) of
      Nothing -> pure ()
      Just kind -> terminateSlot inst (SessionId (fromIntegral h)) kind
    pure ckrOk

-- ---------------------------------------------------------------------------
-- digest
-- ---------------------------------------------------------------------------

-- Look at the borrowed view's live set before running a classic Digest plan.
-- This also permits a Haskell proof caller to finish its private worker before
-- the next classic operation, without consulting a possibly freed token.
withStdDigestIdle :: StdInstance -> SessionId -> IO CULong -> IO CULong
withStdDigestIdle inst sid action = do
  views <- readIORef (siAsyncViews inst)
  busy <- case Map.lookup sid views of
    Nothing -> pure False
    Just view -> do
      c <- deRefStablePtr view
      not . Set.null <$> readIORef (acLive c)
  if busy then pure (stdRvOf CKR_OPERATION_ACTIVE) else action

foreign export ccall "haskoki_std_digest_init" haskokiStdDigestInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> IO CULong
foreign export ccall "haskoki_std_digest" haskokiStdDigest
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_digest_update" haskokiStdDigestUpdate
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
foreign export ccall "haskoki_std_digest_final" haskokiStdDigestFinal
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong

-- | Initialize a digest operation (no key, no permits, no auth).
haskokiStdDigestInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> IO CULong
haskokiStdDigestInit ctx h (CULong mech) pParams (CULong paramsLen) =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    eParams <- decodeInputBytes pParams paramsLen
    case eParams of
      Left _ -> pure ckrArgsBad
      Right params -> withStdDigestIdle inst sid $ do
        let mid = MechanismId (fromIntegral mech)
            -- Decoded init arguments straight to the
            -- planner (no init frame to re-parse).
            dreq = DRInit sid InitDigest Nothing mid [] False params
        runCryptoSilentDecoded inst dreq

-- | Digest one-shot (init must precede it; size-query and
-- short-buffer recall per the shared dialogue).
haskokiStdDigest
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
haskokiStdDigest ctx h pData (CULong dataLen) pOut pLen =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    if pLen == nullPtr
      then refuseArgsTerminate inst sid SlotDigest
      else do
        eInput <- decodeInputBytes pData dataLen
        case eInput of
          Left _ -> refuseArgsTerminate inst sid SlotDigest
          Right input -> withStdDigestIdle inst sid $
            if pOut == nullPtr then runCryptoQuery inst sid SlotDigest F_Digest
                input "digest" pLen
            else do
                CULong cap <- peek pLen
                runStdDigestBuffered inst sid input pOut pLen cap

-- | Only a fresh fixed-width FxDigest execution with adequate caller storage
-- can become pending. Planner refusals, staged recalls, and short buffers all
-- use the existing synchronous publication/encoding dialogue.
runStdDigestBuffered
  :: StdInstance -> SessionId -> ByteString -> Ptr Word8 -> Ptr CULong
  -> Word64 -> IO CULong
runStdDigestBuffered inst sid input pOut pLen cap = do
  m <- snapshotModel (siEnv inst)
  let req = Request Pkcs11_3_2 F_Digest (Just sid) Nothing input
        [RegionBytes "digest" (IntentBuffer cap)]
      planned = planCall (envRules (siEnv inst)) m req
      synchronous = do
        epc <- runCryptoPlanOn inst m planned
        case epc of
          Left rv
            | rv == ckrBufferTooSmall -> reportShortLength inst sid SlotDigest pLen
            | otherwise -> pure rv
          Right pc -> encodeCryptoCommit inst sid SlotDigest pOut pLen cap pc
  case planned of
    Execute _ (EffectCrypto (FxDigest mech _))
      | Just recipe <- digestRecipeFor mech
      , cap >= fromIntegral (drOutLen recipe) -> do
          enabled <- isAsyncSession (siAsyncTable inst) sid
          if not enabled then synchronous else do
            views <- readIORef (siAsyncViews inst)
            case Map.lookup sid views of
              Nothing -> pure ckrGeneralError
              Just view -> do
                c <- deRefStablePtr view
                live <- readIORef (acLive c)
                if not (Set.null live)
                  then pure (stdRvOf CKR_OPERATION_ACTIVE)
                  else startStdDigest inst sid view input pOut (min cap maxOutputBytes)
    _ -> synchronous

-- | The worker copies the decoded input. Mask the handle-to-binding handoff;
-- if publication cannot finish, cancel through that same worker before unwind.
startStdDigest
  :: StdInstance -> SessionId -> StablePtr AsyncCtx -> ByteString
  -> Ptr Word8 -> Word64 -> IO CULong
startStdDigest inst sid view input pOut cap = mask_ $
  BS.useAsCStringLen input $ \(pInput, inputLen) -> alloca $ \pHandle -> do
    poke pHandle (castPtrToStablePtr nullPtr)
    rv <- haskokiAsyncStart view (CULong (fromIntegral (unSessionId sid))) 2
      (castPtr pInput) (fromIntegral inputLen) (CULong cap) 2 pHandle
    handle <- peek pHandle
    c <- deRefStablePtr view
    live <- readIORef (acLive c)
    let isLive = Set.member (castStablePtrToPtr handle) live
        cancel = when isLive $ do
          _ <- haskokiAsyncCancel view handle
          pure ()
    if rv /= stdRvOf CKR_PENDING
      then cancel >> pure rv
      else if not isLive
        then pure ckrGeneralError
        else (do
          bindings <- readIORef (siAsyncBindings inst)
          installed <- evaluate (Map.insert (sid, JobDigest)
            (StdAsyncBinding JobDigest handle pOut cap) bindings)
          writeIORef (siAsyncBindings inst) installed
          pure rv) `onException` cancel

-- | Digest multipart update.
haskokiStdDigestUpdate
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdDigestUpdate ctx h pData (CULong dataLen) =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    eInput <- decodeInputBytes pData dataLen
    case eInput of
      Left _ -> refuseArgsTerminate inst sid SlotDigest
      Right input -> withStdDigestIdle inst sid $ do
        let req = Request Pkcs11_3_2 F_DigestUpdate (Just sid) Nothing input []
        runCryptoSilent inst req

foreign export ccall "haskoki_std_digest_key" haskokiStdDigestKey
  :: StablePtr StdInstance -> CULong -> CULong -> IO CULong

-- | Digest the value of a secret key into the active digest
-- operation (spec 5.13.4: exactly as if the value had been passed
-- to C_DigestUpdate, so op-presence and termination match the
-- update path by construction). Unknown or invisible handles
-- refuse OBJECT_HANDLE_INVALID, non-secret keys
-- KEY_TYPE_INCONSISTENT; key-resolution refusals terminate the
-- active digest like every other error. Digesting never exposes
-- the value, so sensitivity/extractability do not gate it.
haskokiStdDigestKey
  :: StablePtr StdInstance -> CULong -> CULong -> IO CULong
haskokiStdDigestKey ctx h (CULong keyH) =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    m <- snapshotModel (siEnv inst)
    let refuse code = terminateSlot inst sid SlotDigest >> pure code
    case resolveHandle m (ExternalHandle (fromIntegral keyH)) of
      Nothing -> refuse (stdRvOf CKR_OBJECT_HANDLE_INVALID)
      Just ost -> case lookupSession m sid of
        Nothing -> pure (stdRvOf CKR_SESSION_HANDLE_INVALID)
        Just st
          | not (objectVisible st ost) ->
              refuse (stdRvOf CKR_OBJECT_HANDLE_INVALID)
          | Map.lookup AttrClass (osAttrs ost)
              /= Just (ValULong ckoSecretKey) ->
              refuse (stdRvOf CKR_KEY_TYPE_INCONSISTENT)
          | otherwise -> case keyBytesOf ost of
              Nothing -> refuse ckrGeneralError
              Just mat -> runCryptoSilent inst
                (Request Pkcs11_3_2 F_DigestUpdate (Just sid) Nothing mat [])

-- | Digest final (size-query and short-buffer recall per the
-- shared dialogue; a query completes the final).
haskokiStdDigestFinal
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdDigestFinal ctx h pOut pLen =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    if pLen == nullPtr
      then refuseArgsTerminate inst sid SlotDigest
      else withStdDigestIdle inst sid $
        if pOut == nullPtr
          then runCryptoQuery inst sid SlotDigest F_DigestFinal BS.empty
            "digest" pLen
          else do
            CULong cap <- peek pLen
            runCryptoBuffered inst sid SlotDigest F_DigestFinal BS.empty
              "digest" pOut pLen cap

-- ---------------------------------------------------------------------------
-- key generation
-- ---------------------------------------------------------------------------

foreign export ccall "haskoki_std_generate_key" haskokiStdGenerateKey
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> Ptr Word8 -> CULong -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_generate_key_pair" haskokiStdGenerateKeyPair
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> Ptr Word8 -> CULong -> Ptr CULong -> Ptr CULong -> IO CULong

-- | Publish one key-management 'PlanResult': rejections publish
-- their termination and report; Immediate commits publish and
-- their handle outputs decode; anything off-shape fails closed.
publishKeyResult :: StdInstance -> PlanResult -> IO (Either CULong [Word64])
publishKeyResult inst pr = case pr of
  Reject rej -> do
    publishRejection inst rej
    pure (Left (stdRvOf (rejCode rej)))
  Immediate pc -> do
    ePub <- publishCommit inst pc
    case ePub of
      Left _ -> pure (Left ckrGeneralError)
      Right () -> case decodeHandles (pcOutputs pc) of
        Nothing -> pure (Left ckrGeneralError)
        Just hs
          | pcCode pc == CKR_OK -> pure (Right hs)
          | otherwise -> pure (Left (stdRvOf (pcCode pc)))
  Execute _ _ -> pure (Left ckrGeneralError)

-- | Publish one key-plan result with full outputs (the
-- key-material path: handles plus IV bytes, which
-- 'decodeHandles' cannot carry).
publishKeyResultFull :: StdInstance -> PlanResult -> IO (Either CULong [NativeOutput])
publishKeyResultFull inst pr = case pr of
  Reject rej -> do
    publishRejection inst rej
    pure (Left (stdRvOf (rejCode rej)))
  Immediate pc -> do
    ePub <- publishCommit inst pc
    case ePub of
      Left _ -> pure (Left ckrGeneralError)
      Right ()
        | pcCode pc == CKR_OK -> pure (Right (pcOutputs pc))
        | otherwise -> pure (Left (stdRvOf (pcCode pc)))
  Execute _ _ -> pure (Left ckrGeneralError)

-- | Execute one key-management plan: denials report their code;
-- effects run through the instance backend with snapshot keys and
-- finish against a fresh snapshot; immediate commits publish.
-- Owner-aware read-only enforcement ('admitPending') refuses
-- token-object creation before any effect runs. Returns the
-- decoded handle outputs, or the CK_RV.
runKeyPlan
  :: StdInstance -> Model -> SessionState -> KeyPlan -> IO (Either CULong [Word64])
runKeyPlan inst m st kp = case kp of
  KeyDenied deny -> pure (Left (stdRvOf (kdCode deny)))
  KeyImmediate pr -> publishKeyResult inst pr
  -- Finisher-incoherent pairs refuse BEFORE any effect
  -- runs (same GENERAL_ERROR class as 'finishWork' internals).
  KeyEffect pw fx
    | not (keyPairCompatible pw fx) -> pure (Left (stdRvOf CKR_GENERAL_ERROR))
    | Left deny <- admitPending st pw -> pure (Left (stdRvOf (kdCode deny)))
    | otherwise -> do
    res <- runEffect (siBackend inst) (stdResolver m) fx
    m2 <- snapshotModel (siEnv inst)
    case finishWork m2 st pw res of
      Immediate pc -> publishKeyResult inst (Immediate pc)
      Reject rej -> publishKeyResult inst (Reject rej)
      Execute res' (EffectCrypto fx') -> do
        res2 <- runEffect (siBackend inst) (stdResolver m2) fx'
        m3 <- snapshotModel (siEnv inst)
        case finishEffect (envRules (siEnv inst)) m3 res' (encodeResult res2) of
          Left rej -> publishKeyResult inst (Reject rej)
          Right pc -> publishKeyResult inst (Immediate pc)

-- | Execute one key-management plan with full outputs (the
-- key-material path): the 'runKeyPlan' flow, returning the
-- native outputs instead of decoded handles.
runKeyPlanFull
  :: StdInstance -> Model -> SessionState -> KeyPlan -> IO (Either CULong [NativeOutput])
runKeyPlanFull inst m st kp = case kp of
  KeyDenied deny -> pure (Left (stdRvOf (kdCode deny)))
  KeyImmediate pr -> publishKeyResultFull inst pr
  KeyEffect pw fx
    | not (keyPairCompatible pw fx) -> pure (Left (stdRvOf CKR_GENERAL_ERROR))
    | Left deny <- admitPending st pw -> pure (Left (stdRvOf (kdCode deny)))
    | otherwise -> do
    res <- runEffect (siBackend inst) (stdResolver m) fx
    m2 <- snapshotModel (siEnv inst)
    case finishWork m2 st pw res of
      Immediate pc -> publishKeyResultFull inst (Immediate pc)
      Reject rej -> publishKeyResultFull inst (Reject rej)
      Execute res' (EffectCrypto fx') -> do
        res2 <- runEffect (siBackend inst) (stdResolver m2) fx'
        m3 <- snapshotModel (siEnv inst)
        case finishEffect (envRules (siEnv inst)) m3 res' (encodeResult res2) of
          Left rej -> publishKeyResultFull inst (Reject rej)
          Right pc -> publishKeyResultFull inst (Immediate pc)

-- | Publish one key-material result: handles into the ordered
-- slots, IV bytes into the sized buffers (zero-length IVs
-- write nothing), and an invalid primary when the caller
-- passed a handle slot (the trio returns no primary key).
-- Anything off-shape fails closed with zero partial writes
-- past the failing point (slots poke in order; a shape
-- mismatch refuses before any poke).
publishKeyMat :: KeyMatSlots -> [NativeOutput] -> Ptr CULong -> IO CULong
publishKeyMat slots outs phKey =
  case (mapM handleOf handleOuts, ivOf "iv-client", ivOf "iv-server") of
    (Just hs, Just ivC, Just ivS)
      | length hs == length (kmsHandles slots)
      , BS.length ivC == kmsIvCLen slots
      , BS.length ivS == kmsIvSLen slots -> do
          zipWithM_ poke (kmsHandles slots) (map CULong hs)
          pokeIv (kmsIvC slots) ivC
          pokeIv (kmsIvS slots) ivS
          when (phKey /= nullPtr) (poke phKey (CULong 0))
          pure ckrOk
    _ -> pure ckrGeneralError
  where
    handleOuts = [bs | NativeOutput (RegionHandle "key") bs <- outs]
    ivOf name = case [bs | NativeOutput (RegionBytes n _) bs <- outs, n == name] of
      [bs] -> Just bs
      [] -> Just BS.empty
      _ -> Nothing
    handleOf = beWord64
    pokeIv _ iv | BS.null iv = pure ()
    pokeIv ptr iv =
      BSU.unsafeUseAsCString iv $ \src ->
        copyBytes (castPtr ptr) src (BS.length iv)

-- | Resolve a session and run a key-path continuation with its
-- state (unknown handles refuse exactly as planning would).
-- Writability is owner-aware and enforced at the key-plan runner
-- ('admitPending'), which sees the pending objects; wrap creates
-- nothing and is ungated. Transport only, like 'requireSession'.
withSessionState
  :: StdInstance -> CULong -> (SessionState -> IO CULong) -> IO CULong
withSessionState inst (CULong h) k =
  withStdSession inst (CULong h) $ \sid -> do
    m <- snapshotModel (siEnv inst)
    case lookupSession m sid of
      Nothing -> pure (stdRvOf CKR_SESSION_HANDLE_INVALID)
      Just st -> k st

-- | Generate one secret key from a template frame. The
-- pre-master keygens take raw version bytes, PBKD2 takes the
-- native @CK_PKCS5_PBKD2_PARAMS2@ struct (normalized onto
-- @pbkd2-params\/2@ here; unmappable images pass through raw so
-- the recipe refusal is unchanged), and PBE takes the native
-- @CK_PBE_PARAMS@ struct (normalized onto @pbe-params\/1@
-- plus the caller IV slot, written on success only); the
-- planner refuses params on every other keygen.
haskokiStdGenerateKey
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> Ptr Word8 -> CULong -> Ptr CULong -> IO CULong
haskokiStdGenerateKey ctx h (CULong mech) pFrame (CULong frameLen)
    pParams (CULong paramsLen) phKey =
  withStdCtx ctx $ \inst ->
    if phKey == nullPtr
      then pure ckrArgsBad
      else withSessionState inst h $ \st -> do
        eTmpl <- readFrame pFrame (CULong frameLen)
        eParams <- decodeInputBytes pParams paramsLen
        case (eTmpl, eParams) of
          (Left ferr, _) -> pure (frameErrorRV ferr)
          (_, Left _) -> pure ckrArgsBad
          (Right entries, Right raw) -> do
            let mid = MechanismId (fromIntegral mech)
            (params, mIvSlot) <- case kdfRecipeFor mid of
              Just r | rkPbkd2 r ->
                (, Nothing) . fromMaybe raw <$> normalizePbkd2Params2 pParams paramsLen
              _ | Just r <- pbeRecipeFor mid -> do
                mPbe <- normalizePbeParamsMaybeIv pParams paramsLen
                pure $ case mPbe of
                  Just (b, slot) | pbeSlotOk (pbeKind r) slot -> (b, slot)
                  _ -> (raw, Nothing)
              _ -> pure (raw, Nothing)
            m <- snapshotModel (siEnv inst)
            case mIvSlot of
              Just slot -> do
                eOut <- runKeyPlanFull inst m st
                  (planGenerateKey (envRules (siEnv inst)) m st mid params entries)
                case eOut of
                  Left rv -> pure rv
                  Right outs -> publishPbeKey slot outs phKey
              Nothing -> do
                eHs <- runKeyPlan inst m st
                  (planGenerateKey (envRules (siEnv inst)) m st mid params entries)
                case eHs of
                  Left rv -> pure rv
                  Right [oh] -> do
                    poke phKey (CULong oh)
                    pure ckrOk
                  Right _ -> pure ckrGeneralError

-- | A PBE IV slot matches its row: IV rows require the
-- caller buffer, no-IV rows (RC4) require its absence.
-- Anything off-shape fails closed upstream (raw params).
pbeSlotOk :: PbeKind -> Maybe (Ptr Word8) -> Bool
pbeSlotOk kind (Just _) = pbeIvLen kind > 0
pbeSlotOk kind Nothing = pbeIvLen kind == 0

-- | Publish one PBE keygen result: the handle into the caller
-- slot and the 8 IV bytes into the params-embedded buffer.
-- Anything off-shape fails closed with zero partial writes.
publishPbeKey :: Ptr Word8 -> [NativeOutput] -> Ptr CULong -> IO CULong
publishPbeKey slot outs phKey =
  case (handles, ivs) of
    ([h], [iv]) | BS.length iv == 8 -> do
      poke phKey (CULong h)
      BSU.unsafeUseAsCString iv $ \src ->
        copyBytes (castPtr slot) src 8
      pure ckrOk
    _ -> pure ckrGeneralError
  where
    handles = [w | NativeOutput (RegionHandle "key") bs <- outs, Just w <- [beWord64 bs]]
    ivs = [bs | NativeOutput (RegionBytes n _) bs <- outs, n == "iv"]

-- | Generate a key pair from public/private template frames.
haskokiStdGenerateKeyPair
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> Ptr Word8 -> CULong -> Ptr CULong -> Ptr CULong -> IO CULong
haskokiStdGenerateKeyPair ctx h (CULong mech)
    pPubFrame (CULong pubLen) pPrivFrame (CULong privLen) phPub phPriv =
  withStdCtx ctx $ \inst ->
    if phPub == nullPtr || phPriv == nullPtr
      then pure ckrArgsBad
      else withSessionState inst h $ \st -> do
        ePub <- readFrame pPubFrame (CULong pubLen)
        case ePub of
          Left ferr -> pure (frameErrorRV ferr)
          Right pubT -> do
            ePriv <- readFrame pPrivFrame (CULong privLen)
            case ePriv of
              Left ferr -> pure (frameErrorRV ferr)
              Right privT -> do
                m <- snapshotModel (siEnv inst)
                eHs <- runKeyPlan inst m st
                  (planGenerateKeyPair (envRules (siEnv inst)) m st
                    (MechanismId (fromIntegral mech)) pubT privT)
                case eHs of
                  Left rv -> pure rv
                  Right [ohPub, ohPriv] -> do
                    poke phPub (CULong ohPub)
                    poke phPriv (CULong ohPriv)
                    pure ckrOk
                  Right _ -> pure ckrGeneralError

-- ---------------------------------------------------------------------------
-- sign/verify
-- ---------------------------------------------------------------------------

foreign export ccall "haskoki_std_sign_init" haskokiStdSignInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> IO CULong
foreign export ccall "haskoki_std_sign" haskokiStdSign
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_sign_update" haskokiStdSignUpdate
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
foreign export ccall "haskoki_std_sign_final" haskokiStdSignFinal
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_verify_init" haskokiStdVerifyInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> IO CULong
foreign export ccall "haskoki_std_verify" haskokiStdVerify
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> CULong -> IO CULong
foreign export ccall "haskoki_std_verify_update" haskokiStdVerifyUpdate
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
foreign export ccall "haskoki_std_verify_final" haskokiStdVerifyFinal
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong

-- | Shared keyed init: the key handle rides the decoded request
-- with the operation's own permit; the planner resolves
-- visibility, permits and auth.
runKeyedInit
  :: StdInstance -> SessionId -> InitFunction -> MechanismId
  -> ByteString -> Word64 -> IO CULong
runKeyedInit inst sid ifunc mid params key =
  -- Decoded init arguments straight to the planner (the
  -- permit derives from the same init tag — never supplied twice).
  let dreq = DRInit sid ifunc (Just (ExternalHandle (fromIntegral key)))
        mid [initOperation ifunc] False params
  in runCryptoSilentDecoded inst dreq

-- | Shared keyed-init intake: copy the parameter block, normalize
-- caller-native mechanism structs into the recipe canonical codecs
-- ('normalizeMechParams'), and plan.
runKeyedInitParams
  :: StdInstance -> SessionId -> InitFunction -> CULong
  -> Ptr Word8 -> CULong -> CULong -> IO CULong
runKeyedInitParams inst sid ifunc (CULong mech) pParams (CULong paramsLen) (CULong key) = do
  eParams <- decodeInputBytes pParams paramsLen
  case eParams of
    Left _ -> pure ckrArgsBad
    Right raw -> do
      let mid = MechanismId (fromIntegral mech)
      params <- normalizeMechParams mid pParams paramsLen raw
      runKeyedInit inst sid ifunc mid params key

-- | Initialize a sign operation over one key.
haskokiStdSignInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> IO CULong
haskokiStdSignInit ctx h mech pParams paramsLen key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    runKeyedInitParams inst sid InitSign mech pParams paramsLen key

-- | Sign one-shot (size-query and short-buffer recall per the
-- shared dialogue).
haskokiStdSign
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
haskokiStdSign ctx h pData (CULong dataLen) pSig pLen =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    if pLen == nullPtr
      then refuseArgsTerminate inst sid SlotSign
      else do
        eInput <- decodeInputBytes pData dataLen
        case eInput of
          Left _ -> refuseArgsTerminate inst sid SlotSign
          Right input
            | pSig == nullPtr -> runCryptoQuery inst sid SlotSign F_Sign
                input "sign" pLen
            | otherwise -> do
                CULong cap <- peek pLen
                runCryptoBuffered inst sid SlotSign F_Sign input "sign"
                  pSig pLen cap

-- | Sign multipart update.
haskokiStdSignUpdate
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdSignUpdate ctx h pData (CULong dataLen) =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    eInput <- decodeInputBytes pData dataLen
    case eInput of
      Left _ -> refuseArgsTerminate inst sid SlotSign
      Right input -> do
        let req = Request Pkcs11_3_2 F_SignUpdate (Just sid) Nothing input []
        runCryptoSilent inst req

-- | Sign final (size-query and short-buffer recall per the shared
-- dialogue).
haskokiStdSignFinal
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdSignFinal ctx h pSig pLen =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    if pLen == nullPtr
      then refuseArgsTerminate inst sid SlotSign
      else
        if pSig == nullPtr
          then runCryptoQuery inst sid SlotSign F_SignFinal BS.empty
            "sign" pLen
          else do
            CULong cap <- peek pLen
            runCryptoBuffered inst sid SlotSign F_SignFinal BS.empty
              "sign" pSig pLen cap

-- | Initialize a verify operation over one key.
haskokiStdVerifyInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> IO CULong
haskokiStdVerifyInit ctx h mech pParams paramsLen key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    runKeyedInitParams inst sid InitVerify mech pParams paramsLen key

-- | Verify one-shot: data plus the candidate signature frame one
-- input; the verdict is the code (verdicts carry no bytes).
haskokiStdVerify
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> CULong -> IO CULong
haskokiStdVerify ctx h pData (CULong dataLen) pSig (CULong sigLen) =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    eData <- decodeInputBytes pData dataLen
    case eData of
      Left _ -> refuseArgsTerminate inst sid SlotVerify
      Right dat -> do
        eSig <- decodeInputBytes pSig sigLen
        case eSig of
          Left _ -> refuseArgsTerminate inst sid SlotVerify
          Right sig -> do
            let req = Request Pkcs11_3_2 F_Verify (Just sid) Nothing
                  (encodeVerifyInput dat sig)
                  [RegionBytes "verify" (IntentBuffer 0)]
            runCryptoSilent inst req

-- | Verify multipart update.
haskokiStdVerifyUpdate
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdVerifyUpdate ctx h pData (CULong dataLen) =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    eInput <- decodeInputBytes pData dataLen
    case eInput of
      Left _ -> refuseArgsTerminate inst sid SlotVerify
      Right input -> do
        let req = Request Pkcs11_3_2 F_VerifyUpdate (Just sid) Nothing input []
        runCryptoSilent inst req

-- | Verify final: the candidate signature is the whole input; the
-- verdict is the code.
haskokiStdVerifyFinal
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdVerifyFinal ctx h pSig (CULong sigLen) =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    eSig <- decodeInputBytes pSig sigLen
    case eSig of
      Left _ -> refuseArgsTerminate inst sid SlotVerify
      Right sig -> do
        let req = Request Pkcs11_3_2 F_VerifyFinal (Just sid) Nothing sig
              [RegionBytes "verify" (IntentBuffer 0)]
        runCryptoSilent inst req

-- ---------------------------------------------------------------------------
-- message operations
-- ---------------------------------------------------------------------------

foreign export ccall "haskoki_std_message_encrypt_init" haskokiStdMessageEncryptInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageEncryptInit :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageEncryptInit ctx h mech p pn key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageInitFrame MsgEncrypt mech p (fromIntegral pn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_MessageEncryptInit (Just sid)
          (Just (ExternalHandle (fromIntegral key))) input [])

foreign export ccall "haskoki_std_message_encrypt" haskokiStdMessageEncrypt
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageEncrypt :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageEncrypt ctx h p pn a an d dn out len =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageCipherFrame MsgEncrypt p (fromIntegral pn) a (fromIntegral an) d (fromIntegral dn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> messageBytes inst sid MsgEncrypt F_EncryptMessage input out len

foreign export ccall "haskoki_std_message_encrypt_begin" haskokiStdMessageEncryptBegin
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageEncryptBegin :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageEncryptBegin ctx h p pn a an =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageBeginFrame MsgEncrypt p (fromIntegral pn) a (fromIntegral an)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_EncryptMessageBegin (Just sid) Nothing input [])

foreign export ccall "haskoki_std_message_encrypt_next" haskokiStdMessageEncryptNext
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> CULong -> IO CULong
haskokiStdMessageEncryptNext :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> CULong -> IO CULong
haskokiStdMessageEncryptNext ctx h p pn d dn out len end =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    if end /= 0 && end /= 1 then pure ckrArgsBad else do
      frame <- decodeMessageCipherNextFrame MsgEncrypt p (fromIntegral pn) d (fromIntegral dn) (end == 1)
      case frame of
        Left _ -> pure ckrArgsBad
        Right input -> messageBytes inst sid MsgEncrypt F_EncryptMessageNext input out len

foreign export ccall "haskoki_std_message_encrypt_final" haskokiStdMessageEncryptFinal
  :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageEncryptFinal :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageEncryptFinal ctx h =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    runCryptoSilent inst
      (Request Pkcs11_3_2 F_MessageEncryptFinal (Just sid) Nothing BS.empty [])

foreign export ccall "haskoki_std_message_decrypt_init" haskokiStdMessageDecryptInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageDecryptInit :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageDecryptInit ctx h mech p pn key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageInitFrame MsgDecrypt mech p (fromIntegral pn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_MessageDecryptInit (Just sid)
          (Just (ExternalHandle (fromIntegral key))) input [])

foreign export ccall "haskoki_std_message_decrypt" haskokiStdMessageDecrypt
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageDecrypt :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageDecrypt ctx h p pn a an d dn out len =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageCipherFrame MsgDecrypt p (fromIntegral pn) a (fromIntegral an) d (fromIntegral dn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> messageBytes inst sid MsgDecrypt F_DecryptMessage input out len

foreign export ccall "haskoki_std_message_decrypt_begin" haskokiStdMessageDecryptBegin
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageDecryptBegin :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageDecryptBegin ctx h p pn a an =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageBeginFrame MsgDecrypt p (fromIntegral pn) a (fromIntegral an)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_DecryptMessageBegin (Just sid) Nothing input [])

foreign export ccall "haskoki_std_message_decrypt_next" haskokiStdMessageDecryptNext
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> CULong -> IO CULong
haskokiStdMessageDecryptNext :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> CULong -> IO CULong
haskokiStdMessageDecryptNext ctx h p pn d dn out len end =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    if end /= 0 && end /= 1 then pure ckrArgsBad else do
      frame <- decodeMessageCipherNextFrame MsgDecrypt p (fromIntegral pn) d (fromIntegral dn) (end == 1)
      case frame of
        Left _ -> pure ckrArgsBad
        Right input -> messageBytes inst sid MsgDecrypt F_DecryptMessageNext input out len

foreign export ccall "haskoki_std_message_decrypt_final" haskokiStdMessageDecryptFinal
  :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageDecryptFinal :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageDecryptFinal ctx h =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    runCryptoSilent inst
      (Request Pkcs11_3_2 F_MessageDecryptFinal (Just sid) Nothing BS.empty [])

foreign export ccall "haskoki_std_message_sign_init" haskokiStdMessageSignInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageSignInit :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageSignInit ctx h mech p pn key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageInitFrame MsgSign mech p (fromIntegral pn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_MessageSignInit (Just sid)
          (Just (ExternalHandle (fromIntegral key))) input [])

foreign export ccall "haskoki_std_message_sign" haskokiStdMessageSign
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageSign :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageSign ctx h p pn d dn out len =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageSignFrame p (fromIntegral pn) d (fromIntegral dn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> messageBytes inst sid MsgSign F_SignMessage input out len

foreign export ccall "haskoki_std_message_sign_begin" haskokiStdMessageSignBegin
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageSignBegin :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageSignBegin ctx h p pn =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageBeginFrame MsgSign p (fromIntegral pn) nullPtr 0
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_SignMessageBegin (Just sid) Nothing input [])

foreign export ccall "haskoki_std_message_sign_next" haskokiStdMessageSignNext
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageSignNext :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageSignNext ctx h p pn d dn out len =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageSignNextFrame p (fromIntegral pn) d (fromIntegral dn) (len /= nullPtr)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input
        | len == nullPtr -> runCryptoSilent inst
            (Request Pkcs11_3_2 F_SignMessageNext (Just sid) Nothing input
              [RegionBytes "message-sign" (IntentBuffer 0)])
        | otherwise -> messageBytes inst sid MsgSign F_SignMessageNext input out len

foreign export ccall "haskoki_std_message_sign_final" haskokiStdMessageSignFinal
  :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageSignFinal :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageSignFinal ctx h =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    runCryptoSilent inst
      (Request Pkcs11_3_2 F_MessageSignFinal (Just sid) Nothing BS.empty [])

foreign export ccall "haskoki_std_message_verify_init" haskokiStdMessageVerifyInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageVerifyInit :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageVerifyInit ctx h mech p pn key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageInitFrame MsgVerify mech p (fromIntegral pn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_MessageVerifyInit (Just sid)
          (Just (ExternalHandle (fromIntegral key))) input [])

foreign export ccall "haskoki_std_message_verify" haskokiStdMessageVerify
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerify :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerify ctx h p pn d dn out wn =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageVerifyFrame p (fromIntegral pn) d (fromIntegral dn) out (fromIntegral wn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst (Request Pkcs11_3_2 F_VerifyMessage (Just sid) Nothing input [RegionBytes "message-verify" (IntentBuffer 0)])

foreign export ccall "haskoki_std_message_verify_begin" haskokiStdMessageVerifyBegin
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerifyBegin :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerifyBegin ctx h p pn =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageBeginFrame MsgVerify p (fromIntegral pn) nullPtr 0
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_VerifyMessageBegin (Just sid) Nothing input [])

foreign export ccall "haskoki_std_message_verify_next" haskokiStdMessageVerifyNext
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerifyNext :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerifyNext ctx h p pn d dn out wn =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageVerifyNextFrame p (fromIntegral pn) d (fromIntegral dn) out (fromIntegral wn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_VerifyMessageNext (Just sid) Nothing input
          [RegionBytes "message-verify" (IntentBuffer 0)])

foreign export ccall "haskoki_std_message_verify_final" haskokiStdMessageVerifyFinal
  :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageVerifyFinal :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageVerifyFinal ctx h =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    runCryptoSilent inst
      (Request Pkcs11_3_2 F_MessageVerifyFinal (Just sid) Nothing BS.empty [])

-- ---------------------------------------------------------------------------
-- encrypt/decrypt
-- ---------------------------------------------------------------------------

foreign export ccall "haskoki_std_encrypt_init" haskokiStdEncryptInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> IO CULong
foreign export ccall "haskoki_std_encrypt" haskokiStdEncrypt
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_encrypt_update" haskokiStdEncryptUpdate
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_encrypt_final" haskokiStdEncryptFinal
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_decrypt_init" haskokiStdDecryptInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> IO CULong
foreign export ccall "haskoki_std_decrypt" haskokiStdDecrypt
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_decrypt_update" haskokiStdDecryptUpdate
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_decrypt_final" haskokiStdDecryptFinal
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong

-- | Cipher-update dialogue: stream the releasable prefix, or buffer
-- when nothing releases (zero bytes out). A short buffer refuses
-- with the re-derived streamable length; the planner changed no
-- state, so the caller repeats the same part with room.
runCryptoUpdateBuffered
  :: StdInstance -> SessionId -> SlotKind -> FunctionId -> ByteString -> String
  -> Ptr Word8 -> Ptr CULong -> Word64 -> IO CULong
runCryptoUpdateBuffered inst sid kind func input regionName pOut pLen cap = do
  m <- snapshotModel (siEnv inst)
  let req = Request Pkcs11_3_2 func (Just sid) Nothing input
        [RegionBytes regionName (IntentBuffer cap)]
  epc <- runCryptoPlan inst m req
  case epc of
    Left rv
      | rv == ckrBufferTooSmall -> reportUpdateShortLength inst sid kind input pLen
      | otherwise -> pure rv
    Right pc
      | pcCode pc == CKR_OK && null (pcOutputs pc) -> do
          _ <- encodeLength pLen 0
          pure ckrOk
      | otherwise -> encodeCryptoCommit inst sid kind pOut pLen cap pc

-- | Report an update short-buffer length: re-derive the planner's
-- own split from the live slot (the SMALL rejection changed no
-- state, so the slot still holds the pre-call buffer).
reportUpdateShortLength
  :: StdInstance -> SessionId -> SlotKind -> ByteString -> Ptr CULong -> IO CULong
reportUpdateShortLength inst sid kind part pLen = do
  m <- snapshotModel (siEnv inst)
  case lookupSession m sid >>= \st -> lookupSingle (ssOps st) kind of
    Just active -> case activeCipher active of
      Just (dir, sc, spec) -> do
        let total = BS.length (bufferedOf sc) + BS.length part
            (streamable, _) = cipherUpdateSplit (commonMech sc) spec dir total
        _ <- encodeLength pLen (fromIntegral streamable)
        pure ckrBufferTooSmall
      Nothing -> pure ckrGeneralError
    Nothing -> pure ckrGeneralError

-- | Update size-query dialogue: dry-run the planner and report the
-- streamable length WITHOUT committing or executing anything (no
-- append, no gate spend, no crypto). Rejections (missing slot,
-- bound violation) publish and report exactly as the real call.
runCryptoUpdateQuery
  :: StdInstance -> SessionId -> SlotKind -> FunctionId -> ByteString -> String
  -> Ptr CULong -> IO CULong
runCryptoUpdateQuery inst sid _kind func input regionName pLen = do
  m <- snapshotModel (siEnv inst)
  let req = Request Pkcs11_3_2 func (Just sid) Nothing input
        [RegionBytes regionName IntentNull]
  case planCall (envRules (siEnv inst)) m req of
    Reject rej -> do
      publishRejection inst rej
      pure (stdRvOf (rejCode rej))
    Immediate _ -> do
      _ <- encodeLength pLen 0
      pure ckrOk
    Execute _ (EffectCrypto fx) -> case fx of
      FxCipher _ _ _ _ effectInput -> do
        _ <- encodeLength pLen (fromIntegral (BS.length effectInput))
        pure ckrOk
      _ -> pure ckrGeneralError

-- | Initialize an encrypt operation over one key.
haskokiStdEncryptInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> IO CULong
haskokiStdEncryptInit ctx h mech pParams paramsLen key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    runKeyedInitParams inst sid InitEncrypt mech pParams paramsLen key

-- | Encrypt one-shot (size-query and short-buffer recall per the
-- shared dialogue).
haskokiStdEncrypt
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
haskokiStdEncrypt ctx h pData (CULong dataLen) pOut pLen =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    if pLen == nullPtr
      then refuseArgsTerminate inst sid SlotEncrypt
      else do
        eInput <- decodeInputBytes pData dataLen
        case eInput of
          Left _ -> refuseArgsTerminate inst sid SlotEncrypt
          Right input
            | pOut == nullPtr -> runCryptoQuery inst sid SlotEncrypt F_Encrypt
                input "encrypt" pLen
            | otherwise -> do
                CULong cap <- peek pLen
                runCryptoBuffered inst sid SlotEncrypt F_Encrypt input "encrypt"
                  pOut pLen cap

-- | Encrypt multipart update (streams releasable blocks; retains
-- the suffix; short buffers refuse without consuming).
haskokiStdEncryptUpdate
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
haskokiStdEncryptUpdate ctx h pPart (CULong partLen) pOut pLen =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    if pLen == nullPtr
      then refuseArgsTerminate inst sid SlotEncrypt
      else do
        eInput <- decodeInputBytes pPart partLen
        case eInput of
          Left _ -> refuseArgsTerminate inst sid SlotEncrypt
          Right input
            | pOut == nullPtr -> runCryptoUpdateQuery inst sid SlotEncrypt
                F_EncryptUpdate input "encrypt" pLen
            | otherwise -> do
                CULong cap <- peek pLen
                runCryptoUpdateBuffered inst sid SlotEncrypt F_EncryptUpdate
                  input "encrypt" pOut pLen cap

-- | Encrypt final (size-query and short-buffer recall per the
-- shared dialogue).
haskokiStdEncryptFinal
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdEncryptFinal ctx h pOut pLen =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    if pLen == nullPtr
      then refuseArgsTerminate inst sid SlotEncrypt
      else
        if pOut == nullPtr
          then runCryptoQuery inst sid SlotEncrypt F_EncryptFinal BS.empty
            "encrypt" pLen
          else do
            CULong cap <- peek pLen
            runCryptoBuffered inst sid SlotEncrypt F_EncryptFinal BS.empty
              "encrypt" pOut pLen cap

-- | Initialize a decrypt operation over one key.
haskokiStdDecryptInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> IO CULong
haskokiStdDecryptInit ctx h mech pParams paramsLen key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    runKeyedInitParams inst sid InitDecrypt mech pParams paramsLen key

-- | Decrypt one-shot (size-query and short-buffer recall per the
-- shared dialogue).
haskokiStdDecrypt
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
haskokiStdDecrypt ctx h pData (CULong dataLen) pOut pLen =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    if pLen == nullPtr
      then refuseArgsTerminate inst sid SlotDecrypt
      else do
        eInput <- decodeInputBytes pData dataLen
        case eInput of
          Left _ -> refuseArgsTerminate inst sid SlotDecrypt
          Right input
            | pOut == nullPtr -> runCryptoQuery inst sid SlotDecrypt F_Decrypt
                input "decrypt" pLen
            | otherwise -> do
                CULong cap <- peek pLen
                runCryptoBuffered inst sid SlotDecrypt F_Decrypt input "decrypt"
                  pOut pLen cap

-- | Decrypt multipart update (streams releasable blocks; retains
-- the suffix; short buffers refuse without consuming).
haskokiStdDecryptUpdate
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8
  -> Ptr CULong -> IO CULong
haskokiStdDecryptUpdate ctx h pPart (CULong partLen) pOut pLen =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    if pLen == nullPtr
      then refuseArgsTerminate inst sid SlotDecrypt
      else do
        eInput <- decodeInputBytes pPart partLen
        case eInput of
          Left _ -> refuseArgsTerminate inst sid SlotDecrypt
          Right input
            | pOut == nullPtr -> runCryptoUpdateQuery inst sid SlotDecrypt
                F_DecryptUpdate input "decrypt" pLen
            | otherwise -> do
                CULong cap <- peek pLen
                runCryptoUpdateBuffered inst sid SlotDecrypt F_DecryptUpdate
                  input "decrypt" pOut pLen cap

-- | Decrypt final (size-query and short-buffer recall per the
-- shared dialogue).
haskokiStdDecryptFinal
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdDecryptFinal ctx h pOut pLen =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid ->
    if pLen == nullPtr
      then refuseArgsTerminate inst sid SlotDecrypt
      else
        if pOut == nullPtr
          then runCryptoQuery inst sid SlotDecrypt F_DecryptFinal BS.empty
            "decrypt" pLen
          else do
            CULong cap <- peek pLen
            runCryptoBuffered inst sid SlotDecrypt F_DecryptFinal BS.empty
              "decrypt" pOut pLen cap

-- ---------------------------------------------------------------------------
-- random
-- ---------------------------------------------------------------------------

foreign export ccall "haskoki_std_generate_random" haskokiStdGenerateRandom
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong

-- | Fill the caller buffer with backend random bytes. Session
-- validity is the only model check (no state changes); a zero
-- length is a vacuous OK. Lengths past 'generateRandomMaxBytes'
-- refuse with @DATA_LEN_RANGE@ before any allocation: the backend
-- would otherwise try to materialize the full request (the
-- oracle's 4 GiB probe OOM-killed the process pre-bound).
haskokiStdGenerateRandom
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdGenerateRandom ctx h pOut (CULong len) =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \_ ->
    if pOut == nullPtr
      then pure ckrArgsBad
      else
        if len == 0
          then pure ckrOk
          else
            if len > fromIntegral generateRandomMaxBytes
              then pure (stdRvOf CKR_DATA_LEN_RANGE)
              else do
                eBs <- randomBytes (siBackend inst) (fromIntegral len)
                case eBs of
                  EngineFail _ -> pure ckrGeneralError
                  EngineOk bs
                    | BS.length bs /= fromIntegral len -> pure ckrGeneralError
                    | otherwise -> do
                        BSU.unsafeUseAsCString bs $ \src ->
                          copyBytes (castPtr pOut) src (fromIntegral len)
                        pure ckrOk

foreign export ccall "haskoki_std_seed_random" haskokiStdSeedRandom
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong

-- | Mix caller seed bytes into the backend RNG. Session
-- validity is the only model check (no state changes) and runs
-- FIRST; a zero length is a vacuous OK (NULL allowed); NULL with a
-- nonzero length is ARGS_BAD. Oversize seeds refuse with ARGS_BAD
-- BEFORE the caller buffer is copied (copying first would let one
-- call amplify into gigabytes of allocator pressure); backend bad
-- params stay ARGS_BAD; anything else fails closed as GENERAL_ERROR.
haskokiStdSeedRandom
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdSeedRandom ctx h pSeed (CULong len) =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \_ ->
    if pSeed == nullPtr && len /= 0
      then pure ckrArgsBad
      else
        if len == 0
          then pure ckrOk
          else
            if len > fromIntegral seedRandomMaxBytes
              then pure ckrArgsBad
              else do
                seed <- BS.packCStringLen (castPtr pSeed, fromIntegral len)
                eRes <- seedRandom (siBackend inst) seed
                case eRes of
                  EngineFail (BackendBadParam _ _) -> pure ckrArgsBad
                  EngineFail _ -> pure ckrGeneralError
                  EngineOk () -> pure ckrOk

-- ---------------------------------------------------------------------------
-- encapsulate/decapsulate
-- ---------------------------------------------------------------------------

foreign export ccall "haskoki_std_encapsulate_key" haskokiStdEncapsulateKey
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_decapsulate_key" haskokiStdDecapsulateKey
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr CULong -> IO CULong

-- | Publish one encapsulate-plan result: the query and
-- short-buffer legs report the ciphertext length (no key
-- created); a sufficient buffer lands the ciphertext bytes
-- plus exactly one secret handle. Anything off-shape fails
-- closed.
publishEncapsResult
  :: StdInstance -> PlanResult -> Ptr Word8 -> Ptr CULong -> Ptr CULong -> IO CULong
publishEncapsResult inst pr pOut pLen phKey = case pr of
  Reject rej -> do
    publishRejection inst rej
    case rejCode rej of
      CKR_BUFFER_TOO_SMALL -> pokeLenOut (rejOutputs rej) pLen
        (stdRvOf CKR_BUFFER_TOO_SMALL)
      _ -> pure (stdRvOf (rejCode rej))
  Immediate pc -> do
    ePub <- publishCommit inst pc
    case ePub of
      Left _ -> pure ckrGeneralError
      Right ()
        | pcCode pc /= CKR_OK -> pure (stdRvOf (pcCode pc))
        | pOut == nullPtr -> pokeLenOut (pcOutputs pc) pLen ckrOk
        | otherwise -> case pcOutputs pc of
            [NativeOutput (RegionBytes "ciphertext" _) ct, hout] ->
              case decodeHandles [hout] of
                Just [w] -> do
                  BSU.unsafeUseAsCString ct $ \src ->
                    copyBytes (castPtr pOut) src (BS.length ct)
                  poke pLen (CULong (fromIntegral (BS.length ct)))
                  poke phKey (CULong w)
                  pure ckrOk
                _ -> pure ckrGeneralError
            _ -> pure ckrGeneralError
  Execute _ _ -> pure ckrGeneralError

-- | Execute one encapsulate plan through the instance backend.
runEncapsPlan
  :: StdInstance -> Model -> SessionState -> KeyPlan
  -> Ptr Word8 -> Ptr CULong -> Ptr CULong -> IO CULong
runEncapsPlan inst m st kp pOut pLen phKey = case kp of
  KeyDenied deny -> pure (stdRvOf (kdCode deny))
  KeyImmediate pr -> publishEncapsResult inst pr pOut pLen phKey
  -- Finisher-incoherent pairs refuse BEFORE any effect runs.
  KeyEffect pw fx
    | not (keyPairCompatible pw fx) -> pure (stdRvOf CKR_GENERAL_ERROR)
    | Left deny <- admitPending st pw -> pure (stdRvOf (kdCode deny))
    | otherwise -> do
    res <- runEffect (siBackend inst) (stdResolver m) fx
    m2 <- snapshotModel (siEnv inst)
    publishEncapsResult inst (finishWork m2 st pw res) pOut pLen phKey

-- | Encapsulate to a KEM public key: @CKM_ML_KEM@ takes no
-- mechanism parameters (anything non-empty is
-- @CKR_MECHANISM_PARAM_INVALID@); the set resolves from the
-- peer key's parameter tag. A NULL out-buffer queries the
-- ciphertext length, a short buffer reports it with
-- @CKR_BUFFER_TOO_SMALL@ (neither creates a key), and a
-- sufficient buffer lands the ciphertext plus one secret.
haskokiStdEncapsulateKey
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> Ptr CULong -> IO CULong
haskokiStdEncapsulateKey ctx h (CULong mech) pParams (CULong paramsLen)
    (CULong keyH) pFrame (CULong frameLen) pOut pLen phKey =
  withStdCtx ctx $ \inst ->
    if pLen == nullPtr || phKey == nullPtr
      then pure ckrArgsBad
      else withSessionState inst h $ \st -> do
        eParams <- decodeInputBytes pParams paramsLen
        case eParams of
          Left _ -> pure ckrArgsBad
          Right raw
            | not (BS.null raw) -> pure (stdRvOf CKR_MECHANISM_PARAM_INVALID)
            | otherwise -> do
                eTmpl <- readFrame pFrame (CULong frameLen)
                case eTmpl of
                  Left ferr -> pure (frameErrorRV ferr)
                  Right entries -> do
                    CULong cap <- peek pLen
                    let intent = if pOut == nullPtr then IntentNull
                                 else IntentBuffer (fromIntegral cap)
                        mid = MechanismId (fromIntegral mech)
                        kh = ExternalHandle (fromIntegral keyH)
                    m <- snapshotModel (siEnv inst)
                    runEncapsPlan inst m st
                      (planKemEncaps m st mid kh (kemAlgOfKey m kh) entries intent)
                      pOut pLen phKey

-- | Decapsulate with a KEM private key: the parameter rule
-- matches encapsulate; the ciphertext is the whole input and
-- the answer is exactly one secret handle.
haskokiStdDecapsulateKey
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr CULong -> IO CULong
haskokiStdDecapsulateKey ctx h (CULong mech) pParams (CULong paramsLen)
    (CULong keyH) pCt (CULong ctLen) pFrame (CULong frameLen) phKey =
  withStdCtx ctx $ \inst ->
    if phKey == nullPtr
      then pure ckrArgsBad
      else withSessionState inst h $ \st -> do
        eParams <- decodeInputBytes pParams paramsLen
        case eParams of
          Left _ -> pure ckrArgsBad
          Right raw
            | not (BS.null raw) -> pure (stdRvOf CKR_MECHANISM_PARAM_INVALID)
            | otherwise -> do
                eCt <- decodeInputBytes pCt ctLen
                case eCt of
                  Left _ -> pure ckrArgsBad
                  Right ct -> do
                    eTmpl <- readFrame pFrame (CULong frameLen)
                    case eTmpl of
                      Left ferr -> pure (frameErrorRV ferr)
                      Right entries -> do
                        let mid = MechanismId (fromIntegral mech)
                            kh = ExternalHandle (fromIntegral keyH)
                        m <- snapshotModel (siEnv inst)
                        eHs <- runKeyPlan inst m st
                          (planKemDecaps m st mid kh (kemAlgOfKey m kh) ct entries)
                        case eHs of
                          Left rv -> pure rv
                          Right [oh] -> poke phKey (CULong oh) >> pure ckrOk
                          Right _ -> pure ckrGeneralError

-- ---------------------------------------------------------------------------
-- wrap/unwrap/derive
-- ---------------------------------------------------------------------------

foreign export ccall "haskoki_std_wrap_key" haskokiStdWrapKey
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_unwrap_key" haskokiStdUnwrapKey
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_derive_hkdf" haskokiStdDeriveHkdf
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> Ptr Word8 -> CULong -> CULong -> CULong -> CULong
  -> Ptr Word8 -> CULong -> Ptr CULong -> IO CULong
foreign export ccall "haskoki_std_derive_opaque" haskokiStdDeriveOpaque
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> Ptr Word8 -> CULong -> Ptr CULong -> IO CULong

-- | Copy one blob output to the caller buffer and report its
-- length. Anything off-shape fails closed.
pokeBlob :: [NativeOutput] -> Ptr Word8 -> Ptr CULong -> IO CULong
pokeBlob [NativeOutput _ bs] pOut pLen
  | pOut == nullPtr = pure ckrGeneralError
  | otherwise = do
      BSU.unsafeUseAsCString bs $ \src ->
        copyBytes (castPtr pOut) src (BS.length bs)
      poke pLen (CULong (fromIntegral (BS.length bs)))
      pure ckrOk
pokeBlob _ _ _ = pure ckrGeneralError

-- | Report one length output (8-byte big-endian) to the caller.
pokeLenOut :: [NativeOutput] -> Ptr CULong -> CULong -> IO CULong
pokeLenOut [NativeOutput _ bs] pLen rv = case beWord64 bs of
  Just n -> poke pLen (CULong n) >> pure rv
  Nothing -> pure ckrGeneralError
pokeLenOut _ _ _ = pure ckrGeneralError

-- | Publish one wrap-plan result: the query and short-buffer legs
-- report the padded length; a sufficient buffer lands the blob.
publishWrapResult
  :: StdInstance -> PlanResult -> Ptr Word8 -> Ptr CULong -> IO CULong
publishWrapResult inst pr pOut pLen = case pr of
  Reject rej -> do
    publishRejection inst rej
    case rejCode rej of
      CKR_BUFFER_TOO_SMALL -> pokeLenOut (rejOutputs rej) pLen
        (stdRvOf CKR_BUFFER_TOO_SMALL)
      _ -> pure (stdRvOf (rejCode rej))
  Immediate pc -> do
    ePub <- publishCommit inst pc
    case ePub of
      Left _ -> pure ckrGeneralError
      Right ()
        | pcCode pc /= CKR_OK -> pure (stdRvOf (pcCode pc))
        | pOut == nullPtr -> pokeLenOut (pcOutputs pc) pLen ckrOk
        | otherwise -> pokeBlob (pcOutputs pc) pOut pLen
  Execute _ _ -> pure ckrGeneralError

-- | Execute one wrap plan through the instance backend.
runWrapPlan
  :: StdInstance -> Model -> SessionState -> KeyPlan -> Ptr Word8 -> Ptr CULong
  -> IO CULong
runWrapPlan inst m st kp pOut pLen = case kp of
  KeyDenied deny -> pure (stdRvOf (kdCode deny))
  KeyImmediate pr -> publishWrapResult inst pr pOut pLen
  -- Finisher-incoherent pairs refuse BEFORE any effect runs.
  KeyEffect pw fx
    | not (keyPairCompatible pw fx) -> pure (stdRvOf CKR_GENERAL_ERROR)
    | otherwise -> do
    res <- runEffect (siBackend inst) (stdResolver m) fx
    m2 <- snapshotModel (siEnv inst)
    publishWrapResult inst (finishWork m2 st pw res) pOut pLen

-- | Wrap one key: the mechanism parameters ride the raw block
-- (an IV for AES-CBC, empty for v1.5, the native OAEP struct
-- normalized to the canonical codec); a NULL out-buffer queries
-- the blob length.
haskokiStdWrapKey
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdWrapKey ctx h (CULong mech) pIv (CULong ivLen)
    (CULong wrapH) (CULong targetH) pOut pLen =
  withStdCtx ctx $ \inst ->
    if pLen == nullPtr
      then pure ckrArgsBad
      else withSessionState inst h $ \st -> do
        eIv <- decodeInputBytes pIv ivLen
        case eIv of
          Left _ -> pure ckrArgsBad
          Right raw -> do
            CULong cap <- peek pLen
            let intent = if pOut == nullPtr then IntentNull
                         else IntentBuffer (fromIntegral cap)
                mid = MechanismId (fromIntegral mech)
            params <- normalizeMechParams mid pIv ivLen raw
            m <- snapshotModel (siEnv inst)
            runWrapPlan inst m st
              (planWrapKey m st mid params
                (ExternalHandle (fromIntegral wrapH))
                (ExternalHandle (fromIntegral targetH)) intent)
              pOut pLen

-- | Unwrap one blob into a key from a template frame.
haskokiStdUnwrapKey
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr CULong -> IO CULong
haskokiStdUnwrapKey ctx h (CULong mech) pIv (CULong ivLen) (CULong wrapH)
    pBlob (CULong blobLen) pFrame (CULong frameLen) phKey =
  withStdCtx ctx $ \inst ->
    if phKey == nullPtr
      then pure ckrArgsBad
      else withSessionState inst h $ \st -> do
        eIv <- decodeInputBytes pIv ivLen
        case eIv of
          Left _ -> pure ckrArgsBad
          Right raw -> do
            eBlob <- decodeInputBytes pBlob blobLen
            case eBlob of
              Left _ -> pure ckrArgsBad
              Right blob -> do
                eTmpl <- readFrame pFrame (CULong frameLen)
                case eTmpl of
                  Left ferr -> pure (frameErrorRV ferr)
                  Right entries -> do
                    let mid = MechanismId (fromIntegral mech)
                    params <- normalizeMechParams mid pIv ivLen raw
                    m <- snapshotModel (siEnv inst)
                    eHs <- runKeyPlan inst m st
                      (planUnwrapKey (envRules (siEnv inst)) m st
                        mid params
                        (ExternalHandle (fromIntegral wrapH)) blob entries)
                    case eHs of
                      Left rv -> pure rv
                      Right [oh] -> poke phKey (CULong oh) >> pure ckrOk
                      Right _ -> pure ckrGeneralError

-- | Opaque derive for the ECDH, DH, SHA-KDF, TLS-PRF,
-- SP 800-108, TLS-KDF, IKE, byte-op, and key-material rows: the
-- C side forwards the mechanism id, the raw parameter image,
-- and the template frame. ECDH, DH, TLS-PRF, SP 800-108,
-- TLS-KDF, IKE, byte-op, and key-material structs normalize
-- here ('normalizeEcdhParams', 'normalizeDhPkcsParams' for the
-- bare PKCS#3 peer, 'normalizeDhX942Params' for the X9.42
-- struct, 'normalizeTlsPrfParams', 'normalizeSp800KdfParams',
-- the four 'normalizeTlsKdf*' normalizers dispatched by row
-- kind, the four 'normalizeIke*' normalizers likewise, the
-- three 'normalizeByteOps*' normalizers by param shape, and
-- the two key-material normalizers by struct shape); base
-- resolution and the key-type check
-- run first inside 'planDerive', so a wrong-typed base refuses
-- before parameter shape is examined. SHA rows take the image as
-- the info segment (emptiness enforced by 'planDerive').
-- Unmappable struct images pass through raw so the recipe refusal
-- (and its @CKR@) is unchanged. PBKD2 is not served here (its
-- native struct has no decoder yet) and refuses
-- @CKR_MECHANISM_INVALID@. Multi-output rows (SP 800-108 with
-- additional keys, the key-material trio) pack
-- params-embedded templates and write handles (plus IVs) back
-- into caller memory on success only; the trio accepts a NULL
-- @phKey@ (v3.2: it "should be a NULL_PTR").
haskokiStdDeriveOpaque
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong
  -> Ptr Word8 -> CULong -> Ptr CULong -> IO CULong
haskokiStdDeriveOpaque ctx h (CULong mech) pParams (CULong paramsLen)
    (CULong baseH) pFrame (CULong frameLen) phKey =
  withStdCtx ctx $ \inst ->
    let mid = MechanismId (fromIntegral mech)
    in if phKey == nullPtr && not (isKeyMatMulti mid)
      then pure ckrArgsBad
      else withSessionState inst h $ \st -> do
        eParams <- decodeInputBytes pParams paramsLen
        case eParams of
          Left _ -> pure ckrArgsBad
          Right raw -> do
            eTmpl <- readFrame pFrame (CULong frameLen)
            case eTmpl of
              Left ferr -> pure (frameErrorRV ferr)
              Right entries ->
                if not (isOpaqueDeriveMech mid)
                  then pure (stdRvOf CKR_MECHANISM_INVALID)
                  else do
                    (blob, extraTmpls, wb) <- deriveBlobEx mid raw
                    m <- snapshotModel (siEnv inst)
                    let plan = planDerive (envRules (siEnv inst)) m st mid
                          (ExternalHandle (fromIntegral baseH))
                          (encodeDeriveParams blob ([entries] ++ extraTmpls))
                    case wb of
                      WbKeyMat slots -> do
                        eOut <- runKeyPlanFull inst m st plan
                        case eOut of
                          Left rv -> pure rv
                          Right outs -> publishKeyMat slots outs phKey
                      _ -> do
                        eHs <- runKeyPlan inst m st plan
                        case eHs of
                          Left rv -> pure rv
                          Right hs -> publishHandles wb hs
  where
    publishHandles phun hs = case (phun, hs) of
      (WbNone, [oh]) -> poke phKey (CULong oh) >> pure ckrOk
      (WbSp800 slots, oh : rest)
        | length rest == length slots -> do
            zipWithM_ poke slots (map CULong rest)
            poke phKey (CULong oh) >> pure ckrOk
      _ -> pure ckrGeneralError
    deriveBlobEx mid raw = case multiIntake mid of
      Just intake -> do
        mOut <- intake
        pure (fromMaybe (raw, [], WbNone) mOut)
      Nothing -> do
        blob <- deriveBlob mid raw
        pure (blob, [], WbNone)
    multiIntake mid
      | Just r <- sp800RecipeFor mid = Just $ do
          mMulti <- normalizeSp800KdfParams (rsMode r) pParams paramsLen
          pure $ case mMulti of
            Just (b, slots) ->
              Just (b, map dksTemplate slots, WbSp800 (map dksOut slots))
            Nothing -> Nothing
      | Just r <- tlsKeyMatRecipeFor mid = Just $ do
          mKm <- keyMatNormalizer (tkmKind r) pParams paramsLen
          pure $ case mKm of
            Just (b, slots) -> Just (b, [], WbKeyMat slots)
            Nothing -> Nothing
      | Just r <- ssl3RecipeFor mid
      , ssl3Kind r == Ssl3KeyMat = Just $ do
          mKm <- normalizeSsl3KeyMatParams pParams paramsLen
          pure $ case mKm of
            Just (b, slots) -> Just (b, [], WbKeyMat slots)
            Nothing -> Nothing
      | otherwise = Nothing
    deriveBlob mid raw
      | isJust (ecdhRecipeFor mid) =
          fromMaybe raw <$> normalizeEcdhParams pParams paramsLen
      | Just r <- dhRecipeFor mid
      , dhName r == "CKM_DH_PKCS_DERIVE" =
          pure (fromMaybe raw (normalizeDhPkcsParams raw))
      | isJust (dhRecipeFor mid) =
          fromMaybe raw <$> normalizeDhX942Params pParams paramsLen
      | isJust (tlsPrfRecipeFor mid) =
          fromMaybe raw <$> normalizeTlsPrfParams pParams paramsLen
      | Just r <- ssl3RecipeFor mid
      , ssl3Kind r == Ssl3Master || ssl3Kind r == Ssl3MasterDh =
          fromMaybe raw <$> normalizeSsl3MasterParams pParams paramsLen
      | Just r <- tlsKdfRecipeFor mid = case tkKind r of
          TlsMaster10 ->
            fromMaybe raw <$> normalizeTlsKdfMasterParams pParams paramsLen
          TlsMaster12 ->
            fromMaybe raw <$> normalizeTlsKdfTls12MasterParams pParams paramsLen
          TlsExtended12 ->
            fromMaybe raw <$> normalizeTlsKdfExtParams pParams paramsLen
          TlsKdfFree ->
            fromMaybe raw <$> normalizeTlsKdfFreeParams pParams paramsLen
      | Just r <- ikeRecipeFor mid = case ikKind r of
          Ike2PrfPlus ->
            fromMaybe raw <$> normalizeIkePrfPlusParams pParams paramsLen
          IkePrf ->
            fromMaybe raw <$> normalizeIkePrfParams pParams paramsLen
          Ike1Prf ->
            fromMaybe raw <$> normalizeIke1PrfParams pParams paramsLen
          Ike1Extended ->
            fromMaybe raw <$> normalizeIke1ExtParams pParams paramsLen
      | Just r <- byteOpsRecipeFor mid = case boKind r of
          ConcatBaseAndKey ->
            fromMaybe raw <$> normalizeByteOpsConcatKeyParams pParams paramsLen
          ConcatBaseAndData ->
            fromMaybe raw <$> normalizeByteOpsStringDataParams pParams paramsLen
          ConcatDataAndBase ->
            fromMaybe raw <$> normalizeByteOpsStringDataParams pParams paramsLen
          XorBaseAndData ->
            fromMaybe raw <$> normalizeByteOpsStringDataParams pParams paramsLen
          ExtractKeyFromKey ->
            fromMaybe raw <$> normalizeByteOpsExtractParams pParams paramsLen
      -- Encrypt-data rows normalize their native structs (CBC:
      -- the @iv||data@ frame; ECB: the string-data chase onto the
      -- raw data bytes). A refused chase poisons to the empty
      -- blob, never the raw struct bytes: the canonical frame is
      -- unframed, so raw struct bytes could otherwise satisfy the
      -- recipe and accept malformed input.
      | Just r <- encryptDataRecipeFor mid
      , erIvBytes r /= 0 =
          fromMaybe BS.empty <$> normalizeEncryptDataCbcParams (erIvBytes r) pParams paramsLen
      | Just r <- encryptDataRecipeFor mid
      , erIvBytes r == 0 =
          fromMaybe BS.empty <$> normalizeEncryptDataEcbParams pParams paramsLen
      | otherwise = pure raw

-- | Mechanisms served by 'haskokiStdDeriveOpaque': the ECDH rows,
-- the DH rows, the SHA-KDF rows, TLS-PRF, the SP 800-108 rows,
-- the TLS-KDF rows, the IKE rows, the byte-op rows, the
-- key-material rows, the SSL3 derive rows, the encrypt-data
-- rows (PBKD2 excluded: no native decoder), and the
-- pub-from-priv row (no native decoder either: the empty
-- frame passes through and the planner validates emptiness).
isOpaqueDeriveMech :: MechanismId -> Bool
isOpaqueDeriveMech mid =
  isJust (ecdhRecipeFor mid) || isJust (dhRecipeFor mid) || isJust (tlsPrfRecipeFor mid) || isJust (sp800RecipeFor mid) || isJust (tlsKdfRecipeFor mid) || isJust (ikeRecipeFor mid) || isJust (byteOpsRecipeFor mid) || isJust (tlsKeyMatRecipeFor mid) || isJust (encryptDataRecipeFor mid) || isJust (pubPrivRecipeFor mid) || isSsl3DeriveMech mid || case kdfRecipeFor mid of
    Just r -> not (rkPbkd2 r)
    Nothing -> False
  where
    isSsl3DeriveMech m = case ssl3RecipeFor m of
      Just r -> case ssl3Kind r of
        Ssl3Master -> True
        Ssl3MasterDh -> True
        Ssl3KeyMat -> True
        _ -> False
      Nothing -> False

-- | The key-material multi-output rows (the only opaque rows
-- whose outputs live in the mechanism params, so a NULL
-- @phKey@ is legal): the TLS trio plus the SSL3 row.
isKeyMatMulti :: MechanismId -> Bool
isKeyMatMulti mid = isJust (tlsKeyMatRecipeFor mid) || case ssl3RecipeFor mid of
  Just r -> ssl3Kind r == Ssl3KeyMat
  Nothing -> False

-- | Key-material struct normalizer by row kind: the TLS 1.0
-- shape, the TLS 1.2 shape, or the key-safe shape (which
-- ignores the IV size, matching the planner's suppression).
keyMatNormalizer :: TlsKeyMatKind -> Ptr Word8 -> Word64 -> IO (Maybe (ByteString, KeyMatSlots))
keyMatNormalizer KeyMatTls10 = normalizeTlsKeyMatParams
keyMatNormalizer KeyMatTls12Safe = normalizeTls12KeySafeParams
keyMatNormalizer _ = normalizeTls12KeyMatParams

-- | Caller write-back targets for one multi-output derive: no
-- extras (the single-handle rows), SP 800-108 additional
-- handle slots (plan order past the primary), or the
-- key-material slots.
data DeriveWriteBack
  = WbNone
  | WbSp800 ![Ptr CULong]
  | WbKeyMat !KeyMatSlots
  deriving (Eq, Show)

-- | HKDF derive: the C side classifies the parameters (served
-- profiles only reach here) and passes the mechanism id, the
-- info bytes, the salt bytes and the stage mode; the template
-- frame carries the derived shape (exactly one key for
-- HKDF-DERIVE, exactly one data object for HKDF-DATA).
haskokiStdDeriveHkdf
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong
  -> Ptr Word8 -> CULong -> CULong -> CULong -> CULong
  -> Ptr Word8 -> CULong -> Ptr CULong -> IO CULong
haskokiStdDeriveHkdf ctx h (CULong mech) pInfo (CULong infoLen)
    pSalt (CULong saltLen) (CULong mode) (CULong prf) (CULong baseH)
    pFrame (CULong frameLen) phKey =
  withStdCtx ctx $ \inst ->
    if phKey == nullPtr
      then pure ckrArgsBad
      else withSessionState inst h $ \st -> do
        eInfo <- decodeInputBytes pInfo infoLen
        eSalt <- decodeInputBytes pSalt saltLen
        case (eInfo, eSalt) of
          (Right info, Right salt) -> do
            eTmpl <- readFrame pFrame (CULong frameLen)
            case eTmpl of
              Left ferr -> pure (frameErrorRV ferr)
              Right entries -> do
                m <- snapshotModel (siEnv inst)
                let mid = MechanismId (fromIntegral mech)
                -- Defense in depth: the C arm only forwards the
                -- two HKDF mechanisms; anything else refuses here.
                if mid /= hkdfDeriveMech && mid /= hkdfDataMech
                  then pure (stdRvOf CKR_MECHANISM_INVALID)
                  else do
                    eHs <- runKeyPlan inst m st
                      (planDerive (envRules (siEnv inst)) m st mid
                        (ExternalHandle (fromIntegral baseH))
                        (encodeDeriveParams
                          (encodeHkdfInfo (fromIntegral prf) (fromIntegral mode) salt info) [entries]))
                    case eHs of
                      Left rv -> pure rv
                      Right [oh] -> poke phKey (CULong oh) >> pure ckrOk
                      Right _ -> pure ckrGeneralError
          _ -> pure ckrArgsBad
