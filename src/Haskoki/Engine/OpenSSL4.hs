{- | OpenSSL 4 crypto backend: the first REAL engine.

Owns one private @OSSL_LIB_CTX@ per 'BackendEnv' (explicit
@"default"@ provider + property query, never a PKCS#11-backed
provider, never process-global cleanup) behind a single 'ForeignPtr'
whose finalizer tears providers down before the context. Multipart
digest handles live in an explicit registry keyed by
'EngineResourceId'; key references resolve through a small material
registry. 'ForeignPtr's live ONLY here (and the private
'Haskoki.FFI.OpenSSL4.Raw' imports), never in 'Haskoki.Engine.Backend'
types or the pure core.

Original capability set (narrow by design; recipes extend it):

* digest: SHA-256 one-shot + multipart;
* MAC: HMAC-SHA-256, full tag only;
* cipher: AES-256-CBC without padding (block-aligned input only);
* signatures: ECDSA P-256 / SHA-256 with explicit DER or RAW encodings.

Every execute path checks its capability predicate BEFORE touching
native state; misses answer 'BackendUnsupported' with no fallback.

Ownership Contract, registry half (stated in 'Haskoki.Runtime.Async',
implemented here):

* R2 alloc\/register: the native handle is allocator-owned until
  registered. Alloc-to-register runs masked; an interruption after
  alloc frees the handle — never registered-or-leaked.
* R3 take\/consume: the masked take transfers ownership
  registry-to-consumer; consumer failure frees, successful consume
  frees exactly once (the shim final owns the handle past the
  take). No leak, no double free on any path.
* R4 borrow: native-handle use borrows UNDER the registry lock
  ('withBorrowedRegistry'), so close\/release waits for permitted
  in-flight use; raw pointers never escape the lock. Snapshot
  lookup ('lookupRegistry') is restricted to immutable values (key
  material), which cannot dangle.
* Reachability is lifetime, never coordination: 'ForeignPtr's keep
  the native env alive across each use ('withForeignPtr'); every
  ownership transfer is an explicit masked step, never GC timing.
-}
{-# LANGUAGE TypeFamilies #-}
module Haskoki.Engine.OpenSSL4
  ( OpenSSL4 (..)
  , withBorrowedRegistry
  , lookupRegistry
  , takeRegistry
  ) where

import Control.Concurrent.MVar (MVar, modifyMVar, newMVar, readMVar, withMVar)
import Control.Exception (mask_, onException)
import Control.Monad (filterM)
import Data.Bits (xor, (.|.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (intercalate, isInfixOf)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Set as Set
import Data.Word (Word32)
import Foreign.ForeignPtr (ForeignPtr, finalizeForeignPtr, newForeignPtr, withForeignPtr)
import Foreign.Ptr (Ptr, nullPtr)

import qualified Haskoki.FFI.OpenSSL4.Raw as Raw
import Haskoki.Der (coveredCurveNames, integerToBE)
import Haskoki.Engine.Backend
import Haskoki.Recipe.Ecdh (curveWidthOfName, ecdhPeerWidth)
import Haskoki.Recipe.Ecdsa (ecdsaCurveOfDer)
import Haskoki.Types (EngineResourceId (..))

-- | Backend tag for the OpenSSL 4 engine.
data OpenSSL4 = OpenSSL4 deriving (Eq, Show)

-- | Backend handle: private native env + registries. The cached
-- 'osslCtx' pointer is valid only while 'osslEnv' is alive; every use
-- runs inside 'withForeignPtr'.
data OSSL4Env = OSSL4Env
  { osslEnv :: !(ForeignPtr Raw.OsslEnv)
  , osslCtx :: !(Ptr Raw.OsslLibCtx)
  , osslPropQ :: !String
  , osslCaps :: !BackendCaps
  , osslDigests :: !(MVar (Map Word32 (Ptr Raw.DigestHandle)))
  , osslKeys :: !(MVar (Map Word32 KeyMaterial))
  , osslNextId :: !(MVar Word32)
  , osslClosed :: !(MVar Bool)
  }

instance CryptoBackend OpenSSL4 where
  data BackendEnv OpenSSL4 = OSSL4Backend !OSSL4Env

  backendName _ = "openssl4"

  openBackend propq = do
    envp <- Raw.envNew
    if envp == nullPtr
      then pure (EngineFail (BackendNative "open" (-1) "OSSL_LIB_CTX_new failed"))
      else do
        loadRc <- Raw.envLoad envp "default"
        if loadRc /= 0
          then do
            Raw.envFree envp
            detail <- Raw.lastError
            pure (EngineFail (BackendNative "open" loadRc ("load default provider: " ++ detail)))
          else do
            version <- Raw.libVersion
            if not ("4.0.2" `isInfixOf` version)
              then do
                Raw.envFree envp
                pure (EngineFail (BackendNative "open" (-1) ("libcrypto pin mismatch, want 4.0.2, got " ++ version)))
              else do
                ctx <- Raw.envCtx envp
                fenv <- newForeignPtr Raw.envFreeFinalizer envp
                digests <- newMVar Map.empty
                keys <- newMVar Map.empty
                nextId <- newMVar 1
                closed <- newMVar False
                let env = OSSL4Env fenv ctx propq (ossl4Caps version propq) digests keys nextId closed
                caps <- probeCaps env
                pure (EngineOk (OSSL4Backend env { osslCaps = caps }))

  closeBackend (OSSL4Backend env) = modifyMVar (osslClosed env) $ \wasClosed ->
    if wasClosed
      then pure (True, ())
      else do
        hs <- modifyMVar (osslDigests env) $ \m -> pure (Map.empty, Map.elems m)
        mapM_ Raw.digestFree hs
        modifyMVar (osslKeys env) $ \_ -> pure (Map.empty, ())
        finalizeForeignPtr (osslEnv env)
        pure (True, ())

  queryCapabilities (OSSL4Backend env) = pure (osslCaps env)

  digestOneShot be alg msg = runGuarded be "digest" (digestSupported be alg) $ \env ->
    case digestFetchName alg of
      Nothing -> pure (EngineFail (BackendUnsupported "digest"
        ("XOF needs an explicit output length: " ++ show alg)))
      Just mdname -> do
        r <- withForeignPtr (osslEnv env) $ \_ ->
          Raw.digest (osslCtx env) mdname (osslPropQ env) msg
        nativeOut "digest" r

  digestInit be alg = runGuarded be "digestInit" (digestSupported be alg) $ \env ->
    case digestFetchName alg of
      Nothing -> pure (EngineFail (BackendUnsupported "digestInit"
        ("XOF needs an explicit output length: " ++ show alg)))
      -- Ownership rule R2: alloc-to-register is one masked transfer — an
      -- interruption after alloc frees the handle instead of
      -- leaking it, and no kill can land between the two steps.
      Just mdname -> mask_ $ do
        h <- withForeignPtr (osslEnv env) $ \_ ->
          Raw.digestInit (osslCtx env) mdname (osslPropQ env)
        if h == nullPtr
          then do
            detail <- Raw.lastError
            pure (EngineFail (BackendNative "digestInit" (-1) detail))
          else EngineOk <$> (allocResource env h `onException`
            (withForeignPtr (osslEnv env) $ \_ -> Raw.digestFree h))

  digestUpdate (OSSL4Backend env) rid msg =
    -- Ownership rule R4: the handle is borrowed UNDER the registry lock — a
    -- concurrent take (final\/release\/close) waits for this use,
    -- and the raw pointer never escapes unguarded.
    withBorrowedRegistry (osslDigests env) (unEngineResourceId rid) $ \mh ->
      case mh of
        Nothing -> pure (EngineFail (BackendResourceGone "digestUpdate" rid))
        Just h -> do
          rc <- withForeignPtr (osslEnv env) $ \_ -> Raw.digestUpdate h msg
          if rc == 0
            then pure (EngineOk ())
            else do
              detail <- Raw.lastError
              pure (EngineFail (BackendNative "digestUpdate" rc detail))

  digestFinal (OSSL4Backend env) rid = mask_ $ do
    mh <- takeRegistry (osslDigests env) rid
    case mh of
      Nothing -> pure (EngineFail (BackendResourceGone "digestFinal" rid))
      Just h -> do
        -- The shim final consumes the handle; it left the registry above,
        -- so exactly one free happens on every path. Ownership rule R3: the
        -- take-to-consume transfer is masked, and a throw during
        -- consume frees the taken handle instead of leaking it.
        r <- (withForeignPtr (osslEnv env) $ \_ -> Raw.digestFinal h)
          `onException` (withForeignPtr (osslEnv env) $ \_ -> Raw.digestFree h)
        nativeOut "digestFinal" r

  macSign be spec key msg = runGuarded be "mac" (macSupported be spec) $ \env ->
    case spec of
      MacHMAC alg trunc -> do
        mkey <- resolveKeyBytes env key
        case mkey of
          EngineFail err -> pure (EngineFail err)
          EngineOk kb -> case digestFetchName alg of
            -- Unreachable post-guard (the guard only admits
            -- fixed-width digests, all of which fetch); typed, never
            -- a crash.
            Nothing -> pure (EngineFail (BackendUnsupported "mac"
              ("no fetch name: " ++ show alg)))
            Just mdname -> do
              r <- withForeignPtr (osslEnv env) $ \_ ->
                Raw.hmac (osslCtx env) mdname (osslPropQ env) kb msg
              takeTag trunc <$> nativeOut "mac" r
      _ -> pure (EngineFail (BackendUnsupported "mac"
        ("non-HMAC spec: " ++ show spec)))

  macVerify be spec key msg tag = runGuarded be "macVerify" (macSupported be spec) $ \env ->
    case spec of
      MacHMAC alg trunc -> do
        mkey <- resolveKeyBytes env key
        case mkey of
          EngineFail err -> pure (EngineFail err)
          EngineOk kb -> case digestFetchName alg of
            Nothing -> pure (EngineFail (BackendUnsupported "macVerify"
              ("no fetch name: " ++ show alg)))
            Just mdname -> do
              r <- withForeignPtr (osslEnv env) $ \_ ->
                Raw.hmac (osslCtx env) mdname (osslPropQ env) kb msg
              case r of
                Left code -> nativeFail "macVerify" code
                Right good ->
                  let want = case trunc of
                        Nothing -> good
                        Just n -> BS.take n good
                  in if ctEq want tag
                    then pure (EngineOk True)
                    else pure (EngineFail (BackendAuthFailed "macVerify"))
      _ -> pure (EngineFail (BackendUnsupported "macVerify"
        ("non-HMAC spec: " ++ show spec)))

  sign be spec key msg = runGuarded be "sign" (sigSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      EngineFail err -> pure (EngineFail err)
      EngineOk kb -> case spec of
        SigECDSA _ digest -> case ecdsaNativeDigest digest of
          -- Unreachable post-guard (the guard only admits probed
          -- fixed-width digests and the raw row); typed, never a crash.
          Nothing -> pure (EngineFail (BackendUnsupported "sign"
            ("no fetch name: " ++ show spec)))
          -- The curve allowlist runs before any native call: the
          -- driver only hints the curve label, so a DER key on an
          -- off-set curve (or garbage) must refuse here rather than
          -- execute past the advertised cap set.
          Just (mdname, noHash) -> case ecdsaCurveOfDer kb of
            Nothing -> pure (EngineFail (BackendBadKey "sign"
              "EC key is not DER on a covered curve"))
            Just _ -> do
              r <- withForeignPtr (osslEnv env) $ \_ ->
                Raw.ecdsaSign (osslCtx env) mdname (osslPropQ env) kb msg (sigWantRaw spec) noHash
              case r of
                Left code
                  | code == Raw.errBadKey -> pure (EngineFail (BackendBadKey "sign" "private key DER rejected"))
                  | otherwise -> nativeFail "sign" code
                Right sig -> pure (EngineOk sig)
        SigRSA_PKCS1v15 alg -> case digestFetchName alg of
          -- Unreachable post-guard (the guard only admits probed
          -- fixed-width digests); typed, never a crash.
          Nothing -> pure (EngineFail (BackendUnsupported "sign"
            ("no fetch name: " ++ show alg)))
          Just mdname -> rsaSignRun env "sign" mdname False kb msg
        SigRSA_Raw -> rsaSignRun env "sign" "" True kb msg
        SigRSA_PSS (PssParams h m s) ->
          case (digestFetchName h, digestFetchName m) of
            (Just mdname, Just mgfname) -> do
              r <- withForeignPtr (osslEnv env) $ \_ ->
                Raw.rsaPssSign (osslCtx env) mdname mgfname s (osslPropQ env) kb msg
              case r of
                Left code
                  | code == Raw.errBadKey -> pure (EngineFail (BackendBadKey "sign" "private key DER rejected"))
                  | otherwise -> nativeFail "sign" code
                Right sig -> pure (EngineOk sig)
            _ -> pure (EngineFail (BackendUnsupported "sign"
              ("no fetch name: " ++ show spec)))
        _ -> pure (EngineFail (BackendUnsupported "sign"
          ("non-RSA/ECDSA spec: " ++ show spec)))

  verify be spec key msg sig = runGuarded be "verify" (sigSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      EngineFail err -> pure (EngineFail err)
      EngineOk kb -> case spec of
        SigECDSA _ digest -> case ecdsaNativeDigest digest of
          Nothing -> pure (EngineFail (BackendUnsupported "verify"
            ("no fetch name: " ++ show spec)))
          -- Same curve allowlist as sign: before any native call.
          Just (mdname, noHash) -> case ecdsaCurveOfDer kb of
            Nothing -> pure (EngineFail (BackendBadKey "verify"
              "EC key is not DER on a covered curve"))
            Just _ -> do
              rc <- withForeignPtr (osslEnv env) $ \_ ->
                Raw.ecdsaVerify (osslCtx env) mdname (osslPropQ env) kb msg sig (sigWantRaw spec) noHash
              verifyRc "verify" "malformed signature encoding" rc
        SigRSA_PKCS1v15 alg -> case digestFetchName alg of
          Nothing -> pure (EngineFail (BackendUnsupported "verify"
            ("no fetch name: " ++ show alg)))
          Just mdname -> do
            rc <- withForeignPtr (osslEnv env) $ \_ ->
              Raw.rsaVerify (osslCtx env) mdname (osslPropQ env) kb msg sig False
            verifyRc "verify" "malformed RSA signature" rc
        SigRSA_Raw -> do
          rc <- withForeignPtr (osslEnv env) $ \_ ->
            Raw.rsaVerify (osslCtx env) "" (osslPropQ env) kb msg sig True
          verifyRc "verify" "malformed RSA signature" rc
        SigRSA_PSS (PssParams h m s) ->
          case (digestFetchName h, digestFetchName m) of
            (Just mdname, Just mgfname) -> do
              rc <- withForeignPtr (osslEnv env) $ \_ ->
                Raw.rsaPssVerify (osslCtx env) mdname mgfname s (osslPropQ env) kb msg sig
              verifyRc "verify" "malformed RSA signature" rc
            _ -> pure (EngineFail (BackendUnsupported "verify"
              ("no fetch name: " ++ show spec)))
        _ -> pure (EngineFail (BackendUnsupported "verify"
          ("non-RSA/ECDSA spec: " ++ show spec)))

  cipherEncrypt be spec key iv input =
    cipherRun be "cipherEncrypt" True spec key iv input

  cipherDecrypt be spec key iv input =
    cipherRun be "cipherDecrypt" False spec key iv input

  aeadEncrypt be spec key iv aad input = do
    r <- aeadRun be "aeadEncrypt" True spec key iv aad input BS.empty
    pure $ case r of
      EngineFail err -> EngineFail err
      EngineOk blob
        | BS.length blob < aeadTagLen spec -> EngineFail
            (BackendNative "aeadEncrypt" (-1) "native AEAD answer shorter than tag")
        | otherwise -> EngineOk (BS.splitAt (BS.length blob - aeadTagLen spec) blob)
  aeadDecrypt be spec key iv aad input tag =
    aeadRun be "aeadDecrypt" False spec key iv aad input tag

  pkeyEncrypt be (RsaOaep params) key input =
    runGuarded be "pkeyEncrypt" (oaepSupported be params) $ \env -> do
      mkey <- resolveKeyBytes env key
      case mkey of
        EngineFail err -> pure (EngineFail err)
        EngineOk kb -> case oaepFetchNames params of
          -- Unreachable post-guard (the guard only admits probed
          -- fixed-width digests); typed, never a crash.
          Nothing -> pure (EngineFail (BackendUnsupported "pkeyEncrypt"
            ("no fetch name: " ++ show params)))
          Just (mdname, mgfname) -> do
            r <- withForeignPtr (osslEnv env) $ \_ ->
              Raw.rsaOaepEncrypt (osslCtx env) mdname mgfname (oaepLabel params)
                (osslPropQ env) kb input
            case r of
              Left code
                | code == Raw.errBadKey -> pure (EngineFail (BackendBadKey "pkeyEncrypt" "public key DER rejected"))
                | otherwise -> nativeOut "pkeyEncrypt" (Left code)
              Right ct -> pure (EngineOk ct)
  pkeyEncrypt be RsaPkcs1 key input =
    runGuarded be "pkeyEncrypt" (pkcs1Supported be) $ \env -> do
      mkey <- resolveKeyBytes env key
      case mkey of
        EngineFail err -> pure (EngineFail err)
        EngineOk kb -> do
          r <- withForeignPtr (osslEnv env) $ \_ ->
            Raw.rsaPkcs1Encrypt (osslCtx env) (osslPropQ env) kb input
          case r of
            Left code
              | code == Raw.errBadKey -> pure (EngineFail (BackendBadKey "pkeyEncrypt" "public key DER rejected"))
              | otherwise -> nativeOut "pkeyEncrypt" (Left code)
            Right ct -> pure (EngineOk ct)

  pkeyDecrypt be (RsaOaep params) key input =
    runGuarded be "pkeyDecrypt" (oaepSupported be params) $ \env -> do
      mkey <- resolveKeyBytes env key
      case mkey of
        EngineFail err -> pure (EngineFail err)
        EngineOk kb -> case oaepFetchNames params of
          Nothing -> pure (EngineFail (BackendUnsupported "pkeyDecrypt"
            ("no fetch name: " ++ show params)))
          Just (mdname, mgfname) -> do
            r <- withForeignPtr (osslEnv env) $ \_ ->
              Raw.rsaOaepDecrypt (osslCtx env) mdname mgfname (oaepLabel params)
                (osslPropQ env) kb input
            case r of
              Left code
                | code == Raw.errBadKey -> pure (EngineFail (BackendBadKey "pkeyDecrypt" "private key DER rejected"))
                | otherwise -> nativeOut "pkeyDecrypt" (Left code)
              Right pt -> pure (EngineOk pt)
  pkeyDecrypt be RsaPkcs1 key input =
    runGuarded be "pkeyDecrypt" (pkcs1Supported be) $ \env -> do
      mkey <- resolveKeyBytes env key
      case mkey of
        EngineFail err -> pure (EngineFail err)
        EngineOk kb -> do
          r <- withForeignPtr (osslEnv env) $ \_ ->
            Raw.rsaPkcs1Decrypt (osslCtx env) (osslPropQ env) kb input
          case r of
            Left code
              | code == Raw.errBadKey -> pure (EngineFail (BackendBadKey "pkeyDecrypt" "private key DER rejected"))
              | otherwise -> nativeOut "pkeyDecrypt" (Left code)
            Right pt -> pure (EngineOk pt)

  generateKey be spec@(GenEC ec) = runGuarded be "generateKey" (genSupported be spec) $ \env -> do
    r <- withForeignPtr (osslEnv env) $ \_ ->
      Raw.ecGen (osslCtx env) (ecGroupName (ecCurve ec)) (osslPropQ env)
    case r of
      Left code -> nativeFail "generateKey" code
      Right (priv, pub) -> pure (EngineOk (KeyDer priv, Just (KeyDer pub)))
  -- RSA keygen bounds mirror the key planner (2048/3072/4096
  -- bits, odd exponent >= 3); the native call enforces the same
  -- window again.
  generateKey be spec@(GenRSA bits e) = runGuarded be "generateKey" (genSupported be spec) $ \env ->
    case rsaLenOk bits e of
      Just why -> pure (EngineFail (BackendBadParam "generateKey" why))
      Nothing -> do
        r <- withForeignPtr (osslEnv env) $ \_ ->
          Raw.rsaGen (osslCtx env) bits (integerToBE e) (osslPropQ env)
        case r of
          Left code -> nativeFail "generateKey" code
          Right (priv, pub) -> pure (EngineOk (KeyDer priv, Just (KeyDer pub)))
  -- Symmetric keygen is libctx DRBG bytes (bounds mirror
  -- the key planner: AES 16/24/32, HOTP 16..64, GENERIC 1..255).
  generateKey be spec@(GenSym alg n) = runGuarded be "generateKey" (genSupported be spec) $ \env ->
    case symLenOk alg n of
      Just why -> pure (EngineFail (BackendBadParam "generateKey" why))
      Nothing -> do
        r <- withForeignPtr (osslEnv env) $ \_ ->
          Raw.randBytes (osslCtx env) n
        case r of
          Left code -> nativeFail "generateKey" code
          Right bs -> pure (EngineOk (KeyBytes bs, Nothing))
  generateKey be spec = runGuarded be "generateKey" (genSupported be spec) $ \_ ->
    pure (EngineFail (BackendUnsupported "generateKey" ("keygen not in set: " ++ show spec)))

  -- Mix the seed via RAND_add (additional input only, never
  -- a DRBG state replacement) with entropy estimate 0.0 (the
  -- shim's single named home, pinned by caseSeedEntropyHonesty).
  -- Empty seeds are a vacuous OK; oversize seeds are refused.
  seedRandom be seedBytes = runGuarded be "seedRandom" Nothing $ \env ->
    if BS.length seedBytes > seedRandomMaxBytes
      then pure (EngineFail (BackendBadParam "seedRandom"
        ("seed longer than " ++ show seedRandomMaxBytes ++ " bytes")))
      else withForeignPtr (osslEnv env) $ \_ -> do
        r <- Raw.randSeed (osslCtx env) seedBytes
        case r of
          Left code -> nativeFail "seedRandom" code
          Right () -> pure (EngineOk ())

  -- DRBG bytes in 1 MiB native windows (always
  -- available; the only refusal is a non-positive length).
  randomBytes be n = runGuarded be "randomBytes" Nothing $ \env ->
    if n < 1
      then pure (EngineFail (BackendBadParam "randomBytes"
        ("length must be positive: " ++ show n)))
      else if n > generateRandomMaxBytes
        then pure (EngineFail (BackendBadParam "randomBytes"
          ("length longer than " ++ show generateRandomMaxBytes ++ " bytes: " ++ show n)))
        else withForeignPtr (osslEnv env) $ \_ -> go (osslCtx env) n []
    where
      go _ 0 acc = pure (EngineOk (BS.concat (reverse acc)))
      go ctx remaining acc = do
        r <- Raw.randBytes ctx (min remaining 1048576)
        case r of
          Left code -> nativeFail "randomBytes" code
          Right bs -> go ctx (remaining - BS.length bs) (bs : acc)

  importKey (OSSL4Backend env) mat = case mat of
    KeyRefMaterial r -> pure (EngineOk r)
    _ -> do
      rid <- allocId env
      modifyMVar (osslKeys env) $ \m -> pure (Map.insert rid mat m, ())
      pure (EngineOk (KeyRef (EngineResourceId rid) (keyFamily mat)))

  exportKey (OSSL4Backend env) (KeyRef rid _) = do
    mmat <- lookupRegistry (osslKeys env) (unEngineResourceId rid)
    case mmat of
      Nothing -> pure (EngineFail (BackendResourceGone "exportKey" rid))
      Just mat -> pure (EngineOk mat)

  destroyKey (OSSL4Backend env) (KeyRef rid _) =
    modifyMVar (osslKeys env) $ \m -> pure (Map.delete (unEngineResourceId rid) m, ())

  kemEncapsulate _ spec _ =
    pure (EngineFail (BackendUnsupported "kemEncapsulate" ("not in engine set: " ++ show (kemAlg spec))))
  kemDecapsulate _ spec _ _ =
    pure (EngineFail (BackendUnsupported "kemDecapsulate" ("not in engine set: " ++ show (kemAlg spec))))

  ecdhDerive be spec priv peer = runGuarded be "ecdhDerive" (ecdhSupported be spec) $ \env -> do
    mpriv <- resolveKeyBytes env priv
    case mpriv of
      EngineFail err -> pure (EngineFail err)
      EngineOk privB -> do
        mpeer <- resolveKeyBytes env peer
        case mpeer of
          EngineFail err -> pure (EngineFail err)
          -- Width-based agreement gate: the base scans exactly (DER
          -- always carries the OID) while a bare peer point resolves
          -- a width, never a curve (lengths collide). Equal widths
          -- proceed; the shim arbitrates on-curve membership
          -- natively, so a same-width cross-curve peer still
          -- refuses (as a bad key, never a wrong secret).
          EngineOk peerB -> case (ecdsaCurveOfDer privB >>= curveWidthOfName, ecdhPeerWidth peerB) of
            (Just w, Just pw)
              | w == pw -> do
                  r <- withForeignPtr (osslEnv env) $ \_ ->
                    Raw.ecdhDerive (osslCtx env) (osslPropQ env) privB peerB (spec == EcdhCofactor)
                  case r of
                    Left code
                      | code == Raw.errBadKey -> pure (EngineFail (BackendBadKey "ecdhDerive" "ECDH key rejected"))
                      | otherwise -> nativeFail "ecdhDerive" code
                    Right secret -> pure (EngineOk secret)
              | otherwise -> pure (EngineFail (BackendBadKey "ecdhDerive"
                  "base/peer curve mismatch"))
            _ -> pure (EngineFail (BackendBadKey "ecdhDerive"
              "ECDH keys are not on a covered curve"))

  snapshotResource _ _ = pure (Left "unsaveable: OpenSSL4 multipart contexts cannot be serialized")
  restoreResource _ _ = pure (EngineFail (BackendUnsupported "restoreResource" "no saveable resources in engine set"))
  resourceSaveability (OSSL4Backend env) rid = do
    digests <- readMVar (osslDigests env)
    keys <- readMVar (osslKeys env)
    let n = unEngineResourceId rid
    pure $ case (Map.lookup n digests, Map.lookup n keys) of
      (Just _, _) -> ResourceUnsaveable (UnsaveableNative
        "OpenSSL4 multipart contexts cannot be serialized")
      (_, Just _) -> ResourceUnsaveable (UnsaveableNative
        "OpenSSL4 key resources have no restore path in the engine set")
      (Nothing, Nothing) -> ResourceUnsaveable (UnsaveableGone rid)
  releaseResource (OSSL4Backend env) rid = mask_ $ do
    -- Ownership rule R3: take-to-free is one masked transfer — no kill can
    -- strand a taken-but-unfreed handle.
    mh <- takeRegistry (osslDigests env) rid
    mapM_ (\h -> withForeignPtr (osslEnv env) $ \_ -> Raw.digestFree h) mh

-- ---------------------------------------------------------------------------
-- Capabilities
-- ---------------------------------------------------------------------------

-- | The capability set, advertised only for probes that succeed.
-- The recipe table extends the original digest singleton to the full
-- fixed-length set ('t16DigestAlgs'); every other family keeps its
-- original shape.
ossl4Caps :: String -> String -> BackendCaps
ossl4Caps version propq = BackendCaps
  { bcName = "openssl4"
  , bcVersion = version
  , bcDigests = DigestCaps { dcAlgs = Set.fromList t16DigestAlgs, dcMultipart = True, dcXof = False }
  , bcCiphers = CipherCaps { ccCiphers = Set.fromList t16CipherSpecs, ccAead = Set.fromList ["AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "AES-128-CCM", "AES-192-CCM", "AES-256-CCM"] }
  , bcMacs = MacCaps { mcSpecs = osslMacSpecs t16DigestAlgs }
  , bcSigs = SigCaps { scSpecs = Set.fromList ("RSA-PSS" : osslRsaSpecNames t16RsaAlgs ++ osslEcdsaSpecNames t16EcdsaCurves t16DigestAlgs), scCurves = Set.fromList t16EcdsaCurves, scPqcSign = Set.empty }
  , bcKems = KemCaps { kcAlgs = Set.empty }
  , bcKdfs = KdfCaps { kcKdfs = Set.fromList ["ECDH", "ECDH-COFACTOR"] }
  , bcParamNotes = Map.fromList
      ([ ("provider", "default only; propquery " ++ propq)
       ] ++ osslCipherNotes t16CipherSpecs
         ++ osslMacNotes t16DigestAlgs ++
       [ ("RSA-PSS", "salt 0..64; hash/MGF any probed fixed-width digest")
       , ("RSA-OAEP", "label free; hash/MGF any probed fixed-width digest; input bound k-2*hLen-2")
       , ("ECDH", "raw x-coordinate secret; base/peer DER on one NIST prime curve")
       , ("ECDH-COFACTOR", "cofactor-multiplied; no-op on h=1 curves, threaded honestly")
       ] ++ osslRsaNotes t16RsaAlgs ++ osslEcdsaNotes t16EcdsaCurves t16DigestAlgs
      )
  }

-- | The ECDSA curve set: the NIST prime curves.
-- | The ECDSA curve set: every covered curve (deliberately
-- maximal — weak sub-224-bit and binary rows ride for oracle
-- coverage, never as a deployment recommendation).
t16EcdsaCurves :: [String]
t16EcdsaCurves = coveredCurveNames

-- | ECDSA capability names over curves and digests: one
-- hash-and-sign name per (curve, fixed-width digest) plus the raw
-- row per curve. The pre-probe caps cover 't16EcdsaCurves' over
-- 't16DigestAlgs'; 'probeCaps' re-derives over the probed digest
-- subset under the EC keymgmt gate.
osslEcdsaSpecNames :: [String] -> [DigestAlg] -> [String]
osslEcdsaSpecNames curves algs =
  [ name
  | curve <- curves
  , spec <- SigECDSA (EcSpec curve "DER") Nothing :
      [ SigECDSA (EcSpec curve "DER") (Just alg) | alg <- algs ]
  , Just name <- [ecdsaSigCap spec]
  ]

-- | Per-name ECDSA parameter notes for the capability report.
osslEcdsaNotes :: [String] -> [DigestAlg] -> [(String, String)]
osslEcdsaNotes curves algs =
  [ (name, note spec)
  | curve <- curves
  , spec <- SigECDSA (EcSpec curve "DER") Nothing :
      [ SigECDSA (EcSpec curve "DER") (Just alg) | alg <- algs ]
  , Just name <- [ecdsaSigCap spec]
  ]
  where
    note (SigECDSA _ Nothing) = "raw operation, no hashing; encodings DER and RAW"
    note _ = "hash-and-sign; encodings DER and RAW"

-- | The RSA digest set: every fixed-length digest the RSA
-- v1.5 recipe binds. Candidates that fail the fetch probe are
-- narrowed out of the advertised caps (never silently kept).
t16RsaAlgs :: [DigestAlg]
t16RsaAlgs =
  [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
  , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
  , D_RIPEMD160
  ]

-- | RSA capability names over a digest set: one PKCS#1 v1.5 name per
-- digest plus the raw row. The pre-probe caps cover 't16RsaAlgs';
-- 'probeCaps' re-derives over the probed subset.
osslRsaSpecNames :: [DigestAlg] -> [String]
osslRsaSpecNames algs = "RSA-RAW" :
  [ name
  | alg <- algs
  , Just name <- [rsaSigCap (SigRSA_PKCS1v15 alg)]
  ]

-- | Per-name RSA parameter notes for the capability report.
osslRsaNotes :: [DigestAlg] -> [(String, String)]
osslRsaNotes algs =
  ("RSA-RAW", "raw block-type-1 operation, no hashing") :
  [ (name, "PKCS#1 v1.5 hash-and-sign")
  | alg <- algs
  , Just name <- [rsaSigCap (SigRSA_PKCS1v15 alg)]
  ]

-- | The cipher set: every backend spec the block-cipher
-- recipe reaches (AES/ARIA/CAMELLIA CBC+ECB at three widths plus
-- Triple-DES CBC+ECB, plus AES CTR at three widths). Candidates
-- that fail the fetch probe are narrowed out of the advertised
-- caps (never silently kept).
t16CipherSpecs :: [CipherSpec]
t16CipherSpecs =
  [ C_AES128_CBC, C_AES192_CBC, C_AES256_CBC
  , C_AES128_CTR, C_AES192_CTR, C_AES256_CTR
  , C_AES128_ECB, C_AES192_ECB, C_AES256_ECB
  , C_DES3_CBC, C_DES3_ECB
  , C_ARIA128_CBC, C_ARIA192_CBC, C_ARIA256_CBC
  , C_ARIA128_ECB, C_ARIA192_ECB, C_ARIA256_ECB
  , C_CAMELLIA128_CBC, C_CAMELLIA192_CBC, C_CAMELLIA256_CBC
  , C_CAMELLIA128_ECB, C_CAMELLIA192_ECB, C_CAMELLIA256_ECB
  ]

-- | Per-name cipher parameter notes for the capability report,
-- keyed by provider fetch name.
osslCipherNotes :: [CipherSpec] -> [(String, String)]
osslCipherNotes specs =
  [ (cipherFetchName spec, cipherNote spec) | spec <- specs ]
  where
    cipherNote spec =
      "no padding; key " ++ keyNote spec
        ++ ", iv " ++ show (cipherIvLen spec) ++ " bytes, input "
        ++ (if cipherBlockLen spec == 1 then "any length" else "block-aligned")
    keyNote spec =
      intercalate "/" (map show (cipherKeyLens spec)) ++ " bytes"

-- | MAC capability names over an algorithm set: plain and
-- GENERAL names per fixed-width digest. The pre-probe caps cover
-- 't16DigestAlgs'; 'probeCaps' re-derives over the probed subset.
osslMacSpecs :: [DigestAlg] -> Set.Set String
osslMacSpecs algs = Set.fromList
  [ name
  | alg <- algs
  , spec <- [MacHMAC alg Nothing, MacHMAC alg (Just 1)]
  , Just name <- [hmacSpecCap spec]
  ]

-- | Per-name MAC parameter notes for the capability report.
osslMacNotes :: [DigestAlg] -> [(String, String)]
osslMacNotes algs =
  [ note
  | alg <- algs
  , Just stem <- [digestMacStem alg]
  , Just w <- [digestOutLen alg]
  , note <-
      [ ("HMAC-" ++ stem, "full " ++ show w ++ "-byte tag")
      , ("HMAC-" ++ stem ++ "-GENERAL"
        , "tag truncated to the requested 1.." ++ show w ++ " bytes")
      ]
  ]

-- | Fetch-probe each algorithm at open; failures narrow the caps
-- instead of falling back to anything else. Every digest fetch
-- name is probed individually, so a missing provider algorithm
-- narrows to the probed subset (never a silent singleton).
probeCaps :: OSSL4Env -> IO BackendCaps
probeCaps env = do
  mdAlgs <- probeDigests
  macOk <- probe1 "mac" "HMAC"
  ciphers <- probeCiphers
  pkeyOk <- probe1 "pkey" "EC"
  rsaOk <- probe1 "pkey" "RSA"
  let base = osslCaps env
      rsaAlgs = filter (`elem` mdAlgs) t16RsaAlgs
  pure base
    { bcDigests = (bcDigests base) { dcAlgs = Set.fromList mdAlgs }
    , bcCiphers = (bcCiphers base) { ccCiphers = Set.fromList ciphers }
    -- Per-algorithm HMAC caps over the probed digests (the
    -- HMAC path fetches the same digest the "md" probe tests, plus
    -- the EVP_MAC "HMAC" gate above): a missing provider algorithm
    -- narrows both the digest and the HMAC sets, never silently kept.
    , bcMacs = (bcMacs base)
        { mcSpecs = if macOk then osslMacSpecs mdAlgs else Set.empty }
    , bcSigs = (bcSigs base)
        { scSpecs = Set.union
            (keep pkeyOk (Set.fromList (osslEcdsaSpecNames t16EcdsaCurves mdAlgs)))
            (keep rsaOk (Set.fromList ("RSA-PSS" : osslRsaSpecNames rsaAlgs)))
        , scCurves = keep pkeyOk (Set.fromList t16EcdsaCurves)
        }
    }
  where
    probe1 kind name = withForeignPtr (osslEnv env) $ \_ ->
      (== 1) <$> Raw.probe (osslCtx env) kind name (osslPropQ env)
    probeDigests = filterM probeAlg t16DigestAlgs
    probeAlg alg = case digestFetchName alg of
      Nothing -> pure False
      Just mdname -> probe1 "md" mdname
    probeCiphers = filterM probeCipher t16CipherSpecs
    probeCipher spec = probe1 "cipher" (cipherFetchName spec)
    keep True s = s
    keep False _ = Set.empty

digestSupported :: BackendEnv OpenSSL4 -> DigestAlg -> Maybe String
digestSupported (OSSL4Backend env) alg
  | Set.member alg (dcAlgs (bcDigests (osslCaps env))) = Nothing
  | otherwise = Just ("digest not in probed set: " ++ show alg)

-- | Provider fetch names per digest algorithm, verified by
-- executing the OpenSSLSpec KATs against the pinned libcrypto. XOFs
-- have no fixed output length, so they map to 'Nothing' and the
-- digest entry points refuse them typed (the C shim only finalizes
-- fixed-length digests).
digestFetchName :: DigestAlg -> Maybe String
digestFetchName alg = case alg of
  D_MD5 -> Just "MD5"
  D_SHA1 -> Just "SHA1"
  D_SHA224 -> Just "SHA2-224"
  D_SHA256 -> Just "SHA2-256"
  D_SHA384 -> Just "SHA2-384"
  D_SHA512 -> Just "SHA2-512"
  D_SHA512_224 -> Just "SHA2-512/224"
  D_SHA512_256 -> Just "SHA2-512/256"
  D_SHA3_224 -> Just "SHA3-224"
  D_SHA3_256 -> Just "SHA3-256"
  D_SHA3_384 -> Just "SHA3-384"
  D_SHA3_512 -> Just "SHA3-512"
  D_RIPEMD160 -> Just "RIPEMD160"
  D_SHAKE128 -> Nothing
  D_SHAKE256 -> Nothing

-- | The digest set: every fixed-length 'DigestAlg' with a fetch
-- name. Candidates that fail the fetch probe are narrowed out of the
-- advertised caps (never silently kept).
t16DigestAlgs :: [DigestAlg]
t16DigestAlgs =
  [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
  , D_SHA512_224, D_SHA512_256
  , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
  , D_RIPEMD160
  ]

-- | Slice a truncated tag off a sign answer (full tag on 'Nothing').
takeTag :: Maybe Int -> EngineResult ByteString -> EngineResult ByteString
takeTag Nothing r = r
takeTag (Just n) (EngineOk t) = EngineOk (BS.take n t)
takeTag _ r = r

macSupported :: BackendEnv OpenSSL4 -> MacSpec -> Maybe String
macSupported (OSSL4Backend env) spec
  | Just name <- hmacSpecCap spec
  , Set.member name (mcSpecs (bcMacs (osslCaps env))) = Nothing
  | otherwise = Just ("mac not in probed set: " ++ show spec)

sigSupported :: BackendEnv OpenSSL4 -> SigSpec -> Maybe String
sigSupported (OSSL4Backend env) spec
  | Just name <- ecdsaSigCap spec
  , Set.member name (scSpecs (bcSigs (osslCaps env))) = Nothing
  | Just name <- rsaSigCap spec
  , Set.member name (scSpecs (bcSigs (osslCaps env))) = Nothing
  | Just name <- rsaPssCap spec
  , Set.member name (scSpecs (bcSigs (osslCaps env))) = Nothing
  | otherwise = Just ("signature not in supported set: " ++ show spec)

-- | ECDH availability: plain and cofactor agreements are served.
ecdhSupported :: BackendEnv OpenSSL4 -> EcdhSpec -> Maybe String
ecdhSupported (OSSL4Backend env) spec
  | Set.member (ecdhCap spec) (kcKdfs (bcKdfs (osslCaps env))) = Nothing
  | otherwise = Just ("ecdh not in supported set: " ++ show spec)

-- | Native digest selection for one ECDSA spec: the fetch name, or
-- the raw row (empty name, no hashing). 'Nothing' means an XOF
-- digest, which never makes a servable ECDSA spec.
ecdsaNativeDigest :: Maybe DigestAlg -> Maybe (String, Bool)
ecdsaNativeDigest Nothing = Just ("", True)
ecdsaNativeDigest (Just alg) = (, False) <$> digestFetchName alg

-- | OAEP availability: the RSA pkey gate (witnessed by the
-- probe-narrowed RSA signature set) plus per-digest fetch probes
-- for the hash and the MGF. Same probe inputs as the RSA signature
-- set, so OAEP narrows with it; the label is always servable.
oaepSupported :: BackendEnv OpenSSL4 -> OaepParams -> Maybe String
oaepSupported (OSSL4Backend env) params
  | Set.member "RSA-RAW" (scSpecs (bcSigs (osslCaps env)))
  , Set.member (oaepHash params) (dcAlgs (bcDigests (osslCaps env)))
  , Set.member (oaepMgf params) (dcAlgs (bcDigests (osslCaps env))) = Nothing
  | otherwise = Just ("oaep not in probed set: " ++ show params)

-- | PKCS#1 v1.5 availability: the RSA pkey gate (same
-- probe-narrowed RSA signature set as OAEP); no digest
-- dimension, so no per-digest fetch probes.
pkcs1Supported :: BackendEnv OpenSSL4 -> Maybe String
pkcs1Supported (OSSL4Backend env)
  | Set.member "RSA-RAW" (scSpecs (bcSigs (osslCaps env))) = Nothing
  | otherwise = Just "pkcs1 not in probed set"

-- | Fetch names for one OAEP parameter set ('Nothing' when either
-- digest has no fixed-width fetch, e.g. an XOF).
oaepFetchNames :: OaepParams -> Maybe (String, String)
oaepFetchNames params = (,)
  <$> digestFetchName (oaepHash params)
  <*> digestFetchName (oaepMgf params)

sigWantRaw :: SigSpec -> Bool
sigWantRaw (SigECDSA ec _) = ecEncoding ec == "RAW"
sigWantRaw _ = False

-- | RSA sign execution: one native call under the env ForeignPtr,
-- bad DER keys typed.
rsaSignRun :: OSSL4Env -> String -> String -> Bool -> ByteString -> ByteString
           -> IO (EngineResult ByteString)
rsaSignRun env op mdname isRaw kb msg = do
  r <- withForeignPtr (osslEnv env) $ \_ ->
    Raw.rsaSign (osslCtx env) mdname (osslPropQ env) kb msg isRaw
  case r of
    Left code
      | code == Raw.errBadKey -> pure (EngineFail (BackendBadKey op "private key DER rejected"))
      | otherwise -> nativeFail op code
    Right sig -> pure (EngineOk sig)

-- | Verify return-code mapping shared by ECDSA and RSA: 1 is valid,
-- 0 is a verdict-shaped mismatch, bad keys and malformed encodings
-- keep their taxonomy.
verifyRc :: String -> String -> Int -> IO (EngineResult ())
verifyRc op badParamMsg rc = case rc of
  1 -> pure (EngineOk ())
  0 -> pure (EngineFail (BackendAuthFailed "verify"))
  code
    | code == Raw.errBadKey ->
        pure (EngineFail (BackendBadKey op "public key DER rejected"))
    | code == Raw.errBadParam ->
        pure (EngineFail (BackendBadParam op badParamMsg))
    | otherwise -> nativeFail op code

cipherSupported :: BackendEnv OpenSSL4 -> CipherSpec -> Maybe String
cipherSupported (OSSL4Backend env) spec
  | Set.member spec (ccCiphers (bcCiphers (osslCaps env))) = Nothing
  | otherwise = Just ("cipher not in engine set: " ++ show spec)

-- | OpenSSL group name for an engine curve name: identical except
-- @secp192r1@, whose provider group name is @prime192v1@ (the SECG
-- alias is rejected at keygen with "invalid curve"; probed per
-- curve against the pinned CLI).
ecGroupName :: String -> String
ecGroupName "secp192r1" = "prime192v1"
ecGroupName c = c

genSupported :: BackendEnv OpenSSL4 -> KeyGenSpec -> Maybe String
genSupported (OSSL4Backend env) spec
  | GenEC ec <- spec
  , Set.member (ecCurve ec) (scCurves (bcSigs (osslCaps env))) = Nothing
  | GenSym alg _ <- spec
  , alg `elem` ["AES", "HOTP", "GENERIC"] = Nothing
  | GenRSA {} <- spec
  , Set.member "RSA-PSS" (scSpecs (bcSigs (osslCaps env))) = Nothing
  | otherwise = Just ("keygen not in set: " ++ show spec)

-- | RSA keygen bounds: the key planner's window (2048/3072/4096
-- bits, odd exponent >= 3). 'Nothing' when the pair may execute.
rsaLenOk :: Int -> Integer -> Maybe String
rsaLenOk bits e
  | bits `notElem` [2048, 3072, 4096] =
      Just ("RSA keygen bits must be 2048, 3072 or 4096: " ++ show bits)
  | e < 3 || even e =
      Just ("RSA keygen exponent must be odd and >= 3: " ++ show e)
  | otherwise = Nothing



-- | Symmetric keygen bounds: the key planner's windows.
-- 'Nothing' when the (algorithm, length) may execute.
symLenOk :: String -> Int -> Maybe String
symLenOk "AES" n
  | n `elem` [16, 24, 32] = Nothing
  | otherwise = Just ("AES keygen length must be 16, 24 or 32 bytes: " ++ show n)
symLenOk "HOTP" n
  | n >= 16 && n <= 64 = Nothing
  | otherwise = Just ("HOTP keygen length must be 16 to 64 bytes: " ++ show n)
symLenOk "GENERIC" n
  | n >= 1 && n <= 255 = Nothing
  | otherwise = Just ("generic-secret keygen length must be 1 to 255 bytes: " ++ show n)
symLenOk alg _ = Just ("symmetric keygen not in set: " ++ alg)

-- ---------------------------------------------------------------------------
-- Execution helpers
-- ---------------------------------------------------------------------------

-- | Guard-then-run: the capability check answers FIRST (even on a
-- closed backend, so the guard-before-native law is observable), then
-- the closed check, then the native call.
runGuarded :: BackendEnv OpenSSL4 -> String -> Maybe String -> (OSSL4Env -> IO (EngineResult a)) -> IO (EngineResult a)
runGuarded (OSSL4Backend env) op miss action = case miss of
  Just why -> pure (EngineFail (BackendUnsupported op why))
  Nothing -> do
    closed <- readMVar (osslClosed env)
    if closed
      then pure (EngineFail (BackendInvalidState op "backend is closed"))
      -- Keep the env ForeignPtr alive across the action without
      -- reordering the guards above.
      else withForeignPtr (osslEnv env) $ \_ -> action env

-- | Provider fetch names per cipher spec, verified by
-- executing the OpenSSLSpec KATs against the pinned libcrypto.
-- Triple-DES ECB fetches @DES-EDE3@ (the provider's ECB alias).
cipherFetchName :: CipherSpec -> String
cipherFetchName spec = case spec of
  C_AES128_CBC -> "AES-128-CBC"
  C_AES192_CBC -> "AES-192-CBC"
  C_AES256_CBC -> "AES-256-CBC"
  C_AES128_CTR -> "AES-128-CTR"
  C_AES192_CTR -> "AES-192-CTR"
  C_AES256_CTR -> "AES-256-CTR"
  C_AES128_ECB -> "AES-128-ECB"
  C_AES192_ECB -> "AES-192-ECB"
  C_AES256_ECB -> "AES-256-ECB"
  C_DES3_CBC -> "DES-EDE3-CBC"
  C_DES3_ECB -> "DES-EDE3"
  C_ARIA128_CBC -> "ARIA-128-CBC"
  C_ARIA192_CBC -> "ARIA-192-CBC"
  C_ARIA256_CBC -> "ARIA-256-CBC"
  C_ARIA128_ECB -> "ARIA-128-ECB"
  C_ARIA192_ECB -> "ARIA-192-ECB"
  C_ARIA256_ECB -> "ARIA-256-ECB"
  C_CAMELLIA128_CBC -> "CAMELLIA-128-CBC"
  C_CAMELLIA192_CBC -> "CAMELLIA-192-CBC"
  C_CAMELLIA256_CBC -> "CAMELLIA-256-CBC"
  C_CAMELLIA128_ECB -> "CAMELLIA-128-ECB"
  C_CAMELLIA192_ECB -> "CAMELLIA-192-ECB"
  C_CAMELLIA256_ECB -> "CAMELLIA-256-ECB"

-- | Block width in bytes per cipher spec: 8 for Triple-DES, 16 for
-- the AES family (CBC alignment; ECB shares the width), 1 for the
-- CTR stream specs (any input length; the provider reports the
-- stream block size 1 too, so the shim gate agrees).
cipherBlockLen :: CipherSpec -> Int
cipherBlockLen spec = case spec of
  C_DES3_CBC -> 8
  C_DES3_ECB -> 8
  C_AES128_CTR -> 1
  C_AES192_CTR -> 1
  C_AES256_CTR -> 1
  _ -> 16

-- | Expand two-key Triple-DES material (@K1||K2@) to the three-key
-- form the provider takes (@K1||K2||K1@). Any other spec passes
-- key bytes through untouched.
cipherProviderKey :: CipherSpec -> ByteString -> ByteString
cipherProviderKey spec kb
  | (spec == C_DES3_CBC || spec == C_DES3_ECB) && BS.length kb == 16 =
      kb <> BS.take 8 kb
  | otherwise = kb

cipherRun :: BackendEnv OpenSSL4 -> String -> Bool -> CipherSpec -> KeyMaterial -> ByteString -> ByteString -> IO (EngineResult ByteString)
cipherRun be op enc spec key iv input =
  runGuarded be op (cipherSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      EngineFail err -> pure (EngineFail err)
      EngineOk kb
        | BS.length kb `notElem` cipherKeyLens spec ->
            pure (EngineFail (BackendBadParam op
              ("key length " ++ show (BS.length kb)
                ++ " not accepted by " ++ show spec)))
        | BS.length iv /= cipherIvLen spec ->
            pure (EngineFail (BackendBadParam op
              ("iv length " ++ show (BS.length iv)
                ++ " not accepted by " ++ show spec)))
        | BS.length input `mod` cipherBlockLen spec /= 0 ->
            pure (EngineFail (BackendBadParam op
              ("input length must be a multiple of "
                ++ show (cipherBlockLen spec) ++ " (no padding)")))
        | otherwise -> do
            r <- withForeignPtr (osslEnv env) $ \_ ->
              Raw.cipherCbc (osslCtx env) (cipherFetchName spec) (osslPropQ env) enc
                (cipherProviderKey spec kb) iv input
            nativeOut op r

-- | Resolve key material to owned bytes; registry references are
-- looked up, missing ones answer ResourceGone.
aeadRun :: BackendEnv OpenSSL4 -> String -> Bool -> AeadSpec -> KeyMaterial -> ByteString -> ByteString -> ByteString -> ByteString -> IO (EngineResult ByteString)
aeadRun be op enc spec key iv aad input tag =
  runGuarded be op Nothing $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      EngineFail err -> pure (EngineFail err)
      EngineOk kb
        | aeadAlg spec `notElem` aeadServedAlgs ->
            pure (EngineFail (BackendBadParam op
              ("AEAD algorithm " ++ show (aeadAlg spec) ++ " is not served")))
        | BS.length kb /= aeadKeyLen (aeadAlg spec) ->
            pure (EngineFail (BackendBadParam op
              ("key length " ++ show (BS.length kb)
                ++ " not accepted by " ++ aeadAlg spec)))
        | aeadNonceLen spec < fst nonceBounds || aeadNonceLen spec > snd nonceBounds
          || BS.length iv /= aeadNonceLen spec ->
            pure (EngineFail (BackendBadParam op
              ("nonce length " ++ show (BS.length iv)
                ++ " does not match spec " ++ show (aeadNonceLen spec))))
        | aeadTagLen spec `notElem` aeadTagSet (aeadAlg spec) ->
            pure (EngineFail (BackendBadParam op
              ("tag length " ++ show (aeadTagLen spec) ++ " is not approved")))
        | not enc && BS.length tag /= aeadTagLen spec ->
            pure (EngineFail (BackendAuthFailed op))
        | otherwise -> do
            r <- withForeignPtr (osslEnv env) $ \_ ->
              if isCcmAlg (aeadAlg spec)
                then if enc
                  then Raw.aeadCcmEncrypt (osslCtx env) (aeadAlg spec) (osslPropQ env)
                    kb iv aad input (aeadTagLen spec)
                  else Raw.aeadCcmDecrypt (osslCtx env) (aeadAlg spec) (osslPropQ env)
                    kb iv aad input tag
                else if enc
                  then Raw.aeadEncrypt (osslCtx env) (aeadAlg spec) (osslPropQ env)
                    kb iv aad input (aeadTagLen spec)
                  else Raw.aeadDecrypt (osslCtx env) (aeadAlg spec) (osslPropQ env)
                    kb iv aad input tag
            nativeOut op r
  where
    nonceBounds
      | isCcmAlg (aeadAlg spec) = (7, 13)
      | otherwise = (1, 64)

-- | Served AEAD algorithm names.
aeadServedAlgs :: [String]
aeadServedAlgs =
  [ "AES-128-GCM", "AES-192-GCM", "AES-256-GCM"
  , "AES-128-CCM", "AES-192-CCM", "AES-256-CCM"
  ]

-- | CCM algorithm names take the CCM shims and bounds.
isCcmAlg :: String -> Bool
isCcmAlg alg = alg `elem` ["AES-128-CCM", "AES-192-CCM", "AES-256-CCM"]

-- | Approved tag widths per AEAD family (GCM: SP 800-38D; CCM:
-- SP 800-38C even widths).
aeadTagSet :: String -> [Int]
aeadTagSet alg
  | isCcmAlg alg = [4, 6, 8, 10, 12, 14, 16]
  | otherwise = [4, 8, 12, 13, 14, 15, 16]

-- | Key length in bytes for a supported AEAD algorithm name.
aeadKeyLen :: String -> Int
aeadKeyLen alg
  | alg == "AES-128-GCM" || alg == "AES-128-CCM" = 16
  | alg == "AES-192-GCM" || alg == "AES-192-CCM" = 24
  | otherwise = 32

resolveKeyBytes :: OSSL4Env -> KeyMaterial -> IO (EngineResult ByteString)
resolveKeyBytes _ (KeyBytes bs) = pure (EngineOk bs)
resolveKeyBytes _ (KeyDer bs) = pure (EngineOk bs)
resolveKeyBytes env (KeyRefMaterial (KeyRef rid _)) = do
  mmat <- lookupRegistry (osslKeys env) (unEngineResourceId rid)
  case mmat of
    Nothing -> pure (EngineFail (BackendResourceGone "key" rid))
    Just (KeyBytes bs) -> pure (EngineOk bs)
    Just (KeyDer bs) -> pure (EngineOk bs)
    Just (KeyRefMaterial _) -> pure (EngineFail (BackendInvalidState "key" "nested key reference"))

keyFamily :: KeyMaterial -> String
keyFamily (KeyBytes _) = "SYM"
keyFamily (KeyDer _) = "DER"
keyFamily (KeyRefMaterial (KeyRef _ fam)) = fam

-- | Constant-time equality (lengths plus a full xor fold).
ctEq :: ByteString -> ByteString -> Bool
ctEq a b =
  BS.length a == BS.length b
    && foldl' (\acc (x, y) -> acc .|. (x `xor` y)) 0 (BS.zip a b) == 0

nativeOut :: String -> Either Int ByteString -> IO (EngineResult ByteString)
nativeOut _ (Right bs) = pure (EngineOk bs)
nativeOut op (Left code) = nativeFail op code

nativeFail :: String -> Int -> IO (EngineResult a)
nativeFail op code
  | code == Raw.errBadParam = pure (EngineFail (BackendBadParam op "native parameter rejected"))
  | code == Raw.errAuthFail = pure (EngineFail (BackendAuthFailed op))
  | code == Raw.errNoMem = pure (EngineFail (BackendNative op code "native out of memory"))
  | otherwise = do
      detail <- Raw.lastError
      pure (EngineFail (BackendNative op code detail))

allocId :: OSSL4Env -> IO Word32
allocId env = modifyMVar (osslNextId env) $ \n -> pure (n + 1, n)

allocResource :: OSSL4Env -> Ptr Raw.DigestHandle -> IO EngineResourceId
allocResource env h = do
  n <- allocId env
  modifyMVar (osslDigests env) $ \m -> pure (Map.insert n h m, ())
  pure (EngineResourceId n)

-- | Borrow a registry entry UNDER the lock: the use runs inside
-- 'withMVar', so a concurrent take (final\/release\/close) waits
-- for permitted in-flight use and the value never escapes
-- unguarded (rule R4 — the borrowing half of the either\/or, chosen
-- over explicit external serialization). Exception-safe: a throw
-- or kill inside the use restores the lock with the entry intact
-- (borrows never consume; takes own their transfer).
withBorrowedRegistry :: MVar (Map Word32 v) -> Word32 -> (Maybe v -> IO a) -> IO a
withBorrowedRegistry mv n k = withMVar mv (k . Map.lookup n)

-- | Snapshot lookup, restricted to IMMUTABLE registry values (key
-- material): the copy cannot dangle, so no lock is held across the
-- use (rule R4). Never use for native handles — those borrow via
-- 'withBorrowedRegistry'.
lookupRegistry :: MVar (Map Word32 v) -> Word32 -> IO (Maybe v)
lookupRegistry mv n = Map.lookup n <$> readMVar mv

takeRegistry :: MVar (Map Word32 (Ptr Raw.DigestHandle)) -> EngineResourceId -> IO (Maybe (Ptr Raw.DigestHandle))
takeRegistry mv (EngineResourceId n) = modifyMVar mv $ \m ->
  pure (Map.delete n m, Map.lookup n m)
