{- | Synthetic backend: a stable test double behind 'CryptoBackend'.

Versioned deterministic constructions per family, built from
domain-separated FNV-1a accumulation expanded through a splitmix64
finalizer over owned key material, explicit parameters, the backend
seed plus generation sequence, and input. No process addresses, map
ordering, or wall-clock time participate, so the same seed plus the
same call sequence replays exactly.

Shape contracts (exact, no debug prefixes on fixed-length outputs):

* digest: 32 bytes;
* MAC: 32 bytes, verified by recomputation;
* signature: 64 bytes over the signing identity (raw keys sign
  under their own bytes; generated pair halves share one identity,
  so a pair verifies across);
* cipher: length-preserving reversible stream construction
  (wrap specs expand: keyed tag + padded body);
* key generation: explicit byte lengths from the backend's seeded
  sequence; EC pairs as tagged halves;
* resource contexts: @0x01@-versioned key encoding, @0x02@-versioned
  digest encoding, both strict.

Synthetic output is not known-answer evidence for real algorithms.
-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
module Haskoki.Engine.Synthetic
  ( -- * Backend tag
    Synthetic (..)
    -- * Versioned randomness
  , Seed (..)
  , OpNumber (..)
  , RngStream (..)
  , deriveStream
  , nextBytes
    -- * Fixtures
  , FixtureMaterial (..)
  , fixtureKey
  , fixtureKeyPair
    -- * Shape contracts
  , synthDigestLength
  , synthDigestLengthFor
  , synthMacLength
  , synthSigLength
  , synthEcdhWidth
  , synthDhWidth
  , synthKeyContextVersion
    -- * TEST-ONLY capability builder
  , synthCapsBuild
  ) where


import Control.Applicative ((<|>))
import Control.Concurrent.MVar (MVar, modifyMVar, newMVar, readMVar)
import Control.Monad (guard)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Word (Word32, Word64)

import Haskoki.Engine.Backend
  ( AeadSpec (..)
  , BackendCaps (..)
  , forceCaps
  , BackendError (..)
  , CipherCaps (..)
  , CipherSpec (..)
  , cipherIvLenOk
  , cipherKeyLens
  , cipherSpecCanon
  , rc2BitsOf
  , isKwSpec
  , isKwpSpec
  , isWrapSpec
  , isXtsSpec
  , CryptoBackend (..)
  , DigestAlg (..)
  , DigestCaps (..)
  , xofServable
  , ecdhCap
  , EcdhSpec (..)
  , dhCap
  , DhSpec (..)
  , ecdsaSigCap
  , dsaSigCap
  , eddsaSigCap
  , mldsaSigCap
  , slhdsaSigCap
  , slhdsaSets
  , EcSpec (..)
  , hmacSpecCap
  , poly1305SpecCap
  , KdfCaps (..)
  , KemCaps (..)
  , KemSpec (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , KeyRef (..)
  , symKeygenBounds
  , symLenBoundOk
  , MacCaps (..)
  , MacSpec (..)
  , OaepParams (..)
  , PqcKemAlg (..)
  , PqcSigAlg (..)
  , RsaCipherParams (..)
  , ResourceSaveability (..)
  , rsaSigCap
  , rsaPssCap
  , rsaX931Cap
  , SigCaps (..)
  , SigSpec (..)
  , UnsaveableReason (..)
  )
import Haskoki.Der
  ( coveredCurveNames
  , edwardsCurveNames
  , montgomeryCurveNames
  )
import qualified Haskoki.Engine.Backend as B
import Haskoki.Engine.Synthetic.Capabilities
import Haskoki.Engine.Synthetic.Codecs
import Haskoki.Engine.Synthetic.Framing
import Haskoki.Engine.Synthetic.PureOps
import Haskoki.Operation.KeyManagement
  (genericSecretKeygenMaxBytes, genericSecretKeygenMinBytes)
import Haskoki.Recipe.Otp (hotpKeygenMaxBytes, hotpKeygenMinBytes)
import Haskoki.Types (EngineResourceId (..))


-- CryptoBackend class instance (primary home)
--
-- The same stable test-double contract, re-targeted: deterministic
-- domain-separated constructions over owned values, now behind the
-- class interface. The instance carries open/close, capabilities,
-- one-shot and multipart digest, MAC and signatures,
-- cipher, and key generation plus the key registry.
-- Surface outside the synthetic set answers 'BackendUnsupported'
-- per the class law (pinned by @caseUnsupportedRest@).

-- | Backend tag for the synthetic test double.
data Synthetic = Synthetic deriving (Eq, Show)

-- | Backend-private state: fixture seed, registries, next id.
-- The seed lives in an 'MVar' so 'seedRandom' can replace the
-- stream origin (reseed plus counter reset).
data SynthEnv = SynthEnv
  { seSeed :: !(MVar Word64)
  , seCaps :: !BackendCaps
  , seClosed :: !(MVar Bool)
  , seNextId :: !(MVar Word32)
  , seDigests :: !(MVar (Map Word32 (DigestAlg, ByteString)))
  , seKeys :: !(MVar (Map Word32 SynthKey))
  , seGenCtr :: !(MVar Word64)
  }

-- | Stored key: the imported material verbatim, so export and
-- snapshots roundtrip the constructor as well as the bytes. Pair
-- halves (tagged @KeyDer@, see 'genPair') carry their shared pair
-- identity in the bytes, so signatures verify across the pair.
newtype SynthKey = SynthKey { skMat :: KeyMaterial }
  deriving (Eq, Show)

instance CryptoBackend Synthetic where
  data BackendEnv Synthetic = SynthBackend !SynthEnv

  backendName _ = "synthetic"

  openBackend seedStr = case parseSeed seedStr of
    Nothing -> pure (B.EngineFail
      (BackendBadParam "open"
        ("synthetic open wants a decimal seed, got: " ++ show seedStr)))
    Just s -> B.EngineOk . SynthBackend <$> newEnv s
    where
      newEnv :: Word64 -> IO SynthEnv
      newEnv s = SynthEnv
        <$> newMVar s
        <*> pure synthCaps
        <*> newMVar False
        <*> newMVar 1
        <*> newMVar Map.empty
        <*> newMVar Map.empty
        <*> newMVar 0

  closeBackend (SynthBackend env) =
    modifyMVar (seClosed env) $ \wasClosed ->
      if wasClosed
        then pure (True, ())
        else do
          modifyMVar (seDigests env) $ \_ -> pure (Map.empty, ())
          modifyMVar (seKeys env) $ \_ -> pure (Map.empty, ())
          pure (True, ())

  queryCapabilities (SynthBackend env) = pure (seCaps env)

  digestOneShot be alg msg =
    runGuarded be "digest" (digestSupported be alg) $ \_ ->
      pure (B.EngineOk (classDigest alg msg))

  digestInit be alg = runGuarded be "digestInit" (digestSupported be alg) $ \env -> do
    rid <- allocId env
    modifyMVar (seDigests env) $ \m ->
      pure (Map.insert (unEngineResourceId rid) (alg, BS.empty) m, ())
    pure (B.EngineOk rid)

  digestUpdate (SynthBackend env) rid msg = do
    let n = unEngineResourceId rid
    acc <- modifyMVar (seDigests env) $ \m -> case Map.lookup n m of
      Nothing -> pure (m, Nothing)
      Just (alg, prev) -> pure (Map.insert n (alg, prev <> msg) m, Just ())
    case acc of
      Nothing -> pure (B.EngineFail (BackendResourceGone "digestUpdate" rid))
      Just () -> pure (B.EngineOk ())

  digestFinal (SynthBackend env) rid = do
    let n = unEngineResourceId rid
    acc <- modifyMVar (seDigests env) $ \m ->
      pure (Map.delete n m, Map.lookup n m)
    case acc of
      Nothing -> pure (B.EngineFail (BackendResourceGone "digestFinal" rid))
      -- Final honors the INIT algorithm (previously hardcoded
      -- SHA-256, which only SHA-256 inits could reach).
      Just (alg, prev) -> pure (B.EngineOk (classDigest alg prev))

  digestXof be alg msg outLen =
    runGuarded be "digestXof" (xofSupported be alg) $ \_ ->
      pure (B.EngineOk (classXof alg msg outLen))

  macSign be spec key msg = runGuarded be "macSign" (macSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk kb -> pure (B.EngineOk (classMac spec kb msg))

  macVerify be spec key msg tag = runGuarded be "macVerify" (macSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk kb ->
        if ctEq (classMac spec kb msg) tag
          then pure (B.EngineOk True)
          else pure (B.EngineFail (BackendAuthFailed "macVerify"))

  sign be spec key msg = runGuarded be "sign" (sigSupported be spec) $ \env ->
    case dsaFloor spec msg <|> x931Floor spec msg of
      Just why -> pure (B.EngineFail (BackendBadParam "sign" why))
      Nothing -> do
        mkey <- resolveKeyBytes env key
        case mkey of
          B.EngineFail err -> pure (B.EngineFail err)
          B.EngineOk kb ->
            pure (B.EngineOk (classSignFor spec (signIdentity kb) msg))

  verify be spec key msg sig = runGuarded be "verify" (sigSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk kb -> case dsaFloor spec msg <|> x931Floor spec msg of
        Just why -> pure (B.EngineFail (BackendBadParam "verify" why))
        Nothing ->
          if ctEq (classSignFor spec (signIdentity kb) msg) sig
            then pure (B.EngineOk ())
            else pure (B.EngineFail (BackendAuthFailed "verify"))

  cipherEncrypt be spec key iv input
    | isWrapSpec spec = wrapRun be "cipherEncrypt" True spec key iv input
    | otherwise = cipherRun be "cipherEncrypt" spec key iv input

  cipherDecrypt be spec key iv input
    | isWrapSpec spec = wrapRun be "cipherDecrypt" False spec key iv input
    | otherwise = cipherRun be "cipherDecrypt" spec key iv input

  aeadEncrypt be spec key iv aad input = do
    r <- aeadRun be "aeadEncrypt" True spec key iv aad input BS.empty
    pure $ case r of
      B.EngineFail err -> B.EngineFail err
      B.EngineOk blob -> B.EngineOk (BS.splitAt (BS.length blob - aeadTagLen spec) blob)
  aeadDecrypt be spec key iv aad input tag =
    aeadRun be "aeadDecrypt" False spec key iv aad input tag
  pkeyEncrypt be (RsaOaep params) key input =
    runGuarded be "pkeyEncrypt" (oaepSupported be params) $ \env -> do
      mkey <- resolveKeyBytes env key
      case mkey of
        B.EngineFail err -> pure (B.EngineFail err)
        B.EngineOk kb ->
          pure (B.EngineOk (classOaepSeal (signIdentity kb) params input))
  pkeyEncrypt be RsaPkcs1 key input =
    runGuarded be "pkeyEncrypt" (pkcs1Supported be) $ \env -> do
      mkey <- resolveKeyBytes env key
      case mkey of
        B.EngineFail err -> pure (B.EngineFail err)
        B.EngineOk kb ->
          pure (B.EngineOk (classPkcs1Seal (signIdentity kb) input))
  pkeyEncrypt be RsaX509 key input =
    runGuarded be "pkeyEncrypt" (x509Supported be) $ \env -> do
      mkey <- resolveKeyBytes env key
      case mkey of
        B.EngineFail err -> pure (B.EngineFail err)
        B.EngineOk kb -> case rsaModulusOf kb of
          Nothing -> pure (B.EngineFail (BackendBadKey "pkeyEncrypt"
            "X.509 sealing needs an RSA key"))
          Just n -> case classX509Seal n input of
            Just ct -> pure (B.EngineOk ct)
            Nothing -> pure (B.EngineFail (BackendBadParam "pkeyEncrypt"
              "X.509 input is empty or wider than the modulus"))

  pkeyDecrypt be (RsaOaep params) key input =
    runGuarded be "pkeyDecrypt" (oaepSupported be params) $ \env -> do
      mkey <- resolveKeyBytes env key
      case mkey of
        B.EngineFail err -> pure (B.EngineFail err)
        B.EngineOk kb -> case classOaepOpen (signIdentity kb) params input of
          Just pt -> pure (B.EngineOk pt)
          Nothing -> pure (B.EngineFail (BackendAuthFailed "pkeyDecrypt"))
  pkeyDecrypt be RsaPkcs1 key input =
    runGuarded be "pkeyDecrypt" (pkcs1Supported be) $ \env -> do
      mkey <- resolveKeyBytes env key
      case mkey of
        B.EngineFail err -> pure (B.EngineFail err)
        B.EngineOk kb -> case classPkcs1Open (signIdentity kb) input of
          Just pt -> pure (B.EngineOk pt)
          Nothing -> pure (B.EngineFail (BackendAuthFailed "pkeyDecrypt"))
  pkeyDecrypt be RsaX509 key input =
    runGuarded be "pkeyDecrypt" (x509Supported be) $ \env -> do
      mkey <- resolveKeyBytes env key
      case mkey of
        B.EngineFail err -> pure (B.EngineFail err)
        B.EngineOk kb -> case rsaModulusOf kb of
          Nothing -> pure (B.EngineFail (BackendBadKey "pkeyDecrypt"
            "X.509 opening needs an RSA key"))
          Just n -> case classX509Open n input of
            Just pt -> pure (B.EngineOk pt)
            Nothing -> pure (B.EngineFail (BackendBadParam "pkeyDecrypt"
              "X.509 block mismatches the modulus width"))
  kemEncapsulate be spec pub = runGuarded be "kemEncapsulate" (kemSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env pub
    case mkey of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk kb -> case kemHalfOf kb of
        Just (alg, pid, 1)
          | alg == kemAlg spec -> do
              seed <- readMVar (seSeed env)
              pure (B.EngineOk (kemCt seed alg pid, kemSs seed pid))
          | otherwise -> pure (B.EngineFail (BackendBadKey "kemEncapsulate"
              "KEM parameter set mismatch"))
        _ -> pure (B.EngineFail (BackendBadKey "kemEncapsulate"
          "not a synthetic KEM public half"))
  kemDecapsulate be spec priv ct = runGuarded be "kemDecapsulate" (kemSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env priv
    case mkey of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk kb -> case kemHalfOf kb of
        Just (alg, pid, 0)
          | alg == kemAlg spec -> do
              seed <- readMVar (seSeed env)
              let good = kemCt seed alg pid
              if BS.length ct /= BS.length good
                then pure (B.EngineFail (BackendBadParam "kemDecapsulate"
                  "ciphertext length mismatch"))
                else if ctEq good ct
                  then pure (B.EngineOk (kemSs seed pid))
                  else pure (B.EngineFail (BackendAuthFailed "kemDecapsulate"))
          | otherwise -> pure (B.EngineFail (BackendBadKey "kemDecapsulate"
              "KEM parameter set mismatch"))
        _ -> pure (B.EngineFail (BackendBadKey "kemDecapsulate"
          "not a synthetic KEM private half"))

  ecdhDerive be spec priv peer = runGuarded be "ecdhDerive" (ecdhSupported be spec) $ \env -> do
    mpriv <- resolveKeyBytes env priv
    case mpriv of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk privB -> do
        mpeer <- resolveKeyBytes env peer
        case mpeer of
          B.EngineFail err -> pure (B.EngineFail err)
          B.EngineOk peerB ->
            let (agreeBase, agreePeer) = ecdhAgreeInputs privB peerB
            in pure (B.EngineOk (classEcdh spec agreeBase agreePeer))

  dhDerive be spec priv peer = runGuarded be "dhDerive" (dhSupported be spec) $ \env -> do
    mpriv <- resolveKeyBytes env priv
    case mpriv of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk privB -> do
        mpeer <- resolveKeyBytes env peer
        case mpeer of
          B.EngineFail err -> pure (B.EngineFail err)
          B.EngineOk peerB ->
            pure (B.EngineOk (classDh spec (signIdentity privB) peerB))

  -- Deterministic labeled double: 64 pseudorandom bytes over
  -- the base half, opaque to the SPKI parsers, so the finisher
  -- passes the derived object through unstamped (the keygen
  -- opaque-pair precedent). Same base, same double.
  pubFromPriv be priv = runGuarded be "pubFromPriv" Nothing $ \env -> do
    mpriv <- resolveKeyBytes env priv
    case mpriv of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk privB ->
        pure (B.EngineOk (prfBytes (frame ["haskoki-synth/pub-from-priv/v1", privB]) 64))

  generateKey be spec = runGuarded be "generateKey" (genSupported be spec) $ \env -> do
    ctr <- modifyMVar (seGenCtr env) $ \c -> pure (c + 1, c)
    seed <- readMVar (seSeed env)
    case spec of
      GenSym "AES" n
        | n `elem` [16, 24, 32] ->
            pure (B.EngineOk (KeyBytes (genSymBytes seed ctr "AES" n), Nothing))
        | otherwise -> pure (B.EngineFail (BackendBadParam "generateKey"
            "AES key length must be 16, 24, or 32 bytes"))
      GenSym "DES3" n
        | n `elem` [16, 24] ->
            pure (B.EngineOk (KeyBytes (genSymBytes seed ctr "DES3" n), Nothing))
        | otherwise -> pure (B.EngineFail (BackendBadParam "generateKey"
            "DES3 key length must be 16 or 24 bytes"))
      GenSym "HOTP" n
        | n >= hotpKeygenMinBytes && n <= hotpKeygenMaxBytes ->
            pure (B.EngineOk (KeyBytes (genSymBytes seed ctr "HOTP" n), Nothing))
        | otherwise -> pure (B.EngineFail (BackendBadParam "generateKey"
            "HOTP key length must be 16 to 64 bytes"))
      GenSym "GENERIC" n
        | n >= genericSecretKeygenMinBytes && n <= genericSecretKeygenMaxBytes ->
            pure (B.EngineOk (KeyBytes (genSymBytes seed ctr "GENERIC" n), Nothing))
        | otherwise -> pure (B.EngineFail (BackendBadParam "generateKey"
            "generic-secret key length must be 1 to 255 bytes"))
      GenSym "BLAKE2B-512-HMAC" n
        | n >= 1 && n <= 255 ->
            pure (B.EngineOk (KeyBytes (genSymBytes seed ctr "BLAKE2B-512-HMAC" n), Nothing))
        | otherwise -> pure (B.EngineFail (BackendBadParam "generateKey"
            "BLAKE2B-512-HMAC key length must be 1 to 255 bytes"))
      GenSym "ChaCha20" n
        | n == 32 ->
            pure (B.EngineOk (KeyBytes (genSymBytes seed ctr "ChaCha20" n), Nothing))
        | otherwise -> pure (B.EngineFail (BackendBadParam "generateKey"
            "ChaCha20 key length must be 32 bytes"))
      GenSym label n
        | Just bound <- lookup label symKeygenBounds
        , symLenBoundOk bound n ->
            pure (B.EngineOk (KeyBytes (genSymBytes seed ctr (BC8.pack label) n), Nothing))
        | Just bound <- lookup label symKeygenBounds ->
            pure (B.EngineFail (BackendBadParam "generateKey"
              (label ++ " keygen length out of range " ++ show bound ++ ": " ++ show n)))
      GenEC ec
        | genCurveOk (ecCurve ec) ->
            pure (B.EngineOk (genPair seed ctr))
        | otherwise -> pure (B.EngineFail
            (BackendUnsupported "generateKey" ("not in synthetic set: " ++ show spec)))
      GenRSA bits e
        | bits `elem` [2048, 3072, 4096]
        , e >= 3, odd e, e < 256 ^ (8 :: Int) ->
            pure (B.EngineOk (genRsaPair seed ctr bits e))
        | otherwise -> pure (B.EngineFail (BackendBadParam "generateKey"
            ("RSA keygen needs 2048/3072/4096 bits and an odd exponent 3..2^64-1: "
              ++ show spec)))
      GenDSAParams p q ->
        pure (B.EngineOk (KeyDer (synthDsaParams seed ctr p q), Nothing))
      GenDSAKeypair {} ->
        pure (B.EngineOk (genPair seed ctr))
      GenDHKeypair {} ->
        pure (B.EngineOk (genPair seed ctr))
      GenEdDSAKeypair {} ->
        pure (B.EngineOk (genPair seed ctr))
      GenXDHKeypair {} ->
        pure (B.EngineOk (genPair seed ctr))
      GenMLDSA {} ->
        pure (B.EngineOk (genPair seed ctr))
      GenSLHDSA {} ->
        pure (B.EngineOk (genPair seed ctr))
      GenMLKEM alg -> pure (B.EngineOk (genKemPair seed ctr alg))
      _ -> pure (B.EngineFail
        (BackendUnsupported "generateKey" ("not in synthetic set: " ++ show spec)))

  -- Seeded-stream bytes under the generation counter
  -- (same seed plus same call sequence replays; the "random"
  -- label domain-separates from keygen streams).
  randomBytes be n = runGuarded be "randomBytes" Nothing $ \env ->
    if n < 1
      then pure (B.EngineFail (BackendBadParam "randomBytes"
        ("length must be positive: " ++ show n)))
      else if n > B.generateRandomMaxBytes
        then pure (B.EngineFail (BackendBadParam "randomBytes"
          ("length longer than " ++ show B.generateRandomMaxBytes ++ " bytes: " ++ show n)))
        else do
        ctr <- modifyMVar (seGenCtr env) $ \c -> pure (c + 1, c)
        seed <- readMVar (seSeed env)
        pure (B.EngineOk (genSymBytes seed ctr "random" n))

  -- Reseed REPLACES the stream origin — the new seed plus a
  -- counter reset — so the same seed plus the same subsequent call
  -- sequence replays byte-identical bytes. Empty seeds are a
  -- vacuous OK (the origin is untouched); oversize seeds are
  -- 'BackendBadParam', mirroring the 'randomBytes' bounds style.
  -- Concurrency non-contract: the two 'modifyMVar's
  -- below (seed, then counter) are NOT atomic as a pair — a
  -- concurrent 'randomBytes' may observe the new seed with the
  -- old counter. Single-threaded engine use is unaffected.
  seedRandom be seedBytes = runGuarded be "seedRandom" Nothing $ \env ->
    if BS.length seedBytes > B.seedRandomMaxBytes
      then pure (B.EngineFail (BackendBadParam "seedRandom"
        ("seed longer than " ++ show B.seedRandomMaxBytes ++ " bytes")))
      else if BS.null seedBytes
        then pure (B.EngineOk ())
        else do
          modifyMVar (seSeed env) $ \_ ->
            pure (mix64 (fnv1a64 (frame ["haskoki-synth/seed-random/v1", seedBytes])), ())
          modifyMVar (seGenCtr env) $ \_ -> pure (0, ())
          pure (B.EngineOk ())

  importKey (SynthBackend env) mat = case mat of
    KeyRefMaterial r -> pure (B.EngineOk r)
    KeyBytes bs
      | BS.null bs -> pure (B.EngineFail (BackendBadKey "importKey" "empty key material"))
      | otherwise -> store mat
    KeyDer bs
      | BS.null bs -> pure (B.EngineFail (BackendBadKey "importKey" "empty key material"))
      | otherwise -> store mat
    where
      store m = do
        rid <- allocId env
        modifyMVar (seKeys env) $ \keys ->
          pure (Map.insert (unEngineResourceId rid) (SynthKey m) keys, ())
        pure (B.EngineOk (KeyRef rid (keyFamily m)))

  exportKey (SynthBackend env) (KeyRef rid _) = do
    mmat <- Map.lookup (unEngineResourceId rid) <$> readMVar (seKeys env)
    case mmat of
      Nothing -> pure (B.EngineFail (BackendResourceGone "exportKey" rid))
      Just k -> pure (B.EngineOk (skMat k))

  destroyKey (SynthBackend env) (KeyRef rid _) =
    modifyMVar (seKeys env) $ \m ->
      pure (Map.delete (unEngineResourceId rid) m, ())

  snapshotResource (SynthBackend env) rid = do
    digests <- readMVar (seDigests env)
    keys <- readMVar (seKeys env)
    let n = unEngineResourceId rid
    pure $ case (Map.lookup n digests, Map.lookup n keys) of
      (Just (alg, acc), _) -> Right (encodeDigestCtx alg acc)
      (_, Just k) -> Right (encodeKeyCtx k)
      (Nothing, Nothing) ->
        Left ("unsaveable: unknown synthetic resource " ++ show n)

  restoreResource (SynthBackend env) bs = case decodeDigestCtx bs of
    Just (alg, acc) -> do
      rid <- allocId env
      modifyMVar (seDigests env) $ \m ->
        pure (Map.insert (unEngineResourceId rid) (alg, acc) m, ())
      pure (B.EngineOk rid)
    Nothing -> case decodeKeyCtx bs of
      Just mat -> do
        rid <- allocId env
        modifyMVar (seKeys env) $ \m ->
          pure (Map.insert (unEngineResourceId rid) (SynthKey mat) m, ())
        pure (B.EngineOk rid)
      Nothing -> pure (B.EngineFail
        (BackendBadParam "restoreResource" "bad synthetic resource context"))

  releaseResource (SynthBackend env) rid =
    modifyMVar (seDigests env) $ \m ->
      pure (Map.delete (unEngineResourceId rid) m, ())

  resourceSaveability (SynthBackend env) rid = do
    digests <- readMVar (seDigests env)
    keys <- readMVar (seKeys env)
    let n = unEngineResourceId rid
    pure $ case (Map.lookup n digests, Map.lookup n keys) of
      (Just _, _) -> ResourceSaveable
      (_, Just _) -> ResourceSaveable
      (Nothing, Nothing) ->
        ResourceUnsaveable (UnsaveableGone rid)

-- | Parse the explicit open seed: a decimal 'Word64', nothing else.
parseSeed :: String -> Maybe Word64
parseSeed s = case reads s of
  [(n, "")] -> Just n
  _ -> Nothing

-- | The synthetic capability set: SHA-256 digest (one-shot and
-- multipart), full-tag HMAC-SHA-256, the 23-spec
-- block-cipher set (AES-256-CBC keeps the original stream bytes),
-- ECDSA P-256/SHA-256 (DER and RAW), symmetric, EC and ML-KEM key
-- generation, and deterministic ML-KEM encapsulation. Advertised
-- whole from slice 1; slices 2-5 fill the implementation behind
-- it.
synthCaps :: BackendCaps
synthCaps = synthCapsBuild ()
{-# NOINLINE synthCaps #-}

-- | The builder behind 'synthCaps', normalized by 'forceCaps' so the
-- shared table holds no thunk for two threads to race on (GHC
-- #27272). Exported only so a test can build a fresh copy and walk
-- it.
synthCapsBuild :: () -> BackendCaps
synthCapsBuild () = forceCaps BackendCaps
  { bcName = "synthetic"
  , bcVersion = "synthetic/1"
  , bcDigests = DigestCaps
      { dcAlgs = Set.fromList
          [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
          , D_SHA512_224, D_SHA512_256
          , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
          , D_RIPEMD160
          , D_BLAKE2B512
          , D_BLAKE2B160
          , D_BLAKE2B256
          , D_BLAKE2B384
          ]
      , dcMultipart = True, dcXof = True }
  , bcCiphers = CipherCaps
      { ccCiphers = Set.fromList synthCipherSpecs, ccAead = Set.fromList ["AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "AES-128-CCM", "AES-192-CCM", "AES-256-CCM", "ChaCha20-Poly1305"] }
  , bcMacs = MacCaps { mcSpecs = synthMacSpecs }
  , bcSigs = SigCaps
      { scSpecs = Set.fromList ("RSA-PSS" : synthRsaSpecNames ++ synthEcdsaSpecNames ++ synthDsaSpecNames ++ synthEddsaSpecNames ++ synthMldsaSpecNames ++ synthSlhdsaSpecNames)
      , scCurves = Set.fromList coveredCurveNames
      , scPqcSign = Set.fromList ([ML_DSA_44, ML_DSA_65, ML_DSA_87] ++ slhdsaSets)
      }
  , bcKems = KemCaps { kcAlgs = Set.fromList [ML_KEM_512, ML_KEM_768, ML_KEM_1024] }
  , bcKdfs = KdfCaps { kcKdfs = Set.fromList ["ECDH", "ECDH-COFACTOR", "DH"] }
  , bcParamNotes = Map.fromList
      ([ ("open", "decimal Word64 seed string; nothing else opens")
       , ("AES-256-CBC", "length-preserving stream construction; key 32 bytes, iv 16 bytes")
       ] ++ synthMacNotes ++ synthEcdsaNotes ++ synthDsaNotes ++ synthEddsaNotes ++ synthMldsaNotes ++ synthSlhdsaNotes ++
       [ ("RSA-PSS", "salt 0..64; hash/MGF any fixed-width digest")
       , ("RSA-OAEP", "deterministic labeled envelope; 16-byte tag; label free")
       , ("ECDH", "deterministic test agreement; 72-byte max-width secrets")
       , ("ECDH-COFACTOR", "deterministic test agreement; cofactor bit in domain")
       , ("keygen", "GenSym AES 16/24/32 bytes; GenSym DES3 16/24 bytes; GenSym HOTP 16-64 bytes; GenSym GENERIC 1-255 bytes; GenSym BLAKE2B-512-HMAC 1-255 bytes; GenSym sweep labels per symKeygenBounds; GenEC pairs on all 22 covered curves; GenRSA 2048/3072/4096-bit pairs (odd exponent 3..2^64-1); GenDSAParams approved (L,N) pairs; GenDSAKeypair opaque pairs; GenDHKeypair opaque pairs; GenEdDSAKeypair opaque pairs; GenXDHKeypair opaque pairs; GenMLDSA opaque pairs; GenSLHDSA opaque pairs; GenMLKEM pairs")
       , ("KEM", "deterministic test construction; standard ct lengths, 32-byte secrets")
       ])
  }
{-# NOINLINE synthCapsBuild #-}

digestSupported :: BackendEnv Synthetic -> DigestAlg -> Maybe String
digestSupported (SynthBackend env) alg
  | Set.member alg (dcAlgs (bcDigests (seCaps env))) = Nothing
  | otherwise = Just ("digest not in synthetic set: " ++ show alg)

xofSupported :: BackendEnv Synthetic -> DigestAlg -> Maybe String
xofSupported (SynthBackend env) alg = xofServable (seCaps env) alg

macSupported :: BackendEnv Synthetic -> MacSpec -> Maybe String
macSupported (SynthBackend env) spec
  | Just name <- hmacSpecCap spec
  , Set.member name (mcSpecs (bcMacs (seCaps env))) = Nothing
  | Just name <- poly1305SpecCap spec
  , Set.member name (mcSpecs (bcMacs (seCaps env))) = Nothing
  | otherwise = Just ("mac not in synthetic set: " ++ show spec)

sigSupported :: BackendEnv Synthetic -> SigSpec -> Maybe String
sigSupported (SynthBackend env) spec
  | Just name <- ecdsaSigCap spec
  , Set.member name (scSpecs (bcSigs (seCaps env))) = Nothing
  | Just name <- dsaSigCap spec
  , Set.member name (scSpecs (bcSigs (seCaps env))) = Nothing
  | Just name <- eddsaSigCap spec
  , Set.member name (scSpecs (bcSigs (seCaps env))) = Nothing
  | Just name <- mldsaSigCap spec
  , Set.member name (scSpecs (bcSigs (seCaps env))) = Nothing
  | Just name <- slhdsaSigCap spec
  , Set.member name (scSpecs (bcSigs (seCaps env))) = Nothing
  | Just name <- rsaSigCap spec
  , Set.member name (scSpecs (bcSigs (seCaps env))) = Nothing
  | Just name <- rsaPssCap spec
  , Set.member name (scSpecs (bcSigs (seCaps env))) = Nothing
  | Just name <- rsaX931Cap spec
  , Set.member name (scSpecs (bcSigs (seCaps env))) = Nothing
  | otherwise = Just ("signature not in synthetic set: " ++ show spec)

-- | ECDH availability: plain and cofactor agreements are served.
ecdhSupported :: BackendEnv Synthetic -> EcdhSpec -> Maybe String
ecdhSupported (SynthBackend env) spec
  | Set.member (ecdhCap spec) (kcKdfs (bcKdfs (seCaps env))) = Nothing
  | otherwise = Just ("ecdh not in synthetic set: " ++ show spec)

dhSupported :: BackendEnv Synthetic -> DhSpec -> Maybe String
dhSupported (SynthBackend env) spec
  | Set.member (dhCap spec) (kcKdfs (bcKdfs (seCaps env))) = Nothing
  | otherwise = Just ("dh not in synthetic set: " ++ show spec)

-- | OAEP availability: fixed-width hash and MGF (XOFs refused),
-- witnessed against the digest set; the label is always servable.
oaepSupported :: BackendEnv Synthetic -> OaepParams -> Maybe String
oaepSupported (SynthBackend env) params
  | Set.member (oaepHash params) (dcAlgs (bcDigests (seCaps env)))
  , Set.member (oaepMgf params) (dcAlgs (bcDigests (seCaps env))) = Nothing
  | otherwise = Just ("oaep not in synthetic set: " ++ show params)

-- | PKCS#1 v1.5 availability: the synthetic backend models v1.5
-- unconditionally (no digest or probe dimension).
pkcs1Supported :: BackendEnv Synthetic -> Maybe String
pkcs1Supported _ = Nothing

-- | X.509 availability: the synthetic backend models raw RSA
-- unconditionally (no digest or probe dimension).
x509Supported :: BackendEnv Synthetic -> Maybe String
x509Supported _ = Nothing

cipherSupported :: BackendEnv Synthetic -> CipherSpec -> Maybe String
cipherSupported (SynthBackend env) spec
  | Set.member (cipherSpecCanon spec) (ccCiphers (bcCiphers (seCaps env))) = Nothing
  | otherwise = Just ("cipher not in synthetic set: " ++ show spec)

-- | Shared encrypt/decrypt path: guard, key resolution, per-spec
-- shape checks ('cipherKeyLens' / 'cipherIvLenOk'), then the
-- length-preserving stream construction (XOR, so encrypt and
-- decrypt are one function).
cipherRun :: BackendEnv Synthetic -> String -> CipherSpec -> KeyMaterial
          -> ByteString -> ByteString -> IO (B.EngineResult ByteString)
cipherRun be op spec key iv input =
  runGuarded be op (cipherSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk kb
        | BS.length kb `notElem` cipherKeyLens spec ->
            pure (B.EngineFail (BackendBadParam op
              ("key length " ++ show (BS.length kb)
                ++ " not accepted by " ++ show spec)))
        | not (cipherIvLenOk spec (BS.length iv)) ->
            pure (B.EngineFail (BackendBadParam op
              ("iv length " ++ show (BS.length iv)
                ++ " not accepted by " ++ show spec)))
        | Just bits <- rc2BitsOf spec, bits < 1 || bits > 1024 ->
            pure (B.EngineFail (BackendBadParam op
              ("RC2 effective bits " ++ show bits
                ++ " outside 1..1024 (R2 fail-closed)")))
        | isXtsSpec spec && BS.length input < 16 ->
            pure (B.EngineFail (BackendBadParam op
              ("XTS input must be at least 16 bytes (IEEE 1619 data unit)")))
        | otherwise -> pure (B.EngineOk (classCipherFor spec kb iv input))

-- | Synthetic wrap path: same guards as 'cipherRun' plus the wrap
-- geometry (KW: multiple-of-8 input >= 16; KWP: non-empty input;
-- decrypt-side minimum ciphertexts), then the expanding test
-- construction. Decrypt refuses malformed blobs with BadParam
-- and integrity failures with AuthFailed, mirroring the real
-- backend's split.
wrapRun :: BackendEnv Synthetic -> String -> Bool -> CipherSpec -> KeyMaterial
          -> ByteString -> ByteString -> IO (B.EngineResult ByteString)
wrapRun be op enc spec key iv input =
  runGuarded be op (cipherSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk kb
        | BS.length kb `notElem` cipherKeyLens spec ->
            pure (B.EngineFail (BackendBadParam op
              ("key length " ++ show (BS.length kb)
                ++ " not accepted by " ++ show spec)))
        | not (cipherIvLenOk spec (BS.length iv)) ->
            pure (B.EngineFail (BackendBadParam op
              ("iv length " ++ show (BS.length iv)
                ++ " not accepted by " ++ show spec)))
        | isKwSpec spec && (BS.length input < 16 || BS.length input `mod` 8 /= 0) ->
            pure (B.EngineFail (BackendBadParam op
              ("KW input must be a multiple of 8, at least 16 bytes")))
        | isKwpSpec spec && BS.null input ->
            pure (B.EngineFail (BackendBadParam op
              ("KWP input must be non-empty")))
        | not enc && isKwSpec spec
          && (BS.length input < 24 || BS.length input `mod` 8 /= 0) ->
            pure (B.EngineFail (BackendBadParam op
              ("KW ciphertext must be a multiple of 8, at least 24 bytes")))
        | not enc && isKwpSpec spec
          && (BS.length input < 16 || BS.length input `mod` 8 /= 0) ->
            pure (B.EngineFail (BackendBadParam op
              ("KWP ciphertext must be a multiple of 8, at least 16 bytes")))
        | enc -> pure (B.EngineOk (synthWrapSeal spec kb iv input))
        | otherwise -> case synthWrapOpen spec kb iv input of
            Just pt -> pure (B.EngineOk pt)
            Nothing -> pure (B.EngineFail (BackendAuthFailed op))

aeadRun :: BackendEnv Synthetic -> String -> Bool -> AeadSpec -> KeyMaterial
  -> ByteString -> ByteString -> ByteString -> ByteString -> IO (B.EngineResult ByteString)
aeadRun be op enc spec key iv aad input tag =
  runGuarded be op (aeadSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk kb
        | BS.length kb /= aeadKeyLen (aeadAlg spec) ->
            pure (B.EngineFail (BackendBadParam op
              ("key length " ++ show (BS.length kb)
                ++ " not accepted by " ++ aeadAlg spec)))
        | aeadTagLen spec `notElem` aeadTagSet (aeadAlg spec) ->
            pure (B.EngineFail (BackendBadParam op
              ("tag length " ++ show (aeadTagLen spec) ++ " is not approved")))
        | aeadNonceLen spec < fst nonceBounds || aeadNonceLen spec > snd nonceBounds
          || BS.length iv /= aeadNonceLen spec ->
            pure (B.EngineFail (BackendBadParam op
              ("nonce length " ++ show (BS.length iv)
                ++ " does not match spec " ++ show (aeadNonceLen spec))))
        | not enc && BS.length tag /= aeadTagLen spec ->
            pure (B.EngineFail (BackendAuthFailed op))
        | enc -> let (ct, tg) = classAeadSeal kb spec iv aad input
                 in pure (B.EngineOk (ct <> tg))
        | otherwise -> case classAeadOpen kb spec iv aad input tag of
            Just pt -> pure (B.EngineOk pt)
            Nothing -> pure (B.EngineFail (BackendAuthFailed op))
  where
    nonceBounds
      | isCcmAlg (aeadAlg spec) = (7, 13)
      | otherwise = (1, 64)

-- | AEAD support: the three AES-GCM widths, the three
-- AES-CCM widths, and ChaCha20-Poly1305, with sane nonce/tag lengths.
aeadSupported :: BackendEnv Synthetic -> AeadSpec -> Maybe String
aeadSupported _ spec
  | aeadAlg spec `elem` ["AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "AES-128-CCM", "AES-192-CCM", "AES-256-CCM", "ChaCha20-Poly1305"] = Nothing
  | otherwise = Just ("aead not in synthetic set: " ++ show spec)

-- | Resolve key material to owned bytes: empty material is BadKey
-- (as with the retired record's prepare), registry references look
-- up, missing ones answer ResourceGone.
resolveKeyBytes :: SynthEnv -> KeyMaterial -> IO (B.EngineResult ByteString)
resolveKeyBytes _ (KeyBytes bs)
  | BS.null bs = pure (B.EngineFail (BackendBadKey "key" "empty key material"))
  | otherwise = pure (B.EngineOk bs)
resolveKeyBytes _ (KeyDer bs)
  | BS.null bs = pure (B.EngineFail (BackendBadKey "key" "empty key material"))
  | otherwise = pure (B.EngineOk bs)
resolveKeyBytes env (KeyRefMaterial (KeyRef rid _)) = do
  mmat <- Map.lookup (unEngineResourceId rid) <$> readMVar (seKeys env)
  case mmat of
    Nothing -> pure (B.EngineFail (BackendResourceGone "key" rid))
    Just (SynthKey (KeyBytes bs)) -> pure (B.EngineOk bs)
    Just (SynthKey (KeyDer bs)) -> pure (B.EngineOk bs)
    Just (SynthKey (KeyRefMaterial _)) -> pure (B.EngineFail
      (BackendInvalidState "key" "nested key reference"))

genSupported :: BackendEnv Synthetic -> KeyGenSpec -> Maybe String
genSupported _ spec = case spec of
  GenSym "AES" _ -> Nothing
  GenSym "DES3" _ -> Nothing
  GenSym "HOTP" _ -> Nothing
  GenSym "GENERIC" _ -> Nothing
  GenSym "BLAKE2B-512-HMAC" _ -> Nothing
  GenSym "ChaCha20" _ -> Nothing
  GenSym label _ | label `elem` map fst symKeygenBounds -> Nothing
  GenEC ec | genCurveOk (ecCurve ec) -> Nothing
  GenRSA {} -> Nothing
  GenDSAParams p q
    | (p, q) `elem` [(1024, 160), (2048, 224), (2048, 256), (3072, 256)] -> Nothing
  GenDSAKeypair {} -> Nothing
  GenDHKeypair {} -> Nothing
  GenEdDSAKeypair name | BC8.unpack name `elem` edwardsCurveNames -> Nothing
  GenXDHKeypair name | BC8.unpack name `elem` montgomeryCurveNames -> Nothing
  GenMLDSA alg | alg `elem` [ML_DSA_44, ML_DSA_65, ML_DSA_87] -> Nothing
  GenSLHDSA alg | alg `elem` slhdsaSets -> Nothing
  GenMLKEM _ -> Nothing
  _ -> Just ("keygen not in synthetic set: " ++ show spec)

kemSupported :: BackendEnv Synthetic -> KemSpec -> Maybe String
kemSupported _ _ = Nothing

-- | Key snapshot layout: @0x01 || kind(1) || keyLen BE(4) || key@;
-- kind 1 is symmetric bytes, 2 is DER.
encodeKeyCtx :: SynthKey -> ByteString
encodeKeyCtx (SynthKey mat) = case mat of
  KeyBytes bs -> BS.singleton 1 <> BS.singleton 1 <> word32BE (BS.length bs) <> bs
  KeyDer bs -> BS.singleton 1 <> BS.singleton 2 <> word32BE (BS.length bs) <> bs
  KeyRefMaterial _ -> BS.singleton 1 <> BS.singleton 0 <> word32BE 0

-- | Strict parse: version skew, unknown kind, truncation, or any
-- trailing byte rejects. References never persist (kind 0 is
-- unrepresentable on the way back in).
decodeKeyCtx :: ByteString -> Maybe KeyMaterial
decodeKeyCtx bs = case BS.uncons bs of
  Just (1, r1) -> case BS.uncons r1 of
    Just (kind, r2)
      | kind == 1 || kind == 2 -> do
          let (lenBs, r3) = BS.splitAt 4 r2
          guard (BS.length lenBs == 4)
          let n = getWord32BE lenBs
              (keyBs, rest) = BS.splitAt n r3
          guard (BS.length keyBs == n && BS.null rest)
          Just (if kind == 1 then KeyBytes keyBs else KeyDer keyBs)
    _ -> Nothing
  _ -> Nothing

-- | Allocate a fresh resource id from the shared counter.
allocId :: SynthEnv -> IO EngineResourceId
allocId env = modifyMVar (seNextId env) $ \n -> pure (n + 1, EngineResourceId n)

-- | Guard-then-run: the capability check answers FIRST (even on a
-- closed backend, so the guard-before-state law is observable), then
-- the closed check, then the call.
runGuarded :: BackendEnv Synthetic -> String -> Maybe String
           -> (SynthEnv -> IO (B.EngineResult a)) -> IO (B.EngineResult a)
runGuarded (SynthBackend env) op miss action = case miss of
  Just why -> pure (B.EngineFail (BackendUnsupported op why))
  Nothing -> do
    closed <- readMVar (seClosed env)
    if closed
      then pure (B.EngineFail (BackendInvalidState op "backend is closed"))
      else action env
