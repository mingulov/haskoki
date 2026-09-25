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
* cipher: length-preserving reversible stream construction;
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
  , synthKeyContextVersion
  ) where

import Control.Concurrent.MVar (MVar, modifyMVar, newMVar, readMVar)
import Control.Monad (guard)
import Data.Bits ((.|.), shiftR, xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Word (Word8, Word32, Word64)

import Haskoki.Engine.Backend
  ( AeadSpec (..)
  , BackendCaps (..)
  , BackendError (..)
  , CipherCaps (..)
  , CipherSpec (..)
  , cipherIvLen
  , cipherKeyLens
  , CryptoBackend (..)
  , DigestAlg (..)
  , DigestCaps (..)
  , digestMacStem
  , digestOutLen
  , ecdhCap
  , EcdhSpec (..)
  , ecdsaSigCap
  , EcSpec (..)
  , hmacSpecCap
  , KdfCaps (..)
  , KemCaps (..)
  , KemSpec (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , KeyRef (..)
  , MacCaps (..)
  , MacSpec (..)
  , OaepParams (..)
  , PqcKemAlg (..)
  , RsaCipherParams (..)
  , ResourceSaveability (..)
  , rsaSigCap
  , rsaPssCap
  , SigCaps (..)
  , SigSpec (..)
  , UnsaveableReason (..)
  )
import Haskoki.Der
  ( RsaCrt (..)
  , coveredCurveNames
  , curveTable
  , integerToBE
  , parseRsaPrivate
  , parseRsaPublic
  , rsaPrivateDer
  , rsaPublicDer
  )
import qualified Haskoki.Engine.Backend as B
import Haskoki.Operation.KeyManagement
  (genericSecretKeygenMaxBytes, genericSecretKeygenMinBytes)
import Haskoki.Recipe.Ecdh (ecdhSecretWidthMax)
import Haskoki.Recipe.Otp (hotpKeygenMaxBytes, hotpKeygenMinBytes)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Types (EngineResourceId (..))

-- ---------------------------------------------------------------------------
-- Shape contracts
-- ---------------------------------------------------------------------------

-- | Synthetic digest output length (bytes): the SHA-256 width, kept
-- as the historical alias. Prefer 'synthDigestLengthFor'.
synthDigestLength :: Int
synthDigestLength = 32

-- | Synthetic digest output length per algorithm (bytes), matching
-- the real digest widths ('Haskoki.Recipe.Digest' pins the same
-- table; SyntheticSpec executes it).
synthDigestLengthFor :: DigestAlg -> Int
synthDigestLengthFor alg = case alg of
  D_MD5 -> 16
  D_SHA1 -> 20
  D_SHA224 -> 28
  D_SHA256 -> 32
  D_SHA384 -> 48
  D_SHA512 -> 64
  D_SHA512_224 -> 28
  D_SHA512_256 -> 32
  D_SHA3_224 -> 28
  D_SHA3_256 -> 32
  D_SHA3_384 -> 48
  D_SHA3_512 -> 64
  D_RIPEMD160 -> 20
  D_SHAKE128 -> 32
  D_SHAKE256 -> 64

-- | Synthetic MAC output length (bytes).
synthMacLength :: Int
synthMacLength = 32

-- | Synthetic signature output length (bytes).
synthSigLength :: Int
synthSigLength = 64

-- | Synthetic ECDH secret width (bytes): the maximum over the
-- covered curves (the recipe's 'ecdhSecretWidthMax'). Synthetic
-- keys are opaque bytes with no scannable curve, so agreements
-- always emit the max width and the driver truncates to the
-- planned length.
synthEcdhWidth :: Int
synthEcdhWidth = ecdhSecretWidthMax

-- | Synthetic key-context format version (first context byte).
synthKeyContextVersion :: Word8
synthKeyContextVersion = 1

-- ---------------------------------------------------------------------------
-- Deterministic core: FNV-1a accumulation, splitmix64 expansion
-- ---------------------------------------------------------------------------

-- | FNV-1a 64-bit accumulation over domain-framed input.
fnv1a64 :: ByteString -> Word64
fnv1a64 = BS.foldl' step 14695981039346656037
  where
    step :: Word64 -> Word8 -> Word64
    step h b = (h `xor` fromIntegral b) * 1099511628211

-- | splitmix64 finalizer: good avalanche for nearby inputs.
mix64 :: Word64 -> Word64
mix64 z0 =
  let z1 = (z0 `xor` (z0 `shiftR` 30)) * 0xBF58476D1CE4E5B9
      z2 = (z1 `xor` (z1 `shiftR` 27)) * 0x94D049BB133111EB
  in z2 `xor` (z2 `shiftR` 31)

word64BE :: Word64 -> ByteString
word64BE w = BS.pack [byte s | s <- [56, 48 .. 0]]
  where byte s = fromIntegral (w `shiftR` s)

word64LE :: Word64 -> ByteString
word64LE w = BS.pack [byte s | s <- [0, 8 .. 56]]
  where byte s = fromIntegral (w `shiftR` s)

word32BE :: Int -> ByteString
word32BE n = BS.pack
  [ fromIntegral (n `shiftR` 24)
  , fromIntegral (n `shiftR` 16)
  , fromIntegral (n `shiftR` 8)
  , fromIntegral n
  ]

getWord32BE :: ByteString -> Int
getWord32BE = BS.foldl' (\a b -> a * 256 + fromIntegral b) 0

-- | Length-prefixed framing so concatenated domains stay unambiguous.
frame :: [ByteString] -> ByteString
frame = BS.concat . map (\p -> word32BE (BS.length p) <> p)

-- | Domain-separated expansion to exactly @n@ bytes.
prfBytes :: ByteString -> Int -> ByteString
prfBytes domain n
  | n <= 0 = BS.empty
  | otherwise =
      let seed = fnv1a64 domain
          need = (n + 7) `div` 8
      in BS.take n (BS.concat [word64LE (mix64 (seed + fromIntegral i)) | i <- [0 .. need - 1]])

encodeMech :: MechanismId -> ByteString
encodeMech (MechanismId w) = word64BE w

-- ---------------------------------------------------------------------------
-- Versioned RNG streams
-- ---------------------------------------------------------------------------

-- | Fixture seed.
newtype Seed = Seed { unSeed :: Word64 }
  deriving (Eq, Show)

-- | Logical operation number within a schedule. Backends derive
-- independent randomness streams from (seed, operation) so that
-- schedule order and thread interleaving do not move an operation's
-- results; only the same seed plus the same schedule replays.
-- (Moved here from the retired original record: it keys synthetic
-- RNG streams, nothing else.)
newtype OpNumber = OpNumber { unOpNumber :: Word64 }
  deriving (Eq, Ord, Show)

-- | Independent per-operation stream: @(seed, operation, counter)@.
data RngStream = RngStream
  { rsSeed :: !Word64
  , rsStream :: !Word64
  , rsCounter :: !Word64
  } deriving (Eq, Show)

-- | Derive the independent stream for one logical operation.
deriveStream :: Seed -> OpNumber -> RngStream
deriveStream (Seed s) (OpNumber n) = RngStream s n 0

-- | Draw exactly @n@ bytes, advancing the counter by words consumed.
nextBytes :: Int -> RngStream -> (ByteString, RngStream)
nextBytes n rs@(RngStream seed stream ctr)
  | n <= 0 = (BS.empty, rs)
  | otherwise =
      let base = seed + stream * 0x9E3779B97F4A7C15 + ctr
          need = (n + 7) `div` 8
          out = BS.take n (BS.concat
            [word64LE (mix64 (base + fromIntegral i)) | i <- [0 .. need - 1]])
      in (out, rs { rsCounter = ctr + fromIntegral need })

-- ---------------------------------------------------------------------------
-- Seeded keygen streams
-- ---------------------------------------------------------------------------

-- | Keygen bytes from the backend seed folded with the derivation
-- domain, drawn from the generation counter's independent stream, so
-- the same seed plus the same call sequence replays.
streamKeyBytes :: Word64 -> OpNumber -> ByteString -> Int -> ByteString
streamKeyBytes seed op extra n =
  fst (nextBytes n (deriveStream (Seed (seed `xor` fnv1a64 extra)) op))

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

-- | Deterministic fixture material: owned bytes, the 32-byte object
-- identity, and the shared pair identity for halves. Byte-identical
-- to the retired record's fixtures (same domains, new home).
data FixtureMaterial = FixtureMaterial
  { fmBytes :: !ByteString
  , fmIdentity :: !ByteString
  , fmPair :: !(Maybe ByteString)
  } deriving (Eq, Show)

-- | Object identity: the same @keyid/v1@ expansion the retired
-- record used, over owned bytes.
fixtureIdentity :: ByteString -> ByteString
fixtureIdentity mat =
  prfBytes (frame ["haskoki-synth/keyid/v1", mat]) 32

-- | Pair identity over two halves, as the retired record built it.
fixturePairIdentity :: ByteString -> ByteString -> ByteString
fixturePairIdentity pubBytes privBytes = fixtureIdentity
  (frame ["haskoki-synth/pair/v1", pubBytes, privBytes])

-- | Deterministic fixture key: same @(mechanism, seed, label) gives
-- the same material. Fixed 32-byte documented test shape.
fixtureKey :: MechanismId -> Seed -> Text -> FixtureMaterial
fixtureKey mech (Seed s) label =
  FixtureMaterial bytes (fixtureIdentity bytes) Nothing
  where
    bytes = prfBytes
      (frame ["haskoki-synth/fixture/v1", encodeMech mech, word64BE s, TE.encodeUtf8 label])
      32

-- | Deterministic fixture key pair sharing one pair identity.
fixtureKeyPair :: MechanismId -> Seed -> Text -> (FixtureMaterial, FixtureMaterial)
fixtureKeyPair mech (Seed s) label =
  let pair = fixturePairIdentity pubBytes privBytes
  in ( FixtureMaterial pubBytes (fixtureIdentity pubBytes) (Just pair)
     , FixtureMaterial privBytes (fixtureIdentity privBytes) (Just pair)
     )
  where
    pubBytes = prfBytes (frame
      ["haskoki-synth/fixture-pub/v1", encodeMech mech, word64BE s, TE.encodeUtf8 label]) 32
    privBytes = prfBytes (frame
      ["haskoki-synth/fixture-priv/v1", encodeMech mech, word64BE s, TE.encodeUtf8 label]) 32

-- ---------------------------------------------------------------------------
-- CryptoBackend class instance (primary home)
-- ---------------------------------------------------------------------------
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

  sign be spec key msg = runGuarded be "sign" (sigSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk kb ->
        pure (B.EngineOk (classSignFor spec (signIdentity kb) msg))

  verify be spec key msg sig = runGuarded be "verify" (sigSupported be spec) $ \env -> do
    mkey <- resolveKeyBytes env key
    case mkey of
      B.EngineFail err -> pure (B.EngineFail err)
      B.EngineOk kb ->
        if ctEq (classSignFor spec (signIdentity kb) msg) sig
          then pure (B.EngineOk ())
          else pure (B.EngineFail (BackendAuthFailed "verify"))

  cipherEncrypt be spec key iv input =
    cipherRun be "cipherEncrypt" spec key iv input

  cipherDecrypt be spec key iv input =
    cipherRun be "cipherDecrypt" spec key iv input

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
            pure (B.EngineOk (classEcdh spec (signIdentity privB) peerB))

  generateKey be spec = runGuarded be "generateKey" (genSupported be spec) $ \env -> do
    ctr <- modifyMVar (seGenCtr env) $ \c -> pure (c + 1, c)
    seed <- readMVar (seSeed env)
    case spec of
      GenSym "AES" n
        | n `elem` [16, 24, 32] ->
            pure (B.EngineOk (KeyBytes (genSymBytes seed ctr "AES" n), Nothing))
        | otherwise -> pure (B.EngineFail (BackendBadParam "generateKey"
            "AES key length must be 16, 24, or 32 bytes"))
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
synthCaps = BackendCaps
  { bcName = "synthetic"
  , bcVersion = "synthetic/1"
  , bcDigests = DigestCaps
      { dcAlgs = Set.fromList
          [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
          , D_SHA512_224, D_SHA512_256
          , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
          , D_RIPEMD160
          ]
      , dcMultipart = True, dcXof = False }
  , bcCiphers = CipherCaps
      { ccCiphers = Set.fromList synthCipherSpecs, ccAead = Set.fromList ["AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "AES-128-CCM", "AES-192-CCM", "AES-256-CCM"] }
  , bcMacs = MacCaps { mcSpecs = synthMacSpecs }
  , bcSigs = SigCaps
      { scSpecs = Set.fromList ("RSA-PSS" : synthRsaSpecNames ++ synthEcdsaSpecNames)
      , scCurves = Set.fromList coveredCurveNames
      , scPqcSign = Set.empty
      }
  , bcKems = KemCaps { kcAlgs = Set.fromList [ML_KEM_512, ML_KEM_768, ML_KEM_1024] }
  , bcKdfs = KdfCaps { kcKdfs = Set.fromList ["ECDH", "ECDH-COFACTOR"] }
  , bcParamNotes = Map.fromList
      ([ ("open", "decimal Word64 seed string; nothing else opens")
       , ("AES-256-CBC", "length-preserving stream construction; key 32 bytes, iv 16 bytes")
       ] ++ synthMacNotes ++ synthEcdsaNotes ++
       [ ("RSA-PSS", "salt 0..64; hash/MGF any fixed-width digest")
       , ("RSA-OAEP", "deterministic labeled envelope; 16-byte tag; label free")
       , ("ECDH", "deterministic test agreement; 72-byte max-width secrets")
       , ("ECDH-COFACTOR", "deterministic test agreement; cofactor bit in domain")
       , ("keygen", "GenSym AES 16/24/32 bytes; GenSym HOTP 16-64 bytes; GenSym GENERIC 1-255 bytes; GenEC pairs on all 22 covered curves; GenRSA 2048/3072/4096-bit pairs (odd exponent 3..2^64-1); GenMLKEM pairs")
       , ("KEM", "deterministic test construction; standard ct lengths, 32-byte secrets")
       ])
  }

digestSupported :: BackendEnv Synthetic -> DigestAlg -> Maybe String
digestSupported (SynthBackend env) alg
  | Set.member alg (dcAlgs (bcDigests (seCaps env))) = Nothing
  | otherwise = Just ("digest not in synthetic set: " ++ show alg)

-- | The synthetic MAC set: plain and GENERAL names for
-- every fixed-width digest (derived through 'hmacSpecCap', so the
-- advertised set and the guard can never disagree).
synthMacSpecs :: Set.Set String
synthMacSpecs = Set.fromList
  [ name
  | alg <- [minBound .. maxBound]
  , spec <- [MacHMAC alg Nothing, MacHMAC alg (Just 1)]
  , Just name <- [hmacSpecCap spec]
  ]

-- | The RSA names: one PKCS#1 v1.5 name per recipe digest
-- plus the raw row (exactly the OpenSSL4 pre-probe set, so both
-- engines advertise the same names).
synthRsaSpecNames :: [String]
synthRsaSpecNames =
  [ name
  | spec <- SigRSA_Raw : map SigRSA_PKCS1v15 synthRsaAlgs
  , Just name <- [rsaSigCap spec]
  ]
  where
    synthRsaAlgs =
      [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
      , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
      , D_RIPEMD160
      ]

-- | The ECDSA names: one hash-and-sign name per (curve,
-- fixed-width digest) plus the raw row per curve (exactly the
-- OpenSSL4 pre-probe set over its digest set, so both engines
-- advertise the same names).
synthEcdsaSpecNames :: [String]
synthEcdsaSpecNames =
  [ name
  | curve <- coveredCurveNames
  , spec <- SigECDSA (EcSpec curve "DER") Nothing :
      [ SigECDSA (EcSpec curve "DER") (Just alg) | alg <- synthEcdsaAlgs ]
  , Just name <- [ecdsaSigCap spec]
  ]
  where
    synthEcdsaAlgs =
      [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
      , D_SHA512_224, D_SHA512_256
      , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
      , D_RIPEMD160
      ]

-- | Per-name MAC parameter notes for the capability report.
synthMacNotes :: [(String, String)]
synthMacNotes =
  [ note
  | alg <- [minBound .. maxBound]
  , Just stem <- [digestMacStem alg]
  , Just w <- [digestOutLen alg]
  , note <-
      [ ("HMAC-" ++ stem, "full " ++ show w ++ "-byte tag")
      , ("HMAC-" ++ stem ++ "-GENERAL"
        , "tag truncated to the requested 1.." ++ show w ++ " bytes")
      ]
  ]

-- | Per-name ECDSA parameter notes for the capability report.
synthEcdsaNotes :: [(String, String)]
synthEcdsaNotes =
  [ (name, note spec)
  | curve <- coveredCurveNames
  , spec <- SigECDSA (EcSpec curve "DER") Nothing :
      [ SigECDSA (EcSpec curve "DER") (Just alg)
      | alg <- [minBound .. maxBound]
      ]
  , Just name <- [ecdsaSigCap spec]
  ]
  where
    note (SigECDSA _ Nothing) = "raw operation, no hashing; encodings DER and RAW"
    note _ = "hash-and-sign; encodings DER and RAW"

macSupported :: BackendEnv Synthetic -> MacSpec -> Maybe String
macSupported (SynthBackend env) spec
  | Just name <- hmacSpecCap spec
  , Set.member name (mcSpecs (bcMacs (seCaps env))) = Nothing
  | otherwise = Just ("mac not in synthetic set: " ++ show spec)

sigSupported :: BackendEnv Synthetic -> SigSpec -> Maybe String
sigSupported (SynthBackend env) spec
  | Just name <- ecdsaSigCap spec
  , Set.member name (scSpecs (bcSigs (seCaps env))) = Nothing
  | Just name <- rsaSigCap spec
  , Set.member name (scSpecs (bcSigs (seCaps env))) = Nothing
  | Just name <- rsaPssCap spec
  , Set.member name (scSpecs (bcSigs (seCaps env))) = Nothing
  | otherwise = Just ("signature not in synthetic set: " ++ show spec)

-- | ECDH availability: plain and cofactor agreements are served.
ecdhSupported :: BackendEnv Synthetic -> EcdhSpec -> Maybe String
ecdhSupported (SynthBackend env) spec
  | Set.member (ecdhCap spec) (kcKdfs (bcKdfs (seCaps env))) = Nothing
  | otherwise = Just ("ecdh not in synthetic set: " ++ show spec)

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

-- | The cipher set: every backend spec the block-cipher
-- recipe reaches (AES/ARIA/CAMELLIA CBC+ECB at three widths plus
-- Triple-DES CBC+ECB). The CTR specs stay out until the streaming
-- slice wires them to a mechanism.
synthCipherSpecs :: [CipherSpec]
synthCipherSpecs =
  [ C_AES128_CBC, C_AES192_CBC, C_AES256_CBC
  , C_AES128_CTR, C_AES192_CTR, C_AES256_CTR
  , C_AES128_ECB, C_AES192_ECB, C_AES256_ECB
  , C_AES128_CTS, C_AES192_CTS, C_AES256_CTS
  , C_AES128_CFB128, C_AES192_CFB128, C_AES256_CFB128
  , C_AES128_CFB8, C_AES192_CFB8, C_AES256_CFB8
  , C_AES128_CFB1, C_AES192_CFB1, C_AES256_CFB1
  , C_AES128_OFB, C_AES192_OFB, C_AES256_OFB
  , C_DES3_CBC, C_DES3_ECB
  , C_ARIA128_CBC, C_ARIA192_CBC, C_ARIA256_CBC
  , C_ARIA128_ECB, C_ARIA192_ECB, C_ARIA256_ECB
  , C_CAMELLIA128_CBC, C_CAMELLIA192_CBC, C_CAMELLIA256_CBC
  , C_CAMELLIA128_ECB, C_CAMELLIA192_ECB, C_CAMELLIA256_ECB
  ]

cipherSupported :: BackendEnv Synthetic -> CipherSpec -> Maybe String
cipherSupported (SynthBackend env) spec
  | Set.member spec (ccCiphers (bcCiphers (seCaps env))) = Nothing
  | otherwise = Just ("cipher not in synthetic set: " ++ show spec)

-- | Shared encrypt/decrypt path: guard, key resolution, per-spec
-- shape checks ('cipherKeyLens' / 'cipherIvLen'), then the
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
        | BS.length iv /= cipherIvLen spec ->
            pure (B.EngineFail (BackendBadParam op
              ("iv length " ++ show (BS.length iv)
                ++ " not accepted by " ++ show spec)))
        | otherwise -> pure (B.EngineOk (classCipherFor spec kb iv input))

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

-- | AEAD support: the three AES-GCM widths and the three
-- AES-CCM widths with sane nonce/tag lengths.
aeadSupported :: BackendEnv Synthetic -> AeadSpec -> Maybe String
aeadSupported _ spec
  | aeadAlg spec `elem` ["AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "AES-128-CCM", "AES-192-CCM", "AES-256-CCM"] = Nothing
  | otherwise = Just ("aead not in synthetic set: " ++ show spec)

-- | CCM algorithm names take the CCM bounds.
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

-- | Seal under the synthetic AEAD: PRF keystream XOR plus a tag
-- over (key, nonce, aad, body). Deterministic; NOT real GCM.
classAeadSeal :: ByteString -> AeadSpec -> ByteString -> ByteString -> ByteString -> (ByteString, ByteString)
classAeadSeal kb spec iv aad input = (body, tag)
  where
    body = BS.packZipWith xor
      (prfBytes (frame ["haskoki-synth/aead-ct/v1", kb, iv]) (BS.length input))
      input
    tag = prfBytes
      (frame ["haskoki-synth/aead-tag/v1", kb, iv, aad, body])
      (aeadTagLen spec)

-- | Open a synthetic AEAD envelope: the tag must match exactly
-- (constant-time) or the whole open is 'Nothing'.
classAeadOpen :: ByteString -> AeadSpec -> ByteString -> ByteString -> ByteString -> ByteString -> Maybe ByteString
classAeadOpen kb spec iv aad body tag
  | not (ctEq tag want) = Nothing
  | otherwise = Just (BS.packZipWith xor
      (prfBytes (frame ["haskoki-synth/aead-ct/v1", kb, iv]) (BS.length body))
      body)
  where
    want = prfBytes
      (frame ["haskoki-synth/aead-tag/v1", kb, iv, aad, body])
      (aeadTagLen spec)

-- | Signature encoding tag carried into the construction (the guard
-- admits DER and RAW only; anything else never reaches here).
sigEncoding :: SigSpec -> ByteString
sigEncoding (SigECDSA ec _)
  | ecEncoding ec == "RAW" = "RAW"
  | otherwise = "DER"
sigEncoding _ = "DER"

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

-- | Synthetic keygen admits every covered curve: pairs are opaque
-- tagged bytes (see 'genPair'), so no per-curve material applies.
genCurveOk :: String -> Bool
genCurveOk c = BC8.pack c `elem` [n | (n, _, _) <- curveTable]

genSupported :: BackendEnv Synthetic -> KeyGenSpec -> Maybe String
genSupported _ spec = case spec of
  GenSym "AES" _ -> Nothing
  GenSym "HOTP" _ -> Nothing
  GenSym "GENERIC" _ -> Nothing
  GenEC ec | genCurveOk (ecCurve ec) -> Nothing
  GenRSA {} -> Nothing
  GenMLKEM _ -> Nothing
  _ -> Just ("keygen not in synthetic set: " ++ show spec)

kemSupported :: BackendEnv Synthetic -> KemSpec -> Maybe String
kemSupported _ _ = Nothing

-- | Symmetric key bytes from the backend seed and the generation
-- counter: the same seed plus the same call sequence replays. The
-- algorithm label domain-separates the streams, so e.g. HOTP keys
-- never collide with AES keys at equal lengths.
genSymBytes :: Word64 -> Word64 -> ByteString -> Int -> ByteString
genSymBytes seed ctr alg n =
  streamKeyBytes seed (OpNumber ctr)
    (frame ["haskoki-synth/class-keygen/v1", alg, word32BE n]) n

-- | A tagged P-256 pair: both halves share one pair identity, each
-- carrying its own role byte and material. Layout per half:
-- @"HKS1" || pairId(32) || role(1) || mat(32)@; role 0 is private.
genPair :: Word64 -> Word64 -> (KeyMaterial, Maybe KeyMaterial)
genPair seed ctr = (KeyDer priv, Just (KeyDer pub))
  where
    pairId = prfBytes
      (frame ["haskoki-synth/class-pair/v1", word64BE seed, word64BE ctr]) 32
    privM = streamKeyBytes seed (OpNumber ctr)
      (frame ["haskoki-synth/class-pair-priv/v1"]) 32
    pubM = streamKeyBytes seed (OpNumber ctr)
      (frame ["haskoki-synth/class-pair-pub/v1"]) 32
    priv = "HKS1" <> pairId <> BS.singleton 0 <> privM
    pub = "HKS1" <> pairId <> BS.singleton 1 <> pubM

-- | The signing identity: pair halves sign under the shared pair
-- identity, RSA DER halves under their shared modulus, raw keys
-- under their own bytes. The modulus rule lets generated RSA
-- pairs roundtrip sign/verify (both halves carry n) while every
-- distinct key still owns a distinct identity.
signIdentity :: ByteString -> ByteString
signIdentity kb = case pairIdOf kb of
  Just pid -> pid
  Nothing -> case rsaModulusOf kb of
    Just n -> n
    Nothing -> kb

-- | The RSA modulus when the bytes are an RSA SPKI or PKCS#8
-- half (either side of a generated or planted pair).
rsaModulusOf :: ByteString -> Maybe ByteString
rsaModulusOf kb = case parseRsaPublic kb of
  Just (n, _) -> Just n
  Nothing -> crtN <$> parseRsaPrivate kb

-- | Parse a generated pair half back to its pair identity (strict:
-- exact 69 bytes, magic, role 0 or 1).
pairIdOf :: ByteString -> Maybe ByteString
pairIdOf bs = do
  guard (BS.length bs == 69)
  let (magic, r1) = BS.splitAt 4 bs
  guard (magic == "HKS1")
  let (pid, r2) = BS.splitAt 32 r1
  (role, _) <- BS.uncons r2
  guard (role == 0 || role == 1)
  Just pid

-- | A tagged ML-KEM pair: like 'genPair' but under the @HKS2@ magic
-- with a parameter-set byte, so KEM halves never parse as EC halves
-- and vice versa. Layout per half: @"HKS2" || alg(1) || pairId(32)
-- || role(1) || mat(32)@; role 0 is private.
genKemPair :: Word64 -> Word64 -> PqcKemAlg -> (KeyMaterial, Maybe KeyMaterial)
genKemPair seed ctr alg = (KeyDer priv, Just (KeyDer pub))
  where
    tag = BS.singleton (kemAlgByte alg)
    pairId = prfBytes
      (frame ["haskoki-synth/kem-pair/v1", word64BE seed, word64BE ctr, tag]) 32
    privM = streamKeyBytes seed (OpNumber ctr)
      (frame ["haskoki-synth/kem-pair-priv/v1", tag]) 32
    pubM = streamKeyBytes seed (OpNumber ctr)
      (frame ["haskoki-synth/kem-pair-pub/v1", tag]) 32
    priv = "HKS2" <> tag <> pairId <> BS.singleton 0 <> privM
    pub = "HKS2" <> tag <> pairId <> BS.singleton 1 <> pubM

-- | A deterministic test RSA pair: well-formed PKCS#8/SPKI DER
-- around PRF-drawn components (NOT real RSA math; the fixed
-- construction is what makes model tests replay). Both halves
-- share the modulus, so 'signIdentity' unites them for
-- sign/verify roundtrips exactly like the @HKS1@ pair identity
-- does for EC. The exponent is the requested one in minimal
-- big-endian form; primes and CRT parts are top-bit-set PRF
-- bytes at the standard widths.
genRsaPair :: Word64 -> Word64 -> Int -> Integer -> (KeyMaterial, Maybe KeyMaterial)
genRsaPair seed ctr bits e = (KeyDer priv, Just (KeyDer pub))
  where
    nLen = bits `div` 8
    halfLen = bits `div` 16
    base = frame ["haskoki-synth/rsa-pair/v1", word64BE seed, word64BE ctr,
      word64BE (fromIntegral bits), integerToBE e]
    comp label len = topBit (prfBytes (base <> label) len)
    n = comp "n" nLen
    eBs = integerToBE e
    d = comp "d" nLen
    p = comp "p" halfLen
    q = comp "q" halfLen
    dp = comp "dp" halfLen
    dq = comp "dq" halfLen
    qi = comp "qinv" halfLen
    priv = rsaPrivateDer n eBs d p q dp dq qi
    pub = rsaPublicDer n eBs
    topBit bs = case BS.uncons bs of
      Just (b, rest) -> BS.cons (b .|. 0x80) rest
      Nothing -> bs

-- | Parse a KEM half back to its parameter set, pair identity and
-- role (strict: exact 70 bytes, @HKS2@ magic, known set, role 0/1).
kemHalfOf :: ByteString -> Maybe (PqcKemAlg, ByteString, Word8)
kemHalfOf bs = do
  guard (BS.length bs == 70)
  let (magic, r1) = BS.splitAt 4 bs
  guard (magic == "HKS2")
  (tag, r2) <- BS.uncons r1
  alg <- kemByteAlg tag
  let (pid, r3) = BS.splitAt 32 r2
  (role, _) <- BS.uncons r3
  guard (role == 0 || role == 1)
  Just (alg, pid, role)

-- | The deterministic test ciphertext: standard length for the set,
-- derived from the backend seed and the pair identity (NOT real
-- ML-KEM; the fixed construction is what makes model tests replay).
kemCt :: Word64 -> PqcKemAlg -> ByteString -> ByteString
kemCt seed alg pid = prfBytes
  (frame [ "haskoki-synth/kem-ct/v1", word64BE seed
        , BS.singleton (kemAlgByte alg), pid ])
  (kemCtLenOf alg)

-- | The deterministic test shared secret: 32 bytes from the backend
-- seed and the pair identity, shared by both halves.
kemSs :: Word64 -> ByteString -> ByteString
kemSs seed pid = prfBytes
  (frame ["haskoki-synth/kem-ss/v1", word64BE seed, pid]) 32

-- | KEM parameter-set tags: the byte after the @HKS2@ magic.
kemAlgByte :: PqcKemAlg -> Word8
kemAlgByte alg = case alg of
  ML_KEM_512 -> 0
  ML_KEM_768 -> 1
  ML_KEM_1024 -> 2

-- | Tag byte back to its set.
kemByteAlg :: Word8 -> Maybe PqcKemAlg
kemByteAlg tag = case tag of
  0 -> Just ML_KEM_512
  1 -> Just ML_KEM_768
  2 -> Just ML_KEM_1024
  _ -> Nothing

-- | Standard ciphertext lengths per set.
kemCtLenOf :: PqcKemAlg -> Int
kemCtLenOf alg = case alg of
  ML_KEM_512 -> 768
  ML_KEM_768 -> 1088
  ML_KEM_1024 -> 1568

keyFamily :: KeyMaterial -> String
keyFamily (KeyBytes _) = "SYM"
keyFamily (KeyDer _) = "DER"
keyFamily (KeyRefMaterial (KeyRef _ fam)) = fam

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

-- | Constant-time equality (lengths plus a full xor fold).
ctEq :: ByteString -> ByteString -> Bool
ctEq a b =
  BS.length a == BS.length b
    && foldl' (\acc (x, y) -> acc .|. (x `xor` y)) 0 (BS.zip a b) == 0

-- | Allocate a fresh resource id from the shared counter.
allocId :: SynthEnv -> IO EngineResourceId
allocId env = modifyMVar (seNextId env) $ \n -> pure (n + 1, EngineResourceId n)

-- | Digest snapshot layout: @0x02 || algByte(1) || accLen BE(4) || acc@.
-- Key snapshots are @0x01@-versioned; the leading byte keeps the
-- two registries' encodings disjoint. @algByte 1@ is SHA-256 forever
-- (legacy snapshots restore); the recipe table assigns the rest (see
-- 'digestAlgByte' — the mapping is append-only and pinned by
-- SyntheticSpec).
encodeDigestCtx :: DigestAlg -> ByteString -> ByteString
encodeDigestCtx alg acc =
  BS.singleton 2 <> BS.singleton (digestAlgByte alg)
    <> word32BE (BS.length acc) <> acc

-- | Strict parse: version skew, unknown algorithm, truncation, or any
-- trailing byte rejects.
decodeDigestCtx :: ByteString -> Maybe (DigestAlg, ByteString)
decodeDigestCtx bs = case BS.uncons bs of
  Just (2, r1) -> case BS.uncons r1 of
    Just (b, r2) -> do
      alg <- digestAlgFromByte b
      let (lenBs, r3) = BS.splitAt 4 r2
      guard (BS.length lenBs == 4)
      let n = getWord32BE lenBs
          (acc, rest) = BS.splitAt n r3
      guard (BS.length acc == n && BS.null rest)
      Just (alg, acc)
    _ -> Nothing
  _ -> Nothing

-- | Stable snapshot algorithm bytes. 1 is SHA-256 (legacy
-- compat); 2-15 assigned by the recipe table. Never reuse or reorder.
digestAlgByte :: DigestAlg -> Word8
digestAlgByte alg = case alg of
  D_SHA256 -> 1
  D_MD5 -> 2
  D_SHA1 -> 3
  D_SHA224 -> 4
  D_SHA384 -> 5
  D_SHA512 -> 6
  D_SHA512_224 -> 7
  D_SHA512_256 -> 8
  D_SHA3_224 -> 9
  D_SHA3_256 -> 10
  D_SHA3_384 -> 11
  D_SHA3_512 -> 12
  D_RIPEMD160 -> 13
  D_SHAKE128 -> 14
  D_SHAKE256 -> 15

digestAlgFromByte :: Word8 -> Maybe DigestAlg
digestAlgFromByte b = case b of
  1 -> Just D_SHA256
  2 -> Just D_MD5
  3 -> Just D_SHA1
  4 -> Just D_SHA224
  5 -> Just D_SHA384
  6 -> Just D_SHA512
  7 -> Just D_SHA512_224
  8 -> Just D_SHA512_256
  9 -> Just D_SHA3_224
  10 -> Just D_SHA3_256
  11 -> Just D_SHA3_384
  12 -> Just D_SHA3_512
  13 -> Just D_RIPEMD160
  14 -> Just D_SHAKE128
  15 -> Just D_SHAKE256
  _ -> Nothing

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

-- | Class-interface MAC: domain-separated expansion over the
-- owned key bytes and the input, at the spec's algorithm width with
-- the requested truncation sliced off the full tag. SHA-256 keeps
-- its historical bytes (same domain tag, same 32-byte width); the
-- empty fallbacks are unreachable (the guard refuses XOFs and
-- non-HMAC families first).
classMac :: MacSpec -> ByteString -> ByteString -> ByteString
classMac (MacHMAC alg trunc) kb input =
  case (digestMacStem alg, digestOutLen alg) of
    (Just stem, Just w) ->
      BS.take (fromMaybe w trunc) (prfBytes
        (frame ["haskoki-synth/class-mac/v1", kb, BC8.pack ("HMAC-" ++ stem), input])
        w)
    _ -> BS.empty
classMac _ _ _ = BS.empty

-- | Class-interface signature: 64-byte domain-separated expansion
-- over the signing identity, the encoding tag, and the input. Raw
-- keys sign under their object identity; generated pair halves sign
-- under the shared pair identity, so a pair verifies across.
classSign :: ByteString -> ByteString -> ByteString -> ByteString
classSign enc identity input = prfBytes
  (frame ["haskoki-synth/class-sig/v1", identity, enc, input])
  synthSigLength

-- | Spec-keyed signature: the original ECDSA row (P-256, either
-- encoding, SHA-256) keeps the encoding tag byte-for-byte
-- (existing pins hold); every other ECDSA spec tags with its full
-- parameters (curve, encoding, and digest, raw included); RSA rows
-- tag with their capability name (PSS tags with its full
-- parameters, salt included) — so curves, digests, and families
-- never share a test signature over one identity.
classSignFor :: SigSpec -> ByteString -> ByteString -> ByteString
classSignFor spec@(SigECDSA (EcSpec "P-256" _) (Just D_SHA256)) identity input =
  classSign (sigEncoding spec) identity input
classSignFor spec@(SigECDSA _ _) identity input =
  classSign (BC8.pack (show spec)) identity input
classSignFor spec@(SigRSA_PSS _) identity input =
  classSign (BC8.pack (show spec)) identity input
classSignFor spec identity input =
  classSign (BC8.pack (fromMaybe (show spec) (rsaSigCap spec))) identity input

-- | Synthetic ECDH agreement: the domain-framed PRF over the spec,
-- the base identity, and the peer bytes at the max width. The
-- cofactor bit is part of the domain (unlike the real h=1 curves,
-- where cofactor multiplication is a no-op).
classEcdh :: EcdhSpec -> ByteString -> ByteString -> ByteString
classEcdh spec base peer = prfBytes
  (frame ["haskoki-synth/class-ecdh/v1", BC8.pack (show spec), base, peer])
  synthEcdhWidth

-- | Synthetic OAEP seal: deterministic, reversible, param-bound.
-- The body is a keystream XOR over (identity, params, input); the
-- 16-byte tag authenticates (identity, params, body), so a wrong
-- label, hash, MGF, or key fails the open with a verdict-shaped
-- 'Nothing'.
classOaepSeal :: ByteString -> OaepParams -> ByteString -> ByteString
classOaepSeal identity params input =
  body <> prfBytes (frame (oaepTagFrame identity params body)) 16
  where
    body = BS.packZipWith xor
      (prfBytes (frame (oaepStreamFrame identity params)) (BS.length input))
      input

-- | Open a synthetic OAEP envelope: recompute the tag (mismatch is
-- 'Nothing'), then XOR back. Short inputs are 'Nothing', never a
-- crash.
classOaepOpen :: ByteString -> OaepParams -> ByteString -> Maybe ByteString
classOaepOpen identity params sealed
  | BS.length sealed < 16 = Nothing
  | not (ctEq tag (prfBytes (frame (oaepTagFrame identity params body)) 16)) =
      Nothing
  | otherwise = Just (BS.packZipWith xor
      (prfBytes (frame (oaepStreamFrame identity params)) (BS.length body))
      body)
  where
    (body, tag) = BS.splitAt (BS.length sealed - 16) sealed

-- | OAEP parameter framing shared by the stream and the tag.
oaepParamFrame :: OaepParams -> [ByteString]
oaepParamFrame params =
  [ BC8.pack (show (oaepHash params))
  , BC8.pack (show (oaepMgf params))
  , oaepLabel params
  ]

oaepStreamFrame :: ByteString -> OaepParams -> [ByteString]
oaepStreamFrame identity params =
  "haskoki-synth/class-oaep-stream/v1" : identity : oaepParamFrame params

oaepTagFrame :: ByteString -> OaepParams -> ByteString -> [ByteString]
oaepTagFrame identity params body =
  "haskoki-synth/class-oaep-tag/v1" : identity : oaepParamFrame params ++ [body]

-- | Synthetic PKCS#1 v1.5 seal: the OAEP construction with its own
-- domain tags, so v1.5 and OAEP envelopes never cross-open. No
-- parameter framing (v1.5 carries none); the tag still binds
-- (identity, body), so a wrong key fails the open.
classPkcs1Seal :: ByteString -> ByteString -> ByteString
classPkcs1Seal identity input =
  body <> prfBytes (frame (pkcs1TagFrame identity body)) 16
  where
    body = BS.packZipWith xor
      (prfBytes (frame (pkcs1StreamFrame identity)) (BS.length input))
      input

-- | Open a synthetic v1.5 envelope: recompute the tag (mismatch is
-- 'Nothing'), then XOR back. Short inputs are 'Nothing', never a
-- crash.
classPkcs1Open :: ByteString -> ByteString -> Maybe ByteString
classPkcs1Open identity sealed
  | BS.length sealed < 16 = Nothing
  | not (ctEq tag (prfBytes (frame (pkcs1TagFrame identity body)) 16)) =
      Nothing
  | otherwise = Just (BS.packZipWith xor
      (prfBytes (frame (pkcs1StreamFrame identity)) (BS.length body))
      body)
  where
    (body, tag) = BS.splitAt (BS.length sealed - 16) sealed

pkcs1StreamFrame :: ByteString -> [ByteString]
pkcs1StreamFrame identity =
  ["haskoki-synth/class-pkcs1-stream/v1", identity]

pkcs1TagFrame :: ByteString -> ByteString -> [ByteString]
pkcs1TagFrame identity body =
  ["haskoki-synth/class-pkcs1-tag/v1", identity, body]

-- | Class-interface cipher: length-preserving reversible stream
-- construction (keystream XOR over the owned key bytes and iv).
-- Empty input gives empty output; no padding is ever implied.
classCipher :: ByteString -> ByteString -> ByteString -> ByteString
classCipher kb iv input =
  BS.packZipWith xor (classStream kb iv (BS.length input)) input

-- | Spec-keyed cipher: the stream is domain-separated by the
-- backend spec, so two algorithms sharing a key and IV never emit
-- the same test ciphertext. AES-256-CBC keeps its legacy bytes
-- byte-for-byte (existing golden pins hold); every other spec tags
-- the key frame with its constructor name.
classCipherFor :: CipherSpec -> ByteString -> ByteString -> ByteString -> ByteString
classCipherFor C_AES256_CBC kb iv input = classCipher kb iv input
classCipherFor spec kb iv input =
  classCipher (BC8.pack (show spec) <> kb) iv input

classStream :: ByteString -> ByteString -> Int -> ByteString
classStream kb iv n = prfBytes
  (frame ["haskoki-synth/class-stream/v1", kb, iv])
  n

-- | Class-interface digest: domain-separated expansion over the
-- algorithm tag and the input. The seed plays no part (as with the
-- retired record digest, only key generation is seed-keyed). Output
-- width follows 'synthDigestLengthFor'; SHA-256 output is
-- byte-identical to the original construction.
classDigest :: DigestAlg -> ByteString -> ByteString
classDigest alg input = prfBytes
  (frame ["haskoki-synth/class-digest/v1", encodeAlg alg, input])
  (synthDigestLengthFor alg)
  where
    encodeAlg :: DigestAlg -> ByteString
    encodeAlg D_MD5 = "MD5"
    encodeAlg D_SHA1 = "SHA1"
    encodeAlg D_SHA224 = "SHA224"
    encodeAlg D_SHA256 = "SHA256"
    encodeAlg D_SHA384 = "SHA384"
    encodeAlg D_SHA512 = "SHA512"
    encodeAlg D_SHA512_224 = "SHA512-224"
    encodeAlg D_SHA512_256 = "SHA512-256"
    encodeAlg D_SHA3_224 = "SHA3-224"
    encodeAlg D_SHA3_256 = "SHA3-256"
    encodeAlg D_SHA3_384 = "SHA3-384"
    encodeAlg D_SHA3_512 = "SHA3-512"
    encodeAlg D_RIPEMD160 = "RIPEMD160"
    encodeAlg D_SHAKE128 = "SHAKE128"
    encodeAlg D_SHAKE256 = "SHAKE256"
