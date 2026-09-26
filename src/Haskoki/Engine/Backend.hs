{- | Crypto backend abstraction: shared types plus the 'CryptoBackend' class.

Pure types only. This module must never import @Foreign.*@, declare
foreign imports, or touch OpenSSL headers (enforced by
@scripts/check-ossl4-surface.py@): all inputs and outputs are strict
owned values ('ByteString', numbers, enums, descriptors). Native
contexts live behind opaque 'EngineResourceId' handles owned by the
backend instance.

Laws (see Backend-design.md §4):

* Every execute path checks its capability predicate first; on a miss
  it returns 'BackendUnsupported' -- never substitutes another
  algorithm or parameter set, never retries on another engine.
* Failures are typed 'BackendError'; native codes are preserved in
  'BackendNative' for traces.
* Multipart state lives behind 'EngineResourceId'; 'snapshotResource'
  reports @Left "unsaveable..."@ honestly where the provider cannot
  serialize.
-}
{-# LANGUAGE TypeFamilies #-}
module Haskoki.Engine.Backend
  ( -- * Errors and results
    BackendError (..)
  , EngineResult (..)
    -- * Saveability declarations
  , UnsaveableReason (..)
  , ResourceSaveability (..)
    -- * Capabilities
  , BackendCaps (..)
  , DigestCaps (..)
  , CipherCaps (..)
  , MacCaps (..)
  , SigCaps (..)
  , KemCaps (..)
  , KdfCaps (..)
    -- * Parameter descriptors (explicit, no defaults-by-magic)
  , DigestAlg (..)
  , digestOutLen
  , digestMacStem
  , hmacSpecCap
  , rsaSigCap
  , rsaPssCap
  , ecdsaSigCap
  , ecdhCap
  , MacSpec (..)
  , CipherSpec (..)
  , cipherKeyLens
  , cipherIvLen
  , isKwSpec
  , isKwpSpec
  , isWrapSpec
  , AeadSpec (..)
  , SigSpec (..)
  , PssParams (..)
  , OaepParams (..)
  , RsaCipherParams (..)
  , EcSpec (..)
  , PqcKemAlg (..)
  , PqcSigAlg (..)
  , KemSpec (..)
  , EcdhSpec (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , KeyRef (..)
    -- * Class
  , CryptoBackend (..)
    -- * Random reseed bound
  , seedRandomMaxBytes
    -- * Random output bound
  , generateRandomMaxBytes
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Map.Strict (Map)
import Data.Set (Set)

import Haskoki.Der (coveredCurveNames)
import Haskoki.Types (EngineResourceId (..), redactShown)

-- | Opaque backend-side key reference (registry id + public fingerprint).
data KeyRef = KeyRef
  { keyRefId :: !EngineResourceId
  , keyRefFamily :: !String -- e.g. "RSA", "EC", "ML-KEM-768"
  } deriving (Eq, Ord, Show)

-- | Normalized owned key material crossing the boundary.
data KeyMaterial
  = KeyBytes !ByteString -- ^ symmetric / seed material
  | KeyDer !ByteString -- ^ DER SubjectPublicKeyInfo / PKCS#8
  | KeyRefMaterial !KeyRef -- ^ already-imported backend key
  deriving (Eq)

-- | 'Show' redacts owned key bytes: material renders its
-- kind and length only ('redactShown'); backend references (id
-- plus public fingerprint) render normally. Explicit inspection
-- pattern-matches the exported constructors (never 'Show').
instance Show KeyMaterial where
  show (KeyBytes bs) = "KeyBytes " ++ redactShown "key" (BS.length bs)
  show (KeyDer bs) = "KeyDer " ++ redactShown "key-der" (BS.length bs)
  show (KeyRefMaterial ref) = "KeyRefMaterial " ++ show ref

-- | Typed backend failure. The function-specific error adapter
-- translates this to CKR; traces keep the detail string.
data BackendError
  = BackendUnsupported { beOp :: !String, beWhy :: !String }
    -- ^ Capability or parameter combination not offered; the caller
    -- must NOT retry on another engine/mode (no silent fallback).
  | BackendBadParam { beOp :: !String, beWhy :: !String }
  | BackendBadKey { beOp :: !String, beWhy :: !String }
  | BackendMechParamInvalid { beOp :: !String, beWhy :: !String }
    -- ^ The backend rejected mechanism parameters it alone can
    -- validate (an ECDH peer point off the base curve); the edge
    -- answers CKR_MECHANISM_PARAM_INVALID.
  | BackendAuthFailed { beOp :: !String } -- ^ verify/tag mismatch only
  | BackendInvalidState { beOp :: !String, beWhy :: !String }
  | BackendNative { beOp :: !String, beCode :: !Int, beWhy :: !String }
  | BackendResourceGone { beOp :: !String, beId :: !EngineResourceId }
  deriving (Eq, Show)

-- | Owned-bytes-or-failure result.
data EngineResult a
  = EngineOk !a
  | EngineFail !BackendError
  deriving (Eq, Show)

-- | Why a backend resource cannot be snapshotted. Typed so callers can
-- distinguish "the provider cannot serialize this" from "no such
-- resource" without parsing strings.
data UnsaveableReason
  = UnsaveableNative !String
    -- ^ The provider cannot serialize this live resource (e.g. an
    -- OpenSSL EVP context); the detail names the cause.
  | UnsaveableGone !EngineResourceId
    -- ^ Unknown or already-released resource id.
  deriving (Eq, Show)

-- | Per-resource saveability declaration. 'ResourceSaveable' resources
-- snapshot via 'snapshotResource'; 'ResourceUnsaveable' is never a
-- silent drop and never a crash — the reason names the cause.
data ResourceSaveability
  = ResourceSaveable
  | ResourceUnsaveable !UnsaveableReason
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- Parameter descriptors (all explicit)
-- ---------------------------------------------------------------------------

data DigestAlg
  = D_MD5 | D_SHA1 | D_SHA224 | D_SHA256 | D_SHA384 | D_SHA512
  | D_SHA512_224 | D_SHA512_256
  | D_SHA3_224 | D_SHA3_256 | D_SHA3_384 | D_SHA3_512
  | D_RIPEMD160 | D_SHAKE128 | D_SHAKE256
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | Fixed output width in bytes of a digest algorithm. 'Nothing'
-- for the SHAKE XOFs (variable output; never a fixed-width tag).
-- RecipeHmacSpec pins this against the HMAC recipe widths, so the
-- engine truncation guards and the recipe can never drift silently.
digestOutLen :: DigestAlg -> Maybe Int
digestOutLen alg = case alg of
  D_MD5 -> Just 16
  D_SHA1 -> Just 20
  D_SHA224 -> Just 28
  D_SHA256 -> Just 32
  D_SHA384 -> Just 48
  D_SHA512 -> Just 64
  D_SHA512_224 -> Just 28
  D_SHA512_256 -> Just 32
  D_SHA3_224 -> Just 28
  D_SHA3_256 -> Just 32
  D_SHA3_384 -> Just 48
  D_SHA3_512 -> Just 64
  D_RIPEMD160 -> Just 20
  D_SHAKE128 -> Nothing
  D_SHAKE256 -> Nothing

-- | Short MAC capability stem per digest algorithm ('Nothing' for
-- the XOFs, which never make fixed-width tags). Both engines derive
-- the @HMAC-\<stem\>@ and @HMAC-\<stem\>-GENERAL@ capability strings
-- from this; the engine specs pin the full advertised sets.
digestMacStem :: DigestAlg -> Maybe String
digestMacStem alg = case alg of
  D_MD5 -> Just "MD5"
  D_SHA1 -> Just "SHA1"
  D_SHA224 -> Just "SHA224"
  D_SHA256 -> Just "SHA256"
  D_SHA384 -> Just "SHA384"
  D_SHA512 -> Just "SHA512"
  D_SHA512_224 -> Just "SHA512-224"
  D_SHA512_256 -> Just "SHA512-256"
  D_SHA3_224 -> Just "SHA3-224"
  D_SHA3_256 -> Just "SHA3-256"
  D_SHA3_384 -> Just "SHA3-384"
  D_SHA3_512 -> Just "SHA3-512"
  D_RIPEMD160 -> Just "RIPEMD160"
  D_SHAKE128 -> Nothing
  D_SHAKE256 -> Nothing

-- | Capability string required by one MAC spec. 'Nothing' means the
-- spec is never servable: a non-HMAC family, an XOF digest, or a
-- truncation outside @1..width@ (zero and over-width are guard
-- misses, never silent slices).
hmacSpecCap :: MacSpec -> Maybe String
hmacSpecCap (MacHMAC alg trunc) = do
  stem <- digestMacStem alg
  w <- digestOutLen alg
  case trunc of
    Nothing -> pure ("HMAC-" ++ stem)
    Just n
      | n >= 1 && n <= w -> pure ("HMAC-" ++ stem ++ "-GENERAL")
      | otherwise -> Nothing
hmacSpecCap _ = Nothing

-- | Capability string required by one RSA PKCS#1 v1.5 spec.
-- 'Nothing' means the spec is never servable: a non-RSA family or
-- an XOF digest (v1.5 needs a fixed-width hash). Reuses the digest
-- stems ('digestMacStem' names digests, not just MACs).
rsaSigCap :: SigSpec -> Maybe String
rsaSigCap (SigRSA_PKCS1v15 alg) = ("RSA-PKCS1v15-" ++) <$> digestMacStem alg
rsaSigCap SigRSA_Raw = Just "RSA-RAW"
rsaSigCap _ = Nothing

-- | Capability string required by one RSA-PSS spec: the single
-- @RSA-PSS@ name when the hash and MGF are fixed-width digests and
-- the salt is in @0..64@ (the recipe bound, covering every
-- digest-length salt). 'Nothing' means the spec is never servable.
rsaPssCap :: SigSpec -> Maybe String
rsaPssCap (SigRSA_PSS (PssParams h m s))
  | Just _ <- digestMacStem h
  , Just _ <- digestMacStem m
  , s >= 0 && s <= 64 = Just "RSA-PSS"
rsaPssCap _ = Nothing

-- | Capability string required by one ECDSA spec:
-- @ECDSA-<curve>-<digest stem>@ for hash-and-sign,
-- @ECDSA-<curve>-RAW@ for the raw row. Curves cover the full
-- 'Haskoki.Der.curveTable' set, encodings DER/RAW, digests the
-- fixed-width set. 'Nothing' means the spec is never servable
-- (non-ECDSA family, off-set curve/encoding, or an XOF digest).
ecdsaSigCap :: SigSpec -> Maybe String
ecdsaSigCap (SigECDSA (EcSpec curve enc) digest)
  | curve `elem` coveredCurveNames
  , enc == "DER" || enc == "RAW" = case digest of
      Nothing -> Just ("ECDSA-" ++ curve ++ "-RAW")
      Just alg -> (("ECDSA-" ++ curve ++ "-") ++) <$> digestMacStem alg
ecdsaSigCap _ = Nothing

-- | Capability string required by one ECDH spec: @ECDH@ for plain
-- agreement, @ECDH-COFACTOR@ for cofactor-multiplied.
ecdhCap :: EcdhSpec -> String
ecdhCap EcdhPlain = "ECDH"
ecdhCap EcdhCofactor = "ECDH-COFACTOR"

data MacSpec
  = MacHMAC { macDigest :: !DigestAlg, macTruncLen :: !(Maybe Int) }
  | MacCMAC { macCipher :: !CipherSpec }
  | MacKMAC128 { macOutLen :: !Int, macCustom :: !ByteString }
  | MacKMAC256 { macOutLen :: !Int, macCustom :: !ByteString }
  deriving (Eq, Show)

data CipherSpec
  = C_AES128_CBC | C_AES192_CBC | C_AES256_CBC
  | C_AES128_CTR | C_AES192_CTR | C_AES256_CTR
  | C_AES128_ECB | C_AES192_ECB | C_AES256_ECB
  | C_AES128_CTS | C_AES192_CTS | C_AES256_CTS
  | C_AES128_CFB128 | C_AES192_CFB128 | C_AES256_CFB128
  | C_AES128_CFB8 | C_AES192_CFB8 | C_AES256_CFB8
  | C_AES128_CFB1 | C_AES192_CFB1 | C_AES256_CFB1
  | C_AES128_OFB | C_AES192_OFB | C_AES256_OFB
  | C_AES128_KW | C_AES192_KW | C_AES256_KW
  | C_AES128_KWP | C_AES192_KWP | C_AES256_KWP
  | C_DES3_CBC | C_DES3_ECB
  | C_ARIA128_CBC | C_ARIA192_CBC | C_ARIA256_CBC
  | C_ARIA128_ECB | C_ARIA192_ECB | C_ARIA256_ECB
  | C_CAMELLIA128_CBC | C_CAMELLIA192_CBC | C_CAMELLIA256_CBC
  | C_CAMELLIA128_ECB | C_CAMELLIA192_ECB | C_CAMELLIA256_ECB
  deriving (Eq, Ord, Show)

-- | The AES key-wrap specs: KW runs RFC 3394 (input a multiple
-- of 8 bytes, minimum 16; output expands by the 8-byte IV), KWP
-- runs RFC 5649 (any input length >= 1; output pads to a multiple
-- of 8 plus the 8-byte IV). Both take no IV.
isKwSpec :: CipherSpec -> Bool
isKwSpec C_AES128_KW = True
isKwSpec C_AES192_KW = True
isKwSpec C_AES256_KW = True
isKwSpec _ = False

isKwpSpec :: CipherSpec -> Bool
isKwpSpec C_AES128_KWP = True
isKwpSpec C_AES192_KWP = True
isKwpSpec C_AES256_KWP = True
isKwpSpec _ = False

isWrapSpec :: CipherSpec -> Bool
isWrapSpec spec = isKwSpec spec || isKwpSpec spec

-- | Accepted raw key lengths in bytes per cipher. Triple-DES takes
-- 16 two-key (@K1||K2@, expanded to @K1||K2||K1@) or 24 three-key
-- bytes; every other spec takes exactly its width. Both engines
-- enforce this; RecipeCipherSpec pins it against the recipe.
cipherKeyLens :: CipherSpec -> [Int]
cipherKeyLens spec = case spec of
  C_AES128_CBC -> [16]
  C_AES192_CBC -> [24]
  C_AES256_CBC -> [32]
  C_AES128_CTR -> [16]
  C_AES192_CTR -> [24]
  C_AES256_CTR -> [32]
  C_AES128_ECB -> [16]
  C_AES192_ECB -> [24]
  C_AES256_ECB -> [32]
  C_AES128_CTS -> [16]
  C_AES192_CTS -> [24]
  C_AES256_CTS -> [32]
  C_AES128_CFB128 -> [16]
  C_AES192_CFB128 -> [24]
  C_AES256_CFB128 -> [32]
  C_AES128_CFB8 -> [16]
  C_AES192_CFB8 -> [24]
  C_AES256_CFB8 -> [32]
  C_AES128_CFB1 -> [16]
  C_AES192_CFB1 -> [24]
  C_AES256_CFB1 -> [32]
  C_AES128_OFB -> [16]
  C_AES192_OFB -> [24]
  C_AES256_OFB -> [32]
  C_AES128_KW -> [16]
  C_AES192_KW -> [24]
  C_AES256_KW -> [32]
  C_AES128_KWP -> [16]
  C_AES192_KWP -> [24]
  C_AES256_KWP -> [32]
  C_DES3_CBC -> [16, 24]
  C_DES3_ECB -> [16, 24]
  C_ARIA128_CBC -> [16]
  C_ARIA192_CBC -> [24]
  C_ARIA256_CBC -> [32]
  C_ARIA128_ECB -> [16]
  C_ARIA192_ECB -> [24]
  C_ARIA256_ECB -> [32]
  C_CAMELLIA128_CBC -> [16]
  C_CAMELLIA192_CBC -> [24]
  C_CAMELLIA256_CBC -> [32]
  C_CAMELLIA128_ECB -> [16]
  C_CAMELLIA192_ECB -> [24]
  C_CAMELLIA256_ECB -> [32]

-- | IV length in bytes per cipher: the block width for CBC, CTS,
-- CFB128, CFB8, CFB1 and OFB, 16 for CTR, 0 for ECB, KW and KWP
-- (wraps use the fixed AIV, never a caller IV). Both engines
-- enforce this; RecipeCipherSpec pins it against the recipe.
cipherIvLen :: CipherSpec -> Int
cipherIvLen spec = case spec of
  C_AES128_CBC -> 16
  C_AES192_CBC -> 16
  C_AES256_CBC -> 16
  C_AES128_CTR -> 16
  C_AES192_CTR -> 16
  C_AES256_CTR -> 16
  C_AES128_ECB -> 0
  C_AES192_ECB -> 0
  C_AES256_ECB -> 0
  C_AES128_CTS -> 16
  C_AES192_CTS -> 16
  C_AES256_CTS -> 16
  C_AES128_CFB128 -> 16
  C_AES192_CFB128 -> 16
  C_AES256_CFB128 -> 16
  C_AES128_CFB8 -> 16
  C_AES192_CFB8 -> 16
  C_AES256_CFB8 -> 16
  C_AES128_CFB1 -> 16
  C_AES192_CFB1 -> 16
  C_AES256_CFB1 -> 16
  C_AES128_OFB -> 16
  C_AES192_OFB -> 16
  C_AES256_OFB -> 16
  C_AES128_KW -> 0
  C_AES192_KW -> 0
  C_AES256_KW -> 0
  C_AES128_KWP -> 0
  C_AES192_KWP -> 0
  C_AES256_KWP -> 0
  C_DES3_CBC -> 8
  C_DES3_ECB -> 0
  C_ARIA128_CBC -> 16
  C_ARIA192_CBC -> 16
  C_ARIA256_CBC -> 16
  C_ARIA128_ECB -> 0
  C_ARIA192_ECB -> 0
  C_ARIA256_ECB -> 0
  C_CAMELLIA128_CBC -> 16
  C_CAMELLIA192_CBC -> 16
  C_CAMELLIA256_CBC -> 16
  C_CAMELLIA128_ECB -> 0
  C_CAMELLIA192_ECB -> 0
  C_CAMELLIA256_ECB -> 0

-- | AEAD carries its own nonce/tag lengths; padding is never implicit.
data AeadSpec = AeadSpec
  { aeadAlg :: !String -- "AES-128-GCM" | "AES-192-GCM" | "AES-256-GCM" | "ChaCha20-Poly1305"
  , aeadNonceLen :: !Int
  , aeadTagLen :: !Int
  } deriving (Eq, Show)

data PssParams = PssParams
  { pssHash :: !DigestAlg, pssMgf :: !DigestAlg, pssSaltLen :: !Int }
  deriving (Eq, Show)

data OaepParams = OaepParams
  { oaepHash :: !DigestAlg, oaepMgf :: !DigestAlg, oaepLabel :: !ByteString }
  deriving (Eq, Show)

-- | RSA cipher padding selector: OAEP with explicit parameters, or
-- PKCS#1 v1.5 (no parameters; the typed input bound is k - 11).
data RsaCipherParams = RsaOaep OaepParams | RsaPkcs1
  deriving (Eq, Show)

data EcSpec = EcSpec
  { ecCurve :: !String -- coveredCurveNames | "Ed25519" | ...
  , ecEncoding :: !String -- "DER" | "RAW" | "COMPRESSED" | "UNCOMPRESSED"
  } deriving (Eq, Show)

-- | PQC KEM algorithms: explicit parameter set, no bare "ML-KEM".
data PqcKemAlg = ML_KEM_512 | ML_KEM_768 | ML_KEM_1024
  deriving (Eq, Ord, Show, Enum, Bounded)

data KemSpec = KemSpec
  { kemAlg :: !PqcKemAlg
  } deriving (Eq, Show)

-- | ECDH agreement shape: plain or cofactor-multiplied.
-- The KDF dimension is not modeled: only raw (@CKD_NULL@) secrets
-- are served, and the recipe refuses every other selector.
data EcdhSpec = EcdhPlain | EcdhCofactor
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | PQC signatures: explicit parameter set incl. prehash/mu/context knobs.
data PqcSigAlg
  = ML_DSA_44 | ML_DSA_65 | ML_DSA_87
  | SLH_DSA_SHA2_128s | SLH_DSA_SHA2_128f | SLH_DSA_SHA2_192s
  | SLH_DSA_SHAKE_128s | SLH_DSA_SHAKE_128f
  deriving (Eq, Ord, Show)

data SigSpec
  = SigRSA_PKCS1v15 { sigDigest :: !DigestAlg }
  | SigRSA_Raw
    -- ^ Raw PKCS#1 v1.5 private operation (CKM_RSA_PKCS): the input
    -- is signed directly with block-type-1 padding, no hashing.
  | SigRSA_PSS { sigPss :: !PssParams }
  | SigECDSA { sigEc :: !EcSpec, sigEcDigest :: !(Maybe DigestAlg) }
    -- ^ Nothing = raw (caller hashed); Just d = digested input.
  | SigEdDSA { sigEc :: !EcSpec, sigContext :: !ByteString }
  | SigMLDSA
      { sigPqcAlg :: !PqcSigAlg
      , sigMu :: !Bool -- ^ ML-DSA-MU external-mu mode
      , sigContext :: !ByteString
      , sigHedge :: !Bool -- ^ hedged vs deterministic
      }
  | SigSLHDSA
      { sigPqcAlg :: !PqcSigAlg
      , sigContext :: !ByteString
      , sigHedge :: !Bool
      }
  deriving (Eq, Show)

data KeyGenSpec
  = GenRSA { genBits :: !Int, genExponent :: !Integer }
  | GenEC { genEc :: !EcSpec }
  | GenSym { genAlg :: !String, genLen :: !Int } -- "AES", "ChaCha20", "HMAC", "HOTP", "GENERIC"
  | GenMLKEM { genKem :: !PqcKemAlg }
  | GenMLDSA { genSigAlg :: !PqcSigAlg }
  | GenSLHDSA { genSigAlg :: !PqcSigAlg }
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- Capability reports
-- ---------------------------------------------------------------------------

data DigestCaps = DigestCaps
  { dcAlgs :: !(Set DigestAlg), dcMultipart :: !Bool, dcXof :: !Bool }
  deriving (Eq, Show)

data CipherCaps = CipherCaps
  { ccCiphers :: !(Set CipherSpec), ccAead :: !(Set String) }
  deriving (Eq, Show)

data MacCaps = MacCaps { mcSpecs :: !(Set String) } deriving (Eq, Show)

data SigCaps = SigCaps
  { scSpecs :: !(Set String) -- ^ canonical names incl. param sets
  , scCurves :: !(Set String)
  , scPqcSign :: !(Set PqcSigAlg)
  } deriving (Eq, Show)

data KemCaps = KemCaps { kcAlgs :: !(Set PqcKemAlg) } deriving (Eq, Show)

data KdfCaps = KdfCaps { kcKdfs :: !(Set String) } deriving (Eq, Show)

data BackendCaps = BackendCaps
  { bcName :: !String -- ^ "openssl4" | "synthetic"
  , bcVersion :: !String -- ^ libcrypto version string
  , bcDigests :: !DigestCaps
  , bcCiphers :: !CipherCaps
  , bcMacs :: !MacCaps
  , bcSigs :: !SigCaps
  , bcKems :: !KemCaps
  , bcKdfs :: !KdfCaps
  , bcParamNotes :: !(Map String String) -- ^ secondary report: padding/hash-MGF
    -- pairs, saveability
  } deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- The class
-- ---------------------------------------------------------------------------

-- | Largest 'seedRandom' seed in bytes (1 MiB, mirroring the
-- 1048576 native @RAND_bytes_ex@ window in @cbits/ossl4_ctx.h@).
-- Longer seeds are 'BackendBadParam' on every backend.
seedRandomMaxBytes :: Int
seedRandomMaxBytes = 1048576

-- | Largest single 'randomBytes' request in bytes (1 MiB, the same
-- window as 'seedRandomMaxBytes'). Longer requests are
-- 'BackendBadParam' on every backend: an unbounded request lets a
-- caller amplify one call into gigabytes of allocator pressure
-- (the oracle's 4 GiB probe OOM-killed the process pre-bound).
generateRandomMaxBytes :: Int
generateRandomMaxBytes = 1048576

-- | Crypto backend contract. Laws:
--
-- * All inputs/outputs are owned strict values; no Ptr/ForeignPtr crosses.
-- * Every execute path first checks its capability predicate; on miss it
--   returns 'BackendUnsupported' -- never substitutes another alg/param set.
-- * Failures are typed 'BackendError'; native codes are preserved in
--   'BackendNative' for traces, translated per-function to CKR by the
--   caller.
-- * Multipart state lives behind 'EngineResourceId' in the backend
--   registry; 'snapshotResource' reports @Left "unsaveable..."@ honestly
--   where the provider cannot serialize.
class CryptoBackend b where
  -- | Opaque backend handle (owns libctx/registry refs internally).
  data BackendEnv b

  backendName :: proxy b -> String

  -- | Open with a PRIVATE OSSL_LIB_CTX + explicit provider/property query.
  -- OpenSSL4: loads e.g. "default", never auto-loads a PKCS#11 provider.
  openBackend :: String -> IO (EngineResult (BackendEnv b))
  closeBackend :: BackendEnv b -> IO ()

  -- | Full capability report.
  queryCapabilities :: BackendEnv b -> IO BackendCaps

  -- Digest (one-shot + multipart via resource id).
  digestOneShot :: BackendEnv b -> DigestAlg -> ByteString -> IO (EngineResult ByteString)
  digestInit :: BackendEnv b -> DigestAlg -> IO (EngineResult EngineResourceId)
  digestUpdate :: BackendEnv b -> EngineResourceId -> ByteString -> IO (EngineResult ())
  digestFinal :: BackendEnv b -> EngineResourceId -> IO (EngineResult ByteString)

  -- MAC authenticate / verify (constant-time compare inside backend).
  macSign :: BackendEnv b -> MacSpec -> KeyMaterial -> ByteString -> IO (EngineResult ByteString)
  macVerify :: BackendEnv b -> MacSpec -> KeyMaterial -> ByteString -> ByteString -> IO (EngineResult Bool)
  -- ^ 'EngineOk True/False' only for well-formed comparisons; a wrong
  -- tag surfaces as 'EngineFail (BackendAuthFailed ...)' so callers
  -- cannot confuse "no" with "broken".

  -- Sign / verify with explicit spec (incl. PQC sign ops).
  sign :: BackendEnv b -> SigSpec -> KeyMaterial -> ByteString -> IO (EngineResult ByteString)
  verify :: BackendEnv b -> SigSpec -> KeyMaterial -> ByteString -> ByteString -> IO (EngineResult ())

  -- Symmetric encrypt / decrypt (+ AEAD with explicit AAD/nonce/tag split).
  cipherEncrypt :: BackendEnv b -> CipherSpec -> KeyMaterial -> ByteString -> ByteString -> IO (EngineResult ByteString)
  cipherDecrypt :: BackendEnv b -> CipherSpec -> KeyMaterial -> ByteString -> ByteString -> IO (EngineResult ByteString)
  aeadEncrypt :: BackendEnv b -> AeadSpec -> KeyMaterial -> ByteString -> ByteString -> ByteString -> IO (EngineResult (ByteString, ByteString))
  aeadDecrypt :: BackendEnv b -> AeadSpec -> KeyMaterial -> ByteString -> ByteString -> ByteString -> ByteString -> IO (EngineResult ByteString)

  -- Asymmetric encrypt / decrypt (padding explicit).
  pkeyEncrypt :: BackendEnv b -> RsaCipherParams -> KeyMaterial -> ByteString -> IO (EngineResult ByteString)
  pkeyDecrypt :: BackendEnv b -> RsaCipherParams -> KeyMaterial -> ByteString -> IO (EngineResult ByteString)

  -- Key generation (returns owned material or registry ref; never a Ptr).
  generateKey :: BackendEnv b -> KeyGenSpec -> IO (EngineResult (KeyMaterial, Maybe KeyMaterial))
  -- ^ (private-or-only, public-if-asymmetric)
  -- Random bytes: n >= 1 bytes from the backend RNG
  -- (libctx DRBG on OpenSSL4; seeded stream on synthetic).
  -- Requests longer than 'generateRandomMaxBytes' are
  -- 'BackendBadParam'.
  randomBytes :: BackendEnv b -> Int -> IO (EngineResult ByteString)
  -- Random reseed: mix @seed@ into the backend RNG.
  -- Synthetic REPLACES the stream origin (new seed plus counter
  -- reset, so the same seed plus the same subsequent call sequence
  -- replays byte-identical bytes); OpenSSL mixes via @RAND_add@
  -- (never replacing the DRBG state) with entropy estimate 0.0.
  -- Empty seeds are a vacuous 'EngineOk'; seeds longer than
  -- 'seedRandomMaxBytes' are 'BackendBadParam'.
  seedRandom :: BackendEnv b -> ByteString -> IO (EngineResult ())
  importKey :: BackendEnv b -> KeyMaterial -> IO (EngineResult KeyRef)
  exportKey :: BackendEnv b -> KeyRef -> IO (EngineResult KeyMaterial)
  destroyKey :: BackendEnv b -> KeyRef -> IO ()

  -- PQC KEM: encapsulate -> (ciphertext, sharedSecret); decapsulate ->
  -- sharedSecret. Implicit-rejection behavior is the REAL provider's.
  kemEncapsulate :: BackendEnv b -> KemSpec -> KeyMaterial -> IO (EngineResult (ByteString, ByteString))
  kemDecapsulate :: BackendEnv b -> KemSpec -> KeyMaterial -> ByteString -> IO (EngineResult ByteString)

  -- ECDH agreement: the raw x-coordinate secret at the
  -- curve's coordinate width (@CKD_NULL@ only — the recipe refuses
  -- every KDF selector). The real backend returns 32/48/66 bytes
  -- per the base curve; synthetic always returns the 72-byte max
  -- width. The driver truncates to the planned length.
  ecdhDerive :: BackendEnv b -> EcdhSpec -> KeyMaterial -> KeyMaterial -> IO (EngineResult ByteString)
  -- ^ (base private, peer public) -> full secret.

  -- Resource lifecycle for multipart/streaming contexts.
  snapshotResource :: BackendEnv b -> EngineResourceId -> IO (Either String ByteString)
  -- ^ 'Left "unsaveable:..."' where the provider cannot serialize.
  restoreResource :: BackendEnv b -> ByteString -> IO (EngineResult EngineResourceId)
  releaseResource :: BackendEnv b -> EngineResourceId -> IO ()
  resourceSaveability :: BackendEnv b -> EngineResourceId -> IO ResourceSaveability
  -- ^ Per-resource saveability declaration: saveable resources snapshot
  -- via 'snapshotResource'; unsaveable ones answer the typed reason.
