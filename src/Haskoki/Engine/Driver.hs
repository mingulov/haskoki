{- | Specified effect-to-backend driver.

Production owner of the @effect -> backend@ mapping: every
'CryptoEffect' the operation planners emit answers through
'runEffect' against any 'CryptoBackend', and 'encodeResult' adapts
the crypto answer onto the 'finishEffect' contract. Suites may keep
toy drivers; production routing uses this one.

Specified mapping (mechanism ids resolve through the generated
table by @CKM_*@ name; no hand-typed numerics):

* @FxDigest@ SHA-256 runs 'digestOneShot' @D_SHA256@;
  anything else is 'CryptoUnsupported'.
* Digest multipart streams: 'FxDigestInit' runs
  'digestInit' and answers the resource id, 'FxDigestFeed' runs
  'digestUpdate', and 'FxDigestConsume' runs 'digestFinal'; an
  uncovered mechanism is 'CryptoUnsupported' at alloc time.
* HMAC sign\/verify runs the recipe 'MacSpec' ('hmacSpecFor'):
  plain mechanisms take empty parameters (full-width tag),
  GENERAL mechanisms take the 8-byte big-endian tag length
  (truncated tag); an HMAC mechanism with malformed parameters is a
  'CryptoFailed' parameter refusal, never 'CryptoUnsupported'.
* CMAC sign\/verify runs the SP 800-38B composition over the backend
  ECB route ('cmacSpecFor' maps (mechanism, params, key length) to
  the cipher plus truncation; GENERAL rows reuse the HMAC
  tag-length shape). Off-geometry triples are 'CryptoFailed'
  parameter refusals, never 'CryptoUnsupported'.
* HOTP sign\/verify runs HMAC-SHA1 over the counter plus the
  RFC 4226 dynamic truncation ('hotpParamsFor' maps (mechanism,
  params) to (counter, digits); the input is always empty and the
  output is zero-padded ASCII digits). Off-shape triples are
  'CryptoFailed' parameter refusals, never 'CryptoUnsupported'.
* RSA PKCS#1 v1.5 runs the recipe 'SigSpec' ('rsaPkcs1SpecFor'):
  every mechanism takes empty parameters; an RSA mechanism with
  malformed parameters is a 'CryptoFailed' parameter refusal, never
  'CryptoUnsupported'.
* RSA-PSS runs the recipe 'SigSpec' ('rsaPssSpecFor'): the
  @pss-params\/1@ encoding carries hash, MGF1 hash, and salt length.
* RSA-OAEP cipher effects route to the asymmetric backend entry
  points ('rsaOaepParamsFor'): the effect parameters carry the
  @oaep-params\/1@ encoding (hash, MGF1 hash, label).
* ECDSA runs the recipe 'SigSpec' ('ecdsaSpecFor'): the mechanism
  binds the digest (@CKM_ECDSA@ is the raw row — the input is signed
  directly, no hashing), the parameters select the signature
  encoding (@"RAW"@, @"DER"@, or empty for the RAW default), and the
  curve label is a dispatch hint from the DER key's curve OID
  ('ecCurveOfKey'), defaulting to P-256 for unscannable keys; key
  shape is the backend's call (the RSA precedent), so a covered
  mechanism with malformed parameters is a 'CryptoFailed' parameter
  refusal, never 'CryptoUnsupported', and the driver never refuses
  a key.
* DSA runs the recipe 'SigSpec' ('dsaSpecFor'): the mechanism
  binds the digest (@CKM_DSA@ is the raw row — the input is a
  caller-supplied digest, signed directly, no hashing) and the
  parameters select the signature encoding (@"RAW"@, @"DER"@, or
  empty for the RAW default). Unlike ECDSA there is no curve
  label to hint (the key carries p/q/g); key shape is the
  backend's call, so a covered mechanism with malformed
  parameters is a 'CryptoFailed' parameter refusal, never
  'CryptoUnsupported', and the driver never refuses a key.
* EdDSA runs the recipe 'SigSpec' ('eddsaSpecFor'): pure EdDSA
  only (phFlag clear, empty context — empty parameters default
  to pure), and the curve label is a dispatch hint from the DER
  key ('eddsaCurveOfKey'), defaulting to Ed25519 when the key is
  unscannable. Key shape is the backend's call, so a covered
  mechanism with non-pure parameters is a 'CryptoFailed'
  parameter refusal, never 'CryptoUnsupported', and the driver
  never refuses a key.
* ML-DSA runs the recipe 'SigSpec' ('mldsaSpecFor'): any hedge
  variant with a 0..255-byte context (empty parameters default
  to preferred, empty context), and the level label is a
  dispatch hint from the DER key ('mldsaLevelOfKey'),
  defaulting to ML-DSA-44 when the key is unscannable. Key
  shape is the backend's call, so a covered mechanism with
  refused parameters is a 'CryptoFailed' parameter refusal,
  never 'CryptoUnsupported', and the driver never refuses a
  key.
* Block ciphers run the recipe 'CipherSpec' ('cipherSpecFor'):
  every (mechanism, key length, params) triple the
  'Haskoki.Recipe.Cipher' table covers maps to its backend spec
  (CBC takes the IV as parameters, ECB takes empty parameters;
  padding is decided in the pure planner, never here). A covered
  mechanism with a rejected triple is a 'CryptoFailed' parameter
  refusal, never 'CryptoUnsupported'.
* Message cipher effects behave like their classic counterpart with
  the per-message parameters as IV; nonempty AAD is
  'CryptoUnsupported' (the backend is not AEAD: bound AAD is
  refused, never ignored).
* Sign\/verify-recover has no backend operation and is
  'CryptoUnsupported'.
* A verify-shaped backend authentication failure is a verdict
  ('GotValid False'), never a malfunction.
* A missing key binding or an unresolvable key object is
  'CryptoBadKey'.

Key objects resolve through the caller-supplied 'KeyResolver'
(object attributes own key material; the production caller
feeds the mapping from 'keyBytesOf', exactly like the former
smoke-local driver).

Key-management mapping: 'FxGenerateKey' runs backend key
generation (the planner's 'GenArgs' frame selects the 'KeyGenSpec';
the answer frames the private half plus the optional public half
via 'encodeKeyPair'); 'FxKemEncaps' runs backend encapsulation and
answers @ciphertext || secret@ (the finisher splits at the
mechanism's ciphertext length); 'FxWrap'\/'FxUnwrap' run raw AES-CBC
(the planner pads) or the RSA cipher (the payload travels raw:
v1.5 takes empty parameters, OAEP the labeled params);
'FxAuthWrap'\/'FxAuthUnwrap' compose AES-CBC
with an HMAC-SHA-256 tag over @aad || ct@ under a domain-separated
tag key; 'FxDerive' runs HKDF expand-only ('hkdfExpand') or
extract-then-expand ('hkdfExtractExpand') with the PRF HMAC
for the HKDF mechanism, backend ECDH agreement ('ecdhDerive',
truncated to the planned length) for the ECDH mechanisms, digest
('runShaKd') for the SHA key-derivations, and the RFC 8018
iteration over the HMAC PRF ('runPbkd2') for PBKD2.
A bytes-shaped backend authentication failure (rejected KEM
ciphertext or wrap tag) is 'CryptoAuthFailed', while verify-shaped
ones stay verdicts.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver
  ( KeyResolver
  , runEffect
  , encodeResult
  , toCryptoError
  , toCoreFailure
  , fromCoreFailure
  , cryptoToCore
  , drainReleases
  , digestAlgFor
  , hmacSpecFor
  , cipherSpecFor
  , aeadSpecFor
  , rsaPkcs1SpecFor
  , rsaPssSpecFor
  , rsaOaepParamsFor
  , rsaX509SigFor
  , rsaX509CipherFor
  , ecdsaSpecFor
  , dsaSpecFor
  , eddsaSpecFor
  , mldsaSpecFor
  , slhdsaSpecFor
  , ecCurveOfKey
  , eddsaCurveOfKey
  , mldsaLevelOfKey
  , slhdsaLevelOfKey
  , ecdhParamsFor
  , dhParamsFor
  , cmacSpecFor
  , des3macSpecFor
  , hotpParamsFor
  , Pbkd2Params (..)
  , kdfShaFor
  , pbkd2ParamsFor
  , TlsPrfParams (..)
  , tlsPrfParamsFor
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Control.Applicative ((<|>))
import Control.Monad (guard)
import Data.Bits ((.&.), (.|.), popCount, shiftL, shiftR, xor)
import Data.List (unsnoc)
import Data.Word (Word64, Word8)
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Text as T

import Haskoki.Engine.Backend
  ( AeadSpec (..)
  , BackendError (..)
  , CipherSpec (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EcdhSpec (..)
  , DhSpec (..)
  , EcSpec (..)
  , EngineResult (..)
  , digestOutLen
  , KemSpec (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , MacSpec (..)
  , OaepParams (..)
  , PqcKemAlg (..)
  , PqcSigAlg (..)
  , RsaCipherParams (..)
  , PssParams (..)
  , SigSpec (..)
  )
import Haskoki.Operation.Derive (hkdfDeriveMech, maxDerivedTotal)
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.Cipher
  ( BlockCipherRecipe (..)
  , cipherKeyLenValid
  , cipherParamsValid
  , cipherRecipeFor
  , ctrRecipeFor
  , decodeCtrParams
  )
import Haskoki.Recipe.Dh
  ( decodeDhParams
  , dhParamsValid
  , dhRecipeFor
  )
import Haskoki.Recipe.Ecdh
  ( EcdhRecipe (..)
  , decodeEcdhParams
  , ecdhParamsValid
  , ecdhRecipeFor
  )
import Haskoki.Recipe.Ecdsa
  ( EcdsaRecipe (..)
  , ecdsaCurveOfDer
  , ecdsaEncodingOf
  , ecdsaParamsValid
  , ecdsaRecipeFor
  )
import Haskoki.Recipe.Dsa
  ( DsaRecipe (..)
  , dsaEncodingOf
  , dsaParamsValid
  , dsaRecipeFor
  )
import Haskoki.Recipe.Eddsa
  ( eddsaCurveOfDer
  , eddsaParamsValid
  , eddsaRecipeFor
  )
import Haskoki.Recipe.MlDsa
  ( MldsaHedge (..)
  , decodeMldsaParams
  , mldsaLevelOfDer
  , mldsaParamsValid
  , mldsaRecipeFor
  )
import Haskoki.Recipe.SlhDsa
  ( SlhdsaHedge (..)
  , decodeSlhdsaParams
  , slhdsaLevelOfDer
  , slhdsaParamsValid
  , slhdsaRecipeFor
  )
import Haskoki.Recipe.Ccm (ccmParamsValid, ccmRecipeFor, decodeCcmParams)
import Haskoki.Recipe.Chacha20
  ( Chacha20Recipe (..)
  , chachaParamsValid
  , chachaRecipeFor
  , decodeChachaPolyParams
  , decodeChachaStreamParams
  , encodeChachaIv
  )
import Haskoki.Recipe.Gcm (decodeGcmParams, gcmParamsValid, gcmRecipeFor)
import Haskoki.Recipe.RsaOaep (decodeOaepParams, rsaOaepParamsValid, rsaOaepRecipeFor)
import Haskoki.Recipe.RsaX509 (rsaX509ParamsValid, rsaX509RecipeFor)
import Haskoki.Recipe.RsaPkcs1
  ( RsaPkcs1Recipe (..)
  , rsaPkcs1ParamsValid
  , rsaPkcs1RecipeFor
  )
import Haskoki.Recipe.RsaPss
  ( decodePssParams
  , rsaPssParamsValid
  , rsaPssRecipeFor
  )
import Haskoki.Operation.Kem (KemAlg (..), kemAlgFromName, mlKemKeyPairGenMech, mlKemMech)
import Haskoki.Operation.KeyManagement
  ( GenArgs (..)
  , aesCbcMech
  , aesKeyGenMech
  , aesKwMech
  , aesKwPadMech
  , blake2b512KeyGenMech
  , chacha20KeyGenMech
  , des3KeyGenMech
  , aesKwpMech
  , decodeGenArgs
  , decodeWrapParams
  , dhKeyPairGenMech
  , dsaKeyPairGenMech
  , dsaParameterGenMech
  , ecKeyPairGenMech
  , edwardsKeyPairGenMech
  , montgomeryKeyPairGenMech
  , mldsaKeyPairGenMech
  , slhdsaKeyPairGenMech
  , x9_42DhKeyPairGenMech
  , rsaPkcsMech
  , encodeKeyPair
  , genericSecretKeyGenMech
  , hotpKeyGenMech
  , rsaKeyPairGenMech
  , desKeyGenMech
  , des2KeyGenMech
  , cdmfKeyGenMech
  , castKeyGenMech
  , cast3KeyGenMech
  , cast128KeyGenMech
  , rc2KeyGenMech
  , rc4KeyGenMech
  , rc5KeyGenMech
  , ideaKeyGenMech
  , skipjackKeyGenMech
  , batonKeyGenMech
  , juniperKeyGenMech
  , blowfishKeyGenMech
  , twofishKeyGenMech
  , gost28147KeyGenMech
  , seedKeyGenMech
  , ariaKeyGenMech
  , camelliaKeyGenMech
  , salsa20KeyGenMech
  , poly1305KeyGenMech
  , aesXtsKeyGenMech
  , hkdfKeyGenMech
  , sha1KeyGenMech
  , sha224KeyGenMech
  , sha256KeyGenMech
  , sha384KeyGenMech
  , sha512KeyGenMech
  , sha512_224KeyGenMech
  , sha512_256KeyGenMech
  , sha512TKeyGenMech
  , sha3_224KeyGenMech
  , sha3_256KeyGenMech
  , sha3_384KeyGenMech
  , sha3_512KeyGenMech
  , blake2b160KeyGenMech
  , blake2b256KeyGenMech
  , blake2b384KeyGenMech
  , ssl3PremasterKeyGenMech
  , tlsPremasterKeyGenMech
  , wtlsPremasterKeyGenMech
  , pbkd2KeyGenMech
  , pbkd2KeygenMaxBytes
  )
import Haskoki.Operation.State (CipherDir (..))
import Haskoki.Recipe.Cmac
  ( CmacRecipe (..)
  , cmacBlockLen
  , cmacRecipeFor
  )
import Haskoki.Recipe.Des3Mac
  ( Des3MacRecipe (..)
  , des3macBlockLen
  , des3macPlainOutLen
  , des3macRecipeFor
  )
import Haskoki.Recipe.Hmac
  ( HmacRecipe (..)
  , decodeMacGeneral
  , hmacRecipeFor
  )
import Haskoki.Recipe.Kdf
  ( KdfRecipe (..)
  , decodePbkd2Params
  , kdfCodeDigest
  , kdfParamsValid
  , kdfRecipeFor
  )
import Haskoki.Recipe.Otp
  ( decodeHotpParams
  , encodeHotpCounter
  , hotpRecipeFor
  , hotpTruncate
  )
import Haskoki.Recipe.TlsPrf
  ( decodeTlsPrfParams
  , maxTlsPrfOutput
  , tlsPrfParamsValid
  , tlsPrfRecipeFor
  )
import Haskoki.Registry (MechanismId (..), MechanismName)
import Haskoki.Registry.Generated
  ( ckm_BLAKE2B_160
  , ckm_BLAKE2B_256
  , ckm_BLAKE2B_384
  , ckm_BLAKE2B_512
  , ckm_MD5
  , ckm_RIPEMD160
  , ckm_SHA224
  , ckm_SHA256
  , ckm_SHA384
  , ckm_SHA3_224
  , ckm_SHA3_256
  , ckm_SHA3_384
  , ckm_SHA3_512
  , ckm_SHA512
  , ckm_SHA512_224
  , ckm_SHA512_256
  , ckm_SHA_1
  )
import Haskoki.Types (EngineResourceId, ObjectId)
import qualified Haskoki.Outcome as O

-- | Digest dispatch: covered mechanism to backend algorithm (pinned
-- pinned against 'Haskoki.Recipe.Digest' by RecipeDigestSpec, so the
-- table and the recipe can never drift silently).
digestAlgFor :: MechanismId -> Maybe DigestAlg
digestAlgFor mech
  | mech == MechanismId (ckm_BLAKE2B_512) = Just D_BLAKE2B512
  | mech == MechanismId (ckm_BLAKE2B_160) = Just D_BLAKE2B160
  | mech == MechanismId (ckm_BLAKE2B_256) = Just D_BLAKE2B256
  | mech == MechanismId (ckm_BLAKE2B_384) = Just D_BLAKE2B384
  | mech == MechanismId (ckm_SHA224) = Just D_SHA224
  | mech == MechanismId (ckm_SHA256) = Just D_SHA256
  | mech == MechanismId (ckm_SHA384) = Just D_SHA384
  | mech == MechanismId (ckm_SHA512) = Just D_SHA512
  | mech == MechanismId (ckm_SHA512_224) = Just D_SHA512_224
  | mech == MechanismId (ckm_SHA512_256) = Just D_SHA512_256
  | mech == MechanismId (ckm_SHA3_224) = Just D_SHA3_224
  | mech == MechanismId (ckm_SHA3_256) = Just D_SHA3_256
  | mech == MechanismId (ckm_SHA3_384) = Just D_SHA3_384
  | mech == MechanismId (ckm_SHA3_512) = Just D_SHA3_512
  | mech == MechanismId (ckm_SHA_1) = Just D_SHA1
  | mech == MechanismId (ckm_MD5) = Just D_MD5
  | mech == MechanismId (ckm_RIPEMD160) = Just D_RIPEMD160
  | otherwise = Nothing

-- | HMAC dispatch: covered (mechanism, params) pairs to backend
-- specs (pinned against 'Haskoki.Recipe.Hmac' by
-- RecipeHmacSpec, so the table and the recipe can never drift
-- silently). Plain mechanisms resolve on empty parameters only;
-- GENERAL mechanisms thread the decoded tag length. 'Nothing'
-- means uncovered (non-HMAC mechanism) or malformed parameters.
hmacSpecFor :: MechanismId -> ByteString -> Maybe MacSpec
hmacSpecFor mech params = do
  r <- hmacRecipeFor mech
  alg <- hmacDigest (hrName r)
  if hrGeneral r
    then do
      n <- decodeMacGeneral params
      guard (n >= 1 && n <= hrOutLen r)
      pure (MacHMAC alg (Just n))
    else do
      guard (BS.null params)
      pure (MacHMAC alg Nothing)

-- | An HMAC mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed HMAC params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isHmacMech :: MechanismId -> Bool
isHmacMech mech = isJust (hmacRecipeFor mech)

-- | CMAC dispatch: covered (mechanism, params, key length) triples
-- to the backend ECB cipher spec plus the GENERAL truncation (pinned
-- against 'Haskoki.Recipe.Cmac' by RecipeCmacSpec).
-- The cipher binds by key length (AES-128\/192\/256 for the AES
-- rows, 3DES for the DES3 rows); GENERAL rows thread the decoded
-- tag length, capped at the cipher block. 'Nothing' means uncovered
-- (non-CMAC mechanism), malformed parameters, or an off-geometry
-- key length.
cmacSpecFor :: MechanismId -> ByteString -> Int -> Maybe (CipherSpec, Maybe Int)
cmacSpecFor mech params keyLen = do
  r <- cmacRecipeFor mech
  spec <- cmacCipher r keyLen
  if rcGeneral r
    then do
      n <- decodeMacGeneral params
      guard (n >= 1 && n <= cmacBlockLen r)
      pure (spec, Just n)
    else do
      guard (BS.null params)
      pure (spec, Nothing)
  where
    cmacCipher r n
      | rcDes3 r, n == 16 || n == 24 = Just C_DES3_ECB
      | rcDes3 r = Nothing
      | n == 16 = Just C_AES128_ECB
      | n == 24 = Just C_AES192_ECB
      | n == 32 = Just C_AES256_ECB
      | otherwise = Nothing

-- | A CMAC mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed CMAC params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isCmacMech :: MechanismId -> Bool
isCmacMech mech = isJust (cmacRecipeFor mech)

-- | 3DES-MAC dispatch: covered (mechanism, params, key length)
-- triples map to the ECB cipher spec plus the output width (4 for
-- the plain half-block row, the decoded length for GENERAL rows).
-- 'Nothing' means uncovered (non-3DES-MAC mechanism), malformed
-- parameters, or an off-geometry key length.
des3macSpecFor :: MechanismId -> ByteString -> Int -> Maybe (CipherSpec, Maybe Int)
des3macSpecFor mech params keyLen = do
  r <- des3macRecipeFor mech
  guard (keyLen == 16 || keyLen == 24)
  if rdmGeneral r
    then do
      n <- decodeMacGeneral params
      guard (n >= 1 && n <= des3macBlockLen r)
      pure (C_DES3_ECB, Just n)
    else do
      guard (BS.null params)
      pure (C_DES3_ECB, Just (des3macPlainOutLen r))

-- | A 3DES-MAC mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: malformed MAC params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isDes3MacMech :: MechanismId -> Bool
isDes3MacMech mech = isJust (des3macRecipeFor mech)

-- | HOTP dispatch: a covered mechanism with valid @hotp-params\/1@
-- parameters to (counter, digits) (pinned against
-- 'Haskoki.Recipe.Otp' by RecipeOtpSpec). 'Nothing' means uncovered
-- (non-HOTP mechanism) or malformed parameters.
hotpParamsFor :: MechanismId -> ByteString -> Maybe (Word64, Int)
hotpParamsFor mech params = do
  _ <- hotpRecipeFor mech
  decodeHotpParams params

-- | An HOTP mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed HOTP params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isHotpMech :: MechanismId -> Bool
isHotpMech mech = isJust (hotpRecipeFor mech)

-- | Decoded PBKD2 parameters: the PRF digest, the iteration count,
-- and the salt.
data Pbkd2Params = Pbkd2Params
  { ppPrf :: !DigestAlg
  , ppIters :: !Int
  , ppSalt :: !ByteString
  } deriving (Eq, Show)

-- | KDF dispatch, SHA rows: covered mechanisms to digests (pinned
-- pinned against 'Haskoki.Recipe.Kdf' by RecipeKdfSpec). 'Nothing'
-- means uncovered (non-SHA-KD mechanism, PBKD2 included).
kdfShaFor :: MechanismId -> Maybe DigestAlg
kdfShaFor mech = do
  r <- kdfRecipeFor mech
  guard (not (rkPbkd2 r))
  stem <- rkDigestStem r
  rsaDigest stem

-- | KDF dispatch, PBKD2: the covered (mechanism, params) pair to
-- decoded parameters (pinned by RecipeKdfSpec). The PRF
-- stem must map to a servable digest. 'Nothing' means uncovered
-- (non-PBKD2 mechanism) or malformed parameters.
pbkd2ParamsFor :: MechanismId -> ByteString -> Maybe Pbkd2Params
pbkd2ParamsFor mech params = do
  r <- kdfRecipeFor mech
  guard (rkPbkd2 r && kdfParamsValid r params)
  (stem, iters, salt, _) <- decodePbkd2Params params
  alg <- rsaDigest stem
  pure (Pbkd2Params alg iters salt)

-- | A SHA key-derivation mechanism (drives the parameter-refusal
-- branch).
isKdfShaMech :: MechanismId -> Bool
isKdfShaMech mech = case kdfRecipeFor mech of
  Just r -> not (rkPbkd2 r)
  Nothing -> False

-- | The PBKD2 mechanism (drives the parameter-refusal branch).
isPbkd2Mech :: MechanismId -> Bool
isPbkd2Mech mech = case kdfRecipeFor mech of
  Just r -> rkPbkd2 r
  Nothing -> False

-- | TLS-PRF inputs: the label plus the seed (RFC 2246 §5).
data TlsPrfParams = TlsPrfParams
  { tpLabel :: !ByteString
  , tpSeed :: !ByteString
  } deriving (Eq, Show)

-- | TLS-PRF dispatch: the covered (mechanism, params) pair to its
-- decoded label + seed (pinned by RecipeTlsPrfSpec). 'Nothing'
-- means uncovered (non-TLS-PRF mechanism) or malformed parameters.
tlsPrfParamsFor :: MechanismId -> ByteString -> Maybe TlsPrfParams
tlsPrfParamsFor mech params = do
  r <- tlsPrfRecipeFor mech
  guard (tlsPrfParamsValid r params)
  (lab, seed) <- decodeTlsPrfParams params
  pure (TlsPrfParams lab seed)

-- | TLS-PRF secret split (RFC 2246 §5): the first
-- @ceiling(len\/2)@ bytes and the last @ceiling(len\/2)@ bytes; the
-- middle byte is shared on odd lengths.
splitTlsSecret :: ByteString -> (ByteString, ByteString)
splitTlsSecret secret = (BS.take half secret, BS.drop (len - half) secret)
  where
    len = BS.length secret
    half = (len + 1) `div` 2

-- | The TLS-PRF mechanism (drives the parameter-refusal branch).
isTlsPrfMech :: MechanismId -> Bool
isTlsPrfMech mech = case tlsPrfRecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | Digest stem of an HMAC recipe name, without the parameter-shape
-- suffix.
hmacDigest :: MechanismName -> Maybe DigestAlg
hmacDigest name
  | Just stem <- T.stripSuffix "_HMAC_GENERAL" name = stemAlg stem
  | Just stem <- T.stripSuffix "_HMAC" name = stemAlg stem
  | otherwise = Nothing
  where
    stemAlg :: MechanismName -> Maybe DigestAlg
    stemAlg stem
      | stem == "CKM_BLAKE2B_512" = Just D_BLAKE2B512
      | stem == "CKM_BLAKE2B_160" = Just D_BLAKE2B160
      | stem == "CKM_BLAKE2B_256" = Just D_BLAKE2B256
      | stem == "CKM_BLAKE2B_384" = Just D_BLAKE2B384
      | stem == "CKM_SHA224" = Just D_SHA224
      | stem == "CKM_SHA256" = Just D_SHA256
      | stem == "CKM_SHA384" = Just D_SHA384
      | stem == "CKM_SHA512" = Just D_SHA512
      | stem == "CKM_SHA512_224" = Just D_SHA512_224
      | stem == "CKM_SHA512_256" = Just D_SHA512_256
      | stem == "CKM_SHA3_224" = Just D_SHA3_224
      | stem == "CKM_SHA3_256" = Just D_SHA3_256
      | stem == "CKM_SHA3_384" = Just D_SHA3_384
      | stem == "CKM_SHA3_512" = Just D_SHA3_512
      | stem == "CKM_SHA_1" = Just D_SHA1
      | stem == "CKM_MD5" = Just D_MD5
      | stem == "CKM_RIPEMD160" = Just D_RIPEMD160
      | otherwise = Nothing

-- | Cipher dispatch: covered (mechanism, key length, params)
-- triples to backend specs (pinned against
-- 'Haskoki.Recipe.Cipher' by RecipeCipherSpec, so the table and the
-- recipe can never drift silently). The recipe validates the
-- parameters (IV geometry) and the key length; the constructor
-- below selects the width. 'Nothing' means uncovered (non-cipher
-- mechanism) or a rejected triple.
cipherSpecFor :: MechanismId -> Int -> ByteString -> Maybe CipherSpec
cipherSpecFor mech keyLen params =
  blockParts <|> chachaParts
  where
    blockParts = do
      r <- cipherRecipeFor mech
      guard (cipherParamsValid r params)
      guard (cipherKeyLenValid r keyLen)
      cipherCtor (crName r) keyLen
    -- The raw ChaCha20 stream row: 256-bit keys only; the recipe
    -- validates the (counter, nonce) image.
    chachaParts = do
      r <- chachaRecipeFor mech
      guard (chachaName r == "CKM_CHACHA20")
      guard (chachaParamsValid r params)
      guard (keyLen == 32)
      pure C_CHACHA20

-- | A cipher mechanism regardless of triple validity (drives the
-- parameter-refusal branch: rejected triples are 'CryptoFailed',
-- never 'CryptoUnsupported').
isCipherMech :: MechanismId -> Bool
isCipherMech mech = isJust (cipherRecipeFor mech) || isChachaStreamMech mech

-- | The raw ChaCha20 stream row regardless of triple validity
-- (same refusal branch as the block ciphers).
isChachaStreamMech :: MechanismId -> Bool
isChachaStreamMech mech = case chachaRecipeFor mech of
  Just r -> chachaName r == "CKM_CHACHA20"
  Nothing -> False

-- | AEAD dispatch: covered (mechanism, key length, params)
-- triples to the backend spec plus the decoded (IV, AAD) (pinned
-- against 'Haskoki.Recipe.Gcm' by RecipeGcmSpec, so the table and
-- the recipe can never drift silently). The recipe validates the
-- parameters (caller IV, approved tag width) and the key length
-- selects the AES width; the nonce length is the IV length.
-- 'Nothing' means uncovered (non-AEAD mechanism) or a rejected
-- triple.
aeadPartsFor :: MechanismId -> Int -> ByteString -> Maybe (AeadSpec, ByteString, ByteString)
aeadPartsFor mech keyLen params =
  gcmParts <|> ccmParts <|> chachaParts
  where
    gcmParts = do
      r <- gcmRecipeFor mech
      guard (gcmParamsValid r params)
      (iv, aad, tagLen) <- decodeGcmParams params
      alg <- case keyLen of
        16 -> Just "AES-128-GCM"
        24 -> Just "AES-192-GCM"
        32 -> Just "AES-256-GCM"
        _ -> Nothing
      pure (AeadSpec alg (BS.length iv) tagLen, iv, aad)
    ccmParts = do
      r <- ccmRecipeFor mech
      guard (ccmParamsValid r params)
      (nonce, aad, tagLen, _) <- decodeCcmParams params
      alg <- case keyLen of
        16 -> Just "AES-128-CCM"
        24 -> Just "AES-192-CCM"
        32 -> Just "AES-256-CCM"
        _ -> Nothing
      pure (AeadSpec alg (BS.length nonce) tagLen, nonce, aad)
    -- ChaCha20-Poly1305: 256-bit keys only; the recipe pins the
    -- fixed 16-byte tag and the 12-byte nonce.
    chachaParts = do
      r <- chachaRecipeFor mech
      guard (chachaName r == "CKM_CHACHA20_POLY1305")
      guard (chachaParamsValid r params)
      (nonce, aad, tagLen) <- decodeChachaPolyParams params
      guard (keyLen == 32)
      pure (AeadSpec "ChaCha20-Poly1305" (BS.length nonce) tagLen, nonce, aad)

-- | The backend spec of a covered AEAD triple ('aeadPartsFor'
-- without the decoded parts).
aeadSpecFor :: MechanismId -> Int -> ByteString -> Maybe AeadSpec
aeadSpecFor mech keyLen params =
  (\(spec, _, _) -> spec) <$> aeadPartsFor mech keyLen params

-- | CCM data-length agreement: @ulDataLen@ must equal the
-- plaintext length (encrypt: the input; decrypt: the input minus
-- the tag). Short decrypt inputs defer to the authentication
-- failure in 'runAeadSealed' instead of failing here.
ccmLengthBad :: CipherDir -> ByteString -> ByteString -> Int -> Bool
ccmLengthBad dir params input tagLen = case decodeCcmParams params of
  Just (_, _, _, dataLen) -> case dir of
    DirEncrypt -> dataLen /= BS.length input
    DirDecrypt
      | BS.length input < tagLen -> False
      | otherwise -> dataLen /= BS.length input - tagLen
  Nothing -> True

-- | An AEAD mechanism regardless of triple validity (drives the
-- parameter-refusal branch: rejected triples are 'CryptoFailed',
-- never 'CryptoUnsupported').
isGcmMech :: MechanismId -> Bool
isGcmMech mech = isJust (gcmRecipeFor mech)

-- | A CCM mechanism regardless of triple validity (same refusal
-- branch as GCM: rejected triples are 'CryptoFailed', never
-- 'CryptoUnsupported').
isCcmMech :: MechanismId -> Bool
isCcmMech mech = isJust (ccmRecipeFor mech)

-- | The ChaCha20-Poly1305 AEAD row regardless of triple validity
-- (same refusal branch as GCM/CCM).
isChachaPolyMech :: MechanismId -> Bool
isChachaPolyMech mech = case chachaRecipeFor mech of
  Just r -> chachaName r == "CKM_CHACHA20_POLY1305"
  Nothing -> False

-- | Recipe row + key length onto the backend width. @CKM_AES_CBC_PAD@
-- shares the CBC specs (the planner pads before the effect input is
-- fixed); @CKM_AES_CTR@ maps its three widths (the counter block is
-- split from the parameter image in 'runCipher'); Triple-DES widths
-- collapse (the engines expand two-key material to @K1||K2||K1@).
cipherCtor :: MechanismName -> Int -> Maybe CipherSpec
cipherCtor name keyLen
  | name == "CKM_AES_CBC" || name == "CKM_AES_CBC_PAD" = aesCbc keyLen
  | name == "CKM_AES_CTR" = aesCtr keyLen
  | name == "CKM_AES_ECB" = aesEcb keyLen
  | name == "CKM_AES_CTS" = aesCts keyLen
  | name == "CKM_AES_CFB128" = aesCfb128 keyLen
  | name == "CKM_AES_CFB8" = aesCfb8 keyLen
  | name == "CKM_AES_CFB1" = aesCfb1 keyLen
  | name == "CKM_AES_OFB" = aesOfb keyLen
  | name == "CKM_AES_KEY_WRAP" = aesKw keyLen
  | name == "CKM_AES_KEY_WRAP_KWP" = aesKwp keyLen
  | name == "CKM_AES_KEY_WRAP_PAD" = aesKwp keyLen
  | name == "CKM_AES_XTS" = aesXts keyLen
  | name == "CKM_DES3_CBC" = des3 C_DES3_CBC
  | name == "CKM_DES3_ECB" = des3 C_DES3_ECB
  | name == "CKM_ARIA_CBC" = aria C_ARIA128_CBC C_ARIA192_CBC C_ARIA256_CBC
  | name == "CKM_ARIA_ECB" = aria C_ARIA128_ECB C_ARIA192_ECB C_ARIA256_ECB
  | name == "CKM_CAMELLIA_CBC" =
      aria C_CAMELLIA128_CBC C_CAMELLIA192_CBC C_CAMELLIA256_CBC
  | name == "CKM_CAMELLIA_ECB" =
      aria C_CAMELLIA128_ECB C_CAMELLIA192_ECB C_CAMELLIA256_ECB
  | otherwise = Nothing
  where
    aesCbc n = case n of
      16 -> Just C_AES128_CBC
      24 -> Just C_AES192_CBC
      32 -> Just C_AES256_CBC
      _ -> Nothing
    aesCtr n = case n of
      16 -> Just C_AES128_CTR
      24 -> Just C_AES192_CTR
      32 -> Just C_AES256_CTR
      _ -> Nothing
    aesEcb n = case n of
      16 -> Just C_AES128_ECB
      24 -> Just C_AES192_ECB
      32 -> Just C_AES256_ECB
      _ -> Nothing
    aesCts n = case n of
      16 -> Just C_AES128_CTS
      24 -> Just C_AES192_CTS
      32 -> Just C_AES256_CTS
      _ -> Nothing
    aesCfb128 n = case n of
      16 -> Just C_AES128_CFB128
      24 -> Just C_AES192_CFB128
      32 -> Just C_AES256_CFB128
      _ -> Nothing
    aesCfb8 n = case n of
      16 -> Just C_AES128_CFB8
      24 -> Just C_AES192_CFB8
      32 -> Just C_AES256_CFB8
      _ -> Nothing
    aesCfb1 n = case n of
      16 -> Just C_AES128_CFB1
      24 -> Just C_AES192_CFB1
      32 -> Just C_AES256_CFB1
      _ -> Nothing
    aesOfb n = case n of
      16 -> Just C_AES128_OFB
      24 -> Just C_AES192_OFB
      32 -> Just C_AES256_OFB
      _ -> Nothing
    aesKw n = case n of
      16 -> Just C_AES128_KW
      24 -> Just C_AES192_KW
      32 -> Just C_AES256_KW
      _ -> Nothing
    -- CKM_AES_KEY_WRAP_PAD takes KWP semantics (the oracle runs no
    -- distinct vectors for it and calls it the "KWP-PAD path").
    aesKwp n = case n of
      16 -> Just C_AES128_KWP
      24 -> Just C_AES192_KWP
      32 -> Just C_AES256_KWP
      _ -> Nothing
    -- XTS keys are double-width (data + tweak halves); there is no
    -- 192 width (the provider has no AES-192-XTS).
    aesXts n = case n of
      32 -> Just C_AES128_XTS
      64 -> Just C_AES256_XTS
      _ -> Nothing
    des3 spec
      | keyLen == 16 || keyLen == 24 = Just spec
      | otherwise = Nothing
    aria c128 c192 c256 = case keyLen of
      16 -> Just c128
      24 -> Just c192
      32 -> Just c256
      _ -> Nothing

-- | RSA v1.5 dispatch: covered (mechanism, params) pairs to
-- backend specs (pinned against
-- 'Haskoki.Recipe.RsaPkcs1' by RecipeRsaSpec, so the table and the
-- recipe can never drift silently). Digested rows map their stem;
-- the raw row maps to 'SigRSA_Raw'. 'Nothing' means uncovered
-- (non-RSA mechanism) or malformed parameters.
rsaPkcs1SpecFor :: MechanismId -> ByteString -> Maybe SigSpec
rsaPkcs1SpecFor mech params = do
  r <- rsaPkcs1RecipeFor mech
  guard (rsaPkcs1ParamsValid r params)
  case rrDigestStem r of
    Nothing -> pure SigRSA_Raw
    Just stem -> SigRSA_PKCS1v15 <$> rsaDigest stem

-- | An RSA v1.5 mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: malformed RSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isRsaPkcs1Mech :: MechanismId -> Bool
isRsaPkcs1Mech mech = isJust (rsaPkcs1RecipeFor mech)

-- | The raw RSA v1.5 row: the only v1.5 mechanism that wraps
-- (the digest rows are signature-only).
isRsaPkcsWrapMech :: MechanismId -> Bool
isRsaPkcsWrapMech mech = mech == rsaPkcsMech

-- | The AES key-wrap rows (KW plus the two KWP names): the
-- planner frames the payload raw (no padding) and 'runCipher'
-- executes the wrap backend spec selected by 'cipherCtor'.
isAesKwWrapMech :: MechanismId -> Bool
isAesKwWrapMech mech =
  mech == aesKwMech || mech == aesKwPadMech || mech == aesKwpMech

-- | Recipe digest stem onto the backend digest.
rsaDigest :: T.Text -> Maybe DigestAlg
rsaDigest stem
  | stem == "BLAKE2B_512" = Just D_BLAKE2B512
  | stem == "BLAKE2B_160" = Just D_BLAKE2B160
  | stem == "BLAKE2B_256" = Just D_BLAKE2B256
  | stem == "BLAKE2B_384" = Just D_BLAKE2B384
  | stem == "MD5" = Just D_MD5
  | stem == "RIPEMD160" = Just D_RIPEMD160
  | stem == "SHA_1" = Just D_SHA1
  | stem == "SHA224" = Just D_SHA224
  | stem == "SHA256" = Just D_SHA256
  | stem == "SHA384" = Just D_SHA384
  | stem == "SHA512" = Just D_SHA512
  | stem == "SHA512_224" = Just D_SHA512_224
  | stem == "SHA512_256" = Just D_SHA512_256
  | stem == "SHA3_224" = Just D_SHA3_224
  | stem == "SHA3_256" = Just D_SHA3_256
  | stem == "SHA3_384" = Just D_SHA3_384
  | stem == "SHA3_512" = Just D_SHA3_512
  | otherwise = Nothing

-- | RSA-PSS dispatch: covered (mechanism, params) pairs to
-- backend specs (pinned against
-- 'Haskoki.Recipe.RsaPss' by RecipePssSpec). The recipe validates
-- the binding and bounds; the decode below re-reads the same words
-- (total on validated input). 'Nothing' means uncovered
-- (non-PSS mechanism) or malformed parameters.
rsaPssSpecFor :: MechanismId -> ByteString -> Maybe SigSpec
rsaPssSpecFor mech params = do
  r <- rsaPssRecipeFor mech
  guard (rsaPssParamsValid r params)
  (d, m, salt) <- decodePssParams params
  hashAlg <- rsaDigest d
  mgfAlg <- rsaDigest m
  pure (SigRSA_PSS (PssParams hashAlg mgfAlg salt))

-- | A PSS mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed PSS params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isRsaPssMech :: MechanismId -> Bool
isRsaPssMech mech = isJust (rsaPssRecipeFor mech)

-- | RSA-OAEP dispatch: the covered (mechanism, params) pair to
-- backend parameters (pinned against
-- 'Haskoki.Recipe.RsaOaep' by RecipeOaepSpec). 'Nothing' means
-- uncovered (non-OAEP mechanism) or malformed parameters.
rsaOaepParamsFor :: MechanismId -> ByteString -> Maybe OaepParams
rsaOaepParamsFor mech params = do
  r <- rsaOaepRecipeFor mech
  guard (rsaOaepParamsValid r params)
  (d, m, label) <- decodeOaepParams params
  hashAlg <- rsaDigest d
  mgfAlg <- rsaDigest m
  pure (OaepParams hashAlg mgfAlg label)

-- | An OAEP mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed OAEP params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isRsaOaepMech :: MechanismId -> Bool
isRsaOaepMech mech = isJust (rsaOaepRecipeFor mech)

-- | RSA-X.509 dispatch: the covered (mechanism, params) pair to
-- its sign/verify backend spec (pinned against
-- 'Haskoki.Recipe.RsaX509' by RecipeX509Spec). 'Nothing' means
-- uncovered (non-X.509 mechanism) or malformed parameters.
rsaX509SigFor :: MechanismId -> ByteString -> Maybe SigSpec
rsaX509SigFor mech params = do
  r <- rsaX509RecipeFor mech
  guard (rsaX509ParamsValid r params)
  pure SigRSA_X509

-- | RSA-X.509 dispatch: the covered (mechanism, params) pair to
-- its cipher backend params (pinned against
-- 'Haskoki.Recipe.RsaX509' by RecipeX509Spec). 'Nothing' means
-- uncovered (non-X.509 mechanism) or malformed parameters.
rsaX509CipherFor :: MechanismId -> ByteString -> Maybe RsaCipherParams
rsaX509CipherFor mech params = do
  r <- rsaX509RecipeFor mech
  guard (rsaX509ParamsValid r params)
  pure RsaX509

-- | An X.509 mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed X.509 params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isRsaX509Mech :: MechanismId -> Bool
isRsaX509Mech mech = isJust (rsaX509RecipeFor mech)

-- | ECDSA dispatch: covered (mechanism, params, key) triples to
-- backend specs (pinned against
-- 'Haskoki.Recipe.Ecdsa' by RecipeEcdsaSpec). The recipe binds the
-- digest and validates the encoding selection; the curve label is
-- a dispatch hint from the DER key ('ecCurveOfKey'), defaulting to
-- P-256 when the key is unscannable (the backends execute against
-- the key's actual material and refuse bad keys themselves — the
-- driver never refuses a key). 'Nothing' means uncovered
-- (non-ECDSA mechanism) or malformed parameters.
ecdsaSpecFor :: MechanismId -> ByteString -> KeyMaterial -> Maybe SigSpec
ecdsaSpecFor mech params key = do
  r <- ecdsaRecipeFor mech
  guard (ecdsaParamsValid r params)
  enc <- ecdsaEncodingOf params
  alg <- case reDigestStem r of
    Nothing -> pure Nothing
    Just stem -> Just <$> rsaDigest stem
  let curve = fromMaybe "P-256" (ecCurveOfKey key)
  pure (SigECDSA (EcSpec (T.unpack curve) (T.unpack enc)) alg)

-- | An ECDSA mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed ECDSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isEcdsaMech :: MechanismId -> Bool
isEcdsaMech mech = isJust (ecdsaRecipeFor mech)

-- | DSA dispatch: covered (mechanism, params) pairs to backend
-- specs (pinned against 'Haskoki.Recipe.Dsa' by RecipeDsaSpec).
-- The recipe binds the digest and validates the encoding
-- selection; there is no curve label to hint (the DSA key carries
-- its own domain parameters) and key shape is the backend's call
-- (the driver never refuses a key). 'Nothing' means uncovered
-- (non-DSA mechanism) or malformed parameters.
dsaSpecFor :: MechanismId -> ByteString -> Maybe SigSpec
dsaSpecFor mech params = do
  r <- dsaRecipeFor mech
  guard (dsaParamsValid r params)
  enc <- dsaEncodingOf params
  alg <- case rdDigestStem r of
    Nothing -> pure Nothing
    Just stem -> Just <$> rsaDigest stem
  pure (SigDSA (T.unpack enc) alg)

-- | A DSA mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed DSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isDsaMech :: MechanismId -> Bool
isDsaMech mech = isJust (dsaRecipeFor mech)

-- | EdDSA dispatch: the covered (mechanism, params, key) triple
-- to its backend spec (pinned against 'Haskoki.Recipe.Eddsa' by
-- RecipeEddsaSpec). The recipe validates pure parameters; the
-- curve label is a dispatch hint from the DER key
-- ('eddsaCurveOfKey'), defaulting to Ed25519 when the key is
-- unscannable (the backends execute against the key's actual
-- material and refuse bad keys themselves — the driver never
-- refuses a key). 'Nothing' means uncovered (non-EdDSA mechanism),
-- missing parameters, or non-pure parameters.
eddsaSpecFor :: MechanismId -> ByteString -> KeyMaterial -> Maybe SigSpec
eddsaSpecFor mech params key = do
  r <- eddsaRecipeFor mech
  guard (eddsaParamsValid r params)
  let curve = fromMaybe "Ed25519" (eddsaCurveOfKey key)
  pure (SigEdDSA (EcSpec (T.unpack curve) "RAW") BS.empty)

-- | An EdDSA mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: non-pure EdDSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isEddsaMech :: MechanismId -> Bool
isEddsaMech mech = isJust (eddsaRecipeFor mech)

-- | ML-DSA dispatch: the covered (mechanism, params, key) triple
-- to its backend spec (pinned against 'Haskoki.Recipe.MlDsa' by
-- RecipeMlDsaSpec). The recipe validates the hedge/context
-- parameters (empty defaults to preferred, empty context); the
-- level label is a dispatch hint from the DER key
-- ('mldsaLevelOfKey'), defaulting to ML-DSA-44 when the key is
-- unscannable (the backends execute against the key's actual
-- material and refuse bad keys themselves — the driver never
-- refuses a key). Deterministic hedge clears the hedged flag;
-- external-mu mode never dispatches (out of scope). 'Nothing'
-- means uncovered (non-ML-DSA mechanism) or refused parameters.
mldsaSpecFor :: MechanismId -> ByteString -> KeyMaterial -> Maybe SigSpec
mldsaSpecFor mech params key = do
  r <- mldsaRecipeFor mech
  guard (mldsaParamsValid r params)
  (hedge, ctx) <- decodeMldsaParams params
  let alg = fromMaybe ML_DSA_44 (mldsaLevelOfKey key)
      hedged = hedge /= HedgeDeterministic
  pure (SigMLDSA alg False ctx hedged)

-- | An ML-DSA mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: refused ML-DSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isMldsaMech :: MechanismId -> Bool
isMldsaMech mech = isJust (mldsaRecipeFor mech)

-- | The ML-DSA level named by a key's algorithm OID, via the
-- recipe's 'mldsaLevelOfDer'. Both constructors sniff: production
-- resolves every stored key as 'KeyBytes' ('stdResolver'), so a
-- 'KeyDer'-only sniff would miss every production key and
-- misdispatch it as ML-DSA-44 (the shim's type-name check then
-- refuses with BADKEY). 'Nothing' for references, symmetric
-- bytes, RSA, garbage, or a foreign curve. The marker is
-- advisory for dispatch only: 'mldsaSpecFor' defaults it to
-- ML-DSA-44 and the backends always execute against the key's
-- actual material, so a miss can refuse downstream but never
-- mis-sign.
mldsaLevelOfKey :: KeyMaterial -> Maybe PqcSigAlg
mldsaLevelOfKey (KeyDer der) = mldsaLevelOfDer der >>= levelOfName
mldsaLevelOfKey (KeyBytes bs) = mldsaLevelOfDer bs >>= levelOfName
mldsaLevelOfKey _ = Nothing

-- | SLH-DSA dispatch: the covered (mechanism, params, key) triple
-- to its backend spec (pinned against 'Haskoki.Recipe.SlhDsa' by
-- RecipeSlhDsaSpec). The recipe validates the hedge/context
-- parameters (empty defaults to preferred, empty context); the
-- set label is a dispatch hint from the DER key
-- ('slhdsaLevelOfKey'), defaulting to SLH-DSA-SHA2-128s when the
-- key is unscannable (the backends execute against the key's
-- actual material and refuse bad keys themselves — the driver
-- never refuses a key). Deterministic hedge clears the hedged
-- flag. 'Nothing' means uncovered (non-SLH-DSA mechanism) or
-- refused parameters.
slhdsaSpecFor :: MechanismId -> ByteString -> KeyMaterial -> Maybe SigSpec
slhdsaSpecFor mech params key = do
  r <- slhdsaRecipeFor mech
  guard (slhdsaParamsValid r params)
  (hedge, ctx) <- decodeSlhdsaParams params
  let alg = fromMaybe SLH_DSA_SHA2_128s (slhdsaLevelOfKey key)
      hedged = hedge /= SlhDeterministic
  pure (SigSLHDSA alg ctx hedged)

-- | An SLH-DSA mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: refused SLH-DSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isSlhdsaMech :: MechanismId -> Bool
isSlhdsaMech mech = isJust (slhdsaRecipeFor mech)

-- | The SLH-DSA set named by a key's algorithm OID, via the
-- recipe's 'slhdsaLevelOfDer'. Both constructors sniff: production
-- resolves every stored key as 'KeyBytes' ('stdResolver'), so a
-- 'KeyDer'-only sniff would miss every production key and
-- misdispatch it as SLH-DSA-SHA2-128s (the shim's type-name check
-- then refuses with BADKEY). 'Nothing' for references, symmetric
-- bytes, RSA, garbage, or a foreign curve. The marker is
-- advisory for dispatch only: 'slhdsaSpecFor' defaults it to
-- SLH-DSA-SHA2-128s and the backends always execute against the
-- key's actual material, so a miss can refuse downstream but never
-- mis-sign.
slhdsaLevelOfKey :: KeyMaterial -> Maybe PqcSigAlg
slhdsaLevelOfKey (KeyDer der) = slhdsaLevelOfDer der >>= levelOfName
slhdsaLevelOfKey (KeyBytes bs) = slhdsaLevelOfDer bs >>= levelOfName
slhdsaLevelOfKey _ = Nothing

-- | Engine level names onto backend algorithms.
levelOfName :: T.Text -> Maybe PqcSigAlg
levelOfName name = case T.unpack name of
  "ML-DSA-44" -> Just ML_DSA_44
  "ML-DSA-65" -> Just ML_DSA_65
  "ML-DSA-87" -> Just ML_DSA_87
  "SLH-DSA-SHA2-128s" -> Just SLH_DSA_SHA2_128s
  "SLH-DSA-SHA2-128f" -> Just SLH_DSA_SHA2_128f
  "SLH-DSA-SHA2-192s" -> Just SLH_DSA_SHA2_192s
  "SLH-DSA-SHA2-192f" -> Just SLH_DSA_SHA2_192f
  "SLH-DSA-SHA2-256s" -> Just SLH_DSA_SHA2_256s
  "SLH-DSA-SHA2-256f" -> Just SLH_DSA_SHA2_256f
  "SLH-DSA-SHAKE-128s" -> Just SLH_DSA_SHAKE_128s
  "SLH-DSA-SHAKE-128f" -> Just SLH_DSA_SHAKE_128f
  "SLH-DSA-SHAKE-192s" -> Just SLH_DSA_SHAKE_192s
  "SLH-DSA-SHAKE-192f" -> Just SLH_DSA_SHAKE_192f
  "SLH-DSA-SHAKE-256s" -> Just SLH_DSA_SHAKE_256s
  "SLH-DSA-SHAKE-256f" -> Just SLH_DSA_SHAKE_256f
  _ -> Nothing

-- | The Edwards curve named by a key's curve OID, via the
-- recipe's 'eddsaCurveOfDer'. Both constructors sniff: production
-- resolves every stored key as 'KeyBytes' ('stdResolver'), so a
-- 'KeyDer'-only sniff would miss every production Ed448 key and
-- misdispatch it as Ed25519 (the shim's base-id check then
-- refuses with BADKEY). 'Nothing' for references, symmetric
-- bytes, RSA, garbage, or a Weierstrass curve. The marker is
-- advisory for dispatch only: 'eddsaSpecFor' defaults it to
-- Ed25519 and the backends always execute against the key's
-- actual material, so a miss can refuse downstream but never
-- mis-sign.
eddsaCurveOfKey :: KeyMaterial -> Maybe T.Text
eddsaCurveOfKey (KeyDer der) = eddsaCurveOfDer der
eddsaCurveOfKey (KeyBytes bs) = eddsaCurveOfDer bs
eddsaCurveOfKey _ = Nothing

-- | The curve named by a DER key's curve OID, via the recipe's
-- 'ecdsaCurveOfDer' ('Nothing' for raw bytes, references, RSA,
-- garbage, or an off-set curve). The marker is advisory for
-- dispatch only: 'ecdsaSpecFor' defaults it to P-256 and the
-- backends always execute against the key's actual material, so a
-- miss can refuse downstream but never mis-sign.
ecCurveOfKey :: KeyMaterial -> Maybe T.Text
ecCurveOfKey (KeyDer der) = ecdsaCurveOfDer der
ecCurveOfKey _ = Nothing

-- | ECDH dispatch: the covered (mechanism, params) pair to the
-- backend agreement shape plus the peer public key (pinned
-- against 'Haskoki.Recipe.Ecdh' by RecipeEcdhSpec). The cofactor
-- flag comes from the mechanism row. 'Nothing' means uncovered
-- (non-ECDH mechanism) or malformed parameters (a KDF selector
-- included — the recipe serves the null KDF only).
ecdhParamsFor :: MechanismId -> ByteString -> Maybe (EcdhSpec, ByteString)
ecdhParamsFor mech params = do
  r <- ecdhRecipeFor mech
  guard (ecdhParamsValid r params)
  (_, _, peer) <- decodeEcdhParams params
  pure (if rhCofactor r then EcdhCofactor else EcdhPlain, peer)

-- | An ECDH mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed ECDH params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isEcdhMech :: MechanismId -> Bool
isEcdhMech mech = isJust (ecdhRecipeFor mech)

-- | DH agreement parameters for one covered (mechanism, params)
-- pair: the backend spec plus the peer public value. 'Nothing'
-- means uncovered (non-DH mechanism) or malformed parameters (a
-- KDF selector included — the recipe serves the null KDF only).
dhParamsFor :: MechanismId -> ByteString -> Maybe (DhSpec, ByteString)
dhParamsFor mech params = do
  r <- dhRecipeFor mech
  guard (dhParamsValid r params)
  (_, peer) <- decodeDhParams params
  pure (DhPlain, peer)

-- | A DH mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed DH params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isDhMech :: MechanismId -> Bool
isDhMech mech = isJust (dhRecipeFor mech)

-- | Resolve a bound key object to backend key material. 'Nothing'
-- means the object is unknown to the caller (reported as
-- 'CryptoBadKey', never fabricated).
type KeyResolver = ObjectId -> Maybe KeyMaterial

-- | Answer one planned effect against the backend.
runEffect :: CryptoBackend b => BackendEnv b -> KeyResolver -> CryptoEffect -> IO CryptoResult
runEffect env resolve fx = case fx of
  FxDigest mech input -> case digestAlgFor mech of
    Just alg -> toBytes <$> digestOneShot env alg input
    Nothing -> pure (unsupported fx)
  FxDigestInit mech -> case digestAlgFor mech of
    Just alg -> toResource <$> digestInit env alg
    Nothing -> pure (unsupported fx)
  FxDigestFeed rid input -> toUnit <$> digestUpdate env rid input
  FxDigestConsume rid -> toBytes <$> digestFinal env rid
  FxSign mech mkey params input
    | Just spec <- hmacSpecFor mech params -> withKey mkey $ \key ->
        toBytes <$> macSign env spec key input
    | isHmacMech mech -> pure (GotCryptoError (CryptoMechParamInvalid "hmac"
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey mkey $ \key ->
        runCmacSign mech params key input
    | isDes3MacMech mech -> withKey mkey $ \key ->
        runDes3MacSign mech params key input
    | isHotpMech mech -> withKey mkey $ \key ->
        runHotpSign mech params key input
    | Just spec <- rsaPkcs1SpecFor mech params -> withKey mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaPkcs1Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA v1.5 takes empty mechanism parameters"))
    | Just spec <- rsaPssSpecFor mech params -> withKey mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaPssMech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-PSS takes pss-params/1 (hash, MGF1 hash, salt 0..64)"))
    | Just spec <- rsaX509SigFor mech params -> withKey mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaX509Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X.509 takes empty mechanism parameters"))
    | isEcdsaMech mech -> withKey mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure ecdsaRefusal
    | isDsaMech mech -> withKey mkey $ \key ->
        case dsaSpecFor mech params of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure dsaRefusal
    | isEddsaMech mech -> withKey mkey $ \key ->
        case eddsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure eddsaRefusal
    | isMldsaMech mech -> withKey mkey $ \key ->
        case mldsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure mldsaRefusal
    | isSlhdsaMech mech -> withKey mkey $ \key ->
        case slhdsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure slhdsaRefusal
    | otherwise -> pure (unsupported fx)
  FxVerify mech mkey params input sig
    | Just spec <- hmacSpecFor mech params -> withKey mkey $ \key ->
        toVerifyBool <$> macVerify env spec key input sig
    | isHmacMech mech -> pure (GotCryptoError (CryptoMechParamInvalid "hmac"
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey mkey $ \key ->
        runCmacVerify mech params key input sig
    | isDes3MacMech mech -> withKey mkey $ \key ->
        runDes3MacVerify mech params key input sig
    | isHotpMech mech -> withKey mkey $ \key ->
        runHotpVerify mech params key input sig
    | Just spec <- rsaPkcs1SpecFor mech params -> withKey mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaPkcs1Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA v1.5 takes empty mechanism parameters"))
    | Just spec <- rsaPssSpecFor mech params -> withKey mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaPssMech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-PSS takes pss-params/1 (hash, MGF1 hash, salt 0..64)"))
    | Just spec <- rsaX509SigFor mech params -> withKey mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaX509Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X.509 takes empty mechanism parameters"))
    | isEcdsaMech mech -> withKey mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure ecdsaRefusal
    | isDsaMech mech -> withKey mkey $ \key ->
        case dsaSpecFor mech params of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure dsaRefusal
    | isEddsaMech mech -> withKey mkey $ \key ->
        case eddsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure eddsaRefusal
    | isMldsaMech mech -> withKey mkey $ \key ->
        case mldsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure mldsaRefusal
    | isSlhdsaMech mech -> withKey mkey $ \key ->
        case slhdsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure slhdsaRefusal
    | otherwise -> pure (unsupported fx)
  FxCipher dir mech mkey params input
    | isCipherMech mech -> withKey mkey $ \key ->
        runCipher dir mech key params input
    | isGcmMech mech -> withKey mkey $ \key ->
        runAead dir mech key params input
    | isCcmMech mech -> withKey mkey $ \key ->
        runAead dir mech key params input
    | isChachaPolyMech mech -> withKey mkey $ \key ->
        runAead dir mech key params input
    | isRsaOaepMech mech -> withKey mkey $ \key ->
        runOaep dir mech key params input
    | isRsaX509Mech mech -> withKey mkey $ \key ->
        runX509 dir mech key params input
    | otherwise -> pure (unsupported fx)
  FxMessageCipher dir mech mkey params aad input
    | isGcmMech mech -> withKey mkey $ \key ->
        runAeadMessage dir mech key params aad input
    | not (isCipherMech mech) && not (isRsaOaepMech mech) && not (isRsaX509Mech mech) ->
        pure (unsupported fx)
    | not (BS.null aad) -> pure (GotCryptoError (CryptoUnsupported "driver"
        "non-AEAD backend takes no AAD"))
    | isRsaOaepMech mech -> withKey mkey $ \key ->
        runOaep dir mech key params input
    | isRsaX509Mech mech -> withKey mkey $ \key ->
        runX509 dir mech key params input
    | otherwise -> withKey mkey $ \key ->
        runCipher dir mech key params input
  FxMessageSign mech mkey params input
    | Just spec <- hmacSpecFor mech params -> withKey mkey $ \key ->
        toBytes <$> macSign env spec key input
    | isHmacMech mech -> pure (GotCryptoError (CryptoMechParamInvalid "hmac"
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey mkey $ \key ->
        runCmacSign mech params key input
    | isDes3MacMech mech -> withKey mkey $ \key ->
        runDes3MacSign mech params key input
    | isHotpMech mech -> withKey mkey $ \key ->
        runHotpSign mech params key input
    | Just spec <- rsaPkcs1SpecFor mech params -> withKey mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaPkcs1Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA v1.5 takes empty mechanism parameters"))
    | Just spec <- rsaPssSpecFor mech params -> withKey mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaPssMech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-PSS takes pss-params/1 (hash, MGF1 hash, salt 0..64)"))
    | Just spec <- rsaX509SigFor mech params -> withKey mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaX509Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X.509 takes empty mechanism parameters"))
    | isEcdsaMech mech -> withKey mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure ecdsaRefusal
    | isDsaMech mech -> withKey mkey $ \key ->
        case dsaSpecFor mech params of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure dsaRefusal
    | isEddsaMech mech -> withKey mkey $ \key ->
        case eddsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure eddsaRefusal
    | isMldsaMech mech -> withKey mkey $ \key ->
        case mldsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure mldsaRefusal
    | isSlhdsaMech mech -> withKey mkey $ \key ->
        case slhdsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure slhdsaRefusal
    | otherwise -> pure (unsupported fx)
  FxMessageVerify mech mkey params input sig
    | Just spec <- hmacSpecFor mech params -> withKey mkey $ \key ->
        toVerifyBool <$> macVerify env spec key input sig
    | isHmacMech mech -> pure (GotCryptoError (CryptoMechParamInvalid "hmac"
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey mkey $ \key ->
        runCmacVerify mech params key input sig
    | isDes3MacMech mech -> withKey mkey $ \key ->
        runDes3MacVerify mech params key input sig
    | isHotpMech mech -> withKey mkey $ \key ->
        runHotpVerify mech params key input sig
    | Just spec <- rsaPkcs1SpecFor mech params -> withKey mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaPkcs1Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA v1.5 takes empty mechanism parameters"))
    | Just spec <- rsaPssSpecFor mech params -> withKey mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaPssMech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-PSS takes pss-params/1 (hash, MGF1 hash, salt 0..64)"))
    | Just spec <- rsaX509SigFor mech params -> withKey mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaX509Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X.509 takes empty mechanism parameters"))
    | isEcdsaMech mech -> withKey mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure ecdsaRefusal
    | isDsaMech mech -> withKey mkey $ \key ->
        case dsaSpecFor mech params of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure dsaRefusal
    | isEddsaMech mech -> withKey mkey $ \key ->
        case eddsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure eddsaRefusal
    | isMldsaMech mech -> withKey mkey $ \key ->
        case mldsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure mldsaRefusal
    | isSlhdsaMech mech -> withKey mkey $ \key ->
        case slhdsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure slhdsaRefusal
    | otherwise -> pure (unsupported fx)
  FxSignRecover {} -> pure (unsupported fx)
  FxVerifyRecover {} -> pure (unsupported fx)
  FxGenerateKey mech params input
    | not (BS.null params)
    , mech /= tlsPremasterKeyGenMech
    , mech /= ssl3PremasterKeyGenMech
    , mech /= wtlsPremasterKeyGenMech
    , mech /= pbkd2KeyGenMech -> pure (GotCryptoError (CryptoFailed
        "driver: keygen takes no mechanism params"))
    | otherwise -> case decodeGenArgs input of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: malformed keygen args"))
        Just args -> case (mech, args) of
          (m, GenMlKem n) | m == mlKemKeyPairGenMech -> case mlKemAlg n of
            Just alg -> toKeyPair <$> generateKey env (GenMLKEM alg)
            Nothing -> pure (GotCryptoError (CryptoFailed
              ("driver: unknown KEM parameter set: " ++ show n)))
          (m, GenAes n) | m == aesKeyGenMech ->
            toKeyPair <$> generateKey env (GenSym "AES" n)
          (m, GenBytes n) | m == des3KeyGenMech ->
            toKeyPair <$> generateKey env (GenSym "DES3" n)
          (m, GenBytes n) | m == hotpKeyGenMech ->
            toKeyPair <$> generateKey env (GenSym "HOTP" n)
          (m, GenBytes n) | m == blake2b512KeyGenMech ->
            toKeyPair <$> generateKey env (GenSym "BLAKE2B-512-HMAC" n)
          (m, GenBytes n) | m == chacha20KeyGenMech ->
            toKeyPair <$> generateKey env (GenSym "ChaCha20" n)
          (m, GenBytes n) | m == genericSecretKeyGenMech ->
            toKeyPair <$> generateKey env (GenSym "GENERIC" n)
          (m, GenBytes n) | Just label <- lookup m symKeygenLabels ->
            toKeyPair <$> generateKey env (GenSym label n)
          (m, GenParityBytes n) | Just label <- lookup m symKeygenLabels -> do
            res <- generateKey env (GenSym label n)
            pure (toParityPair res)
          (m, GenTlsPremaster major minor)
            | m == tlsPremasterKeyGenMech || m == ssl3PremasterKeyGenMech ->
                toPrefixedPair (BS.pack [major, minor])
                  <$> generateKey env (GenSym "TLS-PRE-MASTER" 46)
          (m, GenWtlsPremaster ver n) | m == wtlsPremasterKeyGenMech ->
            toPrefixedPair (BS.singleton ver)
              <$> generateKey env (GenSym "WTLS-PRE-MASTER" (n - 1))
          (m, GenPbkd2 n) | m == pbkd2KeyGenMech ->
            case decodePbkd2Params params of
              Just (stem, iters, salt, pwd) -> case rsaDigest stem of
                Just alg
                  | n >= 1 && n <= pbkd2KeygenMaxBytes -> do
                      r <- pbkdf2 alg iters salt (KeyBytes pwd) n
                      pure $ case r of
                        EngineFail err -> GotCryptoError (toCryptoError err)
                        EngineOk dk -> toKeyPair
                          (EngineOk (KeyBytes (BS.take n dk), Nothing))
                  | otherwise -> pure (GotCryptoError (CryptoFailed
                      "driver: PBKD2 length out of range"))
                Nothing -> pure (GotCryptoError (CryptoFailed
                  "driver: PBKD2 PRF stem is not servable"))
              Nothing -> pure (GotCryptoError (CryptoFailed
                "driver: malformed PBKD2 keygen params"))
          (m, GenEc curve) | m == ecKeyPairGenMech ->
            toKeyPair <$> generateKey env (GenEC (EcSpec (BC8.unpack curve) "DER"))
          (m, GenRsa bits e) | m == rsaKeyPairGenMech ->
            toKeyPair <$> generateKey env (GenRSA bits e)
          (m, GenDsaParams p q) | m == dsaParameterGenMech ->
            toKeyPair <$> generateKey env (GenDSAParams p q)
          (m, GenDsaKeypair der) | m == dsaKeyPairGenMech ->
            toKeyPair <$> generateKey env (GenDSAKeypair der)
          (m, GenDhKeypair der)
            | m == dhKeyPairGenMech || m == x9_42DhKeyPairGenMech ->
            toKeyPair <$> generateKey env (GenDHKeypair der)
          (m, GenEdwardsKeypair curve) | m == edwardsKeyPairGenMech ->
            toKeyPair <$> generateKey env (GenEdDSAKeypair curve)
          (m, GenMontgomeryKeypair curve) | m == montgomeryKeyPairGenMech ->
            toKeyPair <$> generateKey env (GenXDHKeypair curve)
          (m, GenMlDsa n) | m == mldsaKeyPairGenMech -> case mlDsaAlg n of
            Just alg -> toKeyPair <$> generateKey env (GenMLDSA alg)
            Nothing -> pure (GotCryptoError (CryptoFailed
              ("driver: unknown ML-DSA parameter set: " ++ show n)))
          (m, GenSlhDsa n) | m == slhdsaKeyPairGenMech -> case slhDsaAlg n of
            Just alg -> toKeyPair <$> generateKey env (GenSLHDSA alg)
            Nothing -> pure (GotCryptoError (CryptoFailed
              ("driver: unknown SLH-DSA parameter set: " ++ show n)))
          _
            | mech `elem` [aesKeyGenMech, des3KeyGenMech, hotpKeyGenMech, genericSecretKeyGenMech, chacha20KeyGenMech, ecKeyPairGenMech, rsaKeyPairGenMech, mlKemKeyPairGenMech, dsaKeyPairGenMech, dsaParameterGenMech, dhKeyPairGenMech, x9_42DhKeyPairGenMech, edwardsKeyPairGenMech, montgomeryKeyPairGenMech, mldsaKeyPairGenMech, slhdsaKeyPairGenMech, pbkd2KeyGenMech] ->
                pure (GotCryptoError (CryptoFailed
                  "driver: keygen args mismatch the mechanism"))
            | otherwise -> pure (unsupported fx)
  FxKemEncaps mech mkey params input
    | mech /= mlKemMech -> pure (unsupported fx)
    | not (BS.null input) -> pure (GotCryptoError (CryptoFailed
        "driver: encaps takes no input"))
    | otherwise -> case kemAlgFromName params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: unknown KEM parameter name"))
        Just alg -> withKey mkey $ \key ->
          toKemPair <$> kemEncapsulate env (KemSpec (toPqcKem alg)) key
  FxKemDecaps mech mkey params input
    | mech /= mlKemMech -> pure (unsupported fx)
    | otherwise -> case kemAlgFromName params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: unknown KEM parameter name"))
        Just alg -> withKey mkey $ \key ->
          toBytes <$> kemDecapsulate env (KemSpec (toPqcKem alg)) key input
  FxWrap _mech mkey params input
    | _mech == aesCbcMech -> withKey mkey $ \key ->
        runCipher DirEncrypt _mech key params input
    | isAesKwWrapMech _mech -> withKey mkey $ \key ->
        runCipher DirEncrypt _mech key params input
    | isRsaOaepMech _mech -> withKey mkey $ \key ->
        runOaep DirEncrypt _mech key params input
    | isRsaPkcsWrapMech _mech -> withKey mkey $ \key ->
        runPkcs1 DirEncrypt _mech key params input
    | isRsaX509Mech _mech -> withKey mkey $ \key ->
        runX509 DirEncrypt _mech key params input
    | otherwise -> pure (unsupported fx)
  FxUnwrap _mech mkey params input
    | _mech == aesCbcMech -> withKey mkey $ \key ->
        runCipher DirDecrypt _mech key params input
    | isAesKwWrapMech _mech -> withKey mkey $ \key ->
        runCipher DirDecrypt _mech key params input
    | isRsaOaepMech _mech -> withKey mkey $ \key ->
        runOaep DirDecrypt _mech key params input
    | isRsaPkcsWrapMech _mech -> withKey mkey $ \key ->
        runPkcs1 DirDecrypt _mech key params input
    | isRsaX509Mech _mech -> withKey mkey $ \key ->
        runX509 DirDecrypt _mech key params input
    | otherwise -> pure (unsupported fx)
  FxAuthWrap _mech mkey params input
    | _mech /= aesCbcMech -> pure (unsupported fx)
    | otherwise -> case decodeWrapParams params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: malformed auth-wrap params"))
        Just (iv, aad) -> withKey mkey $ \key ->
          runAuthWrap True _mech key iv aad input
  FxAuthUnwrap _mech mkey params input
    | _mech /= aesCbcMech -> pure (unsupported fx)
    | otherwise -> case decodeWrapParams params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: malformed auth-wrap params"))
        Just (iv, aad) -> withKey mkey $ \key ->
          runAuthWrap False _mech key iv aad input
  FxDerive mech mkey params info outLen
    | mech == hkdfDeriveMech -> case hkdfParamsFor params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: malformed HKDF prf/mode/salt params"))
        Just (alg, hashLen, mode, salt)
          | outLen < 1 || outLen > 255 * hashLen -> pure (GotCryptoError (CryptoFailed
              "driver: derive length out of range"))
          | otherwise -> withKey mkey $ \key -> case key of
              KeyBytes ikm
                | mode == 0x02 -> toBytes <$> hkdfExpand env spec key info outLen
                | otherwise -> toBytes <$> hkdfExtractExpand env spec hashLen ikm salt info outLen
              _ -> pure (GotCryptoError (CryptoBadKey "driver"
                "HKDF base key is not byte material"))
          where spec = MacHMAC alg Nothing
    | isEcdhMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: ECDH derive takes no info string"))
    | Just (spec, peer) <- ecdhParamsFor mech params -> withKey mkey $ \key ->
        runEcdh spec key peer outLen
    | isEcdhMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: ECDH mechanism parameters rejected by the recipe"))
    | isDhMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: DH derive takes no info string"))
    | Just (spec, peer) <- dhParamsFor mech params -> withKey mkey $ \key ->
        runDh spec key peer outLen
    | isDhMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: DH mechanism parameters rejected by the recipe"))
    | isKdfShaMech mech
    , not (BS.null params) || not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: SHA key derivation takes empty params and info"))
    | Just alg <- kdfShaFor mech -> withKey mkey $ \key ->
        runShaKd alg key outLen
    | Just pp <- pbkd2ParamsFor mech params
    , BS.null info -> withKey mkey $ \key ->
        runPbkd2 pp key outLen
    | isPbkd2Mech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: PBKDF2 derive takes no info string"))
    | isPbkd2Mech mech -> pure (GotCryptoError (CryptoFailed
        "driver: PBKDF2 mechanism parameters rejected by the recipe"))
    | Just prf <- tlsPrfParamsFor mech params
    , BS.null info -> withKey mkey $ \key ->
        runTlsPrf prf key outLen
    | isTlsPrfMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: TLS-PRF derive takes no info string"))
    | isTlsPrfMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: TLS-PRF mechanism parameters rejected by the recipe"))
    | otherwise -> pure (unsupported fx)
  where
    withKey :: Maybe ObjectId -> (KeyMaterial -> IO CryptoResult) -> IO CryptoResult
    withKey Nothing _ = pure (GotCryptoError (CryptoBadKey "driver" "effect binds no key"))
    withKey (Just oid) k = case resolve oid of
      Nothing -> pure (GotCryptoError (CryptoBadKey "driver" ("unknown key object: " ++ show oid)))
      Just mat -> k mat
    -- | CMAC sign effects: the SP 800-38B composition over the
    -- backend ECB route, truncated for GENERAL rows. Off-geometry
    -- (mechanism, key length, params) triples are 'CryptoFailed';
    -- a non-bytes key is 'CryptoBadKey'.
    runCmacSign :: MechanismId -> ByteString -> KeyMaterial -> ByteString -> IO CryptoResult
    runCmacSign mech params key input = case key of
      KeyBytes kb -> case cmacSpecFor mech params (BS.length kb) of
        Just (spec, trunc) -> do
          r <- cmacTag spec key input
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk tag -> GotBytes (maybe tag (`BS.take` tag) trunc)
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: CMAC (mechanism, key length, params) rejected by the recipe"))
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "CMAC needs raw symmetric key bytes"))
    -- | CMAC verify effects: recompute, truncate, constant-time
    -- compare. A mismatch is the 'False' verdict, never a
    -- malfunction.
    runCmacVerify :: MechanismId -> ByteString -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
    runCmacVerify mech params key input tag = case key of
      KeyBytes kb -> case cmacSpecFor mech params (BS.length kb) of
        Just (spec, trunc) -> do
          r <- cmacTag spec key input
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk full
              | driverCtEq want tag -> GotValid True
              | otherwise -> GotValid False
              where want = maybe full (`BS.take` full) trunc
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: CMAC (mechanism, key length, params) rejected by the recipe"))
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "CMAC needs raw symmetric key bytes"))
    -- | 3DES-MAC sign effects: CBC-MAC chaining over the backend
    -- ECB route, truncated to the half block (plain) or the
    -- decoded length (GENERAL). Off-geometry (mechanism, key
    -- length, params) triples are 'CryptoFailed'; a non-bytes key
    -- is 'CryptoBadKey'.
    runDes3MacSign :: MechanismId -> ByteString -> KeyMaterial -> ByteString -> IO CryptoResult
    runDes3MacSign mech params key input = case key of
      KeyBytes kb -> case des3macSpecFor mech params (BS.length kb) of
        Just (spec, trunc) -> do
          r <- des3macTag spec key input
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk tag -> GotBytes (maybe tag (`BS.take` tag) trunc)
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: 3DES-MAC (mechanism, key length, params) rejected by the recipe"))
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "3DES-MAC needs raw symmetric key bytes"))
    -- | 3DES-MAC verify effects: recompute, truncate,
    -- constant-time compare. A mismatch is the 'False' verdict,
    -- never a malfunction.
    runDes3MacVerify :: MechanismId -> ByteString -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
    runDes3MacVerify mech params key input tag = case key of
      KeyBytes kb -> case des3macSpecFor mech params (BS.length kb) of
        Just (spec, trunc) -> do
          r <- des3macTag spec key input
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk full
              | driverCtEq want tag -> GotValid True
              | otherwise -> GotValid False
              where want = maybe full (`BS.take` full) trunc
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: 3DES-MAC (mechanism, key length, params) rejected by the recipe"))
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "3DES-MAC needs raw symmetric key bytes"))
    -- | HOTP sign effects: HMAC-SHA1 over the counter, then RFC
    -- 4226 dynamic truncation to ASCII digits. The input is always
    -- empty (HOTP signs the counter only); anything else is a
    -- 'CryptoFailed' parameter refusal, never silently signed.
    runHotpSign :: MechanismId -> ByteString -> KeyMaterial -> ByteString -> IO CryptoResult
    runHotpSign mech params key input = case key of
      KeyBytes _ -> case hotpParamsFor mech params of
        Just (counter, digits)
          | BS.null input -> do
              r <- macSign env (MacHMAC D_SHA1 Nothing) key (encodeHotpCounter counter)
              pure $ case r of
                EngineFail err -> GotCryptoError (toCryptoError err)
                EngineOk mac -> case hotpTruncate mac digits of
                  Just code -> GotBytes code
                  Nothing -> shortMac
          | otherwise -> pure (GotCryptoError (CryptoFailed
              "driver: HOTP signs the counter only: input must be empty"))
        _ -> pure (GotCryptoError (CryptoFailed
            "driver: HOTP takes hotp-params/1 (counter, 6-8 digits)"))
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "HOTP needs raw symmetric key bytes"))
    -- | HOTP verify effects: recompute, truncate, constant-time
    -- compare. A mismatch is the 'False' verdict, never a
    -- malfunction.
    runHotpVerify :: MechanismId -> ByteString -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
    runHotpVerify mech params key input want = case key of
      KeyBytes _ -> case hotpParamsFor mech params of
        Just (counter, digits)
          | BS.null input -> do
              r <- macSign env (MacHMAC D_SHA1 Nothing) key (encodeHotpCounter counter)
              pure $ case r of
                EngineFail err -> GotCryptoError (toCryptoError err)
                EngineOk mac -> case hotpTruncate mac digits of
                  Just code
                    | driverCtEq code want -> GotValid True
                    | otherwise -> GotValid False
                  Nothing -> shortMac
          | otherwise -> pure (GotCryptoError (CryptoFailed
              "driver: HOTP signs the counter only: input must be empty"))
        _ -> pure (GotCryptoError (CryptoFailed
            "driver: HOTP takes hotp-params/1 (counter, 6-8 digits)"))
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "HOTP needs raw symmetric key bytes"))
    -- | A backend MAC shorter than HMAC-SHA1's 20 bytes breaks the
    -- backend contract; the truncation cannot run. Both shipped
    -- backends return full-width MACs, so this arm is defensive.
    shortMac :: CryptoResult
    shortMac = GotCryptoError (CryptoFailed
      "driver: HOTP backend MAC too short to truncate")
    -- | The SP 800-38B tag: subkey doubling (Rb 0x87 for 128-bit
    -- blocks, 0x1B for 64-bit), last-block padding (10*) when
    -- short, CBC-MAC chaining over single-block ECB calls. Full
    -- width; truncation is the caller's call.
    cmacTag :: CipherSpec -> KeyMaterial -> ByteString -> IO (EngineResult ByteString)
    cmacTag spec key input = case (cmacBlockOf spec, cmacRbOf spec) of
      (Just blk, Just rb) -> do
        lz <- enc (BS.replicate blk 0)
        case lz of
          EngineFail err -> pure (EngineFail err)
          EngineOk lb -> do
            let k1 = gfDouble rb lb
                k2 = gfDouble rb k1
                blks = chunksOf blk input
                (front, lastM) = case unsnoc blks of
                  Nothing -> ([], padBlock blk BS.empty `xorB` k2)
                  Just (pre, lst)
                    | BS.length lst == blk -> (pre, lst `xorB` k1)
                    | otherwise -> (pre, padBlock blk lst `xorB` k2)
            chain (BS.replicate blk 0) (front ++ [lastM])
      _ -> pure (EngineFail (BackendBadParam "cmac"
        "CMAC needs an AES or 3DES ECB cipher spec"))
      where
        enc b = cipherEncrypt env spec key BS.empty b
        chain x [] = pure (EngineOk x)
        chain x (m : ms) = do
          e <- enc (x `xorB` m)
          case e of
            EngineFail err -> pure (EngineFail err)
            EngineOk x' -> chain x' ms
    -- | The 3DES CBC-MAC tag: zero IV, input zero-padded to the
    -- 8-byte block, chaining over single-block ECB calls. Full
    -- width; truncation is the caller's call.
    des3macTag :: CipherSpec -> KeyMaterial -> ByteString -> IO (EngineResult ByteString)
    des3macTag spec key input
      | spec /= C_DES3_ECB = pure (EngineFail (BackendBadParam "des3mac"
          "3DES-MAC needs the 3DES ECB cipher spec"))
      | otherwise = chain (BS.replicate blk 0) (zeroPad blk input)
      where
        blk = 8
        enc b = cipherEncrypt env spec key BS.empty b
        chain x [] = pure (EngineOk x)
        chain x (m : ms) = do
          e <- enc (x `xorB` m)
          case e of
            EngineFail err -> pure (EngineFail err)
            EngineOk x' -> chain x' ms
    runCipher :: CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
    runCipher dir mech key iv input = case key of
      KeyBytes kb -> case cipherSpecFor mech (BS.length kb) iv of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: cipher (mechanism, key length, params) rejected by the recipe"))
        -- CTR parameters are the canonical image, not the raw
        -- counter block: split the served 128-bit image (the recipe
        -- already validated it; a mistimed image fails closed).
        -- ChaCha20 parameters split the same way into the backend
        -- (counter, nonce) framing.
        Just spec -> case cipherImage iv of
          Nothing -> pure (GotCryptoError (CryptoFailed
            "driver: cipher parameter image rejected"))
          Just cb -> case dir of
            DirEncrypt -> toBytes <$> cipherEncrypt env spec key cb input
            DirDecrypt -> toBytes <$> cipherDecrypt env spec key cb input
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "block ciphers need raw symmetric key bytes"))
      where
        cipherImage params = case ctrRecipeFor mech of
          Just _ -> case decodeCtrParams params of
            Just (128, cb) -> Just cb
            _ -> Nothing
          Nothing
            | isChachaStreamMech mech -> case decodeChachaStreamParams params of
                Just (counter, nonce) -> Just (encodeChachaIv counter nonce)
                _ -> Nothing
            | otherwise -> Just params

    -- | AEAD cipher effects: the @gcm-params/1@ image decodes to
    -- (IV, AAD, tag length); the key length selects the AES width.
    -- Encrypt answers ciphertext and tag concatenated; decrypt
    -- splits the input at the tag length. An input shorter than
    -- the tag carries no tag to verify and fails authentication
    -- ('CryptoAuthFailed', never a wrong plaintext).
    runAead :: CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
    runAead dir mech key params input = case key of
      KeyBytes kb -> case aeadPartsFor mech (BS.length kb) params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: AEAD (mechanism, key length, params) rejected by the recipe"))
        Just (spec, iv, aad)
          | isCcmMech mech, ccmLengthBad dir params input (aeadTagLen spec) ->
              pure (GotCryptoError (CryptoFailed
                "driver: CCM ulDataLen does not match the input length"))
          | otherwise -> runAeadSealed dir spec key iv aad input
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "AEAD needs raw symmetric key bytes"))
    -- | AEAD message effects: the parameters decode (IV, tag length)
    -- as above, but the AAD travels on the effect, not in the
    -- parameters.
    runAeadMessage :: CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> ByteString -> IO CryptoResult
    runAeadMessage dir mech key params aad input = case key of
      KeyBytes kb -> case aeadPartsFor mech (BS.length kb) params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: AEAD (mechanism, key length, params) rejected by the recipe"))
        Just (spec, iv, _) -> runAeadSealed dir spec key iv aad input
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "AEAD needs raw symmetric key bytes"))
    runAeadSealed :: CipherDir -> AeadSpec -> KeyMaterial -> ByteString -> ByteString -> ByteString -> IO CryptoResult
    runAeadSealed dir spec key iv aad input = case dir of
      DirEncrypt -> toKemPair <$> aeadEncrypt env spec key iv aad input
      DirDecrypt
        | BS.length input < aeadTagLen spec -> pure (GotCryptoError (CryptoAuthFailed
            "driver: AEAD input shorter than the authentication tag"))
        | otherwise ->
            let (ct, tag) = BS.splitAt (BS.length input - aeadTagLen spec) input
            in toBytes <$> aeadDecrypt env spec key iv aad ct tag

    -- | RSA-OAEP cipher effects: the effect parameters carry the
    -- @oaep-params\/1@ encoding straight to the asymmetric backend
    -- entry points (encrypt takes the public half, decrypt the
    -- private half; both travel as DER key material).
    runOaep :: CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
    runOaep dir mech key params input =
      case rsaOaepParamsFor mech params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: OAEP mechanism parameters rejected by the recipe"))
        Just oparams -> case dir of
          DirEncrypt -> toBytes <$> pkeyEncrypt env (RsaOaep oparams) key input
          DirDecrypt -> toBytes <$> pkeyDecrypt env (RsaOaep oparams) key input

    -- | RSA v1.5 cipher effects (wrap/unwrap only): empty
    -- parameters straight to the asymmetric backend entry points
    -- (encrypt takes the public half, decrypt the private half;
    -- both travel as DER key material).
    runPkcs1 :: CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
    runPkcs1 dir _mech key params input
      | not (BS.null params) = pure (GotCryptoError (CryptoFailed
          "driver: v1.5 wrap takes no mechanism parameters"))
      | otherwise = case dir of
          DirEncrypt -> toBytes <$> pkeyEncrypt env RsaPkcs1 key input
          DirDecrypt -> toBytes <$> pkeyDecrypt env RsaPkcs1 key input

    -- | RSA-X.509 cipher effects: empty parameters straight to the
    -- asymmetric backend entry points (encrypt takes the public
    -- half, decrypt the private half; both travel as DER key
    -- material). The backends left-pad short inputs to the modulus
    -- width and answer full k-blocks.
    runX509 :: CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
    runX509 dir mech key params input =
      case rsaX509CipherFor mech params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: X.509 mechanism parameters rejected by the recipe"))
        Just cparams -> case dir of
          DirEncrypt -> toBytes <$> pkeyEncrypt env cparams key input
          DirDecrypt -> toBytes <$> pkeyDecrypt env cparams key input
    runAuthWrap :: Bool -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> ByteString -> IO CryptoResult
    runAuthWrap isWrap mech key iv aad input = case key of
      KeyBytes kb -> case cipherSpecFor mech (BS.length kb) iv of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: auth-wrap (mechanism, key length, params) rejected by the recipe"))
        Just spec -> do
          macKeyR <- macSign env hmacSpec key authWrapDomain
          case macKeyR of
            EngineFail err -> pure (GotCryptoError (toCryptoError err))
            EngineOk macKey -> run (KeyBytes macKey) spec
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "auth-wrap needs raw symmetric key bytes"))
      where
        run macKey spec
          | isWrap = wrapWith macKey spec
          | badUnwrapLen = pure (GotCryptoError
              (CryptoFailed "driver: authenticated blob length"))
          | otherwise = unwrapWith macKey spec
        badUnwrapLen = BS.length input < 32
          || (BS.length input - 32) `mod` 16 /= 0
        wrapWith macKey spec = do
          ctR <- cipherEncrypt env spec key iv input
          case ctR of
            EngineFail err -> pure (GotCryptoError (toCryptoError err))
            EngineOk ct -> do
              tagR <- macSign env hmacSpec macKey (aad <> ct)
              pure $ case tagR of
                EngineFail err -> GotCryptoError (toCryptoError err)
                EngineOk tag -> GotBytes (ct <> tag)
        unwrapWith macKey spec = do
          let (ct, tag) = BS.splitAt (BS.length input - 32) input
          verR <- macVerify env hmacSpec macKey (aad <> ct) tag
          case verR of
            EngineFail (BackendAuthFailed _) ->
              pure (GotCryptoError (CryptoAuthFailed "auth-unwrap"))
            EngineFail err -> pure (GotCryptoError (toCryptoError err))
            EngineOk False ->
              pure (GotCryptoError (CryptoAuthFailed "auth-unwrap"))
            EngineOk True -> toBytes <$> cipherDecrypt env spec key iv ct
    -- | ECDH agreement effects: the backend agrees the full raw
    -- secret over (base key, peer public key) and the driver
    -- truncates to the planned length. A planned length past the
    -- secret is 'CryptoFailed' (the planner caps honestly, so this
    -- fires only for hand-built effects); backend key-shape
    -- refusals keep their taxonomy.
    runEcdh :: EcdhSpec -> KeyMaterial -> ByteString -> Int -> IO CryptoResult
    runEcdh spec key peer outLen
      | outLen < 1 = pure (GotCryptoError (CryptoFailed
          "driver: derive length out of range"))
      | otherwise = do
          r <- ecdhDerive env spec key (KeyDer peer)
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk secret
              | BS.length secret < outLen -> GotCryptoError (CryptoFailed
                  "driver: derive length exceeds the agreement secret")
              -- Truncation drops leading bytes (PKCS#11 v3.2 ECDH:
              -- "removes bytes from the leading end"); full width
              -- drops nothing.
              | otherwise -> GotBytes
                  (BS.drop (BS.length secret - outLen) secret)
    -- | Classic DH agreement: the backend proves the full secret,
    -- truncation drops leading bytes (PKCS#11 v3.2 DH derive
    -- "removes bytes from the leading end", matching ECDH).
    runDh :: DhSpec -> KeyMaterial -> ByteString -> Int -> IO CryptoResult
    runDh spec key peer outLen
      | outLen < 1 = pure (GotCryptoError (CryptoFailed
          "driver: derive length out of range"))
      | otherwise = do
          r <- dhDerive env spec key (KeyDer peer)
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk secret
              | BS.length secret < outLen -> GotCryptoError (CryptoFailed
                  "driver: derive length exceeds the agreement secret")
              | otherwise -> GotBytes
                  (BS.drop (BS.length secret - outLen) secret)
    -- | SHA key-derivation effects: digest the base value,
    -- truncate to the planned length (capped by the digest width —
    -- the planner caps honestly, so over-width fires only for
    -- hand-built effects).
    runShaKd :: DigestAlg -> KeyMaterial -> Int -> IO CryptoResult
    runShaKd alg key outLen = case key of
      KeyBytes kb -> case digestOutLen alg of
        Just w
          | outLen >= 1 && outLen <= w -> do
              r <- digestOneShot env alg kb
              pure $ case r of
                EngineFail err -> GotCryptoError (toCryptoError err)
                EngineOk d -> GotBytes (BS.take outLen d)
        _ -> pure (GotCryptoError (CryptoFailed
          "driver: derive length out of range"))
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "key derivation needs raw secret bytes"))
    -- | PBKDF2 effects: the RFC 8018 iteration over the HMAC PRF,
    -- truncated to the planned length (capped by the shared
    -- ceiling).
    runPbkd2 :: Pbkd2Params -> KeyMaterial -> Int -> IO CryptoResult
    runPbkd2 (Pbkd2Params prf iters salt) key outLen = case key of
      KeyBytes _
        | outLen >= 1 && outLen <= maxDerivedTotal -> do
            r <- pbkdf2 prf iters salt key outLen
            pure $ case r of
              EngineFail err -> GotCryptoError (toCryptoError err)
              EngineOk dk -> GotBytes (BS.take outLen dk)
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: derive length out of range"))
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "key derivation needs raw secret bytes"))
    -- | PBKDF2 proper: T_i = F(password, salt, iters, i) with the
    -- HMAC PRF, concatenated across ceil(outLen\/hLen) blocks.
    pbkdf2 :: DigestAlg -> Int -> ByteString -> KeyMaterial -> Int -> IO (EngineResult ByteString)
    pbkdf2 prf iters salt pwd outLen = case digestOutLen prf of
      Nothing -> pure (EngineFail (BackendBadParam "pbkdf2"
        "PBKDF2 needs a fixed-width PRF"))
      Just h -> do
        let n = (outLen + h - 1) `div` h
        go n 1 []
      where
        go 0 _ acc = pure (EngineOk (BS.concat (reverse acc)))
        go k i acc = do
          b <- fBlock i
          case b of
            EngineFail err -> pure (EngineFail err)
            EngineOk t -> go (k - 1) (i + 1) (t : acc)
        fBlock i = do
          u1 <- prfOf (salt <> word32BE i)
          case u1 of
            EngineFail err -> pure (EngineFail err)
            EngineOk u -> mix (iters - 1) u u
        mix 0 acc _ = pure (EngineOk acc)
        mix k acc prev = do
          u <- prfOf prev
          case u of
            EngineFail err -> pure (EngineFail err)
            EngineOk u' -> mix (k - 1) (acc `xorB` u') u'
        prfOf msg = macSign env (MacHMAC prf Nothing) pwd msg
    -- | TLS-PRF effects: the RFC 2246 expansion over the backend
    -- HMAC-MD5\/SHA-1 routes. Off-range lengths are 'CryptoFailed';
    -- a non-bytes key is 'CryptoBadKey'.
    runTlsPrf :: TlsPrfParams -> KeyMaterial -> Int -> IO CryptoResult
    runTlsPrf (TlsPrfParams lab seed) key outLen = case key of
      KeyBytes kb
        | outLen >= 1 && outLen <= maxTlsPrfOutput -> do
            r <- tlsPrfExpand kb (lab <> seed) outLen
            pure $ case r of
              EngineFail err -> GotCryptoError (toCryptoError err)
              EngineOk ok -> GotBytes (BS.take outLen ok)
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: derive length out of range"))
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "key derivation needs raw secret bytes"))
    -- | TLS 1.0\/1.1 PRF: P_MD5 over the first secret half XOR
    -- P_SHA-1 over the second (RFC 2246 §5; the halves share the
    -- middle byte on odd lengths).
    tlsPrfExpand :: ByteString -> ByteString -> Int -> IO (EngineResult ByteString)
    tlsPrfExpand secret seedBytes outLen = do
      m <- pHash D_MD5 (KeyBytes s1) seedBytes outLen
      case m of
        EngineFail err -> pure (EngineFail err)
        EngineOk mOut -> do
          s <- pHash D_SHA1 (KeyBytes s2) seedBytes outLen
          pure $ case s of
            EngineFail err -> EngineFail err
            EngineOk sOut -> EngineOk (BS.take outLen mOut `xorB` BS.take outLen sOut)
      where
        (s1, s2) = splitTlsSecret secret
    -- | P_hash: A(0) = seed, A(i) = HMAC(secret, A(i-1)),
    -- P(i) = HMAC(secret, A(i) ++ seed), concatenated.
    pHash :: DigestAlg -> KeyMaterial -> ByteString -> Int -> IO (EngineResult ByteString)
    pHash alg secret seedBytes outLen = case digestOutLen alg of
      Nothing -> pure (EngineFail (BackendBadParam "pHash"
        "TLS-PRF needs a fixed-width HMAC"))
      Just h -> do
        let n = (outLen + h - 1) `div` h
        go n seedBytes []
      where
        go 0 _ acc = pure (EngineOk (BS.concat (reverse acc)))
        go k aPrev acc = do
          aNext <- macSign env (MacHMAC alg Nothing) secret aPrev
          case aNext of
            EngineFail err -> pure (EngineFail err)
            EngineOk a -> do
              p <- macSign env (MacHMAC alg Nothing) secret (a <> seedBytes)
              case p of
                EngineFail err -> pure (EngineFail err)
                EngineOk blk -> go (k - 1) a (blk : acc)
    unsupported :: CryptoEffect -> CryptoResult
    unsupported e = GotCryptoError (CryptoUnsupported "driver" (show e))

-- | ECDSA dispatch refusal: 'ecdsaSpecFor' only fails on
-- malformed parameters (same message as the OpenSSL driver), so the
-- refusal is unconditionally a 'CryptoFailed' parameter refusal.
ecdsaRefusal :: CryptoResult
ecdsaRefusal = GotCryptoError (CryptoFailed "ECDSA: params must be RAW, DER, or empty")

-- | DSA dispatch refusal: 'dsaSpecFor' only fails on malformed
-- parameters, so the refusal is unconditionally a 'CryptoFailed'
-- parameter refusal.
dsaRefusal :: CryptoResult
dsaRefusal = GotCryptoError (CryptoFailed "DSA: params must be RAW, DER, or empty")

-- | EdDSA dispatch refusal: 'eddsaSpecFor' only fails on
-- non-pure parameters, so the refusal is unconditionally a
-- 'CryptoFailed' parameter refusal.
eddsaRefusal :: CryptoResult
eddsaRefusal = GotCryptoError (CryptoFailed "EdDSA: params must be an explicit pure struct (phFlag clear, empty context)")

-- | ML-DSA dispatch refusal: 'mldsaSpecFor' only fails on
-- refused parameters, so the refusal is unconditionally a
-- 'CryptoFailed' parameter refusal.
mldsaRefusal :: CryptoResult
mldsaRefusal = GotCryptoError (CryptoFailed "ML-DSA: params must be mldsa-params/1 (hedge 0..2, context 0..255 bytes) or empty")
slhdsaRefusal :: CryptoResult
slhdsaRefusal = GotCryptoError (CryptoFailed "SLH-DSA: params must be slhdsa-params/1 (hedge 0..2, context 0..255 bytes) or empty")

-- | CMAC block width per cipher (only the ECB specs 'cmacSpecFor'
-- yields).
cmacBlockOf :: CipherSpec -> Maybe Int
cmacBlockOf spec = case spec of
  C_AES128_ECB -> Just 16
  C_AES192_ECB -> Just 16
  C_AES256_ECB -> Just 16
  C_DES3_ECB -> Just 8
  _ -> Nothing

-- | CMAC reduction constant per cipher (SP 800-38B: 0x87 for
-- 128-bit blocks, 0x1B for 64-bit).
cmacRbOf :: CipherSpec -> Maybe Word8
cmacRbOf spec = case spec of
  C_DES3_ECB -> Just 0x1b
  C_AES128_ECB -> Just 0x87
  C_AES192_ECB -> Just 0x87
  C_AES256_ECB -> Just 0x87
  _ -> Nothing

-- | GF(2^n) doubling: left shift by one bit, conditional xor of Rb
-- into the low byte.
gfDouble :: Word8 -> ByteString -> ByteString
gfDouble rb w =
  let bytes = BS.unpack w
      msb = case bytes of
        (b : _) -> b .&. 0x80 /= 0
        [] -> False
      shifted = snd (foldr sh (0, []) bytes)
      sh b (carry, acc) =
        ((if b .&. 0x80 /= 0 then 1 else 0), ((b `shiftL` 1) .|. carry) : acc)
      mask = replicate (length bytes - 1) 0 ++ [if msb then rb else 0]
  in BS.pack (zipWith xor shifted mask)

-- | Byte-wise xor (block pairs by construction).
xorB :: ByteString -> ByteString -> ByteString
xorB a b = BS.pack (BS.zipWith xor a b)

-- | CMAC 10* padding of a short last block.
padBlock :: Int -> ByteString -> ByteString
padBlock blk lastB =
  lastB <> BS.singleton 0x80 <> BS.replicate (blk - BS.length lastB - 1) 0

-- | Split into full-or-final blocks.
chunksOf :: Int -> ByteString -> [ByteString]
chunksOf n bs
  | BS.null bs = []
  | otherwise = let (h, t) = BS.splitAt n bs in h : chunksOf n t

-- | Split into zero-padded full blocks (empty input yields one
-- zero block, so CBC-MAC over empty input is well-defined).
zeroPad :: Int -> ByteString -> [ByteString]
zeroPad n bs = case chunksOf n bs of
  [] -> [BS.replicate n 0]
  blks -> case unsnoc blks of
    Just (pre, lst)
      | BS.length lst == n -> blks
      | otherwise -> pre ++ [lst <> BS.replicate (n - BS.length lst) 0]
    Nothing -> [BS.replicate n 0]

-- | Four-byte big-endian word (PBKDF2 block index).
word32BE :: Int -> ByteString
word32BE n = BS.pack
  [ fromIntegral ((n `shiftR` 24) .&. 0xff)
  , fromIntegral ((n `shiftR` 16) .&. 0xff)
  , fromIntegral ((n `shiftR` 8) .&. 0xff)
  , fromIntegral (n .&. 0xff)
  ]

-- | Constant-time byte equality for driver-level MAC verification
-- (mirrors the backend-local compares).
driverCtEq :: ByteString -> ByteString -> Bool
driverCtEq a b =
  BS.length a == BS.length b
    && foldl' (\acc (x, y) -> acc .|. (x `xor` y)) 0 (BS.zip a b) == 0

-- | Bytes-shaped answers: backend failures map onto the typed
-- crypto errors.
toBytes :: EngineResult ByteString -> CryptoResult
toBytes (EngineOk b) = GotBytes b
toBytes (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Allocation answers: the resource id crosses to the finisher,
-- which records it on the slot.
toResource :: EngineResult EngineResourceId -> CryptoResult
toResource (EngineOk rid) = GotResource rid
toResource (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Feed answers: success carries no bytes, and the unit shape is
-- preserved as 'GotUnit' — distinct from empty bytes —
-- through the driver helpers until 'encodeResult'.
toUnit :: EngineResult () -> CryptoResult
toUnit (EngineOk ()) = GotUnit
toUnit (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Backend failures onto crypto errors: total and
-- category-preserving. Each backend error maps to its mirror
-- crypto error with fields intact; a bytes-shaped authentication
-- failure stays 'CryptoAuthFailed'. Every case keeps the code its
-- collapse produced.
toCryptoError :: BackendError -> CryptoError
toCryptoError err = case err of
  BackendUnsupported o w -> CryptoUnsupported o w
  BackendBadParam o w -> CryptoBadParam o w
  BackendBadKey o w -> CryptoBadKey o w
  BackendMechParamInvalid o w -> CryptoMechParamInvalid o w
  BackendAuthFailed o -> CryptoAuthFailed o
  BackendInvalidState o w -> CryptoInvalidState o w
  BackendNative o c w -> CryptoNative o c w
  BackendResourceGone o r -> CryptoResourceGone o r

-- | Backend errors onto core failures: the exact
-- constructor-for-constructor mirror. Total both ways with
-- 'fromCoreFailure' (see the round-trip pins).
toCoreFailure :: BackendError -> O.BackendFailure
toCoreFailure err = case err of
  BackendUnsupported o w -> O.BackendUnsupported o w
  BackendBadParam o w -> O.BackendBadParam o w
  BackendBadKey o w -> O.BackendBadKey o w
  BackendMechParamInvalid o w -> O.BackendMechParamInvalid o w
  BackendAuthFailed o -> O.BackendAuthFailed o
  BackendInvalidState o w -> O.BackendInvalidState o w
  BackendNative o c w -> O.BackendNative o c w
  BackendResourceGone o r -> O.BackendResourceGone o r

-- | Core failures back onto backend errors: the exact inverse of
-- 'toCoreFailure' over all eight constructors.
fromCoreFailure :: O.BackendFailure -> BackendError
fromCoreFailure f = case f of
  O.BackendUnsupported o w -> BackendUnsupported o w
  O.BackendBadParam o w -> BackendBadParam o w
  O.BackendBadKey o w -> BackendBadKey o w
  O.BackendMechParamInvalid o w -> BackendMechParamInvalid o w
  O.BackendAuthFailed o -> BackendAuthFailed o
  O.BackendInvalidState o w -> BackendInvalidState o w
  O.BackendNative o c w -> BackendNative o c w
  O.BackendResourceGone o r -> BackendResourceGone o r

-- | Crypto failures back onto core failures: the exact
-- inverse of 'toCryptoError' on the eight shared categories. The
-- unclassified 'CryptoFailed' bucket has no backend counterpart and
-- lands on a native failure (pinned one-way mapping, code unchanged).
cryptoToCore :: CryptoError -> O.BackendFailure
cryptoToCore err = case err of
  CryptoUnsupported o w -> O.BackendUnsupported o w
  CryptoBadParam o w -> O.BackendBadParam o w
  CryptoBadKey o w -> O.BackendBadKey o w
  CryptoMechParamInvalid o w -> O.BackendMechParamInvalid o w
  CryptoAuthFailed o -> O.BackendAuthFailed o
  CryptoInvalidState o w -> O.BackendInvalidState o w
  CryptoNative o c w -> O.BackendNative o c w
  CryptoResourceGone o r -> O.BackendResourceGone o r
  CryptoFailed s -> O.BackendNative "driver" (-1) s

-- | Keygen answers: the framed private half plus the optional public
-- half. A backend reference (rather than owned material) cannot
-- cross to the object store and fails loudly.
--
-- | Sweep keygens onto backend 'GenSym' labels (slice 11a): the
-- planner admits lengths, the label only selects the backend's
-- domain separation and bound mirror.
symKeygenLabels :: [(MechanismId, String)]
symKeygenLabels =
  [ (desKeyGenMech, "DES")
  , (des2KeyGenMech, "DES2")
  , (cdmfKeyGenMech, "CDMF")
  , (castKeyGenMech, "CAST")
  , (cast3KeyGenMech, "CAST3")
  , (cast128KeyGenMech, "CAST128")
  , (rc2KeyGenMech, "RC2")
  , (rc4KeyGenMech, "RC4")
  , (rc5KeyGenMech, "RC5")
  , (ideaKeyGenMech, "IDEA")
  , (skipjackKeyGenMech, "SKIPJACK")
  , (batonKeyGenMech, "BATON")
  , (juniperKeyGenMech, "JUNIPER")
  , (blowfishKeyGenMech, "BLOWFISH")
  , (twofishKeyGenMech, "TWOFISH")
  , (gost28147KeyGenMech, "GOST28147")
  , (seedKeyGenMech, "SEED")
  , (ariaKeyGenMech, "ARIA")
  , (camelliaKeyGenMech, "CAMELLIA")
  , (salsa20KeyGenMech, "SALSA20")
  , (poly1305KeyGenMech, "POLY1305")
  , (aesXtsKeyGenMech, "AES-XTS")
  , (hkdfKeyGenMech, "HKDF")
  , (sha1KeyGenMech, "SHA-1-HMAC")
  , (sha224KeyGenMech, "SHA224-HMAC")
  , (sha256KeyGenMech, "SHA256-HMAC")
  , (sha384KeyGenMech, "SHA384-HMAC")
  , (sha512KeyGenMech, "SHA512-HMAC")
  , (sha512_224KeyGenMech, "SHA512-224-HMAC")
  , (sha512_256KeyGenMech, "SHA512-256-HMAC")
  , (sha512TKeyGenMech, "SHA512-T-HMAC")
  , (sha3_224KeyGenMech, "SHA3-224-HMAC")
  , (sha3_256KeyGenMech, "SHA3-256-HMAC")
  , (sha3_384KeyGenMech, "SHA3-384-HMAC")
  , (sha3_512KeyGenMech, "SHA3-512-HMAC")
  , (blake2b160KeyGenMech, "BLAKE2B-160-HMAC")
  , (blake2b256KeyGenMech, "BLAKE2B-256-HMAC")
  , (blake2b384KeyGenMech, "BLAKE2B-384-HMAC")
  ]

-- | Parity keygen answers: the backend mints random bytes and the
-- driver sets odd DES parity on the private half (FIPS 46-3),
-- so both backends share one parity home.
toParityPair :: EngineResult (KeyMaterial, Maybe KeyMaterial) -> CryptoResult
toParityPair (EngineOk (priv, mPub)) = toKeyPair (EngineOk (parityMat priv, mPub))
  where
    parityMat (KeyBytes bs) = KeyBytes (setOddParity bs)
    parityMat other = other
toParityPair (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Set odd parity on every byte (DES key material).
setOddParity :: ByteString -> ByteString
setOddParity = BS.map setByte
  where
    setByte b
      | odd (popCount b) = b
      | otherwise = b `xor` 1

-- | Prefixed keygen answers: the version bytes lead the
-- backend-minted random tail (TLS/SSL3/WTLS pre-master).
toPrefixedPair :: ByteString -> EngineResult (KeyMaterial, Maybe KeyMaterial) -> CryptoResult
toPrefixedPair prefix (EngineOk (priv, mPub)) = toKeyPair (EngineOk (prefixMat priv, mPub))
  where
    prefixMat (KeyBytes bs) = KeyBytes (prefix <> bs)
    prefixMat other = other
toPrefixedPair _ (EngineFail err) = GotCryptoError (toCryptoError err)
toKeyPair :: EngineResult (KeyMaterial, Maybe KeyMaterial) -> CryptoResult
toKeyPair (EngineOk (priv, mPub)) = case (keyBytes priv, traverse keyBytes mPub) of
  (Just p, Just q) -> GotBytes (encodeKeyPair p q)
  _ -> GotCryptoError (CryptoFailed "driver: keygen returned an unexportable reference")
  where
    keyBytes :: KeyMaterial -> Maybe ByteString
    keyBytes (KeyBytes bs) = Just bs
    keyBytes (KeyDer bs) = Just bs
    keyBytes (KeyRefMaterial _) = Nothing
toKeyPair (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Encapsulation answers: @ciphertext || secret@ for the finisher
-- to split at the mechanism's ciphertext length.
toKemPair :: EngineResult (ByteString, ByteString) -> CryptoResult
toKemPair (EngineOk (ct, ss)) = GotBytes (ct <> ss)
toKemPair (EngineFail err) = GotCryptoError (toCryptoError err)

-- | ML-KEM parameter-set numbers onto backend algorithms.
mlKemAlg :: Int -> Maybe PqcKemAlg
mlKemAlg n = case n of
  512 -> Just ML_KEM_512
  768 -> Just ML_KEM_768
  1024 -> Just ML_KEM_1024
  _ -> Nothing

-- | ML-DSA parameter-set ids (@CKP_ML_DSA_44\/65\/87@) onto
-- backend algorithms.
mlDsaAlg :: Int -> Maybe PqcSigAlg
mlDsaAlg n = case n of
  1 -> Just ML_DSA_44
  2 -> Just ML_DSA_65
  3 -> Just ML_DSA_87
  _ -> Nothing

-- | SLH-DSA parameter-set ids (@CKP_SLH_DSA_*@) onto backend
-- algorithms.
slhDsaAlg :: Int -> Maybe PqcSigAlg
slhDsaAlg n = case n of
  1 -> Just SLH_DSA_SHA2_128s
  2 -> Just SLH_DSA_SHAKE_128s
  3 -> Just SLH_DSA_SHA2_128f
  4 -> Just SLH_DSA_SHAKE_128f
  5 -> Just SLH_DSA_SHA2_192s
  6 -> Just SLH_DSA_SHAKE_192s
  7 -> Just SLH_DSA_SHA2_192f
  8 -> Just SLH_DSA_SHAKE_192f
  9 -> Just SLH_DSA_SHA2_256s
  10 -> Just SLH_DSA_SHAKE_256s
  11 -> Just SLH_DSA_SHA2_256f
  12 -> Just SLH_DSA_SHAKE_256f
  _ -> Nothing

-- | Planner KEM sets onto backend algorithms.
toPqcKem :: KemAlg -> PqcKemAlg
toPqcKem alg = case alg of
  KemMl512 -> ML_KEM_512
  KemMl768 -> ML_KEM_768
  KemMl1024 -> ML_KEM_1024

-- | The fixed HMAC-SHA-256 spec behind derivation and
-- authenticated wrapping.
hmacSpec :: MacSpec
hmacSpec = MacHMAC D_SHA256 Nothing

-- | Domain separation between the wrapping key's cipher use and its
-- tag use: the tag key is @HMAC(wrapKey, domain)@, never the raw
-- wrapping key.
authWrapDomain :: ByteString
authWrapDomain = "HASKOKI-AUTHWRAP-MAC-V1"

-- | HKDF effect params (@prf:u8 mode:u8 salt@) onto the
-- backend digest, its hash length, the stage mode, and the salt.
-- The PRF code resolves through 'kdfCodeDigest' and the stem
-- through 'rsaDigest' (unservable HMACs refuse); the mode must
-- select expand (extract-only never reaches the driver — the
-- planner refuses it first).
hkdfParamsFor :: ByteString -> Maybe (DigestAlg, Int, Word8, ByteString)
hkdfParamsFor params = do
  (prf, r0) <- BS.uncons params
  (mode, salt) <- BS.uncons r0
  guard (mode == 0x02 || mode == 0x03)
  stem <- kdfCodeDigest (fromIntegral prf)
  alg <- rsaDigest stem
  hashLen <- digestOutLen alg
  pure (alg, hashLen, mode, salt)

-- | HKDF-Expand (RFC 5869) with the PRF HMAC over the base key
-- bytes: @T(i) = HMAC(prk, T(i-1) || info || i)@, truncated to the
-- requested length. The caller bounds the length at 255 blocks.
hkdfExpand
  :: CryptoBackend b
  => BackendEnv b -> MacSpec -> KeyMaterial -> ByteString -> Int -> IO (EngineResult ByteString)
hkdfExpand env spec prk info outLen = go BS.empty 1 []
  where
    go :: ByteString -> Int -> [ByteString] -> IO (EngineResult ByteString)
    go prev ctr acc
      | BS.length (BS.concat acc) >= outLen =
          pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
      | ctr > 255 = pure (EngineFail
          (BackendBadParam "derive" "HKDF-Expand counter overflow"))
      | otherwise = do
          r <- macSign env spec prk (prev <> info <> BS.singleton (fromIntegral ctr))
          case r of
            EngineFail err -> pure (EngineFail err)
            EngineOk t -> go t (ctr + 1) (t : acc)

-- | HKDF extract-then-expand (RFC 5869) with the PRF HMAC: the
-- base key bytes are the input keying material, an empty salt
-- extracts against HashLen zeros (RFC 5869 section 2.2), and the
-- extract output feeds 'hkdfExpand' over the context string.
hkdfExtractExpand
  :: CryptoBackend b
  => BackendEnv b -> MacSpec -> Int -> ByteString -> ByteString -> ByteString -> Int
  -> IO (EngineResult ByteString)
hkdfExtractExpand env spec hashLen ikm salt info outLen = do
  let saltKey = KeyBytes (if BS.null salt then BS.replicate hashLen 0 else salt)
  r <- macSign env spec saltKey ikm
  case r of
    EngineFail err -> pure (EngineFail err)
    EngineOk prk -> hkdfExpand env spec (KeyBytes prk) info outLen

-- | Verify-shaped answers: an authentication failure is a verdict,
-- never a malfunction; any other backend failure keeps its
-- category through 'toCryptoError' (categories survive
-- every adapter). Code-neutral on every reachable path: mismatch
-- stays 'False', and every preserved category still interprets to
-- 'CKR_GENERAL_ERROR' (only 'BackendUnsupported' would interpret
-- differently, and it is unreachable here — the mechanism was
-- validated at plan time; should it ever arrive, classifying beats
-- collapsing).
toVerifyBool :: EngineResult Bool -> CryptoResult
toVerifyBool (EngineOk v) = GotValid v
toVerifyBool (EngineFail (BackendAuthFailed _)) = GotValid False
toVerifyBool (EngineFail err) = GotCryptoError (toCryptoError err)

toVerifyUnit :: EngineResult () -> CryptoResult
toVerifyUnit (EngineOk ()) = GotValid True
toVerifyUnit (EngineFail (BackendAuthFailed _)) = GotValid False
toVerifyUnit (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Drain committed releases through the backend: every
-- 'O.ReleaseEngineResource' runs 'releaseResource', so a commit
-- that frees a multipart context cannot leak it. The fold over an
-- empty list is a no-op for the release-free commits.
drainReleases :: CryptoBackend b => BackendEnv b -> [O.ResourceRelease] -> IO ()
drainReleases be = mapM_ drain
  where
    drain (O.ReleaseEngineResource rid) = releaseResource be rid

-- | Adapt a crypto answer onto the 'finishEffect' contract. Verdicts
-- keep their shape ('O.EngineOkValid'); failures keep their
-- taxonomy one-to-one through 'cryptoToCore', so an
-- authentication failure arrives typed instead of collapsing onto
-- native. This is the ONLY collapse point — the unit feed
-- shape ('GotUnit') lands here as empty bytes, byte-identical to
-- the pre-change collapse.
encodeResult :: CryptoResult -> O.EngineResult
encodeResult (GotBytes b) = O.EngineOkBytes b
encodeResult (GotValid v) = O.EngineOkValid v
encodeResult (GotResource rid) = O.EngineOkResource rid
encodeResult GotUnit = O.EngineOkBytes BS.empty
encodeResult (GotCryptoError err) = O.EngineFail (cryptoToCore err)
