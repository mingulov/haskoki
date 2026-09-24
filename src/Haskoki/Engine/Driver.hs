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
(the planner pads); 'FxAuthWrap'\/'FxAuthUnwrap' compose AES-CBC
with an HMAC-SHA-256 tag over @aad || ct@ under a domain-separated
tag key; 'FxDerive' runs HKDF-Expand with HMAC-SHA-256 ('hkdfExpand')
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
  , rsaPkcs1SpecFor
  , rsaPssSpecFor
  , rsaOaepParamsFor
  , ecdsaSpecFor
  , ecCurveOfKey
  , ecdhParamsFor
  , cmacSpecFor
  , hotpParamsFor
  , Pbkd2Params (..)
  , kdfShaFor
  , pbkd2ParamsFor
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Control.Monad (guard)
import Data.Bits ((.&.), (.|.), shiftL, shiftR, xor)
import Data.List (unsnoc)
import Data.Word (Word64, Word8)
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Text as T

import Haskoki.Engine.Backend
  ( BackendError (..)
  , CipherSpec (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EcdhSpec (..)
  , EcSpec (..)
  , EngineResult (..)
  , digestOutLen
  , KemSpec (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , MacSpec (..)
  , OaepParams (..)
  , PqcKemAlg (..)
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
import Haskoki.Recipe.RsaOaep (decodeOaepParams, rsaOaepParamsValid, rsaOaepRecipeFor)
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
  , decodeGenArgs
  , decodeWrapParams
  , ecKeyPairGenMech
  , encodeKeyPair
  , genericSecretKeyGenMech
  , hotpKeyGenMech
  , rsaKeyPairGenMech
  )
import Haskoki.Operation.State (CipherDir (..))
import Haskoki.Recipe.Cmac
  ( CmacRecipe (..)
  , cmacBlockLen
  , cmacRecipeFor
  )
import Haskoki.Recipe.Hmac
  ( HmacRecipe (..)
  , decodeMacGeneral
  , hmacRecipeFor
  )
import Haskoki.Recipe.Kdf
  ( KdfRecipe (..)
  , decodePbkd2Params
  , kdfParamsValid
  , kdfRecipeFor
  )
import Haskoki.Recipe.Otp
  ( decodeHotpParams
  , encodeHotpCounter
  , hotpRecipeFor
  , hotpTruncate
  )
import Haskoki.Registry (MechanismId (..), MechanismName)
import Haskoki.Registry.Generated
  ( ckm_MD5
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
  (stem, iters, salt) <- decodePbkd2Params params
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
cipherSpecFor mech keyLen params = do
  r <- cipherRecipeFor mech
  guard (cipherParamsValid r params)
  guard (cipherKeyLenValid r keyLen)
  cipherCtor (crName r) keyLen

-- | A cipher mechanism regardless of triple validity (drives the
-- parameter-refusal branch: rejected triples are 'CryptoFailed',
-- never 'CryptoUnsupported').
isCipherMech :: MechanismId -> Bool
isCipherMech mech = isJust (cipherRecipeFor mech)

-- | Recipe row + key length onto the backend width. @CKM_AES_CBC_PAD@
-- shares the CBC specs (the planner pads before the effect input is
-- fixed); Triple-DES widths collapse (the engines expand two-key
-- material to @K1||K2||K1@).
cipherCtor :: MechanismName -> Int -> Maybe CipherSpec
cipherCtor name keyLen
  | name == "CKM_AES_CBC" || name == "CKM_AES_CBC_PAD" = aesCbc keyLen
  | name == "CKM_AES_ECB" = aesEcb keyLen
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
    aesEcb n = case n of
      16 -> Just C_AES128_ECB
      24 -> Just C_AES192_ECB
      32 -> Just C_AES256_ECB
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

-- | Recipe digest stem onto the backend digest.
rsaDigest :: T.Text -> Maybe DigestAlg
rsaDigest stem
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
    | isHmacMech mech -> pure (GotCryptoError (CryptoFailed
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey mkey $ \key ->
        runCmacSign mech params key input
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
    | isEcdsaMech mech -> withKey mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure ecdsaRefusal
    | otherwise -> pure (unsupported fx)
  FxVerify mech mkey params input sig
    | Just spec <- hmacSpecFor mech params -> withKey mkey $ \key ->
        toVerifyBool <$> macVerify env spec key input sig
    | isHmacMech mech -> pure (GotCryptoError (CryptoFailed
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey mkey $ \key ->
        runCmacVerify mech params key input sig
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
    | isEcdsaMech mech -> withKey mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure ecdsaRefusal
    | otherwise -> pure (unsupported fx)
  FxCipher dir mech mkey params input
    | isCipherMech mech -> withKey mkey $ \key ->
        runCipher dir mech key params input
    | isRsaOaepMech mech -> withKey mkey $ \key ->
        runOaep dir mech key params input
    | otherwise -> pure (unsupported fx)
  FxMessageCipher dir mech mkey params aad input
    | not (isCipherMech mech) && not (isRsaOaepMech mech) ->
        pure (unsupported fx)
    | not (BS.null aad) -> pure (GotCryptoError (CryptoUnsupported "driver"
        "non-AEAD backend takes no AAD"))
    | isRsaOaepMech mech -> withKey mkey $ \key ->
        runOaep dir mech key params input
    | otherwise -> withKey mkey $ \key ->
        runCipher dir mech key params input
  FxMessageSign mech mkey params input
    | Just spec <- hmacSpecFor mech params -> withKey mkey $ \key ->
        toBytes <$> macSign env spec key input
    | isHmacMech mech -> pure (GotCryptoError (CryptoFailed
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey mkey $ \key ->
        runCmacSign mech params key input
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
    | isEcdsaMech mech -> withKey mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure ecdsaRefusal
    | otherwise -> pure (unsupported fx)
  FxMessageVerify mech mkey params input sig
    | Just spec <- hmacSpecFor mech params -> withKey mkey $ \key ->
        toVerifyBool <$> macVerify env spec key input sig
    | isHmacMech mech -> pure (GotCryptoError (CryptoFailed
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey mkey $ \key ->
        runCmacVerify mech params key input sig
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
    | isEcdsaMech mech -> withKey mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure ecdsaRefusal
    | otherwise -> pure (unsupported fx)
  FxSignRecover {} -> pure (unsupported fx)
  FxVerifyRecover {} -> pure (unsupported fx)
  FxGenerateKey mech params input
    | not (BS.null params) -> pure (GotCryptoError (CryptoFailed
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
          (m, GenBytes n) | m == hotpKeyGenMech ->
            toKeyPair <$> generateKey env (GenSym "HOTP" n)
          (m, GenBytes n) | m == genericSecretKeyGenMech ->
            toKeyPair <$> generateKey env (GenSym "GENERIC" n)
          (m, GenEc curve) | m == ecKeyPairGenMech ->
            toKeyPair <$> generateKey env (GenEC (EcSpec (BC8.unpack curve) "DER"))
          (m, GenRsa bits e) | m == rsaKeyPairGenMech ->
            toKeyPair <$> generateKey env (GenRSA bits e)
          _
            | mech `elem` [aesKeyGenMech, hotpKeyGenMech, genericSecretKeyGenMech, ecKeyPairGenMech, rsaKeyPairGenMech, mlKemKeyPairGenMech] ->
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
  FxWrap _mech mkey iv input
    | _mech /= aesCbcMech -> pure (unsupported fx)
    | otherwise -> withKey mkey $ \key ->
        runCipher DirEncrypt _mech key iv input
  FxUnwrap _mech mkey iv input
    | _mech /= aesCbcMech -> pure (unsupported fx)
    | otherwise -> withKey mkey $ \key ->
        runCipher DirDecrypt _mech key iv input
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
    | mech == hkdfDeriveMech
    , not (BS.null params) -> pure (GotCryptoError (CryptoFailed
        "driver: derive takes no mechanism params"))
    | mech == hkdfDeriveMech
    , outLen < 1 || outLen > 255 * 32 -> pure (GotCryptoError (CryptoFailed
        "driver: derive length out of range"))
    | mech == hkdfDeriveMech -> withKey mkey $ \key ->
        toBytes <$> hkdfExpand env key info outLen
    | isEcdhMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: ECDH derive takes no info string"))
    | Just (spec, peer) <- ecdhParamsFor mech params -> withKey mkey $ \key ->
        runEcdh spec key peer outLen
    | isEcdhMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: ECDH mechanism parameters rejected by the recipe"))
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
    runCipher :: CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
    runCipher dir mech key iv input = case key of
      KeyBytes kb -> case cipherSpecFor mech (BS.length kb) iv of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: cipher (mechanism, key length, params) rejected by the recipe"))
        Just spec -> case dir of
          DirEncrypt -> toBytes <$> cipherEncrypt env spec key iv input
          DirDecrypt -> toBytes <$> cipherDecrypt env spec key iv input
      _ -> pure (GotCryptoError (CryptoBadKey "driver"
        "block ciphers need raw symmetric key bytes"))

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
          DirEncrypt -> toBytes <$> pkeyEncrypt env oparams key input
          DirDecrypt -> toBytes <$> pkeyDecrypt env oparams key input
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
              | otherwise -> GotBytes (BS.take outLen secret)
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
    unsupported :: CryptoEffect -> CryptoResult
    unsupported e = GotCryptoError (CryptoUnsupported "driver" (show e))

-- | ECDSA dispatch refusal: 'ecdsaSpecFor' only fails on
-- malformed parameters (same message as the OpenSSL driver), so the
-- refusal is unconditionally a 'CryptoFailed' parameter refusal.
ecdsaRefusal :: CryptoResult
ecdsaRefusal = GotCryptoError (CryptoFailed "ECDSA: params must be RAW, DER, or empty")

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
  BackendAuthFailed o -> O.BackendAuthFailed o
  BackendInvalidState o w -> O.BackendInvalidState o w
  BackendNative o c w -> O.BackendNative o c w
  BackendResourceGone o r -> O.BackendResourceGone o r

-- | Core failures back onto backend errors: the exact inverse of
-- 'toCoreFailure' over all seven constructors.
fromCoreFailure :: O.BackendFailure -> BackendError
fromCoreFailure f = case f of
  O.BackendUnsupported o w -> BackendUnsupported o w
  O.BackendBadParam o w -> BackendBadParam o w
  O.BackendBadKey o w -> BackendBadKey o w
  O.BackendAuthFailed o -> BackendAuthFailed o
  O.BackendInvalidState o w -> BackendInvalidState o w
  O.BackendNative o c w -> BackendNative o c w
  O.BackendResourceGone o r -> BackendResourceGone o r

-- | Crypto failures back onto core failures: the exact
-- inverse of 'toCryptoError' on the seven shared categories. The
-- unclassified 'CryptoFailed' bucket has no backend counterpart and
-- lands on a native failure (pinned one-way mapping, code unchanged).
cryptoToCore :: CryptoError -> O.BackendFailure
cryptoToCore err = case err of
  CryptoUnsupported o w -> O.BackendUnsupported o w
  CryptoBadParam o w -> O.BackendBadParam o w
  CryptoBadKey o w -> O.BackendBadKey o w
  CryptoAuthFailed o -> O.BackendAuthFailed o
  CryptoInvalidState o w -> O.BackendInvalidState o w
  CryptoNative o c w -> O.BackendNative o c w
  CryptoResourceGone o r -> O.BackendResourceGone o r
  CryptoFailed s -> O.BackendNative "driver" (-1) s

-- | Keygen answers: the framed private half plus the optional public
-- half. A backend reference (rather than owned material) cannot
-- cross to the object store and fails loudly.
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

-- | HKDF-Expand (RFC 5869) with HMAC-SHA-256 over the base key
-- bytes: @T(i) = HMAC(prk, T(i-1) || info || i)@, truncated to the
-- requested length. The caller bounds the length at 255 blocks.
hkdfExpand
  :: CryptoBackend b
  => BackendEnv b -> KeyMaterial -> ByteString -> Int -> IO (EngineResult ByteString)
hkdfExpand env prk info outLen = go BS.empty 1 []
  where
    go :: ByteString -> Int -> [ByteString] -> IO (EngineResult ByteString)
    go prev ctr acc
      | BS.length (BS.concat acc) >= outLen =
          pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
      | ctr > 255 = pure (EngineFail
          (BackendBadParam "derive" "HKDF-Expand counter overflow"))
      | otherwise = do
          r <- macSign env hmacSpec prk (prev <> info <> BS.singleton (fromIntegral ctr))
          case r of
            EngineFail err -> pure (EngineFail err)
            EngineOk t -> go t (ctr + 1) (t : acc)

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
