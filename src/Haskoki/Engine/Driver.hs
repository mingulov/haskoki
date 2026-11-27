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
  Classic only: HOTP has no message routes (no per-message
  parameter shape in PKCS#11 v3.2), so the message effects fall
  through to 'unsupported'.
* RSA PKCS#1 v1.5 runs the recipe 'SigSpec' ('rsaPkcs1SpecFor'):
  every mechanism takes empty parameters; an RSA mechanism with
  malformed parameters is a 'CryptoFailed' parameter refusal, never
  'CryptoUnsupported'.
* RSA-PSS runs the recipe 'SigSpec' ('rsaPssSpecFor'): the
  @pss-params\/1@ encoding carries hash, MGF1 hash, and salt length.
* RSA-X9.31 runs the recipe 'SigSpec' ('rsaX931SigFor'): the raw
  row signs caller digests (the input length selects the hash id),
  the SHA-1 row hashes inside the backend; every mechanism takes
  empty parameters.
* Poly1305 runs the recipe 'MacSpec' ('poly1305MacFor'): the
  16-byte tag under the 32-byte key; empty parameters only.
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
  , rsaRecoverCipherFor
  , recoverType1Pad
  , recoverType1Strip
  , rsaX931SigFor
  , poly1305MacFor
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
  , cbcmacSpecFor
  , xcbcSpecFor
  , gmacSpecFor
  , hotpParamsFor
  , Pbkd2Params (..)
  , kdfShaFor
  , kdfXofFor
  , pbkd2ParamsFor
  , encryptDataPartsFor
  , TlsPrfParams (..)
  , tlsPrfParamsFor
  , Sp800Exec (..)
  , sp800ParamsFor
  , TlsKdfExec (..)
  , tlsKdfParamsFor
  , IkeExec (..)
  , ikeParamsFor
  , ByteOpsExec (..)
  , byteOpsParamsFor
  , KeyMatExec (..)
  , keyMatParamsFor
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8

import Haskoki.Engine.Backend
  ( CryptoBackend (..)
  , EcSpec (..)
  , EngineResult (..)
  , KemSpec (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , MacSpec (..)
  )
import Haskoki.Engine.Driver.Aead
  ( aeadSpecFor
  , isCcmMech
  , isChachaPolyMech
  , isGcmMech
  , runAead
  , runAeadMessage
  )
import Haskoki.Engine.Driver.AuthWrap (runAuthWrap)
import Haskoki.Engine.Driver.ByteOps
  ( ByteOpsExec (..)
  , byteOpsNeedsAux
  , byteOpsParamsFor
  , isByteOpsMech
  , runByteOps
  )
import Haskoki.Engine.Driver.CbcMac
  ( cbcmacSpecFor
  , isCbcMacMech
  , runCbcMacSign
  , runCbcMacVerify
  )
import Haskoki.Engine.Driver.Cipher
  ( cipherSpecFor
  , isCipherMech
  , runCipher
  )
import Haskoki.Engine.Driver.Cmac
  ( cmacSpecFor
  , isCmacMech
  , runCmacSign
  , runCmacVerify
  )
import Haskoki.Engine.Driver.Common
  ( KeyResolver
  , rsaDigest
  , runPubFromPriv
  , unsupported
  , withKey
  )
import Haskoki.Engine.Driver.Des3Mac
  ( des3macSpecFor
  , isDes3MacMech
  , runDes3MacSign
  , runDes3MacVerify
  )
import Haskoki.Engine.Driver.Digest (digestAlgFor)
import Haskoki.Engine.Driver.Dh (dhParamsFor, isDhMech, runDh)
import Haskoki.Engine.Driver.Dsa (dsaRefusal, dsaSpecFor, isDsaMech)
import Haskoki.Engine.Driver.Ecdh (ecdhParamsFor, isEcdhMech, runEcdh)
import Haskoki.Engine.Driver.Ecdsa
  ( ecCurveOfKey
  , ecdsaRefusal
  , ecdsaSpecFor
  , isEcdsaMech
  )
import Haskoki.Engine.Driver.Eddsa
  ( eddsaCurveOfKey
  , eddsaRefusal
  , eddsaSpecFor
  , isEddsaMech
  )
import Haskoki.Engine.Driver.Gmac
  ( gmacSpecFor
  , isGmacMech
  , runGmacSign
  , runGmacVerify
  )
import Haskoki.Engine.Driver.Hmac (hmacSpecFor, isHmacMech)
import Haskoki.Engine.Driver.Hotp
  ( hotpParamsFor
  , isHotpMech
  , runHotpSign
  , runHotpVerify
  )
import Haskoki.Engine.Driver.Ike
  ( IkeExec (..)
  , ikeNeedsAux
  , ikeParamsFor
  , isIkeMech
  , runIke
  )
import Haskoki.Engine.Driver.Kdf
  ( Pbkd2Params (..)
  , encryptDataPartsFor
  , hkdfExpand
  , hkdfExtractExpand
  , hkdfParamsFor
  , isEncryptDataMech
  , isKdfShaMech
  , isKdfXofMech
  , isPbkd2Mech
  , kdfShaFor
  , kdfXofFor
  , pbkd2ParamsFor
  , pbkdf2
  , runEncryptData
  , runPbkd2
  , runShaKd
  , runXofKd
  )
import Haskoki.Engine.Driver.MlDsa
  ( isMldsaMech
  , mldsaLevelOfKey
  , mldsaRefusal
  , mldsaSpecFor
  )
import Haskoki.Engine.Driver.Pbe (runPbe, runPbkdf1)
import Haskoki.Engine.Driver.Poly1305 (isPoly1305Mech, poly1305MacFor)
import Haskoki.Engine.Driver.Rsa
  ( isRsaOaepMech
  , isRsaPkcs1Mech
  , isRsaPssMech
  , isRsaX509Mech
  , isRsaX931Mech
  , recoverType1Pad
  , recoverType1Strip
  , rsaOaepParamsFor
  , rsaPkcs1SpecFor
  , rsaPssSpecFor
  , rsaRecoverCipherFor
  , rsaX509CipherFor
  , rsaX509SigFor
  , rsaX931SigFor
  , runOaep
  , runPkcs1
  , runX509
  )
import Haskoki.Engine.Driver.SlhDsa
  ( isSlhdsaMech
  , slhdsaLevelOfKey
  , slhdsaRefusal
  , slhdsaSpecFor
  )
import Haskoki.Engine.Driver.Sp800
  ( Sp800Exec (..)
  , isSp800Mech
  , runSp800
  , sp800ParamsFor
  )
import Haskoki.Engine.Driver.Ssl3
  ( isSsl3MacMech
  , isSsl3Mech
  , runSsl3
  , runSsl3MacSign
  , runSsl3MacVerify
  , ssl3MacSpecFor
  , ssl3ParamsFor
  )
import Haskoki.Engine.Driver.Tls
  ( KeyMatExec (..)
  , TlsKdfExec (..)
  , TlsPrfParams (..)
  , isKeyMatMech
  , isTlsKdfMech
  , isTlsPrfMech
  , keyMatParamsFor
  , runKeyMat
  , runTlsKdf
  , runTlsPrf
  , tlsKdfParamsFor
  , tlsPrfParamsFor
  )
import Haskoki.Engine.Driver.Wrap
  ( isAesKwWrapMech
  , isRsaPkcsWrapMech
  , runEcdhCompUnwrap
  , runEcdhCompWrap
  , runRsaCompUnwrap
  , runRsaCompWrap
  )
import Haskoki.Engine.Driver.Xcbc
  ( isXcbcMech
  , runXcbcSign
  , runXcbcVerify
  , xcbcSpecFor
  )
import Haskoki.Engine.Driver.KeyGen
  ( mlDsaAlg
  , mlKemAlg
  , slhDsaAlg
  , symKeygenLabels
  , toKeyPair
  , toParityPair
  , toPqcKem
  , toPrefixedPair
  )
import Haskoki.Engine.Driver.Result
  ( cryptoToCore
  , drainReleases
  , encodeResult
  , fromCoreFailure
  , toBytes
  , toCoreFailure
  , toCryptoError
  , toKemPair
  , toResource
  , toUnit
  , toVerifyBool
  , toVerifyUnit
  )
import Haskoki.Operation.Derive (hkdfDataMech, hkdfDeriveMech, pubPrivMech)
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.WrapComp (wrapCompEcdhRecipeFor)
import Haskoki.Recipe.Pbe (PbeKdf (..), PbeRecipe (pbeKind), decodePbeParams, maxPbeIters, pbeIvLen, pbeKdf, pbeKeyLen, pbeNeedsParity, pbeRecipeFor)
import Haskoki.Recipe.WrapCompRsa (wrapCompRsaRecipeFor)
import Haskoki.Recipe.RsaX509 (x509PadBlock)
import Haskoki.Operation.Kem (kemAlgFromName, mlKemKeyPairGenMech, mlKemMech)
import Haskoki.Operation.KeyManagement
  ( GenArgs (..)
  , aesCbcMech
  , aesKeyGenMech
  , blake2b512KeyGenMech
  , chacha20KeyGenMech
  , des3KeyGenMech
  , decodeGenArgs
  , decodeWrapParams
  , dhKeyPairGenMech
  , dhPkcsParameterGenMech
  , dsaKeyPairGenMech
  , dsaParameterGenMech
  , ecExtraBitsKeyPairGenMech
  , ecKeyPairGenMech
  , edwardsKeyPairGenMech
  , montgomeryKeyPairGenMech
  , mldsaKeyPairGenMech
  , slhdsaKeyPairGenMech
  , x9_42DhKeyPairGenMech
  , x9_42DhParameterGenMech
  , genericSecretKeyGenMech
  , hotpKeyGenMech
  , rsaKeyPairGenMech
  , ssl3PremasterKeyGenMech
  , tlsPremasterKeyGenMech
  , wtlsPremasterKeyGenMech
  , pbkd2KeyGenMech
  , pbeDes3KeyGenMech
  , pbeDes2KeyGenMech
  , pbeSha1Cast128KeyGenMech
  , pbeSha1Rc4_128KeyGenMech
  , pbeSha1Rc4_40KeyGenMech
  , pbeSha1Rc2_128KeyGenMech
  , pbeSha1Rc2_40KeyGenMech
  , pbeMd5DesKeyGenMech
  , pbeMd5CastKeyGenMech
  , pbeMd5Cast3KeyGenMech
  , pbeMd5Cast128KeyGenMech
  , pbkd2KeygenMaxBytes
  )
import Haskoki.Operation.State (CipherDir (..))
import Haskoki.Recipe.Kdf (decodePbkd2Params)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated
  ( ckm_RSA_PKCS
  )

-- ---------------------------------------------------------------------------
-- runEffect workers (lifted to top level, 0.6.3 prep)
-- ---------------------------------------------------------------------------
-- These were the @where@-block of 'runEffect'. Each worker takes
-- explicitly what it closed over ('BackendEnv' via 'CryptoBackend',
-- or 'KeyResolver' for 'withKey'); bodies are unchanged apart from
-- re-indentation and @env@ threading between workers. The next step
-- splits them per family.

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
    | Just spec <- hmacSpecFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> macSign env spec key input
    | isHmacMech mech -> pure (GotCryptoError (CryptoMechParamInvalid "hmac"
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey resolve mkey $ \key ->
        runCmacSign env mech params key input
    | isDes3MacMech mech -> withKey resolve mkey $ \key ->
        runDes3MacSign env mech params key input
    | isCbcMacMech mech -> withKey resolve mkey $ \key ->
        runCbcMacSign env mech params key input
    | isXcbcMech mech -> withKey resolve mkey $ \key ->
        runXcbcSign env mech params key input
    | isGmacMech mech -> withKey resolve mkey $ \key ->
        runGmacSign env mech params key input
    | isHotpMech mech -> withKey resolve mkey $ \key ->
        runHotpSign env mech params key input
    | Just spec <- poly1305MacFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> macSign env spec key input
    | isPoly1305Mech mech -> pure (GotCryptoError (CryptoFailed
        "Poly1305 takes empty mechanism parameters"))
    | Just (alg, n) <- ssl3MacSpecFor mech params -> withKey resolve mkey $ \key ->
        runSsl3MacSign env alg n key input
    | isSsl3MacMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: SSL3 MAC takes a whole-byte bit length within the hash width"))
    | Just spec <- rsaPkcs1SpecFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaPkcs1Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA v1.5 takes empty mechanism parameters"))
    | Just spec <- rsaPssSpecFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaPssMech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-PSS takes pss-params/1 (hash, MGF1 hash, salt 0..64)"))
    | Just spec <- rsaX509SigFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaX509Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X.509 takes empty mechanism parameters"))
    | Just spec <- rsaX931SigFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaX931Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X9.31 takes empty mechanism parameters"))
    | isEcdsaMech mech -> withKey resolve mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure ecdsaRefusal
    | isDsaMech mech -> withKey resolve mkey $ \key ->
        case dsaSpecFor mech params of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure dsaRefusal
    | isEddsaMech mech -> withKey resolve mkey $ \key ->
        case eddsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure eddsaRefusal
    | isMldsaMech mech -> withKey resolve mkey $ \key ->
        case mldsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure mldsaRefusal
    | isSlhdsaMech mech -> withKey resolve mkey $ \key ->
        case slhdsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure slhdsaRefusal
    | otherwise -> pure (unsupported fx)
  FxVerify mech mkey params input sig
    | Just spec <- hmacSpecFor mech params -> withKey resolve mkey $ \key ->
        toVerifyBool <$> macVerify env spec key input sig
    | isHmacMech mech -> pure (GotCryptoError (CryptoMechParamInvalid "hmac"
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey resolve mkey $ \key ->
        runCmacVerify env mech params key input sig
    | isDes3MacMech mech -> withKey resolve mkey $ \key ->
        runDes3MacVerify env mech params key input sig
    | isCbcMacMech mech -> withKey resolve mkey $ \key ->
        runCbcMacVerify env mech params key input sig
    | isXcbcMech mech -> withKey resolve mkey $ \key ->
        runXcbcVerify env mech params key input sig
    | isGmacMech mech -> withKey resolve mkey $ \key ->
        runGmacVerify env mech params key input sig
    | isHotpMech mech -> withKey resolve mkey $ \key ->
        runHotpVerify env mech params key input sig
    | Just spec <- poly1305MacFor mech params -> withKey resolve mkey $ \key ->
        toVerifyBool <$> macVerify env spec key input sig
    | isPoly1305Mech mech -> pure (GotCryptoError (CryptoFailed
        "Poly1305 takes empty mechanism parameters"))
    | Just (alg, n) <- ssl3MacSpecFor mech params -> withKey resolve mkey $ \key ->
        runSsl3MacVerify env alg n key input sig
    | isSsl3MacMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: SSL3 MAC takes a whole-byte bit length within the hash width"))
    | Just spec <- rsaPkcs1SpecFor mech params -> withKey resolve mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaPkcs1Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA v1.5 takes empty mechanism parameters"))
    | Just spec <- rsaPssSpecFor mech params -> withKey resolve mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaPssMech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-PSS takes pss-params/1 (hash, MGF1 hash, salt 0..64)"))
    | Just spec <- rsaX509SigFor mech params -> withKey resolve mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaX509Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X.509 takes empty mechanism parameters"))
    | Just spec <- rsaX931SigFor mech params -> withKey resolve mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaX931Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X9.31 takes empty mechanism parameters"))
    | isEcdsaMech mech -> withKey resolve mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure ecdsaRefusal
    | isDsaMech mech -> withKey resolve mkey $ \key ->
        case dsaSpecFor mech params of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure dsaRefusal
    | isEddsaMech mech -> withKey resolve mkey $ \key ->
        case eddsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure eddsaRefusal
    | isMldsaMech mech -> withKey resolve mkey $ \key ->
        case mldsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure mldsaRefusal
    | isSlhdsaMech mech -> withKey resolve mkey $ \key ->
        case slhdsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure slhdsaRefusal
    | otherwise -> pure (unsupported fx)
  FxCipher dir mech mkey params input
    | isCipherMech mech -> withKey resolve mkey $ \key ->
        runCipher env dir mech key params input
    | isGcmMech mech -> withKey resolve mkey $ \key ->
        runAead env dir mech key params input
    | isCcmMech mech -> withKey resolve mkey $ \key ->
        runAead env dir mech key params input
    | isChachaPolyMech mech -> withKey resolve mkey $ \key ->
        runAead env dir mech key params input
    | isRsaOaepMech mech -> withKey resolve mkey $ \key ->
        runOaep env dir mech key params input
    | isRsaX509Mech mech -> withKey resolve mkey $ \key ->
        runX509 env dir mech key params input
    | otherwise -> pure (unsupported fx)
  FxMessageCipher dir mech mkey params aad input
    | isGcmMech mech -> withKey resolve mkey $ \key ->
        runAeadMessage env dir mech key params aad input
    | not (isCipherMech mech) && not (isRsaOaepMech mech) && not (isRsaX509Mech mech) ->
        pure (unsupported fx)
    | not (BS.null aad) -> pure (GotCryptoError (CryptoUnsupported "driver"
        "non-AEAD backend takes no AAD"))
    | isRsaOaepMech mech -> withKey resolve mkey $ \key ->
        runOaep env dir mech key params input
    | isRsaX509Mech mech -> withKey resolve mkey $ \key ->
        runX509 env dir mech key params input
    | otherwise -> withKey resolve mkey $ \key ->
        runCipher env dir mech key params input
  FxMessageSign mech mkey params input
    | Just spec <- hmacSpecFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> macSign env spec key input
    | isHmacMech mech -> pure (GotCryptoError (CryptoMechParamInvalid "hmac"
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey resolve mkey $ \key ->
        runCmacSign env mech params key input
    | isDes3MacMech mech -> withKey resolve mkey $ \key ->
        runDes3MacSign env mech params key input
    | isCbcMacMech mech -> withKey resolve mkey $ \key ->
        runCbcMacSign env mech params key input
    | isXcbcMech mech -> withKey resolve mkey $ \key ->
        runXcbcSign env mech params key input
    | isGmacMech mech -> withKey resolve mkey $ \key ->
        runGmacSign env mech params key input
    | Just spec <- poly1305MacFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> macSign env spec key input
    | isPoly1305Mech mech -> pure (GotCryptoError (CryptoFailed
        "Poly1305 takes empty mechanism parameters"))
    | Just spec <- rsaPkcs1SpecFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaPkcs1Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA v1.5 takes empty mechanism parameters"))
    | Just spec <- rsaPssSpecFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaPssMech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-PSS takes pss-params/1 (hash, MGF1 hash, salt 0..64)"))
    | Just spec <- rsaX509SigFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaX509Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X.509 takes empty mechanism parameters"))
    | Just spec <- rsaX931SigFor mech params -> withKey resolve mkey $ \key ->
        toBytes <$> sign env spec key input
    | isRsaX931Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X9.31 takes empty mechanism parameters"))
    | isEcdsaMech mech -> withKey resolve mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure ecdsaRefusal
    | isDsaMech mech -> withKey resolve mkey $ \key ->
        case dsaSpecFor mech params of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure dsaRefusal
    | isEddsaMech mech -> withKey resolve mkey $ \key ->
        case eddsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure eddsaRefusal
    | isMldsaMech mech -> withKey resolve mkey $ \key ->
        case mldsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure mldsaRefusal
    | isSlhdsaMech mech -> withKey resolve mkey $ \key ->
        case slhdsaSpecFor mech params key of
          Just spec -> toBytes <$> sign env spec key input
          Nothing -> pure slhdsaRefusal
    | otherwise -> pure (unsupported fx)
  FxMessageVerify mech mkey params input sig
    | Just spec <- hmacSpecFor mech params -> withKey resolve mkey $ \key ->
        toVerifyBool <$> macVerify env spec key input sig
    | isHmacMech mech -> pure (GotCryptoError (CryptoMechParamInvalid "hmac"
        "HMAC: plain takes empty params, GENERAL takes the 8-byte tag length"))
    | isCmacMech mech -> withKey resolve mkey $ \key ->
        runCmacVerify env mech params key input sig
    | isDes3MacMech mech -> withKey resolve mkey $ \key ->
        runDes3MacVerify env mech params key input sig
    | isCbcMacMech mech -> withKey resolve mkey $ \key ->
        runCbcMacVerify env mech params key input sig
    | isXcbcMech mech -> withKey resolve mkey $ \key ->
        runXcbcVerify env mech params key input sig
    | isGmacMech mech -> withKey resolve mkey $ \key ->
        runGmacVerify env mech params key input sig
    | Just spec <- poly1305MacFor mech params -> withKey resolve mkey $ \key ->
        toVerifyBool <$> macVerify env spec key input sig
    | isPoly1305Mech mech -> pure (GotCryptoError (CryptoFailed
        "Poly1305 takes empty mechanism parameters"))
    | Just spec <- rsaPkcs1SpecFor mech params -> withKey resolve mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaPkcs1Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA v1.5 takes empty mechanism parameters"))
    | Just spec <- rsaPssSpecFor mech params -> withKey resolve mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaPssMech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-PSS takes pss-params/1 (hash, MGF1 hash, salt 0..64)"))
    | Just spec <- rsaX509SigFor mech params -> withKey resolve mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaX509Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X.509 takes empty mechanism parameters"))
    | Just spec <- rsaX931SigFor mech params -> withKey resolve mkey $ \key ->
        toVerifyUnit <$> verify env spec key input sig
    | isRsaX931Mech mech -> pure (GotCryptoError (CryptoFailed
        "RSA-X9.31 takes empty mechanism parameters"))
    | isEcdsaMech mech -> withKey resolve mkey $ \key ->
        case ecdsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure ecdsaRefusal
    | isDsaMech mech -> withKey resolve mkey $ \key ->
        case dsaSpecFor mech params of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure dsaRefusal
    | isEddsaMech mech -> withKey resolve mkey $ \key ->
        case eddsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure eddsaRefusal
    | isMldsaMech mech -> withKey resolve mkey $ \key ->
        case mldsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure mldsaRefusal
    | isSlhdsaMech mech -> withKey resolve mkey $ \key ->
        case slhdsaSpecFor mech params key of
          Just spec -> toVerifyUnit <$> verify env spec key input sig
          Nothing -> pure slhdsaRefusal
    | otherwise -> pure (unsupported fx)
  -- Sign-recover over the raw private op: the crossed
  -- 'pkeyDecrypt' entry (raw RSA has no sign/verify backend
  -- entries; the private-half primitive is the decrypt one).
  -- X.509 left-pads the input to the tag width (decrypt takes
  -- full k-blocks on both backends); the raw PKCS row frames
  -- block-type-1 first (the tag width is the modulus width,
  -- fixed at init).
  FxSignRecover mech mkey params input tagLen
    | Just cparams <- rsaRecoverCipherFor mech params -> withKey resolve mkey $ \key ->
        if mech == MechanismId ckm_RSA_PKCS
          then case recoverType1Pad tagLen input of
            -- Defense in depth: the planner gate pre-refuses PKCS
            -- inputs over k - 11 (see 'signRecoverAllowance',
            -- pinned by the pkcs-boundary leg), so a
            -- length-driven 'Nothing' is unreachable via
            -- planning; the arm stays for unplanned callers.
            Nothing -> pure (GotCryptoError (CryptoFailed
              "driver: v1.5 recover data too long for the tag width"))
            Just padded -> toBytes <$> pkeyDecrypt env cparams key padded
          else case x509PadBlock tagLen input of
            Nothing -> pure (GotCryptoError (CryptoFailed
              "driver: X.509 recover data exceeds the tag width"))
            Just padded -> toBytes <$> pkeyDecrypt env cparams key padded
  FxSignRecover {} -> pure (unsupported fx)
  -- Verify-recover over the raw public op (the crossed
  -- 'pkeyEncrypt' entry). X.509 stages whatever the
  -- exponentiation yields; the raw PKCS row strips
  -- block-type-1, reporting a framing deviation as a mismatch
  -- verdict.
  FxVerifyRecover mech mkey params block _tagLen
    | Just cparams <- rsaRecoverCipherFor mech params -> withKey resolve mkey $ \key -> do
        out <- pkeyEncrypt env cparams key block
        pure $ case out of
          EngineOk raw
            | mech == MechanismId ckm_RSA_PKCS -> case recoverType1Strip raw of
                Just dat -> GotBytes dat
                Nothing -> GotValid False
            | otherwise -> GotBytes raw
          EngineFail err -> GotCryptoError (toCryptoError err)
  FxVerifyRecover {} -> pure (unsupported fx)
  FxGenerateKey mech params input
    | not (BS.null params)
    , mech /= tlsPremasterKeyGenMech
    , mech /= ssl3PremasterKeyGenMech
    , mech /= wtlsPremasterKeyGenMech
    , mech /= pbkd2KeyGenMech
    , mech /= pbeDes3KeyGenMech
    , mech /= pbeDes2KeyGenMech
    , mech /= pbeSha1Cast128KeyGenMech
    , mech /= pbeSha1Rc4_128KeyGenMech
    , mech /= pbeSha1Rc4_40KeyGenMech
    , mech /= pbeSha1Rc2_128KeyGenMech
    , mech /= pbeSha1Rc2_40KeyGenMech
    , mech /= pbeMd5DesKeyGenMech
    , mech /= pbeMd5CastKeyGenMech
    , mech /= pbeMd5Cast3KeyGenMech
    , mech /= pbeMd5Cast128KeyGenMech -> pure (GotCryptoError (CryptoFailed
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
                      r <- pbkdf2 env alg iters salt (KeyBytes pwd) n
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
          (m, GenPbe n)
            | Just r <- pbeRecipeFor m
            , m == pbeDes3KeyGenMech || m == pbeDes2KeyGenMech
              || m == pbeSha1Cast128KeyGenMech || m == pbeSha1Rc4_128KeyGenMech
              || m == pbeSha1Rc4_40KeyGenMech || m == pbeSha1Rc2_128KeyGenMech
              || m == pbeSha1Rc2_40KeyGenMech || m == pbeMd5DesKeyGenMech
              || m == pbeMd5CastKeyGenMech || m == pbeMd5Cast3KeyGenMech
              || m == pbeMd5Cast128KeyGenMech ->
                case decodePbeParams params of
                  Just (iters, pw, salt)
                    | iters >= 1 && iters <= fromIntegral maxPbeIters
                    , n == pbeKeyLen (pbeKind r) ->
                        case pbeKdf (pbeKind r) of
                          PbePkcs12Sha1 -> runPbe env iters pw salt n
                            (pbeNeedsParity (pbeKind r)) (pbeIvLen (pbeKind r))
                          PbePbkdf1Md5 -> runPbkdf1 env iters pw salt n
                            (pbeNeedsParity (pbeKind r))
                    | otherwise -> pure (GotCryptoError (CryptoFailed
                        "driver: PBE iterations or length out of range"))
                  Nothing -> pure (GotCryptoError (CryptoFailed
                    "driver: malformed PBE keygen params"))
          (m, GenEc curve) | m == ecKeyPairGenMech || m == ecExtraBitsKeyPairGenMech ->
            toKeyPair <$> generateKey env (GenEC (EcSpec (BC8.unpack curve) "DER"))
          (m, GenRsa bits e) | m == rsaKeyPairGenMech ->
            toKeyPair <$> generateKey env (GenRSA bits e)
          (m, GenDsaParams p q) | m == dsaParameterGenMech ->
            toKeyPair <$> generateKey env (GenDSAParams p q)
          -- X9.42 DH parameter generation runs the DSA entry
          -- point (the OpenSSL backend runs FIPS 186-2 at 1024/160,
          -- 186-4 above; provider DHX unwired, though it also
          -- yields Q); the (P, Q, G)
          -- triple publishes on the OpenSSL backend as X9.42 DH
          -- domain parameters through the shared DSS-Parms
          -- finisher (synthetic passes opaque bytes through
          -- unstamped).
          (m, GenDsaParams p q) | m == x9_42DhParameterGenMech ->
            toKeyPair <$> generateKey env (GenDSAParams p q)
          -- DH PKCS parameter generation runs the same DSA entry
          -- point (186-2 at 1024/160, 186-4 above on the OpenSSL
          -- backend; DHX unwired, as for X9.42); the pending attrs
          -- stamped by the planner publish it as a typed PKCS#3
          -- object on both backends, with p/q/g stamping reading
          -- OpenSSL's DER -- q plus its width are haskoki-specific
          -- readback (v3.2 section 6.4.9 specifies p, g, prime
          -- width).
          (m, GenDsaParams p q) | m == dhPkcsParameterGenMech ->
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
            | mech `elem` [aesKeyGenMech, des3KeyGenMech, hotpKeyGenMech, genericSecretKeyGenMech, chacha20KeyGenMech, ecKeyPairGenMech, ecExtraBitsKeyPairGenMech, rsaKeyPairGenMech, mlKemKeyPairGenMech, dsaKeyPairGenMech, dsaParameterGenMech, dhKeyPairGenMech, dhPkcsParameterGenMech, x9_42DhKeyPairGenMech, x9_42DhParameterGenMech, edwardsKeyPairGenMech, montgomeryKeyPairGenMech, mldsaKeyPairGenMech, slhdsaKeyPairGenMech, pbkd2KeyGenMech] ->
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
        Just alg -> withKey resolve mkey $ \key ->
          toKemPair <$> kemEncapsulate env (KemSpec (toPqcKem alg)) key
  FxKemDecaps mech mkey params input
    | mech /= mlKemMech -> pure (unsupported fx)
    | otherwise -> case kemAlgFromName params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: unknown KEM parameter name"))
        Just alg -> withKey resolve mkey $ \key ->
          toBytes <$> kemDecapsulate env (KemSpec (toPqcKem alg)) key input
  FxWrap _mech mkey params input
    | _mech == aesCbcMech -> withKey resolve mkey $ \key ->
        runCipher env DirEncrypt _mech key params input
    | isAesKwWrapMech _mech -> withKey resolve mkey $ \key ->
        runCipher env DirEncrypt _mech key params input
    | isRsaOaepMech _mech -> withKey resolve mkey $ \key ->
        runOaep env DirEncrypt _mech key params input
    | isRsaPkcsWrapMech _mech -> withKey resolve mkey $ \key ->
        runPkcs1 env DirEncrypt _mech key params input
    | isRsaX509Mech _mech -> withKey resolve mkey $ \key ->
        runX509 env DirEncrypt _mech key params input
    | Just r <- wrapCompEcdhRecipeFor _mech -> withKey resolve mkey $ \key ->
        runEcdhCompWrap env r key params input
    | Just r <- wrapCompRsaRecipeFor _mech -> withKey resolve mkey $ \key ->
        runRsaCompWrap env r key params input
    | otherwise -> pure (unsupported fx)
  FxUnwrap _mech mkey params input
    | _mech == aesCbcMech -> withKey resolve mkey $ \key ->
        runCipher env DirDecrypt _mech key params input
    | isAesKwWrapMech _mech -> withKey resolve mkey $ \key ->
        runCipher env DirDecrypt _mech key params input
    | isRsaOaepMech _mech -> withKey resolve mkey $ \key ->
        runOaep env DirDecrypt _mech key params input
    | isRsaPkcsWrapMech _mech -> withKey resolve mkey $ \key ->
        runPkcs1 env DirDecrypt _mech key params input
    | isRsaX509Mech _mech -> withKey resolve mkey $ \key ->
        runX509 env DirDecrypt _mech key params input
    | Just r <- wrapCompEcdhRecipeFor _mech -> withKey resolve mkey $ \key ->
        runEcdhCompUnwrap env r key params input
    | Just r <- wrapCompRsaRecipeFor _mech -> withKey resolve mkey $ \key ->
        runRsaCompUnwrap env r key params input
    | otherwise -> pure (unsupported fx)
  FxAuthWrap _mech mkey params input
    | _mech /= aesCbcMech -> pure (unsupported fx)
    | otherwise -> case decodeWrapParams params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: malformed auth-wrap params"))
        Just (iv, aad) -> withKey resolve mkey $ \key ->
          runAuthWrap env True _mech key iv aad input
  FxAuthUnwrap _mech mkey params input
    | _mech /= aesCbcMech -> pure (unsupported fx)
    | otherwise -> case decodeWrapParams params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: malformed auth-wrap params"))
        Just (iv, aad) -> withKey resolve mkey $ \key ->
          runAuthWrap env False _mech key iv aad input
  FxDerive mech mkey mkey2 params info outLen
    -- HKDF-DATA executes the same KDF as HKDF-DERIVE (the planner
    -- owns the output-class difference); the effect carries the
    -- HKDF frame either way.
    | mech == hkdfDeriveMech || mech == hkdfDataMech -> case hkdfParamsFor params of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: malformed HKDF prf/mode/salt params"))
        Just (alg, hashLen, mode, salt)
          | outLen < 1 || outLen > 255 * hashLen -> pure (GotCryptoError (CryptoFailed
              "driver: derive length out of range"))
          | otherwise -> withKey resolve mkey $ \key -> case key of
              KeyBytes ikm
                | mode == 0x02 -> toBytes <$> hkdfExpand env spec key info outLen
                | otherwise -> toBytes <$> hkdfExtractExpand env spec hashLen ikm salt info outLen
              _ -> pure (GotCryptoError (CryptoBadKey "driver"
                "HKDF base key is not byte material"))
          where spec = MacHMAC alg Nothing
    | isEcdhMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: ECDH derive takes no info string"))
    | Just (spec, peer) <- ecdhParamsFor mech params -> withKey resolve mkey $ \key ->
        runEcdh env spec key peer outLen
    | isEcdhMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: ECDH mechanism parameters rejected by the recipe"))
    | isDhMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: DH derive takes no info string"))
    | Just (spec, peer) <- dhParamsFor mech params -> withKey resolve mkey $ \key ->
        runDh env spec key peer outLen
    | isDhMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: DH mechanism parameters rejected by the recipe"))
    | mech == pubPrivMech
    , not (BS.null params) || not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: pub-from-priv takes empty params and info"))
    | mech == pubPrivMech -> withKey resolve mkey (runPubFromPriv env)
    | isKdfShaMech mech
    , not (BS.null params) || not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: SHA key derivation takes empty params and info"))
    | Just alg <- kdfShaFor mech -> withKey resolve mkey $ \key ->
        runShaKd env alg key outLen
    | isKdfXofMech mech
    , not (BS.null params) || not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: SHAKE key derivation takes empty params and info"))
    | Just alg <- kdfXofFor mech -> withKey resolve mkey $ \key ->
        runXofKd env alg key outLen
    | Just pp <- pbkd2ParamsFor mech params
    , BS.null info -> withKey resolve mkey $ \key ->
        runPbkd2 env pp key outLen
    | isPbkd2Mech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: PBKDF2 derive takes no info string"))
    | isPbkd2Mech mech -> pure (GotCryptoError (CryptoFailed
        "driver: PBKDF2 mechanism parameters rejected by the recipe"))
    | Just ex <- sp800ParamsFor mech params
    , BS.null info -> withKey resolve mkey $ \key ->
        runSp800 env ex key outLen
    | isSp800Mech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: SP800-108 derive takes no info string"))
    | isSp800Mech mech -> pure (GotCryptoError (CryptoFailed
        "driver: SP800-108 mechanism parameters rejected by the recipe"))
    | Just ex <- tlsKdfParamsFor mech params
    , BS.null info -> withKey resolve mkey $ \key ->
        runTlsKdf env ex key outLen
    | isTlsKdfMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: TLS-KDF derive takes no info string"))
    | isTlsKdfMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: TLS-KDF mechanism parameters rejected by the recipe"))
    | Just ex <- ikeParamsFor mech params
    , BS.null info -> withKey resolve mkey $ \key -> case (ikeNeedsAux ex, mkey2) of
        -- Unreachable post-plan (the planner resolves the aux
        -- handle); typed, never a crash.
        (True, Nothing) -> pure (GotCryptoError (CryptoBadKey "driver"
          "IKE derive binds no aux key"))
        (_, Nothing) -> runIke env ex key Nothing outLen
        (_, Just _) -> withKey resolve mkey2 $ \aux -> runIke env ex key (Just aux) outLen
    | isIkeMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: IKE derive takes no info string"))
    | isIkeMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: IKE mechanism parameters rejected by the recipe"))
    | Just ex <- byteOpsParamsFor mech params
    , BS.null info -> withKey resolve mkey $ \key -> case (byteOpsNeedsAux ex, mkey2) of
        -- Unreachable post-plan (the planner resolves the
        -- second handle); typed, never a crash.
        (True, Nothing) -> pure (GotCryptoError (CryptoBadKey "driver"
          "byte-op derive binds no aux key"))
        (_, Nothing) -> runByteOps ex key Nothing outLen
        (_, Just _) -> withKey resolve mkey2 $ \aux -> runByteOps ex key (Just aux) outLen
    | isByteOpsMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: byte-op derive takes no info string"))
    | isByteOpsMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: byte-op mechanism parameters rejected by the recipe"))
    | Just ex <- keyMatParamsFor mech params
    , BS.null info -> withKey resolve mkey $ \key ->
        runKeyMat env ex key outLen
    | isKeyMatMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: key-material derive takes no info string"))
    | isKeyMatMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: key-material mechanism parameters rejected by the recipe"))
    | Just ex <- ssl3ParamsFor mech params
    , BS.null info -> withKey resolve mkey $ \key ->
        runSsl3 env ex key outLen
    | isSsl3Mech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: SSL3 derive takes no info string"))
    | isSsl3Mech mech -> pure (GotCryptoError (CryptoFailed
        "driver: SSL3 mechanism parameters rejected by the recipe"))
    | Just prf <- tlsPrfParamsFor mech params
    , BS.null info -> withKey resolve mkey $ \key ->
        runTlsPrf env prf key outLen
    | isTlsPrfMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: TLS-PRF derive takes no info string"))
    | isTlsPrfMech mech -> pure (GotCryptoError (CryptoFailed
        "driver: TLS-PRF mechanism parameters rejected by the recipe"))
    | isEncryptDataMech mech
    , not (BS.null info) -> pure (GotCryptoError (CryptoFailed
        "driver: encrypt-data derive takes no info string"))
    | isEncryptDataMech mech -> withKey resolve mkey $ \key ->
        runEncryptData env mech key params outLen
    | otherwise -> pure (unsupported fx)

