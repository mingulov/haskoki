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
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Control.Monad (guard)
import Data.Bits ((.&.), (.|.), shiftL, shiftR, testBit)
import Data.Word (Word64, Word8)
import Data.Maybe (fromMaybe, isJust, isNothing)
import qualified Data.Text as T

import Haskoki.Engine.Backend
  ( BackendError (..)
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
  , PqcSigAlg (..)
  , RsaCipherParams (..)
  , SigSpec (..)
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
import Haskoki.Engine.Driver.CbcMac
  ( cbcmacSpecFor
  , isCbcMacMech
  , runCbcMacSign
  , runCbcMacVerify
  )
import Haskoki.Engine.Driver.Cipher
  ( cipherCtor
  , cipherSpecFor
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
  , compSpec
  , driverCtEq
  , keyBytesOf
  , levelOfName
  , rsaDigest
  , runPubFromPriv
  , unsupported
  , withKey
  , xorB
  )
import Haskoki.Engine.Driver.Des3Mac
  ( des3macSpecFor
  , isDes3MacMech
  , runDes3MacSign
  , runDes3MacVerify
  )
import Haskoki.Engine.Driver.Digest (digestAlgFor)
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
import Haskoki.Operation.Derive (hkdfDataMech, hkdfDeriveMech, maxDerivedTotal, maxXofTotal, pubPrivMech)
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoError (..), CryptoResult (..))
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
import Haskoki.Recipe.WrapComp
  ( WrapCompDomain (..)
  , WrapCompEcdhRecipe (..)
  , wrapCompAesBytes
  , wrapCompAgreePeer
  , wrapCompDomain
  , wrapCompEcdhRecipeFor
  , wrapCompPubPeer
  , wrapCompSplitBlob
  , wrapCompTransportLen
  , wrapCompTransportPrefix
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
import Haskoki.Recipe.ByteOps
  ( ByteOpsKind (..)
  , ByteOpsRecipe (..)
  , byteOpsParamsValid
  , byteOpsRecipeFor
  , decodeByteOpsParams
  )
import Haskoki.Recipe.TlsKeyMat
  ( TlsKeyMatKind (..)
  , TlsKeyMatRecipe (tkmKind)
  , decodeTlsKeyMatParams
  , maxTlsKeyMatBlock
  , tlsKeyMatLabel
  , tlsKeyMatParamsValid
  , tlsKeyMatRecipeFor
  )
import Haskoki.Recipe.Pbe (PbeKdf (..), PbeRecipe (pbeKind), decodePbeParams, maxPbeIters, pbeDesParity, pbeIvLen, pbeKdf, pbeKeyLen, pbeNeedsParity, pbeRecipeFor)
import Haskoki.Recipe.Ssl3
  ( Ssl3Kind (..)
  , Ssl3Recipe (ssl3Kind)
  , decodeSsl3KeyMatParams
  , decodeSsl3MasterParams
  , maxSsl3KeyBlock
  , ssl3ParamsValid
  , ssl3RecipeFor
  )
import Haskoki.Recipe.WrapCompRsa
  ( WrapCompRsaRecipe (..)
  , wrapCompRsaAesBytes
  , wrapCompRsaFrameHead
  , wrapCompRsaModulusBytes
  , wrapCompRsaOaep
  , wrapCompRsaRecipeFor
  , wrapCompRsaSplitBlob
  , wrapCompRsaUnframeHead
  )
import Haskoki.Recipe.RsaX509 (x509PadBlock)
import Haskoki.Operation.Kem (kemAlgFromName, mlKemKeyPairGenMech, mlKemMech)
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
  , aesKwp7Mech
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
  , rsaPkcsMech
  , encodeKeyPair
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
import Haskoki.Recipe.Hmac (decodeMacGeneral)
import Haskoki.Recipe.Kdf
  ( KdfRecipe (..)
  , decodePbkd2Params
  , kdfCodeDigest
  , kdfParamsValid
  , kdfRecipeFor
  , kdfXofStem
  )
import Haskoki.Recipe.EncryptData
  ( EncryptDataRecipe (..)
  , decodeEncryptDataParams
  , encryptDataKeyLenValid
  , encryptDataParamsValid
  , encryptDataRecipeFor
  )
import Haskoki.Recipe.Sp800108
  ( Sp800Mode (..)
  , Sp800Params (..)
  , Sp800Recipe (..)
  , decodeSp800Params
  , maxSp800Total
  , sp800ParamsValid
  , sp800RecipeFor
  )
import Haskoki.Recipe.Ike
  ( IkeKind (..)
  , IkeRecipe (..)
  , decodeIkeParams
  , ikeParamsValid
  , ikeRecipeFor
  , maxIkeOutput
  )
import Haskoki.Recipe.TlsKdf
  ( TlsKdfKind (..)
  , TlsKdfRecipe (..)
  , decodeTlsKdfParams
  , maxTlsKdfOutput
  , tlsKdfParamsValid
  , tlsKdfRecipeFor
  )
import Haskoki.Recipe.TlsPrf
  ( decodeTlsPrfParams
  , maxTlsPrfOutput
  , tlsPrfParamsValid
  , tlsPrfRecipeFor
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated
  ( ckm_RSA_PKCS
  )

-- | SSL3-MAC dispatch: covered (mechanism, params) pairs to the
-- digest plus the whole-byte tag length (pinned against
-- 'Haskoki.Recipe.Ssl3' by RecipeSsl3Spec). 'Nothing' means
-- uncovered (non-SSL3-MAC mechanism) or malformed parameters.
ssl3MacSpecFor :: MechanismId -> ByteString -> Maybe (DigestAlg, Int)
ssl3MacSpecFor mech params = do
  r <- ssl3RecipeFor mech
  alg <- case ssl3Kind r of
    Ssl3Md5Mac -> Just D_MD5
    Ssl3Sha1Mac -> Just D_SHA1
    _ -> Nothing
  guard (ssl3ParamsValid r params)
  n <- decodeMacGeneral params
  pure (alg, n `div` 8)

-- | An SSL3-MAC mechanism regardless of parameter validity
-- (drives the parameter-refusal branch).
isSsl3MacMech :: MechanismId -> Bool
isSsl3MacMech mech = case ssl3RecipeFor mech of
  Just r -> case ssl3Kind r of
    Ssl3Md5Mac -> True
    Ssl3Sha1Mac -> True
    _ -> False
  Nothing -> False

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

-- | SHAKE-KD dispatch: covered XOF mechanisms to the backend
-- digest algorithm (pinned against 'kdfXofStem' by
-- RecipeKdfSpec). The output length rides the 'FxDerive' total.
kdfXofFor :: MechanismId -> Maybe DigestAlg
kdfXofFor mech = do
  r <- kdfRecipeFor mech
  stem <- kdfXofStem r
  case stem of
    "SHAKE_128" -> Just D_SHAKE128
    "SHAKE_256" -> Just D_SHAKE256
    _ -> Nothing

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

-- | Encrypt-data dispatch: the covered (mechanism, base-key
-- length, canonical frame) triple to its backend cipher spec plus
-- the split IV and data (empty IV for ECB rows). The row name
-- strips to its cipher row (@CKM_AES_CBC_ENCRYPT_DATA@ onto
-- @CKM_AES_CBC@), so width selection and the Triple-DES collapse
-- reuse 'cipherCtor' (pinned by RecipeEncryptDataSpec).
encryptDataPartsFor :: MechanismId -> Int -> ByteString -> Maybe (CipherSpec, ByteString, ByteString)
encryptDataPartsFor mech keyLen params = do
  r <- encryptDataRecipeFor mech
  guard (encryptDataParamsValid r params)
  guard (encryptDataKeyLenValid r keyLen)
  base <- T.stripSuffix "_ENCRYPT_DATA" (erName r)
  spec <- cipherCtor base keyLen
  (iv, dat) <- decodeEncryptDataParams r params
  pure (spec, iv, dat)

-- | An encrypt-data mechanism regardless of triple validity
-- (drives the derive parameter-refusal branch: rejected triples
-- are 'CryptoFailed', never 'CryptoUnsupported').
isEncryptDataMech :: MechanismId -> Bool
isEncryptDataMech mech = isJust (encryptDataRecipeFor mech)

-- | A fixed-width SHA key-derivation mechanism (drives the
-- parameter-refusal branch; XOF rows answer through
-- 'isKdfXofMech' instead).
isKdfShaMech :: MechanismId -> Bool
isKdfShaMech mech = case kdfRecipeFor mech of
  Just r -> not (rkPbkd2 r) && isNothing (kdfXofStem r)
  Nothing -> False

-- | A SHAKE XOF key-derivation mechanism (drives the
-- parameter-refusal branch).
isKdfXofMech :: MechanismId -> Bool
isKdfXofMech mech = case kdfRecipeFor mech of
  Just r -> isJust (kdfXofStem r)
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

-- | SP 800-108 execution tuple: the mode, the HMAC digest plus
-- its width, the counter and length widths, the IV, and the
-- flattened fixed input.
data Sp800Exec = Sp800Exec
  { seMode :: !Sp800Mode
  , seAlg :: !DigestAlg
  , seHashLen :: !Int
  , seCounterBits :: !Int
  , seLengthBits :: !Int
  , seIv :: !ByteString
  , seFixed :: !ByteString
  } deriving (Eq, Show)

-- | SP 800-108 dispatch: the covered (mechanism, params) pair to
-- its execution tuple (pinned by RecipeSp800108Spec).
-- 'Nothing' means uncovered (non-SP-800-108 mechanism) or
-- malformed parameters.
sp800ParamsFor :: MechanismId -> ByteString -> Maybe Sp800Exec
sp800ParamsFor mech params = do
  r <- sp800RecipeFor mech
  guard (sp800ParamsValid r params)
  p <- decodeSp800Params params
  stem <- kdfCodeDigest (fromIntegral (spPrf p))
  alg <- rsaDigest stem
  hashLen <- digestOutLen alg
  pure (Sp800Exec (rsMode r) alg hashLen
    (spCounterBits p) (spLengthBits p) (spIv p) (spFixed p))

-- | An SP 800-108 mechanism (drives the parameter-refusal
-- branches).
isSp800Mech :: MechanismId -> Bool
isSp800Mech mech = case sp800RecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | TLS-KDF execution tuple: the row kind, the legacy flag
-- (the TLS 1.0 construction when set, @P_hash@ over the
-- digest otherwise), the label, the seed, and the RFC 5705
-- context (free rows only).
data TlsKdfExec = TlsKdfExec
  { teKind :: !TlsKdfKind
  , teLegacy :: !Bool
  , teAlg :: !(Maybe DigestAlg)
  , teLabel :: !ByteString
  , teSeed :: !ByteString
  , teContext :: !ByteString
  } deriving (Eq, Show)

-- | TLS-KDF dispatch: the covered (mechanism, params) pair to
-- its execution tuple (pinned by RecipeTlsKdfSpec).
-- 'Nothing' means uncovered (non-TLS-KDF mechanism) or
-- malformed parameters.
tlsKdfParamsFor :: MechanismId -> ByteString -> Maybe TlsKdfExec
tlsKdfParamsFor mech params = do
  r <- tlsKdfRecipeFor mech
  guard (tlsKdfParamsValid r params)
  (prf, lab, seed, ctx) <- decodeTlsKdfParams params
  if prf == 0
    then pure (TlsKdfExec (tkKind r) True Nothing lab seed ctx)
    else do
      stem <- kdfCodeDigest (fromIntegral prf)
      alg <- rsaDigest stem
      pure (TlsKdfExec (tkKind r) False (Just alg) lab seed ctx)

-- | A TLS-KDF mechanism (drives the parameter-refusal
-- branches).
isTlsKdfMech :: MechanismId -> Bool
isTlsKdfMech mech = case tlsKdfRecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | One IKE execution: the kind, the PRF digest, and the
-- frame inputs (the aux keygxy material resolves separately
-- through 'fxKey2'; the runner interprets flags, key number,
-- and blobs per kind).
data IkeExec = IkeExec
  { ieKind :: !IkeKind
  , ieAlg :: !DigestAlg
  , ieFlags :: !Word8
  , ieKeyNum :: !Word8
  , ieBlob1 :: !ByteString
  , ieBlob2 :: !ByteString
  } deriving (Eq, Show)

-- | IKE dispatch: the covered (mechanism, params) pair to
-- its execution tuple (pinned by RecipeIkeSpec).
-- 'Nothing' means uncovered (non-IKE mechanism), malformed
-- parameters, or the reserved unmapped-PRF code (the planner
-- denies that one; the driver never sees it).
ikeParamsFor :: MechanismId -> ByteString -> Maybe IkeExec
ikeParamsFor mech params = do
  r <- ikeRecipeFor mech
  guard (ikeParamsValid r params)
  (prf, flags, keynum, _aux, b1, b2) <- decodeIkeParams params
  guard (prf /= 0)
  stem <- kdfCodeDigest (fromIntegral prf)
  alg <- rsaDigest stem
  pure (IkeExec (ikKind r) alg flags keynum b1 b2)

-- | An IKE mechanism (drives the parameter-refusal
-- branches).
isIkeMech :: MechanismId -> Bool
isIkeMech mech = case ikeRecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | The IKE rows needing an aux key: IKEv1-PRF takes the
-- keygxy input (the planner resolves it onto 'fxKey2'); the
-- extended row takes it optionally, the others never.
ikeNeedsAux :: IkeExec -> Bool
ikeNeedsAux ex = ieKind ex == Ike1Prf

-- | A byte-op mechanism (drives the parameter-refusal
-- branches).
isByteOpsMech :: MechanismId -> Bool
isByteOpsMech mech = case byteOpsRecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | The byte-op rows needing an aux key: only
-- BASE_AND_KEY takes the second input (the planner
-- resolves it onto 'fxKey2').
byteOpsNeedsAux :: ByteOpsExec -> Bool
byteOpsNeedsAux ex = boeKind ex == ConcatBaseAndKey

-- | One decoded byte-op execution: the row kind, the second
-- handle (BASE_AND_KEY), the bit offset (EXTRACT), and the
-- string data (the three data rows).
data ByteOpsExec = ByteOpsExec
  { boeKind :: !ByteOpsKind
  , boeAux :: !Word64
  , boeOff :: !Word64
  , boeData :: !ByteString
  } deriving (Eq, Show)

-- | Byte-op dispatch: the covered (mechanism, params) pair to
-- its execution tuple (pinned by RecipeByteOpsSpec).
byteOpsParamsFor :: MechanismId -> ByteString -> Maybe ByteOpsExec
byteOpsParamsFor mech params = do
  r <- byteOpsRecipeFor mech
  guard (byteOpsParamsValid r params)
  (aux, off, blob) <- decodeByteOpsParams params
  pure (ByteOpsExec (boKind r) aux off blob)

-- | One decoded key-material execution: the row kind, the PRF
-- code, the MAC\/key\/IV byte sizes, and the two randoms.
data KeyMatExec = KeyMatExec
  { kmeKind :: !TlsKeyMatKind
  , kmePrf :: !Word8
  , kmeMac :: !Int
  , kmeKey :: !Int
  , kmeIv :: !Int
  , kmeCr :: !ByteString
  , kmeSr :: !ByteString
  } deriving (Eq, Show)

-- | Key-material dispatch: the covered (mechanism, params)
-- pair to its execution tuple (pinned by
-- RecipeTlsKeyMatSpec).
keyMatParamsFor :: MechanismId -> ByteString -> Maybe KeyMatExec
keyMatParamsFor mech params = do
  r <- tlsKeyMatRecipeFor mech
  guard (tlsKeyMatParamsValid r params)
  (prf, mac, key, iv, cr, sr) <- decodeTlsKeyMatParams params
  pure (KeyMatExec (tkmKind r) prf mac key iv cr sr)

-- | A key-material mechanism (drives the parameter-refusal
-- branches).
isKeyMatMech :: MechanismId -> Bool
isKeyMatMech mech = case tlsKeyMatRecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | One decoded SSL3-derive execution: master rows carry the
-- two randoms; the keymat row carries the MAC\/key\/IV byte
-- sizes plus the two randoms.
data Ssl3Exec
  = Ssl3MasterExec !ByteString !ByteString
  | Ssl3KeyMatExec !Int !Int !Int !ByteString !ByteString
  deriving (Eq, Show)

-- | SSL3-derive dispatch: the covered (mechanism, params)
-- pair to its execution tuple (pinned by RecipeSsl3Spec).
-- MAC rows never resolve here (they execute on the sign
-- path).
ssl3ParamsFor :: MechanismId -> ByteString -> Maybe Ssl3Exec
ssl3ParamsFor mech params = do
  r <- ssl3RecipeFor mech
  guard (ssl3ParamsValid r params)
  case ssl3Kind r of
    Ssl3Master -> uncurry Ssl3MasterExec <$> decodeSsl3MasterParams params
    Ssl3MasterDh -> uncurry Ssl3MasterExec <$> decodeSsl3MasterParams params
    Ssl3KeyMat -> do
      (mac, key, iv, cr, sr) <- decodeSsl3KeyMatParams params
      pure (Ssl3KeyMatExec mac key iv cr sr)
    _ -> Nothing

-- | An SSL3-derive mechanism regardless of parameter
-- validity (drives the parameter-refusal branch).
isSsl3Mech :: MechanismId -> Bool
isSsl3Mech mech = case ssl3RecipeFor mech of
  Just r -> case ssl3Kind r of
    Ssl3Master -> True
    Ssl3MasterDh -> True
    Ssl3KeyMat -> True
    _ -> False
  Nothing -> False

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

-- | The raw RSA v1.5 row: the only v1.5 mechanism that wraps
-- (the digest rows are signature-only).
isRsaPkcsWrapMech :: MechanismId -> Bool
isRsaPkcsWrapMech mech = mech == rsaPkcsMech

-- | The AES key-wrap rows (KW plus the two KWP names, plus
-- KW-PKCS7 whose planner pads first): the planner frames the
-- payload (raw, or PKCS#7-padded for PKCS7) and 'runCipher'
-- executes the wrap backend spec selected by 'cipherCtor'.
isAesKwWrapMech :: MechanismId -> Bool
isAesKwWrapMech mech =
  mech == aesKwMech || mech == aesKwPadMech || mech == aesKwpMech || mech == aesKwp7Mech

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
-- refuses a key). 'Nothing' means uncovered (non-EdDSA mechanism)
-- or non-pure parameters (missing parameters decode to pure).
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

-- ---------------------------------------------------------------------------
-- runEffect workers (lifted to top level, 0.6.3 prep)
-- ---------------------------------------------------------------------------
-- These were the @where@-block of 'runEffect'. Each worker takes
-- explicitly what it closed over ('BackendEnv' via 'CryptoBackend',
-- or 'KeyResolver' for 'withKey'); bodies are unchanged apart from
-- re-indentation and @env@ threading between workers. The next step
-- splits them per family.

-- | ECDH agreement effects: the backend agrees the full raw
-- secret over (base key, peer public key) and the driver
-- truncates to the planned length. A planned length past the
-- secret is 'CryptoFailed' (the planner caps honestly, so this
-- fires only for hand-built effects); backend key-shape
-- refusals keep their taxonomy.
runEcdh :: CryptoBackend b => BackendEnv b -> EcdhSpec -> KeyMaterial -> ByteString -> Int -> IO CryptoResult
runEcdh env spec key peer outLen
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
runDh :: CryptoBackend b => BackendEnv b -> DhSpec -> KeyMaterial -> ByteString -> Int -> IO CryptoResult
runDh env spec key peer outLen
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
-- | ECDH-composition wrap: ephemeral transport keygen on
-- the wrapping (recipient PUBLIC) key's domain, ECDH
-- agreement of the transport private half against the
-- wrapping public half, the FIRST agreement bytes as the AES
-- KEK (NOT the derive truncation, which drops leading bytes),
-- KWP seal of the target, blob = transport-pub || kwp-blob.
-- Served primitives only (generateKey, ecdhDerive, the KWP
-- cipher entry); the ephemeral key never persists. Opaque
-- doubles transport on a fixed P-256 request (synthetic pairs
-- are curve-independent opaque halves, so the row's curve
-- family is immaterial there); real keys always scan.
runEcdhCompWrap :: CryptoBackend b => BackendEnv b -> WrapCompEcdhRecipe -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runEcdhCompWrap env r wrapKey params target = case keyBytesOf wrapKey of
  Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
    "composition wrapping key has no bytes"))
  Just wrapB -> case wrapCompAesBytes params of
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: malformed wrap-composition parameters"))
    Just aesBytes ->
      let dom = wrapCompDomain wrapB
      in case wrapCompPubPeer dom wrapB of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: wrapping public peer rejected"))
        Just recipPub -> do
          g <- generateKey env (transportGen dom)
          case g of
            EngineFail err -> pure (GotCryptoError (toCryptoError err))
            EngineOk (KeyDer tpriv, Just (KeyDer tpub)) ->
              case ( wrapCompTransportPrefix r dom tpub
                   , wrapCompTransportLen r dom ) of
                (Just prefix, Just preLen)
                  | BS.length prefix == preLen -> do
                      s <- ecdhDerive env (compSpec r) (KeyDer tpriv) (KeyDer recipPub)
                      case s of
                        EngineFail err -> pure (GotCryptoError (toCryptoError err))
                        EngineOk secret
                          | BS.length secret < aesBytes -> pure (GotCryptoError (CryptoFailed
                              "driver: agreement secret shorter than the KEK"))
                          | otherwise -> do
                              sealed <- runCipher env DirEncrypt aesKwpMech
                                (KeyBytes (BS.take aesBytes secret)) BS.empty target
                              case sealed of
                                GotBytes ct -> pure (GotBytes (prefix <> ct))
                                other -> pure other
                _ -> pure (GotCryptoError (CryptoFailed
                  "driver: transport framing failed"))
            _ -> pure (GotCryptoError (CryptoFailed
              "driver: transport keygen shape rejected"))
  where
    transportGen DomainOpaque = GenEC (EcSpec "P-256" "DER")
    transportGen (DomainWeierstrass name _) =
      GenEC (EcSpec (T.unpack name) "DER")
    transportGen (DomainMontgomery name _) =
      GenXDHKeypair (BC8.pack (T.unpack name))
-- | ECDH-composition unwrap: split the transport prefix,
-- re-derive the KEK against it, KWP-open the tail. KWP-open
-- failures propagate as authentication faults (fail closed,
-- never wrong plaintext).
runEcdhCompUnwrap :: CryptoBackend b => BackendEnv b -> WrapCompEcdhRecipe -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runEcdhCompUnwrap env r unwrapKey params blob = case keyBytesOf unwrapKey of
  Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
    "composition unwrapping key has no bytes"))
  Just wrapB -> case wrapCompAesBytes params of
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: malformed wrap-composition parameters"))
    Just aesBytes ->
      let dom = wrapCompDomain wrapB
      in case wrapCompSplitBlob r dom blob of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: composition blob framing rejected"))
        Just (prefix, kwpBlob) ->
          case wrapCompAgreePeer r dom prefix of
            Nothing -> pure (GotCryptoError (CryptoFailed
              "driver: composition transport peer rejected"))
            Just peer -> do
              s <- ecdhDerive env (compSpec r) unwrapKey (KeyDer peer)
              case s of
                EngineFail err -> pure (GotCryptoError (toCryptoError err))
                EngineOk secret
                  | BS.length secret < aesBytes -> pure (GotCryptoError (CryptoFailed
                      "driver: agreement secret shorter than the KEK"))
                  | otherwise ->
                      runCipher env DirDecrypt aesKwpMech
                        (KeyBytes (BS.take aesBytes secret)) BS.empty kwpBlob
-- | RSA-composition wrap: mint a random temp KEK at the
-- requested strength, OAEP-seal it under the recipient
-- PUBLIC key, KWP-seal the target under the KEK, answer the
-- modulus-wide OAEP head plus the KWP tail. Served
-- primitives only (generateKey, pkeyEncrypt, the KWP cipher
-- entry); the KEK never persists. Tag-sized synthetic seals
-- frame modulus-wide through the recipe (exact-k real seals
-- pass through).
runRsaCompWrap :: CryptoBackend b => BackendEnv b -> WrapCompRsaRecipe -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runRsaCompWrap env _ wrapKey params target = case keyBytesOf wrapKey of
  Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
    "composition wrapping key has no bytes"))
  Just wrapB ->
    case (wrapCompRsaModulusBytes wrapB, wrapCompRsaAesBytes params, wrapCompRsaOaep params) of
      (Just k, Just aesBytes, Just (d, m, label)) -> case (rsaDigest d, rsaDigest m) of
        (Just dh, Just mh) -> do
          g <- generateKey env (GenSym "AES" aesBytes)
          case g of
            EngineOk (KeyBytes kek, _)
              | BS.length kek == aesBytes -> do
                  s <- pkeyEncrypt env (RsaOaep (OaepParams dh mh label)) wrapKey kek
                  case s of
                    EngineFail err -> pure (GotCryptoError (toCryptoError err))
                    EngineOk raw -> case wrapCompRsaFrameHead k (aesBytes + 16) raw of
                      Nothing -> pure (GotCryptoError (CryptoFailed
                        "driver: OAEP head escapes the modulus width"))
                      Just framed -> do
                        sealed <- runCipher env DirEncrypt aesKwpMech
                          (KeyBytes kek) BS.empty target
                        case sealed of
                          GotBytes ct -> pure (GotBytes (framed <> ct))
                          other -> pure other
            EngineOk _ -> pure (GotCryptoError (CryptoFailed
              "driver: temp KEK keygen shape rejected"))
            EngineFail err -> pure (GotCryptoError (toCryptoError err))
        _ -> pure (GotCryptoError (CryptoFailed
          "driver: OAEP digest stems rejected"))
      _ -> pure (GotCryptoError (CryptoFailed
        "driver: malformed wrap-composition parameters"))
-- | RSA-composition unwrap: split the modulus-wide head,
-- OAEP-open the KEK with the PRIVATE key (length-tripwired),
-- KWP-open the tail. Open failures propagate as
-- authentication faults (fail closed, never wrong
-- plaintext).
runRsaCompUnwrap :: CryptoBackend b => BackendEnv b -> WrapCompRsaRecipe -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runRsaCompUnwrap env _ unwrapKey params blob = case keyBytesOf unwrapKey of
  Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
    "composition unwrapping key has no bytes"))
  Just wrapB ->
    case (wrapCompRsaModulusBytes wrapB, wrapCompRsaAesBytes params, wrapCompRsaOaep params) of
      (Just k, Just aesBytes, Just (d, m, label)) ->
        case wrapCompRsaSplitBlob k blob of
          Nothing -> pure (GotCryptoError (CryptoFailed
            "driver: composition blob framing rejected"))
          Just (framed, kwpBlob) -> case (rsaDigest d, rsaDigest m) of
            (Just dh, Just mh) -> do
              let inner = wrapCompRsaUnframeHead k (aesBytes + 16) framed
              o <- pkeyDecrypt env (RsaOaep (OaepParams dh mh label)) unwrapKey inner
              case o of
                EngineFail err -> pure (GotCryptoError (toCryptoError err))
                EngineOk kek
                  | BS.length kek == aesBytes ->
                      runCipher env DirDecrypt aesKwpMech
                        (KeyBytes kek) BS.empty kwpBlob
                  | otherwise -> pure (GotCryptoError (CryptoFailed
                      "driver: opened KEK escapes the requested strength"))
            _ -> pure (GotCryptoError (CryptoFailed
              "driver: OAEP digest stems rejected"))
      _ -> pure (GotCryptoError (CryptoFailed
        "driver: malformed wrap-composition parameters"))
-- | SHA key-derivation effects: digest the base value,
-- truncate to the planned length (capped by the digest width —
-- the planner caps honestly, so over-width fires only for
-- hand-built effects).
runShaKd :: CryptoBackend b => BackendEnv b -> DigestAlg -> KeyMaterial -> Int -> IO CryptoResult
runShaKd env alg key outLen = case key of
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
-- | SHAKE XOF key-derivation effects: XOF output at the planned
-- length (capped by 'maxXofTotal' — the planner caps honestly,
-- so over-ceiling fires only for hand-built effects).
runXofKd :: CryptoBackend b => BackendEnv b -> DigestAlg -> KeyMaterial -> Int -> IO CryptoResult
runXofKd env alg key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxXofTotal -> do
        r <- digestXof env alg kb outLen
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk d -> GotBytes d
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: XOF derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))
-- | Encrypt-data derive: single-shot cipher encryption of the
-- framed data under the base key, truncated to the planned
-- length (the planner caps at the data width; an out-of-range
-- request fails closed here too). Off-geometry triples are
-- 'CryptoFailed'; a non-bytes key is 'CryptoBadKey'.
runEncryptData :: CryptoBackend b => BackendEnv b -> MechanismId -> KeyMaterial -> ByteString -> Int -> IO CryptoResult
runEncryptData env mech key params outLen = case key of
  KeyBytes kb -> case encryptDataPartsFor mech (BS.length kb) params of
    Just (spec, iv, dat)
      | outLen >= 1 && outLen <= BS.length dat -> do
          r <- cipherEncrypt env spec key iv dat
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk d -> GotBytes (BS.take outLen d)
      | otherwise -> pure (GotCryptoError (CryptoFailed
          "driver: derive length out of range"))
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: encrypt-data (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "encrypt-data base key is not byte material"))
-- | PBKDF2 effects: the RFC 8018 iteration over the HMAC PRF,
-- truncated to the planned length (capped by the shared
-- ceiling).
runPbkd2 :: CryptoBackend b => BackendEnv b -> Pbkd2Params -> KeyMaterial -> Int -> IO CryptoResult
runPbkd2 env (Pbkd2Params prf iters salt) key outLen = case key of
  KeyBytes _
    | outLen >= 1 && outLen <= maxDerivedTotal -> do
        r <- pbkdf2 env prf iters salt key outLen
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk dk -> GotBytes (BS.take outLen dk)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))
-- | PBKDF2 proper: T_i = F(password, salt, iters, i) with the
-- HMAC PRF, concatenated across ceil(outLen\/hLen) blocks.
pbkdf2 :: CryptoBackend b => BackendEnv b -> DigestAlg -> Int -> ByteString -> KeyMaterial -> Int -> IO (EngineResult ByteString)
pbkdf2 env prf iters salt pwd outLen = case digestOutLen prf of
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
-- | PBE keygen effects: the §6.38 PKCS#12 construction over
-- SHA-1 (u = 20, v = 64): ID 1 derives the key
-- (parity-adjusted for the DES rows only), ID 2 the IV.
-- Digests run through the provider; the B-feedback
-- addition is pure byte arithmetic. IV rows answer the
-- framed key\/IV pair; no-IV rows (RC4) answer the lone
-- key.
runPbe :: CryptoBackend b => BackendEnv b -> Word64 -> ByteString -> ByteString -> Int -> Bool -> Int -> IO CryptoResult
runPbe env iters pw salt keyLen parity ivLen = do
  rK <- pbeDChain 1 keyLen
  if ivLen > 0
    then do
      rV <- pbeDChain 2 ivLen
      pure $ case (rK, rV) of
        (EngineOk k, EngineOk v) ->
          GotBytes (encodeKeyPair (finish k) (Just v))
        (EngineFail err, _) -> GotCryptoError (toCryptoError err)
        (_, EngineFail err) -> GotCryptoError (toCryptoError err)
    else pure $ case rK of
      EngineOk k -> toKeyPair (EngineOk (KeyBytes (finish k), Nothing))
      EngineFail err -> GotCryptoError (toCryptoError err)
  where
    finish = if parity then pbeDesParity else id
    pbeDChain :: Word8 -> Int -> IO (EngineResult ByteString)
    pbeDChain ident n = loop n (expand salt <> expand pw) []
      where
        d = BS.replicate 64 ident
        expand s
          | BS.null s = BS.empty
          | otherwise =
              let target = 64 * ((BS.length s + 63) `div` 64)
                  copies = target `div` BS.length s + 1
              in BS.take target (BS.concat (replicate copies s))
        loop remaining i acc
          | remaining <= 0 =
              pure (EngineOk (BS.take n (BS.concat (reverse acc))))
          | otherwise = do
              r <- hashTimes (fromIntegral iters) (d <> i)
              case r of
                EngineFail err -> pure (EngineFail err)
                EngineOk a -> loop (remaining - 20) (feedback a i) (a : acc)
        feedback a i = BS.concat (map (addBlock bInt) (chunks i))
          where
            b = BS.take 64 (BS.concat (replicate 4 a))
            bInt = beInt b
            chunks x
              | BS.null x = []
              | otherwise = let (h, t) = BS.splitAt 64 x in h : chunks t
            addBlock bi blk =
              beBytes 64 ((beInt blk + bi + 1) `mod` (2 ^ (512 :: Int)))
        hashTimes :: Int -> ByteString -> IO (EngineResult ByteString)
        hashTimes 0 msg = pure (EngineOk msg)
        hashTimes k msg = do
          r <- digestOneShot env D_SHA1 msg
          case r of
            EngineFail err -> pure (EngineFail err)
            EngineOk dig -> hashTimes (k - 1) dig
        beInt :: ByteString -> Integer
        beInt = BS.foldl' (\a w -> a * 256 + fromIntegral w) 0
        beBytes :: Int -> Integer -> ByteString
        beBytes len v =
          BS.pack [fromIntegral ((v `div` (256 ^ i)) `mod` 256)
                  | i <- [len - 1, len - 2 .. 0]]
-- | MD5 D-chain: @D1 = MD5^c(P||S)@ (the provider-PBKDF1
-- root, byte-exact), @D{i+1} = MD5^c(Di||P||S)@ past the
-- 16-byte PBKDF1 cap; key = stream[0:keyLen], IV =
-- stream[keyLen:keyLen+8]. Digests run through the
-- provider. The answer frames the key\/IV pair.
runPbkdf1 :: CryptoBackend b => BackendEnv b -> Word64 -> ByteString -> ByteString -> Int -> Bool -> IO CryptoResult
runPbkdf1 env iters pw salt keyLen parity = do
  r <- chain (keyLen + 8) BS.empty []
  pure $ case r of
    EngineFail err -> GotCryptoError (toCryptoError err)
    EngineOk stream ->
      let (k, v) = BS.splitAt keyLen (BS.take (keyLen + 8) stream)
      in GotBytes (encodeKeyPair (finish k) (Just v))
  where
    finish = if parity then pbeDesParity else id
    chain :: Int -> ByteString -> [ByteString] -> IO (EngineResult ByteString)
    chain remaining prev acc
      | remaining <= 0 = pure (EngineOk (BS.concat (reverse acc)))
      | otherwise = do
          r <- hashTimes (fromIntegral iters) (prev <> pw <> salt)
          case r of
            EngineFail err -> pure (EngineFail err)
            EngineOk d -> chain (remaining - 16) d (d : acc)
    hashTimes :: Int -> ByteString -> IO (EngineResult ByteString)
    hashTimes 0 msg = pure (EngineOk msg)
    hashTimes k msg = do
      r <- digestOneShot env D_MD5 msg
      case r of
        EngineFail err -> pure (EngineFail err)
        EngineOk d -> hashTimes (k - 1) d
-- | SP 800-108 effects: the mode expansion over the HMAC
-- route, truncated to the planned length (capped by
-- 'maxSp800Total' with the L-fit check — the planner caps
-- honestly, so off-range fires only for hand-built
-- effects). A non-bytes key is 'CryptoBadKey'.
runSp800 :: CryptoBackend b => BackendEnv b -> Sp800Exec -> KeyMaterial -> Int -> IO CryptoResult
runSp800 env ex key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxSp800Total
    , toInteger outLen * 8 < 2 ^ seLengthBits ex
    , seMode ex /= Sp800Counter
      || toInteger ((outLen + seHashLen ex - 1) `div` seHashLen ex)
         <= 2 ^ seCounterBits ex - 1 -> do
        r <- sp800Expand env ex kb outLen
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk d -> GotBytes (BS.take outLen d)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: SP800-108 length out of range or widths do not fit"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))
-- | SP 800-108 expansion (NIST SP 800-108 §5.1\/5.2\/5.3)
-- over the HMAC route: counter @K(i) = PRF(KI, [i]_r ||
-- fixed || [L]_l)@, feedback @K(i) = PRF(KI, K(i-1) ||
-- fixed || [L]_l)@ with @K(0) = IV@, double-pipeline @A(i)
-- = PRF(KI, A(i-1))@, @K(i) = PRF(KI, A(i) || fixed ||
-- [L]_l)@ with @A(0) = fixed || [L]_l@. L is the derived
-- bit-length by construction; counter mode refuses past
-- @2^r - 1@ iterations (never wraps).
sp800Expand :: CryptoBackend b => BackendEnv b -> Sp800Exec -> ByteString -> Int -> IO (EngineResult ByteString)
sp800Expand env ex kb outLen
  | seMode ex == Sp800Counter
  , toInteger n > 2 ^ seCounterBits ex - 1 = pure (EngineFail (BackendBadParam "sp800Expand"
      "iteration count exceeds the counter width"))
  | otherwise = case seMode ex of
      Sp800Counter -> goCounter 1 []
      Sp800Feedback -> goFeedback n (seIv ex) []
      Sp800DoublePipeline -> goPipeline n suffix []
  where
    spec = MacHMAC (seAlg ex) Nothing
    key = KeyBytes kb
    h = seHashLen ex
    n = (outLen + h - 1) `div` h
    suffix = seFixed ex <> encodeW (seLengthBits ex `div` 8) (outLen * 8)
    rBytes = seCounterBits ex `div` 8
    encodeW w v = BS.pack [fromIntegral ((v `div` 256 ^ i) `mod` 256) | i <- [w - 1, w - 2 .. 0]]
    goCounter i acc
      | i > n = pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
      | otherwise = do
          t <- macSign env spec key (encodeW rBytes i <> suffix)
          case t of
            EngineFail err -> pure (EngineFail err)
            EngineOk blk -> goCounter (i + 1) (blk : acc)
    goFeedback 0 _ acc = pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
    goFeedback k prev acc = do
      t <- macSign env spec key (prev <> suffix)
      case t of
        EngineFail err -> pure (EngineFail err)
        EngineOk blk -> goFeedback (k - 1) blk (blk : acc)
    goPipeline 0 _ acc = pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
    goPipeline k aPrev acc = do
      aNext <- macSign env spec key aPrev
      case aNext of
        EngineFail err -> pure (EngineFail err)
        EngineOk a -> do
          p <- macSign env spec key (a <> suffix)
          case p of
            EngineFail err -> pure (EngineFail err)
            EngineOk blk -> goPipeline (k - 1) a (blk : acc)
-- | TLS-PRF effects: the RFC 2246 expansion over the backend
-- HMAC-MD5\/SHA-1 routes. Off-range lengths are 'CryptoFailed';
-- a non-bytes key is 'CryptoBadKey'.
runTlsPrf :: CryptoBackend b => BackendEnv b -> TlsPrfParams -> KeyMaterial -> Int -> IO CryptoResult
runTlsPrf env (TlsPrfParams lab seed) key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxTlsPrfOutput -> do
        r <- tlsPrfExpand env kb (lab <> seed) outLen
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk ok -> GotBytes (BS.take outLen ok)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))
-- | TLS-KDF effects: the legacy RFC 2246 expansion or
-- @P_hash@ over the selected digest, with the RFC 5705
-- context suffix (2-byte big-endian length plus context)
-- when present. Off-range lengths are 'CryptoFailed'; a
-- non-bytes key is 'CryptoBadKey'.
runTlsKdf :: CryptoBackend b => BackendEnv b -> TlsKdfExec -> KeyMaterial -> Int -> IO CryptoResult
runTlsKdf env ex key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxTlsKdfOutput -> do
        let seedFull = teLabel ex <> teSeed ex <> ctxSuffix (teContext ex)
        r <- case (teLegacy ex, teAlg ex) of
          (True, _) -> tlsPrfExpand env kb seedFull outLen
          (False, Just alg) -> pHash env alg (KeyBytes kb) seedFull outLen
          (False, Nothing) -> pure (EngineFail (BackendBadParam "runTlsKdf"
            "TLS-KDF hash PRF without a digest"))
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk ok -> GotBytes (BS.take outLen ok)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))
-- | Key-material effects: the TLS PRF ("key expansion"
-- over server ++ client randoms, RFC 2246 §6.3) expanded to
-- the planned block length — legacy for TLS 1.0, P_hash
-- over the selected digest for TLS 1.2. The planner sizes
-- the block (KEY_SAFE excludes IVs); the finisher splits it
-- into keys + IVs. Off-range lengths are 'CryptoFailed'; a
-- non-bytes key is 'CryptoBadKey'.
runKeyMat :: CryptoBackend b => BackendEnv b -> KeyMatExec -> KeyMaterial -> Int -> IO CryptoResult
runKeyMat env ex key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxTlsKeyMatBlock -> do
        let seedFull = tlsKeyMatLabel <> kmeSr ex <> kmeCr ex
        r <- if kmePrf ex == 0
          then tlsPrfExpand env kb seedFull outLen
          else case kdfCodeDigest (fromIntegral (kmePrf ex)) >>= rsaDigest of
            Just alg -> pHash env alg (KeyBytes kb) seedFull outLen
            Nothing -> pure (EngineFail (BackendBadParam "runKeyMat"
              "key-material hash PRF without a digest"))
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk ok -> GotBytes (BS.take outLen ok)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))
-- | SSL3 derive effects: the RFC 6101 constructions over
-- provider MD5\/SHA-1. Master rows emit the fixed 48-byte
-- §6.1 secret; the keymat row emits the §6.2.2 block
-- (pad bytes @A@..@0xFF@: past round 191 the
-- construction is undefined, so over-bound blocks fail
-- typed even when called past the planner).
runSsl3 :: CryptoBackend b => BackendEnv b -> Ssl3Exec -> KeyMaterial -> Int -> IO CryptoResult
runSsl3 env ex key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxSsl3KeyBlock -> case ex of
        Ssl3MasterExec cr sr -> do
          r <- ssl3Master env kb cr sr
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk ok -> GotBytes (BS.take outLen ok)
        Ssl3KeyMatExec mac k iv cr sr ->
          let total = 2 * mac + 2 * k + 2 * iv
          in if total < 1 || total > maxSsl3KeyBlock
            then pure (GotCryptoError (CryptoFailed
              "driver: SSL3 key block past the 191-round construction bound"))
            else do
              r <- ssl3Block env kb cr sr total
              pure $ case r of
                EngineFail err -> GotCryptoError (toCryptoError err)
                EngineOk ok -> GotBytes (BS.take outLen ok)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))
-- | RFC 6101 §6.1: @MD5(secret + SHA1(pad + secret + CR
-- + SR))@ over pads @A@, @BB@, @CCC@.
ssl3Master :: CryptoBackend b => BackendEnv b -> ByteString -> ByteString -> ByteString -> IO (EngineResult ByteString)
ssl3Master env secret cr sr = go pads []
  where
    pads = [BS.singleton 65, BS.pack [66, 66], BS.pack [67, 67, 67]]
    go [] acc = pure (EngineOk (BS.concat (reverse acc)))
    go (pad : rest) acc = do
      rSha <- digestOneShot env D_SHA1 (pad <> secret <> cr <> sr)
      case rSha of
        EngineFail err -> pure (EngineFail err)
        EngineOk sha -> do
          rMd5 <- digestOneShot env D_MD5 (secret <> sha)
          case rMd5 of
            EngineFail err -> pure (EngineFail err)
            EngineOk d -> go rest (d : acc)
-- | RFC 6101 §6.2.2: @MD5(secret + SHA1(pad + secret + SR
-- + CR))@ iterated, pad @i@ is byte @(0x41 + i - 1)@
-- repeated @i@ times (note server random first).
ssl3Block :: CryptoBackend b => BackendEnv b -> ByteString -> ByteString -> ByteString -> Int -> IO (EngineResult ByteString)
ssl3Block env secret cr sr total = go 1 []
  where
    go i acc
      | length acc * 16 >= total = pure (EngineOk (BS.take total (BS.concat (reverse acc))))
      | i > 191 = pure (EngineFail (BackendBadParam "ssl3Block"
          "SSL3 key block past the 191-round construction bound"))
      | otherwise = do
          let pad = BS.replicate i (65 + fromIntegral i - 1)
          rSha <- digestOneShot env D_SHA1 (pad <> secret <> sr <> cr)
          case rSha of
            EngineFail err -> pure (EngineFail err)
            EngineOk sha -> do
              rMd5 <- digestOneShot env D_MD5 (secret <> sha)
              case rMd5 of
                EngineFail err -> pure (EngineFail err)
                EngineOk d -> go (i + 1) (d : acc)
-- | SSL3 MAC sign effects: @H(secret + pad2 + H(secret +
-- pad1 + data))@ truncated to the requested whole-byte
-- length (pads 48 bytes MD5, 40 bytes SHA-1).
runSsl3MacSign :: CryptoBackend b => BackendEnv b -> DigestAlg -> Int -> KeyMaterial -> ByteString -> IO CryptoResult
runSsl3MacSign env alg n key input = case key of
  KeyBytes kb -> do
    r <- ssl3Mac env alg kb input
    pure $ case r of
      EngineFail err -> GotCryptoError (toCryptoError err)
      EngineOk full -> GotBytes (BS.take n full)
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "SSL3 MAC needs raw symmetric key bytes"))
-- | SSL3 MAC verify effects: recompute, truncate,
-- constant-time compare. A mismatch is the 'False'
-- verdict, never a malfunction.
runSsl3MacVerify :: CryptoBackend b => BackendEnv b -> DigestAlg -> Int -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runSsl3MacVerify env alg n key input tag = case key of
  KeyBytes kb -> do
    r <- ssl3Mac env alg kb input
    pure $ case r of
      EngineFail err -> GotCryptoError (toCryptoError err)
      EngineOk full
        | driverCtEq (BS.take n full) tag -> GotValid True
        | otherwise -> GotValid False
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "SSL3 MAC needs raw symmetric key bytes"))
-- | The RFC 6101 MAC core over the resolved digest.
ssl3Mac :: CryptoBackend b => BackendEnv b -> DigestAlg -> ByteString -> ByteString -> IO (EngineResult ByteString)
ssl3Mac env alg secret input = case alg of
  D_MD5 -> macWith 48
  D_SHA1 -> macWith 40
  _ -> pure (EngineFail (BackendBadParam "ssl3Mac"
    "SSL3 MAC needs MD5 or SHA-1"))
  where
    macWith padLen = do
      let pad1 = BS.replicate padLen 0x36
          pad2 = BS.replicate padLen 0x5c
      rInner <- digestOneShot env alg (secret <> pad1 <> input)
      case rInner of
        EngineFail err -> pure (EngineFail err)
        EngineOk inner -> digestOneShot env alg (secret <> pad2 <> inner)
-- | RFC 5705 context suffix: empty without context, else the
-- 2-byte big-endian length plus the context.
ctxSuffix :: ByteString -> ByteString
ctxSuffix ctx
  | BS.null ctx = BS.empty
  | otherwise = BS.pack [fromIntegral (n `div` 256), fromIntegral (n `mod` 256)] <> ctx
  where n = BS.length ctx
-- | TLS 1.0\/1.1 PRF: P_MD5 over the first secret half XOR
-- P_SHA-1 over the second (RFC 2246 §5; the halves share the
-- middle byte on odd lengths).
tlsPrfExpand :: CryptoBackend b => BackendEnv b -> ByteString -> ByteString -> Int -> IO (EngineResult ByteString)
tlsPrfExpand env secret seedBytes outLen = do
  m <- pHash env D_MD5 (KeyBytes s1) seedBytes outLen
  case m of
    EngineFail err -> pure (EngineFail err)
    EngineOk mOut -> do
      s <- pHash env D_SHA1 (KeyBytes s2) seedBytes outLen
      pure $ case s of
        EngineFail err -> EngineFail err
        EngineOk sOut -> EngineOk (BS.take outLen mOut `xorB` BS.take outLen sOut)
  where
    (s1, s2) = splitTlsSecret secret
-- | P_hash: A(0) = seed, A(i) = HMAC(secret, A(i-1)),
-- P(i) = HMAC(secret, A(i) ++ seed), concatenated.
pHash :: CryptoBackend b => BackendEnv b -> DigestAlg -> KeyMaterial -> ByteString -> Int -> IO (EngineResult ByteString)
pHash env alg secret seedBytes outLen = case digestOutLen alg of
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
-- | IKE effects over the HMAC route: prf+ iteration,
-- the single-shot PRF in either role order, the IKEv1
-- single shot over the aux keygxy input, and the
-- counter-less extended iteration (truncating the base
-- when neither aux nor extra is present — the oracle
-- reference rule). Off-range lengths are 'CryptoFailed';
-- non-bytes keys are 'CryptoBadKey'.
runIke :: CryptoBackend b => BackendEnv b -> IkeExec -> KeyMaterial -> Maybe KeyMaterial -> Int -> IO CryptoResult
runIke env ex key mAux outLen = case key of
  KeyBytes kb -> case auxOf mAux of
    Left err -> pure (GotCryptoError err)
    Right auxB -> case ieKind ex of
      Ike2PrfPlus
        | outLen >= 1
        , Just h <- digestOutLen (ieAlg ex)
        , (outLen + h - 1) `div` h <= 255 -> do
            r <- ikePrfPlusExpand env (ieAlg ex) kb (ieBlob1 ex) outLen
            pure $ case r of
              EngineFail err -> GotCryptoError (toCryptoError err)
              EngineOk d -> GotBytes (BS.take outLen d)
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: IKE prf+ length out of range"))
      IkePrf
        | outLen >= 1, Just h <- digestOutLen (ieAlg ex), outLen <= h -> do
            let (kk, msg) = if ieFlags ex == 1
                  then (ieBlob1 ex <> ieBlob2 ex, kb)
                  else (kb, ieBlob1 ex <> ieBlob2 ex)
            r <- macSign env (MacHMAC (ieAlg ex) Nothing) (KeyBytes kk) msg
            pure $ case r of
              EngineFail err -> GotCryptoError (toCryptoError err)
              EngineOk d -> GotBytes (BS.take outLen d)
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: IKE PRF length out of range"))
      Ike1Prf -> case auxB of
        -- Unreachable post-dispatch (IKEv1-PRF needs aux);
        -- typed, never a crash.
        Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
          "IKEv1-PRF derive binds no keygxy key"))
        Just gx
          | outLen >= 1, Just h <- digestOutLen (ieAlg ex), outLen <= h -> do
              let msg = gx <> ieBlob1 ex <> ieBlob2 ex <> BS.singleton (ieKeyNum ex)
              r <- macSign env (MacHMAC (ieAlg ex) Nothing) (KeyBytes kb) msg
              pure $ case r of
                EngineFail err -> GotCryptoError (toCryptoError err)
                EngineOk d -> GotBytes (BS.take outLen d)
          | otherwise -> pure (GotCryptoError (CryptoFailed
              "driver: IKEv1-PRF length out of range"))
      Ike1Extended
        | outLen >= 1 && outLen <= maxIkeOutput
        , extTruncOk auxB (ieBlob1 ex) (BS.length kb) outLen -> do
            r <- ikeExtExpand env (ieAlg ex) kb auxB (ieBlob1 ex) outLen
            pure $ case r of
              EngineFail err -> GotCryptoError (toCryptoError err)
              EngineOk d -> GotBytes (BS.take outLen d)
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: IKE extended length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))
  where
    auxOf Nothing
      | ikeNeedsAux ex = Left (CryptoBadKey "driver" "IKE derive binds no aux key")
      | otherwise = Right Nothing
    auxOf (Just (KeyBytes ab)) = Right (Just ab)
    auxOf (Just _) = Left (CryptoBadKey "driver" "IKE aux key is not byte material")
    -- | The truncation rule admits the request: without aux
    -- input the output must fit the base.
    extTruncOk Nothing extra kbLen wantLen = not (BS.null extra) || wantLen <= kbLen
    extTruncOk (Just _) _ _ _ = True
-- | Byte-op derives: pure byte manipulation over secret
-- material (no backend crypto — identical on both
-- backends). Concat rows join base and second input and
-- truncate to the planned length; XOR folds the first
-- planned-length bytes of both inputs (at most the shorter
-- one; the planner refuses a longer length first); EXTRACT
-- slices whole bytes at the bit offset, bit-exact
-- (MSB-first) for sub-byte offsets. Off-range lengths are 'CryptoFailed';
-- non-bytes keys are 'CryptoBadKey'.
runByteOps :: ByteOpsExec -> KeyMaterial -> Maybe KeyMaterial -> Int -> IO CryptoResult
runByteOps ex key mAux outLen = case key of
  KeyBytes kb -> case auxOf mAux of
    Left err -> pure (GotCryptoError err)
    Right auxB -> case boeKind ex of
      ConcatBaseAndKey -> case auxB of
        -- Unreachable post-dispatch (concat-key needs
        -- aux); typed, never a crash.
        Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
          "concat-key derive binds no second key"))
        Just sb
          | outLen >= 1, outLen <= BS.length kb + BS.length sb ->
              pure (GotBytes (BS.take outLen (kb <> sb)))
          | otherwise -> pure (GotCryptoError (CryptoFailed
              "driver: concat-key length out of range"))
      ConcatBaseAndData
        | outLen >= 1, outLen <= BS.length kb + BS.length dat ->
            pure (GotBytes (BS.take outLen (kb <> dat)))
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: concat-data length out of range"))
      ConcatDataAndBase
        | outLen >= 1, outLen <= BS.length dat + BS.length kb ->
            pure (GotBytes (BS.take outLen (dat <> kb)))
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: data-concat length out of range"))
      XorBaseAndData
        | outLen >= 1
        , outLen <= min (BS.length kb) (BS.length dat) ->
            pure (GotBytes (BS.take outLen (kb `xorB` dat)))
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: XOR length out of range"))
      ExtractKeyFromKey
        | outLen >= 1
        , toInteger off + toInteger outLen * 8 <= toInteger (BS.length kb) * 8 ->
            pure (GotBytes (extractBits kb (fromIntegral off) outLen))
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: EXTRACT window out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))
  where
    dat = boeData ex
    off = boeOff ex
    auxOf Nothing
      | byteOpsNeedsAux ex = Left (CryptoBadKey "driver" "byte-op derive binds no aux key")
      | otherwise = Right Nothing
    auxOf (Just (KeyBytes ab)) = Right (Just ab)
    auxOf (Just _) = Left (CryptoBadKey "driver" "byte-op aux key is not byte material")
-- | Bit-exact slice (MSB-first): @n@ whole bytes starting
-- at bit @off@ of the input (the caller keeps the window
-- in range).
extractBits :: ByteString -> Int -> Int -> ByteString
extractBits bs off n = BS.pack [byteAt i | i <- [0 .. n - 1]]
  where
    byteAt i = foldl setBit 0 [0 .. 7]
      where
        setBit acc j
          | bitAt (off + i * 8 + j) = acc .|. (1 `shiftL` (7 - j))
          | otherwise = acc
    bitAt p = testBit (BS.index bs (p `div` 8)) (7 - (p `mod` 8))
-- | IKEv2 prf+ (RFC 4306 §2.8): @T(i) = PRF(K, T(i-1) |
-- seed | i)@ with @T(0)@ empty, the counter a single byte
-- (never wraps: past 255 blocks refuses).
ikePrfPlusExpand :: CryptoBackend b => BackendEnv b -> DigestAlg -> ByteString -> ByteString -> Int -> IO (EngineResult ByteString)
ikePrfPlusExpand env alg kb seed outLen = case digestOutLen alg of
  Nothing -> pure (EngineFail (BackendBadParam "ikePrfPlusExpand"
    "IKE prf+ needs a fixed-width HMAC"))
  Just h
    | outLen < 1 -> pure (EngineFail (BackendBadParam "ikePrfPlusExpand"
        "IKE prf+ length out of range"))
    | n > 255 -> pure (EngineFail (BackendBadParam "ikePrfPlusExpand"
        "IKE prf+ length exceeds the counter capacity"))
    | otherwise -> go 1 BS.empty []
    where
      n = (outLen + h - 1) `div` h
      spec = MacHMAC alg Nothing
      key = KeyBytes kb
      go i prev acc
        | i > n = pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
        | otherwise = do
            t <- macSign env spec key (prev <> seed <> BS.singleton (fromIntegral i))
            case t of
              EngineFail err -> pure (EngineFail err)
              EngineOk blk -> go (i + 1) blk (blk : acc)
-- | IKEv1 extended expansion: @T(i) = PRF(K, T(i-1) |
-- keygxy | extra)@ with the first message the bare seed
-- (@\\x00@ when both inputs are empty); with neither
-- input and a short output, the base truncates (the
-- oracle reference rule).
ikeExtExpand :: CryptoBackend b => BackendEnv b -> DigestAlg -> ByteString -> Maybe ByteString -> ByteString -> Int -> IO (EngineResult ByteString)
ikeExtExpand env alg kb mGx extra outLen
  | outLen < 1 = pure (EngineFail (BackendBadParam "ikeExtExpand"
      "IKE extended length out of range"))
  | otherwise = case (mGx, BS.null extra) of
      (Nothing, True)
        | outLen <= BS.length kb -> pure (EngineOk (BS.take outLen kb))
        | otherwise -> pure (EngineFail (BackendBadParam "ikeExtExpand"
            "IKE extended truncation exceeds the base length"))
      _ -> case digestOutLen alg of
        Nothing -> pure (EngineFail (BackendBadParam "ikeExtExpand"
          "IKE extended needs a fixed-width HMAC"))
        Just h ->
          let seed = maybe BS.empty id mGx <> extra
              first = if BS.null seed then BS.singleton 0 else seed
              n = (outLen + h - 1) `div` h
              spec = MacHMAC alg Nothing
              key = KeyBytes kb
              go 0 _ acc = pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
              go k prev acc = do
                let msg = if k == n then first else prev <> seed
                t <- macSign env spec key msg
                case t of
                  EngineFail err -> pure (EngineFail err)
                  EngineOk blk -> go (k - 1) blk (blk : acc)
          in go n first []
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
eddsaRefusal = GotCryptoError (CryptoFailed "EdDSA: params must be pure (phFlag clear, empty context) or empty")

-- | ML-DSA dispatch refusal: 'mldsaSpecFor' only fails on
-- refused parameters, so the refusal is unconditionally a
-- 'CryptoFailed' parameter refusal.
mldsaRefusal :: CryptoResult
mldsaRefusal = GotCryptoError (CryptoFailed "ML-DSA: params must be mldsa-params/1 (hedge 0..2, context 0..255 bytes) or empty")
slhdsaRefusal :: CryptoResult
slhdsaRefusal = GotCryptoError (CryptoFailed "SLH-DSA: params must be slhdsa-params/1 (hedge 0..2, context 0..255 bytes) or empty")

-- | Four-byte big-endian word (PBKDF2 block index).
word32BE :: Int -> ByteString
word32BE n = BS.pack
  [ fromIntegral ((n `shiftR` 24) .&. 0xff)
  , fromIntegral ((n `shiftR` 16) .&. 0xff)
  , fromIntegral ((n `shiftR` 8) .&. 0xff)
  , fromIntegral (n .&. 0xff)
  ]

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

