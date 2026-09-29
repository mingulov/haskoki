{- | Key-management planning: generation, wrap\/unwrap, derivation
and KEM finishers over one shared pending-object publication (pure).

Every planner here returns a 'KeyPlan': a denial, an immediate
'PlanResult' (length queries and short buffers, which create no
objects), or exactly one 'CryptoEffect' plus the 'PendingWork' its
answer completes. 'finishWork' runs the driver's answer against the
pending work and publishes through 'publishPending' — the ONE
atomic-publish mechanism every key, pair, unwrap, derive and
encapsulation funnels through. All templates validate before any id
or handle is allocated, and 'Haskoki.Transition.publishDelta' applies
the resulting delta atomically, so a failed call leaves zero objects.

Key material arrives in driver answers and is stored on the new
objects' 'AttrValue' ('storeMaterial'); 'keyBytesOf' reads it back
for the driver resolver. The seal ('payloadSealed') governs the
attribute READ path only: sealed keys stay usable for crypto, per
PKCS#11.

Template defaults follow PKCS#11: a missing class is incomplete, a
missing key type defaults to the mechanism's key, usage flags and
the extractable mark default to false (absent means false, and the
planners enforce strictly).

Class, key-type and mechanism ids resolve through the
generated tables ('Haskoki.Attribute.Generated',
'Haskoki.Registry.Generated') by name; no numeric ids are hand-typed
here. Strict template paths additionally enforce the generated
template rules ('Haskoki.Object.checkRules').
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.KeyManagement
  ( -- * Plan currency
    KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , publishPending
  , finishWork
  , stampPairComponents
  , stampParamsObject
  , keyPairCompatible
    -- * Object reading
  , keyBytesOf
  , policyFromObject
  , keyTypeCompatible
  , mechAllowed
    -- * Class and key-type codes (spec\/vendor\/pkcs11.h)
  , ckoData
  , ckoSecretKey
  , ckoPublicKey
  , ckoPrivateKey
  , ckoDomainParameters
  , ckkRsa
  , ckkEc
  , ckkDsa
  , ckkDh
  , ckkX9_42Dh
  , ckkEcEdwards
  , ckkEcMontgomery
  , ckkGenericSecret
  , ckkAes
  , ckkAesXts
  , ckkDes3
  , ckkHotp
  , ckkBlake2b512Hmac
  , ckkChacha20
  , ckkMlKem
  , ckkMlDsa
  , ckkSlhDsa
  , ckkDes
  , ckkDes2
  , ckkCdmf
  , ckkCast
  , ckkCast3
  , ckkCast128
  , ckkRc2
  , ckkRc4
  , ckkRc5
  , ckkIdea
  , ckkSkipjack
  , ckkBaton
  , ckkJuniper
  , ckkBlowfish
  , ckkTwofish
  , ckkGost28147
  , ckkSeed
  , ckkAria
  , ckkCamellia
  , ckkSalsa20
  , ckkPoly1305
  , ckkHkdf
  , ckkSha1Hmac
  , ckkSha224Hmac
  , ckkSha256Hmac
  , ckkSha384Hmac
  , ckkSha512Hmac
  , ckkSha512_224Hmac
  , ckkSha512_256Hmac
  , ckkSha512THmac
  , ckkSha3_224Hmac
  , ckkSha3_256Hmac
  , ckkSha3_384Hmac
  , ckkSha3_512Hmac
  , ckkBlake2b160Hmac
  , ckkBlake2b256Hmac
  , ckkBlake2b384Hmac
    -- * Mechanism ids (spec\/vendor\/pkcs11.h)
  , aesKeyGenMech
  , des3KeyGenMech
  , hotpKeyGenMech
  , blake2b512KeyGenMech
  , chacha20KeyGenMech
  , genericSecretKeyGenMech
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
  , pbeDes3KeyGenMech
  , pbeDes2KeyGenMech
  , pbkd2KeygenMaxBytes
  , genericSecretKeygenMinBytes
  , genericSecretKeygenMaxBytes
  , ecKeyPairGenMech
  , ecExtraBitsKeyPairGenMech
  , rsaKeyPairGenMech
  , dsaKeyPairGenMech
  , dsaParameterGenMech
  , dhKeyPairGenMech
  , dhPkcsParameterGenMech
  , x9_42DhKeyPairGenMech
  , x9_42DhParameterGenMech
  , edwardsKeyPairGenMech
  , montgomeryKeyPairGenMech
  , mldsaKeyPairGenMech
  , slhdsaKeyPairGenMech
  , aesCbcMech
  , aesKwMech
  , aesKwPadMech
  , aesKwpMech
  , rsaPkcsMech
  , rsaOaepMech
  , rsaX509Mech
    -- * Shared template checks
  , checkKeyTemplate
  , checkKeyTemplateAny
  , checkDataTemplate
  , pendingFromAttrs
    -- * Generation frames (planner \<-\> driver contract)
  , GenArgs (..)
  , encodeGenArgs
  , decodeGenArgs
  , encodeKeyPair
  , decodeKeyPair
  , encodeWrapParams
  , decodeWrapParams
    -- * Wrap padding (mirrors Haskoki.Operation.Cipher)
  , padPkcs7
  , unpadPkcs7
    -- * Planners
  , planGenerateKeyPair
  , planGenerateKey
  , planWrapKey
  , planUnwrapKey
  , planAuthWrapKey
  , planAuthUnwrapKey
    -- * Writability admission
  , admitPending
  ) where

import Control.Monad (guard)
import Data.Bits ((.|.), countLeadingZeros, shiftL)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Data.Word (Word64, Word8)

import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , attributeTypeByName
  , encodeValue
  )
import Haskoki.Attribute.Generated
  ( classNameById
  , keyTypeNameById
  , mustClassId
  , mustKeyTypeId
  )
import Haskoki.Der (RsaCrt (..), curveTable, derOctet, dhParamsDer, dhParamsDerQ, dhPkcs8Fields, dhSpkiFields, dsaParamsDer, dsaPkcs8Fields, dsaSpkiFields, eddsaPkcs8Fields, eddsaSpkiFields, edwardsNameOfOid, edwardsTable, mldsaPkcs8Fields, mldsaSpkiFields, mlkemPkcs8Fields, mlkemSpkiFields, montgomeryNameOfOid, montgomeryPkcs8Fields, montgomerySpkiFields, montgomeryTable, parseDsaParams, parseRsaPrivate, parseRsaPublic, slhdsaPkcs8Fields, slhdsaSpkiFields, spkiPoint)
import Haskoki.Model (Model (..), ObjectState (..), SessionState (..))
import Haskoki.Object
  ( RuleDeny (..)
  , TemplateError (..)
  , TemplateRule (..)
  , checkRules
  , findRule
  , objectVisible
  , resolveHandle
  , validateTemplate
  )
import Haskoki.Operation.Effect
  ( CryptoEffect (..)
  , CryptoResult (..)
  , TypedError (..)
  , interpretError
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Recipe.Kdf (decodePbkd2Params, maxPbkd2Iters)
import Haskoki.Recipe.Pbe (PbeKind (..), PbeRecipe (pbeKind), decodePbeParams, pbeIvLen, pbeKeyLen, pbeParamsValid, pbeRecipeFor)
import Haskoki.Recipe.Otp (hotpKeygenMaxBytes, hotpKeygenMinBytes)
import Haskoki.Recipe.RsaOaep
  ( decodeOaepParams
  , oaepDigestWidth
  , rsaOaepParamsValid
  , rsaOaepRecipeFor
  )
import Haskoki.Recipe.RsaPkcs1 (rsaPkcs1ParamsValid, rsaPkcs1RecipeFor)
import Haskoki.Recipe.RsaX509 (rsaX509ParamsValid, rsaX509RecipeFor, x509Tail)
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Registry.KeyMatrix (matrixKeyTypes)
import Haskoki.Registry.Generated
  ( ckm_AES_CBC
  , ckm_AES_KEY_GEN
  , ckm_AES_KEY_WRAP
  , ckm_AES_KEY_WRAP_KWP
  , ckm_AES_KEY_WRAP_PAD
  , ckm_BLAKE2B_512_KEY_GEN
  , ckm_CHACHA20_KEY_GEN
  , ckm_DES3_KEY_GEN
  , ckm_DSA_KEY_PAIR_GEN
  , ckm_DSA_PARAMETER_GEN
  , ckm_DH_PKCS_KEY_PAIR_GEN
  , ckm_DH_PKCS_PARAMETER_GEN
  , ckm_X9_42_DH_KEY_PAIR_GEN
  , ckm_X9_42_DH_PARAMETER_GEN
  , ckm_EC_EDWARDS_KEY_PAIR_GEN
  , ckm_EC_MONTGOMERY_KEY_PAIR_GEN
  , ckm_EC_KEY_PAIR_GEN
  , ckm_EC_KEY_PAIR_GEN_W_EXTRA_BITS
  , ckm_GENERIC_SECRET_KEY_GEN
  , ckm_HOTP_KEY_GEN
  , ckm_ML_KEM_KEY_PAIR_GEN
  , ckm_ML_DSA_KEY_PAIR_GEN
  , ckm_SLH_DSA_KEY_PAIR_GEN
  , ckm_RSA_PKCS
  , ckm_RSA_PKCS_KEY_PAIR_GEN
  , ckm_RSA_PKCS_OAEP
  , ckm_RSA_X_509
  , ckm_DES_KEY_GEN
  , ckm_DES2_KEY_GEN
  , ckm_CDMF_KEY_GEN
  , ckm_CAST_KEY_GEN
  , ckm_CAST3_KEY_GEN
  , ckm_CAST128_KEY_GEN
  , ckm_RC2_KEY_GEN
  , ckm_RC4_KEY_GEN
  , ckm_RC5_KEY_GEN
  , ckm_IDEA_KEY_GEN
  , ckm_SKIPJACK_KEY_GEN
  , ckm_BATON_KEY_GEN
  , ckm_JUNIPER_KEY_GEN
  , ckm_BLOWFISH_KEY_GEN
  , ckm_TWOFISH_KEY_GEN
  , ckm_GOST28147_KEY_GEN
  , ckm_SEED_KEY_GEN
  , ckm_ARIA_KEY_GEN
  , ckm_CAMELLIA_KEY_GEN
  , ckm_SALSA20_KEY_GEN
  , ckm_POLY1305_KEY_GEN
  , ckm_AES_XTS_KEY_GEN
  , ckm_HKDF_KEY_GEN
  , ckm_SHA_1_KEY_GEN
  , ckm_SHA224_KEY_GEN
  , ckm_SHA256_KEY_GEN
  , ckm_SHA384_KEY_GEN
  , ckm_SHA512_KEY_GEN
  , ckm_SHA512_224_KEY_GEN
  , ckm_SHA512_256_KEY_GEN
  , ckm_SHA512_T_KEY_GEN
  , ckm_SHA3_224_KEY_GEN
  , ckm_SHA3_256_KEY_GEN
  , ckm_SHA3_384_KEY_GEN
  , ckm_SHA3_512_KEY_GEN
  , ckm_BLAKE2B_160_KEY_GEN
  , ckm_BLAKE2B_256_KEY_GEN
  , ckm_BLAKE2B_384_KEY_GEN
  , ckm_SSL3_PRE_MASTER_KEY_GEN
  , ckm_TLS_PRE_MASTER_KEY_GEN
  , ckm_WTLS_PRE_MASTER_KEY_GEN
  , ckm_PKCS5_PBKD2
  , ckm_PBE_SHA1_DES3_EDE_CBC
  , ckm_PBE_SHA1_DES2_EDE_CBC
  )
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Rules (Rules)
import Haskoki.Session (admitCode, admitObjects, admitPrivate, admitWritable)
import Haskoki.Types
  ( ExternalHandle (..)
  , ObjectId (..)
  , ReturnCode (..)
  , SessionId
  , SlotId
  )

-- ---------------------------------------------------------------------------
-- Class and key-type codes
-- ---------------------------------------------------------------------------

-- | @CKO_DATA@ (generated id, resolved by name).
ckoData :: Word64
ckoData = mustClassId "CKO_DATA"

-- | @CKO_SECRET_KEY@ (generated id, resolved by name).
ckoSecretKey :: Word64
ckoSecretKey = mustClassId "CKO_SECRET_KEY"

-- | @CKO_PUBLIC_KEY@ (generated id, resolved by name).
ckoPublicKey :: Word64
ckoPublicKey = mustClassId "CKO_PUBLIC_KEY"

-- | @CKO_PRIVATE_KEY@ (generated id, resolved by name).
ckoPrivateKey :: Word64
ckoPrivateKey = mustClassId "CKO_PRIVATE_KEY"

-- | @CKO_DOMAIN_PARAMETERS@ (generated id, resolved by name).
ckoDomainParameters :: Word64
ckoDomainParameters = mustClassId "CKO_DOMAIN_PARAMETERS"

-- | @CKK_RSA@ (generated id, resolved by name).
ckkRsa :: Word64
ckkRsa = mustKeyTypeId "CKK_RSA"

-- | @CKK_EC@ (generated id, resolved by name).
ckkEc :: Word64
ckkEc = mustKeyTypeId "CKK_EC"

-- | @CKK_DSA@ (generated id, resolved by name).
ckkDsa :: Word64
ckkDsa = mustKeyTypeId "CKK_DSA"

-- | @CKK_DH@ (generated id, resolved by name).
ckkDh :: Word64
ckkDh = mustKeyTypeId "CKK_DH"

-- | @CKK_X9_42_DH@ (generated id, resolved by name).
ckkX9_42Dh :: Word64
ckkX9_42Dh = mustKeyTypeId "CKK_X9_42_DH"

-- | @CKK_EC_EDWARDS@ (generated id, resolved by name).
ckkEcEdwards :: Word64
ckkEcEdwards = mustKeyTypeId "CKK_EC_EDWARDS"

-- | @CKK_EC_MONTGOMERY@ (generated id, resolved by name).
ckkEcMontgomery :: Word64
ckkEcMontgomery = mustKeyTypeId "CKK_EC_MONTGOMERY"

-- | @CKK_GENERIC_SECRET@ (generated id, resolved by name).
ckkGenericSecret :: Word64
ckkGenericSecret = mustKeyTypeId "CKK_GENERIC_SECRET"

-- | @CKK_AES@ (generated id, resolved by name).
ckkAes :: Word64
ckkAes = mustKeyTypeId "CKK_AES"

-- | @CKK_DES3@ (generated id, resolved by name).
ckkDes3 :: Word64
ckkDes3 = mustKeyTypeId "CKK_DES3"

-- | @CKK_AES_XTS@ (generated id, resolved by name).
ckkAesXts :: Word64
ckkAesXts = mustKeyTypeId "CKK_AES_XTS"

-- | @CKK_HOTP@ (generated id, resolved by name).
ckkHotp :: Word64
ckkHotp = mustKeyTypeId "CKK_HOTP"

-- | @CKK_BLAKE2B_512_HMAC@ (generated id, resolved by name).
ckkBlake2b512Hmac :: Word64
ckkBlake2b512Hmac = mustKeyTypeId "CKK_BLAKE2B_512_HMAC"

-- | @CKK_CHACHA20@ (generated id, resolved by name).
ckkChacha20 :: Word64
ckkChacha20 = mustKeyTypeId "CKK_CHACHA20"

-- | @CKK_ML_KEM@ (generated id, resolved by name).
ckkMlKem :: Word64
ckkMlKem = mustKeyTypeId "CKK_ML_KEM"

-- | @CKK_ML_DSA@ (generated id, resolved by name).
ckkMlDsa :: Word64
ckkMlDsa = mustKeyTypeId "CKK_ML_DSA"

-- ---------------------------------------------------------------------------
-- Mechanism ids
-- ---------------------------------------------------------------------------

-- | @CKM_AES_KEY_GEN@ (generated id, resolved by name).
aesKeyGenMech :: MechanismId
aesKeyGenMech = MechanismId (ckm_AES_KEY_GEN)

-- | @CKM_DES3_KEY_GEN@ (generated id, resolved by name).
des3KeyGenMech :: MechanismId
des3KeyGenMech = MechanismId (ckm_DES3_KEY_GEN)

-- | @CKM_HOTP_KEY_GEN@ (generated id, resolved by name).
hotpKeyGenMech :: MechanismId
hotpKeyGenMech = MechanismId (ckm_HOTP_KEY_GEN)

-- | @CKM_BLAKE2B_512_KEY_GEN@ (generated id, resolved by name).
blake2b512KeyGenMech :: MechanismId
blake2b512KeyGenMech = MechanismId (ckm_BLAKE2B_512_KEY_GEN)

-- | @CKM_CHACHA20_KEY_GEN@ (generated id, resolved by name).
chacha20KeyGenMech :: MechanismId
chacha20KeyGenMech = MechanismId (ckm_CHACHA20_KEY_GEN)

-- | @CKM_GENERIC_SECRET_KEY_GEN@ (generated id, resolved by name).
genericSecretKeyGenMech :: MechanismId
genericSecretKeyGenMech = MechanismId (ckm_GENERIC_SECRET_KEY_GEN)

-- | Generic-secret keygen floor: a zero-length secret carries no key
-- material, so the planner refuses it as inconsistent.
genericSecretKeygenMinBytes :: Int
genericSecretKeygenMinBytes = 1

-- | Generic-secret keygen ceiling: the 'GenBytes' planner-driver frame
-- carries the length in one byte, so 255 is the representable
-- maximum. Revisit (wider frame) if a caller needs longer secrets.
genericSecretKeygenMaxBytes :: Int
genericSecretKeygenMaxBytes = 255

-- | @CKM_DES_KEY_GEN@ (generated id, resolved by name).
desKeyGenMech :: MechanismId
desKeyGenMech = MechanismId (ckm_DES_KEY_GEN)

-- | @CKM_DES2_KEY_GEN@ (generated id, resolved by name).
des2KeyGenMech :: MechanismId
des2KeyGenMech = MechanismId (ckm_DES2_KEY_GEN)

-- | @CKM_CDMF_KEY_GEN@ (generated id, resolved by name).
cdmfKeyGenMech :: MechanismId
cdmfKeyGenMech = MechanismId (ckm_CDMF_KEY_GEN)

-- | @CKM_CAST_KEY_GEN@ (generated id, resolved by name).
castKeyGenMech :: MechanismId
castKeyGenMech = MechanismId (ckm_CAST_KEY_GEN)

-- | @CKM_CAST3_KEY_GEN@ (generated id, resolved by name).
cast3KeyGenMech :: MechanismId
cast3KeyGenMech = MechanismId (ckm_CAST3_KEY_GEN)

-- | @CKM_CAST128_KEY_GEN@ (generated id, resolved by name).
cast128KeyGenMech :: MechanismId
cast128KeyGenMech = MechanismId (ckm_CAST128_KEY_GEN)

-- | @CKM_RC2_KEY_GEN@ (generated id, resolved by name).
rc2KeyGenMech :: MechanismId
rc2KeyGenMech = MechanismId (ckm_RC2_KEY_GEN)

-- | @CKM_RC4_KEY_GEN@ (generated id, resolved by name).
rc4KeyGenMech :: MechanismId
rc4KeyGenMech = MechanismId (ckm_RC4_KEY_GEN)

-- | @CKM_RC5_KEY_GEN@ (generated id, resolved by name).
rc5KeyGenMech :: MechanismId
rc5KeyGenMech = MechanismId (ckm_RC5_KEY_GEN)

-- | @CKM_IDEA_KEY_GEN@ (generated id, resolved by name).
ideaKeyGenMech :: MechanismId
ideaKeyGenMech = MechanismId (ckm_IDEA_KEY_GEN)

-- | @CKM_SKIPJACK_KEY_GEN@ (generated id, resolved by name).
skipjackKeyGenMech :: MechanismId
skipjackKeyGenMech = MechanismId (ckm_SKIPJACK_KEY_GEN)

-- | @CKM_BATON_KEY_GEN@ (generated id, resolved by name).
batonKeyGenMech :: MechanismId
batonKeyGenMech = MechanismId (ckm_BATON_KEY_GEN)

-- | @CKM_JUNIPER_KEY_GEN@ (generated id, resolved by name).
juniperKeyGenMech :: MechanismId
juniperKeyGenMech = MechanismId (ckm_JUNIPER_KEY_GEN)

-- | @CKM_BLOWFISH_KEY_GEN@ (generated id, resolved by name).
blowfishKeyGenMech :: MechanismId
blowfishKeyGenMech = MechanismId (ckm_BLOWFISH_KEY_GEN)

-- | @CKM_TWOFISH_KEY_GEN@ (generated id, resolved by name).
twofishKeyGenMech :: MechanismId
twofishKeyGenMech = MechanismId (ckm_TWOFISH_KEY_GEN)

-- | @CKM_GOST28147_KEY_GEN@ (generated id, resolved by name).
gost28147KeyGenMech :: MechanismId
gost28147KeyGenMech = MechanismId (ckm_GOST28147_KEY_GEN)

-- | @CKM_SEED_KEY_GEN@ (generated id, resolved by name).
seedKeyGenMech :: MechanismId
seedKeyGenMech = MechanismId (ckm_SEED_KEY_GEN)

-- | @CKM_ARIA_KEY_GEN@ (generated id, resolved by name).
ariaKeyGenMech :: MechanismId
ariaKeyGenMech = MechanismId (ckm_ARIA_KEY_GEN)

-- | @CKM_CAMELLIA_KEY_GEN@ (generated id, resolved by name).
camelliaKeyGenMech :: MechanismId
camelliaKeyGenMech = MechanismId (ckm_CAMELLIA_KEY_GEN)

-- | @CKM_SALSA20_KEY_GEN@ (generated id, resolved by name).
salsa20KeyGenMech :: MechanismId
salsa20KeyGenMech = MechanismId (ckm_SALSA20_KEY_GEN)

-- | @CKM_POLY1305_KEY_GEN@ (generated id, resolved by name).
poly1305KeyGenMech :: MechanismId
poly1305KeyGenMech = MechanismId (ckm_POLY1305_KEY_GEN)

-- | @CKM_AES_XTS_KEY_GEN@ (generated id, resolved by name).
aesXtsKeyGenMech :: MechanismId
aesXtsKeyGenMech = MechanismId (ckm_AES_XTS_KEY_GEN)

-- | @CKM_HKDF_KEY_GEN@ (generated id, resolved by name).
hkdfKeyGenMech :: MechanismId
hkdfKeyGenMech = MechanismId (ckm_HKDF_KEY_GEN)

-- | @CKM_SHA_1_KEY_GEN@ (generated id, resolved by name).
sha1KeyGenMech :: MechanismId
sha1KeyGenMech = MechanismId (ckm_SHA_1_KEY_GEN)

-- | @CKM_SHA224_KEY_GEN@ (generated id, resolved by name).
sha224KeyGenMech :: MechanismId
sha224KeyGenMech = MechanismId (ckm_SHA224_KEY_GEN)

-- | @CKM_SHA256_KEY_GEN@ (generated id, resolved by name).
sha256KeyGenMech :: MechanismId
sha256KeyGenMech = MechanismId (ckm_SHA256_KEY_GEN)

-- | @CKM_SHA384_KEY_GEN@ (generated id, resolved by name).
sha384KeyGenMech :: MechanismId
sha384KeyGenMech = MechanismId (ckm_SHA384_KEY_GEN)

-- | @CKM_SHA512_KEY_GEN@ (generated id, resolved by name).
sha512KeyGenMech :: MechanismId
sha512KeyGenMech = MechanismId (ckm_SHA512_KEY_GEN)

-- | @CKM_SHA512_224_KEY_GEN@ (generated id, resolved by name).
sha512_224KeyGenMech :: MechanismId
sha512_224KeyGenMech = MechanismId (ckm_SHA512_224_KEY_GEN)

-- | @CKM_SHA512_256_KEY_GEN@ (generated id, resolved by name).
sha512_256KeyGenMech :: MechanismId
sha512_256KeyGenMech = MechanismId (ckm_SHA512_256_KEY_GEN)

-- | @CKM_SHA512_T_KEY_GEN@ (generated id, resolved by name).
sha512TKeyGenMech :: MechanismId
sha512TKeyGenMech = MechanismId (ckm_SHA512_T_KEY_GEN)

-- | @CKM_SHA3_224_KEY_GEN@ (generated id, resolved by name).
sha3_224KeyGenMech :: MechanismId
sha3_224KeyGenMech = MechanismId (ckm_SHA3_224_KEY_GEN)

-- | @CKM_SHA3_256_KEY_GEN@ (generated id, resolved by name).
sha3_256KeyGenMech :: MechanismId
sha3_256KeyGenMech = MechanismId (ckm_SHA3_256_KEY_GEN)

-- | @CKM_SHA3_384_KEY_GEN@ (generated id, resolved by name).
sha3_384KeyGenMech :: MechanismId
sha3_384KeyGenMech = MechanismId (ckm_SHA3_384_KEY_GEN)

-- | @CKM_SHA3_512_KEY_GEN@ (generated id, resolved by name).
sha3_512KeyGenMech :: MechanismId
sha3_512KeyGenMech = MechanismId (ckm_SHA3_512_KEY_GEN)

-- | @CKM_BLAKE2B_160_KEY_GEN@ (generated id, resolved by name).
blake2b160KeyGenMech :: MechanismId
blake2b160KeyGenMech = MechanismId (ckm_BLAKE2B_160_KEY_GEN)

-- | @CKM_BLAKE2B_256_KEY_GEN@ (generated id, resolved by name).
blake2b256KeyGenMech :: MechanismId
blake2b256KeyGenMech = MechanismId (ckm_BLAKE2B_256_KEY_GEN)

-- | @CKM_BLAKE2B_384_KEY_GEN@ (generated id, resolved by name).
blake2b384KeyGenMech :: MechanismId
blake2b384KeyGenMech = MechanismId (ckm_BLAKE2B_384_KEY_GEN)

-- | @CKM_SSL3_PRE_MASTER_KEY_GEN@ (generated id, resolved by name).
ssl3PremasterKeyGenMech :: MechanismId
ssl3PremasterKeyGenMech = MechanismId (ckm_SSL3_PRE_MASTER_KEY_GEN)

-- | @CKM_TLS_PRE_MASTER_KEY_GEN@ (generated id, resolved by name).
tlsPremasterKeyGenMech :: MechanismId
tlsPremasterKeyGenMech = MechanismId (ckm_TLS_PRE_MASTER_KEY_GEN)

-- | @CKM_WTLS_PRE_MASTER_KEY_GEN@ (generated id, resolved by name).
wtlsPremasterKeyGenMech :: MechanismId
wtlsPremasterKeyGenMech = MechanismId (ckm_WTLS_PRE_MASTER_KEY_GEN)

-- | @CKM_PKCS5_PBKD2@ (generated id, resolved by name): the PBKDF2
-- key-generation mechanism (the v2 frame carries the password
-- inline per @CK_PKCS5_PBKD2_PARAMS2@).
pbkd2KeyGenMech :: MechanismId
pbkd2KeyGenMech = MechanismId (ckm_PKCS5_PBKD2)

-- | The PBE keygen rows (generated ids, resolved by name).
pbeDes3KeyGenMech, pbeDes2KeyGenMech :: MechanismId
pbeDes3KeyGenMech = MechanismId (ckm_PBE_SHA1_DES3_EDE_CBC)
pbeDes2KeyGenMech = MechanismId (ckm_PBE_SHA1_DES2_EDE_CBC)

-- | PBKD2 keygen ceiling: the shared derived-total ceiling (the
-- value mirrors 'Haskoki.Operation.Derive.maxDerivedTotal',
-- which this module cannot import — Derive depends on
-- KeyManagement — pinned equal by the PBKD2 keygen case).
pbkd2KeygenMaxBytes :: Int
pbkd2KeygenMaxBytes = 8160

-- | @CKM_EC_KEY_PAIR_GEN@ (generated id, resolved by name).
ecKeyPairGenMech :: MechanismId
ecKeyPairGenMech = MechanismId (ckm_EC_KEY_PAIR_GEN)

-- | @CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS@ (generated id, resolved by
-- name). The FIPS 186-5 B.4.2 extra-bits method is unobservable
-- from the outside (keys are uniform in range either way), so it
-- plans exactly like plain EC keygen.
ecExtraBitsKeyPairGenMech :: MechanismId
ecExtraBitsKeyPairGenMech = MechanismId (ckm_EC_KEY_PAIR_GEN_W_EXTRA_BITS)

-- | @CKM_RSA_PKCS_KEY_PAIR_GEN@ (generated id, resolved by name).
rsaKeyPairGenMech :: MechanismId
rsaKeyPairGenMech = MechanismId (ckm_RSA_PKCS_KEY_PAIR_GEN)

-- | @CKM_DSA_KEY_PAIR_GEN@ (generated id, resolved by name).
dsaKeyPairGenMech :: MechanismId
dsaKeyPairGenMech = MechanismId (ckm_DSA_KEY_PAIR_GEN)

-- | @CKM_DSA_PARAMETER_GEN@ (generated id, resolved by name).
dsaParameterGenMech :: MechanismId
dsaParameterGenMech = MechanismId (ckm_DSA_PARAMETER_GEN)

-- | @CKM_DH_PKCS_KEY_PAIR_GEN@ (generated id, resolved by name).
dhKeyPairGenMech :: MechanismId
dhKeyPairGenMech = MechanismId (ckm_DH_PKCS_KEY_PAIR_GEN)

-- | @CKM_X9_42_DH_KEY_PAIR_GEN@ (generated id, resolved by name).
x9_42DhKeyPairGenMech :: MechanismId
x9_42DhKeyPairGenMech = MechanismId (ckm_X9_42_DH_KEY_PAIR_GEN)

-- | @CKM_X9_42_DH_PARAMETER_GEN@ (generated id, resolved by name).
x9_42DhParameterGenMech :: MechanismId
x9_42DhParameterGenMech = MechanismId (ckm_X9_42_DH_PARAMETER_GEN)

-- | @CKM_DH_PKCS_PARAMETER_GEN@ (generated id, resolved by name).
dhPkcsParameterGenMech :: MechanismId
dhPkcsParameterGenMech = MechanismId (ckm_DH_PKCS_PARAMETER_GEN)

-- | @CKM_EC_EDWARDS_KEY_PAIR_GEN@ (generated id, resolved by name).
edwardsKeyPairGenMech :: MechanismId
edwardsKeyPairGenMech = MechanismId (ckm_EC_EDWARDS_KEY_PAIR_GEN)

-- | @CKM_EC_MONTGOMERY_KEY_PAIR_GEN@ (generated id, resolved by name).
montgomeryKeyPairGenMech :: MechanismId
montgomeryKeyPairGenMech = MechanismId (ckm_EC_MONTGOMERY_KEY_PAIR_GEN)

-- | @CKM_ML_DSA_KEY_PAIR_GEN@ (generated id, resolved by name).
mldsaKeyPairGenMech :: MechanismId
mldsaKeyPairGenMech = MechanismId (ckm_ML_DSA_KEY_PAIR_GEN)

-- | @CKK_SLH_DSA@ (generated id, resolved by name).
ckkSlhDsa :: Word64
ckkSlhDsa = mustKeyTypeId "CKK_SLH_DSA"

-- | @CKK_DES@ (generated id, resolved by name).
ckkDes :: Word64
ckkDes = mustKeyTypeId "CKK_DES"

-- | @CKK_DES2@ (generated id, resolved by name).
ckkDes2 :: Word64
ckkDes2 = mustKeyTypeId "CKK_DES2"

-- | @CKK_CDMF@ (generated id, resolved by name).
ckkCdmf :: Word64
ckkCdmf = mustKeyTypeId "CKK_CDMF"

-- | @CKK_CAST@ (generated id, resolved by name).
ckkCast :: Word64
ckkCast = mustKeyTypeId "CKK_CAST"

-- | @CKK_CAST3@ (generated id, resolved by name).
ckkCast3 :: Word64
ckkCast3 = mustKeyTypeId "CKK_CAST3"

-- | @CKK_CAST128@ (generated id, resolved by name).
ckkCast128 :: Word64
ckkCast128 = mustKeyTypeId "CKK_CAST128"

-- | @CKK_RC2@ (generated id, resolved by name).
ckkRc2 :: Word64
ckkRc2 = mustKeyTypeId "CKK_RC2"

-- | @CKK_RC4@ (generated id, resolved by name).
ckkRc4 :: Word64
ckkRc4 = mustKeyTypeId "CKK_RC4"

-- | @CKK_RC5@ (generated id, resolved by name).
ckkRc5 :: Word64
ckkRc5 = mustKeyTypeId "CKK_RC5"

-- | @CKK_IDEA@ (generated id, resolved by name).
ckkIdea :: Word64
ckkIdea = mustKeyTypeId "CKK_IDEA"

-- | @CKK_SKIPJACK@ (generated id, resolved by name).
ckkSkipjack :: Word64
ckkSkipjack = mustKeyTypeId "CKK_SKIPJACK"

-- | @CKK_BATON@ (generated id, resolved by name).
ckkBaton :: Word64
ckkBaton = mustKeyTypeId "CKK_BATON"

-- | @CKK_JUNIPER@ (generated id, resolved by name).
ckkJuniper :: Word64
ckkJuniper = mustKeyTypeId "CKK_JUNIPER"

-- | @CKK_BLOWFISH@ (generated id, resolved by name).
ckkBlowfish :: Word64
ckkBlowfish = mustKeyTypeId "CKK_BLOWFISH"

-- | @CKK_TWOFISH@ (generated id, resolved by name).
ckkTwofish :: Word64
ckkTwofish = mustKeyTypeId "CKK_TWOFISH"

-- | @CKK_GOST28147@ (generated id, resolved by name).
ckkGost28147 :: Word64
ckkGost28147 = mustKeyTypeId "CKK_GOST28147"

-- | @CKK_SEED@ (generated id, resolved by name).
ckkSeed :: Word64
ckkSeed = mustKeyTypeId "CKK_SEED"

-- | @CKK_ARIA@ (generated id, resolved by name).
ckkAria :: Word64
ckkAria = mustKeyTypeId "CKK_ARIA"

-- | @CKK_CAMELLIA@ (generated id, resolved by name).
ckkCamellia :: Word64
ckkCamellia = mustKeyTypeId "CKK_CAMELLIA"

-- | @CKK_SALSA20@ (generated id, resolved by name).
ckkSalsa20 :: Word64
ckkSalsa20 = mustKeyTypeId "CKK_SALSA20"

-- | @CKK_POLY1305@ (generated id, resolved by name).
ckkPoly1305 :: Word64
ckkPoly1305 = mustKeyTypeId "CKK_POLY1305"

-- | @CKK_HKDF@ (generated id, resolved by name).
ckkHkdf :: Word64
ckkHkdf = mustKeyTypeId "CKK_HKDF"

-- | @CKK_SHA_1_HMAC@ (generated id, resolved by name).
ckkSha1Hmac :: Word64
ckkSha1Hmac = mustKeyTypeId "CKK_SHA_1_HMAC"

-- | @CKK_SHA224_HMAC@ (generated id, resolved by name).
ckkSha224Hmac :: Word64
ckkSha224Hmac = mustKeyTypeId "CKK_SHA224_HMAC"

-- | @CKK_SHA256_HMAC@ (generated id, resolved by name).
ckkSha256Hmac :: Word64
ckkSha256Hmac = mustKeyTypeId "CKK_SHA256_HMAC"

-- | @CKK_SHA384_HMAC@ (generated id, resolved by name).
ckkSha384Hmac :: Word64
ckkSha384Hmac = mustKeyTypeId "CKK_SHA384_HMAC"

-- | @CKK_SHA512_HMAC@ (generated id, resolved by name).
ckkSha512Hmac :: Word64
ckkSha512Hmac = mustKeyTypeId "CKK_SHA512_HMAC"

-- | @CKK_SHA512_224_HMAC@ (generated id, resolved by name).
ckkSha512_224Hmac :: Word64
ckkSha512_224Hmac = mustKeyTypeId "CKK_SHA512_224_HMAC"

-- | @CKK_SHA512_256_HMAC@ (generated id, resolved by name).
ckkSha512_256Hmac :: Word64
ckkSha512_256Hmac = mustKeyTypeId "CKK_SHA512_256_HMAC"

-- | @CKK_SHA512_T_HMAC@ (generated id, resolved by name).
ckkSha512THmac :: Word64
ckkSha512THmac = mustKeyTypeId "CKK_SHA512_T_HMAC"

-- | @CKK_SHA3_224_HMAC@ (generated id, resolved by name).
ckkSha3_224Hmac :: Word64
ckkSha3_224Hmac = mustKeyTypeId "CKK_SHA3_224_HMAC"

-- | @CKK_SHA3_256_HMAC@ (generated id, resolved by name).
ckkSha3_256Hmac :: Word64
ckkSha3_256Hmac = mustKeyTypeId "CKK_SHA3_256_HMAC"

-- | @CKK_SHA3_384_HMAC@ (generated id, resolved by name).
ckkSha3_384Hmac :: Word64
ckkSha3_384Hmac = mustKeyTypeId "CKK_SHA3_384_HMAC"

-- | @CKK_SHA3_512_HMAC@ (generated id, resolved by name).
ckkSha3_512Hmac :: Word64
ckkSha3_512Hmac = mustKeyTypeId "CKK_SHA3_512_HMAC"

-- | @CKK_BLAKE2B_160_HMAC@ (generated id, resolved by name).
ckkBlake2b160Hmac :: Word64
ckkBlake2b160Hmac = mustKeyTypeId "CKK_BLAKE2B_160_HMAC"

-- | @CKK_BLAKE2B_256_HMAC@ (generated id, resolved by name).
ckkBlake2b256Hmac :: Word64
ckkBlake2b256Hmac = mustKeyTypeId "CKK_BLAKE2B_256_HMAC"

-- | @CKK_BLAKE2B_384_HMAC@ (generated id, resolved by name).
ckkBlake2b384Hmac :: Word64
ckkBlake2b384Hmac = mustKeyTypeId "CKK_BLAKE2B_384_HMAC"

-- | @CKM_SLH_DSA_KEY_PAIR_GEN@ (generated id, resolved by name).
slhdsaKeyPairGenMech :: MechanismId
slhdsaKeyPairGenMech = MechanismId (ckm_SLH_DSA_KEY_PAIR_GEN)

-- | @CKM_AES_CBC@ (the symmetric wrap mechanism: the planner
-- pads, the driver runs raw CBC; generated id, resolved by name).
aesCbcMech :: MechanismId
aesCbcMech = MechanismId (ckm_AES_CBC)

-- | @CKM_AES_KEY_WRAP@ (RFC 3394: the payload travels raw on the
-- 8-byte quantum, minimum 16 bytes; the blob expands by the 8-byte
-- IV; generated id, resolved by name).
aesKwMech :: MechanismId
aesKwMech = MechanismId (ckm_AES_KEY_WRAP)

-- | @CKM_AES_KEY_WRAP_PAD@ (KWP semantics: the oracle equates it
-- with KWP and runs no distinct vectors; generated id, resolved by
-- name).
aesKwPadMech :: MechanismId
aesKwPadMech = MechanismId (ckm_AES_KEY_WRAP_PAD)

-- | @CKM_AES_KEY_WRAP_KWP@ (RFC 5649: any payload length >= 1;
-- the blob pads to a multiple of 8 plus the 8-byte IV; generated
-- id, resolved by name).
aesKwpMech :: MechanismId
aesKwpMech = MechanismId (ckm_AES_KEY_WRAP_KWP)

-- | @CKM_RSA_PKCS@ (the v1.5 wrap mechanism: empty parameters,
-- the payload travels raw, the blob is modulus-wide).
rsaPkcsMech :: MechanismId
rsaPkcsMech = MechanismId (ckm_RSA_PKCS)

-- | @CKM_RSA_PKCS_OAEP@ (the OAEP wrap mechanism: labeled
-- @oaep-params\/1@ parameters, the payload travels raw, the blob
-- is modulus-wide).
rsaOaepMech :: MechanismId
rsaOaepMech = MechanismId (ckm_RSA_PKCS_OAEP)

-- | @CKM_RSA_X_509@ (the raw-RSA wrap mechanism: empty
-- parameters, the payload travels raw, the blob is modulus-wide,
-- unwrap slices the trailing key bytes off the decrypted block).
rsaX509Mech :: MechanismId
rsaX509Mech = MechanismId (ckm_RSA_X_509)

-- ---------------------------------------------------------------------------
-- Plan currency
-- ---------------------------------------------------------------------------

-- | Why a key-management call was denied.
data KeyDeny = KeyDeny
  { kdCode :: !ReturnCode
  , kdReason :: !String
  } deriving (Eq, Show)

-- | One key-management plan: a denial (no objects, no outputs), an
-- immediate outcome (length queries and short buffers, likewise
-- object-free), or exactly one effect plus the pending work its
-- answer completes.
data KeyPlan
  = KeyDenied !KeyDeny
  | KeyImmediate !PlanResult
  | KeyEffect !PendingWork !CryptoEffect
  deriving (Eq, Show)

-- | One object awaiting publication: its full attributes, its
-- lifetime owner ('Nothing' = token object) and its home slot.
data PendingObject = PendingObject
  { poAttrs :: !(Map AttributeType AttributeValue)
  , poOwner :: !(Maybe SessionId)
  , poSlot :: !SlotId
  } deriving (Eq, Show)

-- | The pending work one driver answer completes. Every variant
-- carries fully validated templates; 'finishWork' only adds the
-- driver-supplied material and publishes.
data PendingWork
  = PwGeneratePair
      { pwPub :: !PendingObject
      , pwPriv :: !PendingObject
      }
  | PwGenerateKey
      { pwKey :: !PendingObject
      }
  | PwGenerateKeyIv
      { pwKey :: !PendingObject
      , pwKeyLen :: !Int
      }
  | PwEncaps
      { pwSecret :: !PendingObject
      , pwCtLen :: !Int
      , pwSsLen :: !Int
      }
  | PwDecaps
      { pwSecret :: !PendingObject
      }
  | PwBlobOut
      { pwRegion :: !String
      }
  | PwUnwrap
      { pwKey :: !PendingObject
      }
  | PwUnwrapRaw
      { pwKey :: !PendingObject
      }
  | PwUnwrapTail
      { pwKey :: !PendingObject
      , pwWidth :: !Int
      , pwLen :: !Int
      }
  | PwDerive
      { pwKeys :: ![PendingObject]
      , pwLens :: ![Int]
      }
  | PwDeriveIv
      { pwKeys :: ![PendingObject]
      , pwLens :: ![Int]
      , pwIvLens :: !(Int, Int)
      }
  deriving (Eq, Show)

-- | Writability over the objects a key plan will create: read-only
-- sessions admit session objects and deny token objects
-- (OASIS PKCS#11 Base v3.0 §5.7.1-5.7.3, via 'admitWritable').
-- Length queries and wrap paths create nothing and always admit.
admitPending :: SessionState -> PendingWork -> Either KeyDeny ()
admitPending st pw =
  case admitPrivate (ssLogin st) wantsPrivate of
    Left deny -> Left (KeyDeny (admitCode deny)
      "public session cannot create private objects")
    Right () -> case admitWritable (ssReadOnly st) wantsToken of
      Left deny -> Left (KeyDeny (admitCode deny)
        "read-only session cannot create token objects")
      Right () -> Right ()
  where
    pos = pendingObjects pw
    wantsToken = any isToken pos
    isToken po = case poOwner po of
      Nothing -> True
      Just _ -> False
    wantsPrivate = any isPrivate pos
    isPrivate po =
      Map.lookup AttrPrivate (poAttrs po) == Just (ValBool True)

-- | Objects a pending work item will create (queries and pure
-- bytes-out work create none).
pendingObjects :: PendingWork -> [PendingObject]
pendingObjects pw = case pw of
  PwGeneratePair pub priv -> [pub, priv]
  PwGenerateKey k -> [k]
  PwGenerateKeyIv k _ -> [k]
  PwEncaps s _ _ -> [s]
  PwDecaps s -> [s]
  PwBlobOut _ -> []
  PwUnwrap k -> [k]
  PwUnwrapRaw k -> [k]
  PwUnwrapTail k _ _ -> [k]
  PwDerive pos _ -> pos
  PwDeriveIv pos _ _ -> pos

-- | Publish pending objects as one atomic delta: every object
-- validates before any id or handle is allocated, so a bad entry
-- fails the whole batch with zero allocation. Ids and handles
-- allocate deterministically from the model counters in list order.
publishPending
  :: Model -> SessionState -> [PendingObject] -> Either KeyDeny (StateDelta, [ExternalHandle])
publishPending model _st pos = do
  mapM_ validPending pos
  let oids = [ObjectId (mNextObject model + i) | i <- [0 .. length pos - 1]]
      hs = [ExternalHandle (mNextHandle model + i) | i <- [0 .. length pos - 1]]
      ops = concat
        [ [ DeltaCreateObjectFull oid (poAttrs po) (poOwner po) (poSlot po)
          , DeltaBindHandle h oid
          ]
        | (po, oid, h) <- zip3 pos oids hs
        ]
  pure (StateDelta ops, hs)
  where
    validPending :: PendingObject -> Either KeyDeny ()
    validPending po
      | Map.member AttrClass (poAttrs po) = Right ()
      | otherwise = Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
          "pending object lacks a class")

-- | Whether a pending-work/effect pair is executable:
-- the validated constructor for executable key pairs. Each
-- 'PendingWork' shape accepts exactly the effects whose answers
-- its finisher can consume (see 'finishWork'); generation pairs
-- additionally check the framed 'GenArgs' (single-key vs
-- pair-key). Execution sites ('runKeyPlan', the async drive)
-- refuse incoherent pairs BEFORE running any effect; the
-- planners below produce only coherent pairs (the suite proves
-- it), and 'finishWork' keeps its answer-shape defenses as
-- defense in depth.
keyPairCompatible :: PendingWork -> CryptoEffect -> Bool
keyPairCompatible (PwGeneratePair _ _) (FxGenerateKey _ _ input) =
  case decodeGenArgs input of
    Just (GenEc _) -> True
    Just (GenRsa _ _) -> True
    Just (GenMlKem _) -> True
    Just (GenDsaKeypair _) -> True
    Just (GenDhKeypair _) -> True
    Just (GenEdwardsKeypair _) -> True
    Just (GenMontgomeryKeypair _) -> True
    Just (GenMlDsa _) -> True
    Just (GenSlhDsa _) -> True
    _ -> False
keyPairCompatible (PwGenerateKey _) (FxGenerateKey _ _ input) =
  case decodeGenArgs input of
    Just (GenAes _) -> True
    Just (GenBytes _) -> True
    Just (GenParityBytes _) -> True
    Just (GenTlsPremaster _ _) -> True
    Just (GenWtlsPremaster _ _) -> True
    Just (GenPbkd2 _) -> True
    Just (GenDsaParams _ _) -> True
    _ -> False
keyPairCompatible (PwGenerateKeyIv _ _) (FxGenerateKey _ _ input) =
  case decodeGenArgs input of
    Just (GenPbe _) -> True
    _ -> False
keyPairCompatible (PwBlobOut _) (FxWrap _ _ _ _) = True
keyPairCompatible (PwBlobOut _) (FxAuthWrap _ _ _ _) = True
keyPairCompatible (PwUnwrap _) (FxUnwrap _ _ _ _) = True
keyPairCompatible (PwUnwrap _) (FxAuthUnwrap _ _ _ _) = True
keyPairCompatible (PwUnwrapRaw _) (FxUnwrap _ _ _ _) = True
keyPairCompatible (PwUnwrapTail _ _ _) (FxUnwrap _ _ _ _) = True
keyPairCompatible (PwEncaps _ _ _) (FxKemEncaps _ _ _ _) = True
keyPairCompatible (PwDecaps _) (FxKemDecaps _ _ _ _) = True
keyPairCompatible (PwDerive _ _) (FxDerive _ _ _ _ _ _) = True
keyPairCompatible (PwDeriveIv _ _ _) (FxDerive _ _ _ _ _ _) = True
keyPairCompatible _ _ = False

-- | Finish planned work against the driver's answer. On bytes the
-- material lands on the pending objects and the whole batch
-- publishes through 'publishPending' (all-or-nothing: a malformed
-- answer or a validation failure yields zero objects); on any
-- driver failure the mapped code rejects with an empty delta.
finishWork :: Model -> SessionState -> PendingWork -> CryptoResult -> PlanResult
finishWork model st pw res = case (pw, res) of
  (PwGeneratePair pub priv, GotBytes bs) -> case decodeKeyPair bs of
    Just (privM, Just pubM) ->
      case stampPairComponents pub priv pubM privM of
        Just (pub', priv') ->
          publish (storeMaterial pubM pub') (storeMaterial privM priv')
        Nothing -> internal "keypair answer material fails component decode"
    _ -> internal "keypair answer is not a framed private/public pair"
  (PwEncaps sec ctLen ssLen, GotBytes bs)
    | BS.length bs == ctLen + ssLen ->
        let (ct, ss) = BS.splitAt ctLen bs
        in publish1 (storeMaterial ss sec)
            [NativeOutput (RegionBytes "ciphertext" IntentNull) ct]
            ["encapsulated " ++ show ctLen ++ " ciphertext bytes"]
    | otherwise -> internal
        ("encaps answer length " ++ show (BS.length bs)
          ++ " mismatches " ++ show ctLen ++ "+" ++ show ssLen)
  (PwDecaps sec, GotBytes bs)
    | BS.length bs == 32 -> publish1 (storeMaterial bs sec) []
        ["decapsulated shared secret"]
    | otherwise -> internal
        ("decaps answer length " ++ show (BS.length bs) ++ " mismatches 32")
  (PwGenerateKey po, GotBytes bs) -> case decodeKeyPair bs of
    Just (mat, Nothing) -> case stampParamsObject po mat of
      Just po' -> publish1 (storeMaterial mat po') []
        [paramsReason po']
      Nothing -> internal "params answer material fails component decode"
    _ -> internal "single-key answer is not lone material"
  -- PBE answers frame the key/IV pair: the key publishes as
  -- the object, the IV rides a byte output for the FFI
  -- write-back.
  (PwGenerateKeyIv po keyLen, GotBytes bs) -> case decodeKeyPair bs of
    Just (mat, Just iv)
      | BS.length mat == keyLen && BS.length iv == 8 -> case stampParamsObject po mat of
          Just po' -> publish1 (storeMaterial mat po')
            [NativeOutput (RegionBytes "iv" IntentNull) iv]
            ["pbe key plus iv"]
          Nothing -> internal "pbe answer material fails component decode"
      | otherwise -> internal
          ("pbe answer lengths " ++ show (BS.length mat) ++ "+"
            ++ show (BS.length iv) ++ " mismatch " ++ show keyLen ++ "+8")
    _ -> internal "pbe answer is not a key/iv pair"
  (PwBlobOut region, GotBytes bs) -> Immediate PreparedCommit
    { pcCode = CKR_OK
    , pcDelta = StateDelta []
    , pcPersist = []
    , pcOutputs = [NativeOutput (RegionBytes region IntentNull) bs]
    , pcReleases = []
    , pcReasons = ["wrapped blob ready"]
    }
  (PwUnwrap po, GotBytes bs) -> case unpadPkcs7 16 bs of
    Just mat -> publishUnwrap mat po
    Nothing -> Reject Rejection
      { rejCode = CKR_ENCRYPTED_DATA_INVALID
      , rejOutputs = []
      , rejDelta = StateDelta []
      , rejReleases = []
      , rejReasons = ["unwrap padding check failed"]
      }
  -- RSA unwrap answers raw key material (the asymmetric padding
  -- is consumed by the backend): no PKCS#7 framing to strip.
  (PwUnwrapRaw po, GotBytes bs) ->
    publishUnwrap bs po
  -- X.509 unwrap answers a full k-block; the key is the trailing
  -- value_len bytes (the length the unwrap template named).
  (PwUnwrapTail po k n, GotBytes bs) -> case x509Tail k n bs of
    Just mat -> publishUnwrap mat po
    Nothing -> internal
      ("x509 answer length " ++ show (BS.length bs)
        ++ " mismatches width " ++ show k)
  (PwDerive pos lens, GotBytes bs)
    | BS.length bs /= sum lens -> internal
        ("derive answer length " ++ show (BS.length bs)
          ++ " mismatches " ++ show (sum lens))
    | otherwise -> case publishPending model st
        [storeMaterial mat po | (po, mat) <- zip pos (splitLens lens bs)] of
        Left deny -> rejectOf deny
        Right (delta, hs) -> Immediate PreparedCommit
          { pcCode = CKR_OK
          , pcDelta = delta
          , pcPersist = []
          , pcOutputs =
              [ NativeOutput (RegionHandle "key")
                  (encodeValue (ValULong (fromIntegral (unExternalHandle h))))
              | h <- hs
              ]
          , pcReleases = []
          , pcReasons = ["derived " ++ show (length pos) ++ " keys"]
          }
  -- Key-material answers append the two IVs after the key
  -- bytes (TLS key-block order): keys publish as objects,
  -- IVs ride byte outputs for the FFI write-back. Empty IVs
  -- (a zero size) emit no output.
  (PwDeriveIv pos lens (ivCLen, ivSLen), GotBytes bs)
    | BS.length bs /= sum lens + ivCLen + ivSLen -> internal
        ("keymat answer length " ++ show (BS.length bs)
          ++ " mismatches " ++ show (sum lens + ivCLen + ivSLen))
    | otherwise -> case publishPending model st
        [storeMaterial mat po | (po, mat) <- zip pos (splitLens lens keyBs)] of
        Left deny -> rejectOf deny
        Right (delta, hs) -> Immediate PreparedCommit
          { pcCode = CKR_OK
          , pcDelta = delta
          , pcPersist = []
          , pcOutputs =
              [ NativeOutput (RegionHandle "key")
                  (encodeValue (ValULong (fromIntegral (unExternalHandle h))))
              | h <- hs
              ] ++ ivOut "iv-client" ivC ++ ivOut "iv-server" ivS
          , pcReleases = []
          , pcReasons = ["derived " ++ show (length pos) ++ " keys + ivs"]
          }
    where
      (keyBs, ivBs) = BS.splitAt (sum lens) bs
      (ivC, ivS) = BS.splitAt ivCLen ivBs
      ivOut _ out | BS.null out = []
      ivOut region out = [NativeOutput (RegionBytes region IntentNull) out]
  (_, GotValid _) -> internal "verdict answer to key management"
  (_, GotResource _) -> internal "resource answer to key management"
  -- A feed answer never reaches a key finisher; loud on
  -- violation (same failure class as the pre-change empty-bytes
  -- mis-shape, which failed its frame decode).
  (_, GotUnit) -> internal "unit answer to key management"
  (_, GotCryptoError e) -> Reject Rejection
    { rejCode = interpretError (TyCrypto e)
    , rejOutputs = []
    , rejDelta = StateDelta []
    , rejReleases = []
    , rejReasons = ["driver: " ++ show e]
    }
  where
    publish :: PendingObject -> PendingObject -> PlanResult
    publish pub priv = case publishPending model st [pub, priv] of
      Left deny -> rejectOf deny
      Right (delta, [pubH, privH]) -> Immediate PreparedCommit
        { pcCode = CKR_OK
        , pcDelta = delta
        , pcPersist = []
        , pcOutputs =
            [ NativeOutput (RegionHandle "public") (encodeValue (ValULong (fromIntegral (unExternalHandle pubH))))
            , NativeOutput (RegionHandle "private") (encodeValue (ValULong (fromIntegral (unExternalHandle privH))))
            ]
        , pcReleases = []
        , pcReasons = ["generated key pair"]
        }
      Right _ -> internal "pair publication arity"
    publish1 :: PendingObject -> [NativeOutput] -> [String] -> PlanResult
    publish1 po extraOutputs reasons = case publishPending model st [po] of
      Left deny -> rejectOf deny
      Right (delta, [h]) -> Immediate PreparedCommit
        { pcCode = CKR_OK
        , pcDelta = delta
        , pcPersist = []
        , pcOutputs = extraOutputs
            ++ [NativeOutput (RegionHandle "key") (encodeValue (ValULong (fromIntegral (unExternalHandle h))))]
        , pcReleases = []
        , pcReasons = reasons
        }
      Right _ -> internal "single publication arity"
    -- Publish unwrapped material after the type/length coherence
    -- check: the answered bytes must suit the template key type
    -- (AES: 16/24/32; DES3: 24; XTS: 32/64; anything else: any
    -- length). A mismatch is key-type confusion (Tookan section
    -- 3.2) and refuses with CKR_TEMPLATE_INCONSISTENT, publishing
    -- nothing.
    publishUnwrap :: ByteString -> PendingObject -> PlanResult
    publishUnwrap mat po
      | typeLenOk = publish1 (storeMaterial mat po) [] ["unwrapped key"]
      | otherwise = Reject Rejection
          { rejCode = CKR_TEMPLATE_INCONSISTENT
          , rejOutputs = []
          , rejDelta = StateDelta []
          , rejReleases = []
          , rejReasons = ["unwrapped material length "
              ++ show (BS.length mat) ++ " mismatches key type "
              ++ show (Map.lookup AttrKeyType (poAttrs po))]
          }
      where
        typeLenOk = case Map.lookup AttrKeyType (poAttrs po) of
          Just (ValULong k)
            | k == ckkAes -> BS.length mat `elem` [16, 24, 32]
            | k == ckkDes3 -> BS.length mat == 24
            | k == ckkAesXts -> BS.length mat `elem` [32, 64]
          _ -> True

-- | Store driver-supplied key material on a pending object.
storeMaterial :: ByteString -> PendingObject -> PendingObject
storeMaterial mat po = po { poAttrs = Map.insert AttrValue (ValBytes mat) (poAttrs po) }

-- | Stamp keygen components back onto a pending pair. Reads serve
-- stored attributes only (no decode-on-read path), so an RSA pair
-- must carry its CRT components: the public half gets the modulus
-- and exponent, the private half all eight PKCS#1 parts. The two
-- DER halves must agree on (n, e); any parse failure or mismatch
-- is 'Nothing' (the finisher rejects with zero objects). A DSA
-- pair stamps @CKA_PRIME@\/@CKA_SUBPRIME@\/@CKA_BASE@ onto both
-- halves, parsed authoritatively from the SPKI\/PKCS#8 halves
-- (which must agree on (p, q, g)); @AttrValue@ keeps the DER
-- halves ('storeMaterial' runs after stamping, as for RSA\/EC).
-- Opaque halves (synthetic test doubles, not DER) pass through
-- unstamped rather than rejecting, mirroring the EC arm. An EC
-- pair stamps @CKA_EC_POINT@ (the DER OCTET STRING of the
-- uncompressed SPKI point) on the public half; opaque halves
-- pass through unstamped rather than rejecting. An Edwards pair
-- stamps the raw @CKA_EC_POINT@ on the public half and the
-- agreed engine curve name as @CKA_EC_PARAMS@ on the private
-- half (whose template lacks it); disagreeing or opaque halves
-- pass through unstamped. A Montgomery pair stamps the same way
-- (the raw u-coordinate point, the agreed curve name). An ML-DSA
-- pair stamps the @CKA_SEED@
-- on the private half (parsed from the PKCS#8 half, whose seed
-- the planner cannot know; the set rides both halves from the
-- planner tag, and @AttrValue@ keeps the DER halves via
-- 'storeMaterial' as for every asymmetric family — reads serve
-- DER as @CKA_VALUE@, the codebase-wide convention);
-- disagreeing or opaque halves pass through unstamped. An
-- ML-KEM pair stamps the @CKA_SEED@ on the private half the
-- same way (parsed from the provider-form PKCS#8 half);
-- disagreeing or opaque halves pass through unstamped. Other
-- key types pass through untouched.
stampPairComponents
  :: PendingObject -> PendingObject -> ByteString -> ByteString
  -> Maybe (PendingObject, PendingObject)
stampPairComponents pub priv pubM privM
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkDsa) =
      case (dsaSpkiFields pubM, dsaPkcs8Fields privM) of
        (Just (p, q, g, _), Just (p', q', g', _))
          | p' == p && q' == q && g' == g ->
              let stamp a = Map.insert AttrPrime (ValBytes p)
                    (Map.insert AttrSubprime (ValBytes q)
                    (Map.insert AttrBase (ValBytes g) a))
              in Just (pub { poAttrs = stamp (poAttrs pub) }
                     , priv { poAttrs = stamp (poAttrs priv) })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkDh)
    || Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkX9_42Dh) =
      case (dhSpkiFields pubM, dhPkcs8Fields privM) of
        (Just (p, g, q, _), Just (p', g', q', _))
          | p' == p && g' == g && q' == q ->
              let stamp a = Map.insert AttrPrime (ValBytes p)
                    (Map.insert AttrBase (ValBytes g)
                    (maybe id (\qb -> Map.insert AttrSubprime (ValBytes qb)) q a))
              in Just (pub { poAttrs = stamp (poAttrs pub) }
                     , priv { poAttrs = stamp (poAttrs priv) })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkMlDsa) =
      case (mldsaSpkiFields pubM, mldsaPkcs8Fields privM) of
        (Just (pubOid, _), Just (privOid, seed, _))
          | pubOid == privOid ->
              let privA = Map.insert AttrSeed (ValBytes seed) (poAttrs priv)
              in Just (pub, priv { poAttrs = privA })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkSlhDsa) =
      case (slhdsaSpkiFields pubM, slhdsaPkcs8Fields privM) of
        (Just (pubOid, _), Just (privOid, raw))
          | pubOid == privOid ->
              let n = BS.length raw `div` 4
                  privA = Map.insert AttrSeed (ValBytes (BS.take n raw)) (poAttrs priv)
              in Just (pub, priv { poAttrs = privA })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkMlKem) =
      case (mlkemSpkiFields pubM, mlkemPkcs8Fields privM) of
        (Just (pubOid, _), Just (privOid, seed, _))
          | pubOid == privOid ->
              let privA = Map.insert AttrSeed (ValBytes seed) (poAttrs priv)
              in Just (pub, priv { poAttrs = privA })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkEcEdwards) =
      case (eddsaSpkiFields pubM, eddsaPkcs8Fields privM) of
        (Just (pubOid, pubPoint), Just (privOid, _seed))
          | pubOid == privOid
          , Just curve <- edwardsNameOfOid pubOid ->
              let pubA = Map.insert AttrEcPoint (ValBytes pubPoint) (poAttrs pub)
                  privA = Map.insert AttrEcParams (ValBytes curve) (poAttrs priv)
              in Just (pub { poAttrs = pubA }, priv { poAttrs = privA })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkEcMontgomery) =
      case (montgomerySpkiFields pubM, montgomeryPkcs8Fields privM) of
        (Just (pubOid, pubPoint), Just (privOid, _scalar))
          | pubOid == privOid
          , Just curve <- montgomeryNameOfOid pubOid ->
              let pubA = Map.insert AttrEcPoint (ValBytes pubPoint) (poAttrs pub)
                  privA = Map.insert AttrEcParams (ValBytes curve) (poAttrs priv)
              in Just (pub { poAttrs = pubA }, priv { poAttrs = privA })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkEc) =
      case spkiPoint pubM of
        Just pt | BS.take 1 pt == BS.singleton 0x04 ->
          let pubA = Map.insert AttrEcPoint (ValBytes (derOctet pt)) (poAttrs pub)
          in Just (pub { poAttrs = pubA }, priv)
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) /= Just (ValULong ckkRsa) =
      Just (pub, priv)
  | otherwise = do
      (n, e) <- parseRsaPublic pubM
      crt <- parseRsaPrivate privM
      guard (crtN crt == n && crtE crt == e)
      let pubA = Map.insert AttrModulus (ValBytes n)
            (Map.insert AttrPublicExponent (ValBytes e) (poAttrs pub))
          privA = Map.insert AttrModulus (ValBytes n)
            (Map.insert AttrPublicExponent (ValBytes e)
            (Map.insert AttrPrivateExponent (ValBytes (crtD crt))
            (Map.insert AttrPrime1 (ValBytes (crtP crt))
            (Map.insert AttrPrime2 (ValBytes (crtQ crt))
            (Map.insert AttrExponent1 (ValBytes (crtDp crt))
            (Map.insert AttrExponent2 (ValBytes (crtDq crt))
            (Map.insert AttrCoefficient (ValBytes (crtQinv crt))
              (poAttrs priv))))))))
      Just (pub { poAttrs = pubA }, priv { poAttrs = privA })

-- | Stamp domain-parameter components back onto a pending
-- single object. A @CKO_DOMAIN_PARAMETERS@ pending object carries
-- DER DSS-Parms material; reads serve stored attributes only, so
-- the finisher parses the material and stamps @CKA_PRIME@\/
-- @CKA_SUBPRIME@\/@CKA_BASE@ plus the true bit widths as
-- @CKA_PRIME_BITS@\/@CKA_SUBPRIME_BITS@. Opaque material
-- (synthetic test doubles, not DER) passes through unstamped
-- rather than rejecting, mirroring the EC pair arm. Other
-- classes pass through untouched.
stampParamsObject :: PendingObject -> ByteString -> Maybe PendingObject
stampParamsObject po mat
  | Map.lookup AttrClass (poAttrs po) /= Just (ValULong ckoDomainParameters) =
      Just po
  | otherwise = case parseDsaParams mat of
      Just (p, q, g)
        | not (BS.null p) && not (BS.null q) && not (BS.null g) ->
            let stamped = Map.insert AttrPrime (ValBytes p)
                  (Map.insert AttrSubprime (ValBytes q)
                  (Map.insert AttrBase (ValBytes g)
                  (Map.insert AttrPrimeBits (ValULong (fromIntegral (bitsOf p)))
                  (Map.insert AttrSubprimeBits (ValULong (fromIntegral (bitsOf q)))
                    (poAttrs po)))))
            in Just (po { poAttrs = stamped })
      _ -> Just po

-- | The committed reason for a finished single-key job: domain
-- parameters name themselves, everything else is a key.
paramsReason :: PendingObject -> String
paramsReason po
  | Map.lookup AttrClass (poAttrs po) == Just (ValULong ckoDomainParameters) =
      "generated domain parameters"
  | otherwise = "generated key"

-- | True bit width of unsigned big-endian bytes (leading zero
-- bits discounted, so short top octets measure honestly).
bitsOf :: ByteString -> Int
bitsOf bs = case BS.dropWhile (== 0) bs of
  stripped
    | BS.null stripped -> 0
    | otherwise -> BS.length stripped * 8 - countLeadingZeros (BS.head stripped)

-- | Split concatenated derived material at the planned lengths.
splitLens :: [Int] -> ByteString -> [ByteString]
splitLens [] _ = []
splitLens (n : ns) bs =
  let (h, t) = BS.splitAt n bs
  in h : splitLens ns t

-- | Read stored key material back for the driver resolver. The seal
-- does not apply here: it governs the attribute read path, while
-- crypto use of sealed keys is legal.
keyBytesOf :: ObjectState -> Maybe ByteString
keyBytesOf ost = case Map.lookup AttrValue (osAttrs ost) of
  Just (ValBytes bs) -> Just bs
  _ -> Nothing

-- | Read the usage policy off a key object: the permitted operations
-- plus the always-authenticate mark. 'Nothing' when the object
-- carries no key attributes at all (a legacy object), in
-- which case callers fall back to the caller-derived 'KeyPolicy'.
-- Absent flags read as false, per the PKCS#11 defaults.
policyFromObject :: ObjectState -> Maybe ([Operation], Bool)
policyFromObject ost
  | not (any (`Map.member` osAttrs ost) keyAttrs) = Nothing
  | otherwise = Just (permits, flag AttrAlwaysAuthenticate)
  where
    keyAttrs =
      [ AttrKeyType
      , AttrEncrypt, AttrDecrypt, AttrSign, AttrVerify
      , AttrSignRecover, AttrVerifyRecover
      , AttrWrap, AttrUnwrap, AttrDerive
      , AttrEncapsulate, AttrDecapsulate
      , AttrAlwaysAuthenticate
      ]
    flag t = Map.lookup t (osAttrs ost) == Just (ValBool True)
    permits =
      [ op
      | (t, op) <-
          [ (AttrEncrypt, OpEncrypt)
          , (AttrDecrypt, OpDecrypt)
          , (AttrSign, OpSign)
          , (AttrVerify, OpVerify)
          , (AttrSignRecover, OpSignRecover)
          , (AttrVerifyRecover, OpVerifyRecover)
          , (AttrWrap, OpWrap)
          , (AttrUnwrap, OpUnwrap)
          , (AttrDerive, OpDerive)
          , (AttrEncapsulate, OpEncapsulate)
          , (AttrDecapsulate, OpDecapsulate)
          ]
      , flag t
      ]

-- | Key-type compatibility for one @(mechanism, operation, key)@:
-- the matrix ('Haskoki.Registry.KeyMatrix.matrixKeyTypes') permits
-- the key's @CKA_KEY_TYPE@, the pair sits outside the reviewed
-- matrix, or the key carries no key type at all (the legacy seam:
-- untyped objects skip the matrix, mirroring the 'policyFromObject'
-- fallback to the caller-derived policy). 'False' only when a
-- present type contradicts a reviewed row.
keyTypeCompatible :: MechanismId -> Operation -> ObjectState -> Bool
keyTypeCompatible mech op ost = case matrixKeyTypes mech op of
  Nothing -> True
  Just tys -> case Map.lookup AttrKeyType (osAttrs ost) of
    Just (ValULong k) -> k `elem` tys
    _ -> True

-- | Allowed-mechanism compatibility for a @(mechanism, key)@: keys
-- without @CKA_ALLOWED_MECHANISMS@ serve every mechanism; keys
-- carrying it serve exactly the listed ids. The stored value is a
-- packed little-endian @CK_MECHANISM_TYPE@ array (the frame wire
-- order); a misaligned value or a wrong shape fails closed (serves
-- nothing), since a list the token cannot parse must not grant.
mechAllowed :: MechanismId -> ObjectState -> Bool
mechAllowed (MechanismId m) ost = case Map.lookup AttrAllowedMechanisms (osAttrs ost) of
  Nothing -> True
  Just (ValBytes bs)
    | BS.length bs `mod` 8 /= 0 -> False
    | otherwise -> m `elem` decodeIds bs
  Just _ -> False
  where
    decodeIds :: ByteString -> [Word64]
    decodeIds rest
      | BS.null rest = []
      | otherwise =
          let (h, t) = BS.splitAt 8 rest
          in foldr step 0 (BS.unpack h) : decodeIds t
    step :: Word8 -> Word64 -> Word64
    step b acc = acc `shiftL` 8 .|. fromIntegral b

-- | A key-management denial as a plan outcome: no outputs, no delta.
rejectOf :: KeyDeny -> PlanResult
rejectOf (KeyDeny code why) = Reject Rejection
  { rejCode = code
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = [why]
  }

-- | An internal malfunction: malformed driver answers and
-- publication-arity violations. Zero objects, always.
internal :: String -> PlanResult
internal why = Reject Rejection
  { rejCode = CKR_GENERAL_ERROR
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = ["internal: " ++ why]
  }

-- ---------------------------------------------------------------------------
-- Shared template checks
-- ---------------------------------------------------------------------------

-- | Default a missing template class to the mechanism-implied class.
-- Keygen, keypair, derive, and unwrap templates need not repeat the
-- class the mechanism determines (standard practice: oracle fixtures
-- omit it); a present class must still match, and wrong shapes
-- still refuse before this default applies. The stored object
-- always carries the class either way.
ensureTemplateClass
  :: Word64 -> [(AttributeType, AttributeValue)]
  -> [(AttributeType, AttributeValue)]
ensureTemplateClass wantClass tmpl
  | any ((== AttrClass) . fst) tmpl = tmpl
  | otherwise = (AttrClass, ValULong wantClass) : tmpl

-- | Check one key template against its expected class and key type:
-- contradictions reject, a missing class defaults to the
-- mechanism-implied class, a class that is present but wrong is
-- inconsistent, then the template rule for the @(class, key-type)@
-- context enforces required/forbidden presence, and a missing key
-- type defaults to the mechanism's key.
checkKeyTemplate
  :: Word64 -> Word64 -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (Map AttributeType AttributeValue)
checkKeyTemplate wantClass wantKey tmpl =
  case validateTemplate (ensureTemplateClass wantClass tmpl) of
  Left (TemplateContradiction t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("contradictory attribute: " ++ show t))
  Left (TemplateWrongType t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("wrong shape for attribute: " ++ show t))
  Left TemplateIncomplete -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "template is missing the class")
  Right attrs -> case Map.lookup AttrClass attrs of
    Just (ValULong c)
      | c /= wantClass -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("template class " ++ show c ++ " is not " ++ show wantClass))
      | otherwise -> case applyRules wantClass wantKey attrs of
          Left deny -> Left deny
          Right () -> case Map.lookup AttrKeyType attrs of
            Nothing -> Right (defaultUsage wantClass wantKey
              (Map.insert AttrKeyType (ValULong wantKey) attrs))
            Just (ValULong k)
              | k == wantKey -> Right (defaultUsage wantClass wantKey attrs)
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("template key type " ++ show k ++ " is not " ++ show wantKey))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "template key type is malformed")
    _ -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE "template is missing the class")

-- | Generation-time usage defaults: absent operation flags
-- default TRUE on the strict key-template path (single/pair
-- generation and KEM outputs), so minimal templates mint usable
-- keys; explicit values — including FALSE — always win
-- (left-biased union). Defaults follow the object class: public
-- keys default the public operations (encrypt\/verify\/wrap\/
-- encapsulate), private and secret keys the full set (a private
-- key serves the public operations too); non-key classes get no
-- defaults. Flags the context's generated rule forbids stay
-- absent (a defaulted forbidden flag would poison re-validation:
-- detached rejoin replays stored templates through this same
-- check). This matches the oracle's minimal-template legs (which
-- generate with no usage flags and then operate) and the
-- SoftHSM/NSS generation behavior; explicit-false refusal tests
-- are unaffected. @CKA_ALWAYS_AUTHENTICATE@ is not a usage
-- permit and stays absent (false). Creation (@C_CreateObject@)
-- does not use this path and keeps absent-means-false.
defaultUsage :: Word64 -> Word64 -> Map AttributeType AttributeValue -> Map AttributeType AttributeValue
defaultUsage wantClass wantKey attrs = Map.union attrs defaults
  where
    defaults = Map.fromList [(t, ValBool True) | t <- usageFlags, t `notElem` forbidden]
    usageFlags
      | wantClass == ckoPublicKey =
          [AttrEncrypt, AttrVerify, AttrWrap, AttrEncapsulate]
      | wantClass == ckoPrivateKey || wantClass == ckoSecretKey =
          [ AttrEncrypt, AttrDecrypt, AttrSign, AttrVerify
          , AttrWrap, AttrUnwrap, AttrDerive
          , AttrEncapsulate, AttrDecapsulate
          ]
      | otherwise = []
    forbidden = case (classNameById wantClass, keyTypeNameById wantKey) of
      (Just cn, Just kn) -> case findRule cn kn of
        Just rule -> [t | name <- trForbidden rule, Just t <- [attributeTypeByName name]]
        Nothing -> []
      _ -> []

-- | Enforce the generated template rule for a @(class, key-type)@
-- context selected by the planner (not by the template: the rule
-- applies even when the template omits the key type and it later
-- defaults). Contexts without a rule, or with unresolvable context
-- ids, carry no additional constraints. Missing-required denies
-- incomplete; forbidden-present denies inconsistent.
applyRules :: Word64 -> Word64 -> Map AttributeType AttributeValue -> Either KeyDeny ()
applyRules wantClass wantKey attrs =
  case (classNameById wantClass, keyTypeNameById wantKey) of
    (Just cn, Just kn) -> case findRule cn kn of
      Nothing -> Right ()
      Just rule -> case checkRules rule attrs of
        Right () -> Right ()
        Left (RuleMissingRequired n) -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
          ("template rule " ++ T.unpack cn ++ "/" ++ T.unpack kn
            ++ " requires " ++ T.unpack n))
        Left (RuleForbiddenPresent n) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("template rule " ++ T.unpack cn ++ "/" ++ T.unpack kn
            ++ " forbids " ++ T.unpack n))
    _ -> Right ()

-- | Check one key template against its expected class with any key
-- type: contradictions reject, a missing class defaults to the
-- mechanism-implied class, a class that is present but wrong is
-- inconsistent, and a missing key type defaults to the caller's
-- default. Derivation templates use this (derived keys span key
-- types); generation and KEM use the strict 'checkKeyTemplate'.
checkKeyTemplateAny
  :: Word64 -> Word64 -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (Map AttributeType AttributeValue)
checkKeyTemplateAny wantClass defaultKey tmpl =
  case validateTemplate (ensureTemplateClass wantClass tmpl) of
  Left (TemplateContradiction t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("contradictory attribute: " ++ show t))
  Left (TemplateWrongType t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("wrong shape for attribute: " ++ show t))
  Left TemplateIncomplete -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "template is missing the class")
  Right attrs -> case Map.lookup AttrClass attrs of
    Just (ValULong c)
      | c /= wantClass -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("template class " ++ show c ++ " is not " ++ show wantClass))
      | otherwise -> case Map.lookup AttrKeyType attrs of
          Nothing -> Right (Map.insert AttrKeyType (ValULong defaultKey) attrs)
          Just (ValULong _) -> Right attrs
          Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            "template key type is malformed")
    _ -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE "template is missing the class")

-- | Check one data-object template for data-output derivations
-- (@CKM_HKDF_DATA@): contradictions and wrong shapes reject, a
-- missing class defaults to the mechanism-implied @CKO_DATA@, a
-- class that is present but wrong is a key-type contradiction
-- (the operation derives data objects, never keys), and a
-- @CKA_KEY_TYPE@ attribute is inconsistent (data objects carry
-- no key type).
checkDataTemplate
  :: Word64 -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (Map AttributeType AttributeValue)
checkDataTemplate wantData tmpl =
  case validateTemplate (ensureTemplateClass wantData tmpl) of
  Left (TemplateContradiction t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("contradictory attribute: " ++ show t))
  Left (TemplateWrongType t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("wrong shape for attribute: " ++ show t))
  Left TemplateIncomplete -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "template is missing the class")
  Right attrs -> case Map.lookup AttrClass attrs of
    Just (ValULong c)
      | c /= wantData -> Left (KeyDeny CKR_KEY_TYPE_INCONSISTENT
          ("template class " ++ show c ++ " is not a data object"))
      | Map.member AttrKeyType attrs -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "data template must not carry CKA_KEY_TYPE")
      | otherwise -> Right attrs
    _ -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE "template is missing the class")

-- | Pending object from validated template attributes: the token
-- flag decides the lifetime owner, the calling session the home
-- slot. Generation parameters that are not stored key attributes
-- (@AttrModulusBits@, @AttrPrimeBits@, @AttrSubprimeBits@) are
-- dropped (the finisher re-stamps authoritative sizes); everything
-- else carries over verbatim.
pendingFromAttrs :: SessionState -> Map AttributeType AttributeValue -> PendingObject
pendingFromAttrs st attrs = PendingObject
  { poAttrs = Map.delete AttrSubprimeBits (Map.delete AttrPrimeBits (Map.delete AttrModulusBits attrs))
  , poOwner =
      if Map.lookup AttrToken attrs == Just (ValBool True)
        then Nothing
        else Just (ssId st)
  , poSlot = ssSlot st
  }

-- ---------------------------------------------------------------------------
-- Generation frames (planner <-> driver contract)
-- ---------------------------------------------------------------------------

-- | Key-generation arguments framed for the driver: AES length in
-- bytes, EC curve name, RSA modulus bits plus public exponent, the
-- ML-KEM parameter set (512\/768\/1024), an opaque secret length in
-- bytes (HOTP), the DSA @(L, N)@ size pair (parameter generation),
-- DER DSS-Parms (DSA keypair generation from domain parameters),
-- the Edwards curve name (Edwards keypair generation), the
-- Montgomery curve name (Montgomery keypair generation), or the
-- ML-DSA parameter-set id (@CKP_ML_DSA_44\/65\/87@ = 1\/2\/3),
-- or the SLH-DSA parameter-set id (@CKP_SLH_DSA_*@ = 1..12).
data GenArgs
  = GenAes !Int
  | GenEc !ByteString
  | GenRsa !Int !Integer
  | GenMlKem !Int
  | GenBytes !Int
  | GenDsaParams !Int !Int
  | GenDsaKeypair !ByteString
  | GenEdwardsKeypair !ByteString
  | GenMontgomeryKeypair !ByteString
  | GenMlDsa !Int
  | GenSlhDsa !Int
  | GenDhKeypair !ByteString
  | GenParityBytes !Int
  | GenTlsPremaster !Word8 !Word8
  | GenWtlsPremaster !Word8 !Int
  | GenPbkd2 !Int
  | GenPbe !Int
  deriving (Eq, Show)

-- | Frame generation arguments: @tag:u8 ...@ with tag 0 AES
-- (@len:u8@), 1 EC (curve bytes), 2 RSA (@bits:u64be exp:u64be@),
-- 3 ML-KEM (@alg:u16be@), 4 opaque secret bytes (@len:u8@), 5 DSA
-- parameter sizes (@L:u16be N:u16be@), 6 DSA keypair domain
-- parameters (@len:u32be DER@), 7 Edwards keypair curve name
-- (curve bytes), 8 ML-DSA parameter-set id (@ckp:u16be@),
-- 9 SLH-DSA parameter-set id (@ckp:u16be@), 10 DH keypair domain
-- parameters (@len:u32be DER@), 11 odd-parity secret bytes
-- (@len:u8@: DES/DES2/CDMF set parity per FIPS 46-3), 12
-- TLS/SSL3 pre-master (@major:u8 minor:u8@, fixed 48 bytes),
-- 13 WTLS pre-master (@ver:u8 len:u8@), 14 PBKD2 derived key
-- (@len:u16be@: the shared ceiling exceeds one byte), 15
-- Montgomery keypair curve name (curve bytes), 16 PBE derived
-- key (@len:u8@: fixed 16\/24 widths).
encodeGenArgs :: GenArgs -> ByteString
encodeGenArgs args = case args of
  GenAes n -> BS.singleton 0 <> BS.singleton (fromIntegral n)
  GenEc curve -> BS.singleton 1 <> curve
  GenRsa bits e -> BS.singleton 2 <> u64be (fromIntegral bits) <> u64be (fromIntegral e)
  GenMlKem alg -> BS.singleton 3 <> BS.pack
    [fromIntegral (alg `div` 256), fromIntegral (alg `mod` 256)]
  GenBytes n -> BS.singleton 4 <> BS.singleton (fromIntegral n)
  GenDsaParams l n -> BS.singleton 5 <> u16be l <> u16be n
  GenDsaKeypair der -> BS.singleton 6 <> u32be (BS.length der) <> der
  GenEdwardsKeypair curve -> BS.singleton 7 <> curve
  GenMontgomeryKeypair curve -> BS.singleton 15 <> curve
  GenMlDsa ckp -> BS.singleton 8 <> u16be ckp
  GenSlhDsa ckp -> BS.singleton 9 <> u16be ckp
  GenDhKeypair der -> BS.singleton 10 <> u32be (BS.length der) <> der
  GenParityBytes n -> BS.singleton 11 <> BS.singleton (fromIntegral n)
  GenTlsPremaster major minor -> BS.singleton 12 <> BS.pack [major, minor]
  GenWtlsPremaster ver n -> BS.singleton 13 <> BS.pack [ver, fromIntegral n]
  GenPbkd2 n -> BS.singleton 14 <> u16be n
  GenPbe n -> BS.singleton 16 <> BS.singleton (fromIntegral n)

-- | Parse framed generation arguments. Short frames, unknown tags
-- and trailing bytes all fail.
decodeGenArgs :: ByteString -> Maybe GenArgs
decodeGenArgs bs = case BS.uncons bs of
  Just (0, rest) -> case BS.unpack rest of
    [n] -> Just (GenAes (fromIntegral n))
    _ -> Nothing
  Just (1, curve)
    | not (BS.null curve) -> Just (GenEc curve)
    | otherwise -> Nothing
  Just (2, rest)
    | BS.length rest == 16 ->
        let (bBits, bExp) = BS.splitAt 8 rest
        in Just (GenRsa (fromInteger (foldBE bBits)) (foldBE bExp))
    | otherwise -> Nothing
  Just (3, rest) -> case BS.unpack rest of
    [hi, lo] -> Just (GenMlKem (fromIntegral hi * 256 + fromIntegral lo))
    _ -> Nothing
  Just (4, rest) -> case BS.unpack rest of
    [n] -> Just (GenBytes (fromIntegral n))
    _ -> Nothing
  Just (5, rest) -> case BS.unpack rest of
    [lhi, llo, nhi, nlo] -> Just (GenDsaParams
      (fromIntegral lhi * 256 + fromIntegral llo)
      (fromIntegral nhi * 256 + fromIntegral nlo))
    _ -> Nothing
  Just (6, rest)
    | BS.length rest >= 4 ->
        let (bLen, der) = BS.splitAt 4 rest
            n = fromInteger (foldBE bLen)
        in if BS.length der == n && n > 0
          then Just (GenDsaKeypair der)
          else Nothing
    | otherwise -> Nothing
  Just (7, curve)
    | not (BS.null curve) -> Just (GenEdwardsKeypair curve)
    | otherwise -> Nothing
  Just (8, rest) -> case BS.unpack rest of
    [hi, lo] -> Just (GenMlDsa (fromIntegral hi * 256 + fromIntegral lo))
    _ -> Nothing
  Just (9, rest) -> case BS.unpack rest of
    [hi, lo] -> Just (GenSlhDsa (fromIntegral hi * 256 + fromIntegral lo))
    _ -> Nothing
  Just (10, rest)
    | BS.length rest >= 4 ->
        let (bLen, der) = BS.splitAt 4 rest
            n = fromInteger (foldBE bLen)
        in if BS.length der == n && n > 0
          then Just (GenDhKeypair der)
          else Nothing
    | otherwise -> Nothing
  Just (11, rest) -> case BS.unpack rest of
    [n] -> Just (GenParityBytes (fromIntegral n))
    _ -> Nothing
  Just (12, rest) -> case BS.unpack rest of
    [major, minor] -> Just (GenTlsPremaster major minor)
    _ -> Nothing
  Just (13, rest) -> case BS.unpack rest of
    [ver, n] -> Just (GenWtlsPremaster ver (fromIntegral n))
    _ -> Nothing
  Just (14, rest) -> case BS.unpack rest of
    [hi, lo] -> Just (GenPbkd2 (fromIntegral hi * 256 + fromIntegral lo))
    _ -> Nothing
  Just (16, rest) -> case BS.unpack rest of
    [n] -> Just (GenPbe (fromIntegral n))
    _ -> Nothing
  Just (15, curve)
    | not (BS.null curve) -> Just (GenMontgomeryKeypair curve)
    | otherwise -> Nothing
  _ -> Nothing

-- | 2-byte big-endian framing.
u16be :: Int -> ByteString
u16be n = BS.pack
  [ fromIntegral (n `div` 256 `mod` 256)
  , fromIntegral (n `mod` 256)
  ]

-- | 4-byte big-endian framing.
u32be :: Int -> ByteString
u32be n = BS.pack
  [ fromIntegral (n `div` 16777216 `mod` 256)
  , fromIntegral (n `div` 65536 `mod` 256)
  , fromIntegral (n `div` 256 `mod` 256)
  , fromIntegral (n `mod` 256)
  ]

-- | 8-byte big-endian framing.
u64be :: Int -> ByteString
u64be n = BS.pack
  [ fromIntegral (n `div` 72057594037927936 `mod` 256)
  , fromIntegral (n `div` 281474976710656 `mod` 256)
  , fromIntegral (n `div` 1099511627776 `mod` 256)
  , fromIntegral (n `div` 4294967296 `mod` 256)
  , fromIntegral (n `div` 16777216 `mod` 256)
  , fromIntegral (n `div` 65536 `mod` 256)
  , fromIntegral (n `div` 256 `mod` 256)
  , fromIntegral (n `mod` 256)
  ]

-- | Big-endian fold computed in 'Integer' so large values never wrap.
foldBE :: ByteString -> Integer
foldBE = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | Frame a keygen answer: @privLen:u32be priv pub?@. A single key
-- carries no public half; a pair always carries both.
encodeKeyPair :: ByteString -> Maybe ByteString -> ByteString
encodeKeyPair priv mPub =
  let n = BS.length priv
  in BS.pack
    [ fromIntegral (n `div` 16777216 `mod` 256)
    , fromIntegral (n `div` 65536 `mod` 256)
    , fromIntegral (n `div` 256 `mod` 256)
    , fromIntegral (n `mod` 256)
    ] <> priv <> maybe BS.empty id mPub

-- | Parse a framed keygen answer. A short length prefix, a length
-- overrun, or a length that lies all fail.
decodeKeyPair :: ByteString -> Maybe (ByteString, Maybe ByteString)
decodeKeyPair bs
  | BS.length bs < 4 = Nothing
  | otherwise =
      let (bLen, rest) = BS.splitAt 4 bs
          n = fromInteger (foldBE bLen)
      in if BS.length rest < n
        then Nothing
        else let (priv, pub) = BS.splitAt n rest
             in Just (priv, if BS.null pub then Nothing else Just pub)

-- | Frame authenticated-wrap parameters: @ivLen:u32be iv aad@.
encodeWrapParams :: ByteString -> ByteString -> ByteString
encodeWrapParams iv aad =
  let n = BS.length iv
  in BS.pack
    [ fromIntegral (n `div` 16777216 `mod` 256)
    , fromIntegral (n `div` 65536 `mod` 256)
    , fromIntegral (n `div` 256 `mod` 256)
    , fromIntegral (n `mod` 256)
    ] <> iv <> aad

-- | Parse framed authenticated-wrap parameters. A short prefix or
-- an overrun length fails.
decodeWrapParams :: ByteString -> Maybe (ByteString, ByteString)
decodeWrapParams bs
  | BS.length bs < 4 = Nothing
  | otherwise =
      let (bLen, rest) = BS.splitAt 4 bs
          n = fromInteger (foldBE bLen)
      in if BS.length rest < n
        then Nothing
        else Just (BS.splitAt n rest)

-- ---------------------------------------------------------------------------
-- Wrap padding
-- ---------------------------------------------------------------------------

-- | Pad one wrap payload with PKCS#7. This mirrors
-- 'Haskoki.Operation.Cipher.pkcs7Pad' exactly (duplicated because
-- that module plans cipher slots while this one must stay importable
-- from the init policy without a cycle); 'KeyManagementSpec'
-- cross-checks both on every sample.
padPkcs7 :: Int -> ByteString -> Maybe ByteString
padPkcs7 block bs
  | block < 1 || block > 255 = Nothing
  | otherwise = Just (bs <> BS.replicate n (fromIntegral n))
  where
    n = block - (BS.length bs `mod` block)

-- | Strip PKCS#7 padding, checking the framing strictly. Mirrors
-- 'Haskoki.Operation.Cipher.pkcs7Unpad' exactly (see 'padPkcs7').
unpadPkcs7 :: Int -> ByteString -> Maybe ByteString
unpadPkcs7 block bs = do
  guard (block >= 1 && block <= 255)
  let len = BS.length bs
  guard (len > 0 && len `mod` block == 0)
  let padByte = BS.index bs (len - 1)
      n = fromIntegral padByte
  guard (n >= 1 && n <= min block len)
  let (plain, pad) = BS.splitAt (len - n) bs
  guard (BS.all (== padByte) pad)
  pure plain

-- ---------------------------------------------------------------------------
-- Key-pair generation
-- ---------------------------------------------------------------------------

-- | Plan key-pair generation: both templates validate fully before
-- any effect plans, so a bad template yields zero objects. ML-KEM,
-- EC, RSA and DSA pair mechanisms (generated ids, resolved by
-- name). Admission gates last (parse-first, mirroring
-- 'Haskoki.Operation.Derive'): mechanism, templates, then the
-- bound check just before the effect.
planGenerateKeyPair
  :: Rules -> Model -> SessionState -> MechanismId
  -> [(AttributeType, AttributeValue)] -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planGenerateKeyPair rules model st mech pubT privT =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 2 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | mech == MechanismId (ckm_ML_KEM_KEY_PAIR_GEN) =
          withPair st mech ckkMlKem pubT privT $ \pubA privA -> do
            alg <- kemAlgOf pubA privA
            pubA' <- kemNoDerive pubT pubA
            privA' <- kemNoDerive privT privA
            let ckp = case alg of
                  512 -> 1 :: Int
                  768 -> 2
                  _ -> 3
                tag = Map.insert AttrKemAlg (ValULong (fromIntegral alg))
                  . Map.insert AttrParameterSet (ValULong (fromIntegral ckp))
            pure (GenMlKem alg, tag pubA', tag privA')
      | mech == ecKeyPairGenMech || mech == ecExtraBitsKeyPairGenMech =
          withPair st mech ckkEc pubT privT $ \pubA privA -> do
            curve <- ecCurveOf pubA privA
            pure (GenEc curve, pubA, privA)
      | mech == rsaKeyPairGenMech =
          withPair st mech ckkRsa pubT privT $ \pubA privA -> do
            bits <- rsaBitsOf pubA privA
            e <- rsaExponentOf pubA privA
            pure (GenRsa bits e, pubA, privA)
      | mech == dsaKeyPairGenMech =
          withPair st mech ckkDsa pubT privT $ \pubA privA -> do
            der <- dsaDomainOf pubA privA
            pure (GenDsaKeypair der, pubA, privA)
      | mech == dhKeyPairGenMech =
          withPair st mech ckkDh pubT privT $ \pubA privA -> do
            der <- dhDomainOf False pubA privA
            pure (GenDhKeypair der, pubA, privA)
      | mech == x9_42DhKeyPairGenMech =
          withPair st mech ckkX9_42Dh pubT privT $ \pubA privA -> do
            der <- dhDomainOf True pubA privA
            pure (GenDhKeypair der, pubA, privA)
      | mech == edwardsKeyPairGenMech =
          withPair st mech ckkEcEdwards pubT privT $ \pubA privA -> do
            curve <- edwardsCurveOf pubA privA
            pure (GenEdwardsKeypair curve, pubA, privA)
      | mech == montgomeryKeyPairGenMech =
          withPair st mech ckkEcMontgomery pubT privT $ \pubA privA -> do
            curve <- montgomeryCurveOf pubA privA
            pure (GenMontgomeryKeypair curve, pubA, privA)
      | mech == mldsaKeyPairGenMech =
          withPair st mech ckkMlDsa pubT privT $ \pubA privA -> do
            ckp <- mldsaSetOf pubA privA
            let tag = Map.insert AttrParameterSet (ValULong (fromIntegral ckp))
            pure (GenMlDsa ckp, tag pubA, tag privA)
      | mech == slhdsaKeyPairGenMech =
          withPair st mech ckkSlhDsa pubT privT $ \pubA privA -> do
            ckp <- slhdsaSetOf pubA privA
            let tag = Map.insert AttrParameterSet (ValULong (fromIntegral ckp))
            pure (GenSlhDsa ckp, tag pubA, tag privA)
      | otherwise =
          Left (KeyDeny CKR_MECHANISM_INVALID
            ("not a key-pair mechanism: " ++ show mech))

-- | Shared pair-template validation: both templates check against
-- their class and the mechanism's key type, then the
-- mechanism-specific arguments resolve (which may normalize the
-- attributes, e.g. the agreed KEM set). Returns the validated
-- pair for the caller to admit and wrap (admission runs
-- after validation).
withPair
  :: SessionState -> MechanismId -> Word64
  -> [(AttributeType, AttributeValue)] -> [(AttributeType, AttributeValue)]
  -> (Map AttributeType AttributeValue -> Map AttributeType AttributeValue
      -> Either KeyDeny (GenArgs, Map AttributeType AttributeValue, Map AttributeType AttributeValue))
  -> Either KeyDeny (PendingWork, CryptoEffect)
withPair st mech wantKey pubT privT argsOf =
  case checkKeyTemplate ckoPublicKey wantKey pubT of
    Left deny -> Left deny
    Right pubA -> case checkKeyTemplate ckoPrivateKey wantKey privT of
      Left deny -> Left deny
      Right privA -> case argsOf pubA privA of
        Left deny -> Left deny
        Right (args, pubA', privA') ->
          Right
            ( PwGeneratePair (pendingFromAttrs st pubA') (pendingFromAttrs st privA')
            , FxGenerateKey mech BS.empty (encodeGenArgs args)
            )

-- | KEM keys never derive (no KEM derive operation exists):
-- an explicit @CKA_DERIVE=true@ refuses inconsistent, and
-- absent (or explicit-false) stamps false — the oracle's
-- derive-false leg reads the value back, and only an explicit
-- false passes (a missing attribute records a deviation).
-- Inspects the RAW template: by tag time 'defaultUsage' has
-- already defaulted the flag true. (Not a forbidden rule: a
-- stored false would poison presence-based re-validation.)
kemNoDerive
  :: [(AttributeType, AttributeValue)] -> Map AttributeType AttributeValue
  -> Either KeyDeny (Map AttributeType AttributeValue)
kemNoDerive raw attrs
  | any (\(t, v) -> t == AttrDerive && v == ValBool True) raw =
      Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        "KEM keys do not derive: CKA_DERIVE must not be true")
  | otherwise = Right (Map.insert AttrDerive (ValBool False) attrs)

-- | The ML-KEM parameter set for a pair: the OASIS keygen
-- input @AttrParameterSet@ (@CKP_ML_KEM_512\/768\/1024@ =
-- 1\/2\/3, the 'mldsaSetOf' precedent) wins when present; the
-- internal @AttrKemAlg@ tag (512\/768\/1024) serves callers
-- that already resolved it; absent everywhere defaults to 768.
-- The private template inherits when absent and must agree
-- when present; a template carrying both must agree with
-- itself.
kemAlgOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny Int
kemAlgOf pubA privA = do
  pubSet <- resolveOne "public" pubA
  privSet <- resolveOne "private" privA
  case (pubSet, privSet) of
    (Just a, Just b)
      | a == b -> Right a
      | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "keypair templates disagree on the KEM parameter set")
    (Just a, Nothing) -> Right a
    (Nothing, Just b) -> Right b
    (Nothing, Nothing) -> Right 768
  where
    resolveOne who attrs = case Map.lookup AttrParameterSet attrs of
      Just (ValULong ckp)
        | ckp `elem` [1, 2, 3] ->
            let alg = [512, 768, 1024] !! fromIntegral (ckp - 1)
            in case Map.lookup AttrKemAlg attrs of
              Nothing -> Right (Just alg)
              Just (ValULong alg')
                | fromIntegral alg' == alg -> Right (Just alg)
                | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                    (who ++ " template KEM set contradicts its parameter set"))
              Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                (who ++ " KEM parameter set is malformed"))
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("unknown ML-KEM parameter set: " ++ show ckp))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        (who ++ " KEM parameter set is malformed"))
      Nothing -> case Map.lookup AttrKemAlg attrs of
        Nothing -> Right Nothing
        Just (ValULong alg)
          | alg `elem` [512, 768, 1024] -> Right (Just (fromIntegral alg))
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              ("unknown KEM parameter set: " ++ show alg))
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          (who ++ " KEM parameter set is malformed"))

-- | The ML-DSA parameter-set id for a pair: the public
-- template's @AttrParameterSet@ (@CKP_ML_DSA_44\/65\/87@ =
-- 1\/2\/3, the OASIS keygen input), which the private template
-- inherits when absent and must agree with when present.
-- Absent everywhere defaults to 65 (the 'kemAlgOf' precedent:
-- the middle set, as KEM defaults 768).
mldsaSetOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny Int
mldsaSetOf pubA privA = case Map.lookup AttrParameterSet pubA of
  Just (ValULong ckp)
    | ckp `elem` [1, 2, 3] -> case Map.lookup AttrParameterSet privA of
        Nothing -> Right (fromIntegral ckp)
        Just (ValULong ckp')
          | ckp' == ckp -> Right (fromIntegral ckp)
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the ML-DSA parameter set")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private ML-DSA parameter set is malformed")
    | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("unknown ML-DSA parameter set: " ++ show ckp))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public ML-DSA parameter set is malformed")
  Nothing -> case Map.lookup AttrParameterSet privA of
    Nothing -> Right 2
    Just (ValULong ckp)
      | ckp `elem` [1, 2, 3] -> Right (fromIntegral ckp)
      | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("unknown ML-DSA parameter set: " ++ show ckp))
    Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      "private ML-DSA parameter set is malformed")

-- | The SLH-DSA parameter-set id for a pair: the public
-- template's @AttrParameterSet@ (@CKP_SLH_DSA_*@ = 1..12, the
-- OASIS keygen input), which the private template inherits
-- when absent and must agree with when present. Absent
-- everywhere defaults to 1 (SLH-DSA-SHA2-128s, the first set
-- and the driver's unscannable-key default).
slhdsaSetOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny Int
slhdsaSetOf pubA privA = case Map.lookup AttrParameterSet pubA of
  Just (ValULong ckp)
    | ckp `elem` [1 .. 12] -> case Map.lookup AttrParameterSet privA of
        Nothing -> Right (fromIntegral ckp)
        Just (ValULong ckp')
          | ckp' == ckp -> Right (fromIntegral ckp)
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the SLH-DSA parameter set")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private SLH-DSA parameter set is malformed")
    | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("unknown SLH-DSA parameter set: " ++ show ckp))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public SLH-DSA parameter set is malformed")
  Nothing -> case Map.lookup AttrParameterSet privA of
    Nothing -> Right 1
    Just (ValULong ckp)
      | ckp `elem` [1 .. 12] -> Right (fromIntegral ckp)
      | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("unknown SLH-DSA parameter set: " ++ show ckp))
    Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      "private SLH-DSA parameter set is malformed")

-- | The EC curve for a pair: @AttrEcParams@ is required in the
-- public template (PKCS#11 names the curve there), the private
-- template inherits it when absent and must agree when present.
-- Every 'Haskoki.Der.curveTable' row executes in the engine set —
-- deliberately maximal (weak sub-224-bit and binary curves ride
-- for oracle coverage, never as a deployment recommendation);
-- anything else is mechanism-invalid, never silently
-- substituted.
ecCurveOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny ByteString
ecCurveOf pubA privA = case Map.lookup AttrEcParams pubA of
  Just (ValBytes curve)
    | curve `elem` [n | (n, _, _) <- curveTable] -> case Map.lookup AttrEcParams privA of
        Nothing -> Right curve
        Just (ValBytes curve')
          | curve' == curve -> Right curve
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the curve")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private EC params are malformed")
    | otherwise -> Left (KeyDeny CKR_MECHANISM_INVALID
        ("unsupported curve: " ++ show curve))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public EC params are malformed")
  Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "EC keypair templates must name the curve")

-- | The served Edwards curve for a pair: the public template's
-- @AttrEcParams@ (an 'edwardsTable' engine name — the wire codec
-- maps caller OIDs to names), which the private template inherits
-- when absent and must agree with when present. Unknown curves
-- (including Weierstrass names — a caller mixing
-- @CKM_EC_KEY_PAIR_GEN@ parameters into the Edwards mechanism)
-- refuse mechanism-invalid (the 'ecCurveOf' precedent).
edwardsCurveOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny ByteString
edwardsCurveOf pubA privA = case Map.lookup AttrEcParams pubA of
  Just (ValBytes curve)
    | curve `elem` [n | (n, _, _, _) <- edwardsTable] -> case Map.lookup AttrEcParams privA of
        Nothing -> Right curve
        Just (ValBytes curve')
          | curve' == curve -> Right curve
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the curve")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private EC params are malformed")
    | otherwise -> Left (KeyDeny CKR_MECHANISM_INVALID
        ("unsupported curve: " ++ show curve))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public EC params are malformed")
  Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "Edwards keypair templates must name the curve")

-- | The served Montgomery curve for a pair: the public template's
-- @AttrEcParams@ (a 'montgomeryTable' engine name — the wire codec
-- maps caller OIDs to names), which the private template inherits
-- when absent and must agree with when present. Unknown curves
-- (including Weierstrass and Edwards names — a caller mixing
-- another mechanism's parameters into the Montgomery mechanism)
-- refuse mechanism-invalid (the 'ecCurveOf' precedent).
montgomeryCurveOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny ByteString
montgomeryCurveOf pubA privA = case Map.lookup AttrEcParams pubA of
  Just (ValBytes curve)
    | curve `elem` [n | (n, _, _) <- montgomeryTable] -> case Map.lookup AttrEcParams privA of
        Nothing -> Right curve
        Just (ValBytes curve')
          | curve' == curve -> Right curve
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the curve")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private EC params are malformed")
    | otherwise -> Left (KeyDeny CKR_MECHANISM_INVALID
        ("unsupported curve: " ++ show curve))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public EC params are malformed")
  Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "Montgomery keypair templates must name the curve")

-- | The RSA public exponent for a pair: the public template's
-- @AttrPublicExponent@ when present (big-endian bytes, must decode
-- to an odd integer >= 3), else the 65537 default. A private
-- exponent must agree when present.
rsaExponentOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny Integer
rsaExponentOf pubA privA = case Map.lookup AttrPublicExponent pubA of
  Just (ValBytes bs) -> case bytesToInteger bs of
    Just e
      | e >= 3 && odd e -> case Map.lookup AttrPublicExponent privA of
          Nothing -> Right e
          Just (ValBytes bs')
            | bytesToInteger bs' == Just e -> Right e
            | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                "keypair templates disagree on the public exponent")
          Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            "private public exponent is malformed")
      | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "public exponent must be odd and >= 3")
    Nothing -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      "public exponent is malformed")
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public exponent is malformed")
  Nothing -> case Map.lookup AttrPublicExponent privA of
    Nothing -> Right 65537
    Just (ValBytes bs) -> case bytesToInteger bs of
      Just e
        | e >= 3 && odd e -> Right e
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            "public exponent must be odd and >= 3")
      Nothing -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        "public exponent is malformed")
    Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      "public exponent is malformed")

-- | Big-endian bytes to an integer; empty input decodes to 0.
bytesToInteger :: ByteString -> Maybe Integer
bytesToInteger bs
  | BS.length bs > 8 = Nothing
  | otherwise = Just (BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 bs)

-- | The RSA modulus size for a pair: @AttrModulusBits@ is required
-- in the public template, the private template inherits it when
-- absent and must agree when present.
rsaBitsOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny Int
rsaBitsOf pubA privA = case Map.lookup AttrModulusBits pubA of
  Just (ValULong bits)
    | bits `elem` [2048, 3072, 4096] -> case Map.lookup AttrModulusBits privA of
        Nothing -> Right (fromIntegral bits)
        Just (ValULong bits')
          | bits' == bits -> Right (fromIntegral bits)
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the modulus size")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private modulus bits are malformed")
    | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("modulus size out of range: " ++ show bits))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public modulus bits are malformed")
  Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "RSA keypair templates must name the modulus size")

-- | The DSA domain parameters for a pair, framed as DER DSS-Parms
-- for the driver. @AttrPrime@\/@AttrSubprime@\/@AttrBase@ are
-- required in the public template (PKCS#11 names the domain there),
-- the private template inherits them when absent and must agree
-- when present. Present-but-unserved @AttrPrimeBits@\/
-- @AttrSubprimeBits@ refuse as inconsistent first (a template
-- whose only size hint is unserved contradicts the mechanism even
-- before the missing-parameters check runs, mirroring 'rsaBitsOf');
-- missing parameters are incomplete; malformed or empty parts are
-- inconsistent. Size bounds are generous ceilings (4096-bit p\/g,
-- 512-bit q) — the backend, not the planner, owns the served-pair
-- policy.
dsaDomainOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny ByteString
dsaDomainOf pubA privA = do
  checkSizeBit AttrPrimeBits [1024, 2048, 3072] pubA
  checkSizeBit AttrPrimeBits [1024, 2048, 3072] privA
  checkSizeBit AttrSubprimeBits [160, 224, 256] pubA
  checkSizeBit AttrSubprimeBits [160, 224, 256] privA
  p <- component AttrPrime pubA privA
  q <- component AttrSubprime pubA privA
  g <- component AttrBase pubA privA
  pure (dsaParamsDer p q g)
  where
    checkSizeBit t served attrs = case Map.lookup t attrs of
      Nothing -> Right ()
      Just (ValULong n)
        | n `elem` served -> Right ()
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DSA size out of range: " ++ show t ++ "=" ++ show n))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("DSA size attribute is malformed: " ++ show t))
    component t pub priv = case Map.lookup t pub of
      Just (ValBytes bs)
        | BS.null bs -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DSA domain parameter is empty: " ++ show t))
        | BS.length bs > bound t -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DSA domain parameter oversized: " ++ show t))
        | otherwise -> case Map.lookup t priv of
            Nothing -> Right bs
            Just (ValBytes bs')
              | bs' == bs -> Right bs
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  "keypair templates disagree on DSA domain parameters")
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "private DSA domain parameter is malformed")
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("DSA domain parameter is malformed: " ++ show t))
      Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
        "DSA keypair templates must carry p, q and g")
    bound AttrSubprime = 64
    bound _ = 512

-- | DH domain parameters from keypair templates: @CKA_PRIME@ and
-- @CKA_BASE@ always, @CKA_SUBPRIME@ exactly for X9.42
-- (@wantQ@). Missing parameters are incomplete; malformed,
-- empty, oversized, disagreeing, or structurally impossible
-- parts are inconsistent, as is a subprime on a PKCS#3
-- template (PKCS#3 has no q). Size hints are checked before
-- the missing-parameters check runs (mirroring
-- 'dsaDomainOf'); the backend, not the planner, owns the
-- served-pair policy.
--
-- The structural floor (NIST SP 800-56A rev. 3 section
-- 5.5.1): the prime carries at least 512 significant bits
-- and the generator sits in @2..p-1@ (X9.42: the subprime
-- in @2..p-1@ too). Values compare leading-zero-blind, so
-- zero-padded degenerates refuse exactly like bare ones.
-- Deeper checks (primality, @q | p-1@, @g^q = 1@) stay with
-- the executing backend, which owns the crypto.
dhDomainOf
  :: Bool
  -> Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny ByteString
dhDomainOf wantQ pubA privA = do
  checkSizeBit AttrPrimeBits [1024, 2048, 3072, 4096] pubA
  checkSizeBit AttrPrimeBits [1024, 2048, 3072, 4096] privA
  checkSizeBit AttrSubprimeBits [160, 224, 256] pubA
  checkSizeBit AttrSubprimeBits [160, 224, 256] privA
  p <- component AttrPrime pubA privA
  g <- component AttrBase pubA privA
  case dhStructural p g of
    Just msg -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT msg)
    Nothing -> pure ()
  case (wantQ, Map.lookup AttrSubprime pubA) of
    (True, _) -> do
      q <- component AttrSubprime pubA privA
      case dhSubprime p q of
        Just msg -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT msg)
        Nothing -> pure (dhParamsDerQ p g q)
    (False, Nothing) -> pure (dhParamsDer p g)
    (False, Just _) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      "PKCS#3 DH domain takes no subprime")
  where
    -- Significant bytes: leading zeros dropped (the empty
    -- encoding is value zero).
    sig :: ByteString -> ByteString
    sig = BS.dropWhile (== 0)
    -- Unsigned big-endian comparison, leading-zero-blind.
    ltBE :: ByteString -> ByteString -> Bool
    ltBE a b = case compare (BS.length a') (BS.length b') of
      LT -> True
      GT -> False
      EQ -> a' < b'
      where
        a' = sig a
        b' = sig b
    -- The (p, g) structural floor: 512 significant prime
    -- bits, @2 <= g < p@. 'Nothing' accepts.
    dhStructural :: ByteString -> ByteString -> Maybe String
    dhStructural p g
      | BS.length (sig p) < 64 =
          Just "DH prime under the 512-bit structural floor"
      | BS.null (sig g) || sig g == BS.singleton 1 || not (ltBE g p) =
          Just "DH generator outside 2 <= g < p"
      | otherwise = Nothing
    -- The X9.42 subprime range: @1 < q < p@. 'Nothing'
    -- accepts.
    dhSubprime :: ByteString -> ByteString -> Maybe String
    dhSubprime p q
      | BS.null (sig q) || sig q == BS.singleton 1 || not (ltBE q p) =
          Just "X9.42 subprime outside 1 < q < p"
      | otherwise = Nothing
    checkSizeBit t served attrs = case Map.lookup t attrs of
      Nothing -> Right ()
      Just (ValULong n)
        | n `elem` served -> Right ()
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DH size out of range: " ++ show t ++ "=" ++ show n))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("DH size attribute is malformed: " ++ show t))
    component t pub priv = case Map.lookup t pub of
      Just (ValBytes bs)
        | BS.null bs -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DH domain parameter is empty: " ++ show t))
        | BS.length bs > bound t -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DH domain parameter oversized: " ++ show t))
        | otherwise -> case Map.lookup t priv of
            Nothing -> Right bs
            Just (ValBytes bs')
              | bs' == bs -> Right bs
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  "keypair templates disagree on DH domain parameters")
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "private DH domain parameter is malformed")
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("DH domain parameter is malformed: " ++ show t))
      Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
        "DH keypair templates must carry the domain parameters")
    bound AttrSubprime = 64
    bound _ = 512

-- ---------------------------------------------------------------------------
-- Table-driven single-key generation (slice 11a sweep)
-- ---------------------------------------------------------------------------

-- | Sweep length shapes: fixed sizes mint the headline length when
-- @CKA_VALUE_LEN@ is absent; discrete and ranged shapes require it.
data KeygenLens
  = KeygenFixed !Int
  | KeygenDiscrete ![Int]
  | KeygenRange !Int !Int
  deriving (Eq, Show)

-- | One sweep row: label (for refusal detail), key type,
-- lengths, and whether the driver sets odd DES parity (FIPS
-- 46-3: DES, DES2, CDMF only).
keygenSweepSpecs :: [(MechanismId, (String, Word64, KeygenLens, Bool))]
keygenSweepSpecs =
  [ (desKeyGenMech, ("DES", ckkDes, KeygenFixed 8, True))
  , (des2KeyGenMech, ("DES2", ckkDes2, KeygenFixed 16, True))
  , (cdmfKeyGenMech, ("CDMF", ckkCdmf, KeygenFixed 8, True))
  , (ideaKeyGenMech, ("IDEA", ckkIdea, KeygenFixed 16, False))
  , (seedKeyGenMech, ("SEED", ckkSeed, KeygenFixed 16, False))
  , (skipjackKeyGenMech, ("SKIPJACK", ckkSkipjack, KeygenFixed 12, False))
  , (batonKeyGenMech, ("BATON", ckkBaton, KeygenFixed 40, False))
  , (juniperKeyGenMech, ("JUNIPER", ckkJuniper, KeygenFixed 40, False))
  , (gost28147KeyGenMech, ("GOST28147", ckkGost28147, KeygenFixed 32, False))
  , (salsa20KeyGenMech, ("SALSA20", ckkSalsa20, KeygenFixed 32, False))
  , (poly1305KeyGenMech, ("POLY1305", ckkPoly1305, KeygenFixed 32, False))
  , (ariaKeyGenMech, ("ARIA", ckkAria, KeygenDiscrete [16, 24, 32], False))
  , (camelliaKeyGenMech, ("CAMELLIA", ckkCamellia, KeygenDiscrete [16, 24, 32], False))
  , (twofishKeyGenMech, ("TWOFISH", ckkTwofish, KeygenDiscrete [16, 24, 32], False))
  , (aesXtsKeyGenMech, ("AES-XTS", ckkAesXts, KeygenDiscrete [32, 64], False))
  , (castKeyGenMech, ("CAST", ckkCast, KeygenRange 1 8, False))
  , (cast3KeyGenMech, ("CAST3", ckkCast3, KeygenRange 1 8, False))
  , (cast128KeyGenMech, ("CAST128", ckkCast128, KeygenRange 1 16, False))
  , (rc2KeyGenMech, ("RC2", ckkRc2, KeygenRange 1 128, False))
  , (rc4KeyGenMech, ("RC4", ckkRc4, KeygenRange 1 255, False))
  , (rc5KeyGenMech, ("RC5", ckkRc5, KeygenRange 1 255, False))
  , (blowfishKeyGenMech, ("BLOWFISH", ckkBlowfish, KeygenRange 4 56, False))
  , (hkdfKeyGenMech, ("HKDF", ckkHkdf, KeygenRange 1 255, False))
  , (sha1KeyGenMech, ("SHA-1-HMAC", ckkSha1Hmac, KeygenRange 1 255, False))
  , (sha224KeyGenMech, ("SHA224-HMAC", ckkSha224Hmac, KeygenRange 1 255, False))
  , (sha256KeyGenMech, ("SHA256-HMAC", ckkSha256Hmac, KeygenRange 1 255, False))
  , (sha384KeyGenMech, ("SHA384-HMAC", ckkSha384Hmac, KeygenRange 1 255, False))
  , (sha512KeyGenMech, ("SHA512-HMAC", ckkSha512Hmac, KeygenRange 1 255, False))
  , (sha512_224KeyGenMech, ("SHA512/224-HMAC", ckkSha512_224Hmac, KeygenRange 1 255, False))
  , (sha512_256KeyGenMech, ("SHA512/256-HMAC", ckkSha512_256Hmac, KeygenRange 1 255, False))
  , (sha512TKeyGenMech, ("SHA512/t-HMAC", ckkSha512THmac, KeygenRange 1 255, False))
  , (sha3_224KeyGenMech, ("SHA3-224-HMAC", ckkSha3_224Hmac, KeygenRange 1 255, False))
  , (sha3_256KeyGenMech, ("SHA3-256-HMAC", ckkSha3_256Hmac, KeygenRange 1 255, False))
  , (sha3_384KeyGenMech, ("SHA3-384-HMAC", ckkSha3_384Hmac, KeygenRange 1 255, False))
  , (sha3_512KeyGenMech, ("SHA3-512-HMAC", ckkSha3_512Hmac, KeygenRange 1 255, False))
  , (blake2b160KeyGenMech, ("BLAKE2B-160-HMAC", ckkBlake2b160Hmac, KeygenRange 1 255, False))
  , (blake2b256KeyGenMech, ("BLAKE2B-256-HMAC", ckkBlake2b256Hmac, KeygenRange 1 255, False))
  , (blake2b384KeyGenMech, ("BLAKE2B-384-HMAC", ckkBlake2b384Hmac, KeygenRange 1 255, False))
  , (blake2b512KeyGenMech, ("BLAKE2B-512-HMAC", ckkBlake2b512Hmac, KeygenRange 1 255, False))
  ]

-- | Plan one table-driven keygen: the template check fixes the
-- class and key type, then the shape admits the length (fixed
-- sizes default when absent, anything else needs @CKA_VALUE_LEN@).
planSweepKeygen
  :: SessionState -> MechanismId -> String -> Word64 -> KeygenLens -> Bool
  -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (PendingWork, CryptoEffect)
planSweepKeygen st mech label kt lens parity tmpl =
  case checkKeyTemplate ckoSecretKey kt tmpl of
    Left deny -> Left deny
    Right attrs -> case Map.lookup AttrValueLen attrs of
      Just (ValULong n)
        | lenOk lens (fromIntegral n) ->
            Right (effect attrs (fromIntegral n))
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            (label ++ " length must be " ++ lenDesc lens ++ ": " ++ show n))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        (label ++ " value length is malformed"))
      Nothing -> case lens of
        KeygenFixed d -> Right (effect attrs d)
        _ -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
          (label ++ " keygen needs CKA_VALUE_LEN"))
  where
    effect attrs n =
      ( PwGenerateKey (pendingFromAttrs st attrs)
      , FxGenerateKey mech BS.empty (encodeGenArgs (args n))
      )
    args n
      | parity = GenParityBytes n
      | otherwise = GenBytes n

-- | Admit one sweep length (bytes) against its shape.
lenOk :: KeygenLens -> Int -> Bool
lenOk (KeygenFixed d) n = n == d
lenOk (KeygenDiscrete ns) n = n `elem` ns
lenOk (KeygenRange lo hi) n = n >= lo && n <= hi

-- | Refusal detail for one sweep shape.
lenDesc :: KeygenLens -> String
lenDesc (KeygenFixed d) = show d ++ " bytes"
lenDesc (KeygenDiscrete ns) = "one of " ++ show ns ++ " bytes"
lenDesc (KeygenRange lo hi) = show lo ++ " to " ++ show hi ++ " bytes"

-- | Plan a TLS/SSL3 pre-master keygen: the 2-byte @CK_VERSION@
-- parameter is required and its bytes lead the 48-byte generic
-- secret. A missing length defaults to 48; the validated params
-- ride the effect so async replays reproduce the version.
planTlsPremaster
  :: SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (PendingWork, CryptoEffect)
planTlsPremaster st mech params tmpl = case BS.unpack params of
  [major, minor] -> case checkKeyTemplate ckoSecretKey ckkGenericSecret tmpl of
    Left deny -> Left deny
    Right attrs -> case Map.lookup AttrValueLen attrs of
      Just (ValULong n)
        | n == 48 -> Right (effect attrs major minor)
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("pre-master length must be 48 bytes: " ++ show n))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        "pre-master value length is malformed")
      Nothing -> Right (effect attrs major minor)
  _ -> Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
    "TLS/SSL3 pre-master needs a 2-byte CK_VERSION")
  where
    effect attrs major minor =
      ( PwGenerateKey (pendingFromAttrs st attrs)
      , FxGenerateKey mech params (encodeGenArgs (GenTlsPremaster major minor))
      )

-- | Plan a WTLS pre-master keygen: the 1-byte version parameter
-- is required and leads a variable-length (20-255 byte) generic
-- secret. The validated params ride the effect for replays.
planWtlsPremaster
  :: SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (PendingWork, CryptoEffect)
planWtlsPremaster st mech params tmpl = case BS.unpack params of
  [ver] -> case checkKeyTemplate ckoSecretKey ckkGenericSecret tmpl of
    Left deny -> Left deny
    Right attrs -> case Map.lookup AttrValueLen attrs of
      Just (ValULong n)
        | n >= 20 && n <= 255 -> Right (effect attrs ver (fromIntegral n))
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("WTLS pre-master length must be 20 to 255 bytes: " ++ show n))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        "WTLS pre-master value length is malformed")
      Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
        "WTLS pre-master keygen needs CKA_VALUE_LEN")
  _ -> Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
    "WTLS pre-master needs a 1-byte version")
  where
    effect attrs ver n =
      ( PwGenerateKey (pendingFromAttrs st attrs)
      , FxGenerateKey mech params (encodeGenArgs (GenWtlsPremaster ver n))
      )

-- | Plan a PBKD2 keygen: the @pbkd2-params\/2@ frame (PRF code,
-- iterations, salt, inline password) is required and validated
-- before the template; the derived length is required and checked
-- against the target key type's domain (generic-secret: 1 to the
-- shared ceiling; AES: 16\/24\/32; DES3: 24; XTS: 32\/64 — the
-- unwrap coherence table). Unlisted target types refuse closed:
-- minting an unknown fixed-length type would poison the object
-- store. The validated frame rides the effect so async replays
-- reproduce the derived material bit-for-bit.
planPbkd2Gen
  :: SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (PendingWork, CryptoEffect)
planPbkd2Gen st mech params tmpl = case decodePbkd2Params params of
  Nothing -> Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
    "PBKD2 keygen needs a pbkd2-params/2 frame")
  Just (_, iters, _, _)
    | iters < 1 || iters > maxPbkd2Iters -> Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
        ("PBKD2 iterations must be 1 to " ++ show maxPbkd2Iters ++ ": " ++ show iters))
    | otherwise -> case targetKey of
        Nothing -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("PBKD2 target key type is not served: " ++ show targetRaw))
        Just wantKey -> case checkKeyTemplate ckoSecretKey wantKey tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | lenOk wantKey n -> Right (effect attrs (fromIntegral n))
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("PBKD2 length " ++ show n ++ " is outside " ++ lenDesc wantKey))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "PBKD2 value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "PBKD2 keygen needs CKA_VALUE_LEN")
  where
    targetRaw = lookup AttrKeyType tmpl
    -- Absent defaults to generic-secret (the strict check stamps
    -- it); listed fixed types dispatch to their own strict check
    -- (class, generated rules, usage defaults); anything else —
    -- including malformed shapes — refuses closed.
    targetKey = case targetRaw of
      Nothing -> Just ckkGenericSecret
      Just (ValULong k)
        | k == ckkGenericSecret -> Just ckkGenericSecret
        | k == ckkAes -> Just ckkAes
        | k == ckkDes3 -> Just ckkDes3
        | k == ckkAesXts -> Just ckkAesXts
        | otherwise -> Nothing
      Just _ -> Nothing
    lenOk wantKey n
      | wantKey == ckkAes = n `elem` [16, 24, 32]
      | wantKey == ckkDes3 = n == 24
      | wantKey == ckkAesXts = n `elem` [32, 64]
      | otherwise = n >= 1 && n <= fromIntegral pbkd2KeygenMaxBytes
    lenDesc wantKey
      | wantKey == ckkAes = "the AES 16/24/32 domain"
      | wantKey == ckkDes3 = "the DES3 24-byte domain"
      | wantKey == ckkAesXts = "the XTS 32/64 domain"
      | otherwise = "1 to " ++ show pbkd2KeygenMaxBytes ++ " bytes"
    effect attrs n =
      ( PwGenerateKey (pendingFromAttrs st attrs)
      , FxGenerateKey mech params (encodeGenArgs (GenPbkd2 n))
      )

-- | Plan a PBE keygen: the @pbe-params\/1@ frame (iterations,
-- password, salt) is required and validated before the
-- template; the key type and length are fixed per row (DES3:
-- 24 bytes; DES2: 16 bytes) with a DES3-keygen-style default
-- when @CKA_VALUE_LEN@ is absent. The validated frame rides
-- the effect so async replays reproduce the key and IV
-- bit-for-bit.
planPbeGen
  :: SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (PendingWork, CryptoEffect)
planPbeGen st mech params tmpl = case pbeRecipeFor mech of
  Nothing -> Left (KeyDeny CKR_MECHANISM_INVALID
    "PBE keygen needs a PBE mechanism")
  Just r
    | not (pbeParamsValid r params) -> Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
        "PBE keygen needs a valid pbe-params/1 frame")
    | otherwise -> case checkKeyTemplate ckoSecretKey wantKey tmpl of
        Left deny -> Left deny
        Right attrs -> case Map.lookup AttrValueLen attrs of
          Just (ValULong n)
            | fromIntegral n == keyLen -> Right (effect attrs)
            | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                ("PBE length must be " ++ show keyLen ++ " bytes: " ++ show n))
          Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            "PBE value length is malformed")
          Nothing -> Right (effect attrs)
    where
      wantKey = case pbeKind r of
        PbeDes3 -> ckkDes3
        PbeDes2 -> ckkDes2
      keyLen = pbeKeyLen (pbeKind r)
      effect attrs =
        ( PwGenerateKeyIv (pendingFromAttrs st attrs) keyLen
        , FxGenerateKey mech params (encodeGenArgs (GenPbe keyLen))
        )

-- ---------------------------------------------------------------------------
-- Single-key generation
-- ---------------------------------------------------------------------------

-- | Plan single-key generation: AES takes a 128\/192\/256-bit
-- length via @AttrValueLen@ (bytes); HOTP takes any length in the
-- recipe's 16-64 byte window; the sweep table serves the fixed,
-- discrete and ranged symmetric keygens; DSA and X9.42 DH
-- parameter generation take the @(L, N)@ size pair via
-- @AttrPrimeBits@ (required) and @AttrSubprimeBits@ (defaulted
-- for DSA, required for X9.42 DH) and complete one pending
-- domain-parameters object. The driver answer completes one
-- pending object. Admission gates last (parse-first): mechanism,
-- template, then the bound check just before the effect.
planGenerateKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planGenerateKey rules model st mech params tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      -- Only the pre-master keygens (the client version),
      -- PBKD2 (the v2 frame), and PBE (the v1 frame) take
      -- mechanism parameters; every other keygen refuses
      -- params.
      | not (BS.null params)
      , mech /= tlsPremasterKeyGenMech
      , mech /= ssl3PremasterKeyGenMech
      , mech /= wtlsPremasterKeyGenMech
      , mech /= pbkd2KeyGenMech
      , mech /= pbeDes3KeyGenMech
      , mech /= pbeDes2KeyGenMech =
          Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
            "keygen takes no mechanism params")
      | mech == tlsPremasterKeyGenMech = planTlsPremaster st mech params tmpl
      | mech == ssl3PremasterKeyGenMech = planTlsPremaster st mech params tmpl
      | mech == wtlsPremasterKeyGenMech = planWtlsPremaster st mech params tmpl
      | mech == pbkd2KeyGenMech = planPbkd2Gen st mech params tmpl
      | mech == pbeDes3KeyGenMech = planPbeGen st mech params tmpl
      | mech == pbeDes2KeyGenMech = planPbeGen st mech params tmpl
      | mech == dsaParameterGenMech =
          case checkKeyTemplate ckoDomainParameters ckkDsa tmpl of
          Left deny -> Left deny
          Right attrs -> case dsaParamSizes attrs of
            Left deny -> Left deny
            Right (l, n) -> Right
              ( PwGenerateKey (pendingFromAttrs st attrs)
              , FxGenerateKey mech BS.empty (encodeGenArgs (GenDsaParams l n))
              )
      -- X9.42 DH parameter generation frames the same FIPS
      -- 186-4 (L, N) pair as DSA (the provider's DH paramgen
      -- emits P+G only, no Q in any mode, so the driver runs
      -- the DSA paramgen entry point and the (P, Q, G) triple
      -- publishes as X9.42 DH domain parameters — the same
      -- FIPS 186 math, the same DER DSS-Parms framing the
      -- finisher stamps).
      | mech == x9_42DhParameterGenMech =
          case checkKeyTemplate ckoDomainParameters ckkX9_42Dh tmpl of
          Left deny -> Left deny
          Right attrs -> case dhParamSizes attrs of
            Left deny -> Left deny
            Right (l, n) -> Right
              ( PwGenerateKey (pendingFromAttrs st attrs)
              , FxGenerateKey mech BS.empty (encodeGenArgs (GenDsaParams l n))
              )
      -- DH PKCS parameter generation frames the same FIPS 186-4
      -- (L, N) pair as X9.42 (same driver entry point, same DER
      -- DSS-Parms framing), published as PKCS#3 DH domain
      -- parameters — but the subprime size defaults from L (the
      -- oracle sends CKA_PRIME_BITS only and expects CKR_OK).
      | mech == dhPkcsParameterGenMech =
          case checkKeyTemplate ckoDomainParameters ckkDh tmpl of
          Left deny -> Left deny
          Right attrs -> case dhPkcsParamSizes attrs of
            Left deny -> Left deny
            Right (l, n) -> Right
              ( PwGenerateKey (pendingFromAttrs st attrs)
              , FxGenerateKey mech BS.empty (encodeGenArgs (GenDsaParams l n))
              )
      | mech == aesKeyGenMech = case checkKeyTemplate ckoSecretKey ckkAes tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n `elem` [16, 24, 32] -> Right
                  ( PwGenerateKey (pendingFromAttrs st attrs)
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenAes (fromIntegral n)))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("AES length must be 16, 24 or 32 bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "AES value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "AES keygen needs CKA_VALUE_LEN")
      | mech == des3KeyGenMech = case checkKeyTemplate ckoSecretKey ckkDes3 tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n `elem` [16, 24] -> Right
                  ( PwGenerateKey (pendingFromAttrs st attrs)
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenBytes (fromIntegral n)))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("DES3 length must be 16 or 24 bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "DES3 value length is malformed")
            -- A missing length mints three-key (24 bytes): the
            -- mechanism's headline size (16 selects the two-key
            -- variant explicitly). Fixed-size keygen defaults where
            -- the size is natural; AES keeps its required length.
            Nothing -> Right
              ( PwGenerateKey (pendingFromAttrs st attrs)
              , FxGenerateKey mech BS.empty (encodeGenArgs (GenBytes 24))
              )
      | mech == hotpKeyGenMech = case checkKeyTemplate ckoSecretKey ckkHotp tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n >= fromIntegral hotpKeygenMinBytes && n <= fromIntegral hotpKeygenMaxBytes -> Right
                  ( PwGenerateKey (pendingFromAttrs st attrs)
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenBytes (fromIntegral n)))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("HOTP length must be " ++ show hotpKeygenMinBytes ++ " to "
                    ++ show hotpKeygenMaxBytes ++ " bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "HOTP value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "HOTP keygen needs CKA_VALUE_LEN")
      -- BLAKE2B-512 HMAC keys mint at the digest width only: the
      -- per-width keygen split (160\/256\/384\/512) exists to fix
      -- the size, so any other length is inconsistent and a
      -- missing length is incomplete (the HOTP explicit-length
      -- precedent, not the DES3 default).
      -- Table-driven sweep (slice 11a): one arm serves every
      -- fixed, discrete and ranged symmetric keygen (HMAC keygens
      -- take a VALUE_LEN-sized key per the standard, so the old
      -- exact-64 BLAKE2B-512 arm moved into the table).
      | Just (label, kt, lens, parity) <- lookup mech keygenSweepSpecs =
          planSweepKeygen st mech label kt lens parity tmpl
      -- ChaCha20 keys mint at 256 bits only: the single-width
      -- keygen fixes the size, so any other length is
      -- inconsistent and a missing length is incomplete (the
      -- HOTP explicit-length precedent, not the DES3 default).
      | mech == chacha20KeyGenMech = case checkKeyTemplate ckoSecretKey ckkChacha20 tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n == 32 -> Right
                  ( PwGenerateKey (pendingFromAttrs st attrs)
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenBytes 32))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("ChaCha20 length must be 32 bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "ChaCha20 value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "ChaCha20 keygen needs CKA_VALUE_LEN")
      | mech == genericSecretKeyGenMech =
          case checkKeyTemplate ckoSecretKey ckkGenericSecret tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n >= fromIntegral genericSecretKeygenMinBytes && n <= fromIntegral genericSecretKeygenMaxBytes -> Right
                  ( PwGenerateKey (pendingFromAttrs st attrs)
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenBytes (fromIntegral n)))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("generic-secret length must be " ++ show genericSecretKeygenMinBytes ++ " to "
                    ++ show genericSecretKeygenMaxBytes ++ " bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "generic-secret value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "generic-secret keygen needs CKA_VALUE_LEN")
      | otherwise =
          Left (KeyDeny CKR_MECHANISM_INVALID
            ("not a key mechanism: " ++ show mech))

-- | The DSA @(L, N)@ size pair for parameter generation:
-- @AttrPrimeBits@ is required, @AttrSubprimeBits@ defaults per L
-- (@{1024: 160, 2048: 256, 3072: 256}@). Served pairs are the FIPS
-- 186-4 (L, N) set the backends approve — (1024, 160), (2048,
-- 224), (2048, 256), (3072, 256) — anything else is inconsistent,
-- mirroring 'rsaBitsOf' (unserved keygen sizes refuse as
-- inconsistent, never silently substituted). Shared by DSA and
-- X9.42 DH parameter generation (the same FIPS 186 math); the
-- label names the mechanism in refusal strings. A missing
-- @CKA_SUBPRIME_BITS@ defaults per L for DSA (the headline
-- sizes) but is incomplete for X9.42 DH (the oracle requires
-- it: @test_parameter_gen_rejects_missing_subprime_bits@).
fips186ParamSizes
  :: String -> Bool -> Map AttributeType AttributeValue -> Either KeyDeny (Int, Int)
fips186ParamSizes label requireSub attrs = case Map.lookup AttrPrimeBits attrs of
  Just (ValULong l)
    | l == 1024 || l == 2048 || l == 3072 -> case Map.lookup AttrSubprimeBits attrs of
        Nothing
          | requireSub -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              (label ++ " parameter generation needs CKA_SUBPRIME_BITS"))
          | otherwise -> Right (fromIntegral l, dflt (fromIntegral l))
        Just (ValULong n)
          | (fromIntegral l, fromIntegral n) `elem` served ->
              Right (fromIntegral l, fromIntegral n)
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              (label ++ " (L, N) pair out of range: " ++ show (l, n)))
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          (label ++ " subprime bits are malformed"))
    | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        (label ++ " prime size out of range: " ++ show l))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    (label ++ " prime bits are malformed"))
  Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    (label ++ " parameter generation needs CKA_PRIME_BITS"))
  where
    served = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
    dflt 1024 = 160
    dflt 2048 = 256
    dflt _ = 256

dsaParamSizes :: Map AttributeType AttributeValue -> Either KeyDeny (Int, Int)
dsaParamSizes = fips186ParamSizes "DSA" False

dhParamSizes :: Map AttributeType AttributeValue -> Either KeyDeny (Int, Int)
dhParamSizes = fips186ParamSizes "X9.42 DH" True

dhPkcsParamSizes :: Map AttributeType AttributeValue -> Either KeyDeny (Int, Int)
dhPkcsParamSizes = fips186ParamSizes "DH PKCS" False

-- ---------------------------------------------------------------------------
-- Wrap and unwrap
-- ---------------------------------------------------------------------------

-- | Resolve a wrapping key: the handle resolves to a visible object
-- carrying the required usage mark and stored material. Every
-- caller is an AES-CBC wrap/unwrap path, so the key must be an AES
-- secret key; anything else (EC/RSA halves, generic secrets) is a
-- key-type refusal, never a silent coercion of foreign material.
withWrappingKey
  :: Model -> SessionState -> AttributeType -> String -> ExternalHandle
  -> Either KeyDeny (ObjectId, ByteString)
withWrappingKey model st usage label h = case resolveHandle model h of
  Nothing -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
    "unknown or destroyed wrapping-key handle")
  Just ost
    | not (objectVisible st ost) -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
        "wrapping key not visible in this session")
    | Map.lookup usage (osAttrs ost) /= Just (ValBool True) ->
        Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
          ("wrapping key does not permit " ++ label))
    | Map.lookup AttrClass (osAttrs ost) /= Just (ValULong ckoSecretKey) ||
      Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkAes) ->
        Left (KeyDeny (if usage == AttrWrap
                        then CKR_WRAPPING_KEY_TYPE_INCONSISTENT
                        else CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)
          ("wrapping key is not an AES secret key: " ++ label))
    | otherwise -> case keyBytesOf ost of
        Just mat -> Right (osId ost, mat)
        Nothing -> Left (KeyDeny CKR_GENERAL_ERROR
          "wrapping key lacks material")

-- | Modulus byte width of an RSA wrapping key: the stored DER
-- parses first (authoritative — the same parser that stamps
-- keygen components), the stamped @CKA_MODULUS@ second. The DER
-- integers parse minimal, and a real modulus always sets its top
-- bit, so the parsed length is the modulus width.
rsaModulusBytes :: ObjectState -> Maybe Int
rsaModulusBytes ost =
  case keyBytesOf ost of
    Just der -> case parseRsaPublic der of
      Just (n, _) -> Just (BS.length n)
      Nothing -> case parseRsaPrivate der of
        Just crt -> Just (BS.length (crtN crt))
        Nothing -> fromAttr
    Nothing -> fromAttr
  where
    fromAttr = case Map.lookup AttrModulus (osAttrs ost) of
      Just (ValBytes n) ->
        let stripped = BS.dropWhile (== 0) n
        in if BS.null stripped then Nothing else Just (BS.length stripped)
      _ -> Nothing

-- | Resolve an RSA wrapping key: the handle resolves to a visible
-- RSA object of the required half (public for wrapping, private
-- for unwrapping) carrying the required usage mark and modulus
-- material. Answers the object id and the modulus byte width the
-- length checks and the blob length derive from. Anything else is
-- a key-type refusal, never a silent coercion.
withRsaWrappingKey
  :: Model -> SessionState -> AttributeType -> String -> Word64 -> ExternalHandle
  -> Either KeyDeny (ObjectId, Int)
withRsaWrappingKey model st usage label wantClass h =
  case resolveHandle model h of
    Nothing -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
      "unknown or destroyed wrapping-key handle")
    Just ost
      | not (objectVisible st ost) -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
          "wrapping key not visible in this session")
      | Map.lookup usage (osAttrs ost) /= Just (ValBool True) ->
          Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
            ("wrapping key does not permit " ++ label))
      | Map.lookup AttrClass (osAttrs ost) /= Just (ValULong wantClass) ||
        Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkRsa) ->
          Left (KeyDeny (if usage == AttrWrap
                          then CKR_WRAPPING_KEY_TYPE_INCONSISTENT
                          else CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)
            ("wrapping key is not an RSA key half: " ++ label))
      | otherwise -> case rsaModulusBytes ost of
          Just k -> Right (osId ost, k)
          Nothing -> Left (KeyDeny CKR_GENERAL_ERROR
            "wrapping key lacks modulus material")

-- | Resolve a wrap target: the handle resolves to a visible
-- extractable object carrying stored material.
withWrapTarget
  :: Model -> SessionState -> ExternalHandle
  -> Either KeyDeny ByteString
withWrapTarget model st h = case resolveHandle model h of
  Nothing -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
    "unknown or destroyed target handle")
  Just ost
    | not (objectVisible st ost) -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
        "target not visible in this session")
    | Map.lookup AttrExtractable (osAttrs ost) /= Just (ValBool True) ->
        Left (KeyDeny CKR_KEY_UNEXTRACTABLE "target is not extractable")
    | otherwise -> case keyBytesOf ost of
        Just mat -> Right mat
        Nothing -> Left (KeyDeny CKR_KEY_NOT_WRAPPABLE
          "target carries no key material")

-- | Plan one wrap: AES-CBC pads through 'planAesWrapKey', the
-- AES key-wrap rows expand through 'planAesKwWrapKey', the RSA
-- mechanisms travel raw through 'planRsaWrapKey'.
planWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planWrapKey model st mech params wrapH targetH intent
  | mech == aesCbcMech = planAesWrapKey model st mech params wrapH targetH intent
  | mech == aesKwMech || mech == aesKwPadMech || mech == aesKwpMech =
      planAesKwWrapKey model st mech params wrapH targetH intent
  | mech == rsaPkcsMech || mech == rsaOaepMech || mech == rsaX509Mech =
      planRsaWrapKey model st mech params wrapH targetH intent
  | otherwise =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))

-- | Padding overhead per RSA wrap mechanism: v1.5 takes empty
-- parameters and 11 bytes; OAEP takes the labeled
-- @oaep-params\/1@ parameters and 2*hLen+2 over the main hash
-- width; X.509 takes empty parameters and zero overhead (raw
-- block). Rejected shapes are argument errors (parse-first).
rsaWrapOverhead :: MechanismId -> ByteString -> Either KeyDeny Int
rsaWrapOverhead mech params
  | mech == rsaPkcsMech = case rsaPkcs1RecipeFor mech of
      Just r | rsaPkcs1ParamsValid r params -> Right 11
      _ -> Left (KeyDeny CKR_ARGUMENTS_BAD
        "RSA v1.5 wrap takes empty mechanism parameters")
  | mech == rsaX509Mech = case rsaX509RecipeFor mech of
      Just r | rsaX509ParamsValid r params -> Right 0
      _ -> Left (KeyDeny CKR_ARGUMENTS_BAD
        "RSA-X.509 wrap takes empty mechanism parameters")
  | otherwise = case rsaOaepRecipeFor mech of
      Just r | rsaOaepParamsValid r params ->
        case decodeOaepParams params of
          Just (d, _, _) -> case oaepDigestWidth d of
            Just h -> Right (2 * h + 2)
            -- Unreachable post-validation (the width table covers
            -- every code the codec admits); typed, never a crash.
            Nothing -> Left (KeyDeny CKR_ARGUMENTS_BAD
              "RSA-OAEP hash width is unknown")
          Nothing -> Left (KeyDeny CKR_ARGUMENTS_BAD
            "RSA-OAEP mechanism parameters rejected by the recipe")
      _ -> Left (KeyDeny CKR_ARGUMENTS_BAD
        "RSA-OAEP mechanism parameters rejected by the recipe")

-- | Plan one RSA wrap: the public wrapping key needs the wrap
-- mark, the target must be extractable, and the raw material must
-- fit the padding input bound (over the wrapping key's modulus
-- width). Length queries and short buffers answer the
-- modulus-wide blob length and plan no crypto; a sufficient
-- buffer plans one wrap effect over the raw material.
planRsaWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planRsaWrapKey model st mech params wrapH targetH intent =
  case rsaWrapOverhead mech params of
    Left deny -> KeyDenied deny
    Right over ->
      case withRsaWrappingKey model st AttrWrap "wrapping" ckoPublicKey wrapH of
        Left deny -> KeyDenied deny
        Right (wrapOid, k) -> case withWrapTarget model st targetH of
          Left deny -> KeyDenied deny
          Right mat
            | BS.length mat > k - over -> KeyDenied (KeyDeny CKR_DATA_LEN_RANGE
                "wrap payload escapes the RSA input bound")
            | otherwise ->
                let blobLen = k
                    lenOut = NativeOutput (RegionBytes "wrapped" intent)
                      (encodeValue (ValULong (fromIntegral blobLen)))
                in case intent of
                  IntentNull -> KeyImmediate (Immediate PreparedCommit
                    { pcCode = CKR_OK
                    , pcDelta = StateDelta []
                    , pcPersist = []
                    , pcOutputs = [lenOut]
                    , pcReleases = []
                    , pcReasons = ["wrap length query"]
                    })
                  IntentBuffer cap
                    | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                        { rejCode = CKR_BUFFER_TOO_SMALL
                        , rejOutputs = [lenOut]
                        , rejDelta = StateDelta []
                        , rejReleases = []
                        , rejReasons = ["short buffer"]
                        })
                    | otherwise -> KeyEffect (PwBlobOut "wrapped")
                        (FxWrap mech (Just wrapOid) params mat)

-- | Plan one AES-CBC wrap: the wrapping key needs the wrap mark,
-- the target must be extractable. Length queries and short
-- buffers answer the padded length and plan no crypto; a
-- sufficient buffer plans one wrap effect over the padded
-- material.
planAesWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planAesWrapKey model st mech iv wrapH targetH intent
  | BS.length iv /= 16 =
      KeyDenied (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC wrap needs a 16-byte IV")
  | otherwise = case withWrappingKey model st AttrWrap "wrapping" wrapH of
      Left deny -> KeyDenied deny
      Right (wrapOid, _) -> case withWrapTarget model st targetH of
        Left deny -> KeyDenied deny
        Right mat -> case padPkcs7 16 mat of
          Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
            "wrap payload escapes the PKCS#7 range")
          Just padded ->
            let blobLen = BS.length padded
                lenOut = NativeOutput (RegionBytes "wrapped" intent)
                  (encodeValue (ValULong (fromIntegral blobLen)))
            in case intent of
              IntentNull -> KeyImmediate (Immediate PreparedCommit
                { pcCode = CKR_OK
                , pcDelta = StateDelta []
                , pcPersist = []
                , pcOutputs = [lenOut]
                , pcReleases = []
                , pcReasons = ["wrap length query"]
                })
              IntentBuffer cap
                | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                    { rejCode = CKR_BUFFER_TOO_SMALL
                    , rejOutputs = [lenOut]
                    , rejDelta = StateDelta []
                    , rejReleases = []
                    , rejReasons = ["short buffer"]
                    })
                | otherwise -> KeyEffect (PwBlobOut "wrapped")
                    (FxWrap mech (Just wrapOid) iv padded)

-- | Plan one unwrap: AES-CBC aligns through 'planAesUnwrapKey',
-- the AES key-wrap rows frame through 'planAesKwUnwrapKey', the
-- RSA mechanisms measure modulus-wide through 'planRsaUnwrapKey'.
planUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == aesCbcMech = planAesUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == aesKwMech || mech == aesKwPadMech || mech == aesKwpMech =
      planAesKwUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == rsaPkcsMech || mech == rsaOaepMech || mech == rsaX509Mech =
      planRsaUnwrapKey rules model st mech params wrapH blob tmpl
  | otherwise =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))

-- | Plan one RSA unwrap: the private wrapping key needs the
-- unwrap mark, the blob must be exactly modulus-wide, and the
-- template must name the new key's class and key type explicitly
-- (the blob carries no header). Admission gates last
-- (parse-first): mechanism, parameters, key, blob, template,
-- then admission just before the effect. The pending work is raw
-- (no PKCS#7 framing to strip).
planRsaUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planRsaUnwrapKey rules model st mech params wrapH blob tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated =
      case rsaWrapOverhead mech params of
        Left deny -> Left deny
        Right _ -> case withRsaWrappingKey model st AttrUnwrap "unwrapping" ckoPrivateKey wrapH of
          Left deny -> Left deny
          Right (wrapOid, k)
            | BS.length blob /= k ->
                Left (KeyDeny CKR_ARGUMENTS_BAD
                  "wrapped blob length mismatches the RSA modulus")
            | not (any ((== AttrKeyType) . fst) tmpl) ->
                Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
                  "unwrap template must name the key type")
            | otherwise -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
                Left deny -> Left deny
                Right attrs
                  | mech == rsaX509Mech -> case Map.lookup AttrValueLen attrs of
                      Just (ValULong n)
                        | n >= 1 && fromIntegral n <= k -> Right
                            ( PwUnwrapTail (pendingFromAttrs st attrs) k (fromIntegral n)
                            , FxUnwrap mech (Just wrapOid) params blob
                            )
                        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                            ("X.509 unwrap length escapes the modulus width: " ++ show n))
                      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                        "X.509 unwrap value length is malformed")
                      Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
                        "X.509 unwrap needs CKA_VALUE_LEN")
                  | otherwise -> Right
                      ( PwUnwrapRaw (pendingFromAttrs st attrs)
                      , FxUnwrap mech (Just wrapOid) params blob
                      )

-- | Plan one AES key-wrap wrap: the wrapping key needs the wrap
-- mark (AES secret: 'withWrappingKey'), the target must be
-- extractable, parameters are empty (ECB shape). KW needs
-- multiple-of-8 material >= 16 bytes and answers len + 8; KWP
-- (both names) needs non-empty material and answers ceil8 + 8.
-- Length queries and short buffers answer the expanded length and
-- plan no crypto; a sufficient buffer plans one wrap effect over
-- the raw material.
planAesKwWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planAesKwWrapKey model st mech params wrapH targetH intent
  | not (BS.null params) =
      KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "AES key wrap takes empty mechanism parameters")
  | otherwise = case withWrappingKey model st AttrWrap "wrapping" wrapH of
      Left deny -> KeyDenied deny
      Right (wrapOid, _) -> case withWrapTarget model st targetH of
        Left deny -> KeyDenied deny
        Right mat -> case kwBlobLen mech (BS.length mat) of
          Nothing -> KeyDenied (KeyDeny CKR_DATA_LEN_RANGE
            "wrap payload escapes the key-wrap length rules")
          Just blobLen ->
            let lenOut = NativeOutput (RegionBytes "wrapped" intent)
                  (encodeValue (ValULong (fromIntegral blobLen)))
            in case intent of
              IntentNull -> KeyImmediate (Immediate PreparedCommit
                { pcCode = CKR_OK
                , pcDelta = StateDelta []
                , pcPersist = []
                , pcOutputs = [lenOut]
                , pcReleases = []
                , pcReasons = ["wrap length query"]
                })
              IntentBuffer cap
                | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                    { rejCode = CKR_BUFFER_TOO_SMALL
                    , rejOutputs = [lenOut]
                    , rejDelta = StateDelta []
                    , rejReleases = []
                    , rejReasons = ["short buffer"]
                    })
                | otherwise -> KeyEffect (PwBlobOut "wrapped")
                    (FxWrap mech (Just wrapOid) params mat)

-- | Wrapped-blob length for a payload length, or 'Nothing' when
-- the payload violates the row's floor (KW: multiple-of-8 >= 16;
-- KWP under either name: >= 1). Non-wrap mechanisms answer
-- 'Nothing' (the dispatch guards first; total anyway).
kwBlobLen :: MechanismId -> Int -> Maybe Int
kwBlobLen mech n
  | mech == aesKwMech
  , n >= 16 && n `mod` 8 == 0 = Just (n + 8)
  | (mech == aesKwPadMech || mech == aesKwpMech)
  , n >= 1 = Just (n + (8 - n `mod` 8) `mod` 8 + 8)
  | otherwise = Nothing

-- | Plan one AES-CBC unwrap: the wrapping key needs the unwrap
-- mark, the blob must be block-aligned, and the template must
-- name the new key's class and key type explicitly (the blob
-- carries no header). Admission gates last (parse-first):
-- mechanism, IV, blob, key, template, then the bound check just
-- before the effect.
planAesUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planAesUnwrapKey rules model st mech iv wrapH blob tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | BS.length iv /= 16 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC unwrap needs a 16-byte IV")
      | BS.null blob || BS.length blob `mod` 16 /= 0 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "wrapped blob is not block-aligned")
      | not (any ((== AttrKeyType) . fst) tmpl) =
          Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "unwrap template must name the key type")
      | otherwise = case withWrappingKey model st AttrUnwrap "unwrapping" wrapH of
          Left deny -> Left deny
          Right (wrapOid, _) -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
            Left deny -> Left deny
            Right attrs -> Right
              ( PwUnwrap (pendingFromAttrs st attrs)
              , FxUnwrap mech (Just wrapOid) iv blob
              )

-- | Plan one AES key-wrap unwrap: parameters are empty, the blob
-- must satisfy the row's framing (KW: multiple-of-8 >= 24; KWP
-- under either name: multiple-of-8 >= 16), the wrapping key needs
-- the unwrap mark (AES secret), and the template must name the
-- new key's class and key type explicitly (the blob carries no
-- header). Admission gates last (parse-first). The pending work
-- is raw (the backend answers exact plaintext, consumed framing).
planAesKwUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planAesKwUnwrapKey rules model st mech params wrapH blob tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | not (BS.null params) =
          Left (KeyDeny CKR_ARGUMENTS_BAD
            "AES key unwrap takes empty mechanism parameters")
      | not (kwBlobFramed mech (BS.length blob)) =
          Left (KeyDeny CKR_ARGUMENTS_BAD
            "wrapped blob violates key-wrap framing")
      | not (any ((== AttrKeyType) . fst) tmpl) =
          Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "unwrap template must name the key type")
      | otherwise = case withWrappingKey model st AttrUnwrap "unwrapping" wrapH of
          Left deny -> Left deny
          Right (wrapOid, _) -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
            Left deny -> Left deny
            Right attrs -> Right
              ( PwUnwrapRaw (pendingFromAttrs st attrs)
              , FxUnwrap mech (Just wrapOid) params blob
              )

-- | Wrapped-blob framing check: KW blobs are multiple-of-8 >= 24
-- (16-byte minimum plaintext plus IV); KWP blobs under either
-- name are multiple-of-8 >= 16.
kwBlobFramed :: MechanismId -> Int -> Bool
kwBlobFramed mech n
  | mech == aesKwMech = n >= 24 && n `mod` 8 == 0
  | mech == aesKwPadMech || mech == aesKwpMech =
      n >= 16 && n `mod` 8 == 0
  | otherwise = False

-- | Plan one authenticated wrap: like 'planWrapKey', but the blob
-- binds associated data under a 32-byte tag, so the answered length
-- is the padded length plus 32.
planAuthWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> ByteString -> OutputIntent
  -> KeyPlan
planAuthWrapKey model st mech iv wrapH targetH aad intent
  | mech /= aesCbcMech =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))
  | BS.length iv /= 16 =
      KeyDenied (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC wrap needs a 16-byte IV")
  | otherwise = case withWrappingKey model st AttrWrap "wrapping" wrapH of
      Left deny -> KeyDenied deny
      Right (wrapOid, _) -> case withWrapTarget model st targetH of
        Left deny -> KeyDenied deny
        Right mat -> case padPkcs7 16 mat of
          Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
            "wrap payload escapes the PKCS#7 range")
          Just padded ->
            let blobLen = BS.length padded + 32
                lenOut = NativeOutput (RegionBytes "wrapped" intent)
                  (encodeValue (ValULong (fromIntegral blobLen)))
            in case intent of
              IntentNull -> KeyImmediate (Immediate PreparedCommit
                { pcCode = CKR_OK
                , pcDelta = StateDelta []
                , pcPersist = []
                , pcOutputs = [lenOut]
                , pcReleases = []
                , pcReasons = ["authenticated-wrap length query"]
                })
              IntentBuffer cap
                | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                    { rejCode = CKR_BUFFER_TOO_SMALL
                    , rejOutputs = [lenOut]
                    , rejDelta = StateDelta []
                    , rejReleases = []
                    , rejReasons = ["short buffer"]
                    })
                | otherwise -> KeyEffect (PwBlobOut "wrapped")
                    (FxAuthWrap mech (Just wrapOid) (encodeWrapParams iv aad) padded)

-- | Plan one authenticated unwrap: like 'planUnwrapKey', with the
-- associated data the tag is verified against. Admission gates
-- last (parse-first): mechanism, IV, blob, key, template,
-- then the bound check just before the effect.
planAuthUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planAuthUnwrapKey rules model st mech iv wrapH blob aad tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | mech /= aesCbcMech =
          Left (KeyDeny CKR_MECHANISM_INVALID
            ("not a wrap mechanism: " ++ show mech))
      | BS.length iv /= 16 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC unwrap needs a 16-byte IV")
      | BS.length blob < 32 || (BS.length blob - 32) `mod` 16 /= 0 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "authenticated blob has a bad length")
      | not (any ((== AttrKeyType) . fst) tmpl) =
          Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "unwrap template must name the key type")
      | otherwise = case withWrappingKey model st AttrUnwrap "unwrapping" wrapH of
          Left deny -> Left deny
          Right (wrapOid, _) -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
            Left deny -> Left deny
            Right attrs -> Right
              ( PwUnwrap (pendingFromAttrs st attrs)
              , FxAuthUnwrap mech (Just wrapOid) (encodeWrapParams iv aad) blob
              )
