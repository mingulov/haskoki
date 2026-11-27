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

Creation stamps explicit values: a missing class is incomplete,
a missing key type defaults to the mechanism's key, usage flags
default to true on the strict key-template path (except
CKA_DERIVE, which defaults to false per the PKCS#11 common key
attributes table), and the
protection pair stamps per class (non-sensitive and unextractable
on private and secret keys, non-sensitive and extractable on
public keys; unwrapped keys stamp extractable). Generated keys
additionally take birth history (always-sensitive at the birth
sensitive mark, never-extractable at the negated birth
extractable mark, local true, the generating mechanism);
unwrapped keys take false history and origin. The planners
enforce the effective (reported) values strictly.

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
  , storeDerivedMaterial
  , derivedNeedsParity
  , workFunction
  , stampPairComponents
  , stampParamsObject
  , keyPairCompatible
    -- * Object reading
  , keyBytesOf
  , policyFromObject
  , keyTypeCompatible
  , keyClassCompatible
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
  , aesKwp7Mech
  , ecdhAesKwMech
  , ecdhCofAesKwMech
  , ecdhXAesKwMech
  , rsaAesKwMech
  , rsaPkcsMech
  , rsaOaepMech
  , rsaX509Mech
    -- * Shared template checks
  , checkKeyTemplate
  , checkKeyTemplateAny
  , checkDataTemplate
  , DerivedDomain (..)
  , derivedObjectDomain
  , checkDerivedTarget
  , sealedByteOpChildOk
  , pendingFromAttrs
  , ByteOpsProtection (..)
  , byteOpsProtectionOf
  , resolveByteOpsProtection
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

import Data.ByteString (ByteString)

import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  )
import Haskoki.Model (Model (..), SessionState (..))
import Haskoki.Operation.KeyManagement.Codes
import Haskoki.Operation.KeyManagement.MechIds
import Haskoki.Operation.KeyManagement.Codec
import Haskoki.Operation.KeyManagement.Currency
import Haskoki.Operation.KeyManagement.Keygen
import Haskoki.Operation.KeyManagement.Wrap
import Haskoki.Operation.KeyManagement.WrapComp
import Haskoki.Operation.KeyManagement.Template
import Haskoki.Operation.KeyManagement.Types
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request (OutputIntent (..))
import Haskoki.Rules (Rules)
import Haskoki.Types
  ( ExternalHandle (..)
  , ReturnCode (..)
  )

-- ---------------------------------------------------------------------------
-- Plan currency
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Shared template checks
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Generation frames (planner <-> driver contract)
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Wrap padding
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Key-pair generation
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Table-driven single-key generation (slice 11a sweep)
-- ---------------------------------------------------------------------------



-- ---------------------------------------------------------------------------
-- Single-key generation
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Wrap and unwrap
-- ---------------------------------------------------------------------------

-- | Plan one wrap: AES-CBC pads through 'planAesWrapKey', the
-- AES key-wrap rows expand through 'planAesKwWrapKey', KW-PKCS7
-- pads plus wraps through 'planAesKwPkcs7WrapKey', the ECDH
-- compositions frame through 'planEcdhCompWrapKey', the RSA
-- mechanisms travel raw through 'planRsaWrapKey'.
planWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planWrapKey model st mech params wrapH targetH intent
  | mech == aesCbcMech = planAesWrapKey model st mech params wrapH targetH intent
  | mech == aesKwMech || mech == aesKwPadMech || mech == aesKwpMech =
      planAesKwWrapKey model st mech params wrapH targetH intent
  | mech == aesKwp7Mech =
      planAesKwPkcs7WrapKey model st mech params wrapH targetH intent
  | mech == ecdhAesKwMech || mech == ecdhCofAesKwMech || mech == ecdhXAesKwMech =
      planEcdhCompWrapKey model st mech params wrapH targetH intent
  | mech == rsaAesKwMech =
      planRsaCompWrapKey model st mech params wrapH targetH intent
  | mech == rsaPkcsMech || mech == rsaOaepMech || mech == rsaX509Mech =
      planRsaWrapKey model st mech params wrapH targetH intent
  | otherwise =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))

-- | Plan one unwrap: AES-CBC aligns through 'planAesUnwrapKey',
-- the AES key-wrap rows frame through 'planAesKwUnwrapKey',
-- KW-PKCS7 frames plus strips through
-- 'planAesKwPkcs7UnwrapKey', the ECDH compositions split through
-- 'planEcdhCompUnwrapKey', the RSA composition splits through
-- 'planRsaCompUnwrapKey', the RSA mechanisms measure
-- modulus-wide through 'planRsaUnwrapKey'.
planUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == aesCbcMech = planAesUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == aesKwMech || mech == aesKwPadMech || mech == aesKwpMech =
      planAesKwUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == aesKwp7Mech =
      planAesKwPkcs7UnwrapKey rules model st mech params wrapH blob tmpl
  | mech == ecdhAesKwMech || mech == ecdhCofAesKwMech || mech == ecdhXAesKwMech =
      planEcdhCompUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == rsaAesKwMech =
      planRsaCompUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == rsaPkcsMech || mech == rsaOaepMech || mech == rsaX509Mech =
      planRsaUnwrapKey rules model st mech params wrapH blob tmpl
  | otherwise =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))
