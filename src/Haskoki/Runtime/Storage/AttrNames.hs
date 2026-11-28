{- | Detached attribute names.
-}
module Haskoki.Runtime.Storage.AttrNames
  ( attrName
  , nameAttr
  , encodeAttrValue
  , decodeAttrValue
  ) where

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Runtime.Storage.Base64
import Haskoki.Runtime.Storage.Encoding
import Haskoki.Runtime.Storage.Word64Hex

-- ---------------------------------------------------------------------------
-- Attribute names
-- ---------------------------------------------------------------------------

-- | Canonical attribute names in stored documents. Names (not 'Enum'
-- tags) keep the encoding readable across inventory growth; unknown
-- names reject on decode.
attrName :: AttributeType -> String
attrName t = case t of
  AttrClass -> "class"
  AttrToken -> "token"
  AttrPrivate -> "private"
  AttrLabel -> "label"
  AttrApplication -> "application"
  AttrValue -> "value"
  AttrSensitive -> "sensitive"
  AttrExtractable -> "extractable"
  AttrKeyType -> "key_type"
  AttrValueLen -> "value_len"
  AttrEncrypt -> "encrypt"
  AttrDecrypt -> "decrypt"
  AttrSign -> "sign"
  AttrSignRecover -> "sign_recover"
  AttrVerify -> "verify"
  AttrVerifyRecover -> "verify_recover"
  AttrWrap -> "wrap"
  AttrUnwrap -> "unwrap"
  AttrDerive -> "derive"
  AttrAlwaysAuthenticate -> "always_authenticate"
  AttrEcParams -> "ec_params"
  AttrModulusBits -> "modulus_bits"
  AttrKemAlg -> "kem_alg"
  AttrEncapsulate -> "encapsulate"
  AttrDecapsulate -> "decapsulate"
  AttrId -> "id"
  AttrPublicExponent -> "public_exponent"
  AttrModulus -> "modulus"
  AttrPrivateExponent -> "private_exponent"
  AttrPrime1 -> "prime_1"
  AttrPrime2 -> "prime_2"
  AttrExponent1 -> "exponent_1"
  AttrExponent2 -> "exponent_2"
  AttrCoefficient -> "coefficient"
  AttrEcPoint -> "ec_point"
  AttrAllowedMechanisms -> "allowed_mechanisms"
  AttrCopyable -> "copyable"
  AttrDestroyable -> "destroyable"
  AttrModifiable -> "modifiable"
  AttrCertificateType -> "certificate_type"
  AttrSubject -> "subject"
  AttrIssuer -> "issuer"
  AttrSerialNumber -> "serial_number"
  AttrPublicKeyInfo -> "public_key_info"
  AttrHashOfSubjectPublicKey -> "hash_of_subject_public_key"
  AttrHashOfIssuerPublicKey -> "hash_of_issuer_public_key"
  AttrPrime -> "prime"
  AttrSubprime -> "subprime"
  AttrBase -> "base"
  AttrPrimeBits -> "prime_bits"
  AttrSubprimeBits -> "subprime_bits"
  AttrParameterSet -> "parameter_set"
  AttrSeed -> "seed"
  AttrTrusted -> "trusted"
  AttrCertificateCategory -> "certificate_category"
  AttrStartDate -> "start_date"
  AttrEndDate -> "end_date"
  AttrAlwaysSensitive -> "always_sensitive"
  AttrNeverExtractable -> "never_extractable"
  AttrLocal -> "local"
  AttrKeyGenMechanism -> "key_gen_mechanism"

-- | Name back to type; unknown names fail.
nameAttr :: String -> Maybe AttributeType
nameAttr s = case s of
  "class" -> Just AttrClass
  "token" -> Just AttrToken
  "private" -> Just AttrPrivate
  "label" -> Just AttrLabel
  "application" -> Just AttrApplication
  "value" -> Just AttrValue
  "sensitive" -> Just AttrSensitive
  "extractable" -> Just AttrExtractable
  "key_type" -> Just AttrKeyType
  "value_len" -> Just AttrValueLen
  "encrypt" -> Just AttrEncrypt
  "decrypt" -> Just AttrDecrypt
  "sign" -> Just AttrSign
  "sign_recover" -> Just AttrSignRecover
  "verify" -> Just AttrVerify
  "verify_recover" -> Just AttrVerifyRecover
  "wrap" -> Just AttrWrap
  "unwrap" -> Just AttrUnwrap
  "derive" -> Just AttrDerive
  "always_authenticate" -> Just AttrAlwaysAuthenticate
  "ec_params" -> Just AttrEcParams
  "modulus_bits" -> Just AttrModulusBits
  "kem_alg" -> Just AttrKemAlg
  "encapsulate" -> Just AttrEncapsulate
  "decapsulate" -> Just AttrDecapsulate
  "id" -> Just AttrId
  "public_exponent" -> Just AttrPublicExponent
  "modulus" -> Just AttrModulus
  "private_exponent" -> Just AttrPrivateExponent
  "prime_1" -> Just AttrPrime1
  "prime_2" -> Just AttrPrime2
  "exponent_1" -> Just AttrExponent1
  "exponent_2" -> Just AttrExponent2
  "coefficient" -> Just AttrCoefficient
  "ec_point" -> Just AttrEcPoint
  "allowed_mechanisms" -> Just AttrAllowedMechanisms
  "copyable" -> Just AttrCopyable
  "destroyable" -> Just AttrDestroyable
  "modifiable" -> Just AttrModifiable
  "certificate_type" -> Just AttrCertificateType
  "subject" -> Just AttrSubject
  "issuer" -> Just AttrIssuer
  "serial_number" -> Just AttrSerialNumber
  "public_key_info" -> Just AttrPublicKeyInfo
  "hash_of_subject_public_key" -> Just AttrHashOfSubjectPublicKey
  "hash_of_issuer_public_key" -> Just AttrHashOfIssuerPublicKey
  "prime" -> Just AttrPrime
  "subprime" -> Just AttrSubprime
  "base" -> Just AttrBase
  "prime_bits" -> Just AttrPrimeBits
  "subprime_bits" -> Just AttrSubprimeBits
  "parameter_set" -> Just AttrParameterSet
  "seed" -> Just AttrSeed
  "trusted" -> Just AttrTrusted
  "certificate_category" -> Just AttrCertificateCategory
  "start_date" -> Just AttrStartDate
  "end_date" -> Just AttrEndDate
  "always_sensitive" -> Just AttrAlwaysSensitive
  "never_extractable" -> Just AttrNeverExtractable
  "local" -> Just AttrLocal
  "key_gen_mechanism" -> Just AttrKeyGenMechanism
  _ -> Nothing

-- | Encode one attribute value: bools as JSON booleans, unsigned
-- longs as full-width 16-hex strings, byte arrays as base64
-- strings.
encodeAttrValue :: AttributeValue -> Json
encodeAttrValue v = case v of
  ValBool b -> JBool b
  ValULong n -> JString (encodeHexWord64 n)
  ValBytes bs -> JString (encodeBase64 bs)

-- | Decode one attribute value against its owning type's shape.
-- Cross-shape bytes fail.
decodeAttrValue :: AttributeType -> Json -> Maybe AttributeValue
decodeAttrValue t j = case t of
  AttrToken -> boolOf j
  AttrPrivate -> boolOf j
  AttrSensitive -> boolOf j
  AttrExtractable -> boolOf j
  AttrEncrypt -> boolOf j
  AttrDecrypt -> boolOf j
  AttrSign -> boolOf j
  AttrSignRecover -> boolOf j
  AttrVerify -> boolOf j
  AttrVerifyRecover -> boolOf j
  AttrWrap -> boolOf j
  AttrUnwrap -> boolOf j
  AttrDerive -> boolOf j
  AttrAlwaysAuthenticate -> boolOf j
  AttrEncapsulate -> boolOf j
  AttrDecapsulate -> boolOf j
  AttrCopyable -> boolOf j
  AttrDestroyable -> boolOf j
  AttrModifiable -> boolOf j
  AttrClass -> ulongOf j
  AttrKeyType -> ulongOf j
  AttrValueLen -> ulongOf j
  AttrModulusBits -> ulongOf j
  AttrKemAlg -> ulongOf j
  AttrCertificateType -> ulongOf j
  AttrLabel -> bytesOf j
  AttrApplication -> bytesOf j
  AttrValue -> bytesOf j
  AttrEcParams -> bytesOf j
  AttrId -> bytesOf j
  AttrPublicExponent -> bytesOf j
  AttrModulus -> bytesOf j
  AttrPrivateExponent -> bytesOf j
  AttrPrime1 -> bytesOf j
  AttrPrime2 -> bytesOf j
  AttrExponent1 -> bytesOf j
  AttrExponent2 -> bytesOf j
  AttrCoefficient -> bytesOf j
  AttrEcPoint -> bytesOf j
  AttrAllowedMechanisms -> bytesOf j
  AttrSubject -> bytesOf j
  AttrIssuer -> bytesOf j
  AttrSerialNumber -> bytesOf j
  AttrPublicKeyInfo -> bytesOf j
  AttrHashOfSubjectPublicKey -> bytesOf j
  AttrHashOfIssuerPublicKey -> bytesOf j
  AttrPrime -> bytesOf j
  AttrSubprime -> bytesOf j
  AttrBase -> bytesOf j
  AttrPrimeBits -> ulongOf j
  AttrSubprimeBits -> ulongOf j
  AttrParameterSet -> ulongOf j
  AttrSeed -> bytesOf j
  AttrTrusted -> boolOf j
  AttrCertificateCategory -> ulongOf j
  AttrStartDate -> bytesOf j
  AttrEndDate -> bytesOf j
  AttrAlwaysSensitive -> boolOf j
  AttrNeverExtractable -> boolOf j
  AttrLocal -> boolOf j
  AttrKeyGenMechanism -> ulongOf j
  where
    boolOf (JBool b) = Just (ValBool b)
    boolOf _ = Nothing
    ulongOf (JString s) = ValULong <$> decodeHexWord64 s
    ulongOf _ = Nothing
    bytesOf (JString s) = ValBytes <$> decodeBase64 s
    bytesOf _ = Nothing
