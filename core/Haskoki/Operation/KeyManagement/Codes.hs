{- | KeyManagement class and key-type codes (spec/vendor/pkcs11.h).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.KeyManagement.Codes
  ( ckoData
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
  , ckkDes3
  , ckkAesXts
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
  ) where
import Data.Word (Word64)

import Haskoki.Attribute.Generated (mustClassId, mustKeyTypeId)


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
