{- | KeyManagement mechanism ids and keygen bounds.
-}
module Haskoki.Operation.KeyManagement.MechIds
  ( aesKeyGenMech
  , des3KeyGenMech
  , hotpKeyGenMech
  , blake2b512KeyGenMech
  , chacha20KeyGenMech
  , genericSecretKeyGenMech
  , genericSecretKeygenMinBytes
  , genericSecretKeygenMaxBytes
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
  , ecKeyPairGenMech
  , ecExtraBitsKeyPairGenMech
  , rsaKeyPairGenMech
  , dsaKeyPairGenMech
  , dsaParameterGenMech
  , dhKeyPairGenMech
  , x9_42DhKeyPairGenMech
  , x9_42DhParameterGenMech
  , dhPkcsParameterGenMech
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
  ) where
import Haskoki.Registry (MechanismId (..))
-- Whole-module: ~100 generated ids; an explicit list would churn
-- on every addition with zero review value.
import Haskoki.Registry.Generated


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

-- | Generic-secret keygen ceiling: the GenBytes planner-driver frame
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
pbeSha1Cast128KeyGenMech, pbeSha1Rc4_128KeyGenMech, pbeSha1Rc4_40KeyGenMech :: MechanismId
pbeSha1Cast128KeyGenMech = MechanismId (ckm_PBE_SHA1_CAST128_CBC)
pbeSha1Rc4_128KeyGenMech = MechanismId (ckm_PBE_SHA1_RC4_128)
pbeSha1Rc4_40KeyGenMech = MechanismId (ckm_PBE_SHA1_RC4_40)
pbeSha1Rc2_128KeyGenMech, pbeSha1Rc2_40KeyGenMech :: MechanismId
pbeSha1Rc2_128KeyGenMech = MechanismId (ckm_PBE_SHA1_RC2_128_CBC)
pbeSha1Rc2_40KeyGenMech = MechanismId (ckm_PBE_SHA1_RC2_40_CBC)
pbeMd5DesKeyGenMech, pbeMd5CastKeyGenMech :: MechanismId
pbeMd5DesKeyGenMech = MechanismId (ckm_PBE_MD5_DES_CBC)
pbeMd5CastKeyGenMech = MechanismId (ckm_PBE_MD5_CAST_CBC)
pbeMd5Cast3KeyGenMech, pbeMd5Cast128KeyGenMech :: MechanismId
pbeMd5Cast3KeyGenMech = MechanismId (ckm_PBE_MD5_CAST3_CBC)
pbeMd5Cast128KeyGenMech = MechanismId (ckm_PBE_MD5_CAST128_CBC)

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

-- | @CKM_AES_KEY_WRAP_PKCS7@ (PKCS#7-pad to the 8-byte quantum,
-- always padding, then RFC 3394: raw payload >= 8 bytes, the blob
-- is the padded length plus the 8-byte IV; empty or 8-byte-IV
-- parameters; generated id, resolved by name).
aesKwp7Mech :: MechanismId
aesKwp7Mech = MechanismId (ckm_AES_KEY_WRAP_PKCS7)

-- | @CKM_ECDH_AES_KEY_WRAP@ (ECDH agreement against an ephemeral
-- transport key, first @ulAESKeyBits@ bits as the AES KEK,
-- KWP-wrap of the target; generated id, resolved by name).
ecdhAesKwMech :: MechanismId
ecdhAesKwMech = MechanismId (ckm_ECDH_AES_KEY_WRAP)

-- | @CKM_ECDH_COF_AES_KEY_WRAP@ (the cofactor variant: EC keys
-- only, OCTET-STRING transport framing; generated id, resolved by
-- name).
ecdhCofAesKwMech :: MechanismId
ecdhCofAesKwMech = MechanismId (ckm_ECDH_COF_AES_KEY_WRAP)

-- | @CKM_ECDH_X_AES_KEY_WRAP@ (the Montgomery variant:
-- Montgomery keys only, raw-coordinate transport framing;
-- generated id, resolved by name).
ecdhXAesKwMech :: MechanismId
ecdhXAesKwMech = MechanismId (ckm_ECDH_X_AES_KEY_WRAP)

-- | @CKM_RSA_AES_KEY_WRAP@ (the RSA composition: a random
-- temp KEK at the requested strength, OAEP-sealed under the
-- recipient public key, KWP-seals the target; generated id,
-- resolved by name).
rsaAesKwMech :: MechanismId
rsaAesKwMech = MechanismId (ckm_RSA_AES_KEY_WRAP)

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
