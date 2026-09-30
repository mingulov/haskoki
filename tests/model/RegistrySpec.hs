{- | Descriptor registry tests.

Validation rejects descriptors without a codec or
without a source-backed operation policy, aliases deduplicate, and
catalog-only rows stay unimplemented.
-}
{-# LANGUAGE OverloadedStrings #-}
module RegistrySpec (spec) where

import Data.List (sort)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Registry
  ( Descriptor (..)
  , EngineCapabilities
  , Family (..)
  , KeySizeUnit (..)
  , MechanismId (..)
  , MechanismName
  , MechanismStatus (..)
  , Operation (..)
  , ParameterCodec (..)
  , Registry
  , RegistryError (..)
  , RoutePolicy (..)
  , SourceRef (..)
  , behaviorIds
  , curatedRegistry
  , describeStatus
  , dumpRegistry
  , emptyRegistry
  , inventoryIds
  , isExecutable
  , lookupBehavior
  , lookupByName
  , mechanismList
  , mkCapabilities
  , promoteInventory
  , registerDescriptor
  , setCatalog
  )
import Haskoki.Registry.Generated (mustGeneratedId)
import qualified Haskoki.Registry.Generated as Gen
import Haskoki.Types (Pkcs11Version (..))

spec :: TestTree
spec = testGroup "descriptor registry"
  [ testCase "reject descriptor with no codec" caseNoCodec
  , testCase "reject descriptor with no source-backed policy" caseNoPolicy
  , testCase "aliases deduplicate in mechanism list" caseAliases
  , testCase "catalog-only row stays unimplemented" caseCatalogOnly
  , testCase "curated registry pins reviewed population" caseCurated
  , testCase "registry dump matches mechanisms.json projection" caseJsonProjection
  , testCase "promote catalog-only row to behavior" casePromote
  , testCase "promote rejects mismatches and unknowns" casePromoteReject
  , testCase "Key-management mechs promoted to behavior" caseKeyMgmtPromoted
  , testCase "AES-CBC carries wrap routes" caseAesCbcWrap
  , testCase "Digest mechs promoted to behavior" caseDigestPromoted
  , testCase "Cipher mechs promoted to behavior" caseCipherPromoted
  , testCase "RSA v1.5 mechs promoted to behavior" caseRsaPromoted
  , testCase "RSA PSS/OAEP mechs promoted to behavior" caseRsaPssOaepPromoted
  , testCase "ECDSA mechs promoted to behavior" caseEcdsaPromoted
  , testCase "ECDH mechs promoted to behavior" caseEcdhPromoted
  , testCase "CMAC mechs promoted to behavior" caseCmacPromoted
  , testCase "KDF mechs promoted to behavior" caseKdfPromoted
  , testCase "OTP mechs promoted to behavior" caseOtpPromoted
  , testCase "SP800-108 mechs promoted to behavior" caseSp800Promoted
  , testCase "TLS-KDF mechs promoted to behavior" caseTlsKdfPromoted
  , testCase "IKE mechs promoted to behavior" caseIkePromoted
  , testCase "byte-op mechs promoted to behavior" caseByteOpsPromoted
  , testCase "key-material mechs promoted to behavior" caseKeyMatPromoted
  , testCase "PBE mechs promoted to behavior" casePbePromoted
  , testCase "Catalog-only rows never execute" caseCatalogOnlyNeverExecutes
  , testCase "Specials stay catalog-only" caseSpecialsCatalogOnly
  ]

-- | Test descriptor skeleton; codec and routes are the validation axes.
mkTestDesc :: MechanismId -> MechanismName -> Maybe ParameterCodec -> [RoutePolicy] -> Descriptor
mkTestDesc mid name mcodec routes = Descriptor
  { descId = mid
  , descCanonical = name
  , descAliases = []
  , descBaseline = [Pkcs11_3_2]
  , descFamily = FamilyDigest
  , descCodec = mcodec
  , descRoutes = routes
  , descKeyUnit = NotApplicable
  , descMinKey = 0
  , descMaxKey = 0
  }

testCodec :: ParameterCodec
testCodec = ParameterCodec "no-params" 1

testRoute :: Operation -> RoutePolicy
testRoute op = RoutePolicy op [SourceRef "test-fixture" "test-only"] ["A37"]

expectRight :: (Show e) => Either e a -> IO a
expectRight = either (assertFailure . show) pure

caseNoCodec :: IO ()
caseNoCodec = do
  let d = mkTestDesc (MechanismId 0x250) "CKM_SHA256" Nothing [testRoute OpDigest]
  assertEqual "missing codec rejected"
    (Left (MissingCodec "CKM_SHA256") :: Either RegistryError Registry)
    (registerDescriptor emptyRegistry d)

caseNoPolicy :: IO ()
caseNoPolicy = do
  let noRoutes = mkTestDesc (MechanismId 0x250) "CKM_SHA256" (Just testCodec) []
  case registerDescriptor emptyRegistry noRoutes of
    Left (MissingPolicy _ _) -> pure ()
    other -> assertFailure ("empty routes must reject, got: " ++ show other)
  let noSources = mkTestDesc (MechanismId 0x250) "CKM_SHA256" (Just testCodec)
        [RoutePolicy OpDigest [] ["A37"]]
  case registerDescriptor emptyRegistry noSources of
    Left (MissingPolicy _ _) -> pure ()
    other -> assertFailure ("sourceless route must reject, got: " ++ show other)

caseAliases :: IO ()
caseAliases = do
  let d = (mkTestDesc (MechanismId 0x250) "CKM_SHA256" (Just testCodec) [testRoute OpDigest])
        { descAliases = ["CKM_SHA256_ALIAS"] }
  reg <- expectRight (registerDescriptor emptyRegistry d)
  regC <- expectRight (setCatalog reg [MechanismId 0x250])
  assertEqual "id listed once" [MechanismId 0x250] (mechanismList regC)
  assertEqual "alias resolves like canonical"
    (lookupByName regC "CKM_SHA256") (lookupByName regC "CKM_SHA256_ALIAS")
  case lookupByName regC "CKM_SHA256_ALIAS" of
    Nothing -> assertFailure "alias must resolve"
    Just got -> assertEqual "alias canonical" "CKM_SHA256" (descCanonical got)
  -- The same alias claimed by a different id is a conflict.
  let d2 = (mkTestDesc (MechanismId 0x251) "CKM_OTHER" (Just testCodec) [testRoute OpDigest])
        { descAliases = ["CKM_SHA256_ALIAS"] }
  case registerDescriptor reg d2 of
    Left (AliasConflict _ _ _) -> pure ()
    other -> assertFailure ("alias conflict must reject, got: " ++ show other)
  -- Catalog membership requires inventory presence.
  case setCatalog reg [MechanismId 0x999] of
    Left (UnknownCatalogMember _) -> pure ()
    other -> assertFailure ("unknown catalog member must reject, got: " ++ show other)

caseCatalogOnly :: IO ()
caseCatalogOnly = do
  let reg = curatedRegistry
      x931 = MechanismId 0xa
      skipjack = MechanismId 0x1002
      -- Even with engine support present, catalog-only rows stay down.
      caps :: EngineCapabilities
      caps = mkCapabilities
        [ (x931, OpGenerateKeyPair)
        , (skipjack, OpEncrypt)
        , (skipjack, OpDecrypt)
        ]
  assertEqual "x931 catalog-only" StatusCatalogOnly (describeStatus reg x931)
  assertEqual "skipjack catalog-only" StatusCatalogOnly (describeStatus reg skipjack)
  assertEqual "x931 no behavior" Nothing (lookupBehavior reg x931)
  assertBool "x931 not executable"
    (not (isExecutable reg caps x931 OpGenerateKeyPair))
  assertBool "skipjack not executable"
    (not (isExecutable reg caps skipjack OpEncrypt))
  -- But they are still listed in the catalog projection: they remain
  -- in the coverage denominator.
  assertBool "x931 listed" (x931 `elem` mechanismList reg)
  assertBool "skipjack listed" (skipjack `elem` mechanismList reg)

caseCurated :: IO ()
caseCurated = do
  let reg = curatedRegistry
  assertEqual "behavior population"
    [ MechanismId Gen.ckm_RSA_PKCS_KEY_PAIR_GEN
    , MechanismId Gen.ckm_RSA_PKCS
    , MechanismId Gen.ckm_RSA_X_509
    , MechanismId Gen.ckm_MD5_RSA_PKCS
    , MechanismId Gen.ckm_SHA1_RSA_PKCS
    , MechanismId Gen.ckm_RIPEMD160_RSA_PKCS
    , MechanismId Gen.ckm_RSA_PKCS_OAEP
    , MechanismId Gen.ckm_RSA_X9_31
    , MechanismId Gen.ckm_SHA1_RSA_X9_31
    , MechanismId Gen.ckm_RSA_PKCS_PSS
    , MechanismId Gen.ckm_SHA1_RSA_PKCS_PSS
    , MechanismId Gen.ckm_ML_KEM_KEY_PAIR_GEN
    , MechanismId Gen.ckm_DSA_KEY_PAIR_GEN
    , MechanismId Gen.ckm_DSA
    , MechanismId Gen.ckm_DSA_SHA1
    , MechanismId Gen.ckm_DSA_SHA224
    , MechanismId Gen.ckm_DSA_SHA256
    , MechanismId Gen.ckm_DSA_SHA384
    , MechanismId Gen.ckm_DSA_SHA512
    , MechanismId Gen.ckm_ML_KEM
    , MechanismId Gen.ckm_DSA_SHA3_224
    , MechanismId Gen.ckm_DSA_SHA3_256
    , MechanismId Gen.ckm_DSA_SHA3_384
    , MechanismId Gen.ckm_DSA_SHA3_512
    , MechanismId Gen.ckm_ML_DSA_KEY_PAIR_GEN
    , MechanismId Gen.ckm_ML_DSA
    , MechanismId Gen.ckm_DH_PKCS_KEY_PAIR_GEN
    , MechanismId Gen.ckm_DH_PKCS_DERIVE
    , MechanismId Gen.ckm_SLH_DSA_KEY_PAIR_GEN
    , MechanismId Gen.ckm_SLH_DSA
    , MechanismId Gen.ckm_X9_42_DH_KEY_PAIR_GEN
    , MechanismId Gen.ckm_X9_42_DH_DERIVE
    , MechanismId Gen.ckm_SHA256_RSA_PKCS
    , MechanismId Gen.ckm_SHA384_RSA_PKCS
    , MechanismId Gen.ckm_SHA512_RSA_PKCS
    , MechanismId Gen.ckm_SHA256_RSA_PKCS_PSS
    , MechanismId Gen.ckm_SHA384_RSA_PKCS_PSS
    , MechanismId Gen.ckm_SHA512_RSA_PKCS_PSS
    , MechanismId Gen.ckm_SHA224_RSA_PKCS
    , MechanismId Gen.ckm_SHA224_RSA_PKCS_PSS
    , MechanismId Gen.ckm_SHA512_224
    , MechanismId Gen.ckm_SHA512_224_HMAC
    , MechanismId Gen.ckm_SHA512_224_HMAC_GENERAL
    , MechanismId Gen.ckm_SHA512_224_KEY_DERIVATION
    , MechanismId Gen.ckm_SHA512_256
    , MechanismId Gen.ckm_SHA512_256_HMAC
    , MechanismId Gen.ckm_SHA512_256_HMAC_GENERAL
    , MechanismId Gen.ckm_SHA512_256_KEY_DERIVATION
    , MechanismId Gen.ckm_TLS12_EXTENDED_MASTER_KEY_DERIVE
    , MechanismId Gen.ckm_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH
    , MechanismId Gen.ckm_SHA3_256_RSA_PKCS
    , MechanismId Gen.ckm_SHA3_384_RSA_PKCS
    , MechanismId Gen.ckm_SHA3_512_RSA_PKCS
    , MechanismId Gen.ckm_SHA3_256_RSA_PKCS_PSS
    , MechanismId Gen.ckm_SHA3_384_RSA_PKCS_PSS
    , MechanismId Gen.ckm_SHA3_512_RSA_PKCS_PSS
    , MechanismId Gen.ckm_SHA3_224_RSA_PKCS
    , MechanismId Gen.ckm_SHA3_224_RSA_PKCS_PSS
    , MechanismId Gen.ckm_RC2_KEY_GEN
    , MechanismId Gen.ckm_RC2_ECB
    , MechanismId Gen.ckm_RC2_CBC
    , MechanismId Gen.ckm_RC2_CBC_PAD
    , MechanismId Gen.ckm_RC4_KEY_GEN
    , MechanismId Gen.ckm_RC4
    , MechanismId Gen.ckm_DES_KEY_GEN
    , MechanismId Gen.ckm_DES_ECB
    , MechanismId Gen.ckm_DES_CBC
    , MechanismId Gen.ckm_DES_CBC_PAD
    , MechanismId Gen.ckm_DES2_KEY_GEN
    , MechanismId Gen.ckm_DES3_KEY_GEN
    , MechanismId Gen.ckm_DES3_ECB
    , MechanismId Gen.ckm_DES3_CBC
    , MechanismId Gen.ckm_DES3_MAC
    , MechanismId Gen.ckm_DES3_MAC_GENERAL
    , MechanismId Gen.ckm_DES3_CBC_PAD
    , MechanismId Gen.ckm_DES3_CMAC_GENERAL
    , MechanismId Gen.ckm_DES3_CMAC
    , MechanismId Gen.ckm_CDMF_KEY_GEN
    , MechanismId Gen.ckm_DES_OFB64
    , MechanismId Gen.ckm_DES_CFB64
    , MechanismId Gen.ckm_DES_CFB8
    , MechanismId Gen.ckm_MD5
    , MechanismId Gen.ckm_MD5_HMAC
    , MechanismId Gen.ckm_MD5_HMAC_GENERAL
    , MechanismId Gen.ckm_SHA_1
    , MechanismId Gen.ckm_SHA_1_HMAC
    , MechanismId Gen.ckm_SHA_1_HMAC_GENERAL
    , MechanismId Gen.ckm_RIPEMD160
    , MechanismId Gen.ckm_RIPEMD160_HMAC
    , MechanismId Gen.ckm_RIPEMD160_HMAC_GENERAL
    , MechanismId Gen.ckm_SHA256
    , MechanismId Gen.ckm_SHA256_HMAC
    , MechanismId Gen.ckm_SHA256_HMAC_GENERAL
    , MechanismId Gen.ckm_SHA224
    , MechanismId Gen.ckm_SHA224_HMAC
    , MechanismId Gen.ckm_SHA224_HMAC_GENERAL
    , MechanismId Gen.ckm_SHA384
    , MechanismId Gen.ckm_SHA384_HMAC
    , MechanismId Gen.ckm_SHA384_HMAC_GENERAL
    , MechanismId Gen.ckm_SHA512
    , MechanismId Gen.ckm_SHA512_HMAC
    , MechanismId Gen.ckm_SHA512_HMAC_GENERAL
    , MechanismId Gen.ckm_HOTP_KEY_GEN
    , MechanismId Gen.ckm_HOTP
    , MechanismId Gen.ckm_SHA3_256
    , MechanismId Gen.ckm_SHA3_256_HMAC
    , MechanismId Gen.ckm_SHA3_256_HMAC_GENERAL
    , MechanismId Gen.ckm_SHA3_256_KEY_GEN
    , MechanismId Gen.ckm_SHA3_224
    , MechanismId Gen.ckm_SHA3_224_HMAC
    , MechanismId Gen.ckm_SHA3_224_HMAC_GENERAL
    , MechanismId Gen.ckm_SHA3_224_KEY_GEN
    , MechanismId Gen.ckm_SHA3_384
    , MechanismId Gen.ckm_SHA3_384_HMAC
    , MechanismId Gen.ckm_SHA3_384_HMAC_GENERAL
    , MechanismId Gen.ckm_SHA3_384_KEY_GEN
    , MechanismId Gen.ckm_SHA3_512
    , MechanismId Gen.ckm_SHA3_512_HMAC
    , MechanismId Gen.ckm_SHA3_512_HMAC_GENERAL
    , MechanismId Gen.ckm_SHA3_512_KEY_GEN
    , MechanismId Gen.ckm_CAST_KEY_GEN
    , MechanismId Gen.ckm_CAST_ECB
    , MechanismId Gen.ckm_CAST_CBC
    , MechanismId Gen.ckm_CAST_CBC_PAD
    , MechanismId Gen.ckm_CAST3_KEY_GEN
    , MechanismId Gen.ckm_CAST3_ECB
    , MechanismId Gen.ckm_CAST3_CBC
    , MechanismId Gen.ckm_CAST3_CBC_PAD
    , MechanismId Gen.ckm_CAST128_KEY_GEN
    , MechanismId Gen.ckm_CAST128_ECB
    , MechanismId Gen.ckm_CAST128_CBC
    , MechanismId Gen.ckm_CAST128_CBC_PAD
    , MechanismId Gen.ckm_RC5_KEY_GEN
    , MechanismId Gen.ckm_IDEA_KEY_GEN
    , MechanismId Gen.ckm_IDEA_ECB
    , MechanismId Gen.ckm_IDEA_CBC
    , MechanismId Gen.ckm_IDEA_CBC_PAD
    , MechanismId Gen.ckm_GENERIC_SECRET_KEY_GEN
    , MechanismId Gen.ckm_CONCATENATE_BASE_AND_KEY
    , MechanismId Gen.ckm_CONCATENATE_BASE_AND_DATA
    , MechanismId Gen.ckm_CONCATENATE_DATA_AND_BASE
    , MechanismId Gen.ckm_XOR_BASE_AND_DATA
    , MechanismId Gen.ckm_EXTRACT_KEY_FROM_KEY
    , MechanismId Gen.ckm_SSL3_PRE_MASTER_KEY_GEN
    , MechanismId Gen.ckm_SSL3_MASTER_KEY_DERIVE
    , MechanismId Gen.ckm_SSL3_KEY_AND_MAC_DERIVE
    , MechanismId Gen.ckm_SSL3_MASTER_KEY_DERIVE_DH
    , MechanismId Gen.ckm_TLS_PRE_MASTER_KEY_GEN
    , MechanismId Gen.ckm_TLS_MASTER_KEY_DERIVE
    , MechanismId Gen.ckm_TLS_KEY_AND_MAC_DERIVE
    , MechanismId Gen.ckm_TLS_MASTER_KEY_DERIVE_DH
    , MechanismId Gen.ckm_TLS_PRF
    , MechanismId Gen.ckm_SSL3_MD5_MAC
    , MechanismId Gen.ckm_SSL3_SHA1_MAC
    , MechanismId Gen.ckm_MD5_KEY_DERIVATION
    , MechanismId Gen.ckm_SHA1_KEY_DERIVATION
    , MechanismId Gen.ckm_SHA256_KEY_DERIVATION
    , MechanismId Gen.ckm_SHA384_KEY_DERIVATION
    , MechanismId Gen.ckm_SHA512_KEY_DERIVATION
    , MechanismId Gen.ckm_SHA224_KEY_DERIVATION
    , MechanismId Gen.ckm_SHA3_256_KEY_DERIVATION
    , MechanismId Gen.ckm_SHA3_224_KEY_DERIVATION
    , MechanismId Gen.ckm_SHA3_384_KEY_DERIVATION
    , MechanismId Gen.ckm_SHA3_512_KEY_DERIVATION
    , MechanismId Gen.ckm_SHAKE_128_KEY_DERIVATION
    , MechanismId Gen.ckm_SHAKE_256_KEY_DERIVATION
    , MechanismId Gen.ckm_PBE_MD5_DES_CBC
    , MechanismId Gen.ckm_PBE_MD5_CAST_CBC
    , MechanismId Gen.ckm_PBE_MD5_CAST3_CBC
    , MechanismId Gen.ckm_PBE_MD5_CAST128_CBC
    , MechanismId Gen.ckm_PBE_SHA1_CAST128_CBC
    , MechanismId Gen.ckm_PBE_SHA1_RC4_128
    , MechanismId Gen.ckm_PBE_SHA1_RC4_40
    , MechanismId Gen.ckm_PBE_SHA1_DES3_EDE_CBC
    , MechanismId Gen.ckm_PBE_SHA1_DES2_EDE_CBC
    , MechanismId Gen.ckm_PBE_SHA1_RC2_128_CBC
    , MechanismId Gen.ckm_PBE_SHA1_RC2_40_CBC
    , MechanismId Gen.ckm_SP800_108_COUNTER_KDF
    , MechanismId Gen.ckm_SP800_108_FEEDBACK_KDF
    , MechanismId Gen.ckm_SP800_108_DOUBLE_PIPELINE_KDF
    , MechanismId Gen.ckm_PKCS5_PBKD2
    , MechanismId Gen.ckm_WTLS_PRE_MASTER_KEY_GEN
    , MechanismId Gen.ckm_TLS12_KDF
    , MechanismId Gen.ckm_TLS12_MASTER_KEY_DERIVE
    , MechanismId Gen.ckm_TLS12_KEY_AND_MAC_DERIVE
    , MechanismId Gen.ckm_TLS12_MASTER_KEY_DERIVE_DH
    , MechanismId Gen.ckm_TLS12_KEY_SAFE_DERIVE
    , MechanismId Gen.ckm_TLS_KDF
    , MechanismId Gen.ckm_CAMELLIA_KEY_GEN
    , MechanismId Gen.ckm_CAMELLIA_ECB
    , MechanismId Gen.ckm_CAMELLIA_CBC
    , MechanismId Gen.ckm_CAMELLIA_MAC
    , MechanismId Gen.ckm_CAMELLIA_MAC_GENERAL
    , MechanismId Gen.ckm_CAMELLIA_CBC_PAD
    , MechanismId Gen.ckm_CAMELLIA_ECB_ENCRYPT_DATA
    , MechanismId Gen.ckm_CAMELLIA_CBC_ENCRYPT_DATA
    , MechanismId Gen.ckm_CAMELLIA_CTR
    , MechanismId Gen.ckm_ARIA_KEY_GEN
    , MechanismId Gen.ckm_ARIA_ECB
    , MechanismId Gen.ckm_ARIA_CBC
    , MechanismId Gen.ckm_ARIA_MAC
    , MechanismId Gen.ckm_ARIA_MAC_GENERAL
    , MechanismId Gen.ckm_ARIA_CBC_PAD
    , MechanismId Gen.ckm_ARIA_ECB_ENCRYPT_DATA
    , MechanismId Gen.ckm_ARIA_CBC_ENCRYPT_DATA
    , MechanismId Gen.ckm_SEED_KEY_GEN
    , MechanismId Gen.ckm_SEED_ECB
    , MechanismId Gen.ckm_SEED_CBC
    , MechanismId Gen.ckm_SEED_CBC_PAD
    , MechanismId Gen.ckm_SEED_ECB_ENCRYPT_DATA
    , MechanismId Gen.ckm_SEED_CBC_ENCRYPT_DATA
    , MechanismId Gen.ckm_SKIPJACK_KEY_GEN
    , MechanismId Gen.ckm_BATON_KEY_GEN
    , MechanismId Gen.ckm_EC_KEY_PAIR_GEN
    , MechanismId Gen.ckm_ECDSA
    , MechanismId Gen.ckm_ECDSA_SHA1
    , MechanismId Gen.ckm_ECDSA_SHA224
    , MechanismId Gen.ckm_ECDSA_SHA256
    , MechanismId Gen.ckm_ECDSA_SHA384
    , MechanismId Gen.ckm_ECDSA_SHA512
    , MechanismId Gen.ckm_ECDSA_SHA3_224
    , MechanismId Gen.ckm_ECDSA_SHA3_256
    , MechanismId Gen.ckm_ECDSA_SHA3_384
    , MechanismId Gen.ckm_ECDSA_SHA3_512
    , MechanismId Gen.ckm_ECDH1_DERIVE
    , MechanismId Gen.ckm_ECDH1_COFACTOR_DERIVE
    , MechanismId Gen.ckm_ECDH_AES_KEY_WRAP
    , MechanismId Gen.ckm_RSA_AES_KEY_WRAP
    , MechanismId Gen.ckm_EC_EDWARDS_KEY_PAIR_GEN
    , MechanismId Gen.ckm_EC_MONTGOMERY_KEY_PAIR_GEN
    , MechanismId Gen.ckm_EDDSA
    , MechanismId Gen.ckm_JUNIPER_KEY_GEN
    , MechanismId Gen.ckm_AES_XTS
    , MechanismId Gen.ckm_AES_XTS_KEY_GEN
    , MechanismId Gen.ckm_AES_KEY_GEN
    , MechanismId Gen.ckm_AES_ECB
    , MechanismId Gen.ckm_AES_CBC
    , MechanismId Gen.ckm_AES_MAC
    , MechanismId Gen.ckm_AES_MAC_GENERAL
    , MechanismId Gen.ckm_AES_CBC_PAD
    , MechanismId Gen.ckm_AES_CTR
    , MechanismId Gen.ckm_AES_GCM
    , MechanismId Gen.ckm_AES_CCM
    , MechanismId Gen.ckm_AES_CTS
    , MechanismId Gen.ckm_AES_CMAC
    , MechanismId Gen.ckm_AES_CMAC_GENERAL
    , MechanismId Gen.ckm_AES_XCBC_MAC
    , MechanismId Gen.ckm_AES_XCBC_MAC_96
    , MechanismId Gen.ckm_AES_GMAC
    , MechanismId Gen.ckm_BLOWFISH_KEY_GEN
    , MechanismId Gen.ckm_BLOWFISH_CBC
    , MechanismId Gen.ckm_TWOFISH_KEY_GEN
    , MechanismId Gen.ckm_BLOWFISH_CBC_PAD
    , MechanismId Gen.ckm_DES_ECB_ENCRYPT_DATA
    , MechanismId Gen.ckm_DES_CBC_ENCRYPT_DATA
    , MechanismId Gen.ckm_DES3_ECB_ENCRYPT_DATA
    , MechanismId Gen.ckm_DES3_CBC_ENCRYPT_DATA
    , MechanismId Gen.ckm_AES_ECB_ENCRYPT_DATA
    , MechanismId Gen.ckm_AES_CBC_ENCRYPT_DATA
    , MechanismId Gen.ckm_GOST28147_KEY_GEN
    , MechanismId Gen.ckm_CHACHA20_KEY_GEN
    , MechanismId Gen.ckm_CHACHA20
    , MechanismId Gen.ckm_POLY1305_KEY_GEN
    , MechanismId Gen.ckm_POLY1305
    , MechanismId Gen.ckm_EC_KEY_PAIR_GEN_W_EXTRA_BITS
    , MechanismId Gen.ckm_DSA_PARAMETER_GEN
    , MechanismId Gen.ckm_DH_PKCS_PARAMETER_GEN
    , MechanismId Gen.ckm_X9_42_DH_PARAMETER_GEN
    , MechanismId Gen.ckm_AES_OFB
    , MechanismId Gen.ckm_AES_CFB8
    , MechanismId Gen.ckm_AES_CFB128
    , MechanismId Gen.ckm_AES_CFB1
    , MechanismId Gen.ckm_AES_KEY_WRAP
    , MechanismId Gen.ckm_AES_KEY_WRAP_PAD
    , MechanismId Gen.ckm_AES_KEY_WRAP_KWP
    , MechanismId Gen.ckm_AES_KEY_WRAP_PKCS7
    , MechanismId Gen.ckm_SHA_1_KEY_GEN
    , MechanismId Gen.ckm_SHA224_KEY_GEN
    , MechanismId Gen.ckm_SHA256_KEY_GEN
    , MechanismId Gen.ckm_SHA384_KEY_GEN
    , MechanismId Gen.ckm_SHA512_KEY_GEN
    , MechanismId Gen.ckm_SHA512_224_KEY_GEN
    , MechanismId Gen.ckm_SHA512_256_KEY_GEN
    , MechanismId Gen.ckm_SHA512_T_KEY_GEN
    , MechanismId Gen.ckm_BLAKE2B_160
    , MechanismId Gen.ckm_BLAKE2B_160_HMAC
    , MechanismId Gen.ckm_BLAKE2B_160_HMAC_GENERAL
    , MechanismId Gen.ckm_BLAKE2B_160_KEY_DERIVE
    , MechanismId Gen.ckm_BLAKE2B_160_KEY_GEN
    , MechanismId Gen.ckm_BLAKE2B_256
    , MechanismId Gen.ckm_BLAKE2B_256_HMAC
    , MechanismId Gen.ckm_BLAKE2B_256_HMAC_GENERAL
    , MechanismId Gen.ckm_BLAKE2B_256_KEY_DERIVE
    , MechanismId Gen.ckm_BLAKE2B_256_KEY_GEN
    , MechanismId Gen.ckm_BLAKE2B_384
    , MechanismId Gen.ckm_BLAKE2B_384_HMAC
    , MechanismId Gen.ckm_BLAKE2B_384_HMAC_GENERAL
    , MechanismId Gen.ckm_BLAKE2B_384_KEY_DERIVE
    , MechanismId Gen.ckm_BLAKE2B_384_KEY_GEN
    , MechanismId Gen.ckm_BLAKE2B_512
    , MechanismId Gen.ckm_BLAKE2B_512_HMAC
    , MechanismId Gen.ckm_BLAKE2B_512_HMAC_GENERAL
    , MechanismId Gen.ckm_BLAKE2B_512_KEY_DERIVE
    , MechanismId Gen.ckm_BLAKE2B_512_KEY_GEN
    , MechanismId Gen.ckm_CHACHA20_POLY1305
    , MechanismId Gen.ckm_HKDF_DERIVE
    , MechanismId Gen.ckm_HKDF_DATA
    , MechanismId Gen.ckm_HKDF_KEY_GEN
    , MechanismId Gen.ckm_SALSA20_KEY_GEN
    , MechanismId Gen.ckm_IKE2_PRF_PLUS_DERIVE
    , MechanismId Gen.ckm_IKE_PRF_DERIVE
    , MechanismId Gen.ckm_IKE1_PRF_DERIVE
    , MechanismId Gen.ckm_IKE1_EXTENDED_DERIVE
    , MechanismId Gen.ckm_ECDH_X_AES_KEY_WRAP
    , MechanismId Gen.ckm_ECDH_COF_AES_KEY_WRAP
    ]
    (behaviorIds reg)
  -- The full header inventory (464 canonical ids) is folded in
  -- from the generated table; pin the cardinality, the reviewed
  -- members, ascending order, and the catalog projection.
  let inv = inventoryIds reg
  assertEqual "inventory cardinality" 464 (length inv)
  assertBool "inventory ascending" (inv == sort inv)
  mapM_ (\i -> assertBool ("inventory member " ++ show i) (i `elem` inv))
    [ MechanismId 0x0
    , MechanismId 0x250
    , MechanismId 0x251
    , MechanismId 0x1080
    , MechanismId 0x1082
    , MechanismId 0x1087
    ]
  assertEqual "catalog projection covers inventory"
    inv (mechanismList reg)

caseJsonProjection :: IO ()
caseJsonProjection = do
  -- The reviewed head stays pinned verbatim; the 330 generated
  -- catalog-only rows are pinned by count + full file equality (the
  -- file is generator output; equality proves the Haskell registry
  -- matches the JSON catalog byte-for-byte, and
  -- check-denominators.py proves the JSON matches the headers).
  let expectedHead =
        [ "schema 1"
        , "mech|0x00000250|CKM_SHA256||digest|no-params/1|not-applicable:0-0|digest:A16,A37,A39"
        , "mech|0x00000251|CKM_SHA256_HMAC||mac|no-params/1|mechanism-specific:0-0|sign:A37,A39;verify:A37,A39"
        , "mech|0x00001080|CKM_AES_KEY_GEN||keygen|no-params/1|bits:128-256|generate-key:A37"
        , "mech|0x00000350|CKM_GENERIC_SECRET_KEY_GEN||keygen|no-params/1|bits:8-2040|generate-key:A37"
        , "mech|0x00001082|CKM_AES_CBC||cipher|iv-bytes/1|bytes:16-32|authenticated-unwrap:A23,A37;authenticated-wrap:A23,A37;decrypt:A16,A37,A39;encrypt:A16,A37,A39;unwrap:A20,A37,A39;wrap:A20,A37,A39"
        , "mech|0x00001087|CKM_AES_GCM||aead|gcm-params/1|bytes:16-32|decrypt:A16,A37,A39;encrypt:A16,A37,A39"
        ]
      dumpLines = T.lines (dumpRegistry curatedRegistry)
  -- Order-free: behavior sorts by id, so new low-id promotions sort
  -- ahead of the seed rows; every reviewed line must still be present
  -- verbatim (the AES-CBC pin extends to the promoted routes).
  mapM_ (\line -> assertBool ("reviewed line present: " ++ T.unpack line)
    (line `elem` dumpLines)) expectedHead
  -- schema + 315 behavior + 149 catalog-only + catalog line.
  assertEqual "dump line count" 466 (length dumpLines)
  assertEqual "behavior line count" 315
    (length (filter ("mech|" `T.isPrefixOf`) dumpLines))
  assertEqual "catalog-only line count" 149
    (length (filter ("inv|" `T.isPrefixOf`) dumpLines))
  catalogLine <- case reverse dumpLines of
    (c : _) -> pure c
    [] -> assertFailure "dumpLines empty"
  assertBool "catalog line prefix" ("catalog|0x00000000," `T.isPrefixOf` catalogLine)
  assertEqual "catalog id count" 464
    (length (T.splitOn "," (T.drop (T.length "catalog|") catalogLine)))
  content <- TIO.readFile "spec/mechanisms-canonical.txt"
  assertEqual "json projection" dumpLines (T.lines (T.strip content))

casePromote :: IO ()
casePromote = do
  -- Promote a real catalog-only row (CKM_SKIPJACK_CBC64, 0x1002)
  -- with a test-local descriptor: behavior appears, inventory is
  -- unchanged, and executability follows caps.
  let sj = MechanismId 0x1002
      reg = curatedRegistry
  assertEqual "sj starts catalog-only" StatusCatalogOnly (describeStatus reg sj)
  let d = (mkTestDesc sj "CKM_SKIPJACK_CBC64" (Just testCodec) [testRoute OpEncrypt])
        { descFamily = FamilyCipher }
  regP <- expectRight (promoteInventory reg d)
  assertEqual "sj promoted" StatusSupported (describeStatus regP sj)
  assertEqual "inventory unchanged" (inventoryIds reg) (inventoryIds regP)
  assertEqual "catalog unchanged" (mechanismList reg) (mechanismList regP)
  case lookupBehavior regP sj of
    Nothing -> assertFailure "promoted behavior must resolve"
    Just got -> assertEqual "promoted canonical" "CKM_SKIPJACK_CBC64" (descCanonical got)
  let caps = mkCapabilities [(sj, OpEncrypt)]
  assertBool "promoted row executable with caps"
    (isExecutable regP caps sj OpEncrypt)
  assertBool "unpermitted op stays down"
    (not (isExecutable regP caps sj OpDecrypt))

casePromoteReject :: IO ()
casePromoteReject = do
  let reg = curatedRegistry
      sj = MechanismId 0x1002
      d = mkTestDesc sj "CKM_SKIPJACK_CBC64" (Just testCodec) [testRoute OpDigest]
  -- Unknown id.
  case promoteInventory reg (d { descId = MechanismId 0x4712 }) of
    Left (UnknownCatalogMember _) -> pure ()
    other -> assertFailure ("unknown promote must reject, got: " ++ show other)
  -- Id that already has behavior.
  case promoteInventory reg
         (d { descId = MechanismId 0x250, descCanonical = "CKM_SHA256" }) of
    Left (DuplicateMechanism _) -> pure ()
    other -> assertFailure ("behavior promote must reject, got: " ++ show other)
  -- Canonical rename.
  case promoteInventory reg (d { descCanonical = "CKM_RENAMED" }) of
    Left (PromoteMismatch _ _ _) -> pure ()
    other -> assertFailure ("renamed promote must reject, got: " ++ show other)
  -- Missing codec / policy still rejected on the promote path.
  case promoteInventory reg (d { descCodec = Nothing }) of
    Left (MissingCodec _) -> pure ()
    other -> assertFailure ("codeless promote must reject, got: " ++ show other)
  case promoteInventory reg (d { descRoutes = [] }) of
    Left (MissingPolicy _ _) -> pure ()
    other -> assertFailure ("routeless promote must reject, got: " ++ show other)

caseKeyMgmtPromoted :: IO ()
caseKeyMgmtPromoted = do
  -- The key-management behaviors promote from
  -- catalog-only to supported, with executable routes under caps.
  let cases =
        [ (MechanismId 0x1040, "CKM_EC_KEY_PAIR_GEN", [OpGenerateKeyPair])
        , (MechanismId 0x0, "CKM_RSA_PKCS_KEY_PAIR_GEN", [OpGenerateKeyPair])
        , (MechanismId 0x0f, "CKM_ML_KEM_KEY_PAIR_GEN", [OpGenerateKeyPair])
        , (MechanismId 0x10, "CKM_DSA_KEY_PAIR_GEN", [OpGenerateKeyPair])
        , (MechanismId 0x2000, "CKM_DSA_PARAMETER_GEN", [OpGenerateKey])
        , (MechanismId 0x2002, "CKM_X9_42_DH_PARAMETER_GEN", [OpGenerateKey])
        , (MechanismId 0x402a, "CKM_HKDF_DERIVE", [OpDerive])
        , (MechanismId 0x17, "CKM_ML_KEM", [OpEncapsulate, OpDecapsulate])
        ]
  mapM_ checkOne cases
  -- Alias promotion: the ECDSA_KEY_PAIR_GEN spelling shares 0x1040.
  case lookupByName curatedRegistry "CKM_ECDSA_KEY_PAIR_GEN" of
    Nothing -> assertFailure "ECDSA_KEY_PAIR_GEN alias must resolve"
    Just d -> assertEqual "alias canonical" "CKM_EC_KEY_PAIR_GEN" (descCanonical d)
  where
    checkOne (mid, name, ops) = do
      let reg = curatedRegistry
          tag = T.unpack name
      assertEqual (tag ++ " supported") StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure (tag ++ " behavior must resolve")
        Just d -> do
          assertEqual (tag ++ " canonical") name (descCanonical d)
          assertEqual (tag ++ " routes") ops
            (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool (tag ++ " executable " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op)) ops

caseAesCbcWrap :: IO ()
caseAesCbcWrap = do
  -- AES-CBC gains the wrap/unwrap/authenticated
  -- routes alongside encrypt/decrypt.
  let reg = curatedRegistry
      mid = MechanismId 0x1082
  case lookupBehavior reg mid of
    Nothing -> assertFailure "AES-CBC behavior must resolve"
    Just d -> assertEqual "AES-CBC routes"
      [OpEncrypt, OpDecrypt, OpWrap, OpUnwrap, OpAuthWrap, OpAuthUnwrap]
      (map routeOperation (descRoutes d))
  let caps = mkCapabilities [(mid, OpWrap), (mid, OpUnwrap)]
  assertBool "wrap executable" (isExecutable reg caps mid OpWrap)
  assertBool "unwrap executable" (isExecutable reg caps mid OpUnwrap)

caseDigestPromoted :: IO ()
caseDigestPromoted = do
  -- The 12 new digest behaviors resolve with the digest route
  -- and execute under caps. (SHA-256 was in the seed set.) The
  -- four BLAKE2B rows resolve the same way.
  let mids =
        [ MechanismId 0x48, MechanismId 0x4c
        , MechanismId 0x210, MechanismId 0x220, MechanismId 0x240
        , MechanismId 0x255, MechanismId 0x260, MechanismId 0x270
        , MechanismId 0x2b0, MechanismId 0x2b5
        , MechanismId 0x2c0, MechanismId 0x2d0
        , MechanismId 0x400c, MechanismId 0x4011
        , MechanismId 0x4016, MechanismId 0x401b
        ]
  mapM_ checkOne mids
  where
    checkOne mid = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("digest route " ++ show mid) [OpDigest]
          (map routeOperation (descRoutes d))
      assertBool ("executable " ++ show mid)
        (isExecutable reg (mkCapabilities [(mid, OpDigest)]) mid OpDigest)

caseCipherPromoted :: IO ()
caseCipherPromoted = do
  -- The 8 new block-cipher behaviors resolve with the
  -- encrypt/decrypt routes and execute under caps. (AES-CBC was in the seed set;
  -- caseAesCbcWrap pins its wrap routes.)
  let mids =
        [ MechanismId 0x1081, MechanismId 0x1085
        , MechanismId 0x132, MechanismId 0x133
        , MechanismId 0x551, MechanismId 0x552
        , MechanismId 0x561, MechanismId 0x562
        ]
  mapM_ checkOne mids
  where
    checkOne mid = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("cipher routes " ++ show mid) [OpEncrypt, OpDecrypt]
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        [OpEncrypt, OpDecrypt]

caseRsaPromoted :: IO ()
caseRsaPromoted = do
  -- The 12 RSA v1.5 behaviors resolve with the sign/verify
  -- routes and execute under caps; the raw row additionally
  -- serves wrap/unwrap (the digest rows are signature-only).
  mapM_ (checkOne [OpSign, OpVerify])
    [ MechanismId 0x05
    , MechanismId 0x06, MechanismId 0x08
    , MechanismId 0x40, MechanismId 0x41
    , MechanismId 0x42, MechanismId 0x46
    , MechanismId 0x60, MechanismId 0x61
    , MechanismId 0x62, MechanismId 0x66
    ]
  checkOne [OpSign, OpVerify, OpWrap, OpUnwrap] (MechanismId 0x01)
  where
    checkOne ops mid = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("rsa routes " ++ show mid) ops
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        ops

caseRsaPssOaepPromoted :: IO ()
caseRsaPssOaepPromoted = do
  -- The 10 PSS behaviors resolve with sign/verify routes and
  -- the OAEP behavior with encrypt/decrypt/wrap/unwrap routes;
  -- all execute under caps.
  mapM_ (checkOne [OpSign, OpVerify])
    [ MechanismId 0x0d, MechanismId 0x0e
    , MechanismId 0x43, MechanismId 0x44, MechanismId 0x45
    , MechanismId 0x47, MechanismId 0x63, MechanismId 0x64
    , MechanismId 0x65, MechanismId 0x67
    ]
  checkOne [OpEncrypt, OpDecrypt, OpWrap, OpUnwrap] (MechanismId 0x09)
  where
    checkOne ops mid = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("routes " ++ show mid) ops
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op)) ops

caseEcdsaPromoted :: IO ()
caseEcdsaPromoted = do
  -- The 10 ECDSA behaviors resolve with the sign/verify routes
  -- and execute under caps.
  let mids = map MechanismId
        [0x1041, 0x1042, 0x1043, 0x1044, 0x1045
        , 0x1046, 0x1047, 0x1048, 0x1049, 0x104a
        ]
  mapM_ checkOne mids
  where
    checkOne mid = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("ecdsa routes " ++ show mid) [OpSign, OpVerify]
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        [OpSign, OpVerify]

caseEcdhPromoted :: IO ()
caseEcdhPromoted = do
  -- S10: the 2 ECDH behaviors resolve with the derive route and
  -- execute under caps.
  let mids = map MechanismId [0x1050, 0x1051]
  mapM_ checkOne mids
  where
    checkOne mid = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("ecdh routes " ++ show mid) [OpDerive]
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        [OpDerive]

caseCmacPromoted :: IO ()
caseCmacPromoted = do
  -- S11: the 4 CMAC behaviors resolve with the sign/verify routes
  -- and execute under caps.
  let mids = map MechanismId [0x108a, 0x108b, 0x137, 0x138]
  mapM_ checkOne mids
  where
    checkOne mid = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("cmac routes " ++ show mid) [OpSign, OpVerify]
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        [OpSign, OpVerify]

caseKdfPromoted :: IO ()
caseKdfPromoted = do
  -- S12: the 16 KDF behaviors (11 SHA, 4 BLAKE2B, PBKD2)
  -- resolve with the derive route and execute under caps; PBKD2
  -- carries a second, generate-key route over the same frame.
  mapM_ checkOne
    ([ (MechanismId mid, [OpDerive])
     | mid <- [0x4b, 0x4f, 0x392, 0x393, 0x394, 0x395
              , 0x396, 0x397, 0x398, 0x399, 0x39a
              , 0x400f, 0x4014, 0x4019, 0x401e
              ]
     ] ++ [(MechanismId 0x3b0, [OpDerive, OpGenerateKey])])
  where
    checkOne (mid, ops) = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("kdf routes " ++ show mid) ops
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        ops

caseOtpPromoted :: IO ()
caseOtpPromoted = do
  -- S13: the HOTP behavior resolves with the sign/verify routes and
  -- the KEY_GEN behavior with the generate-key route; both execute
  -- under caps.
  mapM_ checkOne
    [ (MechanismId 0x291, [OpSign, OpVerify])
    , (MechanismId 0x290, [OpGenerateKey])
    ]
  where
    checkOne (mid, ops) = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("otp routes " ++ show mid) ops
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        ops

caseSp800Promoted :: IO ()
caseSp800Promoted = do
  -- S14: the 3 SP 800-108 behaviors (counter, feedback,
  -- double-pipeline) resolve with the derive route and execute
  -- under caps.
  mapM_ checkOne
    [ (MechanismId 0x3ac, [OpDerive])
    , (MechanismId 0x3ad, [OpDerive])
    , (MechanismId 0x3ae, [OpDerive])
    ]
  where
    checkOne (mid, ops) = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("sp800 routes " ++ show mid) ops
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        ops

caseTlsKdfPromoted :: IO ()
caseTlsKdfPromoted = do
  -- S14: the 8 TLS-KDF behaviors (TLS 1.0 master pair, TLS 1.2
  -- master pair, extended-master pair, free-label pair) resolve
  -- with the derive route and execute under caps.
  mapM_ checkOne
    [ (MechanismId 0x375, [OpDerive])
    , (MechanismId 0x377, [OpDerive])
    , (MechanismId 0x3e0, [OpDerive])
    , (MechanismId 0x3e2, [OpDerive])
    , (MechanismId 0x56, [OpDerive])
    , (MechanismId 0x57, [OpDerive])
    , (MechanismId 0x3d9, [OpDerive])
    , (MechanismId 0x3e5, [OpDerive])
    ]
  where
    checkOne (mid, ops) = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("tls-kdf routes " ++ show mid) ops
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        ops

casePbePromoted :: IO ()
casePbePromoted = do
  -- S14: the 11 PBE behaviors (DES3, DES2, SHA1
  -- CAST128/RC4/RC2, MD5 DES/CAST/CAST3/CAST128) resolve with
  -- the generate-key route and execute under caps.
  mapM_ checkOne
    [ (MechanismId 0x3a8, [OpGenerateKey])
    , (MechanismId 0x3a9, [OpGenerateKey])
    , (MechanismId 0x3a5, [OpGenerateKey])
    , (MechanismId 0x3a6, [OpGenerateKey])
    , (MechanismId 0x3a7, [OpGenerateKey])
    , (MechanismId 0x3aa, [OpGenerateKey])
    , (MechanismId 0x3ab, [OpGenerateKey])
    , (MechanismId 0x3a1, [OpGenerateKey])
    , (MechanismId 0x3a2, [OpGenerateKey])
    , (MechanismId 0x3a3, [OpGenerateKey])
    , (MechanismId 0x3a4, [OpGenerateKey])
    ]
  where
    checkOne (mid, ops) = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("pbe routes " ++ show mid) ops
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        ops

caseIkePromoted :: IO ()
caseIkePromoted = do
  -- S14: the 4 IKE behaviors (v2 prf+, IKE PRF, v1 PRF,
  -- v1 extended) resolve with the derive route and execute
  -- under caps.
  mapM_ checkOne
    [ (MechanismId 0x402e, [OpDerive])
    , (MechanismId 0x402f, [OpDerive])
    , (MechanismId 0x4030, [OpDerive])
    , (MechanismId 0x4031, [OpDerive])
    ]
  where
    checkOne (mid, ops) = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("ike routes " ++ show mid) ops
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        ops

caseByteOpsPromoted :: IO ()
caseByteOpsPromoted = do
  -- S14: the 5 byte-op behaviors (concat-key, the two
  -- data concats, XOR, EXTRACT) resolve with the derive
  -- route and execute under caps.
  mapM_ checkOne
    [ (MechanismId 0x360, [OpDerive])
    , (MechanismId 0x362, [OpDerive])
    , (MechanismId 0x363, [OpDerive])
    , (MechanismId 0x364, [OpDerive])
    , (MechanismId 0x365, [OpDerive])
    ]
  where
    checkOne (mid, ops) = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("byte-op routes " ++ show mid) ops
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        ops

caseKeyMatPromoted :: IO ()
caseKeyMatPromoted = do
  -- S14: the 3 key-material behaviors (TLS 1.0, TLS 1.2,
  -- TLS 1.2 safe) resolve with the derive route and execute
  -- under caps.
  mapM_ checkOne
    [ (MechanismId 0x376, [OpDerive])
    , (MechanismId 0x3e1, [OpDerive])
    , (MechanismId 0x3e3, [OpDerive])
    ]
  where
    checkOne (mid, ops) = do
      let reg = curatedRegistry
      assertEqual ("supported " ++ show mid) StatusSupported (describeStatus reg mid)
      case lookupBehavior reg mid of
        Nothing -> assertFailure ("behavior must resolve " ++ show mid)
        Just d -> assertEqual ("keymat routes " ++ show mid) ops
          (map routeOperation (descRoutes d))
      mapM_ (\op -> assertBool ("executable " ++ show mid ++ " " ++ show op)
        (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
        ops

caseCatalogOnlyNeverExecutes :: IO ()
caseCatalogOnlyNeverExecutes = do
  -- S15 honesty guard: every catalog-only id from the canonical
  -- projection reports StatusCatalogOnly and refuses execution
  -- under FULLY GRANTED caps, for every operation. A behavior
  -- descriptor added without JSON promotion (or vice versa) fails
  -- the byte-equality case; this case fails a registry that
  -- executes catalog rows.
  content <- TIO.readFile "spec/mechanisms-canonical.txt"
  let invIds =
        [ MechanismId (parseHex w)
        | line <- T.lines content
        , "inv|" `T.isPrefixOf` line
        , let w = T.splitOn "|" line !! 1
        ]
      allOps = [minBound .. maxBound] :: [Operation]
      reg = curatedRegistry
  assertEqual "guard covers every catalog row" 149 (length invIds)
  mapM_ (checkOne reg allOps) invIds
  where
    parseHex w = case reads (T.unpack w) :: [(Word, String)] of
      [(n, "")] -> fromIntegral n
      _ -> error ("bad canonical id: " ++ T.unpack w)
    checkOne reg allOps mid = do
      assertEqual ("catalog " ++ show mid) StatusCatalogOnly (describeStatus reg mid)
      let caps = mkCapabilities [(mid, op) | op <- allOps]
      mapM_ (\op -> assertBool ("refuses " ++ show mid ++ " " ++ show op)
        (not (isExecutable reg caps mid op))) allOps

caseSpecialsCatalogOnly :: IO ()
caseSpecialsCatalogOnly = do
  -- S15: one named representative per reviewed gap group stays
  -- catalog-only with its headline operation refused under
  -- granted caps (the exhaustive guard above covers all 315;
  -- this table documents the groups for humans). The 11n
  -- vendor stances pin in full: both rows per OTP vendor plus
  -- the FASTHASH digest row. DES/RC4 left when the legacy
  -- provider landed (11p); the 11p fetch-absent stances pin one
  -- cipher row per absent family. KW-PKCS7 left when the
  -- wrap-composition slice served it (11s-1).
  let reg = curatedRegistry
      reps =
        [ ("CKM_ACTI", OpSign)
        , ("CKM_ACTI_KEY_GEN", OpGenerateKey)
        , ("CKM_XMSS", OpSign)
        , ("CKM_HSS", OpSign)
        , ("CKM_SECURID", OpSign)
        , ("CKM_SECURID_KEY_GEN", OpGenerateKey)
        , ("CKM_FASTHASH", OpDigest)
        , ("CKM_CMS_SIG", OpSign)
        , ("CKM_FORTEZZA_TIMESTAMP", OpSign)
        , ("CKM_RC5_CBC", OpEncrypt)
        , ("CKM_CDMF_CBC", OpEncrypt)
        , ("CKM_SKIPJACK_CBC64", OpEncrypt)
        , ("CKM_BATON_CBC128", OpEncrypt)
        , ("CKM_JUNIPER_CBC128", OpEncrypt)
        , ("CKM_TWOFISH_CBC", OpEncrypt)
        , ("CKM_GOST28147_ECB", OpEncrypt)
        , ("CKM_DES_OFB8", OpEncrypt)
        , ("CKM_SALSA20", OpEncrypt)
        , ("CKM_DSA_PROBABILISTIC_PARAMETER_GEN", OpGenerateKey)
        , ("CKM_HASH_ML_DSA", OpSign)
        , ("CKM_RSA_X9_31_KEY_PAIR_GEN", OpGenerateKeyPair)
        , ("CKM_SHA512_T", OpDigest)
        , ("CKM_NULL", OpDigest)
        , ("CKM_VENDOR_DEFINED", OpDigest)
        ]
  mapM_ (checkOne reg) reps
  where
    checkOne reg (name, op) = do
      let mid = MechanismId (mustGeneratedId name)
      assertEqual ("catalog " ++ T.unpack name) StatusCatalogOnly (describeStatus reg mid)
      assertBool ("refuses " ++ T.unpack name)
        (not (isExecutable reg (mkCapabilities [(mid, op)]) mid op))
