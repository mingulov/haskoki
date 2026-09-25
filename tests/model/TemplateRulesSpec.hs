{- | Template-rule tests.

Template rules are data: @TEMPLATE_RULES@ in
@scripts/generate-attributes.py@ is the single source, emitted to
@spec/attributes.json@ (@template_rules@) and to
@Haskoki.Attribute.Generated@. These tests pin:

* generated CKO\/CKK\/CKM id resolution (production code carries no
  hand-typed numeric ids; expectations live here, cross-checked
  against the headers by @scripts/check-denominators.py@);
* rule-table consistency (every rule name maps to the model
  'AttributeType' inventory);
* 'checkRules' presence enforcement (missing-required refused,
  forbidden-present refused) at the unit level;
* planner integration: the reviewed requirements (AES
  @CKA_VALUE_LEN@, EC @CKA_EC_PARAMS@, RSA @CKA_MODULUS_BITS@) deny
  with the rule-citing reasons, and value-context forbiddens (wrong
  class\/key-type, malformed key-type, pair disagreements) refuse.
* the reviewed HOTP requirement (@CKA_VALUE_LEN@ for
  @CKO_SECRET_KEY@\/@CKK_HOTP@) denies with its rule-citing reason,
  and template value shapes enforce (wrong-type refused as
  inconsistent at creation, keygen, and pairgen paths alike).
-}
{-# LANGUAGE OverloadedStrings #-}
module TemplateRulesSpec (spec) where

import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , attributeTypeByName
  , shapeMatches
  )
import Haskoki.Attribute.Generated
  ( attributeIdByName
  , attributeNameById
  , classIdByName
  , classNameById
  , generatedAttributes
  , generatedClasses
  , generatedKeyTypes
  , generatedTemplateRules
  , keyTypeIdByName
  , keyTypeNameById
  )
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Object
  ( RuleDeny (..)
  , TemplateError (..)
  , TemplateRule (..)
  , checkRules
  , findRule
  , planCreateObject
  , validateTemplate
  )
import Haskoki.Operation (emptySessionOps)
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , aesKeyGenMech
  , ckkAes
  , ckkEc
  , ckkGenericSecret
  , ckkHotp
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , checkKeyTemplate
  , checkKeyTemplateAny
  , ecKeyPairGenMech
  , hotpKeyGenMech
  , planGenerateKey
  , planGenerateKeyPair
  , rsaKeyPairGenMech
  )
import Haskoki.Outcome (PlanResult (..), Rejection (..))
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated (generatedIdByName)
import Data.Maybe (isJust)
import qualified Haskoki.Registry.Generated as Gen
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( Generation (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Template rules"
  [ testCase "generated CKO ids resolve" caseClassIds
  , testCase "generated CKK ids resolve" caseKeyIds
  , testCase "generated CKM ids resolve" caseMechIds
  , testCase "generated CKM constants agree" caseMechConstants
  , testCase "descriptor names resolve" caseDescNames
  , testCase "generated CKA ids resolve" caseAttrIds
  , testCase "Inventory names CKA_ID and CKA_PUBLIC_EXPONENT" caseInventoryAttrs
  , testCase "keymgmt codes match generated ids" caseCodesMatch
  , testCase "rules table is consistent" caseRulesConsistent
  , testCase "findRule resolves constraining contexts" caseFindRule
  , testCase "checkRules refuses missing-required" caseMissingRequired
  , testCase "checkRules refuses forbidden-present" caseForbiddenPresent
  , testCase "AES keygen without VALUE_LEN is incomplete" caseAesMissingLen
  , testCase "EC pair without curve is incomplete" caseEcMissingCurve
  , testCase "EC pair off-set curve is mechanism-invalid" caseEcOffSetCurve
  , testCase "RSA pair without modulus bits is incomplete" caseRsaMissingBits
  , testCase "wrong class value is inconsistent" caseWrongClass
  , testCase "wrong key type value is inconsistent" caseWrongKeyType
  , testCase "malformed key type is inconsistent" caseMalformedKeyType
  , testCase "pair disagreements are inconsistent" casePairDisagree
  , testCase "HOTP keygen without VALUE_LEN is incomplete" caseHotpMissingLen
  , testCase "validateTemplate refuses wrong shapes" caseWrongShape
  , testCase "mistyped class is inconsistent at keygen" caseMistypedClassKeygen
  , testCase "mistyped class is inconsistent at creation" caseMistypedClassCreate
  , testCase "classless AES keygen defaults the class" caseClasslessAesKeygen
  , testCase "classless EC keypair defaults classes" caseClasslessEcKeypair
  , testCase "classless derive check defaults the class" caseClasslessDeriveCheck
  , testCase "classless unwrap check defaults the class" caseClasslessUnwrapCheck
  , testCase "unknown class value is rejected at creation" caseCreateUnknownClass
  ]

caseClassIds :: IO ()
caseClassIds = do
  assertEqual "CKO_DATA" (Just 0x00 :: Maybe Word64) (classIdByName "CKO_DATA")
  assertEqual "CKO_SECRET_KEY" (Just 0x04 :: Maybe Word64) (classIdByName "CKO_SECRET_KEY")
  assertEqual "CKO_PUBLIC_KEY" (Just 0x02 :: Maybe Word64) (classIdByName "CKO_PUBLIC_KEY")
  assertEqual "CKO_PRIVATE_KEY" (Just 0x03 :: Maybe Word64) (classIdByName "CKO_PRIVATE_KEY")
  assertEqual "class count" 13 (length generatedClasses)
  assertEqual "reverse 0x04" (Just "CKO_SECRET_KEY") (classNameById 0x04)
  assertEqual "unknown class" Nothing (classIdByName "CKO_NOPE")

caseKeyIds :: IO ()
caseKeyIds = do
  assertEqual "CKK_RSA" (Just 0x00 :: Maybe Word64) (keyTypeIdByName "CKK_RSA")
  assertEqual "CKK_EC" (Just 0x03 :: Maybe Word64) (keyTypeIdByName "CKK_EC")
  assertEqual "CKK_GENERIC_SECRET" (Just 0x10 :: Maybe Word64) (keyTypeIdByName "CKK_GENERIC_SECRET")
  assertEqual "CKK_AES" (Just 0x1F :: Maybe Word64) (keyTypeIdByName "CKK_AES")
  assertEqual "CKK_ML_KEM" (Just 0x49 :: Maybe Word64) (keyTypeIdByName "CKK_ML_KEM")
  assertEqual "key type count" 67 (length generatedKeyTypes)
  assertEqual "reverse 0x1F" (Just "CKK_AES") (keyTypeNameById 0x1F)
  assertEqual "unknown key type" Nothing (keyTypeIdByName "CKK_NOPE")

-- | Every literal descriptor name ('promotedDesc'\/digestDesc'
-- call sites, the remaining production 'mustGeneratedId' path)
-- resolves in the generated inventory.
caseDescNames :: IO ()
caseDescNames = mapM_ pin
  [ "CKM_EC_KEY_PAIR_GEN",
  "CKM_HKDF_DERIVE",
  "CKM_HOTP_KEY_GEN",
  "CKM_MD5",
  "CKM_ML_KEM",
  "CKM_ML_KEM_KEY_PAIR_GEN",
  "CKM_RIPEMD160",
  "CKM_SHA_1",
  "CKM_SHA224",
  "CKM_SHA3_224",
  "CKM_SHA3_256",
  "CKM_SHA3_384",
  "CKM_SHA3_512",
  "CKM_SHA384",
  "CKM_SHA512",
  "CKM_SHA512_224",
  "CKM_SHA512_256"
  ]
  where
    pin name = assertBool ("resolves: " ++ show name)
      (isJust (generatedIdByName name))

-- | Every converted static name resolves to its generated
-- @ckm_*@ constant — the conversion changed no id.
-- This pin documents the retirement of the last production mustGeneratedId static table: caseDescNames covers descriptor-literal heads; caseMechConstants below covers the converted static names.
caseMechConstants :: IO ()
caseMechConstants = mapM_ pin
  [ ("CKM_AES_CBC", Gen.ckm_AES_CBC),
  ("CKM_AES_CBC_PAD", Gen.ckm_AES_CBC_PAD),
  ("CKM_AES_CMAC", Gen.ckm_AES_CMAC),
  ("CKM_AES_CMAC_GENERAL", Gen.ckm_AES_CMAC_GENERAL),
  ("CKM_AES_ECB", Gen.ckm_AES_ECB),
  ("CKM_AES_KEY_GEN", Gen.ckm_AES_KEY_GEN),
  ("CKM_ARIA_CBC", Gen.ckm_ARIA_CBC),
  ("CKM_ARIA_ECB", Gen.ckm_ARIA_ECB),
  ("CKM_CAMELLIA_CBC", Gen.ckm_CAMELLIA_CBC),
  ("CKM_CAMELLIA_ECB", Gen.ckm_CAMELLIA_ECB),
  ("CKM_DES3_CBC", Gen.ckm_DES3_CBC),
  ("CKM_DES3_CMAC", Gen.ckm_DES3_CMAC),
  ("CKM_DES3_CMAC_GENERAL", Gen.ckm_DES3_CMAC_GENERAL),
  ("CKM_DES3_ECB", Gen.ckm_DES3_ECB),
  ("CKM_ECDH1_COFACTOR_DERIVE", Gen.ckm_ECDH1_COFACTOR_DERIVE),
  ("CKM_ECDH1_DERIVE", Gen.ckm_ECDH1_DERIVE),
  ("CKM_ECDH_AES_KEY_WRAP", Gen.ckm_ECDH_AES_KEY_WRAP),
  ("CKM_ECDSA", Gen.ckm_ECDSA),
  ("CKM_ECDSA_SHA256", Gen.ckm_ECDSA_SHA256),
  ("CKM_EC_KEY_PAIR_GEN", Gen.ckm_EC_KEY_PAIR_GEN),
  ("CKM_ECMQV_DERIVE", Gen.ckm_ECMQV_DERIVE),
  ("CKM_EDDSA", Gen.ckm_EDDSA),
  ("CKM_HKDF_DERIVE", Gen.ckm_HKDF_DERIVE),
  ("CKM_HOTP", Gen.ckm_HOTP),
  ("CKM_HOTP_KEY_GEN", Gen.ckm_HOTP_KEY_GEN),
  ("CKM_MD5", Gen.ckm_MD5),
  ("CKM_ML_KEM", Gen.ckm_ML_KEM),
  ("CKM_ML_KEM_KEY_PAIR_GEN", Gen.ckm_ML_KEM_KEY_PAIR_GEN),
  ("CKM_PKCS5_PBKD2", Gen.ckm_PKCS5_PBKD2),
  ("CKM_RIPEMD160", Gen.ckm_RIPEMD160),
  ("CKM_RSA_PKCS", Gen.ckm_RSA_PKCS),
  ("CKM_RSA_PKCS_KEY_PAIR_GEN", Gen.ckm_RSA_PKCS_KEY_PAIR_GEN),
  ("CKM_RSA_PKCS_OAEP", Gen.ckm_RSA_PKCS_OAEP),
  ("CKM_RSA_PKCS_PSS", Gen.ckm_RSA_PKCS_PSS),
  ("CKM_SHA_1", Gen.ckm_SHA_1),
  ("CKM_SHA_1_HMAC", Gen.ckm_SHA_1_HMAC),
  ("CKM_SHA1_KEY_DERIVATION", Gen.ckm_SHA1_KEY_DERIVATION),
  ("CKM_SHA224", Gen.ckm_SHA224),
  ("CKM_SHA256", Gen.ckm_SHA256),
  ("CKM_SHA256_HMAC", Gen.ckm_SHA256_HMAC),
  ("CKM_SHA256_HMAC_GENERAL", Gen.ckm_SHA256_HMAC_GENERAL),
  ("CKM_SHA256_KEY_DERIVATION", Gen.ckm_SHA256_KEY_DERIVATION),
  ("CKM_SHA256_RSA_PKCS", Gen.ckm_SHA256_RSA_PKCS),
  ("CKM_SHA256_RSA_PKCS_PSS", Gen.ckm_SHA256_RSA_PKCS_PSS),
  ("CKM_SHA3_224", Gen.ckm_SHA3_224),
  ("CKM_SHA3_256", Gen.ckm_SHA3_256),
  ("CKM_SHA3_384", Gen.ckm_SHA3_384),
  ("CKM_SHA3_512", Gen.ckm_SHA3_512),
  ("CKM_SHA384", Gen.ckm_SHA384),
  ("CKM_SHA512", Gen.ckm_SHA512),
  ("CKM_SHA512_224", Gen.ckm_SHA512_224),
  ("CKM_SHA512_224_KEY_DERIVATION", Gen.ckm_SHA512_224_KEY_DERIVATION),
  ("CKM_SHA512_256", Gen.ckm_SHA512_256),
  ("CKM_TLS12_KDF", Gen.ckm_TLS12_KDF)
  ]
  where
    pin (name, c) = assertEqual (show name) (Just c) (generatedIdByName name)

caseMechIds :: IO ()
caseMechIds = do
  assertEqual "AES_KEY_GEN" (Just 0x1080 :: Maybe Word64) (generatedIdByName "CKM_AES_KEY_GEN")
  assertEqual "EC_KEY_PAIR_GEN" (Just 0x1040 :: Maybe Word64) (generatedIdByName "CKM_EC_KEY_PAIR_GEN")
  assertEqual "RSA_PKCS_KEY_PAIR_GEN" (Just 0x00 :: Maybe Word64) (generatedIdByName "CKM_RSA_PKCS_KEY_PAIR_GEN")
  assertEqual "AES_CBC" (Just 0x1082 :: Maybe Word64) (generatedIdByName "CKM_AES_CBC")
  assertEqual "ECDSA" (Just 0x1041 :: Maybe Word64) (generatedIdByName "CKM_ECDSA")
  assertEqual "ML_KEM" (Just 0x17 :: Maybe Word64) (generatedIdByName "CKM_ML_KEM")
  assertEqual "ML_KEM_KEY_PAIR_GEN" (Just 0x0F :: Maybe Word64) (generatedIdByName "CKM_ML_KEM_KEY_PAIR_GEN")
  assertEqual "HKDF_DERIVE" (Just 0x402A :: Maybe Word64) (generatedIdByName "CKM_HKDF_DERIVE")
  assertEqual "unknown mech" Nothing (generatedIdByName "CKM_NOPE")

caseAttrIds :: IO ()
caseAttrIds = do
  assertEqual "CKA_CLASS" (Just 0x00 :: Maybe Word64) (attributeIdByName "CKA_CLASS")
  assertEqual "CKA_TOKEN" (Just 0x01 :: Maybe Word64) (attributeIdByName "CKA_TOKEN")
  assertEqual "CKA_VALUE" (Just 0x11 :: Maybe Word64) (attributeIdByName "CKA_VALUE")
  assertEqual "CKA_ID" (Just 0x102 :: Maybe Word64) (attributeIdByName "CKA_ID")
  assertEqual "CKA_EC_PARAMS" (Just 0x180 :: Maybe Word64) (attributeIdByName "CKA_EC_PARAMS")
  assertEqual "attribute count" 158 (length generatedAttributes)
  assertEqual "reverse 0x11" (Just "CKA_VALUE") (attributeNameById 0x11)
  assertEqual "unknown attribute" Nothing (attributeIdByName "CKA_NOPE")

caseInventoryAttrs :: IO ()
caseInventoryAttrs = do
  assertEqual "CKA_ID maps" (Just AttrId) (attributeTypeByName "CKA_ID")
  assertEqual "CKA_PUBLIC_EXPONENT maps" (Just AttrPublicExponent)
    (attributeTypeByName "CKA_PUBLIC_EXPONENT")
  assertBool "AttrId is bytes-shaped"
    (shapeMatches AttrId (ValBytes "x"))
  assertBool "AttrPublicExponent is bytes-shaped"
    (shapeMatches AttrPublicExponent (ValBytes "x"))

caseCodesMatch :: IO ()
caseCodesMatch = do
  -- The key-management codes resolve through the generated tables:
  -- same values as the planner literals, zero hand-typed ids in src/.
  assertEqual "ckoSecretKey" 0x04 ckoSecretKey
  assertEqual "ckoPublicKey" 0x02 ckoPublicKey
  assertEqual "ckoPrivateKey" 0x03 ckoPrivateKey
  assertEqual "ckkAes" 0x1F ckkAes
  assertEqual "ckkEc" 0x03 ckkEc
  assertEqual "aesKeyGenMech" (MechanismId 0x1080) aesKeyGenMech
  assertEqual "ecKeyPairGenMech" (MechanismId 0x1040) ecKeyPairGenMech
  assertEqual "rsaKeyPairGenMech" (MechanismId 0x00) rsaKeyPairGenMech

caseRulesConsistent :: IO ()
caseRulesConsistent = do
  -- Exactly the four reviewed constraining rules (three
  -- key-management, one HOTP); every cited name maps into the model
  -- AttributeType inventory (unmappable names would make
  -- enforcement vacuous or fail-closed).
  assertEqual "rule count" 4 (length generatedTemplateRules)
  mapM_ checkRule generatedTemplateRules
  where
    checkRule (cls, keyType, req, frb) = do
      assertBool ("class known " ++ show cls) (classIdByName cls /= Nothing)
      case keyType of
        Nothing -> pure ()
        Just kn -> assertBool ("key type known " ++ show kn)
          (keyTypeIdByName kn /= Nothing)
      mapM_ (\n -> assertBool ("required maps " ++ show n)
        (attributeTypeByName n /= Nothing)) req
      mapM_ (\n -> assertBool ("forbidden maps " ++ show n)
        (attributeTypeByName n /= Nothing)) frb

caseFindRule :: IO ()
caseFindRule = do
  assertBool "SECRET/AES resolves"
    (findRule "CKO_SECRET_KEY" "CKK_AES" /= Nothing)
  assertBool "PUB/EC resolves"
    (findRule "CKO_PUBLIC_KEY" "CKK_EC" /= Nothing)
  assertBool "PUB/RSA resolves"
    (findRule "CKO_PUBLIC_KEY" "CKK_RSA" /= Nothing)
  assertBool "SECRET/HOTP resolves"
    (findRule "CKO_SECRET_KEY" "CKK_HOTP" /= Nothing)
  assertEqual "PRIV/EC has no presence rule" Nothing
    (findRule "CKO_PRIVATE_KEY" "CKK_EC")
  assertEqual "SECRET/GENERIC has no presence rule" Nothing
    (findRule "CKO_SECRET_KEY" "CKK_GENERIC_SECRET")
  assertEqual "unknown context has no rule" Nothing
    (findRule "CKO_DATA" "CKK_AES")

synthRule :: TemplateRule
synthRule = TemplateRule
  { trClass = "CKO_SECRET_KEY"
  , trKeyType = Just "CKK_AES"
  , trRequired = ["CKA_CLASS", "CKA_VALUE_LEN"]
  , trForbidden = ["CKA_MODULUS_BITS"]
  }

caseMissingRequired :: IO ()
caseMissingRequired = do
  let attrs = Map.fromList [(AttrClass, ValULong ckoSecretKey)]
  assertEqual "VALUE_LEN missing"
    (Left (RuleMissingRequired "CKA_VALUE_LEN"))
    (checkRules synthRule attrs)
  let full = Map.fromList
        [(AttrClass, ValULong ckoSecretKey), (AttrValueLen, ValULong 32)]
  assertEqual "complete template passes" (Right ()) (checkRules synthRule full)

caseForbiddenPresent :: IO ()
caseForbiddenPresent = do
  let attrs = Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrValueLen, ValULong 32)
        , (AttrModulusBits, ValULong 2048)
        ]
  assertEqual "MODULUS_BITS forbidden"
    (Left (RuleForbiddenPresent "CKA_MODULUS_BITS"))
    (checkRules synthRule attrs)

testSession :: SessionState
testSession = SessionState
  { ssId = SessionId 1
  , ssSlot = SlotId 7
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

caseAesMissingLen :: IO ()
caseAesMissingLen = do
  let tmpl = [(AttrClass, ValULong ckoSecretKey)]
  case planGenerateKey defaultRules emptyModel testSession aesKeyGenMech tmpl of
    KeyDenied (KeyDeny code reason) -> do
      assertEqual "incomplete code" CKR_TEMPLATE_INCOMPLETE code
      assertEqual "rule-citing reason"
        "template rule CKO_SECRET_KEY/CKK_AES requires CKA_VALUE_LEN" reason
    other -> assertFailure ("must deny, got: " ++ show other)

caseEcMissingCurve :: IO ()
caseEcMissingCurve = do
  let pubT = [(AttrClass, ValULong ckoPublicKey)]
      privT = [(AttrClass, ValULong ckoPrivateKey)]
  case planGenerateKeyPair defaultRules emptyModel testSession ecKeyPairGenMech pubT privT of
    KeyDenied (KeyDeny code reason) -> do
      assertEqual "incomplete code" CKR_TEMPLATE_INCOMPLETE code
      assertEqual "rule-citing reason"
        "template rule CKO_PUBLIC_KEY/CKK_EC requires CKA_EC_PARAMS" reason
    other -> assertFailure ("must deny, got: " ++ show other)

caseEcOffSetCurve :: IO ()
caseEcOffSetCurve = do
  -- Only covered curves plan; brainpoolP160r1 (a real curve
  -- outside the engine set) is mechanism-invalid, never
  -- substituted.
  let pubT = [ (AttrClass, ValULong ckoPublicKey)
             , (AttrKeyType, ValULong ckkEc)
             , (AttrEcParams, ValBytes "brainpoolP160r1")
             ]
      privT = [(AttrClass, ValULong ckoPrivateKey)]
  case planGenerateKeyPair defaultRules emptyModel testSession ecKeyPairGenMech pubT privT of
    KeyDenied (KeyDeny code _) -> assertEqual "mechanism code"
      CKR_MECHANISM_INVALID code
    other -> assertFailure ("must deny, got: " ++ show other)

caseRsaMissingBits :: IO ()
caseRsaMissingBits = do
  let pubT = [(AttrClass, ValULong ckoPublicKey)]
      privT = [(AttrClass, ValULong ckoPrivateKey)]
  case planGenerateKeyPair defaultRules emptyModel testSession rsaKeyPairGenMech pubT privT of
    KeyDenied (KeyDeny code reason) -> do
      assertEqual "incomplete code" CKR_TEMPLATE_INCOMPLETE code
      assertEqual "rule-citing reason"
        "template rule CKO_PUBLIC_KEY/CKK_RSA requires CKA_MODULUS_BITS" reason
    other -> assertFailure ("must deny, got: " ++ show other)

caseWrongClass :: IO ()
caseWrongClass = do
  -- AES keygen template naming the public-key class.
  let tmpl = [(AttrClass, ValULong ckoPublicKey), (AttrValueLen, ValULong 32)]
  case checkKeyTemplate ckoSecretKey ckkAes tmpl of
    Left (KeyDeny code _) -> assertEqual "inconsistent code"
      CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)

caseWrongKeyType :: IO ()
caseWrongKeyType = do
  -- AES keygen template naming the EC key type.
  let tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkEc)
             , (AttrValueLen, ValULong 32)]
  case checkKeyTemplate ckoSecretKey ckkAes tmpl of
    Left (KeyDeny code _) -> assertEqual "inconsistent code"
      CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)

caseMalformedKeyType :: IO ()
caseMalformedKeyType = do
  let tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValBool True)
             , (AttrValueLen, ValULong 32)]
  case checkKeyTemplate ckoSecretKey ckkAes tmpl of
    Left (KeyDeny code _) -> assertEqual "inconsistent code"
      CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)

casePairDisagree :: IO ()
casePairDisagree = do
  -- EC templates disagreeing on the curve.
  let pubT = [(AttrClass, ValULong ckoPublicKey), (AttrEcParams, ValBytes "P-256")]
      privT = [(AttrClass, ValULong ckoPrivateKey), (AttrEcParams, ValBytes "P-384")]
  case planGenerateKeyPair defaultRules emptyModel testSession ecKeyPairGenMech pubT privT of
    KeyDenied (KeyDeny code _) -> assertEqual "curve disagreement"
      CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- RSA templates disagreeing on the modulus size.
  let rsaPub = [(AttrClass, ValULong ckoPublicKey), (AttrModulusBits, ValULong 2048)]
      rsaPriv = [(AttrClass, ValULong ckoPrivateKey), (AttrModulusBits, ValULong 3072)]
  case planGenerateKeyPair defaultRules emptyModel testSession rsaKeyPairGenMech rsaPub rsaPriv of
    KeyDenied (KeyDeny code _) -> assertEqual "modulus disagreement"
      CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)

caseHotpMissingLen :: IO ()
caseHotpMissingLen = do
  let tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkHotp)]
  case planGenerateKey defaultRules emptyModel testSession hotpKeyGenMech tmpl of
    KeyDenied (KeyDeny code reason) -> do
      assertEqual "incomplete code" CKR_TEMPLATE_INCOMPLETE code
      assertEqual "rule-citing reason"
        "template rule CKO_SECRET_KEY/CKK_HOTP requires CKA_VALUE_LEN" reason
    other -> assertFailure ("must deny, got: " ++ show other)

caseWrongShape :: IO ()
caseWrongShape = do
  -- Cross-shape values refuse with the offending type; well-typed
  -- templates still validate.
  assertEqual "bool class refused"
    (Left (TemplateWrongType AttrClass))
    (validateTemplate [(AttrClass, ValBool True)])
  assertEqual "bytes length refused"
    (Left (TemplateWrongType AttrValueLen))
    (validateTemplate [(AttrClass, ValULong ckoSecretKey), (AttrValueLen, ValBytes "32")])
  assertEqual "ulong flag refused"
    (Left (TemplateWrongType AttrToken))
    (validateTemplate [(AttrClass, ValULong ckoSecretKey), (AttrToken, ValULong 1)])
  case validateTemplate [(AttrClass, ValULong ckoSecretKey), (AttrToken, ValBool True)] of
    Right _ -> pure ()
    other -> assertFailure ("well-typed must pass, got: " ++ show other)

caseMistypedClassKeygen :: IO ()
caseMistypedClassKeygen = do
  -- A present-but-mistyped class is inconsistent (malformedness
  -- outranks incompleteness), not a missing class.
  let tmpl = [(AttrClass, ValBool True), (AttrValueLen, ValULong 32)]
  case checkKeyTemplate ckoSecretKey ckkAes tmpl of
    Left (KeyDeny code _) -> assertEqual "inconsistent code"
      CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)

caseMistypedClassCreate :: IO ()
caseMistypedClassCreate = do
  -- Creation shares the choke point: no object with a mistyped
  -- class is ever allocated.
  case planCreateObject emptyModel testSession [(AttrClass, ValBool True)] of
    Reject rej -> assertEqual "inconsistent code"
      CKR_TEMPLATE_INCONSISTENT (rejCode rej)
    Immediate _ -> assertFailure "must reject, committed"
    Execute _ _ -> assertFailure "must reject, reserved execution"

caseClasslessAesKeygen :: IO ()
caseClasslessAesKeygen = do
  -- The mechanism implies the class: AES keygen without CKA_CLASS
  -- is accepted (oracle fixtures omit it), and the validated
  -- attributes carry the implied secret-key class.
  let tmpl = [(AttrValueLen, ValULong 32)]
  case checkKeyTemplate ckoSecretKey ckkAes tmpl of
    Right attrs -> assertEqual "implied class"
      (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass attrs)
    other -> assertFailure ("must accept, got: " ++ show other)
  case planGenerateKey defaultRules emptyModel testSession aesKeyGenMech tmpl of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("must plan, got: " ++ show other)

caseClasslessEcKeypair :: IO ()
caseClasslessEcKeypair = do
  -- Neither pair template repeats its class; the public curve
  -- still gates, and the private side inherits it.
  let pubT = [(AttrEcParams, ValBytes "P-256")]
      privT = []
  case planGenerateKeyPair defaultRules emptyModel testSession ecKeyPairGenMech pubT privT of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("must plan, got: " ++ show other)

caseClasslessDeriveCheck :: IO ()
caseClasslessDeriveCheck = do
  -- Derivation templates share the defaulting (class implied by
  -- the derivation context).
  let tmpl = [(AttrValueLen, ValULong 32)]
  case checkKeyTemplateAny ckoSecretKey ckkAes tmpl of
    Right attrs -> assertEqual "implied class"
      (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass attrs)
    other -> assertFailure ("must accept, got: " ++ show other)

caseClasslessUnwrapCheck :: IO ()
caseClasslessUnwrapCheck = do
  -- Unwrap templates share the defaulting: the secret class is
  -- implied by the unwrap context (the key type stays mandatory —
  -- the blob carries no header — enforced by the planner before
  -- this check runs).
  let tmpl = [(AttrKeyType, ValULong ckkAes), (AttrToken, ValBool False)]
  case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
    Right attrs -> assertEqual "implied class"
      (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass attrs)
    other -> assertFailure ("must accept, got: " ++ show other)

caseCreateUnknownClass :: IO ()
caseCreateUnknownClass = do
  -- 0xDEADBEEF is not an object class: creation refuses with
  -- INCONSISTENT, the established code for bad template values
  -- (oracle: invalid-class-value probe accepts any template error).
  case planCreateObject emptyModel testSession [(AttrClass, ValULong 0xDEADBEEF)] of
    Reject rej -> assertEqual "value code"
      CKR_TEMPLATE_INCONSISTENT (rejCode rej)
    Immediate _ -> assertFailure "must reject, committed"
    Execute _ _ -> assertFailure "must reject, reserved execution"
