{- | USDT mapping pins.

The 'Haskoki.Runtime.Usdt' mapping (codes, routes, key facts,
policy table, op ids) is pinned here row by row. Cross-language
consistency (Haskell codes vs @cbits/usdt.h@) is enforced by
@scripts/check-usdt-codes.py@; these tests pin the Haskell side
of that contract plus the mapping rules.
-}
{-# LANGUAGE OverloadedStrings #-}
module UsdtMapSpec (spec) where

import qualified Data.ByteString as BS
import Data.Bits ((.&.))
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Model (ObjectState (..))
import Haskoki.Operation.State (SlotKind (..))
import Haskoki.Recipe.RsaOaep (encodeOaepParams)
import Haskoki.Recipe.RsaPss (encodePssParams)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..))
import Haskoki.Request (FunctionId (..))
import Haskoki.ReturnCode.Generated (ReturnCode (..), returnCodeToRV)
import Haskoki.Runtime.Usdt
import Haskoki.Types (Generation (..), ObjectId (..), Revision (..),
  SlotId (..))

spec :: TestTree
spec = testGroup "USDT mapping"
  [ codePins
  , routePins
  , hashPadPins
  , keyFactPins
  , policyPins
  , slotPins
  , idPins
  , redactPins
  ]

codePins :: TestTree
codePins = testGroup "codes match cbits/usdt.h"
  [ testCase "pk names 1..8" $ do
      assertEqual "sign" 1 (pkNameCode PkSign)
      assertEqual "verify" 2 (pkNameCode PkVerify)
      assertEqual "encrypt" 3 (pkNameCode PkEncrypt)
      assertEqual "decrypt" 4 (pkNameCode PkDecrypt)
      assertEqual "encapsulate" 5 (pkNameCode PkEncapsulate)
      assertEqual "decapsulate" 6 (pkNameCode PkDecapsulate)
      assertEqual "generate" 7 (pkNameCode PkGenerate)
      assertEqual "derive" 8 (pkNameCode PkDerive)
  , testCase "dispositions 1..5" $ do
      assertEqual "delivered" 1 (dispositionCode DispDelivered)
      assertEqual "failed-exec" 2 (dispositionCode DispFailedExec)
      assertEqual "failed-publish" 3 (dispositionCode DispFailedPublish)
      assertEqual "failed-writeback" 4
        (dispositionCode DispFailedWriteback)
      assertEqual "abandoned" 5 (dispositionCode DispAbandoned)
  , testCase "modes" $ do
      assertEqual "sync" 0 (opModeCode ModeSync)
      assertEqual "async" 1 (opModeCode ModeAsync)
  , testCase "reasons 1..5" $ do
      assertEqual "auth" 1 (policyReasonCode ReasonAuth)
      assertEqual "usage" 2 (policyReasonCode ReasonUsage)
      assertEqual "readonly" 3 (policyReasonCode ReasonReadonly)
      assertEqual "template" 4 (policyReasonCode ReasonTemplate)
      assertEqual "state" 5 (policyReasonCode ReasonState)
  , testCase "phases 1..6" $ do
      assertEqual "accepted" 1 (jobPhaseCode PhaseAccepted)
      assertEqual "claimed" 2 (jobPhaseCode PhaseClaimed)
      assertEqual "ready" 3 (jobPhaseCode PhaseReady)
      assertEqual "delivered" 4 (jobPhaseCode PhaseDelivered)
      assertEqual "failed" 5 (jobPhaseCode PhaseFailed)
      assertEqual "canceled" 6 (jobPhaseCode PhaseCanceled)
  ]

routePins :: TestTree
routePins = testGroup "function routes"
  [ testCase "classic finals route" $ do
      assertEqual "sign" (Just RouteSign) (routeOfFunc F_SignFinal)
      assertEqual "verify" (Just RouteVerify) (routeOfFunc F_VerifyFinal)
      assertEqual "encrypt" (Just RouteEncrypt) (routeOfFunc F_EncryptFinal)
      assertEqual "decrypt" (Just RouteDecrypt) (routeOfFunc F_DecryptFinal)
  , testCase "inits and updates do not route" $ do
      assertEqual "sign-init" Nothing (routeOfFunc F_SignInit)
      assertEqual "encrypt-update" Nothing (routeOfFunc F_EncryptUpdate)
      assertEqual "digest" Nothing (routeOfFunc F_Digest)
      assertEqual "digest-final" Nothing (routeOfFunc F_DigestFinal)
  , testCase "key management routes" $ do
      assertEqual "genpair" (Just RouteGenerate)
        (routeOfFunc F_GenerateKeyPair)
      assertEqual "derive" (Just RouteDerive) (routeOfFunc F_DeriveKey)
      assertEqual "wrap" (Just RouteWrap) (routeOfFunc F_WrapKey)
      assertEqual "unwrap" (Just RouteUnwrap) (routeOfFunc F_UnwrapKey)
      assertEqual "encap" (Just RouteEncapsulate)
        (routeOfFunc F_EncapsulateKey)
      assertEqual "decap" (Just RouteDecapsulate)
        (routeOfFunc F_DecapsulateKey)
  , testCase "message legs route by family" $ do
      assertEqual "msg-sign" (Just RouteSign) (routeOfFunc F_SignMessageNext)
      assertEqual "msg-verify" (Just RouteVerify)
        (routeOfFunc F_MessageVerifyFinal)
      assertEqual "msg-encrypt" (Just RouteEncrypt)
        (routeOfFunc F_EncryptMessage)
  ]

ckm :: Text -> MechanismId
ckm = MechanismId . mustGeneratedId

hashPadPins :: TestTree
hashPadPins = testGroup "mechanism hash/padding"
  [ testCase "rsa hashes" $ do
      assertEqual "sha256-rsa" 4
        (hashOfMechanism (ckm "CKM_SHA256_RSA_PKCS"))
      assertEqual "sha1-rsa" 2
        (hashOfMechanism (ckm "CKM_SHA1_RSA_PKCS"))
      assertEqual "raw-rsa" 0 (hashOfMechanism (ckm "CKM_RSA_PKCS"))
  , testCase "ecdsa hashes" $ do
      assertEqual "ecdsa-sha256" 4
        (hashOfMechanism (ckm "CKM_ECDSA_SHA256"))
      assertEqual "raw-ecdsa" 0 (hashOfMechanism (ckm "CKM_ECDSA"))
  , testCase "paddings" $ do
      assertEqual "pss" 1 (paddingOfMechanism (ckm "CKM_RSA_PKCS_PSS"))
      assertEqual "oaep" 2 (paddingOfMechanism (ckm "CKM_RSA_PKCS_OAEP"))
      assertEqual "v15" 3 (paddingOfMechanism (ckm "CKM_RSA_PKCS"))
      assertEqual "x509" 0 (paddingOfMechanism (ckm "CKM_RSA_X_509"))
      assertEqual "ecdsa" 0
        (paddingOfMechanism (ckm "CKM_ECDSA_SHA256"))
  , testCase "generic pss/oaep hash from validated params" $ do
      let rsa = PkKeyFacts 1 0 0 2048
          pss = ckm "CKM_RSA_PKCS_PSS"
          oaep = ckm "CKM_RSA_PKCS_OAEP"
      assertEqual "pss-sha384" (Just (PkRecord PkSign rsa 5 1))
        (resolvePk RouteSign pss rsa
          (encodePssParams "SHA384" "SHA384" 48))
      assertEqual "oaep-sha1" (Just (PkRecord PkEncrypt rsa 2 2))
        (resolvePk RouteEncrypt oaep rsa
          (encodeOaepParams "SHA_1" "SHA_1" BS.empty))
      assertEqual "oaep-garbage-omits" (Just (PkRecord PkEncrypt rsa 0 2))
        (resolvePk RouteEncrypt oaep rsa "not-params")
      assertEqual "pss-ripemd-omits" (Just (PkRecord PkSign rsa 0 1))
        (resolvePk RouteSign pss rsa
          (encodePssParams "RIPEMD160" "RIPEMD160" 20))
      assertEqual "bound-mech-ignores-params"
        (Just (PkRecord PkSign rsa 4 3))
        (resolvePk RouteSign (ckm "CKM_SHA256_RSA_PKCS") rsa "not-params")
  ]

mkObj :: [(AttributeType, AttributeValue)] -> ObjectState
mkObj attrs = ObjectState
  { osId = ObjectId 1
  , osRevision = Revision 1
  , osGeneration = Generation 1
  , osAttrs = Map.fromList attrs
  , osOwner = Nothing
  , osSlot = SlotId 0
  }

keyFactPins :: TestTree
keyFactPins = testGroup "key facts"
  [ testCase "rsa from modulus bits" $ do
      let rsa = mkObj
            [ (AttrKeyType, ValULong (mustKeyTypeId "CKK_RSA"))
            , (AttrModulusBits, ValULong 2048)
            ]
      assertEqual "rsa" (PkKeyFacts 1 0 0 2048) (keyFactsOf rsa)
  , testCase "rsa from modulus length" $ do
      let rsa = mkObj
            [ (AttrKeyType, ValULong (mustKeyTypeId "CKK_RSA"))
            , (AttrModulus, ValBytes (BS.replicate 256 7))
            ]
      assertEqual "rsa-len" (PkKeyFacts 1 0 0 2048) (keyFactsOf rsa)
  , testCase "ec p-256 omits bits" $ do
      let ec = mkObj
            [ (AttrKeyType, ValULong (mustKeyTypeId "CKK_EC"))
            , (AttrEcParams, ValBytes p256oid)
            ]
      assertEqual "p256" (PkKeyFacts 2 1 0 0) (keyFactsOf ec)
  , testCase "ed25519 exact" $ do
      let ed = mkObj
            [ (AttrKeyType, ValULong (mustKeyTypeId "CKK_EC_EDWARDS"))
            , (AttrValue, ValBytes (BS.replicate 32 9))
            ]
      assertEqual "ed25519" (PkKeyFacts 6 5 0 256) (keyFactsOf ed)
  , testCase "ml-kem algorithm-only" $ do
      let kem = mkObj
            [(AttrKeyType, ValULong (mustKeyTypeId "CKK_ML_KEM"))]
      assertEqual "mlkem" (PkKeyFacts 8 0 0 0) (keyFactsOf kem)
  , testCase "symmetric yields none" $ do
      let aes = mkObj
            [ (AttrKeyType, ValULong (mustKeyTypeId "CKK_AES"))
            , (AttrValue, ValBytes (BS.replicate 32 1))
            ]
      assertEqual "aes" noPkFacts (keyFactsOf aes)
  , testCase "resolvePk eligibility" $ do
      let rsa = PkKeyFacts 1 0 0 2048
          mech = ckm "CKM_SHA256_RSA_PKCS"
          noParams = BS.empty
      assertEqual "rsa-sign" (Just (PkRecord PkSign rsa 4 3))
        (resolvePk RouteSign mech rsa noParams)
      assertEqual "hmac-sign-private" Nothing
        (resolvePk RouteSign mech noPkFacts noParams)
      assertEqual "oaep-wrap" (Just (PkRecord PkEncrypt rsa 4 2))
        (resolvePk RouteWrap (ckm "CKM_RSA_PKCS_OAEP") rsa
          (encodeOaepParams "SHA256" "SHA256" BS.empty))
      assertEqual "aes-wrap-private" Nothing
        (resolvePk RouteWrap (ckm "CKM_AES_KEY_WRAP_PAD") noPkFacts
          noParams)
  ]

p256oid :: BS.ByteString
p256oid = BS.pack
  [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]

policyPins :: TestTree
policyPins = testGroup "policy mapping"
  [ testCase "policy codes map" $ do
      assertEqual "login" (Just ReasonAuth)
        (policyReasonOf CKR_USER_NOT_LOGGED_IN)
      assertEqual "usage" (Just ReasonUsage)
        (policyReasonOf CKR_KEY_FUNCTION_NOT_PERMITTED)
      assertEqual "readonly" (Just ReasonReadonly)
        (policyReasonOf CKR_SESSION_READ_ONLY)
      assertEqual "template" (Just ReasonTemplate)
        (policyReasonOf CKR_TEMPLATE_INCONSISTENT)
      assertEqual "state" (Just ReasonState)
        (policyReasonOf CKR_OPERATION_NOT_INITIALIZED)
  , testCase "verdicts and caller bugs excluded" $ do
      assertEqual "sig-invalid" Nothing
        (policyReasonOf CKR_SIGNATURE_INVALID)
      assertEqual "args-bad" Nothing (policyReasonOf CKR_ARGUMENTS_BAD)
      assertEqual "range" Nothing (policyReasonOf CKR_DATA_LEN_RANGE)
      assertEqual "ok" Nothing (policyReasonOf CKR_OK)
  , testCase "rv numbers agree" $ do
      assertEqual "rv-auth" (Just ReasonAuth)
        (policyReasonOfRv (returnCodeToRV CKR_PIN_LOCKED))
      assertEqual "rv-excluded" Nothing
        (policyReasonOfRv (returnCodeToRV CKR_ENCRYPTED_DATA_INVALID))
  ]

slotPins :: TestTree
slotPins = testGroup "slot mapping"
  [ testCase "classic legs" $ do
      assertEqual "sign" (Just SlotSign) (slotKindOfFunc F_SignFinal)
      assertEqual "verify-init" (Just SlotVerify)
        (slotKindOfFunc F_VerifyInit)
      assertEqual "digest" (Just SlotDigest) (slotKindOfFunc F_DigestUpdate)
  , testCase "session-wide excluded" $ do
      assertEqual "cancel" Nothing (slotKindOfFunc F_SessionCancel)
      assertEqual "login" Nothing (slotKindOfFunc F_Login)
  ]

idPins :: TestTree
idPins = testGroup "op ids"
  [ testCase "tag, nonzero, unique" $ do
      m1 <- newUsdtOpId
      m2 <- newUsdtOpId
      case (m1, m2) of
        (Just (UsdtOpId a), Just (UsdtOpId b)) -> do
          assertBool "nonzero" (a /= 0 && b /= 0)
          assertEqual "tag" 0x48534B30 (a .&. 0xFFFFFFFF)
          assertEqual "tag2" 0x48534B30 (b .&. 0xFFFFFFFF)
          assertBool "unique" (a /= b)
          assertBool "ordered" (a < b)
        _ -> assertBool "saturated in test" False
  ]

-- Distinctive fixture secrets: every emitted USDT fact must be
-- content-independent in these blobs (only lengths and validated
-- codes flow). The A/B pairs share lengths but differ in content,
-- so equal outputs prove no secret byte reaches the record.
-- Curve/group selection from validated OIDs is metadata by design
-- (the registry requires pk::curve); the redaction property is
-- that outputs are small codes, never secret bytes.
secretCycle :: BS.ByteString -> Int -> BS.ByteString
secretCycle seed n =
  BS.take n (BS.concat (replicate (n `div` BS.length seed + 1) seed))

secretModA, secretModB :: BS.ByteString
secretModA = secretCycle "USDT-REDACT-ALPHA-MODULUS-must-never-leak:" 256
secretModB = secretCycle "USDT-REDACT-BETA-MODULUS-must-never-leak!!" 256

secretKeyA, secretKeyB :: BS.ByteString
secretKeyA = secretCycle "USDT-REDACT-ALPHA-KEY-must-never-leak:" 32
secretKeyB = secretCycle "USDT-REDACT-BETA-KEY-must-never-leak!!" 32

redactPins :: TestTree
redactPins = testGroup "secret content independence"
  [ testCase "rsa modulus content-independent" $ do
      let mk m = mkObj
            [ (AttrKeyType, ValULong (mustKeyTypeId "CKK_RSA"))
            , (AttrModulus, ValBytes m)
            ]
      assertEqual "same facts" (keyFactsOf (mk secretModA))
        (keyFactsOf (mk secretModB))
      assertEqual "length-only" (PkKeyFacts 1 0 0 2048)
        (keyFactsOf (mk secretModA))
  , testCase "symmetric value content-independent" $ do
      let mk v = mkObj
            [ (AttrKeyType, ValULong (mustKeyTypeId "CKK_AES"))
            , (AttrValue, ValBytes v)
            ]
      assertEqual "aes-a" noPkFacts (keyFactsOf (mk secretKeyA))
      assertEqual "aes-b" noPkFacts (keyFactsOf (mk secretKeyB))
  , testCase "edwards value content-independent" $ do
      let mk v = mkObj
            [ (AttrKeyType, ValULong (mustKeyTypeId "CKK_EC_EDWARDS"))
            , (AttrValue, ValBytes v)
            ]
      assertEqual "same facts" (keyFactsOf (mk secretKeyA))
        (keyFactsOf (mk secretKeyB))
      assertEqual "length-only" (PkKeyFacts 6 5 0 256)
        (keyFactsOf (mk secretKeyA))
  , testCase "record chain content-independent" $ do
      let mk m = mkObj
            [ (AttrKeyType, ValULong (mustKeyTypeId "CKK_RSA"))
            , (AttrModulus, ValBytes m)
            ]
          mech = ckm "CKM_SHA256_RSA_PKCS"
      assertEqual "same record"
        (resolvePk RouteSign mech (keyFactsOf (mk secretModA)) BS.empty)
        (resolvePk RouteSign mech (keyFactsOf (mk secretModB)) BS.empty)
  ]
