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
      assertEqual "rsa-sign" (Just (PkRecord PkSign rsa 4 3))
        (resolvePk RouteSign mech rsa)
      assertEqual "hmac-sign-private" Nothing
        (resolvePk RouteSign mech noPkFacts)
      case resolvePk RouteWrap (ckm "CKM_RSA_PKCS_OAEP") rsa of
        Just rec -> assertEqual "oaep-wrap" PkEncrypt (prName rec)
        Nothing -> assertBool "oaep-wrap resolves" False
      assertEqual "aes-wrap-private" Nothing
        (resolvePk RouteWrap (ckm "CKM_AES_KEY_WRAP_PAD") noPkFacts)
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
