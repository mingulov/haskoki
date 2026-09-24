{- | Secrets-discipline pins.

Debug output must not contain key or PIN payloads: every
secret-carrying type redacts its 'Show' output (following the
'Trace.hs' redacted\/kind\/length shape) while staying
explicitly inspectable through its exported constructors.
Canary strings seed each carrier; every 'show' below must omit
its canary.
-}
{-# LANGUAGE OverloadedStrings #-}
module SecretsSpec (spec) where

import Data.ByteString (ByteString)
import Data.List (isInfixOf)
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend (KeyMaterial (..), KeyRef (..))
import Haskoki.Model (Model (..), ObjectState (..), emptyModel)
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoResult (..))
import Haskoki.Operation.KeyManagement
  ( KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request (FunctionId (..), Request (..))
import Haskoki.Runtime.Async (JobSnapState (..))
import Haskoki.Runtime.Config (Config (..), TokensCfg (..), defaultConfig)
import Haskoki.Runtime.Storage (JobBody (..), ObjectRecord (..), StoredDoc (..))
import Haskoki.Runtime.Trace
  ( TraceEvent (..)
  , TraceIds (..)
  , TraceSecret (..)
  , renderJSONL
  )
import Haskoki.Types
  ( EngineResourceId (..)
  , Generation (..)
  , ObjectId (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

-- | Distinctive key-material canary (fake bytes, greppable).
keyCanary :: ByteString
keyCanary = "SECRET-K3Y-CANARY-0123456789abcdef"

-- | Same canary as a 'String' for 'String'-carrying types.
keyCanaryStr :: String
keyCanaryStr = "SECRET-K3Y-CANARY-0123456789abcdef"

-- | Distinctive PIN canary (fake PIN, greppable).
pinCanary :: String
pinCanary = "SECRET-P1N-9876"

spec :: TestTree
spec = testGroup "Secrets discipline"
  [ testCase "attr value redacted" caseAttrValue
  , testCase "key material bytes redacted" caseKeyBytes
  , testCase "key material DER redacted" caseKeyDer
  , testCase "key reference shown (control)" caseKeyRefShown
  , testCase "object state redacted" caseObjectState
  , testCase "model redacted" caseModel
  , testCase "pending object redacted" casePendingObject
  , testCase "pending work redacted" casePendingWork
  , testCase "key plan redacted" caseKeyPlan
  , testCase "object record redacted" caseObjectRecord
  , testCase "stored doc redacted" caseStoredDoc
  , testCase "crypto result bytes redacted" caseCryptoResult
  , testCase "verdict shown (control)" caseVerdictShown
  , testCase "wrap effect input redacted" caseWrapEffect
  , testCase "auth-wrap effect input redacted" caseAuthWrapEffect
  , testCase "digest effect input shown (control)" caseDigestEffectShown
  , testCase "create request input redacted" caseCreateRequest
  , testCase "copy request input redacted" caseCopyRequest
  , testCase "find request input redacted" caseFindRequest
  , testCase "digest request input shown (control)" caseDigestRequestShown
  , testCase "trace PIN redacted" caseTracePin
  , testCase "trace key redacted" caseTraceKey
  , testCase "trace event redacted" caseTraceEvent
  , testCase "token catalog PINs redacted" caseTokensCfg
  , testCase "config PINs redacted" caseConfig
  , testCase "pending job body redacted" caseJobPending
  , testCase "result job body redacted" caseJobResult
  , testCase "ready snapshot bytes redacted" caseSnapReady
  , testCase "trace renderer still redacts" caseRendererStillRedacts
  ]

-- | The canary must be absent from the shown string.
assertAbsent :: String -> String -> String -> IO ()
assertAbsent label canary shown =
  assertBool (label ++ ": payload leaks into show")
    (not (canary `isInfixOf` shown))

-- | The Trace-shaped redaction marker must be present.
assertMarker :: String -> String -> IO ()
assertMarker label shown =
  assertBool (label ++ ": redaction marker missing")
    ("redacted" `isInfixOf` shown)

caseAttrValue :: IO ()
caseAttrValue = do
  let s = show (ValBytes keyCanary)
  assertAbsent "attr value" keyCanaryStr s
  assertMarker "attr value" s

caseKeyBytes :: IO ()
caseKeyBytes = do
  let s = show (KeyBytes keyCanary)
  assertAbsent "key bytes" keyCanaryStr s
  assertMarker "key bytes" s

caseKeyDer :: IO ()
caseKeyDer = do
  let s = show (KeyDer keyCanary)
  assertAbsent "key DER" keyCanaryStr s
  assertMarker "key DER" s

caseKeyRefShown :: IO ()
caseKeyRefShown =
  assertBool "key ref hidden"
    ("RSA-2048" `isInfixOf`
      show (KeyRefMaterial (KeyRef (EngineResourceId 7) "RSA-2048")))

seededObject :: ObjectState
seededObject = ObjectState
  { osId = ObjectId 9
  , osRevision = Revision 1
  , osGeneration = Generation 1
  , osAttrs = Map.fromList
      [ (AttrClass, ValULong 4)
      , (AttrValue, ValBytes keyCanary)
      ]
  , osOwner = Nothing
  , osSlot = SlotId 7
  }

caseObjectState :: IO ()
caseObjectState = do
  let s = show seededObject
  assertAbsent "object" keyCanaryStr s
  assertMarker "object" s

caseModel :: IO ()
caseModel = do
  let s = show (emptyModel { mObjects = Map.singleton (ObjectId 9) seededObject })
  assertAbsent "model" keyCanaryStr s
  assertMarker "model" s

seededPending :: PendingObject
seededPending = PendingObject
  { poAttrs = Map.fromList
      [ (AttrClass, ValULong 4)
      , (AttrValue, ValBytes keyCanary)
      ]
  , poOwner = Nothing
  , poSlot = SlotId 7
  }

casePendingObject :: IO ()
casePendingObject = do
  let s = show seededPending
  assertAbsent "pending object" keyCanaryStr s
  assertMarker "pending object" s

casePendingWork :: IO ()
casePendingWork = do
  let s = show (PwGenerateKey seededPending)
  assertAbsent "pending work" keyCanaryStr s
  assertMarker "pending work" s

caseKeyPlan :: IO ()
caseKeyPlan = do
  let s = show
        (KeyEffect (PwGenerateKey seededPending)
          (FxDigestInit (MechanismId 0x250)))
  assertAbsent "key plan" keyCanaryStr s
  assertMarker "key plan" s

caseObjectRecord :: IO ()
caseObjectRecord = do
  let s = show ObjectRecord
        { orId = ObjectId 9
        , orToken = TokenId 1
        , orClass = 4
        , orKeyType = Just 0x1F
        , orAttrs = Map.singleton AttrValue (ValBytes keyCanary)
        , orMaterialEncoding = "attr-value/v1"
        , orMaterial = Just keyCanary
        , orRevision = Revision 1
        }
  assertAbsent "object record" keyCanaryStr s
  assertMarker "object record" s

caseStoredDoc :: IO ()
caseStoredDoc = do
  let s = show (StoredDoc "objects" "object:9"
        ("{\"material\":\"" ++ keyCanaryStr ++ "\"}"))
  assertAbsent "stored doc" keyCanaryStr s
  assertMarker "stored doc" s

caseCryptoResult :: IO ()
caseCryptoResult = do
  let s = show (GotBytes keyCanary)
  assertAbsent "crypto result" keyCanaryStr s
  assertMarker "crypto result" s

caseVerdictShown :: IO ()
caseVerdictShown =
  assertBool "verdict hidden" ("True" `isInfixOf` show (GotValid True))

caseWrapEffect :: IO ()
caseWrapEffect = do
  let s = show (FxWrap (MechanismId 0x1082) (Just (ObjectId 1)) "iv" keyCanary)
  assertAbsent "wrap input" keyCanaryStr s
  assertMarker "wrap input" s

caseAuthWrapEffect :: IO ()
caseAuthWrapEffect = do
  let s = show (FxAuthWrap (MechanismId 0x1082) (Just (ObjectId 1)) "params" keyCanary)
  assertAbsent "auth-wrap input" keyCanaryStr s
  assertMarker "auth-wrap input" s

caseDigestEffectShown :: IO ()
caseDigestEffectShown =
  assertBool "digest input hidden"
    ("public-digest-input" `isInfixOf`
      show (FxDigest (MechanismId 0x250) "public-digest-input"))

mkRequest :: FunctionId -> ByteString -> Request
mkRequest fun input = Request Pkcs11_3_2 fun (Just (SessionId 1)) Nothing input []

caseCreateRequest :: IO ()
caseCreateRequest = do
  let s = show (mkRequest F_CreateObject ("template:" <> keyCanary))
  assertAbsent "create input" keyCanaryStr s
  assertMarker "create input" s

caseCopyRequest :: IO ()
caseCopyRequest = do
  let s = show (mkRequest F_CopyObject ("template:" <> keyCanary))
  assertAbsent "copy input" keyCanaryStr s
  assertMarker "copy input" s

caseFindRequest :: IO ()
caseFindRequest = do
  let s = show (mkRequest F_FindObjects ("template:" <> keyCanary))
  assertAbsent "find input" keyCanaryStr s
  assertMarker "find input" s

caseDigestRequestShown :: IO ()
caseDigestRequestShown =
  assertBool "digest input hidden"
    ("public-input" `isInfixOf` show (mkRequest F_Digest "public-input"))

caseTracePin :: IO ()
caseTracePin = do
  let s = show (TracePin pinCanary)
  assertAbsent "trace PIN" pinCanary s
  assertMarker "trace PIN" s

caseTraceKey :: IO ()
caseTraceKey = do
  let s = show (TraceKeyMaterial keyCanaryStr)
  assertAbsent "trace key" keyCanaryStr s
  assertMarker "trace key" s

seededEvent :: TraceEvent
seededEvent = TraceEvent
  { teFunction = "C_Sign"
  , teInterface = "3.2"
  , teMechanism = Just "CKM_AES_CBC"
  , teSession = Just "session:1"
  , teObject = Just "object:9"
  , teJob = Nothing
  , teInputLen = 16
  , teOutputLen = 16
  , teCkr = 0
  , teDisposition = "ok"
  , teReason = "served"
  , teMode = "attached"
  , teSecret = Just (TracePin pinCanary)
  }

caseTraceEvent :: IO ()
caseTraceEvent = do
  let s = show seededEvent
  assertAbsent "trace event" pinCanary s
  assertMarker "trace event" s
  assertBool "trace function hidden" ("C_Sign" `isInfixOf` s)

caseTokensCfg :: IO ()
caseTokensCfg = do
  let s = show (TokensCfg [("haskoki-demo", pinCanary, pinCanary)])
  assertAbsent "token catalog" pinCanary s
  assertMarker "token catalog" s
  assertBool "token label hidden" ("haskoki-demo" `isInfixOf` s)

caseConfig :: IO ()
caseConfig = do
  let cfg = defaultConfig
        { cfgTokens = TokensCfg [("haskoki-demo", pinCanary, pinCanary)] }
      s = show cfg
  assertAbsent "config" pinCanary s
  assertMarker "config" s
  assertBool "config profile hidden" ("ProfileDemoMaximal" `isInfixOf` s)

caseJobPending :: IO ()
caseJobPending = do
  let s = show (JobPending "haskoki-call/v1" keyCanary)
  assertAbsent "pending body" keyCanaryStr s
  assertMarker "pending body" s

caseJobResult :: IO ()
caseJobResult = do
  let s = show (JobResult CKR_OK keyCanary)
  assertAbsent "result body" keyCanaryStr s
  assertMarker "result body" s
  assertBool "result code hidden" ("CKR_OK" `isInfixOf` s)

caseSnapReady :: IO ()
caseSnapReady = do
  let s = show (SnapReady keyCanary)
  assertAbsent "snapshot bytes" keyCanaryStr s
  assertMarker "snapshot bytes" s

caseRendererStillRedacts :: IO ()
caseRendererStillRedacts =
  let ids = TraceIds "trace/1" "haskoki" "provider" "demo-maximal" "run-0"
      rendered = show (renderJSONL ids 0 seededEvent)
  in assertAbsent "renderer" pinCanary rendered
