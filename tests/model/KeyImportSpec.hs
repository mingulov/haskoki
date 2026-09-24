{- | Key-import coverage: RSA/EC component templates create objects
whose stored value is the PKCS#8/SPKI DER the engine consumes
(the same shape key generation stores), with the components kept
verbatim for reads.

Fixtures are pinned OpenSSL 4.0.2 vectors (an RSA-2048 key and a
P-256 key, generated once); the DER goldens are openssl-emitted
bytes, so golden equality is an independent cross-check of the
assembly, not self-agreement.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyImportSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8
import Data.Char (digitToInt, isHexDigit)
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit
  (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute
  (AttributeResult (..), AttributeType (..), AttributeValue (..),
   PartialReads (..), getAttributes)
import Haskoki.Der (curveOidOfParams, unwrapEcPoint)
import Haskoki.Engine.Backend
  (CryptoBackend (..), DigestAlg (..), EcSpec (..),
   EngineResult (..), KeyMaterial (..), SigSpec (..))
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.FFI.Standard (ecParamsToWire)
import Haskoki.Model
  (Model, ObjectState (..), SessionState, addToken, emptyModel,
   lookupSession)
import Haskoki.Object (decodeHandle, planCreateObject, resolveHandle)
import Haskoki.Operation.KeyManagement
  (ckoPrivateKey, ckoPublicKey, ckkEc, ckkRsa)
import Haskoki.Outcome
  (DeltaOp (..), NativeOutput (..), PlanResult (..),
   PreparedCommit (..), Rejection (..), StateDelta (..))
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  (ExternalHandle, ReturnCode (..), SessionId (..), SlotId (..))

spec :: TestTree
spec = testGroup "key import"
  [ testCase "RSA private import assembles PKCS#8" caseRsaPrivate
  , testCase "RSA public import assembles SPKI" caseRsaPublic
  , testCase "EC private import assembles PKCS#8" caseEcPrivate
  , testCase "EC public import assembles SPKI" caseEcPublic
  , testCase "partial RSA import is incomplete" casePartialRsa
  , testCase "foreign curve refuses CURVE_NOT_SUPPORTED" caseForeignCurve
  , testCase "malformed point refuses inconsistent" caseBadPoint
  , testCase "explicit value with components contradicts" caseValueConflict
  , testCase "private components seal with the payload" caseSealedComponents
  , testCase "curve OID table agrees with the FFI" caseCurveTableAgreement
  , testCase "imported EC key signs through the real backend" caseEcExecutes
  , testCase "imported RSA key signs through the real backend" caseRsaExecutes
  ]

slot0 :: SlotId
slot0 = SlotId 0

sid1 :: SessionId
sid1 = SessionId 1

-- | Decode a hex string (whitespace-tolerant).
hex :: String -> ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

seedModel :: IO Model
seedModel = do
  let m0 = addToken emptyModel slot0
  expectRight (publishDelta m0 (StateDelta [DeltaOpenSession sid1 slot0 False]))

getSession :: Model -> IO SessionState
getSession m = case lookupSession m sid1 of
  Nothing -> assertFailure "seed session missing" >> undefined
  Just st -> pure st

expectRight :: Show e => Either e a -> IO a
expectRight (Right a) = pure a
expectRight (Left e) = assertFailure ("expected Right, got: " ++ show e) >> undefined

-- | Answer effects against the real OpenSSL4 backend.
withRealEnv :: (BackendEnv OpenSSL4 -> IO a) -> IO a
withRealEnv action = do
  opened <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case opened of
    EngineFail err -> assertFailure ("openssl4 open failed: " ++ show err) >> undefined
    EngineOk env -> do
      r <- action env
      closeBackend env
      pure r

-- | Create one object, publish it, and return the stored attributes.
doCreate :: Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle, Map.Map AttributeType AttributeValue)
doCreate m st tmpl = case planCreateObject m st tmpl of
  Immediate c -> do
    m' <- expectRight (publishDelta m (pcDelta c))
    h <- case pcOutputs c of
      [o] -> handleOf o
      _ -> assertFailure "create outputs arity" >> undefined
    case resolveHandle m' h of
      Nothing -> assertFailure "created object unresolvable" >> undefined
      Just ost -> pure (m', h, osAttrs ost)
  Reject rej -> assertFailure ("must create, got: " ++ show (rejCode rej)) >> undefined
  Execute _ _ -> assertFailure "create must not execute" >> undefined

handleOf :: NativeOutput -> IO ExternalHandle
handleOf o = case decodeHandle (outBytes o) of
  Just h -> pure h
  Nothing -> assertFailure "handle output undecodable" >> undefined

expectReject :: ReturnCode -> PlanResult -> IO ()
expectReject want res = case res of
  Reject rej -> assertEqual "reject code" want (rejCode rej)
  Immediate _ -> assertFailure "must reject, created"
  Execute _ _ -> assertFailure "must reject, executed"

rsaPrivTmpl :: [(AttributeType, AttributeValue)]
rsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrToken, ValBool False)
  , (AttrModulus, ValBytes rsaN)
  , (AttrPublicExponent, ValBytes rsaE)
  , (AttrPrivateExponent, ValBytes rsaD)
  , (AttrPrime1, ValBytes rsaP)
  , (AttrPrime2, ValBytes rsaQ)
  , (AttrExponent1, ValBytes rsaDp)
  , (AttrExponent2, ValBytes rsaDq)
  , (AttrCoefficient, ValBytes rsaQinv)
  ]

rsaPubTmpl :: [(AttributeType, AttributeValue)]
rsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrToken, ValBool False)
  , (AttrModulus, ValBytes rsaN)
  , (AttrPublicExponent, ValBytes rsaE)
  ]

ecParamsP256 :: ByteString
ecParamsP256 = hex "06082a8648ce3d030107"

ecPrivTmpl :: [(AttributeType, AttributeValue)]
ecPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrToken, ValBool False)
  , (AttrEcParams, ValBytes ecParamsP256)
  , (AttrValue, ValBytes ecScalar)
  ]

ecPubTmpl :: [(AttributeType, AttributeValue)]
ecPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrToken, ValBool False)
  , (AttrEcParams, ValBytes ecParamsP256)
  , (AttrEcPoint, ValBytes ecPointWrapped)
  ]

storedValue :: Map.Map AttributeType AttributeValue -> IO ByteString
storedValue attrs = case Map.lookup AttrValue attrs of
  Just (ValBytes bs) -> pure bs
  _ -> assertFailure "stored value missing" >> undefined

caseRsaPrivate :: IO ()
caseRsaPrivate = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st rsaPrivTmpl
  der <- storedValue attrs
  assertEqual "PKCS#8 golden" rsaP8Gold der
  assertEqual "modulus kept" (Just (ValBytes rsaN)) (Map.lookup AttrModulus attrs)
  assertEqual "coefficient kept" (Just (ValBytes rsaQinv)) (Map.lookup AttrCoefficient attrs)

caseRsaPublic :: IO ()
caseRsaPublic = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st rsaPubTmpl
  der <- storedValue attrs
  assertEqual "SPKI golden" rsaSpkiGold der

caseEcPrivate :: IO ()
caseEcPrivate = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st ecPrivTmpl
  der <- storedValue attrs
  assertEqual "no-pub PKCS#8 golden" ecP8NoPubGold der

caseEcPublic :: IO ()
caseEcPublic = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st ecPubTmpl
  der <- storedValue attrs
  assertEqual "SPKI golden" ecSpkiGold der
  assertEqual "point kept" (Just (ValBytes ecPointWrapped)) (Map.lookup AttrEcPoint attrs)

casePartialRsa :: IO ()
casePartialRsa = do
  m0 <- seedModel
  st <- getSession m0
  let tmpl = filter ((/= AttrPrime1) . fst) rsaPrivTmpl
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st tmpl)

caseForeignCurve :: IO ()
caseForeignCurve = do
  m0 <- seedModel
  st <- getSession m0
  -- secp256k1 OID (DER): a real curve we do not execute.
  let k1 = hex "06052b8104000a"
      tmpl = (AttrEcParams, ValBytes k1)
        : filter ((/= AttrEcParams) . fst) ecPubTmpl
  expectReject CKR_CURVE_NOT_SUPPORTED (planCreateObject m0 st tmpl)

caseBadPoint :: IO ()
caseBadPoint = do
  m0 <- seedModel
  st <- getSession m0
  let raw = BS.drop 2 ecPointWrapped
      bads =
        [ ("unwrapped", raw)
        , ("trailing garbage", ecPointWrapped <> "zz")
        , ("compressed", BS.pack [0x04, 0x22] <> BS.pack [0x02] <> BS.replicate 32 0x11)
        , ("empty", BS.empty)
        ]
  mapM_ (\(label, point) -> do
    let tmpl = (AttrEcPoint, ValBytes point)
          : filter ((/= AttrEcPoint) . fst) ecPubTmpl
    case planCreateObject m0 st tmpl of
      Reject rej -> assertEqual ("bad point " ++ label) CKR_TEMPLATE_INCONSISTENT (rejCode rej)
      Immediate _ -> assertFailure ("bad point accepted: " ++ label)
      Execute _ _ -> assertFailure ("bad point executed: " ++ label)
    ) bads
  -- The unwrapper agrees directly: garbage in, Nothing out.
  assertBool "unwrap rejects garbage" (unwrapEcPoint 32 "zz" == Nothing)
  assertBool "curve rejects garbage" (curveOidOfParams "P-999" == Nothing)

caseValueConflict :: IO ()
caseValueConflict = do
  m0 <- seedModel
  st <- getSession m0
  let tmpl = (AttrValue, ValBytes "opaque") : rsaPrivTmpl
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st tmpl)

caseSealedComponents :: IO ()
caseSealedComponents = do
  let attrs = Map.fromList
        [ (AttrSensitive, ValBool True)
        , (AttrModulus, ValBytes rsaN)
        , (AttrPrivateExponent, ValBytes rsaD)
        , (AttrPrime1, ValBytes rsaP)
        , (AttrValue, ValBytes rsaP8Gold)
        ]
      PartialReads code results = getAttributes attrs
        [AttrModulus, AttrPrivateExponent, AttrPrime1, AttrValue]
  assertEqual "sealed code" CKR_ATTRIBUTE_SENSITIVE code
  assertEqual "modulus readable"
    (Just (ResOk (ValBytes rsaN))) (lookup AttrModulus results)
  assertEqual "private exponent sealed"
    (Just ResSensitive) (lookup AttrPrivateExponent results)
  assertEqual "prime sealed"
    (Just ResSensitive) (lookup AttrPrime1 results)
  assertEqual "value sealed"
    (Just ResSensitive) (lookup AttrValue results)

caseCurveTableAgreement :: IO ()
caseCurveTableAgreement = do
  -- The core OID table and the FFI wire mapping agree both ways on
  -- the three curves; anything else passes through untouched.
  let oids = ["06082a8648ce3d030107", "06052b81040022", "06052b81040023"]
      names = ["P-256", "P-384", "P-521"]
  mapM_ (\(name, oid) -> do
    assertEqual ("core resolves " ++ name) (Just (hex oid)) (curveOidOfParams (BS8.pack name))
    assertEqual ("core resolves DER " ++ name) (Just (hex oid)) (curveOidOfParams (hex oid))
    assertEqual ("ffi emits " ++ name) (hex oid) (ecParamsToWire (BS8.pack name))
    ) (zip names oids)

caseEcExecutes :: IO ()
caseEcExecutes = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, _, privAttrs) <- doCreate m0 st ecPrivTmpl
  privDer <- storedValue privAttrs
  (_, _, pubAttrs) <- doCreate m1 st ecPubTmpl
  pubDer <- storedValue pubAttrs
  let spec = SigECDSA (EcSpec "P-256" "RAW") (Just D_SHA256)
  sres <- sign env spec (KeyDer privDer) "import-msg"
  sig <- case sres of
    EngineOk s -> pure s
    EngineFail err -> assertFailure ("imported EC sign failed: " ++ show err) >> undefined
  assertEqual "raw signature length" 64 (BS.length sig)
  vres <- verify env spec (KeyDer pubDer) "import-msg" sig
  case vres of
    EngineOk () -> pure ()
    EngineFail err -> assertFailure ("imported EC verify failed: " ++ show err)

caseRsaExecutes :: IO ()
caseRsaExecutes = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, _, privAttrs) <- doCreate m0 st rsaPrivTmpl
  privDer <- storedValue privAttrs
  (_, _, pubAttrs) <- doCreate m1 st rsaPubTmpl
  pubDer <- storedValue pubAttrs
  let spec = SigRSA_PKCS1v15 D_SHA256
  sres <- sign env spec (KeyDer privDer) "import-msg"
  sig <- case sres of
    EngineOk s -> pure s
    EngineFail err -> assertFailure ("imported RSA sign failed: " ++ show err) >> undefined
  vres <- verify env spec (KeyDer pubDer) "import-msg" sig
  case vres of
    EngineOk () -> pure ()
    EngineFail err -> assertFailure ("imported RSA verify failed: " ++ show err)

rsaN :: ByteString
rsaN = hex $ concat
    [ "bf249542389ea0de381c11c04c7777e6c56106165ec581cc378e6f9022cd2b4f"
    , "efd66e575e7043004afef1e4916177cea097cef02d4f09de587d869840cd75ec"
    , "a6adb70c19824f9a8a573c9ac337876cd2c490e6c5d69a686386009d54d13f1b"
    , "1be0a71055f23717d81bdc060c29d0ec7a6d8280a677ab92d65c9b64981300e4"
    , "a4eb60e4180189362c964ba3d55ca2db2d2998331ea0e87ab44d577fe8533717"
    , "9f02cf8d71404b4f8bd99e4e3e636c45ceea91e7660165f35451ee15fd44b42a"
    , "5eee7552aaccc25737be7f3d43542a43cc46b39fb127608c5a055327d339855e"
    , "838995295160067a417cc8c3095ee012bf078da33c71becae36b9805c174f357"
    ]

rsaE :: ByteString
rsaE = hex $ concat
    [ "010001"
    ]

rsaD :: ByteString
rsaD = hex $ concat
    [ "02147aaaa8fabcedbe219165e22478ac626079befb92b2fa0f1960886a8088b9"
    , "f5765966b4fde16a1ae6d1a8b6eb9f1b4e0468e43f31f97daf167fef9f363d29"
    , "7144e4558adf855092b47bfc83d1a7b51cf40ba449e9d9c34cb5f4181788b162"
    , "f0f78db4854d934b91f6a25079ddbdf5722847ea70cff8e62a540152e3bec287"
    , "3598079bf1965083cca686d500ab2867c43db553dd2894a3014fa30814f58966"
    , "b7f91e71b9c6928f41d22587daa3a939b409b9aeac3765404b0b3a890000c2e3"
    , "480d90950529f73df1340f69cc8be3c69def997524a3883cc618f51a81130842"
    , "f094b95699d093acb3e8c59a9a65b968101f6220638265e398f8f65ba6363ca5"
    ]

rsaP :: ByteString
rsaP = hex $ concat
    [ "f38edb79d7c425b930bee769f17aa3cc565f6e0a72b7fd0c734a0257960213f5"
    , "c5c5d16887e80d0d8c9136daa855e26e38319f7cd5f454b875e9eff1c9a6dc88"
    , "753a65d825d079d1fd9b8d1843e250793279877e1db7bd932b09473a1973ce71"
    , "0f5179baf192a17052a66c5247205bdad49fb48938b6590d5f2154820337498b"
    ]

rsaQ :: ByteString
rsaQ = hex $ concat
    [ "c8e8439d64764eaff4f6bf45bc56df3280d3c5aeedae00f0099f3d169db75f3a"
    , "0105900eef944f120f0d49d63d623e07b6feafa043914bf8e4ae243a9f82b853"
    , "dc1e347b262a250423d1f53f097cdce6677813a277f8eca15b5a61acb08bbdc2"
    , "042a0457492f09488ab22936aa8e098798484a230f3c4d27294589d4c8a1bee5"
    ]

rsaDp :: ByteString
rsaDp = hex $ concat
    [ "17e28b9d804e6910a73a21819f3fd2ae684e05819acc76517140f1c7db1b2b0f"
    , "f02c3d240e27f097c2903f1be4643fc765556079a295ca7528831f97cb99c488"
    , "d14e3fcc99b0bf319bb85476ebb95700fbb5355765dcae07afb1c23d6d5f9100"
    , "3f6b530fc53f06fbf7ef0032756d33f4dae32a96466c83812f321a9281743b8f"
    ]

rsaDq :: ByteString
rsaDq = hex $ concat
    [ "80b900096a02bb2bd5e1fa6f2ddae32ab28bfd0eb54e555f766ac673251e062f"
    , "5dd43896b93de6e3852d586fa1e8be21a747cb32fdd7ac3b8e195d310a5e70c7"
    , "9a32e8213734ad7ed78c807ba112955e325127136396e3d606780438e6ecc1e9"
    , "fb4d0876fc76dc95d3f78e9c6dee8f80873b59f4d8a02436c124c2c8c8bb8959"
    ]

rsaQinv :: ByteString
rsaQinv = hex $ concat
    [ "3cefd2574cbb2056d55f71c3fe82090a9797c6c038d1ef045e0373081801f4e4"
    , "68f7822b9580bcd21aac3c601a330ca745978cd01761cbccf29201086defab1f"
    , "08ec5024b60b79ed839dbf43c9c35a07da5cf8163fc4c57a1e06b20378077dab"
    , "fb54e39d56bf2a4d478187829ec00236001f1503a903482246a21aac1c04ae4f"
    ]

ecScalar :: ByteString
ecScalar = hex $ concat
    [ "5bc5fc2e1cb344d11de202ea057cbfd5da5f9a9a54a83fda363e5742b044366c"
    ]

ecPointWrapped :: ByteString
ecPointWrapped = hex $ concat
    [ "044104a113ffac941b89a293f5bb308496c60f74732c92b5724a97191ba3f76d"
    , "afa9b00ba279852742b80f7e8bc51f7fd41b368d1c611c391a4abd0559ddf16b"
    , "63ee01"
    ]

rsaP8Gold :: ByteString
rsaP8Gold = hex $ concat
    [ "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201"
    , "000282010100bf249542389ea0de381c11c04c7777e6c56106165ec581cc378e"
    , "6f9022cd2b4fefd66e575e7043004afef1e4916177cea097cef02d4f09de587d"
    , "869840cd75eca6adb70c19824f9a8a573c9ac337876cd2c490e6c5d69a686386"
    , "009d54d13f1b1be0a71055f23717d81bdc060c29d0ec7a6d8280a677ab92d65c"
    , "9b64981300e4a4eb60e4180189362c964ba3d55ca2db2d2998331ea0e87ab44d"
    , "577fe85337179f02cf8d71404b4f8bd99e4e3e636c45ceea91e7660165f35451"
    , "ee15fd44b42a5eee7552aaccc25737be7f3d43542a43cc46b39fb127608c5a05"
    , "5327d339855e838995295160067a417cc8c3095ee012bf078da33c71becae36b"
    , "9805c174f35702030100010282010002147aaaa8fabcedbe219165e22478ac62"
    , "6079befb92b2fa0f1960886a8088b9f5765966b4fde16a1ae6d1a8b6eb9f1b4e"
    , "0468e43f31f97daf167fef9f363d297144e4558adf855092b47bfc83d1a7b51c"
    , "f40ba449e9d9c34cb5f4181788b162f0f78db4854d934b91f6a25079ddbdf572"
    , "2847ea70cff8e62a540152e3bec2873598079bf1965083cca686d500ab2867c4"
    , "3db553dd2894a3014fa30814f58966b7f91e71b9c6928f41d22587daa3a939b4"
    , "09b9aeac3765404b0b3a890000c2e3480d90950529f73df1340f69cc8be3c69d"
    , "ef997524a3883cc618f51a81130842f094b95699d093acb3e8c59a9a65b96810"
    , "1f6220638265e398f8f65ba6363ca502818100f38edb79d7c425b930bee769f1"
    , "7aa3cc565f6e0a72b7fd0c734a0257960213f5c5c5d16887e80d0d8c9136daa8"
    , "55e26e38319f7cd5f454b875e9eff1c9a6dc88753a65d825d079d1fd9b8d1843"
    , "e250793279877e1db7bd932b09473a1973ce710f5179baf192a17052a66c5247"
    , "205bdad49fb48938b6590d5f2154820337498b02818100c8e8439d64764eaff4"
    , "f6bf45bc56df3280d3c5aeedae00f0099f3d169db75f3a0105900eef944f120f"
    , "0d49d63d623e07b6feafa043914bf8e4ae243a9f82b853dc1e347b262a250423"
    , "d1f53f097cdce6677813a277f8eca15b5a61acb08bbdc2042a0457492f09488a"
    , "b22936aa8e098798484a230f3c4d27294589d4c8a1bee502818017e28b9d804e"
    , "6910a73a21819f3fd2ae684e05819acc76517140f1c7db1b2b0ff02c3d240e27"
    , "f097c2903f1be4643fc765556079a295ca7528831f97cb99c488d14e3fcc99b0"
    , "bf319bb85476ebb95700fbb5355765dcae07afb1c23d6d5f91003f6b530fc53f"
    , "06fbf7ef0032756d33f4dae32a96466c83812f321a9281743b8f0281810080b9"
    , "00096a02bb2bd5e1fa6f2ddae32ab28bfd0eb54e555f766ac673251e062f5dd4"
    , "3896b93de6e3852d586fa1e8be21a747cb32fdd7ac3b8e195d310a5e70c79a32"
    , "e8213734ad7ed78c807ba112955e325127136396e3d606780438e6ecc1e9fb4d"
    , "0876fc76dc95d3f78e9c6dee8f80873b59f4d8a02436c124c2c8c8bb89590281"
    , "803cefd2574cbb2056d55f71c3fe82090a9797c6c038d1ef045e0373081801f4"
    , "e468f7822b9580bcd21aac3c601a330ca745978cd01761cbccf29201086defab"
    , "1f08ec5024b60b79ed839dbf43c9c35a07da5cf8163fc4c57a1e06b20378077d"
    , "abfb54e39d56bf2a4d478187829ec00236001f1503a903482246a21aac1c04ae"
    , "4f"
    ]

rsaSpkiGold :: ByteString
rsaSpkiGold = hex $ concat
    [ "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
    , "00bf249542389ea0de381c11c04c7777e6c56106165ec581cc378e6f9022cd2b"
    , "4fefd66e575e7043004afef1e4916177cea097cef02d4f09de587d869840cd75"
    , "eca6adb70c19824f9a8a573c9ac337876cd2c490e6c5d69a686386009d54d13f"
    , "1b1be0a71055f23717d81bdc060c29d0ec7a6d8280a677ab92d65c9b64981300"
    , "e4a4eb60e4180189362c964ba3d55ca2db2d2998331ea0e87ab44d577fe85337"
    , "179f02cf8d71404b4f8bd99e4e3e636c45ceea91e7660165f35451ee15fd44b4"
    , "2a5eee7552aaccc25737be7f3d43542a43cc46b39fb127608c5a055327d33985"
    , "5e838995295160067a417cc8c3095ee012bf078da33c71becae36b9805c174f3"
    , "570203010001"
    ]

ecSpkiGold :: ByteString
ecSpkiGold = hex $ concat
    [ "3059301306072a8648ce3d020106082a8648ce3d03010703420004a113ffac94"
    , "1b89a293f5bb308496c60f74732c92b5724a97191ba3f76dafa9b00ba2798527"
    , "42b80f7e8bc51f7fd41b368d1c611c391a4abd0559ddf16b63ee01"
    ]

ecP8NoPubGold :: ByteString
ecP8NoPubGold = hex $ concat
    [ "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201"
    , "0104205bc5fc2e1cb344d11de202ea057cbfd5da5f9a9a54a83fda363e5742b0"
    , "44366c"
    ]

