{- | DH recipe pins: the agreement shape-group recipe contract.

Covers the mechanism table (PKCS#3 + X9.42 rows with their base
key types), uniform @dh-params\/1@ codec (roundtrip, truncation,
overrun, trailing), parameter validation (null-KDF + non-empty
peer; every other KDF refused), the secret-width rule (prime scan
from PKCS#8\/SPKI DER incl. both DH OIDs, OID-gated against EC
DER, max fallback for opaque material), the derive planner
mapping ('planDerive' accepts DH frames, denies bad params \/
wrong base type \/ over-width templates), and the driver mapping
('dhParamsFor' to @(DhPlain, peer)@).

slice 10e (Diffie-Hellman over EVP DH). Key fixtures are pinned
CLI output (OpenSSL 4.0.2, ffdhe2048): @dhPrivA@ is a PKCS#8 DH
private key, @dhPeerB@\/@dhPeerA@ the 256-byte peer public
values, @dhSecretAB@ the agreement secret A↔B.
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeDhSpec (spec) where

import qualified Data.ByteString as BS
import Data.Char (digitToInt, isHexDigit)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend (DhSpec (..))
import Haskoki.Engine.Driver (dhParamsFor)
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , emptyModel
  )
import Haskoki.Operation (emptySessionOps)
import Haskoki.Operation.Derive (encodeDeriveParams, planDerive)
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , ckkDh
  , ckkEc
  , ckkGenericSecret
  , ckkX9_42Dh
  , ckoSecretKey
  )
import Haskoki.Recipe.Dh
  ( DhRecipe (..)
  , decodeDhParams
  , dhCodec
  , dhCodecFor
  , dhParamsValid
  , dhPrimeWidthOfDer
  , dhRecipeFor
  , dhRecipes
  , dhSecretWidth
  , dhSecretWidthMax
  , encodeDhParams
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated
  ( ckm_DH_PKCS_DERIVE
  , ckm_X9_42_DH_DERIVE
  , ckm_SHA256
  )
import Haskoki.Registry.Types (ParameterCodec (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

-- ---------------------------------------------------------------------------
-- Fixtures (pinned OpenSSL 4.0.2 output, ffdhe2048)
-- ---------------------------------------------------------------------------

hex :: String -> BS.ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [] = []
    go _ = error "odd hex"

dhPrivA :: BS.ByteString
dhPrivA = hex "3082013f0201003082011706092a864886f70d010301308201080282010100ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff020102041f021d009fa3ef2b4c8dfa3c47df391c7a7bc8018609291f24a761a569699de1"

dhPeerB :: BS.ByteString
dhPeerB = hex "c75ae3465dfd93b6a1b50841c679448a34ef087b30edfe7c25bd9d897d105e6dd943419867a2009eea2f0e931b1925e134468889a06d92c3a5251af1b39a4092ba99e124f795852a9de46f85b421f4d5232d73b0b2ba42f033609789f0ca2bc316f79b7a64ad04f410dfb0443ebac1e8844485e9e1c3772ef0558623a9ef3476ff8549d3a259511e0490a7b4af4f8f0b73582e1cf2bafdc4348614163197203938e4c95ecbddf0bc638d09a12d473e5b1cc576831e43a0cb35f8561e40f5c264d66a58f3fcc14ed3bf9a71ac134810fca2da8a98c47c3db55f05d228a9efd4a3de7db7d1e45b79a0636fc3f6885efce43b24900b2341ef074543d54120dcd700"

-- | A P-256 SPKI (EC OID): the OID gate must refuse it as DH.
ecSpki :: BS.ByteString
ecSpki = hex "3059301306072a8648ce3d020106082a8648ce3d03010703420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"

-- | A 1024-bit DSA SPKI (pinned CLI output): DH-shaped parameters
-- (SEQ of INTEGERs, p first) under a non-DH OID — the true OID
-- gate pin (an EC key fails on shape, never reaching the gate).
dsaSpki :: BS.ByteString
dsaSpki = hex "308201bf3082013306072a8648ce3804013082012602818100b867ca2b9d5492c483a19abf0f8d637359329324cf6ca8256bbf0903b419b6d585e59f2093ab802d3a9dcc5955311753605e17186cae28f827bfdd2bb5d34625036b68653daa54f3267ea7a0fad3e67ed37abc02b9ea44e2b2bdbadac614146422f973d952d13a4c4922e16e0016104bf5cfceb0cc941bbabbf1305847c0b47d021d00a1e94e2b4ead8d88a8bcd46d2412c907e30145784ad217f1ca30920f02818022fe3d64d3b4648e3c088ec7dcf6b15ba70e86cfc0a2037e13566053f7de17b41a8a8ce895863eb5d229a8d3e931f2ca476090d7f06868ab7cae1622d170998e9c12ec96df033bdc4a61e168c0421cb4023cfb81c90dd73d9ead1c46acdb4558e4df2091ed72d6181c871f8408a7354973d10a5adb389bc47b880c92bcaa00cf03818500028181008d5f4f60ed1c70502d625e3ec94605ea291a84846ea3540d8aaafe27a29e6907ebe3e0ad11d28e1e8ca9509ae597115099773a8bb490e4686e51ab23f5c73ad66c29323c9761ea07eec799bcdcb5b7d25344f7688bbf7b56b97cbd44813d059590990e5cb238ad557e864e49043329afa5e7423f0dc73b98283d87cb93eed456"

dhMech, x942Mech :: MechanismId
dhMech = MechanismId ckm_DH_PKCS_DERIVE
x942Mech = MechanismId ckm_X9_42_DH_DERIVE

recipeOf :: Text -> DhRecipe
recipeOf name = case [ r | r <- dhRecipes, dhName r == name ] of
  (r : _) -> r
  [] -> error ("missing DH recipe: " ++ T.unpack name)

-- ---------------------------------------------------------------------------
-- Spec
-- ---------------------------------------------------------------------------

spec :: TestTree
spec = testGroup "DH recipe"
  [ testCase "table: two rows with key types" caseTable
  , testCase "lookup resolves both rows" caseLookup
  , testCase "codec is uniform dh-params/1" caseCodec
  , testCase "params: null-KDF accept, others refuse" caseParams
  , testCase "codec: truncation/overrun/trailing refuse" caseFraming
  , testCase "secret width follows the prime" caseWidth
  , testCase "planDerive: DH accept and deny" casePlan
  , testCase "driver maps the agreement pair" caseDriver
  ]

caseTable :: IO ()
caseTable = do
  assertEqual "row count" 2 (length dhRecipes)
  assertEqual "pkcs name" "CKM_DH_PKCS_DERIVE" (dhName (recipeOf "CKM_DH_PKCS_DERIVE"))
  assertEqual "pkcs key type" ckkDh (dhKeyType (recipeOf "CKM_DH_PKCS_DERIVE"))
  assertEqual "x942 key type" ckkX9_42Dh (dhKeyType (recipeOf "CKM_X9_42_DH_DERIVE"))

caseLookup :: IO ()
caseLookup = do
  assertEqual "pkcs resolves" (Just (recipeOf "CKM_DH_PKCS_DERIVE")) (dhRecipeFor dhMech)
  assertEqual "x942 resolves" (Just (recipeOf "CKM_X9_42_DH_DERIVE")) (dhRecipeFor x942Mech)
  assertEqual "unknown misses" Nothing
    (dhRecipeFor (MechanismId ckm_SHA256))

caseCodec :: IO ()
caseCodec = do
  assertEqual "codec name" "dh-params" (codecName dhCodec)
  assertEqual "codec version" 1 (codecVersion dhCodec)
  assertEqual "row codec uniform" dhCodec
    (dhCodecFor (recipeOf "CKM_X9_42_DH_DERIVE"))

caseParams :: IO ()
caseParams = do
  let pkcs = recipeOf "CKM_DH_PKCS_DERIVE"
      good = encodeDhParams 0 dhPeerB
  assertBool "null-KDF + peer valid" (dhParamsValid pkcs good)
  assertEqual "roundtrip" (Just (0, dhPeerB)) (decodeDhParams good)
  -- Every nonzero KDF selector refuses (deferred dimension).
  assertBool "kdf 1 refuses" (not (dhParamsValid pkcs (encodeDhParams 1 dhPeerB)))
  assertBool "kdf 6 refuses" (not (dhParamsValid pkcs (encodeDhParams 6 dhPeerB)))
  assertBool "empty peer refuses" (not (dhParamsValid pkcs (encodeDhParams 0 BS.empty)))
  assertBool "garbage refuses" (not (dhParamsValid pkcs "not-a-frame"))
  -- X9.42 row: same shape, same null-KDF-only rule.
  let x9 = recipeOf "CKM_X9_42_DH_DERIVE"
  assertBool "x942 null-KDF valid" (dhParamsValid x9 good)
  assertBool "x942 kdf refuses" (not (dhParamsValid x9 (encodeDhParams 2 dhPeerB)))

caseFraming :: IO ()
caseFraming = do
  let good = encodeDhParams 0 dhPeerB
  assertEqual "truncated refuses" Nothing
    (decodeDhParams (BS.take (BS.length good - 1) good))
  assertEqual "short header refuses" Nothing
    (decodeDhParams (BS.take 10 good))
  assertEqual "trailing refuses" Nothing
    (decodeDhParams (good <> "x"))
  -- Overrun length (peerLen past the buffer) refuses.
  let badLen = encodeDhParams 0 BS.empty
      forged = BS.take 8 badLen <> BS.pack [0, 0, 0, 0, 0, 0, 0x04, 0x00] <> "ab"
  assertEqual "overrun refuses" Nothing (decodeDhParams forged)

caseWidth :: IO ()
caseWidth = do
  assertEqual "pkcs8 prime width" (Just 256) (dhPrimeWidthOfDer dhPrivA)
  assertEqual "secret width" 256 (dhSecretWidth dhPrivA)
  assertEqual "garbage width max" Nothing (dhPrimeWidthOfDer "opaque")
  assertEqual "garbage secret max" dhSecretWidthMax (dhSecretWidth "opaque")
  assertEqual "EC DER gated out" Nothing (dhPrimeWidthOfDer ecSpki)
  assertEqual "EC secret max" dhSecretWidthMax (dhSecretWidth ecSpki)
  assertEqual "DSA DER gated out" Nothing (dhPrimeWidthOfDer dsaSpki)
  assertEqual "DSA secret max" dhSecretWidthMax (dhSecretWidth dsaSpki)
  assertEqual "max is 512" 512 dhSecretWidthMax

-- ---------------------------------------------------------------------------
-- planDerive pins (light model harness: one DH base key + handle)
-- ---------------------------------------------------------------------------

baseOid :: ObjectId
baseOid = ObjectId 43

baseHandle :: ExternalHandle
baseHandle = ExternalHandle 403

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

mkBaseModel :: Word64 -> BS.ByteString -> Bool -> Model
mkBaseModel keyType mat canDerive = emptyModel
  { mObjects = Map.fromList [(baseOid, ost)]
  , mHandles = Map.fromList [(baseHandle, HandleBinding baseOid (Generation 1))]
  }
  where
    ost = ObjectState
      { osId = baseOid
      , osRevision = Revision 1
      , osGeneration = Generation 1
      , osAttrs = Map.fromList
          [ (AttrClass, ValULong ckoSecretKey)
          , (AttrKeyType, ValULong keyType)
          , (AttrPrivate, ValBool False)
          , (AttrDerive, ValBool canDerive)
          , (AttrValue, ValBytes mat)
          ]
      , osOwner = Nothing
      , osSlot = SlotId 7
      }

derivedTmpl :: Int -> [(AttributeType, AttributeValue)]
derivedTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  ]

-- | Derive template without CKA_VALUE_LEN (defaults to the full secret).
derivedTmplNoLen :: [(AttributeType, AttributeValue)]
derivedTmplNoLen =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrToken, ValBool False)
  ]

expectDeny :: String -> ReturnCode -> KeyPlan -> IO ()
expectDeny label code plan = case plan of
  KeyDenied (KeyDeny c _) -> assertEqual ("deny " ++ label) code c
  other -> assertFailure ("expected denial, got " ++ show other)

casePlan :: IO ()
casePlan = do
  let m = mkBaseModel ckkDh dhPrivA True
      blob peer = encodeDeriveParams (encodeDhParams 0 peer)
  -- Accepted: single key under the prime width; the effect carries
  -- the DH blob as mechanism params with empty info.
  case planDerive defaultRules m testSession dhMech baseHandle (blob dhPeerB [derivedTmpl 32]) of
    KeyEffect _ (FxDerive mech (Just oid) params info total) -> do
      assertEqual "mech" dhMech mech
      assertEqual "base" baseOid oid
      assertEqual "params" (encodeDhParams 0 dhPeerB) params
      assertEqual "info empty" BS.empty info
      assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- X9.42 row accepts against a CKK_X9_42_DH base.
  let mx = mkBaseModel ckkX9_42Dh dhPrivA True
  case planDerive defaultRules mx testSession x942Mech baseHandle (blob dhPeerB [derivedTmpl 64]) of
    KeyEffect _ (FxDerive mech _ _ _ total) -> do
      assertEqual "x942 mech" x942Mech mech
      assertEqual "x942 total" 64 total
    other -> assertFailure ("expected x942 effect, got " ++ show other)
  -- Over the prime width is ARGUMENTS_BAD (truncation cap).
  expectDeny "over-width" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession dhMech baseHandle (blob dhPeerB [derivedTmpl 257]))
  -- Bad params are PARAM_INVALID (never INVALID).
  expectDeny "bad params" CKR_MECHANISM_PARAM_INVALID
    (planDerive defaultRules m testSession dhMech baseHandle
      (encodeDeriveParams (encodeDhParams 3 dhPeerB) [derivedTmpl 32]))
  -- Wrong base key type is INCONSISTENT (contradiction outranks shape).
  expectDeny "ec base" CKR_KEY_TYPE_INCONSISTENT
    (planDerive defaultRules (mkBaseModel ckkEc dhPrivA True) testSession
      dhMech baseHandle (blob dhPeerB [derivedTmpl 32]))
  -- Opaque material plans against the max width.
  case planDerive defaultRules (mkBaseModel ckkDh (BS.replicate 40 0) True) testSession
    dhMech baseHandle (blob dhPeerB [derivedTmpl 512]) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "opaque total" 512 total
    other -> assertFailure ("expected opaque effect, got " ++ show other)
  -- Truncated frames and empty templates refuse.
  expectDeny "malformed blob" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession dhMech baseHandle "truncated")
  expectDeny "no templates" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession dhMech baseHandle (blob dhPeerB []))
  -- Missing CKA_VALUE_LEN defaults to the full agreement secret
  -- (PKCS#11 v3.2: "if it has one" a length); the default is
  -- stamped on the pending object so readback matches explicit.
  case planDerive defaultRules m testSession dhMech baseHandle (blob dhPeerB [derivedTmplNoLen]) of
    KeyEffect (PwDerive [po] [n]) (FxDerive _ _ _ _ total) -> do
      assertEqual "default total" 256 total
      assertEqual "default len" 256 n
      assertEqual "default stamped" (Just (ValULong 256))
        (Map.lookup AttrValueLen (poAttrs po))
    other -> assertFailure ("expected defaulted effect, got " ++ show other)
  -- Unscannable base material defaults to the max width.
  case planDerive defaultRules (mkBaseModel ckkDh (BS.replicate 40 0) True) testSession
        dhMech baseHandle (blob dhPeerB [derivedTmplNoLen]) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "opaque default total" 512 total
    other -> assertFailure ("expected defaulted effect, got " ++ show other)
  -- Base must permit derivation; handle must resolve.
  expectDeny "derive mark" CKR_KEY_FUNCTION_NOT_PERMITTED
    (planDerive defaultRules (mkBaseModel ckkDh dhPrivA False) testSession
      dhMech baseHandle (blob dhPeerB [derivedTmpl 32]))
  expectDeny "bad handle" CKR_KEY_HANDLE_INVALID
    (planDerive defaultRules m testSession dhMech (ExternalHandle 999) (blob dhPeerB [derivedTmpl 32]))

caseDriver :: IO ()
caseDriver = do
  let p = encodeDhParams 0 dhPeerB
  assertEqual "pkcs maps" (Just (DhPlain, dhPeerB)) (dhParamsFor dhMech p)
  assertEqual "x942 maps" (Just (DhPlain, dhPeerB)) (dhParamsFor x942Mech p)
  assertEqual "kdf rejected" Nothing
    (dhParamsFor dhMech (encodeDhParams 1 dhPeerB))
  assertEqual "non-DH uncovered" Nothing
    (dhParamsFor (MechanismId ckm_SHA256) p)
