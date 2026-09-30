{- | IKE recipe pins (slice 11j).

'Haskoki.Recipe.Ike' owns the canonical codec, parameter
validation, and the four-row table; 'Haskoki.Operation.Derive'
owns admission (including the aux-handle resolution onto
'fxKey2'); 'Haskoki.Engine.Driver' owns the
params-to-execution mapping. This spec pins all three against
the table: the table shape, id resolution, codec identity, the
per-kind parameter matrix (aux rules, flags, key number, PRF
range, ceilings), the PRF mechanism map (HMAC selectors only),
the base key types, one planDerive accept\/deny set, and the
driver mapping.
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeIkeSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend (DigestAlg (..))
import Haskoki.Engine.Driver (IkeExec (..), ikeParamsFor)
import Haskoki.FFI.NativeParams
  ( ike1ExtStructToCanonical
  , ike1PrfStructToCanonical
  , ikePrfPlusStructToCanonical
  , ikePrfStructToCanonical
  )
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , emptyModel
  )
import Haskoki.Operation (emptySessionOps)
import Haskoki.Operation.Derive
  ( encodeDeriveParams
  , planDerive
  )
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , ckkEc
  , ckkGenericSecret
  , ckkSha256Hmac
  , ckoSecretKey
  )
import Haskoki.Recipe.Ike
import Haskoki.Registry.Generated
  ( ckm_AES_ECB
  , ckm_IKE1_EXTENDED_DERIVE
  , ckm_IKE1_PRF_DERIVE
  , ckm_IKE2_PRF_PLUS_DERIVE
  , ckm_IKE_PRF_DERIVE
  , ckm_MD2_HMAC
  , ckm_SHA256
  , ckm_SHA256_HMAC
  , ckm_SHA384_HMAC
  )
import Haskoki.Registry.Types (MechanismId (..))
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

spec :: TestTree
spec = testGroup "IKE recipe"
  [ testCase "table: four rows with kinds" caseTable
  , testCase "lookup: ids resolve, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: per-kind matrix" caseParams
  , testCase "PRF mechanisms map to codes" casePrfCodes
  , testCase "base key types" caseBaseTypes
  , testCase "planDerive: accept and deny" casePlan
  , testCase "driver maps the pair to the exec tuple" caseDriverMap
  , testCase "native structs translate" caseNative
  ]

caseTable :: IO ()
caseTable = assertEqual "four rows" expected
  [(ikName r, ikKind r) | r <- ikeRecipes]
  where
    expected =
      [ ("CKM_IKE2_PRF_PLUS_DERIVE", Ike2PrfPlus)
      , ("CKM_IKE_PRF_DERIVE", IkePrf)
      , ("CKM_IKE1_PRF_DERIVE", Ike1Prf)
      , ("CKM_IKE1_EXTENDED_DERIVE", Ike1Extended)
      ]

caseLookup :: IO ()
caseLookup = do
  mapM_ resolves
    [ ckm_IKE2_PRF_PLUS_DERIVE
    , ckm_IKE_PRF_DERIVE
    , ckm_IKE1_PRF_DERIVE
    , ckm_IKE1_EXTENDED_DERIVE
    ]
  assertEqual "other id" Nothing (ikeRecipeFor (MechanismId 0x4032))
  where
    resolves i = assertBool ("resolves " ++ show i)
      (case ikeRecipeFor (MechanismId i) of Just _ -> True; Nothing -> False)

caseCodec :: IO ()
caseCodec = do
  let frame = encodeIkeParams 4 1 7 405 (BS.replicate 16 1) (BS.replicate 16 2)
  assertEqual "roundtrip" (Just (4, 1, 7, 405, BS.replicate 16 1, BS.replicate 16 2))
    (decodeIkeParams frame)
  let plus = encodeIkeParams 4 0 0 0 (BS.replicate 32 9) BS.empty
  assertEqual "prf+ roundtrip" (Just (4, 0, 0, 0, BS.replicate 32 9, BS.empty))
    (decodeIkeParams plus)

resolveIke :: Word64 -> IO IkeRecipe
resolveIke mid = case ikeRecipeFor (MechanismId mid) of
  Just r -> pure r
  Nothing -> assertFailure ("recipe must resolve " ++ show mid)

caseParams :: IO ()
caseParams = do
  rPlus <- resolveIke ckm_IKE2_PRF_PLUS_DERIVE
  rPrf <- resolveIke ckm_IKE_PRF_DERIVE
  r1 <- resolveIke ckm_IKE1_PRF_DERIVE
  rExt <- resolveIke ckm_IKE1_EXTENDED_DERIVE
  let seed32 = BS.replicate 32 9
      ni = BS.replicate 16 1
      nr = BS.replicate 16 2
  -- Valid shapes.
  assertBool "prf+ valid"
    (ikeParamsValid rPlus (encodeIkeParams 4 0 0 0 seed32 BS.empty))
  assertBool "prf valid key order"
    (ikeParamsValid rPrf (encodeIkeParams 4 0 0 0 ni nr))
  assertBool "prf valid data-as-key"
    (ikeParamsValid rPrf (encodeIkeParams 4 1 0 0 ni nr))
  assertBool "ike1 valid"
    (ikeParamsValid r1 (encodeIkeParams 4 0 7 405 ni nr))
  assertBool "ext valid without aux"
    (ikeParamsValid rExt (encodeIkeParams 4 0 0 0 seed32 BS.empty))
  assertBool "ext valid with aux"
    (ikeParamsValid rExt (encodeIkeParams 4 0 0 405 seed32 BS.empty))
  assertBool "prf 0 structurally valid (planner denies PARAM_INVALID)"
    (ikeParamsValid rPlus (encodeIkeParams 0 0 0 0 seed32 BS.empty))
  -- Refused shapes.
  assertBool "prf code range"
    (not (ikeParamsValid rPlus (encodeIkeParams 14 0 0 0 seed32 BS.empty)))
  assertBool "prf+ aux refused"
    (not (ikeParamsValid rPlus (encodeIkeParams 4 0 0 405 seed32 BS.empty)))
  assertBool "prf+ flags refused"
    (not (ikeParamsValid rPlus (encodeIkeParams 4 1 0 0 seed32 BS.empty)))
  assertBool "prf+ second blob refused"
    (not (ikeParamsValid rPlus (encodeIkeParams 4 0 0 0 seed32 ni)))
  assertBool "prf flags range"
    (not (ikeParamsValid rPrf (encodeIkeParams 4 2 0 0 ni nr)))
  assertBool "prf aux refused"
    (not (ikeParamsValid rPrf (encodeIkeParams 4 0 0 405 ni nr)))
  assertBool "ike1 aux required"
    (not (ikeParamsValid r1 (encodeIkeParams 4 0 7 0 ni nr)))
  assertBool "ike1 flags refused"
    (not (ikeParamsValid r1 (encodeIkeParams 4 1 7 405 ni nr)))
  assertBool "ext flags refused"
    (not (ikeParamsValid rExt (encodeIkeParams 4 1 0 0 seed32 BS.empty)))
  assertBool "ext keynum refused"
    (not (ikeParamsValid rExt (encodeIkeParams 4 0 3 0 seed32 BS.empty)))
  assertBool "truncation refused"
    (not (ikeParamsValid rPlus (BS.take 5 (encodeIkeParams 4 0 0 0 seed32 BS.empty))))
  assertBool "trailing refused"
    (not (ikeParamsValid rPlus (encodeIkeParams 4 0 0 0 seed32 BS.empty <> "x")))
  assertBool "ceiling refused"
    (not (ikeParamsValid rPlus (encodeIkeParams 4 0 0 0 (BS.replicate 70000 1) BS.empty)))

casePrfCodes :: IO ()
casePrfCodes = do
  assertEqual "SHA256_HMAC code" (Just 4) (ikePrfCodeFor (MechanismId ckm_SHA256_HMAC))
  assertEqual "SHA384_HMAC code" (Just 5) (ikePrfCodeFor (MechanismId ckm_SHA384_HMAC))
  assertEqual "bare digest refused" Nothing (ikePrfCodeFor (MechanismId ckm_SHA256))
  assertEqual "AES is no PRF" Nothing (ikePrfCodeFor (MechanismId ckm_AES_ECB))
  assertEqual "unserved HMAC is no PRF" Nothing (ikePrfCodeFor (MechanismId ckm_MD2_HMAC))

caseBaseTypes :: IO ()
caseBaseTypes = do
  assertBool "generic secret ok" (ikeBaseKeyOk ckkGenericSecret)
  assertBool "hmac ok" (ikeBaseKeyOk ckkSha256Hmac)
  assertBool "ec refused" (not (ikeBaseKeyOk ckkEc))

-- planDerive pins (light model harness: base + aux secret keys)
-- ---------------------------------------------------------------------------

baseOid :: ObjectId
baseOid = ObjectId 44

baseHandle :: ExternalHandle
baseHandle = ExternalHandle 404

auxOid :: ObjectId
auxOid = ObjectId 45

auxHandle :: ExternalHandle
auxHandle = ExternalHandle 405

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

mkSecret :: ObjectId -> Word64 -> BS.ByteString -> Bool -> ObjectState
mkSecret oid kty mat canDerive = ObjectState
  { osId = oid
  , osRevision = Revision 1
  , osGeneration = Generation 1
  , osAttrs = Map.fromList
      [ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong kty)
      , (AttrPrivate, ValBool False)
      , (AttrDerive, ValBool canDerive)
      , (AttrValue, ValBytes mat)
      ]
  , osOwner = Nothing
  , osSlot = SlotId 7
  }

mkIkeModel :: Word64 -> Bool -> Model
mkIkeModel baseType canDerive = emptyModel
  { mObjects = Map.fromList
      [ (baseOid, mkSecret baseOid baseType "secret" canDerive)
      , (auxOid, mkSecret auxOid ckkGenericSecret "auxkey" True)
      ]
  , mHandles = Map.fromList
      [ (baseHandle, HandleBinding baseOid (Generation 1))
      , (auxHandle, HandleBinding auxOid (Generation 1))
      ]
  }

derivedTmpl :: Int -> [(AttributeType, AttributeValue)]
derivedTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  ]

plusMech :: MechanismId
plusMech = MechanismId ckm_IKE2_PRF_PLUS_DERIVE

prfMech :: MechanismId
prfMech = MechanismId ckm_IKE_PRF_DERIVE

ike1Mech :: MechanismId
ike1Mech = MechanismId ckm_IKE1_PRF_DERIVE

extMech :: MechanismId
extMech = MechanismId ckm_IKE1_EXTENDED_DERIVE

plusFrame :: BS.ByteString
plusFrame = encodeIkeParams 4 0 0 0 (BS.replicate 32 9) BS.empty

prfFrame :: BS.ByteString
prfFrame = encodeIkeParams 4 1 0 0 (BS.replicate 16 1) (BS.replicate 16 2)

ike1Frame :: BS.ByteString
ike1Frame = encodeIkeParams 4 0 7 405 (BS.replicate 16 1) (BS.replicate 16 2)

extFrame :: BS.ByteString
extFrame = encodeIkeParams 4 0 0 0 (BS.replicate 20 3) BS.empty

expectDeny :: String -> ReturnCode -> KeyPlan -> IO ()
expectDeny label code plan = case plan of
  KeyDenied (KeyDeny c _) -> assertEqual ("deny " ++ label) code c
  other -> assertFailure ("expected denial, got " ++ show other)

casePlan :: IO ()
casePlan = do
  let m = mkIkeModel ckkGenericSecret True
      mh = mkIkeModel ckkSha256Hmac True
  -- Accepted: prf+ over a generic base, no aux.
  case planDerive defaultRules m testSession plusMech baseHandle
      (encodeDeriveParams plusFrame [derivedTmpl 32]) of
    KeyEffect _ (FxDerive mech (Just oid) Nothing params info total) -> do
      assertEqual "mech" plusMech mech
      assertEqual "base" baseOid oid
      assertEqual "params" plusFrame params
      assertEqual "info empty" BS.empty info
      assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Accepted: ike-prf over an HMAC base.
  case planDerive defaultRules mh testSession prfMech baseHandle
      (encodeDeriveParams prfFrame [derivedTmpl 32]) of
    KeyEffect _ (FxDerive mech (Just oid) Nothing _ _ total) -> do
      assertEqual "mech" prfMech mech
      assertEqual "base" baseOid oid
      assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Accepted: ike1 resolves the aux handle onto fxKey2.
  case planDerive defaultRules mh testSession ike1Mech baseHandle
      (encodeDeriveParams ike1Frame [derivedTmpl 32]) of
    KeyEffect _ (FxDerive mech (Just oid) (Just aux) _ _ total) -> do
      assertEqual "mech" ike1Mech mech
      assertEqual "base" baseOid oid
      assertEqual "aux" auxOid aux
      assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Accepted: extended without aux.
  case planDerive defaultRules m testSession extMech baseHandle
      (encodeDeriveParams extFrame [derivedTmpl 48]) of
    KeyEffect _ (FxDerive mech (Just oid) Nothing _ _ total) -> do
      assertEqual "mech" extMech mech
      assertEqual "total" 48 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Malformed frames refuse typed.
  expectDeny "junk params" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession plusMech baseHandle
      (encodeDeriveParams "junk" [derivedTmpl 32]))
  -- Output past the ceiling refuses typed.
  expectDeny "over ceiling" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession plusMech baseHandle
      (encodeDeriveParams plusFrame [derivedTmpl (maxIkeOutput + 1)]))
  -- A non-derive-marked base refuses typed.
  expectDeny "sealed base" CKR_KEY_FUNCTION_NOT_PERMITTED
    (planDerive defaultRules (mkIkeModel ckkGenericSecret False) testSession plusMech baseHandle
      (encodeDeriveParams plusFrame [derivedTmpl 32]))
  -- A wrong-typed base refuses typed.
  expectDeny "ec base" CKR_KEY_TYPE_INCONSISTENT
    (planDerive defaultRules (mkIkeModel ckkEc True) testSession plusMech baseHandle
      (encodeDeriveParams plusFrame [derivedTmpl 32]))
  -- An unmapped PRF selector refuses with the spec code.
  expectDeny "unmapped prf" CKR_MECHANISM_PARAM_INVALID
    (planDerive defaultRules m testSession plusMech baseHandle
      (encodeDeriveParams (encodeIkeParams 0 0 0 0 (BS.replicate 32 9) BS.empty) [derivedTmpl 32]))
  -- IKE1 without aux refuses typed.
  expectDeny "ike1 no aux" CKR_ARGUMENTS_BAD
    (planDerive defaultRules mh testSession ike1Mech baseHandle
      (encodeDeriveParams (encodeIkeParams 4 0 7 0 (BS.replicate 16 1) (BS.replicate 16 2)) [derivedTmpl 32]))
  -- An unknown aux handle refuses typed.
  expectDeny "unknown aux" CKR_KEY_HANDLE_INVALID
    (planDerive defaultRules mh testSession ike1Mech baseHandle
      (encodeDeriveParams (encodeIkeParams 4 0 7 999 (BS.replicate 16 1) (BS.replicate 16 2)) [derivedTmpl 32]))

caseDriverMap :: IO ()
caseDriverMap = do
  assertEqual "prf+ pair decodes"
    (Just (IkeExec Ike2PrfPlus D_SHA256 0 0 (BS.replicate 32 9) BS.empty))
    (ikeParamsFor plusMech plusFrame)
  assertEqual "prf pair decodes"
    (Just (IkeExec IkePrf D_SHA256 1 0 (BS.replicate 16 1) (BS.replicate 16 2)))
    (ikeParamsFor prfMech prfFrame)
  assertEqual "ike1 pair decodes"
    (Just (IkeExec Ike1Prf D_SHA256 0 7 (BS.replicate 16 1) (BS.replicate 16 2)))
    (ikeParamsFor ike1Mech ike1Frame)
  assertEqual "ext pair decodes"
    (Just (IkeExec Ike1Extended D_SHA256 0 0 (BS.replicate 20 3) BS.empty))
    (ikeParamsFor extMech extFrame)
  assertEqual "junk refused" Nothing
    (ikeParamsFor plusMech "junk")

caseNative :: IO ()
caseNative = do
  let seed = BS.replicate 32 9
      ni = BS.replicate 16 1
      nr = BS.replicate 16 2
  -- prf+: the PRF id plus the seed bytes.
  assertEqual "prf+ translates"
    (Just (encodeIkeParams 4 0 0 0 seed BS.empty))
    (ikePrfPlusStructToCanonical ckm_SHA256_HMAC seed)
  assertEqual "prf+ bare digest marks code 0"
    (Just (encodeIkeParams 0 0 0 0 seed BS.empty))
    (ikePrfPlusStructToCanonical ckm_SHA256 seed)
  assertEqual "prf+ unmapped PRF marks code 0"
    (Just (encodeIkeParams 0 0 0 0 seed BS.empty))
    (ikePrfPlusStructToCanonical ckm_AES_ECB seed)
  -- ike-prf: flags ride, rekey refuses.
  assertEqual "prf translates"
    (Just (encodeIkeParams 4 1 0 0 ni nr))
    (ikePrfStructToCanonical ckm_SHA256_HMAC True False ni nr 0)
  assertEqual "prf rekey refuses" Nothing
    (ikePrfStructToCanonical ckm_SHA256_HMAC False True ni nr 77)
  assertEqual "prf rekey handle refuses" Nothing
    (ikePrfStructToCanonical ckm_SHA256_HMAC False False ni nr 77)
  assertEqual "prf unmapped PRF marks code 0"
    (Just (encodeIkeParams 0 0 0 0 ni nr))
    (ikePrfStructToCanonical ckm_AES_ECB False False ni nr 0)
  -- ike1: the keygxy handle rides, prevkey refuses.
  assertEqual "ike1 translates"
    (Just (encodeIkeParams 4 0 7 405 ni nr))
    (ike1PrfStructToCanonical ckm_SHA256_HMAC False 405 0 ni nr 7)
  assertEqual "ike1 zero keygxy refuses" Nothing
    (ike1PrfStructToCanonical ckm_SHA256_HMAC False 0 0 ni nr 7)
  assertEqual "ike1 prevkey refuses" Nothing
    (ike1PrfStructToCanonical ckm_SHA256_HMAC True 405 406 ni nr 7)
  assertEqual "ike1 prev handle refuses" Nothing
    (ike1PrfStructToCanonical ckm_SHA256_HMAC False 405 406 ni nr 7)
  assertEqual "ike1 unmapped PRF marks code 0"
    (Just (encodeIkeParams 0 0 7 405 ni nr))
    (ike1PrfStructToCanonical ckm_AES_ECB False 405 0 ni nr 7)
  -- extended: the keygxy handle is optional.
  assertEqual "ext translates"
    (Just (encodeIkeParams 4 0 0 0 seed BS.empty))
    (ike1ExtStructToCanonical ckm_SHA256_HMAC False 0 seed)
  assertEqual "ext aux translates"
    (Just (encodeIkeParams 4 0 0 405 seed BS.empty))
    (ike1ExtStructToCanonical ckm_SHA256_HMAC True 405 seed)
  assertEqual "ext flag/handle mismatch refuses" Nothing
    (ike1ExtStructToCanonical ckm_SHA256_HMAC True 0 seed)
  assertEqual "ext handle/flag mismatch refuses" Nothing
    (ike1ExtStructToCanonical ckm_SHA256_HMAC False 405 seed)
  assertEqual "ext unmapped PRF marks code 0"
    (Just (encodeIkeParams 0 0 0 0 seed BS.empty))
    (ike1ExtStructToCanonical ckm_AES_ECB False 0 seed)
