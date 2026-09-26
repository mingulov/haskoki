{- | TLS-PRF recipe tests.

One header mechanism, @CKM_TLS_PRF@: @PRF(secret, label, seed) =
P_MD5(first-half, label ++ seed) XOR P_SHA1(second-half, label ++
seed)@. Parameters are the label + seed frame
(@tls-prf-params\/1@); the output length arrives via the derived
template's @CKA_VALUE_LEN@.

'Haskoki.Recipe.TlsPrf' owns the canonical codec, parameter
validation, and mechanism table; these tests pin the recipe and
its consumers:

* the derive planner accepts TLS-PRF frames ('planDerive') with
  the output ceiling, and denies malformed frames;
* the driver maps the covered (mechanism, params) pair to its
  (label, seed) inputs ('tlsPrfParamsFor' agrees with the recipe
  table);
* engines execute the pinned construction (RoutingE2ESpec vectors
  against the pinned libcrypto, SyntheticSpec constructions).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeTlsPrfSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Driver (TlsPrfParams (..), tlsPrfParamsFor)
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
  , ckkGenericSecret
  , ckoSecretKey
  )
import Haskoki.Recipe.TlsPrf
  ( TlsPrfRecipe (..)
  , decodeTlsPrfParams
  , encodeTlsPrfParams
  , maxTlsPrfOutput
  , maxTlsPrfSeed
  , tlsPrfCodec
  , tlsPrfCodecFor
  , tlsPrfParamsValid
  , tlsPrfRecipeFor
  , tlsPrfRecipes
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated
  ( mustGeneratedId
  , ckm_SHA256_RSA_PKCS
  , ckm_TLS_PRF
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

spec :: TestTree
spec = testGroup "TLS-PRF recipe"
  [ testCase "table: one row" caseTable
  , testCase "lookup: id resolves, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: valid and refused shapes" caseParams
  , testCase "planDerive: accept and deny" casePlan
  , testCase "driver maps the pair to label + seed" caseDriverMap
  ]

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 1 (length tlsPrfRecipes)
  case tlsPrfRecipes of
    [r] -> assertEqual "row name" "CKM_TLS_PRF" (rtName r)
    rs -> assertFailure ("rows: " ++ show (length rs))

caseLookup :: IO ()
caseLookup = do
  case tlsPrfRecipeFor (MechanismId (mustGeneratedId "CKM_TLS_PRF")) of
    Nothing -> assertFailure "CKM_TLS_PRF unresolved"
    Just r -> assertEqual "lookup CKM_TLS_PRF" "CKM_TLS_PRF" (rtName r)
  assertEqual "unknown id has no recipe" Nothing
    (tlsPrfRecipeFor (MechanismId 0x4712))
  assertEqual "RSA has no TLS-PRF recipe" Nothing
    (tlsPrfRecipeFor (MechanismId ckm_SHA256_RSA_PKCS))
  assertEqual "raw id resolves" (Just "CKM_TLS_PRF")
    (rtName <$> tlsPrfRecipeFor (MechanismId ckm_TLS_PRF))

caseCodec :: IO ()
caseCodec = do
  assertEqual "tls-prf codec" (ParameterCodec "tls-prf-params" 1) tlsPrfCodec
  case tlsPrfRecipeFor (MechanismId ckm_TLS_PRF) of
    Nothing -> assertFailure "CKM_TLS_PRF unresolved"
    Just r -> assertEqual "codec row" tlsPrfCodec (tlsPrfCodecFor r)

caseParams :: IO ()
caseParams = do
  let lab = "test label"
      seed = "test seed"
  assertEqual "round-trip" (Just (lab, seed))
    (decodeTlsPrfParams (encodeTlsPrfParams lab seed))
  assertEqual "empty round-trip" (Just (BS.empty, BS.empty))
    (decodeTlsPrfParams (encodeTlsPrfParams BS.empty BS.empty))
  let full = encodeTlsPrfParams "label" "seed"
  assertEqual "truncated refuses" Nothing
    (decodeTlsPrfParams (BS.take (BS.length full - 1) full))
  assertEqual "short refuses" Nothing
    (decodeTlsPrfParams (BS.take 3 full))
  assertEqual "trailing refuses" Nothing
    (decodeTlsPrfParams (full <> "x"))
  let big = BS.replicate (maxTlsPrfSeed + 1) 0x41
  assertEqual "over-ceiling refuses" Nothing
    (decodeTlsPrfParams (encodeTlsPrfParams big BS.empty))
  case tlsPrfRecipeFor (MechanismId ckm_TLS_PRF) of
    Nothing -> assertFailure "CKM_TLS_PRF unresolved"
    Just r -> do
      assertEqual "valid frame" True
        (tlsPrfParamsValid r (encodeTlsPrfParams "l" "s"))
      assertEqual "junk frame" False (tlsPrfParamsValid r "junk")
  assertEqual "output ceiling" (255 * 32) maxTlsPrfOutput

-- planDerive pins (light model harness: one secret base key + handle)
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

mkBaseModel :: BS.ByteString -> Bool -> Model
mkBaseModel mat canDerive = emptyModel
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
          , (AttrKeyType, ValULong ckkGenericSecret)
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

tlsPrfMech :: MechanismId
tlsPrfMech = MechanismId ckm_TLS_PRF

expectDeny :: String -> ReturnCode -> KeyPlan -> IO ()
expectDeny label code plan = case plan of
  KeyDenied (KeyDeny c _) -> assertEqual ("deny " ++ label) code c
  other -> assertFailure ("expected denial, got " ++ show other)

caseDriverMap :: IO ()
caseDriverMap = do
  let good = encodeTlsPrfParams "test label" "test seed"
  assertEqual "covered pair decodes"
    (Just (TlsPrfParams "test label" "test seed"))
    (tlsPrfParamsFor tlsPrfMech good)
  assertEqual "junk refuses" Nothing (tlsPrfParamsFor tlsPrfMech "junk")
  assertEqual "other mechanism uncovered" Nothing
    (tlsPrfParamsFor (MechanismId ckm_SHA256_RSA_PKCS) good)
  assertEqual "unknown id uncovered" Nothing
    (tlsPrfParamsFor (MechanismId 0x4712) good)

casePlan :: IO ()
casePlan = do
  let m = mkBaseModel "secret" True
      good = encodeTlsPrfParams "test label" "test seed"
  -- Accepted: label + seed frame plus a VALUE_LEN template.
  case planDerive defaultRules m testSession tlsPrfMech baseHandle
      (encodeDeriveParams good [derivedTmpl 48]) of
    KeyEffect _ (FxDerive mech (Just oid) params info total) -> do
      assertEqual "mech" tlsPrfMech mech
      assertEqual "base" baseOid oid
      assertEqual "params" good params
      assertEqual "info empty" BS.empty info
      assertEqual "total" 48 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Malformed frames refuse typed.
  expectDeny "junk params" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession tlsPrfMech baseHandle
      (encodeDeriveParams "junk" [derivedTmpl 48]))
  -- Output past the ceiling refuses typed.
  expectDeny "over ceiling" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession tlsPrfMech baseHandle
      (encodeDeriveParams good [derivedTmpl (maxTlsPrfOutput + 1)]))
  -- A non-derivable base refuses at the key check.
  expectDeny "no derive flag" CKR_KEY_FUNCTION_NOT_PERMITTED
    (planDerive defaultRules (mkBaseModel "secret" False) testSession
      tlsPrfMech baseHandle
      (encodeDeriveParams good [derivedTmpl 48]))
