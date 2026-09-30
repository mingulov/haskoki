{- | Byte-op recipe pins (slice 11k).

'Haskoki.Recipe.ByteOps' owns the canonical codec, parameter
validation, and the five-row table; 'Haskoki.Operation.Derive'
owns admission (including the second-handle resolution onto
'fxKey2' for BASE_AND_KEY); 'Haskoki.Engine.Driver' owns the
params-to-execution mapping. This spec pins all three against
the table: the table shape, id resolution, codec identity, the
per-kind parameter matrix (aux\/offset\/blob slot rules,
ceilings), the base key types, one planDerive accept\/deny set,
and the driver mapping.
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeByteOpsSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Driver (ByteOpsExec (..), byteOpsParamsFor)
import Haskoki.FFI.NativeParams
  ( byteOpsConcatKeyStructToCanonical
  , byteOpsExtractStructToCanonical
  , byteOpsStringDataStructToCanonical
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
  , ckoSecretKey
  )
import Haskoki.Recipe.ByteOps
import Haskoki.Registry.Generated
  ( ckm_CONCATENATE_BASE_AND_DATA
  , ckm_CONCATENATE_BASE_AND_KEY
  , ckm_CONCATENATE_DATA_AND_BASE
  , ckm_EXTRACT_KEY_FROM_KEY
  , ckm_XOR_BASE_AND_DATA
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
spec = testGroup "ByteOps recipe"
  [ testCase "table: five rows with kinds" caseTable
  , testCase "lookup: ids resolve, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: per-kind matrix" caseParams
  , testCase "base key types" caseBaseTypes
  , testCase "planDerive: accept and deny" casePlan
  , testCase "driver maps the pair to the exec tuple" caseDriverMap
  , testCase "native structs translate" caseNative
  ]

caseTable :: IO ()
caseTable = assertEqual "five rows" expected
  [(boName r, boKind r) | r <- byteOpsRecipes]
  where
    expected =
      [ ("CKM_CONCATENATE_BASE_AND_KEY", ConcatBaseAndKey)
      , ("CKM_CONCATENATE_BASE_AND_DATA", ConcatBaseAndData)
      , ("CKM_CONCATENATE_DATA_AND_BASE", ConcatDataAndBase)
      , ("CKM_XOR_BASE_AND_DATA", XorBaseAndData)
      , ("CKM_EXTRACT_KEY_FROM_KEY", ExtractKeyFromKey)
      ]

caseLookup :: IO ()
caseLookup = do
  mapM_ resolves
    [ ckm_CONCATENATE_BASE_AND_KEY
    , ckm_CONCATENATE_BASE_AND_DATA
    , ckm_CONCATENATE_DATA_AND_BASE
    , ckm_XOR_BASE_AND_DATA
    , ckm_EXTRACT_KEY_FROM_KEY
    ]
  assertEqual "other id" Nothing (byteOpsRecipeFor (MechanismId 0x366))
  where
    resolves i = assertBool ("resolves " ++ show i)
      (case byteOpsRecipeFor (MechanismId i) of Just _ -> True; Nothing -> False)

caseCodec :: IO ()
caseCodec = do
  let frame = encodeByteOpsParams 405 128 (BS.replicate 16 7)
  assertEqual "roundtrip" (Just (405, 128, BS.replicate 16 7))
    (decodeByteOpsParams frame)
  let bare = encodeByteOpsParams 0 0 BS.empty
  assertEqual "bare roundtrip" (Just (0, 0, BS.empty))
    (decodeByteOpsParams bare)
  assertEqual "truncation refused" Nothing
    (decodeByteOpsParams (BS.take 9 frame))
  assertEqual "trailing bytes refused" Nothing
    (decodeByteOpsParams (frame <> BS.singleton 0))

resolveByteOps :: Word64 -> IO ByteOpsRecipe
resolveByteOps mid = case byteOpsRecipeFor (MechanismId mid) of
  Just r -> pure r
  Nothing -> assertFailure ("recipe must resolve " ++ show mid)

caseParams :: IO ()
caseParams = do
  rKey <- resolveByteOps ckm_CONCATENATE_BASE_AND_KEY
  rBD <- resolveByteOps ckm_CONCATENATE_BASE_AND_DATA
  rDB <- resolveByteOps ckm_CONCATENATE_DATA_AND_BASE
  rXor <- resolveByteOps ckm_XOR_BASE_AND_DATA
  rExt <- resolveByteOps ckm_EXTRACT_KEY_FROM_KEY
  -- Each row accepts its own slot shape.
  assertBool "key accepts handle" (byteOpsParamsValid rKey (encodeByteOpsParams 405 0 BS.empty))
  assertBool "base-data accepts blob" (byteOpsParamsValid rBD (encodeByteOpsParams 0 0 (BS.replicate 16 1)))
  assertBool "data-base accepts blob" (byteOpsParamsValid rDB (encodeByteOpsParams 0 0 (BS.replicate 16 1)))
  assertBool "xor accepts blob" (byteOpsParamsValid rXor (encodeByteOpsParams 0 0 (BS.replicate 16 1)))
  assertBool "extract accepts offset" (byteOpsParamsValid rExt (encodeByteOpsParams 0 128 BS.empty))
  -- Cross-row shapes refuse.
  assertBool "key refuses blob" (not (byteOpsParamsValid rKey (encodeByteOpsParams 405 0 (BS.singleton 1))))
  assertBool "key refuses zero handle" (not (byteOpsParamsValid rKey (encodeByteOpsParams 0 0 BS.empty)))
  assertBool "base-data refuses handle" (not (byteOpsParamsValid rBD (encodeByteOpsParams 405 0 (BS.replicate 16 1))))
  assertBool "base-data refuses offset" (not (byteOpsParamsValid rBD (encodeByteOpsParams 0 8 (BS.replicate 16 1))))
  assertBool "xor refuses handle" (not (byteOpsParamsValid rXor (encodeByteOpsParams 405 0 (BS.replicate 16 1))))
  assertBool "extract refuses handle" (not (byteOpsParamsValid rExt (encodeByteOpsParams 405 128 BS.empty)))
  assertBool "extract refuses blob" (not (byteOpsParamsValid rExt (encodeByteOpsParams 0 128 (BS.singleton 1))))
  -- Over-ceiling material refuses.
  assertBool "blob ceiling" (not (byteOpsParamsValid rBD
    (encodeByteOpsParams 0 0 (BS.replicate (maxByteOpsMaterial + 1) 1))))
  -- Junk never validates.
  assertBool "junk refuses" (not (byteOpsParamsValid rBD "junk"))

caseBaseTypes :: IO ()
caseBaseTypes = do
  assertBool "generic ok" (byteOpsBaseKeyOk ckkGenericSecret)
  assertBool "ec refused" (not (byteOpsBaseKeyOk ckkEc))

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

mkByteOpsModel :: Word64 -> Bool -> Model
mkByteOpsModel baseType canDerive = emptyModel
  { mObjects = Map.fromList
      [ (baseOid, mkSecret baseOid baseType (BS.pack [0 .. 31]) canDerive)
      , (auxOid, mkSecret auxOid ckkGenericSecret (BS.pack [32 .. 63]) True)
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

derivedTmplNoLen :: [(AttributeType, AttributeValue)]
derivedTmplNoLen =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrToken, ValBool False)
  ]

concatKeyMech :: MechanismId
concatKeyMech = MechanismId ckm_CONCATENATE_BASE_AND_KEY

concatDataMech :: MechanismId
concatDataMech = MechanismId ckm_CONCATENATE_BASE_AND_DATA

dataConcatMech :: MechanismId
dataConcatMech = MechanismId ckm_CONCATENATE_DATA_AND_BASE

xorMech :: MechanismId
xorMech = MechanismId ckm_XOR_BASE_AND_DATA

extractMech :: MechanismId
extractMech = MechanismId ckm_EXTRACT_KEY_FROM_KEY

concatKeyFrame :: BS.ByteString
concatKeyFrame = encodeByteOpsParams 405 0 BS.empty

concatDataFrame :: BS.ByteString
concatDataFrame = encodeByteOpsParams 0 0 (BS.replicate 16 1)

xorFrame :: BS.ByteString
xorFrame = encodeByteOpsParams 0 0 (BS.pack [0 .. 31])

extractFrame :: BS.ByteString
extractFrame = encodeByteOpsParams 0 0 BS.empty

expectDeny :: String -> ReturnCode -> KeyPlan -> IO ()
expectDeny label code plan = case plan of
  KeyDenied (KeyDeny c _) -> assertEqual ("deny " ++ label) code c
  other -> assertFailure ("expected denial, got " ++ show other)

casePlan :: IO ()
casePlan = do
  let m = mkByteOpsModel ckkGenericSecret True
  -- Accepted: concat-key resolves the second handle onto fxKey2.
  case planDerive defaultRules m testSession concatKeyMech baseHandle
      (encodeDeriveParams concatKeyFrame [derivedTmpl 64]) of
    KeyEffect _ (FxDerive mech (Just oid) (Just aux) params _ total) -> do
      assertEqual "mech" concatKeyMech mech
      assertEqual "base" baseOid oid
      assertEqual "aux" auxOid aux
      assertEqual "params" concatKeyFrame params
      assertEqual "total" 64 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Accepted: concat-data truncates to the template length.
  case planDerive defaultRules m testSession concatDataMech baseHandle
      (encodeDeriveParams concatDataFrame [derivedTmpl 16]) of
    KeyEffect _ (FxDerive mech (Just oid) Nothing _ _ total) -> do
      assertEqual "mech" concatDataMech mech
      assertEqual "base" baseOid oid
      assertEqual "total" 16 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Accepted: concat rows default to the full natural output.
  case planDerive defaultRules m testSession concatDataMech baseHandle
      (encodeDeriveParams concatDataFrame [derivedTmplNoLen]) of
    KeyEffect _ (FxDerive _ _ _ _ _ total) ->
      assertEqual "natural total" 48 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Accepted: xor over equal lengths.
  case planDerive defaultRules m testSession xorMech baseHandle
      (encodeDeriveParams xorFrame [derivedTmpl 16]) of
    KeyEffect _ (FxDerive mech _ _ _ _ total) -> do
      assertEqual "mech" xorMech mech
      assertEqual "total" 16 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Accepted: extract at a byte-aligned offset.
  case planDerive defaultRules m testSession extractMech baseHandle
      (encodeDeriveParams extractFrame [derivedTmpl 16]) of
    KeyEffect _ (FxDerive mech _ _ _ _ total) -> do
      assertEqual "mech" extractMech mech
      assertEqual "total" 16 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Malformed frames refuse typed.
  expectDeny "junk params" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession concatDataMech baseHandle
      (encodeDeriveParams "junk" [derivedTmpl 16]))
  -- Output past the natural length refuses typed.
  expectDeny "over natural" CKR_KEY_SIZE_RANGE
    (planDerive defaultRules m testSession concatDataMech baseHandle
      (encodeDeriveParams concatDataFrame [derivedTmpl 49]))
  -- XOR over mismatched lengths refuses typed.
  expectDeny "xor mismatch" CKR_DATA_LEN_RANGE
    (planDerive defaultRules m testSession xorMech baseHandle
      (encodeDeriveParams concatDataFrame [derivedTmpl 16]))
  -- EXTRACT without a template length refuses typed.
  expectDeny "extract no length" CKR_TEMPLATE_INCOMPLETE
    (planDerive defaultRules m testSession extractMech baseHandle
      (encodeDeriveParams extractFrame [derivedTmplNoLen]))
  -- EXTRACT past the base end refuses typed.
  expectDeny "extract overrun" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession extractMech baseHandle
      (encodeDeriveParams (encodeByteOpsParams 0 248 BS.empty) [derivedTmpl 16]))
  -- A wrong-typed base refuses typed.
  expectDeny "ec base" CKR_KEY_TYPE_INCONSISTENT
    (planDerive defaultRules (mkByteOpsModel ckkEc True) testSession concatDataMech baseHandle
      (encodeDeriveParams concatDataFrame [derivedTmpl 16]))
  -- An unknown second handle refuses typed.
  expectDeny "unknown aux" CKR_KEY_HANDLE_INVALID
    (planDerive defaultRules m testSession concatKeyMech baseHandle
      (encodeDeriveParams (encodeByteOpsParams 999 0 BS.empty) [derivedTmpl 64]))

caseDriverMap :: IO ()
caseDriverMap = do
  assertEqual "concat-key pair decodes"
    (Just (ByteOpsExec ConcatBaseAndKey 405 0 BS.empty))
    (byteOpsParamsFor concatKeyMech concatKeyFrame)
  assertEqual "concat-data pair decodes"
    (Just (ByteOpsExec ConcatBaseAndData 0 0 (BS.replicate 16 1)))
    (byteOpsParamsFor concatDataMech concatDataFrame)
  assertEqual "xor pair decodes"
    (Just (ByteOpsExec XorBaseAndData 0 0 (BS.pack [0 .. 31])))
    (byteOpsParamsFor xorMech xorFrame)
  assertEqual "extract pair decodes"
    (Just (ByteOpsExec ExtractKeyFromKey 0 0 BS.empty))
    (byteOpsParamsFor extractMech extractFrame)
  assertEqual "junk refused" Nothing
    (byteOpsParamsFor concatDataMech "junk")

caseNative :: IO ()
caseNative = do
  let blob = BS.replicate 16 1
  assertEqual "concat-key translates"
    (Just (encodeByteOpsParams 405 0 BS.empty))
    (byteOpsConcatKeyStructToCanonical 405)
  assertEqual "concat-key zero handle refuses" Nothing
    (byteOpsConcatKeyStructToCanonical 0)
  assertEqual "string-data translates"
    (Just (encodeByteOpsParams 0 0 blob))
    (byteOpsStringDataStructToCanonical blob)
  assertEqual "extract translates"
    (Just (encodeByteOpsParams 0 128 BS.empty))
    (byteOpsExtractStructToCanonical 128)
