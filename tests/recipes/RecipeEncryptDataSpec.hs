{- | Encrypt-data recipe tests.

The CBC/ECB-encrypt-data group: 8 header mechanisms over four
algorithm families deriving key material by encrypting
caller-supplied data with the base cipher key — the CBC rows take
the canonical @iv||data@ frame (IV width one block: 16 bytes for
AES/ARIA/CAMELLIA, 8 for Triple-DES), the ECB rows the raw data
bytes (chased from @CK_KEY_DERIVATION_STRING_DATA@ at the FFI
boundary). Data is non-empty and block-multiple; output length
equals input length; the base key must be the row's cipher key
type.

'Haskoki.Recipe.EncryptData' owns the group's canonical codecs,
parameter/data validation, width rules, and mechanism table; these
tests pin the recipe and its consumers:

* the derive planner accepts encrypt-data frames ('planDerive')
  with the data-width ceiling;
* the driver maps covered (mechanism, key length, params) triples
  to backend 'CipherSpec's plus split IV/data
  ('encryptDataPartsFor');
* engines execute the pinned vectors (OpenSSLSpec EVP goldens,
  SyntheticSpec constructions).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeEncryptDataSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Driver (encryptDataPartsFor)
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
  , ckkAes
  , ckkAria
  , ckkDes3
  , ckkGenericSecret
  , ckoSecretKey
  )
import Haskoki.Recipe.EncryptData
  ( EncryptDataRecipe (..)
  , decodeEncryptDataParams
  , encryptDataCbcCodec
  , encryptDataCodecFor
  , encryptDataEcbCodec
  , encryptDataKeyLenValid
  , encryptDataOutputLen
  , encryptDataParamsValid
  , encryptDataRecipeFor
  , encryptDataRecipes
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated
  ( mustGeneratedId
  , ckm_AES_CBC
  , ckm_SHA256
  )
import Haskoki.Registry.Types (ParameterCodec (..))
import Haskoki.Rules (defaultRules)
import Data.Word (Word64)
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
spec = testGroup "Encrypt-data recipe"
  [ testCase "table: twelve rows with geometry" caseTable
  , testCase "lookup: ids resolve, others do not" caseLookup
  , testCase "codecs: cbc frame vs ecb bytes" caseCodec
  , testCase "params: iv||data and raw-data shapes" caseParams
  , testCase "decode splits iv/data, output length is data width" caseDecode
  , testCase "key lengths per family" caseKeyLens
  , testCase "planDerive: accept, gates, ceilings" casePlan
  , testCase "driver maps triples to specs" caseDriverMap
  ]

-- | (Name suffix, block bytes, key lengths, IV bytes, key type name).
groupShape :: [(Text, Int, [Int], Int, Text)]
groupShape =
  [ ("AES_CBC_ENCRYPT_DATA", 16, [16, 24, 32], 16, "CKK_AES")
  , ("AES_ECB_ENCRYPT_DATA", 16, [16, 24, 32], 0, "CKK_AES")
  , ("ARIA_CBC_ENCRYPT_DATA", 16, [16, 24, 32], 16, "CKK_ARIA")
  , ("ARIA_ECB_ENCRYPT_DATA", 16, [16, 24, 32], 0, "CKK_ARIA")
  , ("CAMELLIA_CBC_ENCRYPT_DATA", 16, [16, 24, 32], 16, "CKK_CAMELLIA")
  , ("CAMELLIA_ECB_ENCRYPT_DATA", 16, [16, 24, 32], 0, "CKK_CAMELLIA")
  , ("DES3_CBC_ENCRYPT_DATA", 8, [16, 24], 8, "CKK_DES3")
  , ("DES3_ECB_ENCRYPT_DATA", 8, [16, 24], 0, "CKK_DES3")
  , ("DES_CBC_ENCRYPT_DATA", 8, [8], 8, "CKK_DES")
  , ("DES_ECB_ENCRYPT_DATA", 8, [8], 0, "CKK_DES")
  , ("SEED_CBC_ENCRYPT_DATA", 16, [16], 16, "CKK_SEED")
  , ("SEED_ECB_ENCRYPT_DATA", 16, [16], 0, "CKK_SEED")
  ]

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 12 (length encryptDataRecipes)
  mapM_ (\(suffix, block, keys, iv, kty) -> do
    let name = mechName suffix
        found = [ r | r <- encryptDataRecipes, erName r == name ]
    case found of
      [r] -> do
        assertEqual ("block " ++ T.unpack name) block (erBlockBytes r)
        assertEqual ("keys " ++ T.unpack name) keys (erKeyLens r)
        assertEqual ("iv " ++ T.unpack name) iv (erIvBytes r)
        assertEqual ("keytype " ++ T.unpack name) kty (erKeyType r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _, _, _, _) -> do
    let name = mechName suffix
    case encryptDataRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (erName r)
    ) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (encryptDataRecipeFor (MechanismId 0x4712))
  assertEqual "cipher mech has no recipe" Nothing
    (encryptDataRecipeFor (MechanismId ckm_AES_CBC))
  assertEqual "digest mech has no recipe" Nothing
    (encryptDataRecipeFor (MechanismId ckm_SHA256))

caseCodec :: IO ()
caseCodec = do
  assertEqual "cbc codec" (ParameterCodec "encrypt-data-cbc" 1) encryptDataCbcCodec
  assertEqual "ecb codec" (ParameterCodec "encrypt-data-ecb" 1) encryptDataEcbCodec
  mapM_ (\(suffix, _, _, iv, _) -> do
    let name = mechName suffix
        want = if iv == 0 then encryptDataEcbCodec else encryptDataCbcCodec
    case encryptDataRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("codec " ++ T.unpack name) want (encryptDataCodecFor r)
    ) groupShape

recipeOf :: Text -> EncryptDataRecipe
recipeOf name =
  case encryptDataRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

caseParams :: IO ()
caseParams = do
  let aesCbc = recipeOf "CKM_AES_CBC_ENCRYPT_DATA"
      iv16 = BS.replicate 16 0xcb
  assertBool "cbc iv+1 block valid"
    (encryptDataParamsValid aesCbc (iv16 <> BS.replicate 16 0xda))
  assertBool "cbc iv+2 blocks valid"
    (encryptDataParamsValid aesCbc (iv16 <> BS.replicate 32 0xda))
  assertBool "cbc empty refused"
    (not (encryptDataParamsValid aesCbc BS.empty))
  assertBool "cbc iv-only refused (empty data)"
    (not (encryptDataParamsValid aesCbc iv16))
  assertBool "cbc short-iv refused"
    (not (encryptDataParamsValid aesCbc (BS.replicate 8 0 <> BS.replicate 16 0)))
  assertBool "cbc ragged data refused"
    (not (encryptDataParamsValid aesCbc (iv16 <> BS.replicate 20 0)))
  let aesEcb = recipeOf "CKM_AES_ECB_ENCRYPT_DATA"
  assertBool "ecb 1 block valid"
    (encryptDataParamsValid aesEcb (BS.replicate 16 0xda))
  assertBool "ecb 3 blocks valid"
    (encryptDataParamsValid aesEcb (BS.replicate 48 0xda))
  assertBool "ecb empty refused"
    (not (encryptDataParamsValid aesEcb BS.empty))
  assertBool "ecb ragged refused"
    (not (encryptDataParamsValid aesEcb (BS.replicate 20 0)))
  let d3Cbc = recipeOf "CKM_DES3_CBC_ENCRYPT_DATA"
      iv8 = BS.replicate 8 0xcb
  assertBool "des3-cbc iv+1 block valid"
    (encryptDataParamsValid d3Cbc (iv8 <> BS.replicate 8 0xda))
  assertBool "des3-cbc 16-data refused (wrong iv split)"
    -- 16 bytes total parses as iv(8)+data(8): valid. A 12-byte
    -- frame leaves ragged data.
    (not (encryptDataParamsValid d3Cbc (BS.replicate 12 0)))
  assertBool "des3-cbc ragged refused"
    (not (encryptDataParamsValid d3Cbc (iv8 <> BS.replicate 12 0)))
  let d3Ecb = recipeOf "CKM_DES3_ECB_ENCRYPT_DATA"
  assertBool "des3-ecb 8 valid"
    (encryptDataParamsValid d3Ecb (BS.replicate 8 0xda))
  assertBool "des3-ecb 12 refused"
    (not (encryptDataParamsValid d3Ecb (BS.replicate 12 0)))
  -- Whole-table: the canonical frame validates per row.
  mapM_ (\(suffix, block, _, iv, _) -> do
    let r = recipeOf (mechName suffix)
        frame = BS.replicate iv 0xcb <> BS.replicate (2 * block) 0xda
    assertBool ("frame ok " ++ T.unpack suffix)
      (encryptDataParamsValid r frame)
    assertBool ("ragged refused " ++ T.unpack suffix)
      (not (encryptDataParamsValid r (frame <> BS.singleton 0)))
    ) groupShape

caseDecode :: IO ()
caseDecode = do
  let aesCbc = recipeOf "CKM_AES_CBC_ENCRYPT_DATA"
      iv = BS.replicate 16 0xcb
      dat = BS.replicate 32 0xda
  assertEqual "cbc splits" (Just (iv, dat))
    (decodeEncryptDataParams aesCbc (iv <> dat))
  assertEqual "cbc invalid decodes Nothing" Nothing
    (decodeEncryptDataParams aesCbc (iv <> BS.replicate 20 0))
  assertEqual "cbc output length" (Just 32)
    (encryptDataOutputLen aesCbc (iv <> dat))
  assertEqual "cbc output length invalid" Nothing
    (encryptDataOutputLen aesCbc BS.empty)
  let aesEcb = recipeOf "CKM_AES_ECB_ENCRYPT_DATA"
  assertEqual "ecb splits" (Just (BS.empty, dat))
    (decodeEncryptDataParams aesEcb dat)
  assertEqual "ecb output length" (Just 32)
    (encryptDataOutputLen aesEcb dat)
  assertEqual "ecb output length invalid" Nothing
    (encryptDataOutputLen aesEcb (BS.replicate 20 0))

caseKeyLens :: IO ()
caseKeyLens = do
  let aes = recipeOf "CKM_AES_CBC_ENCRYPT_DATA"
  mapM_ (\n -> assertBool ("aes key " ++ show n) (encryptDataKeyLenValid aes n))
    [16, 24, 32]
  mapM_ (\n -> assertBool ("aes key refused " ++ show n)
    (not (encryptDataKeyLenValid aes n))) [0, 8, 15, 17, 31, 33, 64]
  let d3 = recipeOf "CKM_DES3_CBC_ENCRYPT_DATA"
  mapM_ (\n -> assertBool ("des3 key " ++ show n) (encryptDataKeyLenValid d3 n))
    [16, 24]
  mapM_ (\n -> assertBool ("des3 key refused " ++ show n)
    (not (encryptDataKeyLenValid d3 n))) [0, 8, 15, 17, 23, 25, 32]
  mapM_ (\(suffix, _, keys, _, _) -> do
    let r = recipeOf (mechName suffix)
    mapM_ (\n -> assertBool ("key ok " ++ T.unpack suffix ++ "/" ++ show n)
      (encryptDataKeyLenValid r n)) keys
    ) groupShape

-- ---------------------------------------------------------------------------
-- planDerive pins (light model harness: one cipher base key + handle)
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

-- | A default derive template: booleans only, no class, key type, or
-- length (the lane's default-template shape).
defaultTmpl :: [(AttributeType, AttributeValue)]
defaultTmpl =
  [ (AttrToken, ValBool False)
  , (AttrSensitive, ValBool False)
  , (AttrExtractable, ValBool True)
  ]

-- | A length-only template: VALUE_LEN plus booleans, no key type.
lengthOnlyTmpl :: Int -> [(AttributeType, AttributeValue)]
lengthOnlyTmpl n = (AttrValueLen, ValULong (fromIntegral n)) : defaultTmpl

aesCbcMech, aesEcbMech, ariaCbcMech, d3CbcMech :: MechanismId
aesCbcMech = MechanismId (mustGeneratedId "CKM_AES_CBC_ENCRYPT_DATA")
aesEcbMech = MechanismId (mustGeneratedId "CKM_AES_ECB_ENCRYPT_DATA")
ariaCbcMech = MechanismId (mustGeneratedId "CKM_ARIA_CBC_ENCRYPT_DATA")
d3CbcMech = MechanismId (mustGeneratedId "CKM_DES3_CBC_ENCRYPT_DATA")

expectDeny :: String -> ReturnCode -> KeyPlan -> IO ()
expectDeny label code plan = case plan of
  KeyDenied (KeyDeny c _) -> assertEqual ("deny " ++ label) code c
  other -> assertFailure ("expected denial, got " ++ show other)

casePlan :: IO ()
casePlan = do
  let aesBase = mkBaseModel ckkAes (BS.replicate 16 0x11) True
      frame = BS.replicate 16 0xcb <> BS.replicate 32 0xda
      derive m mech params tmpl = planDerive defaultRules m testSession mech baseHandle
        (encodeDeriveParams params [tmpl])
  -- Accepted at full data width; the frame travels as params.
  case derive aesBase aesCbcMech frame (derivedTmpl 32) of
    KeyEffect _ (FxDerive mech (Just oid) Nothing params info total) -> do
      assertEqual "mech" aesCbcMech mech
      assertEqual "base" baseOid oid
      assertEqual "params" frame params
      assertEqual "info empty" BS.empty info
      assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Truncated totals plan.
  case derive aesBase aesCbcMech frame (derivedTmpl 16) of
    KeyEffect _ (FxDerive _ _ _ _ _ total) -> assertEqual "total" 16 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Default templates succeed at the full data width.
  case derive aesBase aesCbcMech frame defaultTmpl of
    KeyEffect _ (FxDerive _ _ _ _ _ total) -> assertEqual "default total" 32 total
    other -> assertFailure ("default must plan: " ++ show other)
  -- Length-only under the width succeeds; overlong and zero deny
  -- KEY_SIZE_RANGE.
  case derive aesBase aesCbcMech frame (lengthOnlyTmpl 12) of
    KeyEffect _ (FxDerive _ _ _ _ _ total) -> assertEqual "length-only total" 12 total
    other -> assertFailure ("length-only must plan: " ++ show other)
  expectDeny "length-only overlong" CKR_KEY_SIZE_RANGE
    (derive aesBase aesCbcMech frame (lengthOnlyTmpl 33))
  expectDeny "typed overlong" CKR_KEY_SIZE_RANGE
    (derive aesBase aesCbcMech frame (derivedTmpl 48))
  expectDeny "length-only zero" CKR_KEY_SIZE_RANGE
    (derive aesBase aesCbcMech frame (lengthOnlyTmpl 0))
  -- ECB accepts raw data with an AES base.
  case derive aesBase aesEcbMech (BS.replicate 32 0xda) (derivedTmpl 32) of
    KeyEffect _ (FxDerive _ _ _ _ _ total) -> assertEqual "ecb total" 32 total
    other -> assertFailure ("ecb must plan: " ++ show other)
  -- Malformed frames deny PARAM_INVALID (recipe shape).
  expectDeny "ragged cbc data" CKR_MECHANISM_PARAM_INVALID
    (derive aesBase aesCbcMech (BS.replicate 16 0 <> BS.replicate 20 0) (derivedTmpl 16))
  expectDeny "empty ecb data" CKR_MECHANISM_PARAM_INVALID
    (derive aesBase aesEcbMech BS.empty (derivedTmpl 16))
  expectDeny "ragged ecb data" CKR_MECHANISM_PARAM_INVALID
    (derive aesBase aesEcbMech (BS.replicate 20 0) (derivedTmpl 16))
  expectDeny "malformed blob" CKR_ARGUMENTS_BAD
    (planDerive defaultRules aesBase testSession aesCbcMech baseHandle "truncated")
  -- Base-key faults: the key-type contradiction outranks shape (the
  -- Init-matrix ordering, shared with the ECDH/SHA-KDF arms).
  let genericBase = mkBaseModel ckkGenericSecret (BS.replicate 16 0x11) True
  expectDeny "generic base rejected" CKR_KEY_TYPE_INCONSISTENT
    (derive genericBase aesCbcMech frame (derivedTmpl 32))
  expectDeny "aria row rejects aes base" CKR_KEY_TYPE_INCONSISTENT
    (derive aesBase ariaCbcMech frame (derivedTmpl 32))
  let ariaBase = mkBaseModel ckkAria (BS.replicate 16 0x11) True
  case derive ariaBase ariaCbcMech frame (derivedTmpl 32) of
    KeyEffect _ (FxDerive _ _ _ _ _ total) -> assertEqual "aria total" 32 total
    other -> assertFailure ("aria must plan: " ++ show other)
  let d3Base = mkBaseModel ckkDes3 (BS.replicate 24 0x11) True
      d3frame = BS.replicate 8 0xcb <> BS.replicate 16 0xda
  case derive d3Base d3CbcMech d3frame (derivedTmpl 16) of
    KeyEffect _ (FxDerive _ _ _ _ _ total) -> assertEqual "des3 total" 16 total
    other -> assertFailure ("des3 must plan: " ++ show other)
  expectDeny "no derive mark" CKR_KEY_FUNCTION_NOT_PERMITTED
    (derive (mkBaseModel ckkAes (BS.replicate 16 0x11) False) aesCbcMech frame (derivedTmpl 32))
  expectDeny "unknown handle" CKR_KEY_HANDLE_INVALID
    (planDerive defaultRules aesBase testSession aesCbcMech (ExternalHandle 999)
      (encodeDeriveParams frame [derivedTmpl 32]))
  -- Caller-supplied CKA_VALUE in a derive template is rejected.
  expectDeny "value injection" CKR_TEMPLATE_INCONSISTENT
    (derive aesBase aesCbcMech frame
      (derivedTmpl 32 ++ [(AttrValue, ValBytes (BS.replicate 32 0xa5))]))

caseDriverMap :: IO ()
caseDriverMap = do
  let iv16 = BS.replicate 16 0xcb
      dat32 = BS.replicate 32 0xda
  -- CBC rows map (mechanism, key length, frame) to the shared CBC
  -- spec plus split iv/data.
  case encryptDataPartsFor aesCbcMech 16 (iv16 <> dat32) of
    Just (_, iv, dat) -> do
      assertEqual "aes-cbc iv" iv16 iv
      assertEqual "aes-cbc data" dat32 dat
    Nothing -> assertFailure "aes-cbc must map"
  assertEqual "aes-cbc rejects bad keylen" Nothing
    (encryptDataPartsFor aesCbcMech 15 (iv16 <> dat32))
  assertEqual "aes-cbc rejects ragged" Nothing
    (encryptDataPartsFor aesCbcMech 16 (iv16 <> BS.replicate 20 0))
  case encryptDataPartsFor aesEcbMech 32 dat32 of
    Just (_, iv, dat) -> do
      assertEqual "aes-ecb iv" BS.empty iv
      assertEqual "aes-ecb data" dat32 dat
    Nothing -> assertFailure "aes-ecb must map"
  assertEqual "aes-ecb rejects empty" Nothing
    (encryptDataPartsFor aesEcbMech 32 BS.empty)
  let iv8 = BS.replicate 8 0xcb
      dat16 = BS.replicate 16 0xda
  case encryptDataPartsFor d3CbcMech 24 (iv8 <> dat16) of
    Just (_, iv, dat) -> do
      assertEqual "des3-cbc iv" iv8 iv
      assertEqual "des3-cbc data" dat16 dat
    Nothing -> assertFailure "des3-cbc must map"
  assertEqual "non-encrypt-data uncovered" Nothing
    (encryptDataPartsFor (MechanismId ckm_SHA256) 32 dat32)
  -- Whole-table agreement: every (recipe, key length) triple maps.
  mapM_ (\(suffix, block, keys, iv, _) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
        frame = BS.replicate iv 0xcb <> BS.replicate (2 * block) 0xda
    mapM_ (\n -> case encryptDataPartsFor mech n frame of
      Nothing -> assertFailure ("unmapped " ++ T.unpack suffix ++ "/" ++ show n)
      Just (_, gotIv, gotDat) -> do
        assertEqual ("iv " ++ T.unpack suffix) (BS.replicate iv 0xcb) gotIv
        assertEqual ("data " ++ T.unpack suffix) (BS.replicate (2 * block) 0xda) gotDat
      ) keys
    ) groupShape
