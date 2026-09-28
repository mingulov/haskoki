{- | KDF recipe tests.

The KDF group: 12 header mechanisms sharing the derive shape —
eleven @CKM_SHA*_KEY_DERIVATION@ rows (hash the base value,
truncate to the digest width; empty parameters) plus
@CKM_PKCS5_PBKD2@ (@pbkd2-params\/2@: PRF code, iteration count,
salt, password; the PRF is any servable HMAC; the derive route
pins the password empty). Iterations cap at a
documented ceiling; derived totals cap at the construction width.

'Haskoki.Recipe.Kdf' owns the group's canonical codecs, parameter
validation, width rules, and mechanism table; these tests pin the
recipe and its three consumers:

* the derive planner accepts KDF frames ('planDerive') with the
  construction ceilings;
* the driver maps SHAs to digests ('kdfShaFor') and PBKD2 params
  ('pbkd2ParamsFor'), executing over the digest\/MAC routes;
* engines execute the pinned vectors (RoutingE2ESpec RFC 6070 +
  CLI PBKDF2 vectors, SyntheticSpec constructions).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeKdfSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Data.Word (Word64)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend (DigestAlg (..))
import Haskoki.Engine.Driver (Pbkd2Params (..), kdfShaFor, pbkd2ParamsFor)
import Haskoki.FFI.NativeParams (pbkd2Params2StructToCanonical)
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
  , maxDerivedTotal
  , planDerive
  )
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , ckkAes
  , ckkGenericSecret
  , ckoSecretKey
  )
import Haskoki.Recipe.Kdf
  ( KdfRecipe (..)
  , decodePbkd2Params
  , encodePbkd2Params
  , kdfCodecFor
  , kdfCodeDigest
  , kdfDigestWidth
  , kdfParamsValid
  , kdfPbkd2Codec
  , kdfPlainCodec
  , kdfRecipeFor
  , kdfRecipes
  , kdfShaWidth
  , maxPbkd2Iters
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated
  ( mustGeneratedId
  , ckm_ECDH1_DERIVE
  , ckm_HKDF_DERIVE
  , ckm_PKCS5_PBKD2
  , ckm_SHA1_KEY_DERIVATION
  , ckm_SHA256_KEY_DERIVATION
  , ckm_SHA512_224_KEY_DERIVATION
  , ckm_TLS12_KDF
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
import qualified Data.Map.Strict as Map

spec :: TestTree
spec = testGroup "KDF recipe"
  [ testCase "digest widths agree with PRF codes" caseDigestWidths
  , testCase "table: twelve rows, kinds" caseTable
  , testCase "lookup: ids resolve, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: valid and refused shapes" caseParams
  , testCase "pbkd2-params/2: password frame codec" casePbkd2GenCodec
  , testCase "PARAMS2 struct mapping" casePbkd2Params2Struct
  , testCase "planDerive: SHA-KD accept and deny" casePlanSha
  , testCase "planDerive: BLAKE2B-KD template semantics" casePlanBlake2
  , testCase "planDerive: PBKD2 accept and deny" casePlanPbkd2
  , testCase "driver maps mechanisms to digests" caseDriverMap
  ]

-- ---------------------------------------------------------------------------
-- Table + lookup + codec
-- ---------------------------------------------------------------------------

-- | (suffix, digest stem, width).
shaShape :: [(Text, Text, Int)]
shaShape =
  [ ("SHA1_KEY_DERIVATION", "SHA_1", 20)
  , ("SHA224_KEY_DERIVATION", "SHA224", 28)
  , ("SHA256_KEY_DERIVATION", "SHA256", 32)
  , ("SHA384_KEY_DERIVATION", "SHA384", 48)
  , ("SHA512_KEY_DERIVATION", "SHA512", 64)
  , ("SHA512_224_KEY_DERIVATION", "SHA512_224", 28)
  , ("SHA512_256_KEY_DERIVATION", "SHA512_256", 32)
  , ("SHA3_224_KEY_DERIVATION", "SHA3_224", 28)
  , ("SHA3_256_KEY_DERIVATION", "SHA3_256", 32)
  , ("SHA3_384_KEY_DERIVATION", "SHA3_384", 48)
  , ("SHA3_512_KEY_DERIVATION", "SHA3_512", 64)
  , ("BLAKE2B_512_KEY_DERIVE", "BLAKE2B_512", 64)
  , ("BLAKE2B_160_KEY_DERIVE", "BLAKE2B_160", 20)
  , ("BLAKE2B_256_KEY_DERIVE", "BLAKE2B_256", 32)
  , ("BLAKE2B_384_KEY_DERIVE", "BLAKE2B_384", 48)
  ]

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 16 (length kdfRecipes)
  mapM_ (\(suffix, stem, _) -> do
    let name = mechName suffix
        found = [ r | r <- kdfRecipes, rkName r == name ]
    case found of
      [r] -> do
        assertBool ("not pbkd2 " ++ T.unpack name) (not (rkPbkd2 r))
        assertEqual ("stem " ++ T.unpack name) (Just stem) (rkDigestStem r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) shaShape
  case [ r | r <- kdfRecipes, rkName r == "CKM_PKCS5_PBKD2" ] of
    [r] -> do
      assertBool "pbkd2 flag" (rkPbkd2 r)
      assertEqual "no stem" Nothing (rkDigestStem r)
    rs -> assertFailure ("pbkd2 rows: " ++ show (length rs))

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _, _) -> do
    let name = mechName suffix
    case kdfRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (rkName r)
    ) shaShape
  case kdfRecipeFor (MechanismId (ckm_PKCS5_PBKD2)) of
    Nothing -> assertFailure "unresolved CKM_PKCS5_PBKD2"
    Just r -> assertEqual "lookup pbkd2" "CKM_PKCS5_PBKD2" (rkName r)
  assertEqual "unknown id has no recipe" Nothing
    (kdfRecipeFor (MechanismId 0x4712))
  assertEqual "HKDF has no KDF recipe" Nothing
    (kdfRecipeFor (MechanismId (ckm_HKDF_DERIVE)))
  assertEqual "ECDH has no KDF recipe" Nothing
    (kdfRecipeFor (MechanismId (ckm_ECDH1_DERIVE)))
  assertEqual "TLS-KDF has no KDF recipe" Nothing
    (kdfRecipeFor (MechanismId (ckm_TLS12_KDF)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "plain codec" (ParameterCodec "no-params" 1) kdfPlainCodec
  assertEqual "pbkd2 codec" (ParameterCodec "pbkd2-params" 2) kdfPbkd2Codec
  mapM_ (\(suffix, _, _) ->
    case kdfRecipeFor (MechanismId (mustGeneratedId (mechName suffix))) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack suffix)
      Just r -> assertEqual ("codec " ++ T.unpack suffix) kdfPlainCodec
        (kdfCodecFor r)
    ) shaShape
  case kdfRecipeFor (MechanismId (ckm_PKCS5_PBKD2)) of
    Nothing -> assertFailure "unresolved pbkd2"
    Just r -> assertEqual "pbkd2 codec" kdfPbkd2Codec (kdfCodecFor r)

-- ---------------------------------------------------------------------------
-- Params
-- ---------------------------------------------------------------------------

recipeOf :: Text -> KdfRecipe
recipeOf name =
  case kdfRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

-- | Engine-local PRF codes (documented in the recipe).
caseDigestWidths :: IO ()
caseDigestWidths = do
  -- Every PRF code resolves to a stem with a known width; the
  -- two tables share their domain, so HKDF defaults can never
  -- dangle. Widths are the FIPS/RFC digest sizes.
  let widths =
        [ (1, 16), (2, 20), (3, 28), (4, 32), (5, 48), (6, 64)
        , (7, 28), (8, 32), (9, 28), (10, 32), (11, 48), (12, 64)
        , (13, 20)
        ]
  mapM_ (\(c, w) -> case kdfCodeDigest c of
    Nothing -> assertFailure ("unmapped code " ++ show c)
    Just stem -> assertEqual ("width " ++ show c) (Just w) (kdfDigestWidth stem)
    ) widths
  mapM_ (\c -> assertEqual ("code refused " ++ show c) Nothing (kdfCodeDigest c))
    [0, 14, 99]

prfSha1, prfSha256 :: Int
prfSha1 = 2
prfSha256 = 4

caseParams :: IO ()
caseParams = do
  let sha = recipeOf "CKM_SHA256_KEY_DERIVATION"
      pbkd2 = recipeOf "CKM_PKCS5_PBKD2"
      good = encodePbkd2Params prfSha256 4096 "salt" BS.empty
  assertBool "sha empty valid" (kdfParamsValid sha BS.empty)
  assertBool "sha nonempty refused" (not (kdfParamsValid sha "x"))
  assertEqual "pbkd2 roundtrip"
    (Just ("SHA256", 4096, "salt", BS.empty)) (decodePbkd2Params good)
  assertBool "pbkd2 valid" (kdfParamsValid pbkd2 good)
  assertBool "pbkd2 empty salt valid"
    (kdfParamsValid pbkd2 (encodePbkd2Params prfSha1 1 BS.empty BS.empty))
  assertBool "pbkd2 max iters valid"
    (kdfParamsValid pbkd2 (encodePbkd2Params prfSha1 maxPbkd2Iters "s" BS.empty))
  assertBool "pbkd2 inline password refused on derive"
    (not (kdfParamsValid pbkd2 (encodePbkd2Params prfSha256 1 "s" "p")))
  mapM_ (\c -> assertBool ("prf refused: " ++ show c)
    (not (kdfParamsValid pbkd2 (encodePbkd2Params c 1 "s" BS.empty)))) [0, 14, 99]
  mapM_ (\n -> assertBool ("iters refused: " ++ show n)
    (not (kdfParamsValid pbkd2 (encodePbkd2Params prfSha256 n "s" BS.empty))))
    [0, -1, maxPbkd2Iters + 1]
  assertBool "truncated refused"
    (not (kdfParamsValid pbkd2 (BS.take 20 good)))
  assertBool "trailing refused"
    (not (kdfParamsValid pbkd2 (good <> "x")))
  assertEqual "overrun prefix" Nothing
    (decodePbkd2Params (BS.pack [0,0,0,0,0,0,0,4, 0,0,0,0,0,0,0,1, 0,0,0,0,0x10,0,0,0]))
  mapM_ (\(suffix, _, w) ->
    assertEqual ("width " ++ T.unpack suffix) (Just w)
      (kdfShaWidth (recipeOf (mechName suffix)))
    ) shaShape
  assertEqual "pbkd2 has no sha width" Nothing (kdfShaWidth pbkd2)

-- | CKP_PKCS5_PBKD2_HMAC_* selector to digest stem (v3.2 §2.5.2
-- table; GOSTR3411 has no servable HMAC and stays unmapped).
ckpShape :: [(Word64, Text)]
ckpShape =
  [ (1, "SHA_1")
  , (3, "SHA224")
  , (4, "SHA256")
  , (5, "SHA384")
  , (6, "SHA512")
  , (7, "SHA512_224")
  , (8, "SHA512_256")
  ]

casePbkd2GenCodec :: IO ()
casePbkd2GenCodec = do
  let good = encodePbkd2Params prfSha256 4096 "salt" "password"
  assertEqual "password roundtrip"
    (Just ("SHA256", 4096, "salt", "password")) (decodePbkd2Params good)
  assertBool "empty password roundtrips" $
    decodePbkd2Params (encodePbkd2Params prfSha1 1 "s" BS.empty)
      == Just ("SHA_1", 1, "s", BS.empty)
  assertEqual "truncated refused" Nothing
    (decodePbkd2Params (BS.take 30 good))
  assertEqual "trailing refused" Nothing
    (decodePbkd2Params (good <> "x"))
  assertEqual "password overrun refused" Nothing
    (decodePbkd2Params (BS.take (BS.length good - 2) good))
  assertEqual "unknown prf refused" Nothing
    (decodePbkd2Params (encodePbkd2Params 99 1 "s" "p"))

casePbkd2Params2Struct :: IO ()
casePbkd2Params2Struct = do
  mapM_ (\(ckp, stem) ->
    case pbkd2Params2StructToCanonical 1 "salt" 4096 ckp BS.empty "password" of
      Nothing -> assertFailure ("unmapped CKP " ++ show ckp)
      Just frame -> assertEqual ("CKP " ++ show ckp)
        (Just (stem, 4096, "salt", "password")) (decodePbkd2Params frame)
    ) ckpShape
  let badPrf prf = pbkd2Params2StructToCanonical 1 "s" 1 prf BS.empty "p"
  mapM_ (\prf -> assertEqual ("prf refused: " ++ show prf) Nothing (badPrf prf))
    [0, 2, 9, 0xFF]
  let badSource src =
        pbkd2Params2StructToCanonical src "s" 1 4 BS.empty "p"
  mapM_ (\src -> assertEqual ("source refused: " ++ show src) Nothing (badSource src))
    [0, 2, 3]
  assertEqual "prfData refused" Nothing
    (pbkd2Params2StructToCanonical 1 "s" 1 4 "x" "p")
  assertEqual "zero iters refused" Nothing
    (pbkd2Params2StructToCanonical 1 "s" 0 4 BS.empty "p")
  assertEqual "over-ceiling iters refused" Nothing
    (pbkd2Params2StructToCanonical 1 "s"
      (fromIntegral (maxPbkd2Iters + 1)) 4 BS.empty "p")

-- ---------------------------------------------------------------------------
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

sha256Mech, sha1Mech, pbkd2Mech :: MechanismId
sha256Mech = MechanismId (ckm_SHA256_KEY_DERIVATION)
sha1Mech = MechanismId (ckm_SHA1_KEY_DERIVATION)
pbkd2Mech = MechanismId (ckm_PKCS5_PBKD2)

blake2b160Mech, blake2b256Mech, blake2b384Mech, blake2b512Mech :: MechanismId
blake2b160Mech = MechanismId (mustGeneratedId "CKM_BLAKE2B_160_KEY_DERIVE")
blake2b256Mech = MechanismId (mustGeneratedId "CKM_BLAKE2B_256_KEY_DERIVE")
blake2b384Mech = MechanismId (mustGeneratedId "CKM_BLAKE2B_384_KEY_DERIVE")
blake2b512Mech = MechanismId (mustGeneratedId "CKM_BLAKE2B_512_KEY_DERIVE")

-- | A default derive template: booleans only, no class, key type, or
-- length (the lane's test_blake2 default-template shape).
defaultTmpl :: [(AttributeType, AttributeValue)]
defaultTmpl =
  [ (AttrToken, ValBool False)
  , (AttrSensitive, ValBool False)
  , (AttrExtractable, ValBool True)
  ]

-- | A length-only template: VALUE_LEN plus booleans, no key type.
lengthOnlyTmpl :: Int -> [(AttributeType, AttributeValue)]
lengthOnlyTmpl n = (AttrValueLen, ValULong (fromIntegral n)) : defaultTmpl

-- | A typed template naming an AES output of the given length.
aesTmpl :: Int -> [(AttributeType, AttributeValue)]
aesTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkAes)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  ]

casePlanBlake2 :: IO ()
casePlanBlake2 = do
  let m = mkBaseModel "password" True
      derive mech tmpl = planDerive defaultRules m testSession mech baseHandle
        (encodeDeriveParams BS.empty [tmpl])
  -- Default templates succeed at full digest width (generic secret).
  mapM_ (\(mech, w) -> case derive mech defaultTmpl of
    KeyEffect _ (FxDerive _ _ _ _ total) ->
      assertEqual ("default total " ++ show mech) w total
    other -> assertFailure ("default must plan: " ++ show other))
    [ (blake2b160Mech, 20), (blake2b256Mech, 32)
    , (blake2b384Mech, 48), (blake2b512Mech, 64)
    ]
  -- Length-only templates succeed under the width.
  case derive blake2b512Mech (lengthOnlyTmpl 12) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "length-only total" 12 total
    other -> assertFailure ("length-only must plan: " ++ show other)
  -- Overlong outputs deny KEY_SIZE_RANGE (typed and length-only).
  expectDeny "length-only overlong" CKR_KEY_SIZE_RANGE
    (derive blake2b512Mech (lengthOnlyTmpl 65))
  expectDeny "typed overlong AES-256 via 160" CKR_KEY_SIZE_RANGE
    (derive blake2b160Mech (aesTmpl 32))
  -- A variable-length target without a length stays incomplete.
  expectDeny "AES without length" CKR_TEMPLATE_INCOMPLETE
    (derive blake2b256Mech
      [ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong ckkAes)
      , (AttrToken, ValBool False)
      ])
  -- Zero length denies KEY_SIZE_RANGE, never silently mints empty.
  expectDeny "length-only zero" CKR_KEY_SIZE_RANGE
    (derive blake2b512Mech (lengthOnlyTmpl 0))
  -- Caller-supplied CKA_VALUE in a derive template is rejected.
  expectDeny "value injection" CKR_TEMPLATE_INCONSISTENT
    (derive blake2b512Mech
      (derivedTmpl 64 ++ [(AttrValue, ValBytes (BS.replicate 64 0xa5))]))

expectDeny :: String -> ReturnCode -> KeyPlan -> IO ()
expectDeny label code plan = case plan of
  KeyDenied (KeyDeny c _) -> assertEqual ("deny " ++ label) code c
  other -> assertFailure ("expected denial, got " ++ show other)

casePlanSha :: IO ()
casePlanSha = do
  let m = mkBaseModel "password" True
  -- Accepted at full width and truncated; empty params/info.
  case planDerive defaultRules m testSession sha256Mech baseHandle
      (encodeDeriveParams BS.empty [derivedTmpl 32]) of
    KeyEffect _ (FxDerive mech (Just oid) params info total) -> do
      assertEqual "mech" sha256Mech mech
      assertEqual "base" baseOid oid
      assertEqual "params" BS.empty params
      assertEqual "info empty" BS.empty info
      assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  case planDerive defaultRules m testSession sha256Mech baseHandle
      (encodeDeriveParams BS.empty [derivedTmpl 16, derivedTmpl 16]) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Width ceiling per digest.
  expectDeny "over sha256 width" CKR_KEY_SIZE_RANGE
    (planDerive defaultRules m testSession sha256Mech baseHandle
      (encodeDeriveParams BS.empty [derivedTmpl 33]))
  case planDerive defaultRules m testSession sha1Mech baseHandle
      (encodeDeriveParams BS.empty [derivedTmpl 20]) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "total" 20 total
    other -> assertFailure ("expected effect, got " ++ show other)
  expectDeny "over sha1 width" CKR_KEY_SIZE_RANGE
    (planDerive defaultRules m testSession sha1Mech baseHandle
      (encodeDeriveParams BS.empty [derivedTmpl 21]))
  -- Non-empty info denies (no parameters).
  expectDeny "nonempty info" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession sha256Mech baseHandle
      (encodeDeriveParams "x" [derivedTmpl 32]))
  expectDeny "malformed blob" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession sha256Mech baseHandle "truncated")
  -- Base-key faults mirror the HKDF denials.
  expectDeny "no derive mark" CKR_KEY_FUNCTION_NOT_PERMITTED
    (planDerive defaultRules (mkBaseModel "password" False) testSession
      sha256Mech baseHandle (encodeDeriveParams BS.empty [derivedTmpl 32]))
  expectDeny "unknown handle" CKR_KEY_HANDLE_INVALID
    (planDerive defaultRules m testSession sha256Mech (ExternalHandle 999)
      (encodeDeriveParams BS.empty [derivedTmpl 32]))

casePlanPbkd2 :: IO ()
casePlanPbkd2 = do
  let m = mkBaseModel "password" True
      blob = encodePbkd2Params prfSha256 4096 "salt" BS.empty
  -- Accepted; the blob travels as mechanism params.
  case planDerive defaultRules m testSession pbkd2Mech baseHandle
      (encodeDeriveParams blob [derivedTmpl 32]) of
    KeyEffect _ (FxDerive mech (Just oid) params info total) -> do
      assertEqual "mech" pbkd2Mech mech
      assertEqual "base" baseOid oid
      assertEqual "params" blob params
      assertEqual "info empty" BS.empty info
      assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Multi-block totals plan (PBKDF2 output is unbounded).
  case planDerive defaultRules m testSession pbkd2Mech baseHandle
      (encodeDeriveParams blob [derivedTmpl 64, derivedTmpl 64]) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "total" 128 total
    other -> assertFailure ("expected effect, got " ++ show other)
  expectDeny "over ceiling" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession pbkd2Mech baseHandle
      (encodeDeriveParams blob [derivedTmpl (maxDerivedTotal + 1)]))
  -- Bad blobs deny at the frame.
  expectDeny "bad prf" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession pbkd2Mech baseHandle
      (encodeDeriveParams (encodePbkd2Params 99 1 "s" BS.empty) [derivedTmpl 32]))
  expectDeny "zero iters" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession pbkd2Mech baseHandle
      (encodeDeriveParams (encodePbkd2Params prfSha256 0 "s" BS.empty) [derivedTmpl 32]))
  expectDeny "malformed blob" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession pbkd2Mech baseHandle "truncated")
  expectDeny "no templates" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession pbkd2Mech baseHandle (encodeDeriveParams blob []))
  expectDeny "no derive mark" CKR_KEY_FUNCTION_NOT_PERMITTED
    (planDerive defaultRules (mkBaseModel "password" False) testSession
      pbkd2Mech baseHandle (encodeDeriveParams blob [derivedTmpl 32]))

-- ---------------------------------------------------------------------------
-- Driver mapping
-- ---------------------------------------------------------------------------

caseDriverMap :: IO ()
caseDriverMap = do
  mapM_ (\(suffix, _, _) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
    case kdfShaFor mech of
      Just _ -> pure ()
      Nothing -> assertFailure ("unmapped " ++ T.unpack suffix)
    ) shaShape
  assertEqual "sha256 maps" (Just D_SHA256) (kdfShaFor sha256Mech)
  assertEqual "sha1 maps" (Just D_SHA1) (kdfShaFor sha1Mech)
  assertEqual "sha512_224 maps" (Just D_SHA512_224)
    (kdfShaFor (MechanismId (ckm_SHA512_224_KEY_DERIVATION)))
  assertEqual "pbkd2 is not a sha row" Nothing (kdfShaFor pbkd2Mech)
  assertEqual "hkdf uncovered" Nothing
    (kdfShaFor (MechanismId (ckm_HKDF_DERIVE)))
  let good = encodePbkd2Params prfSha256 4096 "salt" BS.empty
  case pbkd2ParamsFor pbkd2Mech good of
    Just pp -> do
      assertEqual "prf" D_SHA256 (ppPrf pp)
      assertEqual "iters" 4096 (ppIters pp)
      assertEqual "salt" "salt" (ppSalt pp)
    Nothing -> assertFailure "pbkd2 must map"
  assertEqual "bad prf refused" Nothing
    (pbkd2ParamsFor pbkd2Mech (encodePbkd2Params 99 1 "s" BS.empty))
  assertEqual "zero iters refused" Nothing
    (pbkd2ParamsFor pbkd2Mech (encodePbkd2Params prfSha256 0 "s" BS.empty))
  assertEqual "truncated refused" Nothing
    (pbkd2ParamsFor pbkd2Mech (BS.take 20 good))
  assertEqual "sha row takes no pbkd2" Nothing
    (pbkd2ParamsFor sha256Mech good)
  assertEqual "non-KDF uncovered" Nothing
    (pbkd2ParamsFor (MechanismId (ckm_HKDF_DERIVE)) good)
