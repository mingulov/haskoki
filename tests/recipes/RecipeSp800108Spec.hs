{- | SP 800-108 recipe tests.

Three header mechanisms, @CKM_SP800_108_COUNTER_KDF@,
@CKM_SP800_108_FEEDBACK_KDF@, @CKM_SP800_108_DOUBLE_PIPELINE_KDF@
(NIST SP 800-108 §5.1\/5.2\/5.3 over an HMAC PRF). Parameters
are the canonical frame (@sp800-params\/1@: @prf:u8 rWidth:u8
lWidth:u8 ivLen:u64be iv fixedLen:u64be fixed@); the mode rides
the mechanism. The output length arrives via the derived
template's @CKA_VALUE_LEN@, capped by 'maxSp800Total', and must
fit the DKM-length width (L does not fit = typed refusal).

'Haskoki.Recipe.Sp800108' owns the canonical codec, parameter
validation, and mechanism table; these tests pin the recipe and
its consumers:

* the derive planner accepts SP 800-108 frames ('planDerive')
  with the output ceiling and the L-fit check, and denies
  malformed frames;
* the driver maps the covered (mechanism, params) triple to its
  execution tuple ('sp800ParamsFor' agrees with the recipe
  table);
* engines execute the pinned construction (RoutingE2ESpec vectors
  against the pinned libcrypto, SyntheticSpec constructions).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeSp800108Spec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend (DigestAlg (..))
import Haskoki.Engine.Driver (Sp800Exec (..), sp800ParamsFor)
import Haskoki.FFI.NativeParams (Sp800DataParam (..), sp800StructToCanonical)
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
import Haskoki.Recipe.Sp800108
  ( Sp800Mode (..)
  , Sp800Params (..)
  , Sp800Recipe (..)
  , decodeSp800Params
  , encodeSp800Params
  , maxSp800Fixed
  , maxSp800Total
  , sp800Codec
  , sp800CodecFor
  , sp800ParamsValid
  , sp800PrfCodeFor
  , sp800RecipeFor
  , sp800Recipes
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated
  ( mustGeneratedId
  , ckm_BLAKE2B_256_HMAC
  , ckm_MD2_HMAC
  , ckm_MD5_HMAC
  , ckm_SHA256_HMAC
  , ckm_SHA256_HMAC_GENERAL
  , ckm_SHA256_RSA_PKCS
  , ckm_SP800_108_COUNTER_KDF
  , ckm_SP800_108_DOUBLE_PIPELINE_KDF
  , ckm_SP800_108_FEEDBACK_KDF
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
spec = testGroup "SP800-108 recipe"
  [ testCase "table: three rows with modes" caseTable
  , testCase "lookup: ids resolve, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: valid and refused shapes" caseParams
  , testCase "PRF mechanisms map to codes" casePrfCodes
  , testCase "struct profile translates" caseStruct
  , testCase "planDerive: accept and deny" casePlan
  , testCase "driver maps the pair to the exec tuple" caseDriverMap
  ]

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 3 (length sp800Recipes)
  let modes = [(rsName r, rsMode r) | r <- sp800Recipes]
  assertEqual "row modes"
    [ ("CKM_SP800_108_COUNTER_KDF" :: T.Text, Sp800Counter)
    , ("CKM_SP800_108_FEEDBACK_KDF", Sp800Feedback)
    , ("CKM_SP800_108_DOUBLE_PIPELINE_KDF", Sp800DoublePipeline)
    ] modes

caseLookup :: IO ()
caseLookup = do
  let yes :: Word64 -> T.Text -> IO ()
      yes mid name = case sp800RecipeFor (MechanismId mid) of
        Nothing -> assertFailure (T.unpack name ++ " unresolved")
        Just r -> assertEqual ("lookup " ++ T.unpack name) name (rsName r)
  yes ckm_SP800_108_COUNTER_KDF "CKM_SP800_108_COUNTER_KDF"
  yes ckm_SP800_108_FEEDBACK_KDF "CKM_SP800_108_FEEDBACK_KDF"
  yes ckm_SP800_108_DOUBLE_PIPELINE_KDF "CKM_SP800_108_DOUBLE_PIPELINE_KDF"
  yes (mustGeneratedId "CKM_SP800_108_COUNTER_KDF") "CKM_SP800_108_COUNTER_KDF"
  assertEqual "unknown id has no recipe" Nothing
    (sp800RecipeFor (MechanismId 0x4712))
  assertEqual "RSA has no SP800 recipe" Nothing
    (sp800RecipeFor (MechanismId ckm_SHA256_RSA_PKCS))

caseCodec :: IO ()
caseCodec = do
  assertEqual "sp800 codec" (ParameterCodec "sp800-params" 1) sp800Codec
  case sp800RecipeFor (MechanismId ckm_SP800_108_COUNTER_KDF) of
    Nothing -> assertFailure "COUNTER unresolved"
    Just r -> assertEqual "codec row" sp800Codec (sp800CodecFor r)

-- | The oracle-profile frame: HMAC-SHA256 (code 4), 32-bit
-- counter, 32-bit length, the label/0x00/context fixed input.
oracleFrame :: BS.ByteString
oracleFrame = encodeSp800Params 4 32 32 BS.empty oracleFixed

oracleFixed :: BS.ByteString
oracleFixed = "SP800-108 test label" <> "\x00" <> "SP800-108 test context"

caseParams :: IO ()
caseParams = do
  assertEqual "round-trip"
    (Just (Sp800Params 4 32 32 BS.empty oracleFixed))
    (decodeSp800Params oracleFrame)
  let iv = BS.pack [0 .. 15]
  assertEqual "iv round-trip"
    (Just (Sp800Params 4 32 32 iv oracleFixed))
    (decodeSp800Params (encodeSp800Params 4 32 32 iv oracleFixed))
  -- PRF codes are the kdfCodeDigest space (1..13); 0 and 14+
  -- refuse.
  assertEqual "prf 0 refuses" Nothing
    (decodeSp800Params (encodeSp800Params 0 32 32 BS.empty oracleFixed))
  assertEqual "prf 14 refuses" Nothing
    (decodeSp800Params (encodeSp800Params 14 32 32 BS.empty oracleFixed))
  -- Widths are one of 8/16/24/32 bits.
  mapM_ (\w -> assertEqual ("r width " ++ show w ++ " decodes") True $
    case decodeSp800Params (encodeSp800Params 4 w 32 BS.empty oracleFixed) of
      Just p -> spCounterBits p == w
      Nothing -> False) [8, 16, 24, 32]
  mapM_ (\w -> assertEqual ("r width " ++ show w ++ " refuses") Nothing
    (decodeSp800Params (encodeSp800Params 4 w 32 BS.empty oracleFixed)))
    [0, 7, 33, 64]
  assertEqual "l width 7 refuses" Nothing
    (decodeSp800Params (encodeSp800Params 4 32 7 BS.empty oracleFixed))
  -- Truncation, trailing bytes, and over-ceiling inputs refuse.
  assertEqual "truncated refuses" Nothing
    (decodeSp800Params (BS.take (BS.length oracleFrame - 1) oracleFrame))
  assertEqual "short refuses" Nothing
    (decodeSp800Params (BS.take 3 oracleFrame))
  assertEqual "trailing refuses" Nothing
    (decodeSp800Params (oracleFrame <> "x"))
  let big = BS.replicate (maxSp800Fixed + 1) 0x41
  assertEqual "over-ceiling fixed refuses" Nothing
    (decodeSp800Params (encodeSp800Params 4 32 32 BS.empty big))
  -- Mode/IV consistency needs the recipe: only feedback rows
  -- take an IV.
  case sp800RecipeFor (MechanismId ckm_SP800_108_COUNTER_KDF) of
    Nothing -> assertFailure "COUNTER unresolved"
    Just r -> do
      assertEqual "counter frame valid" True (sp800ParamsValid r oracleFrame)
      assertEqual "counter iv refused" False
        (sp800ParamsValid r (encodeSp800Params 4 32 32 "iv" oracleFixed))
      assertEqual "junk refused" False (sp800ParamsValid r "junk")
  case sp800RecipeFor (MechanismId ckm_SP800_108_FEEDBACK_KDF) of
    Nothing -> assertFailure "FEEDBACK unresolved"
    Just r -> assertEqual "feedback iv valid" True
      (sp800ParamsValid r (encodeSp800Params 4 32 32 "iv" oracleFixed))
  assertEqual "output ceiling" 65536 maxSp800Total
  assertEqual "fixed ceiling" 65536 maxSp800Fixed

casePrfCodes :: IO ()
casePrfCodes = do
  assertEqual "sha256 hmac" (Just 4)
    (sp800PrfCodeFor (MechanismId ckm_SHA256_HMAC))
  assertEqual "general names the same prf" (Just 4)
    (sp800PrfCodeFor (MechanismId ckm_SHA256_HMAC_GENERAL))
  assertEqual "md5 hmac" (Just 1)
    (sp800PrfCodeFor (MechanismId ckm_MD5_HMAC))
  assertEqual "rsa is no prf" Nothing
    (sp800PrfCodeFor (MechanismId ckm_SHA256_RSA_PKCS))
  assertEqual "unserved hmac is no prf" Nothing
    (sp800PrfCodeFor (MechanismId ckm_MD2_HMAC))
  assertEqual "blake hmac has no code" Nothing
    (sp800PrfCodeFor (MechanismId ckm_BLAKE2B_256_HMAC))

-- | The oracle-profile data params: iteration first, label /
-- separator / context byte arrays, DKM length last.
oracleDataParams :: [Sp800DataParam]
oracleDataParams =
  [ Sp800Iter False 32
  , Sp800Bytes "SP800-108 test label"
  , Sp800Bytes "\x00"
  , Sp800Bytes "SP800-108 test context"
  , Sp800DkmLen 1 False 32
  ]

caseStruct :: IO ()
caseStruct = do
  assertEqual "canonical profile translates" (Just oracleFrame)
    (sp800StructToCanonical Sp800Counter ckm_SHA256_HMAC
      oracleDataParams BS.empty 0)
  assertEqual "general prf names the same frame" (Just oracleFrame)
    (sp800StructToCanonical Sp800Counter ckm_SHA256_HMAC_GENERAL
      oracleDataParams BS.empty 0)
  let iv = BS.pack [0 .. 15]
  assertEqual "feedback keeps its iv"
    (Just (encodeSp800Params 4 32 32 iv oracleFixed))
    (sp800StructToCanonical Sp800Feedback ckm_SHA256_HMAC
      oracleDataParams iv 0)
  assertEqual "minimal pair translates with empty fixed"
    (Just (encodeSp800Params 4 16 24 BS.empty BS.empty))
    (sp800StructToCanonical Sp800Counter ckm_SHA256_HMAC
      [Sp800Iter False 16, Sp800DkmLen 1 False 24] BS.empty 0)
  -- Off-profile shapes refuse.
  let bad label ps iv' add prf =
        assertEqual label Nothing
          (sp800StructToCanonical Sp800Counter prf ps iv' add)
      good = ckm_SHA256_HMAC
  bad "little-endian counter refuses"
    (Sp800Iter True 32 : tail oracleDataParams) BS.empty 0 good
  bad "little-endian dkm refuses"
    (init oracleDataParams ++ [Sp800DkmLen 1 True 32]) BS.empty 0 good
  bad "wide counter refuses"
    (Sp800Iter False 64 : tail oracleDataParams) BS.empty 0 good
  bad "wide dkm refuses"
    (init oracleDataParams ++ [Sp800DkmLen 1 False 64]) BS.empty 0 good
  bad "segments method refuses"
    (init oracleDataParams ++ [Sp800DkmLen 2 False 32]) BS.empty 0 good
  bad "iteration must lead"
    (tail oracleDataParams ++ [Sp800Iter False 32]) BS.empty 0 good
  bad "dkm must trail"
    (oracleDataParams ++ [Sp800Bytes "x"]) BS.empty 0 good
  bad "lone iteration refuses" [Sp800Iter False 32] BS.empty 0 good
  bad "empty params refuse" [] BS.empty 0 good
  bad "rsa is no prf" oracleDataParams BS.empty 0 ckm_SHA256_RSA_PKCS
  bad "unserved hmac is no prf" oracleDataParams BS.empty 0 ckm_MD2_HMAC
  bad "additional keys refuse" oracleDataParams BS.empty 1 good
  bad "counter iv refuses" oracleDataParams "iv" 0 good
  assertEqual "feedback iv-empty translates" (Just oracleFrame)
    (sp800StructToCanonical Sp800Feedback ckm_SHA256_HMAC
      oracleDataParams BS.empty 0)
  assertEqual "double-pipeline iv refuses" Nothing
    (sp800StructToCanonical Sp800DoublePipeline ckm_SHA256_HMAC
      oracleDataParams "iv" 0)
  -- Feedback and double-pipeline callers send the iteration
  -- variable as a NULL/0 placeholder (lane r56: those modes
  -- have no counter); the frame records width 32, inert
  -- downstream. Counter mode refuses the placeholder (it
  -- needs its width).
  let noIter = Sp800IterAbsent : tail oracleDataParams
  assertEqual "feedback absent-iter translates" (Just oracleFrame)
    (sp800StructToCanonical Sp800Feedback ckm_SHA256_HMAC
      noIter BS.empty 0)
  assertEqual "double-pipeline absent-iter translates" (Just oracleFrame)
    (sp800StructToCanonical Sp800DoublePipeline ckm_SHA256_HMAC
      noIter BS.empty 0)
  assertEqual "counter absent-iter refuses" Nothing
    (sp800StructToCanonical Sp800Counter ckm_SHA256_HMAC
      noIter BS.empty 0)

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

counterMech :: MechanismId
counterMech = MechanismId ckm_SP800_108_COUNTER_KDF

expectDeny :: String -> ReturnCode -> KeyPlan -> IO ()
expectDeny label code plan = case plan of
  KeyDenied (KeyDeny c _) -> assertEqual ("deny " ++ label) code c
  other -> assertFailure ("expected denial, got " ++ show other)

caseDriverMap :: IO ()
caseDriverMap = do
  assertEqual "covered pair decodes"
    (Just (Sp800Exec Sp800Counter D_SHA256 32 32 32 BS.empty oracleFixed))
    (sp800ParamsFor counterMech oracleFrame)
  assertEqual "junk refuses" Nothing (sp800ParamsFor counterMech "junk")
  assertEqual "other mechanism uncovered" Nothing
    (sp800ParamsFor (MechanismId ckm_SHA256_RSA_PKCS) oracleFrame)
  assertEqual "unknown id uncovered" Nothing
    (sp800ParamsFor (MechanismId 0x4712) oracleFrame)

casePlan :: IO ()
casePlan = do
  let m = mkBaseModel "secret" True
  -- Accepted: the oracle-profile frame plus a VALUE_LEN template.
  case planDerive defaultRules m testSession counterMech baseHandle
      (encodeDeriveParams oracleFrame [derivedTmpl 16]) of
    KeyEffect _ (FxDerive mech (Just oid) Nothing params info total) -> do
      assertEqual "mech" counterMech mech
      assertEqual "base" baseOid oid
      assertEqual "params" oracleFrame params
      assertEqual "info empty" BS.empty info
      assertEqual "total" 16 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Malformed frames refuse typed.
  expectDeny "junk params" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession counterMech baseHandle
      (encodeDeriveParams "junk" [derivedTmpl 16]))
  -- Output past the ceiling refuses typed.
  expectDeny "over ceiling" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession counterMech baseHandle
      (encodeDeriveParams oracleFrame [derivedTmpl (maxSp800Total + 1)]))
  -- A total whose bit-length does not fit the L width refuses
  -- typed (320 bits need more than 8).
  let narrow = encodeSp800Params 4 32 8 BS.empty oracleFixed
  expectDeny "L does not fit" CKR_KEY_SIZE_RANGE
    (planDerive defaultRules m testSession counterMech baseHandle
      (encodeDeriveParams narrow [derivedTmpl 40]))
  -- Counter mode past 2^r - 1 iterations refuses typed (256
  -- blocks need more than 8 counter bits; the counter never
  -- wraps).
  let short = encodeSp800Params 4 8 32 BS.empty oracleFixed
  expectDeny "counter does not fit" CKR_KEY_SIZE_RANGE
    (planDerive defaultRules m testSession counterMech baseHandle
      (encodeDeriveParams short [derivedTmpl 8192]))
  -- A non-derivable base refuses at the key check.
  expectDeny "no derive flag" CKR_KEY_FUNCTION_NOT_PERMITTED
    (planDerive defaultRules (mkBaseModel "secret" False) testSession
      counterMech baseHandle
      (encodeDeriveParams oracleFrame [derivedTmpl 16]))
