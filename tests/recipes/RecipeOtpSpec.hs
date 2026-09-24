{- | OTP recipe tests.

The OTP group: @CKM_HOTP@ executes HOTP (RFC 4226) as a keyed
sign\/verify MAC over HMAC-SHA1 with @hotp-params\/1@ parameters
(@counter:u64be digits:u64be@, 6-8 digits); @CKM_HOTP_KEY_GEN@
mints 16-64 byte secrets (synthetic-only, like @CKM_AES_KEY_GEN@).
@CKM_ACTI@\/@CKM_ACTI_KEY_GEN@ and the stateful-signature families
stay catalog-only (planned, with reasons).

'Haskoki.Recipe.Otp' owns the group's canonical codec, parameter
validation, RFC 4226 dynamic truncation, keygen bounds, and
mechanism table; these tests pin the recipe and its three
consumers:

* the model init path enforces HOTP parameters ('validateInit',
  'CKR_ARGUMENTS_BAD');
* the driver maps (mechanism, params) to (counter, digits)
  ('hotpParamsFor') and executes the HMAC-SHA1-plus-truncate
  composition over the backend MAC route;
* the keygen planner mints HOTP secrets from @CKA_VALUE_LEN@
  templates ('planGenerateKey');
* engines execute the pinned KATs (RoutingE2ESpec RFC 4226 vectors
  on the real backend, SyntheticSpec constructions).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeOtpSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Driver (hotpParamsFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( CryptoEffect (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Operation.KeyManagement
  ( GenArgs (..)
  , KeyDeny (..)
  , KeyPlan (..)
  , ckkAes
  , ckkHotp
  , ckoSecretKey
  , decodeGenArgs
  , hotpKeyGenMech
  , planGenerateKey
  )
import Haskoki.Recipe.Otp
  ( OtpRecipe (..)
  , decodeHotpParams
  , encodeHotpCounter
  , encodeHotpParams
  , hotpCodec
  , hotpCodecFor
  , hotpKeygenMaxBytes
  , hotpKeygenMinBytes
  , hotpParamsValid
  , hotpRecipeFor
  , hotpRecipes
  , hotpTruncate
  )
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , ParameterCodec (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Registry.Generated (ckm_HOTP, ckm_SHA_1_HMAC)
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "OTP recipe"
  [ testCase "table: one row" caseTable
  , testCase "lookup: HOTP resolves, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: layout and round-trip" caseParamsCodec
  , testCase "params: validity" caseParamsValid
  , testCase "truncate: RFC 4226 pins" caseTruncate
  , testCase "keygen geometry" caseKeygenGeometry
  , testCase "init enforces parameters" caseInitParams
  , testCase "driver maps params" caseDriverMap
  , testCase "keygen planning accepts the HOTP template" caseKeygenPlan
  , testCase "keygen planning refuses bad templates" caseKeygenRefuse
  ]

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

hex :: String -> ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

hotpMech :: MechanismId
hotpMech = MechanismId (ckm_HOTP)

recipeOf :: OtpRecipe
recipeOf = case hotpRecipeFor hotpMech of
  Just r -> r
  Nothing -> error "test recipe missing: CKM_HOTP"

-- ---------------------------------------------------------------------------
-- Table + lookup + codec
-- ---------------------------------------------------------------------------

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 1 (length hotpRecipes)
  case hotpRecipes of
    (r : _) -> assertEqual "row name" "CKM_HOTP" (otpName r)
    [] -> assertFailure "hotpRecipes empty"

caseLookup :: IO ()
caseLookup = do
  case hotpRecipeFor hotpMech of
    Nothing -> assertFailure "HOTP unresolved"
    Just r -> assertEqual "lookup" "CKM_HOTP" (otpName r)
  assertEqual "KEY_GEN has no sign recipe" Nothing
    (hotpRecipeFor hotpKeyGenMech)
  assertEqual "unknown id has no recipe" Nothing
    (hotpRecipeFor (MechanismId 0x4712))
  assertEqual "HMAC-SHA1 has no HOTP recipe" Nothing
    (hotpRecipeFor (MechanismId (ckm_SHA_1_HMAC)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "codec" (ParameterCodec "hotp-params" 1) hotpCodec
  assertEqual "row codec" hotpCodec (hotpCodecFor recipeOf)

-- ---------------------------------------------------------------------------
-- Params codec + validity
-- ---------------------------------------------------------------------------

-- | (counter, digits) round-trip samples, edges included.
codecSamples :: [(Word64, Int)]
codecSamples =
  [ (0, 6)
  , (1, 6)
  , (9, 6)
  , (42, 7)
  , (0xffffffff, 8)
  , (0xffffffffffffffff, 6)
  , (0xffffffffffffffff, 8)
  ]

caseParamsCodec :: IO ()
caseParamsCodec = do
  assertEqual "layout pin"
    (hex "0000000000000001" <> hex "0000000000000006")
    (encodeHotpParams 1 6)
  assertEqual "counter pin" (hex "0000000000000001") (encodeHotpCounter 1)
  mapM_ (\(c, d) -> assertEqual ("round-trip " ++ show (c, d))
    (Just (c, d)) (decodeHotpParams (encodeHotpParams c d))) codecSamples
  assertEqual "empty rejected" Nothing (decodeHotpParams BS.empty)
  assertEqual "short rejected" Nothing
    (decodeHotpParams (hex "0000000000000001"))
  assertEqual "long rejected" Nothing
    (decodeHotpParams (encodeHotpParams 1 6 <> "x"))
  mapM_ (\d -> assertEqual ("digits rejected " ++ show d) Nothing
    (decodeHotpParams (word64be 3 <> word64be d))) [0, 1, 5, 9, 10, 0xffffffff]
  where
    word64be :: Word64 -> ByteString
    word64be w = BS.pack
      [ fromIntegral (w `div` 72057594037927936 `mod` 256)
      , fromIntegral (w `div` 281474976710656 `mod` 256)
      , fromIntegral (w `div` 1099511627776 `mod` 256)
      , fromIntegral (w `div` 4294967296 `mod` 256)
      , fromIntegral (w `div` 16777216 `mod` 256)
      , fromIntegral (w `div` 65536 `mod` 256)
      , fromIntegral (w `div` 256 `mod` 256)
      , fromIntegral (w `mod` 256)
      ]

caseParamsValid :: IO ()
caseParamsValid = do
  let r = recipeOf
  mapM_ (\(c, d) -> assertBool ("valid " ++ show (c, d))
    (hotpParamsValid r (encodeHotpParams c d))) codecSamples
  assertBool "empty invalid" (not (hotpParamsValid r BS.empty))
  assertBool "short invalid"
    (not (hotpParamsValid r (hex "0000000000000001")))
  assertBool "digits 5 invalid"
    (not (hotpParamsValid r (hex "0000000000000003" <> hex "0000000000000005")))

caseTruncate :: IO ()
caseTruncate = do
  -- RFC 4226 Appendix D key "12345678901234567890": the HMAC-SHA1
  -- bytes below come from the independent Python hmac oracle.
  assertEqual "counter 0" (Just "755224")
    (hotpTruncate (hex "cc93cf18508d94934c64b65d8ba7667fb7cde4b0") 6)
  assertEqual "counter 1" (Just "287082")
    (hotpTruncate (hex "75a48a19d4cbe100644e8ac1397eea747a2d33ab") 6)
  assertEqual "leading zero kept" (Just "026920")
    (hotpTruncate (hex "543c61f8f9aeb35f6dbc3a6847c3fe288cc0ee4c") 6)
  assertEqual "7 digits" (Just "4755224")
    (hotpTruncate (hex "cc93cf18508d94934c64b65d8ba7667fb7cde4b0") 7)
  assertEqual "8 digits" (Just "84755224")
    (hotpTruncate (hex "cc93cf18508d94934c64b65d8ba7667fb7cde4b0") 8)
  assertEqual "digits 5 refused" Nothing
    (hotpTruncate (hex "cc93cf18508d94934c64b65d8ba7667fb7cde4b0") 5)
  assertEqual "digits 9 refused" Nothing
    (hotpTruncate (hex "cc93cf18508d94934c64b65d8ba7667fb7cde4b0") 9)
  assertEqual "short mac refused" Nothing
    (hotpTruncate (hex "cc93cf18508d94934c64b65d8ba7667fb7cde4") 6)

caseKeygenGeometry :: IO ()
caseKeygenGeometry = do
  assertEqual "min bytes" 16 hotpKeygenMinBytes
  assertEqual "max bytes" 64 hotpKeygenMaxBytes

-- ---------------------------------------------------------------------------
-- Init path
-- ---------------------------------------------------------------------------

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

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(hotpMech, OpSign), (hotpMech, OpVerify)]
  , oeModel = emptyModel
  }

-- | Unknown handle: valid parameters proceed PAST the parameter check
-- to key resolution (proving acceptance); bad parameters stop at
-- 'CKR_ARGUMENTS_BAD'.
badKey :: KeyPolicy
badKey = KeyPolicy (ExternalHandle 999) [OpSign, OpVerify] False

runInit :: InitArgs -> ReturnCode
runInit args = ioCode (snd (initOperation testEnv emptySessionOps testSession args))

caseInitParams :: IO ()
caseInitParams = do
  assertEqual "empty refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign hotpMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "short refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign hotpMech "x" (Just badKey) Nothing Nothing))
  assertEqual "bad digits refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign hotpMech
      (hex "0000000000000003" <> hex "0000000000000005")
      (Just badKey) Nothing Nothing))
  assertEqual "good passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign hotpMech (encodeHotpParams 3 6)
      (Just badKey) Nothing Nothing))
  assertEqual "verify good passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpVerify hotpMech (encodeHotpParams 3 8)
      (Just badKey) Nothing Nothing))

-- ---------------------------------------------------------------------------
-- Driver mapping
-- ---------------------------------------------------------------------------

caseDriverMap :: IO ()
caseDriverMap = do
  assertEqual "params decode" (Just (7, 8))
    (hotpParamsFor hotpMech (encodeHotpParams 7 8))
  assertEqual "bad params" Nothing
    (hotpParamsFor hotpMech "x")
  assertEqual "bad digits" Nothing
    (hotpParamsFor hotpMech (encodeHotpParams 7 9))
  assertEqual "wrong mech" Nothing
    (hotpParamsFor (MechanismId 0x4712) (encodeHotpParams 7 6))
  assertEqual "KEY_GEN is not a sign mech" Nothing
    (hotpParamsFor hotpKeyGenMech (encodeHotpParams 7 6))

-- ---------------------------------------------------------------------------
-- Keygen planning
-- ---------------------------------------------------------------------------

hotpTmpl :: Int -> [(AttributeType, AttributeValue)]
hotpTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkHotp)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  , (AttrSign, ValBool True)
  , (AttrVerify, ValBool True)
  ]

caseKeygenPlan :: IO ()
caseKeygenPlan =
  mapM_ (\n -> case planGenerateKey defaultRules emptyModel testSession hotpKeyGenMech (hotpTmpl n) of
    KeyEffect _ (FxGenerateKey m params input)
      | m == hotpKeyGenMech
      , BS.null params
      , decodeGenArgs input == Just (GenBytes n) -> pure ()
    other -> assertFailure ("length " ++ show n ++ ": " ++ show other)
    ) [16, 20, 64]

denyCode :: KeyPlan -> IO ReturnCode
denyCode plan = case plan of
  KeyDenied (KeyDeny code _) -> pure code
  other -> assertFailure ("expected denial, got: " ++ show other)

caseKeygenRefuse :: IO ()
caseKeygenRefuse = do
  assertEqual "8 bytes refused" CKR_TEMPLATE_INCONSISTENT =<< denyCode
    (planGenerateKey defaultRules emptyModel testSession hotpKeyGenMech (hotpTmpl 8))
  assertEqual "15 bytes refused" CKR_TEMPLATE_INCONSISTENT =<< denyCode
    (planGenerateKey defaultRules emptyModel testSession hotpKeyGenMech (hotpTmpl 15))
  assertEqual "65 bytes refused" CKR_TEMPLATE_INCONSISTENT =<< denyCode
    (planGenerateKey defaultRules emptyModel testSession hotpKeyGenMech (hotpTmpl 65))
  assertEqual "missing length incomplete" CKR_TEMPLATE_INCOMPLETE =<< denyCode
    (planGenerateKey defaultRules emptyModel testSession hotpKeyGenMech
      (filter ((/= AttrValueLen) . fst) (hotpTmpl 20)))
  assertEqual "missing class incomplete" CKR_TEMPLATE_INCOMPLETE =<< denyCode
    (planGenerateKey defaultRules emptyModel testSession hotpKeyGenMech
      (filter ((/= AttrClass) . fst) (hotpTmpl 20)))
  assertEqual "HOTP sign mech is not keygen" CKR_MECHANISM_INVALID =<< denyCode
    (planGenerateKey defaultRules emptyModel testSession hotpMech (hotpTmpl 20))
  assertEqual "unknown mech is not keygen" CKR_MECHANISM_INVALID =<< denyCode
    (planGenerateKey defaultRules emptyModel testSession (MechanismId 0x4712) (hotpTmpl 20))
  -- A CKK_AES key type contradicts the HOTP keygen mechanism.
  assertEqual "wrong key type refused" CKR_TEMPLATE_INCONSISTENT =<< denyCode
    (planGenerateKey defaultRules emptyModel testSession hotpKeyGenMech
      [ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong ckkAes)
      , (AttrValueLen, ValULong 20)
      ])
