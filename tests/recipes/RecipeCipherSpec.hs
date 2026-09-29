{- | block-cipher-shape recipe tests.

The CBC/ECB group: 50 header mechanisms sharing one parameter shape
over eleven algorithm families — CBC takes the IV as mechanism
parameters (one block: 16 bytes for AES/ARIA/CAMELLIA, 8 for
Triple-DES), ECB takes empty parameters, @CKM_AES_CTR@ and
@CKM_CAMELLIA_CTR@ take the canonical counter image,
@CKM_AES_CTS@ takes the raw IV like CBC
(the stealing floor replaces alignment in the planners),
@CKM_AES_CFB128@/@CFB8@/@CFB1@/@OFB@ take the raw IV with any
input length (length-preserving streams), @CKM_AES_KEY_WRAP@/
@KEY_WRAP_PAD@/@KEY_WRAP_KWP@ take empty parameters on the 8-byte
wrap quantum (KW: multiple-of-8 input >= 16; KWP: any length >= 1;
output expands by the wrap framing), @CKM_AES_XTS@ takes the
16-byte tweak like a CBC IV on double-width keys (data units
>= 16 bytes, any length above), and the CBC_PAD rows
(@CKM_AES_CBC_PAD@, @CKM_ARIA_CBC_PAD@, @CKM_CAMELLIA_CBC_PAD@,
@CKM_DES3_CBC_PAD@) add PKCS#7 framing (decided in the pure
planner, never the backend). 'Haskoki.Recipe.Cipher' owns the group's canonical
codecs, parameter validation, block/key/IV geometry, and mechanism
table; these tests pin the recipe and its three consumers:

* the model init path enforces per-mechanism cipher parameters
  ('validateInit', 'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, key length, params)
  triple to its backend 'CipherSpec' ('cipherSpecFor' agrees with
  the recipe table);
* engine key/IV geometry agrees with the recipe ('cipherKeyLen' /
  'cipherIvLen' laws; executed against the synthetic backend in
  SyntheticSpec, against libcrypto KATs in OpenSSLSpec).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeCipherSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend
  ( CipherSpec
    ( C_AES128_CBC
    , C_AES128_CTR
    , C_AES128_CTS
    , C_AES128_CFB1
    , C_AES128_CFB128
    , C_AES128_CFB8
    , C_AES128_ECB
    , C_AES128_KW
    , C_AES128_KWP
    , C_AES128_OFB
    , C_AES128_XTS
    , C_AES192_CBC
    , C_AES192_CTR
    , C_AES192_CTS
    , C_AES192_CFB1
    , C_AES192_CFB128
    , C_AES192_CFB8
    , C_AES192_KW
    , C_AES192_KWP
    , C_AES192_OFB
    , C_AES256_CBC
    , C_AES256_CTR
    , C_AES256_CTS
    , C_AES256_CFB1
    , C_AES256_CFB128
    , C_AES256_CFB8
    , C_AES256_KW
    , C_AES256_KWP
    , C_AES256_OFB
    , C_AES256_XTS
    , C_AES256_ECB
    , C_ARIA256_CBC
    , C_BLOWFISH_CBC
    , C_CAMELLIA128_CBC
    , C_CAMELLIA128_CTR
    , C_CAMELLIA128_ECB
    , C_CAMELLIA192_CTR
    , C_CAMELLIA256_CTR
    , C_CAST128_CBC
    , C_CAST128_ECB
    , C_CAST_CBC
    , C_CAST_ECB
    , C_CAST3_CBC
    , C_CAST3_ECB
    , C_DES3_CBC
    , C_DES_CBC
    , C_DES_CFB64
    , C_DES_CFB8
    , C_DES_ECB
    , C_DES_OFB64
    , C_IDEA_CBC
    , C_IDEA_ECB
    , C_RC2_CBC
    , C_RC2_ECB
    , C_RC4
    , C_SEED_CBC
    , C_SEED_ECB
    )
  , cipherIvLen
  , cipherKeyLens
  )
import Haskoki.Engine.Driver (cipherSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( CipherSpec (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Operation.Codec (cipherShapeFor)
import Haskoki.Recipe.Cipher
  ( BlockCipherRecipe (..)
  , cipherCodecFor
  , cipherKwPkcs7Codec
  , cipherCtrCodec
  , cipherIvCodec
  , cipherKeyLenValid
  , cipherParamsValid
  , cipherPlainCodec
  , cipherRc2Codec
  , cipherRecipeFor
  , cipherRecipes
  , ctrNextImage
  , decodeCtrParams
  , decodeRc2Params
  , encodeCtrParams
  , encodeRc2CbcParams
  , encodeRc2EcbParams
  )
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , ParameterCodec (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Registry.Generated
  ( mustGeneratedId
  , ckm_AES_CBC
  , ckm_AES_CFB1
  , ckm_AES_CFB128
  , ckm_AES_CFB8
  , ckm_AES_CTR
  , ckm_AES_CTS
  , ckm_AES_ECB
  , ckm_AES_KEY_WRAP
  , ckm_AES_KEY_WRAP_KWP
  , ckm_AES_KEY_WRAP_PAD
  , ckm_AES_KEY_WRAP_PKCS7
  , ckm_AES_OFB
  , ckm_AES_XTS
  , ckm_ARIA_CBC_PAD
  , ckm_CAMELLIA_CBC_PAD
  , ckm_CAMELLIA_CTR
  , ckm_DES3_CBC
  , ckm_DES3_CBC_PAD
  , ckm_DES_ECB
  , ckm_DES_CBC
  , ckm_DES_CBC_PAD
  , ckm_DES_OFB64
  , ckm_DES_CFB64
  , ckm_DES_CFB8
  , ckm_RC2_ECB
  , ckm_RC2_CBC
  , ckm_RC2_CBC_PAD
  , ckm_RC4
  , ckm_CAST128_ECB
  , ckm_CAST128_CBC
  , ckm_CAST128_CBC_PAD
  , ckm_CAST_ECB
  , ckm_CAST_CBC
  , ckm_CAST_CBC_PAD
  , ckm_CAST3_ECB
  , ckm_CAST3_CBC
  , ckm_CAST3_CBC_PAD
  , ckm_IDEA_ECB
  , ckm_IDEA_CBC
  , ckm_IDEA_CBC_PAD
  , ckm_SEED_ECB
  , ckm_SEED_CBC
  , ckm_SEED_CBC_PAD
  , ckm_BLOWFISH_CBC
  , ckm_BLOWFISH_CBC_PAD
  , ckm_SHA256
  , ckm_SHA256_HMAC
  )
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
spec = testGroup "Block-cipher recipe"
  [ testCase "recipe table covers 50 mechanisms with geometry" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "ECB is no-params/1, CBC is iv-bytes/1" caseCodec
  , testCase "params: IV length or empty-only" caseParams
  , testCase "RC2 struct params: bits range + shape per row" caseRc2Params
  , testCase "key lengths: AES-family 16/24/32, DES3 16/24, XTS 32/64" caseKeyLens
  , testCase "init enforces per-mechanism cipher params" caseInitParams
  , testCase "driver maps every triple to its CipherSpec" caseDriverMap
  , testCase "engine geometry agrees with the recipe" caseGeometryLaw
  , testCase "legacy rows resolve their operation shapes" caseLegacyShapes
  ]

-- | (Name suffix, block bytes, key lengths, IV bytes, padded).
groupShape :: [(Text, Int, [Int], Int, Bool)]
groupShape =
  [ ("AES_CBC", 16, [16, 24, 32], 16, False)
  , ("AES_CBC_PAD", 16, [16, 24, 32], 16, True)
  , ("AES_ECB", 16, [16, 24, 32], 0, False)
  , ("AES_CTR", 16, [16, 24, 32], 16, False)
  , ("AES_CTS", 16, [16, 24, 32], 16, False)
  , ("AES_CFB128", 16, [16, 24, 32], 16, False)
  , ("AES_CFB8", 16, [16, 24, 32], 16, False)
  , ("AES_CFB1", 16, [16, 24, 32], 16, False)
  , ("AES_OFB", 16, [16, 24, 32], 16, False)
  , ("AES_KEY_WRAP", 8, [16, 24, 32], 0, False)
  , ("AES_KEY_WRAP_PAD", 8, [16, 24, 32], 0, False)
  , ("AES_KEY_WRAP_KWP", 8, [16, 24, 32], 0, False)
  , ("AES_KEY_WRAP_PKCS7", 8, [16, 24, 32], 0, True)
  , ("AES_XTS", 16, [32, 64], 16, False)
  , ("DES3_CBC", 8, [16, 24], 8, False)
  , ("DES3_ECB", 8, [16, 24], 0, False)
  , ("ARIA_CBC", 16, [16, 24, 32], 16, False)
  , ("ARIA_ECB", 16, [16, 24, 32], 0, False)
  , ("CAMELLIA_CBC", 16, [16, 24, 32], 16, False)
  , ("CAMELLIA_ECB", 16, [16, 24, 32], 0, False)
  , ("ARIA_CBC_PAD", 16, [16, 24, 32], 16, True)
  , ("CAMELLIA_CBC_PAD", 16, [16, 24, 32], 16, True)
  , ("DES3_CBC_PAD", 8, [16, 24], 8, True)
  , ("CAMELLIA_CTR", 16, [16, 24, 32], 16, False)
  , ("DES_ECB", 8, [8], 0, False)
  , ("DES_CBC", 8, [8], 8, False)
  , ("DES_CBC_PAD", 8, [8], 8, True)
  , ("DES_OFB64", 8, [8], 8, False)
  , ("DES_CFB64", 8, [8], 8, False)
  , ("DES_CFB8", 8, [8], 8, False)
  , ("CAST128_ECB", 8, [1 .. 16], 0, False)
  , ("CAST128_CBC", 8, [1 .. 16], 8, False)
  , ("CAST128_CBC_PAD", 8, [1 .. 16], 8, True)
  , ("CAST_ECB", 8, [5], 0, False)
  , ("CAST_CBC", 8, [5], 8, False)
  , ("CAST_CBC_PAD", 8, [5], 8, True)
  , ("CAST3_ECB", 8, [10], 0, False)
  , ("CAST3_CBC", 8, [10], 8, False)
  , ("CAST3_CBC_PAD", 8, [10], 8, True)
  , ("IDEA_ECB", 8, [16], 0, False)
  , ("IDEA_CBC", 8, [16], 8, False)
  , ("IDEA_CBC_PAD", 8, [16], 8, True)
  , ("SEED_ECB", 16, [16], 0, False)
  , ("SEED_CBC", 16, [16], 16, False)
  , ("SEED_CBC_PAD", 16, [16], 16, True)
  , ("BLOWFISH_CBC", 8, [4 .. 56], 8, False)
  , ("BLOWFISH_CBC_PAD", 8, [4 .. 56], 8, True)
  , ("RC2_ECB", 8, [1 .. 128], 0, False)
  , ("RC2_CBC", 8, [1 .. 128], 8, False)
  , ("RC2_CBC_PAD", 8, [1 .. 128], 8, True)
  , ("RC4", 1, [1 .. 255], 0, False)
  ]

-- | Valid mechanism parameters per row: the CTR rows take the
-- canonical image (128-bit width over a zero block), every other
-- row the zero IV of its length.
validParams :: Text -> Int -> BS.ByteString
validParams suffix iv
  | suffix `elem` (["AES_CTR", "CAMELLIA_CTR"] :: [Text]) =
      encodeCtrParams 128 (BS.replicate 16 0)
  | suffix == "RC2_ECB" = encodeRc2EcbParams 128
  | suffix `elem` (["RC2_CBC", "RC2_CBC_PAD"] :: [Text]) =
      encodeRc2CbcParams 128 (BS.replicate 8 0)
  | otherwise = BS.replicate iv 0

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 51 (length cipherRecipes)
  mapM_ (\(suffix, block, keys, iv, pad) -> do
    let name = mechName suffix
        found = [ r | r <- cipherRecipes, crName r == name ]
    case found of
      [r] -> do
        assertEqual ("block " ++ T.unpack name) block (crBlockBytes r)
        assertEqual ("keys " ++ T.unpack name) keys (crKeyLens r)
        assertEqual ("iv " ++ T.unpack name) iv (crIvBytes r)
        assertEqual ("pad " ++ T.unpack name) pad (crPad r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _, _, _, _) -> do
    let name = mechName suffix
    case cipherRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (hrName' r)
    ) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (cipherRecipeFor (MechanismId 0x4712))
  assertEqual "digest mech has no cipher recipe" Nothing
    (cipherRecipeFor (MechanismId (ckm_SHA256)))
  assertEqual "HMAC has no cipher recipe" Nothing
    (cipherRecipeFor (MechanismId (ckm_SHA256_HMAC)))
  where
    hrName' = crName

caseCodec :: IO ()
caseCodec = do
  assertEqual "plain codec" (ParameterCodec "no-params" 1) cipherPlainCodec
  assertEqual "iv codec" (ParameterCodec "iv-bytes" 1) cipherIvCodec
  assertEqual "ctr codec" (ParameterCodec "ctr-params" 1) cipherCtrCodec
  assertEqual "rc2 codec" (ParameterCodec "rc2-params" 1) cipherRc2Codec
  mapM_ (\(suffix, _, _, iv, _) -> do
    let name = mechName suffix
        want
          | suffix `elem` (["AES_CTR", "CAMELLIA_CTR"] :: [Text]) = cipherCtrCodec
          | suffix `elem` (["RC2_ECB", "RC2_CBC", "RC2_CBC_PAD"] :: [Text]) = cipherRc2Codec
          | suffix == "AES_KEY_WRAP_PKCS7" = cipherKwPkcs7Codec
          | iv == 0 = cipherPlainCodec
          | otherwise = cipherIvCodec
    case cipherRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("codec " ++ T.unpack name) want (cipherCodecFor r)
    ) groupShape

recipeOf :: Text -> BlockCipherRecipe
recipeOf name =
  case cipherRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

caseParams :: IO ()
caseParams = do
  let cbc = recipeOf "CKM_AES_CBC"
  assertBool "cbc 16 valid" (cipherParamsValid cbc (BS.replicate 16 0))
  assertBool "cbc empty refused" (not (cipherParamsValid cbc BS.empty))
  assertBool "cbc 8 refused" (not (cipherParamsValid cbc (BS.replicate 8 0)))
  assertBool "cbc 17 refused" (not (cipherParamsValid cbc (BS.replicate 17 0)))
  let pad = recipeOf "CKM_AES_CBC_PAD"
  assertBool "pad 16 valid" (cipherParamsValid pad (BS.replicate 16 0))
  assertBool "pad empty refused" (not (cipherParamsValid pad BS.empty))
  let ecb = recipeOf "CKM_AES_ECB"
  assertBool "ecb empty valid" (cipherParamsValid ecb BS.empty)
  assertBool "ecb 16 refused" (not (cipherParamsValid ecb (BS.replicate 16 0)))
  let cts = recipeOf "CKM_AES_CTS"
  assertBool "cts 16 valid" (cipherParamsValid cts (BS.replicate 16 0))
  assertBool "cts empty refused" (not (cipherParamsValid cts BS.empty))
  assertBool "cts 8 refused" (not (cipherParamsValid cts (BS.replicate 8 0)))
  assertBool "cts 17 refused" (not (cipherParamsValid cts (BS.replicate 17 0)))
  let cfb128 = recipeOf "CKM_AES_CFB128"
  assertBool "cfb128 16 valid" (cipherParamsValid cfb128 (BS.replicate 16 0))
  assertBool "cfb128 empty refused" (not (cipherParamsValid cfb128 BS.empty))
  assertBool "cfb128 8 refused" (not (cipherParamsValid cfb128 (BS.replicate 8 0)))
  assertBool "cfb128 17 refused" (not (cipherParamsValid cfb128 (BS.replicate 17 0)))
  let cfb8 = recipeOf "CKM_AES_CFB8"
  assertBool "cfb8 16 valid" (cipherParamsValid cfb8 (BS.replicate 16 0))
  assertBool "cfb8 empty refused" (not (cipherParamsValid cfb8 BS.empty))
  let cfb1 = recipeOf "CKM_AES_CFB1"
  assertBool "cfb1 16 valid" (cipherParamsValid cfb1 (BS.replicate 16 0))
  assertBool "cfb1 empty refused" (not (cipherParamsValid cfb1 BS.empty))
  let ofb = recipeOf "CKM_AES_OFB"
  assertBool "ofb 16 valid" (cipherParamsValid ofb (BS.replicate 16 0))
  assertBool "ofb empty refused" (not (cipherParamsValid ofb BS.empty))
  assertBool "ofb 8 refused" (not (cipherParamsValid ofb (BS.replicate 8 0)))
  assertBool "ofb 17 refused" (not (cipherParamsValid ofb (BS.replicate 17 0)))
  let kw = recipeOf "CKM_AES_KEY_WRAP"
  assertBool "kw empty valid" (cipherParamsValid kw BS.empty)
  assertBool "kw 16 refused" (not (cipherParamsValid kw (BS.replicate 16 0)))
  assertBool "kw 8 refused" (not (cipherParamsValid kw (BS.replicate 8 0)))
  let kwp = recipeOf "CKM_AES_KEY_WRAP_KWP"
  assertBool "kwp empty valid" (cipherParamsValid kwp BS.empty)
  assertBool "kwp 16 refused" (not (cipherParamsValid kwp (BS.replicate 16 0)))
  let kwpad = recipeOf "CKM_AES_KEY_WRAP_PAD"
  assertBool "kwpad empty valid" (cipherParamsValid kwpad BS.empty)
  assertBool "kwpad 16 refused" (not (cipherParamsValid kwpad (BS.replicate 16 0)))
  let kwp7 = recipeOf "CKM_AES_KEY_WRAP_PKCS7"
  assertBool "kwpkcs7 empty valid" (cipherParamsValid kwp7 BS.empty)
  assertBool "kwpkcs7 8 valid" (cipherParamsValid kwp7 (BS.replicate 8 0))
  assertBool "kwpkcs7 4 refused" (not (cipherParamsValid kwp7 (BS.replicate 4 0)))
  assertBool "kwpkcs7 16 refused" (not (cipherParamsValid kwp7 (BS.replicate 16 0)))
  let xts = recipeOf "CKM_AES_XTS"
  assertBool "xts tweak 16 valid" (cipherParamsValid xts (BS.replicate 16 0))
  assertBool "xts empty refused" (not (cipherParamsValid xts BS.empty))
  assertBool "xts 8 refused" (not (cipherParamsValid xts (BS.replicate 8 0)))
  assertBool "xts 17 refused" (not (cipherParamsValid xts (BS.replicate 17 0)))
  let d3 = recipeOf "CKM_DES3_CBC"
  assertBool "des3 8 valid" (cipherParamsValid d3 (BS.replicate 8 0))
  assertBool "des3 16 refused" (not (cipherParamsValid d3 (BS.replicate 16 0)))
  assertBool "des3 empty refused" (not (cipherParamsValid d3 BS.empty))
  let d3e = recipeOf "CKM_DES3_ECB"
  assertBool "des3-ecb empty valid" (cipherParamsValid d3e BS.empty)
  assertBool "des3-ecb 8 refused"
    (not (cipherParamsValid d3e (BS.replicate 8 0)))
  let ctr = recipeOf "CKM_AES_CTR"
      ctrGood = encodeCtrParams 128 (BS.replicate 16 0xcb)
  assertBool "ctr 128-bit image valid" (cipherParamsValid ctr ctrGood)
  assertEqual "ctr image roundtrips" (Just (128, BS.replicate 16 0xcb))
    (decodeCtrParams ctrGood)
  assertBool "ctr 64-bit refused"
    (not (cipherParamsValid ctr (encodeCtrParams 64 (BS.replicate 16 0))))
  assertBool "ctr zero-width refused"
    (not (cipherParamsValid ctr (encodeCtrParams 0 (BS.replicate 16 0))))
  assertBool "ctr short block refused"
    (not (cipherParamsValid ctr (encodeCtrParams 128 (BS.replicate 15 0))))
  assertBool "ctr truncated refused"
    (not (cipherParamsValid ctr (BS.replicate 20 0)))
  assertBool "ctr raw iv refused"
    (not (cipherParamsValid ctr (BS.replicate 16 0)))
  let ariaPad = recipeOf "CKM_ARIA_CBC_PAD"
  assertBool "aria-pad 16 valid" (cipherParamsValid ariaPad (BS.replicate 16 0))
  assertBool "aria-pad empty refused" (not (cipherParamsValid ariaPad BS.empty))
  assertBool "aria-pad 8 refused"
    (not (cipherParamsValid ariaPad (BS.replicate 8 0)))
  let camPad = recipeOf "CKM_CAMELLIA_CBC_PAD"
  assertBool "camellia-pad 16 valid" (cipherParamsValid camPad (BS.replicate 16 0))
  assertBool "camellia-pad empty refused" (not (cipherParamsValid camPad BS.empty))
  let d3Pad = recipeOf "CKM_DES3_CBC_PAD"
  assertBool "des3-pad 8 valid" (cipherParamsValid d3Pad (BS.replicate 8 0))
  assertBool "des3-pad 16 refused"
    (not (cipherParamsValid d3Pad (BS.replicate 16 0)))
  assertBool "des3-pad empty refused" (not (cipherParamsValid d3Pad BS.empty))
  let camCtr = recipeOf "CKM_CAMELLIA_CTR"
      camCtrGood = encodeCtrParams 128 (BS.replicate 16 0xcb)
  assertBool "camellia-ctr 128-bit image valid"
    (cipherParamsValid camCtr camCtrGood)
  assertBool "camellia-ctr 64-bit refused"
    (not (cipherParamsValid camCtr (encodeCtrParams 64 (BS.replicate 16 0))))
  assertBool "camellia-ctr raw iv refused"
    (not (cipherParamsValid camCtr (BS.replicate 16 0)))
  -- Counter advance: big-endian block steps with carry and wrap.
  let cb0 = BS.replicate 16 0
      img0 = encodeCtrParams 128 cb0
  assertEqual "advance zero" (Just img0) (ctrNextImage img0 0)
  assertEqual "advance one" (Just (encodeCtrParams 128 (BS.replicate 15 0 <> BS.singleton 1)))
    (ctrNextImage img0 1)
  assertEqual "advance carries" (Just (encodeCtrParams 128 (BS.replicate 14 0 <> BS.pack [1, 0])))
    (ctrNextImage img0 256)
  assertEqual "advance wraps"
    (Just img0)
    (ctrNextImage (encodeCtrParams 128 (BS.replicate 16 0xff)) 1)
  assertEqual "advance refuses non-image" Nothing
    (ctrNextImage (encodeCtrParams 64 cb0) 1)
  assertEqual "advance refuses negative" Nothing (ctrNextImage img0 (-1))
  -- Every row enforces its own IV geometry across the table.
  mapM_ (\(suffix, _, _, iv, _) -> do
    let r = recipeOf (mechName suffix)
    assertBool ("params ok " ++ T.unpack suffix)
      (cipherParamsValid r (validParams suffix iv))
    assertBool ("iv+1 refused " ++ T.unpack suffix)
      (not (cipherParamsValid r (BS.replicate (iv + 1) 0)))
    ) groupShape

caseRc2Params :: IO ()
caseRc2Params = do
  let ecb = recipeOf "CKM_RC2_ECB"
      cbc = recipeOf "CKM_RC2_CBC"
      pad = recipeOf "CKM_RC2_CBC_PAD"
      iv0 = BS.replicate 8 0
  assertEqual "ecb image roundtrips" (Just (128, BS.empty))
    (decodeRc2Params (encodeRc2EcbParams 128))
  assertEqual "cbc image roundtrips" (Just (128, iv0))
    (decodeRc2Params (encodeRc2CbcParams 128 iv0))
  assertBool "ecb 128 valid"
    (cipherParamsValid ecb (encodeRc2EcbParams 128))
  assertBool "cbc 128 valid"
    (cipherParamsValid cbc (encodeRc2CbcParams 128 iv0))
  assertBool "pad 40 valid"
    (cipherParamsValid pad (encodeRc2CbcParams 40 iv0))
  assertBool "ecb bits 0 refused"
    (not (cipherParamsValid ecb (encodeRc2EcbParams 0)))
  assertBool "cbc bits 0 refused"
    (not (cipherParamsValid cbc (encodeRc2CbcParams 0 iv0)))
  assertBool "cbc bits 1025 refused"
    (not (cipherParamsValid cbc (encodeRc2CbcParams 1025 iv0)))
  assertBool "ecb cbc-image refused"
    (not (cipherParamsValid ecb (encodeRc2CbcParams 128 iv0)))
  assertBool "cbc ecb-image refused"
    (not (cipherParamsValid cbc (encodeRc2EcbParams 128)))
  assertBool "cbc truncated refused"
    (not (cipherParamsValid cbc (BS.replicate 12 0)))
  assertBool "cbc raw iv refused"
    (not (cipherParamsValid cbc iv0))
  assertBool "ecb empty refused"
    (not (cipherParamsValid ecb BS.empty))

caseKeyLens :: IO ()
caseKeyLens = do
  let aes = recipeOf "CKM_AES_CBC"
  mapM_ (\n -> assertBool ("aes key " ++ show n) (cipherKeyLenValid aes n))
    [16, 24, 32]
  mapM_ (\n -> assertBool ("aes key refused " ++ show n)
    (not (cipherKeyLenValid aes n))) [0, 8, 15, 17, 31, 33, 64]
  let d3 = recipeOf "CKM_DES3_CBC"
  mapM_ (\n -> assertBool ("des3 key " ++ show n) (cipherKeyLenValid d3 n))
    [16, 24]
  mapM_ (\n -> assertBool ("des3 key refused " ++ show n)
    (not (cipherKeyLenValid d3 n))) [0, 8, 15, 17, 23, 25, 32]
  let xts = recipeOf "CKM_AES_XTS"
  mapM_ (\n -> assertBool ("xts key " ++ show n) (cipherKeyLenValid xts n))
    [32, 64]
  mapM_ (\n -> assertBool ("xts key refused " ++ show n)
    (not (cipherKeyLenValid xts n))) [0, 16, 24, 31, 33, 48, 63, 65]
  let rc2 = recipeOf "CKM_RC2_CBC"
  mapM_ (\n -> assertBool ("rc2 key " ++ show n) (cipherKeyLenValid rc2 n))
    [1, 5, 16, 128]
  mapM_ (\n -> assertBool ("rc2 key refused " ++ show n)
    (not (cipherKeyLenValid rc2 n))) [0, 129, 256]
  let rc4 = recipeOf "CKM_RC4"
  mapM_ (\n -> assertBool ("rc4 key " ++ show n) (cipherKeyLenValid rc4 n))
    [1, 5, 16, 255]
  mapM_ (\n -> assertBool ("rc4 key refused " ++ show n)
    (not (cipherKeyLenValid rc4 n))) [0, 256]
  let bf = recipeOf "CKM_BLOWFISH_CBC"
  mapM_ (\n -> assertBool ("bf key " ++ show n) (cipherKeyLenValid bf n))
    [4, 16, 56]
  mapM_ (\n -> assertBool ("bf key refused " ++ show n)
    (not (cipherKeyLenValid bf n))) [0, 3, 57]
  let c5 = recipeOf "CKM_CAST128_CBC"
  mapM_ (\n -> assertBool ("cast128 key " ++ show n) (cipherKeyLenValid c5 n))
    [1, 5, 16]
  mapM_ (\n -> assertBool ("cast128 key refused " ++ show n)
    (not (cipherKeyLenValid c5 n))) [0, 17]
  let c40 = recipeOf "CKM_CAST_CBC"
  mapM_ (\n -> assertBool ("cast key " ++ show n) (cipherKeyLenValid c40 n))
    [5]
  mapM_ (\n -> assertBool ("cast key refused " ++ show n)
    (not (cipherKeyLenValid c40 n))) [0, 4, 6, 10, 16]
  let c80 = recipeOf "CKM_CAST3_CBC"
  mapM_ (\n -> assertBool ("cast3 key " ++ show n) (cipherKeyLenValid c80 n))
    [10]
  mapM_ (\n -> assertBool ("cast3 key refused " ++ show n)
    (not (cipherKeyLenValid c80 n))) [0, 5, 9, 11, 16]
  mapM_ (\(suffix, _, keys, _, _) -> do
    let r = recipeOf (mechName suffix)
    mapM_ (\n -> assertBool ("key ok " ++ T.unpack suffix ++ "/" ++ show n)
      (cipherKeyLenValid r n)) keys
    ) groupShape

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

cbcMech, ecbMech, d3Mech, ctrMech, ctsMech, cfb128Mech, cfb8Mech, cfb1Mech, ofbMech, kwMech, kwPadMech, kwpMech, xtsMech, ariaPadMech, camPadMech, d3PadMech, camCtrMech :: MechanismId
cbcMech = MechanismId (ckm_AES_CBC)
ecbMech = MechanismId (ckm_AES_ECB)
d3Mech = MechanismId (ckm_DES3_CBC)
ariaPadMech = MechanismId (ckm_ARIA_CBC_PAD)
camPadMech = MechanismId (ckm_CAMELLIA_CBC_PAD)
d3PadMech = MechanismId (ckm_DES3_CBC_PAD)
camCtrMech = MechanismId (ckm_CAMELLIA_CTR)
ctrMech = MechanismId (ckm_AES_CTR)
ctsMech = MechanismId (ckm_AES_CTS)
cfb128Mech = MechanismId (ckm_AES_CFB128)
cfb8Mech = MechanismId (ckm_AES_CFB8)
cfb1Mech = MechanismId (ckm_AES_CFB1)
ofbMech = MechanismId (ckm_AES_OFB)
kwMech = MechanismId (ckm_AES_KEY_WRAP)
kwPadMech = MechanismId (ckm_AES_KEY_WRAP_PAD)
kwpMech = MechanismId (ckm_AES_KEY_WRAP_KWP)
kwp7Mech :: MechanismId
kwp7Mech = MechanismId (ckm_AES_KEY_WRAP_PKCS7)
xtsMech = MechanismId (ckm_AES_XTS)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities
      [ (cbcMech, OpEncrypt), (ecbMech, OpEncrypt), (d3Mech, OpEncrypt)
      , (ctrMech, OpEncrypt), (ctsMech, OpEncrypt)
      , (cfb128Mech, OpEncrypt), (cfb8Mech, OpEncrypt)
      , (cfb1Mech, OpEncrypt), (ofbMech, OpEncrypt)
      , (kwMech, OpEncrypt), (kwPadMech, OpEncrypt), (kwpMech, OpEncrypt)
      , (kwp7Mech, OpEncrypt)
      , (xtsMech, OpEncrypt)
      , (ariaPadMech, OpEncrypt), (camPadMech, OpEncrypt)
      , (d3PadMech, OpEncrypt), (camCtrMech, OpEncrypt)
      ]
  , oeModel = emptyModel
  }

-- | Unknown handle: valid parameters proceed PAST the parameter check
-- to key resolution (proving acceptance); bad parameters stop at
-- 'CKR_ARGUMENTS_BAD'.
badKey :: KeyPolicy
badKey = KeyPolicy (ExternalHandle 999) [OpEncrypt] False

runInit :: InitArgs -> ReturnCode
runInit args = ioCode (snd (initOperation testEnv emptySessionOps testSession args))

-- | Valid parameters proceed PAST the parameter check (which runs
-- before key binding): with a well-formed cipher spec they reach key
-- resolution ('CKR_OBJECT_HANDLE_INVALID' for the unknown handle).
mkArgs :: MechanismId -> BS.ByteString -> InitArgs
mkArgs mech params = InitArgs OpEncrypt mech params (Just badKey)
  (Just (CipherSpec 16 False)) Nothing

caseInitParams :: IO ()
caseInitParams = do
  assertEqual "cbc ragged iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs cbcMech (BS.replicate 8 0)))
  assertEqual "cbc empty iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs cbcMech BS.empty))
  assertEqual "cbc valid iv passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs cbcMech (BS.replicate 16 0)))
  assertEqual "ecb iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs ecbMech (BS.replicate 16 0)))
  assertEqual "ecb empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs ecbMech BS.empty))
  assertEqual "des3 16-byte iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs d3Mech (BS.replicate 16 0)))
  assertEqual "des3 8-byte iv passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs d3Mech (BS.replicate 8 0)))
  assertEqual "ctr 128-bit image passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs ctrMech (encodeCtrParams 128 (BS.replicate 16 0))))
  assertEqual "ctr 64-bit refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs ctrMech (encodeCtrParams 64 (BS.replicate 16 0))))
  assertEqual "ctr raw iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs ctrMech (BS.replicate 16 0)))
  assertEqual "cts ragged iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs ctsMech (BS.replicate 8 0)))
  assertEqual "cts empty iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs ctsMech BS.empty))
  assertEqual "cts valid iv passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs ctsMech (BS.replicate 16 0)))
  assertEqual "cfb128 ragged iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs cfb128Mech (BS.replicate 8 0)))
  assertEqual "cfb128 valid iv passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs cfb128Mech (BS.replicate 16 0)))
  assertEqual "cfb8 valid iv passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs cfb8Mech (BS.replicate 16 0)))
  assertEqual "cfb1 valid iv passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs cfb1Mech (BS.replicate 16 0)))
  assertEqual "ofb ragged iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs ofbMech (BS.replicate 8 0)))
  assertEqual "ofb valid iv passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs ofbMech (BS.replicate 16 0)))
  assertEqual "kw iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs kwMech (BS.replicate 16 0)))
  assertEqual "kw empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs kwMech BS.empty))
  assertEqual "kwpad iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs kwPadMech (BS.replicate 8 0)))
  assertEqual "kwpad empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs kwPadMech BS.empty))
  assertEqual "kwp iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs kwpMech (BS.replicate 16 0)))
  assertEqual "kwp empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs kwpMech BS.empty))
  assertEqual "kwpkcs7 4-byte iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs kwp7Mech (BS.replicate 4 0)))
  assertEqual "kwpkcs7 16-byte iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs kwp7Mech (BS.replicate 16 0)))
  assertEqual "kwpkcs7 empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs kwp7Mech BS.empty))
  assertEqual "kwpkcs7 8-byte iv passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs kwp7Mech (BS.replicate 8 0)))
  assertEqual "xts ragged tweak refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs xtsMech (BS.replicate 8 0)))
  assertEqual "xts empty refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs xtsMech BS.empty))
  assertEqual "xts valid tweak passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs xtsMech (BS.replicate 16 0)))
  assertEqual "aria-pad ragged iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs ariaPadMech (BS.replicate 8 0)))
  assertEqual "aria-pad valid iv passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs ariaPadMech (BS.replicate 16 0)))
  assertEqual "camellia-pad empty refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs camPadMech BS.empty))
  assertEqual "camellia-pad valid iv passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs camPadMech (BS.replicate 16 0)))
  assertEqual "des3-pad 16-byte iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs d3PadMech (BS.replicate 16 0)))
  assertEqual "des3-pad 8-byte iv passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs d3PadMech (BS.replicate 8 0)))
  assertEqual "camellia-ctr 128-bit image passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs camCtrMech (encodeCtrParams 128 (BS.replicate 16 0))))
  assertEqual "camellia-ctr 64-bit refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs camCtrMech (encodeCtrParams 64 (BS.replicate 16 0))))
  assertEqual "camellia-ctr raw iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs camCtrMech (BS.replicate 16 0)))

caseDriverMap :: IO ()
caseDriverMap = do
  let iv16 = BS.replicate 16 0
      iv8 = BS.replicate 8 0
  -- AES-CBC across key sizes.
  assertEqual "aes-cbc-128" (Just C_AES128_CBC)
    (cipherSpecFor cbcMech 16 iv16)
  assertEqual "aes-cbc-192" (Just C_AES192_CBC)
    (cipherSpecFor cbcMech 24 iv16)
  assertEqual "aes-cbc-256" (Just C_AES256_CBC)
    (cipherSpecFor cbcMech 32 iv16)
  assertEqual "aes-cbc rejects bad keylen" Nothing
    (cipherSpecFor cbcMech 15 iv16)
  assertEqual "aes-cbc rejects bad iv" Nothing
    (cipherSpecFor cbcMech 16 iv8)
  -- AES-ECB: empty params only.
  assertEqual "aes-ecb-256" (Just C_AES256_ECB)
    (cipherSpecFor ecbMech 32 BS.empty)
  assertEqual "aes-ecb-128" (Just C_AES128_ECB)
    (cipherSpecFor ecbMech 16 BS.empty)
  assertEqual "aes-ecb rejects iv" Nothing
    (cipherSpecFor ecbMech 32 iv16)
  -- Triple-DES: 16/24-byte keys, 8-byte IV.
  assertEqual "des3-cbc-24" (Just C_DES3_CBC)
    (cipherSpecFor d3Mech 24 iv8)
  assertEqual "des3-cbc-16" (Just C_DES3_CBC)
    (cipherSpecFor d3Mech 16 iv8)
  assertEqual "des3-cbc rejects 32" Nothing
    (cipherSpecFor d3Mech 32 iv8)
  assertEqual "des3-cbc rejects 16-iv" Nothing
    (cipherSpecFor d3Mech 24 iv16)
  -- AES-CTR: the canonical image maps each width; off-width and
  -- raw-IV parameters refuse.
  let ctrGood = encodeCtrParams 128 iv16
  assertEqual "aes-ctr-128" (Just C_AES128_CTR)
    (cipherSpecFor ctrMech 16 ctrGood)
  assertEqual "aes-ctr-192" (Just C_AES192_CTR)
    (cipherSpecFor ctrMech 24 ctrGood)
  assertEqual "aes-ctr-256" (Just C_AES256_CTR)
    (cipherSpecFor ctrMech 32 ctrGood)
  assertEqual "aes-ctr rejects bad keylen" Nothing
    (cipherSpecFor ctrMech 15 ctrGood)
  assertEqual "aes-ctr rejects 64-bit" Nothing
    (cipherSpecFor ctrMech 16 (encodeCtrParams 64 iv16))
  assertEqual "aes-ctr rejects raw iv" Nothing
    (cipherSpecFor ctrMech 16 iv16)
  -- AES-CTS: raw IV, three widths, same refusals as CBC.
  assertEqual "aes-cts-128" (Just C_AES128_CTS)
    (cipherSpecFor ctsMech 16 iv16)
  assertEqual "aes-cts-192" (Just C_AES192_CTS)
    (cipherSpecFor ctsMech 24 iv16)
  assertEqual "aes-cts-256" (Just C_AES256_CTS)
    (cipherSpecFor ctsMech 32 iv16)
  assertEqual "aes-cts rejects bad keylen" Nothing
    (cipherSpecFor ctsMech 15 iv16)
  assertEqual "aes-cts rejects bad iv" Nothing
    (cipherSpecFor ctsMech 16 iv8)
  -- AES-CFB128: raw IV, three widths, same refusals as CBC.
  assertEqual "aes-cfb128-128" (Just C_AES128_CFB128)
    (cipherSpecFor cfb128Mech 16 iv16)
  assertEqual "aes-cfb128-192" (Just C_AES192_CFB128)
    (cipherSpecFor cfb128Mech 24 iv16)
  assertEqual "aes-cfb128-256" (Just C_AES256_CFB128)
    (cipherSpecFor cfb128Mech 32 iv16)
  assertEqual "aes-cfb128 rejects bad keylen" Nothing
    (cipherSpecFor cfb128Mech 15 iv16)
  assertEqual "aes-cfb128 rejects bad iv" Nothing
    (cipherSpecFor cfb128Mech 16 iv8)
  assertEqual "aes-cfb8-128" (Just C_AES128_CFB8)
    (cipherSpecFor cfb8Mech 16 iv16)
  assertEqual "aes-cfb8-192" (Just C_AES192_CFB8)
    (cipherSpecFor cfb8Mech 24 iv16)
  assertEqual "aes-cfb8-256" (Just C_AES256_CFB8)
    (cipherSpecFor cfb8Mech 32 iv16)
  assertEqual "aes-cfb8 rejects bad keylen" Nothing
    (cipherSpecFor cfb8Mech 15 iv16)
  assertEqual "aes-cfb1-128" (Just C_AES128_CFB1)
    (cipherSpecFor cfb1Mech 16 iv16)
  assertEqual "aes-cfb1-192" (Just C_AES192_CFB1)
    (cipherSpecFor cfb1Mech 24 iv16)
  assertEqual "aes-cfb1-256" (Just C_AES256_CFB1)
    (cipherSpecFor cfb1Mech 32 iv16)
  assertEqual "aes-cfb1 rejects bad keylen" Nothing
    (cipherSpecFor cfb1Mech 15 iv16)
  assertEqual "aes-ofb-128" (Just C_AES128_OFB)
    (cipherSpecFor ofbMech 16 iv16)
  assertEqual "aes-ofb-192" (Just C_AES192_OFB)
    (cipherSpecFor ofbMech 24 iv16)
  assertEqual "aes-ofb-256" (Just C_AES256_OFB)
    (cipherSpecFor ofbMech 32 iv16)
  assertEqual "aes-ofb rejects bad keylen" Nothing
    (cipherSpecFor ofbMech 15 iv16)
  assertEqual "aes-ofb rejects bad iv" Nothing
    (cipherSpecFor ofbMech 16 iv8)
  -- AES-KW: empty params only, three widths.
  assertEqual "aes-kw-128" (Just C_AES128_KW)
    (cipherSpecFor kwMech 16 BS.empty)
  assertEqual "aes-kw-192" (Just C_AES192_KW)
    (cipherSpecFor kwMech 24 BS.empty)
  assertEqual "aes-kw-256" (Just C_AES256_KW)
    (cipherSpecFor kwMech 32 BS.empty)
  assertEqual "aes-kw rejects bad keylen" Nothing
    (cipherSpecFor kwMech 15 BS.empty)
  assertEqual "aes-kw rejects iv" Nothing
    (cipherSpecFor kwMech 16 iv16)
  -- AES-KWP (+ PAD alias): empty params only, three widths.
  assertEqual "aes-kwp-128" (Just C_AES128_KWP)
    (cipherSpecFor kwpMech 16 BS.empty)
  assertEqual "aes-kwp-192" (Just C_AES192_KWP)
    (cipherSpecFor kwpMech 24 BS.empty)
  assertEqual "aes-kwp-256" (Just C_AES256_KWP)
    (cipherSpecFor kwpMech 32 BS.empty)
  assertEqual "aes-kwp rejects bad keylen" Nothing
    (cipherSpecFor kwpMech 15 BS.empty)
  assertEqual "aes-kwp rejects iv" Nothing
    (cipherSpecFor kwpMech 32 iv8)
  assertEqual "aes-kwpad-256" (Just C_AES256_KWP)
    (cipherSpecFor kwPadMech 32 BS.empty)
  assertEqual "aes-kwpad rejects iv" Nothing
    (cipherSpecFor kwPadMech 32 iv16)
  -- AES-XTS: 16-byte tweak, double-width keys, no 192.
  assertEqual "aes-xts-128" (Just C_AES128_XTS)
    (cipherSpecFor xtsMech 32 iv16)
  assertEqual "aes-xts-256" (Just C_AES256_XTS)
    (cipherSpecFor xtsMech 64 iv16)
  assertEqual "aes-xts rejects bad keylen" Nothing
    (cipherSpecFor xtsMech 48 iv16)
  assertEqual "aes-xts rejects single-width key" Nothing
    (cipherSpecFor xtsMech 16 iv16)
  assertEqual "aes-xts rejects bad tweak" Nothing
    (cipherSpecFor xtsMech 32 iv8)
  -- PAD rows share the CBC specs (the planner pads before the
  -- effect input is fixed).
  assertEqual "aria-pad-256" (Just C_ARIA256_CBC)
    (cipherSpecFor ariaPadMech 32 iv16)
  assertEqual "aria-pad rejects bad iv" Nothing
    (cipherSpecFor ariaPadMech 32 iv8)
  assertEqual "camellia-pad-128" (Just C_CAMELLIA128_CBC)
    (cipherSpecFor camPadMech 16 iv16)
  assertEqual "camellia-pad rejects bad keylen" Nothing
    (cipherSpecFor camPadMech 15 iv16)
  assertEqual "des3-pad-24" (Just C_DES3_CBC)
    (cipherSpecFor d3PadMech 24 iv8)
  assertEqual "des3-pad rejects 16-iv" Nothing
    (cipherSpecFor d3PadMech 24 iv16)
  -- CAMELLIA-CTR: the canonical image maps each width; off-width
  -- and raw-IV parameters refuse.
  let camCtrGood = encodeCtrParams 128 iv16
  assertEqual "camellia-ctr-128" (Just C_CAMELLIA128_CTR)
    (cipherSpecFor camCtrMech 16 camCtrGood)
  assertEqual "camellia-ctr-192" (Just C_CAMELLIA192_CTR)
    (cipherSpecFor camCtrMech 24 camCtrGood)
  assertEqual "camellia-ctr-256" (Just C_CAMELLIA256_CTR)
    (cipherSpecFor camCtrMech 32 camCtrGood)
  assertEqual "camellia-ctr rejects bad keylen" Nothing
    (cipherSpecFor camCtrMech 15 camCtrGood)
  assertEqual "camellia-ctr rejects 64-bit" Nothing
    (cipherSpecFor camCtrMech 16 (encodeCtrParams 64 iv16))
  assertEqual "camellia-ctr rejects raw iv" Nothing
    (cipherSpecFor camCtrMech 16 iv16)
  assertEqual "non-cipher uncovered" Nothing
    (cipherSpecFor (MechanismId (ckm_SHA256)) 32 iv16)
  -- Legacy rows: exact specs, PAD sharing the CBC ctor.
  let legacy mech = MechanismId (mustGeneratedId mech)
  assertEqual "des-ecb" (Just C_DES_ECB)
    (cipherSpecFor (legacy "CKM_DES_ECB") 8 BS.empty)
  assertEqual "des-cbc" (Just C_DES_CBC)
    (cipherSpecFor (legacy "CKM_DES_CBC") 8 iv8)
  assertEqual "des-cbc-pad shares CBC" (Just C_DES_CBC)
    (cipherSpecFor (legacy "CKM_DES_CBC_PAD") 8 iv8)
  assertEqual "des-ofb64" (Just C_DES_OFB64)
    (cipherSpecFor (legacy "CKM_DES_OFB64") 8 iv8)
  assertEqual "des-cfb64" (Just C_DES_CFB64)
    (cipherSpecFor (legacy "CKM_DES_CFB64") 8 iv8)
  assertEqual "des-cfb8" (Just C_DES_CFB8)
    (cipherSpecFor (legacy "CKM_DES_CFB8") 8 iv8)
  assertEqual "des rejects 7-byte key" Nothing
    (cipherSpecFor (legacy "CKM_DES_CBC") 7 iv8)
  assertEqual "cast128-cbc-5" (Just C_CAST128_CBC)
    (cipherSpecFor (legacy "CKM_CAST128_CBC") 5 iv8)
  assertEqual "cast128-ecb-16" (Just C_CAST128_ECB)
    (cipherSpecFor (legacy "CKM_CAST128_ECB") 16 BS.empty)
  assertEqual "cast-ecb-5" (Just C_CAST_ECB)
    (cipherSpecFor (legacy "CKM_CAST_ECB") 5 BS.empty)
  assertEqual "cast-cbc-5" (Just C_CAST_CBC)
    (cipherSpecFor (legacy "CKM_CAST_CBC") 5 iv8)
  assertEqual "cast-pad shares CBC" (Just C_CAST_CBC)
    (cipherSpecFor (legacy "CKM_CAST_CBC_PAD") 5 iv8)
  assertEqual "cast rejects 16-byte key" Nothing
    (cipherSpecFor (legacy "CKM_CAST_CBC") 16 iv8)
  assertEqual "cast3-ecb-10" (Just C_CAST3_ECB)
    (cipherSpecFor (legacy "CKM_CAST3_ECB") 10 BS.empty)
  assertEqual "cast3-cbc-10" (Just C_CAST3_CBC)
    (cipherSpecFor (legacy "CKM_CAST3_CBC") 10 iv8)
  assertEqual "cast3-pad shares CBC" (Just C_CAST3_CBC)
    (cipherSpecFor (legacy "CKM_CAST3_CBC_PAD") 10 iv8)
  assertEqual "cast3 rejects 5-byte key" Nothing
    (cipherSpecFor (legacy "CKM_CAST3_CBC") 5 iv8)
  assertEqual "idea-cbc" (Just C_IDEA_CBC)
    (cipherSpecFor (legacy "CKM_IDEA_CBC") 16 iv8)
  assertEqual "idea-ecb" (Just C_IDEA_ECB)
    (cipherSpecFor (legacy "CKM_IDEA_ECB") 16 BS.empty)
  assertEqual "idea rejects 8-byte key" Nothing
    (cipherSpecFor (legacy "CKM_IDEA_CBC") 8 iv8)
  assertEqual "seed-cbc" (Just C_SEED_CBC)
    (cipherSpecFor (legacy "CKM_SEED_CBC") 16 iv16)
  assertEqual "seed-ecb" (Just C_SEED_ECB)
    (cipherSpecFor (legacy "CKM_SEED_ECB") 16 BS.empty)
  assertEqual "bf-cbc-56" (Just C_BLOWFISH_CBC)
    (cipherSpecFor (legacy "CKM_BLOWFISH_CBC") 56 iv8)
  assertEqual "bf rejects 3-byte key" Nothing
    (cipherSpecFor (legacy "CKM_BLOWFISH_CBC") 3 iv8)
  assertEqual "rc4-16" (Just C_RC4)
    (cipherSpecFor (legacy "CKM_RC4") 16 BS.empty)
  assertEqual "rc4 rejects params" Nothing
    (cipherSpecFor (legacy "CKM_RC4") 16 iv8)
  let rc2cbc = encodeRc2CbcParams 128 iv8
  assertEqual "rc2-ecb-128" (Just (C_RC2_ECB 128))
    (cipherSpecFor (legacy "CKM_RC2_ECB") 16 (encodeRc2EcbParams 128))
  assertEqual "rc2-cbc-128" (Just (C_RC2_CBC 128))
    (cipherSpecFor (legacy "CKM_RC2_CBC") 16 rc2cbc)
  assertEqual "rc2-pad shares CBC" (Just (C_RC2_CBC 40))
    (cipherSpecFor (legacy "CKM_RC2_CBC_PAD") 5 (encodeRc2CbcParams 40 iv8))
  assertEqual "rc2 rejects bits 0" Nothing
    (cipherSpecFor (legacy "CKM_RC2_CBC") 16 (encodeRc2CbcParams 0 iv8))
  assertEqual "rc2 rejects raw iv" Nothing
    (cipherSpecFor (legacy "CKM_RC2_CBC") 16 iv8)
  -- Whole-table agreement: every (recipe, key length) triple maps.
  mapM_ (\(suffix, _, keys, iv, _) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
        params = validParams suffix iv
    mapM_ (\n -> case cipherSpecFor mech n params of
      Nothing -> assertFailure ("unmapped " ++ T.unpack suffix ++ "/" ++ show n)
      Just cspec -> do
        assertBool ("keylen " ++ T.unpack suffix) (n `elem` cipherKeyLens cspec)
        assertEqual ("ivlen " ++ T.unpack suffix) iv (cipherIvLen cspec)
      ) keys
    ) groupShape

caseGeometryLaw :: IO ()
caseGeometryLaw = do
  assertEqual "aes128-cbc key" [16] (cipherKeyLens C_AES128_CBC)
  assertEqual "aes192-cbc key" [24] (cipherKeyLens C_AES192_CBC)
  assertEqual "aes256-cbc key" [32] (cipherKeyLens C_AES256_CBC)
  assertEqual "aes-cbc iv" 16 (cipherIvLen C_AES256_CBC)
  assertEqual "aes-ecb iv" 0 (cipherIvLen C_AES256_ECB)
  assertEqual "aes128-ctr key" [16] (cipherKeyLens C_AES128_CTR)
  assertEqual "aes192-ctr key" [24] (cipherKeyLens C_AES192_CTR)
  assertEqual "aes256-ctr key" [32] (cipherKeyLens C_AES256_CTR)
  assertEqual "aes-ctr iv" 16 (cipherIvLen C_AES256_CTR)
  assertEqual "aes128-cts key" [16] (cipherKeyLens C_AES128_CTS)
  assertEqual "aes192-cts key" [24] (cipherKeyLens C_AES192_CTS)
  assertEqual "aes256-cts key" [32] (cipherKeyLens C_AES256_CTS)
  assertEqual "aes-cts iv" 16 (cipherIvLen C_AES256_CTS)
  assertEqual "aes128-cfb128 key" [16] (cipherKeyLens C_AES128_CFB128)
  assertEqual "aes192-cfb128 key" [24] (cipherKeyLens C_AES192_CFB128)
  assertEqual "aes256-cfb128 key" [32] (cipherKeyLens C_AES256_CFB128)
  assertEqual "aes-cfb128 iv" 16 (cipherIvLen C_AES256_CFB128)
  assertEqual "aes128-cfb8 key" [16] (cipherKeyLens C_AES128_CFB8)
  assertEqual "aes192-cfb8 key" [24] (cipherKeyLens C_AES192_CFB8)
  assertEqual "aes256-cfb8 key" [32] (cipherKeyLens C_AES256_CFB8)
  assertEqual "aes-cfb8 iv" 16 (cipherIvLen C_AES256_CFB8)
  assertEqual "aes128-cfb1 key" [16] (cipherKeyLens C_AES128_CFB1)
  assertEqual "aes192-cfb1 key" [24] (cipherKeyLens C_AES192_CFB1)
  assertEqual "aes256-cfb1 key" [32] (cipherKeyLens C_AES256_CFB1)
  assertEqual "aes-cfb1 iv" 16 (cipherIvLen C_AES256_CFB1)
  assertEqual "aes128-ofb key" [16] (cipherKeyLens C_AES128_OFB)
  assertEqual "aes192-ofb key" [24] (cipherKeyLens C_AES192_OFB)
  assertEqual "aes256-ofb key" [32] (cipherKeyLens C_AES256_OFB)
  assertEqual "aes-ofb iv" 16 (cipherIvLen C_AES256_OFB)
  assertEqual "aes128-kw key" [16] (cipherKeyLens C_AES128_KW)
  assertEqual "aes192-kw key" [24] (cipherKeyLens C_AES192_KW)
  assertEqual "aes256-kw key" [32] (cipherKeyLens C_AES256_KW)
  assertEqual "aes-kw iv" 0 (cipherIvLen C_AES256_KW)
  assertEqual "aes128-kwp key" [16] (cipherKeyLens C_AES128_KWP)
  assertEqual "aes192-kwp key" [24] (cipherKeyLens C_AES192_KWP)
  assertEqual "aes256-kwp key" [32] (cipherKeyLens C_AES256_KWP)
  assertEqual "aes-kwp iv" 0 (cipherIvLen C_AES256_KWP)
  assertEqual "aes128-xts key" [32] (cipherKeyLens C_AES128_XTS)
  assertEqual "aes256-xts key" [64] (cipherKeyLens C_AES256_XTS)
  assertEqual "aes-xts tweak iv" 16 (cipherIvLen C_AES256_XTS)
  assertEqual "des3 keys" [16, 24] (cipherKeyLens C_DES3_CBC)
  assertEqual "des3 iv" 8 (cipherIvLen C_DES3_CBC)
  assertEqual "aria key" [32] (cipherKeyLens C_ARIA256_CBC)
  assertEqual "camellia-ecb iv" 0 (cipherIvLen C_CAMELLIA128_ECB)
  assertEqual "camellia128-ctr key" [16] (cipherKeyLens C_CAMELLIA128_CTR)
  assertEqual "camellia192-ctr key" [24] (cipherKeyLens C_CAMELLIA192_CTR)
  assertEqual "camellia256-ctr key" [32] (cipherKeyLens C_CAMELLIA256_CTR)
  assertEqual "camellia-ctr iv" 16 (cipherIvLen C_CAMELLIA256_CTR)

caseLegacyShapes :: IO ()
caseLegacyShapes = do
  -- The planner gates classic inits on this shape; without it init
  -- refuses CKR_MECHANISM_INVALID before the driver is reached (the
  -- 11p consumer gap: served + importable, not executable).
  mapM_ check legacyShapes
  where
    check (name, mid, want) =
      assertEqual ("legacy cipher shape " ++ name) (Just want)
        (cipherShapeFor (MechanismId mid))
    legacyShapes =
      [ ("CKM_DES_ECB", ckm_DES_ECB, CipherSpec 8 False)
      , ("CKM_DES_CBC", ckm_DES_CBC, CipherSpec 8 False)
      , ("CKM_DES_CBC_PAD", ckm_DES_CBC_PAD, CipherSpec 8 True)
      , ("CKM_DES_OFB64", ckm_DES_OFB64, CipherSpec 8 False)
      , ("CKM_DES_CFB64", ckm_DES_CFB64, CipherSpec 8 False)
      , ("CKM_DES_CFB8", ckm_DES_CFB8, CipherSpec 8 False)
      , ("CKM_RC2_ECB", ckm_RC2_ECB, CipherSpec 8 False)
      , ("CKM_RC2_CBC", ckm_RC2_CBC, CipherSpec 8 False)
      , ("CKM_RC2_CBC_PAD", ckm_RC2_CBC_PAD, CipherSpec 8 True)
      , ("CKM_RC4", ckm_RC4, CipherSpec 1 False)
      , ("CKM_CAST128_ECB", ckm_CAST128_ECB, CipherSpec 8 False)
      , ("CKM_CAST128_CBC", ckm_CAST128_CBC, CipherSpec 8 False)
      , ("CKM_CAST128_CBC_PAD", ckm_CAST128_CBC_PAD, CipherSpec 8 True)
      , ("CKM_CAST_ECB", ckm_CAST_ECB, CipherSpec 8 False)
      , ("CKM_CAST_CBC", ckm_CAST_CBC, CipherSpec 8 False)
      , ("CKM_CAST_CBC_PAD", ckm_CAST_CBC_PAD, CipherSpec 8 True)
      , ("CKM_CAST3_ECB", ckm_CAST3_ECB, CipherSpec 8 False)
      , ("CKM_CAST3_CBC", ckm_CAST3_CBC, CipherSpec 8 False)
      , ("CKM_CAST3_CBC_PAD", ckm_CAST3_CBC_PAD, CipherSpec 8 True)
      , ("CKM_IDEA_ECB", ckm_IDEA_ECB, CipherSpec 8 False)
      , ("CKM_IDEA_CBC", ckm_IDEA_CBC, CipherSpec 8 False)
      , ("CKM_IDEA_CBC_PAD", ckm_IDEA_CBC_PAD, CipherSpec 8 True)
      , ("CKM_SEED_ECB", ckm_SEED_ECB, CipherSpec 16 False)
      , ("CKM_SEED_CBC", ckm_SEED_CBC, CipherSpec 16 False)
      , ("CKM_SEED_CBC_PAD", ckm_SEED_CBC_PAD, CipherSpec 16 True)
      , ("CKM_BLOWFISH_CBC", ckm_BLOWFISH_CBC, CipherSpec 8 False)
      , ("CKM_BLOWFISH_CBC_PAD", ckm_BLOWFISH_CBC_PAD, CipherSpec 8 True)
      ]
