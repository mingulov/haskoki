{- | block-cipher-shape recipe tests.

The CBC/ECB group: 9 header mechanisms sharing one parameter shape
over four algorithm families — CBC takes the IV as mechanism
parameters (one block: 16 bytes for AES/ARIA/CAMELLIA, 8 for
Triple-DES), ECB takes empty parameters, and @CKM_AES_CBC_PAD@
adds PKCS#7 framing (decided in the pure planner, never the
backend). 'Haskoki.Recipe.Cipher' owns the group's canonical
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
    , C_AES128_ECB
    , C_AES192_CBC
    , C_AES192_CTR
    , C_AES256_CBC
    , C_AES256_CTR
    , C_AES256_ECB
    , C_ARIA256_CBC
    , C_CAMELLIA128_ECB
    , C_DES3_CBC
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
import Haskoki.Recipe.Cipher
  ( BlockCipherRecipe (..)
  , cipherCodecFor
  , cipherCtrCodec
  , cipherIvCodec
  , cipherKeyLenValid
  , cipherParamsValid
  , cipherPlainCodec
  , cipherRecipeFor
  , cipherRecipes
  , ctrNextImage
  , decodeCtrParams
  , encodeCtrParams
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
  , ckm_AES_CTR
  , ckm_AES_ECB
  , ckm_DES3_CBC
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
  [ testCase "recipe table covers 9 mechanisms with geometry" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "ECB is no-params/1, CBC is iv-bytes/1" caseCodec
  , testCase "params: IV length or empty-only" caseParams
  , testCase "key lengths: AES-family 16/24/32, DES3 16/24" caseKeyLens
  , testCase "init enforces per-mechanism cipher params" caseInitParams
  , testCase "driver maps every triple to its CipherSpec" caseDriverMap
  , testCase "engine geometry agrees with the recipe" caseGeometryLaw
  ]

-- | (Name suffix, block bytes, key lengths, IV bytes, padded).
groupShape :: [(Text, Int, [Int], Int, Bool)]
groupShape =
  [ ("AES_CBC", 16, [16, 24, 32], 16, False)
  , ("AES_CBC_PAD", 16, [16, 24, 32], 16, True)
  , ("AES_ECB", 16, [16, 24, 32], 0, False)
  , ("AES_CTR", 16, [16, 24, 32], 16, False)
  , ("DES3_CBC", 8, [16, 24], 8, False)
  , ("DES3_ECB", 8, [16, 24], 0, False)
  , ("ARIA_CBC", 16, [16, 24, 32], 16, False)
  , ("ARIA_ECB", 16, [16, 24, 32], 0, False)
  , ("CAMELLIA_CBC", 16, [16, 24, 32], 16, False)
  , ("CAMELLIA_ECB", 16, [16, 24, 32], 0, False)
  ]

-- | Valid mechanism parameters per row: the CTR row takes the
-- canonical image (128-bit width over a zero block), every other
-- row the zero IV of its length.
validParams :: Text -> Int -> BS.ByteString
validParams suffix iv
  | suffix == "AES_CTR" = encodeCtrParams 128 (BS.replicate 16 0)
  | otherwise = BS.replicate iv 0

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 10 (length cipherRecipes)
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
  mapM_ (\(suffix, _, _, iv, _) -> do
    let name = mechName suffix
        want
          | suffix == "AES_CTR" = cipherCtrCodec
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

cbcMech, ecbMech, d3Mech, ctrMech :: MechanismId
cbcMech = MechanismId (ckm_AES_CBC)
ecbMech = MechanismId (ckm_AES_ECB)
d3Mech = MechanismId (ckm_DES3_CBC)
ctrMech = MechanismId (ckm_AES_CTR)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities
      [ (cbcMech, OpEncrypt), (ecbMech, OpEncrypt), (d3Mech, OpEncrypt)
      , (ctrMech, OpEncrypt)
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
  assertEqual "non-cipher uncovered" Nothing
    (cipherSpecFor (MechanismId (ckm_SHA256)) 32 iv16)
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
  assertEqual "des3 keys" [16, 24] (cipherKeyLens C_DES3_CBC)
  assertEqual "des3 iv" 8 (cipherIvLen C_DES3_CBC)
  assertEqual "aria key" [32] (cipherKeyLens C_ARIA256_CBC)
  assertEqual "camellia-ecb iv" 0 (cipherIvLen C_CAMELLIA128_ECB)
