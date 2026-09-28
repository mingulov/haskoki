{- | CBC-MAC recipe tests.

The CBC-MAC group: 6 header mechanisms sharing the MAC parameter
shape across three 16-byte-block ciphers (AES, ARIA, Camellia) —
plain rows take empty parameters (@no-params\/1@) and emit the
first 8 bytes of the final CBC-MAC block (the OASIS half-block
rule), GENERAL rows take the 8-byte tag length (@mac-general\/1@,
the HMAC convention, reused verbatim) and emit its first 1..16
bytes. Keys are 128\/192\/256-bit cipher keys; input zero-pads
to the 16-byte block.

'Haskoki.Recipe.CbcMac' owns the group's canonical codecs,
parameter validation, key-length and truncation rules, and
mechanism table; these tests pin the recipe and its three
consumers:

* the model init path enforces MAC parameters ('validateInit',
  'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, params, key length)
  triple to its cipher spec plus truncation ('cbcmacSpecFor')
  and executes CBC-MAC chaining over the backend ECB route;
* engines execute the pinned KATs (RoutingE2ESpec CBC-MAC
  vectors on the real backend, SyntheticSpec constructions).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeCbcMacSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (CipherSpec (..))
import Haskoki.Engine.Driver (cbcmacSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.CbcMac
  ( CbcMacCipher (..)
  , CbcMacRecipe (..)
  , cbcmacBlockLen
  , cbcmacCodecFor
  , cbcmacGeneralCodec
  , cbcmacKeyLens
  , cbcmacParamsValid
  , cbcmacPlainCodec
  , cbcmacPlainOutLen
  , cbcmacRecipeFor
  , cbcmacRecipes
  )
import Haskoki.Recipe.Hmac (encodeMacGeneral)
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , ParameterCodec (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Registry.Generated
  ( mustGeneratedId
  , ckm_AES_MAC
  , ckm_AES_MAC_GENERAL
  , ckm_ARIA_MAC
  , ckm_ARIA_MAC_GENERAL
  , ckm_CAMELLIA_MAC
  , ckm_CAMELLIA_MAC_GENERAL
  , ckm_DES3_MAC
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
spec = testGroup "CBC-MAC recipe"
  [ testCase "table: six rows, flags, ciphers" caseTable
  , testCase "lookup: ids resolve, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: valid and refused shapes" caseParams
  , testCase "key lengths and block widths" caseKeyLens
  , testCase "init enforces parameters" caseInitParams
  , testCase "driver maps triples to specs" caseDriverMap
  ]

-- ---------------------------------------------------------------------------
-- Table + lookup + codec
-- ---------------------------------------------------------------------------

-- | (suffix, general?, cipher).
groupShape :: [(Text, Bool, CbcMacCipher)]
groupShape =
  [ ("AES_MAC", False, CbcAes)
  , ("AES_MAC_GENERAL", True, CbcAes)
  , ("ARIA_MAC", False, CbcAria)
  , ("ARIA_MAC_GENERAL", True, CbcAria)
  , ("CAMELLIA_MAC", False, CbcCamellia)
  , ("CAMELLIA_MAC_GENERAL", True, CbcCamellia)
  ]

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 6 (length cbcmacRecipes)
  mapM_ (\(suffix, gen, cipher) -> do
    let name = mechName suffix
        found = [ r | r <- cbcmacRecipes, cbmName r == name ]
    case found of
      [r] -> do
        assertEqual ("general " ++ T.unpack name) gen (cbmGeneral r)
        assertEqual ("cipher " ++ T.unpack name) cipher (cbmCipher r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _, _) -> do
    let name = mechName suffix
    case cbcmacRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (cbmName r)
    ) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (cbcmacRecipeFor (MechanismId 0x4712))
  assertEqual "HMAC has no CBC-MAC recipe" Nothing
    (cbcmacRecipeFor (MechanismId (ckm_SHA256_HMAC)))
  assertEqual "3DES-MAC has no CBC-MAC recipe" Nothing
    (cbcmacRecipeFor (MechanismId (ckm_DES3_MAC)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "plain codec" (ParameterCodec "no-params" 1) cbcmacPlainCodec
  assertEqual "general codec" (ParameterCodec "mac-general" 1) cbcmacGeneralCodec
  mapM_ (\(suffix, gen, _) ->
    case cbcmacRecipeFor (MechanismId (mustGeneratedId (mechName suffix))) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack suffix)
      Just r -> assertEqual ("codec " ++ T.unpack suffix)
        (if gen then cbcmacGeneralCodec else cbcmacPlainCodec)
        (cbcmacCodecFor r)
    ) groupShape

-- ---------------------------------------------------------------------------
-- Params + key geometry
-- ---------------------------------------------------------------------------

recipeOf :: Text -> CbcMacRecipe
recipeOf name =
  case cbcmacRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

caseParams :: IO ()
caseParams = do
  let plain = recipeOf "CKM_AES_MAC"
      gen = recipeOf "CKM_AES_MAC_GENERAL"
  assertBool "plain empty valid" (cbcmacParamsValid plain BS.empty)
  assertBool "plain nonempty refused" (not (cbcmacParamsValid plain "x"))
  mapM_ (\n -> assertBool ("general " ++ show n)
    (cbcmacParamsValid gen (encodeMacGeneral n))) [1, 8, 16]
  mapM_ (\n -> assertBool ("general refused " ++ show n)
    (not (cbcmacParamsValid gen (encodeMacGeneral n)))) [0, 17, 32]
  assertBool "general truncated refused"
    (not (cbcmacParamsValid gen (BS.take 4 (encodeMacGeneral 8))))
  -- Every GENERAL row shares the 1..16 rule; every plain row is empty-only.
  mapM_ (\(suffix, isGen, _) -> do
    let r = recipeOf (mechName suffix)
    if isGen
      then do
        assertBool (T.unpack suffix ++ " 16 valid")
          (cbcmacParamsValid r (encodeMacGeneral 16))
        assertBool (T.unpack suffix ++ " 17 refused")
          (not (cbcmacParamsValid r (encodeMacGeneral 17)))
      else assertBool (T.unpack suffix ++ " empty-only")
        (cbcmacParamsValid r BS.empty && not (cbcmacParamsValid r "x"))
    ) groupShape

caseKeyLens :: IO ()
caseKeyLens = do
  mapM_ (\(suffix, _, _) -> do
    let r = recipeOf (mechName suffix)
    assertEqual ("key lens " ++ T.unpack suffix) [16, 24, 32] (cbcmacKeyLens r)
    assertEqual ("block " ++ T.unpack suffix) 16 (cbcmacBlockLen r)
    assertEqual ("plain output " ++ T.unpack suffix) 8 (cbcmacPlainOutLen r)
    ) groupShape

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

allMechs :: [MechanismId]
allMechs =
  [ MechanismId ckm_AES_MAC
  , MechanismId ckm_AES_MAC_GENERAL
  , MechanismId ckm_ARIA_MAC
  , MechanismId ckm_ARIA_MAC_GENERAL
  , MechanismId ckm_CAMELLIA_MAC
  , MechanismId ckm_CAMELLIA_MAC_GENERAL
  ]

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(m, OpSign) | m <- allMechs]
  , oeModel = emptyModel
  }

-- | Unknown handle: valid parameters proceed PAST the parameter check
-- to key resolution (proving acceptance); bad parameters stop at
-- 'CKR_ARGUMENTS_BAD'.
badKey :: KeyPolicy
badKey = KeyPolicy (ExternalHandle 999) [OpSign] False

runInit :: InitArgs -> ReturnCode
runInit args = ioCode (snd (initOperation testEnv emptySessionOps testSession args))

caseInitParams :: IO ()
caseInitParams = do
  mapM_ (\(suffix, isGen, _) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
        bad = if isGen then encodeMacGeneral 17 else "x"
        good = if isGen then encodeMacGeneral 8 else BS.empty
    assertEqual (T.unpack suffix ++ " bad refused") CKR_ARGUMENTS_BAD
      (runInit (InitArgs OpSign mech bad (Just badKey) Nothing Nothing))
    assertEqual (T.unpack suffix ++ " good passes params") CKR_OBJECT_HANDLE_INVALID
      (runInit (InitArgs OpSign mech good (Just badKey) Nothing Nothing))
    ) groupShape

-- ---------------------------------------------------------------------------
-- Driver mapping
-- ---------------------------------------------------------------------------

-- | (suffix, key length, ECB spec).
ecbOf :: Text -> Int -> CipherSpec
ecbOf suffix k = case T.unpack suffix of
  'A' : 'E' : 'S' : _ -> case k of
    16 -> C_AES128_ECB
    24 -> C_AES192_ECB
    _ -> C_AES256_ECB
  'A' : 'R' : 'I' : 'A' : _ -> case k of
    16 -> C_ARIA128_ECB
    24 -> C_ARIA192_ECB
    _ -> C_ARIA256_ECB
  _ -> case k of
    16 -> C_CAMELLIA128_ECB
    24 -> C_CAMELLIA192_ECB
    _ -> C_CAMELLIA256_ECB

caseDriverMap :: IO ()
caseDriverMap = do
  let aes = MechanismId ckm_AES_MAC
      aesGen = MechanismId ckm_AES_MAC_GENERAL
  assertEqual "aes-128 half block"
    (Just (C_AES128_ECB, Just 8)) (cbcmacSpecFor aes BS.empty 16)
  assertEqual "aes-192 half block"
    (Just (C_AES192_ECB, Just 8)) (cbcmacSpecFor aes BS.empty 24)
  assertEqual "aes-256 half block"
    (Just (C_AES256_ECB, Just 8)) (cbcmacSpecFor aes BS.empty 32)
  assertEqual "bad length" Nothing (cbcmacSpecFor aes BS.empty 15)
  assertEqual "bad params" Nothing (cbcmacSpecFor aes "x" 16)
  assertEqual "general trunc"
    (Just (C_AES256_ECB, Just 5)) (cbcmacSpecFor aesGen (encodeMacGeneral 5) 32)
  assertEqual "general full"
    (Just (C_AES128_ECB, Just 16)) (cbcmacSpecFor aesGen (encodeMacGeneral 16) 16)
  assertEqual "general over block" Nothing (cbcmacSpecFor aesGen (encodeMacGeneral 17) 24)
  assertEqual "general zero" Nothing (cbcmacSpecFor aesGen (encodeMacGeneral 0) 16)
  assertEqual "non-MAC uncovered" Nothing
    (cbcmacSpecFor (MechanismId (ckm_SHA256_HMAC)) BS.empty 32)
  assertEqual "3DES-MAC uncovered" Nothing
    (cbcmacSpecFor (MechanismId (ckm_DES3_MAC)) BS.empty 24)
  -- Whole-table agreement: every (recipe, key length) pair maps.
  mapM_ (\(suffix, isGen, _) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
    mapM_ (\k ->
      case cbcmacSpecFor mech (if isGen then encodeMacGeneral 8 else BS.empty) k of
        Just (spec, _) -> assertEqual ("ecb " ++ T.unpack suffix ++ "/" ++ show k)
          (ecbOf suffix k) spec
        Nothing -> assertFailure ("unmapped " ++ T.unpack suffix ++ "/" ++ show k)
      ) [16, 24, 32]
    ) groupShape
