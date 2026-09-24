{- | CMAC recipe tests.

The CMAC group: 4 header mechanisms sharing the MAC parameter
shape — plain rows take empty parameters (@no-params\/1@),
GENERAL rows take the 8-byte tag length (@mac-general\/1@, the
HMAC convention, reused verbatim). The cipher binds by key
length (AES-128\/192\/256 for the AES rows, 3DES for the DES3
rows); the GENERAL truncation caps at the cipher block (16\/8).

'Haskoki.Recipe.Cmac' owns the group's canonical codecs, parameter
validation, key-length and truncation rules, and mechanism table;
these tests pin the recipe and its three consumers:

* the model init path enforces CMAC parameters ('validateInit',
  'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, params, key length)
  triple to its cipher spec plus truncation ('cmacSpecFor') and
  executes the SP 800-38B composition over the backend ECB route;
* engines execute the pinned KATs (RoutingE2ESpec RFC 4494 vectors
  on the real backend, SyntheticSpec constructions).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeCmacSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (CipherSpec (..))
import Haskoki.Engine.Driver (cmacSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.Cmac
  ( CmacRecipe (..)
  , cmacBlockLen
  , cmacCodecFor
  , cmacKeyLens
  , cmacParamsValid
  , cmacPlainCodec
  , cmacGeneralCodec
  , cmacRecipeFor
  , cmacRecipes
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
  , ckm_AES_CBC
  , ckm_AES_CMAC
  , ckm_AES_CMAC_GENERAL
  , ckm_DES3_CMAC
  , ckm_DES3_CMAC_GENERAL
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
spec = testGroup "CMAC recipe"
  [ testCase "table: four rows, flags" caseTable
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

-- | (suffix, general?, 3DES?).
groupShape :: [(Text, Bool, Bool)]
groupShape =
  [ ("AES_CMAC", False, False)
  , ("AES_CMAC_GENERAL", True, False)
  , ("DES3_CMAC", False, True)
  , ("DES3_CMAC_GENERAL", True, True)
  ]

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 4 (length cmacRecipes)
  mapM_ (\(suffix, gen, des3) -> do
    let name = mechName suffix
        found = [ r | r <- cmacRecipes, rcName r == name ]
    case found of
      [r] -> do
        assertEqual ("general " ++ T.unpack name) gen (rcGeneral r)
        assertEqual ("des3 " ++ T.unpack name) des3 (rcDes3 r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _, _) -> do
    let name = mechName suffix
    case cmacRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (rcName r)
    ) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (cmacRecipeFor (MechanismId 0x4712))
  assertEqual "HMAC has no CMAC recipe" Nothing
    (cmacRecipeFor (MechanismId (ckm_SHA256_HMAC)))
  assertEqual "AES-CBC has no CMAC recipe" Nothing
    (cmacRecipeFor (MechanismId (ckm_AES_CBC)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "plain codec" (ParameterCodec "no-params" 1) cmacPlainCodec
  assertEqual "general codec" (ParameterCodec "mac-general" 1) cmacGeneralCodec
  mapM_ (\(suffix, gen, _) ->
    case cmacRecipeFor (MechanismId (mustGeneratedId (mechName suffix))) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack suffix)
      Just r -> assertEqual ("codec " ++ T.unpack suffix)
        (if gen then cmacGeneralCodec else cmacPlainCodec)
        (cmacCodecFor r)
    ) groupShape

-- ---------------------------------------------------------------------------
-- Params + key geometry
-- ---------------------------------------------------------------------------

recipeOf :: Text -> CmacRecipe
recipeOf name =
  case cmacRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

caseParams :: IO ()
caseParams = do
  let plain = recipeOf "CKM_AES_CMAC"
      des3 = recipeOf "CKM_DES3_CMAC"
      gen = recipeOf "CKM_AES_CMAC_GENERAL"
      gen3 = recipeOf "CKM_DES3_CMAC_GENERAL"
  assertBool "plain empty valid" (cmacParamsValid plain BS.empty)
  assertBool "plain nonempty refused" (not (cmacParamsValid plain "x"))
  assertBool "des3 empty valid" (cmacParamsValid des3 BS.empty)
  assertBool "des3 nonempty refused" (not (cmacParamsValid des3 "x"))
  mapM_ (\n -> assertBool ("general aes " ++ show n)
    (cmacParamsValid gen (encodeMacGeneral n))) [1, 8, 16]
  mapM_ (\n -> assertBool ("general aes refused " ++ show n)
    (not (cmacParamsValid gen (encodeMacGeneral n)))) [0, 17, 32]
  assertBool "general truncated refused"
    (not (cmacParamsValid gen (BS.take 4 (encodeMacGeneral 8))))
  mapM_ (\n -> assertBool ("general des3 " ++ show n)
    (cmacParamsValid gen3 (encodeMacGeneral n))) [1, 8]
  mapM_ (\n -> assertBool ("general des3 refused " ++ show n)
    (not (cmacParamsValid gen3 (encodeMacGeneral n)))) [0, 9, 16]

caseKeyLens :: IO ()
caseKeyLens = do
  assertEqual "aes key lens" [16, 24, 32]
    (cmacKeyLens (recipeOf "CKM_AES_CMAC"))
  assertEqual "aes general key lens" [16, 24, 32]
    (cmacKeyLens (recipeOf "CKM_AES_CMAC_GENERAL"))
  assertEqual "des3 key lens" [16, 24]
    (cmacKeyLens (recipeOf "CKM_DES3_CMAC"))
  assertEqual "aes block" 16 (cmacBlockLen (recipeOf "CKM_AES_CMAC"))
  assertEqual "des3 block" 8 (cmacBlockLen (recipeOf "CKM_DES3_CMAC"))

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

cmacMech, cmacGenMech :: MechanismId
cmacMech = MechanismId (ckm_AES_CMAC)
cmacGenMech = MechanismId (ckm_AES_CMAC_GENERAL)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(cmacMech, OpSign), (cmacGenMech, OpSign)]
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
  assertEqual "nonempty refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign cmacMech "x" (Just badKey) Nothing Nothing))
  assertEqual "empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign cmacMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "general bad length refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign cmacGenMech (encodeMacGeneral 17) (Just badKey) Nothing Nothing))
  assertEqual "general good length passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign cmacGenMech (encodeMacGeneral 8) (Just badKey) Nothing Nothing))

-- ---------------------------------------------------------------------------
-- Driver mapping
-- ---------------------------------------------------------------------------

caseDriverMap :: IO ()
caseDriverMap = do
  let aes = MechanismId (ckm_AES_CMAC)
      aesG = MechanismId (ckm_AES_CMAC_GENERAL)
      d3 = MechanismId (ckm_DES3_CMAC)
      d3G = MechanismId (ckm_DES3_CMAC_GENERAL)
  assertEqual "aes-128" (Just (C_AES128_ECB, Nothing)) (cmacSpecFor aes BS.empty 16)
  assertEqual "aes-192" (Just (C_AES192_ECB, Nothing)) (cmacSpecFor aes BS.empty 24)
  assertEqual "aes-256" (Just (C_AES256_ECB, Nothing)) (cmacSpecFor aes BS.empty 32)
  assertEqual "aes bad length" Nothing (cmacSpecFor aes BS.empty 15)
  assertEqual "aes bad params" Nothing (cmacSpecFor aes "x" 16)
  assertEqual "aes general trunc"
    (Just (C_AES256_ECB, Just 8)) (cmacSpecFor aesG (encodeMacGeneral 8) 32)
  assertEqual "aes general full"
    (Just (C_AES128_ECB, Just 16)) (cmacSpecFor aesG (encodeMacGeneral 16) 16)
  assertEqual "aes general over block" Nothing (cmacSpecFor aesG (encodeMacGeneral 17) 16)
  assertEqual "aes general zero" Nothing (cmacSpecFor aesG (encodeMacGeneral 0) 16)
  assertEqual "des3 two-key" (Just (C_DES3_ECB, Nothing)) (cmacSpecFor d3 BS.empty 16)
  assertEqual "des3 three-key" (Just (C_DES3_ECB, Nothing)) (cmacSpecFor d3 BS.empty 24)
  assertEqual "des3 bad length" Nothing (cmacSpecFor d3 BS.empty 32)
  assertEqual "des3 general trunc"
    (Just (C_DES3_ECB, Just 8)) (cmacSpecFor d3G (encodeMacGeneral 8) 24)
  assertEqual "des3 general over block" Nothing (cmacSpecFor d3G (encodeMacGeneral 9) 24)
  assertEqual "non-CMAC uncovered" Nothing
    (cmacSpecFor (MechanismId (ckm_SHA256_HMAC)) BS.empty 32)
  -- Whole-table agreement: every (recipe, key length) pair maps.
  mapM_ (\(suffix, gen, _) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
        keys = if gen then [16, 24, 32] else [16, 24, 32]
    mapM_ (\k -> do
      let params = if gen then encodeMacGeneral 8 else BS.empty
      case cmacSpecFor mech params k of
        Just _ -> pure ()
        Nothing -> assertFailure ("unmapped " ++ T.unpack suffix ++ "/" ++ show k)
      ) keys
    ) [("AES_CMAC", False, False), ("AES_CMAC_GENERAL", True, False)]
  mapM_ (\(suffix, gen) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
    mapM_ (\k ->
      case cmacSpecFor mech (if gen then encodeMacGeneral 8 else BS.empty) k of
        Just _ -> pure ()
        Nothing -> assertFailure ("unmapped " ++ T.unpack suffix ++ "/" ++ show k)
      ) [16, 24]
    ) [("DES3_CMAC", False), ("DES3_CMAC_GENERAL", True)]
