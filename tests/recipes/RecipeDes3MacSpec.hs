{- | 3DES CBC-MAC recipe tests.

The 3DES-MAC group: 2 header mechanisms sharing the MAC parameter
shape — the plain row takes empty parameters (@no-params\/1@) and
emits the first 4 bytes of the final CBC-MAC block (the OASIS
half-block rule), the GENERAL row takes the 8-byte tag length
(@mac-general\/1@, the HMAC convention, reused verbatim) and
emits its first 1..8 bytes. Keys are two-key\/three-key 3DES
(16\/24 bytes); input zero-pads to the 8-byte block.

'Haskoki.Recipe.Des3Mac' owns the group's canonical codecs,
parameter validation, key-length and truncation rules, and
mechanism table; these tests pin the recipe and its three
consumers:

* the model init path enforces MAC parameters ('validateInit',
  'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, params, key length)
  triple to its cipher spec plus truncation ('des3macSpecFor')
  and executes CBC-MAC chaining over the backend ECB route;
* engines execute the pinned KATs (RoutingE2ESpec 3DES-MAC
  vectors on the real backend, SyntheticSpec constructions).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeDes3MacSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (CipherSpec (..))
import Haskoki.Engine.Driver (des3macSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.Des3Mac
  ( Des3MacRecipe (..)
  , des3macBlockLen
  , des3macCodecFor
  , des3macKeyLens
  , des3macParamsValid
  , des3macPlainCodec
  , des3macGeneralCodec
  , des3macPlainOutLen
  , des3macRecipeFor
  , des3macRecipes
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
  , ckm_DES3_MAC
  , ckm_DES3_MAC_GENERAL
  , ckm_DES3_CMAC
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
spec = testGroup "3DES-MAC recipe"
  [ testCase "table: two rows, flags" caseTable
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

-- | (suffix, general?).
groupShape :: [(Text, Bool)]
groupShape =
  [ ("DES3_MAC", False)
  , ("DES3_MAC_GENERAL", True)
  ]

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 2 (length des3macRecipes)
  mapM_ (\(suffix, gen) -> do
    let name = mechName suffix
        found = [ r | r <- des3macRecipes, rdmName r == name ]
    case found of
      [r] -> assertEqual ("general " ++ T.unpack name) gen (rdmGeneral r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _) -> do
    let name = mechName suffix
    case des3macRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (rdmName r)
    ) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (des3macRecipeFor (MechanismId 0x4712))
  assertEqual "HMAC has no 3DES-MAC recipe" Nothing
    (des3macRecipeFor (MechanismId (ckm_SHA256_HMAC)))
  assertEqual "CMAC has no 3DES-MAC recipe" Nothing
    (des3macRecipeFor (MechanismId (ckm_DES3_CMAC)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "plain codec" (ParameterCodec "no-params" 1) des3macPlainCodec
  assertEqual "general codec" (ParameterCodec "mac-general" 1) des3macGeneralCodec
  mapM_ (\(suffix, gen) ->
    case des3macRecipeFor (MechanismId (mustGeneratedId (mechName suffix))) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack suffix)
      Just r -> assertEqual ("codec " ++ T.unpack suffix)
        (if gen then des3macGeneralCodec else des3macPlainCodec)
        (des3macCodecFor r)
    ) groupShape

-- ---------------------------------------------------------------------------
-- Params + key geometry
-- ---------------------------------------------------------------------------

recipeOf :: Text -> Des3MacRecipe
recipeOf name =
  case des3macRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

caseParams :: IO ()
caseParams = do
  let plain = recipeOf "CKM_DES3_MAC"
      gen = recipeOf "CKM_DES3_MAC_GENERAL"
  assertBool "plain empty valid" (des3macParamsValid plain BS.empty)
  assertBool "plain nonempty refused" (not (des3macParamsValid plain "x"))
  mapM_ (\n -> assertBool ("general " ++ show n)
    (des3macParamsValid gen (encodeMacGeneral n))) [1, 4, 8]
  mapM_ (\n -> assertBool ("general refused " ++ show n)
    (not (des3macParamsValid gen (encodeMacGeneral n)))) [0, 9, 16]
  assertBool "general truncated refused"
    (not (des3macParamsValid gen (BS.take 4 (encodeMacGeneral 8))))

caseKeyLens :: IO ()
caseKeyLens = do
  assertEqual "plain key lens" [16, 24]
    (des3macKeyLens (recipeOf "CKM_DES3_MAC"))
  assertEqual "general key lens" [16, 24]
    (des3macKeyLens (recipeOf "CKM_DES3_MAC_GENERAL"))
  assertEqual "block" 8 (des3macBlockLen (recipeOf "CKM_DES3_MAC"))
  assertEqual "plain output" 4 (des3macPlainOutLen (recipeOf "CKM_DES3_MAC"))
  assertEqual "general output" 4 (des3macPlainOutLen (recipeOf "CKM_DES3_MAC_GENERAL"))

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

des3macMech, des3macGenMech :: MechanismId
des3macMech = MechanismId (ckm_DES3_MAC)
des3macGenMech = MechanismId (ckm_DES3_MAC_GENERAL)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(des3macMech, OpSign), (des3macGenMech, OpSign)]
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
    (runInit (InitArgs OpSign des3macMech "x" (Just badKey) Nothing Nothing))
  assertEqual "empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign des3macMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "general bad length refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign des3macGenMech (encodeMacGeneral 9) (Just badKey) Nothing Nothing))
  assertEqual "general good length passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign des3macGenMech (encodeMacGeneral 8) (Just badKey) Nothing Nothing))

-- ---------------------------------------------------------------------------
-- Driver mapping
-- ---------------------------------------------------------------------------

caseDriverMap :: IO ()
caseDriverMap = do
  let plain = MechanismId (ckm_DES3_MAC)
      gen = MechanismId (ckm_DES3_MAC_GENERAL)
  assertEqual "two-key half block" (Just (C_DES3_ECB, Just 4)) (des3macSpecFor plain BS.empty 16)
  assertEqual "three-key half block" (Just (C_DES3_ECB, Just 4)) (des3macSpecFor plain BS.empty 24)
  assertEqual "bad length" Nothing (des3macSpecFor plain BS.empty 32)
  assertEqual "bad params" Nothing (des3macSpecFor plain "x" 16)
  assertEqual "general trunc"
    (Just (C_DES3_ECB, Just 4)) (des3macSpecFor gen (encodeMacGeneral 4) 24)
  assertEqual "general full"
    (Just (C_DES3_ECB, Just 8)) (des3macSpecFor gen (encodeMacGeneral 8) 16)
  assertEqual "general over block" Nothing (des3macSpecFor gen (encodeMacGeneral 9) 24)
  assertEqual "general zero" Nothing (des3macSpecFor gen (encodeMacGeneral 0) 16)
  assertEqual "non-MAC uncovered" Nothing
    (des3macSpecFor (MechanismId (ckm_SHA256_HMAC)) BS.empty 32)
  assertEqual "CMAC uncovered" Nothing
    (des3macSpecFor (MechanismId (ckm_DES3_CMAC)) BS.empty 24)
  -- Whole-table agreement: every (recipe, key length) pair maps.
  mapM_ (\(suffix, isGen) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
    mapM_ (\k ->
      case des3macSpecFor mech (if isGen then encodeMacGeneral 8 else BS.empty) k of
        Just _ -> pure ()
        Nothing -> assertFailure ("unmapped " ++ T.unpack suffix ++ "/" ++ show k)
      ) [16, 24]
    ) groupShape
