{- | AES-XCBC-MAC recipe tests (RFC 3566).

The XCBC group: 2 header mechanisms sharing the empty parameter
shape (@no-params\/1@) — the plain row emits the full 16-byte
tag, the _96 row its first 12 bytes. Keys are 128-bit AES only;
192\/256-bit keys are refused.

'Haskoki.Recipe.XcbcMac' owns the group's canonical codec,
parameter validation, key-length and truncation rules, and
mechanism table; these tests pin the recipe and its three
consumers:

* the model init path enforces MAC parameters ('validateInit',
  'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, params, key length)
  triple to AES-128-ECB plus truncation ('xcbcSpecFor') and
  executes the RFC 3566 composition over the backend ECB route;
* engines execute the pinned KATs (RoutingE2ESpec XCBC vectors
  on the real backend, SyntheticSpec constructions).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeXcbcMacSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (CipherSpec (..))
import Haskoki.Engine.Driver (xcbcSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.XcbcMac
  ( XcbcRecipe (..)
  , xcbcCodec
  , xcbcCodecFor
  , xcbcKeyLens
  , xcbcOutLen
  , xcbcParamsValid
  , xcbcRecipeFor
  , xcbcRecipes
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
  , ckm_AES_XCBC_MAC
  , ckm_AES_XCBC_MAC_96
  , ckm_AES_CMAC
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
spec = testGroup "XCBC-MAC recipe"
  [ testCase "table: two rows, truncation flags" caseTable
  , testCase "lookup: ids resolve, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: empty-only" caseParams
  , testCase "key lengths and output widths" caseKeyLens
  , testCase "init enforces parameters" caseInitParams
  , testCase "driver maps triples to specs" caseDriverMap
  ]

-- ---------------------------------------------------------------------------
-- Table + lookup + codec
-- ---------------------------------------------------------------------------

-- | (suffix, truncated?).
groupShape :: [(Text, Bool)]
groupShape =
  [ ("AES_XCBC_MAC", False)
  , ("AES_XCBC_MAC_96", True)
  ]

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 2 (length xcbcRecipes)
  mapM_ (\(suffix, trunc) -> do
    let name = mechName suffix
        found = [ r | r <- xcbcRecipes, xcbName r == name ]
    case found of
      [r] -> assertEqual ("truncated " ++ T.unpack name) trunc (xcbTruncated r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _) -> do
    let name = mechName suffix
    case xcbcRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (xcbName r)
    ) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (xcbcRecipeFor (MechanismId 0x4712))
  assertEqual "HMAC has no XCBC recipe" Nothing
    (xcbcRecipeFor (MechanismId (ckm_SHA256_HMAC)))
  assertEqual "CMAC has no XCBC recipe" Nothing
    (xcbcRecipeFor (MechanismId (ckm_AES_CMAC)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "codec" (ParameterCodec "no-params" 1) xcbcCodec
  mapM_ (\(suffix, _) ->
    case xcbcRecipeFor (MechanismId (mustGeneratedId (mechName suffix))) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack suffix)
      Just r -> assertEqual ("codec " ++ T.unpack suffix) xcbcCodec (xcbcCodecFor r)
    ) groupShape

-- ---------------------------------------------------------------------------
-- Params + key geometry
-- ---------------------------------------------------------------------------

recipeOf :: Text -> XcbcRecipe
recipeOf name =
  case xcbcRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

caseParams :: IO ()
caseParams = do
  mapM_ (\(suffix, _) -> do
    let r = recipeOf (mechName suffix)
    assertBool (T.unpack suffix ++ " empty valid") (xcbcParamsValid r BS.empty)
    assertBool (T.unpack suffix ++ " nonempty refused")
      (not (xcbcParamsValid r "x"))
    ) groupShape

caseKeyLens :: IO ()
caseKeyLens = do
  assertEqual "plain key lens" [16]
    (xcbcKeyLens (recipeOf "CKM_AES_XCBC_MAC"))
  assertEqual "truncated key lens" [16]
    (xcbcKeyLens (recipeOf "CKM_AES_XCBC_MAC_96"))
  assertEqual "plain output" 16 (xcbcOutLen (recipeOf "CKM_AES_XCBC_MAC"))
  assertEqual "truncated output" 12 (xcbcOutLen (recipeOf "CKM_AES_XCBC_MAC_96"))

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

xcbcMech, xcbc96Mech :: MechanismId
xcbcMech = MechanismId (ckm_AES_XCBC_MAC)
xcbc96Mech = MechanismId (ckm_AES_XCBC_MAC_96)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(xcbcMech, OpSign), (xcbc96Mech, OpSign)]
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
    (runInit (InitArgs OpSign xcbcMech "x" (Just badKey) Nothing Nothing))
  assertEqual "empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign xcbcMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "96 nonempty refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign xcbc96Mech "x" (Just badKey) Nothing Nothing))
  assertEqual "96 empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign xcbc96Mech BS.empty (Just badKey) Nothing Nothing))

-- ---------------------------------------------------------------------------
-- Driver mapping
-- ---------------------------------------------------------------------------

caseDriverMap :: IO ()
caseDriverMap = do
  let plain = MechanismId (ckm_AES_XCBC_MAC)
      trunc = MechanismId (ckm_AES_XCBC_MAC_96)
  assertEqual "128-bit full tag"
    (Just (C_AES128_ECB, Just 16)) (xcbcSpecFor plain BS.empty 16)
  assertEqual "192 refused" Nothing (xcbcSpecFor plain BS.empty 24)
  assertEqual "256 refused" Nothing (xcbcSpecFor plain BS.empty 32)
  assertEqual "bad params" Nothing (xcbcSpecFor plain "x" 16)
  assertEqual "96 truncates"
    (Just (C_AES128_ECB, Just 12)) (xcbcSpecFor trunc BS.empty 16)
  assertEqual "96 192 refused" Nothing (xcbcSpecFor trunc BS.empty 24)
  assertEqual "non-MAC uncovered" Nothing
    (xcbcSpecFor (MechanismId (ckm_SHA256_HMAC)) BS.empty 16)
  assertEqual "CMAC uncovered" Nothing
    (xcbcSpecFor (MechanismId (ckm_AES_CMAC)) BS.empty 16)
  -- Whole-table agreement: every recipe maps on its 128-bit key.
  mapM_ (\(suffix, _) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
    case xcbcSpecFor mech BS.empty 16 of
      Just _ -> pure ()
      Nothing -> assertFailure ("unmapped " ++ T.unpack suffix)
    ) groupShape
