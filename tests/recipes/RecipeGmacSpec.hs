{- | AES-GMAC recipe tests.

The GMAC group: the single CKM_AES_GMAC mechanism takes the
canonical @gcm-params\/1@ image (tag length, IV, AAD remainder —
the GCM convention, reused verbatim) with the tag width from the
SP 800-38D approved set (OASIS v3.2 §6.13.6: @ulTagBits@
determines the length) and a caller-supplied
1..64-byte IV. The signed message travels as the GCM AAD with
empty plaintext; keys are 128\/192\/256-bit AES.

'Haskoki.Recipe.Gmac' owns the group's canonical codec,
parameter validation, key-length rule, and mechanism table;
these tests pin the recipe and its three consumers:

* the model init path enforces GMAC parameters ('validateInit',
  'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, params, key length)
  triple to its AEAD spec plus IV ('gmacSpecFor') and executes
  GMAC over the backend GCM route;
* engines execute the pinned KATs (RoutingE2ESpec GMAC vectors
  on the real backend, SyntheticSpec constructions).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeGmacSpec (spec) where

import qualified Data.ByteString as BS
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (AeadSpec (..))
import Haskoki.Engine.Driver (gmacSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.Gcm (encodeGcmParams)
import Haskoki.Recipe.Gmac
  ( GmacRecipe (..)
  , gmacCodec
  , gmacCodecFor
  , gmacIvMax
  , gmacKeyLens
  , gmacParamsValid
  , gmacRecipeFor
  , gmacRecipes
  , gmacTagLens
  )
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , ParameterCodec (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Registry.Generated
  ( ckm_AES_GCM
  , ckm_AES_GMAC
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
spec = testGroup "GMAC recipe"
  [ testCase "table: one row" caseTable
  , testCase "lookup: id resolves, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: valid and refused shapes" caseParams
  , testCase "key lengths and tag width" caseKeyLens
  , testCase "init enforces parameters" caseInitParams
  , testCase "driver maps triples to specs" caseDriverMap
  ]

-- ---------------------------------------------------------------------------
-- Table + lookup + codec
-- ---------------------------------------------------------------------------

gmacMech :: MechanismId
gmacMech = MechanismId (ckm_AES_GMAC)

caseTable :: IO ()
caseTable = case gmacRecipes of
  [r] -> assertEqual "row name" "CKM_AES_GMAC" (gmName r)
  rs -> assertFailure ("rows: " ++ show (length rs))

caseLookup :: IO ()
caseLookup = do
  case gmacRecipeFor gmacMech of
    Nothing -> assertFailure "unresolved CKM_AES_GMAC"
    Just r -> assertEqual "lookup" "CKM_AES_GMAC" (gmName r)
  assertEqual "unknown id has no recipe" Nothing
    (gmacRecipeFor (MechanismId 0x4712))
  assertEqual "HMAC has no GMAC recipe" Nothing
    (gmacRecipeFor (MechanismId (ckm_SHA256_HMAC)))
  assertEqual "GCM has no GMAC recipe" Nothing
    (gmacRecipeFor (MechanismId (ckm_AES_GCM)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "codec" (ParameterCodec "gcm-params" 1) gmacCodec
  case gmacRecipeFor gmacMech of
    Nothing -> assertFailure "unresolved CKM_AES_GMAC"
    Just r -> assertEqual "row codec" gmacCodec (gmacCodecFor r)

-- ---------------------------------------------------------------------------
-- Params + key geometry
-- ---------------------------------------------------------------------------

recipeOf :: GmacRecipe
recipeOf =
  case gmacRecipeFor gmacMech of
    Just r -> r
    Nothing -> error "test recipe missing: CKM_AES_GMAC"

iv12 :: BS.ByteString
iv12 = BS.replicate 12 0x9d

caseParams :: IO ()
caseParams = do
  let r = recipeOf
  assertBool "12-byte IV valid"
    (gmacParamsValid r (encodeGcmParams iv12 BS.empty 16))
  assertBool "short IV valid"
    (gmacParamsValid r (encodeGcmParams "i" BS.empty 16))
  assertBool "64-byte IV valid"
    (gmacParamsValid r (encodeGcmParams (BS.replicate 64 1) BS.empty 16))
  mapM_ (\t -> assertBool ("approved tag " ++ show t)
    (gmacParamsValid r (encodeGcmParams iv12 BS.empty t))) [4, 8, 12, 13, 14, 15, 16]
  mapM_ (\t -> assertBool ("unapproved tag refused " ++ show t)
    (not (gmacParamsValid r (encodeGcmParams iv12 BS.empty t))))
    [0, 1, 2, 3, 5, 6, 7, 9, 10, 11, 17]
  assertBool "empty IV refused"
    (not (gmacParamsValid r (encodeGcmParams BS.empty BS.empty 16)))
  assertBool "65-byte IV refused"
    (not (gmacParamsValid r (encodeGcmParams (BS.replicate 65 1) BS.empty 16)))
  assertBool "empty params refused" (not (gmacParamsValid r BS.empty))
  assertBool "truncated refused"
    (not (gmacParamsValid r (BS.take 10 (encodeGcmParams iv12 BS.empty 16))))

caseKeyLens :: IO ()
caseKeyLens = do
  assertEqual "key lens" [16, 24, 32] (gmacKeyLens recipeOf)
  assertEqual "tag widths" [4, 8, 12, 13, 14, 15, 16] gmacTagLens
  assertEqual "iv ceiling" 64 gmacIvMax

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
  , oeCaps = mkCapabilities [(gmacMech, OpSign)]
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
  assertEqual "empty refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign gmacMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "truncated tag passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign gmacMech
      (encodeGcmParams iv12 BS.empty 4) (Just badKey) Nothing Nothing))
  assertEqual "unapproved width refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign gmacMech
      (encodeGcmParams iv12 BS.empty 5) (Just badKey) Nothing Nothing))
  assertEqual "good passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign gmacMech
      (encodeGcmParams iv12 BS.empty 16) (Just badKey) Nothing Nothing))

-- ---------------------------------------------------------------------------
-- Driver mapping
-- ---------------------------------------------------------------------------

caseDriverMap :: IO ()
caseDriverMap = do
  let good = encodeGcmParams iv12 BS.empty 16
  assertEqual "128 maps"
    (Just (AeadSpec "AES-128-GCM" 12 16, iv12)) (gmacSpecFor gmacMech good 16)
  assertEqual "192 maps"
    (Just (AeadSpec "AES-192-GCM" 12 16, iv12)) (gmacSpecFor gmacMech good 24)
  assertEqual "256 maps"
    (Just (AeadSpec "AES-256-GCM" 12 16, iv12)) (gmacSpecFor gmacMech good 32)
  assertEqual "bad length" Nothing (gmacSpecFor gmacMech good 20)
  assertEqual "empty params" Nothing (gmacSpecFor gmacMech BS.empty 16)
  assertEqual "truncated tag maps"
    (Just (AeadSpec "AES-128-GCM" 12 4, iv12))
    (gmacSpecFor gmacMech (encodeGcmParams iv12 BS.empty 4) 16)
  assertEqual "unapproved width" Nothing
    (gmacSpecFor gmacMech (encodeGcmParams iv12 BS.empty 5) 16)
  assertEqual "non-MAC uncovered" Nothing
    (gmacSpecFor (MechanismId (ckm_SHA256_HMAC)) good 16)
  assertEqual "GCM uncovered" Nothing
    (gmacSpecFor (MechanismId (ckm_AES_GCM)) good 16)
