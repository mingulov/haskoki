{- | AES-GCM AEAD recipe tests.

The single-row GCM group: caller-supplied IV (1..64 bytes),
NIST SP 800-38D tag widths, AAD bound at seal ('gcm-params/1':
tag length, IV length, IV, AAD). 'Haskoki.Recipe.Gcm' owns the
canonical codec and parameter validation; these tests pin the
recipe and its two consumers:

* the model init path enforces GCM parameters ('validateInit',
  'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, key length, params)
  triple to its backend 'AeadSpec' ('aeadSpecFor' agrees with
  the recipe table: key length selects the AES width, the IV
  length is the nonce length, the tag width crosses intact).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeGcmSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (AeadSpec (..))
import Haskoki.Engine.Driver (aeadSpecFor)
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
import Haskoki.Recipe.Gcm
  ( GcmRecipe (..)
  , encodeGcmParams
  , gcmCodec
  , gcmCodecFor
  , gcmParamsValid
  , gcmRecipeFor
  , gcmRecipes
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
  , ckm_AES_GCM
  , ckm_SHA256
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
spec = testGroup "AES-GCM recipe"
  [ testCase "recipe table covers AES-GCM alone" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codec is gcm-params/1" caseCodec
  , testCase "params: caller IV, approved tag widths" caseParams
  , testCase "init enforces GCM params" caseInitParams
  , testCase "driver maps every triple to its AeadSpec" caseDriverMap
  ]

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 1 (length gcmRecipes)
  case gcmRecipes of
    [r] -> assertEqual "row" ("CKM_AES_GCM" :: Text) (gcmName r)
    rs -> assertFailure ("rows: " ++ show (length rs))

caseLookup :: IO ()
caseLookup = do
  case gcmRecipeFor (MechanismId ckm_AES_GCM) of
    Nothing -> assertFailure "unresolved CKM_AES_GCM"
    Just r -> assertEqual "lookup" ("CKM_AES_GCM" :: Text) (gcmName r)
  assertEqual "unknown id has no recipe" Nothing
    (gcmRecipeFor (MechanismId 0x4712))
  assertEqual "digest mech has no GCM recipe" Nothing
    (gcmRecipeFor (MechanismId ckm_SHA256))
  assertEqual "CBC has no GCM recipe" Nothing
    (gcmRecipeFor (MechanismId ckm_AES_CBC))

caseCodec :: IO ()
caseCodec = do
  assertEqual "group codec" (ParameterCodec "gcm-params" 1) gcmCodec
  case gcmRecipeFor (MechanismId ckm_AES_GCM) of
    Nothing -> assertFailure "unresolved CKM_AES_GCM"
    Just r -> assertEqual "row codec" gcmCodec (gcmCodecFor r)

recipeOf :: Text -> GcmRecipe
recipeOf name =
  case gcmRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ show name)

iv12 :: BS.ByteString
iv12 = "0123456789ab"

caseParams :: IO ()
caseParams = do
  let gcm = recipeOf "CKM_AES_GCM"
      good tag iv = encodeGcmParams iv "AD" tag
  -- Every approved tag width validates at the standard nonce.
  mapM_ (\t -> assertBool ("tag " ++ show t)
    (gcmParamsValid gcm (good t iv12))) [4, 8, 12, 13, 14, 15, 16]
  -- Unapproved widths refuse.
  mapM_ (\t -> assertBool ("tag refused " ++ show t)
    (not (gcmParamsValid gcm (good t iv12)))) [0, 1, 7, 11, 17, 32]
  -- IV bounds: 1..64 bytes.
  assertBool "iv 1 valid"
    (gcmParamsValid gcm (good 16 "x"))
  assertBool "iv 64 valid"
    (gcmParamsValid gcm (good 16 (BS.replicate 64 0)))
  assertBool "iv empty refused"
    (not (gcmParamsValid gcm (good 16 BS.empty)))
  assertBool "iv 65 refused"
    (not (gcmParamsValid gcm (good 16 (BS.replicate 65 0))))
  -- AAD is free-form (including empty); garbage never validates.
  assertBool "empty aad valid"
    (gcmParamsValid gcm (encodeGcmParams iv12 BS.empty 16))
  assertBool "garbage refused" (not (gcmParamsValid gcm "nope"))
  assertBool "truncated refused"
    (not (gcmParamsValid gcm (BS.take 20 (good 16 iv12))))

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

gcmMech :: MechanismId
gcmMech = MechanismId ckm_AES_GCM

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(gcmMech, OpEncrypt)]
  , oeModel = emptyModel
  }

-- | Unknown handle: valid parameters proceed PAST the parameter check
-- to key resolution (proving acceptance); bad parameters stop at
-- 'CKR_ARGUMENTS_BAD'.
badKey :: KeyPolicy
badKey = KeyPolicy (ExternalHandle 999) [OpEncrypt] False

runInit :: InitArgs -> ReturnCode
runInit args = ioCode (snd (initOperation testEnv emptySessionOps testSession args))

mkArgs :: MechanismId -> BS.ByteString -> InitArgs
mkArgs mech params = InitArgs OpEncrypt mech params (Just badKey)
  (Just (CipherSpec 1 False)) Nothing

caseInitParams :: IO ()
caseInitParams = do
  let good = encodeGcmParams iv12 "AD" 16
  assertEqual "empty iv refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs gcmMech (encodeGcmParams BS.empty "AD" 16)))
  assertEqual "bad tag refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs gcmMech (encodeGcmParams iv12 "AD" 7)))
  assertEqual "garbage refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs gcmMech "nope"))
  assertEqual "valid params pass to key resolution" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs gcmMech good))

caseDriverMap :: IO ()
caseDriverMap = do
  let params tag iv = encodeGcmParams iv "AD" tag
      p12 = params 16 iv12
  assertEqual "gcm-128" (Just (AeadSpec "AES-128-GCM" 12 16))
    (aeadSpecFor gcmMech 16 p12)
  assertEqual "gcm-192" (Just (AeadSpec "AES-192-GCM" 12 16))
    (aeadSpecFor gcmMech 24 p12)
  assertEqual "gcm-256" (Just (AeadSpec "AES-256-GCM" 12 16))
    (aeadSpecFor gcmMech 32 p12)
  -- The nonce length follows the IV; the tag width crosses intact.
  assertEqual "gcm-256 short iv/narrow tag"
    (Just (AeadSpec "AES-256-GCM" 8 12))
    (aeadSpecFor gcmMech 32 (params 12 "12345678"))
  assertEqual "gcm rejects bad keylen" Nothing
    (aeadSpecFor gcmMech 15 p12)
  assertEqual "gcm rejects bad tag" Nothing
    (aeadSpecFor gcmMech 32 (params 7 iv12))
  assertEqual "gcm rejects empty iv" Nothing
    (aeadSpecFor gcmMech 32 (params 16 BS.empty))
  assertEqual "non-gcm uncovered" Nothing
    (aeadSpecFor (MechanismId ckm_SHA256) 32 p12)
  -- Whole-table agreement: every (row, key length, tag width)
  -- triple maps with the recipe's own geometry.
  mapM_ (\n -> mapM_ (\t -> case aeadSpecFor gcmMech n (params t iv12) of
      Nothing -> assertFailure ("unmapped " ++ show n ++ "/" ++ show t)
      Just s -> do
        assertEqual ("alg " ++ show n) (algOf n) (aeadAlg s)
        assertEqual "nonce 12" 12 (aeadNonceLen s)
        assertEqual ("tag " ++ show t) t (aeadTagLen s)
      ) [4, 8, 12, 13, 14, 15, 16]
    ) [16, 24, 32]
  where
    algOf :: Int -> String
    algOf 16 = "AES-128-GCM"
    algOf 24 = "AES-192-GCM"
    algOf _ = "AES-256-GCM"
