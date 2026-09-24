{- | RSA-OAEP recipe tests.

The OAEP group: one header mechanism (@CKM_RSA_PKCS_OAEP@) with the
labeled parameter shape — @oaep-params\/1@: the hash code, the MGF1
hash code (two 8-byte big-endian words), and the trailing label
bytes (possibly empty). 'Haskoki.Recipe.RsaOaep' owns the group's
canonical codec, parameter validation, and mechanism table; these
tests pin the recipe and its three consumers:

* the model init path enforces OAEP parameters and refuses padded
  cipher specs for the RSA row ('validateInit', 'CKR_ARGUMENTS_BAD':
  the block-cipher planner's PKCS#7 framing must never cover an
  asymmetric operation);
* the driver maps the covered (mechanism, params) pair to its
  backend 'OaepParams' ('rsaOaepParamsFor') and routes OAEP cipher
  effects to the asymmetric backend entry points;
* engines execute the pinned params (SyntheticSpec roundtrips,
  OpenSSLSpec interop vectors against the pinned libcrypto).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeOaepSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (DigestAlg (..), OaepParams (..))
import Haskoki.Engine.Driver (rsaOaepParamsFor)
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
import Haskoki.Recipe.RsaOaep
  ( RsaOaepRecipe (..)
  , decodeOaepParams
  , encodeOaepParams
  , rsaOaepCodec
  , rsaOaepCodecFor
  , rsaOaepParamsValid
  , rsaOaepRecipeFor
  , rsaOaepRecipes
  )
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , ParameterCodec (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Registry.Generated (mustGeneratedId, ckm_RSA_PKCS, ckm_RSA_PKCS_PSS)
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
spec = testGroup "RSA-OAEP recipe"
  [ testCase "recipe table covers CKM_RSA_PKCS_OAEP" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codec is oaep-params/1 with a fixed golden" caseCodec
  , testCase "params: coded hashes, free label" caseParams
  , testCase "init enforces OAEP params, refuses padding" caseInitParams
  , testCase "driver maps params to OaepParams" caseDriverMap
  ]

oaepName :: Text
oaepName = "CKM_RSA_PKCS_OAEP"

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 1 (length rsaOaepRecipes)
  case rsaOaepRecipes of
    [r] -> assertEqual "row name" oaepName (roName r)
    rs -> assertFailure ("rows: " ++ show (length rs))

caseLookup :: IO ()
caseLookup = do
  case rsaOaepRecipeFor (MechanismId (mustGeneratedId oaepName)) of
    Nothing -> assertFailure "unresolved CKM_RSA_PKCS_OAEP"
    Just r -> assertEqual "lookup" oaepName (roName r)
  assertEqual "unknown id has no recipe" Nothing
    (rsaOaepRecipeFor (MechanismId 0x4712))
  assertEqual "v1.5 has no OAEP recipe" Nothing
    (rsaOaepRecipeFor (MechanismId (ckm_RSA_PKCS)))
  assertEqual "PSS has no OAEP recipe" Nothing
    (rsaOaepRecipeFor (MechanismId (ckm_RSA_PKCS_PSS)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "oaep codec" (ParameterCodec "oaep-params" 1) rsaOaepCodec
  case rsaOaepRecipes of
    [r] -> assertEqual "row codec" rsaOaepCodec (rsaOaepCodecFor r)
    _ -> assertFailure "row count"
  -- Golden: SHA-256 (code 4) / MGF1-SHA-256 (code 4) / "label".
  assertEqual "oaep golden"
    (BS.pack [0,0,0,0,0,0,0,4, 0,0,0,0,0,0,0,4] <> "label")
    (encodeOaepParams "SHA256" "SHA256" "label")
  assertEqual "oaep round-trip" (Just ("SHA_1", "SHA256", ""))
    (decodeOaepParams (encodeOaepParams "SHA_1" "SHA256" ""))
  assertEqual "oaep label round-trip" (Just ("SHA256", "SHA_1", "label-9"))
    (decodeOaepParams (encodeOaepParams "SHA256" "SHA_1" "label-9"))
  assertEqual "oaep short rejected" Nothing
    (decodeOaepParams (BS.replicate 15 0))
  assertEqual "oaep empty rejected" Nothing (decodeOaepParams BS.empty)

recipeOf :: Text -> RsaOaepRecipe
recipeOf name =
  case rsaOaepRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ show name)

caseParams :: IO ()
caseParams = do
  let r = recipeOf oaepName
  assertBool "empty label valid"
    (rsaOaepParamsValid r (encodeOaepParams "SHA256" "SHA256" ""))
  assertBool "label valid"
    (rsaOaepParamsValid r (encodeOaepParams "SHA_1" "SHA_1" "label"))
  assertBool "empty refused" (not (rsaOaepParamsValid r BS.empty))
  assertBool "short refused"
    (not (rsaOaepParamsValid r (BS.replicate 15 0)))
  assertBool "unknown hash refused"
    (not (rsaOaepParamsValid r (BS.pack
      [0,0,0,0,0,0,0,99, 0,0,0,0,0,0,0,4])))
  assertBool "unknown mgf refused"
    (not (rsaOaepParamsValid r (BS.pack
      [0,0,0,0,0,0,0,4, 0,0,0,0,0,0,0,99])))

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

oaepMech :: MechanismId
oaepMech = MechanismId (mustGeneratedId oaepName)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(oaepMech, OpEncrypt)]
  , oeModel = emptyModel
  }

-- | Unknown handle: valid parameters proceed PAST the parameter check
-- to key resolution (proving acceptance); bad parameters stop at
-- 'CKR_ARGUMENTS_BAD'.
badKey :: KeyPolicy
badKey = KeyPolicy (ExternalHandle 999) [OpEncrypt] False

runInit :: InitArgs -> ReturnCode
runInit args = ioCode (snd (initOperation testEnv emptySessionOps testSession args))

caseInitParams :: IO ()
caseInitParams = do
  let valid = encodeOaepParams "SHA256" "SHA256" ""
  assertEqual "empty params refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpEncrypt oaepMech BS.empty
      (Just badKey) (Just (CipherSpec 256 False)) Nothing))
  assertEqual "short params refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpEncrypt oaepMech (BS.replicate 15 0)
      (Just badKey) (Just (CipherSpec 256 False)) Nothing))
  assertEqual "padded spec refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpEncrypt oaepMech valid
      (Just badKey) (Just (CipherSpec 256 True)) Nothing))
  assertEqual "valid passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpEncrypt oaepMech valid
      (Just badKey) (Just (CipherSpec 256 False)) Nothing))

caseDriverMap :: IO ()
caseDriverMap = do
  assertEqual "driver labeled"
    (Just (OaepParams D_SHA256 D_SHA256 "label"))
    (rsaOaepParamsFor oaepMech (encodeOaepParams "SHA256" "SHA256" "label"))
  assertEqual "driver sha1 pair"
    (Just (OaepParams D_SHA1 D_SHA1 ""))
    (rsaOaepParamsFor oaepMech (encodeOaepParams "SHA_1" "SHA_1" ""))
  assertEqual "driver rejects empty" Nothing
    (rsaOaepParamsFor oaepMech BS.empty)
  assertEqual "driver rejects short" Nothing
    (rsaOaepParamsFor oaepMech (BS.replicate 15 0))
  assertEqual "non-oaep uncovered" Nothing
    (rsaOaepParamsFor (MechanismId (ckm_RSA_PKCS))
      (encodeOaepParams "SHA256" "SHA256" ""))
