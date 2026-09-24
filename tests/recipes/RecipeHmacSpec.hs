{- | HMAC-shape recipe tests.

The HMAC group: 26 header mechanisms sharing two parameter shapes
over 13 digests — plain @CKM_*_HMAC@ (empty mechanism parameters,
full-width tag) and @CKM_*_HMAC_GENERAL@ (@CK_MAC_GENERAL_PARAMS@:
desired tag length, truncated tag). 'Haskoki.Recipe.Hmac' owns the
group's canonical codecs, parameter validation, output widths, and
mechanism table; these tests pin the recipe and its three consumers:

* the model init path enforces per-mechanism HMAC parameters
  ('validateInit', 'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, params) pair to its
  backend 'MacSpec' ('hmacSpecFor' agrees with the recipe table,
  threading the GENERAL length);
* engine tag widths agree with the recipe ('macOutLen' law; executed
  against the synthetic backend in SyntheticSpec, against libcrypto
  KATs in OpenSSLSpec).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeHmacSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (DigestAlg (..), MacSpec (..), digestOutLen)
import Haskoki.Engine.Driver (hmacSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.Hmac
  ( HmacRecipe (..)
  , decodeMacGeneral
  , encodeMacGeneral
  , hmacCodecFor
  , hmacGeneralCodec
  , hmacParamsValid
  , hmacPlainCodec
  , hmacRecipeFor
  , hmacRecipes
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
  , ckm_ECDSA
  , ckm_SHA256
  , ckm_SHA256_HMAC
  , ckm_SHA256_HMAC_GENERAL
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
spec = testGroup "HMAC recipe"
  [ testCase "recipe table covers 26 mechanisms with widths" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "plain codec is no-params/1, general is mac-general/1" caseCodec
  , testCase "params: plain empty-only, general length-in-range" caseParams
  , testCase "mac-general codec round-trips strict 8-byte BE" caseCodecRoundTrip
  , testCase "init enforces per-mechanism HMAC params" caseInitParams
  , testCase "driver maps every recipe to its MacSpec" caseDriverMap
  , testCase "engine widths agree with the recipe" caseWidthLaw
  ]

-- | (Digest stem, output width, backend alg): the group's shared shape.
-- Each stem yields a plain and a GENERAL mechanism.
groupShape :: [(Text, Int, DigestAlg)]
groupShape =
  [ ("SHA224", 28, D_SHA224)
  , ("SHA256", 32, D_SHA256)
  , ("SHA384", 48, D_SHA384)
  , ("SHA512", 64, D_SHA512)
  , ("SHA512_224", 28, D_SHA512_224)
  , ("SHA512_256", 32, D_SHA512_256)
  , ("SHA3_224", 28, D_SHA3_224)
  , ("SHA3_256", 32, D_SHA3_256)
  , ("SHA3_384", 48, D_SHA3_384)
  , ("SHA3_512", 64, D_SHA3_512)
  , ("SHA_1", 20, D_SHA1)
  , ("MD5", 16, D_MD5)
  , ("RIPEMD160", 20, D_RIPEMD160)
  ]

plainName :: Text -> Text
plainName stem = "CKM_" <> stem <> "_HMAC"

generalName :: Text -> Text
generalName stem = "CKM_" <> stem <> "_HMAC_GENERAL"

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 26 (length hmacRecipes)
  let find name =
        [ r | r <- hmacRecipes, hrName r == name ]
  mapM_ (\(stem, width, _alg) -> do
    case find (plainName stem) of
      [r] -> do
        assertEqual ("plain width " ++ T.unpack stem) width (hrOutLen r)
        assertBool ("plain not general " ++ T.unpack stem) (not (hrGeneral r))
      rs -> assertFailure ("plain rows " ++ T.unpack stem ++ ": " ++ show (length rs))
    case find (generalName stem) of
      [r] -> do
        assertEqual ("general width " ++ T.unpack stem) width (hrOutLen r)
        assertBool ("general flag " ++ T.unpack stem) (hrGeneral r)
      rs -> assertFailure ("general rows " ++ T.unpack stem ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(stem, _width, _alg) ->
    mapM_ (\name ->
      case hmacRecipeFor (MechanismId (mustGeneratedId name)) of
        Nothing -> assertFailure ("unresolved " ++ T.unpack name)
        Just r -> assertEqual ("lookup " ++ T.unpack name) name (hrName r))
      [plainName stem, generalName stem]) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (hmacRecipeFor (MechanismId 0x4712))
  assertEqual "digest mech has no HMAC recipe" Nothing
    (hmacRecipeFor (MechanismId (ckm_SHA256)))
  assertEqual "ECDSA has no HMAC recipe" Nothing
    (hmacRecipeFor (MechanismId (ckm_ECDSA)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "plain codec" (ParameterCodec "no-params" 1) hmacPlainCodec
  assertEqual "general codec" (ParameterCodec "mac-general" 1) hmacGeneralCodec
  mapM_ (\(stem, _width, _alg) ->
    mapM_ (\(name, want) ->
      case hmacRecipeFor (MechanismId (mustGeneratedId name)) of
        Nothing -> assertFailure ("unresolved " ++ T.unpack name)
        Just r -> assertEqual ("codec " ++ T.unpack name) want (hmacCodecFor r))
      [ (plainName stem, hmacPlainCodec)
      , (generalName stem, hmacGeneralCodec)
      ]) groupShape

recipeOf :: Text -> HmacRecipe
recipeOf name =
  case hmacRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

caseParams :: IO ()
caseParams = do
  let pr = recipeOf "CKM_SHA256_HMAC"
  assertBool "plain empty valid" (hmacParamsValid pr BS.empty)
  assertBool "plain non-empty refused" (not (hmacParamsValid pr "x"))
  assertBool "plain general-encoding refused"
    (not (hmacParamsValid pr (encodeMacGeneral 16)))
  let gr = recipeOf "CKM_SHA256_HMAC_GENERAL"
  assertBool "general empty refused" (not (hmacParamsValid gr BS.empty))
  assertBool "general full width valid"
    (hmacParamsValid gr (encodeMacGeneral 32))
  assertBool "general truncated valid"
    (hmacParamsValid gr (encodeMacGeneral 16))
  assertBool "general 1 valid" (hmacParamsValid gr (encodeMacGeneral 1))
  assertBool "general 0 refused" (not (hmacParamsValid gr (encodeMacGeneral 0)))
  assertBool "general width+1 refused"
    (not (hmacParamsValid gr (encodeMacGeneral 33)))
  assertBool "general 4-byte refused"
    (not (hmacParamsValid gr (BS.replicate 4 0)))
  assertBool "general 9-byte refused"
    (not (hmacParamsValid gr (BS.replicate 9 0)))
  -- Every GENERAL row enforces its own width as the ceiling.
  mapM_ (\(stem, width, _alg) -> do
    let r = recipeOf (generalName stem)
    assertBool ("ceiling ok " ++ T.unpack stem)
      (hmacParamsValid r (encodeMacGeneral width))
    assertBool ("ceiling+1 refused " ++ T.unpack stem)
      (not (hmacParamsValid r (encodeMacGeneral (width + 1))))
    ) groupShape

caseCodecRoundTrip :: IO ()
caseCodecRoundTrip = do
  assertEqual "encodes caller-native LE" (BS.pack [16,0,0,0,0,0,0,0]) (encodeMacGeneral 16)
  assertEqual "round-trip" (Just 16) (decodeMacGeneral (encodeMacGeneral 16))
  assertEqual "round-trip 1" (Just 1) (decodeMacGeneral (encodeMacGeneral 1))
  assertEqual "empty rejected" Nothing (decodeMacGeneral BS.empty)
  assertEqual "short rejected" Nothing (decodeMacGeneral (BS.replicate 7 0))
  assertEqual "long rejected" Nothing (decodeMacGeneral (BS.replicate 9 0))

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

plainMech, generalMech :: MechanismId
plainMech = MechanismId (ckm_SHA256_HMAC)
generalMech = MechanismId (ckm_SHA256_HMAC_GENERAL)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(plainMech, OpSign), (generalMech, OpSign)]
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
  assertEqual "plain non-empty refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign plainMech "x" (Just badKey) Nothing Nothing))
  assertEqual "plain empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign plainMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "general empty refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign generalMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "general valid passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign generalMech (encodeMacGeneral 16) (Just badKey) Nothing Nothing))
  assertEqual "general zero refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign generalMech (encodeMacGeneral 0) (Just badKey) Nothing Nothing))
  assertEqual "general over-width refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign generalMech (encodeMacGeneral 33) (Just badKey) Nothing Nothing))

caseDriverMap :: IO ()
caseDriverMap =
  mapM_ (\(stem, width, alg) -> do
    assertEqual ("driver plain " ++ T.unpack stem)
      (Just (MacHMAC alg Nothing))
      (hmacSpecFor (MechanismId (mustGeneratedId (plainName stem))) BS.empty)
    assertEqual ("driver plain rejects params " ++ T.unpack stem)
      Nothing
      (hmacSpecFor (MechanismId (mustGeneratedId (plainName stem))) "x")
    assertEqual ("driver general " ++ T.unpack stem)
      (Just (MacHMAC alg (Just (width - 1))))
      (hmacSpecFor (MechanismId (mustGeneratedId (generalName stem)))
        (encodeMacGeneral (width - 1)))
    assertEqual ("driver general rejects empty " ++ T.unpack stem)
      Nothing
      (hmacSpecFor (MechanismId (mustGeneratedId (generalName stem))) BS.empty)
    ) groupShape

caseWidthLaw :: IO ()
caseWidthLaw = do
  mapM_ (\(_stem, width, alg) ->
    assertEqual ("engine width " ++ show alg) (Just width) (digestOutLen alg)) groupShape
  assertEqual "SHAKE128 has no fixed width" Nothing (digestOutLen D_SHAKE128)
  assertEqual "SHAKE256 has no fixed width" Nothing (digestOutLen D_SHAKE256)
