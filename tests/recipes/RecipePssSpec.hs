{- | RSA-PSS recipe tests.

The PSS group: 10 header mechanisms sharing the salted parameter
shape — @pss-params\/1@: the hash code, the MGF1 hash code, and the
salt length (three 8-byte big-endian words). Digest-bound rows
(@CKM_*_RSA_PKCS_PSS@) fix the hash through the recipe; the generic
@CKM_RSA_PKCS_PSS@ row takes any recipe digest. 'Haskoki.Recipe.RsaPss'
owns the group's canonical codec, parameter validation, digest
bindings, and mechanism table; these tests pin the recipe and its
three consumers:

* the model init path enforces PSS parameters ('validateInit',
  'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, params) pair to its
  backend 'SigSpec' ('rsaPssSpecFor' agrees with the recipe table);
* engines execute the pinned specs (SyntheticSpec roundtrips,
  OpenSSLSpec interop vectors against the pinned libcrypto).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipePssSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (DigestAlg (..), PssParams (..), SigSpec (..))
import Haskoki.Engine.Driver (rsaPssSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.RsaPss
  ( RsaPssRecipe (..)
  , decodePssParams
  , encodePssParams
  , rsaPssCodec
  , rsaPssCodecFor
  , rsaPssParamsValid
  , rsaPssRecipeFor
  , rsaPssRecipes
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
  , ckm_RSA_PKCS_OAEP
  , ckm_SHA256_RSA_PKCS
  , ckm_SHA256_RSA_PKCS_PSS
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
spec = testGroup "RSA-PSS recipe"
  [ testCase "recipe table covers 10 mechanisms with digests" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codec is pss-params/1 with a fixed golden" caseCodec
  , testCase "params: digest-bound, mgf-coded, salt 0..64" caseParams
  , testCase "init enforces PSS params" caseInitParams
  , testCase "driver maps every recipe to its SigSpec" caseDriverMap
  ]

-- | (Name suffix, bound digest stem or Nothing, backend alg).
groupShape :: [(Text, Maybe Text, Maybe DigestAlg)]
groupShape =
  [ ("RSA_PKCS_PSS", Nothing, Nothing)
  , ("SHA1_RSA_PKCS_PSS", Just "SHA_1", Just D_SHA1)
  , ("SHA224_RSA_PKCS_PSS", Just "SHA224", Just D_SHA224)
  , ("SHA256_RSA_PKCS_PSS", Just "SHA256", Just D_SHA256)
  , ("SHA384_RSA_PKCS_PSS", Just "SHA384", Just D_SHA384)
  , ("SHA512_RSA_PKCS_PSS", Just "SHA512", Just D_SHA512)
  , ("SHA3_224_RSA_PKCS_PSS", Just "SHA3_224", Just D_SHA3_224)
  , ("SHA3_256_RSA_PKCS_PSS", Just "SHA3_256", Just D_SHA3_256)
  , ("SHA3_384_RSA_PKCS_PSS", Just "SHA3_384", Just D_SHA3_384)
  , ("SHA3_512_RSA_PKCS_PSS", Just "SHA3_512", Just D_SHA3_512)
  ]

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 10 (length rsaPssRecipes)
  mapM_ (\(suffix, stem, _alg) -> do
    let name = mechName suffix
        found = [ r | r <- rsaPssRecipes, rpName r == name ]
    case found of
      [r] -> assertEqual ("digest " ++ T.unpack name) stem (rpDigestStem r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _, _) -> do
    let name = mechName suffix
    case rsaPssRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (rpName r)
    ) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (rsaPssRecipeFor (MechanismId 0x4712))
  assertEqual "v1.5 has no PSS recipe" Nothing
    (rsaPssRecipeFor (MechanismId (ckm_SHA256_RSA_PKCS)))
  assertEqual "OAEP has no PSS recipe" Nothing
    (rsaPssRecipeFor (MechanismId (ckm_RSA_PKCS_OAEP)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "pss codec" (ParameterCodec "pss-params" 1) rsaPssCodec
  mapM_ (\(suffix, _, _) -> do
    let name = mechName suffix
    case rsaPssRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("codec " ++ T.unpack name) rsaPssCodec
        (rsaPssCodecFor r)
    ) groupShape
  -- Golden: SHA-256 (code 4) / MGF1-SHA-256 (code 4) / salt 32.
  assertEqual "pss golden" (BS.pack
    [0,0,0,0,0,0,0,4, 0,0,0,0,0,0,0,4, 0,0,0,0,0,0,0,32])
    (encodePssParams "SHA256" "SHA256" 32)
  assertEqual "pss round-trip" (Just ("SHA256", "SHA384", 20))
    (decodePssParams (encodePssParams "SHA256" "SHA384" 20))
  assertEqual "pss short rejected" Nothing
    (decodePssParams (BS.replicate 23 0))
  assertEqual "pss long rejected" Nothing
    (decodePssParams (BS.replicate 25 0))
  assertEqual "pss empty rejected" Nothing (decodePssParams BS.empty)

recipeOf :: Text -> RsaPssRecipe
recipeOf name =
  case rsaPssRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

caseParams :: IO ()
caseParams = do
  let bound = recipeOf "CKM_SHA256_RSA_PKCS_PSS"
  assertBool "bound matching valid"
    (rsaPssParamsValid bound (encodePssParams "SHA256" "SHA256" 32))
  assertBool "bound mgf may differ"
    (rsaPssParamsValid bound (encodePssParams "SHA256" "SHA512" 32))
  assertBool "bound wrong digest refused"
    (not (rsaPssParamsValid bound (encodePssParams "SHA512" "SHA512" 32)))
  assertBool "bound salt 0 valid"
    (rsaPssParamsValid bound (encodePssParams "SHA256" "SHA256" 0))
  assertBool "bound salt 64 valid"
    (rsaPssParamsValid bound (encodePssParams "SHA256" "SHA256" 64))
  assertBool "bound salt 65 refused"
    (not (rsaPssParamsValid bound (encodePssParams "SHA256" "SHA256" 65)))
  assertBool "bound empty refused"
    (not (rsaPssParamsValid bound BS.empty))
  let generic = recipeOf "CKM_RSA_PKCS_PSS"
  assertBool "generic sha256 valid"
    (rsaPssParamsValid generic (encodePssParams "SHA256" "SHA256" 32))
  assertBool "generic sha512 valid"
    (rsaPssParamsValid generic (encodePssParams "SHA512" "SHA_1" 20))
  assertBool "generic salt 65 refused"
    (not (rsaPssParamsValid generic (encodePssParams "SHA256" "SHA256" 65)))
  -- Unknown digest codes never validate (strict 24-byte words with
  -- out-of-table codes).
  assertBool "unknown digest refused"
    (not (rsaPssParamsValid generic (BS.pack
      [0,0,0,0,0,0,0,99, 0,0,0,0,0,0,0,4, 0,0,0,0,0,0,0,32])))
  assertBool "unknown mgf refused"
    (not (rsaPssParamsValid generic (BS.pack
      [0,0,0,0,0,0,0,4, 0,0,0,0,0,0,0,99, 0,0,0,0,0,0,0,32])))
  -- Every bound row enforces its own digest.
  mapM_ (\(suffix, stem, _alg) -> case stem of
    Nothing -> pure ()
    Just d -> do
      let r = recipeOf (mechName suffix)
      assertBool ("bound ok " ++ T.unpack suffix)
        (rsaPssParamsValid r (encodePssParams d "SHA256" 32))
      assertBool ("bound mismatch refused " ++ T.unpack suffix)
        (not (rsaPssParamsValid r (encodePssParams "SHA256" "SHA256" 32))
          || d == "SHA256")
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

pssMech :: MechanismId
pssMech = MechanismId (ckm_SHA256_RSA_PKCS_PSS)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(pssMech, OpSign)]
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
    (runInit (InitArgs OpSign pssMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "wrong digest refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign pssMech (encodePssParams "SHA512" "SHA512" 32)
      (Just badKey) Nothing Nothing))
  assertEqual "salt 65 refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign pssMech (encodePssParams "SHA256" "SHA256" 65)
      (Just badKey) Nothing Nothing))
  assertEqual "valid passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign pssMech (encodePssParams "SHA256" "SHA256" 32)
      (Just badKey) Nothing Nothing))

caseDriverMap :: IO ()
caseDriverMap =
  mapM_ (\(suffix, stem, alg) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
        hashStem = case stem of
          Nothing -> "SHA256"
          Just d -> d
        hashAlg = case alg of
          Nothing -> D_SHA256
          Just a -> a
        want = SigRSA_PSS (PssParams hashAlg D_SHA384 20)
    assertEqual ("driver " ++ T.unpack suffix) (Just want)
      (rsaPssSpecFor mech (encodePssParams hashStem "SHA384" 20))
    assertEqual ("driver rejects empty " ++ T.unpack suffix) Nothing
      (rsaPssSpecFor mech BS.empty)
    ) groupShape
