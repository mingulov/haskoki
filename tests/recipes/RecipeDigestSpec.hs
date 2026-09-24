{- | digest-shape recipe tests.

The digest group: 13 header mechanisms sharing the no-params digest
shape (one-shot plus multipart init\/update\/final, empty mechanism
parameters, fixed output width per algorithm). 'Haskoki.Recipe.Digest'
owns the group's canonical codec, parameter validation, output
widths, and mechanism table; these tests pin the recipe and its two
consumers:

* the model init path refuses non-empty digest mechanism parameters
  ('validateInit', 'CKR_ARGUMENTS_BAD');
* the driver maps every covered mechanism to its backend algorithm
  ('digestAlgFor' agrees with the recipe table);
* widths pin the synthetic output contract per algorithm (executed
  against the synthetic backend in SyntheticSpec, against libcrypto
  KATs in OpenSSLSpec).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeDigestSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (DigestAlg (..))
import Haskoki.Engine.Driver (digestAlgFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.Digest
  ( DigestRecipe (..)
  , digestCodec
  , digestParamsValid
  , digestRecipeFor
  , digestRecipes
  )
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , ParameterCodec (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( Generation (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Digest recipe"
  [ testCase "recipe table covers 13 mechanisms with widths" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "digest codec is no-params/1" caseCodec
  , testCase "empty params valid, non-empty refused" caseParams
  , testCase "init refuses non-empty digest params" caseInitRefusesParams
  , testCase "driver maps every recipe to its backend alg" caseDriverMap
  ]

-- | (CKM name, output width, backend alg): the group's shared shape.
groupShape :: [(Text, Int, DigestAlg)]
groupShape =
  [ ("CKM_SHA224", 28, D_SHA224)
  , ("CKM_SHA256", 32, D_SHA256)
  , ("CKM_SHA384", 48, D_SHA384)
  , ("CKM_SHA512", 64, D_SHA512)
  , ("CKM_SHA512_224", 28, D_SHA512_224)
  , ("CKM_SHA512_256", 32, D_SHA512_256)
  , ("CKM_SHA3_224", 28, D_SHA3_224)
  , ("CKM_SHA3_256", 32, D_SHA3_256)
  , ("CKM_SHA3_384", 48, D_SHA3_384)
  , ("CKM_SHA3_512", 64, D_SHA3_512)
  , ("CKM_SHA_1", 20, D_SHA1)
  , ("CKM_MD5", 16, D_MD5)
  , ("CKM_RIPEMD160", 20, D_RIPEMD160)
  ]

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 13 (length digestRecipes)
  let widthOf name =
        [ drOutLen r | r <- digestRecipes, drName r == name ]
  mapM_ (\(name, width, _alg) ->
    assertEqual ("width " ++ T.unpack name) [width] (widthOf name)) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(name, _width, _alg) ->
    case digestRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (drName r)) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (digestRecipeFor (MechanismId 0x4712))

caseCodec :: IO ()
caseCodec =
  assertEqual "digest codec" (ParameterCodec "no-params" 1) digestCodec

caseParams :: IO ()
caseParams = do
  assertBool "empty valid" (digestParamsValid BS.empty)
  assertBool "non-empty refused" (not (digestParamsValid "x"))
  assertBool "iv-length refused" (not (digestParamsValid (BS.replicate 16 0)))

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
  , oeCaps = mkCapabilities [(MechanismId 0x250, OpDigest)]
  , oeModel = emptyModel
  }

caseInitRefusesParams :: IO ()
caseInitRefusesParams = do
  let badArgs = InitArgs OpDigest (MechanismId 0x250) "params" Nothing Nothing Nothing
      (_, badOut) = initOperation testEnv emptySessionOps testSession badArgs
  assertEqual "refusal code" CKR_ARGUMENTS_BAD (ioCode badOut)
  let goodArgs = InitArgs OpDigest (MechanismId 0x250) BS.empty Nothing Nothing Nothing
      (_, goodOut) = initOperation testEnv emptySessionOps testSession goodArgs
  assertEqual "empty params pass" CKR_OK (ioCode goodOut)

caseDriverMap :: IO ()
caseDriverMap =
  mapM_ (\(name, _width, alg) ->
    assertEqual ("driver alg " ++ T.unpack name) (Just alg)
      (digestAlgFor (MechanismId (mustGeneratedId name)))) groupShape
