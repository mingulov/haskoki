{- | Poly1305 recipe tests (slice 11o, stage 1).

'Haskoki.Recipe.Poly1305' owns the group's canonical codec,
parameter validation, key rule, and mechanism table;
'Haskoki.Operation.validateInit' enforces empty parameters and
the CKK_POLY1305 key type; 'Haskoki.Engine.Driver.poly1305MacFor'
maps the covered (mechanism, params) pair to its backend
'MacSpec' (the key rule lives at init; the provider refuses
off-length keys). This spec pins the table, id resolution, codec
identity, the empty-only parameter matrix, the key rule, and
the driver mapping.

Ground truth (pinned 4.0.2 CLI @openssl mac POLY1305@ vs
python-cryptography, agreeing): key
60ae20bd9302aea34cafbc620011e17b7774e97764b9bb6e035ffb2b8b63be9f
over "Poly1305 KAT message, second vector" tags
f70a350ed794a7e0660bba7638f5a6d2. The oracle (@TestPoly1305@)
roundtrips generated keys, asserts the 16-byte tag, and checks
tamper failure plus key independence.
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipePoly1305Spec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Engine.Backend (MacSpec (..))
import Haskoki.Engine.Driver (poly1305MacFor)
import Haskoki.Recipe.Poly1305
  ( Poly1305Recipe (..)
  , poly1305Codec
  , poly1305CodecFor
  , poly1305KeyLen
  , poly1305KeyOk
  , poly1305ParamsValid
  , poly1305RecipeFor
  , poly1305Recipes
  , poly1305TagLen
  )
import Haskoki.Registry.Generated (ckm_POLY1305)
import Haskoki.Registry.Types (MechanismId (..), ParameterCodec (..))

spec :: TestTree
spec = testGroup "Poly1305 recipe"
  [ testCase "one-row table" caseTable
  , testCase "id resolution" caseResolve
  , testCase "codec identity" caseCodec
  , testCase "params empty-only" caseParams
  , testCase "key rule" caseKey
  , testCase "driver mapping" caseDriver
  ]

polyMech :: MechanismId
polyMech = MechanismId ckm_POLY1305

caseTable :: IO ()
caseTable = do
  assertEqual "row count" 1 (length poly1305Recipes)
  assertEqual "row names"
    ["CKM_POLY1305" :: Text]
    (map polyName poly1305Recipes)

caseResolve :: IO ()
caseResolve = do
  assertEqual "poly resolves"
    (Just (head poly1305Recipes)) (poly1305RecipeFor polyMech)
  assertEqual "foreign id resolves to Nothing"
    Nothing (poly1305RecipeFor (MechanismId 0xdead))

caseCodec :: IO ()
caseCodec = do
  assertEqual "canonical codec"
    (ParameterCodec "no-params" 1) poly1305Codec
  mapM_ (\r -> assertEqual "row codec" poly1305Codec (poly1305CodecFor r))
    poly1305Recipes

caseParams :: IO ()
caseParams =
  mapM_ (\r -> do
    assertBool "empty params validate" (poly1305ParamsValid r BS.empty)
    assertBool "non-empty params refuse"
      (not (poly1305ParamsValid r (BS.pack [0]))))
    poly1305Recipes

caseKey :: IO ()
caseKey = do
  assertEqual "key length" 32 poly1305KeyLen
  assertEqual "tag length" 16 poly1305TagLen
  let poly = mustKeyTypeId "CKK_POLY1305"
      generic = mustKeyTypeId "CKK_GENERIC_SECRET"
  assertBool "poly1305 32-byte key ok" (poly1305KeyOk poly 32)
  assertBool "short key refuses" (not (poly1305KeyOk poly 16))
  assertBool "long key refuses" (not (poly1305KeyOk poly 64))
  assertBool "foreign key type refuses" (not (poly1305KeyOk generic 32))

caseDriver :: IO ()
caseDriver = do
  assertEqual "covered pair maps"
    (Just MacPoly1305) (poly1305MacFor polyMech BS.empty)
  assertEqual "non-empty params refuse"
    Nothing (poly1305MacFor polyMech (BS.pack [0]))
  assertEqual "foreign mechanism refuses"
    Nothing (poly1305MacFor (MechanismId 0xdead) BS.empty)
