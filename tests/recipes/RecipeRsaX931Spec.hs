{- | RSA-X9.31 recipe tests (slice 11o, stage 1).

'Haskoki.Recipe.RsaX931' owns the group's canonical codec,
parameter validation, digest-length rule, and mechanism table;
'Haskoki.Operation.validateInit' enforces empty parameters;
'Haskoki.Engine.Driver.rsaX931SigFor' maps the covered
(mechanism, params) pair to its backend 'SigSpec'. This spec
pins the table, id resolution, codec identity, the empty-only
parameter matrix, the raw digest-length rule, and the driver
mapping.

Ground truth (pinned 4.0.2 CLI + provider probes, independent
of the token): X9.31 sign needs the digest set before the pad
mode (@invalid x931 digest@ otherwise); prehash roundtrips for
20\/32\/48\/64-byte inputs (SHA-1\/SHA-256\/SHA-384\/SHA-512
hash ids); SHA-224 and digest-less operation refuse. The
oracle sends 20- and 32-byte digests only (TestRSAX931).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeRsaX931Spec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Engine.Backend (DigestAlg (..), SigSpec (..))
import Haskoki.Engine.Driver (rsaX931SigFor)
import Haskoki.Recipe.RsaX931
  ( RsaX931Recipe (..)
  , rsaX931Codec
  , rsaX931CodecFor
  , rsaX931DigestOfLen
  , rsaX931ParamsValid
  , rsaX931RecipeFor
  , rsaX931Recipes
  , x931Digests
  )
import Haskoki.Registry.Generated (ckm_RSA_X9_31, ckm_SHA1_RSA_X9_31)
import Haskoki.Registry.Types (MechanismId (..), ParameterCodec (..))

spec :: TestTree
spec = testGroup "RSA-X9.31 recipe"
  [ testCase "two-row table" caseTable
  , testCase "id resolution" caseResolve
  , testCase "codec identity" caseCodec
  , testCase "params empty-only" caseParams
  , testCase "raw digest-length rule" caseDigestRule
  , testCase "driver mapping" caseDriver
  ]

x931Mech :: MechanismId
x931Mech = MechanismId ckm_RSA_X9_31

sha1Mech :: MechanismId
sha1Mech = MechanismId ckm_SHA1_RSA_X9_31

caseTable :: IO ()
caseTable = do
  assertEqual "row count" 2 (length rsaX931Recipes)
  assertEqual "row names"
    ["CKM_RSA_X9_31", "CKM_SHA1_RSA_X9_31" :: Text]
    (map rx931Name rsaX931Recipes)

caseResolve :: IO ()
caseResolve = do
  assertEqual "raw resolves"
    (Just (head rsaX931Recipes)) (rsaX931RecipeFor x931Mech)
  assertEqual "sha1 resolves"
    (Just (rsaX931Recipes !! 1)) (rsaX931RecipeFor sha1Mech)
  assertEqual "foreign id resolves to Nothing"
    Nothing (rsaX931RecipeFor (MechanismId 0xdead))

caseCodec :: IO ()
caseCodec = do
  assertEqual "canonical codec"
    (ParameterCodec "no-params" 1) rsaX931Codec
  mapM_ (\r -> assertEqual "row codec" rsaX931Codec (rsaX931CodecFor r))
    rsaX931Recipes

caseParams :: IO ()
caseParams =
  mapM_ (\r -> do
    assertBool "empty params validate" (rsaX931ParamsValid r BS.empty)
    assertBool "non-empty params refuse"
      (not (rsaX931ParamsValid r (BS.pack [0]))))
    rsaX931Recipes

caseDigestRule :: IO ()
caseDigestRule = do
  assertEqual "served lengths"
    [20, 32, 48, 64] (map fst x931Digests)
  assertEqual "20 -> SHA1" (Just "SHA1") (rsaX931DigestOfLen 20)
  assertEqual "32 -> SHA256" (Just "SHA256") (rsaX931DigestOfLen 32)
  assertEqual "48 -> SHA384" (Just "SHA384") (rsaX931DigestOfLen 48)
  assertEqual "64 -> SHA512" (Just "SHA512") (rsaX931DigestOfLen 64)
  assertEqual "28 (SHA224) refuses" Nothing (rsaX931DigestOfLen 28)
  assertEqual "16 (MD5) refuses" Nothing (rsaX931DigestOfLen 16)
  assertEqual "0 refuses" Nothing (rsaX931DigestOfLen 0)
  assertEqual "33 refuses" Nothing (rsaX931DigestOfLen 33)

caseDriver :: IO ()
caseDriver = do
  assertEqual "raw maps to prehash spec"
    (Just (SigRSA_X931 Nothing)) (rsaX931SigFor x931Mech BS.empty)
  assertEqual "sha1 row maps to digested spec"
    (Just (SigRSA_X931 (Just D_SHA1))) (rsaX931SigFor sha1Mech BS.empty)
  assertEqual "non-empty params refuse"
    Nothing (rsaX931SigFor x931Mech (BS.pack [0]))
  assertEqual "foreign mechanism refuses"
    Nothing (rsaX931SigFor (MechanismId 0xdead) BS.empty)
