-- REGISTRATION: haskoki-client-tests
-- | @haskoki-client-tests@: Tasty pins for the test-only PKCS#11
-- client that need no token: lifecycle brackets and retry policy
-- (token-backed behavior stays in @scripts/test-client.sh@).
module Main (main) where

import Test.Tasty (TestTree, defaultMain, testGroup)

import qualified ClientLifecycleSpec

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "haskoki-client-tests" [ClientLifecycleSpec.spec]
