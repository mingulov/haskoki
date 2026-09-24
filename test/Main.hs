{- | Scaffold smoke suite (kept): two cases pinning the version
enumeration and the stub outcome type.

The real suites live in @tests\/@: model, engine, storage, prop, and
core Haskell suites plus the independent C harness in @tests\/c@.

@pkcs11-check@ hook note: @pkcs11-check@ is an /external, independent/
consumer used as evidence (rung 5 in @docs\/trust-ladder.md@). It must
be invoked as a separately built binary against the compiled shared
library (e.g. from @scripts\/test-consumers.sh@), never linked into
this suite and never as the sole oracle: do not import its expected
results or reuse its marshalling implementation here.
-}
module Main (main) where

import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (assertBool, testCase)

import Haskoki (Outcome (..), Pkcs11Version (..), ReturnCode (..))

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "haskoki scaffold"
  [ testCase "version enumeration covers four interfaces" $
      assertBool "expected exactly 4 versions"
        (length ([minBound .. maxBound] :: [Pkcs11Version]) == 4)
  , testCase "stub outcome type is constructible" $
      assertBool "OutcomeErr must differ from OutcomeOk"
        (OutcomeErr CKR_GENERAL_ERROR /= OutcomeOk ())
  ]
