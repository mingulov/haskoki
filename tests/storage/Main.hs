module Main (main) where

import Test.Tasty (defaultMain, testGroup)

import qualified CommitSpec
import qualified MultiSessionSpec
import qualified StoreCtlSpec
import qualified StoreSpec

main :: IO ()
main = defaultMain $ testGroup "haskoki storage"
  [ StoreSpec.spec
  , CommitSpec.spec
  , StoreCtlSpec.spec
  , MultiSessionSpec.spec
  ]
