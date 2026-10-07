module Main (main) where

import System.Environment (getArgs)
import Test.Tasty (defaultMain, testGroup)

import qualified CommitSpec
import qualified MultiSessionSpec
import qualified StoreCtlSpec
import qualified StoreSpec

-- | The storage suite; re-invoked with @--holder@ it runs a lock
-- holder child instead (see 'StoreSpec.spawnHolder').
main :: IO ()
main = do
  args <- getArgs
  case args of
    ["--holder", path, doneFile, readyFile] -> StoreSpec.holderMain path doneFile readyFile
    _ -> defaultMain $ testGroup "haskoki storage"
      [ StoreSpec.spec
      , CommitSpec.spec
      , StoreCtlSpec.spec
      , MultiSessionSpec.spec
      ]
