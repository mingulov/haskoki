-- REGISTRATION: haskoki-storage-tests
module Main (main) where

import Control.Concurrent (getNumCapabilities)
import System.Environment (getArgs)
import Test.Tasty (defaultMain, localOption, testGroup)
import Test.Tasty.Runners (NumThreads (..))

import qualified CommitSpec
import qualified MultiSessionSpec
import qualified PreflightSpec
import qualified StoreCtlSpec
import qualified StoreSpec
import StoreFixtures (fifoWriterMain, walChildMain)

-- | The storage suite; re-invoked with @--holder@ it runs a lock
-- holder child instead (see 'StoreSpec.spawnHolder').
--
-- The suite is capped at two worker threads (overriding @-j N@).
-- With three or more concurrent MVar-intensive tests the run hung,
-- idle, in about 1-4% of executions at @-N4@; with two workers it
-- never hung in 600 runs. An audit of the test bodies, both store
-- backends and tasty's scheduler found no blocking point, and any
-- instrumentation made the hang disappear, so the cause is presumed
-- to lie below the Haskell code. It needs three or more capabilities
-- running Haskell code at once. The shipped library starts the RTS
-- with default settings, a single capability, so it does not run in
-- that mode. Revisit if a smaller reproduction appears.
main :: IO ()
main = do
  args <- getArgs
  case args of
    ["--wal-child", store, mode] -> walChildMain store mode
    ["--fifo-writer", fifo, hexBytes] -> fifoWriterMain fifo hexBytes
    ["--holder", path, doneFile, readyFile] -> StoreSpec.holderMain path doneFile readyFile
    ["--migrate-child", store, cfg, backups, ready] -> PreflightSpec.migrateChildMain store cfg backups ready
    ["--migrate-child-small", store, cfg, backups, ready] -> PreflightSpec.migrateChildSmallMain store cfg backups ready
    ["--reserved-holder", store, ready, go] -> PreflightSpec.reservedHolderMain store ready go
    ["--rel-child", mode, relpath, cfg, backups, result] ->
      StoreCtlSpec.relChildMain mode relpath cfg backups result
    _ -> do
      -- Never above the capability count: tasty raises the RTS
      -- capabilities to match NumThreads, which would turn a -N1 run
      -- into -N2.
      caps <- getNumCapabilities
      defaultMain $ localOption (NumThreads (min 2 caps)) $ testGroup "haskoki storage"
        [ StoreSpec.spec
        , CommitSpec.spec
        , StoreCtlSpec.spec
        , PreflightSpec.spec
        , MultiSessionSpec.spec
        ]
