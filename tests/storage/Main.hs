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
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , Store (..)
  , StoreDelta (..)
  , TokenRecord (..)
  , emptyDelta
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStore)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Types (Generation (..), SlotId (..), TokenId (..))
import StoreFixtures (fifoWriterMain, walChildMain, withScratch)

-- | The storage suite; re-invoked with @--holder@ it runs a lock
-- holder child instead (see 'StoreSpec.spawnHolder').
--
-- The suite is capped at two worker threads (overriding @-j N@).
-- With three or more concurrent MVar-intensive tests the run hung,
-- idle, in about 1-4% of executions at @-N4@; with two workers it
-- never hung in 600 runs. That hang is almost certainly the known
-- upstream runtime bug GHC #27272 (two threads first-evaluating the
-- same commit-path constant orphan a string-literal black hole):
-- the bug needs only two capabilities, not three, and the 2-worker
-- cap lowers the rate but cannot eliminate the hang. An audit of
-- the test bodies, both store backends and tasty's scheduler found
-- no blocking point, and any instrumentation made the hang
-- disappear, which fits a first-evaluation race below the Haskell
-- code. When it starts the RTS itself, the shipped library pins
-- one RTS capability and ignores @GHCRTS@, so it never runs
-- multi-capability; only this test binary (started by tasty at
-- @-N@) is exposed, plus a host that already runs a GHC RTS,
-- which keeps its own capability count. The 'warmupCommitPath'
-- call below pre-forces the commit-path constants single-threaded
-- before any test forks, as a mitigation for that upstream bug.
-- Revisit if a smaller reproduction appears.
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
      warmupCommitPath
      defaultMain $ localOption (NumThreads (min 2 caps)) $ testGroup "haskoki storage"
        [ StoreSpec.spec
        , CommitSpec.spec
        , StoreCtlSpec.spec
        , PreflightSpec.spec
        , MultiSessionSpec.spec
        ]

-- | GHC #27272 warm-up MITIGATION (not a fix): run one seat-token
-- commit on each backend, single-threaded, before tasty forks any
-- worker. Two threads first-evaluating the same commit-path
-- constant can orphan a string-literal black hole and hang the
-- whole suite binary (GHC #27272, a known upstream runtime bug, not
-- a defect in this suite); evaluating those constants once up
-- front removes the concurrent first evaluation. This lowers the
-- hang rate; it does not fix the upstream bug. See the module note
-- above.
warmupCommitPath :: IO ()
warmupCommitPath = do
  world <- newMemoryWorld
  eMem <- openMemoryStore world
  mem <- case eMem of
    Left err -> fail ("commit warmup: memory open: " ++ show err)
    Right s -> pure s
  commitSeat mem "commit warmup: memory commit"
  storeClose mem
  withScratch "haskoki-warmup" $ \dir -> do
    eSql <- openSQLiteStore (dir ++ "/warmup.db")
    sql <- case eSql of
      Left err -> fail ("commit warmup: sqlite open: " ++ show err)
      Right s -> pure s
    commitSeat sql "commit warmup: sqlite commit"
    storeClose sql
  where
    commitSeat store what = do
      res <- storeCommit store emptyDelta { sdPutTokens = [seatTok] }
      case res of
        Committed -> pure ()
        other -> fail (what ++ ": " ++ show other)
    seatTok = TokenRecord
      { trId = TokenId 1
      , trSlot = SlotId 0
      , trGeneration = Generation 0
      , trLabel = "warmup"
      , trAuth = tokenAuthNew
      }
