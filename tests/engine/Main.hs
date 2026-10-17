-- REGISTRATION: haskoki-engine-tests
module Main (main) where

import Control.Concurrent.MVar (newMVar)
import Test.Tasty (defaultMain, testGroup)

import qualified AsyncEngineSpec
import qualified CertificateEngineSpec
import qualified CryptoExportSpec
import qualified DetachedEngineSpec
import qualified FfiAcquireSpec
import qualified LeaseWedgeDenseSpec
import qualified LeaseWedgeSpec
import qualified NativeParamsSpec
import qualified NotificationsEngineSpec
import qualified OpenSSLSpec
import qualified OperationSmokeSpec
import qualified RoutingE2ESpec
import qualified SnapshotEngineSpec
import qualified SyntheticSpec
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , Store (..)
  , StoreDelta (..)
  , TokenRecord (..)
  , emptyDelta
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Types (Generation (..), SlotId (..), TokenId (..))

main :: IO ()
-- GHC #27272 warm-up MITIGATION (not a fix): one single-threaded
-- first commit before tasty forks any worker (see
-- 'warmupCommitPath'). Concurrent first evaluation of the
-- commit-path constants can orphan a string-literal black hole and
-- hang the suite binary (GHC #27272, a known upstream runtime bug);
-- pre-forcing them up front removes the concurrent first
-- evaluation. This lowers the hang rate; it does not fix upstream.
main = do
  warmupCommitPath
  -- One process-wide HASKOKI_CONFIG lock, threaded
  -- through the specs with env-sensitive opens (see EnvLock).
  envLock <- newMVar ()
  defaultMain $ testGroup "haskoki engine"
    [ SyntheticSpec.spec
    , OpenSSLSpec.spec
    , OperationSmokeSpec.spec
    , RoutingE2ESpec.spec
    , CryptoExportSpec.spec envLock
    , SnapshotEngineSpec.spec
    , AsyncEngineSpec.spec envLock
    , DetachedEngineSpec.spec envLock
    , FfiAcquireSpec.spec envLock
    , LeaseWedgeSpec.spec
    , LeaseWedgeDenseSpec.spec
    , NativeParamsSpec.spec
    , NotificationsEngineSpec.spec envLock
    , CertificateEngineSpec.spec envLock
    ]

-- | GHC #27272 warm-up MITIGATION (not a fix): one seat-token
-- commit on a memory store, single-threaded, before tasty forks any
-- worker. Two threads first-evaluating the same commit-path
-- constant can orphan a string-literal black hole and hang the
-- whole suite binary (GHC #27272, a known upstream runtime bug, not
-- a defect in this suite); evaluating those constants once up
-- front removes the concurrent first evaluation. This lowers the
-- hang rate; it does not fix the upstream bug.
warmupCommitPath :: IO ()
warmupCommitPath = do
  world <- newMemoryWorld
  eStore <- openMemoryStore world
  store <- case eStore of
    Left err -> fail ("commit warmup: memory open: " ++ show err)
    Right s -> pure s
  res <- storeCommit store emptyDelta { sdPutTokens = [seatTok] }
  case res of
    Committed -> pure ()
    other -> fail ("commit warmup: memory commit: " ++ show other)
  storeClose store
  where
    seatTok = TokenRecord
      { trId = TokenId 1
      , trSlot = SlotId 0
      , trGeneration = Generation 0
      , trLabel = "warmup"
      , trAuth = tokenAuthNew
      }
