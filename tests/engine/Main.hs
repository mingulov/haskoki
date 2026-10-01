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

main :: IO ()
main = do
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
