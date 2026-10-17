-- REGISTRATION: haskoki-prop-tests
module Main (main) where

import System.IO (hPutStrLn, stderr)
import Test.Tasty (defaultMain, testGroup)

import Haskoki.Engine.Backend
  ( BackendEnv
  , EngineResult (..)
  , closeBackend
  , openBackend
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4)
import Haskoki.Engine.Synthetic (Synthetic)
import qualified BytesProps
import qualified CipherProps
import qualified CodecProps
import qualified DeltaProps
import qualified DigestCmdProps
import qualified ErrorProps
import qualified NamespaceProps
import qualified OracleProps
import qualified SnapshotProps
import qualified StreamProps
import qualified ULongProps
import qualified WrapProps
import Gen (propCases, propSeedOverride)

main :: IO ()
main = do
  count <- propCases
  seedOv <- propSeedOverride
  -- Effective knobs, printed once per suite start: a seeded failure
  -- reruns bit-identically via PROP_SEED=<logged> PROP_CASES=<logged>.
  -- On stderr: stdout carries only test output (and the name list
  -- under --list-tests, which the execution join counts).
  hPutStrLn stderr ("haskoki-prop-tests: effective PROP_SEED=" ++ showSeed seedOv
    ++ " PROP_CASES=" ++ show count)
  warmupBackends
  defaultMain $
    testGroup
      "haskoki properties"
      [ BytesProps.spec seedOv count
      , CodecProps.spec seedOv count
      , ErrorProps.spec seedOv count
      , DeltaProps.spec count
      , SnapshotProps.spec count
      , StreamProps.spec count
      , DigestCmdProps.spec seedOv count
      , CipherProps.spec count
      , NamespaceProps.spec count
      , OracleProps.spec count
      , ULongProps.spec seedOv count
      , WrapProps.spec seedOv count
      ]

showSeed :: Maybe Int -> String
showSeed Nothing = "fixed-defaults"
showSeed (Just s) = show s

-- | GHC #27272 warm-up MITIGATION (not a fix): open and close one
-- backend of each kind, single-threaded, before tasty forks any
-- worker. This suite opens backends concurrently at @-N@; two
-- threads first-evaluating the same capability-table constant can
-- orphan a string-literal black hole and hang the whole suite
-- binary (GHC #27272, a known upstream runtime bug, not a defect
-- in this suite). Opening once up front removes the concurrent
-- first evaluation. This lowers the hang rate; it does not fix the
-- upstream bug.
warmupBackends :: IO ()
warmupBackends = do
  eSynth <- openBackend "0" :: IO (EngineResult (BackendEnv Synthetic))
  synth <- case eSynth of
    EngineOk env -> pure env
    EngineFail err -> fail ("backend warmup: synthetic open: " ++ show err)
  eOssl <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  ossl <- case eOssl of
    EngineOk env -> pure env
    EngineFail err -> fail ("backend warmup: openssl open: " ++ show err)
  closeBackend synth
  closeBackend ossl
