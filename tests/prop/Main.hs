module Main (main) where

import Test.Tasty (defaultMain, testGroup)

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
  putStrLn ("haskoki-prop-tests: effective PROP_SEED=" ++ showSeed seedOv
    ++ " PROP_CASES=" ++ show count)
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
