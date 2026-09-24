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
import Gen (propCases)

main :: IO ()
main = do
  count <- propCases
  defaultMain $
    testGroup
      "haskoki properties"
      [ BytesProps.spec count
      , CodecProps.spec count
      , ErrorProps.spec count
      , DeltaProps.spec count
      , SnapshotProps.spec count
      , StreamProps.spec count
      , DigestCmdProps.spec count
      , CipherProps.spec count
      , NamespaceProps.spec count
      , OracleProps.spec count
      , ULongProps.spec count
      , WrapProps.spec count
      ]
