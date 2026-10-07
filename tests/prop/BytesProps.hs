{- | Byte round-trip properties.

The codec round-trip law over arbitrary byte strings, including
the length bound: in-bound inputs decode and re-encode to
themselves; over-bound inputs reject.
-}
module BytesProps (spec) where

import qualified Data.ByteString as BS
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (Property, forAll)

import Gen (propWith, qcBytes)
import Haskoki.Attribute
  ( AttributeType (..)
  , decodeValue
  , encodeValue
  , maxAttributeBytes
  )

spec :: Maybe Int -> Int -> TestTree
spec seedOv count = testGroup "byte representation laws"
  [ propWith seedOv "bytes round-trip" 304 count pBytesRoundTrip
  ]

pBytesRoundTrip :: Property
pBytesRoundTrip = forAll (qcBytes 70000) $ \bs ->
  case decodeValue AttrValue bs of
    Just v -> encodeValue v == bs
    Nothing -> BS.length bs > maxAttributeBytes
