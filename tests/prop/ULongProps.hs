{- | Unsigned-attribute properties.

The ULong totality law over the unsigned representation: every
'Word64' round-trips through the codec.
-}
module ULongProps (spec) where

import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (Gen, Property, arbitrary, forAll)

import Gen (propWith)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , decodeValue
  , encodeValue
  )

spec :: Maybe Int -> Int -> TestTree
spec seedOv count = testGroup "unsigned attribute laws"
  [ propWith seedOv "ulong totality" 305 count pUlongTotal
  ]

pUlongTotal :: Property
pUlongTotal = forAll (arbitrary :: Gen Word64) $ \n ->
  let v = ValULong n
  in decodeValue AttrClass (encodeValue v) == Just v
