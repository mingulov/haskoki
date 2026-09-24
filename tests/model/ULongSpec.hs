{- | Unsigned-attribute pins.

'ValULong' is unsigned: negatives are unrepresentable, the codec
is total over the 'Word64' domain, and conversions to
platform-width types guard at their own site (e.g.
'decodeHandle'). Same wire bytes for in-range values.
-}
module ULongSpec (spec) where

import Data.Word (Word64)
import qualified Data.ByteString as BS
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , decodeValue
  , encodeValue
  )
import Haskoki.Object (decodeHandle)

spec :: TestTree
spec = testGroup "Unsigned attributes"
  [ testCase "negatives unrepresentable (unsigned totality)" caseNoNegatives
  , testCase "codec total over its representation" caseCodecTotal
  , testCase "out-of-range handle bytes rejected at the boundary" caseHandleBoundary
  , testCase "in-range values round-trip" caseInRange
  ]

-- | There is no negative 'ValULong': the old silent-wrap input
-- (all-ones bytes, once the wrapped form of -1) is now a
-- first-class large value that round-trips, while the
-- platform-width handle conversion rejects it at the boundary.
caseNoNegatives :: IO ()
caseNoNegatives = do
  let big = ValULong maxBound
  assertEqual "maxBound round-trips" (Just big)
    (decodeValue AttrClass (encodeValue big))
  assertEqual "maxBound rejects as a handle" Nothing
    (decodeHandle (encodeValue big))
  assertEqual "wrap-around literal is maxBound" (ValULong maxBound)
    (ValULong (fromIntegral (-1 :: Int)))
  assertEqual "just past Int range round-trips"
    (Just (ValULong (fromIntegral (maxBound :: Int) + 1)))
    (decodeValue AttrClass
      (encodeValue (ValULong (fromIntegral (maxBound :: Int) + 1))))

-- | The totality law over the unsigned representation: every
-- 'Word64' round-trips, including the old boundary values.
caseCodecTotal :: IO ()
caseCodecTotal = mapM_ check
  [ 0
  , 1
  , 42
  , maxBound
  , maxBound - 1
  , fromIntegral (maxBound :: Int)
  , fromIntegral (maxBound :: Int) + 1
  ]
  where
    check :: Word64 -> IO ()
    check n =
      let v = ValULong n
      in assertEqual ("value " ++ show n) (Just v)
        (decodeValue AttrClass (encodeValue v))

-- | Handle bytes past 'Int' range reject at the boundary
-- conversion to 'ExternalHandle': the platform-width check stays
-- at the C boundary while the model representation is full-width.
caseHandleBoundary :: IO ()
caseHandleBoundary =
  assertEqual "0xFF..FF rejects" Nothing
    (decodeHandle (BS.replicate 8 0xFF))

-- | In-range values round-trip with the same wire bytes as before.
caseInRange :: IO ()
caseInRange = mapM_ check
  [ ValULong 0
  , ValULong 42
  , ValULong 0x7FFFFFFFFFFFFFFF
  , ValULong (fromIntegral (maxBound :: Int))
  ]
  where
    check v = assertEqual ("value " ++ show v) (Just v)
      (decodeValue AttrClass (encodeValue v))
