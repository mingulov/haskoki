{- | Store attribute codec cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module Store.AttrCodec
  ( testHistoryAttrsRoundTrip
  , testLegacyGoldenBytes
  ) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Test.Tasty.HUnit (assertEqual)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Attribute.Generated (mustClassId, mustKeyTypeId)
import Haskoki.Runtime.Storage
  ( decodeAttrsDoc
  , encodeAttrsDoc
  )

-- | The history attributes survive the attribute-document codec in
-- both directions: the three flags as booleans, the mechanism id as
-- an unsigned long, including the unavailable-information sentinel.
testHistoryAttrsRoundTrip :: IO ()
testHistoryAttrsRoundTrip = do
  let m = Map.fromList
        [ (AttrAlwaysSensitive, ValBool True)
        , (AttrNeverExtractable, ValBool False)
        , (AttrLocal, ValBool True)
        , (AttrKeyGenMechanism, ValULong 0x1082)
        ]
  assertEqual "history codec round-trip" (Just m) (decodeAttrsDoc (encodeAttrsDoc m))
  let mMax = Map.fromList
        [ (AttrAlwaysSensitive, ValBool False)
        , (AttrNeverExtractable, ValBool False)
        , (AttrLocal, ValBool False)
        , (AttrKeyGenMechanism, ValULong maxBound)
        ]
  assertEqual "history codec sentinel round-trip"
    (Just mMax) (decodeAttrsDoc (encodeAttrsDoc mMax))

-- | The legacy encoding is pinned byte-for-byte: a fixed v0.4-shaped
-- attribute map (the same shape the reload case seats as
-- "legacy-empty") encodes to the bytes the v0.4.0.0 encoder produced
-- for it, and those bytes decode back to the map. Encoder drift for
-- the legacy shapes would break the upgrade path, so it must break
-- this test instead.
testLegacyGoldenBytes :: IO ()
testLegacyGoldenBytes = do
  let m = Map.fromList
        [ (AttrClass, ValULong (mustClassId "CKO_SECRET_KEY"))
        , (AttrKeyType, ValULong (mustKeyTypeId "CKK_AES"))
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "legacy-empty")
        , (AttrValue, ValBytes (BS.replicate 16 1))
        , (AttrValueLen, ValULong 16)
        ]
      golden = "{\"class\":\"0000000000000004\",\"key_type\":\"000000000000001f\",\"label\":\"bGVnYWN5LWVtcHR5\",\"token\":true,\"value\":\"AQEBAQEBAQEBAQEBAQEBAQ==\",\"value_len\":\"0000000000000010\"}"
  assertEqual "legacy bytes match v0.4" golden (encodeAttrsDoc m)
  assertEqual "golden bytes decode" (Just m) (decodeAttrsDoc golden)
