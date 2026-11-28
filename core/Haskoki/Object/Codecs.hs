{- | Object request-argument codecs.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object.Codecs
  ( encodeTemplate
  , maxTemplateEntries
  , parseTemplate
  , encodeWanted
  , parseWanted
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , decodeValue
  , encodeValue
  )

-- | Attribute-type tag: the 'Enum' order of 'AttributeType'.
attrTag :: AttributeType -> Word8
attrTag = fromIntegral . fromEnum

-- | Tag back to type; unknown tags fail.
tagAttr :: Word8 -> Maybe AttributeType
tagAttr w
  | w <= fromIntegral (fromEnum (maxBound :: AttributeType)) =
      Just (toEnum (fromIntegral w))
  | otherwise = Nothing

-- | Encode a template (order and duplicates preserved): each entry
-- is a tag byte, a 4-byte big-endian length, then the canonical
-- value bytes ('encodeValue').
encodeTemplate :: [(AttributeType, AttributeValue)] -> ByteString
encodeTemplate = BS.concat . map encodeEntry
  where
    encodeEntry :: (AttributeType, AttributeValue) -> ByteString
    encodeEntry (t, v) =
      let bs = encodeValue v
          len = BS.length bs
      in BS.pack
        [ attrTag t
        , fromIntegral (len `div` 16777216 `mod` 256)
        , fromIntegral (len `div` 65536 `mod` 256)
        , fromIntegral (len `div` 256 `mod` 256)
        , fromIntegral (len `mod` 256)
        ] <> bs

-- | Bound on entries per template (pinned single source of truth;
-- ConfigSpec pins the value through the FFI alias). The C packer
-- and the FFI frame decode enforce the same bound on native paths;
-- the core codec enforces it here so in-process planCall paths
-- (scenario, detached) cannot bypass it. @limits.attribute_entries@
-- does NOT drive this bound (reserved key, disclosed in the
-- capabilities report).
maxTemplateEntries :: Int
maxTemplateEntries = 64

-- | Decode a template; truncation, unknown tags, overruns,
-- cross-shape value bytes, and past-bound entry counts all fail.
-- Values decode against their owning type's shape, so a template
-- cannot smuggle a bool where a ULong belongs.
parseTemplate :: ByteString -> Maybe [(AttributeType, AttributeValue)]
parseTemplate = go 0
  where
    go :: Int -> ByteString -> Maybe [(AttributeType, AttributeValue)]
    go n bs
      | BS.null bs = Just []
      | n >= maxTemplateEntries = Nothing
      | BS.length bs < 5 = Nothing
      | otherwise = case BS.unpack (BS.take 5 bs) of
          [tag, b3, b2, b1, b0] ->
            let len = fromIntegral b3 * 16777216
                  + fromIntegral b2 * 65536
                  + fromIntegral b1 * 256
                  + fromIntegral b0
                rest = BS.drop 5 bs
            in if BS.length rest < len
              then Nothing
              else do
                t <- tagAttr tag
                let (valBs, more) = BS.splitAt len rest
                v <- decodeValue t valBs
                ((t, v) :) <$> go (n + 1) more
          _ -> Nothing

-- | Encode a wanted-attribute list as tag bytes.
encodeWanted :: [AttributeType] -> ByteString
encodeWanted = BS.pack . map attrTag

-- | Decode a wanted-attribute list; any unknown tag fails.
parseWanted :: ByteString -> Maybe [AttributeType]
parseWanted = mapM tagAttr . BS.unpack
