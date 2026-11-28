{- | Detached object documents.
-}
module Haskoki.Runtime.Storage.ObjectDocs
  ( encodeObjectRecord
  , decodeObjectRecord
  , encodeAttrsDoc
  , decodeAttrsDoc
  , knownMaterialEncodings
  ) where

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Control.Monad (guard)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Types
  ( ObjectId (..)
  , Revision (..)
  , TokenId (..)
  )
import Haskoki.Runtime.Storage.AttrNames
import Haskoki.Runtime.Storage.Base64
import Haskoki.Runtime.Storage.Encoding
import Haskoki.Runtime.Storage.FixedHex
import Haskoki.Runtime.Storage.Records
import Haskoki.Runtime.Storage.Word64Hex

-- ---------------------------------------------------------------------------
-- Object documents
-- ---------------------------------------------------------------------------

-- | Canonical object document bytes.
encodeObjectRecord :: ObjectRecord -> String
encodeObjectRecord o = renderJson $ JObject
  [ ("format_version", JNumber (fromIntegral recordFormatVersion))
  , ("object_id", JString (encodeHex16 (unObjectId (orId o))))
  , ("token_id", JString (encodeHex16 (unTokenId (orToken o))))
  , ("class", JString (encodeHexWord64 (orClass o)))
  , ("key_type", maybe JNull (JString . encodeHexWord64) (orKeyType o))
  , ("attrs", JObject [(attrName t, encodeAttrValue v) | (t, v) <- Map.toAscList (orAttrs o)])
  , ("material_encoding", JString (orMaterialEncoding o))
  , ("material", maybe JNull (JString . encodeBase64) (orMaterial o))
  , ("revision", JString (encodeHex16 (unRevision (orRevision o))))
  ]

-- | Decode an object document; unknown format versions and
-- cross-shape attribute bytes all fail.
decodeObjectRecord :: String -> Maybe ObjectRecord
decodeObjectRecord s = do
  JObject kvs <- parseJson s
  JNumber v <- lookupField "format_version" kvs
  if v /= fromIntegral recordFormatVersion then Nothing else do
    oid <- lookupField "object_id" kvs >>= asString >>= decodeHex16
    tid <- lookupField "token_id" kvs >>= asString >>= decodeHex16
    cls <- lookupField "class" kvs >>= asString >>= decodeHexWord64
    kty <- case lookupField "key_type" kvs of
      Just JNull -> Just Nothing
      Just (JString h) -> Just <$> decodeHexWord64 h
      _ -> Nothing
    attrJson <- lookupField "attrs" kvs >>= asObject
    attrs <- decodeAttrPairs attrJson
    menc <- lookupField "material_encoding" kvs >>= asString
    guard (menc `elem` knownMaterialEncodings)
    mat <- case lookupField "material" kvs of
      Just JNull -> Just Nothing
      Just (JString b) -> Just <$> decodeBase64 b
      _ -> Nothing
    rev <- lookupField "revision" kvs >>= asString >>= decodeHex16
    pure ObjectRecord
      { orId = ObjectId oid
      , orToken = TokenId tid
      , orClass = cls
      , orKeyType = kty
      , orAttrs = attrs
      , orMaterialEncoding = menc
      , orMaterial = mat
      , orRevision = Revision rev
      }

-- | Decode parsed attribute pairs (shared by the object document
-- and the SQLite @attributes_json@ column decoders).
decodeAttrPairs :: [(String, Json)] -> Maybe (Map AttributeType AttributeValue)
decodeAttrPairs pairs = Map.fromList <$> mapM decodeOne pairs
  where
    decodeOne :: (String, Json) -> Maybe (AttributeType, AttributeValue)
    decodeOne (name, j) = do
      t <- nameAttr name
      v <- decodeAttrValue t j
      pure (t, v)

-- | Canonical attribute-document bytes (the SQLite
-- @attributes_json@ column encoding): the bare attrs object.
encodeAttrsDoc :: Map AttributeType AttributeValue -> String
encodeAttrsDoc attrs = renderJson
  (JObject [(attrName t, encodeAttrValue v) | (t, v) <- Map.toAscList attrs])

-- | Decode attribute-document bytes; unknown names and
-- cross-shape values fail.
decodeAttrsDoc :: String -> Maybe (Map AttributeType AttributeValue)
decodeAttrsDoc s = do
  JObject pairs <- parseJson s
  decodeAttrPairs pairs

-- Identifier projections ('unTokenId' et al.) come from 'Haskoki.Types'.

-- | The material encodings this format version understands.
-- Anything else in a stored row is corruption, never silently
-- preserved.
knownMaterialEncodings :: [String]
knownMaterialEncodings = ["none", "attr-value/v1"]
