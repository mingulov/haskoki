{- | Detached model projection.
-}
module Haskoki.Runtime.Storage.Projection
  ( objectToRecord
  , reserveRestoredIds
  ) where

import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Word ( Word64)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), ObjectState (..))
import Haskoki.Types
  ( ObjectId (..)
  , TokenId (..)
  )
import Haskoki.Runtime.Storage.Records

-- ---------------------------------------------------------------------------
-- Model projection
-- ---------------------------------------------------------------------------

-- | Project a live token object onto its storable record. The class
-- and key-type keys derive from the stored attributes (absent or
-- wrongly shaped = 0\/absent, matching the model's lenient reads);
-- the material columns carry the @AttrValue@ payload bytes when
-- present, else the explicit @none@ encoding with no blob.
objectToRecord :: TokenId -> ObjectState -> ObjectRecord
objectToRecord tok ost =
  let attrs = osAttrs ost
  in ObjectRecord
    { orId = osId ost
    , orToken = tok
    , orClass = classOf attrs
    , orKeyType = keyTypeOf attrs
    , orAttrs = attrs
    , orMaterialEncoding = materialEncodingOf attrs
    , orMaterial = materialOf attrs
    , orRevision = osRevision ost
    }
  where
    classOf :: Map AttributeType AttributeValue -> Word64
    classOf attrs = case Map.lookup AttrClass attrs of
      Just (ValULong n) -> n
      _ -> 0
    keyTypeOf :: Map AttributeType AttributeValue -> Maybe Word64
    keyTypeOf attrs = case Map.lookup AttrKeyType attrs of
      Just (ValULong n) -> Just n
      _ -> Nothing
    materialEncodingOf :: Map AttributeType AttributeValue -> String
    materialEncodingOf attrs = case Map.lookup AttrValue attrs of
      Just (ValBytes _) -> "attr-value/v1"
      _ -> "none"
    materialOf :: Map AttributeType AttributeValue -> Maybe ByteString
    materialOf attrs = case Map.lookup AttrValue attrs of
      Just (ValBytes bs) -> Just bs
      _ -> Nothing

-- | Reserve the restored id space in a fresh model: after re-seating
-- persisted objects under their stable 'ObjectId's, advance
-- @mNextObject@ past the restored maximum so later allocations
-- never collide with it. (Handle counters advance on bind; object
-- counters do not advance on explicit-id creates.)
reserveRestoredIds :: [ObjectId] -> Model -> Model
reserveRestoredIds oids m =
  m { mNextObject = max (mNextObject m) (restoredMax + 1) }
  where
    restoredMax = maximum (0 : [n | ObjectId n <- oids])
