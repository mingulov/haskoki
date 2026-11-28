{- | Object handles and resolution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object.Handles
  ( encodeHandle
  , decodeHandle
  , resolveHandle
  ) where

import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , decodeValue
  , encodeValue
  )
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  )
import Haskoki.Types
  ( ExternalHandle (..)
  )

-- | Canonical handle encoding: the handle number as an unsigned long.
encodeHandle :: ExternalHandle -> ByteString
encodeHandle (ExternalHandle n) = encodeValue (ValULong (fromIntegral n))

-- | Decode a handle; anything but 8-byte in-'Int'-range bytes
-- fails. The range guard is the platform-width check at the C
-- boundary: handles cross as 'Int'-backed words, while
-- the model representation stays full-width.
decodeHandle :: ByteString -> Maybe ExternalHandle
decodeHandle bs = case decodeValue AttrClass bs of
  Just (ValULong w)
    | w <= fromIntegral (maxBound :: Int) ->
        Just (ExternalHandle (fromIntegral w))
  _ -> Nothing

-- | Guarded resolution: the binding must exist, the object must
-- exist, and the binding generation must still match the object's.
-- Anything else is 'Nothing' (the caller maps it to
-- 'CKR_OBJECT_HANDLE_INVALID').
resolveHandle :: Model -> ExternalHandle -> Maybe ObjectState
resolveHandle m h = case Map.lookup h (mHandles m) of
  Nothing -> Nothing
  Just b -> case Map.lookup (hbObject b) (mObjects m) of
    Nothing -> Nothing
    Just ost
      | hbGeneration b == osGeneration ost -> Just ost
      | otherwise -> Nothing

-- ---------------------------------------------------------------------------
-- Common storage-object attributes
-- ---------------------------------------------------------------------------
