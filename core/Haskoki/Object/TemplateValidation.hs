{- | Object template validation.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object.TemplateValidation
  ( TemplateError (..)
  , checkDuplicates
  , wrongShape
  , validateTemplate
  ) where

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , shapeMatches
  )

-- | Why a template was rejected: two entries for one type with
-- different values, a value with the wrong shape for its type, or
-- a missing required class.
data TemplateError
  = TemplateContradiction !AttributeType
  | TemplateWrongType !AttributeType
  | TemplateIncomplete
  deriving (Eq, Show)

-- | Reject contradictory duplicates; repeated identical values merge
-- silently. The incoming template stays an ordered sequence until
-- this check runs so contradictions cannot hide in a map.
checkDuplicates
  :: [(AttributeType, AttributeValue)]
  -> Either AttributeType (Map AttributeType AttributeValue)
checkDuplicates = go Map.empty
  where
    go acc [] = Right acc
    go acc ((t, v) : rest) = case Map.lookup t acc of
      Nothing -> go (Map.insert t v acc) rest
      Just v'
        | v' == v -> go acc rest
        | otherwise -> Left t

-- | First wrongly shaped entry in a validated template list, if any.
-- Shared by the setter and the copy path so wrong shapes refuse
-- before any seal, immutable, or mutability rule.
wrongShape :: [(AttributeType, AttributeValue)] -> Maybe AttributeType
wrongShape [] = Nothing
wrongShape ((t, v) : rest)
  | shapeMatches t v = wrongShape rest
  | otherwise = Just t

-- | Validate a creation template: no contradictions, every value
-- carrying its type's shape, and the class present (the one
-- required attribute in this inventory; class-specific required
-- sets arrive with the generated inventory). Malformedness
-- outranks incompleteness: contradictions and wrong shapes refuse
-- before the class check runs.
validateTemplate
  :: [(AttributeType, AttributeValue)]
  -> Either TemplateError (Map AttributeType AttributeValue)
validateTemplate entries = case checkDuplicates entries of
  Left t -> Left (TemplateContradiction t)
  Right m -> case wrongShape (Map.toList m) of
    Just t -> Left (TemplateWrongType t)
    Nothing
      | Map.member AttrClass m -> Right m
      | otherwise -> Left TemplateIncomplete
