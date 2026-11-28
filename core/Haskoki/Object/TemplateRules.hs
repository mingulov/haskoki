{- | Object template rules.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object.TemplateRules
  ( TemplateRule (..)
  , RuleDeny (..)
  , findRule
  , checkRules
  ) where

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe)
import Data.Text (Text)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , attributeTypeByName
  )
import Haskoki.Attribute.Generated
  ( generatedTemplateRules)

-- | One template rule: the class and key-type context plus the
-- required and forbidden @CKA_*@ names. Rules come from the generated
-- table ('generatedTemplateRules'); this type is the curated view.
data TemplateRule = TemplateRule
  { trClass :: !Text
  , trKeyType :: !(Maybe Text)
  , trRequired :: ![Text]
  , trForbidden :: ![Text]
  } deriving (Eq, Show)

-- | Why a template broke its rule: a required attribute is absent, or
-- a forbidden one is present. Names are the @CKA_*@ spellings from
-- the rule, so denials cite the rule exactly.
data RuleDeny
  = RuleMissingRequired !Text
  | RuleForbiddenPresent !Text
  deriving (Eq, Show)

-- | Find the rule for a @(class, key-type)@ context, if any. Contexts
-- without a rule carry no presence constraints beyond @validateTemplate@.
findRule :: Text -> Text -> Maybe TemplateRule
findRule clsName keyName = listToMaybe
  [ TemplateRule c k req frb
  | (c, k, req, frb) <- generatedTemplateRules
  , c == clsName
  , k == Just keyName
  ]

-- | Enforce one rule against validated template attributes. Required
-- names that do not map into the 'AttributeType' inventory fail
-- closed (missing); forbidden names without a mapping cannot be
-- present in a model template, so they are vacuously satisfied.
checkRules :: TemplateRule -> Map AttributeType AttributeValue -> Either RuleDeny ()
checkRules rule attrs = do
  mapM_ require (trRequired rule)
  mapM_ forbid (trForbidden rule)
  where
    require :: Text -> Either RuleDeny ()
    require name = case attributeTypeByName name of
      Nothing -> Left (RuleMissingRequired name)
      Just t
        | Map.member t attrs -> Right ()
        | otherwise -> Left (RuleMissingRequired name)
    forbid :: Text -> Either RuleDeny ()
    forbid name = case attributeTypeByName name of
      Just t
        | Map.member t attrs -> Left (RuleForbiddenPresent name)
      _ -> Right ()
