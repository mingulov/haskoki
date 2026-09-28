{- | AES-XCBC-MAC recipe (RFC 3566).

Two header mechanisms share the empty parameter shape
(@no-params\/1@): the plain row emits the full 16-byte tag,
the _96 row its first 12 bytes. Keys are 128-bit AES only;
192\/256-bit keys are refused. The driver composes the RFC
3566 subkey schedule plus CBC-MAC chaining over the backend
AES-128-ECB route.

This module owns the group's canonical codecs, parameter
validation, key-length and truncation rules, and mechanism
table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'xcbcCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces per-mechanism MAC
  parameters via 'xcbcRecipeFor' + 'xcbcParamsValid';
* 'Haskoki.Engine.Driver.xcbcSpecFor' maps covered (mechanism,
  params, key length) triples to the backend cipher spec plus
  truncation; RecipeXcbcMacSpec pins the mapping against this table;
* the driver executes the RFC 3566 composition over the backend
  ECB route (real AES on the real backend, test constructions
  on synthetic) — pinned by RoutingE2ESpec KATs and
  SyntheticSpec constructions.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.XcbcMac
  ( XcbcRecipe (..)
  , xcbcRecipes
  , xcbcRecipeFor
  , xcbcCodec
  , xcbcCodecFor
  , xcbcParamsValid
  , xcbcKeyLens
  , xcbcOutLen
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Haskoki.Recipe.Hmac (hmacPlainCodec)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One XCBC-MAC recipe: the mechanism name and whether it is the
-- truncated _96 row.
data XcbcRecipe = XcbcRecipe
  { xcbName :: !MechanismName
  , xcbTruncated :: !Bool
  } deriving (Eq, Show)

-- | Both rows take empty parameters. Shared engine convention,
-- never re-typed.
xcbcCodec :: ParameterCodec
xcbcCodec = hmacPlainCodec

-- | The codec for one recipe row (uniform across the group).
xcbcCodecFor :: XcbcRecipe -> ParameterCodec
xcbcCodecFor _ = xcbcCodec

-- | MAC parameter validation: empty parameters only.
xcbcParamsValid :: XcbcRecipe -> ByteString -> Bool
xcbcParamsValid _ params = BS.null params

-- | Accepted raw key lengths in bytes: 128-bit AES only.
xcbcKeyLens :: XcbcRecipe -> [Int]
xcbcKeyLens _ = [16]

-- | Row output width in bytes (16 plain, 12 for _96).
xcbcOutLen :: XcbcRecipe -> Int
xcbcOutLen r
  | xcbTruncated r = 12
  | otherwise = 16

-- | Both covered mechanisms.
xcbcRecipes :: [XcbcRecipe]
xcbcRecipes =
  [ XcbcRecipe "CKM_AES_XCBC_MAC" False
  , XcbcRecipe "CKM_AES_XCBC_MAC_96" True
  ]

-- | Resolve a mechanism id to its XCBC-MAC recipe, if covered.
xcbcRecipeFor :: MechanismId -> Maybe XcbcRecipe
xcbcRecipeFor mid =
  case [ r | r <- xcbcRecipes
           , MechanismId (mustGeneratedId (xcbName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
