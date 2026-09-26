{- | 3DES CBC-MAC recipe: the retail-MAC shape-group recipe.

Two header mechanisms share the MAC parameter shape — the plain
row takes empty parameters (@no-params\/1@) and emits the first
4 bytes of the final CBC-MAC block (the OASIS half-block rule),
the GENERAL row takes the 8-byte tag length
(@mac-general\/1@, the HMAC convention, reused verbatim) and
emits its first 1..8 bytes. Keys are two-key\/three-key 3DES
(16\/24 bytes); input zero-pads to the 8-byte block.

This module owns the group's canonical codecs, parameter
validation, key-length and truncation rules, and mechanism table.
Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'des3macCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces per-mechanism MAC
  parameters via 'des3macRecipeFor' + 'des3macParamsValid';
* 'Haskoki.Engine.Driver.des3macSpecFor' maps covered (mechanism,
  params, key length) triples to the backend cipher spec plus
  truncation; RecipeDes3MacSpec pins the mapping against this table;
* the driver executes CBC-MAC chaining over the backend ECB route
  (real 3DES on the real backend, test constructions on
  synthetic) — pinned by RoutingE2ESpec KATs and SyntheticSpec
  constructions.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Des3Mac
  ( Des3MacRecipe (..)
  , des3macRecipes
  , des3macRecipeFor
  , des3macPlainCodec
  , des3macGeneralCodec
  , des3macCodecFor
  , des3macParamsValid
  , des3macKeyLens
  , des3macBlockLen
  , des3macPlainOutLen
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Haskoki.Recipe.Hmac (decodeMacGeneral, hmacGeneralCodec, hmacPlainCodec)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One 3DES-MAC recipe: the mechanism name and whether it takes
-- the GENERAL length parameter.
data Des3MacRecipe = Des3MacRecipe
  { rdmName :: !MechanismName
  , rdmGeneral :: !Bool
  } deriving (Eq, Show)

-- | Plain rows take empty parameters; GENERAL rows take the
-- tag-length codec. Shared engine conventions, never re-typed.
des3macPlainCodec :: ParameterCodec
des3macPlainCodec = hmacPlainCodec

-- | See 'des3macPlainCodec'.
des3macGeneralCodec :: ParameterCodec
des3macGeneralCodec = hmacGeneralCodec

-- | The codec for one recipe row.
des3macCodecFor :: Des3MacRecipe -> ParameterCodec
des3macCodecFor r
  | rdmGeneral r = des3macGeneralCodec
  | otherwise = des3macPlainCodec

-- | MAC parameter validation: plain rows take empty parameters
-- only; GENERAL rows take the 8-byte tag length in @1..block@.
des3macParamsValid :: Des3MacRecipe -> ByteString -> Bool
des3macParamsValid r params
  | rdmGeneral r = case decodeMacGeneral params of
      Just n -> n >= 1 && n <= des3macBlockLen r
      Nothing -> False
  | otherwise = BS.null params

-- | Accepted raw key lengths in bytes: two-key\/three-key 3DES.
des3macKeyLens :: Des3MacRecipe -> [Int]
des3macKeyLens _ = [16, 24]

-- | Cipher block width in bytes (the GENERAL truncation ceiling).
des3macBlockLen :: Des3MacRecipe -> Int
des3macBlockLen _ = 8

-- | Plain-row output width in bytes (the OASIS half-block rule:
-- the first 4 of the final 8-byte CBC-MAC block).
des3macPlainOutLen :: Des3MacRecipe -> Int
des3macPlainOutLen _ = 4

-- | Both covered mechanisms.
des3macRecipes :: [Des3MacRecipe]
des3macRecipes =
  [ Des3MacRecipe "CKM_DES3_MAC" False
  , Des3MacRecipe "CKM_DES3_MAC_GENERAL" True
  ]

-- | Resolve a mechanism id to its 3DES-MAC recipe, if covered.
des3macRecipeFor :: MechanismId -> Maybe Des3MacRecipe
des3macRecipeFor mid =
  case [ r | r <- des3macRecipes
           , MechanismId (mustGeneratedId (rdmName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
