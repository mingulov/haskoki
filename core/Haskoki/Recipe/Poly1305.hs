{- | Poly1305 recipe: the standalone-Poly1305 shape-group recipe.

One header mechanism (@CKM_POLY1305@) with the empty parameter
shape — @no-params\/1@: the 16-byte authenticator over the
message under a 32-byte @CKK_POLY1305@ key (keygen rides the
already-served @CKM_POLY1305_KEY_GEN@). Any other key type or
length refuses at init.

This module owns the group's canonical codec, parameter
validation, key rule, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the behavior descriptor from
  'poly1305CodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces empty Poly1305
  parameters and the key rule via 'poly1305RecipeFor' +
  'poly1305ParamsValid' + 'poly1305KeyOk';
* 'Haskoki.Engine.Driver.poly1305MacFor' maps the covered
  (mechanism, params) pair to the backend
  'Haskoki.Engine.Backend.MacSpec' (the key rule lives at init;
  the provider refuses off-length keys); RecipePoly1305Spec pins
  the mapping;
* the synthetic backend's labeled construction and the libcrypto
  KAT execute the rule pinned here (SyntheticSpec, OpenSSLSpec).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Poly1305
  ( Poly1305Recipe (..)
  , poly1305Recipes
  , poly1305RecipeFor
  , poly1305Codec
  , poly1305CodecFor
  , poly1305ParamsValid
  , poly1305KeyOk
  , poly1305KeyLen
  , poly1305TagLen
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word64)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The single Poly1305 recipe row.
data Poly1305Recipe = Poly1305Recipe
  { polyName :: !MechanismName
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: Poly1305 takes NULL
-- mechanism parameters.
poly1305Codec :: ParameterCodec
poly1305Codec = ParameterCodec "no-params" 1

-- | The codec for one recipe row (uniform across the group).
poly1305CodecFor :: Poly1305Recipe -> ParameterCodec
poly1305CodecFor _ = poly1305Codec

-- | Poly1305 parameter validation: empty-only.
poly1305ParamsValid :: Poly1305Recipe -> ByteString -> Bool
poly1305ParamsValid _ params = BS.null params

-- | Poly1305 key length in bytes (one-time 256-bit key).
poly1305KeyLen :: Int
poly1305KeyLen = 32

-- | Poly1305 tag length in bytes.
poly1305TagLen :: Int
poly1305TagLen = 16

-- | Poly1305 key rule: @CKK_POLY1305@ at exactly 32 bytes.
poly1305KeyOk :: Word64 -> Int -> Bool
poly1305KeyOk kty n = kty == mustKeyTypeId "CKK_POLY1305" && n == poly1305KeyLen

-- | The single covered mechanism.
poly1305Recipes :: [Poly1305Recipe]
poly1305Recipes = [Poly1305Recipe "CKM_POLY1305"]

-- | Resolve a mechanism id to its Poly1305 recipe, if covered.
poly1305RecipeFor :: MechanismId -> Maybe Poly1305Recipe
poly1305RecipeFor mid =
  case [ r | r <- poly1305Recipes
           , MechanismId (mustGeneratedId (polyName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
