{- | AES-GMAC recipe: GCM authentication-only as a sign mechanism.

The single header mechanism takes the canonical
@gcm-params\/1@ image (tag length, IV, AAD remainder — the
GCM convention, reused verbatim) with the tag width from
the NIST SP 800-38D approved set (OASIS v3.2 §6.13.6: the
tag's length is determined by @ulTagBits@) and a
caller-supplied 1..64-byte IV. The signed message travels
as the GCM AAD with empty plaintext; the tag is the GCM
authentication tag. Keys are 128\/192\/256-bit AES.

This module owns the group's canonical codec, parameter
validation, key-length rule, and mechanism table. Pure core
only.

Consumers:

* 'Haskoki.Registry' builds the behavior descriptor from
  'gmacCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces GMAC parameters
  via 'gmacRecipeFor' + 'gmacParamsValid';
* 'Haskoki.Engine.Driver.gmacSpecFor' maps covered (mechanism,
  params, key length) triples to the backend AEAD spec plus
  IV; RecipeGmacSpec pins the mapping against this table;
* the driver executes GMAC over the backend GCM route
  (empty plaintext, message as AAD) — pinned by
  RoutingE2ESpec KATs and SyntheticSpec constructions.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Gmac
  ( GmacRecipe (..)
  , gmacRecipes
  , gmacRecipeFor
  , gmacCodec
  , gmacCodecFor
  , gmacParamsValid
  , gmacKeyLens
  , gmacTagLens
  , gmacIvMax
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Haskoki.Recipe.Gcm (decodeGcmParams, gcmCodec, gcmTagLens)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The single GMAC recipe row.
data GmacRecipe = GmacRecipe
  { gmName :: !MechanismName
  } deriving (Eq, Show)

-- | GMAC takes the GCM parameter image. Shared engine
-- convention, never re-typed.
gmacCodec :: ParameterCodec
gmacCodec = gcmCodec

-- | The codec for one recipe row (uniform across the group).
gmacCodecFor :: GmacRecipe -> ParameterCodec
gmacCodecFor _ = gmacCodec

-- | GMAC tag widths in bytes (the SP 800-38D approved set,
-- shared with the GCM route: OASIS v3.2 §6.13.6 determines the
-- tag length by @ulTagBits@).
gmacTagLens :: [Int]
gmacTagLens = gcmTagLens

-- | Maximum caller IV in bytes (matches the GCM route).
gmacIvMax :: Int
gmacIvMax = 64

-- | Validate canonical parameters: the image decodes, the tag
-- width is approved, and the IV is caller-supplied in range.
gmacParamsValid :: GmacRecipe -> ByteString -> Bool
gmacParamsValid _ bs = case decodeGcmParams bs of
  Just (iv, _, tagLen) ->
    tagLen `elem` gmacTagLens
      && BS.length iv >= 1
      && BS.length iv <= gmacIvMax
  Nothing -> False

-- | Accepted raw key lengths in bytes: 128\/192\/256-bit AES.
gmacKeyLens :: GmacRecipe -> [Int]
gmacKeyLens _ = [16, 24, 32]

-- | The covered mechanism.
gmacRecipes :: [GmacRecipe]
gmacRecipes = [GmacRecipe "CKM_AES_GMAC"]

-- | Resolve a mechanism id to its GMAC recipe, if covered.
gmacRecipeFor :: MechanismId -> Maybe GmacRecipe
gmacRecipeFor mid =
  case [ r | r <- gmacRecipes
           , MechanismId (mustGeneratedId (gmName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
