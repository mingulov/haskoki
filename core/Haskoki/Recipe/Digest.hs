{- | Digest-shape recipe: the first shape-group recipe.

Thirteen header mechanisms share the no-params digest shape: empty
mechanism parameters, one-shot plus multipart init\/update\/final,
and a fixed output width per algorithm. This module owns the group's
canonical codec, parameter validation, output widths, and mechanism
table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'digestCodec' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' refuses non-empty digest
  mechanism parameters via 'digestParamsValid';
* 'Haskoki.Engine.Driver.digestAlgFor' maps covered mechanisms to
  backend algorithms; RecipeDigestSpec pins the mapping against
  this table;
* the synthetic backend's per-algorithm widths and the libcrypto
  KATs execute the widths pinned here (SyntheticSpec, OpenSSLSpec).

Deferred family members (not recipes, named gaps): @CKM_SHA512_T@
(t-parameter codec pending, stays planned), @CKM_MD2@ and
@CKM_RIPEMD128@ (no EVP in the pinned provider), @CKM_GOSTR3411@
(needs an engine, no provider), @CKM_FASTHASH@ (vendor mechanism, no
public algorithm), @CKM_BLAKE2B_*@ (output-length parameter
semantics need the base-spec prose; see source-issues.json GAP-BLAKE2B).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Digest
  ( DigestRecipe (..)
  , digestRecipes
  , digestRecipeFor
  , digestCodec
  , digestParamsValid
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One digest recipe: the mechanism name and its fixed output width
-- in bytes. Ids resolve through the generated table, never hand-typed.
data DigestRecipe = DigestRecipe
  { drName :: !MechanismName
  , drOutLen :: !Int
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: digest mechanisms take
-- empty mechanism parameters.
digestCodec :: ParameterCodec
digestCodec = ParameterCodec "no-params" 1

-- | Digest parameter validation: only empty parameters are valid.
digestParamsValid :: ByteString -> Bool
digestParamsValid = BS.null

-- | All fourteen covered mechanisms with their output widths.
-- Only the full-width BLAKE2B-512 row is covered (the 160\/256\/384
-- widths need an output-length parameter the provider does not
-- offer, and slicing would be invented semantics — see
-- @GAP-BLAKE2B@).
digestRecipes :: [DigestRecipe]
digestRecipes =
  [ DigestRecipe "CKM_BLAKE2B_512" 64
  , DigestRecipe "CKM_SHA224" 28
  , DigestRecipe "CKM_SHA256" 32
  , DigestRecipe "CKM_SHA384" 48
  , DigestRecipe "CKM_SHA512" 64
  , DigestRecipe "CKM_SHA512_224" 28
  , DigestRecipe "CKM_SHA512_256" 32
  , DigestRecipe "CKM_SHA3_224" 28
  , DigestRecipe "CKM_SHA3_256" 32
  , DigestRecipe "CKM_SHA3_384" 48
  , DigestRecipe "CKM_SHA3_512" 64
  , DigestRecipe "CKM_SHA_1" 20
  , DigestRecipe "CKM_MD5" 16
  , DigestRecipe "CKM_RIPEMD160" 20
  ]

-- | Resolve a mechanism id to its digest recipe, if covered.
digestRecipeFor :: MechanismId -> Maybe DigestRecipe
digestRecipeFor mid =
  case [ r | r <- digestRecipes
           , MechanismId (mustGeneratedId (drName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
