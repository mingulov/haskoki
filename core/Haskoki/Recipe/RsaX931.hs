{- | RSA-X9.31 recipe: the X9.31-padding shape-group recipe.

Two header mechanisms with the empty parameter shape —
@no-params\/1@:

* @CKM_RSA_X9_31@ signs caller-hashed digests (the input length
  selects the X9.31 hash identifier: 20\/32\/48\/64 bytes map to
  SHA-1\/SHA-256\/SHA-384\/SHA-512; every other length refuses —
  the pinned provider has no hash id for it, proven by probe);
* @CKM_SHA1_RSA_X9_31@ hashes the message with SHA-1, then
  signs with X9.31 padding.

The provider needs the digest set before the pad mode
(@invalid x931 digest@ otherwise — the driver orders the
parameters accordingly). Signatures are deterministic
full-modulus blocks.

This module owns the group's canonical codec, parameter
validation, digest-length rule, and mechanism table. Pure core
only.

Consumers:

* 'Haskoki.Registry' builds the behavior descriptors from
  'rsaX931CodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces empty X9.31 parameters
  via 'rsaX931RecipeFor' + 'rsaX931ParamsValid';
* 'Haskoki.Engine.Driver.rsaX931SigFor' maps the covered
  (mechanism, params) pair to the backend
  'Haskoki.Engine.Backend.SigSpec'; RecipeRsaX931Spec pins the
  mapping;
* the synthetic backend's labeled construction and the libcrypto
  KATs execute the rule pinned here (SyntheticSpec,
  OpenSSLSpec).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.RsaX931
  ( RsaX931Recipe (..)
  , rsaX931Recipes
  , rsaX931RecipeFor
  , rsaX931Codec
  , rsaX931CodecFor
  , rsaX931ParamsValid
  , rsaX931DigestOfLen
  , x931Digests
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Text (Text)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One X9.31 recipe: the mechanism name (raw binds no digest —
-- the input length selects it; the SHA-1 row digests).
data RsaX931Recipe = RsaX931Recipe
  { rx931Name :: !MechanismName
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: X9.31 takes NULL
-- mechanism parameters.
rsaX931Codec :: ParameterCodec
rsaX931Codec = ParameterCodec "no-params" 1

-- | The codec for one recipe row (uniform across the group).
rsaX931CodecFor :: RsaX931Recipe -> ParameterCodec
rsaX931CodecFor _ = rsaX931Codec

-- | X9.31 parameter validation: empty-only, every row.
rsaX931ParamsValid :: RsaX931Recipe -> ByteString -> Bool
rsaX931ParamsValid _ params = BS.null params

-- | Raw-input digest rule: the (length, stem) pairs the pinned
-- provider accepts (its X9.31 hash-id set, proven by probe;
-- SHA-224 and MD5 lengths are absent — they refuse).
x931Digests :: [(Int, Text)]
x931Digests =
  [ (20, "SHA1")
  , (32, "SHA256")
  , (48, "SHA384")
  , (64, "SHA512")
  ]

-- | The digest stem for a raw-input length, if servable.
rsaX931DigestOfLen :: Int -> Maybe Text
rsaX931DigestOfLen n = lookup n x931Digests

-- | The two covered mechanisms.
rsaX931Recipes :: [RsaX931Recipe]
rsaX931Recipes =
  [ RsaX931Recipe "CKM_RSA_X9_31"
  , RsaX931Recipe "CKM_SHA1_RSA_X9_31"
  ]

-- | Resolve a mechanism id to its X9.31 recipe, if covered.
rsaX931RecipeFor :: MechanismId -> Maybe RsaX931Recipe
rsaX931RecipeFor mid =
  case [ r | r <- rsaX931Recipes
           , MechanismId (mustGeneratedId (rx931Name r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
