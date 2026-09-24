{- | RSA PKCS#1 v1.5 recipe: the fourth shape-group recipe.

Twelve header mechanisms share one parameter shape — empty
mechanism parameters, one-shot sign\/verify. Eleven rows bind a
digest (@CKM_*_RSA_PKCS@: the backend hashes and signs in one
step); @CKM_RSA_PKCS@ is the raw row (the input is signed directly
with block-type-1 padding, no hashing).

This module owns the group's canonical codec, parameter
validation, digest bindings, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'rsaPkcs1CodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces empty RSA parameters
  via 'rsaPkcs1RecipeFor' + 'rsaPkcs1ParamsValid';
* 'Haskoki.Engine.Driver.rsaPkcs1SpecFor' maps covered
  (mechanism, params) pairs to backend 'Haskoki.Engine.Backend.SigSpec's;
  RecipeRsaSpec pins the mapping against this table;
* the synthetic backend's per-digest constructions and the
  libcrypto KATs execute the bindings pinned here (SyntheticSpec,
  OpenSSLSpec).

Deferred family members (not recipes, named gaps): @CKM_RSA_PKCS_PSS@
and @CKM_*_RSA_PKCS_PSS@ (the PSS shape: salt-length parameters,
next slice), @CKM_RSA_PKCS_OAEP@ (the OAEP shape), @CKM_RSA_X_509@
(raw modular exponentiation, no padding), @CKM_RSA_9796@ and the
X9.31 rows (signature paddings without a provider surface in this
slice), the TPM 1.1 rows (TPM encodings, no provider equivalent),
@CKM_MD2_RSA_PKCS@\/@CKM_RIPEMD128_RSA_PKCS@ (digests absent from
the pinned provider) — see mechanisms.json honesty notes.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.RsaPkcs1
  ( RsaPkcs1Recipe (..)
  , rsaPkcs1Recipes
  , rsaPkcs1RecipeFor
  , rsaPkcs1Codec
  , rsaPkcs1CodecFor
  , rsaPkcs1ParamsValid
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Text (Text)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One RSA v1.5 recipe: the mechanism name and the bound digest
-- stem (@Nothing@ for the raw @CKM_RSA_PKCS@ row). Stems use the
-- digest-algorithm spelling (@SHA_1@ with the underscore); the
-- driver maps them onto backend digests.
data RsaPkcs1Recipe = RsaPkcs1Recipe
  { rrName :: !MechanismName
  , rrDigestStem :: !(Maybe Text)
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: PKCS#1 v1.5 signature
-- mechanisms take NULL mechanism parameters.
rsaPkcs1Codec :: ParameterCodec
rsaPkcs1Codec = ParameterCodec "no-params" 1

-- | The codec for one recipe row (uniform across the group).
rsaPkcs1CodecFor :: RsaPkcs1Recipe -> ParameterCodec
rsaPkcs1CodecFor _ = rsaPkcs1Codec

-- | RSA v1.5 parameter validation: empty-only, every row.
rsaPkcs1ParamsValid :: RsaPkcs1Recipe -> ByteString -> Bool
rsaPkcs1ParamsValid _ params = BS.null params

-- | All twelve covered mechanisms with their digest bindings.
rsaPkcs1Recipes :: [RsaPkcs1Recipe]
rsaPkcs1Recipes =
  [ RsaPkcs1Recipe "CKM_RSA_PKCS" Nothing
  , RsaPkcs1Recipe "CKM_MD5_RSA_PKCS" (Just "MD5")
  , RsaPkcs1Recipe "CKM_RIPEMD160_RSA_PKCS" (Just "RIPEMD160")
  , RsaPkcs1Recipe "CKM_SHA1_RSA_PKCS" (Just "SHA_1")
  , RsaPkcs1Recipe "CKM_SHA224_RSA_PKCS" (Just "SHA224")
  , RsaPkcs1Recipe "CKM_SHA256_RSA_PKCS" (Just "SHA256")
  , RsaPkcs1Recipe "CKM_SHA384_RSA_PKCS" (Just "SHA384")
  , RsaPkcs1Recipe "CKM_SHA512_RSA_PKCS" (Just "SHA512")
  , RsaPkcs1Recipe "CKM_SHA3_224_RSA_PKCS" (Just "SHA3_224")
  , RsaPkcs1Recipe "CKM_SHA3_256_RSA_PKCS" (Just "SHA3_256")
  , RsaPkcs1Recipe "CKM_SHA3_384_RSA_PKCS" (Just "SHA3_384")
  , RsaPkcs1Recipe "CKM_SHA3_512_RSA_PKCS" (Just "SHA3_512")
  ]

-- | Resolve a mechanism id to its RSA v1.5 recipe, if covered.
rsaPkcs1RecipeFor :: MechanismId -> Maybe RsaPkcs1Recipe
rsaPkcs1RecipeFor mid =
  case [ r | r <- rsaPkcs1Recipes
           , MechanismId (mustGeneratedId (rrName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
