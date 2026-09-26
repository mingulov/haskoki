{- | DSA recipe: the eighth shape-group recipe.

Ten header mechanisms share the encoding parameter shape —
@sig-encoding\/1@: @"RAW"@, @"DER"@, or empty (an engine
convention selecting the signature encoding; empty defaults to
RAW — PKCS#11 DSA signatures are the raw r||s concatenation).
Nine rows bind a digest (hash-and-sign); @CKM_DSA@ is the raw row
(the input is a caller-supplied digest of at least 20 bytes,
signed directly, no hashing).

This module owns the group's canonical codec, parameter
validation, digest bindings, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'dsaCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces DSA parameters via
  'dsaRecipeFor' + 'dsaParamsValid';
* 'Haskoki.Engine.Driver.dsaSpecFor' maps covered (mechanism,
  params) pairs to backend 'Haskoki.Engine.Backend.SigSpec's
  (no curve label to hint, unlike ECDSA — DSA carries its
  domain parameters in the key, and key shape is the backend's
  call); RecipeDsaSpec pins the mapping against this table;
* the synthetic backend's per-digest constructions and the
  libcrypto interop vectors execute the bindings pinned here
  (SyntheticSpec, OpenSSLSpec).

Deferred family members (not recipes, named gaps):
@CKM_DSA_PARAMETER_GEN@ and @CKM_DSA_KEY_PAIR_GEN@ (generation,
planned alongside this group), @CKM_DSA_PROBABILISTIC_PARAMETER_GEN@,
@CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN@ and @CKM_DSA_FIPS_G_GEN@
(seeded FIPS 186-4 generation: no provider equivalent),
@CKM_ML_DSA@\/@CKM_HASH_ML_DSA@ (later slice) — see
mechanisms.json honesty notes.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Dsa
  ( DsaRecipe (..)
  , dsaRecipes
  , dsaRecipeFor
  , dsaCodec
  , dsaCodecFor
  , dsaEncodingOf
  , dsaParamsValid
  , dsaRawDigestFloor
  , dsaRawFloorFor
  ) where

import Data.ByteString (ByteString)
import Data.Text (Text)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One DSA recipe: the mechanism name and the bound digest stem
-- (@Nothing@ for the raw @CKM_DSA@ row).
data DsaRecipe = DsaRecipe
  { rdName :: !MechanismName
  , rdDigestStem :: !(Maybe Text)
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: the signature encoding
-- selection (@RAW@, @DER@, or empty for the RAW default).
dsaCodec :: ParameterCodec
dsaCodec = ParameterCodec "sig-encoding" 1

-- | The codec for one recipe row (uniform across the group).
dsaCodecFor :: DsaRecipe -> ParameterCodec
dsaCodecFor _ = dsaCodec

-- | Decode the encoding selection (empty defaults to @RAW@: PKCS#11
-- DSA mechanisms take no parameters, and the standard signature
-- shape is the raw r||s concatenation).
dsaEncodingOf :: ByteString -> Maybe Text
dsaEncodingOf params
  | params == "RAW" = Just "RAW"
  | params == "DER" = Just "DER"
  | params == "" = Just "RAW"
  | otherwise = Nothing

-- | DSA parameter validation: @RAW@, @DER@, or empty (RAW) only.
dsaParamsValid :: DsaRecipe -> ByteString -> Bool
dsaParamsValid _ params = case dsaEncodingOf params of
  Just _ -> True
  Nothing -> False

-- | All ten covered mechanisms with their digest bindings.
dsaRecipes :: [DsaRecipe]
dsaRecipes =
  [ DsaRecipe "CKM_DSA" Nothing
  , DsaRecipe "CKM_DSA_SHA1" (Just "SHA_1")
  , DsaRecipe "CKM_DSA_SHA224" (Just "SHA224")
  , DsaRecipe "CKM_DSA_SHA256" (Just "SHA256")
  , DsaRecipe "CKM_DSA_SHA384" (Just "SHA384")
  , DsaRecipe "CKM_DSA_SHA512" (Just "SHA512")
  , DsaRecipe "CKM_DSA_SHA3_224" (Just "SHA3_224")
  , DsaRecipe "CKM_DSA_SHA3_256" (Just "SHA3_256")
  , DsaRecipe "CKM_DSA_SHA3_384" (Just "SHA3_384")
  , DsaRecipe "CKM_DSA_SHA3_512" (Just "SHA3_512")
  ]

-- | Resolve a mechanism id to its DSA recipe, if covered.
dsaRecipeFor :: MechanismId -> Maybe DsaRecipe
dsaRecipeFor mid =
  case [ r | r <- dsaRecipes
           , MechanismId (mustGeneratedId (rdName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing

-- | Raw-@CKM_DSA@ digest floor: the caller-supplied digest must
-- carry at least 20 bytes (the smallest valid subprime width —
-- SHA-1; FIPS 186-4 hashes run 20..64 bytes). Shorter input is
-- not a digest on any served (L, N) pair and refuses
-- @CKR_DATA_LEN_RANGE@ at the sign\/verify planners (the backends
-- and the shim enforce the same floor as defense in depth).
dsaRawDigestFloor :: Int
dsaRawDigestFloor = 20

-- | The digest floor for a mechanism: 'Just' 'dsaRawDigestFloor'
-- on the raw row, 'Nothing' on hash-and-sign rows and non-DSA
-- mechanisms (hash rows accept arbitrary message lengths).
dsaRawFloorFor :: MechanismId -> Maybe Int
dsaRawFloorFor mid = case dsaRecipeFor mid of
  Just r | rdDigestStem r == Nothing -> Just dsaRawDigestFloor
  _ -> Nothing
