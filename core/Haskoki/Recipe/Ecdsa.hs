{- | ECDSA recipe: the seventh shape-group recipe.

Ten header mechanisms share the encoding parameter shape —
@sig-encoding\/1@: @"RAW"@, @"DER"@, or empty (an engine
convention selecting the signature encoding; empty defaults to
RAW — PKCS#11 ECDSA mechanisms take no parameters and emit the
raw r||s concatenation). Nine rows bind a digest (hash-and-sign);
@CKM_ECDSA@ is the raw row (the input is signed directly, no
hashing).

This module owns the group's canonical codec, parameter
validation, digest bindings, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'ecdsaCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces ECDSA parameters via
  'ecdsaRecipeFor' + 'ecdsaParamsValid';
* 'Haskoki.Engine.Driver.ecdsaSpecFor' maps covered (mechanism,
  params, key) triples to backend 'Haskoki.Engine.Backend.SigSpec's
  (the curve label comes from 'ecdsaCurveOfDer', defaulting to
  P-256 for unscannable keys — the RSA precedent: the driver
  checks (mechanism, params), key shape is the backend's call);
  RecipeEcdsaSpec pins the mapping against this table;
* the synthetic backend's per-curve/per-digest constructions and
  the libcrypto interop vectors execute the bindings pinned here
  (SyntheticSpec, OpenSSLSpec).

Deferred family members (not recipes, named gaps): @CKM_ECDH1_DERIVE@
and @CKM_ECDH1_COFACTOR_DERIVE@ (the ECDH shape, next slice),
@CKM_EDDSA@ (Ed25519: provider-supported, later slice),
@CKM_XEDDSA@ (no provider equivalent), @CKM_GOSTR3410*@ (no
provider equivalent) — see mechanisms.json honesty notes.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Ecdsa
  ( EcdsaRecipe (..)
  , ecdsaRecipes
  , ecdsaRecipeFor
  , ecdsaCodec
  , ecdsaCodecFor
  , ecdsaEncodingOf
  , ecdsaParamsValid
  , ecdsaCurveOfDer
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One ECDSA recipe: the mechanism name and the bound digest stem
-- (@Nothing@ for the raw @CKM_ECDSA@ row).
data EcdsaRecipe = EcdsaRecipe
  { reName :: !MechanismName
  , reDigestStem :: !(Maybe Text)
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: the signature encoding
-- selection (@RAW@, @DER@, or empty for the RAW default).
ecdsaCodec :: ParameterCodec
ecdsaCodec = ParameterCodec "sig-encoding" 1

-- | The codec for one recipe row (uniform across the group).
ecdsaCodecFor :: EcdsaRecipe -> ParameterCodec
ecdsaCodecFor _ = ecdsaCodec

-- | Decode the encoding selection (empty defaults to @RAW@: PKCS#11
-- ECDSA mechanisms take no parameters, and the standard signature
-- shape is the raw r||s concatenation).
ecdsaEncodingOf :: ByteString -> Maybe Text
ecdsaEncodingOf params
  | params == "RAW" = Just "RAW"
  | params == "DER" = Just "DER"
  | params == "" = Just "RAW"
  | otherwise = Nothing

-- | ECDSA parameter validation: @RAW@, @DER@, or empty (RAW) only.
ecdsaParamsValid :: EcdsaRecipe -> ByteString -> Bool
ecdsaParamsValid _ params = case ecdsaEncodingOf params of
  Just _ -> True
  Nothing -> False

-- | All ten covered mechanisms with their digest bindings.
ecdsaRecipes :: [EcdsaRecipe]
ecdsaRecipes =
  [ EcdsaRecipe "CKM_ECDSA" Nothing
  , EcdsaRecipe "CKM_ECDSA_SHA1" (Just "SHA_1")
  , EcdsaRecipe "CKM_ECDSA_SHA224" (Just "SHA224")
  , EcdsaRecipe "CKM_ECDSA_SHA256" (Just "SHA256")
  , EcdsaRecipe "CKM_ECDSA_SHA384" (Just "SHA384")
  , EcdsaRecipe "CKM_ECDSA_SHA512" (Just "SHA512")
  , EcdsaRecipe "CKM_ECDSA_SHA3_224" (Just "SHA3_224")
  , EcdsaRecipe "CKM_ECDSA_SHA3_256" (Just "SHA3_256")
  , EcdsaRecipe "CKM_ECDSA_SHA3_384" (Just "SHA3_384")
  , EcdsaRecipe "CKM_ECDSA_SHA3_512" (Just "SHA3_512")
  ]

-- | The NIST prime curve named by a DER key's curve OID (SPKI
-- and PKCS#8 both carry it in the algorithm parameters): P-256 is
-- @1.2.840.10045.3.1.7@, P-384 @1.3.132.0.34@, P-521
-- @1.3.132.0.35@. 'Nothing' means not a DER key on the covered set
-- (raw bytes, RSA, garbage, or an off-set curve). The driver uses
-- this as a dispatch hint (defaulting to P-256); the real backend
-- re-checks it before any native call so an off-set curve can
-- refuse but never mis-sign.
ecdsaCurveOfDer :: ByteString -> Maybe Text
ecdsaCurveOfDer der
  | p256 `BS.isInfixOf` der = Just "P-256"
  | p384 `BS.isInfixOf` der = Just "P-384"
  | p521 `BS.isInfixOf` der = Just "P-521"
  | otherwise = Nothing
  where
    p256 = BS.pack [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
    p384 = BS.pack [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
    p521 = BS.pack [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]

-- | Resolve a mechanism id to its ECDSA recipe, if covered.
ecdsaRecipeFor :: MechanismId -> Maybe EcdsaRecipe
ecdsaRecipeFor mid =
  case [ r | r <- ecdsaRecipes
           , MechanismId (mustGeneratedId (reName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
