{- | CBC-MAC recipe: the 128-bit-cipher MAC shape-group recipe.

Six header mechanisms share the MAC parameter shape across
three 16-byte-block ciphers (AES, ARIA, Camellia) — plain
rows take empty parameters (@no-params\/1@) and emit the
first 8 bytes of the final CBC-MAC block (the OASIS
half-block rule, as for 3DES-MAC), GENERAL rows take the
8-byte tag length (@mac-general\/1@, the HMAC convention,
reused verbatim) and emit its first 1..16 bytes. Keys are
128\/192\/256-bit cipher keys; input zero-pads to the
16-byte block.

This module owns the group's canonical codecs, parameter
validation, key-length and truncation rules, and mechanism
table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'cbcmacCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces per-mechanism MAC
  parameters via 'cbcmacRecipeFor' + 'cbcmacParamsValid';
* 'Haskoki.Engine.Driver.cbcmacSpecFor' maps covered (mechanism,
  params, key length) triples to the backend cipher spec plus
  truncation; RecipeCbcMacSpec pins the mapping against this table;
* the driver executes CBC-MAC chaining over the backend ECB route
  (real ciphers on the real backend, test constructions on
  synthetic) — pinned by RoutingE2ESpec KATs and SyntheticSpec
  constructions.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.CbcMac
  ( CbcMacCipher (..)
  , CbcMacRecipe (..)
  , cbcmacRecipes
  , cbcmacRecipeFor
  , cbcmacPlainCodec
  , cbcmacGeneralCodec
  , cbcmacCodecFor
  , cbcmacParamsValid
  , cbcmacKeyLens
  , cbcmacBlockLen
  , cbcmacPlainOutLen
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Haskoki.Recipe.Hmac (decodeMacGeneral, hmacGeneralCodec, hmacPlainCodec)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The underlying 128-bit-block cipher.
data CbcMacCipher
  = CbcAes
  | CbcAria
  | CbcCamellia
  deriving (Eq, Show)

-- | One CBC-MAC recipe: the mechanism name, whether it takes the
-- GENERAL length parameter, and the underlying cipher.
data CbcMacRecipe = CbcMacRecipe
  { cbmName :: !MechanismName
  , cbmGeneral :: !Bool
  , cbmCipher :: !CbcMacCipher
  } deriving (Eq, Show)

-- | Plain rows take empty parameters; GENERAL rows take the
-- tag-length codec. Shared engine conventions, never re-typed.
cbcmacPlainCodec :: ParameterCodec
cbcmacPlainCodec = hmacPlainCodec

-- | See 'cbcmacPlainCodec'.
cbcmacGeneralCodec :: ParameterCodec
cbcmacGeneralCodec = hmacGeneralCodec

-- | The codec for one recipe row.
cbcmacCodecFor :: CbcMacRecipe -> ParameterCodec
cbcmacCodecFor r
  | cbmGeneral r = cbcmacGeneralCodec
  | otherwise = cbcmacPlainCodec

-- | MAC parameter validation: plain rows take empty parameters
-- only; GENERAL rows take the 8-byte tag length in @1..block@.
cbcmacParamsValid :: CbcMacRecipe -> ByteString -> Bool
cbcmacParamsValid r params
  | cbmGeneral r = case decodeMacGeneral params of
      Just n -> n >= 1 && n <= cbcmacBlockLen r
      Nothing -> False
  | otherwise = BS.null params

-- | Accepted raw key lengths in bytes: 128\/192\/256-bit keys.
cbcmacKeyLens :: CbcMacRecipe -> [Int]
cbcmacKeyLens _ = [16, 24, 32]

-- | Cipher block width in bytes (the GENERAL truncation ceiling).
cbcmacBlockLen :: CbcMacRecipe -> Int
cbcmacBlockLen _ = 16

-- | Plain-row output width in bytes (the OASIS half-block rule:
-- the first 8 of the final 16-byte CBC-MAC block).
cbcmacPlainOutLen :: CbcMacRecipe -> Int
cbcmacPlainOutLen _ = 8

-- | All covered mechanisms.
cbcmacRecipes :: [CbcMacRecipe]
cbcmacRecipes =
  [ CbcMacRecipe "CKM_AES_MAC" False CbcAes
  , CbcMacRecipe "CKM_AES_MAC_GENERAL" True CbcAes
  , CbcMacRecipe "CKM_ARIA_MAC" False CbcAria
  , CbcMacRecipe "CKM_ARIA_MAC_GENERAL" True CbcAria
  , CbcMacRecipe "CKM_CAMELLIA_MAC" False CbcCamellia
  , CbcMacRecipe "CKM_CAMELLIA_MAC_GENERAL" True CbcCamellia
  ]

-- | Resolve a mechanism id to its CBC-MAC recipe, if covered.
cbcmacRecipeFor :: MechanismId -> Maybe CbcMacRecipe
cbcmacRecipeFor mid =
  case [ r | r <- cbcmacRecipes
           , MechanismId (mustGeneratedId (cbmName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
