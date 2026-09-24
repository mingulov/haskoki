{- | CMAC recipe: the ninth shape-group recipe.

Four header mechanisms share the MAC parameter shape — plain
rows take empty parameters (@no-params\/1@), GENERAL rows take the
8-byte tag length (@mac-general\/1@, the HMAC convention,
reused verbatim). The cipher binds by key length (AES-128\/192\/256
for the AES rows, 3DES two-key\/three-key for the DES3 rows); the
GENERAL truncation caps at the cipher block (16\/8 bytes).

This module owns the group's canonical codecs, parameter
validation, key-length and truncation rules, and mechanism table.
Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'cmacCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces per-mechanism CMAC
  parameters via 'cmacRecipeFor' + 'cmacParamsValid';
* 'Haskoki.Engine.Driver.cmacSpecFor' maps covered (mechanism,
  params, key length) triples to the backend cipher spec plus
  truncation; RecipeCmacSpec pins the mapping against this table;
* the driver executes the SP 800-38B composition over the backend
  ECB route (real AES\/3DES on the real backend, test
  constructions on synthetic) — pinned by RoutingE2ESpec KATs and
  SyntheticSpec constructions.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Cmac
  ( CmacRecipe (..)
  , cmacRecipes
  , cmacRecipeFor
  , cmacPlainCodec
  , cmacGeneralCodec
  , cmacCodecFor
  , cmacParamsValid
  , cmacKeyLens
  , cmacBlockLen
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Haskoki.Recipe.Hmac (decodeMacGeneral, hmacGeneralCodec, hmacPlainCodec)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One CMAC recipe: the mechanism name, whether it takes the
-- GENERAL length parameter, and whether it binds 3DES (else AES).
data CmacRecipe = CmacRecipe
  { rcName :: !MechanismName
  , rcGeneral :: !Bool
  , rcDes3 :: !Bool
  } deriving (Eq, Show)

-- | Plain rows take empty parameters; GENERAL rows take the
-- tag-length codec. Shared engine conventions, never re-typed.
cmacPlainCodec :: ParameterCodec
cmacPlainCodec = hmacPlainCodec

-- | See 'cmacPlainCodec'.
cmacGeneralCodec :: ParameterCodec
cmacGeneralCodec = hmacGeneralCodec

-- | The codec for one recipe row.
cmacCodecFor :: CmacRecipe -> ParameterCodec
cmacCodecFor r
  | rcGeneral r = cmacGeneralCodec
  | otherwise = cmacPlainCodec

-- | CMAC parameter validation: plain rows take empty parameters
-- only; GENERAL rows take the 8-byte tag length in @1..block@.
cmacParamsValid :: CmacRecipe -> ByteString -> Bool
cmacParamsValid r params
  | rcGeneral r = case decodeMacGeneral params of
      Just n -> n >= 1 && n <= cmacBlockLen r
      Nothing -> False
  | otherwise = BS.null params

-- | Accepted raw key lengths in bytes: AES-128\/192\/256 for the
-- AES rows, two-key\/three-key for the DES3 rows.
cmacKeyLens :: CmacRecipe -> [Int]
cmacKeyLens r
  | rcDes3 r = [16, 24]
  | otherwise = [16, 24, 32]

-- | Cipher block width in bytes (the GENERAL truncation ceiling):
-- 16 for AES, 8 for 3DES.
cmacBlockLen :: CmacRecipe -> Int
cmacBlockLen r
  | rcDes3 r = 8
  | otherwise = 16

-- | All four covered mechanisms.
cmacRecipes :: [CmacRecipe]
cmacRecipes =
  [ CmacRecipe "CKM_AES_CMAC" False False
  , CmacRecipe "CKM_AES_CMAC_GENERAL" True False
  , CmacRecipe "CKM_DES3_CMAC" False True
  , CmacRecipe "CKM_DES3_CMAC_GENERAL" True True
  ]

-- | Resolve a mechanism id to its CMAC recipe, if covered.
cmacRecipeFor :: MechanismId -> Maybe CmacRecipe
cmacRecipeFor mid =
  case [ r | r <- cmacRecipes
           , MechanismId (mustGeneratedId (rcName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
