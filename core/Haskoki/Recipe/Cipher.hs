{- | Block-cipher CBC/ECB recipe: the third shape-group recipe.

Nine header mechanisms share one parameter shape over four
algorithm families: CBC takes the IV as mechanism parameters (one
block: 16 bytes for AES/ARIA/CAMELLIA, 8 for Triple-DES), ECB
takes empty parameters, and @CKM_AES_CBC_PAD@ adds PKCS#7 framing
(decided in the pure planner from the recipe's 'crPad' flag, never
in the backend). Key length selects the cipher width (16\/24\/32
bytes for the AES family; 16 two-key or 24 three-key bytes for
Triple-DES, where the engines expand @K1||K2@ to @K1||K2||K1@).

This module owns the group's canonical codecs, parameter/key
validation, block/key/IV geometry, and mechanism table. Pure core
only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'cipherCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces per-mechanism cipher
  parameters via 'cipherRecipeFor' + 'cipherParamsValid';
* 'Haskoki.Engine.Driver.cipherSpecFor' maps covered (mechanism,
  key length, params) triples to backend 'Haskoki.Engine.Backend.CipherSpec's;
  RecipeCipherSpec pins the mapping against this table;
* the synthetic backend's per-spec geometry and the libcrypto
  KATs execute the geometry pinned here (SyntheticSpec,
  OpenSSLSpec).

Deferred family members (not recipes, named gaps): the streaming
sub-shapes (@CKM_AES_CTR@\/@CFB*@\/@OFB@, same for ARIA/CAMELLIA),
@CKM_AES_CTS@\/@XTS@, @CKM_*_GCM@\/@CCM@ (AEAD shape, needs its
own nonce\/tag recipe), @CKM_*_ENCRYPT_DATA@ (single-part data
shape), the PBE constructors, and every legacy-only or
provider-absent cipher (single DES, RC2\/RC4\/RC5, IDEA, CAST,
SEED, Blowfish, SKIPJACK, BATON, JUNIPER, GOST, KASUMI, TWOFISH —
see mechanisms.json honesty notes and the pinned-provider probe
record).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Cipher
  ( BlockCipherRecipe (..)
  , cipherRecipes
  , cipherRecipeFor
  , cipherPlainCodec
  , cipherIvCodec
  , cipherCodecFor
  , cipherParamsValid
  , cipherKeyLenValid
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One block-cipher recipe: the mechanism name, the block width in
-- bytes, the accepted raw key lengths, the IV length carried as
-- mechanism parameters (0 for ECB), the PKCS#7 flag, and the key
-- type name (@CKK_*@) the Init key-type matrix requires.
data BlockCipherRecipe = BlockCipherRecipe
  { crName :: !MechanismName
  , crBlockBytes :: !Int
  , crKeyLens :: ![Int]
  , crIvBytes :: !Int
  , crPad :: !Bool
  , crKeyType :: !MechanismName
  } deriving (Eq, Show)

-- | The group's canonical parameter codecs: ECB mechanisms take
-- empty mechanism parameters; CBC mechanisms take the raw IV bytes
-- (the length is mechanism-keyed through the recipe, like the HMAC
-- GENERAL width ceiling).
cipherPlainCodec :: ParameterCodec
cipherPlainCodec = ParameterCodec "no-params" 1

cipherIvCodec :: ParameterCodec
cipherIvCodec = ParameterCodec "iv-bytes" 1

-- | The codec for one recipe row.
cipherCodecFor :: BlockCipherRecipe -> ParameterCodec
cipherCodecFor r
  | crIvBytes r == 0 = cipherPlainCodec
  | otherwise = cipherIvCodec

-- | Cipher parameter validation: exactly the recipe's IV length
-- (empty-only for ECB rows).
cipherParamsValid :: BlockCipherRecipe -> ByteString -> Bool
cipherParamsValid r params = BS.length params == crIvBytes r

-- | Cipher key-length validation: membership in the recipe's key
-- set (Triple-DES takes 16 two-key or 24 three-key bytes).
cipherKeyLenValid :: BlockCipherRecipe -> Int -> Bool
cipherKeyLenValid r n = n `elem` crKeyLens r

-- | All nine covered mechanisms with their geometry.
cipherRecipes :: [BlockCipherRecipe]
cipherRecipes =
  [ BlockCipherRecipe "CKM_AES_CBC" 16 [16, 24, 32] 16 False "CKK_AES"
  , BlockCipherRecipe "CKM_AES_CBC_PAD" 16 [16, 24, 32] 16 True "CKK_AES"
  , BlockCipherRecipe "CKM_AES_ECB" 16 [16, 24, 32] 0 False "CKK_AES"
  , BlockCipherRecipe "CKM_DES3_CBC" 8 [16, 24] 8 False "CKK_DES3"
  , BlockCipherRecipe "CKM_DES3_ECB" 8 [16, 24] 0 False "CKK_DES3"
  , BlockCipherRecipe "CKM_ARIA_CBC" 16 [16, 24, 32] 16 False "CKK_ARIA"
  , BlockCipherRecipe "CKM_ARIA_ECB" 16 [16, 24, 32] 0 False "CKK_ARIA"
  , BlockCipherRecipe "CKM_CAMELLIA_CBC" 16 [16, 24, 32] 16 False "CKK_CAMELLIA"
  , BlockCipherRecipe "CKM_CAMELLIA_ECB" 16 [16, 24, 32] 0 False "CKK_CAMELLIA"
  ]

-- | Resolve a mechanism id to its block-cipher recipe, if covered.
cipherRecipeFor :: MechanismId -> Maybe BlockCipherRecipe
cipherRecipeFor mid =
  case [ r | r <- cipherRecipes
           , MechanismId (mustGeneratedId (crName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
