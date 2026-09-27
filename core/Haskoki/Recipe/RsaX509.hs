{- | RSA-X.509 recipe: the raw-RSA shape-group recipe.

One header mechanism (@CKM_RSA_X_509@) with the empty parameter
shape — @no-params\/1@: raw modular exponentiation, no padding.
Short inputs are left-padded with zero bytes to the modulus width
(@k@ bytes); outputs are full @k@-blocks; unwrap derives the key
from the trailing bytes of the decrypted block (the length comes
from @CKA_VALUE_LEN@, which the unwrap template must supply).

This module owns the group's canonical codec, parameter
validation, block framing, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the behavior descriptor from
  'rsaX509CodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces empty X.509 parameters
  via 'rsaX509RecipeFor' + 'rsaX509ParamsValid' and refuses padded
  cipher specs for the RSA row (PKCS#7 framing must never cover an
  asymmetric operation);
* 'Haskoki.Engine.Driver.rsaX509SigFor' maps the covered
  (mechanism, params) pair to the backend 'Haskoki.Engine.Backend.SigSpec',
  and 'Haskoki.Engine.Driver.rsaX509CipherFor' to the backend
  'Haskoki.Engine.Backend.RsaCipherParams'; RecipeX509Spec pins both;
* the synthetic backend's labeled construction and the libcrypto
  KATs execute the framing pinned here (SyntheticSpec,
  OpenSSLSpec).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.RsaX509
  ( RsaX509Recipe (..)
  , rsaX509Recipes
  , rsaX509RecipeFor
  , rsaX509Codec
  , rsaX509CodecFor
  , rsaX509ParamsValid
  , x509PadBlock
  , x509Tail
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The single X.509 recipe row.
data RsaX509Recipe = RsaX509Recipe
  { rxName :: !MechanismName
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: X.509 takes NULL
-- mechanism parameters.
rsaX509Codec :: ParameterCodec
rsaX509Codec = ParameterCodec "no-params" 1

-- | The codec for one recipe row (uniform across the group).
rsaX509CodecFor :: RsaX509Recipe -> ParameterCodec
rsaX509CodecFor _ = rsaX509Codec

-- | X.509 parameter validation: empty-only, every row.
rsaX509ParamsValid :: RsaX509Recipe -> ByteString -> Bool
rsaX509ParamsValid _ params = BS.null params

-- | Left-pad an input to the modulus width: @Just@ the @k@-block
-- for non-empty inputs of at most @k@ bytes, 'Nothing' otherwise
-- (empty input, overlong input, or a non-positive width).
x509PadBlock :: Int -> ByteString -> Maybe ByteString
x509PadBlock k input
  | k <= 0 = Nothing
  | BS.null input = Nothing
  | BS.length input > k = Nothing
  | otherwise = Just (BS.replicate (k - BS.length input) 0 <> input)

-- | Take the trailing @n@ bytes of a decrypted @k@-block (the
-- unwrap framing): @Just@ the key bytes when the block is exactly
-- @k@ bytes and @0 < n <= k@, 'Nothing' otherwise.
x509Tail :: Int -> Int -> ByteString -> Maybe ByteString
x509Tail k n block
  | k <= 0 = Nothing
  | n <= 0 || n > k = Nothing
  | BS.length block /= k = Nothing
  | otherwise = Just (BS.drop (k - n) block)

-- | The single covered mechanism.
rsaX509Recipes :: [RsaX509Recipe]
rsaX509Recipes = [RsaX509Recipe "CKM_RSA_X_509"]

-- | Resolve a mechanism id to its X.509 recipe, if covered.
rsaX509RecipeFor :: MechanismId -> Maybe RsaX509Recipe
rsaX509RecipeFor mid =
  case [ r | r <- rsaX509Recipes
           , MechanismId (mustGeneratedId (rxName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
