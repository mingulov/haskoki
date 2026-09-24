{- | ECDH recipe: the eighth shape-group recipe.

Two header mechanisms share the agreement parameter shape —
@ecdh-params\/1@: @kdf:u64be sharedLen:u64be shared pubLen:u64be
pub@. Only the null-KDF selector (code 0, @CKD_NULL@ semantics:
the raw x-coordinate secret at the curve's coordinate width) is
served; every other KDF selector names a deferred dimension and is
refused, never silently downgraded. Shared data is accepted and
ignored under the null KDF (documented). The cofactor flag comes
from the mechanism row, not the parameters.

This module owns the group's canonical codec, parameter
validation, secret-width rule, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'ecdhCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.Derive.planDerive' accepts ECDH frames via
  'ecdhRecipeFor' + 'ecdhParamsValid', capped by
  'ecdhSecretWidth';
* 'Haskoki.Engine.Driver.ecdhParamsFor' maps covered (mechanism,
  params) pairs to the backend 'EcdhSpec' plus the peer key;
  RecipeEcdhSpec pins the mapping against this table;
* the synthetic backend's per-agreement constructions and the
  libcrypto interop vectors execute the bindings pinned here
  (SyntheticSpec, OpenSSLSpec).

Deferred family members (not recipes, named gaps):
@CKM_ECMQV_DERIVE@ (no provider equivalent),
@CKM_ECDH_AES_KEY_WRAP@, @CKM_ECDH_X_AES_KEY_WRAP@,
@CKM_ECDH_COF_AES_KEY_WRAP@ (ECDH+KDF+AES-KW compositions, a later
wrap-composition slice), and every non-null ECDH KDF selector —
see mechanisms.json honesty notes.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Ecdh
  ( EcdhRecipe (..)
  , ecdhRecipes
  , ecdhRecipeFor
  , ecdhCodec
  , ecdhCodecFor
  , encodeEcdhParams
  , decodeEcdhParams
  , ecdhParamsValid
  , ecdhSecretWidth
  , ecdhPeerCurve
  ) where

import Data.Bits ((.&.), shiftL, shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Word (Word8)

import Haskoki.Recipe.Ecdsa (ecdsaCurveOfDer)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One ECDH recipe: the mechanism name and the cofactor flag
-- (@True@ for @CKM_ECDH1_COFACTOR_DERIVE@).
data EcdhRecipe = EcdhRecipe
  { rhName :: !MechanismName
  , rhCofactor :: !Bool
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: the agreement frame
-- (KDF selector, shared data, peer public key).
ecdhCodec :: ParameterCodec
ecdhCodec = ParameterCodec "ecdh-params" 1

-- | The codec for one recipe row (uniform across the group).
ecdhCodecFor :: EcdhRecipe -> ParameterCodec
ecdhCodecFor _ = ecdhCodec

-- | Encode one 8-byte big-endian word.
encodeWord64 :: Int -> ByteString
encodeWord64 n = BS.pack [byte s | s <- [56, 48 .. 0]]
  where
    byte :: Int -> Word8
    byte s = fromIntegral ((n `shiftR` s) .&. 0xff)

-- | Decode one 8-byte big-endian word.
decodeWord64 :: ByteString -> Maybe Int
decodeWord64 bs
  | BS.length bs /= 8 = Nothing
  | otherwise = Just (BS.foldl' (\a b -> a `shiftL` 8 + fromIntegral b) 0 bs)

-- | Encode ECDH parameters (total; validation is strict).
encodeEcdhParams :: Int -> ByteString -> ByteString -> ByteString
encodeEcdhParams kdf shared peer =
  encodeWord64 kdf
    <> encodeWord64 (BS.length shared) <> shared
    <> encodeWord64 (BS.length peer) <> peer

-- | Decode ECDH parameters: truncation, overrun lengths, and
-- trailing bytes all fail (never a crash, never a partial read).
decodeEcdhParams :: ByteString -> Maybe (Int, ByteString, ByteString)
decodeEcdhParams bs = do
  let (w0, r0) = BS.splitAt 8 bs
      (w1, r1) = BS.splitAt 8 r0
  kdf <- decodeWord64 w0
  sLen <- decodeWord64 w1
  let (shared, r2) = BS.splitAt sLen r1
  if BS.length shared /= sLen
    then Nothing
    else do
      let (w3, r3) = BS.splitAt 8 r2
      pLen <- decodeWord64 w3
      let (peer, rest) = BS.splitAt pLen r3
      if BS.length peer /= pLen || not (BS.null rest)
        then Nothing
        else pure (kdf, shared, peer)

-- | ECDH parameter validation: the null-KDF selector (code 0) with
-- a non-empty peer key. Shared data is accepted and ignored under
-- the null KDF. Every nonzero KDF selector is refused (deferred
-- dimension, named in the mechanisms.json honesty notes).
ecdhParamsValid :: EcdhRecipe -> ByteString -> Bool
ecdhParamsValid _ params = case decodeEcdhParams params of
  Just (0, _, peer) -> not (BS.null peer)
  _ -> False

-- | Raw-secret width in bytes for a base-key material: the curve's
-- coordinate width (32\/48\/66) when the DER curve OID scans,
-- else the 66-byte maximum (synthetic backends serve opaque key
-- bytes with 66-byte secrets, so the planner must not cap them
-- lower; the real backend refuses unscannable keys itself).
ecdhSecretWidth :: ByteString -> Int
ecdhSecretWidth mat = case ecdsaCurveOfDer mat of
  Just "P-256" -> 32
  Just "P-384" -> 48
  Just "P-521" -> 66
  _ -> 66

-- | Peer curve for the agreement: the DER OID scan first (SPKI
-- peers), else the raw uncompressed-point length table (PKCS#11
-- carries the peer as a bare @0x04 \|\| X \|\| Y@ point with no
-- OID: 65\/97\/133 bytes pin P-256\/P-384\/P-521). Anything else
-- is unscannable and refused downstream.
ecdhPeerCurve :: ByteString -> Maybe Text
ecdhPeerCurve bs = case ecdsaCurveOfDer bs of
  Just c -> Just c
  Nothing
    | BS.length bs == 65, BS.index bs 0 == 0x04 -> Just "P-256"
    | BS.length bs == 97, BS.index bs 0 == 0x04 -> Just "P-384"
    | BS.length bs == 133, BS.index bs 0 == 0x04 -> Just "P-521"
    | otherwise -> Nothing

-- | Both covered mechanisms with their cofactor flags.
ecdhRecipes :: [EcdhRecipe]
ecdhRecipes =
  [ EcdhRecipe "CKM_ECDH1_DERIVE" False
  , EcdhRecipe "CKM_ECDH1_COFACTOR_DERIVE" True
  ]

-- | Resolve a mechanism id to its ECDH recipe, if covered.
ecdhRecipeFor :: MechanismId -> Maybe EcdhRecipe
ecdhRecipeFor mid =
  case [ r | r <- ecdhRecipes
           , MechanismId (mustGeneratedId (rhName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
