{- | TLS-PRF recipe: the TLS 1.0\/1.1 pseudo-random function.

One header mechanism, @CKM_TLS_PRF@: @PRF(secret, label, seed) =
P_MD5(first-half, label ++ seed) XOR P_SHA1(second-half, label ++
seed)@ (RFC 2246 §5; the halves share the middle byte on odd
lengths). Parameters are the label + seed frame
(@tls-prf-params\/1@: @labLen:u64be lab seedLen:u64be seed@); the
output length arrives via the derived template's @CKA_VALUE_LEN@,
capped by 'maxTlsPrfOutput' (a documented CPU ceiling —
unbounded expansion from a small input is a typed refusal, not a
hang).

This module owns the canonical codec and parameter validation.
Pure core only.

Consumers:

* 'Haskoki.Registry' builds the behavior descriptor from
  'tlsPrfCodec' (never a re-typed codec literal);
* 'Haskoki.Operation.Derive.planDerive' accepts TLS-PRF frames
  via 'tlsPrfRecipeFor' + 'tlsPrfParamsValid', capped by
  'maxTlsPrfOutput';
* 'Haskoki.Engine.Driver.tlsPrfParamsFor' maps params to the
  (label, seed) pair; RecipeTlsPrfSpec pins the mapping against
  this table;
* the driver executes P_hash over the HMAC-MD5\/SHA-1 routes
  (real digests on the real backend, test constructions on
  synthetic) — pinned by RoutingE2ESpec vectors and
  SyntheticSpec constructions.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.TlsPrf
  ( TlsPrfRecipe (..)
  , tlsPrfRecipes
  , tlsPrfRecipeFor
  , tlsPrfCodec
  , tlsPrfCodecFor
  , encodeTlsPrfParams
  , decodeTlsPrfParams
  , tlsPrfParamsValid
  , maxTlsPrfOutput
  , maxTlsPrfSeed
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One TLS-PRF recipe: the mechanism name (a single row).
data TlsPrfRecipe = TlsPrfRecipe
  { rtName :: !MechanismName
  } deriving (Eq, Show)

-- | TLS-PRF takes the label + seed frame.
tlsPrfCodec :: ParameterCodec
tlsPrfCodec = ParameterCodec "tls-prf-params" 1

-- | Output ceiling in bytes (the shared 255-block construction
-- ceiling): larger derivations refuse typed.
maxTlsPrfOutput :: Int
maxTlsPrfOutput = 255 * 32

-- | Label + seed ceiling in bytes (the derive info ceiling).
maxTlsPrfSeed :: Int
maxTlsPrfSeed = 65536

encodeWord64 :: Int -> ByteString
encodeWord64 n =
  BS.pack [ fromIntegral ((n `div` 2 ^ (8 * i)) `mod` 256) | i <- ([7, 6 .. 0] :: [Int]) ]

decodeWord64 :: ByteString -> Maybe (Int, ByteString)
decodeWord64 bs
  | BS.length bs < 8 = Nothing
  | otherwise =
      let (w, rest) = BS.splitAt 8 bs
      in Just (BS.foldl' (\a b -> a * 256 + fromIntegral b) 0 w, rest)

-- | Encode the label + seed frame.
encodeTlsPrfParams :: ByteString -> ByteString -> ByteString
encodeTlsPrfParams lab seed =
  encodeWord64 (BS.length lab) <> lab
    <> encodeWord64 (BS.length seed) <> seed

-- | Decode the label + seed frame ('Nothing' on truncation,
-- trailing bytes, or an over-ceiling seed).
decodeTlsPrfParams :: ByteString -> Maybe (ByteString, ByteString)
decodeTlsPrfParams bs = do
  (ll, r1) <- decodeWord64 bs
  (lab, r2) <- Just (BS.splitAt ll r1)
  (sl, r3) <- decodeWord64 r2
  (seed, rest) <- Just (BS.splitAt sl r3)
  if BS.length lab /= ll || BS.length seed /= sl || not (BS.null rest)
    then Nothing
    else if ll + sl > maxTlsPrfSeed then Nothing else Just (lab, seed)

-- | Parameter validation: the frame decodes.
tlsPrfParamsValid :: TlsPrfRecipe -> ByteString -> Bool
tlsPrfParamsValid _ params = case decodeTlsPrfParams params of
  Just _ -> True
  Nothing -> False

-- | The codec rides every recipe row (single-row group).
tlsPrfCodecFor :: TlsPrfRecipe -> ParameterCodec
tlsPrfCodecFor _ = tlsPrfCodec

-- | The single covered mechanism.
tlsPrfRecipes :: [TlsPrfRecipe]
tlsPrfRecipes = [TlsPrfRecipe "CKM_TLS_PRF"]

-- | Resolve a mechanism id to its TLS-PRF recipe, if covered.
tlsPrfRecipeFor :: MechanismId -> Maybe TlsPrfRecipe
tlsPrfRecipeFor mid =
  case [ r | r <- tlsPrfRecipes
           , MechanismId (mustGeneratedId (rtName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
