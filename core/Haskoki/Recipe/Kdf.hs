{- | KDF recipe: the tenth shape-group recipe.

Twelve header mechanisms share the derive shape — eleven
@CKM_SHA*_KEY_DERIVATION@ rows (hash the base value, truncate to
the digest width; empty parameters, @no-params\/1@) plus
@CKM_PKCS5_PBKD2@ (@pbkd2-params\/1@: @prf:u64be
iters:u64be saltLen:u64be salt@). The PBKD2 PRF is any servable
HMAC (engine-local codes 1..13 over the fixed-width digests);
iterations cap at 'maxPbkd2Iters' (a documented CPU ceiling —
unbounded work from a small input is a typed refusal, not a hang).

This module owns the group's canonical codecs, parameter
validation, width and iteration rules, and mechanism table. Pure
core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'kdfCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.Derive.planDerive' accepts KDF frames via
  'kdfRecipeFor' + 'kdfParamsValid', capped by 'kdfShaWidth' (SHA
  rows) or the shared ceiling (PBKD2);
* 'Haskoki.Engine.Driver.kdfShaFor' maps SHA rows to digests and
  'Haskoki.Engine.Driver.pbkd2ParamsFor' maps PBKD2 params;
  RecipeKdfSpec pins both against this table;
* the driver executes over the digest\/MAC routes (real digests on
  the real backend, test constructions on synthetic) — pinned by
  RoutingE2ESpec vectors and SyntheticSpec constructions.

Deferred family members (not recipes, named gaps): the TLS\/SSL
protocol KDFs (a later protocol-specials slice), @CKM_HKDF_DATA@
and @CKM_HKDF_KEY_GEN@ (object-typed HKDF affordances, later) —
see mechanisms.json honesty notes.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Kdf
  ( KdfRecipe (..)
  , kdfRecipes
  , kdfRecipeFor
  , kdfPlainCodec
  , kdfPbkd2Codec
  , kdfCodecFor
  , encodePbkd2Params
  , decodePbkd2Params
  , kdfParamsValid
  , kdfShaWidth
  , kdfCodeDigest
  , maxPbkd2Iters
  ) where

import Data.Bits ((.&.), shiftL, shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Word (Word8)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One KDF recipe: the mechanism name, whether it is PBKD2 (else a
-- SHA row), and the digest stem for SHA rows.
data KdfRecipe = KdfRecipe
  { rkName :: !MechanismName
  , rkPbkd2 :: !Bool
  , rkDigestStem :: !(Maybe Text)
  } deriving (Eq, Show)

-- | SHA rows take empty parameters.
kdfPlainCodec :: ParameterCodec
kdfPlainCodec = ParameterCodec "no-params" 1

-- | PBKD2 takes the PRF\/iterations\/salt frame.
kdfPbkd2Codec :: ParameterCodec
kdfPbkd2Codec = ParameterCodec "pbkd2-params" 1

-- | The codec for one recipe row.
kdfCodecFor :: KdfRecipe -> ParameterCodec
kdfCodecFor r
  | rkPbkd2 r = kdfPbkd2Codec
  | otherwise = kdfPlainCodec

-- | Documented PBKD2 iteration ceiling (CPU guard: each iteration
-- is a full HMAC over the salt\/block, so unbounded counts from a
-- small input refuse typed instead of hanging the engine).
maxPbkd2Iters :: Int
maxPbkd2Iters = 10000000

-- | Engine-local PRF codes over the fixed-width digests (the
-- driver's HMAC selector; the driver additionally requires the
-- stem to map to a servable HMAC, so the table and the backend can
-- never drift silently).
kdfCodeDigest :: Int -> Maybe Text
kdfCodeDigest code
  | code == 1 = Just "MD5"
  | code == 2 = Just "SHA_1"
  | code == 3 = Just "SHA224"
  | code == 4 = Just "SHA256"
  | code == 5 = Just "SHA384"
  | code == 6 = Just "SHA512"
  | code == 7 = Just "SHA512_224"
  | code == 8 = Just "SHA512_256"
  | code == 9 = Just "SHA3_224"
  | code == 10 = Just "SHA3_256"
  | code == 11 = Just "SHA3_384"
  | code == 12 = Just "SHA3_512"
  | code == 13 = Just "RIPEMD160"
  | otherwise = Nothing

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

-- | Encode PBKD2 parameters (total; validation is strict).
encodePbkd2Params :: Int -> Int -> ByteString -> ByteString
encodePbkd2Params prf iters salt =
  encodeWord64 prf <> encodeWord64 iters
    <> encodeWord64 (BS.length salt) <> salt

-- | Decode PBKD2 parameters to (PRF stem, iterations, salt):
-- unknown PRF codes, truncation, overrun lengths, and trailing
-- bytes all fail (never a crash, never a partial read).
decodePbkd2Params :: ByteString -> Maybe (Text, Int, ByteString)
decodePbkd2Params bs = do
  let (w0, r0) = BS.splitAt 8 bs
      (w1, r1) = BS.splitAt 8 r0
      (w2, r2) = BS.splitAt 8 r1
  c0 <- decodeWord64 w0
  iters <- decodeWord64 w1
  sLen <- decodeWord64 w2
  stem <- kdfCodeDigest c0
  let (salt, rest) = BS.splitAt sLen r2
  if BS.length salt /= sLen || not (BS.null rest)
    then Nothing
    else pure (stem, iters, salt)

-- | KDF parameter validation: SHA rows take empty parameters only;
-- PBKD2 takes a known PRF with @1..'maxPbkd2Iters'@ iterations
-- (any salt, empty included).
kdfParamsValid :: KdfRecipe -> ByteString -> Bool
kdfParamsValid r params
  | rkPbkd2 r = case decodePbkd2Params params of
      Just (_, iters, _) -> iters >= 1 && iters <= maxPbkd2Iters
      Nothing -> False
  | otherwise = BS.null params

-- | SHA-row digest width in bytes (the derived-total ceiling);
-- 'Nothing' for PBKD2 (unbounded construction, shared ceiling).
kdfShaWidth :: KdfRecipe -> Maybe Int
kdfShaWidth r = case rkDigestStem r of
  Just "BLAKE2B_512" -> Just 64
  Just "SHA_1" -> Just 20
  Just "SHA224" -> Just 28
  Just "SHA256" -> Just 32
  Just "SHA384" -> Just 48
  Just "SHA512" -> Just 64
  Just "SHA512_224" -> Just 28
  Just "SHA512_256" -> Just 32
  Just "SHA3_224" -> Just 28
  Just "SHA3_256" -> Just 32
  Just "SHA3_384" -> Just 48
  Just "SHA3_512" -> Just 64
  _ -> Nothing

-- | All thirteen covered mechanisms (eleven SHA rows, one
-- BLAKE2B-512 row, PBKD2).
kdfRecipes :: [KdfRecipe]
kdfRecipes =
  [ KdfRecipe "CKM_BLAKE2B_512_KEY_DERIVE" False (Just "BLAKE2B_512")
  , KdfRecipe "CKM_SHA1_KEY_DERIVATION" False (Just "SHA_1")
  , KdfRecipe "CKM_SHA224_KEY_DERIVATION" False (Just "SHA224")
  , KdfRecipe "CKM_SHA256_KEY_DERIVATION" False (Just "SHA256")
  , KdfRecipe "CKM_SHA384_KEY_DERIVATION" False (Just "SHA384")
  , KdfRecipe "CKM_SHA512_KEY_DERIVATION" False (Just "SHA512")
  , KdfRecipe "CKM_SHA512_224_KEY_DERIVATION" False (Just "SHA512_224")
  , KdfRecipe "CKM_SHA512_256_KEY_DERIVATION" False (Just "SHA512_256")
  , KdfRecipe "CKM_SHA3_224_KEY_DERIVATION" False (Just "SHA3_224")
  , KdfRecipe "CKM_SHA3_256_KEY_DERIVATION" False (Just "SHA3_256")
  , KdfRecipe "CKM_SHA3_384_KEY_DERIVATION" False (Just "SHA3_384")
  , KdfRecipe "CKM_SHA3_512_KEY_DERIVATION" False (Just "SHA3_512")
  , KdfRecipe "CKM_PKCS5_PBKD2" True Nothing
  ]

-- | Resolve a mechanism id to its KDF recipe, if covered.
kdfRecipeFor :: MechanismId -> Maybe KdfRecipe
kdfRecipeFor mid =
  case [ r | r <- kdfRecipes
           , MechanismId (mustGeneratedId (rkName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
