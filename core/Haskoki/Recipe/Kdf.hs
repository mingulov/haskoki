{- | KDF recipe: the tenth shape-group recipe.

Sixteen header mechanisms share the derive shape — eleven
@CKM_SHA*_KEY_DERIVATION@ rows and four @CKM_BLAKE2B_*_KEY_DERIVE@
rows (hash the base value, truncate to the digest width; empty
parameters, @no-params\/1@) plus
@CKM_PKCS5_PBKD2@ (@pbkd2-params\/2@: @prf:u64be
iters:u64be saltLen:u64be salt pwdLen:u64be pwd@). The PBKD2 PRF
is any servable HMAC (engine-local codes 1..13 over the
fixed-width digests); iterations cap at 'maxPbkd2Iters' (a
documented CPU ceiling — unbounded work from a small input is
a typed refusal, not a hang). The derive route pins the
password segment empty (the password rides the base key); the
keygen route carries it inline per @CK_PKCS5_PBKD2_PARAMS2@.

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
  , kdfDigestWidth
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

-- | PBKD2 takes the PRF\/iterations\/salt\/password frame
-- (one shape for both routes; the derive route pins the
-- password segment empty).
kdfPbkd2Codec :: ParameterCodec
kdfPbkd2Codec = ParameterCodec "pbkd2-params" 2

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

-- | Digest stems onto output widths in bytes. The domain is
-- exactly the 'kdfCodeDigest' range (pinned by RecipeKdfSpec):
-- HKDF defaults and ceilings derive from the PRF through this
-- table, never from a hardcoded hash.
kdfDigestWidth :: Text -> Maybe Int
kdfDigestWidth stem
  | stem == "MD5" = Just 16
  | stem == "SHA_1" = Just 20
  | stem == "SHA224" = Just 28
  | stem == "SHA256" = Just 32
  | stem == "SHA384" = Just 48
  | stem == "SHA512" = Just 64
  | stem == "SHA512_224" = Just 28
  | stem == "SHA512_256" = Just 32
  | stem == "SHA3_224" = Just 28
  | stem == "SHA3_256" = Just 32
  | stem == "SHA3_384" = Just 48
  | stem == "SHA3_512" = Just 64
  | stem == "RIPEMD160" = Just 20
  | otherwise = Nothing

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

-- | Encode PBKD2 parameters (total; validation is strict):
-- @prf:u64be iters:u64be saltLen:u64be salt pwdLen:u64be pwd@.
encodePbkd2Params :: Int -> Int -> ByteString -> ByteString -> ByteString
encodePbkd2Params prf iters salt pwd =
  encodeWord64 prf <> encodeWord64 iters
    <> encodeWord64 (BS.length salt) <> salt
    <> encodeWord64 (BS.length pwd) <> pwd

-- | Decode PBKD2 parameters to (PRF stem, iterations, salt,
-- password): unknown PRF codes, truncation, overrun lengths,
-- and trailing bytes all fail (never a crash, never a partial
-- read).
decodePbkd2Params :: ByteString -> Maybe (Text, Int, ByteString, ByteString)
decodePbkd2Params bs = do
  let (w0, r0) = BS.splitAt 8 bs
      (w1, r1) = BS.splitAt 8 r0
      (w2, r2) = BS.splitAt 8 r1
  c0 <- decodeWord64 w0
  iters <- decodeWord64 w1
  sLen <- decodeWord64 w2
  stem <- kdfCodeDigest c0
  let (salt, r3) = BS.splitAt sLen r2
  (w3, pwd) <- if BS.length salt /= sLen then Nothing else Just (BS.splitAt 8 r3)
  pLen <- decodeWord64 w3
  let (pwb, rest) = BS.splitAt pLen pwd
  if BS.length pwb /= pLen || not (BS.null rest)
    then Nothing
    else pure (stem, iters, salt, pwb)

-- | KDF parameter validation (derive route): SHA rows take empty
-- parameters only; PBKD2 takes a known PRF with
-- @1..'maxPbkd2Iters'@ iterations, any salt (empty included),
-- and an empty password segment (the password rides the base
-- key — the keygen route carries it inline instead).
kdfParamsValid :: KdfRecipe -> ByteString -> Bool
kdfParamsValid r params
  | rkPbkd2 r = case decodePbkd2Params params of
      Just (_, iters, _, pwd) ->
        iters >= 1 && iters <= maxPbkd2Iters && BS.null pwd
      Nothing -> False
  | otherwise = BS.null params

-- | SHA-row digest width in bytes (the derived-total ceiling);
-- 'Nothing' for PBKD2 (unbounded construction, shared ceiling).
kdfShaWidth :: KdfRecipe -> Maybe Int
kdfShaWidth r = case rkDigestStem r of
  Just "BLAKE2B_512" -> Just 64
  Just "BLAKE2B_160" -> Just 20
  Just "BLAKE2B_256" -> Just 32
  Just "BLAKE2B_384" -> Just 48
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

-- | All sixteen covered mechanisms (eleven SHA rows, four
-- BLAKE2B rows, PBKD2).
kdfRecipes :: [KdfRecipe]
kdfRecipes =
  [ KdfRecipe "CKM_BLAKE2B_512_KEY_DERIVE" False (Just "BLAKE2B_512")
  , KdfRecipe "CKM_BLAKE2B_160_KEY_DERIVE" False (Just "BLAKE2B_160")
  , KdfRecipe "CKM_BLAKE2B_256_KEY_DERIVE" False (Just "BLAKE2B_256")
  , KdfRecipe "CKM_BLAKE2B_384_KEY_DERIVE" False (Just "BLAKE2B_384")
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
