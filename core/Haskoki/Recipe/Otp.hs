{- | OTP recipe: the eleventh shape-group recipe.

One header mechanism executes: @CKM_HOTP@ is HOTP (RFC 4226) as a
keyed sign\/verify MAC over HMAC-SHA1. Its parameters are
@hotp-params\/1@: @counter:u64be digits:u64be@ (16 bytes, digits
6-8); the input is always empty (HOTP signs the counter only) and
the output is ASCII decimal digits, zero-padded to the width.
@CKM_HOTP_KEY_GEN@ mints 16-64 byte @CKK_HOTP@ secrets and has no
sign recipe row (the @CKM_AES_KEY_GEN@ precedent: keygen lengths
arrive via @CKA_VALUE_LEN@, not parameters).

This module owns the group's canonical codec, parameter
validation, RFC 4226 dynamic truncation, keygen bounds, and
mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the HOTP behavior descriptor from
  'hotpCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.validateInit' enforces HOTP parameters via
  'hotpRecipeFor' + 'hotpParamsValid';
* 'Haskoki.Engine.Driver.hotpParamsFor' maps (mechanism, params) to
  (counter, digits); RecipeOtpSpec pins the mapping;
* the driver executes the HMAC-SHA1-plus-truncate composition over
  the backend MAC route (real HMAC-SHA1 on the real backend, test
  constructions on synthetic) — pinned by RoutingE2ESpec KATs and
  SyntheticSpec constructions;
* 'Haskoki.Operation.KeyManagement.planGenerateKey' enforces the
  keygen bounds 'hotpKeygenMinBytes'\/'hotpKeygenMaxBytes'.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Otp
  ( OtpRecipe (..)
  , hotpRecipes
  , hotpRecipeFor
  , hotpCodec
  , hotpCodecFor
  , encodeHotpCounter
  , encodeHotpParams
  , decodeHotpParams
  , hotpParamsValid
  , hotpTruncate
  , hotpKeygenMinBytes
  , hotpKeygenMaxBytes
  ) where

import Data.Bits ((.&.), shiftL, shiftR, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64, Word8)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One OTP recipe: the mechanism name and the key type name
-- (@CKK_HOTP@) the Init key-type matrix requires. The table carries
-- the sign\/verify row only; keygen has no parameter shape.
data OtpRecipe = OtpRecipe
  { otpName :: !MechanismName
  , otpKeyType :: !MechanismName
  } deriving (Eq, Show)

-- | HOTP parameters: @counter:u64be digits:u64be@.
hotpCodec :: ParameterCodec
hotpCodec = ParameterCodec "hotp-params" 1

-- | The codec for one recipe row.
hotpCodecFor :: OtpRecipe -> ParameterCodec
hotpCodecFor _ = hotpCodec

-- | Encode one 8-byte big-endian word: the HOTP counter (the
-- HMAC input) and the digit count share this shape.
encodeHotpCounter :: Word64 -> ByteString
encodeHotpCounter n = BS.pack [byte s | s <- [56, 48 .. 0]]
  where
    byte :: Int -> Word8
    byte s = fromIntegral ((n `shiftR` s) .&. 0xff)

-- | Encode HOTP parameters (two 8-byte big-endians). Total:
-- out-of-range digit counts encode and are refused by
-- 'decodeHotpParams'\/'hotpParamsValid' (the @mac-general\/1@
-- convention).
encodeHotpParams :: Word64 -> Int -> ByteString
encodeHotpParams counter digits =
  encodeHotpCounter counter <> encodeHotpCounter (fromIntegral digits)

-- | Strict decode: exactly 16 bytes and digits 6-8.
decodeHotpParams :: ByteString -> Maybe (Word64, Int)
decodeHotpParams bs
  | BS.length bs /= 16 = Nothing
  | otherwise =
      let (bCounter, bDigits) = BS.splitAt 8 bs
          digits = foldBE bDigits
      in if digits >= 6 && digits <= 8
           then Just (fromInteger (foldBE bCounter), fromInteger digits)
           else Nothing
  where
    foldBE :: ByteString -> Integer
    foldBE = BS.foldl' (\a b -> a `shiftL` 8 + fromIntegral b) 0

-- | HOTP parameter validation: the strict decode accepts.
hotpParamsValid :: OtpRecipe -> ByteString -> Bool
hotpParamsValid _ params = case decodeHotpParams params of
  Just _ -> True
  Nothing -> False

-- | RFC 4226 dynamic truncation: the low 4 bits of the last MAC
-- byte select the offset, 4 bytes at the offset mask to 31 bits
-- and reduce mod @10^digits@, rendered as zero-padded ASCII
-- decimal. Short MACs and out-of-range widths refuse.
hotpTruncate :: ByteString -> Int -> Maybe ByteString
hotpTruncate mac digits
  | digits < 6 || digits > 8 = Nothing
  | BS.length mac < 20 = Nothing
  | otherwise =
      let offset = fromIntegral (BS.last mac .&. 0x0f)
          slice = BS.take 4 (BS.drop offset mac)
          code = (fold31 slice `mod` 10 ^ digits) :: Int
          shown = show code
      in Just (BS.pack (map (fromIntegral . fromEnum) (replicate (digits - length shown) '0' ++ shown)))
  where
    fold31 :: ByteString -> Int
    fold31 = fromIntegral . (.&. 0x7fffffff) . BS.foldl' (\a b -> a `shiftL` 8 .|. fromIntegral b) (0 :: Word64)

-- | HOTP keygen floor: RFC 4226 section 4 demands at least 128-bit
-- secrets (160 recommended); the planner and the backends refuse
-- shorter lengths.
hotpKeygenMinBytes :: Int
hotpKeygenMinBytes = 16

-- | HOTP keygen ceiling: 512 bits. Longer keys add no HMAC-SHA1
-- strength past the 512-bit block; the planner and the backends
-- refuse longer lengths.
hotpKeygenMaxBytes :: Int
hotpKeygenMaxBytes = 64

-- | The covered mechanism.
hotpRecipes :: [OtpRecipe]
hotpRecipes =
  [ OtpRecipe "CKM_HOTP" "CKK_HOTP"
  ]

-- | Resolve a mechanism id to its HOTP recipe, if covered.
hotpRecipeFor :: MechanismId -> Maybe OtpRecipe
hotpRecipeFor mid =
  case [ r | r <- hotpRecipes
           , MechanismId (mustGeneratedId (otpName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
