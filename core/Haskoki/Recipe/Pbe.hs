{- | PKCS#12 password-based keygen recipes.

The two served rows generate DES keys from a password, salt,
and iteration count (§6.38, based on the PKCS#12 method with
raw password bytes — no BMPString conversion appears in the
section prose):

* @CKM_PBE_SHA1_DES3_EDE_CBC@ (0x3a8): 24-byte @CKK_DES3@
  key plus 8-byte IV;
* @CKM_PBE_SHA1_DES2_EDE_CBC@ (0x3a9): 16-byte @CKK_DES2@
  key plus 8-byte IV.

Key bytes get DES odd-parity adjustment (FIPS 46-3); the IV
is raw KDF output. The canonical frame (@pbe-params\/1@) is
the iteration count (@u64be@) plus the length-prefixed
password and salt.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Pbe
  ( PbeKind (..)
  , PbeRecipe (..)
  , pbeCodec
  , pbeCodecFor
  , pbeRecipes
  , pbeRecipeFor
  , encodePbeParams
  , decodePbeParams
  , pbeParamsValid
  , pbeKeyLen
  , pbeIvLen
  , pbeDesParity
  , maxPbeIters
  , maxPbeMaterial
  ) where

import Data.Bits (popCount, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The two served PBE rows.
data PbeKind
  = PbeDes3
  | PbeDes2
  deriving (Eq, Show)

-- | One PBE recipe: the mechanism name and its shape.
data PbeRecipe = PbeRecipe
  { pbeName :: !MechanismName
  , pbeKind :: !PbeKind
  } deriving (Eq, Show)

-- | The PBE frame codec.
pbeCodec :: ParameterCodec
pbeCodec = ParameterCodec "pbe-params" 1

-- | The codec rides every recipe row.
pbeCodecFor :: PbeRecipe -> ParameterCodec
pbeCodecFor _ = pbeCodec

-- | The two covered mechanisms.
pbeRecipes :: [PbeRecipe]
pbeRecipes =
  [ PbeRecipe "CKM_PBE_SHA1_DES3_EDE_CBC" PbeDes3
  , PbeRecipe "CKM_PBE_SHA1_DES2_EDE_CBC" PbeDes2
  ]

-- | Resolve a mechanism id to its PBE recipe, if covered.
pbeRecipeFor :: MechanismId -> Maybe PbeRecipe
pbeRecipeFor mid =
  case [ r | r <- pbeRecipes
           , MechanismId (mustGeneratedId (pbeName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing

-- | Fixed key length per row (bytes).
pbeKeyLen :: PbeKind -> Int
pbeKeyLen PbeDes3 = 24
pbeKeyLen PbeDes2 = 16

-- | The IV is always one DES block.
pbeIvLen :: PbeKind -> Int
pbeIvLen _ = 8

-- | Iteration ceiling (the PBKD2 DoS bound, shared).
maxPbeIters :: Int
maxPbeIters = 10000000

-- | Password-plus-salt ceiling in bytes.
maxPbeMaterial :: Int
maxPbeMaterial = 65536

encodeU16 :: Int -> ByteString
encodeU16 n = BS.pack [fromIntegral ((n `div` 256) `mod` 256), fromIntegral (n `mod` 256)]

decodeU16 :: ByteString -> Maybe (Int, ByteString)
decodeU16 bs
  | BS.length bs < 2 = Nothing
  | otherwise =
      let (w, rest) = BS.splitAt 2 bs
      in Just (BS.foldl' (\a b -> a * 256 + fromIntegral b) 0 w, rest)

encodeU64 :: Word64 -> ByteString
encodeU64 w = BS.pack [fromIntegral ((w `div` (256 ^ i)) `mod` 256) | i <- [7, 6 .. 0]]

decodeU64 :: ByteString -> Maybe (Word64, ByteString)
decodeU64 bs
  | BS.length bs < 8 = Nothing
  | otherwise =
      let (w, rest) = BS.splitAt 8 bs
      in Just (BS.foldl' (\a b -> a * 256 + fromIntegral b) 0 w, rest)

-- | Encode the canonical frame: @iter:u64be pwLen:u16be pw
-- saltLen:u16be salt@.
encodePbeParams :: Word64 -> ByteString -> ByteString -> ByteString
encodePbeParams iters pw salt =
  encodeU64 iters
    <> encodeU16 (BS.length pw) <> pw
    <> encodeU16 (BS.length salt) <> salt

-- | Decode the canonical frame ('Nothing' on truncation or
-- trailing bytes).
decodePbeParams :: ByteString -> Maybe (Word64, ByteString, ByteString)
decodePbeParams bs = do
  (iters, r0) <- decodeU64 bs
  (pwLen, r1) <- decodeU16 r0
  let (pw, r2) = BS.splitAt pwLen r1
  if BS.length pw /= pwLen then Nothing else do
    (saltLen, r3) <- decodeU16 r2
    let (salt, rest) = BS.splitAt saltLen r3
    if BS.length salt /= saltLen || not (BS.null rest) then Nothing
      else Just (iters, pw, salt)

-- | Parameter validation: the frame decodes, the iteration
-- count is in range, and the password plus salt fit the
-- ceiling. Empty passwords and salts accept (the §6.38
-- construction defines empty S\/P).
pbeParamsValid :: PbeRecipe -> ByteString -> Bool
pbeParamsValid _ params = case decodePbeParams params of
  Nothing -> False
  Just (iters, pw, salt) ->
    iters >= 1 && iters <= fromIntegral maxPbeIters
      && BS.length pw + BS.length salt <= maxPbeMaterial

-- | DES odd-parity adjustment (FIPS 46-3): set the low bit
-- when the upper seven bits have even parity, else clear it,
-- so every output byte holds an odd number of one-bits.
pbeDesParity :: ByteString -> ByteString
pbeDesParity = BS.map adjust
  where
    adjust b
      | even (popCount (b .&. 0xFE)) = b .|. 1
      | otherwise = b .&. 0xFE
