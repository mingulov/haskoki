{- | Block-cipher CBC/ECB/CTR recipe: the third shape-group recipe.

Ten header mechanisms share one parameter shape over four
algorithm families: CBC takes the IV as mechanism parameters (one
block: 16 bytes for AES/ARIA/CAMELLIA, 8 for Triple-DES), ECB
takes empty parameters, and @CKM_AES_CBC_PAD@ adds PKCS#7 framing
(decided in the pure planner from the recipe's 'crPad' flag, never
in the backend). @CKM_AES_CTR@ takes the canonical @ctr-params/1@
image (counter width u64be plus the 16-byte counter block); only
the 128-bit counter width is served. Key length selects the
cipher width (16\/24\/32 bytes for the AES family; 16 two-key or
24 three-key bytes for Triple-DES, where the engines expand
@K1||K2@ to @K1||K2||K1@).

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

Deferred family members (not recipes, named gaps): @CKM_AES_CFB64@
(provider 4.0.2 has no CFB64 mode for AES),
@CKM_AES_XTS@, @CKM_*_GCM@\/@CCM@ (AEAD shape, needs its
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
  , ctrRecipeFor
  , cipherPlainCodec
  , cipherIvCodec
  , cipherCtrCodec
  , cipherCodecFor
  , cipherParamsValid
  , cipherKeyLenValid
  , encodeCtrParams
  , decodeCtrParams
  , ctrNextImage
  , ctsName
  , streamNames
  , ofbName
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8)

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

-- | The CTR parameter codec: the canonical image below, not raw
-- IV bytes (the native struct carries the counter width too).
cipherCtrCodec :: ParameterCodec
cipherCtrCodec = ParameterCodec "ctr-params" 1

-- | The codec for one recipe row.
cipherCodecFor :: BlockCipherRecipe -> ParameterCodec
cipherCodecFor r
  | crName r == ctrName = cipherCtrCodec
  | crIvBytes r == 0 = cipherPlainCodec
  | otherwise = cipherIvCodec

-- | Cipher parameter validation: exactly the recipe's IV length
-- (empty-only for ECB rows). The CTR row decodes the canonical
-- image and serves only the 128-bit counter width.
cipherParamsValid :: BlockCipherRecipe -> ByteString -> Bool
cipherParamsValid r params
  | crName r == ctrName = case decodeCtrParams params of
      Just (bits, cb) -> bits == 128 && BS.length cb == 16
      Nothing -> False
  | otherwise = BS.length params == crIvBytes r

-- | This group's CTR row name (the only streaming row).
ctrName :: MechanismName
ctrName = "CKM_AES_CTR"

-- | The CTS mechanism name. CTS keeps the CBC IV geometry but the
-- planners replace block alignment with the stealing floor (see
-- 'Haskoki.Operation.isCtsMech').
ctsName :: MechanismName
ctsName = "CKM_AES_CTS"

-- | The length-preserving AES stream rows: CFB128/CFB8/CFB1/OFB
-- accept any input length (see 'Haskoki.Operation.isAesStreamMech').
streamNames :: [MechanismName]
streamNames = ["CKM_AES_CFB128", "CKM_AES_CFB8", "CKM_AES_CFB1", "CKM_AES_OFB"]

-- | The OFB row, which never streams multipart updates (see
-- 'Haskoki.Operation.isOfbMech').
ofbName :: MechanismName
ofbName = "CKM_AES_OFB"

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

-- | Encode CTR parameters: the counter width plus the 16-byte
-- counter block.
encodeCtrParams :: Int -> ByteString -> ByteString
encodeCtrParams bits cb = encodeWord64 bits <> cb

-- | Decode CTR parameters: @(counterBits, cb)@. 'Nothing' on any
-- truncation, overrun, short block, or negative width.
decodeCtrParams :: ByteString -> Maybe (Int, ByteString)
decodeCtrParams bs = do
  let (w, cb) = BS.splitAt 8 bs
  bits <- decodeWord64 w
  if bits < 0 || BS.length cb /= 16
    then Nothing
    else Just (bits, cb)

-- | Advance a CTR parameter image by a whole number of counter
-- blocks: the 128-bit counter block increments big-endian (PKCS#11
-- counts the low @ulCounterBits@ bits; only the full width is
-- served, so the whole block advances). 'Nothing' on a
-- non-128-bit image or a negative step; the all-ones block wraps
-- to zero.
ctrNextImage :: ByteString -> Int -> Maybe ByteString
ctrNextImage bs n = case decodeCtrParams bs of
  Just (128, cb)
    | n >= 0 -> Just (encodeCtrParams 128 (addBlocks cb n))
  _ -> Nothing
  where
    addBlocks :: ByteString -> Int -> ByteString
    addBlocks start k = BS.pack (reverse (go (reverse (BS.unpack start)) k))
      where
        go [] _ = []
        go (b : rest) carry =
          let total = fromIntegral b + carry :: Int
          in fromIntegral (total .&. 0xff)
               : go rest (total `shiftR` 8)

-- | Cipher key-length validation: membership in the recipe's key
-- set (Triple-DES takes 16 two-key or 24 three-key bytes).
cipherKeyLenValid :: BlockCipherRecipe -> Int -> Bool
cipherKeyLenValid r n = n `elem` crKeyLens r

-- | All ten covered mechanisms with their geometry. The CTR row
-- carries the counter-block width as its block geometry and IV
-- length (agreeing with the backend 'cipherIvLen' law); the
-- canonical parameter image is wider (width word plus block) and
-- the stream itself takes unaligned input (the operation shape is
-- @CipherSpec 1@, set in
-- 'Haskoki.Operation.Codec.cipherShapeFor').
cipherRecipes :: [BlockCipherRecipe]
cipherRecipes =
  [ BlockCipherRecipe "CKM_AES_CBC" 16 [16, 24, 32] 16 False "CKK_AES"
  , BlockCipherRecipe "CKM_AES_CBC_PAD" 16 [16, 24, 32] 16 True "CKK_AES"
  , BlockCipherRecipe "CKM_AES_ECB" 16 [16, 24, 32] 0 False "CKK_AES"
  , BlockCipherRecipe "CKM_AES_CTR" 16 [16, 24, 32] 16 False "CKK_AES"
  -- CTS takes the raw IV like CBC (the stealing construction needs
  -- >= 1 block of input; the planners enforce the length floor, not
  -- block alignment, via 'Haskoki.Operation.isCtsMech').
  , BlockCipherRecipe "CKM_AES_CTS" 16 [16, 24, 32] 16 False "CKK_AES"
  -- CFB128/CFB8/CFB1/OFB take the raw IV like CBC and accept any
  -- input length (length-preserving streams; the planners allow
  -- unaligned input via 'Haskoki.Operation.isAesStreamMech').
  , BlockCipherRecipe "CKM_AES_CFB128" 16 [16, 24, 32] 16 False "CKK_AES"
  , BlockCipherRecipe "CKM_AES_CFB8" 16 [16, 24, 32] 16 False "CKK_AES"
  , BlockCipherRecipe "CKM_AES_CFB1" 16 [16, 24, 32] 16 False "CKK_AES"
  , BlockCipherRecipe "CKM_AES_OFB" 16 [16, 24, 32] 16 False "CKK_AES"
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

-- | Resolve a mechanism id to the CTR recipe row, if it is the
-- CTR mechanism (drives the FFI struct translation and the driver
-- image split).
ctrRecipeFor :: MechanismId -> Maybe BlockCipherRecipe
ctrRecipeFor mid = case cipherRecipeFor mid of
  Just r | crName r == ctrName -> Just r
  _ -> Nothing
