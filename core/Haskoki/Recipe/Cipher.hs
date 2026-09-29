{- | Block-cipher CBC/ECB/CTR recipe: the third shape-group recipe.

Forty-four header mechanisms share one parameter shape over
eleven algorithm families: CBC takes the IV as mechanism parameters
(one block: 16 bytes for AES/ARIA/CAMELLIA/SEED, 8 for
Triple-DES/single-DES/CAST-128/IDEA/Blowfish/RC2),
ECB takes empty parameters, and the CBC_PAD rows add PKCS#7
framing (decided in the pure planner from the recipe's 'crPad'
flag, never in the backend).
@CKM_AES_CTR@ and @CKM_CAMELLIA_CTR@ take the canonical
@ctr-params/1@ image (counter width u64be plus the 16-byte
counter block); only the 128-bit counter width is served. The
RC2 rows take the canonical @rc2-params/1@ image
(effective-bits u64be, plus the 8-byte IV for CBC rows); only
effective-bits 1..1024 are served. Key
length selects the cipher width (16\/24\/32 bytes for the AES
family; 16 two-key or 24 three-key bytes for Triple-DES, where
the engines expand @K1||K2@ to @K1||K2||K1@; variable ranges
for the legacy rows: RC2 1..128, RC4 1..255, Blowfish 4..56,
CAST-128 1..16).

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

The @CKM_*_ENCRYPT_DATA@ single-part data shape is its own
recipe ('Haskoki.Recipe.EncryptData'), not a row here.

Deferred family members (not recipes, named gaps): @CKM_AES_CFB64@
(provider 4.0.2 has no CFB64 mode for AES),
@CKM_*_GCM@\/@CCM@ (AEAD shape, needs its
own nonce\/tag recipe), the PBE constructors, @CKM_DES_OFB8@
(no 8-bit OFB for DES in the provider), and every
provider-absent cipher (RC5, CAST, CAST3, CDMF, SKIPJACK, BATON,
JUNIPER, GOST, KASUMI, TWOFISH, SALSA20 — see mechanisms.json
honesty notes and the pinned-provider probe record). Single
DES, RC2, RC4, CAST-128, IDEA, SEED and Blowfish ride the
@legacy@ provider (loaded alongside @default@ since 11p).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Cipher
  ( BlockCipherRecipe (..)
  , cipherRecipes
  , cipherRecipeFor
  , ctrRecipeFor
  , rc2RecipeFor
  , cipherPlainCodec
  , cipherIvCodec
  , cipherCtrCodec
  , cipherKwPkcs7Codec
  , cipherCodecFor
  , cipherParamsValid
  , cipherKeyLenValid
  , encodeCtrParams
  , decodeCtrParams
  , ctrNextImage
  , cipherRc2Codec
  , encodeRc2EcbParams
  , encodeRc2CbcParams
  , decodeRc2Params
  , rc2Names
  , ctsName
  , streamNames
  , desStreamNames
  , ofbName
  , desOfbName
  , wrapNames
  , kwpNames
  , kwPkcs7Name
  , xtsName
  , rc4Name
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

-- | The KW-PKCS7 parameter codec: empty (default §4.3 AIV) or the
-- raw 8-byte alternate initial value, never a struct.
cipherKwPkcs7Codec :: ParameterCodec
cipherKwPkcs7Codec = ParameterCodec "optional-wrap-iv" 1

-- | The RC2 parameter codec: the canonical image below, not raw
-- IV bytes (the native structs carry the effective-bits word too).
cipherRc2Codec :: ParameterCodec
cipherRc2Codec = ParameterCodec "rc2-params" 1

-- | The codec for one recipe row.
cipherCodecFor :: BlockCipherRecipe -> ParameterCodec
cipherCodecFor r
  | crName r `elem` ctrNames = cipherCtrCodec
  | crName r `elem` rc2Names = cipherRc2Codec
  | crName r == kwPkcs7Name = cipherKwPkcs7Codec
  | crIvBytes r == 0 = cipherPlainCodec
  | otherwise = cipherIvCodec

-- | Cipher parameter validation: exactly the recipe's IV length
-- (empty-only for ECB rows). The CTR rows decode the canonical
-- image and serve only the 128-bit counter width. The RC2 rows
-- decode the canonical RC2 image and serve effective-bits 1..1024
-- with the row's shape (word-only for ECB, word+IV otherwise).
cipherParamsValid :: BlockCipherRecipe -> ByteString -> Bool
cipherParamsValid r params
  | crName r `elem` ctrNames = case decodeCtrParams params of
      Just (bits, cb) -> bits == 128 && BS.length cb == 16
      Nothing -> False
  | crName r `elem` rc2Names = case decodeRc2Params params of
      Just (bits, iv)
        | bits >= 1 && bits <= 1024 ->
            if crName r == "CKM_RC2_ECB"
              then BS.null iv
              else BS.length iv == 8
      _ -> False
  | crName r == kwPkcs7Name =
      BS.null params || BS.length params == 8
  | otherwise = BS.length params == crIvBytes r

-- | This group's CTR row names (the streaming rows): AES and
-- Camellia share the canonical counter image and the 128-bit-only
-- rule (the native structs are layout-identical).
ctrNames :: [MechanismName]
ctrNames = ["CKM_AES_CTR", "CKM_CAMELLIA_CTR"]

-- | The RC2 row names: ECB takes the word-only image
-- (@CK_RC2_PARAMS@), CBC/CBC_PAD the word+IV image
-- (@CK_RC2_CBC_PARAMS@); the driver splits the image for the FFI
-- key-bits control.
rc2Names :: [MechanismName]
rc2Names = ["CKM_RC2_ECB", "CKM_RC2_CBC", "CKM_RC2_CBC_PAD"]

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

-- | Length-preserving single-DES stream rows: CFB64/CFB8 chain
-- like CBC (the ciphertext tail is the next register); OFB64
-- takes any length too but never streams (register evolves
-- through the block cipher — 'desOfbName' excludes it from
-- streaming, mirroring the AES row).
desStreamNames :: [MechanismName]
desStreamNames = ["CKM_DES_CFB64", "CKM_DES_CFB8", "CKM_DES_OFB64"]

desOfbName :: MechanismName
desOfbName = "CKM_DES_OFB64"

-- | The AES key-wrap rows: KW (RFC 3394) plus the two KWP names
-- (see 'Haskoki.Operation.isAesWrapMech'). Wraps never stream
-- multipart updates (one-shot integrity over the whole buffer)
-- and take empty parameters like ECB (KW-PKCS7 is the exception:
-- optional 8-byte IV, see 'kwPkcs7Name').
wrapNames :: [MechanismName]
wrapNames = ["CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_PAD", "CKM_AES_KEY_WRAP_KWP"]

-- | The KWP rows (RFC 5649, any input length >= 1), including the
-- PAD alias the oracle equates with KWP (see
-- 'Haskoki.Operation.isKwpMech').
kwpNames :: [MechanismName]
kwpNames = ["CKM_AES_KEY_WRAP_PAD", "CKM_AES_KEY_WRAP_KWP"]

-- | The KW-PKCS7 row: PKCS#7-pad to the 8-byte wrap quantum
-- (always padding, output longer than input) then RFC 3394 §6.2
-- over the plain KW backend specs; empty or 8-byte-IV parameters
-- (see 'Haskoki.Operation.isKwPkcs7Mech').
kwPkcs7Name :: MechanismName
kwPkcs7Name = "CKM_AES_KEY_WRAP_PKCS7"

-- | The XTS row: IEEE 1619 tweakable encryption over data units of
-- >= 16 bytes (see 'Haskoki.Operation.isXtsMech'). The 16-byte
-- tweak rides as the raw mechanism parameter like a CBC IV; keys
-- are double-width (data + tweak halves, 32/64 bytes).
xtsName :: MechanismName
xtsName = "CKM_AES_XTS"

-- | The RC4 row: a pure stream cipher with no chaining state,
-- so multipart updates never stream (only the final runs the
-- whole buffer one-shot; see 'Haskoki.Operation.isRc4Mech').
rc4Name :: MechanismName
rc4Name = "CKM_RC4"

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

-- | Encode RC2 ECB parameters: the effective-bits word only.
encodeRc2EcbParams :: Int -> ByteString
encodeRc2EcbParams bits = encodeWord64 bits

-- | Encode RC2 CBC parameters: the effective-bits word plus the
-- 8-byte IV.
encodeRc2CbcParams :: Int -> ByteString -> ByteString
encodeRc2CbcParams bits iv = encodeWord64 bits <> iv

-- | Decode RC2 parameters: @(effectiveBits, iv)@, length-dispatched
-- (8 bytes word-only, 16 bytes word+IV). Structural only: the
-- range (1..1024) and the row shape are enforced by
-- 'cipherParamsValid', mirroring the CTR split.
decodeRc2Params :: ByteString -> Maybe (Int, ByteString)
decodeRc2Params bs = case BS.length bs of
  8 -> do
    bits <- decodeWord64 bs
    if bits < 0 then Nothing else Just (bits, BS.empty)
  16 -> do
    let (w, iv) = BS.splitAt 8 bs
    bits <- decodeWord64 w
    if bits < 0 then Nothing else Just (bits, iv)
  _ -> Nothing

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

-- | All forty-four covered mechanisms with their geometry. The
-- CTR rows carry the counter-block width as their block geometry
-- and IV length (agreeing with the backend 'cipherIvLen' law);
-- the canonical parameter image is wider (width word plus block)
-- and the stream itself takes unaligned input (the operation shape
-- is @CipherSpec 1@, set in
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
  -- KW/KWP take empty parameters like ECB on the 8-byte wrap
  -- quantum; the planners enforce the length rules (KW:
  -- multiple-of-8 >= 16; KWP: any length >= 1) and never stream
  -- multipart updates (see 'Haskoki.Operation.isAesWrapMech').
  , BlockCipherRecipe "CKM_AES_KEY_WRAP" 8 [16, 24, 32] 0 False "CKK_AES"
  , BlockCipherRecipe "CKM_AES_KEY_WRAP_PAD" 8 [16, 24, 32] 0 False "CKK_AES"
  , BlockCipherRecipe "CKM_AES_KEY_WRAP_KWP" 8 [16, 24, 32] 0 False "CKK_AES"
  -- KW-PKCS7 pads in the pure layer like a CBC_PAD row (crPad, 8-byte
  -- quantum) but executes over the plain KW specs with an optional
  -- caller IV (empty = default AIV); the planners enforce the >= 8
  -- raw floor (padded input must reach the 16-byte KW minimum) and
  -- never stream (see 'Haskoki.Operation.isKwPkcs7Mech').
  , BlockCipherRecipe "CKM_AES_KEY_WRAP_PKCS7" 8 [16, 24, 32] 0 True "CKK_AES"
  -- XTS takes the 16-byte tweak as the raw parameter like a CBC IV
  -- on double-width keys (no 192 width: the provider has no
  -- AES-192-XTS); the planners enforce the >= 16 floor and never
  -- stream multipart updates (see 'Haskoki.Operation.isXtsMech').
  , BlockCipherRecipe "CKM_AES_XTS" 16 [32, 64] 16 False "CKK_AES_XTS"
  , BlockCipherRecipe "CKM_DES3_CBC" 8 [16, 24] 8 False "CKK_DES3"
  , BlockCipherRecipe "CKM_DES3_ECB" 8 [16, 24] 0 False "CKK_DES3"
  , BlockCipherRecipe "CKM_DES3_CBC_PAD" 8 [16, 24] 8 True "CKK_DES3"
  , BlockCipherRecipe "CKM_ARIA_CBC" 16 [16, 24, 32] 16 False "CKK_ARIA"
  , BlockCipherRecipe "CKM_ARIA_ECB" 16 [16, 24, 32] 0 False "CKK_ARIA"
  , BlockCipherRecipe "CKM_ARIA_CBC_PAD" 16 [16, 24, 32] 16 True "CKK_ARIA"
  , BlockCipherRecipe "CKM_CAMELLIA_CBC" 16 [16, 24, 32] 16 False "CKK_CAMELLIA"
  , BlockCipherRecipe "CKM_CAMELLIA_ECB" 16 [16, 24, 32] 0 False "CKK_CAMELLIA"
  , BlockCipherRecipe "CKM_CAMELLIA_CBC_PAD" 16 [16, 24, 32] 16 True "CKK_CAMELLIA"
  , BlockCipherRecipe "CKM_CAMELLIA_CTR" 16 [16, 24, 32] 16 False "CKK_CAMELLIA"
  -- Single DES: fixed 8-byte keys (parity-adjusted at keygen);
  -- CFB/OFB take the raw 8-byte IV and accept any input length
  -- (length-preserving; planners allow unaligned input via
  -- 'Haskoki.Operation.isDesStreamMech'). No OFB8 row: the
  -- provider has no 8-bit OFB for DES.
  , BlockCipherRecipe "CKM_DES_ECB" 8 [8] 0 False "CKK_DES"
  , BlockCipherRecipe "CKM_DES_CBC" 8 [8] 8 False "CKK_DES"
  , BlockCipherRecipe "CKM_DES_CBC_PAD" 8 [8] 8 True "CKK_DES"
  , BlockCipherRecipe "CKM_DES_OFB64" 8 [8] 8 False "CKK_DES"
  , BlockCipherRecipe "CKM_DES_CFB64" 8 [8] 8 False "CKK_DES"
  , BlockCipherRecipe "CKM_DES_CFB8" 8 [8] 8 False "CKK_DES"
  -- CAST-128: variable 1..16-byte keys; plain ECB/CBC geometry.
  , BlockCipherRecipe "CKM_CAST128_ECB" 8 [1 .. 16] 0 False "CKK_CAST128"
  , BlockCipherRecipe "CKM_CAST128_CBC" 8 [1 .. 16] 8 False "CKK_CAST128"
  , BlockCipherRecipe "CKM_CAST128_CBC_PAD" 8 [1 .. 16] 8 True "CKK_CAST128"
  -- CAST/CAST3: the CAST-128 identity at fixed 40/80-bit keys
  -- (RFC 2144 short-key schedules); same geometry, keytypes
  -- CKK_CAST/CKK_CAST3.
  , BlockCipherRecipe "CKM_CAST_ECB" 8 [5] 0 False "CKK_CAST"
  , BlockCipherRecipe "CKM_CAST_CBC" 8 [5] 8 False "CKK_CAST"
  , BlockCipherRecipe "CKM_CAST_CBC_PAD" 8 [5] 8 True "CKK_CAST"
  , BlockCipherRecipe "CKM_CAST3_ECB" 8 [10] 0 False "CKK_CAST3"
  , BlockCipherRecipe "CKM_CAST3_CBC" 8 [10] 8 False "CKK_CAST3"
  , BlockCipherRecipe "CKM_CAST3_CBC_PAD" 8 [10] 8 True "CKK_CAST3"
  -- IDEA: fixed 16-byte keys; plain ECB/CBC geometry.
  , BlockCipherRecipe "CKM_IDEA_ECB" 8 [16] 0 False "CKK_IDEA"
  , BlockCipherRecipe "CKM_IDEA_CBC" 8 [16] 8 False "CKK_IDEA"
  , BlockCipherRecipe "CKM_IDEA_CBC_PAD" 8 [16] 8 True "CKK_IDEA"
  -- SEED: fixed 16-byte keys on 16-byte blocks.
  , BlockCipherRecipe "CKM_SEED_ECB" 16 [16] 0 False "CKK_SEED"
  , BlockCipherRecipe "CKM_SEED_CBC" 16 [16] 16 False "CKK_SEED"
  , BlockCipherRecipe "CKM_SEED_CBC_PAD" 16 [16] 16 True "CKK_SEED"
  -- Blowfish: variable 4..56-byte keys; no ECB row exists.
  , BlockCipherRecipe "CKM_BLOWFISH_CBC" 8 [4 .. 56] 8 False "CKK_BLOWFISH"
  , BlockCipherRecipe "CKM_BLOWFISH_CBC_PAD" 8 [4 .. 56] 8 True "CKK_BLOWFISH"
  -- RC2: variable 1..128-byte keys; parameters are the canonical
  -- RC2 image (effective-bits word, plus the IV for CBC rows),
  -- never raw IV bytes. The crIvBytes holds the IV length (0 for
  -- ECB, 8 for CBC rows); 'cipherParamsValid' enforces the struct
  -- shape.
  , BlockCipherRecipe "CKM_RC2_ECB" 8 [1 .. 128] 0 False "CKK_RC2"
  , BlockCipherRecipe "CKM_RC2_CBC" 8 [1 .. 128] 8 False "CKK_RC2"
  , BlockCipherRecipe "CKM_RC2_CBC_PAD" 8 [1 .. 128] 8 True "CKK_RC2"
  -- RC4: stream cipher; empty parameters, any input length, keys
  -- 1..255 bytes (planners allow unaligned input via
  -- 'Haskoki.Operation.isRc4Mech').
  , BlockCipherRecipe "CKM_RC4" 1 [1 .. 255] 0 False "CKK_RC4"
  ]

-- | Resolve a mechanism id to its block-cipher recipe, if covered.
cipherRecipeFor :: MechanismId -> Maybe BlockCipherRecipe
cipherRecipeFor mid =
  case [ r | r <- cipherRecipes
           , MechanismId (mustGeneratedId (crName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing

-- | Resolve a mechanism id to its CTR recipe row, if it is a CTR
-- mechanism (drives the FFI struct translation and the driver
-- image split).
ctrRecipeFor :: MechanismId -> Maybe BlockCipherRecipe
ctrRecipeFor mid = case cipherRecipeFor mid of
  Just r | crName r `elem` ctrNames -> Just r
  _ -> Nothing

-- | Resolve a mechanism id to its RC2 recipe row, if it is an RC2
-- mechanism (drives the FFI struct translation; the driver image
-- split keys off 'rc2Names' through 'isRc2Mech').
rc2RecipeFor :: MechanismId -> Maybe BlockCipherRecipe
rc2RecipeFor mid = case cipherRecipeFor mid of
  Just r | crName r `elem` rc2Names -> Just r
  _ -> Nothing
