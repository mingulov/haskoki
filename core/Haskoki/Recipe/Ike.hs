{- | IKE protocol-KDF recipes.

The four IKE rows derive HMAC-based keying material from a
base key (generic-secret or HMAC-typed) plus per-row inputs:

* @CKM_IKE2_PRF_PLUS_DERIVE@ (0x402e): prf+ iteration
  @T_i = PRF(K, T_{i-1} | seed | i)@ (RFC 4306 §2.8),
  seed bytes only (a seed key is refused: no oracle leg
  carries one);
* @CKM_IKE_PRF_DERIVE@ (0x402f): the single shot
  @PRF(K, Ni | Nr)@, or @PRF(Ni | Nr, K)@ with data-as-key
  (the rekey leg is refused: the only oracle leg is the
  data-as-key+rekey combination rejection);
* @CKM_IKE1_PRF_DERIVE@ (0x4030): the single shot
  @PRF(K, g^xy | CKY-I | CKY-R | n)@ with the g^xy aux key
  resolved from its params-carried handle (a prevkey is
  refused: no oracle leg carries one);
* @CKM_IKE1_EXTENDED_DERIVE@ (0x4031): the prf-like
  iteration @T_i = PRF(K, T_{i-1} | g^xy | extra)@ (no
  counter), the aux keygxy optional, truncating the base
  when neither input is present (the oracle reference
  rule).

The canonical frame (@ike-params\/1@) is the PRF code byte
(0 = unmapped selector, structurally valid so the planner
can deny it with the spec code; 1..13 served), a flags byte
(bit 0 = data-as-key, IKE-PRF only), the key-number byte
(IKEv1-PRF only), the aux external handle (u64be, 0 =
absent), and two length-prefixed blobs (seed \/ nonces \/
cookies \/ extra, unused slots empty).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Ike
  ( IkeKind (..)
  , IkeRecipe (..)
  , ikeCodec
  , ikeCodecFor
  , ikeRecipes
  , ikeRecipeFor
  , encodeIkeParams
  , decodeIkeParams
  , ikeParamsValid
  , ikePrfCodeFor
  , ikeBaseKeyOk
  , maxIkeOutput
  , maxIkeMaterial
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64, Word8)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Recipe.Kdf (kdfCodeDigest)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The four IKE parameter shapes.
data IkeKind
  = Ike2PrfPlus
  | IkePrf
  | Ike1Prf
  | Ike1Extended
  deriving (Eq, Show)

-- | One IKE recipe: the mechanism name and its shape.
data IkeRecipe = IkeRecipe
  { ikName :: !MechanismName
  , ikKind :: !IkeKind
  } deriving (Eq, Show)

-- | The IKE frame codec.
ikeCodec :: ParameterCodec
ikeCodec = ParameterCodec "ike-params" 1

-- | The codec rides every recipe row.
ikeCodecFor :: IkeRecipe -> ParameterCodec
ikeCodecFor _ = ikeCodec

-- | Output ceiling: the prf+ counter capacity at the widest
-- served digest (255 blocks of 64 bytes); the single-shot
-- rows additionally cap at their PRF width.
maxIkeOutput :: Int
maxIkeOutput = 255 * 64

-- | Blob material ceiling in bytes.
maxIkeMaterial :: Int
maxIkeMaterial = 65536

encodeWord64 :: Int -> ByteString
encodeWord64 n =
  BS.pack [fromIntegral ((n `shiftR` s) .&. 0xff) | s <- [56, 48 .. 0]]

decodeWord64 :: ByteString -> Maybe (Int, ByteString)
decodeWord64 bs = do
  (h, r) <- Just (BS.splitAt 8 bs)
  if BS.length h /= 8 then Nothing
    else Just (BS.foldl' (\a b -> a `shiftL` 8 + fromIntegral b) 0 h, r)

decodeSized :: ByteString -> Maybe (ByteString, ByteString)
decodeSized bs = do
  (n, r0) <- decodeWord64 bs
  if n < 0 || n > BS.length r0 then Nothing
    else Just (BS.splitAt n r0)

-- | Encode the canonical frame.
encodeIkeParams :: Word8 -> Word8 -> Word8 -> Word64 -> ByteString -> ByteString -> ByteString
encodeIkeParams prf flags keynum aux b1 b2 =
  BS.singleton prf <> BS.singleton flags <> BS.singleton keynum
    <> encodeWord64 (fromIntegral aux)
    <> encodeWord64 (BS.length b1) <> b1
    <> encodeWord64 (BS.length b2) <> b2

-- | Decode the canonical frame ('Nothing' on truncation,
-- trailing bytes, or over-ceiling material).
decodeIkeParams :: ByteString -> Maybe (Word8, Word8, Word8, Word64, ByteString, ByteString)
decodeIkeParams bs = case BS.uncons bs of
  Nothing -> Nothing
  Just (prf, r0) -> case BS.uncons r0 of
    Nothing -> Nothing
    Just (flags, r1) -> case BS.uncons r1 of
      Nothing -> Nothing
      Just (keynum, r2) -> do
        (auxN, r3) <- decodeWord64 r2
        (b1, r4) <- decodeSized r3
        (b2, rest) <- decodeSized r4
        if not (BS.null rest) then Nothing
          else if BS.length b1 + BS.length b2 > maxIkeMaterial
            then Nothing
            else Just (prf, flags, keynum, fromIntegral auxN, b1, b2)

-- | Frame validation: the per-kind matrix (PRF 0..13 with 0
-- structurally valid for the planner's spec denial; aux,
-- flags, key-number, and blob-slot rules per kind).
ikeParamsValid :: IkeRecipe -> ByteString -> Bool
ikeParamsValid r bs = case decodeIkeParams bs of
  Nothing -> False
  Just (prf, flags, keynum, aux, _b1, b2)
    | prf > 13 -> False
    | otherwise -> case ikKind r of
        Ike2PrfPlus -> flags == 0 && keynum == 0 && aux == 0 && BS.null b2
        IkePrf -> flags <= 1 && keynum == 0 && aux == 0
        Ike1Prf -> flags == 0 && aux /= 0
        Ike1Extended -> flags == 0 && keynum == 0 && BS.null b2

-- | The PRF selector onto the code: @CKM_\<stem\>_HMAC@ over
-- the served digest space (codes 1..13 via 'kdfCodeDigest').
-- Bare digests, GENERAL rows, and non-MAC mechanisms refuse
-- ('Nothing' — the planner denies the reserved code-0 frame
-- with the spec code).
ikePrfCodeFor :: MechanismId -> Maybe Word8
ikePrfCodeFor (MechanismId mid) =
  foldr (\c acc -> case match c of Just k -> Just k; Nothing -> acc) Nothing [1 .. 13]
  where
    match code = case kdfCodeDigest (fromIntegral code) of
      Just stem
        | mid == mustGeneratedId ("CKM_" <> stem <> "_HMAC") -> Just code
      _ -> Nothing

-- | Base\/aux key types: generic-secret or any HMAC key type.
ikeBaseKeyOk :: Word64 -> Bool
ikeBaseKeyOk kty =
  kty == mustKeyTypeId "CKK_GENERIC_SECRET" || kty `elem` hmacKeyTypes
  where
    hmacKeyTypes =
      [ mustKeyTypeId ("CKK_" <> stem <> "_HMAC")
      | stem <-
          [ "BLAKE2B_512", "BLAKE2B_160", "BLAKE2B_256", "BLAKE2B_384"
          , "SHA224", "SHA256", "SHA384", "SHA512"
          , "SHA512_224", "SHA512_256"
          , "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"
          , "SHA_1", "MD5", "RIPEMD160"
          ]
      ]

-- | The four covered mechanisms.
ikeRecipes :: [IkeRecipe]
ikeRecipes =
  [ IkeRecipe "CKM_IKE2_PRF_PLUS_DERIVE" Ike2PrfPlus
  , IkeRecipe "CKM_IKE_PRF_DERIVE" IkePrf
  , IkeRecipe "CKM_IKE1_PRF_DERIVE" Ike1Prf
  , IkeRecipe "CKM_IKE1_EXTENDED_DERIVE" Ike1Extended
  ]

-- | Resolve a mechanism id to its IKE recipe, if covered.
ikeRecipeFor :: MechanismId -> Maybe IkeRecipe
ikeRecipeFor mid =
  case [ r | r <- ikeRecipes
           , MechanismId (mustGeneratedId (ikName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
