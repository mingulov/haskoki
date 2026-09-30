{- | Byte-operation derive recipes.

The five byte-op rows derive by pure byte manipulation over
secret values (no provider crypto):

* @CKM_CONCATENATE_BASE_AND_KEY@ (0x360): base ++ second key
  (the second handle rides the params as a bare @CK_ULONG@);
* @CKM_CONCATENATE_BASE_AND_DATA@ (0x362): base ++ data;
* @CKM_CONCATENATE_DATA_AND_BASE@ (0x363): data ++ base;
* @CKM_XOR_BASE_AND_DATA@ (0x364): byte-wise XOR (equal
  lengths only — a mismatch refuses @CKR_DATA_LEN_RANGE@);
* @CKM_EXTRACT_KEY_FROM_KEY@ (0x365): bit-exact slice at the
  params-carried bit offset (a bare @CK_ULONG@).

The canonical frame (@byteops-params\/1@) is the aux external
handle (u64be, BASE_AND_KEY only), the bit offset (u64be,
EXTRACT only), and one length-prefixed data blob (the three
string-data rows).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.ByteOps
  ( ByteOpsKind (..)
  , ByteOpsRecipe (..)
  , byteOpsCodec
  , byteOpsCodecFor
  , byteOpsRecipes
  , byteOpsRecipeFor
  , encodeByteOpsParams
  , decodeByteOpsParams
  , byteOpsParamsValid
  , byteOpsBaseKeyOk
  , maxByteOpsOutput
  , maxByteOpsMaterial
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The five byte-op parameter shapes.
data ByteOpsKind
  = ConcatBaseAndKey
  | ConcatBaseAndData
  | ConcatDataAndBase
  | XorBaseAndData
  | ExtractKeyFromKey
  deriving (Eq, Show)

-- | One byte-op recipe: the mechanism name and its shape.
data ByteOpsRecipe = ByteOpsRecipe
  { boName :: !MechanismName
  , boKind :: !ByteOpsKind
  } deriving (Eq, Show)

-- | The byte-ops frame codec.
byteOpsCodec :: ParameterCodec
byteOpsCodec = ParameterCodec "byteops-params" 1

-- | The codec rides every recipe row.
byteOpsCodecFor :: ByteOpsRecipe -> ParameterCodec
byteOpsCodecFor _ = byteOpsCodec

-- | Output ceiling: byte-op outputs are bounded by their
-- inputs; the ceiling matches the material ceiling.
maxByteOpsOutput :: Int
maxByteOpsOutput = 65536

-- | Blob material ceiling in bytes.
maxByteOpsMaterial :: Int
maxByteOpsMaterial = 65536

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
encodeByteOpsParams :: Word64 -> Word64 -> ByteString -> ByteString
encodeByteOpsParams aux off blob =
  encodeWord64 (fromIntegral aux)
    <> encodeWord64 (fromIntegral off)
    <> encodeWord64 (BS.length blob) <> blob

-- | Decode the canonical frame ('Nothing' on truncation,
-- trailing bytes, or over-ceiling material).
decodeByteOpsParams :: ByteString -> Maybe (Word64, Word64, ByteString)
decodeByteOpsParams bs = do
  (auxN, r0) <- decodeWord64 bs
  (offN, r1) <- decodeWord64 r0
  (blob, rest) <- decodeSized r1
  if not (BS.null rest) then Nothing
    else if BS.length blob > maxByteOpsMaterial then Nothing
      else Just (fromIntegral auxN, fromIntegral offN, blob)

-- | Frame validation: the per-kind slot matrix (aux only on
-- BASE_AND_KEY and nonzero there; offset only on EXTRACT;
-- blob only on the three string-data rows).
byteOpsParamsValid :: ByteOpsRecipe -> ByteString -> Bool
byteOpsParamsValid r bs = case decodeByteOpsParams bs of
  Nothing -> False
  Just (aux, off, blob) -> case boKind r of
    ConcatBaseAndKey -> aux /= 0 && off == 0 && BS.null blob
    ConcatBaseAndData -> aux == 0 && off == 0
    ConcatDataAndBase -> aux == 0 && off == 0
    XorBaseAndData -> aux == 0 && off == 0
    ExtractKeyFromKey -> aux == 0 && BS.null blob

-- | Base\/aux key types: generic-secret only (the byte ops
-- manipulate secret values; the oracle probes generic
-- bases exclusively).
byteOpsBaseKeyOk :: Word64 -> Bool
byteOpsBaseKeyOk kty = kty == mustKeyTypeId "CKK_GENERIC_SECRET"

-- | The five covered mechanisms.
byteOpsRecipes :: [ByteOpsRecipe]
byteOpsRecipes =
  [ ByteOpsRecipe "CKM_CONCATENATE_BASE_AND_KEY" ConcatBaseAndKey
  , ByteOpsRecipe "CKM_CONCATENATE_BASE_AND_DATA" ConcatBaseAndData
  , ByteOpsRecipe "CKM_CONCATENATE_DATA_AND_BASE" ConcatDataAndBase
  , ByteOpsRecipe "CKM_XOR_BASE_AND_DATA" XorBaseAndData
  , ByteOpsRecipe "CKM_EXTRACT_KEY_FROM_KEY" ExtractKeyFromKey
  ]

-- | Resolve a mechanism id to its byte-op recipe, if covered.
byteOpsRecipeFor :: MechanismId -> Maybe ByteOpsRecipe
byteOpsRecipeFor mid =
  case [ r | r <- byteOpsRecipes
           , MechanismId (mustGeneratedId (boName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
