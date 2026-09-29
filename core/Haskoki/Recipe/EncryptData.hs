{- | CBC/ECB-encrypt-data recipe: the derive-by-encryption shape.

Eight header mechanisms over four algorithm families derive key
material by encrypting caller-supplied data with the base cipher
key (OASIS PKCS#11 v3.2 §2.8-2.9 family): the CBC rows take the
@CK_*_CBC_ENCRYPT_DATA_PARAMS@ struct (inline IV plus a data
pointer the FFI layer chases into the canonical @iv||data@
frame), the ECB rows take @CK_KEY_DERIVATION_STRING_DATA@
(chased onto the raw data bytes). Output length equals input
length (no padding);
derived totals cap at the data width.

This module owns the group's canonical codecs, parameter/data
validation, block/key/IV geometry, and mechanism table. Pure core
only.

Consumers:

* 'Haskoki.Operation.Derive.planDerive' admits the group's frames
  (base key must be the row's cipher key type);
* 'Haskoki.Engine.Driver' maps covered (mechanism, params) pairs
  to backend 'Haskoki.Engine.Backend.CipherSpec's plus the split
  IV and data;
* the FFI layer chases both native struct shapes onto the
  canonical frames (refusals poison to the empty blob, never the
  raw struct bytes, which could satisfy the unframed recipe).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.EncryptData
  ( EncryptDataRecipe (..)
  , encryptDataRecipes
  , encryptDataRecipeFor
  , encryptDataCbcCodec
  , encryptDataEcbCodec
  , encryptDataCodecFor
  , encryptDataParamsValid
  , encryptDataKeyLenValid
  , decodeEncryptDataParams
  , encryptDataOutputLen
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One encrypt-data recipe: the mechanism name, the block width in
-- bytes, the accepted raw base-key lengths, the IV length carried
-- at the head of the canonical frame (0 for ECB rows), and the key
-- type name (@CKK_*@) the derive planner requires of the base key.
data EncryptDataRecipe = EncryptDataRecipe
  { erName :: !MechanismName
  , erBlockBytes :: !Int
  , erKeyLens :: ![Int]
  , erIvBytes :: !Int
  , erKeyType :: !MechanismName
  } deriving (Eq, Show)

-- | The group's canonical parameter codecs: CBC rows take the
-- @iv||data@ frame, ECB rows the raw data bytes.
encryptDataCbcCodec :: ParameterCodec
encryptDataCbcCodec = ParameterCodec "encrypt-data-cbc" 1

encryptDataEcbCodec :: ParameterCodec
encryptDataEcbCodec = ParameterCodec "encrypt-data-ecb" 1

-- | The codec for one recipe row.
encryptDataCodecFor :: EncryptDataRecipe -> ParameterCodec
encryptDataCodecFor r
  | erIvBytes r == 0 = encryptDataEcbCodec
  | otherwise = encryptDataCbcCodec

-- | All twelve covered mechanisms with their geometry: AES, ARIA
-- and Camellia take 16/24/32-byte keys on 16-byte blocks, Triple-DES
-- takes 16 two-key or 24 three-key bytes on 8-byte blocks (the engines
-- expand @K1||K2@ to @K1||K2||K1@, shared with the Cipher recipe),
-- single DES takes 8-byte keys on 8-byte blocks and SEED 16-byte
-- keys on 16-byte blocks.
encryptDataRecipes :: [EncryptDataRecipe]
encryptDataRecipes =
  [ EncryptDataRecipe "CKM_AES_CBC_ENCRYPT_DATA" 16 [16, 24, 32] 16 "CKK_AES"
  , EncryptDataRecipe "CKM_AES_ECB_ENCRYPT_DATA" 16 [16, 24, 32] 0 "CKK_AES"
  , EncryptDataRecipe "CKM_ARIA_CBC_ENCRYPT_DATA" 16 [16, 24, 32] 16 "CKK_ARIA"
  , EncryptDataRecipe "CKM_ARIA_ECB_ENCRYPT_DATA" 16 [16, 24, 32] 0 "CKK_ARIA"
  , EncryptDataRecipe "CKM_CAMELLIA_CBC_ENCRYPT_DATA" 16 [16, 24, 32] 16 "CKK_CAMELLIA"
  , EncryptDataRecipe "CKM_CAMELLIA_ECB_ENCRYPT_DATA" 16 [16, 24, 32] 0 "CKK_CAMELLIA"
  , EncryptDataRecipe "CKM_DES3_CBC_ENCRYPT_DATA" 8 [16, 24] 8 "CKK_DES3"
  , EncryptDataRecipe "CKM_DES3_ECB_ENCRYPT_DATA" 8 [16, 24] 0 "CKK_DES3"
  , EncryptDataRecipe "CKM_DES_CBC_ENCRYPT_DATA" 8 [8] 8 "CKK_DES"
  , EncryptDataRecipe "CKM_DES_ECB_ENCRYPT_DATA" 8 [8] 0 "CKK_DES"
  , EncryptDataRecipe "CKM_SEED_CBC_ENCRYPT_DATA" 16 [16] 16 "CKK_SEED"
  , EncryptDataRecipe "CKM_SEED_ECB_ENCRYPT_DATA" 16 [16] 0 "CKK_SEED"
  ]

-- | Resolve a mechanism id to its encrypt-data recipe, if covered.
encryptDataRecipeFor :: MechanismId -> Maybe EncryptDataRecipe
encryptDataRecipeFor mid =
  case [ r | r <- encryptDataRecipes
           , MechanismId (mustGeneratedId (erName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing

-- | Parameter validation: CBC rows need the IV plus non-empty
-- block-multiple data; ECB rows need non-empty block-multiple
-- data.
encryptDataParamsValid :: EncryptDataRecipe -> ByteString -> Bool
encryptDataParamsValid r bs =
  let iv = erIvBytes r
      block = erBlockBytes r
      datLen = BS.length bs - iv
  in BS.length bs >= iv && datLen > 0 && datLen `mod` block == 0

-- | Base-key-length validation: membership in the recipe's key set.
encryptDataKeyLenValid :: EncryptDataRecipe -> Int -> Bool
encryptDataKeyLenValid r n = n `elem` erKeyLens r

-- | Split a valid canonical frame into @(iv, data)@ (empty IV for
-- ECB rows). 'Nothing' on any invalid frame.
decodeEncryptDataParams :: EncryptDataRecipe -> ByteString -> Maybe (ByteString, ByteString)
decodeEncryptDataParams r bs
  | encryptDataParamsValid r bs = Just (BS.take (erIvBytes r) bs, BS.drop (erIvBytes r) bs)
  | otherwise = Nothing

-- | The derived-output width of a valid frame: the data length.
-- 'Nothing' on any invalid frame.
encryptDataOutputLen :: EncryptDataRecipe -> ByteString -> Maybe Int
encryptDataOutputLen r bs = fmap (BS.length . snd) (decodeEncryptDataParams r bs)
