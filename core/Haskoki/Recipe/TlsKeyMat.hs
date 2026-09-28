{- | TLS key-material recipes.

The three key-material rows derive TLS key blocks via the TLS
PRF and split them into keys (+ IVs):

* @CKM_TLS_KEY_AND_MAC_DERIVE@ (0x376): TLS 1.0 PRF
  (MD5/SHA-1), @CK_SSL3_KEY_MAT_PARAMS@;
* @CKM_TLS12_KEY_AND_MAC_DERIVE@ (0x3e1): TLS 1.2 PRF
  (hash-selected), @CK_TLS12_KEY_MAT_PARAMS@;
* @CKM_TLS12_KEY_SAFE_DERIVE@ (0x3e3): identical to 0x3e1
  except IVs are never produced (v3.2 §6.40.7).

The canonical frame (@keymat-params\/1@) is the PRF code
(0 = legacy, else the hash code), the MAC\/key\/IV byte sizes
(u16be each), and the two length-prefixed randoms
(client, server).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.TlsKeyMat
  ( TlsKeyMatKind (..)
  , TlsKeyMatRecipe (..)
  , TlsKeyMatRole (..)
  , tlsKeyMatCodec
  , tlsKeyMatCodecFor
  , tlsKeyMatRecipes
  , tlsKeyMatRecipeFor
  , encodeTlsKeyMatParams
  , decodeTlsKeyMatParams
  , tlsKeyMatParamsValid
  , tlsKeyMatPrfOk
  , tlsKeyMatBaseKeyOk
  , tlsKeyMatLayout
  , tlsKeyMatLabel
  , maxTlsKeyMatBlock
  , maxTlsKeyMatMaterial
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64, Word8)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The three key-material rows.
data TlsKeyMatKind
  = KeyMatTls10
  | KeyMatTls12
  | KeyMatTls12Safe
  deriving (Eq, Show)

-- | One key-material recipe: the mechanism name and its shape.
data TlsKeyMatRecipe = TlsKeyMatRecipe
  { tkmName :: !MechanismName
  , tkmKind :: !TlsKeyMatKind
  } deriving (Eq, Show)

-- | One key-block segment role, in RFC 2246 §6.3 order.
data TlsKeyMatRole
  = KeyMatMacClient
  | KeyMatMacServer
  | KeyMatKeyClient
  | KeyMatKeyServer
  | KeyMatIvClient
  | KeyMatIvServer
  deriving (Eq, Show)

-- | The key-material frame codec.
tlsKeyMatCodec :: ParameterCodec
tlsKeyMatCodec = ParameterCodec "keymat-params" 1

-- | The codec rides every recipe row.
tlsKeyMatCodecFor :: TlsKeyMatRecipe -> ParameterCodec
tlsKeyMatCodecFor _ = tlsKeyMatCodec

-- | The TLS key-expansion label.
tlsKeyMatLabel :: ByteString
tlsKeyMatLabel = "key expansion"

-- | Key-block ceiling in bytes.
maxTlsKeyMatBlock :: Int
maxTlsKeyMatBlock = 65536

-- | Random material ceiling in bytes.
maxTlsKeyMatMaterial :: Int
maxTlsKeyMatMaterial = 65536

-- | The three covered mechanisms.
tlsKeyMatRecipes :: [TlsKeyMatRecipe]
tlsKeyMatRecipes =
  [ TlsKeyMatRecipe "CKM_TLS_KEY_AND_MAC_DERIVE" KeyMatTls10
  , TlsKeyMatRecipe "CKM_TLS12_KEY_AND_MAC_DERIVE" KeyMatTls12
  , TlsKeyMatRecipe "CKM_TLS12_KEY_SAFE_DERIVE" KeyMatTls12Safe
  ]

-- | Resolve a mechanism id to its key-material recipe, if covered.
tlsKeyMatRecipeFor :: MechanismId -> Maybe TlsKeyMatRecipe
tlsKeyMatRecipeFor mid =
  case [ r | r <- tlsKeyMatRecipes
           , MechanismId (mustGeneratedId (tkmName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing

encodeU16 :: Int -> ByteString
encodeU16 n = BS.pack [fromIntegral ((n `div` 256) `mod` 256), fromIntegral (n `mod` 256)]

decodeU16 :: ByteString -> Maybe (Int, ByteString)
decodeU16 bs
  | BS.length bs < 2 = Nothing
  | otherwise =
      let (w, rest) = BS.splitAt 2 bs
      in Just (BS.foldl' (\a b -> a * 256 + fromIntegral b) 0 w, rest)

-- | Encode the canonical frame: @prf:u8 mac:u16be key:u16be
-- iv:u16be crLen:u16be cr srLen:u16be sr@.
encodeTlsKeyMatParams :: Word8 -> Int -> Int -> Int -> ByteString -> ByteString -> ByteString
encodeTlsKeyMatParams prf mac key iv cr sr =
  BS.singleton prf
    <> encodeU16 mac <> encodeU16 key <> encodeU16 iv
    <> encodeU16 (BS.length cr) <> cr
    <> encodeU16 (BS.length sr) <> sr

-- | Decode the canonical frame ('Nothing' on truncation,
-- trailing bytes, or over-ceiling material).
decodeTlsKeyMatParams :: ByteString -> Maybe (Word8, Int, Int, Int, ByteString, ByteString)
decodeTlsKeyMatParams bs = case BS.uncons bs of
  Nothing -> Nothing
  Just (prf, r0) -> do
    (mac, r1) <- decodeU16 r0
    (key, r2) <- decodeU16 r1
    (iv, r3) <- decodeU16 r2
    (crLen, r4) <- decodeU16 r3
    let (cr, r5) = BS.splitAt crLen r4
    if BS.length cr /= crLen then Nothing else do
      (srLen, r6) <- decodeU16 r5
      let (sr, rest) = BS.splitAt srLen r6
      if BS.length sr /= srLen || not (BS.null rest) then Nothing
        else if BS.length cr + BS.length sr > maxTlsKeyMatMaterial then Nothing
          else Just (prf, mac, key, iv, cr, sr)

-- | A TLS random is fixed 32 bytes (RFC 2246 §6.1, RFC 5246
-- §6.1: 4-byte time + 28-byte nonce).
tlsKeyMatRandomLen :: Int
tlsKeyMatRandomLen = 32

-- | PRF rule by kind: the TLS 1.0 row is legacy-only (code 0),
-- the TLS 1.2 rows are hash-only (codes 1..13 in the
-- 'kdfCodeDigest' space).
tlsKeyMatPrfOk :: TlsKeyMatKind -> Word8 -> Bool
tlsKeyMatPrfOk KeyMatTls10 prf = prf == 0
tlsKeyMatPrfOk _ prf = prf >= 1 && prf <= 13

-- | Parameter validation: the frame decodes, the PRF matches
-- the row kind, keys are mandatory (MAC\/IV optional), both
-- randoms are 32 bytes, and the key block fits the ceiling.
tlsKeyMatParamsValid :: TlsKeyMatRecipe -> ByteString -> Bool
tlsKeyMatParamsValid r params = case decodeTlsKeyMatParams params of
  Nothing -> False
  Just (prf, mac, key, iv, cr, sr) ->
    tlsKeyMatPrfOk (tkmKind r) prf
      && key > 0
      && BS.length cr == tlsKeyMatRandomLen
      && BS.length sr == tlsKeyMatRandomLen
      && 2 * mac + 2 * key + 2 * iv <= maxTlsKeyMatBlock

-- | Key-material bases are generic secrets only (the master
-- secret rides a generic-secret key, as the oracle imports
-- it).
tlsKeyMatBaseKeyOk :: Word64 -> Bool
tlsKeyMatBaseKeyOk kty = kty == mustKeyTypeId "CKK_GENERIC_SECRET"

-- | Split sizes into RFC-ordered segments (RFC 2246 §6.3: MAC
-- pair, key pair, IV pair); zero MAC\/IV sizes emit no
-- segment.
tlsKeyMatLayout :: Int -> Int -> Int -> [(TlsKeyMatRole, Int)]
tlsKeyMatLayout mac key iv =
  macSeg KeyMatMacClient ++ macSeg KeyMatMacServer
    ++ [(KeyMatKeyClient, key), (KeyMatKeyServer, key)]
    ++ ivSeg KeyMatIvClient ++ ivSeg KeyMatIvServer
  where
    macSeg _ | mac <= 0 = []
    macSeg role = [(role, mac)]
    ivSeg _ | iv <= 0 = []
    ivSeg role = [(role, iv)]
