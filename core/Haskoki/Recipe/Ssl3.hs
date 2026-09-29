{- | SSL 3.0 recipes (RFC 6101).

The five served rows:

* @CKM_SSL3_MASTER_KEY_DERIVE@ (0x371): 48-byte master
  secret from @MD5(pre_master + SHA1(pad + pre_master +
  CR + SR))@ over pads @A@, @BB@, @CCC@ (§6.1);
* @CKM_SSL3_MASTER_KEY_DERIVE_DH@ (0x373): the same
  construction over a DH-derived base;
* @CKM_SSL3_KEY_AND_MAC_DERIVE@ (0x372): the §6.2.2 key
  block (@MD5(master + SHA1(pad + master + SR + CR))@
  iterated, pads @A@..@Zz...@) split client MAC, server
  MAC, client key, server key, client IV, server IV;
* @CKM_SSL3_MD5_MAC@ (0x380) and @CKM_SSL3_SHA1_MAC@
  (0x381): @H(secret + pad2 + H(secret + pad1 + data))@
  with 48-byte (MD5) \/ 40-byte (SHA-1) @0x36@\/@0x5c@
  pads, truncated to the requested bit length.

The canonical frames are @ssl3-master-params\/1@
(@crLen:u16be cr srLen:u16be sr@) and
@ssl3-keymat-params\/1@ (@mac:u16be key:u16be iv:u16be@
plus the two length-prefixed randoms); the MAC rows reuse
the shared @mac-general\/1@ length codec, interpreted in
BITS (128 selects the full 16-byte MD5 tag).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Ssl3
  ( Ssl3Kind (..)
  , Ssl3Recipe (..)
  , Ssl3KeyMatRole (..)
  , ssl3MasterCodec
  , ssl3KeyMatCodec
  , ssl3CodecFor
  , ssl3Recipes
  , ssl3RecipeFor
  , encodeSsl3MasterParams
  , decodeSsl3MasterParams
  , encodeSsl3KeyMatParams
  , decodeSsl3KeyMatParams
  , ssl3ParamsValid
  , ssl3BaseKeyOk
  , ssl3KeyMatLayout
  , ssl3MacOutLen
  , maxSsl3KeyBlock
  , maxSsl3Material
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Recipe.Hmac (decodeMacGeneral, hmacGeneralCodec)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The five served SSL3 rows.
data Ssl3Kind
  = Ssl3Master
  | Ssl3MasterDh
  | Ssl3KeyMat
  | Ssl3Md5Mac
  | Ssl3Sha1Mac
  deriving (Eq, Show)

-- | One SSL3 recipe: the mechanism name and its shape.
data Ssl3Recipe = Ssl3Recipe
  { ssl3Name :: !MechanismName
  , ssl3Kind :: !Ssl3Kind
  } deriving (Eq, Show)

-- | One key-block segment role, in RFC 6101 §6.2.2 order.
data Ssl3KeyMatRole
  = Ssl3MacClient
  | Ssl3MacServer
  | Ssl3KeyClient
  | Ssl3KeyServer
  | Ssl3IvClient
  | Ssl3IvServer
  deriving (Eq, Show)

-- | The master-derive frame codec.
ssl3MasterCodec :: ParameterCodec
ssl3MasterCodec = ParameterCodec "ssl3-master-params" 1

-- | The key-material frame codec.
ssl3KeyMatCodec :: ParameterCodec
ssl3KeyMatCodec = ParameterCodec "ssl3-keymat-params" 1

-- | The codec for one recipe row (MAC rows share the
-- GENERAL length codec).
ssl3CodecFor :: Ssl3Recipe -> ParameterCodec
ssl3CodecFor r = case ssl3Kind r of
  Ssl3Master -> ssl3MasterCodec
  Ssl3MasterDh -> ssl3MasterCodec
  Ssl3KeyMat -> ssl3KeyMatCodec
  Ssl3Md5Mac -> hmacGeneralCodec
  Ssl3Sha1Mac -> hmacGeneralCodec

-- | Key-block ceiling in bytes: 191 MD5 rounds, the RFC 6101
-- construction bound (pad bytes run @A@..@0xFF@; past round
-- 191 the pad byte is undefined, so larger blocks refuse).
maxSsl3KeyBlock :: Int
maxSsl3KeyBlock = 3056

-- | Random material ceiling in bytes.
maxSsl3Material :: Int
maxSsl3Material = 65536

-- | The five covered mechanisms.
ssl3Recipes :: [Ssl3Recipe]
ssl3Recipes =
  [ Ssl3Recipe "CKM_SSL3_MASTER_KEY_DERIVE" Ssl3Master
  , Ssl3Recipe "CKM_SSL3_MASTER_KEY_DERIVE_DH" Ssl3MasterDh
  , Ssl3Recipe "CKM_SSL3_KEY_AND_MAC_DERIVE" Ssl3KeyMat
  , Ssl3Recipe "CKM_SSL3_MD5_MAC" Ssl3Md5Mac
  , Ssl3Recipe "CKM_SSL3_SHA1_MAC" Ssl3Sha1Mac
  ]

-- | Resolve a mechanism id to its SSL3 recipe, if covered.
ssl3RecipeFor :: MechanismId -> Maybe Ssl3Recipe
ssl3RecipeFor mid =
  case [ r | r <- ssl3Recipes
           , MechanismId (mustGeneratedId (ssl3Name r)) == mid ] of
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

-- | Encode the master frame: @crLen:u16be cr srLen:u16be
-- sr@.
encodeSsl3MasterParams :: ByteString -> ByteString -> ByteString
encodeSsl3MasterParams cr sr =
  encodeU16 (BS.length cr) <> cr
    <> encodeU16 (BS.length sr) <> sr

-- | Decode the master frame ('Nothing' on truncation or
-- trailing bytes).
decodeSsl3MasterParams :: ByteString -> Maybe (ByteString, ByteString)
decodeSsl3MasterParams bs = do
  (crLen, r0) <- decodeU16 bs
  let (cr, r1) = BS.splitAt crLen r0
  if BS.length cr /= crLen then Nothing else do
    (srLen, r2) <- decodeU16 r1
    let (sr, rest) = BS.splitAt srLen r2
    if BS.length sr /= srLen || not (BS.null rest) then Nothing
      else Just (cr, sr)

-- | Encode the key-material frame: @mac:u16be key:u16be
-- iv:u16be crLen:u16be cr srLen:u16be sr@.
encodeSsl3KeyMatParams :: Int -> Int -> Int -> ByteString -> ByteString -> ByteString
encodeSsl3KeyMatParams mac key iv cr sr =
  encodeU16 mac <> encodeU16 key <> encodeU16 iv
    <> encodeU16 (BS.length cr) <> cr
    <> encodeU16 (BS.length sr) <> sr

-- | Decode the key-material frame ('Nothing' on
-- truncation or trailing bytes).
decodeSsl3KeyMatParams :: ByteString -> Maybe (Int, Int, Int, ByteString, ByteString)
decodeSsl3KeyMatParams bs = do
  (mac, r0) <- decodeU16 bs
  (key, r1) <- decodeU16 r0
  (iv, r2) <- decodeU16 r1
  (crLen, r3) <- decodeU16 r2
  let (cr, r4) = BS.splitAt crLen r3
  if BS.length cr /= crLen then Nothing else do
    (srLen, r5) <- decodeU16 r4
    let (sr, rest) = BS.splitAt srLen r5
    if BS.length sr /= srLen || not (BS.null rest) then Nothing
      else Just (mac, key, iv, cr, sr)

-- | Full MAC output width in bytes (the bit-length
-- ceiling is eight times this).
ssl3MacOutLen :: Ssl3Kind -> Int
ssl3MacOutLen Ssl3Md5Mac = 16
ssl3MacOutLen Ssl3Sha1Mac = 20
ssl3MacOutLen _ = 0

-- | Parameter validation: master rows take non-empty
-- randoms within the material ceiling (no fixed width —
-- the oracle sends 28-byte randoms); keymat rows
-- additionally require keys plus a within-ceiling block;
-- MAC rows take a whole-byte bit length within the hash
-- width.
ssl3ParamsValid :: Ssl3Recipe -> ByteString -> Bool
ssl3ParamsValid r params = case ssl3Kind r of
  Ssl3Master -> masterValid params
  Ssl3MasterDh -> masterValid params
  Ssl3KeyMat -> case decodeSsl3KeyMatParams params of
    Nothing -> False
    Just (mac, key, iv, cr, sr) ->
      key > 0
        && randomsOk cr sr
        && 2 * mac + 2 * key + 2 * iv <= maxSsl3KeyBlock
  Ssl3Md5Mac -> macValid 16 params
  Ssl3Sha1Mac -> macValid 20 params
  where
    masterValid bs = case decodeSsl3MasterParams bs of
      Nothing -> False
      Just (cr, sr) -> randomsOk cr sr
    randomsOk cr sr =
      not (BS.null cr) && not (BS.null sr)
        && BS.length cr + BS.length sr <= maxSsl3Material
    macValid outLen bs = case decodeMacGeneral bs of
      Just n -> n >= 8 && n <= 8 * outLen && n `mod` 8 == 0
      Nothing -> False

-- | SSL3 bases are generic secrets only (the oracle
-- imports pre-master and master secrets as generic
-- secrets, including the DH variant's base).
ssl3BaseKeyOk :: Word64 -> Bool
ssl3BaseKeyOk kty = kty == mustKeyTypeId "CKK_GENERIC_SECRET"

-- | Split sizes into RFC 6101 §6.2.2-ordered segments;
-- zero MAC\/IV sizes emit no segment.
ssl3KeyMatLayout :: Int -> Int -> Int -> [(Ssl3KeyMatRole, Int)]
ssl3KeyMatLayout mac key iv =
  macSeg Ssl3MacClient ++ macSeg Ssl3MacServer
    ++ [(Ssl3KeyClient, key), (Ssl3KeyServer, key)]
    ++ ivSeg Ssl3IvClient ++ ivSeg Ssl3IvServer
  where
    macSeg _ | mac <= 0 = []
    macSeg role = [(role, mac)]
    ivSeg _ | iv <= 0 = []
    ivSeg role = [(role, iv)]
