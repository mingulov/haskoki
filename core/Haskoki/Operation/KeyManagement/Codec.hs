{- | KeyManagement framing codecs: generation-argument frames,
wrap params, key-pair framing, integer codecs, and PKCS#7 padding.

Pure leaf module: bytestring framing only. Used by the planners
and the currency finisher, and re-exported to the driver via the shell.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.KeyManagement.Codec
  ( GenArgs (..)
  , encodeGenArgs
  , decodeGenArgs
  , encodeWrapParams
  , decodeWrapParams
  , encodeKeyPair
  , decodeKeyPair
  , padPkcs7
  , unpadPkcs7
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Word (Word8)

import Haskoki.Bytes (foldBE, u16be, u32be, u64be)


-- | Key-generation arguments framed for the driver: AES length in
-- bytes, EC curve name, RSA modulus bits plus public exponent, the
-- ML-KEM parameter set (512\/768\/1024), an opaque secret length in
-- bytes (HOTP), the DSA @(L, N)@ size pair (parameter generation),
-- DER DSS-Parms (DSA keypair generation from domain parameters),
-- the Edwards curve name (Edwards keypair generation), the
-- Montgomery curve name (Montgomery keypair generation), or the
-- ML-DSA parameter-set id (@CKP_ML_DSA_44\/65\/87@ = 1\/2\/3),
-- or the SLH-DSA parameter-set id (@CKP_SLH_DSA_*@ = 1..12).
data GenArgs
  = GenAes !Int
  | GenEc !ByteString
  | GenRsa !Int !Integer
  | GenMlKem !Int
  | GenBytes !Int
  | GenDsaParams !Int !Int
  | GenDsaKeypair !ByteString
  | GenEdwardsKeypair !ByteString
  | GenMontgomeryKeypair !ByteString
  | GenMlDsa !Int
  | GenSlhDsa !Int
  | GenDhKeypair !ByteString
  | GenParityBytes !Int
  | GenTlsPremaster !Word8 !Word8
  | GenWtlsPremaster !Word8 !Int
  | GenPbkd2 !Int
  | GenPbe !Int
  deriving (Eq, Show)

-- | Frame generation arguments: @tag:u8 ...@ with tag 0 AES
-- (@len:u8@), 1 EC (curve bytes), 2 RSA (@bits:u64be exp:u64be@),
-- 3 ML-KEM (@alg:u16be@), 4 opaque secret bytes (@len:u8@), 5 DSA
-- parameter sizes (@L:u16be N:u16be@), 6 DSA keypair domain
-- parameters (@len:u32be DER@), 7 Edwards keypair curve name
-- (curve bytes), 8 ML-DSA parameter-set id (@ckp:u16be@),
-- 9 SLH-DSA parameter-set id (@ckp:u16be@), 10 DH keypair domain
-- parameters (@len:u32be DER@), 11 odd-parity secret bytes
-- (@len:u8@: DES/DES2/CDMF set parity per FIPS 46-3), 12
-- TLS/SSL3 pre-master (@major:u8 minor:u8@, fixed 48 bytes),
-- 13 WTLS pre-master (@ver:u8 len:u8@), 14 PBKD2 derived key
-- (@len:u16be@: the shared ceiling exceeds one byte), 15
-- Montgomery keypair curve name (curve bytes), 16 PBE derived
-- key (@len:u8@: fixed 16\/24 widths).
encodeGenArgs :: GenArgs -> ByteString
encodeGenArgs args = case args of
  GenAes n -> BS.singleton 0 <> BS.singleton (fromIntegral n)
  GenEc curve -> BS.singleton 1 <> curve
  GenRsa bits e -> BS.singleton 2 <> u64be (fromIntegral bits) <> u64be (fromIntegral e)
  GenMlKem alg -> BS.singleton 3 <> BS.pack
    [fromIntegral (alg `div` 256), fromIntegral (alg `mod` 256)]
  GenBytes n -> BS.singleton 4 <> BS.singleton (fromIntegral n)
  GenDsaParams l n -> BS.singleton 5 <> u16be l <> u16be n
  GenDsaKeypair der -> BS.singleton 6 <> u32be (BS.length der) <> der
  GenEdwardsKeypair curve -> BS.singleton 7 <> curve
  GenMontgomeryKeypair curve -> BS.singleton 15 <> curve
  GenMlDsa ckp -> BS.singleton 8 <> u16be ckp
  GenSlhDsa ckp -> BS.singleton 9 <> u16be ckp
  GenDhKeypair der -> BS.singleton 10 <> u32be (BS.length der) <> der
  GenParityBytes n -> BS.singleton 11 <> BS.singleton (fromIntegral n)
  GenTlsPremaster major minor -> BS.singleton 12 <> BS.pack [major, minor]
  GenWtlsPremaster ver n -> BS.singleton 13 <> BS.pack [ver, fromIntegral n]
  GenPbkd2 n -> BS.singleton 14 <> u16be n
  GenPbe n -> BS.singleton 16 <> BS.singleton (fromIntegral n)

-- | Parse framed generation arguments. Short frames, unknown tags
-- and trailing bytes all fail.
decodeGenArgs :: ByteString -> Maybe GenArgs
decodeGenArgs bs = case BS.uncons bs of
  Just (0, rest) -> case BS.unpack rest of
    [n] -> Just (GenAes (fromIntegral n))
    _ -> Nothing
  Just (1, curve)
    | not (BS.null curve) -> Just (GenEc curve)
    | otherwise -> Nothing
  Just (2, rest)
    | BS.length rest == 16 ->
        let (bBits, bExp) = BS.splitAt 8 rest
        in Just (GenRsa (fromInteger (foldBE bBits)) (foldBE bExp))
    | otherwise -> Nothing
  Just (3, rest) -> case BS.unpack rest of
    [hi, lo] -> Just (GenMlKem (fromIntegral hi * 256 + fromIntegral lo))
    _ -> Nothing
  Just (4, rest) -> case BS.unpack rest of
    [n] -> Just (GenBytes (fromIntegral n))
    _ -> Nothing
  Just (5, rest) -> case BS.unpack rest of
    [lhi, llo, nhi, nlo] -> Just (GenDsaParams
      (fromIntegral lhi * 256 + fromIntegral llo)
      (fromIntegral nhi * 256 + fromIntegral nlo))
    _ -> Nothing
  Just (6, rest)
    | BS.length rest >= 4 ->
        let (bLen, der) = BS.splitAt 4 rest
            n = fromInteger (foldBE bLen)
        in if BS.length der == n && n > 0
          then Just (GenDsaKeypair der)
          else Nothing
    | otherwise -> Nothing
  Just (7, curve)
    | not (BS.null curve) -> Just (GenEdwardsKeypair curve)
    | otherwise -> Nothing
  Just (8, rest) -> case BS.unpack rest of
    [hi, lo] -> Just (GenMlDsa (fromIntegral hi * 256 + fromIntegral lo))
    _ -> Nothing
  Just (9, rest) -> case BS.unpack rest of
    [hi, lo] -> Just (GenSlhDsa (fromIntegral hi * 256 + fromIntegral lo))
    _ -> Nothing
  Just (10, rest)
    | BS.length rest >= 4 ->
        let (bLen, der) = BS.splitAt 4 rest
            n = fromInteger (foldBE bLen)
        in if BS.length der == n && n > 0
          then Just (GenDhKeypair der)
          else Nothing
    | otherwise -> Nothing
  Just (11, rest) -> case BS.unpack rest of
    [n] -> Just (GenParityBytes (fromIntegral n))
    _ -> Nothing
  Just (12, rest) -> case BS.unpack rest of
    [major, minor] -> Just (GenTlsPremaster major minor)
    _ -> Nothing
  Just (13, rest) -> case BS.unpack rest of
    [ver, n] -> Just (GenWtlsPremaster ver (fromIntegral n))
    _ -> Nothing
  Just (14, rest) -> case BS.unpack rest of
    [hi, lo] -> Just (GenPbkd2 (fromIntegral hi * 256 + fromIntegral lo))
    _ -> Nothing
  Just (16, rest) -> case BS.unpack rest of
    [n] -> Just (GenPbe (fromIntegral n))
    _ -> Nothing
  Just (15, curve)
    | not (BS.null curve) -> Just (GenMontgomeryKeypair curve)
    | otherwise -> Nothing
  _ -> Nothing

-- | Frame authenticated-wrap parameters: @ivLen:u32be iv aad@.
encodeWrapParams :: ByteString -> ByteString -> ByteString
encodeWrapParams iv aad =
  let n = BS.length iv
  in BS.pack
    [ fromIntegral (n `div` 16777216 `mod` 256)
    , fromIntegral (n `div` 65536 `mod` 256)
    , fromIntegral (n `div` 256 `mod` 256)
    , fromIntegral (n `mod` 256)
    ] <> iv <> aad

-- | Parse framed authenticated-wrap parameters. A short prefix or
-- an overrun length fails.
decodeWrapParams :: ByteString -> Maybe (ByteString, ByteString)
decodeWrapParams bs
  | BS.length bs < 4 = Nothing
  | otherwise =
      let (bLen, rest) = BS.splitAt 4 bs
          n = fromInteger (foldBE bLen)
      in if BS.length rest < n
        then Nothing
        else Just (BS.splitAt n rest)

-- | Frame a keygen answer: @privLen:u32be priv pub?@. A single key
-- carries no public half; a pair always carries both.
encodeKeyPair :: ByteString -> Maybe ByteString -> ByteString
encodeKeyPair priv mPub =
  let n = BS.length priv
  in BS.pack
    [ fromIntegral (n `div` 16777216 `mod` 256)
    , fromIntegral (n `div` 65536 `mod` 256)
    , fromIntegral (n `div` 256 `mod` 256)
    , fromIntegral (n `mod` 256)
    ] <> priv <> maybe BS.empty id mPub

-- | Parse a framed keygen answer. A short length prefix, a length
-- overrun, or a length that lies all fail.
decodeKeyPair :: ByteString -> Maybe (ByteString, Maybe ByteString)
decodeKeyPair bs
  | BS.length bs < 4 = Nothing
  | otherwise =
      let (bLen, rest) = BS.splitAt 4 bs
          n = fromInteger (foldBE bLen)
      in if BS.length rest < n
        then Nothing
        else let (priv, pub) = BS.splitAt n rest
             in Just (priv, if BS.null pub then Nothing else Just pub)

-- Integer framing lives in Haskoki.Bytes (u16be/u32be/u64be/foldBE).

-- | Pad one wrap payload with PKCS#7. This mirrors
-- 'Haskoki.Operation.Cipher.pkcs7Pad' exactly (duplicated because
-- that module plans cipher slots while this one must stay importable
-- from the init policy without a cycle); 'KeyManagementSpec'
-- cross-checks both on every sample.
padPkcs7 :: Int -> ByteString -> Maybe ByteString
padPkcs7 block bs
  | block < 1 || block > 255 = Nothing
  | otherwise = Just (bs <> BS.replicate n (fromIntegral n))
  where
    n = block - (BS.length bs `mod` block)

-- | Strip PKCS#7 padding, checking the framing strictly. Mirrors
-- 'Haskoki.Operation.Cipher.pkcs7Unpad' exactly (see 'padPkcs7').
unpadPkcs7 :: Int -> ByteString -> Maybe ByteString
unpadPkcs7 block bs = do
  guard (block >= 1 && block <= 255)
  let len = BS.length bs
  guard (len > 0 && len `mod` block == 0)
  let padByte = BS.index bs (len - 1)
      n = fromIntegral padByte
  guard (n >= 1 && n <= min block len)
  let (plain, pad) = BS.splitAt (len - n) bs
  guard (BS.all (== padByte) pad)
  pure plain
