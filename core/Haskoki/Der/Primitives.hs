{- | Haskoki.Der.Primitives: DER tag-length-value readers and writers, algorithm OIDs.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Der.Primitives
  ( integerToBE
  , derOctet
  , derLen
  , tagged
  , derSeq
  , derSmallInt
  , derInteger
  , derNull
  , derBitString
  , oidRsaEncryption
  , oidEcPublicKey
  , oidDsa
  , oidDhKeyAgreement
  , oidDhPublicNumber
  , tlv
  , seqTop
  , derInt
  , whole
  ) where


import Data.Bits (shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)
-- DER primitives

-- | DER length octets (short form below 128, long form above).
-- Total over non-negative inputs; lengths here always come from
-- 'BS.length'.
derLen :: Int -> ByteString
derLen n
  | n < 128 = BS.singleton (fromIntegral n)
  | otherwise =
      let bytes = bigEndian n
      in BS.pack (fromIntegral (0x80 + length bytes) : bytes)
  where
    bigEndian :: Int -> [Word8]
    bigEndian x
      | x < 256 = [fromIntegral x]
      | otherwise = bigEndian (x `shiftR` 8) ++ [fromIntegral (x .&. 0xFF)]

tagged :: Word8 -> ByteString -> ByteString
tagged t body = BS.singleton t <> derLen (BS.length body) <> body

-- | Minimal big-endian encoding of a non-negative integer (at
-- least one octet; no leading zero). Shared by the backends for
-- exponent framing.
integerToBE :: Integer -> ByteString
integerToBE n
  | n <= 0 = BS.singleton 0
  | otherwise = BS.pack (go n [])
  where
    go 0 acc = acc
    go x acc = go (x `div` 256) (fromIntegral (x `mod` 256) : acc)

derSeq :: [ByteString] -> ByteString
derSeq parts = tagged 0x30 (mconcat parts)

-- | DER INTEGER for the small version numbers used below (0, 1).
derSmallInt :: Word8 -> ByteString
derSmallInt n = tagged 0x02 (BS.singleton n)

-- | DER INTEGER from unsigned big-endian bytes (minimal: leading
-- zeroes stripped, zero-length encodes 0, high bit padded).
derInteger :: ByteString -> ByteString
derInteger bs =
  let stripped = BS.dropWhile (== 0) bs
      body = case BS.uncons stripped of
        Nothing -> BS.singleton 0
        Just (h, _)
          | h >= 0x80 -> BS.cons 0 stripped
          | otherwise -> stripped
  in tagged 0x02 body

derOctet :: ByteString -> ByteString
derOctet = tagged 0x04

derNull :: ByteString
derNull = BS.pack [0x05, 0x00]

derBitString :: ByteString -> ByteString
derBitString body = tagged 0x03 (BS.cons 0 body)

-- Algorithm OIDs (DER-encoded, tag included)

oidRsaEncryption :: ByteString
oidRsaEncryption = BS.pack
  [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

oidEcPublicKey :: ByteString
oidEcPublicKey = BS.pack [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]

-- | DER OID 1.2.840.10040.4.1 (dsaEncryption).
oidDsa :: ByteString
oidDsa = BS.pack [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01]

-- | DER OID 1.2.840.113549.1.3.1 (dhKeyAgreement, PKCS#3 keys —
-- what OpenSSL emits for PKCS#3-param keygen).
oidDhKeyAgreement :: ByteString
oidDhKeyAgreement = BS.pack
  [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x03, 0x01]

-- | DER OID 1.2.840.10046.2.1 (dhpublicnumber, X9.42 keys).
oidDhPublicNumber :: ByteString
oidDhPublicNumber = BS.pack
  [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01]

-- Parsing (total; 'Nothing' on any malformation)

-- | One TLV element: tag, content, remainder. Lengths accept short
-- form and long form up to two octets (16 MiB ceiling, far above
-- any key DER here).
tlv :: ByteString -> Maybe (Word8, ByteString, ByteString)
tlv bs = do
  (t, rest) <- BS.uncons bs
  (n, body) <- splitLen rest
  guardLen n body
  pure (t, BS.take n body, BS.drop n body)
  where
    splitLen s = case BS.uncons s of
      Just (h, rest)
        | h < 0x80 -> Just (fromIntegral h, rest)
        | h == 0x81 -> case BS.uncons rest of
            Just (b, r) -> Just (fromIntegral b, r)
            Nothing -> Nothing
        | h == 0x82 -> case BS.unpack (BS.take 2 rest) of
            [b1, b2] -> Just (fromIntegral b1 * 256 + fromIntegral b2,
              BS.drop 2 rest)
            _ -> Nothing
        | otherwise -> Nothing
      Nothing -> Nothing
    guardLen n body
      | BS.length body >= n = Just ()
      | otherwise = Nothing

-- | The top-level elements of a SEQUENCE body, in order, WITH
-- their tags (re-encoded, so callers re-enter per element).
seqTop :: ByteString -> Maybe [ByteString]
seqTop body = go body []
  where
    go rest acc
      | BS.null rest = Just (reverse acc)
      | otherwise = case tlv rest of
          Just (t, content, rest') -> go rest' (tagged t content : acc)
          Nothing -> Nothing

-- | INTEGER content as minimal unsigned bytes (inverse of
-- 'derInteger' over well-formed input).
derInt :: ByteString -> Maybe ByteString
derInt el = do
  (t, content, rest) <- tlv el
  case (t, BS.null rest) of
    (0x02, True) -> Just (minimal content)
    _ -> Nothing
  where
    minimal bs = case BS.dropWhile (== 0) bs of
      stripped | BS.null stripped -> BS.singleton 0
               | otherwise -> stripped

-- | Expect a full TLV element of the given tag covering the whole
-- input; return its content.
whole :: Word8 -> ByteString -> Maybe ByteString
whole tag el = do
  (t, content, rest) <- tlv el
  case (t, BS.null rest) of
    (tag', True) | tag' == tag -> Just content
    _ -> Nothing
