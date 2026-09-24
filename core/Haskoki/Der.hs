{- | Minimal DER writer for key-import assembly.

'planCreateObject' stores asymmetric keys the same way key generation
does: @AttrValue@ carries PKCS#8 (private) or SubjectPublicKeyInfo
(public) DER, while the PKCS#11 components stay stored verbatim for
reads. This module assembles that DER purely from components — the
only runtime input the backend needs beyond the components is the
curve OID, resolved by 'curveOidOfParams'.

Scope is deliberately narrow: RSA PKCS#1/SPKI/PKCS#8 and SEC1 EC
keys on the three SEC2 prime curves. Anything else refuses at the
call site ('CKR_CURVE_NOT_SUPPORTED' for foreign curves,
'CKR_TEMPLATE_INCONSISTENT' for malformed parts) instead of
encoding half-understood structures.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Der
  ( rsaPrivateDer
  , rsaPublicDer
  , ecPrivateDer
  , ecPublicDer
  , unwrapEcPoint
  , curveOidOfParams
  , curveCoordLen
  ) where

import Data.Bits (shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

-- ---------------------------------------------------------------------------
-- DER primitives
-- ---------------------------------------------------------------------------

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

-- ---------------------------------------------------------------------------
-- Algorithm OIDs (DER-encoded, tag included)
-- ---------------------------------------------------------------------------

oidRsaEncryption :: ByteString
oidRsaEncryption = BS.pack
  [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

oidEcPublicKey :: ByteString
oidEcPublicKey = BS.pack [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]

oidP256 :: ByteString
oidP256 = BS.pack
  [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]

oidP384 :: ByteString
oidP384 = BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]

oidP521 :: ByteString
oidP521 = BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23]

-- ---------------------------------------------------------------------------
-- Curves
-- ---------------------------------------------------------------------------

-- | Resolve engine curve names (@"P-256"@, …) or raw DER OIDs to the
-- DER OID. Anything else is unsupported ('Nothing'). The OID table
-- must agree with 'ecParamsToWire' (pinned by KeyImportSpec).
curveOidOfParams :: ByteString -> Maybe ByteString
curveOidOfParams bs
  | bs == "P-256" || bs == oidP256 = Just oidP256
  | bs == "P-384" || bs == oidP384 = Just oidP384
  | bs == "P-521" || bs == oidP521 = Just oidP521
  | otherwise = Nothing

-- | Coordinate length in bytes for a DER curve OID.
curveCoordLen :: ByteString -> Maybe Int
curveCoordLen oid
  | oid == oidP256 = Just 32
  | oid == oidP384 = Just 48
  | oid == oidP521 = Just 66
  | otherwise = Nothing

-- | Unwrap a @CKA_EC_POINT@ value (DER OCTET STRING around the X9.62
-- point) against the expected coordinate length. Only uncompressed
-- points (@0x04 \|\| X \|\| Y@) are accepted.
unwrapEcPoint :: Int -> ByteString -> Maybe ByteString
unwrapEcPoint coordLen bs = case BS.uncons bs of
  Just (0x04, rest) -> do
    (n, body) <- splitLen rest
    point <- pure (BS.take n body)
    if BS.length body == n
       && BS.length point == 2 * coordLen + 1
       && BS.index point 0 == 0x04
      then Just point
      else Nothing
  _ -> Nothing
  where
    splitLen :: ByteString -> Maybe (Int, ByteString)
    splitLen s = case BS.uncons s of
      Just (h, rest)
        | h < 0x80 -> Just (fromIntegral h, rest)
        | h == 0x81 -> case BS.uncons rest of
            Just (b, r) -> Just (fromIntegral b, r)
            Nothing -> Nothing
        | h == 0x82 -> case BS.unpack (BS.take 2 rest) of
            [b1, b2] -> Just (fromIntegral b1 * 256 + fromIntegral b2, BS.drop 2 rest)
            _ -> Nothing
        | otherwise -> Nothing
      Nothing -> Nothing

-- ---------------------------------------------------------------------------
-- Assembly (total over any input bytes; validation is the caller's)
-- ---------------------------------------------------------------------------

-- | PKCS#8 for an RSA private key from CRT components
-- (n, e, d, p, q, dp, dq, qinv).
rsaPrivateDer :: ByteString -> ByteString -> ByteString -> ByteString
  -> ByteString -> ByteString -> ByteString -> ByteString -> ByteString
rsaPrivateDer n e d p q dp dq qinv =
  let pkcs1 = derSeq
        [ derSmallInt 0
        , derInteger n
        , derInteger e
        , derInteger d
        , derInteger p
        , derInteger q
        , derInteger dp
        , derInteger dq
        , derInteger qinv
        ]
  in derSeq [derSmallInt 0, derSeq [oidRsaEncryption, derNull], derOctet pkcs1]

-- | SPKI for an RSA public key from (n, e).
rsaPublicDer :: ByteString -> ByteString -> ByteString
rsaPublicDer n e =
  let pkcs1pub = derSeq [derInteger n, derInteger e]
  in derSeq [derSeq [oidRsaEncryption, derNull], derBitString pkcs1pub]

-- | PKCS#8 for an EC private key from the DER curve OID and the
-- scalar. The SEC1 carries version + scalar only (no public point:
-- scalar-only input cannot produce one; the curve rides the outer
-- algorithm identifier, matching OpenSSL's own SEC1 shape minus the
-- public half). OpenSSL-backed sign/derive paths consume this
-- shape (pinned by CLI interop: @pkeyutl -sign@ accepts it).
ecPrivateDer :: ByteString -> ByteString -> ByteString
ecPrivateDer curveOid scalar =
  let sec1 = derSeq [derSmallInt 1, derOctet scalar]
  in derSeq [derSmallInt 0, derSeq [oidEcPublicKey, curveOid], derOctet sec1]

-- | SPKI for an EC public key from the DER curve OID and the raw
-- (unwrapped) X9.62 point.
ecPublicDer :: ByteString -> ByteString -> ByteString
ecPublicDer curveOid point =
  derSeq [derSeq [oidEcPublicKey, curveOid], derBitString point]
