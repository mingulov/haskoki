{- | Minimal DER codec for key assembly and keygen stamping.

'planCreateObject' stores asymmetric keys the same way key generation
does: @AttrValue@ carries PKCS#8 (private) or SubjectPublicKeyInfo
(public) DER, while the PKCS#11 components stay stored verbatim for
reads. The writers assemble that DER purely from components — the
only runtime input the backend needs beyond the components is the
curve OID, resolved by 'curveOidOfParams'. The readers run the
other way at keygen finish time: the backend returns DER halves,
and 'finishWork' stamps the components back onto the new objects
so reads serve them without a decode-on-read path.

Scope is deliberately narrow: RSA PKCS#1/SPKI/PKCS#8 and SEC1 EC
keys on the 22 covered curves ('curveTable'). Anything else refuses
at the call site ('CKR_CURVE_NOT_SUPPORTED' for foreign curves,
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
  , curveTable
  , integerToBE
  , RsaCrt (..)
  , parseRsaPrivate
  , parseRsaPublic
  , spkiPoint
  , derOctet
  ) where

import Data.Bits (shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (find)
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

-- ---------------------------------------------------------------------------
-- Algorithm OIDs (DER-encoded, tag included)
-- ---------------------------------------------------------------------------

oidRsaEncryption :: ByteString
oidRsaEncryption = BS.pack
  [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

oidEcPublicKey :: ByteString
oidEcPublicKey = BS.pack [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]

-- ---------------------------------------------------------------------------
-- Curves
-- ---------------------------------------------------------------------------

-- | The covered curve table: engine name, DER OID (tag included),
-- coordinate width in bytes. The single source of truth both
-- lookups below derive from (pinned against the oracle's OID table
-- by KeyImportSpec, and against the FFI wire mapping).
--
-- Coverage is deliberately maximal: every curve the oracle collects
-- legs for, including the groups below that production deployments
-- should treat with suspicion. Sub-224-bit curves offer below
-- 112-bit security and binary curves are legacy-only; both ride
-- here exactly so the oracle's wycheproof legs execute instead of
-- skipping, never as a recommendation to deploy them.
curveTable :: [(ByteString, ByteString, Int)]
curveTable =
  -- NIST prime curves (the original set).
  [ ("P-256", BS.pack [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], 32)
  , ("P-384", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22], 48)
  , ("P-521", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23], 66)
  -- SEC prime curves at 224 bits and above.
  , ("secp224r1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21], 28)
  , ("secp224k1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x20], 28)
  , ("secp256k1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A], 32)
  -- Weak sub-224-bit curves: maximal-coverage rows only (see above).
  , ("secp192r1", BS.pack [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01], 24)
  , ("secp192k1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1F], 24)
  , ("secp160r1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x08], 20)
  , ("secp160r2", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1E], 20)
  , ("secp160k1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x09], 20)
  -- Brainpool prime curves (RFC 5639; the P224r1 tail byte is 0x05 —
  -- 0x0C would be the twisted variant, which is NOT covered).
  , ("brainpoolP224r1", BS.pack [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05], 28)
  , ("brainpoolP256r1", BS.pack [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07], 32)
  , ("brainpoolP320r1", BS.pack [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09], 40)
  , ("brainpoolP384r1", BS.pack [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B], 48)
  , ("brainpoolP512r1", BS.pack [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D], 64)
  -- Binary curves: maximal-coverage rows only (see above).
  , ("sect283k1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x10], 36)
  , ("sect283r1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x11], 36)
  , ("sect409k1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x24], 52)
  , ("sect409r1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x25], 52)
  , ("sect571k1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x26], 72)
  , ("sect571r1", BS.pack [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x27], 72)
  ]

-- | Resolve engine curve names (@"P-256"@, …) or raw DER OIDs to the
-- DER OID. Anything else is unsupported ('Nothing'). The OID table
-- must agree with 'ecParamsToWire' (pinned by KeyImportSpec).
curveOidOfParams :: ByteString -> Maybe ByteString
curveOidOfParams bs = case find hit curveTable of
  Just (_, oid, _) -> Just oid
  Nothing -> Nothing
  where
    hit (name, oid, _) = bs == name || bs == oid

-- | Coordinate length in bytes for a DER curve OID.
curveCoordLen :: ByteString -> Maybe Int
curveCoordLen oid = case find hit curveTable of
  Just (_, _, w) -> Just w
  Nothing -> Nothing
  where
    hit (_, o, _) = oid == o

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

-- ---------------------------------------------------------------------------
-- Parsing (total; 'Nothing' on any malformation)
-- ---------------------------------------------------------------------------

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

-- | RSA CRT components in 'rsaPrivateDer' order.
data RsaCrt = RsaCrt
  { crtN :: !ByteString
  , crtE :: !ByteString
  , crtD :: !ByteString
  , crtP :: !ByteString
  , crtQ :: !ByteString
  , crtDp :: !ByteString
  , crtDq :: !ByteString
  , crtQinv :: !ByteString
  } deriving (Eq, Show)

-- | Parse PKCS#8 RSA private DER into CRT components: outer SEQ of
-- [version, algId, OCTET STRING], inner RSAPrivateKey SEQ of
-- [version, n, e, d, p, q, dp, dq, qinv]. Versions and the
-- algorithm identifier are shape-checked, not value-checked.
parseRsaPrivate :: ByteString -> Maybe RsaCrt
parseRsaPrivate der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [_, _, privOct] -> do
      pkcs1 <- whole 0x04 privOct
      inner <- whole 0x30 pkcs1
      parts <- seqTop inner
      case parts of
        [_v, n, e, d, p, q, dp, dq, qi] -> RsaCrt
          <$> derInt n <*> derInt e <*> derInt d <*> derInt p
          <*> derInt q <*> derInt dp <*> derInt dq <*> derInt qi
        _ -> Nothing
    _ -> Nothing

-- | The RSA modulus and public exponent from an RSA SPKI:
-- outer SEQ of [algId, BIT STRING]; the bit string (past its
-- zero unused-bits octet) is a PKCS#1 RSAPublicKey, a SEQ of
-- exactly two INTEGERs. 'Nothing' on any framing or tag
-- mismatch.
parseRsaPublic :: ByteString -> Maybe (ByteString, ByteString)
parseRsaPublic der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [_, bits] -> do
      content <- whole 0x03 bits
      case BS.uncons content of
        Just (0, pkcs1der) -> do
          inner <- whole 0x30 pkcs1der
          parts <- seqTop inner
          case parts of
            [n, e] -> (,) <$> derInt n <*> derInt e
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | The raw X9.62 point from an EC SPKI: outer SEQ of [algId, BIT
-- STRING]; the bit string's leading unused-bits octet must be 0.
spkiPoint :: ByteString -> Maybe ByteString
spkiPoint der = do
  outer <- whole 0x30 der
  parts <- seqTop outer
  case parts of
    [_, bits] -> do
      content <- whole 0x03 bits
      case BS.uncons content of
        Just (0, point) -> Just point
        _ -> Nothing
    _ -> Nothing
