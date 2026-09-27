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

Scope is deliberately narrow: RSA PKCS#1/SPKI/PKCS#8, SEC1 EC
keys on the 22 covered curves ('curveTable'), DSA DSS-Parms /
SPKI / PKCS#8, Edwards SPKI / PKCS#8 on the 2 served curves
('edwardsTable'), Montgomery SPKI / PKCS#8 on the 2 served
curves ('montgomeryTable'), ML-DSA SPKI / flat-expanded PKCS#8
on the 3 served levels ('mldsaTable'), and ML-KEM SPKI /
provider-form PKCS#8 on the 3 served sets ('mlkemTable').
Anything else refuses at the call site
('CKR_CURVE_NOT_SUPPORTED' for foreign curves,
'CKR_TEMPLATE_INCONSISTENT' for malformed parts) instead of
encoding half-understood structures.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Der
  ( rsaPrivateDer
  , rsaPublicDer
  , rsaSpkiFields
  , ecPrivateDer
  , ecPublicDer
  , dsaParamsDer
  , dsaPrivateDer
  , dsaPublicDer
  , parseDsaParams
  , dsaSpkiFields
  , dsaPkcs8Fields
  , dhParamsDer
  , dhParamsDerQ
  , dhPrivateDer
  , dhPublicDer
  , dhPrivateDerQ
  , dhPublicDerQ
  , parseDhParams
  , dhSpkiFields
  , dhPkcs8Fields
  , eddsaPrivateDer
  , eddsaPublicDer
  , eddsaSpkiFields
  , eddsaPkcs8Fields
  , mldsaTable
  , mldsaPublicDer
  , mldsaPrivateDer
  , mldsaSpkiFields
  , mldsaPkcs8Fields
  , mldsaOidOfParams
  , mldsaNameOfOid
  , mldsaWidthsOfOid
  , mldsaCkpOfOid
  , mldsaOidOfCkp
  , mlkemTable
  , mlkemPublicDer
  , mlkemPrivateDer
  , mlkemSpkiFields
  , mlkemPkcs8Fields
  , mlkemOidOfParams
  , mlkemNameOfOid
  , mlkemWidthsOfOid
  , mlkemCkpOfOid
  , mlkemOidOfCkp
  , mlkemEkWellFormed
  , slhdsaTable
  , slhdsaPublicDer
  , slhdsaPrivateDer
  , slhdsaSpkiFields
  , slhdsaPkcs8Fields
  , slhdsaOidOfParams
  , slhdsaNameOfOid
  , slhdsaWidthsOfOid
  , slhdsaCkpOfOid
  , slhdsaOidOfCkp
  , unwrapEcPoint
  , unwrapEdwardsPoint
  , unwrapMontgomeryPoint
  , curveOidOfParams
  , curveCoordLen
  , curveTable
  , edwardsTable
  , edwardsOidOfParams
  , edwardsNameOfOid
  , edwardsWidthsOfParams
  , montgomeryTable
  , montgomeryOidOfParams
  , montgomeryNameOfOid
  , montgomeryWidthOfParams
  , montgomeryPrivateDer
  , montgomeryPublicDer
  , montgomerySpkiFields
  , montgomeryPkcs8Fields
  , coveredCurveNames
  , edwardsCurveNames
  , montgomeryCurveNames
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
import qualified Data.ByteString.Char8 as BC8
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

-- | Edwards curves served by the EdDSA recipe: (name, DER OID,
-- seed width, signature width). Kept separate from 'curveTable'
-- (Weierstrass ECDSA/ECDH must never resolve an Edwards OID).
edwardsTable :: [(ByteString, ByteString, Int, Int)]
edwardsTable =
  [ ("Ed25519", BS.pack [0x06, 0x03, 0x2B, 0x65, 0x70], 32, 64)
  , ("Ed448", BS.pack [0x06, 0x03, 0x2B, 0x65, 0x71], 57, 114)
  ]

-- | ML-DSA parameter sets: engine name, DER algorithm OID
-- (2.16.840.1.101.3.4.3.17/18/19), public-key width, private
-- (expanded) width, signature width, and the 'CKP_ML_DSA_*' id
-- carried by @CKA_PARAMETER_SET@. Widths are FIPS 204 (sig
-- 2420 and the flat private import additionally
-- provider-witnessed).
mldsaTable :: [(ByteString, ByteString, Int, Int, Int, Int)]
mldsaTable =
  [ ("ML-DSA-44", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11], 1312, 2560, 2420, 1)
  , ("ML-DSA-65", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12], 1952, 4032, 3309, 2)
  , ("ML-DSA-87", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13], 2592, 4896, 4627, 3)
  ]

-- | Covered engine curve names (the 'curveTable' name column).
coveredCurveNames :: [String]
coveredCurveNames = [BC8.unpack n | (n, _, _) <- curveTable]

-- | Served Edwards engine names (the 'edwardsTable' name column).
edwardsCurveNames :: [String]
edwardsCurveNames = [BC8.unpack n | (n, _, _, _) <- edwardsTable]

-- | Montgomery curves served by the ECDH recipe: (name, DER OID,
-- coordinate width). Kept separate from 'curveTable' and
-- 'edwardsTable' (Weierstrass ECDSA/ECDH and EdDSA must never
-- resolve a Montgomery OID). OIDs are RFC 8410 1.3.101.110/111.
montgomeryTable :: [(ByteString, ByteString, Int)]
montgomeryTable =
  [ ("X25519", BS.pack [0x06, 0x03, 0x2B, 0x65, 0x6E], 32)
  , ("X448", BS.pack [0x06, 0x03, 0x2B, 0x65, 0x6F], 56)
  ]

-- | Served Montgomery engine names (the 'montgomeryTable' name column).
montgomeryCurveNames :: [String]
montgomeryCurveNames = [BC8.unpack n | (n, _, _) <- montgomeryTable]

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

-- | Resolve engine Edwards names (@"Ed25519"@, …) or raw DER
-- OIDs to the DER OID (the 'curveOidOfParams' precedent).
edwardsOidOfParams :: ByteString -> Maybe ByteString
edwardsOidOfParams bs = case find hit edwardsTable of
  Just (_, oid, _, _) -> Just oid
  Nothing -> Nothing
  where
    hit (name, oid, _, _) = bs == name || bs == oid

-- | The engine Edwards name for a DER OID ('Nothing' for
-- foreign OIDs).
edwardsNameOfOid :: ByteString -> Maybe ByteString
edwardsNameOfOid oid = case find hit edwardsTable of
  Just (name, _, _, _) -> Just name
  Nothing -> Nothing
  where
    hit (_, o, _, _) = oid == o

-- | Seed and signature widths in bytes for a DER Edwards OID.
edwardsWidthsOfParams :: ByteString -> Maybe (Int, Int)
edwardsWidthsOfParams oid = case find hit edwardsTable of
  Just (_, _, seedW, sigW) -> Just (seedW, sigW)
  Nothing -> Nothing
  where
    hit (_, o, _, _) = oid == o

-- | Resolve engine Montgomery names (@"X25519"@, …) or raw DER
-- OIDs to the DER OID (the 'curveOidOfParams' precedent).
montgomeryOidOfParams :: ByteString -> Maybe ByteString
montgomeryOidOfParams bs = case find hit montgomeryTable of
  Just (_, oid, _) -> Just oid
  Nothing -> Nothing
  where
    hit (name, oid, _) = bs == name || bs == oid

-- | The engine Montgomery name for a DER OID ('Nothing' for
-- foreign OIDs).
montgomeryNameOfOid :: ByteString -> Maybe ByteString
montgomeryNameOfOid oid = case find hit montgomeryTable of
  Just (name, _, _) -> Just name
  Nothing -> Nothing
  where
    hit (_, o, _) = oid == o

-- | Coordinate width in bytes for a DER Montgomery OID.
montgomeryWidthOfParams :: ByteString -> Maybe Int
montgomeryWidthOfParams oid = case find hit montgomeryTable of
  Just (_, _, w) -> Just w
  Nothing -> Nothing
  where
    hit (_, o, _) = oid == o

-- | Resolve engine ML-DSA names (@"ML-DSA-44"@, …) or raw DER
-- OIDs to the DER OID (the 'edwardsOidOfParams' precedent).
mldsaOidOfParams :: ByteString -> Maybe ByteString
mldsaOidOfParams bs = case find hit mldsaTable of
  Just (_, oid, _, _, _, _) -> Just oid
  Nothing -> Nothing
  where
    hit (name, oid, _, _, _, _) = bs == name || bs == oid

-- | The engine ML-DSA name for a DER OID ('Nothing' for
-- foreign OIDs).
mldsaNameOfOid :: ByteString -> Maybe ByteString
mldsaNameOfOid oid = case find hit mldsaTable of
  Just (name, _, _, _, _, _) -> Just name
  Nothing -> Nothing
  where
    hit (_, o, _, _, _, _) = oid == o

-- | Public-key, private (expanded), and signature widths in
-- bytes for a DER ML-DSA OID.
mldsaWidthsOfOid :: ByteString -> Maybe (Int, Int, Int)
mldsaWidthsOfOid oid = case find hit mldsaTable of
  Just (_, _, pubW, privW, sigW, _) -> Just (pubW, privW, sigW)
  Nothing -> Nothing
  where
    hit (_, o, _, _, _, _) = oid == o

-- | The @CKP_ML_DSA_*@ id for a DER ML-DSA OID.
mldsaCkpOfOid :: ByteString -> Maybe Int
mldsaCkpOfOid oid = case find hit mldsaTable of
  Just (_, _, _, _, _, ckp) -> Just ckp
  Nothing -> Nothing
  where
    hit (_, o, _, _, _, _) = oid == o

-- | The DER ML-DSA OID for a @CKP_ML_DSA_*@ id.
mldsaOidOfCkp :: Int -> Maybe ByteString
mldsaOidOfCkp ckp = case find hit mldsaTable of
  Just (_, oid, _, _, _, _) -> Just oid
  Nothing -> Nothing
  where
    hit (_, _, _, _, _, c) = ckp == c

-- | SLH-DSA parameter sets: engine name, DER algorithm OID
-- (2.16.840.1.101.3.4.3.20-31), public-key width (2n),
-- private-key width (4n, the full FIPS 205 secret), signature
-- width, and the 'CKP_SLH_DSA_*' id carried by
-- @CKA_PARAMETER_SET@. Widths are FIPS 205 (sig widths and
-- the flat private shape additionally provider-witnessed).
slhdsaTable :: [(ByteString, ByteString, Int, Int, Int, Int)]
slhdsaTable =
  [ ("SLH-DSA-SHA2-128s", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14], 32, 64, 7856, 1)
  , ("SLH-DSA-SHA2-128f", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x15], 32, 64, 17088, 3)
  , ("SLH-DSA-SHA2-192s", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x16], 48, 96, 16224, 5)
  , ("SLH-DSA-SHA2-192f", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x17], 48, 96, 35664, 7)
  , ("SLH-DSA-SHA2-256s", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x18], 64, 128, 29792, 9)
  , ("SLH-DSA-SHA2-256f", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x19], 64, 128, 49856, 11)
  , ("SLH-DSA-SHAKE-128s", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1a], 32, 64, 7856, 2)
  , ("SLH-DSA-SHAKE-128f", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1b], 32, 64, 17088, 4)
  , ("SLH-DSA-SHAKE-192s", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1c], 48, 96, 16224, 6)
  , ("SLH-DSA-SHAKE-192f", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1d], 48, 96, 35664, 8)
  , ("SLH-DSA-SHAKE-256s", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1e], 64, 128, 29792, 10)
  , ("SLH-DSA-SHAKE-256f", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1f], 64, 128, 49856, 12)
  ]

-- | Resolve engine SLH-DSA names (@"SLH-DSA-SHA2-128s"@, …) or
-- raw DER OIDs to the DER OID (the 'mldsaOidOfParams'
-- precedent).
slhdsaOidOfParams :: ByteString -> Maybe ByteString
slhdsaOidOfParams bs = case find hit slhdsaTable of
  Just (_, oid, _, _, _, _) -> Just oid
  Nothing -> Nothing
  where
    hit (name, oid, _, _, _, _) = bs == name || bs == oid

-- | The engine SLH-DSA name for a DER OID ('Nothing' for
-- foreign OIDs).
slhdsaNameOfOid :: ByteString -> Maybe ByteString
slhdsaNameOfOid oid = case find hit slhdsaTable of
  Just (name, _, _, _, _, _) -> Just name
  Nothing -> Nothing
  where
    hit (_, o, _, _, _, _) = oid == o

-- | Public-key, private (4n secret), and signature widths in
-- bytes for a DER SLH-DSA OID.
slhdsaWidthsOfOid :: ByteString -> Maybe (Int, Int, Int)
slhdsaWidthsOfOid oid = case find hit slhdsaTable of
  Just (_, _, pubW, privW, sigW, _) -> Just (pubW, privW, sigW)
  Nothing -> Nothing
  where
    hit (_, o, _, _, _, _) = oid == o

-- | The @CKP_SLH_DSA_*@ id for a DER SLH-DSA OID.
slhdsaCkpOfOid :: ByteString -> Maybe Int
slhdsaCkpOfOid oid = case find hit slhdsaTable of
  Just (_, _, _, _, _, ckp) -> Just ckp
  Nothing -> Nothing
  where
    hit (_, o, _, _, _, _) = oid == o

-- | The DER SLH-DSA OID for a @CKP_SLH_DSA_*@ id.
slhdsaOidOfCkp :: Int -> Maybe ByteString
slhdsaOidOfCkp ckp = case find hit slhdsaTable of
  Just (_, oid, _, _, _, _) -> Just oid
  Nothing -> Nothing
  where
    hit (_, _, _, _, _, c) = ckp == c

-- | ML-KEM parameter sets: engine name, DER algorithm OID
-- (2.16.840.1.101.3.4.4.1\/2\/3), encapsulation-key width,
-- decapsulation-key width, ciphertext width, and the
-- 'CKP_ML_KEM_*' id carried by @CKA_PARAMETER_SET@. Widths
-- are FIPS 203 Table 2 (every shared secret is 32 bytes, so
-- no column is needed).
mlkemTable :: [(ByteString, ByteString, Int, Int, Int, Int)]
mlkemTable =
  [ ("ML-KEM-512", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01], 800, 1632, 768, 1)
  , ("ML-KEM-768", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02], 1184, 2400, 1088, 2)
  , ("ML-KEM-1024", BS.pack [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03], 1568, 3168, 1568, 3)
  ]

-- | Resolve engine ML-KEM names (@"ML-KEM-512"@, …) or raw DER
-- OIDs to the DER OID (the 'mldsaOidOfParams' precedent).
mlkemOidOfParams :: ByteString -> Maybe ByteString
mlkemOidOfParams bs = case find hit mlkemTable of
  Just (_, oid, _, _, _, _) -> Just oid
  Nothing -> Nothing
  where
    hit (name, oid, _, _, _, _) = bs == name || bs == oid

-- | The engine ML-KEM name for a DER OID ('Nothing' for
-- foreign OIDs).
mlkemNameOfOid :: ByteString -> Maybe ByteString
mlkemNameOfOid oid = case find hit mlkemTable of
  Just (name, _, _, _, _, _) -> Just name
  Nothing -> Nothing
  where
    hit (_, o, _, _, _, _) = oid == o

-- | Encapsulation-key, decapsulation-key, and ciphertext
-- widths in bytes for a DER ML-KEM OID.
mlkemWidthsOfOid :: ByteString -> Maybe (Int, Int, Int)
mlkemWidthsOfOid oid = case find hit mlkemTable of
  Just (_, _, ekW, dkW, ctW, _) -> Just (ekW, dkW, ctW)
  Nothing -> Nothing
  where
    hit (_, o, _, _, _, _) = oid == o

-- | The @CKP_ML_KEM_*@ id for a DER ML-KEM OID.
mlkemCkpOfOid :: ByteString -> Maybe Int
mlkemCkpOfOid oid = case find hit mlkemTable of
  Just (_, _, _, _, _, ckp) -> Just ckp
  Nothing -> Nothing
  where
    hit (_, o, _, _, _, _) = oid == o

-- | The DER ML-KEM OID for a @CKP_ML_KEM_*@ id.
mlkemOidOfCkp :: Int -> Maybe ByteString
mlkemOidOfCkp ckp = case find hit mlkemTable of
  Just (_, oid, _, _, _, _) -> Just oid
  Nothing -> Nothing
  where
    hit (_, _, _, _, _, c) = ckp == c

-- | An encapsulation key is well-formed when its set OID is
-- served, its width is exact, and every 12-bit-packed
-- coefficient of the @t@ vector is reduced modulo @q = 3329@
-- (FIPS 203 §7.2 modulus check; the trailing 32-byte @rho@
-- seed is unchecked). Non-canonical keys MUST be rejected
-- (the oracle's encaps-modulus legs), and the provider
-- refuses them at fromdata — this pure check moves the
-- refusal to import time with the spec-correct code.
mlkemEkWellFormed :: ByteString -> ByteString -> Bool
mlkemEkWellFormed oid ek = case mlkemWidthsOfOid oid of
  Just (ekW, _, _)
    | BS.length ek == ekW -> coeffsOk (BS.take (ekW - 32) ek)
  _ -> False
  where
    coeffsOk bs
      | BS.null bs = True
      | BS.length bs < 3 = False
      | otherwise =
          let b0 = fromIntegral (BS.index bs 0) :: Int
              b1 = fromIntegral (BS.index bs 1) :: Int
              b2 = fromIntegral (BS.index bs 2) :: Int
              d0 = b0 + 256 * (b1 `mod` 16)
              d1 = (b1 `div` 16) + 16 * b2
          in d0 < 3329 && d1 < 3329 && coeffsOk (BS.drop 3 bs)

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

-- | Unwrap a @CKA_EC_POINT@ value for a @CKK_EC_EDWARDS@ key
-- against the expected seed width. Raw RFC 8032 bytes
-- (width-exact) pass through; a DER OCTET STRING wrapper
-- unwraps (some providers emit it). The length decides —
-- unambiguous, since a wrapped point is always longer than the
-- seed width.
unwrapEdwardsPoint :: Int -> ByteString -> Maybe ByteString
unwrapEdwardsPoint seedW bs
  | BS.length bs == seedW = Just bs
  | otherwise = do
      body <- whole 0x04 bs
      if BS.length body == seedW then Just body else Nothing

-- | Unwrap a @CKA_EC_POINT@ value for a @CKK_EC_MONTGOMERY@ key
-- against the expected coordinate width. Raw RFC 7748 bytes
-- (width-exact) pass through; a DER OCTET STRING wrapper
-- unwraps (the Edwards precedent). The length decides —
-- unambiguous, since a wrapped point is always longer than the
-- coordinate width.
unwrapMontgomeryPoint :: Int -> ByteString -> Maybe ByteString
unwrapMontgomeryPoint w bs
  | BS.length bs == w = Just bs
  | otherwise = do
      body <- whole 0x04 bs
      if BS.length body == w then Just body else Nothing

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

-- | The modulus plus the public exponent from an RSA SPKI: outer
-- SEQ of [algId, BIT STRING] where the algorithm is
-- rsaEncryption with NULL parameters and the bit string (past
-- its zero unused-bits octet) is the PKCS#1 SEQ of
-- [INTEGER n, INTEGER e]. 'Nothing' on any framing, tag, or OID
-- mismatch.
rsaSpkiFields :: ByteString -> Maybe (ByteString, ByteString)
rsaSpkiFields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [algId, bits] -> do
      algParts <- whole 0x30 algId >>= seqTop
      case algParts of
        [oid, nullp] | oid == oidRsaEncryption && nullp == derNull -> do
          content <- whole 0x03 bits
          case BS.uncons content of
            Just (0, pkcs1) -> do
              body <- whole 0x30 pkcs1
              parts1 <- seqTop body
              case parts1 of
                [nder, eder] -> do
                  n <- derInt nder
                  e <- derInt eder
                  pure (n, e)
                _ -> Nothing
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

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

-- | DER DSS-Parms: the SEQUENCE of p, q, g INTEGERs (minimal
-- encoding, leading zeros stripped, sign pad when the top bit is
-- set). Shared by SPKI/PKCS#8 assembly, keypair-gen input
-- assembly, and paramgen-answer parsing.
dsaParamsDer :: ByteString -> ByteString -> ByteString -> ByteString
dsaParamsDer p q g = derSeq [derInteger p, derInteger q, derInteger g]

-- | PKCS#8 (version 0, dsaEncryption OID 1.2.840.10040.4.1) for a
-- DSA private key: parameters plus the OCTET-wrapped INTEGER x.
dsaPrivateDer :: ByteString -> ByteString -> ByteString -> ByteString -> ByteString
dsaPrivateDer p q g x =
  derSeq [derSmallInt 0, derSeq [oidDsa, dsaParamsDer p q g], derOctet (derInteger x)]

-- | SPKI for a DSA public key: parameters plus the BIT-wrapped
-- INTEGER y.
dsaPublicDer :: ByteString -> ByteString -> ByteString -> ByteString -> ByteString
dsaPublicDer p q g y =
  derSeq [derSeq [oidDsa, dsaParamsDer p q g], derBitString (derInteger y)]

-- | DER PKCS#3 DH parameters: the SEQUENCE of p, g INTEGERs
-- (minimal encoding). Shared by keypair-gen input assembly and
-- SPKI/PKCS#8 assembly.
dhParamsDer :: ByteString -> ByteString -> ByteString
dhParamsDer p g = derSeq [derInteger p, derInteger g]

-- | DER X9.42 DH domain parameters: the SEQUENCE of p, g, q
-- INTEGERs (no cofactor/validation fields — the pinned decoder
-- accepts the 3-field form, proven by probe).
dhParamsDerQ :: ByteString -> ByteString -> ByteString -> ByteString
dhParamsDerQ p g q = derSeq [derInteger p, derInteger g, derInteger q]

-- | PKCS#8 (version 0, dhKeyAgreement OID 1.2.840.113549.1.3.1)
-- for a PKCS#3 DH private key: parameters plus the OCTET-wrapped
-- INTEGER x.
dhPrivateDer :: ByteString -> ByteString -> ByteString -> ByteString
dhPrivateDer p g x =
  derSeq [derSmallInt 0, derSeq [oidDhKeyAgreement, dhParamsDer p g], derOctet (derInteger x)]

-- | SPKI for a PKCS#3 DH public key: parameters plus the
-- BIT-wrapped INTEGER y.
dhPublicDer :: ByteString -> ByteString -> ByteString -> ByteString
dhPublicDer p g y =
  derSeq [derSeq [oidDhKeyAgreement, dhParamsDer p g], derBitString (derInteger y)]

-- | PKCS#8 (version 0, dhpublicnumber OID 1.2.840.10046.2.1) for
-- an X9.42 DH private key: parameters plus the OCTET-wrapped
-- INTEGER x.
dhPrivateDerQ :: ByteString -> ByteString -> ByteString -> ByteString -> ByteString
dhPrivateDerQ p g q x =
  derSeq [derSmallInt 0, derSeq [oidDhPublicNumber, dhParamsDerQ p g q], derOctet (derInteger x)]

-- | SPKI for an X9.42 DH public key: parameters plus the
-- BIT-wrapped INTEGER y.
dhPublicDerQ :: ByteString -> ByteString -> ByteString -> ByteString -> ByteString
dhPublicDerQ p g q y =
  derSeq [derSeq [oidDhPublicNumber, dhParamsDerQ p g q], derBitString (derInteger y)]

-- | PKCS#8 for an Edwards private key from the DER curve OID and
-- the seed (RFC 8410 @OneAsymmetricKey@: the inner OCTET STRING
-- carries the seed directly).
eddsaPrivateDer :: ByteString -> ByteString -> ByteString
eddsaPrivateDer oid seed =
  derSeq [derSmallInt 0, derSeq [oid], derOctet (derOctet seed)]

-- | SPKI for an Edwards public key from the DER curve OID and the
-- raw point (the algorithm identifier is the bare OID — Edwards
-- SPKIs carry no parameters).
eddsaPublicDer :: ByteString -> ByteString -> ByteString
eddsaPublicDer oid point =
  derSeq [derSeq [oid], derBitString point]

-- | PKCS#8 for a Montgomery private key from the DER curve OID and
-- the scalar (RFC 8410 @OneAsymmetricKey@: the inner OCTET STRING
-- carries the scalar directly — the Edwards shape).
montgomeryPrivateDer :: ByteString -> ByteString -> ByteString
montgomeryPrivateDer oid scalar =
  derSeq [derSmallInt 0, derSeq [oid], derOctet (derOctet scalar)]

-- | SPKI for a Montgomery public key from the DER curve OID and
-- the raw u-coordinate (the algorithm identifier is the bare OID —
-- Montgomery SPKIs carry no parameters).
montgomeryPublicDer :: ByteString -> ByteString -> ByteString
montgomeryPublicDer oid point =
  derSeq [derSeq [oid], derBitString point]

-- | PKCS#8 for an ML-DSA private key from the DER algorithm OID
-- and the raw expanded key (NOT the Edwards nested-seed shape:
-- the pinned provider refuses seed-only PKCS#8 and has no
-- seed fromdata; it decodes the flat expanded key — proven by
-- probe against a wycheproof vector, sign+verify roundtrip).
mldsaPrivateDer :: ByteString -> ByteString -> ByteString
mldsaPrivateDer oid raw =
  derSeq [derSmallInt 0, derSeq [oid], derOctet raw]

-- | SPKI for an ML-DSA public key from the DER algorithm OID and
-- the raw public key (the algorithm identifier is the bare OID —
-- ML-DSA SPKIs carry no parameters).
mldsaPublicDer :: ByteString -> ByteString -> ByteString
mldsaPublicDer oid point =
  derSeq [derSeq [oid], derBitString point]

-- | PKCS#8 for an ML-KEM private key from the DER algorithm OID,
-- the 64-byte seed (@d || z@), and the raw decapsulation key:
-- the provider's own @SEQ { seed, dk }@ form, which the pinned
-- decoder accepts (a flat @OCTET(dk)@ is refused — proven by
-- probe — so dk-only import stores raw bytes instead and this
-- builder serves seed+dk templates only).
mlkemPrivateDer :: ByteString -> ByteString -> ByteString -> ByteString
mlkemPrivateDer oid seed dk =
  derSeq [derSmallInt 0, derSeq [oid], derOctet (derSeq [derOctet seed, derOctet dk])]

-- | SPKI for an ML-KEM public key from the DER algorithm OID and
-- the raw encapsulation key (the algorithm identifier is the
-- bare OID — ML-KEM SPKIs carry no parameters).
mlkemPublicDer :: ByteString -> ByteString -> ByteString
mlkemPublicDer oid ek =
  derSeq [derSeq [oid], derBitString ek]

-- | PKCS#8 for an SLH-DSA private key from the DER algorithm OID
-- and the raw 4n secret (the provider's own flat shape —
-- asn1parse-witnessed on pinned-CLI genpkey output — so
-- assembly and the keygen-stored form agree; no SEQ{seed,
-- expanded} dual shape like ML-DSA).
slhdsaPrivateDer :: ByteString -> ByteString -> ByteString
slhdsaPrivateDer oid raw =
  derSeq [derSmallInt 0, derSeq [oid], derOctet raw]

-- | SPKI for an SLH-DSA public key from the DER algorithm OID and
-- the raw public key (the algorithm identifier is the bare OID —
-- SLH-DSA SPKIs carry no parameters).
slhdsaPublicDer :: ByteString -> ByteString -> ByteString
slhdsaPublicDer oid point =
  derSeq [derSeq [oid], derBitString point]

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

-- | DSS-Parms from DER: a SEQUENCE of exactly three INTEGERs
-- (p, q, g), values unsigned-stripped. 'Nothing' on any framing
-- or tag mismatch.
parseDsaParams :: ByteString -> Maybe (ByteString, ByteString, ByteString)
parseDsaParams der = do
  body <- whole 0x30 der
  parts <- seqTop body
  case parts of
    [p, q, g] -> (,,) <$> derInt p <*> derInt q <*> derInt g
    _ -> Nothing

-- | DSA parameters plus the public value from an SPKI: outer SEQ
-- of [algId, BIT STRING] where the algorithm is dsaEncryption,
-- the parameters are DSS-Parms, and the bit string (past its zero
-- unused-bits octet) is the INTEGER y. 'Nothing' on any framing,
-- tag, or OID mismatch.
dsaSpkiFields :: ByteString -> Maybe (ByteString, ByteString, ByteString, ByteString)
dsaSpkiFields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [algId, bits] -> do
      algParts <- whole 0x30 algId >>= seqTop
      case algParts of
        [oid, params] | oid == oidDsa -> do
          (p, q, g) <- parseDsaParams params
          content <- whole 0x03 bits
          case BS.uncons content of
            Just (0, yder) -> do
              y <- derInt yder
              pure (p, q, g, y)
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | DSA parameters plus the private scalar from a PKCS#8: outer SEQ
-- of [version INTEGER 0, algId, OCTET STRING] where the algorithm
-- is dsaEncryption, the parameters are DSS-Parms, and the octet
-- string wraps the INTEGER x. 'Nothing' on any framing, tag,
-- version, or OID mismatch.
dsaPkcs8Fields :: ByteString -> Maybe (ByteString, ByteString, ByteString, ByteString)
dsaPkcs8Fields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [ver, algId, oct] -> do
      v <- derInt ver
      case BS.uncons v of
        Just (0, rest) | BS.null rest -> do
          algParts <- whole 0x30 algId >>= seqTop
          case algParts of
            [oid, params] | oid == oidDsa -> do
              (p, q, g) <- parseDsaParams params
              xder <- whole 0x04 oct
              x <- derInt xder
              pure (p, q, g, x)
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | DH domain parameters: the SEQUENCE of exactly two (PKCS#3
-- p, g) or three (X9.42 p, g, q) INTEGERs. Anything else is
-- 'Nothing'.
parseDhParams :: ByteString -> Maybe (ByteString, ByteString, Maybe ByteString)
parseDhParams der = do
  body <- whole 0x30 der
  parts <- seqTop body
  case parts of
    [p, g] -> (,,) <$> derInt p <*> derInt g <*> pure Nothing
    [p, g, q] -> (,,) <$> derInt p <*> derInt g <*> (Just <$> derInt q)
    _ -> Nothing

-- | DH domain plus the public value from an SPKI: outer SEQ of
-- [algId, BIT STRING] where the algorithm is dhKeyAgreement
-- with PKCS#3 parameters or dhpublicnumber with X9.42
-- parameters, and the bit string (past its zero unused-bits
-- octet) is the INTEGER y. 'Nothing' on any framing, tag, or
-- OID mismatch.
dhSpkiFields :: ByteString -> Maybe (ByteString, ByteString, Maybe ByteString, ByteString)
dhSpkiFields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [algId, bits] -> do
      algParts <- whole 0x30 algId >>= seqTop
      case algParts of
        [oid, params]
          | oid == oidDhKeyAgreement || oid == oidDhPublicNumber -> do
              (p, g, q) <- parseDhParams params
              content <- whole 0x03 bits
              case BS.uncons content of
                Just (0, yder) -> do
                  y <- derInt yder
                  pure (p, g, q, y)
                _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | DH domain plus the private scalar from a PKCS#8: outer SEQ
-- of [version INTEGER 0, algId, OCTET STRING] where the
-- algorithm is dhKeyAgreement with PKCS#3 parameters or
-- dhpublicnumber with X9.42 parameters, and the octet string
-- wraps the INTEGER x. 'Nothing' on any framing, tag, version,
-- or OID mismatch.
dhPkcs8Fields :: ByteString -> Maybe (ByteString, ByteString, Maybe ByteString, ByteString)
dhPkcs8Fields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [ver, algId, oct] -> do
      v <- derInt ver
      case BS.uncons v of
        Just (0, rest) | BS.null rest -> do
          algParts <- whole 0x30 algId >>= seqTop
          case algParts of
            [oid, params]
              | oid == oidDhKeyAgreement || oid == oidDhPublicNumber -> do
                  (p, g, q) <- parseDhParams params
                  xder <- whole 0x04 oct
                  x <- derInt xder
                  pure (p, g, q, x)
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | The curve OID plus the raw point from an Edwards SPKI: outer
-- SEQ of [algId, BIT STRING] where the algorithm identifier is
-- the bare OID (a served 'edwardsTable' row) and the bit string
-- (past its zero unused-bits octet) is the width-exact point.
-- 'Nothing' on any framing, tag, OID, or width mismatch.
eddsaSpkiFields :: ByteString -> Maybe (ByteString, ByteString)
eddsaSpkiFields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [algId, bits] -> do
      algParts <- whole 0x30 algId >>= seqTop
      case algParts of
        [oid] -> do
          (seedW, _) <- edwardsWidthsOfParams oid
          content <- whole 0x03 bits
          case BS.uncons content of
            Just (0, point)
              | BS.length point == seedW -> pure (oid, point)
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | The curve OID plus the seed from an Edwards PKCS#8: outer SEQ
-- of [version INTEGER 0, algId, OCTET STRING] where the
-- algorithm identifier is the bare OID (a served 'edwardsTable'
-- row) and the octet string wraps the width-exact seed (RFC 8410
-- nested OCTET STRING). 'Nothing' on any framing, tag, version,
-- OID, or width mismatch.
eddsaPkcs8Fields :: ByteString -> Maybe (ByteString, ByteString)
eddsaPkcs8Fields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [ver, algId, oct] -> do
      v <- derInt ver
      case BS.uncons v of
        Just (0, rest) | BS.null rest -> do
          algParts <- whole 0x30 algId >>= seqTop
          case algParts of
            [oid] -> do
              (seedW, _) <- edwardsWidthsOfParams oid
              inner <- whole 0x04 oct
              seed <- whole 0x04 inner
              if BS.length seed == seedW
                then pure (oid, seed)
                else Nothing
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | The curve OID plus the raw u-coordinate from a Montgomery
-- SPKI: outer SEQ of [algId, BIT STRING] where the algorithm
-- identifier is the bare OID (a served 'montgomeryTable' row)
-- and the bit string (past its zero unused-bits octet) is the
-- width-exact coordinate. 'Nothing' on any framing, tag, OID, or
-- width mismatch.
montgomerySpkiFields :: ByteString -> Maybe (ByteString, ByteString)
montgomerySpkiFields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [algId, bits] -> do
      algParts <- whole 0x30 algId >>= seqTop
      case algParts of
        [oid] -> do
          w <- montgomeryWidthOfParams oid
          content <- whole 0x03 bits
          case BS.uncons content of
            Just (0, point)
              | BS.length point == w -> pure (oid, point)
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | The curve OID plus the scalar from a Montgomery PKCS#8: outer
-- SEQ of [version INTEGER 0, algId, OCTET STRING] where the
-- algorithm identifier is the bare OID (a served
-- 'montgomeryTable' row) and the octet string wraps the
-- width-exact scalar (RFC 8410 nested OCTET STRING — the Edwards
-- shape). 'Nothing' on any framing, tag, version, OID, or width
-- mismatch.
montgomeryPkcs8Fields :: ByteString -> Maybe (ByteString, ByteString)
montgomeryPkcs8Fields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [ver, algId, oct] -> do
      v <- derInt ver
      case BS.uncons v of
        Just (0, rest) | BS.null rest -> do
          algParts <- whole 0x30 algId >>= seqTop
          case algParts of
            [oid] -> do
              w <- montgomeryWidthOfParams oid
              inner <- whole 0x04 oct
              scalar <- whole 0x04 inner
              if BS.length scalar == w
                then pure (oid, scalar)
                else Nothing
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | The algorithm OID plus the raw public key from an ML-DSA
-- SPKI: outer SEQ of [algId, BIT STRING] where the algorithm
-- identifier is the bare OID (a served 'mldsaTable' row) and
-- the bit string (past its zero unused-bits octet) is the
-- width-exact key. 'Nothing' on any framing, tag, OID, or
-- width mismatch.
mldsaSpkiFields :: ByteString -> Maybe (ByteString, ByteString)
mldsaSpkiFields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [algId, bits] -> do
      algParts <- whole 0x30 algId >>= seqTop
      case algParts of
        [oid] -> do
          (pubW, _, _) <- mldsaWidthsOfOid oid
          content <- whole 0x03 bits
          case BS.uncons content of
            Just (0, point)
              | BS.length point == pubW -> pure (oid, point)
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | The algorithm OID plus the seed and the raw expanded key
-- from a provider-form ML-DSA PKCS#8: outer SEQ of [version
-- INTEGER 0, algId, OCTET STRING] where the algorithm
-- identifier is the bare OID (a served 'mldsaTable' row) and
-- the octet string wraps SEQ { seed OCTET (32), expanded OCTET
-- (width-exact) }. This is the provider's own encoding (what
-- keygen stores; the seed feeds @CKA_SEED@, the expanded key
-- @CKA_VALUE@); our import assembly is the flat form instead
-- ('mldsaPrivateDer'), which this reader does not accept.
-- 'Nothing' on any framing, tag, version, OID, or width
-- mismatch.
mldsaPkcs8Fields :: ByteString -> Maybe (ByteString, ByteString, ByteString)
mldsaPkcs8Fields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [ver, algId, oct] -> do
      v <- derInt ver
      case BS.uncons v of
        Just (0, rest) | BS.null rest -> do
          algParts <- whole 0x30 algId >>= seqTop
          case algParts of
            [oid] -> do
              (_, privW, _) <- mldsaWidthsOfOid oid
              inner <- whole 0x04 oct
              parts1 <- whole 0x30 inner >>= seqTop
              case parts1 of
                [seedOct, expOct] -> do
                  seed <- whole 0x04 seedOct
                  expanded <- whole 0x04 expOct
                  if BS.length seed == 32 && BS.length expanded == privW
                    then pure (oid, seed, expanded)
                    else Nothing
                _ -> Nothing
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | The algorithm OID plus the raw public key from an SLH-DSA
-- SPKI: outer SEQ of [algId, BIT STRING] where the algorithm
-- identifier is the bare OID (a served 'slhdsaTable' row) and
-- the bit string (past its zero unused-bits octet) is the
-- width-exact key. 'Nothing' on any framing, tag, OID, or
-- width mismatch.
slhdsaSpkiFields :: ByteString -> Maybe (ByteString, ByteString)
slhdsaSpkiFields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [algId, bits] -> do
      algParts <- whole 0x30 algId >>= seqTop
      case algParts of
        [oid] -> do
          (pubW, _, _) <- slhdsaWidthsOfOid oid
          content <- whole 0x03 bits
          case BS.uncons content of
            Just (0, point)
              | BS.length point == pubW -> pure (oid, point)
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | The algorithm OID plus the raw 4n secret from an SLH-DSA
-- PKCS#8: outer SEQ of [version INTEGER 0, algId, OCTET STRING]
-- where the algorithm identifier is the bare OID (a served
-- 'slhdsaTable' row) and the octet string carries the flat
-- secret directly (the provider's own shape — assembly and
-- the keygen-stored form agree, unlike ML-DSA's SEQ form).
-- 'Nothing' on any framing, tag, version, OID, or width
-- mismatch.
slhdsaPkcs8Fields :: ByteString -> Maybe (ByteString, ByteString)
slhdsaPkcs8Fields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [ver, algId, oct] -> do
      v <- derInt ver
      case BS.uncons v of
        Just (0, rest) | BS.null rest -> do
          algParts <- whole 0x30 algId >>= seqTop
          case algParts of
            [oid] -> do
              (_, privW, _) <- slhdsaWidthsOfOid oid
              raw <- whole 0x04 oct
              if BS.length raw == privW
                then pure (oid, raw)
                else Nothing
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | The algorithm OID plus the raw encapsulation key from an
-- ML-KEM SPKI: outer SEQ of [algId, BIT STRING] where the
-- algorithm identifier is the bare OID (a served 'mlkemTable'
-- row) and the bit string (past its zero unused-bits octet)
-- is the width-exact key. 'Nothing' on any framing, tag, OID,
-- or width mismatch.
mlkemSpkiFields :: ByteString -> Maybe (ByteString, ByteString)
mlkemSpkiFields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [algId, bits] -> do
      algParts <- whole 0x30 algId >>= seqTop
      case algParts of
        [oid] -> do
          (ekW, _, _) <- mlkemWidthsOfOid oid
          content <- whole 0x03 bits
          case BS.uncons content of
            Just (0, ek)
              | BS.length ek == ekW -> pure (oid, ek)
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing

-- | The algorithm OID plus the seed and the raw
-- decapsulation key from a provider-form ML-KEM PKCS#8: outer
-- SEQ of [version INTEGER 0, algId, OCTET STRING] where the
-- algorithm identifier is the bare OID (a served 'mlkemTable'
-- row) and the octet string wraps SEQ { seed OCTET (64,
-- @d || z@), dk OCTET (width-exact) }. This is the provider's
-- own encoding (what keygen stores; the seed feeds
-- @CKA_SEED@, the dk @CKA_VALUE@); dk-only import stores raw
-- bytes instead (no decodable DER exists without the seed),
-- and seed+dk import assembles this same form
-- ('mlkemPrivateDer'). 'Nothing' on any framing, tag,
-- version, OID, or width mismatch.
mlkemPkcs8Fields :: ByteString -> Maybe (ByteString, ByteString, ByteString)
mlkemPkcs8Fields der = do
  outer <- whole 0x30 der
  parts0 <- seqTop outer
  case parts0 of
    [ver, algId, oct] -> do
      v <- derInt ver
      case BS.uncons v of
        Just (0, rest) | BS.null rest -> do
          algParts <- whole 0x30 algId >>= seqTop
          case algParts of
            [oid] -> do
              (_, dkW, _) <- mlkemWidthsOfOid oid
              inner <- whole 0x04 oct
              parts1 <- whole 0x30 inner >>= seqTop
              case parts1 of
                [seedOct, dkOct] -> do
                  seed <- whole 0x04 seedOct
                  dk <- whole 0x04 dkOct
                  if BS.length seed == 64 && BS.length dk == dkW
                    then pure (oid, seed, dk)
                    else Nothing
                _ -> Nothing
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing
