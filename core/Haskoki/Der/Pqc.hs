{- | Haskoki.Der.Pqc: ML-DSA, SLH-DSA and ML-KEM DER codecs.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Der.Pqc
  ( mldsaTable
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
  ) where


import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (find)

import Haskoki.Der.Primitives

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

-- | PKCS#8 for an ML-DSA private key from the DER algorithm OID
-- and the raw expanded key (NOT the Edwards nested-seed shape:
-- haskoki's import path requires the flat expanded key -- the
-- provider documents seed expansion, but haskoki never supplies
-- seed-only PKCS#8; expanded-key import proven by probe against
-- a wycheproof vector, sign+verify roundtrip).
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
