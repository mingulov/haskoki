{- | Haskoki.Engine.Synthetic.Capabilities: served-algorithm tables behind the capability builder.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Synthetic.Capabilities
  ( synthMacSpecs
  , synthRsaSpecNames
  , synthEcdsaSpecNames
  , synthDsaAlgs
  , synthDsaSpecNames
  , synthDsaNotes
  , synthEddsaSpecNames
  , synthEddsaNotes
  , synthMldsaSpecNames
  , synthMldsaNotes
  , synthSlhdsaSpecNames
  , synthSlhdsaNotes
  , synthMacNotes
  , synthEcdsaNotes
  , synthCipherSpecs
  , isCcmAlg
  , aeadTagSet
  , aeadKeyLen
  ) where


import qualified Data.Set as Set

import Haskoki.Engine.Backend
  ( CipherSpec (..)
  , DigestAlg (..)
  , digestMacStem
  , digestOutLen
  , ecdsaSigCap
  , dsaSigCap
  , eddsaSigCap
  , mldsaSigCap
  , slhdsaSigCap
  , slhdsaSets
  , EcSpec (..)
  , hmacSpecCap
  , poly1305SpecCap
  , MacSpec (..)
  , PqcSigAlg (..)
  , rsaSigCap
  , rsaX931Cap
  , SigSpec (..)
  )
import Haskoki.Der
  ( coveredCurveNames
  , edwardsCurveNames
  )


-- | The synthetic MAC set: plain and GENERAL names for
-- every fixed-width digest (derived through 'hmacSpecCap', so the
-- advertised set and the guard can never disagree).
synthMacSpecs :: Set.Set String
synthMacSpecs = Set.fromList
  ( [ name
    | alg <- [minBound .. maxBound]
    , spec <- [MacHMAC alg Nothing, MacHMAC alg (Just 1)]
    , Just name <- [hmacSpecCap spec]
    ]
    ++ [ name | Just name <- [poly1305SpecCap MacPoly1305] ]
  )

-- | The RSA names: one PKCS#1 v1.5 name per recipe digest
-- plus the raw and X.509 rows (exactly the OpenSSL4 pre-probe
-- set, so both engines advertise the same names).
synthRsaSpecNames :: [String]
synthRsaSpecNames =
  [ name
  | spec <- SigRSA_Raw : SigRSA_X509 : map SigRSA_PKCS1v15 synthRsaAlgs
  , Just name <- [rsaSigCap spec]
  ]
  ++ [ name | Just name <- [rsaX931Cap (SigRSA_X931 Nothing)] ]
  where
    synthRsaAlgs =
      [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
      , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
      , D_RIPEMD160
      ]

-- | The ECDSA names: one hash-and-sign name per (curve,
-- fixed-width digest) plus the raw row per curve (exactly the
-- OpenSSL4 pre-probe set over its digest set, so both engines
-- advertise the same names).
synthEcdsaSpecNames :: [String]
synthEcdsaSpecNames =
  [ name
  | curve <- coveredCurveNames
  , spec <- SigECDSA (EcSpec curve "DER") Nothing :
      [ SigECDSA (EcSpec curve "DER") (Just alg) | alg <- synthEcdsaAlgs ]
  , Just name <- [ecdsaSigCap spec]
  ]
  where
    synthEcdsaAlgs =
      [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
      , D_SHA512_224, D_SHA512_256
      , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
      , D_RIPEMD160
      , D_BLAKE2B512
      , D_BLAKE2B160
      , D_BLAKE2B256
      , D_BLAKE2B384
      ]

-- | The DSA digest set: exactly the recipe's nine (same names as
-- the OpenSSL4 pre-probe set, so both engines advertise the same
-- DSA names).
synthDsaAlgs :: [DigestAlg]
synthDsaAlgs =
  [ D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
  , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
  ]

-- | DSA capability names: one hash-and-sign name per recipe digest
-- plus the raw row.
synthDsaSpecNames :: [String]
synthDsaSpecNames =
  [ name
  | spec <- SigDSA "DER" Nothing :
      [ SigDSA "DER" (Just alg) | alg <- synthDsaAlgs ]
  , Just name <- [dsaSigCap spec]
  ]

-- | Per-name DSA parameter notes for the capability report.
synthDsaNotes :: [(String, String)]
synthDsaNotes =
  [ (name, note spec)
  | spec <- SigDSA "DER" Nothing :
      [ SigDSA "DER" (Just alg) | alg <- synthDsaAlgs ]
  , Just name <- [dsaSigCap spec]
  ]
  where
    note (SigDSA _ Nothing) = "raw operation, no hashing (>= 20-byte digest); encodings DER and RAW"
    note _ = "hash-and-sign; encodings DER and RAW"

-- | The EdDSA names: one pure-sign name per served curve (exactly
-- the OpenSSL4 pre-probe set, so both engines advertise the same
-- names).
synthEddsaSpecNames :: [String]
synthEddsaSpecNames =
  [ name
  | curve <- edwardsCurveNames
  , Just name <- [eddsaSigCap (SigEdDSA (EcSpec curve "RAW") "")]
  ]

-- | Per-name EdDSA parameter notes for the capability report.
synthEddsaNotes :: [(String, String)]
synthEddsaNotes =
  [ (name, "pure EdDSA, one-shot; raw fixed-width signatures (64/114 bytes)")
  | curve <- edwardsCurveNames
  , Just name <- [eddsaSigCap (SigEdDSA (EcSpec curve "RAW") "")]
  ]

-- | The ML-DSA names: one sign name per level (exactly the
-- OpenSSL4 pre-probe set, so both engines advertise the same
-- names).
synthMldsaSpecNames :: [String]
synthMldsaSpecNames =
  [ name
  | alg <- [ML_DSA_44, ML_DSA_65, ML_DSA_87]
  , Just name <- [mldsaSigCap (SigMLDSA alg False "" True)]
  ]

-- | Per-name ML-DSA parameter notes for the capability report.
synthMldsaNotes :: [(String, String)]
synthMldsaNotes =
  [ (name, "deterministic test construction; level, context, and hedge in domain")
  | alg <- [ML_DSA_44, ML_DSA_65, ML_DSA_87]
  , Just name <- [mldsaSigCap (SigMLDSA alg False "" True)]
  ]

-- | The SLH-DSA names: one sign name per set (exactly the
-- OpenSSL4 pre-probe set, so both engines advertise the same
-- names).
synthSlhdsaSpecNames :: [String]
synthSlhdsaSpecNames =
  [ name
  | alg <- slhdsaSets
  , Just name <- [slhdsaSigCap (SigSLHDSA alg "" True)]
  ]

-- | Per-name SLH-DSA parameter notes for the capability report.
synthSlhdsaNotes :: [(String, String)]
synthSlhdsaNotes =
  [ (name, "deterministic test construction; set, context, and hedge in domain")
  | alg <- slhdsaSets
  , Just name <- [slhdsaSigCap (SigSLHDSA alg "" True)]
  ]

-- | Per-name MAC parameter notes for the capability report.
synthMacNotes :: [(String, String)]
synthMacNotes =
  [ note
  | alg <- [minBound .. maxBound]
  , Just stem <- [digestMacStem alg]
  , Just w <- [digestOutLen alg]
  , note <-
      [ ("HMAC-" ++ stem, "full " ++ show w ++ "-byte tag")
      , ("HMAC-" ++ stem ++ "-GENERAL"
        , "tag truncated to the requested 1.." ++ show w ++ " bytes")
      ]
  ]

-- | Per-name ECDSA parameter notes for the capability report.
synthEcdsaNotes :: [(String, String)]
synthEcdsaNotes =
  [ (name, note spec)
  | curve <- coveredCurveNames
  , spec <- SigECDSA (EcSpec curve "DER") Nothing :
      [ SigECDSA (EcSpec curve "DER") (Just alg)
      | alg <- [minBound .. maxBound]
      ]
  , Just name <- [ecdsaSigCap spec]
  ]
  where
    note (SigECDSA _ Nothing) = "raw operation, no hashing; encodings DER and RAW"
    note _ = "hash-and-sign; encodings DER and RAW"

-- | The cipher set: every backend spec the block-cipher
-- recipe reaches (AES CBC/ECB/CTR/CTS/CFB/OFB/WRAP/XTS at three
-- widths, ARIA/CAMELLIA CBC+ECB+CTR at three widths, Triple-DES
-- CBC+ECB, ChaCha20, single-DES/CAST-128/IDEA/SEED/Blowfish/RC4,
-- RC2 in canonical 0-bits form — membership normalizes).
synthCipherSpecs :: [CipherSpec]
synthCipherSpecs =
  [ C_AES128_CBC, C_AES192_CBC, C_AES256_CBC
  , C_AES128_CTR, C_AES192_CTR, C_AES256_CTR
  , C_AES128_ECB, C_AES192_ECB, C_AES256_ECB
  , C_AES128_CTS, C_AES192_CTS, C_AES256_CTS
  , C_AES128_CFB128, C_AES192_CFB128, C_AES256_CFB128
  , C_AES128_CFB8, C_AES192_CFB8, C_AES256_CFB8
  , C_AES128_CFB1, C_AES192_CFB1, C_AES256_CFB1
  , C_AES128_OFB, C_AES192_OFB, C_AES256_OFB
  , C_AES128_KW, C_AES192_KW, C_AES256_KW
  , C_AES128_KWP, C_AES192_KWP, C_AES256_KWP
  , C_AES128_XTS, C_AES256_XTS
  , C_DES3_CBC, C_DES3_ECB
  , C_ARIA128_CBC, C_ARIA192_CBC, C_ARIA256_CBC
  , C_ARIA128_ECB, C_ARIA192_ECB, C_ARIA256_ECB
  , C_CAMELLIA128_CBC, C_CAMELLIA192_CBC, C_CAMELLIA256_CBC
  , C_CAMELLIA128_ECB, C_CAMELLIA192_ECB, C_CAMELLIA256_ECB
  , C_CAMELLIA128_CTR, C_CAMELLIA192_CTR, C_CAMELLIA256_CTR
  , C_CHACHA20
  , C_DES_ECB, C_DES_CBC, C_DES_OFB64, C_DES_CFB64, C_DES_CFB8
  , C_CAST128_ECB, C_CAST128_CBC
  , C_CAST_ECB, C_CAST_CBC
  , C_CAST3_ECB, C_CAST3_CBC
  , C_IDEA_ECB, C_IDEA_CBC
  , C_SEED_ECB, C_SEED_CBC
  , C_BLOWFISH_CBC
  , C_RC2_ECB 0, C_RC2_CBC 0
  , C_RC4
  ]

-- | CCM algorithm names take the CCM bounds.
isCcmAlg :: String -> Bool
isCcmAlg alg = alg `elem` ["AES-128-CCM", "AES-192-CCM", "AES-256-CCM"]

-- | Approved tag widths per AEAD family (GCM: SP 800-38D; CCM:
-- SP 800-38C even widths; Poly1305: the fixed 16).
aeadTagSet :: String -> [Int]
aeadTagSet alg
  | isCcmAlg alg = [4, 6, 8, 10, 12, 14, 16]
  | alg == "ChaCha20-Poly1305" = [16]
  | otherwise = [4, 8, 12, 13, 14, 15, 16]

-- | Key length in bytes for a supported AEAD algorithm name.
aeadKeyLen :: String -> Int
aeadKeyLen alg
  | alg == "AES-128-GCM" || alg == "AES-128-CCM" = 16
  | alg == "AES-192-GCM" || alg == "AES-192-CCM" = 24
  | otherwise = 32
