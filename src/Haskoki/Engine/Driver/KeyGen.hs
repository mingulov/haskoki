{- | Keygen and KEM answer adapters: symmetric labels, parity and
prefix shaping, key-pair joining, and the PQC keygen-alg numbers.

Imports 'Haskoki.Engine.Driver.Result' for the failure collapse and
'Haskoki.Operation.KeyManagement' for the keygen mechanism ids and
the pair encoding. Used by the 'runEffect' keygen arms.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.KeyGen
  ( symKeygenLabels
  , toParityPair
  , toPrefixedPair
  , toKeyPair
  , mlKemAlg
  , mlDsaAlg
  , slhDsaAlg
  , toPqcKem
  ) where

import Data.Bits (popCount, xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

import Haskoki.Engine.Backend
  ( EngineResult (..)
  , KeyMaterial (..)
  , PqcKemAlg (..)
  , PqcSigAlg (..)
  )
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Operation.Kem (KemAlg (..))
import Haskoki.Operation.KeyManagement
  ( aesXtsKeyGenMech
  , ariaKeyGenMech
  , batonKeyGenMech
  , blake2b160KeyGenMech
  , blake2b256KeyGenMech
  , blake2b384KeyGenMech
  , blowfishKeyGenMech
  , camelliaKeyGenMech
  , cast128KeyGenMech
  , cast3KeyGenMech
  , castKeyGenMech
  , cdmfKeyGenMech
  , des2KeyGenMech
  , desKeyGenMech
  , encodeKeyPair
  , gost28147KeyGenMech
  , hkdfKeyGenMech
  , ideaKeyGenMech
  , juniperKeyGenMech
  , poly1305KeyGenMech
  , rc2KeyGenMech
  , rc4KeyGenMech
  , rc5KeyGenMech
  , salsa20KeyGenMech
  , seedKeyGenMech
  , sha1KeyGenMech
  , sha224KeyGenMech
  , sha256KeyGenMech
  , sha384KeyGenMech
  , sha3_224KeyGenMech
  , sha3_256KeyGenMech
  , sha3_384KeyGenMech
  , sha3_512KeyGenMech
  , sha512_224KeyGenMech
  , sha512_256KeyGenMech
  , sha512KeyGenMech
  , sha512TKeyGenMech
  , skipjackKeyGenMech
  , twofishKeyGenMech
  )
import Haskoki.Registry (MechanismId (..))

-- | Keygen answers: the framed private half plus the optional public
-- half. A backend reference (rather than owned material) cannot
-- cross to the object store and fails loudly.
--
-- | Sweep keygens onto backend 'GenSym' labels (slice 11a): the
-- planner admits lengths, the label only selects the backend's
-- domain separation and bound mirror.
symKeygenLabels :: [(MechanismId, String)]
symKeygenLabels =
  [ (desKeyGenMech, "DES")
  , (des2KeyGenMech, "DES2")
  , (cdmfKeyGenMech, "CDMF")
  , (castKeyGenMech, "CAST")
  , (cast3KeyGenMech, "CAST3")
  , (cast128KeyGenMech, "CAST128")
  , (rc2KeyGenMech, "RC2")
  , (rc4KeyGenMech, "RC4")
  , (rc5KeyGenMech, "RC5")
  , (ideaKeyGenMech, "IDEA")
  , (skipjackKeyGenMech, "SKIPJACK")
  , (batonKeyGenMech, "BATON")
  , (juniperKeyGenMech, "JUNIPER")
  , (blowfishKeyGenMech, "BLOWFISH")
  , (twofishKeyGenMech, "TWOFISH")
  , (gost28147KeyGenMech, "GOST28147")
  , (seedKeyGenMech, "SEED")
  , (ariaKeyGenMech, "ARIA")
  , (camelliaKeyGenMech, "CAMELLIA")
  , (salsa20KeyGenMech, "SALSA20")
  , (poly1305KeyGenMech, "POLY1305")
  , (aesXtsKeyGenMech, "AES-XTS")
  , (hkdfKeyGenMech, "HKDF")
  , (sha1KeyGenMech, "SHA-1-HMAC")
  , (sha224KeyGenMech, "SHA224-HMAC")
  , (sha256KeyGenMech, "SHA256-HMAC")
  , (sha384KeyGenMech, "SHA384-HMAC")
  , (sha512KeyGenMech, "SHA512-HMAC")
  , (sha512_224KeyGenMech, "SHA512-224-HMAC")
  , (sha512_256KeyGenMech, "SHA512-256-HMAC")
  , (sha512TKeyGenMech, "SHA512-T-HMAC")
  , (sha3_224KeyGenMech, "SHA3-224-HMAC")
  , (sha3_256KeyGenMech, "SHA3-256-HMAC")
  , (sha3_384KeyGenMech, "SHA3-384-HMAC")
  , (sha3_512KeyGenMech, "SHA3-512-HMAC")
  , (blake2b160KeyGenMech, "BLAKE2B-160-HMAC")
  , (blake2b256KeyGenMech, "BLAKE2B-256-HMAC")
  , (blake2b384KeyGenMech, "BLAKE2B-384-HMAC")
  ]

-- | Parity keygen answers: the backend mints random bytes and the
-- driver sets odd DES parity on the private half (FIPS 46-3),
-- so both backends share one parity home.
toParityPair :: EngineResult (KeyMaterial, Maybe KeyMaterial) -> CryptoResult
toParityPair (EngineOk (priv, mPub)) = toKeyPair (EngineOk (parityMat priv, mPub))
  where
    parityMat (KeyBytes bs) = KeyBytes (setOddParity bs)
    parityMat other = other
toParityPair (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Set odd parity on every byte (DES key material).
setOddParity :: ByteString -> ByteString
setOddParity = BS.map setByte
  where
    setByte b
      | odd (popCount b) = b
      | otherwise = b `xor` 1

-- | Prefixed keygen answers: the version bytes lead the
-- backend-minted random tail (TLS/SSL3/WTLS pre-master).
toPrefixedPair :: ByteString -> EngineResult (KeyMaterial, Maybe KeyMaterial) -> CryptoResult
toPrefixedPair prefix (EngineOk (priv, mPub)) = toKeyPair (EngineOk (prefixMat priv, mPub))
  where
    prefixMat (KeyBytes bs) = KeyBytes (prefix <> bs)
    prefixMat other = other
toPrefixedPair _ (EngineFail err) = GotCryptoError (toCryptoError err)

toKeyPair :: EngineResult (KeyMaterial, Maybe KeyMaterial) -> CryptoResult
toKeyPair (EngineOk (priv, mPub)) = case (keyBytes priv, traverse keyBytes mPub) of
  (Just p, Just q) -> GotBytes (encodeKeyPair p q)
  _ -> GotCryptoError (CryptoFailed "driver: keygen returned an unexportable reference")
  where
    keyBytes :: KeyMaterial -> Maybe ByteString
    keyBytes (KeyBytes bs) = Just bs
    keyBytes (KeyDer bs) = Just bs
    keyBytes (KeyRefMaterial _) = Nothing
toKeyPair (EngineFail err) = GotCryptoError (toCryptoError err)

-- | ML-KEM parameter-set numbers onto backend algorithms.
mlKemAlg :: Int -> Maybe PqcKemAlg
mlKemAlg n = case n of
  512 -> Just ML_KEM_512
  768 -> Just ML_KEM_768
  1024 -> Just ML_KEM_1024
  _ -> Nothing

-- | ML-DSA parameter-set ids (@CKP_ML_DSA_44\/65\/87@) onto
-- backend algorithms.
mlDsaAlg :: Int -> Maybe PqcSigAlg
mlDsaAlg n = case n of
  1 -> Just ML_DSA_44
  2 -> Just ML_DSA_65
  3 -> Just ML_DSA_87
  _ -> Nothing

-- | SLH-DSA parameter-set ids (@CKP_SLH_DSA_*@) onto backend
-- algorithms.
slhDsaAlg :: Int -> Maybe PqcSigAlg
slhDsaAlg n = case n of
  1 -> Just SLH_DSA_SHA2_128s
  2 -> Just SLH_DSA_SHAKE_128s
  3 -> Just SLH_DSA_SHA2_128f
  4 -> Just SLH_DSA_SHAKE_128f
  5 -> Just SLH_DSA_SHA2_192s
  6 -> Just SLH_DSA_SHAKE_192s
  7 -> Just SLH_DSA_SHA2_192f
  8 -> Just SLH_DSA_SHAKE_192f
  9 -> Just SLH_DSA_SHA2_256s
  10 -> Just SLH_DSA_SHAKE_256s
  11 -> Just SLH_DSA_SHA2_256f
  12 -> Just SLH_DSA_SHAKE_256f
  _ -> Nothing

-- | Planner KEM sets onto backend algorithms.
toPqcKem :: KemAlg -> PqcKemAlg
toPqcKem alg = case alg of
  KemMl512 -> ML_KEM_512
  KemMl768 -> ML_KEM_768
  KemMl1024 -> ML_KEM_1024
