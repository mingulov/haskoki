{- | OpenSSL capability and guard cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Caps
  ( caseCaps
  , caseCapsEvaluated
  , caseCapsNotes
  , caseGuardBeforeNative
  , caseStaticCapsEvaluated
  , caseUnsupported
  ) where

import Control.Exception (evaluate)
import qualified Data.ByteString as BS
import Data.List (isInfixOf, isPrefixOf)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import LazyWalk (lazyClosures)
import Haskoki.Engine.Backend
  ( BackendCaps (..)
  , BackendEnv
  , BackendError (..)
  , CipherCaps (..)
  , CipherSpec (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , DigestCaps (..)
  , EngineResult (..)
  , KemCaps (..)
  , KeyMaterial (..)
  , KdfCaps (..)
  , MacCaps (..)
  , MacSpec (..)
  , OaepParams (..)
  , PqcKemAlg (..)
  , RsaCipherParams (..)
  , SigCaps (..)
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..), ossl4StaticCapsBuild)
import OpenSSL.Fixtures

caseUnsupported :: IO ()
caseUnsupported = withBackend $ \env -> do
  -- Fixed-length digests are supported; XOF stays out.
  expectUnsupported "shake128 digest" =<< digestOneShot env D_SHAKE128 "abc"
  expectUnsupported "shake256 digest" =<< digestOneShot env D_SHAKE256 "abc"
  -- The 23-spec CBC/CTR/ECB set is supported (see
  -- caseCipherKats, which pins the CTR stream specs too).
  expectUnsupported "cmac" =<< macSign env (MacCMAC C_AES256_CBC) (KeyBytes hmacKey1) hmacMsg1
  -- In-range truncation is supported (see caseHmacGeneral);
  -- out-of-range lengths and XOFs stay out.
  expectUnsupported "zero-length hmac" =<< macSign env (MacHMAC D_SHA256 (Just 0)) (KeyBytes hmacKey1) hmacMsg1
  expectUnsupported "over-width hmac" =<< macSign env (MacHMAC D_SHA256 (Just 33)) (KeyBytes hmacKey1) hmacMsg1
  expectUnsupported "shake hmac" =<< macSign env (MacHMAC D_SHAKE128 Nothing) (KeyBytes hmacKey1) hmacMsg1
  -- OAEP is supported (see caseRsaOaepVectors); XOF
  -- hashes stay out.
  expectUnsupported "rsa oaep xof" =<< pkeyEncrypt env (mkOaep D_SHAKE128) (KeyDer ecPubDer) "x"
  -- ML-KEM is served (see caseMlkem); a foreign key under it
  -- refuses typed, never unsupported, never silent.
  expectBadKey "ml-kem encaps cross-key" =<< kemEncapsulate env (mkKem ML_KEM_768) (KeyDer ecPubDer)

caseGuardBeforeNative :: IO ()
caseGuardBeforeNative = do
  -- On a closed backend the capability guard still answers Unsupported
  -- (not a native crash): the check precedes any native call. Every
  -- cipher spec is served, so the cipher leg pins the closed check
  -- instead: a supported cipher answers InvalidState, never a crash.
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  env <- case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk e -> pure e
  closeBackend env
  expectUnsupported "unsupported on closed backend" =<< digestOneShot env D_SHAKE128 "abc"
  closed <- cipherEncrypt env C_AES128_CTR (KeyBytes aes128Key) aes256Iv aes256Pt
  case closed of
    EngineFail (BackendInvalidState _ _) -> pure ()
    other -> assertFailure ("expected InvalidState, got: " ++ show other)

-- | Regression for the whole-process model-test stall: GHC's RTS
-- (seen on 9.10.3, 9.12.4 and 9.14.1; a GHC #26324 variant) can
-- orphan a string-literal CAF black hole when two threads
-- dup-evaluate the same lazily black-holed thunk, deadlocking every
-- thread that needs it. Concurrent opens used to evaluate the
-- capability tables' shared thunks in parallel (and concurrent
-- capability readers could too), so the report must reach callers
-- with no thunk left in it.
caseCapsEvaluated :: IO ()
caseCapsEvaluated = withBackend $ \env -> do
  caps <- evaluate =<< queryCapabilities env
  lz <- lazyClosures caps
  assertBool ("published capability report holds " ++ show (length lz)
              ++ " lazy closures, e.g. " ++ show (take 5 lz)) (null lz)

-- | The open-independent capability table publishes only normal
-- form: no thunk of it is ever shared between threads (GHC #27272).
-- The test builds a fresh copy through the builder, so it does not
-- depend on whichever open already forced the shared table.
caseStaticCapsEvaluated :: IO ()
caseStaticCapsEvaluated = do
  caps <- evaluate (ossl4StaticCapsBuild ())
  lz <- lazyClosures caps
  assertBool ("static capability table holds " ++ show (length lz)
              ++ " lazy closures after WHNF, e.g. " ++ show (take 5 lz)) (null lz)

-- | The published notes keep their content: the provider note
-- carries the open's property query, and a cipher note is present.
caseCapsNotes :: IO ()
caseCapsNotes = withBackend $ \env -> do
  caps <- queryCapabilities env
  case Map.lookup "provider" (bcParamNotes caps) of
    Just note -> assertBool ("provider note: " ++ note)
      ("default+legacy; propquery " `isPrefixOf` note)
    Nothing -> assertFailure "no provider note"
  assertEqual "cipher note"
    (Just "no padding; key 32 bytes, iv 16 bytes, input block-aligned")
    (Map.lookup "AES-256-CBC" (bcParamNotes caps))

caseCaps :: IO ()
caseCaps = withBackend $ \env -> do
  caps <- queryCapabilities env
  assertEqual "backend name" "openssl4" (bcName caps)
  assertBool ("version pins 4.1.0, got " ++ bcVersion caps)
    ("4.1.0" `isInfixOf` bcVersion caps)
  assertEqual "digest set" (Set.fromList
    [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
    , D_SHA512_224, D_SHA512_256
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    , D_RIPEMD160
    , D_BLAKE2B512
    , D_BLAKE2B160
    , D_BLAKE2B256
    , D_BLAKE2B384
    ]) (dcAlgs (bcDigests caps))
  assertEqual "cipher set" (Set.fromList
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
    ]) (ccCiphers (bcCiphers caps))
  assertEqual "cipher set size" 69 (Set.size (ccCiphers (bcCiphers caps)))
  assertEqual "aead set" (Set.fromList
    [ "AES-128-GCM", "AES-192-GCM", "AES-256-GCM"
    , "AES-128-CCM", "AES-192-CCM", "AES-256-CCM"
    , "ChaCha20-Poly1305"
    ]) (ccAead (bcCiphers caps))
  assertEqual "mac set" (Set.fromList
    [ "HMAC-MD5", "HMAC-SHA1"
    , "HMAC-SHA224", "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"
    , "HMAC-SHA512-224", "HMAC-SHA512-256"
    , "HMAC-SHA3-224", "HMAC-SHA3-256", "HMAC-SHA3-384", "HMAC-SHA3-512"
    , "HMAC-RIPEMD160"
    , "HMAC-BLAKE2B-512"
    , "HMAC-BLAKE2B-160", "HMAC-BLAKE2B-256", "HMAC-BLAKE2B-384"
    , "HMAC-MD5-GENERAL", "HMAC-SHA1-GENERAL"
    , "HMAC-SHA224-GENERAL", "HMAC-SHA256-GENERAL"
    , "HMAC-SHA384-GENERAL", "HMAC-SHA512-GENERAL"
    , "HMAC-SHA512-224-GENERAL", "HMAC-SHA512-256-GENERAL"
    , "HMAC-SHA3-224-GENERAL", "HMAC-SHA3-256-GENERAL"
    , "HMAC-SHA3-384-GENERAL", "HMAC-SHA3-512-GENERAL"
    , "HMAC-RIPEMD160-GENERAL"
    , "HMAC-BLAKE2B-512-GENERAL"
    , "HMAC-BLAKE2B-160-GENERAL", "HMAC-BLAKE2B-256-GENERAL", "HMAC-BLAKE2B-384-GENERAL"
    , "POLY1305"
    ]) (mcSpecs (bcMacs caps))
  assertBool "ecdsa-p256-sha256 advertised"
    (Set.member "ECDSA-P-256-SHA256" (scSpecs (bcSigs caps)))
  -- The RSA v1.5 names join the signature set (probe-narrowed
  -- over the same probed digests as the digest set, so all 11 land).
  -- The ECDSA names (22 curves x 13 digests + 22 raw), generated
  -- over explicit dimensions so a dropped curve or digest fails.
  let dsaCurves =
        [ "P-256", "P-384", "P-521", "secp224r1", "secp224k1"
        , "secp256k1", "secp192r1", "secp192k1", "secp160r1"
        , "secp160r2", "secp160k1", "brainpoolP224r1"
        , "brainpoolP256r1", "brainpoolP320r1", "brainpoolP384r1"
        , "brainpoolP512r1", "sect283k1", "sect283r1", "sect409k1"
        , "sect409r1", "sect571k1", "sect571r1"
        ]
      dsaStems =
        [ "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"
        , "SHA512-224", "SHA512-256", "SHA3-224", "SHA3-256"
        , "SHA3-384", "SHA3-512", "RIPEMD160", "BLAKE2B-512"
        ]
      dsaNames =
        ["ECDSA-" ++ c ++ "-RAW" | c <- dsaCurves]
          ++ ["ECDSA-" ++ c ++ "-" ++ s | c <- dsaCurves, s <- dsaStems]
      fipsDsaNames =
        ["DSA-RAW"]
          ++ ["DSA-" ++ s | s <- fipsDsaStems]
      fipsDsaStems =
        [ "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"
        , "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
        ]
      eddsaNames = ["EDDSA-Ed25519", "EDDSA-Ed448"]
      mldsaNames = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
      slhdsaNames =
        [ "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"
        , "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f"
        , "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f"
        , "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f"
        , "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f"
        , "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
        ]
  assertEqual "sig set" (Set.fromList
    ([ "RSA-PSS"
    , "RSA-RAW"
    , "RSA-X509"
    , "RSA-X931"
    , "RSA-PKCS1v15-MD5", "RSA-PKCS1v15-SHA1"
    , "RSA-PKCS1v15-SHA224", "RSA-PKCS1v15-SHA256"
    , "RSA-PKCS1v15-SHA384", "RSA-PKCS1v15-SHA512"
    , "RSA-PKCS1v15-SHA3-224", "RSA-PKCS1v15-SHA3-256"
    , "RSA-PKCS1v15-SHA3-384", "RSA-PKCS1v15-SHA3-512"
    , "RSA-PKCS1v15-RIPEMD160"
    ] ++ dsaNames ++ fipsDsaNames ++ eddsaNames ++ mldsaNames ++ slhdsaNames)) (scSpecs (bcSigs caps))
  assertEqual "curves" (Set.fromList dsaCurves) (scCurves (bcSigs caps))
  assertEqual "kem set" (Set.fromList [ML_KEM_512, ML_KEM_768, ML_KEM_1024]) (kcAlgs (bcKems caps))
  assertEqual "kdf set" (Set.fromList ["DH", "ECDH", "ECDH-COFACTOR"]) (kcKdfs (bcKdfs caps))

mkOaep :: DigestAlg -> RsaCipherParams
mkOaep d = RsaOaep (OaepParams { oaepHash = d, oaepMgf = d, oaepLabel = BS.empty })
