{- | OpenSSL 4 engine tests.

Known-answer vectors for SHA-256 (FIPS 180-4),
HMAC-SHA-256 (RFC 4231 case 1), AES-256-CBC (NIST SP 800-38A F.2.5),
and ECDSA P-256/SHA-256 (fixed vector generated with the system
openssl CLI, verified there before embedding). All oracles are
independent of synthetic-engine outputs.

Also: capability-miss rejection without silent fallback (including a
guard-before-native probe on a closed backend), explicit RAW-vs-DER
signature encodings with no silent conversion, private-context
isolation, lifetime-gate post-close pins plus simultaneous-close
totality, and shim-hygiene assertions.
-}
module OpenSSLSpec (spec) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)

import OpenSSL.Digest
import OpenSSL.Cipher
import OpenSSL.Rsa
import OpenSSL.Ecdsa
import OpenSSL.Dsa
import OpenSSL.Pqc
import OpenSSL.Agreement
import OpenSSL.Aead
import OpenSSL.Random
import OpenSSL.Caps
import OpenSSL.Lifecycle

spec :: TestTree
spec = testGroup "openssl4 engine"
  [ testCase "sha256 known answers (FIPS 180-4)" caseSha256Kat
  , testCase "sha256 multipart equals one-shot" caseSha256Multipart
  , testCase "Digest KATs (FIPS/RFC/RIPEMD)" caseDigestKats
  , testCase "Digest multipart equals one-shot" caseSha384Multipart
  , testCase "hmac-sha256 known answer (RFC 4231)" caseHmacKat
  , testCase "HMAC KATs (RFC/hashlib)" caseHmacKats
  , testCase "HMAC-GENERAL truncation (real)" caseHmacGeneral
  , testCase "hmac verify roundtrip and tamper" caseHmacVerify
  , testCase "aes-256-cbc known answer (SP 800-38A)" caseAesKat
  , testCase "aes-256-cbc roundtrip and bad lengths" caseAesRoundtrip
  , testCase "Block-cipher KATs (NIST/RFC/CLI)" caseCipherKats
  , testCase "aes-cts known answers (ACVP CBC-CS1)" caseAesCts
  , testCase "aes cfb/ofb known answers (ACVP)" caseAesCfbOfb
  , testCase "Legacy-cipher KATs (oracle/FIPS/RFC)" caseLegacyKats
  , testCase "aes-kw/kwp known answers (ACVP)" caseAesWrapKwp
  , testCase "aes-kw caller IV + kw-pkcs7 framing (provider)" caseAesWrapPkcs7
  , testCase "aes-xts known answers (ACVP)" caseAesXts
  , testCase "RSA v1.5 KATs (CLI vectors)" caseRsaKats
  , testCase "RSA-PSS interop (CLI vector)" caseRsaPssVectors
  , testCase "RSA-OAEP interop (CLI vectors)" caseRsaOaepVectors
  , testCase "RSA PKCS#1 v1.5 interop (CLI vector)" caseRsaPkcs1Vectors
  , testCase "RSA-X.509 interop (CLI vectors)" caseRsaX509Vectors
  , testCase "RSA-X9.31 interop (CLI vectors)" caseRsaX931Vectors
  , testCase "Poly1305 KAT (CLI + pyca vector)" casePoly1305Vector
  , testCase "ecdsa fixed-vector verify (DER and RAW)" caseEcdsaKat
  , testCase "ecdsa sign/verify roundtrip, both encodings" caseEcdsaRoundtrip
  , testCase "ECDSA curves/digests/raw (CLI vectors)" caseEcdsaCurvesVectors
  , testCase "ECDSA raw truncates overlong digests (SEC1)" caseEcdsaRawTruncate
  , testCase "ECDSA point-at-infinity rejects as mismatch" caseEcdsaInfinity
  , testCase "ECDSA odd-length raw sig refused by length" caseEcdsaOddSig
  , testCase "ECDSA short raw forms verify, past-bound refuses" caseEcdsaShortForms
  , testCase "ECDSA off-curve keys refused typed" caseEcdsaOffCurve
  , testCase "DSA wycheproof KAT + roundtrips (q224/q256)" caseDsa
  , testCase "DSA paramgen + keygen mint usable pairs" caseDsaKeygen
  , testCase "EdDSA wycheproof KAT + roundtrips (Ed25519/Ed448)" caseEddsa
  , testCase "EdDSA keygen mints usable pairs" caseRealEddsaKeygen
  , testCase "ML-DSA wycheproof KAT + roundtrips (44/65/87)" caseMldsa
  , testCase "ML-DSA keygen mints usable pairs" caseRealMldsaKeygen
  , testCase "SLH-DSA ACVP KAT + roundtrips (12 sets)" caseSlhdsa
  , testCase "SLH-DSA keygen mints usable pairs" caseRealSlhdsaKeygen
  , testCase "ML-KEM wycheproof KAT + roundtrips (512/768/1024)" caseMlkem
  , testCase "ML-KEM keygen mints usable pairs" caseRealMlkemKeygen
  , testCase "ECDH agreement KATs (CLI vectors)" caseEcdhVectors
  , testCase "XDH agreement KATs (CLI + wycheproof tc1)" caseXdhVectors
  , testCase "ECDH wrap compositions roundtrip (provider)" caseEcdhCompWrap
  , testCase "RSA wrap composition roundtrips (provider)" caseRsaCompWrap
  , testCase "pub-from-priv re-exports SPKI (provider)" casePubFromPrivProvider
  , testCase "Montgomery keygen mints agreeing pairs" caseRealMontgomeryKeygen
  , testCase "DH agreement KAT (CLI vectors)" caseDhAgree
  , testCase "DH derive keeps a leading zero byte (full width)" caseDhPadLeadingZero
  , testCase "DH keygen mints agreeing pairs" caseDhKeygen
  , testCase "raw-vs-der encodings never convert silently" caseRawVsDer
  , testCase "Symmetric keygen (fresh random bytes)" caseSymKeygen
  , testCase "RSA keygen mints DER halves in bounds" caseRsaKeygen
  , testCase "AES-GCM matches the pinned vector and round-trips" caseAeadReal
  , testCase "AES-GCM empty plaintext with AAD round-trips (tc92)" caseAeadEmptyPlaintext
  , testCase "AES-CCM wycheproof KATs seal and open" caseAeadCcmReal
  , testCase "ChaCha20 matches RFC 8439 2.4.2 (counter 1)" caseChachaReal
  , testCase "ChaCha20-Poly1305 matches RFC 8439 2.8.2" caseChachaPolyReal
  , testCase "Random bytes (fresh DRBG output)" caseRandomBytes
  , testCase "seedRandom mixes, randomBytes unaffected" caseSeedRandomMix
  , testCase "Seed entropy estimate pinned at 0.0" caseSeedEntropyHonesty
  , testCase "OpenSSL reseed never replays (scope pin)" caseSeedNoReplay
  , testCase "unsupported algs rejected without fallback" caseUnsupported
  , testCase "guard runs before any native call" caseGuardBeforeNative
  , testCase "capability report is exactly the supported set" caseCaps
  , testCase "capability report is published fully evaluated" caseCapsEvaluated
  , testCase "static capability table is a normal-form CAF" caseStaticCapsEvaluated
  , testCase "capability notes keep provider and cipher content" caseCapsNotes
  , testCase "private contexts are isolated" caseIsolation
  , testCase "shim has no pkcs11 provider or global cleanup" caseShimHygiene
  , testCase "invalid inputs fail typed, never crash" caseInvalidInputs
  , testCase "digest final consumes exactly once (behavioral)" caseFinalConsumesOnce
  , testCase "lifetime gate: sequential post-close stays typed" caseLifetimeGateSequential
  , testCase "lifetime gate: simultaneous close stays total" caseLifetimeGateSimultaneous
  ]
