{- | OpenSSL 4 engine tests.

Known-answer vectors for SHA-256 (FIPS 180-4),
HMAC-SHA-256 (RFC 4231 case 1), AES-256-CBC (NIST SP 800-38A F.2.5),
and ECDSA P-256/SHA-256 (fixed vector generated with the system
openssl CLI, verified there before embedding). All oracles are
independent of synthetic-engine outputs.

Also: capability-miss rejection without silent fallback (including a
guard-before-native probe on a closed backend), explicit RAW-vs-DER
signature encodings with no silent conversion, private-context
isolation, and shim-hygiene assertions.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSLSpec (spec) where

import Data.Bits (xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Data.List (isInfixOf, stripPrefix, tails)
import qualified Data.Set as Set
import System.Directory (doesFileExist)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Data.Word (Word32)
import Haskoki.Engine.Backend
  ( AeadSpec (..)
  , BackendCaps (..)
  , BackendEnv
  , BackendError (..)
  , CipherCaps (..)
  , CipherSpec (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , DigestCaps (..)
  , EcdhSpec (..)
  , EcSpec (..)
  , EngineResult (..)
  , KemCaps (..)
  , KemSpec (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , KdfCaps (..)
  , MacCaps (..)
  , MacSpec (..)
  , OaepParams (..)
  , PqcKemAlg (..)
  , RsaCipherParams (..)
  , PssParams (..)
  , SigCaps (..)
  , SigSpec (..)
  , generateRandomMaxBytes
  , seedRandomMaxBytes
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.Types (EngineResourceId (..))

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
  , testCase "RSA v1.5 KATs (CLI vectors)" caseRsaKats
  , testCase "RSA-PSS interop (CLI vector)" caseRsaPssVectors
  , testCase "RSA-OAEP interop (CLI vectors)" caseRsaOaepVectors
  , testCase "RSA PKCS#1 v1.5 interop (CLI vector)" caseRsaPkcs1Vectors
  , testCase "ecdsa fixed-vector verify (DER and RAW)" caseEcdsaKat
  , testCase "ecdsa sign/verify roundtrip, both encodings" caseEcdsaRoundtrip
  , testCase "ECDSA curves/digests/raw (CLI vectors)" caseEcdsaCurvesVectors
  , testCase "ECDSA off-curve keys refused typed" caseEcdsaOffCurve
  , testCase "ECDH agreement KATs (CLI vectors)" caseEcdhVectors
  , testCase "raw-vs-der encodings never convert silently" caseRawVsDer
  , testCase "Symmetric keygen (fresh random bytes)" caseSymKeygen
  , testCase "RSA keygen mints DER halves in bounds" caseRsaKeygen
  , testCase "AES-GCM matches the pinned vector and round-trips" caseAeadReal
  , testCase "AES-GCM empty plaintext with AAD round-trips (tc92)" caseAeadEmptyPlaintext
  , testCase "AES-CCM wycheproof KATs seal and open" caseAeadCcmReal
  , testCase "Random bytes (fresh DRBG output)" caseRandomBytes
  , testCase "seedRandom mixes, randomBytes unaffected" caseSeedRandomMix
  , testCase "Seed entropy estimate pinned at 0.0" caseSeedEntropyHonesty
  , testCase "OpenSSL reseed never replays (scope pin)" caseSeedNoReplay
  , testCase "unsupported algs rejected without fallback" caseUnsupported
  , testCase "guard runs before any native call" caseGuardBeforeNative
  , testCase "capability report is exactly the supported set" caseCaps
  , testCase "private contexts are isolated" caseIsolation
  , testCase "shim has no pkcs11 provider or global cleanup" caseShimHygiene
  , testCase "invalid inputs fail typed, never crash" caseInvalidInputs
  ]

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- | Decode a hex string (whitespace-tolerant).
hex :: String -> ByteString
hex s =
  let h = filter isHexDigit s
  in BS.pack (go h)
  where
    go [] = []
    go (a:b:rest) =
      fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

withBackend :: (BackendEnv OpenSSL4 -> IO ()) -> IO ()
withBackend action = do
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk env -> action env >> closeBackend env

expectOk :: (Eq a, Show a) => String -> EngineResult a -> IO a
expectOk label r = case r of
  EngineOk a -> pure a
  EngineFail err -> assertFailure (label ++ ": expected EngineOk, got " ++ show err)

expectUnsupported :: Show a => String -> EngineResult a -> IO ()
expectUnsupported label r = case r of
  EngineFail (BackendUnsupported _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendUnsupported, got " ++ show other)

expectAuthFailed :: Show a => String -> EngineResult a -> IO ()
expectAuthFailed label r = case r of
  EngineFail (BackendAuthFailed _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendAuthFailed, got " ++ show other)

expectBadParam :: Show a => String -> EngineResult a -> IO ()
expectBadParam label r = case r of
  EngineFail (BackendBadParam _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendBadParam, got " ++ show other)

expectBadKey :: Show a => String -> EngineResult a -> IO ()
expectBadKey label r = case r of
  EngineFail (BackendBadKey _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendBadKey, got " ++ show other)

-- ---------------------------------------------------------------------------
-- Known-answer fixtures (independent oracles, see module header)
-- ---------------------------------------------------------------------------

-- FIPS 180-4 §B.1 / §B.2.
sha256Abc :: ByteString
sha256Abc = hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

sha256Empty :: ByteString
sha256Empty = hex "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

sha256Long :: ByteString
sha256Long = hex "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

longMsg :: ByteString
longMsg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

-- RFC 4231 test case 1: key = 0x0b * 20, data = "Hi There".
hmacKey1 :: ByteString
hmacKey1 = BS.replicate 20 0x0b

hmacMsg1 :: ByteString
hmacMsg1 = "Hi There"

hmacOut1 :: ByteString
hmacOut1 = hex "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

-- NIST SP 800-38A F.2.5 AES-256-CBC, first block.
aes256Key :: ByteString
aes256Key = hex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

aes256Iv :: ByteString
aes256Iv = hex "000102030405060708090a0b0c0d0e0f"

aes256Pt :: ByteString
aes256Pt = hex "6bc1bee22e409f96e93d7e117393172a"

aes256Ct :: ByteString
aes256Ct = hex "f58c4c04d6e5f1ba779eabfb5f7bfbd6"

-- NIST SP 800-38A F.1/F.2 AES rows (128/192 CBC+ECB, 256
-- ECB; 256 CBC is caseAesKat). Generated on the pinned 4.0.2 CLI,
-- cross-checked byte-identical on the system 3.5.5 CLI.
aes128Key :: ByteString
aes128Key = hex "2b7e151628aed2a6abf7158809cf4f3c"

aes192Key :: ByteString
aes192Key = hex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"

aes128CbcCt, aes128EcbCt, aes192CbcCt, aes192EcbCt, aes256EcbCt :: ByteString
aes128CbcCt = hex "7649abac8119b246cee98e9b12e9197d"
aes128EcbCt = hex "3ad77bb40d7a3660a89ecaf32466ef97"
aes192CbcCt = hex "4f021db243bc633d7178183a9fa071e8"
aes192EcbCt = hex "bd334f1d6e45f25ff712a214571fa5cc"
aes256EcbCt = hex "f3eed1bdb5d2a03c064b5a7e3db181f8"

-- NIST SP 800-38A F.5 CTR rows (128/192/256): the shared
-- four-block plaintext and initial counter plus the per-width
-- ciphertexts, transcribed from the PDF and cross-checked with
-- Python cryptography.
ctrPt, ctrIcb :: ByteString
ctrPt = hex $ "6bc1bee22e409f96e93d7e117393172a"
  <> "ae2d8a571e03ac9c9eb76fac45af8e51"
  <> "30c81c46a35ce411e5fbc1191a0a52ef"
  <> "f69f2445df4f9b17ad2b417be66c3710"
ctrIcb = hex "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

aes128CtrCt, aes192CtrCt, aes256CtrCt :: ByteString
aes128CtrCt = hex $ "874d6191b620e3261bef6864990db6ce"
  <> "9806f66b7970fdff8617187bb9fffdff"
  <> "5ae4df3edbd5d35e5b4f09020db03eab"
  <> "1e031dda2fbe03d1792170a0f3009cee"
aes192CtrCt = hex $ "1abc932417521ca24f2b0459fe7e6e0b"
  <> "090339ec0aa6faefd5ccc2c6f4ce8e94"
  <> "1e36b26bd1ebc670d1bd1d665620abf7"
  <> "4f78a7f6d29809585a97daec58c6b050"
aes256CtrCt = hex $ "601ec313775789a5b7a7f504bbf3d228"
  <> "f443e3ca4d62b59aca84e990cacaf5c5"
  <> "2b0930daa23de94ce87017ba2d84988d"
  <> "dfc9c58db67aada613c2dd08457941a6"

-- Triple-DES MMT row (K1 = K3, so the 24-byte key doubles
-- as the two-key expansion target): zero block -> 08d7b4fb629d0885;
-- CBC with the zero IV equals ECB. Agreed on both CLIs.
des3Key24 :: ByteString
des3Key24 = hex "0123456789abcdeffedcba98765432100123456789abcdef"

des3Key16 :: ByteString
des3Key16 = hex "0123456789abcdeffedcba9876543210"

des3Pt, des3Iv, des3Ct :: ByteString
des3Pt = hex "0000000000000000"
des3Iv = hex "0000000000000000"
des3Ct = hex "08d7b4fb629d0885"

-- ARIA/CAMELLIA rows (sequential key bytes, RFC-style
-- plaintext). Pinned 4.0.2 CLI, cross-checked byte-identical on the
-- system 3.5.5 CLI.
ariaPt, ariaIv :: ByteString
ariaPt = hex "00112233445566778899aabbccddeeff"
ariaIv = hex "000102030405060708090a0b0c0d0e0f"

ariaKey128, ariaKey192, ariaKey256 :: ByteString
ariaKey128 = hex "000102030405060708090a0b0c0d0e0f"
ariaKey192 = hex "000102030405060708090a0b0c0d0e0f1011121314151617"
ariaKey256 = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

aria128CbcCt, aria128EcbCt, aria192CbcCt, aria192EcbCt, aria256CbcCt, aria256EcbCt :: ByteString
aria128CbcCt = hex "d87ae512c018266fcd74ddf801efabf9"
aria128EcbCt = hex "d718fbd6ab644c739da95f3be6451778"
aria192CbcCt = hex "b22cdd3ca4ee4d8da19777c93d930eb9"
aria192EcbCt = hex "26449c1805dbe7aa25a468ce263a9e79"
aria256CbcCt = hex "06ad7356394a53e875c70ba8ab0d49d5"
aria256EcbCt = hex "f92bd7c79fb72e2f2b8f80c1972d24fc"

cam128CbcCt, cam128EcbCt, cam192CbcCt, cam192EcbCt, cam256CbcCt, cam256EcbCt :: ByteString
cam128CbcCt = hex "94887caa8b90cd132d9aa972db3e52bb"
cam128EcbCt = hex "77cf412067af8270613529149919546f"
cam192CbcCt = hex "a0a022e9de176eaaec0bcab1ad5f6e9d"
cam192EcbCt = hex "b22f3c36b72d31329eee8addc2906c68"
cam256CbcCt = hex "cd3f05325b834e2bd83510993ca53afb"
cam256EcbCt = hex "2edf1f3418d53b88841fc8985fb1ecf2"

-- ECDSA P-256/SHA-256 fixed vector (system openssl CLI 3.5.5, Verified OK
-- there before embedding; independent of this backend).
ecMsg :: ByteString
ecMsg = hex "543037206563647361206b6174206d657373616765"

ecPrivDer :: ByteString
ecPrivDer = hex "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e9032e4f06ee6b5397252cfb48e73a8d3f7717d4024dd4cc5b98bbf041c11bb3a14403420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"

ecPubDer :: ByteString
ecPubDer = hex "3059301306072a8648ce3d020106082a8648ce3d03010703420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"

ecSigDer :: ByteString
ecSigDer = hex "3045022100debdbb00072c928d38bf43791d32f0eefe8a562d8444869adabdf77820cbed49022063cc0a678a74c3e006c7387907210825f12920ff5f15b96709291e48b84ddc21"

ecSigRaw :: ByteString
ecSigRaw = hex "debdbb00072c928d38bf43791d32f0eefe8a562d8444869adabdf77820cbed4963cc0a678a74c3e006c7387907210825f12920ff5f15b96709291e48b84ddc21"

-- RSA-2048 fixed vector (pinned 4.0.2 CLI genpkey; PKCS#8 +
-- SPKI DER). The SHA-256 signature is `dgst -sha256 -sign` output and
-- the raw signature is `pkeyutl -sign` (PKCS#1 block type 1) output,
-- both Verified OK on the CLI before embedding; independent of this
-- backend.
rsaPrivDer :: ByteString
rsaPrivDer = hex $ concat
  [ "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201"
  , "000282010100c926e2edfdfd3886e1b3cc75c224421b0fc2deeb1f780943d23a"
  , "39698d4f6944cffda2957fb8aa9f70e410231e4fb89dfe370fce96515fcb2093"
  , "d512c4603632a6b83d2c42144a53138113ba96442c63311f8b8fc6b2b4424831"
  , "979b94f5e2929a0c2c9f2b4b17f713b394546faaa1c0e65cb87911cb244af772"
  , "5b894f6f27d059d6e9e9c761032577912bfc1eccac593d0df649ec03e2fc13fe"
  , "723c268c1ecfa63c80b3dcf04ee18c758189567f753fa6f936f926347632f18e"
  , "4d4b1252539235ae4929f72b990ebb78db7159f6779cffe23e96ca1908babc51"
  , "34c424688d37eadaf126bd94fd108ac4415e4503ff2e6d125cd5c762a3fbe6ec"
  , "ae8e2a76011102030100010282010009c28c237bcdc9ecba7e0ebb3e7da3a2fc"
  , "416a6f4a5e38c5dc891470cf89553c6062a83d3c7e9d71c1c8a1135124d15a82"
  , "23920de62b81dc416306e54397befd776b2c55adc99dff18accc4423072107b9"
  , "9214239862a29e2e3250cebcdc2edf89dfb2191180d1e37c465bf9ba56d34520"
  , "b04a479e92469b2815398588b006248edc33d6ca1867543f7ae188e38c2d6b05"
  , "34711b1320e3ba0bba97d39b36a581927deb148d0deef6ea2627a2a91fe8b408"
  , "1062e726ed764788eec572b38bc86ad158a1d04b1c35aca6ae1270e05c137c2d"
  , "38d9762cbe4b06d07c87f038608a96b9efac090a08175207eaf2393cd0a2d301"
  , "9dd5102bb1a21554dd416f6a316f0102818100fa935980bc731d39e87d225964"
  , "017bfefcd827a3d43126fa1426efb9dcfb8e693030dd4aadeaa9b977611b747e"
  , "7993f5b78e9358e58b2442cdb8f038d466cfc28d0af579e12adc781abdbedc97"
  , "7d1b5a2bd547506441e622ff73bba38c7097d464adf8169e8df412a7a5d65c4b"
  , "405884590388ee4625c3f2e2e7679b963cb48102818100cd81a378890e9c224c"
  , "660acd28f0edd17b17f1cf0068a6185d13bbef2383e303258ccb79ad37899344"
  , "7126397e57e8e19e26ed0b6e20d338ab4d092548374b5e3e909dcf59416e46eb"
  , "0f7e1e5efe01cd4ae55f49856430cdb230bb9861b9fdd72b5f6c265da17a6f78"
  , "f3f5acd3b9a30cdd46bc279b7fa72679a4b4b1b361c49102818048d9fa55b174"
  , "8e74bda154114540213adb6c44ea1ed14391c5b62450976d13d4854c4faa5cb2"
  , "3332570106a871f50b0d8f9686447c485dfc862f54b85118ab22d73aee6fc705"
  , "5d201636407d8615bb9415d6666b7b1aa5bc5b24dcd30a0bda38c824c4525f3a"
  , "ca517a287f104a58a4e3a5b59f641744f799705af3068b418f0102818015a7c5"
  , "8c1c15380abd363b8926f94c76389c6b54bedc4834650a81514fd2c4073edbb9"
  , "4d571d7517d9ac7ab4b0459f3ab729aeecf76bea161ca6ff81b83c6b6ac0f908"
  , "482345abd3394de6a258ac379064860b267a31f69a965e60464c7606f3b79454"
  , "972e62a7be3b66a9cace7ccf5bb9ad8c8237f699ac8a40faf186cf94a1028180"
  , "4a51ff546c065beff7c5e653db4011aa3989470826473c6afb0eca603fd4109a"
  , "6d731fac84d8d1c0647f1a2d8e68246449eb18ef6ef433f654785f9713798c85"
  , "4a10352d4db6aa28fb9ec13d0772dec7ebd1b1c3faa5979672bad3c6be7c45e0"
  , "82b79fcbc58b7d39abed53870ec5efb62b66c52da906950afcd7117007b99f7d"
  ]

rsaPubDer :: ByteString
rsaPubDer = hex $ concat
  [ "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
  , "00c926e2edfdfd3886e1b3cc75c224421b0fc2deeb1f780943d23a39698d4f69"
  , "44cffda2957fb8aa9f70e410231e4fb89dfe370fce96515fcb2093d512c46036"
  , "32a6b83d2c42144a53138113ba96442c63311f8b8fc6b2b4424831979b94f5e2"
  , "929a0c2c9f2b4b17f713b394546faaa1c0e65cb87911cb244af7725b894f6f27"
  , "d059d6e9e9c761032577912bfc1eccac593d0df649ec03e2fc13fe723c268c1e"
  , "cfa63c80b3dcf04ee18c758189567f753fa6f936f926347632f18e4d4b125253"
  , "9235ae4929f72b990ebb78db7159f6779cffe23e96ca1908babc5134c424688d"
  , "37eadaf126bd94fd108ac4415e4503ff2e6d125cd5c762a3fbe6ecae8e2a7601"
  , "110203010001"
  ]

rsaMsg :: ByteString
rsaMsg = "T16 S7 RSA PKCS#1 v1.5 KAT message"

rsaSig256 :: ByteString
rsaSig256 = hex $ concat
  [ "1a688970cd06fcbd04ca437952ea041cb952a0022698c4d77358cafccaf2490f"
  , "ddaf1b854bc40d854710d203e689b1f1422ae7669ea9ae8b5bac74e8762e3eae"
  , "bc916f66b052e369753b7fa27f44d0f5a762481a19ad4c078b11fecc66ce5b70"
  , "28152c1fbc4d750f81e58d3c9763f000b2a7cd10291127c2e85a8aa5ae6b31cf"
  , "286197885eea82b768e12588e2e386aa7ff1ecdcf3746480d73335e716ca779b"
  , "3bf45729506c742d3b860d5f6473f54a2afa6e0c6dae9bebeed2874e3f7c698a"
  , "c997d4af99317d4361e5e80d538a7551ada520d9ec4f8a90ecbc88f87866888c"
  , "cac430db724c03347f2470b65f9db3dcd42bdbd3bf00fce8dd311f0230e5ca96"
  ]

rsaRawMsg :: ByteString
rsaRawMsg = "raw-rsa-pkcs1-input"

rsaRawSig :: ByteString
rsaRawSig = hex $ concat
  [ "28d1e96dee36cacc910b992a1205c1c6328e224e15cde51a2e5c48f96f2549a0"
  , "8702edd609d00f5597b35b81a9edfa67f7a2177e79b8785f046773e22c9b613b"
  , "9073a0ca88888dacd83486660c370b513810d0e262a2ece08bcd7f47be2fcd76"
  , "2231e521dd5adde4668143c5151b7d38c4ee2f4360c62c76d1d2c787a7eca502"
  , "3f991c6cd81d36778ec1d57006f6be5f08782559cc6b2bd35ae784d0742521b7"
  , "8a90020f082b07be789468f2861660053f2c2026dfb84ce193b6f53d2e67d040"
  , "dfe9a1cc352af6c8449daa5d0bd83e201e622bcb663cf3cb84bf491a45974142"
  , "6159d1f203f89db9f9e790b16837254f81f87bf59c4e55bdea4ac6de3b8a5ffc"
  ]

-- PSS/OAEP interop vectors (pinned 4.0.2 CLI, same RSA-2048
-- key as the v1.5 vectors). PSS is randomized, so the suite verifies
-- the CLI's bytes (proving interop) and roundtrips its own; OAEP
-- likewise. All three vectors were CLI-verified before embedding.
pssMsg :: ByteString
pssMsg = "T16 S8 RSA-PSS KAT message"

pssSig256 :: ByteString
pssSig256 = hex $ concat
  [ "a485e83b8a92370e6b770164476f3f8154f59aa95616100eb0d79d333d080a18"
  , "e346d063dc2600f91bad8ec68c55de62e6b4cce8478284ef8f6822d9f3e40355"
  , "2c658e40a67f6dc68e1d7075c4ee42fc021851809b264a6811859a462347f060"
  , "b219b7b4e42065146008062e78684d4dff08ba80c46b9243c6ed47bca6c8d766"
  , "bd97dd87577410690fd98bbef29c07a5a6f90044b967e04a736bb18b500ece12"
  , "1d175ebae0e64927af63753ff906df57cf99609794483f054b4e12874df6cbde"
  , "243e1cbb4796c1dc338686695aab96ca6f48015af476da7482055e2c969dfc46"
  , "7538fdffa5ed548c66ebd18413b565c967ea033a79fb8ca4fd69233851d5d3d7"
  ]

oaepMsg :: ByteString
oaepMsg = "oaep-secret-32-bytes-payload!!!!"

oaepCt256 :: ByteString
oaepCt256 = hex $ concat
  [ "c8487aa483b4807c96df59d7d7cba952026c0af0ae9b1e34bb2df9cf86990866"
  , "de54bed6a552bc48d9fc3460f3e72666206b154c1dd213a94cb9810cf2861f1b"
  , "413c03124cc51f3f049154887e9d704ebb1d3aebbd508529ce91c9a73eef04e0"
  , "0e701e7bad72f97714ecde22bcc491228f8ca831e7fb22a570747362eea7a204"
  , "054315fc13a1074c3221c8c125e2a8cd6f2c1636b7e012c0afbbef48681f076d"
  , "cbe2c2a894afe2a0a16bc7d4f0df9a329c395aee38cd05b771748b3647c2ded7"
  , "cce302721f6a674ef9c864682dfc3c7b0ab92ef00347435c7b2a55173fbae7c2"
  , "087096ad95fb3c77b495699fb8d8a51b212cd9197265f684eb834302ac09a8ea"
  ]

oaepCtLabel :: ByteString
oaepCtLabel = hex $ concat
  [ "8731edc179823659994212b26301adfff66b3f2371d79640d2b9ec4100d47e9c"
  , "e4c047373deefa92d8cca0000c26259d7471441b966e9e85d78215e96324e5ca"
  , "372639a789c4162108dcaa177ff26760f3f0b19dd0ae05fb2824819576eadc77"
  , "8219912a2cb5f4ee76ba2ad27a68b6f283636f1b04ca7dc87b2009ea41e4247a"
  , "48ba0615ce5f5fb6932bcca6aaed9ebd79d9b0ba7d40c4128bfcda1ee60fb718"
  , "da7c783d3d1bf59391eef1a6f30cd5be6c7d0e1fd32d7fbf57629e60ea43a250"
  , "de38228fb7cb7d016cd64710c4b9485cbb336abca3699e0f11ebde8c57889940"
  , "20a2a3e03dfb241ff23d76351f9bbdd6e7e292e02fdd6c19d967b4f904187e73"
  ]

-- PKCS#1 v1.5 interop vector (pinned 4.0.2 CLI, same RSA-2048 key
-- as the OAEP vectors): @pkeyutl -encrypt -pkeyopt
-- rsa_padding_mode:pkcs1@ over 'pkcs1Msg'. The CLI decrypted the
-- same bytes back before embedding.
pkcs1Msg :: ByteString
pkcs1Msg = "pkcs1-v15-secret-payload"

pkcs1Ct :: ByteString
pkcs1Ct = hex $ concat
  [ "95c544fce5a8a92aa7ce3e2cd4c3b8f1f73ef2bab790f7b47bd68b0f852e6390"
  , "59beca2d3d9c755880b5665f0b86384bd8fd993516f09a19e2ef47d526d781dc"
  , "a9f28eac278cb5ac6cd4582013f0b48e415a5ce8a8f1d4f6374fcd755a9c8239"
  , "f9c3df96be044a3fb21de404b0b4dae2981bfad77af50b763e290f5e4308e7ff"
  , "cc9e950f9d1cff829df9ca2d9a21b01472b7eaab505cf05771c5f22a2823690b"
  , "1c2c70892cb74fab75f105b83ff22f36a39023a41dd916190f8b3df30b9caf90"
  , "e7827d13d4672a3315f854598b385cdcceac5d1c0b486d5c6010d74489858a06"
  , "eeeeefebddf38af708eb71fbec554aa5c8f5f0163c6a9f470f8d8af53f7f7bf4"
  ]

-- P-384/SHA-384, P-521/SHA-512, and raw-P-256 interop
-- vectors (pinned 4.0.2 CLI; the raw vector reuses the P-256 key from
-- the fixtures above). ECDSA is randomized, so the suite verifies the
-- CLI's bytes (proving interop) and roundtrips its own. All vectors
-- were CLI-verified before embedding.
ecMsg384 :: ByteString
ecMsg384 = "T16 S9 ECDSA P-384/SHA384 message"

ecP384Pub :: ByteString
ecP384Pub = hex $ concat
  [ "3076301006072a8648ce3d020106052b8104002203620004467ab2e9c927f143"
  , "e9f6151006e492da4d11c9e079e339f6086dfd988bd0cac51e25adf31d504a7c"
  , "730a94c1c4b3bb880cffcceaf56ebc0c1a42e04051e8d11e409440f6a4924c1c"
  , "fea44e8858601cd2a041d7340fe670712e91ca3ec5389a0c"
  ]

ecSig384 :: ByteString
ecSig384 = hex $ concat
  [ "306502301745214d2dd601618123d12577281adfd877401da97434930c6be638"
  , "71069f00aa881a2c7552d1a6cd11964d962d35ec0231009aa7912604646cd498"
  , "08da3a73f279d55a4000bc3ab2f60ee9fc84be326142d18e50efadccac7a38a7"
  , "90846dda3abddd"
  ]

ecMsg521 :: ByteString
ecMsg521 = "T16 S9 ECDSA P-521/SHA512 message"

ecP521Pub :: ByteString
ecP521Pub = hex $ concat
  [ "30819b301006072a8648ce3d020106052b810400230381860004019eed1a84c8"
  , "46d69d26a869d864b0d1bf557cc7320ce1d8018f22f3b963f6b4c136b38d44c8"
  , "cb2e21218e96f93aa82459dfb186d80fe06db19cc3c49989e1da9c1701a68897"
  , "45283941b46bb94ab6f59ad10786191c910aa0183b702b25cd18de9afa573180"
  , "5cab4f7e3309226b19e397fbaed8b54a03e2e9e1e79ec3862f0ca47a1fc9"
  ]

ecSig521 :: ByteString
ecSig521 = hex $ concat
  [ "30818702410b6ed9ef58252d7628e1da101ce8d563ee4958740c9420407bdeaa"
  , "2d9ebe7b3e8fc7d32c21fe434dfde0975955dd86d1175a7e8aeb0bc4f5cc42ef"
  , "5bd3ccdce926024201650e92bc9c37d7b2a71309cad43ab170ecc530ab1696d8"
  , "b674246e5275205b60c260f59c00ca96a0dadbd9e180d76a2592ffeb2eb6d8eb"
  , "d43f0e6def4440fe9a46"
  ]

ecRaw32 :: ByteString
ecRaw32 = hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

ecRawSig :: ByteString
ecRawSig = hex $ concat
  [ "304502200c0b980a724edb395232d3fe7434d0ff85c10ee8db983fc5ca245d67"
  , "5d6337c7022100f446a1b647aa0fc78ed12dab16076692a4128980fdbba6f874"
  , "997a935c1219b3"
  ]

-- | Off-set-curve fixtures: a well-formed brainpoolP160r1 key
-- pair (CLI genpkey; curve OID @1.3.36.3.3.2.8.1.1.1@ — real but
-- uncollected, so outside the covered set). The real backend must
-- refuse these with 'BackendBadKey' — never execute past the
-- advertised cap set.
ecBp160Priv, ecBp160Pub :: ByteString
ecBp160Priv = hex $ concat
  [ "305402010104148b826497e301a31d83e16a10c7ba9070fd6e5bf6a00b0609"
  , "2b2403030208010101a12c032a0004e471b91d45036f84037b7e2c3804348be"
  , "1455d93662b6814bfeb22a8acb58b5ae6f583f2a0de1081"
  ]
ecBp160Pub = hex $ concat
  [ "3042301406072a8648ce3d020106092b2403030208010101032a0004e471b91d"
  , "45036f84037b7e2c3804348be1455d93662b6814bfeb22a8acb58b5ae6f583f2"
  , "a0de1081"
  ]

-- | S10 ECDH KAT fixtures: two fresh P-256 pairs plus one P-384 pair
-- (pinned-CLI genpkey); the secrets are pinned-CLI @pkeyutl -derive@
-- output (A->B and B->A agree; cofactor mode agrees on P-256, h=1).
ecdhPrivA, ecdhPubA, ecdhPrivB, ecdhPubB :: ByteString
ecdhPrivA = hex $ concat
  [ "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
  , "01010420311c1de45b711a6ba76e060470e0db863ac2b9ff60a44db447fc70360"
  , "eaa5ef6a1440342000448ac633084fc453d57a59703893c48f26d1eefd067c1f8"
  , "e69382565b21bf3a2e6dc574e35285f5dd6028eb00471de54d74e3de18a1f9a8a"
  , "280081e7ccec47e98"
  ]
ecdhPubA = hex $ concat
  [ "3059301306072a8648ce3d020106082a8648ce3d0301070342000448ac633084"
  , "fc453d57a59703893c48f26d1eefd067c1f8e69382565b21bf3a2e6dc574e35285"
  , "f5dd6028eb00471de54d74e3de18a1f9a8a280081e7ccec47e98"
  ]
ecdhPrivB = hex $ concat
  [ "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
  , "0101042087762e6a31210036b5e0cf9af7e2703f31c84916b9df67b4f062f3021"
  , "991d835a144034200043bb6f938a377952e614445d9933c97d15a76d94d1ef9d8"
  , "bafb02ac3cda56ee209e5d0221a899cf628c9cef305fe1a14f3af46e0c7ac2be8"
  , "b68e0e2707d9225e1"
  ]
ecdhPubB = hex $ concat
  [ "3059301306072a8648ce3d020106082a8648ce3d030107034200043bb6f938a3"
  , "77952e614445d9933c97d15a76d94d1ef9d8bafb02ac3cda56ee209e5d0221a89"
  , "9cf628c9cef305fe1a14f3af46e0c7ac2be8b68e0e2707d9225e1"
  ]
ecdhPrivC, ecdhPubC, ecdhSecretAB, ecdhSecretCC :: ByteString
ecdhPrivC = hex $ concat
  [ "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010"
  , "104302adb33390dd6fbfc9522bade688cb1ef2960f2bd7fe0c29a87153357e7f7"
  , "aaf44c2efda7eccd10cca7a8d117f49de506a16403620004adce07c5ce4996c1c"
  , "3b5561a7e2ef688d0c046d473ab6676a2e472c096e24d923304f955b099b1ca6d"
  , "9fd414a536e90b6f30acb85c0f74e539ee2905d574ac7b7a918172d8f7c075e833"
  , "3883b626a7a74649dda234ed7694f4332d4be4f227cf"
  ]
ecdhPubC = hex $ concat
  [ "3076301006072a8648ce3d020106052b8104002203620004adce07c5ce4996c1"
  , "c3b5561a7e2ef688d0c046d473ab6676a2e472c096e24d923304f955b099b1ca6d"
  , "9fd414a536e90b6f30acb85c0f74e539ee2905d574ac7b7a918172d8f7c075e833"
  , "3883b626a7a74649dda234ed7694f4332d4be4f227cf"
  ]
ecdhSecretAB = hex "9671ac43cbf5d68893022679b588483c63cdd6e370ae62c81d4ce95d9eae7b05"
ecdhSecretCC = hex "6c0636f7c3858a26c97f7215f27f7a5a952ac99513c70ee3ea54386dad9ff3e50f9eb0004242035779c505284316e9c0"

-- | Tiny DER ECDSA-signature parser: SEQUENCE { INTEGER r, INTEGER s }.
-- Independent of the backend's own conversion; used to cross-check
-- RAW (r || s) against DER on the same signature bytes.
-- | Minimal DER ECDSA-signature parser for cross-checks: the
-- coordinate length is the caller's curve half-width (32/48/66).
-- P-384/P-521 signatures use long-form lengths, so both length
-- forms parse.
parseDerEcdsa :: Int -> ByteString -> Maybe (ByteString, ByteString)
parseDerEcdsa coordLen der = do
  (seqBody, rest0) <- takeTLV 0x30 der
  if not (BS.null rest0) then Nothing else do
    (r, rest1) <- takeTLV 0x02 seqBody
    (s, rest2) <- takeTLV 0x02 rest1
    if not (BS.null rest2) then Nothing else pure (stripInt r, stripInt s)
  where
    takeTLV :: Int -> ByteString -> Maybe (ByteString, ByteString)
    takeTLV tag bs = case BS.uncons bs of
      Just (t, r0)
        | fromIntegral t == tag -> case BS.uncons r0 of
            Just (l0, r1)
              | l0 < 0x80 ->
                  let n = fromIntegral l0
                  in Just (BS.take n r1, BS.drop n r1)
              | l0 == 0x81 -> case BS.uncons r1 of
                  Just (n, r2) ->
                    let k = fromIntegral n
                    in Just (BS.take k r2, BS.drop k r2)
                  _ -> Nothing
              | l0 == 0x82 -> case (BS.uncons r1 >>= \(h, tl) -> BS.uncons tl >>= \(l, u) -> Just (h, l, u)) of
                  Just (h, l, r2) ->
                    let k = fromIntegral h * 256 + fromIntegral l
                    in Just (BS.take k r2, BS.drop k r2)
                  _ -> Nothing
              | otherwise -> Nothing
            _ -> Nothing
      _ -> Nothing
    stripInt bs =
      let s = BS.dropWhile (== 0) bs
      in BS.dropWhile (== 0) (if BS.length s > coordLen then BS.drop (BS.length s - coordLen) s else s)

pad32 :: ByteString -> ByteString
pad32 bs = BS.replicate (32 - BS.length bs) 0 <> bs

-- ---------------------------------------------------------------------------
-- Cases
-- ---------------------------------------------------------------------------

caseSha256Kat :: IO ()
caseSha256Kat = withBackend $ \env -> do
  d1 <- expectOk "sha256(abc)" =<< digestOneShot env D_SHA256 "abc"
  assertEqual "sha256(abc)" sha256Abc d1
  d2 <- expectOk "sha256(empty)" =<< digestOneShot env D_SHA256 BS.empty
  assertEqual "sha256(empty)" sha256Empty d2
  d3 <- expectOk "sha256(long)" =<< digestOneShot env D_SHA256 longMsg
  assertEqual "sha256(long)" sha256Long d3
  -- Independent of synthetic outputs: synthetic digest is 32 bytes but
  -- never these values (spot-check the first vector differs from the
  -- synthetic construction only by trusting the FIPS oracle here).
  assertBool "non-empty digest" (BS.length d1 == 32)

-- | Digest "abc" vectors, each independently verified against
-- the pinned @/opt/openssl-4.0.2/bin/openssl dgst@ CLI on 2026-09-21
-- and citing its standard: FIPS 180-4 (SHA-1/SHA-2), FIPS 202
-- (SHA-3), RFC 1321 A.5 (MD5), the RIPEMD-160 test suite.
digestKats :: [(DigestAlg, String, ByteString)]
digestKats =
  [ (D_MD5, "RFC1321", hex "900150983cd24fb0d6963f7d28e17f72")
  , (D_SHA1, "FIPS180-4", hex "a9993e364706816aba3e25717850c26c9cd0d89d")
  , (D_SHA224, "FIPS180-4", hex "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
  , (D_SHA384, "FIPS180-4", hex "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
  , (D_SHA512, "FIPS180-4", hex "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
  , (D_SHA512_224, "FIPS180-4", hex "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa")
  , (D_SHA512_256, "FIPS180-4", hex "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23")
  , (D_SHA3_224, "FIPS202", hex "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")
  , (D_SHA3_256, "FIPS202", hex "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
  , (D_SHA3_384, "FIPS202", hex "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25")
  , (D_SHA3_512, "FIPS202", hex "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")
  , (D_RIPEMD160, "RIPEMD160", hex "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
  ]

caseDigestKats :: IO ()
caseDigestKats = withBackend $ \env -> do
  -- SHA-256 KATs live in caseSha256Kat; every other recipe alg here.
  mapM_ (\(alg, src, want) -> do
    d <- expectOk (show alg ++ " abc") =<< digestOneShot env alg "abc"
    assertEqual (show alg ++ " KAT " ++ src) want d
    assertEqual (show alg ++ " width") (BS.length want) (BS.length d)) digestKats

caseSha384Multipart :: IO ()
caseSha384Multipart = withBackend $ \env -> do
  -- Multipart honors the init alg for every recipe alg: multipart
  -- output equals one-shot output (KAT equality per alg lives in
  -- caseDigestKats; SHA-256 multipart in caseSha256Multipart).
  mapM_ (checkAlg env)
    [ D_MD5, D_SHA1, D_SHA224, D_SHA384, D_SHA512
    , D_SHA512_224, D_SHA512_256
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    , D_RIPEMD160
    ]
  where
    checkAlg e alg = do
      rid <- expectOk ("init " ++ show alg) =<< digestInit e alg
      expectOk "update(a)" =<< digestUpdate e rid "a"
      expectOk "update(bc)" =<< digestUpdate e rid "bc"
      d <- expectOk "final" =<< digestFinal e rid
      one <- expectOk "one-shot" =<< digestOneShot e alg "abc"
      assertEqual ("multipart == one-shot " ++ show alg) one d

caseSha256Multipart :: IO ()
caseSha256Multipart = withBackend $ \env -> do
  rid <- expectOk "digestInit" =<< digestInit env D_SHA256
  expectOk "update(a)" =<< digestUpdate env rid "a"
  expectOk "update(bc)" =<< digestUpdate env rid "bc"
  d <- expectOk "digestFinal" =<< digestFinal env rid
  assertEqual "multipart == one-shot" sha256Abc d
  one <- expectOk "one-shot" =<< digestOneShot env D_SHA256 "abc"
  assertEqual "multipart matches one-shot" one d

caseHmacKat :: IO ()
caseHmacKat = withBackend $ \env -> do
  let spec' = MacHMAC { macDigest = D_SHA256, macTruncLen = Nothing }
  t <- expectOk "hmac kat" =<< macSign env spec' (KeyBytes hmacKey1) hmacMsg1
  assertEqual "rfc4231 case 1" hmacOut1 t

-- | HMAC known answers over the shared RFC 4231 case-1 key
-- ('hmacKey1', 20x0x0b) and message ('hmacMsg1', "Hi There").
-- SHA-1/SHA-2 tags coincide with the RFC 2202/4231 TC1 vectors; MD5
-- (RFC 2202 TC1 uses a 16-byte key), RIPEMD160, and the SHA-3 rows
-- are pinned against the CPython hashlib reference (computed
-- 2026-09-21) and independently cross-checked against the container
-- openssl CLI (3.5.5 mac); the suite itself executes them against
-- the pinned 4.0.2 libcrypto.
hmacKats :: [(DigestAlg, String, ByteString)]
hmacKats =
  [ (D_MD5, "hashlib", hex "5ccec34ea9656392457fa1ac27f08fbc")
  , (D_SHA1, "RFC2202-TC1", hex "b617318655057264e28bc0b6fb378c8ef146be00")
  , (D_SHA224, "RFC4231-TC1", hex "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22")
  , (D_SHA384, "RFC4231-TC1", hex "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")
  , (D_SHA512, "RFC4231-TC1", hex "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
  , (D_SHA512_224, "RFC4231-TC1", hex "b244ba01307c0e7a8ccaad13b1067a4cf6b961fe0c6a20bda3d92039")
  , (D_SHA512_256, "RFC4231-TC1", hex "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab")
  , (D_SHA3_224, "hashlib", hex "3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7")
  , (D_SHA3_256, "hashlib", hex "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb")
  , (D_SHA3_384, "hashlib", hex "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd")
  , (D_SHA3_512, "hashlib", hex "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e")
  , (D_RIPEMD160, "hashlib", hex "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668")
  ]

caseHmacKats :: IO ()
caseHmacKats = withBackend $ \env -> do
  -- SHA-256 KAT lives in caseHmacKat; every other recipe alg here.
  mapM_ (\(alg, src, want) -> do
    t <- expectOk (show alg ++ " hmac") =<< macSign env (MacHMAC alg Nothing) (KeyBytes hmacKey1) hmacMsg1
    assertEqual (show alg ++ " KAT " ++ src) want t
    assertEqual (show alg ++ " width") (BS.length want) (BS.length t)) hmacKats

caseHmacGeneral :: IO ()
caseHmacGeneral = withBackend $ \env -> do
  let key = KeyBytes hmacKey1
  full <- expectOk "full sha256" =<< macSign env (MacHMAC D_SHA256 Nothing) key hmacMsg1
  trunc16 <- expectOk "truncated sha256" =<< macSign env (MacHMAC D_SHA256 (Just 16)) key hmacMsg1
  assertEqual "truncation slices the KAT" (BS.take 16 hmacOut1) trunc16
  assertEqual "full == KAT" hmacOut1 full
  ok <- expectOk "truncated verifies" =<< macVerify env (MacHMAC D_SHA256 (Just 16)) key hmacMsg1 trunc16
  assertBool "truncated roundtrip" ok
  trunc48 <- expectOk "ceiling sha384" =<< macSign env (MacHMAC D_SHA384 (Just 48)) key hmacMsg1
  f48 <- expectOk "full sha384" =<< macSign env (MacHMAC D_SHA384 Nothing) key hmacMsg1
  assertEqual "ceiling == full" f48 trunc48
  -- Out-of-range lengths refuse without fallback.
  expectUnsupported "zero refused" =<< macSign env (MacHMAC D_SHA256 (Just 0)) key hmacMsg1
  expectUnsupported "over-width refused" =<< macSign env (MacHMAC D_SHA256 (Just 33)) key hmacMsg1
  expectUnsupported "shake hmac refused" =<< macSign env (MacHMAC D_SHAKE128 Nothing) key hmacMsg1

caseHmacVerify :: IO ()
caseHmacVerify = withBackend $ \env -> do
  let spec' = MacHMAC { macDigest = D_SHA256, macTruncLen = Nothing }
      key = KeyBytes hmacKey1
  ok <- expectOk "verify good" =<< macVerify env spec' key hmacMsg1 hmacOut1
  assertBool "good tag verifies" ok
  let bad = BS.init hmacOut1 <> BS.singleton (BS.last hmacOut1 + 1)
  expectAuthFailed "verify tampered" =<< macVerify env spec' key hmacMsg1 bad
  expectAuthFailed "verify truncated" =<< macVerify env spec' key hmacMsg1 (BS.take 16 hmacOut1)

caseAesKat :: IO ()
caseAesKat = withBackend $ \env -> do
  let key = KeyBytes aes256Key
  ct <- expectOk "aes encrypt kat"
    =<< cipherEncrypt env C_AES256_CBC key aes256Iv aes256Pt
  assertEqual "sp800-38a f.2.5" aes256Ct ct
  pt <- expectOk "aes decrypt kat"
    =<< cipherDecrypt env C_AES256_CBC key aes256Iv aes256Ct
  assertEqual "decrypt inverts" aes256Pt pt

caseAesRoundtrip :: IO ()
caseAesRoundtrip = withBackend $ \env -> do
  let key = KeyBytes aes256Key
      pt2 = aes256Pt <> aes256Pt -- two blocks
  ct <- expectOk "encrypt 2 blocks" =<< cipherEncrypt env C_AES256_CBC key aes256Iv pt2
  assertEqual "no padding: length preserved" (BS.length pt2) (BS.length ct)
  pt <- expectOk "decrypt 2 blocks" =<< cipherDecrypt env C_AES256_CBC key aes256Iv ct
  assertEqual "roundtrip" pt2 pt
  -- Non-block-aligned input is rejected (padding is never implicit).
  expectBadParam "encrypt misaligned" =<< cipherEncrypt env C_AES256_CBC key aes256Iv "short"
  expectBadParam "decrypt misaligned" =<< cipherDecrypt env C_AES256_CBC key aes256Iv "short!!"
  expectBadParam "bad key length" =<< cipherEncrypt env C_AES256_CBC (KeyBytes "short") aes256Iv aes256Pt
  expectBadParam "bad iv length" =<< cipherEncrypt env C_AES256_CBC key "short" aes256Pt

caseCipherKats :: IO ()
caseCipherKats = withBackend $ \env -> do
  -- AES widths: NIST rows (CBC shares the F.2 IV/PT; ECB is empty-IV).
  katCbc env "aes-128-cbc" C_AES128_CBC aes128Key aes256Iv aes256Pt aes128CbcCt
  katEcb env "aes-128-ecb" C_AES128_ECB aes128Key aes256Pt aes128EcbCt
  katCbc env "aes-192-cbc" C_AES192_CBC aes192Key aes256Iv aes256Pt aes192CbcCt
  katEcb env "aes-192-ecb" C_AES192_ECB aes192Key aes256Pt aes192EcbCt
  katEcb env "aes-256-ecb" C_AES256_ECB aes256Key aes256Pt aes256EcbCt
  -- AES-CTR: the F.5 rows at all widths, plus unaligned stream input.
  katCtr env "aes-128-ctr" C_AES128_CTR aes128Key ctrIcb ctrPt aes128CtrCt
  katCtr env "aes-192-ctr" C_AES192_CTR aes192Key ctrIcb ctrPt aes192CtrCt
  katCtr env "aes-256-ctr" C_AES256_CTR aes256Key ctrIcb ctrPt aes256CtrCt
  ragged <- expectOk "ctr unaligned encrypt" =<<
    cipherEncrypt env C_AES128_CTR (KeyBytes aes128Key) ctrIcb "twenty bytes exactly!!"
  assertEqual "ctr length preserved" 22 (BS.length ragged)
  raggedPt <- expectOk "ctr unaligned decrypt" =<<
    cipherDecrypt env C_AES128_CTR (KeyBytes aes128Key) ctrIcb ragged
  assertEqual "ctr unaligned inverts" "twenty bytes exactly!!" raggedPt
  -- Triple-DES: three-key and two-key (K1 = K3, so both agree).
  katCbc env "des3-cbc" C_DES3_CBC des3Key24 des3Iv des3Pt des3Ct
  katEcb env "des3-ecb" C_DES3_ECB des3Key24 des3Pt des3Ct
  ct16 <- expectOk "des3-cbc two-key encrypt"
    =<< cipherEncrypt env C_DES3_CBC (KeyBytes des3Key16) des3Iv des3Pt
  assertEqual "des3 two-key expands to K1||K2||K1" des3Ct ct16
  -- ARIA/CAMELLIA widths share the key/PT/IV fixtures.
  katCbc env "aria-128-cbc" C_ARIA128_CBC ariaKey128 ariaIv ariaPt aria128CbcCt
  katEcb env "aria-128-ecb" C_ARIA128_ECB ariaKey128 ariaPt aria128EcbCt
  katCbc env "aria-192-cbc" C_ARIA192_CBC ariaKey192 ariaIv ariaPt aria192CbcCt
  katEcb env "aria-192-ecb" C_ARIA192_ECB ariaKey192 ariaPt aria192EcbCt
  katCbc env "aria-256-cbc" C_ARIA256_CBC ariaKey256 ariaIv ariaPt aria256CbcCt
  katEcb env "aria-256-ecb" C_ARIA256_ECB ariaKey256 ariaPt aria256EcbCt
  katCbc env "camellia-128-cbc" C_CAMELLIA128_CBC ariaKey128 ariaIv ariaPt cam128CbcCt
  katEcb env "camellia-128-ecb" C_CAMELLIA128_ECB ariaKey128 ariaPt cam128EcbCt
  katCbc env "camellia-192-cbc" C_CAMELLIA192_CBC ariaKey192 ariaIv ariaPt cam192CbcCt
  katEcb env "camellia-192-ecb" C_CAMELLIA192_ECB ariaKey192 ariaPt cam192EcbCt
  katCbc env "camellia-256-cbc" C_CAMELLIA256_CBC ariaKey256 ariaIv ariaPt cam256CbcCt
  katEcb env "camellia-256-ecb" C_CAMELLIA256_ECB ariaKey256 ariaPt cam256EcbCt
  -- Geometry refusals stay typed on the new specs.
  expectBadParam "ecb rejects iv" =<<
    cipherEncrypt env C_AES128_ECB (KeyBytes aes128Key) aes256Iv aes256Pt
  expectBadParam "des3 rejects 16-byte iv" =<<
    cipherEncrypt env C_DES3_CBC (KeyBytes des3Key24) aes256Iv des3Pt
  expectBadParam "des3 rejects 8-byte key" =<<
    cipherEncrypt env C_DES3_CBC (KeyBytes "12345678") des3Iv des3Pt
  where
    katCbc env label cipher key iv pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) iv pt
      assertEqual (label ++ " kat") want ct
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) iv want
      assertEqual (label ++ " inverts") pt pt'
    katEcb env label cipher key pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) BS.empty pt
      assertEqual (label ++ " kat") want ct
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) BS.empty want
      assertEqual (label ++ " inverts") pt pt'
    katCtr env label cipher key icb pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) icb pt
      assertEqual (label ++ " kat") want ct
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) icb want
      assertEqual (label ++ " inverts") pt pt'

caseRsaKats :: IO ()
caseRsaKats = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
      sha256 = SigRSA_PKCS1v15 D_SHA256
  -- SHA-256 KAT: the backend signs the CLI's exact bytes
  -- (deterministic v1.5) and verifies the CLI's vector.
  sig <- expectOk "rsa-sha256 sign kat" =<< sign env sha256 priv rsaMsg
  assertEqual "rsa-sha256 kat" rsaSig256 sig
  expectOk "rsa-sha256 verify kat" =<< verify env sha256 pub rsaMsg rsaSig256
  expectAuthFailed "rsa-sha256 tampered" =<<
    verify env sha256 pub rsaMsg (BS.init rsaSig256 <> "X")
  expectAuthFailed "rsa-sha256 wrong msg" =<<
    verify env sha256 pub "wrong message" rsaSig256
  -- Raw KAT: block-type-1 over the input, no hashing.
  rsig <- expectOk "rsa-raw sign kat" =<< sign env SigRSA_Raw priv rsaRawMsg
  assertEqual "rsa-raw kat" rsaRawSig rsig
  expectOk "rsa-raw verify kat" =<< verify env SigRSA_Raw pub rsaRawMsg rsaRawSig
  expectAuthFailed "rsa-raw tampered" =<<
    verify env SigRSA_Raw pub rsaRawMsg (BS.init rsaRawSig <> "X")
  -- Every other bound digest roundtrips (sign is deterministic:
  -- signing twice agrees, and cross-digest verifies fail).
  mapM_ (roundtrip env priv pub)
    [ D_MD5, D_SHA1, D_SHA224, D_SHA384, D_SHA512
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    , D_RIPEMD160
    ]
  cross <- expectOk "rsa-sha512 sign" =<<
    sign env (SigRSA_PKCS1v15 D_SHA512) priv rsaMsg
  expectAuthFailed "sha512 sig under sha256 rejected" =<<
    verify env sha256 pub rsaMsg cross
  -- Typed key refusals: garbage DER is a bad key, never native.
  expectBadKey "rsa sign garbage priv" =<< sign env sha256 (KeyDer "bogus") rsaMsg
  expectBadKey "rsa verify garbage pub" =<<
    verify env sha256 (KeyDer "bogus") rsaMsg rsaSig256
  where
    roundtrip env priv pub alg = do
      let spec' = SigRSA_PKCS1v15 alg
          label = show alg
      s1 <- expectOk ("sign " ++ label) =<< sign env spec' priv rsaMsg
      assertEqual ("sig length " ++ label) 256 (BS.length s1)
      s2 <- expectOk ("resign " ++ label) =<< sign env spec' priv rsaMsg
      assertEqual ("deterministic " ++ label) s1 s2
      expectOk ("verify " ++ label) =<< verify env spec' pub rsaMsg s1

caseRsaPssVectors :: IO ()
caseRsaPssVectors = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
      sha256 = SigRSA_PSS (PssParams D_SHA256 D_SHA256 32)
  -- Interop: the backend verifies the CLI's signature bytes.
  expectOk "pss-sha256 verify cli vector" =<<
    verify env sha256 pub pssMsg pssSig256
  expectAuthFailed "pss-sha256 tampered" =<<
    verify env sha256 pub pssMsg (BS.init pssSig256 <> "X")
  expectAuthFailed "pss-sha256 wrong msg" =<<
    verify env sha256 pub "wrong message" pssSig256
  expectAuthFailed "pss-sha256 wrong salt rejected" =<<
    verify env (SigRSA_PSS (PssParams D_SHA256 D_SHA256 20)) pub pssMsg pssSig256
  -- Roundtrips: the backend signs (fresh randomness each call) and
  -- verifies its own output across salts and digests.
  mapM_ (roundtrip env priv pub)
    [ PssParams D_SHA256 D_SHA256 0
    , PssParams D_SHA256 D_SHA256 20
    , PssParams D_SHA256 D_SHA256 32
    , PssParams D_SHA256 D_SHA256 64
    , PssParams D_SHA256 D_SHA512 32
    , PssParams D_SHA512 D_SHA512 64
    , PssParams D_SHA1 D_SHA1 20
    , PssParams D_SHA3_256 D_SHA3_256 32
    ]
  -- Typed key refusals: garbage DER is a bad key, never native.
  expectBadKey "pss sign garbage priv" =<< sign env sha256 (KeyDer "bogus") pssMsg
  expectBadKey "pss verify garbage pub" =<<
    verify env sha256 (KeyDer "bogus") pssMsg pssSig256
  where
    roundtrip env priv pub p = do
      let spec' = SigRSA_PSS p
          label = show p
      s1 <- expectOk ("sign " ++ label) =<< sign env spec' priv pssMsg
      assertEqual ("sig length " ++ label) 256 (BS.length s1)
      s2 <- expectOk ("resign " ++ label) =<< sign env spec' priv pssMsg
      -- Positive salts randomize; salt 0 is deterministic by design.
      if pssSaltLen p > 0
        then assertBool ("randomized " ++ label) (s1 /= s2)
        else assertEqual ("salt-0 deterministic " ++ label) s1 s2
      expectOk ("verify own " ++ label) =<< verify env spec' pub pssMsg s1
      expectOk ("verify own2 " ++ label) =<< verify env spec' pub pssMsg s2

caseRsaOaepVectors :: IO ()
caseRsaOaepVectors = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
      sha256 = RsaOaep (OaepParams D_SHA256 D_SHA256 BS.empty)
      sha1Label = RsaOaep (OaepParams D_SHA1 D_SHA1 "label")
  -- Interop: the backend decrypts the CLI's ciphertexts.
  pt <- expectOk "oaep-sha256 decrypt cli vector" =<<
    pkeyDecrypt env sha256 priv oaepCt256
  assertEqual "oaep-sha256 interop" oaepMsg pt
  ptL <- expectOk "oaep-sha1-label decrypt cli vector" =<<
    pkeyDecrypt env sha1Label priv oaepCtLabel
  assertEqual "oaep-sha1-label interop" oaepMsg ptL
  -- Wrong label, tampering, and wrong keys are verdicts.
  expectAuthFailed "oaep wrong label rejected" =<<
    pkeyDecrypt env sha256 priv oaepCtLabel
  expectAuthFailed "oaep tampered rejected" =<<
    pkeyDecrypt env sha256 priv (BS.init oaepCt256 <> "X")
  -- Uniformity (Manger 2001): every modulus-wide invalid
  -- ciphertext is the same AuthFailed verdict — no reason-code
  -- partition across padding-failure shapes.
  let badBlobs = [ BS.replicate 256 0x00
                 , BS.replicate 256 0xFF
                 , BS.pack [0x00, 0x02] <> BS.replicate 254 0x00
                 , BS.reverse oaepCt256
                 ]
  mapM_ (\(i, bad) -> expectAuthFailed ("oaep uniform " ++ show (i :: Int)) =<<
    pkeyDecrypt env sha256 priv bad) (zip [1 ..] badBlobs)
  expectBadParam "oaep wrong-length refused" =<<
    pkeyDecrypt env sha256 priv "short"
  -- Roundtrips: fresh randomness each call, label binding holds.
  mapM_ (roundtrip env priv pub) [sha256, sha1Label]
  -- Typed bounds: overlong input is BadParam (k-2*hLen-2 = 190 for
  -- SHA-256 on this key), garbage DER is a bad key.
  expectBadParam "oaep overlong refused" =<<
    pkeyEncrypt env sha256 pub (BS.replicate 191 0x41)
  ct190 <- expectOk "oaep boundary seals" =<<
    pkeyEncrypt env sha256 pub (BS.replicate 190 0x41)
  pt190 <- expectOk "oaep boundary opens" =<<
    pkeyDecrypt env sha256 priv ct190
  assertEqual "oaep boundary reversible" (BS.replicate 190 0x41) pt190
  expectBadKey "oaep encrypt garbage pub" =<<
    pkeyEncrypt env sha256 (KeyDer "bogus") oaepMsg
  expectBadKey "oaep decrypt garbage priv" =<<
    pkeyDecrypt env sha256 (KeyDer "bogus") oaepCt256
  where
    roundtrip env priv pub params = do
      let label = show params
      c1 <- expectOk ("seal " ++ label) =<< pkeyEncrypt env params pub oaepMsg
      assertEqual ("ct length " ++ label) 256 (BS.length c1)
      c2 <- expectOk ("reseal " ++ label) =<< pkeyEncrypt env params pub oaepMsg
      assertBool ("randomized " ++ label) (c1 /= c2)
      p1 <- expectOk ("open " ++ label) =<< pkeyDecrypt env params priv c1
      assertEqual ("reversible " ++ label) oaepMsg p1

caseRsaPkcs1Vectors :: IO ()
caseRsaPkcs1Vectors = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
  -- Interop: the backend decrypts the CLI's ciphertext.
  pt <- expectOk "pkcs1 decrypt cli vector" =<<
    pkeyDecrypt env RsaPkcs1 priv pkcs1Ct
  assertEqual "pkcs1 interop" pkcs1Msg pt
  -- Header tampering is a verdict. (A last-byte flip is NOT
  -- tested: v1.5 carries no integrity check, so it still opens to
  -- garbage — that is correct padding behavior, not a bypass.)
  expectAuthFailed "pkcs1 tampered rejected" =<<
    pkeyDecrypt env RsaPkcs1 priv ("\xFF\xFF" <> BS.drop 2 pkcs1Ct)
  -- Uniformity (Manger 2001): every modulus-wide invalid
  -- ciphertext is the same AuthFailed verdict — no reason-code
  -- partition across padding-failure shapes.
  let badBlobs = [ BS.replicate 256 0x00
                 , BS.replicate 256 0xFF
                 , BS.pack [0x00, 0x02] <> BS.replicate 254 0x00
                 , BS.pack [0x00, 0x01] <> BS.replicate 254 0xFF
                 , BS.reverse pkcs1Ct
                 ]
  mapM_ (\(i, bad) -> expectAuthFailed ("pkcs1 uniform " ++ show (i :: Int)) =<<
    pkeyDecrypt env RsaPkcs1 priv bad) (zip [1 ..] badBlobs)
  expectBadParam "pkcs1 wrong-length refused" =<<
    pkeyDecrypt env RsaPkcs1 priv "short"
  -- Roundtrip: fresh randomness each call, own output opens.
  c1 <- expectOk "pkcs1 seal" =<< pkeyEncrypt env RsaPkcs1 pub pkcs1Msg
  assertEqual "pkcs1 ct length" 256 (BS.length c1)
  c2 <- expectOk "pkcs1 reseal" =<< pkeyEncrypt env RsaPkcs1 pub pkcs1Msg
  assertBool "pkcs1 randomized" (c1 /= c2)
  p1 <- expectOk "pkcs1 open" =<< pkeyDecrypt env RsaPkcs1 priv c1
  assertEqual "pkcs1 reversible" pkcs1Msg p1
  -- Typed bounds: overlong input is BadParam (k-11 = 245 on this
  -- key), garbage DER is a bad key.
  expectBadParam "pkcs1 overlong refused" =<<
    pkeyEncrypt env RsaPkcs1 pub (BS.replicate 246 0x41)
  ct245 <- expectOk "pkcs1 boundary seals" =<<
    pkeyEncrypt env RsaPkcs1 pub (BS.replicate 245 0x41)
  pt245 <- expectOk "pkcs1 boundary opens" =<<
    pkeyDecrypt env RsaPkcs1 priv ct245
  assertEqual "pkcs1 boundary reversible" (BS.replicate 245 0x41) pt245
  expectBadKey "pkcs1 encrypt garbage pub" =<<
    pkeyEncrypt env RsaPkcs1 (KeyDer "bogus") pkcs1Msg
  expectBadKey "pkcs1 decrypt garbage priv" =<<
    pkeyDecrypt env RsaPkcs1 (KeyDer "bogus") pkcs1Ct

caseEcdsaKat :: IO ()
caseEcdsaKat = withBackend $ \env -> do
  let pub = KeyDer ecPubDer
      derSpec = SigECDSA { sigEc = p256der, sigEcDigest = Just D_SHA256 }
      rawSpec = SigECDSA { sigEc = p256raw, sigEcDigest = Just D_SHA256 }
  expectOk "verify fixed DER" =<< verify env derSpec pub ecMsg ecSigDer
  expectOk "verify fixed RAW" =<< verify env rawSpec pub ecMsg ecSigRaw
  -- Cross-check: the test's own DER parser recovers the same r || s.
  case parseDerEcdsa 32 ecSigDer of
    Nothing -> assertFailure "test DER parser rejected the fixed signature"
    Just (r, s) -> assertEqual "raw == parsed der" ecSigRaw (pad32 r <> pad32 s)
  where
    p256der = mkEc "P-256" "DER"
    p256raw = mkEc "P-256" "RAW"

caseEcdsaRoundtrip :: IO ()
caseEcdsaRoundtrip = withBackend $ \env -> do
  (priv, Just pub) <- expectOk "gen p-256" =<< generateKey env (GenEC (mkEc "P-256" "DER"))
  let derSpec = SigECDSA { sigEc = mkEc "P-256" "DER", sigEcDigest = Just D_SHA256 }
      rawSpec = SigECDSA { sigEc = mkEc "P-256" "RAW", sigEcDigest = Just D_SHA256 }
  sigD <- expectOk "sign DER" =<< sign env derSpec priv ecMsg
  assertBool "der parses" (parseDerEcdsa 32 sigD /= Nothing)
  expectOk "verify DER" =<< verify env derSpec pub ecMsg sigD
  sigR <- expectOk "sign RAW" =<< sign env rawSpec priv ecMsg
  assertEqual "raw is exactly r||s" 64 (BS.length sigR)
  expectOk "verify RAW" =<< verify env rawSpec pub ecMsg sigR
  -- Tampered signatures fail authentication, never verify.
  let tamper bs = BS.init bs <> BS.singleton (BS.last bs + 1)
  expectAuthFailed "tampered DER" =<< verify env derSpec pub ecMsg (tamper sigD)
  expectAuthFailed "tampered RAW" =<< verify env rawSpec pub ecMsg (tamper sigR)

caseEcdsaCurvesVectors :: IO ()
caseEcdsaCurvesVectors = withBackend $ \env -> do
  -- Interop: the CLI's P-384/SHA-384 and P-521/SHA-512 bytes verify.
  let s384 = SigECDSA (mkEc "P-384" "DER") (Just D_SHA384)
      s521 = SigECDSA (mkEc "P-521" "DER") (Just D_SHA512)
  expectOk "verify cli p384" =<<
    verify env s384 (KeyDer ecP384Pub) ecMsg384 ecSig384
  expectOk "verify cli p521" =<<
    verify env s521 (KeyDer ecP521Pub) ecMsg521 ecSig521
  expectAuthFailed "p384 tampered" =<<
    verify env s384 (KeyDer ecP384Pub) ecMsg384 (BS.init ecSig384 <> "X")
  -- Raw interop: the CLI's raw P-256 bytes verify under the raw row.
  let sraw = SigECDSA (mkEc "P-256" "DER") Nothing
  expectOk "verify cli raw" =<<
    verify env sraw (KeyDer ecPubDer) ecRaw32 ecRawSig
  expectAuthFailed "raw tampered" =<<
    verify env sraw (KeyDer ecPubDer) ecRaw32 (BS.init ecRawSig <> "X")
  -- Raw input bounds are typed: 33 bytes on P-256 is BadParam.
  expectBadParam "raw overlong sign refused" =<<
    sign env sraw (KeyDer ecPrivDer) (BS.replicate 33 0)
  expectBadParam "raw overlong verify refused" =<<
    verify env sraw (KeyDer ecPubDer) (BS.replicate 33 0) ecRawSig
  -- Roundtrips: every (curve, digest-or-raw, encoding) signs and
  -- verifies its own output (fresh randomness each call).
  (p384, Just q384) <- expectOk "gen p384" =<<
    generateKey env (GenEC (mkEc "P-384" "DER"))
  (p521, Just q521) <- expectOk "gen p521" =<<
    generateKey env (GenEC (mkEc "P-521" "DER"))
  (p256, Just q256) <- expectOk "gen p256" =<<
    generateKey env (GenEC (mkEc "P-256" "DER"))
  mapM_ (roundtrip env p384 q384 "P-384" 96)
    (Nothing : map Just
      [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
      , D_SHA512_224, D_SHA512_256
      , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
      , D_RIPEMD160
      ])
  mapM_ (roundtrip env p521 q521 "P-521" 132)
    [Nothing, Just D_SHA256, Just D_SHA512, Just D_SHA3_512]
  mapM_ (roundtrip env p256 q256 "P-256" 64)
    [Nothing, Just D_SHA1, Just D_SHA256, Just D_SHA512, Just D_SHA3_256]
  where
    roundtrip env priv pub curve rawLen digest = do
      let derSpec = SigECDSA (mkEc curve "DER") digest
          rawSpec = SigECDSA (mkEc curve "RAW") digest
          label = curve ++ "/" ++ show digest
          input = if digest == Nothing then BS.replicate (rawLen `div` 2) 0x5a else ecMsg
      sigD <- expectOk ("sign DER " ++ label) =<< sign env derSpec priv input
      assertBool ("der parses " ++ label) (parseDerEcdsa (rawLen `div` 2) sigD /= Nothing)
      expectOk ("verify DER " ++ label) =<< verify env derSpec pub input sigD
      sigR <- expectOk ("sign RAW " ++ label) =<< sign env rawSpec priv input
      assertEqual ("raw length " ++ label) rawLen (BS.length sigR)
      expectOk ("verify RAW " ++ label) =<< verify env rawSpec pub input sigR

-- | The curve allowlist: a well-formed P-224 key refuses typed
-- on both sign and verify (the driver only hints the curve label,
-- so the backend re-checks before any native call). Garbage DER
-- refuses the same way.
caseEcdsaOffCurve :: IO ()
caseEcdsaOffCurve = withBackend $ \env -> do
  let ecdsaSpec = SigECDSA (mkEc "P-256" "DER") (Just D_SHA256)
  expectBadKey "bp160 sign refused" =<<
    sign env ecdsaSpec (KeyDer ecBp160Priv) ecMsg
  expectBadKey "bp160 verify refused" =<<
    verify env ecdsaSpec (KeyDer ecBp160Pub) ecMsg ecSigDer
  expectBadKey "garbage sign refused" =<<
    sign env ecdsaSpec (KeyDer "bogus") ecMsg
  expectBadKey "garbage verify refused" =<<
    verify env ecdsaSpec (KeyDer "bogus") ecMsg ecSigDer

-- | S10 ECDH agreement: CLI cross-checked KATs in both
-- directions, cofactor-equals-plain on P-256 (h=1), the P-384
-- width, and typed key-shape refusals (garbage, off-set curve,
-- base/peer curve mismatch).
caseEcdhVectors :: IO ()
caseEcdhVectors = withBackend $ \env -> do
  let pA = KeyDer ecdhPrivA
      qA = KeyDer ecdhPubA
      pB = KeyDer ecdhPrivB
      qB = KeyDer ecdhPubB
      pC = KeyDer ecdhPrivC
      qC = KeyDer ecdhPubC
  sAB <- expectOk "derive A->B" =<< ecdhDerive env EcdhPlain pA qB
  assertEqual "KAT A->B" ecdhSecretAB sAB
  sBA <- expectOk "derive B->A" =<< ecdhDerive env EcdhPlain pB qA
  assertEqual "commute" ecdhSecretAB sBA
  sCof <- expectOk "derive cofactor" =<< ecdhDerive env EcdhCofactor pA qB
  assertEqual "cofactor == plain (h=1)" ecdhSecretAB sCof
  sCC <- expectOk "derive P-384" =<< ecdhDerive env EcdhPlain pC qC
  assertEqual "KAT P-384" ecdhSecretCC sCC
  assertEqual "P-384 width" 48 (BS.length sCC)
  expectBadKey "garbage priv refused" =<< ecdhDerive env EcdhPlain (KeyDer "bogus") qB
  expectBadKey "garbage peer refused" =<< ecdhDerive env EcdhPlain pA (KeyDer "bogus")
  expectBadKey "off-curve priv refused" =<< ecdhDerive env EcdhPlain (KeyDer ecBp160Priv) qB
  expectBadKey "curve mismatch refused" =<< ecdhDerive env EcdhPlain pA qC

caseRawVsDer :: IO ()
caseRawVsDer = withBackend $ \env -> do
  let pub = KeyDer ecPubDer
      derSpec = SigECDSA { sigEc = mkEc "P-256" "DER", sigEcDigest = Just D_SHA256 }
      rawSpec = SigECDSA { sigEc = mkEc "P-256" "RAW", sigEcDigest = Just D_SHA256 }
  -- Same bytes under the wrong encoding are rejected: the backend never
  -- sniffs or converts encodings silently.
  r1 <- verify env derSpec pub ecMsg ecSigRaw
  case r1 of
    EngineFail (BackendAuthFailed _) -> pure ()
    EngineFail (BackendBadParam _ _) -> pure ()
    other -> assertFailure ("raw-as-der must be rejected, got " ++ show other)
  r2 <- verify env rawSpec pub ecMsg ecSigDer
  case r2 of
    EngineFail (BackendAuthFailed _) -> pure ()
    EngineFail (BackendBadParam _ _) -> pure ()
    other -> assertFailure ("der-as-raw must be rejected, got " ++ show other)
  -- RSA v1.5 is supported (see caseRsaKats); the XOF
  -- digest never makes a servable RSA spec.
  expectUnsupported "rsa xof never servable"
    =<< sign env (SigRSA_PKCS1v15 D_SHAKE128) (KeyDer ecPrivDer) ecMsg
  -- The NIST prime curves, every fixed-width digest, and the
  -- raw row are supported (see caseEcdsaCurvesVectors); off-set
  -- curves and XOF digests stay out, never coerced.
  expectUnsupported "ecdsa p-224 never servable"
    =<< sign env (SigECDSA (mkEc "P-224" "DER") (Just D_SHA256)) (KeyDer ecPrivDer) ecMsg
  expectUnsupported "ecdsa xof never servable"
    =<< sign env (SigECDSA (mkEc "P-256" "DER") (Just D_SHAKE128)) (KeyDer ecPrivDer) ecMsg

caseSymKeygen :: IO ()
caseSymKeygen = withBackend $ \env -> do
  -- AES lengths land as lone raw bytes; two generations differ
  -- (fresh randomness every call; no KAT is possible).
  (KeyBytes k16, Nothing) <- expectOk "gen aes-16" =<< generateKey env (GenSym "AES" 16)
  assertEqual "aes-16 length" 16 (BS.length k16)
  (KeyBytes k16b, Nothing) <- expectOk "gen aes-16 again" =<< generateKey env (GenSym "AES" 16)
  assertBool "aes-16 fresh" (k16 /= k16b)
  (KeyBytes k24, Nothing) <- expectOk "gen aes-24" =<< generateKey env (GenSym "AES" 24)
  assertEqual "aes-24 length" 24 (BS.length k24)
  (KeyBytes k32, Nothing) <- expectOk "gen aes-32" =<< generateKey env (GenSym "AES" 32)
  assertEqual "aes-32 length" 32 (BS.length k32)
  (KeyBytes kh, Nothing) <- expectOk "gen hotp-20" =<< generateKey env (GenSym "HOTP" 20)
  assertEqual "hotp-20 length" 20 (BS.length kh)
  (KeyBytes kg, Nothing) <- expectOk "gen generic-32" =<< generateKey env (GenSym "GENERIC" 32)
  assertEqual "generic-32 length" 32 (BS.length kg)
  -- Bounds are typed: off-window lengths are bad params, unknown
  -- algorithms are unsupported (never silent bytes).
  expectBadParam "aes-15 refused" =<< generateKey env (GenSym "AES" 15)
  expectBadParam "aes-0 refused" =<< generateKey env (GenSym "AES" 0)
  expectBadParam "hotp-15 refused" =<< generateKey env (GenSym "HOTP" 15)
  expectBadParam "hotp-65 refused" =<< generateKey env (GenSym "HOTP" 65)
  expectBadParam "generic-0 refused" =<< generateKey env (GenSym "GENERIC" 0)
  expectBadParam "generic-256 refused" =<< generateKey env (GenSym "GENERIC" 256)
  expectUnsupported "des keygen out" =<< generateKey env (GenSym "DES" 8)
  expectUnsupported "ml-kem keygen out" =<< generateKey env (GenMLKEM ML_KEM_768)

caseAeadReal :: IO ()
caseAeadReal = withBackend $ \env -> do
  -- Pinned vector (Python cryptography AESGCM, the oracle's own
  -- cross-check root): key 00..0f, nonce 00..0b, aad "aad-data",
  -- pt "Hello GCM world!".
  let key = KeyBytes (hex "000102030405060708090a0b0c0d0e0f")
      nonce = hex "000102030405060708090a0b"
      aad = "aad-data"
      pt = "Hello GCM world!"
      spec = AeadSpec "AES-128-GCM" 12 16
  (ct, tag) <- expectOk "gcm vector" =<<
    aeadEncrypt env spec key nonce aad pt
  assertEqual "vector ct" (hex "db09cba2093bb01706f216e544cf1429") ct
  assertEqual "vector tag" (hex "39f0385041afdfd3a2d5a8e8ed69a2e6") tag
  pt' <- expectOk "gcm vector decrypt" =<<
    aeadDecrypt env spec key nonce aad ct tag
  assertEqual "vector roundtrip" pt pt'
  -- Tampering anywhere fails closed.
  let badTag = BS.pack [BS.head tag `xor` 1] <> BS.tail tag
  expectAuthFailed "tag tamper" =<<
    aeadDecrypt env spec key nonce aad ct badTag
  let badCt = BS.pack [BS.head ct `xor` 1] <> BS.tail ct
  expectAuthFailed "ct tamper" =<<
    aeadDecrypt env spec key nonce aad badCt tag
  expectAuthFailed "aad tamper" =<<
    aeadDecrypt env spec key nonce "aad-datX" ct tag
  -- Bounds: wrong key/nonce/tag widths refuse as bad params.
  expectBadParam "short key" =<<
    aeadEncrypt env spec (KeyBytes "short") nonce aad pt
  expectBadParam "short nonce" =<<
    aeadEncrypt env (AeadSpec "AES-128-GCM" 12 16) key "short" aad pt
  expectBadParam "bad alg" =<<
    aeadEncrypt env (AeadSpec "NOPE" 12 16) key nonce aad pt

-- | Empty plaintext must seal to ct="" plus the pinned tag and open back
-- to "". The AAD Update call used to clobber the shared output-length
-- accumulator, so empty-message seals wrote the tag out of bounds (lane
-- crash) and opens returned aad-length garbage (Wycheproof tc92).
caseAeadEmptyPlaintext :: IO ()
caseAeadEmptyPlaintext = withBackend $ \env -> do
  -- Pinned tags from Python cryptography AESGCM (same oracle root as
  -- caseAeadReal): key 00..0f, nonce 00..0b.
  let key = KeyBytes (hex "000102030405060708090a0b0c0d0e0f")
      nonce = hex "000102030405060708090a0b"
      spec = AeadSpec "AES-128-GCM" 12 16
  (ct1, tag1) <- expectOk "empty-pt seal with aad" =<<
    aeadEncrypt env spec key nonce "aad-data" ""
  assertEqual "empty-pt ct with aad" "" ct1
  assertEqual "empty-pt tag with aad" (hex "e01312146176abd643fcee9d4a640184") tag1
  pt1 <- expectOk "empty-pt open with aad" =<<
    aeadDecrypt env spec key nonce "aad-data" ct1 tag1
  assertEqual "empty-pt roundtrip with aad" "" pt1
  (ct0, tag0) <- expectOk "empty-pt seal without aad" =<<
    aeadEncrypt env spec key nonce "" ""
  assertEqual "empty-pt ct without aad" "" ct0
  assertEqual "empty-pt tag without aad" (hex "435b9ba12d75a4be8a977ea3cd011890") tag0
  pt0 <- expectOk "empty-pt open without aad" =<<
    aeadDecrypt env spec key nonce "" ct0 tag0
  assertEqual "empty-pt roundtrip without aad" "" pt0

caseAeadCcmReal :: IO ()
caseAeadCcmReal = withBackend $ \env -> do
  -- Wycheproof aes_ccm_test.json group 0 (AES-128, 128-bit tag).
  -- tcId 1: empty message, the CCM analogue of the GCM tc92 shape.
  let key1 = KeyBytes (hex "bedcfb5a011ebc84600fcb296c15af0d")
      nonce1 = hex "438a547a94ea88dce46c6c85"
      cspec = AeadSpec "AES-128-CCM" 12 16
  (ct1, tag1) <- expectOk "ccm tcId 1 seal" =<<
    aeadEncrypt env cspec key1 nonce1 "" ""
  assertEqual "ccm tcId 1 ct" "" ct1
  assertEqual "ccm tcId 1 tag" (hex "25d1a38495a7dea45bda049705627d10") tag1
  pt1 <- expectOk "ccm tcId 1 open" =<<
    aeadDecrypt env cspec key1 nonce1 "" ct1 tag1
  assertEqual "ccm tcId 1 roundtrip" "" pt1
  -- tcId 2: single-byte message.
  let key2 = KeyBytes (hex "384ea416ac3c2f51a76e7d8226346d4e")
      nonce2 = hex "b30c084727ad1c592ac21d12"
  (ct2, tag2) <- expectOk "ccm tcId 2 seal" =<<
    aeadEncrypt env cspec key2 nonce2 "" (hex "35")
  assertEqual "ccm tcId 2 ct" (hex "d7") ct2
  assertEqual "ccm tcId 2 tag" (hex "6be3fd13b7065afc19e3b8a3b96b39fb") tag2
  pt2 <- expectOk "ccm tcId 2 open" =<<
    aeadDecrypt env cspec key2 nonce2 "" ct2 tag2
  assertEqual "ccm tcId 2 roundtrip" (hex "35") pt2
  -- tcId 52 "Flipped bit 0 in tag" (result invalid): must fail closed.
  let key52 = KeyBytes (hex "000102030405060708090a0b0c0d0e0f")
      nonce52 = hex "505152535455565758595a5b"
      ct52 = hex "3ee9f3430f3e803c0a46b7a84cd803de"
      badTag52 = hex "3d6d5f66430ad65bb034077297f0929a"
  expectAuthFailed "ccm tcId 52 flipped tag" =<<
    aeadDecrypt env cspec key52 nonce52 "" ct52 badTag52
  -- Bounds: CCM-only widths refuse as bad params.
  expectBadParam "ccm 6-byte tag" =<<
    aeadEncrypt env (AeadSpec "AES-128-CCM" 12 5) key2 nonce2 "" (hex "35")
  expectBadParam "ccm 6-byte nonce" =<<
    aeadEncrypt env (AeadSpec "AES-128-CCM" 6 16) key2 (BS.take 6 nonce2) "" (hex "35")

caseRsaKeygen :: IO ()
caseRsaKeygen = withBackend $ \env -> do
  -- The real backend mints PKCS#8/SPKI DER halves (no KAT
  -- possible for randomized generation; lengths pin the shape).
  (KeyDer priv, Just (KeyDer pub)) <- expectOk "rsa-2048 mints" =<<
    generateKey env (GenRSA 2048 65537)
  assertBool "priv PKCS#8 length" (BS.length priv >= 1180 && BS.length priv <= 1250)
  assertBool "pub SPKI length" (BS.length pub >= 280 && BS.length pub <= 310)
  assertBool "halves differ" (priv /= pub)
  assertEqual "priv framing" (BS.singleton 0x30) (BS.take 1 priv)
  assertEqual "pub framing" (BS.singleton 0x30) (BS.take 1 pub)
  -- Bounds mirror the key planner (bad params, never silent).
  expectBadParam "rsa-1024 refused" =<< generateKey env (GenRSA 1024 65537)
  expectBadParam "rsa even exponent refused" =<< generateKey env (GenRSA 2048 4)

caseRandomBytes :: IO ()
caseRandomBytes = withBackend $ \env -> do
  -- Fresh DRBG bytes every call; zero length is a bad param; the
  -- 1 MiB window serves exactly; past it refuses (no transparent
  -- chunking: unbounded requests amplify into OOM kills).
  r1 <- expectOk "random 32" =<< randomBytes env 32
  assertEqual "random length" 32 (BS.length r1)
  r2 <- expectOk "random 32 again" =<< randomBytes env 32
  assertBool "random fresh" (r1 /= r2)
  expectBadParam "random 0 refused" =<< randomBytes env 0
  full <- expectOk "random 1MiB" =<< randomBytes env generateRandomMaxBytes
  assertEqual "window length" generateRandomMaxBytes (BS.length full)
  expectBadParam "random 1MiB+1 refused" =<< randomBytes env (generateRandomMaxBytes + 1)

caseSeedRandomMix :: IO ()
caseSeedRandomMix = withBackend $ \env -> do
  -- Seeding mixes additional input (never replacing the DRBG
  -- state); post-seed randomBytes works normally, empty seeds are
  -- a vacuous OK, oversize seeds are refused.
  expectOk "seed ok" =<< seedRandom env "test-seed"
  r <- expectOk "random after seed" =<< randomBytes env 32
  assertEqual "random length" 32 (BS.length r)
  expectOk "empty seed ok" =<< seedRandom env BS.empty
  r2 <- expectOk "random after empty seed" =<< randomBytes env 32
  assertEqual "random length again" 32 (BS.length r2)
  expectBadParam "oversize seed refused"
    =<< seedRandom env (BS.replicate (seedRandomMaxBytes + 1) 0)

caseSeedEntropyHonesty :: IO ()
caseSeedEntropyHonesty = do
  -- The seed path never claims entropy it doesn't have. The
  -- 0.0 estimate lives in ONE named home in the shim, and the
  -- single RAND_add call site passes that name (never a literal,
  -- never RAND_seed). Mirrors the caseShimHygiene read-the-shim
  -- idiom (cwd-tolerant lookup included).
  src <- findShim ["cbits/ossl4_ctx.c", "../cbits/ossl4_ctx.c", "haskoki/cbits/ossl4_ctx.c"]
  assertEqual "single entropy-estimate home" 1
    (count "#define HSK_OSSL4_SEED_ENTROPY_ESTIMATE 0.0" src)
  let calls = filter ("RAND_add(" `isInfixOf`) (lines src)
  assertEqual "single RAND_add call site" 1 (length calls)
  case calls of
    [c] -> assertBool "call site passes the named estimate"
             ("HSK_OSSL4_SEED_ENTROPY_ESTIMATE" `isInfixOf` c)
    _ -> assertFailure ("expected one RAND_add call site, saw " ++ show (length calls))
  assertEqual "no RAND_seed anywhere" 0 (count "RAND_seed" src)
  where
    count needle hay = length (filter (hasPrefix needle) (tails hay))
    hasPrefix needle s = case stripPrefix needle s of
      Just _ -> True
      Nothing -> False
    findShim [] = assertFailure "cbits/ossl4_ctx.c not found from test cwd"
    findShim (p:ps) = do
      exists <- doesFileExist p
      if exists then readFile p else findShim ps

caseSeedNoReplay :: IO ()
caseSeedNoReplay = withBackend $ \env -> do
  -- Scope pin: the OpenSSL seed path mixes (RAND_add) and never
  -- replaces DRBG state, so identical reseeds do NOT replay --
  -- freshness is preserved across them. C-table determinism is
  -- therefore NOT asserted anywhere (the served C path is
  -- OpenSSL-typed end to end: siBackend :: BackendEnv OpenSSL4);
  -- the determinism contract lives in SyntheticSpec
  -- caseSeedRandomReplay.
  expectOk "seed S ok" =<< seedRandom env "scope-S"
  a <- expectOk "bytes after seed" =<< randomBytes env 32
  expectOk "reseed S ok" =<< seedRandom env "scope-S"
  b <- expectOk "bytes after reseed" =<< randomBytes env 32
  assertBool "reseed does not replay" (a /= b)

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
  expectUnsupported "ml-kem encaps" =<< kemEncapsulate env (mkKem ML_KEM_768) (KeyDer ecPubDer)

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

caseCaps :: IO ()
caseCaps = withBackend $ \env -> do
  caps <- queryCapabilities env
  assertEqual "backend name" "openssl4" (bcName caps)
  assertBool ("version pins 4.0.2, got " ++ bcVersion caps)
    ("4.0.2" `isInfixOf` bcVersion caps)
  assertEqual "digest set" (Set.fromList
    [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
    , D_SHA512_224, D_SHA512_256
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    , D_RIPEMD160
    ]) (dcAlgs (bcDigests caps))
  assertEqual "cipher set" (Set.fromList
    [ C_AES128_CBC, C_AES192_CBC, C_AES256_CBC
    , C_AES128_CTR, C_AES192_CTR, C_AES256_CTR
    , C_AES128_ECB, C_AES192_ECB, C_AES256_ECB
    , C_DES3_CBC, C_DES3_ECB
    , C_ARIA128_CBC, C_ARIA192_CBC, C_ARIA256_CBC
    , C_ARIA128_ECB, C_ARIA192_ECB, C_ARIA256_ECB
    , C_CAMELLIA128_CBC, C_CAMELLIA192_CBC, C_CAMELLIA256_CBC
    , C_CAMELLIA128_ECB, C_CAMELLIA192_ECB, C_CAMELLIA256_ECB
    ]) (ccCiphers (bcCiphers caps))
  assertEqual "aead set" (Set.fromList
    [ "AES-128-GCM", "AES-192-GCM", "AES-256-GCM"
    , "AES-128-CCM", "AES-192-CCM", "AES-256-CCM"
    ]) (ccAead (bcCiphers caps))
  assertEqual "mac set" (Set.fromList
    [ "HMAC-MD5", "HMAC-SHA1"
    , "HMAC-SHA224", "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"
    , "HMAC-SHA512-224", "HMAC-SHA512-256"
    , "HMAC-SHA3-224", "HMAC-SHA3-256", "HMAC-SHA3-384", "HMAC-SHA3-512"
    , "HMAC-RIPEMD160"
    , "HMAC-MD5-GENERAL", "HMAC-SHA1-GENERAL"
    , "HMAC-SHA224-GENERAL", "HMAC-SHA256-GENERAL"
    , "HMAC-SHA384-GENERAL", "HMAC-SHA512-GENERAL"
    , "HMAC-SHA512-224-GENERAL", "HMAC-SHA512-256-GENERAL"
    , "HMAC-SHA3-224-GENERAL", "HMAC-SHA3-256-GENERAL"
    , "HMAC-SHA3-384-GENERAL", "HMAC-SHA3-512-GENERAL"
    , "HMAC-RIPEMD160-GENERAL"
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
        , "SHA3-384", "SHA3-512", "RIPEMD160"
        ]
      dsaNames =
        ["ECDSA-" ++ c ++ "-RAW" | c <- dsaCurves]
          ++ ["ECDSA-" ++ c ++ "-" ++ s | c <- dsaCurves, s <- dsaStems]
  assertEqual "sig set" (Set.fromList
    ([ "RSA-PSS"
    , "RSA-RAW"
    , "RSA-PKCS1v15-MD5", "RSA-PKCS1v15-SHA1"
    , "RSA-PKCS1v15-SHA224", "RSA-PKCS1v15-SHA256"
    , "RSA-PKCS1v15-SHA384", "RSA-PKCS1v15-SHA512"
    , "RSA-PKCS1v15-SHA3-224", "RSA-PKCS1v15-SHA3-256"
    , "RSA-PKCS1v15-SHA3-384", "RSA-PKCS1v15-SHA3-512"
    , "RSA-PKCS1v15-RIPEMD160"
    ] ++ dsaNames)) (scSpecs (bcSigs caps))
  assertEqual "curves" (Set.fromList dsaCurves) (scCurves (bcSigs caps))
  assertEqual "no kem advertised" Set.empty (kcAlgs (bcKems caps))
  assertEqual "kdf set" (Set.fromList ["ECDH", "ECDH-COFACTOR"]) (kcKdfs (bcKdfs caps))

caseIsolation :: IO ()
caseIsolation = do
  r1 <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  r2 <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  (e1, e2) <- case (r1, r2) of
    (EngineOk a, EngineOk b) -> pure (a, b)
    _ -> assertFailure "could not open two backends"
  d1 <- expectOk "ctx1 digest" =<< digestOneShot e1 D_SHA256 "abc"
  closeBackend e1
  -- Closing one private context leaves the other fully usable.
  d2 <- expectOk "ctx2 digest after close" =<< digestOneShot e2 D_SHA256 "abc"
  assertEqual "same vector" d1 d2
  assertEqual "still correct" sha256Abc d2
  closeBackend e2

caseShimHygiene :: IO ()
caseShimHygiene = do
  src <- findShim ["cbits/ossl4_ctx.c", "../cbits/ossl4_ctx.c", "haskoki/cbits/ossl4_ctx.c"]
  let low = lower src
  -- A provider *string* (quoted literal or header include), not a prose
  -- mention in a comment, would load a token-backed provider.
  assertBool "no pkcs11 provider string in shim"
    (not ("\"pkcs11\"" `isInfixOf` low || "pkcs11.h" `isInfixOf` low))
  -- A *reference* (call or address-of), not a prose mention, would run
  -- process-global teardown.
  assertBool "no OPENSSL_cleanup reference in shim" (not (hasRef low "openssl_cleanup"))
  assertBool "no OPENSSL_atexit reference in shim" (not (hasRef low "openssl_atexit"))
  where
    lower = map (\c -> if c >= 'A' && c <= 'Z' then toEnum (fromEnum c + 32) else c)
    hasRef src name = any match (tails src)
      where
        match s = case stripPrefix name s of
          Just rest -> case dropWhile (== ' ') rest of
            ('(' : _) -> True
            _ -> False
          Nothing -> case s of
            ('&' : rest) -> case stripPrefix name (dropWhile (== ' ') rest) of
              Just _ -> True
              Nothing -> False
            _ -> False
    findShim [] = assertFailure "cbits/ossl4_ctx.c not found from test cwd"
    findShim (p:ps) = do
      exists <- doesFileExist p
      if exists then readFile p else findShim ps

caseInvalidInputs :: IO ()
caseInvalidInputs = withBackend $ \env -> do
  -- Garbage key DER is a typed BadKey, never a crash.
  let badKey = KeyDer "not-der-at-all"
      spec' = SigECDSA { sigEc = mkEc "P-256" "DER", sigEcDigest = Just D_SHA256 }
  r1 <- verify env spec' badKey ecMsg ecSigDer
  case r1 of
    EngineFail (BackendBadKey _ _) -> pure ()
    EngineFail (BackendBadParam _ _) -> pure ()
    other -> assertFailure ("garbage key must be BadKey/BadParam, got " ++ show other)
  -- Unknown multipart resource is ResourceGone.
  r2 <- digestFinal env (mkResId 0xdeadbeef)
  case r2 of
    EngineFail (BackendResourceGone _ _) -> pure ()
    other -> assertFailure ("unknown resource must be ResourceGone, got " ++ show other)
  -- Double-final is ResourceGone (final releases).
  rid <- expectOk "init" =<< digestInit env D_SHA256
  _ <- expectOk "final" =<< digestFinal env rid
  r3 <- digestFinal env rid
  case r3 of
    EngineFail (BackendResourceGone _ _) -> pure ()
    other -> assertFailure ("second final must be ResourceGone, got " ++ show other)

-- ---------------------------------------------------------------------------
-- Small constructors used above
-- ---------------------------------------------------------------------------

mkEc :: String -> String -> EcSpec
mkEc curve enc = EcSpec { ecCurve = curve, ecEncoding = enc }

mkOaep :: DigestAlg -> RsaCipherParams
mkOaep d = RsaOaep (OaepParams { oaepHash = d, oaepMgf = d, oaepLabel = BS.empty })

mkKem :: PqcKemAlg -> KemSpec
mkKem a = KemSpec { kemAlg = a }

mkResId :: Word32 -> EngineResourceId
mkResId = EngineResourceId
