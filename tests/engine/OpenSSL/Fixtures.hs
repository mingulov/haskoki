{- | OpenSSL shared fixtures.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Fixtures
  ( aes128CbcCt
  , aes128CtrCt
  , aes128EcbCt
  , aes128Key
  , aes192CbcCt
  , aes192CtrCt
  , aes192EcbCt
  , aes256CtrCt
  , aes256EcbCt
  , aes256Iv
  , aes256Pt
  , aria128CbcCt
  , aria128EcbCt
  , aria192CbcCt
  , aria192EcbCt
  , aria256CbcCt
  , aria256EcbCt
  , ariaIv
  , ariaKey128
  , ariaKey192
  , ariaKey256
  , ariaPt
  , bfCt8z
  , bfIv8z
  , bfKey8z
  , bfPt8z
  , cam128CbcCt
  , cam128EcbCt
  , cam192CbcCt
  , cam192EcbCt
  , cam256CbcCt
  , cam256EcbCt
  , camCtr128Ct
  , camCtr128Icb
  , camCtr128Key
  , camCtr192Ct
  , camCtr192Icb
  , camCtr192Key
  , camCtr256Ct
  , camCtr256Icb
  , camCtr256Key
  , castCbcCt
  , castCbcPt
  , castEcb40Ct
  , castEcb80Ct
  , castEcb8Ct
  , castEcbCt
  , castEcbPt
  , castIv
  , castKey
  , castKey40
  , castKey8
  , castKey80
  , cfb128_128_ct
  , cfb128_128_iv
  , cfb128_128_key
  , cfb128_128_pt
  , cfb128_192_ct
  , cfb128_192_iv
  , cfb128_192_key
  , cfb128_192_pt
  , cfb128_256_ct
  , cfb128_256_iv
  , cfb128_256_key
  , cfb128_256_pt
  , cfb1_128_iv
  , cfb1_128_key
  , cfb1_128b_iv
  , cfb1_128b_key
  , cfb1_192_iv
  , cfb1_192_key
  , cfb1_192b_iv
  , cfb1_192b_key
  , cfb1_256_iv
  , cfb1_256_key
  , cfb1_256b_iv
  , cfb1_256b_key
  , cfb8_128_ct
  , cfb8_128_iv
  , cfb8_128_key
  , cfb8_128_pt
  , cfb8_192_ct
  , cfb8_192_iv
  , cfb8_192_key
  , cfb8_192_pt
  , cfb8_256_ct
  , cfb8_256_iv
  , cfb8_256_key
  , cfb8_256_pt
  , ctrIcb
  , ctrPt
  , cts128Ct156
  , cts128Ct64
  , cts128Iv156
  , cts128Iv64
  , cts128Key156
  , cts128Key64
  , cts128Pt156
  , cts128Pt64
  , cts192Ct32
  , cts192Ct57
  , cts192Iv32
  , cts192Iv57
  , cts192Key32
  , cts192Key57
  , cts192Pt32
  , cts192Pt57
  , cts256Ct19
  , cts256Ct66
  , cts256Iv19
  , cts256Iv66
  , cts256Key19
  , cts256Key66
  , cts256Pt19
  , cts256Pt66
  , des3Ct
  , des3Iv
  , des3Pt
  , desCbc1Ct
  , desCbc1Iv
  , desCbc1Key
  , desCbcCt
  , desCbcIv
  , desCbcKey
  , desCbcPt
  , desCfb64Ct
  , desCfb8Ct
  , desEcbCt
  , desEcbKey
  , desEcbPt
  , desFipsCt
  , desFipsKey
  , desFipsPt
  , desNow
  , desOfbCt
  , dhPadPeerA
  , dhPadPeerB
  , dhPadPrivA
  , dhPadPrivB
  , dhPadSecret
  , dhPeerA
  , dhPeerB
  , dhPrime2048
  , dhPrivA
  , dhPrivB
  , dhSecretAB
  , dhX942G
  , dhX942P
  , dhX942Q
  , ecBp160Priv
  , ecBp160Pub
  , ecdhPrivA
  , ecdhPrivB
  , ecdhPrivC
  , ecdhPrivD
  , ecdhPrivE
  , ecdhPubA
  , ecdhPubB
  , ecdhPubC
  , ecdhPubD
  , ecdhPubE
  , ecdhSecretAB
  , ecdhSecretCC
  , ecdhSecretDE
  , ecdhSecretDEcof
  , ecInf224Digest
  , ecInf224Pub
  , ecInf224Sig
  , ecMsg
  , ecPrivDer
  , ecPubDer
  , ecSigDer
  , ecSigRaw
  , expectAuthFailed
  , expectBadKey
  , expectBadParam
  , expectOk
  , expectSigLenRange
  , expectUnsupported
  , hex
  , hmacKey1
  , hmacMsg1
  , ideaCbcCt
  , ideaCbcIv
  , ideaCbcKey
  , ideaCbcPt
  , ideaNessieCt
  , ideaNessieKey
  , kw128_16_ct
  , kw128_16_key
  , kw128_16_pt
  , kw128_72_ct
  , kw128_72_key
  , kw128_72_pt
  , kw192_16_ct
  , kw192_16_key
  , kw192_16_pt
  , kw192_72_ct
  , kw192_72_key
  , kw192_72_pt
  , kw256_16_ct
  , kw256_16_key
  , kw256_16_pt
  , kw256_72_ct
  , kw256_72_key
  , kw256_72_pt
  , kwp128_1_ct
  , kwp128_1_key
  , kwp128_1_pt
  , kwp128_269_ct
  , kwp128_269_key
  , kwp128_269_pt
  , kwp192_1_ct
  , kwp192_1_key
  , kwp192_1_pt
  , kwp192_269_ct
  , kwp192_269_key
  , kwp192_269_pt
  , kwp256_1_ct
  , kwp256_1_key
  , kwp256_1_pt
  , kwp256_269_ct
  , kwp256_269_key
  , kwp256_269_pt
  , kwp7_ct_default
  , kwp7_ct_iv8
  , kwp7_ct_raw20
  , kwp7_iv8
  , kwp7_pad20
  , kwp7_pad24
  , kwp_iv4
  , kwp_iv4_ct
  , mkEc
  , mkKem
  , ofb_128_ct
  , ofb_128_iv
  , ofb_128_key
  , ofb_128_pt
  , ofb_192_ct
  , ofb_192_iv
  , ofb_192_key
  , ofb_192_pt
  , ofb_256_ct
  , ofb_256_iv
  , ofb_256_key
  , ofb_256_pt
  , rc2CbcCt
  , rc2CbcPt
  , rc2EcbCt
  , rc2EcbPt
  , rc2Iv
  , rc2Key
  , rc4Ct128
  , rc4Ct256
  , rc4Key128
  , rc4Key256
  , rc4Zero32
  , seedCbcCt
  , seedCbcIv
  , seedCbcKey
  , seedCbcPt
  , seedEcbCt
  , seedEcbKey
  , seedEcbPt
  , sha256Abc
  , tamperLast
  , withBackend
  , xdh48PointA
  , xdh48PointB
  , xdh48PrivA
  , xdh48PrivB
  , xdh48SecretAB
  , xdh48Tc1Priv
  , xdh48Tc1Pub
  , xdh48Tc1Shared
  , xdhPointA
  , xdhPointB
  , xdhPrivA
  , xdhPrivB
  , xdhSecretAB
  , xdhTc1Priv
  , xdhTc1Pub
  , xdhTc1Shared
  , xts128_ct
  , xts128_key
  , xts128_pt
  , xts128_rag_ct
  , xts128_rag_key
  , xts128_rag_pt
  , xts128_rag_tweak
  , xts128_tweak
  , xts256_ct
  , xts256_key
  , xts256_pt
  , xts256_rag_ct
  , xts256_rag_key
  , xts256_rag_pt
  , xts256_rag_tweak
  , xts256_tweak
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Test.Tasty.HUnit (assertFailure)
import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CryptoBackend (..)
  , EcSpec (..)
  , EngineResult (..)
  , KemSpec (..)
  , PqcKemAlg (..)
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))

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

expectSigLenRange :: Show a => String -> EngineResult a -> IO ()
expectSigLenRange label r = case r of
  EngineFail (BackendSigLenRange _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendSigLenRange, got " ++ show other)

expectBadParam :: Show a => String -> EngineResult a -> IO ()
expectBadParam label r = case r of
  EngineFail (BackendBadParam _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendBadParam, got " ++ show other)

expectBadKey :: Show a => String -> EngineResult a -> IO ()
expectBadKey label r = case r of
  EngineFail (BackendBadKey _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendBadKey, got " ++ show other)

-- FIPS 180-4 §B.1 / §B.2.
sha256Abc :: ByteString
sha256Abc = hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

-- RFC 4231 test case 1: key = 0x0b * 20, data = "Hi There".
hmacKey1 :: ByteString
hmacKey1 = BS.replicate 20 0x0b

hmacMsg1 :: ByteString
hmacMsg1 = "Hi There"

aes256Iv :: ByteString
aes256Iv = hex "000102030405060708090a0b0c0d0e0f"

aes256Pt :: ByteString
aes256Pt = hex "6bc1bee22e409f96e93d7e117393172a"

-- NIST SP 800-38A F.1/F.2 AES rows (128/192 CBC+ECB, 256
-- ECB; 256 CBC is caseAesKat). Generated on the OpenSSL 4.0.2 CLI,
-- cross-checked byte-identical on the system 3.5.5 CLI.
aes128Key :: ByteString
aes128Key = hex "2b7e151628aed2a6abf7158809cf4f3c"

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

mkEc :: String -> String -> EcSpec
mkEc curve enc = EcSpec { ecCurve = curve, ecEncoding = enc }

mkKem :: PqcKemAlg -> KemSpec
mkKem a = KemSpec { kemAlg = a }

-- | Change the last byte (always differs: +1 wraps on Word8). Replacing it
-- with a fixed byte is a no-op when a randomized value already ends in it.
tamperLast :: ByteString -> ByteString
tamperLast bs = BS.init bs <> BS.singleton (BS.last bs + 1)

ecdhSecretDE, ecdhSecretDEcof :: ByteString
ecdhSecretDE = hex "01d8b812087d09360c6db7f56ebc9c9799348bf951571db0390a8fd5e696c1369aedb255"
ecdhSecretDEcof = hex "07e629aca2075197a2a88ca5e4dc2c870bb32ae36a070c84bde114af867386b2a58879e4"

-- | S10e DH KAT fixtures: two ffdhe2048 pairs (pinned-CLI genpkey);
-- the secret is pinned-CLI @pkeyutl -derive@ output (A->B and B->A agree).
dhPrivA, dhPrivB, dhPeerA, dhPeerB, dhSecretAB, dhPrime2048 :: ByteString
dhPrivA = hex $ concat
  [ "3082013f0201003082011706092a864886f70d010301308201080282010100ff"
  , "ffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9"
  , "e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3"
  , "df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c93598"
  , "4f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc"
  , "0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae"
  , "56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f6191"
  , "72fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c5"
  , "8ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff02"
  , "0102041f021d009fa3ef2b4c8dfa3c47df391c7a7bc8018609291f24a761a569"
  , "699de1"
  ]
dhPrivB = hex $ concat
  [ "3082013f0201003082011706092a864886f70d010301308201080282010100ff"
  , "ffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9"
  , "e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3"
  , "df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c93598"
  , "4f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc"
  , "0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae"
  , "56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f6191"
  , "72fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c5"
  , "8ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff02"
  , "0102041f021d0147586245374ff5bc320cfe03ca2049b8b46f5eb702c9c3b1e0"
  , "5a5ca0"
  ]
dhPeerA = hex $ concat
  [ "f738b2ecbdd1d53faa936e55572f1d5304d2a1b983454250848e463dbb125727"
  , "c865d36944cd303ae8daf3855df44cedfc5352c47d090c96efeaed6f70e17bf3"
  , "60aa2248c4c6664c8713d3aa7a53d711c883f7c1493cb69e8a72068af1ab5705"
  , "097e538536523384cf237c576cc3d9acc47c26768162c1290687a596a7a6aa87"
  , "33e04354594fabad2eb42797518dcc5220194a5106195bbdba6e9e7025dd33bf"
  , "cfd1c95e8ad1efc97c0884b31079b794fba0d583fcb93096c76a17b4f8b3c067"
  , "0477c56f1ff367b1ecdfeb90fc25f7b1dae5ebc377d059a3d7b7e66e9bc26c26"
  , "5caee6fd5528c97b892eeb89842d666299c02e1344620662148952a1cc103fa2"
  ]
dhPeerB = hex $ concat
  [ "c75ae3465dfd93b6a1b50841c679448a34ef087b30edfe7c25bd9d897d105e6d"
  , "d943419867a2009eea2f0e931b1925e134468889a06d92c3a5251af1b39a4092"
  , "ba99e124f795852a9de46f85b421f4d5232d73b0b2ba42f033609789f0ca2bc3"
  , "16f79b7a64ad04f410dfb0443ebac1e8844485e9e1c3772ef0558623a9ef3476"
  , "ff8549d3a259511e0490a7b4af4f8f0b73582e1cf2bafdc43486141631972039"
  , "38e4c95ecbddf0bc638d09a12d473e5b1cc576831e43a0cb35f8561e40f5c264"
  , "d66a58f3fcc14ed3bf9a71ac134810fca2da8a98c47c3db55f05d228a9efd4a3"
  , "de7db7d1e45b79a0636fc3f6885efce43b24900b2341ef074543d54120dcd700"
  ]
dhSecretAB = hex $ concat
  [ "96cbacbfc6da3d06a280605284b5729ccce84f1896870ece31468d38f3463c90"
  , "98c303e4abc67edacbb6a78a074a869ea32e293f621ac0546214310932a024e9"
  , "1f0f9f60ff8b329cf655734012a67fb37cc03a281522b56c52944f0332810ad2"
  , "a7c4680ce64db5c13155153dfa9ece121622c9338b605441097d4a5c83da8d8d"
  , "528ceb3b2550eb6b2dfdb2f76ffa8fbcb6aabf7e93495c84c395c9e2d2a2442b"
  , "617f2af65ef63436ee5df3634b530b9373f3c985a91d4930995e1b05db29d82d"
  , "95762e42025f58f59e08c805e65be03c131016f05c1cfec08c94a046ec053048"
  , "5d3d8516e9de0a331e6ec041cc354c7b44950f1811dfe063242781d7a7fe0cc4"
  ]
dhPrime2048 = hex $ concat
  [ "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695"
  , "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a"
  , "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935"
  , "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a"
  , "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4"
  , "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61"
  , "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005"
  , "c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"
  ]

-- | Full-width DH KAT fixtures: an ffdhe2048 pair (OpenSSL 4.0.2
-- genpkey, offline) whose shared secret starts with 0x00. The same
-- pinned vector as the sanitizer @prod-dh-width@ case; the secret
-- is the left-padded @pkeyutl -derive@ output, cross-checked by
-- independent big-int arithmetic at generation time.
dhPadPrivA, dhPadPrivB, dhPadPeerA, dhPadPeerB, dhPadSecret :: ByteString
dhPadPrivA = hex $ concat
  [ "3082013e0201003082011706092a864886f70d010301308201080282010100"
  , "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d36"
  , "95a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4"
  , "617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f"
  , "57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f"
  , "483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42"
  , "a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc034"
  , "04cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733b"
  , "b5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97"
  , "ffffffffffffffff020102041e021c3c1d2502efef371d66145d353243a1b6"
  , "11a50fbd6116e82f25a6bb4c"
  ]
dhPadPrivB = hex $ concat
  [ "3082013f0201003082011706092a864886f70d010301308201080282010100"
  , "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d36"
  , "95a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4"
  , "617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f"
  , "57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f"
  , "483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42"
  , "a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc034"
  , "04cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733b"
  , "b5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97"
  , "ffffffffffffffff020102041f021d01e24035d936f9c80346520ffe08eee7"
  , "5aab53fd4a6b07dc53029aa851"
  ]
dhPadPeerA = hex $ concat
  [ "b5031e2d1102a913689788f835b01459be9c35bba5f339f2e11ac2a3b66078"
  , "d7077be61f967c4e4ac380fe0ae73a80d40cb7dcfc84cec5fd3f28fef08074"
  , "93eacefa6150f43be868d111a59f28c4fd1625cd48fca4420ca91caa372a4a"
  , "6edb4cb2059b0762891519bb357b4637ac67e724de8e9931a71aaa09ad97ac"
  , "1b56046a3efd874268a25c147d5664df5bbd4f266bc264b50b88b67aefb70b"
  , "c4218f9d49757a2c6cb77b352dc48cddc60a8c340eaf46bb7139746a9e75e0"
  , "15cb3622713785f73c779e812326af2c373434a28d1c27b2421b6c59f6280e"
  , "467854fd725a6274f1cdf1d47cae9cbd851a778c4a494acd2811b22c5adcb7"
  , "6b39abb41bd5e7da"
  ]
dhPadPeerB = hex $ concat
  [ "126a89220e681d915d9fb9cb22f8420f770923d5e81d0b340f7c4511688d13"
  , "4e92107fb8124a36672426a1fe39dba38e454472347298aaac48b4eaff6e37"
  , "dd4394ba3293ee304bba4aba969e4e856a4458f7d71c5c423a3a08a01b7ebe"
  , "587f0e90d12ab580267b4b982d792fc7410b3de152a102e88d4776e85d5a3e"
  , "ce1415b00333a9c97693071047c063d006232d1c5c6d37f85b63cd4edc02ae"
  , "f4095f9806bc21d65ad612242b8d1d3aa1b88b91dad1264d89367a8318d979"
  , "1e491edd6289c541b20436c6647af0f2d60f8a87cffd77e4efaea29f75bcb0"
  , "67ee7b4dc6bc91216ba7b32456cff5d8739c4f9c128782fdab722aa8ee1fe1"
  , "5c81d715f88aeb19"
  ]
dhPadSecret = hex $ concat
  [ "00ce799864d8059c2e77b227556aa9f7c91820d4b65fb4d45097e8f4fbbf3c"
  , "8dd8bc9bf75c0cba9b1e5974a367bb395c070411e69b14916c6513569b419d"
  , "79c64c49dff416aee8435750e450750dfc5b6d1d5695183b12cf2a47d7a979"
  , "aea27bdd575c139984e54573f5d62bf7901051ed84dc02f75c1493a2712596"
  , "f20f5a3b789d8ad902b85a36a447f3d0db556e2de7412baf9d36175809f932"
  , "ed792739a24b2d7490db6c5e30dd170d195664bced25e092cd60ad6b08b8f5"
  , "bc42d28b90e6ad310cfe7dbb3fc45e7cdca6cb34b78a0a0b3b88eaeacea633"
  , "f02704df21b2129e710119104a643629fed2592261a8a38d5b78984058ee0f"
  , "1188bbf6013c43e0"
  ]

-- | X9.42 domain triple (1024-bit DSA paramgen output
-- re-encoded as SEQ{p, g, q}; sign pads stripped).
dhX942P, dhX942G, dhX942Q :: ByteString
dhX942P = hex $ concat
  [ "ddc17b058e1ec15b51996f85eae0b678ea9bb72444159fe2fcd0f44f7be7e7"
  , "37eeebe94c47e751bcd826c53960d7e1af0f0f421f4f31104d07b13af401ed76"
  , "567b31d2ebf1eaac37c626698e60dff128c671f9055600740581508c10081444"
  , "4ffa21fada6af011260c1bc070a3d58f9a098607d92a938eff5a16fdc388e41e"
  , "09"
  ]
dhX942G = hex $ concat
  [ "d1a4428b2e04060534ad2a284a7039276bf6306a88bfde2d92332a824da217"
  , "82e30b3642625f08ca00c5997626d6733d00eafcc206afbbdafb0086ddf1d06d"
  , "4887ff77e549937bdde181e6955cec0b29e710168d891687515c1ad3e03eee3f"
  , "60f96a9063d540b7907cdb24b99dfd490e3cc447be9d47cdefde5aa30c857a9c"
  , "fa"
  ]
dhX942Q = hex "fcbd52881b3c3975a661ce18c867832617b49b0dc2c467c10c264a67"

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

des3Pt, des3Iv, des3Ct :: ByteString
des3Pt = hex "0000000000000000"
des3Iv = hex "0000000000000000"
des3Ct = hex "08d7b4fb629d0885"

-- ARIA/CAMELLIA rows (sequential key bytes, RFC-style
-- plaintext). Generated with the OpenSSL 4.0.2 CLI, cross-checked
-- byte-identical on the system 3.5.5 CLI.
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

camCtr128Key, camCtr128Icb, camCtr128Ct :: ByteString
camCtr128Key = hex "ae6852f8121067cc4bf7a5765577f39e"
camCtr128Icb = hex "00000030000000000000000000000001"
camCtr128Ct = hex "d09dc29a8214619a20877c76db1f0b3f"

camCtr192Key, camCtr192Icb, camCtr192Ct :: ByteString
camCtr192Key = hex "16af5b145fc9f579c175f93e3bfb0eed863d06ccfdb78515"
camCtr192Icb = hex "0000004836733c147d6d93cb00000001"
camCtr192Ct = hex "2379399e8a8d2b2b16702fc78b9e9696"

camCtr256Key, camCtr256Icb, camCtr256Ct :: ByteString
camCtr256Key = hex "776beff2851db06f4c8a0542c8696f6c6a81af1eec96b4d37fc1d689e6c1c104"
camCtr256Icb = hex "00000060db5672c97aa8f0b200000001"
camCtr256Ct = hex "3401f9c8247effcebd6994714c1bbb11"

-- Pinned-oracle legacy vectors (pkcs11-check
-- mechanism_vectors/*.json): every one reproduced byte-identical
-- on the then-pinned OpenSSL 4.0.2 provider before transcription.
-- DES-CFB64,
-- DES-CFB8 and DES-OFB64 have no oracle vector file, so those
-- pins are cross-checked between the OpenSSL 4.0.2 provider and
-- the system 3.5.5 CLI instead (CFB64/OFB first blocks also equal
-- ECB_K(IV) xored with the plaintext by construction).
desEcbKey, desEcbPt, desEcbCt :: ByteString
desEcbKey = hex "ae7a5bff9a66ccd4"
desEcbPt = hex "6614a40c7202bad03f5b8b962d7c6435"
desEcbCt = hex "795b284fe8a856259daa3e683e85cf12"

desCbcKey, desCbcIv, desCbcPt, desCbcCt :: ByteString
desCbcKey = hex "540b316b5cd417e5"
desCbcIv = hex "0552d668d3319583"
desCbcPt = hex "c687007ed5972de9e31b5aa7745368b9"
desCbcCt = hex "ccfec8fe28d5828eb8fce5dbd0029d7f"

-- FIPS 46-3 A.1 ECB and FIPS 81 CBC (first block) anchors.
desFipsKey, desFipsPt, desFipsCt :: ByteString
desFipsKey = hex "133457799BBCDFF1"
desFipsPt = hex "0123456789ABCDEF"
desFipsCt = hex "85E813540F0AB405"

desCbc1Key, desCbc1Iv, desNow, desCbc1Ct :: ByteString
desCbc1Key = hex "0123456789abcdef"
desCbc1Iv = hex "1234567890abcdef"
desNow = "Now is t"
desCbc1Ct = hex "e5c7cdde872bf27c"

desCfb64Ct, desCfb8Ct, desOfbCt :: ByteString
desCfb64Ct = hex "f3096249c7f46e51"
desCfb8Ct = hex "f31fda07011462ee"
desOfbCt = hex "f3096249c7f46e51"

-- Oracle rc2_ecb.json / rc2_cbc.json (OpenSSL-legacy generated,
-- effective bits 128).
rc2Key, rc2EcbPt, rc2EcbCt :: ByteString
rc2Key = hex "000102030405060708090a0b0c0d0e0f"
rc2EcbPt = hex "0123456789abcdef"
rc2EcbCt = hex "c1de66972a5efb2b"

rc2Iv, rc2CbcPt, rc2CbcCt :: ByteString
rc2Iv = hex "0102030405060708"
rc2CbcPt = hex "0123456789abcdeffedcba9876543210"
rc2CbcCt = hex "5dc06db7afa1896aa2c26c096309b4bf"

-- Oracle cast128_ecb.json (RFC 2144 Appendix A) and
-- cast128_cbc.json (same keying, two blocks).
castKey, castEcbPt, castEcbCt :: ByteString
castKey = hex "0123456712345678234567893456789a"
castEcbPt = hex "0123456789abcdef"
castEcbCt = hex "238b4fe5847e44b2"

castIv, castCbcPt, castCbcCt :: ByteString
castIv = hex "0102030405060708"
castCbcPt = hex "0123456789abcdeffedcba9876543210"
castCbcCt = hex "c5aa82a2a6c97d5cf5c5b2354db7e71f"

-- 8-byte CAST key pin: the pinned provider only (no RFC row at
-- this width), kept because it pins the two-step key-length flow
-- against the single-step regression (which answers 85126c3b...).
castKey8, castEcb8Ct :: ByteString
castKey8 = hex "0123456789abcdef"
castEcb8Ct = hex "2be46102b438604c"

-- RFC 2144 Appendix B short-key rows (same plaintext): the
-- 40-bit and 80-bit schedules (12 rounds) over zero-padded
-- key bytes. Verified against the pinned provider out of band
-- (/tmp/castkat.c).
castKey40, castEcb40Ct :: ByteString
castKey40 = hex "0123456712"
castEcb40Ct = hex "7ac816d16e9b302e"

castKey80, castEcb80Ct :: ByteString
castKey80 = hex "01234567123456782345"
castEcb80Ct = hex "eb6a711a2c02271b"

-- Oracle rc4.json (RFC 6229 section 2, offset 0) at 128 and 256
-- key bits, plus the RSA "Key"/"Plaintext" anchor.
rc4Key128, rc4Zero32, rc4Ct128 :: ByteString
rc4Key128 = hex "0102030405060708090a0b0c0d0e0f10"
rc4Zero32 = BS.replicate 32 0
rc4Ct128 = hex "9ac7cc9a609d1ef7b2932899cde41b975248c4959014126a6e8a84f11d1a9e1c"

rc4Key256, rc4Ct256 :: ByteString
rc4Key256 = hex "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
rc4Ct256 = hex "eaa6bd25880bf93d3f5d1e4ca2611d91cfa45c9f7e714b54bdfa80027cb14380"

-- Oracle blowfish_cbc.json (Schneier zero key/IV/block): every
-- all-zero Blowfish key shares one schedule, so the 8-byte pin
-- below also governs the 16/56-byte zero keys.
bfKey8z, bfIv8z, bfPt8z, bfCt8z :: ByteString
bfKey8z = BS.replicate 8 0
bfIv8z = BS.replicate 8 0
bfPt8z = BS.replicate 8 0
bfCt8z = hex "4ef997456198dd78"

-- Oracle idea_ecb.json (NESSIE count 0 via pyca) and
-- idea_cbc.json (pyca vector).
ideaNessieKey, ideaNessieCt :: ByteString
ideaNessieKey = hex "80000000000000000000000000000000"
ideaNessieCt = hex "b1f5f7f87901370f"

ideaCbcKey, ideaCbcIv, ideaCbcPt, ideaCbcCt :: ByteString
ideaCbcKey = hex "1f8e4973953f3fb0bd6b16662e9a3c17"
ideaCbcIv = hex "2fe2b333ceda8f98"
ideaCbcPt = hex "45cf12964fc824ab76616ae2f4bf0822"
ideaCbcCt = hex "2cb10d22ac22a375c0021ab6732936c1"

-- Oracle seed_ecb.json / seed_cbc.json (generated).
seedEcbKey, seedEcbPt, seedEcbCt :: ByteString
seedEcbKey = hex "630097850757e0a64b1d385a7c30a5f7"
seedEcbPt = hex "9406e50d3ae6de268202d2754f45e9d1"
seedEcbCt = hex "f353f89ce52d7929a1df5e2a37fdbf5b"

seedCbcKey, seedCbcIv, seedCbcPt, seedCbcCt :: ByteString
seedCbcKey = hex "428347c5863bd4348f1e9e2fec808513"
seedCbcIv = hex "8622f0291038b9f34217732a92697c8e"
seedCbcPt = hex "ae96f55be2bf3caeef848dda2e200a84"
seedCbcCt = hex "abe7139abb5ef24d59602b356726fb85"

-- KW-PKCS7 backend legs: the PKCS#7 framing itself is pure-layer
-- (Operation/Cipher), so these legs pin what the backend owns:
-- plain-KW encryption of padded images under the default AIV and
-- under a caller 8-byte IV, plus the KWP 4-byte-IV geometry the
-- shim accepts. Ciphertexts below are pinned-provider outputs
-- (compute record /tmp/kwp7vec.c, 2026-09-29); the raw16 image
-- reuses the RFC 3394 section 4 key/plaintext above.
kwp7_iv8, kwp7_pad24, kwp7_ct_default, kwp7_ct_iv8 :: ByteString
kwp7_iv8 = hex "deadbeef00112233"
kwp7_pad24 = kw128_16_pt <> BS.replicate 8 8
kwp7_ct_default = hex "ef396379694a053b17db8e6a5370ee86ff17cf6ca7ba13dfdd7fb619c504f657"
kwp7_ct_iv8 = hex "b4cabb493c3bec3d5b0b82ec908a36dc913bc7ca3f5e050fd929b2159085a308"

kwp7_pad20raw, kwp7_pad20, kwp7_ct_raw20 :: ByteString
kwp7_pad20raw = kw128_16_pt <> hex "aabbccdd"
kwp7_pad20 = kwp7_pad20raw <> BS.replicate 4 4
kwp7_ct_raw20 = hex "8ec9cf063015a788404dcac6013f7d912e9588d8f99b5b74d366a4449f1cdf58"

kwp_iv4, kwp_iv4_ct :: ByteString
kwp_iv4 = hex "deadbeef"
kwp_iv4_ct = hex "dab104833b678215a9a94db94422e5ef"

-- | Point-at-infinity fixture: Wycheproof
-- @ecdsa_brainpoolP224r1_sha224_test.json@ tc360 (invalid,
-- PointDuplication/ArithmeticError), PKCS#11-shaped exactly as the
-- lane sends it — 28-byte SHA-224 digest, 56-byte raw r||s with
-- both halves in range. The verification math lands on the point
-- at infinity, which X9.62 §7.4.2 says REJECTS; OpenSSL reports
-- it as an internal error (rc -1), so the shim must map that one
-- degenerate-math reason to a mismatch verdict.
ecInf224Pub, ecInf224Digest, ecInf224Sig :: ByteString
ecInf224Pub = hex $ concat
  [ "3052301406072a8648ce3d020106092b2403030208010105033a0004d4b6e51"
  , "12406fb743b6bb55f49ea2030d904420831ebddacd67bba89652265384b75d85"
  , "0e7c27f4e33ed6c576df0ff969470a9ef25ffafcd"
  ]
ecInf224Digest = hex "753bb40078934081d7bd113ec49b19ef09d1ba33498690516d4d122c"
ecInf224Sig = hex $ concat
  [ "6be09a551321b343150c1812bae87dcc688b5e25b6ef5e51d2d3c9cf47eb11"
  , "8e0cc1222cb8b2bab72745a932f05ce96e79f4e98be1e2868a"
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

-- | XDH KAT fixtures: two fresh CLI pairs per curve (pinned-CLI
-- genpkey; the A halves are the KeyImportSpec goldens) with
-- pinned-CLI @pkeyutl -derive@ secrets (A->B and B->A agree),
-- plus the wycheproof tc1 exchange vectors per curve (external
-- KATs; the tc1 bases assemble through @montgomeryPrivateDer@,
-- whose framing the import goldens pin independently).
xdhPrivA, xdhPrivB, xdhSecretAB :: ByteString
xdhPrivA = hex "302e020100300506032b656e04220420107c0296168df7ef1da8bf471f5ac2d793788e84eb8b34d86a2605b2424d0847"
xdhPrivB = hex "302e020100300506032b656e04220420202ea3672e47f763457157ae6915e4ac327f6120a8c1551ae73813d3b3c92175"
xdhSecretAB = hex "a52e5f55676e562a916a32f95cfc05671e85f17bd5975647dcb09eec6418073c"

xdhPointA, xdhPointB :: ByteString
xdhPointA = hex "684cd5fbe3473e3cb8dc7263ec9f0a837d770e5c9e2db619c8e9b0294b0e991d"
xdhPointB = hex "67d790586fcaf48d1628ec7ea2be1281c6cf1e599fffbd059ece5c521143ab7c"

xdh48PrivA, xdh48PrivB, xdh48SecretAB :: ByteString
xdh48PrivA = hex $ concat
  ["3046020100300506032b656f043a0438f0b746caef9d715d94ecf3cc83b6b5caf0140402"
  ,"ff06b3043a56f2904b1594350ce4b7523116d8422a97365bb37c3f11f746e4765e71efad"
  ]
xdh48PrivB = hex $ concat
  ["3046020100300506032b656f043a0438d89fb4cb38f9a4196b39873961f8349f729865ac"
  ,"74ab6f4fee94ed46a668c8b19f38cb4b936dcb68253ebec18a7a4a16565f60b86e5d18cf"
  ]
xdh48SecretAB = hex "d361d60928257b80eb3709a87502c6b5a1d0959533690a29d3af730824a55f3bfb749afe176ca5e4c62dd16a0c17f283dc46ace3047aee2a"

xdh48PointA, xdh48PointB :: ByteString
xdh48PointA = hex $ concat
  ["a661ed99e0dfbb6c4985d6affe9247682f0a809ffab3e351e1142820c636c30c6947fb4c"
  ,"69833ba7e4ec2ec0638016f5ddbcd72e77ebf670"
  ]
xdh48PointB = hex "20ae62a605737b5568b8423ebc0f1479b088c8bb1c2d10de702ea71b179e694d1e87c51ca1b2817e05387e4ca918ae13499e64493bb99c27"

xdhTc1Priv, xdhTc1Pub, xdhTc1Shared :: ByteString
xdhTc1Priv = hex "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475"
xdhTc1Pub = hex "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829"
xdhTc1Shared = hex "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320"

xdh48Tc1Priv, xdh48Tc1Pub, xdh48Tc1Shared :: ByteString
xdh48Tc1Priv = hex $ concat
  ["e41c63d5159c89de12163fde9d04cf1f430f346b8b2c1f2a4b1f5aee63d17aec29d4b1de"
  ,"bf8b6457e7809d2b15ff9779c97becb04b824efa"
  ]
xdh48Tc1Pub = hex $ concat
  ["f8073fc01c8358362c08740c914b419847ef1e409f4e40d9440febc26f00551adb1c37c6c"
  ,"2a87d8283b8cb453e928a0d42793f72894e0f81"
  ]
xdh48Tc1Shared = hex $ concat
  ["acd496ceb5f68bf9c267196b405f59701a40ec88744b7e5e60bf8f81e8b13df448efe4020"
  ,"01750edb0b695a0512f08c572a2e356493d170b"
  ]

-- | sect283k1 ECDH KAT (pinned CLI): plain and cofactor (h=2, so
-- the two secrets differ) plus the bare peer point.
ecdhPrivD, ecdhPubD, ecdhPrivE, ecdhPubE :: ByteString
ecdhPrivD = hex $ concat
  [ "308180020101042400d5930db9e585af6e5ea746c0fd932202771cbcd2e4acd91"
  , "4ca94a95ef95c2eab736beca00706052b81040010a14c034a000400a519b87152d"
  , "fcb842c7ba62870f3c910db05aaf690bb790c2226822005de24e118e64e0731b30"
  , "b4a66a4a86ebaa58b5b0a23673ab13bcb46421ab42a4710f24c578cbbc94c7a38"
  ]
ecdhPubD = hex $ concat
  [ "305e301006072a8648ce3d020106052b81040010034a000400a519b87152dfcb84"
  , "2c7ba62870f3c910db05aaf690bb790c2226822005de24e118e64e0731b30b4a66"
  , "a4a86ebaa58b5b0a23673ab13bcb46421ab42a4710f24c578cbbc94c7a38"
  ]
ecdhPrivE = hex $ concat
  [ "3081800201010424000b81e39e6ef5ccc92df1b207beb8cd71b246ff4e57c1494d"
  , "4221f5fa91d00b01dd2f40a00706052b81040010a14c034a000407277db5580914a"
  , "8be1b6752a4abbe5e329d63243632155bd04174a611af790852d57a16079ed448d"
  , "e40bb0c7d01f3a882bf0aa01e3278b8f537397cc606b7323ef57eeb134d022a"
  ]
ecdhPubE = hex $ concat
  [ "305e301006072a8648ce3d020106052b81040010034a000407277db5580914a8be1"
  , "b6752a4abbe5e329d63243632155bd04174a611af790852d57a16079ed448de40bb"
  , "0c7d01f3a882bf0aa01e3278b8f537397cc606b7323ef57eeb134d022a"
  ]

-- ACVP-AES-CBC-CS1-1.0 encrypt vectors (prompt + expectedResults).
-- PKCS#11 names no CS variant for CKM_AES_CTS, so the module
-- implements CS1 (NIST SP 800-38A canonical first variant) and the
-- oracle auto-detects it; CS2/CS3 legs skip by detector design.
cts128Key64, cts128Iv64, cts128Pt64, cts128Ct64 :: ByteString
cts128Key64 = hex "D08FF477651FE9C084F20B2FFE50849B"
cts128Iv64 = hex "5A2623FC47B3F0D88C641AFC0DE45967"
cts128Pt64 = hex $ concat
  [ "28DE99791E5BA3329AF0C1E66DE07E1CE117A6211390F0F49F4157EBE58BC94"
  , "E4A88DD8B003A7E77B1070855138902DBDDF1BBC79FCF23056A9AB49DD25539A2"
  ]
cts128Ct64 = hex $ concat
  [ "247D046CBEA8A6A76CC9EFA0564559C19BC39869BDAFB9350ED5995469B705C13"
  , "177B7397625FD1A5B2FDFABCC9AEC131C7766F0081024F9718E781B491580E9"
  ]

cts128Key156, cts128Iv156, cts128Pt156, cts128Ct156 :: ByteString
cts128Key156 = hex "D616101E6BA31CF80E62A6EC8FC74F6F"
cts128Iv156 = hex "7E1E4E5E1A29465BF5987E5020DDE649"
cts128Pt156 = hex $ concat
  [ "25E5E1339994FD97A82CFE9B3297E52A64EE0D8914EA206052E7F217C0EF88F3"
  , "33B1E705074B38E4A025098B036EE0017A66DB17BA82210DEAE97ED1789DBCB2B"
  , "8020A12985F914006C80C35F70B4AD1B96BB47DA140F63DC48065998B3FACAC5A"
  , "01964D40996C2FE47D58B1C0E58D50830A11244917B34F504AAC058F75BD5E79CC"
  , "1B855BCDDBCA90FE94548F46877186F40F499E25797686F21B1B"
  ]
cts128Ct156 = hex $ concat
  [ "D751512C2C7548A71DAA70FDABA2A30F15EB09DF75D398A03E8CDE6F80FBE3335D"
  , "B3C98EF4188692E03BF99FF3BFFBF6FA256EE4C06B936DCE72A553FD2D6358DC39"
  , "392CD84A84F057CF77F834DD157F98F97A79187C883F6C020EE2EEA495A91EB272C"
  , "1308C19ED7402198E6FD02384F53DDDA839D55C902E8E5C01FF3B66A0FED0987D2"
  , "1834A7F36A49BC32452B2DBEF92EF40FA4BD25122B39E58"
  ]

cts192Key32, cts192Iv32, cts192Pt32, cts192Ct32 :: ByteString
cts192Key32 = hex "851ADF39D5CA81EB5ABD6043766DA706C42E3ABB74ED754E"
cts192Iv32 = hex "877FA72ED20AE32EE57BE60E86F5B5C6"
cts192Pt32 = hex $ concat
  [ "87EAA4FEAEC9803DA1B7D4F39B4146C23A1C1C47596A198A7994D80732567E59" ]
cts192Ct32 = hex $ concat
  [ "678D222A3E661C726C54B0877115921B319D2639AB00A23CC03B6A9D034EC225" ]

cts192Key57, cts192Iv57, cts192Pt57, cts192Ct57 :: ByteString
cts192Key57 = hex "000000000000000000000000000000000000000000000000"
cts192Iv57 = hex "00000000000000000000000000000000"
cts192Pt57 = hex $ concat
  [ "1B077A6AF4B7F98229DE786D7516B63900000000000000000000000000000000"
  , "00000000000000000000000000000000000000000000000000"
  ]
cts192Ct57 = hex $ concat
  [ "275CFC0413D8CCB70513C3859B1D0F729F88A422F49262C8B0B54CFD7C95DD5E2"
  , "4137195A73064E6EDB3EC9A5446C99351A26B06CF7DC930E7"
  ]

cts256Key66, cts256Iv66, cts256Pt66, cts256Ct66 :: ByteString
cts256Key66 = hex "8E6635BB59960919CDD8BAA3DEF14D7AC38D86882539A5CCAF9FE27B3B6D9C78"
cts256Iv66 = hex "BFBD702277C2FC416FB27656A011B6A2"
cts256Pt66 = hex $ concat
  [ "8E1B6C9FCCCCC84546955C1C8FACE0522DB2C43D8A44BEFA06028722DC50AF29F4"
  , "494FBE437A2D87CA10CDE334ABCE36C1BECBEA9791C2DDDAB01AFA539355137890"
  ]
cts256Ct66 = hex $ concat
  [ "3CEA9005FCA1DEEFDC800A271C06868A2068B0145084B8C1F400B8418C2AC38E20C"
  , "B26B674FB629DF542EC152CA36998494514902C77AB5E620C0517B0E53E7210F1"
  ]

cts256Key19, cts256Iv19, cts256Pt19, cts256Ct19 :: ByteString
cts256Key19 = hex "2A88FED687FF2FC5E920DD98100DB031057A847758A12FF5D1E63579CE21C0A4"
cts256Iv19 = hex "460D42F6C44BF495DFCB7D6855C60F0A"
cts256Pt19 = hex "E325A505A54F7CCB859B98F440C67B14444B89"
cts256Ct19 = hex "8752AD80462421DC5E5ECA1EFAA9790E4B398A"

-- ACVP-AES-KW-1.0 / ACVP-AES-KWP-1.0 encrypt vectors
-- (internalProjection.json, kwCipher=cipher, direction=encrypt).
-- KW legs: 16B minimal + 72B multiblock per width; KWP legs: 1B
-- minimal + 269B ragged per width. No IV (empty-IV, ECB shape);
-- output expands by the 8-byte wrap IV.
kw128_16_key, kw128_16_pt, kw128_16_ct :: ByteString
kw128_16_key = hex "8F684992A8BCB568DDA90ECF82D0EDE7"
kw128_16_pt = hex "E41B0CC0CB58B9A4EDBCC6057748A1CF"
kw128_16_ct = hex "CA31B1B6FA7C9C1152524421924555EDB25AC702D73037CD"

kw128_72_key, kw128_72_pt, kw128_72_ct :: ByteString
kw128_72_key = hex "A51BFEF0E23F74C6EE45E50E52D52159"
kw128_72_pt = hex $ concat
  [ "604A42E9A00001C004351C1BF84BBB35D1C47416E6B0DA4C47D8C2F9C0DEE578"
  , "3536D11AE5957582EA8D6FB98C08BA439DE12EE0A7E8093165277E1683EC4E73EFA924B28E591700"
  ]
kw128_72_ct = hex $ concat
  [ "F83C0E64F45E609F399DD66A31F830BC6DFBCBF60CBC30507AB370EA64D371B1"
  , "493C3F1329DFBBA05FF7DA4D920A56B2340B5C92301B15E103717A6FE674654376336FBAC0C563CF1FB6CDC02353E7D7"
  ]

kw192_16_key, kw192_16_pt, kw192_16_ct :: ByteString
kw192_16_key = hex "DAA150E331CA487709620A9E62E06FFD16905801B99028E6"
kw192_16_pt = hex "0F369E5B9D2DD76F9457813DB1E76DFB"
kw192_16_ct = hex "319A65CE21EECE1325955A27191C917EB806EF0D1D6B8FE1"

kw192_72_key, kw192_72_pt, kw192_72_ct :: ByteString
kw192_72_key = hex "D616A4FA0FAAB6C8180F2C608173B897EDF98668B502D45C"
kw192_72_pt = hex $ concat
  [ "1FE4625EBDE2E2F36A9BC9E0845D38184619EC67BCD3DF26912F6F923BFD1A000A1B1CE72DD82CBEB83119BDEDAD4D7F662396BC293D3D3BCB8F36E9A09A258359B78DD1DD9F3BDD"
  ]
kw192_72_ct = hex $ concat
  [ "4482CD60BA9F9AA30B60897E2F3E821284F4E3971C9B72E4DB2B445576D25EF815E1B4BA3914EFDC55AA31A41878DBB3CE8F4776BB5371ECF6BE5C9EC80B2E4C9177DE28F202F811B0788E10E8C47299"
  ]

kw256_16_key, kw256_16_pt, kw256_16_ct :: ByteString
kw256_16_key = hex "CEC66703B9DEC70887BE1C30D4DB1CCFA7A0B24906280B87FA078BAB1DB4B097"
kw256_16_pt = hex "5207914442601FEDD22F274C17975B27"
kw256_16_ct = hex "C949844B62EA0B68250687291E4EBA6E3FA2693B7018E3B6"

kw256_72_key, kw256_72_pt, kw256_72_ct :: ByteString
kw256_72_key = hex "D6CAEB95C7DFC07392DB74BD6E37433B9DE1ECF68192B58678BB020C709C391E"
kw256_72_pt = hex $ concat
  [ "9D918A3A7D3F629DFAC5EA0ED8590A31C7F90F5EFD00165C2758B0773C7F4F0E30BA2937D911BCEB9AE3F3224BFC0A5EA9EAA7DCBA8D97C7C9644B392AFD81EEE8350BE2B7B41C6F"
  ]
kw256_72_ct = hex $ concat
  [ "6115034CC3CCC8ADE9C88BB32887144F21D5E7B72F32A8E891D734D29901FC9E4F1A8AA2B4C91EFA4A3D4D6DB798DC5902774A8E2A5AC5ED664C08BA1F55FAA02BCC15C681A12CD078D2AA409C9B6E74"
  ]

kwp128_1_key, kwp128_1_pt, kwp128_1_ct :: ByteString
kwp128_1_key = hex "045779F345ECF100480481C9A2FB7219"
kwp128_1_pt = hex "f0"
kwp128_1_ct = hex "867E3EDFC4B327C6E01072E95DA7E071"

kwp128_269_key, kwp128_269_pt, kwp128_269_ct :: ByteString
kwp128_269_key = hex "D953348EC9BDB24EF56DFE62C3C10750"
kwp128_269_pt = hex $ concat
  [ "4B69C751243B1F9AABEDCD94552644F35F66525CF58DE694B7F93E64C8D21ABA9DC7413E4C53EDC4524738F74C40B14871E94140B9EC598DA714A5110071E2E3E519D5076EB6DCA1A70B484F1A8DA85C0B3ED6ABB5FFD472CFB0F429F494D09A965385F49CBC864794F7408D5F283E9C3E99A6D00C78376A0E71C4F5FE7198E799A7775829E7F6B10FE224ED6AE2E493A5F39B8D7C69420EACAFDB926E962AB8E4AA6F43BBE38FD926223A4F87E319E904328B292A7D9108EB333CB9C01CD44931ABD183CBE9C6311CC60A0D722E42E9689CAF42DF5C64B52E3B2C8215ACA03030AC7DC9CC8286B4756B858F32C04417B55165614D04F5AF759D06529D3B9DA2553DCEB645F73ACEFEFD46D50B"
  ]
kwp128_269_ct = hex $ concat
  [ "3EC7F5257C7BA8EDFC13CBEB3468226B94471C50F5C7B0DDB565209D3F3A81EA6D6A7C53074C3CEA94FAD159B2C1F6AE736D1853377F67135EFEF4A08E882FAC9F4846B31E92709D4D10E69F7CF9B9C8057C1ED4E758EFFE0C76EA85658EC1CC29C13682F194937083C60C5F9E72154089735E19AFB8CAB86E4232ACB4D1C91C54AEACDE5AFB1A9FDB0537FC6FF968227B9BA23BACC7813C9D40032A40908577A3C33550A7E20BEC9F85F5836936A1ED6F9AFB99813E035898A6D14146956697256A2B1DD4AE90B9D496C44DC848D5364C180CDC160C2A047B479C4D320912D64D8578C2EDA56A01CD05DB3C2137D19C30293526BE90230FF5546B560F9C62D541C75B8D78BDF4B1E4985452067259D4B92600EBC68814C0"
  ]

kwp192_1_key, kwp192_1_pt, kwp192_1_ct :: ByteString
kwp192_1_key = hex "50037744E6DC3F21729497550A0D277858188AD5584AC489"
kwp192_1_pt = hex "1D"
kwp192_1_ct = hex "B3EAC3B55425309A94EDBB4D9AF45894"

kwp192_269_key, kwp192_269_pt, kwp192_269_ct :: ByteString
kwp192_269_key = hex "5165C133705476947523330CDE4C734561E9AD3387D0F599"
kwp192_269_pt = hex $ concat
  [ "A220A41F0E30A7193A272C6065AA21BCEAFE1C39981288403C0BF255938231BA226562089B3F155ED6201E5A577003DAF9700218D60EC104293F5E238F7D39598283D169841B2DEC16F2485A17B17F9A2F81D3CCDBB33EF3CFE624C82B2C511E7A350CD70B335BCD3DDECB140290EB4D088A50E09CB38F8E5ADC9CE0E86BCAE2074AEA02FE88257F626F806A4199D06BC70C33F60E586864380B5F30B2BE3CBD480DADD2FCB2593C805E390517C899BA0D4F9E252813EFB51DE6B558C4A5DE9B749832DB53DDBB65325C09FE0E864BEE6324D69159B1567BE801B0B7188B998A5C478B63B6FDDEE3E0F7D67F8FD8B6CD9ECEE45E2F3BE2FFFBE9D832C09C5D08DC99D6C453E9BD478205CC3BB1"
  ]
kwp192_269_ct = hex $ concat
  [ "3CEA6ED129FEEAF73E6BCA72D914B2C7D9397CD8A365DCB890115471C2FDE98DA527DA23D4860FE7D3F90EC2CA19AADFCAB53AAADD33B8A87750E995FAF90431227C912651D7FC2F462A893075909D57C453060EBC91E8DB5BC8F9745316CFEA184E3BB915C169992CE0C80D98805B02605199B29D3FB7FBDF2518D47FBA6EE8F194CE24224F2385D06CC94A1F72A1DBB0B2FFE4B2CA825021E781F7EF523FCB0BC98F8101AAC53FE50AB6E2B7A62D0F1F977948A048FF0712CCC425EFD41BAFBEBF7818A06A9E238F93B8D43B5012CD2976A6A5C188047D4D6A50E6B12DED906D9BCC5A4F9D3FFAFA0AD3DF0CD7AFCA4E113B9D7355437D38B40D5C1823C677DACDD1562F24F64ABDA4C5B38D0164C15FBB91A5BFEA4E0A"
  ]

kwp256_1_key, kwp256_1_pt, kwp256_1_ct :: ByteString
kwp256_1_key = hex "CBACADE82EFC97AD2EE38B19F955DBCB1178ADE01E78C30676FD27AAAAE9D8AE"
kwp256_1_pt = hex "C0"
kwp256_1_ct = hex "462A7E8D992594F6163BD7A24C0FE4E5"

kwp256_269_key, kwp256_269_pt, kwp256_269_ct :: ByteString
kwp256_269_key = hex "CE53CBA5CCF56762F664D3487D46CE30C88B14242E084173900C4189774FBB29"
kwp256_269_pt = hex $ concat
  [ "65A836920C1345356B77330B7A3F9D516CB801AB8E268B4CB32DBBB6DC7A5BECFB9F8D47E76DE387A383719306201EB4A35CB105AD6548F2EF1E00F09AE9B8DC0B3A2B99F341AD1DBEAF11D6197B6BB41D569F9456662727398188958BA236B5598A0F72D43C0A43F0086CD58C817378B48B92D19E12661AACFFD5FE849E252A849E588CF41F3FB0273DA7BD81D4260E7F0D33B1CDBA53B217039113ED328097C5EEA9B390F286E83D5F8BF2C47E1E3E13C3300536EB192E52E87F7A077C10B32F6B3CA0123AD2AF136A9DE6E9A59B977E9890FDE5B003028EBCEE62A29952DA4574985F159DD6A4C015B539EDA7EA404B211459565528C7CB513DE9DE93C5C9A38A8ED3E5E6B893F1E7530E78"
  ]
kwp256_269_ct = hex $ concat
  [ "9CF90C5CF0364383D94748245C6D727D058BD18CF35BFF30EF9249A6990526B83328EAA9E0462396EAEDF905696853A21909294C52D34DAD0DD9D49363B9082289DC15FF6D3AD9814877492BE56F292CF640FD85CFBD2D6D311942E2049126A6366E0E9303730B5537962372E8C66827B67F2CFA4995871320541A694E0F5DB3D4DA897023DBA6B9BAF289368339ECC56536E865BBF0AF059B88EA4D758F4F4AC758B3A2120C03A98F2E73DD29AD4436D8055FF596F46412CC9DE54245C0269BB9082D2017CC9672340AEEB4C74949B6C7112BC58242DF18B527DF7A12C5F3E32A7F6A382B022F1270FC76234D4BA1D0269378ED51D9A896437DF2F709EF285AF432D2DB047A202A4D087C4D96689D08333C240737B03D62"
  ]

-- ACVP-AES-XTS-2.0 encrypt vectors (prompt + expectedResults,
-- each cross-checked against the `cryptography` oracle before
-- hardcoding). One aligned (16B) + one ragged leg per width;
-- keys are double-width (data + tweak halves), tweak is the
-- 16-byte data-unit sequence number.
xts128_key, xts128_tweak, xts128_pt, xts128_ct :: ByteString
xts128_key = hex "8ACB99D1D215612314D6B262147343F23F1B1E8F34F1DCBD6D57200FAE54E8C4"
xts128_tweak = hex "bf0d3404d7bce2b4132d02e90a256ebf"
xts128_pt = hex "EA29098CB827A1DE9D69F5B47A500C34"
xts128_ct = hex "7A4CC60DE7997471AAB765348F08D935"

xts128_rag_key, xts128_rag_tweak, xts128_rag_pt, xts128_rag_ct :: ByteString
xts128_rag_key = hex "6FA0AE27860CB658B40A3D95666954442E418EE3E4565657DD08EDC69E20E5D2"
xts128_rag_tweak = hex "c7c71ac8a3f858145b9ba0e658491af7"
xts128_rag_pt = hex "316F416DD8828155AAFE1EFA50361D48613E073E1B4B66B00D86A908626157D3058DCB83B1B6833580AA2F4A0663DE87115027F5F4EB60FCF2F2235BB801"
xts128_rag_ct = hex "74FCCB3C6FA20BAE9D1FBA9525519A5AEBB0BD4F2803A40C4EC0D80FBE3D5ECF53EA3D8C7456D23B4FD7772C4BC44B06C0C7A533E53747A4CB94927D4572"

xts256_key, xts256_tweak, xts256_pt, xts256_ct :: ByteString
xts256_key = hex "9D9674635844373FBAC65EA8FEFCCF4BEDB7B1845C89DC1B28B343FDCD5DF7AF1C0A96EDEEAD069C6666B741153FA3F367AD7538F9615C348462115FE09DA571"
xts256_tweak = hex "eae1092e65f917efaf69e01740494551"
xts256_pt = hex "0873E8A1EF36F962EFAAE5B9BD617D39"
xts256_ct = hex "6EA0F22583C4C6397ADCAF702A08C27D"

xts256_rag_key, xts256_rag_tweak, xts256_rag_pt, xts256_rag_ct :: ByteString
xts256_rag_key = hex "DCF8C5F5AC2FF90719DF2DCBBEE159C53C44E80BCFA95C718C659C4E8F6FC0A4C85A9E3C16527E66BDD924C13EC8314987F0F3E89089007B34DC472B95B7E03E"
xts256_rag_tweak = hex "7eb2097b64cc3bccad39608427ecc1a5"
xts256_rag_pt = hex "A06B93F02AE1B52F2D7995D024914DD490320670AD610F5B4BC91E"
xts256_rag_ct = hex "87E96FCD94D73BA5E2CFE45A96BE469C2A13CE2F621CD76FC1C875"

-- ACVP-AES-CFB128/CFB8/CFB1/OFB-1.0 encrypt vectors (prompt +
-- expectedResults). One leg per mode x width; CFB1 adds sub-byte
-- payloadLen-10 legs with oracle-defined top-bits masking.
cfb128_128_key, cfb128_128_iv, cfb128_128_pt, cfb128_128_ct :: ByteString
cfb128_128_key = hex "8E5D75D976DB6983954B54C1A714E135"
cfb128_128_iv = hex "A610F1879CDD7B3D1267E51D55ACFE87"
cfb128_128_pt = hex $ concat
  [ "531F2B906CFFE6541BDDE16F267D7481A62DA1A6462525D1A05E878332971BF4D"
  , "60C9ACA2DA5B42F04BCFF9CAC0AE21D"
  ]
cfb128_128_ct = hex $ concat
  [ "04F436D93655427BB495029F789F72B597CCEBEC6FE927BF1B08FE29AC05CCCDE5"
  , "AED842AE89C8D858736C1772760FD2"
  ]

cfb128_192_key, cfb128_192_iv, cfb128_192_pt, cfb128_192_ct :: ByteString
cfb128_192_key = hex "D86D60ABA397596E00FC643E5CA178679F92127470514715"
cfb128_192_iv = hex "4B82C289E366F05F5F23E4D2B8E48ED2"
cfb128_192_pt = hex $ concat
  [ "31DA4A73E7BF25ADAB8778AD607F1B5DF733DB2A7C213AAA97CB91DD913A5A501A"
  , "C12ABEF450A2DB27E060964B103230"
  ]
cfb128_192_ct = hex $ concat
  [ "5325ED26C6695717E7813790CAB764F43C60C3B8882AC1F3DEB2FA5A4E1E784DFD"
  , "E4CB4BDAA8F500DD470AB08F71C312"
  ]

cfb128_256_key, cfb128_256_iv, cfb128_256_pt, cfb128_256_ct :: ByteString
cfb128_256_key = hex "193477C335697BA0FA61FDA15AE1E4BA9D0D76EE5EA4552EE5DD22759FFA2EEE"
cfb128_256_iv = hex "B335E95FCD2983A349165581C1A8E9A6"
cfb128_256_pt = hex $ concat
  [ "0F98CBBE70A5EB2A244703235869816B8CF57CF097F93EE4F2E8692193A0E8FE84"
  , "550ADC4C70B01AFD0EE79D8848164F"
  ]
cfb128_256_ct = hex $ concat
  [ "37D20635E92B613C7A36FFE827B4C74D75D5E2A92965C8850380F5E1340D8C17CF"
  , "98B53D98372AABA4C286D956DEC1F7"
  ]

cfb8_128_key, cfb8_128_iv, cfb8_128_pt, cfb8_128_ct :: ByteString
cfb8_128_key = hex "D8B5B55196BC7BA12C1A3F383D53055E"
cfb8_128_iv = hex "59866908DB5E9CBD8188E5BB11228E91"
cfb8_128_pt = hex "746C1B57DA68713B3826094A9FE85DC2680AC7C696457074DD44704D99D5E48B"
cfb8_128_ct = hex "4EE17694BBFC7EF4CE603CD14D5E8EBDF1AB7BD84F2A7C4E4E1577B81205DEDB"

cfb8_192_key, cfb8_192_iv, cfb8_192_pt, cfb8_192_ct :: ByteString
cfb8_192_key = hex "9A3E3FCE8BC21CCBE4893470234F48845BD1B4AE23B3BCF8"
cfb8_192_iv = hex "0419D52672D4C61B4924E09A5347C0EF"
cfb8_192_pt = hex "602562FEFB49745E2A185A3651AB98B9C8F8D92FCC2741AB23DCE4C7A6EB08F5"
cfb8_192_ct = hex "C5D1E776F3F428D592A3116A6993C10E0DB63737775D2A77200262A1EF8DDD21"

cfb8_256_key, cfb8_256_iv, cfb8_256_pt, cfb8_256_ct :: ByteString
cfb8_256_key = hex "880B1086E6326896D02DCE97C04DB55A10BD17F97F257374265FA3A1AED8495E"
cfb8_256_iv = hex "2306207DE21D456E1B4E2DD21419BC54"
cfb8_256_pt = hex "25E3EDD024537E3B009FA356926CCDBEEFDBAA5E77E23775DB34D9646D683673"
cfb8_256_ct = hex "267A52D8B3C6BE04FC16412A99682089CDD17328126A5DF6B3E78C4DE8F2B3CF"

cfb1_128_key, cfb1_128_iv :: ByteString
cfb1_128_key = hex "5ACB11FB4A72B089C492D6C8B3636E95"
cfb1_128_iv = hex "0E9BCCA0A1F1A840D0C9F6FB6FCD4B6E"

cfb1_192_key, cfb1_192_iv :: ByteString
cfb1_192_key = hex "5E763B08CE4A24E9059E134F8DB68A6500C847B4A1876ADE"
cfb1_192_iv = hex "F2AB1305D9D681A02DE6D6C0D9CC3E53"

cfb1_256_key, cfb1_256_iv :: ByteString
cfb1_256_key = hex "A2C614B71BE9F438C472A9DACB49865DE2516AE353AD0E7453E8731799DFC0A1"
cfb1_256_iv = hex "9FD31916DEC92DB8CBB390ABD3ADDA05"

cfb1_128b_key, cfb1_128b_iv :: ByteString
cfb1_128b_key = hex "CA8838F0F0E94106A9FED0120A79C2B3"
cfb1_128b_iv = hex "A6070E04A2DD5C1CA26B279E2EB5183C"

cfb1_192b_key, cfb1_192b_iv :: ByteString
cfb1_192b_key = hex "B33C80CCCB7E2D9C272E3052D7A1D300661A33357670403B"
cfb1_192b_iv = hex "52F67B2D4A2C21E9AB33BC8BF6E2D07C"

cfb1_256b_key, cfb1_256b_iv :: ByteString
cfb1_256b_key = hex "01416CB918CAD2CEF6AC40B2E2CACC0B976A91EC40902F9185B5622055FD9B3F"
cfb1_256b_iv = hex "1B263E429DA5F706A62DB54AC45CE040"

ofb_128_key, ofb_128_iv, ofb_128_pt, ofb_128_ct :: ByteString
ofb_128_key = hex "055B701A06741E45FF8F9A0AB72AD4C8"
ofb_128_iv = hex "D3B99DB990F923FF0C46A41D810B2763"
ofb_128_pt = hex $ concat
  [ "CD49B6830E22C3C08B5965175C21885F47C62E3A67CC558A3DABDB54BAAE58715D"
  , "003F096A6E293395D8E75BFE5BF1DAE455B80F9C32C90C5321F23755599872"
  ]
ofb_128_ct = hex $ concat
  [ "D0C883857DC4DE820D76E115A74274EFFBF3DD364E27EE57050BF161F5AAE2F498"
  , "31DCAD7F1E464728B59A9E59C655552D5D91219D8D88F320F4681925B8CAA8"
  ]

ofb_192_key, ofb_192_iv, ofb_192_pt, ofb_192_ct :: ByteString
ofb_192_key = hex "1737AC3C014C74E20F6254A71C9165D311AE21D2DDCF8F74"
ofb_192_iv = hex "F4BFF3A113C0C63732BEB6E77216EB9F"
ofb_192_pt = hex $ concat
  [ "18ADD7BF57AA00844759AFA1B468C81592D170A335DFE50A7D0D91729B32F8C7D8"
  , "60A5C96206B480058987019BE2E0A220BD04D69668D5BE773AC60B2A050ECE"
  ]
ofb_192_ct = hex $ concat
  [ "E7765838AF94B62C494C6E0C5D43E6D1BD6DCA82E8C90BCED23AA2FFF3B250E5F"
  , "9D86CE055EABD6951EED2B2E6901D1D0DDE9329F4ADC66D3B48906476713A34"
  ]

ofb_256_key, ofb_256_iv, ofb_256_pt, ofb_256_ct :: ByteString
ofb_256_key = hex "FAA7B060B20C10D6700D13718CA610223688BFD4D49C5CF5CA10992CD93F6494"
ofb_256_iv = hex "83922A2CC59B353517FE3965DAA9BBCF"
ofb_256_pt = hex $ concat
  [ "1355175F24941D4367FFC922900045B12A13A43E3ECE241206D5F4CF5078D5392F"
  , "A471D2573A35DAC7FDA3F8AF62CBBFE0E9A4AF79933984276F99596FE5410B"
  ]
ofb_256_ct = hex $ concat
  [ "56A0EAA8290D0DE9EF6C382E33327D108D04793AE3FE97933E5AF1F0A617C28E0"
  , "0C07BD84A498EF39C6C33668F044FB7C10C2F4383BE61F20212210025B90666"
  ]
