{- | OpenSSL RSA cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Rsa
  ( caseRsaKats
  , caseRsaKeygen
  , caseRsaOaepVectors
  , caseRsaPkcs1Vectors
  , caseRsaPssVectors
  , caseRsaX509Vectors
  , caseRsaX931Vectors
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Engine.Backend
  ( CryptoBackend (..)
  , DigestAlg (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , OaepParams (..)
  , RsaCipherParams (..)
  , PssParams (..)
  , SigSpec (..)
  )
import Haskoki.Der (integerToBE, rsaSpkiFields)
import OpenSSL.Fixtures

-- RSA-2048 fixed vector (OpenSSL 4.0.2 CLI genpkey; PKCS#8 +
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

-- PSS/OAEP interop vectors (OpenSSL 4.0.2 CLI, same RSA-2048
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

-- PKCS#1 v1.5 interop vector (OpenSSL 4.0.2 CLI, same RSA-2048 key
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

-- X.509 raw-RSA interop vectors (host 3.5.5 CLI, same RSA-2048 key
-- as the v1.5 vectors; raw RSA is deterministic modular
-- exponentiation, so the bytes are version-independent). The
-- 32-byte message left-pads to the 256-byte block; the ciphertext
-- is `pkeyutl -encrypt -pkeyopt rsa_padding_mode:none` output and
-- the signature is the private-op output (`pkeyutl -decrypt` with
-- rsa_padding_mode:none — the CLI sign path refuses padding none).
-- Both were CLI roundtripped before embedding.
x509Msg :: ByteString
x509Msg = "x509-secret-32-bytes-payload!!!!"

x509Ct :: ByteString
x509Ct = hex $ concat
  [ "a7f6abc64915f4386b2e119279cd401812c50abef4e3793b73274b4ac45c1e38"
  , "57d58688cde8de2175138d9d93514d5f42f3ca44ee46ebafdac354d130deeaa4"
  , "d78986ee865932e3c83820ee94300c06d0e235ad244dbcc35ca2b938ec6a6291"
  , "7d931b784c6f0e801de6076e704ac4b71ab685f84875d5b9b2155a36f704621f"
  , "f9758a41629a99be36b66fea0c98509571ec902f6ec018e4ce5fe9d22657192f"
  , "f6ede732ce8f7acdd38781ce7250f17b8e2757d929650dd69de55ad2f46f0727"
  , "81357a7f2952d9f739feba0021a4168041f4ebea0cce69f1eb18de1a82e77910"
  , "5ac7565685b880b4b008a350e52ceb90ac9c7b6d48d621a1f7c238db0c43b76a"
  ]

x509Sig :: ByteString
x509Sig = hex $ concat
  [ "7b62d8db852ec3c1ff4b3c5b61abe1db40e29f17a778888a88e7aa69087a6304"
  , "2976e27207d690a66f5becc18562f95ffabe90429ed817a4ff02b1662dafb24c"
  , "1ea340bc7df8cc8aaedd568d417238653f5916ae0aaa1961a27501dde8aead57"
  , "4565f396f80b77050476e7192069e4fc08ae65ad826b64219e5a34030786ea90"
  , "062b5721f2f502758891f68587762f48c94617db402062b5bbb7461f3229b4ae"
  , "348d871d7f8f2e6d65110a3378d444c409ad2e92dc35b7c844616fc4641dec01"
  , "d2b287d34a706b196c8b21f3d8a421360b4e811e5a399ab5b994b426a5bc9d8a"
  , "8627519be535674cb4a09d02eede177143a5e7fde37b1ecdb2a9efd1ac20048a"
  ]

-- X9.31 interop vectors (OpenSSL 4.0.2 CLI, same RSA-2048 key as the
-- v1.5 vectors; X9.31 is deterministic, so the backend replays the
-- CLI's bytes). The digest is SHA-256 over "T16 S7 X9.31 KAT
-- digest input"; the signature is `pkeyutl -sign -pkeyopt
-- digest:sha256 -pkeyopt rsa_padding_mode:x931` output, CLI-verified
-- before embedding.
x931Digest :: ByteString
x931Digest = hex "0281e0bf4eddce53c3ebe418aaef70f85fdbd3fbb7b736683ea4b6acdbdeb0c0"

x931Sig :: ByteString
x931Sig = hex $ concat
  [ "456576fa9624988d3210f3fa2ef1d859e469e742852f0861caddaed79eda5b10"
  , "099db855968d2a894e79b8260ed42d3da606a383fe88579b31d41dae5d258d18"
  , "1a62811e34250f9a0c25ae65ae760948b829cab8fbc054472f91ed02b9f8c1fd"
  , "cfaf68ade709d3f3a1312bf8cf4b9e35f9f2d0e15cf0cb84cc8e1ad40800b619"
  , "185dd6e9749f157e2e4a5ef666633a5e4d31ee60cae1941205c1e8deed18494d"
  , "c17dd63f0dac58fdc03863a900a568b877f9693e689d6649285419d34fbc6ca1"
  , "ecd808dd9f404e38da6275905867f80f7fc08c2b35ee6c3717426e48bf28c3c5"
  , "0b1cb683efa07322a713d1e7a0371ae78450c1390df6f95760c9e50fd225e400"
  ]

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
    verify env sha256 pub rsaMsg (tamperLast rsaSig256)
  expectAuthFailed "rsa-sha256 wrong msg" =<<
    verify env sha256 pub "wrong message" rsaSig256
  -- Raw KAT: block-type-1 over the input, no hashing.
  rsig <- expectOk "rsa-raw sign kat" =<< sign env SigRSA_Raw priv rsaRawMsg
  assertEqual "rsa-raw kat" rsaRawSig rsig
  expectOk "rsa-raw verify kat" =<< verify env SigRSA_Raw pub rsaRawMsg rsaRawSig
  expectAuthFailed "rsa-raw tampered" =<<
    verify env SigRSA_Raw pub rsaRawMsg (tamperLast rsaRawSig)
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
  -- Wrong-length signatures refuse by length, never verify.
  expectSigLenRange "truncated refused by length" =<<
    verify env sha256 pub rsaMsg (BS.init rsaSig256)
  expectSigLenRange "overlong refused by length" =<<
    verify env sha256 pub rsaMsg (rsaSig256 <> "\x00")
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
    verify env sha256 pub pssMsg (tamperLast pssSig256)
  expectAuthFailed "pss-sha256 wrong msg" =<<
    verify env sha256 pub "wrong message" pssSig256
  expectAuthFailed "pss-sha256 wrong salt rejected" =<<
    verify env (SigRSA_PSS (PssParams D_SHA256 D_SHA256 20)) pub pssMsg pssSig256
  -- Wrong-length signatures refuse by length, never verify.
  expectSigLenRange "pss truncated refused by length" =<<
    verify env sha256 pub pssMsg (BS.init pssSig256)
  expectSigLenRange "pss overlong refused by length" =<<
    verify env sha256 pub pssMsg (pssSig256 <> "\x00")
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
    pkeyDecrypt env sha256 priv (tamperLast oaepCt256)
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

caseRsaX509Vectors :: IO ()
caseRsaX509Vectors = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
      padded = BS.replicate (256 - BS.length x509Msg) 0 <> x509Msg
  -- Interop: the backend decrypts the CLI's ciphertext and verifies
  -- the CLI's raw signature (same RSA-2048 key as the v1.5 vectors).
  pt <- expectOk "x509 decrypt cli vector" =<<
    pkeyDecrypt env RsaX509 priv x509Ct
  assertEqual "x509 interop" padded pt
  expectOk "x509 verify cli vector" =<<
    verify env SigRSA_X509 pub x509Msg x509Sig
  -- Raw RSA has no integrity: tampered blocks open to garbage and
  -- mismatched messages verify to a verdict; the zero block is
  -- the identity.
  garbled <- expectOk "x509 tampered opens" =<<
    pkeyDecrypt env RsaX509 priv (tamperLast x509Ct)
  assertBool "x509 tamper garbles" (garbled /= padded)
  expectAuthFailed "x509 tampered sig rejected" =<<
    verify env SigRSA_X509 pub x509Msg (tamperLast x509Sig)
  expectAuthFailed "x509 wrong msg rejected" =<<
    verify env SigRSA_X509 pub "tampered-data-32-bytes-payload!!!" x509Sig
  -- Wrong-length signatures refuse by length, never verify.
  expectSigLenRange "x509 truncated refused by length" =<<
    verify env SigRSA_X509 pub x509Msg (BS.init x509Sig)
  expectSigLenRange "x509 overlong refused by length" =<<
    verify env SigRSA_X509 pub x509Msg (x509Sig <> "\x00")
  zeroPt <- expectOk "x509 zero opens" =<<
    pkeyDecrypt env RsaX509 priv (BS.replicate 256 0)
  assertEqual "x509 zero identity" (BS.replicate 256 0) zeroPt
  -- Above-modulus blocks are verdicts (uniform invalid-block shape).
  expectAuthFailed "x509 above-n rejected" =<<
    pkeyDecrypt env RsaX509 priv (BS.replicate 256 0xFF)
  expectBadParam "x509 wrong-length refused" =<<
    pkeyDecrypt env RsaX509 priv "short"
  -- Roundtrips: raw RSA is deterministic — seals replay the CLI
  -- vector byte for byte.
  c1 <- expectOk "x509 seal" =<< pkeyEncrypt env RsaX509 pub x509Msg
  assertEqual "x509 ct length" 256 (BS.length c1)
  assertEqual "x509 matches cli vector" x509Ct c1
  c2 <- expectOk "x509 reseal" =<< pkeyEncrypt env RsaX509 pub x509Msg
  assertEqual "x509 deterministic" c1 c2
  p1 <- expectOk "x509 open" =<< pkeyDecrypt env RsaX509 priv c1
  assertEqual "x509 reversible" padded p1
  s1 <- expectOk "x509 sign" =<< sign env SigRSA_X509 priv x509Msg
  assertEqual "x509 sig length" 256 (BS.length s1)
  assertEqual "x509 sig matches cli vector" x509Sig s1
  expectOk "x509 self-verify" =<< verify env SigRSA_X509 pub x509Msg s1
  -- Typed bounds: empty and over-wide inputs refuse (k = 256 on
  -- this key), garbage DER is a bad key.
  expectBadParam "x509 empty encrypt refused" =<<
    pkeyEncrypt env RsaX509 pub BS.empty
  expectBadParam "x509 overlong encrypt refused" =<<
    pkeyEncrypt env RsaX509 pub (BS.replicate 257 0x41)
  full <- expectOk "x509 full-width seals" =<<
    pkeyEncrypt env RsaX509 pub (BS.replicate 256 0x41)
  assertEqual "x509 full-width length" 256 (BS.length full)
  expectBadParam "x509 empty sign refused" =<< sign env SigRSA_X509 priv BS.empty
  expectBadParam "x509 overlong sign refused" =<<
    sign env SigRSA_X509 priv (BS.replicate 257 0x41)
  expectBadKey "x509 encrypt garbage pub" =<<
    pkeyEncrypt env RsaX509 (KeyDer "bogus") x509Msg
  expectBadKey "x509 decrypt garbage priv" =<<
    pkeyDecrypt env RsaX509 (KeyDer "bogus") x509Ct
  expectBadKey "x509 sign garbage priv" =<<
    sign env SigRSA_X509 (KeyDer "bogus") x509Msg
  expectBadKey "x509 verify garbage pub" =<<
    verify env SigRSA_X509 (KeyDer "bogus") x509Msg x509Sig

caseRsaX931Vectors :: IO ()
caseRsaX931Vectors = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
      raw = SigRSA_X931 Nothing
      sha1 = SigRSA_X931 (Just D_SHA1)
  -- Interop: the backend replays the CLI's deterministic bytes and
  -- verifies the CLI's vector (same RSA-2048 key as v1.5).
  s1 <- expectOk "x931 sign kat" =<< sign env raw priv x931Digest
  assertEqual "x931 kat" x931Sig s1
  s2 <- expectOk "x931 resign" =<< sign env raw priv x931Digest
  assertEqual "x931 deterministic" s1 s2
  expectOk "x931 verify kat" =<< verify env raw pub x931Digest x931Sig
  expectAuthFailed "x931 tampered sig rejected" =<<
    verify env raw pub x931Digest (tamperLast x931Sig)
  expectAuthFailed "x931 wrong digest rejected" =<<
    verify env raw pub (BS.replicate 32 0x55) x931Sig
  -- Wrong-length signatures refuse by length, never verify.
  expectSigLenRange "x931 truncated refused by length" =<<
    verify env raw pub x931Digest (BS.init x931Sig)
  expectSigLenRange "x931 overlong refused by length" =<<
    verify env raw pub x931Digest (x931Sig <> "\x00")
  -- Every other hash-id length roundtrips (20/48/64 bytes).
  mapM_ (rawRoundtrip env priv pub) [20, 48, 64]
  -- Off-rule lengths refuse typed (28-byte SHA-224 has no X9.31
  -- hash id — the provider rejects it, proven by probe).
  expectUnsupported "x931 28-byte refused" =<<
    sign env raw priv (BS.replicate 28 0xAA)
  expectUnsupported "x931 16-byte refused" =<<
    sign env raw priv (BS.replicate 16 0xAA)
  expectUnsupported "x931 empty refused" =<< sign env raw priv BS.empty
  -- The SHA-1 row hashes inside the backend and roundtrips.
  msig <- expectOk "x931-sha1 sign" =<< sign env sha1 priv "SHA1 X9.31 interop message"
  assertEqual "x931-sha1 sig length" 256 (BS.length msig)
  expectOk "x931-sha1 verify" =<< verify env sha1 pub "SHA1 X9.31 interop message" msig
  expectAuthFailed "x931-sha1 wrong msg rejected" =<<
    verify env sha1 pub "tampered message" msig
  -- Off-rule digested rows refuse; garbage DER is a bad key.
  expectUnsupported "x931-sha224 digested refused" =<<
    sign env (SigRSA_X931 (Just D_SHA224)) priv "message"
  expectBadKey "x931 sign garbage priv" =<< sign env raw (KeyDer "bogus") x931Digest
  expectBadKey "x931 verify garbage pub" =<<
    verify env raw (KeyDer "bogus") x931Digest x931Sig
  where
    rawRoundtrip env priv pub n = do
      let d = BS.pack (take n (cycle [0x31, 0xA7, 0xE2, 0x09]))
          label = show n ++ "-byte"
      s <- expectOk ("x931 sign " ++ label) =<< sign env (SigRSA_X931 Nothing) priv d
      assertEqual ("x931 sig length " ++ label) 256 (BS.length s)
      expectOk ("x931 verify " ++ label) =<< verify env (SigRSA_X931 Nothing) pub d s

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
  -- A non-palindromic exponent round-trips exactly: OSSL_PARAM
  -- BN import reads native-endian, and the stock 65537 masked a
  -- big-endian pass-through that minted mirrored exponents.
  (KeyDer _, Just (KeyDer pub3)) <- expectOk "rsa odd-e mints" =<<
    generateKey env (GenRSA 2048 65539)
  case rsaSpkiFields pub3 of
    Just (_, e3) -> assertEqual "minted exponent" (integerToBE 65539) e3
    Nothing -> assertFailure "rsa odd-e SPKI failed to parse"
