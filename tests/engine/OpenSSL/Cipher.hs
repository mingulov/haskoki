{- | OpenSSL block-cipher cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Cipher
  ( caseAesCfbOfb
  , caseAesCts
  , caseAesKat
  , caseAesRoundtrip
  , caseAesWrapKwp
  , caseAesWrapPkcs7
  , caseAesXts
  , caseCipherKats
  , caseLegacyKats
  ) where

import Data.Bits ((.&.), shiftL, xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Engine.Backend
  ( CipherSpec (..)
  , CryptoBackend (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver (cipherSpecFor)
import Haskoki.Recipe.Cipher (encodeCtrParams)
import Haskoki.Registry (MechanismId (..))
import OpenSSL.Fixtures

-- NIST SP 800-38A F.2.5 AES-256-CBC, first block.
aes256Key :: ByteString
aes256Key = hex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

aes256Ct :: ByteString
aes256Ct = hex "f58c4c04d6e5f1ba779eabfb5f7bfbd6"

aes192Key :: ByteString
aes192Key = hex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"

-- Triple-DES MMT row (K1 = K3, so the 24-byte key doubles
-- as the two-key expansion target): zero block -> 08d7b4fb629d0885;
-- CBC with the zero IV equals ECB. Agreed on both CLIs.
des3Key24 :: ByteString
des3Key24 = hex "0123456789abcdeffedcba98765432100123456789abcdef"

des3Key16 :: ByteString
des3Key16 = hex "0123456789abcdeffedcba9876543210"

-- CAMELLIA-CTR rows: RFC 5528 TV#1/#4/#7 (single block each;
-- counter block drives the 16-byte IV directly), verified under
-- the OpenSSL 4.0.2 CLI before embedding; independent of this
-- backend's fetch path.
camCtrPt :: ByteString
camCtrPt = hex "53696e676c6520626c6f636b206d7367"

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

rc4RsaCt :: ByteString
rc4RsaCt = hex "BBF316E8D940AF0AD3"

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
  -- CAMELLIA-CTR: the RFC 5528 rows at all widths, resolved through
  -- the driver map (the spec constructors land with the backend
  -- slice; the map-plus-fetch agreement stays pinned here).
  katCtrMapped env "camellia-128-ctr" 16 camCtr128Key camCtr128Icb camCtrPt camCtr128Ct
  katCtrMapped env "camellia-192-ctr" 24 camCtr192Key camCtr192Icb camCtrPt camCtr192Ct
  katCtrMapped env "camellia-256-ctr" 32 camCtr256Key camCtr256Icb camCtrPt camCtr256Ct
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
    katCtrMapped env label keyLen key icb pt want =
      case cipherSpecFor (MechanismId 0x558) keyLen (encodeCtrParams 128 icb) of
        Nothing -> assertFailure (label ++ " unmapped")
        Just cipher -> katCtr env label cipher key icb pt want

-- Legacy ciphers (DES/RC2/RC4/CAST-128/IDEA/SEED/Blowfish):
-- pinned-oracle KATs plus FIPS/RFC anchors, variable-keylen and
-- RC2-bits coverage, and typed geometry refusals. CBC_PAD rows
-- have no engine spec (the Operation layer pads onto these CBC
-- specs); their oracle vectors land in the C-consumer suite.
caseLegacyKats :: IO ()
caseLegacyKats = withBackend $ \env -> do
  -- DES: oracle two-block rows plus the FIPS anchors.
  katEcb env "des-ecb" C_DES_ECB desEcbKey desEcbPt desEcbCt
  katCbc env "des-cbc" C_DES_CBC desCbcKey desCbcIv desCbcPt desCbcCt
  katEcb env "des-ecb-fips" C_DES_ECB desFipsKey desFipsPt desFipsCt
  katCbc env "des-cbc-fips81" C_DES_CBC desCbc1Key desCbc1Iv desNow desCbc1Ct
  -- DES stream modes: exact pins plus unaligned legs (the
  -- provider reports block size 1, so any length encrypts).
  katStream env "des-cfb64" C_DES_CFB64 desCbc1Key desCbc1Iv desNow desCfb64Ct
  katStream env "des-cfb8" C_DES_CFB8 desCbc1Key desCbc1Iv desNow desCfb8Ct
  katStream env "des-ofb64" C_DES_OFB64 desCbc1Key desCbc1Iv desNow desOfbCt
  raggedCfb <- expectOk "cfb64 unaligned encrypt" =<<
    cipherEncrypt env C_DES_CFB64 (KeyBytes desCbc1Key) desCbc1Iv "eleven bytes"
  assertEqual "cfb64 length preserved" 12 (BS.length raggedCfb)
  raggedBack <- expectOk "cfb64 unaligned decrypt" =<<
    cipherDecrypt env C_DES_CFB64 (KeyBytes desCbc1Key) desCbc1Iv raggedCfb
  assertEqual "cfb64 unaligned inverts" "eleven bytes" raggedBack
  raggedOfb <- expectOk "ofb64 unaligned encrypt" =<<
    cipherEncrypt env C_DES_OFB64 (KeyBytes desCbc1Key) desCbc1Iv "eleven bytes"
  assertEqual "ofb64 length preserved" 12 (BS.length raggedOfb)
  -- OFB and CFB64 share the first block (ECB_K(IV) xored with plaintext block 0).
  assertEqual "ofb==cfb64 at one block" desCfb64Ct desOfbCt
  -- RC2: oracle rows at 128 bits; other widths stay
  -- sensitivity-checked (never pinned to single-impl bytes).
  katEcbBits env "rc2-ecb-128" 128 rc2Key rc2EcbPt rc2EcbCt
  katCbcBits env "rc2-cbc-128" 128 rc2Key rc2Iv rc2CbcPt rc2CbcCt
  ct64 <- expectOk "rc2-ecb-64 encrypt" =<<
    cipherEncrypt env (C_RC2_ECB 64) (KeyBytes rc2Key) BS.empty rc2EcbPt
  assertBool "rc2 bits separate 64/128" (ct64 /= rc2EcbCt)
  pt64 <- expectOk "rc2-ecb-64 decrypt" =<<
    cipherDecrypt env (C_RC2_ECB 64) (KeyBytes rc2Key) BS.empty ct64
  assertEqual "rc2-64 inverts" rc2EcbPt pt64
  ct40 <- expectOk "rc2-ecb-40 encrypt" =<<
    cipherEncrypt env (C_RC2_ECB 40) (KeyBytes rc2Key) BS.empty rc2EcbPt
  assertBool "rc2 bits separate 40/128" (ct40 /= rc2EcbCt)
  assertBool "rc2 bits separate 40/64" (ct40 /= ct64)
  -- RC2 bits range: 1 and 1024 execute, 0 and 1025 refuse (R2).
  rt1 <- expectOk "rc2 bits 1 encrypt" =<<
    cipherEncrypt env (C_RC2_ECB 1) (KeyBytes rc2Key) BS.empty rc2EcbPt
  pt1 <- expectOk "rc2 bits 1 decrypt" =<<
    cipherDecrypt env (C_RC2_ECB 1) (KeyBytes rc2Key) BS.empty rt1
  assertEqual "rc2 bits 1 inverts" rc2EcbPt pt1
  rt1024 <- expectOk "rc2 bits 1024 encrypt" =<<
    cipherEncrypt env (C_RC2_CBC 1024) (KeyBytes rc2Key) rc2Iv rc2CbcPt
  pt1024 <- expectOk "rc2 bits 1024 decrypt" =<<
    cipherDecrypt env (C_RC2_CBC 1024) (KeyBytes rc2Key) rc2Iv rt1024
  assertEqual "rc2 bits 1024 inverts" rc2CbcPt pt1024
  expectBadParam "rc2 bits 0 refused" =<<
    cipherEncrypt env (C_RC2_ECB 0) (KeyBytes rc2Key) BS.empty rc2EcbPt
  expectBadParam "rc2 bits 1025 refused" =<<
    cipherEncrypt env (C_RC2_CBC 1025) (KeyBytes rc2Key) rc2Iv rc2CbcPt
  -- RC4: RFC 6229 rows plus the RSA anchor; any length streams.
  katStream env "rc4-128" C_RC4 rc4Key128 BS.empty rc4Zero32 rc4Ct128
  katStream env "rc4-256" C_RC4 rc4Key256 BS.empty rc4Zero32 rc4Ct256
  katStream env "rc4-rsa" C_RC4 "Key" BS.empty "Plaintext" rc4RsaCt
  rtRc4 <- expectOk "rc4 1-byte key encrypt" =<<
    cipherEncrypt env C_RC4 (KeyBytes "K") BS.empty "seven!!"
  ptRc4 <- expectOk "rc4 1-byte key decrypt" =<<
    cipherDecrypt env C_RC4 (KeyBytes "K") BS.empty rtRc4
  assertEqual "rc4 1-byte key inverts" "seven!!" ptRc4
  let key255 = BS.replicate 255 0xA5
  rt255 <- expectOk "rc4 255-byte key encrypt" =<<
    cipherEncrypt env C_RC4 (KeyBytes key255) BS.empty "sixteen bytes xx"
  pt255 <- expectOk "rc4 255-byte key decrypt" =<<
    cipherDecrypt env C_RC4 (KeyBytes key255) BS.empty rt255
  assertEqual "rc4 255-byte key inverts" "sixteen bytes xx" pt255
  -- CAST-128: RFC 2144 row, oracle CBC row, short-key pin.
  katEcb env "cast128-ecb" C_CAST128_ECB castKey castEcbPt castEcbCt
  katCbc env "cast128-cbc" C_CAST128_CBC castKey castIv castCbcPt castCbcCt
  katEcb env "cast128-ecb-8byte-key" C_CAST128_ECB castKey8 bfPt8z castEcb8Ct
  rtCast1 <- expectOk "cast128 1-byte key encrypt" =<<
    cipherEncrypt env C_CAST128_ECB (KeyBytes "K") BS.empty castEcbPt
  ptCast1 <- expectOk "cast128 1-byte key decrypt" =<<
    cipherDecrypt env C_CAST128_ECB (KeyBytes "K") BS.empty rtCast1
  assertEqual "cast128 1-byte key inverts" castEcbPt ptCast1
  -- CAST/CAST3: the RFC 2144 short-key rows (fixed key lengths).
  katEcb env "cast-ecb-40" C_CAST_ECB castKey40 castEcbPt castEcb40Ct
  katEcb env "cast3-ecb-80" C_CAST3_ECB castKey80 castEcbPt castEcb80Ct
  rtCast40 <- expectOk "cast 5-byte key encrypt" =<<
    cipherEncrypt env C_CAST_CBC (KeyBytes castKey40) castIv castCbcPt
  ptCast40 <- expectOk "cast 5-byte key decrypt" =<<
    cipherDecrypt env C_CAST_CBC (KeyBytes castKey40) castIv rtCast40
  assertEqual "cast 5-byte key inverts" castCbcPt ptCast40
  rtCast80 <- expectOk "cast3 10-byte key encrypt" =<<
    cipherEncrypt env C_CAST3_CBC (KeyBytes castKey80) castIv castCbcPt
  ptCast80 <- expectOk "cast3 10-byte key decrypt" =<<
    cipherDecrypt env C_CAST3_CBC (KeyBytes castKey80) castIv rtCast80
  assertEqual "cast3 10-byte key inverts" castCbcPt ptCast80
  -- Blowfish: oracle zero row; all-zero keys share one schedule.
  katCbc env "blowfish-cbc" C_BLOWFISH_CBC bfKey8z bfIv8z bfPt8z bfCt8z
  ct16z <- expectOk "blowfish 16-byte zero key" =<<
    cipherEncrypt env C_BLOWFISH_CBC (KeyBytes (BS.replicate 16 0)) bfIv8z bfPt8z
  assertEqual "blowfish zero keys agree" bfCt8z ct16z
  ct56z <- expectOk "blowfish 56-byte zero key" =<<
    cipherEncrypt env C_BLOWFISH_CBC (KeyBytes (BS.replicate 56 0)) bfIv8z bfPt8z
  assertEqual "blowfish zero keys agree at ceiling" bfCt8z ct56z
  rtBf <- expectOk "blowfish 4-byte key encrypt" =<<
    cipherEncrypt env C_BLOWFISH_CBC (KeyBytes "key!") bfIv8z bfPt8z
  ptBf <- expectOk "blowfish 4-byte key decrypt" =<<
    cipherDecrypt env C_BLOWFISH_CBC (KeyBytes "key!") bfIv8z rtBf
  assertEqual "blowfish floor key inverts" bfPt8z ptBf
  -- IDEA: NESSIE row and oracle CBC row.
  katEcb env "idea-ecb-nessie" C_IDEA_ECB ideaNessieKey bfPt8z ideaNessieCt
  katCbc env "idea-cbc" C_IDEA_CBC ideaCbcKey ideaCbcIv ideaCbcPt ideaCbcCt
  -- SEED: oracle rows (16-byte blocks).
  katEcb env "seed-ecb" C_SEED_ECB seedEcbKey seedEcbPt seedEcbCt
  katCbc env "seed-cbc" C_SEED_CBC seedCbcKey seedCbcIv seedCbcPt seedCbcCt
  -- Geometry refusals stay typed on the legacy specs.
  expectBadParam "des rejects 7-byte key" =<<
    cipherEncrypt env C_DES_CBC (KeyBytes "1234567") desCbcIv desCbcPt
  expectBadParam "des-cbc rejects misaligned input" =<<
    cipherEncrypt env C_DES_CBC (KeyBytes desCbcKey) desCbcIv "eleven bytes"
  expectBadParam "des-ecb rejects iv" =<<
    cipherEncrypt env C_DES_ECB (KeyBytes desEcbKey) desCbcIv desEcbPt
  expectBadParam "cast rejects 17-byte key" =<<
    cipherEncrypt env C_CAST128_ECB (KeyBytes (BS.replicate 17 0)) BS.empty castEcbPt
  -- Empty keys reach the length check here (BadParam); the
  -- synthetic backend refuses them earlier with BadKey.
  expectBadParam "cast rejects empty key" =<<
    cipherEncrypt env C_CAST128_ECB (KeyBytes BS.empty) BS.empty castEcbPt
  expectBadParam "cast40 rejects 16-byte key" =<<
    cipherEncrypt env C_CAST_ECB (KeyBytes castKey) BS.empty castEcbPt
  expectBadParam "cast80 rejects 5-byte key" =<<
    cipherEncrypt env C_CAST3_ECB (KeyBytes castKey40) BS.empty castEcbPt
  expectBadParam "bf rejects 3-byte key" =<<
    cipherEncrypt env C_BLOWFISH_CBC (KeyBytes "key") bfIv8z bfPt8z
  expectBadParam "bf rejects 57-byte key" =<<
    cipherEncrypt env C_BLOWFISH_CBC (KeyBytes (BS.replicate 57 0)) bfIv8z bfPt8z
  expectBadParam "idea rejects 8-byte key" =<<
    cipherEncrypt env C_IDEA_ECB (KeyBytes bfPt8z) BS.empty bfPt8z
  expectBadParam "seed rejects 8-byte key" =<<
    cipherEncrypt env C_SEED_ECB (KeyBytes bfPt8z) BS.empty seedEcbPt
  expectBadParam "rc2 rejects 129-byte key" =<<
    cipherEncrypt env (C_RC2_ECB 128) (KeyBytes (BS.replicate 129 0)) BS.empty rc2EcbPt
  expectBadParam "rc4 rejects empty key" =<<
    cipherEncrypt env C_RC4 (KeyBytes BS.empty) BS.empty "seven!!"
  expectBadParam "rc4 rejects 256-byte key" =<<
    cipherEncrypt env C_RC4 (KeyBytes (BS.replicate 256 0)) BS.empty "seven!!"
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
    katStream env label cipher key iv pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) iv pt
      assertEqual (label ++ " kat") want ct
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) iv want
      assertEqual (label ++ " inverts") pt pt'
    katEcbBits env label bits key pt want =
      katEcb env label (C_RC2_ECB bits) key pt want
    katCbcBits env label bits key iv pt want =
      katCbc env label (C_RC2_CBC bits) key iv pt want

-- AES-CTS (CBC-CS1): ACVP encrypt vectors plus geometry/KAT-edge negatives.
caseAesCts :: IO ()
caseAesCts = withBackend $ \env -> do
  -- 6 legs: 128/192/256 x (exactly-2-blocks, multi-block, ragged, short).
  katCts env "aes-128-cts-64" C_AES128_CTS cts128Key64 cts128Iv64 cts128Pt64 cts128Ct64
  katCts env "aes-128-cts-156" C_AES128_CTS cts128Key156 cts128Iv156 cts128Pt156 cts128Ct156
  katCts env "aes-192-cts-32" C_AES192_CTS cts192Key32 cts192Iv32 cts192Pt32 cts192Ct32
  katCts env "aes-192-cts-57" C_AES192_CTS cts192Key57 cts192Iv57 cts192Pt57 cts192Ct57
  katCts env "aes-256-cts-66" C_AES256_CTS cts256Key66 cts256Iv66 cts256Pt66 cts256Ct66
  katCts env "aes-256-cts-19" C_AES256_CTS cts256Key19 cts256Iv19 cts256Pt19 cts256Ct19
  -- CTS needs >= 1 full block; sub-block input is a typed refusal.
  expectBadParam "cts encrypt sub-block" =<<
    cipherEncrypt env C_AES128_CTS (KeyBytes cts128Key64) cts128Iv64 "short"
  expectBadParam "cts decrypt sub-block" =<<
    cipherDecrypt env C_AES128_CTS (KeyBytes cts128Key64) cts128Iv64 "short!!"
  expectBadParam "cts bad key length" =<<
    cipherEncrypt env C_AES128_CTS (KeyBytes "short") cts128Iv64 cts128Pt64
  expectBadParam "cts bad iv length" =<<
    cipherEncrypt env C_AES128_CTS (KeyBytes cts128Key64) "short" cts128Pt64
  -- CS1 degenerates to plain CBC at exactly one block: cross-check.
  oneBlock <- expectOk "cts 1-block encrypt" =<<
    cipherEncrypt env C_AES256_CTS (KeyBytes aes256Key) aes256Iv aes256Pt
  oneBlockCbc <- expectOk "cbc 1-block encrypt" =<<
    cipherEncrypt env C_AES256_CBC (KeyBytes aes256Key) aes256Iv aes256Pt
  assertEqual "cts==cbc at 16 bytes" oneBlockCbc oneBlock
  where
    katCts env label cipher key iv pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) iv pt
      assertEqual (label ++ " kat") want ct
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) iv want
      assertEqual (label ++ " inverts") pt pt'

-- AES CFB128/CFB8/CFB1/OFB: ACVP encrypt vectors (enc+dec) plus
-- ragged roundtrips (length-preserving, self-inverse) and geometry
-- negatives. CFB1 sub-byte legs mask to the payload bits per the
-- oracle's _cfb1_mask rule (top payloadLen bits compared).
caseAesCfbOfb :: IO ()
caseAesCfbOfb = withBackend $ \env -> do
  kat env "aes-128-cfb128-48" C_AES128_CFB128 cfb128_128_key cfb128_128_iv cfb128_128_pt cfb128_128_ct
  kat env "aes-192-cfb128-48" C_AES192_CFB128 cfb128_192_key cfb128_192_iv cfb128_192_pt cfb128_192_ct
  kat env "aes-256-cfb128-48" C_AES256_CFB128 cfb128_256_key cfb128_256_iv cfb128_256_pt cfb128_256_ct
  kat env "aes-128-cfb8-32" C_AES128_CFB8 cfb8_128_key cfb8_128_iv cfb8_128_pt cfb8_128_ct
  kat env "aes-192-cfb8-32" C_AES192_CFB8 cfb8_192_key cfb8_192_iv cfb8_192_pt cfb8_192_ct
  kat env "aes-256-cfb8-32" C_AES256_CFB8 cfb8_256_key cfb8_256_iv cfb8_256_pt cfb8_256_ct
  kat env "aes-128-cfb1-8b" C_AES128_CFB1 cfb1_128_key cfb1_128_iv (hex "93") (hex "75")
  kat env "aes-192-cfb1-8b" C_AES192_CFB1 cfb1_192_key cfb1_192_iv (hex "5C") (hex "76")
  kat env "aes-256-cfb1-8b" C_AES256_CFB1 cfb1_256_key cfb1_256_iv (hex "51") (hex "D2")
  katMasked env "aes-128-cfb1-10b" C_AES128_CFB1 cfb1_128b_key cfb1_128b_iv (hex "CDC0") (hex "6B00") 10
  katMasked env "aes-192-cfb1-10b" C_AES192_CFB1 cfb1_192b_key cfb1_192b_iv (hex "3480") (hex "F740") 10
  katMasked env "aes-256-cfb1-10b" C_AES256_CFB1 cfb1_256b_key cfb1_256b_iv (hex "1280") (hex "2F00") 10
  kat env "aes-128-ofb-64" C_AES128_OFB ofb_128_key ofb_128_iv ofb_128_pt ofb_128_ct
  kat env "aes-192-ofb-64" C_AES192_OFB ofb_192_key ofb_192_iv ofb_192_pt ofb_192_ct
  kat env "aes-256-ofb-64" C_AES256_OFB ofb_256_key ofb_256_iv ofb_256_pt ofb_256_ct
  -- Ragged roundtrips (no ACVP ragged vectors exist; these pin
  -- length preservation + inversion, not oracle bytes).
  roundtrip env "cfb128 ragged 20" C_AES128_CFB128 cfb128_128_key cfb128_128_iv 20
  roundtrip env "cfb8 ragged 20" C_AES128_CFB8 cfb8_128_key cfb8_128_iv 20
  roundtrip env "cfb1 ragged 3" C_AES128_CFB1 cfb1_128_key cfb1_128_iv 3
  roundtrip env "ofb ragged 20" C_AES128_OFB ofb_128_key ofb_128_iv 20
  -- Geometry negatives.
  expectBadParam "cfb128 bad key" =<<
    cipherEncrypt env C_AES128_CFB128 (KeyBytes "short") cfb128_128_iv cfb128_128_pt
  expectBadParam "cfb128 bad iv" =<<
    cipherEncrypt env C_AES128_CFB128 (KeyBytes cfb128_128_key) "short" cfb128_128_pt
  expectBadParam "cfb8 bad key" =<<
    cipherEncrypt env C_AES128_CFB8 (KeyBytes "short") cfb8_128_iv cfb8_128_pt
  expectBadParam "cfb8 bad iv" =<<
    cipherEncrypt env C_AES128_CFB8 (KeyBytes cfb8_128_key) "short" cfb8_128_pt
  expectBadParam "cfb1 bad key" =<<
    cipherEncrypt env C_AES128_CFB1 (KeyBytes "short") cfb1_128_iv (hex "93")
  expectBadParam "cfb1 bad iv" =<<
    cipherEncrypt env C_AES128_CFB1 (KeyBytes cfb1_128_key) "short" (hex "93")
  expectBadParam "ofb bad key" =<<
    cipherEncrypt env C_AES128_OFB (KeyBytes "short") ofb_128_iv ofb_128_pt
  expectBadParam "ofb bad iv" =<<
    cipherEncrypt env C_AES128_OFB (KeyBytes ofb_128_key) "short" ofb_128_pt
  where
    kat env label cipher key iv pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) iv pt
      assertEqual (label ++ " kat") want ct
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) iv want
      assertEqual (label ++ " inverts") pt pt'
    katMasked env label cipher key iv pt want bits = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) iv pt
      assertEqual (label ++ " kat") (maskTopBits bits want) (maskTopBits bits ct)
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) iv want
      assertEqual (label ++ " inverts") (maskTopBits bits pt) (maskTopBits bits pt')
    roundtrip env label cipher key iv n = do
      let pt = BS.take n "ragged-input-bytes-0123456789ABCDEF"
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) iv pt
      assertEqual (label ++ " length preserved") n (BS.length ct)
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) iv ct
      assertEqual (label ++ " inverts") pt pt'
    -- Keep the first n bits (oracle _cfb1_mask rule); the engine
    -- always returns full bytes.
    maskTopBits bits bs
      | BS.length bs * 8 <= bits = bs
      | rest == 0 = hd
      | otherwise = hd <> BS.take 1 (BS.map (.&. mask) tl)
      where
        (full, rest) = bits `divMod` 8
        (hd, tl) = BS.splitAt full bs
        mask = fromIntegral (0xFF `shiftL` (8 - rest) .&. 0xFF :: Int)

-- AES-KW (RFC 3394) / AES-KWP (RFC 5649): ACVP vectors, empty-IV
-- (ECB shape), output expands by the 8-byte wrap IV.
caseAesWrapKwp :: IO ()
caseAesWrapKwp = withBackend $ \env -> do
  -- 12 legs: KW/KWP x 128/192/256 x (minimal, multiblock/ragged).
  katKw env "aes-128-kw-16" C_AES128_KW kw128_16_key kw128_16_pt kw128_16_ct
  katKw env "aes-128-kw-72" C_AES128_KW kw128_72_key kw128_72_pt kw128_72_ct
  katKw env "aes-192-kw-16" C_AES192_KW kw192_16_key kw192_16_pt kw192_16_ct
  katKw env "aes-192-kw-72" C_AES192_KW kw192_72_key kw192_72_pt kw192_72_ct
  katKw env "aes-256-kw-16" C_AES256_KW kw256_16_key kw256_16_pt kw256_16_ct
  katKw env "aes-256-kw-72" C_AES256_KW kw256_72_key kw256_72_pt kw256_72_ct
  katKwp env "aes-128-kwp-1" C_AES128_KWP kwp128_1_key kwp128_1_pt kwp128_1_ct
  katKwp env "aes-128-kwp-269" C_AES128_KWP kwp128_269_key kwp128_269_pt kwp128_269_ct
  katKwp env "aes-192-kwp-1" C_AES192_KWP kwp192_1_key kwp192_1_pt kwp192_1_ct
  katKwp env "aes-192-kwp-269" C_AES192_KWP kwp192_269_key kwp192_269_pt kwp192_269_ct
  katKwp env "aes-256-kwp-1" C_AES256_KWP kwp256_1_key kwp256_1_pt kwp256_1_ct
  katKwp env "aes-256-kwp-269" C_AES256_KWP kwp256_269_key kwp256_269_pt kwp256_269_ct
  -- Geometry negatives (provider-proven: KW minimum is 16 bytes,
  -- multiple-of-8; KWP refuses empty rather than emitting the
  -- provider's vacuous 0-byte success).
  expectBadParam "kw rejects 8-byte input" =<<
    cipherEncrypt env C_AES128_KW (KeyBytes kw128_16_key) BS.empty "12345678"
  expectBadParam "kw rejects non-multiple-of-8" =<<
    cipherEncrypt env C_AES128_KW (KeyBytes kw128_16_key) BS.empty "twenty bytes exactly!!"
  expectBadParam "kw rejects iv" =<<
    cipherEncrypt env C_AES128_KW (KeyBytes kw128_16_key) aes256Iv kw128_16_pt
  expectBadParam "kw bad key length" =<<
    cipherEncrypt env C_AES128_KW (KeyBytes "short") BS.empty kw128_16_pt
  expectBadParam "kwp rejects empty input" =<<
    cipherEncrypt env C_AES128_KWP (KeyBytes kwp128_1_key) BS.empty BS.empty
  expectBadParam "kwp rejects iv" =<<
    cipherEncrypt env C_AES128_KWP (KeyBytes kwp128_1_key) aes256Iv kwp128_1_pt
  expectBadParam "kwp bad key length" =<<
    cipherEncrypt env C_AES128_KWP (KeyBytes "short") BS.empty kwp128_1_pt
  -- Integrity negatives: decrypt failures are authentication
  -- failures (GCM-tag-failure precedent), never wrong plaintext.
  expectAuthFailed "kw corrupt ct" =<<
    cipherDecrypt env C_AES128_KW (KeyBytes kw128_16_key) BS.empty (corrupt kw128_16_ct)
  expectAuthFailed "kwp corrupt ct" =<<
    cipherDecrypt env C_AES128_KWP (KeyBytes kwp128_1_key) BS.empty (corrupt kwp128_1_ct)
  where
    katKw env label cipher key pt want =
      kat env label cipher key pt want (+ 8)
    katKwp env label cipher key pt want =
      kat env label cipher key pt want (\n -> n + (8 - n `mod` 8) `mod` 8 + 8)
    kat env label cipher key pt want expand = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) BS.empty pt
      assertEqual (label ++ " kat") want ct
      assertEqual (label ++ " expands") (expand (BS.length pt)) (BS.length ct)
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) BS.empty want
      assertEqual (label ++ " inverts") pt pt'
    corrupt bs = case BS.uncons bs of
      Nothing -> bs
      Just (b, rest) -> BS.cons (b `xor` 0x01) rest

caseAesWrapPkcs7 :: IO ()
caseAesWrapPkcs7 = withBackend $ \env -> do
  let key = KeyBytes kw128_16_key
  -- Default AIV: padded images wrap to the pinned vectors.
  ct0 <- expectOk "pkcs7 default-iv encrypt" =<<
    cipherEncrypt env C_AES128_KW key BS.empty kwp7_pad24
  assertEqual "pkcs7 default-iv kat" kwp7_ct_default ct0
  assertEqual "pkcs7 expands by 8" 32 (BS.length ct0)
  pt0 <- expectOk "pkcs7 default-iv decrypt" =<<
    cipherDecrypt env C_AES128_KW key BS.empty kwp7_ct_default
  assertEqual "pkcs7 default-iv inverts" kwp7_pad24 pt0
  ct20 <- expectOk "pkcs7 raw20 encrypt" =<<
    cipherEncrypt env C_AES128_KW key BS.empty kwp7_pad20
  assertEqual "pkcs7 raw20 kat" kwp7_ct_raw20 ct20
  -- Caller 8-byte IV: distinct pinned vector, inverts only
  -- under the same IV (wrong/default IV is an integrity
  -- failure, never wrong plaintext).
  ct8 <- expectOk "pkcs7 iv8 encrypt" =<<
    cipherEncrypt env C_AES128_KW key kwp7_iv8 kwp7_pad24
  assertEqual "pkcs7 iv8 kat" kwp7_ct_iv8 ct8
  assertBool "pkcs7 iv8 differs from default" (ct8 /= kwp7_ct_default)
  pt8 <- expectOk "pkcs7 iv8 decrypt" =<<
    cipherDecrypt env C_AES128_KW key kwp7_iv8 kwp7_ct_iv8
  assertEqual "pkcs7 iv8 inverts" kwp7_pad24 pt8
  expectAuthFailed "pkcs7 iv8 ct under default iv" =<<
    cipherDecrypt env C_AES128_KW key BS.empty kwp7_ct_iv8
  expectAuthFailed "pkcs7 corrupt ct" =<<
    cipherDecrypt env C_AES128_KW key kwp7_iv8 (corrupt kwp7_ct_iv8)
  -- IV-width geometry: KW takes 0/8 only; KWP takes 0/4 only.
  expectBadParam "kw rejects 4-byte iv" =<<
    cipherEncrypt env C_AES128_KW key (BS.take 4 kwp7_iv8) kwp7_pad24
  expectBadParam "kwp rejects 8-byte iv" =<<
    cipherEncrypt env C_AES128_KWP (KeyBytes kwp128_1_key) kwp7_iv8 kwp128_1_pt
  kwp4 <- expectOk "kwp iv4 encrypt" =<<
    cipherEncrypt env C_AES128_KWP (KeyBytes kwp128_1_key) kwp_iv4 kwp_iv4_pt
  assertEqual "kwp iv4 kat" kwp_iv4_ct kwp4
  kwp4pt <- expectOk "kwp iv4 decrypt" =<<
    cipherDecrypt env C_AES128_KWP (KeyBytes kwp128_1_key) kwp_iv4 kwp_iv4_ct
  assertEqual "kwp iv4 inverts" kwp_iv4_pt kwp4pt
  where
    kwp_iv4_pt = BS.pack [1, 2, 3, 4, 5, 6, 7]
    corrupt bs = case BS.uncons bs of
      Nothing -> bs
      Just (b, rest) -> BS.cons (b `xor` 0x01) rest

-- AES-XTS (IEEE 1619): ACVP vectors, 16-byte tweak as the IV,
-- double-width keys (data + tweak halves), length-preserving
-- over data units >= 16 bytes (stealing covers ragged tails).
caseAesXts :: IO ()
caseAesXts = withBackend $ \env -> do
  -- 4 legs: 128/256 x (aligned 16B, ragged).
  kat env "aes-128-xts-16" C_AES128_XTS xts128_key xts128_tweak xts128_pt xts128_ct
  kat env "aes-128-xts-62" C_AES128_XTS xts128_rag_key xts128_rag_tweak xts128_rag_pt xts128_rag_ct
  kat env "aes-256-xts-16" C_AES256_XTS xts256_key xts256_tweak xts256_pt xts256_ct
  kat env "aes-256-xts-27" C_AES256_XTS xts256_rag_key xts256_rag_tweak xts256_rag_pt xts256_rag_ct
  -- Geometry negatives (provider-proven: input floor is 16
  -- bytes; equal-halves keys refused at init as bad keys).
  expectBadParam "xts rejects 15-byte input" =<<
    cipherEncrypt env C_AES128_XTS (KeyBytes xts128_key) xts128_tweak (BS.take 15 xts128_pt)
  expectBadParam "xts bad key length" =<<
    cipherEncrypt env C_AES128_XTS (KeyBytes "short") xts128_tweak xts128_pt
  expectBadParam "xts bad tweak length" =<<
    cipherEncrypt env C_AES128_XTS (KeyBytes xts128_key) "short" xts128_pt
  expectBadKey "xts rejects equal-halves key" =<<
    cipherEncrypt env C_AES128_XTS (KeyBytes (BS.take 16 xts128_key <> BS.take 16 xts128_key)) xts128_tweak xts128_pt
  where
    kat env label cipher key tweak pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) tweak pt
      assertEqual (label ++ " kat") want ct
      assertEqual (label ++ " length preserved") (BS.length pt) (BS.length ct)
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) tweak want
      assertEqual (label ++ " inverts") pt pt'


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


kwp7_pad20raw :: ByteString
kwp7_pad20raw = kw128_16_pt <> hex "aabbccdd"


kwp7_pad20, kwp7_ct_raw20 :: ByteString
kwp7_pad20 = kwp7_pad20raw <> BS.replicate 4 4
kwp7_ct_raw20 = hex "8ec9cf063015a788404dcac6013f7d912e9588d8f99b5b74d366a4449f1cdf58"


kwp_iv4, kwp_iv4_ct :: ByteString
kwp_iv4 = hex "deadbeef"
kwp_iv4_ct = hex "dab104833b678215a9a94db94422e5ef"


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
