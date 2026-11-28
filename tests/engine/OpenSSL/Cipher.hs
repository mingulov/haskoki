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
