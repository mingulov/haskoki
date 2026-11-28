{- | OpenSSL digest and MAC cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Digest
  ( caseDigestKats
  , caseHmacGeneral
  , caseHmacKat
  , caseHmacKats
  , caseHmacVerify
  , casePoly1305Vector
  , caseSha256Kat
  , caseSha256Multipart
  , caseSha384Multipart
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Engine.Backend
  ( BackendError (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , MacSpec (..)
  )
import OpenSSL.Fixtures

expectNative :: Show a => String -> EngineResult a -> IO ()
expectNative label r = case r of
  EngineFail (BackendNative _ _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendNative, got " ++ show other)

sha256Empty :: ByteString
sha256Empty = hex "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

sha256Long :: ByteString
sha256Long = hex "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

longMsg :: ByteString
longMsg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

hmacOut1 :: ByteString
hmacOut1 = hex "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

-- Poly1305 KAT (OpenSSL 4.0.2 CLI `openssl mac POLY1305` and
-- python-cryptography agreeing byte for byte, independent of this
-- backend).
polyKey :: ByteString
polyKey = hex "60ae20bd9302aea34cafbc620011e17b7774e97764b9bb6e035ffb2b8b63be9f"

polyMsg :: ByteString
polyMsg = "Poly1305 KAT message, second vector"

polyTag :: ByteString
polyTag = hex "f70a350ed794a7e0660bba7638f5a6d2"

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
-- the @/opt/openssl-4.0.2/bin/openssl dgst@ CLI on 2026-09-21
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
  , (D_BLAKE2B512, "RFC7693", hex "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
  , (D_BLAKE2B160, "hashlib-nn20", hex "384264f676f39536840523f284921cdc68b6846b")
  , (D_BLAKE2B256, "hashlib-nn32", hex "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")
  , (D_BLAKE2B384, "hashlib-nn48", hex "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4")
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
    , D_BLAKE2B512
    , D_BLAKE2B160
    , D_BLAKE2B256
    , D_BLAKE2B384
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
-- the pinned 4.1.0 libcrypto.
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
  , (D_BLAKE2B512, "CLI-TC1", hex "358a6a184924894fc34bee5680eedf57d84a37bb38832f288e3b27dc63a98cc8c91e76da476b508bc6b2d408a248857452906e4a20b48c6b4b55d2df0fe1dd24")
  , (D_BLAKE2B160, "hashlib-TC1-nn20", hex "8e52620843a0942dc68ff03ef437d379a361175e")
  , (D_BLAKE2B256, "hashlib-TC1-nn32", hex "b6996ecae165cdb17a02becfbf442b5dee41c5075ded9a5763185cd68bd261d0")
  , (D_BLAKE2B384, "hashlib-TC1-nn48", hex "948364b074f4739bb1be6e7f8c918405f1f06c7a18a125534618269d57e337b67750ba54bd3d6456a59b6b9bb39a7601")
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
  b2full <- expectOk "full blake2b512" =<< macSign env (MacHMAC D_BLAKE2B512 Nothing) key hmacMsg1
  b2t32 <- expectOk "truncated blake2b512" =<< macSign env (MacHMAC D_BLAKE2B512 (Just 32)) key hmacMsg1
  assertEqual "blake2b truncation slices the KAT" (BS.take 32 b2full) b2t32
  s2full <- expectOk "full blake2b256" =<< macSign env (MacHMAC D_BLAKE2B256 Nothing) key hmacMsg1
  s2t12 <- expectOk "truncated blake2b256" =<< macSign env (MacHMAC D_BLAKE2B256 (Just 12)) key hmacMsg1
  assertEqual "sized truncation slices the KAT" (BS.take 12 s2full) s2t12
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

casePoly1305Vector :: IO ()
casePoly1305Vector = withBackend $ \env -> do
  let key = KeyBytes polyKey
  -- KAT: the backend tags the CLI/pyca bytes exactly.
  tag <- expectOk "poly1305 kat" =<< macSign env MacPoly1305 key polyMsg
  assertEqual "poly1305 tag" polyTag tag
  assertEqual "poly1305 tag length" 16 (BS.length tag)
  _ <- expectOk "poly1305 verify kat" =<< macVerify env MacPoly1305 key polyMsg polyTag
  expectAuthFailed "poly1305 tampered rejected" =<<
    macVerify env MacPoly1305 key polyMsg (tamperLast polyTag)
  expectAuthFailed "poly1305 wrong msg rejected" =<<
    macVerify env MacPoly1305 key "tampered message" polyTag
  -- Key independence: a second key tags differently.
  tag2 <- expectOk "poly1305 second key" =<<
    macSign env MacPoly1305 (KeyBytes (BS.replicate 32 0x11)) polyMsg
  assertBool "poly1305 keys differ" (tag2 /= tag)
  -- Off-length keys refuse at the provider (native error, never a tag).
  expectNative "poly1305 short key refused" =<<
    macSign env MacPoly1305 (KeyBytes (BS.replicate 16 0x11)) polyMsg
  expectNative "poly1305 long key refused" =<<
    macSign env MacPoly1305 (KeyBytes (BS.replicate 64 0x11)) polyMsg
