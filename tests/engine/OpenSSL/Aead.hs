{- | OpenSSL AEAD cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Aead
  ( caseAeadCcmReal
  , caseAeadEmptyPlaintext
  , caseAeadReal
  , caseChachaPolyReal
  , caseChachaReal
  ) where

import Data.Bits (xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Test.Tasty.HUnit (assertBool, assertEqual)
import Haskoki.Engine.Backend
  ( AeadSpec (..)
  , CipherSpec (..)
  , CryptoBackend (..)
  , KeyMaterial (..)
  )
import OpenSSL.Fixtures

caseAeadReal :: IO ()
caseAeadReal = withBackend $ \env -> do
  -- Pinned vector (Python cryptography AESGCM, the oracle's own
  -- cross-check root): key 00..0f, nonce 00..0b, aad "aad-data",
  -- pt "Hello GCM world!".
  let key = KeyBytes (hex "000102030405060708090a0b0c0d0e0f")
      nonce = hex "000102030405060708090a0b"
      aad = "aad-data"
      pt = "Hello GCM world!"
      aead = AeadSpec "AES-128-GCM" 12 16
  (ct, tag) <- expectOk "gcm vector" =<<
    aeadEncrypt env aead key nonce aad pt
  assertEqual "vector ct" (hex "db09cba2093bb01706f216e544cf1429") ct
  assertEqual "vector tag" (hex "39f0385041afdfd3a2d5a8e8ed69a2e6") tag
  pt' <- expectOk "gcm vector decrypt" =<<
    aeadDecrypt env aead key nonce aad ct tag
  assertEqual "vector roundtrip" pt pt'
  -- Tampering anywhere fails closed.
  let badTag = BS.pack [BS.head tag `xor` 1] <> BS.tail tag
  expectAuthFailed "tag tamper" =<<
    aeadDecrypt env aead key nonce aad ct badTag
  let badCt = BS.pack [BS.head ct `xor` 1] <> BS.tail ct
  expectAuthFailed "ct tamper" =<<
    aeadDecrypt env aead key nonce aad badCt tag
  expectAuthFailed "aad tamper" =<<
    aeadDecrypt env aead key nonce "aad-datX" ct tag
  -- Bounds: wrong key/nonce/tag widths refuse as bad params.
  expectBadParam "short key" =<<
    aeadEncrypt env aead (KeyBytes "short") nonce aad pt
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
      aead = AeadSpec "AES-128-GCM" 12 16
  (ct1, tag1) <- expectOk "empty-pt seal with aad" =<<
    aeadEncrypt env aead key nonce "aad-data" ""
  assertEqual "empty-pt ct with aad" "" ct1
  assertEqual "empty-pt tag with aad" (hex "e01312146176abd643fcee9d4a640184") tag1
  pt1 <- expectOk "empty-pt open with aad" =<<
    aeadDecrypt env aead key nonce "aad-data" ct1 tag1
  assertEqual "empty-pt roundtrip with aad" "" pt1
  (ct0, tag0) <- expectOk "empty-pt seal without aad" =<<
    aeadEncrypt env aead key nonce "" ""
  assertEqual "empty-pt ct without aad" "" ct0
  assertEqual "empty-pt tag without aad" (hex "435b9ba12d75a4be8a977ea3cd011890") tag0
  pt0 <- expectOk "empty-pt open without aad" =<<
    aeadDecrypt env aead key nonce "" ct0 tag0
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

-- | RFC 8439 section 2.4.2: key 00..1f, nonce
-- 000000000000004a00000000, initial counter 1, the 114-byte
-- Sunscreen plaintext. The counter rides the IV natively (4-byte
-- LE counter plus the 12-byte nonce, the exact IV layout
-- @EVP_chacha20@ takes).
caseChachaReal :: IO ()
caseChachaReal = withBackend $ \env -> do
  let key = KeyBytes (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      nonce = hex "000000000000004a00000000"
      pt = chachaSunscreen
      iv1 = hex "01000000" <> nonce
      ct = hex $ concat
        [ "6e2e359a2568f98041ba0728dd0d6981"
        , "e97e7aec1d4360c20a27afccfd9fae0b"
        , "f91b65c5524733ab8f593dabcd62b357"
        , "1639d624e65152ab8f530c359f0861d8"
        , "07ca0dbf500d6a6156a38e088a22b65e"
        , "52bc514d16ccf806818ce91ab7793736"
        , "5af90bbf74a35be6b40b8eedf2785e42"
        , "874d"
        ]
  got <- expectOk "rfc 2.4.2 encrypt" =<<
    cipherEncrypt env C_CHACHA20 key iv1 pt
  assertEqual "rfc 2.4.2 ct" ct got
  back <- expectOk "rfc 2.4.2 decrypt" =<<
    cipherDecrypt env C_CHACHA20 key iv1 got
  assertEqual "rfc 2.4.2 roundtrip" pt back
  -- Counter 0 differs (the framework's block-counter
  -- independence leg); unaligned input preserves length.
  let iv0 = hex "00000000" <> nonce
  got0 <- expectOk "counter 0 encrypt" =<<
    cipherEncrypt env C_CHACHA20 key iv0 pt
  assertBool "counters differentiate" (got0 /= got)
  ragged <- expectOk "unaligned encrypt" =<<
    cipherEncrypt env C_CHACHA20 key iv0 "twenty bytes exactly!!"
  assertEqual "length preserved" 22 (BS.length ragged)
  -- Bounds: key exactly 32, framing exactly 20.
  expectBadParam "short key" =<<
    cipherEncrypt env C_CHACHA20 (KeyBytes "short") iv0 pt
  expectBadParam "bare nonce" =<<
    cipherEncrypt env C_CHACHA20 key nonce pt

-- | RFC 8439 section 2.8.2: key 80..9f, nonce
-- 070000004041424344454647, the 12-byte AAD, the Sunscreen
-- plaintext, fixed 16-byte tag.
caseChachaPolyReal :: IO ()
caseChachaPolyReal = withBackend $ \env -> do
  let key = KeyBytes (hex "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
      nonce = hex "070000004041424344454647"
      aad = hex "50515253c0c1c2c3c4c5c6c7"
      pt = chachaSunscreen
      aead = AeadSpec "ChaCha20-Poly1305" 12 16
      ct = hex $ concat
        [ "d31a8d34648e60db7b86afbc53ef7ec2"
        , "a4aded51296e08fea9e2b5a736ee62d6"
        , "3dbea45e8ca9671282fafb69da92728b"
        , "1a71de0a9e060b2905d6a5b67ecd3b36"
        , "92ddbd7f2d778b8c9803aee328091b58"
        , "fab324e4fad675945585808b4831d7bc"
        , "3ff4def08e4b7a9de576d26586cec64b"
        , "6116"
        ]
      tag = hex "1ae10b594f09e26a7e902ecbd0600691"
  (got, gotTag) <- expectOk "rfc 2.8.2 seal" =<<
    aeadEncrypt env aead key nonce aad pt
  assertEqual "rfc 2.8.2 ct" ct got
  assertEqual "rfc 2.8.2 tag" tag gotTag
  back <- expectOk "rfc 2.8.2 open" =<<
    aeadDecrypt env aead key nonce aad got gotTag
  assertEqual "rfc 2.8.2 roundtrip" pt back
  -- Tampering anywhere fails closed.
  let badTag = BS.pack [BS.head gotTag `xor` 1] <> BS.tail gotTag
  expectAuthFailed "tag tamper" =<<
    aeadDecrypt env aead key nonce aad got badTag
  expectAuthFailed "aad tamper" =<<
    aeadDecrypt env aead key nonce "tampered-aad!" got gotTag
  -- Bounds: key exactly 32, tag exactly 16.
  expectBadParam "short key" =<<
    aeadEncrypt env aead (KeyBytes "short") nonce aad pt
  expectBadParam "short tag" =<<
    aeadEncrypt env (AeadSpec "ChaCha20-Poly1305" 12 8) key nonce aad pt

-- | The RFC 8439 Sunscreen plaintext (114 bytes).
chachaSunscreen :: ByteString
chachaSunscreen =
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
