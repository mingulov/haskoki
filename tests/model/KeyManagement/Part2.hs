{- | KeyManagement Part 2: symmetric keygen.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.Part2
  ( caseAesKeygen
  , caseDes3Keygen
  , caseBlake2b512Keygen
  , caseChacha20Keygen
  ) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Test.Tasty.HUnit (assertEqual, assertFailure)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  )
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState
  )
import Haskoki.Object (resolveHandle)
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoResult (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , blake2b512KeyGenMech
  , chacha20KeyGenMech
  , ckkAes
  , ckkBlake2b512Hmac
  , ckkChacha20
  , ckkDes3
  , ckoSecretKey
  , des3KeyGenMech
  , keyBytesOf
  , planGenerateKey
  )
import Haskoki.Outcome
  ( PreparedCommit (..)
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , ReturnCode (..)
  )
import KeyManagement.Fixtures
import KeyManagement.Part2Fixtures

-- ---------------------------------------------------------------------------
-- Part 2
-- ---------------------------------------------------------------------------

caseAesKeygen :: IO ()
caseAesKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genAesKey answer m0 st (aesTmpl 32)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
  assertEqual "key type" (Just (ValULong ckkAes)) (Map.lookup AttrKeyType (osAttrs ost))
  assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "AES-256 material" 32 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"

caseDes3Keygen :: IO ()
caseDes3Keygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genDes3Key answer m0 st (des3Tmpl 24)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
  assertEqual "key type" (Just (ValULong ckkDes3)) (Map.lookup AttrKeyType (osAttrs ost))
  assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrSign (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "DES3 material" 24 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"
  -- Two-key mints; off-geometry refuses inconsistent; a missing
  -- length mints three-key (24 bytes, the headline default).
  (m2, h2) <- genDes3Key answer m1 st (des3Tmpl 16)
  Just ost2 <- pure (resolveHandle m2 h2)
  case keyBytesOf ost2 of
    Just mat2 -> assertEqual "DES3 two-key material" 16 (BS.length mat2)
    Nothing -> assertFailure "generated key lacks material"
  case planGenerateKey defaultRules m2 st des3KeyGenMech BS.empty (des3Tmpl 32) of
    KeyDenied deny -> assertEqual "bad length code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("32-byte DES3 must refuse: " ++ show other)
  (m3, h3) <- genDes3Key answer m2 st
    [a | a@(t, _) <- des3Tmpl 24, t /= AttrValueLen]
  Just ost3 <- pure (resolveHandle m3 h3)
  case keyBytesOf ost3 of
    Just mat3 -> assertEqual "DES3 default material" 24 (BS.length mat3)
    Nothing -> assertFailure "generated key lacks material"

caseBlake2b512Keygen :: IO ()
caseBlake2b512Keygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genBlake2b512Key answer m0 st (blake2b512Tmpl 64)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
  assertEqual "key type" (Just (ValULong ckkBlake2b512Hmac)) (Map.lookup AttrKeyType (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "BLAKE2B-512 material" 64 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"
  -- HMAC keygens take a VALUE_LEN-sized key (spec 6.x: "with a
  -- particular length in bytes, as specified in CKA_VALUE_LEN"),
  -- so 32 bytes mint; empty and over-frame refuse
  -- inconsistent, and a missing length refuses incomplete.
  (m2, h2) <- genBlake2b512Key answer m1 st (blake2b512Tmpl 32)
  Just ost2 <- pure (resolveHandle m2 h2)
  case keyBytesOf ost2 of
    Just mat2 -> assertEqual "BLAKE2B-512 short material" 32 (BS.length mat2)
    Nothing -> assertFailure "generated key lacks material"
  (m3, h3) <- genBlake2b512Key answer m2 st (blake2b512Tmpl 1)
  Just ost3 <- pure (resolveHandle m3 h3)
  case keyBytesOf ost3 of
    Just mat3 -> assertEqual "BLAKE2B-512 minimal material" 1 (BS.length mat3)
    Nothing -> assertFailure "generated key lacks material"
  (m4, h4) <- genBlake2b512Key answer m3 st (blake2b512Tmpl 255)
  Just ost4 <- pure (resolveHandle m4 h4)
  case keyBytesOf ost4 of
    Just mat4 -> assertEqual "BLAKE2B-512 maximal material" 255 (BS.length mat4)
    Nothing -> assertFailure "generated key lacks material"
  case planGenerateKey defaultRules m4 st blake2b512KeyGenMech BS.empty (blake2b512Tmpl 0) of
    KeyDenied deny -> assertEqual "empty length code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("0-byte BLAKE2B-512 must refuse: " ++ show other)
  case planGenerateKey defaultRules m4 st blake2b512KeyGenMech BS.empty (blake2b512Tmpl 256) of
    KeyDenied deny -> assertEqual "over-frame length code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("256-byte BLAKE2B-512 must refuse: " ++ show other)
  case planGenerateKey defaultRules m4 st blake2b512KeyGenMech BS.empty
      [a | a@(t, _) <- blake2b512Tmpl 64, t /= AttrValueLen] of
    KeyDenied deny -> assertEqual "missing length code"
      CKR_TEMPLATE_INCOMPLETE (kdCode deny)
    other -> assertFailure ("missing length must refuse: " ++ show other)

-- | Generate one BLAKE2B-512 HMAC key through the planner +
-- synthetic backend.
genBlake2b512Key :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genBlake2b512Key answer m st tmpl = case planGenerateKey defaultRules m st blake2b512KeyGenMech BS.empty tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

blake2b512Tmpl :: Int -> [(AttributeType, AttributeValue)]
blake2b512Tmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkBlake2b512Hmac)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrSign, ValBool True)
  , (AttrVerify, ValBool True)
  ]

caseChacha20Keygen :: IO ()
caseChacha20Keygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genChacha20Key answer m0 st (chacha20Tmpl 32)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
  assertEqual "key type" (Just (ValULong ckkChacha20)) (Map.lookup AttrKeyType (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "ChaCha20 material" 32 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"
  -- Off-width refuses inconsistent; a missing length refuses
  -- incomplete (exact-32, the HOTP explicit-length precedent).
  case planGenerateKey defaultRules m1 st chacha20KeyGenMech BS.empty (chacha20Tmpl 16) of
    KeyDenied deny -> assertEqual "bad length code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("16-byte ChaCha20 must refuse: " ++ show other)
  case planGenerateKey defaultRules m1 st chacha20KeyGenMech BS.empty
      [a | a@(t, _) <- chacha20Tmpl 32, t /= AttrValueLen] of
    KeyDenied deny -> assertEqual "missing length code"
      CKR_TEMPLATE_INCOMPLETE (kdCode deny)
    other -> assertFailure ("missing length must refuse: " ++ show other)

-- | Generate one ChaCha20 key through the planner + synthetic backend.
genChacha20Key :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genChacha20Key answer m st tmpl = case planGenerateKey defaultRules m st chacha20KeyGenMech BS.empty tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

chacha20Tmpl :: Int -> [(AttributeType, AttributeValue)]
chacha20Tmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkChacha20)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrEncrypt, ValBool True)
  , (AttrDecrypt, ValBool True)
  ]
