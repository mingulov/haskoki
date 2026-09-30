{- | Wrap-composition RSA recipe tests.

The RSA half of the wrap-composition group: the single header
mechanism @CKM_RSA_AES_KEY_WRAP@ (0x1054) over
@wrapcomp-rsa-params\/1@ (@digest:u64be mgf:u64be
labelLen:u64be label aesBits:u64be@). The OAEP frame reuses
the @oaep-params\/1@ digest codes; the temp KEK is random at
the requested strength; the blob is the modulus-wide OAEP
head plus the KWP tail.

'Haskoki.Recipe.WrapCompRsa' owns the codec, validation,
key-type gate, KEK-fit bound, and blob split; these tests
pin the recipe. Consumers (planner arms, driver arms,
engines) pin their own layers against this table.
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeWrapCompRsaSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Der (rsaPrivateDer, rsaPublicDer)
import Haskoki.Recipe.WrapCompRsa
  ( WrapCompRsaRecipe (..)
  , decodeWrapCompRsaParams
  , encodeWrapCompRsaParams
  , wrapCompRsaAesBitsSet
  , wrapCompRsaAesBytes
  , wrapCompRsaFrameHead
  , wrapCompRsaKekFits
  , wrapCompRsaKeyOk
  , wrapCompRsaModulusBytes
  , wrapCompRsaOaep
  , wrapCompRsaParamsValid
  , wrapCompRsaRecipeFor
  , wrapCompRsaSplitBlob
  , wrapCompRsaUnframeHead
  )
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..))

spec :: TestTree
spec = testGroup "wrap-composition RSA recipe"
  [ testCase "codec round-trips" caseCodecRoundtrip
  , testCase "canonical layout pins codes" caseCanonicalLayout
  , testCase "validation serves strengths, refuses off-set" caseValidation
  , testCase "truncation, overrun, and trailing bytes refuse" caseStrictDecode
  , testCase "unknown digest codes refuse" caseUnknownCodes
  , testCase "labels ride to the backend" caseLabels
  , testCase "row lookup and key gate" caseRowGate
  , testCase "KEK-fit bound follows k - 2h - 2" caseKekFit
  , testCase "split takes the modulus head plus a KWP tail" caseSplit
  , testCase "modulus scan reads DER halves" caseModulusScan
  , testCase "head framing pads short seals, passes exact heads" caseFraming
  ]

sha256 :: Text
sha256 = "SHA256"

caseCodecRoundtrip :: IO ()
caseCodecRoundtrip = do
  let p = encodeWrapCompRsaParams sha256 sha256 "" 256
  assertEqual "roundtrip" (Just (sha256, sha256, "", 256))
    (decodeWrapCompRsaParams p)
  let q = encodeWrapCompRsaParams "SHA_1" "SHA_1" "tag" 128
  assertEqual "labeled roundtrip" (Just ("SHA_1", "SHA_1", "tag", 128))
    (decodeWrapCompRsaParams q)

caseCanonicalLayout :: IO ()
caseCanonicalLayout = do
  -- SHA256 is code 4 on both words, empty label, 256-bit strength.
  let p = encodeWrapCompRsaParams sha256 sha256 "" 256
      word :: Int -> BS.ByteString
      word n = BS.pack [0, 0, 0, 0, 0, 0, fromIntegral (n `div` 256), fromIntegral (n `mod` 256)]
  assertEqual "exact image"
    (word 4 <> word 4 <> word 0 <> word 256) p
  assertEqual "served set" [128, 192, 256] wrapCompRsaAesBitsSet

caseValidation :: IO ()
caseValidation = do
  Just r <- pure (wrapCompRsaRecipeFor (MechanismId 0x1054))
  assertBool "sha256/256 valid"
    (wrapCompRsaParamsValid r (encodeWrapCompRsaParams sha256 sha256 "" 256))
  assertBool "sha1/128 valid"
    (wrapCompRsaParamsValid r (encodeWrapCompRsaParams "SHA_1" "SHA_1" "" 128))
  assertBool "off-set strength refused"
    (not (wrapCompRsaParamsValid r (encodeWrapCompRsaParams sha256 sha256 "" 512)))
  assertEqual "aes bytes 256" (Just 32)
    (wrapCompRsaAesBytes (encodeWrapCompRsaParams sha256 sha256 "" 256))
  assertEqual "aes bytes 192" (Just 24)
    (wrapCompRsaAesBytes (encodeWrapCompRsaParams sha256 sha256 "" 192))
  assertEqual "aes bytes 128" (Just 16)
    (wrapCompRsaAesBytes (encodeWrapCompRsaParams sha256 sha256 "" 128))
  assertEqual "aes bytes off-set" Nothing
    (wrapCompRsaAesBytes (encodeWrapCompRsaParams sha256 sha256 "" 512))
  assertEqual "oaep frame"
    (Just (sha256, sha256, ""))
    (wrapCompRsaOaep (encodeWrapCompRsaParams sha256 sha256 "" 256))

caseStrictDecode :: IO ()
caseStrictDecode = do
  let p = encodeWrapCompRsaParams sha256 sha256 "tag" 256
  assertEqual "truncated" Nothing
    (decodeWrapCompRsaParams (BS.take (BS.length p - 1) p))
  assertEqual "trailing" Nothing
    (decodeWrapCompRsaParams (p <> "x"))
  -- Label-length overrun: the length word lies past the end.
  let badLen = BS.take 16 p <> BS.pack [0, 0, 0, 0, 0, 0, 0, 99] <> "tag"
  assertEqual "overrun" Nothing (decodeWrapCompRsaParams badLen)
  Just r <- pure (wrapCompRsaRecipeFor (MechanismId 0x1054))
  assertBool "truncated invalid"
    (not (wrapCompRsaParamsValid r (BS.take 10 p)))

caseUnknownCodes :: IO ()
caseUnknownCodes = do
  let word :: Int -> BS.ByteString
      word n = BS.pack [0, 0, 0, 0, 0, 0, fromIntegral (n `div` 256), fromIntegral (n `mod` 256)]
      bad = word 99 <> word 4 <> word 0 <> word 256
  assertEqual "unknown digest" Nothing (decodeWrapCompRsaParams bad)
  let badMgf = word 4 <> word 99 <> word 0 <> word 256
  assertEqual "unknown mgf" Nothing (decodeWrapCompRsaParams badMgf)

caseLabels :: IO ()
caseLabels = do
  Just r <- pure (wrapCompRsaRecipeFor (MechanismId 0x1054))
  -- Non-empty labels are served: they ride the OAEP frame to
  -- the backend exactly like the CKM_RSA_PKCS_OAEP row.
  assertBool "labeled valid"
    (wrapCompRsaParamsValid r (encodeWrapCompRsaParams sha256 sha256 "tag" 256))

caseRowGate :: IO ()
caseRowGate = do
  let mid = MechanismId (mustGeneratedId "CKM_RSA_AES_KEY_WRAP")
  Just r <- pure (wrapCompRsaRecipeFor mid)
  assertEqual "row name" "CKM_RSA_AES_KEY_WRAP" (wcrName r)
  assertEqual "unknown row" Nothing
    (wrapCompRsaRecipeFor (MechanismId 0x1053))
  assertBool "rsa admitted"
    (wrapCompRsaKeyOk r (mustKeyTypeId "CKK_RSA"))
  assertBool "aes refused"
    (not (wrapCompRsaKeyOk r (mustKeyTypeId "CKK_AES")))
  assertBool "ec refused"
    (not (wrapCompRsaKeyOk r (mustKeyTypeId "CKK_EC")))

caseKekFit :: IO ()
caseKekFit = do
  -- 2048-bit RSA, SHA-256: 256 - 64 - 2 = 190 >= 32.
  assertBool "2048/sha256/32 fits" (wrapCompRsaKekFits 256 sha256 32)
  assertBool "2048/sha256/16 fits" (wrapCompRsaKekFits 256 sha256 16)
  -- 512-bit RSA, SHA-256: 64 - 64 - 2 < 0 refuses every strength.
  assertBool "512/sha256/16 refused" (not (wrapCompRsaKekFits 64 sha256 16))
  -- 1024-bit RSA, SHA-512: 128 - 128 - 2 < 0 refuses.
  assertBool "1024/sha512/16 refused" (not (wrapCompRsaKekFits 128 "SHA512" 16))
  -- 1024-bit RSA, SHA-1: 128 - 40 - 2 = 86 >= 32.
  assertBool "1024/sha1/32 fits" (wrapCompRsaKekFits 128 "SHA_1" 32)

caseSplit :: IO ()
caseSplit = do
  let blob = BS.replicate 256 0x52 <> BS.replicate 24 0x4b
  assertEqual "head/tail" (Just (BS.replicate 256 0x52, BS.replicate 24 0x4b))
    (wrapCompRsaSplitBlob 256 blob)
  assertEqual "short" Nothing (wrapCompRsaSplitBlob 256 (BS.replicate 200 0))
  assertEqual "ragged tail" Nothing
    (wrapCompRsaSplitBlob 256 (BS.replicate 256 0 <> BS.replicate 20 0))
  assertEqual "short tail" Nothing
    (wrapCompRsaSplitBlob 256 (BS.replicate 256 0 <> BS.replicate 8 0))

caseModulusScan :: IO ()
caseModulusScan = do
  let n = BS.pack (0x80 : replicate 255 0x4d)
      spki = rsaPublicDer n "AQAB"
      pkcs8 = rsaPrivateDer n "AQAB" n n n n n n
  assertEqual "spki width" (Just 256) (wrapCompRsaModulusBytes spki)
  assertEqual "pkcs8 width" (Just 256) (wrapCompRsaModulusBytes pkcs8)
  assertEqual "garbage" Nothing (wrapCompRsaModulusBytes "not-a-key")
  assertEqual "short" Nothing (wrapCompRsaModulusBytes (BS.take 10 spki))

caseFraming :: IO ()
caseFraming = do
  let seal = BS.replicate 48 0x53
      exact = BS.replicate 256 0x52
  -- Exact-k heads pass through untouched (the real backend).
  assertEqual "exact passes" (Just exact) (wrapCompRsaFrameHead 256 48 exact)
  assertEqual "exact unframes" exact (wrapCompRsaUnframeHead 256 48 exact)
  -- Short seals zero-pad to k and strip back exactly.
  let padded = seal <> BS.replicate 208 0
  assertEqual "padded" (Just padded) (wrapCompRsaFrameHead 256 48 seal)
  assertEqual "stripped" seal (wrapCompRsaUnframeHead 256 48 padded)
  -- Over-wide seals refuse (never a wrong head).
  assertEqual "over-wide" Nothing
    (wrapCompRsaFrameHead 256 48 (BS.replicate 300 0x53))
  -- Wrong-short seals refuse too: only the exact seal width
  -- pads (anything else would strip to a wrong inner seal).
  assertEqual "wrong-short" Nothing
    (wrapCompRsaFrameHead 256 48 (BS.replicate 100 0x53))
  -- A k-wide head WITHOUT the zero run passes through whole
  -- (a real seal ending in nonzero bytes is not a padded seal).
  let realish = BS.replicate 200 0x52 <> BS.replicate 56 0x01
  assertEqual "nonzero tail passes" realish
    (wrapCompRsaUnframeHead 256 48 realish)
