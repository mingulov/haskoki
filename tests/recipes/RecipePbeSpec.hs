{- | PBE recipe pins (slice 11m, stage 1: codec/table/parity).

'Haskoki.Recipe.Pbe' owns the canonical codec, parameter
validation, and the two-row table; 'Haskoki.Operation.KeyManagement'
owns keygen admission (fixed key type and length per row);
'Haskoki.Engine.Driver' owns the PKCS#12-KDF execution plus DES
odd-parity adjustment. This spec pins the table, id resolution,
codec identity, the parameter matrix (iteration bounds, material
ceilings), and the parity helper.

Reference vectors (password = @TestPassword123!@, salt =
@deadbeefcafebabe@, iterations = 1024; the PKCS#12 §6.38
construction with raw password bytes; triple-checked: a Python
implementation of the section prose agrees byte-exact with the
pinned provider @PKCS12KDF@, and the unicode-password variant
agrees too):

* 0x3a8 DES3 key (parity-adjusted): 73b93bb0...
* 0x3a8 IV: f7eb3b1c7d9ce2a0
* 0x3a9 DES2 key (parity-adjusted): 73b93bb0... (16 bytes)

Slice 11q adds the five SHA1 rows over the same KDF outputs
(raw bytes, no parity; RC4 rows derive no IV):

* 0x3a5 CAST128 key: 72b93bb1f796b464f6d80317b27e0fe8
* 0x3a6 RC4-128 key: 72b93bb1f796b464f6d80317b27e0fe8
* 0x3a7 RC4-40 key: 72b93bb1f7
* 0x3aa RC2-128 key: 72b93bb1f796b464f6d80317b27e0fe8
* 0x3ab RC2-40 key: 72b93bb1f7

The MD5 rows run the D-chain (@D1@ is the provider-PBKDF1
root @ffd54e05...@, @D2 = 69fba8ad...@):

* 0x3a1 DES key (parity-adjusted): fed54f04efa44a7a, IV f3a2adee8fa98e67
* 0x3a2 CAST key: ffd54e05ee, IV a44b7bf3a2adee8f
* 0x3a3 CAST3 key: ffd54e05eea44b7bf3a2, IV adee8fa98e6769fb
* 0x3a4 CAST128 key: ffd54e05eea44b7bf3a2adee8fa98e67, IV 69fba8ad294fa220
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipePbeSpec (spec) where

import qualified Data.ByteString as BS
import Data.Bits (popCount)
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Recipe.Pbe
  ( PbeKdf (..)
  , PbeKind (..)
  , PbeRecipe (..)
  , decodePbeParams
  , encodePbeParams
  , maxPbeIters
  , maxPbeMaterial
  , pbeCodec
  , pbeDesParity
  , pbeIvLen
  , pbeKdf
  , pbeKeyLen
  , pbeNeedsParity
  , pbeParamsValid
  , pbeRecipeFor
  , pbeRecipes
  )
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), ParameterCodec (..))

spec :: TestTree
spec = testGroup "RecipePbeSpec"
  [ testCase "table carries the eleven PBE rows" $ do
      let names = map pbeName pbeRecipes
      assertEqual "rows"
        [ "CKM_PBE_SHA1_DES3_EDE_CBC", "CKM_PBE_SHA1_DES2_EDE_CBC"
        , "CKM_PBE_SHA1_CAST128_CBC", "CKM_PBE_SHA1_RC4_128"
        , "CKM_PBE_SHA1_RC4_40", "CKM_PBE_SHA1_RC2_128_CBC"
        , "CKM_PBE_SHA1_RC2_40_CBC", "CKM_PBE_MD5_DES_CBC"
        , "CKM_PBE_MD5_CAST_CBC", "CKM_PBE_MD5_CAST3_CBC"
        , "CKM_PBE_MD5_CAST128_CBC"
        ] names
      assertEqual "codec" (ParameterCodec "pbe-params" 1) pbeCodec
  , testCase "id resolution matches the table" $ do
      let des3 = MechanismId (mustGeneratedId "CKM_PBE_SHA1_DES3_EDE_CBC")
          des2 = MechanismId (mustGeneratedId "CKM_PBE_SHA1_DES2_EDE_CBC")
          cast5 = MechanismId (mustGeneratedId "CKM_PBE_SHA1_CAST128_CBC")
          rc4b = MechanismId (mustGeneratedId "CKM_PBE_SHA1_RC4_128")
          rc4s = MechanismId (mustGeneratedId "CKM_PBE_SHA1_RC4_40")
          rc2b = MechanismId (mustGeneratedId "CKM_PBE_SHA1_RC2_128_CBC")
          rc2s = MechanismId (mustGeneratedId "CKM_PBE_SHA1_RC2_40_CBC")
      assertEqual "des3 kind" (Just PbeDes3) (pbeKind <$> pbeRecipeFor des3)
      assertEqual "des2 kind" (Just PbeDes2) (pbeKind <$> pbeRecipeFor des2)
      assertEqual "cast128 kind" (Just PbeSha1Cast128) (pbeKind <$> pbeRecipeFor cast5)
      assertEqual "rc4-128 kind" (Just PbeSha1Rc4_128) (pbeKind <$> pbeRecipeFor rc4b)
      assertEqual "rc4-40 kind" (Just PbeSha1Rc4_40) (pbeKind <$> pbeRecipeFor rc4s)
      assertEqual "rc2-128 kind" (Just PbeSha1Rc2_128) (pbeKind <$> pbeRecipeFor rc2b)
      assertEqual "rc2-40 kind" (Just PbeSha1Rc2_40) (pbeKind <$> pbeRecipeFor rc2s)
      let md5d = MechanismId (mustGeneratedId "CKM_PBE_MD5_DES_CBC")
          md5c = MechanismId (mustGeneratedId "CKM_PBE_MD5_CAST_CBC")
          md53 = MechanismId (mustGeneratedId "CKM_PBE_MD5_CAST3_CBC")
          md5c128 = MechanismId (mustGeneratedId "CKM_PBE_MD5_CAST128_CBC")
      assertEqual "md5-des kind" (Just PbeMd5Des) (pbeKind <$> pbeRecipeFor md5d)
      assertEqual "md5-cast kind" (Just PbeMd5Cast) (pbeKind <$> pbeRecipeFor md5c)
      assertEqual "md5-cast3 kind" (Just PbeMd5Cast3) (pbeKind <$> pbeRecipeFor md53)
      assertEqual "md5-cast128 kind" (Just PbeMd5Cast128) (pbeKind <$> pbeRecipeFor md5c128)
      assertEqual "wild misses" Nothing
        (pbeRecipeFor (MechanismId 0x999 :: MechanismId))
  , testCase "key and IV lengths are fixed per row" $ do
      assertEqual "des3 key" 24 (pbeKeyLen PbeDes3)
      assertEqual "des2 key" 16 (pbeKeyLen PbeDes2)
      assertEqual "cast128 key" 16 (pbeKeyLen PbeSha1Cast128)
      assertEqual "rc4-128 key" 16 (pbeKeyLen PbeSha1Rc4_128)
      assertEqual "rc4-40 key" 5 (pbeKeyLen PbeSha1Rc4_40)
      assertEqual "rc2-128 key" 16 (pbeKeyLen PbeSha1Rc2_128)
      assertEqual "rc2-40 key" 5 (pbeKeyLen PbeSha1Rc2_40)
      assertEqual "des3 iv" 8 (pbeIvLen PbeDes3)
      assertEqual "des2 iv" 8 (pbeIvLen PbeDes2)
      assertEqual "cast128 iv" 8 (pbeIvLen PbeSha1Cast128)
      assertEqual "rc4-128 iv" 0 (pbeIvLen PbeSha1Rc4_128)
      assertEqual "rc4-40 iv" 0 (pbeIvLen PbeSha1Rc4_40)
      assertEqual "rc2-128 iv" 8 (pbeIvLen PbeSha1Rc2_128)
      assertEqual "rc2-40 iv" 8 (pbeIvLen PbeSha1Rc2_40)
      assertEqual "des3 parity" True (pbeNeedsParity PbeDes3)
      assertEqual "des2 parity" True (pbeNeedsParity PbeDes2)
      assertEqual "cast128 raw" False (pbeNeedsParity PbeSha1Cast128)
      assertEqual "rc4-128 raw" False (pbeNeedsParity PbeSha1Rc4_128)
      assertEqual "rc4-40 raw" False (pbeNeedsParity PbeSha1Rc4_40)
      assertEqual "rc2-128 raw" False (pbeNeedsParity PbeSha1Rc2_128)
      assertEqual "rc2-40 raw" False (pbeNeedsParity PbeSha1Rc2_40)
      assertEqual "md5-des key" 8 (pbeKeyLen PbeMd5Des)
      assertEqual "md5-cast key" 5 (pbeKeyLen PbeMd5Cast)
      assertEqual "md5-cast3 key" 10 (pbeKeyLen PbeMd5Cast3)
      assertEqual "md5-cast128 key" 16 (pbeKeyLen PbeMd5Cast128)
      assertEqual "md5-des iv" 8 (pbeIvLen PbeMd5Des)
      assertEqual "md5-cast iv" 8 (pbeIvLen PbeMd5Cast)
      assertEqual "md5-cast3 iv" 8 (pbeIvLen PbeMd5Cast3)
      assertEqual "md5-cast128 iv" 8 (pbeIvLen PbeMd5Cast128)
      assertEqual "md5-des parity" True (pbeNeedsParity PbeMd5Des)
      assertEqual "md5-cast raw" False (pbeNeedsParity PbeMd5Cast)
      assertEqual "md5-cast3 raw" False (pbeNeedsParity PbeMd5Cast3)
      assertEqual "md5-cast128 raw" False (pbeNeedsParity PbeMd5Cast128)
      assertEqual "des3 kdf" PbePkcs12Sha1 (pbeKdf PbeDes3)
      assertEqual "rc4-40 kdf" PbePkcs12Sha1 (pbeKdf PbeSha1Rc4_40)
      assertEqual "md5-des kdf" PbePbkdf1Md5 (pbeKdf PbeMd5Des)
      assertEqual "md5-cast kdf" PbePbkdf1Md5 (pbeKdf PbeMd5Cast)
      assertEqual "md5-cast3 kdf" PbePbkdf1Md5 (pbeKdf PbeMd5Cast3)
      assertEqual "md5-cast128 kdf" PbePbkdf1Md5 (pbeKdf PbeMd5Cast128)
  , testCase "frame round-trips the lane fixtures" $ do
      let frame = encodePbeParams 1024 pw salt
      case decodePbeParams frame of
        Nothing -> fail "frame refused"
        Just (iters, pw', salt') -> do
          assertEqual "iters" 1024 iters
          assertEqual "pw" pw pw'
          assertEqual "salt" salt salt'
  , testCase "frame rejects truncation and trailing bytes" $ do
      let frame = encodePbeParams 1024 pw salt
      assertEqual "short" Nothing (decodePbeParams (BS.take (BS.length frame - 1) frame))
      assertEqual "trailing" Nothing (decodePbeParams (frame <> BS.singleton 0))
      assertEqual "empty" Nothing (decodePbeParams BS.empty)
  , testCase "parameter matrix accepts and refuses" $ do
      let good = encodePbeParams 1024 pw salt
      case pbeRecipeFor (MechanismId (mustGeneratedId "CKM_PBE_SHA1_DES3_EDE_CBC")) of
        Nothing -> fail "des3 recipe missing"
        Just r3 -> do
          assertBool "lane fixtures accept" (pbeParamsValid r3 good)
          assertBool "zero iters refuse"
            (not (pbeParamsValid r3 (encodePbeParams 0 pw salt)))
          assertBool "over-bound iters refuse"
            (not (pbeParamsValid r3 (encodePbeParams (fromIntegral maxPbeIters + 1) pw salt)))
          assertBool "max iters accept"
            (pbeParamsValid r3 (encodePbeParams (fromIntegral maxPbeIters) pw salt))
          let big = BS.replicate (maxPbeMaterial + 1) 0x41
          assertBool "over-material refuse"
            (not (pbeParamsValid r3 (encodePbeParams 1024 big salt)))
          assertBool "empty password accepts (spec: P empty is defined)"
            (pbeParamsValid r3 (encodePbeParams 1024 BS.empty salt))
          assertBool "empty salt accepts (spec: S empty is defined)"
            (pbeParamsValid r3 (encodePbeParams 1024 pw BS.empty))
  , testCase "DES odd parity adjusts the low bit" $ do
      assertEqual "upper-even sets" (BS.pack [0x73]) (pbeDesParity (BS.pack [0x72]))
      assertEqual "already-odd keeps" (BS.pack [0x73]) (pbeDesParity (BS.pack [0x73]))
      assertEqual "upper-odd clears" (BS.pack [0x02]) (pbeDesParity (BS.pack [0x03]))
      assertEqual "lane pre-parity head adjusts to the key"
        des3Key (pbeDesParity des3PreParity)
      assertBool "adjusted key is all-odd" (BS.all (odd . popCount) des3Key)
  , testCase "ground-truth vectors are recorded" $ do
      assertEqual "des3 key" "73b93bb0f797b564f7d90216b37f0ee9e9bc8004021fd39d"
        (hex des3Key)
      assertEqual "des3 iv" "f7eb3b1c7d9ce2a0" (hex des3Iv)
      assertEqual "des2 key" "73b93bb0f797b564f7d90216b37f0ee9" (hex des2Key)
      assertEqual "des2 iv" "f7eb3b1c7d9ce2a0" (hex des3Iv)
      assertEqual "cast128 key" "72b93bb1f796b464f6d80317b27e0fe8" (hex cast128Key)
      assertEqual "rc4-128 key" "72b93bb1f796b464f6d80317b27e0fe8" (hex rc4_128Key)
      assertEqual "rc4-40 key" "72b93bb1f7" (hex rc4_40Key)
      assertEqual "rc2-128 key" "72b93bb1f796b464f6d80317b27e0fe8" (hex rc2_128Key)
      assertEqual "rc2-40 key" "72b93bb1f7" (hex rc2_40Key)
      assertEqual "md5-des key" "fed54f04efa44a7a" (hex md5DesKey)
      assertEqual "md5-des iv" "f3a2adee8fa98e67" (hex md5DesIv)
      assertEqual "md5-cast key" "ffd54e05ee" (hex md5CastKey)
      assertEqual "md5-cast iv" "a44b7bf3a2adee8f" (hex md5CastIv)
      assertEqual "md5-cast3 key" "ffd54e05eea44b7bf3a2" (hex md5Cast3Key)
      assertEqual "md5-cast3 iv" "adee8fa98e6769fb" (hex md5Cast3Iv)
      assertEqual "md5-cast128 key" "ffd54e05eea44b7bf3a2adee8fa98e67" (hex md5Cast128Key)
      assertEqual "md5-cast128 iv" "69fba8ad294fa220" (hex md5Cast128Iv)
  ]
  where
    pw = "TestPassword123!" :: BS.ByteString
    salt = BS.pack [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]
    des3Key = BS.pack
      [ 0x73, 0xb9, 0x3b, 0xb0, 0xf7, 0x97, 0xb5, 0x64
      , 0xf7, 0xd9, 0x02, 0x16, 0xb3, 0x7f, 0x0e, 0xe9
      , 0xe9, 0xbc, 0x80, 0x04, 0x02, 0x1f, 0xd3, 0x9d
      ]
    des3PreParity = BS.pack
      [ 0x72, 0xb9, 0x3b, 0xb1, 0xf7, 0x96, 0xb4, 0x64
      , 0xf6, 0xd8, 0x03, 0x17, 0xb2, 0x7e, 0x0f, 0xe8
      , 0xe8, 0xbc, 0x80, 0x04, 0x02, 0x1e, 0xd3, 0x9d
      ]
    des3Iv = BS.pack [0xf7, 0xeb, 0x3b, 0x1c, 0x7d, 0x9c, 0xe2, 0xa0]
    des2Key = BS.take 16 des3Key
    cast128Key = BS.take 16 des3PreParity
    rc4_128Key = BS.take 16 des3PreParity
    rc4_40Key = BS.take 5 des3PreParity
    rc2_128Key = BS.take 16 des3PreParity
    rc2_40Key = BS.take 5 des3PreParity
    md5d1 = BS.pack
      [ 0xff, 0xd5, 0x4e, 0x05, 0xee, 0xa4, 0x4b, 0x7b
      , 0xf3, 0xa2, 0xad, 0xee, 0x8f, 0xa9, 0x8e, 0x67
      ]
    md5d2 = BS.pack
      [ 0x69, 0xfb, 0xa8, 0xad, 0x29, 0x4f, 0xa2, 0x20
      , 0xd9, 0x6d, 0xc7, 0x4e, 0xb7, 0xcc, 0xb2, 0x02
      ]
    md5stream = md5d1 <> md5d2
    md5DesKey = pbeDesParity (BS.take 8 md5stream)
    md5DesIv = BS.take 8 (BS.drop 8 md5stream)
    md5CastKey = BS.take 5 md5stream
    md5CastIv = BS.take 8 (BS.drop 5 md5stream)
    md5Cast3Key = BS.take 10 md5stream
    md5Cast3Iv = BS.take 8 (BS.drop 10 md5stream)
    md5Cast128Key = BS.take 16 md5stream
    md5Cast128Iv = BS.take 8 (BS.drop 16 md5stream)
    hex = concatMap (flip showHex2 "") . BS.unpack
    showHex2 w rest =
      let hi = "0123456789abcdef" !! fromIntegral (w `div` 16)
          lo = "0123456789abcdef" !! fromIntegral (w `mod` 16)
      in hi : lo : rest
