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
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipePbeSpec (spec) where

import qualified Data.ByteString as BS
import Data.Bits (popCount)
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Recipe.Pbe
  ( PbeKind (..)
  , PbeRecipe (..)
  , decodePbeParams
  , encodePbeParams
  , maxPbeIters
  , maxPbeMaterial
  , pbeCodec
  , pbeDesParity
  , pbeIvLen
  , pbeKeyLen
  , pbeParamsValid
  , pbeRecipeFor
  , pbeRecipes
  )
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), ParameterCodec (..))

spec :: TestTree
spec = testGroup "RecipePbeSpec"
  [ testCase "table carries the two PBE rows" $ do
      let names = map pbeName pbeRecipes
      assertEqual "rows" ["CKM_PBE_SHA1_DES3_EDE_CBC", "CKM_PBE_SHA1_DES2_EDE_CBC"] names
      assertEqual "codec" (ParameterCodec "pbe-params" 1) pbeCodec
  , testCase "id resolution matches the table" $ do
      let des3 = MechanismId (mustGeneratedId "CKM_PBE_SHA1_DES3_EDE_CBC")
          des2 = MechanismId (mustGeneratedId "CKM_PBE_SHA1_DES2_EDE_CBC")
      assertEqual "des3 kind" (Just PbeDes3) (pbeKind <$> pbeRecipeFor des3)
      assertEqual "des2 kind" (Just PbeDes2) (pbeKind <$> pbeRecipeFor des2)
      assertEqual "wild misses" Nothing
        (pbeRecipeFor (MechanismId 0x999 :: MechanismId))
  , testCase "key and IV lengths are fixed per row" $ do
      assertEqual "des3 key" 24 (pbeKeyLen PbeDes3)
      assertEqual "des2 key" 16 (pbeKeyLen PbeDes2)
      assertEqual "des3 iv" 8 (pbeIvLen PbeDes3)
      assertEqual "des2 iv" 8 (pbeIvLen PbeDes2)
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
    hex = concatMap (flip showHex2 "") . BS.unpack
    showHex2 w rest =
      let hi = "0123456789abcdef" !! fromIntegral (w `div` 16)
          lo = "0123456789abcdef" !! fromIntegral (w `mod` 16)
      in hi : lo : rest
