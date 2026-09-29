{- | SSL3 recipe pins (slice 11n, stage 1: codec/table/validation).

'Haskoki.Recipe.Ssl3' owns the canonical codecs, parameter
validation, and the five-row table; 'Haskoki.Operation.Derive'
owns derive admission (generic-secret bases, template gates);
'Haskoki.Engine.Driver' owns the RFC 6101 execution; the FFI
owns the native struct normalizers. This spec pins the table,
id resolution, codec identity, the parameter matrix (random
lengths, key-mandatory rule, block ceilings, MAC bit widths),
the key-block layout order, and the base-key gate.

Reference vectors (RFC 6101 via hashlib, independent of the
token; oracle inputs CR = bytes(range(28)),
SR = bytes(range(28,56)), PMS = 03 00 || bytes(range(2,48))):

* master48: faf3f203...
* keyblock96 cMAC/sMAC/cKey/sKey/cIV/sIV: 698e3265.../cceb1267.../
  f9efaf9d.../0eca6dcc.../083ea2e0.../e601719a...
* md5mac (key bytes(range(16)), "test handshake data"):
  f8adc4aa2994ad2296ec759d1a321b0b
* sha1mac (same): d50aeadef9ad7678028f4188d05989fc869e57ca

The MAC length parameter is in BITS (the oracle passes 128
for a 16-byte MD5 tag and 160 for a 20-byte SHA-1 tag).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeSsl3Spec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Recipe.Hmac (encodeMacGeneral)
import Haskoki.Recipe.Ssl3
  ( Ssl3KeyMatRole (..)
  , Ssl3Kind (..)
  , Ssl3Recipe (..)
  , decodeSsl3KeyMatParams
  , decodeSsl3MasterParams
  , encodeSsl3KeyMatParams
  , encodeSsl3MasterParams
  , maxSsl3KeyBlock
  , maxSsl3Material
  , ssl3BaseKeyOk
  , ssl3CodecFor
  , ssl3KeyMatLayout
  , ssl3MacOutLen
  , ssl3ParamsValid
  , ssl3RecipeFor
  , ssl3Recipes
  )
import Haskoki.Registry.Generated
  ( ckm_SSL3_KEY_AND_MAC_DERIVE
  , ckm_SSL3_MASTER_KEY_DERIVE
  , ckm_SSL3_MASTER_KEY_DERIVE_DH
  , ckm_SSL3_MD5_MAC
  , ckm_SSL3_SHA1_MAC
  )
import Haskoki.Registry.Types (MechanismId (..), ParameterCodec (..))

cr28 :: BS.ByteString
cr28 = BS.pack [0 .. 27]

sr28 :: BS.ByteString
sr28 = BS.pack [28 .. 55]

recipeNamed :: Text -> Ssl3Recipe
recipeNamed want =
  case [r | r <- ssl3Recipes, ssl3Name r == want] of
    (r : _) -> r
    [] -> error "missing SSL3 recipe"

spec :: TestTree
spec = testGroup "SSL3 recipes"
  [ testCase "table carries the five quintet rows" $ do
      assertEqual "row count" 5 (length ssl3Recipes)
      assertEqual "row names"
        [ "CKM_SSL3_MASTER_KEY_DERIVE"
        , "CKM_SSL3_MASTER_KEY_DERIVE_DH"
        , "CKM_SSL3_KEY_AND_MAC_DERIVE"
        , "CKM_SSL3_MD5_MAC"
        , "CKM_SSL3_SHA1_MAC"
        ]
        (map ssl3Name ssl3Recipes)
  , testCase "mechanism ids resolve to their rows" $ do
      let kinds =
            [ (ckm_SSL3_MASTER_KEY_DERIVE, Ssl3Master)
            , (ckm_SSL3_MASTER_KEY_DERIVE_DH, Ssl3MasterDh)
            , (ckm_SSL3_KEY_AND_MAC_DERIVE, Ssl3KeyMat)
            , (ckm_SSL3_MD5_MAC, Ssl3Md5Mac)
            , (ckm_SSL3_SHA1_MAC, Ssl3Sha1Mac)
            ]
      mapM_ (\(i, k) ->
        assertEqual ("kind for " ++ show i) (Just k)
          (ssl3Kind <$> ssl3RecipeFor (MechanismId i))) kinds
      assertEqual "unknown id refuses" Nothing
        (ssl3RecipeFor (MechanismId 0xFFFF))
  , testCase "codec rides per shape" $ do
      assertEqual "master codec" (ParameterCodec "ssl3-master-params" 1)
        (ssl3CodecFor (recipeNamed "CKM_SSL3_MASTER_KEY_DERIVE"))
      assertEqual "keymat codec" (ParameterCodec "ssl3-keymat-params" 1)
        (ssl3CodecFor (recipeNamed "CKM_SSL3_KEY_AND_MAC_DERIVE"))
      assertEqual "MAC codec" (ParameterCodec "mac-general" 1)
        (ssl3CodecFor (recipeNamed "CKM_SSL3_MD5_MAC"))
  , testCase "master frame roundtrips" $ do
      let frame = encodeSsl3MasterParams cr28 sr28
      assertEqual "decode identity" (Just (cr28, sr28))
        (decodeSsl3MasterParams frame)
      assertEqual "trailing byte refuses" Nothing
        (decodeSsl3MasterParams (frame <> BS.singleton 0))
      assertEqual "truncation refuses" Nothing
        (decodeSsl3MasterParams (BS.take 10 frame))
  , testCase "master validation takes the oracle randoms" $ do
      let r = recipeNamed "CKM_SSL3_MASTER_KEY_DERIVE"
      assertBool "28-byte randoms accept" $
        ssl3ParamsValid r (encodeSsl3MasterParams cr28 sr28)
      assertBool "32-byte randoms accept" $
        ssl3ParamsValid r (encodeSsl3MasterParams (BS.replicate 32 1) (BS.replicate 32 2))
      assertBool "empty client random refuses" $
        not (ssl3ParamsValid r (encodeSsl3MasterParams BS.empty sr28))
      assertBool "empty server random refuses" $
        not (ssl3ParamsValid r (encodeSsl3MasterParams cr28 BS.empty))
      assertBool "over-ceiling material refuses" $
        not (ssl3ParamsValid r
          (encodeSsl3MasterParams
            (BS.replicate (maxSsl3Material - BS.length sr28 + 1) 1) sr28))
  , testCase "keymat frame roundtrips with RFC 6101 layout" $ do
      let frame = encodeSsl3KeyMatParams 16 16 16 cr28 sr28
      assertEqual "decode identity" (Just (16, 16, 16, cr28, sr28))
        (decodeSsl3KeyMatParams frame)
      assertEqual "layout order"
        [ (Ssl3MacClient, 16), (Ssl3MacServer, 16)
        , (Ssl3KeyClient, 16), (Ssl3KeyServer, 16)
        , (Ssl3IvClient, 16), (Ssl3IvServer, 16)
        ]
        (ssl3KeyMatLayout 16 16 16)
      assertEqual "zero MAC/IV elide" [(Ssl3KeyClient, 16), (Ssl3KeyServer, 16)]
        (ssl3KeyMatLayout 0 16 0)
  , testCase "keymat validation enforces keys plus ceilings" $ do
      let r = recipeNamed "CKM_SSL3_KEY_AND_MAC_DERIVE"
          good = encodeSsl3KeyMatParams 16 16 16 cr28 sr28
      assertBool "oracle shape accepts" (ssl3ParamsValid r good)
      assertBool "zero key refuses" $
        not (ssl3ParamsValid r (encodeSsl3KeyMatParams 16 0 16 cr28 sr28))
      assertBool "zero MAC/IV accept" $
        ssl3ParamsValid r (encodeSsl3KeyMatParams 0 16 0 cr28 sr28)
      assertBool "over-ceiling block refuses" $
        not (ssl3ParamsValid r
          (encodeSsl3KeyMatParams (maxSsl3KeyBlock `div` 2) 16 16 cr28 sr28))
      assertBool "191-round bound is exact" $
        ssl3ParamsValid r (encodeSsl3KeyMatParams 0 1528 0 cr28 sr28)
          && not (ssl3ParamsValid r (encodeSsl3KeyMatParams 0 1529 0 cr28 sr28))
  , testCase "MAC lengths are whole bytes in bits" $ do
      let md5 = recipeNamed "CKM_SSL3_MD5_MAC"
          sha1 = recipeNamed "CKM_SSL3_SHA1_MAC"
      assertEqual "MD5 output width" 16 (ssl3MacOutLen Ssl3Md5Mac)
      assertEqual "SHA-1 output width" 20 (ssl3MacOutLen Ssl3Sha1Mac)
      assertBool "MD5 128 bits accepts" (ssl3ParamsValid md5 (encodeMacGeneral 128))
      assertBool "MD5 8 bits accepts" (ssl3ParamsValid md5 (encodeMacGeneral 8))
      assertBool "MD5 129 bits refuses" (not (ssl3ParamsValid md5 (encodeMacGeneral 129)))
      assertBool "MD5 136 bits refuses" (not (ssl3ParamsValid md5 (encodeMacGeneral 136)))
      assertBool "MD5 zero refuses" (not (ssl3ParamsValid md5 (encodeMacGeneral 0)))
      assertBool "SHA-1 160 bits accepts" (ssl3ParamsValid sha1 (encodeMacGeneral 160))
      assertBool "SHA-1 168 bits refuses" (not (ssl3ParamsValid sha1 (encodeMacGeneral 168)))
      assertBool "short image refuses" (not (ssl3ParamsValid md5 (BS.replicate 7 0)))
  , testCase "bases are generic secrets only" $ do
      assertBool "generic secret accepts"
        (ssl3BaseKeyOk (mustKeyTypeId "CKK_GENERIC_SECRET"))
      assertBool "AES refuses"
        (not (ssl3BaseKeyOk (mustKeyTypeId "CKK_AES")))
  , testCase "ceilings pin the construction bound" $ do
      assertEqual "key-block ceiling (191 rounds)" 3056 maxSsl3KeyBlock
      assertEqual "material ceiling" 65536 maxSsl3Material
  ]
