{- | AES-CCM AEAD recipe tests.

The single-row CCM group: caller-supplied nonce (7..13 bytes per
NIST SP 800-38C), even tag widths 4..16 bytes, AAD bound at seal
('ccm-params/1': tag length, nonce length, nonce, AAD).
'Haskoki.Recipe.Ccm' owns the canonical codec and parameter
validation; these tests pin the recipe and (later tasks) its two
consumers: the model init path and the driver AEAD arm.
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeCcmSpec (spec) where

import qualified Data.ByteString as BS
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertFailure, testCase)

import Haskoki.Recipe.Ccm
  ( CcmRecipe (..)
  , ccmParamsValid
  , ccmRecipes
  , decodeCcmParams
  , encodeCcmParams
  )

ccmRow :: CcmRecipe
ccmRow = case ccmRecipes of
  (r : _) -> r
  [] -> CcmRecipe "CKM_AES_CCM"

spec :: TestTree
spec = testGroup "RecipeCcm"
  [ testCase "ccm-params roundtrip" $ do
      let nonce = BS.replicate 12 0x01
          aad = BS.pack [0x02, 0x03]
          img = encodeCcmParams nonce aad 16
      case decodeCcmParams img of
        Nothing -> assertFailure "valid image refused"
        Just (n, a, t) -> do
          assertBool "nonce" (n == nonce)
          assertBool "aad" (a == aad)
          assertBool "taglen" (t == 16)
  , testCase "ccm-params rejects bad nonce/tag widths" $ do
      assertBool "6-byte nonce refuses"
        (not (ccmParamsValid ccmRow (encodeCcmParams (BS.replicate 6 0) BS.empty 16)))
      assertBool "14-byte nonce refuses"
        (not (ccmParamsValid ccmRow (encodeCcmParams (BS.replicate 14 0) BS.empty 16)))
      assertBool "5-byte tag refuses"
        (not (ccmParamsValid ccmRow (encodeCcmParams (BS.replicate 12 0) BS.empty 5)))
  ]
