{- | Snapshot engine saveability tests.

Each backend declares per-resource saveability,
native contexts that cannot be saved answer an explicit TYPED
unsaveable (never a silent drop, never a crash), and snapshot bytes
carry no resource-id encoding.
-}
{-# LANGUAGE OverloadedStrings #-}
module SnapshotEngineSpec (spec) where

import qualified Data.ByteString as BS
import Data.Bits (shiftR)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , DigestAlg (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , KeyRef (..)
  , ResourceSaveability (..)
  , UnsaveableReason (..)
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.Engine.Synthetic (Synthetic (..))
import Haskoki.Types (EngineResourceId (..))

spec :: TestTree
spec = testGroup "snapshot engine saveability"
  [ testCase "synthetic digest declares saveable; restore finalizes equal"
      caseSynthSaveable
  , testCase "synthetic unknown resource is typed unsaveable-gone"
      caseSynthGone
  , testCase "synthetic snapshot bytes carry no resource-id encoding"
      caseNoRidBytes
  , testCase "synthetic key declares saveable" caseSynthKeySaveable
  , testCase "openssl4 digest is typed unsaveable-native, never silent"
      caseOssl4Native
  , testCase "openssl4 unknown resource is typed unsaveable-gone"
      caseOssl4Gone
  ]

withSynth :: String -> (BackendEnv Synthetic -> IO ()) -> IO ()
withSynth seed action = do
  r <- openBackend seed :: IO (EngineResult (BackendEnv Synthetic))
  case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk env -> action env >> closeBackend env

withOSSL :: (BackendEnv OpenSSL4 -> IO ()) -> IO ()
withOSSL action = do
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk env -> action env >> closeBackend env

expectOk :: Show a => String -> EngineResult a -> IO a
expectOk label r = case r of
  EngineOk a -> pure a
  EngineFail err -> assertFailure (label ++ ": expected EngineOk, got " ++ show err)

word32BE :: Int -> BS.ByteString
word32BE n = BS.pack
  [ fromIntegral (n `shiftR` 24)
  , fromIntegral (n `shiftR` 16)
  , fromIntegral (n `shiftR` 8)
  , fromIntegral n
  ]

word64BE :: Int -> BS.ByteString
word64BE n = BS.pack
  [ fromIntegral (n `shiftR` 56)
  , fromIntegral (n `shiftR` 48)
  , fromIntegral (n `shiftR` 40)
  , fromIntegral (n `shiftR` 32)
  , fromIntegral (n `shiftR` 24)
  , fromIntegral (n `shiftR` 16)
  , fromIntegral (n `shiftR` 8)
  , fromIntegral n
  ]

caseSynthSaveable :: IO ()
caseSynthSaveable = withSynth "21" $ \env -> do
  rid <- expectOk "digestInit" =<< digestInit env D_SHA256
  decl <- resourceSaveability env rid
  assertEqual "digest declares saveable" ResourceSaveable decl
  expectOk "update(a)" =<< digestUpdate env rid "a"
  snap <- snapshotResource env rid
  ctx <- case snap of
    Left err -> assertFailure ("snapshot failed: " ++ err) >> undefined
    Right b -> pure b
  rid2 <- expectOk "restore" =<< restoreResource env ctx
  assertBool "restore mints a fresh handle" (rid2 /= rid)
  expectOk "update(bc)" =<< digestUpdate env rid2 "bc"
  d <- expectOk "digestFinal" =<< digestFinal env rid2
  one <- expectOk "one-shot abc" =<< digestOneShot env D_SHA256 "abc"
  assertEqual "restored stream == one-shot" one d

caseSynthGone :: IO ()
caseSynthGone = withSynth "21" $ \env -> do
  let ghost = EngineResourceId 999
  decl <- resourceSaveability env ghost
  assertEqual "unknown declares typed gone"
    (ResourceUnsaveable (UnsaveableGone ghost)) decl

caseNoRidBytes :: IO ()
caseNoRidBytes = withSynth "21" $ \env -> do
  rid <- expectOk "digestInit" =<< digestInit env D_SHA256
  let n = fromIntegral (unEngineResourceId rid) :: Int
  -- Controlled accumulation: no zero bytes, length distinct from the id,
  -- so any resource-id encoding would stand out instead of colliding.
  expectOk "update" =<< digestUpdate env rid "abcdefgh"
  snap <- snapshotResource env rid
  ctx <- case snap of
    Left err -> assertFailure ("snapshot failed: " ++ err) >> undefined
    Right b -> pure b
  -- Structural proof: the context is exactly version + alg + length +
  -- accumulation — no field where an id could hide.
  assertEqual "digest context layout"
    (BS.singleton 0x02 <> BS.singleton 0x01 <> word32BE 8 <> "abcdefgh") ctx
  assertBool "no BE32 resource id" (not (word32BE n `BS.isInfixOf` ctx))
  assertBool "no BE64 resource id" (not (word64BE n `BS.isInfixOf` ctx))
  -- Key contexts likewise: version + kind + length + material, exactly.
  let mat = "keymaterial-32-bytes-long!!!!!!"
  pref <- expectOk "import key" =<< importKey env (KeyBytes mat)
  ksnap <- snapshotResource env (keyRefId pref)
  kctx <- case ksnap of
    Left err -> assertFailure ("key snapshot failed: " ++ err) >> undefined
    Right b -> pure b
  assertEqual "key context layout"
    (BS.singleton 0x01 <> BS.singleton 0x01 <> word32BE (BS.length mat)
      <> mat) kctx
  let kn = fromIntegral (unEngineResourceId (keyRefId pref)) :: Int
  assertBool "no BE32 key id" (not (word32BE kn `BS.isInfixOf` kctx))
  assertBool "no BE64 key id" (not (word64BE kn `BS.isInfixOf` kctx))

caseSynthKeySaveable :: IO ()
caseSynthKeySaveable = withSynth "21" $ \env -> do
  pref <- expectOk "import key" =<< importKey env (KeyBytes "keymaterial-32-bytes-long!!!!!!")
  decl <- resourceSaveability env (keyRefId pref)
  assertEqual "key declares saveable" ResourceSaveable decl

caseOssl4Native :: IO ()
caseOssl4Native = withOSSL $ \env -> do
  rid <- expectOk "digestInit" =<< digestInit env D_SHA256
  decl <- resourceSaveability env rid
  assertEqual "native context is typed unsaveable"
    (ResourceUnsaveable (UnsaveableNative
      "OpenSSL4 multipart contexts cannot be serialized")) decl
  -- The legacy stringly path agrees (and stays honest, never silent).
  snap <- snapshotResource env rid
  case snap of
    Left err -> assertBool "unsaveable prefix" ("unsaveable:" `isPrefixOf` err)
    Right _ -> assertFailure "native snapshot unexpectedly succeeded"
  releaseResource env rid
  where
    isPrefixOf pre s = take (length pre) s == pre

caseOssl4Gone :: IO ()
caseOssl4Gone = withOSSL $ \env -> do
  let ghost = EngineResourceId 999
  decl <- resourceSaveability env ghost
  assertEqual "unknown declares typed gone"
    (ResourceUnsaveable (UnsaveableGone ghost)) decl
