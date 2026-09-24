{- | A1 crypto export proof: the digest one-shot path through the
real FFI exports (Haskell side of the C trampolines), asserting FIPS
KAT bytes, init conflict semantics, and size-query\/short\/recall
intent handling.
-}
{-# LANGUAGE OverloadedStrings #-}
module CryptoExportSpec (spec) where

import Control.Concurrent.MVar (MVar)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Data.Word (Word8)
import EnvLock (withEnvLock)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr)
import Foreign.Storable (peek, poke)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.FFI.Encode (nativeToWrite)
import Haskoki.FFI.Exports
  ( CryptoCtx
  , haskokiCryptoClose
  , haskokiCryptoDigest
  , haskokiCryptoDigestInit
  , haskokiCryptoOpen
  )
import Haskoki.Outcome (NativeOutput (..))
import Haskoki.Output (TypedWrite (..), WritePayload (..))
import Haskoki.Request (OutputIntent (..), OutputRegion (..))

spec :: MVar () -> TestTree
spec envLock = testGroup "Crypto exports"
  [ testCase "digest one-shot through the export, KAT bytes" (caseExportDigest envLock)
  , testCase "double init is ACTIVE; bad mech/session rejected" (caseExportInitErrors envLock)
  , testCase "size query reports length; short then recall" (caseExportIntents envLock)
  , testCase "nativeToWrite round-trips byte regions" caseNativeToWrite
  ]

hex :: String -> ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

sha256Abc :: ByteString
sha256Abc = hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

-- Pinned CK_RV values (PKCS#11 v2.40).
rvOK, rvActive, rvMech, rvSession, rvNotInit, rvShort :: CULong
rvOK = CULong 0x0
rvActive = CULong 0x90
rvMech = CULong 0x70
rvSession = CULong 0xB3
rvNotInit = CULong 0x91
rvShort = CULong 0x150

withCtx :: MVar () -> (StablePtr CryptoCtx -> IO a) -> IO a
withCtx envLock action = do
  ctx <- withEnvLock envLock haskokiCryptoOpen
  assertBool "ctx opened" (castStablePtrToPtr ctx /= nullPtr)
  r <- action ctx
  haskokiCryptoClose ctx
  pure r

-- | Call the digest export with a caller buffer of @cap@ bytes over
-- @input@; returns @(rv, reported length, output bytes)@.
callDigest
  :: StablePtr CryptoCtx -> CULong -> ByteString -> Int
  -> IO (CULong, Int, ByteString)
callDigest ctx hSession input cap =
  BS.useAsCStringLen input $ \(pIn, nIn) ->
    allocaBytes cap $ \(pOut :: Ptr Word8) ->
      alloca $ \(pLen :: Ptr CULong) -> do
        poke pLen (CULong (fromIntegral cap))
        rv <- haskokiCryptoDigest ctx hSession
          (castPtr pIn) (fromIntegral nIn) pOut pLen
        CULong got <- peek pLen
        out <- BS.packCStringLen (castPtr pOut, min (fromIntegral got) cap)
        pure (rv, fromIntegral got, out)

caseExportDigest :: MVar () -> IO ()
caseExportDigest envLock = withCtx envLock $ \ctx -> do
  rvInit <- haskokiCryptoDigestInit ctx 1 0x250 nullPtr 0
  assertEqual "init ok" rvOK rvInit
  (rv, n, out) <- callDigest ctx 1 "abc" 64
  assertEqual "digest ok" rvOK rv
  assertEqual "length" 32 n
  assertEqual "FIPS 180-4 digest of abc" sha256Abc out

caseExportInitErrors :: MVar () -> IO ()
caseExportInitErrors envLock = withCtx envLock $ \ctx -> do
  rvInit <- haskokiCryptoDigestInit ctx 1 0x250 nullPtr 0
  assertEqual "init ok" rvOK rvInit
  rvAgain <- haskokiCryptoDigestInit ctx 1 0x250 nullPtr 0
  assertEqual "second init ACTIVE" rvActive rvAgain
  rvSess <- haskokiCryptoDigestInit ctx 99 0x250 nullPtr 0
  assertEqual "bad session" rvSession rvSess
  withCtx envLock $ \fresh -> do
    rvMech' <- haskokiCryptoDigestInit fresh 1 0x999 nullPtr 0
    assertEqual "bad mechanism" rvMech rvMech'
    (rvNoInit, _, _) <- callDigest fresh 1 "abc" 64
    assertEqual "digest without init" rvNotInit rvNoInit

caseExportIntents :: MVar () -> IO ()
caseExportIntents envLock = withCtx envLock $ \ctx -> do
  -- Size query: NULL buffer reports the length and keeps the op live.
  rvInit <- haskokiCryptoDigestInit ctx 1 0x250 nullPtr 0
  assertEqual "init ok" rvOK rvInit
  BS.useAsCStringLen "abc" $ \(pIn, nIn) ->
    alloca $ \(pLen :: Ptr CULong) -> do
      poke pLen (CULong 0)
      rv <- haskokiCryptoDigest ctx 1 (castPtr pIn) (fromIntegral nIn)
        nullPtr pLen
      assertEqual "query ok" rvOK rv
      CULong got <- peek pLen
      assertEqual "query length" (32 :: Word) (fromIntegral got)
  -- The query leaves the one-shot live: a re-init is ACTIVE, and the
  -- follow-up one-shot completes.
  rvReInit <- haskokiCryptoDigestInit ctx 1 0x250 nullPtr 0
  assertEqual "re-init after query is ACTIVE" rvActive rvReInit
  (rvAfter, nAfter, outAfter) <- callDigest ctx 1 "abc" 64
  assertEqual "one-shot after query ok" rvOK rvAfter
  assertEqual "one-shot after query length" 32 nAfter
  assertEqual "one-shot after query bytes" sha256Abc outAfter
  -- Short buffer reports the length; recall with room completes.
  rvInit2 <- haskokiCryptoDigestInit ctx 1 0x250 nullPtr 0
  assertEqual "re-init after one-shot" rvOK rvInit2
  (rvShort', nShort, _) <- callDigest ctx 1 "abc" 8
  assertEqual "short" rvShort rvShort'
  assertEqual "short length" 32 nShort
  (rvRecall, nRecall, outRecall) <- callDigest ctx 1 "abc" 64
  assertEqual "recall ok" rvOK rvRecall
  assertEqual "recall length" 32 nRecall
  assertEqual "recall bytes" sha256Abc outRecall

caseNativeToWrite :: IO ()
caseNativeToWrite = do
  let region = RegionBytes "d" (IntentBuffer 9)
  assertEqual "bytes round-trip"
    (Just (TypedWrite ["d"] region (PayloadBytes "bytes")))
    (nativeToWrite (NativeOutput region "bytes"))
  assertEqual "scalar refuses" Nothing
    (nativeToWrite (NativeOutput (RegionScalar "s") "bytes"))
