{- | Driver PBE/PBKDF1 keygen execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Pbe
  ( runPbe
  , runPbkdf1
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word64, Word8)

import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , DigestAlg (..)
  , EngineResult (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver.KeyGen (toKeyPair)
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoResult (..))
import Haskoki.Operation.KeyManagement (encodeKeyPair)
import Haskoki.Recipe.Pbe (pbeDesParity)


-- | PBE keygen effects: the §6.38 PKCS#12 construction over
-- SHA-1 (u = 20, v = 64): ID 1 derives the key
-- (parity-adjusted for the DES rows only), ID 2 the IV.
-- Digests run through the provider; the B-feedback
-- addition is pure byte arithmetic. IV rows answer the
-- framed key\/IV pair; no-IV rows (RC4) answer the lone
-- key.
runPbe :: CryptoBackend b => BackendEnv b -> Word64 -> ByteString -> ByteString -> Int -> Bool -> Int -> IO CryptoResult
runPbe env iters pw salt keyLen parity ivLen = do
  rK <- pbeDChain 1 keyLen
  if ivLen > 0
    then do
      rV <- pbeDChain 2 ivLen
      pure $ case (rK, rV) of
        (EngineOk k, EngineOk v) ->
          GotBytes (encodeKeyPair (finish k) (Just v))
        (EngineFail err, _) -> GotCryptoError (toCryptoError err)
        (_, EngineFail err) -> GotCryptoError (toCryptoError err)
    else pure $ case rK of
      EngineOk k -> toKeyPair (EngineOk (KeyBytes (finish k), Nothing))
      EngineFail err -> GotCryptoError (toCryptoError err)
  where
    finish = if parity then pbeDesParity else id
    pbeDChain :: Word8 -> Int -> IO (EngineResult ByteString)
    pbeDChain ident n = loop n (expand salt <> expand pw) []
      where
        d = BS.replicate 64 ident
        expand s
          | BS.null s = BS.empty
          | otherwise =
              let target = 64 * ((BS.length s + 63) `div` 64)
                  copies = target `div` BS.length s + 1
              in BS.take target (BS.concat (replicate copies s))
        loop remaining i acc
          | remaining <= 0 =
              pure (EngineOk (BS.take n (BS.concat (reverse acc))))
          | otherwise = do
              r <- hashTimes (fromIntegral iters) (d <> i)
              case r of
                EngineFail err -> pure (EngineFail err)
                EngineOk a -> loop (remaining - 20) (feedback a i) (a : acc)
        feedback a i = BS.concat (map (addBlock bInt) (chunks i))
          where
            b = BS.take 64 (BS.concat (replicate 4 a))
            bInt = beInt b
            chunks x
              | BS.null x = []
              | otherwise = let (h, t) = BS.splitAt 64 x in h : chunks t
            addBlock bi blk =
              beBytes 64 ((beInt blk + bi + 1) `mod` (2 ^ (512 :: Int)))
        hashTimes :: Int -> ByteString -> IO (EngineResult ByteString)
        hashTimes 0 msg = pure (EngineOk msg)
        hashTimes k msg = do
          r <- digestOneShot env D_SHA1 msg
          case r of
            EngineFail err -> pure (EngineFail err)
            EngineOk dig -> hashTimes (k - 1) dig
        beInt :: ByteString -> Integer
        beInt = BS.foldl' (\a w -> a * 256 + fromIntegral w) 0
        beBytes :: Int -> Integer -> ByteString
        beBytes len v =
          BS.pack [fromIntegral ((v `div` (256 ^ i)) `mod` 256)
                  | i <- [len - 1, len - 2 .. 0]]

-- | MD5 D-chain: @D1 = MD5^c(P||S)@ (the provider-PBKDF1
-- root, byte-exact), @D{i+1} = MD5^c(Di||P||S)@ past the
-- 16-byte PBKDF1 cap; key = stream[0:keyLen], IV =
-- stream[keyLen:keyLen+8]. Digests run through the
-- provider. The answer frames the key\/IV pair.
runPbkdf1 :: CryptoBackend b => BackendEnv b -> Word64 -> ByteString -> ByteString -> Int -> Bool -> IO CryptoResult
runPbkdf1 env iters pw salt keyLen parity = do
  r <- chain (keyLen + 8) BS.empty []
  pure $ case r of
    EngineFail err -> GotCryptoError (toCryptoError err)
    EngineOk stream ->
      let (k, v) = BS.splitAt keyLen (BS.take (keyLen + 8) stream)
      in GotBytes (encodeKeyPair (finish k) (Just v))
  where
    finish = if parity then pbeDesParity else id
    chain :: Int -> ByteString -> [ByteString] -> IO (EngineResult ByteString)
    chain remaining prev acc
      | remaining <= 0 = pure (EngineOk (BS.concat (reverse acc)))
      | otherwise = do
          r <- hashTimes (fromIntegral iters) (prev <> pw <> salt)
          case r of
            EngineFail err -> pure (EngineFail err)
            EngineOk d -> chain (remaining - 16) d (d : acc)
    hashTimes :: Int -> ByteString -> IO (EngineResult ByteString)
    hashTimes 0 msg = pure (EngineOk msg)
    hashTimes k msg = do
      r <- digestOneShot env D_MD5 msg
      case r of
        EngineFail err -> pure (EngineFail err)
        EngineOk d -> hashTimes (k - 1) d
