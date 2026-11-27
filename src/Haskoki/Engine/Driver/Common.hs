{- | Driver-wide shared workers: key resolution, the refusal
shapes every family renders, raw-bytes extraction, the recipe
digest and PQC level stems, pub-from-priv extraction, and the
byte utilities shared across families (xor and the constant-time
compare reach PBE, TLS, SSL3 and ByteOps; the block helpers are
shared by the MAC families).

Below all 'Haskoki.Engine.Driver.*' family modules: families import
this (and 'Haskoki.Engine.Driver.Result'); nothing here imports a
family. 'Haskoki.Engine.Driver' re-exports 'KeyResolver' so existing
imports keep working.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Common
  ( KeyResolver
  , withKey
  , unsupported
  , keyBytesOf
  , compSpec
  , runPubFromPriv
  , rsaDigest
  , levelOfName

  , xorB
  , padBlock
  , chunksOf
  , zeroPad
  , driverCtEq
  ) where

import Data.Bits ((.|.), xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (unsnoc)
import qualified Data.Text as T

import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , DigestAlg (..)
  , EcdhSpec (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , PqcSigAlg (..)
  )
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoEffect, CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.WrapComp (WrapCompEcdhRecipe, wceCofactor)
import Haskoki.Types (ObjectId)

-- | Recipe digest stem onto the backend digest.
rsaDigest :: T.Text -> Maybe DigestAlg
rsaDigest stem
  | stem == "BLAKE2B_512" = Just D_BLAKE2B512
  | stem == "BLAKE2B_160" = Just D_BLAKE2B160
  | stem == "BLAKE2B_256" = Just D_BLAKE2B256
  | stem == "BLAKE2B_384" = Just D_BLAKE2B384
  | stem == "MD5" = Just D_MD5
  | stem == "RIPEMD160" = Just D_RIPEMD160
  | stem == "SHA_1" = Just D_SHA1
  | stem == "SHA224" = Just D_SHA224
  | stem == "SHA256" = Just D_SHA256
  | stem == "SHA384" = Just D_SHA384
  | stem == "SHA512" = Just D_SHA512
  | stem == "SHA512_224" = Just D_SHA512_224
  | stem == "SHA512_256" = Just D_SHA512_256
  | stem == "SHA3_224" = Just D_SHA3_224
  | stem == "SHA3_256" = Just D_SHA3_256
  | stem == "SHA3_384" = Just D_SHA3_384
  | stem == "SHA3_512" = Just D_SHA3_512
  | otherwise = Nothing

-- | Engine level names onto backend algorithms.
levelOfName :: T.Text -> Maybe PqcSigAlg
levelOfName name = case T.unpack name of
  "ML-DSA-44" -> Just ML_DSA_44
  "ML-DSA-65" -> Just ML_DSA_65
  "ML-DSA-87" -> Just ML_DSA_87
  "SLH-DSA-SHA2-128s" -> Just SLH_DSA_SHA2_128s
  "SLH-DSA-SHA2-128f" -> Just SLH_DSA_SHA2_128f
  "SLH-DSA-SHA2-192s" -> Just SLH_DSA_SHA2_192s
  "SLH-DSA-SHA2-192f" -> Just SLH_DSA_SHA2_192f
  "SLH-DSA-SHA2-256s" -> Just SLH_DSA_SHA2_256s
  "SLH-DSA-SHA2-256f" -> Just SLH_DSA_SHA2_256f
  "SLH-DSA-SHAKE-128s" -> Just SLH_DSA_SHAKE_128s
  "SLH-DSA-SHAKE-128f" -> Just SLH_DSA_SHAKE_128f
  "SLH-DSA-SHAKE-192s" -> Just SLH_DSA_SHAKE_192s
  "SLH-DSA-SHAKE-192f" -> Just SLH_DSA_SHAKE_192f
  "SLH-DSA-SHAKE-256s" -> Just SLH_DSA_SHAKE_256s
  "SLH-DSA-SHAKE-256f" -> Just SLH_DSA_SHAKE_256f
  _ -> Nothing

-- | Resolve a bound key object to backend key material. 'Nothing'
-- means the object is unknown to the caller (reported as
-- 'CryptoBadKey', never fabricated).
type KeyResolver = ObjectId -> Maybe KeyMaterial

withKey :: KeyResolver -> Maybe ObjectId -> (KeyMaterial -> IO CryptoResult) -> IO CryptoResult
withKey _ Nothing _ = pure (GotCryptoError (CryptoBadKey "driver" "effect binds no key"))
withKey resolve (Just oid) k = case resolve oid of
  Nothing -> pure (GotCryptoError (CryptoBadKey "driver" ("unknown key object: " ++ show oid)))
  Just mat -> k mat

-- | The agreement spec for a composition row: cofactor from
-- the row (COF over EC only; X over Montgomery is plain).
compSpec :: WrapCompEcdhRecipe -> EcdhSpec
compSpec r = if wceCofactor r then EcdhCofactor else EcdhPlain

-- | Raw bytes out of key material (DER halves and byte seeds;
-- backend references carry no bytes here).
keyBytesOf :: KeyMaterial -> Maybe ByteString
keyBytesOf (KeyBytes b) = Just b
keyBytesOf (KeyDer b) = Just b
keyBytesOf _ = Nothing

-- | Pub-from-priv extraction: the backend answers the DER
-- SPKI for the base half (any material shape the backend
-- resolves); the finisher parses and stamps per key type.
runPubFromPriv :: CryptoBackend b => BackendEnv b -> KeyMaterial -> IO CryptoResult
runPubFromPriv env key = do
  r <- pubFromPriv env key
  pure $ case r of
    EngineFail err -> GotCryptoError (toCryptoError err)
    EngineOk spki -> GotBytes spki

unsupported :: CryptoEffect -> CryptoResult
unsupported e = GotCryptoError (CryptoUnsupported "driver" (show e))

-- | Byte-wise xor (block pairs by construction).
xorB :: ByteString -> ByteString -> ByteString
xorB a b = BS.pack (BS.zipWith xor a b)

-- | CMAC 10* padding of a short last block.
padBlock :: Int -> ByteString -> ByteString
padBlock blk lastB =
  lastB <> BS.singleton 0x80 <> BS.replicate (blk - BS.length lastB - 1) 0

-- | Split into full-or-final blocks.
chunksOf :: Int -> ByteString -> [ByteString]
chunksOf n bs
  | BS.null bs = []
  | otherwise = let (h, t) = BS.splitAt n bs in h : chunksOf n t

-- | Split into zero-padded full blocks (empty input yields one
-- zero block, so CBC-MAC over empty input is well-defined).
zeroPad :: Int -> ByteString -> [ByteString]
zeroPad n bs = case chunksOf n bs of
  [] -> [BS.replicate n 0]
  blks -> case unsnoc blks of
    Just (pre, lst)
      | BS.length lst == n -> blks
      | otherwise -> pre ++ [lst <> BS.replicate (n - BS.length lst) 0]
    Nothing -> [BS.replicate n 0]

-- | Constant-time byte equality for driver-level MAC verification
-- (mirrors the backend-local compares).
driverCtEq :: ByteString -> ByteString -> Bool
driverCtEq a b =
  BS.length a == BS.length b
    && foldl' (\acc (x, y) -> acc .|. (x `xor` y)) 0 (BS.zip a b) == 0
