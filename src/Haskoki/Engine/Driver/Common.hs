{- | Driver-wide shared workers: key resolution, the refusal
shapes every family renders, raw-bytes extraction, the recipe
digest and PQC level stems, and pub-from-priv extraction.

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
  ) where

import Data.ByteString (ByteString)
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
