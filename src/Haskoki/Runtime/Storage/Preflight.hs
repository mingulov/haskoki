{- | Offline store preflight and explicit migration (AC-05). Read-only
diagnosis, the owned migration and their redacted renderings. Not
re-exported from "Haskoki"; the serving open does not import this module.
-}
module Haskoki.Runtime.Storage.Preflight
  ( sha256Hex
  ) where

import Control.Exception (finally)
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8)

import Haskoki.Engine.Backend (CryptoBackend (..), DigestAlg (D_SHA256), EngineResult (..))
import Haskoki.Engine.OpenSSL4 (OpenSSL4)

-- | SHA-256 of a byte string as 64 lowercase hex digits, computed by
-- the OpenSSL4 engine (never a synthetic stand-in). Any engine
-- failure is a 'Left' the caller treats as a refusal.
sha256Hex :: ByteString -> IO (Either String String)
sha256Hex bytes = do
  opened <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case opened of
    EngineFail err -> pure (Left ("SHA-256 engine unavailable: " ++ show err))
    EngineOk be -> do
      r <- digestOneShot be D_SHA256 bytes `finally` closeBackend be
      pure $ case r of
        EngineOk d | BS.length d == 32 -> Right (concatMap hexByte (BS.unpack d))
        EngineOk d -> Left ("SHA-256 returned " ++ show (BS.length d) ++ " bytes")
        EngineFail err -> Left ("SHA-256 failed: " ++ show err)
  where
    hexByte :: Word8 -> String
    hexByte w = [digit (w `shiftR` 4), digit (w .&. 15)]
    digit n = "0123456789abcdef" !! fromIntegral n
