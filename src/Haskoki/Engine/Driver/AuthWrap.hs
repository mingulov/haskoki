{- | Driver authenticated wrap/unwrap (cipher + HMAC composition).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.AuthWrap
  ( runAuthWrap
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , MacSpec (..)
  )
import Haskoki.Engine.Driver.Cipher (cipherSpecFor)
import Haskoki.Engine.Driver.Result (toBytes, toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Registry (MechanismId (..))


runAuthWrap :: CryptoBackend b => BackendEnv b -> Bool -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> ByteString -> IO CryptoResult
runAuthWrap env isWrap mech key iv aad input = case key of
  KeyBytes kb -> case cipherSpecFor mech (BS.length kb) iv of
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: auth-wrap (mechanism, key length, params) rejected by the recipe"))
    Just spec -> do
      macKeyR <- macSign env hmacSpec key authWrapDomain
      case macKeyR of
        EngineFail err -> pure (GotCryptoError (toCryptoError err))
        EngineOk macKey -> run (KeyBytes macKey) spec
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "auth-wrap needs raw symmetric key bytes"))
  where
    run macKey spec
      | isWrap = wrapWith macKey spec
      | badUnwrapLen = pure (GotCryptoError
          (CryptoFailed "driver: authenticated blob length"))
      | otherwise = unwrapWith macKey spec
    badUnwrapLen = BS.length input < 32
      || (BS.length input - 32) `mod` 16 /= 0
    wrapWith macKey spec = do
      ctR <- cipherEncrypt env spec key iv input
      case ctR of
        EngineFail err -> pure (GotCryptoError (toCryptoError err))
        EngineOk ct -> do
          tagR <- macSign env hmacSpec macKey (aad <> ct)
          pure $ case tagR of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk tag -> GotBytes (ct <> tag)
    unwrapWith macKey spec = do
      let (ct, tag) = BS.splitAt (BS.length input - 32) input
      verR <- macVerify env hmacSpec macKey (aad <> ct) tag
      case verR of
        EngineFail (BackendAuthFailed _) ->
          pure (GotCryptoError (CryptoAuthFailed "auth-unwrap"))
        EngineFail err -> pure (GotCryptoError (toCryptoError err))
        EngineOk False ->
          pure (GotCryptoError (CryptoAuthFailed "auth-unwrap"))
        EngineOk True -> toBytes <$> cipherDecrypt env spec key iv ct

-- | The fixed HMAC-SHA-256 spec behind derivation and
-- authenticated wrapping.
hmacSpec :: MacSpec
hmacSpec = MacHMAC D_SHA256 Nothing

-- | Domain separation between the wrapping key's cipher use and its
-- tag use: the tag key is @HMAC(wrapKey, domain)@, never the raw
-- wrapping key.
authWrapDomain :: ByteString
authWrapDomain = "HASKOKI-AUTHWRAP-MAC-V1"
