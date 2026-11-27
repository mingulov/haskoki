{- | Driver GMAC dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Gmac
  ( gmacSpecFor
  , isGmacMech
  , runGmacSign
  , runGmacVerify
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Maybe (isJust)

import Haskoki.Engine.Backend
  ( AeadSpec (..)
  , BackendEnv
  , CryptoBackend (..)
  , EngineResult (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver.Common (driverCtEq)
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.Gcm (decodeGcmParams)
import Haskoki.Recipe.Gmac (gmacParamsValid, gmacRecipeFor)
import Haskoki.Registry (MechanismId (..))


-- | GMAC dispatch: covered (mechanism, params, key length) triples
-- map to the backend AES-GCM spec plus the IV. The tag width is
-- fixed at 16 (GMAC has no truncation variant); the key binds by
-- length (AES-128\/192\/256). 'Nothing' means uncovered
-- (non-GMAC mechanism), malformed parameters, or an off-geometry
-- key length.
gmacSpecFor :: MechanismId -> ByteString -> Int -> Maybe (AeadSpec, ByteString)
gmacSpecFor mech params keyLen = do
  r <- gmacRecipeFor mech
  guard (gmacParamsValid r params)
  (iv, _, tagLen) <- decodeGcmParams params
  alg <- case keyLen of
    16 -> Just "AES-128-GCM"
    24 -> Just "AES-192-GCM"
    32 -> Just "AES-256-GCM"
    _ -> Nothing
  pure (AeadSpec alg (BS.length iv) tagLen, iv)

-- | A GMAC mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed GMAC params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isGmacMech :: MechanismId -> Bool
isGmacMech mech = isJust (gmacRecipeFor mech)

-- | GMAC sign effects: the message travels as GCM AAD with
-- empty plaintext over the backend AES-GCM route; the tag is
-- the GCM authentication tag. Off-geometry (mechanism, key
-- length, params) triples are 'CryptoFailed'; a non-bytes key
-- is 'CryptoBadKey'.
runGmacSign :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> IO CryptoResult
runGmacSign env mech params key input = case key of
  KeyBytes kb -> case gmacSpecFor mech params (BS.length kb) of
    Just (spec, iv) -> do
      r <- aeadEncrypt env spec key iv input BS.empty
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk (_, tag) -> GotBytes tag
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: GMAC (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "GMAC needs raw symmetric key bytes"))

-- | GMAC verify effects: recompute over the GCM route,
-- constant-time compare. A mismatch is the 'False' verdict,
-- never a malfunction.
runGmacVerify :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runGmacVerify env mech params key input tag = case key of
  KeyBytes kb -> case gmacSpecFor mech params (BS.length kb) of
    Just (spec, iv) -> do
      r <- aeadEncrypt env spec key iv input BS.empty
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk (_, want)
          | driverCtEq want tag -> GotValid True
          | otherwise -> GotValid False
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: GMAC (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "GMAC needs raw symmetric key bytes"))
