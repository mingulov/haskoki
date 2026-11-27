{- | Driver DH dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Dh
  ( dhParamsFor
  , isDhMech
  , runDh
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Maybe (isJust)

import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , DhSpec (..)
  , EngineResult (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.Dh
  ( decodeDhParams
  , dhParamsValid
  , dhRecipeFor
  )
import Haskoki.Registry (MechanismId (..))


-- | DH agreement parameters for one covered (mechanism, params)
-- pair: the backend spec plus the peer public value. 'Nothing'
-- means uncovered (non-DH mechanism) or malformed parameters (a
-- KDF selector included — the recipe serves the null KDF only).
dhParamsFor :: MechanismId -> ByteString -> Maybe (DhSpec, ByteString)
dhParamsFor mech params = do
  r <- dhRecipeFor mech
  guard (dhParamsValid r params)
  (_, peer) <- decodeDhParams params
  pure (DhPlain, peer)

-- | A DH mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed DH params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isDhMech :: MechanismId -> Bool
isDhMech mech = isJust (dhRecipeFor mech)

-- | Classic DH agreement: the backend proves the full secret,
-- truncation drops leading bytes (PKCS#11 v3.2 DH derive
-- "removes bytes from the leading end", matching ECDH).
runDh :: CryptoBackend b => BackendEnv b -> DhSpec -> KeyMaterial -> ByteString -> Int -> IO CryptoResult
runDh env spec key peer outLen
  | outLen < 1 = pure (GotCryptoError (CryptoFailed
      "driver: derive length out of range"))
  | otherwise = do
      r <- dhDerive env spec key (KeyDer peer)
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk secret
          | BS.length secret < outLen -> GotCryptoError (CryptoFailed
              "driver: derive length exceeds the agreement secret")
          | otherwise -> GotBytes
              (BS.drop (BS.length secret - outLen) secret)
