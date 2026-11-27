{- | Driver ECDH dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Ecdh
  ( ecdhParamsFor
  , isEcdhMech
  , runEcdh
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Maybe (isJust)

import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , EcdhSpec (..)
  , EngineResult (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.Ecdh
  ( EcdhRecipe (..)
  , decodeEcdhParams
  , ecdhParamsValid
  , ecdhRecipeFor
  )
import Haskoki.Registry (MechanismId (..))


-- | ECDH dispatch: the covered (mechanism, params) pair to the
-- backend agreement shape plus the peer public key (pinned
-- against 'Haskoki.Recipe.Ecdh' by RecipeEcdhSpec). The cofactor
-- flag comes from the mechanism row. 'Nothing' means uncovered
-- (non-ECDH mechanism) or malformed parameters (a KDF selector
-- included — the recipe serves the null KDF only).
ecdhParamsFor :: MechanismId -> ByteString -> Maybe (EcdhSpec, ByteString)
ecdhParamsFor mech params = do
  r <- ecdhRecipeFor mech
  guard (ecdhParamsValid r params)
  (_, _, peer) <- decodeEcdhParams params
  pure (if rhCofactor r then EcdhCofactor else EcdhPlain, peer)

-- | An ECDH mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed ECDH params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isEcdhMech :: MechanismId -> Bool
isEcdhMech mech = isJust (ecdhRecipeFor mech)

-- | ECDH agreement effects: the backend agrees the full raw
-- secret over (base key, peer public key) and the driver
-- truncates to the planned length. A planned length past the
-- secret is 'CryptoFailed' (the planner caps honestly, so this
-- fires only for hand-built effects); backend key-shape
-- refusals keep their taxonomy.
runEcdh :: CryptoBackend b => BackendEnv b -> EcdhSpec -> KeyMaterial -> ByteString -> Int -> IO CryptoResult
runEcdh env spec key peer outLen
  | outLen < 1 = pure (GotCryptoError (CryptoFailed
      "driver: derive length out of range"))
  | otherwise = do
      r <- ecdhDerive env spec key (KeyDer peer)
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk secret
          | BS.length secret < outLen -> GotCryptoError (CryptoFailed
              "driver: derive length exceeds the agreement secret")
          -- Truncation drops leading bytes (PKCS#11 v3.2 ECDH:
          -- "removes bytes from the leading end"); full width
          -- drops nothing.
          | otherwise -> GotBytes
              (BS.drop (BS.length secret - outLen) secret)
