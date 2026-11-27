{- | Driver ECDSA dispatch.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Ecdsa
  ( ecdsaSpecFor
  , isEcdsaMech
  , ecCurveOfKey
  , ecdsaRefusal
  ) where
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Text as T

import Haskoki.Engine.Backend
  ( EcSpec (..)
  , KeyMaterial (..)
  , SigSpec (..)
  )
import Haskoki.Engine.Driver.Common (rsaDigest)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.Ecdsa
  ( EcdsaRecipe (..)
  , ecdsaCurveOfDer
  , ecdsaEncodingOf
  , ecdsaParamsValid
  , ecdsaRecipeFor
  )
import Haskoki.Registry (MechanismId (..))


-- | ECDSA dispatch: covered (mechanism, params, key) triples to
-- backend specs (pinned against
-- 'Haskoki.Recipe.Ecdsa' by RecipeEcdsaSpec). The recipe binds the
-- digest and validates the encoding selection; the curve label is
-- a dispatch hint from the DER key ('ecCurveOfKey'), defaulting to
-- P-256 when the key is unscannable (the backends execute against
-- the key's actual material and refuse bad keys themselves — the
-- driver never refuses a key). 'Nothing' means uncovered
-- (non-ECDSA mechanism) or malformed parameters.
ecdsaSpecFor :: MechanismId -> ByteString -> KeyMaterial -> Maybe SigSpec
ecdsaSpecFor mech params key = do
  r <- ecdsaRecipeFor mech
  guard (ecdsaParamsValid r params)
  enc <- ecdsaEncodingOf params
  alg <- case reDigestStem r of
    Nothing -> pure Nothing
    Just stem -> Just <$> rsaDigest stem
  let curve = fromMaybe "P-256" (ecCurveOfKey key)
  pure (SigECDSA (EcSpec (T.unpack curve) (T.unpack enc)) alg)

-- | An ECDSA mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed ECDSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isEcdsaMech :: MechanismId -> Bool
isEcdsaMech mech = isJust (ecdsaRecipeFor mech)

-- | The curve named by a DER key's curve OID, via the recipe's
-- 'ecdsaCurveOfDer' ('Nothing' for raw bytes, references, RSA,
-- garbage, or an off-set curve). The marker is advisory for
-- dispatch only: 'ecdsaSpecFor' defaults it to P-256 and the
-- backends always execute against the key's actual material, so a
-- miss can refuse downstream but never mis-sign.
ecCurveOfKey :: KeyMaterial -> Maybe T.Text
ecCurveOfKey (KeyDer der) = ecdsaCurveOfDer der
ecCurveOfKey _ = Nothing

-- | ECDSA dispatch refusal: 'ecdsaSpecFor' only fails on
-- malformed parameters (same message as the OpenSSL driver), so the
-- refusal is unconditionally a 'CryptoFailed' parameter refusal.
ecdsaRefusal :: CryptoResult
ecdsaRefusal = GotCryptoError (CryptoFailed "ECDSA: params must be RAW, DER, or empty")
