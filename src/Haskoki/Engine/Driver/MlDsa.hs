{- | Driver ML-DSA dispatch.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.MlDsa
  ( mldsaSpecFor
  , isMldsaMech
  , mldsaLevelOfKey
  , mldsaRefusal
  ) where
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Maybe (fromMaybe, isJust)

import Haskoki.Engine.Backend
  ( KeyMaterial (..)
  , PqcSigAlg (..)
  , SigSpec (..)
  )
import Haskoki.Engine.Driver.Common (levelOfName)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.MlDsa
  ( MldsaHedge (..)
  , decodeMldsaParams
  , mldsaLevelOfDer
  , mldsaParamsValid
  , mldsaRecipeFor
  )
import Haskoki.Registry (MechanismId (..))


-- | ML-DSA dispatch: the covered (mechanism, params, key) triple
-- to its backend spec (pinned against 'Haskoki.Recipe.MlDsa' by
-- RecipeMlDsaSpec). The recipe validates the hedge/context
-- parameters (empty defaults to preferred, empty context); the
-- level label is a dispatch hint from the DER key
-- ('mldsaLevelOfKey'), defaulting to ML-DSA-44 when the key is
-- unscannable (the backends execute against the key's actual
-- material and refuse bad keys themselves — the driver never
-- refuses a key). Deterministic hedge clears the hedged flag;
-- external-mu mode never dispatches (out of scope). 'Nothing'
-- means uncovered (non-ML-DSA mechanism) or refused parameters.
mldsaSpecFor :: MechanismId -> ByteString -> KeyMaterial -> Maybe SigSpec
mldsaSpecFor mech params key = do
  r <- mldsaRecipeFor mech
  guard (mldsaParamsValid r params)
  (hedge, ctx) <- decodeMldsaParams params
  let alg = fromMaybe ML_DSA_44 (mldsaLevelOfKey key)
      hedged = hedge /= HedgeDeterministic
  pure (SigMLDSA alg False ctx hedged)

-- | An ML-DSA mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: refused ML-DSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isMldsaMech :: MechanismId -> Bool
isMldsaMech mech = isJust (mldsaRecipeFor mech)

-- | The ML-DSA level named by a key's algorithm OID, via the
-- recipe's 'mldsaLevelOfDer'. Both constructors sniff: production
-- resolves every stored key as 'KeyBytes' ('stdResolver'), so a
-- 'KeyDer'-only sniff would miss every production key and
-- misdispatch it as ML-DSA-44 (the shim's type-name check then
-- refuses with BADKEY). 'Nothing' for references, symmetric
-- bytes, RSA, garbage, or a foreign curve. The marker is
-- advisory for dispatch only: 'mldsaSpecFor' defaults it to
-- ML-DSA-44 and the backends always execute against the key's
-- actual material, so a miss can refuse downstream but never
-- mis-sign.
mldsaLevelOfKey :: KeyMaterial -> Maybe PqcSigAlg
mldsaLevelOfKey (KeyDer der) = mldsaLevelOfDer der >>= levelOfName
mldsaLevelOfKey (KeyBytes bs) = mldsaLevelOfDer bs >>= levelOfName
mldsaLevelOfKey _ = Nothing

-- | ML-DSA dispatch refusal: 'mldsaSpecFor' only fails on
-- refused parameters, so the refusal is unconditionally a
-- 'CryptoFailed' parameter refusal.
mldsaRefusal :: CryptoResult
mldsaRefusal = GotCryptoError (CryptoFailed "ML-DSA: params must be mldsa-params/1 (hedge 0..2, context 0..255 bytes) or empty")
