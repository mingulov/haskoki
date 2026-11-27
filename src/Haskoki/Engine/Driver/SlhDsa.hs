{- | Driver SLH-DSA dispatch.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.SlhDsa
  ( slhdsaSpecFor
  , isSlhdsaMech
  , slhdsaLevelOfKey
  , slhdsaRefusal
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
import Haskoki.Recipe.SlhDsa
  ( SlhdsaHedge (..)
  , decodeSlhdsaParams
  , slhdsaLevelOfDer
  , slhdsaParamsValid
  , slhdsaRecipeFor
  )
import Haskoki.Registry (MechanismId (..))


-- | SLH-DSA dispatch: the covered (mechanism, params, key) triple
-- to its backend spec (pinned against 'Haskoki.Recipe.SlhDsa' by
-- RecipeSlhDsaSpec). The recipe validates the hedge/context
-- parameters (empty defaults to preferred, empty context); the
-- set label is a dispatch hint from the DER key
-- ('slhdsaLevelOfKey'), defaulting to SLH-DSA-SHA2-128s when the
-- key is unscannable (the backends execute against the key's
-- actual material and refuse bad keys themselves — the driver
-- never refuses a key). Deterministic hedge clears the hedged
-- flag. 'Nothing' means uncovered (non-SLH-DSA mechanism) or
-- refused parameters.
slhdsaSpecFor :: MechanismId -> ByteString -> KeyMaterial -> Maybe SigSpec
slhdsaSpecFor mech params key = do
  r <- slhdsaRecipeFor mech
  guard (slhdsaParamsValid r params)
  (hedge, ctx) <- decodeSlhdsaParams params
  let alg = fromMaybe SLH_DSA_SHA2_128s (slhdsaLevelOfKey key)
      hedged = hedge /= SlhDeterministic
  pure (SigSLHDSA alg ctx hedged)

-- | An SLH-DSA mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: refused SLH-DSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isSlhdsaMech :: MechanismId -> Bool
isSlhdsaMech mech = isJust (slhdsaRecipeFor mech)

-- | The SLH-DSA set named by a key's algorithm OID, via the
-- recipe's 'slhdsaLevelOfDer'. Both constructors sniff: production
-- resolves every stored key as 'KeyBytes' ('stdResolver'), so a
-- 'KeyDer'-only sniff would miss every production key and
-- misdispatch it as SLH-DSA-SHA2-128s (the shim's type-name check
-- then refuses with BADKEY). 'Nothing' for references, symmetric
-- bytes, RSA, garbage, or a foreign curve. The marker is
-- advisory for dispatch only: 'slhdsaSpecFor' defaults it to
-- SLH-DSA-SHA2-128s and the backends always execute against the
-- key's actual material, so a miss can refuse downstream but never
-- mis-sign.
slhdsaLevelOfKey :: KeyMaterial -> Maybe PqcSigAlg
slhdsaLevelOfKey (KeyDer der) = slhdsaLevelOfDer der >>= levelOfName
slhdsaLevelOfKey (KeyBytes bs) = slhdsaLevelOfDer bs >>= levelOfName
slhdsaLevelOfKey _ = Nothing

slhdsaRefusal :: CryptoResult
slhdsaRefusal = GotCryptoError (CryptoFailed "SLH-DSA: params must be slhdsa-params/1 (hedge 0..2, context 0..255 bytes) or empty")
