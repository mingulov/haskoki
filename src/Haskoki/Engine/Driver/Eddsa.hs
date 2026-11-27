{- | Driver EdDSA dispatch.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Eddsa
  ( eddsaSpecFor
  , isEddsaMech
  , eddsaCurveOfKey
  , eddsaRefusal
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Text as T

import Haskoki.Engine.Backend
  ( EcSpec (..)
  , KeyMaterial (..)
  , SigSpec (..)
  )
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.Eddsa
  ( eddsaCurveOfDer
  , eddsaParamsValid
  , eddsaRecipeFor
  )
import Haskoki.Registry (MechanismId (..))


-- | EdDSA dispatch: the covered (mechanism, params, key) triple
-- to its backend spec (pinned against 'Haskoki.Recipe.Eddsa' by
-- RecipeEddsaSpec). The recipe validates pure parameters; the
-- curve label is a dispatch hint from the DER key
-- ('eddsaCurveOfKey'), defaulting to Ed25519 when the key is
-- unscannable (the backends execute against the key's actual
-- material and refuse bad keys themselves — the driver never
-- refuses a key). 'Nothing' means uncovered (non-EdDSA mechanism)
-- or non-pure parameters (missing parameters decode to pure).
eddsaSpecFor :: MechanismId -> ByteString -> KeyMaterial -> Maybe SigSpec
eddsaSpecFor mech params key = do
  r <- eddsaRecipeFor mech
  guard (eddsaParamsValid r params)
  let curve = fromMaybe "Ed25519" (eddsaCurveOfKey key)
  pure (SigEdDSA (EcSpec (T.unpack curve) "RAW") BS.empty)

-- | An EdDSA mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: non-pure EdDSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isEddsaMech :: MechanismId -> Bool
isEddsaMech mech = isJust (eddsaRecipeFor mech)

-- | The Edwards curve named by a key's curve OID, via the
-- recipe's 'eddsaCurveOfDer'. Both constructors sniff: production
-- resolves every stored key as 'KeyBytes' ('stdResolver'), so a
-- 'KeyDer'-only sniff would miss every production Ed448 key and
-- misdispatch it as Ed25519 (the shim's base-id check then
-- refuses with BADKEY). 'Nothing' for references, symmetric
-- bytes, RSA, garbage, or a Weierstrass curve. The marker is
-- advisory for dispatch only: 'eddsaSpecFor' defaults it to
-- Ed25519 and the backends always execute against the key's
-- actual material, so a miss can refuse downstream but never
-- mis-sign.
eddsaCurveOfKey :: KeyMaterial -> Maybe T.Text
eddsaCurveOfKey (KeyDer der) = eddsaCurveOfDer der
eddsaCurveOfKey (KeyBytes bs) = eddsaCurveOfDer bs
eddsaCurveOfKey _ = Nothing

-- | EdDSA dispatch refusal: 'eddsaSpecFor' only fails on
-- non-pure parameters, so the refusal is unconditionally a
-- 'CryptoFailed' parameter refusal.
eddsaRefusal :: CryptoResult
eddsaRefusal = GotCryptoError (CryptoFailed "EdDSA: params must be pure (phFlag clear, empty context) or empty")
