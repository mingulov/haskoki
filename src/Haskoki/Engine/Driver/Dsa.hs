{- | Driver DSA dispatch.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Dsa
  ( dsaSpecFor
  , isDsaMech
  , dsaRefusal
  ) where
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Maybe (isJust)
import qualified Data.Text as T

import Haskoki.Engine.Backend (SigSpec (..))
import Haskoki.Engine.Driver.Common (rsaDigest)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.Dsa
  ( DsaRecipe (..)
  , dsaEncodingOf
  , dsaParamsValid
  , dsaRecipeFor
  )
import Haskoki.Registry (MechanismId (..))


-- | DSA dispatch: covered (mechanism, params) pairs to backend
-- specs (pinned against 'Haskoki.Recipe.Dsa' by RecipeDsaSpec).
-- The recipe binds the digest and validates the encoding
-- selection; there is no curve label to hint (the DSA key carries
-- its own domain parameters) and key shape is the backend's call
-- (the driver never refuses a key). 'Nothing' means uncovered
-- (non-DSA mechanism) or malformed parameters.
dsaSpecFor :: MechanismId -> ByteString -> Maybe SigSpec
dsaSpecFor mech params = do
  r <- dsaRecipeFor mech
  guard (dsaParamsValid r params)
  enc <- dsaEncodingOf params
  alg <- case rdDigestStem r of
    Nothing -> pure Nothing
    Just stem -> Just <$> rsaDigest stem
  pure (SigDSA (T.unpack enc) alg)

-- | A DSA mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed DSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isDsaMech :: MechanismId -> Bool
isDsaMech mech = isJust (dsaRecipeFor mech)

-- | DSA dispatch refusal: 'dsaSpecFor' only fails on malformed
-- parameters, so the refusal is unconditionally a 'CryptoFailed'
-- parameter refusal.
dsaRefusal :: CryptoResult
dsaRefusal = GotCryptoError (CryptoFailed "DSA: params must be RAW, DER, or empty")
