{- | Driver Poly1305 dispatch.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Poly1305
  ( poly1305MacFor
  , isPoly1305Mech
  ) where
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Maybe (isJust)

import Haskoki.Engine.Backend (MacSpec (..))
import Haskoki.Recipe.Poly1305 (poly1305ParamsValid, poly1305RecipeFor)
import Haskoki.Registry (MechanismId (..))


-- | Poly1305 dispatch: the covered (mechanism, params) pair to
-- its backend spec (pinned against
-- 'Haskoki.Recipe.Poly1305' by RecipePoly1305Spec). 'Nothing'
-- means uncovered (non-Poly1305 mechanism) or malformed
-- parameters.
poly1305MacFor :: MechanismId -> ByteString -> Maybe MacSpec
poly1305MacFor mech params = do
  r <- poly1305RecipeFor mech
  guard (poly1305ParamsValid r params)
  pure MacPoly1305

-- | A Poly1305 mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: malformed Poly1305 params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isPoly1305Mech :: MechanismId -> Bool
isPoly1305Mech mech = isJust (poly1305RecipeFor mech)
