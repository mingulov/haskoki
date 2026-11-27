{- | Driver HMAC dispatch.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Hmac
  ( hmacSpecFor
  , isHmacMech
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Maybe (isJust)
import qualified Data.Text as T

import Haskoki.Engine.Backend (DigestAlg (..), MacSpec (..))
import Haskoki.Recipe.Hmac
  ( HmacRecipe (..)
  , decodeMacGeneral
  , hmacRecipeFor
  )
import Haskoki.Registry (MechanismId (..), MechanismName)


-- | HMAC dispatch: covered (mechanism, params) pairs to backend
-- specs (pinned against 'Haskoki.Recipe.Hmac' by
-- RecipeHmacSpec, so the table and the recipe can never drift
-- silently). Plain mechanisms resolve on empty parameters only;
-- GENERAL mechanisms thread the decoded tag length. 'Nothing'
-- means uncovered (non-HMAC mechanism) or malformed parameters.
hmacSpecFor :: MechanismId -> ByteString -> Maybe MacSpec
hmacSpecFor mech params = do
  r <- hmacRecipeFor mech
  alg <- hmacDigest (hrName r)
  if hrGeneral r
    then do
      n <- decodeMacGeneral params
      guard (n >= 1 && n <= hrOutLen r)
      pure (MacHMAC alg (Just n))
    else do
      guard (BS.null params)
      pure (MacHMAC alg Nothing)

-- | An HMAC mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed HMAC params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isHmacMech :: MechanismId -> Bool
isHmacMech mech = isJust (hmacRecipeFor mech)

-- | Digest stem of an HMAC recipe name, without the parameter-shape
-- suffix.
hmacDigest :: MechanismName -> Maybe DigestAlg
hmacDigest name
  | Just stem <- T.stripSuffix "_HMAC_GENERAL" name = stemAlg stem
  | Just stem <- T.stripSuffix "_HMAC" name = stemAlg stem
  | otherwise = Nothing
  where
    stemAlg :: MechanismName -> Maybe DigestAlg
    stemAlg stem
      | stem == "CKM_BLAKE2B_512" = Just D_BLAKE2B512
      | stem == "CKM_BLAKE2B_160" = Just D_BLAKE2B160
      | stem == "CKM_BLAKE2B_256" = Just D_BLAKE2B256
      | stem == "CKM_BLAKE2B_384" = Just D_BLAKE2B384
      | stem == "CKM_SHA224" = Just D_SHA224
      | stem == "CKM_SHA256" = Just D_SHA256
      | stem == "CKM_SHA384" = Just D_SHA384
      | stem == "CKM_SHA512" = Just D_SHA512
      | stem == "CKM_SHA512_224" = Just D_SHA512_224
      | stem == "CKM_SHA512_256" = Just D_SHA512_256
      | stem == "CKM_SHA3_224" = Just D_SHA3_224
      | stem == "CKM_SHA3_256" = Just D_SHA3_256
      | stem == "CKM_SHA3_384" = Just D_SHA3_384
      | stem == "CKM_SHA3_512" = Just D_SHA3_512
      | stem == "CKM_SHA_1" = Just D_SHA1
      | stem == "CKM_MD5" = Just D_MD5
      | stem == "CKM_RIPEMD160" = Just D_RIPEMD160
      | otherwise = Nothing
