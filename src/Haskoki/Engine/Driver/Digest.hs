{- | Driver digest dispatch.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Digest
  ( digestAlgFor
  ) where
import Haskoki.Engine.Backend (DigestAlg (..))
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated
  ( ckm_BLAKE2B_160
  , ckm_BLAKE2B_256
  , ckm_BLAKE2B_384
  , ckm_BLAKE2B_512
  , ckm_MD5
  , ckm_RIPEMD160
  , ckm_SHA224
  , ckm_SHA256
  , ckm_SHA384
  , ckm_SHA3_224
  , ckm_SHA3_256
  , ckm_SHA3_384
  , ckm_SHA3_512
  , ckm_SHA512
  , ckm_SHA512_224
  , ckm_SHA512_256
  , ckm_SHA_1
  )


-- | Digest dispatch: covered mechanism to backend algorithm (pinned
-- pinned against 'Haskoki.Recipe.Digest' by RecipeDigestSpec, so the
-- table and the recipe can never drift silently).
digestAlgFor :: MechanismId -> Maybe DigestAlg
digestAlgFor mech
  | mech == MechanismId (ckm_BLAKE2B_512) = Just D_BLAKE2B512
  | mech == MechanismId (ckm_BLAKE2B_160) = Just D_BLAKE2B160
  | mech == MechanismId (ckm_BLAKE2B_256) = Just D_BLAKE2B256
  | mech == MechanismId (ckm_BLAKE2B_384) = Just D_BLAKE2B384
  | mech == MechanismId (ckm_SHA224) = Just D_SHA224
  | mech == MechanismId (ckm_SHA256) = Just D_SHA256
  | mech == MechanismId (ckm_SHA384) = Just D_SHA384
  | mech == MechanismId (ckm_SHA512) = Just D_SHA512
  | mech == MechanismId (ckm_SHA512_224) = Just D_SHA512_224
  | mech == MechanismId (ckm_SHA512_256) = Just D_SHA512_256
  | mech == MechanismId (ckm_SHA3_224) = Just D_SHA3_224
  | mech == MechanismId (ckm_SHA3_256) = Just D_SHA3_256
  | mech == MechanismId (ckm_SHA3_384) = Just D_SHA3_384
  | mech == MechanismId (ckm_SHA3_512) = Just D_SHA3_512
  | mech == MechanismId (ckm_SHA_1) = Just D_SHA1
  | mech == MechanismId (ckm_MD5) = Just D_MD5
  | mech == MechanismId (ckm_RIPEMD160) = Just D_RIPEMD160
  | otherwise = Nothing
