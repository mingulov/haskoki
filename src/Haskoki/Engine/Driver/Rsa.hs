{- | Driver RSA dispatch and execution (v1.5, PSS, OAEP, X.509, X9.31).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Rsa
  ( rsaPkcs1SpecFor
  , isRsaPkcs1Mech
  , rsaPssSpecFor
  , isRsaPssMech
  , rsaOaepParamsFor
  , isRsaOaepMech
  , rsaX509SigFor
  , rsaX509CipherFor
  , isRsaX509Mech
  , rsaRecoverCipherFor
  , recoverType1Pad
  , recoverType1Strip
  , rsaX931SigFor
  , isRsaX931Mech
  , runOaep
  , runPkcs1
  , runX509
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Maybe (isJust)

import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , DigestAlg (..)
  , KeyMaterial (..)
  , OaepParams (..)
  , PssParams (..)
  , RsaCipherParams (..)
  , SigSpec (..)
  )
import Haskoki.Engine.Driver.Common (rsaDigest)
import Haskoki.Engine.Driver.Result (toBytes)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Operation.State (CipherDir (..))
import Haskoki.Recipe.RsaOaep (decodeOaepParams, rsaOaepParamsValid, rsaOaepRecipeFor)
import Haskoki.Recipe.RsaPkcs1
  ( RsaPkcs1Recipe (..)
  , rsaPkcs1ParamsValid
  , rsaPkcs1RecipeFor
  )
import Haskoki.Recipe.RsaPss
  ( decodePssParams
  , rsaPssParamsValid
  , rsaPssRecipeFor
  )
import Haskoki.Recipe.RsaX509 (rsaX509ParamsValid, rsaX509RecipeFor)
import Haskoki.Recipe.RsaX931 (rsaX931ParamsValid, rsaX931RecipeFor, rx931Name)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated (ckm_RSA_PKCS)


-- | RSA v1.5 dispatch: covered (mechanism, params) pairs to
-- backend specs (pinned against
-- 'Haskoki.Recipe.RsaPkcs1' by RecipeRsaSpec, so the table and the
-- recipe can never drift silently). Digested rows map their stem;
-- the raw row maps to 'SigRSA_Raw'. 'Nothing' means uncovered
-- (non-RSA mechanism) or malformed parameters.
rsaPkcs1SpecFor :: MechanismId -> ByteString -> Maybe SigSpec
rsaPkcs1SpecFor mech params = do
  r <- rsaPkcs1RecipeFor mech
  guard (rsaPkcs1ParamsValid r params)
  case rrDigestStem r of
    Nothing -> pure SigRSA_Raw
    Just stem -> SigRSA_PKCS1v15 <$> rsaDigest stem

-- | An RSA v1.5 mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: malformed RSA params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isRsaPkcs1Mech :: MechanismId -> Bool
isRsaPkcs1Mech mech = isJust (rsaPkcs1RecipeFor mech)

-- | RSA-PSS dispatch: covered (mechanism, params) pairs to
-- backend specs (pinned against
-- 'Haskoki.Recipe.RsaPss' by RecipePssSpec). The recipe validates
-- the binding and bounds; the decode below re-reads the same words
-- (total on validated input). 'Nothing' means uncovered
-- (non-PSS mechanism) or malformed parameters.
rsaPssSpecFor :: MechanismId -> ByteString -> Maybe SigSpec
rsaPssSpecFor mech params = do
  r <- rsaPssRecipeFor mech
  guard (rsaPssParamsValid r params)
  (d, m, salt) <- decodePssParams params
  hashAlg <- rsaDigest d
  mgfAlg <- rsaDigest m
  pure (SigRSA_PSS (PssParams hashAlg mgfAlg salt))

-- | A PSS mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed PSS params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isRsaPssMech :: MechanismId -> Bool
isRsaPssMech mech = isJust (rsaPssRecipeFor mech)

-- | RSA-OAEP dispatch: the covered (mechanism, params) pair to
-- backend parameters (pinned against
-- 'Haskoki.Recipe.RsaOaep' by RecipeOaepSpec). 'Nothing' means
-- uncovered (non-OAEP mechanism) or malformed parameters.
rsaOaepParamsFor :: MechanismId -> ByteString -> Maybe OaepParams
rsaOaepParamsFor mech params = do
  r <- rsaOaepRecipeFor mech
  guard (rsaOaepParamsValid r params)
  (d, m, label) <- decodeOaepParams params
  hashAlg <- rsaDigest d
  mgfAlg <- rsaDigest m
  pure (OaepParams hashAlg mgfAlg label)

-- | An OAEP mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed OAEP params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isRsaOaepMech :: MechanismId -> Bool
isRsaOaepMech mech = isJust (rsaOaepRecipeFor mech)

-- | RSA-X.509 dispatch: the covered (mechanism, params) pair to
-- its sign/verify backend spec (pinned against
-- 'Haskoki.Recipe.RsaX509' by RecipeX509Spec). 'Nothing' means
-- uncovered (non-X.509 mechanism) or malformed parameters.
rsaX509SigFor :: MechanismId -> ByteString -> Maybe SigSpec
rsaX509SigFor mech params = do
  r <- rsaX509RecipeFor mech
  guard (rsaX509ParamsValid r params)
  pure SigRSA_X509

-- | RSA-X.509 dispatch: the covered (mechanism, params) pair to
-- its cipher backend params (pinned against
-- 'Haskoki.Recipe.RsaX509' by RecipeX509Spec). 'Nothing' means
-- uncovered (non-X.509 mechanism) or malformed parameters.
rsaX509CipherFor :: MechanismId -> ByteString -> Maybe RsaCipherParams
rsaX509CipherFor mech params = do
  r <- rsaX509RecipeFor mech
  guard (rsaX509ParamsValid r params)
  pure RsaX509

-- | An X.509 mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed X.509 params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isRsaX509Mech :: MechanismId -> Bool
isRsaX509Mech mech = isJust (rsaX509RecipeFor mech)

-- | Recover dispatch: the covered (mechanism, params) pair to its
-- raw backend params (pinned against the recipe tables by
-- RecipeX509Spec and RecipeRsaSpec). 'Just RsaX509' covers the
-- two raw-RSA rows with empty parameters: X.509 runs the raw
-- op directly, while the raw PKCS row frames block-type-1 in
-- the driver ('recoverType1Pad'/'recoverType1Strip') around the
-- same raw op. The eleven PKCS digest rows and every other
-- mechanism map to 'Nothing' (never 'CryptoUnsupported' here;
-- the arms' fallthrough owns that refusal).
rsaRecoverCipherFor :: MechanismId -> ByteString -> Maybe RsaCipherParams
rsaRecoverCipherFor mech params
  | isJust (rsaX509CipherFor mech params) = Just RsaX509
  | mech == MechanismId ckm_RSA_PKCS
  , Just r <- rsaPkcs1RecipeFor mech
  , rsaPkcs1ParamsValid r params = Just RsaX509
  | otherwise = Nothing

-- | PKCS#1 block-type-1 framing for the raw-PKCS recover arm:
-- pad @0x00 0x01 0xFF.. 0x00 data@ out to the given width
-- ('Nothing' when the data cannot fit with the mandatory
-- 8-byte filler).
recoverType1Pad :: Int -> ByteString -> Maybe ByteString
recoverType1Pad width input
  | BS.length input + 11 > width = Nothing
  | otherwise = Just
      (BS.pack [0x00, 0x01]
        <> BS.replicate (width - BS.length input - 3) 0xff
        <> BS.pack [0x00]
        <> input)

-- | The inverse framing: validate @0x00 0x01 0xFF.. 0x00 data@
-- and return the data ('Nothing' on any deviation, which the
-- arm reports as a mismatch verdict).
recoverType1Strip :: ByteString -> Maybe ByteString
recoverType1Strip raw = case BS.uncons raw of
  Just (0x00, r1) -> case BS.uncons r1 of
    Just (0x01, r2) ->
      let (fill, rest) = BS.span (== 0xff) r2
      in case BS.uncons rest of
        Just (0x00, dat)
          | BS.length fill >= 8 -> Just dat
        _ -> Nothing
    _ -> Nothing
  _ -> Nothing

-- | RSA-X9.31 dispatch: the covered (mechanism, params) pair to
-- its sign/verify backend spec (pinned against
-- 'Haskoki.Recipe.RsaX931' by RecipeRsaX931Spec). The raw row
-- maps to the prehash spec (the input length selects the hash id
-- at op time); the SHA-1 row maps to the digested spec.
-- 'Nothing' means uncovered (non-X9.31 mechanism) or malformed
-- parameters.
rsaX931SigFor :: MechanismId -> ByteString -> Maybe SigSpec
rsaX931SigFor mech params = do
  r <- rsaX931RecipeFor mech
  guard (rsaX931ParamsValid r params)
  case rx931Name r of
    "CKM_SHA1_RSA_X9_31" -> pure (SigRSA_X931 (Just D_SHA1))
    _ -> pure (SigRSA_X931 Nothing)

-- | An X9.31 mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed X9.31 params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isRsaX931Mech :: MechanismId -> Bool
isRsaX931Mech mech = isJust (rsaX931RecipeFor mech)

-- | RSA-OAEP cipher effects: the effect parameters carry the
-- @oaep-params\/1@ encoding straight to the asymmetric backend
-- entry points (encrypt takes the public half, decrypt the
-- private half; both travel as DER key material).
runOaep :: CryptoBackend b => BackendEnv b -> CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runOaep env dir mech key params input =
  case rsaOaepParamsFor mech params of
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: OAEP mechanism parameters rejected by the recipe"))
    Just oparams -> case dir of
      DirEncrypt -> toBytes <$> pkeyEncrypt env (RsaOaep oparams) key input
      DirDecrypt -> toBytes <$> pkeyDecrypt env (RsaOaep oparams) key input

-- | RSA v1.5 cipher effects (wrap/unwrap only): empty
-- parameters straight to the asymmetric backend entry points
-- (encrypt takes the public half, decrypt the private half;
-- both travel as DER key material).
runPkcs1 :: CryptoBackend b => BackendEnv b -> CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runPkcs1 env dir _mech key params input
  | not (BS.null params) = pure (GotCryptoError (CryptoFailed
      "driver: v1.5 wrap takes no mechanism parameters"))
  | otherwise = case dir of
      DirEncrypt -> toBytes <$> pkeyEncrypt env RsaPkcs1 key input
      DirDecrypt -> toBytes <$> pkeyDecrypt env RsaPkcs1 key input

-- | RSA-X.509 cipher effects: empty parameters straight to the
-- asymmetric backend entry points (encrypt takes the public
-- half, decrypt the private half; both travel as DER key
-- material). The backends left-pad short inputs to the modulus
-- width and answer full k-blocks.
runX509 :: CryptoBackend b => BackendEnv b -> CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runX509 env dir mech key params input =
  case rsaX509CipherFor mech params of
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: X.509 mechanism parameters rejected by the recipe"))
    Just cparams -> case dir of
      DirEncrypt -> toBytes <$> pkeyEncrypt env cparams key input
      DirDecrypt -> toBytes <$> pkeyDecrypt env cparams key input
