{- | Driver AEAD dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Aead
  ( aeadSpecFor
  , isGcmMech
  , isCcmMech
  , isChachaPolyMech
  , runAead
  , runAeadMessage
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Applicative ((<|>))
import Control.Monad (guard)
import Data.Maybe (isJust)

import Haskoki.Engine.Backend
  ( AeadSpec (..)
  , BackendEnv
  , CryptoBackend (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver.Result (toBytes, toKemPair)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Operation.State (CipherDir (..))
import Haskoki.Recipe.Ccm (ccmParamsValid, ccmRecipeFor, decodeCcmParams)
import Haskoki.Recipe.Chacha20
  ( Chacha20Recipe (..)
  , chachaParamsValid
  , chachaRecipeFor
  , decodeChachaPolyParams
  )
import Haskoki.Recipe.Gcm (decodeGcmParams, gcmParamsValid, gcmRecipeFor)
import Haskoki.Registry (MechanismId (..))


-- | The backend spec of a covered AEAD triple ('aeadPartsFor'
-- without the decoded parts).
aeadSpecFor :: MechanismId -> Int -> ByteString -> Maybe AeadSpec
aeadSpecFor mech keyLen params =
  (\(spec, _, _) -> spec) <$> aeadPartsFor mech keyLen params

-- | AEAD dispatch: covered (mechanism, key length, params)
-- triples to the backend spec plus the decoded (IV, AAD) (pinned
-- against 'Haskoki.Recipe.Gcm' by RecipeGcmSpec, so the table and
-- the recipe can never drift silently). The recipe validates the
-- parameters (caller IV, approved tag width) and the key length
-- selects the AES width; the nonce length is the IV length.
-- 'Nothing' means uncovered (non-AEAD mechanism) or a rejected
-- triple.
aeadPartsFor :: MechanismId -> Int -> ByteString -> Maybe (AeadSpec, ByteString, ByteString)
aeadPartsFor mech keyLen params =
  gcmParts <|> ccmParts <|> chachaParts
  where
    gcmParts = do
      r <- gcmRecipeFor mech
      guard (gcmParamsValid r params)
      (iv, aad, tagLen) <- decodeGcmParams params
      alg <- case keyLen of
        16 -> Just "AES-128-GCM"
        24 -> Just "AES-192-GCM"
        32 -> Just "AES-256-GCM"
        _ -> Nothing
      pure (AeadSpec alg (BS.length iv) tagLen, iv, aad)
    ccmParts = do
      r <- ccmRecipeFor mech
      guard (ccmParamsValid r params)
      (nonce, aad, tagLen, _) <- decodeCcmParams params
      alg <- case keyLen of
        16 -> Just "AES-128-CCM"
        24 -> Just "AES-192-CCM"
        32 -> Just "AES-256-CCM"
        _ -> Nothing
      pure (AeadSpec alg (BS.length nonce) tagLen, nonce, aad)
    -- ChaCha20-Poly1305: 256-bit keys only; the recipe pins the
    -- fixed 16-byte tag and the 12-byte nonce.
    chachaParts = do
      r <- chachaRecipeFor mech
      guard (chachaName r == "CKM_CHACHA20_POLY1305")
      guard (chachaParamsValid r params)
      (nonce, aad, tagLen) <- decodeChachaPolyParams params
      guard (keyLen == 32)
      pure (AeadSpec "ChaCha20-Poly1305" (BS.length nonce) tagLen, nonce, aad)

-- | CCM data-length agreement: @ulDataLen@ must equal the
-- plaintext length (encrypt: the input; decrypt: the input minus
-- the tag). Short decrypt inputs defer to the authentication
-- failure in 'runAeadSealed' instead of failing here.
ccmLengthBad :: CipherDir -> ByteString -> ByteString -> Int -> Bool
ccmLengthBad dir params input tagLen = case decodeCcmParams params of
  Just (_, _, _, dataLen) -> case dir of
    DirEncrypt -> dataLen /= BS.length input
    DirDecrypt
      | BS.length input < tagLen -> False
      | otherwise -> dataLen /= BS.length input - tagLen
  Nothing -> True

-- | An AEAD mechanism regardless of triple validity (drives the
-- parameter-refusal branch: rejected triples are 'CryptoFailed',
-- never 'CryptoUnsupported').
isGcmMech :: MechanismId -> Bool
isGcmMech mech = isJust (gcmRecipeFor mech)

-- | A CCM mechanism regardless of triple validity (same refusal
-- branch as GCM: rejected triples are 'CryptoFailed', never
-- 'CryptoUnsupported').
isCcmMech :: MechanismId -> Bool
isCcmMech mech = isJust (ccmRecipeFor mech)

-- | The ChaCha20-Poly1305 AEAD row regardless of triple validity
-- (same refusal branch as GCM/CCM).
isChachaPolyMech :: MechanismId -> Bool
isChachaPolyMech mech = case chachaRecipeFor mech of
  Just r -> chachaName r == "CKM_CHACHA20_POLY1305"
  Nothing -> False

-- | AEAD cipher effects: the @gcm-params/1@ image decodes to
-- (IV, AAD, tag length); the key length selects the AES width.
-- Encrypt answers ciphertext and tag concatenated; decrypt
-- splits the input at the tag length. An input shorter than
-- the tag carries no tag to verify and fails authentication
-- ('CryptoAuthFailed', never a wrong plaintext).
runAead :: CryptoBackend b => BackendEnv b -> CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runAead env dir mech key params input = case key of
  KeyBytes kb -> case aeadPartsFor mech (BS.length kb) params of
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: AEAD (mechanism, key length, params) rejected by the recipe"))
    Just (spec, iv, aad)
      | isCcmMech mech, ccmLengthBad dir params input (aeadTagLen spec) ->
          pure (GotCryptoError (CryptoFailed
            "driver: CCM ulDataLen does not match the input length"))
      | otherwise -> runAeadSealed env dir spec key iv aad input
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "AEAD needs raw symmetric key bytes"))

-- | AEAD message effects: the parameters decode (IV, tag length)
-- as above, but the AAD travels on the effect, not in the
-- parameters.
runAeadMessage :: CryptoBackend b => BackendEnv b -> CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> ByteString -> IO CryptoResult
runAeadMessage env dir mech key params aad input = case key of
  KeyBytes kb -> case aeadPartsFor mech (BS.length kb) params of
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: AEAD (mechanism, key length, params) rejected by the recipe"))
    Just (spec, iv, _) -> runAeadSealed env dir spec key iv aad input
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "AEAD needs raw symmetric key bytes"))

runAeadSealed :: CryptoBackend b => BackendEnv b -> CipherDir -> AeadSpec -> KeyMaterial -> ByteString -> ByteString -> ByteString -> IO CryptoResult
runAeadSealed env dir spec key iv aad input = case dir of
  DirEncrypt -> toKemPair <$> aeadEncrypt env spec key iv aad input
  DirDecrypt
    | BS.length input < aeadTagLen spec -> pure (GotCryptoError (CryptoAuthFailed
        "driver: AEAD input shorter than the authentication tag"))
    | otherwise ->
        let (ct, tag) = BS.splitAt (BS.length input - aeadTagLen spec) input
        in toBytes <$> aeadDecrypt env spec key iv aad ct tag
