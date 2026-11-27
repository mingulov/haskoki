{- | Driver CBC-MAC dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.CbcMac
  ( cbcmacSpecFor
  , isCbcMacMech
  , runCbcMacSign
  , runCbcMacVerify
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Maybe (isJust)

import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CipherSpec (..)
  , CryptoBackend (..)
  , EngineResult (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver.Common (driverCtEq, xorB, zeroPad)
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.CbcMac
  ( CbcMacCipher (..)
  , CbcMacRecipe (..)
  , cbcmacBlockLen
  , cbcmacPlainOutLen
  , cbcmacRecipeFor
  )
import Haskoki.Recipe.Hmac (decodeMacGeneral)
import Haskoki.Registry (MechanismId (..))


-- | CBC-MAC dispatch: covered (mechanism, params, key length)
-- triples map to the ECB cipher spec plus the output width (8
-- for the plain half-block rows, the decoded length for GENERAL
-- rows). The cipher binds by recipe and key length (AES\/ARIA\/
-- Camellia 128\/192\/256). 'Nothing' means uncovered
-- (non-CBC-MAC mechanism), malformed parameters, or an
-- off-geometry key length.
cbcmacSpecFor :: MechanismId -> ByteString -> Int -> Maybe (CipherSpec, Maybe Int)
cbcmacSpecFor mech params keyLen = do
  r <- cbcmacRecipeFor mech
  spec <- cbcmacCipher r keyLen
  if cbmGeneral r
    then do
      n <- decodeMacGeneral params
      guard (n >= 1 && n <= cbcmacBlockLen r)
      pure (spec, Just n)
    else do
      guard (BS.null params)
      pure (spec, Just (cbcmacPlainOutLen r))
  where
    cbcmacCipher r n = case cbmCipher r of
      CbcAes
        | n == 16 -> Just C_AES128_ECB
        | n == 24 -> Just C_AES192_ECB
        | n == 32 -> Just C_AES256_ECB
        | otherwise -> Nothing
      CbcAria
        | n == 16 -> Just C_ARIA128_ECB
        | n == 24 -> Just C_ARIA192_ECB
        | n == 32 -> Just C_ARIA256_ECB
        | otherwise -> Nothing
      CbcCamellia
        | n == 16 -> Just C_CAMELLIA128_ECB
        | n == 24 -> Just C_CAMELLIA192_ECB
        | n == 32 -> Just C_CAMELLIA256_ECB
        | otherwise -> Nothing

-- | A CBC-MAC mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: malformed MAC params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isCbcMacMech :: MechanismId -> Bool
isCbcMacMech mech = isJust (cbcmacRecipeFor mech)

-- | CBC-MAC sign effects: CBC-MAC chaining over the backend
-- ECB route, truncated to the half block (plain) or the
-- decoded length (GENERAL). Off-geometry (mechanism, key
-- length, params) triples are 'CryptoFailed'; a non-bytes key
-- is 'CryptoBadKey'.
runCbcMacSign :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> IO CryptoResult
runCbcMacSign env mech params key input = case key of
  KeyBytes kb -> case cbcmacSpecFor mech params (BS.length kb) of
    Just (spec, trunc) -> do
      r <- cbcmacTag env spec key input
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk tag -> GotBytes (maybe tag (`BS.take` tag) trunc)
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: CBC-MAC (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "CBC-MAC needs raw symmetric key bytes"))

-- | CBC-MAC verify effects: recompute, truncate,
-- constant-time compare. A mismatch is the 'False' verdict,
-- never a malfunction.
runCbcMacVerify :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runCbcMacVerify env mech params key input tag = case key of
  KeyBytes kb -> case cbcmacSpecFor mech params (BS.length kb) of
    Just (spec, trunc) -> do
      r <- cbcmacTag env spec key input
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk full
          | driverCtEq want tag -> GotValid True
          | otherwise -> GotValid False
          where want = maybe full (`BS.take` full) trunc
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: CBC-MAC (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "CBC-MAC needs raw symmetric key bytes"))

-- | The CBC-MAC tag over a 128-bit-block cipher: zero IV,
-- input zero-padded to the 16-byte block, chaining over
-- single-block ECB calls. Full width; truncation is the
-- caller's call.
cbcmacTag :: CryptoBackend b => BackendEnv b -> CipherSpec -> KeyMaterial -> ByteString -> IO (EngineResult ByteString)
cbcmacTag env spec key input
  | spec `notElem` served = pure (EngineFail (BackendBadParam "cbcmac"
      "CBC-MAC needs an AES, ARIA, or Camellia ECB cipher spec"))
  | otherwise = chain (BS.replicate blk 0) (zeroPad blk input)
  where
    blk = 16
    served =
      [ C_AES128_ECB, C_AES192_ECB, C_AES256_ECB
      , C_ARIA128_ECB, C_ARIA192_ECB, C_ARIA256_ECB
      , C_CAMELLIA128_ECB, C_CAMELLIA192_ECB, C_CAMELLIA256_ECB
      ]
    enc b = cipherEncrypt env spec key BS.empty b
    chain x [] = pure (EngineOk x)
    chain x (m : ms) = do
      e <- enc (x `xorB` m)
      case e of
        EngineFail err -> pure (EngineFail err)
        EngineOk x' -> chain x' ms
