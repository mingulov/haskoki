{- | Driver 3DES-MAC dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Des3Mac
  ( des3macSpecFor
  , isDes3MacMech
  , runDes3MacSign
  , runDes3MacVerify
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
import Haskoki.Recipe.Des3Mac
  ( Des3MacRecipe (..)
  , des3macBlockLen
  , des3macPlainOutLen
  , des3macRecipeFor
  )
import Haskoki.Recipe.Hmac (decodeMacGeneral)
import Haskoki.Registry (MechanismId (..))


-- | 3DES-MAC dispatch: covered (mechanism, params, key length)
-- triples map to the ECB cipher spec plus the output width (4 for
-- the plain half-block row, the decoded length for GENERAL rows).
-- 'Nothing' means uncovered (non-3DES-MAC mechanism), malformed
-- parameters, or an off-geometry key length.
des3macSpecFor :: MechanismId -> ByteString -> Int -> Maybe (CipherSpec, Maybe Int)
des3macSpecFor mech params keyLen = do
  r <- des3macRecipeFor mech
  guard (keyLen == 16 || keyLen == 24)
  if rdmGeneral r
    then do
      n <- decodeMacGeneral params
      guard (n >= 1 && n <= des3macBlockLen r)
      pure (C_DES3_ECB, Just n)
    else do
      guard (BS.null params)
      pure (C_DES3_ECB, Just (des3macPlainOutLen r))

-- | A 3DES-MAC mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: malformed MAC params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isDes3MacMech :: MechanismId -> Bool
isDes3MacMech mech = isJust (des3macRecipeFor mech)

-- | 3DES-MAC sign effects: CBC-MAC chaining over the backend
-- ECB route, truncated to the half block (plain) or the
-- decoded length (GENERAL). Off-geometry (mechanism, key
-- length, params) triples are 'CryptoFailed'; a non-bytes key
-- is 'CryptoBadKey'.
runDes3MacSign :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> IO CryptoResult
runDes3MacSign env mech params key input = case key of
  KeyBytes kb -> case des3macSpecFor mech params (BS.length kb) of
    Just (spec, trunc) -> do
      r <- des3macTag env spec key input
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk tag -> GotBytes (maybe tag (`BS.take` tag) trunc)
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: 3DES-MAC (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "3DES-MAC needs raw symmetric key bytes"))

-- | 3DES-MAC verify effects: recompute, truncate,
-- constant-time compare. A mismatch is the 'False' verdict,
-- never a malfunction.
runDes3MacVerify :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runDes3MacVerify env mech params key input tag = case key of
  KeyBytes kb -> case des3macSpecFor mech params (BS.length kb) of
    Just (spec, trunc) -> do
      r <- des3macTag env spec key input
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk full
          | driverCtEq want tag -> GotValid True
          | otherwise -> GotValid False
          where want = maybe full (`BS.take` full) trunc
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: 3DES-MAC (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "3DES-MAC needs raw symmetric key bytes"))

-- | The 3DES CBC-MAC tag: zero IV, input zero-padded to the
-- 8-byte block, chaining over single-block ECB calls. Full
-- width; truncation is the caller's call.
des3macTag :: CryptoBackend b => BackendEnv b -> CipherSpec -> KeyMaterial -> ByteString -> IO (EngineResult ByteString)
des3macTag env spec key input
  | spec /= C_DES3_ECB = pure (EngineFail (BackendBadParam "des3mac"
      "3DES-MAC needs the 3DES ECB cipher spec"))
  | otherwise = chain (BS.replicate blk 0) (zeroPad blk input)
  where
    blk = 8
    enc b = cipherEncrypt env spec key BS.empty b
    chain x [] = pure (EngineOk x)
    chain x (m : ms) = do
      e <- enc (x `xorB` m)
      case e of
        EngineFail err -> pure (EngineFail err)
        EngineOk x' -> chain x' ms
