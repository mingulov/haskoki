{- | Driver XCBC-MAC dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Xcbc
  ( xcbcSpecFor
  , isXcbcMech
  , runXcbcSign
  , runXcbcVerify
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.List (unsnoc)
import Data.Maybe (isJust)

import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CipherSpec (..)
  , CryptoBackend (..)
  , EngineResult (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver.Common (chunksOf, driverCtEq, padBlock, xorB)
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.XcbcMac (xcbcOutLen, xcbcRecipeFor)
import Haskoki.Registry (MechanismId (..))


-- | XCBC-MAC dispatch: covered (mechanism, params, key length)
-- triples map to AES-128-ECB plus the output width (16 plain,
-- 12 for _96). Keys are 128-bit only. 'Nothing' means uncovered
-- (non-XCBC mechanism), malformed parameters, or an off-geometry
-- key length.
xcbcSpecFor :: MechanismId -> ByteString -> Int -> Maybe (CipherSpec, Maybe Int)
xcbcSpecFor mech params keyLen = do
  r <- xcbcRecipeFor mech
  guard (keyLen == 16)
  guard (BS.null params)
  pure (C_AES128_ECB, Just (xcbcOutLen r))

-- | An XCBC-MAC mechanism regardless of parameter validity (drives
-- the parameter-refusal branch: malformed MAC params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isXcbcMech :: MechanismId -> Bool
isXcbcMech mech = isJust (xcbcRecipeFor mech)

-- | XCBC-MAC sign effects: the RFC 3566 composition over the
-- backend AES-128-ECB route, truncated for the _96 row.
-- Off-geometry (mechanism, key length, params) triples are
-- 'CryptoFailed'; a non-bytes key is 'CryptoBadKey'.
runXcbcSign :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> IO CryptoResult
runXcbcSign env mech params key input = case key of
  KeyBytes kb -> case xcbcSpecFor mech params (BS.length kb) of
    Just (spec, trunc) -> do
      r <- xcbcTag env spec key input
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk tag -> GotBytes (maybe tag (`BS.take` tag) trunc)
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: XCBC-MAC (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "XCBC-MAC needs raw symmetric key bytes"))

-- | XCBC-MAC verify effects: recompute, truncate,
-- constant-time compare. A mismatch is the 'False' verdict,
-- never a malfunction.
runXcbcVerify :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runXcbcVerify env mech params key input tag = case key of
  KeyBytes kb -> case xcbcSpecFor mech params (BS.length kb) of
    Just (spec, trunc) -> do
      r <- xcbcTag env spec key input
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk full
          | driverCtEq want tag -> GotValid True
          | otherwise -> GotValid False
          where want = maybe full (`BS.take` full) trunc
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: XCBC-MAC (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "XCBC-MAC needs raw symmetric key bytes"))

-- | The RFC 3566 XCBC-MAC tag: subkeys K1\/K2\/K3 from the
-- 128-bit key over AES-128-ECB, 10* padding when the final
-- block is short (K3) or K2 when full, chaining under K1 over
-- single-block ECB calls. Full 16-byte width; truncation is
-- the caller's call.
xcbcTag :: CryptoBackend b => BackendEnv b -> CipherSpec -> KeyMaterial -> ByteString -> IO (EngineResult ByteString)
xcbcTag env spec key input
  | spec /= C_AES128_ECB = pure (EngineFail (BackendBadParam "xcbc"
      "XCBC-MAC needs the AES-128 ECB cipher spec"))
  | otherwise = do
      k1 <- encKey key (BS.replicate blk 0x01)
      k2 <- encKey key (BS.replicate blk 0x02)
      k3 <- encKey key (BS.replicate blk 0x03)
      case (k1, k2, k3) of
        (EngineOk s1, EngineOk s2, EngineOk s3) ->
          let blks = chunksOf blk input
              (front, lastM) = case unsnoc blks of
                Nothing -> ([], padBlock blk BS.empty `xorB` s3)
                Just (pre, lst)
                  | BS.length lst == blk -> (pre, lst `xorB` s2)
                  | otherwise -> (pre, padBlock blk lst `xorB` s3)
          in chain (KeyBytes s1) (BS.replicate blk 0) (front ++ [lastM])
        (EngineFail err, _, _) -> pure (EngineFail err)
        (_, EngineFail err, _) -> pure (EngineFail err)
        (_, _, EngineFail err) -> pure (EngineFail err)
  where
    blk = 16
    encKey k b = cipherEncrypt env spec k BS.empty b
    chain _ x [] = pure (EngineOk x)
    chain k x (m : ms) = do
      e <- encKey k (x `xorB` m)
      case e of
        EngineFail err -> pure (EngineFail err)
        EngineOk x' -> chain k x' ms
