{- | Driver SSL3 derive and MAC dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Ssl3
  ( ssl3ParamsFor
  , isSsl3Mech
  , ssl3MacSpecFor
  , isSsl3MacMech
  , runSsl3
  , runSsl3MacSign
  , runSsl3MacVerify
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)

import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EngineResult (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver.Common (driverCtEq)
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.Hmac (decodeMacGeneral)
import Haskoki.Recipe.Ssl3
  ( Ssl3Kind (..)
  , Ssl3Recipe (ssl3Kind)
  , decodeSsl3KeyMatParams
  , decodeSsl3MasterParams
  , maxSsl3KeyBlock
  , ssl3ParamsValid
  , ssl3RecipeFor
  )
import Haskoki.Registry (MechanismId (..))


-- | One decoded SSL3-derive execution: master rows carry the
-- two randoms; the keymat row carries the MAC\/key\/IV byte
-- sizes plus the two randoms.
data Ssl3Exec
  = Ssl3MasterExec !ByteString !ByteString
  | Ssl3KeyMatExec !Int !Int !Int !ByteString !ByteString
  deriving (Eq, Show)

-- | SSL3-derive dispatch: the covered (mechanism, params)
-- pair to its execution tuple (pinned by RecipeSsl3Spec).
-- MAC rows never resolve here (they execute on the sign
-- path).
ssl3ParamsFor :: MechanismId -> ByteString -> Maybe Ssl3Exec
ssl3ParamsFor mech params = do
  r <- ssl3RecipeFor mech
  guard (ssl3ParamsValid r params)
  case ssl3Kind r of
    Ssl3Master -> uncurry Ssl3MasterExec <$> decodeSsl3MasterParams params
    Ssl3MasterDh -> uncurry Ssl3MasterExec <$> decodeSsl3MasterParams params
    Ssl3KeyMat -> do
      (mac, key, iv, cr, sr) <- decodeSsl3KeyMatParams params
      pure (Ssl3KeyMatExec mac key iv cr sr)
    _ -> Nothing

-- | An SSL3-derive mechanism regardless of parameter
-- validity (drives the parameter-refusal branch).
isSsl3Mech :: MechanismId -> Bool
isSsl3Mech mech = case ssl3RecipeFor mech of
  Just r -> case ssl3Kind r of
    Ssl3Master -> True
    Ssl3MasterDh -> True
    Ssl3KeyMat -> True
    _ -> False
  Nothing -> False

-- | SSL3-MAC dispatch: covered (mechanism, params) pairs to the
-- digest plus the whole-byte tag length (pinned against
-- 'Haskoki.Recipe.Ssl3' by RecipeSsl3Spec). 'Nothing' means
-- uncovered (non-SSL3-MAC mechanism) or malformed parameters.
ssl3MacSpecFor :: MechanismId -> ByteString -> Maybe (DigestAlg, Int)
ssl3MacSpecFor mech params = do
  r <- ssl3RecipeFor mech
  alg <- case ssl3Kind r of
    Ssl3Md5Mac -> Just D_MD5
    Ssl3Sha1Mac -> Just D_SHA1
    _ -> Nothing
  guard (ssl3ParamsValid r params)
  n <- decodeMacGeneral params
  pure (alg, n `div` 8)

-- | An SSL3-MAC mechanism regardless of parameter validity
-- (drives the parameter-refusal branch).
isSsl3MacMech :: MechanismId -> Bool
isSsl3MacMech mech = case ssl3RecipeFor mech of
  Just r -> case ssl3Kind r of
    Ssl3Md5Mac -> True
    Ssl3Sha1Mac -> True
    _ -> False
  Nothing -> False

-- | SSL3 derive effects: the RFC 6101 constructions over
-- provider MD5\/SHA-1. Master rows emit the fixed 48-byte
-- §6.1 secret; the keymat row emits the §6.2.2 block
-- (pad bytes @A@..@0xFF@: past round 191 the
-- construction is undefined, so over-bound blocks fail
-- typed even when called past the planner).
runSsl3 :: CryptoBackend b => BackendEnv b -> Ssl3Exec -> KeyMaterial -> Int -> IO CryptoResult
runSsl3 env ex key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxSsl3KeyBlock -> case ex of
        Ssl3MasterExec cr sr -> do
          r <- ssl3Master env kb cr sr
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk ok -> GotBytes (BS.take outLen ok)
        Ssl3KeyMatExec mac k iv cr sr ->
          let total = 2 * mac + 2 * k + 2 * iv
          in if total < 1 || total > maxSsl3KeyBlock
            then pure (GotCryptoError (CryptoFailed
              "driver: SSL3 key block past the 191-round construction bound"))
            else do
              r <- ssl3Block env kb cr sr total
              pure $ case r of
                EngineFail err -> GotCryptoError (toCryptoError err)
                EngineOk ok -> GotBytes (BS.take outLen ok)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))

-- | RFC 6101 §6.1: @MD5(secret + SHA1(pad + secret + CR
-- + SR))@ over pads @A@, @BB@, @CCC@.
ssl3Master :: CryptoBackend b => BackendEnv b -> ByteString -> ByteString -> ByteString -> IO (EngineResult ByteString)
ssl3Master env secret cr sr = go pads []
  where
    pads = [BS.singleton 65, BS.pack [66, 66], BS.pack [67, 67, 67]]
    go [] acc = pure (EngineOk (BS.concat (reverse acc)))
    go (pad : rest) acc = do
      rSha <- digestOneShot env D_SHA1 (pad <> secret <> cr <> sr)
      case rSha of
        EngineFail err -> pure (EngineFail err)
        EngineOk sha -> do
          rMd5 <- digestOneShot env D_MD5 (secret <> sha)
          case rMd5 of
            EngineFail err -> pure (EngineFail err)
            EngineOk d -> go rest (d : acc)

-- | RFC 6101 §6.2.2: @MD5(secret + SHA1(pad + secret + SR
-- + CR))@ iterated, pad @i@ is byte @(0x41 + i - 1)@
-- repeated @i@ times (note server random first).
ssl3Block :: CryptoBackend b => BackendEnv b -> ByteString -> ByteString -> ByteString -> Int -> IO (EngineResult ByteString)
ssl3Block env secret cr sr total = go 1 []
  where
    go i acc
      | length acc * 16 >= total = pure (EngineOk (BS.take total (BS.concat (reverse acc))))
      | i > 191 = pure (EngineFail (BackendBadParam "ssl3Block"
          "SSL3 key block past the 191-round construction bound"))
      | otherwise = do
          let pad = BS.replicate i (65 + fromIntegral i - 1)
          rSha <- digestOneShot env D_SHA1 (pad <> secret <> sr <> cr)
          case rSha of
            EngineFail err -> pure (EngineFail err)
            EngineOk sha -> do
              rMd5 <- digestOneShot env D_MD5 (secret <> sha)
              case rMd5 of
                EngineFail err -> pure (EngineFail err)
                EngineOk d -> go (i + 1) (d : acc)

-- | SSL3 MAC sign effects: @H(secret + pad2 + H(secret +
-- pad1 + data))@ truncated to the requested whole-byte
-- length (pads 48 bytes MD5, 40 bytes SHA-1).
runSsl3MacSign :: CryptoBackend b => BackendEnv b -> DigestAlg -> Int -> KeyMaterial -> ByteString -> IO CryptoResult
runSsl3MacSign env alg n key input = case key of
  KeyBytes kb -> do
    r <- ssl3Mac env alg kb input
    pure $ case r of
      EngineFail err -> GotCryptoError (toCryptoError err)
      EngineOk full -> GotBytes (BS.take n full)
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "SSL3 MAC needs raw symmetric key bytes"))

-- | SSL3 MAC verify effects: recompute, truncate,
-- constant-time compare. A mismatch is the 'False'
-- verdict, never a malfunction.
runSsl3MacVerify :: CryptoBackend b => BackendEnv b -> DigestAlg -> Int -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runSsl3MacVerify env alg n key input tag = case key of
  KeyBytes kb -> do
    r <- ssl3Mac env alg kb input
    pure $ case r of
      EngineFail err -> GotCryptoError (toCryptoError err)
      EngineOk full
        | driverCtEq (BS.take n full) tag -> GotValid True
        | otherwise -> GotValid False
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "SSL3 MAC needs raw symmetric key bytes"))

-- | The RFC 6101 MAC core over the resolved digest.
ssl3Mac :: CryptoBackend b => BackendEnv b -> DigestAlg -> ByteString -> ByteString -> IO (EngineResult ByteString)
ssl3Mac env alg secret input = case alg of
  D_MD5 -> macWith 48
  D_SHA1 -> macWith 40
  _ -> pure (EngineFail (BackendBadParam "ssl3Mac"
    "SSL3 MAC needs MD5 or SHA-1"))
  where
    macWith padLen = do
      let pad1 = BS.replicate padLen 0x36
          pad2 = BS.replicate padLen 0x5c
      rInner <- digestOneShot env alg (secret <> pad1 <> input)
      case rInner of
        EngineFail err -> pure (EngineFail err)
        EngineOk inner -> digestOneShot env alg (secret <> pad2 <> inner)
