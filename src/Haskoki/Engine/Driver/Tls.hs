{- | Driver TLS PRF/KDF/key-material dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Tls
  ( TlsPrfParams (..)
  , tlsPrfParamsFor
  , TlsKdfExec (..)
  , tlsKdfParamsFor
  , KeyMatExec (..)
  , keyMatParamsFor
  , isTlsKdfMech
  , isKeyMatMech
  , isTlsPrfMech
  , runTlsPrf
  , runTlsKdf
  , runKeyMat
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Word (Word8)

import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , digestOutLen
  , EngineResult (..)
  , KeyMaterial (..)
  , MacSpec (..)
  )
import Haskoki.Bytes (u16be)
import Haskoki.Engine.Driver.Common (rsaDigest, xorB)
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.Kdf (kdfCodeDigest)
import Haskoki.Recipe.TlsKdf
  ( TlsKdfKind (..)
  , TlsKdfRecipe (..)
  , decodeTlsKdfParams
  , maxTlsKdfOutput
  , tlsKdfParamsValid
  , tlsKdfRecipeFor
  )
import Haskoki.Recipe.TlsKeyMat
  ( TlsKeyMatKind (..)
  , TlsKeyMatRecipe (tkmKind)
  , decodeTlsKeyMatParams
  , maxTlsKeyMatBlock
  , tlsKeyMatLabel
  , tlsKeyMatParamsValid
  , tlsKeyMatRecipeFor
  )
import Haskoki.Recipe.TlsPrf
  ( decodeTlsPrfParams
  , maxTlsPrfOutput
  , tlsPrfParamsValid
  , tlsPrfRecipeFor
  )
import Haskoki.Registry (MechanismId (..))


-- | TLS-PRF inputs: the label plus the seed (RFC 2246 §5).
data TlsPrfParams = TlsPrfParams
  { tpLabel :: !ByteString
  , tpSeed :: !ByteString
  } deriving (Eq, Show)

-- | TLS-PRF dispatch: the covered (mechanism, params) pair to its
-- decoded label + seed (pinned by RecipeTlsPrfSpec). 'Nothing'
-- means uncovered (non-TLS-PRF mechanism) or malformed parameters.
tlsPrfParamsFor :: MechanismId -> ByteString -> Maybe TlsPrfParams
tlsPrfParamsFor mech params = do
  r <- tlsPrfRecipeFor mech
  guard (tlsPrfParamsValid r params)
  (lab, seed) <- decodeTlsPrfParams params
  pure (TlsPrfParams lab seed)

-- | TLS-KDF execution tuple: the row kind, the legacy flag
-- (the TLS 1.0 construction when set, @P_hash@ over the
-- digest otherwise), the label, the seed, and the RFC 5705
-- context (free rows only).
data TlsKdfExec = TlsKdfExec
  { teKind :: !TlsKdfKind
  , teLegacy :: !Bool
  , teAlg :: !(Maybe DigestAlg)
  , teLabel :: !ByteString
  , teSeed :: !ByteString
  , teContext :: !ByteString
  } deriving (Eq, Show)

-- | TLS-KDF dispatch: the covered (mechanism, params) pair to
-- its execution tuple (pinned by RecipeTlsKdfSpec).
-- 'Nothing' means uncovered (non-TLS-KDF mechanism) or
-- malformed parameters.
tlsKdfParamsFor :: MechanismId -> ByteString -> Maybe TlsKdfExec
tlsKdfParamsFor mech params = do
  r <- tlsKdfRecipeFor mech
  guard (tlsKdfParamsValid r params)
  (prf, lab, seed, ctx) <- decodeTlsKdfParams params
  if prf == 0
    then pure (TlsKdfExec (tkKind r) True Nothing lab seed ctx)
    else do
      stem <- kdfCodeDigest (fromIntegral prf)
      alg <- rsaDigest stem
      pure (TlsKdfExec (tkKind r) False (Just alg) lab seed ctx)

-- | One decoded key-material execution: the row kind, the PRF
-- code, the MAC\/key\/IV byte sizes, and the two randoms.
data KeyMatExec = KeyMatExec
  { kmeKind :: !TlsKeyMatKind
  , kmePrf :: !Word8
  , kmeMac :: !Int
  , kmeKey :: !Int
  , kmeIv :: !Int
  , kmeCr :: !ByteString
  , kmeSr :: !ByteString
  } deriving (Eq, Show)

-- | Key-material dispatch: the covered (mechanism, params)
-- pair to its execution tuple (pinned by
-- RecipeTlsKeyMatSpec).
keyMatParamsFor :: MechanismId -> ByteString -> Maybe KeyMatExec
keyMatParamsFor mech params = do
  r <- tlsKeyMatRecipeFor mech
  guard (tlsKeyMatParamsValid r params)
  (prf, mac, key, iv, cr, sr) <- decodeTlsKeyMatParams params
  pure (KeyMatExec (tkmKind r) prf mac key iv cr sr)

-- | A TLS-KDF mechanism (drives the parameter-refusal
-- branches).
isTlsKdfMech :: MechanismId -> Bool
isTlsKdfMech mech = case tlsKdfRecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | A key-material mechanism (drives the parameter-refusal
-- branches).
isKeyMatMech :: MechanismId -> Bool
isKeyMatMech mech = case tlsKeyMatRecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | The TLS-PRF mechanism (drives the parameter-refusal branch).
isTlsPrfMech :: MechanismId -> Bool
isTlsPrfMech mech = case tlsPrfRecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | TLS-PRF secret split (RFC 2246 §5): the first
-- @ceiling(len\/2)@ bytes and the last @ceiling(len\/2)@ bytes; the
-- middle byte is shared on odd lengths.
splitTlsSecret :: ByteString -> (ByteString, ByteString)
splitTlsSecret secret = (BS.take half secret, BS.drop (len - half) secret)
  where
    len = BS.length secret
    half = (len + 1) `div` 2

-- | TLS-PRF effects: the RFC 2246 expansion over the backend
-- HMAC-MD5\/SHA-1 routes. Off-range lengths are 'CryptoFailed';
-- a non-bytes key is 'CryptoBadKey'.
runTlsPrf :: CryptoBackend b => BackendEnv b -> TlsPrfParams -> KeyMaterial -> Int -> IO CryptoResult
runTlsPrf env (TlsPrfParams lab seed) key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxTlsPrfOutput -> do
        r <- tlsPrfExpand env kb (lab <> seed) outLen
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk ok -> GotBytes (BS.take outLen ok)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))

-- | TLS-KDF effects: the legacy RFC 2246 expansion or
-- @P_hash@ over the selected digest, with the RFC 5705
-- context suffix (2-byte big-endian length plus context)
-- when present. Off-range lengths are 'CryptoFailed'; a
-- non-bytes key is 'CryptoBadKey'.
runTlsKdf :: CryptoBackend b => BackendEnv b -> TlsKdfExec -> KeyMaterial -> Int -> IO CryptoResult
runTlsKdf env ex key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxTlsKdfOutput -> do
        let seedFull = teLabel ex <> teSeed ex <> ctxSuffix (teContext ex)
        r <- case (teLegacy ex, teAlg ex) of
          (True, _) -> tlsPrfExpand env kb seedFull outLen
          (False, Just alg) -> pHash env alg (KeyBytes kb) seedFull outLen
          (False, Nothing) -> pure (EngineFail (BackendBadParam "runTlsKdf"
            "TLS-KDF hash PRF without a digest"))
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk ok -> GotBytes (BS.take outLen ok)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))

-- | Key-material effects: the TLS PRF ("key expansion"
-- over server ++ client randoms, RFC 2246 §6.3) expanded to
-- the planned block length — legacy for TLS 1.0, P_hash
-- over the selected digest for TLS 1.2. The planner sizes
-- the block (KEY_SAFE excludes IVs); the finisher splits it
-- into keys + IVs. Off-range lengths are 'CryptoFailed'; a
-- non-bytes key is 'CryptoBadKey'.
runKeyMat :: CryptoBackend b => BackendEnv b -> KeyMatExec -> KeyMaterial -> Int -> IO CryptoResult
runKeyMat env ex key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxTlsKeyMatBlock -> do
        let seedFull = tlsKeyMatLabel <> kmeSr ex <> kmeCr ex
        r <- if kmePrf ex == 0
          then tlsPrfExpand env kb seedFull outLen
          else case kdfCodeDigest (fromIntegral (kmePrf ex)) >>= rsaDigest of
            Just alg -> pHash env alg (KeyBytes kb) seedFull outLen
            Nothing -> pure (EngineFail (BackendBadParam "runKeyMat"
              "key-material hash PRF without a digest"))
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk ok -> GotBytes (BS.take outLen ok)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))

-- | TLS 1.0\/1.1 PRF: P_MD5 over the first secret half XOR
-- P_SHA-1 over the second (RFC 2246 §5; the halves share the
-- middle byte on odd lengths).
tlsPrfExpand :: CryptoBackend b => BackendEnv b -> ByteString -> ByteString -> Int -> IO (EngineResult ByteString)
tlsPrfExpand env secret seedBytes outLen = do
  m <- pHash env D_MD5 (KeyBytes s1) seedBytes outLen
  case m of
    EngineFail err -> pure (EngineFail err)
    EngineOk mOut -> do
      s <- pHash env D_SHA1 (KeyBytes s2) seedBytes outLen
      pure $ case s of
        EngineFail err -> EngineFail err
        EngineOk sOut -> EngineOk (BS.take outLen mOut `xorB` BS.take outLen sOut)
  where
    (s1, s2) = splitTlsSecret secret

-- | P_hash: A(0) = seed, A(i) = HMAC(secret, A(i-1)),
-- P(i) = HMAC(secret, A(i) ++ seed), concatenated.
pHash :: CryptoBackend b => BackendEnv b -> DigestAlg -> KeyMaterial -> ByteString -> Int -> IO (EngineResult ByteString)
pHash env alg secret seedBytes outLen = case digestOutLen alg of
  Nothing -> pure (EngineFail (BackendBadParam "pHash"
    "TLS-PRF needs a fixed-width HMAC"))
  Just h -> do
    let n = (outLen + h - 1) `div` h
    go n seedBytes []
  where
    go 0 _ acc = pure (EngineOk (BS.concat (reverse acc)))
    go k aPrev acc = do
      aNext <- macSign env (MacHMAC alg Nothing) secret aPrev
      case aNext of
        EngineFail err -> pure (EngineFail err)
        EngineOk a -> do
          p <- macSign env (MacHMAC alg Nothing) secret (a <> seedBytes)
          case p of
            EngineFail err -> pure (EngineFail err)
            EngineOk blk -> go (k - 1) a (blk : acc)

-- | RFC 5705 context suffix: empty without context, else the
-- 2-byte big-endian length plus the context.
ctxSuffix :: ByteString -> ByteString
ctxSuffix ctx
  | BS.null ctx = BS.empty
  | otherwise = u16be n <> ctx
  where n = BS.length ctx
