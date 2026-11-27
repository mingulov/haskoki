{- | Driver KDF dispatch and execution (SHA, XOF, PBKDF2, HKDF, encrypt-data).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Kdf
  ( Pbkd2Params (..)
  , kdfShaFor
  , kdfXofFor
  , pbkd2ParamsFor
  , pbkdf2
  , encryptDataPartsFor
  , isEncryptDataMech
  , isKdfShaMech
  , isKdfXofMech
  , isPbkd2Mech
  , runShaKd
  , runXofKd
  , runEncryptData
  , runPbkd2
  , hkdfParamsFor
  , hkdfExpand
  , hkdfExtractExpand
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Bits ((.&.), shiftR)
import Data.Maybe (isJust, isNothing)
import qualified Data.Text as T
import Data.Word (Word8)

import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CipherSpec
  , CryptoBackend (..)
  , DigestAlg (..)
  , digestOutLen
  , EngineResult (..)
  , KeyMaterial (..)
  , MacSpec (..)
  )
import Haskoki.Engine.Driver.Cipher (cipherCtor)
import Haskoki.Engine.Driver.Common (rsaDigest, xorB)
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Derive (maxDerivedTotal, maxXofTotal)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.EncryptData
  ( EncryptDataRecipe (..)
  , decodeEncryptDataParams
  , encryptDataKeyLenValid
  , encryptDataParamsValid
  , encryptDataRecipeFor
  )
import Haskoki.Recipe.Kdf
  ( KdfRecipe (..)
  , decodePbkd2Params
  , kdfCodeDigest
  , kdfParamsValid
  , kdfRecipeFor
  , kdfXofStem
  )
import Haskoki.Registry (MechanismId (..))


-- | Decoded PBKD2 parameters: the PRF digest, the iteration count,
-- and the salt.
data Pbkd2Params = Pbkd2Params
  { ppPrf :: !DigestAlg
  , ppIters :: !Int
  , ppSalt :: !ByteString
  } deriving (Eq, Show)

-- | KDF dispatch, SHA rows: covered mechanisms to digests (pinned
-- pinned against 'Haskoki.Recipe.Kdf' by RecipeKdfSpec). 'Nothing'
-- means uncovered (non-SHA-KD mechanism, PBKD2 included).
kdfShaFor :: MechanismId -> Maybe DigestAlg
kdfShaFor mech = do
  r <- kdfRecipeFor mech
  guard (not (rkPbkd2 r))
  stem <- rkDigestStem r
  rsaDigest stem

-- | SHAKE-KD dispatch: covered XOF mechanisms to the backend
-- digest algorithm (pinned against 'kdfXofStem' by
-- RecipeKdfSpec). The output length rides the 'FxDerive' total.
kdfXofFor :: MechanismId -> Maybe DigestAlg
kdfXofFor mech = do
  r <- kdfRecipeFor mech
  stem <- kdfXofStem r
  case stem of
    "SHAKE_128" -> Just D_SHAKE128
    "SHAKE_256" -> Just D_SHAKE256
    _ -> Nothing

-- | KDF dispatch, PBKD2: the covered (mechanism, params) pair to
-- decoded parameters (pinned by RecipeKdfSpec). The PRF
-- stem must map to a servable digest. 'Nothing' means uncovered
-- (non-PBKD2 mechanism) or malformed parameters.
pbkd2ParamsFor :: MechanismId -> ByteString -> Maybe Pbkd2Params
pbkd2ParamsFor mech params = do
  r <- kdfRecipeFor mech
  guard (rkPbkd2 r && kdfParamsValid r params)
  (stem, iters, salt, _) <- decodePbkd2Params params
  alg <- rsaDigest stem
  pure (Pbkd2Params alg iters salt)

-- | Encrypt-data dispatch: the covered (mechanism, base-key
-- length, canonical frame) triple to its backend cipher spec plus
-- the split IV and data (empty IV for ECB rows). The row name
-- strips to its cipher row (@CKM_AES_CBC_ENCRYPT_DATA@ onto
-- @CKM_AES_CBC@), so width selection and the Triple-DES collapse
-- reuse 'cipherCtor' (pinned by RecipeEncryptDataSpec).
encryptDataPartsFor :: MechanismId -> Int -> ByteString -> Maybe (CipherSpec, ByteString, ByteString)
encryptDataPartsFor mech keyLen params = do
  r <- encryptDataRecipeFor mech
  guard (encryptDataParamsValid r params)
  guard (encryptDataKeyLenValid r keyLen)
  base <- T.stripSuffix "_ENCRYPT_DATA" (erName r)
  spec <- cipherCtor base keyLen
  (iv, dat) <- decodeEncryptDataParams r params
  pure (spec, iv, dat)

-- | An encrypt-data mechanism regardless of triple validity
-- (drives the derive parameter-refusal branch: rejected triples
-- are 'CryptoFailed', never 'CryptoUnsupported').
isEncryptDataMech :: MechanismId -> Bool
isEncryptDataMech mech = isJust (encryptDataRecipeFor mech)

-- | A fixed-width SHA key-derivation mechanism (drives the
-- parameter-refusal branch; XOF rows answer through
-- 'isKdfXofMech' instead).
isKdfShaMech :: MechanismId -> Bool
isKdfShaMech mech = case kdfRecipeFor mech of
  Just r -> not (rkPbkd2 r) && isNothing (kdfXofStem r)
  Nothing -> False

-- | A SHAKE XOF key-derivation mechanism (drives the
-- parameter-refusal branch).
isKdfXofMech :: MechanismId -> Bool
isKdfXofMech mech = case kdfRecipeFor mech of
  Just r -> isJust (kdfXofStem r)
  Nothing -> False

-- | The PBKD2 mechanism (drives the parameter-refusal branch).
isPbkd2Mech :: MechanismId -> Bool
isPbkd2Mech mech = case kdfRecipeFor mech of
  Just r -> rkPbkd2 r
  Nothing -> False

-- | SHA key-derivation effects: digest the base value,
-- truncate to the planned length (capped by the digest width —
-- the planner caps honestly, so over-width fires only for
-- hand-built effects).
runShaKd :: CryptoBackend b => BackendEnv b -> DigestAlg -> KeyMaterial -> Int -> IO CryptoResult
runShaKd env alg key outLen = case key of
  KeyBytes kb -> case digestOutLen alg of
    Just w
      | outLen >= 1 && outLen <= w -> do
          r <- digestOneShot env alg kb
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk d -> GotBytes (BS.take outLen d)
    _ -> pure (GotCryptoError (CryptoFailed
      "driver: derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))

-- | SHAKE XOF key-derivation effects: XOF output at the planned
-- length (capped by 'maxXofTotal' — the planner caps honestly,
-- so over-ceiling fires only for hand-built effects).
runXofKd :: CryptoBackend b => BackendEnv b -> DigestAlg -> KeyMaterial -> Int -> IO CryptoResult
runXofKd env alg key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxXofTotal -> do
        r <- digestXof env alg kb outLen
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk d -> GotBytes d
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: XOF derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))

-- | Encrypt-data derive: single-shot cipher encryption of the
-- framed data under the base key, truncated to the planned
-- length (the planner caps at the data width; an out-of-range
-- request fails closed here too). Off-geometry triples are
-- 'CryptoFailed'; a non-bytes key is 'CryptoBadKey'.
runEncryptData :: CryptoBackend b => BackendEnv b -> MechanismId -> KeyMaterial -> ByteString -> Int -> IO CryptoResult
runEncryptData env mech key params outLen = case key of
  KeyBytes kb -> case encryptDataPartsFor mech (BS.length kb) params of
    Just (spec, iv, dat)
      | outLen >= 1 && outLen <= BS.length dat -> do
          r <- cipherEncrypt env spec key iv dat
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk d -> GotBytes (BS.take outLen d)
      | otherwise -> pure (GotCryptoError (CryptoFailed
          "driver: derive length out of range"))
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: encrypt-data (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "encrypt-data base key is not byte material"))

-- | PBKDF2 effects: the RFC 8018 iteration over the HMAC PRF,
-- truncated to the planned length (capped by the shared
-- ceiling).
runPbkd2 :: CryptoBackend b => BackendEnv b -> Pbkd2Params -> KeyMaterial -> Int -> IO CryptoResult
runPbkd2 env (Pbkd2Params prf iters salt) key outLen = case key of
  KeyBytes _
    | outLen >= 1 && outLen <= maxDerivedTotal -> do
        r <- pbkdf2 env prf iters salt key outLen
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk dk -> GotBytes (BS.take outLen dk)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: derive length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))

-- | PBKDF2 proper: T_i = F(password, salt, iters, i) with the
-- HMAC PRF, concatenated across ceil(outLen\/hLen) blocks.
pbkdf2 :: CryptoBackend b => BackendEnv b -> DigestAlg -> Int -> ByteString -> KeyMaterial -> Int -> IO (EngineResult ByteString)
pbkdf2 env prf iters salt pwd outLen = case digestOutLen prf of
  Nothing -> pure (EngineFail (BackendBadParam "pbkdf2"
    "PBKDF2 needs a fixed-width PRF"))
  Just h -> do
    let n = (outLen + h - 1) `div` h
    go n 1 []
  where
    go 0 _ acc = pure (EngineOk (BS.concat (reverse acc)))
    go k i acc = do
      b <- fBlock i
      case b of
        EngineFail err -> pure (EngineFail err)
        EngineOk t -> go (k - 1) (i + 1) (t : acc)
    fBlock i = do
      u1 <- prfOf (salt <> word32BE i)
      case u1 of
        EngineFail err -> pure (EngineFail err)
        EngineOk u -> mix (iters - 1) u u
    mix 0 acc _ = pure (EngineOk acc)
    mix k acc prev = do
      u <- prfOf prev
      case u of
        EngineFail err -> pure (EngineFail err)
        EngineOk u' -> mix (k - 1) (acc `xorB` u') u'
    prfOf msg = macSign env (MacHMAC prf Nothing) pwd msg

-- | HKDF effect params (@prf:u8 mode:u8 salt@) onto the
-- backend digest, its hash length, the stage mode, and the salt.
-- The PRF code resolves through 'kdfCodeDigest' and the stem
-- through 'rsaDigest' (unservable HMACs refuse); the mode must
-- select expand (extract-only never reaches the driver — the
-- planner refuses it first).
hkdfParamsFor :: ByteString -> Maybe (DigestAlg, Int, Word8, ByteString)
hkdfParamsFor params = do
  (prf, r0) <- BS.uncons params
  (mode, salt) <- BS.uncons r0
  guard (mode == 0x02 || mode == 0x03)
  stem <- kdfCodeDigest (fromIntegral prf)
  alg <- rsaDigest stem
  hashLen <- digestOutLen alg
  pure (alg, hashLen, mode, salt)

-- | HKDF-Expand (RFC 5869) with the PRF HMAC over the base key
-- bytes: @T(i) = HMAC(prk, T(i-1) || info || i)@, truncated to the
-- requested length. The caller bounds the length at 255 blocks.
hkdfExpand
  :: CryptoBackend b
  => BackendEnv b -> MacSpec -> KeyMaterial -> ByteString -> Int -> IO (EngineResult ByteString)
hkdfExpand env spec prk info outLen = go BS.empty 1 []
  where
    go :: ByteString -> Int -> [ByteString] -> IO (EngineResult ByteString)
    go prev ctr acc
      | BS.length (BS.concat acc) >= outLen =
          pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
      | ctr > 255 = pure (EngineFail
          (BackendBadParam "derive" "HKDF-Expand counter overflow"))
      | otherwise = do
          r <- macSign env spec prk (prev <> info <> BS.singleton (fromIntegral ctr))
          case r of
            EngineFail err -> pure (EngineFail err)
            EngineOk t -> go t (ctr + 1) (t : acc)

-- | HKDF extract-then-expand (RFC 5869) with the PRF HMAC: the
-- base key bytes are the input keying material, an empty salt
-- extracts against HashLen zeros (RFC 5869 section 2.2), and the
-- extract output feeds 'hkdfExpand' over the context string.
hkdfExtractExpand
  :: CryptoBackend b
  => BackendEnv b -> MacSpec -> Int -> ByteString -> ByteString -> ByteString -> Int
  -> IO (EngineResult ByteString)
hkdfExtractExpand env spec hashLen ikm salt info outLen = do
  let saltKey = KeyBytes (if BS.null salt then BS.replicate hashLen 0 else salt)
  r <- macSign env spec saltKey ikm
  case r of
    EngineFail err -> pure (EngineFail err)
    EngineOk prk -> hkdfExpand env spec (KeyBytes prk) info outLen

-- | Four-byte big-endian word (PBKDF2 block index).
word32BE :: Int -> ByteString
word32BE n = BS.pack
  [ fromIntegral ((n `shiftR` 24) .&. 0xff)
  , fromIntegral ((n `shiftR` 16) .&. 0xff)
  , fromIntegral ((n `shiftR` 8) .&. 0xff)
  , fromIntegral (n .&. 0xff)
  ]
