{- | Driver block/stream cipher dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Cipher
  ( cipherSpecFor
  , isCipherMech
  , cipherCtor
  , runCipher
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Applicative ((<|>))
import Control.Monad (guard)
import Data.Maybe (isJust)

import Haskoki.Engine.Backend
  ( BackendEnv
  , CipherSpec (..)
  , CryptoBackend (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver.Result (toBytes)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Operation.State (CipherDir (..))
import Haskoki.Recipe.Chacha20
  ( Chacha20Recipe (..)
  , chachaParamsValid
  , chachaRecipeFor
  , decodeChachaStreamParams
  , encodeChachaIv
  )
import Haskoki.Recipe.Cipher
  ( BlockCipherRecipe (..)
  , cipherKeyLenValid
  , cipherParamsValid
  , cipherRecipeFor
  , ctrRecipeFor
  , decodeCtrParams
  , decodeRc2Params
  , rc2Names
  )
import Haskoki.Registry (MechanismId (..), MechanismName)


-- | Cipher dispatch: covered (mechanism, key length, params)
-- triples to backend specs (pinned against
-- 'Haskoki.Recipe.Cipher' by RecipeCipherSpec, so the table and the
-- recipe can never drift silently). The recipe validates the
-- parameters (IV geometry) and the key length; the constructor
-- below selects the width. 'Nothing' means uncovered (non-cipher
-- mechanism) or a rejected triple.
cipherSpecFor :: MechanismId -> Int -> ByteString -> Maybe CipherSpec
cipherSpecFor mech keyLen params =
  blockParts <|> chachaParts
  where
    blockParts = do
      r <- cipherRecipeFor mech
      guard (cipherParamsValid r params)
      guard (cipherKeyLenValid r keyLen)
      -- RC2 carries the effective-bits word in the spec (the FFI
      -- key-bits control needs it); the recipe already validated
      -- the range and the row shape.
      if crName r `elem` rc2Names then rc2Parts r else cipherCtor (crName r) keyLen
    rc2Parts r = do
      (bits, _) <- decodeRc2Params params
      case crName r of
        "CKM_RC2_ECB" -> pure (C_RC2_ECB bits)
        _ -> pure (C_RC2_CBC bits)
    -- The raw ChaCha20 stream row: 256-bit keys only; the recipe
    -- validates the (counter, nonce) image.
    chachaParts = do
      r <- chachaRecipeFor mech
      guard (chachaName r == "CKM_CHACHA20")
      guard (chachaParamsValid r params)
      guard (keyLen == 32)
      pure C_CHACHA20

-- | A cipher mechanism regardless of triple validity (drives the
-- parameter-refusal branch: rejected triples are 'CryptoFailed',
-- never 'CryptoUnsupported').
isCipherMech :: MechanismId -> Bool
isCipherMech mech = isJust (cipherRecipeFor mech) || isChachaStreamMech mech

-- | The raw ChaCha20 stream row regardless of triple validity
-- (same refusal branch as the block ciphers).
isChachaStreamMech :: MechanismId -> Bool
isChachaStreamMech mech = case chachaRecipeFor mech of
  Just r -> chachaName r == "CKM_CHACHA20"
  Nothing -> False

isRc2Mech :: MechanismId -> Bool
isRc2Mech mech = case cipherRecipeFor mech of
  Just r -> crName r `elem` rc2Names
  Nothing -> False

-- | Recipe row + key length onto the backend width. The CBC_PAD
-- rows share the CBC specs (the planner pads before the effect
-- input is fixed); the CTR rows map their three widths (the
-- counter block is split from the parameter image in 'runCipher');
-- Triple-DES widths collapse (the engines expand two-key material
-- to @K1||K2||K1@).
cipherCtor :: MechanismName -> Int -> Maybe CipherSpec
cipherCtor name keyLen
  | name == "CKM_AES_CBC" || name == "CKM_AES_CBC_PAD" = aesCbc keyLen
  | name == "CKM_AES_CTR" = aesCtr keyLen
  | name == "CKM_AES_ECB" = aesEcb keyLen
  | name == "CKM_AES_CTS" = aesCts keyLen
  | name == "CKM_AES_CFB128" = aesCfb128 keyLen
  | name == "CKM_AES_CFB8" = aesCfb8 keyLen
  | name == "CKM_AES_CFB1" = aesCfb1 keyLen
  | name == "CKM_AES_OFB" = aesOfb keyLen
  | name == "CKM_AES_KEY_WRAP" = aesKw keyLen
  | name == "CKM_AES_KEY_WRAP_KWP" = aesKwp keyLen
  | name == "CKM_AES_KEY_WRAP_PAD" = aesKwp keyLen
  -- KW-PKCS7 pads in the pure layer and executes the plain KW
  -- spec (the optional caller IV rides the params, empty means
  -- the default AIV).
  | name == "CKM_AES_KEY_WRAP_PKCS7" = aesKw keyLen
  | name == "CKM_AES_XTS" = aesXts keyLen
  | name == "CKM_DES3_CBC" || name == "CKM_DES3_CBC_PAD" = des3 C_DES3_CBC
  | name == "CKM_DES3_ECB" = des3 C_DES3_ECB
  | name == "CKM_DES_ECB" = des1 C_DES_ECB
  | name == "CKM_DES_CBC" || name == "CKM_DES_CBC_PAD" = des1 C_DES_CBC
  | name == "CKM_DES_OFB64" = des1 C_DES_OFB64
  | name == "CKM_DES_CFB64" = des1 C_DES_CFB64
  | name == "CKM_DES_CFB8" = des1 C_DES_CFB8
  | name == "CKM_CAST128_ECB" = cast128 C_CAST128_ECB
  | name == "CKM_CAST128_CBC" || name == "CKM_CAST128_CBC_PAD" = cast128 C_CAST128_CBC
  | name == "CKM_CAST_ECB" = castN 5 C_CAST_ECB
  | name == "CKM_CAST_CBC" || name == "CKM_CAST_CBC_PAD" = castN 5 C_CAST_CBC
  | name == "CKM_CAST3_ECB" = castN 10 C_CAST3_ECB
  | name == "CKM_CAST3_CBC" || name == "CKM_CAST3_CBC_PAD" = castN 10 C_CAST3_CBC
  | name == "CKM_IDEA_ECB" = idea16 C_IDEA_ECB
  | name == "CKM_IDEA_CBC" || name == "CKM_IDEA_CBC_PAD" = idea16 C_IDEA_CBC
  | name == "CKM_SEED_ECB" = idea16 C_SEED_ECB
  | name == "CKM_SEED_CBC" || name == "CKM_SEED_CBC_PAD" = idea16 C_SEED_CBC
  | name == "CKM_BLOWFISH_CBC" || name == "CKM_BLOWFISH_CBC_PAD" = blowfish C_BLOWFISH_CBC
  | name == "CKM_RC4" = rc4any C_RC4
  | name == "CKM_ARIA_CBC" || name == "CKM_ARIA_CBC_PAD" =
      aria C_ARIA128_CBC C_ARIA192_CBC C_ARIA256_CBC
  | name == "CKM_ARIA_ECB" = aria C_ARIA128_ECB C_ARIA192_ECB C_ARIA256_ECB
  | name == "CKM_CAMELLIA_CBC" || name == "CKM_CAMELLIA_CBC_PAD" =
      aria C_CAMELLIA128_CBC C_CAMELLIA192_CBC C_CAMELLIA256_CBC
  | name == "CKM_CAMELLIA_ECB" =
      aria C_CAMELLIA128_ECB C_CAMELLIA192_ECB C_CAMELLIA256_ECB
  | name == "CKM_CAMELLIA_CTR" = camCtr keyLen
  | otherwise = Nothing
  where
    aesCbc n = case n of
      16 -> Just C_AES128_CBC
      24 -> Just C_AES192_CBC
      32 -> Just C_AES256_CBC
      _ -> Nothing
    aesCtr n = case n of
      16 -> Just C_AES128_CTR
      24 -> Just C_AES192_CTR
      32 -> Just C_AES256_CTR
      _ -> Nothing
    camCtr n = case n of
      16 -> Just C_CAMELLIA128_CTR
      24 -> Just C_CAMELLIA192_CTR
      32 -> Just C_CAMELLIA256_CTR
      _ -> Nothing
    aesEcb n = case n of
      16 -> Just C_AES128_ECB
      24 -> Just C_AES192_ECB
      32 -> Just C_AES256_ECB
      _ -> Nothing
    aesCts n = case n of
      16 -> Just C_AES128_CTS
      24 -> Just C_AES192_CTS
      32 -> Just C_AES256_CTS
      _ -> Nothing
    aesCfb128 n = case n of
      16 -> Just C_AES128_CFB128
      24 -> Just C_AES192_CFB128
      32 -> Just C_AES256_CFB128
      _ -> Nothing
    aesCfb8 n = case n of
      16 -> Just C_AES128_CFB8
      24 -> Just C_AES192_CFB8
      32 -> Just C_AES256_CFB8
      _ -> Nothing
    aesCfb1 n = case n of
      16 -> Just C_AES128_CFB1
      24 -> Just C_AES192_CFB1
      32 -> Just C_AES256_CFB1
      _ -> Nothing
    aesOfb n = case n of
      16 -> Just C_AES128_OFB
      24 -> Just C_AES192_OFB
      32 -> Just C_AES256_OFB
      _ -> Nothing
    aesKw n = case n of
      16 -> Just C_AES128_KW
      24 -> Just C_AES192_KW
      32 -> Just C_AES256_KW
      _ -> Nothing
    -- CKM_AES_KEY_WRAP_PAD takes KWP semantics (the oracle runs no
    -- distinct vectors for it and calls it the "KWP-PAD path").
    aesKwp n = case n of
      16 -> Just C_AES128_KWP
      24 -> Just C_AES192_KWP
      32 -> Just C_AES256_KWP
      _ -> Nothing
    -- XTS keys are double-width (data + tweak halves); there is no
    -- 192 width (the provider has no AES-192-XTS).
    aesXts n = case n of
      32 -> Just C_AES128_XTS
      64 -> Just C_AES256_XTS
      _ -> Nothing
    des3 spec
      | keyLen == 16 || keyLen == 24 = Just spec
      | otherwise = Nothing
    des1 spec
      | keyLen == 8 = Just spec
      | otherwise = Nothing
    cast128 spec
      | keyLen >= 1 && keyLen <= 16 = Just spec
      | otherwise = Nothing
    castN n spec
      | keyLen == n = Just spec
      | otherwise = Nothing
    idea16 spec
      | keyLen == 16 = Just spec
      | otherwise = Nothing
    blowfish spec
      | keyLen >= 4 && keyLen <= 56 = Just spec
      | otherwise = Nothing
    rc4any spec
      | keyLen >= 1 && keyLen <= 255 = Just spec
      | otherwise = Nothing
    aria c128 c192 c256 = case keyLen of
      16 -> Just c128
      24 -> Just c192
      32 -> Just c256
      _ -> Nothing

runCipher :: CryptoBackend b => BackendEnv b -> CipherDir -> MechanismId -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runCipher env dir mech key iv input = case key of
  KeyBytes kb -> case cipherSpecFor mech (BS.length kb) iv of
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: cipher (mechanism, key length, params) rejected by the recipe"))
    -- CTR parameters are the canonical image, not the raw
    -- counter block: split the served 128-bit image (the recipe
    -- already validated it; a mistimed image fails closed).
    -- ChaCha20 parameters split the same way into the backend
    -- (counter, nonce) framing.
    Just spec -> case cipherImage iv of
      Nothing -> pure (GotCryptoError (CryptoFailed
        "driver: cipher parameter image rejected"))
      Just cb -> case dir of
        DirEncrypt -> toBytes <$> cipherEncrypt env spec key cb input
        DirDecrypt -> toBytes <$> cipherDecrypt env spec key cb input
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "block ciphers need raw symmetric key bytes"))
  where
    cipherImage params = case ctrRecipeFor mech of
      Just _ -> case decodeCtrParams params of
        Just (128, cb) -> Just cb
        _ -> Nothing
      Nothing
        | isChachaStreamMech mech -> case decodeChachaStreamParams params of
            Just (counter, nonce) -> Just (encodeChachaIv counter nonce)
            _ -> Nothing
        -- RC2 parameters are the canonical image, not the raw
        -- IV: split off the effective-bits word (the recipe
        -- already validated the range and the row shape; the
        -- spec carries the bits to the FFI control).
        | isRc2Mech mech -> case decodeRc2Params params of
            Just (_, splitIv) -> Just splitIv
            _ -> Nothing
        | otherwise -> Just params
