{- | Driver CMAC dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Cmac
  ( cmacSpecFor
  , isCmacMech
  , runCmacSign
  , runCmacVerify
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Bits ((.&.), (.|.), shiftL, xor)
import Data.List (unsnoc)
import Data.Maybe (isJust)
import Data.Word (Word8)

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
import Haskoki.Recipe.Cmac
  ( CmacRecipe (..)
  , cmacBlockLen
  , cmacRecipeFor
  )
import Haskoki.Recipe.Hmac (decodeMacGeneral)
import Haskoki.Registry (MechanismId (..))


-- | CMAC dispatch: covered (mechanism, params, key length) triples
-- to the backend ECB cipher spec plus the GENERAL truncation (pinned
-- against 'Haskoki.Recipe.Cmac' by RecipeCmacSpec).
-- The cipher binds by key length (AES-128\/192\/256 for the AES
-- rows, 3DES for the DES3 rows); GENERAL rows thread the decoded
-- tag length, capped at the cipher block. 'Nothing' means uncovered
-- (non-CMAC mechanism), malformed parameters, or an off-geometry
-- key length.
cmacSpecFor :: MechanismId -> ByteString -> Int -> Maybe (CipherSpec, Maybe Int)
cmacSpecFor mech params keyLen = do
  r <- cmacRecipeFor mech
  spec <- cmacCipher r keyLen
  if rcGeneral r
    then do
      n <- decodeMacGeneral params
      guard (n >= 1 && n <= cmacBlockLen r)
      pure (spec, Just n)
    else do
      guard (BS.null params)
      pure (spec, Nothing)
  where
    cmacCipher r n
      | rcDes3 r, n == 16 || n == 24 = Just C_DES3_ECB
      | rcDes3 r = Nothing
      | n == 16 = Just C_AES128_ECB
      | n == 24 = Just C_AES192_ECB
      | n == 32 = Just C_AES256_ECB
      | otherwise = Nothing

-- | A CMAC mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed CMAC params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isCmacMech :: MechanismId -> Bool
isCmacMech mech = isJust (cmacRecipeFor mech)

-- | CMAC sign effects: the SP 800-38B composition over the
-- backend ECB route, truncated for GENERAL rows. Off-geometry
-- (mechanism, key length, params) triples are 'CryptoFailed';
-- a non-bytes key is 'CryptoBadKey'.
runCmacSign :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> IO CryptoResult
runCmacSign env mech params key input = case key of
  KeyBytes kb -> case cmacSpecFor mech params (BS.length kb) of
    Just (spec, trunc) -> do
      r <- cmacTag env spec key input
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk tag -> GotBytes (maybe tag (`BS.take` tag) trunc)
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: CMAC (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "CMAC needs raw symmetric key bytes"))

-- | CMAC verify effects: recompute, truncate, constant-time
-- compare. A mismatch is the 'False' verdict, never a
-- malfunction.
runCmacVerify :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runCmacVerify env mech params key input tag = case key of
  KeyBytes kb -> case cmacSpecFor mech params (BS.length kb) of
    Just (spec, trunc) -> do
      r <- cmacTag env spec key input
      pure $ case r of
        EngineFail err -> GotCryptoError (toCryptoError err)
        EngineOk full
          | driverCtEq want tag -> GotValid True
          | otherwise -> GotValid False
          where want = maybe full (`BS.take` full) trunc
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: CMAC (mechanism, key length, params) rejected by the recipe"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "CMAC needs raw symmetric key bytes"))

-- | The SP 800-38B tag: subkey doubling (Rb 0x87 for 128-bit
-- blocks, 0x1B for 64-bit), last-block padding (10*) when
-- short, CBC-MAC chaining over single-block ECB calls. Full
-- width; truncation is the caller's call.
cmacTag :: CryptoBackend b => BackendEnv b -> CipherSpec -> KeyMaterial -> ByteString -> IO (EngineResult ByteString)
cmacTag env spec key input = case (cmacBlockOf spec, cmacRbOf spec) of
  (Just blk, Just rb) -> do
    lz <- enc (BS.replicate blk 0)
    case lz of
      EngineFail err -> pure (EngineFail err)
      EngineOk lb -> do
        let k1 = gfDouble rb lb
            k2 = gfDouble rb k1
            blks = chunksOf blk input
            (front, lastM) = case unsnoc blks of
              Nothing -> ([], padBlock blk BS.empty `xorB` k2)
              Just (pre, lst)
                | BS.length lst == blk -> (pre, lst `xorB` k1)
                | otherwise -> (pre, padBlock blk lst `xorB` k2)
        chain (BS.replicate blk 0) (front ++ [lastM])
  _ -> pure (EngineFail (BackendBadParam "cmac"
    "CMAC needs an AES or 3DES ECB cipher spec"))
  where
    enc b = cipherEncrypt env spec key BS.empty b
    chain x [] = pure (EngineOk x)
    chain x (m : ms) = do
      e <- enc (x `xorB` m)
      case e of
        EngineFail err -> pure (EngineFail err)
        EngineOk x' -> chain x' ms

-- | CMAC block width per cipher (only the ECB specs 'cmacSpecFor'
-- yields).
cmacBlockOf :: CipherSpec -> Maybe Int
cmacBlockOf spec = case spec of
  C_AES128_ECB -> Just 16
  C_AES192_ECB -> Just 16
  C_AES256_ECB -> Just 16
  C_DES3_ECB -> Just 8
  _ -> Nothing

-- | CMAC reduction constant per cipher (SP 800-38B: 0x87 for
-- 128-bit blocks, 0x1B for 64-bit).
cmacRbOf :: CipherSpec -> Maybe Word8
cmacRbOf spec = case spec of
  C_DES3_ECB -> Just 0x1b
  C_AES128_ECB -> Just 0x87
  C_AES192_ECB -> Just 0x87
  C_AES256_ECB -> Just 0x87
  _ -> Nothing

-- | GF(2^n) doubling: left shift by one bit, conditional xor of Rb
-- into the low byte.
gfDouble :: Word8 -> ByteString -> ByteString
gfDouble rb w =
  let bytes = BS.unpack w
      msb = case bytes of
        (b : _) -> b .&. 0x80 /= 0
        [] -> False
      shifted = snd (foldr sh (0, []) bytes)
      sh b (carry, acc) =
        ((if b .&. 0x80 /= 0 then 1 else 0), ((b `shiftL` 1) .|. carry) : acc)
      mask = replicate (length bytes - 1) 0 ++ [if msb then rb else 0]
  in BS.pack (zipWith xor shifted mask)
