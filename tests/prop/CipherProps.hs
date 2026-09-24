{- | Cipher laws: AES encrypt\/decrypt inverse and HMAC
sign\/verify over generated keys, params, and plaintexts, driven
through the production driver on both backends.
-}
module CipherProps (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Gen (lcgBytes)
import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , EngineResult (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver (runEffect)
import Haskoki.Engine.OpenSSL4 (OpenSSL4)
import Haskoki.Engine.Synthetic (Synthetic)
import Haskoki.Operation
  ( CipherDir (..)
  , CryptoEffect (..)
  , CryptoResult (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Types (ObjectId (..))

aesCbcMech :: MechanismId
aesCbcMech = MechanismId 0x1082

hmacMech :: MechanismId
hmacMech = MechanismId 0x251

keyOid :: ObjectId
keyOid = ObjectId 101

keyResolver :: ByteString -> ObjectId -> Maybe KeyMaterial
keyResolver key oid
  | oid == keyOid = Just (KeyBytes key)
  | otherwise = Nothing

openSynth :: IO (BackendEnv Synthetic)
openSynth = do
  res <- openBackend "0" :: IO (EngineResult (BackendEnv Synthetic))
  case res of
    EngineOk env -> pure env
    EngineFail err -> assertFailure ("synth open: " ++ show err) >> undefined

openOssl :: IO (BackendEnv OpenSSL4)
openOssl = do
  res <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case res of
    EngineOk env -> pure env
    EngineFail err -> assertFailure ("ossl4 open: " ++ show err) >> undefined

withBackends :: (BackendEnv Synthetic -> BackendEnv OpenSSL4 -> IO ()) -> IO ()
withBackends action = do
  synth <- openSynth
  ossl <- openOssl
  action synth ossl
  closeBackend synth
  closeBackend ossl

spec :: Int -> TestTree
spec count =
  testGroup
    "cipher laws"
    [ testCase "aes encrypt/decrypt inverse" (caseAesInverse count)
    , testCase "hmac sign/verify" (caseHmac count)
    ]

expectBytes :: String -> CryptoResult -> IO ByteString
expectBytes label res = case res of
  GotBytes b -> pure b
  other -> assertFailure (label ++ ": wanted bytes, got " ++ show other) >> undefined

expectValid :: String -> CryptoResult -> IO Bool
expectValid label res = case res of
  GotValid b -> pure b
  other -> assertFailure (label ++ ": wanted verdict, got " ++ show other) >> undefined

-- | Valid AES key lengths, cycled by seed (valid by construction).
keyLenFor :: Word64 -> Int
keyLenFor seed = case seed `mod` 3 of
  0 -> 16
  1 -> 24
  _ -> 32

-- | Encrypt then decrypt recovers the plaintext on both backends.
aesInverse
  :: CryptoBackend b => BackendEnv b -> ByteString -> ByteString -> ByteString -> IO ()
aesInverse be key iv pt = do
  ct <-
    runEffect be (keyResolver key)
      (FxCipher DirEncrypt aesCbcMech (Just keyOid) iv pt)
      >>= expectBytes "encrypt"
  pt' <-
    runEffect be (keyResolver key)
      (FxCipher DirDecrypt aesCbcMech (Just keyOid) iv ct)
      >>= expectBytes "decrypt"
  assertEqual "decrypt(encrypt(p)) == p" pt pt'

-- | Generated (key, iv, plaintext): all three key widths, 16-byte
-- IVs, block-aligned plaintexts of 0..4 blocks, plus explicit empty
-- and single-block edges.
caseAesInverse :: Int -> IO ()
caseAesInverse count = withBackends $ \synth ossl ->
  mapM_ (check synth ossl) (edges ++ gens)
  where
    gens :: [(ByteString, ByteString, ByteString)]
    gens =
      [ ( lcgBytes s (keyLenFor s)
        , lcgBytes (s * 2 + 1) 16
        , lcgBytes (s * 4 + 3) (fromIntegral (s `mod` 5) * 16)
        )
      | s <- [1 .. fromIntegral count]
      ]
    edges :: [(ByteString, ByteString, ByteString)]
    edges =
      [ (lcgBytes 7 16, lcgBytes 8 16, BS.empty)
      , (lcgBytes 9 24, lcgBytes 10 16, lcgBytes 11 16)
      , (lcgBytes 12 32, lcgBytes 13 16, BS.empty)
      ]
    check
      :: BackendEnv Synthetic
      -> BackendEnv OpenSSL4
      -> (ByteString, ByteString, ByteString)
      -> IO ()
    check synth ossl (key, iv, pt) = do
      aesInverse synth key iv pt
      aesInverse ossl key iv pt

-- | Flip one byte (total; empty input maps to a fixed nonzero byte).
tamper :: ByteString -> ByteString
tamper bs = case BS.uncons bs of
  Nothing -> BS.singleton 0
  Just (b, rest) -> BS.cons (b + 1) rest

-- | Sign then verify accepts, and a tampered tag rejects, on both
-- backends.
hmacRoundtrip :: CryptoBackend b => BackendEnv b -> ByteString -> ByteString -> IO ()
hmacRoundtrip be key msg = do
  tag <-
    runEffect be (keyResolver key)
      (FxSign hmacMech (Just keyOid) BS.empty msg)
      >>= expectBytes "sign"
  good <-
    runEffect be (keyResolver key)
      (FxVerify hmacMech (Just keyOid) BS.empty msg tag)
      >>= expectValid "verify"
  assertEqual "valid verifies" True good
  bad <-
    runEffect be (keyResolver key)
      (FxVerify hmacMech (Just keyOid) BS.empty msg (tamper tag))
      >>= expectValid "verify tampered"
  assertEqual "tampered rejects" False bad

-- | Generated (key, message): keys 1..64 bytes, messages 0..128
-- bytes cycling, plus an explicit empty-message edge.
caseHmac :: Int -> IO ()
caseHmac count = withBackends $ \synth ossl ->
  mapM_ (check synth ossl) (edges ++ gens)
  where
    gens :: [(ByteString, ByteString)]
    gens =
      [ ( lcgBytes s (fromIntegral (1 + s `mod` 64))
        , lcgBytes (s + 99) (fromIntegral (s `mod` 129))
        )
      | s <- [1 .. fromIntegral count]
      ]
    edges :: [(ByteString, ByteString)]
    edges = [(lcgBytes 7 20, BS.empty)]
    check
      :: BackendEnv Synthetic
      -> BackendEnv OpenSSL4
      -> (ByteString, ByteString)
      -> IO ()
    check synth ossl (key, msg) = do
      hmacRoundtrip synth key msg
      hmacRoundtrip ossl key msg
