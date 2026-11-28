{- | OpenSSL shared fixtures.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Fixtures
  ( aes128Key
  , aes256Iv
  , aes256Pt
  , ecBp160Priv
  , ecMsg
  , ecPrivDer
  , ecPubDer
  , ecSigDer
  , ecSigRaw
  , expectAuthFailed
  , expectBadKey
  , expectBadParam
  , expectOk
  , expectSigLenRange
  , expectUnsupported
  , hex
  , hmacKey1
  , hmacMsg1
  , mkEc
  , mkKem
  , sha256Abc
  , tamperLast
  , withBackend
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Test.Tasty.HUnit (assertFailure)
import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CryptoBackend (..)
  , EcSpec (..)
  , EngineResult (..)
  , KemSpec (..)
  , PqcKemAlg (..)
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))

-- | Decode a hex string (whitespace-tolerant).
hex :: String -> ByteString
hex s =
  let h = filter isHexDigit s
  in BS.pack (go h)
  where
    go [] = []
    go (a:b:rest) =
      fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

withBackend :: (BackendEnv OpenSSL4 -> IO ()) -> IO ()
withBackend action = do
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk env -> action env >> closeBackend env

expectOk :: (Eq a, Show a) => String -> EngineResult a -> IO a
expectOk label r = case r of
  EngineOk a -> pure a
  EngineFail err -> assertFailure (label ++ ": expected EngineOk, got " ++ show err)

expectUnsupported :: Show a => String -> EngineResult a -> IO ()
expectUnsupported label r = case r of
  EngineFail (BackendUnsupported _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendUnsupported, got " ++ show other)

expectAuthFailed :: Show a => String -> EngineResult a -> IO ()
expectAuthFailed label r = case r of
  EngineFail (BackendAuthFailed _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendAuthFailed, got " ++ show other)

expectSigLenRange :: Show a => String -> EngineResult a -> IO ()
expectSigLenRange label r = case r of
  EngineFail (BackendSigLenRange _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendSigLenRange, got " ++ show other)

expectBadParam :: Show a => String -> EngineResult a -> IO ()
expectBadParam label r = case r of
  EngineFail (BackendBadParam _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendBadParam, got " ++ show other)

expectBadKey :: Show a => String -> EngineResult a -> IO ()
expectBadKey label r = case r of
  EngineFail (BackendBadKey _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendBadKey, got " ++ show other)

-- FIPS 180-4 §B.1 / §B.2.
sha256Abc :: ByteString
sha256Abc = hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

-- RFC 4231 test case 1: key = 0x0b * 20, data = "Hi There".
hmacKey1 :: ByteString
hmacKey1 = BS.replicate 20 0x0b

hmacMsg1 :: ByteString
hmacMsg1 = "Hi There"

aes256Iv :: ByteString
aes256Iv = hex "000102030405060708090a0b0c0d0e0f"

aes256Pt :: ByteString
aes256Pt = hex "6bc1bee22e409f96e93d7e117393172a"

-- NIST SP 800-38A F.1/F.2 AES rows (128/192 CBC+ECB, 256
-- ECB; 256 CBC is caseAesKat). Generated on the OpenSSL 4.0.2 CLI,
-- cross-checked byte-identical on the system 3.5.5 CLI.
aes128Key :: ByteString
aes128Key = hex "2b7e151628aed2a6abf7158809cf4f3c"

-- ECDSA P-256/SHA-256 fixed vector (system openssl CLI 3.5.5, Verified OK
-- there before embedding; independent of this backend).
ecMsg :: ByteString
ecMsg = hex "543037206563647361206b6174206d657373616765"

ecPrivDer :: ByteString
ecPrivDer = hex "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e9032e4f06ee6b5397252cfb48e73a8d3f7717d4024dd4cc5b98bbf041c11bb3a14403420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"

ecPubDer :: ByteString
ecPubDer = hex "3059301306072a8648ce3d020106082a8648ce3d03010703420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"

ecSigDer :: ByteString
ecSigDer = hex "3045022100debdbb00072c928d38bf43791d32f0eefe8a562d8444869adabdf77820cbed49022063cc0a678a74c3e006c7387907210825f12920ff5f15b96709291e48b84ddc21"

ecSigRaw :: ByteString
ecSigRaw = hex "debdbb00072c928d38bf43791d32f0eefe8a562d8444869adabdf77820cbed4963cc0a678a74c3e006c7387907210825f12920ff5f15b96709291e48b84ddc21"

mkEc :: String -> String -> EcSpec
mkEc curve enc = EcSpec { ecCurve = curve, ecEncoding = enc }

mkKem :: PqcKemAlg -> KemSpec
mkKem a = KemSpec { kemAlg = a }

-- | Change the last byte (always differs: +1 wraps on Word8). Replacing it
-- with a fixed byte is a no-op when a randomized value already ends in it.
tamperLast :: ByteString -> ByteString
tamperLast bs = BS.init bs <> BS.singleton (BS.last bs + 1)

-- | Off-set-curve fixtures: a well-formed brainpoolP160r1 key
-- pair (CLI genpkey; curve OID @1.3.36.3.3.2.8.1.1.1@ — real but
-- uncollected, so outside the covered set). The real backend must
-- refuse these with 'BackendBadKey' — never execute past the
-- advertised cap set.
ecBp160Priv :: ByteString
ecBp160Priv = hex $ concat
  [ "305402010104148b826497e301a31d83e16a10c7ba9070fd6e5bf6a00b0609"
  , "2b2403030208010101a12c032a0004e471b91d45036f84037b7e2c3804348be"
  , "1455d93662b6814bfeb22a8acb58b5ae6f583f2a0de1081"
  ]
