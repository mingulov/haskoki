{- | Oracle laws: the OpenSSL4 backend agrees byte-for-byte with
the truly independent external @openssl@ CLI over a generated
corpus; ACCEPTANCE KATs stay passing under the oracle runner; and the
synthetic backend agrees with OpenSSL4 structurally (widths,
refusal taxonomy, determinism).

Byte-equality between synthetic and OpenSSL4 is NOT asserted: the
synthetic backend is a labeled test construction
('haskoki-synth\/class-digest\/v1' PRF stem), deliberately not real
crypto.
-}
{-# LANGUAGE OverloadedStrings #-}
module OracleProps (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Data.List (isPrefixOf)
import Data.Word (Word64)
import System.Directory
  ( createDirectory
  , doesDirectoryExist
  , doesFileExist
  , removeDirectoryRecursive
  )
import System.FilePath ((</>))
import System.Process (readProcess)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

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
  , CryptoError (..)
  , CryptoResult (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated (ckm_SHA512)
import Haskoki.Types (ObjectId (..))

-- ---------------------------------------------------------------------------
-- Oracle identity + fixtures
-- ---------------------------------------------------------------------------

-- | The pinned external oracle (brief anchor: OpenSSL 4.x at
-- /opt/openssl-4.0.2).
cliPath :: FilePath
cliPath = "/opt/openssl-4.0.2/bin/openssl"

cliWorkDir :: FilePath
cliWorkDir = "/tmp/oracle-corpus"

sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

sha512Mech :: MechanismId
sha512Mech = MechanismId (ckm_SHA512)

hmacMech :: MechanismId
hmacMech = MechanismId 0x251

aesCbcMech :: MechanismId
aesCbcMech = MechanismId 0x1082

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

-- | ACCEPTANCE vectors, copied from RoutingE2ESpec (cited, not
-- re-derived): FIPS 180-4 SHA-256("abc"), RFC 4231 HMAC case 1,
-- SP 800-38A F.2.5 AES-256-CBC.
hex :: String -> ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) =
      fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

sha256Abc :: ByteString
sha256Abc = hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

hmacKey1 :: ByteString
hmacKey1 = BS.replicate 20 0x0b

hmacMsg1 :: ByteString
hmacMsg1 = "Hi There"

hmacOut1 :: ByteString
hmacOut1 = hex "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

aes256Key :: ByteString
aes256Key = hex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

aes256Iv :: ByteString
aes256Iv = hex "000102030405060708090a0b0c0d0e0f"

aes256Pt :: ByteString
aes256Pt = hex "6bc1bee22e409f96e93d7e117393172a"

aes256Ct :: ByteString
aes256Ct = hex "f58c4c04d6e5f1ba779eabfb5f7bfbd6"

spec :: Int -> TestTree
spec count =
  testGroup
    "oracle laws"
    [ testCase "oracle identity" caseIdentity
    , testCase "ossl4 agrees with CLI" (caseCliDigest count)
    , testCase "KAT pins under new runner" caseKat
    , testCase "synth structural agreement" (caseStructural count)
    ]

expectBytes :: String -> CryptoResult -> IO ByteString
expectBytes label res = case res of
  GotBytes b -> pure b
  other -> assertFailure (label ++ ": wanted bytes, got " ++ show other) >> undefined

-- ---------------------------------------------------------------------------
-- Oracle identity
-- ---------------------------------------------------------------------------

-- | The external oracle is the pinned OpenSSL 4.0.2 binary.
caseIdentity :: IO ()
caseIdentity = do
  exists <- doesFileExist cliPath
  assertBool ("oracle binary present: " ++ cliPath) exists
  out <- readProcess cliPath ["version"] ""
  assertBool ("oracle version 4.0.2, got: " ++ out)
    ("OpenSSL 4.0.2" `isPrefixOf` out)

-- ---------------------------------------------------------------------------
-- Backend <-> CLI digest agreement
-- ---------------------------------------------------------------------------

-- | Total hex decoder.
unhex :: String -> Maybe ByteString
unhex s = BS.pack <$> go (filter isHexDigit s)
  where
    go [] = Just []
    go (a : b : rest) =
      (fromIntegral (digitToInt a * 16 + digitToInt b) :) <$> go rest
    go [_] = Nothing

-- | Parse one @ALG(file)= hex@ line.
parseDgst :: String -> Maybe (FilePath, ByteString)
parseDgst line = case break (== '=') line of
  (lhs, '=' : ' ' : hexpart) -> do
    bs <- unhex hexpart
    pure (extractFile lhs, bs)
  _ -> Nothing
  where
    extractFile :: String -> FilePath
    extractFile lhs = case break (== '(') lhs of
      (_, '(' : rest) -> takeWhile (/= ')') rest
      _ -> lhs

pad4 :: Int -> String
pad4 i = let s = show i in replicate (4 - length s) '0' ++ s

-- | Generated corpus inputs (sizes 0..128 cycling) plus explicit
-- empty and "abc" edges.
corpusInputs :: Int -> [(FilePath, ByteString)]
corpusInputs count =
  edgeInputs ++ genInputs
  where
    genInputs =
      [ ("input-" ++ pad4 (fromIntegral s) ++ ".bin",
         lcgBytes s (fromIntegral (s `mod` 129)))
      | s <- [1 .. fromIntegral count]
      ]
    edgeInputs =
      [("input-edge-empty.bin", BS.empty), ("input-edge-abc.bin", "abc")]

-- | Run the CLI once over files, returning parsed (file, digest)
-- pairs in output order.
runCliDgst :: String -> [FilePath] -> IO [(FilePath, ByteString)]
runCliDgst alg files = do
  out <- readProcess cliPath (["dgst", "-" ++ alg] ++ files) ""
  case mapM parseDgst (lines out) of
    Nothing -> assertFailure ("CLI parse failed: " ++ out) >> undefined
    Just pairs -> pure pairs

-- | The OpenSSL4 backend agrees byte-for-byte with the external CLI
-- over the whole generated corpus, at two widths.
caseCliDigest :: Int -> IO ()
caseCliDigest count = do
  exists <- doesFileExist cliPath
  assertBool ("oracle binary present: " ++ cliPath) exists
  ossl <- openOssl
  let inputs = corpusInputs count
  haveDir <- doesDirectoryExist cliWorkDir
  if haveDir then removeDirectoryRecursive cliWorkDir else pure ()
  createDirectory cliWorkDir
  let files = [cliWorkDir </> name | (name, _) <- inputs]
  mapM_ (\(name, bs) -> BS.writeFile (cliWorkDir </> name) bs) inputs
  checkAlg ossl inputs files sha256Mech "sha256" 32
  checkAlg ossl inputs files sha512Mech "sha512" 64
  closeBackend ossl
  where
    checkAlg
      :: BackendEnv OpenSSL4
      -> [(FilePath, ByteString)]
      -> [FilePath]
      -> MechanismId
      -> String
      -> Int
      -> IO ()
    checkAlg be inputs files mech alg width = do
      pairs <- runCliDgst alg files
      assertEqual "CLI answers every file" (length files) (length pairs)
      mapM_ checkPair (zip inputs pairs)
      where
        checkPair
          :: ((FilePath, ByteString), (FilePath, ByteString))
          -> IO ()
        checkPair ((name, input), (gotFile, cliBytes)) = do
          assertEqual "CLI echoes the file" (cliWorkDir </> name) gotFile
          assertEqual ("CLI width " ++ alg) width (BS.length cliBytes)
          beBytes <-
            runEffect be (keyResolver BS.empty)
              (FxDigest mech input)
              >>= expectBytes ("backend " ++ alg)
          assertEqual ("backend == CLI " ++ alg ++ " " ++ name) cliBytes beBytes

-- ---------------------------------------------------------------------------
-- KAT pins under the new runner
-- ---------------------------------------------------------------------------

caseKat :: IO ()
caseKat = do
  ossl <- openOssl
  sha <-
    runEffect ossl (keyResolver BS.empty) (FxDigest sha256Mech "abc")
      >>= expectBytes "sha256 abc"
  assertEqual "FIPS 180-4 digest of abc" sha256Abc sha
  tag <-
    runEffect ossl (keyResolver hmacKey1)
      (FxSign hmacMech (Just keyOid) BS.empty hmacMsg1)
      >>= expectBytes "hmac sign"
  assertEqual "RFC 4231 case 1" hmacOut1 tag
  verdict <-
    runEffect ossl (keyResolver hmacKey1)
      (FxVerify hmacMech (Just keyOid) BS.empty hmacMsg1 tag)
  case verdict of
    GotValid True -> pure ()
    other -> assertFailure ("hmac verify: " ++ show other)
  ct <-
    runEffect ossl (keyResolver aes256Key)
      (FxCipher DirEncrypt aesCbcMech (Just keyOid) aes256Iv aes256Pt)
      >>= expectBytes "aes encrypt"
  assertEqual "SP 800-38A F.2.5" aes256Ct ct
  pt <-
    runEffect ossl (keyResolver aes256Key)
      (FxCipher DirDecrypt aesCbcMech (Just keyOid) aes256Iv ct)
      >>= expectBytes "aes decrypt"
  assertEqual "decrypt recovers" aes256Pt pt
  closeBackend ossl

-- ---------------------------------------------------------------------------
-- Synthetic structural agreement (NOT byte-equality)
-- ---------------------------------------------------------------------------

-- | Widths, refusal taxonomy, and synthetic determinism agree; byte
-- content deliberately does not (synthetic is a test construction).
caseStructural :: Int -> IO ()
caseStructural count = do
  synth <- openSynth
  ossl <- openOssl
  mapM_ (checkDigest synth ossl) [1 .. fromIntegral count]
  checkDigest synth ossl 100001
  mapM_ (checkCipherLen synth ossl) [1 .. fromIntegral count]
  checkRefusal synth
  checkRefusal ossl
  checkDeterminism synth
  closeBackend synth
  closeBackend ossl
  where
    checkDigest
      :: BackendEnv Synthetic -> BackendEnv OpenSSL4 -> Word64 -> IO ()
    checkDigest synth ossl seed = do
      let input = lcgBytes seed (fromIntegral (seed `mod` 65))
      s256 <-
        runEffect synth (keyResolver BS.empty) (FxDigest sha256Mech input)
          >>= expectBytes "synth sha256"
      o256 <-
        runEffect ossl (keyResolver BS.empty) (FxDigest sha256Mech input)
          >>= expectBytes "ossl4 sha256"
      assertEqual "sha256 width synth" 32 (BS.length s256)
      assertEqual "sha256 width ossl4" 32 (BS.length o256)
      s512 <-
        runEffect synth (keyResolver BS.empty) (FxDigest sha512Mech input)
          >>= expectBytes "synth sha512"
      o512 <-
        runEffect ossl (keyResolver BS.empty) (FxDigest sha512Mech input)
          >>= expectBytes "ossl4 sha512"
      assertEqual "sha512 width synth" 64 (BS.length s512)
      assertEqual "sha512 width ossl4" 64 (BS.length o512)
    checkCipherLen
      :: BackendEnv Synthetic -> BackendEnv OpenSSL4 -> Word64 -> IO ()
    checkCipherLen synth ossl seed = do
      let key = lcgBytes seed 32
          iv = lcgBytes (seed + 1) 16
          pt = lcgBytes (seed + 2) (fromIntegral (seed `mod` 5) * 16)
      sct <-
        runEffect synth (keyResolver key)
          (FxCipher DirEncrypt aesCbcMech (Just keyOid) iv pt)
          >>= expectBytes "synth encrypt"
      oct <-
        runEffect ossl (keyResolver key)
          (FxCipher DirEncrypt aesCbcMech (Just keyOid) iv pt)
          >>= expectBytes "ossl4 encrypt"
      assertEqual "synth length-preserving" (BS.length pt) (BS.length sct)
      assertEqual "ossl4 length-preserving" (BS.length pt) (BS.length oct)
    checkRefusal :: CryptoBackend b => BackendEnv b -> IO ()
    checkRefusal be = do
      res <- runEffect be (keyResolver BS.empty)
        (FxDigest (MechanismId 0x9999) "x")
      case res of
        GotCryptoError (CryptoUnsupported _ _) -> pure ()
        other -> assertFailure ("refusal: wanted Unsupported, got " ++ show other)
    checkDeterminism :: BackendEnv Synthetic -> IO ()
    checkDeterminism synth = do
      a <-
        runEffect synth (keyResolver BS.empty) (FxDigest sha256Mech "abc")
          >>= expectBytes "synth first"
      b <-
        runEffect synth (keyResolver BS.empty) (FxDigest sha256Mech "abc")
          >>= expectBytes "synth second"
      assertEqual "synthetic deterministic" a b
