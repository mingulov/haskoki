{- | OpenSSL randomness and seed cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Random
  ( caseRandomBytes
  , caseSeedEntropyHonesty
  , caseSeedNoReplay
  , caseSeedRandomMix
  , caseSymKeygen
  ) where

import qualified Data.ByteString as BS
import Data.List (isInfixOf, stripPrefix, tails)
import System.Directory (doesFileExist)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , generateRandomMaxBytes
  , seedRandomMaxBytes
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import OpenSSL.Fixtures

caseSymKeygen :: IO ()
caseSymKeygen = withBackend $ \env -> do
  -- AES lengths land as lone raw bytes; two generations differ
  -- (fresh randomness every call; no KAT is possible).
  (KeyBytes k16, Nothing) <- expectOk "gen aes-16" =<< generateKey env (GenSym "AES" 16)
  assertEqual "aes-16 length" 16 (BS.length k16)
  (KeyBytes k16b, Nothing) <- expectOk "gen aes-16 again" =<< generateKey env (GenSym "AES" 16)
  assertBool "aes-16 fresh" (k16 /= k16b)
  (KeyBytes k24, Nothing) <- expectOk "gen aes-24" =<< generateKey env (GenSym "AES" 24)
  assertEqual "aes-24 length" 24 (BS.length k24)
  (KeyBytes k32, Nothing) <- expectOk "gen aes-32" =<< generateKey env (GenSym "AES" 32)
  assertEqual "aes-32 length" 32 (BS.length k32)
  (KeyBytes kh, Nothing) <- expectOk "gen hotp-20" =<< generateKey env (GenSym "HOTP" 20)
  assertEqual "hotp-20 length" 20 (BS.length kh)
  (KeyBytes kg, Nothing) <- expectOk "gen generic-32" =<< generateKey env (GenSym "GENERIC" 32)
  assertEqual "generic-32 length" 32 (BS.length kg)
  (KeyBytes kd, Nothing) <- expectOk "gen des3-24" =<< generateKey env (GenSym "DES3" 24)
  assertEqual "des3-24 length" 24 (BS.length kd)
  (KeyBytes kd2, Nothing) <- expectOk "gen des3-16" =<< generateKey env (GenSym "DES3" 16)
  assertEqual "des3-16 length" 16 (BS.length kd2)
  (KeyBytes kc, Nothing) <- expectOk "gen chacha20-32" =<< generateKey env (GenSym "ChaCha20" 32)
  assertEqual "chacha20-32 length" 32 (BS.length kc)
  (KeyBytes kc2, Nothing) <- expectOk "gen chacha20-32 again" =<< generateKey env (GenSym "ChaCha20" 32)
  assertBool "chacha20-32 fresh" (kc /= kc2)
  -- Bounds are typed: off-window lengths are bad params, unknown
  -- algorithms are unsupported (never silent bytes).
  expectBadParam "aes-15 refused" =<< generateKey env (GenSym "AES" 15)
  expectBadParam "aes-0 refused" =<< generateKey env (GenSym "AES" 0)
  expectBadParam "des3-15 refused" =<< generateKey env (GenSym "DES3" 15)
  expectBadParam "des3-32 refused" =<< generateKey env (GenSym "DES3" 32)
  expectBadParam "hotp-15 refused" =<< generateKey env (GenSym "HOTP" 15)
  expectBadParam "hotp-65 refused" =<< generateKey env (GenSym "HOTP" 65)
  expectBadParam "generic-0 refused" =<< generateKey env (GenSym "GENERIC" 0)
  expectBadParam "generic-256 refused" =<< generateKey env (GenSym "GENERIC" 256)
  expectBadParam "chacha20-16 refused" =<< generateKey env (GenSym "ChaCha20" 16)
  expectBadParam "chacha20-0 refused" =<< generateKey env (GenSym "ChaCha20" 0)
  -- BLAKE2B-512-HMAC widened to VALUE_LEN sizes (slice 11a).
  (KeyBytes kb2, Nothing) <- expectOk "gen blake2b512-32" =<< generateKey env (GenSym "BLAKE2B-512-HMAC" 32)
  assertEqual "blake2b512-32 length" 32 (BS.length kb2)
  expectBadParam "blake2b512-0 refused" =<< generateKey env (GenSym "BLAKE2B-512-HMAC" 0)
  -- Sweep labels mint with planner-mirrored bounds (slice 11a).
  mapM_ (checkSweepLabel env) sweepLabelBounds
  -- Unknown labels stay unsupported (never silent bytes).
  expectUnsupported "unknown keygen out" =<< generateKey env (GenSym "NOPE-NOT-A-LABEL" 8)
  -- ML-KEM keygen is served (see caseRealMlkemKeygen).

-- | (label, good lengths, bad lengths) for the sweep keygens.
sweepLabelBounds :: [(String, [Int], [Int])]
sweepLabelBounds =
  [ ("DES", [8], [0, 7, 9])
  , ("DES2", [16], [0, 15, 17])
  , ("CDMF", [8], [0, 7, 9])
  , ("IDEA", [16], [0, 15, 17])
  , ("SEED", [16], [0, 15, 17])
  , ("SKIPJACK", [12], [0, 10, 13])
  , ("BATON", [40], [0, 32, 41])
  , ("JUNIPER", [40], [0, 32, 41])
  , ("GOST28147", [32], [0, 16, 33])
  , ("SALSA20", [32], [0, 16, 33])
  , ("POLY1305", [32], [0, 16, 33])
  , ("ARIA", [16, 24, 32], [0, 8, 20, 40])
  , ("CAMELLIA", [16, 24, 32], [0, 8, 20, 40])
  , ("TWOFISH", [16, 24, 32], [0, 8, 20, 40])
  , ("AES-XTS", [32, 64], [0, 16, 48, 65])
  , ("CAST", [1, 4, 8], [0, 9])
  , ("CAST3", [1, 4, 8], [0, 9])
  , ("CAST128", [1, 8, 16], [0, 17])
  , ("RC2", [1, 64, 128], [0, 129])
  , ("RC4", [1, 128, 255], [0, 256])
  , ("RC5", [1, 128, 255], [0, 256])
  , ("BLOWFISH", [4, 32, 56], [0, 3, 57])
  , ("HKDF", [1, 128, 255], [0, 256])
  , ("SHA-1-HMAC", [1, 32, 255], [0, 256])
  , ("SHA224-HMAC", [1, 32, 255], [0, 256])
  , ("SHA256-HMAC", [1, 32, 255], [0, 256])
  , ("SHA384-HMAC", [1, 48, 255], [0, 256])
  , ("SHA512-HMAC", [1, 64, 255], [0, 256])
  , ("SHA512-224-HMAC", [1, 28, 255], [0, 256])
  , ("SHA512-256-HMAC", [1, 32, 255], [0, 256])
  , ("SHA512-T-HMAC", [1, 32, 255], [0, 256])
  , ("SHA3-224-HMAC", [1, 28, 255], [0, 256])
  , ("SHA3-256-HMAC", [1, 32, 255], [0, 256])
  , ("SHA3-384-HMAC", [1, 48, 255], [0, 256])
  , ("SHA3-512-HMAC", [1, 64, 255], [0, 256])
  , ("BLAKE2B-160-HMAC", [1, 20, 255], [0, 256])
  , ("BLAKE2B-256-HMAC", [1, 32, 255], [0, 256])
  , ("BLAKE2B-384-HMAC", [1, 48, 255], [0, 256])
  , ("TLS-PRE-MASTER", [46], [0, 45, 47])
  , ("WTLS-PRE-MASTER", [19, 128, 254], [0, 18, 255])
  ]

checkSweepLabel :: BackendEnv OpenSSL4 -> (String, [Int], [Int]) -> IO ()
checkSweepLabel env (label, good, bad) = do
  mapM_ mint good
  mapM_ refuse bad
  where
    mint n = do
      (KeyBytes ks, Nothing) <- expectOk ("gen " ++ label) =<< generateKey env (GenSym label n)
      assertEqual (label ++ " length") n (BS.length ks)
    refuse n = expectBadParam (label ++ "-" ++ show n ++ " refused")
      =<< generateKey env (GenSym label n)

caseRandomBytes :: IO ()
caseRandomBytes = withBackend $ \env -> do
  -- Fresh DRBG bytes every call; zero length is a bad param; the
  -- 1 MiB window serves exactly; past it refuses (no transparent
  -- chunking: unbounded requests amplify into OOM kills).
  r1 <- expectOk "random 32" =<< randomBytes env 32
  assertEqual "random length" 32 (BS.length r1)
  r2 <- expectOk "random 32 again" =<< randomBytes env 32
  assertBool "random fresh" (r1 /= r2)
  expectBadParam "random 0 refused" =<< randomBytes env 0
  full <- expectOk "random 1MiB" =<< randomBytes env generateRandomMaxBytes
  assertEqual "window length" generateRandomMaxBytes (BS.length full)
  expectBadParam "random 1MiB+1 refused" =<< randomBytes env (generateRandomMaxBytes + 1)

caseSeedRandomMix :: IO ()
caseSeedRandomMix = withBackend $ \env -> do
  -- Seeding mixes additional input (never replacing the DRBG
  -- state); post-seed randomBytes works normally, empty seeds are
  -- a vacuous OK, oversize seeds are refused.
  expectOk "seed ok" =<< seedRandom env "test-seed"
  r <- expectOk "random after seed" =<< randomBytes env 32
  assertEqual "random length" 32 (BS.length r)
  expectOk "empty seed ok" =<< seedRandom env BS.empty
  r2 <- expectOk "random after empty seed" =<< randomBytes env 32
  assertEqual "random length again" 32 (BS.length r2)
  expectBadParam "oversize seed refused"
    =<< seedRandom env (BS.replicate (seedRandomMaxBytes + 1) 0)

caseSeedEntropyHonesty :: IO ()
caseSeedEntropyHonesty = do
  -- The seed path never claims entropy it doesn't have. The
  -- 0.0 estimate lives in ONE named home in the shim, and the
  -- single RAND_add call site passes that name (never a literal,
  -- never RAND_seed). Mirrors the caseShimHygiene read-the-shim
  -- idiom (cwd-tolerant lookup included).
  src <- findShim ["cbits/ossl4_ctx.c", "../cbits/ossl4_ctx.c", "haskoki/cbits/ossl4_ctx.c"]
  assertEqual "single entropy-estimate home" 1
    (count "#define HSK_OSSL4_SEED_ENTROPY_ESTIMATE 0.0" src)
  let calls = filter ("RAND_add(" `isInfixOf`) (lines src)
  assertEqual "single RAND_add call site" 1 (length calls)
  case calls of
    [c] -> assertBool "call site passes the named estimate"
             ("HSK_OSSL4_SEED_ENTROPY_ESTIMATE" `isInfixOf` c)
    _ -> assertFailure ("expected one RAND_add call site, saw " ++ show (length calls))
  assertEqual "no RAND_seed anywhere" 0 (count "RAND_seed" src)
  where
    count needle hay = length (filter (hasPrefix needle) (tails hay))
    hasPrefix needle s = case stripPrefix needle s of
      Just _ -> True
      Nothing -> False
    findShim [] = assertFailure "cbits/ossl4_ctx.c not found from test cwd"
    findShim (p:ps) = do
      exists <- doesFileExist p
      if exists then readFile p else findShim ps

caseSeedNoReplay :: IO ()
caseSeedNoReplay = withBackend $ \env -> do
  -- Scope pin: the OpenSSL seed path mixes (RAND_add) and never
  -- replaces DRBG state, so identical reseeds do NOT replay --
  -- freshness is preserved across them. C-table determinism is
  -- therefore NOT asserted anywhere (the served C path is
  -- OpenSSL-typed end to end: siBackend :: BackendEnv OpenSSL4);
  -- the determinism contract lives in SyntheticSpec
  -- caseSeedRandomReplay.
  expectOk "seed S ok" =<< seedRandom env "scope-S"
  a <- expectOk "bytes after seed" =<< randomBytes env 32
  expectOk "reseed S ok" =<< seedRandom env "scope-S"
  b <- expectOk "bytes after reseed" =<< randomBytes env 32
  assertBool "reseed does not replay" (a /= b)
