{- | Synthetic backend tests (A2 convergence).

The synthetic test double through the
'CryptoBackend' class interface (not the old record): fixed digest
bytes for a fixed input, explicit open seeds, the capability report,
the not-yet-migrated surface answering Unsupported, and guard order
on a closed backend.
-}
{-# LANGUAGE OverloadedStrings #-}
module SyntheticSpec (spec) where

import Data.Bits (complement)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.Set as Set
import qualified Data.Text as T
import Numeric (showHex)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Der (coveredCurveNames)
import Haskoki.Engine.Backend
  ( AeadSpec (..)
  , BackendCaps (..)
  , BackendEnv
  , BackendError (..)
  , CipherCaps (..)
  , CipherSpec (..)
  , cipherIvLen
  , cipherKeyLens
  , CryptoBackend (..)
  , DigestAlg (..)
  , DigestCaps (..)
  , EcdhSpec (..)
  , EcSpec (..)
  , EngineResult (..)
  , KdfCaps (..)
  , KemCaps (..)
  , KemSpec (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , KeyRef (..)
  , MacCaps (..)
  , MacSpec (..)
  , OaepParams (..)
  , PqcKemAlg (..)
  , PssParams (..)
  , RsaCipherParams (..)
  , PqcSigAlg (..)
  , SigCaps (..)
  , SigSpec (..)
  , slhdsaSets
  , generateRandomMaxBytes
  , seedRandomMaxBytes
  )
import Haskoki.Engine.Driver (encodeResult, runEffect)
import Haskoki.Engine.Synthetic
  ( FixtureMaterial (..)
  , OpNumber (..)
  , Seed (..)
  , Synthetic (..)
  , deriveStream
  , fixtureKey
  , fixtureKeyPair
  , nextBytes
  , synthDigestLength
  , synthEcdhWidth
  , synthKeyContextVersion
  , synthMacLength
  , synthSigLength
  )
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoError (..), CryptoResult (..), cryptoCode)
import Haskoki.Operation.KeyManagement
  (GenArgs (..), decodeKeyPair, encodeGenArgs, hotpKeyGenMech)
import Haskoki.Operation.State (CipherDir (..))
import qualified Haskoki.Outcome as O
import Haskoki.Recipe.Hmac (encodeMacGeneral)
import Haskoki.Recipe.Kdf (encodePbkd2Params)
import Haskoki.Recipe.TlsPrf (encodeTlsPrfParams)
import Haskoki.Recipe.Otp (encodeHotpParams)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Types (EngineResourceId (..), ObjectId (..), ReturnCode (..))

spec :: TestTree
spec = testGroup "synthetic engine"
  [ testCase "digest fixed bytes through class" caseDigestClass
  , testCase "open seeds and capability report" caseOpenCaps
  , testCase "not-yet-migrated surface answers Unsupported" caseUnsupportedRest
  , testCase "closed backend keeps guard order" caseClosedGuards
  , testCase "multipart digest equals one-shot" caseDigestMultipart
  , testCase "Streamed equals one-shot, all algorithms" caseDigestStreamAll
  , testCase "digest snapshots are versioned and restorable" caseDigestSnapshot
  , testCase "mac roundtrip and tamper detection" caseMac
  , testCase "signatures verify by key identity" caseSign
  , testCase "cipher reversible with explicit length" caseCipher
  , testCase "keygen deterministic on seed and sequence" caseKeygen
  , testCase "key registry lifecycle" caseRegistry
  , testCase "pairs verify across, key snapshots versioned" casePairs
  , testCase "rng streams: same seed plus schedule" caseRng
  , testCase "fixture identities pinned" caseFixtures
  , testCase "capability report is exactly the synthetic set" caseCapsFull
  , testCase "driver bridge answers over synthetic" caseDriverBridge
  , testCase "Verify backend failure keeps its category" caseVerifyCategory
  , testCase "Verify category fix stays general-error" caseVerifyNeutral
  , testCase "KEM generation and encaps roundtrip" caseKemRoundtrip
  , testCase "Digest widths per algorithm" caseDigestWidths
  , testCase "Multipart final honors the init alg" caseMultipartAlg
  , testCase "Digest snapshot roundtrips the alg" caseSnapshotAlg
  , testCase "HMAC widths per algorithm" caseHmacWidths
  , testCase "HMAC truncation honored and bounded" caseHmacTrunc
  , testCase "Block-cipher specs roundtrip per geometry" caseCipherSpecs
  , testCase "RSA v1.5 specs roundtrip per digest" caseRsaRoundtrip
  , testCase "RSA-PSS specs roundtrip per salt" casePssRoundtrip
  , testCase "RSA-OAEP envelopes bind params" caseOaepRoundtrip
  , testCase "RSA PKCS#1 v1.5 envelopes roundtrip, never cross-open" casePkcs1Roundtrip
  , testCase "synthetic AEAD seals deterministically" caseAeadRoundtrip
  , testCase "synthetic CCM seals deterministically" caseAeadCcmRoundtrip
  , testCase "ECDSA curves and digests roundtrip" caseEcdsaCurves
  , testCase "DSA digests and raw roundtrip" caseDsaRoundtrip
  , testCase "EdDSA curves roundtrip" caseEddsaRoundtrip
  , testCase "ML-DSA levels roundtrip" caseMldsaRoundtrip
  , testCase "SLH-DSA sets roundtrip" caseSlhdsaRoundtrip
  , testCase "ECDH agreements separate and replay" caseEcdh
  , testCase "CMAC tags separate and truncate" caseCmac
  , testCase "3DES-MAC tags separate and truncate" caseDes3mac
  , testCase "KDF output separates and truncates" caseKdf
  , testCase "TLS-PRF output separates and truncates" caseTlsPrf
  , testCase "HOTP codes separate, keygen lengths" caseHotp
  , testCase "Specials refuse explicitly" caseSpecialsRefuse
  , testCase "Random bytes deterministic on seed" caseRandomBytes
  , testCase "seedRandom replays and re-origins" caseSeedRandomReplay
  , testCase "seedRandom bounds: vacuous empty, 1 MiB cap" caseSeedRandomBounds
  ]

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

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

withSynth :: String -> (BackendEnv Synthetic -> IO ()) -> IO ()
withSynth seed action = do
  r <- openBackend seed :: IO (EngineResult (BackendEnv Synthetic))
  case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk env -> action env >> closeBackend env

expectOk :: Show a => String -> EngineResult a -> IO a
expectOk label r = case r of
  EngineOk a -> pure a
  EngineFail err -> assertFailure (label ++ ": expected EngineOk, got " ++ show err)

expectBytes :: CryptoResult -> IO ByteString
expectBytes (GotBytes b) = pure b
expectBytes other = assertFailure ("expected bytes, got " ++ show other)

expectUnsupported :: String -> EngineResult a -> IO ()
expectUnsupported label r = case r of
  EngineFail (BackendUnsupported _ _) -> pure ()
  EngineFail e -> assertFailure (label ++ ": expected BackendUnsupported, got " ++ show e)
  EngineOk _ -> assertFailure (label ++ ": expected BackendUnsupported, got EngineOk")

expectBadParam :: String -> EngineResult a -> IO ()
expectBadParam label r = case r of
  EngineFail (BackendBadParam _ _) -> pure ()
  EngineFail e -> assertFailure (label ++ ": expected BackendBadParam, got " ++ show e)
  EngineOk _ -> assertFailure (label ++ ": expected BackendBadParam, got EngineOk")

expectResourceGone :: String -> EngineResult a -> IO ()
expectResourceGone label r = case r of
  EngineFail (BackendResourceGone _ _) -> pure ()
  EngineFail e -> assertFailure (label ++ ": expected BackendResourceGone, got " ++ show e)
  EngineOk _ -> assertFailure (label ++ ": expected BackendResourceGone, got EngineOk")

expectUnsavable :: String -> Either String ByteString -> IO ()
expectUnsavable label r = case r of
  Left _ -> pure ()
  Right b -> assertFailure (label ++ ": expected Left, got " ++ show (BS.length b) ++ " bytes")

expectAuthFailed :: String -> EngineResult a -> IO ()
expectAuthFailed label r = case r of
  EngineFail (BackendAuthFailed _) -> pure ()
  EngineFail e -> assertFailure (label ++ ": expected BackendAuthFailed, got " ++ show e)
  EngineOk _ -> assertFailure (label ++ ": expected BackendAuthFailed, got EngineOk")

-- | Golden digest bytes as hex: characterization value observed
-- from the first passing run (cf. the fixture goldens, likewise
-- observed-then-pinned), locking the stable synthetic contract
-- against accidental drift. Sanity shape (32 bytes, deterministic,
-- input-sensitive) is asserted alongside, not by the golden alone.
synthDigestAbcHex :: String
synthDigestAbcHex = "4b3984eaffdebf1d55ed43c79908966f0416e509a7ea4068618bdba8dc2afca8"

hexBytes :: ByteString -> String
hexBytes bs = concatMap byte (BS.unpack bs)
  where
    byte b = let s = showHex b "" in replicate (2 - length s) '0' ++ s

-- ---------------------------------------------------------------------------
-- Part 1 cases
-- ---------------------------------------------------------------------------

caseDigestClass :: IO ()
caseDigestClass = withSynth "11" $ \env -> do
  d1 <- expectOk "digest abc" =<< digestOneShot env D_SHA256 "abc"
  assertEqual "digest length" 32 (BS.length d1)
  assertEqual "declared length" synthDigestLength (BS.length d1)
  assertEqual "golden digest bytes" synthDigestAbcHex (hexBytes d1)
  d2 <- expectOk "digest abc again" =<< digestOneShot env D_SHA256 "abc"
  assertEqual "digest deterministic" d1 d2
  dEmpty <- expectOk "digest empty" =<< digestOneShot env D_SHA256 BS.empty
  assertEqual "empty digest length" synthDigestLength (BS.length dEmpty)
  assertBool "empty differs from abc" (dEmpty /= d1)
  dTampered <- expectOk "digest abd" =<< digestOneShot env D_SHA256 "abd"
  assertBool "data change detected" (dTampered /= d1)

caseOpenCaps :: IO ()
caseOpenCaps = do
  r <- openBackend "11" :: IO (EngineResult (BackendEnv Synthetic))
  env <- case r of
    EngineFail err -> assertFailure ("open 11 failed: " ++ show err)
    EngineOk e -> pure e
  caps <- queryCapabilities env
  assertEqual "backend name" "synthetic" (bcName caps)
  assertEqual "backendName tag" "synthetic" (backendName (Just Synthetic))
  assertBool "sha256 advertised" (Set.member D_SHA256 (dcAlgs (bcDigests caps)))
  assertBool "multipart advertised" (dcMultipart (bcDigests caps))
  closeBackend env
  bad <- openBackend "bogus" :: IO (EngineResult (BackendEnv Synthetic))
  expectBadParam "open bogus" bad
  empty <- openBackend "" :: IO (EngineResult (BackendEnv Synthetic))
  expectBadParam "open empty" empty

key32 :: KeyMaterial
key32 = KeyBytes "0123456789abcdef0123456789abcdef"

otherKey32 :: KeyMaterial
otherKey32 = KeyBytes (hex "ffeeddbbcc9988776655443322110042446688aaccee1133557799bbddff1971")

hmacFull :: MacSpec
hmacFull = MacHMAC D_SHA256 Nothing

ecdsaDer, ecdsaRaw :: SigSpec
ecdsaDer = SigECDSA (EcSpec "P-256" "DER") (Just D_SHA256)
ecdsaRaw = SigECDSA (EcSpec "P-256" "RAW") (Just D_SHA256)

-- | Blanket pin for the unmigrated surface: everything outside the
-- migrated set answers BackendUnsupported (the class-law default), so
-- each slice demonstrably narrows it. Permanent outsiders stay;
-- temporary entries migrated out part by part (multipart digest
-- + restore, mac + sign/verify, cipher, generateKey +
-- importKey). What remains is the permanent unsupported set.
caseUnsupportedRest :: IO ()
caseUnsupportedRest = withSynth "11" $ \env -> do
  -- Permanent: outside the synthetic capability set (stays).
  -- sha384 is supported; XOF stays the digest holdout.
  -- In-range truncation is supported (see caseHmacTrunc);
  -- out-of-range lengths stay the MAC holdout.
  expectUnsupported "digest shake128" =<< digestOneShot env D_SHAKE128 "abc"
  expectUnsupported "hmac over-width truncation" =<<
    macSign env (MacHMAC D_SHA256 (Just 33)) key32 "hello"
  -- The NIST prime curves are supported (see caseEcdsaCurves);
  -- P-224 stays the curve holdout.
  expectUnsupported "ecdsa p224" =<<
    sign env (SigECDSA (EcSpec "P-224" "DER") (Just D_SHA256)) key32 "msg"
  -- The 23-spec CBC/CTR/ECB set is supported (see
  -- caseCipherSpecs, which roundtrips the CTR stream specs too).
  ctrCt <- expectOk "aes128-ctr served" =<<
    cipherEncrypt env C_AES128_CTR (KeyBytes "0123456789abcdef") "0123456789abcdef" "0123456789abcdef"
  ctrPt <- expectOk "aes128-ctr opens" =<<
    cipherDecrypt env C_AES128_CTR (KeyBytes "0123456789abcdef") "0123456789abcdef" ctrCt
  assertEqual "aes128-ctr reversible" "0123456789abcdef" ctrPt
  -- AEAD is supported (see caseAeadRoundtrip).
  -- OAEP is supported (see caseOaepRoundtrip); XOF
  -- hashes stay out.
  expectUnsupported "pkeyEncrypt xof" =<<
    pkeyEncrypt env (RsaOaep (OaepParams D_SHAKE128 D_SHA256 BS.empty)) key32 "m"
  expectUnsupported "pkeyDecrypt xof" =<<
    pkeyDecrypt env (RsaOaep (OaepParams D_SHA256 D_SHAKE256 BS.empty)) key32 "c"
  expectResourceGone "exportKey unknown" =<<
    exportKey env (KeyRef (EngineResourceId 999) "SYM")
  -- (All temporary entries migrated out; the ML-KEM entries:
  -- generation and encapsulation are supported, covered by
  -- caseKemRoundtrip.)

caseClosedGuards :: IO ()
caseClosedGuards = do
  r <- openBackend "11" :: IO (EngineResult (BackendEnv Synthetic))
  env <- case r of
    EngineFail err -> assertFailure ("open failed: " ++ show err)
    EngineOk e -> pure e
  closeBackend env
  dr <- digestOneShot env D_SHA256 "abc"
  case dr of
    EngineFail (BackendInvalidState _ _) -> pure ()
    other -> assertFailure ("expected InvalidState, got " ++ show other)
  -- Guard-before-state: a capability miss still reports
  -- Unsupported on a closed backend, never InvalidState.
  expectUnsupported "closed unsupported stays Unsupported" =<<
    digestOneShot env D_SHAKE128 "abc"

-- ---------------------------------------------------------------------------
-- Part 2 cases: multipart digest + versioned resource snapshots
-- ---------------------------------------------------------------------------

caseDigestMultipart :: IO ()
caseDigestMultipart = withSynth "11" $ \env -> do
  one <- expectOk "one-shot abc" =<< digestOneShot env D_SHA256 "abc"
  rid <- expectOk "digestInit" =<< digestInit env D_SHA256
  expectOk "update(a)" =<< digestUpdate env rid "a"
  expectOk "update(bc)" =<< digestUpdate env rid "bc"
  d <- expectOk "digestFinal" =<< digestFinal env rid
  assertEqual "multipart == one-shot" one d
  assertEqual "multipart golden" synthDigestAbcHex (hexBytes d)
  -- Final consumes the handle (exactly-once release).
  expectResourceGone "second final" =<< digestFinal env rid
  expectResourceGone "update after final" =<< digestUpdate env rid "x"
  -- Unknown handles are ResourceGone, never fabricated.
  expectResourceGone "update unknown" =<<
    digestUpdate env (EngineResourceId 999) "x"
  expectResourceGone "final unknown" =<<
    digestFinal env (EngineResourceId 999)
  -- Capability guard runs before allocation (XOF stays unsupported).
  expectUnsupported "init shake128" =<< digestInit env D_SHAKE128
  -- Release drops the handle without finalizing.
  rid2 <- expectOk "digestInit 2" =<< digestInit env D_SHA256
  releaseResource env rid2
  expectResourceGone "final after release" =<< digestFinal env rid2

-- | Streamed multipart is byte-identical to the one-shot
-- across every fixed-width digest algorithm (the XOFs stay
-- unsupported on both paths, pinned above).
caseDigestStreamAll :: IO ()
caseDigestStreamAll = withSynth "11" $ \env -> do
  let msg = "the quick brown fox jumps over the lazy dog" :: ByteString
      (a, b) = BS.splitAt 20 msg
  mapM_ (check env (a <> b) a b)
    [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
    , D_SHA512_224, D_SHA512_256
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    , D_RIPEMD160
    , D_BLAKE2B512
    ]
  where
    check env full a b alg = do
      one <- expectOk ("one-shot " ++ show alg) =<< digestOneShot env alg full
      rid <- expectOk ("init " ++ show alg) =<< digestInit env alg
      expectOk ("update(a) " ++ show alg) =<< digestUpdate env rid a
      expectOk ("update(b) " ++ show alg) =<< digestUpdate env rid b
      d <- expectOk ("final " ++ show alg) =<< digestFinal env rid
      assertEqual ("multipart == one-shot: " ++ show alg) one d

caseDigestSnapshot :: IO ()
caseDigestWidths :: IO ()
caseDigestWidths = withSynth "11" $ \env -> do
  -- (alg, width): the recipe widths, executed against synthetic.
  let widths =
        [ (D_SHA224, 28), (D_SHA256, 32), (D_SHA384, 48), (D_SHA512, 64)
        , (D_SHA512_224, 28), (D_SHA512_256, 32)
        , (D_SHA3_224, 28), (D_SHA3_256, 32), (D_SHA3_384, 48), (D_SHA3_512, 64)
        , (D_MD5, 16), (D_SHA1, 20), (D_RIPEMD160, 20)
        , (D_BLAKE2B512, 64)
        ]
  outs <- mapM (\(alg, w) -> do
    d <- expectOk ("digest " ++ show alg) =<< digestOneShot env alg "abc"
    assertEqual ("width " ++ show alg) w (BS.length d)
    d2 <- expectOk ("redigest " ++ show alg) =<< digestOneShot env alg "abc"
    assertEqual ("deterministic " ++ show alg) d d2
    pure (alg, d)) widths
  -- Domain separation: same input, distinct bytes per algorithm.
  let digests = map snd outs
  assertEqual "all algs differ" (length digests) (length (nub digests))
  where
    nub = foldr (\x acc -> if x `elem` acc then acc else x : acc) []

caseMultipartAlg :: IO ()
caseMultipartAlg = withSynth "11" $ \env -> do
  -- Final must use the INIT algorithm, not SHA-256: multipart
  -- output equals one-shot output per algorithm, at full width.
  mapM_ (checkAlg env)
    [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
    , D_SHA512_224, D_SHA512_256
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    , D_RIPEMD160
    , D_BLAKE2B512
    ]
  where
    checkAlg e alg = do
      rid <- expectOk ("init " ++ show alg) =<< digestInit e alg
      expectOk "update(a)" =<< digestUpdate e rid "a"
      expectOk "update(bc)" =<< digestUpdate e rid "bc"
      d <- expectOk "final" =<< digestFinal e rid
      one <- expectOk "one-shot" =<< digestOneShot e alg "abc"
      assertEqual ("multipart == one-shot " ++ show alg) one d

caseSnapshotAlg :: IO ()
caseSnapshotAlg = withSynth "11" $ \env -> do
  -- Snapshot/restore preserves the algorithm across the boundary.
  rid <- expectOk "digestInit" =<< digestInit env D_SHA384
  expectOk "update(a)" =<< digestUpdate env rid "a"
  snap <- snapshotResource env rid
  ctx <- case snap of
    Left err -> assertFailure ("snapshot failed: " ++ err) >> undefined
    Right b -> pure b
  rid2 <- expectOk "restore" =<< restoreResource env ctx
  expectOk "update(bc)" =<< digestUpdate env rid2 "bc"
  d <- expectOk "digestFinal" =<< digestFinal env rid2
  one <- expectOk "one-shot abc" =<< digestOneShot env D_SHA384 "abc"
  assertEqual "restored sha384 == one-shot" one d
  assertEqual "restored width" 48 (BS.length d)

-- | (alg, width): the recipe widths, executed against synthetic MAC.
hmacWidths :: [(DigestAlg, Int)]
hmacWidths =
  [ (D_SHA224, 28), (D_SHA256, 32), (D_SHA384, 48), (D_SHA512, 64)
  , (D_SHA512_224, 28), (D_SHA512_256, 32)
  , (D_SHA3_224, 28), (D_SHA3_256, 32), (D_SHA3_384, 48), (D_SHA3_512, 64)
  , (D_MD5, 16), (D_SHA1, 20), (D_RIPEMD160, 20)
  , (D_BLAKE2B512, 64)
  ]

caseHmacWidths :: IO ()
caseHmacWidths = withSynth "11" $ \env -> do
  outs <- mapM (\(alg, w) -> do
    t <- expectOk ("mac " ++ show alg)
      =<< macSign env (MacHMAC alg Nothing) key32 "hello"
    assertEqual ("width " ++ show alg) w (BS.length t)
    t2 <- expectOk ("remac " ++ show alg)
      =<< macSign env (MacHMAC alg Nothing) key32 "hello"
    assertEqual ("deterministic " ++ show alg) t t2
    ok <- expectOk ("verify " ++ show alg)
      =<< macVerify env (MacHMAC alg Nothing) key32 "hello" t
    assertBool ("roundtrip " ++ show alg) ok
    pure (alg, t)) hmacWidths
  -- Domain separation: same key and input, distinct bytes per alg.
  let tags = map snd outs
  assertEqual "all algs differ" (length tags) (length (nub tags))
  where
    nub = foldr (\x acc -> if x `elem` acc then acc else x : acc) []

caseHmacTrunc :: IO ()
caseHmacTrunc = withSynth "11" $ \env -> do
  full <- expectOk "full tag" =<< macSign env hmacFull key32 "hello"
  trunc16 <- expectOk "truncated tag" =<< macSign env (MacHMAC D_SHA256 (Just 16)) key32 "hello"
  assertEqual "truncation slices the full tag" (BS.take 16 full) trunc16
  ok <- expectOk "truncated verifies" =<< macVerify env (MacHMAC D_SHA256 (Just 16)) key32 "hello" trunc16
  assertBool "truncated roundtrip" ok
  expectAuthFailed "full tag rejected under trunc spec" =<<
    macVerify env (MacHMAC D_SHA256 (Just 16)) key32 "hello" full
  -- Every recipe alg honors its own ceiling: width ok, width+1 and
  -- zero refused without fallback.
  mapM_ (\(alg, w) -> do
    tw <- expectOk ("ceiling " ++ show alg)
      =<< macSign env (MacHMAC alg (Just w)) key32 "hello"
    fw <- expectOk ("full " ++ show alg)
      =<< macSign env (MacHMAC alg Nothing) key32 "hello"
    assertEqual ("ceiling == full " ++ show alg) fw tw
    t1 <- expectOk ("one byte " ++ show alg)
      =<< macSign env (MacHMAC alg (Just 1)) key32 "hello"
    assertEqual ("single byte " ++ show alg) 1 (BS.length t1)
    expectUnsupported ("zero refused " ++ show alg) =<<
      macSign env (MacHMAC alg (Just 0)) key32 "hello"
    expectUnsupported ("over-width refused " ++ show alg) =<<
      macSign env (MacHMAC alg (Just (w + 1))) key32 "hello"
    ) hmacWidths
  -- XOFs never make fixed-width tags.
  expectUnsupported "shake128 hmac" =<<
    macSign env (MacHMAC D_SHAKE128 Nothing) key32 "hello"
  expectUnsupported "shake256 hmac" =<<
    macSign env (MacHMAC D_SHAKE256 (Just 16)) key32 "hello"

caseDigestSnapshot = withSynth "11" $ \env -> do
  rid <- expectOk "digestInit" =<< digestInit env D_SHA256
  expectOk "update(a)" =<< digestUpdate env rid "a"
  snap <- snapshotResource env rid
  ctx <- case snap of
    Left err -> assertFailure ("snapshot failed: " ++ err)
    Right b -> pure b
  -- Explicit format version: digest contexts start with 0x02
  -- (key contexts are 0x01; see the key-generation case).
  assertEqual "digest context version" 2 (BS.head ctx)
  rid2 <- expectOk "restore" =<< restoreResource env ctx
  assertBool "restore mints a fresh handle" (rid2 /= rid)
  expectOk "update(bc)" =<< digestUpdate env rid2 "bc"
  d <- expectOk "digestFinal" =<< digestFinal env rid2
  one <- expectOk "one-shot abc" =<< digestOneShot env D_SHA256 "abc"
  assertEqual "restored stream == one-shot" one d
  -- The pre-snapshot handle is undisturbed by the snapshot.
  expectOk "update(bc) on original" =<< digestUpdate env rid "bc"
  dOrig <- expectOk "final original" =<< digestFinal env rid
  assertEqual "original stream == one-shot" one dOrig
  -- Strict parse: garbage, truncation, and version skew reject.
  expectBadParam "restore garbage" =<< restoreResource env "bogus"
  expectBadParam "restore truncated" =<<
    restoreResource env (BS.take 3 ctx)
  expectBadParam "restore bad version" =<<
    restoreResource env (BS.singleton 0x09 <> BS.drop 1 ctx)
  expectUnsavable "snapshot unknown" =<<
    snapshotResource env (EngineResourceId 999)

-- ---------------------------------------------------------------------------
-- Part 3 cases: MAC + signatures
-- ---------------------------------------------------------------------------

caseMac :: IO ()
caseMac = withSynth "11" $ \env -> do
  mac <- expectOk "mac hello" =<< macSign env hmacFull key32 "hello"
  assertEqual "mac length" synthMacLength (BS.length mac)
  assertEqual "declared mac length" 32 (BS.length mac)
  mac2 <- expectOk "mac hello again" =<< macSign env hmacFull key32 "hello"
  assertEqual "mac deterministic" mac mac2
  ok <- expectOk "verify good" =<< macVerify env hmacFull key32 "hello" mac
  assertBool "good tag verifies" ok
  expectAuthFailed "changed data rejected" =<<
    macVerify env hmacFull key32 "hellp" mac
  expectAuthFailed "wrong key rejected" =<<
    macVerify env hmacFull otherKey32 "hello" mac
  expectAuthFailed "tampered tag rejected" =<<
    macVerify env hmacFull key32 "hello" (mac <> "x")
  expectAuthFailed "truncated tag rejected" =<<
    macVerify env hmacFull key32 "hello" (BS.take 16 mac)
  -- Capability misses: wrong MAC family (per-algorithm HMAC;
  -- see caseHmacWidths).
  expectUnsupported "cmac unsupported" =<<
    macSign env (MacCMAC C_AES256_CBC) key32 "hello"
  r <- macSign env hmacFull (KeyBytes BS.empty) "hello"
  case r of
    EngineFail (BackendBadKey _ _) -> pure ()
    EngineFail e -> assertFailure ("empty key must be BadKey, got " ++ show e)
    EngineOk _ -> assertFailure "empty key must be BadKey, got EngineOk"
  expectResourceGone "mac with unknown ref" =<<
    macSign env hmacFull (KeyRefMaterial (KeyRef (EngineResourceId 999) "SYM")) "hello"

caseSign :: IO ()
caseSign = withSynth "11" $ \env -> do
  sig <- expectOk "sign msg" =<< sign env ecdsaDer key32 "msg"
  assertEqual "sig length" synthSigLength (BS.length sig)
  assertEqual "declared sig length" 64 (BS.length sig)
  sig2 <- expectOk "sign msg again" =<< sign env ecdsaDer key32 "msg"
  assertEqual "sign deterministic" sig sig2
  expectOk "verify good" =<< verify env ecdsaDer key32 "msg" sig
  expectAuthFailed "changed data rejected" =<<
    verify env ecdsaDer key32 "msf" sig
  expectAuthFailed "wrong key rejected" =<<
    verify env ecdsaDer otherKey32 "msg" sig
  expectAuthFailed "tampered sig rejected" =<<
    verify env ecdsaDer key32 "msg" (BS.init sig <> "X")
  -- Encodings are explicit participants: DER and RAW both run, give
  -- different bytes, and never verify across (no silent conversion).
  sigR <- expectOk "sign raw" =<< sign env ecdsaRaw key32 "msg"
  assertEqual "raw length" synthSigLength (BS.length sigR)
  assertBool "encoding participates" (sigR /= sig)
  expectOk "verify raw" =<< verify env ecdsaRaw key32 "msg" sigR
  expectAuthFailed "der sig under raw rejected" =<<
    verify env ecdsaRaw key32 "msg" sig
  expectAuthFailed "raw sig under der rejected" =<<
    verify env ecdsaDer key32 "msg" sigR
  -- Outside the set: off-set curves/digests.
  -- (Raw ECDSA, the NIST prime curves, and every fixed-width
  -- digest are supported, see caseEcdsaCurves; EdDSA signs
  -- inside the set, see caseEddsaRoundtrip.)
  expectUnsupported "p224" =<<
    sign env (SigECDSA (EcSpec "P-224" "DER") (Just D_SHA256)) key32 "msg"
  expectUnsupported "xof digest" =<<
    sign env (SigECDSA (EcSpec "P-256" "DER") (Just D_SHAKE128)) key32 "msg"
  edSig <- expectOk "eddsa signs" =<<
    sign env (SigEdDSA (EcSpec "Ed25519" "RAW") BS.empty) key32 "msg"
  expectOk "eddsa verifies" =<<
    verify env (SigEdDSA (EcSpec "Ed25519" "RAW") BS.empty) key32 "msg" edSig

-- ---------------------------------------------------------------------------
-- Part 4 case: cipher
-- ---------------------------------------------------------------------------

caseCipher :: IO ()
caseCipher = withSynth "11" $ \env -> do
  let iv = "0123456789abcdef"
      plain = "sixteen bytes xx" -- 15 bytes: odd length, no padding
  ct <- expectOk "encrypt" =<< cipherEncrypt env C_AES256_CBC key32 iv plain
  -- Explicit length contract: length-preserving stream construction.
  assertEqual "cipher length-preserving" (BS.length plain) (BS.length ct)
  pt <- expectOk "decrypt" =<< cipherDecrypt env C_AES256_CBC key32 iv ct
  assertEqual "cipher reversible" plain pt
  wrongKey <- expectOk "decrypt wrong key" =<<
    cipherDecrypt env C_AES256_CBC otherKey32 iv ct
  assertBool "wrong key detected" (wrongKey /= plain)
  otherIv <- expectOk "encrypt other iv" =<<
    cipherEncrypt env C_AES256_CBC key32 "fedcba9876543210" plain
  assertBool "iv change detected" (otherIv /= ct)
  tampered <- expectOk "decrypt tampered" =<<
    cipherDecrypt env C_AES256_CBC key32 iv ("X" <> BS.drop 1 ct)
  assertBool "data change detected" (tampered /= plain)
  emptyCt <- expectOk "encrypt empty" =<<
    cipherEncrypt env C_AES256_CBC key32 iv BS.empty
  assertEqual "empty roundtrip" BS.empty emptyCt
  ct2 <- expectOk "encrypt deterministic" =<<
    cipherEncrypt env C_AES256_CBC key32 iv plain
  assertEqual "encrypt deterministic" ct ct2
  -- Typed length errors (AES-256 shape: 32-byte key, 16-byte iv).
  expectBadParam "short key" =<<
    cipherEncrypt env C_AES256_CBC (KeyBytes "short") iv plain
  expectBadParam "short iv" =<<
    cipherEncrypt env C_AES256_CBC key32 "short" plain
  expectBadParam "decrypt short iv" =<<
    cipherDecrypt env C_AES256_CBC key32 "short" ct
  -- AES-128-CBC is supported; a 32-byte key against
  -- it is a typed length refusal, not a capability miss.
  expectBadParam "aes128 wrong key" =<<
    cipherEncrypt env C_AES128_CBC key32 iv plain

-- ---------------------------------------------------------------------------
-- Part 5 cases: key generation + registry + pairs
-- ---------------------------------------------------------------------------

openSynth :: String -> IO (BackendEnv Synthetic)
openSynth seed = do
  r <- openBackend seed :: IO (EngineResult (BackendEnv Synthetic))
  case r of
    EngineFail err -> assertFailure ("open " ++ show seed ++ " failed: " ++ show err)
    EngineOk e -> pure e

caseKeygen :: IO ()
caseKeygen = do
  envA <- openSynth "11"
  envB <- openSynth "11"
  envC <- openSynth "12"
  let genSym env n = generateKey env (GenSym "AES" n)
  (KeyBytes k16, Nothing) <- expectOk "gen aes128" =<< genSym envA 16
  (KeyBytes k16b, Nothing) <- expectOk "gen aes128 again" =<< genSym envB 16
  assertEqual "same seed same first key" k16 k16b
  assertEqual "explicit byte length" 16 (BS.length k16)
  (KeyBytes k32, Nothing) <- expectOk "gen aes256" =<< genSym envA 32
  assertEqual "aes256 length" 32 (BS.length k32)
  (KeyBytes k24, Nothing) <- expectOk "gen aes192" =<< genSym envA 24
  assertEqual "aes192 length" 24 (BS.length k24)
  assertBool "sequence advances" (k16 /= BS.take 16 k32)
  (KeyBytes k16c, Nothing) <- expectOk "gen other seed" =<< genSym envC 16
  assertBool "changed seed detected" (k16 /= k16c)
  -- Same seed, same call sequence: full-sequence determinism.
  (KeyBytes k32b, Nothing) <- expectOk "gen aes256 b" =<< genSym envB 32
  assertEqual "sequence deterministic" k32 k32b
  -- Length discipline: AES takes 16/24/32 bytes, nothing else.
  expectBadParam "aes-17 rejected" =<< genSym envA 17
  expectBadParam "aes-0 rejected" =<< genSym envA 0
  expectUnsupported "chacha unsupported" =<< generateKey envA (GenSym "ChaCha20" 32)
  expectUnsupported "hmac gen unsupported" =<< generateKey envA (GenSym "HMAC" 32)
  -- EC: P-256 pairs only. Fresh same-seed backends replaying the
  -- same call sequence agree bit-for-bit.
  envD <- openSynth "11"
  envE <- openSynth "11"
  (priv, Just pub) <- expectOk "gen p256" =<< generateKey envD (GenEC (EcSpec "P-256" "DER"))
  (privB, Just pubB) <- expectOk "gen p256 b" =<< generateKey envE (GenEC (EcSpec "P-256" "DER"))
  assertBool "ec deterministic across same-seed backends" (priv == privB && pub == pubB)
  assertBool "halves differ" (priv /= pub)
  -- P-384/P-521 replay the same curve-blind construction;
  -- off-set curves stay out.
  (KeyDer p384, Just (KeyDer q384)) <- expectOk "gen p384" =<<
    generateKey envD (GenEC (EcSpec "P-384" "DER"))
  (KeyDer p384b, Just (KeyDer q384b)) <- expectOk "gen p384 b" =<<
    generateKey envE (GenEC (EcSpec "P-384" "DER"))
  assertBool "p384 deterministic" (p384 == p384b && q384 == q384b)
  (KeyDer p521, Just (KeyDer q521)) <- expectOk "gen p521" =<<
    generateKey envD (GenEC (EcSpec "P-521" "DER"))
  assertBool "p521 halves differ" (p521 /= q521)
  expectUnsupported "p224 gen" =<< generateKey envD (GenEC (EcSpec "P-224" "DER"))
  -- RSA: deterministic DER pairs replay bit-for-bit across
  -- same-seed backends; bounds refuse as bad params.
  envF <- openSynth "11"
  envG <- openSynth "11"
  (KeyDer rpriv, Just (KeyDer rpub)) <- expectOk "gen rsa" =<<
    generateKey envF (GenRSA 2048 65537)
  (KeyDer rprivB, Just (KeyDer rpubB)) <- expectOk "gen rsa b" =<<
    generateKey envG (GenRSA 2048 65537)
  assertBool "rsa deterministic across same-seed backends"
    (rpriv == rprivB && rpub == rpubB)
  assertBool "rsa halves differ" (rpriv /= rpub)
  expectBadParam "rsa-1024 refused" =<< generateKey envF (GenRSA 1024 65537)
  expectBadParam "rsa even exponent refused" =<< generateKey envF (GenRSA 2048 4)
  mapM_ closeBackend [envA, envB, envC, envD, envE, envF, envG]

caseRegistry :: IO ()
caseRegistry = withSynth "11" $ \env -> do
  ref <- expectOk "import sym" =<< importKey env key32
  assertEqual "sym family" "SYM" (keyRefFamily ref)
  mat <- expectOk "export sym" =<< exportKey env ref
  assertEqual "export roundtrip" key32 mat
  -- Registry references resolve inside execute paths.
  mac <- expectOk "mac via ref" =<<
    macSign env hmacFull (KeyRefMaterial ref) "hello"
  macDirect <- expectOk "mac direct" =<< macSign env hmacFull key32 "hello"
  assertEqual "ref resolves to stored bytes" macDirect mac
  -- Re-importing a reference is the identity (no nesting).
  ref2 <- expectOk "import ref" =<< importKey env (KeyRefMaterial ref)
  assertEqual "ref import identity" ref ref2
  -- DER material keeps its shape and family.
  refD <- expectOk "import der" =<< importKey env (KeyDer "fake-der-bytes")
  assertEqual "der family" "DER" (keyRefFamily refD)
  matD <- expectOk "export der" =<< exportKey env refD
  assertEqual "der roundtrip" (KeyDer "fake-der-bytes") matD
  -- Destroy drops; double-destroy is silent; export then gone.
  destroyKey env ref
  expectResourceGone "export after destroy" =<< exportKey env ref
  destroyKey env ref
  expectResourceGone "export unknown" =<<
    exportKey env (KeyRef (EngineResourceId 4242) "SYM")
  r <- importKey env (KeyBytes BS.empty)
  case r of
    EngineFail (BackendBadKey _ _) -> pure ()
    EngineFail e -> assertFailure ("empty import must be BadKey, got " ++ show e)
    EngineOk _ -> assertFailure "empty import must be BadKey, got EngineOk"

casePairs :: IO ()
casePairs = withSynth "11" $ \env -> do
  (priv, Just pub) <- expectOk "gen pair" =<<
    generateKey env (GenEC (EcSpec "P-256" "DER"))
  (_, Just pub2) <- expectOk "gen pair 2" =<<
    generateKey env (GenEC (EcSpec "P-256" "DER"))
  sig <- expectOk "sign with priv" =<< sign env ecdsaDer priv "data"
  assertEqual "pair sig length" synthSigLength (BS.length sig)
  -- Paired halves verify across (shared pair identity).
  expectOk "pub verifies priv sig" =<< verify env ecdsaDer pub "data" sig
  sigPub <- expectOk "sign with pub" =<< sign env ecdsaDer pub "data"
  assertEqual "pair signs identically" sig sigPub
  expectOk "priv verifies pub sig" =<< verify env ecdsaDer priv "data" sigPub
  expectAuthFailed "other pair rejected" =<<
    verify env ecdsaDer pub2 "data" sig
  expectAuthFailed "changed data rejected" =<<
    verify env ecdsaDer pub "date" sig
  -- Key snapshots: versioned 0x01 contexts, pair-ness preserved.
  pref <- expectOk "import priv" =<< importKey env priv
  snap <- snapshotResource env (keyRefId pref)
  ctx <- case snap of
    Left err -> assertFailure ("key snapshot failed: " ++ err)
    Right b -> pure b
  assertEqual "key context version" synthKeyContextVersion (BS.head ctx)
  restored <- expectOk "restore key" =<< restoreResource env ctx
  rmat <- expectOk "export restored" =<<
    exportKey env (KeyRef restored "DER")
  assertEqual "restored bytes" priv rmat
  sigR <- expectOk "sign with restored" =<<
    sign env ecdsaDer (KeyRefMaterial (KeyRef restored "DER")) "data"
  assertEqual "restored signs as pair" sig sigR
  expectOk "restored verifies across" =<<
    verify env ecdsaDer pub "data" sigR

-- ---------------------------------------------------------------------------
-- Part 6 cases: pure keep + full caps + driver bridge
-- ---------------------------------------------------------------------------

mAESCBC :: MechanismId
mAESCBC = MechanismId 0x1082

caseRandomBytes :: IO ()
caseRandomBytes = do
  -- Same seed replays the stream; the counter advances within
  -- one backend; zero length is a bad param.
  ref <- newIORef BS.empty
  withSynth "19" $ \env -> do
    a <- expectOk "random 32" =<< randomBytes env 32
    writeIORef ref a
  a <- readIORef ref
  withSynth "19" $ \env -> do
    b <- expectOk "random 32 replay" =<< randomBytes env 32
    assertEqual "seed replays" a b
  withSynth "19" $ \env -> do
    x <- expectOk "first" =<< randomBytes env 32
    y <- expectOk "second" =<< randomBytes env 32
    assertBool "counter advances" (x /= y)
    assertEqual "first replays head" a x
    expectBadParam "random 0 refused" =<< randomBytes env 0
    full <- expectOk "random 1MiB" =<< randomBytes env generateRandomMaxBytes
    assertEqual "window length" generateRandomMaxBytes (BS.length full)
    expectBadParam "random 1MiB+1 refused" =<< randomBytes env (generateRandomMaxBytes + 1)

caseSeedRandomReplay :: IO ()
caseSeedRandomReplay = withSynth "21" $ \env -> do
  -- Reseed REPLACES the stream origin (new seed plus
  -- counter reset). The same seed plus the same subsequent call
  -- sequence replays byte-identical bytes; a different seed
  -- moves the stream.
  _ <- expectOk "pre-seed bytes" =<< randomBytes env 32
  expectOk "seed S ok" =<< seedRandom env "S"
  a <- expectOk "bytes after seed S" =<< randomBytes env 32
  expectOk "reseed S ok" =<< seedRandom env "S"
  a2 <- expectOk "bytes after reseed S" =<< randomBytes env 32
  assertEqual "same seed replays" a a2
  expectOk "seed T ok" =<< seedRandom env "T"
  b <- expectOk "bytes after seed T" =<< randomBytes env 32
  assertBool "different seed moves stream" (a /= b)

caseSeedRandomBounds :: IO ()
caseSeedRandomBounds = do
  -- The seed bound is exactly 1 MiB (mirroring the native
  -- 1048576 window); an empty seed is a vacuous OK that leaves
  -- the stream undisturbed.
  assertEqual "seed bound is 1 MiB" 1048576 seedRandomMaxBytes
  ref <- newIORef (BS.empty, BS.empty)
  withSynth "21" $ \env -> do
    o1 <- expectOk "oracle first" =<< randomBytes env 32
    o2 <- expectOk "oracle second" =<< randomBytes env 32
    writeIORef ref (o1, o2)
  (o1, o2) <- readIORef ref
  withSynth "21" $ \env -> do
    r1 <- expectOk "first" =<< randomBytes env 32
    expectOk "empty seed ok" =<< seedRandom env BS.empty
    r2 <- expectOk "second" =<< randomBytes env 32
    assertEqual "empty seed keeps head" o1 r1
    assertEqual "empty seed keeps tail" o2 r2
    expectOk "1 MiB seed ok" =<< seedRandom env (BS.replicate seedRandomMaxBytes 0)
    expectBadParam "oversize seed refused"
      =<< seedRandom env (BS.replicate (seedRandomMaxBytes + 1) 0)

caseRng :: IO ()
caseRng = do
  let s = deriveStream (Seed 7) (OpNumber 3)
      (a, s') = nextBytes 32 s
      (b, _) = nextBytes 32 s'
      (a2, _) = nextBytes 32 (deriveStream (Seed 7) (OpNumber 3))
      (c, _) = nextBytes 32 (deriveStream (Seed 7) (OpNumber 4))
  assertEqual "stream deterministic" a a2
  assertEqual "stream length" 32 (BS.length a)
  assertBool "counter advances" (a /= b)
  assertBool "streams independent" (a /= c)

caseFixtures :: IO ()
caseFixtures = do
  let k1 = fixtureKey mAESCBC (Seed 7) "t06-pin"
      k2 = fixtureKey mAESCBC (Seed 7) "t06-pin"
      k3 = fixtureKey mAESCBC (Seed 7) "t06-pin-other"
  assertEqual "fixture deterministic" (fmBytes k1) (fmBytes k2)
  assertEqual "identity deterministic" (fmIdentity k1) (fmIdentity k2)
  assertBool "label separates" (fmBytes k1 /= fmBytes k3)
  assertBool "seed separates"
    (fmBytes k1 /= fmBytes (fixtureKey mAESCBC (Seed 8) "t06-pin"))
  -- Byte-identical goldens: the retired record's characterization
  -- values carry over verbatim onto the new fixture home.
  assertEqual "golden fixture bytes"
    "6eec9da092187111aa02f46c2e203fb25912ed95e9e174730444c60a1c1f1c03"
    (hexBytes (fmBytes k1))
  assertEqual "golden fixture identity"
    "55f1ba9af6168d48c4fe66f6f318027bffceb16e278f4568af4de8239e3e97d2"
    (hexBytes (fmIdentity k1))
  let (pubMat, privMat) = fixtureKeyPair mAESCBC (Seed 9) "t06-sig"
  assertEqual "shared pair identity" (fmPair pubMat) (fmPair privMat)
  case fmPair pubMat of
    Nothing -> assertFailure "pair identity must be present"
    Just _ -> pure ()
  assertBool "halves differ" (fmBytes pubMat /= fmBytes privMat)

caseCapsFull :: IO ()
caseCapsFull = withSynth "11" $ \env -> do
  caps <- queryCapabilities env
  assertEqual "backend name" "synthetic" (bcName caps)
  assertEqual "backend version" "synthetic/1" (bcVersion caps)
  assertEqual "digest set" (Set.fromList
    [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
    , D_SHA512_224, D_SHA512_256
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    , D_RIPEMD160
    , D_BLAKE2B512
    ]) (dcAlgs (bcDigests caps))
  assertBool "multipart digest" (dcMultipart (bcDigests caps))
  assertBool "no xof" (not (dcXof (bcDigests caps)))
  assertEqual "cipher set" (Set.fromList
    [ C_AES128_CBC, C_AES192_CBC, C_AES256_CBC
    , C_AES128_CTR, C_AES192_CTR, C_AES256_CTR
    , C_AES128_ECB, C_AES192_ECB, C_AES256_ECB
    , C_AES128_CTS, C_AES192_CTS, C_AES256_CTS
    , C_AES128_CFB128, C_AES192_CFB128, C_AES256_CFB128
    , C_AES128_CFB8, C_AES192_CFB8, C_AES256_CFB8
    , C_AES128_CFB1, C_AES192_CFB1, C_AES256_CFB1
    , C_AES128_OFB, C_AES192_OFB, C_AES256_OFB
    , C_AES128_KW, C_AES192_KW, C_AES256_KW
    , C_AES128_KWP, C_AES192_KWP, C_AES256_KWP
    , C_AES128_XTS, C_AES256_XTS
    , C_DES3_CBC, C_DES3_ECB
    , C_ARIA128_CBC, C_ARIA192_CBC, C_ARIA256_CBC
    , C_ARIA128_ECB, C_ARIA192_ECB, C_ARIA256_ECB
    , C_CAMELLIA128_CBC, C_CAMELLIA192_CBC, C_CAMELLIA256_CBC
    , C_CAMELLIA128_ECB, C_CAMELLIA192_ECB, C_CAMELLIA256_ECB
    ]) (ccCiphers (bcCiphers caps))
  assertEqual "aead set" (Set.fromList
    [ "AES-128-GCM", "AES-192-GCM", "AES-256-GCM"
    , "AES-128-CCM", "AES-192-CCM", "AES-256-CCM"
    ]) (ccAead (bcCiphers caps))
  assertEqual "mac set" (Set.fromList
    [ "HMAC-MD5", "HMAC-SHA1"
    , "HMAC-SHA224", "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"
    , "HMAC-SHA512-224", "HMAC-SHA512-256"
    , "HMAC-SHA3-224", "HMAC-SHA3-256", "HMAC-SHA3-384", "HMAC-SHA3-512"
    , "HMAC-RIPEMD160"
    , "HMAC-BLAKE2B-512"
    , "HMAC-MD5-GENERAL", "HMAC-SHA1-GENERAL"
    , "HMAC-SHA224-GENERAL", "HMAC-SHA256-GENERAL"
    , "HMAC-SHA384-GENERAL", "HMAC-SHA512-GENERAL"
    , "HMAC-SHA512-224-GENERAL", "HMAC-SHA512-256-GENERAL"
    , "HMAC-SHA3-224-GENERAL", "HMAC-SHA3-256-GENERAL"
    , "HMAC-SHA3-384-GENERAL", "HMAC-SHA3-512-GENERAL"
    , "HMAC-RIPEMD160-GENERAL"
    , "HMAC-BLAKE2B-512-GENERAL"
    ]) (mcSpecs (bcMacs caps))
  assertBool "ecdsa-p256-sha256 advertised"
    (Set.member "ECDSA-P-256-SHA256" (scSpecs (bcSigs caps)))
  -- The RSA v1.5 names join the signature set.
  -- The ECDSA names (22 curves x 13 digests + 22 raw), generated
  -- over explicit dimensions so a dropped curve or digest fails.
  let dsaCurves =
        [ "P-256", "P-384", "P-521", "secp224r1", "secp224k1"
        , "secp256k1", "secp192r1", "secp192k1", "secp160r1"
        , "secp160r2", "secp160k1", "brainpoolP224r1"
        , "brainpoolP256r1", "brainpoolP320r1", "brainpoolP384r1"
        , "brainpoolP512r1", "sect283k1", "sect283r1", "sect409k1"
        , "sect409r1", "sect571k1", "sect571r1"
        ]
      dsaStems =
        [ "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"
        , "SHA512-224", "SHA512-256", "SHA3-224", "SHA3-256"
        , "SHA3-384", "SHA3-512", "RIPEMD160", "BLAKE2B-512"
        ]
      dsaNames =
        ["ECDSA-" ++ c ++ "-RAW" | c <- dsaCurves]
          ++ ["ECDSA-" ++ c ++ "-" ++ s | c <- dsaCurves, s <- dsaStems]
      fipsDsaNames =
        ["DSA-RAW"]
          ++ ["DSA-" ++ s | s <- fipsDsaStems]
      fipsDsaStems =
        [ "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"
        , "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
        ]
      eddsaNames = ["EDDSA-Ed25519", "EDDSA-Ed448"]
      mldsaNames = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
      slhdsaNames =
        [ "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"
        , "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f"
        , "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f"
        , "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f"
        , "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f"
        , "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
        ]
  assertEqual "sig set" (Set.fromList
    ([ "RSA-PSS"
    , "RSA-RAW"
    , "RSA-PKCS1v15-MD5", "RSA-PKCS1v15-SHA1"
    , "RSA-PKCS1v15-SHA224", "RSA-PKCS1v15-SHA256"
    , "RSA-PKCS1v15-SHA384", "RSA-PKCS1v15-SHA512"
    , "RSA-PKCS1v15-SHA3-224", "RSA-PKCS1v15-SHA3-256"
    , "RSA-PKCS1v15-SHA3-384", "RSA-PKCS1v15-SHA3-512"
    , "RSA-PKCS1v15-RIPEMD160"
    ] ++ dsaNames ++ fipsDsaNames ++ eddsaNames ++ mldsaNames ++ slhdsaNames)) (scSpecs (bcSigs caps))
  assertEqual "curves" (Set.fromList dsaCurves) (scCurves (bcSigs caps))
  assertEqual "pqc sig set"
    (Set.fromList ([ML_DSA_44, ML_DSA_65, ML_DSA_87] ++ slhdsaSets)) (scPqcSign (bcSigs caps))
  assertEqual "kem set"
    (Set.fromList [ML_KEM_512, ML_KEM_768, ML_KEM_1024]) (kcAlgs (bcKems caps))
  assertEqual "kdf set" (Set.fromList ["ECDH", "ECDH-COFACTOR"]) (kcKdfs (bcKdfs caps))

caseKemRoundtrip :: IO ()
caseKemRoundtrip = withSynth "11" $ \env -> do
  (priv, mPub) <- expectOk "ml-kem gen" =<< generateKey env (GenMLKEM ML_KEM_768)
  pub <- case mPub of
    Just p -> pure p
    Nothing -> assertFailure "kem gen must return a pair"
  (ct, ss1) <- expectOk "encaps" =<< kemEncapsulate env (KemSpec ML_KEM_768) pub
  assertEqual "ct length is standard" 1088 (BS.length ct)
  assertEqual "secret length" 32 (BS.length ss1)
  ss2 <- expectOk "decaps" =<< kemDecapsulate env (KemSpec ML_KEM_768) priv ct
  assertEqual "decaps recovers the secret" ss1 ss2
  -- Role discipline: encaps needs the public half, decaps the private.
  expectBadKey "encaps with private half" =<< kemEncapsulate env (KemSpec ML_KEM_768) priv
  expectBadKey "decaps with public half" =<< kemDecapsulate env (KemSpec ML_KEM_768) pub ct
  -- A tampered ciphertext fails closed; a short one is a bad param.
  let bad = BS.map complement ct
  decBad <- kemDecapsulate env (KemSpec ML_KEM_768) priv bad
  case decBad of
    EngineFail (BackendAuthFailed _) -> pure ()
    other -> assertFailure ("tampered ct must auth-fail, got " ++ show other)
  decShort <- kemDecapsulate env (KemSpec ML_KEM_768) priv "short"
  case decShort of
    EngineFail (BackendBadParam _ _) -> pure ()
    other -> assertFailure ("short ct must be a bad param, got " ++ show other)

expectBadKey :: Show a => String -> EngineResult a -> IO ()
expectBadKey label r = case r of
  EngineFail (BackendBadKey _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BadKey, got " ++ show other)

-- | A non-auth backend failure on a verify path keeps its
-- category through the verify adapter (empty HMAC key ->
-- 'BackendBadKey' -> 'CryptoBadKey'), instead of collapsing to
-- 'CryptoFailed' (previously collapsed).
caseVerifyCategory :: IO ()
caseVerifyCategory = withSynth "11" $ \env -> do
  let resolve _ = Just (KeyBytes BS.empty)
      oid = Just (ObjectId 7)
  r <- runEffect env resolve
    (FxVerify (MechanismId 0x251) oid BS.empty "hello" "tag")
  assertEqual "category preserved"
    (GotCryptoError (CryptoBadKey "key" "empty key material")) r

-- | Guard: the category fix is code-neutral — the
-- preserved category still interprets to 'CKR_GENERAL_ERROR'
-- (mismatch verdicts stay verdicts; see the bridge roundtrip).
caseVerifyNeutral :: IO ()
caseVerifyNeutral = withSynth "11" $ \env -> do
  let resolve _ = Just (KeyBytes BS.empty)
      oid = Just (ObjectId 7)
  r <- runEffect env resolve
    (FxVerify (MechanismId 0x251) oid BS.empty "hello" "tag")
  case r of
    GotCryptoError e -> assertEqual "still general-error"
      CKR_GENERAL_ERROR (cryptoCode e)
    other -> assertFailure ("expected crypto error, got " ++ show other)

caseDriverBridge :: IO ()
caseDriverBridge = withSynth "11" $ \env -> do
  let resolve _ = Just key32
      oid = Just (ObjectId 7)
  -- Digest through the bridge equals the direct call.
  direct <- expectOk "direct digest" =<< digestOneShot env D_SHA256 "abc"
  bridged <- runEffect env resolve (FxDigest (MechanismId 0x250) "abc")
  case bridged of
    GotBytes b -> assertEqual "bridge digest == direct" direct b
    other -> assertFailure ("bridge digest must be bytes, got " ++ show other)
  -- HMAC sign/verify roundtrip through the bridge.
  sres <- runEffect env resolve (FxSign (MechanismId 0x251) oid BS.empty "hello")
  tag <- case sres of
    GotBytes b -> pure b
    other -> assertFailure ("bridge mac must be bytes, got " ++ show other)
  assertEqual "bridge tag length" synthMacLength (BS.length tag)
  vres <- runEffect env resolve (FxVerify (MechanismId 0x251) oid BS.empty "hello" tag)
  case vres of
    GotValid True -> pure ()
    other -> assertFailure ("bridge verify must be true, got " ++ show other)
  vbad <- runEffect env resolve (FxVerify (MechanismId 0x251) oid BS.empty "hello" "bogus-tag-padded-to-32-bytes!!!!")
  case vbad of
    GotValid False -> pure ()
    other -> assertFailure ("bridge verify must be false, got " ++ show other)
  -- AES cipher roundtrip through the bridge.
  let iv = "0123456789abcdef"
  cres <- runEffect env resolve (FxCipher DirEncrypt (MechanismId 0x1082) oid iv "sixteen bytes xx")
  ct <- case cres of
    GotBytes b -> pure b
    other -> assertFailure ("bridge encrypt must be bytes, got " ++ show other)
  dres <- runEffect env resolve (FxCipher DirDecrypt (MechanismId 0x1082) oid iv ct)
  case dres of
    GotBytes pt -> assertEqual "bridge roundtrip" "sixteen bytes xx" pt
    other -> assertFailure ("bridge decrypt must be bytes, got " ++ show other)
  -- ECDSA roundtrip through the bridge, DER params.
  eres <- runEffect env resolve (FxSign (MechanismId 0x1041) oid "DER" "msg")
  sig <- case eres of
    GotBytes b -> pure b
    other -> assertFailure ("bridge sign must be bytes, got " ++ show other)
  assertEqual "bridge sig length" synthSigLength (BS.length sig)
  evres <- runEffect env resolve (FxVerify (MechanismId 0x1041) oid "DER" "msg" sig)
  case evres of
    GotValid True -> pure ()
    other -> assertFailure ("bridge ecdsa verify must be true, got " ++ show other)
  -- Unknown mechanisms stay honestly unsupported through the bridge.
  ures <- runEffect env resolve (FxDigest (MechanismId 0x1087) "abc")
  case ures of
    GotCryptoError (CryptoUnsupported _ _) -> pure ()
    other -> assertFailure ("unknown mech must be unsupported, got " ++ show other)
  -- The Backend/Outcome seam survives convergence.
  case encodeResult (GotValid True) of
    O.EngineOkValid True -> pure ()
    other -> assertFailure ("seam must keep verdicts, got " ++ show other)
  case encodeResult (GotBytes "b") of
    O.EngineOkBytes b | b == "b" -> pure ()
    other -> assertFailure ("seam must keep bytes, got " ++ show other)

-- ---------------------------------------------------------------------------
-- The 23-spec block-cipher set
-- ---------------------------------------------------------------------------

-- | Every advertised spec roundtrips at every accepted geometry,
-- refuses off-geometry keys and IVs typed, and stays
-- domain-separated across algorithms sharing a key and IV.
caseCipherSpecs :: IO ()
caseCipherSpecs = withSynth "11" $ \env -> do
  mapM_ (roundtripAll env) cipherSpecSet
  xtsFloor env
  -- ECB takes empty IV only; CBC takes its block.
  expectBadParam "ecb rejects iv" =<<
    cipherEncrypt env C_AES256_ECB key32 "0123456789abcdef" "sixteen bytes xx"
  expectBadParam "cbc rejects empty iv" =<<
    cipherEncrypt env C_AES256_CBC key32 BS.empty "sixteen bytes xx"
  expectBadParam "des3 rejects 16-byte iv" =<<
    cipherEncrypt env C_DES3_CBC des3Key24 "0123456789abcdef" "eight!!!"
  -- Domain separation: AES-128-CBC and ARIA-128-CBC share key and
  -- IV bytes but must not emit the same test ciphertext (and the
  -- same for the ECB pair with empty IVs).
  let k16 = KeyBytes "0123456789abcdef"
      iv16 = "0123456789abcdef"
  aesCt <- expectOk "aes128-cbc" =<<
    cipherEncrypt env C_AES128_CBC k16 iv16 "sixteen bytes xx"
  ariaCt <- expectOk "aria128-cbc" =<<
    cipherEncrypt env C_ARIA128_CBC k16 iv16 "sixteen bytes xx"
  assertBool "cbc algs separated" (aesCt /= ariaCt)
  aesEcb <- expectOk "aes128-ecb" =<<
    cipherEncrypt env C_AES128_ECB k16 BS.empty "sixteen bytes xx"
  ariaEcb <- expectOk "aria128-ecb" =<<
    cipherEncrypt env C_ARIA128_ECB k16 BS.empty "sixteen bytes xx"
  assertBool "ecb algs separated" (aesEcb /= ariaEcb)
  where
    cipherSpecSet :: [CipherSpec]
    cipherSpecSet =
      [ C_AES128_CBC, C_AES192_CBC, C_AES256_CBC
      , C_AES128_CTR, C_AES192_CTR, C_AES256_CTR
      , C_AES128_ECB, C_AES192_ECB, C_AES256_ECB
      , C_DES3_CBC, C_DES3_ECB
      , C_ARIA128_CBC, C_ARIA192_CBC, C_ARIA256_CBC
      , C_ARIA128_ECB, C_ARIA192_ECB, C_ARIA256_ECB
      , C_CAMELLIA128_CBC, C_CAMELLIA192_CBC, C_CAMELLIA256_CBC
      , C_CAMELLIA128_ECB, C_CAMELLIA192_ECB, C_CAMELLIA256_ECB
      , C_AES128_XTS, C_AES256_XTS
      ]
    xtsFloor env = do
      let key = KeyBytes (BS.replicate 32 0x4b)
          tweak = BS.replicate 16 0x77
      expectBadParam "xts rejects short input" =<<
        cipherEncrypt env C_AES128_XTS key tweak "fifteen bytes!!"
    roundtripAll env cspec = mapM_ (roundtripOne env cspec) (cipherKeyLens cspec)
    roundtripOne env cspec keyLen = do
      let key = KeyBytes (BS.replicate keyLen 0x4b)
          iv = BS.replicate (cipherIvLen cspec) 0x77
          plain = "odd-length plaintext, no padding"
          label = show cspec ++ "/" ++ show keyLen
      ct <- expectOk ("encrypt " ++ label) =<<
        cipherEncrypt env cspec key iv plain
      assertEqual ("length-preserving " ++ label) (BS.length plain) (BS.length ct)
      pt <- expectOk ("decrypt " ++ label) =<<
        cipherDecrypt env cspec key iv ct
      assertEqual ("reversible " ++ label) plain pt
      expectBadParam ("short key " ++ label) =<<
        cipherEncrypt env cspec (KeyBytes "short") iv plain

des3Key24 :: KeyMaterial
des3Key24 = KeyBytes "0123456789abcdef01234567"

des3Key24b :: KeyMaterial
des3Key24b = KeyBytes "0123456789abcdef01234566"

des3Key16 :: KeyMaterial
des3Key16 = KeyBytes "0123456789abcdef"

-- ---------------------------------------------------------------------------
-- The RSA v1.5 spec set
-- ---------------------------------------------------------------------------

-- | Every RSA spec roundtrips, rejects tampering and wrong keys, and
-- stays domain-separated across digests and against ECDSA.
caseRsaRoundtrip :: IO ()
caseRsaRoundtrip = withSynth "11" $ \env -> do
  mapM_ (roundtrip env) rsaSpecs
  -- Separation: digests and families never share a test signature
  -- over one key and message.
  s256 <- expectOk "sign sha256" =<< sign env (SigRSA_PKCS1v15 D_SHA256) key32 "msg"
  s512 <- expectOk "sign sha512" =<< sign env (SigRSA_PKCS1v15 D_SHA512) key32 "msg"
  assertBool "digests separated" (s256 /= s512)
  sraw <- expectOk "sign raw" =<< sign env SigRSA_Raw key32 "msg"
  assertBool "raw separated" (sraw /= s256)
  ec <- expectOk "sign ecdsa" =<< sign env ecdsaDer key32 "msg"
  assertBool "families separated" (ec /= s256)
  expectAuthFailed "sha512 sig under sha256 rejected" =<<
    verify env (SigRSA_PKCS1v15 D_SHA256) key32 "msg" s512
  where
    rsaSpecs :: [SigSpec]
    rsaSpecs = SigRSA_Raw :
      [ SigRSA_PKCS1v15 alg
      | alg <- [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
               , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
               , D_RIPEMD160
               ]
      ]
    roundtrip env sspec = do
      let label = show sspec
      sig <- expectOk ("sign " ++ label) =<< sign env sspec key32 "msg"
      assertEqual ("sig length " ++ label) synthSigLength (BS.length sig)
      expectOk ("verify " ++ label) =<< verify env sspec key32 "msg" sig
      expectAuthFailed ("tampered " ++ label) =<<
        verify env sspec key32 "msg" (BS.map complement sig)
      expectAuthFailed ("wrong key " ++ label) =<<
        verify env sspec otherKey32 "msg" sig
      sig2 <- expectOk ("resign " ++ label) =<< sign env sspec key32 "msg"
      assertEqual ("deterministic " ++ label) sig sig2

-- ---------------------------------------------------------------------------
-- RSA-PSS and RSA-OAEP
-- ---------------------------------------------------------------------------

-- | Every PSS shape roundtrips (salts 0/20/32/64, mixed MGFs),
-- tampering and wrong salts fail, and out-of-bound salts stay
-- unsupported.
casePssRoundtrip :: IO ()
casePssRoundtrip = withSynth "11" $ \env -> do
  mapM_ (roundtrip env) pssSpecs
  -- Separation: salts and MGFs never share a test signature.
  s32 <- expectOk "sign salt32" =<<
    sign env (pss D_SHA256 D_SHA256 32) key32 "msg"
  s20 <- expectOk "sign salt20" =<<
    sign env (pss D_SHA256 D_SHA256 20) key32 "msg"
  assertBool "salts separated" (s32 /= s20)
  smgf <- expectOk "sign mgf512" =<<
    sign env (pss D_SHA256 D_SHA512 32) key32 "msg"
  assertBool "mgfs separated" (s32 /= smgf)
  expectAuthFailed "salt20 sig under salt32 rejected" =<<
    verify env (pss D_SHA256 D_SHA256 32) key32 "msg" s20
  -- Bounds: negative and 65+ salts are unsupported, never coerced.
  expectUnsupported "salt 65" =<<
    sign env (pss D_SHA256 D_SHA256 65) key32 "msg"
  expectUnsupported "salt negative" =<<
    sign env (pss D_SHA256 D_SHA256 (-1)) key32 "msg"
  expectUnsupported "xof hash" =<<
    sign env (pss D_SHAKE128 D_SHA256 32) key32 "msg"
  where
    pss h m s = SigRSA_PSS (PssParams h m s)
    pssSpecs :: [SigSpec]
    pssSpecs =
      [ pss D_SHA256 D_SHA256 s | s <- [0, 20, 32, 64] ]
      ++ [ pss D_SHA512 D_SHA256 64
         , pss D_SHA1 D_SHA1 20
         , pss D_SHA3_256 D_SHA3_256 32
         ]
    roundtrip env sspec = do
      let label = show sspec
      sig <- expectOk ("sign " ++ label) =<< sign env sspec key32 "msg"
      assertEqual ("sig length " ++ label) synthSigLength (BS.length sig)
      expectOk ("verify " ++ label) =<< verify env sspec key32 "msg" sig
      expectAuthFailed ("tampered " ++ label) =<<
        verify env sspec key32 "msg" (BS.map complement sig)
      expectAuthFailed ("wrong key " ++ label) =<<
        verify env sspec otherKey32 "msg" sig

-- | OAEP envelopes roundtrip, bind the label/hash/MGF/key, and stay
-- unsupported for XOF hashes.
caseAeadRoundtrip :: IO ()
caseAeadRoundtrip = do
  let aspec = AeadSpec "AES-256-GCM" 12 16
      key = key32
      nonce = "nonce1234567"
  withSynth "11" $ \env -> do
    (ct, tag) <- expectOk "seal" =<< aeadEncrypt env aspec key nonce "aad" "input"
    assertEqual "ct length" 5 (BS.length ct)
    assertEqual "tag length" 16 (BS.length tag)
    pt <- expectOk "open" =<< aeadDecrypt env aspec key nonce "aad" ct tag
    assertEqual "roundtrip" "input" pt
    -- Tampering anywhere fails closed.
    expectAuthFailed "tag tamper" =<<
      aeadDecrypt env aspec key nonce "aad" ct (BS.pack [0] <> BS.drop 1 tag)
    expectAuthFailed "ct tamper" =<<
      aeadDecrypt env aspec key nonce "aad" (BS.pack [0] <> BS.drop 1 ct) tag
    expectAuthFailed "aad tamper" =<<
      aeadDecrypt env aspec key nonce "AAX" ct tag
    expectAuthFailed "nonce tamper" =<<
      aeadDecrypt env aspec key "nonce123456X" "aad" ct tag
    expectAuthFailed "short tag" =<<
      aeadDecrypt env aspec key nonce "aad" ct "short"
    -- Bounds: unknown algs unsupported, short keys bad params.
    expectUnsupported "bad alg" =<<
      aeadEncrypt env (AeadSpec "NOPE" 12 16) key nonce "aad" "input"
    expectBadParam "short key" =<<
      aeadEncrypt env aspec (KeyBytes "short") nonce "aad" "input"
    expectBadParam "short nonce" =<<
      aeadEncrypt env aspec key "short" "aad" "input"
  -- Deterministic across same-seed backends.
  withSynth "11" $ \envA -> withSynth "11" $ \envB -> do
    (ctA, tagA) <- expectOk "seal a" =<< aeadEncrypt envA aspec key nonce "aad" "input"
    (ctB, tagB) <- expectOk "seal b" =<< aeadEncrypt envB aspec key nonce "aad" "input"
    assertEqual "deterministic" (ctA, tagA) (ctB, tagB)

-- | CCM twin of 'caseAeadRoundtrip': the synthetic seal/open path
-- serves AES-CCM with the SP 800-38C widths (nonce 7..13, even
-- tags), fails tampering closed, and stays deterministic.
caseAeadCcmRoundtrip :: IO ()
caseAeadCcmRoundtrip = do
  let aspec = AeadSpec "AES-256-CCM" 12 16
      key = key32
      nonce = "nonce1234567"
  withSynth "11" $ \env -> do
    (ct, tag) <- expectOk "ccm seal" =<< aeadEncrypt env aspec key nonce "aad" "input"
    assertEqual "ccm ct length" 5 (BS.length ct)
    assertEqual "ccm tag length" 16 (BS.length tag)
    pt <- expectOk "ccm open" =<< aeadDecrypt env aspec key nonce "aad" ct tag
    assertEqual "ccm roundtrip" "input" pt
    expectAuthFailed "ccm tag tamper" =<<
      aeadDecrypt env aspec key nonce "aad" ct (BS.pack [0] <> BS.drop 1 tag)
    expectAuthFailed "ccm aad tamper" =<<
      aeadDecrypt env aspec key nonce "AAX" ct tag
    expectBadParam "ccm odd tag" =<<
      aeadEncrypt env (AeadSpec "AES-256-CCM" 12 5) key nonce "aad" "input"
    expectBadParam "ccm short nonce" =<<
      aeadEncrypt env (AeadSpec "AES-256-CCM" 6 16) key "short!" "aad" "input"
  withSynth "11" $ \envA -> withSynth "11" $ \envB -> do
    (ctA, tagA) <- expectOk "ccm seal a" =<< aeadEncrypt envA aspec key nonce "aad" "input"
    (ctB, tagB) <- expectOk "ccm seal b" =<< aeadEncrypt envB aspec key nonce "aad" "input"
    assertEqual "ccm deterministic" (ctA, tagA) (ctB, tagB)

caseOaepRoundtrip :: IO ()
caseOaepRoundtrip = withSynth "11" $ \env -> do
  let sha256 = RsaOaep (OaepParams D_SHA256 D_SHA256 BS.empty)
      labeled = RsaOaep (OaepParams D_SHA256 D_SHA256 "label")
  ct <- expectOk "seal" =<< pkeyEncrypt env sha256 key32 "secret bytes"
  assertEqual "tag growth" (BS.length "secret bytes" + 16) (BS.length ct)
  pt <- expectOk "open" =<< pkeyDecrypt env sha256 key32 ct
  assertEqual "reversible" "secret bytes" pt
  -- Every parameter binds: label, hash, MGF, key, and tampering.
  ctL <- expectOk "seal labeled" =<< pkeyEncrypt env labeled key32 "secret bytes"
  assertBool "label separates" (ctL /= ct)
  ptL <- expectOk "open labeled" =<< pkeyDecrypt env labeled key32 ctL
  assertEqual "labeled reversible" "secret bytes" ptL
  expectAuthFailed "unlabeled open of labeled rejected" =<<
    pkeyDecrypt env sha256 key32 ctL
  expectAuthFailed "wrong hash rejected" =<<
    pkeyDecrypt env (RsaOaep (OaepParams D_SHA512 D_SHA256 BS.empty)) key32 ct
  expectAuthFailed "wrong mgf rejected" =<<
    pkeyDecrypt env (RsaOaep (OaepParams D_SHA256 D_SHA512 BS.empty)) key32 ct
  expectAuthFailed "wrong key rejected" =<<
    pkeyDecrypt env sha256 otherKey32 ct
  expectAuthFailed "tampered rejected" =<<
    pkeyDecrypt env sha256 key32 (BS.map complement ct)
  expectAuthFailed "short rejected" =<<
    pkeyDecrypt env sha256 key32 "short"
  expectAuthFailed "empty rejected" =<<
    pkeyDecrypt env sha256 key32 BS.empty
  -- Empty plaintext still seals (tag-only envelope).
  ct0 <- expectOk "seal empty" =<< pkeyEncrypt env sha256 key32 BS.empty
  assertEqual "empty tag-only" 16 (BS.length ct0)
  pt0 <- expectOk "open empty" =<< pkeyDecrypt env sha256 key32 ct0
  assertEqual "empty reversible" BS.empty pt0

casePkcs1Roundtrip :: IO ()
casePkcs1Roundtrip = withSynth "11" $ \env -> do
  let oaep = RsaOaep (OaepParams D_SHA256 D_SHA256 BS.empty)
  ct <- expectOk "seal" =<< pkeyEncrypt env RsaPkcs1 key32 "secret bytes"
  assertEqual "tag growth" (BS.length "secret bytes" + 16) (BS.length ct)
  pt <- expectOk "open" =<< pkeyDecrypt env RsaPkcs1 key32 ct
  assertEqual "reversible" "secret bytes" pt
  -- Key binds, tampering and truncation fail shut.
  expectAuthFailed "wrong key rejected" =<<
    pkeyDecrypt env RsaPkcs1 otherKey32 ct
  expectAuthFailed "tampered rejected" =<<
    pkeyDecrypt env RsaPkcs1 key32 (BS.map complement ct)
  expectAuthFailed "short rejected" =<<
    pkeyDecrypt env RsaPkcs1 key32 "short"
  -- Padding domains never cross-open: a v1.5 envelope is not
  -- OAEP, and an OAEP envelope is not v1.5.
  ctO <- expectOk "seal oaep" =<< pkeyEncrypt env oaep key32 "secret bytes"
  assertBool "domains separate" (ctO /= ct)
  expectAuthFailed "oaep open of v1.5 rejected" =<<
    pkeyDecrypt env oaep key32 ct
  expectAuthFailed "v1.5 open of oaep rejected" =<<
    pkeyDecrypt env RsaPkcs1 key32 ctO
  -- Empty plaintext still seals (tag-only envelope).
  ct0 <- expectOk "seal empty" =<< pkeyEncrypt env RsaPkcs1 key32 BS.empty
  assertEqual "empty tag-only" 16 (BS.length ct0)
  pt0 <- expectOk "open empty" =<< pkeyDecrypt env RsaPkcs1 key32 ct0
  assertEqual "empty reversible" BS.empty pt0

-- ---------------------------------------------------------------------------
-- ECDSA curves and digests
-- ---------------------------------------------------------------------------

-- | Every (curve, digest-or-raw, encoding) spec roundtrips, rejects
-- tampering and wrong keys, and stays domain-separated across
-- curves, digests, and the P-256/SHA-256 baseline row.
caseDsaRoundtrip :: IO ()
caseDsaRoundtrip = withSynth "11" $ \env -> do
  mapM_ (roundtrip env) dsaSpecs
  -- Separation: digests, encodings, and the raw row never share a
  -- test signature over one key and message.
  s256 <- expectOk "sign sha256" =<< sign env (SigDSA "RAW" (Just D_SHA256)) key32 "msg"
  s512 <- expectOk "sign sha512" =<< sign env (SigDSA "RAW" (Just D_SHA512)) key32 "msg"
  assertBool "digests separated" (s256 /= s512)
  sder <- expectOk "sign der" =<< sign env (SigDSA "DER" (Just D_SHA256)) key32 "msg"
  assertBool "encodings separated" (sder /= s256)
  sraw <- expectOk "sign raw" =<< sign env (SigDSA "RAW" Nothing) key32 (BS.replicate 20 0)
  assertBool "raw separated" (sraw /= s256)
  expectBadParam "raw short refused" =<< sign env (SigDSA "RAW" Nothing) key32 "short"
  expectBadParam "raw short verify refused" =<<
    verify env (SigDSA "RAW" Nothing) key32 "short" sraw
  expectAuthFailed "sha512 sig under sha256 rejected" =<<
    verify env (SigDSA "RAW" (Just D_SHA256)) key32 "msg" s512
  -- Keygen: approved pairs mint opaque params, pairs roundtrip.
  (paramsM, mAgain) <- expectOk "paramgen" =<< generateKey env (GenDSAParams 2048 256)
  assertEqual "params single" Nothing mAgain
  paramsDer <- case paramsM of
    KeyDer der -> pure der
    other -> assertFailure ("params answer is not DER: " ++ show other)
  assertEqual "params length frames (L,N)" (256 + 32 + 256) (BS.length paramsDer)
  (priv, Just pub) <- expectOk "keygen" =<< generateKey env (GenDSAKeypair paramsDer)
  sig <- expectOk "genkey sign" =<< sign env (SigDSA "RAW" (Just D_SHA256)) priv "msg"
  expectOk "genkey verify" =<< verify env (SigDSA "RAW" (Just D_SHA256)) pub "msg" sig
  expectUnsupported "off-pair params refused" =<< generateKey env (GenDSAParams 2048 160)
  where
    dsaSpecs :: [SigSpec]
    dsaSpecs =
      [ SigDSA enc digest
      | enc <- ["DER", "RAW"]
      , digest <- Nothing :
          [ Just alg
          | alg <- [ D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
                   , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
                   ]
          ]
      ]
    roundtrip env sspec = do
      let label = show sspec
          input = case sspec of
            SigDSA _ Nothing -> BS.replicate 20 0xA5
            _ -> "msg"
      sig <- expectOk ("sign " ++ label) =<< sign env sspec key32 input
      assertEqual ("sig length " ++ label) synthSigLength (BS.length sig)
      expectOk ("verify " ++ label) =<< verify env sspec key32 input sig
      expectAuthFailed ("tampered " ++ label) =<<
        verify env sspec key32 input (BS.map complement sig)
      expectAuthFailed ("wrong key " ++ label) =<<
        verify env sspec otherKey32 input sig

-- | Both Edwards curves roundtrip through the synthetic
-- constructions (pure specs only), tampering and wrong keys fail,
-- curves stay domain-separated from each other and from ECDSA,
-- and keygen mints opaque pairs that sign/verify across halves.
caseEddsaRoundtrip :: IO ()
caseEddsaRoundtrip = withSynth "11" $ \env -> do
  mapM_ (roundtrip env) eddsaSpecs
  -- Separation: curves never share a test signature over one key
  -- and message, and EdDSA never collides with ECDSA.
  s19 <- expectOk "sign Ed25519" =<< sign env ed19 key32 "msg"
  s48 <- expectOk "sign Ed448" =<< sign env ed48 key32 "msg"
  assertBool "curves separated" (s19 /= s48)
  ec <- expectOk "sign ecdsa" =<< sign env ecdsaDer key32 "msg"
  assertBool "families separated" (ec /= s19)
  expectAuthFailed "Ed448 sig under Ed25519 rejected" =<<
    verify env ed19 key32 "msg" s48
  -- Keygen: opaque pairs roundtrip across halves.
  (priv, Just pub) <- expectOk "keygen" =<< generateKey env (GenEdDSAKeypair "Ed25519")
  sig <- expectOk "genkey sign" =<< sign env ed19 priv "msg"
  expectOk "genkey verify" =<< verify env ed19 pub "msg" sig
  expectUnsupported "off-set curve refused" =<< generateKey env (GenEdDSAKeypair "P-256")
  where
    ed19 = SigEdDSA (EcSpec "Ed25519" "RAW") ""
    ed48 = SigEdDSA (EcSpec "Ed448" "RAW") ""
    eddsaSpecs :: [SigSpec]
    eddsaSpecs = [ed19, ed48]
    roundtrip env sspec = do
      let label = show sspec
      sig <- expectOk ("sign " ++ label) =<< sign env sspec key32 "msg"
      assertEqual ("sig length " ++ label) synthSigLength (BS.length sig)
      expectOk ("verify " ++ label) =<< verify env sspec key32 "msg" sig
      expectAuthFailed ("tampered " ++ label) =<<
        verify env sspec key32 "msg" (BS.map complement sig)
      expectAuthFailed ("wrong key " ++ label) =<<
        verify env sspec otherKey32 "msg" sig

-- | All three ML-DSA levels roundtrip through the synthetic
-- constructions (both hedges, pure and context modes), tampering
-- and wrong keys fail, levels/contexts/hedges stay
-- domain-separated from each other and from EdDSA, external-mu
-- mode and overlong contexts refuse unsupported, and keygen
-- mints opaque pairs that sign/verify across halves.
caseMldsaRoundtrip :: IO ()
caseMldsaRoundtrip = withSynth "11" $ \env -> do
  mapM_ (roundtrip env) mldsaSpecs
  -- Separation: levels, contexts, and hedges never share a test
  -- signature over one key and message, and ML-DSA never
  -- collides with EdDSA.
  s44 <- expectOk "sign 44" =<< sign env mldsa44 key32 "msg"
  s65 <- expectOk "sign 65" =<< sign env mldsa65 key32 "msg"
  assertBool "levels separated" (s44 /= s65)
  sctx <- expectOk "sign ctx" =<< sign env mldsa44ctx key32 "msg"
  assertBool "contexts separated" (sctx /= s44)
  sdet <- expectOk "sign det" =<< sign env mldsa44det key32 "msg"
  assertBool "hedges separated" (sdet /= s44)
  ed <- expectOk "sign eddsa" =<< sign env ed19 key32 "msg"
  assertBool "families separated" (ed /= s44)
  expectAuthFailed "65 sig under 44 rejected" =<<
    verify env mldsa44 key32 "msg" s65
  expectAuthFailed "ctx sig under pure rejected" =<<
    verify env mldsa44 key32 "msg" sctx
  expectUnsupported "external-mu refused" =<<
    sign env (SigMLDSA ML_DSA_44 True "" True) key32 "msg"
  expectUnsupported "overlong context refused" =<<
    sign env (SigMLDSA ML_DSA_44 False (BS.replicate 256 0) True) key32 "msg"
  expectUnsupported "SLH level refused" =<<
    sign env (SigMLDSA SLH_DSA_SHA2_128s False "" True) key32 "msg"
  -- Keygen: opaque pairs roundtrip across halves.
  (priv, Just pub) <- expectOk "keygen" =<< generateKey env (GenMLDSA ML_DSA_65)
  sig <- expectOk "genkey sign" =<< sign env mldsa65 priv "msg"
  expectOk "genkey verify" =<< verify env mldsa65 pub "msg" sig
  expectUnsupported "off-set level refused" =<< generateKey env (GenMLDSA SLH_DSA_SHA2_128s)
  where
    ed19 = SigEdDSA (EcSpec "Ed25519" "RAW") ""
    mldsa44 = SigMLDSA ML_DSA_44 False "" True
    mldsa65 = SigMLDSA ML_DSA_65 False "" True
    mldsa44ctx = SigMLDSA ML_DSA_44 False "CTX" True
    mldsa44det = SigMLDSA ML_DSA_44 False "" False
    mldsaSpecs :: [SigSpec]
    mldsaSpecs =
      [ SigMLDSA alg False ctx hedged
      | alg <- [ML_DSA_44, ML_DSA_65, ML_DSA_87]
      , ctx <- ["", "CTX"]
      , hedged <- [True, False]
      ]
    roundtrip env sspec = do
      let label = show sspec
      sig <- expectOk ("sign " ++ label) =<< sign env sspec key32 "msg"
      assertEqual ("sig length " ++ label) synthSigLength (BS.length sig)
      expectOk ("verify " ++ label) =<< verify env sspec key32 "msg" sig
      expectAuthFailed ("tampered " ++ label) =<<
        verify env sspec key32 "msg" (BS.map complement sig)
      expectAuthFailed ("wrong key " ++ label) =<<
        verify env sspec otherKey32 "msg" sig

-- | All twelve SLH-DSA sets roundtrip through the synthetic
-- constructions (both hedges, pure and context modes), tampering
-- and wrong keys fail, sets/contexts/hedges stay
-- domain-separated from each other and from ML-DSA, ML-DSA
-- levels and overlong contexts refuse unsupported, and keygen
-- mints opaque pairs that sign/verify across halves.
caseSlhdsaRoundtrip :: IO ()
caseSlhdsaRoundtrip = withSynth "11" $ \env -> do
  mapM_ (roundtrip env) slhdsaSpecs
  -- Separation: sets, contexts, and hedges never share a test
  -- signature over one key and message, and SLH-DSA never
  -- collides with ML-DSA.
  ss <- expectOk "sign 128s" =<< sign env slh128s key32 "msg"
  sf <- expectOk "sign 128f" =<< sign env slh128f key32 "msg"
  assertBool "sets separated" (ss /= sf)
  sctx <- expectOk "sign ctx" =<< sign env slh128sCtx key32 "msg"
  assertBool "contexts separated" (sctx /= ss)
  sdet <- expectOk "sign det" =<< sign env slh128sDet key32 "msg"
  assertBool "hedges separated" (sdet /= ss)
  m44 <- expectOk "sign mldsa" =<< sign env mldsa44 key32 "msg"
  assertBool "families separated" (m44 /= ss)
  expectAuthFailed "128f sig under 128s rejected" =<<
    verify env slh128s key32 "msg" sf
  expectAuthFailed "ctx sig under pure rejected" =<<
    verify env slh128s key32 "msg" sctx
  expectUnsupported "ML-DSA level refused" =<<
    sign env (SigSLHDSA ML_DSA_44 "" True) key32 "msg"
  expectUnsupported "overlong context refused" =<<
    sign env (SigSLHDSA SLH_DSA_SHA2_128s (BS.replicate 256 0) True) key32 "msg"
  -- Keygen: opaque pairs roundtrip across halves.
  (priv, Just pub) <- expectOk "keygen" =<< generateKey env (GenSLHDSA SLH_DSA_SHAKE_256f)
  sig <- expectOk "genkey sign" =<< sign env slhShake256f priv "msg"
  expectOk "genkey verify" =<< verify env slhShake256f pub "msg" sig
  expectUnsupported "off-set level refused" =<< generateKey env (GenSLHDSA ML_DSA_44)
  where
    mldsa44 = SigMLDSA ML_DSA_44 False "" True
    slh128s = SigSLHDSA SLH_DSA_SHA2_128s "" True
    slh128f = SigSLHDSA SLH_DSA_SHA2_128f "" True
    slh128sCtx = SigSLHDSA SLH_DSA_SHA2_128s "CTX" True
    slh128sDet = SigSLHDSA SLH_DSA_SHA2_128s "" False
    slhShake256f = SigSLHDSA SLH_DSA_SHAKE_256f "" True
    slhdsaSpecs :: [SigSpec]
    slhdsaSpecs =
      [ SigSLHDSA alg ctx hedged
      | alg <- slhdsaSets
      , ctx <- ["", "CTX"]
      , hedged <- [True, False]
      ]
    roundtrip env sspec = do
      let label = show sspec
      sig <- expectOk ("sign " ++ label) =<< sign env sspec key32 "msg"
      assertEqual ("sig length " ++ label) synthSigLength (BS.length sig)
      expectOk ("verify " ++ label) =<< verify env sspec key32 "msg" sig
      expectAuthFailed ("tampered " ++ label) =<<
        verify env sspec key32 "msg" (BS.map complement sig)
      expectAuthFailed ("wrong key " ++ label) =<<
        verify env sspec otherKey32 "msg" sig

caseEcdsaCurves :: IO ()
caseEcdsaCurves = withSynth "11" $ \env -> do
  mapM_ (roundtrip env) ecdsaSpecs
  -- Separation: curves, digests, and the raw row never share a test
  -- signature over one key and message.
  s256 <- expectOk "sign p256" =<< sign env ecdsaDer key32 "msg"
  s384 <- expectOk "sign p384" =<<
    sign env (SigECDSA (EcSpec "P-384" "DER") (Just D_SHA256)) key32 "msg"
  assertBool "curves separated" (s256 /= s384)
  s512 <- expectOk "sign sha512" =<<
    sign env (SigECDSA (EcSpec "P-256" "DER") (Just D_SHA512)) key32 "msg"
  assertBool "digests separated" (s256 /= s512)
  sraw <- expectOk "sign raw" =<<
    sign env (SigECDSA (EcSpec "P-256" "DER") Nothing) key32 "msg"
  assertBool "raw separated" (sraw /= s256)
  expectAuthFailed "p384 sig under p256 rejected" =<<
    verify env ecdsaDer key32 "msg" s384
  where
    ecdsaSpecs :: [SigSpec]
    ecdsaSpecs =
      [ SigECDSA (EcSpec curve enc) digest
      | curve <- coveredCurveNames
      , enc <- ["DER", "RAW"]
      , digest <- Nothing :
          [ Just alg
          | alg <- [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
                   , D_SHA512_224, D_SHA512_256
                   , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
                   , D_RIPEMD160
                   , D_BLAKE2B512
                   ]
          ]
      ]
    roundtrip env sspec = do
      let label = show sspec
      sig <- expectOk ("sign " ++ label) =<< sign env sspec key32 "msg"
      assertEqual ("sig length " ++ label) synthSigLength (BS.length sig)
      expectOk ("verify " ++ label) =<< verify env sspec key32 "msg" sig
      expectAuthFailed ("tampered " ++ label) =<<
        verify env sspec key32 "msg" (BS.map complement sig)
      expectAuthFailed ("wrong key " ++ label) =<<
        verify env sspec otherKey32 "msg" sig
      sig2 <- expectOk ("resign " ++ label) =<< sign env sspec key32 "msg"
      assertEqual ("deterministic " ++ label) sig sig2

-- ---------------------------------------------------------------------------
-- ECDH agreement
-- ---------------------------------------------------------------------------

-- | Agreements replay deterministically at the 72-byte max width and
-- stay domain-separated across bases, peers, and the cofactor bit.
-- Opaque key bytes are served (no key parsing in synthetic).
caseEcdh :: IO ()
caseEcdh = withSynth "11" $ \env -> do
  let peer = KeyBytes "peer-public-bytes-0123456789abcdef"
      other = KeyBytes "other-peer-bytes-0123456789abcdef"
  s1 <- expectOk "derive" =<< ecdhDerive env EcdhPlain key32 peer
  assertEqual "max width" synthEcdhWidth (BS.length s1)
  s2 <- expectOk "rederive" =<< ecdhDerive env EcdhPlain key32 peer
  assertEqual "deterministic" s1 s2
  sPeer <- expectOk "other peer" =<< ecdhDerive env EcdhPlain key32 other
  assertBool "peers separated" (s1 /= sPeer)
  sBase <- expectOk "other base" =<< ecdhDerive env EcdhPlain otherKey32 peer
  assertBool "bases separated" (s1 /= sBase)
  sCof <- expectOk "cofactor" =<< ecdhDerive env EcdhCofactor key32 peer
  assertBool "cofactor separated" (s1 /= sCof)
  assertEqual "cofactor width" synthEcdhWidth (BS.length sCof)
  sDer <- expectOk "der halves served" =<<
    ecdhDerive env EcdhPlain (KeyDer "priv-half") (KeyDer "pub-half")
  assertEqual "der width" synthEcdhWidth (BS.length sDer)

-- ---------------------------------------------------------------------------
-- CMAC composition
-- ---------------------------------------------------------------------------

-- | CMAC through the driver over synthetic ECB: deterministic tags at
-- full block width, GENERAL truncation is the prefix, keys/messages
-- separate, verify verdicts, and off-geometry triples refuse typed.
caseCmac :: IO ()
caseCmac = withSynth "11" $ \env -> do
  let aesMech = MechanismId 0x108a
      aesGen = MechanismId 0x108b
      d3Mech = MechanismId 0x138
      d3Gen = MechanismId 0x137
      kOid = ObjectId 51
      badOid = ObjectId 52
      d3Oid = ObjectId 53
      shortOid = ObjectId 54
      res oid
        | oid == kOid = Just key32
        | oid == badOid = Just otherKey32
        | oid == d3Oid = Just des3Key24
        | oid == shortOid = Just (KeyBytes "fifteen bytes!!")
        | otherwise = Nothing
      signAs mech oid params msg =
        runEffect env res (FxSign mech (Just oid) params msg) >>= expectBytes
  t1 <- signAs aesMech kOid BS.empty "hello cmac world, hello!"
  assertEqual "aes full width" 16 (BS.length t1)
  t2 <- signAs aesMech kOid BS.empty "hello cmac world, hello!"
  assertEqual "deterministic" t1 t2
  tOther <- signAs aesMech badOid BS.empty "hello cmac world, hello!"
  assertBool "keys separated" (t1 /= tOther)
  tMsg <- signAs aesMech kOid BS.empty "hello cmac world, hello?"
  assertBool "messages separated" (t1 /= tMsg)
  tEmpty <- signAs aesMech kOid BS.empty BS.empty
  assertEqual "empty width" 16 (BS.length tEmpty)
  -- GENERAL truncation is the tag prefix; bounds enforced.
  g8 <- signAs aesGen kOid (encodeMacGeneral 8) "hello cmac world, hello!"
  assertEqual "truncation is the prefix" (BS.take 8 t1) g8
  vGen <- runEffect env res (FxVerify aesGen (Just kOid) (encodeMacGeneral 8)
    "hello cmac world, hello!" g8)
  assertEqual "general verifies" (GotValid True) vGen
  badLen <- runEffect env res (FxSign aesGen (Just kOid) (encodeMacGeneral 17)
    "hello cmac world, hello!")
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  -- Verify verdicts.
  vGood <- runEffect env res (FxVerify aesMech (Just kOid) BS.empty
    "hello cmac world, hello!" t1)
  assertEqual "verifies" (GotValid True) vGood
  vBad <- runEffect env res (FxVerify aesMech (Just kOid) BS.empty
    "hello cmac world, hello!" (BS.map (255 -) t1))
  assertEqual "tamper rejects" (GotValid False) vBad
  vKey <- runEffect env res (FxVerify aesMech (Just badOid) BS.empty
    "hello cmac world, hello!" t1)
  assertEqual "wrong key rejects" (GotValid False) vKey
  -- Off-geometry triples refuse typed.
  badParams <- runEffect env res (FxSign aesMech (Just kOid) "x"
    "hello cmac world, hello!")
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badKey <- runEffect env res (FxSign aesMech (Just shortOid) BS.empty
    "hello cmac world, hello!")
  case badKey of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  -- 3DES path at the 8-byte width, GENERAL capped at 8.
  d1 <- signAs d3Mech d3Oid BS.empty "twenty bytes of input!!"
  assertEqual "des3 width" 8 (BS.length d1)
  dg <- signAs d3Gen d3Oid (encodeMacGeneral 8) "twenty bytes of input!!"
  assertEqual "des3 full trunc" d1 dg
  dg9 <- runEffect env res (FxSign d3Gen (Just d3Oid) (encodeMacGeneral 9)
    "twenty bytes of input!!")
  case dg9 of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | 3DES-MAC through the driver over synthetic ECB:
-- deterministic 4-byte half-block tags on the plain row,
-- GENERAL truncation is the prefix, keys/messages separate,
-- verify verdicts, and off-geometry triples refuse typed.
caseDes3mac :: IO ()
caseDes3mac = withSynth "11" $ \env -> do
  let macMech = MechanismId 0x134
      macGen = MechanismId 0x135
      kOid = ObjectId 55
      badOid = ObjectId 56
      k2Oid = ObjectId 57
      shortOid = ObjectId 58
      res oid
        | oid == kOid = Just des3Key24
        | oid == badOid = Just des3Key24b
        | oid == k2Oid = Just des3Key16
        | oid == shortOid = Just (KeyBytes "fifteen bytes!!")
        | otherwise = Nothing
      signAs mech oid params msg =
        runEffect env res (FxSign mech (Just oid) params msg) >>= expectBytes
      msg = "twenty bytes of input!!"
  t1 <- signAs macMech kOid BS.empty msg
  assertEqual "plain half width" 4 (BS.length t1)
  t2 <- signAs macMech kOid BS.empty msg
  assertEqual "deterministic" t1 t2
  tOther <- signAs macMech badOid BS.empty msg
  assertBool "keys separated" (t1 /= tOther)
  tMsg <- signAs macMech kOid BS.empty "?wenty bytes of input!!"
  assertBool "messages separated" (t1 /= tMsg)
  tEmpty <- signAs macMech kOid BS.empty BS.empty
  assertEqual "empty width" 4 (BS.length tEmpty)
  -- GENERAL truncation is the tag prefix; bounds enforced.
  g8 <- signAs macGen kOid (encodeMacGeneral 8) msg
  assertEqual "truncation width" 8 (BS.length g8)
  assertEqual "half is the prefix" t1 (BS.take 4 g8)
  vGen <- runEffect env res (FxVerify macGen (Just kOid) (encodeMacGeneral 8)
    msg g8)
  assertEqual "general verifies" (GotValid True) vGen
  badLen <- runEffect env res (FxSign macGen (Just kOid) (encodeMacGeneral 9)
    msg)
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  -- Verify verdicts.
  vGood <- runEffect env res (FxVerify macMech (Just kOid) BS.empty msg t1)
  assertEqual "verifies" (GotValid True) vGood
  vBad <- runEffect env res (FxVerify macMech (Just kOid) BS.empty msg
    (BS.map (255 -) t1))
  assertEqual "tamper rejects" (GotValid False) vBad
  vKey <- runEffect env res (FxVerify macMech (Just badOid) BS.empty msg t1)
  assertEqual "wrong key rejects" (GotValid False) vKey
  -- Off-geometry triples refuse typed.
  badParams <- runEffect env res (FxSign macMech (Just kOid) "x" msg)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badKey <- runEffect env res (FxSign macMech (Just shortOid) BS.empty msg)
  case badKey of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  -- Two-key path serves at the half width.
  tagHalf <- signAs macMech k2Oid BS.empty msg
  assertEqual "two-key width" 4 (BS.length tagHalf)

-- ---------------------------------------------------------------------------
-- KDF constructions
-- ---------------------------------------------------------------------------

-- | PBKDF2 and SHA-KD through the driver over synthetic digests:
-- deterministic output, separated across passwords/salts/params,
-- truncation is the prefix, per-row widths, and typed refusals.
caseKdf :: IO ()
caseKdf = withSynth "11" $ \env -> do
  let pbkd2 = MechanismId 0x3b0
      sha256kd = MechanismId 0x393
      pwOid = ObjectId 71
      otherOid = ObjectId 72
      res oid
        | oid == pwOid = Just (KeyBytes "password")
        | oid == otherOid = Just (KeyBytes "otherpass")
        | otherwise = Nothing
      derive oid mech params outLen =
        runEffect env res (FxDerive mech (Just oid) params BS.empty outLen)
          >>= expectBytes
      prfSha256 = 4
  d1 <- derive pwOid pbkd2 (encodePbkd2Params prfSha256 2 "salt") 32
  assertEqual "dk length" 32 (BS.length d1)
  d2 <- derive pwOid pbkd2 (encodePbkd2Params prfSha256 2 "salt") 32
  assertEqual "deterministic" d1 d2
  dSalt <- derive pwOid pbkd2 (encodePbkd2Params prfSha256 2 "pepper") 32
  assertBool "salts separated" (d1 /= dSalt)
  dPw <- derive otherOid pbkd2 (encodePbkd2Params prfSha256 2 "salt") 32
  assertBool "passwords separated" (d1 /= dPw)
  dIt <- derive pwOid pbkd2 (encodePbkd2Params prfSha256 3 "salt") 32
  assertBool "iterations separated" (d1 /= dIt)
  dPrf <- derive pwOid pbkd2 (encodePbkd2Params 6 2 "salt") 32
  assertBool "prfs separated" (d1 /= dPrf)
  dBig <- derive pwOid pbkd2 (encodePbkd2Params prfSha256 2 "salt") 48
  assertEqual "multi-block prefix" d1 (BS.take 32 dBig)
  trunc16 <- derive pwOid pbkd2 (encodePbkd2Params prfSha256 2 "salt") 16
  assertEqual "truncation prefix" (BS.take 16 d1) trunc16
  -- SHA-KD rows at digest width.
  s32 <- derive pwOid sha256kd BS.empty 32
  assertEqual "sha256 width" 32 (BS.length s32)
  s20 <- derive pwOid (MechanismId 0x392) BS.empty 20
  assertEqual "sha1 width" 20 (BS.length s20)
  u28 <- derive pwOid (MechanismId 0x4b) BS.empty 28
  assertEqual "sha512/224 width" 28 (BS.length u28)
  -- Typed refusals.
  badPrf <- runEffect env res
    (FxDerive pbkd2 (Just pwOid) (encodePbkd2Params 99 1 "s") BS.empty 32)
  case badPrf of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badLen <- runEffect env res
    (FxDerive sha256kd (Just pwOid) BS.empty BS.empty 33)
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badInfo <- runEffect env res
    (FxDerive sha256kd (Just pwOid) BS.empty "x" 32)
  case badInfo of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | TLS-PRF through the driver over synthetic HMAC-MD5\/SHA-1:
-- deterministic output, separated across secrets\/labels\/seeds,
-- truncation is the prefix, even and odd secrets both serve, and
-- typed refusals. (The synthetic MAC stream differs from real HMAC
-- by design; exact KAT bytes live on the real backend.)
caseTlsPrf :: IO ()
caseTlsPrf = withSynth "11" $ \env -> do
  let tlsPrf = MechanismId 0x378
      secOid = ObjectId 74
      oddOid = ObjectId 75
      res oid
        | oid == secOid = Just (KeyBytes (BS.pack [0 .. 47]))
        | oid == oddOid = Just (KeyBytes (BS.pack [0 .. 46]))
        | otherwise = Nothing
      deriveAs oid params outLen =
        runEffect env res (FxDerive tlsPrf (Just oid) params BS.empty outLen)
          >>= expectBytes
      params = encodeTlsPrfParams "test label" "0123456789abcdef"
  d1 <- deriveAs secOid params 48
  assertEqual "output length" 48 (BS.length d1)
  d2 <- deriveAs secOid params 48
  assertEqual "deterministic" d1 d2
  dOdd <- deriveAs oddOid params 48
  assertBool "secrets separated" (d1 /= dOdd)
  dLab <- deriveAs secOid (encodeTlsPrfParams "other label" "0123456789abcdef") 48
  assertBool "labels separated" (d1 /= dLab)
  dSeed <- deriveAs secOid (encodeTlsPrfParams "test label" "0123456789abcdee") 48
  assertBool "seeds separated" (d1 /= dSeed)
  trunc16 <- deriveAs secOid params 16
  assertEqual "truncation prefix" (BS.take 16 d1) trunc16
  dBig <- deriveAs secOid params 64
  assertEqual "multi-block prefix" d1 (BS.take 48 dBig)
  -- Typed refusals.
  badParams <- runEffect env res
    (FxDerive tlsPrf (Just secOid) "junk" BS.empty 48)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badInfo <- runEffect env res
    (FxDerive tlsPrf (Just secOid) params "x" 48)
  case badInfo of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badLen <- runEffect env res
    (FxDerive tlsPrf (Just secOid) params BS.empty 0)
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- ---------------------------------------------------------------------------
-- OTP constructions
-- ---------------------------------------------------------------------------

-- | HOTP through the driver over synthetic HMAC-SHA1: ASCII digit
-- shape at the requested width, deterministic codes separated across
-- counters\/keys\/widths, verify verdicts, message variants, typed
-- refusals, and HOTP keygen lengths through the driver plus the
-- backend gate. (The synthetic MAC stream differs from real
-- HMAC-SHA1 by design; exact KAT bytes live on the real backend.)
caseHotp :: IO ()
caseHotp = withSynth "13" $ \env -> do
  let hotpMech = MechanismId 0x291
      kOid = ObjectId 81
      badOid = ObjectId 82
      shortOid = ObjectId 83
      res oid
        | oid == kOid = Just (KeyBytes "12345678901234567890")
        | oid == badOid = Just (KeyBytes "12345678901234567891")
        | oid == shortOid = Just (KeyBytes "short")
        | otherwise = Nothing
      codeAs oid c d =
        runEffect env res (FxSign hotpMech (Just oid) (encodeHotpParams c d) BS.empty)
          >>= expectBytes
      isDigits bs = not (BS.null bs)
        && BS.all (\w -> w >= 48 && w <= 57) bs
      -- Every digit plus one mod 10: guaranteed different, still digits.
      tamper = BS.map (\w -> 48 + ((w - 48 + 1) `mod` 10))
  c0 <- codeAs kOid 0 6
  assertEqual "6-digit width" 6 (BS.length c0)
  assertBool "ascii digits" (isDigits c0)
  c0b <- codeAs kOid 0 6
  assertEqual "deterministic" c0 c0b
  c1 <- codeAs kOid 1 6
  assertBool "counters separated" (c0 /= c1)
  c7 <- codeAs kOid 0 7
  assertEqual "7-digit width" 7 (BS.length c7)
  assertBool "7-digit shape" (isDigits c7)
  c8 <- codeAs kOid 0 8
  assertEqual "8-digit width" 8 (BS.length c8)
  assertBool "8-digit shape" (isDigits c8)
  ck <- codeAs badOid 0 6
  assertBool "keys separated" (c0 /= ck)
  cs <- codeAs shortOid 0 6
  assertEqual "short key still codes" 6 (BS.length cs)
  -- Counter boundaries execute at full width.
  cMax <- codeAs kOid 0xffffffffffffffff 6
  assertEqual "max counter width" 6 (BS.length cMax)
  assertBool "max counter digits" (isDigits cMax)
  cTop <- codeAs kOid 0xffffffff 8
  assertEqual "2^32-1 8-digit width" 8 (BS.length cTop)
  assertBool "2^32-1 8-digit shape" (isDigits cTop)
  -- Verify verdicts.
  vGood <- runEffect env res
    (FxVerify hotpMech (Just kOid) (encodeHotpParams 0 6) BS.empty c0)
  assertEqual "verifies" (GotValid True) vGood
  vBad <- runEffect env res
    (FxVerify hotpMech (Just kOid) (encodeHotpParams 0 6) BS.empty (tamper c0))
  assertEqual "tamper rejects" (GotValid False) vBad
  vKey <- runEffect env res
    (FxVerify hotpMech (Just badOid) (encodeHotpParams 0 6) BS.empty c0)
  assertEqual "wrong key rejects" (GotValid False) vKey
  vCounter <- runEffect env res
    (FxVerify hotpMech (Just kOid) (encodeHotpParams 1 6) BS.empty c0)
  assertEqual "wrong counter rejects" (GotValid False) vCounter
  -- Message variants agree.
  m0 <- runEffect env res
    (FxMessageSign hotpMech (Just kOid) (encodeHotpParams 0 6) BS.empty)
    >>= expectBytes
  assertEqual "message agrees" c0 m0
  mv <- runEffect env res
    (FxMessageVerify hotpMech (Just kOid) (encodeHotpParams 0 6) BS.empty c0)
  assertEqual "message verifies" (GotValid True) mv
  -- Typed refusals: any input, bad digits, malformed params.
  badInput <- runEffect env res
    (FxSign hotpMech (Just kOid) (encodeHotpParams 0 6) "x")
  case badInput of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badMsg <- runEffect env res
    (FxMessageSign hotpMech (Just kOid) (encodeHotpParams 0 6) "x")
  case badMsg of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badDigits <- runEffect env res
    (FxSign hotpMech (Just kOid) (encodeHotpParams 0 9) BS.empty)
  case badDigits of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badParams <- runEffect env res
    (FxSign hotpMech (Just kOid) "x" BS.empty)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  -- Keygen through the driver: framed lengths, counter separation.
  let gen n = runEffect env res
        (FxGenerateKey hotpKeyGenMech BS.empty (encodeGenArgs (GenBytes n)))
        >>= expectBytes
      expectLen label want framed = case decodeKeyPair framed of
        Just (priv, Nothing) -> assertEqual label want (BS.length priv)
        other -> assertFailure (label ++ ": " ++ show other)
  g16 <- gen 16
  expectLen "16 bytes" 16 g16
  g20 <- gen 20
  expectLen "20 bytes" 20 g20
  g64 <- gen 64
  expectLen "64 bytes" 64 g64
  g20b <- gen 20
  assertBool "generation counter advances" (g20 /= g20b)
  badLen <- runEffect env res
    (FxGenerateKey hotpKeyGenMech BS.empty (encodeGenArgs (GenBytes 8)))
  case badLen of
    -- The backend BadParam arrives with its category intact
    -- (same CKR_GENERAL_ERROR as the old collapse).
    GotCryptoError (CryptoBadParam _ _) -> pure ()
    other -> assertFailure ("expected BadParam, got: " ++ show other)
  badLen2 <- runEffect env res
    (FxGenerateKey hotpKeyGenMech BS.empty (encodeGenArgs (GenBytes 65)))
  case badLen2 of
    GotCryptoError (CryptoBadParam _ _) -> pure ()
    other -> assertFailure ("expected BadParam, got: " ++ show other)
  -- Backend gate, direct: lengths, determinism on seed and sequence.
  (KeyBytes h20, Nothing) <- expectOk "hotp backend" =<<
    generateKey env (GenSym "HOTP" 20)
  assertEqual "backend length" 20 (BS.length h20)
  expectBadParam "hotp-15 rejected" =<< generateKey env (GenSym "HOTP" 15)
  expectBadParam "hotp-65 rejected" =<< generateKey env (GenSym "HOTP" 65)
  expectBadParam "hotp-0 rejected" =<< generateKey env (GenSym "HOTP" 0)
  (KeyBytes g32, Nothing) <- expectOk "generic backend" =<<
    generateKey env (GenSym "GENERIC" 32)
  assertEqual "generic length" 32 (BS.length g32)
  expectBadParam "generic-0 rejected" =<< generateKey env (GenSym "GENERIC" 0)
  expectBadParam "generic-256 rejected" =<< generateKey env (GenSym "GENERIC" 256)
  (KeyBytes d24, Nothing) <- expectOk "des3 backend" =<<
    generateKey env (GenSym "DES3" 24)
  assertEqual "des3 length" 24 (BS.length d24)
  (KeyBytes d16, Nothing) <- expectOk "des3 two-key backend" =<<
    generateKey env (GenSym "DES3" 16)
  assertEqual "des3 two-key length" 16 (BS.length d16)
  expectBadParam "des3-15 rejected" =<< generateKey env (GenSym "DES3" 15)
  expectBadParam "des3-32 rejected" =<< generateKey env (GenSym "DES3" 32)
  envA <- openSynth "13"
  envB <- openSynth "13"
  (KeyBytes a1, Nothing) <- expectOk "hotp seed a" =<<
    generateKey envA (GenSym "HOTP" 20)
  (KeyBytes b1, Nothing) <- expectOk "hotp seed b" =<<
    generateKey envB (GenSym "HOTP" 20)
  assertEqual "same seed same key" a1 b1
  (KeyBytes aes16, Nothing) <- expectOk "aes seed a" =<<
    generateKey envA (GenSym "AES" 16)
  (KeyBytes hotp16, Nothing) <- expectOk "hotp seed a" =<<
    generateKey envB (GenSym "HOTP" 16)
  assertBool "HOTP stream domain-separated from AES"
    (aes16 /= hotp16)

-- ---------------------------------------------------------------------------
-- Specials refuse explicitly
-- ---------------------------------------------------------------------------

-- | Every reviewed gap group refuses at the driver with typed
-- 'CryptoUnsupported' (never success, never a silent verdict):
-- stateful exhaustion (sign\/verify\/keygen), unknown-semantics and
-- historical specials, absent-provider primitives, unmapped
-- surfaces, and both recovery effects. Backends never see these
-- effects (driver-otherwise).
caseSpecialsRefuse :: IO ()
caseSpecialsRefuse = withSynth "15" $ \env -> do
  let kOid = ObjectId 91
      res oid
        | oid == kOid = Just (KeyBytes "12345678901234567890")
        | otherwise = Nothing
      mech = MechanismId . mustGeneratedId
      refused label fx = do
        r <- runEffect env res fx
        case r of
          GotCryptoError (CryptoUnsupported _ _) -> pure ()
          other -> assertFailure (label ++ ": expected Unsupported, got: " ++ show other)
      mkSign name = FxSign (mech name) (Just kOid) BS.empty BS.empty
      mkVerify name = FxVerify (mech name) (Just kOid) BS.empty BS.empty BS.empty
      keygen name args = FxGenerateKey (mech name) BS.empty (encodeGenArgs args)
  -- Stateful exhaustion: one-time key state the engine cannot
  -- advance (see source-issues.json GAP-OTP-STATEFUL).
  mapM_ (\name -> do
    refused ("sign " ++ T.unpack name) (mkSign name)
    refused ("verify " ++ T.unpack name) (mkVerify name)
    ) ["CKM_XMSS", "CKM_XMSSMT", "CKM_HSS"]
  mapM_ (\name -> refused ("keygen " ++ T.unpack name) (keygen name (GenBytes 32)))
    ["CKM_XMSS_KEY_PAIR_GEN", "CKM_XMSSMT_KEY_PAIR_GEN", "CKM_HSS_KEY_PAIR_GEN"]
  -- Unknown-semantics / proprietary / historical specials.
  refused "sign ACTI" (mkSign "CKM_ACTI")
  refused "keygen ACTI" (keygen "CKM_ACTI_KEY_GEN" (GenBytes 32))
  refused "sign SECURID" (mkSign "CKM_SECURID")
  refused "sign CMS_SIG" (mkSign "CKM_CMS_SIG")
  refused "sign FORTEZZA" (mkSign "CKM_FORTEZZA_TIMESTAMP")
  refused "digest FASTHASH" (FxDigest (mech "CKM_FASTHASH") BS.empty)
  refused "digest NULL" (FxDigest (mech "CKM_NULL") BS.empty)
  refused "digest VENDOR" (FxDigest (mech "CKM_VENDOR_DEFINED") BS.empty)
  -- Absent-provider primitives (pinned-CLI survey).
  refused "cipher DES" (FxCipher DirEncrypt (mech "CKM_DES_CBC") (Just kOid) BS.empty BS.empty)
  refused "cipher RC4" (FxCipher DirEncrypt (mech "CKM_RC4") (Just kOid) BS.empty BS.empty)
  -- Present-but-unmapped surfaces (needs a Raw entry point).
  -- GCM left this group when the AEAD entry points landed (see
  -- caseAeadRoundtrip); AES-KW left it when the wrap entry point
  -- landed (see caseCipherSpecs and the OpenSSLSpec wrap KATs);
  -- DSA left it when the DSA entry points landed (see
  -- caseDsaRoundtrip and the OpenSSLSpec DSA KATs); ML-DSA left
  -- it when the ML-DSA entry points landed (see caseMldsaRoundtrip
  -- and the OpenSSLSpec ML-DSA KATs); SLH-DSA left it when the
  -- SLH-DSA entry points landed (see caseSlhdsaRoundtrip and the
  -- OpenSSLSpec SLH-DSA KATs); TLS-PRF left it when the driver
  -- composition over the HMAC routes landed (see caseTlsPrf and
  -- the RoutingE2ESpec TLS-PRF KATs); empty GCM
  -- params still fail typed at the driver (CryptoFailed recipe
  -- refusal, pinned below).
  refused "derive DH" (FxDerive (mech "CKM_DH_PKCS_DERIVE") (Just kOid) BS.empty BS.empty 32)
  -- Recovery effects refuse on synthetic exactly as on real.
  refused "sign-recover"
    (FxSignRecover (mech "CKM_SHA256_HMAC") (Just kOid) BS.empty BS.empty 4)
  refused "verify-recover"
    (FxVerifyRecover (mech "CKM_SHA256_HMAC") (Just kOid) BS.empty BS.empty 4)
  -- GCM with empty params: mapped but recipe-refused (typed
  -- 'CryptoFailed', never 'CryptoUnsupported', never success).
  rGcm <- runEffect env res
    (FxCipher DirEncrypt (mech "CKM_AES_GCM") (Just kOid) BS.empty BS.empty)
  case rGcm of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("cipher GCM empty params: expected Failed, got: " ++ show other)
