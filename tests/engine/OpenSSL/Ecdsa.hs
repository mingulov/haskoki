{- | OpenSSL ECDSA cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Ecdsa
  ( caseEcdsaCurvesVectors
  , caseEcdsaInfinity
  , caseEcdsaKat
  , caseEcdsaOddSig
  , caseEcdsaOffCurve
  , caseEcdsaRawTruncate
  , caseEcdsaRoundtrip
  , caseEcdsaShortForms
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Engine.Backend
  ( CryptoBackend (..)
  , DigestAlg (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , SigSpec (..)
  )
import OpenSSL.Fixtures

-- P-384/SHA-384, P-521/SHA-512, and raw-P-256 interop
-- vectors (OpenSSL 4.0.2 CLI; the raw vector reuses the P-256 key from
-- the fixtures above), plus one vector per new curve family
-- (Koblitz secp256k1, brainpoolP256r1, binary sect283r1).
-- ECDSA is randomized, so the suite verifies the CLI's bytes
-- (proving interop) and roundtrips its own. All vectors were
-- CLI-verified before embedding.
ecMsgK256 :: ByteString
ecMsgK256 = "T16 curves ECDSA secp256k1 message"

ecK256Pub :: ByteString
ecK256Pub = hex $ concat
  [ "3056301006072a8648ce3d020106052b8104000a03420004e352f674324827b1f8"
  , "37300d5895a22acc9525bbe6870870be10da08c1a86564d459a356f3c940fbc11f"
  , "dc99b1c14b1fd066cc5b70c0ce2f5da36c98cc21302d"
  ]

ecSigK256 :: ByteString
ecSigK256 = hex $ concat
  [ "3045022100a090d3cf9830d5119cbb22ad47643819af723a45b140be25f65bb324"
  , "3d1c927402207e2d68f4e8c18d57964f8fcc6613f4f8882653b1661db1abf3fb62"
  , "18b308f745"
  ]

ecMsgBp256 :: ByteString
ecMsgBp256 = "T16 curves ECDSA brainpoolP256r1 message"

ecBp256Pub :: ByteString
ecBp256Pub = hex $ concat
  [ "305a301406072a8648ce3d020106092b2403030208010107034200040bd5b550aad"
  , "747b0cc578ac7b16b0def74c510abaad293e37782316101d9bb5d6f22ed582fd49b"
  , "5624c612eeb556710ebd8cbf479748d717ee3af83e7956cf6a"
  ]

ecSigBp256 :: ByteString
ecSigBp256 = hex $ concat
  [ "304402207462de59f25d911fef3f6fa57abe9476583c61b6fccbaa25a5fb88ea27c"
  , "c18cd02203750f9012d446286c257337fc1bc6a5d43d27a1913eab536eb78c828fb"
  , "79d3ed"
  ]

ecMsgT283 :: ByteString
ecMsgT283 = "T16 curves ECDSA sect283r1 message"

ecT283Pub :: ByteString
ecT283Pub = hex $ concat
  [ "305e301006072a8648ce3d020106052b81040011034a00040776c09667a56b6f058"
  , "5fd97a89be7cf0210f279264f8e3a4429835000951148fbed79ec03ca63c04605c1"
  , "dbac6efc38b97d99af003eafe001febbefbdbce33d5b9ea34f2d8a5d6b"
  ]

ecSigT283 :: ByteString
ecSigT283 = hex $ concat
  [ "304c0224027d44ac97d49f193cf0ffee770a5a7a1e2e046ddb3452276fabb32d9fe"
  , "7fcfc3fbd014202240371cf18faf7654c4b0a5a6d902295e72859d9fadee6498084"
  , "8236a12832177883e388c6"
  ]

ecMsg384 :: ByteString
ecMsg384 = "T16 S9 ECDSA P-384/SHA384 message"

ecP384Pub :: ByteString
ecP384Pub = hex $ concat
  [ "3076301006072a8648ce3d020106052b8104002203620004467ab2e9c927f143"
  , "e9f6151006e492da4d11c9e079e339f6086dfd988bd0cac51e25adf31d504a7c"
  , "730a94c1c4b3bb880cffcceaf56ebc0c1a42e04051e8d11e409440f6a4924c1c"
  , "fea44e8858601cd2a041d7340fe670712e91ca3ec5389a0c"
  ]

ecSig384 :: ByteString
ecSig384 = hex $ concat
  [ "306502301745214d2dd601618123d12577281adfd877401da97434930c6be638"
  , "71069f00aa881a2c7552d1a6cd11964d962d35ec0231009aa7912604646cd498"
  , "08da3a73f279d55a4000bc3ab2f60ee9fc84be326142d18e50efadccac7a38a7"
  , "90846dda3abddd"
  ]

-- | CLI ECDSA P-256/BLAKE2b-512 interop bytes ('openssl pkeyutl
-- -sign -rawin -digest blake2b512', verified back through the CLI).
ecMsgB2 :: ByteString
ecMsgB2 = "ecdsa-blake2b-test-message"

ecB2Pub :: ByteString
ecB2Pub = hex $ concat
  [ "3059301306072a8648ce3d020106082a8648ce3d03010703420004cd49ef94a0"
  , "69a3e45c179d5dcfa51271c9c61b04e94838067cbfd351a1056b0c07d2690f20"
  , "51acf535a3d672ae17613067c32f64517f84eb8ab6ca9a4eb7669d"
  ]

ecSigB2 :: ByteString
ecSigB2 = hex $ concat
  [ "3044022005f2b419c99f1dcd0f0ddd0982b8d643517b51002a169ad91641328ca"
  , "c12253302207d5ca1f3b3d58bfeb3482238e0db956ea750a241e5da3ea3a76ab0"
  , "0650d3fd00"
  ]

ecMsg521 :: ByteString
ecMsg521 = "T16 S9 ECDSA P-521/SHA512 message"

ecP521Pub :: ByteString
ecP521Pub = hex $ concat
  [ "30819b301006072a8648ce3d020106052b810400230381860004019eed1a84c8"
  , "46d69d26a869d864b0d1bf557cc7320ce1d8018f22f3b963f6b4c136b38d44c8"
  , "cb2e21218e96f93aa82459dfb186d80fe06db19cc3c49989e1da9c1701a68897"
  , "45283941b46bb94ab6f59ad10786191c910aa0183b702b25cd18de9afa573180"
  , "5cab4f7e3309226b19e397fbaed8b54a03e2e9e1e79ec3862f0ca47a1fc9"
  ]

ecSig521 :: ByteString
ecSig521 = hex $ concat
  [ "30818702410b6ed9ef58252d7628e1da101ce8d563ee4958740c9420407bdeaa"
  , "2d9ebe7b3e8fc7d32c21fe434dfde0975955dd86d1175a7e8aeb0bc4f5cc42ef"
  , "5bd3ccdce926024201650e92bc9c37d7b2a71309cad43ab170ecc530ab1696d8"
  , "b674246e5275205b60c260f59c00ca96a0dadbd9e180d76a2592ffeb2eb6d8eb"
  , "d43f0e6def4440fe9a46"
  ]

ecRaw32 :: ByteString
ecRaw32 = hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

ecRawSig :: ByteString
ecRawSig = hex $ concat
  [ "304502200c0b980a724edb395232d3fe7434d0ff85c10ee8db983fc5ca245d67"
  , "5d6337c7022100f446a1b647aa0fc78ed12dab16076692a4128980fdbba6f874"
  , "997a935c1219b3"
  ]

-- | Tiny DER ECDSA-signature parser: SEQUENCE { INTEGER r, INTEGER s }.
-- Independent of the backend's own conversion; used to cross-check
-- RAW (r || s) against DER on the same signature bytes.
-- | Minimal DER ECDSA-signature parser for cross-checks: the
-- coordinate length is the caller's curve half-width (any covered
-- width). Wider curves use long-form lengths, so both length forms
-- parse.
parseDerEcdsa :: Int -> ByteString -> Maybe (ByteString, ByteString)
parseDerEcdsa coordLen der = do
  (seqBody, rest0) <- takeTLV 0x30 der
  if not (BS.null rest0) then Nothing else do
    (r, rest1) <- takeTLV 0x02 seqBody
    (s, rest2) <- takeTLV 0x02 rest1
    if not (BS.null rest2) then Nothing else pure (stripInt r, stripInt s)
  where
    takeTLV :: Int -> ByteString -> Maybe (ByteString, ByteString)
    takeTLV tag bs = case BS.uncons bs of
      Just (t, r0)
        | fromIntegral t == tag -> case BS.uncons r0 of
            Just (l0, r1)
              | l0 < 0x80 ->
                  let n = fromIntegral l0
                  in Just (BS.take n r1, BS.drop n r1)
              | l0 == 0x81 -> case BS.uncons r1 of
                  Just (n, r2) ->
                    let k = fromIntegral n
                    in Just (BS.take k r2, BS.drop k r2)
                  _ -> Nothing
              | l0 == 0x82 -> case (BS.uncons r1 >>= \(h, tl) -> BS.uncons tl >>= \(l, u) -> Just (h, l, u)) of
                  Just (h, l, r2) ->
                    let k = fromIntegral h * 256 + fromIntegral l
                    in Just (BS.take k r2, BS.drop k r2)
                  _ -> Nothing
              | otherwise -> Nothing
            _ -> Nothing
      _ -> Nothing
    stripInt bs =
      let s = BS.dropWhile (== 0) bs
      in BS.dropWhile (== 0) (if BS.length s > coordLen then BS.drop (BS.length s - coordLen) s else s)

pad32 :: ByteString -> ByteString
pad32 bs = BS.replicate (32 - BS.length bs) 0 <> bs

caseEcdsaKat :: IO ()
caseEcdsaKat = withBackend $ \env -> do
  let pub = KeyDer ecPubDer
      derSpec = SigECDSA { sigEc = p256der, sigEcDigest = Just D_SHA256 }
      rawSpec = SigECDSA { sigEc = p256raw, sigEcDigest = Just D_SHA256 }
  expectOk "verify fixed DER" =<< verify env derSpec pub ecMsg ecSigDer
  expectOk "verify fixed RAW" =<< verify env rawSpec pub ecMsg ecSigRaw
  -- Cross-check: the test's own DER parser recovers the same r || s.
  case parseDerEcdsa 32 ecSigDer of
    Nothing -> assertFailure "test DER parser rejected the fixed signature"
    Just (r, s) -> assertEqual "raw == parsed der" ecSigRaw (pad32 r <> pad32 s)
  where
    p256der = mkEc "P-256" "DER"
    p256raw = mkEc "P-256" "RAW"

caseEcdsaRoundtrip :: IO ()
caseEcdsaRoundtrip = withBackend $ \env -> do
  (priv, Just pub) <- expectOk "gen p-256" =<< generateKey env (GenEC (mkEc "P-256" "DER"))
  let derSpec = SigECDSA { sigEc = mkEc "P-256" "DER", sigEcDigest = Just D_SHA256 }
      rawSpec = SigECDSA { sigEc = mkEc "P-256" "RAW", sigEcDigest = Just D_SHA256 }
  sigD <- expectOk "sign DER" =<< sign env derSpec priv ecMsg
  assertBool "der parses" (parseDerEcdsa 32 sigD /= Nothing)
  expectOk "verify DER" =<< verify env derSpec pub ecMsg sigD
  sigR <- expectOk "sign RAW" =<< sign env rawSpec priv ecMsg
  assertEqual "raw is exactly r||s" 64 (BS.length sigR)
  expectOk "verify RAW" =<< verify env rawSpec pub ecMsg sigR
  -- Tampered signatures fail authentication, never verify.
  let tamper bs = BS.init bs <> BS.singleton (BS.last bs + 1)
  expectAuthFailed "tampered DER" =<< verify env derSpec pub ecMsg (tamper sigD)
  expectAuthFailed "tampered RAW" =<< verify env rawSpec pub ecMsg (tamper sigR)

caseEcdsaCurvesVectors :: IO ()
caseEcdsaCurvesVectors = withBackend $ \env -> do
  -- Interop: the CLI's P-384/SHA-384 and P-521/SHA-512 bytes verify.
  let s384 = SigECDSA (mkEc "P-384" "DER") (Just D_SHA384)
      s521 = SigECDSA (mkEc "P-521" "DER") (Just D_SHA512)
  expectOk "verify cli p384" =<<
    verify env s384 (KeyDer ecP384Pub) ecMsg384 ecSig384
  expectOk "verify cli p521" =<<
    verify env s521 (KeyDer ecP521Pub) ecMsg521 ecSig521
  -- Interop on the new families: Koblitz, brainpool, binary.
  let sK256 = SigECDSA (mkEc "secp256k1" "DER") (Just D_SHA256)
      sBp256 = SigECDSA (mkEc "brainpoolP256r1" "DER") (Just D_SHA256)
      sT283 = SigECDSA (mkEc "sect283r1" "DER") (Just D_SHA256)
  expectOk "verify cli k256" =<<
    verify env sK256 (KeyDer ecK256Pub) ecMsgK256 ecSigK256
  expectOk "verify cli bp256" =<<
    verify env sBp256 (KeyDer ecBp256Pub) ecMsgBp256 ecSigBp256
  expectOk "verify cli t283" =<<
    verify env sT283 (KeyDer ecT283Pub) ecMsgT283 ecSigT283
  expectAuthFailed "p384 tampered" =<<
    verify env s384 (KeyDer ecP384Pub) ecMsg384 (tamperLast ecSig384)
  -- Interop on BLAKE2B-512: the CLI's P-256 bytes verify.
  let sB2 = SigECDSA (mkEc "P-256" "DER") (Just D_BLAKE2B512)
  expectOk "verify cli blake2b512" =<<
    verify env sB2 (KeyDer ecB2Pub) ecMsgB2 ecSigB2
  expectAuthFailed "blake2b512 tampered" =<<
    verify env sB2 (KeyDer ecB2Pub) ecMsgB2 (tamperLast ecSigB2)
  expectAuthFailed "t283 tampered" =<<
    verify env sT283 (KeyDer ecT283Pub) ecMsgT283 (tamperLast ecSigT283)
  -- Raw interop: the CLI's raw P-256 bytes verify under the raw row.
  let sraw = SigECDSA (mkEc "P-256" "DER") Nothing
  expectOk "verify cli raw" =<<
    verify env sraw (KeyDer ecPubDer) ecRaw32 ecRawSig
  expectAuthFailed "raw tampered" =<<
    verify env sraw (KeyDer ecPubDer) ecRaw32 (tamperLast ecRawSig)
  -- Raw input bounds follow SEC1: 33 bytes on P-256 truncates
  -- to the leftmost 256 bits (a verdict input, never a refusal).
  sig33 <- expectOk "raw overlong sign truncates" =<<
    sign env sraw (KeyDer ecPrivDer) (BS.replicate 33 0)
  expectOk "raw overlong verify truncates" =<<
    verify env sraw (KeyDer ecPubDer) (BS.replicate 33 0) sig33
  -- Roundtrips: every (curve, digest-or-raw, encoding) signs and
  -- verifies its own output (fresh randomness each call).
  (p384, Just q384) <- expectOk "gen p384" =<<
    generateKey env (GenEC (mkEc "P-384" "DER"))
  (p521, Just q521) <- expectOk "gen p521" =<<
    generateKey env (GenEC (mkEc "P-521" "DER"))
  (p256, Just q256) <- expectOk "gen p256" =<<
    generateKey env (GenEC (mkEc "P-256" "DER"))
  mapM_ (roundtrip env p384 q384 "P-384" 96)
    (Nothing : map Just
      [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
      , D_SHA512_224, D_SHA512_256
      , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
      , D_RIPEMD160
      , D_BLAKE2B512
      ])
  mapM_ (roundtrip env p521 q521 "P-521" 132)
    [Nothing, Just D_SHA256, Just D_SHA512, Just D_SHA3_512]
  mapM_ (roundtrip env p256 q256 "P-256" 64)
    [Nothing, Just D_SHA1, Just D_SHA256, Just D_SHA512, Just D_SHA3_256]
  -- Roundtrips on every new curve (real keygen each): the raw
  -- length pins the coordinate width end to end.
  mapM_ (\(curve, rawLen) -> do
    (p, Just q) <- expectOk ("gen " ++ curve) =<<
      generateKey env (GenEC (mkEc curve "DER"))
    mapM_ (roundtrip env p q curve rawLen)
      [Nothing, Just D_SHA256, Just D_SHA512]
    ) newCurveLens
  where
    newCurveLens :: [(String, Int)]
    newCurveLens =
      -- Wider-order curves emit order-width halves (PKCS#11 §6.3.1
      -- nLen): 161-bit orders on 160-bit fields sign 42 bytes, the
      -- 225-bit order on the 224-bit field signs 58.
      [ ("secp160r1", 42), ("secp160r2", 42), ("secp160k1", 42)
      , ("secp192r1", 48), ("secp192k1", 48)
      , ("secp224r1", 56), ("secp224k1", 58), ("secp256k1", 64)
      , ("brainpoolP224r1", 56), ("brainpoolP256r1", 64)
      , ("brainpoolP320r1", 80), ("brainpoolP384r1", 96)
      , ("brainpoolP512r1", 128)
      , ("sect283k1", 72), ("sect283r1", 72)
      -- sect409k1's order is 51 bytes, narrower than its 52-byte
      -- field, so order-width halves are 51 (raw 102); its twin
      -- sect409r1 has a full 52-byte order and stays 104.
      , ("sect409k1", 102), ("sect409r1", 104)
      , ("sect571k1", 144), ("sect571r1", 144)
      ]
    roundtrip env priv pub curve rawLen digest = do
      let derSpec = SigECDSA (mkEc curve "DER") digest
          rawSpec = SigECDSA (mkEc curve "RAW") digest
          label = curve ++ "/" ++ show digest
          input = if digest == Nothing then BS.replicate (rawLen `div` 2) 0x5a else ecMsg
      sigD <- expectOk ("sign DER " ++ label) =<< sign env derSpec priv input
      assertBool ("der parses " ++ label) (parseDerEcdsa (rawLen `div` 2) sigD /= Nothing)
      expectOk ("verify DER " ++ label) =<< verify env derSpec pub input sigD
      sigR <- expectOk ("sign RAW " ++ label) =<< sign env rawSpec priv input
      assertEqual ("raw length " ++ label) rawLen (BS.length sigR)
      expectOk ("verify RAW " ++ label) =<< verify env rawSpec pub input sigR

-- | SEC1 truncation on the raw row: PKCS#11 §2.3.1 / SEC1
-- §4.1.3 sign and verify the leftmost min(N, n) bits when the
-- input is longer than the group order — overlong input is a
-- verdict input, never a parameter refusal.
caseEcdsaRawTruncate :: IO ()
caseEcdsaRawTruncate = withBackend $ \env -> do
  let sraw = SigECDSA (mkEc "P-256" "RAW") Nothing
      long = ecRaw32 <> BS.replicate 32 0xA5
  sigL <- expectOk "sign 64B on P-256 truncates" =<<
    sign env sraw (KeyDer ecPrivDer) long
  assertEqual "truncated sign is r||s" 64 (BS.length sigL)
  expectOk "verify 64B with its own sig" =<<
    verify env sraw (KeyDer ecPubDer) long sigL
  -- Cross: a signature over the 32-byte prefix verifies against
  -- the 64-byte input (same leftmost 256 bits).
  sigP <- expectOk "sign 32B prefix" =<<
    sign env sraw (KeyDer ecPrivDer) ecRaw32
  expectOk "verify truncates to the prefix" =<<
    verify env sraw (KeyDer ecPubDer) long sigP
  -- Negative: a wrong prefix still mismatches after truncation.
  expectAuthFailed "verify wrong prefix mismatches" =<<
    verify env sraw (KeyDer ecPubDer)
      (BS.replicate 32 0x5A <> BS.replicate 32 0xA5) sigP
  -- Non-aligned order (P-521: 521 bits): a 66-byte input keeps
  -- the leftmost 521 bits — the low 7 bits of the last byte are
  -- masked away, so inputs differing only there are identical.
  (p521, Just q521) <- expectOk "gen p521" =<<
    generateKey env (GenEC (mkEc "P-521" "DER"))
  let sraw521 = SigECDSA (mkEc "P-521" "RAW") Nothing
      hi = BS.replicate 65 0x33 <> BS.singleton 0x80
      lo = BS.replicate 65 0x33 <> BS.singleton 0xFF
  sig521 <- expectOk "sign 66B on P-521 truncates" =<<
    sign env sraw521 p521 hi
  assertEqual "p521 truncated sign is r||s" 132 (BS.length sig521)
  expectOk "verify masked-away bits ignored" =<<
    verify env sraw521 q521 lo sig521

-- | Degenerate-math verdict: the point-at-infinity fixture
-- verifies as a mismatch (X9.62 §7.4.2 rejects), never a native
-- malfunction — even though OpenSSL reports rc -1.
caseEcdsaInfinity :: IO ()
caseEcdsaInfinity = withBackend $ \env -> do
  let sraw = SigECDSA (mkEc "brainpoolP224r1" "RAW") Nothing
  assertEqual "fixture sig is r||s" 56 (BS.length ecInf224Sig)
  expectAuthFailed "infinity fixture mismatches" =<<
    verify env sraw (KeyDer ecInf224Pub) ecInf224Digest ecInf224Sig

-- | An odd-length raw signature cannot split into halves and can
-- never be valid: refused by length, like an overlong encoding —
-- not a value mismatch.
caseEcdsaOddSig :: IO ()
caseEcdsaOddSig = withBackend $ \env -> do
  let sraw = SigECDSA (mkEc "P-256" "RAW") Nothing
  expectSigLenRange "63-byte raw sig refused by length" =<<
    verify env sraw (KeyDer ecPubDer) ecRaw32 (BS.replicate 63 1)

-- | Short raw ECDSA forms verify (PKCS#11 §6.3.1: an even
-- non-zero length up to twice the wider of the order and
-- coordinate widths): a P-521 signature with leading-zero bytes
-- stripped from both halves, a wider-order secp160r1 signature
-- stripped back to the 40-byte field form, and the pre-narrowing
-- 104-byte sect409k1 form. Past the bound still refuses by
-- length.
caseEcdsaShortForms :: IO ()
caseEcdsaShortForms = withBackend $ \env -> do
  -- P-521: sign until both halves carry a leading zero (about 1
  -- in 4), strip one byte per half, and the 130-byte form
  -- verifies.
  (p521, Just q521) <- expectOk "gen p521" =<<
    generateKey env (GenEC (mkEc "P-521" "DER"))
  let sraw521 = SigECDSA (mkEc "P-521" "RAW") Nothing
      input521 = BS.replicate 66 0x33
      findShort :: Int -> IO BS.ByteString
      findShort tries
        | tries <= 0 =
            assertFailure "no short P-521 signature in 64 signs" >> undefined
        | otherwise = do
            sig <- expectOk "sign p521" =<< sign env sraw521 p521 input521
            assertEqual "p521 raw width" 132 (BS.length sig)
            let (r, s) = BS.splitAt 66 sig
            if BS.index r 0 == 0 && BS.index s 0 == 0
              then pure (BS.drop 1 r <> BS.drop 1 s)
              else findShort (tries - 1)
  short521 <- findShort 64
  assertEqual "stripped form is 130 bytes" 130 (BS.length short521)
  expectOk "p521 stripped form verifies" =<<
    verify env sraw521 q521 input521 short521
  -- secp160r1: the order is 21 bytes against a 20-byte field,
  -- so signing emits 42 bytes; a 40-byte stripped form still
  -- verifies through the short-form tolerance.
  (p160, Just q160) <- expectOk "gen secp160r1" =<<
    generateKey env (GenEC (mkEc "secp160r1" "DER"))
  let sraw160 = SigECDSA (mkEc "secp160r1" "RAW") Nothing
      input160 = BS.replicate 20 0x33
      findNarrow :: Int -> IO BS.ByteString
      findNarrow tries
        | tries <= 0 =
            assertFailure "no short secp160r1 signature in 64 signs" >> undefined
        | otherwise = do
            sig <- expectOk "sign secp160r1" =<< sign env sraw160 p160 input160
            assertEqual "secp160r1 raw width" 42 (BS.length sig)
            let (r, s) = BS.splitAt 21 sig
            if BS.index r 0 == 0 && BS.index s 0 == 0
              then pure (BS.drop 1 r <> BS.drop 1 s)
              else findNarrow (tries - 1)
  short40 <- findNarrow 64
  assertEqual "stripped form is 40 bytes" 40 (BS.length short40)
  expectOk "secp160r1 40-byte form verifies" =<<
    verify env sraw160 q160 input160 short40
  -- sect409k1: the sign side emits 102 bytes (51-byte order),
  -- but the 104-byte field-width form from before the narrowing
  -- still verifies through the compatibility bound.
  (p409, Just q409) <- expectOk "gen sect409k1" =<<
    generateKey env (GenEC (mkEc "sect409k1" "DER"))
  let sraw409 = SigECDSA (mkEc "sect409k1" "RAW") Nothing
      input409 = BS.replicate 52 0x33
  sig102 <- expectOk "sign sect409k1" =<< sign env sraw409 p409 input409
  assertEqual "sect409k1 raw width" 102 (BS.length sig102)
  let wide104 = BS.singleton 0 <> BS.take 51 sig102
        <> BS.singleton 0 <> BS.drop 51 sig102
  expectOk "sect409k1 104-byte form verifies" =<<
    verify env sraw409 q409 input409 wide104
  -- Past the bound refuses by length: 66 bytes on P-256.
  let sraw256 = SigECDSA (mkEc "P-256" "RAW") Nothing
  expectSigLenRange "p256 66-byte refused by length" =<<
    verify env sraw256 (KeyDer ecPubDer) ecRaw32 (BS.replicate 66 1)
  -- Degenerate values at allowed lengths still mismatch (the
  -- bound guards the length; OpenSSL guards the range).
  expectAuthFailed "p256 2-byte zero sig mismatches" =<<
    verify env sraw256 (KeyDer ecPubDer) ecRaw32 (BS.pack [0, 0])
  let secp160r1Order = hex "0100000000000000000001f4c8f927aed3ca752257"
  assertEqual "secp160r1 order is 21 bytes" 21 (BS.length secp160r1Order)
  expectAuthFailed "secp160r1 r=n mismatches" =<<
    verify env sraw160 q160 input160 (secp160r1Order <> BS.replicate 20 0 <> BS.singleton 1)
  let bad409 = BS.singleton 0xFF <> BS.drop 1 wide104
  expectAuthFailed "sect409k1 r above n mismatches" =<<
    verify env sraw409 q409 input409 bad409
  -- Bound+2 refuses by length where the max matters.
  expectSigLenRange "secp160r1 44-byte refused by length" =<<
    verify env sraw160 q160 input160 (BS.replicate 44 1)
  expectSigLenRange "sect409k1 106-byte refused by length" =<<
    verify env sraw409 q409 input409 (BS.replicate 106 1)

-- | The curve allowlist: a well-formed brainpoolP160r1 key (real
-- but uncollected) refuses typed on both sign and verify (the
-- driver only hints the curve label, so the backend re-checks
-- before any native call). Garbage DER refuses the same way.
caseEcdsaOffCurve :: IO ()
caseEcdsaOffCurve = withBackend $ \env -> do
  let ecdsaSpec = SigECDSA (mkEc "P-256" "DER") (Just D_SHA256)
  expectBadKey "bp160 sign refused" =<<
    sign env ecdsaSpec (KeyDer ecBp160Priv) ecMsg
  expectBadKey "bp160 verify refused" =<<
    verify env ecdsaSpec (KeyDer ecBp160Pub) ecMsg ecSigDer
  expectBadKey "garbage sign refused" =<<
    sign env ecdsaSpec (KeyDer "bogus") ecMsg
  expectBadKey "garbage verify refused" =<<
    verify env ecdsaSpec (KeyDer "bogus") ecMsg ecSigDer


-- | Point-at-infinity fixture: Wycheproof
-- @ecdsa_brainpoolP224r1_sha224_test.json@ tc360 (invalid,
-- PointDuplication/ArithmeticError), PKCS#11-shaped exactly as the
-- lane sends it — 28-byte SHA-224 digest, 56-byte raw r||s with
-- both halves in range. The verification math lands on the point
-- at infinity, which X9.62 §7.4.2 says REJECTS; OpenSSL reports
-- it as an internal error (rc -1), so the shim must map that one
-- degenerate-math reason to a mismatch verdict.
ecInf224Pub, ecInf224Digest, ecInf224Sig :: ByteString
ecInf224Pub = hex $ concat
  [ "3052301406072a8648ce3d020106092b2403030208010105033a0004d4b6e51"
  , "12406fb743b6bb55f49ea2030d904420831ebddacd67bba89652265384b75d85"
  , "0e7c27f4e33ed6c576df0ff969470a9ef25ffafcd"
  ]
ecInf224Digest = hex "753bb40078934081d7bd113ec49b19ef09d1ba33498690516d4d122c"
ecInf224Sig = hex $ concat
  [ "6be09a551321b343150c1812bae87dcc688b5e25b6ef5e51d2d3c9cf47eb11"
  , "8e0cc1222cb8b2bab72745a932f05ce96e79f4e98be1e2868a"
  ]

ecBp160Pub :: ByteString
ecBp160Pub = hex $ concat
  [ "3042301406072a8648ce3d020106092b2403030208010101032a0004e471b91d"
  , "45036f84037b7e2c3804348be1455d93662b6814bfeb22a8acb58b5ae6f583f2"
  , "a0de1081"
  ]
