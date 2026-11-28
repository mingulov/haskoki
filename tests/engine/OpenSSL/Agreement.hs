{- | OpenSSL key-agreement cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Agreement
  ( caseDhAgree
  , caseDhKeygen
  , caseDhPadLeadingZero
  , caseEcdhCompWrap
  , caseEcdhVectors
  , casePubFromPrivProvider
  , caseRawVsDer
  , caseRealMontgomeryKeygen
  , caseRsaCompWrap
  , caseXdhVectors
  ) where

import Data.Bits (xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Engine.Backend
  ( BackendError (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EcdhSpec (..)
  , DhSpec (..)
  , EngineResult (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , SigSpec (..)
  )
import Haskoki.Der (dhParamsDer, dhParamsDerQ, dhPkcs8Fields, dhSpkiFields, montgomeryPkcs8Fields, montgomeryPrivateDer, montgomerySpkiFields)
import Haskoki.Engine.Driver (runEffect)
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoResult (..))
import Haskoki.Recipe.WrapComp (encodeWrapCompEcdhParams)
import Haskoki.Recipe.WrapCompRsa (encodeWrapCompRsaParams)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Types (ObjectId (..))
import OpenSSL.Fixtures

expectMechParamInvalid :: Show a => String -> EngineResult a -> IO ()
expectMechParamInvalid label r = case r of
  EngineFail (BackendMechParamInvalid _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendMechParamInvalid, got " ++ show other)

ecdhPointE :: ByteString
ecdhPointE = hex $ concat
  [ "0407277db5580914a8be1b6752a4abbe5e329d63243632155bd04174a611af7908"
  , "52d57a16079ed448de40bb0c7d01f3a882bf0aa01e3278b8f537397cc606b7323ef"
  , "57eeb134d022a"
  ]
-- | S10 ECDH agreement: CLI cross-checked KATs in both
-- directions, cofactor-equals-plain on P-256 (h=1), the P-384
-- width, and typed key-shape refusals (garbage, off-set curve,
-- base/peer curve mismatch).
caseEcdhVectors :: IO ()
caseEcdhVectors = withBackend $ \env -> do
  let pA = KeyDer ecdhPrivA
      qA = KeyDer ecdhPubA
      pB = KeyDer ecdhPrivB
      qB = KeyDer ecdhPubB
      pC = KeyDer ecdhPrivC
      qC = KeyDer ecdhPubC
  sAB <- expectOk "derive A->B" =<< ecdhDerive env EcdhPlain pA qB
  assertEqual "KAT A->B" ecdhSecretAB sAB
  sBA <- expectOk "derive B->A" =<< ecdhDerive env EcdhPlain pB qA
  assertEqual "commute" ecdhSecretAB sBA
  sCof <- expectOk "derive cofactor" =<< ecdhDerive env EcdhCofactor pA qB
  assertEqual "cofactor == plain (h=1)" ecdhSecretAB sCof
  sCC <- expectOk "derive P-384" =<< ecdhDerive env EcdhPlain pC qC
  assertEqual "KAT P-384" ecdhSecretCC sCC
  assertEqual "P-384 width" 48 (BS.length sCC)
  -- sect283k1 KAT: plain + cofactor (h=2, so they differ), SPKI and
  -- bare-point peers agree, commute holds.
  let pD = KeyDer ecdhPrivD
      qE = KeyDer ecdhPubE
      bE = KeyDer ecdhPointE
  sDE <- expectOk "derive t283k1" =<< ecdhDerive env EcdhPlain pD qE
  assertEqual "KAT t283k1" ecdhSecretDE sDE
  assertEqual "t283k1 width" 36 (BS.length sDE)
  sDEb <- expectOk "derive t283k1 bare peer" =<< ecdhDerive env EcdhPlain pD bE
  assertEqual "bare peer agrees" ecdhSecretDE sDEb
  sED <- expectOk "derive t283k1 commute" =<<
    ecdhDerive env EcdhPlain (KeyDer ecdhPrivE) (KeyDer ecdhPubD)
  assertEqual "commute t283k1" ecdhSecretDE sED
  sDEcof <- expectOk "derive t283k1 cofactor" =<< ecdhDerive env EcdhCofactor pD qE
  assertEqual "KAT t283k1 cofactor" ecdhSecretDEcof sDEcof
  assertBool "cofactor differs (h=2)" (sDEcof /= ecdhSecretDE)
  expectBadKey "garbage priv refused" =<< ecdhDerive env EcdhPlain (KeyDer "bogus") qB
  expectMechParamInvalid "garbage peer refused" =<< ecdhDerive env EcdhPlain pA (KeyDer "bogus")
  expectBadKey "off-curve priv refused" =<< ecdhDerive env EcdhPlain (KeyDer ecBp160Priv) qB
  expectMechParamInvalid "curve mismatch refused" =<< ecdhDerive env EcdhPlain pA qC

-- | XDH agreement: CLI cross-checked KATs in both directions per
-- curve, wycheproof tc1 exchange KATs, and typed peer refusals
-- (low-order, off-width, cofactor spec).
caseXdhVectors :: IO ()
caseXdhVectors = withBackend $ \env -> do
  let pA = KeyDer xdhPrivA
      pB = KeyDer xdhPrivB
      qA = KeyBytes xdhPointA
      qB = KeyBytes xdhPointB
  sAB <- expectOk "derive X25519 A->B" =<< ecdhDerive env EcdhPlain pA qB
  assertEqual "KAT X25519" xdhSecretAB sAB
  assertEqual "X25519 width" 32 (BS.length sAB)
  sBA <- expectOk "derive X25519 B->A" =<< ecdhDerive env EcdhPlain pB qA
  assertEqual "commute X25519" xdhSecretAB sBA
  let p48A = KeyDer xdh48PrivA
      p48B = KeyDer xdh48PrivB
      q48A = KeyBytes xdh48PointA
      q48B = KeyBytes xdh48PointB
  s48AB <- expectOk "derive X448 A->B" =<< ecdhDerive env EcdhPlain p48A q48B
  assertEqual "KAT X448" xdh48SecretAB s48AB
  assertEqual "X448 width" 56 (BS.length s48AB)
  s48BA <- expectOk "derive X448 B->A" =<< ecdhDerive env EcdhPlain p48B q48A
  assertEqual "commute X448" xdh48SecretAB s48BA
  -- Wycheproof tc1 exchange KATs (external vectors).
  let priv19w = KeyDer (montgomeryPrivateDer (hex "06032b656e") xdhTc1Priv)
  sT19 <- expectOk "derive wycheproof X25519 tc1" =<< ecdhDerive env EcdhPlain priv19w (KeyBytes xdhTc1Pub)
  assertEqual "KAT wycheproof X25519 tc1" xdhTc1Shared sT19
  let priv48w = KeyDer (montgomeryPrivateDer (hex "06032b656f") xdh48Tc1Priv)
  sT48 <- expectOk "derive wycheproof X448 tc1" =<< ecdhDerive env EcdhPlain priv48w (KeyBytes xdh48Tc1Pub)
  assertEqual "KAT wycheproof X448 tc1" xdh48Tc1Shared sT48
  -- Low-order peers (u=0, the wycheproof tc32 shape) refuse as
  -- mechanism-param-invalid: the pinned provider fails
  -- zero-output derives and the shim attributes the peer.
  expectMechParamInvalid "low-order X25519 peer refused" =<<
    ecdhDerive env EcdhPlain pA (KeyBytes (BS.replicate 32 0))
  expectMechParamInvalid "low-order X448 peer refused" =<<
    ecdhDerive env EcdhPlain p48A (KeyBytes (BS.replicate 56 0))
  -- Off-width peers refuse before any native call.
  expectMechParamInvalid "short peer refused" =<<
    ecdhDerive env EcdhPlain pA (KeyBytes (BS.take 31 xdhPointB))
  expectMechParamInvalid "long peer refused" =<<
    ecdhDerive env EcdhPlain pA (KeyBytes (xdhPointB <> BS.singleton 0))
  expectMechParamInvalid "cross-curve peer refused" =<<
    ecdhDerive env EcdhPlain pA (KeyBytes xdh48PointB)
  -- Cofactor derive over Montgomery curves is unserved (named gap).
  expectMechParamInvalid "cofactor over montgomery refused" =<<
    ecdhDerive env EcdhCofactor pA qB

-- | Montgomery keygen: both curves mint parseable DER halves
-- whose halves agree both directions at the curve width (no KAT
-- possible for randomized generation). Off-set curves refuse
-- unsupported.
caseRealMontgomeryKeygen :: IO ()
caseRealMontgomeryKeygen = withBackend $ \env -> do
  let mint label curve = do
        (priv, mpub) <- expectOk label =<< generateKey env (GenXDHKeypair curve)
        case (priv, mpub) of
          (KeyDer privB, Just (KeyDer pubB)) -> pure (privB, pubB)
          other -> assertFailure (label ++ ": halves are not DER: " ++ show other)
      agree label w privA pubA privB pubB = do
        pointA <- case montgomerySpkiFields pubA of
          Just (_, pt) -> pure pt
          Nothing -> assertFailure (label ++ ": SPKI A failed to parse") >> undefined
        pointB <- case montgomerySpkiFields pubB of
          Just (_, pt) -> pure pt
          Nothing -> assertFailure (label ++ ": SPKI B failed to parse") >> undefined
        case montgomeryPkcs8Fields privA of
          Just _ -> pure ()
          Nothing -> assertFailure (label ++ ": PKCS#8 A failed to parse")
        sAB <- expectOk (label ++ " A->B") =<<
          ecdhDerive env EcdhPlain (KeyDer privA) (KeyBytes pointB)
        sBA <- expectOk (label ++ " B->A") =<<
          ecdhDerive env EcdhPlain (KeyDer privB) (KeyBytes pointA)
        assertEqual (label ++ " commutes") sAB sBA
        assertEqual (label ++ " width") w (BS.length sAB)
  (privA, pubA) <- mint "x25519 mint A" "X25519"
  (privB, pubB) <- mint "x25519 mint B" "X25519"
  assertBool "x25519 halves differ" (privA /= pubA && privB /= pubB)
  agree "x25519" 32 privA pubA privB pubB
  (privC, pubC) <- mint "x448 mint A" "X448"
  (privD, pubD) <- mint "x448 mint B" "X448"
  agree "x448" 56 privC pubC privD pubD
  expectUnsupported "unknown curve refused" =<<
    generateKey env (GenXDHKeypair "P-256")

-- ECDH wrap compositions through the driver bridge: ephemeral
-- transport keygen on the wrapping key's domain, first-bytes KEK,
-- KWP seal. Transport is ephemeral, so blobs are unpinned —
-- framing geometry, roundtrips, strength separation, and
-- fail-closed tamper legs pin the behavior instead.
caseEcdhCompWrap :: IO ()
caseEcdhCompWrap = withBackend $ \env -> do
  let target = "sixteen bytes xx" :: BS.ByteString
      oid = Just (ObjectId 7)
      params bits = encodeWrapCompEcdhParams 0 BS.empty bits
  -- Plain over P-256: 65-byte bare point + 24-byte KWP tail.
  -- Wrap resolves the recipient PUBLIC half, unwrap the private.
  (priv, mpub) <- expectOk "gen p-256" =<< generateKey env (GenEC (mkEc "P-256" "DER"))
  pub <- case mpub of
    Just p -> pure p
    Nothing -> assertFailure "gen p-256 must mint a pair" >> undefined
  let wrapResolve _ = Just pub
      unwrapResolve _ = Just priv
  blob <- expectBytes "plain wrap" =<<
    runEffect env wrapResolve (FxWrap (MechanismId 0x1053) oid (params 128) target)
  assertEqual "plain blob length" 89 (BS.length blob)
  assertEqual "bare point tag" 0x04 (BS.index blob 0)
  pt <- expectBytes "plain unwrap" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1053) oid (params 128) blob)
  assertEqual "plain roundtrip" target pt
  -- Tampered tail and tampered prefix both fail closed.
  expectCryptoError "tampered tail fails closed" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1053) oid (params 128) (corruptAt 80 blob))
  expectCryptoError "tampered prefix fails closed" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1053) oid (params 128) (corruptAt 10 blob))
  -- Strength separation: wrap@128 opens only under 128.
  expectCryptoError "cross-strength unwrap fails closed" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1053) oid (params 256) blob)
  blob256 <- expectBytes "plain wrap 256" =<<
    runEffect env wrapResolve (FxWrap (MechanismId 0x1053) oid (params 256) target)
  assertEqual "plain 256 length" 89 (BS.length blob256)
  pt256 <- expectBytes "plain unwrap 256" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1053) oid (params 256) blob256)
  assertEqual "plain 256 roundtrip" target pt256
  -- Cofactor over P-256: 67-byte OCTET image + 24-byte tail.
  coBlob <- expectBytes "cof wrap" =<<
    runEffect env wrapResolve (FxWrap (MechanismId 0x4039) oid (params 128) target)
  assertEqual "cof blob length" 91 (BS.length coBlob)
  assertEqual "cof octet header" (BS.pack [0x04, 0x41]) (BS.take 2 coBlob)
  coPt <- expectBytes "cof unwrap" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x4039) oid (params 128) coBlob)
  assertEqual "cof roundtrip" target coPt
  -- X over X25519: 32-byte raw coordinate + 24-byte tail.
  (xpriv, mxpub) <- expectOk "gen x25519" =<< generateKey env (GenXDHKeypair "X25519")
  xpub <- case mxpub of
    Just p -> pure p
    Nothing -> assertFailure "gen x25519 must mint a pair" >> undefined
  let xWrapResolve _ = Just xpub
      xUnwrapResolve _ = Just xpriv
  xBlob <- expectBytes "x wrap" =<<
    runEffect env xWrapResolve (FxWrap (MechanismId 0x4038) oid (params 128) target)
  assertEqual "x blob length" 56 (BS.length xBlob)
  xPt <- expectBytes "x unwrap" =<<
    runEffect env xUnwrapResolve (FxUnwrap (MechanismId 0x4038) oid (params 128) xBlob)
  assertEqual "x roundtrip" target xPt
  -- Garbage wrapping keys refuse typed, never wrong bytes.
  let badResolve _ = Just (KeyDer "bogus")
  expectCryptoError "garbage wrapping key fails closed" =<<
    runEffect env badResolve (FxWrap (MechanismId 0x1053) oid (params 128) target)
  where
    expectBytes label r = case r of
      GotBytes b -> pure b
      other -> assertFailure (label ++ ": expected bytes, got " ++ show other)
    expectCryptoError label r = case r of
      GotCryptoError _ -> pure ()
      other -> assertFailure (label ++ ": expected crypto error, got " ++ show other)
    corruptAt i bs =
      let (pre, rest) = BS.splitAt i bs
      in case BS.uncons rest of
        Just (b, post) -> pre <> BS.singleton (b `xor` 0x01) <> post
        Nothing -> bs

caseRsaCompWrap :: IO ()
caseRsaCompWrap = withBackend $ \env -> do
  let target = "sixteen bytes xx" :: BS.ByteString
      oid = Just (ObjectId 7)
      params = encodeWrapCompRsaParams "SHA256" "SHA256" BS.empty 256
  -- RSA-2048: 256-byte OAEP head + 24-byte KWP tail. Wrap
  -- resolves the recipient PUBLIC half, unwrap the private.
  (priv, mpub) <- expectOk "gen rsa-2048" =<< generateKey env (GenRSA 2048 65537)
  pub <- case mpub of
    Just p -> pure p
    Nothing -> assertFailure "gen rsa-2048 must mint a pair" >> undefined
  let wrapResolve _ = Just pub
      unwrapResolve _ = Just priv
  blob <- expectBytes "rsa wrap" =<<
    runEffect env wrapResolve (FxWrap (MechanismId 0x1054) oid params target)
  assertEqual "rsa blob length" 280 (BS.length blob)
  pt <- expectBytes "rsa unwrap" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1054) oid params blob)
  assertEqual "rsa roundtrip" target pt
  -- Fresh random KEK per wrap: heads differ, both unwrap.
  blob2 <- expectBytes "rsa wrap again" =<<
    runEffect env wrapResolve (FxWrap (MechanismId 0x1054) oid params target)
  assertBool "fresh KEK" (BS.take 256 blob2 /= BS.take 256 blob)
  pt2 <- expectBytes "rsa unwrap again" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1054) oid params blob2)
  assertEqual "second roundtrip" target pt2
  -- Tampered head and tampered tail both fail closed.
  expectCryptoError "tampered head fails closed" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1054) oid params (corruptAt 10 blob))
  expectCryptoError "tampered tail fails closed" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1054) oid params (corruptAt 270 blob))
  -- Strength separation: wrap@256 opens only under 256.
  let params128 = encodeWrapCompRsaParams "SHA256" "SHA256" BS.empty 128
  expectCryptoError "cross-strength unwrap fails closed" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1054) oid params128 blob)
  -- Labels ride the OAEP frame: labeled seals open labeled,
  -- and refuse unlabeled (the label binds the KEK envelope).
  let labeled = encodeWrapCompRsaParams "SHA256" "SHA256" "tag" 256
  blobL <- expectBytes "labeled wrap" =<<
    runEffect env wrapResolve (FxWrap (MechanismId 0x1054) oid labeled target)
  ptL <- expectBytes "labeled unwrap" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1054) oid labeled blobL)
  assertEqual "labeled roundtrip" target ptL
  expectCryptoError "label mismatch fails closed" =<<
    runEffect env unwrapResolve (FxUnwrap (MechanismId 0x1054) oid params blobL)
  -- Garbage wrapping keys refuse typed, never wrong bytes.
  let badResolve _ = Just (KeyDer "bogus")
  expectCryptoError "garbage wrapping key fails closed" =<<
    runEffect env badResolve (FxWrap (MechanismId 0x1054) oid params target)
  where
    expectBytes label r = case r of
      GotBytes b -> pure b
      other -> assertFailure (label ++ ": expected bytes, got " ++ show other)
    expectCryptoError label r = case r of
      GotCryptoError _ -> pure ()
      other -> assertFailure (label ++ ": expected crypto error, got " ++ show other)
    corruptAt i bs =
      let (pre, rest) = BS.splitAt i bs
      in case BS.uncons rest of
        Just (b, post) -> pre <> BS.singleton (b `xor` 0x01) <> post
        Nothing -> bs

-- Pub-from-priv through the provider: minted pairs re-export
-- the exact SPKI (RSA-2048, P-256, both Montgomery and both
-- Edwards curves); garbage DER refuses as a bad key.
casePubFromPrivProvider :: IO ()
casePubFromPrivProvider = withBackend $ \env -> do
  let mint label keyGen = do
        (priv, mpub) <- expectOk label =<< generateKey env keyGen
        case (priv, mpub) of
          (KeyDer privB, Just (KeyDer pubB)) -> pure (privB, pubB)
          other -> assertFailure (label ++ ": halves are not DER: " ++ show other) >> undefined
      check label keyGen = do
        (privB, pubB) <- mint ("mint " ++ label) keyGen
        spki <- expectOk ("extract " ++ label) =<< pubFromPriv env (KeyDer privB)
        assertEqual ("SPKI equals minted pub: " ++ label) pubB spki
  check "rsa2048" (GenRSA 2048 65537)
  check "p256" (GenEC (mkEc "P-256" "DER"))
  check "x25519" (GenXDHKeypair "X25519")
  check "x448" (GenXDHKeypair "X448")
  check "ed25519" (GenEdDSAKeypair "Ed25519")
  check "ed448" (GenEdDSAKeypair "Ed448")
  expectBadKey "garbage refused" =<< pubFromPriv env (KeyBytes "not-der")

caseDhAgree :: IO ()
caseDhAgree = withBackend $ \env -> do
  let pA = KeyDer dhPrivA
      pB = KeyDer dhPrivB
      qA = KeyDer dhPeerA
      qB = KeyDer dhPeerB
  -- Both directions agree with the pinned CLI secret at the
  -- prime's byte width; the peer rides as bare bytes.
  sAB <- expectOk "derive A->B" =<< dhDerive env DhPlain pA qB
  assertEqual "KAT A->B" dhSecretAB sAB
  assertEqual "prime width" 256 (BS.length sAB)
  sBA <- expectOk "derive B->A" =<< dhDerive env DhPlain pB qA
  assertEqual "commute" dhSecretAB sBA
  -- Fault attribution mirrors ECDH: the base is the caller's
  -- key (bad base stays a bad key) while the peer rides in
  -- the mechanism parameters.
  expectBadKey "garbage base refused" =<< dhDerive env DhPlain (KeyDer "bogus") qB
  -- Any in-range integer is a legitimate DH peer (a short
  -- "bogus" value derives); only structural violations refuse.
  expectMechParamInvalid "over-max peer refused" =<<
    dhDerive env DhPlain pA (KeyDer (BS.replicate 4097 1))
  expectMechParamInvalid "peer 0 refused" =<< dhDerive env DhPlain pA (KeyDer (BS.replicate 256 0))
  expectMechParamInvalid "peer 1 refused" =<<
    dhDerive env DhPlain pA (KeyDer (BS.replicate 255 0 <> BS.singleton 1))
  expectMechParamInvalid "peer p refused" =<< dhDerive env DhPlain pA (KeyDer dhPrime2048)
  expectMechParamInvalid "peer over p refused" =<<
    dhDerive env DhPlain pA (KeyDer (BS.replicate 257 0xff))
  expectMechParamInvalid "empty peer refused" =<< dhDerive env DhPlain pA (KeyDer BS.empty)
  -- A tampered peer still derives (in range) but to a
  -- different secret — no silent KAT match.
  sTam <- expectOk "derive tampered peer" =<<
    dhDerive env DhPlain pA (KeyDer (BS.singleton 0x00 <> BS.drop 1 dhPeerB))
  assertBool "tamper diverges" (sTam /= dhSecretAB)

caseDhPadLeadingZero :: IO ()
caseDhPadLeadingZero = withBackend $ \env -> do
  let pA = KeyDer dhPadPrivA
      pB = KeyDer dhPadPrivB
      qA = KeyDer dhPadPeerA
      qB = KeyDer dhPadPeerB
  -- The pinned secret's top byte is zero, so a minimal-length
  -- derive would return 255 bytes here, not 256.
  sAB <- expectOk "derive A->B" =<< dhDerive env DhPlain pA qB
  assertEqual "full width" 256 (BS.length sAB)
  assertEqual "leading zero kept" 0 (BS.index sAB 0)
  assertEqual "KAT A->B" dhPadSecret sAB
  sBA <- expectOk "derive B->A" =<< dhDerive env DhPlain pB qA
  assertEqual "KAT B->A" dhPadSecret sBA

-- | DH keygen: PKCS#3 and X9.42 params mint parseable pairs
-- whose halves carry the domain, and minted pairs on the same
-- domain agree both directions at the prime width. Garbage
-- params refuse as a bad key (DSA mirror).
caseDhKeygen :: IO ()
caseDhKeygen = withBackend $ \env -> do
  let mint label params = do
        (priv, mpub) <- expectOk label =<< generateKey env (GenDHKeypair params)
        case (priv, mpub) of
          (KeyDer privB, Just (KeyDer pubB)) -> pure (privB, pubB)
          other -> assertFailure (label ++ ": halves are not DER: " ++ show other)
      agree label w privA pubA privB pubB = do
        yA <- case dhSpkiFields pubA of
          Just (_, _, _, y) -> pure y
          Nothing -> assertFailure (label ++ ": SPKI A failed to parse") >> undefined
        yB <- case dhSpkiFields pubB of
          Just (_, _, _, y) -> pure y
          Nothing -> assertFailure (label ++ ": SPKI B failed to parse") >> undefined
        sAB <- expectOk (label ++ " A->B") =<< dhDerive env DhPlain (KeyDer privA) (KeyDer yB)
        sBA <- expectOk (label ++ " B->A") =<< dhDerive env DhPlain (KeyDer privB) (KeyDer yA)
        assertEqual (label ++ " commutes") sAB sBA
        -- Full prime width, left-padded: every draw fills
        -- the width exactly (a leading zero byte is kept).
        assertBool (label ++ " nonempty") (not (BS.null sAB))
        assertEqual (label ++ " fills width") w (BS.length sAB)
  -- PKCS#3 on ffdhe2048.
  (privA, pubA) <- mint "pkcs mint A" (dhParamsDer dhPrime2048 (BS.singleton 2))
  (privB, pubB) <- mint "pkcs mint B" (dhParamsDer dhPrime2048 (BS.singleton 2))
  assertBool "pkcs halves differ" (privA /= pubA && privB /= pubB)
  case dhSpkiFields pubA of
    Just (p, g, q, _) -> do
      assertEqual "pkcs p" dhPrime2048 p
      assertEqual "pkcs g" (BS.singleton 2) g
      assertEqual "pkcs no q" Nothing q
    Nothing -> assertFailure "pkcs SPKI failed to parse"
  case dhPkcs8Fields privA of
    Just (p, g, q, _) -> do
      assertEqual "pkcs8 p" dhPrime2048 p
      assertEqual "pkcs8 g" (BS.singleton 2) g
      assertEqual "pkcs8 no q" Nothing q
    Nothing -> assertFailure "pkcs PKCS#8 failed to parse"
  agree "pkcs" 256 privA pubA privB pubB
  -- X9.42 on the embedded (p, g, q) domain.
  let x942 = dhParamsDerQ dhX942P dhX942G dhX942Q
  (privC, pubC) <- mint "x942 mint A" x942
  (privD, pubD) <- mint "x942 mint B" x942
  case dhSpkiFields pubC of
    Just (p, g, q, _) -> do
      assertEqual "x942 p" dhX942P p
      assertEqual "x942 g" dhX942G g
      assertEqual "x942 q" (Just dhX942Q) q
    Nothing -> assertFailure "x942 SPKI failed to parse"
  agree "x942" 128 privC pubC privD pubD
  expectBadKey "garbage params refused" =<<
    generateKey env (GenDHKeypair "bogus")

caseRawVsDer :: IO ()
caseRawVsDer = withBackend $ \env -> do
  let pub = KeyDer ecPubDer
      derSpec = SigECDSA { sigEc = mkEc "P-256" "DER", sigEcDigest = Just D_SHA256 }
      rawSpec = SigECDSA { sigEc = mkEc "P-256" "RAW", sigEcDigest = Just D_SHA256 }
  -- Same bytes under the wrong encoding are rejected: the backend never
  -- sniffs or converts encodings silently.
  r1 <- verify env derSpec pub ecMsg ecSigRaw
  case r1 of
    EngineFail (BackendAuthFailed _) -> pure ()
    EngineFail (BackendBadParam _ _) -> pure ()
    other -> assertFailure ("raw-as-der must be rejected, got " ++ show other)
  -- The 71-byte DER fixture is odd, so length alone disproves
  -- it on the raw row: pin the length refusal exactly.
  expectSigLenRange "der-as-raw refused by length" =<<
    verify env rawSpec pub ecMsg ecSigDer
  -- RSA v1.5 is supported (see caseRsaKats); the XOF
  -- digest never makes a servable RSA spec.
  expectUnsupported "rsa xof never servable"
    =<< sign env (SigRSA_PKCS1v15 D_SHAKE128) (KeyDer ecPrivDer) ecMsg
  -- The NIST prime curves, every fixed-width digest, and the
  -- raw row are supported (see caseEcdsaCurvesVectors); off-set
  -- curves and XOF digests stay out, never coerced.
  expectUnsupported "ecdsa p-224 never servable"
    =<< sign env (SigECDSA (mkEc "P-224" "DER") (Just D_SHA256)) (KeyDer ecPrivDer) ecMsg
  expectUnsupported "ecdsa xof never servable"
    =<< sign env (SigECDSA (mkEc "P-256" "DER") (Just D_SHAKE128)) (KeyDer ecPrivDer) ecMsg
