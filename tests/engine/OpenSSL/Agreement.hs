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


ecdhSecretDE, ecdhSecretDEcof :: ByteString
ecdhSecretDE = hex "01d8b812087d09360c6db7f56ebc9c9799348bf951571db0390a8fd5e696c1369aedb255"
ecdhSecretDEcof = hex "07e629aca2075197a2a88ca5e4dc2c870bb32ae36a070c84bde114af867386b2a58879e4"


-- | S10e DH KAT fixtures: two ffdhe2048 pairs (pinned-CLI genpkey);
-- the secret is pinned-CLI @pkeyutl -derive@ output (A->B and B->A agree).
dhPrivA, dhPrivB, dhPeerA, dhPeerB, dhSecretAB, dhPrime2048 :: ByteString
dhPrivA = hex $ concat
  [ "3082013f0201003082011706092a864886f70d010301308201080282010100ff"
  , "ffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9"
  , "e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3"
  , "df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c93598"
  , "4f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc"
  , "0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae"
  , "56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f6191"
  , "72fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c5"
  , "8ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff02"
  , "0102041f021d009fa3ef2b4c8dfa3c47df391c7a7bc8018609291f24a761a569"
  , "699de1"
  ]
dhPrivB = hex $ concat
  [ "3082013f0201003082011706092a864886f70d010301308201080282010100ff"
  , "ffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9"
  , "e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3"
  , "df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c93598"
  , "4f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc"
  , "0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae"
  , "56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f6191"
  , "72fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c5"
  , "8ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff02"
  , "0102041f021d0147586245374ff5bc320cfe03ca2049b8b46f5eb702c9c3b1e0"
  , "5a5ca0"
  ]
dhPeerA = hex $ concat
  [ "f738b2ecbdd1d53faa936e55572f1d5304d2a1b983454250848e463dbb125727"
  , "c865d36944cd303ae8daf3855df44cedfc5352c47d090c96efeaed6f70e17bf3"
  , "60aa2248c4c6664c8713d3aa7a53d711c883f7c1493cb69e8a72068af1ab5705"
  , "097e538536523384cf237c576cc3d9acc47c26768162c1290687a596a7a6aa87"
  , "33e04354594fabad2eb42797518dcc5220194a5106195bbdba6e9e7025dd33bf"
  , "cfd1c95e8ad1efc97c0884b31079b794fba0d583fcb93096c76a17b4f8b3c067"
  , "0477c56f1ff367b1ecdfeb90fc25f7b1dae5ebc377d059a3d7b7e66e9bc26c26"
  , "5caee6fd5528c97b892eeb89842d666299c02e1344620662148952a1cc103fa2"
  ]
dhPeerB = hex $ concat
  [ "c75ae3465dfd93b6a1b50841c679448a34ef087b30edfe7c25bd9d897d105e6d"
  , "d943419867a2009eea2f0e931b1925e134468889a06d92c3a5251af1b39a4092"
  , "ba99e124f795852a9de46f85b421f4d5232d73b0b2ba42f033609789f0ca2bc3"
  , "16f79b7a64ad04f410dfb0443ebac1e8844485e9e1c3772ef0558623a9ef3476"
  , "ff8549d3a259511e0490a7b4af4f8f0b73582e1cf2bafdc43486141631972039"
  , "38e4c95ecbddf0bc638d09a12d473e5b1cc576831e43a0cb35f8561e40f5c264"
  , "d66a58f3fcc14ed3bf9a71ac134810fca2da8a98c47c3db55f05d228a9efd4a3"
  , "de7db7d1e45b79a0636fc3f6885efce43b24900b2341ef074543d54120dcd700"
  ]
dhSecretAB = hex $ concat
  [ "96cbacbfc6da3d06a280605284b5729ccce84f1896870ece31468d38f3463c90"
  , "98c303e4abc67edacbb6a78a074a869ea32e293f621ac0546214310932a024e9"
  , "1f0f9f60ff8b329cf655734012a67fb37cc03a281522b56c52944f0332810ad2"
  , "a7c4680ce64db5c13155153dfa9ece121622c9338b605441097d4a5c83da8d8d"
  , "528ceb3b2550eb6b2dfdb2f76ffa8fbcb6aabf7e93495c84c395c9e2d2a2442b"
  , "617f2af65ef63436ee5df3634b530b9373f3c985a91d4930995e1b05db29d82d"
  , "95762e42025f58f59e08c805e65be03c131016f05c1cfec08c94a046ec053048"
  , "5d3d8516e9de0a331e6ec041cc354c7b44950f1811dfe063242781d7a7fe0cc4"
  ]
dhPrime2048 = hex $ concat
  [ "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695"
  , "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a"
  , "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935"
  , "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a"
  , "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4"
  , "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61"
  , "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005"
  , "c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"
  ]


-- | Full-width DH KAT fixtures: an ffdhe2048 pair (OpenSSL 4.0.2
-- genpkey, offline) whose shared secret starts with 0x00. The same
-- pinned vector as the sanitizer @prod-dh-width@ case; the secret
-- is the left-padded @pkeyutl -derive@ output, cross-checked by
-- independent big-int arithmetic at generation time.
dhPadPrivA, dhPadPrivB, dhPadPeerA, dhPadPeerB, dhPadSecret :: ByteString
dhPadPrivA = hex $ concat
  [ "3082013e0201003082011706092a864886f70d010301308201080282010100"
  , "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d36"
  , "95a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4"
  , "617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f"
  , "57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f"
  , "483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42"
  , "a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc034"
  , "04cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733b"
  , "b5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97"
  , "ffffffffffffffff020102041e021c3c1d2502efef371d66145d353243a1b6"
  , "11a50fbd6116e82f25a6bb4c"
  ]
dhPadPrivB = hex $ concat
  [ "3082013f0201003082011706092a864886f70d010301308201080282010100"
  , "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d36"
  , "95a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4"
  , "617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f"
  , "57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f"
  , "483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42"
  , "a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc034"
  , "04cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733b"
  , "b5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97"
  , "ffffffffffffffff020102041f021d01e24035d936f9c80346520ffe08eee7"
  , "5aab53fd4a6b07dc53029aa851"
  ]
dhPadPeerA = hex $ concat
  [ "b5031e2d1102a913689788f835b01459be9c35bba5f339f2e11ac2a3b66078"
  , "d7077be61f967c4e4ac380fe0ae73a80d40cb7dcfc84cec5fd3f28fef08074"
  , "93eacefa6150f43be868d111a59f28c4fd1625cd48fca4420ca91caa372a4a"
  , "6edb4cb2059b0762891519bb357b4637ac67e724de8e9931a71aaa09ad97ac"
  , "1b56046a3efd874268a25c147d5664df5bbd4f266bc264b50b88b67aefb70b"
  , "c4218f9d49757a2c6cb77b352dc48cddc60a8c340eaf46bb7139746a9e75e0"
  , "15cb3622713785f73c779e812326af2c373434a28d1c27b2421b6c59f6280e"
  , "467854fd725a6274f1cdf1d47cae9cbd851a778c4a494acd2811b22c5adcb7"
  , "6b39abb41bd5e7da"
  ]
dhPadPeerB = hex $ concat
  [ "126a89220e681d915d9fb9cb22f8420f770923d5e81d0b340f7c4511688d13"
  , "4e92107fb8124a36672426a1fe39dba38e454472347298aaac48b4eaff6e37"
  , "dd4394ba3293ee304bba4aba969e4e856a4458f7d71c5c423a3a08a01b7ebe"
  , "587f0e90d12ab580267b4b982d792fc7410b3de152a102e88d4776e85d5a3e"
  , "ce1415b00333a9c97693071047c063d006232d1c5c6d37f85b63cd4edc02ae"
  , "f4095f9806bc21d65ad612242b8d1d3aa1b88b91dad1264d89367a8318d979"
  , "1e491edd6289c541b20436c6647af0f2d60f8a87cffd77e4efaea29f75bcb0"
  , "67ee7b4dc6bc91216ba7b32456cff5d8739c4f9c128782fdab722aa8ee1fe1"
  , "5c81d715f88aeb19"
  ]
dhPadSecret = hex $ concat
  [ "00ce799864d8059c2e77b227556aa9f7c91820d4b65fb4d45097e8f4fbbf3c"
  , "8dd8bc9bf75c0cba9b1e5974a367bb395c070411e69b14916c6513569b419d"
  , "79c64c49dff416aee8435750e450750dfc5b6d1d5695183b12cf2a47d7a979"
  , "aea27bdd575c139984e54573f5d62bf7901051ed84dc02f75c1493a2712596"
  , "f20f5a3b789d8ad902b85a36a447f3d0db556e2de7412baf9d36175809f932"
  , "ed792739a24b2d7490db6c5e30dd170d195664bced25e092cd60ad6b08b8f5"
  , "bc42d28b90e6ad310cfe7dbb3fc45e7cdca6cb34b78a0a0b3b88eaeacea633"
  , "f02704df21b2129e710119104a643629fed2592261a8a38d5b78984058ee0f"
  , "1188bbf6013c43e0"
  ]


-- | X9.42 domain triple (1024-bit DSA paramgen output
-- re-encoded as SEQ{p, g, q}; sign pads stripped).
dhX942P, dhX942G, dhX942Q :: ByteString
dhX942P = hex $ concat
  [ "ddc17b058e1ec15b51996f85eae0b678ea9bb72444159fe2fcd0f44f7be7e7"
  , "37eeebe94c47e751bcd826c53960d7e1af0f0f421f4f31104d07b13af401ed76"
  , "567b31d2ebf1eaac37c626698e60dff128c671f9055600740581508c10081444"
  , "4ffa21fada6af011260c1bc070a3d58f9a098607d92a938eff5a16fdc388e41e"
  , "09"
  ]
dhX942G = hex $ concat
  [ "d1a4428b2e04060534ad2a284a7039276bf6306a88bfde2d92332a824da217"
  , "82e30b3642625f08ca00c5997626d6733d00eafcc206afbbdafb0086ddf1d06d"
  , "4887ff77e549937bdde181e6955cec0b29e710168d891687515c1ad3e03eee3f"
  , "60f96a9063d540b7907cdb24b99dfd490e3cc447be9d47cdefde5aa30c857a9c"
  , "fa"
  ]
dhX942Q = hex "fcbd52881b3c3975a661ce18c867832617b49b0dc2c467c10c264a67"


-- | S10 ECDH KAT fixtures: two fresh P-256 pairs plus one P-384 pair
-- (pinned-CLI genpkey); the secrets are pinned-CLI @pkeyutl -derive@
-- output (A->B and B->A agree; cofactor mode agrees on P-256, h=1).
ecdhPrivA, ecdhPubA, ecdhPrivB, ecdhPubB :: ByteString
ecdhPrivA = hex $ concat
  [ "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
  , "01010420311c1de45b711a6ba76e060470e0db863ac2b9ff60a44db447fc70360"
  , "eaa5ef6a1440342000448ac633084fc453d57a59703893c48f26d1eefd067c1f8"
  , "e69382565b21bf3a2e6dc574e35285f5dd6028eb00471de54d74e3de18a1f9a8a"
  , "280081e7ccec47e98"
  ]
ecdhPubA = hex $ concat
  [ "3059301306072a8648ce3d020106082a8648ce3d0301070342000448ac633084"
  , "fc453d57a59703893c48f26d1eefd067c1f8e69382565b21bf3a2e6dc574e35285"
  , "f5dd6028eb00471de54d74e3de18a1f9a8a280081e7ccec47e98"
  ]
ecdhPrivB = hex $ concat
  [ "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
  , "0101042087762e6a31210036b5e0cf9af7e2703f31c84916b9df67b4f062f3021"
  , "991d835a144034200043bb6f938a377952e614445d9933c97d15a76d94d1ef9d8"
  , "bafb02ac3cda56ee209e5d0221a899cf628c9cef305fe1a14f3af46e0c7ac2be8"
  , "b68e0e2707d9225e1"
  ]
ecdhPubB = hex $ concat
  [ "3059301306072a8648ce3d020106082a8648ce3d030107034200043bb6f938a3"
  , "77952e614445d9933c97d15a76d94d1ef9d8bafb02ac3cda56ee209e5d0221a89"
  , "9cf628c9cef305fe1a14f3af46e0c7ac2be8b68e0e2707d9225e1"
  ]


ecdhPrivC, ecdhPubC, ecdhSecretAB, ecdhSecretCC :: ByteString
ecdhPrivC = hex $ concat
  [ "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010"
  , "104302adb33390dd6fbfc9522bade688cb1ef2960f2bd7fe0c29a87153357e7f7"
  , "aaf44c2efda7eccd10cca7a8d117f49de506a16403620004adce07c5ce4996c1c"
  , "3b5561a7e2ef688d0c046d473ab6676a2e472c096e24d923304f955b099b1ca6d"
  , "9fd414a536e90b6f30acb85c0f74e539ee2905d574ac7b7a918172d8f7c075e833"
  , "3883b626a7a74649dda234ed7694f4332d4be4f227cf"
  ]
ecdhPubC = hex $ concat
  [ "3076301006072a8648ce3d020106052b8104002203620004adce07c5ce4996c1"
  , "c3b5561a7e2ef688d0c046d473ab6676a2e472c096e24d923304f955b099b1ca6d"
  , "9fd414a536e90b6f30acb85c0f74e539ee2905d574ac7b7a918172d8f7c075e833"
  , "3883b626a7a74649dda234ed7694f4332d4be4f227cf"
  ]
ecdhSecretAB = hex "9671ac43cbf5d68893022679b588483c63cdd6e370ae62c81d4ce95d9eae7b05"
ecdhSecretCC = hex "6c0636f7c3858a26c97f7215f27f7a5a952ac99513c70ee3ea54386dad9ff3e50f9eb0004242035779c505284316e9c0"


-- | XDH KAT fixtures: two fresh CLI pairs per curve (pinned-CLI
-- genpkey; the A halves are the KeyImportSpec goldens) with
-- pinned-CLI @pkeyutl -derive@ secrets (A->B and B->A agree),
-- plus the wycheproof tc1 exchange vectors per curve (external
-- KATs; the tc1 bases assemble through @montgomeryPrivateDer@,
-- whose framing the import goldens pin independently).
xdhPrivA, xdhPrivB, xdhSecretAB :: ByteString
xdhPrivA = hex "302e020100300506032b656e04220420107c0296168df7ef1da8bf471f5ac2d793788e84eb8b34d86a2605b2424d0847"
xdhPrivB = hex "302e020100300506032b656e04220420202ea3672e47f763457157ae6915e4ac327f6120a8c1551ae73813d3b3c92175"
xdhSecretAB = hex "a52e5f55676e562a916a32f95cfc05671e85f17bd5975647dcb09eec6418073c"


xdhPointA, xdhPointB :: ByteString
xdhPointA = hex "684cd5fbe3473e3cb8dc7263ec9f0a837d770e5c9e2db619c8e9b0294b0e991d"
xdhPointB = hex "67d790586fcaf48d1628ec7ea2be1281c6cf1e599fffbd059ece5c521143ab7c"


xdh48PrivA, xdh48PrivB, xdh48SecretAB :: ByteString
xdh48PrivA = hex $ concat
  ["3046020100300506032b656f043a0438f0b746caef9d715d94ecf3cc83b6b5caf0140402"
  ,"ff06b3043a56f2904b1594350ce4b7523116d8422a97365bb37c3f11f746e4765e71efad"
  ]
xdh48PrivB = hex $ concat
  ["3046020100300506032b656f043a0438d89fb4cb38f9a4196b39873961f8349f729865ac"
  ,"74ab6f4fee94ed46a668c8b19f38cb4b936dcb68253ebec18a7a4a16565f60b86e5d18cf"
  ]
xdh48SecretAB = hex "d361d60928257b80eb3709a87502c6b5a1d0959533690a29d3af730824a55f3bfb749afe176ca5e4c62dd16a0c17f283dc46ace3047aee2a"


xdh48PointA, xdh48PointB :: ByteString
xdh48PointA = hex $ concat
  ["a661ed99e0dfbb6c4985d6affe9247682f0a809ffab3e351e1142820c636c30c6947fb4c"
  ,"69833ba7e4ec2ec0638016f5ddbcd72e77ebf670"
  ]
xdh48PointB = hex "20ae62a605737b5568b8423ebc0f1479b088c8bb1c2d10de702ea71b179e694d1e87c51ca1b2817e05387e4ca918ae13499e64493bb99c27"


xdhTc1Priv, xdhTc1Pub, xdhTc1Shared :: ByteString
xdhTc1Priv = hex "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475"
xdhTc1Pub = hex "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829"
xdhTc1Shared = hex "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320"


xdh48Tc1Priv, xdh48Tc1Pub, xdh48Tc1Shared :: ByteString
xdh48Tc1Priv = hex $ concat
  ["e41c63d5159c89de12163fde9d04cf1f430f346b8b2c1f2a4b1f5aee63d17aec29d4b1de"
  ,"bf8b6457e7809d2b15ff9779c97becb04b824efa"
  ]
xdh48Tc1Pub = hex $ concat
  ["f8073fc01c8358362c08740c914b419847ef1e409f4e40d9440febc26f00551adb1c37c6c"
  ,"2a87d8283b8cb453e928a0d42793f72894e0f81"
  ]
xdh48Tc1Shared = hex $ concat
  ["acd496ceb5f68bf9c267196b405f59701a40ec88744b7e5e60bf8f81e8b13df448efe4020"
  ,"01750edb0b695a0512f08c572a2e356493d170b"
  ]


-- | sect283k1 ECDH KAT (pinned CLI): plain and cofactor (h=2, so
-- the two secrets differ) plus the bare peer point.
ecdhPrivD, ecdhPubD, ecdhPrivE, ecdhPubE :: ByteString
ecdhPrivD = hex $ concat
  [ "308180020101042400d5930db9e585af6e5ea746c0fd932202771cbcd2e4acd91"
  , "4ca94a95ef95c2eab736beca00706052b81040010a14c034a000400a519b87152d"
  , "fcb842c7ba62870f3c910db05aaf690bb790c2226822005de24e118e64e0731b30"
  , "b4a66a4a86ebaa58b5b0a23673ab13bcb46421ab42a4710f24c578cbbc94c7a38"
  ]
ecdhPubD = hex $ concat
  [ "305e301006072a8648ce3d020106052b81040010034a000400a519b87152dfcb84"
  , "2c7ba62870f3c910db05aaf690bb790c2226822005de24e118e64e0731b30b4a66"
  , "a4a86ebaa58b5b0a23673ab13bcb46421ab42a4710f24c578cbbc94c7a38"
  ]
ecdhPrivE = hex $ concat
  [ "3081800201010424000b81e39e6ef5ccc92df1b207beb8cd71b246ff4e57c1494d"
  , "4221f5fa91d00b01dd2f40a00706052b81040010a14c034a000407277db5580914a"
  , "8be1b6752a4abbe5e329d63243632155bd04174a611af790852d57a16079ed448d"
  , "e40bb0c7d01f3a882bf0aa01e3278b8f537397cc606b7323ef57eeb134d022a"
  ]
ecdhPubE = hex $ concat
  [ "305e301006072a8648ce3d020106052b81040010034a000407277db5580914a8be1"
  , "b6752a4abbe5e329d63243632155bd04174a611af790852d57a16079ed448de40bb"
  , "0c7d01f3a882bf0aa01e3278b8f537397cc606b7323ef57eeb134d022a"
  ]
