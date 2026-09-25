{- | Operation-layer smoke over the real OpenSSL backend.

Independent-consumer check: every backend call in this spec answers
an effect planned by an operation slot — SHA-256 multipart
sequencing, HMAC sign/verify, AES-CBC encrypt/decrypt, ECDSA
sign/verify in both DER and RAW encodings, and a dual digest+encrypt
final. Oracles are the same independent vectors as in OpenSSLSpec
(FIPS 180-4, RFC 4231, SP 800-38A, the fixed ECDSA vector), plus a
host-computed SHA-256 for the dual case.

Driver conventions (smoke-local): init parameters select the ECDSA
encoding (@"RAW"@ or anything-else-means-DER); a backend
authentication failure on a verify-shaped call is a verdict
('GotValid False'), never a malfunction.
-}
{-# LANGUAGE OverloadedStrings #-}
module OperationSmokeSpec (spec) where

import qualified Data.ByteString as BS
import Data.Bits (xor)
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend
  ( BackendError (..)
  , BackendEnv
  , CipherSpec (C_AES256_CBC, C_AES256_CTR)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EcSpec (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , MacSpec (..)
  , ResourceSaveability (..)
  , SigSpec (..)
  , UnsaveableReason (..)
  )
import Haskoki.Engine.Driver (drainReleases)
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , emptyModel
  )
import Haskoki.Operation
  ( CipherDir (..)
  , CipherSpec (..)
  , CryptoEffect (..)
  , CryptoError (..)
  , CryptoResult (..)
  , DigestStream (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , MsgFamily (..)
  , OpEnv (..)
  , SessionOps
  , SlotKind (..)
  , StepOutcome (..)
  , activeDigest
  , activeSlots
  , bufferedLength
  , emptySessionOps
  , hasDual
  , initDualOperation
  , initMessageOperation
  , initOperation
  , insertOp
  , lookupSingle
  , mkActiveDigest
  , setLive
  )
import Haskoki.Operation.Cipher (finishCipher, planCipherOneShot)
import Haskoki.Operation.Digest (finishDigest, planDigestFinal, planDigestUpdate)
import Haskoki.Operation.Dual (finishDual, planDualFinal, planDualUpdate)
import Haskoki.Operation.Message
  ( MsgBegin (..)
  , MsgNext (..)
  , MsgOneShot (..)
  , finalizeMessage
  , finishMessage
  , planMessageBegin
  , planMessageNext
  , planMessageOneShot
  )
import Haskoki.Operation.Signature
  ( finishSign
  , finishVerify
  , planSignOneShot
  , planVerifyOneShot
  )
import Haskoki.Outcome (ResourceRelease (..))
import Haskoki.Recipe.Cipher (decodeCtrParams, encodeCtrParams)
import Haskoki.Output (OutputPlan (..), TypedWrite (..), WritePayload (..))
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , Registry
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Request (OutputIntent (..))
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( EngineResourceId
  , ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "operations over the real backend"
  [ testCase "sha256 multipart through the digest slot" caseSha256Slot
  , testCase "streamed digest equals one-shot across all algorithms" caseStreamEqualsOneShot
  , testCase "hmac sign/verify through slots" caseHmacSlot
  , testCase "aes-256-cbc KAT through cipher slots" caseAesKatSlot
  , testCase "aes padded roundtrip through cipher slots" caseAesPadSlot
  , testCase "aes-ctr unaligned roundtrip through cipher slots" caseAesCtrSlot
  , testCase "ecdsa sign/verify through slots, DER and RAW" caseEcdsaSlot
  , testCase "dual digest+encrypt through the real backend" caseDualSlot
  , testCase "denied init plans no crypto" caseDeniedPlansNothing
  , testCase "message aes KAT through message slots" caseMessageAesKat
  , testCase "message hmac sign/verify through slots" caseMessageHmac
  ]

-- ---------------------------------------------------------------------------
-- Vectors (same independent oracles as OpenSSLSpec)
-- ---------------------------------------------------------------------------

hex :: String -> ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

sha256Long :: ByteString
sha256Long = hex "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

longMsg :: ByteString
longMsg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

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

sha256OfAesPt :: ByteString
sha256OfAesPt = hex "a063df83a8c28a49daf4aeba0e29ee7b2177e8511072944c3d299cf77dc83e7a"

ecMsg :: ByteString
ecMsg = hex "543037206563647361206b6174206d657373616765"

ecPrivDer :: ByteString
ecPrivDer = hex "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e9032e4f06ee6b5397252cfb48e73a8d3f7717d4024dd4cc5b98bbf041c11bb3a14403420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"

ecPubDer :: ByteString
ecPubDer = hex "3059301306072a8648ce3d020106082a8648ce3d03010703420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"

ecSigRaw :: ByteString
ecSigRaw = hex "debdbb00072c928d38bf43791d32f0eefe8a562d8444869adabdf77820cbed4963cc0a678a74c3e006c7387907210825f12920ff5f15b96709291e48b84ddc21"

-- ---------------------------------------------------------------------------
-- Fixtures: registry, model, sessions
-- ---------------------------------------------------------------------------

sha256Mech, hmacMech, aesCbcMech, ecdsaMech, aesCtrMech :: MechanismId
sha256Mech = MechanismId 0x250
hmacMech = MechanismId 0x251
aesCbcMech = MechanismId 0x1082
ecdsaMech = MechanismId 0x1041
aesCtrMech = MechanismId 0x1086

-- | The curated registry as-is: every mechanism these smoke
-- tests touch (0x250, 0x251, 0x1082, 0x1041) ships behavior-tested
-- (promoting a tested row is a 'DuplicateMechanism' error by
-- design).
smokeRegistry :: Registry
smokeRegistry = curatedRegistry

hmacOid, aesOid, ecPrivOid, ecPubOid :: ObjectId
hmacOid = ObjectId 11
aesOid = ObjectId 12
ecPrivOid = ObjectId 13
ecPubOid = ObjectId 14

mkObject :: ObjectId -> ObjectState
mkObject oid = ObjectState
  { osId = oid
  , osRevision = Revision 1
  , osGeneration = Generation 1
  , osAttrs = Map.fromList
      [(AttrClass, ValULong 4), (AttrPrivate, ValBool False)]
  , osOwner = Nothing
  , osSlot = SlotId 7
  }

smokeModel :: Model
smokeModel = emptyModel
  { mObjects = Map.fromList [(oid, mkObject oid) | oid <- [hmacOid, aesOid, ecPrivOid, ecPubOid]]
  , mHandles = Map.fromList
      [ (ExternalHandle 101, HandleBinding hmacOid (Generation 1))
      , (ExternalHandle 102, HandleBinding aesOid (Generation 1))
      , (ExternalHandle 103, HandleBinding ecPrivOid (Generation 1))
      , (ExternalHandle 104, HandleBinding ecPubOid (Generation 1))
      ]
  }

smokeEnv :: OpEnv
smokeEnv = OpEnv
  { oeRegistry = smokeRegistry
  , oeCaps = mkCapabilities
      [ (sha256Mech, OpDigest)
      , (hmacMech, OpSign)
      , (hmacMech, OpVerify)
      , (aesCbcMech, OpEncrypt)
      , (aesCbcMech, OpDecrypt)
      , (aesCtrMech, OpEncrypt)
      , (aesCtrMech, OpDecrypt)
      , (ecdsaMech, OpSign)
      , (ecdsaMech, OpVerify)
      ]
  , oeModel = smokeModel
  }

smokeSession :: SessionState
smokeSession = SessionState
  { ssId = SessionId 1
  , ssSlot = SlotId 7
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

hmacKeyP, aesKeyP, ecPrivKeyP, ecPubKeyP :: KeyPolicy
hmacKeyP = KeyPolicy (ExternalHandle 101) [OpSign, OpVerify] False
aesKeyP = KeyPolicy (ExternalHandle 102) [OpEncrypt, OpDecrypt] False
ecPrivKeyP = KeyPolicy (ExternalHandle 103) [OpSign] False
ecPubKeyP = KeyPolicy (ExternalHandle 104) [OpVerify] False

-- ---------------------------------------------------------------------------
-- The driver: planned effects answered by the real backend
-- ---------------------------------------------------------------------------

keyFor :: ObjectId -> Maybe KeyMaterial
keyFor oid
  | oid == hmacOid = Just (KeyBytes hmacKey1)
  | oid == aesOid = Just (KeyBytes aes256Key)
  | oid == ecPrivOid = Just (KeyDer ecPrivDer)
  | oid == ecPubOid = Just (KeyDer ecPubDer)
  | otherwise = Nothing

toBytes :: EngineResult ByteString -> CryptoResult
toBytes (EngineOk b) = GotBytes b
toBytes (EngineFail (BackendUnsupported o w)) =
  GotCryptoError (CryptoUnsupported o w)
toBytes (EngineFail (BackendBadKey o w)) =
  GotCryptoError (CryptoBadKey o w)
toBytes (EngineFail err) = GotCryptoError (CryptoFailed (show err))

-- | Verify-shaped answers: an authentication failure is a verdict,
-- never a malfunction.
toVerifyBool :: EngineResult Bool -> CryptoResult
toVerifyBool (EngineOk v) = GotValid v
toVerifyBool (EngineFail (BackendAuthFailed _)) = GotValid False
toVerifyBool (EngineFail err) = GotCryptoError (CryptoFailed (show err))

toVerifyUnit :: EngineResult () -> CryptoResult
toVerifyUnit (EngineOk ()) = GotValid True
toVerifyUnit (EngineFail (BackendAuthFailed _)) = GotValid False
toVerifyUnit (EngineFail err) = GotCryptoError (CryptoFailed (show err))

smokeEncoding :: ByteString -> String
smokeEncoding params
  | params == "RAW" = "RAW"
  | otherwise = "DER"

runRealEffect :: BackendEnv OpenSSL4 -> CryptoEffect -> IO CryptoResult
runRealEffect env fx = case fx of
  FxDigest mech input
    | mech == sha256Mech -> toBytes <$> digestOneShot env D_SHA256 input
    | otherwise -> pure (unsupported fx)
  FxSign mech (Just oid) params input
    | mech == hmacMech, Just key <- keyFor oid ->
        toBytes <$> macSign env (MacHMAC D_SHA256 Nothing) key input
    | mech == ecdsaMech, Just key <- keyFor oid ->
        toBytes <$> sign env (SigECDSA (EcSpec "P-256" (smokeEncoding params)) (Just D_SHA256)) key input
    | otherwise -> pure (badKey fx)
  FxVerify mech (Just oid) params input sig
    | mech == hmacMech, Just key <- keyFor oid ->
        toVerifyBool <$> macVerify env (MacHMAC D_SHA256 Nothing) key input sig
    | mech == ecdsaMech, Just key <- keyFor oid ->
        toVerifyUnit <$> verify env (SigECDSA (EcSpec "P-256" (smokeEncoding params)) (Just D_SHA256)) key input sig
    | otherwise -> pure (badKey fx)
  FxCipher DirEncrypt mech (Just oid) iv input
    | mech == aesCbcMech, Just key <- keyFor oid ->
        toBytes <$> cipherEncrypt env C_AES256_CBC key iv input
    | mech == aesCtrMech, Just key <- keyFor oid, Just cb <- ctrBlock iv ->
        toBytes <$> cipherEncrypt env C_AES256_CTR key cb input
    | otherwise -> pure (badKey fx)
  FxCipher DirDecrypt mech (Just oid) iv input
    | mech == aesCbcMech, Just key <- keyFor oid ->
        toBytes <$> cipherDecrypt env C_AES256_CBC key iv input
    | mech == aesCtrMech, Just key <- keyFor oid, Just cb <- ctrBlock iv ->
        toBytes <$> cipherDecrypt env C_AES256_CTR key cb input
    | otherwise -> pure (badKey fx)
  -- Message effects: per-message params drive crypto (the IV
  -- arrives per message, not from init). The backend is not
  -- AEAD, so bound AAD is honestly refused, never ignored.
  FxMessageCipher DirEncrypt mech (Just oid) params aad input
    | mech == aesCbcMech, Just key <- keyFor oid, BS.null aad ->
        toBytes <$> cipherEncrypt env C_AES256_CBC key params input
    | mech == aesCbcMech, Just _ <- keyFor oid ->
        pure (GotCryptoError (CryptoUnsupported "smoke driver" "non-AEAD backend takes no AAD"))
    | otherwise -> pure (badKey fx)
  FxMessageCipher DirDecrypt mech (Just oid) params aad input
    | mech == aesCbcMech, Just key <- keyFor oid, BS.null aad ->
        toBytes <$> cipherDecrypt env C_AES256_CBC key params input
    | mech == aesCbcMech, Just _ <- keyFor oid ->
        pure (GotCryptoError (CryptoUnsupported "smoke driver" "non-AEAD backend takes no AAD"))
    | otherwise -> pure (badKey fx)
  FxMessageSign mech (Just oid) _params input
    | mech == hmacMech, Just key <- keyFor oid ->
        toBytes <$> macSign env (MacHMAC D_SHA256 Nothing) key input
    | otherwise -> pure (badKey fx)
  FxMessageVerify mech (Just oid) _params input sig
    | mech == hmacMech, Just key <- keyFor oid ->
        toVerifyBool <$> macVerify env (MacHMAC D_SHA256 Nothing) key input sig
    | otherwise -> pure (badKey fx)
  _ -> pure (unsupported fx)
  where
    unsupported e = GotCryptoError (CryptoUnsupported "smoke driver" (show e))
    badKey _ = GotCryptoError (CryptoBadKey "smoke driver" "unknown key object")
    ctrBlock iv = case decodeCtrParams iv of
      Just (128, cb) -> Just cb
      _ -> Nothing

withBackend :: (BackendEnv OpenSSL4 -> IO ()) -> IO ()
withBackend action = do
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk env -> action env >> closeBackend env

-- | Run one planned effect and fail on anything but bytes.
expectBytes :: BackendEnv OpenSSL4 -> CryptoEffect -> IO ByteString
expectBytes env fx = do
  res <- runRealEffect env fx
  case res of
    GotBytes b -> pure b
    other -> assertFailure ("expected bytes, got " ++ show other)

stagedBytes :: StepOutcome -> Maybe ByteString
stagedBytes out = case soPlan out of
  Just plan -> case opWrites plan of
    [TypedWrite _ _ (PayloadBytes bs)] -> Just bs
    _ -> Nothing
  Nothing -> Nothing

-- ---------------------------------------------------------------------------
-- Cases
-- ---------------------------------------------------------------------------

-- | Allocate a real backend digest context, failing loudly.
allocStream :: BackendEnv OpenSSL4 -> DigestAlg -> IO EngineResourceId
allocStream env alg = do
  eRid <- digestInit env alg
  case eRid of
    EngineOk rid -> pure rid
    EngineFail err -> assertFailure ("digestInit failed: " ++ show err) >> undefined

-- | Feed one part through the backend, failing loudly.
feedStream :: BackendEnv OpenSSL4 -> EngineResourceId -> ByteString -> IO ()
feedStream env rid part = do
  r <- digestUpdate env rid part
  case r of
    EngineOk () -> pure ()
    EngineFail err -> assertFailure ("digestUpdate failed: " ++ show err)

-- | Install a live stream on the digest slot.
withStream :: SessionOps -> EngineResourceId -> SessionOps
withStream ops rid = case lookupSingle ops SlotDigest of
  Just active -> case activeDigest active of
    Just sc -> insertOp
      (mkActiveDigest (setLive (DigestStream rid False) sc)) ops
    Nothing -> ops
  Nothing -> ops

caseSha256Slot :: IO ()
caseSha256Slot = withBackend $ \env -> do
  let dArgs = InitArgs OpDigest sha256Mech BS.empty Nothing Nothing Nothing
      (ops0, i0) = initOperation smokeEnv emptySessionOps smokeSession dArgs
  assertEqual "digest init ok" CKR_OK (ioCode i0)
  rid <- allocStream env D_SHA256
  let opsS = withStream ops0 rid
  let (ops1, _, u1) = planDigestUpdate opsS smokeSession "abc"
  assertEqual "update 1 ok" CKR_OK (soCode u1)
  case soEffects u1 of
    [FxDigestFeed rid1 part1] -> do
      assertEqual "feed 1 names the stream" rid rid1
      feedStream env rid1 part1
    other -> assertFailure ("expected one feed effect, got " ++ show other)
  assertEqual "update 1 buffers nothing" (Just 0) (bufferedLength ops1 SlotDigest)
  let (ops2, _, u2) = planDigestUpdate ops1 smokeSession (BS.drop 3 longMsg)
  assertEqual "update 2 ok" CKR_OK (soCode u2)
  case soEffects u2 of
    [FxDigestFeed rid2 part2] -> do
      assertEqual "feed 2 names the stream" rid rid2
      feedStream env rid2 part2
    other -> assertFailure ("expected one feed effect, got " ++ show other)
  assertEqual "update 2 buffers nothing" (Just 0) (bufferedLength ops2 SlotDigest)
  let (ops3, _, f1) = planDigestFinal ops2 smokeSession "digest"
  case soEffects f1 of
    [FxDigestConsume rid3] -> do
      assertEqual "consume names the stream" rid rid3
      eOut <- digestFinal env rid3
      out <- case eOut of
        EngineOk b -> pure b
        EngineFail err -> assertFailure ("digestFinal failed: " ++ show err)
      let (ops4, fin) = finishDigest ops3 SlotDigest "digest"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "final ok" CKR_OK (soCode fin)
      assertEqual "multipart digest matches FIPS" (Just sha256Long)
        (stagedBytes fin)
      assertEqual "slot freed" [] (activeSlots ops4)
      assertEqual "final releases the stream"
        [ReleaseEngineResource rid] (soReleases fin)
      drainReleases env (soReleases fin)
      gone <- resourceSaveability env rid
      assertEqual "stream drained" (ResourceUnsaveable (UnsaveableGone rid)) gone
    other -> assertFailure ("expected one consume effect, got " ++ show other)

-- | The streamed primitive is byte-identical to the
-- one-shot across every digest algorithm (XOFs agree on
-- unsupported: neither path offers them).
caseStreamEqualsOneShot :: IO ()
caseStreamEqualsOneShot = withBackend $ \env -> do
  let msg = "the quick brown fox jumps over the lazy dog" :: ByteString
      (a, b) = BS.splitAt 20 msg
  mapM_ (check env a b) [minBound .. maxBound]
  where
    check env a b alg = do
      one <- digestOneShot env alg (a <> b)
      streamed <- do
        eRid <- digestInit env alg
        case eRid of
          EngineFail _ -> pure (Left () :: Either () ByteString)
          EngineOk rid -> do
            r1 <- digestUpdate env rid a
            r2 <- digestUpdate env rid b
            r3 <- digestFinal env rid
            case (r1, r2, r3) of
              (EngineOk (), EngineOk (), EngineOk out) -> pure (Right out)
              _ -> pure (Left ())
      case (one, streamed) of
        (EngineOk x, Right y) ->
          assertEqual ("streamed == one-shot: " ++ show alg) x y
        (EngineFail _, Left _) -> pure ()
        (x, y) -> assertFailure
          ("diverge on " ++ show alg ++ ": " ++ show x ++ " vs " ++ show y)

caseHmacSlot :: IO ()
caseHmacSlot = withBackend $ \env -> do
  let sArgs = InitArgs OpSign hmacMech BS.empty (Just hmacKeyP) Nothing Nothing
      (ops0, _) = initOperation smokeEnv emptySessionOps smokeSession sArgs
      (ops1, _, o1) = planSignOneShot ops0 smokeSession "tag" hmacMsg1
  tag <- case soEffects o1 of
    [fx@(FxSign _ _ _ _)] -> do
      out <- expectBytes env fx
      let (_, fin) = finishSign ops1 SlotSign "tag"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "sign ok" CKR_OK (soCode fin)
      case stagedBytes fin of
        Just t -> pure t
        Nothing -> assertFailure "expected staged tag"
    other -> assertFailure ("expected one sign effect, got " ++ show other)
  assertEqual "hmac matches RFC 4231" hmacOut1 tag
  let vArgs = InitArgs OpVerify hmacMech BS.empty (Just hmacKeyP) Nothing Nothing
      (ops2, _) = initOperation smokeEnv emptySessionOps smokeSession vArgs
      (ops3, _, o2) = planVerifyOneShot ops2 smokeSession "verify" hmacMsg1 tag
  case soEffects o2 of
    [fx] -> do
      res <- runRealEffect env fx
      let (ops4, fin) = finishVerify ops3 SlotVerify "verify"
            res (IntentBuffer 0)
      assertEqual "verify ok" CKR_OK (soCode fin)
      assertEqual "slot freed" [] (activeSlots ops4)
    other -> assertFailure ("expected one verify effect, got " ++ show other)
  -- A tampered tag verifies invalid through the same path.
  let (ops5, _) = initOperation smokeEnv emptySessionOps smokeSession vArgs
      (ops6, _, o3) = planVerifyOneShot ops5 smokeSession "verify" hmacMsg1
        (BS.map (255 -) tag)
  case soEffects o3 of
    [fx] -> do
      res <- runRealEffect env fx
      let (_, fin) = finishVerify ops6 SlotVerify "verify"
            res (IntentBuffer 0)
      assertEqual "tampered invalid" CKR_SIGNATURE_INVALID
        (soCode fin)
    other -> assertFailure ("expected one verify effect, got " ++ show other)

caseAesKatSlot :: IO ()
caseAesKatSlot = withBackend $ \env -> do
  let noPad = Just (CipherSpec 16 False)
      eArgs = InitArgs OpEncrypt aesCbcMech aes256Iv (Just aesKeyP) noPad Nothing
      (ops0, _) = initOperation smokeEnv emptySessionOps smokeSession eArgs
      (ops1, _, o1) = planCipherOneShot ops0 smokeSession
        SlotEncrypt "cipher" aes256Pt
  ct <- case soEffects o1 of
    [fx@(FxCipher DirEncrypt _ _ _ _)] -> do
      out <- expectBytes env fx
      let (_, fin) = finishCipher ops1 SlotEncrypt "cipher"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "encrypt ok" CKR_OK (soCode fin)
      case stagedBytes fin of
        Just c -> pure c
        Nothing -> assertFailure "expected ciphertext"
    other -> assertFailure ("expected one cipher effect, got " ++ show other)
  assertEqual "ciphertext matches SP 800-38A" aes256Ct ct
  let dArgs = InitArgs OpDecrypt aesCbcMech aes256Iv (Just aesKeyP) noPad Nothing
      (ops2, _) = initOperation smokeEnv emptySessionOps smokeSession dArgs
      (ops3, _, o2) = planCipherOneShot ops2 smokeSession
        SlotDecrypt "plain" ct
  case soEffects o2 of
    [fx] -> do
      out <- expectBytes env fx
      let (ops4, fin) = finishCipher ops3 SlotDecrypt "plain"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "decrypt ok" CKR_OK (soCode fin)
      assertEqual "roundtrip recovers" (Just aes256Pt) (stagedBytes fin)
      assertEqual "slot freed" [] (activeSlots ops4)
    other -> assertFailure ("expected one cipher effect, got " ++ show other)

caseAesCtrSlot :: IO ()
caseAesCtrSlot = withBackend $ \env -> do
  let stream = Just (CipherSpec 1 False)
      params = encodeCtrParams 128 aes256Iv
      msg = "ctr stream takes unaligned input" :: ByteString
      eArgs = InitArgs OpEncrypt aesCtrMech params (Just aesKeyP) stream Nothing
      (ops0, _) = initOperation smokeEnv emptySessionOps smokeSession eArgs
      (ops1, _, o1) = planCipherOneShot ops0 smokeSession
        SlotEncrypt "cipher" msg
  ct <- case soEffects o1 of
    [fx@(FxCipher DirEncrypt _ _ _ _)] -> do
      out <- expectBytes env fx
      let (_, fin) = finishCipher ops1 SlotEncrypt "cipher"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "encrypt ok" CKR_OK (soCode fin)
      case stagedBytes fin of
        Just c -> pure c
        Nothing -> assertFailure "expected ciphertext"
    other -> assertFailure ("expected one cipher effect, got " ++ show other)
  assertEqual "stream length preserved" (BS.length msg) (BS.length ct)
  let dArgs = InitArgs OpDecrypt aesCtrMech params (Just aesKeyP) stream Nothing
      (ops2, _) = initOperation smokeEnv emptySessionOps smokeSession dArgs
      (ops3, _, o2) = planCipherOneShot ops2 smokeSession
        SlotDecrypt "plain" ct
  case soEffects o2 of
    [fx] -> do
      out <- expectBytes env fx
      let (ops4, fin) = finishCipher ops3 SlotDecrypt "plain"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "decrypt ok" CKR_OK (soCode fin)
      assertEqual "roundtrip recovers" (Just msg) (stagedBytes fin)
      assertEqual "slot freed" [] (activeSlots ops4)
    other -> assertFailure ("expected one cipher effect, got " ++ show other)

caseAesPadSlot :: IO ()
caseAesPadSlot = withBackend $ \env -> do
  let pad = Just (CipherSpec 16 True)
      msg = "padded aes roundtrip" :: ByteString
      eArgs = InitArgs OpEncrypt aesCbcMech aes256Iv (Just aesKeyP) pad Nothing
      (ops0, _) = initOperation smokeEnv emptySessionOps smokeSession eArgs
      (ops1, _, o1) = planCipherOneShot ops0 smokeSession
        SlotEncrypt "cipher" msg
  ct <- case soEffects o1 of
    [fx] -> do
      out <- expectBytes env fx
      let (_, fin) = finishCipher ops1 SlotEncrypt "cipher"
            (GotBytes out) (IntentBuffer 64)
      case stagedBytes fin of
        Just c -> pure c
        Nothing -> assertFailure "expected ciphertext"
    other -> assertFailure ("expected one cipher effect, got " ++ show other)
  assertEqual "one padded block" 32 (BS.length ct)
  let dArgs = InitArgs OpDecrypt aesCbcMech aes256Iv (Just aesKeyP) pad Nothing
      (ops2, _) = initOperation smokeEnv emptySessionOps smokeSession dArgs
      (ops3, _, o2) = planCipherOneShot ops2 smokeSession
        SlotDecrypt "plain" ct
  case soEffects o2 of
    [fx] -> do
      out <- expectBytes env fx
      let (_, fin) = finishCipher ops3 SlotDecrypt "plain"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "decrypt ok" CKR_OK (soCode fin)
      assertEqual "pad tail strips" (Just msg) (stagedBytes fin)
    other -> assertFailure ("expected one cipher effect, got " ++ show other)

caseEcdsaSlot :: IO ()
caseEcdsaSlot = withBackend $ \env -> do
  -- Fresh DER sign through the slot, verified back through the slot.
  let sArgs = InitArgs OpSign ecdsaMech "DER" (Just ecPrivKeyP) Nothing Nothing
      (ops0, _) = initOperation smokeEnv emptySessionOps smokeSession sArgs
      (ops1, _, o1) = planSignOneShot ops0 smokeSession "sig" ecMsg
  sig <- case soEffects o1 of
    [fx@(FxSign _ _ _ _)] -> do
      out <- expectBytes env fx
      let (_, fin) = finishSign ops1 SlotSign "sig"
            (GotBytes out) (IntentBuffer 128)
      assertEqual "sign ok" CKR_OK (soCode fin)
      case stagedBytes fin of
        Just s -> pure s
        Nothing -> assertFailure "expected signature"
    other -> assertFailure ("expected one sign effect, got " ++ show other)
  let vArgs = InitArgs OpVerify ecdsaMech "DER" (Just ecPubKeyP) Nothing Nothing
      (ops2, _) = initOperation smokeEnv emptySessionOps smokeSession vArgs
      (ops3, _, o2) = planVerifyOneShot ops2 smokeSession "verify" ecMsg sig
  case soEffects o2 of
    [fx] -> do
      res <- runRealEffect env fx
      let (_, fin) = finishVerify ops3 SlotVerify "verify"
            res (IntentBuffer 0)
      assertEqual "fresh sig verifies" CKR_OK (soCode fin)
    other -> assertFailure ("expected one verify effect, got " ++ show other)
  -- The fixed RAW vector verifies through the RAW path.
  let rArgs = InitArgs OpVerify ecdsaMech "RAW" (Just ecPubKeyP) Nothing Nothing
      (ops4, _) = initOperation smokeEnv emptySessionOps smokeSession rArgs
      (ops5, _, o3) = planVerifyOneShot ops4 smokeSession "verify" ecMsg ecSigRaw
  case soEffects o3 of
    [fx] -> do
      res <- runRealEffect env fx
      let (_, fin) = finishVerify ops5 SlotVerify "verify"
            res (IntentBuffer 0)
      assertEqual "fixed RAW vector verifies" CKR_OK (soCode fin)
    other -> assertFailure ("expected one verify effect, got " ++ show other)
  -- A bit flip inside the RAW body invalidates without breaking shape.
  let badRaw = BS.init ecSigRaw <> BS.singleton (BS.last ecSigRaw `xor` 1)
      (ops6, _) = initOperation smokeEnv emptySessionOps smokeSession rArgs
      (ops7, _, o4) = planVerifyOneShot ops6 smokeSession "verify" ecMsg badRaw
  case soEffects o4 of
    [fx] -> do
      res <- runRealEffect env fx
      let (_, fin) = finishVerify ops7 SlotVerify "verify"
            res (IntentBuffer 0)
      assertEqual "flipped RAW invalid" CKR_SIGNATURE_INVALID
        (soCode fin)
    other -> assertFailure ("expected one verify effect, got " ++ show other)

caseDualSlot :: IO ()
caseDualSlot = withBackend $ \env -> do
  let noPad = Just (CipherSpec 16 False)
      dArgs = InitArgs OpDigest sha256Mech BS.empty Nothing Nothing Nothing
      eArgs = InitArgs OpEncrypt aesCbcMech aes256Iv (Just aesKeyP) noPad Nothing
      (ops0, i0) = initDualOperation smokeEnv emptySessionOps smokeSession dArgs eArgs
  assertEqual "dual init ok" CKR_OK (ioCode i0)
  let (ops1, _, _) = planDualUpdate ops0 smokeSession aes256Pt
      (ops2, _, f1) = planDualFinal ops1 smokeSession
  case soEffects f1 of
    [fxD@(FxDigest _ _), fxC@(FxCipher DirEncrypt _ _ _ _)] -> do
      dOut <- expectBytes env fxD
      cOut <- expectBytes env fxC
      let (ops3, fin) = finishDual ops2 "digest" "cipher"
            (GotBytes dOut) (GotBytes cOut) (IntentBuffer 64) (IntentBuffer 64)
      assertEqual "dual final ok" CKR_OK (soCode fin)
      assertBool "dual freed" (not (hasDual ops3))
      case soPlan fin of
        Just plan -> case opWrites plan of
          [ TypedWrite _ _ (PayloadBytes d)
            , TypedWrite _ _ (PayloadBytes c) ] -> do
            assertEqual "dual digest matches" sha256OfAesPt d
            assertEqual "dual cipher matches SP 800-38A" aes256Ct c
          other -> assertFailure ("expected two writes, got " ++ show other)
        Nothing -> assertFailure "expected a merged plan"
    other -> assertFailure ("expected two dual effects, got " ++ show other)

caseDeniedPlansNothing :: IO ()
caseDeniedPlansNothing = do
  let dArgs = InitArgs OpDigest sha256Mech BS.empty Nothing Nothing Nothing
      (ops0, i0) = initOperation smokeEnv emptySessionOps smokeSession dArgs
  assertEqual "first init ok" CKR_OK (ioCode i0)
  let (ops1, i1) = initOperation smokeEnv ops0 smokeSession dArgs
  assertEqual "conflicting init denied" CKR_OPERATION_ACTIVE (ioCode i1)
  -- The denied init leaves no planners behind: an update on a fresh
  -- (empty) op set plans no crypto either.
  let (_, _, upd) = planDigestUpdate emptySessionOps smokeSession "data"
  assertEqual "no op, no crypto" CKR_OPERATION_NOT_INITIALIZED (soCode upd)
  assertEqual "denied plans nothing" [] (soEffects upd)
  assertEqual "original slot survives" [SlotDigest] (activeSlots ops1)

-- ---------------------------------------------------------------------------
-- Message cases: the same oracles through message lifecycles
-- ---------------------------------------------------------------------------

caseMessageAesKat :: IO ()
caseMessageAesKat = withBackend $ \env -> do
  let noPad = Just (CipherSpec 16 False)
      -- Init params are zeros: the per-message IV must drive crypto.
      eArgs = InitArgs OpEncrypt aesCbcMech (BS.replicate 16 0) (Just aesKeyP) noPad Nothing
      (ops0, i0) = initMessageOperation MsgEncrypt smokeEnv emptySessionOps smokeSession eArgs
  assertEqual "message init ok" CKR_OK (ioCode i0)
  -- One-shot encrypt hits the SP 800-38A vector; the slot survives.
  let (ops1, _, o1) = planMessageOneShot ops0 smokeSession MsgEncrypt "ct"
        (MsgOneShotCipher aes256Iv BS.empty aes256Pt)
  ops2 <- case soEffects o1 of
    [fx@(FxMessageCipher _ _ _ _ _ _)] -> do
      out <- expectBytes env fx
      let (o, fin) = finishMessage MsgEncrypt ops1 SlotEncrypt "ct"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "encrypt ok" CKR_OK (soCode fin)
      assertEqual "KAT ciphertext" (Just aes256Ct) (stagedBytes fin)
      assertEqual "slot kept for message 2" [SlotEncrypt] (activeSlots o)
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- Multipart over the same input matches; then the outer final frees.
  let (ops3, st3, _) = planMessageBegin ops2 smokeSession MsgEncrypt
        (MsgBegin aes256Iv BS.empty)
      (ops4, st4, _) = planMessageNext ops3 st3 MsgEncrypt
        (MsgNextCipher BS.empty (BS.take 8 aes256Pt) False)
      (ops5, _, nEnd) = planMessageNext ops4 st4 MsgEncrypt
        (MsgNextCipher BS.empty (BS.drop 8 aes256Pt) True)
  ops6 <- case soEffects nEnd of
    [fx] -> do
      out <- expectBytes env fx
      let (o, fin) = finishMessage MsgEncrypt ops5 SlotEncrypt "ct"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "multipart matches KAT" (Just aes256Ct) (stagedBytes fin)
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  let (ops7, final) = finalizeMessage MsgEncrypt ops6
  assertEqual "outer final ok" CKR_OK (soCode final)
  assertEqual "outer final frees" [] (activeSlots ops7)
  -- Decrypt roundtrips in a sibling message context.
  let dArgs = InitArgs OpDecrypt aesCbcMech (BS.replicate 16 0) (Just aesKeyP) noPad Nothing
      (opsD0, _) = initMessageOperation MsgDecrypt smokeEnv emptySessionOps smokeSession dArgs
      (opsD1, _, oD) = planMessageOneShot opsD0 smokeSession MsgDecrypt "pt"
        (MsgOneShotCipher aes256Iv BS.empty aes256Ct)
  opsD2 <- case soEffects oD of
    [fx] -> do
      out <- expectBytes env fx
      let (o, fin) = finishMessage MsgDecrypt opsD1 SlotDecrypt "pt"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "decrypt ok" CKR_OK (soCode fin)
      assertEqual "roundtrip" (Just aes256Pt) (stagedBytes fin)
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- Bound AAD reaches the driver, which honestly refuses it on the
  -- non-AEAD backend; the message ends, the context survives.
  let (opsD3, _, oA) = planMessageOneShot opsD2 smokeSession MsgDecrypt "pt"
        (MsgOneShotCipher aes256Iv "aad" aes256Ct)
  case soEffects oA of
    [fx@(FxMessageCipher _ _ _ _ aad _)] -> do
      assertEqual "aad bound" "aad" aad
      res <- runRealEffect env fx
      let (o, bad) = finishMessage MsgDecrypt opsD3 SlotDecrypt "pt"
            res (IntentBuffer 64)
      assertEqual "unsupported maps to mechanism-invalid" CKR_MECHANISM_INVALID (soCode bad)
      assertEqual "context survives" [SlotDecrypt] (activeSlots o)
    other -> assertFailure ("expected one effect, got " ++ show other)

caseMessageHmac :: IO ()
caseMessageHmac = withBackend $ \env -> do
  let sArgs = InitArgs OpSign hmacMech BS.empty (Just hmacKeyP) Nothing Nothing
      (ops0, _) = initMessageOperation MsgSign smokeEnv emptySessionOps smokeSession sArgs
      (ops1, st1, _) = planMessageBegin ops0 smokeSession MsgSign
        (MsgBegin BS.empty BS.empty)
      (ops2, st2, _) = planMessageNext ops1 st1 MsgSign
        (MsgNextSign BS.empty "Hi " False)
      (ops3, _, nEnd) = planMessageNext ops2 st2 MsgSign
        (MsgNextSign BS.empty "There" True)
  tag <- case soEffects nEnd of
    [fx@(FxMessageSign _ _ _ _)] -> do
      out <- expectBytes env fx
      let (o, fin) = finishMessage MsgSign ops3 SlotSign "tag"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "sign ok" CKR_OK (soCode fin)
      assertEqual "slot kept" [SlotSign] (activeSlots o)
      case stagedBytes fin of
        Just t -> pure t
        Nothing -> assertFailure "expected staged tag"
    other -> assertFailure ("expected one effect, got " ++ show other)
  assertEqual "hmac matches RFC 4231" hmacOut1 tag
  let vArgs = InitArgs OpVerify hmacMech BS.empty (Just hmacKeyP) Nothing Nothing
      (ops4, _) = initMessageOperation MsgVerify smokeEnv emptySessionOps smokeSession vArgs
      (ops5, _, o1) = planMessageOneShot ops4 smokeSession MsgVerify "vrf"
        (MsgOneShotVerify BS.empty hmacMsg1 tag)
  ops6 <- case soEffects o1 of
    [fx] -> do
      res <- runRealEffect env fx
      let (o, fin) = finishMessage MsgVerify ops5 SlotVerify "vrf"
            res (IntentBuffer 0)
      assertEqual "verify ok" CKR_OK (soCode fin)
      assertEqual "slot kept" [SlotVerify] (activeSlots o)
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  let (ops7, st7, _) = planMessageBegin ops6 smokeSession MsgVerify
        (MsgBegin BS.empty BS.empty)
      (ops8, _, nBad) = planMessageNext ops7 st7 MsgVerify
        (MsgNextVerify BS.empty hmacMsg1 (Just (BS.map (xor 1) tag)))
  case soEffects nBad of
    [fx] -> do
      res <- runRealEffect env fx
      let (o, fin) = finishMessage MsgVerify ops8 SlotVerify "vrf"
            res (IntentBuffer 0)
      assertEqual "tampered invalid" CKR_SIGNATURE_INVALID (soCode fin)
      let (o2, final) = finalizeMessage MsgVerify o
      assertEqual "outer final ok" CKR_OK (soCode final)
      assertEqual "slot freed" [] (activeSlots o2)
    other -> assertFailure ("expected one effect, got " ++ show other)