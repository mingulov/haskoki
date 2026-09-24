{- | Key management, KEM and authenticated-wrapping tests.

A KEM encapsulation length query creates no key; the delivery
call then returns ciphertext plus exactly one handle. Key/pair
generation, wrap/unwrap, derivation and authenticated wrapping
run through the shared atomic-publish mechanism; multi-key
derive with an invalid additional template publishes zero
objects. AAD/key/parameter mismatches fail closed, key
attributes land on unwrap/derive children, and the KeyPolicy
seam disposition is covered. The real backend is proven only
for implemented capabilities; key-output codec cases close the
suite.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagementSpec (spec) where

import Data.Bits (complement)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import qualified Data.Map.Strict as Map
import Data.Word (Word64, Word8)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Array (pokeArray)
import Foreign.Ptr (Ptr, nullPtr)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..), encodeValue)
import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Engine.Backend
  ( CryptoBackend (..)
  , DigestAlg (..)
  , EcSpec (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , MacSpec (..)
  , SigSpec (..)
  )
import Haskoki.Engine.Driver (KeyResolver, runEffect)
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.Engine.Synthetic (Synthetic (..))
import Haskoki.FFI.Decode (maxInputBytes)
import Haskoki.FFI.KeyOutputs
  ( KeyOutputError (..)
  , decodeKemCiphertext
  , decodeWrappedInput
  , planCiphertextWriteback
  , planHandleWriteback
  , planWrappedWriteback
  )
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState
  , addToken
  , emptyModel
  , lookupSession
  )
import Haskoki.Object (resolveHandle)
import Haskoki.Operation.Cipher (pkcs7Pad, pkcs7Unpad)
import Haskoki.Operation
  ( CipherSpec (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Operation.Derive
  ( decodeDeriveParams
  , encodeDeriveParams
  , hkdfDeriveMech
  , planDerive
  )
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoError (..), CryptoResult (..))
import Haskoki.Operation.Kem
  ( KemAlg (..)
  , kemCtLen
  , mlKemKeyPairGenMech
  , mlKemMech
  , planKemDecaps
  , planKemEncaps
  )
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork
  , aesCbcMech
  , aesKeyGenMech
  , ckkAes
  , ckkEc
  , ckkGenericSecret
  , ckkMlKem
  , ckkRsa
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , ecKeyPairGenMech
  , finishWork
  , genericSecretKeyGenMech
  , genericSecretKeygenMaxBytes
  , genericSecretKeygenMinBytes
  , keyBytesOf
  , padPkcs7
  , pendingFromAttrs
  , planAuthUnwrapKey
  , planAuthWrapKey
  , planGenerateKey
  , planGenerateKeyPair
  , planUnwrapKey
  , policyFromObject
  , planWrapKey
  , publishPending
  , rsaKeyPairGenMech
  , unpadPkcs7
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Output (OutputPlan (..), TypedWrite (..), WritePayload (..))
import Haskoki.Registry (MechanismId (..), Operation (..), curatedRegistry, mkCapabilities)
import Haskoki.Recipe.Ecdh (encodeEcdhParams)
import Haskoki.Registry.Generated
  ( ckm_ECDH1_DERIVE
  , ckm_SHA256
  , ckm_SHA256_HMAC
  , ckm_SHA256_KEY_DERIVATION
  )
import Haskoki.Registry.KeyMatrix (matrixKeyTypes)
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Key management, KEM and wrapping"
  [ testCase "Setup: ML-KEM-768 keypair generation delivers two handles"
      caseKemKeygen
  , testCase "Encaps length query creates no key" caseKemLengthQuery
  , testCase "Encaps delivers ciphertext and exactly one handle" caseKemEncaps
  , testCase "Short-buffer encaps creates no key" caseKemEncapsShort
  , testCase "AES keygen delivers one handle" caseAesKeygen
  , testCase "Generic-secret keygen mints typed material in bounds" caseGenericSecretKeygen
  , testCase "Init enforces the key-type matrix" caseInitKeyTypeMatrix
  , testCase "EC keypair delivers two handles" caseEcKeypair
  , testCase "RSA keypair is honestly unsupported" caseRsaUnsupported
  , testCase "Wrap length query then wrap/unwrap roundtrip" caseWrapRoundtrip
  , testCase "Authenticated wrap roundtrip binds the tag" caseAuthWrapRoundtrip
  , testCase "Single-key derive delivers one handle" caseDeriveSingle
  , testCase "ECDH derive refuses a non-EC base before params" caseDeriveEcdhWrongKeyType
  , testCase "ECDH derive refuses malformed params on an EC base" caseDeriveEcdhBadParams
  , testCase "SHA-KDF derive refuses a destroyed base handle" caseDeriveKdfBadHandle
  , testCase "SHA-KDF derive refuses a non-generic-secret base" caseDeriveKdfWrongKeyType
  , testCase "Shared publication is all-or-nothing" casePublishAtomic
  , testCase "Wrap padding mirrors the cipher construction" casePadMirror
  , testCase "Multi-key derive delivers N handles" caseDeriveMulti
  , testCase "Invalid additional template publishes zero objects" caseDeriveInvalidExtra
  , testCase "Derive codec round-trips and rejects malformed frames" caseDeriveCodec
  , testCase "Decaps recovers the secret as one handle" caseKemDecaps
  , testCase "KEM key/ciphertext mismatches fail closed" caseKemMismatch
  , testCase "Wrap key/parameter mismatches fail closed" caseWrapMismatch
  , testCase "Wrap/unwrap with a non-AES key is a key-type refusal" caseWrapKeyTypeGate
  , testCase "Auth-unwrap AAD/tag mismatches fail closed" caseAuthWrapMismatch
  , testCase "Init reads usage from the key object" caseInitFromObject
  , testCase "Usage attributes land on unwrap/derive children" caseAttrsLand
  , testCase "Real EC keypair generates and signs" caseRealEcKeygen
  , testCase "Real wrap matches SP 800-38A and round-trips" caseRealWrapVector
  , testCase "Real derive matches RFC 5869" caseRealHkdfVector
  , testCase "Real authenticated wrap round-trips" caseRealAuthWrap
  , testCase "Real backend mints AES, honestly lacks KEM/RSA-gen" caseRealUnsupported
  , testCase "Handle writeback plans one exact handle" caseHandleWriteback
  , testCase "Wrapped writeback plans query/short/exact" caseWrappedWriteback
  , testCase "Ciphertext writeback enforces the length" caseCiphertextWriteback
  , testCase "Wrapped/KEM inputs decode with checks" caseKeyInputDecode
  ]

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

slot0 :: SlotId
slot0 = SlotId 0

sid1 :: SessionId
sid1 = SessionId 1

-- | A model with one token and one open session.
seedModel :: IO Model
seedModel = do
  let m0 = addToken emptyModel slot0
  expectRight (publishDelta m0 (StateDelta [DeltaOpenSession sid1 slot0 False]))

getSession :: Model -> IO SessionState
getSession m = case lookupSession m sid1 of
  Nothing -> assertFailure "seed session missing" >> undefined
  Just st -> pure st

-- | Log the seed session in as a normal user (private wrapping and
-- base keys are only visible past a login).
loginUser :: Model -> IO Model
loginUser m =
  expectRight (publishDelta m (StateDelta [DeltaSetSessionLogin sid1 LoginUser]))

expectRight :: Show e => Either e a -> IO a
expectRight (Right a) = pure a
expectRight (Left e) = assertFailure ("expected Right, got: " ++ show e) >> undefined

-- | Production-shaped key resolver: material comes from the key
-- objects' stored value, never from caller fixtures.
resolverFromModel :: Model -> KeyResolver
resolverFromModel m oid = KeyBytes <$> (keyBytesOf =<< Map.lookup oid (mObjects m))

-- | Decode a hex string (whitespace-tolerant).
hex :: String -> ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

-- | Answer effects against the real OpenSSL4 backend.
withRealEnv :: (BackendEnv OpenSSL4 -> IO a) -> IO a
withRealEnv action = do
  opened <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case opened of
    EngineFail err -> assertFailure ("openssl4 open failed: " ++ show err) >> undefined
    EngineOk env -> do
      r <- action env
      closeBackend env
      pure r

answerReal :: BackendEnv OpenSSL4 -> Model -> CryptoEffect -> IO CryptoResult
answerReal env m fx = runEffect env (resolverFromModel m) fx

-- | Plant one key object with fixed material (for real-backend
-- proofs over capabilities the real backend cannot generate).
plantKey :: Model -> SessionState -> [(AttributeType, AttributeValue)] -> ByteString
  -> IO (Model, ExternalHandle)
plantKey m st tmpl mat = do
  let attrs = Map.fromList tmpl
      base = pendingFromAttrs st attrs
      po = base { poAttrs = Map.insert AttrValue (ValBytes mat) (poAttrs base) }
  case publishPending m st [po] of
    Left deny -> assertFailure ("plant must publish: " ++ show deny) >> undefined
    Right (delta, [h]) -> do
      m' <- expectRight (publishDelta m delta)
      pure (m', h)
    Right _ -> assertFailure "plant arity" >> undefined

-- | Answer effects against one seeded synthetic backend per test
-- case: sequential generations draw distinct keys from the
-- backend's counter, while every case replays the same sequence.
withSynth :: ((Model -> CryptoEffect -> IO CryptoResult) -> IO a) -> IO a
withSynth action = do
  opened <- openBackend "11" :: IO (EngineResult (BackendEnv Synthetic))
  case opened of
    EngineFail err -> assertFailure ("synthetic open failed: " ++ show err) >> undefined
    EngineOk env -> do
      r <- action (\m fx -> runEffect env (resolverFromModel m) fx)
      closeBackend env
      pure r

-- | ML-KEM-768 keypair templates.
kemPubTmpl :: [(AttributeType, AttributeValue)]
kemPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkMlKem)
  , (AttrKemAlg, ValULong 768)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool False)
  , (AttrEncapsulate, ValBool True)
  ]

kemPrivTmpl :: [(AttributeType, AttributeValue)]
kemPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkMlKem)
  , (AttrKemAlg, ValULong 768)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrDecapsulate, ValBool True)
  ]

-- | Shared-secret template for encapsulation.
secretTmpl :: [(AttributeType, AttributeValue)]
secretTmpl =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong 32)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  , (AttrEncrypt, ValBool True)
  , (AttrDecrypt, ValBool True)
  ]

handleOf :: NativeOutput -> IO ExternalHandle
handleOf (NativeOutput (RegionHandle _) bs) = case BS.length bs of
  8 -> pure (ExternalHandle (fromIntegral (BS.foldl' (\a b -> a * 256 + fromIntegral b) 0 bs :: Int)))
  _ -> assertFailure "handle output is not 8 bytes" >> undefined
handleOf _ = assertFailure "expected a handle output" >> undefined

-- | Generate an ML-KEM-768 pair through the planner + synthetic
-- backend, publishing both objects. Returns the model and the
-- (public, private) handles.
genKemPair :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> IO (Model, ExternalHandle, ExternalHandle)
genKemPair answer m st = case planGenerateKeyPair defaultRules m st mlKemKeyPairGenMech kemPubTmpl kemPrivTmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 2
    pubH <- handleOf (pcOutputs c !! 0)
    privH <- handleOf (pcOutputs c !! 1)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', pubH, privH)
  other -> assertFailure ("keypair plan is not an effect: " ++ show other) >> undefined

-- | Finish planned work and demand an Immediate commit publishing
-- exactly @n@ objects.
finishCommit :: Model -> SessionState -> PendingWork -> CryptoResult -> Int -> IO PreparedCommit
finishCommit m st pw res n = case finishWork m st pw res of
  Immediate c -> do
    let StateDelta ops = pcDelta c
        created = length [() | DeltaCreateObjectFull {} <- ops]
    assertEqual "published object count" n created
    pure c
  other -> assertFailure ("finish is not Immediate: " ++ show other) >> undefined

-- ---------------------------------------------------------------------------
-- Part 1
-- ---------------------------------------------------------------------------

caseKemKeygen :: IO ()
caseKemKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, privH) <- genKemPair answer m0 st
  assertBool "handles differ" (pubH /= privH)
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  assertEqual "pub class" (Just (ValULong ckoPublicKey)) (Map.lookup AttrClass (osAttrs pub))
  assertEqual "priv class" (Just (ValULong ckoPrivateKey)) (Map.lookup AttrClass (osAttrs priv))
  assertEqual "pub keytype" (Just (ValULong ckkMlKem)) (Map.lookup AttrKeyType (osAttrs pub))
  assertEqual "priv kem alg" (Just (ValULong 768)) (Map.lookup AttrKemAlg (osAttrs priv))
  assertEqual "pub usage" (Just (ValBool True)) (Map.lookup AttrEncapsulate (osAttrs pub))
  assertEqual "priv usage" (Just (ValBool True)) (Map.lookup AttrDecapsulate (osAttrs priv))
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just p, Just q) -> do
      assertBool "pub material nonempty" (not (BS.null p))
      assertBool "priv material nonempty" (not (BS.null q))
      assertBool "halves differ" (p /= q)
    _ -> assertFailure "keypair halves lack stored material"

caseKemLengthQuery :: IO ()
caseKemLengthQuery = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, _) <- genKemPair answer m0 st
  let before = Map.size (mObjects m1)
  case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl IntentNull of
    KeyImmediate (Immediate c) -> do
      assertEqual "query code" CKR_OK (pcCode c)
      assertEqual "query publishes nothing" (StateDelta []) (pcDelta c)
      assertEqual "query answers the ct length"
        [NativeOutput (RegionBytes "ciphertext" IntentNull)
          (encodeValue (ValULong (fromIntegral (kemCtLen KemMl768))))]
        (pcOutputs c)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      assertEqual "no key created" before (Map.size (mObjects m2))
    other -> assertFailure ("length query is not an Immediate commit: " ++ show other)

caseKemEncaps :: IO ()
caseKemEncaps = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, _) <- genKemPair answer m0 st
  let before = Map.size (mObjects m1)
      ctLen = kemCtLen KemMl768
      intent = IntentBuffer (fromIntegral ctLen)
  (ct1, h) <- case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl intent of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      let outs = pcOutputs c
      assertEqual "ciphertext plus exactly one handle" 2 (length outs)
      ct <- case outs !! 0 of
        NativeOutput (RegionBytes "ciphertext" _) bs -> pure bs
        o -> assertFailure ("first output is not the ciphertext: " ++ show o) >> undefined
      assertEqual "ciphertext length" ctLen (BS.length ct)
      hh <- handleOf (outs !! 1)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      assertEqual "exactly one object published" (before + 1) (Map.size (mObjects m2))
      Just ost <- pure (resolveHandle m2 hh)
      assertEqual "secret class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
      assertEqual "secret keytype" (Just (ValULong ckkGenericSecret)) (Map.lookup AttrKeyType (osAttrs ost))
      assertEqual "secret usage" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
      case keyBytesOf ost of
        Just ss -> assertEqual "shared secret length" 32 (BS.length ss)
        Nothing -> assertFailure "secret object lacks stored material"
      pure (ct, hh)
    other -> assertFailure ("encaps plan is not an effect: " ++ show other) >> undefined
  -- Deterministic test engine: the same key encapsulates the same bytes.
  case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl intent of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      case pcOutputs c of
        (NativeOutput (RegionBytes "ciphertext" _) ct2 : _) ->
          assertEqual "synthetic encaps is seed-deterministic" ct1 ct2
        _ -> assertFailure "no ciphertext output"
    other -> assertFailure ("encaps plan is not an effect: " ++ show other) >> undefined
  _ <- pure h
  pure ()

caseKemEncapsShort :: IO ()
caseKemEncapsShort = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, _) <- genKemPair answer m0 st
  let before = Map.size (mObjects m1)
      ctLen = kemCtLen KemMl768
  case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl (IntentBuffer 100) of
    KeyImmediate (Reject r) -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short publishes nothing" (StateDelta []) (rejDelta r)
      assertEqual "short answers the ct length"
        [NativeOutput (RegionBytes "ciphertext" (IntentBuffer 100))
          (encodeValue (ValULong (fromIntegral ctLen)))]
        (rejOutputs r)
      m2 <- expectRight (publishDelta m1 (rejDelta r))
      assertEqual "no key created" before (Map.size (mObjects m2))
    other -> assertFailure ("short encaps is not a length rejection: " ++ show other)

-- ---------------------------------------------------------------------------
-- Part 2 fixtures
-- ---------------------------------------------------------------------------

iv16 :: ByteString
iv16 = "0123456789abcdef"

-- | Generate one AES key through the planner + synthetic backend.
genAesKey :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genAesKey answer m st tmpl = case planGenerateKey defaultRules m st aesKeyGenMech tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

aesTmpl :: Int -> [(AttributeType, AttributeValue)]
aesTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkAes)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  , (AttrEncrypt, ValBool True)
  , (AttrDecrypt, ValBool True)
  ]

wrapKeyTmpl :: [(AttributeType, AttributeValue)]
wrapKeyTmpl =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkAes)
  , (AttrValueLen, ValULong 32)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrWrap, ValBool True)
  , (AttrUnwrap, ValBool True)
  ]

ecPubTmpl :: [(AttributeType, AttributeValue)]
ecPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrEcParams, ValBytes "P-256")
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  ]

ecPrivTmpl :: [(AttributeType, AttributeValue)]
ecPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrEcParams, ValBytes "P-256")
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrSign, ValBool True)
  ]

rsaPubTmpl :: [(AttributeType, AttributeValue)]
rsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrModulusBits, ValULong 2048)
  , (AttrToken, ValBool False)
  ]

rsaPrivTmpl :: [(AttributeType, AttributeValue)]
rsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrModulusBits, ValULong 2048)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  ]

-- ---------------------------------------------------------------------------
-- Part 2
-- ---------------------------------------------------------------------------

caseAesKeygen :: IO ()
caseAesKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genAesKey answer m0 st (aesTmpl 32)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
  assertEqual "key type" (Just (ValULong ckkAes)) (Map.lookup AttrKeyType (osAttrs ost))
  assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "AES-256 material" 32 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"

genericTmpl :: Int -> [(AttributeType, AttributeValue)]
genericTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSign, ValBool True)
  , (AttrVerify, ValBool True)
  , (AttrEncrypt, ValBool True)
  ]

-- | Generate one key with an explicit mechanism through the planner
-- + synthetic backend.
genKeyWith :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> MechanismId -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genKeyWith answer m st mech tmpl = case planGenerateKey defaultRules m st mech tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

caseGenericSecretKeygen :: IO ()
caseGenericSecretKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genKeyWith answer m0 st genericSecretKeyGenMech (genericTmpl 32)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key type" (Just (ValULong ckkGenericSecret)) (Map.lookup AttrKeyType (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "generic-256 material" 32 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"
  -- Bounds: the 1..255 window mints, edges refuse.
  let plan n = planGenerateKey defaultRules m1 st genericSecretKeyGenMech (genericTmpl n)
  case plan genericSecretKeygenMinBytes of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("min length must plan: " ++ show (voidFx other))
  case plan genericSecretKeygenMaxBytes of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("max length must plan: " ++ show (voidFx other))
  case plan (genericSecretKeygenMinBytes - 1) of
    KeyDenied deny -> assertEqual "zero length code" CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("zero length must refuse: " ++ show (voidFx other))
  case plan (genericSecretKeygenMaxBytes + 1) of
    KeyDenied deny -> assertEqual "over length code" CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("over length must refuse: " ++ show (voidFx other))
  -- A contradictory key type refuses.
  case planGenerateKey defaultRules m1 st genericSecretKeyGenMech
      [ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong ckkAes)
      , (AttrValueLen, ValULong 16)
      ] of
    KeyDenied deny -> assertEqual "wrong type code" CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("wrong key type must refuse: " ++ show (voidFx other))
  where
    voidFx :: KeyPlan -> String
    voidFx (KeyDenied deny) = "denied: " ++ show (kdCode deny)
    voidFx (KeyImmediate _) = "immediate"
    voidFx (KeyEffect _ _) = "effect"

hmacSha256Mech :: MechanismId
hmacSha256Mech = MechanismId ckm_SHA256_HMAC

sha256Mech :: MechanismId
sha256Mech = MechanismId ckm_SHA256

caseInitKeyTypeMatrix :: IO ()
caseInitKeyTypeMatrix = withSynth $ \answer -> do
  mSeed <- seedModel
  m0 <- loginUser mSeed
  st <- getSession m0
  -- Both keys carry sign AND encrypt usage: a usage-first check
  -- would admit every leg below, so each refusal proves the matrix
  -- fired (type before usage).
  (m1, aesH) <- genKeyWith answer m0 st aesKeyGenMech
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 16)
    , (AttrToken, ValBool False)
    , (AttrSign, ValBool True)
    , (AttrEncrypt, ValBool True)
    ]
  (m2, genH) <- genKeyWith answer m1 st genericSecretKeyGenMech (genericTmpl 32)
  let env = OpEnv
        { oeRegistry = curatedRegistry
        , oeCaps = mkCapabilities [(hmacSha256Mech, OpSign), (aesCbcMech, OpEncrypt)]
        , oeModel = m2
        }
      mkSign h = InitArgs
        { iaOp = OpSign
        , iaMech = hmacSha256Mech
        , iaParams = BS.empty
        , iaKey = Just (KeyPolicy h [OpSign] False)
        , iaCipher = Nothing
        , iaRecover = Nothing
        }
      mkEnc h = InitArgs
        { iaOp = OpEncrypt
        , iaMech = aesCbcMech
        , iaParams = iv16
        , iaKey = Just (KeyPolicy h [OpEncrypt] False)
        , iaCipher = Just (CipherSpec 16 False)
        , iaRecover = Nothing
        }
  let (_, signGen) = initOperation env emptySessionOps st (mkSign genH)
  assertEqual "HMAC sign with generic key" CKR_OK (ioCode signGen)
  let (_, signAes) = initOperation env emptySessionOps st (mkSign aesH)
  assertEqual "HMAC sign with AES key" CKR_KEY_TYPE_INCONSISTENT (ioCode signAes)
  let (_, encAes) = initOperation env emptySessionOps st (mkEnc aesH)
  assertEqual "AES-CBC encrypt with AES key" CKR_OK (ioCode encAes)
  let (_, encGen) = initOperation env emptySessionOps st (mkEnc genH)
  assertEqual "AES-CBC encrypt with generic key" CKR_KEY_TYPE_INCONSISTENT (ioCode encGen)
  -- Direct matrix pins.
  assertEqual "hmac row" (Just [ckkGenericSecret, mustKeyTypeId "CKK_SHA256_HMAC"])
    (matrixKeyTypes hmacSha256Mech OpSign)
  assertEqual "cbc row" (Just [ckkAes]) (matrixKeyTypes aesCbcMech OpEncrypt)
  assertEqual "digest unmatrices" Nothing (matrixKeyTypes sha256Mech OpDigest)
  assertEqual "off-op unmatrices" Nothing (matrixKeyTypes hmacSha256Mech OpEncrypt)
  -- Legacy objects without a key type skip the matrix (the seam).
  let legacyAttrs = Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrToken, ValBool False)
        ]
  (m3, legacyH) <- case publishPending m2 st [pendingFromAttrs st legacyAttrs] of
    Left deny -> assertFailure ("plant must publish: " ++ show deny) >> undefined
    Right (delta, [h]) -> do
      m' <- expectRight (publishDelta m2 delta)
      pure (m', h)
    Right _ -> assertFailure "plant must mint one handle" >> undefined
  let env3 = env { oeModel = m3 }
      (_, signLegacy) = initOperation env3 emptySessionOps st (mkSign legacyH)
  assertEqual "untyped legacy key skips matrix" CKR_OK (ioCode signLegacy)

caseEcKeypair :: IO ()
caseEcKeypair = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubTmpl ecPrivTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      pubH <- handleOf (pcOutputs c !! 0)
      privH <- handleOf (pcOutputs c !! 1)
      m1 <- expectRight (publishDelta m0 (pcDelta c))
      Just pub <- pure (resolveHandle m1 pubH)
      Just priv <- pure (resolveHandle m1 privH)
      assertEqual "pub usage" (Just (ValBool True)) (Map.lookup AttrVerify (osAttrs pub))
      assertEqual "priv usage" (Just (ValBool True)) (Map.lookup AttrSign (osAttrs priv))
      case (keyBytesOf pub, keyBytesOf priv) of
        (Just p, Just q) -> do
          assertEqual "pub half length" 69 (BS.length p)
          assertEqual "priv half length" 69 (BS.length q)
          assertEqual "pair magic" "HKS1" (BS.take 4 p)
        _ -> assertFailure "EC halves lack material"
    other -> assertFailure ("EC keypair plan is not an effect: " ++ show other)

caseRsaUnsupported :: IO ()
caseRsaUnsupported = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let before = Map.size (mObjects m0)
  case planGenerateKeyPair defaultRules m0 st rsaKeyPairGenMech rsaPubTmpl rsaPrivTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      case finishWork m0 st pw res of
        Reject r -> do
          assertEqual "unsupported code" CKR_MECHANISM_INVALID (rejCode r)
          assertEqual "zero objects" (StateDelta []) (rejDelta r)
          m1 <- expectRight (publishDelta m0 (rejDelta r))
          assertEqual "nothing published" before (Map.size (mObjects m1))
        other -> assertFailure ("RSA finish must reject, got: " ++ show other)
    other -> assertFailure ("RSA keypair plan is not an effect: " ++ show other)

caseWrapRoundtrip :: IO ()
caseWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  -- Length query first: padded length, no effect planned.
  case planWrapKey m2 st aesCbcMech iv16 wrapH targetH IntentNull of
    KeyImmediate (Immediate c) -> do
      assertEqual "wrap query length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 32))]
        (pcOutputs c)
      assertEqual "query publishes nothing" (StateDelta []) (pcDelta c)
    other -> assertFailure ("wrap query is not an Immediate commit: " ++ show other)
  -- Wrap for real.
  blob <- case planWrapKey m2 st aesCbcMech iv16 wrapH targetH (IntentBuffer 32) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> do
          assertEqual "wrap publishes nothing" (StateDelta []) (pcDelta c)
          case pcOutputs c of
            [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
            o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("wrap plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 32 (BS.length blob)
  assertBool "blob differs from plaintext" (blob /= targetMat)
  -- Unwrap under a fresh template: material back, attributes landed.
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        , (AttrLabel, ValBytes "unwrapped")
        , (AttrEncrypt, ValBool True)
        ]
  case planUnwrapKey defaultRules m2 st aesCbcMech iv16 wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
      assertEqual "label landed"
        (Just (ValBytes "unwrapped")) (Map.lookup AttrLabel (osAttrs ost))
      assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
    other -> assertFailure ("unwrap plan is not an effect: " ++ show other)

caseAuthWrapRoundtrip :: IO ()
caseAuthWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 24)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  let aad = "associated-data"
  blob <- case planAuthWrapKey m2 st aesCbcMech iv16 wrapH targetH aad (IntentBuffer 64) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("auth-wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("auth-wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("auth-wrap plan is not an effect: " ++ show other) >> undefined
  assertEqual "blob is padded ct plus 32-byte tag" 64 (BS.length blob)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        , (AttrDecrypt, ValBool True)
        ]
  case planAuthUnwrapKey defaultRules m2 st aesCbcMech iv16 wrapH blob aad tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "auth-unwrapped material" (Just targetMat) (keyBytesOf ost)
      assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrDecrypt (osAttrs ost))
    other -> assertFailure ("auth-unwrap plan is not an effect: " ++ show other)

caseDeriveSingle :: IO ()
caseDeriveSingle = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let baseTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 32)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        ]
  (m1, baseH) <- genAesKey answer m0 st baseTmpl
  let soloTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 32)
        , (AttrToken, ValBool False)
        , (AttrEncrypt, ValBool True)
        ]
      blob = encodeDeriveParams "derive-info" [soloTmpl]
      before = Map.size (mObjects m1)
  mats <- case planDerive defaultRules m1 st hkdfDeriveMech baseH blob of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      assertEqual "one derived object" (before + 1) (Map.size (mObjects m2))
      Just ost <- pure (resolveHandle m2 h)
      assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
      case keyBytesOf ost of
        Just mat -> do
          assertEqual "derived length" 32 (BS.length mat)
          pure (mat, m2)
        Nothing -> assertFailure "derived key lacks material" >> undefined
    other -> assertFailure ("derive plan is not an effect: " ++ show other) >> undefined
  -- Deterministic construction: the same derive replays its bytes.
  case planDerive defaultRules m1 st hkdfDeriveMech baseH blob of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m1 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "derive replays" (Just (fst mats)) (keyBytesOf ost)
    other -> assertFailure ("derive plan is not an effect: " ++ show other)

-- | ECDH key-type-before-params ordering (the Init-matrix rule for
-- derive): an RSA base refuses KEY_TYPE_INCONSISTENT whether the
-- agreement parameters are garbage or well-formed.
caseDeriveEcdhWrongKeyType :: IO ()
caseDeriveEcdhWrongKeyType = do
  m0 <- seedModel
  st <- getSession m0
  let rsaAttrs = Map.fromList
        [ (AttrClass, ValULong ckoPrivateKey)
        , (AttrKeyType, ValULong ckkRsa)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        , (AttrModulus, ValBytes "n")
        , (AttrPublicExponent, ValBytes "e")
        , (AttrPrivateExponent, ValBytes "d")
        , (AttrPrime1, ValBytes "p")
        , (AttrPrime2, ValBytes "q")
        , (AttrExponent1, ValBytes "dp")
        , (AttrExponent2, ValBytes "dq")
        , (AttrCoefficient, ValBytes "qi")
        , (AttrValue, ValBytes "rsa-material-stands-in")
        ]
      tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
      mech = MechanismId ckm_ECDH1_DERIVE
  (m1, baseH) <- case publishPending m0 st [pendingFromAttrs st rsaAttrs] of
    Left deny -> assertFailure ("plant must publish: " ++ show deny) >> undefined
    Right (delta, [h]) -> do
      m' <- expectRight (publishDelta m0 delta)
      pure (m', h)
    Right _ -> assertFailure "plant must mint one handle" >> undefined
  let garbage = encodeDeriveParams "not-ecdh-params" [tmpl]
      wellFormed = encodeDeriveParams (encodeEcdhParams 0 BS.empty "peer") [tmpl]
  case planDerive defaultRules m1 st mech baseH garbage of
    KeyDenied (KeyDeny code _) ->
      assertEqual "garbage params, RSA base" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("RSA base must not plan: " ++ show other)
  case planDerive defaultRules m1 st mech baseH wellFormed of
    KeyDenied (KeyDeny code _) ->
      assertEqual "valid params, RSA base" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("RSA base must not plan: " ++ show other)

-- | ECDH parameter shape still enforced: an EC base with malformed
-- agreement parameters refuses ARGUMENTS_BAD.
caseDeriveEcdhBadParams :: IO ()
caseDeriveEcdhBadParams = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let privTmpl = ecPrivTmpl ++ [(AttrDerive, ValBool True)]
      tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
      mech = MechanismId ckm_ECDH1_DERIVE
  (m1, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubTmpl privTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h)
    other -> assertFailure ("EC keypair must plan: " ++ show other) >> undefined
  case planDerive defaultRules m1 st mech privH (encodeDeriveParams "garbage" [tmpl]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "EC base, garbage params" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("garbage params must not plan: " ++ show other)

-- | KDF handle resolution: a destroyed base handle refuses
-- KEY_HANDLE_INVALID (the oracle's null-base leg prefers the
-- key-specific code over OBJECT_HANDLE_INVALID).
caseDeriveKdfBadHandle :: IO ()
caseDeriveKdfBadHandle = do
  m0 <- seedModel
  st <- getSession m0
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
      mech = MechanismId ckm_SHA256_KEY_DERIVATION
  case planDerive defaultRules m0 st mech (ExternalHandle 99999)
      (encodeDeriveParams BS.empty [tmpl]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "destroyed base handle" CKR_KEY_HANDLE_INVALID code
    other -> assertFailure ("destroyed handle must not plan: " ++ show other)

-- | SHA-KDF rows derive from generic-secret bases only: an AES
-- base refuses KEY_TYPE_INCONSISTENT (the oracle's
-- derive-wrong-key-type legs).
caseDeriveKdfWrongKeyType :: IO ()
caseDeriveKdfWrongKeyType = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, baseH) <- genAesKey answer m0 st (aesTmpl 32 ++ [(AttrDerive, ValBool True)])
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
      mech = MechanismId ckm_SHA256_KEY_DERIVATION
  case planDerive defaultRules m1 st mech baseH (encodeDeriveParams BS.empty [tmpl]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "AES base" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("AES base must not plan: " ++ show other)

casePublishAtomic :: IO ()
casePublishAtomic = do
  m0 <- seedModel
  st <- getSession m0
  let goodAttrs = Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValue, ValBytes "0123456789abcdef")
        ]
      badAttrs = Map.delete AttrClass goodAttrs
      good = pendingFromAttrs st goodAttrs
      bad = PendingObject badAttrs (Just sid1) slot0
  case publishPending m0 st [good, bad] of
    Left (KeyDeny code _) -> assertEqual "bad batch code" CKR_TEMPLATE_INCOMPLETE code
    Right _ -> assertFailure "mixed batch must not publish"
  case publishPending m0 st [good, good] of
    Left deny -> assertFailure ("good batch must publish: " ++ show deny)
    Right (StateDelta ops, [h1, h2]) -> do
      assertEqual "two creates plus two binds" 4 (length ops)
      assertBool "handles differ" (h1 /= h2)
      m1 <- expectRight (publishDelta m0 (StateDelta ops))
      assertEqual "two objects" 2 (Map.size (mObjects m1))
    Right _ -> assertFailure "good batch arity"

casePadMirror :: IO ()
casePadMirror = do
  let samples = ["", "a", "0123456789abcde", "0123456789abcdef", "0123456789abcdefg"]
  mapM_ checkPad samples
  mapM_ checkUnpad
    ["0123456789abcdef\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10", "short", ""]
  where
    checkPad s = assertEqual ("pad " ++ show s) (pkcs7Pad 16 s) (padPkcs7 16 s)
    checkUnpad s = assertEqual ("unpad " ++ show s) (pkcs7Unpad 16 s) (unpadPkcs7 16 s)

-- ---------------------------------------------------------------------------
-- Part 3
-- ---------------------------------------------------------------------------

childTmpl :: Int -> [(AttributeType, AttributeValue)]
childTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  ]

deriveBase :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> IO (Model, ExternalHandle)
deriveBase answer m st = genAesKey answer m st
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkAes)
  , (AttrValueLen, ValULong 32)
  , (AttrToken, ValBool False)
  , (AttrDerive, ValBool True)
  ]

runDerive :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> ExternalHandle -> ByteString -> Int
  -> IO (Model, [ExternalHandle])
runDerive answer m st baseH blob n = case planDerive defaultRules m st hkdfDeriveMech baseH blob of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res n
    hs <- mapM handleOf (pcOutputs c)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', hs)
  other -> assertFailure ("derive plan is not an effect: " ++ show other) >> undefined

caseDeriveMulti :: IO ()
caseDeriveMulti = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- deriveBase answer m0 st
  let before = Map.size (mObjects m1)
  (m2, [h1, h2, h3]) <- runDerive answer m1 st baseH
    (encodeDeriveParams "multi-child" [childTmpl 16, childTmpl 24, childTmpl 32]) 3
  assertEqual "three derived objects" (before + 3) (Map.size (mObjects m2))
  Just o1 <- pure (resolveHandle m2 h1)
  Just o2 <- pure (resolveHandle m2 h2)
  Just o3 <- pure (resolveHandle m2 h3)
  case (keyBytesOf o1, keyBytesOf o2, keyBytesOf o3) of
    (Just m16, Just m24, Just m32) -> do
      assertEqual "first length" 16 (BS.length m16)
      assertEqual "second length" 24 (BS.length m24)
      assertEqual "third length" 32 (BS.length m32)
      -- The multi answer is the concatenation the finisher splits:
      -- a lone 16-byte derive replays the first child's bytes.
      (mSolo, [hsolo]) <- runDerive answer m1 st baseH (encodeDeriveParams "multi-child" [childTmpl 16]) 1
      Just osolo <- pure (resolveHandle mSolo hsolo)
      assertEqual "split matches lone derive" (Just m16) (keyBytesOf osolo)
    _ -> assertFailure "derived children lack material"

caseDeriveInvalidExtra :: IO ()
caseDeriveInvalidExtra = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- deriveBase answer m0 st
  let before = Map.size (mObjects m1)
      badClass = [(AttrClass, ValULong ckoPublicKey), (AttrKeyType, ValULong ckkGenericSecret), (AttrValueLen, ValULong 16)]
      badLen =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 0)
        ]
  -- An invalid SECOND template denies the whole derive.
  case planDerive defaultRules m1 st hkdfDeriveMech baseH
      (encodeDeriveParams "probe" [childTmpl 32, badClass]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrong class code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("bad additional template must deny, got: " ++ show other)
  -- An invalid THIRD template denies the whole derive.
  case planDerive defaultRules m1 st hkdfDeriveMech baseH
      (encodeDeriveParams "probe" [childTmpl 16, childTmpl 16, badLen]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "zero length code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("bad additional template must deny, got: " ++ show other)
  -- A malformed frame denies too.
  case planDerive defaultRules m1 st hkdfDeriveMech baseH "truncated" of
    KeyDenied (KeyDeny code _) ->
      assertEqual "malformed frame code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("malformed frame must deny, got: " ++ show other)
  assertEqual "zero objects published" before (Map.size (mObjects m1))

caseDeriveCodec :: IO ()
caseDeriveCodec = do
  let tmpls = [childTmpl 16, childTmpl 32]
      blob = encodeDeriveParams "info" tmpls
  assertEqual "codec round-trips" (Just ("info", tmpls)) (decodeDeriveParams blob)
  assertEqual "truncated frame" Nothing (decodeDeriveParams (BS.take 7 blob))
  assertEqual "trailing bytes" Nothing (decodeDeriveParams (blob <> "junk"))
  assertEqual "empty blob" Nothing (decodeDeriveParams BS.empty)
  -- A count past the fan-out bound rejects even when well-framed.
  let info = "i" :: ByteString
      over = BS.concat
        [ BS.pack [0, 0, 0, 1], info, BS.pack [0, 17]
        , BS.concat (replicate 17 (BS.pack [0, 0, 0, 0]))
        ]
  assertEqual "fan-out bound" Nothing (decodeDeriveParams over)

-- ---------------------------------------------------------------------------
-- Part 4
-- ---------------------------------------------------------------------------

runEncaps :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> ExternalHandle -> IO (Model, ByteString, ByteString)
runEncaps answer m st pubH = do
  let ctLen = kemCtLen KemMl768
  case planKemEncaps m st mlKemMech pubH KemMl768 secretTmpl
      (IntentBuffer (fromIntegral ctLen)) of
    KeyEffect pw fx -> do
      res <- answer m fx
      c <- finishCommit m st pw res 1
      ct <- case pcOutputs c !! 0 of
        NativeOutput (RegionBytes "ciphertext" _) bs -> pure bs
        o -> assertFailure ("no ciphertext: " ++ show o) >> undefined
      h <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m (pcDelta c))
      Just ost <- pure (resolveHandle m' h)
      case keyBytesOf ost of
        Just ss -> pure (m', ct, ss)
        Nothing -> assertFailure "secret lacks material" >> undefined
    other -> assertFailure ("encaps plan is not an effect: " ++ show other) >> undefined

caseKemDecaps :: IO ()
caseKemDecaps = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, pubH, privH) <- genKemPair answer m0 st
  (m2, ct, ssEnc) <- runEncaps answer m1 st pubH
  let before = Map.size (mObjects m2)
  case planKemDecaps m2 st mlKemMech privH KemMl768 ct secretTmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      assertEqual "decaps outputs exactly one handle" 1 (length (pcOutputs c))
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      assertEqual "exactly one object" (before + 1) (Map.size (mObjects m3))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "decaps recovers the encaps secret" (Just ssEnc) (keyBytesOf ost)
      assertEqual "secret class" (Just (ValULong ckoSecretKey))
        (Map.lookup AttrClass (osAttrs ost))
    other -> assertFailure ("decaps plan is not an effect: " ++ show other)

caseKemMismatch :: IO ()
caseKemMismatch = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, pubH, privH) <- genKemPair answer m0 st
  (m2, _, privH2) <- genKemPair answer m1 st
  (m3, ct, _) <- runEncaps answer m2 st pubH
  let before = Map.size (mObjects m3)
  -- Decaps under the WRONG private key fails closed.
  case planKemDecaps m3 st mlKemMech privH2 KemMl768 ct secretTmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> do
          assertEqual "wrong-key code" CKR_ENCRYPTED_DATA_INVALID (rejCode r)
          assertEqual "zero objects" (StateDelta []) (rejDelta r)
        other -> assertFailure ("wrong-key decaps must reject, got: " ++ show other)
    other -> assertFailure ("decaps plan is not an effect: " ++ show other)
  -- A tampered ciphertext fails closed.
  let bad = BS.map complement ct
  case planKemDecaps m3 st mlKemMech privH KemMl768 bad secretTmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> assertEqual "tampered code" CKR_ENCRYPTED_DATA_INVALID (rejCode r)
        other -> assertFailure ("tampered decaps must reject, got: " ++ show other)
    other -> assertFailure ("decaps plan is not an effect: " ++ show other)
  -- A short ciphertext is a parameter refusal with no effect planned.
  case planKemDecaps m3 st mlKemMech privH KemMl768 "short" secretTmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "short ct code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("short ct must deny, got: " ++ show other)
  assertEqual "zero objects published" before (Map.size (mObjects m3))

caseWrapMismatch :: IO ()
caseWrapMismatch = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  let before = Map.size (mObjects m2)
      tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  -- NOTE: a plain-wrap wrong-key outcome is padding luck (CBC has no
  -- integrity), so fail-closed key mismatch is tested on the
  -- authenticated wrap, which binds a tag. Here the deterministic
  -- parameter and usage/shape refuses:
  -- A short IV is a parameter refusal.
  case planWrapKey m2 st aesCbcMech "short" wrapH targetH (IntentBuffer 32) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "short IV code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("short IV must deny, got: " ++ show other)
  -- A ragged blob is a parameter refusal.
  case planUnwrapKey defaultRules m2 st aesCbcMech iv16 wrapH "15-bytes-blob!!" tmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "ragged blob code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("ragged blob must deny, got: " ++ show other)
  -- A key without the wrap mark cannot wrap.
  (m3, plainH) <- genAesKey answer m2 st (aesTmpl 32)
  case planWrapKey m3 st aesCbcMech iv16 plainH targetH (IntentBuffer 32) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "no-wrap-mark code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("unmarked wrap must deny, got: " ++ show other)
  -- An unextractable target cannot wrap.
  (m4, sealedH) <- genAesKey answer m3 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 16)
    , (AttrToken, ValBool False)
    , (AttrExtractable, ValBool False)
    ]
  case planWrapKey m4 st aesCbcMech iv16 wrapH sealedH (IntentBuffer 32) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "sealed code" CKR_KEY_UNEXTRACTABLE code
    other -> assertFailure ("sealed wrap must deny, got: " ++ show other)
  -- A material-less object is not wrappable.
  let bareAttrs = Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrExtractable, ValBool True)
        ]
  (m5, bareH) <- case publishPending m4 st [pendingFromAttrs st bareAttrs] of
    Left deny -> assertFailure ("plant must publish: " ++ show deny) >> undefined
    Right (delta, [h]) -> do
      m' <- expectRight (publishDelta m4 delta)
      pure (m', h)
    Right _ -> assertFailure "plant arity" >> undefined
  case planWrapKey m5 st aesCbcMech iv16 wrapH bareH (IntentBuffer 32) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "bare code" CKR_KEY_NOT_WRAPPABLE code
    other -> assertFailure ("bare wrap must deny, got: " ++ show other)
  assertEqual "zero objects from denies" (before + 3) (Map.size (mObjects m5))

caseWrapKeyTypeGate :: IO ()
caseWrapKeyTypeGate = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  -- An EC private key carrying the wrap/unwrap marks: the marks
  -- pass, but the key type must refuse (AES-CBC wrap takes an AES
  -- secret key only — never foreign key material).
  let ecWrapTmpl = ecPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
  (m1, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubTmpl ecWrapTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h)
    other -> assertFailure ("EC keypair plan is not an effect: " ++ show other) >> undefined
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  case planWrapKey m2 st aesCbcMech iv16 privH targetH (IntentBuffer 64) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrap key-type code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("EC wrap must deny, got: " ++ show other)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
  case planUnwrapKey defaultRules m2 st aesCbcMech iv16 privH (BS.replicate 32 0) tmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "unwrap key-type code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("EC unwrap must deny, got: " ++ show other)
  -- A generic-secret key with the marks (the oracle's exact
  -- wrong-key setup: negotiated import, not keygen) refuses the
  -- same way.
  (m3, genH) <- plantKey m2 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    , (AttrUnwrap, ValBool True)
    ]
    (BS.replicate 32 0x42)
  case planWrapKey m3 st aesCbcMech iv16 genH targetH (IntentBuffer 64) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "generic wrap key-type code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("generic wrap must deny, got: " ++ show other)
  case planUnwrapKey defaultRules m3 st aesCbcMech iv16 genH (BS.replicate 32 0) tmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "generic unwrap key-type code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("generic unwrap must deny, got: " ++ show other)
  -- An RSA private half refuses too (no silent use of
  -- asymmetric material as a block-cipher key).
  (m4, rsaH) <- plantKey m3 st
    [ (AttrClass, ValULong ckoPrivateKey)
    , (AttrKeyType, ValULong ckkRsa)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    ]
    (BS.replicate 32 0x43)
  case planWrapKey m4 st aesCbcMech iv16 rsaH targetH (IntentBuffer 64) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "RSA wrap key-type code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("RSA wrap must deny, got: " ++ show other)
  -- The authenticated paths share the gate (all four
  -- 'withWrappingKey' call sites).
  let aad = "associated-data"
  case planAuthWrapKey m4 st aesCbcMech iv16 privH targetH aad (IntentBuffer 64) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "auth-wrap key-type code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("EC auth-wrap must deny, got: " ++ show other)
  case planAuthUnwrapKey defaultRules m4 st aesCbcMech iv16 privH (BS.replicate 48 0) aad tmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "auth-unwrap key-type code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("EC auth-unwrap must deny, got: " ++ show other)

caseAuthWrapMismatch :: IO ()
caseAuthWrapMismatch = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, wrapH2) <- genAesKey answer m1 st wrapKeyTmpl
  (m3, targetH) <- genAesKey answer m2 st (aesTmpl 16)
  let aad = "wrap-aad"
  blob <- case planAuthWrapKey m3 st aesCbcMech iv16 wrapH targetH aad (IntentBuffer 64) of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("one blob: " ++ show o) >> undefined
        other -> assertFailure ("wrap must commit: " ++ show other) >> undefined
    other -> assertFailure ("wrap must plan: " ++ show other) >> undefined
  let before = Map.size (mObjects m3)
      tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  -- Wrong AAD fails closed.
  case planAuthUnwrapKey defaultRules m3 st aesCbcMech iv16 wrapH blob "wrong-aad" tmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> do
          assertEqual "wrong-AAD code" CKR_ENCRYPTED_DATA_INVALID (rejCode r)
          assertEqual "zero objects" (StateDelta []) (rejDelta r)
        other -> assertFailure ("wrong-AAD unwrap must reject, got: " ++ show other)
    other -> assertFailure ("unwrap must plan: " ++ show other)
  -- A tampered blob fails closed.
  let bad = BS.map complement blob
  case planAuthUnwrapKey defaultRules m3 st aesCbcMech iv16 wrapH bad aad tmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> assertEqual "tampered code" CKR_ENCRYPTED_DATA_INVALID (rejCode r)
        other -> assertFailure ("tampered unwrap must reject, got: " ++ show other)
    other -> assertFailure ("unwrap must plan: " ++ show other)
  -- The WRONG wrapping key fails closed (the tag binds the key).
  case planAuthUnwrapKey defaultRules m3 st aesCbcMech iv16 wrapH2 blob aad tmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> do
          assertEqual "wrong-key code" CKR_ENCRYPTED_DATA_INVALID (rejCode r)
          assertEqual "zero objects" (StateDelta []) (rejDelta r)
        other -> assertFailure ("wrong-key unwrap must reject, got: " ++ show other)
    other -> assertFailure ("unwrap must plan: " ++ show other)
  assertEqual "zero objects published" before (Map.size (mObjects m3))

caseInitFromObject :: IO ()
caseInitFromObject = withSynth $ \answer -> do
  mSeed <- seedModel
  m0 <- loginUser mSeed
  stPublic <- getSession mSeed
  st <- getSession m0
  -- A key permitting encrypt but not decrypt.
  (m1, keyH) <- genAesKey answer m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 32)
    , (AttrToken, ValBool False)
    , (AttrEncrypt, ValBool True)
    , (AttrDecrypt, ValBool False)
    ]
  let env = OpEnv
        { oeRegistry = curatedRegistry
        , oeCaps = mkCapabilities [(aesCbcMech, OpEncrypt), (aesCbcMech, OpDecrypt)]
        , oeModel = m1
        }
      mkArgs op permits auth = InitArgs
        { iaOp = op
        , iaMech = aesCbcMech
        , iaParams = iv16
        , iaKey = Just (KeyPolicy keyH permits auth)
        , iaCipher = Just (CipherSpec 16 False)
        , iaRecover = Nothing
        }
  -- The object permits encrypt even when the caller claims nothing.
  let (_, encNone) = initOperation env emptySessionOps st (mkArgs OpEncrypt [] False)
  assertEqual "object permits encrypt" CKR_OK (ioCode encNone)
  -- The object forbids decrypt even when the caller claims it.
  let (_, decClaim) = initOperation env emptySessionOps st (mkArgs OpDecrypt [OpDecrypt] False)
  assertEqual "object forbids decrypt" CKR_KEY_FUNCTION_NOT_PERMITTED (ioCode decClaim)
  -- The object policy reads back directly.
  Just ost <- pure (resolveHandle m1 keyH)
  assertEqual "policy from object" (Just ([OpEncrypt], False)) (policyFromObject ost)
  -- Legacy objects without usage attributes still honor the caller.
  let legacyAttrs = Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrToken, ValBool False)
        ]
  (m2, legacyH) <- case publishPending m1 st [pendingFromAttrs st legacyAttrs] of
    Left deny -> assertFailure ("plant must publish: " ++ show deny) >> undefined
    Right (delta, [h]) -> do
      m' <- expectRight (publishDelta m1 delta)
      pure (m', h)
    Right _ -> assertFailure "plant arity" >> undefined
  let env2 = env { oeModel = m2 }
      mkLegacy op permits auth = InitArgs
        { iaOp = op
        , iaMech = aesCbcMech
        , iaParams = iv16
        , iaKey = Just (KeyPolicy legacyH permits auth)
        , iaCipher = Just (CipherSpec 16 False)
        , iaRecover = Nothing
        }
  let (_, legYes) = initOperation env2 emptySessionOps st (mkLegacy OpEncrypt [OpEncrypt] False)
  assertEqual "legacy honors caller permit" CKR_OK (ioCode legYes)
  let (_, legNo) = initOperation env2 emptySessionOps st (mkLegacy OpEncrypt [] False)
  assertEqual "legacy honors caller denial" CKR_KEY_FUNCTION_NOT_PERMITTED (ioCode legNo)
  Just lost <- pure (resolveHandle m2 legacyH)
  assertEqual "no policy without attrs" Nothing (policyFromObject lost)
  -- An always-authenticate key needs a user login however the
  -- caller marks it; the public session cannot use it.
  (m3, authH) <- genAesKey answer m2 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 32)
    , (AttrToken, ValBool False)
    , (AttrEncrypt, ValBool True)
    , (AttrAlwaysAuthenticate, ValBool True)
    ]
  let env3 = env { oeModel = m3 }
      mkAuth loginH permits auth = InitArgs
        { iaOp = OpEncrypt
        , iaMech = aesCbcMech
        , iaParams = iv16
        , iaKey = Just (KeyPolicy loginH permits auth)
        , iaCipher = Just (CipherSpec 16 False)
        , iaRecover = Nothing
        }
  let (_, authPub) = initOperation env3 emptySessionOps stPublic (mkAuth authH [OpEncrypt] False)
  assertEqual "object demands login" CKR_USER_NOT_LOGGED_IN (ioCode authPub)
  let (_, authUser) = initOperation env3 emptySessionOps st (mkAuth authH [] False)
  assertEqual "login satisfies object" CKR_OK (ioCode authUser)

caseAttrsLand :: IO ()
caseAttrsLand = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  blob <- case planWrapKey m2 st aesCbcMech iv16 wrapH targetH (IntentBuffer 32) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("one blob: " ++ show o) >> undefined
        other -> assertFailure ("wrap must commit: " ++ show other) >> undefined
    other -> assertFailure ("wrap must plan: " ++ show other) >> undefined
  -- Unwrap template flags land verbatim; unnamed flags stay absent
  -- (absent reads as false in every usage check).
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool True)
        , (AttrWrap, ValBool True)
        , (AttrUnwrap, ValBool False)
        ]
  case planUnwrapKey defaultRules m2 st aesCbcMech iv16 wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "wrap landed" (Just (ValBool True)) (Map.lookup AttrWrap (osAttrs ost))
      assertEqual "unwrap landed" (Just (ValBool False)) (Map.lookup AttrUnwrap (osAttrs ost))
      assertEqual "unnamed stays absent" Nothing (Map.lookup AttrEncrypt (osAttrs ost))
      assertEqual "token object" Nothing (osOwner ost)
    other -> assertFailure ("unwrap must plan: " ++ show other)
  -- Derive children likewise carry their template flags.
  (m4, baseH) <- deriveBase answer m2 st
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        , (AttrSign, ValBool True)
        , (AttrVerify, ValBool False)
        ]
  (m5, [dh]) <- runDerive answer m4 st baseH (encodeDeriveParams "derive-attrs" [kid]) 1
  Just dost <- pure (resolveHandle m5 dh)
  assertEqual "sign landed" (Just (ValBool True)) (Map.lookup AttrSign (osAttrs dost))
  assertEqual "verify landed" (Just (ValBool False)) (Map.lookup AttrVerify (osAttrs dost))

-- ---------------------------------------------------------------------------
-- Part 5: real-backend proofs (implemented capabilities only)
-- ---------------------------------------------------------------------------

-- SP 800-38A F.2.5 AES-256-CBC vector.
spKey, spIv, spP1, spC1 :: ByteString
spKey = hex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
spIv = hex "000102030405060708090a0b0c0d0e0f"
spP1 = hex "6bc1bee22e409f96e93d7e117393172a"
spC1 = hex "f58c4c04d6e5f1ba779eabfb5f7bfbd6"

-- RFC 5869 A.1 Test Case 1 (SHA-256): our construction runs Expand
-- over the base key bytes, so the base carries the RFC PRK and the
-- derived 42 bytes must equal the RFC OKM. Vector confirmed with an
-- independent Python implementation before embedding.
rfcPrk, rfcInfo, rfcOkm :: ByteString
rfcPrk = hex "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
rfcInfo = hex "f0f1f2f3f4f5f6f7f8f9"
rfcOkm = hex "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

caseRealEcKeygen :: IO ()
caseRealEcKeygen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubTmpl ecPrivTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("EC plan is not an effect: " ++ show other) >> undefined
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just pubB, Just privB) -> do
      assertBool "real pub DER nonempty" (not (BS.null pubB))
      assertBool "real priv DER nonempty" (not (BS.null privB))
      assertBool "halves differ" (pubB /= privB)
      -- The generated pair really signs: ECDSA roundtrip at the backend.
      sres <- sign env (SigECDSA (EcSpec "P-256" "DER") (Just D_SHA256))
        (KeyDer privB) "ec-msg"
      sig <- case sres of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real sign failed: " ++ show err) >> undefined
      vres <- verify env (SigECDSA (EcSpec "P-256" "DER") (Just D_SHA256))
        (KeyDer pubB) "ec-msg" sig
      case vres of
        EngineOk () -> pure ()
        EngineFail err -> assertFailure ("real verify failed: " ++ show err)
    _ -> assertFailure "real EC halves lack material"

caseRealWrapVector :: IO ()
caseRealWrapVector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, wrapH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    , (AttrUnwrap, ValBool True)
    ] spKey
  (m2, targetH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrExtractable, ValBool True)
    ] spP1
  blob <- case planWrapKey m2 st aesCbcMech spIv wrapH targetH (IntentBuffer 32) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("one blob: " ++ show o) >> undefined
        other -> assertFailure ("wrap must commit: " ++ show other) >> undefined
    other -> assertFailure ("wrap must plan: " ++ show other) >> undefined
  -- The padded target's first block is the F.2.5 vector plaintext,
  -- so the blob opens with the F.2.5 ciphertext block.
  assertEqual "SP 800-38A F.2.5 first block" spC1 (BS.take 16 blob)
  let tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  case planUnwrapKey defaultRules m2 st aesCbcMech spIv wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "real unwrap recovers" (Just spP1) (keyBytesOf ost)
    other -> assertFailure ("unwrap must plan: " ++ show other)

caseRealHkdfVector :: IO ()
caseRealHkdfVector = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcPrk
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 42)
        , (AttrToken, ValBool False)
        ]
  (m2, [h]) <- case planDerive defaultRules m1 st hkdfDeriveMech baseH (encodeDeriveParams rfcInfo [kid]) of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      hh <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      pure (m', [hh])
    other -> assertFailure ("derive must plan: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m2 h)
  assertEqual "RFC 5869 A.1 OKM" (Just rfcOkm) (keyBytesOf ost)
  -- The synthetic construction is a different (test-only) MAC, so it
  -- must replay itself rather than the RFC vector.
  withSynth $ \sanswer -> do
    let deriveOnce mm = case planDerive defaultRules mm st hkdfDeriveMech baseH (encodeDeriveParams rfcInfo [kid]) of
          KeyEffect pw fx -> do
            res <- sanswer mm fx
            c <- finishCommit mm st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta mm (pcDelta c))
            pure (m', hh)
          _ -> assertFailure "derive must plan" >> undefined
    (ms1, hs1) <- deriveOnce m1
    (ms2, hs2) <- deriveOnce m1
    Just os1 <- pure (resolveHandle ms1 hs1)
    Just os2 <- pure (resolveHandle ms2 hs2)
    assertEqual "synthetic derive replays" (keyBytesOf os1) (keyBytesOf os2)

caseRealAuthWrap :: IO ()
caseRealAuthWrap = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, wrapH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    , (AttrUnwrap, ValBool True)
    ] spKey
  (m2, targetH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrExtractable, ValBool True)
    ] spP1
  let aad = "real-aad"
  blob <- case planAuthWrapKey m2 st aesCbcMech spIv wrapH targetH aad (IntentBuffer 64) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("one blob: " ++ show o) >> undefined
        other -> assertFailure ("wrap must commit: " ++ show other) >> undefined
    other -> assertFailure ("wrap must plan: " ++ show other) >> undefined
  assertEqual "blob length" 64 (BS.length blob)
  -- The tag is the KAT'd HMAC over aad||ct under the derived tag key.
  mkRes <- macSign env (MacHMAC D_SHA256 Nothing) (KeyBytes spKey)
    "HASKOKI-AUTHWRAP-MAC-V1"
  macKey <- case mkRes of
    EngineOk k -> pure k
    EngineFail err -> assertFailure ("tag key failed: " ++ show err) >> undefined
  let (ct, tag) = BS.splitAt 32 blob
  tagRes <- macSign env (MacHMAC D_SHA256 Nothing) (KeyBytes macKey) (aad <> ct)
  tag2 <- case tagRes of
    EngineOk t -> pure t
    EngineFail err -> assertFailure ("tag recompute failed: " ++ show err) >> undefined
  assertEqual "tag binds aad and ct" tag tag2
  let tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  case planAuthUnwrapKey defaultRules m2 st aesCbcMech spIv wrapH blob aad tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "real auth-unwrap recovers" (Just spP1) (keyBytesOf ost)
    other -> assertFailure ("unwrap must plan: " ++ show other)

caseRealUnsupported :: IO ()
caseRealUnsupported = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
      expectUnsupported m plan = case plan of
        KeyEffect pw fx -> do
          res <- answer m fx
          case res of
            GotCryptoError (CryptoUnsupported _ _) -> pure ()
            other -> assertFailure ("must be unsupported, got: " ++ show other)
          case finishWork m st pw res of
            Reject r -> do
              assertEqual "code" CKR_MECHANISM_INVALID (rejCode r)
              assertEqual "zero objects" (StateDelta []) (rejDelta r)
            other -> assertFailure ("must reject, got: " ++ show other)
        other -> assertFailure ("must plan an effect, got: " ++ show other)
  (m1, fakeH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkMlKem)
    , (AttrKemAlg, ValULong 768)
    , (AttrToken, ValBool False)
    , (AttrEncapsulate, ValBool True)
    ] "not-a-real-kem-key"
  -- RSA keygen: planned, honestly refused by the real backend.
  expectUnsupported m1 (planGenerateKeyPair defaultRules m1 st rsaKeyPairGenMech rsaPubTmpl rsaPrivTmpl)
  -- AES keygen: real via the native DRBG surface; one
  -- object lands carrying 32 fresh bytes.
  case planGenerateKey defaultRules m1 st aesKeyGenMech (aesTmpl 32) of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      Just ost <- pure (resolveHandle m2 h)
      Just mat <- pure (keyBytesOf ost)
      assertEqual "real AES-256 material length" 32 (BS.length mat)
    other -> assertFailure ("AES keygen plan is not an effect: " ++ show other)
  -- ML-KEM keygen and encaps: no real KEM in the supported set.
  expectUnsupported m1
    (planGenerateKeyPair defaultRules m1 st mlKemKeyPairGenMech kemPubTmpl kemPrivTmpl)
  expectUnsupported m1
    (planKemEncaps m1 st mlKemMech fakeH KemMl768 secretTmpl
      (IntentBuffer (fromIntegral (kemCtLen KemMl768))))

-- ---------------------------------------------------------------------------
-- Part 6: key-output codecs
-- ---------------------------------------------------------------------------

-- | Fill a fresh buffer with the given bytes and hand its pointer on.
withInputBytes :: [Word8] -> (Ptr Word8 -> Word64 -> IO a) -> IO a
withInputBytes bytes k =
  allocaBytes (length bytes) $ \ptr -> do
    pokeArray ptr bytes
    k ptr (fromIntegral (length bytes))

caseHandleWriteback :: IO ()
caseHandleWriteback = do
  let plan = planHandleWriteback "key" (ExternalHandle 7)
  assertEqual "handle code" CKR_OK (opCode plan)
  assertEqual "one handle write"
    [TypedWrite ["key"] (RegionHandle "key") (PayloadHandle (ExternalHandle 7))]
    (opWrites plan)
  assertEqual "handle length" [(["key"], 8)] (opLengths plan)

caseWrappedWriteback :: IO ()
caseWrappedWriteback = do
  let blob = BS.pack [1 .. 32]
      query = planWrappedWriteback "wrapped" blob IntentNull
  assertEqual "query code" CKR_OK (opCode query)
  assertEqual "query writes nothing" [] (opWrites query)
  assertEqual "query length" [(["wrapped"], 32)] (opLengths query)
  let short = planWrappedWriteback "wrapped" blob (IntentBuffer 16)
  assertEqual "short code" CKR_BUFFER_TOO_SMALL (opCode short)
  assertEqual "short writes nothing" [] (opWrites short)
  assertEqual "short still reports" [(["wrapped"], 32)] (opLengths short)
  let exact = planWrappedWriteback "wrapped" blob (IntentBuffer 32)
  assertEqual "exact code" CKR_OK (opCode exact)
  assertEqual "exact writes the blob"
    [TypedWrite ["wrapped"] (RegionBytes "wrapped" (IntentBuffer 32)) (PayloadBytes blob)]
    (opWrites exact)

caseCiphertextWriteback :: IO ()
caseCiphertextWriteback = do
  let ct = BS.replicate 1088 9
      good = planCiphertextWriteback "ciphertext" 1088 ct (IntentBuffer 1088)
  assertEqual "good code" CKR_OK (opCode good)
  assertEqual "good writes once" 1 (length (opWrites good))
  let bad = planCiphertextWriteback "ciphertext" 1088 (BS.pack [1, 2, 3]) (IntentBuffer 1088)
  assertEqual "wrong length code" CKR_ARGUMENTS_BAD (opCode bad)
  assertEqual "wrong length writes nothing" [] (opWrites bad)
  let short = planCiphertextWriteback "ciphertext" 1088 ct (IntentBuffer 100)
  assertEqual "short code" CKR_BUFFER_TOO_SMALL (opCode short)
  assertEqual "short reports the length" [(["ciphertext"], 1088)] (opLengths short)

caseKeyInputDecode :: IO ()
caseKeyInputDecode = do
  withInputBytes [1 .. 40] $ \ptr len -> do
    wrapped <- decodeWrappedInput ptr len
    assertEqual "wrapped copied" (Right (BS.pack [1 .. 40])) wrapped
    kem <- decodeKemCiphertext 40 ptr len
    assertEqual "kem copied" (Right (BS.pack [1 .. 40])) kem
    mismatch <- decodeKemCiphertext 32 ptr len
    assertEqual "kem length enforced" (Left (KeyOutputLengthMismatch 32 40)) mismatch
  badNull <- decodeWrappedInput nullPtr 4
  assertEqual "null with length" (Left (KeyOutputBadPointer 4)) badNull
  tooLarge <- decodeWrappedInput nullPtr (maxInputBytes + 1)
  assertEqual "oversize rejects" (Left (KeyOutputTooLarge (maxInputBytes + 1))) tooLarge
  empty <- decodeWrappedInput nullPtr 0
  assertEqual "null empty" (Right BS.empty) empty
