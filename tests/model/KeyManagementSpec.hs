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

import Data.Bits ((.&.), complement, shiftR)
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

import Haskoki.Attribute
  ( AttributeResult (..)
  , AttributeType (..)
  , AttributeValue (..)
  , PartialReads (..)
  , encodeValue
  , getAttributes
  )
import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Der (curveTable, dsaParamsDer, dsaPrivateDer, dsaPublicDer, ecPublicDer, eddsaPrivateDer, eddsaPublicDer, mlkemPkcs8Fields, mlkemSpkiFields, parseDsaParams, rsaPrivateDer, rsaPublicDer)
import Haskoki.Engine.Backend
  ( BackendError (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EcSpec (..)
  , EngineResult (..)
  , KeyGenSpec (..)
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
  ( GenArgs (..)
  , KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , aesCbcMech
  , aesKeyGenMech
  , aesKwMech
  , aesKwPadMech
  , aesKwpMech
  , ckkAes
  , ckkDes3
  , ckkDsa
  , ckkEc
  , ckkEcEdwards
  , ckkGenericSecret
  , ckkMlDsa
  , ckkMlKem
  , ckkRsa
  , ckoDomainParameters
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , checkKeyTemplate
  , decodeGenArgs
  , des3KeyGenMech
  , dsaKeyPairGenMech
  , dsaParameterGenMech
  , ecKeyPairGenMech
  , edwardsKeyPairGenMech
  , encodeGenArgs
  , mldsaKeyPairGenMech
  , finishWork
  , genericSecretKeyGenMech
  , genericSecretKeygenMaxBytes
  , genericSecretKeygenMinBytes
  , keyBytesOf
  , keyPairCompatible
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
  , rsaOaepMech
  , rsaPkcsMech
  , stampPairComponents
  , stampParamsObject
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
import Haskoki.Recipe.RsaOaep (encodeOaepParams)
import Haskoki.Registry.Generated
  ( ckm_AES_CCM
  , ckm_DES3_MAC
  , ckm_DES3_MAC_GENERAL
  , ckm_ECDH1_DERIVE
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
  , testCase "DES3 keygen delivers one handle" caseDes3Keygen
  , testCase "AES keygen refuses PQC wrap flags" caseAesKeygenEncapsulate
  , testCase "Init enforces the allowed-mechanism list" caseInitAllowedMechanisms
  , testCase "Generic-secret keygen mints typed material in bounds" caseGenericSecretKeygen
  , testCase "Init enforces the key-type matrix" caseInitKeyTypeMatrix
  , testCase "EC keypair delivers two handles" caseEcKeypair
  , testCase "ML-DSA keypair delivers two handles" caseMldsaKeypair
  , testCase "ML-DSA set plans, agrees and refuses" caseMldsaSetPlanner
  , testCase "ML-DSA stamping lands CKA_SEED on agreement" caseMldsaStampSeed
  , testCase "EC keypair serves all covered curves" caseEcKeygenCurves
  , testCase "RSA keypair stamps components and round-trips" caseRsaKeygen
  , testCase "RSA keypair generations are distinct" caseRsaKeygenDistinct
  , testCase "RSA keygen bounds refuse out-of-window specs" caseRsaKeygenBounds
  , testCase "RSA exponent plans, agrees and refuses" caseRsaExponentPlanner
  , testCase "RSA stamping refuses mismatched halves" caseRsaStampMismatch
  , testCase "EC stamping lands CKA_EC_POINT" caseEcPointStamped
  , testCase "Wrap length query then wrap/unwrap roundtrip" caseWrapRoundtrip
  , testCase "AES-KW wrap/unwrap roundtrips with +8 expansion" caseAesKwWrapRoundtrip
  , testCase "AES-KWP wrap/unwrap roundtrips ragged (PAD alias)" caseAesKwpWrapRoundtrip
  , testCase "unwrap commits refuse type/length confusion" caseUnwrapKeyTypeLength
  , testCase "RSA wrap/unwrap roundtrips modulus-wide" caseRsaWrapRoundtrip
  , testCase "RSA wrap key/parameter/length mismatches fail closed" caseRsaWrapMismatch
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
  , testCase "Real RSA keypair generates and signs" caseRealRsaKeygen
  , testCase "DSA param sizes plan and refuse" caseDsaParamSizesPlanner
  , testCase "DSA domain templates plan and refuse" caseDsaDomainPlanner
  , testCase "DSA GenArgs codec round-trips and rejects" caseDsaGenArgsCodec
  , testCase "DSA pending/effect pairs cohere" caseDsaCompatible
  , testCase "Edwards GenArgs codec round-trips and rejects" caseEdwardsGenArgsCodec
  , testCase "Edwards pair templates plan and refuse" caseEdwardsPairPlanner
  , testCase "Edwards pending/effect pairs cohere" caseEdwardsCompatible
  , testCase "Edwards components stamp, doubles pass through" caseEdwardsStamp
  , testCase "DSA components stamp, doubles pass through" caseDsaStamp
  , testCase "Real DSA params generate with readback" caseRealDsaParamgen
  , testCase "Real DSA keypair generates and signs" caseRealDsaKeygen
  , testCase "Keygen defaults absent usage flags true" caseKeygenUsageDefaults
  , testCase "Real P-384 keypair generates and signs" caseRealEcKeygen384
  , testCase "Real P-521 keypair generates and signs" caseRealEcKeygen521
  , testCase "Real wrap matches SP 800-38A and round-trips" caseRealWrapVector
  , testCase "Real derive matches RFC 5869" caseRealHkdfVector
  , testCase "Real authenticated wrap round-trips" caseRealAuthWrap
  , testCase "Real backend mints AES and ML-KEM" caseRealAesKem
  , testCase "KEM refuses wrong key types inconsistent" caseKemWrongKeyType
  , testCase "KEM accepts AES-256 secret templates" caseKemAesTemplate
  , testCase "KEM keygen honors CKA_PARAMETER_SET" caseKemKeygenParamSet
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

-- | Generate one 3DES key through the planner + synthetic backend.
genDes3Key :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genDes3Key answer m st tmpl = case planGenerateKey defaultRules m st des3KeyGenMech tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

des3Tmpl :: Int -> [(AttributeType, AttributeValue)]
des3Tmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkDes3)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  , (AttrSign, ValBool True)
  , (AttrVerify, ValBool True)
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

-- Toy DSA domain values (shaped, not prime: planners check
-- presence and shape, never primality).
dsaP :: ByteString
dsaP = BS.pack (0x80 : replicate 127 1)

dsaQ :: ByteString
dsaQ = BS.pack (0x80 : replicate 19 2)

dsaG :: ByteString
dsaG = BS.pack (0x40 : replicate 127 3)

dsaPubTmpl :: [(AttributeType, AttributeValue)]
dsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkDsa)
  , (AttrPrime, ValBytes dsaP)
  , (AttrSubprime, ValBytes dsaQ)
  , (AttrBase, ValBytes dsaG)
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  ]

dsaPrivTmpl :: [(AttributeType, AttributeValue)]
dsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkDsa)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrSign, ValBool True)
  ]

dsaParamsTmpl :: Word64 -> [(AttributeType, AttributeValue)]
dsaParamsTmpl l =
  [ (AttrClass, ValULong ckoDomainParameters)
  , (AttrKeyType, ValULong ckkDsa)
  , (AttrPrimeBits, ValULong l)
  , (AttrToken, ValBool False)
  ]

-- Toy Edwards values (shaped: planners check presence and shape;
-- stamping parses real DER assembled from these parts).
ed19OidBytes :: ByteString
ed19OidBytes = hex "06032b6570"

ed48OidBytes :: ByteString
ed48OidBytes = hex "06032b6571"

edPoint19 :: ByteString
edPoint19 = BS.pack (0x58 : replicate 31 0x42)

edSeed19 :: ByteString
edSeed19 = BS.pack (0x11 : replicate 31 0x24)

edPubTmpl :: [(AttributeType, AttributeValue)]
edPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEcEdwards)
  , (AttrEcParams, ValBytes "Ed25519")
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  ]

edPrivTmpl :: [(AttributeType, AttributeValue)]
edPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEcEdwards)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrSign, ValBool True)
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

caseDes3Keygen :: IO ()
caseDes3Keygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genDes3Key answer m0 st (des3Tmpl 24)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
  assertEqual "key type" (Just (ValULong ckkDes3)) (Map.lookup AttrKeyType (osAttrs ost))
  assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrSign (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "DES3 material" 24 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"
  -- Two-key mints; off-geometry refuses inconsistent; a missing
  -- length mints three-key (24 bytes, the headline default).
  (m2, h2) <- genDes3Key answer m1 st (des3Tmpl 16)
  Just ost2 <- pure (resolveHandle m2 h2)
  case keyBytesOf ost2 of
    Just mat2 -> assertEqual "DES3 two-key material" 16 (BS.length mat2)
    Nothing -> assertFailure "generated key lacks material"
  case planGenerateKey defaultRules m2 st des3KeyGenMech (des3Tmpl 32) of
    KeyDenied deny -> assertEqual "bad length code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("32-byte DES3 must refuse: " ++ show other)
  (m3, h3) <- genDes3Key answer m2 st
    [a | a@(t, _) <- des3Tmpl 24, t /= AttrValueLen]
  Just ost3 <- pure (resolveHandle m3 h3)
  case keyBytesOf ost3 of
    Just mat3 -> assertEqual "DES3 default material" 24 (BS.length mat3)
    Nothing -> assertFailure "generated key lacks material"

caseAesKeygenEncapsulate :: IO ()
caseAesKeygenEncapsulate = withSynth $ \_answer -> do
  m0 <- seedModel
  st <- getSession m0
  case planGenerateKey defaultRules m0 st aesKeyGenMech (aesTmpl 16 ++
      [(AttrEncapsulate, ValBool True)]) of
    KeyDenied deny -> assertEqual "encapsulate code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure
      ("encapsulate on AES keygen must refuse: " ++ show (voidFx other))
  where
    voidFx :: KeyPlan -> String
    voidFx (KeyDenied deny) = "denied: " ++ show (kdCode deny)
    voidFx (KeyImmediate _) = "immediate"
    voidFx (KeyEffect _ _) = "effect"

caseInitAllowedMechanisms :: IO ()
caseInitAllowedMechanisms = withSynth $ \answer -> do
  mSeed <- seedModel
  m0 <- loginUser mSeed
  st <- getSession m0
  let listed = le64 (unMech hmacSha256Mech)
      other = le64 (unMech aesCbcMech)
  (m1, listedH) <- genKeyWith answer m0 st genericSecretKeyGenMech
    (genericTmpl 32 ++ [(AttrAllowedMechanisms, ValBytes listed)])
  (m2, otherH) <- genKeyWith answer m1 st genericSecretKeyGenMech
    (genericTmpl 32 ++ [(AttrAllowedMechanisms, ValBytes other)])
  (m3, freeH) <- genKeyWith answer m2 st genericSecretKeyGenMech
    (genericTmpl 32)
  let env = OpEnv
        { oeRegistry = curatedRegistry
        , oeCaps = mkCapabilities [(hmacSha256Mech, OpSign)]
        , oeModel = m3
        }
      mkSign h = InitArgs
        { iaOp = OpSign
        , iaMech = hmacSha256Mech
        , iaParams = BS.empty
        , iaKey = Just (KeyPolicy h [OpSign] False)
        , iaCipher = Nothing
        , iaRecover = Nothing
        }
  let (_, okListed) = initOperation env emptySessionOps st (mkSign listedH)
  assertEqual "listed mech inits" CKR_OK (ioCode okListed)
  let (_, denyOther) = initOperation env emptySessionOps st (mkSign otherH)
  assertEqual "unlisted mech refused" CKR_KEY_FUNCTION_NOT_PERMITTED
    (ioCode denyOther)
  let (_, okFree) = initOperation env emptySessionOps st (mkSign freeH)
  assertEqual "unlisted key inits" CKR_OK (ioCode okFree)
  where
    unMech (MechanismId w) = w
    le64 :: Word64 -> ByteString
    le64 w = BS.pack
      [ fromIntegral ((w `shiftR` s) .&. 0xFF) | s <- [0, 8 .. 56] ]

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

des3macMech :: MechanismId
des3macMech = MechanismId ckm_DES3_MAC

des3macGenMech :: MechanismId
des3macGenMech = MechanismId ckm_DES3_MAC_GENERAL

sha256Mech :: MechanismId
sha256Mech = MechanismId ckm_SHA256

aesCcmMech :: MechanismId
aesCcmMech = MechanismId ckm_AES_CCM

caseInitKeyTypeMatrix :: IO ()
caseInitKeyTypeMatrix = withSynth $ \answer -> do
  mSeed <- seedModel
  m0 <- loginUser mSeed
  st <- getSession m0
  -- All keys carry sign, verify, AND encrypt usage: a usage-first
  -- check would admit every leg below, so each refusal proves the
  -- matrix fired (type before usage).
  (m1, aesH) <- genKeyWith answer m0 st aesKeyGenMech
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 16)
    , (AttrToken, ValBool False)
    , (AttrSign, ValBool True)
    , (AttrVerify, ValBool True)
    , (AttrEncrypt, ValBool True)
    ]
  (m2, genH) <- genKeyWith answer m1 st genericSecretKeyGenMech (genericTmpl 32)
  (m3, des3H) <- genDes3Key answer m2 st (des3Tmpl 24)
  let env = OpEnv
        { oeRegistry = curatedRegistry
        , oeCaps = mkCapabilities
            [ (hmacSha256Mech, OpSign)
            , (aesCbcMech, OpEncrypt)
            , (des3macMech, OpSign)
            , (des3macMech, OpVerify)
            ]
        , oeModel = m3
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
      mkMacSign h = InitArgs
        { iaOp = OpSign
        , iaMech = des3macMech
        , iaParams = BS.empty
        , iaKey = Just (KeyPolicy h [OpSign] False)
        , iaCipher = Nothing
        , iaRecover = Nothing
        }
      mkMacVerify h = InitArgs
        { iaOp = OpVerify
        , iaMech = des3macMech
        , iaParams = BS.empty
        , iaKey = Just (KeyPolicy h [OpVerify] False)
        , iaCipher = Nothing
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
  let (_, macSignDes3) = initOperation env emptySessionOps st (mkMacSign des3H)
  assertEqual "3DES-MAC sign with DES3 key" CKR_OK (ioCode macSignDes3)
  let (_, macSignAes) = initOperation env emptySessionOps st (mkMacSign aesH)
  assertEqual "3DES-MAC sign with AES key" CKR_KEY_TYPE_INCONSISTENT (ioCode macSignAes)
  let (_, macVerifyDes3) = initOperation env emptySessionOps st (mkMacVerify des3H)
  assertEqual "3DES-MAC verify with DES3 key" CKR_OK (ioCode macVerifyDes3)
  let (_, macVerifyGen) = initOperation env emptySessionOps st (mkMacVerify genH)
  assertEqual "3DES-MAC verify with generic key" CKR_KEY_TYPE_INCONSISTENT (ioCode macVerifyGen)
  -- Direct matrix pins.
  assertEqual "hmac row" (Just [ckkGenericSecret, mustKeyTypeId "CKK_SHA256_HMAC"])
    (matrixKeyTypes hmacSha256Mech OpSign)
  assertEqual "des3mac row" (Just [ckkDes3]) (matrixKeyTypes des3macMech OpSign)
  assertEqual "des3mac row verify" (Just [ckkDes3]) (matrixKeyTypes des3macMech OpVerify)
  assertEqual "des3mac general row" (Just [ckkDes3]) (matrixKeyTypes des3macGenMech OpSign)
  assertEqual "des3mac general row verify" (Just [ckkDes3]) (matrixKeyTypes des3macGenMech OpVerify)
  assertEqual "cbc row" (Just [ckkAes]) (matrixKeyTypes aesCbcMech OpEncrypt)
  assertEqual "ccm row" (Just [ckkAes]) (matrixKeyTypes aesCcmMech OpEncrypt)
  assertEqual "ccm row decrypt" (Just [ckkAes]) (matrixKeyTypes aesCcmMech OpDecrypt)
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

-- | ML-DSA keygen templates (the set rides the public half; the
-- private half inherits it).
mldsaPubTmpl :: [(AttributeType, AttributeValue)]
mldsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkMlDsa)
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  , (AttrParameterSet, ValULong 1)
  ]

mldsaPrivTmpl :: [(AttributeType, AttributeValue)]
mldsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkMlDsa)
  , (AttrToken, ValBool False)
  , (AttrSign, ValBool True)
  ]

caseMldsaKeypair :: IO ()
caseMldsaKeypair = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  case planGenerateKeyPair defaultRules m0 st mldsaKeyPairGenMech mldsaPubTmpl mldsaPrivTmpl of
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
      assertEqual "pub set" (Just (ValULong 1)) (Map.lookup AttrParameterSet (osAttrs pub))
      assertEqual "priv set inherited" (Just (ValULong 1)) (Map.lookup AttrParameterSet (osAttrs priv))
      -- Opaque synthetic halves pass through unstamped: no seed.
      assertEqual "no seed stamped" Nothing (Map.lookup AttrSeed (osAttrs priv))
      case (keyBytesOf pub, keyBytesOf priv) of
        (Just p, Just q) -> do
          assertEqual "pair magic" "HKS1" (BS.take 4 p)
          assertBool "halves differ" (p /= q)
        _ -> assertFailure "ML-DSA halves lack material"
    other -> assertFailure ("ML-DSA keypair plan is not an effect: " ++ show other)

caseMldsaSetPlanner :: IO ()
caseMldsaSetPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf pubT privT =
        case planGenerateKeyPair defaultRules m0 st mldsaKeyPairGenMech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      withSet tmpl n = tmpl ++ [(AttrParameterSet, ValULong n)]
      noSet = filter ((/= AttrParameterSet) . fst) mldsaPubTmpl
  -- Public-side set carries into the effect args.
  assertEqual "44 plans" (Right (Just (GenMlDsa 1)))
    (argsOf mldsaPubTmpl mldsaPrivTmpl)
  assertEqual "87 plans" (Right (Just (GenMlDsa 3)))
    (argsOf (withSet noSet 3) mldsaPrivTmpl)
  -- Private-side set alone also plans.
  assertEqual "private-side set" (Right (Just (GenMlDsa 3)))
    (argsOf noSet (withSet mldsaPrivTmpl 3))
  -- Absent everywhere defaults to 65 (the KEM precedent).
  assertEqual "default 65" (Right (Just (GenMlDsa 2)))
    (argsOf noSet mldsaPrivTmpl)
  -- Disagreement and unknown sets refuse.
  assertEqual "set disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf mldsaPubTmpl (withSet mldsaPrivTmpl 3))
  assertEqual "unknown set" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withSet noSet 7) mldsaPrivTmpl)
  -- The tag-8 frame pins the CKP id big-endian.
  assertEqual "frame tag 8" (BS.pack [8, 0, 2]) (encodeGenArgs (GenMlDsa 2))
  assertEqual "frame roundtrip" (Just (GenMlDsa 3))
    (decodeGenArgs (BS.pack [8, 0, 3]))
  assertEqual "short frame refuses" Nothing
    (decodeGenArgs (BS.pack [8, 0]))

caseMldsaStampSeed :: IO ()
caseMldsaStampSeed = do
  m0 <- seedModel
  st <- getSession m0
  pub44 <- BS.readFile "tests/fixtures/mldsa44-pub.der"
  priv44 <- BS.readFile "tests/fixtures/mldsa44-priv.der"
  priv65 <- BS.readFile "tests/fixtures/mldsa65-priv.der"
  let pub = pendingFromAttrs st (Map.fromList mldsaPubTmpl)
      priv = pendingFromAttrs st (Map.fromList mldsaPrivTmpl)
  case stampPairComponents pub priv pub44 priv44 of
    Just (_, priv') -> case Map.lookup AttrSeed (poAttrs priv') of
      Just (ValBytes seed) -> assertEqual "seed width" 32 (BS.length seed)
      other -> assertFailure ("seed not stamped: " ++ show other)
    Nothing -> assertFailure "agreeing halves must stamp"
  -- Disagreeing or opaque halves pass through unstamped (no
  -- seed), never refused.
  case stampPairComponents pub priv pub44 priv65 of
    Just (_, priv') -> assertEqual "mismatch unstamped" Nothing
      (Map.lookup AttrSeed (poAttrs priv'))
    Nothing -> assertFailure "mismatched halves must pass through"
  case stampPairComponents pub priv "nope" "nope" of
    Just (_, priv') -> assertEqual "garbage unstamped" Nothing
      (Map.lookup AttrSeed (poAttrs priv'))
    Nothing -> assertFailure "opaque halves must pass through"

-- | EC templates on the given engine curve name.
ecTmpls :: ByteString
  -> ([(AttributeType, AttributeValue)], [(AttributeType, AttributeValue)])
ecTmpls curve = (retmpl ecPubTmpl, retmpl ecPrivTmpl)
  where
    retmpl = map (\(t, v) -> if t == AttrEcParams then (t, ValBytes curve) else (t, v))

caseEcKeygenCurves :: IO ()
caseEcKeygenCurves = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let gen m curve = do
        let (pubT, privT) = ecTmpls curve
        case planGenerateKeyPair defaultRules m st ecKeyPairGenMech pubT privT of
          KeyEffect pw fx -> do
            res <- answer m fx
            c <- finishCommit m st pw res 2
            pubH <- handleOf (pcOutputs c !! 0)
            privH <- handleOf (pcOutputs c !! 1)
            m' <- expectRight (publishDelta m (pcDelta c))
            Just pub <- pure (resolveHandle m' pubH)
            Just priv <- pure (resolveHandle m' privH)
            case (keyBytesOf pub, keyBytesOf priv) of
              (Just p, Just q) -> do
                assertEqual "pair magic" "HKS1" (BS.take 4 p)
                assertBool "halves differ" (p /= q)
              _ -> assertFailure "EC halves lack material"
            pure m'
          other -> assertFailure ("EC plan is not an effect: " ++ show other) >> undefined
  let go m [] = pure m
      go m (c : cs) = do
        m' <- gen m c
        go m' cs
  _ <- go m0 [n | (n, _, _) <- curveTable]
  pure ()

caseRsaKeygen :: IO ()
caseRsaKeygen = do
  opened <- openBackend "11" :: IO (EngineResult (BackendEnv Synthetic))
  case opened of
    EngineFail err -> assertFailure ("synthetic open failed: " ++ show err)
    EngineOk env -> do
      let answer m fx = runEffect env (resolverFromModel m) fx
      m0 <- seedModel
      st <- getSession m0
      (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st rsaKeyPairGenMech rsaPubTmpl rsaPrivTmpl of
        KeyEffect pw fx -> do
          res <- answer m0 fx
          c <- finishCommit m0 st pw res 2
          h1 <- handleOf (pcOutputs c !! 0)
          h2 <- handleOf (pcOutputs c !! 1)
          m' <- expectRight (publishDelta m0 (pcDelta c))
          pure (m', h1, h2)
        other -> assertFailure ("RSA plan is not an effect: " ++ show other) >> undefined
      Just pub <- pure (resolveHandle m1 pubH)
      Just priv <- pure (resolveHandle m1 privH)
      -- Components stamped: 256-byte modulus, default exponent.
      n <- case Map.lookup AttrModulus (osAttrs pub) of
        Just (ValBytes bs) -> do
          assertEqual "modulus length" 256 (BS.length bs)
          pure bs
        other -> assertFailure ("pub lacks modulus: " ++ show other) >> undefined
      assertEqual "default exponent"
        (Just (ValBytes (BS.pack [1, 0, 1])))
        (Map.lookup AttrPublicExponent (osAttrs pub))
      -- Generation params are not stored attributes.
      assertBool "modulus bits dropped"
        (Map.notMember AttrModulusBits (osAttrs pub))
      assertBool "modulus bits dropped (priv)"
        (Map.notMember AttrModulusBits (osAttrs priv))
      -- The private half carries all eight CRT parts ...
      mapM_ (assertPresent (osAttrs priv))
        [ AttrModulus, AttrPublicExponent, AttrPrivateExponent, AttrPrime1
        , AttrPrime2, AttrExponent1, AttrExponent2, AttrCoefficient
        ]
      -- ... sealed on the read path (sensitive + unextractable template).
      case getAttributes (osAttrs priv) [AttrPrivateExponent, AttrModulus] of
        PartialReads code results -> do
          assertEqual "seal code" CKR_ATTRIBUTE_SENSITIVE code
          assertEqual "private exponent sealed" (Just ResSensitive)
            (lookup AttrPrivateExponent results)
          assertEqual "modulus stays readable"
            (Just (ResOk (ValBytes n))) (lookup AttrModulus results)
      -- The generated pair really signs at the backend.
      case (keyBytesOf pub, keyBytesOf priv) of
        (Just pubB, Just privB) -> do
          sres <- sign env (SigRSA_PKCS1v15 D_SHA256) (KeyDer privB) "rsa-msg"
          sig <- case sres of
            EngineOk s -> pure s
            EngineFail err -> assertFailure ("synth sign failed: " ++ show err) >> undefined
          vres <- verify env (SigRSA_PKCS1v15 D_SHA256) (KeyDer pubB) "rsa-msg" sig
          case vres of
            EngineOk () -> pure ()
            EngineFail err -> assertFailure ("synth verify failed: " ++ show err)
        _ -> assertFailure "RSA halves lack material"
      closeBackend env
  where
    assertPresent attrs t = case Map.lookup t attrs of
      Just (ValBytes bs) | not (BS.null bs) -> pure ()
      other -> assertFailure ("missing component " ++ show t ++ ": " ++ show other)

caseRsaKeygenDistinct :: IO ()
caseRsaKeygenDistinct = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let gen m = case planGenerateKeyPair defaultRules m st rsaKeyPairGenMech rsaPubTmpl rsaPrivTmpl of
        KeyEffect pw fx -> do
          res <- answer m fx
          c <- finishCommit m st pw res 2
          h <- handleOf (pcOutputs c !! 0)
          m' <- expectRight (publishDelta m (pcDelta c))
          Just ost <- pure (resolveHandle m' h)
          case Map.lookup AttrModulus (osAttrs ost) of
            Just (ValBytes n) -> pure (m', n)
            other -> assertFailure ("modulus missing: " ++ show other) >> undefined
        other -> assertFailure ("RSA plan is not an effect: " ++ show other) >> undefined
  (m1, n1) <- gen m0
  (_, n2) <- gen m1
  assertBool "sequential pairs differ" (n1 /= n2)

caseRsaKeygenBounds :: IO ()
caseRsaKeygenBounds = do
  opened <- openBackend "11" :: IO (EngineResult (BackendEnv Synthetic))
  case opened of
    EngineFail err -> assertFailure ("synthetic open failed: " ++ show err)
    EngineOk env -> do
      ok <- generateKey env (GenRSA 2048 65537)
      case ok of
        EngineOk (KeyDer priv, Just (KeyDer pub)) -> do
          assertBool "priv DER nonempty" (not (BS.null priv))
          assertBool "pub DER nonempty" (not (BS.null pub))
          assertBool "halves differ" (priv /= pub)
        other -> assertFailure ("2048/65537 must mint: " ++ show other)
      badBits <- generateKey env (GenRSA 1024 65537)
      case badBits of
        EngineFail (BackendBadParam _ _) -> pure ()
        other -> assertFailure ("1024 bits must refuse: " ++ show other)
      evenE <- generateKey env (GenRSA 2048 4)
      case evenE of
        EngineFail (BackendBadParam _ _) -> pure ()
        other -> assertFailure ("even exponent must refuse: " ++ show other)
      closeBackend env

caseRsaExponentPlanner :: IO ()
caseRsaExponentPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf pubT privT =
        case planGenerateKeyPair defaultRules m0 st rsaKeyPairGenMech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      withExp tmpl e = tmpl ++ [(AttrPublicExponent, ValBytes e)]
  -- Absent on both sides: the 65537 default.
  assertEqual "default exponent" (Right (Just (GenRsa 2048 65537)))
    (argsOf rsaPubTmpl rsaPrivTmpl)
  -- Custom odd exponent carries into the effect args.
  assertEqual "custom exponent" (Right (Just (GenRsa 2048 257)))
    (argsOf (withExp rsaPubTmpl (BS.pack [1, 1])) rsaPrivTmpl)
  -- Private-side exponent alone also plans.
  assertEqual "private-side exponent" (Right (Just (GenRsa 2048 3)))
    (argsOf rsaPubTmpl (withExp rsaPrivTmpl (BS.pack [3])))
  -- Disagreement refuses.
  assertEqual "exponent disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withExp rsaPubTmpl (BS.pack [1, 0, 1]))
      (withExp rsaPrivTmpl (BS.pack [3])))
  -- Even exponents refuse.
  assertEqual "even exponent" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withExp rsaPubTmpl (BS.pack [4])) rsaPrivTmpl)
  -- Overlong exponents refuse.
  assertEqual "overlong exponent" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withExp rsaPubTmpl (BS.replicate 9 1)) rsaPrivTmpl)

caseRsaStampMismatch :: IO ()
caseRsaStampMismatch = do
  m0 <- seedModel
  st <- getSession m0
  let n = BS.pack [1, 2, 3]
      n2 = BS.pack [4, 5, 6]
      e = BS.pack [1, 0, 1]
      tiny = BS.pack [7]
      pubM = rsaPublicDer n e
      privM = rsaPrivateDer n e tiny tiny tiny tiny tiny tiny
      privM2 = rsaPrivateDer n2 e tiny tiny tiny tiny tiny tiny
      pub = pendingFromAttrs st (Map.fromList rsaPubTmpl)
      priv = pendingFromAttrs st (Map.fromList rsaPrivTmpl)
  case stampPairComponents pub priv pubM privM of
    Just (pub', _) -> assertEqual "modulus stamped"
      (Just (ValBytes n)) (Map.lookup AttrModulus (poAttrs pub'))
    Nothing -> assertFailure "matching halves must stamp"
  assertEqual "mismatched halves refuse" Nothing
    (stampPairComponents pub priv pubM privM2)
  assertEqual "garbage refuses" Nothing
    (stampPairComponents pub priv "nope" "nope")
  -- Non-RSA, non-EC pairs pass through untouched.
  let ecPub = pendingFromAttrs st (Map.fromList ecPubTmpl)
      ecPriv = pendingFromAttrs st (Map.fromList ecPrivTmpl)
  assertEqual "EC opaque passthrough" (Just (ecPub, ecPriv))
    (stampPairComponents ecPub ecPriv "pub" "priv")

caseDsaParamSizesPlanner :: IO ()
caseDsaParamSizesPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf tmpl =
        case planGenerateKey defaultRules m0 st dsaParameterGenMech tmpl of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      withN tmpl n = tmpl ++ [(AttrSubprimeBits, ValULong n)]
  -- Served sizes plan with per-L subprime defaults.
  assertEqual "1024 defaults to 160" (Right (Just (GenDsaParams 1024 160)))
    (argsOf (dsaParamsTmpl 1024))
  assertEqual "2048 defaults to 256" (Right (Just (GenDsaParams 2048 256)))
    (argsOf (dsaParamsTmpl 2048))
  assertEqual "3072 defaults to 256" (Right (Just (GenDsaParams 3072 256)))
    (argsOf (dsaParamsTmpl 3072))
  -- Explicit served pairs plan.
  assertEqual "explicit (2048, 224)" (Right (Just (GenDsaParams 2048 224)))
    (argsOf (withN (dsaParamsTmpl 2048) 224))
  assertEqual "explicit (2048, 256)" (Right (Just (GenDsaParams 2048 256)))
    (argsOf (withN (dsaParamsTmpl 2048) 256))
  -- Missing prime bits are incomplete (oracle-pinned).
  assertEqual "missing prime bits" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)])
  -- Unserved sizes and pairs are inconsistent.
  assertEqual "unserved L" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (dsaParamsTmpl 512))
  assertEqual "unserved pair" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withN (dsaParamsTmpl 2048) 160))
  -- Malformed sizes are inconsistent.
  assertEqual "malformed prime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf ([(AttrPrimeBits, ValBool True), (AttrToken, ValBool False)]))

caseDsaDomainPlanner :: IO ()
caseDsaDomainPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf pubT privT =
        case planGenerateKeyPair defaultRules m0 st dsaKeyPairGenMech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      dropT t = filter ((/= t) . fst)
      withT tmpl t v = tmpl ++ [(t, v)]
  -- Happy path frames DER DSS-Parms.
  case argsOf dsaPubTmpl dsaPrivTmpl of
    Right (Just (GenDsaKeypair der)) ->
      assertEqual "DER round-trips" (Just (dsaP, dsaQ, dsaG)) (parseDsaParams der)
    other -> assertFailure ("DSA pair must plan: " ++ show other)
  -- Served size hints alongside the domain are accepted.
  case argsOf (withT dsaPubTmpl AttrPrimeBits (ValULong 2048)) dsaPrivTmpl of
    Right (Just (GenDsaKeypair _)) -> pure ()
    other -> assertFailure ("served size hint must plan: " ++ show other)
  -- Missing parameters are incomplete.
  assertEqual "missing base" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf (dropT AttrBase dsaPubTmpl) dsaPrivTmpl)
  assertEqual "missing all" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)] dsaPrivTmpl)
  -- The field-size probe shape (PRIME_BITS=(1<<32)+1024, no p/q/g)
  -- refuses inconsistent, never incomplete.
  assertEqual "oversized prime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf [(AttrPrimeBits, ValULong 4294968320), (AttrToken, ValBool False)]
      [(AttrToken, ValBool False)])
  assertEqual "unserved prime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT dsaPubTmpl AttrPrimeBits (ValULong 512)) dsaPrivTmpl)
  assertEqual "unserved subprime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT dsaPubTmpl AttrSubprimeBits (ValULong 128)) dsaPrivTmpl)
  -- Disagreement, empty, oversized and malformed parts refuse.
  assertEqual "domain disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dsaPubTmpl (withT dsaPrivTmpl AttrPrime (ValBytes "other")))
  assertEqual "empty prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrPrime dsaPubTmpl) AttrPrime (ValBytes BS.empty)) dsaPrivTmpl)
  assertEqual "oversized prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrPrime dsaPubTmpl) AttrPrime (ValBytes (BS.replicate 513 1))) dsaPrivTmpl)
  assertEqual "malformed prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrPrime dsaPubTmpl) AttrPrime (ValULong 7)) dsaPrivTmpl)
  -- Private-side agreement plans.
  case argsOf dsaPubTmpl (dsaPrivTmpl ++
      [(AttrPrime, ValBytes dsaP), (AttrSubprime, ValBytes dsaQ), (AttrBase, ValBytes dsaG)]) of
    Right (Just (GenDsaKeypair _)) -> pure ()
    other -> assertFailure ("agreeing priv domain must plan: " ++ show other)

caseDsaGenArgsCodec :: IO ()
caseDsaGenArgsCodec = do
  let rt args = assertEqual ("round-trip " ++ show args) (Just args)
        (decodeGenArgs (encodeGenArgs args))
  rt (GenDsaParams 1024 160)
  rt (GenDsaParams 2048 224)
  rt (GenDsaParams 2048 256)
  rt (GenDsaParams 3072 256)
  rt (GenDsaKeypair (dsaParamsDer dsaP dsaQ dsaG))
  -- Tag bytes are pinned (5 sizes, 6 domain DER).
  assertEqual "params tag" (Just 5) (fst <$> BS.uncons (encodeGenArgs (GenDsaParams 2048 256)))
  assertEqual "keypair tag" (Just 6)
    (fst <$> BS.uncons (encodeGenArgs (GenDsaKeypair "d")))
  -- Short frames, trailing bytes, empty DER and unknown tags fail.
  assertEqual "short params" Nothing (decodeGenArgs (BS.pack [5, 8]))
  assertEqual "params trailing" Nothing
    (decodeGenArgs (encodeGenArgs (GenDsaParams 2048 256) <> "x"))
  assertEqual "short keypair" Nothing (decodeGenArgs (BS.pack [6, 0, 0]))
  assertEqual "keypair trailing" Nothing
    (decodeGenArgs (encodeGenArgs (GenDsaKeypair "der") <> "x"))
  assertEqual "empty keypair DER" Nothing
    (decodeGenArgs (BS.pack [6, 0, 0, 0, 0]))
  assertEqual "unknown tag" Nothing (decodeGenArgs (BS.pack [8, 1, 2, 3]))

caseDsaCompatible :: IO ()
caseDsaCompatible = do
  m0 <- seedModel
  st <- getSession m0
  let pub = pendingFromAttrs st (Map.fromList dsaPubTmpl)
      priv = pendingFromAttrs st (Map.fromList dsaPrivTmpl)
      params = pendingFromAttrs st (Map.fromList (dsaParamsTmpl 2048))
      fx args = FxGenerateKey dsaKeyPairGenMech BS.empty (encodeGenArgs args)
      fxP args = FxGenerateKey dsaParameterGenMech BS.empty (encodeGenArgs args)
      der = dsaParamsDer dsaP dsaQ dsaG
  assertBool "pair/keypair cohere"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenDsaKeypair der)))
  assertBool "single/params cohere"
    (keyPairCompatible (PwGenerateKey params) (fxP (GenDsaParams 2048 256)))
  assertBool "pair/params incoherent"
    (not (keyPairCompatible (PwGeneratePair pub priv) (fxP (GenDsaParams 2048 256))))
  assertBool "single/keypair incoherent"
    (not (keyPairCompatible (PwGenerateKey params) (fx (GenDsaKeypair der))))
  -- Coherence is shape-level: any pair-shaped args cohere with a pair.
  assertBool "pair/RSA coherent"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenRsa 2048 65537)))
  assertBool "pair/AES incoherent"
    (not (keyPairCompatible (PwGeneratePair pub priv) (fx (GenAes 16))))

caseDsaStamp :: IO ()
caseDsaStamp = do
  m0 <- seedModel
  st <- getSession m0
  let y = BS.pack (0x60 : replicate 127 4)
      x = BS.pack (0x07 : replicate 19 5)
      pubM = dsaPublicDer dsaP dsaQ dsaG y
      privM = dsaPrivateDer dsaP dsaQ dsaG x
      privM2 = dsaPrivateDer dsaQ dsaQ dsaG x
      pub = pendingFromAttrs st (Map.fromList dsaPubTmpl)
      priv = pendingFromAttrs st (Map.fromList dsaPrivTmpl)
  case stampPairComponents pub priv pubM privM of
    Just (pub', priv') -> do
      assertEqual "prime stamped"
        (Just (ValBytes dsaP)) (Map.lookup AttrPrime (poAttrs pub'))
      assertEqual "subprime stamped"
        (Just (ValBytes dsaQ)) (Map.lookup AttrSubprime (poAttrs pub'))
      assertEqual "base stamped"
        (Just (ValBytes dsaG)) (Map.lookup AttrBase (poAttrs pub'))
      assertEqual "priv inherits prime"
        (Just (ValBytes dsaP)) (Map.lookup AttrPrime (poAttrs priv'))
      assertEqual "priv inherits base"
        (Just (ValBytes dsaG)) (Map.lookup AttrBase (poAttrs priv'))
    Nothing -> assertFailure "matching DSA halves must stamp"
  -- Disagreeing and opaque halves pass through unstamped (EC mirror).
  assertEqual "mismatched halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv pubM privM2)
  assertEqual "opaque halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv "HKS1pub" "HKS1priv")
  -- Params objects stamp p/q/g plus true bit widths.
  let params = pendingFromAttrs st (Map.fromList (dsaParamsTmpl 1024))
      mat = dsaParamsDer dsaP dsaQ dsaG
  case stampParamsObject params mat of
    Just po' -> do
      assertEqual "params prime" (Just (ValBytes dsaP))
        (Map.lookup AttrPrime (poAttrs po'))
      assertEqual "params subprime" (Just (ValBytes dsaQ))
        (Map.lookup AttrSubprime (poAttrs po'))
      assertEqual "params base" (Just (ValBytes dsaG))
        (Map.lookup AttrBase (poAttrs po'))
      assertEqual "prime bits" (Just (ValULong 1024))
        (Map.lookup AttrPrimeBits (poAttrs po'))
      assertEqual "subprime bits" (Just (ValULong 160))
        (Map.lookup AttrSubprimeBits (poAttrs po'))
    Nothing -> assertFailure "DER params must stamp"
  assertEqual "opaque params pass through" (Just params)
    (stampParamsObject params "HKS1params")
  -- Non-params classes pass through untouched.
  let secret = pendingFromAttrs st (Map.fromList
        [(AttrClass, ValULong ckoSecretKey), (AttrToken, ValBool False)])
  assertEqual "secret untouched" (Just secret)
    (stampParamsObject secret mat)

caseEdwardsGenArgsCodec :: IO ()
caseEdwardsGenArgsCodec = do
  let rt args = assertEqual ("round-trip " ++ show args) (Just args)
        (decodeGenArgs (encodeGenArgs args))
  rt (GenEdwardsKeypair "Ed25519")
  rt (GenEdwardsKeypair "Ed448")
  -- Tag byte is pinned (7 Edwards keypair curve name).
  assertEqual "keypair tag" (Just 7)
    (fst <$> BS.uncons (encodeGenArgs (GenEdwardsKeypair "Ed25519")))
  -- Short frames and empty names fail.
  assertEqual "short keypair" Nothing (decodeGenArgs (BS.singleton 7))
  assertEqual "unknown tag" Nothing (decodeGenArgs (BS.pack [8, 1, 2, 3]))

caseEdwardsPairPlanner :: IO ()
caseEdwardsPairPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf pubT privT =
        case planGenerateKeyPair defaultRules m0 st edwardsKeyPairGenMech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      dropT t = filter ((/= t) . fst)
      withT tmpl t v = tmpl ++ [(t, v)]
      setParams tmpl curve =
        withT (dropT AttrEcParams tmpl) AttrEcParams (ValBytes curve)
  -- Happy path frames the curve name (both curves).
  case argsOf edPubTmpl edPrivTmpl of
    Right (Just (GenEdwardsKeypair "Ed25519")) -> pure ()
    other -> assertFailure ("Ed25519 pair must plan: " ++ show other)
  case argsOf (setParams edPubTmpl "Ed448") edPrivTmpl of
    Right (Just (GenEdwardsKeypair "Ed448")) -> pure ()
    other -> assertFailure ("Ed448 pair must plan: " ++ show other)
  -- Missing curve is incomplete.
  assertEqual "missing params" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf (dropT AttrEcParams edPubTmpl) edPrivTmpl)
  assertEqual "missing all" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)] edPrivTmpl)
  -- Foreign curves refuse mechanism-invalid (the EC precedent),
  -- never incomplete: the template names a curve the mechanism
  -- cannot serve.
  assertEqual "weierstrass refused" (Left CKR_MECHANISM_INVALID)
    (argsOf (setParams edPubTmpl "P-256") edPrivTmpl)
  assertEqual "garbage refused" (Left CKR_MECHANISM_INVALID)
    (argsOf (setParams edPubTmpl "nope") edPrivTmpl)
  -- Disagreement and malformed parts refuse inconsistent.
  assertEqual "curve disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf edPubTmpl (withT edPrivTmpl AttrEcParams (ValBytes "Ed448")))
  assertEqual "malformed params" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrEcParams edPubTmpl) AttrEcParams (ValULong 7)) edPrivTmpl)
  assertEqual "malformed priv params" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf edPubTmpl (withT edPrivTmpl AttrEcParams (ValULong 7)))
  -- Private-side agreement plans; key-type contradiction refuses.
  case argsOf edPubTmpl (withT edPrivTmpl AttrEcParams (ValBytes "Ed25519")) of
    Right (Just (GenEdwardsKeypair "Ed25519")) -> pure ()
    other -> assertFailure ("agreeing priv curve must plan: " ++ show other)
  assertEqual "key-type contradiction" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrKeyType edPubTmpl) AttrKeyType (ValULong ckkEc)) edPrivTmpl)

caseEdwardsCompatible :: IO ()
caseEdwardsCompatible = do
  m0 <- seedModel
  st <- getSession m0
  let pub = pendingFromAttrs st (Map.fromList edPubTmpl)
      priv = pendingFromAttrs st (Map.fromList edPrivTmpl)
      fx args = FxGenerateKey edwardsKeyPairGenMech BS.empty (encodeGenArgs args)
  assertBool "pair/edwards cohere"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenEdwardsKeypair "Ed25519")))
  assertBool "single/edwards incoherent"
    (not (keyPairCompatible (PwGenerateKey pub) (fx (GenEdwardsKeypair "Ed25519"))))
  -- Coherence is shape-level: any pair-shaped args cohere with a pair.
  assertBool "pair/RSA coherent"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenRsa 2048 65537)))
  assertBool "pair/AES incoherent"
    (not (keyPairCompatible (PwGeneratePair pub priv) (fx (GenAes 16))))

caseEdwardsStamp :: IO ()
caseEdwardsStamp = do
  m0 <- seedModel
  st <- getSession m0
  let pubM = eddsaPublicDer ed19OidBytes edPoint19
      privM = eddsaPrivateDer ed19OidBytes edSeed19
      privM48 = eddsaPrivateDer ed48OidBytes (BS.replicate 57 9)
      pub = pendingFromAttrs st (Map.fromList edPubTmpl)
      priv = pendingFromAttrs st (Map.fromList edPrivTmpl)
  case stampPairComponents pub priv pubM privM of
    Just (pub', priv') -> do
      assertEqual "point stamped raw"
        (Just (ValBytes edPoint19)) (Map.lookup AttrEcPoint (poAttrs pub'))
      assertEqual "pub params kept"
        (Just (ValBytes "Ed25519")) (Map.lookup AttrEcParams (poAttrs pub'))
      assertEqual "priv inherits params"
        (Just (ValBytes "Ed25519")) (Map.lookup AttrEcParams (poAttrs priv'))
    Nothing -> assertFailure "matching Edwards halves must stamp"
  -- Disagreeing and opaque halves pass through unstamped (EC mirror).
  assertEqual "mismatched halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv pubM privM48)
  assertEqual "opaque halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv "HKS1pub" "HKS1priv")

caseKeygenUsageDefaults :: IO ()
caseKeygenUsageDefaults = do
  -- Minimal templates (the oracle's DSA leg shape: p/q/g only, empty
  -- private side) mint keys whose absent usage flags read TRUE,
  -- scoped by class: public keys default the public operations,
  -- private keys the full set, domain parameters none.
  let minimal =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrPrime, ValBytes dsaP)
        , (AttrSubprime, ValBytes dsaQ)
        , (AttrBase, ValBytes dsaG)
        ]
  case checkKeyTemplate ckoPublicKey ckkDsa minimal of
    Right attrs -> do
      mapM_
        (\t -> assertEqual ("pub default " ++ show t) (Just (ValBool True))
          (Map.lookup t attrs))
        [AttrEncrypt, AttrVerify, AttrWrap, AttrEncapsulate]
      mapM_
        (\t -> assertEqual ("pub skips " ++ show t) Nothing
          (Map.lookup t attrs))
        [AttrDecrypt, AttrSign, AttrUnwrap, AttrDerive, AttrDecapsulate]
    Left deny -> assertFailure ("minimal template must check: " ++ show deny)
  case checkKeyTemplate ckoPrivateKey ckkDsa [(AttrClass, ValULong ckoPrivateKey)] of
    Right attrs -> mapM_
      (\t -> assertEqual ("priv default " ++ show t) (Just (ValBool True))
        (Map.lookup t attrs))
      [ AttrEncrypt, AttrDecrypt, AttrSign, AttrVerify
      , AttrWrap, AttrUnwrap, AttrDerive
      , AttrEncapsulate, AttrDecapsulate
      ]
    Left deny -> assertFailure ("empty priv template must check: " ++ show deny)
  case checkKeyTemplate ckoDomainParameters ckkDsa
      [(AttrClass, ValULong ckoDomainParameters), (AttrPrimeBits, ValULong 1024)] of
    Right attrs -> mapM_
      (\t -> assertEqual ("params skip " ++ show t) Nothing
        (Map.lookup t attrs))
      [AttrEncrypt, AttrSign, AttrVerify, AttrDerive]
    Left deny -> assertFailure ("params template must check: " ++ show deny)
  -- Explicit values win, including FALSE (refusal tests unaffected).
  case checkKeyTemplate ckoPrivateKey ckkDsa
      [(AttrSign, ValBool False), (AttrToken, ValBool False)] of
    Right attrs -> do
      assertEqual "explicit false kept" (Just (ValBool False))
        (Map.lookup AttrSign attrs)
      assertEqual "sibling defaulted" (Just (ValBool True))
        (Map.lookup AttrVerify attrs)
    Left deny -> assertFailure ("explicit template must check: " ++ show deny)
  -- A minimal pair plans and carries usable permits end to end.
  m0 <- seedModel
  st <- getSession m0
  case planGenerateKeyPair defaultRules m0 st dsaKeyPairGenMech minimal [] of
    KeyEffect (PwGeneratePair pub priv) _ -> do
      assertEqual "pub verify default" (Just (ValBool True))
        (Map.lookup AttrVerify (poAttrs pub))
      assertEqual "priv sign default" (Just (ValBool True))
        (Map.lookup AttrSign (poAttrs priv))
    other -> assertFailure ("minimal pair must plan: " ++ show other)
  -- Rule-forbidden flags stay absent (AES secrets forbid the
  -- encapsulate pair; a defaulted forbidden flag would poison
  -- detached rejoin, which replays stored templates).
  case checkKeyTemplate ckoSecretKey ckkAes [(AttrValueLen, ValULong 16)] of
    Right attrs -> do
      assertEqual "aes encrypt default" (Just (ValBool True))
        (Map.lookup AttrEncrypt attrs)
      assertEqual "encapsulate stays absent" Nothing
        (Map.lookup AttrEncapsulate attrs)
      assertEqual "decapsulate stays absent" Nothing
        (Map.lookup AttrDecapsulate attrs)
    Left deny -> assertFailure ("minimal AES template must check: " ++ show deny)

caseEcPointStamped :: IO ()
caseEcPointStamped = do
  m0 <- seedModel
  st <- getSession m0
  let p256oid = hex "06082a8648ce3d030107"
      point = BS.pack (0x04 : [1 .. 64])
      spki = ecPublicDer p256oid point
      ecPub = pendingFromAttrs st (Map.fromList ecPubTmpl)
      ecPriv = pendingFromAttrs st (Map.fromList ecPrivTmpl)
  -- A parseable EC SPKI stamps CKA_EC_POINT (DER OCTET STRING
  -- of the uncompressed point) on the public half; the private
  -- half is untouched.
  case stampPairComponents ecPub ecPriv spki "opaque-priv" of
    Just (pub', priv') -> do
      -- CKA_EC_POINT is the DER OCTET STRING of the point
      -- (0x04 0x41 header over the 65 uncompressed bytes).
      assertEqual "EC_POINT stamped"
        (Just (ValBytes ("\x04\x41" <> point))) (Map.lookup AttrEcPoint (poAttrs pub'))
      assertEqual "priv untouched" (poAttrs ecPriv) (poAttrs priv')
    Nothing -> assertFailure "EC SPKI halves must stamp"
  -- Opaque halves (synthetic HKS1 frames) pass through: no
  -- EC_POINT, no rejection.
  assertEqual "opaque passthrough" (Just (ecPub, ecPriv))
    (stampPairComponents ecPub ecPriv "pub" "priv")

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

-- | Extractable generic-secret template with caller-chosen length
-- (ragged wrap targets the AES keygen bounds cannot mint).
secretTmplN :: Int -> [(AttributeType, AttributeValue)]
secretTmplN n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  ]

caseAesKwWrapRoundtrip :: IO ()
caseAesKwWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  -- Length query first: 16 + 8 expansion, no effect planned.
  case planWrapKey m2 st aesKwMech BS.empty wrapH targetH IntentNull of
    KeyImmediate (Immediate c) -> do
      assertEqual "kw query length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 24))]
        (pcOutputs c)
      assertEqual "query publishes nothing" (StateDelta []) (pcDelta c)
    other -> assertFailure ("kw query is not an Immediate commit: " ++ show other)
  -- Short buffer refuses with the predicted length.
  case planWrapKey m2 st aesKwMech BS.empty wrapH targetH (IntentBuffer 23) of
    KeyImmediate (Reject r) -> do
      assertEqual "short buffer code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short buffer length"
        [NativeOutput (RegionBytes "wrapped" (IntentBuffer 23)) (encodeValue (ValULong 24))]
        (rejOutputs r)
    other -> assertFailure ("kw short buffer is not a Reject: " ++ show other)
  -- Non-empty parameters refuse (KW takes empty params like ECB).
  case planWrapKey m2 st aesKwMech iv16 wrapH targetH IntentNull of
    KeyDenied d -> assertEqual "params code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("kw params accepted, got: " ++ show other)
  -- Wrap for real.
  blob <- case planWrapKey m2 st aesKwMech BS.empty wrapH targetH (IntentBuffer 24) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> do
          assertEqual "wrap publishes nothing" (StateDelta []) (pcDelta c)
          case pcOutputs c of
            [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
            o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("kw plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 24 (BS.length blob)
  assertBool "blob differs from plaintext" (blob /= targetMat)
  -- Unwrap under a fresh template: material back.
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        , (AttrLabel, ValBytes "unwrapped-kw")
        ]
  case planUnwrapKey defaultRules m2 st aesKwMech BS.empty wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
    other -> assertFailure ("kw unwrap plan is not an effect: " ++ show other)
  -- An 8-byte target is below the KW floor (generic secret mints
  -- what AES keygen bounds forbid).
  (m4, shortH) <- genKeyWith answer m2 st genericSecretKeyGenMech (secretTmplN 8)
  case planWrapKey m4 st aesKwMech BS.empty wrapH shortH IntentNull of
    KeyDenied d -> assertEqual "floor code" CKR_DATA_LEN_RANGE (kdCode d)
    other -> assertFailure ("short target accepted, got: " ++ show other)
  -- A 16-byte blob cannot be a KW wrap (minimum 24).
  case planUnwrapKey defaultRules m2 st aesKwMech BS.empty wrapH (BS.replicate 16 0) tmpl of
    KeyDenied d -> assertEqual "blob code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("short blob accepted, got: " ++ show other)

caseAesKwpWrapRoundtrip :: IO ()
caseAesKwpWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genKeyWith answer m1 st genericSecretKeyGenMech (secretTmplN 20)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  assertEqual "target length" 20 (BS.length targetMat)
  -- Length query: ceil8(20) + 8 = 32, no effect planned.
  case planWrapKey m2 st aesKwpMech BS.empty wrapH targetH IntentNull of
    KeyImmediate (Immediate c) ->
      assertEqual "kwp query length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 32))]
        (pcOutputs c)
    other -> assertFailure ("kwp query is not an Immediate commit: " ++ show other)
  -- Wrap under the PAD alias, unwrap under KWP: the equation holds
  -- end to end (same RFC 5649 construction).
  blob <- case planWrapKey m2 st aesKwPadMech BS.empty wrapH targetH (IntentBuffer 32) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("pad plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 32 (BS.length blob)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        ]
  case planUnwrapKey defaultRules m2 st aesKwpMech BS.empty wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
    other -> assertFailure ("kwp unwrap plan is not an effect: " ++ show other)
  -- A 10-byte blob is not KWP framing (multiple of 8, >= 16).
  case planUnwrapKey defaultRules m2 st aesKwpMech BS.empty wrapH (BS.replicate 10 0) tmpl of
    KeyDenied d -> assertEqual "blob code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("ragged blob accepted, got: " ++ show other)

-- | Unwrap commits measure the answered material against the
-- template key type (Tookan §3.2 key-type confusion: a 16-byte
-- AES blob unwrapped as CKK_DES3 must refuse, never mint a
-- confused key). AES takes 16/24/32 bytes, DES3 takes 24, XTS
-- takes 32/64, and generic secret takes any length.
caseUnwrapKeyTypeLength :: IO ()
caseUnwrapKeyTypeLength = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  (m3, target24H) <- genAesKey answer m2 st (aesTmpl 24)
  Just target24 <- pure (resolveHandle m3 target24H)
  Just target24Mat <- pure (keyBytesOf target24)
  let wrap16Blob = doWrap aesKwMech m3 st answer wrapH targetH 24
  blob16 <- wrap16Blob
  blob32 <- doWrap aesKwMech m3 st answer wrapH target24H 32
  let des3Tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong (mustKeyTypeId "CKK_DES3"))
        , (AttrToken, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
      xtsTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong (mustKeyTypeId "CKK_AES_XTS"))
        , (AttrToken, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
  -- 16 bytes as DES3 refuses at commit (the confusion leg).
  case planUnwrapKey defaultRules m3 st aesKwMech BS.empty wrapH blob16 des3Tmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> do
          assertEqual "confusion code" CKR_TEMPLATE_INCONSISTENT (rejCode r)
          assertEqual "confusion publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("confused unwrap committed, got: " ++ show other)
    other -> assertFailure ("unwrap plan is not an effect: " ++ show other)
  -- 24 bytes as DES3 commits (the type path itself works).
  case planUnwrapKey defaultRules m3 st aesKwMech BS.empty wrapH blob32 des3Tmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      c <- finishCommit m3 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m4 <- expectRight (publishDelta m3 (pcDelta c))
      Just ost <- pure (resolveHandle m4 h)
      assertEqual "des3 material" (Just target24Mat) (keyBytesOf ost)
    other -> assertFailure ("unwrap plan is not an effect: " ++ show other)
  -- 32 bytes as XTS commits (double-width data + tweak halves).
  (m5, target32H) <- genAesKey answer m3 st (aesTmpl 32)
  Just target32 <- pure (resolveHandle m5 target32H)
  Just target32Mat <- pure (keyBytesOf target32)
  blob40 <- doWrap aesKwMech m5 st answer wrapH target32H 40
  case planUnwrapKey defaultRules m5 st aesKwMech BS.empty wrapH blob40 xtsTmpl of
    KeyEffect pw fx -> do
      res <- answer m5 fx
      c <- finishCommit m5 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m6 <- expectRight (publishDelta m5 (pcDelta c))
      Just ost <- pure (resolveHandle m6 h)
      assertEqual "xts material" (Just target32Mat) (keyBytesOf ost)
    other -> assertFailure ("unwrap plan is not an effect: " ++ show other)
  -- 12 bytes as XTS refuses (not a double width).
  (m7, target12H) <- genKeyWith answer m5 st genericSecretKeyGenMech (secretTmplN 12)
  blob24 <- doWrap aesKwpMech m7 st answer wrapH target12H 24
  case planUnwrapKey defaultRules m7 st aesKwpMech BS.empty wrapH blob24 xtsTmpl of
    KeyEffect pw fx -> do
      res <- answer m7 fx
      case finishWork m7 st pw res of
        Reject r -> do
          assertEqual "xts confusion code" CKR_TEMPLATE_INCONSISTENT (rejCode r)
          assertEqual "xts confusion publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("confused unwrap committed, got: " ++ show other)
    other -> assertFailure ("unwrap plan is not an effect: " ++ show other)
  where
    doWrap wmech m st answer wrapH targetH wantLen =
      case planWrapKey m st wmech BS.empty wrapH targetH (IntentBuffer wantLen) of
        KeyEffect pw fx -> do
          res <- answer m fx
          case finishWork m st pw res of
            Immediate c -> case pcOutputs c of
              [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
              o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
            other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
        other -> assertFailure ("wrap plan is not an effect: " ++ show other) >> undefined

-- | Generate one RSA pair through the planner + backend, with
-- caller-supplied templates (so the wrap/unwrap marks land).
genRsaPair :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState
  -> [(AttributeType, AttributeValue)] -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle, ExternalHandle)
genRsaPair answer m st pubT privT =
  case planGenerateKeyPair defaultRules m st rsaKeyPairGenMech pubT privT of
    KeyEffect pw fx -> do
      res <- answer m fx
      c <- finishCommit m st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("RSA plan is not an effect: " ++ show other) >> undefined

caseRsaWrapRoundtrip :: IO ()
caseRsaWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let pubT = rsaPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      privT = rsaPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      oaep = encodeOaepParams "SHA256" "SHA256" BS.empty
      oaepLabel = encodeOaepParams "SHA_1" "SHA_1" "label"
  (m1, pubH, privH) <- genRsaPair answer m0 st pubT privT
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  -- Length queries answer the modulus width and plan no crypto.
  mapM_ (queryOk m2 st pubH targetH) [(rsaPkcsMech, BS.empty), (rsaOaepMech, oaep)]
  -- Both paddings wrap the raw material. (The synthetic seal is
  -- tag-sized, not modulus-wide; the modulus-wide real-backend
  -- roundtrip is pinned in RoutingE2ESpec caseDriverRsaWrap.)
  blob15 <- wrapOk m2 st answer rsaPkcsMech BS.empty pubH targetH
  assertEqual "v1.5 synthetic length" 32 (BS.length blob15)
  assertBool "v1.5 blob differs from plaintext" (blob15 /= targetMat)
  blobO <- wrapOk m2 st answer rsaOaepMech oaep pubH targetH
  assertEqual "oaep synthetic length" 32 (BS.length blobO)
  assertBool "padding domains separate" (blob15 /= blobO)
  blobL <- wrapOk m2 st answer rsaOaepMech oaepLabel pubH targetH
  assertBool "labeled row differs" (blobL /= blobO)
  -- Unwrap plans pair raw pending work with the unwrap effect
  -- (coherent, modulus-wide blob), and the finisher stores the
  -- answer raw (no PKCS#7 framing to strip).
  mapM_ (unwrapPlanOk m2 st privH) [(rsaPkcsMech, BS.empty), (rsaOaepMech, oaep)]
  case planUnwrapKey defaultRules m2 st rsaPkcsMech BS.empty privH
    (BS.replicate 256 0)
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrLabel, ValBytes "unwrapped")
    , (AttrEncrypt, ValBool True)
    ] of
    KeyEffect pw@(PwUnwrapRaw _) fx@(FxUnwrap _ _ _ _) -> do
      assertBool "raw pair coherent" (keyPairCompatible pw fx)
      c <- finishCommit m2 st pw (GotBytes targetMat) 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
      assertEqual "label landed"
        (Just (ValBytes "unwrapped")) (Map.lookup AttrLabel (osAttrs ost))
      assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
    other -> assertFailure ("unwrap plan is not a raw effect: " ++ show other)
  where
    queryOk m st pubH targetH (mech, params) =
      case planWrapKey m st mech params pubH targetH IntentNull of
        KeyImmediate (Immediate c) -> do
          assertEqual ("query length " ++ show mech)
            [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 256))]
            (pcOutputs c)
          assertEqual "query publishes nothing" (StateDelta []) (pcDelta c)
        other -> assertFailure ("wrap query is not an Immediate commit: " ++ show other)
    wrapOk m st answer mech params wrapH targetH =
      case planWrapKey m st mech params wrapH targetH (IntentBuffer 256) of
        KeyEffect pw fx -> do
          res <- answer m fx
          case finishWork m st pw res of
            Immediate c -> case pcOutputs c of
              [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
              o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
            other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
        other -> assertFailure ("wrap plan is not an effect: " ++ show other) >> undefined
    unwrapPlanOk m st wrapH (mech, params) =
      case planUnwrapKey defaultRules m st mech params wrapH (BS.replicate 256 0)
        [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)] of
        KeyEffect pw@(PwUnwrapRaw _) fx@(FxUnwrap _ _ _ _) ->
          assertBool ("raw pair coherent " ++ show mech) (keyPairCompatible pw fx)
        other -> assertFailure ("unwrap plan is not a raw effect: " ++ show other)

caseRsaWrapMismatch :: IO ()
caseRsaWrapMismatch = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  -- Both halves carry both marks, so the wrong-half legs reach
  -- the type gate (usage gates first, mirroring the AES resolver).
  let pubT = rsaPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      privT = rsaPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      oaep = encodeOaepParams "SHA256" "SHA256" BS.empty
  (m1, pubH, privH) <- genRsaPair answer m0 st pubT privT
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  (m3, aesWrapH) <- genAesKey answer m2 st wrapKeyTmpl
  let denyWrap m mech params wrapH targetH cap = case planWrapKey m st mech params wrapH targetH cap of
        KeyDenied (KeyDeny code _) -> pure code
        other -> assertFailure ("wrap must deny, got: " ++ show other) >> undefined
      denyUnwrap m mech params wrapH blob tmpl =
        case planUnwrapKey defaultRules m st mech params wrapH blob tmpl of
          KeyDenied (KeyDeny code _) -> pure code
          other -> assertFailure ("unwrap must deny, got: " ++ show other) >> undefined
      tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  -- Parameter shapes refuse.
  code <- denyWrap m3 rsaPkcsMech "nonempty" pubH targetH (IntentBuffer 256)
  assertEqual "v1.5 params code" CKR_ARGUMENTS_BAD code
  code <- denyWrap m3 rsaOaepMech "garbage" pubH targetH (IntentBuffer 256)
  assertEqual "oaep params code" CKR_ARGUMENTS_BAD code
  -- Wrong halves and foreign key types refuse.
  code <- denyWrap m3 rsaPkcsMech BS.empty privH targetH (IntentBuffer 256)
  assertEqual "private-half wrap code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code
  code <- denyWrap m3 rsaPkcsMech BS.empty aesWrapH targetH (IntentBuffer 256)
  assertEqual "aes-key wrap code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code
  code <- denyUnwrap m3 rsaPkcsMech BS.empty pubH (BS.replicate 256 0) tmpl
  assertEqual "public-half unwrap code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT code
  -- A key marked non-wrapping cannot wrap (absent flags default
  -- true at keygen, so the refusal needs an explicit false).
  (m4, plainPubH, _) <- genRsaPair answer m3 st
    (rsaPubTmpl ++ [(AttrWrap, ValBool False)]) rsaPrivTmpl
  code <- denyWrap m4 rsaPkcsMech BS.empty plainPubH targetH (IntentBuffer 256)
  assertEqual "no-wrap-mark code" CKR_KEY_FUNCTION_NOT_PERMITTED code
  -- An unextractable target cannot wrap.
  (m5, sealedH) <- genAesKey answer m4 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 16)
    , (AttrToken, ValBool False)
    , (AttrExtractable, ValBool False)
    ]
  code <- denyWrap m5 rsaPkcsMech BS.empty pubH sealedH (IntentBuffer 256)
  assertEqual "unextractable code" CKR_KEY_UNEXTRACTABLE code
  -- Oversized payloads refuse with the length code (v1.5 bound
  -- k-11 = 245; OAEP-SHA-512 bound k-2*64-2 = 126).
  (m6, bigH) <- genKeyWith answer m5 st genericSecretKeyGenMech
    (genericTmpl 250 ++ [(AttrExtractable, ValBool True)])
  code <- denyWrap m6 rsaPkcsMech BS.empty pubH bigH (IntentBuffer 256)
  assertEqual "oversized code" CKR_DATA_LEN_RANGE code
  let oaep512 = encodeOaepParams "SHA512" "SHA512" BS.empty
  (m7, midH) <- genKeyWith answer m6 st genericSecretKeyGenMech
    (genericTmpl 200 ++ [(AttrExtractable, ValBool True)])
  code <- denyWrap m7 rsaOaepMech oaep512 pubH midH (IntentBuffer 256)
  assertEqual "oversized oaep code" CKR_DATA_LEN_RANGE code
  -- Off-modulus blobs and key-typeless templates refuse.
  code <- denyUnwrap m7 rsaPkcsMech BS.empty privH "short" tmpl
  assertEqual "short blob code" CKR_ARGUMENTS_BAD code
  code <- denyUnwrap m7 rsaPkcsMech BS.empty privH (BS.replicate 256 0)
    [(AttrClass, ValULong ckoSecretKey)]
  assertEqual "typeless template code" CKR_TEMPLATE_INCOMPLETE code
  -- Short buffers answer the modulus width.
  case planWrapKey m3 st rsaPkcsMech BS.empty pubH targetH (IntentBuffer 255) of
    KeyImmediate (Reject r) -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short length"
        [NativeOutput (RegionBytes "wrapped" (IntentBuffer 255)) (encodeValue (ValULong 256))]
        (rejOutputs r)
    other -> assertFailure ("short buffer must reject, got: " ++ show other)

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
-- agreement parameters refuses CKR_MECHANISM_PARAM_INVALID.
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
      assertEqual "EC base, garbage params" CKR_MECHANISM_PARAM_INVALID code
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
  -- A short ciphertext is a length-range refusal with no
  -- effect planned (the cipher/dual precedent for wrong-length
  -- crypto inputs, and the oracle's expected code).
  case planKemDecaps m3 st mlKemMech privH KemMl768 "short" secretTmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "short ct code" CKR_ENCRYPTED_DATA_LEN_RANGE code
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
  -- A key marked non-wrapping cannot wrap (absent flags default
  -- true at keygen, so the refusal needs an explicit false).
  (m3, plainH) <- genAesKey answer m2 st (aesTmpl 32 ++ [(AttrWrap, ValBool False)])
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
  -- The object policy reads back directly (absent flags defaulted
  -- true at keygen; the explicit Decrypt=false stays out, as do
  -- the rule-forbidden encapsulate flags on AES secrets).
  Just ost <- pure (resolveHandle m1 keyH)
  assertEqual "policy from object"
    (Just ([OpEncrypt, OpSign, OpVerify, OpWrap, OpUnwrap, OpDerive], False))
    (policyFromObject ost)
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

caseRealRsaKeygen :: IO ()
caseRealRsaKeygen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st rsaKeyPairGenMech rsaPubTmpl rsaPrivTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("RSA plan is not an effect: " ++ show other) >> undefined
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  -- The native halves carry real DER; stamped components match.
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just pubB, Just privB) -> do
      assertBool "real pub DER nonempty" (not (BS.null pubB))
      assertBool "real priv DER nonempty" (not (BS.null privB))
      assertBool "halves differ" (pubB /= privB)
      case Map.lookup AttrModulus (osAttrs pub) of
        Just (ValBytes n) -> assertEqual "real modulus length" 256 (BS.length n)
        other -> assertFailure ("real pub lacks modulus: " ++ show other)
      assertEqual "real default exponent"
        (Just (ValBytes (BS.pack [1, 0, 1])))
        (Map.lookup AttrPublicExponent (osAttrs pub))
      -- The generated pair really signs: RSA v1.5 roundtrip at the backend.
      sres <- sign env (SigRSA_PKCS1v15 D_SHA256) (KeyDer privB) "rsa-msg"
      sig <- case sres of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real sign failed: " ++ show err) >> undefined
      vres <- verify env (SigRSA_PKCS1v15 D_SHA256) (KeyDer pubB) "rsa-msg" sig
      case vres of
        EngineOk () -> pure ()
        EngineFail err -> assertFailure ("real verify failed: " ++ show err)
    _ -> assertFailure "real RSA halves lack material"

caseRealDsaParamgen :: IO ()
caseRealDsaParamgen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, h) <- case planGenerateKey defaultRules m0 st dsaParameterGenMech (dsaParamsTmpl 1024) of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 1
      h' <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h')
    other -> assertFailure ("DSA paramgen plan is not an effect: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "params class" (Just (ValULong ckoDomainParameters))
    (Map.lookup AttrClass (osAttrs ost))
  assertEqual "params key type" (Just (ValULong ckkDsa))
    (Map.lookup AttrKeyType (osAttrs ost))
  case (Map.lookup AttrPrime (osAttrs ost), Map.lookup AttrSubprime (osAttrs ost),
      Map.lookup AttrBase (osAttrs ost)) of
    (Just (ValBytes p), Just (ValBytes q), Just (ValBytes g)) -> do
      assertEqual "prime width" 128 (BS.length p)
      assertEqual "subprime width" 20 (BS.length q)
      assertEqual "base width" 128 (BS.length g)
      assertEqual "prime bits" (Just (ValULong 1024))
        (Map.lookup AttrPrimeBits (osAttrs ost))
      assertEqual "subprime bits" (Just (ValULong 160))
        (Map.lookup AttrSubprimeBits (osAttrs ost))
    other -> assertFailure ("real params lack components: " ++ show other)

caseRealDsaKeygen :: IO ()
caseRealDsaKeygen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, ph) <- case planGenerateKey defaultRules m0 st dsaParameterGenMech (dsaParamsTmpl 1024) of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 1
      h' <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h')
    other -> assertFailure ("DSA paramgen plan is not an effect: " ++ show other) >> undefined
  Just post <- pure (resolveHandle m1 ph)
  (p, q, g) <- case (Map.lookup AttrPrime (osAttrs post),
      Map.lookup AttrSubprime (osAttrs post), Map.lookup AttrBase (osAttrs post)) of
    (Just (ValBytes p), Just (ValBytes q), Just (ValBytes g)) -> pure (p, q, g)
    other -> assertFailure ("real params lack components: " ++ show other) >> undefined
  let pubT =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkDsa)
        , (AttrPrime, ValBytes p)
        , (AttrSubprime, ValBytes q)
        , (AttrBase, ValBytes g)
        , (AttrToken, ValBool False)
        , (AttrVerify, ValBool True)
        ]
  (m2, pubH, privH) <- case planGenerateKeyPair defaultRules m1 st dsaKeyPairGenMech pubT dsaPrivTmpl of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("DSA plan is not an effect: " ++ show other) >> undefined
  Just pub <- pure (resolveHandle m2 pubH)
  Just priv <- pure (resolveHandle m2 privH)
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just pubB, Just privB) -> do
      assertBool "real pub DER nonempty" (not (BS.null pubB))
      assertBool "real priv DER nonempty" (not (BS.null privB))
      assertBool "halves differ" (pubB /= privB)
      assertEqual "priv inherits prime" (Just (ValBytes p))
        (Map.lookup AttrPrime (osAttrs priv))
      -- The generated pair really signs: DSA-SHA256 roundtrip at the backend.
      sres <- sign env (SigDSA "DER" (Just D_SHA256)) (KeyDer privB) "dsa-msg"
      sig <- case sres of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real sign failed: " ++ show err) >> undefined
      vres <- verify env (SigDSA "DER" (Just D_SHA256)) (KeyDer pubB) "dsa-msg" sig
      case vres of
        EngineOk () -> pure ()
        EngineFail err -> assertFailure ("real verify failed: " ++ show err)
    _ -> assertFailure "real DSA halves lack material"

caseRealEcKeygen384 :: IO ()
caseRealEcKeygen384 = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
      (pubT, privT) = ecTmpls "P-384"
  (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech pubT privT of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("P-384 plan is not an effect: " ++ show other) >> undefined
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just pubB, Just privB) -> do
      assertBool "real pub DER nonempty" (not (BS.null pubB))
      assertBool "real priv DER nonempty" (not (BS.null privB))
      sres <- sign env (SigECDSA (EcSpec "P-384" "DER") (Just D_SHA384))
        (KeyDer privB) "ec384-msg"
      sig <- case sres of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real sign failed: " ++ show err) >> undefined
      vres <- verify env (SigECDSA (EcSpec "P-384" "DER") (Just D_SHA384))
        (KeyDer pubB) "ec384-msg" sig
      case vres of
        EngineOk () -> pure ()
        EngineFail err -> assertFailure ("real verify failed: " ++ show err)
    _ -> assertFailure "real P-384 halves lack material"

caseRealEcKeygen521 :: IO ()
caseRealEcKeygen521 = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
      (pubT, privT) = ecTmpls "P-521"
  (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech pubT privT of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("P-521 plan is not an effect: " ++ show other) >> undefined
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just pubB, Just privB) -> do
      assertBool "real pub DER nonempty" (not (BS.null pubB))
      assertBool "real priv DER nonempty" (not (BS.null privB))
      sres <- sign env (SigECDSA (EcSpec "P-521" "DER") (Just D_SHA512))
        (KeyDer privB) "ec521-msg"
      sig <- case sres of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real sign failed: " ++ show err) >> undefined
      vres <- verify env (SigECDSA (EcSpec "P-521" "DER") (Just D_SHA512))
        (KeyDer pubB) "ec521-msg" sig
      case vres of
        EngineOk () -> pure ()
        EngineFail err -> assertFailure ("real verify failed: " ++ show err)
    _ -> assertFailure "real P-521 halves lack material"

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

caseRealAesKem :: IO ()
caseRealAesKem = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, fakeH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkMlKem)
    , (AttrKemAlg, ValULong 768)
    , (AttrToken, ValBool False)
    , (AttrEncapsulate, ValBool True)
    ] "not-a-real-kem-key"
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
  -- ML-KEM keygen through the real backend mints a usable
  -- pair (provider DER halves, agreeing OIDs, 64-byte seed
  -- stamped, set tag kept); encaps/decaps round-trip; a
  -- corrupt KEM key fails closed as a bad key (GENERAL_ERROR),
  -- never unsupported.
  (m2, realPubH, realPrivH) <- genKemPair answer m1 st
  Just realPub <- pure (resolveHandle m2 realPubH)
  Just realPriv <- pure (resolveHandle m2 realPrivH)
  Just pubDer <- pure (keyBytesOf realPub)
  Just privDer <- pure (keyBytesOf realPriv)
  case (mlkemSpkiFields pubDer, mlkemPkcs8Fields privDer) of
    (Just (pubOid, _), Just (privOid, seed, _))
      | pubOid == privOid -> assertEqual "real seed width" 64 (BS.length seed)
    _ -> assertFailure "real KEM halves disagree or do not parse"
  assertEqual "real set tag" (Just (ValULong 2))
    (Map.lookup AttrParameterSet (osAttrs realPub))
  (m3, ct, ss) <- runEncaps answer m2 st realPubH
  assertEqual "real ct length" (kemCtLen KemMl768) (BS.length ct)
  assertEqual "real ss length" 32 (BS.length ss)
  case planKemDecaps m3 st mlKemMech realPrivH KemMl768 ct secretTmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      c <- finishCommit m3 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m4 <- expectRight (publishDelta m3 (pcDelta c))
      Just ost <- pure (resolveHandle m4 h)
      assertEqual "real decaps recovers" (Just ss) (keyBytesOf ost)
    other -> assertFailure ("real decaps must plan: " ++ show other)
  case planKemEncaps m1 st mlKemMech fakeH KemMl768 secretTmpl
      (IntentBuffer (fromIntegral (kemCtLen KemMl768))) of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      case res of
        GotCryptoError (CryptoBadKey _ _) -> pure ()
        other -> assertFailure ("must be a bad key, got: " ++ show other)
      case finishWork m1 st pw res of
        Reject r -> do
          assertEqual "code" CKR_GENERAL_ERROR (rejCode r)
          assertEqual "zero objects" (StateDelta []) (rejDelta r)
        other -> assertFailure ("must reject, got: " ++ show other)
    other -> assertFailure ("must plan an effect, got: " ++ show other)

caseKemWrongKeyType :: IO ()
caseKemWrongKeyType = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, aesH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, pubH, _) <- genKemPair answer m1 st
  let ctLen = kemCtLen KemMl768
      intent = IntentBuffer (fromIntegral ctLen)
  -- A wrong-typed key refuses TYPE_INCONSISTENT (the deep
  -- mismatch), even carrying usage flags.
  case planKemEncaps m2 st mlKemMech aesH KemMl768 secretTmpl intent of
    KeyDenied (KeyDeny code _) ->
      assertEqual "encaps wrong-type code" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  case planKemDecaps m2 st mlKemMech aesH KemMl768 (BS.replicate ctLen 0) secretTmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "decaps wrong-type code" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- A right-typed key on another set refuses PERMITTED (the
  -- usage-class refusal, not a type contradiction).
  case planKemEncaps m2 st mlKemMech pubH KemMl512 secretTmpl intent of
    KeyDenied (KeyDeny code _) ->
      assertEqual "encaps wrong-set code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- An unknown handle refuses handle-invalid.
  case planKemEncaps m2 st mlKemMech (ExternalHandle 9999) KemMl768 secretTmpl intent of
    KeyDenied (KeyDeny code _) ->
      assertEqual "encaps bad-handle code" CKR_OBJECT_HANDLE_INVALID code
    other -> assertFailure ("must deny, got: " ++ show other)

caseKemAesTemplate :: IO ()
caseKemAesTemplate = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, pubH, privH) <- genKemPair answer m0 st
  let aesTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 32)
        , (AttrToken, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
      ctLen = kemCtLen KemMl768
  -- Encaps against an AES template mints an AES-256 object
  -- carrying the 32-byte secret.
  (m2, ct) <- case planKemEncaps m1 st mlKemMech pubH KemMl768 aesTmpl
      (IntentBuffer (fromIntegral ctLen)) of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      hh <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      Just ost <- pure (resolveHandle m' hh)
      assertEqual "secret keytype" (Just (ValULong ckkAes))
        (Map.lookup AttrKeyType (osAttrs ost))
      case keyBytesOf ost of
        Just ss -> assertEqual "secret length" 32 (BS.length ss)
        Nothing -> assertFailure "AES secret lacks material"
      case pcOutputs c !! 0 of
        NativeOutput (RegionBytes "ciphertext" _) bytes -> pure (m', bytes)
        o -> assertFailure ("no ciphertext: " ++ show o) >> undefined
    other -> assertFailure ("must plan, got: " ++ show other) >> undefined
  -- Decaps against an AES template likewise mints AES-256.
  case planKemDecaps m2 st mlKemMech privH KemMl768 ct aesTmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      hh <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m' hh)
      assertEqual "decaps keytype" (Just (ValULong ckkAes))
        (Map.lookup AttrKeyType (osAttrs ost))
    other -> assertFailure ("must plan, got: " ++ show other)
  -- Any other explicit secret type refuses inconsistent.
  let rsaTmpl = (AttrKeyType, ValULong ckkRsa) :
        filter ((/= AttrKeyType) . fst) aesTmpl
  case planKemEncaps m1 st mlKemMech pubH KemMl768 rsaTmpl
      (IntentBuffer (fromIntegral ctLen)) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "rsa template code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- Mechanism-contributed attributes refuse inconsistent on
  -- both entries (the finisher would otherwise silently
  -- overwrite caller bytes with the real secret).
  let injected = (AttrValue, ValBytes "injected") : aesTmpl
  case planKemEncaps m1 st mlKemMech pubH KemMl768 injected
      (IntentBuffer (fromIntegral ctLen)) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "encaps injection code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  case planKemDecaps m2 st mlKemMech privH KemMl768 ct injected of
    KeyDenied (KeyDeny code _) ->
      assertEqual "decaps injection code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- An AES template without CKA_VALUE_LEN proceeds (the 32 is
  -- mechanism-determined, supplied upfront for the presence
  -- rule rather than refused).
  let noLen = filter ((/= AttrValueLen) . fst) aesTmpl
  case planKemEncaps m1 st mlKemMech pubH KemMl768 noLen
      (IntentBuffer (fromIntegral ctLen)) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("must plan, got: " ++ show other)

caseKemKeygenParamSet :: IO ()
caseKemKeygenParamSet = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let setT tmpl v = (AttrParameterSet, ValULong v) :
        filter ((/= AttrParameterSet) . fst) tmpl
      noAlg tmpl = filter ((/= AttrKemAlg) . fst) tmpl
      gen pubT privT = planGenerateKeyPair defaultRules m0 st
        mlKemKeyPairGenMech pubT privT
  -- CKA_PARAMETER_SET selects the set (1/2/3 -> 512/768/1024);
  -- the minted halves carry both the numeric tag and the CKP id.
  mapM_ (\(ckp, alg) -> do
    let pubT = setT (noAlg kemPubTmpl) ckp
        privT = setT (noAlg kemPrivTmpl) ckp
    case gen pubT privT of
      KeyEffect pw fx -> do
        res <- answer m0 fx
        c <- finishCommit m0 st pw res 2
        pubH <- handleOf (pcOutputs c !! 0)
        privH <- handleOf (pcOutputs c !! 1)
        m' <- expectRight (publishDelta m0 (pcDelta c))
        Just pub <- pure (resolveHandle m' pubH)
        Just priv <- pure (resolveHandle m' privH)
        assertEqual ("alg tag " ++ show alg) (Just (ValULong alg))
          (Map.lookup AttrKemAlg (osAttrs pub))
        assertEqual ("ckp tag " ++ show alg) (Just (ValULong ckp))
          (Map.lookup AttrParameterSet (osAttrs priv))
        assertBool ("halves differ " ++ show alg)
          (keyBytesOf pub /= keyBytesOf priv)
      other -> assertFailure ("must plan: " ++ show other))
    [(1, 512), (2, 768), (3, 1024)]
  -- An unknown set refuses inconsistent.
  case gen (setT (noAlg kemPubTmpl) 7) (noAlg kemPrivTmpl) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "unknown set code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- Disagreeing templates refuse inconsistent.
  case gen (setT (noAlg kemPubTmpl) 1) (setT (noAlg kemPrivTmpl) 2) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "disagree code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- A template contradicting itself refuses inconsistent.
  let contra = (AttrKemAlg, ValULong 512) : setT (noAlg kemPubTmpl) 2
  case gen contra (noAlg kemPrivTmpl) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "self-contradiction code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- CKA_DERIVE stamps false on KEM halves (no derive
  -- operation exists): explicit-true refuses, and minted
  -- halves read back false (the oracle's derive-false leg
  -- only passes on an explicit false, not a missing flag).
  let withDerive tmpl = (AttrDerive, ValBool True) : tmpl
  case gen (withDerive (setT (noAlg kemPubTmpl) 2)) (noAlg kemPrivTmpl) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "pub derive code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  case gen (setT (noAlg kemPubTmpl) 2) (withDerive (noAlg kemPrivTmpl)) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "priv derive code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  case gen (setT (noAlg kemPubTmpl) 2) (setT (noAlg kemPrivTmpl) 2) of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      pubH <- handleOf (pcOutputs c !! 0)
      privH <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      Just pub <- pure (resolveHandle m' pubH)
      Just priv <- pure (resolveHandle m' privH)
      assertEqual "minted pub derive false" (Just (ValBool False))
        (Map.lookup AttrDerive (osAttrs pub))
      assertEqual "minted priv derive false" (Just (ValBool False))
        (Map.lookup AttrDerive (osAttrs priv))
    other -> assertFailure ("must plan: " ++ show other)

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
