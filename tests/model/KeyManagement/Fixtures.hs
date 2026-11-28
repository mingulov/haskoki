{- | KeyManagement fixtures.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.Fixtures
  ( slot0
  , sid1
  , seedModel
  , getSession
  , loginUser
  , expectRight
  , resolverFromModel
  , hex
  , withRealEnv
  , answerReal
  , plantKey
  , withSynth
  , kemPubTmpl
  , kemPrivTmpl
  , secretTmpl
  , handleOf
  , genKemPair
  , finishCommit
  , byteOpsD16
  , sp800Fixed
  , tlsKdfSeed64
  , spKey
  , spIv
  , spP1
  , spC1
  , rfcPrk
  , rfcInfo
  , rfcOkm
  , rfcIkm
  , rfcSalt
  , rfcOkmZeroSalt
  , tlsKdfMasterMech
  , tlsKdfTls12Mech
  , tlsKdfExtMech
  , tlsKdfFreeMech
  , tlsKdfGenMech
  , ikePlusMech
  , ikePrfMech
  , ike1Mech
  , ikeExtMech
  , ikeNi
  , ikeNr
  , ikeSeed32
  , concatKeyMech
  , concatDataMech
  , dataConcatMech
  , xorMech
  , extractMech
  , keyMat10Mech
  , keyMat12Mech
  , keyMatSafeMech
  , keyMatCr
  , keyMatSr
  , keyMatKid
  , ssl3MasterMech
  , ssl3MasterDhMech
  , ssl3KeyMatMech
  , ssl3Cr
  , ssl3Sr
  , sp800CounterMech
  , sp800FeedbackMech
  , sp800DoubleMech
  , genRsaPair
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import qualified Data.Map.Strict as Map
import Test.Tasty.HUnit (assertEqual, assertFailure)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  )
import Haskoki.Engine.Backend
  ( CryptoBackend (..)
  , EngineResult (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver (KeyResolver, runEffect)
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.Engine.Synthetic (Synthetic (..))
import Haskoki.Model
  ( Model (..)
  , SessionState
  , addToken
  , emptyModel
  , lookupSession
  )
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoResult (..))
import Haskoki.Operation.Kem
  ( mlKemKeyPairGenMech
  )
import Haskoki.Operation.KeyManagement
  ( KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , ckkGenericSecret
  , ckkMlKem
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , finishWork
  , keyBytesOf
  , pendingFromAttrs
  , planGenerateKeyPair
  , publishPending
  , rsaKeyPairGenMech
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , StateDelta (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated
  ( ckm_CONCATENATE_BASE_AND_DATA
  , ckm_CONCATENATE_BASE_AND_KEY
  , ckm_CONCATENATE_DATA_AND_BASE
  , ckm_EXTRACT_KEY_FROM_KEY
  , ckm_IKE1_EXTENDED_DERIVE
  , ckm_IKE1_PRF_DERIVE
  , ckm_IKE2_PRF_PLUS_DERIVE
  , ckm_IKE_PRF_DERIVE
  , ckm_SP800_108_COUNTER_KDF
  , ckm_SP800_108_DOUBLE_PIPELINE_KDF
  , ckm_SP800_108_FEEDBACK_KDF
  , ckm_TLS_MASTER_KEY_DERIVE
  , ckm_TLS_KEY_AND_MAC_DERIVE
  , ckm_TLS12_KEY_AND_MAC_DERIVE
  , ckm_TLS12_KEY_SAFE_DERIVE
  , ckm_TLS12_KDF
  , ckm_TLS12_MASTER_KEY_DERIVE
  , ckm_TLS12_EXTENDED_MASTER_KEY_DERIVE
  , ckm_TLS_KDF
  , ckm_XOR_BASE_AND_DATA
  , ckm_SSL3_MASTER_KEY_DERIVE
  , ckm_SSL3_MASTER_KEY_DERIVE_DH
  , ckm_SSL3_KEY_AND_MAC_DERIVE
  )
import Haskoki.Request (OutputRegion (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , SessionId (..)
  , SlotId (..)
  )

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

-- | The oracle-profile fixed input: label, 0x00 separator,
-- context (the DKM length rides execution, never the frame).
sp800Fixed :: BS.ByteString
sp800Fixed = "SP800-108 test label" <> "\x00" <> "SP800-108 test context"

sp800CounterMech, sp800FeedbackMech, sp800DoubleMech :: MechanismId
sp800CounterMech = MechanismId ckm_SP800_108_COUNTER_KDF
sp800FeedbackMech = MechanismId ckm_SP800_108_FEEDBACK_KDF
sp800DoubleMech = MechanismId ckm_SP800_108_DOUBLE_PIPELINE_KDF

tlsKdfSeed64 :: BS.ByteString
tlsKdfSeed64 = BS.pack [0 .. 63]

byteOpsD16 :: BS.ByteString
byteOpsD16 = BS.pack (replicate 16 1)

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

rfcIkm, rfcSalt, rfcOkmZeroSalt :: ByteString
rfcIkm = hex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
rfcSalt = hex "000102030405060708090a0b0c"
rfcOkmZeroSalt = hex "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"

tlsKdfMasterMech, tlsKdfTls12Mech, tlsKdfExtMech, tlsKdfFreeMech, tlsKdfGenMech :: MechanismId
tlsKdfMasterMech = MechanismId ckm_TLS_MASTER_KEY_DERIVE
tlsKdfTls12Mech = MechanismId ckm_TLS12_MASTER_KEY_DERIVE
tlsKdfExtMech = MechanismId ckm_TLS12_EXTENDED_MASTER_KEY_DERIVE
tlsKdfFreeMech = MechanismId ckm_TLS12_KDF
tlsKdfGenMech = MechanismId ckm_TLS_KDF

ikePlusMech, ikePrfMech, ike1Mech, ikeExtMech :: MechanismId
ikePlusMech = MechanismId ckm_IKE2_PRF_PLUS_DERIVE
ikePrfMech = MechanismId ckm_IKE_PRF_DERIVE
ike1Mech = MechanismId ckm_IKE1_PRF_DERIVE
ikeExtMech = MechanismId ckm_IKE1_EXTENDED_DERIVE

ikeNi, ikeNr, ikeSeed32 :: BS.ByteString
ikeNi = BS.pack (replicate 16 1)
ikeNr = BS.pack (replicate 16 2)
ikeSeed32 = ikeNi <> ikeNr

concatKeyMech, concatDataMech, dataConcatMech, xorMech, extractMech :: MechanismId
concatKeyMech = MechanismId ckm_CONCATENATE_BASE_AND_KEY
concatDataMech = MechanismId ckm_CONCATENATE_BASE_AND_DATA
dataConcatMech = MechanismId ckm_CONCATENATE_DATA_AND_BASE
xorMech = MechanismId ckm_XOR_BASE_AND_DATA
extractMech = MechanismId ckm_EXTRACT_KEY_FROM_KEY

keyMat10Mech, keyMat12Mech, keyMatSafeMech :: MechanismId
keyMat10Mech = MechanismId ckm_TLS_KEY_AND_MAC_DERIVE
keyMat12Mech = MechanismId ckm_TLS12_KEY_AND_MAC_DERIVE
keyMatSafeMech = MechanismId ckm_TLS12_KEY_SAFE_DERIVE

keyMatCr, keyMatSr :: BS.ByteString
keyMatCr = BS.pack [0 .. 31]
keyMatSr = BS.pack [32 .. 63]

-- | The single key-material template: protection matching an
-- extractable non-sensitive base, no length (lengths come
-- from params).
keyMatKid :: [(AttributeType, AttributeValue)]
keyMatKid =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrSensitive, ValBool False)
  , (AttrExtractable, ValBool True)
  , (AttrToken, ValBool False)
  ]

ssl3MasterMech, ssl3MasterDhMech, ssl3KeyMatMech :: MechanismId
ssl3MasterMech = MechanismId ckm_SSL3_MASTER_KEY_DERIVE
ssl3MasterDhMech = MechanismId ckm_SSL3_MASTER_KEY_DERIVE_DH
ssl3KeyMatMech = MechanismId ckm_SSL3_KEY_AND_MAC_DERIVE

-- | The oracle's 28-byte randoms (SSL3 randoms carry
-- explicit lengths; no fixed 32).
ssl3Cr, ssl3Sr :: BS.ByteString
ssl3Cr = BS.pack [0 .. 27]
ssl3Sr = BS.pack [28 .. 55]

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
