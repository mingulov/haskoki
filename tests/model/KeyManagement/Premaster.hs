{- | KeyManagement pre-master keygens (slice 11a, phase 2).
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.Premaster
  ( caseTlsPremasterKeygen
  , caseSsl3PremasterKeygen
  , caseWtlsPremasterKeygen
  , genPremasterKey
  , premasterTmpl
  , casePbkd2Keygen
  , caseAesKeygenEncapsulate
  , caseInitAllowedMechanisms
  , allowedList
  , caseDeriveAllowedMechanisms
  , caseDeriveDesParity
  , caseDeriveGenericPassthrough
  , caseDeriveKeymatParity
  , caseWrapAllowedMechanisms
  , caseKemAllowedMechanisms
  , genericTmpl
  , genKeyWith
  , caseGenericSecretKeygen
  , hmacSha256Mech
  , des3macMech
  , des3macGenMech
  , sha256Mech
  , aesCcmMech
  , caseInitKeyTypeMatrix
  , caseInitClassConfusion
  , caseUnwrapRefusesAsymmetric
  , caseEcKeypair
  , mldsaPubTmpl
  , mldsaPrivTmpl
  , caseMldsaKeypair
  , caseMldsaSetPlanner
  , caseMldsaStampSeed
  , ecTmpls
  , caseEcKeygenCurves
  , caseRsaKeygen
  , caseRsaModulusBits
  , caseRsaKeygenDistinct
  , caseRsaKeygenBounds
  , caseRsaExponentPlanner
  , caseRsaStampMismatch
  , caseX942ParamSizesPlanner
  , caseDhPkcsParamSizesPlanner
  , caseEcExtraBitsPlanner
  , caseDsaParamSizesPlanner
  , caseDsaDomainPlanner
  , caseDsaGenArgsCodec
  , caseDsaCompatible
  , caseDsaStamp
  , caseDhDomainPlanner
  , caseDhGenArgsCodec
  , caseDhCompatible
  , caseDhStamp
  , caseEdwardsGenArgsCodec
  , caseEdwardsPairPlanner
  , caseEdwardsCompatible
  , caseEdwardsStamp
  , caseMontgomeryGenArgsCodec
  , caseMontgomeryPairPlanner
  , caseMontgomeryCompatible
  , caseMontgomeryStamp
  , caseKeygenUsageDefaults
  , caseDeriveDefaultsFalse
  , caseDeriveReadViewUnwrapDerive
  , caseEcPointStamped
  , caseEcOpaqueBareCopy
  , caseEcParamsDisagree
  , caseWrapRoundtrip
  , secretTmplN
  , caseAesKwWrapRoundtrip
  , caseAesKwpWrapRoundtrip
  , caseAesKwPkcs7WrapRoundtrip
  , caseEcdhCompWrapRoundtrip
  , caseRsaCompWrapRoundtrip
  , caseUnwrapKeyTypeLength
  , caseRsaWrapRoundtrip
  , caseRsaWrapMismatch
  , caseRsaX509Wrap
  , caseRecoverAttrs
  , caseAuthWrapRoundtrip
  , caseDeriveSingle
  , caseDeriveEcdhWrongKeyType
  , caseDeriveEcdhBadParams
  , caseDeriveKdfBadHandle
  , caseDeriveKdfWrongKeyType
  , casePublishAtomic
  , casePadMirror
  ) where

import Data.Bits ((.&.), shiftR, xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Attribute
  ( AttributeResult (..)
  , AttributeType (..)
  , AttributeValue (..)
  , PartialReads (..)
  , decodeValue
  , encodeValue
  , getAttributes
  )
import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Der (curveTable, dhParamsDer, dhParamsDerQ, dhPrivateDer, dhPrivateDerQ, dhPublicDer, dhPublicDerQ, dsaParamsDer, dsaPrivateDer, dsaPublicDer, ecPublicDer, eddsaPrivateDer, eddsaPublicDer, montgomeryPrivateDer, montgomeryPublicDer, parseDhParams, parseDsaParams, rsaPrivateDer, rsaPublicDer)
import Haskoki.Engine.Backend
  ( BackendError (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EngineResult (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , SigSpec (..)
  )
import Haskoki.Engine.Driver ( runEffect)
import Haskoki.Engine.Synthetic (Synthetic (..))
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState
  )
import Haskoki.Object ( planFindObjects, planGetAttributes, resolveHandle)
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
  ( encodeDeriveParams
  , encodeHkdfInfo
  , hkdfDeriveMech
  , maxDerivedTotal
  , planDerive
  )
import Haskoki.Operation.Effect ( CryptoEffect (..), CryptoResult (..))
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
  , aesKwp7Mech
  , ecdhAesKwMech
  , ecdhCofAesKwMech
  , ecdhXAesKwMech
  , ckkAes
  , ckkDes3
  , ckkDsa
  , ckkEc
  , ckkGenericSecret
  , ckkMlDsa
  , ckkMlKem
  , ckkRsa
  , ckkAesXts
  , ckkDes
  , ckkDes2
  , ckkCdmf
  , ckkSha256Hmac
  , ckoDomainParameters
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , checkKeyTemplate
  , decodeGenArgs
  , dhKeyPairGenMech
  , dsaKeyPairGenMech
  , dsaParameterGenMech
  , ecKeyPairGenMech
  , ecExtraBitsKeyPairGenMech
  , dhPkcsParameterGenMech
  , x9_42DhKeyPairGenMech
  , x9_42DhParameterGenMech
  , edwardsKeyPairGenMech
  , montgomeryKeyPairGenMech
  , encodeGenArgs
  , mldsaKeyPairGenMech
  , finishWork
  , derivedNeedsParity
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
  , ssl3PremasterKeyGenMech
  , tlsPremasterKeyGenMech
  , wtlsPremasterKeyGenMech
  , planUnwrapKey
  , policyFromObject
  , planWrapKey
  , publishPending
  , rsaAesKwMech
  , rsaKeyPairGenMech
  , rsaOaepMech
  , rsaPkcsMech
  , rsaX509Mech
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
import Haskoki.Registry (MechanismId (..), Operation (..), curatedRegistry, mkCapabilities)
import Haskoki.Recipe.Ecdh (encodeEcdhParams)
import Haskoki.Recipe.Kdf (encodePbkd2Params, maxPbkd2Iters)
import Haskoki.Recipe.ByteOps (encodeByteOpsParams)
import Haskoki.Recipe.Ike (encodeIkeParams)
import Haskoki.Recipe.RsaOaep (encodeOaepParams)
import Haskoki.Recipe.WrapComp (encodeWrapCompEcdhParams)
import Haskoki.Recipe.WrapCompRsa (encodeWrapCompRsaParams)
import Haskoki.Registry.Generated
  ( ckm_AES_CCM
  , ckm_DES3_MAC
  , ckm_DES3_MAC_GENERAL
  , ckm_ECDH1_DERIVE
  , ckm_PKCS5_PBKD2
  , ckm_SHA256
  , ckm_SHA256_HMAC
  , ckm_SHA256_RSA_PKCS
  , ckm_SHA256_KEY_DERIVATION
  )
import Haskoki.Registry.KeyMatrix (matrixKeyTypes)
import Haskoki.Request ( OutputIntent (..), OutputRegion (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , ReturnCode (..)
  )
import KeyManagement.Fixtures
import KeyManagement.KeygenSweep
import KeyManagement.Part2Fixtures
import KeyManagement.Part3

-- ---------------------------------------------------------------------------
-- Pre-master keygens (slice 11a, phase 2)
-- ---------------------------------------------------------------------------

-- | TLS/SSL3 pre-master: the 2-byte CK_VERSION parameter is
-- required and its bytes lead the 48-byte generic secret.
caseTlsPremasterKeygen :: IO ()
caseTlsPremasterKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genPremasterKey answer m0 st tlsPremasterKeyGenMech
    (BS.pack [3, 3]) (premasterTmpl 48)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key type"
    (Just (ValULong ckkGenericSecret)) (Map.lookup AttrKeyType (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> do
      assertEqual "pre-master length" 48 (BS.length mat)
      assertEqual "version prefix" (BS.pack [3, 3]) (BS.take 2 mat)
    Nothing -> assertFailure "generated key lacks material"
  -- A missing length defaults to 48; any other length refuses.
  (m2, h2) <- genPremasterKey answer m1 st tlsPremasterKeyGenMech
    (BS.pack [3, 1]) [a | a@(t, _) <- premasterTmpl 48, t /= AttrValueLen]
  Just ost2 <- pure (resolveHandle m2 h2)
  case keyBytesOf ost2 of
    Just mat2 -> do
      assertEqual "default length" 48 (BS.length mat2)
      assertEqual "default version prefix" (BS.pack [3, 1]) (BS.take 2 mat2)
    Nothing -> assertFailure "generated key lacks material"
  case planGenerateKey defaultRules m2 st tlsPremasterKeyGenMech
      (BS.pack [3, 3]) (premasterTmpl 16) of
    KeyDenied deny -> assertEqual "bad length code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("16-byte pre-master must refuse: " ++ show other)
  -- The version parameter is required and exactly 2 bytes.
  mapM_ (refuseParams m2 st tlsPremasterKeyGenMech)
    [BS.empty, BS.singleton 3, BS.pack [3, 3, 3]]
  -- A non-generic-secret key type refuses.
  case planGenerateKey defaultRules m2 st tlsPremasterKeyGenMech
      (BS.pack [3, 3]) (sweepTmpl ckkAes 48) of
    KeyDenied deny -> assertEqual "wrong type code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("AES-typed pre-master must refuse: " ++ show other)
  where
    refuseParams m st mech params =
      case planGenerateKey defaultRules m st mech params (premasterTmpl 48) of
        KeyDenied deny -> assertEqual ("params code " ++ show params)
          CKR_MECHANISM_PARAM_INVALID (kdCode deny)
        other -> assertFailure
          ("params " ++ show params ++ " must refuse: " ++ show other)

-- | SSL3 pre-master mirrors TLS (same parameter, same shape).
caseSsl3PremasterKeygen :: IO ()
caseSsl3PremasterKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genPremasterKey answer m0 st ssl3PremasterKeyGenMech
    (BS.pack [3, 0]) (premasterTmpl 48)
  Just ost <- pure (resolveHandle m1 h)
  case keyBytesOf ost of
    Just mat -> do
      assertEqual "pre-master length" 48 (BS.length mat)
      assertEqual "version prefix" (BS.pack [3, 0]) (BS.take 2 mat)
    Nothing -> assertFailure "generated key lacks material"
  case planGenerateKey defaultRules m1 st ssl3PremasterKeyGenMech
      BS.empty (premasterTmpl 48) of
    KeyDenied deny -> assertEqual "null params code"
      CKR_MECHANISM_PARAM_INVALID (kdCode deny)
    other -> assertFailure ("null params must refuse: " ++ show other)

-- | WTLS pre-master: a 1-byte version parameter leads a
-- variable-length (20-255 byte) generic secret.
caseWtlsPremasterKeygen :: IO ()
caseWtlsPremasterKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genPremasterKey answer m0 st wtlsPremasterKeyGenMech
    (BS.singleton 1) (premasterTmpl 32)
  Just ost <- pure (resolveHandle m1 h)
  case keyBytesOf ost of
    Just mat -> do
      assertEqual "pre-master length" 32 (BS.length mat)
      assertEqual "version prefix" (BS.singleton 1) (BS.take 1 mat)
    Nothing -> assertFailure "generated key lacks material"
  (m2, h2) <- genPremasterKey answer m1 st wtlsPremasterKeyGenMech
    (BS.singleton 1) (premasterTmpl 20)
  Just ost2 <- pure (resolveHandle m2 h2)
  case keyBytesOf ost2 of
    Just mat2 -> assertEqual "minimal length" 20 (BS.length mat2)
    Nothing -> assertFailure "generated key lacks material"
  mapM_ (refuseLen m2 st) [0, 19, 256]
  case planGenerateKey defaultRules m2 st wtlsPremasterKeyGenMech
      (BS.singleton 1) [a | a@(t, _) <- premasterTmpl 32, t /= AttrValueLen] of
    KeyDenied deny -> assertEqual "missing length code"
      CKR_TEMPLATE_INCOMPLETE (kdCode deny)
    other -> assertFailure ("missing length must refuse: " ++ show other)
  mapM_ (refuseParams m2 st) [BS.empty, BS.pack [1, 2]]
  where
    refuseLen m st n =
      case planGenerateKey defaultRules m st wtlsPremasterKeyGenMech
          (BS.singleton 1) (premasterTmpl n) of
        KeyDenied deny -> assertEqual ("length code " ++ show n)
          CKR_TEMPLATE_INCONSISTENT (kdCode deny)
        other -> assertFailure
          ("length " ++ show n ++ " must refuse: " ++ show other)
    refuseParams m st params =
      case planGenerateKey defaultRules m st wtlsPremasterKeyGenMech
          params (premasterTmpl 32) of
        KeyDenied deny -> assertEqual ("params code " ++ show params)
          CKR_MECHANISM_PARAM_INVALID (kdCode deny)
        other -> assertFailure
          ("params " ++ show params ++ " must refuse: " ++ show other)

-- | Generate one pre-master key through the planner + synthetic backend.
genPremasterKey :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genPremasterKey answer m st mech params tmpl =
  case planGenerateKey defaultRules m st mech params tmpl of
    KeyEffect pw fx -> do
      res <- answer m fx
      c <- finishCommit m st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m (pcDelta c))
      pure (m', h)
    other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

premasterTmpl :: Int -> [(AttributeType, AttributeValue)]
premasterTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrSign, ValBool True)
  ]

-- | PBKD2 keygen (slice 11b): the v2 frame carries the password
-- inline and the planner mints deterministic generic-secret
-- material through the synthetic backend.
casePbkd2Keygen :: IO ()
casePbkd2Keygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let mech = MechanismId ckm_PKCS5_PBKD2
      frame = encodePbkd2Params 4 4096 "salt" "password"
  (m1, h) <- genPremasterKey answer m0 st mech frame (premasterTmpl 32)
  Just ost <- pure (resolveHandle m1 h)
  mat1 <- case keyBytesOf ost of
    Just mat -> do
      assertEqual "derived length" 32 (BS.length mat)
      pure mat
    Nothing -> assertFailure "generated key lacks material" >> undefined
  (m2, h2) <- genPremasterKey answer m1 st mech frame (premasterTmpl 32)
  Just ost2 <- pure (resolveHandle m2 h2)
  case keyBytesOf ost2 of
    Just mat2 -> assertEqual "deterministic material" mat1 mat2
    Nothing -> assertFailure "generated key lacks material"
  -- Typed secret targets (fast r46 `test_derive_aes_key`): AES-256
  -- plans and mints 32 bytes stamped CKK_AES; off-domain AES
  -- lengths refuse. DES3/XTS serve their fixed domains; unlisted
  -- types refuse closed.
  (mAes, hAes) <- genPremasterKey answer m2 st mech frame (aesTmpl 32)
  Just ostAes <- pure (resolveHandle mAes hAes)
  assertEqual "aes keytype" (Just (ValULong ckkAes))
    (Map.lookup AttrKeyType (osAttrs ostAes))
  case keyBytesOf ostAes of
    Just matAes -> assertEqual "aes length" 32 (BS.length matAes)
    Nothing -> assertFailure "AES target lacks material"
  case planGenerateKey defaultRules mAes st mech frame (aesTmpl 20) of
    KeyDenied deny -> assertEqual "aes-20 code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("AES-20 must refuse: " ++ show other)
  case planGenerateKey defaultRules mAes st mech frame (typedTmpl ckkDes3 24) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("DES3-24 must plan: " ++ show (voidFx other))
  case planGenerateKey defaultRules mAes st mech frame (typedTmpl ckkAesXts 64) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("XTS-64 must plan: " ++ show (voidFx other))
  case planGenerateKey defaultRules mAes st mech frame (typedTmpl ckkSha256Hmac 32) of
    KeyDenied deny -> assertEqual "hmac code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("HMAC target must refuse: " ++ show (voidFx other))
  -- A missing length refuses; zero and over-ceiling refuse.
  case planGenerateKey defaultRules m2 st mech frame
      [a | a@(t, _) <- premasterTmpl 32, t /= AttrValueLen] of
    KeyDenied deny -> assertEqual "missing length code"
      CKR_TEMPLATE_INCOMPLETE (kdCode deny)
    other -> assertFailure ("missing length must refuse: " ++ show other)
  mapM_ (refuseLen m2 st mech frame) [0, maxDerivedTotal + 1]
  -- Malformed frames refuse with the parameter code.
  mapM_ (refuseParams m2 st mech)
    [ BS.empty
    , BS.take 30 frame
    , encodePbkd2Params 4 0 "salt" "password"
    , encodePbkd2Params 4 (maxPbkd2Iters + 1) "salt" "password"
    , encodePbkd2Params 99 1 "salt" "password"
    ]
  where
    refuseLen m st mech frame n =
      case planGenerateKey defaultRules m st mech frame (premasterTmpl n) of
        KeyDenied deny -> assertEqual ("length code " ++ show n)
          CKR_TEMPLATE_INCONSISTENT (kdCode deny)
        other -> assertFailure
          ("length " ++ show n ++ " must refuse: " ++ show other)
    refuseParams m st mech params =
      case planGenerateKey defaultRules m st mech params (premasterTmpl 32) of
        KeyDenied deny -> assertEqual ("params code " ++ show params)
          CKR_MECHANISM_PARAM_INVALID (kdCode deny)
        other -> assertFailure
          ("params " ++ show params ++ " must refuse: " ++ show other)
    typedTmpl :: Word64 -> Int -> [(AttributeType, AttributeValue)]
    typedTmpl k n =
      [ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong k)
      , (AttrValueLen, ValULong (fromIntegral n))
      , (AttrToken, ValBool False)
      ]
    voidFx :: KeyPlan -> String
    voidFx (KeyDenied deny) = "denied: " ++ show (kdCode deny)
    voidFx (KeyImmediate _) = "immediate"
    voidFx (KeyEffect _ _) = "effect"

caseAesKeygenEncapsulate :: IO ()
caseAesKeygenEncapsulate = withSynth $ \_answer -> do
  m0 <- seedModel
  st <- getSession m0
  case planGenerateKey defaultRules m0 st aesKeyGenMech BS.empty (aesTmpl 16 ++
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

-- | The stored form of a @CKA_ALLOWED_MECHANISMS@ list: packed
-- little-endian mechanism ids.
allowedList :: [MechanismId] -> AttributeValue
allowedList mechs = ValBytes (BS.concat (map (le64 . unMechanismId) mechs))
  where
    le64 :: Word64 -> ByteString
    le64 w = BS.pack
      [ fromIntegral ((w `shiftR` s) .&. 0xFF) | s <- [0, 8 .. 56] ]

-- | The derive base and the concat-key aux refuse a mechanism
-- outside their allowed list; a listed mechanism still derives.
caseDeriveAllowedMechanisms :: IO ()
caseDeriveAllowedMechanisms = do
  m0 <- seedModel
  st <- getSession m0
  let openTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        , (AttrSensitive, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
      listed = allowedList [extractMech]
      otherList = allowedList [hmacSha256Mech]
  (m1, listedH) <- plantKey m0 st
    (openTmpl ++ [(AttrAllowedMechanisms, listed)]) (BS.pack [0 .. 31])
  (m2, otherH) <- plantKey m1 st
    (openTmpl ++ [(AttrAllowedMechanisms, otherList)]) (BS.pack [32 .. 63])
  (m3, listedAuxH) <- plantKey m2 st
    (openTmpl ++ [(AttrAllowedMechanisms, allowedList [concatKeyMech])])
    (BS.pack [64 .. 95])
  (m4, otherAuxH) <- plantKey m3 st
    (openTmpl ++ [(AttrAllowedMechanisms, otherList)]) (BS.pack [96 .. 127])
  (m5, concatBaseH) <- plantKey m4 st
    (openTmpl ++ [(AttrAllowedMechanisms, allowedList [concatKeyMech])])
    (BS.pack [128 .. 159])
  (m6, ikeBaseH) <- plantKey m5 st
    (openTmpl ++ [(AttrAllowedMechanisms, allowedList [ike1Mech])])
    (BS.pack [160 .. 191])
  (m7, ikeAuxListedH) <- plantKey m6 st
    (openTmpl ++ [(AttrAllowedMechanisms, allowedList [ike1Mech])])
    (BS.pack [192 .. 223])
  let kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      plans label mech base frame tmpl =
        case planDerive defaultRules m7 st mech base (encodeDeriveParams frame [tmpl]) of
          KeyEffect _ (FxDerive _ _ _ _ _ got) -> pure got
          other -> assertFailure (label ++ " must plan, got: " ++ show other) >> undefined
      refuses label mech base frame tmpl =
        case planDerive defaultRules m7 st mech base (encodeDeriveParams frame [tmpl]) of
          KeyDenied (KeyDeny code _) ->
            assertEqual label CKR_KEY_FUNCTION_NOT_PERMITTED code
          other -> assertFailure (label ++ " must deny, got: " ++ show other)
      fExt = encodeByteOpsParams 0 0 BS.empty
  refuses "unlisted base extract" extractMech otherH fExt (kid 1)
  _ <- plans "listed base extract" extractMech listedH fExt (kid 1)
  let listedAuxN = fromIntegral (unExternalHandle listedAuxH)
      otherAuxN = fromIntegral (unExternalHandle otherAuxH)
      ikeAuxListedN = fromIntegral (unExternalHandle ikeAuxListedH)
  refuses "unlisted aux concat-key" concatKeyMech concatBaseH
    (encodeByteOpsParams otherAuxN 0 BS.empty) (kid 64)
  _ <- plans "listed aux concat-key" concatKeyMech concatBaseH
    (encodeByteOpsParams listedAuxN 0 BS.empty) (kid 64)
  refuses "unlisted aux IKEv1-PRF" ike1Mech ikeBaseH
    (encodeIkeParams 4 0 7 otherAuxN ikeNi ikeNr) (kid 32)
  _ <- plans "listed aux IKEv1-PRF" ike1Mech ikeBaseH
    (encodeIkeParams 4 0 7 ikeAuxListedN ikeNi ikeNr) (kid 32)
  pure ()

-- | Derived DES-family material takes FIPS 46-3 odd-parity
-- adjustment at finish, on every derive mechanism (the planner
-- is type-driven, not mechanism-driven): 0x00 (upper seven all
-- zero) sets the low bit, 0xFF (upper seven all one) clears it.
caseDeriveDesParity :: IO ()
caseDeriveDesParity = do
  m0 <- seedModel
  st <- getSession m0
  assertBool "DES needs parity" (derivedNeedsParity desAttrs)
  assertBool "generic skips parity" (not (derivedNeedsParity genericAttrs))
  mapM_ (\(tag, kty, n) ->
    mapM_ (\(vtag, inp, want) -> do
      let po = pendingFromAttrs st (Map.fromList
            [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong kty)
            , (AttrToken, ValBool False)])
      case finishWork m0 st (PwDerive [po] [n]) (GotBytes inp) of
        Immediate c -> case [a | DeltaCreateObjectFull _ a _ _ <- opsOf c] of
          [stored] -> assertEqual ("stored " ++ tag ++ " " ++ vtag)
            (Just (ValBytes want)) (Map.lookup AttrValue stored)
          _ -> assertFailure ("arity " ++ tag ++ " " ++ vtag)
        other -> assertFailure ("finish " ++ tag ++ " " ++ vtag ++ ": " ++ show other))
      [ ("zeros", BS.replicate n 0x00, BS.replicate n 0x01)
      , ("ones", BS.replicate n 0xFF, BS.replicate n 0xFE)
      ])
    [ ("DES", ckkDes, 8), ("DES2", ckkDes2, 16)
    , ("DES3", ckkDes3, 24), ("CDMF", ckkCdmf, 8)
    ]
  -- A mixed vector distinguishes real parity adjustment from a
  -- blanket xor (0x02/0x73/0xFE already hold odd parity and stay).
  let mixedIn = BS.pack [0x00, 0x01, 0x02, 0x03, 0x72, 0x73, 0xFE, 0xFF]
      mixedWant = BS.pack [0x01, 0x01, 0x02, 0x02, 0x73, 0x73, 0xFE, 0xFE]
      poDes = pendingFromAttrs st (Map.fromList
        [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkDes)
        , (AttrToken, ValBool False)])
  case finishWork m0 st (PwDerive [poDes] [8]) (GotBytes mixedIn) of
    Immediate c -> case [a | DeltaCreateObjectFull _ a _ _ <- opsOf c] of
      [stored] -> assertEqual "stored DES mixed"
        (Just (ValBytes mixedWant)) (Map.lookup AttrValue stored)
      _ -> assertFailure "mixed arity"
    other -> assertFailure ("mixed finish: " ++ show other)
  where
    desAttrs = Map.fromList [(AttrKeyType, ValULong ckkDes)]
    genericAttrs = Map.fromList [(AttrKeyType, ValULong ckkGenericSecret)]
    opsOf c = case pcDelta c of StateDelta ops -> ops

-- | A multi-object derive adjusts only the DES-family slice;
-- the generic slice passes through byte-equal.
caseDeriveGenericPassthrough :: IO ()
caseDeriveGenericPassthrough = do
  m0 <- seedModel
  st <- getSession m0
  let mkPo kty = pendingFromAttrs st (Map.fromList
        [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong kty)
        , (AttrToken, ValBool False)])
      desIn = BS.replicate 8 0x00
      genIn = BS.pack [0 .. 31]
  case finishWork m0 st (PwDerive [mkPo ckkDes, mkPo ckkGenericSecret] [8, 32])
       (GotBytes (desIn <> genIn)) of
    Immediate c -> case [a | DeltaCreateObjectFull _ a _ _ <- opsOf c] of
      [dStored, gStored] -> do
        assertEqual "DES slice adjusted"
          (Just (ValBytes (BS.replicate 8 0x01))) (Map.lookup AttrValue dStored)
        assertEqual "generic slice untouched"
          (Just (ValBytes genIn)) (Map.lookup AttrValue gStored)
      _ -> assertFailure "passthrough arity"
    other -> assertFailure ("passthrough finish: " ++ show other)
  where
    opsOf c = case pcDelta c of StateDelta ops -> ops

-- | Key-material derives adjust DES-family key slices; the IV
-- byte outputs pass through untouched (IVs are bytes, never keys).
caseDeriveKeymatParity :: IO ()
caseDeriveKeymatParity = do
  m0 <- seedModel
  st <- getSession m0
  let po = pendingFromAttrs st (Map.fromList
        [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkDes)
        , (AttrToken, ValBool False)])
      keyIn = BS.replicate 8 0x00
      ivC = BS.pack [0x10, 0x20, 0x30, 0x40]
      ivS = BS.pack [0x50, 0x60, 0x70, 0x80]
  case finishWork m0 st (PwDeriveIv [po] [8] (4, 4))
       (GotBytes (keyIn <> ivC <> ivS)) of
    Immediate c -> do
      case [a | DeltaCreateObjectFull _ a _ _ <- opsOf c] of
        [stored] -> assertEqual "keymat DES slice adjusted"
          (Just (ValBytes (BS.replicate 8 0x01))) (Map.lookup AttrValue stored)
        _ -> assertFailure "keymat arity"
      case pcOutputs c of
        [NativeOutput (RegionHandle "key") _, NativeOutput (RegionBytes "iv-client" _) c',
         NativeOutput (RegionBytes "iv-server" _) s'] -> do
          assertEqual "client IV untouched" ivC c'
          assertEqual "server IV untouched" ivS s'
        o -> assertFailure ("keymat outputs: " ++ show o)
    other -> assertFailure ("keymat finish: " ++ show other)
  where
    opsOf c = case pcDelta c of StateDelta ops -> ops

-- | The wrapping key (secret, RSA and EC-composition rows) and the
-- unwrapping key refuse a mechanism outside their allowed list; a
-- listed mechanism still plans.
caseWrapAllowedMechanisms :: IO ()
caseWrapAllowedMechanisms = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let otherList = allowedList [aesCbcMech]
      kwTmpl extra = aesTmpl 32 ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)] ++ extra
  (m1, kwListedH) <- genAesKey answer m0 st
    (kwTmpl [(AttrAllowedMechanisms, allowedList [aesKwMech])])
  (m2, kwOtherH) <- genAesKey answer m1 st (kwTmpl [(AttrAllowedMechanisms, otherList)])
  (m3, targetH) <- genAesKey answer m2 st (aesTmpl 16)
  let unwrapTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
      refusesWrap label mech wrapH =
        case planWrapKey m3 st mech BS.empty wrapH targetH IntentNull of
          KeyDenied (KeyDeny code _) ->
            assertEqual label CKR_KEY_FUNCTION_NOT_PERMITTED code
          other -> assertFailure (label ++ " must deny, got: " ++ show other)
      plansWrap label mech wrapH =
        case planWrapKey m3 st mech BS.empty wrapH targetH IntentNull of
          KeyDenied deny -> assertFailure (label ++ " must plan, got: " ++ show deny)
          _ -> pure ()
      refusesUnwrap label mech wrapH blob =
        case planUnwrapKey defaultRules m3 st mech BS.empty wrapH blob unwrapTmpl of
          KeyDenied (KeyDeny code _) ->
            assertEqual label CKR_KEY_FUNCTION_NOT_PERMITTED code
          other -> assertFailure (label ++ " must deny, got: " ++ show other)
      plansUnwrap label mech wrapH blob =
        case planUnwrapKey defaultRules m3 st mech BS.empty wrapH blob unwrapTmpl of
          KeyDenied deny -> assertFailure (label ++ " must plan, got: " ++ show deny)
          _ -> pure ()
  refusesWrap "unlisted AES wrap" aesKwMech kwOtherH
  plansWrap "listed AES wrap" aesKwMech kwListedH
  refusesUnwrap "unlisted AES unwrap" aesKwMech kwOtherH (BS.replicate 24 0)
  plansUnwrap "listed AES unwrap" aesKwMech kwListedH (BS.replicate 24 0)
  -- RSA row: OAEP wrap takes the public half, unwrap the private.
  let oaep = encodeOaepParams "SHA256" "SHA256" BS.empty
      rsaPubListed = rsaPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True), (AttrAllowedMechanisms, allowedList [rsaOaepMech])]
      rsaPrivListed = rsaPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True), (AttrAllowedMechanisms, allowedList [rsaOaepMech])]
      rsaPubOther = rsaPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True), (AttrAllowedMechanisms, otherList)]
      rsaPrivOther = rsaPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True), (AttrAllowedMechanisms, otherList)]
  (m4, rsaPubListedH, rsaPrivListedH) <- genRsaPair answer m3 st rsaPubListed rsaPrivListed
  (m5, rsaPubOtherH, rsaPrivOtherH) <- genRsaPair answer m4 st rsaPubOther rsaPrivOther
  let refusesRsaWrap label wrapH =
        case planWrapKey m5 st rsaOaepMech oaep wrapH targetH IntentNull of
          KeyDenied (KeyDeny code _) ->
            assertEqual label CKR_KEY_FUNCTION_NOT_PERMITTED code
          other -> assertFailure (label ++ " must deny, got: " ++ show other)
      plansRsaWrap label wrapH =
        case planWrapKey m5 st rsaOaepMech oaep wrapH targetH IntentNull of
          KeyDenied deny -> assertFailure (label ++ " must plan, got: " ++ show deny)
          _ -> pure ()
      refusesRsaUnwrap label wrapH =
        case planUnwrapKey defaultRules m5 st rsaOaepMech oaep wrapH (BS.replicate 256 0) unwrapTmpl of
          KeyDenied (KeyDeny code _) ->
            assertEqual label CKR_KEY_FUNCTION_NOT_PERMITTED code
          other -> assertFailure (label ++ " must deny, got: " ++ show other)
      plansRsaUnwrap label wrapH =
        case planUnwrapKey defaultRules m5 st rsaOaepMech oaep wrapH (BS.replicate 256 0) unwrapTmpl of
          KeyDenied deny -> assertFailure (label ++ " must plan, got: " ++ show deny)
          _ -> pure ()
  refusesRsaWrap "unlisted RSA wrap" rsaPubOtherH
  plansRsaWrap "listed RSA wrap" rsaPubListedH
  refusesRsaUnwrap "unlisted RSA unwrap" rsaPrivOtherH
  plansRsaUnwrap "listed RSA unwrap" rsaPrivListedH
  -- EC-composition row: wrap takes the public half, unwrap the private.
  let compParams = encodeWrapCompEcdhParams 0 BS.empty 128
      ecPubListed = ecPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True), (AttrAllowedMechanisms, allowedList [ecdhAesKwMech])]
      ecPrivListed = ecPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True), (AttrAllowedMechanisms, allowedList [ecdhAesKwMech])]
      ecPubOther = ecPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True), (AttrAllowedMechanisms, otherList)]
      ecPrivOther = ecPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True), (AttrAllowedMechanisms, otherList)]
      genEcPair m pubT privT =
        case planGenerateKeyPair defaultRules m st ecKeyPairGenMech pubT privT of
          KeyEffect pw fx -> do
            res <- answer m fx
            c <- finishCommit m st pw res 2
            pub <- handleOf (pcOutputs c !! 0)
            priv <- handleOf (pcOutputs c !! 1)
            m' <- expectRight (publishDelta m (pcDelta c))
            pure (m', pub, priv)
          other -> assertFailure ("EC keypair plan is not an effect: " ++ show other) >> undefined
  (m6, ecPubListedH, ecPrivListedH) <- genEcPair m5 ecPubListed ecPrivListed
  (m7, ecPubOtherH, ecPrivOtherH) <- genEcPair m6 ecPubOther ecPrivOther
  let refusesEcWrap label wrapH =
        case planWrapKey m7 st ecdhAesKwMech compParams wrapH targetH IntentNull of
          KeyDenied (KeyDeny code _) ->
            assertEqual label CKR_KEY_FUNCTION_NOT_PERMITTED code
          other -> assertFailure (label ++ " must deny, got: " ++ show other)
      plansEcWrap label wrapH =
        case planWrapKey m7 st ecdhAesKwMech compParams wrapH targetH IntentNull of
          KeyDenied deny -> assertFailure (label ++ " must plan, got: " ++ show deny)
          _ -> pure ()
      refusesEcUnwrap label wrapH =
        case planUnwrapKey defaultRules m7 st ecdhAesKwMech compParams wrapH (BS.replicate 93 0) unwrapTmpl of
          KeyDenied (KeyDeny code _) ->
            assertEqual label CKR_KEY_FUNCTION_NOT_PERMITTED code
          other -> assertFailure (label ++ " must deny, got: " ++ show other)
      plansEcUnwrap label wrapH =
        case planUnwrapKey defaultRules m7 st ecdhAesKwMech compParams wrapH (BS.replicate 93 0) unwrapTmpl of
          KeyDenied deny -> assertFailure (label ++ " must plan, got: " ++ show deny)
          _ -> pure ()
  refusesEcWrap "unlisted EC-comp wrap" ecPubOtherH
  plansEcWrap "listed EC-comp wrap" ecPubListedH
  refusesEcUnwrap "unlisted EC-comp unwrap" ecPrivOtherH
  plansEcUnwrap "listed EC-comp unwrap" ecPrivListedH
  pure ()

-- | The KEM encapsulate and decapsulate keys refuse a mechanism
-- outside their allowed list; a listed mechanism still plans.
caseKemAllowedMechanisms :: IO ()
caseKemAllowedMechanisms = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let otherList = allowedList [aesCbcMech]
      listed = allowedList [mlKemMech]
      genPair m pubT privT =
        case planGenerateKeyPair defaultRules m st mlKemKeyPairGenMech pubT privT of
          KeyEffect pw fx -> do
            res <- answer m fx
            c <- finishCommit m st pw res 2
            pub <- handleOf (pcOutputs c !! 0)
            priv <- handleOf (pcOutputs c !! 1)
            m' <- expectRight (publishDelta m (pcDelta c))
            pure (m', pub, priv)
          other -> assertFailure ("KEM keypair plan is not an effect: " ++ show other) >> undefined
  (m1, pubListedH, privListedH) <- genPair m0
    (kemPubTmpl ++ [(AttrAllowedMechanisms, listed)])
    (kemPrivTmpl ++ [(AttrAllowedMechanisms, listed)])
  (m2, pubOtherH, privOtherH) <- genPair m1
    (kemPubTmpl ++ [(AttrAllowedMechanisms, otherList)])
    (kemPrivTmpl ++ [(AttrAllowedMechanisms, otherList)])
  let ctLen = kemCtLen KemMl768
      intent = IntentBuffer (fromIntegral ctLen)
  case planKemEncaps m2 st mlKemMech pubOtherH KemMl768 secretTmpl intent of
    KeyDenied (KeyDeny code _) ->
      assertEqual "unlisted encaps" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("unlisted encaps must deny, got: " ++ show other)
  ct <- case planKemEncaps m2 st mlKemMech pubListedH KemMl768 secretTmpl intent of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      case pcOutputs c of
        (NativeOutput (RegionBytes "ciphertext" _) ct0 : _) -> pure ct0
        _ -> assertFailure "no ciphertext output" >> undefined
    other -> assertFailure ("listed encaps must plan, got: " ++ show other) >> undefined
  case planKemDecaps m2 st mlKemMech privOtherH KemMl768 ct secretTmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "unlisted decaps" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("unlisted decaps must deny, got: " ++ show other)
  case planKemDecaps m2 st mlKemMech privListedH KemMl768 ct secretTmpl of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("listed decaps must plan, got: " ++ show other)

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
genKeyWith answer m st mech tmpl = case planGenerateKey defaultRules m st mech BS.empty tmpl of
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
  let plan n = planGenerateKey defaultRules m1 st genericSecretKeyGenMech BS.empty (genericTmpl n)
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
  case planGenerateKey defaultRules m1 st genericSecretKeyGenMech BS.empty
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
  (m4, legacyH) <- case publishPending m3 st [pendingFromAttrs st legacyAttrs] of
    Left deny -> assertFailure ("plant must publish: " ++ show deny) >> undefined
    Right (delta, [h]) -> do
      m' <- expectRight (publishDelta m3 delta)
      pure (m', h)
    Right _ -> assertFailure "plant must mint one handle" >> undefined
  let env3 = env { oeModel = m4 }
      (_, signLegacy) = initOperation env3 emptySessionOps st (mkSign legacyH)
  assertEqual "untyped legacy key skips matrix" CKR_OK (ioCode signLegacy)

-- | A secret-class object carrying an asymmetric key type (or a
-- public-class object carrying a secret type) refuses at Init
-- with the key-type code on reviewed rows, even with the usage
-- mark set; coherent keys still init.
caseInitClassConfusion :: IO ()
caseInitClassConfusion = withSynth $ \answer -> do
  mSeed <- seedModel
  m0 <- loginUser mSeed
  st <- getSession m0
  let rsaSignMech = MechanismId ckm_SHA256_RSA_PKCS
  (m1, confusedH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkRsa)
    , (AttrToken, ValBool False)
    , (AttrSign, ValBool True)
    ] (BS.pack [0 .. 15])
  (m2, flippedH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrEncrypt, ValBool True)
    ] (BS.pack [0 .. 15])
  (m3, rsaPubH, rsaPrivH) <- genRsaPair answer m2 st
    (rsaPubTmpl ++ [(AttrVerify, ValBool True)])
    (rsaPrivTmpl ++ [(AttrSign, ValBool True)])
  (m4, aesH) <- genAesKey answer m3 st (aesTmpl 16)
  let env = OpEnv
        { oeRegistry = curatedRegistry
        , oeCaps = mkCapabilities
            [ (rsaSignMech, OpSign)
            , (rsaSignMech, OpVerify)
            , (aesCbcMech, OpEncrypt)
            ]
        , oeModel = m4
        }
      mkRsaSign h = InitArgs
        { iaOp = OpSign
        , iaMech = rsaSignMech
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
  let (_, denyConfused) = initOperation env emptySessionOps st (mkRsaSign confusedH)
  assertEqual "secret-class RSA key refuses sign" CKR_KEY_TYPE_INCONSISTENT
    (ioCode denyConfused)
  let (_, denyFlipped) = initOperation env emptySessionOps st (mkEnc flippedH)
  assertEqual "public-class AES key refuses encrypt" CKR_KEY_TYPE_INCONSISTENT
    (ioCode denyFlipped)
  let (_, okRsa) = initOperation env emptySessionOps st (mkRsaSign rsaPrivH)
  assertEqual "RSA private key signs" CKR_OK (ioCode okRsa)
  let (_, okAes) = initOperation env emptySessionOps st (mkEnc aesH)
  assertEqual "AES key encrypts" CKR_OK (ioCode okAes)
  _ <- pure (rsaPubH, m1, m2, m3)
  pure ()

-- | An unwrap template asking for a secret-class object with an
-- asymmetric key type refuses inconsistent; the coherent
-- template over the same blob still plans.
caseUnwrapRefusesAsymmetric :: IO ()
caseUnwrapRefusesAsymmetric = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st
    (aesTmpl 32 ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)])
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  blob <- case planWrapKey m2 st aesKwMech BS.empty wrapH targetH (IntentBuffer 24) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("wrap plan is not an effect: " ++ show other) >> undefined
  let mkTmpl kty =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong kty)
        , (AttrToken, ValBool False)
        ]
  mapM_ (\(tag, kty) ->
    case planUnwrapKey defaultRules m2 st aesKwMech BS.empty wrapH blob (mkTmpl kty) of
      KeyDenied (KeyDeny code _) ->
        assertEqual ("reject code " ++ tag) CKR_TEMPLATE_INCONSISTENT code
      other -> assertFailure ("must deny, got (" ++ tag ++ "): " ++ show other))
    [ ("RSA", ckkRsa)
    , ("EC", ckkEc)
    , ("ML-KEM", ckkMlKem)
    ]
  case planUnwrapKey defaultRules m2 st aesKwMech BS.empty wrapH blob (mkTmpl ckkAes) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("coherent unwrap must plan, got: " ++ show other)

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
  _ <- go m0 [n | (n, _, _, _) <- curveTable]
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
      -- The public half carries the authoritative size; the private
      -- half carries no size, per PKCS#11 3.2 section 6.1.
      assertEqual "modulus bits stamped"
        (Just (ValULong 2048))
        (Map.lookup AttrModulusBits (osAttrs pub))
      assertBool "modulus bits absent (priv)"
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

caseRsaModulusBits :: IO ()
caseRsaModulusBits = withSynth $ \answer -> do
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
  assertEqual "public modulus bits"
    (Just (ValULong 2048))
    (Map.lookup AttrModulusBits (osAttrs pub))
  assertBool "private lacks modulus bits"
    (Map.notMember AttrModulusBits (osAttrs priv))
  case getAttributes (osAttrs pub) [AttrModulusBits] of
    PartialReads code results -> do
      assertEqual "public read code" CKR_OK code
      assertEqual "public read value"
        (Just (ResOk (ValULong 2048)))
        (lookup AttrModulusBits results)
  case getAttributes (osAttrs priv) [AttrModulusBits] of
    PartialReads code _ ->
      assertEqual "private read code" CKR_ATTRIBUTE_TYPE_INVALID code
  -- Pub-from-priv stamps the same size from the SPKI half.
  case (Map.lookup AttrModulus (osAttrs pub), Map.lookup AttrPublicExponent (osAttrs pub)) of
    (Just (ValBytes n), Just (ValBytes e)) -> do
      let po = pendingFromAttrs st (Map.fromList
            [(AttrClass, ValULong ckoPublicKey), (AttrKeyType, ValULong ckkRsa)
            , (AttrToken, ValBool False)])
          spki = rsaPublicDer n e
      case finishWork m1 st (PwDerivePub po ckkRsa) (GotBytes spki) of
        Immediate c -> do
          let StateDelta ops = pcDelta c
          case [a | DeltaCreateObjectFull _ a _ _ <- ops] of
            [stored] -> assertEqual "derived public modulus bits"
              (Just (ValULong 2048)) (Map.lookup AttrModulusBits stored)
            _ -> assertFailure "derived public arity"
        other -> assertFailure ("derived public finish shape: " ++ show other)
    _ -> assertFailure "generated public lacks components"

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

caseX942ParamSizesPlanner :: IO ()
caseX942ParamSizesPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf tmpl =
        case planGenerateKey defaultRules m0 st x9_42DhParameterGenMech BS.empty tmpl of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
  -- Explicit served pairs plan (the DSA frame: the driver
  -- runs the DSA entry point (186-2 at 1024/160, 186-4 above)).
  assertEqual "explicit (1024, 160)" (Right (Just (GenDsaParams 1024 160)))
    (argsOf (x942ParamsTmpl 1024 160))
  assertEqual "explicit (2048, 224)" (Right (Just (GenDsaParams 2048 224)))
    (argsOf (x942ParamsTmpl 2048 224))
  assertEqual "explicit (2048, 256)" (Right (Just (GenDsaParams 2048 256)))
    (argsOf (x942ParamsTmpl 2048 256))
  -- A missing subprime is incomplete (the oracle requires it;
  -- DSA keeps the per-L default).
  assertEqual "missing subprime bits" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf (filter ((/= AttrSubprimeBits) . fst) (x942ParamsTmpl 2048 256)))
  -- The oracle's minimal template (no class, no key type) plans.
  assertEqual "oracle minimal plans" (Right (Just (GenDsaParams 2048 256)))
    (argsOf [(AttrPrimeBits, ValULong 2048), (AttrSubprimeBits, ValULong 256),
             (AttrToken, ValBool False)])
  -- A DSA-typed template contradicts the mechanism.
  assertEqual "DSA key type refused" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (dsaParamsTmpl 1024))
  -- Missing prime bits are incomplete.
  assertEqual "missing prime bits" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)])
  -- Unserved sizes and pairs are inconsistent.
  assertEqual "unserved L" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (x942ParamsTmpl 512 160))
  assertEqual "unserved pair" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (x942ParamsTmpl 2048 160))

caseDhPkcsParamSizesPlanner :: IO ()
caseDhPkcsParamSizesPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf tmpl =
        case planGenerateKey defaultRules m0 st dhPkcsParameterGenMech BS.empty tmpl of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
  -- Explicit served pairs plan (the DSA frame: the driver
  -- runs the DSA entry point (186-2 at 1024/160, 186-4 above),
  -- as for X9.42).
  assertEqual "explicit (1024, 160)" (Right (Just (GenDsaParams 1024 160)))
    (argsOf (dhPkcsParamsTmpl 1024 160))
  assertEqual "explicit (2048, 256)" (Right (Just (GenDsaParams 2048 256)))
    (argsOf (dhPkcsParamsTmpl 2048 256))
  -- A missing subprime defaults from L (the oracle sends
  -- CKA_PRIME_BITS only and expects CKR_OK — unlike X9.42,
  -- which requires the subprime).
  assertEqual "missing subprime defaults" (Right (Just (GenDsaParams 2048 256)))
    (argsOf (filter ((/= AttrSubprimeBits) . fst) (dhPkcsParamsTmpl 2048 256)))
  -- The oracle's minimal template (PRIME_BITS only) plans.
  assertEqual "oracle minimal plans" (Right (Just (GenDsaParams 2048 256)))
    (argsOf [(AttrPrimeBits, ValULong 2048), (AttrToken, ValBool False)])
  -- An X9.42-typed template contradicts the mechanism.
  assertEqual "X9.42 key type refused" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (x942ParamsTmpl 1024 160))
  -- Missing prime bits are incomplete.
  assertEqual "missing prime bits" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)])
  -- Unserved sizes and pairs are inconsistent.
  assertEqual "unserved L" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (dhPkcsParamsTmpl 512 160))
  assertEqual "unserved pair" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (dhPkcsParamsTmpl 2048 160))

caseEcExtraBitsPlanner :: IO ()
caseEcExtraBitsPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf mech = case planGenerateKeyPair defaultRules m0 st mech ecPubTmpl ecPrivTmpl of
        KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
        KeyDenied (KeyDeny code _) -> Left code
        other -> error ("unexpected plan shape: " ++ show other)
  -- The extra-bits mechanism plans exactly like plain EC keygen
  -- (the FIPS 186-5 B.4.2 method is unobservable from outside).
  assertEqual "extra-bits plans like EC"
    (argsOf ecKeyPairGenMech) (argsOf ecExtraBitsKeyPairGenMech)

caseDsaParamSizesPlanner :: IO ()
caseDsaParamSizesPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf tmpl =
        case planGenerateKey defaultRules m0 st dsaParameterGenMech BS.empty tmpl of
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
      assertBool "key carries no prime bits"
        (Map.notMember AttrPrimeBits (poAttrs pub'))
      assertBool "key carries no subprime bits"
        (Map.notMember AttrSubprimeBits (poAttrs pub'))
      assertBool "priv carries no prime bits"
        (Map.notMember AttrPrimeBits (poAttrs priv'))
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

caseDhDomainPlanner :: IO ()
caseDhDomainPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf mech pubT privT =
        case planGenerateKeyPair defaultRules m0 st mech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      dropT t = filter ((/= t) . fst)
      withT tmpl t v = tmpl ++ [(t, v)]
  -- Happy paths frame DER domain params (PKCS#3 without q,
  -- X9.42 with q).
  case argsOf dhKeyPairGenMech dhPubTmpl dhPrivTmpl of
    Right (Just (GenDhKeypair der)) ->
      assertEqual "PKCS#3 round-trips" (Just (dhP, dhG, Nothing)) (parseDhParams der)
    other -> assertFailure ("DH pair must plan: " ++ show other)
  case argsOf x9_42DhKeyPairGenMech dhX942PubTmpl dhX942PrivTmpl of
    Right (Just (GenDhKeypair der)) ->
      assertEqual "X9.42 round-trips" (Just (dhP, dhG, Just dhQ)) (parseDhParams der)
    other -> assertFailure ("X9.42 pair must plan: " ++ show other)
  -- Served size hints alongside the domain are accepted.
  case argsOf dhKeyPairGenMech (withT dhPubTmpl AttrPrimeBits (ValULong 2048)) dhPrivTmpl of
    Right (Just (GenDhKeypair _)) -> pure ()
    other -> assertFailure ("served size hint must plan: " ++ show other)
  -- Missing parameters are incomplete.
  assertEqual "missing base" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf dhKeyPairGenMech (dropT AttrBase dhPubTmpl) dhPrivTmpl)
  assertEqual "missing all" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf dhKeyPairGenMech [(AttrToken, ValBool False)] dhPrivTmpl)
  assertEqual "x942 missing subprime" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf x9_42DhKeyPairGenMech (dropT AttrSubprime dhX942PubTmpl) dhX942PrivTmpl)
  -- The field-size probe shape refuses inconsistent, never incomplete.
  assertEqual "oversized prime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      [(AttrPrimeBits, ValULong 4294968320), (AttrToken, ValBool False)]
      [(AttrToken, ValBool False)])
  assertEqual "unserved prime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech (withT dhPubTmpl AttrPrimeBits (ValULong 512)) dhPrivTmpl)
  assertEqual "unserved subprime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf x9_42DhKeyPairGenMech
      (withT dhX942PubTmpl AttrSubprimeBits (ValULong 128)) dhX942PrivTmpl)
  -- PKCS#3 has no subprime: carrying one is inconsistent.
  assertEqual "pkcs rejects subprime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT dhPubTmpl AttrSubprime (ValBytes dhQ)) dhPrivTmpl)
  -- Crossed key types refuse.
  assertEqual "pkcs mech x942 templates" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech dhX942PubTmpl dhX942PrivTmpl)
  assertEqual "x942 mech pkcs templates" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf x9_42DhKeyPairGenMech dhPubTmpl dhPrivTmpl)
  -- Disagreement, empty, oversized and malformed parts refuse.
  assertEqual "domain disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech dhPubTmpl (withT dhPrivTmpl AttrPrime (ValBytes "other")))
  assertEqual "empty prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime (ValBytes BS.empty)) dhPrivTmpl)
  assertEqual "oversized prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime (ValBytes (BS.replicate 513 1))) dhPrivTmpl)
  assertEqual "malformed prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime (ValULong 7)) dhPrivTmpl)
  -- Private-side agreement plans.
  case argsOf dhKeyPairGenMech dhPubTmpl (dhPrivTmpl ++
      [(AttrPrime, ValBytes dhP), (AttrBase, ValBytes dhG)]) of
    Right (Just (GenDhKeypair _)) -> pure ()
    other -> assertFailure ("agreeing priv domain must plan: " ++ show other)
  -- Structural floor (NIST SP 800-56A rev. 3 section 5.5.1;
  -- the security suite probes prime=1, tiny prime and
  -- generator=0): primes under 512 significant bits and
  -- generators outside 2..p-1 refuse inconsistent, never
  -- incomplete, and never plan.
  assertEqual "prime one" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime (ValBytes "\x01")) dhPrivTmpl)
  assertEqual "tiny prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime (ValBytes "\x0f")) dhPrivTmpl)
  assertEqual "zero generator" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrBase dhPubTmpl) AttrBase (ValBytes "\x00")) dhPrivTmpl)
  assertEqual "generator one" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrBase dhPubTmpl) AttrBase (ValBytes "\x01")) dhPrivTmpl)
  assertEqual "generator at prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrBase dhPubTmpl) AttrBase (ValBytes dhP)) dhPrivTmpl)
  assertEqual "short prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime
        (ValBytes (BS.pack (0x80 : replicate 62 1)))) dhPrivTmpl)
  assertEqual "zero-padded tiny prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime
        (ValBytes (BS.replicate 63 0 <> "\x0f"))) dhPrivTmpl)
  case argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime
        (ValBytes (BS.pack (0x80 : replicate 63 1)))) dhPrivTmpl of
    Right (Just (GenDhKeypair _)) -> pure ()
    other -> assertFailure ("512-bit floor prime must plan: " ++ show other)
  assertEqual "x942 generator above prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf x9_42DhKeyPairGenMech
      (withT (dropT AttrBase dhX942PubTmpl) AttrBase (ValBytes (dhP <> "\x01")))
      dhX942PrivTmpl)
  assertEqual "x942 subprime one" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf x9_42DhKeyPairGenMech
      (withT (dropT AttrSubprime dhX942PubTmpl) AttrSubprime (ValBytes "\x01"))
      dhX942PrivTmpl)

caseDhGenArgsCodec :: IO ()
caseDhGenArgsCodec = do
  let rt args = assertEqual ("round-trip " ++ show args) (Just args)
        (decodeGenArgs (encodeGenArgs args))
  rt (GenDhKeypair (dhParamsDer dhP dhG))
  rt (GenDhKeypair (dhParamsDerQ dhP dhG dhQ))
  -- Tag byte is pinned (10 DH keypair domain DER).
  assertEqual "keypair tag" (Just 10)
    (fst <$> BS.uncons (encodeGenArgs (GenDhKeypair "d")))
  -- Short frames, trailing bytes, empty DER and unknown tags fail.
  assertEqual "short keypair" Nothing (decodeGenArgs (BS.pack [10, 0, 0]))
  assertEqual "keypair trailing" Nothing
    (decodeGenArgs (encodeGenArgs (GenDhKeypair "der") <> "x"))
  assertEqual "empty keypair DER" Nothing
    (decodeGenArgs (BS.pack [10, 0, 0, 0, 0]))
  assertEqual "unknown tag" Nothing (decodeGenArgs (BS.pack [11, 1, 2, 3]))

caseDhCompatible :: IO ()
caseDhCompatible = do
  m0 <- seedModel
  st <- getSession m0
  let pub = pendingFromAttrs st (Map.fromList dhPubTmpl)
      priv = pendingFromAttrs st (Map.fromList dhPrivTmpl)
      params = pendingFromAttrs st (Map.fromList (dsaParamsTmpl 2048))
      fx args = FxGenerateKey dhKeyPairGenMech BS.empty (encodeGenArgs args)
      fxP args = FxGenerateKey dsaParameterGenMech BS.empty (encodeGenArgs args)
      der = dhParamsDer dhP dhG
  assertBool "pair/keypair cohere"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenDhKeypair der)))
  assertBool "single/keypair incoherent"
    (not (keyPairCompatible (PwGenerateKey params) (fx (GenDhKeypair der))))
  assertBool "pair/params incoherent"
    (not (keyPairCompatible (PwGeneratePair pub priv) (fxP (GenDsaParams 2048 256))))

caseDhStamp :: IO ()
caseDhStamp = do
  m0 <- seedModel
  st <- getSession m0
  let y = BS.pack (0x60 : replicate 255 4)
      x = BS.pack (0x07 : replicate 31 5)
      pubM = dhPublicDer dhP dhG y
      privM = dhPrivateDer dhP dhG x
      privM2 = dhPrivateDer dhQ dhG x
      pubX = dhPublicDerQ dhP dhG dhQ y
      privX = dhPrivateDerQ dhP dhG dhQ x
      pub = pendingFromAttrs st (Map.fromList dhPubTmpl)
      priv = pendingFromAttrs st (Map.fromList dhPrivTmpl)
      pub9 = pendingFromAttrs st (Map.fromList dhX942PubTmpl)
      priv9 = pendingFromAttrs st (Map.fromList dhX942PrivTmpl)
  case stampPairComponents pub priv pubM privM of
    Just (pub', priv') -> do
      assertEqual "prime stamped"
        (Just (ValBytes dhP)) (Map.lookup AttrPrime (poAttrs pub'))
      assertEqual "base stamped"
        (Just (ValBytes dhG)) (Map.lookup AttrBase (poAttrs pub'))
      assertEqual "no subprime stamped"
        Nothing (Map.lookup AttrSubprime (poAttrs pub'))
      assertEqual "priv inherits prime"
        (Just (ValBytes dhP)) (Map.lookup AttrPrime (poAttrs priv'))
      assertEqual "priv inherits base"
        (Just (ValBytes dhG)) (Map.lookup AttrBase (poAttrs priv'))
      assertBool "key carries no prime bits"
        (Map.notMember AttrPrimeBits (poAttrs pub'))
      assertBool "priv carries no prime bits"
        (Map.notMember AttrPrimeBits (poAttrs priv'))
    Nothing -> assertFailure "matching DH halves must stamp"
  case stampPairComponents pub9 priv9 pubX privX of
    Just (pub', _) ->
      assertEqual "x942 subprime stamped"
        (Just (ValBytes dhQ)) (Map.lookup AttrSubprime (poAttrs pub'))
    Nothing -> assertFailure "matching X9.42 halves must stamp"
  -- Disagreeing and opaque halves pass through unstamped.
  assertEqual "mismatched halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv pubM privM2)
  assertEqual "opaque halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv "HKS1pub" "HKS1priv")

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

caseMontgomeryGenArgsCodec :: IO ()
caseMontgomeryGenArgsCodec = do
  let rt args = assertEqual ("round-trip " ++ show args) (Just args)
        (decodeGenArgs (encodeGenArgs args))
  rt (GenMontgomeryKeypair "X25519")
  rt (GenMontgomeryKeypair "X448")
  -- Tag byte is pinned (15 Montgomery keypair curve name).
  assertEqual "keypair tag" (Just 15)
    (fst <$> BS.uncons (encodeGenArgs (GenMontgomeryKeypair "X25519")))
  -- Short frames and empty names fail.
  assertEqual "short keypair" Nothing (decodeGenArgs (BS.singleton 15))
  assertEqual "unknown tag" Nothing (decodeGenArgs (BS.pack [16, 1, 2, 3]))

caseMontgomeryPairPlanner :: IO ()
caseMontgomeryPairPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf pubT privT =
        case planGenerateKeyPair defaultRules m0 st montgomeryKeyPairGenMech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      dropT t = filter ((/= t) . fst)
      withT tmpl t v = tmpl ++ [(t, v)]
      setParams tmpl curve =
        withT (dropT AttrEcParams tmpl) AttrEcParams (ValBytes curve)
  -- Happy path frames the curve name (both curves).
  case argsOf xdPubTmpl xdPrivTmpl of
    Right (Just (GenMontgomeryKeypair "X25519")) -> pure ()
    other -> assertFailure ("X25519 pair must plan: " ++ show other)
  case argsOf (setParams xdPubTmpl "X448") xdPrivTmpl of
    Right (Just (GenMontgomeryKeypair "X448")) -> pure ()
    other -> assertFailure ("X448 pair must plan: " ++ show other)
  -- Missing curve is incomplete.
  assertEqual "missing params" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf (dropT AttrEcParams xdPubTmpl) xdPrivTmpl)
  assertEqual "missing all" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)] xdPrivTmpl)
  -- Foreign curves refuse mechanism-invalid (the Edwards
  -- precedent), never incomplete: the template names a curve
  -- the mechanism cannot serve.
  assertEqual "weierstrass refused" (Left CKR_MECHANISM_INVALID)
    (argsOf (setParams xdPubTmpl "P-256") xdPrivTmpl)
  assertEqual "edwards refused" (Left CKR_MECHANISM_INVALID)
    (argsOf (setParams xdPubTmpl "Ed25519") xdPrivTmpl)
  assertEqual "garbage refused" (Left CKR_MECHANISM_INVALID)
    (argsOf (setParams xdPubTmpl "nope") xdPrivTmpl)
  -- Disagreement and malformed parts refuse inconsistent.
  assertEqual "curve disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf xdPubTmpl (withT xdPrivTmpl AttrEcParams (ValBytes "X448")))
  assertEqual "malformed params" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrEcParams xdPubTmpl) AttrEcParams (ValULong 7)) xdPrivTmpl)
  assertEqual "malformed priv params" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf xdPubTmpl (withT xdPrivTmpl AttrEcParams (ValULong 7)))
  -- Private-side agreement plans; key-type contradiction refuses.
  case argsOf xdPubTmpl (withT xdPrivTmpl AttrEcParams (ValBytes "X25519")) of
    Right (Just (GenMontgomeryKeypair "X25519")) -> pure ()
    other -> assertFailure ("agreeing priv curve must plan: " ++ show other)
  assertEqual "key-type contradiction" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrKeyType xdPubTmpl) AttrKeyType (ValULong ckkEc)) xdPrivTmpl)

caseMontgomeryCompatible :: IO ()
caseMontgomeryCompatible = do
  m0 <- seedModel
  st <- getSession m0
  let pub = pendingFromAttrs st (Map.fromList xdPubTmpl)
      priv = pendingFromAttrs st (Map.fromList xdPrivTmpl)
      fx args = FxGenerateKey montgomeryKeyPairGenMech BS.empty (encodeGenArgs args)
  assertBool "pair/montgomery cohere"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenMontgomeryKeypair "X25519")))
  assertBool "single/montgomery incoherent"
    (not (keyPairCompatible (PwGenerateKey pub) (fx (GenMontgomeryKeypair "X25519"))))
  -- Coherence is shape-level: any pair-shaped args cohere with a pair.
  assertBool "pair/RSA coherent"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenRsa 2048 65537)))
  assertBool "pair/AES incoherent"
    (not (keyPairCompatible (PwGeneratePair pub priv) (fx (GenAes 16))))

caseMontgomeryStamp :: IO ()
caseMontgomeryStamp = do
  m0 <- seedModel
  st <- getSession m0
  let pubM = montgomeryPublicDer x19OidBytes xPoint19
      privM = montgomeryPrivateDer x19OidBytes xScalar19
      privM48 = montgomeryPrivateDer x48OidBytes (BS.replicate 56 9)
      pub = pendingFromAttrs st (Map.fromList xdPubTmpl)
      priv = pendingFromAttrs st (Map.fromList xdPrivTmpl)
  case stampPairComponents pub priv pubM privM of
    Just (pub', priv') -> do
      assertEqual "point stamped raw"
        (Just (ValBytes xPoint19)) (Map.lookup AttrEcPoint (poAttrs pub'))
      assertEqual "pub params kept"
        (Just (ValBytes "X25519")) (Map.lookup AttrEcParams (poAttrs pub'))
      assertEqual "priv inherits params"
        (Just (ValBytes "X25519")) (Map.lookup AttrEcParams (poAttrs priv'))
    Nothing -> assertFailure "matching Montgomery halves must stamp"
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
  -- private keys the full set, domain parameters none — except
  -- CKA_DERIVE, which defaults FALSE per the PKCS#11 common key
  -- attributes table (derivation is opt-in).
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
        [AttrDecrypt, AttrSign, AttrUnwrap, AttrDecapsulate]
      assertEqual "pub derive defaults false" (Just (ValBool False))
        (Map.lookup AttrDerive attrs)
    Left deny -> assertFailure ("minimal template must check: " ++ show deny)
  case checkKeyTemplate ckoPrivateKey ckkDsa [(AttrClass, ValULong ckoPrivateKey)] of
    Right attrs -> do
      mapM_
        (\t -> assertEqual ("priv default " ++ show t) (Just (ValBool True))
          (Map.lookup t attrs))
        [ AttrEncrypt, AttrDecrypt, AttrSign, AttrVerify
        , AttrWrap, AttrUnwrap
        , AttrEncapsulate, AttrDecapsulate
        ]
      assertEqual "priv derive defaults false" (Just (ValBool False))
        (Map.lookup AttrDerive attrs)
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

caseDeriveDefaultsFalse :: IO ()
caseDeriveDefaultsFalse = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  -- A secret key generated without CKA_DERIVE reads CK_FALSE
  -- (the PKCS#11 common key attributes default), stored and
  -- through the attribute-read plan (visibility + C encoding).
  (m1, secH) <- genAesKey answer m0 st minimalSecret
  assertStoredFalse "secret" m1 secH
  assertReadFalse "secret" m1 st secH
  -- An EC pair generated without CKA_DERIVE: both halves false.
  (m2, ecPubH, ecPrivH) <- genEcPair answer m1 st ecPubTmpl ecPrivTmpl
  assertStoredFalse "ec-pub" m2 ecPubH
  assertStoredFalse "ec-priv" m2 ecPrivH
  assertReadFalse "ec-pub" m2 st ecPubH
  assertReadFalse "ec-priv" m2 st ecPrivH
  -- An RSA pair likewise.
  (m3, rsaPubH, rsaPrivH) <- genRsaPair answer m2 st rsaPubTmpl rsaPrivTmpl
  assertStoredFalse "rsa-pub" m3 rsaPubH
  assertStoredFalse "rsa-priv" m3 rsaPrivH
  assertReadFalse "rsa-pub" m3 st rsaPubH
  assertReadFalse "rsa-priv" m3 st rsaPrivH
  -- An explicit CKA_DERIVE=TRUE still wins, and the key derives.
  (m4, expH) <- genAesKey answer m3 st (minimalSecret ++ [(AttrDerive, ValBool True)])
  Just expOst <- pure (resolveHandle m4 expH)
  assertEqual "explicit true stored" (Just (ValBool True))
    (Map.lookup AttrDerive (osAttrs expOst))
  case planDerive defaultRules m4 st hkdfDeriveMech expH
      (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "info") [childTmpl 32]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("explicit-derive base must plan: " ++ show other)
  -- A derive from a key generated without DERIVE refuses with
  -- CKR_KEY_FUNCTION_NOT_PERMITTED (the resolveBase gate).
  case planDerive defaultRules m4 st hkdfDeriveMech secH
      (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "info") [childTmpl 32]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "default-false code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("default-false base must refuse: " ++ show other)
  -- KEM outputs take the same default: the encaps and decaps
  -- secrets read false.
  (m5, kemPubH, kemPrivH) <- genKemPair answer m4 st
  let ctLen = kemCtLen KemMl768
  (m6, kemSecH, kemCt) <- case planKemEncaps m5 st mlKemMech kemPubH KemMl768 secretTmpl
      (IntentBuffer (fromIntegral ctLen)) of
    KeyEffect pw fx -> do
      res <- answer m5 fx
      c <- finishCommit m5 st pw res 1
      ct <- case pcOutputs c !! 0 of
        NativeOutput (RegionBytes "ciphertext" _) bs -> pure bs
        o -> assertFailure ("kem encaps first output is not the ciphertext: " ++ show o) >> undefined
      h <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m5 (pcDelta c))
      pure (m', h, ct)
    other -> assertFailure ("encaps plan is not an effect: " ++ show other) >> undefined
  assertStoredFalse "kem-secret" m6 kemSecH
  assertReadFalse "kem-secret" m6 st kemSecH
  (m7, kemDecH) <- case planKemDecaps m6 st mlKemMech kemPrivH KemMl768 kemCt secretTmpl of
    KeyEffect pw fx -> do
      res <- answer m6 fx
      c <- finishCommit m6 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m6 (pcDelta c))
      pure (m', h)
    other -> assertFailure ("decaps plan is not an effect: " ++ show other) >> undefined
  assertStoredFalse "kem-decaps-secret" m7 kemDecH
  assertReadFalse "kem-decaps-secret" m7 st kemDecH
  where
    minimalSecret =
      [ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong ckkAes)
      , (AttrValueLen, ValULong 32)
      , (AttrToken, ValBool False)
      ]
    assertStoredFalse tag m h = case resolveHandle m h of
      Nothing -> assertFailure (tag ++ ": handle unpublished") >> undefined
      Just ost -> assertEqual (tag ++ " stored false") (Just (ValBool False))
        (Map.lookup AttrDerive (osAttrs ost))
    assertReadFalse tag m st0 h = case planGetAttributes m st0 h [AttrDerive] of
      Immediate c -> case pcOutputs c of
        [o] -> do
          assertEqual (tag ++ " read code") CKR_OK (pcCode c)
          assertEqual (tag ++ " reads CK_FALSE") (Just (ValBool False))
            (decodeValue AttrDerive (outBytes o))
        _ -> assertFailure (tag ++ ": read outputs arity") >> undefined
      Reject rej -> assertFailure (tag ++ ": read rejected: " ++ show (rejCode rej))
        >> undefined
      Execute _ _ -> assertFailure (tag ++ ": read must not execute") >> undefined
    genEcPair ans m st0 pubT privT =
      case planGenerateKeyPair defaultRules m st0 ecKeyPairGenMech pubT privT of
        KeyEffect pw fx -> do
          res <- ans m fx
          c <- finishCommit m st0 pw res 2
          h1 <- handleOf (pcOutputs c !! 0)
          h2 <- handleOf (pcOutputs c !! 1)
          m' <- expectRight (publishDelta m (pcDelta c))
          pure (m', h1, h2)
        other -> assertFailure ("EC plan is not an effect: " ++ show other) >> undefined

caseDeriveReadViewUnwrapDerive :: IO ()
caseDeriveReadViewUnwrapDerive = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 32)
  blob <- case planWrapKey m2 st aesCbcMech iv16 wrapH targetH (IntentBuffer 48) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("one blob: " ++ show o) >> undefined
        other -> assertFailure ("wrap must commit: " ++ show other) >> undefined
    other -> assertFailure ("wrap must plan: " ++ show other) >> undefined
  -- An unwrap child without CKA_DERIVE: stored without the
  -- attribute, reads CK_FALSE through the read view.
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
  (m3, unwH) <- case planUnwrapKey defaultRules m2 st aesCbcMech iv16 wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m2 (pcDelta c))
      pure (m', h)
    other -> assertFailure ("unwrap must plan: " ++ show other) >> undefined
  assertStoredAbsent "unwrap" m3 unwH
  assertReadsFalse "unwrap" m3 st unwH
  -- A derive child without CKA_DERIVE likewise.
  (m4, baseH) <- deriveBase answer m3 st
  (m5, [dh]) <- runDerive answer m4 st baseH
    (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "derive-readview") [childTmpl 32]) 1
  assertStoredAbsent "derive-child" m5 dh
  assertReadsFalse "derive-child" m5 st dh
  -- Find on false matches both; true matches neither.
  hitsF <- findWith m5 st [(AttrDerive, ValBool False)]
  assertBool "unwrap matches derive-false" (unwH `elem` hitsF)
  assertBool "derive-child matches derive-false" (dh `elem` hitsF)
  hitsT <- findWith m5 st [(AttrDerive, ValBool True)]
  assertBool "unwrap misses derive-true" (unwH `notElem` hitsT)
  assertBool "derive-child misses derive-true" (dh `notElem` hitsT)
  -- Enforcement is unchanged: deriving from the unwrapped key
  -- refuses with CKR_KEY_FUNCTION_NOT_PERMITTED.
  case planDerive defaultRules m5 st hkdfDeriveMech unwH
      (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "no-permit") [childTmpl 32]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "unwrapped base code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("unwrapped base must refuse: " ++ show other)
  -- An explicit CKA_DERIVE=TRUE on the unwrap template still
  -- stores true, reads true and derives.
  (m6, expH) <- case planUnwrapKey defaultRules m5 st aesCbcMech iv16 wrapH blob
      (tmpl ++ [(AttrDerive, ValBool True)]) of
    KeyEffect pw fx -> do
      res <- answer m5 fx
      c <- finishCommit m5 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m5 (pcDelta c))
      pure (m', h)
    other -> assertFailure ("explicit unwrap must plan: " ++ show other) >> undefined
  Just expOst <- pure (resolveHandle m6 expH)
  assertEqual "explicit true stored" (Just (ValBool True))
    (Map.lookup AttrDerive (osAttrs expOst))
  case planGetAttributes m6 st expH [AttrDerive] of
    Immediate c -> case pcOutputs c of
      [o] -> do
        assertEqual "explicit read code" CKR_OK (pcCode c)
        assertEqual "explicit reads CK_TRUE" (Just (ValBool True))
          (decodeValue AttrDerive (outBytes o))
      _ -> assertFailure "explicit read outputs arity" >> undefined
    Reject rej -> assertFailure ("explicit read rejected: " ++ show (rejCode rej)) >> undefined
    Execute _ _ -> assertFailure "explicit read must not execute" >> undefined
  case planDerive defaultRules m6 st hkdfDeriveMech expH
      (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "permit") [childTmpl 32]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("explicit-derive base must plan: " ++ show other)
  where
    assertStoredAbsent tag m h = case resolveHandle m h of
      Nothing -> assertFailure (tag ++ ": handle unpublished") >> undefined
      Just ost -> assertEqual (tag ++ " stored lacks derive") Nothing
        (Map.lookup AttrDerive (osAttrs ost))
    assertReadsFalse tag m st0 h = case planGetAttributes m st0 h [AttrDerive] of
      Immediate c -> case pcOutputs c of
        [o] -> do
          assertEqual (tag ++ " read code") CKR_OK (pcCode c)
          assertEqual (tag ++ " reads CK_FALSE") (Just (ValBool False))
            (decodeValue AttrDerive (outBytes o))
        _ -> assertFailure (tag ++ ": read outputs arity") >> undefined
      Reject rej -> assertFailure (tag ++ ": read rejected: " ++ show (rejCode rej))
        >> undefined
      Execute _ _ -> assertFailure (tag ++ ": read must not execute") >> undefined
    findWith m st0 q = case planFindObjects m st0 q of
      Immediate fc -> mapM handleOf (pcOutputs fc)
      Reject rej -> assertFailure ("find rejected: " ++ show (rejCode rej)) >> undefined
      Execute _ _ -> assertFailure "find must not execute" >> undefined

caseEcPointStamped :: IO ()
caseEcPointStamped = do
  m0 <- seedModel
  st <- getSession m0
  let p256oid = hex "06082a8648ce3d030107"
      point = BS.pack (0x04 : [1 .. 64])
      spki = ecPublicDer p256oid point
      ecPub = pendingFromAttrs st (Map.fromList ecPubTmpl)
      ecPriv = pendingFromAttrs st (Map.fromList ecPrivTmpl)
      barePriv = pendingFromAttrs st (Map.delete AttrEcParams (Map.fromList ecPrivTmpl))
  -- A parseable EC SPKI stamps CKA_EC_POINT (DER OCTET STRING
  -- of the uncompressed point) on the public half; a private
  -- half lacking CKA_EC_PARAMS inherits the public curve,
  -- and its other attributes are unchanged.
  case stampPairComponents ecPub barePriv spki "opaque-priv" of
    Just (pub', priv') -> do
      -- CKA_EC_POINT is the DER OCTET STRING of the point
      -- (0x04 0x41 header over the 65 uncompressed bytes).
      assertEqual "EC_POINT stamped"
        (Just (ValBytes ("\x04\x41" <> point))) (Map.lookup AttrEcPoint (poAttrs pub'))
      assertEqual "EC_PARAMS inherited"
        (Just (ValBytes "P-256")) (Map.lookup AttrEcParams (poAttrs priv'))
      assertEqual "other private attrs unchanged"
        (Map.delete AttrEcParams (poAttrs ecPriv))
        (Map.delete AttrEcParams (poAttrs priv'))
    Nothing -> assertFailure "EC SPKI halves must stamp"
  -- Equal values pass through untouched.
  case stampPairComponents ecPub ecPriv spki "opaque-priv" of
    Just (_, priv') ->
      assertEqual "equal params untouched" (poAttrs ecPriv) (poAttrs priv')
    Nothing -> assertFailure "EC SPKI halves must stamp"
  -- Opaque halves (synthetic HKS1 frames) pass through: no
  -- EC_POINT, no rejection.
  assertEqual "opaque passthrough" (Just (ecPub, ecPriv))
    (stampPairComponents ecPub ecPriv "pub" "priv")

caseEcOpaqueBareCopy :: IO ()
caseEcOpaqueBareCopy = do
  m0 <- seedModel
  st <- getSession m0
  let ecPub = pendingFromAttrs st (Map.fromList ecPubTmpl)
      barePriv = pendingFromAttrs st (Map.delete AttrEcParams (Map.fromList ecPrivTmpl))
  -- Opaque halves with a bare private template: the
  -- template-derived copy still lands CKA_EC_PARAMS on the
  -- private half, without stamping CKA_EC_POINT on it.
  case stampPairComponents ecPub barePriv "pub" "priv" of
    Just (_, priv') -> do
      assertEqual "opaque bare priv inherits params"
        (Just (ValBytes "P-256")) (Map.lookup AttrEcParams (poAttrs priv'))
      assertEqual "no EC_POINT on opaque bare priv"
        Nothing (Map.lookup AttrEcPoint (poAttrs priv'))
    Nothing -> assertFailure "opaque halves must pass through"

caseEcParamsDisagree :: IO ()
caseEcParamsDisagree = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let dropT t = filter ((/= t) . fst)
      disagreePriv = (AttrEcParams, ValBytes "P-384") : dropT AttrEcParams ecPrivTmpl
      barePrivTmpl = dropT AttrEcParams ecPrivTmpl
  -- Disagreeing halves refuse at plan time, before any driver
  -- call: the public result is CKR_TEMPLATE_INCONSISTENT.
  case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubTmpl disagreePriv of
    KeyDenied (KeyDeny code _) ->
      assertEqual "disagreeing curves refuse" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("disagreeing curves must refuse at plan time: " ++ show other)
  -- Equal values are accepted.
  case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubTmpl ecPrivTmpl of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("equal curves must plan: " ++ show other)
  -- A private template lacking CKA_EC_PARAMS plans, and the
  -- minted private object carries the public curve.
  case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubTmpl barePrivTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      pubH <- handleOf (pcOutputs c !! 0)
      privH <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      Just pub <- pure (resolveHandle m' pubH)
      Just priv <- pure (resolveHandle m' privH)
      assertEqual "minted public keeps the curve"
        (Just (ValBytes "P-256")) (Map.lookup AttrEcParams (osAttrs pub))
      assertEqual "minted private carries the curve"
        (Just (ValBytes "P-256")) (Map.lookup AttrEcParams (osAttrs priv))
    other -> assertFailure ("lacking private params must plan: " ++ show other)

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
  -- A minimal template mints explicit import history: protection
  -- defaults (non-sensitive, extractable) plus false origin rows.
  let bareTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
  case planUnwrapKey defaultRules m2 st aesCbcMech iv16 wrapH blob bareTmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "minimal sensitive"
        (Just (ValBool False)) (Map.lookup AttrSensitive (osAttrs ost))
      assertEqual "minimal extractable"
        (Just (ValBool True)) (Map.lookup AttrExtractable (osAttrs ost))
      assertEqual "minimal always-sensitive"
        (Just (ValBool False)) (Map.lookup AttrAlwaysSensitive (osAttrs ost))
      assertEqual "minimal never-extractable"
        (Just (ValBool False)) (Map.lookup AttrNeverExtractable (osAttrs ost))
      assertEqual "minimal local"
        (Just (ValBool False)) (Map.lookup AttrLocal (osAttrs ost))
      assertEqual "minimal key-gen mechanism"
        (Just (ValULong maxBound)) (Map.lookup AttrKeyGenMechanism (osAttrs ost))
    other -> assertFailure ("bare unwrap plan is not an effect: " ++ show other)

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

-- | KW-PKCS7 pads the target to the 8-byte quantum (always
-- padding) and wraps with RFC 3394 under the default AIV or a
-- caller 8-byte IV: a 20-byte target queries 32 (24 padded + 8),
-- wraps/unwraps end to end under the same IV, and fails closed
-- (reject, nothing published) under the wrong IV.
caseAesKwPkcs7WrapRoundtrip :: IO ()
caseAesKwPkcs7WrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genKeyWith answer m1 st genericSecretKeyGenMech (secretTmplN 20)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  assertEqual "target length" 20 (BS.length targetMat)
  let iv8 = BS.pack [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]
      queryLen params = case planWrapKey m2 st aesKwp7Mech params wrapH targetH IntentNull of
        KeyImmediate (Immediate c) -> pure (pcOutputs c)
        other -> assertFailure ("pkcs7 query is not an Immediate commit: " ++ show other) >> undefined
  -- Length query: pad 20 -> 24, + 8 wrap = 32 (same under
  -- either IV: the IV is not part of the blob).
  assertEqual "pkcs7 query length default iv"
    [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 32))]
    =<< queryLen BS.empty
  assertEqual "pkcs7 query length caller iv"
    [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 32))]
    =<< queryLen iv8
  -- A 4-byte IV is neither empty nor 8: refused.
  case planWrapKey m2 st aesKwp7Mech (BS.replicate 4 0) wrapH targetH IntentNull of
    KeyDenied d -> assertEqual "iv code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("ragged iv accepted, got: " ++ show other)
  -- Wrap under the caller IV, unwrap under the same IV.
  blob <- case planWrapKey m2 st aesKwp7Mech iv8 wrapH targetH (IntentBuffer 32) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("pkcs7 plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 32 (BS.length blob)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        ]
  case planUnwrapKey defaultRules m2 st aesKwp7Mech iv8 wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
    other -> assertFailure ("pkcs7 unwrap plan is not an effect: " ++ show other)
  -- Unwrap under the WRONG (empty) IV plans, then the driver
  -- answers AuthFailed and the finish rejects with nothing
  -- published (fail closed, never wrong plaintext).
  case planUnwrapKey defaultRules m2 st aesKwp7Mech BS.empty wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Reject r -> assertEqual "wrong iv publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("wrong-iv unwrap committed, got: " ++ show other)
    other -> assertFailure ("wrong-iv unwrap plan is not an effect: " ++ show other)
  -- A 7-byte target is below the floor (pads to 8 < 16).
  (m4, shortH) <- genKeyWith answer m2 st genericSecretKeyGenMech (secretTmplN 7)
  case planWrapKey m4 st aesKwp7Mech BS.empty wrapH shortH IntentNull of
    KeyDenied d -> assertEqual "floor code" CKR_DATA_LEN_RANGE (kdCode d)
    other -> assertFailure ("short target accepted, got: " ++ show other)
  -- A 16-byte blob is not PKCS7 framing (multiple of 8, >= 24).
  case planUnwrapKey defaultRules m2 st aesKwp7Mech BS.empty wrapH (BS.replicate 16 0) tmpl of
    KeyDenied d -> assertEqual "blob code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("short blob accepted, got: " ++ show other)

caseEcdhCompWrapRoundtrip :: IO ()
caseEcdhCompWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  -- EC recipient pair with the marks (synthetic opaque material:
  -- transport prefix 69, agreement secret 72). Composition wrap
  -- takes the PUBLIC half, unwrap takes the private half.
  let ecPubWrapTmpl = ecPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      ecPrivWrapTmpl = ecPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
  (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubWrapTmpl ecPrivWrapTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      pub <- handleOf (pcOutputs c !! 0)
      priv <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', pub, priv)
    other -> assertFailure ("EC keypair plan is not an effect: " ++ show other) >> undefined
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  let params128 = encodeWrapCompEcdhParams 0 BS.empty 128
      queryLen m wh mech ps = case planWrapKey m st mech ps wh targetH IntentNull of
        KeyImmediate (Immediate c) -> pure (pcOutputs c)
        other -> assertFailure ("comp query is not an Immediate commit: " ++ show other) >> undefined
  -- Length query: opaque transport 69 + KWP(16) 24 = 93.
  assertEqual "comp query length"
    [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 93))]
    =<< queryLen m2 pubH ecdhAesKwMech params128
  -- Short buffer answers the length and refuses.
  case planWrapKey m2 st ecdhAesKwMech params128 pubH targetH (IntentBuffer 92) of
    KeyImmediate (Reject r) -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short length"
        [NativeOutput (RegionBytes "wrapped" (IntentBuffer 92)) (encodeValue (ValULong 93))]
        (rejOutputs r)
    other -> assertFailure ("short buffer accepted, got: " ++ show other)
  -- Full wrap: 93 bytes, opaque transport prefix + KWP tail.
  blob <- case planWrapKey m2 st ecdhAesKwMech params128 pubH targetH (IntentBuffer 93) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("comp plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 93 (BS.length blob)
  assertEqual "opaque prefix tag" "HKS1" (BS.take 4 blob)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
  -- Unwrap roundtrip recovers the target material.
  case planUnwrapKey defaultRules m2 st ecdhAesKwMech params128 privH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      mu <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle mu h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
    other -> assertFailure ("comp unwrap plan is not an effect: " ++ show other)
  -- Tampered KWP tail plans, then the driver answers AuthFailed
  -- and the finish rejects with nothing published (fail closed).
  let (pre, tailB) = BS.splitAt 69 blob
      badTail = BS.pack [BS.index tailB 0 `xor` 0x01] <> BS.drop 1 tailB
  case planUnwrapKey defaultRules m2 st ecdhAesKwMech params128 privH (pre <> badTail) tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Reject r -> assertEqual "tamper publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("tampered unwrap committed, got: " ++ show other)
    other -> assertFailure ("tampered unwrap plan is not an effect: " ++ show other)
  -- Bad parameters: off-set strengths refuse argument-bad
  -- (malformed), unserved KDFs refuse parameter-invalid (the open
  -- KDF enum is a feature refusal, not a malformed struct).
  case planWrapKey m2 st ecdhAesKwMech (encodeWrapCompEcdhParams 1 BS.empty 128) pubH targetH IntentNull of
    KeyDenied d -> assertEqual "kdf code" CKR_MECHANISM_PARAM_INVALID (kdCode d)
    other -> assertFailure ("non-null kdf accepted, got: " ++ show other)
  case planWrapKey m2 st ecdhAesKwMech (encodeWrapCompEcdhParams 0 BS.empty 512) pubH targetH IntentNull of
    KeyDenied d -> assertEqual "strength code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("off-set strength accepted, got: " ++ show other)
  -- Foreign wrapping keys refuse type-inconsistent: an AES
  -- secret, an RSA public half, and the EC PRIVATE half (wrap
  -- takes the public half; the swapped-roles regression pin).
  (m3, aesH) <- genAesKey answer m2 st wrapKeyTmpl
  case planWrapKey m3 st ecdhAesKwMech params128 aesH targetH IntentNull of
    KeyDenied d -> assertEqual "aes code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("AES wrapping accepted, got: " ++ show other)
  (m4, rsaH) <- plantKey m3 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkRsa)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    ]
    (BS.replicate 32 0x43)
  case planWrapKey m4 st ecdhAesKwMech params128 rsaH targetH IntentNull of
    KeyDenied d -> assertEqual "rsa code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("RSA wrapping accepted, got: " ++ show other)
  case planWrapKey m4 st ecdhAesKwMech params128 privH targetH IntentNull of
    KeyDenied d -> assertEqual "priv-half code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("private-half wrapping accepted, got: " ++ show other)
  case planUnwrapKey defaultRules m4 st ecdhAesKwMech params128 pubH blob tmpl of
    KeyDenied d -> assertEqual "pub-half unwrap code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("public-half unwrap accepted, got: " ++ show other)
  -- Row gates: X refuses the EC key, cofactor refuses Montgomery.
  case planWrapKey m2 st ecdhXAesKwMech params128 pubH targetH IntentNull of
    KeyDenied d -> assertEqual "x/ec code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("X over EC accepted, got: " ++ show other)
  (m5, montPubH) <- case planGenerateKeyPair defaultRules m4 st montgomeryKeyPairGenMech
      (xdPubTmpl ++ [(AttrWrap, ValBool True)])
      (xdPrivTmpl ++ [(AttrUnwrap, ValBool True)]) of
    KeyEffect pw fx -> do
      res <- answer m4 fx
      c <- finishCommit m4 st pw res 2
      h <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m4 (pcDelta c))
      pure (m', h)
    other -> assertFailure ("Montgomery keypair plan is not an effect: " ++ show other) >> undefined
  case planWrapKey m5 st ecdhCofAesKwMech params128 montPubH targetH IntentNull of
    KeyDenied d -> assertEqual "cof/mont code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("cofactor over Montgomery accepted, got: " ++ show other)
  -- Plain over Montgomery plans (opaque 69 + KWP 24 = 93).
  assertEqual "plain/mont query length"
    [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 93))]
    =<< queryLen m5 montPubH ecdhAesKwMech params128
  -- Blob framing: short and ragged tails refuse argument-bad.
  case planUnwrapKey defaultRules m2 st ecdhAesKwMech params128 privH (BS.replicate 80 0) tmpl of
    KeyDenied d -> assertEqual "short blob code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("short blob accepted, got: " ++ show other)
  case planUnwrapKey defaultRules m2 st ecdhAesKwMech params128 privH (BS.replicate 69 0 <> BS.replicate 20 0) tmpl of
    KeyDenied d -> assertEqual "ragged code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("ragged tail accepted, got: " ++ show other)
  -- The secret-width rule: a P-192 key (24-byte secret) refuses
  -- AES-256 but serves AES-128 (49 + 24 = 73).
  let p192oid = BS.pack [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01]
  (m6, p192H) <- plantKey m5 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkEc)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    ]
    ("junk" <> p192oid <> "junk")
  case planWrapKey m6 st ecdhAesKwMech (encodeWrapCompEcdhParams 0 BS.empty 256) p192H targetH IntentNull of
    KeyDenied d -> assertEqual "width code" CKR_MECHANISM_PARAM_INVALID (kdCode d)
    other -> assertFailure ("P-192 x AES-256 accepted, got: " ++ show other)
  case planWrapKey m6 st ecdhAesKwMech params128 p192H targetH IntentNull of
    KeyImmediate (Immediate c) ->
      assertEqual "P-192 x AES-128 length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 73))]
        (pcOutputs c)
    other -> assertFailure ("P-192 x AES-128 refused, got: " ++ show other)

-- | RSA-composition wrap mints a random temp KEK under the
-- recipient PUBLIC key (OAEP head, modulus-wide) plus the
-- KWP-sealed target; unwrap splits the head, opens the KEK
-- with the PRIVATE key, and recovers the target. Off-fit
-- strengths refuse the length range; foreign halves refuse
-- type-inconsistent.
caseRsaCompWrapRoundtrip :: IO ()
caseRsaCompWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let pubT = rsaPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      privT = rsaPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      params256 = encodeWrapCompRsaParams "SHA256" "SHA256" BS.empty 256
  (m1, pubH, privH) <- genRsaPair answer m0 st pubT privT
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  let queryLen m wh mech ps = case planWrapKey m st mech ps wh targetH IntentNull of
        KeyImmediate (Immediate c) -> pure (pcOutputs c)
        other -> assertFailure ("comp query is not an Immediate commit: " ++ show other) >> undefined
  -- Length query: 2048-bit modulus 256 + KWP(16) 24 = 280.
  assertEqual "comp query length"
    [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 280))]
    =<< queryLen m2 pubH rsaAesKwMech params256
  -- Short buffer answers the length and refuses.
  case planWrapKey m2 st rsaAesKwMech params256 pubH targetH (IntentBuffer 279) of
    KeyImmediate (Reject r) -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short length"
        [NativeOutput (RegionBytes "wrapped" (IntentBuffer 279)) (encodeValue (ValULong 280))]
        (rejOutputs r)
    other -> assertFailure ("short buffer accepted, got: " ++ show other)
  -- Full wrap: 280 bytes, modulus head + KWP tail.
  blob <- case planWrapKey m2 st rsaAesKwMech params256 pubH targetH (IntentBuffer 280) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("comp plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 280 (BS.length blob)
  -- A second wrap mints a FRESH random KEK (heads differ).
  blob2 <- case planWrapKey m2 st rsaAesKwMech params256 pubH targetH (IntentBuffer 280) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("rewrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("rewrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("rewrap plan is not an effect: " ++ show other) >> undefined
  assertBool "fresh KEK per wrap" (BS.take 256 blob2 /= BS.take 256 blob)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
  -- Unwrap roundtrip recovers the target material.
  case planUnwrapKey defaultRules m2 st rsaAesKwMech params256 privH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      mu <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle mu h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
    other -> assertFailure ("comp unwrap plan is not an effect: " ++ show other)
  -- Tampered head and tampered tail both fail closed (nothing
  -- published).
  let (hd, tl) = BS.splitAt 256 blob
      badHead = BS.pack [BS.index hd 0 `xor` 0x01] <> BS.drop 1 hd
  case planUnwrapKey defaultRules m2 st rsaAesKwMech params256 privH (badHead <> tl) tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Reject r -> assertEqual "head tamper publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("tampered head committed, got: " ++ show other)
    other -> assertFailure ("tampered-head unwrap plan is not an effect: " ++ show other)
  let badTail = BS.pack [BS.index tl 0 `xor` 0x01] <> BS.drop 1 tl
  case planUnwrapKey defaultRules m2 st rsaAesKwMech params256 privH (hd <> badTail) tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Reject r -> assertEqual "tail tamper publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("tampered tail committed, got: " ++ show other)
    other -> assertFailure ("tampered-tail unwrap plan is not an effect: " ++ show other)
  -- Bad parameters refuse argument-bad.
  case planWrapKey m2 st rsaAesKwMech (encodeWrapCompRsaParams "SHA256" "SHA256" BS.empty 512) pubH targetH IntentNull of
    KeyDenied d -> assertEqual "strength code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("off-set strength accepted, got: " ++ show other)
  case planWrapKey m2 st rsaAesKwMech "truncated" pubH targetH IntentNull of
    KeyDenied d -> assertEqual "truncated code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("truncated params accepted, got: " ++ show other)
  -- Foreign wrapping halves refuse type-inconsistent: an AES
  -- secret, an EC public half, and the RSA PRIVATE half (wrap
  -- takes the public half).
  (m3, aesH) <- genAesKey answer m2 st wrapKeyTmpl
  case planWrapKey m3 st rsaAesKwMech params256 aesH targetH IntentNull of
    KeyDenied d -> assertEqual "aes code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("AES wrapping accepted, got: " ++ show other)
  (m4, ecH) <- plantKey m3 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkEc)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    ]
    (BS.replicate 32 0x45)
  case planWrapKey m4 st rsaAesKwMech params256 ecH targetH IntentNull of
    KeyDenied d -> assertEqual "ec code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("EC wrapping accepted, got: " ++ show other)
  case planWrapKey m4 st rsaAesKwMech params256 privH targetH IntentNull of
    KeyDenied d -> assertEqual "priv-half code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("private-half wrapping accepted, got: " ++ show other)
  case planUnwrapKey defaultRules m4 st rsaAesKwMech params256 pubH blob tmpl of
    KeyDenied d -> assertEqual "pub-half unwrap code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("public-half unwrap accepted, got: " ++ show other)
  -- Blob framing: short and ragged tails refuse argument-bad.
  case planUnwrapKey defaultRules m2 st rsaAesKwMech params256 privH (BS.replicate 270 0) tmpl of
    KeyDenied d -> assertEqual "short blob code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("short blob accepted, got: " ++ show other)
  case planUnwrapKey defaultRules m2 st rsaAesKwMech params256 privH (BS.replicate 256 0 <> BS.replicate 20 0) tmpl of
    KeyDenied d -> assertEqual "ragged code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("ragged tail accepted, got: " ++ show other)
  -- The KEK-fit rule: a 512-bit modulus (64-byte head) refuses
  -- AES-256 under SHA-256 (64 - 64 - 2 < 32) but serves
  -- AES-128 under SHA-1 (64 - 40 - 2 = 22 >= 16; 64 + 24 = 88).
  (m5, shortH) <- plantKey m4 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkRsa)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    , (AttrModulus, ValBytes (BS.pack (0x80 : replicate 63 0x4d)))
    ]
    "opaque-rsa-half"
  case planWrapKey m5 st rsaAesKwMech params256 shortH targetH IntentNull of
    KeyDenied d -> assertEqual "fit code" CKR_DATA_LEN_RANGE (kdCode d)
    other -> assertFailure ("unfit KEK accepted, got: " ++ show other)
  case planWrapKey m5 st rsaAesKwMech (encodeWrapCompRsaParams "SHA_1" "SHA_1" BS.empty 128) shortH targetH IntentNull of
    KeyImmediate (Immediate c) ->
      assertEqual "short-modulus query length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 88))]
        (pcOutputs c)
    other -> assertFailure ("fit KEK refused, got: " ++ show other)

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
  let des3UnwrapTmpl =
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
  case planUnwrapKey defaultRules m3 st aesKwMech BS.empty wrapH blob16 des3UnwrapTmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> do
          assertEqual "confusion code" CKR_TEMPLATE_INCONSISTENT (rejCode r)
          assertEqual "confusion publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("confused unwrap committed, got: " ++ show other)
    other -> assertFailure ("unwrap plan is not an effect: " ++ show other)
  -- 24 bytes as DES3 commits (the type path itself works).
  case planUnwrapKey defaultRules m3 st aesKwMech BS.empty wrapH blob32 des3UnwrapTmpl of
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
  (m1, pubH, privH) <- genRsaPair answer m0 st pubT privT
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  (m3, aesWrapH) <- genAesKey answer m2 st wrapKeyTmpl
  let denyWrap m mech params wrapH tgtH cap = case planWrapKey m st mech params wrapH tgtH cap of
        KeyDenied (KeyDeny code _) -> pure code
        other -> assertFailure ("wrap must deny, got: " ++ show other) >> undefined
      denyUnwrap m mech params wrapH blob outTmpl =
        case planUnwrapKey defaultRules m st mech params wrapH blob outTmpl of
          KeyDenied (KeyDeny code _) -> pure code
          other -> assertFailure ("unwrap must deny, got: " ++ show other) >> undefined
      tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  -- Parameter shapes refuse.
  code1 <- denyWrap m3 rsaPkcsMech "nonempty" pubH targetH (IntentBuffer 256)
  assertEqual "v1.5 params code" CKR_ARGUMENTS_BAD code1
  code2 <- denyWrap m3 rsaOaepMech "garbage" pubH targetH (IntentBuffer 256)
  assertEqual "oaep params code" CKR_ARGUMENTS_BAD code2
  -- Wrong halves and foreign key types refuse.
  code3 <- denyWrap m3 rsaPkcsMech BS.empty privH targetH (IntentBuffer 256)
  assertEqual "private-half wrap code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code3
  code4 <- denyWrap m3 rsaPkcsMech BS.empty aesWrapH targetH (IntentBuffer 256)
  assertEqual "aes-key wrap code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code4
  code5 <- denyUnwrap m3 rsaPkcsMech BS.empty pubH (BS.replicate 256 0) tmpl
  assertEqual "public-half unwrap code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT code5
  -- A key marked non-wrapping cannot wrap (absent flags default
  -- true at keygen, so the refusal needs an explicit false).
  (m4, plainPubH, _) <- genRsaPair answer m3 st
    (rsaPubTmpl ++ [(AttrWrap, ValBool False)]) rsaPrivTmpl
  code6 <- denyWrap m4 rsaPkcsMech BS.empty plainPubH targetH (IntentBuffer 256)
  assertEqual "no-wrap-mark code" CKR_KEY_FUNCTION_NOT_PERMITTED code6
  -- An unextractable target cannot wrap.
  (m5, sealedH) <- genAesKey answer m4 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 16)
    , (AttrToken, ValBool False)
    , (AttrExtractable, ValBool False)
    ]
  code7 <- denyWrap m5 rsaPkcsMech BS.empty pubH sealedH (IntentBuffer 256)
  assertEqual "unextractable code" CKR_KEY_UNEXTRACTABLE code7
  -- Oversized payloads refuse with the length code (v1.5 bound
  -- k-11 = 245; OAEP-SHA-512 bound k-2*64-2 = 126).
  (m6, bigH) <- genKeyWith answer m5 st genericSecretKeyGenMech
    (genericTmpl 250 ++ [(AttrExtractable, ValBool True)])
  code8 <- denyWrap m6 rsaPkcsMech BS.empty pubH bigH (IntentBuffer 256)
  assertEqual "oversized code" CKR_DATA_LEN_RANGE code8
  let oaep512 = encodeOaepParams "SHA512" "SHA512" BS.empty
  (m7, midH) <- genKeyWith answer m6 st genericSecretKeyGenMech
    (genericTmpl 200 ++ [(AttrExtractable, ValBool True)])
  code9 <- denyWrap m7 rsaOaepMech oaep512 pubH midH (IntentBuffer 256)
  assertEqual "oversized oaep code" CKR_DATA_LEN_RANGE code9
  -- Off-modulus blobs and key-typeless templates refuse.
  code10 <- denyUnwrap m7 rsaPkcsMech BS.empty privH "short" tmpl
  assertEqual "short blob code" CKR_ARGUMENTS_BAD code10
  code11 <- denyUnwrap m7 rsaPkcsMech BS.empty privH (BS.replicate 256 0)
    [(AttrClass, ValULong ckoSecretKey)]
  assertEqual "typeless template code" CKR_TEMPLATE_INCOMPLETE code11
  -- Short buffers answer the modulus width.
  case planWrapKey m3 st rsaPkcsMech BS.empty pubH targetH (IntentBuffer 255) of
    KeyImmediate (Reject r) -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short length"
        [NativeOutput (RegionBytes "wrapped" (IntentBuffer 255)) (encodeValue (ValULong 256))]
        (rejOutputs r)
    other -> assertFailure ("short buffer must reject, got: " ++ show other)

caseRsaX509Wrap :: IO ()
caseRsaX509Wrap = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let pubT = rsaPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      privT = rsaPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
  (m1, pubH, privH) <- genRsaPair answer m0 st pubT privT
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  -- Length queries answer the modulus width and plan no crypto.
  case planWrapKey m2 st rsaX509Mech BS.empty pubH targetH IntentNull of
    KeyImmediate (Immediate c) -> do
      assertEqual "query length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 256))]
        (pcOutputs c)
      assertEqual "query publishes nothing" (StateDelta []) (pcDelta c)
    other -> assertFailure ("wrap query is not an Immediate commit: " ++ show other)
  -- Wrap seals modulus-wide (the synthetic seal pads like the real one).
  blob <- case planWrapKey m2 st rsaX509Mech BS.empty pubH targetH (IntentBuffer 256) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("wrap plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped width" 256 (BS.length blob)
  assertBool "blob differs from plaintext" (blob /= targetMat)
  -- Unwrap pairs tail pending work with the unwrap effect, and the
  -- full roundtrip recovers the target material.
  let tmpl16 =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
  case planUnwrapKey defaultRules m2 st rsaX509Mech BS.empty privH blob tmpl16 of
    KeyEffect pw@(PwUnwrapTail _ 256 16) fx@(FxUnwrap _ _ _ _) -> do
      assertBool "tail pair coherent" (keyPairCompatible pw fx)
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> do
          h <- handleOf (pcOutputs c !! 0)
          m3 <- expectRight (publishDelta m2 (pcDelta c))
          Just ost <- pure (resolveHandle m3 h)
          assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
        other -> assertFailure ("unwrap finish must commit, got: " ++ show other)
    other -> assertFailure ("unwrap plan is not a tail effect: " ++ show other)
  -- Direct finisher pin: the key is the trailing value_len bytes.
  let block = BS.replicate 240 0 <> targetMat
  case planUnwrapKey defaultRules m2 st rsaX509Mech BS.empty privH
    (BS.replicate 256 0) tmpl16 of
    KeyEffect pw@(PwUnwrapTail _ 256 16) _ ->
      case finishWork m2 st pw (GotBytes block) of
        Immediate c -> do
          h <- handleOf (pcOutputs c !! 0)
          m3 <- expectRight (publishDelta m2 (pcDelta c))
          Just ost <- pure (resolveHandle m3 h)
          assertEqual "tail material" (Just targetMat) (keyBytesOf ost)
        other -> assertFailure ("tail finish must commit, got: " ++ show other)
    other -> assertFailure ("unwrap plan is not a tail effect: " ++ show other)
  -- Refusals: parameters, lengths, blobs, oversized payloads.
  let denyWrap m mech params wrapH tgtH cap =
        case planWrapKey m st mech params wrapH tgtH cap of
          KeyDenied (KeyDeny code _) -> pure code
          other -> assertFailure ("wrap must deny, got: " ++ show other) >> undefined
      denyUnwrap m mech params wrapH wrapBlob tmpl =
        case planUnwrapKey defaultRules m st mech params wrapH wrapBlob tmpl of
          KeyDenied (KeyDeny code _) -> pure code
          other -> assertFailure ("unwrap must deny, got: " ++ show other) >> undefined
      notmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  xcode1 <- denyWrap m2 rsaX509Mech "nonempty" pubH targetH (IntentBuffer 256)
  assertEqual "params code" CKR_ARGUMENTS_BAD xcode1
  xcode2 <- denyUnwrap m2 rsaX509Mech BS.empty privH (BS.replicate 256 0) notmpl
  assertEqual "missing length code" CKR_TEMPLATE_INCOMPLETE xcode2
  xcode3 <- denyUnwrap m2 rsaX509Mech BS.empty privH (BS.replicate 256 0)
    (notmpl ++ [(AttrValueLen, ValULong 300)])
  assertEqual "over-wide length code" CKR_TEMPLATE_INCONSISTENT xcode3
  xcode4 <- denyUnwrap m2 rsaX509Mech BS.empty privH (BS.replicate 256 0)
    (notmpl ++ [(AttrValueLen, ValBool True)])
  assertEqual "malformed length code" CKR_TEMPLATE_INCONSISTENT xcode4
  xcode5 <- denyUnwrap m2 rsaX509Mech BS.empty privH "short" tmpl16
  assertEqual "short blob code" CKR_ARGUMENTS_BAD xcode5
  -- Zero overhead: the widest generatable secret (255) fits, while
  -- an extractable RSA private half (DER wider than k) refuses.
  (m3, wideH) <- genKeyWith answer m2 st genericSecretKeyGenMech
    (genericTmpl 255 ++ [(AttrExtractable, ValBool True)])
  case planWrapKey m3 st rsaX509Mech BS.empty pubH wideH (IntentBuffer 256) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("255-byte payload must plan, got: " ++ show other)
  (m4, _, bigPrivH) <- genRsaPair answer m3 st rsaPubTmpl
    (filter ((/= AttrExtractable) . fst) rsaPrivTmpl
      ++ [(AttrExtractable, ValBool True)])
  xcode6 <- denyWrap m4 rsaX509Mech BS.empty pubH bigPrivH (IntentBuffer 512)
  assertEqual "oversized code" CKR_DATA_LEN_RANGE xcode6

caseRecoverAttrs :: IO ()
caseRecoverAttrs = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  -- The oracle's sign-recover subset generates with these flags; the
  -- template must accept and store them (C_SignRecover itself stays
  -- stubbed, which the oracle skips cleanly).
  (m1, pubH, privH) <- genRsaPair answer m0 st
    (rsaPubTmpl ++ [(AttrVerifyRecover, ValBool True)])
    (rsaPrivTmpl ++ [(AttrSignRecover, ValBool True)])
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  assertEqual "verify-recover stored" (Just (ValBool True))
    (Map.lookup AttrVerifyRecover (osAttrs pub))
  assertEqual "sign-recover stored" (Just (ValBool True))
    (Map.lookup AttrSignRecover (osAttrs priv))
  case (policyFromObject pub, policyFromObject priv) of
    (Just (pubPermits, _), Just (privPermits, _)) -> do
      assertBool "pub recover permit" (OpVerifyRecover `elem` pubPermits)
      assertBool "priv recover permit" (OpSignRecover `elem` privPermits)
    other -> assertFailure ("policies must resolve, got: " ++ show other)
  -- Absent flags read as false (the PKCS#11 defaults): a plain pair
  -- carries no recover permits.
  (m2, pubH2, privH2) <- genRsaPair answer m1 st rsaPubTmpl rsaPrivTmpl
  Just pub2 <- pure (resolveHandle m2 pubH2)
  Just priv2 <- pure (resolveHandle m2 privH2)
  case (policyFromObject pub2, policyFromObject priv2) of
    (Just (pubPermits, _), Just (privPermits, _)) -> do
      assertBool "no pub recover permit" (OpVerifyRecover `notElem` pubPermits)
      assertBool "no priv recover permit" (OpSignRecover `notElem` privPermits)
    other -> assertFailure ("policies must resolve, got: " ++ show other)

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
      blob = encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "derive-info") [soloTmpl]
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
