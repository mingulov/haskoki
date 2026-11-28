{- | KeyManagement Part 5: real-backend proofs and planner KDF cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.Part5
  ( caseRealEcKeygen
  , caseRealRsaKeygen
  , caseRealX942Paramgen
  , caseRealDhPkcsParamgen
  , caseRealDsaParamgen
  , caseRealDsaKeygen
  , caseRealDhKeygen
  , caseRealEcKeygen384
  , caseRealEcKeygen521
  , caseRealWrapVector
  , caseRealHkdfVector
  , caseRealHkdfExtractExpand
  , caseRealHkdfMultiPrf
  , caseHkdfExtractOnlyRefused
  , caseHkdfDataPlans
  , caseRealHkdfDataVector
  , caseSp800Plans
  , caseRealSp800Vector
  , caseTlsKdfPlans
  , caseRealTlsKdfVector
  , caseIkePlans
  , caseRealIkeVector
  , caseByteOpsPlans
  , caseSealedByteOpsRefuse
  , caseSealedIkeTruncRefuse
  , caseRealByteOpsVector
  , caseByteOpsProtection
  , caseKeyTemplatesRefuseHistory
  , caseSsl3DerivePlans
  , caseRealSsl3Vector
  , caseKeyMatPlans
  , caseKeyMatAbsentBase
  , caseRealKeyMatVector
  , caseSp800MultiPlans
  , caseRealAuthWrap
  , caseRealAesKem
  , caseKemWrongKeyType
  , caseKemAesTemplate
  , caseKemStampsOutputHistory
  , caseKemKeygenParamSet
  ) where

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
  , Shape (..)
  , attributeTypeByName
  , decodeValue
  , getAttributes
  , shapeOf
  )
import Haskoki.Der (dhSpkiFields, mlkemPkcs8Fields, mlkemSpkiFields)
import Haskoki.Engine.Backend
  ( CryptoBackend (..)
  , DhSpec (..)
  , DigestAlg (..)
  , EcSpec (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , MacSpec (..)
  , SigSpec (..)
  )
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  )
import Haskoki.Object (planFindObjects, planGetAttributes, resolveHandle)
import Haskoki.Operation.Derive
  ( encodeDeriveParams
  , encodeHkdfInfo
  , hkdfDataMech
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
  , PendingWork (..)
  , aesCbcMech
  , aesKeyGenMech
  , ckkAes
  , ckkChacha20
  , ckkDes3
  , ckkDh
  , ckkDsa
  , ckkGenericSecret
  , ckkMlKem
  , ckkRsa
  , ckkX9_42Dh
  , ckkDes
  , ckkRc2
  , ckkRc4
  , ckkPoly1305
  , ckkHkdf
  , ckkSha256Hmac
  , ckoData
  , ckoDomainParameters
  , ckoPublicKey
  , ckoSecretKey
  , dhKeyPairGenMech
  , dsaKeyPairGenMech
  , dsaParameterGenMech
  , ecKeyPairGenMech
  , dhPkcsParameterGenMech
  , x9_42DhParameterGenMech
  , finishWork
  , keyBytesOf
  , planAuthUnwrapKey
  , planAuthWrapKey
  , planGenerateKey
  , planGenerateKeyPair
  , planUnwrapKey
  , planWrapKey
  , rsaKeyPairGenMech
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Recipe.Sp800108 (encodeSp800Params, maxSp800Total)
import Haskoki.Recipe.TlsKdf (encodeTlsKdfParams, maxTlsKdfOutput)
import Haskoki.Recipe.ByteOps (encodeByteOpsParams)
import Haskoki.Recipe.Ssl3 (encodeSsl3KeyMatParams, encodeSsl3MasterParams)
import Haskoki.Recipe.TlsKeyMat (encodeTlsKeyMatParams)
import Haskoki.Recipe.Ike (encodeIkeParams, maxIkeOutput)
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , ObjectId (..)
  , ReturnCode (..)
  )
import KeyManagement.CreationStamping
import KeyManagement.Fixtures
import KeyManagement.Part2Fixtures
import KeyManagement.Part4
import KeyManagement.Premaster

-- ---------------------------------------------------------------------------
-- Part 5: real-backend proofs (implemented capabilities only)
-- ---------------------------------------------------------------------------

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

-- A generated base is an unsigned integer, not a prime-width field:
-- DER strips leading zero octets, so valid g can be shorter than p.
-- All three parameter-generation mechanisms use DSA P/Q/G generation.
assertDomainGenerator :: ByteString -> ByteString -> ByteString -> IO ()
assertDomainGenerator p q g = do
  assertBool "base has a nonempty minimal unsigned encoding"
    (not (BS.null g) && BS.head g /= 0)
  let pInt = unsigned p
      qInt = unsigned q
      gInt = unsigned g
  assertBool "subprime is between one and prime" (1 < qInt && qInt < pInt)
  assertBool "base is between one and prime minus one" (1 < gInt && gInt < pInt - 1)
  assertEqual "subprime divides prime minus one" 0 ((pInt - 1) `mod` qInt)
  assertEqual "base is in the subprime-order subgroup" 1 (powerMod gInt qInt pInt)
  where
    unsigned :: ByteString -> Integer
    unsigned = BS.foldl' (\acc octet -> acc * 256 + fromIntegral octet) 0

    powerMod :: Integer -> Integer -> Integer -> Integer
    powerMod base power modulus = go 1 (base `mod` modulus) power
      where
        go acc _ 0 = acc
        go acc factor n =
          go (if odd n then (acc * factor) `mod` modulus else acc)
            ((factor * factor) `mod` modulus) (n `div` 2)

caseRealX942Paramgen :: IO ()
caseRealX942Paramgen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, h) <- case planGenerateKey defaultRules m0 st x9_42DhParameterGenMech BS.empty (x942ParamsTmpl 1024 160) of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 1
      h' <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h')
    other -> assertFailure ("X9.42 paramgen plan is not an effect: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "params class" (Just (ValULong ckoDomainParameters))
    (Map.lookup AttrClass (osAttrs ost))
  assertEqual "params key type" (Just (ValULong ckkX9_42Dh))
    (Map.lookup AttrKeyType (osAttrs ost))
  case (Map.lookup AttrPrime (osAttrs ost), Map.lookup AttrSubprime (osAttrs ost),
      Map.lookup AttrBase (osAttrs ost)) of
    (Just (ValBytes p), Just (ValBytes q), Just (ValBytes g)) -> do
      assertEqual "prime width" 128 (BS.length p)
      assertEqual "subprime width" 20 (BS.length q)
      assertDomainGenerator p q g
      assertEqual "prime bits" (Just (ValULong 1024))
        (Map.lookup AttrPrimeBits (osAttrs ost))
      assertEqual "subprime bits" (Just (ValULong 160))
        (Map.lookup AttrSubprimeBits (osAttrs ost))
    other -> assertFailure ("real params lack components: " ++ show other)

caseRealDhPkcsParamgen :: IO ()
caseRealDhPkcsParamgen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, h) <- case planGenerateKey defaultRules m0 st dhPkcsParameterGenMech BS.empty (dhPkcsParamsTmpl 1024 160) of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 1
      h' <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h')
    other -> assertFailure ("DH PKCS paramgen plan is not an effect: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "params class" (Just (ValULong ckoDomainParameters))
    (Map.lookup AttrClass (osAttrs ost))
  assertEqual "params key type" (Just (ValULong ckkDh))
    (Map.lookup AttrKeyType (osAttrs ost))
  case (Map.lookup AttrPrime (osAttrs ost), Map.lookup AttrSubprime (osAttrs ost),
      Map.lookup AttrBase (osAttrs ost)) of
    (Just (ValBytes p), Just (ValBytes q), Just (ValBytes g)) -> do
      assertEqual "prime width" 128 (BS.length p)
      assertEqual "subprime width" 20 (BS.length q)
      assertDomainGenerator p q g
      assertEqual "prime bits" (Just (ValULong 1024))
        (Map.lookup AttrPrimeBits (osAttrs ost))
      assertEqual "subprime bits" (Just (ValULong 160))
        (Map.lookup AttrSubprimeBits (osAttrs ost))
    other -> assertFailure ("real params lack components: " ++ show other)

caseRealDsaParamgen :: IO ()
caseRealDsaParamgen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, h) <- case planGenerateKey defaultRules m0 st dsaParameterGenMech BS.empty (dsaParamsTmpl 1024) of
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
      assertDomainGenerator p q g
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
  (m1, ph) <- case planGenerateKey defaultRules m0 st dsaParameterGenMech BS.empty (dsaParamsTmpl 1024) of
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
      yRead <- case planGetAttributes m2 st pubH [AttrValue] of
        Immediate c -> case pcOutputs c of
          [o] -> case decodeValue AttrValue (outBytes o) of
            Just (ValBytes y) -> pure y
            _ -> assertFailure "generated DSA value undecodable" >> undefined
          _ -> assertFailure "generated DSA read arity" >> undefined
        Reject rej -> assertFailure ("generated DSA read rejected: " ++ show (rejCode rej)) >> undefined
        Execute _ _ -> assertFailure "generated DSA read must not execute" >> undefined
      hits <- case planFindObjects m2 st
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkDsa)
        , (AttrValue, ValBytes yRead)
        ] of
        Immediate fc -> mapM handleOf (pcOutputs fc)
        Reject rej -> assertFailure ("generated DSA find rejected: " ++ show (rejCode rej)) >> undefined
        Execute _ _ -> assertFailure "generated DSA find must not execute" >> undefined
      assertEqual "generated DSA find by read-back" [pubH] hits
    _ -> assertFailure "real DSA halves lack material"

caseRealDhKeygen :: IO ()
caseRealDhKeygen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
      pubT =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkDh)
        , (AttrPrime, ValBytes dhRealP)
        , (AttrBase, ValBytes dhG)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        ]
      mint m n = case planGenerateKeyPair defaultRules m st dhKeyPairGenMech pubT dhPrivTmpl of
        KeyEffect pw fx -> do
          res <- answer m fx
          c <- finishCommit m st pw res n
          h1 <- handleOf (pcOutputs c !! 0)
          h2 <- handleOf (pcOutputs c !! 1)
          m' <- expectRight (publishDelta m (pcDelta c))
          pure (m', h1, h2)
        other -> assertFailure ("DH plan is not an effect: " ++ show other) >> undefined
  (m1, pubHA, privHA) <- mint m0 2
  (m2, pubHB, privHB) <- mint m1 2
  Just pubA <- pure (resolveHandle m2 pubHA)
  Just privA <- pure (resolveHandle m2 privHA)
  Just pubB <- pure (resolveHandle m2 pubHB)
  Just privB <- pure (resolveHandle m2 privHB)
  case (keyBytesOf pubA, keyBytesOf privA, keyBytesOf pubB, keyBytesOf privB) of
    (Just pubBA, Just privBA, Just pubBB, Just privBB) -> do
      assertBool "halves differ" (pubBA /= privBA)
      assertEqual "priv inherits prime" (Just (ValBytes dhRealP))
        (Map.lookup AttrPrime (osAttrs privA))
      assertEqual "priv inherits base" (Just (ValBytes dhG))
        (Map.lookup AttrBase (osAttrs privA))
      -- The generated pairs really agree: cross-derive both ways.
      yA <- case dhSpkiFields pubBA of
        Just (_, _, _, y) -> pure y
        Nothing -> assertFailure "SPKI A failed to parse" >> undefined
      yB <- case dhSpkiFields pubBB of
        Just (_, _, _, y) -> pure y
        Nothing -> assertFailure "SPKI B failed to parse" >> undefined
      rab <- dhDerive env DhPlain (KeyDer privBA) (KeyDer yB)
      sAB <- case rab of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real derive A->B failed: " ++ show err) >> undefined
      rba <- dhDerive env DhPlain (KeyDer privBB) (KeyDer yA)
      sBA <- case rba of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real derive B->A failed: " ++ show err) >> undefined
      assertEqual "agreement commutes" sAB sBA
      -- The shim left-pads the agreement to the prime byte
      -- width, so every draw fills all 256 bytes exactly (a
      -- leading zero byte is kept, not stripped).
      assertBool "secret nonempty" (not (BS.null sAB))
      assertEqual "secret fills prime width" 256 (BS.length sAB)
      let checkGenerated pubH label = do
            yRead <- case planGetAttributes m2 st pubH [AttrValue] of
              Immediate c -> case pcOutputs c of
                [o] -> case decodeValue AttrValue (outBytes o) of
                  Just (ValBytes y) -> pure y
                  _ -> assertFailure ("generated DH value undecodable: " ++ label) >> undefined
                _ -> assertFailure ("generated DH read arity: " ++ label) >> undefined
              Reject rej -> assertFailure ("generated DH read rejected: " ++ label ++ ": " ++ show (rejCode rej)) >> undefined
              Execute _ _ -> assertFailure ("generated DH read must not execute: " ++ label) >> undefined
            hits <- case planFindObjects m2 st
              [ (AttrClass, ValULong ckoPublicKey)
              , (AttrKeyType, ValULong ckkDh)
              , (AttrValue, ValBytes yRead)
              ] of
              Immediate fc -> mapM handleOf (pcOutputs fc)
              Reject rej -> assertFailure ("generated DH find rejected: " ++ label ++ ": " ++ show (rejCode rej)) >> undefined
              Execute _ _ -> assertFailure ("generated DH find must not execute: " ++ label) >> undefined
            assertEqual ("generated DH find by read-back: " ++ label) [pubH] hits
      checkGenerated pubHA "A"
      checkGenerated pubHB "B"
    _ -> assertFailure "real DH halves lack material"

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
  (m2, [h]) <- case planDerive defaultRules m1 st hkdfDeriveMech baseH (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty rfcInfo) [kid]) of
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
    let deriveOnce mm = case planDerive defaultRules mm st hkdfDeriveMech baseH (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty rfcInfo) [kid]) of
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

caseRealHkdfExtractExpand :: IO ()
caseRealHkdfExtractExpand = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcIkm
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 42)
        , (AttrToken, ValBool False)
        ]
      deriveWith salt info = case planDerive defaultRules m1 st hkdfDeriveMech baseH
        (encodeDeriveParams (encodeHkdfInfo 4 0x03 salt info) [kid]) of
          KeyEffect pw fx -> do
            res <- answer m1 fx
            c <- finishCommit m1 st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta m1 (pcDelta c))
            pure (m', hh)
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
  (m2, h1) <- deriveWith rfcSalt rfcInfo
  Just ost1 <- pure (resolveHandle m2 h1)
  assertEqual "RFC 5869 A.1 OKM" (Just rfcOkm) (keyBytesOf ost1)
  (m3, h3) <- deriveWith BS.empty BS.empty
  Just ost3 <- pure (resolveHandle m3 h3)
  assertEqual "RFC 5869 A.3 OKM (zero salt)" (Just rfcOkmZeroSalt) (keyBytesOf ost3)
  -- Synthetic replays itself on the same extract profile.
  withSynth $ \sanswer -> do
    let once mm = case planDerive defaultRules mm st hkdfDeriveMech baseH
          (encodeDeriveParams (encodeHkdfInfo 4 0x03 rfcSalt rfcInfo) [kid]) of
            KeyEffect pw fx -> do
              res <- sanswer mm fx
              c <- finishCommit mm st pw res 1
              hh <- handleOf (pcOutputs c !! 0)
              m' <- expectRight (publishDelta mm (pcDelta c))
              pure (m', hh)
            _ -> assertFailure "derive must plan" >> undefined
    (ms1, hs1) <- once m1
    (ms2, hs2) <- once m1
    Just os1 <- pure (resolveHandle ms1 hs1)
    Just os2 <- pure (resolveHandle ms2 hs2)
    assertEqual "synthetic extract replays" (keyBytesOf os1) (keyBytesOf os2)

-- | Multi-PRF HKDF over the real backend: the A.1 inputs
-- under SHA-1 and SHA-512. RFC 5869 pins SHA-256 only; these
-- references were computed programmatically (a python hmac
-- one-off) and cross-check the PRF threading, not the RFC.
caseRealHkdfMultiPrf :: IO ()
caseRealHkdfMultiPrf = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcIkm
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 42)
        , (AttrToken, ValBool False)
        ]
      deriveWith prf = case planDerive defaultRules m1 st hkdfDeriveMech baseH
        (encodeDeriveParams (encodeHkdfInfo prf 0x03 rfcSalt rfcInfo) [kid]) of
          KeyEffect pw fx -> do
            res <- answer m1 fx
            c <- finishCommit m1 st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta m1 (pcDelta c))
            pure (m', hh)
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
      sha1Okm = hex "d6000ffb5b50bd3970b260017798fb9c8df9ce2e2c16b6cd709cca07dc3cf9cf26d6c6d750d0aaf5ac94"
      sha512Okm = hex "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
  (m2, h1) <- deriveWith 2
  Just ost1 <- pure (resolveHandle m2 h1)
  assertEqual "HKDF-SHA-1 OKM" (Just sha1Okm) (keyBytesOf ost1)
  (m3, h2) <- deriveWith 6
  Just ost2 <- pure (resolveHandle m3 h2)
  assertEqual "HKDF-SHA-512 OKM" (Just sha512Okm) (keyBytesOf ost2)

caseHkdfExtractOnlyRefused :: IO ()
caseHkdfExtractOnlyRefused = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcIkm
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 32)
        , (AttrToken, ValBool False)
        ]
      blob = encodeDeriveParams (encodeHkdfInfo 4 0x01 BS.empty BS.empty) [kid]
  case planDerive defaultRules m1 st hkdfDeriveMech baseH blob of
    KeyDenied (KeyDeny code _) ->
      assertEqual "extract-only code" CKR_MECHANISM_PARAM_INVALID code
    other -> assertFailure ("extract-only must deny, got: " ++ show other)

caseHkdfDataPlans :: IO ()
caseHkdfDataPlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcIkm
  (m2, hkdfH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkHkdf)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcIkm
  let frame = encodeHkdfInfo 4 0x03 BS.empty rfcInfo
      dat = [ (AttrClass, ValULong ckoData)
            , (AttrValueLen, ValULong 42)
            , (AttrToken, ValBool False)
            ]
      key = [ (AttrClass, ValULong ckoSecretKey)
            , (AttrKeyType, ValULong ckkGenericSecret)
            , (AttrValueLen, ValULong 42)
            , (AttrToken, ValBool False)
            ]
      noLen = [ (AttrClass, ValULong ckoData)
              , (AttrToken, ValBool False)
              ]
  case planDerive defaultRules m2 st hkdfDataMech baseH
      (encodeDeriveParams frame [dat]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("data output must plan, got: " ++ show other)
  case planDerive defaultRules m2 st hkdfDataMech baseH
      (encodeDeriveParams frame [key]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "key-class code" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("key output must deny, got: " ++ show other)
  -- Base acceptance mirrors HKDF-DERIVE (any derive-marked
  -- base): only the output class differs.
  case planDerive defaultRules m2 st hkdfDataMech hkdfH
      (encodeDeriveParams frame [dat]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("hkdf base must plan, got: " ++ show other)
  case planDerive defaultRules m2 st hkdfDataMech baseH
      (encodeDeriveParams frame [noLen]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "missing length code" CKR_TEMPLATE_INCOMPLETE code
    other -> assertFailure ("missing length must deny, got: " ++ show other)
  case planDerive defaultRules m2 st hkdfDataMech baseH
      (encodeDeriveParams (encodeHkdfInfo 4 0x01 BS.empty BS.empty) [dat]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "extract-only code" CKR_MECHANISM_PARAM_INVALID code
    other -> assertFailure ("extract-only must deny, got: " ++ show other)
  -- A history attribute in a data-output template refuses
  -- inconsistent, like every other creation entry.
  case planDerive defaultRules m2 st hkdfDataMech baseH
      (encodeDeriveParams frame [dat ++ [(AttrLocal, ValBool True)]]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "history data code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("history data must deny, got: " ++ show other)

caseRealHkdfDataVector :: IO ()
caseRealHkdfDataVector = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  -- The A.1 shape, mirrored from caseRealHkdfVector: the base
  -- carries the RFC PRK, expand-only, and the derived 42 bytes
  -- must equal the RFC OKM — the same KDF as HKDF-DERIVE, only
  -- the output class differs.
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcPrk
  let dat =
        [ (AttrClass, ValULong ckoData)
        , (AttrValueLen, ValULong 42)
        , (AttrToken, ValBool False)
        ]
      frame = encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty rfcInfo) [dat]
  (m2, [h]) <- case planDerive defaultRules m1 st hkdfDataMech baseH frame of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      hh <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      pure (m', [hh])
    other -> assertFailure ("derive must plan: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m2 h)
  assertEqual "RFC 5869 A.1 OKM" (Just rfcOkm) (keyBytesOf ost)
  assertEqual "data class" (Just (ValULong ckoData))
    (Map.lookup AttrClass (osAttrs ost))
  -- The synthetic construction replays itself on the data-output
  -- arm (same determinism bar as the key-output arm).
  withSynth $ \sanswer -> do
    let deriveOnce mm = case planDerive defaultRules mm st hkdfDataMech baseH frame of
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
    assertEqual "synthetic data derive replays" (keyBytesOf os1) (keyBytesOf os2)

caseSp800Plans :: IO ()
caseSp800Plans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  let kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong n)
        , (AttrToken, ValBool False)
        ]
      counter = encodeSp800Params 4 32 32 BS.empty sp800Fixed
      feedback = encodeSp800Params 4 32 32 (BS.pack [0 .. 15]) sp800Fixed
      dbl = encodeSp800Params 4 32 32 BS.empty sp800Fixed
  -- All three modes plan with a VALUE_LEN template.
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams counter [kid 16]) of
    KeyEffect _ (FxDerive mech _ _ params info total) -> do
      assertEqual "counter mech" sp800CounterMech mech
      assertEqual "counter params" counter params
      assertEqual "counter info empty" BS.empty info
      assertEqual "counter total" 16 total
    other -> assertFailure ("counter must plan: " ++ show other)
  case planDerive defaultRules m1 st sp800FeedbackMech baseH
      (encodeDeriveParams feedback [kid 16]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("feedback must plan: " ++ show other)
  case planDerive defaultRules m1 st sp800DoubleMech baseH
      (encodeDeriveParams dbl [kid 32]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("double-pipeline must plan: " ++ show other)
  -- Junk frames refuse typed.
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams "junk" [kid 16]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "junk code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("junk must deny, got: " ++ show other)
  -- An IV on a counter frame refuses typed (mode/IV
  -- consistency).
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams feedback [kid 16]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "counter-iv code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("counter iv must deny, got: " ++ show other)
  -- A missing length stays INCOMPLETE (no natural width).
  let noLen =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams counter [noLen]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "no-length code" CKR_TEMPLATE_INCOMPLETE code
    other -> assertFailure ("missing length must deny, got: " ++ show other)
  -- Output past the ceiling refuses typed.
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams counter [kid (fromIntegral (maxSp800Total + 1))]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "ceiling code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("over-ceiling must deny, got: " ++ show other)
  -- L must fit its width (320 bits need more than 8).
  let narrow = encodeSp800Params 4 32 8 BS.empty sp800Fixed
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams narrow [kid 40]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "L-fit code" CKR_KEY_SIZE_RANGE code
    other -> assertFailure ("L misfit must deny, got: " ++ show other)
  -- Counter mode past 2^r - 1 iterations refuses typed (256
  -- blocks need more than 8 counter bits).
  let short = encodeSp800Params 4 8 32 BS.empty sp800Fixed
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams short [kid 8192]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "counter-fit code" CKR_KEY_SIZE_RANGE code
    other -> assertFailure ("counter misfit must deny, got: " ++ show other)

caseRealSp800Vector :: IO ()
caseRealSp800Vector = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
      frame = encodeSp800Params 4 32 32 BS.empty sp800Fixed
  (m2, [h]) <- case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams frame [kid]) of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      hh <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      pure (m', [hh])
    other -> assertFailure ("derive must plan: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m2 h)
  -- Triple-verified: independent python construction, the
  -- oracle reference, and the provider KBKDF CLI agree.
  assertEqual "SP800-108 counter AES-128 KAT"
    (Just (hex "caff7a6a35ca9b35afcc64fa658d8bc2")) (keyBytesOf ost)

tlsKdfSess32 :: BS.ByteString
tlsKdfSess32 = BS.pack [0 .. 31]

caseTlsKdfPlans :: IO ()
caseTlsKdfPlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 47])
  let kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      master = encodeTlsKdfParams 0 "master secret" tlsKdfSeed64 BS.empty
      kdf = encodeTlsKdfParams 4 "key expansion" tlsKdfSeed64 BS.empty
  -- Each row plans with its frame.
  mapM_ (\(mech, frame, n) ->
    case planDerive defaultRules m1 st mech baseH
        (encodeDeriveParams frame [kid n]) of
      KeyEffect _ (FxDerive _ _ _ _ _ total) ->
        assertEqual ("total " ++ show mech) n total
      other -> assertFailure ("must plan, got: " ++ show other))
    [ (tlsKdfMasterMech, master, 48)
    , (tlsKdfTls12Mech, encodeTlsKdfParams 4 "master secret" tlsKdfSeed64 BS.empty, 48)
    , (tlsKdfExtMech, encodeTlsKdfParams 4 "extended master secret" tlsKdfSess32 BS.empty, 48)
    , (tlsKdfFreeMech, kdf, 32)
    , (tlsKdfGenMech, encodeTlsKdfParams 0 "key expansion" tlsKdfSeed64 BS.empty, 32)
    ]
  -- A wrong-row frame refuses typed.
  case planDerive defaultRules m1 st tlsKdfMasterMech baseH
      (encodeDeriveParams kdf [kid 32]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrong-row code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("wrong row must deny, got: " ++ show other)
  -- A missing length stays INCOMPLETE (no natural width).
  let noLen =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        ]
  case planDerive defaultRules m1 st tlsKdfMasterMech baseH
      (encodeDeriveParams master [noLen]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "no-length code" CKR_TEMPLATE_INCOMPLETE code
    other -> assertFailure ("missing length must deny, got: " ++ show other)
  -- Output past the ceiling refuses typed.
  case planDerive defaultRules m1 st tlsKdfFreeMech baseH
      (encodeDeriveParams kdf [kid (fromIntegral (maxTlsKdfOutput + 1))]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "ceiling code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("over-ceiling must deny, got: " ++ show other)

caseRealTlsKdfVector :: IO ()
caseRealTlsKdfVector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 47])
  let kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      derive mech frame n = do
        (m', [h]) <- case planDerive defaultRules m1 st mech baseH
            (encodeDeriveParams frame [kid n]) of
          KeyEffect pw fx -> do
            res <- answer m1 fx
            c <- finishCommit m1 st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta m1 (pcDelta c))
            pure (m', [hh])
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
        Just ost <- pure (resolveHandle m' h)
        pure (keyBytesOf ost)
  gotM10 <- derive tlsKdfMasterMech
    (encodeTlsKdfParams 0 "master secret" tlsKdfSeed64 BS.empty) 48
  assertEqual "TLS master KAT"
    (Just (hex "539391828d1d131678646180c5bda5c9a2eb62382c8cfb9440545cae85c8c205b93e0d22161e06be1189235aefca7570")) gotM10
  gotM12 <- derive tlsKdfTls12Mech
    (encodeTlsKdfParams 4 "master secret" tlsKdfSeed64 BS.empty) 48
  assertEqual "TLS12 master KAT"
    (Just (hex "2b7cccb6d48adb8692df640b9252502fb000fd68fb2dc4b6a8cd67d870492f38e4c5dd509ba7c4863c003c07d23f9a3b")) gotM12
  gotKdf <- derive tlsKdfFreeMech
    (encodeTlsKdfParams 4 "key expansion" tlsKdfSeed64 "context-info") 32
  assertEqual "TLS12 KDF ctx KAT"
    (Just (hex "5c0125c5f281488f681349499f252df0d29934469aabc15136b0a6a78a4b39d7")) gotKdf
  gotExt <- derive tlsKdfExtMech
    (encodeTlsKdfParams 4 "extended master secret" tlsKdfSess32 BS.empty) 48
  assertEqual "extended master KAT"
    (Just (hex "c3d5ea08b472cbb67e205711e5006647e2b8cb5f6b2a20847780122bdb78cf874a37fb5aa6ae0e3ce513256f888efa1b")) gotExt

caseIkePlans :: IO ()
caseIkePlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  (m2, auxH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [32 .. 63])
  let auxN = fromIntegral (unExternalHandle auxH)
      kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      fPlus = encodeIkeParams 4 0 0 0 ikeSeed32 BS.empty
      fPrf = encodeIkeParams 4 1 0 0 ikeNi ikeNr
      fIke1 = encodeIkeParams 4 0 7 auxN ikeNi ikeNr
      fExt = encodeIkeParams 4 0 0 auxN ikeSeed32 BS.empty
  -- Each row plans with its frame; the two-key rows bind fxKey2.
  mapM_ (\(mech, frame, n, needsAux) ->
    case planDerive defaultRules m2 st mech baseH
        (encodeDeriveParams frame [kid n]) of
      KeyEffect _ (FxDerive _ _ mAux _ _ total) -> do
        assertEqual ("total " ++ show mech) n total
        assertEqual ("aux " ++ show mech) needsAux (mAux /= Nothing)
      other -> assertFailure ("must plan, got: " ++ show other))
    [ (ikePlusMech, fPlus, 32, False)
    , (ikePrfMech, fPrf, 32, False)
    , (ike1Mech, fIke1, 32, True)
    , (ikeExtMech, fExt, 32, True)
    ]
  -- A wrong-row frame refuses typed.
  case planDerive defaultRules m2 st ike1Mech baseH
      (encodeDeriveParams fPlus [kid 32]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrong-row code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("wrong row must deny, got: " ++ show other)
  -- The reserved PRF code denies with the spec-exact code.
  case planDerive defaultRules m2 st ikePrfMech baseH
      (encodeDeriveParams (encodeIkeParams 0 1 0 0 ikeNi ikeNr) [kid 32]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "prf code" CKR_MECHANISM_PARAM_INVALID code
    other -> assertFailure ("prf 0 must deny, got: " ++ show other)
  -- An unknown aux handle denies typed.
  case planDerive defaultRules m2 st ike1Mech baseH
      (encodeDeriveParams (encodeIkeParams 4 0 7 999999 ikeNi ikeNr) [kid 32]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "aux code" CKR_KEY_HANDLE_INVALID code
    other -> assertFailure ("bad aux must deny, got: " ++ show other)
  -- Output past the ceiling refuses typed.
  case planDerive defaultRules m2 st ikePlusMech baseH
      (encodeDeriveParams fPlus [kid (fromIntegral (maxIkeOutput + 1))]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "ceiling code" CKR_KEY_SIZE_RANGE code
    other -> assertFailure ("over-ceiling must deny, got: " ++ show other)

caseRealIkeVector :: IO ()
caseRealIkeVector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  (m2, auxH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [32 .. 63])
  let auxN = fromIntegral (unExternalHandle auxH)
      kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      derive mech frame n = do
        (m', [h]) <- case planDerive defaultRules m2 st mech baseH
            (encodeDeriveParams frame [kid n]) of
          KeyEffect pw fx -> do
            res <- answer m2 fx
            c <- finishCommit m2 st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta m2 (pcDelta c))
            pure (m', [hh])
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
        Just ost <- pure (resolveHandle m' h)
        pure (keyBytesOf ost)
      fPlus = encodeIkeParams 4 0 0 0 ikeSeed32 BS.empty
      fPrfDk = encodeIkeParams 4 1 0 0 ikeNi ikeNr
      fPrfK = encodeIkeParams 4 0 0 0 ikeNi ikeNr
      fIke1 = encodeIkeParams 4 0 7 auxN ikeNi ikeNr
      fExt = encodeIkeParams 4 0 0 auxN ikeSeed32 BS.empty
  gotPlus <- derive ikePlusMech fPlus 32
  assertEqual "ike prf+ KAT"
    (Just (hex "e3703ee905295e6c0141c98f382e17e9df07a5d0e7fb5d1d5eb45e117022cbb1")) gotPlus
  gotPrfDk <- derive ikePrfMech fPrfDk 32
  assertEqual "ike prf data-as-key KAT"
    (Just (hex "909be39279fec3ad8b16546a956974ee435bb4acfa8f0c9167f0f019ff977f45")) gotPrfDk
  gotPrfK <- derive ikePrfMech fPrfK 32
  assertEqual "ike prf key order KAT"
    (Just (hex "df53a0de91b1e3a8d1523ea225bbc6814065bbe96203108f45501f20467046fb")) gotPrfK
  gotIke1 <- derive ike1Mech fIke1 32
  assertEqual "ike1 prf KAT"
    (Just (hex "612802ecc378ea82898f416865a51c36ade29e1acfbe2bceb19033c95a702f5a")) gotIke1
  gotExt <- derive ikeExtMech fExt 32
  assertEqual "ike extended KAT"
    (Just (hex "1c81c4b9c9083605362e98bed89e4eef320559270ae273a55ed90710e74e6951")) gotExt

caseByteOpsPlans :: IO ()
caseByteOpsPlans = do
  m0 <- seedModel
  st <- getSession m0
  -- Explicitly unsealed fixtures: this case pins the row
  -- shapes (including shortening rows), and sealed inputs
  -- refuse shortening derives.
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 31])
  (m2, auxH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [32 .. 63])
  let auxN = fromIntegral (unExternalHandle auxH)
      kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      kidNoLen =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        ]
      fKey = encodeByteOpsParams auxN 0 BS.empty
      fBD = encodeByteOpsParams 0 0 byteOpsD16
      fXor = encodeByteOpsParams 0 0 (BS.pack [0 .. 31])
      fExt = encodeByteOpsParams 0 0 BS.empty
  -- Each row plans with its frame; concat-key binds fxKey2.
  mapM_ (\(mech, frame, n, needsAux) ->
    case planDerive defaultRules m2 st mech baseH
        (encodeDeriveParams frame [kid n]) of
      KeyEffect _ (FxDerive _ _ mAux _ _ total) -> do
        assertEqual ("total " ++ show mech) n total
        assertEqual ("aux " ++ show mech) needsAux (mAux /= Nothing)
      other -> assertFailure ("must plan, got: " ++ show other))
    [ (concatKeyMech, fKey, 64, True)
    , (concatDataMech, fBD, 16, False)
    , (dataConcatMech, fBD, 16, False)
    , (xorMech, fXor, 16, False)
    , (extractMech, fExt, 16, False)
    ]
  -- Concat rows default a missing length to the full width.
  case planDerive defaultRules m2 st concatDataMech baseH
      (encodeDeriveParams fBD [kidNoLen]) of
    KeyEffect _ (FxDerive _ _ _ _ _ total) ->
      assertEqual "natural total" 48 total
    other -> assertFailure ("must default, got: " ++ show other)
  -- A wrong-row frame refuses typed.
  case planDerive defaultRules m2 st concatKeyMech baseH
      (encodeDeriveParams fBD [kid 16]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrong-row code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("wrong row must deny, got: " ++ show other)
  -- Output past the natural width refuses typed.
  case planDerive defaultRules m2 st concatDataMech baseH
      (encodeDeriveParams fBD [kid 49]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "natural code" CKR_KEY_SIZE_RANGE code
    other -> assertFailure ("over-natural must deny, got: " ++ show other)
  -- XOR over unequal lengths covers the shorter operand
  -- (§6.43.6): the 16-byte data admits 16, and 17 refuses typed
  -- like every over-natural byte-op request.
  case planDerive defaultRules m2 st xorMech baseH
      (encodeDeriveParams fBD [kid 16]) of
    KeyEffect _ (FxDerive _ _ _ _ _ total) ->
      assertEqual "xor shorter-operand total" 16 total
    other -> assertFailure ("xor over unequal lengths must plan, got: " ++ show other)
  case planDerive defaultRules m2 st xorMech baseH
      (encodeDeriveParams fBD [kid 17]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "xor past the shorter length" CKR_KEY_SIZE_RANGE code
    other -> assertFailure ("xor past the shorter length must deny, got: " ++ show other)
  -- EXTRACT without a template length refuses typed.
  case planDerive defaultRules m2 st extractMech baseH
      (encodeDeriveParams fExt [kidNoLen]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "extract code" CKR_TEMPLATE_INCOMPLETE code
    other -> assertFailure ("extract no-len must deny, got: " ++ show other)
  -- EXTRACT past the base end refuses typed.
  case planDerive defaultRules m2 st extractMech baseH
      (encodeDeriveParams (encodeByteOpsParams 0 248 BS.empty) [kid 16]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "overrun code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("overrun must deny, got: " ++ show other)
  -- An unknown second handle denies typed.
  case planDerive defaultRules m2 st concatKeyMech baseH
      (encodeDeriveParams (encodeByteOpsParams 999999 0 BS.empty) [kid 64]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "aux code" CKR_KEY_HANDLE_INVALID code
    other -> assertFailure ("bad aux must deny, got: " ++ show other)

-- | A sealed byte-op input (sensitive, or unextractable, on the
-- effective view) cannot mint a shorter child: EXTRACT refuses,
-- short-data XOR refuses, a template length below the natural
-- width refuses, and a child key type outside the allow-list
-- refuses even at full width. Full-width allow-listed derives
-- still plan, and unsealed inputs keep every row.
caseSealedByteOpsRefuse :: IO ()
caseSealedByteOpsRefuse = do
  m0 <- seedModel
  st <- getSession m0
  let sealedTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        , (AttrSensitive, ValBool True)
        , (AttrExtractable, ValBool False)
        ]
      openTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        , (AttrSensitive, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
  (m1, sealedH) <- plantKey m0 st sealedTmpl (BS.pack [0 .. 31])
  (m2, sealedAuxH) <- plantKey m1 st sealedTmpl (BS.pack [32 .. 63])
  (m3, openH) <- plantKey m2 st openTmpl (BS.pack [64 .. 95])
  (m4, openAuxH) <- plantKey m3 st openTmpl (BS.pack [96 .. 127])
  (m5, sealed16H) <- plantKey m4 st sealedTmpl (BS.pack [0 .. 15])
  (m6, sealed16AuxH) <- plantKey m5 st sealedTmpl (BS.pack [16 .. 31])
  (m7, sealed24H) <- plantKey m6 st sealedTmpl (BS.pack [32 .. 55])
  let sealedAuxN = fromIntegral (unExternalHandle sealedAuxH)
      openAuxN = fromIntegral (unExternalHandle openAuxH)
      sealed16AuxN = fromIntegral (unExternalHandle sealed16AuxH)
      kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      kidNoLen =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        ]
      kidNoType :: Int -> [(AttributeType, AttributeValue)]
      kidNoType n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      fExt = encodeByteOpsParams 0 0 BS.empty
      fExtOff = encodeByteOpsParams 0 64 BS.empty
      fShort = encodeByteOpsParams 0 0 (BS.pack (replicate 16 0))
      fFull = encodeByteOpsParams 0 0 (BS.pack (replicate 32 0))
      fLong = encodeByteOpsParams 0 0 (BS.pack (replicate 48 0))
      fEmpty = encodeByteOpsParams 0 0 BS.empty
      fData8 = encodeByteOpsParams 0 0 (BS.pack (replicate 8 0))
      fFull24 = encodeByteOpsParams 0 0 (BS.pack (replicate 24 0))
      fKeySealed = encodeByteOpsParams sealedAuxN 0 BS.empty
      fKeyOpen = encodeByteOpsParams openAuxN 0 BS.empty
      fKeySealed16 = encodeByteOpsParams sealed16AuxN 0 BS.empty
      kidTyped kty =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong kty)
        , (AttrToken, ValBool False)
        ]
      kidTypedLen :: Word64 -> Int -> [(AttributeType, AttributeValue)]
      kidTypedLen kty n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong kty)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      refuses label code mech base frame tmpl =
        case planDerive defaultRules m7 st mech base (encodeDeriveParams frame [tmpl]) of
          KeyDenied (KeyDeny got _) -> assertEqual label code got
          other -> assertFailure (label ++ " must deny, got: " ++ show other)
      plans label total mech base frame tmpl =
        case planDerive defaultRules m7 st mech base (encodeDeriveParams frame [tmpl]) of
          KeyEffect _ (FxDerive _ _ _ _ _ got) -> assertEqual label total got
          other -> assertFailure (label ++ " must plan, got: " ++ show other)
  -- EXTRACT on a sealed base refuses, at any offset and length.
  refuses "sealed extract 1 byte" CKR_KEY_FUNCTION_NOT_PERMITTED
    extractMech sealedH fExt (kid 1)
  refuses "sealed extract offset" CKR_KEY_FUNCTION_NOT_PERMITTED
    extractMech sealedH fExtOff (kid 1)
  refuses "sealed extract full width" CKR_KEY_FUNCTION_NOT_PERMITTED
    extractMech sealedH fExt (kid 32)
  refuses "sealed extract no length" CKR_KEY_FUNCTION_NOT_PERMITTED
    extractMech sealedH fExt kidNoLen
  -- Short-data XOR on a sealed base refuses, with or without a length.
  refuses "sealed xor short data" CKR_KEY_FUNCTION_NOT_PERMITTED
    xorMech sealedH fShort (kid 16)
  refuses "sealed xor short data no length" CKR_KEY_FUNCTION_NOT_PERMITTED
    xorMech sealedH fShort kidNoLen
  -- Truncating lengths on sealed inputs refuse inconsistent.
  refuses "sealed xor truncation" CKR_TEMPLATE_INCONSISTENT
    xorMech sealedH fFull (kid 16)
  refuses "sealed concat-data truncation" CKR_TEMPLATE_INCONSISTENT
    concatDataMech sealedH fShort (kid 16)
  refuses "sealed concat-data-base truncation" CKR_TEMPLATE_INCONSISTENT
    dataConcatMech sealedH fShort (kid 16)
  refuses "sealed concat-key truncation" CKR_TEMPLATE_INCONSISTENT
    concatKeyMech sealedH fKeySealed (kid 32)
  refuses "sealed base open aux truncation" CKR_TEMPLATE_INCONSISTENT
    concatKeyMech sealedH fKeyOpen (kid 32)
  refuses "open base sealed aux truncation" CKR_TEMPLATE_INCONSISTENT
    concatKeyMech openH fKeySealed (kid 32)
  -- A fixed-length template key type without CKA_VALUE_LEN fills
  -- in that type's length: below the natural width it refuses the
  -- same way as an explicit short length.
  mapM_ (\(label, mech, frame) ->
    mapM_ (\(tlabel, kty) ->
      refuses (label ++ " " ++ tlabel) CKR_TEMPLATE_INCONSISTENT
        mech sealedH frame (kidTyped kty))
      [ ("DES/8", ckkDes)
      , ("DES3/24", ckkDes3)
      , ("ChaCha20/32", ckkChacha20)
      , ("Poly1305/32", ckkPoly1305)
      ])
    [ ("sealed concat-data typelen", concatDataMech, fShort)
    , ("sealed data-concat typelen", dataConcatMech, fShort)
    , ("sealed concat-key typelen", concatKeyMech, fKeySealed)
    ]
  refuses "sealed xor typelen DES/8" CKR_TEMPLATE_INCONSISTENT
    xorMech sealedH fFull (kidTyped ckkDes)
  refuses "sealed xor typelen DES3/24" CKR_TEMPLATE_INCONSISTENT
    xorMech sealedH fFull (kidTyped ckkDes3)
  -- A DES3 child at the natural width reaches the child-type
  -- gate: a known part of a DES3 key reduces the sealed bytes to
  -- DES-strength search, so it refuses (planned on the base
  -- revision, where DES3 was allow-listed).
  refuses "sealed concat-data DES3/24" CKR_TEMPLATE_INCONSISTENT
    concatDataMech sealed16H fData8 (kidTyped ckkDes3)
  refuses "sealed xor DES3/24" CKR_TEMPLATE_INCONSISTENT
    xorMech sealed24H fFull24 (kidTyped ckkDes3)
  -- A 16+16 concat-key reaches the gate for Poly1305/32: the
  -- floor (32) and the type domain (32) both pass, so only the
  -- gate refuses. The reason names the allow-list, telling the
  -- gate apart from the floor and domain checks sharing the code.
  case planDerive defaultRules m7 st concatKeyMech sealed16H
      (encodeDeriveParams fKeySealed16 [kidTyped ckkPoly1305]) of
    KeyDenied (KeyDeny got reason) -> do
      assertEqual "sealed concat-key Poly1305/32"
        CKR_TEMPLATE_INCONSISTENT got
      assertEqual "sealed concat-key Poly1305/32 reason"
        "sealed byte-op child key type is outside the allow-list"
        reason
    other -> assertFailure
      ("sealed concat-key Poly1305/32 must deny, got: " ++ show other)
  -- A sealed concat-key aux triggers the type-length rule even
  -- when the base is open.
  mapM_ (\(tlabel, kty) ->
    refuses ("open base sealed aux typelen " ++ tlabel) CKR_TEMPLATE_INCONSISTENT
      concatKeyMech openH fKeySealed (kidTyped kty))
    [ ("DES/8", ckkDes)
    , ("DES3/24", ckkDes3)
    , ("ChaCha20/32", ckkChacha20)
    , ("Poly1305/32", ckkPoly1305)
    ]
  -- A full-width child of a leak-prone type refuses even at the
  -- natural width: the child's own mechanism would expose the
  -- sealed bytes (the child-type allow-list gate).
  refuses "sealed xor typelen Poly1305/32" CKR_TEMPLATE_INCONSISTENT
    xorMech sealedH fFull (kidTyped ckkPoly1305)
  refuses "sealed concat-data Poly1305/32" CKR_TEMPLATE_INCONSISTENT
    concatDataMech sealedH fEmpty (kidTyped ckkPoly1305)
  refuses "sealed data-concat Poly1305/32" CKR_TEMPLATE_INCONSISTENT
    dataConcatMech sealedH fEmpty (kidTyped ckkPoly1305)
  refuses "sealed concat-key Poly1305/64" CKR_TEMPLATE_INCONSISTENT
    concatKeyMech sealedH fKeySealed (kidTypedLen ckkPoly1305 64)
  refuses "open base sealed aux concat-key Poly1305/64" CKR_TEMPLATE_INCONSISTENT
    concatKeyMech openH fKeySealed (kidTypedLen ckkPoly1305 64)
  refuses "sealed concat-data RC2/48" CKR_TEMPLATE_INCONSISTENT
    concatDataMech sealedH fShort (kidTypedLen ckkRc2 48)
  refuses "sealed concat-data RC4/48" CKR_TEMPLATE_INCONSISTENT
    concatDataMech sealedH fShort (kidTypedLen ckkRc4 48)
  refuses "sealed data-concat RC2/48" CKR_TEMPLATE_INCONSISTENT
    dataConcatMech sealedH fShort (kidTypedLen ckkRc2 48)
  refuses "sealed data-concat RC4/48" CKR_TEMPLATE_INCONSISTENT
    dataConcatMech sealedH fShort (kidTypedLen ckkRc4 48)
  refuses "sealed xor RC2/32" CKR_TEMPLATE_INCONSISTENT
    xorMech sealedH fFull (kidTypedLen ckkRc2 32)
  refuses "sealed xor RC4/32" CKR_TEMPLATE_INCONSISTENT
    xorMech sealedH fFull (kidTypedLen ckkRc4 32)
  refuses "sealed concat-key RC2/64" CKR_TEMPLATE_INCONSISTENT
    concatKeyMech sealedH fKeySealed (kidTypedLen ckkRc2 64)
  refuses "sealed concat-key RC4/64" CKR_TEMPLATE_INCONSISTENT
    concatKeyMech sealedH fKeySealed (kidTypedLen ckkRc4 64)
  refuses "open base sealed aux concat-key RC2/64" CKR_TEMPLATE_INCONSISTENT
    concatKeyMech openH fKeySealed (kidTypedLen ckkRc2 64)
  refuses "open base sealed aux concat-key RC4/64" CKR_TEMPLATE_INCONSISTENT
    concatKeyMech openH fKeySealed (kidTypedLen ckkRc4 64)
  -- An allow-listed type at the natural width still plans.
  plans "sealed xor typelen ChaCha20/32" 32
    xorMech sealedH fFull (kidTyped ckkChacha20)
  plans "sealed xor AES/32" 32
    xorMech sealedH fFull (kidTypedLen ckkAes 32)
  plans "sealed xor HMAC/32" 32
    xorMech sealedH fFull (kidTypedLen ckkSha256Hmac 32)
  -- Full-width derives on sealed inputs still plan.
  plans "sealed concat-data default" 48 concatDataMech sealedH fShort kidNoLen
  plans "sealed concat-data full" 48 concatDataMech sealedH fShort (kid 48)
  plans "sealed data-concat default" 48 dataConcatMech sealedH fShort kidNoLen
  plans "sealed xor default" 32 xorMech sealedH fFull kidNoLen
  plans "sealed xor full" 32 xorMech sealedH fFull (kid 32)
  -- A sealed template without CKA_KEY_TYPE takes the generic
  -- default and still plans.
  plans "sealed xor full no key type" 32
    xorMech sealedH fFull (kidNoType 32)
  plans "sealed xor long data default" 32 xorMech sealedH fLong kidNoLen
  plans "sealed concat-key default" 64 concatKeyMech sealedH fKeySealed kidNoLen
  plans "sealed concat-key full" 64 concatKeyMech sealedH fKeySealed (kid 64)
  -- Unsealed inputs keep every row, including shortening ones.
  plans "open extract 1 byte" 1 extractMech openH fExt (kid 1)
  plans "open xor short data" 16 xorMech openH fShort kidNoLen
  plans "open xor truncation" 16 xorMech openH fFull (kid 16)
  plans "open concat-data truncation" 16 concatDataMech openH fShort (kid 16)
  plans "open concat-key truncation" 32 concatKeyMech openH fKeyOpen (kid 32)
  -- Unsealed controls for the refused types: RC2, RC4, Poly1305
  -- and DES3 byte-op children still plan on the open base.
  plans "open xor typelen Poly1305/32" 32
    xorMech openH fFull (kidTyped ckkPoly1305)
  plans "open xor RC2/32" 32
    xorMech openH fFull (kidTypedLen ckkRc2 32)
  plans "open xor RC4/32" 32
    xorMech openH fFull (kidTypedLen ckkRc4 32)
  plans "open concat-data DES3/24" 24
    concatDataMech openH fData8 (kidTyped ckkDes3)

-- | A sealed base refuses the IKEv1-extended truncation shape (no
-- aux key, empty extra data): the driver would return raw base
-- bytes. The same request with extra data goes through the PRF
-- and still plans, as does the unsealed truncation.
caseSealedIkeTruncRefuse :: IO ()
caseSealedIkeTruncRefuse = do
  m0 <- seedModel
  st <- getSession m0
  let sealedTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        , (AttrSensitive, ValBool True)
        , (AttrExtractable, ValBool False)
        ]
      openTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        , (AttrSensitive, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
  (m1, sealedH) <- plantKey m0 st sealedTmpl (BS.pack [0 .. 31])
  (m2, openH) <- plantKey m1 st openTmpl (BS.pack [64 .. 95])
  (m3, sealedHmacH) <- plantKey m2 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkSha256Hmac)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool True)
    , (AttrExtractable, ValBool False)
    ] (BS.pack [128 .. 159])
  let kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      trunc = encodeIkeParams 4 0 0 0 BS.empty BS.empty
      withExtra = encodeIkeParams 4 0 0 0 ikeSeed32 BS.empty
      refuses label base frame tmpl =
        case planDerive defaultRules m3 st ikeExtMech base (encodeDeriveParams frame [tmpl]) of
          KeyDenied (KeyDeny got _) ->
            assertEqual label CKR_KEY_FUNCTION_NOT_PERMITTED got
          other -> assertFailure (label ++ " must deny, got: " ++ show other)
      plans label total base frame tmpl =
        case planDerive defaultRules m3 st ikeExtMech base (encodeDeriveParams frame [tmpl]) of
          KeyEffect _ (FxDerive _ _ _ _ _ got) -> assertEqual label total got
          other -> assertFailure (label ++ " must plan, got: " ++ show other)
  refuses "sealed ike truncation" sealedH trunc (kid 16)
  refuses "sealed ike truncation full width" sealedH trunc (kid 32)
  refuses "sealed hmac ike truncation" sealedHmacH trunc (kid 16)
  plans "sealed ike with extra data" 32 sealedH withExtra (kid 32)
  plans "open ike truncation" 16 openH trunc (kid 16)

caseRealByteOpsVector :: IO ()
caseRealByteOpsVector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  -- Explicitly unsealed fixtures: this case pins the
  -- executed output bytes (including shortening rows), and
  -- sealed inputs refuse shortening derives.
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 31])
  (m2, auxH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [32 .. 63])
  let auxN = fromIntegral (unExternalHandle auxH)
      kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      derive mech frame n = do
        (m', [h]) <- case planDerive defaultRules m2 st mech baseH
            (encodeDeriveParams frame [kid n]) of
          KeyEffect pw fx -> do
            res <- answer m2 fx
            c <- finishCommit m2 st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta m2 (pcDelta c))
            pure (m', [hh])
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
        Just ost <- pure (resolveHandle m' h)
        pure (keyBytesOf ost)
      fKey = encodeByteOpsParams auxN 0 BS.empty
      fBD = encodeByteOpsParams 0 0 byteOpsD16
      fXor = encodeByteOpsParams 0 0 (BS.pack (replicate 32 0x0f))
      fExt = encodeByteOpsParams 0 0 BS.empty
      fExt4 = encodeByteOpsParams 0 4 BS.empty
  gotKey <- derive concatKeyMech fKey 64
  assertEqual "concat-key KAT"
    (Just (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")) gotKey
  gotBD <- derive concatDataMech fBD 48
  assertEqual "concat-data KAT"
    (Just (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f01010101010101010101010101010101")) gotBD
  gotDB <- derive dataConcatMech fBD 48
  assertEqual "data-concat KAT"
    (Just (hex "01010101010101010101010101010101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")) gotDB
  gotXor <- derive xorMech fXor 32
  assertEqual "xor KAT"
    (Just (hex "0f0e0d0c0b0a090807060504030201001f1e1d1c1b1a19181716151413121110")) gotXor
  gotExt <- derive extractMech fExt 16
  assertEqual "extract KAT"
    (Just (hex "000102030405060708090a0b0c0d0e0f")) gotExt
  gotExt4 <- derive extractMech fExt4 2
  assertEqual "extract sub-byte KAT" (Just (hex "0010")) gotExt4

-- | The delta a key plan would publish: denials carry no objects
-- (empty delta); immediate outcomes carry their own delta; an
-- effect would allocate its pending objects on finish, so it maps
-- to a sentinel allocation at the model's next id (a plan that
-- allocates fails the size check instead of passing it).
denialDelta :: Model -> KeyPlan -> StateDelta
denialDelta m plan = case plan of
  KeyDenied _ -> StateDelta []
  KeyImmediate pr -> case pr of
    Immediate pc -> pcDelta pc
    Reject rej -> rejDelta rej
    Execute _ _ -> StateDelta [DeltaCreateObject (ObjectId (mNextObject m))]
  KeyEffect _ _ -> StateDelta [DeltaCreateObject (ObjectId (mNextObject m))]

-- | Byte-operation protection inheritance (PKCS #11 3.2 §6.43.3–§6.43.7,
-- finding TS4): a template that explicitly downgrades inherited
-- protection refuses 'CKR_TEMPLATE_INCONSISTENT'; matching and
-- omitted attributes resolve to the sealed flags and retain through
-- finish/publication, with exact output bytes, readback refusal and
-- wrap refusal. Split-flag sources prove the two rules are
-- independent on every row, aux-only and mixed concat-key inputs
-- combine, length boundaries, the history-attribute audit and two
-- unaffected-rule controls (unprotected byte-op inputs, HKDF over a
-- protected base) pin the scope: the byte-operation rules apply to
-- the named mechanisms only. Byte ops need no backend crypto, so
-- the synthetic driver serves the retained chain.
caseByteOpsProtection :: IO ()
caseByteOpsProtection = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let secretAttrs prot =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        ] ++ prot
      protFlags = [(AttrSensitive, ValBool True), (AttrExtractable, ValBool False)]
      plainFlags = [(AttrSensitive, ValBool False), (AttrExtractable, ValBool True)]
      sensOnlyFlags = [(AttrSensitive, ValBool True), (AttrExtractable, ValBool True)]
      unextrOnlyFlags = [(AttrSensitive, ValBool False), (AttrExtractable, ValBool False)]
      baseMat = BS.pack [0 .. 31]
      auxMat = BS.pack [32 .. 63]
  (m1, protBaseH) <- plantKey m0 st (secretAttrs protFlags) baseMat
  (m2, plainBaseH) <- plantKey m1 st (secretAttrs plainFlags) baseMat
  (m3, protAuxH) <- plantKey m2 st (secretAttrs protFlags) auxMat
  (m4, plainAuxH) <- plantKey m3 st (secretAttrs plainFlags) auxMat
  (m4s, sensOnlyH) <- plantKey m4 st (secretAttrs sensOnlyFlags) baseMat
  (m4u, unextrOnlyH) <- plantKey m4s st (secretAttrs unextrOnlyFlags) baseMat
  (m5, wrapH) <- plantKey m4u st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    ] (BS.pack [64 .. 95])
  let protAuxN = fromIntegral (unExternalHandle protAuxH)
      plainAuxN = fromIntegral (unExternalHandle plainAuxH)
      sensAuxN = fromIntegral (unExternalHandle sensOnlyH)
      unextrAuxN = fromIntegral (unExternalHandle unextrOnlyH)
      kid :: Int -> [(AttributeType, AttributeValue)] -> [(AttributeType, AttributeValue)]
      kid n prot =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ] ++ prot
      kidDown n = kid n plainFlags
      kidMatch n = kid n protFlags
      kidOmit n = kid n []
      kidOmitNoLen =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        ]
      fKeyProtAux = encodeByteOpsParams protAuxN 0 BS.empty
      fKeyPlainAux = encodeByteOpsParams plainAuxN 0 BS.empty
      fKeySensAux = encodeByteOpsParams sensAuxN 0 BS.empty
      fKeyUnextrAux = encodeByteOpsParams unextrAuxN 0 BS.empty
      fBD = encodeByteOpsParams 0 0 byteOpsD16
      fXor = encodeByteOpsParams 0 0 (BS.pack [0 .. 31])
      fExt = encodeByteOpsParams 0 0 BS.empty
      assertSealed tag attrs = do
        assertEqual (tag ++ " sensitive")
          (Just (ValBool True)) (Map.lookup AttrSensitive attrs)
        assertEqual (tag ++ " extractable")
          (Just (ValBool False)) (Map.lookup AttrExtractable attrs)
      pendingSealed tag plan = case plan of
        KeyEffect (PwDerive (po : _) _) _ -> assertSealed tag (poAttrs po)
        other -> assertFailure (tag ++ " must plan sealed, got: " ++ show other)
  -- Every row refuses an explicit downgrade of a protected base
  -- at the natural width (below it the sealed shortening refusal
  -- would answer first with the same code; the extract row
  -- refuses the sealed base before the template merge, so its
  -- code is the permission refusal).
  mapM_ (\(mech, frame, n, code) ->
    case planDerive defaultRules m5 st mech protBaseH
        (encodeDeriveParams frame [kidDown n]) of
      KeyDenied (KeyDeny got _) ->
        assertEqual ("downgrade code " ++ show mech) code got
      other -> assertFailure ("downgrade must deny, got: " ++ show other))
    [ (concatKeyMech, fKeyPlainAux, 64, CKR_TEMPLATE_INCONSISTENT)
    , (concatDataMech, fBD, 48, CKR_TEMPLATE_INCONSISTENT)
    , (dataConcatMech, fBD, 48, CKR_TEMPLATE_INCONSISTENT)
    , (xorMech, fXor, 32, CKR_TEMPLATE_INCONSISTENT)
    , (extractMech, fExt, 16, CKR_KEY_FUNCTION_NOT_PERMITTED)
    ]
  -- Aux-only concat-key protection: the protected second input
  -- alone refuses a downgrade and seals an omitted template.
  case planDerive defaultRules m5 st concatKeyMech plainBaseH
      (encodeDeriveParams fKeyProtAux [kidDown 64]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "aux-only downgrade code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("aux-only downgrade must deny, got: " ++ show other)
  pendingSealed "aux-only omitted" (planDerive defaultRules m5 st concatKeyMech plainBaseH
    (encodeDeriveParams fKeyProtAux [kidOmit 64]))
  -- Split-flag sources prove the two rules are independent on every
  -- row: each flag alone refuses its own downgrade, stamps only
  -- itself when omitted (the unrequired flag inherits the
  -- source-effective value), and passes its own matching template
  -- through. Downgrade, match and omitted legs all run at the
  -- natural width (below it the sealed shortening refusal would
  -- answer first with the same code); the extract row refuses
  -- outright on either flag (separate block below).
  mapM_ (\(mech, frame, downN, fullN) -> do
    case planDerive defaultRules m5 st mech sensOnlyH
        (encodeDeriveParams frame [kidDown downN]) of
      KeyDenied (KeyDeny code _) ->
        assertEqual ("sens-only downgrade " ++ show mech) CKR_TEMPLATE_INCONSISTENT code
      other -> assertFailure ("sens-only downgrade must deny, got: " ++ show other)
    case planDerive defaultRules m5 st mech sensOnlyH
        (encodeDeriveParams frame [kid fullN sensOnlyFlags]) of
      KeyEffect (PwDerive (po : _) _) _ -> do
        assertEqual ("sens-only match sensitive " ++ show mech)
          (Just (ValBool True)) (Map.lookup AttrSensitive (poAttrs po))
        assertEqual ("sens-only match extractable " ++ show mech)
          (Just (ValBool True)) (Map.lookup AttrExtractable (poAttrs po))
      other -> assertFailure ("sens-only match must plan, got: " ++ show other)
    case planDerive defaultRules m5 st mech sensOnlyH
        (encodeDeriveParams frame [kidOmit fullN]) of
      KeyEffect (PwDerive (po : _) _) _ -> do
        assertEqual ("sens-only omitted sensitive " ++ show mech)
          (Just (ValBool True)) (Map.lookup AttrSensitive (poAttrs po))
        assertEqual ("sens-only omitted extractable " ++ show mech)
          (Just (ValBool True)) (Map.lookup AttrExtractable (poAttrs po))
        assertEqual ("sens-only omitted always " ++ show mech)
          (Just (ValBool False)) (Map.lookup AttrAlwaysSensitive (poAttrs po))
        assertEqual ("sens-only omitted never " ++ show mech)
          (Just (ValBool False)) (Map.lookup AttrNeverExtractable (poAttrs po))
        assertEqual ("sens-only omitted local " ++ show mech)
          (Just (ValBool False)) (Map.lookup AttrLocal (poAttrs po))
        assertEqual ("sens-only omitted kgm " ++ show mech)
          (Just (ValULong maxBound)) (Map.lookup AttrKeyGenMechanism (poAttrs po))
      other -> assertFailure ("sens-only omitted must plan, got: " ++ show other)
    case planDerive defaultRules m5 st mech unextrOnlyH
        (encodeDeriveParams frame [kidDown downN]) of
      KeyDenied (KeyDeny code _) ->
        assertEqual ("unextr-only downgrade " ++ show mech) CKR_TEMPLATE_INCONSISTENT code
      other -> assertFailure ("unextr-only downgrade must deny, got: " ++ show other)
    case planDerive defaultRules m5 st mech unextrOnlyH
        (encodeDeriveParams frame [kid fullN unextrOnlyFlags]) of
      KeyEffect (PwDerive (po : _) _) _ -> do
        assertEqual ("unextr-only match sensitive " ++ show mech)
          (Just (ValBool False)) (Map.lookup AttrSensitive (poAttrs po))
        assertEqual ("unextr-only match extractable " ++ show mech)
          (Just (ValBool False)) (Map.lookup AttrExtractable (poAttrs po))
      other -> assertFailure ("unextr-only match must plan, got: " ++ show other)
    case planDerive defaultRules m5 st mech unextrOnlyH
        (encodeDeriveParams frame [kidOmit fullN]) of
      KeyEffect (PwDerive (po : _) _) _ -> do
        assertEqual ("unextr-only omitted sensitive " ++ show mech)
          (Just (ValBool False)) (Map.lookup AttrSensitive (poAttrs po))
        assertEqual ("unextr-only omitted extractable " ++ show mech)
          (Just (ValBool False)) (Map.lookup AttrExtractable (poAttrs po))
        assertEqual ("unextr-only omitted always " ++ show mech)
          (Just (ValBool False)) (Map.lookup AttrAlwaysSensitive (poAttrs po))
        assertEqual ("unextr-only omitted never " ++ show mech)
          (Just (ValBool False)) (Map.lookup AttrNeverExtractable (poAttrs po))
        assertEqual ("unextr-only omitted local " ++ show mech)
          (Just (ValBool False)) (Map.lookup AttrLocal (poAttrs po))
        assertEqual ("unextr-only omitted kgm " ++ show mech)
          (Just (ValULong maxBound)) (Map.lookup AttrKeyGenMechanism (poAttrs po))
      other -> assertFailure ("unextr-only omitted must plan, got: " ++ show other))
    [ (concatKeyMech, fKeyPlainAux, 64, 64)
    , (concatDataMech, fBD, 48, 48)
    , (dataConcatMech, fBD, 48, 48)
    , (xorMech, fXor, 32, 32)
    ]
  -- Either flag alone seals the base for the extract row:
  -- downgrade, matching and omitted templates all refuse
  -- with the permission code.
  mapM_ (\(tag, base, matchFlags) ->
    mapM_ (\(tmplTag, tmpl) ->
      case planDerive defaultRules m5 st extractMech base
          (encodeDeriveParams fExt [tmpl]) of
        KeyDenied (KeyDeny code _) ->
          assertEqual (tag ++ " extract " ++ tmplTag) CKR_KEY_FUNCTION_NOT_PERMITTED code
        other -> assertFailure (tag ++ " extract must deny, got: " ++ show other))
      [ ("downgrade", kidDown 16)
      , ("match", kid 16 matchFlags)
      , ("omitted", kidOmit 16)
      ])
    [("sens-only", sensOnlyH, sensOnlyFlags), ("unextr-only", unextrOnlyH, unextrOnlyFlags)]
  -- Mixed inputs combine: a sensitivity-only base plus a
  -- nonextractable-only aux requires both flags, in either
  -- direction.
  case planDerive defaultRules m5 st concatKeyMech sensOnlyH
      (encodeDeriveParams fKeyUnextrAux [kidDown 64]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "mixed downgrade code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("mixed downgrade must deny, got: " ++ show other)
  pendingSealed "mixed omitted" (planDerive defaultRules m5 st concatKeyMech sensOnlyH
    (encodeDeriveParams fKeyUnextrAux [kidOmit 64]))
  pendingSealed "mixed reversed omitted" (planDerive defaultRules m5 st concatKeyMech unextrOnlyH
    (encodeDeriveParams fKeySensAux [kidOmit 64]))
  -- Matching passes through and omitted stamps (full-width
  -- rows); an omitted length still defaults to the natural
  -- width with the sealed flags. The extract row refuses the
  -- sealed base at any length.
  pendingSealed "match" (planDerive defaultRules m5 st concatKeyMech protBaseH
    (encodeDeriveParams fKeyPlainAux [kidMatch 64]))
  pendingSealed "omitted" (planDerive defaultRules m5 st concatDataMech protBaseH
    (encodeDeriveParams fBD [kidOmit 48]))
  case planDerive defaultRules m5 st concatDataMech protBaseH
      (encodeDeriveParams fBD [kidOmitNoLen]) of
    KeyEffect (PwDerive (po : _) _) (FxDerive _ _ _ _ _ total) -> do
      assertEqual "natural total" 48 total
      assertSealed "natural omitted" (poAttrs po)
    other -> assertFailure ("natural default must plan, got: " ++ show other)
  case planDerive defaultRules m5 st extractMech protBaseH
      (encodeDeriveParams fExt [kidMatch 16]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "sealed extract code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("sealed extract must deny, got: " ++ show other)
  -- Boundaries with protection: the sealed base refuses extract
  -- before the window check, so even a past-the-end request
  -- reports the permission refusal.
  case planDerive defaultRules m5 st extractMech protBaseH
      (encodeDeriveParams fExt [kidMatch 32]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "full-length code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("full-length extract must deny, got: " ++ show other)
  case planDerive defaultRules m5 st extractMech protBaseH
      (encodeDeriveParams fExt [kidMatch 33]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "overrun code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("overrun must deny, got: " ++ show other)
  -- A refused derivation allocates nothing: publishing the
  -- denied plan's own delta leaves the pre-snapshot unchanged. The
  -- size check runs before the code match, so a plan that allocates
  -- fails here rather than below.
  let before = Map.size (mObjects m5)
      deniedPlan = planDerive defaultRules m5 st extractMech protBaseH
        (encodeDeriveParams fExt [kidDown 16])
  mAfterDeny <- expectRight (publishDelta m5 (denialDelta m5 deniedPlan))
  assertEqual "denied derive allocates nothing" before (Map.size (mObjects mAfterDeny))
  case deniedPlan of
    KeyDenied _ -> pure ()
    other -> assertFailure ("downgrade must deny, got: " ++ show other)
  -- The sealed flags retain through finish/publication with exact
  -- output bytes; readback and wrap then refuse typed. The
  -- full-width concat row carries the execution (extract refuses
  -- the sealed base).
  (m6, childH) <- case planDerive defaultRules m5 st concatDataMech protBaseH
      (encodeDeriveParams fBD [kidMatch 48]) of
    KeyEffect pw fx -> do
      res <- answer m5 fx
      c <- finishCommit m5 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m5 (pcDelta c))
      pure (m', h)
    other -> assertFailure ("sealed derive must plan: " ++ show other) >> undefined
  Just child <- pure (resolveHandle m6 childH)
  assertSealed "child" (osAttrs child)
  assertEqual "child bytes" (Just (baseMat <> byteOpsD16)) (keyBytesOf child)
  case getAttributes (osAttrs child) [AttrValue] of
    PartialReads code results -> do
      assertEqual "readback code" CKR_ATTRIBUTE_SENSITIVE code
      assertEqual "readback result" [(AttrValue, ResSensitive)] results
  Just baseOst <- pure (resolveHandle m6 protBaseH)
  case getAttributes (osAttrs baseOst) [AttrValue] of
    PartialReads bcode _ ->
      assertEqual "base stays sealed" CKR_ATTRIBUTE_SENSITIVE bcode
  case planWrapKey m6 st aesCbcMech iv16 wrapH childH IntentNull of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrap code" CKR_KEY_UNEXTRACTABLE code
    other -> assertFailure ("sealed child wrap must deny, got: " ++ show other)
  -- A key with no stored flags wraps as unextractable: the absent
  -- EXTRACTABLE reads as unextractable through the effective view.
  (mFlagless, flaglessH) <- plantKey m6 st
    [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes),
     (AttrToken, ValBool False)] (BS.pack [96..111])
  case planWrapKey mFlagless st aesCbcMech iv16 wrapH flaglessH IntentNull of
    KeyDenied (KeyDeny code _) ->
      assertEqual "flag-less wrap code" CKR_KEY_UNEXTRACTABLE code
    other -> assertFailure ("flag-less wrap must deny, got: " ++ show other)
  -- History attributes are inventoried: the names map and the
  -- mechanism-id shape is unsigned-long. Caller templates carrying
  -- them refuse inconsistent at every creation entry (the derive
  -- leg below proves the lenient choke point; generation proves
  -- the strict one).
  assertEqual "ALWAYS_SENSITIVE mapped"
    (Just AttrAlwaysSensitive) (attributeTypeByName "CKA_ALWAYS_SENSITIVE")
  assertEqual "NEVER_EXTRACTABLE mapped"
    (Just AttrNeverExtractable) (attributeTypeByName "CKA_NEVER_EXTRACTABLE")
  assertEqual "LOCAL mapped"
    (Just AttrLocal) (attributeTypeByName "CKA_LOCAL")
  assertEqual "KEY_GEN_MECHANISM mapped"
    (Just AttrKeyGenMechanism) (attributeTypeByName "CKA_KEY_GEN_MECHANISM")
  assertEqual "KGM shape" ShapeULong (shapeOf AttrKeyGenMechanism)
  -- Unaffected inputs: unprotected byte-op derivations keep the
  -- caller's readable template, and omitted attributes inherit the
  -- source-effective values (inherit-or-default when nothing is
  -- required).
  case planDerive defaultRules m5 st extractMech plainBaseH
      (encodeDeriveParams fExt [kidDown 16]) of
    KeyEffect (PwDerive (po : _) _) _ -> do
      assertEqual "plain template sensitive"
        (Just (ValBool False)) (Map.lookup AttrSensitive (poAttrs po))
      assertEqual "plain template extractable"
        (Just (ValBool True)) (Map.lookup AttrExtractable (poAttrs po))
    other -> assertFailure ("plain derive must plan, got: " ++ show other)
  case planDerive defaultRules m5 st concatKeyMech plainBaseH
      (encodeDeriveParams fKeyPlainAux [kidOmit 64]) of
    KeyEffect (PwDerive (po : _) _) _ -> do
      assertEqual "plain omitted sensitive"
        (Just (ValBool False)) (Map.lookup AttrSensitive (poAttrs po))
      assertEqual "plain omitted extractable"
        (Just (ValBool True)) (Map.lookup AttrExtractable (poAttrs po))
      assertEqual "plain omitted always-sensitive"
        (Just (ValBool False)) (Map.lookup AttrAlwaysSensitive (poAttrs po))
      assertEqual "plain omitted never-extractable"
        (Just (ValBool False)) (Map.lookup AttrNeverExtractable (poAttrs po))
      assertEqual "plain omitted local"
        (Just (ValBool False)) (Map.lookup AttrLocal (poAttrs po))
      assertEqual "plain omitted key-gen mechanism"
        (Just (ValULong maxBound)) (Map.lookup AttrKeyGenMechanism (poAttrs po))
    other -> assertFailure ("plain concat-key must plan, got: " ++ show other)
  -- Over a protected base the omitted template stamps sealed: the
  -- inherited protection plus history derived from the sources
  -- (both lack stored history, so it reads false).
  case planDerive defaultRules m5 st concatKeyMech protBaseH
      (encodeDeriveParams fKeyPlainAux [kidOmit 64]) of
    KeyEffect (PwDerive (po : _) _) _ -> do
      assertEqual "protected omitted sensitive"
        (Just (ValBool True)) (Map.lookup AttrSensitive (poAttrs po))
      assertEqual "protected omitted extractable"
        (Just (ValBool False)) (Map.lookup AttrExtractable (poAttrs po))
      assertEqual "protected omitted always-sensitive"
        (Just (ValBool False)) (Map.lookup AttrAlwaysSensitive (poAttrs po))
      assertEqual "protected omitted never-extractable"
        (Just (ValBool False)) (Map.lookup AttrNeverExtractable (poAttrs po))
      assertEqual "protected omitted local"
        (Just (ValBool False)) (Map.lookup AttrLocal (poAttrs po))
      assertEqual "protected omitted key-gen mechanism"
        (Just (ValULong maxBound)) (Map.lookup AttrKeyGenMechanism (poAttrs po))
    other -> assertFailure ("protected concat-key must plan, got: " ++ show other)
  -- A base with no protection flags derives unextractable but
  -- non-sensitive: the absent EXTRACTABLE reads as unextractable
  -- through the effective view, the absent SENSITIVE as false.
  -- The full-width concat row carries the derivation (the
  -- flag-less base counts as sealed, so extract refuses it).
  (mAbsBase, absBaseH) <- plantKey m5 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] baseMat
  case planDerive defaultRules mAbsBase st concatDataMech absBaseH
      (encodeDeriveParams fBD [kidOmit 48]) of
    KeyEffect (PwDerive (po : _) _) _ -> do
      assertEqual "absent-base omitted sensitive"
        (Just (ValBool False)) (Map.lookup AttrSensitive (poAttrs po))
      assertEqual "absent-base omitted extractable"
        (Just (ValBool False)) (Map.lookup AttrExtractable (poAttrs po))
      assertEqual "absent-base omitted always-sensitive"
        (Just (ValBool False)) (Map.lookup AttrAlwaysSensitive (poAttrs po))
      assertEqual "absent-base omitted never-extractable"
        (Just (ValBool False)) (Map.lookup AttrNeverExtractable (poAttrs po))
      assertEqual "absent-base omitted local"
        (Just (ValBool False)) (Map.lookup AttrLocal (poAttrs po))
      assertEqual "absent-base omitted key-gen mechanism"
        (Just (ValULong maxBound)) (Map.lookup AttrKeyGenMechanism (poAttrs po))
    other -> assertFailure ("absent-base derive must plan, got: " ++ show other)
  -- A history attribute in the derive template refuses
  -- inconsistent and allocates nothing: publishing the denied
  -- plan's own delta leaves the pre-snapshot unchanged.
  let histBefore = Map.size (mObjects m5)
      histPlan = planDerive defaultRules m5 st concatKeyMech plainBaseH
        (encodeDeriveParams fKeyPlainAux [kidOmit 64 ++ [(AttrLocal, ValBool True)]])
  mAfterHist <- expectRight (publishDelta m5 (denialDelta m5 histPlan))
  assertEqual "refused history derive allocates nothing" histBefore (Map.size (mObjects mAfterHist))
  case histPlan of
    KeyDenied (KeyDeny code _) ->
      assertEqual "history derive code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("history derive must deny, got: " ++ show other)
  -- Unaffected family: HKDF carries no §6.43 inheritance rule, so
  -- a readable template over a protected base still plans with the
  -- caller's flags (scoping control against a global rule).
  let hkdfKid = kidDown 32
  case planDerive defaultRules m5 st hkdfDeriveMech protBaseH
      (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "p1-control") [hkdfKid]) of
    KeyEffect (PwDerive (po : _) _) _ -> do
      assertEqual "hkdf template sensitive"
        (Just (ValBool False)) (Map.lookup AttrSensitive (poAttrs po))
      assertEqual "hkdf template extractable"
        (Just (ValBool True)) (Map.lookup AttrExtractable (poAttrs po))
    other -> assertFailure ("HKDF control must plan, got: " ++ show other)

-- | A history attribute in a generation template refuses
-- inconsistent at the strict choke point and allocates nothing:
-- publishing the denied plan's own delta leaves the pre-snapshot
-- unchanged.
caseKeyTemplatesRefuseHistory :: IO ()
caseKeyTemplatesRefuseHistory = do
  m0 <- seedModel
  st <- getSession m0
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        , (AttrAlwaysSensitive, ValBool True)
        ]
      before = Map.size (mObjects m0)
      genPlan = planGenerateKey defaultRules m0 st aesKeyGenMech BS.empty tmpl
  mAfterGen <- expectRight (publishDelta m0 (denialDelta m0 genPlan))
  assertEqual "refused history generate allocates nothing" before (Map.size (mObjects mAfterGen))
  case genPlan of
    KeyDenied (KeyDeny code _) ->
      assertEqual "history generate code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("history generate must deny, got: " ++ show other)

-- | The SSL3 master template: the oracle's shape (48-byte
-- generic secret, protection matching the base).
ssl3MasterKid :: [(AttributeType, AttributeValue)]
ssl3MasterKid =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong 48)
  , (AttrSensitive, ValBool False)
  , (AttrExtractable, ValBool True)
  , (AttrToken, ValBool False)
  , (AttrDerive, ValBool True)
  ]

caseSsl3DerivePlans :: IO ()
caseSsl3DerivePlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 47])
  let fm = encodeSsl3MasterParams ssl3Cr ssl3Sr
      fk = encodeSsl3KeyMatParams 16 16 16 ssl3Cr ssl3Sr
  -- Master rows plan the fixed 48-byte output.
  mapM_ (\mech ->
    case planDerive defaultRules m1 st mech baseH
        (encodeDeriveParams fm [ssl3MasterKid]) of
      KeyEffect (PwDerive _ [48]) (FxDerive _ _ _ _ _ 48) -> pure ()
      other -> assertFailure ("master must plan, got: " ++ show other))
    [ssl3MasterMech, ssl3MasterDhMech]
  -- The keymat row plans its key/IV shape with the block total.
  case planDerive defaultRules m1 st ssl3KeyMatMech baseH
      (encodeDeriveParams fk [keyMatKid]) of
    KeyEffect (PwDeriveIv _ [16, 16, 16, 16] (16, 16)) (FxDerive _ _ _ _ _ 96) ->
      pure ()
    other -> assertFailure ("keymat must plan, got: " ++ show other)
  -- A non-generic base refuses (the key-type gate outranks shape).
  (m2, aesH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 15])
  case planDerive defaultRules m2 st ssl3MasterMech aesH
      (encodeDeriveParams fm [ssl3MasterKid]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "base code" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("AES base must deny, got: " ++ show other)
  -- A template length on keymat refuses: lengths come from params.
  case planDerive defaultRules m1 st ssl3KeyMatMech baseH
      (encodeDeriveParams fk [keyMatKid ++ [(AttrValueLen, ValULong 16)]]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "vlen code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("vlen must deny, got: " ++ show other)
  -- Protection differing from the base refuses (the oracle's
  -- template-conflict leg).
  let conflict =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrSensitive, ValBool True)
        , (AttrExtractable, ValBool True)
        , (AttrToken, ValBool False)
        ]
  case planDerive defaultRules m1 st ssl3KeyMatMech baseH
      (encodeDeriveParams fk [conflict]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "conflict code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("conflict must deny, got: " ++ show other)
  -- A malformed frame refuses typed.
  case planDerive defaultRules m1 st ssl3MasterMech baseH
      (encodeDeriveParams (BS.take 10 fm) [ssl3MasterKid]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "shape code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("bad shape must deny, got: " ++ show other)

caseRealSsl3Vector :: IO ()
caseRealSsl3Vector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [3, 0] <> BS.pack [2 .. 47])
  (m2, dhH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 31])
  let fm = encodeSsl3MasterParams ssl3Cr ssl3Sr
      deriveOne mech base tmpl = do
        (_m', mat) <- case planDerive defaultRules m2 st mech base
            (encodeDeriveParams fm [tmpl]) of
          KeyEffect pw fx -> do
            res <- answer m2 fx
            c <- finishCommit m2 st pw res 1
            let outs = pcOutputs c
            hs <- mapM handleOf [o | o@(NativeOutput (RegionHandle "key") _) <- outs]
            m' <- expectRight (publishDelta m2 (pcDelta c))
            mats <- mapM (\h -> case resolveHandle m' h of
              Just ost -> pure (keyBytesOf ost)
              Nothing -> assertFailure "derived key must resolve" >> undefined) hs
            pure (m', mats)
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
        pure mat
  [master48] <- deriveOne ssl3MasterMech baseH ssl3MasterKid
  assertEqual "master48"
    (Just (hex "faf3f20343e53bd6b6d81b3642a2f78a64e1b5837aace5b9ce41e8e14ff1140d3908bac02e5afe34652644a90dbb5f59"))
    master48
  [masterDh] <- deriveOne ssl3MasterDhMech dhH ssl3MasterKid
  assertEqual "masterDH32"
    (Just (hex "159ce46fa901e70e79d351599fd24cdc5e98c7db7921972aa8c67151657aa89232e3b01d3fb09584bfd678b52b31e302"))
    masterDh
  (m3, msH) <- plantKey m2 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (hex "faf3f20343e53bd6b6d81b3642a2f78a64e1b5837aace5b9ce41e8e14ff1140d3908bac02e5afe34652644a90dbb5f59")
  let fk = encodeSsl3KeyMatParams 16 16 16 ssl3Cr ssl3Sr
  (mats, (ivc, ivs)) <- case planDerive defaultRules m3 st ssl3KeyMatMech msH
      (encodeDeriveParams fk [keyMatKid]) of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      c <- finishCommit m3 st pw res 4
      let outs = pcOutputs c
      hs <- mapM handleOf [o | o@(NativeOutput (RegionHandle "key") _) <- outs]
      let iv n = case [bs | NativeOutput (RegionBytes m _) bs <- outs, m == n] of
            [bs] -> bs
            _ -> BS.empty
      m' <- expectRight (publishDelta m3 (pcDelta c))
      mats <- mapM (\h -> case resolveHandle m' h of
        Just ost -> pure (keyBytesOf ost)
        Nothing -> assertFailure "derived key must resolve" >> undefined) hs
      pure (mats, (iv "iv-client", iv "iv-server"))
    other -> assertFailure ("keymat must plan: " ++ show other) >> undefined
  assertEqual "keymat keys"
    [ Just (hex "698e3265825326fdf57444e2b1e45064")
    , Just (hex "cceb1267b84f81e14a1ce6c2d9696031")
    , Just (hex "f9efaf9d8e27955f638bda4d0df1d6ab")
    , Just (hex "0eca6dccabd29fdff201da989870bcea")
    ] mats
  assertEqual "keymat ivc" (hex "083ea2e07385c9580f7cf01db35d0a20") ivc
  assertEqual "keymat ivs" (hex "e601719a5c2a088bd3478436d42fe569") ivs

caseKeyMatPlans :: IO ()
caseKeyMatPlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 47])
  let f10 = encodeTlsKeyMatParams 0 0 16 16 keyMatCr keyMatSr
      f12 = encodeTlsKeyMatParams 4 0 16 16 keyMatCr keyMatSr
      f12m = encodeTlsKeyMatParams 4 20 16 16 keyMatCr keyMatSr
  -- Each row plans its key/IV shape with the block total.
  mapM_ (\(mech, frame, lens, ivs, total) ->
    case planDerive defaultRules m1 st mech baseH
        (encodeDeriveParams frame [keyMatKid]) of
      KeyEffect (PwDeriveIv _ gotLens gotIvs) (FxDerive _ _ _ _ _ gotTotal) -> do
        assertEqual ("lens " ++ show mech) lens gotLens
        assertEqual ("ivs " ++ show mech) ivs gotIvs
        assertEqual ("total " ++ show mech) total gotTotal
      other -> assertFailure ("must plan, got: " ++ show other))
    [ (keyMat10Mech, f10, [16, 16], (16, 16), 64)
    , (keyMat12Mech, f12, [16, 16], (16, 16), 64)
    , (keyMat12Mech, f12m, [20, 20, 16, 16], (16, 16), 104)
    , (keyMatSafeMech, f12, [16, 16], (0, 0), 32)
    ]
  -- A template length refuses: lengths come from params.
  case planDerive defaultRules m1 st keyMat12Mech baseH
      (encodeDeriveParams f12 [keyMatKid ++ [(AttrValueLen, ValULong 16)]]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "vlen code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("vlen must deny, got: " ++ show other)
  -- Protection differing from the base refuses (the oracle's
  -- template-conflict leg).
  let conflict =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrSensitive, ValBool True)
        , (AttrExtractable, ValBool True)
        , (AttrToken, ValBool False)
        ]
  case planDerive defaultRules m1 st keyMat10Mech baseH
      (encodeDeriveParams f10 [conflict]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "conflict code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("conflict must deny, got: " ++ show other)
  -- A wrong-row frame refuses typed.
  case planDerive defaultRules m1 st keyMat10Mech baseH
      (encodeDeriveParams f12 [keyMatKid]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrong-row code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("wrong row must deny, got: " ++ show other)

-- | Key-material protection over a base with no stored flags: the
-- absent base reads as non-sensitive and unextractable, so a
-- matching false/false template and an omitted template plan,
-- while either flag set true refuses as a conflict.
caseKeyMatAbsentBase :: IO ()
caseKeyMatAbsentBase = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 47])
  let f12 = encodeTlsKeyMatParams 4 0 16 16 keyMatCr keyMatSr
      kid prot =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        ] ++ prot
      matchFalse = kid [(AttrSensitive, ValBool False), (AttrExtractable, ValBool False)]
      omitted = kid []
      conflictSens = kid [(AttrSensitive, ValBool True), (AttrExtractable, ValBool False)]
      conflictExtr = kid [(AttrSensitive, ValBool False), (AttrExtractable, ValBool True)]
  case planDerive defaultRules m1 st keyMat12Mech baseH
      (encodeDeriveParams f12 [matchFalse]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("absent-base match must plan, got: " ++ show other)
  case planDerive defaultRules m1 st keyMat12Mech baseH
      (encodeDeriveParams f12 [omitted]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("absent-base omitted must plan, got: " ++ show other)
  case planDerive defaultRules m1 st keyMat12Mech baseH
      (encodeDeriveParams f12 [conflictSens]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "absent-base sens code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("absent-base sens must deny, got: " ++ show other)
  case planDerive defaultRules m1 st keyMat12Mech baseH
      (encodeDeriveParams f12 [conflictExtr]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "absent-base extr code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("absent-base extr must deny, got: " ++ show other)

caseRealKeyMatVector :: IO ()
caseRealKeyMatVector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 47])
  let derive mech frame nKeys = do
        (m', hs, ivs) <- case planDerive defaultRules m1 st mech baseH
            (encodeDeriveParams frame [keyMatKid]) of
          KeyEffect pw fx -> do
            res <- answer m1 fx
            c <- finishCommit m1 st pw res nKeys
            let outs = pcOutputs c
            hs <- mapM handleOf [o | o@(NativeOutput (RegionHandle "key") _) <- outs]
            let iv n = case [bs | NativeOutput (RegionBytes m _) bs <- outs, m == n] of
                  [bs] -> bs
                  _ -> BS.empty
            m' <- expectRight (publishDelta m1 (pcDelta c))
            pure (m', hs, (iv "iv-client", iv "iv-server"))
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
        mats <- mapM (\h -> case resolveHandle m' h of
          Just ost -> pure (keyBytesOf ost)
          Nothing -> assertFailure "derived key must resolve" >> undefined) hs
        pure (mats, ivs)
      f10 = encodeTlsKeyMatParams 0 0 16 16 keyMatCr keyMatSr
      f12m = encodeTlsKeyMatParams 4 20 16 16 keyMatCr keyMatSr
      fSafe = encodeTlsKeyMatParams 4 0 16 0 keyMatCr keyMatSr
  (tls10Keys, (tls10Ivc, tls10Ivs)) <- derive keyMat10Mech f10 2
  assertEqual "tls10 keys"
    [ Just (hex "f3771f99cf91858748dc50ed540edc39")
    , Just (hex "efb06a256dcd4d9ffdf87298f72cf700")
    ] tls10Keys
  assertEqual "tls10 ivc" (hex "f5585f14e9db80e3af1a7ccc2c218d42") tls10Ivc
  assertEqual "tls10 ivs" (hex "b36aa1a7584498f75edaca5bf8f86328") tls10Ivs
  (tls12Keys, (tls12Ivc, tls12Ivs)) <- derive keyMat12Mech f12m 4
  assertEqual "tls12 keys"
    [ Just (hex "fbe0dbb71e9097fcfe644317a16d334fac721a5f")
    , Just (hex "822730468a366a4ef2f2206848092b65ca8b00c3")
    , Just (hex "56742cd5bae70ed8ac35e70945a53033")
    , Just (hex "866a9b3abca98806f6ba1048b7cd53eb")
    ] tls12Keys
  assertEqual "tls12 ivc" (hex "2f2584955a68b87c9d198ce2c55c204f") tls12Ivc
  assertEqual "tls12 ivs" (hex "053dddc6f5ce4f96c242e8bb758cd5fa") tls12Ivs
  (safeKeys, (safeIvc, safeIvs)) <- derive keyMatSafeMech fSafe 2
  assertEqual "safe keys"
    [ Just (hex "fbe0dbb71e9097fcfe644317a16d334f")
    , Just (hex "ac721a5f822730468a366a4ef2f22068")
    ] safeKeys
  assertEqual "safe writes no ivs" (BS.empty, BS.empty) (safeIvc, safeIvs)

caseSp800MultiPlans :: IO ()
caseSp800MultiPlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  let kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong n)
        , (AttrToken, ValBool False)
        ]
      counter = encodeSp800Params 4 32 32 BS.empty sp800Fixed
  -- Primary plus one additional template plans two keys
  -- with the summed total (the frame-level multi path the
  -- FFI additional-keys chase feeds).
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams counter [kid 16, kid 16]) of
    KeyEffect (PwDerive _ lens) (FxDerive mech _ _ _ _ total) -> do
      assertEqual "mech" sp800CounterMech mech
      assertEqual "lens" [16, 16] lens
      assertEqual "total" 32 total
    other -> assertFailure ("multi must plan: " ++ show other)
  -- Over the fan-out the frame refuses typed.
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams counter (replicate 17 (kid 16))) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "fanout code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("fanout must deny, got: " ++ show other)

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
  case planGenerateKey defaultRules m1 st aesKeyGenMech BS.empty (aesTmpl 32) of
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
          assertEqual "code" CKR_FUNCTION_FAILED (rejCode r)
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
  let aesKemTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 32)
        , (AttrToken, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
      ctLen = kemCtLen KemMl768
  -- Encaps against an AES template mints an AES-256 object
  -- carrying the 32-byte secret.
  (m2, ct) <- case planKemEncaps m1 st mlKemMech pubH KemMl768 aesKemTmpl
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
  case planKemDecaps m2 st mlKemMech privH KemMl768 ct aesKemTmpl of
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
        filter ((/= AttrKeyType) . fst) aesKemTmpl
  case planKemEncaps m1 st mlKemMech pubH KemMl768 rsaTmpl
      (IntentBuffer (fromIntegral ctLen)) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "rsa template code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- Mechanism-contributed attributes refuse inconsistent on
  -- both entries (the finisher would otherwise silently
  -- overwrite caller bytes with the real secret).
  let injected = (AttrValue, ValBytes "injected") : aesKemTmpl
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
  let noLen = filter ((/= AttrValueLen) . fst) aesKemTmpl
  case planKemEncaps m1 st mlKemMech pubH KemMl768 noLen
      (IntentBuffer (fromIntegral ctLen)) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("must plan, got: " ++ show other)

-- | KEM outputs stamp creation history: minimal templates mint
-- defaulted protection plus false history and origin on both the
-- encapsulate and decapsulate paths, for generic-secret and AES-256
-- shapes; explicit flags win without forging history; history rows
-- in the caller template refuse.
caseKemStampsOutputHistory :: IO ()
caseKemStampsOutputHistory = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, pubH, privH) <- genKemPair answer m0 st
  let ctLen = kemCtLen KemMl768
      intent = IntentBuffer (fromIntegral ctLen)
      minimalGeneric = bareSecretTmpl ckkGenericSecret 32
      minimalAes = bareSecretTmpl ckkAes 32
      explicit = minimalGeneric ++ [(AttrSensitive, ValBool True), (AttrExtractable, ValBool True)]
  (m2, ct) <- case planKemEncaps m1 st mlKemMech pubH KemMl768 minimalGeneric intent of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      hh <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      Just ost <- pure (resolveHandle m' hh)
      assertKemHistory "encaps generic" (osAttrs ost) False False
      case pcOutputs c !! 0 of
        NativeOutput (RegionBytes "ciphertext" _) bytes -> pure (m', bytes)
        o -> assertFailure ("no ciphertext: " ++ show o) >> undefined
    other -> assertFailure ("encaps must plan, got: " ++ show other) >> undefined
  m3 <- case planKemDecaps m2 st mlKemMech privH KemMl768 ct minimalGeneric of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      hh <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m' hh)
      assertKemHistory "decaps generic" (osAttrs ost) False False
      pure m'
    other -> assertFailure ("decaps must plan, got: " ++ show other) >> undefined
  (m4, ctAes) <- case planKemEncaps m3 st mlKemMech pubH KemMl768 minimalAes intent of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      c <- finishCommit m3 st pw res 1
      hh <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m3 (pcDelta c))
      Just ost <- pure (resolveHandle m' hh)
      assertEqual "encaps aes keytype" (Just (ValULong ckkAes))
        (Map.lookup AttrKeyType (osAttrs ost))
      assertKemHistory "encaps aes" (osAttrs ost) False False
      case pcOutputs c !! 0 of
        NativeOutput (RegionBytes "ciphertext" _) bytes -> pure (m', bytes)
        o -> assertFailure ("no ciphertext: " ++ show o) >> undefined
    other -> assertFailure ("encaps aes must plan, got: " ++ show other) >> undefined
  m5 <- case planKemDecaps m4 st mlKemMech privH KemMl768 ctAes minimalAes of
    KeyEffect pw fx -> do
      res <- answer m4 fx
      c <- finishCommit m4 st pw res 1
      hh <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m4 (pcDelta c))
      Just ost <- pure (resolveHandle m' hh)
      assertKemHistory "decaps aes" (osAttrs ost) False False
      pure m'
    other -> assertFailure ("decaps aes must plan, got: " ++ show other) >> undefined
  case planKemEncaps m5 st mlKemMech pubH KemMl768 explicit intent of
    KeyEffect pw fx -> do
      res <- answer m5 fx
      c <- finishCommit m5 st pw res 1
      hh <- handleOf (pcOutputs c !! 1)
      m6 <- expectRight (publishDelta m5 (pcDelta c))
      Just ost <- pure (resolveHandle m6 hh)
      assertKemHistory "encaps explicit" (osAttrs ost) True True
      case planKemDecaps m6 st mlKemMech privH KemMl768 ct explicit of
        KeyEffect pw2 fx2 -> do
          res2 <- answer m6 fx2
          c2 <- finishCommit m6 st pw2 res2 1
          hh2 <- handleOf (pcOutputs c2 !! 0)
          m7 <- expectRight (publishDelta m6 (pcDelta c2))
          Just ost2 <- pure (resolveHandle m7 hh2)
          assertKemHistory "decaps explicit" (osAttrs ost2) True True
        other2 -> assertFailure ("decaps explicit must plan, got: " ++ show other2)
    other -> assertFailure ("encaps explicit must plan, got: " ++ show other)
  let forged = (AttrAlwaysSensitive, ValBool True) : minimalGeneric
  case planKemEncaps m5 st mlKemMech pubH KemMl768 forged intent of
    KeyDenied (KeyDeny code _) ->
      assertEqual "encaps history code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("encaps history must deny, got: " ++ show other)
  case planKemDecaps m5 st mlKemMech privH KemMl768 ct forged of
    KeyDenied (KeyDeny code _) ->
      assertEqual "decaps history code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("decaps history must deny, got: " ++ show other)

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
