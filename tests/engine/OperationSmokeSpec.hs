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
  ( AeadSpec (..)
  , BackendError (..)
  , BackendEnv
  , CipherSpec (C_AES256_CBC, C_AES256_CTR, C_AES256_CTS, C_AES256_CFB128, C_AES256_OFB, C_AES256_KW, C_AES256_KWP, C_AES128_XTS)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EcSpec (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , KeyGenSpec (..)
  , MacSpec (..)
  , ResourceSaveability (..)
  , SigSpec (..)
  , UnsaveableReason (..)
  )
import Haskoki.Engine.Driver (KeyResolver, drainReleases, runEffect)
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.Engine.Synthetic (Synthetic)
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
  , RecoverSpec (..)
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
  , finishSignRecover
  , finishVerify
  , finishVerifyRecover
  , planSignOneShot
  , planSignRecoverOneShot
  , planVerifyOneShot
  , planVerifyRecoverOneShot
  )
import Haskoki.Outcome (ResourceRelease (..))
import Haskoki.Recipe.Cipher (decodeCtrParams, encodeCtrParams)
import Haskoki.Recipe.Gcm (decodeGcmParams, encodeGcmParams)
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
  , testCase "aes-cts ragged roundtrip through cipher slots" caseAesCtsSlot
  , testCase "aes-cfb128 ragged roundtrip through cipher slots" caseAesCfb128Slot
  , testCase "aes-ofb ragged roundtrip through cipher slots" caseAesOfbSlot
  , testCase "aes-kw expanding roundtrip through cipher slots" caseAesKwSlot
  , testCase "aes-kwp ragged roundtrip through cipher slots" caseAesKwpSlot
  , testCase "aes-xts ragged roundtrip through cipher slots" caseAesXtsSlot
  , testCase "ecdsa sign/verify through slots, DER and RAW" caseEcdsaSlot
  , testCase "dual digest+encrypt through the real backend" caseDualSlot
  , testCase "denied init plans no crypto" caseDeniedPlansNothing
  , testCase "message aes KAT through message slots" caseMessageAesKat
  , testCase "message hmac sign/verify through slots" caseMessageHmac
  , testCase "message gcm+aad KAT through message slots" caseMessageGcmAad
  , testCase "message ecdsa sign/verify through slots" caseMessageEcdsa
  , testCase "rsa-x509 sign-recover round-trip through slots (openssl)" caseX509RecoverOpenssl
  , testCase "rsa-x509 sign-recover round-trip through slots (synthetic)" caseX509RecoverSynthetic
  , testCase "rsa-pkcs sign-recover round-trip through slots (openssl)" casePkcsRecoverOpenssl
  , testCase "rsa-pkcs sign-recover round-trip through slots (synthetic)" casePkcsRecoverSynthetic
  , testCase "recover refuses non-pair mechanisms at the driver" caseRecoverRefusesNonPair
  , testCase "sign-recover empty input pins the pair verdicts" caseRecoverEmptyInput
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

-- | Fixed RSA-2048 recover fixture (committed DER, generated once
-- with host OpenSSL): raw-RSA round-trips are deterministic, so
-- one keypair pins every recover vector below.
rsaPrivDer :: ByteString
rsaPrivDer = hex (concat
  [ "308204a30201000282010100c68c1f0205a16273e77a4a6df6ae1870fbf4f58e2465e5d7b6997ab57f5278ab0014c888bd9a9457053d56945639fd25d881afb1"
  , "f2a2a50b37f2b81323c16d4b62ddb8ba1c8b86fae1c63fa4316a48c433e20e7de9a18dd4b0d7244c35c90f652ab45482a23ad6fe30acf9096f7885b88bac6fa7"
  , "8fce311e73d17ee600f2b3fe1f2ff69998f6e0f7585fd5dcc7f9b6d275a01e402b1d763105bc47ec0d7fbcf615658f9769cb62eb5f142515c99b42d75b50ec55"
  , "15f2564487eeb15e061b4f9d2717c4be7778f39b47a4d463f0234e2a41d8f795aa6f0dcdeba112e17fe732f712970cbcda1ca1081279e2cb6da08f61e5efc42b"
  , "f93ca34563ffacce5a5d7317020301000102820100182d41d806302903ecc0f86fe6cf90f703c7480b74a52fd567a2782317b646d953c6341bbfdd7888c180e9"
  , "9a6086e92b82ef5a7749bb6d162e4c3bb14b9e51c7bc94912fa080365735c78fed0228c0b99b8915b356baaf16f77db5d4233730cd0f392c3d480745876862a2"
  , "64a2bd43533de17e807743680f1ee7f8bd85df5d495d38affd70e4e1d3459043a9dcbbc6573b9fb8e79669c7a15938d4635f65c92668e525bdfd316a2150b9a4"
  , "b72b84bf2c6909eb86f89c9090f4be0ef0901049ecfa1f0e5567e12ccdc8b8f5cbba677a2547cc4f6638c224171a2cd2cdbc9227c6748969e874f8fe3b8e5294"
  , "737464bbe4454db9528f8cd8d685ae2f61f7b2444902818100e9dea63e1c37ae4d7f2f056fd6ee88eff3454d559d47df6befdce86272dfa8ed4d999d4a54e0f1"
  , "5d167fb501c2b39a77a4b355df5012d88e054c1e8f847fb43b7ad7c8a44b4d30c294c0b321f7d146f9172b2906a46cc6f89166782593fa461ab58cb4cf190c0d"
  , "aed5adbd45a240ddfb23ff91779ba3383a9e413385b7d807e302818100d955cf10938075ed8b3095135a9dbc06a70b30a964450d07a1e6d970fee61401b3450b"
  , "8db0cba076b88c0d14023ed627f416e70baf06bff89d6ba1f04bc08fe900595578463e3cede2d33d63e1b2bfe63341d2b63d7ba585bc22d033c70f45459d67ce"
  , "97b37b1fd0a37a3eed9057b7b30ba7d9d0caa4c5b4dbfbec94b92ec63d02818100ce4381a99be77c027b9eb413dca38b00de350c2ceb47bd848c0bf0a50b9db9"
  , "767a0f76cb5d2afb9557479114196da059cf581fef91c6dd59fcd012d00f5336599351877367ba8fbbbdc86af515856d2c39c3e62e268c8dbc233915d446bbe0"
  , "62a426923d6960d91c8ef6e9cce57a828d8245603df675b11cfa0095796518d27302818018ade7cf88106453cf247b2931770beced7715d5866f58e56efb19e1"
  , "fcefff8199ebd33e09bf75bf458191d29dd6a8d6ec9ed529bc7c55bc5393ef55ac2477b30bb9193d892c741ac751197d88199634fbc913b66210f260d75654b2"
  , "2c7e8d6d344c9f6716987aaa6485f33362dab31f7fc955b0a1f248091b99e5e99585bc3902818032f73e09fea6cf6598169aed3afe0b4f53f01411869fea2611"
  , "49c2c5972df484149f875a9e4b21b95953d0da5f57f5556e9e2a8a84f6269beb4d0c564af69bb85c939cc3696508c2b18c462f4a71f0026a982a0f346e0f403d"
  , "229527e008932d656de98cd180f90cc03d9ed9ba2ba6f0640e3d5adf956d7c03b6f29ab5b875f7"
  ])

rsaPubDer :: ByteString
rsaPubDer = hex (concat
  [ "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c68c1f0205a16273e77a4a6df6ae1870fbf4f58e2465e5d7b6997ab57f5278"
  , "ab0014c888bd9a9457053d56945639fd25d881afb1f2a2a50b37f2b81323c16d4b62ddb8ba1c8b86fae1c63fa4316a48c433e20e7de9a18dd4b0d7244c35c90f"
  , "652ab45482a23ad6fe30acf9096f7885b88bac6fa78fce311e73d17ee600f2b3fe1f2ff69998f6e0f7585fd5dcc7f9b6d275a01e402b1d763105bc47ec0d7fbc"
  , "f615658f9769cb62eb5f142515c99b42d75b50ec5515f2564487eeb15e061b4f9d2717c4be7778f39b47a4d463f0234e2a41d8f795aa6f0dcdeba112e17fe732"
  , "f712970cbcda1ca1081279e2cb6da08f61e5efc42bf93ca34563ffacce5a5d73170203010001"
  ])

-- | AES-GCM message vector (the OpenSSLSpec caseAeadReal root:
-- Python cryptography AESGCM): key 00..0f, nonce 00..0b, aad
-- "aad-data", pt "Hello GCM world!".
gcmKatKey, gcmNonce, gcmAad, gcmPt, gcmCt, gcmTag :: ByteString
gcmKatKey = hex "000102030405060708090a0b0c0d0e0f"
gcmNonce = hex "000102030405060708090a0b"
gcmAad = "aad-data"
gcmPt = "Hello GCM world!"
gcmCt = hex "db09cba2093bb01706f216e544cf1429"
gcmTag = hex "39f0385041afdfd3a2d5a8e8ed69a2e6"

gcmAead :: AeadSpec
gcmAead = AeadSpec "AES-128-GCM" 12 16

-- ---------------------------------------------------------------------------
-- Fixtures: registry, model, sessions
-- ---------------------------------------------------------------------------

sha256Mech, hmacMech, aesCbcMech, ecdsaMech, aesCtrMech, aesCtsMech, aesCfb128Mech, aesOfbMech, aesKwMech, aesKwpMech, aesXtsMech, gcmMech :: MechanismId
sha256Mech = MechanismId 0x250
hmacMech = MechanismId 0x251
aesCbcMech = MechanismId 0x1082
gcmMech = MechanismId 0x1087
ecdsaMech = MechanismId 0x1041
aesCtrMech = MechanismId 0x1086
aesCtsMech = MechanismId 0x1089
aesCfb128Mech = MechanismId 0x2107
aesOfbMech = MechanismId 0x2104
aesKwMech = MechanismId 0x2109
aesKwpMech = MechanismId 0x210B
aesXtsMech = MechanismId 0x1071

-- | The curated registry as-is: every mechanism these smoke
-- tests touch (0x250, 0x251, 0x1082, 0x1041, 0x1086, 0x1089, 0x2107, 0x2104) ships behavior-tested
-- (promoting a tested row is a 'DuplicateMechanism' error by
-- design).
smokeRegistry :: Registry
smokeRegistry = curatedRegistry

hmacOid, aesOid, ecPrivOid, ecPubOid, gcmOid :: ObjectId
hmacOid = ObjectId 11
aesOid = ObjectId 12
ecPrivOid = ObjectId 13
ecPubOid = ObjectId 14
gcmOid = ObjectId 15

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
  { mObjects = Map.fromList [(oid, mkObject oid) | oid <- [hmacOid, aesOid, ecPrivOid, ecPubOid, gcmOid]]
  , mHandles = Map.fromList
      [ (ExternalHandle 101, HandleBinding hmacOid (Generation 1))
      , (ExternalHandle 102, HandleBinding aesOid (Generation 1))
      , (ExternalHandle 103, HandleBinding ecPrivOid (Generation 1))
      , (ExternalHandle 104, HandleBinding ecPubOid (Generation 1))
      , (ExternalHandle 105, HandleBinding gcmOid (Generation 1))
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
      , (aesCtsMech, OpEncrypt)
      , (aesCtsMech, OpDecrypt)
      , (aesCfb128Mech, OpEncrypt)
      , (aesCfb128Mech, OpDecrypt)
      , (aesOfbMech, OpEncrypt)
      , (aesOfbMech, OpDecrypt)
      , (aesKwMech, OpEncrypt)
      , (aesKwMech, OpDecrypt)
      , (aesKwpMech, OpEncrypt)
      , (aesKwpMech, OpDecrypt)
      , (aesXtsMech, OpEncrypt)
      , (aesXtsMech, OpDecrypt)
      , (ecdsaMech, OpSign)
      , (ecdsaMech, OpVerify)
      , (gcmMech, OpEncrypt)
      , (gcmMech, OpDecrypt)
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

hmacKeyP, aesKeyP, ecPrivKeyP, ecPubKeyP, gcmKeyP :: KeyPolicy
hmacKeyP = KeyPolicy (ExternalHandle 101) [OpSign, OpVerify] False
aesKeyP = KeyPolicy (ExternalHandle 102) [OpEncrypt, OpDecrypt] False
ecPrivKeyP = KeyPolicy (ExternalHandle 103) [OpSign] False
ecPubKeyP = KeyPolicy (ExternalHandle 104) [OpVerify] False
gcmKeyP = KeyPolicy (ExternalHandle 105) [OpEncrypt, OpDecrypt] False

x509Mech, pkcsMech :: MechanismId
x509Mech = MechanismId 0x03
pkcsMech = MechanismId 0x01

rsaPrivOid, rsaPubOid :: ObjectId
rsaPrivOid = ObjectId 16
rsaPubOid = ObjectId 17

recPrivKeyP, recPubKeyP :: KeyPolicy
recPrivKeyP = KeyPolicy (ExternalHandle 106) [OpSignRecover] False
recPubKeyP = KeyPolicy (ExternalHandle 107) [OpVerifyRecover] False

recModel :: Model
recModel = smokeModel
  { mObjects = Map.insert rsaPrivOid (mkObject rsaPrivOid)
      (Map.insert rsaPubOid (mkObject rsaPubOid) (mObjects smokeModel))
  , mHandles = Map.insert (ExternalHandle 106)
      (HandleBinding rsaPrivOid (Generation 1))
      (Map.insert (ExternalHandle 107)
        (HandleBinding rsaPubOid (Generation 1)) (mHandles smokeModel))
  }

recEnv :: OpEnv
recEnv = smokeEnv
  { oeCaps = mkCapabilities
      [ (x509Mech, OpSignRecover)
      , (x509Mech, OpVerifyRecover)
      , (pkcsMech, OpSignRecover)
      , (pkcsMech, OpVerifyRecover)
      ]
  , oeModel = recModel
  }

recShape :: RecoverSpec
recShape = RecoverSpec 256 256

-- ---------------------------------------------------------------------------
-- The driver: planned effects answered by the real backend
-- ---------------------------------------------------------------------------

keyFor :: ObjectId -> Maybe KeyMaterial
keyFor oid
  | oid == hmacOid = Just (KeyBytes hmacKey1)
  | oid == aesOid = Just (KeyBytes aes256Key)
  | oid == ecPrivOid = Just (KeyDer ecPrivDer)
  | oid == ecPubOid = Just (KeyDer ecPubDer)
  | oid == gcmOid = Just (KeyBytes gcmKatKey)
  | oid == rsaPrivOid = Just (KeyDer rsaPrivDer)
  | oid == rsaPubOid = Just (KeyDer rsaPubDer)
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

-- | Sealed answers: ciphertext and tag concatenate (the production
-- driver's sealed shape); decrypt splits the trailing tag width.
toSealed :: EngineResult (ByteString, ByteString) -> CryptoResult
toSealed (EngineOk (ct, tag)) = GotBytes (ct <> tag)
toSealed (EngineFail (BackendUnsupported o w)) =
  GotCryptoError (CryptoUnsupported o w)
toSealed (EngineFail (BackendBadKey o w)) =
  GotCryptoError (CryptoBadKey o w)
toSealed (EngineFail err) = GotCryptoError (CryptoFailed (show err))

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
    | mech == aesCtsMech, Just key <- keyFor oid ->
        toBytes <$> cipherEncrypt env C_AES256_CTS key iv input
    | mech == aesCfb128Mech, Just key <- keyFor oid ->
        toBytes <$> cipherEncrypt env C_AES256_CFB128 key iv input
    | mech == aesOfbMech, Just key <- keyFor oid ->
        toBytes <$> cipherEncrypt env C_AES256_OFB key iv input
    | mech == aesKwMech, Just key <- keyFor oid ->
        toBytes <$> cipherEncrypt env C_AES256_KW key iv input
    | mech == aesKwpMech, Just key <- keyFor oid ->
        toBytes <$> cipherEncrypt env C_AES256_KWP key iv input
    | mech == aesXtsMech, Just key <- keyFor oid ->
        toBytes <$> cipherEncrypt env C_AES128_XTS key iv input
    | otherwise -> pure (badKey fx)
  FxCipher DirDecrypt mech (Just oid) iv input
    | mech == aesCbcMech, Just key <- keyFor oid ->
        toBytes <$> cipherDecrypt env C_AES256_CBC key iv input
    | mech == aesCtrMech, Just key <- keyFor oid, Just cb <- ctrBlock iv ->
        toBytes <$> cipherDecrypt env C_AES256_CTR key cb input
    | mech == aesCtsMech, Just key <- keyFor oid ->
        toBytes <$> cipherDecrypt env C_AES256_CTS key iv input
    | mech == aesCfb128Mech, Just key <- keyFor oid ->
        toBytes <$> cipherDecrypt env C_AES256_CFB128 key iv input
    | mech == aesOfbMech, Just key <- keyFor oid ->
        toBytes <$> cipherDecrypt env C_AES256_OFB key iv input
    | mech == aesKwMech, Just key <- keyFor oid ->
        toBytes <$> cipherDecrypt env C_AES256_KW key iv input
    | mech == aesKwpMech, Just key <- keyFor oid ->
        toBytes <$> cipherDecrypt env C_AES256_KWP key iv input
    | mech == aesXtsMech, Just key <- keyFor oid ->
        toBytes <$> cipherDecrypt env C_AES128_XTS key iv input
    | otherwise -> pure (badKey fx)
  -- Message effects: per-message params drive crypto (the IV
  -- arrives per message, not from init). The backend is not
  -- AEAD, so bound AAD is honestly refused, never ignored.
  FxMessageCipher DirEncrypt mech (Just oid) params aad input
    | mech == gcmMech, Just key <- keyFor oid
    , Just (nonce, _, _) <- decodeGcmParams params ->
        toSealed <$> aeadEncrypt env gcmAead key nonce aad input
    | mech == aesCbcMech, Just key <- keyFor oid, BS.null aad ->
        toBytes <$> cipherEncrypt env C_AES256_CBC key params input
    | mech == aesCbcMech, Just _ <- keyFor oid ->
        pure (GotCryptoError (CryptoUnsupported "smoke driver" "non-AEAD backend takes no AAD"))
    | otherwise -> pure (badKey fx)
  FxMessageCipher DirDecrypt mech (Just oid) params aad input
    | mech == gcmMech, Just key <- keyFor oid
    , Just (nonce, _, _) <- decodeGcmParams params, BS.length input >= 16 ->
        let (ct, tag) = BS.splitAt (BS.length input - 16) input
        in toBytes <$> aeadDecrypt env gcmAead key nonce aad ct tag
    | mech == aesCbcMech, Just key <- keyFor oid, BS.null aad ->
        toBytes <$> cipherDecrypt env C_AES256_CBC key params input
    | mech == aesCbcMech, Just _ <- keyFor oid ->
        pure (GotCryptoError (CryptoUnsupported "smoke driver" "non-AEAD backend takes no AAD"))
    | otherwise -> pure (badKey fx)
  FxMessageSign mech (Just oid) params input
    | mech == hmacMech, Just key <- keyFor oid ->
        toBytes <$> macSign env (MacHMAC D_SHA256 Nothing) key input
    | mech == ecdsaMech, Just key <- keyFor oid ->
        toBytes <$> sign env (SigECDSA (EcSpec "P-256" (smokeEncoding params)) (Just D_SHA256)) key input
    | otherwise -> pure (badKey fx)
  FxMessageVerify mech (Just oid) params input sig
    | mech == hmacMech, Just key <- keyFor oid ->
        toVerifyBool <$> macVerify env (MacHMAC D_SHA256 Nothing) key input sig
    | mech == ecdsaMech, Just key <- keyFor oid ->
        toVerifyUnit <$> verify env (SigECDSA (EcSpec "P-256" (smokeEncoding params)) (Just D_SHA256)) key input sig
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

withSynth :: String -> (BackendEnv Synthetic -> IO ()) -> IO ()
withSynth seed action = do
  r <- openBackend seed :: IO (EngineResult (BackendEnv Synthetic))
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

-- | CTS through the slots: ragged input plans (no alignment
-- denial), the real backend steals over libcrypto ECB, and
-- decrypt recovers. (A roundtrip, not a KAT: no ACVP vector
-- covers the fixed smoke key; the KATs live in OpenSSLSpec.)
caseAesCtsSlot :: IO ()
caseAesCtsSlot = withBackend $ \env -> do
  let noPad = Just (CipherSpec 16 False)
      msg = "cts steals over ragged input" :: ByteString
      eArgs = InitArgs OpEncrypt aesCtsMech aes256Iv (Just aesKeyP) noPad Nothing
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
  assertEqual "stealing length preserved" (BS.length msg) (BS.length ct)
  let dArgs = InitArgs OpDecrypt aesCtsMech aes256Iv (Just aesKeyP) noPad Nothing
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

-- | CFB128/OFB through the slots: ragged input plans (no alignment
-- denial), the real backend streams over provider modes, decrypt
-- recovers. (Roundtrips, not KATs: no ACVP vector covers the fixed
-- smoke key; the KATs live in OpenSSLSpec.)
caseAesCfb128Slot :: IO ()
caseAesCfb128Slot = streamSlot aesCfb128Mech "cfb128 streams over ragged input!"

caseAesOfbSlot :: IO ()
caseAesOfbSlot = streamSlot aesOfbMech "ofb buffers over ragged input!!"

streamSlot :: MechanismId -> ByteString -> IO ()
streamSlot mech msg = withBackend $ \env -> do
  let noPad = Just (CipherSpec 16 False)
      eArgs = InitArgs OpEncrypt mech aes256Iv (Just aesKeyP) noPad Nothing
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
  let dArgs = InitArgs OpDecrypt mech aes256Iv (Just aesKeyP) noPad Nothing
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

caseAesKwSlot :: IO ()
caseAesKwSlot = wrapSlot aesKwMech "wrap-me-16-byte!" 24

caseAesKwpSlot :: IO ()
caseAesKwpSlot = wrapSlot aesKwpMech "kwp ragged msg, 23 byte" 32

-- | XTS through the slots: the 32-byte smoke key feeds XTS-128,
-- the 16-byte tweak rides as the parameter, ragged input plans
-- (no alignment denial), decrypt recovers. (Roundtrip, not KAT:
-- no ACVP vector covers the fixed smoke key; the KATs live in
-- OpenSSLSpec.)
caseAesXtsSlot :: IO ()
caseAesXtsSlot = withBackend $ \env -> do
  let noPad = Just (CipherSpec 16 False)
      msg = "xts data unit, 23 bytes" :: ByteString
      eArgs = InitArgs OpEncrypt aesXtsMech aes256Iv (Just aesKeyP) noPad Nothing
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
  assertEqual "xts length preserved" (BS.length msg) (BS.length ct)
  let dArgs = InitArgs OpDecrypt aesXtsMech aes256Iv (Just aesKeyP) noPad Nothing
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

-- | Wrap roundtrip through the cipher slots: wraps take empty
-- mechanism parameters (no IV), expand the output by the wrap
-- framing (KW: inlen + 8; KWP: 8-byte ceiling + 8), and recover
-- the input on unwrap.
wrapSlot :: MechanismId -> ByteString -> Int -> IO ()
wrapSlot mech msg wantCtLen = withBackend $ \env -> do
  let noPad = Just (CipherSpec 8 False)
      eArgs = InitArgs OpEncrypt mech BS.empty (Just aesKeyP) noPad Nothing
      (ops0, i0) = initOperation smokeEnv emptySessionOps smokeSession eArgs
  assertEqual "wrap init ok" CKR_OK (ioCode i0)
  let (ops1, _, o1) = planCipherOneShot ops0 smokeSession
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
  assertEqual "wrap output expands" wantCtLen (BS.length ct)
  let dArgs = InitArgs OpDecrypt mech BS.empty (Just aesKeyP) noPad Nothing
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

caseMessageGcmAad :: IO ()
caseMessageGcmAad = withBackend $ \env -> do
  -- Init carries the full recipe params; per-message delivery
  -- rebinds the nonce while the AAD travels bound alongside.
  let gcmInit = encodeGcmParams gcmNonce gcmAad 16
      gcmOne = encodeGcmParams gcmNonce BS.empty 16
      eArgs = InitArgs OpEncrypt gcmMech gcmInit (Just gcmKeyP)
        (Just (CipherSpec 1 False)) Nothing
      (ops0, i0) = initMessageOperation MsgEncrypt smokeEnv emptySessionOps smokeSession eArgs
  assertEqual "message gcm init ok" CKR_OK (ioCode i0)
  -- One-shot seal hits the pinned ct||tag vector; the slot survives.
  let (ops1, _, o1) = planMessageOneShot ops0 smokeSession MsgEncrypt "sealed"
        (MsgOneShotCipher gcmOne gcmAad gcmPt)
  ops2 <- case soEffects o1 of
    [fx@(FxMessageCipher _ _ _ _ _ _)] -> do
      out <- expectBytes env fx
      let (o, fin) = finishMessage MsgEncrypt ops1 SlotEncrypt "sealed"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "encrypt ok" CKR_OK (soCode fin)
      assertEqual "KAT sealed" (Just (gcmCt <> gcmTag)) (stagedBytes fin)
      assertEqual "slot kept" [SlotEncrypt] (activeSlots o)
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  let (ops3, final) = finalizeMessage MsgEncrypt ops2
  assertEqual "outer final ok" CKR_OK (soCode final)
  assertEqual "outer final frees" [] (activeSlots ops3)
  -- Decrypt opens the sealed bytes back to the plaintext.
  let dArgs = InitArgs OpDecrypt gcmMech gcmInit (Just gcmKeyP)
        (Just (CipherSpec 1 False)) Nothing
      (opsD0, _) = initMessageOperation MsgDecrypt smokeEnv emptySessionOps smokeSession dArgs
      (opsD1, _, oD) = planMessageOneShot opsD0 smokeSession MsgDecrypt "pt"
        (MsgOneShotCipher gcmOne gcmAad (gcmCt <> gcmTag))
  opsD2 <- case soEffects oD of
    [fx] -> do
      out <- expectBytes env fx
      let (o, fin) = finishMessage MsgDecrypt opsD1 SlotDecrypt "pt"
            (GotBytes out) (IntentBuffer 64)
      assertEqual "decrypt ok" CKR_OK (soCode fin)
      assertEqual "roundtrip" (Just gcmPt) (stagedBytes fin)
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- A tampered tag fails closed (never bytes, never silent).
  let bad = gcmCt <> BS.pack [BS.head gcmTag `xor` 1] <> BS.tail gcmTag
      (opsD3, _, oT) = planMessageOneShot opsD2 smokeSession MsgDecrypt "pt"
        (MsgOneShotCipher gcmOne gcmAad bad)
  case soEffects oT of
    [fx] -> do
      res <- runRealEffect env fx
      case res of
        GotBytes _ -> assertFailure "tampered tag sealed bytes"
        _ -> pure ()
      let (o, fin) = finishMessage MsgDecrypt opsD3 SlotDecrypt "pt"
            res (IntentBuffer 64)
      assertBool "tamper fails closed" (soCode fin /= CKR_OK)
      assertEqual "context survives" [SlotDecrypt] (activeSlots o)
    other -> assertFailure ("expected one effect, got " ++ show other)

caseMessageEcdsa :: IO ()
caseMessageEcdsa = withBackend $ \env -> do
  -- Fresh DER sign through the message slot (ECDSA signs are
  -- randomized: the KAT is the verify roundtrip, not fixed bytes).
  let sArgs = InitArgs OpSign ecdsaMech BS.empty (Just ecPrivKeyP) Nothing Nothing
      (ops0, i0) = initMessageOperation MsgSign smokeEnv emptySessionOps smokeSession sArgs
  assertEqual "message ecdsa init ok" CKR_OK (ioCode i0)
  let (ops1, _, o1) = planMessageOneShot ops0 smokeSession MsgSign "sig"
        (MsgOneShotSign BS.empty ecMsg)
  (opsS, sig) <- case soEffects o1 of
    [fx@(FxMessageSign _ _ _ _)] -> do
      out <- expectBytes env fx
      let (o, fin) = finishMessage MsgSign ops1 SlotSign "sig"
            (GotBytes out) (IntentBuffer 128)
      assertEqual "sign ok" CKR_OK (soCode fin)
      assertEqual "slot kept" [SlotSign] (activeSlots o)
      case stagedBytes fin of
        Just s -> pure (o, s)
        Nothing -> assertFailure "expected staged signature"
    other -> assertFailure ("expected one effect, got " ++ show other)
  assertBool "nonempty signature" (not (BS.null sig))
  let (ops2, final) = finalizeMessage MsgSign opsS
  assertEqual "outer final ok" CKR_OK (soCode final)
  assertEqual "outer final frees" [] (activeSlots ops2)
  let vArgs = InitArgs OpVerify ecdsaMech BS.empty (Just ecPubKeyP) Nothing Nothing
      (ops3, _) = initMessageOperation MsgVerify smokeEnv emptySessionOps smokeSession vArgs
      (ops4, _, o2) = planMessageOneShot ops3 smokeSession MsgVerify "vrf"
        (MsgOneShotVerify BS.empty ecMsg sig)
  case soEffects o2 of
    [fx] -> do
      res <- runRealEffect env fx
      let (o, fin) = finishMessage MsgVerify ops4 SlotVerify "vrf"
            res (IntentBuffer 0)
      assertEqual "verify ok" CKR_OK (soCode fin)
      assertEqual "slot kept" [SlotVerify] (activeSlots o)
      let (o2', final') = finalizeMessage MsgVerify o
      assertEqual "outer final ok" CKR_OK (soCode final')
      assertEqual "slot freed" [] (activeSlots o2')
    other -> assertFailure ("expected one effect, got " ++ show other)

-- ---------------------------------------------------------------------------
-- Recover round-trips through the production driver
-- ---------------------------------------------------------------------------

-- | One recover round-trip through slots: sign over the input,
-- then verify over the staged signature. Runs the planned
-- effects through the production driver ('runEffect') so the
-- recover arms execute on the given backend. Returns the staged
-- signature and the staged recovered bytes.
roundRecover
  :: CryptoBackend b
  => BackendEnv b -> KeyResolver -> MechanismId -> ByteString
  -> IO (ByteString, ByteString)
roundRecover env resolve mech input = do
  let (ops0, i0) = initOperation recEnv emptySessionOps smokeSession
        (InitArgs OpSignRecover mech BS.empty (Just recPrivKeyP)
          Nothing (Just recShape))
  assertEqual "sign-recover init ok" CKR_OK (ioCode i0)
  let (ops1, _, u1) = planSignRecoverOneShot ops0 smokeSession "rec" input
  assertEqual "sign-recover plans" CKR_OK (soCode u1)
  sig <- case soEffects u1 of
    [fx] -> do
      res <- runEffect env resolve fx
      res2 <- runEffect env resolve fx
      case (res, res2) of
        (GotBytes b, GotBytes b2) -> do
          assertEqual "raw RSA deterministic" b b2
          pure b
        other -> assertFailure ("sign bytes twice, got " ++ show other)
    other -> assertFailure ("one sign effect, got " ++ show other)
  assertEqual "signature width" 256 (BS.length sig)
  sigStaged <- case soEffects u1 of
    [_] -> do
      let (o, fin) = finishSignRecover ops1 SlotSign "rec"
            (GotBytes sig) (IntentBuffer 512)
      assertEqual "sign finish ok" CKR_OK (soCode fin)
      assertEqual "sign finish frees" [] (activeSlots o)
      case stagedBytes fin of
        Just s -> pure s
        Nothing -> assertFailure "expected staged signature"
    other -> assertFailure ("one sign effect, got " ++ show other)
  assertEqual "staged signature matches" sig sigStaged
  let (ops2, i2) = initOperation recEnv emptySessionOps smokeSession
        (InitArgs OpVerifyRecover mech BS.empty (Just recPubKeyP)
          Nothing (Just recShape))
  assertEqual "verify-recover init ok" CKR_OK (ioCode i2)
  let (ops3, _, u2) = planVerifyRecoverOneShot ops2 smokeSession "rec" sig
  assertEqual "verify-recover plans" CKR_OK (soCode u2)
  case soEffects u2 of
    [fx] -> do
      res <- runEffect env resolve fx
      let (o, fin) = finishVerifyRecover ops3 SlotVerify "rec"
            res (IntentBuffer 512)
      assertEqual "verify finish ok" CKR_OK (soCode fin)
      assertEqual "verify finish frees" [] (activeSlots o)
      case stagedBytes fin of
        Just rec -> pure (sig, rec)
        Nothing -> assertFailure "expected staged recovery"
    other -> assertFailure ("one verify effect, got " ++ show other)

-- | The X.509 recovered shape: the input left-padded to the
-- modulus width (raw RSA has no framing to strip).
leftPad256 :: ByteString -> ByteString
leftPad256 input = BS.replicate (256 - BS.length input) 0 <> input

caseX509RecoverOpenssl :: IO ()
caseX509RecoverOpenssl = withBackend $ \env -> do
  (sig, rec) <- roundRecover env keyFor x509Mech "abc"
  assertEqual "x509 recovers the padded input" (leftPad256 "abc") rec
  assertBool "signature is no passthrough" (sig /= leftPad256 "abc")

caseX509RecoverSynthetic :: IO ()
caseX509RecoverSynthetic = withSynth "11" $ \env -> do
  eKeys <- generateKey env (GenRSA 2048 65537)
  (priv, mPub) <- case eKeys of
    EngineOk pair -> pure pair
    EngineFail err -> assertFailure ("gen rsa failed: " ++ show err)
  pub <- case mPub of
    Just p -> pure p
    Nothing -> assertFailure "rsa gen must return a pair"
  let resolve oid
        | oid == rsaPrivOid = Just priv
        | oid == rsaPubOid = Just pub
        | otherwise = keyFor oid
  (_sig, rec) <- roundRecover env resolve x509Mech "abc"
  assertEqual "x509 recovers the padded input" (leftPad256 "abc") rec

casePkcsRecoverOpenssl :: IO ()
casePkcsRecoverOpenssl = withBackend $ \env -> do
  (sig, rec) <- roundRecover env keyFor pkcsMech "abc"
  assertEqual "pkcs recovers the input" "abc" rec
  assertEqual "signature width" 256 (BS.length sig)

casePkcsRecoverSynthetic :: IO ()
casePkcsRecoverSynthetic = withSynth "11" $ \env -> do
  eKeys <- generateKey env (GenRSA 2048 65537)
  (priv, mPub) <- case eKeys of
    EngineOk pair -> pure pair
    EngineFail err -> assertFailure ("gen rsa failed: " ++ show err)
  pub <- case mPub of
    Just p -> pure p
    Nothing -> assertFailure "rsa gen must return a pair"
  let resolve oid
        | oid == rsaPrivOid = Just priv
        | oid == rsaPubOid = Just pub
        | otherwise = keyFor oid
  (_sig, rec) <- roundRecover env resolve pkcsMech "abc"
  assertEqual "pkcs recovers the input" "abc" rec

caseRecoverRefusesNonPair :: IO ()
caseRecoverRefusesNonPair = withBackend $ \env -> do
  let digested = MechanismId 0x40
  r1 <- runEffect env keyFor
    (FxSignRecover hmacMech (Just hmacOid) BS.empty "x" 4)
  case r1 of
    GotCryptoError (CryptoUnsupported _ _) -> pure ()
    other -> assertFailure ("expected Unsupported, got: " ++ show other)
  r2 <- runEffect env keyFor
    (FxVerifyRecover hmacMech (Just hmacOid) BS.empty "x" 4)
  case r2 of
    GotCryptoError (CryptoUnsupported _ _) -> pure ()
    other -> assertFailure ("expected Unsupported, got: " ++ show other)
  r3 <- runEffect env keyFor
    (FxSignRecover digested (Just hmacOid) BS.empty "x" 256)
  case r3 of
    GotCryptoError (CryptoUnsupported _ _) -> pure ()
    other -> assertFailure ("expected Unsupported, got: " ++ show other)
  r4 <- runEffect env keyFor
    (FxVerifyRecover digested (Just hmacOid) BS.empty
      (BS.replicate 256 9) 256)
  case r4 of
    GotCryptoError (CryptoUnsupported _ _) -> pure ()
    other -> assertFailure ("expected Unsupported, got: " ++ show other)

caseRecoverEmptyInput :: IO ()
caseRecoverEmptyInput = withBackend $ \env -> do
  -- X.509: the planner admits the empty input (it fits the
  -- capacity); the driver refuses it (no empty X.509 block) and
  -- the finisher surfaces the failure, freeing the slot.
  let (xops0, xi0) = initOperation recEnv emptySessionOps smokeSession
        (InitArgs OpSignRecover x509Mech BS.empty (Just recPrivKeyP)
          Nothing (Just recShape))
  assertEqual "x509 empty init ok" CKR_OK (ioCode xi0)
  let (xops1, _, xu1) = planSignRecoverOneShot xops0 smokeSession "rec" BS.empty
  assertEqual "x509 empty plans" CKR_OK (soCode xu1)
  case soEffects xu1 of
    [fx] -> do
      res <- runEffect env keyFor fx
      case res of
        GotCryptoError (CryptoFailed _) -> pure ()
        other -> assertFailure ("expected driver failure, got: " ++ show other)
      let (o, fin) = finishSignRecover xops1 SlotSign "rec" res (IntentBuffer 512)
      assertEqual "x509 empty surfaces" CKR_GENERAL_ERROR (soCode fin)
      assertEqual "x509 empty frees" [] (activeSlots o)
    other -> assertFailure ("one sign effect, got " ++ show other)
  -- PKCS: the empty input pads, signs, and recovers the empty
  -- payload (type-1 framing admits empty data).
  (sig, rec) <- roundRecover env keyFor pkcsMech BS.empty
  assertEqual "pkcs empty signature width" 256 (BS.length sig)
  assertEqual "pkcs empty recovers empty" BS.empty rec