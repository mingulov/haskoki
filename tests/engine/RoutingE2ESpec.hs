{- | A1 routed end-to-end proofs over the real backend.

Acceptance 2: a digest one-shot executes through the FULL chain
Request -> Transition -> planner -> production driver -> real
OpenSSL4 backend -> output planner, asserting FIPS KAT digest bytes
from the commit outputs. Companion cases pin the production
'Driver' mapping per effect (KATs where fixed, round-trips where
randomized) plus the keyed sign\/verify path through
'planCall'\/'finishEffect'.
-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
module RoutingE2ESpec (spec) where

import Data.Bits (complement, (.&.), shiftR)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , DhSpec (..)
  , DigestAlg (..)
  , EcdhSpec (..)
  , EcSpec (..)
  , EngineResult (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , ResourceSaveability (..)
  , UnsaveableReason (..)
  )
import Haskoki.Engine.Driver (KeyResolver, drainReleases, encodeResult, runEffect)
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , addToken
  , emptyModel
  , lookupSession
  )
import Haskoki.Operation
  ( CipherDir (..)
  , CryptoEffect (..)
  , CryptoError (..)
  , CryptoResult (..)
  , activeSlots
  )
import Haskoki.Operation.Codec (encodeInitInput, encodeVerifyInput)
import Haskoki.Operation.Derive (maxXofTotal)
import Haskoki.Operation.KeyManagement
  (GenArgs (..), decodeKeyPair, encodeGenArgs, hotpKeyGenMech)
import Haskoki.Outcome
  ( EffectRequest (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , ResourceRelease (..)
  )
import qualified Haskoki.Outcome as O
import Haskoki.Der (dhParamsDer, dhSpkiFields)
import Haskoki.Recipe.Ccm (encodeCcmParams)
import Haskoki.Recipe.Chacha20 (encodeChachaPolyParams, encodeChachaStreamParams)
import Haskoki.Recipe.Cipher (encodeCtrParams, encodeRc2CbcParams)
import Haskoki.Recipe.Dh (encodeDhParams)
import Haskoki.Recipe.Ecdh (encodeEcdhParams)
import Haskoki.Recipe.Gcm (encodeGcmParams)
import Haskoki.Recipe.Hmac (encodeMacGeneral)
import Haskoki.Recipe.Ike (encodeIkeParams, maxIkeOutput)
import Haskoki.Recipe.ByteOps (encodeByteOpsParams)
import Haskoki.Recipe.TlsKeyMat (encodeTlsKeyMatParams)
import Haskoki.Recipe.Kdf (encodePbkd2Params)
import Haskoki.Recipe.Pbe (encodePbeParams)
import Haskoki.Recipe.Sp800108 (encodeSp800Params, maxSp800Total)
import Haskoki.Recipe.TlsKdf (encodeTlsKdfParams, maxTlsKdfOutput)
import Haskoki.Recipe.Otp (encodeHotpParams)
import Haskoki.Recipe.RsaOaep (encodeOaepParams)
import Haskoki.Recipe.TlsPrf (encodeTlsPrfParams)
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Request
  ( FunctionId (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Transition (finishEffect, planCall, publishDelta)
import Haskoki.Types
  ( EngineResourceId (..)
  , ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.Engine.Synthetic (Synthetic)

spec :: TestTree
spec = testGroup "Routed end-to-end"
  [ testCase "ACCEPTANCE 2: digest one-shot full chain, KAT bytes" caseDigestE2E
  , testCase "driver: digest KAT + unknown mechanism" caseDriverDigest
  , testCase "driver: hmac sign/verify + key errors" caseDriverHmac
  , testCase "driver: aes KAT + size errors" caseDriverAes
  , testCase "driver: RSA wrap/unwrap roundtrip, modulus-wide" caseDriverRsaWrap
  , testCase "driver: RSA-X.509 wrap/unwrap, trailing key bytes" caseDriverRsaX509Wrap
  , testCase "driver: gcm roundtrip + tamper fails closed" caseDriverGcm
  , testCase "driver: ccm roundtrip + datalen + tamper" caseDriverCcm
  , testCase "driver: ecdsa roundtrip both encodings" caseDriverEcdsa
  , testCase "driver: ecdh agree + truncate + refuse" caseDriverEcdh
  , testCase "driver: dh agree + truncate + refuse" caseDriverDh
  , testCase "driver: cmac KATs + truncate + refuse" caseDriverCmac
  , testCase "driver: 3des-mac KATs + truncate + refuse" caseDriverDes3Mac
  , testCase "driver: cbc-mac KATs + truncate + refuse" caseDriverCbcMac
  , testCase "driver: xcbc KATs + refuse" caseDriverXcbc
  , testCase "driver: gmac KATs + refuse" caseDriverGmac
  , testCase "driver: kdf vectors + refuse" caseDriverKdf
  , testCase "driver: sp800-108 vectors + refuse" caseDriverSp800
  , testCase "driver: tls-kdf vectors + refuse" caseDriverTlsKdf
  , testCase "driver: ike vectors + refuse" caseDriverIke
  , testCase "driver: byte-op vectors + refuse" caseDriverByteOps
  , testCase "driver: key-material vectors + refuse" caseDriverKeyMat
  , testCase "driver: pbkd2 keygen vector" caseDriverPbkd2Gen
  , testCase "driver: pbe keygen vectors" caseDriverPbe
  , testCase "driver: ssl3 mac vectors + refuse" caseDriverSsl3Mac
  , testCase "driver: x931 vectors + refuse" caseDriverX931
  , testCase "driver: poly1305 vector + refuse" caseDriverPoly1305
  , testCase "driver: tls-prf vectors + refuse" caseDriverTlsPrf
  , testCase "driver: hotp vectors + refuse" caseDriverHotp
  , testCase "driver: blake2b-512 digest/hmac/general + refuse" caseDriverBlake2b512
  , testCase "driver: blake2b-256 digest/hmac/general + refuse" caseDriverBlake2b256
  , testCase "driver: chacha20 KAT + poly KAT + tamper + refuse" caseDriverChacha
  , testCase "driver: camellia-ctr KAT + stream + refuse" caseDriverCamelliaCtr
  , testCase "driver: legacy KAT + rc2 params + refuse" caseDriverLegacy
  , testCase "driver: encrypt-data goldens + truncate + refuse" caseDriverEncryptData
  , testCase "driver: message cipher/sign/verify" caseDriverMessage
  , testCase "driver: recovery is honestly unsupported" caseDriverRecover
  , testCase "driver: encodeResult mapping" caseEncodeResult
  , testCase "routed hmac sign E2E, tag in commit" caseSignE2E
  , testCase "routed hmac verify E2E, verdict commits" caseVerifyE2E
  , testCase "Multipart digest feeds the backend" caseDigestStreamsFeeds
  ]

-- ---------------------------------------------------------------------------
-- Vectors
-- ---------------------------------------------------------------------------

hex :: String -> ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

sha256Abc :: ByteString
sha256Abc = hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

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

chachaRfcKey, chachaPolyRfcKey :: ByteString
chachaRfcKey = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
chachaPolyRfcKey = hex "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"

chachaSunscreen :: ByteString
chachaSunscreen =
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

chachaMech, chachaPolyMech :: MechanismId
chachaMech = MechanismId 0x1226
chachaPolyMech = MechanismId 0x4021

sha256Mech, hmacMech, aesCbcMech, ecdsaMech :: MechanismId
sha256Mech = MechanismId 0x250
hmacMech = MechanismId 0x251
aesCbcMech = MechanismId 0x1082
ecdsaMech = MechanismId 0x1041

ecdhMech, ecdhCofMech :: MechanismId
ecdhMech = MechanismId 0x1050
ecdhCofMech = MechanismId 0x1051

dhMech, dhX942Mech :: MechanismId
dhMech = MechanismId 0x21
dhX942Mech = MechanismId 0x31

-- | The RFC 3526 2048-bit MODP prime (DH keygen domain).
dhP2048 :: ByteString
dhP2048 = hex $ concat
  [ "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9"
  , "e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3"
  , "df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c93598"
  , "4f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc"
  , "0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae"
  , "56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f6191"
  , "72fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c5"
  , "8ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"
  ]

cmacMech, cmacGenMech, cmac3Mech, cmac3GenMech :: MechanismId
cmacMech = MechanismId 0x108a
cmacGenMech = MechanismId 0x108b
cmac3Mech = MechanismId 0x138
cmac3GenMech = MechanismId 0x137

des3macMech, des3macGenMech :: MechanismId
des3macMech = MechanismId 0x134
des3macGenMech = MechanismId 0x135

aesMacMech, aesMacGenMech :: MechanismId
aesMacMech = MechanismId 0x1083
aesMacGenMech = MechanismId 0x1084

ariaMacMech, ariaMacGenMech :: MechanismId
ariaMacMech = MechanismId 0x563
ariaMacGenMech = MechanismId 0x564

camMacMech, camMacGenMech :: MechanismId
camMacMech = MechanismId 0x553
camMacGenMech = MechanismId 0x554

xcbcMech, xcbc96Mech :: MechanismId
xcbcMech = MechanismId 0x108c
xcbc96Mech = MechanismId 0x108d

gmacMech :: MechanismId
gmacMech = MechanismId 0x108e

aesGcmMech :: MechanismId
aesGcmMech = MechanismId 0x1087

aesCcmMech :: MechanismId
aesCcmMech = MechanismId 0x1088

pbkd2Mech :: MechanismId
pbkd2Mech = MechanismId 0x3b0

-- | (mechanism, label, width, digest of "abc").
shaKdMechs :: [(MechanismId, String, Int, String)]
shaKdMechs =
  [ (MechanismId 0x392, "SHA1", 20, "a9993e364706816aba3e25717850c26c9cd0d89d")
  , (MechanismId 0x396, "SHA224", 28, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
  , (MechanismId 0x393, "SHA256", 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  , (MechanismId 0x394, "SHA384", 48, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
  , (MechanismId 0x395, "SHA512", 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
  , (MechanismId 0x4b, "SHA512/224", 28, "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa")
  , (MechanismId 0x4f, "SHA512/256", 32, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23")
  , (MechanismId 0x398, "SHA3-224", 28, "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")
  , (MechanismId 0x397, "SHA3-256", 32, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
  , (MechanismId 0x399, "SHA3-384", 48, "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25")
  , (MechanismId 0x39a, "SHA3-512", 64, "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")
  , (MechanismId 0x401e, "BLAKE2B-512", 64, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
  , (MechanismId 0x390, "MD5", 16, "900150983cd24fb0d6963f7d28e17f72")
  ]

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

hmacOid, aesOid :: ObjectId
hmacOid = ObjectId 21
aesOid = ObjectId 22

chachaOid, chachaPolyOid :: ObjectId
chachaOid = ObjectId 23
chachaPolyOid = ObjectId 24

hmacHandle, aesHandle :: ExternalHandle
hmacHandle = ExternalHandle 201
aesHandle = ExternalHandle 202

chachaHandle, chachaPolyHandle :: ExternalHandle
chachaHandle = ExternalHandle 203
chachaPolyHandle = ExternalHandle 204

resolver :: KeyResolver
resolver oid
  | oid == hmacOid = Just (KeyBytes hmacKey1)
  | oid == aesOid = Just (KeyBytes aes256Key)
  | oid == chachaOid = Just (KeyBytes chachaRfcKey)
  | oid == chachaPolyOid = Just (KeyBytes chachaPolyRfcKey)
  | otherwise = Nothing

mkObject :: ObjectId -> ObjectState
mkObject oid = ObjectState
  { osId = oid
  , osRevision = Revision 1
  , osGeneration = Generation 1
  , osAttrs = Map.fromList [(AttrClass, ValULong 4), (AttrPrivate, ValBool False)]
  , osOwner = Nothing
  , osSlot = SlotId 0
  }

seedKeys :: Model -> Model
seedKeys m = m
  { mObjects = Map.fromList
      [ (hmacOid, mkObject hmacOid), (aesOid, mkObject aesOid)
      , (chachaOid, mkObject chachaOid), (chachaPolyOid, mkObject chachaPolyOid)
      ]
  , mHandles = Map.fromList
      [ (hmacHandle, HandleBinding hmacOid (Generation 1))
      , (aesHandle, HandleBinding aesOid (Generation 1))
      , (chachaHandle, HandleBinding chachaOid (Generation 1))
      , (chachaPolyHandle, HandleBinding chachaPolyOid (Generation 1))
      ]
  }

mkRequest :: FunctionId -> Maybe SessionId -> Request
mkRequest fid mSid = Request
  { reqVersion = Pkcs11_3_2
  , reqFunction = fid
  , reqSession = mSid
  , reqHandle = Nothing
  , reqInput = BS.empty
  , reqRegions = []
  }

openModel :: IO (SessionId, Model)
openModel = do
  let m0 = seedKeys (addToken emptyModel (SlotId 0))
      req = (mkRequest F_OpenSession Nothing) { reqInput = "slot=0,rw" }
  case planCall defaultRules m0 req of
    Immediate pc -> case publishDelta m0 (pcDelta pc) of
      Left fault -> assertFailure ("open delta fault: " ++ show fault)
      Right m1 -> pure (SessionId 1, m1)
    other -> assertFailure ("open failed: " ++ show other)

runCommit :: Model -> Request -> IO Model
runCommit model req = case planCall defaultRules model req of
  Immediate pc -> case publishDelta model (pcDelta pc) of
    Left fault -> assertFailure ("delta fault: " ++ show fault)
    Right m' -> pure m'
  Reject rej -> assertFailure ("expected commit: " ++ show (rejCode rej))
  Execute _ _ -> assertFailure "expected commit, got Execute"

withBackend :: (BackendEnv OpenSSL4 -> IO ()) -> IO ()
withBackend action = do
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk env -> action env >> closeBackend env

expectBytes :: CryptoResult -> IO ByteString
expectBytes (GotBytes b) = pure b
expectBytes other = assertFailure ("expected bytes, got " ++ show other)

commitBytes :: PreparedCommit -> IO ByteString
commitBytes pc = case pcOutputs pc of
  [NativeOutput _ bs] -> pure bs
  outs -> assertFailure ("expected one output, got: " ++ show outs)

-- ---------------------------------------------------------------------------
-- Feed-counting Synthetic wrapper
-- ---------------------------------------------------------------------------

-- | Feed-counting wrapper over Synthetic: every method delegates
-- except 'digestUpdate', which counts calls. Identified by type
-- only (no values); the instance dispatches on 'BackendEnv'.
data Counting

instance CryptoBackend Counting where
  data BackendEnv Counting = CountingEnv !(BackendEnv Synthetic) !(IORef Int)

  backendName _ = "counting-synthetic"

  openBackend seed = do
    eBe <- openBackend seed :: IO (EngineResult (BackendEnv Synthetic))
    case eBe of
      EngineFail err -> pure (EngineFail err)
      EngineOk be -> do
        ref <- newIORef 0
        pure (EngineOk (CountingEnv be ref))

  closeBackend (CountingEnv be _) = closeBackend be
  queryCapabilities (CountingEnv be _) = queryCapabilities be
  digestOneShot (CountingEnv be _) alg msg = digestOneShot be alg msg
  digestInit (CountingEnv be _) alg = digestInit be alg
  digestUpdate (CountingEnv be ref) rid msg = do
    atomicModifyIORef' ref (\n -> (n + 1, ()))
    digestUpdate be rid msg
  digestFinal (CountingEnv be _) rid = digestFinal be rid
  digestXof (CountingEnv be _) alg msg n = digestXof be alg msg n
  macSign (CountingEnv be _) sp key msg = macSign be sp key msg
  macVerify (CountingEnv be _) sp key msg tag = macVerify be sp key msg tag
  sign (CountingEnv be _) sp key msg = sign be sp key msg
  verify (CountingEnv be _) sp key msg sig = verify be sp key msg sig
  cipherEncrypt (CountingEnv be _) sp key iv input =
    cipherEncrypt be sp key iv input
  cipherDecrypt (CountingEnv be _) sp key iv input =
    cipherDecrypt be sp key iv input
  aeadEncrypt (CountingEnv be _) sp key x y z =
    aeadEncrypt be sp key x y z
  aeadDecrypt (CountingEnv be _) sp key w x y z =
    aeadDecrypt be sp key w x y z
  pkeyEncrypt (CountingEnv be _) params key input =
    pkeyEncrypt be params key input
  pkeyDecrypt (CountingEnv be _) params key input =
    pkeyDecrypt be params key input
  generateKey (CountingEnv be _) sp = generateKey be sp
  randomBytes (CountingEnv be _) n = randomBytes be n
  seedRandom (CountingEnv be _) seed = seedRandom be seed
  importKey (CountingEnv be _) mat = importKey be mat
  exportKey (CountingEnv be _) ref = exportKey be ref
  destroyKey (CountingEnv be _) ref = destroyKey be ref
  kemEncapsulate (CountingEnv be _) sp key = kemEncapsulate be sp key
  kemDecapsulate (CountingEnv be _) sp key ct = kemDecapsulate be sp key ct
  ecdhDerive (CountingEnv be _) sp priv peer = ecdhDerive be sp priv peer
  dhDerive (CountingEnv be _) sp priv peer = dhDerive be sp priv peer
  pubFromPriv (CountingEnv be _) priv = pubFromPriv be priv
  snapshotResource (CountingEnv be _) rid = snapshotResource be rid
  restoreResource (CountingEnv be _) bs = restoreResource be bs
  releaseResource (CountingEnv be _) rid = releaseResource be rid
  resourceSaveability (CountingEnv be _) rid = resourceSaveability be rid

-- | Open the counting wrapper on the synthetic decimal seed.
openCounting :: IO (BackendEnv Counting)
openCounting = do
  eBe <- openBackend "0" :: IO (EngineResult (BackendEnv Counting))
  case eBe of
    EngineOk be -> pure be
    EngineFail err ->
      assertFailure ("counting open failed: " ++ show err) >> undefined

-- | Digest feeds observed so far.
feedCount :: BackendEnv Counting -> IO Int
feedCount (CountingEnv _ ref) = readIORef ref

-- ---------------------------------------------------------------------------
-- Cases
-- ---------------------------------------------------------------------------

-- | Drive a digest init through the counting backend; returns the
-- committed model and the allocated stream resource.
runCountingInit
  :: BackendEnv Counting -> Model -> Request -> IO (Model, EngineResourceId)
runCountingInit be model req = case planCall defaultRules model req of
  Execute res (EffectCrypto (FxDigestInit _)) -> do
    crypto <- runEffect be resolver (FxDigestInit sha256Mech)
    case finishEffect defaultRules model res (encodeResult crypto) of
      Left rej -> assertFailure ("init rejected: " ++ show (rejCode rej))
      Right pc -> case publishDelta model (pcDelta pc) of
        Left fault -> assertFailure ("init fault: " ++ show fault)
        Right m' -> case encodeResult crypto of
          O.EngineOkResource rid -> pure (m', rid)
          other -> assertFailure ("alloc answered: " ++ show other)
  other -> assertFailure ("expected Execute alloc, got: " ++ show other)

-- | Multipart digest feeds the backend once per update
-- through the production driver, finishes byte-identical to the
-- one-shot, and drains its stream.
caseDigestStreamsFeeds :: IO ()
caseDigestStreamsFeeds = do
  be <- openCounting
  (sid, m0) <- openModel
  let iReq = (mkRequest F_DigestInit (Just sid))
        { reqInput = encodeInitInput sha256Mech [] False BS.empty }
  (m1, rid) <- runCountingInit be m0 iReq
  let feed m part = do
        let uReq = (mkRequest F_DigestUpdate (Just sid)) { reqInput = part }
        case planCall defaultRules m uReq of
          Execute res (EffectCrypto fx@(FxDigestFeed rid' part')) -> do
            assertEqual "feed names the stream" rid rid'
            assertEqual "feed carries the part" part part'
            crypto <- runEffect be resolver fx
            case finishEffect defaultRules m res (encodeResult crypto) of
              Left rej ->
                assertFailure ("feed rejected: " ++ show (rejCode rej))
              Right pc -> case publishDelta m (pcDelta pc) of
                Left fault -> assertFailure ("feed fault: " ++ show fault)
                Right m' -> pure m'
          other -> assertFailure ("expected Execute feed, got: " ++ show other)
  m2 <- feed m1 "hello, "
  m3 <- feed m2 "world"
  n <- feedCount be
  assertEqual "two backend feeds observed" 2 n
  -- The final consumes the stream and matches the one-shot bytes.
  let fReq = (mkRequest F_DigestFinal (Just sid))
        { reqRegions = [RegionBytes "digest" (IntentBuffer 64)] }
  multi <- case planCall defaultRules m3 fReq of
    Execute res (EffectCrypto fx@(FxDigestConsume rid')) -> do
      assertEqual "consume names the stream" rid rid'
      crypto <- runEffect be resolver fx
      case finishEffect defaultRules m3 res (encodeResult crypto) of
        Left rej -> assertFailure ("final rejected: " ++ show (rejCode rej))
        Right pc -> do
          assertEqual "final carries the stream release"
            [ReleaseEngineResource rid] (pcReleases pc)
          drainReleases be (pcReleases pc)
          case pcOutputs pc of
            [NativeOutput _ out] -> pure out
            other -> assertFailure ("expected one output, got: " ++ show other)
    other -> assertFailure ("expected Execute final, got: " ++ show other)
  gone <- resourceSaveability be rid
  assertEqual "stream drained" (ResourceUnsaveable (UnsaveableGone rid)) gone
  eOne <- digestOneShot be D_SHA256 "hello, world"
  case eOne of
    EngineOk one -> assertEqual "streamed == one-shot" one multi
    EngineFail err -> assertFailure ("one-shot failed: " ++ show err)
  closeBackend be

caseDigestE2E :: IO ()
caseDigestE2E = withBackend $ \env -> do
  (sid, m0) <- openModel
  let iReq = (mkRequest F_DigestInit (Just sid))
        { reqInput = encodeInitInput sha256Mech [] False BS.empty }
  m1 <- case planCall defaultRules m0 iReq of
    Execute res (EffectCrypto fx@(FxDigestInit _)) -> do
      crypto <- runEffect env resolver fx
      case finishEffect defaultRules m0 res (encodeResult crypto) of
        Left rej -> assertFailure ("init rejected: " ++ show (rejCode rej))
        Right pc -> case publishDelta m0 (pcDelta pc) of
          Left fault -> assertFailure ("init fault: " ++ show fault)
          Right m' -> pure m'
    other -> assertFailure ("expected Execute alloc, got: " ++ show other)
  let req = (mkRequest F_Digest (Just sid))
        { reqInput = "abc"
        , reqRegions = [RegionBytes "digest" (IntentBuffer 64)]
        }
  (res, m2) <- case planCall defaultRules m1 req of
    Execute r _ -> pure (r, m1)
    other -> assertFailure ("expected Execute, got: " ++ show other)
  crypto <- runEffect env resolver (FxDigest sha256Mech "abc")
  _ <- expectBytes crypto
  case finishEffect defaultRules m2 res (encodeResult crypto) of
    Left rej -> assertFailure ("finish rejected: " ++ show (rejCode rej))
    Right pc -> do
      assertEqual "commit code" CKR_OK (pcCode pc)
      out <- commitBytes pc
      assertEqual "FIPS 180-4 digest of abc" sha256Abc out
      drainReleases env (pcReleases pc)
      case publishDelta m2 (pcDelta pc) of
        Left fault -> assertFailure ("commit fault: " ++ show fault)
        Right m3 -> case lookupSession m3 sid of
          Nothing -> assertFailure "session vanished"
          Just st -> assertEqual "slot freed" [] (activeSlots (ssOps st))

caseDriverDigest :: IO ()
caseDriverDigest = withBackend $ \env -> do
  out <- runEffect env resolver (FxDigest sha256Mech "abc") >>= expectBytes
  assertEqual "sha256 abc" sha256Abc out
  bad <- runEffect env resolver (FxDigest (MechanismId 0x999) "abc")
  case bad of
    GotCryptoError (CryptoUnsupported _ _) -> pure ()
    other -> assertFailure ("expected Unsupported, got: " ++ show other)

caseDriverHmac :: IO ()
caseDriverHmac = withBackend $ \env -> do
  tag <- runEffect env resolver (FxSign hmacMech (Just hmacOid) BS.empty hmacMsg1)
    >>= expectBytes
  assertEqual "RFC 4231 case 1" hmacOut1 tag
  good <- runEffect env resolver
    (FxVerify hmacMech (Just hmacOid) BS.empty hmacMsg1 tag)
  assertEqual "valid verifies" (GotValid True) good
  bad <- runEffect env resolver
    (FxVerify hmacMech (Just hmacOid) BS.empty hmacMsg1 (BS.map (255 -) tag))
  assertEqual "tampered rejects" (GotValid False) bad
  nokey <- runEffect env resolver (FxSign hmacMech Nothing BS.empty hmacMsg1)
  case nokey of
    GotCryptoError (CryptoBadKey _ _) -> pure ()
    other -> assertFailure ("expected BadKey, got: " ++ show other)
  ghost <- runEffect env resolver
    (FxSign hmacMech (Just (ObjectId 404)) BS.empty hmacMsg1)
  case ghost of
    GotCryptoError (CryptoBadKey _ _) -> pure ()
    other -> assertFailure ("expected BadKey, got: " ++ show other)

-- | BLAKE2B-512 through the driver over real EVP BLAKE2b512:
-- digest KAT, HMAC KAT (CLI-TC1), GENERAL truncation, verify
-- verdicts, and a typed over-width refusal.
caseDriverBlake2b512 :: IO ()
caseDriverBlake2b512 = withBackend $ \env -> do
  let b2Mech = MechanismId 0x401b
      b2Hmac = MechanismId 0x401c
      b2Gen = MechanismId 0x401d
      kat = hex "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
      hkat = hex "358a6a184924894fc34bee5680eedf57d84a37bb38832f288e3b27dc63a98cc8c91e76da476b508bc6b2d408a248857452906e4a20b48c6b4b55d2df0fe1dd24"
  out <- runEffect env resolver (FxDigest b2Mech "abc") >>= expectBytes
  assertEqual "blake2b-512 abc" kat out
  tag <- runEffect env resolver (FxSign b2Hmac (Just hmacOid) BS.empty hmacMsg1)
    >>= expectBytes
  assertEqual "blake2b hmac TC1" hkat tag
  good <- runEffect env resolver
    (FxVerify b2Hmac (Just hmacOid) BS.empty hmacMsg1 tag)
  assertEqual "valid verifies" (GotValid True) good
  g32 <- runEffect env resolver (FxSign b2Gen (Just hmacOid)
    (encodeMacGeneral 32) hmacMsg1) >>= expectBytes
  assertEqual "general truncation" (BS.take 32 hkat) g32
  over <- runEffect env resolver (FxSign b2Gen (Just hmacOid)
    (encodeMacGeneral 65) hmacMsg1)
  case over of
    GotCryptoError (CryptoMechParamInvalid _ _) -> pure ()
    other -> assertFailure ("expected MechParamInvalid, got: " ++ show other)

-- | BLAKE2B-256 through the driver over the sized EVP path:
-- digest KAT, HMAC KAT (hashlib TC1), GENERAL truncation, verify
-- verdicts, and a typed over-width refusal.
caseDriverBlake2b256 :: IO ()
caseDriverBlake2b256 = withBackend $ \env -> do
  let b2Mech = MechanismId 0x4011
      b2Hmac = MechanismId 0x4012
      b2Gen = MechanismId 0x4013
      kat = hex "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
      hkat = hex "b6996ecae165cdb17a02becfbf442b5dee41c5075ded9a5763185cd68bd261d0"
  out <- runEffect env resolver (FxDigest b2Mech "abc") >>= expectBytes
  assertEqual "blake2b-256 abc" kat out
  tag <- runEffect env resolver (FxSign b2Hmac (Just hmacOid) BS.empty hmacMsg1)
    >>= expectBytes
  assertEqual "blake2b hmac TC1" hkat tag
  good <- runEffect env resolver
    (FxVerify b2Hmac (Just hmacOid) BS.empty hmacMsg1 tag)
  assertEqual "valid verifies" (GotValid True) good
  g12 <- runEffect env resolver (FxSign b2Gen (Just hmacOid)
    (encodeMacGeneral 12) hmacMsg1) >>= expectBytes
  assertEqual "general truncation" (BS.take 12 hkat) g12
  over <- runEffect env resolver (FxSign b2Gen (Just hmacOid)
    (encodeMacGeneral 33) hmacMsg1)
  case over of
    GotCryptoError (CryptoMechParamInvalid _ _) -> pure ()
    other -> assertFailure ("expected MechParamInvalid, got: " ++ show other)

-- | Both ChaCha20 rows through the driver over the real backend:
-- the RFC 8439 2.4.2 stream KAT (counter in the parameter image),
-- the RFC 8439 2.8.2 AEAD KAT (nonce/AAD in the parameter image),
-- tag tamper failing closed, and recipe refusals (never
-- Unsupported) for off-spec parameter images.
caseDriverChacha :: IO ()
caseDriverChacha = withBackend $ \env -> do
  let nonce = hex "000000000000004a00000000"
      pt = chachaSunscreen
      streamCt = hex $ concat
        [ "6e2e359a2568f98041ba0728dd0d6981"
        , "e97e7aec1d4360c20a27afccfd9fae0b"
        , "f91b65c5524733ab8f593dabcd62b357"
        , "1639d624e65152ab8f530c359f0861d8"
        , "07ca0dbf500d6a6156a38e088a22b65e"
        , "52bc514d16ccf806818ce91ab7793736"
        , "5af90bbf74a35be6b40b8eedf2785e42"
        , "874d"
        ]
  got <- runEffect env resolver (FxCipher DirEncrypt chachaMech
    (Just chachaOid) (encodeChachaStreamParams 1 nonce) pt)
    >>= expectBytes
  assertEqual "stream rfc 2.4.2 ct" streamCt got
  back <- runEffect env resolver (FxCipher DirDecrypt chachaMech
    (Just chachaOid) (encodeChachaStreamParams 1 nonce) got)
    >>= expectBytes
  assertEqual "stream roundtrip" pt back
  got0 <- runEffect env resolver (FxCipher DirEncrypt chachaMech
    (Just chachaOid) (encodeChachaStreamParams 0 nonce) pt)
    >>= expectBytes
  assertBool "counters differentiate" (got0 /= got)
  badStream <- runEffect env resolver (FxCipher DirEncrypt chachaMech
    (Just chachaOid) BS.empty pt)
  case badStream of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  -- The AEAD row: RFC 8439 2.8.2 key/nonce/AAD through the
  -- parameter image; ciphertext plus the 16-byte tag in one answer.
  let pnonce = hex "070000004041424344454647"
      paad = hex "50515253c0c1c2c3c4c5c6c7"
      pparams = encodeChachaPolyParams pnonce paad 16
      polyCt = hex $ concat
        [ "d31a8d34648e60db7b86afbc53ef7ec2"
        , "a4aded51296e08fea9e2b5a736ee62d6"
        , "3dbea45e8ca9671282fafb69da92728b"
        , "1a71de0a9e060b2905d6a5b67ecd3b36"
        , "92ddbd7f2d778b8c9803aee328091b58"
        , "fab324e4fad675945585808b4831d7bc"
        , "3ff4def08e4b7a9de576d26586cec64b"
        , "6116"
        ]
      polyTag = hex "1ae10b594f09e26a7e902ecbd0600691"
  sealed <- runEffect env resolver (FxCipher DirEncrypt chachaPolyMech
    (Just chachaPolyOid) pparams pt)
    >>= expectBytes
  assertEqual "poly ct+tag" (polyCt <> polyTag) sealed
  opened <- runEffect env resolver (FxCipher DirDecrypt chachaPolyMech
    (Just chachaPolyOid) pparams sealed)
    >>= expectBytes
  assertEqual "poly roundtrip" pt opened
  tampered <- runEffect env resolver (FxCipher DirDecrypt chachaPolyMech
    (Just chachaPolyOid) pparams (polyCt <> BS.pack [0] <> BS.drop 1 polyTag))
  case tampered of
    GotCryptoError (CryptoAuthFailed _) -> pure ()
    other -> assertFailure ("expected AuthFailed, got: " ++ show other)
  badPoly <- runEffect env resolver (FxCipher DirEncrypt chachaPolyMech
    (Just chachaPolyOid) (encodeChachaPolyParams pnonce paad 8) pt)
  case badPoly of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

caseDriverGcm :: IO ()
caseDriverGcm = withBackend $ \env -> do
  -- Canonical gcm-params/1 image: tagLen || ivLen || iv || aad.
  let params = u64be 16 <> u64be 12 <> "0123456789ab" <> "AD"
      u64be :: Int -> ByteString
      u64be n = BS.pack [fromIntegral (n `shiftR` s) .&. 0xff | s <- [56, 48 .. 0]]
  out <- runEffect env resolver
      (FxCipher DirEncrypt aesGcmMech (Just aesOid) params "hello!")
    >>= expectBytes
  -- Ciphertext plus the 16-byte tag in one answer.
  assertEqual "ct+tag length" (6 + 16) (BS.length out)
  let (ct, tag) = BS.splitAt 6 out
  pt <- runEffect env resolver
      (FxCipher DirDecrypt aesGcmMech (Just aesOid) params out)
    >>= expectBytes
  assertEqual "decrypt recovers" "hello!" pt
  -- Tag tamper fails closed (never a wrong plaintext).
  tampered <- runEffect env resolver
    (FxCipher DirDecrypt aesGcmMech (Just aesOid) params (ct <> BS.pack [0] <> BS.drop 1 tag))
  case tampered of
    GotCryptoError (CryptoAuthFailed _) -> pure ()
    other -> assertFailure ("expected AuthFailed, got: " ++ show other)

caseDriverCcm :: IO ()
caseDriverCcm = withBackend $ \env -> do
  -- Canonical ccm-params/1 image via the recipe encoder.
  let nonce = "0123456789ab"
      params d = encodeCcmParams nonce "AD" 16 d
  out <- runEffect env resolver
      (FxCipher DirEncrypt aesCcmMech (Just aesOid) (params 6) "hello!")
    >>= expectBytes
  -- Ciphertext plus the 16-byte tag in one answer.
  assertEqual "ct+tag length" (6 + 16) (BS.length out)
  pt <- runEffect env resolver
      (FxCipher DirDecrypt aesCcmMech (Just aesOid) (params 6) out)
    >>= expectBytes
  assertEqual "decrypt recovers" "hello!" pt
  -- ulDataLen mismatch is a recipe refusal (CryptoFailed, never Unsupported).
  bad <- runEffect env resolver
      (FxCipher DirEncrypt aesCcmMech (Just aesOid) (params 5) "hello!")
  case bad of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  -- Tag tamper fails closed (never a wrong plaintext).
  let (ct, tag) = BS.splitAt 6 out
  tampered <- runEffect env resolver
    (FxCipher DirDecrypt aesCcmMech (Just aesOid) (params 6) (ct <> BS.pack [0] <> BS.drop 1 tag))
  case tampered of
    GotCryptoError (CryptoAuthFailed _) -> pure ()
    other -> assertFailure ("expected AuthFailed, got: " ++ show other)

caseDriverAes :: IO ()
caseDriverAes = withBackend $ \env -> do
  ct <- runEffect env resolver
      (FxCipher DirEncrypt aesCbcMech (Just aesOid) aes256Iv aes256Pt)
    >>= expectBytes
  assertEqual "SP 800-38A F.2.5" aes256Ct ct
  pt <- runEffect env resolver
      (FxCipher DirDecrypt aesCbcMech (Just aesOid) aes256Iv ct)
    >>= expectBytes
  assertEqual "decrypt recovers" aes256Pt pt
  -- A 16-byte key is AES-128, not a bad key (it
  -- encrypts and decrypts through the recipe mapping); a 15-byte
  -- key is a recipe refusal (CryptoFailed, never Unsupported).
  let shortKey oid
        | oid == aesOid = Just (KeyBytes (BS.take 16 aes256Key))
        | otherwise = Nothing
  ct16 <- runEffect env shortKey
    (FxCipher DirEncrypt aesCbcMech (Just aesOid) aes256Iv aes256Pt)
    >>= expectBytes
  pt16 <- runEffect env shortKey
    (FxCipher DirDecrypt aesCbcMech (Just aesOid) aes256Iv ct16)
    >>= expectBytes
  assertEqual "aes-128 roundtrip" aes256Pt pt16
  let badLenKey oid
        | oid == aesOid = Just (KeyBytes (BS.take 15 aes256Key))
        | otherwise = Nothing
  badKey <- runEffect env badLenKey
    (FxCipher DirEncrypt aesCbcMech (Just aesOid) aes256Iv aes256Pt)
  case badKey of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badIv <- runEffect env resolver
    (FxCipher DirEncrypt aesCbcMech (Just aesOid) "short" aes256Pt)
  case badIv of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

camCtrMech :: MechanismId
camCtrMech = MechanismId 0x558

-- RFC 5528 TV#1/#4/#7 (single-block Camellia-CTR at 128/192/256;
-- counter block drives the 16-byte IV directly).
camCtr128Key, camCtr128Icb, camCtrPt, camCtr128Ct :: ByteString
camCtr128Key = hex "ae6852f8121067cc4bf7a5765577f39e"
camCtr128Icb = hex "00000030000000000000000000000001"
camCtrPt = hex "53696e676c6520626c6f636b206d7367"
camCtr128Ct = hex "d09dc29a8214619a20877c76db1f0b3f"

camCtr192Key, camCtr192Icb, camCtr192Ct :: ByteString
camCtr192Key = hex "16af5b145fc9f579c175f93e3bfb0eed863d06ccfdb78515"
camCtr192Icb = hex "0000004836733c147d6d93cb00000001"
camCtr192Ct = hex "2379399e8a8d2b2b16702fc78b9e9696"

camCtr256Key, camCtr256Icb, camCtr256Ct :: ByteString
camCtr256Key = hex "776beff2851db06f4c8a0542c8696f6c6a81af1eec96b4d37fc1d689e6c1c104"
camCtr256Icb = hex "00000060db5672c97aa8f0b200000001"
camCtr256Ct = hex "3401f9c8247effcebd6994714c1bbb11"

caseDriverCamelliaCtr :: IO ()
caseDriverCamelliaCtr = withBackend $ \env -> do
  let c128 = ObjectId 81
      c192 = ObjectId 82
      c256 = ObjectId 83
      res oid
        | oid == c128 = Just (KeyBytes camCtr128Key)
        | oid == c192 = Just (KeyBytes camCtr192Key)
        | oid == c256 = Just (KeyBytes camCtr256Key)
        | otherwise = Nothing
      enc oid icb pt =
        runEffect env res (FxCipher DirEncrypt camCtrMech (Just oid)
          (encodeCtrParams 128 icb) pt) >>= expectBytes
      dec oid icb ct =
        runEffect env res (FxCipher DirDecrypt camCtrMech (Just oid)
          (encodeCtrParams 128 icb) ct) >>= expectBytes
  ct128 <- enc c128 camCtr128Icb camCtrPt
  assertEqual "rfc5528 tv1" camCtr128Ct ct128
  ct192 <- enc c192 camCtr192Icb camCtrPt
  assertEqual "rfc5528 tv4" camCtr192Ct ct192
  ct256 <- enc c256 camCtr256Icb camCtrPt
  assertEqual "rfc5528 tv7" camCtr256Ct ct256
  pt128 <- dec c128 camCtr128Icb ct128
  assertEqual "decrypt recovers" camCtrPt pt128
  -- CTR streams unaligned input.
  ragged <- enc c128 camCtr128Icb "twenty bytes exactly!!"
  assertEqual "stream length" 22 (BS.length ragged)
  back <- dec c128 camCtr128Icb ragged
  assertEqual "stream roundtrip" "twenty bytes exactly!!" back
  -- Refusals: off-width images and bad key lengths fail closed.
  badWidth <- runEffect env res (FxCipher DirEncrypt camCtrMech (Just c128)
    (encodeCtrParams 64 camCtr128Icb) camCtrPt)
  case badWidth of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  let badLenKey oid
        | oid == c128 = Just (KeyBytes (BS.take 15 camCtr128Key))
        | otherwise = Nothing
  badKey <- runEffect env badLenKey (FxCipher DirEncrypt camCtrMech (Just c128)
    (encodeCtrParams 128 camCtr128Icb) camCtrPt)
  case badKey of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- Legacy driver routing: DES-CBC through the raw-IV path and
-- RC2-CBC through the canonical-image path (oracle KATs), plus
-- RC2 parameter refusals. IDs at core/Haskoki/Registry/Generated.
desCbcMech, rc2CbcMech :: MechanismId
desCbcMech = MechanismId 0x122
rc2CbcMech = MechanismId 0x102

drvDesKey, drvDesIv, drvDesPt, drvDesCt :: ByteString
drvDesKey = hex "540b316b5cd417e5"
drvDesIv = hex "0552d668d3319583"
drvDesPt = hex "c687007ed5972de9e31b5aa7745368b9"
drvDesCt = hex "ccfec8fe28d5828eb8fce5dbd0029d7f"

drvRc2Key, drvRc2Iv, drvRc2Pt, drvRc2Ct :: ByteString
drvRc2Key = hex "000102030405060708090a0b0c0d0e0f"
drvRc2Iv = hex "0102030405060708"
drvRc2Pt = hex "0123456789abcdeffedcba9876543210"
drvRc2Ct = hex "5dc06db7afa1896aa2c26c096309b4bf"

caseDriverLegacy :: IO ()
caseDriverLegacy = withBackend $ \env -> do
  let dOid = ObjectId 84
      rOid = ObjectId 85
      res oid
        | oid == dOid = Just (KeyBytes drvDesKey)
        | oid == rOid = Just (KeyBytes drvRc2Key)
        | otherwise = Nothing
  ct <- runEffect env res
      (FxCipher DirEncrypt desCbcMech (Just dOid) drvDesIv drvDesPt)
    >>= expectBytes
  assertEqual "des-cbc oracle kat" drvDesCt ct
  pt <- runEffect env res
      (FxCipher DirDecrypt desCbcMech (Just dOid) drvDesIv ct)
    >>= expectBytes
  assertEqual "des-cbc decrypt recovers" drvDesPt pt
  let rc2Params = encodeRc2CbcParams 128 drvRc2Iv
  ct2 <- runEffect env res
      (FxCipher DirEncrypt rc2CbcMech (Just rOid) rc2Params drvRc2Pt)
    >>= expectBytes
  assertEqual "rc2-cbc oracle kat" drvRc2Ct ct2
  pt2 <- runEffect env res
      (FxCipher DirDecrypt rc2CbcMech (Just rOid) rc2Params ct2)
    >>= expectBytes
  assertEqual "rc2-cbc decrypt recovers" drvRc2Pt pt2
  -- RC2 parameter refusals fail closed at the recipe: zero
  -- effective bits and mistimed images never reach the backend.
  badBits <- runEffect env res (FxCipher DirEncrypt rc2CbcMech (Just rOid)
    (encodeRc2CbcParams 0 drvRc2Iv) drvRc2Pt)
  case badBits of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badShape <- runEffect env res (FxCipher DirEncrypt rc2CbcMech (Just rOid)
    "short" drvRc2Pt)
  case badShape of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  -- A 7-byte DES key is a recipe refusal, never Unsupported.
  let badLenKey oid
        | oid == dOid = Just (KeyBytes (BS.take 7 drvDesKey))
        | otherwise = Nothing
  badKey <- runEffect env badLenKey (FxCipher DirEncrypt desCbcMech (Just dOid)
    drvDesIv drvDesPt)
  case badKey of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- Encrypt-data derive mechs (header ids at spec/vendor/pkcs11.h).
aesCbcEdMech, aesEcbEdMech :: MechanismId
aesCbcEdMech = MechanismId 0x1105
aesEcbEdMech = MechanismId 0x1104

ariaCbcEdMech, ariaEcbEdMech :: MechanismId
ariaCbcEdMech = MechanismId 0x567
ariaEcbEdMech = MechanismId 0x566

camCbcEdMech, camEcbEdMech :: MechanismId
camCbcEdMech = MechanismId 0x557
camEcbEdMech = MechanismId 0x556

d3CbcEdMech, d3EcbEdMech :: MechanismId
d3CbcEdMech = MechanismId 0x1103
d3EcbEdMech = MechanismId 0x1102

desCbcEdMech, desEcbEdMech, seedCbcEdMech, seedEcbEdMech :: MechanismId
desCbcEdMech = MechanismId 0x1101
desEcbEdMech = MechanismId 0x1100
seedCbcEdMech = MechanismId 0x657
seedEcbEdMech = MechanismId 0x656

-- Shared fixtures: 128-bit key/IV plus two distinct data blocks
-- (CBC chaining and ECB confusion both visible); 3DES takes a
-- 24-byte three-key key, 8-byte IV, two 8-byte blocks. Goldens are
-- python-cryptography output, decrypt-verified under the pinned
-- OpenSSL 4.0.2 CLI (AES-ECB block one is NIST F.1.1; ARIA-CBC
-- block one repeats the committed ARIA fixture).
edKey128, edIv16, edData32 :: ByteString
edKey128 = hex "000102030405060708090a0b0c0d0e0f"
edIv16 = hex "000102030405060708090a0b0c0d0e0f"
edData32 = hex "00112233445566778899aabbccddeeff" <> hex "ffeeddccbbaa99887766554433221100"

edKey24, edIv8, edData16 :: ByteString
edKey24 = hex "0123456789abcdeff0e1d2c3b4a596870123456789abcdef"
edIv8 = hex "0001020304050607"
edData16 = hex "00112233445566778899aabbccddeeff"

-- Legacy encrypt-data goldens are pinned-oracle vectors
-- (mechanism_vectors/des_ecb.json, des_cbc.json, seed_ecb.json,
-- seed_cbc.json; DES-CBC reuses the drvDes fixtures above).
edDesEcbKey, edDesEcbData, edDesEcbCt :: ByteString
edDesEcbKey = hex "ae7a5bff9a66ccd4"
edDesEcbData = hex "6614a40c7202bad03f5b8b962d7c6435"
edDesEcbCt = hex "795b284fe8a856259daa3e683e85cf12"

edSeedCbcKey, edSeedCbcIv, edSeedCbcData, edSeedCbcCt :: ByteString
edSeedCbcKey = hex "428347c5863bd4348f1e9e2fec808513"
edSeedCbcIv = hex "8622f0291038b9f34217732a92697c8e"
edSeedCbcData = hex "ae96f55be2bf3caeef848dda2e200a84"
edSeedCbcCt = hex "abe7139abb5ef24d59602b356726fb85"

edSeedEcbKey, edSeedEcbData, edSeedEcbCt :: ByteString
edSeedEcbKey = hex "630097850757e0a64b1d385a7c30a5f7"
edSeedEcbData = hex "9406e50d3ae6de268202d2754f45e9d1"
edSeedEcbCt = hex "f353f89ce52d7929a1df5e2a37fdbf5b"

caseDriverEncryptData :: IO ()
caseDriverEncryptData = withBackend $ \env -> do
  let kAes = ObjectId 91
      kAria = ObjectId 92
      kCam = ObjectId 93
      kD3 = ObjectId 94
      kDesCbc = ObjectId 95
      kDesEcb = ObjectId 96
      kSeedCbc = ObjectId 97
      kSeedEcb = ObjectId 98
      res oid
        | oid == kAes = Just (KeyBytes edKey128)
        | oid == kAria = Just (KeyBytes edKey128)
        | oid == kCam = Just (KeyBytes edKey128)
        | oid == kD3 = Just (KeyBytes edKey24)
        | oid == kDesCbc = Just (KeyBytes drvDesKey)
        | oid == kDesEcb = Just (KeyBytes edDesEcbKey)
        | oid == kSeedCbc = Just (KeyBytes edSeedCbcKey)
        | oid == kSeedEcb = Just (KeyBytes edSeedEcbKey)
        | otherwise = Nothing
      derive oid mech params outLen =
        runEffect env res (FxDerive mech (Just oid) Nothing params BS.empty outLen)
          >>= expectBytes
      cbc = edIv16 <> edData32
      d3cbc = edIv8 <> edData16
  full <- derive kAes aesCbcEdMech cbc 32
  assertEqual "aes-cbc full" (hex "76d0627da1d290436e21a4af7fca94b730cdf5479769414250df6cf5d3fcae8e") full
  trunc <- derive kAes aesCbcEdMech cbc 16
  assertEqual "truncation prefix" (BS.take 16 full) trunc
  ecb <- derive kAes aesEcbEdMech edData32 32
  assertEqual "aes-ecb full" (hex "69c4e0d86a7b0430d8cdb78070b4c55a1b872378795f4ffd772855fc87ca964d") ecb
  ariaCbc <- derive kAria ariaCbcEdMech cbc 32
  assertEqual "aria-cbc full" (hex "d87ae512c018266fcd74ddf801efabf92b8636eb88dd8d019510238ff02804d7") ariaCbc
  ariaEcb <- derive kAria ariaEcbEdMech edData32 32
  assertEqual "aria-ecb full" (hex "d718fbd6ab644c739da95f3be6451778385de1969edfa82817cb70d63530f634") ariaEcb
  camCbc <- derive kCam camCbcEdMech cbc 32
  assertEqual "camellia-cbc full" (hex "94887caa8b90cd132d9aa972db3e52bbd31bfa4ec4d6392631742a8ad4cf91a6") camCbc
  camEcb <- derive kCam camEcbEdMech edData32 32
  assertEqual "camellia-ecb full" (hex "77cf412067af8270613529149919546f460efad46fc3bf49c3b66d8bff668492") camEcb
  d3cbc <- derive kD3 d3CbcEdMech d3cbc 16
  assertEqual "des3-cbc full" (hex "a78cd104d767ee1a17dfe53c25fb97d3") d3cbc
  d3ecb <- derive kD3 d3EcbEdMech edData16 16
  assertEqual "des3-ecb full" (hex "534c0b5cdcb62ea80cfcfab978042851") d3ecb
  desCbc <- derive kDesCbc desCbcEdMech (drvDesIv <> drvDesPt) 16
  assertEqual "des-cbc full" drvDesCt desCbc
  desTrunc <- derive kDesCbc desCbcEdMech (drvDesIv <> drvDesPt) 8
  assertEqual "des-cbc truncation prefix" (BS.take 8 drvDesCt) desTrunc
  desEcb <- derive kDesEcb desEcbEdMech edDesEcbData 16
  assertEqual "des-ecb full" edDesEcbCt desEcb
  seedCbc <- derive kSeedCbc seedCbcEdMech (edSeedCbcIv <> edSeedCbcData) 16
  assertEqual "seed-cbc full" edSeedCbcCt seedCbc
  seedEcb <- derive kSeedEcb seedEcbEdMech edSeedEcbData 16
  assertEqual "seed-ecb full" edSeedEcbCt seedEcb
  -- Refusals: ragged frames and bad key lengths fail closed.
  ragged <- runEffect env res
    (FxDerive aesCbcEdMech (Just kAes) Nothing (edIv16 <> BS.replicate 20 0) BS.empty 16)
  case ragged of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  let badLenKey oid
        | oid == kAes = Just (KeyBytes (BS.take 15 edKey128))
        | otherwise = Nothing
  badKey <- runEffect env badLenKey
    (FxDerive aesCbcEdMech (Just kAes) Nothing cbc BS.empty 32)
  case badKey of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

rsaPkcsWrapMech, rsaOaepWrapMech, rsaX509WrapMech, sha256RsaMech :: MechanismId
rsaPkcsWrapMech = MechanismId 0x1
rsaOaepWrapMech = MechanismId 0x9
rsaX509WrapMech = MechanismId 0x3
sha256RsaMech = MechanismId 0x40

caseDriverRsaWrap :: IO ()
caseDriverRsaWrap = withBackend $ \env -> do
  gen <- generateKey env (GenRSA 2048 65537)
  (priv, pub) <- case gen of
    EngineOk (p, Just q) -> pure (p, q)
    other -> assertFailure ("keygen failed: " ++ show other)
  let pubOid = ObjectId 41
      privOid = ObjectId 42
      res oid
        | oid == pubOid = Just pub
        | oid == privOid = Just priv
        | otherwise = Nothing
      oaep = encodeOaepParams "SHA256" "SHA256" BS.empty
      target = "wrap-target-16byte"
  -- v1.5: modulus-wide, randomized, reversible.
  c1 <- runEffect env res
      (FxWrap rsaPkcsWrapMech (Just pubOid) BS.empty target)
    >>= expectBytes
  assertEqual "v1.5 modulus-wide" 256 (BS.length c1)
  c2 <- runEffect env res
      (FxWrap rsaPkcsWrapMech (Just pubOid) BS.empty target)
    >>= expectBytes
  assertBool "v1.5 randomized" (c1 /= c2)
  p1 <- runEffect env res
      (FxUnwrap rsaPkcsWrapMech (Just privOid) BS.empty c1)
    >>= expectBytes
  assertEqual "v1.5 reversible" target p1
  -- OAEP: likewise.
  o1 <- runEffect env res
      (FxWrap rsaOaepWrapMech (Just pubOid) oaep target)
    >>= expectBytes
  assertEqual "oaep modulus-wide" 256 (BS.length o1)
  o2 <- runEffect env res
      (FxWrap rsaOaepWrapMech (Just pubOid) oaep target)
    >>= expectBytes
  assertBool "oaep randomized" (o1 /= o2)
  po <- runEffect env res
      (FxUnwrap rsaOaepWrapMech (Just privOid) oaep o1)
    >>= expectBytes
  assertEqual "oaep reversible" target po
  assertBool "padding domains separate" (c1 /= o1)
  -- Tampering fails closed with a verdict, never a wrong plaintext.
  -- The tamper byte is guaranteed to differ (a literal "X" equals
  -- the ciphertext tail with probability 1/256, unwrapping
  -- successfully and flaking the verdict).
  let tamperB = if BS.last o1 == 0x58 then 0x59 else 0x58
  tampered <- runEffect env res
    (FxUnwrap rsaOaepWrapMech (Just privOid) oaep (BS.init o1 <> BS.singleton tamperB))
  case tampered of
    GotCryptoError (CryptoAuthFailed _) -> pure ()
    other -> assertFailure ("expected AuthFailed, got: " ++ show other)
  -- v1.5 takes no parameters; the digest v1.5 rows never wrap.
  badParams <- runEffect env res
    (FxWrap rsaPkcsWrapMech (Just pubOid) "nope" target)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  digestRow <- runEffect env res
    (FxWrap sha256RsaMech (Just pubOid) BS.empty target)
  case digestRow of
    GotCryptoError (CryptoUnsupported _ _) -> pure ()
    other -> assertFailure ("expected Unsupported, got: " ++ show other)

caseDriverRsaX509Wrap :: IO ()
caseDriverRsaX509Wrap = withBackend $ \env -> do
  gen <- generateKey env (GenRSA 2048 65537)
  (priv, pub) <- case gen of
    EngineOk (p, Just q) -> pure (p, q)
    other -> assertFailure ("keygen failed: " ++ show other)
  let pubOid = ObjectId 41
      privOid = ObjectId 42
      res oid
        | oid == pubOid = Just pub
        | oid == privOid = Just priv
        | otherwise = Nothing
      target = "wrap-target-16byte"
  -- X.509: modulus-wide, deterministic, and the decrypted block
  -- carries the key in its trailing bytes (the planner slices).
  c1 <- runEffect env res
      (FxWrap rsaX509WrapMech (Just pubOid) BS.empty target)
    >>= expectBytes
  assertEqual "x509 modulus-wide" 256 (BS.length c1)
  c2 <- runEffect env res
      (FxWrap rsaX509WrapMech (Just pubOid) BS.empty target)
    >>= expectBytes
  assertEqual "x509 deterministic" c1 c2
  p1 <- runEffect env res
      (FxUnwrap rsaX509WrapMech (Just privOid) BS.empty c1)
    >>= expectBytes
  assertEqual "x509 block-wide" 256 (BS.length p1)
  let tailOf = BS.drop (256 - BS.length target)
  assertEqual "x509 trailing key bytes" target (tailOf p1)
  -- Tampering garbles instead of failing: raw RSA has no verdict.
  g1 <- runEffect env res
      (FxUnwrap rsaX509WrapMech (Just privOid) BS.empty (BS.init c1 <> "X"))
    >>= expectBytes
  assertBool "x509 tamper garbles" (tailOf g1 /= target)
  -- X.509 takes no parameters.
  badParams <- runEffect env res
    (FxWrap rsaX509WrapMech (Just pubOid) "nope" target)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

caseDriverEcdsa :: IO ()
caseDriverEcdsa = withBackend $ \env -> do
  gen <- generateKey env (GenEC (EcSpec "P-256" "DER"))
  (priv, pub) <- case gen of
    EngineOk (p, Just q) -> pure (p, q)
    other -> assertFailure ("keygen failed: " ++ show other)
  let privOid = ObjectId 31
      pubOid = ObjectId 32
      res oid
        | oid == privOid = Just priv
        | oid == pubOid = Just pub
        | otherwise = Nothing
      msg = "ecdsa driver roundtrip" :: ByteString
  sig <- runEffect env res (FxSign ecdsaMech (Just privOid) "DER" msg)
    >>= expectBytes
  vGood <- runEffect env res (FxVerify ecdsaMech (Just pubOid) "DER" msg sig)
  assertEqual "DER verifies" (GotValid True) vGood
  vBad <- runEffect env res
    (FxVerify ecdsaMech (Just pubOid) "DER" msg (BS.map (255 -) sig))
  assertEqual "DER tamper rejects" (GotValid False) vBad
  sigRaw <- runEffect env res (FxSign ecdsaMech (Just privOid) "RAW" msg)
    >>= expectBytes
  vRaw <- runEffect env res (FxVerify ecdsaMech (Just pubOid) "RAW" msg sigRaw)
  assertEqual "RAW verifies" (GotValid True) vRaw
  bogus <- runEffect env res (FxSign ecdsaMech (Just privOid) "PEM" msg)
  case bogus of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  -- 0x1041 is the raw row (no hashing); the digested rows
  -- hash-and-sign (here SHA-256 over a long message).
  let sha256MechDig = MechanismId 0x1044
      long = BS.replicate 100 0x61
  sigH <- runEffect env res (FxSign sha256MechDig (Just privOid) "DER" long)
    >>= expectBytes
  vH <- runEffect env res (FxVerify sha256MechDig (Just pubOid) "DER" long sigH)
  assertEqual "digested verifies" (GotValid True) vH
  -- The raw row truncates overlong input to the leftmost order
  -- bits (SEC1 §4.1.3): a 100-byte message signs and verifies.
  sigLong <- runEffect env res (FxSign ecdsaMech (Just privOid) "DER" long)
    >>= expectBytes
  vLong <- runEffect env res (FxVerify ecdsaMech (Just pubOid) "DER" long sigLong)
  assertEqual "truncated verifies" (GotValid True) vLong

-- | ECDH through the driver — full-width agreement equals
-- the direct backend call, truncation drops leading bytes
-- (PKCS#11 v3.2), the reverse direction commutes, cofactor agrees
-- (h=1), over-length/KDF/info faults refuse typed.
caseDriverEcdh :: IO ()
caseDriverEcdh = withBackend $ \env -> do
  genA <- generateKey env (GenEC (EcSpec "P-256" "DER"))
  (privA, pubA) <- case genA of
    EngineOk (p, Just q) -> pure (p, q)
    other -> assertFailure ("keygen A failed: " ++ show other)
  genB <- generateKey env (GenEC (EcSpec "P-256" "DER"))
  (privB, pubB) <- case genB of
    EngineOk (p, Just q) -> pure (p, q)
    other -> assertFailure ("keygen B failed: " ++ show other)
  peerB <- case pubB of
    KeyDer bs -> pure bs
    KeyBytes bs -> pure bs
    other -> assertFailure ("peer B not material: " ++ show other)
  peerA <- case pubA of
    KeyDer bs -> pure bs
    KeyBytes bs -> pure bs
    other -> assertFailure ("peer A not material: " ++ show other)
  let aOid = ObjectId 41
      bOid = ObjectId 42
      res oid
        | oid == aOid = Just privA
        | oid == bOid = Just privB
        | otherwise = Nothing
      blob peer = encodeEcdhParams 0 BS.empty peer
  directR <- ecdhDerive env EcdhPlain privA pubB
  direct <- case directR of
    EngineOk s -> pure s
    other -> assertFailure ("direct derive failed: " ++ show other)
  full <- runEffect env res (FxDerive ecdhMech (Just aOid) Nothing (blob peerB) BS.empty 32)
    >>= expectBytes
  assertEqual "driver == direct" direct full
  short <- runEffect env res (FxDerive ecdhMech (Just aOid) Nothing (blob peerB) BS.empty 16)
    >>= expectBytes
  assertEqual "truncation drops leading bytes" (BS.drop 16 direct) short
  rev <- runEffect env res (FxDerive ecdhMech (Just bOid) Nothing (blob peerA) BS.empty 32)
    >>= expectBytes
  assertEqual "commutes" direct rev
  cof <- runEffect env res (FxDerive ecdhCofMech (Just aOid) Nothing (blob peerB) BS.empty 32)
    >>= expectBytes
  assertEqual "cofactor agrees" direct cof
  over <- runEffect env res (FxDerive ecdhMech (Just aOid) Nothing (blob peerB) BS.empty 33)
  case over of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  kdf <- runEffect env res
    (FxDerive ecdhMech (Just aOid) Nothing (encodeEcdhParams 1 BS.empty peerB) BS.empty 32)
  case kdf of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  inf <- runEffect env res (FxDerive ecdhMech (Just aOid) Nothing (blob peerB) "info" 32)
  case inf of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

caseDriverDh :: IO ()
caseDriverDh = withBackend $ \env -> do
  let params = dhParamsDer dhP2048 (BS.singleton 2)
  genA <- generateKey env (GenDHKeypair params)
  (privA, pubA) <- case genA of
    EngineOk (p, Just q) -> pure (p, q)
    other -> assertFailure ("keygen A failed: " ++ show other)
  genB <- generateKey env (GenDHKeypair params)
  (privB, pubB) <- case genB of
    EngineOk (p, Just q) -> pure (p, q)
    other -> assertFailure ("keygen B failed: " ++ show other)
  peerB <- case pubB of
    KeyDer bs -> case dhSpkiFields bs of
      Just (_, _, _, y) -> pure y
      Nothing -> assertFailure "SPKI B failed to parse"
    other -> assertFailure ("peer B not DER: " ++ show other)
  peerA <- case pubA of
    KeyDer bs -> case dhSpkiFields bs of
      Just (_, _, _, y) -> pure y
      Nothing -> assertFailure "SPKI A failed to parse"
    other -> assertFailure ("peer A not DER: " ++ show other)
  let aOid = ObjectId 43
      bOid = ObjectId 44
      res oid
        | oid == aOid = Just privA
        | oid == bOid = Just privB
        | otherwise = Nothing
      blob y = encodeDhParams 0 y
  directR <- dhDerive env DhPlain privA (KeyDer peerB)
  direct <- case directR of
    EngineOk s -> pure s
    other -> assertFailure ("direct derive failed: " ++ show other)
  full <- runEffect env res (FxDerive dhMech (Just aOid) Nothing (blob peerB) BS.empty 256)
    >>= expectBytes
  assertEqual "driver == direct" direct full
  short <- runEffect env res (FxDerive dhMech (Just aOid) Nothing (blob peerB) BS.empty 128)
    >>= expectBytes
  assertEqual "truncation drops leading bytes" (BS.drop 128 direct) short
  rev <- runEffect env res (FxDerive dhMech (Just bOid) Nothing (blob peerA) BS.empty 256)
    >>= expectBytes
  assertEqual "commutes" direct rev
  x9 <- runEffect env res (FxDerive dhX942Mech (Just aOid) Nothing (blob peerB) BS.empty 256)
    >>= expectBytes
  assertEqual "x9.42 row agrees identically" direct x9
  over <- runEffect env res (FxDerive dhMech (Just aOid) Nothing (blob peerB) BS.empty 257)
  case over of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  kdf <- runEffect env res
    (FxDerive dhMech (Just aOid) Nothing (encodeDhParams 1 peerB) BS.empty 256)
  case kdf of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  inf <- runEffect env res (FxDerive dhMech (Just aOid) Nothing (blob peerB) "info" 256)
  case inf of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | CMAC through the driver over real ECB — RFC 4494
-- AES-128 vectors plus pinned-CLI AES-192\/256 and 3DES vectors,
-- GENERAL truncation, verify verdicts, and typed refusals.
caseDriverCmac :: IO ()
caseDriverCmac = withBackend $ \env -> do
  let k128 = KeyBytes (hex "2b7e151628aed2a6abf7158809cf4f3c")
      k192 = KeyBytes (hex "000102030405060708090a0b0c0d0e0f1011121314151617")
      k256 = KeyBytes (hex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
      k3a = KeyBytes (hex "0123456789abcdeffedcba9876543210")
      k3b = KeyBytes (hex "0123456789abcdeffedcba98765432100011223344556677")
      kBad = KeyBytes (hex "00112233445566778899aabbccddee")
      m0 = BS.empty
      m16 = hex "6bc1bee22e409f96e93d7e117393172a"
      m40 = hex "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"
      m60 = m40 <> hex "00112233445566778899aabbccddeeff00112233"
      m8 = hex "6bc1bee22e409f96"
      m18 = hex "6bc1bee22e409f96e93d7e117393172a4b5c"
      o128 = ObjectId 61
      o192 = ObjectId 62
      o256 = ObjectId 63
      o3a = ObjectId 64
      o3b = ObjectId 65
      oBad = ObjectId 66
      res oid
        | oid == o128 = Just k128
        | oid == o192 = Just k192
        | oid == o256 = Just k256
        | oid == o3a = Just k3a
        | oid == o3b = Just k3b
        | oid == oBad = Just kBad
        | otherwise = Nothing
      tag mech oid params msg =
        runEffect env res (FxSign mech (Just oid) params msg) >>= expectBytes
  -- RFC 4494 AES-128-CMAC (also pinned-CLI cross-checked).
  tag0 <- tag cmacMech o128 BS.empty m0
  assertEqual "rfc4494 empty" (hex "bb1d6929e95937287fa37d129b756746") tag0
  tag16 <- tag cmacMech o128 BS.empty m16
  assertEqual "rfc4494 one block" (hex "070a16b46b4d4144f79bdd9dd04a287c") tag16
  tag40 <- tag cmacMech o128 BS.empty m40
  assertEqual "rfc4494 partial" (hex "dfa66747de9ae63030ca32611497c827") tag40
  tag60 <- tag cmacMech o128 BS.empty m60
  assertEqual "cli four blocks" (hex "11dafe91b43fde679b94dc43468c1472") tag60
  -- Other AES widths (pinned CLI).
  t192 <- tag cmacMech o192 BS.empty m16
  assertEqual "cli aes192" (hex "002ffdcd32f620b60d0087178c83d16c") t192
  t256 <- tag cmacMech o256 BS.empty m16
  assertEqual "cli aes256" (hex "28a7023f452e8f82bd4bf28d8c37c35c") t256
  -- 3DES widths (pinned CLI; the 16-byte tag equals the K1||K2||K1
  -- 24-byte expansion tag).
  t3a <- tag cmac3Mech o3a BS.empty m8
  assertEqual "cli des3 two-key" (hex "0ac36c430011f46b") t3a
  t3b <- tag cmac3Mech o3b BS.empty m18
  assertEqual "cli des3 three-key" (hex "500b4e4b803ee987") t3b
  -- GENERAL truncation is the prefix on both families.
  g8 <- tag cmacGenMech o256 (encodeMacGeneral 8) m16
  assertEqual "general prefix" (BS.take 8 t256) g8
  g4 <- tag cmac3GenMech o3b (encodeMacGeneral 4) m18
  assertEqual "des3 general prefix" (BS.take 4 t3b) g4
  -- Verify verdicts.
  vGood <- runEffect env res (FxVerify cmacMech (Just o128) BS.empty m16 tag16)
  assertEqual "verifies" (GotValid True) vGood
  vBad <- runEffect env res (FxVerify cmacMech (Just o128) BS.empty m16
    (BS.map (255 -) tag16))
  assertEqual "tamper rejects" (GotValid False) vBad
  vGen <- runEffect env res (FxVerify cmacGenMech (Just o256)
    (encodeMacGeneral 8) m16 g8)
  assertEqual "general verifies" (GotValid True) vGen
  -- Typed refusals: bad key length, bad params, bad GENERAL length.
  badLen <- runEffect env res (FxSign cmacMech (Just oBad) BS.empty m16)
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badParams <- runEffect env res (FxSign cmacMech (Just o128) "x" m16)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badGen <- runEffect env res (FxSign cmac3GenMech (Just o3b)
    (encodeMacGeneral 9) m18)
  case badGen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | 3DES-MAC through the driver over real ECB — lane des3_mac
-- vectors (one-block 192-bit, plain half block + GENERAL full
-- block) plus pinned-CLI two-key and zero-padded multi-block
-- vectors, GENERAL truncation, verify verdicts, and typed
-- refusals.
caseDriverDes3Mac :: IO ()
caseDriverDes3Mac = withBackend $ \env -> do
  let kLane = KeyBytes (hex "96dea09d832e4609742ccd800a8958caecdb70730c27d8b1")
      k2 = KeyBytes (hex "0123456789abcdeffedcba9876543210")
      k3 = KeyBytes (hex "0123456789abcdeffedcba98765432100011223344556677")
      kBad = KeyBytes (hex "00112233445566778899aabbccddee")
      mLane = hex "0cb1c9965ea202b0"
      m8 = hex "6bc1bee22e409f96"
      m18 = hex "6bc1bee22e409f96e93d7e117393172a4b5c"
      oLane = ObjectId 67
      o2 = ObjectId 68
      o3 = ObjectId 69
      oBad = ObjectId 70
      res oid
        | oid == oLane = Just kLane
        | oid == o2 = Just k2
        | oid == o3 = Just k3
        | oid == oBad = Just kBad
        | otherwise = Nothing
      tag mech oid params msg =
        runEffect env res (FxSign mech (Just oid) params msg) >>= expectBytes
  -- Lane vectors: one-block 192-bit key, plain emits the first
  -- 4 of the 8-byte CBC-MAC block, GENERAL the full block.
  tLane <- tag des3macMech oLane BS.empty mLane
  assertEqual "lane half block" (hex "2bc46d1d") tLane
  gLane <- tag des3macGenMech oLane (encodeMacGeneral 8) mLane
  assertEqual "lane full block" (hex "2bc46d1df3349c3b") gLane
  -- Pinned CLI: two-key expands K1||K2||K1; ragged input
  -- zero-pads (18 bytes -> 24 zero-padded, last CBC block).
  t2 <- tag des3macMech o2 BS.empty m8
  assertEqual "cli two-key" (hex "ea43f9aa") t2
  t3 <- tag des3macGenMech o3 (encodeMacGeneral 8) m18
  assertEqual "cli ragged padded" (hex "642073063006a81a") t3
  -- GENERAL truncation is the prefix.
  g4 <- tag des3macGenMech oLane (encodeMacGeneral 4) mLane
  assertEqual "general prefix" tLane g4
  -- Verify verdicts.
  vGood <- runEffect env res (FxVerify des3macMech (Just oLane) BS.empty mLane tLane)
  assertEqual "verifies" (GotValid True) vGood
  vBad <- runEffect env res (FxVerify des3macMech (Just oLane) BS.empty mLane
    (BS.map (255 -) tLane))
  assertEqual "tamper rejects" (GotValid False) vBad
  vGen <- runEffect env res (FxVerify des3macGenMech (Just oLane)
    (encodeMacGeneral 8) mLane gLane)
  assertEqual "general verifies" (GotValid True) vGen
  -- Typed refusals: bad key length, bad params, bad GENERAL length.
  badLen <- runEffect env res (FxSign des3macMech (Just oBad) BS.empty m8)
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badParams <- runEffect env res (FxSign des3macMech (Just oLane) "x" mLane)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badGen <- runEffect env res (FxSign des3macGenMech (Just o3)
    (encodeMacGeneral 9) m18)
  case badGen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | CBC-MAC through the driver over real AES\/ARIA\/Camellia ECB:
-- single-block anchors (FIPS-197 AES, the oracle's ARIA\/Camellia
-- MAC vectors), CLI+pinned-python chaining vectors (two-block and
-- ragged zero-padded), GENERAL truncation, verify verdicts, and
-- typed refusals. Plain rows emit the first 8 of the final
-- 16-byte CBC-MAC block (the OASIS half-block rule).
caseDriverCbcMac :: IO ()
caseDriverCbcMac = withBackend $ \env -> do
  let kAes = KeyBytes (hex "000102030405060708090a0b0c0d0e0f")
      kAria = KeyBytes (hex "6de74ebf339ee34b1abaf3fbab7feee5")
      kCam = KeyBytes (hex "fac1358c3c30f3869337eea6e9a92fbd")
      kBad = KeyBytes (hex "00112233445566778899aabbccddee")
      b1 = hex "00112233445566778899aabbccddeeff"
      b2 = hex "000102030405060708090a0b0c0d0e0f"
      tail4 = hex "00112233"
      mAria = hex "f7a6894b0a98a691101659f3225c28ea"
      mCam = hex "33b0b9ba525a3abe3489a3a600c295eb"
      oAes = ObjectId 71
      oAria = ObjectId 72
      oCam = ObjectId 73
      oBad = ObjectId 74
      res oid
        | oid == oAes = Just kAes
        | oid == oAria = Just kAria
        | oid == oCam = Just kCam
        | oid == oBad = Just kBad
        | otherwise = Nothing
      tag mech oid params msg =
        runEffect env res (FxSign mech (Just oid) params msg) >>= expectBytes
  -- AES anchors: FIPS-197 single block, CLI two-block + ragged.
  tAes <- tag aesMacMech oAes BS.empty b1
  assertEqual "aes half block" (hex "69c4e0d86a7b0430") tAes
  gAes <- tag aesMacGenMech oAes (encodeMacGeneral 16) b1
  assertEqual "aes full block" (hex "69c4e0d86a7b0430d8cdb78070b4c55a") gAes
  tAes2 <- tag aesMacMech oAes BS.empty (b1 <> b2)
  assertEqual "aes chained" (hex "2ee702bbfb7d094b") tAes2
  tAesR <- tag aesMacMech oAes BS.empty (b1 <> tail4)
  assertEqual "aes ragged padded" (hex "c9ad3c49c43db7a7") tAesR
  -- ARIA: oracle one-block vector plus CLI chaining vectors.
  tAria <- tag ariaMacMech oAria BS.empty mAria
  assertEqual "aria half block" (hex "b5c11c1494615dc7") tAria
  gAria <- tag ariaMacGenMech oAria (encodeMacGeneral 16) mAria
  assertEqual "aria full block" (hex "b5c11c1494615dc7d4bcd3aecf6852e4") gAria
  tAria2 <- tag ariaMacMech oAria BS.empty (b1 <> b2)
  assertEqual "aria chained" (hex "1bb011c67c340573") tAria2
  tAriaR <- tag ariaMacMech oAria BS.empty (b1 <> tail4)
  assertEqual "aria ragged padded" (hex "7aee0eb59a1238d4") tAriaR
  -- Camellia: oracle one-block vector plus CLI chaining vectors.
  tCam <- tag camMacMech oCam BS.empty mCam
  assertEqual "camellia half block" (hex "f96073b123ee5bdd") tCam
  gCam <- tag camMacGenMech oCam (encodeMacGeneral 16) mCam
  assertEqual "camellia full block" (hex "f96073b123ee5bdd75675f790362a798") gCam
  tCam2 <- tag camMacMech oCam BS.empty (b1 <> b2)
  assertEqual "camellia chained" (hex "bd81119019ddfeb1") tCam2
  tCamR <- tag camMacMech oCam BS.empty (b1 <> tail4)
  assertEqual "camellia ragged padded" (hex "4cc5169549b3803a") tCamR
  -- GENERAL truncation is the prefix.
  g5 <- tag aesMacGenMech oAes (encodeMacGeneral 5) b1
  assertEqual "general prefix" (BS.take 5 gAes) g5
  -- Verify verdicts.
  vGood <- runEffect env res (FxVerify aesMacMech (Just oAes) BS.empty b1 tAes)
  assertEqual "verifies" (GotValid True) vGood
  vBad <- runEffect env res (FxVerify aesMacMech (Just oAes) BS.empty b1
    (BS.map (255 -) tAes))
  assertEqual "tamper rejects" (GotValid False) vBad
  vGen <- runEffect env res (FxVerify ariaMacGenMech (Just oAria)
    (encodeMacGeneral 16) mAria gAria)
  assertEqual "general verifies" (GotValid True) vGen
  -- Typed refusals: bad key length, bad params, bad GENERAL length.
  badLen <- runEffect env res (FxSign camMacMech (Just oBad) BS.empty b1)
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badParams <- runEffect env res (FxSign aesMacMech (Just oAes) "x" b1)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badGen <- runEffect env res (FxSign aesMacGenMech (Just oAes)
    (encodeMacGeneral 17) b1)
  case badGen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | AES-XCBC-MAC through the driver over real AES-128-ECB: RFC
-- 3566 test cases (empty, short, block-aligned, ragged), the _96
-- truncation, verify verdicts, and typed refusals (192\/256-bit
-- keys and non-empty params refuse: XCBC is 128-bit-only).
caseDriverXcbc :: IO ()
caseDriverXcbc = withBackend $ \env -> do
  let k128 = KeyBytes (hex "000102030405060708090a0b0c0d0e0f")
      k192 = KeyBytes (hex "000102030405060708090a0b0c0d0e0f1011121314151617")
      m0 = BS.empty
      m3 = hex "000102"
      m16 = hex "000102030405060708090a0b0c0d0e0f"
      m20 = hex "000102030405060708090a0b0c0d0e0f10111213"
      o128 = ObjectId 71
      o192 = ObjectId 72
      res oid
        | oid == o128 = Just k128
        | oid == o192 = Just k192
        | otherwise = Nothing
      tag mech oid params msg =
        runEffect env res (FxSign mech (Just oid) params msg) >>= expectBytes
  -- RFC 3566 test cases #1-#4 (plain + _96).
  t1 <- tag xcbcMech o128 BS.empty m0
  assertEqual "rfc3566 #1" (hex "75f0251d528ac01c4573dfd584d79f29") t1
  n1 <- tag xcbc96Mech o128 BS.empty m0
  assertEqual "rfc3566 #1 96" (hex "75f0251d528ac01c4573dfd5") n1
  t2 <- tag xcbcMech o128 BS.empty m3
  assertEqual "rfc3566 #2" (hex "5b376580ae2f19afe7219ceef172756f") t2
  n2 <- tag xcbc96Mech o128 BS.empty m3
  assertEqual "rfc3566 #2 96" (hex "5b376580ae2f19afe7219cee") n2
  t3 <- tag xcbcMech o128 BS.empty m16
  assertEqual "rfc3566 #3" (hex "d2a246fa349b68a79998a4394ff7a263") t3
  n3 <- tag xcbc96Mech o128 BS.empty m16
  assertEqual "rfc3566 #3 96" (hex "d2a246fa349b68a79998a439") n3
  t4 <- tag xcbcMech o128 BS.empty m20
  assertEqual "rfc3566 #4" (hex "47f51b4564966215b8985c63055ed308") t4
  -- _96 truncation is the prefix.
  assertEqual "96 prefix" (BS.take 12 t4)
    =<< tag xcbc96Mech o128 BS.empty m20
  -- Verify verdicts.
  vGood <- runEffect env res (FxVerify xcbcMech (Just o128) BS.empty m16 t3)
  assertEqual "verifies" (GotValid True) vGood
  vBad <- runEffect env res (FxVerify xcbcMech (Just o128) BS.empty m16
    (BS.map (255 -) t3))
  assertEqual "tamper rejects" (GotValid False) vBad
  v96 <- runEffect env res (FxVerify xcbc96Mech (Just o128) BS.empty m3 n2)
  assertEqual "96 verifies" (GotValid True) v96
  -- Typed refusals: 192-bit key, non-empty params.
  badLen <- runEffect env res (FxSign xcbcMech (Just o192) BS.empty m16)
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badParams <- runEffect env res (FxSign xcbcMech (Just o128) "x" m16)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | AES-GMAC through the driver over the real GCM route: the
-- message travels as GCM AAD with empty plaintext (pinned tags
-- from Python cryptography AESGCM, the AEAD oracle root, plus
-- the ACVP tc16 32-bit tag), verify verdicts, and typed refusals
-- (GMAC takes gcm-params with an approved tag width and a caller
-- IV; OASIS v3.2 §6.13.6 determines the length by @ulTagBits@).
caseDriverGmac :: IO ()
caseDriverGmac = withBackend $ \env -> do
  let k128 = KeyBytes (hex "000102030405060708090a0b0c0d0e0f")
      kAcvp = KeyBytes (hex "E3F49ACE9713B2EC43B5AA9D0E0CF119")
      kBad = KeyBytes (hex "00112233445566778899aabbccddee")
      nonce = hex "000102030405060708090a0b"
      msg = "aad-data"
      o128 = ObjectId 71
      oBad = ObjectId 72
      oAcvp = ObjectId 73
      res oid
        | oid == o128 = Just k128
        | oid == oBad = Just kBad
        | oid == oAcvp = Just kAcvp
        | otherwise = Nothing
      good = encodeGcmParams nonce BS.empty 16
      tag oid params input =
        runEffect env res (FxSign gmacMech (Just oid) params input) >>= expectBytes
  t1 <- tag o128 good msg
  assertEqual "gmac tag" (hex "e01312146176abd643fcee9d4a640184") t1
  t0 <- tag o128 good BS.empty
  assertEqual "gmac empty" (hex "435b9ba12d75a4be8a977ea3cd011890") t0
  -- ACVP tc16: 32-bit tag over empty AAD.
  tag32 <- runEffect env res (FxSign gmacMech (Just oAcvp)
    (encodeGcmParams (hex "CE5AD159921FCB89FB95BF7A") BS.empty 4) BS.empty)
    >>= expectBytes
  assertEqual "gmac acvp tc16" (hex "DDF76017") tag32
  -- The params AAD field carries no meaning on the sign path: the
  -- message is the sign input only.
  tAad <- tag o128 (encodeGcmParams nonce "ignored-aad" 16) msg
  assertEqual "params aad ignored" t1 tAad
  -- Verify verdicts.
  vGood <- runEffect env res (FxVerify gmacMech (Just o128) good msg t1)
  assertEqual "verifies" (GotValid True) vGood
  vBad <- runEffect env res (FxVerify gmacMech (Just o128) good msg
    (BS.map (255 -) t1))
  assertEqual "tamper rejects" (GotValid False) vBad
  -- Typed refusals: bad key length, empty params, unapproved width.
  badLen <- runEffect env res (FxSign gmacMech (Just oBad) good msg)
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badParams <- runEffect env res (FxSign gmacMech (Just o128) BS.empty msg)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badTag <- runEffect env res
    (FxSign gmacMech (Just o128) (encodeGcmParams nonce BS.empty 5) msg)
  case badTag of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | PBKDF2 through the driver over real HMAC — RFC 6070
-- SP 800-108 vectors (triple-verified: independent python,
-- the oracle reference, the provider KBKDF CLI) plus typed
-- refusals.
caseDriverSp800 :: IO ()
caseDriverSp800 = withBackend $ \env -> do
  let kiOid = ObjectId 81
      res oid
        | oid == kiOid = Just (KeyBytes (BS.pack [0 .. 31]))
        | otherwise = Nothing
      derive mech params outLen =
        runEffect env res (FxDerive mech (Just kiOid) Nothing params BS.empty outLen)
          >>= expectBytes
      fixed = "SP800-108 test label" <> "\x00" <> "SP800-108 test context"
      counter = encodeSp800Params 4 32 32 BS.empty fixed
      feedbackIv = encodeSp800Params 4 32 32 (BS.pack [0 .. 15]) fixed
      feedback = encodeSp800Params 4 32 32 BS.empty fixed
      ctrMech = MechanismId 0x3ac
      fbMech = MechanismId 0x3ad
      dpMech = MechanismId 0x3ae
  c16 <- derive ctrMech counter 16
  assertEqual "counter aes128" (hex "caff7a6a35ca9b35afcc64fa658d8bc2") c16
  c32 <- derive ctrMech counter 32
  assertEqual "counter aes256"
    (hex "b88f2b0575ec7271d57a76d5dc05355edbb56652e0a19e1788661f2b473e35a3") c32
  f16 <- derive fbMech feedback 16
  assertEqual "feedback aes128" (hex "0eb73e600b11c4474e6fb84c226c8b1a") f16
  fi16 <- derive fbMech feedbackIv 16
  assertEqual "feedback iv aes128" (hex "6e5e3e704d682f4c420681f60d46da54") fi16
  d16 <- derive dpMech counter 16
  assertEqual "double-pipeline aes128" (hex "12a1627e163bbff00bf9d3daf7eddf92") d16
  d32 <- derive dpMech counter 32
  assertEqual "double-pipeline aes256"
    (hex "865126a55ca1386cd245a4b2ba4c29ec21a7d46d4b74c26e899fcc5a39f68b65") d32
  -- Typed refusals: junk params, a non-empty info string, and
  -- an over-ceiling length.
  junk <- runEffect env res (FxDerive ctrMech (Just kiOid) Nothing "junk" BS.empty 16)
  case junk of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed sp800 junk, got: " ++ show other)
  withInfo <- runEffect env res (FxDerive ctrMech (Just kiOid) Nothing counter "x" 16)
  case withInfo of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed sp800 info, got: " ++ show other)
  over <- runEffect env res
    (FxDerive ctrMech (Just kiOid) Nothing counter BS.empty (maxSp800Total + 1))
  case over of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed sp800 length, got: " ++ show other)
  let short = encodeSp800Params 4 8 32 BS.empty fixed
  overCtr <- runEffect env res (FxDerive ctrMech (Just kiOid) Nothing short BS.empty 8192)
  case overCtr of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed sp800 counter, got: " ++ show other)

-- | TLS-KDF vectors (triple-verified: independent python, the
-- oracle reference, the provider TLS1-PRF CLI — DH legs are
-- own vectors) plus typed refusals.
caseDriverTlsKdf :: IO ()
caseDriverTlsKdf = withBackend $ \env -> do
  let pmsOid = ObjectId 82
      dhOid = ObjectId 83
      res oid
        | oid == pmsOid = Just (KeyBytes (BS.pack [0 .. 47]))
        | oid == dhOid = Just (KeyBytes (BS.pack [0 .. 31]))
        | otherwise = Nothing
      deriveAs oid mech params outLen =
        runEffect env res (FxDerive mech (Just oid) Nothing params BS.empty outLen)
          >>= expectBytes
      cr = BS.pack [0 .. 31]
      sr = BS.pack [32 .. 63]
      seed64 = cr <> sr
      sess = BS.pack [0 .. 31]
      m10 = MechanismId 0x375
      m10dh = MechanismId 0x377
      m12 = MechanismId 0x3e0
      m12dh = MechanismId 0x3e2
      ext = MechanismId 0x56
      extdh = MechanismId 0x57
      kdf = MechanismId 0x3d9
      gen = MechanismId 0x3e5
      f10 = encodeTlsKdfParams 0 "master secret" seed64 BS.empty
      f12 = encodeTlsKdfParams 4 "master secret" seed64 BS.empty
      fExt = encodeTlsKdfParams 4 "extended master secret" sess BS.empty
      fKdf = encodeTlsKdfParams 4 "key expansion" seed64 BS.empty
      fKdfCtx = encodeTlsKdfParams 4 "key expansion" seed64 "context-info"
      fGen = encodeTlsKdfParams 0 "key expansion" seed64 BS.empty
  m48 <- deriveAs pmsOid m10 f10 48
  assertEqual "tls master" (hex "539391828d1d131678646180c5bda5c9a2eb62382c8cfb9440545cae85c8c205b93e0d22161e06be1189235aefca7570") m48
  m48dh <- deriveAs dhOid m10dh f10 48
  assertEqual "tls master dh" (hex "38b5ba7767c6c68bb2c74a70ac3406dd204997e375684d5a190b265360fbb62202053fb60f77c4733be5a97f29b856e0") m48dh
  mast48 <- deriveAs pmsOid m12 f12 48
  assertEqual "tls12 master" (hex "2b7cccb6d48adb8692df640b9252502fb000fd68fb2dc4b6a8cd67d870492f38e4c5dd509ba7c4863c003c07d23f9a3b") mast48
  t48dh <- deriveAs dhOid m12dh f12 48
  assertEqual "tls12 master dh" (hex "2f759d1b14d26737622ba106d6321958f3913a545a502a34073d305f2c90fe73d184bf43c4352b4b83e1b58072a47eb8") t48dh
  k32 <- deriveAs pmsOid kdf fKdf 32
  assertEqual "tls12 kdf" (hex "4ac38c4d46e5ff44538c63cd6644009fd1aa1b19a81b76452615cb3f94ce61ea") k32
  kc32 <- deriveAs pmsOid kdf fKdfCtx 32
  assertEqual "tls12 kdf ctx" (hex "5c0125c5f281488f681349499f252df0d29934469aabc15136b0a6a78a4b39d7") kc32
  e48 <- deriveAs pmsOid ext fExt 48
  assertEqual "extended master" (hex "c3d5ea08b472cbb67e205711e5006647e2b8cb5f6b2a20847780122bdb78cf874a37fb5aa6ae0e3ce513256f888efa1b") e48
  e48dh <- deriveAs dhOid extdh fExt 48
  assertEqual "extended master dh" (hex "48cf0bec47fd85bf9c0ed067a961a5b0bae70feef18b231d32e11c6155c49959f333fa7c155d455e67cf44cd295e3f0a") e48dh
  g32 <- deriveAs pmsOid gen fGen 32
  assertEqual "tls kdf legacy" (hex "023d49a0cea8ad8071bf64519dc8f45bd302c1db3e33d39d1f21c548d05194aa") g32
  -- Typed refusals: junk params, a non-empty info string, and
  -- an over-ceiling length.
  junk <- runEffect env res (FxDerive m10 (Just pmsOid) Nothing "junk" BS.empty 48)
  case junk of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed tlskdf junk, got: " ++ show other)
  withInfo <- runEffect env res (FxDerive m10 (Just pmsOid) Nothing f10 "x" 48)
  case withInfo of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed tlskdf info, got: " ++ show other)
  over <- runEffect env res
    (FxDerive m10 (Just pmsOid) Nothing f10 BS.empty (maxTlsKdfOutput + 1))
  case over of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed tlskdf length, got: " ++ show other)

caseDriverIke :: IO ()
caseDriverIke = withBackend $ \env -> do
  let baseOid = ObjectId 84
      auxOid = ObjectId 85
      res oid
        | oid == baseOid = Just (KeyBytes (BS.pack [0 .. 31]))
        | oid == auxOid = Just (KeyBytes (BS.pack [32 .. 63]))
        | otherwise = Nothing
      -- The frame aux number is planner-bound (onto fxKey2);
      -- the driver resolves the effect field, so these pass
      -- the external 405 in-frame and bind fxKey2 directly.
      deriveAs mAux mech params outLen =
        runEffect env res (FxDerive mech (Just baseOid) mAux params BS.empty outLen)
          >>= expectBytes
      ni = BS.pack (replicate 16 1)
      nr = BS.pack (replicate 16 2)
      seed32 = ni <> nr
      plus = MechanismId 0x402e
      prf = MechanismId 0x402f
      ike1 = MechanismId 0x4030
      ext = MechanismId 0x4031
      fPlus = encodeIkeParams 4 0 0 0 seed32 BS.empty
      fPrfDk = encodeIkeParams 4 1 0 0 ni nr
      fPrfK = encodeIkeParams 4 0 0 0 ni nr
      fIke1 = encodeIkeParams 4 0 7 405 ni nr
      fExt = encodeIkeParams 4 0 0 405 seed32 BS.empty
      fExtNox = encodeIkeParams 4 0 0 0 BS.empty BS.empty
  p32 <- deriveAs Nothing plus fPlus 32
  assertEqual "ike prf+" (hex "e3703ee905295e6c0141c98f382e17e9df07a5d0e7fb5d1d5eb45e117022cbb1") p32
  p48 <- deriveAs Nothing plus fPlus 48
  assertEqual "ike prf+ long" (hex "e3703ee905295e6c0141c98f382e17e9df07a5d0e7fb5d1d5eb45e117022cbb1c5710476207a417af1bc594f29830d68") p48
  dk32 <- deriveAs Nothing prf fPrfDk 32
  assertEqual "ike prf data-as-key" (hex "909be39279fec3ad8b16546a956974ee435bb4acfa8f0c9167f0f019ff977f45") dk32
  k32 <- deriveAs Nothing prf fPrfK 32
  assertEqual "ike prf key order" (hex "df53a0de91b1e3a8d1523ea225bbc6814065bbe96203108f45501f20467046fb") k32
  s32 <- deriveAs (Just auxOid) ike1 fIke1 32
  assertEqual "ike1 prf" (hex "612802ecc378ea82898f416865a51c36ade29e1acfbe2bceb19033c95a702f5a") s32
  e32 <- deriveAs (Just auxOid) ext fExt 32
  assertEqual "ike extended" (hex "1c81c4b9c9083605362e98bed89e4eef320559270ae273a55ed90710e74e6951") e32
  e48 <- deriveAs (Just auxOid) ext fExt 48
  assertEqual "ike extended long" (hex "1c81c4b9c9083605362e98bed89e4eef320559270ae273a55ed90710e74e6951b39e23e7bba290a013caca808ea6af06") e48
  trunc16 <- deriveAs Nothing ext fExtNox 16
  assertEqual "ike extended truncates base" (hex "000102030405060708090a0b0c0d0e0f") trunc16
  -- Typed refusals: junk params, a non-empty info string, an
  -- over-ceiling length, the missing aux key, past-counter
  -- prf+, and a single shot past its digest.
  junk <- runEffect env res (FxDerive plus (Just baseOid) Nothing "junk" BS.empty 32)
  case junk of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed ike junk, got: " ++ show other)
  withInfo <- runEffect env res (FxDerive plus (Just baseOid) Nothing fPlus "x" 32)
  case withInfo of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed ike info, got: " ++ show other)
  over <- runEffect env res
    (FxDerive plus (Just baseOid) Nothing fPlus BS.empty (maxIkeOutput + 1))
  case over of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed ike length, got: " ++ show other)
  noAux <- runEffect env res (FxDerive ike1 (Just baseOid) Nothing fIke1 BS.empty 32)
  case noAux of
    GotCryptoError (CryptoBadKey _ _) -> pure ()
    other -> assertFailure ("expected BadKey ike no-aux, got: " ++ show other)
  cap <- runEffect env res (FxDerive plus (Just baseOid) Nothing fPlus BS.empty 8161)
  case cap of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed ike counter cap, got: " ++ show other)
  wide <- runEffect env res (FxDerive prf (Just baseOid) Nothing fPrfK BS.empty 33)
  case wide of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed ike digest cap, got: " ++ show other)
  trunc <- runEffect env res (FxDerive ext (Just baseOid) Nothing fExtNox BS.empty 48)
  case trunc of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed ike trunc cap, got: " ++ show other)

caseDriverByteOps :: IO ()
caseDriverByteOps = withBackend $ \env -> do
  let baseOid = ObjectId 84
      auxOid = ObjectId 85
      res oid
        | oid == baseOid = Just (KeyBytes (BS.pack [0 .. 31]))
        | oid == auxOid = Just (KeyBytes (BS.pack [32 .. 63]))
        | otherwise = Nothing
      deriveAs mAux mech params outLen =
        runEffect env res (FxDerive mech (Just baseOid) mAux params BS.empty outLen)
          >>= expectBytes
      d16 = BS.pack (replicate 16 1)
      xd = BS.pack (replicate 32 0x0f)
      ck = MechanismId 0x360
      cbd = MechanismId 0x362
      cdb = MechanismId 0x363
      xx = MechanismId 0x364
      xt = MechanismId 0x365
      fKey = encodeByteOpsParams 405 0 BS.empty
      fBD = encodeByteOpsParams 0 0 d16
      fDB = encodeByteOpsParams 0 0 d16
      fXor = encodeByteOpsParams 0 0 xd
      fExt0 = encodeByteOpsParams 0 0 BS.empty
      fExt128 = encodeByteOpsParams 0 128 BS.empty
      fExt4 = encodeByteOpsParams 0 4 BS.empty
  k64 <- deriveAs (Just auxOid) ck fKey 64
  assertEqual "concat-key" (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f") k64
  k16 <- deriveAs (Just auxOid) ck fKey 16
  assertEqual "concat-key truncates" (hex "000102030405060708090a0b0c0d0e0f") k16
  b48 <- deriveAs Nothing cbd fBD 48
  assertEqual "concat-data" (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f01010101010101010101010101010101") b48
  d48 <- deriveAs Nothing cdb fDB 48
  assertEqual "data-concat" (hex "01010101010101010101010101010101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") d48
  x32 <- deriveAs Nothing xx fXor 32
  assertEqual "xor" (hex "0f0e0d0c0b0a090807060504030201001f1e1d1c1b1a19181716151413121110") x32
  e16 <- deriveAs Nothing xt fExt0 16
  assertEqual "extract aligned" (hex "000102030405060708090a0b0c0d0e0f") e16
  e16b <- deriveAs Nothing xt fExt128 16
  assertEqual "extract offset" (hex "101112131415161718191a1b1c1d1e1f") e16b
  e2 <- deriveAs Nothing xt fExt4 2
  assertEqual "extract sub-byte" (hex "0010") e2
  -- Typed refusals: junk params, a non-empty info string, an
  -- over-natural length, the missing aux key, the XOR
  -- mismatch, and the EXTRACT overrun.
  junk <- runEffect env res (FxDerive cbd (Just baseOid) Nothing "junk" BS.empty 16)
  case junk of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed byteop junk, got: " ++ show other)
  withInfo <- runEffect env res (FxDerive cbd (Just baseOid) Nothing fBD "x" 16)
  case withInfo of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed byteop info, got: " ++ show other)
  over <- runEffect env res (FxDerive cbd (Just baseOid) Nothing fBD BS.empty 49)
  case over of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed byteop length, got: " ++ show other)
  noAux <- runEffect env res (FxDerive ck (Just baseOid) Nothing fKey BS.empty 64)
  case noAux of
    GotCryptoError (CryptoBadKey _ _) -> pure ()
    other -> assertFailure ("expected BadKey byteop no-aux, got: " ++ show other)
  mismatch <- runEffect env res (FxDerive xx (Just baseOid) Nothing fBD BS.empty 16)
  case mismatch of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed byteop xor mismatch, got: " ++ show other)
  overrun <- runEffect env res
    (FxDerive xt (Just baseOid) Nothing (encodeByteOpsParams 0 248 BS.empty) BS.empty 16)
  case overrun of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed byteop extract overrun, got: " ++ show other)

-- TLS key-block vectors (master secret bytes 0..47, client
-- random 0..31, server random 32..63; oracle-cross-checked
-- PRF outputs, RFC 2246 §6.3 layout) plus typed refusals.
caseDriverKeyMat :: IO ()
caseDriverKeyMat = withBackend $ \env -> do
  let baseOid = ObjectId 86
      res oid
        | oid == baseOid = Just (KeyBytes (BS.pack [0 .. 47]))
        | otherwise = Nothing
      deriveAs mech params outLen =
        runEffect env res (FxDerive mech (Just baseOid) Nothing params BS.empty outLen)
          >>= expectBytes
      cr = BS.pack [0 .. 31]
      sr = BS.pack [32 .. 63]
      k10 = MechanismId 0x376
      k12 = MechanismId 0x3e1
      kSafe = MechanismId 0x3e3
      f10 = encodeTlsKeyMatParams 0 0 16 16 cr sr
      f10m = encodeTlsKeyMatParams 0 20 16 16 cr sr
      f12 = encodeTlsKeyMatParams 4 0 16 16 cr sr
      f12m = encodeTlsKeyMatParams 4 20 16 16 cr sr
      f12b = encodeTlsKeyMatParams 6 0 16 16 cr sr
  b64 <- deriveAs k10 f10 64
  assertEqual "tls10 key block" (hex "f3771f99cf91858748dc50ed540edc39efb06a256dcd4d9ffdf87298f72cf700f5585f14e9db80e3af1a7ccc2c218d42b36aa1a7584498f75edaca5bf8f86328") b64
  b104 <- deriveAs k10 f10m 104
  assertEqual "tls10 key block mac160" (hex "f3771f99cf91858748dc50ed540edc39efb06a256dcd4d9ffdf87298f72cf700f5585f14e9db80e3af1a7ccc2c218d42b36aa1a7584498f75edaca5bf8f86328bfd1fa7577fd88c0ffb682e2db691a4273d72711a70f82d180e78fbda5f5d14e01b717cf0173305e") b104
  b12 <- deriveAs k12 f12 64
  assertEqual "tls12-sha256 key block" (hex "fbe0dbb71e9097fcfe644317a16d334fac721a5f822730468a366a4ef2f2206848092b65ca8b00c356742cd5bae70ed8ac35e70945a53033866a9b3abca98806") b12
  b12m <- deriveAs k12 f12m 104
  assertEqual "tls12-sha256 key block mac160" (hex "fbe0dbb71e9097fcfe644317a16d334fac721a5f822730468a366a4ef2f2206848092b65ca8b00c356742cd5bae70ed8ac35e70945a53033866a9b3abca98806f6ba1048b7cd53eb2f2584955a68b87c9d198ce2c55c204f053dddc6f5ce4f96c242e8bb758cd5fa") b12m
  b12b <- deriveAs k12 f12b 64
  assertEqual "tls12-sha512 key block" (hex "5a6f3c22b22f1f29cbc4444ace696a20a4fa4fd868068e2e8cefd0c39b4b70948490ff3b47621ec6161df962702a7f620a95dc96dd49f8aee772047ff4dd305f") b12b
  bSafe <- deriveAs kSafe f12 32
  assertEqual "safe shares the tls12 prefix" (BS.take 32 b12) bSafe
  -- Typed refusals: junk params, a non-empty info string, and
  -- out-of-range lengths.
  junk <- runEffect env res (FxDerive k12 (Just baseOid) Nothing "junk" BS.empty 64)
  case junk of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed keymat junk, got: " ++ show other)
  withInfo <- runEffect env res (FxDerive k12 (Just baseOid) Nothing f12 "x" 64)
  case withInfo of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed keymat info, got: " ++ show other)
  zero <- runEffect env res (FxDerive k12 (Just baseOid) Nothing f12 BS.empty 0)
  case zero of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed keymat zero, got: " ++ show other)
  over <- runEffect env res (FxDerive k12 (Just baseOid) Nothing f12 BS.empty 65537)
  case over of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed keymat over-ceiling, got: " ++ show other)

-- SHA-1 vectors plus hashlib\/CLI cross-checked SHA-256\/512
-- vectors, multi-block output, truncation, SHA-KD rows, and typed
-- refusals.
caseDriverKdf :: IO ()
caseDriverKdf = withBackend $ \env -> do
  let pwOid = ObjectId 71
      pw2Oid = ObjectId 73
      res oid
        | oid == pwOid = Just (KeyBytes "password")
        | oid == pw2Oid = Just (KeyBytes "passwordPASSWORDpassword")
        | otherwise = Nothing
      derive mech params outLen =
        runEffect env res (FxDerive mech (Just pwOid) Nothing params BS.empty outLen)
          >>= expectBytes
      deriveAs oid mech params outLen =
        runEffect env res (FxDerive mech (Just oid) Nothing params BS.empty outLen)
          >>= expectBytes
      -- Engine-local PRF codes (recipe documents the table).
      prfSha1 = 2
      prfSha256 = 4
      prfSha512 = 6
  -- RFC 6070 PBKDF2-HMAC-SHA1 (also hashlib cross-checked).
  d1 <- derive pbkd2Mech (encodePbkd2Params prfSha1 1 "salt" "") 20
  assertEqual "rfc6070 c1" (hex "0c60c80f961f0e71f3a9b524af6012062fe037a6") d1
  d2 <- derive pbkd2Mech (encodePbkd2Params prfSha1 2 "salt" "") 20
  assertEqual "rfc6070 c2" (hex "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957") d2
  d3 <- derive pbkd2Mech (encodePbkd2Params prfSha1 4096 "salt" "") 20
  assertEqual "rfc6070 c4096" (hex "4b007901b765489abead49d926f721d065a429c1") d3
  -- SHA-256 (hashlib + pinned CLI).
  full32 <- derive pbkd2Mech (encodePbkd2Params prfSha256 1 "salt" "") 32
  assertEqual "sha256 c1"
    (hex "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b") full32
  s2 <- derive pbkd2Mech (encodePbkd2Params prfSha256 4096 "salt" "") 32
  assertEqual "sha256 c4096"
    (hex "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a") s2
  -- Multi-block output (dkLen 48 > hLen 32; long password/salt).
  m48 <- deriveAs pw2Oid pbkd2Mech
    (encodePbkd2Params prfSha256 2 "saltSALTsaltSALTsaltSALT" "") 48
  assertEqual "sha256 multi-block"
    (hex "75e097216ced1e94c12662c52666a1420f6958a1f882144451770fd697eaca751d932d69a5b45cccaed0c84d91f219c9") m48
  -- SHA-512 (pinned CLI).
  h1 <- derive pbkd2Mech (encodePbkd2Params prfSha512 1 "salt" "") 64
  assertEqual "sha512 c1"
    (hex "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce") h1
  -- Truncation is the prefix.
  trunc16 <- derive pbkd2Mech (encodePbkd2Params prfSha256 1 "salt" "") 16
  assertEqual "truncation prefix" (BS.take 16 full32) trunc16
  -- SHA-KD rows: full-width derive equals digest("abc") and
  -- truncation takes the prefix (digests cross-checked against
  -- hashlib; this pins the routing plus the per-row widths).
  let abcOid = ObjectId 72
      resAbc oid
        | oid == abcOid = Just (KeyBytes "abc")
        | otherwise = Nothing
      deriveAbc mech outLen =
        runEffect env resAbc (FxDerive mech (Just abcOid) Nothing BS.empty BS.empty outLen)
          >>= expectBytes
  mapM_ (\(mech, label, width, dgst) -> do
    full <- deriveAbc mech width
    assertEqual ("digest " ++ label) (hex dgst) full
    short <- deriveAbc mech 8
    assertEqual ("trunc " ++ label) (BS.take 8 full) short
    over <- runEffect env resAbc (FxDerive mech (Just abcOid) Nothing BS.empty BS.empty (width + 1))
    case over of
      GotCryptoError (CryptoFailed _) -> pure ()
      other -> assertFailure ("expected Failed " ++ label ++ ", got: " ++ show other)
    ) shaKdMechs
  -- SHAKE XOF rows: the output length rides the request (hashlib
  -- cross-checked); truncation is the prefix; over-ceiling
  -- requests refuse typed.
  x128 <- deriveAbc (MechanismId 0x39b) 32
  assertEqual "shake128 abc/32"
    (hex "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8") x128
  x256 <- deriveAbc (MechanismId 0x39c) 64
  assertEqual "shake256 abc/64"
    (hex "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4") x256
  xshort <- deriveAbc (MechanismId 0x39b) 8
  assertEqual "shake trunc" (BS.take 8 x128) xshort
  xover <- runEffect env resAbc
    (FxDerive (MechanismId 0x39b) (Just abcOid) Nothing BS.empty BS.empty (maxXofTotal + 1))
  case xover of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed shake128, got: " ++ show other)
  -- Typed refusals.
  badPrf <- runEffect env res
    (FxDerive pbkd2Mech (Just pwOid) Nothing (encodePbkd2Params 99 1 "s" "") BS.empty 32)
  case badPrf of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badInfo <- runEffect env res
    (FxDerive pbkd2Mech (Just pwOid) Nothing (encodePbkd2Params prfSha256 1 "s" "") "x" 32)
  case badInfo of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badLen <- runEffect env res
    (FxDerive (MechanismId 0x393) (Just pwOid) Nothing BS.empty BS.empty 33)
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | PBKD2 keygen through the driver over real HMAC: the v2 frame
-- carries the password inline and the derived key lands framed
-- as lone material. RFC 6070 c=1 plus a malformed-frame refusal.
caseDriverPbkd2Gen :: IO ()
caseDriverPbkd2Gen = withBackend $ \env -> do
  let res _ = Nothing
      gen frame n =
        runEffect env res
          (FxGenerateKey pbkd2Mech frame (encodeGenArgs (GenPbkd2 n)))
  kg <- gen (encodePbkd2Params 2 1 "salt" "password") 20
  case kg of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Nothing) -> assertEqual "rfc6070 c1 gen"
        (hex "0c60c80f961f0e71f3a9b524af6012062fe037a6") mat
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  badFrame <- gen BS.empty 20
  case badFrame of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | PBE keygen through the driver over real SHA-1: the v1 frame
-- carries password\/salt\/iterations and the key\/IV pair lands
-- framed (parity-adjusted key, raw IV). Lane fixtures c=1024
-- plus malformed-frame and off-geometry refusals.
caseDriverPbe :: IO ()
caseDriverPbe = withBackend $ \env -> do
  let res _ = Nothing
      des3 = MechanismId 0x3a8
      des2 = MechanismId 0x3a9
      frame = encodePbeParams 1024 "TestPassword123!"
        (BS.pack [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe])
      gen mech f n =
        runEffect env res (FxGenerateKey mech f (encodeGenArgs (GenPbe n)))
  kg3 <- gen des3 frame 24
  case kg3 of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Just iv) -> do
        assertEqual "des3 key"
          (hex "73b93bb0f797b564f7d90216b37f0ee9e9bc8004021fd39d") mat
        assertEqual "des3 iv" (hex "f7eb3b1c7d9ce2a0") iv
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  kg2 <- gen des2 frame 16
  case kg2 of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Just iv) -> do
        assertEqual "des2 key" (hex "73b93bb0f797b564f7d90216b37f0ee9") mat
        assertEqual "des2 iv" (hex "f7eb3b1c7d9ce2a0") iv
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  kg5 <- gen (MechanismId 0x3a5) frame 16
  case kg5 of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Just iv) -> do
        assertEqual "cast128 key" (hex "72b93bb1f796b464f6d80317b27e0fe8") mat
        assertEqual "cast128 iv" (hex "f7eb3b1c7d9ce2a0") iv
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  kg6 <- gen (MechanismId 0x3a6) frame 16
  case kg6 of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Nothing) ->
        assertEqual "rc4-128 key" (hex "72b93bb1f796b464f6d80317b27e0fe8") mat
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  kg7 <- gen (MechanismId 0x3a7) frame 5
  case kg7 of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Nothing) ->
        assertEqual "rc4-40 key" (hex "72b93bb1f7") mat
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  kga <- gen (MechanismId 0x3aa) frame 16
  case kga of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Just iv) -> do
        assertEqual "rc2-128 key" (hex "72b93bb1f796b464f6d80317b27e0fe8") mat
        assertEqual "rc2-128 iv" (hex "f7eb3b1c7d9ce2a0") iv
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  kgb <- gen (MechanismId 0x3ab) frame 5
  case kgb of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Just iv) -> do
        assertEqual "rc2-40 key" (hex "72b93bb1f7") mat
        assertEqual "rc2-40 iv" (hex "f7eb3b1c7d9ce2a0") iv
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  kgd <- gen (MechanismId 0x3a1) frame 8
  case kgd of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Just iv) -> do
        assertEqual "md5-des key" (hex "fed54f04efa44a7a") mat
        assertEqual "md5-des iv" (hex "f3a2adee8fa98e67") iv
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  kgc <- gen (MechanismId 0x3a2) frame 5
  case kgc of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Just iv) -> do
        assertEqual "md5-cast key" (hex "ffd54e05ee") mat
        assertEqual "md5-cast iv" (hex "a44b7bf3a2adee8f") iv
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  kg3c <- gen (MechanismId 0x3a3) frame 10
  case kg3c of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Just iv) -> do
        assertEqual "md5-cast3 key" (hex "ffd54e05eea44b7bf3a2") mat
        assertEqual "md5-cast3 iv" (hex "adee8fa98e6769fb") iv
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  kgc128 <- gen (MechanismId 0x3a4) frame 16
  case kgc128 of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Just iv) -> do
        assertEqual "md5-cast128 key" (hex "ffd54e05eea44b7bf3a2adee8fa98e67") mat
        assertEqual "md5-cast128 iv" (hex "69fba8ad294fa220") iv
      other -> assertFailure ("gen misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)
  badFrame <- gen des3 BS.empty 24
  case badFrame of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badLen <- gen des3 frame 20
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | SSL3 MACs through the driver over real MD5\/SHA-1: full-width
-- RFC 6101 vectors (hashlib-checked), bit truncation as the tag
-- prefix, verify verdicts, and typed refusals.
caseDriverSsl3Mac :: IO ()
caseDriverSsl3Mac = withBackend $ \env -> do
  let md5 = MechanismId 0x380
      sha1 = MechanismId 0x381
      secOid = ObjectId 95
      res oid
        | oid == secOid = Just (KeyBytes (BS.pack [0 .. 15]))
        | otherwise = Nothing
      msg = "test handshake data"
      signAs mech params =
        runEffect env res (FxSign mech (Just secOid) params msg)
  mac16 <- signAs md5 (encodeMacGeneral 128)
  case mac16 of
    GotBytes bs -> assertEqual "md5 vector"
      (hex "f8adc4aa2994ad2296ec759d1a321b0b") bs
    other -> assertFailure ("expected tag bytes, got: " ++ show other)
  mac20 <- signAs sha1 (encodeMacGeneral 160)
  case mac20 of
    GotBytes bs -> assertEqual "sha1 vector"
      (hex "d50aeadef9ad7678028f4188d05989fc869e57ca") bs
    other -> assertFailure ("expected tag bytes, got: " ++ show other)
  mac8 <- signAs md5 (encodeMacGeneral 64)
  case (mac16, mac8) of
    (GotBytes full, GotBytes short) ->
      assertEqual "truncation is the prefix" (BS.take 8 full) short
    other -> assertFailure ("expected tag bytes, got: " ++ show other)
  vOk <- runEffect env res (FxVerify md5 (Just secOid) (encodeMacGeneral 128)
    msg (hex "f8adc4aa2994ad2296ec759d1a321b0b"))
  assertEqual "mac verifies" (GotValid True) vOk
  vBad <- runEffect env res (FxVerify md5 (Just secOid) (encodeMacGeneral 128)
    msg (hex "f8adc4aa2994ad2296ec759d1a321b0c"))
  assertEqual "tamper refuses" (GotValid False) vBad
  badBits <- signAs md5 (encodeMacGeneral 129)
  case badBits of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badWidth <- signAs sha1 (encodeMacGeneral 168)
  case badWidth of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

caseDriverX931 :: IO ()
caseDriverX931 = withBackend $ \env -> do
  gen <- generateKey env (GenRSA 2048 65537)
  (priv, pub) <- case gen of
    EngineOk (p, Just q) -> pure (p, q)
    other -> assertFailure ("keygen failed: " ++ show other)
  let raw = MechanismId 0xb
      sha1 = MechanismId 0xc
      pubOid = ObjectId 96
      privOid = ObjectId 97
      res oid
        | oid == pubOid = Just pub
        | oid == privOid = Just priv
        | otherwise = Nothing
      d32 = BS.pack [0 .. 31]
  s1 <- runEffect env res (FxSign raw (Just privOid) BS.empty d32)
    >>= expectBytes
  assertEqual "raw sig length" 256 (BS.length s1)
  vOk <- runEffect env res (FxVerify raw (Just pubOid) BS.empty d32 s1)
  assertEqual "raw verifies" (GotValid True) vOk
  vBad <- runEffect env res
    (FxVerify raw (Just pubOid) BS.empty d32 (BS.map complement s1))
  assertEqual "tamper refuses" (GotValid False) vBad
  badLen <- runEffect env res
    (FxSign raw (Just privOid) BS.empty (BS.replicate 28 0xAA))
  case badLen of
    GotCryptoError (CryptoUnsupported _ _) -> pure ()
    other -> assertFailure ("expected Unsupported, got: " ++ show other)
  badParams <- runEffect env res
    (FxSign raw (Just privOid) (BS.pack [0]) d32)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  s2 <- runEffect env res (FxSign sha1 (Just privOid) BS.empty "message")
    >>= expectBytes
  assertEqual "sha1 sig length" 256 (BS.length s2)
  v2 <- runEffect env res (FxVerify sha1 (Just pubOid) BS.empty "message" s2)
  assertEqual "sha1 verifies" (GotValid True) v2

caseDriverPoly1305 :: IO ()
caseDriverPoly1305 = withBackend $ \env -> do
  let poly = MechanismId 0x1228
      keyOid = ObjectId 98
      res oid
        | oid == keyOid = Just (KeyBytes (hex "60ae20bd9302aea34cafbc620011e17b7774e97764b9bb6e035ffb2b8b63be9f"))
        | otherwise = Nothing
      msg = "Poly1305 KAT message, second vector"
  t1 <- runEffect env res (FxSign poly (Just keyOid) BS.empty msg)
    >>= expectBytes
  assertEqual "poly vector" (hex "f70a350ed794a7e0660bba7638f5a6d2") t1
  vOk <- runEffect env res
    (FxVerify poly (Just keyOid) BS.empty msg (hex "f70a350ed794a7e0660bba7638f5a6d2"))
  assertEqual "poly verifies" (GotValid True) vOk
  vBad <- runEffect env res
    (FxVerify poly (Just keyOid) BS.empty msg (hex "f70a350ed794a7e0660bba7638f5a6d3"))
  assertEqual "tamper refuses" (GotValid False) vBad
  badParams <- runEffect env res
    (FxSign poly (Just keyOid) (BS.pack [0]) msg)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | TLS-PRF through the driver over real HMAC-MD5\/SHA-1 —
-- 48-byte (even) and 47-byte (odd, shared middle byte) secrets,
-- truncation, label\/seed separation, and typed refusals. The
-- expected outputs come from the pinned OpenSSL 4.0.2 CLI ('openssl
-- mac' per P_hash block; only concat\/XOR in the harness — the
-- provider's TLS1-PRF takes a digest and serves TLS 1.2 only, so it
-- cannot oracle the MD5\/SHA-1 split directly).
caseDriverTlsPrf :: IO ()
caseDriverTlsPrf = withBackend $ \env -> do
  let tlsPrf = MechanismId 0x378
      sec48 = BS.pack [0 .. 47]
      sec47 = BS.pack [0 .. 46]
      evenOid = ObjectId 74
      oddOid = ObjectId 75
      res oid
        | oid == evenOid = Just (KeyBytes sec48)
        | oid == oddOid = Just (KeyBytes sec47)
        | otherwise = Nothing
      deriveAs oid params outLen =
        runEffect env res (FxDerive tlsPrf (Just oid) Nothing params BS.empty outLen)
          >>= expectBytes
      params = encodeTlsPrfParams "test label" "0123456789abcdef"
  full48 <- deriveAs evenOid params 48
  assertEqual "tls-prf even secret"
    (hex "7b986b57ecc5575e7ac26a43f503a3b4b2d0721c16a9176f2f6d6ec426294904a121842a6d2c1c7a1cd00fc0f48ed8a8") full48
  odd48 <- deriveAs oddOid params 48
  assertEqual "tls-prf odd secret (shared middle byte)"
    (hex "8674e6753c2ce33ce4af90a9b081a1340061db03dd08408b848577684ec9d26916658f0baa24fa6f151d27942487002d") odd48
  trunc16 <- deriveAs evenOid params 16
  assertEqual "truncation prefix" (BS.take 16 full48) trunc16
  trunc20 <- deriveAs oddOid params 20
  assertEqual "odd truncation prefix" (BS.take 20 odd48) trunc20
  otherLab <- deriveAs evenOid (encodeTlsPrfParams "other label" "0123456789abcdef") 48
  assertBool "labels separated" (otherLab /= full48)
  otherSeed <- deriveAs evenOid (encodeTlsPrfParams "test label" "0123456789abcdee") 48
  assertBool "seeds separated" (otherSeed /= full48)
  -- Typed refusals.
  badParams <- runEffect env res
    (FxDerive tlsPrf (Just evenOid) Nothing "junk" BS.empty 48)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badInfo <- runEffect env res
    (FxDerive tlsPrf (Just evenOid) Nothing params "x" 48)
  case badInfo of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badLen <- runEffect env res
    (FxDerive tlsPrf (Just evenOid) Nothing params BS.empty 0)
  case badLen of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)

-- | HOTP through the driver over real HMAC-SHA1 — the
-- full RFC 4226 Appendix D vector set (counters 0-9, 6 digits) plus
-- Python-hmac-oracle 7\/8-digit pins, verify verdicts, message
-- variants, typed refusals, and the synthetic-only keygen pin.
caseDriverHotp :: IO ()
caseDriverHotp = withBackend $ \env -> do
  let hotpMech = MechanismId 0x291
      keyOid = ObjectId 81
      otherOid = ObjectId 82
      res oid
        | oid == keyOid = Just (KeyBytes "12345678901234567890")
        | oid == otherOid = Just (KeyBytes "12345678901234567891")
        | otherwise = Nothing
      code oid c d =
        runEffect env res (FxSign hotpMech (Just oid) (encodeHotpParams c d) BS.empty)
          >>= expectBytes
      -- RFC 4226 Appendix D (independently recomputed with Python hmac).
      rfc4226 =
        [ "755224", "287082", "359152", "969429", "338314"
        , "254676", "287922", "162583", "399871", "520489"
        ]
  mapM_ (\(c, want) -> do
    got <- code keyOid c 6
    assertEqual ("rfc4226 counter " ++ show c) want got
    ) (zip [0 .. 9] rfc4226)
  d7 <- code keyOid 0 7
  assertEqual "oracle 7-digit" "4755224" d7
  d8 <- code keyOid 9 8
  assertEqual "oracle 8-digit" "45520489" d8
  -- Counter boundaries execute (oracle KATs; the maxBound
  -- code keeps its leading zero).
  top <- code keyOid 0xffffffff 6
  assertEqual "counter 2^32-1" "117190" top
  top8 <- code keyOid 0xffffffff 8
  assertEqual "counter 2^32-1 8-digit" "57117190" top8
  maxC <- code keyOid 0xffffffffffffffff 6
  assertEqual "counter maxBound" "094451" maxC
  maxC8 <- code keyOid 0xffffffffffffffff 8
  assertEqual "counter maxBound 8-digit" "63094451" maxC8
  -- Verify verdicts.
  vGood <- runEffect env res
    (FxVerify hotpMech (Just keyOid) (encodeHotpParams 0 6) BS.empty "755224")
  assertEqual "verifies" (GotValid True) vGood
  vBad <- runEffect env res
    (FxVerify hotpMech (Just keyOid) (encodeHotpParams 0 6) BS.empty "755225")
  assertEqual "tamper rejects" (GotValid False) vBad
  vCounter <- runEffect env res
    (FxVerify hotpMech (Just keyOid) (encodeHotpParams 1 6) BS.empty "755224")
  assertEqual "wrong counter rejects" (GotValid False) vCounter
  vKey <- runEffect env res
    (FxVerify hotpMech (Just otherOid) (encodeHotpParams 0 6) BS.empty "755224")
  assertEqual "wrong key rejects" (GotValid False) vKey
  -- Typed refusals: HOTP signs the counter only, so any input
  -- refuses; bad digits and malformed params refuse too.
  badInput <- runEffect env res
    (FxSign hotpMech (Just keyOid) (encodeHotpParams 0 6) "x")
  case badInput of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badDigits <- runEffect env res
    (FxSign hotpMech (Just keyOid) (encodeHotpParams 0 9) BS.empty)
  case badDigits of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badParams <- runEffect env res
    (FxSign hotpMech (Just keyOid) "x" BS.empty)
  case badParams of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  -- Message variants agree on empty input and refuse input alike.
  mCode <- runEffect env res
    (FxMessageSign hotpMech (Just keyOid) (encodeHotpParams 0 6) BS.empty)
    >>= expectBytes
  assertEqual "message agrees" "755224" mCode
  mVer <- runEffect env res
    (FxMessageVerify hotpMech (Just keyOid) (encodeHotpParams 0 6) BS.empty "755224")
  assertEqual "message verifies" (GotValid True) mVer
  mBad <- runEffect env res
    (FxMessageSign hotpMech (Just keyOid) (encodeHotpParams 0 6) "x")
  case mBad of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  -- HOTP keygen is real via the native DRBG surface (
  -- AES_KEY_GEN precedent flipped): 20 fresh bytes land framed
  -- as lone material.
  kg <- runEffect env res
    (FxGenerateKey hotpKeyGenMech BS.empty (encodeGenArgs (GenBytes 20)))
  case kg of
    GotBytes bs -> case decodeKeyPair bs of
      Just (mat, Nothing) -> assertEqual "hotp key length" 20 (BS.length mat)
      other -> assertFailure ("hotp key misframed, got: " ++ show other)
    other -> assertFailure ("expected key bytes, got: " ++ show other)

caseDriverMessage :: IO ()
caseDriverMessage = withBackend $ \env -> do
  ct <- runEffect env resolver
      (FxMessageCipher DirEncrypt aesCbcMech (Just aesOid) aes256Iv BS.empty aes256Pt)
    >>= expectBytes
  assertEqual "message cipher KAT" aes256Ct ct
  aad <- runEffect env resolver
    (FxMessageCipher DirEncrypt aesCbcMech (Just aesOid) aes256Iv "aad" aes256Pt)
  case aad of
    GotCryptoError (CryptoUnsupported _ _) -> pure ()
    other -> assertFailure ("expected Unsupported, got: " ++ show other)
  tag <- runEffect env resolver
      (FxMessageSign hmacMech (Just hmacOid) BS.empty hmacMsg1)
    >>= expectBytes
  assertEqual "message hmac" hmacOut1 tag
  vGood <- runEffect env resolver
    (FxMessageVerify hmacMech (Just hmacOid) BS.empty hmacMsg1 tag)
  assertEqual "message verify" (GotValid True) vGood

caseDriverRecover :: IO ()
caseDriverRecover = withBackend $ \env -> do
  r1 <- runEffect env resolver
    (FxSignRecover hmacMech (Just hmacOid) BS.empty "x" 4)
  case r1 of
    GotCryptoError (CryptoUnsupported _ _) -> pure ()
    other -> assertFailure ("expected Unsupported, got: " ++ show other)
  r2 <- runEffect env resolver
    (FxVerifyRecover hmacMech (Just hmacOid) BS.empty "x" 4)
  case r2 of
    GotCryptoError (CryptoUnsupported _ _) -> pure ()
    other -> assertFailure ("expected Unsupported, got: " ++ show other)

caseEncodeResult :: IO ()
caseEncodeResult = do
  assertEqual "bytes" (O.EngineOkBytes "b")
    (encodeResult (GotBytes "b"))
  assertEqual "verdict" (O.EngineOkValid False)
    (encodeResult (GotValid False))
  case encodeResult (GotCryptoError (CryptoUnsupported "driver" "u")) of
    O.EngineFail (O.BackendUnsupported _ _) -> pure ()
    other -> assertFailure ("expected fail: " ++ show other)
  case encodeResult (GotCryptoError (CryptoBadKey "driver" "k")) of
    O.EngineFail (O.BackendBadKey _ _) -> pure ()
    other -> assertFailure ("expected fail: " ++ show other)
  case encodeResult (GotCryptoError (CryptoFailed "f")) of
    O.EngineFail (O.BackendNative _ _ _) -> pure ()
    other -> assertFailure ("expected fail: " ++ show other)

caseSignE2E :: IO ()
caseSignE2E = withBackend $ \env -> do
  (sid, m0) <- openModel
  let iReq = (mkRequest F_SignInit (Just sid))
        { reqHandle = Just hmacHandle
        , reqInput = encodeInitInput hmacMech [OpSign] False BS.empty
        }
  m1 <- runCommit m0 iReq
  let req = (mkRequest F_Sign (Just sid))
        { reqInput = hmacMsg1
        , reqRegions = [RegionBytes "tag" (IntentBuffer 64)]
        }
  (res, fx) <- case planCall defaultRules m1 req of
    Execute r (O.EffectCrypto e) -> pure (r, e)
    other -> assertFailure ("expected Execute, got: " ++ show other)
  crypto <- runEffect env resolver fx
  case finishEffect defaultRules m1 res (encodeResult crypto) of
    Left rej -> assertFailure ("finish rejected: " ++ show (rejCode rej))
    Right pc -> do
      out <- commitBytes pc
      assertEqual "RFC 4231 tag in commit" hmacOut1 out

caseVerifyE2E :: IO ()
caseVerifyE2E = withBackend $ \env -> do
  (sid, m0) <- openModel
  let iReq = (mkRequest F_VerifyInit (Just sid))
        { reqHandle = Just hmacHandle
        , reqInput = encodeInitInput hmacMech [OpVerify] False BS.empty
        }
  m1 <- runCommit m0 iReq
  let vReq tag = (mkRequest F_Verify (Just sid))
        { reqInput = encodeVerifyInput hmacMsg1 tag
        , reqRegions = [RegionBytes "verify" (IntentBuffer 0)]
        }
  (res, fx) <- case planCall defaultRules m1 (vReq hmacOut1) of
    Execute r (O.EffectCrypto e) -> pure (r, e)
    other -> assertFailure ("expected Execute, got: " ++ show other)
  crypto <- runEffect env resolver fx
  m1b <- case finishEffect defaultRules m1 res (encodeResult crypto) of
    Left rej -> assertFailure ("finish rejected: " ++ show (rejCode rej))
    Right pc -> do
      assertEqual "valid commits OK" CKR_OK (pcCode pc)
      case publishDelta m1 (pcDelta pc) of
        Left fault -> assertFailure ("commit fault: " ++ show fault)
        Right m' -> pure m'
  m2 <- runCommit m1b iReq
  (res2, fx2) <- case planCall defaultRules m2 (vReq (BS.map (255 -) hmacOut1)) of
    Execute r (O.EffectCrypto e) -> pure (r, e)
    other -> assertFailure ("expected Execute, got: " ++ show other)
  crypto2 <- runEffect env resolver fx2
  case finishEffect defaultRules m2 res2 (encodeResult crypto2) of
    Left rej -> assertFailure ("finish rejected: " ++ show (rejCode rej))
    Right pc -> assertEqual "mismatch commits INVALID" CKR_SIGNATURE_INVALID (pcCode pc)
