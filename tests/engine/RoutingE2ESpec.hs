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

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
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
import Haskoki.Recipe.Ecdh (encodeEcdhParams)
import Haskoki.Recipe.Hmac (encodeMacGeneral)
import Haskoki.Recipe.Kdf (encodePbkd2Params)
import Haskoki.Recipe.Otp (encodeHotpParams)
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
  , testCase "driver: ecdsa roundtrip both encodings" caseDriverEcdsa
  , testCase "driver: ecdh agree + truncate + refuse" caseDriverEcdh
  , testCase "driver: cmac KATs + truncate + refuse" caseDriverCmac
  , testCase "driver: kdf vectors + refuse" caseDriverKdf
  , testCase "driver: hotp vectors + refuse" caseDriverHotp
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

sha256Mech, hmacMech, aesCbcMech, ecdsaMech :: MechanismId
sha256Mech = MechanismId 0x250
hmacMech = MechanismId 0x251
aesCbcMech = MechanismId 0x1082
ecdsaMech = MechanismId 0x1041

ecdhMech, ecdhCofMech :: MechanismId
ecdhMech = MechanismId 0x1050
ecdhCofMech = MechanismId 0x1051

cmacMech, cmacGenMech, cmac3Mech, cmac3GenMech :: MechanismId
cmacMech = MechanismId 0x108a
cmacGenMech = MechanismId 0x108b
cmac3Mech = MechanismId 0x138
cmac3GenMech = MechanismId 0x137

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
  ]

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

hmacOid, aesOid :: ObjectId
hmacOid = ObjectId 21
aesOid = ObjectId 22

hmacHandle, aesHandle :: ExternalHandle
hmacHandle = ExternalHandle 201
aesHandle = ExternalHandle 202

resolver :: KeyResolver
resolver oid
  | oid == hmacOid = Just (KeyBytes hmacKey1)
  | oid == aesOid = Just (KeyBytes aes256Key)
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
  { mObjects = Map.fromList [(hmacOid, mkObject hmacOid), (aesOid, mkObject aesOid)]
  , mHandles = Map.fromList
      [ (hmacHandle, HandleBinding hmacOid (Generation 1))
      , (aesHandle, HandleBinding aesOid (Generation 1))
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
  -- hash-and-sign (here SHA-256 over a long message raw could never
  -- take).
  let sha256MechDig = MechanismId 0x1044
      long = BS.replicate 100 0x61
  sigH <- runEffect env res (FxSign sha256MechDig (Just privOid) "DER" long)
    >>= expectBytes
  vH <- runEffect env res (FxVerify sha256MechDig (Just pubOid) "DER" long sigH)
  assertEqual "digested verifies" (GotValid True) vH
  tooLong <- runEffect env res (FxSign ecdsaMech (Just privOid) "DER" long)
  case tooLong of
    -- The native BadParam arrives with its category intact
    -- (same CKR_GENERAL_ERROR as the old collapse).
    GotCryptoError (CryptoBadParam _ _) -> pure ()
    other -> assertFailure ("expected BadParam, got: " ++ show other)

-- | ECDH through the driver — full-width agreement equals
-- the direct backend call, truncation takes the prefix, the reverse
-- direction commutes, cofactor agrees (h=1), over-length/KDF/info
-- faults refuse typed.
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
  full <- runEffect env res (FxDerive ecdhMech (Just aOid) (blob peerB) BS.empty 32)
    >>= expectBytes
  assertEqual "driver == direct" direct full
  short <- runEffect env res (FxDerive ecdhMech (Just aOid) (blob peerB) BS.empty 16)
    >>= expectBytes
  assertEqual "truncation is the prefix" (BS.take 16 direct) short
  rev <- runEffect env res (FxDerive ecdhMech (Just bOid) (blob peerA) BS.empty 32)
    >>= expectBytes
  assertEqual "commutes" direct rev
  cof <- runEffect env res (FxDerive ecdhCofMech (Just aOid) (blob peerB) BS.empty 32)
    >>= expectBytes
  assertEqual "cofactor agrees" direct cof
  over <- runEffect env res (FxDerive ecdhMech (Just aOid) (blob peerB) BS.empty 33)
  case over of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  kdf <- runEffect env res
    (FxDerive ecdhMech (Just aOid) (encodeEcdhParams 1 BS.empty peerB) BS.empty 32)
  case kdf of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  inf <- runEffect env res (FxDerive ecdhMech (Just aOid) (blob peerB) "info" 32)
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

-- | PBKDF2 through the driver over real HMAC — RFC 6070
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
        runEffect env res (FxDerive mech (Just pwOid) params BS.empty outLen)
          >>= expectBytes
      deriveAs oid mech params outLen =
        runEffect env res (FxDerive mech (Just oid) params BS.empty outLen)
          >>= expectBytes
      -- Engine-local PRF codes (recipe documents the table).
      prfSha1 = 2
      prfSha256 = 4
      prfSha512 = 6
  -- RFC 6070 PBKDF2-HMAC-SHA1 (also hashlib cross-checked).
  d1 <- derive pbkd2Mech (encodePbkd2Params prfSha1 1 "salt") 20
  assertEqual "rfc6070 c1" (hex "0c60c80f961f0e71f3a9b524af6012062fe037a6") d1
  d2 <- derive pbkd2Mech (encodePbkd2Params prfSha1 2 "salt") 20
  assertEqual "rfc6070 c2" (hex "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957") d2
  d3 <- derive pbkd2Mech (encodePbkd2Params prfSha1 4096 "salt") 20
  assertEqual "rfc6070 c4096" (hex "4b007901b765489abead49d926f721d065a429c1") d3
  -- SHA-256 (hashlib + pinned CLI).
  full32 <- derive pbkd2Mech (encodePbkd2Params prfSha256 1 "salt") 32
  assertEqual "sha256 c1"
    (hex "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b") full32
  s2 <- derive pbkd2Mech (encodePbkd2Params prfSha256 4096 "salt") 32
  assertEqual "sha256 c4096"
    (hex "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a") s2
  -- Multi-block output (dkLen 48 > hLen 32; long password/salt).
  m48 <- deriveAs pw2Oid pbkd2Mech
    (encodePbkd2Params prfSha256 2 "saltSALTsaltSALTsaltSALT") 48
  assertEqual "sha256 multi-block"
    (hex "75e097216ced1e94c12662c52666a1420f6958a1f882144451770fd697eaca751d932d69a5b45cccaed0c84d91f219c9") m48
  -- SHA-512 (pinned CLI).
  h1 <- derive pbkd2Mech (encodePbkd2Params prfSha512 1 "salt") 64
  assertEqual "sha512 c1"
    (hex "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce") h1
  -- Truncation is the prefix.
  trunc16 <- derive pbkd2Mech (encodePbkd2Params prfSha256 1 "salt") 16
  assertEqual "truncation prefix" (BS.take 16 full32) trunc16
  -- SHA-KD rows: full-width derive equals digest("abc") and
  -- truncation takes the prefix (digests cross-checked against
  -- hashlib; this pins the routing plus the per-row widths).
  let abcOid = ObjectId 72
      resAbc oid
        | oid == abcOid = Just (KeyBytes "abc")
        | otherwise = Nothing
      deriveAbc mech outLen =
        runEffect env resAbc (FxDerive mech (Just abcOid) BS.empty BS.empty outLen)
          >>= expectBytes
  mapM_ (\(mech, label, width, dgst) -> do
    full <- deriveAbc mech width
    assertEqual ("digest " ++ label) (hex dgst) full
    short <- deriveAbc mech 8
    assertEqual ("trunc " ++ label) (BS.take 8 full) short
    over <- runEffect env resAbc (FxDerive mech (Just abcOid) BS.empty BS.empty (width + 1))
    case over of
      GotCryptoError (CryptoFailed _) -> pure ()
      other -> assertFailure ("expected Failed " ++ label ++ ", got: " ++ show other)
    ) shaKdMechs
  -- Typed refusals.
  badPrf <- runEffect env res
    (FxDerive pbkd2Mech (Just pwOid) (encodePbkd2Params 99 1 "s") BS.empty 32)
  case badPrf of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badInfo <- runEffect env res
    (FxDerive pbkd2Mech (Just pwOid) (encodePbkd2Params prfSha256 1 "s") "x" 32)
  case badInfo of
    GotCryptoError (CryptoFailed _) -> pure ()
    other -> assertFailure ("expected Failed, got: " ++ show other)
  badLen <- runEffect env res
    (FxDerive (MechanismId 0x393) (Just pwOid) BS.empty BS.empty 33)
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
