{- | Operation lifecycle tests.

A source-legal digest/encrypt pair is permitted
but a conflicting same-kind init is rejected; init policy (source
routes, engine capabilities, key shape, handle resolution,
visibility, usage permission, auth marking); the context-auth gate
(consumed only at the first data call); and digest one-shot / update
/ final sequencing with per-result dispositions.
-}
{-# LANGUAGE OverloadedStrings #-}
module OperationSpec (spec) where

import Data.Bits ((.&.), complement, shiftR)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
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
  , DataGate (..)
  , DigestStream (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpAuth (..)
  , OpEnv (..)
  , RecoverSpec (..)
  , SessionOps
  , SlotCommon
  , SlotKind (..)
  , StepDeny (..)
  , StepOutcome (..)
  , activeCipher
  , activeDigest
  , activeSlots
  , bufferedLength
  , bufferedOf
  , chainIvOf
  , commonAuth
  , commonOf
  , emptySessionOps
  , gateDataCall
  , hasDual
  , hasStreamed
  , initDualOperation
  , initOperation
  , insertOp
  , lookupSingle
  , mkActiveDigest
  , mkSlotCommon
  , retryStaged
  , setCommonAuth
  , setLive
  , streamOf
  , slotAuth
  )
import Haskoki.Operation.Cipher
  ( cipherUpdateSplit
  , finishCipher
  , finishCipherUpdate
  , pkcs7Pad
  , pkcs7Unpad
  , planCipherFinal
  , planCipherOneShot
  , planCipherUpdate
  )
import Haskoki.Operation.Dual
  ( dualAuth
  , dualBuffered
  , finishDual
  , planDualFinal
  , planDualUpdate
  , retryDualFinal
  )
import Haskoki.Operation.Digest
  ( finishDigest
  , planDigestFinal
  , planDigestOneShot
  , planDigestUpdate
  )
import Haskoki.Operation.Signature
  ( finishSign
  , finishSignRecover
  , finishVerify
  , finishVerifyRecover
  , planSignFinal
  , planSignOneShot
  , planSignRecoverOneShot
  , planSignUpdate
  , planVerifyFinal
  , planVerifyOneShot
  , planVerifyRecoverOneShot
  , planVerifyUpdate
  )
import Haskoki.Outcome (ResourceRelease (..))
import Haskoki.Output (OutputPlan (..), TypedWrite (..), WritePayload (..))
import Haskoki.Recipe.Ccm (encodeCcmParams)
import Haskoki.Recipe.Eddsa (encodeEddsaParams)
import Haskoki.Recipe.Hmac (encodeMacGeneral)
import Haskoki.Recipe.MlDsa (MldsaHedge (..), encodeMldsaParams)
import Haskoki.Registry
  ( Descriptor (..)
  , Family (..)
  , KeySizeUnit (..)
  , MechanismId (..)
  , Operation (..)
  , ParameterCodec (..)
  , Registry
  , RoutePolicy (..)
  , SourceRef (..)
  , curatedRegistry
  , mkCapabilities
  , registerDescriptor
  )
import Haskoki.Request (OutputIntent (..))
import Haskoki.Session (SessionLogin (..))
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

spec :: TestTree
spec = testGroup "operation lifecycles"
  [ testCase "gcm encrypt init admits canonical params" caseGcmInit
  , testCase "ccm encrypt init admits canonical params" caseCcmInit
  , testCase "digest/encrypt pair permitted, same-kind rejected" casePairVsConflict
  , testCase "init checks source routes before engine caps" caseInitLegality
  , testCase "init enforces key shape and usage" caseInitKeyPolicy
  , testCase "context gate consumes only at the first data call" caseGate
  , testCase "digest multipart: update, update, final" caseDigestMultipart
  , testCase "Digest updates stream without buffering" caseDigestStreamsNoBuffer
  , testCase "Digest final consumes the stream" caseDigestFinalConsumes
  , testCase "digest one-shot after update is rejected" caseOneShotAfterUpdate
  , testCase "digest final short buffer keeps the slot" caseDigestShortRetry
  , testCase "digest failure terminates the slot" caseDigestFailureTerminates
  , testCase "premature grant use fails and consumes nothing" casePremature
  , testCase "pkcs7 pad and unpad vectors" casePkcs7
  , testCase "encrypt multipart equals one-shot" caseCipherMultipart
  , testCase "update split table" caseUpdateSplitTable
  , testCase "update short buffer refuses without consuming" caseUpdateShortNoConsume
  , testCase "streamed-but-drained slot still blocks one-shot" caseStreamedDrainedMarker
  , testCase "decrypt update advances the chaining value" caseDecryptChainsRunningIv
  , testCase "ecb decrypt streams without a chaining value" caseEcbDecryptNoChain
  , testCase "encrypt update chains the next chunk from the answer" caseEncryptChainsFromAnswer
  , testCase "encrypt/decrypt roundtrip with padding" caseCipherRoundtrip
  , testCase "unpadded length denies terminate the slot" caseCipherLengths
  , testCase "cts stealing floor and buffer-all" caseCtsFloor
  , testCase "aes stream rows accept any length" caseAesStreamFloor
  , testCase "decrypt bad padding fails terminally" caseCipherBadPad
  , testCase "cipher short buffer retry then failure" caseCipherShortFail
  , testCase "empty-output query stages for the recall" caseEmptyQueryStages
  , testCase "always-auth encrypt consumes at first update" caseAuthConsumeUpdate
  , testCase "grantless first update terminates the slot" caseAuthLateFails
  , testCase "oversized padded block rejected at init" caseCipherBlockRange
  , testCase "sign multipart and verify roundtrip" caseSignRoundtrip
  , testCase "Guard: sign updates stay buffered" caseSignStaysBuffered
  , testCase "Guard: verify updates stay buffered" caseVerifyStaysBuffered
  , testCase "verify mismatch frees with SIGNATURE_INVALID" caseVerifyMismatch
  , testCase "verify empty signature fails without effect" caseVerifyEmpty
  , testCase "verify one-shot after update terminates" caseVerifyOneShotAfterUpdate
  , testCase "sign one-shot after update rejected" caseSignOneShotAfterUpdate
  , testCase "sign short buffer retry; failure terminates" caseSignShortFail
  , testCase "raw DSA digest floor refuses short input" caseRawDsaFloor
  , testCase "EdDSA init requires explicit pure, refuses rest" caseEddsaParams
  , testCase "SSL3 MAC init takes whole-byte bit lengths" caseSsl3MacParams
  , testCase "ML-DSA init admits empty, refuses bad hedge/overlong" caseMldsaParams
  , testCase "recover roundtrip" caseRecoverRoundtrip
  , testCase "recover oversize data fails terminally" caseRecoverOversize
  , testCase "recover tampered block fails" caseRecoverTampered
  , testCase "recovery slots reject multipart" caseRecoverNoMultipart
  , testCase "dual init conflicts with singles and itself" caseDualConflicts
  , testCase "dual update matches separate updates" caseDualUpdate
  , testCase "dual final equals non-combined outputs" caseDualFinal
  , testCase "dual decrypt padded tail matches standalone" caseDualDecryptTail
  , testCase "dual short-output retry replays pending only" caseDualShortRetry
  , testCase "dual failure terminates" caseDualFailure
  , testCase "dual consumes the grant at first update" caseDualAuth
  ]

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

hmacMech :: MechanismId
hmacMech = MechanismId 0x251

aesCbcMech :: MechanismId
aesCbcMech = MechanismId 0x1082

aesEcbMech :: MechanismId
aesEcbMech = MechanismId 0x1081

aesGcmMech :: MechanismId
aesGcmMech = MechanismId 0x1087

aesCcmMech :: MechanismId
aesCcmMech = MechanismId 0x1088

aesCtsMech :: MechanismId
aesCtsMech = MechanismId 0x1089

aesXtsMech :: MechanismId
aesXtsMech = MechanismId 0x1071

aesCfb128Mech, aesCfb8Mech, aesCfb1Mech, aesOfbMech :: MechanismId
aesCfb128Mech = MechanismId 0x2107
aesCfb8Mech = MechanismId 0x2106
aesCfb1Mech = MechanismId 0x2108
aesOfbMech = MechanismId 0x2104

rsaGenMech :: MechanismId
rsaGenMech = MechanismId 0x0

dsaMech :: MechanismId
dsaMech = MechanismId 0x11

dsaSha256Mech :: MechanismId
dsaSha256Mech = MechanismId 0x14

eddsaMech :: MechanismId
eddsaMech = MechanismId 0x1057

ssl3Md5Mech :: MechanismId
ssl3Md5Mech = MechanismId 0x380

ssl3Sha1Mech :: MechanismId
ssl3Sha1Mech = MechanismId 0x381

mldsaMech :: MechanismId
mldsaMech = MechanismId 0x1D

unknownMech :: MechanismId
unknownMech = MechanismId 0x9999

-- | Test-local recover-capable mechanism. The family tag is
-- descriptive only (init keys off operation routes, never family).
recMech :: MechanismId
recMech = MechanismId 0x4711

recRegistry :: Registry
recRegistry = case registerDescriptor curatedRegistry recDesc of
  Right r -> r
  Left err -> error ("recRegistry: " ++ show err)
  where
    recDesc = Descriptor
      { descId = recMech
      , descCanonical = "CKM_TEST_RECOVER"
      , descAliases = []
      , descBaseline = [Pkcs11_2_40]
      , descFamily = FamilyMac
      , descCodec = Just (ParameterCodec "no-params" 1)
      , descRoutes =
          [ RoutePolicy OpSignRecover [SourceRef "S-TEST" "recover"] ["CLASSIC"]
          , RoutePolicy OpVerifyRecover [SourceRef "S-TEST" "recover"] ["CLASSIC"]
          ]
      , descKeyUnit = KeyBytes
      , descMinKey = 32
      , descMaxKey = 64
      }

recEnv :: OpEnv
recEnv = testEnv
  { oeRegistry = recRegistry
  , oeCaps = mkCapabilities [(recMech, OpSignRecover), (recMech, OpVerifyRecover)]
  }

testSlot :: SlotId
testSlot = SlotId 7

testSession :: SessionState
testSession = SessionState
  { ssId = SessionId 1
  , ssSlot = testSlot
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

-- | Model holding one public AES key object bound to handle 3.
modelWithKey :: Model
modelWithKey =
  let ost = ObjectState
        { osId = ObjectId 9
        , osRevision = Revision 1
        , osGeneration = Generation 1
        , osAttrs = Map.fromList
            [ (AttrClass, ValULong 4)
            , (AttrPrivate, ValBool False)
            ]
        , osOwner = Nothing
        , osSlot = testSlot
        }
  in emptyModel
    { mObjects = Map.singleton (ObjectId 9) ost
    , mHandles = Map.singleton (ExternalHandle 3)
        (HandleBinding (ObjectId 9) (Generation 1))
    }

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities
      [ (sha256Mech, OpDigest)
      , (aesCbcMech, OpEncrypt)
      , (aesCbcMech, OpDecrypt)
      ]
  , oeModel = modelWithKey
  }

digestArgs :: InitArgs
digestArgs = InitArgs
  { iaOp = OpDigest
  , iaMech = sha256Mech
  , iaParams = BS.empty
  , iaKey = Nothing
  , iaCipher = Nothing
  , iaRecover = Nothing
  }

aesKey :: KeyPolicy
aesKey = KeyPolicy
  { kpHandle = ExternalHandle 3
  , kpPermits = [OpEncrypt, OpDecrypt]
  , kpAlwaysAuth = False
  }

encryptArgs :: InitArgs
encryptArgs = InitArgs
  { iaOp = OpEncrypt
  , iaMech = aesCbcMech
  , iaParams = BS.replicate 16 0
  , iaKey = Just aesKey
  , iaCipher = Just (CipherSpec 16 True)
  , iaRecover = Nothing
  }

gcmArgs :: InitArgs
gcmArgs = InitArgs
  { iaOp = OpEncrypt
  , iaMech = aesGcmMech
  , iaParams = u64be 16 <> u64be 12 <> "0123456789ab" <> "AD"
  , iaKey = Just aesKey
  , iaCipher = Just (CipherSpec 1 False)
  , iaRecover = Nothing
  }
  where
    u64be :: Int -> ByteString
    u64be n = BS.pack [fromIntegral (n `shiftR` s) .&. 0xff | s <- [56, 48 .. 0]]

-- | Fake stream resource for planner-level tests, which bypass the
-- init-alloc finish that records the real one.
streamRid :: EngineResourceId
streamRid = EngineResourceId 7

-- | Install a fake live (unfed) stream on the digest slot.
withDigestStream :: SessionOps -> SessionOps
withDigestStream ops = case lookupSingle ops SlotDigest of
  Just active -> case activeDigest active of
    Just sc -> insertOp
      (mkActiveDigest (setLive (DigestStream streamRid False) sc)) ops
    Nothing -> ops
  _ -> ops

-- | Toy digest executor: length-prefixed byte reversal. Sequencing is
-- what is under test, not the hash.
toyDigest :: ByteString -> ByteString
toyDigest bs = BS.pack [fromIntegral (BS.length bs)] <> BS.reverse bs

runDigestEffect :: CryptoEffect -> CryptoResult
runDigestEffect (FxDigest _ input) = GotBytes (toyDigest input)
runDigestEffect fx = GotCryptoError (CryptoFailed ("unexpected effect: " ++ show fx))

caseGcmInit :: IO ()
caseGcmInit = do
  let env = testEnv { oeCaps = mkCapabilities [(aesGcmMech, OpEncrypt)] }
      (ops1, out1) = initOperation env emptySessionOps testSession gcmArgs
  assertEqual "gcm init code" CKR_OK (ioCode out1)
  assertEqual "one active slot" [SlotEncrypt] (activeSlots ops1)
  let badArgs = gcmArgs { iaParams = "nope" }
      (_, outBad) = initOperation env emptySessionOps testSession badArgs
  assertEqual "gcm bad params code" CKR_ARGUMENTS_BAD (ioCode outBad)

ccmArgs :: InitArgs
ccmArgs = InitArgs
  { iaOp = OpEncrypt
  , iaMech = aesCcmMech
  , iaParams = encodeCcmParams "0123456789ab" "AD" 8 16
  , iaKey = Just aesKey
  , iaCipher = Just (CipherSpec 1 False)
  , iaRecover = Nothing
  }

caseCcmInit :: IO ()
caseCcmInit = do
  let env = testEnv { oeCaps = mkCapabilities [(aesCcmMech, OpEncrypt)] }
      (ops1, out1) = initOperation env emptySessionOps testSession ccmArgs
  assertEqual "ccm init code" CKR_OK (ioCode out1)
  assertEqual "one active slot" [SlotEncrypt] (activeSlots ops1)
  let badNonce = ccmArgs
        { iaParams = encodeCcmParams "0123456789abcdef" "AD" 8 16 }
      (_, outNonce) = initOperation env emptySessionOps testSession badNonce
  assertEqual "ccm bad nonce code"
    CKR_MECHANISM_PARAM_INVALID (ioCode outNonce)
  let badTag = ccmArgs { iaParams = encodeCcmParams "0123456789ab" "AD" 2 16 }
      (_, outTag) = initOperation env emptySessionOps testSession badTag
  assertEqual "ccm bad tag code"
    CKR_MECHANISM_PARAM_INVALID (ioCode outTag)

-- ---------------------------------------------------------------------------
-- Acceptance 1: pair permitted, same-kind conflict rejected
-- ---------------------------------------------------------------------------

casePairVsConflict :: IO ()
casePairVsConflict = do
  let (ops1, out1) = initOperation testEnv emptySessionOps testSession digestArgs
  assertEqual "digest init code" CKR_OK (ioCode out1)
  assertEqual "one active slot" [SlotDigest] (activeSlots ops1)
  -- A conflicting same-kind init is rejected; the first slot survives.
  let (ops2, out2) = initOperation testEnv ops1 testSession digestArgs
  assertEqual "second digest init conflicts" CKR_OPERATION_ACTIVE (ioCode out2)
  assertEqual "conflict keeps the first slot" [SlotDigest] (activeSlots ops2)
  -- A source-legal digest/encrypt pair coexists in one session.
  let (ops3, out3) = initOperation testEnv ops2 testSession encryptArgs
  assertEqual "encrypt init code" CKR_OK (ioCode out3)
  assertEqual "pair coexists" [SlotDigest, SlotEncrypt] (activeSlots ops3)
  -- And the encrypt side conflicts with itself too.
  let (ops4, out4) = initOperation testEnv ops3 testSession encryptArgs
  assertEqual "second encrypt conflicts" CKR_OPERATION_ACTIVE (ioCode out4)
  assertEqual "pair survives" [SlotDigest, SlotEncrypt] (activeSlots ops4)

-- ---------------------------------------------------------------------------
-- Init legality: source routes, engine capabilities, operation set
-- ---------------------------------------------------------------------------

caseInitLegality :: IO ()
caseInitLegality = do
  let badMech = digestArgs { iaMech = unknownMech }
      (_, o1) = initOperation testEnv emptySessionOps testSession badMech
  assertEqual "unknown mechanism" CKR_MECHANISM_INVALID (ioCode o1)
  let catalogOnly = digestArgs { iaMech = rsaGenMech, iaOp = OpGenerateKeyPair }
      (_, o2) = initOperation testEnv emptySessionOps testSession catalogOnly
  assertEqual "catalog-only row never executes" CKR_MECHANISM_INVALID (ioCode o2)
  -- HMAC/Sign is source-backed in the curated registry, but this
  -- engine reports no HMAC capability: no silent fallback.
  let noCaps = InitArgs OpSign hmacMech BS.empty
        (Just aesKey { kpPermits = [OpSign] }) Nothing Nothing
      (_, o3) = initOperation testEnv emptySessionOps testSession noCaps
  assertEqual "engine capability miss" CKR_MECHANISM_INVALID (ioCode o3)
  -- Wrap is outside the classic set entirely.
  let nonClassic = encryptArgs { iaOp = OpWrap }
      (_, o4) = initOperation testEnv emptySessionOps testSession nonClassic
  assertEqual "non-classic op rejected" CKR_MECHANISM_INVALID (ioCode o4)
  assertEqual "nothing activated" [] (activeSlots emptySessionOps)

-- ---------------------------------------------------------------------------
-- Init key policy: shape, handles, visibility, permission, auth marking
-- ---------------------------------------------------------------------------

caseInitKeyPolicy :: IO ()
caseInitKeyPolicy = do
  -- Keyed op without a key.
  let (_, k1) = initOperation testEnv emptySessionOps testSession
        (encryptArgs { iaKey = Nothing })
  assertEqual "key required" CKR_ARGUMENTS_BAD (ioCode k1)
  -- Unkeyed op with a key.
  let (_, k2) = initOperation testEnv emptySessionOps testSession
        (digestArgs { iaKey = Just aesKey })
  assertEqual "digest takes no key" CKR_ARGUMENTS_BAD (ioCode k2)
  -- Cipher op without a cipher spec.
  let (_, k3) = initOperation testEnv emptySessionOps testSession
        (encryptArgs { iaCipher = Nothing })
  assertEqual "cipher spec required" CKR_ARGUMENTS_BAD (ioCode k3)
  -- HMAC carries no SignRecover route: route miss, not a shape error.
  let noRoute = InitArgs OpSignRecover hmacMech BS.empty
        (Just aesKey { kpPermits = [OpSignRecover] }) Nothing Nothing
      (_, k4) = initOperation testEnv emptySessionOps testSession noRoute
  assertEqual "recover route miss" CKR_MECHANISM_INVALID (ioCode k4)
  -- A recover-capable (test-local) mechanism without a recover spec.
  let recNoSpec = InitArgs OpSignRecover recMech BS.empty
        (Just aesKey { kpPermits = [OpSignRecover] }) Nothing Nothing
      (_, k4b) = initOperation recEnv emptySessionOps testSession recNoSpec
  assertEqual "recover spec required" CKR_ARGUMENTS_BAD (ioCode k4b)
  -- ... and the recover init with a spec.
  let recOk = recNoSpec { iaRecover = Just (RecoverSpec 64 32) }
      (ops4c, k4c) = initOperation recEnv emptySessionOps testSession recOk
  assertEqual "recover init ok" CKR_OK (ioCode k4c)
  assertEqual "recover takes the sign slot" [SlotSign] (activeSlots ops4c)
  -- Unknown handle.
  let badHandle = encryptArgs
        { iaKey = Just aesKey { kpHandle = ExternalHandle 99 } }
      (_, k5) = initOperation testEnv emptySessionOps testSession badHandle
  assertEqual "bad handle" CKR_OBJECT_HANDLE_INVALID (ioCode k5)
  -- Key does not permit the requested op.
  let wrongPermits = encryptArgs
        { iaKey = Just aesKey { kpPermits = [OpDecrypt] } }
      (_, k6) = initOperation testEnv emptySessionOps testSession wrongPermits
  assertEqual "usage refused" CKR_KEY_FUNCTION_NOT_PERMITTED (ioCode k6)
  -- Private key invisible to a public session reads as an invalid handle.
  let privModel = modelWithKey
        { mObjects = Map.adjust
            (\ost -> ost { osAttrs = Map.insert AttrPrivate (ValBool True) (osAttrs ost) })
            (ObjectId 9) (mObjects modelWithKey)
        }
      privEnv = testEnv { oeModel = privModel }
      (_, k7) = initOperation privEnv emptySessionOps testSession encryptArgs
  assertEqual "private key hidden from public" CKR_OBJECT_HANDLE_INVALID (ioCode k7)
  -- Always-authenticate key: public session cannot even init.
  let authKey = encryptArgs
        { iaKey = Just aesKey { kpAlwaysAuth = True } }
      (_, k8) = initOperation testEnv emptySessionOps testSession authKey
  assertEqual "always-auth needs a login" CKR_USER_NOT_LOGGED_IN (ioCode k8)
  -- ... while a user login marks the slot auth-pending.
  let logged = testSession { ssLogin = LoginUser }
      (ops9, k9) = initOperation testEnv emptySessionOps logged authKey
  assertEqual "user login inits" CKR_OK (ioCode k9)
  assertEqual "slot marked pending" (Just AuthPending) (slotAuth ops9 SlotEncrypt)

-- ---------------------------------------------------------------------------
-- Context gate: consumed only at the first data call
-- ---------------------------------------------------------------------------

plainCommon :: SlotCommon
plainCommon = mkSlotCommon sha256Mech OpDigest Nothing BS.empty AuthNone

caseGate :: IO ()
caseGate = do
  -- Pending + grant: consumed, session returns to plain user login.
  let pending = setCommonAuth AuthPending plainCommon
      granted = testSession { ssLogin = LoginContextUser }
  case gateDataCall granted pending of
    GateOk st' sc' -> do
      assertEqual "grant consumed" LoginUser (ssLogin st')
      assertEqual "slot satisfied" AuthSatisfied (commonAuth sc')
    GateDeny d _ -> assertFailure ("expected consume, got " ++ show d)
  -- Pending without a grant: denied AND the slot must terminate, so a
  -- late grant finds nothing to spend on.
  case gateDataCall testSession pending of
    GateDeny d term -> do
      assertEqual "late/missing grant code" CKR_USER_NOT_LOGGED_IN (sdCode d)
      assertBool "pending slot terminates" term
    GateOk _ _ -> assertFailure "expected deny without a grant"
  -- Premature: a grant presented to a non-pending slot fails and the
  -- grant survives unconsumed (checked at the planner level).
  case gateDataCall granted plainCommon of
    GateDeny d term -> do
      assertEqual "premature code" CKR_USER_NOT_LOGGED_IN (sdCode d)
      assertBool "plain slot survives" (not term)
    GateOk _ _ -> assertFailure "expected premature-use deny"
  -- Satisfied slots proceed under a plain user login.
  let satisfied = setCommonAuth AuthSatisfied plainCommon
      logged = testSession { ssLogin = LoginUser }
  case gateDataCall logged satisfied of
    GateOk _ sc' -> assertEqual "stays satisfied" AuthSatisfied (commonAuth sc')
    GateDeny d _ -> assertFailure ("expected proceed, got " ++ show d)

-- ---------------------------------------------------------------------------
-- Digest sequencing and dispositions
-- ---------------------------------------------------------------------------

caseDigestMultipart :: IO ()
caseDigestMultipart = do
  let (ops0, initOut) = initOperation testEnv emptySessionOps testSession digestArgs
  assertEqual "init ok" CKR_OK (ioCode initOut)
  let opsS = withDigestStream ops0
  let (ops1, _, upd1) = planDigestUpdate opsS testSession "hello, "
  assertEqual "update 1 ok" CKR_OK (soCode upd1)
  assertEqual "update 1 feeds the stream"
    [FxDigestFeed streamRid "hello, "] (soEffects upd1)
  assertEqual "update 1 buffers nothing" (Just 0) (bufferedLength ops1 SlotDigest)
  let (ops2, _, upd2) = planDigestUpdate ops1 testSession "world"
  assertEqual "update 2 ok" CKR_OK (soCode upd2)
  assertEqual "update 2 feeds the stream"
    [FxDigestFeed streamRid "world"] (soEffects upd2)
  assertEqual "update 2 buffers nothing" (Just 0) (bufferedLength ops2 SlotDigest)
  let (ops3, _, finPlan) = planDigestFinal ops2 testSession "digest"
  assertEqual "final plans ok" CKR_OK (soCode finPlan)
  case soEffects finPlan of
    [FxDigestConsume rid] -> do
      assertEqual "final consumes the stream" streamRid rid
      let (ops4, finOut) = finishDigest ops3 SlotDigest "digest"
            (GotBytes (toyDigest "hello, world")) (IntentBuffer 64)
      assertEqual "final ok" CKR_OK (soCode finOut)
      assertEqual "final frees the slot" [] (activeSlots ops4)
      assertEqual "final releases the stream"
        [ReleaseEngineResource streamRid] (soReleases finOut)
      let (_, _, upd3) = planDigestUpdate ops4 testSession "late"
      assertEqual "update after final" CKR_OPERATION_NOT_INITIALIZED (soCode upd3)
    other -> assertFailure ("expected one consume effect, got " ++ show other)

-- | Streamed updates plan one feed effect each and
-- leave the slot buffer empty.
caseDigestStreamsNoBuffer :: IO ()
caseDigestStreamsNoBuffer = do
  let (ops0, _) = initOperation testEnv emptySessionOps testSession digestArgs
  let opsS = withDigestStream ops0
  let (ops1, _, upd1) = planDigestUpdate opsS testSession "hello, "
  assertEqual "update 1 ok" CKR_OK (soCode upd1)
  assertEqual "update 1 plans one feed effect"
    [FxDigestFeed streamRid "hello, "] (soEffects upd1)
  assertEqual "update 1 buffers nothing" (Just 0) (bufferedLength ops1 SlotDigest)
  let (ops2, _, upd2) = planDigestUpdate ops1 testSession "world"
  assertEqual "update 2 ok" CKR_OK (soCode upd2)
  assertEqual "update 2 plans one feed effect"
    [FxDigestFeed streamRid "world"] (soEffects upd2)
  assertEqual "update 2 buffers nothing" (Just 0) (bufferedLength ops2 SlotDigest)

-- | The final consumes the backend stream instead of
-- planning a one-shot over a buffered concatenation, and the
-- finisher releases the stream.
caseDigestFinalConsumes :: IO ()
caseDigestFinalConsumes = do
  let (ops0, _) = initOperation testEnv emptySessionOps testSession digestArgs
  let opsS = withDigestStream ops0
  let (ops1, _, _) = planDigestUpdate opsS testSession "hello, "
  let (ops2, _, _) = planDigestUpdate ops1 testSession "world"
  let (ops3, _, finPlan) = planDigestFinal ops2 testSession "digest"
  assertEqual "final plans ok" CKR_OK (soCode finPlan)
  case soEffects finPlan of
    [FxDigestConsume rid] -> do
      assertEqual "final consumes the stream" streamRid rid
      let (ops4, finOut) = finishDigest ops3 SlotDigest "digest"
            (GotBytes (toyDigest "hello, world")) (IntentBuffer 64)
      assertEqual "final ok" CKR_OK (soCode finOut)
      assertEqual "final frees the slot" [] (activeSlots ops4)
      assertEqual "final releases the stream"
        [ReleaseEngineResource streamRid] (soReleases finOut)
    other -> assertFailure ("expected one consume effect, got " ++ show other)

caseOneShotAfterUpdate :: IO ()
caseOneShotAfterUpdate = do
  let (ops0, _) = initOperation testEnv emptySessionOps testSession digestArgs
  let (ops1, _, upd) = planDigestUpdate (withDigestStream ops0) testSession "part"
  assertEqual "update ok" CKR_OK (soCode upd)
  let (ops2, _, one) = planDigestOneShot ops1 testSession "digest" "whole"
  assertEqual "one-shot after update rejected" CKR_OPERATION_ACTIVE (soCode one)
  assertEqual "rejected one-shot plans nothing" [] (soEffects one)
  assertEqual "rejected one-shot terminates" [] (activeSlots ops2)

caseDigestShortRetry :: IO ()
caseDigestShortRetry = do
  let (ops0, _) = initOperation testEnv emptySessionOps testSession digestArgs
  let (ops1, _, one) = planDigestOneShot ops0 testSession "digest" "abc"
  res <- case soEffects one of
    [fx@(FxDigest _ _)] -> pure (runDigestEffect fx)
    other -> assertFailure ("expected one digest effect, got " ++ show other)
  -- toyDigest "abc" is 4 bytes; a 2-byte buffer is short.
  let (ops2, short) = finishDigest ops1 SlotDigest "digest" res (IntentBuffer 2)
  assertEqual "short buffer" CKR_BUFFER_TOO_SMALL (soCode short)
  assertEqual "short buffer keeps the slot" [SlotDigest] (activeSlots ops2)
  let (ops3, retry) = retryStaged ops2 SlotDigest (IntentBuffer 64)
  assertEqual "retry ok" CKR_OK (soCode retry)
  assertEqual "retry frees the slot" [] (activeSlots ops3)

caseDigestFailureTerminates :: IO ()
caseDigestFailureTerminates = do
  let (ops0, _) = initOperation testEnv emptySessionOps testSession digestArgs
  let (ops1, _, one) = planDigestOneShot ops0 testSession "digest" "abc"
  assertEqual "one-shot plans" 1 (length (soEffects one))
  let (ops2, failed) = finishDigest ops1 SlotDigest "digest"
        (GotCryptoError (CryptoFailed "boom")) (IntentBuffer 64)
  assertEqual "failure code" CKR_GENERAL_ERROR (soCode failed)
  assertEqual "failure frees the slot" [] (activeSlots ops2)
  -- A verdict-shaped result is a driver protocol violation: same end.
  let (ops3, _) = initOperation testEnv emptySessionOps testSession digestArgs
  let (ops4, _, one2) = planDigestOneShot ops3 testSession "digest" "abc"
  assertEqual "one-shot plans again" 1 (length (soEffects one2))
  let (ops5, bad) = finishDigest ops4 SlotDigest "digest"
        (GotValid True) (IntentBuffer 64)
  assertEqual "verdict for digest fails" CKR_GENERAL_ERROR (soCode bad)
  assertEqual "violation frees the slot" [] (activeSlots ops5)

casePremature :: IO ()
casePremature = do
  let (ops0, _) = initOperation testEnv emptySessionOps testSession digestArgs
      granted = testSession { ssLogin = LoginContextUser }
      (ops1, granted', upd) = planDigestUpdate ops0 granted "data"
  assertEqual "premature grant use fails" CKR_USER_NOT_LOGGED_IN (soCode upd)
  assertEqual "grant not consumed" LoginContextUser (ssLogin granted')
  assertEqual "slot survives premature use" [SlotDigest] (activeSlots ops1)
  assertEqual "nothing buffered" (Just 0) (bufferedLength ops1 SlotDigest)

-- ---------------------------------------------------------------------------
-- Part B: cipher lifecycle
-- ---------------------------------------------------------------------------

decryptArgs :: InitArgs
decryptArgs = InitArgs
  { iaOp = OpDecrypt
  , iaMech = aesCbcMech
  , iaParams = BS.replicate 16 0
  , iaKey = Just aesKey
  , iaCipher = Just (CipherSpec 16 True)
  , iaRecover = Nothing
  }

encryptNoPadArgs :: InitArgs
encryptNoPadArgs = encryptArgs { iaCipher = Just (CipherSpec 16 False) }

-- | CTS init environment and arguments: the 16-byte shape with raw
-- IV parameters, encrypt and decrypt routed.
ctsEnv :: OpEnv
ctsEnv = testEnv
  { oeCaps = mkCapabilities [(aesCtsMech, OpEncrypt), (aesCtsMech, OpDecrypt)] }

ctsEncArgs :: InitArgs
ctsEncArgs = InitArgs
  { iaOp = OpEncrypt
  , iaMech = aesCtsMech
  , iaParams = BS.replicate 16 0
  , iaKey = Just aesKey
  , iaCipher = Just (CipherSpec 16 False)
  , iaRecover = Nothing
  }

ctsDecArgs :: InitArgs
ctsDecArgs = ctsEncArgs { iaOp = OpDecrypt }

-- | AES stream init environment and arguments: the 16-byte shape
-- with raw IV parameters; CFB128 represents the streaming rows,
-- OFB the buffer-all row.
streamEnv :: OpEnv
streamEnv = testEnv
  { oeCaps = mkCapabilities
      [ (m, op)
      | m <- [aesCfb128Mech, aesCfb8Mech, aesCfb1Mech, aesOfbMech]
      , op <- [OpEncrypt, OpDecrypt]
      ]
  }

streamArgs :: MechanismId -> InitArgs
streamArgs mech = InitArgs
  { iaOp = OpEncrypt
  , iaMech = mech
  , iaParams = BS.replicate 16 0
  , iaKey = Just aesKey
  , iaCipher = Just (CipherSpec 16 False)
  , iaRecover = Nothing
  }

-- | Toy block cipher: byte reversal, self-inverse, length-preserving.
toyCrypt :: ByteString -> ByteString
toyCrypt = BS.reverse

runCipherEffect :: CryptoEffect -> CryptoResult
runCipherEffect (FxCipher _ _ _ _ input) = GotBytes (toyCrypt input)
runCipherEffect fx = GotCryptoError (CryptoFailed ("unexpected effect: " ++ show fx))

-- | The first staged payload bytes of a finished step, if any.
stagedBytes :: StepOutcome -> Maybe ByteString
stagedBytes out = case soPlan out of
  Just plan -> case opWrites plan of
    [TypedWrite _ _ (PayloadBytes bs)] -> Just bs
    _ -> Nothing
  Nothing -> Nothing

casePkcs7 :: IO ()
casePkcs7 = do
  assertEqual "pad short" (Just "AB\x06\x06\x06\x06\x06\x06") (pkcs7Pad 8 "AB")
  assertEqual "pad full block appended" (Just ("12345678" <> BS.replicate 8 8))
    (pkcs7Pad 8 "12345678")
  assertEqual "pad empty" (Just (BS.replicate 16 16)) (pkcs7Pad 16 BS.empty)
  assertEqual "pad rejects wide block" Nothing (pkcs7Pad 300 "AB")
  assertEqual "pad rejects zero block" Nothing (pkcs7Pad 0 "AB")
  assertEqual "unpad roundtrip" (Just "AB") (pkcs7Unpad 8 "AB\x06\x06\x06\x06\x06\x06")
  assertEqual "unpad zero pad" Nothing (pkcs7Unpad 8 "ABCDEFG\x00")
  assertEqual "unpad overlong" Nothing (pkcs7Unpad 8 "ABCDEFG\x09")
  assertEqual "unpad ragged" Nothing (pkcs7Unpad 8 "ABC")
  assertEqual "unpad empty" Nothing (pkcs7Unpad 8 BS.empty)

caseCipherMultipart :: IO ()
caseCipherMultipart = do
  let msg = "hello, world, this is padded"
      -- A bytewise toy (streaming preserves one-shot equivalence
      -- exactly when the cipher is position-independent; the
      -- reversing toy cannot express that).
      streamCrypt = BS.map complement
      runStream (FxCipher _ _ _ _ input) = GotBytes (streamCrypt input)
      runStream fx = GotCryptoError (CryptoFailed ("unexpected effect: " ++ show fx))
  -- Multipart: two updates plus final. The first update buffers
  -- (7 bytes release nothing); the second streams 16 and retains
  -- 12; the final pads the retained 12.
  let (ops0, i0) = initOperation testEnv emptySessionOps testSession encryptArgs
  assertEqual "encrypt init ok" CKR_OK (ioCode i0)
  let (ops1, _, u1) = planCipherUpdate ops0 testSession SlotEncrypt "hello, " Nothing
  assertEqual "update 1 ok" CKR_OK (soCode u1)
  assertEqual "update 1 plans no crypto" [] (soEffects u1)
  let (ops2, _, u2) = planCipherUpdate ops1 testSession SlotEncrypt "world, this is padded" Nothing
  assertEqual "update 2 ok" CKR_OK (soCode u2)
  updCt <- case soEffects u2 of
    [fx@(FxCipher DirEncrypt mech _ _ input)] -> do
      assertEqual "update mechanism" aesCbcMech mech
      assertEqual "update streams one block" 16 (BS.length input)
      let (opsU, finU) = finishCipherUpdate ops2 SlotEncrypt "cipher"
            (runStream fx) (IntentBuffer 128)
      assertEqual "update finish ok" CKR_OK (soCode finU)
      assertEqual "update keeps the slot" [SlotEncrypt] (activeSlots opsU)
      case stagedBytes finU of
        Just ct -> pure (opsU, ct)
        Nothing -> assertFailure "expected streamed ciphertext"
    other -> assertFailure ("expected one update effect, got " ++ show other)
  let (opsU, updBytes) = updCt
  let (ops3, _, f0) = planCipherFinal opsU testSession SlotEncrypt "cipher"
  assertEqual "final plans" CKR_OK (soCode f0)
  multiCt <- case soEffects f0 of
    [FxCipher DirEncrypt mech _ _ input] -> do
      assertEqual "effect mechanism" aesCbcMech mech
      assertEqual "final input is padded retained" 16 (BS.length input)
      assertBool "block aligned" (BS.length input `mod` 16 == 0)
      let (ops4, fin) = finishCipher ops3 SlotEncrypt "cipher"
            (runStream (FxCipher DirEncrypt mech Nothing BS.empty input))
            (IntentBuffer 128)
      assertEqual "final ok" CKR_OK (soCode fin)
      assertEqual "final frees the slot" [] (activeSlots ops4)
      case stagedBytes fin of
        Just ct -> pure (updBytes <> ct)
        Nothing -> assertFailure "expected staged ciphertext"
    other -> assertFailure ("expected one cipher effect, got " ++ show other)
  -- One-shot over the same message gives identical bytes.
  let (ops5, _) = initOperation testEnv emptySessionOps testSession encryptArgs
  let (ops6, _, o1) = planCipherOneShot ops5 testSession SlotEncrypt "cipher" msg
  oneCt <- case soEffects o1 of
    [fx@(FxCipher DirEncrypt _ _ _ _)] -> do
      let (_, fin) = finishCipher ops6 SlotEncrypt "cipher"
            (runStream fx) (IntentBuffer 128)
      case stagedBytes fin of
        Just ct -> pure ct
        Nothing -> assertFailure "expected staged ciphertext"
    other -> assertFailure ("expected one cipher effect, got " ++ show other)
  assertEqual "multipart equals one-shot" oneCt multiCt
  -- One-shot after an update is rejected on cipher slots too.
  let (ops7, _) = initOperation testEnv emptySessionOps testSession encryptArgs
  let (ops8, _, _) = planCipherUpdate ops7 testSession SlotEncrypt "part" Nothing
  let (_, _, bad) = planCipherOneShot ops8 testSession SlotEncrypt "cipher" msg
  assertEqual "one-shot after update" CKR_OPERATION_ACTIVE (soCode bad)

caseUpdateSplitTable :: IO ()
caseUpdateSplitTable = do
  let cbc = aesCbcMech
      ecb = aesEcbMech
      gcm = aesGcmMech
      oaep = MechanismId 0x0009
      plain = CipherSpec 16 False
      padded = CipherSpec 16 True
  -- Unpadded modes stream every full block, both directions.
  mapM_ (\(total, want) -> do
      assertEqual ("ecb enc " ++ show total) want
        (cipherUpdateSplit ecb plain DirEncrypt total)
      assertEqual ("ecb dec " ++ show total) want
        (cipherUpdateSplit ecb plain DirDecrypt total)
      assertEqual ("cbc enc " ++ show total) want
        (cipherUpdateSplit cbc plain DirEncrypt total)
      assertEqual ("cbc dec " ++ show total) want
        (cipherUpdateSplit cbc plain DirDecrypt total)
    ) [(0, (0, 0)), (15, (0, 15)), (16, (16, 0)), (31, (16, 15)), (32, (32, 0))]
  -- Padded encrypt holds the trailing partial block (or one full
  -- block when aligned: the pad companion is undecided).
  mapM_ (\(total, want) -> assertEqual ("pad enc " ++ show total) want
    (cipherUpdateSplit cbc padded DirEncrypt total)
    ) [(0, (0, 0)), (15, (0, 15)), (16, (0, 16)), (31, (16, 15)), (32, (16, 16)), (33, (32, 1))]
  -- Padded decrypt always holds the last block (it carries the pad).
  mapM_ (\(total, want) -> assertEqual ("pad dec " ++ show total) want
    (cipherUpdateSplit cbc padded DirDecrypt total)
    ) [(0, (0, 0)), (16, (0, 16)), (31, (0, 31)), (32, (16, 16)), (40, (16, 24)), (48, (32, 16))]
  -- Unframed ciphers never stream; degenerate specs buffer too.
  assertEqual "gcm buffers" (0, 100)
    (cipherUpdateSplit gcm (CipherSpec 1 False) DirEncrypt 100)
  assertEqual "gcm decrypt buffers" (0, 100)
    (cipherUpdateSplit gcm (CipherSpec 1 False) DirDecrypt 100)
  assertEqual "oaep buffers" (0, 64)
    (cipherUpdateSplit oaep (CipherSpec 16 False) DirEncrypt 64)
  assertEqual "zero block buffers" (0, 32)
    (cipherUpdateSplit cbc (CipherSpec 0 False) DirEncrypt 32)
  -- CTR streams whole counter blocks despite its unit shape (the
  -- partial tail retains for final: the chain cannot name a
  -- mid-block offset).
  let ctr = MechanismId 0x1086
      stream = CipherSpec 1 False
  mapM_ (\(total, want) -> do
      assertEqual ("ctr enc " ++ show total) want
        (cipherUpdateSplit ctr stream DirEncrypt total)
      assertEqual ("ctr dec " ++ show total) want
        (cipherUpdateSplit ctr stream DirDecrypt total)
    ) [(0, (0, 0)), (15, (0, 15)), (16, (16, 0)), (20, (16, 4)), (31, (16, 15)), (32, (32, 0))]
  -- CTS never streams: the steal pair intertwines the last two
  -- blocks, so every update buffers and only the final runs the
  -- effect over the whole input.
  let cts = aesCtsMech
  mapM_ (\(total, want) -> do
      assertEqual ("cts enc " ++ show total) want
        (cipherUpdateSplit cts plain DirEncrypt total)
      assertEqual ("cts dec " ++ show total) want
        (cipherUpdateSplit cts plain DirDecrypt total)
    ) [(0, (0, 0)), (5, (0, 5)), (16, (0, 16)), (19, (0, 19)), (32, (0, 32)), (37, (0, 37))]
  -- CFB128/CFB8/CFB1 stream full 16-byte chunks like unpadded CBC
  -- (ciphertext-tail chaining); OFB buffers everything (its
  -- register evolves through the block cipher).
  mapM_ (\(total, want) -> do
      assertEqual ("cfb128 enc " ++ show total) want
        (cipherUpdateSplit aesCfb128Mech plain DirEncrypt total)
      assertEqual ("cfb128 dec " ++ show total) want
        (cipherUpdateSplit aesCfb128Mech plain DirDecrypt total)
      assertEqual ("cfb8 enc " ++ show total) want
        (cipherUpdateSplit aesCfb8Mech plain DirEncrypt total)
      assertEqual ("cfb1 enc " ++ show total) want
        (cipherUpdateSplit aesCfb1Mech plain DirEncrypt total)
    ) [(0, (0, 0)), (15, (0, 15)), (16, (16, 0)), (20, (16, 4)), (32, (32, 0)), (37, (32, 5))]
  mapM_ (\(total, want) -> do
      assertEqual ("ofb enc " ++ show total) want
        (cipherUpdateSplit aesOfbMech plain DirEncrypt total)
      assertEqual ("ofb dec " ++ show total) want
        (cipherUpdateSplit aesOfbMech plain DirDecrypt total)
    ) [(0, (0, 0)), (15, (0, 15)), (16, (0, 16)), (20, (0, 20)), (32, (0, 32))]
  -- XTS never streams: within-call tweak evolution is GF doubling
  -- per block, so every update buffers and only the final runs the
  -- effect over the whole data unit.
  mapM_ (\(total, want) -> do
      assertEqual ("xts enc " ++ show total) want
        (cipherUpdateSplit aesXtsMech plain DirEncrypt total)
      assertEqual ("xts dec " ++ show total) want
        (cipherUpdateSplit aesXtsMech plain DirDecrypt total)
    ) [(0, (0, 0)), (15, (0, 15)), (16, (0, 16)), (20, (0, 20)), (32, (0, 32))]

caseUpdateShortNoConsume :: IO ()
caseUpdateShortNoConsume = do
  let (ops0, _) = initOperation testEnv emptySessionOps testSession encryptArgs
      part = BS.replicate 31 0x41
      -- 31 bytes release 16; a 1-byte buffer refuses cleanly.
      (ops1, st1, short) = planCipherUpdate ops0 testSession SlotEncrypt part
        (Just (IntentBuffer 1))
  assertEqual "short update refuses" CKR_BUFFER_TOO_SMALL (soCode short)
  assertEqual "short update changes no slot state"
    (lookupSingle ops0 SlotEncrypt) (lookupSingle ops1 SlotEncrypt)
  assertEqual "short update spends no gate" (ssLogin testSession) (ssLogin st1)
  -- The same part with room streams; the slot was untouched, so
  -- this plans exactly as a first call.
  let (ops2, _, full) = planCipherUpdate ops0 testSession SlotEncrypt part
        (Just (IntentBuffer 128))
  assertEqual "roomy update ok" CKR_OK (soCode full)
  case soEffects full of
    [FxCipher DirEncrypt _ _ _ input] ->
      assertEqual "streams one block" 16 (BS.length input)
    other -> assertFailure ("expected one update effect, got " ++ show other)
  assertEqual "retained suffix" (Just 15) (bufferedLength ops2 SlotEncrypt)

ecbEncryptArgs :: InitArgs
ecbEncryptArgs = InitArgs
  { iaOp = OpEncrypt
  , iaMech = aesEcbMech
  , iaParams = BS.empty
  , iaKey = Just aesKey
  , iaCipher = Just (CipherSpec 16 False)
  , iaRecover = Nothing
  }

ecbDecryptArgs :: InitArgs
ecbDecryptArgs = InitArgs
  { iaOp = OpDecrypt
  , iaMech = aesEcbMech
  , iaParams = BS.empty
  , iaKey = Just aesKey
  , iaCipher = Just (CipherSpec 16 False)
  , iaRecover = Nothing
  }

ecbTestEnv :: OpEnv
ecbTestEnv = testEnv
  { oeCaps = mkCapabilities [(aesEcbMech, OpEncrypt), (aesEcbMech, OpDecrypt)] }

caseStreamedDrainedMarker :: IO ()
caseStreamedDrainedMarker = do
  let (ops0, i0) = initOperation ecbTestEnv emptySessionOps testSession ecbEncryptArgs
  assertEqual "ecb init ok" CKR_OK (ioCode i0)
  -- One full block streams and drains the buffer — yet the slot
  -- still counts as multipart-started.
  let (ops1, _, u1) = planCipherUpdate ops0 testSession SlotEncrypt
        (BS.replicate 16 0x42) Nothing
  assertEqual "update ok" CKR_OK (soCode u1)
  assertEqual "buffer drained" (Just 0) (bufferedLength ops1 SlotEncrypt)
  case lookupSingle ops1 SlotEncrypt >>= activeCipher of
    Just (_, sc, _) -> do
      assertBool "stream marker set" (hasStreamed sc)
      assertEqual "ecb marker is empty" (Just BS.empty) (chainIvOf sc)
    Nothing -> assertFailure "expected cipher slot"
  let (_, _, bad) = planCipherOneShot ops1 testSession SlotEncrypt "cipher" "x"
  assertEqual "one-shot after streamed update" CKR_OPERATION_ACTIVE (soCode bad)

caseDecryptChainsRunningIv :: IO ()
caseDecryptChainsRunningIv = do
  let (ops0, i0) = initOperation testEnv emptySessionOps testSession decryptArgs
  assertEqual "decrypt init ok" CKR_OK (ioCode i0)
  -- 32 bytes of padded-decrypt input release the first block; the
  -- chaining value advances to it at plan time (ciphertext input
  -- is known before the effect runs).
  let ct = BS.pack [0 .. 31]
      (ops1, _, u1) = planCipherUpdate ops0 testSession SlotDecrypt ct Nothing
  assertEqual "update ok" CKR_OK (soCode u1)
  case soEffects u1 of
    [FxCipher DirDecrypt mech _ params input] -> do
      assertEqual "update mechanism" aesCbcMech mech
      assertEqual "streams one block" 16 (BS.length input)
      assertEqual "first chunk chains the init IV" (BS.replicate 16 0) params
    other -> assertFailure ("expected one update effect, got " ++ show other)
  sc1 <- case lookupSingle ops1 SlotDecrypt >>= activeCipher of
    Just (_, sc, _) -> pure sc
    Nothing -> assertFailure "expected decrypt slot"
  assertEqual "chaining value is the first block"
    (Just (BS.pack [0 .. 15])) (chainIvOf sc1)
  assertEqual "retained suffix" 16 (BS.length (bufferedOf sc1))
  -- The final chains from the running value, not the init IV.
  let (_, _, f0) = planCipherFinal ops1 testSession SlotDecrypt "cipher"
  case soEffects f0 of
    [FxCipher DirDecrypt _ _ params _] ->
      assertEqual "final chains the running IV" (BS.pack [0 .. 15]) params
    other -> assertFailure ("expected one final effect, got " ++ show other)

caseEcbDecryptNoChain :: IO ()
caseEcbDecryptNoChain = do
  let (ops0, i0) = initOperation ecbTestEnv emptySessionOps testSession ecbDecryptArgs
  assertEqual "ecb decrypt init ok" CKR_OK (ioCode i0)
  -- ECB has no IV: the streamed block must NOT become a chaining
  -- value, or the final effect would carry a 16-byte "IV" the ECB
  -- recipe rejects (GENERAL_ERROR at the driver).
  let ct = BS.pack [0 .. 15]
      (ops1, _, u1) = planCipherUpdate ops0 testSession SlotDecrypt ct Nothing
  assertEqual "update ok" CKR_OK (soCode u1)
  case lookupSingle ops1 SlotDecrypt >>= activeCipher of
    Just (_, sc, _) -> do
      assertBool "stream marker set" (hasStreamed sc)
      assertEqual "ecb marker is empty" (Just BS.empty) (chainIvOf sc)
    Nothing -> assertFailure "expected decrypt slot"
  let (_, _, f0) = planCipherFinal ops1 testSession SlotDecrypt "cipher"
  case soEffects f0 of
    [FxCipher DirDecrypt mech _ params input] -> do
      assertEqual "final mechanism" aesEcbMech mech
      assertEqual "final chains empty params" BS.empty params
      assertEqual "final input drained" BS.empty input
    other -> assertFailure ("expected one final effect, got " ++ show other)

caseEncryptChainsFromAnswer :: IO ()
caseEncryptChainsFromAnswer = do
  let (ops0, _) = initOperation testEnv emptySessionOps testSession encryptArgs
  -- Nothing is known at plan time (the chaining block is ciphertext
  -- the driver has not produced yet).
  let (ops1, _, u1) = planCipherUpdate ops0 testSession SlotEncrypt
        (BS.replicate 31 0x43) Nothing
  case soEffects u1 of
    [FxCipher DirEncrypt _ _ _ input] ->
      assertEqual "streams one block" 16 (BS.length input)
    other -> assertFailure ("expected one update effect, got " ++ show other)
  case lookupSingle ops1 SlotEncrypt >>= activeCipher of
    Just (_, sc, _) -> assertEqual "no chaining value yet" Nothing (chainIvOf sc)
    Nothing -> assertFailure "expected cipher slot"
  -- The finisher advances the chaining value from the answer and
  -- keeps the slot open on the retained suffix.
  let answer = BS.pack [100 .. 115]
      (ops2, fin) = finishCipherUpdate ops1 SlotEncrypt "cipher"
        (GotBytes answer) (IntentBuffer 128)
  assertEqual "update finish ok" CKR_OK (soCode fin)
  assertEqual "update keeps the slot" [SlotEncrypt] (activeSlots ops2)
  sc2 <- case lookupSingle ops2 SlotEncrypt >>= activeCipher of
    Just (_, sc, _) -> pure sc
    Nothing -> assertFailure "expected cipher slot"
  assertEqual "chaining value is the answer block" (Just answer) (chainIvOf sc2)
  assertEqual "retained suffix" 15 (BS.length (bufferedOf sc2))
  -- A short answer terminates instead of chaining garbage.
  let (ops3, badFin) = finishCipherUpdate ops1 SlotEncrypt "cipher"
        (GotBytes "short") (IntentBuffer 128)
  assertEqual "short answer fails closed" CKR_GENERAL_ERROR (soCode badFin)
  assertEqual "short answer terminates" [] (activeSlots ops3)

caseCipherRoundtrip :: IO ()
caseCipherRoundtrip = do
  let msg = "roundtrip me"
  let (ops0, _) = initOperation testEnv emptySessionOps testSession encryptArgs
  let (ops1, _, o1) = planCipherOneShot ops0 testSession SlotEncrypt "cipher" msg
  ct <- case soEffects o1 of
    [fx@(FxCipher DirEncrypt _ _ _ _)] -> do
      let (_, fin) = finishCipher ops1 SlotEncrypt "cipher"
            (runCipherEffect fx) (IntentBuffer 128)
      case stagedBytes fin of
        Just ct -> pure ct
        Nothing -> assertFailure "expected ciphertext"
    other -> assertFailure ("expected one cipher effect, got " ++ show other)
  assertEqual "padded to one block" 16 (BS.length ct)
  let (ops2, i2) = initOperation testEnv emptySessionOps testSession decryptArgs
  assertEqual "decrypt init ok" CKR_OK (ioCode i2)
  let (ops3, _, o2) = planCipherOneShot ops2 testSession SlotDecrypt "plain" ct
  case soEffects o2 of
    [fx@(FxCipher DirDecrypt _ _ _ input)] -> do
      assertEqual "decrypt input is the full block" ct input
      let (ops4, fin) = finishCipher ops3 SlotDecrypt "plain"
            (runCipherEffect fx) (IntentBuffer 128)
      assertEqual "decrypt ok" CKR_OK (soCode fin)
      assertEqual "roundtrip recovers" (Just msg) (stagedBytes fin)
      assertEqual "decrypt slot freed" [] (activeSlots ops4)
    other -> assertFailure ("expected one cipher effect, got " ++ show other)

caseCipherLengths :: IO ()
caseCipherLengths = do
  -- Unpadded encrypt of a ragged length denies AND terminates the
  -- slot (spec: every error other than BUFFER_TOO_SMALL terminates);
  -- no repair update can follow a denied final.
  let (ops0, _) = initOperation testEnv emptySessionOps testSession encryptNoPadArgs
  let (ops1, _, _) = planCipherUpdate ops0 testSession SlotEncrypt "twelve bytes" Nothing
  assertEqual "buffered" (Just 12) (bufferedLength ops1 SlotEncrypt)
  let (ops2, _, fout) = planCipherFinal ops1 testSession SlotEncrypt "cipher"
  assertEqual "ragged unpadded denied" CKR_DATA_LEN_RANGE (soCode fout)
  assertEqual "length deny frees the slot" [] (activeSlots ops2)
  let (_, _, upd) = planCipherUpdate ops2 testSession SlotEncrypt "1234" Nothing
  assertEqual "no repair after denied final"
    CKR_OPERATION_NOT_INITIALIZED (soCode upd)
  -- The ragged one-shot terminates the same way.
  let (opsA, _) = initOperation testEnv emptySessionOps testSession encryptNoPadArgs
  let (opsB, _, one) = planCipherOneShot opsA testSession SlotEncrypt "cipher" "short"
  assertEqual "ragged one-shot denied" CKR_DATA_LEN_RANGE (soCode one)
  assertEqual "one-shot deny frees the slot" [] (activeSlots opsB)
  -- One-shot over buffered multipart input denies ACTIVE and
  -- terminates (a re-init, not a final, follows).
  let (opsC, _) = initOperation testEnv emptySessionOps testSession encryptArgs
  let (opsD, _, _) = planCipherUpdate opsC testSession SlotEncrypt "abc" Nothing
  let (opsE, _, mid) = planCipherOneShot opsD testSession SlotEncrypt "cipher" "d"
  assertEqual "one-shot over buffered" CKR_OPERATION_ACTIVE (soCode mid)
  assertEqual "mid-stream deny frees the slot" [] (activeSlots opsE)
  -- Unpadded decrypt of a ragged driver answer fails at finish.
  let noPadDec = decryptArgs { iaCipher = Just (CipherSpec 16 False) }
  let (ops5, _) = initOperation testEnv emptySessionOps testSession noPadDec
  let (ops6, _, _) = planCipherOneShot ops5 testSession SlotDecrypt "plain" "short"
  let (ops7, fin) = finishCipher ops6 SlotDecrypt "plain"
        (GotBytes "short") (IntentBuffer 128)
  assertEqual "ragged decrypt answer" CKR_ENCRYPTED_DATA_LEN_RANGE (soCode fin)
  assertEqual "length failure frees" [] (activeSlots ops7)

-- | CTS replaces block alignment with the stealing floor: ragged
-- input at/above one block plans (one-shot and multipart final),
-- sub-block input denies DATA_LEN_RANGE and terminates, updates
-- buffer everything, and decrypt finish stages ragged answers at
-- the floor while refusing short ones.
caseCtsFloor :: IO ()
caseCtsFloor = do
  let ragged21 = "0123456789abcdefghijk" :: ByteString
  -- Ragged one-shot encrypt plans with the raw bytes as effect input.
  let (ops0, i0) = initOperation ctsEnv emptySessionOps testSession ctsEncArgs
  assertEqual "cts init ok" CKR_OK (ioCode i0)
  let (ops1, _, one) = planCipherOneShot ops0 testSession SlotEncrypt "cipher" ragged21
  assertEqual "cts ragged one-shot plans" CKR_OK (soCode one)
  case soEffects one of
    [FxCipher DirEncrypt mech _ _ input] -> do
      assertEqual "cts effect mechanism" aesCtsMech mech
      assertEqual "cts effect carries ragged bytes" ragged21 input
    other -> assertFailure ("expected one cts effect, got " ++ show other)
  assertEqual "cts one-shot keeps the slot" [SlotEncrypt] (activeSlots ops1)
  -- Sub-block one-shot denies and terminates.
  let (opsA, _) = initOperation ctsEnv emptySessionOps testSession ctsEncArgs
  let (opsB, _, short) = planCipherOneShot opsA testSession SlotEncrypt "cipher" "short"
  assertEqual "cts short one-shot denied" CKR_DATA_LEN_RANGE (soCode short)
  assertEqual "cts short deny frees the slot" [] (activeSlots opsB)
  -- Multipart buffers everything: updates plan no crypto, the
  -- final sees the whole 37-byte buffer.
  let (opsC, _) = initOperation ctsEnv emptySessionOps testSession ctsEncArgs
  let (opsD, _, u1) = planCipherUpdate opsC testSession SlotEncrypt "0123456789abcdef" Nothing
  assertEqual "cts update 1 ok" CKR_OK (soCode u1)
  assertEqual "cts update 1 plans no crypto" [] (soEffects u1)
  let (opsE, _, u2) = planCipherUpdate opsD testSession SlotEncrypt "0123456789abcdef01234" Nothing
  assertEqual "cts update 2 ok" CKR_OK (soCode u2)
  assertEqual "cts update 2 plans no crypto" [] (soEffects u2)
  assertEqual "cts buffered all" (Just 37) (bufferedLength opsE SlotEncrypt)
  let (_, _, f0) = planCipherFinal opsE testSession SlotEncrypt "cipher"
  assertEqual "cts final plans" CKR_OK (soCode f0)
  case soEffects f0 of
    [FxCipher DirEncrypt _ _ _ input] ->
      assertEqual "cts final input is the whole buffer" 37 (BS.length input)
    other -> assertFailure ("expected one cts final effect, got " ++ show other)
  -- Decrypt finish stages ragged answers at/above the floor.
  let (opsG, _) = initOperation ctsEnv emptySessionOps testSession ctsDecArgs
  let (opsH, _, _) = planCipherOneShot opsG testSession SlotDecrypt "plain" ragged21
  let (opsI, fin) = finishCipher opsH SlotDecrypt "plain"
        (GotBytes ragged21) (IntentBuffer 128)
  assertEqual "cts ragged decrypt stages" CKR_OK (soCode fin)
  assertEqual "cts decrypt stages bytes" (Just ragged21) (stagedBytes fin)
  assertEqual "cts decrypt frees the slot" [] (activeSlots opsI)
  -- ... and refuses answers below the floor.
  let (opsJ, _) = initOperation ctsEnv emptySessionOps testSession ctsDecArgs
  let (opsK, _, _) = planCipherOneShot opsJ testSession SlotDecrypt "plain" "short"
  let (opsL, finS) = finishCipher opsK SlotDecrypt "plain"
        (GotBytes "short") (IntentBuffer 128)
  assertEqual "cts short decrypt refused" CKR_ENCRYPTED_DATA_LEN_RANGE (soCode finS)
  assertEqual "cts short decrypt frees" [] (activeSlots opsL)

-- | AES stream rows (CFB128/CFB8/CFB1/OFB) accept any input length,
-- empty included: ragged one-shots plan, CFB* multipart streams
-- 16-byte chunks with ciphertext-tail chaining, OFB multipart
-- buffers to the final, and decrypt finish stages ragged answers.
caseAesStreamFloor :: IO ()
caseAesStreamFloor = do
  let ragged20 = "0123456789abcdefghij" :: ByteString
  -- Ragged one-shot encrypt plans on all four rows.
  mapM_ (\mech -> do
      let (ops0, i0) = initOperation streamEnv emptySessionOps testSession (streamArgs mech)
      assertEqual ("stream init ok " ++ show mech) CKR_OK (ioCode i0)
      let (_, _, one) = planCipherOneShot ops0 testSession SlotEncrypt "cipher" ragged20
      assertEqual ("ragged one-shot plans " ++ show mech) CKR_OK (soCode one)
      case soEffects one of
        [FxCipher DirEncrypt _ _ _ input] ->
          assertEqual ("effect carries ragged bytes " ++ show mech) ragged20 input
        other -> assertFailure ("expected one stream effect, got " ++ show other)
    ) [aesCfb128Mech, aesCfb8Mech, aesCfb1Mech, aesOfbMech]
  -- Empty one-shot plans too (length-preserving, 0 -> 0).
  let (opsE, _) = initOperation streamEnv emptySessionOps testSession (streamArgs aesCfb128Mech)
  let (_, _, empty) = planCipherOneShot opsE testSession SlotEncrypt "cipher" BS.empty
  assertEqual "empty one-shot plans" CKR_OK (soCode empty)
  -- CFB128 multipart streams 16, chains the answer tail, finals 4.
  let (ops0, _) = initOperation streamEnv emptySessionOps testSession (streamArgs aesCfb128Mech)
  let (ops1, _, u1) = planCipherUpdate ops0 testSession SlotEncrypt "0123456789abcdef" Nothing
  assertEqual "cfb128 update ok" CKR_OK (soCode u1)
  updAns <- case soEffects u1 of
    [fx@(FxCipher DirEncrypt _ _ _ input)] -> do
      assertEqual "update streams one block" 16 (BS.length input)
      pure (runCipherEffect fx)
    other -> assertFailure ("expected one update effect, got " ++ show other)
  let (ops2, finU) = finishCipherUpdate ops1 SlotEncrypt "cipher" updAns (IntentBuffer 128)
  assertEqual "update finish ok" CKR_OK (soCode finU)
  let (ops3, _, u2) = planCipherUpdate ops2 testSession SlotEncrypt "ghij" Nothing
  assertEqual "cfb128 tail update ok" CKR_OK (soCode u2)
  assertEqual "tail update plans no crypto" [] (soEffects u2)
  let (_, _, f0) = planCipherFinal ops3 testSession SlotEncrypt "cipher"
  assertEqual "cfb128 final plans" CKR_OK (soCode f0)
  case (updAns, soEffects f0) of
    (GotBytes ans, [FxCipher DirEncrypt _ _ params input]) -> do
      assertEqual "final input is the retained tail" "ghij" input
      assertEqual "final chains the answer tail" ans params
    other -> assertFailure ("expected chained final effect, got " ++ show other)
  -- OFB multipart buffers everything: updates plan no crypto.
  let (opsA, _) = initOperation streamEnv emptySessionOps testSession (streamArgs aesOfbMech)
  let (opsB, _, uo1) = planCipherUpdate opsA testSession SlotEncrypt "0123456789abcdef" Nothing
  assertEqual "ofb update ok" CKR_OK (soCode uo1)
  assertEqual "ofb update plans no crypto" [] (soEffects uo1)
  let (opsC, _, uo2) = planCipherUpdate opsB testSession SlotEncrypt ragged20 Nothing
  assertEqual "ofb update 2 plans no crypto" [] (soEffects uo2)
  assertEqual "ofb buffered all" (Just 36) (bufferedLength opsC SlotEncrypt)
  let (_, _, fo) = planCipherFinal opsC testSession SlotEncrypt "cipher"
  assertEqual "ofb final plans" CKR_OK (soCode fo)
  case soEffects fo of
    [FxCipher DirEncrypt _ _ _ input] ->
      assertEqual "ofb final input is the whole buffer" 36 (BS.length input)
    other -> assertFailure ("expected one ofb final effect, got " ++ show other)
  -- Decrypt finish stages ragged answers (even 1-byte CFB8).
  let (opsD, _) = initOperation streamEnv emptySessionOps testSession
        ((streamArgs aesCfb8Mech) { iaOp = OpDecrypt })
  let (opsF, _, _) = planCipherOneShot opsD testSession SlotDecrypt "plain" "X"
  let (opsG, fin) = finishCipher opsF SlotDecrypt "plain"
        (GotBytes "X") (IntentBuffer 128)
  assertEqual "cfb8 1-byte decrypt stages" CKR_OK (soCode fin)
  assertEqual "decrypt stages bytes" (Just "X") (stagedBytes fin)
  assertEqual "decrypt frees the slot" [] (activeSlots opsG)

caseCipherBadPad :: IO ()
caseCipherBadPad = do
  let (ops0, _) = initOperation testEnv emptySessionOps testSession decryptArgs
  let (ops1, _, o1) = planCipherOneShot ops0 testSession SlotDecrypt "plain"
        (BS.replicate 16 0)
  assertEqual "decrypt plans" 1 (length (soEffects o1))
  -- A zero last byte is never valid PKCS#7.
  let (ops2, fin) = finishCipher ops1 SlotDecrypt "plain"
        (GotBytes (BS.replicate 15 0x41 <> BS.singleton 0)) (IntentBuffer 128)
  assertEqual "bad pad code" CKR_ENCRYPTED_DATA_INVALID (soCode fin)
  assertEqual "bad pad frees the slot" [] (activeSlots ops2)

caseCipherShortFail :: IO ()
caseCipherShortFail = do
  let (ops0, _) = initOperation testEnv emptySessionOps testSession encryptArgs
  let (ops1, _, o1) = planCipherOneShot ops0 testSession SlotEncrypt "cipher" "0123456789abcdef0123"
  res <- case soEffects o1 of
    [fx@(FxCipher DirEncrypt _ _ _ _)] -> pure (runCipherEffect fx)
    other -> assertFailure ("expected one cipher effect, got " ++ show other)
  let (ops2, short) = finishCipher ops1 SlotEncrypt "cipher" res (IntentBuffer 4)
  assertEqual "short buffer" CKR_BUFFER_TOO_SMALL (soCode short)
  assertEqual "short keeps the slot" [SlotEncrypt] (activeSlots ops2)
  let (ops3, retry) = retryStaged ops2 SlotEncrypt (IntentBuffer 128)
  assertEqual "retry ok" CKR_OK (soCode retry)
  assertEqual "retry frees" [] (activeSlots ops3)
  -- Crypto failure terminates.
  let (ops4, _) = initOperation testEnv emptySessionOps testSession encryptArgs
  let (ops5, _, o2) = planCipherOneShot ops4 testSession SlotEncrypt "cipher" "data"
  assertEqual "plans" 1 (length (soEffects o2))
  let (ops6, failed) = finishCipher ops5 SlotEncrypt "cipher"
        (GotCryptoError (CryptoFailed "boom")) (IntentBuffer 128)
  assertEqual "failure code" CKR_GENERAL_ERROR (soCode failed)
  assertEqual "failure frees" [] (activeSlots ops6)

-- | A size query always stages — even an empty output, which would
-- otherwise "fit" a zero cap and free the slot before the recall
-- (the wycheproof empty-message OAEP legs).
caseEmptyQueryStages :: IO ()
caseEmptyQueryStages = do
  let noPadDec = decryptArgs { iaCipher = Just (CipherSpec 16 False) }
  let (ops0, _) = initOperation testEnv emptySessionOps testSession noPadDec
  let (ops1, _, o1) = planCipherOneShot ops0 testSession SlotDecrypt "plain" BS.empty
  assertEqual "empty plans" 1 (length (soEffects o1))
  let (ops2, query) = finishCipher ops1 SlotDecrypt "plain"
        (GotBytes BS.empty) IntentNull
  assertEqual "query stages" CKR_BUFFER_TOO_SMALL (soCode query)
  assertEqual "query keeps the slot" [SlotDecrypt] (activeSlots ops2)
  let (ops3, recall) = retryStaged ops2 SlotDecrypt (IntentBuffer 0)
  assertEqual "recall completes" CKR_OK (soCode recall)
  assertEqual "recall frees" [] (activeSlots ops3)
  -- A re-query re-reports instead of completing.
  let (ops4, _) = initOperation testEnv emptySessionOps testSession noPadDec
  let (ops5, _, _) = planCipherOneShot ops4 testSession SlotDecrypt "plain" BS.empty
  let (ops6, q2) = finishCipher ops5 SlotDecrypt "plain"
        (GotBytes BS.empty) IntentNull
  assertEqual "second query stages" CKR_BUFFER_TOO_SMALL (soCode q2)
  let (ops7, q3) = retryStaged ops6 SlotDecrypt IntentNull
  assertEqual "re-query re-reports" CKR_BUFFER_TOO_SMALL (soCode q3)
  assertEqual "re-query keeps the slot" [SlotDecrypt] (activeSlots ops7)

caseAuthConsumeUpdate :: IO ()
caseAuthConsumeUpdate = do
  let authArgs = encryptArgs { iaKey = Just aesKey { kpAlwaysAuth = True } }
      logged = testSession { ssLogin = LoginUser }
      granted = testSession { ssLogin = LoginContextUser }
  let (ops0, i0) = initOperation testEnv emptySessionOps logged authArgs
  assertEqual "init ok" CKR_OK (ioCode i0)
  assertEqual "pending" (Just AuthPending) (slotAuth ops0 SlotEncrypt)
  -- First data call spends the grant and returns to a plain login.
  let (ops1, st1, u1) = planCipherUpdate ops0 granted SlotEncrypt "part-1" Nothing
  assertEqual "first update ok" CKR_OK (soCode u1)
  assertEqual "grant consumed" LoginUser (ssLogin st1)
  assertEqual "slot satisfied" (Just AuthSatisfied) (slotAuth ops1 SlotEncrypt)
  -- Later updates proceed under the plain login.
  let (ops2, st2, u2) = planCipherUpdate ops1 st1 SlotEncrypt "part-2" Nothing
  assertEqual "second update ok" CKR_OK (soCode u2)
  assertEqual "still plain login" LoginUser (ssLogin st2)
  assertEqual "buffered both" (Just 12) (bufferedLength ops2 SlotEncrypt)

caseAuthLateFails :: IO ()
caseAuthLateFails = do
  let authArgs = encryptArgs { iaKey = Just aesKey { kpAlwaysAuth = True } }
      logged = testSession { ssLogin = LoginUser }
      granted = testSession { ssLogin = LoginContextUser }
  let (ops0, _) = initOperation testEnv emptySessionOps logged authArgs
  -- Grantless first data call denies and terminates the pending slot.
  let (ops1, st1, u1) = planCipherUpdate ops0 logged SlotEncrypt "part-1" Nothing
  assertEqual "grantless denied" CKR_USER_NOT_LOGGED_IN (soCode u1)
  assertEqual "pending slot terminated" [] (activeSlots ops1)
  assertEqual "login untouched" LoginUser (ssLogin st1)
  -- The late grant finds no operation to spend on.
  let (_, _, u2) = planCipherUpdate ops1 granted SlotEncrypt "part-1" Nothing
  assertEqual "late use fails" CKR_OPERATION_NOT_INITIALIZED (soCode u2)

caseCipherBlockRange :: IO ()
caseCipherBlockRange = do
  let wide = encryptArgs { iaCipher = Just (CipherSpec 300 True) }
      (_, o1) = initOperation testEnv emptySessionOps testSession wide
  assertEqual "padded wide block rejected" CKR_ARGUMENTS_BAD (ioCode o1)
  let narrow = encryptArgs { iaCipher = Just (CipherSpec 0 True) }
      (_, o2) = initOperation testEnv emptySessionOps testSession narrow
  assertEqual "zero block rejected" CKR_ARGUMENTS_BAD (ioCode o2)

-- ---------------------------------------------------------------------------
-- Part C: signature and recovery lifecycles
-- ---------------------------------------------------------------------------

signEnv :: OpEnv
signEnv = testEnv
  { oeCaps = mkCapabilities [(hmacMech, OpSign), (hmacMech, OpVerify)]
  }

signKey :: KeyPolicy
signKey = aesKey { kpPermits = [OpSign, OpVerify] }

signArgs :: InitArgs
signArgs = InitArgs OpSign hmacMech BS.empty (Just signKey) Nothing Nothing

verifyArgs :: InitArgs
verifyArgs = InitArgs OpVerify hmacMech BS.empty (Just signKey) Nothing Nothing

dsaSignEnv :: OpEnv
dsaSignEnv = testEnv
  { oeCaps = mkCapabilities
      [ (dsaMech, OpSign), (dsaMech, OpVerify)
      , (dsaSha256Mech, OpSign), (dsaSha256Mech, OpVerify)
      ]
  }

dsaSignArgs :: InitArgs
dsaSignArgs = InitArgs OpSign dsaMech BS.empty (Just signKey) Nothing Nothing

dsaVerifyArgs :: InitArgs
dsaVerifyArgs = InitArgs OpVerify dsaMech BS.empty (Just signKey) Nothing Nothing

dsaSha256SignArgs :: InitArgs
dsaSha256SignArgs = InitArgs OpSign dsaSha256Mech BS.empty (Just signKey) Nothing Nothing

eddsaSignEnv :: OpEnv
eddsaSignEnv = testEnv
  { oeCaps = mkCapabilities
      [ (eddsaMech, OpSign), (eddsaMech, OpVerify)
      ]
  }

caseEddsaParams :: IO ()
caseEddsaParams = do
  -- NULL params refuse: the struct is required (PARAM_INVALID, exact).
  let (_, i0) = initOperation eddsaSignEnv emptySessionOps testSession
        (InitArgs OpSign eddsaMech BS.empty (Just signKey) Nothing Nothing)
  assertEqual "eddsa NULL refused" CKR_MECHANISM_PARAM_INVALID (ioCode i0)
  let (_, i0v) = initOperation eddsaSignEnv emptySessionOps testSession
        (InitArgs OpVerify eddsaMech BS.empty (Just signKey) Nothing Nothing)
  assertEqual "eddsa verify NULL refused" CKR_MECHANISM_PARAM_INVALID (ioCode i0v)
  -- Pure explicit struct admits.
  let (_, i1) = initOperation eddsaSignEnv emptySessionOps testSession
        (InitArgs OpSign eddsaMech (encodeEddsaParams False BS.empty)
          (Just signKey) Nothing Nothing)
  assertEqual "eddsa pure init ok" CKR_OK (ioCode i1)
  -- Prehash flag refuses with the sibling recipe code.
  let (_, i2) = initOperation eddsaSignEnv emptySessionOps testSession
        (InitArgs OpSign eddsaMech (encodeEddsaParams True BS.empty)
          (Just signKey) Nothing Nothing)
  assertEqual "eddsa prehash refused" CKR_ARGUMENTS_BAD (ioCode i2)
  -- Non-empty context refuses the same way.
  let (_, i3) = initOperation eddsaSignEnv emptySessionOps testSession
        (InitArgs OpSign eddsaMech (encodeEddsaParams False "CTX")
          (Just signKey) Nothing Nothing)
  assertEqual "eddsa context refused" CKR_ARGUMENTS_BAD (ioCode i3)
  -- Verify init follows the same params gate.
  let (_, i4) = initOperation eddsaSignEnv emptySessionOps testSession
        (InitArgs OpVerify eddsaMech (encodeEddsaParams True BS.empty)
          (Just signKey) Nothing Nothing)
  assertEqual "eddsa verify prehash refused" CKR_ARGUMENTS_BAD (ioCode i4)

ssl3MacSignEnv :: OpEnv
ssl3MacSignEnv = testEnv
  { oeCaps = mkCapabilities
      [ (ssl3Md5Mech, OpSign), (ssl3Md5Mech, OpVerify)
      , (ssl3Sha1Mech, OpSign), (ssl3Sha1Mech, OpVerify)
      ]
  }

caseSsl3MacParams :: IO ()
caseSsl3MacParams = do
  -- NULL params refuse: the length is required (PARAM_INVALID, exact).
  let (_, i0) = initOperation ssl3MacSignEnv emptySessionOps testSession
        (InitArgs OpSign ssl3Md5Mech BS.empty (Just signKey) Nothing Nothing)
  assertEqual "ssl3 NULL refused" CKR_MECHANISM_PARAM_INVALID (ioCode i0)
  let (_, i0v) = initOperation ssl3MacSignEnv emptySessionOps testSession
        (InitArgs OpVerify ssl3Md5Mech BS.empty (Just signKey) Nothing Nothing)
  assertEqual "ssl3 verify NULL refused" CKR_MECHANISM_PARAM_INVALID (ioCode i0v)
  -- Whole-byte bit lengths admit.
  let (_, i1) = initOperation ssl3MacSignEnv emptySessionOps testSession
        (InitArgs OpSign ssl3Md5Mech (encodeMacGeneral 128)
          (Just signKey) Nothing Nothing)
  assertEqual "ssl3 md5 128 admits" CKR_OK (ioCode i1)
  let (_, i2) = initOperation ssl3MacSignEnv emptySessionOps testSession
        (InitArgs OpSign ssl3Sha1Mech (encodeMacGeneral 160)
          (Just signKey) Nothing Nothing)
  assertEqual "ssl3 sha1 160 admits" CKR_OK (ioCode i2)
  -- Fractional bytes and over-width refuse with the recipe code.
  let (_, i3) = initOperation ssl3MacSignEnv emptySessionOps testSession
        (InitArgs OpSign ssl3Md5Mech (encodeMacGeneral 129)
          (Just signKey) Nothing Nothing)
  assertEqual "ssl3 md5 129 refused" CKR_MECHANISM_PARAM_INVALID (ioCode i3)
  let (_, i4) = initOperation ssl3MacSignEnv emptySessionOps testSession
        (InitArgs OpSign ssl3Sha1Mech (encodeMacGeneral 168)
          (Just signKey) Nothing Nothing)
  assertEqual "ssl3 sha1 168 refused" CKR_MECHANISM_PARAM_INVALID (ioCode i4)

mldsaSignEnv :: OpEnv
mldsaSignEnv = testEnv
  { oeCaps = mkCapabilities
      [ (mldsaMech, OpSign), (mldsaMech, OpVerify)
      ]
  }

caseMldsaParams :: IO ()
caseMldsaParams = do
  -- NULL params admit (the struct is optional; empty means
  -- hedge-preferred, empty context) — the opposite of EdDSA.
  let (_, i0) = initOperation mldsaSignEnv emptySessionOps testSession
        (InitArgs OpSign mldsaMech BS.empty (Just signKey) Nothing Nothing)
  assertEqual "mldsa NULL admits" CKR_OK (ioCode i0)
  let (_, i0v) = initOperation mldsaSignEnv emptySessionOps testSession
        (InitArgs OpVerify mldsaMech BS.empty (Just signKey) Nothing Nothing)
  assertEqual "mldsa verify NULL admits" CKR_OK (ioCode i0v)
  -- Explicit structs admit (context and deterministic included).
  let (_, i1) = initOperation mldsaSignEnv emptySessionOps testSession
        (InitArgs OpSign mldsaMech (encodeMldsaParams HedgePreferred "CTX")
          (Just signKey) Nothing Nothing)
  assertEqual "mldsa context init ok" CKR_OK (ioCode i1)
  let (_, i1d) = initOperation mldsaSignEnv emptySessionOps testSession
        (InitArgs OpSign mldsaMech (encodeMldsaParams HedgeDeterministic BS.empty)
          (Just signKey) Nothing Nothing)
  assertEqual "mldsa deterministic init ok" CKR_OK (ioCode i1d)
  -- Unmapped hedge words refuse with the recipe code.
  let (_, i2) = initOperation mldsaSignEnv emptySessionOps testSession
        (InitArgs OpSign mldsaMech (BS.replicate 15 0 <> BS.singleton 3 <> BS.replicate 8 0)
          (Just signKey) Nothing Nothing)
  assertEqual "mldsa bad hedge refused" CKR_ARGUMENTS_BAD (ioCode i2)
  -- Overlong contexts refuse the same way.
  let (_, i3) = initOperation mldsaSignEnv emptySessionOps testSession
        (InitArgs OpSign mldsaMech (encodeMldsaParams HedgePreferred (BS.replicate 256 0x41))
          (Just signKey) Nothing Nothing)
  assertEqual "mldsa overlong context refused" CKR_ARGUMENTS_BAD (ioCode i3)
  -- Verify init follows the same params gate.
  let (_, i4) = initOperation mldsaSignEnv emptySessionOps testSession
        (InitArgs OpVerify mldsaMech (encodeMldsaParams HedgePreferred (BS.replicate 256 0x41))
          (Just signKey) Nothing Nothing)
  assertEqual "mldsa verify overlong refused" CKR_ARGUMENTS_BAD (ioCode i4)

caseRawDsaFloor :: IO ()
caseRawDsaFloor = do
  -- Sign one-shot under the floor refuses and terminates.
  let (ops0, i0) = initOperation dsaSignEnv emptySessionOps testSession dsaSignArgs
  assertEqual "raw DSA sign init ok" CKR_OK (ioCode i0)
  let (ops1, _, o1) = planSignOneShot ops0 testSession "signature" (BS.replicate 7 0)
  assertEqual "short digest code" CKR_DATA_LEN_RANGE (soCode o1)
  assertEqual "short digest plans nothing" [] (soEffects o1)
  assertEqual "short digest frees" [] (activeSlots ops1)
  -- A 20-byte digest plans one effect.
  let (ops2, _) = initOperation dsaSignEnv emptySessionOps testSession dsaSignArgs
      (_, _, o2) = planSignOneShot ops2 testSession "signature" (BS.replicate 20 0)
  assertEqual "floor digest plans" 1 (length (soEffects o2))
  -- Sign final under the floor refuses too.
  let (ops3, _) = initOperation dsaSignEnv emptySessionOps testSession dsaSignArgs
      (ops4, _, _) = planSignUpdate ops3 testSession (BS.replicate 7 0)
      (ops5, _, o3) = planSignFinal ops4 testSession "signature"
  assertEqual "short final code" CKR_DATA_LEN_RANGE (soCode o3)
  assertEqual "short final frees" [] (activeSlots ops5)
  -- Verify one-shot under the floor refuses and terminates.
  let (ops6, i6) = initOperation dsaSignEnv emptySessionOps testSession dsaVerifyArgs
  assertEqual "raw DSA verify init ok" CKR_OK (ioCode i6)
  let (ops7, _, o4) = planVerifyOneShot ops6 testSession "verify"
        (BS.replicate 7 0) "sig-witness"
  assertEqual "short verify code" CKR_DATA_LEN_RANGE (soCode o4)
  assertEqual "short verify plans nothing" [] (soEffects o4)
  assertEqual "short verify frees" [] (activeSlots ops7)
  -- Verify final under the floor refuses.
  let (ops8, _) = initOperation dsaSignEnv emptySessionOps testSession dsaVerifyArgs
      (ops9, _, _) = planVerifyUpdate ops8 testSession (BS.replicate 7 0)
      (ops10, _, o5) = planVerifyFinal ops9 testSession "verify" "sig-witness"
  assertEqual "short verify final code" CKR_DATA_LEN_RANGE (soCode o5)
  assertEqual "short verify final frees" [] (activeSlots ops10)
  -- Hash-and-sign rows carry no floor: short messages plan.
  let (ops11, i11) = initOperation dsaSignEnv emptySessionOps testSession dsaSha256SignArgs
  assertEqual "DSA-SHA256 init ok" CKR_OK (ioCode i11)
  let (_, _, o6) = planSignOneShot ops11 testSession "signature" (BS.replicate 7 0)
  assertEqual "hash row plans short input" 1 (length (soEffects o6))

-- | Toy MAC: 8-byte length tag over the reversal. Verify recomputes.
toyTag :: ByteString -> ByteString
toyTag bs = BS.take 8 (BS.reverse bs <> BS.replicate 8 0)

runSignEffect :: CryptoEffect -> CryptoResult
runSignEffect (FxSign _ _ _ input) = GotBytes (toyTag input)
runSignEffect fx = GotCryptoError (CryptoFailed ("unexpected effect: " ++ show fx))

runVerifyEffect :: CryptoEffect -> CryptoResult
runVerifyEffect (FxVerify _ _ _ input sig) = GotValid (toyTag input == sig)
runVerifyEffect fx = GotCryptoError (CryptoFailed ("unexpected effect: " ++ show fx))

-- | Toy recovery tag: fixed-width bytes derived from the input.
toyRecTag :: Int -> ByteString -> ByteString
toyRecTag tagLen bs = BS.take tagLen (BS.reverse bs <> BS.replicate tagLen 0)

runSignRecoverEffect :: CryptoEffect -> CryptoResult
runSignRecoverEffect (FxSignRecover _ _ _ input tagLen) =
  GotBytes (toyRecTag tagLen input)
runSignRecoverEffect fx =
  GotCryptoError (CryptoFailed ("unexpected effect: " ++ show fx))

runVerifyRecoverEffect :: CryptoEffect -> CryptoResult
runVerifyRecoverEffect (FxVerifyRecover _ _ _ sig tagLen)
  | BS.length sig <= tagLen = GotValid False
  | otherwise =
      let (dat, tag) = BS.splitAt (BS.length sig - tagLen) sig
      in if tag == toyRecTag tagLen dat then GotBytes dat else GotValid False
runVerifyRecoverEffect fx =
  GotCryptoError (CryptoFailed ("unexpected effect: " ++ show fx))

signRecoverArgs :: InitArgs
signRecoverArgs = InitArgs OpSignRecover recMech BS.empty
  (Just aesKey { kpPermits = [OpSignRecover] })
  Nothing (Just (RecoverSpec 64 32))

verifyRecoverArgs :: InitArgs
verifyRecoverArgs = InitArgs OpVerifyRecover recMech BS.empty
  (Just aesKey { kpPermits = [OpVerifyRecover] })
  Nothing (Just (RecoverSpec 64 32))

caseSignRoundtrip :: IO ()
caseSignRoundtrip = do
  let (ops0, i0) = initOperation signEnv emptySessionOps testSession signArgs
  assertEqual "sign init ok" CKR_OK (ioCode i0)
  let (ops1, _, u1) = planSignUpdate ops0 testSession "hello, "
  assertEqual "sign update ok" CKR_OK (soCode u1)
  assertEqual "update plans no crypto" [] (soEffects u1)
  let (ops2, _, u2) = planSignUpdate ops1 testSession "world"
  assertEqual "sign update 2 ok" CKR_OK (soCode u2)
  let (ops3, _, fout) = planSignFinal ops2 testSession "signature"
  sig <- case soEffects fout of
    [fx@(FxSign mech _ _ input)] -> do
      assertEqual "effect mechanism" hmacMech mech
      assertEqual "effect input concatenated" "hello, world" input
      let (ops4, fin) = finishSign ops3 SlotSign "signature"
            (runSignEffect fx) (IntentBuffer 64)
      assertEqual "sign ok" CKR_OK (soCode fin)
      assertEqual "sign frees" [] (activeSlots ops4)
      case stagedBytes fin of
        Just s -> pure s
        Nothing -> assertFailure "expected staged signature"
    other -> assertFailure ("expected one sign effect, got " ++ show other)
  assertEqual "toy tag width" 8 (BS.length sig)
  -- Verify the multipart message against the staged tag.
  let (ops5, i5) = initOperation signEnv emptySessionOps testSession verifyArgs
  assertEqual "verify init ok" CKR_OK (ioCode i5)
  let (ops6, _, v1) = planVerifyUpdate ops5 testSession "hello, "
  assertEqual "verify update ok" CKR_OK (soCode v1)
  let (ops7, _, v2) = planVerifyUpdate ops6 testSession "world"
  assertEqual "verify update 2 ok" CKR_OK (soCode v2)
  let (ops8, _, f2) = planVerifyFinal ops7 testSession "verify" sig
  case soEffects f2 of
    [fx@(FxVerify _ _ _ input wit)] -> do
      assertEqual "verify input concatenated" "hello, world" input
      assertEqual "verify witness carried" sig wit
      let (ops9, fin) = finishVerify ops8 SlotVerify "verify"
            (runVerifyEffect fx) (IntentBuffer 0)
      assertEqual "verify ok" CKR_OK (soCode fin)
      assertEqual "verify frees" [] (activeSlots ops9)
    other -> assertFailure ("expected one verify effect, got " ++ show other)

-- | No live stream on the slot: buffered operations never
-- allocate one.
assertNoStream :: SessionOps -> SlotKind -> IO ()
assertNoStream ops kind = case lookupSingle ops kind of
  Just active ->
    assertEqual "no stream allocated" Nothing (streamOf (commonOf active))
  Nothing -> assertFailure "slot missing"

-- | Guard: sign stays buffered — updates plan no effects,
-- accumulate in the buffer, and allocate no stream. (Verdict: the
-- backend signs/verifies one-shot only; see the walkthrough.)
caseSignStaysBuffered :: IO ()
caseSignStaysBuffered = do
  let (ops0, i0) = initOperation signEnv emptySessionOps testSession signArgs
  assertEqual "sign init ok" CKR_OK (ioCode i0)
  let (ops1, _, u1) = planSignUpdate ops0 testSession "hello, "
  assertEqual "update 1 ok" CKR_OK (soCode u1)
  assertEqual "update 1 plans no crypto" [] (soEffects u1)
  assertEqual "update 1 buffered" (Just 7) (bufferedLength ops1 SlotSign)
  assertNoStream ops1 SlotSign
  let (ops2, _, u2) = planSignUpdate ops1 testSession "world"
  assertEqual "update 2 ok" CKR_OK (soCode u2)
  assertEqual "update 2 plans no crypto" [] (soEffects u2)
  assertEqual "update 2 buffered" (Just 12) (bufferedLength ops2 SlotSign)
  assertNoStream ops2 SlotSign

-- | Guard: verify stays buffered — updates plan no effects,
-- accumulate in the buffer, and allocate no stream. (Verdict: the
-- backend signs/verifies one-shot only; see the walkthrough.)
caseVerifyStaysBuffered :: IO ()
caseVerifyStaysBuffered = do
  let (ops0, i0) = initOperation signEnv emptySessionOps testSession verifyArgs
  assertEqual "verify init ok" CKR_OK (ioCode i0)
  let (ops1, _, u1) = planVerifyUpdate ops0 testSession "hello, "
  assertEqual "update 1 ok" CKR_OK (soCode u1)
  assertEqual "update 1 plans no crypto" [] (soEffects u1)
  assertEqual "update 1 buffered" (Just 7) (bufferedLength ops1 SlotVerify)
  assertNoStream ops1 SlotVerify
  let (ops2, _, u2) = planVerifyUpdate ops1 testSession "world"
  assertEqual "update 2 ok" CKR_OK (soCode u2)
  assertEqual "update 2 plans no crypto" [] (soEffects u2)
  assertEqual "update 2 buffered" (Just 12) (bufferedLength ops2 SlotVerify)
  assertNoStream ops2 SlotVerify

caseVerifyMismatch :: IO ()
caseVerifyMismatch = do
  let (ops0, _) = initOperation signEnv emptySessionOps testSession verifyArgs
  let (ops1, _, o1) = planVerifyOneShot ops0 testSession "verify" "data" "wrong!!"
  assertEqual "verify plans" 1 (length (soEffects o1))
  let (ops2, fin) = finishVerify ops1 SlotVerify "verify"
        (GotValid False) (IntentBuffer 0)
  assertEqual "mismatch code" CKR_SIGNATURE_INVALID (soCode fin)
  assertEqual "mismatch frees" [] (activeSlots ops2)

caseVerifyEmpty :: IO ()
caseVerifyEmpty = do
  let (ops0, _) = initOperation signEnv emptySessionOps testSession verifyArgs
  let (ops1, _, o1) = planVerifyOneShot ops0 testSession "verify" "data" BS.empty
  assertEqual "empty sig invalid" CKR_SIGNATURE_INVALID (soCode o1)
  assertEqual "empty sig plans nothing" [] (soEffects o1)
  assertEqual "empty sig frees" [] (activeSlots ops1)

caseVerifyOneShotAfterUpdate :: IO ()
caseVerifyOneShotAfterUpdate = do
  let (ops0, _) = initOperation signEnv emptySessionOps testSession verifyArgs
  let (ops1, _, _) = planVerifyUpdate ops0 testSession "part"
  let (ops2, _, one) =
        planVerifyOneShot ops1 testSession "verify" "whole" "sig-witness"
  assertEqual "one-shot after update" CKR_OPERATION_ACTIVE (soCode one)
  assertEqual "rejected one-shot terminates" [] (activeSlots ops2)

caseSignOneShotAfterUpdate :: IO ()
caseSignOneShotAfterUpdate = do
  let (ops0, _) = initOperation signEnv emptySessionOps testSession signArgs
  let (ops1, _, _) = planSignUpdate ops0 testSession "part"
  let (ops2, _, one) = planSignOneShot ops1 testSession "signature" "whole"
  assertEqual "one-shot after update" CKR_OPERATION_ACTIVE (soCode one)
  assertEqual "rejected one-shot terminates" [] (activeSlots ops2)

caseSignShortFail :: IO ()
caseSignShortFail = do
  let (ops0, _) = initOperation signEnv emptySessionOps testSession signArgs
  let (ops1, _, o1) = planSignOneShot ops0 testSession "signature" "message"
  res <- case soEffects o1 of
    [fx@(FxSign _ _ _ _)] -> pure (runSignEffect fx)
    other -> assertFailure ("expected one sign effect, got " ++ show other)
  let (ops2, short) = finishSign ops1 SlotSign "signature" res (IntentBuffer 2)
  assertEqual "short buffer" CKR_BUFFER_TOO_SMALL (soCode short)
  assertEqual "short keeps" [SlotSign] (activeSlots ops2)
  let (ops3, retry) = retryStaged ops2 SlotSign (IntentBuffer 64)
  assertEqual "retry ok" CKR_OK (soCode retry)
  assertEqual "retry frees" [] (activeSlots ops3)
  let (ops4, _) = initOperation signEnv emptySessionOps testSession signArgs
  let (ops5, _, o2) = planSignOneShot ops4 testSession "signature" "message"
  assertEqual "plans" 1 (length (soEffects o2))
  let (ops6, failed) = finishSign ops5 SlotSign "signature"
        (GotCryptoError (CryptoFailed "boom")) (IntentBuffer 64)
  assertEqual "failure code" CKR_GENERAL_ERROR (soCode failed)
  assertEqual "failure frees" [] (activeSlots ops6)

caseRecoverRoundtrip :: IO ()
caseRecoverRoundtrip = do
  let msg = "recover me"
  let (ops0, i0) = initOperation recEnv emptySessionOps testSession signRecoverArgs
  assertEqual "sign-recover init ok" CKR_OK (ioCode i0)
  let (ops1, _, o1) = planSignRecoverOneShot ops0 testSession "block" msg
  block <- case soEffects o1 of
    [fx@(FxSignRecover _ _ _ input tagLen)] -> do
      assertEqual "effect input" msg input
      assertEqual "effect tag width" 32 tagLen
      let (ops2, fin) = finishSignRecover ops1 SlotSign "block"
            (runSignRecoverEffect fx) (IntentBuffer 128)
      assertEqual "sign-recover ok" CKR_OK (soCode fin)
      assertEqual "sign-recover frees" [] (activeSlots ops2)
      case stagedBytes fin of
        Just b -> pure b
        Nothing -> assertFailure "expected staged block"
    other -> assertFailure ("expected one recover effect, got " ++ show other)
  assertEqual "block is data||tag" (BS.length msg + 32) (BS.length block)
  let (ops3, i3) = initOperation recEnv emptySessionOps testSession verifyRecoverArgs
  assertEqual "verify-recover init ok" CKR_OK (ioCode i3)
  let (ops4, _, o2) = planVerifyRecoverOneShot ops3 testSession "data" block
  case soEffects o2 of
    [fx@(FxVerifyRecover _ _ _ sig tagLen)] -> do
      assertEqual "effect sig" block sig
      assertEqual "effect tag width" 32 tagLen
      let (ops5, fin) = finishVerifyRecover ops4 SlotVerify "data"
            (runVerifyRecoverEffect fx) (IntentBuffer 128)
      assertEqual "verify-recover ok" CKR_OK (soCode fin)
      assertEqual "data recovered" (Just msg) (stagedBytes fin)
      assertEqual "verify-recover frees" [] (activeSlots ops5)
    other -> assertFailure ("expected one recover effect, got " ++ show other)

caseRecoverOversize :: IO ()
caseRecoverOversize = do
  -- 33 data bytes plus the 32-byte tag exceed the 64-byte capacity.
  let (ops0, _) = initOperation recEnv emptySessionOps testSession signRecoverArgs
  let (ops1, _, o1) = planSignRecoverOneShot ops0 testSession "block"
        (BS.replicate 33 0x41)
  assertEqual "oversize code" CKR_DATA_LEN_RANGE (soCode o1)
  assertEqual "oversize plans nothing" [] (soEffects o1)
  assertEqual "oversize frees" [] (activeSlots ops1)

caseRecoverTampered :: IO ()
caseRecoverTampered = do
  let (ops0, _) = initOperation recEnv emptySessionOps testSession verifyRecoverArgs
  let block = "some-data" <> BS.replicate 32 0xFF
  let (ops1, _, o1) = planVerifyRecoverOneShot ops0 testSession "data" block
  assertEqual "tampered plans" 1 (length (soEffects o1))
  let (ops2, fin) = finishVerifyRecover ops1 SlotVerify "data"
        (GotValid False) (IntentBuffer 128)
  assertEqual "tampered code" CKR_SIGNATURE_INVALID (soCode fin)
  assertEqual "tampered frees" [] (activeSlots ops2)
  -- A block shorter than the tag alone is invalid without an effect.
  let (ops3, _) = initOperation recEnv emptySessionOps testSession verifyRecoverArgs
  let (ops4, _, o2) = planVerifyRecoverOneShot ops3 testSession "data" "tiny"
  assertEqual "tiny block invalid" CKR_SIGNATURE_INVALID (soCode o2)
  assertEqual "tiny plans nothing" [] (soEffects o2)
  assertEqual "tiny frees" [] (activeSlots ops4)

caseRecoverNoMultipart :: IO ()
caseRecoverNoMultipart = do
  let (ops0, _) = initOperation recEnv emptySessionOps testSession signRecoverArgs
  let (_, _, u1) = planSignUpdate ops0 testSession "part"
  assertEqual "recover takes no updates" CKR_OPERATION_NOT_INITIALIZED (soCode u1)
  let (_, _, fout) = planSignFinal ops0 testSession "signature"
  assertEqual "recover takes no final" CKR_OPERATION_NOT_INITIALIZED (soCode fout)
  let (_, _, o1) = planSignOneShot ops0 testSession "signature" "data"
  assertEqual "plain one-shot refused on recover" CKR_OPERATION_NOT_INITIALIZED (soCode o1)
  -- And the mirror: recover one-shot on a plain sign slot.
  let (ops1, _) = initOperation signEnv emptySessionOps testSession signArgs
  let (_, _, o2) = planSignRecoverOneShot ops1 testSession "block" "data"
  assertEqual "recover refused on plain slot" CKR_OPERATION_NOT_INITIALIZED (soCode o2)

-- ---------------------------------------------------------------------------
-- Part D: dual operations
-- ---------------------------------------------------------------------------

-- | Both staged payloads of a merged dual plan, in plan order.
stagedPair :: StepOutcome -> Maybe (ByteString, ByteString)
stagedPair out = case soPlan out of
  Just plan -> case opWrites plan of
    [TypedWrite _ _ (PayloadBytes a), TypedWrite _ _ (PayloadBytes b)] ->
      Just (a, b)
    _ -> Nothing
  Nothing -> Nothing

caseDualConflicts :: IO ()
caseDualConflicts = do
  let (ops0, i0) = initDualOperation testEnv emptySessionOps testSession
        digestArgs encryptArgs
  assertEqual "dual init ok" CKR_OK (ioCode i0)
  assertBool "dual present" (hasDual ops0)
  assertEqual "dual occupies both slots" [SlotDigest, SlotEncrypt] (activeSlots ops0)
  let (_, i1) = initOperation testEnv ops0 testSession digestArgs
  assertEqual "digest conflicts with dual" CKR_OPERATION_ACTIVE (ioCode i1)
  let (_, i2) = initOperation testEnv ops0 testSession encryptArgs
  assertEqual "encrypt conflicts with dual" CKR_OPERATION_ACTIVE (ioCode i2)
  let (_, i3) = initDualOperation testEnv ops0 testSession digestArgs encryptArgs
  assertEqual "dual conflicts with dual" CKR_OPERATION_ACTIVE (ioCode i3)
  -- Unoccupied slots still admit singles alongside the dual.
  let (ops4, i4) = initOperation testEnv ops0 testSession decryptArgs
  assertEqual "decrypt coexists" CKR_OK (ioCode i4)
  assertEqual "dual plus decrypt" [SlotDigest, SlotEncrypt, SlotDecrypt]
    (activeSlots ops4)
  -- A digest single blocks a later dual init.
  let (ops5, _) = initOperation testEnv emptySessionOps testSession digestArgs
  let (_, i5) = initDualOperation testEnv ops5 testSession digestArgs encryptArgs
  assertEqual "dual needs a free digest slot" CKR_OPERATION_ACTIVE (ioCode i5)

caseDualUpdate :: IO ()
caseDualUpdate = do
  let (ops0, _) = initDualOperation testEnv emptySessionOps testSession
        digestArgs encryptArgs
  let (ops1, _, u1) = planDualUpdate ops0 testSession "part-1"
  assertEqual "dual update 1 ok" CKR_OK (soCode u1)
  assertEqual "update plans no crypto" [] (soEffects u1)
  assertEqual "both sides buffered" (Just (6, 6)) (dualBuffered ops1)
  let (ops2, _, u2) = planDualUpdate ops1 testSession "part-2!!"
  assertEqual "dual update 2 ok" CKR_OK (soCode u2)
  assertEqual "both sides grow together" (Just (14, 14)) (dualBuffered ops2)
  -- The supported non-combined sequence: the single digest
  -- streams its parts while the dual buffers both sides.
  let (dOps0, _) = initOperation testEnv emptySessionOps testSession digestArgs
  let (dOps1, _, du1) = planDigestUpdate (withDigestStream dOps0) testSession "part-1"
  let (dOps2, _, du2) = planDigestUpdate dOps1 testSession "part-2!!"
  let (cOps0, _) = initOperation testEnv emptySessionOps testSession encryptArgs
  let (cOps1, _, _) = planCipherUpdate cOps0 testSession SlotEncrypt "part-1" Nothing
  let (cOps2, _, _) = planCipherUpdate cOps1 testSession SlotEncrypt "part-2!!" Nothing
  assertEqual "single digest streams part 1"
    [FxDigestFeed streamRid "part-1"] (soEffects du1)
  assertEqual "single digest streams part 2"
    [FxDigestFeed streamRid "part-2!!"] (soEffects du2)
  assertEqual "single digest buffers nothing" (Just 0) (bufferedLength dOps2 SlotDigest)
  assertEqual "cipher side matches" (Just 14) (bufferedLength cOps2 SlotEncrypt)

caseDualFinal :: IO ()
caseDualFinal = do
  let msg = "hello, world, this is padded"
      -- Bytewise toy: dual buffers everything while the streamed
      -- single cipher emits per chunk, so only a
      -- position-independent cipher keeps the pair equal.
      runStream (FxCipher _ _ _ _ input) =
        GotBytes (BS.map complement input)
      runStream fx = GotCryptoError (CryptoFailed ("unexpected effect: " ++ show fx))
  let (ops0, _) = initDualOperation testEnv emptySessionOps testSession
        digestArgs encryptArgs
  let (ops1, _, _) = planDualUpdate ops0 testSession "hello, "
  let (ops2, _, _) = planDualUpdate ops1 testSession "world, this is padded"
  let (ops3, _, fout) = planDualFinal ops2 testSession
  assertEqual "dual final plans" CKR_OK (soCode fout)
  dualPair <- case soEffects fout of
    [FxDigest dMech dIn, FxCipher DirEncrypt cMech _ _ cIn] -> do
      assertEqual "digest mechanism" sha256Mech dMech
      assertEqual "digest input" msg dIn
      assertEqual "cipher mechanism" aesCbcMech cMech
      assertEqual "cipher input padded" 32 (BS.length cIn)
      let (ops4, fin) = finishDual ops3 "digest" "cipher"
            (runDigestEffect (FxDigest dMech dIn))
            (runStream (FxCipher DirEncrypt cMech Nothing BS.empty cIn))
            (IntentBuffer 64) (IntentBuffer 128)
      assertEqual "dual final ok" CKR_OK (soCode fin)
      assertBool "dual freed" (not (hasDual ops4))
      assertEqual "all slots freed" [] (activeSlots ops4)
      case stagedPair fin of
        Just p -> pure p
        Nothing -> assertFailure "expected two staged outputs"
    other -> assertFailure ("expected two effects, got " ++ show other)
  -- The non-combined sequence produces the identical pair.
  let (dOps0, _) = initOperation testEnv emptySessionOps testSession digestArgs
  let (dOps1, _, _) = planDigestUpdate (withDigestStream dOps0) testSession "hello, "
  let (dOps2, _, _) = planDigestUpdate dOps1 testSession "world, this is padded"
  let (dOps3, _, df) = planDigestFinal dOps2 testSession "digest"
  dOut <- case soEffects df of
    [FxDigestConsume rid] -> do
      assertEqual "single final consumes the stream" streamRid rid
      let (_, fin) = finishDigest dOps3 SlotDigest "digest"
            (GotBytes (toyDigest msg)) (IntentBuffer 64)
      case stagedBytes fin of
        Just b -> pure b
        Nothing -> assertFailure "expected digest bytes"
    other -> assertFailure ("expected one consume effect, got " ++ show other)
  let (cOps0, _) = initOperation testEnv emptySessionOps testSession encryptArgs
  let (cOps1, _, _) = planCipherUpdate cOps0 testSession SlotEncrypt "hello, " Nothing
  let (cOps2, _, cu) = planCipherUpdate cOps1 testSession SlotEncrypt "world, this is padded" Nothing
  streamOut <- case soEffects cu of
    [fx@(FxCipher DirEncrypt _ _ _ input)] -> do
      assertEqual "update streams one block" 16 (BS.length input)
      let (cOpsU, finU) = finishCipherUpdate cOps2 SlotEncrypt "cipher"
            (runStream fx) (IntentBuffer 128)
      assertEqual "update finish ok" CKR_OK (soCode finU)
      case stagedBytes finU of
        Just b -> pure (cOpsU, b)
        Nothing -> assertFailure "expected streamed bytes"
    other -> assertFailure ("expected one update effect, got " ++ show other)
  let (cOpsU, updBytes) = streamOut
  let (cOps3, _, cf) = planCipherFinal cOpsU testSession SlotEncrypt "cipher"
  cOut <- case soEffects cf of
    [fx@(FxCipher DirEncrypt _ _ _ _)] -> do
      let (_, fin) = finishCipher cOps3 SlotEncrypt "cipher"
            (runStream fx) (IntentBuffer 128)
      case stagedBytes fin of
        Just b -> pure (updBytes <> b)
        Nothing -> assertFailure "expected cipher bytes"
    other -> assertFailure ("expected one cipher effect, got " ++ show other)
  assertEqual "dual equals non-combined" (dOut, cOut) dualPair

caseDualDecryptTail :: IO ()
caseDualDecryptTail = do
  let msg = "dual decrypt tail!"
  -- Standalone encrypt first, so a real padded tail exists.
  let (eOps0, _) = initOperation testEnv emptySessionOps testSession encryptArgs
  let (eOps1, _, eo) = planCipherOneShot eOps0 testSession SlotEncrypt "cipher" msg
  ct <- case soEffects eo of
    [fx@(FxCipher DirEncrypt _ _ _ _)] -> do
      let (_, fin) = finishCipher eOps1 SlotEncrypt "cipher"
            (runCipherEffect fx) (IntentBuffer 128)
      case stagedBytes fin of
        Just b -> pure b
        Nothing -> assertFailure "expected ciphertext"
    other -> assertFailure ("expected one cipher effect, got " ++ show other)
  assertEqual "padded tail present" 32 (BS.length ct)
  -- Dual digest+decrypt over the ciphertext.
  let (ops0, _) = initDualOperation testEnv emptySessionOps testSession
        digestArgs decryptArgs
  let (ops1, _, _) = planDualUpdate ops0 testSession (BS.take 20 ct)
  let (ops2, _, _) = planDualUpdate ops1 testSession (BS.drop 20 ct)
  let (ops3, _, fout) = planDualFinal ops2 testSession
  dualPair <- case soEffects fout of
    [FxDigest _ dIn, FxCipher DirDecrypt _ _ _ cIn] -> do
      assertEqual "digest covers all ct" ct dIn
      assertEqual "decrypt covers all ct" ct cIn
      let (_, fin) = finishDual ops3 "digest" "plain"
            (runDigestEffect (FxDigest sha256Mech dIn))
            (runCipherEffect (FxCipher DirDecrypt aesCbcMech Nothing BS.empty cIn))
            (IntentBuffer 64) (IntentBuffer 128)
      assertEqual "dual decrypt ok" CKR_OK (soCode fin)
      case stagedPair fin of
        Just p -> pure p
        Nothing -> assertFailure "expected two staged outputs"
    other -> assertFailure ("expected two effects, got " ++ show other)
  -- Standalone: digest over ct plus decrypt with pad-strip.
  let (dOps0, _) = initOperation testEnv emptySessionOps testSession digestArgs
  let (dOps1, _, do_) = planDigestOneShot dOps0 testSession "digest" ct
  dOut <- case soEffects do_ of
    [fx@(FxDigest _ _)] -> do
      let (_, fin) = finishDigest dOps1 SlotDigest "digest"
            (runDigestEffect fx) (IntentBuffer 64)
      case stagedBytes fin of
        Just b -> pure b
        Nothing -> assertFailure "expected digest bytes"
    other -> assertFailure ("expected one digest effect, got " ++ show other)
  let (cOps0, _) = initOperation testEnv emptySessionOps testSession decryptArgs
  let (cOps1, _, co) = planCipherOneShot cOps0 testSession SlotDecrypt "plain" ct
  cOut <- case soEffects co of
    [fx@(FxCipher DirDecrypt _ _ _ _)] -> do
      let (_, fin) = finishCipher cOps1 SlotDecrypt "plain"
            (runCipherEffect fx) (IntentBuffer 128)
      case stagedBytes fin of
        Just b -> pure b
        Nothing -> assertFailure "expected plain bytes"
    other -> assertFailure ("expected one cipher effect, got " ++ show other)
  assertEqual "padded tail matches standalone" (dOut, cOut) dualPair
  assertEqual "tail strips to the message" msg cOut

caseDualShortRetry :: IO ()
caseDualShortRetry = do
  let msg = "short retry dual output"
  let (ops0, _) = initDualOperation testEnv emptySessionOps testSession
        digestArgs encryptArgs
  let (ops1, _, _) = planDualUpdate ops0 testSession msg
  let (ops2, _, fout) = planDualFinal ops1 testSession
  (dRes, cRes, expectD, expectC) <- case soEffects fout of
    [fxD@(FxDigest _ _), fxC@(FxCipher DirEncrypt _ _ _ _)] -> do
      let dRes = runDigestEffect fxD
          cRes = runCipherEffect fxC
      pure (dRes, cRes, expectBytes dRes, expectBytes cRes)
    other -> assertFailure ("expected two effects, got " ++ show other)
  -- Digest fits; the cipher tail does not.
  let (ops3, short) = finishDual ops2 "digest" "cipher" dRes cRes
        (IntentBuffer 64) (IntentBuffer 4)
  assertEqual "short code" CKR_BUFFER_TOO_SMALL (soCode short)
  assertBool "dual kept" (hasDual ops3)
  -- Retry replays only the pending cipher side.
  let (ops4, retry) = retryDualFinal ops3 (IntentBuffer 64) (IntentBuffer 128)
  assertEqual "retry ok" CKR_OK (soCode retry)
  assertBool "retry frees the dual" (not (hasDual ops4))
  case soPlan retry of
    Just plan -> case opWrites plan of
      [TypedWrite _ _ (PayloadBytes only)] ->
        assertEqual "only the pending side replays" expectC only
      other -> assertFailure ("expected one replayed write, got " ++ show other)
    Nothing -> assertFailure "expected a retry plan"
  -- And the first plan already delivered the digest bytes.
  case soPlan short of
    Just plan -> case opWrites plan of
      [TypedWrite _ _ (PayloadBytes d)] ->
        assertEqual "digest delivered first" expectD d
      other -> assertFailure ("expected one digest write, got " ++ show other)
    Nothing -> assertFailure "expected a short plan"
  where
    expectBytes (GotBytes b) = b
    expectBytes r = error ("expected bytes, got " ++ show r)

caseDualFailure :: IO ()
caseDualFailure = do
  let (ops0, _) = initDualOperation testEnv emptySessionOps testSession
        digestArgs encryptArgs
  let (ops1, _, _) = planDualUpdate ops0 testSession "data"
  let (ops2, _, fout) = planDualFinal ops1 testSession
  assertEqual "dual plans two" 2 (length (soEffects fout))
  let (ops3, failed) = finishDual ops2 "digest" "cipher"
        (GotCryptoError (CryptoFailed "boom")) (GotBytes "ct")
        (IntentBuffer 64) (IntentBuffer 64)
  assertEqual "digest failure code" CKR_GENERAL_ERROR (soCode failed)
  assertBool "failure frees the dual" (not (hasDual ops3))
  -- A corrupt decrypt pad through the dual fails the same way.
  let (ops4, _) = initDualOperation testEnv emptySessionOps testSession
        digestArgs decryptArgs
  let (ops5, _, _) = planDualUpdate ops4 testSession (BS.replicate 16 0)
  let (ops6, _, f2) = planDualFinal ops5 testSession
  assertEqual "dual decrypt plans two" 2 (length (soEffects f2))
  let (ops7, badPad) = finishDual ops6 "digest" "plain"
        (GotBytes "digest") (GotBytes (BS.replicate 15 1 <> BS.singleton 0))
        (IntentBuffer 64) (IntentBuffer 64)
  assertEqual "dual bad pad code" CKR_ENCRYPTED_DATA_INVALID (soCode badPad)
  assertBool "bad pad frees the dual" (not (hasDual ops7))

caseDualAuth :: IO ()
caseDualAuth = do
  let authArgs = encryptArgs { iaKey = Just aesKey { kpAlwaysAuth = True } }
      logged = testSession { ssLogin = LoginUser }
      granted = testSession { ssLogin = LoginContextUser }
  let (ops0, i0) = initDualOperation testEnv emptySessionOps logged
        digestArgs authArgs
  assertEqual "dual init ok" CKR_OK (ioCode i0)
  assertEqual "dual pending" (Just AuthPending) (dualAuth ops0)
  let (ops1, st1, u1) = planDualUpdate ops0 granted "part-1"
  assertEqual "first dual update ok" CKR_OK (soCode u1)
  assertEqual "grant consumed" LoginUser (ssLogin st1)
  assertEqual "dual satisfied" (Just AuthSatisfied) (dualAuth ops1)
  assertEqual "both buffered" (Just (6, 6)) (dualBuffered ops1)
