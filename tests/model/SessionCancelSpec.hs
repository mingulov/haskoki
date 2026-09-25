{- | Session-cancel tests: 'F_SessionCancel' clears the session's
active operations per its CKF_* selector mask and releases live
digest streams, so a cancelled session re-inits clean (the MCT
recovery path: cancel must clear CKR_OPERATION_ACTIVE).

CKF_* selector values are pinned by spec/vendor/pkcs11.h
(CKF_ENCRYPT 0x100, CKF_DECRYPT 0x200, CKF_DIGEST 0x400,
CKF_SIGN 0x800, CKF_SIGN_RECOVER 0x1000, CKF_VERIFY 0x2000,
CKF_VERIFY_RECOVER 0x4000).
-}
{-# LANGUAGE OverloadedStrings #-}
module SessionCancelSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word32)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , emptyModel
  , lookupSession
  )
import Haskoki.Operation
  ( CipherSpec (..)
  , DigestStream (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , SessionOps
  , SlotKind (..)
  , activeDigest
  , activeSlots
  , emptySessionOps
  , hasDual
  , initDualOperation
  , initOperation
  , insertOp
  , lookupSingle
  , mkActiveDigest
  , opsActive
  , setLive
  )
import Haskoki.Operation.Codec (decodeCancelInput, encodeCancelInput)
import Haskoki.Outcome
  ( PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , ResourceRelease (..)
  , StateDelta (..)
  )
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Request
  ( FunctionId (..)
  , Request (..)
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Transition (planCall, publishDelta)
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
spec = testGroup "session cancel"
  [ testCase "cancel flags codec round-trips" caseCodecRoundTrip
  , testCase "cancel flags codec rejects malformed" caseCodecMalformed
  , testCase "cancel-all clears an encrypt single" caseCancelAllEncrypt
  , testCase "empty input refuses (strict flags)" caseCancelEmptyRefuses
  , testCase "selective cancel keeps unselected slots" caseSelective
  , testCase "recover bits select their shared slot" caseRecoverBits
  , testCase "cancel-all clears a dual plus singles" caseCancelDual
  , testCase "cancel releases a live digest stream" caseCancelReleasesStream
  , testCase "cancel on an idle session is a no-op OK" caseCancelIdle
  , testCase "cancel on an unknown session refuses" caseCancelUnknown
  , testCase "cancel with malformed input refuses" caseCancelMalformed
  ]

-- | CKF_* selector bits (pinned header, see module doc).
ckfEncrypt, ckfDecrypt, ckfDigest, ckfSign :: Word32
ckfSignRecover, ckfVerify, ckfVerifyRecover :: Word32
ckfEncrypt = 0x100
ckfDecrypt = 0x200
ckfDigest = 0x400
ckfSign = 0x800
ckfSignRecover = 0x1000
ckfVerify = 0x2000
ckfVerifyRecover = 0x4000

-- | Every classic selector bit at once (the harness recovery mask).
allOpFlags :: Word32
allOpFlags = ckfEncrypt + ckfDecrypt + ckfDigest + ckfSign
  + ckfSignRecover + ckfVerify + ckfVerifyRecover

sha256Mech, hmacMech, aesCbcMech :: MechanismId
sha256Mech = MechanismId 0x250
hmacMech = MechanismId 0x251
aesCbcMech = MechanismId 0x1082

aesKey :: KeyPolicy
aesKey = KeyPolicy
  { kpHandle = ExternalHandle 3
  , kpPermits = [OpEncrypt, OpDecrypt]
  , kpAlwaysAuth = False
  }

signKey :: KeyPolicy
signKey = aesKey { kpPermits = [OpSign, OpVerify] }

digestArgs :: InitArgs
digestArgs = InitArgs
  { iaOp = OpDigest
  , iaMech = sha256Mech
  , iaParams = BS.empty
  , iaKey = Nothing
  , iaCipher = Nothing
  , iaRecover = Nothing
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

decryptArgs :: InitArgs
decryptArgs = encryptArgs
  { iaOp = OpDecrypt
  , iaCipher = Just (CipherSpec 16 True)
  }

signArgs :: InitArgs
signArgs = InitArgs OpSign hmacMech BS.empty (Just signKey) Nothing Nothing

verifyArgs :: InitArgs
verifyArgs = InitArgs OpVerify hmacMech BS.empty (Just signKey) Nothing Nothing

cancelEnv :: Model -> OpEnv
cancelEnv model = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities
      [ (sha256Mech, OpDigest)
      , (hmacMech, OpSign)
      , (hmacMech, OpVerify)
      , (aesCbcMech, OpEncrypt)
      , (aesCbcMech, OpDecrypt)
      ]
  , oeModel = model
  }

testSession :: SessionState
testSession = SessionState
  { ssId = SessionId 1
  , ssSlot = SlotId 0
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

-- | A model holding exactly one session (with the given ops) plus
-- the key object behind 'ExternalHandle 3', as in OperationSpec.
opsModel :: SessionOps -> Model
opsModel ops = emptyModel
  { mSessions = Map.singleton (SessionId 1) (testSession { ssOps = ops })
  , mObjects = Map.singleton (ObjectId 9) ObjectState
      { osId = ObjectId 9
      , osRevision = Revision 1
      , osGeneration = Generation 1
      , osAttrs = Map.fromList
          [ (AttrClass, ValULong 4)
          , (AttrPrivate, ValBool False)
          ]
      , osOwner = Nothing
      , osSlot = SlotId 0
      }
  , mHandles = Map.singleton (ExternalHandle 3)
      (HandleBinding (ObjectId 9) (Generation 1))
  }

-- | Install actives with the real init planners (init must succeed).
mustInit :: SessionOps -> [InitArgs] -> SessionOps
mustInit ops args =
  let model = opsModel ops
      env = cancelEnv model
      go acc [] = acc
      go acc (a : rest) =
        let (acc', outcome) = initOperation env acc testSession a
        in case ioCode outcome of
          CKR_OK -> go acc' rest
          code -> error ("mustInit: init failed: " ++ show code)
  in go ops args

mustDual :: SessionOps
mustDual =
  let model = opsModel emptySessionOps
      env = cancelEnv model
      (ops, outcome) =
        initDualOperation env emptySessionOps testSession digestArgs encryptArgs
  in case ioCode outcome of
    CKR_OK -> ops
    code -> error ("mustDual: dual init failed: " ++ show code)

-- | Fake stream resource, as in OperationSpec: planner-level tests
-- bypass the init-alloc finish that records the real one.
streamRid :: EngineResourceId
streamRid = EngineResourceId 7

-- | Install a fake live (unfed) stream on the digest slot.
withDigestStream :: SessionOps -> SessionOps
withDigestStream ops = case lookupSingle ops SlotDigest of
  Just active -> case activeDigest active of
    Just sc -> insertOp
      (mkActiveDigest (setLive (DigestStream streamRid False) sc)) ops
    Nothing -> ops
  Nothing -> ops

cancelRequest :: Maybe SessionId -> ByteString -> Request
cancelRequest mSid input = Request
  { reqVersion = Pkcs11_3_2
  , reqFunction = F_SessionCancel
  , reqSession = mSid
  , reqHandle = Nothing
  , reqInput = input
  , reqRegions = []
  }

planCancel :: Model -> ByteString -> PlanResult
planCancel model input =
  planCall defaultRules model (cancelRequest (Just (SessionId 1)) input)

expectImmediate :: String -> PlanResult -> IO PreparedCommit
expectImmediate label result = case result of
  Immediate pc -> pure pc
  Reject rej -> do
    assertFailure (label ++ ": rejected: " ++ show (rejCode rej))
  Execute _ _ -> do
    assertFailure (label ++ ": unexpected Execute")

expectReject :: String -> ReturnCode -> PlanResult -> IO ()
expectReject label code result = case result of
  Reject rej -> assertEqual (label ++ ": code") code (rejCode rej)
  Immediate pc -> assertFailure (label ++ ": committed: " ++ show (pcCode pc))
  Execute _ _ -> assertFailure (label ++ ": unexpected Execute")

publishedOps :: Model -> PreparedCommit -> IO SessionOps
publishedOps model pc = case publishDelta model (pcDelta pc) of
  Left fault -> do
    assertFailure ("publish failed: " ++ show fault)
  Right model' -> case lookupSession model' (SessionId 1) of
    Nothing -> do
      assertFailure "session vanished after cancel"
    Just st -> pure (ssOps st)

caseCodecRoundTrip :: IO ()
caseCodecRoundTrip = do
  assertEqual "zero" (Just 0)
    (decodeCancelInput (encodeCancelInput 0))
  assertEqual "all-ops mask" (Just allOpFlags)
    (decodeCancelInput (encodeCancelInput allOpFlags))
  assertEqual "single bit" (Just ckfEncrypt)
    (decodeCancelInput (encodeCancelInput ckfEncrypt))
  assertEqual "maxBound" (Just (maxBound :: Word32))
    (decodeCancelInput (encodeCancelInput maxBound))
  assertEqual "encoding is 4 bytes" 4
    (BS.length (encodeCancelInput allOpFlags))

caseCodecMalformed :: IO ()
caseCodecMalformed = do
  assertEqual "3 bytes" Nothing (decodeCancelInput "abc")
  assertEqual "5 bytes" Nothing (decodeCancelInput "abcde")
  assertEqual "1 byte" Nothing (decodeCancelInput "a")

caseCancelAllEncrypt :: IO ()
caseCancelAllEncrypt = do
  let ops = mustInit emptySessionOps [encryptArgs]
      model = opsModel ops
  assertBool "encrypt active before cancel" (opsActive ops)
  pc <- expectImmediate "cancel-all" (planCancel model (encodeCancelInput 0))
  assertEqual "cancel code" CKR_OK (pcCode pc)
  ops' <- publishedOps model pc
  assertEqual "ops cleared" emptySessionOps ops'
  -- The MCT recovery proof: the session re-inits clean.
  let env = cancelEnv (opsModel ops')
      (_, outcome) = initOperation env ops' testSession encryptArgs
  assertEqual "re-init after cancel" CKR_OK (ioCode outcome)

caseCancelEmptyRefuses :: IO ()
caseCancelEmptyRefuses =
  expectReject "empty input" CKR_ARGUMENTS_BAD
    (planCancel (opsModel (mustInit emptySessionOps [encryptArgs])) BS.empty)

caseSelective :: IO ()
caseSelective = do
  let model = opsModel (mustInit emptySessionOps [encryptArgs, digestArgs])
  pc <- expectImmediate "selective encrypt"
    (planCancel model (encodeCancelInput ckfEncrypt))
  ops' <- publishedOps model pc
  assertEqual "only digest remains" [SlotDigest] (activeSlots ops')
  pc2 <- expectImmediate "selective digest"
    (planCancel model (encodeCancelInput ckfDigest))
  ops2 <- publishedOps model pc2
  assertEqual "only encrypt remains" [SlotEncrypt] (activeSlots ops2)

caseRecoverBits :: IO ()
caseRecoverBits = do
  let signModel = opsModel (mustInit emptySessionOps [signArgs])
  pc <- expectImmediate "sign-recover bit"
    (planCancel signModel (encodeCancelInput ckfSignRecover))
  ops' <- publishedOps signModel pc
  assertEqual "sign slot cleared by recover bit" emptySessionOps ops'
  let verifyModel = opsModel (mustInit emptySessionOps [verifyArgs])
  pc2 <- expectImmediate "verify-recover bit"
    (planCancel verifyModel (encodeCancelInput ckfVerifyRecover))
  ops2 <- publishedOps verifyModel pc2
  assertEqual "verify slot cleared by recover bit" emptySessionOps ops2

caseCancelDual :: IO ()
caseCancelDual = do
  assertBool "dual present" (hasDual mustDual)
  let model = opsModel mustDual
  -- A single-class mask drops the dual when it covers either side.
  pc <- expectImmediate "cancel digest side"
    (planCancel model (encodeCancelInput ckfDigest))
  ops' <- publishedOps model pc
  assertEqual "dual dropped" emptySessionOps ops'
  -- Cancel-all drops the dual plus a coexisting single.
  let model2 = opsModel (mustInit mustDual [decryptArgs])
  pc2 <- expectImmediate "cancel all with dual"
    (planCancel model2 (encodeCancelInput allOpFlags))
  ops2 <- publishedOps model2 pc2
  assertEqual "everything cleared" emptySessionOps ops2

caseCancelReleasesStream :: IO ()
caseCancelReleasesStream = do
  let model = opsModel (withDigestStream (mustInit emptySessionOps [digestArgs]))
  pc <- expectImmediate "cancel with live stream"
    (planCancel model (encodeCancelInput 0))
  assertEqual "stream released" [ReleaseEngineResource streamRid] (pcReleases pc)
  -- A selective cancel that spares the digest slot releases nothing.
  let model2 = opsModel
        (withDigestStream (mustInit emptySessionOps [digestArgs, encryptArgs]))
  pc2 <- expectImmediate "selective cancel spares stream"
    (planCancel model2 (encodeCancelInput ckfEncrypt))
  assertEqual "no release" [] (pcReleases pc2)

caseCancelIdle :: IO ()
caseCancelIdle = do
  let model = opsModel emptySessionOps
  pc <- expectImmediate "cancel idle" (planCancel model (encodeCancelInput 0))
  assertEqual "cancel code" CKR_OK (pcCode pc)
  assertEqual "no delta" (StateDelta []) (pcDelta pc)
  assertEqual "no releases" [] (pcReleases pc)

caseCancelUnknown :: IO ()
caseCancelUnknown = do
  let req = cancelRequest (Just (SessionId 999)) (encodeCancelInput 0)
  expectReject "unknown session" CKR_SESSION_HANDLE_INVALID
    (planCall defaultRules (opsModel emptySessionOps) req)
  let req2 = cancelRequest Nothing (encodeCancelInput 0)
  expectReject "missing session" CKR_SESSION_HANDLE_INVALID
    (planCall defaultRules (opsModel emptySessionOps) req2)

caseCancelMalformed :: IO ()
caseCancelMalformed =
  expectReject "malformed input" CKR_ARGUMENTS_BAD
    (planCancel (opsModel emptySessionOps) "abc")
