{- | Operation-layer routing tests.

Acceptance 1 (FIRST TEST): a 'F_DigestInit' request routed through
'planCall' persists a digest slot in the 'Model'; a second init on
the same session yields 'CKR_OPERATION_ACTIVE'. Companion cases
cover the init codec, the routed one-shot\/finish path, the init
matrix for every crypto family, exhaustiveness over 'FunctionId',
and the resource-identity/AAD drive-bys.
-}
{-# LANGUAGE OverloadedStrings #-}
module RoutingSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word32)
import Foreign.Ptr (castPtr, nullPtr)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend (BackendError (..))
import Haskoki.FFI.MessageParams (MsgParamError (..), decodeMessageParams)
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
  ( CryptoEffect (..)
  , DigestStream (..)
  , MsgFamily (..)
  , MsgState (..)
  , SlotKind (..)
  , activeDigest
  , activeSlots
  , bufferedOf
  , commonMech
  , lookupSingle
  , streamOf
  )
import Haskoki.Operation.Codec
  ( decodeInitInput
  , decodeMsgBegin
  , decodeMsgNext
  , decodeMsgOneShot
  , decodeVerifyInput
  , encodeInitInput
  , encodeMsgBegin
  , encodeMsgNext
  , encodeMsgOneShot
  , encodeVerifyInput
  )
import Haskoki.Operation.Message
  ( MsgBegin (..)
  , MsgNext (..)
  , MsgOneShot (..)
  , familyAad
  , lookupMessage
  )
import Haskoki.Outcome
  ( EffectRequest (..)
  , EngineResult (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , Reservation (..)
  , ResourceRelease (..)
  , RevisionDep (..)
  , StateDelta (..)
  )
import qualified Haskoki.Outcome as O
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  )
import Haskoki.Request
  ( FunctionId (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.Lifecycle (newEnv, publish, seatToken, snapshotModel)
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

spec :: TestTree
spec = testGroup "Operation routing"
  [ testCase "ACCEPTANCE 1: digest init persists; second init is ACTIVE" caseDigestInitPersists
  , testCase "digest init on unknown mechanism rejects cleanly" caseDigestInitBadMech
  , testCase "sign init routes; digest and sign coexist" caseSignInitRoutes
  , testCase "digest update streams through Execute" caseUpdateBuffers
  , testCase "one-shot without init rejects without mutation" caseOneShotNoInit
  , testCase "one-shot plans a crypto effect with pinned deps" caseOneShotPlans
  , testCase "finishEffect completes the one-shot with bytes" caseFinishCompletes
  , testCase "finishEffect rejects stale reservations" caseFinishStale
  , testCase "short one-shot stages; recall retries to bytes" caseDigestRetry
  , testCase "message short output recalls through retry" caseMessageRetry
  , testCase "init matrix: verify/cipher/message families" caseInitMatrix
  , testCase "every FunctionId routes (no crash, principled)" caseEveryFunctionRoutes
  , testCase "init codec round-trips; malformed rejects" caseInitCodec
  , testCase "verify/message codecs round-trip" caseDataCodecs
  , testCase "EngineResourceId is one Word32 type" caseUnifiedResourceId
  , testCase "Core owns the AAD family rule" caseAadRule
  , testCase "Env persists ops across calls via publish" caseEnvPersists
  , testCase "Digest update executes a feed effect" caseDigestUpdateExecutes
  , testCase "Digest final commit carries the release" caseDigestFinalReleases
  , testCase "Closing mid-stream releases the context" caseDigestAbortReleases
  , testCase "Stale alloc finish releases the orphan" caseStaleAllocReleases
  , testCase "Regionless final refuses without executing" caseRegionlessFinalRefuses
  , testCase "Feed failure releases the stream" caseFeedFailureReleases
  , testCase "Final failure releases the stream" caseFinalFailureReleases
  ]

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

sha256Mech, hmacMech, aesCbcMech :: MechanismId
sha256Mech = MechanismId 0x250
hmacMech = MechanismId 0x251
aesCbcMech = MechanismId 0x1082

aesCbcPadMech, aesEcbMech :: MechanismId
aesCbcPadMech = MechanismId 0x1085
aesEcbMech = MechanismId 0x1081

-- The remaining recipe-backed block ciphers (8-byte IV
-- for Triple-DES, 16 for ARIA/Camellia, empty for ECB).
des3CbcMech, des3EcbMech, ariaCbcMech, ariaEcbMech, camCbcMech, camEcbMech
  :: MechanismId
des3CbcMech = MechanismId 0x133
des3EcbMech = MechanismId 0x132
ariaCbcMech = MechanismId 0x562
ariaEcbMech = MechanismId 0x561
camCbcMech = MechanismId 0x552
camEcbMech = MechanismId 0x551

keyOid :: ObjectId
keyOid = ObjectId 7

keyHandle :: ExternalHandle
keyHandle = ExternalHandle 70

mkRequest :: FunctionId -> Maybe SessionId -> Request
mkRequest fid mSid = Request
  { reqVersion = Pkcs11_3_2
  , reqFunction = fid
  , reqSession = mSid
  , reqHandle = Nothing
  , reqInput = BS.empty
  , reqRegions = []
  }

openReq :: Request
openReq = (mkRequest F_OpenSession Nothing) { reqInput = "slot=0,rw" }

initReq :: FunctionId -> SessionId -> Maybe ExternalHandle -> ByteString -> Request
initReq fid sid mh blob =
  (mkRequest fid (Just sid)) { reqHandle = mh, reqInput = blob }

dataReq :: FunctionId -> SessionId -> String -> ByteString -> Word32 -> Request
dataReq fid sid name blob cap =
  (mkRequest fid (Just sid))
    { reqInput = blob
    , reqRegions = [RegionBytes name (IntentBuffer (fromIntegral cap))]
    }

-- | Model with a token in slot 0 and one open rw session (id 1).
openModel :: IO (SessionId, Model)
openModel = do
  let m0 = addToken emptyModel (SlotId 0)
  case planCall defaultRules m0 openReq of
    Immediate pc -> case publishDelta m0 (pcDelta pc) of
      Left fault -> assertFailure ("open delta fault: " ++ show fault)
      Right m1 -> pure (SessionId 1, m1)
    other -> assertFailure ("open failed to commit: " ++ show other)

-- | Seed one public visible key object bound to 'keyHandle'.
seedKey :: Model -> Model
seedKey m = m
  { mObjects = Map.insert keyOid ost (mObjects m)
  , mHandles = Map.insert keyHandle (HandleBinding keyOid (Generation 1)) (mHandles m)
  }
  where
    ost = ObjectState
      { osId = keyOid
      , osRevision = Revision 1
      , osGeneration = Generation 1
      , osAttrs = Map.fromList [(AttrClass, ValULong 4), (AttrPrivate, ValBool False)]
      , osOwner = Nothing
      , osSlot = SlotId 0
      }

runCommit :: Model -> Request -> IO Model
runCommit model req = case planCall defaultRules model req of
  Immediate pc -> case publishDelta model (pcDelta pc) of
    Left fault -> assertFailure ("delta fault: " ++ show fault)
    Right m' -> pure m'
  Reject rej -> assertFailure ("expected commit, rejected: " ++ show (rejCode rej))
  Execute _ _ -> assertFailure "expected commit, got Execute"

runRejectCode :: Model -> Request -> IO ReturnCode
runRejectCode model req = case planCall defaultRules model req of
  Reject rej -> pure (rejCode rej)
  Immediate pc -> assertFailure ("expected reject, committed: " ++ show (pcCode pc))
  Execute _ _ -> assertFailure "expected reject, got Execute"

opsOf :: Model -> SessionId -> IO SessionState
opsOf model sid = case lookupSession model sid of
  Nothing -> assertFailure "session missing" >> undefined
  Just st -> pure st

-- | Drive a digest init to completion with a fake allocated
-- resource; returns the committed model and the resource id.
runDigestInit :: Model -> Request -> IO (Model, EngineResourceId)
runDigestInit model req = case planCall defaultRules model req of
  Execute res (EffectCrypto (FxDigestInit _)) -> do
    let rid = EngineResourceId 11
    case finishEffect defaultRules model res (EngineOkResource rid) of
      Left rej -> assertFailure ("init finish rejected: " ++ show (rejCode rej))
      Right pc -> case publishDelta model (pcDelta pc) of
        Left fault -> assertFailure ("init fault: " ++ show fault)
        Right m' -> pure (m', rid)
  other -> assertFailure ("expected Execute alloc, got: " ++ show other)

-- | Drive one digest update feed to completion.
runDigestFeed :: Model -> SessionId -> ByteString -> IO Model
runDigestFeed model sid part = do
  let req = (mkRequest F_DigestUpdate (Just sid)) { reqInput = part }
  case planCall defaultRules model req of
    Execute res (EffectCrypto (FxDigestFeed _ fed)) -> do
      assertEqual "fed part" part fed
      case finishEffect defaultRules model res (EngineOkBytes BS.empty) of
        Left rej -> assertFailure ("feed rejected: " ++ show (rejCode rej))
        Right pc -> case publishDelta model (pcDelta pc) of
          Left fault -> assertFailure ("feed fault: " ++ show fault)
          Right m' -> pure m'
    other -> assertFailure ("expected Execute feed, got: " ++ show other)

-- ---------------------------------------------------------------------------
-- Cases
-- ---------------------------------------------------------------------------

caseDigestInitPersists :: IO ()
caseDigestInitPersists = do
  (sid, m0) <- openModel
  let req = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, rid) <- runDigestInit m0 req
  st1 <- opsOf m1 sid
  case lookupSingle (ssOps st1) SlotDigest of
    Just active -> case activeDigest active of
      Just sc -> do
        assertEqual "mechanism persisted" sha256Mech (commonMech sc)
        case streamOf sc of
          Just ds -> do
            assertEqual "stream resource recorded" rid (dsResource ds)
            assertBool "stream starts unfed" (not (dsFed ds))
          Nothing -> assertFailure "init recorded no stream"
      Nothing -> assertFailure ("expected active digest slot, got: " ++ show active)
    Nothing -> assertFailure "expected active digest slot, got: Nothing"
  code <- runRejectCode m1 req
  assertEqual "second init is ACTIVE" CKR_OPERATION_ACTIVE code

caseDigestInitBadMech :: IO ()
caseDigestInitBadMech = do
  (sid, m0) <- openModel
  let req = initReq F_DigestInit sid Nothing
        (encodeInitInput (MechanismId 0x999) [] False BS.empty)
  case planCall defaultRules m0 req of
    Reject rej -> do
      assertEqual "code" CKR_MECHANISM_INVALID (rejCode rej)
      assertEqual "no mutation" (StateDelta []) (rejDelta rej)
    other -> assertFailure ("expected Reject, got: " ++ show other)

caseSignInitRoutes :: IO ()
caseSignInitRoutes = do
  (sid, m0) <- openModel
  let mK = seedKey m0
      sReq = initReq F_SignInit sid (Just keyHandle)
        (encodeInitInput hmacMech [OpSign] False BS.empty)
      dReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  m1 <- runCommit mK sReq
  (m2, _) <- runDigestInit m1 dReq
  st2 <- opsOf m2 sid
  assertEqual "both slots active" [SlotDigest, SlotSign] (activeSlots (ssOps st2))
  code <- runRejectCode m2 sReq
  assertEqual "second sign init is ACTIVE" CKR_OPERATION_ACTIVE code

caseUpdateBuffers :: IO ()
caseUpdateBuffers = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, rid) <- runDigestInit m0 iReq
  m2 <- runDigestFeed m1 sid "abc"
  st2 <- opsOf m2 sid
  case lookupSingle (ssOps st2) SlotDigest of
    Just active -> case activeDigest active of
      Just sc -> do
        assertEqual "nothing buffered" BS.empty (bufferedOf sc)
        case streamOf sc of
          Just ds -> do
            assertEqual "same stream" rid (dsResource ds)
            assertBool "stream fed" (dsFed ds)
          Nothing -> assertFailure "feed lost the stream"
      Nothing -> assertFailure ("expected digest slot, got: " ++ show active)
    Nothing -> assertFailure "expected digest slot, got: Nothing"

-- | Updates execute backend feed effects instead
-- of committing buffered bytes immediately.
caseDigestUpdateExecutes :: IO ()
caseDigestUpdateExecutes = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, rid) <- runDigestInit m0 iReq
  let uReq = (mkRequest F_DigestUpdate (Just sid)) { reqInput = "abc" }
  case planCall defaultRules m1 uReq of
    Execute res (EffectCrypto (FxDigestFeed rid' part)) -> do
      assertEqual "feed names the stream" rid rid'
      assertEqual "feed carries the part" "abc" part
      case finishEffect defaultRules m1 res (EngineOkBytes BS.empty) of
        Left rej -> assertFailure ("feed rejected: " ++ show (rejCode rej))
        Right pc -> do
          assertEqual "feed commits clean" CKR_OK (pcCode pc)
          assertEqual "live feed releases nothing" [] (pcReleases pc)
    other -> assertFailure ("expected Execute feed, got: " ++ show other)

-- | The finished final commit carries the stream
-- release.
caseDigestFinalReleases :: IO ()
caseDigestFinalReleases = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, rid) <- runDigestInit m0 iReq
  m2 <- runDigestFeed m1 sid "abc"
  res <- case planCall defaultRules m2
      (dataReq F_DigestFinal sid "digest" BS.empty 64) of
    Execute r (EffectCrypto (FxDigestConsume rid')) -> do
      assertEqual "consume names the stream" rid rid'
      pure r
    other -> assertFailure ("expected Execute final, got: " ++ show other)
  case finishEffect defaultRules m2 res
      (EngineOkBytes (BS.replicate 32 0xAB)) of
    Right pc -> assertEqual "final carries the stream release"
      [ReleaseEngineResource rid] (pcReleases pc)
    Left rej -> assertFailure ("expected commit: " ++ show (rejCode rej))

-- | Guard: a regionless final refuses
-- @CKR_ARGUMENTS_BAD@ upstream (planRetryable's region check),
-- without planning or executing anything — the behavior the
-- packStep silent-step scope preserves. (The silent arm itself is
-- reachable only for digest updates; the white-box scope pin needs
-- the packStep export and arrives with it.)
caseRegionlessFinalRefuses :: IO ()
caseRegionlessFinalRefuses = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, _rid) <- runDigestInit m0 iReq
  case planCall defaultRules m1
      ((mkRequest F_DigestFinal (Just sid)) { reqInput = BS.empty }) of
    Reject rej -> assertEqual "refusal code" CKR_ARGUMENTS_BAD (rejCode rej)
    other -> assertFailure ("regionless final planned: " ++ show other)

-- | Closing a session with a live stream releases it.
caseDigestAbortReleases :: IO ()
caseDigestAbortReleases = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, rid) <- runDigestInit m0 iReq
  m2 <- runDigestFeed m1 sid "abc"
  case planCall defaultRules m2 (mkRequest F_CloseSession (Just sid)) of
    Immediate pc -> assertEqual "close carries the stream release"
      [ReleaseEngineResource rid] (pcReleases pc)
    other -> assertFailure ("expected Immediate close, got: " ++ show other)

-- | A resource answer whose reservation went stale is an
-- orphan that drains through the rejection instead of leaking.
caseStaleAllocReleases :: IO ()
caseStaleAllocReleases = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  res <- case planCall defaultRules m0 iReq of
    Execute r (EffectCrypto (FxDigestInit _)) -> pure r
    other -> assertFailure ("expected Execute alloc, got: " ++ show other)
  -- The session closes before the alloc lands: the finish goes
  -- stale and must release the orphan.
  m1 <- runCommit m0 (mkRequest F_CloseSession (Just sid))
  let rid = EngineResourceId 9
  case finishEffect defaultRules m1 res (EngineOkResource rid) of
    Left rej -> assertEqual "orphan released"
      [ReleaseEngineResource rid] (rejReleases rej)
    Right _ -> assertFailure "stale alloc committed"

-- | A failed feed finish rejects carrying the stream
-- release instead of leaking the live backend context.
caseFeedFailureReleases :: IO ()
caseFeedFailureReleases = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, rid) <- runDigestInit m0 iReq
  res <- case planCall defaultRules m1
      ((mkRequest F_DigestUpdate (Just sid)) { reqInput = "abc" }) of
    Execute r (EffectCrypto (FxDigestFeed rid' _)) -> do
      assertEqual "feed names the stream" rid rid'
      pure r
    other -> assertFailure ("expected Execute feed, got: " ++ show other)
  case finishEffect defaultRules m1 res
      (EngineFail (O.BackendNative "digestUpdate" 1 "EVP fail")) of
    Left rej -> assertEqual "feed failure releases the stream"
      [ReleaseEngineResource rid] (rejReleases rej)
    Right _ -> assertFailure "failed feed committed"

-- | A failed final finish rejects carrying the stream
-- release instead of leaking the live backend context.
caseFinalFailureReleases :: IO ()
caseFinalFailureReleases = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, rid) <- runDigestInit m0 iReq
  m2 <- runDigestFeed m1 sid "abc"
  res <- case planCall defaultRules m2
      (dataReq F_DigestFinal sid "digest" BS.empty 64) of
    Execute r (EffectCrypto (FxDigestConsume rid')) -> do
      assertEqual "consume names the stream" rid rid'
      pure r
    other -> assertFailure ("expected Execute final, got: " ++ show other)
  case finishEffect defaultRules m2 res
      (EngineFail (O.BackendNative "digestFinal" 1 "EVP fail")) of
    Left rej -> assertEqual "final failure releases the stream"
      [ReleaseEngineResource rid] (rejReleases rej)
    Right _ -> assertFailure "failed final committed"

caseOneShotNoInit :: IO ()
caseOneShotNoInit = do
  (sid, m0) <- openModel
  let req = dataReq F_Digest sid "digest" "hello" 64
  case planCall defaultRules m0 req of
    Reject rej -> do
      assertEqual "code" CKR_OPERATION_NOT_INITIALIZED (rejCode rej)
      assertEqual "no mutation" (StateDelta []) (rejDelta rej)
    other -> assertFailure ("expected Reject, got: " ++ show other)

caseOneShotPlans :: IO ()
caseOneShotPlans = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, _) <- runDigestInit m0 iReq
  st1 <- opsOf m1 sid
  let req = dataReq F_Digest sid "digest" "hello" 64
  case planCall defaultRules m1 req of
    Execute res eff -> do
      assertEqual "operation" "digest" (resOperation res)
      assertEqual "deps pinned"
        [DepSession sid (ssRevision st1) (ssGeneration st1)]
        (resDeps res)
      assertEqual "planned effect"
        (EffectCrypto (FxDigest sha256Mech "hello")) eff
    other -> assertFailure ("expected Execute, got: " ++ show other)

caseFinishCompletes :: IO ()
caseFinishCompletes = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, _) <- runDigestInit m0 iReq
  let req = dataReq F_Digest sid "digest" "hello" 64
  (res, m2) <- case planCall defaultRules m1 req of
    Execute r _ -> pure (r, m1)
    other -> assertFailure ("expected Execute, got: " ++ show other)
  let bytes = BS.replicate 32 0xAB
  case finishEffect defaultRules m2 res (EngineOkBytes bytes) of
    Right pc -> do
      assertEqual "code" CKR_OK (pcCode pc)
      assertEqual "outputs"
        [NativeOutput (RegionBytes "digest" (IntentBuffer 64)) bytes]
        (pcOutputs pc)
      case publishDelta m2 (pcDelta pc) of
        Left fault -> assertFailure ("commit fault: " ++ show fault)
        Right m3 -> do
          st3 <- opsOf m3 sid
          assertEqual "slot freed" [] (activeSlots (ssOps st3))
    Left rej -> assertFailure ("expected commit, rejected: " ++ show (rejCode rej))

caseFinishStale :: IO ()
caseFinishStale = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, _) <- runDigestInit m0 iReq
  let req = dataReq F_Digest sid "digest" "hello" 64
  res <- case planCall defaultRules m1 req of
    Execute r _ -> pure r
    other -> assertFailure ("expected Execute, got: " ++ show other)
  -- A concurrent update bumps the session revision: the one-shot
  -- reservation is now stale and must reject, never retry.
  m2 <- runDigestFeed m1 sid "x"
  case finishEffect defaultRules m2 res (EngineOkBytes "d") of
    Left rej -> assertBool "stale reason" (not (null (rejReasons rej)))
    Right _ -> assertFailure "stale reservation committed"

caseDigestRetry :: IO ()
caseDigestRetry = do
  (sid, m0) <- openModel
  let iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  (m1, _) <- runDigestInit m0 iReq
  let shortReq = dataReq F_Digest sid "digest" "abc" 8
  res <- case planCall defaultRules m1 shortReq of
    Execute r _ -> pure r
    other -> assertFailure ("expected Execute, got: " ++ show other)
  let bytes = BS.replicate 32 0xCD
  m2 <- case finishEffect defaultRules m1 res (EngineOkBytes bytes) of
    Right pc -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (pcCode pc)
      assertEqual "no outputs yet" [] (pcOutputs pc)
      case publishDelta m1 (pcDelta pc) of
        Left fault -> assertFailure ("commit fault: " ++ show fault)
        Right m' -> pure m'
    Left rej -> assertFailure ("expected commit: " ++ show (rejCode rej))
  st2 <- opsOf m2 sid
  assertEqual "slot kept" [SlotDigest] (activeSlots (ssOps st2))
  let recallReq = dataReq F_Digest sid "digest" BS.empty 64
  case planCall defaultRules m2 recallReq of
    Immediate pc -> do
      assertEqual "recall code" CKR_OK (pcCode pc)
      assertEqual "recalled bytes"
        [NativeOutput (RegionBytes "digest" (IntentBuffer 64)) bytes]
        (pcOutputs pc)
      case publishDelta m2 (pcDelta pc) of
        Left fault -> assertFailure ("recall fault: " ++ show fault)
        Right m3 -> do
          st3 <- opsOf m3 sid
          assertEqual "slot freed" [] (activeSlots (ssOps st3))
    other -> assertFailure ("expected Immediate recall, got: " ++ show other)

caseMessageRetry :: IO ()
caseMessageRetry = do
  (sid, m0) <- openModel
  let mK = seedKey m0
      iReq = initReq F_MessageEncryptInit sid (Just keyHandle)
        (encodeInitInput aesCbcMech [OpEncrypt] False (BS.replicate 16 0))
  m1 <- runCommit mK iReq
  let one = MsgOneShotCipher (BS.replicate 16 1) BS.empty "0123456789abcdef"
      shortReq = (mkRequest F_EncryptMessage (Just sid))
        { reqInput = encodeMsgOneShot one
        , reqRegions = [RegionBytes "cipher" (IntentBuffer 8)]
        }
  res <- case planCall defaultRules m1 shortReq of
    Execute r _ -> pure r
    other -> assertFailure ("expected Execute, got: " ++ show other)
  let ct = BS.replicate 16 0xEE
  m2 <- case finishEffect defaultRules m1 res (EngineOkBytes ct) of
    Right pc -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (pcCode pc)
      case publishDelta m1 (pcDelta pc) of
        Left fault -> assertFailure ("commit fault: " ++ show fault)
        Right m' -> pure m'
    Left rej -> assertFailure ("expected commit: " ++ show (rejCode rej))
  let recallReq = (mkRequest F_EncryptMessage (Just sid))
        { reqInput = encodeMsgOneShot one
        , reqRegions = [RegionBytes "cipher" (IntentBuffer 64)]
        }
  case planCall defaultRules m2 recallReq of
    Immediate pc -> do
      assertEqual "recall code" CKR_OK (pcCode pc)
      assertEqual "recalled bytes"
        [NativeOutput (RegionBytes "cipher" (IntentBuffer 64)) ct]
        (pcOutputs pc)
      case publishDelta m2 (pcDelta pc) of
        Left fault -> assertFailure ("recall fault: " ++ show fault)
        Right m3 -> do
          st3 <- opsOf m3 sid
          case lookupMessage (ssOps st3) SlotEncrypt of
            Just ms -> assertEqual "message counted" 1 (msMessages ms)
            Nothing -> assertFailure "outer context lost"
    other -> assertFailure ("expected Immediate recall, got: " ++ show other)

caseInitMatrix :: IO ()
caseInitMatrix = mapM_ check
  [ (F_VerifyInit, hmacMech, [OpVerify], BS.empty, SlotVerify)
  , (F_EncryptInit, aesCbcMech, [OpEncrypt], BS.replicate 16 0, SlotEncrypt)
  , (F_DecryptInit, aesCbcMech, [OpDecrypt], BS.replicate 16 0, SlotDecrypt)
  -- PAD shares the CBC shape (planner pads); ECB is the
  -- unpadded shape with empty params.
  , (F_EncryptInit, aesCbcPadMech, [OpEncrypt], BS.replicate 16 0, SlotEncrypt)
  , (F_DecryptInit, aesCbcPadMech, [OpDecrypt], BS.replicate 16 0, SlotDecrypt)
  , (F_EncryptInit, aesEcbMech, [OpEncrypt], BS.empty, SlotEncrypt)
  , (F_DecryptInit, aesEcbMech, [OpDecrypt], BS.empty, SlotDecrypt)
  , (F_EncryptInit, des3CbcMech, [OpEncrypt], BS.replicate 8 0, SlotEncrypt)
  , (F_DecryptInit, des3CbcMech, [OpDecrypt], BS.replicate 8 0, SlotDecrypt)
  , (F_EncryptInit, des3EcbMech, [OpEncrypt], BS.empty, SlotEncrypt)
  , (F_DecryptInit, des3EcbMech, [OpDecrypt], BS.empty, SlotDecrypt)
  , (F_EncryptInit, ariaCbcMech, [OpEncrypt], BS.replicate 16 0, SlotEncrypt)
  , (F_DecryptInit, ariaCbcMech, [OpDecrypt], BS.replicate 16 0, SlotDecrypt)
  , (F_EncryptInit, ariaEcbMech, [OpEncrypt], BS.empty, SlotEncrypt)
  , (F_DecryptInit, ariaEcbMech, [OpDecrypt], BS.empty, SlotDecrypt)
  , (F_EncryptInit, camCbcMech, [OpEncrypt], BS.replicate 16 0, SlotEncrypt)
  , (F_DecryptInit, camCbcMech, [OpDecrypt], BS.replicate 16 0, SlotDecrypt)
  , (F_EncryptInit, camEcbMech, [OpEncrypt], BS.empty, SlotEncrypt)
  , (F_DecryptInit, camEcbMech, [OpDecrypt], BS.empty, SlotDecrypt)
  , (F_MessageEncryptInit, aesCbcMech, [OpEncrypt], BS.replicate 16 0, SlotEncrypt)
  , (F_MessageDecryptInit, aesCbcMech, [OpDecrypt], BS.replicate 16 0, SlotDecrypt)
  , (F_MessageSignInit, hmacMech, [OpSign], BS.empty, SlotSign)
  , (F_MessageVerifyInit, hmacMech, [OpVerify], BS.empty, SlotVerify)
  ]
  where
    check (fid, mech, permits, params, kind) = do
      (sid, m0) <- openModel
      let req = initReq fid sid (Just keyHandle)
            (encodeInitInput mech permits False params)
      m1 <- runCommit (seedKey m0) req
      st1 <- opsOf m1 sid
      assertBool (show fid ++ " active") (kind `elem` activeSlots (ssOps st1))
      code <- runRejectCode m1 req
      assertEqual (show fid ++ " second init ACTIVE") CKR_OPERATION_ACTIVE code

caseEveryFunctionRoutes :: IO ()
caseEveryFunctionRoutes = mapM_ check [minBound .. maxBound]
  where
    check :: FunctionId -> IO ()
    check fid = case fid of
      F_GetInfo -> expectImmediate fid
      F_GetSlotList -> expectImmediate fid
      F_OpenSession -> case planCall defaultRules emptyModel openReq of
        Reject rej -> assertEqual "open without token" CKR_TOKEN_NOT_PRESENT (rejCode rej)
        other -> assertFailure ("open misrouted: " ++ show other)
      _ -> case planCall defaultRules emptyModel (mkRequest fid Nothing) of
        Reject rej -> assertEqual (show fid ++ " needs session")
          CKR_SESSION_HANDLE_INVALID (rejCode rej)
        other -> assertFailure (show fid ++ " misrouted: " ++ show other)
    expectImmediate fid = case planCall defaultRules emptyModel (mkRequest fid Nothing) of
      Immediate _ -> pure ()
      other -> assertFailure (show fid ++ " misrouted: " ++ show other)

caseInitCodec :: IO ()
caseInitCodec = do
  let blob = encodeInitInput aesCbcMech [OpEncrypt, OpDecrypt] True "params-iv-16...."
  assertEqual "round-trip"
    (Just (aesCbcMech, [OpEncrypt, OpDecrypt], True, "params-iv-16...."))
    (decodeInitInput blob)
  assertEqual "empty params"
    (Just (sha256Mech, [], False, BS.empty))
    (decodeInitInput (encodeInitInput sha256Mech [] False BS.empty))
  mapM_ (assertEqual "malformed" Nothing . decodeInitInput)
    [ BS.empty
    , BS.pack [0, 0, 0, 0, 0, 0, 2, 0x50]
    , BS.pack [0, 0, 0, 0, 0, 0, 2, 0x50, 0xFF, 0xFF, 0]
    ]

caseDataCodecs :: IO ()
caseDataCodecs = do
  assertEqual "verify round-trip"
    (Just ("data", "sig")) (decodeVerifyInput (encodeVerifyInput "data" "sig"))
  assertEqual "verify malformed" Nothing (decodeVerifyInput "xx")
  let begin = MsgBegin "nonce" "aad"
  assertEqual "begin round-trip" (Just begin)
    (decodeMsgBegin (encodeMsgBegin begin))
  let next = MsgNextCipher "p" "part" True
  assertEqual "cipher-next round-trip" (Just next)
    (decodeMsgNext MsgEncrypt (encodeMsgNext next))
  let vnext = MsgNextVerify "p" "part" (Just "wit")
  assertEqual "verify-next round-trip" (Just vnext)
    (decodeMsgNext MsgVerify (encodeMsgNext vnext))
  let one = MsgOneShotCipher "p" "aad" "input"
  assertEqual "one-shot round-trip" (Just one)
    (decodeMsgOneShot MsgEncrypt (encodeMsgOneShot one))
  let vs = MsgOneShotVerify "p" "input" "wit"
  assertEqual "verify one-shot round-trip" (Just vs)
    (decodeMsgOneShot MsgVerify (encodeMsgOneShot vs))
  assertEqual "wrong family" Nothing
    (decodeMsgNext MsgSign (encodeMsgNext next))

caseUnifiedResourceId :: IO ()
caseUnifiedResourceId = do
  assertEqual "word32 width"
    (maxBound :: Word32)
    (unEngineResourceId (EngineResourceId maxBound))
  -- The Types constructor feeds the Backend failure directly: one type.
  let _f = BackendResourceGone "t" (EngineResourceId 9)
  assertEqual "shared ctor" (EngineResourceId 9) (EngineResourceId 9)

caseAadRule :: IO ()
caseAadRule = do
  assertEqual "table"
    [(MsgEncrypt, True), (MsgDecrypt, True), (MsgSign, False), (MsgVerify, False)]
    [(fam, familyAad fam) | fam <- [minBound .. maxBound]]
  BS.useAsCStringLen "aad" $ \(aPtr, aLen) -> do
    let aW = castPtr aPtr
        n = fromIntegral aLen
    enc <- decodeMessageParams MsgEncrypt nullPtr 0 aW n
    case enc of
      Right _ -> pure ()
      Left err -> assertFailure ("cipher must bind aad: " ++ show err)
    sgn <- decodeMessageParams MsgSign nullPtr 0 aW n
    assertEqual "sign rejects aad" (Left MsgParamAadRejected) sgn
    vfy <- decodeMessageParams MsgVerify nullPtr 0 aW n
    assertEqual "verify rejects aad" (Left MsgParamAadRejected) vfy

caseEnvPersists :: IO ()
caseEnvPersists = do
  env <- newEnv defaultRules
  seatToken env (SlotId 0) >>= assertEqual "seat ok" (Right ())
  m0 <- snapshotModel env
  m1 <- runCommit m0 openReq
  _ <- publish env (StateDelta [])
  _ <- publishCommit env m0 openReq
  m2 <- snapshotModel env
  let sid = SessionId 1
      iReq = initReq F_DigestInit sid Nothing
        (encodeInitInput sha256Mech [] False BS.empty)
  case planCall defaultRules m2 iReq of
    Execute res (EffectCrypto (FxDigestInit _)) ->
      case finishEffect defaultRules m2 res
          (EngineOkResource (EngineResourceId 17)) of
        Left rej -> assertFailure ("init rejected: " ++ show (rejCode rej))
        Right pc -> do
          r <- publish env (pcDelta pc)
          case r of
            Left fault -> assertFailure ("publish fault: " ++ show fault)
            Right () -> pure ()
    other -> assertFailure ("expected Execute alloc, got: " ++ show other)
  m3 <- snapshotModel env
  st3 <- opsOf m3 sid
  case lookupSingle (ssOps st3) SlotDigest of
    Just active -> case activeDigest active of
      Just sc -> case streamOf sc of
        Just _ -> pure ()
        Nothing -> assertFailure "stream did not persist"
      Nothing -> assertFailure ("ops did not persist: " ++ show active)
    Nothing -> assertFailure "ops did not persist: Nothing"
  code <- runRejectCode m3
    (initReq F_DigestInit sid Nothing (encodeInitInput sha256Mech [] False BS.empty))
  assertEqual "second init ACTIVE via Env" CKR_OPERATION_ACTIVE code
  _ <- pure m1
  pure ()
  where
    publishCommit env model req = case planCall defaultRules model req of
      Immediate pc -> do
        r <- publish env (pcDelta pc)
        case r of
          Left fault -> assertFailure ("publish fault: " ++ show fault)
          Right () -> snapshotModel env
      other -> assertFailure ("expected commit, got: " ++ show other)
