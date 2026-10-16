{- | Model transition tests: missing sessions, error outcomes with
required effects, and generated sequence tests for handle separation
and delta consistency.

Deterministic: the sequence generator is an inline LCG (no new test
dependencies), so the same seed always yields the same cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module TransitionSpec (spec) where

import qualified Data.ByteString as BS
import Data.Either (isRight)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust)
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.CallWork
  ( CallFamily (..)
  , WorkMismatch (..)
  , callFunctionEffect
  , callFunctionFamily
  , callFunctionSlot
  , callWorkEffect
  , callWorkReservation
  , callWorkSession
  , checkedCallWork
  , mkFixtureCallWork
  )
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , addToken
  , emptyModel
  , lookupObject
  , lookupSession
  , lookupTokenAuth
  )
import Haskoki.Operation
  ( CipherDir (..)
  , CipherSpec (..)
  , CryptoEffect (..)
  , CryptoResult (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , MsgFamily (..)
  , OpAuth (..)
  , OpEnv (..)
  , RecoverRole (..)
  , RecoverSpec (..)
  , SessionOps
  , SlotKind (..)
  , StepOutcome (..)
  , emptySessionOps
  , initMessageOperation
  , initOperation
  , insertOp
  , mkActiveCipher
  , mkActiveRecover
  , mkActiveSign
  , mkActiveVerify
  , mkSlotCommon
  )
import Haskoki.Operation.Cipher (planCipherFinal, planCipherOneShot, planCipherUpdate)
import Haskoki.Operation.Message
  ( MsgBegin (..)
  , MsgNext (..)
  , MsgOneShot (..)
  , planMessageBegin
  , planMessageNext
  , planMessageOneShot
  )
import Haskoki.Operation.Signature
  ( planSignFinal
  , planSignOneShot
  , planSignRecoverOneShot
  , planSignUpdate
  , planVerifyFinal
  , planVerifyOneShot
  , planVerifyRecoverOneShot
  , planVerifyUpdate
  )
import Haskoki.Outcome
  ( CryptoStep (..)
  , DeltaOp (..)
  , EffectRequest (..)
  , EngineResult (..)
  , BackendFailure (..)
  , ModelFault (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , Reservation (..)
  , ResourceRelease (..)
  , RevisionDep (..)
  , StateDelta (..)
  )
import Haskoki.Request
  ( DecodedRequest (..)
  , FunctionId (..)
  , InitFunction (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  )
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..), TokenAuth (..), tokenAuthNew)
import Haskoki.Transition
  ( finishEffect
  , packStep
  , planCall
  , planDecoded
  , publishDelta
  , runFinisher
  )
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
spec = testGroup "model transitions"
  [ testCase "missing session rejects with no output and no mutation" caseMissingSession
  , testCase "known session plans digest execution" caseKnownSession
  , testCase "error outcome carries required effects" caseErrorWithEffects
  , testCase "stale reservation rejects without retry" caseStaleReservation
  , testCase "legacy resource finish carries its release" caseLegacyResourceRelease
  , testCase "silent step scoped to digest streaming" caseSilentStepScope
  , testCase "regionless foreign effect refuses" caseSilentStepRefuses
  , testCase "stale context grant dies with its operation" caseStaleGrantInvalidated
  , testCase "live pending operation keeps its grant" caseGrantPreserved
  , testCase "generated: delta split-application equivalence" caseDeltaSplit
  , testCase "generated: session/object namespaces stay separate" caseNamespaces
  , testCase "generated: unknown destroy reports exact fault" caseUnknownDestroy
  , testCase "unbind retains parked object and allocation counters" caseUnbindHandle
  , testCase "runFinisher finishing-leg set is pinned" caseFinisherCoverage
  , testCase "call-work slot table matches the finisher legs" caseCallSlotPin
  , testCase "call-work effect matrix refuses cross-family pairs" caseCallEffectMatrix
  , testCase "legacy unstepped pairs pin the checked/fixture split" caseCallLegacySplit
  , testCase "planned digest dialogue checks coherently" caseCoherentDigest
  , testCase "planned sign dialogue checks coherently" caseCoherentSign
  , testCase "seeded planner emissions check coherently" caseCoherentEmissions
  , testCase "seeded message emissions check coherently" caseCoherentMessage
  , testCase "reinit refused on a bad SO verdict preserves everything" caseInitTokenDeniedPreserves
  , testCase "reinit granted on a good SO verdict resets its own token" caseInitTokenAuthorizedResets
  , testCase "first init without a verdict grants" caseInitTokenFirstInitGrants
  , testCase "init-token argument shape refuses junk" caseInitTokenArgsShape
  , testCase "locked SO: refusal preserves the lock, grant clears it" caseInitTokenLockedSo
  , testCase "fixture constructor admits unstepped triples explicitly" caseFixtureConstructsUnstepped
  , testCase "outer family table is pinned" caseFamilyTablePinned
  ]

caseUnbindHandle :: IO ()
caseUnbindHandle = do
  let oid = ObjectId 42
      handle = ExternalHandle 17
      seeded = publishDelta emptyModel (StateDelta [DeltaCreateObject oid, DeltaBindHandle handle oid])
  case seeded of
    Left fault -> assertBool (show fault) False
    Right before -> do
      let removed = publishDelta before (StateDelta [DeltaUnbindHandle handle, DeltaUnbindHandle handle])
      case removed of
        Left fault -> assertBool (show fault) False
        Right after -> do
          assertEqual "no binding survives" Map.empty (mHandles after)
          assertEqual "parked record retained" (mObjects before) (mObjects after)
          assertEqual "counter never recycled" (mNextHandle before) (mNextHandle after)
      assertEqual "later fault aborts the entire delta" (Left (FaultUnknownSession (SessionId 999)))
        (publishDelta before (StateDelta [DeltaUnbindHandle handle, DeltaCloseSession (SessionId 999)]))

-- | The exact 'FunctionId's with a finishing leg: in
-- declaration order, as produced by the coverage sweep. A new
-- constructor fails validation at compile time
-- (-Werror=incomplete-patterns over the exhaustive 'runFinisher');
-- this pin catches an arm silently flipped between Just/Nothing.
finisherJustSet :: [FunctionId]
finisherJustSet =
  [ F_DigestInit
  , F_Digest
  , F_Sign
  , F_DigestUpdate
  , F_DigestFinal
  , F_SignFinal
  , F_Verify
  , F_VerifyFinal
  , F_Encrypt
  , F_EncryptUpdate
  , F_EncryptFinal
  , F_Decrypt
  , F_DecryptUpdate
  , F_DecryptFinal
  , F_EncryptMessage
  , F_DecryptMessage
  , F_SignMessage
  , F_VerifyMessage
  , F_EncryptMessageNext
  , F_DecryptMessageNext
  , F_SignMessageNext
  , F_VerifyMessageNext
  , F_SignRecover
  , F_VerifyRecover
  ]

-- | A quiescent probe step: finishers answer deny outcomes on the
-- empty op set, so the sweep observes arm presence, never behavior.
finisherProbeStep :: FunctionId -> CryptoStep
finisherProbeStep fid = CryptoStep
  { csFunction = fid
  , csKind = SlotDigest
  , csName = ""
  , csIntent = IntentNull
  , csOps = emptySessionOps
  , csSession = SessionState
      { ssId = SessionId 1
      , ssSlot = SlotId 0
      , ssRevision = Revision 1
      , ssGeneration = Generation 1
      , ssReadOnly = False
      , ssLogin = LoginPublic
      , ssOps = emptySessionOps
      }
  }

caseFinisherCoverage :: IO ()
caseFinisherCoverage =
  assertEqual "finisher Just-set" finisherJustSet
    [ fid | fid <- [minBound .. maxBound]
          , isJust (runFinisher (finisherProbeStep fid) GotUnit) ]

-- | A request skeleton for session-scoped digest calls.
digestRequest :: Maybe SessionId -> Request
digestRequest mSid = Request
  { reqVersion = Pkcs11_3_2
  , reqFunction = F_Digest
  , reqSession = mSid
  , reqHandle = Nothing
  , reqInput = mempty
  , reqRegions =
      [ RegionBytes "digest" (IntentBuffer 64)
      ]
  }

-- | A model holding exactly one session (id 1, revision 1, gen 1).
oneSessionModel :: Model
oneSessionModel = emptyModel
  { mSessions = Map.singleton (SessionId 1) SessionState
      { ssId = SessionId 1
      , ssSlot = SlotId 0
      , ssRevision = Revision 1
      , ssGeneration = Generation 1
      , ssReadOnly = False
      , ssLogin = LoginPublic
      , ssOps = emptySessionOps
      }
  }

-- | The one-session model with a live digest operation, built by the
-- real init planner (no revision movement: the ops are installed
-- without publication).
digestActiveModel :: Model
digestActiveModel = case Map.lookup (SessionId 1) (mSessions oneSessionModel) of
  Nothing -> error "digestActiveModel: session 1 missing"
  Just st0 ->
    let env = OpEnv curatedRegistry
          (mkCapabilities [(MechanismId 0x250, OpDigest)])
          oneSessionModel
        (ops, _) = initOperation env emptySessionOps st0
          (InitArgs OpDigest (MechanismId 0x250) mempty Nothing Nothing Nothing)
        st1 = st0 { ssOps = ops }
    in oneSessionModel { mSessions = Map.singleton (SessionId 1) st1 }

caseMissingSession :: IO ()
caseMissingSession = do
  mapM_ check [Nothing, Just (SessionId 9)]
  where
    check :: Maybe SessionId -> IO ()
    check mSid = do
      let plan = planCall defaultRules emptyModel (digestRequest mSid)
      case plan of
        Reject rej -> do
          assertEqual "code" CKR_SESSION_HANDLE_INVALID (rejCode rej)
          assertEqual "no outputs" [] (rejOutputs rej)
          assertEqual "no delta" (StateDelta []) (rejDelta rej)
          assertBool "reason present" (not (null (rejReasons rej)))
        other -> fail ("expected Reject, got: " ++ show other)

caseKnownSession :: IO ()
caseKnownSession = do
  -- The routed arm denies without an active operation ...
  let denied = planCall defaultRules oneSessionModel (digestRequest (Just (SessionId 1)))
  case denied of
    Reject rej -> assertEqual "code" CKR_OPERATION_NOT_INITIALIZED (rejCode rej)
    other -> fail ("expected Reject, got: " ++ show other)
  -- ... and executes with pinned deps once the slot is live. The
  -- reservation shape is unchanged from the probe contract.
  let plan = planCall defaultRules digestActiveModel (digestRequest (Just (SessionId 1)))
  case plan of
    Execute res _eff -> do
      assertEqual "operation" "digest" (resOperation res)
      assertEqual "deps"
        [DepSession (SessionId 1) (Revision 1) (Generation 1)]
        (resDeps res)
    other -> fail ("expected Execute, got: " ++ show other)

caseErrorWithEffects :: IO ()
caseErrorWithEffects = do
  -- A modeled error that changes operation disposition: finishEffect on
  -- a backend failure yields a rejection (not a commit) that still
  -- carries diagnostic reasons.
  let res = Reservation "digest" [] Nothing Nothing
      result = EngineFail (BackendBadParam "digest" "bad mechanism")
  case finishEffect defaultRules oneSessionModel res result of
    Left rej -> do
      assertEqual "code" CKR_GENERAL_ERROR (rejCode rej)
      assertBool "reasons present" (not (null (rejReasons rej)))
    Right pc -> fail ("expected rejection, got commit: " ++ show (pcCode pc))
  -- The outcome representation carries an error AND required effects:
  -- a rejection with outputs plus a publishable delta.
  let rej = Rejection
        { rejCode = CKR_BUFFER_TOO_SMALL
        , rejOutputs = [NativeOutput (RegionBytes "part" IntentNull) "partial"]
        , rejDelta = StateDelta [DeltaBumpGeneration (SessionId 1) (Generation 2)]
        , rejReleases = []
        , rejReasons = ["partial attribute-style result"]
        }
  assertBool "outputs carried" (not (null (rejOutputs rej)))
  case publishDelta oneSessionModel (rejDelta rej) of
    Left fault -> fail ("delta should apply: " ++ show fault)
    Right m' ->
      assertBool "delta applied" (mSessions m' /= mSessions oneSessionModel)

caseStaleReservation :: IO ()
caseStaleReservation = do
  let res = Reservation "digest"
        [DepSession (SessionId 1) (Revision 1) (Generation 99)] Nothing Nothing
  case finishEffect defaultRules oneSessionModel res (EngineOkBytes "x") of
    Left rej -> assertEqual "code" CKR_GENERAL_ERROR (rejCode rej)
    Right _ -> fail "stale reservation must not commit"

-- | The legacy branch (an unstepped reservation answered with a
-- resource) attaches the rid instead of dropping it (previously
-- @pcReleases@ stayed @[]@ here).
caseLegacyResourceRelease :: IO ()
caseLegacyResourceRelease = do
  let res = Reservation "legacy" [] Nothing Nothing
      rid = EngineResourceId 7
  case finishEffect defaultRules oneSessionModel res (EngineOkResource rid) of
    Right pc -> assertEqual "release carried"
      [ReleaseEngineResource rid] (pcReleases pc)
    Left rej -> fail ("expected commit, got rejection: " ++ show (rejCode rej))

-- | The packStep silent arm executes for digest
-- streaming shapes (white-box: the arm is reachable only for
-- digest updates through 'planCall', by construction).
caseSilentStepScope :: IO ()
caseSilentStepScope = do
  st <- silentState
  case packStep (silentReq F_DigestUpdate) st SlotDigest
      emptySessionOps st silentOutcome of
    Execute _ _ -> pure ()
    other -> fail ("digest silent step must execute: " ++ show other)

-- | A regionless single effect for any other function
-- refuses @CKR_ARGUMENTS_BAD@ instead of silently executing.
caseSilentStepRefuses :: IO ()
caseSilentStepRefuses = do
  st <- silentState
  case packStep (silentReq F_SignUpdate) st SlotSign
      emptySessionOps st silentOutcome of
    Reject rej -> assertEqual "refusal code" CKR_ARGUMENTS_BAD (rejCode rej)
    other -> fail ("foreign silent step must refuse: " ++ show other)

silentState :: IO SessionState
silentState = case lookupSession oneSessionModel (SessionId 1) of
  Just st -> pure st
  Nothing -> fail "session 1 missing"

silentReq :: FunctionId -> Request
silentReq fun = Request Pkcs11_3_2 fun (Just (SessionId 1)) Nothing
  "part" []

silentOutcome :: StepOutcome
silentOutcome = StepOutcome CKR_OK
  [FxDigestFeed (EngineResourceId 3) "part"] Nothing [] [] Nothing

-- | A sign slot awaiting its context-specific authentication: the
-- eligible shape a grant binds to.
pendingSignOps :: SessionOps
pendingSignOps = insertOp
  (mkActiveSign
    (mkSlotCommon (MechanismId 0x251) OpSign (Just (ObjectId 9)) mempty AuthPending))
  emptySessionOps

-- | The one-session model holding a context grant for the pending
-- sign slot above.
grantedSession :: SessionState
grantedSession = case lookupSession oneSessionModel (SessionId 1) of
  Just st -> st { ssLogin = LoginContextUser, ssOps = pendingSignOps }
  Nothing -> error "grantedSession: session 1 missing"

-- | A data call that terminates the granted operation without
-- spending the grant (a pre-gate refusal) must not strand a
-- spendable grant: packing drops the session back to a plain user
-- login on both the rejection and the commit path.
caseStaleGrantInvalidated :: IO ()
caseStaleGrantInvalidated = do
  let st = grantedSession
      stStale = st { ssOps = emptySessionOps }
      req = digestRequest (Just (SessionId 1))
      want = StateDelta
        [ DeltaSetSessionOps (SessionId 1) emptySessionOps
        , DeltaSetSessionLogin (SessionId 1) LoginUser
        ]
      denied = StepOutcome CKR_OPERATION_NOT_INITIALIZED [] Nothing ["terminated"] [] Nothing
  case packStep req st SlotSign emptySessionOps stStale denied of
    Reject rej -> assertEqual "stale grant dies with its slot" want (rejDelta rej)
    other -> fail ("expected Reject, got: " ++ show other)
  -- The committed twin (a slot freed with CKR_OK, as a finalizer
  -- does): the same login delta rides along.
  let freed = StepOutcome CKR_OK [] Nothing ["freed"] [] Nothing
  case packStep req st SlotSign emptySessionOps stStale freed of
    Immediate pc -> assertEqual "stale grant dies on commit too" want (pcDelta pc)
    other -> fail ("expected Immediate, got: " ++ show other)

-- | A grant whose pending operation survives the step is untouched:
-- a premature denial on another slot carries an empty delta.
caseGrantPreserved :: IO ()
caseGrantPreserved = do
  let st = grantedSession
      req = digestRequest (Just (SessionId 1))
      denied = StepOutcome CKR_USER_NOT_LOGGED_IN [] Nothing ["premature"] [] Nothing
  case packStep req st SlotDigest (ssOps st) st denied of
    Reject rej -> assertEqual "live grant survives premature use"
      (StateDelta []) (rejDelta rej)
    other -> fail ("expected Reject, got: " ++ show other)

-- ---------------------------------------------------------------------------
-- Deterministic sequence generator (inline LCG; fixed seeds)
-- ---------------------------------------------------------------------------

-- | Next LCG value (Numerical Recipes constants; determinism is the
-- only requirement).
lcgNext :: Word64 -> Word64
lcgNext s = s * 6364136223846793005 + 1442695040888963407

-- | One delta op drawn from the generator state over a small id space.
genOp :: Word64 -> (DeltaOp, Word64)
genOp s0 =
  let s1 = lcgNext s0
      s2 = lcgNext s1
      pick = fromIntegral (s1 `mod` 5) :: Int
      sid = SessionId (1 + fromIntegral (s2 `mod` 3))
      oid = ObjectId (1 + fromIntegral (s2 `mod` 5))
      gen = Generation (1 + fromIntegral ((s2 `div` 7) `mod` 4))
  in case pick of
    0 -> (DeltaTouchSession sid, s2)
    1 -> (DeltaCloseSession sid, s2)
    2 -> (DeltaBumpGeneration sid gen, s2)
    3 -> (DeltaCreateObject oid, s2)
    _ -> (DeltaDestroyObject oid, s2)

-- | A deterministic op sequence of the requested length from a seed.
genSeq :: Word64 -> Int -> [DeltaOp]
genSeq seed n = go seed n []
  where
    go :: Word64 -> Int -> [DeltaOp] -> [DeltaOp]
    go _ 0 acc = reverse acc
    go s k acc = let (op, s') = genOp s in go s' (k - 1) (op : acc)

-- | Seed corpus: fixed seeds, fixed lengths.
corpus :: [(Word64, Int)]
corpus = [(seed, len) | seed <- [1 .. 40], len <- [1, 5, 12]]

-- | Split-application equivalence: publishing a++b at once equals
-- publishing a then b, whenever both orders succeed.
caseDeltaSplit :: IO ()
caseDeltaSplit = mapM_ check corpus
  where
    check :: (Word64, Int) -> IO ()
    check (seed, len) = do
      let ops = genSeq seed len
          (a, b) = splitAt (len `div` 2) ops
          whole = publishDelta emptyModel (StateDelta ops)
          split = publishDelta emptyModel (StateDelta a) >>= \m -> publishDelta m (StateDelta b)
      assertEqual ("split equivalence seed=" ++ show seed ++ " len=" ++ show len) whole split

-- | Namespace separation: session ops never create/destroy objects and
-- object ops never touch sessions.
caseNamespaces :: IO ()
caseNamespaces = mapM_ check corpus
  where
    check :: (Word64, Int) -> IO ()
    check (seed, len) = do
      let ops = genSeq seed len
          sessionOnly = [op | op <- ops, isSessionOp op]
          objectOnly = [op | op <- ops, not (isSessionOp op)]
      case publishDelta emptyModel (StateDelta sessionOnly) of
        Left _ -> pure ()
        Right m -> assertEqual "session ops leave objects empty"
          Map.empty (mObjects m :: Map ObjectId ObjectState)
      case publishDelta emptyModel (StateDelta objectOnly) of
        Left _ -> pure ()
        Right m -> assertEqual "object ops leave sessions empty"
          Map.empty (mSessions m :: Map SessionId SessionState)
    isSessionOp :: DeltaOp -> Bool
    isSessionOp op = case op of
      DeltaCreateObject _ -> False
      DeltaDestroyObject _ -> False
      _ -> True

-- | Fault atomicity: a failing delta reports the exact fault and
-- leaves the model unchanged. Prefixes use create-only ops (which
-- cannot fault), so the appended destroy is the single fault point.
caseUnknownDestroy :: IO ()
caseUnknownDestroy = mapM_ check [0 .. 20]
  where
    check :: Int -> IO ()
    check k = do
      let prefix = [DeltaCreateObject (ObjectId i) | i <- [1 .. k]]
          ops = prefix ++ [DeltaDestroyObject (ObjectId 9999)]
      case publishDelta emptyModel (StateDelta ops) of
        Left (FaultUnknownObject (ObjectId 9999)) -> pure ()
        Left fault -> fail ("wrong fault: " ++ show fault)
        Right _ -> fail "destroy of unknown object must fault"
      -- And the prefix alone applies cleanly.
      case publishDelta emptyModel (StateDelta prefix) of
        Left fault -> fail ("clean prefix faulted: " ++ show fault)
        Right m -> assertEqual "prefix creates k objects" k (Map.size (mObjects m))

-- ---------------------------------------------------------------------------
-- Checked call-work construction (H1)
-- ---------------------------------------------------------------------------

h1Sid, h1SidOther :: SessionId
h1Sid = SessionId 1
h1SidOther = SessionId 2

sha256Mech, hmacMech, aesCbcMech :: MechanismId
sha256Mech = MechanismId 0x250
hmacMech = MechanismId 0x251
aesCbcMech = MechanismId 0x1082

h1KeyOid :: ObjectId
h1KeyOid = ObjectId 9

-- | A quiescent session snapshot for pinned steps.
h1Session :: SessionState
h1Session = SessionState
  { ssId = h1Sid
  , ssSlot = SlotId 0
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

-- | A pinned step for a function/slot pair.
h1Step :: FunctionId -> SlotKind -> CryptoStep
h1Step fid slot = CryptoStep
  { csFunction = fid
  , csKind = slot
  , csName = "h1"
  , csIntent = IntentBuffer 64
  , csOps = emptySessionOps
  , csSession = h1Session
  }

-- | A stepped reservation pinning a function/slot pair.
h1Res :: FunctionId -> SlotKind -> Reservation
h1Res fid slot = Reservation "h1" [] Nothing (Just (h1Step fid slot))

-- | One effect representative per call shape: digest one-shot, stream
-- allocation, stream feed, stream consume, cipher directions, the
-- sign/verify/recovery shapes, the message shapes, and every
-- key-management shape (which never pairs with a call step).
fxDigest, fxDigestInit, fxDigestFeed, fxDigestConsume :: CryptoEffect
fxDigest = FxDigest sha256Mech "hello"
fxDigestInit = FxDigestInit sha256Mech
fxDigestFeed = FxDigestFeed (EngineResourceId 3) "part"
fxDigestConsume = FxDigestConsume (EngineResourceId 3)

fxCipherEnc, fxCipherDec :: CryptoEffect
fxCipherEnc = FxCipher DirEncrypt aesCbcMech Nothing mempty "0123456789abcdef"
fxCipherDec = FxCipher DirDecrypt aesCbcMech Nothing mempty "0123456789abcdef"

fxSign, fxVerify, fxSignRecover, fxVerifyRecover :: CryptoEffect
fxSign = FxSign hmacMech (Just h1KeyOid) mempty "hello"
fxVerify = FxVerify hmacMech (Just h1KeyOid) mempty "hello" "sig"
fxSignRecover = FxSignRecover hmacMech (Just h1KeyOid) mempty "hello" 32
fxVerifyRecover = FxVerifyRecover hmacMech (Just h1KeyOid) mempty "sig" 32

fxMsgCipherEnc, fxMsgCipherDec, fxMsgSign, fxMsgVerify :: CryptoEffect
fxMsgCipherEnc =
  FxMessageCipher DirEncrypt aesCbcMech Nothing mempty mempty "0123456789abcdef"
fxMsgCipherDec =
  FxMessageCipher DirDecrypt aesCbcMech Nothing mempty mempty "0123456789abcdef"
fxMsgSign = FxMessageSign hmacMech (Just h1KeyOid) mempty "hello"
fxMsgVerify = FxMessageVerify hmacMech (Just h1KeyOid) mempty "hello" "sig"

fxGenKey, fxWrap, fxUnwrap, fxAuthWrap, fxAuthUnwrap :: CryptoEffect
fxGenKey = FxGenerateKey aesCbcMech mempty "genargs"
fxWrap = FxWrap aesCbcMech Nothing mempty "target"
fxUnwrap = FxUnwrap aesCbcMech Nothing mempty "wrapped"
fxAuthWrap = FxAuthWrap aesCbcMech Nothing mempty "target"
fxAuthUnwrap = FxAuthUnwrap aesCbcMech Nothing mempty "wrapped"

fxDerive, fxKemEnc, fxKemDec :: CryptoEffect
fxDerive = FxDerive sha256Mech (Just h1KeyOid) Nothing mempty "info" 32
fxKemEnc = FxKemEncaps aesCbcMech (Just h1KeyOid) mempty "seed"
fxKemDec = FxKemDecaps aesCbcMech (Just h1KeyOid) mempty "ct"

-- | Every representative, in constructor order.
allReps :: [CryptoEffect]
allReps =
  [ fxDigest, fxDigestInit, fxDigestFeed, fxDigestConsume
  , fxCipherEnc, fxCipherDec
  , fxSign, fxVerify, fxSignRecover, fxVerifyRecover
  , fxMsgCipherEnc, fxMsgCipherDec, fxMsgSign, fxMsgVerify
  , fxGenKey, fxWrap, fxUnwrap, fxAuthWrap, fxAuthUnwrap
  , fxDerive, fxKemEnc, fxKemDec
  ]

-- | The accepted (function, slot, effects) rows, in 'finisherJustSet'
-- order: each row names the planner shapes behind it (the producing
-- planner and call shape in parentheses).
acceptRows :: [(FunctionId, SlotKind, [CryptoEffect])]
acceptRows =
  [ (F_DigestInit, SlotDigest, [fxDigestInit]) -- DRInit digest arm
  , (F_Digest, SlotDigest, [fxDigest]) -- planDigestOneShot
  , (F_Sign, SlotSign, [fxSign]) -- planSignOneShot
  , (F_DigestUpdate, SlotDigest, [fxDigestFeed]) -- planDigestUpdate
  , (F_DigestFinal, SlotDigest, [fxDigest, fxDigestConsume]) -- planDigestFinal
  , (F_SignFinal, SlotSign, [fxSign]) -- planSignFinal
  , (F_Verify, SlotVerify, [fxVerify]) -- planVerifyOneShot
  , (F_VerifyFinal, SlotVerify, [fxVerify]) -- planVerifyFinal
  , (F_Encrypt, SlotEncrypt, [fxCipherEnc]) -- planCipherOneShot
  , (F_EncryptUpdate, SlotEncrypt, [fxCipherEnc]) -- planCipherUpdate
  , (F_EncryptFinal, SlotEncrypt, [fxCipherEnc]) -- planCipherFinal
  , (F_Decrypt, SlotDecrypt, [fxCipherDec]) -- planCipherOneShot
  , (F_DecryptUpdate, SlotDecrypt, [fxCipherDec]) -- planCipherUpdate
  , (F_DecryptFinal, SlotDecrypt, [fxCipherDec]) -- planCipherFinal
  , (F_EncryptMessage, SlotEncrypt, [fxMsgCipherEnc]) -- planMessageOneShot
  , (F_DecryptMessage, SlotDecrypt, [fxMsgCipherDec]) -- planMessageOneShot
  , (F_SignMessage, SlotSign, [fxMsgSign]) -- planMessageOneShot
  , (F_VerifyMessage, SlotVerify, [fxMsgVerify]) -- planMessageOneShot
  , (F_EncryptMessageNext, SlotEncrypt, [fxMsgCipherEnc]) -- planMessageNext
  , (F_DecryptMessageNext, SlotDecrypt, [fxMsgCipherDec]) -- planMessageNext
  , (F_SignMessageNext, SlotSign, [fxMsgSign]) -- planMessageNext
  , (F_VerifyMessageNext, SlotVerify, [fxMsgVerify]) -- planMessageNext
  , (F_SignRecover, SlotSign, [fxSignRecover]) -- planSignRecoverOneShot
  , (F_VerifyRecover, SlotVerify, [fxVerifyRecover]) -- planVerifyRecoverOneShot
  ]

-- | The slot table agrees with the finisher legs in both directions:
-- exactly the finishing functions have a slot, so neither table can
-- drift without failing this pin (and 'caseCallEffectMatrix' covers
-- the rows themselves).
caseCallSlotPin :: IO ()
caseCallSlotPin = do
  assertEqual "slot Just-set matches the finisher legs" finisherJustSet
    [fid | fid <- [minBound .. maxBound], isJust (callFunctionSlot fid)]
  assertEqual "accept rows cover the finisher legs" finisherJustSet
    [fid | (fid, _, _) <- acceptRows]

-- | The full cross product: every accepted triple checks, and every
-- other combination — wrong effect, wrong slot, wrong session, or a
-- function with no finishing leg — refuses with its exact typed
-- mismatch.
caseCallEffectMatrix :: IO ()
caseCallEffectMatrix = do
  mapM_ checkAccept acceptRows
  mapM_ checkRefuses acceptRows
  mapM_ checkWrongSlot acceptRows
  mapM_ checkWrongSession acceptRows
  mapM_ checkNoLeg noLegs
  where
    noLegs = [fid | fid <- [minBound .. maxBound], fid `notElem` finisherJustSet]
    ctx fid fx = " (" ++ show fid ++ " / " ++ show fx ++ ")"
    checkAccept (fid, slot, fxs) = mapM_ check fxs
      where
        res = h1Res fid slot
        check fx = do
          let eff = EffectCrypto fx
          assertBool ("accepts" ++ ctx fid fx)
            (isRight (checkedCallWork h1Sid res eff))
          assertEqual ("slot pins" ++ ctx fid fx)
            (Just slot) (callFunctionSlot fid)
          assertEqual ("effect pins" ++ ctx fid fx)
            True (callFunctionEffect fid fx)
    checkRefuses (fid, slot, fxs) =
      mapM_ check [fx | fx <- allReps, fx `notElem` fxs]
      where
        res = h1Res fid slot
        check fx = do
          let eff = EffectCrypto fx
          assertEqual ("refuses" ++ ctx fid fx)
            (Left (WorkEffectMismatch fid fx)) (checkedCallWork h1Sid res eff)
          assertEqual ("effect refuses" ++ ctx fid fx)
            False (callFunctionEffect fid fx)
    checkWrongSlot (fid, slot, fxs) =
      mapM_ check [s | s <- [minBound .. maxBound], s /= slot]
      where
        check s = mapM_ (checkFx s) fxs
        checkFx s fx = do
          let res = h1Res fid s
              eff = EffectCrypto fx
          assertEqual ("wrong slot refuses" ++ ctx fid fx)
            (Left (WorkFunctionSlotMismatch fid s)) (checkedCallWork h1Sid res eff)
    checkWrongSession (fid, slot, fxs) = mapM_ check fxs
      where
        res = h1Res fid slot
        check fx = do
          let eff = EffectCrypto fx
          -- Session identity is checked first: a wrong session
          -- reports even when slot and effect agree.
          assertEqual ("wrong session refuses" ++ ctx fid fx)
            (Left (WorkSessionMismatch h1SidOther h1Sid))
            (checkedCallWork h1SidOther res eff)
    checkNoLeg fid =
      mapM_ check [s | s <- [minBound .. maxBound]]
      where
        check s = mapM_ (checkFx s) allReps
        checkFx s fx = do
          let res = h1Res fid s
              eff = EffectCrypto fx
          assertEqual ("legless refuses" ++ ctx fid fx)
            (Left (WorkFunctionSlotMismatch fid s)) (checkedCallWork h1Sid res eff)
          assertEqual ("legless slot is Nothing" ++ ctx fid fx)
            Nothing (callFunctionSlot fid)
          assertEqual ("legless effect refuses" ++ ctx fid fx)
            False (callFunctionEffect fid fx)

-- Twin pin with 'caseFixtureConstructsUnstepped' below: both assert
-- the same fixture-constructor read-backs; keep them in sync.
caseCallLegacySplit :: IO ()
caseCallLegacySplit = mapM_ check allReps
  where
    res = Reservation "legacy" [] Nothing Nothing
    check fx = do
      let eff = EffectCrypto fx
          ctx = " (" ++ show fx ++ ")"
      assertEqual ("checked refuses unstepped" ++ ctx)
        (Left WorkUnstepped) (checkedCallWork h1Sid res eff)
      let cw = mkFixtureCallWork h1Sid res eff
      assertEqual ("fixture session reads back" ++ ctx)
        h1Sid (callWorkSession cw)
      assertEqual ("fixture reservation reads back" ++ ctx)
        res (callWorkReservation cw)
      assertEqual ("fixture effect reads back" ++ ctx)
        eff (callWorkEffect cw)

-- Twin pin with 'caseCallLegacySplit' above: both assert the same
-- fixture-constructor read-backs; keep them in sync.
caseFixtureConstructsUnstepped :: IO ()
caseFixtureConstructsUnstepped = mapM_ check allReps
  where
    res = Reservation "legacy" [] Nothing Nothing
    check fx = do
      let eff = EffectCrypto fx
          ctx = " (" ++ show fx ++ ")"
      assertEqual ("checked still refuses unstepped" ++ ctx)
        (Left WorkUnstepped) (checkedCallWork h1Sid res eff)
      let cw = mkFixtureCallWork h1Sid res eff
      assertEqual ("fixture session reads back" ++ ctx)
        h1Sid (callWorkSession cw)
      assertEqual ("fixture reservation reads back" ++ ctx)
        res (callWorkReservation cw)
      assertEqual ("fixture effect reads back" ++ ctx)
        eff (callWorkEffect cw)

caseFamilyTablePinned :: IO ()
caseFamilyTablePinned = do
  mapM_ (check FamilySign)
    [F_Sign, F_SignFinal, F_SignRecover, F_SignMessage, F_SignMessageNext]
  mapM_ (check FamilyDigest)
    [F_Digest, F_DigestInit, F_DigestUpdate, F_DigestFinal]
  mapM_ (check FamilyOther)
    [fid | fid <- [minBound .. maxBound], fid `notElem` signFids,
      fid `notElem` digestFids]
  where
    signFids =
      [F_Sign, F_SignFinal, F_SignRecover, F_SignMessage, F_SignMessageNext]
    digestFids = [F_Digest, F_DigestInit, F_DigestUpdate, F_DigestFinal]
    check fam fid = assertEqual ("family " ++ show fid)
      fam (callFunctionFamily fid)

-- | Open one read-write session on a seated token.
openTokenSession :: IO (SessionId, Model)
openTokenSession = do
  let m0 = addToken emptyModel (SlotId 0)
      req = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []
  case planCall defaultRules m0 req of
    Immediate pc -> case publishDelta m0 (pcDelta pc) of
      Left fault -> fail ("open delta fault: " ++ show fault)
      Right m1 -> pure (SessionId (mNextSession m0), m1)
    other -> fail ("open failed: " ++ show other)

-- | Finish an effect against the model and publish the commit.
finishPublish :: Model -> Reservation -> EngineResult -> IO Model
finishPublish m res ans = case finishEffect defaultRules m res ans of
  Left rej -> fail ("finish rejected: " ++ show (rejCode rej))
  Right pc -> case publishDelta m (pcDelta pc) of
    Left fault -> fail ("finish delta fault: " ++ show fault)
    Right m' -> pure m'

-- | Assert one planned execution checks coherently with its exact
-- planned effect, returning the reservation for finishing.
assertCoherent :: SessionId -> CryptoEffect -> PlanResult -> IO Reservation
assertCoherent sid want pr = case pr of
  Execute res (EffectCrypto fx) -> do
    assertEqual "planned effect" want fx
    assertBool ("checks: " ++ show (resOperation res))
      (isRight (checkedCallWork sid res (EffectCrypto fx)))
    pure res
  other -> fail ("expected Execute, got: " ++ show other)

-- | The digest streaming dialogue, planned end to end: init
-- allocates, update feeds, final consumes, and a fresh one-shot
-- digests — every execution checks with its exact effect.
caseCoherentDigest :: IO ()
caseCoherentDigest = do
  (sid, m0) <- openTokenSession
  let rid = EngineResourceId 11
      ireq = DRInit sid InitDigest Nothing sha256Mech [] False mempty
  resI <- assertCoherent sid (FxDigestInit sha256Mech)
    (planDecoded defaultRules m0 ireq)
  m1 <- finishPublish m0 resI (EngineOkResource rid)
  let ureq = Request Pkcs11_3_2 F_DigestUpdate (Just sid) Nothing "abc" []
  resU <- assertCoherent sid (FxDigestFeed rid "abc")
    (planCall defaultRules m1 ureq)
  m2 <- finishPublish m1 resU (EngineOkBytes mempty)
  let freq = (Request Pkcs11_3_2 F_DigestFinal (Just sid) Nothing mempty [])
        { reqRegions = [RegionBytes "digest" (IntentBuffer 64)] }
  resF <- assertCoherent sid (FxDigestConsume rid)
    (planCall defaultRules m2 freq)
  m3 <- finishPublish m2 resF (EngineOkBytes "digest-bytes")
  -- The slot terminated with the final: re-init, then one-shot.
  resI2 <- assertCoherent sid (FxDigestInit sha256Mech)
    (planDecoded defaultRules m3 ireq)
  m4 <- finishPublish m3 resI2 (EngineOkResource (EngineResourceId 12))
  let oreq = (Request Pkcs11_3_2 F_Digest (Just sid) Nothing "abc" [])
        { reqRegions = [RegionBytes "digest" (IntentBuffer 64)] }
  _ <- assertCoherent sid (FxDigest sha256Mech "abc")
    (planCall defaultRules m4 oreq)
  pure ()

-- | A public visible key object bound to a handle (legacy seam: no
-- usage attributes, so the caller-derived init permits apply).
seedSignKey :: Model -> ExternalHandle -> Model
seedSignKey m h = m
  { mObjects = Map.insert oid ost (mObjects m)
  , mHandles = Map.insert h (HandleBinding oid (Generation 1)) (mHandles m)
  }
  where
    oid = ObjectId 9
    ost = ObjectState
      { osId = oid
      , osRevision = Revision 1
      , osGeneration = Generation 1
      , osAttrs = Map.fromList [(AttrClass, ValULong 4), (AttrPrivate, ValBool False)]
      , osOwner = Nothing
      , osSlot = SlotId 0
      }

-- | The sign dialogue, planned end to end: a decoded init persists
-- the slot, and the one-shot over it checks with its exact effect.
caseCoherentSign :: IO ()
caseCoherentSign = do
  (sid, m0) <- openTokenSession
  let h = ExternalHandle 70
      mK = seedSignKey m0 h
      ireq = DRInit sid InitSign (Just h) hmacMech [OpSign] False mempty
  m1 <- case planDecoded defaultRules mK ireq of
    Immediate pc -> case publishDelta mK (pcDelta pc) of
      Left fault -> fail ("sign init delta fault: " ++ show fault)
      Right m' -> pure m'
    other -> fail ("sign init did not persist: " ++ show other)
  let oreq = (Request Pkcs11_3_2 F_Sign (Just sid) Nothing "hello" [])
        { reqRegions = [RegionBytes "sig" (IntentBuffer 64)] }
  _ <- assertCoherent sid (FxSign hmacMech (Just (ObjectId 9)) mempty "hello")
    (planCall defaultRules m1 oreq)
  pure ()

-- | Assert one seeded planner emission: the outcome plans exactly the
-- wanted effect, and the effect checks under its finishing function.
assertEmission
  :: FunctionId -> SlotKind -> CryptoEffect -> StepOutcome -> IO CryptoEffect
assertEmission fid slot want outcome = do
  assertEqual ("code for " ++ show fid) CKR_OK (soCode outcome)
  case soEffects outcome of
    [fx] -> do
      assertEqual ("emission for " ++ show fid) want fx
      let res = h1Res fid slot
      assertBool ("checks: " ++ show fid)
        (isRight (checkedCallWork h1Sid res (EffectCrypto fx)))
      pure fx
    fxs -> fail ("expected one effect for " ++ show fid ++ ", got: " ++ show fxs)

-- | Every classic planner emission checks under its finishing
-- function: sign/verify one-shots and finals, both recovery
-- one-shots, and cipher one-shots, updates, and finals in both
-- directions (cipher directions pin exactly: an encrypt emission
-- refuses under every decrypt function and vice versa).
caseCoherentEmissions :: IO ()
caseCoherentEmissions = do
  let st = h1Session
      oid = Just h1KeyOid
      sCommon = mkSlotCommon hmacMech OpSign oid mempty AuthNone
      vCommon = mkSlotCommon hmacMech OpVerify oid mempty AuthNone
      cCommon = mkSlotCommon aesCbcMech OpEncrypt oid mempty AuthNone
      dCommon = mkSlotCommon aesCbcMech OpDecrypt oid mempty AuthNone
      cipherSpec = CipherSpec 16 True
      rSpec = RecoverSpec 256 32
      signOps = insertOp (mkActiveSign sCommon) emptySessionOps
      verifyOps = insertOp (mkActiveVerify vCommon) emptySessionOps
      encOps = insertOp (mkActiveCipher DirEncrypt cCommon cipherSpec) emptySessionOps
      decOps = insertOp (mkActiveCipher DirDecrypt dCommon cipherSpec) emptySessionOps
      srOps = insertOp
        (mkActiveRecover RoleSignRecover
          (mkSlotCommon hmacMech OpSignRecover oid mempty AuthNone) rSpec)
        emptySessionOps
      vrOps = insertOp
        (mkActiveRecover RoleVerifyRecover
          (mkSlotCommon hmacMech OpVerifyRecover oid mempty AuthNone) rSpec)
        emptySessionOps
  -- Sign and verify verticals over seeded slots.
  let (_, _, s1) = planSignOneShot signOps st "" "hello"
  _ <- assertEmission F_Sign SlotSign
    (FxSign hmacMech oid mempty "hello") s1
  let (opsSU, stSU, sU) = planSignUpdate signOps st "hel"
  assertEqual "sign update buffers" [] (soEffects sU)
  let (_, _, sF) = planSignFinal opsSU stSU ""
  _ <- assertEmission F_SignFinal SlotSign
    (FxSign hmacMech oid mempty "hel") sF
  let (_, _, v1) = planVerifyOneShot verifyOps st "" "hello" "sig"
  _ <- assertEmission F_Verify SlotVerify
    (FxVerify hmacMech oid mempty "hello" "sig") v1
  let (opsVU, stVU, vU) = planVerifyUpdate verifyOps st "hel"
  assertEqual "verify update buffers" [] (soEffects vU)
  let (_, _, vF) = planVerifyFinal opsVU stVU "" "lo"
  _ <- assertEmission F_VerifyFinal SlotVerify
    (FxVerify hmacMech oid mempty "hel" "lo") vF
  -- Recovery one-shots over seeded slots.
  let (_, _, sR) = planSignRecoverOneShot srOps st "" "hello"
  _ <- assertEmission F_SignRecover SlotSign
    (FxSignRecover hmacMech oid mempty "hello" 32) sR
  -- The recovery block must hold data past the tag length.
  let vrWit = BS.replicate 64 0x51
      (_, _, vR) = planVerifyRecoverOneShot vrOps st "" vrWit
  _ <- assertEmission F_VerifyRecover SlotVerify
    (FxVerifyRecover hmacMech oid mempty vrWit 32) vR
  -- Cipher verticals in both directions (encrypt pads, so
  -- one-shot/update/final pin the emitted direction and check the
  -- emitted effect rather than exact padded bytes; decrypt passes
  -- input through verbatim, pinned exactly).
  let block = "0123456789abcdef0123456789abcdef"
      (_, _, e1) = planCipherOneShot encOps st SlotEncrypt "" block
  fxE1 <- case soEffects e1 of
    [fx@(FxCipher DirEncrypt _ _ _ _)] -> do
      _ <- assertEmission F_Encrypt SlotEncrypt fx e1
      pure fx
    fxs -> fail ("expected one encrypt one-shot effect, got: " ++ show fxs)
  let (_, _, eU) = planCipherUpdate encOps st SlotEncrypt block Nothing
  fxEU <- case soEffects eU of
    [fx@(FxCipher DirEncrypt _ _ _ _)] -> do
      _ <- assertEmission F_EncryptUpdate SlotEncrypt fx eU
      pure fx
    fxs -> fail ("expected one encrypt update effect, got: " ++ show fxs)
  let (_, _, eF) = planCipherFinal encOps st SlotEncrypt ""
  fxEF <- case soEffects eF of
    [fx@(FxCipher DirEncrypt _ _ _ _)] -> do
      _ <- assertEmission F_EncryptFinal SlotEncrypt fx eF
      pure fx
    fxs -> fail ("expected one encrypt final effect, got: " ++ show fxs)
  let (_, _, d1) = planCipherOneShot decOps st SlotDecrypt "" block
  fxD1 <- assertEmission F_Decrypt SlotDecrypt
    (FxCipher DirDecrypt aesCbcMech oid mempty block) d1
  let (_, _, dU) = planCipherUpdate decOps st SlotDecrypt block Nothing
  fxDU <- case soEffects dU of
    [fx@(FxCipher DirDecrypt _ _ _ _)] -> do
      _ <- assertEmission F_DecryptUpdate SlotDecrypt fx dU
      pure fx
    fxs -> fail ("expected one decrypt update effect, got: " ++ show fxs)
  let (_, _, dF) = planCipherFinal decOps st SlotDecrypt ""
  fxDF <- case soEffects dF of
    [fx@(FxCipher DirDecrypt _ _ _ _)] -> do
      _ <- assertEmission F_DecryptFinal SlotDecrypt fx dF
      pure fx
    fxs -> fail ("expected one decrypt final effect, got: " ++ show fxs)
  -- Direction precision: encrypt emissions refuse under every
  -- decrypt function and vice versa.
  mapM_ (assertDirRefuses [F_Decrypt, F_DecryptUpdate, F_DecryptFinal])
    [fxE1, fxEU, fxEF]
  mapM_ (assertDirRefuses [F_Encrypt, F_EncryptUpdate, F_EncryptFinal])
    [fxD1, fxDU, fxDF]
  where
    assertDirRefuses fids fx = mapM_ check fids
      where
        check fid = assertEqual ("direction refuses " ++ show fid)
          False (callFunctionEffect fid fx)

-- | Message fixtures mirroring the message-operation suite: a keyed
-- model, an op env over the curated registry, and per-family init
-- arguments.
msgModel :: Model
msgModel =
  let ost = ObjectState
        { osId = ObjectId 9
        , osRevision = Revision 1
        , osGeneration = Generation 1
        , osAttrs = Map.fromList
            [(AttrClass, ValULong 4), (AttrPrivate, ValBool False)]
        , osOwner = Nothing
        , osSlot = SlotId 0
        }
  in emptyModel
    { mObjects = Map.singleton (ObjectId 9) ost
    , mHandles = Map.singleton (ExternalHandle 3)
        (HandleBinding (ObjectId 9) (Generation 1))
    }

msgEnv :: OpEnv
msgEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities
      [ (sha256Mech, OpDigest)
      , (hmacMech, OpSign)
      , (hmacMech, OpVerify)
      , (aesCbcMech, OpEncrypt)
      , (aesCbcMech, OpDecrypt)
      ]
  , oeModel = msgModel
  }

msgKey :: [Operation] -> KeyPolicy
msgKey permits = KeyPolicy
  { kpHandle = ExternalHandle 3
  , kpPermits = permits
  , kpAlwaysAuth = False
  }

msgArgs :: MsgFamily -> InitArgs
msgArgs MsgEncrypt = InitArgs
  { iaOp = OpEncrypt
  , iaMech = aesCbcMech
  , iaParams = BS.replicate 16 0
  , iaKey = Just (msgKey [OpEncrypt, OpDecrypt])
  , iaCipher = Just (CipherSpec 16 True)
  , iaRecover = Nothing
  }
msgArgs MsgDecrypt = InitArgs
  { iaOp = OpDecrypt
  , iaMech = aesCbcMech
  , iaParams = BS.replicate 16 0
  , iaKey = Just (msgKey [OpEncrypt, OpDecrypt])
  , iaCipher = Just (CipherSpec 16 True)
  , iaRecover = Nothing
  }
msgArgs MsgSign =
  InitArgs OpSign hmacMech BS.empty
    (Just (msgKey [OpSign, OpVerify])) Nothing Nothing
msgArgs MsgVerify =
  InitArgs OpVerify hmacMech BS.empty
    (Just (msgKey [OpSign, OpVerify])) Nothing Nothing

-- | Every message planner emission checks under its finishing
-- function: one-shots and concluding nexts in all four families
-- (cipher directions pin exactly across families too).
caseCoherentMessage :: IO ()
caseCoherentMessage = do
  let encParams = BS.replicate 16 2
  -- One-shots in all four families.
  fxEO <- msgOneShot MsgEncrypt
    (MsgOneShotCipher encParams BS.empty "second")
  fxDO <- msgOneShot MsgDecrypt
    (MsgOneShotCipher BS.empty BS.empty "0123456789abcdef")
  fxSO <- msgOneShot MsgSign (MsgOneShotSign BS.empty "hello")
  fxVO <- msgOneShot MsgVerify (MsgOneShotVerify BS.empty "hello" "sig")
  assertMsgCipher F_EncryptMessage SlotEncrypt fxEO DirEncrypt
  assertMsgCipher F_DecryptMessage SlotDecrypt fxDO DirDecrypt
  assertMsgFamily F_SignMessage SlotSign fxSO
  assertMsgFamily F_VerifyMessage SlotVerify fxVO
  -- Concluding nexts in all four families.
  fxEN <- msgNext MsgEncrypt (MsgBegin encParams BS.empty)
    [ MsgNextCipher BS.empty "hello, " False
    , MsgNextCipher BS.empty "world" True
    ]
  fxDN <- msgNext MsgDecrypt (MsgBegin BS.empty BS.empty)
    [MsgNextCipher BS.empty "0123456789abcdef" True]
  fxSN <- msgNext MsgSign (MsgBegin BS.empty BS.empty)
    [ MsgNextSign BS.empty "hello, " False
    , MsgNextSign BS.empty "world" True
    ]
  fxVN <- msgNext MsgVerify (MsgBegin BS.empty BS.empty)
    [MsgNextVerify BS.empty "hello" (Just "sig")]
  assertMsgCipher F_EncryptMessageNext SlotEncrypt fxEN DirEncrypt
  assertMsgCipher F_DecryptMessageNext SlotDecrypt fxDN DirDecrypt
  assertMsgFamily F_SignMessageNext SlotSign fxSN
  assertMsgFamily F_VerifyMessageNext SlotVerify fxVN
  -- Cross-family precision: cipher directions and families refuse
  -- across each other.
  assertEqual "encrypt refuses decrypt legs"
    False (callFunctionEffect F_DecryptMessage fxEO)
  assertEqual "decrypt refuses encrypt legs"
    False (callFunctionEffect F_EncryptMessage fxDO)
  assertEqual "cipher refuses sign legs"
    False (callFunctionEffect F_SignMessage fxEO)
  assertEqual "sign refuses cipher legs"
    False (callFunctionEffect F_EncryptMessage fxSO)
  where
    msgOps fam =
      case initMessageOperation fam msgEnv emptySessionOps h1Session (msgArgs fam) of
        (ops, out)
          | ioCode out == CKR_OK -> pure ops
          | otherwise -> fail ("message init refused: " ++ show (ioCode out))
    msgOneShot fam one = do
      ops0 <- msgOps fam
      let (_, _, o) = planMessageOneShot ops0 h1Session fam "" one
      assertEqual ("one-shot code for " ++ show fam) CKR_OK (soCode o)
      case soEffects o of
        [fx] -> pure fx
        fxs -> fail ("expected one effect for " ++ show fam ++ ", got: " ++ show fxs)
    msgNext fam begin parts = do
      ops0 <- msgOps fam
      let (ops1, st1, b) = planMessageBegin ops0 h1Session fam begin
      assertEqual ("begin code for " ++ show fam) CKR_OK (soCode b)
      assertEqual ("begin plans no crypto for " ++ show fam) [] (soEffects b)
      go ops1 st1 parts
      where
        go _ _ [] = fail ("no concluding next for " ++ show fam)
        go ops s [n] = do
          let (_, _, o) = planMessageNext ops s fam n
          assertEqual ("next code for " ++ show fam) CKR_OK (soCode o)
          case soEffects o of
            [fx] -> pure fx
            fxs -> fail ("expected one effect for " ++ show fam ++ ", got: " ++ show fxs)
        go ops s (n : ns) = do
          let (ops', s', o) = planMessageNext ops s fam n
          assertEqual ("part code for " ++ show fam) CKR_OK (soCode o)
          go ops' s' ns
    assertMsgCipher fid slot fx dir = case fx of
      FxMessageCipher dir' _ _ _ _ _
        | dir' == dir -> assertChecked fid slot fx
        | otherwise -> fail ("wrong direction for " ++ show fid)
      _ -> fail ("expected message cipher for " ++ show fid ++ ", got: " ++ show fx)
    assertMsgFamily fid slot fx = assertChecked fid slot fx
    assertChecked fid slot fx = do
      let res = h1Res fid slot
      assertEqual ("effect pins " ++ show fid)
        True (callFunctionEffect fid fx)
      assertBool ("checks " ++ show fid)
        (isRight (checkedCallWork h1Sid res (EffectCrypto fx)))

-- | Two seated tokens, one token object each, and a worn
-- slot-0 auth (one SO strike short of nothing: attempts and
-- locks are what a refused reinit must leave untouched).
seedInitTokenModel :: IO Model
seedInitTokenModel = do
  let seated = addToken (addToken emptyModel (SlotId 0)) (SlotId 1)
      tokenAttrs = Map.singleton AttrToken (ValBool True)
      worn = tokenAuthNew { taSoAttempts = 1, taUserAttempts = 2 }
      seed = StateDelta
        [ DeltaCreateObjectFull (ObjectId 1) tokenAttrs Nothing (SlotId 0)
        , DeltaCreateObjectFull (ObjectId 2) tokenAttrs Nothing (SlotId 1)
        , DeltaSetTokenAuth (SlotId 0) worn
        ]
  either (fail . show) pure (publishDelta seated seed)

-- | An InitToken request with the given raw argument bytes.
initTokenReq :: BS.ByteString -> Request
initTokenReq args = Request Pkcs11_3_2 F_InitToken Nothing Nothing args []

-- | A denied reinit answers @CKR_PIN_INCORRECT@ with an empty
-- delta, no outputs, and no releases: objects, auth halves,
-- and counters survive byte-identical (the published model
-- equals the pre-call model).
caseInitTokenDeniedPreserves :: IO ()
caseInitTokenDeniedPreserves = do
  m0 <- seedInitTokenModel
  case planCall defaultRules m0 (initTokenReq "slot=0,so:bad") of
    Reject rej -> do
      assertEqual "denied code" CKR_PIN_INCORRECT (rejCode rej)
      assertEqual "no delta" (StateDelta []) (rejDelta rej)
      assertEqual "no outputs" [] (rejOutputs rej)
      assertEqual "no releases" [] (rejReleases rej)
      case publishDelta m0 (rejDelta rej) of
        Left fault -> assertBool (show fault) False
        Right m1 -> assertEqual "model unchanged" m0 m1
    other -> fail ("expected Reject, got: " ++ show other)

-- | An authorized reinit plans the wipe: fresh auth plus the
-- destruction of exactly its own slot's objects. Publishing
-- drops the slot-0 object, keeps the sibling, and resets the
-- worn auth half.
caseInitTokenAuthorizedResets :: IO ()
caseInitTokenAuthorizedResets = do
  m0 <- seedInitTokenModel
  case planCall defaultRules m0 (initTokenReq "slot=0,so:ok") of
    Immediate pc -> do
      assertEqual "grant code" CKR_OK (pcCode pc)
      assertEqual "wipe shape"
        [ DeltaSetTokenAuth (SlotId 0) tokenAuthNew
        , DeltaDestroyObject (ObjectId 1)
        ]
        (unStateDelta (pcDelta pc))
      case publishDelta m0 (pcDelta pc) of
        Left fault -> assertBool (show fault) False
        Right m1 -> do
          assertEqual "own object destroyed"
            Nothing (lookupObject m1 (ObjectId 1))
          assertEqual "sibling object survives"
            (lookupObject m0 (ObjectId 2)) (lookupObject m1 (ObjectId 2))
          assertEqual "auth fresh"
            (Just tokenAuthNew) (lookupTokenAuth m1 (SlotId 0))
    other -> fail ("expected Immediate, got: " ++ show other)

-- | A bare slot argument (no verdict: the token carries no SO
-- PIN yet, so there is nothing to check against) plans the
-- same own-token wipe as an authorized reinit.
caseInitTokenFirstInitGrants :: IO ()
caseInitTokenFirstInitGrants = do
  m0 <- seedInitTokenModel
  case planCall defaultRules m0 (initTokenReq "slot=0") of
    Immediate pc -> do
      assertEqual "grant code" CKR_OK (pcCode pc)
      assertEqual "wipe shape"
        [ DeltaSetTokenAuth (SlotId 0) tokenAuthNew
        , DeltaDestroyObject (ObjectId 1)
        ]
        (unStateDelta (pcDelta pc))
    other -> fail ("expected Immediate, got: " ++ show other)

-- | The init-token codec accepts exactly @slot=\<nat\>@ with an
-- optional @,so:ok|bad@ verdict: junk refuses with
-- @CKR_ARGUMENTS_BAD@, and a missing token reports
-- @CKR_TOKEN_NOT_PRESENT@ ahead of the verdict either way.
caseInitTokenArgsShape :: IO ()
caseInitTokenArgsShape = do
  m0 <- seedInitTokenModel
  let badArgs =
        [ BS.empty
        , "slot="
        , "slot=0,"
        , "slot=0,so:"
        , "slot=0,so:might"
        , "slot=0,so:ok,extra"
        , "slot=0,user:ok"
        , "Slot=0"
        , "slot=-1"
        ]
  mapM_ (assertArgsBad m0) badArgs
  mapM_ (assertNoToken m0) ["slot=9", "slot=9,so:ok", "slot=9,so:bad"]
  where
    assertArgsBad m0 args = case planCall defaultRules m0 (initTokenReq args) of
      Reject rej -> assertEqual ("args bad: " ++ show args)
        CKR_ARGUMENTS_BAD (rejCode rej)
      other -> fail ("expected ARGUMENTS_BAD for " ++ show args ++ ", got: " ++ show other)
    assertNoToken m0 args = case planCall defaultRules m0 (initTokenReq args) of
      Reject rej -> assertEqual ("no token: " ++ show args)
        CKR_TOKEN_NOT_PRESENT (rejCode rej)
      other -> fail ("expected TOKEN_NOT_PRESENT for " ++ show args ++ ", got: " ++ show other)

-- | A locked SO role ignores the lock on the reinit path: a
-- bad verdict still refuses with @CKR_PIN_INCORRECT@ and an
-- empty delta (the lock and counters survive), while a good
-- verdict grants and the fresh auth clears the lock (the
-- locked-SO recovery path).
caseInitTokenLockedSo :: IO ()
caseInitTokenLockedSo = do
  m0 <- seedInitTokenModel
  let locked = tokenAuthNew { taSoAttempts = 3, taSoLocked = True, taUserAttempts = 2 }
  mLocked <- either (fail . show) pure
    (publishDelta m0 (StateDelta [DeltaSetTokenAuth (SlotId 0) locked]))
  case planCall defaultRules mLocked (initTokenReq "slot=0,so:bad") of
    Reject rej -> do
      assertEqual "denied code" CKR_PIN_INCORRECT (rejCode rej)
      assertEqual "no delta" (StateDelta []) (rejDelta rej)
      case publishDelta mLocked (rejDelta rej) of
        Left fault -> assertBool (show fault) False
        Right m1 -> assertEqual "lock preserved" mLocked m1
    other -> fail ("expected Reject, got: " ++ show other)
  case planCall defaultRules mLocked (initTokenReq "slot=0,so:ok") of
    Immediate pc -> do
      assertEqual "grant code" CKR_OK (pcCode pc)
      case publishDelta mLocked (pcDelta pc) of
        Left fault -> assertBool (show fault) False
        Right m1 -> assertEqual "lock cleared"
          (Just tokenAuthNew) (lookupTokenAuth m1 (SlotId 0))
    other -> fail ("expected Immediate, got: " ++ show other)
