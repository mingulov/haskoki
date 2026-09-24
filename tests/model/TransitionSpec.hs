{- | Model transition tests: missing sessions, error outcomes with
required effects, and generated sequence tests for handle separation
and delta consistency.

Deterministic: the sequence generator is an inline LCG (no new test
dependencies), so the same seed always yields the same cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module TransitionSpec (spec) where

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust)
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState (..)
  , emptyModel
  , lookupSession
  )
import Haskoki.Operation
  ( CryptoEffect (..)
  , CryptoResult (..)
  , InitArgs (..)
  , OpEnv (..)
  , SlotKind (..)
  , StepOutcome (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Outcome
  ( CryptoStep (..)
  , DeltaOp (..)
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
  ( FunctionId (..)
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
import Haskoki.Session (SessionLogin (..))
import Haskoki.Transition (finishEffect, packStep, planCall, publishDelta, runFinisher)
import Haskoki.Types
  ( EngineResourceId (..)
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
  , testCase "generated: delta split-application equivalence" caseDeltaSplit
  , testCase "generated: session/object namespaces stay separate" caseNamespaces
  , testCase "generated: unknown destroy reports exact fault" caseUnknownDestroy
  , testCase "runFinisher finishing-leg set is pinned" caseFinisherCoverage
  ]

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
  , F_EncryptFinal
  , F_Decrypt
  , F_DecryptFinal
  , F_EncryptMessage
  , F_DecryptMessage
  , F_SignMessage
  , F_VerifyMessage
  , F_EncryptMessageNext
  , F_DecryptMessageNext
  , F_SignMessageNext
  , F_VerifyMessageNext
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
