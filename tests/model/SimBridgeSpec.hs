{- | Delay-bridge + sim-verb proofs.

* @scheduler.advance@ decrements pending-job ticks through the async
  poll path (saturating at 1: the last tick always drives via poll,
  advance never executes effects);
* configured @[sim]@ delay schedules boost the advance per job
  (exact CKM name > function tag > wildcard; last file entry wins
  per key; gated on @sim.enabled@);
* the new test-gated scenario verbs (@token.insert@, @async.delay@,
  @fault.window@) parse and execute deterministically;
* sync sessions never pend, delays or not (guard).
-}
{-# LANGUAGE OverloadedStrings #-}
module SimBridgeSpec (spec) where

import Control.Exception (bracket)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.IORef (newIORef, readIORef, modifyIORef')
import Data.List (isInfixOf)
import System.Directory (getTemporaryDirectory, removeFile)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Ctl (CtlExit (..), runCtl)
import Haskoki.CallWork (mkFixtureCallWork)
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoResult (..))
import Haskoki.Outcome (EffectRequest (..), Reservation (..))
import Haskoki.Registry (MechanismId (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.Async
  ( AsyncTable
  , AsyncWork (..)
  , CompleteOutcome (..)
  , Completion (..)
  , Delivery (..)
  , EffectRunner
  , JobFunction (..)
  , JobRequest (..)
  , JobView (..)
  , PollOutcome (..)
  , completeJob
  , enableAsyncSession
  , inspectJob
  , newAsyncTable
  , pollJob
  , startFixtureJob
  )
import Haskoki.Runtime.Config
  ( Config (..)
  , SimCfg (..)
  , defaultConfig
  )
import Haskoki.FFI.Exports (returnCodeToRV)
import Haskoki.Runtime.Control
  ( ControlState
  , Json (..)
  , Scenario (..)
  , base64DecodedLength
  , dispatchControl
  , newControlState
  , bindPrivatePresenceOwner
  , renderJson
  , validateScenario
  )
import Haskoki.Runtime.Events
  ( OverflowPolicy (DropOldest)
  , newEventQueue
  , newTokenRegistry
  )
import Haskoki.Runtime.Lifecycle (Env, newEnv)
import Haskoki.Types (ReturnCode (..), SessionId (..))

spec :: TestTree
spec = testGroup "Sim bridge"
  [ testCase "advance-completion: covering advance saturates, poll drives, complete delivers" caseAdvanceCompletes
  , testCase "schedule boost: precedence, file-order override, gating" caseScheduleBoost
  , testCase "new verbs validate" caseVerbsValidate
  , testCase "sim scenario succeeds and is byte-deterministic" caseSimScenario
  , testCase "sim verbs need a test-enabled instance" caseVerbsGated
  , testCase "fault windows: config seed applies, later verb replaces" caseFaultWindows
  , testCase "sync sessions never pend (guard)" caseSyncNeverPends
  , testCase "rules: nonempty rejects, empty validates" caseRulesRejected
  , testCase "save_as validates (string, session.open only)" caseSaveAsValidated
  , testCase "expect validates (object, supported clause only)" caseExpectValidated
  , testCase "unknown step fields reject" caseStepFieldsRejected
  , testCase "top-level note validates and is dropped" caseTopNoteDropped
  , testCase "unknown top-level fields reject" caseTopUnknownRejected
  , testCase "string note rejects" caseTopNoteShape
  , testCase "top-level schema version admits only 1" caseTopSchemaVersion
  , testCase "unsupported mechanism refuses at load" caseMechanismRefused
  , testCase "unknown fixture key refuses at load" caseFixtureKeyRefused
  , testCase "malformed base64 refuses at load" caseBase64Refused
  , testCase "negative capacity refuses at load" caseCapacityRefused
  , testCase "unsupported function refuses at load" caseFunctionRefused
  , testCase "unknown role refuses at load" caseRoleRefused
  , testCase "read-only session refuses at load" caseReadOnlyRefused
  , testCase "missing operation inputs refuse at load" caseRequiredInputs
  , testCase "retired execution key refuses" caseRetiredKeyRefused
  , testCase "unsupported fixture refuses at load" caseFixtureRefused
  , testCase "empty token refuses at load" caseEmptyTokenRefused
  , testCase "base64 decoder accepts canonical shapes" caseBase64Shapes
  , testCase "duplicate fields reject" caseDuplicateFieldsRejected
  , testCase "per-action arguments validate" caseArgumentsValidated
  , testCase "save_as names the opened session" caseSaveAsHonored
  , testCase "duplicate session names refuse" caseSaveAsDuplicate
  , testCase "s1 aliases the first-opened session" caseFirstOpenedAlias
  , testCase "expect mismatch fails the run" caseExpectEnforced
  , testCase "wrong initialize expectation fails" caseInitializeWrongExpectationFails
  , testCase "every verb's expectation enforces" caseEveryVerbExpectation
  , testCase "wrong PIN is an expected refusal" caseWrongPinExpected
  , testCase "absent token label refuses the open" caseTokenAbsent
  , testCase "absent token label refuses removal" caseTokenRemoveAbsent
  , testCase "zero capacity answers too-small" caseCapacityZero
  , testCase "steps before initialize refuse" caseNotInitialized
  , testCase "repeated initialize answers already-initialized" caseDoubleInitialize
  , testCase "post-finalize use refuses" casePostFinalize
  , testCase "signing without login refuses" caseLoginRequired
  , testCase "armed mechanism and key echo in step lines" caseArmedEcho
  ]

fixture :: FilePath -> FilePath
fixture name = "tests/ops/fixtures/" ++ name

-- ---------------------------------------------------------------------------
-- Harness
-- ---------------------------------------------------------------------------

-- | An owned control state with its async table and lifecycle env.
mkBridge :: Config -> IO (ControlState, AsyncTable, Env)
mkBridge cfg = do
  eq <- newEventQueue 64 DropOldest
  at <- newAsyncTable 16
  reg <- newTokenRegistry eq at
  st <- newControlState cfg reg at True False
  bindPrivatePresenceOwner st reg
  env <- newEnv defaultRules
  pure (st, at, env)

-- | A sign job request with an explicit mechanism and schedule.
bridgeRequest :: SessionId -> MechanismId -> Int -> JobRequest
bridgeRequest sid mech ticks = JobRequest
  { jrSession = sid
  , jrFunction = JobSign
  , jrWork = WorkCall (mkFixtureCallWork sid
      (Reservation "bridge" [] Nothing Nothing)
      (EffectCrypto (FxSign mech Nothing BS.empty "hello")))
  , jrTicks = ticks
  , jrCapacity = 64
  }

-- | A scheduler.advance request for N ticks.
advanceReq :: Integer -> BC8.ByteString
advanceReq n = BC8.pack
  ("{\"schema_version\":1,\"command\":\"scheduler.advance\",\"arguments\":{\"ticks\":" ++ show n ++ "}}")

-- | Stub effect runner: canned bytes, no engine.
stubRun :: EffectRunner
stubRun _fx = pure (GotBytes (BS.replicate 64 0x51))

-- ---------------------------------------------------------------------------
-- Advance (a)
-- ---------------------------------------------------------------------------

-- | A covering advance saturates the job at 1 tick (never 0: advance
-- never executes effects); one poll then drives it ready and the
-- completion delivers exactly once.
caseAdvanceCompletes :: IO ()
caseAdvanceCompletes = do
  (st, table, env) <- mkBridge defaultConfig
  let sid = SessionId 1
  enableAsyncSession table sid
  eJid <- startFixtureJob table (bridgeRequest sid (MechanismId 0x1) 5)
  jid <- case eJid of
    Left deny -> assertFailure ("start refused: " ++ show deny)
    Right j -> pure j
  (code, body, _) <- dispatchControl st (advanceReq 5) (Just 65536)
  assertEqual "advance ok" (fromIntegral (returnCodeToRV CKR_OK)) code
  mAfter <- inspectJob table jid
  assertEqual "advance saturates at 1" (Just (Just 1)) (fmap jvTicksLeft mAfter)
  assertBool "bridge ran" ("\"jobs_advanced\":1" `isInfixOf` BC8.unpack body)
  p <- pollJob stubRun env table JobSign jid
  assertEqual "last tick drives via poll" PollReady p
  frames <- newIORef []
  let del = Delivery 64 (\bs -> modifyIORef' frames (++ [bs])) (\_ -> pure ())
  out <- completeJob env table JobSign jid del (\_ -> pure ())
  case out of
    CompleteDelivered (CompBytes _) -> pure ()
    other -> assertFailure ("expected delivery, got: " ++ show other)
  got <- readIORef frames
  assertEqual "exactly one write" 1 (length got)

-- | Start one job under the given schedule, advance, read ticks left.
boostLeft :: [(String, Int)] -> Bool -> MechanismId -> Int -> Integer -> IO (Maybe Int)
boostLeft sched enabled mech ticks adv = do
  (st, table, _) <- mkBridge (defaultConfig { cfgSim = SimCfg enabled sched [] 0 0 })
  let sid = SessionId 1
  enableAsyncSession table sid
  eJid <- startFixtureJob table (bridgeRequest sid mech ticks)
  jid <- case eJid of
    Left deny -> assertFailure ("start refused: " ++ show deny)
    Right j -> pure j
  (code, _, _) <- dispatchControl st (advanceReq adv) (Just 65536)
  assertEqual "advance ok" (fromIntegral (returnCodeToRV CKR_OK)) code
  mAfter <- inspectJob table jid
  pure (mAfter >>= jvTicksLeft)

-- | Schedule application: exact mechanism name beats the function
-- tag beats the wildcard; within one key the LAST file entry wins;
-- unknown names are inert; the boost needs sim.enabled.
caseScheduleBoost :: IO ()
caseScheduleBoost = do
  let rsa = MechanismId 0x1
  fTag <- boostLeft [("sign", 2)] True rsa 3 1
  assertEqual "function tag boosts" (Just 1) fTag
  mech <- boostLeft [("sign", 1), ("CKM_RSA_PKCS", 5)] True rsa 5 1
  assertEqual "mechanism name wins over function tag" (Just 1) mech
  wild <- boostLeft [("*", 4)] True rsa 5 1
  assertEqual "wildcard boosts" (Just 1) wild
  lastWins <- boostLeft [("sign", 0), ("sign", 4)] True rsa 5 1
  assertEqual "last file entry wins" (Just 1) lastWins
  firstLoses <- boostLeft [("sign", 4), ("sign", 0)] True rsa 5 1
  assertEqual "earlier entry loses" (Just 4) firstLoses
  inert <- boostLeft [("CKM_NOPE_NOPE", 9)] True rsa 5 1
  assertEqual "unknown names inert" (Just 4) inert
  gated <- boostLeft [("sign", 9)] False rsa 5 1
  assertEqual "boost needs sim.enabled" (Just 4) gated

-- ---------------------------------------------------------------------------
-- Verbs (b)
-- ---------------------------------------------------------------------------

-- | The three new verbs validate as scenario actions (with
-- their required arguments).
caseVerbsValidate :: IO ()
caseVerbsValidate = do
  let sc = JObj
        [ ("name", JStr "verbs")
        , ("steps", JArr
            [ verbStep "token.insert" [("slot", JNum 0)]
            , verbStep "async.delay" [("polls", JNum 1)]
            , verbStep "fault.window" [("start", JNum 0), ("ticks", JNum 1)]
            ])
        ]
  case validateScenario sc of
    Left err -> assertFailure ("verbs must validate: " ++ err)
    Right v -> assertEqual "three steps" 3 (length (scSteps v))
  where
    verbStep a args = JObj [("action", JStr a), ("arguments", JObj args)]

-- | The sim scenario succeeds and runs byte-identically 3 times, with
-- the token script and the fault window observably applied.
caseSimScenario :: IO ()
caseSimScenario = do
  let run = runCtl ["scenario", "run", "--config", fixture "sim-demo.toml"
                   , "--scenario", fixture "sim-scenario.json"]
  r1 <- run
  r2 <- run
  r3 <- run
  assertEqual ("first run exit 0: " ++ ceErr r1) 0 (ceCode r1)
  assertEqual "deterministic rerun 2" (ceOut r1) (ceOut r2)
  assertEqual "deterministic rerun 3" (ceOut r1) (ceOut r3)
  assertBool "token script ran" ("sim-script: insert 1,remove 1" `isInfixOf` ceOut r1)
  assertBool "fault observed" ("CKR_DEVICE_ERROR" `isInfixOf` ceOut r1)

-- | Sim verbs refuse on a non-test-enabled instance.
caseVerbsGated :: IO ()
caseVerbsGated = do
  r <- runCtl ["scenario", "run", "--config", fixture "maximal-demo.toml"
              , "--scenario", fixture "sim-scenario.json"]
  assertEqual "refused" 1 (ceCode r)
  assertBool "gate named" ("test_instance_required" `isInfixOf` ceErr r)

-- | One scenario step builder: action + object args + optional
-- return expectation.
step :: String -> [(String, Json)] -> Maybe String -> Json
step action args mExpect = JObj $
  [("action", JStr action), ("arguments", JObj args)] ++
  maybe [] (\w -> [("expect", JObj [("return", JStr w)])]) mExpect

-- | A scenario object with a name, optional rules, and built steps.
scenarioWith :: String -> Maybe [Json] -> [Json] -> Json
scenarioWith name mRules steps = JObj $
  [("name", JStr name)]
  ++ maybe [] (\rs -> [("rules", JArr rs)]) mRules
  ++ [("steps", JArr steps)]

-- | Reject unless validation fails.
assertRejected :: String -> Json -> IO ()
assertRejected tag val = case validateScenario val of
  Left _ -> pure ()
  Right _ -> assertFailure ("must reject: " ++ tag)

-- | Run a temp scenario (built steps) under sim-demo.toml.
runTempScenario :: String -> [Json] -> IO CtlExit
runTempScenario tag steps =
  runTempScenarioFull (fixture "sim-demo.toml") tag Nothing steps

-- | Run a temp scenario (built steps, optional rules) under any
-- fixture config.
runTempScenarioFull
  :: FilePath -> String -> Maybe [Json] -> [Json] -> IO CtlExit
runTempScenarioFull cfg tag mRules steps =
  bracket (writeTemp tag body) removeFile $ \path ->
    runCtl ["scenario", "run", "--config", cfg, "--scenario", path]
  where
    body = BC8.unpack
      (renderJson (scenarioWith ("scenario-" ++ tag) mRules steps))
    writeTemp t content = do
      base <- getTemporaryDirectory
      let path = base </> ("haskoki-sim-" ++ t ++ ".json")
      writeFile path content
      pure path

-- | The configured fault window seeds the runner (a step inside it
-- faults with no verb present), and a later fault.window verb
-- REPLACES the earlier one (the A-window step stays normal while
-- the B-window step faults).
caseFaultWindows :: IO ()
caseFaultWindows = do
  let openArgs async =
        [ ("token", JStr "haskoki-demo"), ("read_write", JBool True)
        , ("asynchronous", JBool async)
        ]
      loginArgs = [("session", JStr "s1"), ("role", JStr "USER"), ("pin", JStr "1234")]
      signArgs = [("session", JStr "s1"), ("data_base64", JStr "eA=="), ("output_capacity", JNum 256)]
      compArgs = [("session", JStr "s1"), ("function", JStr "C_Sign")]
  -- Seed: sign at index 5 sits in sim-demo's seeded (2,4) window.
  rSeed <- runTempScenario "seed"
    [ step "initialize" [] Nothing
    , step "fixture.load" [] Nothing
    , step "session.open" (openArgs True) Nothing
    , step "session.login" loginArgs Nothing
    , step "sign.init"
        [("session", JStr "s1"), ("fixture_key", JStr "demo-signing-key"), ("mechanism", JStr "CKM_RSA_PKCS")] Nothing
    , step "sign" signArgs (Just "CKR_DEVICE_ERROR")
    , step "finalize" [] Nothing
    ]
  assertEqual ("seed run exit 0: " ++ ceErr rSeed) 0 (ceCode rSeed)
  assertBool "seeded window faults step 5"
    ("step[5] sign -> CKR_DEVICE_ERROR" `isInfixOf` ceOut rSeed)
  -- Replace: A=(7,5) then B=(9,1); step 7 stays PENDING (A gone),
  -- step 9 faults (B live).
  rRepl <- runTempScenario "replace"
    [ step "initialize" [] Nothing
    , step "fixture.load" [] Nothing
    , step "session.open" (openArgs True) Nothing
    , step "session.login" loginArgs Nothing
    , step "sign.init"
        [("session", JStr "s1"), ("fixture_key", JStr "demo-signing-key"), ("mechanism", JStr "CKM_RSA_PKCS")] Nothing
    , step "fault.window" [("start", JNum 7), ("ticks", JNum 5)] Nothing
    , step "fault.window" [("start", JNum 9), ("ticks", JNum 1)] Nothing
    , step "sign" signArgs (Just "CKR_PENDING")
    , step "async.delay" [("session", JStr "s1"), ("polls", JNum 1)] Nothing
    , step "async.complete" compArgs (Just "CKR_DEVICE_ERROR")
    , step "async.complete" compArgs (Just "CKR_PENDING")
    , step "async.complete" compArgs (Just "CKR_PENDING")
    , step "async.complete" compArgs (Just "CKR_PENDING")
    , step "async.complete" compArgs (Just "CKR_OK")
    , step "finalize" [] Nothing
    ]
  assertEqual ("replace run exit 0: " ++ ceErr rRepl) 0 (ceCode rRepl)
  assertBool "A-window step stays normal"
    ("step[7] sign -> CKR_PENDING" `isInfixOf` ceOut rRepl)
  assertBool "B-window step faults"
    ("step[9] async.complete -> CKR_DEVICE_ERROR" `isInfixOf` ceOut rRepl)

-- ---------------------------------------------------------------------------
-- Sync guard (c)
-- ---------------------------------------------------------------------------

-- | GUARD: with pending/delay configuration present, a sync
-- session still signs immediately. Uses only long-known verbs.
-- The
-- sign sits at index 6, OUTSIDE sim-demo's seeded (2,4) fault
-- window: this pins delay-immunity, not fault-immunity (fault
-- windows fault by design; see 'caseFaultWindows').
caseSyncNeverPends :: IO ()
caseSyncNeverPends = do
  r <- runTempScenario "sync"
    [ step "initialize" [] Nothing
    , step "fixture.load" [] Nothing
    , step "session.open"
        [("token", JStr "haskoki-demo"), ("read_write", JBool True)] Nothing
    , step "session.open"
        [("token", JStr "haskoki-demo"), ("read_write", JBool True)] Nothing
    , step "session.login"
        [("session", JStr "s1"), ("role", JStr "USER"), ("pin", JStr "1234")] Nothing
    , step "sign.init"
        [("session", JStr "s1"), ("fixture_key", JStr "demo-signing-key"), ("mechanism", JStr "CKM_RSA_PKCS")] Nothing
    , step "sign"
        [("session", JStr "s1"), ("data_base64", JStr "eA=="), ("output_capacity", JNum 256)]
        (Just "CKR_OK")
    , step "finalize" [] Nothing
    ]
  assertEqual ("sync run exit 0: " ++ ceErr r) 0 (ceCode r)
  assertBool "sync sign immediate" ("step[6] sign -> CKR_OK" `isInfixOf` ceOut r)

-- ---------------------------------------------------------------------------
-- Strict scenario inputs (C4)
-- ---------------------------------------------------------------------------

-- | The runner never executes rules, so a nonempty list rejects at
-- load (unit + end-to-end); absent and empty rules validate.
caseRulesRejected :: IO ()
caseRulesRejected = do
  let bad = scenarioWith "c4-rules" (Just [JObj [("match", JNull)]])
        [JObj [("action", JStr "initialize")]]
  case validateScenario bad of
    Left err -> assertBool "names rules" ("rules" `isInfixOf` err)
    Right _ -> assertFailure "nonempty rules must reject"
  r <- runTempScenarioFull (fixture "maximal-demo.toml") "rulesrun"
    (Just [JObj [("match", JNull), ("effect", JNull)]])
    [step "initialize" [] Nothing, step "finalize" [] Nothing]
  assertEqual "rules refuse at load" 1 (ceCode r)
  assertBool "rejection named" ("scenario-rejected" `isInfixOf` ceErr r)
  let goodAbsent = scenarioWith "c4-rules" Nothing
        [JObj [("action", JStr "initialize")]]
  case validateScenario goodAbsent of
    Left err -> assertFailure ("absent rules must validate: " ++ err)
    Right sc -> assertEqual "no rules kept" [] (scRules sc)
  let goodEmpty = scenarioWith "c4-rules" (Just [])
        [JObj [("action", JStr "initialize")]]
  case validateScenario goodEmpty of
    Left err -> assertFailure ("empty rules must validate: " ++ err)
    Right sc -> assertEqual "no rules kept" [] (scRules sc)

-- | 'save_as' must be a non-empty string, and only 'session.open'
-- carries one (anywhere else it would be silently ignored).
caseSaveAsValidated :: IO ()
caseSaveAsValidated = do
  assertRejected "numeric save_as" (openWith [("save_as", JNum 1)])
  assertRejected "empty save_as" (openWith [("save_as", JStr "")])
  assertRejected "save_as on sign" (scenarioWith "c4-saveas" Nothing
    [JObj [("action", JStr "sign"), ("save_as", JStr "s9")]])
  case validateScenario (openWith [("save_as", JStr "alice")]) of
    Left err -> assertFailure ("session.open save_as must validate: " ++ err)
    Right sc -> assertEqual "one step" 1 (length (scSteps sc))
  where
    openWith extras = scenarioWith "c4-saveas" Nothing
      [JObj ([("action", JStr "session.open")] ++ extras)]

-- | 'expect' must be an object carrying the clause its action
-- produces ('return' everywhere except slot-event.wait, 'event'
-- only there); malformed and wrong-clause expects reject instead
-- of passing silently.
caseExpectValidated :: IO ()
caseExpectValidated = do
  assertRejected "non-object expect" (scenarioWith "c4-expect" Nothing
    [JObj [("action", JStr "sign"), ("arguments", JObj signArgs), ("expect", JStr "CKR_OK")]])
  assertRejected "non-string return" (scenarioWith "c4-expect" Nothing
    [JObj [("action", JStr "sign")
      , ("arguments", JObj signArgs), ("expect", JObj [("return", JNum 1)])]])
  assertRejected "event on initialize" (scenarioWith "c4-expect" Nothing
    [JObj [("action", JStr "initialize")
      , ("expect", JObj [("event", JStr "token-state-change")])]])
  assertRejected "return on slot-event.wait" (scenarioWith "c4-expect" Nothing
    [JObj [("action", JStr "slot-event.wait")
      , ("expect", JObj [("return", JStr "CKR_OK")])]])
  assertRejected "event on sign" (scenarioWith "c4-expect" Nothing
    [JObj [("action", JStr "sign")
      , ("arguments", JObj signArgs), ("expect", JObj [("event", JStr "token-state-change")])]])
  assertRejected "unknown expect key" (scenarioWith "c4-expect" Nothing
    [JObj [("action", JStr "sign")
      , ("arguments", JObj signArgs), ("expect", JObj [("return", JStr "CKR_OK"), ("trace", JBool True)])]])
  case validateScenario (scenarioWith "c4-expect" Nothing
    [ JObj [("action", JStr "initialize")
      , ("expect", JObj [("return", JStr "CKR_OK")])]
    , JObj [("action", JStr "sign")
      , ("arguments", JObj signArgs), ("expect", JObj [("return", JStr "CKR_OK")])]
    , JObj [("action", JStr "slot-event.wait")
      , ("expect", JObj [("event", JStr "token-state-change")])]
    ]) of
    Left err -> assertFailure ("well-formed expects must validate: " ++ err)
    Right sc -> assertEqual "three steps" 3 (length (scSteps sc))
  where
    signArgs = [("session", JStr "s1"), ("data_base64", JStr "eA=="), ("output_capacity", JNum 256)]

-- | Unknown step-level fields reject (the runner would ignore them).
caseStepFieldsRejected :: IO ()
caseStepFieldsRejected =
  assertRejected "unknown step field" (scenarioWith "c4-fields" Nothing
    [JObj [("action", JStr "initialize"), ("when", JStr "now")]])

-- | A scenario object with extra top-level fields.
scenarioTop :: String -> [(String, Json)] -> [Json] -> Json
scenarioTop name extras steps = JObj $
  [("name", JStr name)] ++ extras ++ [("steps", JArr steps)]

-- | A top-level 'note' object validates and changes nothing: the
-- noted scenario validates to the same value as the plain one.
caseTopNoteDropped :: IO ()
caseTopNoteDropped = do
  let steps = [JObj [("action", JStr "initialize")]]
      note = [("note", JObj [("status", JStr "sim-demo")
                      , ("notice", JStr "free prose")])]
  case (validateScenario (scenarioTop "noted" note steps)
       , validateScenario (scenarioWith "noted" Nothing steps)) of
    (Right noted, Right plain) ->
      assertEqual "note validates and is dropped" plain noted
    (Left err, _) -> assertFailure ("noted scenario must validate: " ++ err)
    (_, Left err) -> assertFailure ("plain scenario must validate: " ++ err)

-- | Unknown top-level fields reject, naming the field.
caseTopUnknownRejected :: IO ()
caseTopUnknownRejected = do
  let steps = [JObj [("action", JStr "initialize")]]
  assertRejected "top-level status"
    (scenarioTop "top" [("status", JStr "x")] steps)
  assertRejected "top-level notice"
    (scenarioTop "top" [("notice", JStr "x")] steps)
  assertRejected "top-level token"
    (scenarioTop "top" [("token", JStr "demo-token")] steps)
  case validateScenario (scenarioTop "top" [("status", JStr "x")] steps) of
    Left err -> assertBool "names the field" ("unknown scenario field: status" `isInfixOf` err)
    Right _ -> assertFailure "must reject"

-- | A non-object top-level 'note' rejects.
caseTopNoteShape :: IO ()
caseTopNoteShape =
  assertRejected "string note"
    (scenarioTop "top" [("note", JStr "prose")] [JObj [("action", JStr "initialize")]])

-- | 'schema_version' is optional but admits only 1.
caseTopSchemaVersion :: IO ()
caseTopSchemaVersion = do
  let steps = [JObj [("action", JStr "initialize")]]
  case validateScenario (scenarioTop "top" [("schema_version", JNum 1)] steps) of
    Left err -> assertFailure ("schema_version 1 must validate: " ++ err)
    Right _ -> pure ()
  assertRejected "schema_version 2"
    (scenarioTop "top" [("schema_version", JNum 2)] steps)

-- | An unknown mechanism refuses at load, naming the value.
caseMechanismRefused :: IO ()
caseMechanismRefused = do
  let bad = scenarioWith "mech" Nothing [JObj [("action", JStr "sign.init")
        , ("arguments", JObj [("session", JStr "s1")
          , ("fixture_key", JStr "demo-signing-key")
          , ("mechanism", JStr "NO_SUCH_MECHANISM")])]]
  assertRejected "unknown mechanism" bad
  case validateScenario bad of
    Left err -> do
      assertBool "names the value"
        ("unknown mechanism 'NO_SUCH_MECHANISM'" `isInfixOf` err)
      assertBool "names the action"
        ("for action 'sign.init'" `isInfixOf` err)
    Right _ -> assertFailure "must reject"

-- | An unknown fixture key refuses at load, naming the reason.
caseFixtureKeyRefused :: IO ()
caseFixtureKeyRefused = do
  let bad = scenarioWith "key" Nothing [JObj [("action", JStr "sign.init")
        , ("arguments", JObj [("session", JStr "s1")
          , ("fixture_key", JStr "no-such-key")
          , ("mechanism", JStr "CKM_RSA_PKCS")])]]
  assertRejected "unknown fixture key" bad
  case validateScenario bad of
    Left err -> do
      assertBool "names the key and value"
        ("unsupported fixture_key 'no-such-key'" `isInfixOf` err)
      assertBool "names the action"
        ("for action 'sign.init'" `isInfixOf` err)
    Right _ -> assertFailure "must reject"

-- | Malformed base64 refuses at load, each shape naming the reason.
caseBase64Refused :: IO ()
caseBase64Refused = do
  let bad tag payload = do
        let sc = scenarioWith "b64" Nothing [JObj [("action", JStr "sign")
              , ("arguments", JObj [("session", JStr "s1")
                , ("data_base64", JStr payload), ("output_capacity", JNum 256)])]]
        assertRejected tag sc
        case validateScenario sc of
          Left err -> assertBool ("names the reason: " ++ tag)
            ("must be strict base64" `isInfixOf` err)
          Right _ -> assertFailure "must reject"
  bad "odd length" "eA"
  bad "bad alphabet" "****"
  bad "mid padding" "eA==eA=="
  bad "over padding" "eA==="
  bad "data after pad" "AB=C"
  bad "non-canonical trailing bits" "eB=="

-- | Out-of-range capacities refuse at load, naming the range.
caseCapacityRefused :: IO ()
caseCapacityRefused = do
  let cap tag n = assertRejected tag
        (scenarioWith "cap" Nothing [JObj [("action", JStr "sign")
          , ("arguments", JObj [("session", JStr "s1")
            , ("data_base64", JStr "eA=="), ("output_capacity", JNum n)])]])
  cap "negative" (-1)
  cap "over 16 MiB" 16777217
  case validateScenario (scenarioWith "cap" Nothing [JObj [("action", JStr "sign")
      , ("arguments", JObj [("session", JStr "s1")
        , ("data_base64", JStr "eA=="), ("output_capacity", JNum (-1))])]]) of
    Left err -> assertBool "names the range" ("0..16777216" `isInfixOf` err)
    Right _ -> assertFailure "must reject"

-- | A foreign async function refuses at load, naming the reason.
caseFunctionRefused :: IO ()
caseFunctionRefused = do
  let bad = scenarioWith "fn" Nothing [JObj [("action", JStr "async.complete")
        , ("arguments", JObj [("session", JStr "s1")
          , ("function", JStr "C_Encrypt")])]]
  assertRejected "foreign function" bad
  case validateScenario bad of
    Left err -> do
      assertBool "names the value"
        ("unsupported function 'C_Encrypt'" `isInfixOf` err)
      assertBool "names the action"
        ("for action 'async.complete'" `isInfixOf` err)
    Right _ -> assertFailure "must reject"

-- | An unknown login role refuses at load, naming the reason.
caseRoleRefused :: IO ()
caseRoleRefused = do
  let bad = scenarioWith "role" Nothing [JObj [("action", JStr "session.login")
        , ("arguments", JObj [("session", JStr "s1")
          , ("role", JStr "ADMIN"), ("pin", JStr "1234")])]]
  assertRejected "unknown role" bad
  case validateScenario bad of
    Left err -> do
      assertBool "names the value"
        ("unsupported role 'ADMIN'" `isInfixOf` err)
      assertBool "names the action"
        ("for action 'session.login'" `isInfixOf` err)
    Right _ -> assertFailure "must reject"

-- | A read-only open refuses at load: the simulator models
-- read-write sessions only.
caseReadOnlyRefused :: IO ()
caseReadOnlyRefused = do
  let bad = scenarioWith "ro" Nothing [JObj [("action", JStr "session.open")
        , ("arguments", JObj [("read_write", JBool False)])]]
  assertRejected "read-only open" bad
  case validateScenario bad of
    Left err -> do
      assertBool "names the reason" ("must be true" `isInfixOf` err)
      assertBool "names the action"
        ("for action 'session.open'" `isInfixOf` err)
    Right _ -> assertFailure "must reject"

-- | Missing per-operation inputs refuse at load.
caseRequiredInputs :: IO ()
caseRequiredInputs = do
  assertRejected "login without pin"
    (scenarioWith "req" Nothing [JObj [("action", JStr "session.login")
      , ("arguments", JObj [("session", JStr "s1"), ("role", JStr "USER")])]])
  assertRejected "login without role"
    (scenarioWith "req" Nothing [JObj [("action", JStr "session.login")
      , ("arguments", JObj [("session", JStr "s1"), ("pin", JStr "1234")])]])
  assertRejected "init without mechanism"
    (scenarioWith "req" Nothing [JObj [("action", JStr "sign.init")
      , ("arguments", JObj [("session", JStr "s1")
        , ("fixture_key", JStr "demo-signing-key")])]])
  assertRejected "init without fixture key"
    (scenarioWith "req" Nothing [JObj [("action", JStr "sign.init")
      , ("arguments", JObj [("session", JStr "s1")
        , ("mechanism", JStr "CKM_RSA_PKCS")])]])
  assertRejected "sign without capacity"
    (scenarioWith "req" Nothing [JObj [("action", JStr "sign")
      , ("arguments", JObj [("session", JStr "s1")
        , ("data_base64", JStr "eA==")])]])
  assertRejected "sign without data"
    (scenarioWith "req" Nothing [JObj [("action", JStr "sign")
      , ("arguments", JObj [("session", JStr "s1")
        , ("output_capacity", JNum 256)])]])
  assertRejected "complete without function"
    (scenarioWith "req" Nothing [JObj [("action", JStr "async.complete")
      , ("arguments", JObj [("session", JStr "s1")])]])

-- | The retired 'only_if_new_store' key refuses at load, naming
-- the reason.
caseRetiredKeyRefused :: IO ()
caseRetiredKeyRefused = do
  let bad = scenarioWith "ret" Nothing [JObj [("action", JStr "fixture.load")
        , ("arguments", JObj [("fixture", JStr "minimal-demo")
          , ("only_if_new_store", JBool True)])]]
  assertRejected "only_if_new_store retired" bad
  case validateScenario bad of
    Left err -> do
      assertBool "names the retired key"
        ("unknown argument 'only_if_new_store'" `isInfixOf` err)
      assertBool "names the action"
        ("for action 'fixture.load'" `isInfixOf` err)
    Right _ -> assertFailure "must reject"

-- | An unsupported fixture label refuses at load, naming the
-- supported label.
caseFixtureRefused :: IO ()
caseFixtureRefused = do
  let bad = scenarioWith "fix" Nothing [JObj [("action", JStr "fixture.load")
        , ("arguments", JObj [("fixture", JStr "other-demo")])]]
  assertRejected "unsupported fixture" bad
  case validateScenario bad of
    Left err -> do
      assertBool "names the value"
        ("unsupported fixture 'other-demo'" `isInfixOf` err)
      assertBool "names the supported label"
        ("(supported: minimal-demo)" `isInfixOf` err)
      assertBool "names the action"
        ("for action 'fixture.load'" `isInfixOf` err)
    Right _ -> assertFailure "must reject"

-- | An empty token label refuses at load wherever a label is given.
caseEmptyTokenRefused :: IO ()
caseEmptyTokenRefused = do
  assertRejected "empty open token"
    (scenarioWith "tok" Nothing [JObj [("action", JStr "session.open")
      , ("arguments", JObj [("token", JStr "")])]])
  assertRejected "empty remove token"
    (scenarioWith "tok" Nothing [JObj [("action", JStr "token.remove")
      , ("arguments", JObj [("token", JStr "")])]])

-- | The strict base64 length decoder accepts canonical shapes and
-- rejects malformed input, including non-canonical trailing bits.
caseBase64Shapes :: IO ()
caseBase64Shapes = do
  assertEqual "empty" (Just 0) (base64DecodedLength "")
  assertEqual "demo message" (Just 12) (base64DecodedLength "ZGVtbyBtZXNzYWdl")
  assertEqual "one pad" (Just 2) (base64DecodedLength "eGk=")
  assertEqual "two pads" (Just 1) (base64DecodedLength "eA==")
  assertEqual "odd length" Nothing (base64DecodedLength "eA")
  assertEqual "bad alphabet" Nothing (base64DecodedLength "****")
  assertEqual "mid padding" Nothing (base64DecodedLength "eA==eA==")
  assertEqual "data after pad" Nothing (base64DecodedLength "AB=C")
  assertEqual "canonical two-pad stays" (Just 1) (base64DecodedLength "Qg==")
  assertEqual "non-canonical two-pad bits" Nothing (base64DecodedLength "eB==")
  assertEqual "non-canonical one-pad bits" Nothing (base64DecodedLength "eGh=")
  assertEqual "non-canonical zero byte" Nothing (base64DecodedLength "AB==")

-- | Duplicate keys reject: lookup takes the first, so a second
-- entry would silently vanish (notably an empty 'rules' hiding a
-- nonempty one).
caseDuplicateFieldsRejected :: IO ()
caseDuplicateFieldsRejected = do
  assertRejected "duplicate rules" (JObj
    [ ("name", JStr "c4-dup")
    , ("rules", JArr [])
    , ("rules", JArr [JObj []])
    , ("steps", JArr [JObj [("action", JStr "initialize")]])
    ])
  assertRejected "duplicate step field" (scenarioWith "c4-dup" Nothing
    [JObj [("action", JStr "initialize"), ("action", JStr "finalize")]])
  assertRejected "duplicate argument" (scenarioWith "c4-dup" Nothing
    [JObj [("action", JStr "session.login")
      , ("arguments", JObj [("session", JStr "s1"), ("session", JStr "s2")])]])
  assertRejected "duplicate expect key" (scenarioWith "c4-dup" Nothing
    [JObj [("action", JStr "sign")
      , ("expect", JObj [("return", JStr "CKR_OK"), ("return", JStr "CKR_OK")])]])

-- | Per-action arguments validate before execution: unknown keys,
-- mistyped values, out-of-range integers, and empty session
-- references reject; the documented per-action shapes validate.
caseArgumentsValidated :: IO ()
caseArgumentsValidated = do
  assertRejected "unknown argument" (withArgs "sign" [("seesion", JStr "s1")])
  assertRejected "argument on bare verb"
    (withArgs "initialize" [("token", JStr "demo-token")])
  assertRejected "mistyped asynchronous"
    (withArgs "session.open" [("asynchronous", JStr "yes")])
  assertRejected "mistyped session"
    (withArgs "session.login" [("session", JNum 42)])
  assertRejected "mistyped nonblocking"
    (withArgs "slot-event.wait" [("nonblocking", JNum 1)])
  assertRejected "mistyped slot"
    (withArgs "token.insert" [("slot", JStr "5")])
  assertRejected "negative slot"
    (withArgs "token.insert" [("slot", JNum (-1))])
  assertRejected "oversized polls"
    (withArgs "async.delay" [("session", JStr "s1"), ("polls", JNum 1000001)])
  assertRejected "negative fault start"
    (withArgs "fault.window" [("start", JNum (-1)), ("ticks", JNum 1)])
  assertRejected "empty session"
    (withArgs "sign" [("session", JStr "")])
  assertRejected "insert without slot" (withArgs "token.insert" [])
  assertRejected "delay without polls"
    (withArgs "async.delay" [("session", JStr "s1")])
  assertRejected "window without ticks"
    (withArgs "fault.window" [("start", JNum 9)])
  assertRejected "window without start"
    (withArgs "fault.window" [("ticks", JNum 1)])
  case validateScenario (scenarioWith "c4-args" Nothing
    [withArgsStep "async.delay" [("polls", JNum 1)]]) of
    Left err -> assertFailure ("session defaults to s1: " ++ err)
    Right _ -> pure ()
  case validateScenario (scenarioWith "c4-args" Nothing
    [ withArgsStep "fixture.load"
        [("fixture", JStr "minimal-demo")]
    , withArgsStep "session.open"
        [("token", JStr "demo-token"), ("read_write", JBool True)
        , ("asynchronous", JBool True)]
    , withArgsStep "session.login"
        [("session", JStr "s1"), ("role", JStr "USER"), ("pin", JStr "1234")]
    , withArgsStep "sign.init"
        [("session", JStr "s1"), ("fixture_key", JStr "demo-signing-key")
        , ("mechanism", JStr "CKM_RSA_PKCS")]
    , withArgsStep "sign"
        [("session", JStr "s1"), ("data_base64", JStr "eA==")
        , ("output_capacity", JNum 256)]
    , withArgsStep "async.complete"
        [("session", JStr "s1"), ("function", JStr "C_Sign")]
    , withArgsStep "token.remove" [("token", JStr "demo-token")]
    , withArgsStep "slot-event.wait" [("nonblocking", JBool True)]
    , withArgsStep "token.insert" [("slot", JNum 5)]
    , withArgsStep "async.delay" [("session", JStr "s1"), ("polls", JNum 1)]
    , withArgsStep "fault.window" [("start", JNum 9), ("ticks", JNum 1)]
    ]) of
    Left err -> assertFailure ("documented shapes must validate: " ++ err)
    Right sc -> assertEqual "eleven steps" 11 (length (scSteps sc))
  where
    withArgsStep action args =
      JObj [("action", JStr action), ("arguments", JObj args)]
    withArgs action args = scenarioWith "c4-args" Nothing [withArgsStep action args]

-- | 'session.open' honors 'save_as': later steps address the saved
-- name (sync session under maximal-demo signs immediately).
caseSaveAsHonored :: IO ()
caseSaveAsHonored = do
  r <- runTempScenarioFull (fixture "maximal-demo.toml") "saveas" Nothing
    [ step "initialize" [] Nothing
    , step "fixture.load" [] Nothing
    , stepSaveAs "session.open"
        [("token", JStr "haskoki-demo"), ("read_write", JBool True)] "alice"
    , step "session.login"
        [("session", JStr "alice"), ("role", JStr "USER"), ("pin", JStr "1234")]
        Nothing
    , step "sign.init"
        [("session", JStr "alice"), ("fixture_key", JStr "demo-signing-key"), ("mechanism", JStr "CKM_RSA_PKCS")] Nothing
    , step "sign"
        [("session", JStr "alice"), ("data_base64", JStr "eA=="), ("output_capacity", JNum 256)] (Just "CKR_OK")
    , step "finalize" [] Nothing
    ]
  assertEqual ("save_as run exit 0: " ++ ceErr r) 0 (ceCode r)
  assertBool "saved session signs"
    ("step[5] sign -> CKR_OK" `isInfixOf` ceOut r)

-- | Session names are unique before execution: a 'save_as'
-- colliding with an earlier positional name, with an earlier
-- 'save_as', or with the live "s1" alias rejects at load.
caseSaveAsDuplicate :: IO ()
caseSaveAsDuplicate = do
  assertRejected "positional then save_as s1" (scenarioWith "c4-dupname" Nothing
    [ JObj [("action", JStr "session.open")]
    , JObj [("action", JStr "session.open"), ("save_as", JStr "s1")]
    ])
  assertRejected "repeated save_as" (scenarioWith "c4-dupname" Nothing
    [ JObj [("action", JStr "session.open"), ("save_as", JStr "zeta")]
    , JObj [("action", JStr "session.open"), ("save_as", JStr "zeta")]
    ])
  assertRejected "save_as s1 steals the alias" (scenarioWith "c4-dupname" Nothing
    [ JObj [("action", JStr "session.open"), ("save_as", JStr "zeta")]
    , JObj [("action", JStr "session.open"), ("save_as", JStr "s1")]
    ])
  case validateScenario (scenarioWith "c4-dupname" Nothing
    [ JObj [("action", JStr "session.open"), ("save_as", JStr "zeta")]
    , JObj [("action", JStr "session.open"), ("save_as", JStr "alpha")]
    ]) of
    Left err -> assertFailure ("distinct names must validate: " ++ err)
    Right _ -> pure ()
  r <- runTempScenarioFull (fixture "maximal-demo.toml") "savedup" Nothing
    [ step "initialize" [] Nothing
    , step "fixture.load" [] Nothing
    , step "session.open" [] Nothing
    , stepSaveAs "session.open" [] "s1"
    ]
  assertEqual "duplicate refuses" 1 (ceCode r)
  assertBool "refused at load" ("scenario-rejected" `isInfixOf` ceErr r)
  assertBool "duplicate named" ("duplicate session name" `isInfixOf` ceErr r)
  r2 <- runTempScenarioFull (fixture "maximal-demo.toml") "savedupalias" Nothing
    [ step "initialize" [] Nothing
    , step "fixture.load" [] Nothing
    , stepSaveAs "session.open" [] "zeta"
    , stepSaveAs "session.open" [] "s1"
    ]
  assertEqual "alias steal refuses" 1 (ceCode r2)
  assertBool "refused at load" ("scenario-rejected" `isInfixOf` ceErr r2)
  assertBool "duplicate named" ("duplicate session name" `isInfixOf` ceErr r2)

-- | A declared expectation that disagrees with the outcome fails the
-- run (async sign pends, so expecting CKR_OK must fail).
caseExpectEnforced :: IO ()
caseExpectEnforced = do
  r <- runTempScenario "wrongexpect"
    [ step "initialize" [] Nothing
    , step "fixture.load" [] Nothing
    , step "session.open" (openArgs True) Nothing
    , step "session.login" loginArgs Nothing
    , step "sign.init"
        [("session", JStr "s1"), ("fixture_key", JStr "demo-signing-key"), ("mechanism", JStr "CKM_RSA_PKCS")] Nothing
    , step "fault.window" [("start", JNum 100), ("ticks", JNum 0)] Nothing
    , step "sign" signArgs (Just "CKR_OK")
    ]
  assertEqual "mismatch fails" 1 (ceCode r)
  assertBool "mismatch named" ("expect.return mismatch" `isInfixOf` ceErr r)
  where
    openArgs async =
      [ ("token", JStr "haskoki-demo"), ("read_write", JBool True)
      , ("asynchronous", JBool async)
      ]
    loginArgs = [("session", JStr "s1"), ("role", JStr "USER"), ("pin", JStr "1234")]
    signArgs = [("session", JStr "s1"), ("data_base64", JStr "eA=="), ("output_capacity", JNum 256)]

-- | The "s1" alias resolves to the first-OPENED session, not the
-- first by name: zeta (async) opens before alpha (sync), so a sign
-- through s1 pends.
caseFirstOpenedAlias :: IO ()
caseFirstOpenedAlias = do
  r <- runTempScenarioFull (fixture "maximal-demo.toml") "alias" Nothing
    [ step "initialize" [] Nothing
    , step "fixture.load" [] Nothing
    , stepSaveAs "session.open" [("asynchronous", JBool True)] "zeta"
    , stepSaveAs "session.open" [("asynchronous", JBool False)] "alpha"
    , step "session.login"
        [("session", JStr "s1"), ("role", JStr "USER"), ("pin", JStr "1234")] Nothing
    , step "sign.init"
        [("session", JStr "s1"), ("fixture_key", JStr "demo-signing-key"), ("mechanism", JStr "CKM_RSA_PKCS")] Nothing
    , step "sign"
        [("session", JStr "s1"), ("data_base64", JStr "eA=="), ("output_capacity", JNum 256)] (Just "CKR_PENDING")
    , step "finalize" [] Nothing
    ]
  assertEqual ("alias run exit 0: " ++ ceErr r) 0 (ceCode r)
  assertBool "first-opened session signs"
    ("step[6] sign -> CKR_PENDING" `isInfixOf` ceOut r)

-- | A wrong expectation on 'initialize' fails the run, naming the
-- step, the action, and the expected vs actual results.
caseInitializeWrongExpectationFails :: IO ()
caseInitializeWrongExpectationFails = do
  r <- runTempScenarioFull (fixture "maximal-demo.toml") "wronginit" Nothing
    [ JObj [("action", JStr "initialize")
      , ("expect", JObj [("return", JStr "CKR_GENERAL_ERROR")])]
    ]
  assertEqual "mismatch fails" 1 (ceCode r)
  assertBool "step named" ("step[0]" `isInfixOf` ceErr r)
  assertBool "action named" ("initialize" `isInfixOf` ceErr r)
  assertBool "expected named" ("CKR_GENERAL_ERROR" `isInfixOf` ceErr r)
  assertBool "actual named" ("CKR_OK" `isInfixOf` ceErr r)

-- | Every verb's supported expectation enforces in one run: return
-- clauses on each CKR-reporting action, the event clause on the
-- slot wait (async sign pends, delay extends the poll count).
caseEveryVerbExpectation :: IO ()
caseEveryVerbExpectation = do
  r <- runTempScenario "everyverb"
    [ step "initialize" [] (Just "CKR_OK")
    , step "fixture.load" [] (Just "CKR_OK")
    , step "token.insert" [("slot", JNum 5)] (Just "CKR_OK")
    , step "session.open" (openArgs True) (Just "CKR_OK")
    , step "session.login" loginArgs (Just "CKR_OK")
    , step "sign.init"
        [("session", JStr "s1"), ("fixture_key", JStr "demo-signing-key"), ("mechanism", JStr "CKM_RSA_PKCS")] (Just "CKR_OK")
    , step "fault.window" [("start", JNum 100), ("ticks", JNum 0)] (Just "CKR_OK")
    , step "sign" signArgs (Just "CKR_PENDING")
    , step "async.delay" [("session", JStr "s1"), ("polls", JNum 1)] (Just "CKR_OK")
    , step "async.complete" compArgs (Just "CKR_PENDING")
    , step "async.complete" compArgs (Just "CKR_PENDING")
    , step "async.complete" compArgs (Just "CKR_PENDING")
    , step "async.complete" compArgs (Just "CKR_OK")
    , step "token.remove" [("token", JStr "haskoki-demo")] (Just "CKR_OK")
    , JObj [("action", JStr "slot-event.wait")
      , ("arguments", JObj [("nonblocking", JBool True)])
      , ("expect", JObj [("event", JStr "token-state-change")])]
    , step "finalize" [] (Just "CKR_OK")
    ]
  assertEqual ("every-verb run exit 0: " ++ ceErr r) 0 (ceCode r)
  assertBool "wait reports the event"
    ("step[14] slot-event.wait -> event:token-state-change" `isInfixOf` ceOut r)
  where
    openArgs async =
      [ ("token", JStr "haskoki-demo"), ("read_write", JBool True)
      , ("asynchronous", JBool async)
      ]
    loginArgs = [("session", JStr "s1"), ("role", JStr "USER"), ("pin", JStr "1234")]
    signArgs = [("session", JStr "s1"), ("data_base64", JStr "eA=="), ("output_capacity", JNum 256)]
    compArgs = [("session", JStr "s1"), ("function", JStr "C_Sign")]

-- | One scenario step builder with a 'save_as' name.
stepSaveAs :: String -> [(String, Json)] -> String -> Json
stepSaveAs action args name = JObj
  [("action", JStr action), ("arguments", JObj args), ("save_as", JStr name)]

-- | One scenario step builder with a 'note' object.
stepNote :: String -> [(String, Json)] -> [(String, Json)] -> Json
stepNote action args note = JObj
  [("action", JStr action), ("arguments", JObj args), ("note", JObj note)]

fullLogin :: [(String, Json)] -> [(String, Json)]
fullLogin rest = [("session", JStr "s1"), ("role", JStr "USER")] ++ rest

caseWrongPinExpected :: IO ()
caseWrongPinExpected = do
  let login pin expect = JObj [("action", JStr "session.login")
        , ("arguments", JObj (fullLogin [("pin", JStr pin)]))
        , ("expect", JObj [("return", JStr expect)])]
      prefix = [step "initialize" [] Nothing, step "fixture.load" [] Nothing
               , step "session.open" [] Nothing]
  r <- runTempScenario "badpin" (prefix ++ [login "0000" "CKR_PIN_INCORRECT"])
  assertEqual ("wrong PIN is an expected refusal: " ++ ceErr r) 0 (ceCode r)
  assertBool "refusal observed"
    ("session.login -> CKR_PIN_INCORRECT" `isInfixOf` ceOut r)
  r2 <- runTempScenario "badpinok" (prefix ++ [login "0000" "CKR_OK"])
  assertEqual "expecting OK fails" 1 (ceCode r2)
  assertBool "mismatch named" ("expect.return mismatch" `isInfixOf` ceErr r2)
  r3 <- runTempScenario "goodpin" (prefix ++ [login "1234" "CKR_OK"])
  assertEqual ("right PIN still passes: " ++ ceErr r3) 0 (ceCode r3)

caseTokenAbsent :: IO ()
caseTokenAbsent = do
  let open tok expect = JObj [("action", JStr "session.open")
        , ("arguments", JObj [("token", JStr tok)])
        , ("expect", JObj [("return", JStr expect)])]
      prefix = [step "initialize" [] Nothing, step "fixture.load" [] Nothing]
  r <- runTempScenario "notoken" (prefix ++ [open "missing" "CKR_TOKEN_NOT_PRESENT"])
  assertEqual ("absent token is an expected refusal: " ++ ceErr r) 0 (ceCode r)
  assertBool "detail echoes the label"
    ("token=missing" `isInfixOf` ceOut r)
  r2 <- runTempScenario "notokenok" (prefix ++ [open "missing" "CKR_OK"])
  assertEqual "expecting OK fails" 1 (ceCode r2)
  r3 <- runTempScenario "notedopen" (prefix
    ++ [stepNote "session.open" [] [("why", JStr "step annotation")]])
  assertEqual ("per-step note runs: " ++ ceErr r3) 0 (ceCode r3)

caseTokenRemoveAbsent :: IO ()
caseTokenRemoveAbsent = do
  let remove tok expect = JObj [("action", JStr "token.remove")
        , ("arguments", JObj [("token", JStr tok)])
        , ("expect", JObj [("return", JStr expect)])]
      prefix = [step "initialize" [] Nothing, step "fixture.load" [] Nothing]
  r <- runTempScenario "noremove" (prefix ++ [remove "missing" "CKR_TOKEN_NOT_PRESENT"])
  assertEqual ("absent remove target refuses: " ++ ceErr r) 0 (ceCode r)
  r2 <- runTempScenario "noremoveok" (prefix ++ [remove "missing" "CKR_OK"])
  assertEqual "expecting OK fails" 1 (ceCode r2)

caseCapacityZero :: IO ()
caseCapacityZero = do
  let signWith cap expect = JObj [("action", JStr "sign")
        , ("arguments", JObj [("session", JStr "s1")
          , ("data_base64", JStr "eA=="), ("output_capacity", JNum cap)])
        , ("expect", JObj [("return", JStr expect)])]
      prefix = [step "initialize" [] Nothing, step "fixture.load" [] Nothing
        , step "session.open" [("asynchronous", JBool False)] Nothing
        , step "session.login" [("session", JStr "s1"), ("role", JStr "USER")
          , ("pin", JStr "1234")] Nothing
        , step "sign.init" [("session", JStr "s1")
          , ("fixture_key", JStr "demo-signing-key")
          , ("mechanism", JStr "CKM_RSA_PKCS")] Nothing]
  r <- runTempScenarioFull (fixture "maximal-demo.toml") "zerocap" Nothing
    (prefix ++ [signWith 0 "CKR_BUFFER_TOO_SMALL"])
  assertEqual ("zero capacity answers too-small: " ++ ceErr r) 0 (ceCode r)
  r2 <- runTempScenarioFull (fixture "maximal-demo.toml") "zerocapok" Nothing
    (prefix ++ [signWith 0 "CKR_OK"])
  assertEqual "expecting OK fails" 1 (ceCode r2)
  r3 <- runTempScenarioFull (fixture "maximal-demo.toml") "sizedcap" Nothing
    (prefix ++ [signWith 256 "CKR_OK"])
  assertEqual ("sized capacity signs: " ++ ceErr r3) 0 (ceCode r3)
  assertBool "consumption echoed"
    (("bytes=1 capacity=256") `isInfixOf` ceOut r3)

-- | Steps before any initialize refuse; expecting OK for one fails
-- the run.
caseNotInitialized :: IO ()
caseNotInitialized = do
  r <- runTempScenario "noinit"
    [step "session.open" [] (Just "CKR_CRYPTOKI_NOT_INITIALIZED")]
  assertEqual ("pre-initialize step refuses: " ++ ceErr r) 0 (ceCode r)
  r2 <- runTempScenario "noinitok" [step "session.open" [] (Just "CKR_OK")]
  assertEqual "expecting OK fails" 1 (ceCode r2)

-- | A repeat initialize answers already-initialized; after finalize
-- a fresh initialize resets the runner.
caseDoubleInitialize :: IO ()
caseDoubleInitialize = do
  r <- runTempScenario "twiceinit"
    [ step "initialize" [] Nothing
    , step "initialize" [] (Just "CKR_CRYPTOKI_ALREADY_INITIALIZED")
    , step "session.open" [] (Just "CKR_OK") ]
  assertEqual ("repeat answers already-initialized: " ++ ceErr r) 0 (ceCode r)
  r2 <- runTempScenario "reinit"
    [ step "initialize" [] Nothing, step "finalize" [] Nothing
    , step "initialize" [] (Just "CKR_OK")
    , step "session.open" [] (Just "CKR_OK") ]
  assertEqual ("re-initialize after finalize resets: " ++ ceErr r2) 0 (ceCode r2)

-- | Steps after finalize refuse, and so does a repeated finalize.
casePostFinalize :: IO ()
casePostFinalize = do
  r <- runTempScenario "postfin"
    [ step "initialize" [] Nothing, step "finalize" [] Nothing
    , step "session.open" [] (Just "CKR_CRYPTOKI_NOT_INITIALIZED") ]
  assertEqual ("post-finalize use refuses: " ++ ceErr r) 0 (ceCode r)
  r2 <- runTempScenario "twicefin"
    [ step "initialize" [] Nothing, step "finalize" [] Nothing
    , step "finalize" [] (Just "CKR_CRYPTOKI_NOT_INITIALIZED") ]
  assertEqual ("repeated finalize refuses: " ++ ceErr r2) 0 (ceCode r2)

-- | Signing without a logged-in session refuses instead of arming.
caseLoginRequired :: IO ()
caseLoginRequired = do
  let initArgs = [("session", JStr "s1"), ("fixture_key", JStr "demo-signing-key")
        , ("mechanism", JStr "CKM_RSA_PKCS")]
  r <- runTempScenario "unsigned"
    [ step "initialize" [] Nothing, step "fixture.load" [] Nothing
    , step "session.open" [] Nothing
    , JObj [("action", JStr "sign.init"), ("arguments", JObj initArgs)
      , ("expect", JObj [("return", JStr "CKR_USER_NOT_LOGGED_IN")])] ]
  assertEqual ("signing without login refuses: " ++ ceErr r) 0 (ceCode r)

-- | A logged-in sign.init arms the session and echoes the consumed
-- mechanism and key in its step line.
caseArmedEcho :: IO ()
caseArmedEcho = do
  r <- runTempScenario "armed"
    [ step "initialize" [] Nothing, step "fixture.load" [] Nothing
    , step "session.open" [] Nothing
    , step "session.login" [("session", JStr "s1"), ("role", JStr "USER")
      , ("pin", JStr "1234")] Nothing
    , step "sign.init" [("session", JStr "s1")
      , ("fixture_key", JStr "demo-signing-key")
      , ("mechanism", JStr "CKM_RSA_PKCS")] (Just "CKR_OK") ]
  assertEqual ("arming run passes: " ++ ceErr r) 0 (ceCode r)
  assertBool "armed pair echoed"
    ("mechanism=CKM_RSA_PKCS key=demo-signing-key" `isInfixOf` ceOut r)
