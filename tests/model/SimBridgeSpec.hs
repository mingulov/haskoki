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
  , startJob
  )
import Haskoki.Runtime.Config
  ( Config (..)
  , SimCfg (..)
  , defaultConfig
  )
import Haskoki.Runtime.Control
  ( ControlState
  , Json (..)
  , Scenario (..)
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
  , jrWork = WorkCall
      (Reservation "bridge" [] Nothing Nothing)
      (EffectCrypto (FxSign mech Nothing BS.empty "hello"))
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
  eJid <- startJob table (bridgeRequest sid (MechanismId 0x1) 5)
  jid <- case eJid of
    Left deny -> assertFailure ("start refused: " ++ show deny)
    Right j -> pure j
  (code, body, _) <- dispatchControl st (advanceReq 5) (Just 65536)
  assertEqual "advance ok" CKR_OK code
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
  eJid <- startJob table (bridgeRequest sid mech ticks)
  jid <- case eJid of
    Left deny -> assertFailure ("start refused: " ++ show deny)
    Right j -> pure j
  (code, _, _) <- dispatchControl st (advanceReq adv) (Just 65536)
  assertEqual "advance ok" CKR_OK code
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

-- | The three new verbs validate as scenario actions.
caseVerbsValidate :: IO ()
caseVerbsValidate = do
  let sc = JObj
        [ ("name", JStr "verbs")
        , ("steps", JArr [verbStep "token.insert", verbStep "async.delay", verbStep "fault.window"])
        ]
  case validateScenario sc of
    Left err -> assertFailure ("verbs must validate: " ++ err)
    Right v -> assertEqual "three steps" 3 (length (scSteps v))
  where
    verbStep a = JObj [("action", JStr a)]

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

-- | Run a temp scenario (built steps) under sim-demo.toml.
runTempScenario :: String -> [Json] -> IO CtlExit
runTempScenario tag steps =
  bracket (writeTemp tag body) removeFile $ \path ->
    runCtl ["scenario", "run", "--config", fixture "sim-demo.toml", "--scenario", path]
  where
    body = BC8.unpack (renderJson (JObj [("name", JStr ("scenario-" ++ tag)), ("steps", JArr steps)]))
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
        [ ("token", JStr "demo-token"), ("read_write", JBool True)
        , ("asynchronous", JBool async)
        ]
      loginArgs = [("session", JStr "s1"), ("role", JStr "USER"), ("pin", JStr "1234")]
      signArgs = [("session", JStr "s1"), ("data_base64", JStr "eA"), ("output_capacity", JNum 256)]
      compArgs = [("session", JStr "s1"), ("function", JStr "C_Sign")]
  -- Seed: sign at index 5 sits in sim-demo's seeded (2,4) window.
  rSeed <- runTempScenario "seed"
    [ step "initialize" [] Nothing
    , step "fixture.load" [] Nothing
    , step "session.open" (openArgs True) Nothing
    , step "session.login" loginArgs Nothing
    , step "sign.init" [("session", JStr "s1")] Nothing
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
    , step "sign.init" [("session", JStr "s1")] Nothing
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
        [("token", JStr "demo-token"), ("read_write", JBool True)] Nothing
    , step "session.open"
        [("token", JStr "demo-token"), ("read_write", JBool True)] Nothing
    , step "session.login"
        [("session", JStr "s1"), ("role", JStr "USER"), ("pin", JStr "1234")] Nothing
    , step "sign.init" [("session", JStr "s1")] Nothing
    , step "sign"
        [("session", JStr "s1"), ("data_base64", JStr "eA"), ("output_capacity", JNum 256)]
        (Just "CKR_OK")
    , step "finalize" [] Nothing
    ]
  assertEqual ("sync run exit 0: " ++ ceErr r) 0 (ceCode r)
  assertBool "sync sign immediate" ("step[6] sign -> CKR_OK" `isInfixOf` ceOut r)
