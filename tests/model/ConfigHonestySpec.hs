{- | Config-honesty contracts: every known knob is ENFORCED
(validated or behavior-selecting, with a behavior contract test),
refused with an exact error (parseable-but-dishonest values fail
loudly at parse, hence at startup), or CONFIG-NOT-POLICY
(documented reserved, with a doc-claim test proving the doc).

Layout: one group per knob family, review-proposed never-knobs,
dogfood + startup refusal, catalog audit. Startup-NULL pins live
in the engine suite ('FfiAcquireSpec', next to
'caseCryptoEnvGarbage') because
this suite mutates @HASKOKI_CONFIG@ process-wide.
-}
{-# LANGUAGE OverloadedStrings #-}
module ConfigHonestySpec (spec) where

import Control.Exception (bracket)
import qualified Data.ByteString.Char8 as BC8
import Data.List (isInfixOf)
import System.Directory (doesFileExist, getTemporaryDirectory, removeFile)
import System.FilePath ((</>))
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Ctl (CtlExit (..), runCtl)
import Haskoki.FFI.Instance (Instance (..), buildInstance)
import Haskoki.Model (Model (..), addToken, emptyModel, lookupSession)
import Haskoki.Operation (CryptoEffect (..))
import Haskoki.Outcome (EffectRequest (..), PlanResult (..), PreparedCommit (..), Rejection (..), Reservation (..))
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request (FunctionId (..), Request (..))
import Haskoki.Rules (Rules (..))
import Haskoki.Runtime.Config
import Haskoki.Runtime.Async
  ( AsyncWork (..)
  , JobFunction (..)
  , JobRequest (..)
  , StartDeny (..)
  , enableAsyncSession
  , newAsyncTable
  , startJob
  )
import Haskoki.Runtime.Control (ControlState, Json (..), dispatchControl, newControlState, renderJson)
import Haskoki.Runtime.Events
  ( OverflowPolicy (DropOldest)
  , droppedEvents
  , insertToken
  , newEventQueue
  , newTokenRegistry
  )
import Haskoki.Runtime.Lifecycle (rulesFromConfig)
import Haskoki.Transition (planCall, publishDelta)
import Haskoki.Types (Pkcs11Version (..), ReturnCode (..), SessionId (..), SlotId (..))
import Haskoki.Runtime.Trace (DrainReport (..), TraceEvent (..), drainTracer, droppedTraces, emitTrace)

spec :: TestTree
spec = testGroup "Config honesty"
  [ testGroup "top-level"
    [ testCase "seed: non-default refused" caseSeedRefused
    , testCase "seed: default accepted" caseSeedDefault
    , testCase "schema_version: non-1 refused" caseSchemaRefused
    , testCase "profile: unknown refused" caseProfileRefused
    , testCase "interfaces: bad member refused" caseInterfacesBad
    , testCase "interfaces: empty refused" caseInterfacesEmpty
    , testCase "interfaces: declared set reported" caseInterfacesReported
    ]
  , testGroup "storage"
    [ testCase "storage.kind: unknown refused" caseStorageKindBad
    , testCase "storage.path: memory-plus-path refused" caseStoragePathMemory
    , testCase "storage.busy_timeout_ms: non-default refused" caseBusyRefused
    , testCase "storage.busy_timeout_ms: default accepted" caseBusyDefault
    , testCase "storage.exclusive_provider_ownership: false refused" caseExclRefused
    , testCase "storage.exclusive_provider_ownership: true accepted" caseExclTrue
    ]
  , testGroup "engine"
    [ testCase "engine.kind: unknown refused" caseEngineKindBad
    , testCase "engine.allow_synthetic_fallback: true refused" caseFallbackRefused
    , testCase "engine.allow_synthetic_fallback: false accepted" caseFallbackFalse
    , testCase "engine.private_library_context: false refused" casePrivCtxRefused
    , testCase "engine.private_library_context: default is true" casePrivCtxDefault
    , testCase "engine.private_library_context: true accepted" casePrivCtxTrue
    ]
  , testGroup "async"
    [ testCase "async.executor: non-logical refused" caseExecutorBad
    , testCase "async.enabled: false never pends" caseAsyncDisabled
    , testCase "async.enabled: true pends" caseAsyncEnabled
    , testCase "async.pending_polls: counts pending completes" casePendingPolls
    , testCase "async.persist_detached: both values parse (reserved)" casePersistParses
    , testCase "async.persist_detached: disclosed in capabilities" casePersistDisclosed
    ]
  , testGroup "trace"
    [ testCase "trace.enabled: false writes nothing" caseTraceDisabled
    , testCase "trace.path: enabled writes the file" caseTracePath
    , testCase "trace.queue_limit: bounds the queue" caseQueueLimit
    , testCase "trace.redact_secrets: false refused" caseRedactRefused
    , testCase "trace.redact_secrets: true accepted" caseRedactTrue
    ]
  , testGroup "control"
    [ testCase "control.enabled: false refused" caseCtlEnabledRefused
    , testCase "control.enabled: true accepted" caseCtlEnabledTrue
    , testCase "control.max_request_bytes: oversize refused" caseMaxRequest
    , testCase "control.response_budget_bytes: non-65536 refused" caseBudgetRefused
    ]
  , testGroup "fixtures"
    [ testCase "fixtures.set: non-default refused" caseFixSetRefused
    , testCase "fixtures.apply: non-default refused" caseFixApplyRefused
    , testCase "fixtures: defaults accepted" caseFixDefaults
    ]
  , testGroup "limits"
    [ testCase "limits.sessions: tracks enforcement" caseSessionsTrack
    , testCase "limits.jobs: bounds the async table" caseJobsBound
    , testCase "limits.events: bounds the event queue" caseEventsBound
    , testCase "limits: zero refused" caseLimitsZero
    , testCase "limits.reserved: parse (no enforcement)" caseReservedParse
    , testCase "limits.reserved: disclosed in capabilities" caseReservedDisclosed
    ]
  , testGroup "never-knobs"
    [ testCase "seclevel refused as unknown" caseSeclevelUnknown
    , testCase "max-tls refused as unknown" caseMaxTlsUnknown
    , testCase "native-engine knob refused as unknown" caseNativeEngineUnknown
    , testCase "admission section refused as unknown" caseAdmissionUnknown
    , testCase "async.max-queue refused as unknown" caseMaxQueueUnknown
    , testCase "async.waiters refused as unknown" caseWaitersUnknown
    ]
  , testGroup "dogfood"
    [ testCase "dogfood: defaultConfig is honest" caseDogfoodDefault
    , testCase "dogfood: all fixtures honest" caseDogfoodFixtures
    , testCase "refusal: dishonest file fails resolve" caseStartupRefusalResolve
    , testCase "refusal: config check rejects dishonesty" caseStartupRefusalCheck
    ]
  , testGroup "audit"
    [ testCase "catalog names every reserved knob" caseAuditReserved
    , testCase "catalog names every never-knob" caseAuditNeverKnobs
    , testCase "catalog names every refusal rule" caseAuditRefusals
    , testCase "catalog carries the dogfood matrix" caseAuditDogfood
    ]
  ]

-- | 30s backstop for every IO case (no-wedge rule).
withTimeout :: String -> IO a -> IO a
withTimeout what action = do
  mR <- timeout 30000000 action
  case mR of
    Nothing -> assertFailure ("wedge detected: " ++ what) >> error "unreachable"
    Just r -> pure r

fixture :: FilePath -> FilePath
fixture name = "tests/ops/fixtures/" ++ name

-- ---------------------------------------------------------------------------
-- Top-level
-- ---------------------------------------------------------------------------

-- | @seed@ has no reader (repo-wide grep: only 'Config.hs'
-- defines/stores it; nothing selects behavior by it), so any
-- non-default value promises determinism control that does not
-- exist. Previously parsed fine (Right).
caseSeedRefused :: IO ()
caseSeedRefused =
  case parseConfig "schema_version = 1\nseed = 42\n" of
    Left (CfgInvalid msg) -> assertEqual "exact refusal" seedMsg msg
    other -> assertFailure ("non-default seed must be refused, got: " ++ show other)
  where
    seedMsg = "seed is reserved (no determinism seeding reads it yet): the only accepted value is 1234"

caseSeedDefault :: IO ()
caseSeedDefault =
  case parseConfig "schema_version = 1\nseed = 1234\n" of
    Right cfg -> assertEqual "seed default" 1234 (cfgSeed cfg)
    other -> assertFailure ("default seed must parse, got: " ++ show other)

-- | ENFORCED-by-validation: schema_version /= 1 errors.
caseSchemaRefused :: IO ()
caseSchemaRefused =
  case parseConfig "schema_version = 2\n" of
    Left (CfgInvalid msg) ->
      assertEqual "exact refusal" "unsupported schema_version: 2" msg
    other -> assertFailure ("schema_version=2 must be refused, got: " ++ show other)

-- | ENFORCED-by-validation: unknown profile errors (reported half
-- is pinned by CtlSpec caseCapabilities "names the profile").
caseProfileRefused :: IO ()
caseProfileRefused =
  case parseConfig "schema_version = 1\nprofile = \"prod\"\n" of
    Left (CfgInvalid msg) ->
      assertEqual "exact refusal" "unknown profile: prod" msg
    other -> assertFailure ("unknown profile must be refused, got: " ++ show other)

-- | ENFORCED-by-validation: interfaces must be a non-empty subset
-- of 2.40/3.0/3.1/3.2. Scope note (S2b): the declared set is
-- validated + reported, but no native path gates behavior on it
-- (repo-wide grep: only Ctl reporting reads 'cfgInterfaces');
-- see docs/config-honesty.md.
caseInterfacesBad :: IO ()
caseInterfacesBad =
  case parseConfig "schema_version = 1\ninterfaces = [\"9.9\"]\n" of
    Left (CfgInvalid _) -> pure ()
    other -> assertFailure ("bad interfaces member must be refused, got: " ++ show other)

caseInterfacesEmpty :: IO ()
caseInterfacesEmpty =
  case parseConfig "schema_version = 1\ninterfaces = []\n" of
    Left (CfgInvalid _) -> pure ()
    other -> assertFailure ("empty interfaces must be refused, got: " ++ show other)

caseInterfacesReported :: IO ()
caseInterfacesReported = withTimeout "capabilities run" $ do
  r <- runCtl ["capabilities", "--config", fixture "maximal-demo.toml"]
  assertEqual "exit 0" 0 (ceCode r)
  assertBool "declared set reported"
    ("interfaces: 2.40 3.0 3.1 3.2" `isInfixOf` ceOut r)

-- ---------------------------------------------------------------------------
-- Storage
-- ---------------------------------------------------------------------------

-- | ENFORCED: kind routes the store ('openStdStore': memory opens
-- transient, sqlite opens the explicit path). Routing behavior is
-- pinned by FfiAsyncSpec caseStdSuccess/caseStdBadSqlite; the
-- sqlite-requires-path half by ConfigSpec caseNoSilentShare.
caseStorageKindBad :: IO ()
caseStorageKindBad =
  case parseConfig "schema_version = 1\n[storage]\nkind = \"nfs\"\n" of
    Left (CfgInvalid msg) ->
      assertEqual "exact refusal" "unknown storage.kind: nfs" msg
    other -> assertFailure ("unknown storage.kind must be refused, got: " ++ show other)

-- | Memory ignores 'scPath' ('openStdStore' memory arm), so an
-- explicit path with kind=memory is a silent ignore.
-- Previously accepted silently.
caseStoragePathMemory :: IO ()
caseStoragePathMemory =
  case parseConfig (unlines ["schema_version = 1", "[storage]", "kind = \"memory\"", "path = \"./x.db\""]) of
    Left (CfgInvalid msg) -> assertEqual "exact refusal" pathMsg msg
    other -> assertFailure ("memory-plus-path must be refused, got: " ++ show other)
  where
    pathMsg = "storage.path is only meaningful with storage.kind=sqlite (memory ignores it; refusing rather than silently ignoring)"

-- | SQLite opens with a pinned @PRAGMA busy_timeout = 5000@
-- ('Storage.SQLite', no knob read), so any other value is a false
-- tuning promise. Previously parsed fine.
caseBusyRefused :: IO ()
caseBusyRefused =
  case parseConfig (unlines ["schema_version = 1", "[storage]", "busy_timeout_ms = 100"]) of
    Left (CfgInvalid msg) -> assertEqual "exact refusal" busyMsg msg
    other -> assertFailure ("non-default busy_timeout_ms must be refused, got: " ++ show other)
  where
    busyMsg = "storage.busy_timeout_ms is not honored (SQLite opens with the pinned 5000ms busy timeout): the only accepted value is 5000"

caseBusyDefault :: IO ()
caseBusyDefault =
  case parseConfig (unlines ["schema_version = 1", "[storage]", "busy_timeout_ms = 5000"]) of
    Right cfg -> assertEqual "busy default" 5000 (scBusyTimeoutMs (cfgStorage cfg))
    other -> assertFailure ("default busy_timeout_ms must parse, got: " ++ show other)

-- | The store is always single-writer with O_EXCL create
-- ('Storage.SQLite' exclusive flags + the Standard "second open
-- fails loudly" rule), so @false@ promises sharing that never
-- happens. Previously parsed fine.
caseExclRefused :: IO ()
caseExclRefused =
  case parseConfig (unlines ["schema_version = 1", "[storage]", "exclusive_provider_ownership = false"]) of
    Left (CfgInvalid msg) -> assertEqual "exact refusal" exclMsg msg
    other -> assertFailure ("exclusive=false must be refused, got: " ++ show other)
  where
    exclMsg = "storage.exclusive_provider_ownership=false is not supported (the store is always single-writer with O_EXCL create): must be true"

caseExclTrue :: IO ()
caseExclTrue =
  case parseConfig (unlines ["schema_version = 1", "[storage]", "exclusive_provider_ownership = true"]) of
    Right cfg -> assertEqual "exclusive true" True (scExclusiveOwnership (cfgStorage cfg))
    other -> assertFailure ("exclusive=true must parse, got: " ++ show other)

-- ---------------------------------------------------------------------------
-- Engine (knobs + never-knobs)
-- ---------------------------------------------------------------------------

-- | ENFORCED: kind validates + observably selects the reported
-- active catalog (CtlSpec caseCapabilities: 109 synthetic vs 107
-- openssl rows). Headline answer (S2a): NOTHING routes native
-- backends by engine.kind — all four native opens bind
-- @BackendEnv OpenSSL4@ ('Standard.hs' engine-policy doc,
-- CtlSpec caseNativeScope); kind describes the configured engine
-- only, disclosed by the native-engine report line.
caseEngineKindBad :: IO ()
caseEngineKindBad =
  case parseConfig (unlines ["schema_version = 1", "[engine]", "kind = \"boringssl\""]) of
    Left (CfgInvalid msg) ->
      assertEqual "exact refusal" "unknown engine.kind: boringssl" msg
    other -> assertFailure ("unknown engine.kind must be refused, got: " ++ show other)

-- | No synthetic-fallback logic exists on any path (repo-wide
-- grep: the accessor is never read), so @true@ promises a crypto
-- fallback that cannot happen. Previously parsed fine.
caseFallbackRefused :: IO ()
caseFallbackRefused =
  case parseConfig (unlines ["schema_version = 1", "[engine]", "allow_synthetic_fallback = true"]) of
    Left (CfgInvalid msg) -> assertEqual "exact refusal" fallbackMsg msg
    other -> assertFailure ("fallback=true must be refused, got: " ++ show other)
  where
    fallbackMsg = "engine.allow_synthetic_fallback=true is not supported (no synthetic fallback exists on any path): must be false"

caseFallbackFalse :: IO ()
caseFallbackFalse =
  case parseConfig (unlines ["schema_version = 1", "[engine]", "allow_synthetic_fallback = false"]) of
    Right cfg -> assertEqual "fallback false" False (ecAllowSyntheticFallback (cfgEngine cfg))
    other -> assertFailure ("fallback=false must parse, got: " ++ show other)

-- | Native OpenSSL4 paths ALWAYS open a private OSSL_LIB_CTX
-- ('OpenSSL4.hs': one private libctx per 'BackendEnv'), so @false@
-- promises a shared context that never happens — and the old
-- default (@False@) was the dishonest value. The default is now
-- @True@ and @false@ is refused. Previously parsed fine (both).
casePrivCtxRefused :: IO ()
casePrivCtxRefused =
  case parseConfig (unlines ["schema_version = 1", "[engine]", "private_library_context = false"]) of
    Left (CfgInvalid msg) -> assertEqual "exact refusal" privMsg msg
    other -> assertFailure ("private_library_context=false must be refused, got: " ++ show other)
  where
    privMsg = "engine.private_library_context=false is not supported (native OpenSSL4 paths always open a private OSSL_LIB_CTX): must be true"

casePrivCtxDefault :: IO ()
casePrivCtxDefault =
  assertEqual "default is private" True (ecPrivateLibraryContext (cfgEngine defaultConfig))

casePrivCtxTrue :: IO ()
casePrivCtxTrue =
  case parseConfig (unlines ["schema_version = 1", "[engine]", "private_library_context = true"]) of
    Right cfg -> assertEqual "private true" True (ecPrivateLibraryContext (cfgEngine cfg))
    other -> assertFailure ("private_library_context=true must parse, got: " ++ show other)

-- ---------------------------------------------------------------------------
-- Async
-- ---------------------------------------------------------------------------

-- | ENFORCED-by-validation: only the logical executor exists.
caseExecutorBad :: IO ()
caseExecutorBad =
  case parseConfig (unlines ["schema_version = 1", "[async]", "executor = \"threads\""]) of
    Left (CfgInvalid msg) ->
      assertEqual "exact refusal" "async.executor must be \"logical\": threads" msg
    other -> assertFailure ("non-logical executor must be refused, got: " ++ show other)

-- | Temp config + temp scenario runners (unique tag per case; the
-- scenario path mirrors SimBridgeSpec, the config is minimal).
runTempAsync :: String -> Bool -> Int -> Int -> IO CtlExit
runTempAsync tag enabled polls completes = withTimeout ("scenario " ++ tag) $
  bracket (writeTemp (tag ++ ".toml") cfg) removeFile $ \cfgPath ->
    bracket (writeTemp (tag ++ ".json") scn) removeFile $ \scnPath ->
      runCtl ["scenario", "run", "--config", cfgPath, "--scenario", scnPath]
  where
    cfg = unlines
      [ "schema_version = 1"
      , "[async]"
      , "enabled = " ++ (if enabled then "true" else "false")
      , "pending_polls = " ++ show polls
      ]
    scn = BC8.unpack (renderJson (JObj [("name", JStr ("honesty-" ++ tag)), ("steps", JArr steps)]))
    steps =
      [ step "initialize" []
      , step "fixture.load" []
      , step "session.open"
          [ ("token", JStr "demo-token"), ("read_write", JBool True)
          , ("asynchronous", JBool True)
          ]
      , step "sign.init" [("session", JStr "s1")]
      , step "sign" [("session", JStr "s1")]
      ]
      ++ replicate completes (step "async.complete" [("session", JStr "s1"), ("function", JStr "C_Sign")])
    step action args = JObj [("action", JStr action), ("arguments", JObj args)]
    writeTemp name content = do
      base <- getTemporaryDirectory
      let path = base </> ("haskoki-" ++ name)
      writeFile path content
      pure path

pendingLines :: String -> [String]
pendingLines out = [ln | ln <- lines out, "CKR_PENDING" `isInfixOf` ln]

-- | ENFORCED: enabled=false never pends, even in an async session
-- ('Ctl.hs' wantPending). Scope note: the scenario runner reads
-- these knobs; native async paths do not consult them
-- (repo-wide grep); see docs/config-honesty.md.
caseAsyncDisabled :: IO ()
caseAsyncDisabled = do
  r <- runTempAsync "async-off" False 2 3
  assertEqual ("run exit 0: " ++ ceErr r) 0 (ceCode r)
  assertEqual "nothing pends" [] (pendingLines (ceOut r))

caseAsyncEnabled :: IO ()
caseAsyncEnabled = do
  r <- runTempAsync "async-on" True 2 3
  assertEqual ("run exit 0: " ++ ceErr r) 0 (ceCode r)
  assertEqual "sign + 2 completes pend" 3 (length (pendingLines (ceOut r)))

-- | ENFORCED: pending_polls counts the PENDING completes (polls+1
-- PENDING lines: the sign plus each complete).
casePendingPolls :: IO ()
casePendingPolls = do
  r <- runTempAsync "async-polls" True 5 7
  assertEqual ("run exit 0: " ++ ceErr r) 0 (ceCode r)
  assertEqual "sign + 5 completes pend" 6 (length (pendingLines (ceOut r)))

-- | CONFIG-NOT-POLICY: detached records always commit to the store
-- ('Detached.hs' detach path, unconditional 'storeCommit';
-- durability follows storage.kind), so the knob selects nothing —
-- but both values stay parseable (fixtures use both) with a loud
-- capabilities disclosure (reserved-knob shape).
casePersistParses :: IO ()
casePersistParses = do
  case parseConfig (unlines ["schema_version = 1", "[async]", "persist_detached = true"]) of
    Right _ -> pure ()
    other -> assertFailure ("persist=true must parse, got: " ++ show other)
  case parseConfig (unlines ["schema_version = 1", "[async]", "persist_detached = false"]) of
    Right _ -> pure ()
    other -> assertFailure ("persist=false must parse, got: " ++ show other)

casePersistDisclosed :: IO ()
casePersistDisclosed = withTimeout "capabilities run" $ do
  r <- runCtl ["capabilities", "--config", fixture "maximal-demo.toml"]
  assertEqual "exit 0" 0 (ceCode r)
  assertBool "reserved-async line present" (reservedAsyncLine `isInfixOf` ceOut r)
  where
    reservedAsyncLine = "reserved-async: persist_detached reserved (detached records always commit to the store; durability follows storage.kind, no knob effect)"

-- ---------------------------------------------------------------------------
-- Trace
-- ---------------------------------------------------------------------------

honestyEvent :: TraceEvent
honestyEvent = TraceEvent
  { teFunction = "C_Sign"
  , teInterface = "3.2"
  , teMechanism = Just "CKM_RSA_PKCS"
  , teSession = Just "s1"
  , teObject = Just "demo-signing-key"
  , teJob = Nothing
  , teInputLen = 12
  , teOutputLen = 256
  , teCkr = 0
  , teDisposition = "delivered"
  , teReason = "rule:none"
  , teMode = "sync"
  , teSecret = Nothing
  }

withTraceCfg :: String -> Bool -> FilePath -> Config
withTraceCfg _tag enabled path =
  defaultConfig { cfgTrace = (cfgTrace defaultConfig) { tcEnabled = enabled, tcPath = path } }

-- | ENFORCED: enabled=false writes nothing ('fileSink' no-op arm).
caseTraceDisabled :: IO ()
caseTraceDisabled = withTimeout "trace disabled" $ do
  base <- getTemporaryDirectory
  let path = base </> "haskoki-trace-off.jsonl"
  before <- doesFileExist path
  inst <- buildInstance (withTraceCfg "off" False path)
  _ <- emitTrace (instTracer inst) honestyEvent 0
  _ <- drainTracer (instTracer inst)
  after <- doesFileExist path
  assertEqual "no file before" False before
  assertEqual "no file after" False after

-- | ENFORCED: path selects the sink file ('fileSink' append arm).
caseTracePath :: IO ()
caseTracePath = withTimeout "trace path" $ do
  base <- getTemporaryDirectory
  let path = base </> "haskoki-trace-on.jsonl"
  inst <- buildInstance (withTraceCfg "on" True path)
  _ <- emitTrace (instTracer inst) honestyEvent 0
  rep <- drainTracer (instTracer inst)
  assertEqual "one line written" 1 (drWritten rep)
  body <- readFile path
  removeFile path
  assertBool "call recorded" ("C_Sign" `isInfixOf` body)

-- | ENFORCED: queue_limit bounds the tracer queue (overflow drops +
-- counts; the floor is @max 8@ at both build sites).
caseQueueLimit :: IO ()
caseQueueLimit = withTimeout "queue limit" $ do
  let small = defaultConfig
        { cfgLimits = (cfgLimits defaultConfig) { limEvents = 8, limJobs = 8 }
        , cfgTrace = (cfgTrace defaultConfig) { tcQueueLimit = 1 }
        }
  inst <- buildInstance small
  mapM_ (\_ -> emitTrace (instTracer inst) honestyEvent 0) [1 .. 9 :: Int]
  drops <- droppedTraces (instTracer inst)
  assertEqual "9 emits over bound 8 drop 1" 1 drops
  inst2 <- buildInstance defaultConfig
  mapM_ (\_ -> emitTrace (instTracer inst2) honestyEvent 0) [1 .. 9 :: Int]
  drops2 <- droppedTraces (instTracer inst2)
  assertEqual "9 emits under 4096 drop 0" 0 drops2

-- | Redaction is unconditional (the renderer + 'Show'
-- instances always redact; no knob read), so @false@ promises
-- visible secrets that never appear. Previously parsed fine.
caseRedactRefused :: IO ()
caseRedactRefused =
  case parseConfig (unlines ["schema_version = 1", "[trace]", "redact_secrets = false"]) of
    Left (CfgInvalid msg) -> assertEqual "exact refusal" redactMsg msg
    other -> assertFailure ("redact=false must be refused, got: " ++ show other)
  where
    redactMsg = "trace.redact_secrets=false is not supported (secrets are always redacted): must be true"

caseRedactTrue :: IO ()
caseRedactTrue =
  case parseConfig (unlines ["schema_version = 1", "[trace]", "redact_secrets = true"]) of
    Right cfg -> assertEqual "redact true" True (tcRedactSecrets (cfgTrace cfg))
    other -> assertFailure ("redact=true must parse, got: " ++ show other)

-- ---------------------------------------------------------------------------
-- Control
-- ---------------------------------------------------------------------------

-- | The control plane is always on (nothing reads
-- 'ccEnabled'; dispatch has no disabled arm), so @false@ promises
-- a closed control plane that stays open. Previously parsed fine.
caseCtlEnabledRefused :: IO ()
caseCtlEnabledRefused =
  case parseConfig (unlines ["schema_version = 1", "[control]", "enabled = false"]) of
    Left (CfgInvalid msg) -> assertEqual "exact refusal" ctlMsg msg
    other -> assertFailure ("control.enabled=false must be refused, got: " ++ show other)
  where
    ctlMsg = "control.enabled=false is not supported (the control plane is always on): must be true"

caseCtlEnabledTrue :: IO ()
caseCtlEnabledTrue =
  case parseConfig (unlines ["schema_version = 1", "[control]", "enabled = true"]) of
    Right cfg -> assertEqual "control on" True (ccEnabled (cfgControl cfg))
    other -> assertFailure ("control.enabled=true must parse, got: " ++ show other)

mkCtlState :: Config -> IO ControlState
mkCtlState cfg = withTimeout "control state" $ do
  eq <- newEventQueue 64 DropOldest
  at <- newAsyncTable 16
  reg <- newTokenRegistry eq at
  newControlState cfg reg at False False

-- | ENFORCED: requests past max_request_bytes refuse with
-- request_too_large ('dispatchControl'); smaller ones execute.
-- (@test_enabled@ enforcement is pinned by ControlSpec
-- caseTestGate + SimBridgeSpec caseVerbsGated.)
caseMaxRequest :: IO ()
caseMaxRequest = withTimeout "max request" $ do
  let tiny = defaultConfig
        { cfgControl = (cfgControl defaultConfig) { ccMaxRequestBytes = 64 } }
  st <- mkCtlState tiny
  let big = BC8.pack ("{\"schema_version\":1,\"command\":\"status\",\"arguments\":{},\"pad\":\"" ++ replicate 200 'x' ++ "\"}")
      small = BC8.pack "{\"schema_version\":1,\"command\":\"status\",\"arguments\":{}}"
  (codeBig, bodyBig, _) <- dispatchControl st big (Just 65536)
  assertEqual "oversize code" CKR_ARGUMENTS_BAD codeBig
  assertBool "oversize named" ("request_too_large" `isInfixOf` BC8.unpack bodyBig)
  (codeSmall, _, _) <- dispatchControl st small (Just 65536)
  assertEqual "small executes" CKR_OK codeSmall

-- | ENFORCED-by-validation: the §5.1 budget is fixed at 65536.
caseBudgetRefused :: IO ()
caseBudgetRefused =
  case parseConfig (unlines ["schema_version = 1", "[control]", "response_budget_bytes = 100"]) of
    Left (CfgInvalid msg) ->
      assertEqual "exact refusal" "control.response_budget_bytes is fixed at 65536 by the §5.1 protocol" msg
    other -> assertFailure ("non-65536 budget must be refused, got: " ++ show other)

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

-- | No fixture application reads these knobs (repo-wide grep:
-- only defaults + fixtures mention the values), so only the
-- documented placeholders are accepted. Previously parsed fine (both).
caseFixSetRefused :: IO ()
caseFixSetRefused =
  case parseConfig (unlines ["schema_version = 1", "[fixtures]", "set = \"full-demo\""]) of
    Left (CfgInvalid msg) -> assertEqual "exact refusal" fixSetMsg msg
    other -> assertFailure ("non-default fixtures.set must be refused, got: " ++ show other)
  where
    fixSetMsg = "fixtures.set is reserved (no fixture application reads it yet): the only accepted value is \"minimal-demo\""

caseFixApplyRefused :: IO ()
caseFixApplyRefused =
  case parseConfig (unlines ["schema_version = 1", "[fixtures]", "apply = \"always\""]) of
    Left (CfgInvalid msg) -> assertEqual "exact refusal" fixApplyMsg msg
    other -> assertFailure ("non-default fixtures.apply must be refused, got: " ++ show other)
  where
    fixApplyMsg = "fixtures.apply is reserved (no fixture application reads it yet): the only accepted value is \"new-store-only\""

caseFixDefaults :: IO ()
caseFixDefaults =
  case parseConfig (unlines ["schema_version = 1", "[fixtures]", "set = \"minimal-demo\"", "apply = \"new-store-only\""]) of
    Right cfg -> do
      assertEqual "set default" "minimal-demo" (fcSet (cfgFixtures cfg))
      assertEqual "apply default" "new-store-only" (fcApply (cfgFixtures cfg))
    other -> assertFailure ("fixture defaults must parse, got: " ++ show other)

-- ---------------------------------------------------------------------------
-- Limits (knobs + never-knobs)
-- ---------------------------------------------------------------------------

honestySeeded :: Model
honestySeeded = addToken emptyModel (SlotId 0)

honestyOpenReq :: Request
honestyOpenReq = Request
  { reqVersion = Pkcs11_3_2
  , reqFunction = F_OpenSession
  , reqSession = Nothing
  , reqHandle = Nothing
  , reqInput = "slot=0,rw"
  , reqRegions = []
  }

honestyRunCommit :: Rules -> Model -> Request -> IO Model
honestyRunCommit rules model req =
  case planCall rules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("delta fault: " ++ show fault)
      Right m' -> pure m'
    Reject rej -> assertFailure ("expected commit, rejected: " ++ show (rejCode rej))
    Execute _ _ -> assertFailure "expected commit, got Execute"

-- | ENFORCED (S2b pin): limits.sessions flows through
-- 'rulesFromConfig' into session admission (slots/objects halves
-- pinned by AdmissionSpec caseTracksConfig).
caseSessionsTrack :: IO ()
caseSessionsTrack = do
  let cfg = defaultConfig { cfgLimits = (cfgLimits defaultConfig) { limSessions = 1 } }
      rules = rulesFromConfig cfg
  assertEqual "sessions tracked" 1 (rulesMaxSessions rules)
  m1 <- honestyRunCommit rules honestySeeded honestyOpenReq
  case lookupSession m1 (SessionId 1) of
    Nothing -> assertFailure "opened session missing from model"
    Just _ -> pure ()
  case planCall rules m1 honestyOpenReq of
    Reject rej -> assertEqual "second open refused" CKR_SESSION_COUNT (rejCode rej)
    other -> assertFailure ("second open must refuse, got: " ++ show other)

honestySignRequest :: SessionId -> Int -> JobRequest
honestySignRequest sid ticks = JobRequest
  { jrSession = sid
  , jrFunction = JobSign
  , jrWork = WorkCall
      (Reservation "jobs-test" [] Nothing Nothing)
      (EffectCrypto (FxSign (MechanismId 0x251) Nothing BC8.empty "hello"))
  , jrTicks = ticks
  , jrCapacity = 64
  }

-- | ENFORCED: limits.jobs sizes the async table (9th submit over a
-- bound-8 table refuses with StartOverCapacity).
caseJobsBound :: IO ()
caseJobsBound = withTimeout "jobs bound" $ do
  let cfg = defaultConfig { cfgLimits = (cfgLimits defaultConfig) { limJobs = 8 } }
  inst <- buildInstance cfg
  let table = instAsync inst
      sid = SessionId 7
  enableAsyncSession table sid
  results <- mapM (\_ -> startJob table (honestySignRequest sid 2)) [1 .. 9 :: Int]
  let oks = [j | Right j <- results]
  assertEqual "8 submits accepted" 8 (length oks)
  case reverse results of
    Left StartOverCapacity : _ -> pure ()
    other : _ -> assertFailure ("9th submit must refuse over-capacity, got: " ++ show other)
    [] -> assertFailure "9 submits expected, got none"

-- | ENFORCED: limits.events sizes the slot-event queue (9 arrivals
-- over a bound-8 queue drop exactly 1).
caseEventsBound :: IO ()
caseEventsBound = withTimeout "events bound" $ do
  let cfg = defaultConfig { cfgLimits = (cfgLimits defaultConfig) { limEvents = 8 } }
  inst <- buildInstance cfg
  mapM_ (\i -> insertToken (instRegistry inst) (SlotId i)) [1 .. 9 :: Int]
  drops <- droppedEvents (instEvents inst)
  assertEqual "9 arrivals over bound 8 drop 1" 1 drops

-- | ENFORCED-by-validation: every [limits] value must be >= 1.
caseLimitsZero :: IO ()
caseLimitsZero =
  case parseConfig (unlines ["schema_version = 1", "[limits]", "slots = 0"]) of
    Left (CfgInvalid msg) ->
      assertEqual "exact refusal" "all [limits] values must be >= 1" msg
    other -> assertFailure ("zero limit must be refused, got: " ++ show other)

-- | CONFIG-NOT-POLICY (found items): transcript_bytes,
-- aggregate_payload_bytes and attribute_depth have no reader and
-- no dedicated disclosure line — same treatment as the
-- reserved knobs: parse + validate + report, disclosed reserved
-- (never silently ignored again).
caseReservedParse :: IO ()
caseReservedParse =
  case parseConfig (unlines ["schema_version = 1", "[limits]"
                            , "transcript_bytes = 11", "aggregate_payload_bytes = 12", "attribute_depth = 3"]) of
    Right cfg -> do
      assertEqual "transcript" 11 (limTranscriptBytes (cfgLimits cfg))
      assertEqual "aggregate" 12 (limAggregatePayloadBytes (cfgLimits cfg))
      assertEqual "depth" 3 (limAttributeDepth (cfgLimits cfg))
    other -> assertFailure ("reserved limits must parse, got: " ++ show other)

caseReservedDisclosed :: IO ()
caseReservedDisclosed = withTimeout "capabilities run" $ do
  r <- runCtl ["capabilities", "--config", fixture "maximal-demo.toml"]
  assertEqual "exit 0" 0 (ceCode r)
  assertBool "reserved-limits line present" (reservedLimitsLine `isInfixOf` ceOut r)
  where
    reservedLimitsLine = "reserved-limits: transcript_bytes/aggregate_payload_bytes/attribute_depth reserved (parse+report, no enforcement effect; buffer_bytes/attribute_entries: see template-bounds)"

-- ---------------------------------------------------------------------------
-- Never-knobs (S2a + S2c): review-proposed names with no config
-- surface. Each must reject as unknown (never silently ignored);
-- docs/config-honesty.md lists them as explicitly non-config.
-- ---------------------------------------------------------------------------

caseSeclevelUnknown :: IO ()
caseSeclevelUnknown =
  case parseConfig "schema_version = 1\nseclevel = 2\n" of
    Left (CfgUnknownKey k) -> assertEqual "named" "seclevel" k
    other -> assertFailure ("seclevel must be rejected as unknown, got: " ++ show other)

caseMaxTlsUnknown :: IO ()
caseMaxTlsUnknown =
  case parseConfig "schema_version = 1\nmax-tls = \"1.3\"\n" of
    Left (CfgUnknownKey k) -> assertEqual "named" "max-tls" k
    other -> assertFailure ("max-tls must be rejected as unknown, got: " ++ show other)

-- | @native-engine@ is a Ctl REPORT line ('Ctl.hs'), not a knob: a
-- user writing it as config gets an error, never silent ignorance.
caseNativeEngineUnknown :: IO ()
caseNativeEngineUnknown =
  case parseConfig "schema_version = 1\nnative-engine = \"openssl\"\n" of
    Left (CfgUnknownKey k) -> assertEqual "named" "native-engine" k
    other -> assertFailure ("native-engine knob must be rejected as unknown, got: " ++ show other)

caseAdmissionUnknown :: IO ()
caseAdmissionUnknown =
  case parseConfig "schema_version = 1\n[admission]\nslots = 1\n" of
    Left (CfgUnknownKey k) -> assertEqual "named" "admission" k
    other -> assertFailure ("[admission] must be rejected as unknown, got: " ++ show other)

caseMaxQueueUnknown :: IO ()
caseMaxQueueUnknown =
  case parseConfig (unlines ["schema_version = 1", "[async]", "max-queue = 4"]) of
    Left (CfgUnknownKey k) -> assertEqual "named" "async.max-queue" k
    other -> assertFailure ("async.max-queue must be rejected as unknown, got: " ++ show other)

caseWaitersUnknown :: IO ()
caseWaitersUnknown =
  case parseConfig (unlines ["schema_version = 1", "[async]", "waiters = 2"]) of
    Left (CfgUnknownKey k) -> assertEqual "named" "async.waiters" k
    other -> assertFailure ("async.waiters must be rejected as unknown, got: " ++ show other)

-- ---------------------------------------------------------------------------
-- Dogfood + startup refusal
-- ---------------------------------------------------------------------------

-- | Every refusal-prone knob of 'defaultConfig' sits on its honest
-- value (regression pin: a default flipped back to a dishonest
-- value fails here, not silently in production).
caseDogfoodDefault :: IO ()
caseDogfoodDefault = do
  let cfg = defaultConfig
  assertEqual "seed" 1234 (cfgSeed cfg)
  assertEqual "busy" 5000 (scBusyTimeoutMs (cfgStorage cfg))
  assertEqual "exclusive" True (scExclusiveOwnership (cfgStorage cfg))
  assertBool "memory has no path" (scPath (cfgStorage cfg) == Nothing)
  assertEqual "no fallback" False (ecAllowSyntheticFallback (cfgEngine cfg))
  assertEqual "private libctx" True (ecPrivateLibraryContext (cfgEngine cfg))
  assertEqual "redact" True (tcRedactSecrets (cfgTrace cfg))
  assertEqual "control on" True (ccEnabled (cfgControl cfg))
  assertEqual "fixture set" "minimal-demo" (fcSet (cfgFixtures cfg))
  assertEqual "fixture apply" "new-store-only" (fcApply (cfgFixtures cfg))

-- | All six shipped fixtures satisfy the honesty rules (parse under
-- the refusing parser); zero exemptions.
caseDogfoodFixtures :: IO ()
caseDogfoodFixtures = withTimeout "fixture dogfood" $ do
  results <- mapM loadConfigFile fixtures
  case sequence results of
    Left err -> assertFailure ("all fixtures must be honest: " ++ show err)
    Right cfgs -> do
      assertEqual "six fixtures" 6 (length cfgs)
      -- The reserved knobs keep their disclosed values (maximal sets
      -- persist=true, real-crypto sets persist=false + private
      -- libctx=true): both parse, both disclosed.
      case cfgs of
        maximal : _ -> assertEqual "maximal persist" True (acPersistDetached (cfgAsync maximal))
        [] -> assertFailure "six fixtures expected, got none"
  where
    fixtures =
      [ fixture "maximal-demo.toml", fixture "persistent-demo.toml"
      , fixture "real-crypto.toml", fixture "small-limits.toml"
      , fixture "sim-demo.toml", fixture "multi-token.toml"
      ]

dishonestToml :: String
dishonestToml = unlines
  [ "schema_version = 1"
  , "profile = \"demo-maximal\""
  , "[control]"
  , "enabled = false"
  ]

-- | The startup path ('resolveFrom', what every native open calls)
-- answers Left with the exact honesty error on a dishonest file.
caseStartupRefusalResolve :: IO ()
caseStartupRefusalResolve = withTimeout "startup refusal" $
  bracket (writeTempDishonest "haskoki-dishonest.toml") removeFile $ \path -> do
    eCfg <- resolveFrom (Just path) Nothing
    case eCfg of
      Left (CfgInvalid msg) -> assertEqual "exact error" ctlMsg msg
      other -> assertFailure ("dishonest file must fail resolve, got: " ++ show other)
  where
    ctlMsg = "control.enabled=false is not supported (the control plane is always on): must be true"
    writeTempDishonest name = do
      base <- getTemporaryDirectory
      let path = base </> name
      writeFile path dishonestToml
      pure path

-- | @config check@ rejects a dishonest file loudly (exit /= 0,
-- naming the knob).
caseStartupRefusalCheck :: IO ()
caseStartupRefusalCheck = withTimeout "config check refusal" $
  bracket (writeTempDishonest "haskoki-dishonest-check.toml") removeFile $ \path -> do
    r <- runCtl ["config", "check", "--config", path]
    assertBool "config check rejects dishonesty" (ceCode r /= 0)
    assertBool "names the knob" ("control.enabled" `isInfixOf` (ceOut r ++ ceErr r))
  where
    writeTempDishonest name = do
      base <- getTemporaryDirectory
      let path = base </> name
      writeFile path dishonestToml
      pure path

-- ---------------------------------------------------------------------------
-- Catalog audit: docs/config-honesty.md is complete 1:1 against
-- the knob table — every reserved knob, every never-knob, every
-- refusal rule, and the dogfood matrix must be named there.
-- ---------------------------------------------------------------------------

honestyCatalog :: IO String
honestyCatalog = withTimeout "read catalog" (readFile "docs/config-honesty.md")

caseAuditReserved :: IO ()
caseAuditReserved = do
  doc <- honestyCatalog
  mapM_ (\k -> assertBool ("reserved named: " ++ k) (k `isInfixOf` doc))
    [ "buffer_bytes", "attribute_entries"
    , "transcript_bytes", "aggregate_payload_bytes", "attribute_depth"
    , "persist_detached", "template-bounds"
    ]

caseAuditNeverKnobs :: IO ()
caseAuditNeverKnobs = do
  doc <- honestyCatalog
  mapM_ (\k -> assertBool ("never-knob named: " ++ k) (k `isInfixOf` doc))
    [ "seclevel", "max-tls", "native-engine"
    , "admission", "max-queue", "waiters"
    ]

caseAuditRefusals :: IO ()
caseAuditRefusals = do
  doc <- honestyCatalog
  mapM_ (\k -> assertBool ("refusal named: " ++ k) (k `isInfixOf` doc))
    [ "seed", "storage.path", "busy_timeout_ms"
    , "exclusive_provider_ownership", "allow_synthetic_fallback"
    , "private_library_context", "redact_secrets", "control.enabled"
    , "fixtures.set", "fixtures.apply"
    ]

caseAuditDogfood :: IO ()
caseAuditDogfood = do
  doc <- honestyCatalog
  mapM_ (\k -> assertBool ("dogfood named: " ++ k) (k `isInfixOf` doc))
    [ "maximal-demo.toml", "persistent-demo.toml", "real-crypto.toml"
    , "small-limits.toml", "sim-demo.toml", "multi-token.toml"
    , "defaultConfig"
    ]
