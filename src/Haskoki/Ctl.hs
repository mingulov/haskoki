{- | @haskoki-ctl@ command logic.

Pure-ish dispatch over @[String]@ so the contract suite exercises the
real code in-process ('runCtl'); @app\/Main.hs@ is a thin wrapper.
Every command owns its instance or works offline:

* @config check@ validates a TOML file (accepts the examples,
  rejects bad keys);
* @capabilities@ reports the active catalog + gap set for a config
  (@demo-maximal@ is labeled a target profile, never complete);
* @scenario run@ executes a declarative scenario against an OWNED
  in-memory instance, deterministically (no code execution; a sync
  session never pends);
* @store inspect@ reads a SQLite store offline (SELECT-only under
  @query_only@; never takes the ownership lock);
* @store reset@ REFUSES a live (lock-held) store and resets an
  offline one only with @--confirm-demo-reset@.

No command is described as remote live control: the CLI cannot touch
another process's loaded module without an IPC transport (§5), and
the help text says so.
-}
module Haskoki.Ctl
  ( CtlExit (..)
  , ctlHelp
  , runCtl
  ) where

import Control.Exception (SomeException, try)
import qualified Data.ByteString.Char8 as BC8
import Data.List (intercalate, sort)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import System.IO.Error (tryIOError)
import System.Posix.Files (fileExist, removeLink)
import Text.Read (readMaybe)

import Haskoki.Runtime.Async (newAsyncTable)
import Haskoki.Runtime.Config
import Haskoki.Runtime.Control
  ( Json (..)
  , Scenario (..)
  , parseJson
  , validateScenario
  )
import Haskoki.Runtime.Events
  ( OverflowPolicy (DropOldest)
  , TokenRegistry
  , WaitOutcome (..)
  , insertToken
  , newEventQueue
  , newTokenRegistry
  , registerSessionSlot
  , registryEvents
  , removeToken
  , tryWaitSlotEvent
  , waitSlotEvent
  )
import Haskoki.Registry (MechanismId (..), behaviorIds, curatedRegistry)
import Haskoki.Registry.Generated (generatedInventory)
import Haskoki.Runtime.Trace
  ( DrainReport (..)
  , TraceEvent (..)
  , Tracer
  , drainTracer
  , emitTrace
  , newTracer
  )
import Haskoki.Types (SessionId (..), SlotId (..))

-- ---------------------------------------------------------------------------
-- Exit + help
-- ---------------------------------------------------------------------------

-- | What a CLI invocation reports (exit code + captured streams).
data CtlExit = CtlExit
  { ceCode :: !Int
  , ceOut :: !String
  , ceErr :: !String
  } deriving (Eq, Show)

-- | Help text. It names the owned-instance\/offline model and never
-- claims live control of another process.
ctlHelp :: String
ctlHelp = unlines
  [ "haskoki-ctl — offline and owned-instance operator tool"
  , ""
  , "Usage:"
  , "  haskoki-ctl config check --config FILE"
  , "  haskoki-ctl capabilities --config FILE"
  , "  haskoki-ctl scenario run --config FILE --scenario FILE"
  , "  haskoki-ctl store inspect --path FILE"
  , "  haskoki-ctl store reset --path FILE --confirm-demo-reset"
  , ""
  , "Model: capabilities and scenario run own their module instance;"
  , "store commands are offline and honor the database-ownership lock"
  , "(reset refuses a live store). There is no remote administration:"
  , "this tool cannot mutate another process's loaded module."
  ]

-- ---------------------------------------------------------------------------
-- Dispatch
-- ---------------------------------------------------------------------------

-- | Run the CLI over an argument vector.
runCtl :: [String] -> IO CtlExit
runCtl ["--help"] = pure (CtlExit 0 ctlHelp "")
runCtl ["-h"] = pure (CtlExit 0 ctlHelp "")
runCtl ["--version"] = pure (CtlExit 0 "haskoki-ctl 0.3.0.0\n" "")
runCtl ("config" : "check" : rest) = do
  case flag "--config" rest of
    Nothing -> pure (CtlExit 2 "" "config check needs --config FILE\n")
    Just path -> do
      eCfg <- loadConfigFile path
      case eCfg of
        Left err -> pure (CtlExit 1 "" ("config-invalid: " ++ show err ++ "\n"))
        Right cfg -> pure (CtlExit 0
          ("config-ok: profile=" ++ show (cfgProfile cfg)
           ++ " interfaces=" ++ show (cfgInterfaces cfg) ++ "\n") "")
runCtl ("capabilities" : rest) = do
  case flag "--config" rest of
    Nothing -> pure (CtlExit 2 "" "capabilities needs --config FILE\n")
    Just path -> do
      eCfg <- loadConfigFile path
      case eCfg of
        Left err -> pure (CtlExit 1 "" ("config-invalid: " ++ show err ++ "\n"))
        Right cfg -> pure (CtlExit 0 (capabilitiesReport cfg) "")
runCtl ("scenario" : "run" : rest) = do
  case (flag "--config" rest, flag "--scenario" rest) of
    (Just cfgPath, Just scPath) -> runScenario cfgPath scPath
    _ -> pure (CtlExit 2 "" "scenario run needs --config FILE --scenario FILE\n")
runCtl ("store" : "inspect" : rest) = do
  case flag "--path" rest of
    Nothing -> pure (CtlExit 2 "" "store inspect needs --path FILE\n")
    Just path -> inspectStore path
runCtl ("store" : "reset" : rest) = do
  case flag "--path" rest of
    Nothing -> pure (CtlExit 2 "" "store reset needs --path FILE\n")
    Just path -> resetStore path ("--confirm-demo-reset" `elem` rest)
runCtl [] = pure (CtlExit 2 "" ctlHelp)
runCtl unknown = pure (CtlExit 2 "" ("unknown command: " ++ unwords unknown ++ "\n" ++ ctlHelp))

-- | @--flag VALUE@ lookup.
flag :: String -> [String] -> Maybe String
flag _ [] = Nothing
flag _ [_] = Nothing
flag name (x : y : rest)
  | x == name = Just y
  | otherwise = flag name (y : rest)

-- ---------------------------------------------------------------------------
-- Capabilities
-- ---------------------------------------------------------------------------

-- | Full-baseline mechanism names from the generated header
-- inventory (464 canonical; labels, not a conformance claim).
baselineMechanisms :: [String]
baselineMechanisms = sort [T.unpack name | (_, name, _) <- generatedInventory]

-- | Tested-behavior mechanism names from the curated registry.
behaviorNames :: [String]
behaviorNames = sort
  [ T.unpack name
  | (w, name, _) <- generatedInventory
  , MechanismId w `elem` behaviorIds curatedRegistry
  ]

-- | Behaviors the real backend does not serve (real column not
-- tested in @spec/mechanisms.json@: the synthetic-only KEM pair;
-- keygen went real, so its rows left the list). CtlSpec pins the
-- per-engine counts, so a new synthetic-only behavior fails loudly
-- here until this list grows with it.
realGapNames :: [String]
realGapNames =
  [ "CKM_ML_KEM"
  , "CKM_ML_KEM_KEY_PAIR_GEN"
  ]

-- | Active catalog per engine, derived from the registry:
-- synthetic serves every tested behavior; OpenSSL serves every
-- tested behavior except 'realGapNames'. This describes the
-- CONFIGURED engine only; native paths always bind OpenSSL4 (see
-- the @native-engine@ report line).
activeCatalog :: Config -> [String]
activeCatalog cfg = case ecKind (cfgEngine cfg) of
  EngineSynthetic -> behaviorNames
  EngineOpenSSL -> filter (`notElem` realGapNames) behaviorNames

-- | Deterministic capabilities report: profile, active catalog, gap
-- set, limits. @demo-maximal@ is marked a target profile. The
-- @native-engine@ line scopes the binding honestly: every native
-- open binds @BackendEnv OpenSSL4@ regardless of @engine.kind@.
capabilitiesReport :: Config -> String
capabilitiesReport cfg = unlines $
  [ "profile: " ++ profileName (cfgProfile cfg) ++ targetMark
  , "engine: " ++ show (ecKind (cfgEngine cfg))
  , nativeEngineLine
  , templateBoundsLine
  , reservedAsyncLine
  , reservedLimitsLine
  , "interfaces: " ++ unwords (cfgInterfaces cfg)
  , "active-catalog: " ++ unwords active
  , "gap-set: " ++ unwords gaps
  ] ++ map (\(k, v) -> "limit." ++ k ++ ": " ++ show v) (reportLimits cfg)
    ++ map (\(k, v) -> "sim." ++ k ++ ": " ++ v) (reportSim cfg)
    ++ map (\(k, v) -> "tokens." ++ k ++ ": " ++ v) (reportTokens cfg)
  where
    active = activeCatalog cfg
    gaps = filter (`notElem` active) baselineMechanisms
    targetMark = case cfgProfile cfg of
      ProfileDemoMaximal -> " [target-profile: gaps remain, not a completeness claim]"
      _ -> ""
    profileName ProfileDemoMaximal = "demo-maximal"
    profileName ProfileRealCrypto = "real-crypto"
    profileName ProfileScenario = "scenario"

-- | The native binding scope sentence, pinned verbatim by CtlSpec:
-- table, attached-crypto, attached-async and detached paths all run
-- the OpenSSL4 backend; @engine.kind@ (and the catalog above)
-- describes the configured engine only.
nativeEngineLine :: String
nativeEngineLine = "native-engine: EngineOpenSSL (native paths always run OpenSSL4; engine/active-catalog describe the configured engine)"

-- | The template-bounds disclosure sentence, pinned verbatim by
-- ConfigSpec: effective bounds are the pinned constants; the
-- config keys are reserved and drive no enforcement.
templateBoundsLine :: String
templateBoundsLine = "template-bounds: entries=64 bytes=65536 (pinned; limits.attribute_entries/buffer_bytes reserved, no enforcement effect)"

-- | The detached-durability disclosure sentence, pinned verbatim by
-- ConfigHonestySpec: detached records always commit to the store
-- (unconditional, durability follows storage.kind);
-- @async.persist_detached@ selects nothing.
reservedAsyncLine :: String
reservedAsyncLine = "reserved-async: persist_detached reserved (detached records always commit to the store; durability follows storage.kind, no knob effect)"

-- | The reserved-limits disclosure sentence, pinned verbatim by
-- ConfigHonestySpec: the three found items
-- (@transcript_bytes@/@aggregate_payload_bytes@/@attribute_depth@)
-- parse + validate + report but drive no enforcement (the
-- reserved-knob shape; @buffer_bytes@/@attribute_entries@ stay on the
-- template-bounds line above).
reservedLimitsLine :: String
reservedLimitsLine = "reserved-limits: transcript_bytes/aggregate_payload_bytes/attribute_depth reserved (parse+report, no enforcement effect; buffer_bytes/attribute_entries: see template-bounds)"

-- ---------------------------------------------------------------------------
-- Scenario runner (owned instance, declarative, deterministic)
-- ---------------------------------------------------------------------------

-- | A runnable step: validated verb + raw extras (save_as, expect).
data RunStep = RunStep
  { rsAction :: !String
  , rsArgs :: ![(String, Json)]
  , rsSaveAs :: !(Maybe String)
  , rsExpect :: !(Maybe Json)
  } deriving (Eq, Show)

-- | Logical session in the owned instance.
data LogicalSession = LogicalSession
  { lsId :: !SessionId
  , lsAsync :: !Bool
  , lsLoggedIn :: !Bool
  , lsSignArmed :: !Bool
  , lsPendingLeft :: !Int
  , lsSignCalls :: !Int
  } deriving (Eq, Show)

-- | Runner state (all in-memory; nothing escapes the process).
-- 'rnFault' is the live fault window @(start-tick, length)@ over
-- step indices: sign\/async.complete steps inside it report
-- @CKR_DEVICE_ERROR@ instead of running (seeded from @[sim]@ when
-- sim is enabled; the @fault.window@ verb replaces it).
data Runner = Runner
  { rnTracer :: !Tracer
  , rnSessions :: !(Map String LogicalSession)
  , rnNextSession :: !Int
  , rnFinalized :: !Bool
  , rnFault :: !(Maybe (Int, Int))
  }

-- | Run a scenario file against an owned instance.
runScenario :: FilePath -> FilePath -> IO CtlExit
runScenario cfgPath scPath = do
  eCfg <- loadConfigFile cfgPath
  case eCfg of
    Left err -> pure (CtlExit 1 "" ("config-invalid: " ++ show err ++ "\n"))
    Right cfg -> do
      eBody <- tryIOError (BC8.readFile scPath)
      case eBody of
        Left _ -> pure (CtlExit 1 "" ("scenario-missing: " ++ scPath ++ "\n"))
        Right body -> case parseJson body of
          Left err -> pure (CtlExit 1 "" ("scenario-malformed: " ++ err ++ "\n"))
          Right val -> case validateScenario val of
            Left err -> pure (CtlExit 1 "" ("scenario-rejected: " ++ show err ++ "\n"))
            Right sc -> do
              steps <- pure (runSteps val)
              execScenario cfg sc steps

-- | Re-walk the raw steps for runner extras (verbs already validated).
runSteps :: Json -> [RunStep]
runSteps (JObj kvs) = case lookup "steps" kvs of
  Just (JArr ss) -> [ toStep s | s@(JObj _) <- ss ]
  _ -> []
  where
    toStep (JObj skvs) = RunStep
      { rsAction = case lookup "action" skvs of Just (JStr a) -> a; _ -> ""
      , rsArgs = case lookup "arguments" skvs of Just (JObj ps) -> ps; _ -> []
      , rsSaveAs = case lookup "save_as" skvs of Just (JStr n) -> Just n; _ -> Nothing
      , rsExpect = lookup "expect" skvs
      }
    toStep _ = RunStep "" [] Nothing Nothing
runSteps _ = []

-- | Execute validated steps in file order (deterministic rule order).
-- When sim is enabled, the @[sim]@ token script runs first (in file
-- order) and the configured fault window seeds the runner.
execScenario :: Config -> Scenario -> [RunStep] -> IO CtlExit
execScenario cfg sc steps = do
  eq <- newEventQueue (max 8 (limEvents (cfgLimits cfg))) DropOldest
  at <- newAsyncTable (max 8 (limJobs (cfgLimits cfg)))
  reg <- newTokenRegistry eq at
  tr <- newTracer (max 8 (tcQueueLimit (cfgTrace cfg))) (\_ -> pure (Right ())) False
  applyTokenScript reg (simScript cfg)
  let rn0 = Runner tr Map.empty 1 False (seedFault cfg)
  eOut <- go rn0 reg tr (zip [0 :: Int ..] steps) []
  case eOut of
    Left err -> pure (CtlExit 1 "" ("scenario-failed: " ++ err ++ "\n"))
    Right (rnF, lines_) -> do
      rep <- drainTracer (rnTracer rnF)
      let out = unlines $
            [ "scenario: " ++ scName sc
              , "steps-executed: " ++ show (length lines_)
              ] ++ scriptLine ++ lines_ ++
            [ "trace-lines: " ++ show (drWritten rep + drFailed rep)
            , "scenario-ok"
            ]
      pure (CtlExit 0 out "")
  where
    scriptLine = case simScript cfg of
      [] -> []
      script -> ["sim-script: " ++ intercalate "," [op ++ " " ++ show s | (op, s) <- script]]
    go rn _ _ [] acc = pure (Right (rn, reverse acc))
    go rn reg tr ((i, st) : rest) acc = do
      eLine <- execStep cfg reg tr rn i st
      case eLine of
        Left err -> pure (Left ("step[" ++ show i ++ "] " ++ rsAction st ++ ": " ++ err))
        Right (rn', note) -> go rn' reg tr rest (("step[" ++ show i ++ "] " ++ rsAction st ++ " -> " ++ note) : acc)

-- | The effective token script (empty unless sim is enabled).
simScript :: Config -> [(String, Int)]
simScript cfg
  | scEnabled (cfgSim cfg) = scTokenScript (cfgSim cfg)
  | otherwise = []

-- | The seeded fault window (only when sim is enabled).
seedFault :: Config -> Maybe (Int, Int)
seedFault cfg
  | scEnabled sim = Just (scFaultWindowStart sim, scFaultWindowTicks sim)
  | otherwise = Nothing
  where sim = cfgSim cfg

-- | Run the token script in file order (config validation admits
-- only @insert N@ \/ @remove N@; anything else is a no-op).
applyTokenScript :: TokenRegistry -> [(String, Int)] -> IO ()
applyTokenScript reg script = mapM_ one script
  where
    one ("insert", s) = insertToken reg (SlotId s) >> pure ()
    one ("remove", s) = removeToken reg (SlotId s) >> pure ()
    one _ = pure ()

-- | Whether a step index falls in the live fault window.
inFault :: Runner -> Int -> Bool
inFault rn i = case rnFault rn of
  Just (s, t) -> s <= i && i < s + t
  Nothing -> False

-- | Fixture credentials (test-only, from the design §6 fixture set).
fixtureUserPin, fixtureSoPin :: String
fixtureUserPin = "1234"
fixtureSoPin = "5678"

-- | Execute one step (@i@ is the step index for fault-window
-- checks). Unknown verbs cannot arrive (validated), so the fallback
-- is an internal error, never code execution. @expect@ clauses are
-- enforced: a mismatch fails the run. Program errors (unknown
-- session, unarmed sign) precede device faults: an in-window step
-- reports @CKR_DEVICE_ERROR@ instead of running, without consuming
-- any pending poll.
execStep :: Config -> TokenRegistry -> Tracer -> Runner -> Int -> RunStep -> IO (Either String (Runner, String))
execStep cfg reg tr rn i st = case rsAction st of
  "initialize" -> do
    emit tr "C_Initialize" 0 "initialized"
    pure (Right (rn, "CKR_OK"))
  "fixture.load" -> do
    _ <- insertToken reg (SlotId 0)
    emit tr "C_InitToken" 0 "fixture-loaded"
    pure (Right (rn, "CKR_OK"))
  "session.open" -> do
    let name = saveName (rnNextSession rn)
        isAsync = case lookup "asynchronous" (rsArgs st) of
          Just (JBool b) -> b
          _ -> False
        sid = SessionId (rnNextSession rn)
    registerSessionSlot reg sid (SlotId 0)
    emit tr "C_OpenSession" 0 ("session=" ++ name)
    let ls = LogicalSession sid isAsync False False 0 0
        rn' = rn { rnSessions = Map.insert name ls (rnSessions rn)
                 , rnNextSession = rnNextSession rn + 1 }
    pure (Right (rn', "CKR_OK"))
  "session.login" -> do
    case sessionOf rn st of
      Left err -> pure (Left err)
      Right (name, ls) -> do
        let pin = case lookup "pin" (rsArgs st) of Just (JStr p) -> p; _ -> ""
            role = case lookup "role" (rsArgs st) of Just (JStr r) -> r; _ -> ""
            okPin = (role == "USER" && pin == fixtureUserPin)
                 || (role == "SO" && pin == fixtureSoPin)
        emit tr "C_Login" (if okPin then 0 else 0xA0) ("session=" ++ name)
        if okPin
          then pure (Right (rn { rnSessions = Map.insert name (ls { lsLoggedIn = True }) (rnSessions rn) }, "CKR_OK"))
          else pure (Left "login pin incorrect")
  "sign.init" -> do
    case sessionOf rn st of
      Left err -> pure (Left err)
      Right (name, ls) -> do
        emit tr "C_SignInit" 0 ("session=" ++ name)
        pure (Right (rn { rnSessions = Map.insert name (ls { lsSignArmed = True }) (rnSessions rn) }, "CKR_OK"))
  "sign" -> do
    case sessionOf rn st of
      Left err -> pure (Left err)
      Right (name, ls) -> do
        if not (lsSignArmed ls)
          then pure (Left "sign without sign.init")
          else if inFault rn i
            then do
              emit tr "C_Sign" 0x30 ("session=" ++ name)
              case checkExpect st "CKR_DEVICE_ERROR" of
                Left err -> pure (Left err)
                Right () -> pure (Right (rn, "CKR_DEVICE_ERROR"))
            else do
              -- pending_polls applies ONLY to async-eligible ops in
              -- async sessions: a sync session never pends, no matter
              -- what the scenario rules say.
              let polls = acPendingPolls (cfgAsync cfg)
                  wantPending = lsAsync ls && acEnabled (cfgAsync cfg) && polls > 0
                  calls' = lsSignCalls ls + 1
              emit tr "C_Sign" (if wantPending then 0x204 else 0) ("session=" ++ name)
              if wantPending
                then do
                  let ls' = ls { lsSignCalls = calls', lsPendingLeft = polls }
                  case checkExpect st "CKR_PENDING" of
                    Left err -> pure (Left err)
                    Right () -> pure (Right (rn { rnSessions = Map.insert name ls' (rnSessions rn) }, "CKR_PENDING"))
                else case checkExpect st "CKR_OK" of
                  Left err -> pure (Left err)
                  Right () -> pure (Right (rn { rnSessions = Map.insert name (ls { lsSignCalls = calls' }) (rnSessions rn) }, "CKR_OK"))
  "async.complete" -> do
    case sessionOf rn st of
      Left err -> pure (Left err)
      Right (name, ls) -> do
        if inFault rn i
          then do
            emit tr "C_Sign" 0x30 ("session=" ++ name)
            case checkExpect st "CKR_DEVICE_ERROR" of
              Left err -> pure (Left err)
              Right () -> pure (Right (rn, "CKR_DEVICE_ERROR"))
          else do
            let left_ = lsPendingLeft ls
            -- polls = pending completes before the final OK.
            if left_ > 0
              then do
                emit tr "C_Sign" 0x204 ("session=" ++ name)
                case checkExpect st "CKR_PENDING" of
                  Left err -> pure (Left err)
                  Right () -> pure (Right (rn { rnSessions = Map.insert name (ls { lsPendingLeft = left_ - 1 }) (rnSessions rn) }, "CKR_PENDING"))
              else do
                emit tr "C_Sign" 0 ("session=" ++ name)
                case checkExpect st "CKR_OK" of
                  Left err -> pure (Left err)
                  Right () -> pure (Right (rn { rnSessions = Map.insert name (ls { lsPendingLeft = 0 }) (rnSessions rn) }, "CKR_OK"))
  "token.remove" -> do
    _ <- removeToken reg (SlotId 0)
    emit tr "C_WaitForSlotEvent" 0 "token-removed"
    pure (Right (rn, "CKR_OK"))
  "slot-event.wait" -> do
    let nonblocking = case lookup "nonblocking" (rsArgs st) of
          Just (JBool b) -> b
          _ -> True
    w <- if nonblocking then tryWaitSlotEvent (registryEvents reg) else waitSlotEvent (registryEvents reg)
    case w of
      WaitEvent _ -> do
        emit tr "C_WaitForSlotEvent" 0 "event"
        case checkExpectEvent st "token-state-change" of
          Left err -> pure (Left err)
          Right () -> pure (Right (rn, "event:token-state-change"))
      WaitNoEvent -> pure (Left "expected a slot event, queue empty")
      WaitFinalized -> pure (Left "instance finalized while waiting")
  "finalize" -> do
    emit tr "C_Finalize" 0 "finalized"
    pure (Right (rn { rnFinalized = True }, "CKR_OK"))
  -- Sim verbs: test-gated like scenario.load (the gate refuses
  -- without mutation when the instance is not test-enabled).
  "token.insert" -> withSimGate $ do
    case lookup "slot" (rsArgs st) of
      Just (JNum n)
        | n >= 0 && n <= 0xFFFFFFFF -> do
            _ <- insertToken reg (SlotId (fromInteger n))
            emit tr "C_WaitForSlotEvent" 0 "token-inserted"
            pure (Right (rn, "CKR_OK"))
      _ -> pure (Left "token.insert needs an integer 'slot' in 0..2^32-1")
  "async.delay" -> withSimGate $ do
    case sessionOf rn st of
      Left err -> pure (Left err)
      Right (name, ls) -> case lookup "polls" (rsArgs st) of
        Just (JNum p)
          | p >= 0 && p <= 1000000 -> do
              emit tr "C_Sign" 0x204 ("session=" ++ name)
              let ls' = ls { lsPendingLeft = lsPendingLeft ls + fromInteger p }
              pure (Right (rn { rnSessions = Map.insert name ls' (rnSessions rn) }, "CKR_OK"))
        _ -> pure (Left "async.delay needs integer 'polls' in 0..1000000")
  "fault.window" -> withSimGate $ do
    case (lookup "start" (rsArgs st), lookup "ticks" (rsArgs st)) of
      (Just (JNum s), Just (JNum t))
        | s >= 0 && t >= 0 && s <= 1000000 && t <= 1000000 -> do
            emit tr "C_Sign" 0 "fault-window"
            pure (Right (rn { rnFault = Just (fromInteger s, fromInteger t) }, "CKR_OK"))
      _ -> pure (Left "fault.window needs integer 'start'/'ticks' in 0..1000000")
  other -> pure (Left ("unknown action (rejected, never executed): " ++ other))
  where
    -- | Refuse sim verbs without mutation unless test-enabled (the
    -- scenario.load gating discipline).
    withSimGate action
      | ccTestEnabled (cfgControl cfg) = action
      | otherwise = pure (Left "test_instance_required (sim verbs need a test-enabled instance)")

-- | Session reference of a step (default save slot "s1").
sessionOf :: Runner -> RunStep -> Either String (String, LogicalSession)
sessionOf rn st =
  let want = case lookup "session" (rsArgs st) of
        Just (JStr n) -> n
        _ -> case rsSaveAs st of
          Just n -> n
          Nothing -> "s1"
      -- save_as on session.open names the slot; later steps address
      -- "s1" positionally (first opened session).
      name = if want == "s1" && Map.notMember want (rnSessions rn)
        then case Map.keys (rnSessions rn) of
          (k : _) -> k
          [] -> want
        else want
  in case Map.lookup name (rnSessions rn) of
    Just ls -> Right (name, ls)
    Nothing -> Left ("unknown session reference: " ++ want)

-- | Default save slot name (positional: first session is "s1").
saveName :: Int -> String
saveName n = "s" ++ show n

-- | Enforce @expect.return@ when the step declares one.
checkExpect :: RunStep -> String -> Either String ()
checkExpect st got = case rsExpect st of
  Just (JObj kvs) -> case lookup "return" kvs of
    Just (JStr want)
      | want == got -> Right ()
      | otherwise -> Left ("expect.return mismatch: want " ++ want ++ ", got " ++ got)
    Just _ -> Left "expect.return must be a string"
    Nothing -> Right ()
  Just _ -> Left "expect must be an object"
  Nothing -> Right ()

-- | Enforce @expect.event@ when the step declares one.
checkExpectEvent :: RunStep -> String -> Either String ()
checkExpectEvent st got = case rsExpect st of
  Just (JObj kvs) -> case lookup "event" kvs of
    Just (JStr want)
      | want == got -> Right ()
      | otherwise -> Left ("expect.event mismatch: want " ++ want ++ ", got " ++ got)
    Just _ -> Left "expect.event must be a string"
    Nothing -> Right ()
  Just _ -> Left "expect must be an object"
  Nothing -> Right ()

-- | Emit one §7 line for the step (memory sink; counted, not printed).
emit :: Tracer -> String -> Int -> String -> IO ()
emit tr fn ckr reason = do
  _ <- emitTrace tr (TraceEvent fn "3.2" Nothing Nothing Nothing Nothing
      0 0 (fromIntegral ckr) "delivered" reason "scenario" Nothing) (fromIntegral ckr)
  pure ()

-- ---------------------------------------------------------------------------
-- Offline store commands
-- ---------------------------------------------------------------------------

-- | Ownership-lock state of a store path (mirrors the sidecar format:
-- @<db>.lock@ carrying the owner's pid; liveness via @\/proc@).
data LockState
  = LockAbsent
  | LockLive !Int
  | LockStale !Int
  deriving (Eq, Show)

-- | Read the lock state without taking anything.
readLockState :: FilePath -> IO LockState
readLockState dbPath = do
  let lockPath = dbPath ++ ".lock"
  exists <- fileExist lockPath
  if not exists
    then pure LockAbsent
    else do
      eContent <- tryIOError (readFile lockPath)
      case eContent of
        Left _ -> pure (LockLive (-1))
        Right content -> case readMaybe (takeWhile (/= '\n') content) of
          Just pid -> do
            alive <- fileExist ("/proc/" ++ show (pid :: Int))
            pure (if alive then LockLive pid else LockStale pid)
          Nothing -> pure (LockLive (-1))

-- | Offline inspect: report lock state + table counts over a
-- SELECT-only connection. Never creates the sidecar, never writes.
inspectStore :: FilePath -> IO CtlExit
inspectStore path = do
  exists <- fileExist path
  if not exists
    then pure (CtlExit 1 "" ("store-missing: " ++ path ++ "\n"))
    else do
      lock <- readLockState path
      eCounts <- try (readCounts path) :: IO (Either SomeException (Either String (Int, Int, Int)))
      case eCounts of
        Left ex -> pure (CtlExit 1 "" ("store-unreadable: " ++ show ex ++ "\n"))
        Right (Left err) -> pure (CtlExit 1 "" ("store-unreadable: " ++ err ++ "\n"))
        Right (Right (nt, no, nj)) -> pure (CtlExit 0 (unlines
          [ "store: " ++ path
          , "lock: " ++ lockWord lock
          , "tokens: " ++ show nt
          , "objects: " ++ show no
          , "detached_jobs: " ++ show nj
          ]) "")
  where
    lockWord LockAbsent = "offline (no lock)"
    lockWord (LockLive pid) = "live (pid " ++ show pid ++ " holds the lock)"
    lockWord (LockStale pid) = "offline (stale lock, pid " ++ show pid ++ " dead)"

-- | SELECT-only counts (the connection is @query_only@; the schema
-- check doubles as the not-a-store detector).
readCounts :: FilePath -> IO (Either String (Int, Int, Int))
readCounts path = do
  eDb <- try (S.open (T.pack path)) :: IO (Either SomeException S.Database)
  case eDb of
    Left ex -> pure (Left (show ex))
    Right db -> do
      outcome <- try (do
        S.exec db (T.pack "PRAGMA query_only = ON")
        eNt <- countRows db "tokens"
        eNo <- countRows db "objects"
        eNj <- countRows db "detached_jobs"
        pure ((,,) <$> eNt <*> eNo <*> eNj)
        ) :: IO (Either SomeException (Either String (Int, Int, Int)))
      _ <- try (S.close db) :: IO (Either SomeException ())
      case outcome of
        Left ex -> pure (Left (show ex))
        Right val -> pure val
  where
    countRows :: S.Database -> String -> IO (Either String Int)
    countRows db table = do
      eRows <- try (do
        stmt <- S.prepare db (T.pack ("SELECT COUNT(*) FROM " ++ table))
        r <- S.step stmt
        cols <- case r of
          S.Row -> S.columns stmt
          S.Done -> pure []
        S.finalize stmt
        pure cols) :: IO (Either SomeException [S.SQLData])
      case eRows of
        Left ex -> pure (Left ("count failed in " ++ table ++ ": " ++ show ex))
        Right [S.SQLInteger n] -> pure (Right (fromIntegral n))
        Right other -> pure (Left ("unexpected count row in " ++ table ++ ": " ++ show other))

-- | Offline reset: refuse live stores; reset offline ones only with
-- the confirm flag (removes the db + sidecar; the next open
-- recreates).
resetStore :: FilePath -> Bool -> IO CtlExit
resetStore path confirmed = do
  exists <- fileExist path
  if not exists
    then pure (CtlExit 1 "" ("store-missing: " ++ path ++ "\n"))
    else do
      lock <- readLockState path
      case lock of
        LockLive pid ->
          pure (CtlExit 1 ""
            ("reset-refused: store is live (pid " ++ show pid ++ " holds the lock)\n"))
        _ | not confirmed ->
              pure (CtlExit 1 "" "reset-refused: pass --confirm-demo-reset to reset an offline demo store\n")
            | otherwise -> do
                _ <- tryIOError (removeLink path)
                _ <- tryIOError (removeLink (path ++ ".lock"))
                stillThere <- fileExist path
                if stillThere
                  then pure (CtlExit 1 "" ("reset-failed: cannot remove " ++ path ++ "\n"))
                  else pure (CtlExit 0 ("reset: " ++ path ++ " removed (offline)\n") "")
