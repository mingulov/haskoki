{- | Immutable provider configuration.

One TOML file selected by @HASKOKI_CONFIG@, resolved and validated
ONCE at init ('resolveOnce' \/ 'cellResolve'); unknown keys are
REJECTED ('CfgUnknownKey'); the resolved value is pure data and
immutable. The only environment overrides are the config path
(@HASKOKI_CONFIG@) and the trace destination (@HASKOKI_TRACE@).

TOML route (see @docs/operations-notes.md@): a minimal hand
parser covering exactly the subset the three example fixtures use
(top-level scalars, @[sections]@, strings, integers, booleans,
string arrays, @#@ comments). No new dependencies.
-}
module Haskoki.Runtime.Config
  ( Profile (..)
  , StorageKind (..)
  , EngineKind (..)
  , StorageCfg (..)
  , EngineCfg (..)
  , AsyncCfg (..)
  , TraceCfg (..)
  , ControlCfg (..)
  , FixturesCfg (..)
  , Limits (..)
  , SimCfg (..)
  , TokensCfg (..)
  , Config (..)
  , ConfigError (..)
  , defaultConfig
  , parseConfig
  , loadConfigFile
  , reportLimits
  , reportSim
  , reportTokens
  , ConfigCell
  , newConfigCell
  , cellResolve
  , cellConfig
  , resolveFrom
  , resolveOnce
  ) where

import Control.Exception (try, IOException)
import Data.Char (isDigit, isSpace)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.List (intercalate, nub)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import System.Environment (lookupEnv)

import Haskoki.Types (redactShown)

-- ---------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------

-- | Startup profile. 'ProfileDemoMaximal' is a target label, never a
-- completeness claim; gaps stay reported (see 'Haskoki.Ctl').
data Profile
  = ProfileDemoMaximal
  | ProfileRealCrypto
  | ProfileScenario
  deriving (Eq, Show)

-- | Storage backend selector.
data StorageKind
  = StorageMemory
  | StorageSQLite
  deriving (Eq, Show)

-- | Crypto engine selector.
data EngineKind
  = EngineSynthetic
  | EngineOpenSSL
  deriving (Eq, Show)

-- | @[storage]@ section. SQLite mode requires an explicit path: the
-- provider never silently shares a storage directory.
data StorageCfg = StorageCfg
  { scKind :: !StorageKind
  , scPath :: !(Maybe FilePath)
  , scBusyTimeoutMs :: !Int
  , scExclusiveOwnership :: !Bool
  } deriving (Eq, Show)

-- | @[engine]@ section.
data EngineCfg = EngineCfg
  { ecKind :: !EngineKind
  , ecAllowSyntheticFallback :: !Bool
  , ecPrivateLibraryContext :: !Bool
  } deriving (Eq, Show)

-- | @[async]@ section.
data AsyncCfg = AsyncCfg
  { acExecutor :: !String
  , acEnabled :: !Bool
  , acPendingPolls :: !Int
  , acPersistDetached :: !Bool
  } deriving (Eq, Show)

-- | @[trace]@ section.
data TraceCfg = TraceCfg
  { tcEnabled :: !Bool
  , tcPath :: !FilePath
  , tcRedactSecrets :: !Bool
  , tcQueueLimit :: !Int
  } deriving (Eq, Show)

-- | @[control]@ section. The response budget is the fixed §5.1
-- protocol value (65536); any other configured value is invalid.
-- 'ccTestEnabled' gates scenario\/mutation commands.
data ControlCfg = ControlCfg
  { ccEnabled :: !Bool
  , ccMaxRequestBytes :: !Int
  , ccResponseBudgetBytes :: !Int
  , ccTestEnabled :: !Bool
  } deriving (Eq, Show)

-- | @[fixtures]@ section.
data FixturesCfg = FixturesCfg
  { fcSet :: !String
  , fcApply :: !String
  } deriving (Eq, Show)

-- | @[limits]@ section (§3 project defaults, all configurable).
-- Slots\/sessions\/objects drive instance admission ('rulesFromConfig').
-- @buffer_bytes@ and @attribute_entries@ are RESERVED: they
-- parse, validate, and report, but drive no enforcement — template
-- bounds are the pinned constants (64 entries, 65536 bytes),
-- disclosed in the capabilities @template-bounds@ line.
data Limits = Limits
  { limSlots :: !Int
  , limSessions :: !Int
  , limObjects :: !Int
  , limBufferBytes :: !Int
  , limTranscriptBytes :: !Int
  , limAggregatePayloadBytes :: !Int
  , limAttributeEntries :: !Int
  , limAttributeDepth :: !Int
  , limJobs :: !Int
  , limEvents :: !Int
  } deriving (Eq, Show)

-- | @[sim]@ section: operator-facing HSM simulation knobs.
-- Delay schedules pair a name (a CKM mechanism name, a
-- job-function tag @sign@\/@digest@\/@genkey@\/@genkeypair@, or @*@
-- for all jobs) with logical-tick delays; the token script lists
-- @("insert"\/"remove", slot)@ steps in file order; the fault window
-- is a bounded labeled tick range. All simulation: no real-time
-- guarantees, delays are logical ticks only.
data SimCfg = SimCfg
  { scEnabled :: !Bool
  , scDelaySchedule :: ![(String, Int)]
  , scTokenScript :: ![(String, Int)]
  , scFaultWindowStart :: !Int
  , scFaultWindowTicks :: !Int
  } deriving (Eq, Show)

-- | @[tokens]@ section: the declarative multi-token
-- catalog. Parallel string arrays (@labels@, @so_pins@,
-- @user_pins@ — the parser supports flat sections + string arrays
-- only, no @[[tables]]@); slot = catalog index, slot 0 MUST be
-- @haskoki-demo@ (the stability anchor for every existing
-- single-slot pin). Catalog PINs are EXAMPLE-GRADE fixture
-- material ("Do not use production secrets", the same discipline
-- as the existing fixtures): no PIN policy or lockout changes.
data TokensCfg = TokensCfg
  { tcEntries :: ![(String, String, String)]
    -- ^ @(label, soPin, userPin)@ triples, slot = index. Empty
    -- when the section is absent (home token only).
  } deriving (Eq)

-- | 'Show' redacts catalog PINs: labels render, both PINs
-- render their kind and length only ('redactShown'). Explicit
-- inspection pattern-matches the exported record (never 'Show').
instance Show TokensCfg where
  show (TokensCfg entries) =
    "TokensCfg {tcEntries = " ++ show (map redactEntry entries) ++ "}"
    where
      redactEntry (label, so, user) =
        (label, redactShown "pin" (length so), redactShown "pin" (length user))

-- | The fully resolved, immutable configuration.
data Config = Config
  { cfgSchemaVersion :: !Int
  , cfgProfile :: !Profile
  , cfgInterfaces :: ![String]
  , cfgSeed :: !Int
  , cfgStorage :: !StorageCfg
  , cfgEngine :: !EngineCfg
  , cfgAsync :: !AsyncCfg
  , cfgTrace :: !TraceCfg
  , cfgControl :: !ControlCfg
  , cfgFixtures :: !FixturesCfg
  , cfgLimits :: !Limits
  , cfgSim :: !SimCfg
  , cfgTokens :: !TokensCfg
  } deriving (Eq)

-- | 'Show' renders every section; the token catalog renders
-- through its redacted instance above (labels shown, PINs never).
instance Show Config where
  show c = "Config {cfgSchemaVersion = " ++ show (cfgSchemaVersion c)
    ++ ", cfgProfile = " ++ show (cfgProfile c)
    ++ ", cfgInterfaces = " ++ show (cfgInterfaces c)
    ++ ", cfgSeed = " ++ show (cfgSeed c)
    ++ ", cfgStorage = " ++ show (cfgStorage c)
    ++ ", cfgEngine = " ++ show (cfgEngine c)
    ++ ", cfgAsync = " ++ show (cfgAsync c)
    ++ ", cfgTrace = " ++ show (cfgTrace c)
    ++ ", cfgControl = " ++ show (cfgControl c)
    ++ ", cfgFixtures = " ++ show (cfgFixtures c)
    ++ ", cfgLimits = " ++ show (cfgLimits c)
    ++ ", cfgSim = " ++ show (cfgSim c)
    ++ ", cfgTokens = " ++ show (cfgTokens c) ++ "}"

-- | Why configuration failed.
data ConfigError
  = CfgParseError !String
  | CfgUnknownKey !String
  | CfgInvalid !String
  | CfgAlreadyResolved
  | CfgMissingFile !FilePath
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- Defaults
-- ---------------------------------------------------------------------------

-- | Defaults: demo-maximal over memory + synthetic, §3 limits, control
-- enabled but NOT test-enabled (mutations stay gated until a config
-- opts in).
defaultConfig :: Config
defaultConfig = Config
  { cfgSchemaVersion = 1
  , cfgProfile = ProfileDemoMaximal
  , cfgInterfaces = ["2.40", "3.0", "3.1", "3.2"]
  , cfgSeed = 1234
  , cfgStorage = StorageCfg StorageMemory Nothing 5000 True
  , cfgEngine = EngineCfg EngineSynthetic False True
  , cfgAsync = AsyncCfg "logical" True 2 False
  , cfgTrace = TraceCfg True "./haskoki-{pid}.jsonl" True 4096
  , cfgControl = ControlCfg True 1048576 65536 False
  , cfgFixtures = FixturesCfg "minimal-demo" "new-store-only"
  , cfgLimits = Limits 16 1024 100000 67108864 67108864 268435456 4096 8 1024 1024
  , cfgSim = SimCfg False [] [] 0 0
  , cfgTokens = TokensCfg []
  }

-- ---------------------------------------------------------------------------
-- Minimal TOML reader
-- ---------------------------------------------------------------------------

-- | Parsed scalar values of the supported subset.
data TomlVal
  = TInt !Integer
  | TBool !Bool
  | TStr !String
  | TArr ![String]
  deriving (Eq, Show)

-- | Dotted key: @("storage", "path")@; top-level keys use @""@.
type TomlKey = (String, String)

-- | Every key the provider understands. Anything else is rejected.
knownKeys :: [TomlKey]
knownKeys =
  [ ("", "schema_version"), ("", "profile"), ("", "interfaces"), ("", "seed")
  , ("storage", "kind"), ("storage", "path"), ("storage", "busy_timeout_ms")
  , ("storage", "exclusive_provider_ownership")
  , ("engine", "kind"), ("engine", "allow_synthetic_fallback")
  , ("engine", "private_library_context")
  , ("async", "executor"), ("async", "enabled"), ("async", "pending_polls")
  , ("async", "persist_detached")
  , ("trace", "enabled"), ("trace", "path"), ("trace", "redact_secrets")
  , ("trace", "queue_limit")
  , ("control", "enabled"), ("control", "max_request_bytes")
  , ("control", "response_budget_bytes"), ("control", "test_enabled")
  , ("fixtures", "set"), ("fixtures", "apply")
  , ("limits", "slots"), ("limits", "sessions"), ("limits", "objects")
  , ("limits", "buffer_bytes"), ("limits", "transcript_bytes")
  , ("limits", "aggregate_payload_bytes"), ("limits", "attribute_entries")
  , ("limits", "attribute_depth"), ("limits", "jobs"), ("limits", "events")
  , ("sim", "enabled"), ("sim", "delay_schedule"), ("sim", "token_script")
  , ("sim", "fault_window_start"), ("sim", "fault_window_ticks")
  , ("tokens", "labels"), ("tokens", "so_pins"), ("tokens", "user_pins")
  ]

knownSections :: [String]
knownSections = ["storage", "engine", "async", "trace", "control", "fixtures", "limits", "sim", "tokens"]

-- | Strip a @#@ comment (outside string literals) and trim.
stripComment :: String -> String
stripComment = go False
  where
    go _ [] = []
    go True ('\\' : c : rest) = '\\' : c : go True rest
    go True ('"' : rest) = '"' : go False rest
    go True (c : rest) = c : go True rest
    go False ('#' : _) = []
    go False ('"' : rest) = '"' : go True rest
    go False (c : rest) = c : go False rest

trim :: String -> String
trim = reverse . dropWhile isSpace . reverse . dropWhile isSpace

-- | Parse the file into dotted-key assignments (bare; validation later).
parseToml :: String -> Either ConfigError (Map TomlKey TomlVal)
parseToml body = go (zip [1 :: Int ..] (lines body)) "" Map.empty
  where
    go [] _ acc = Right acc
    go ((n, raw) : rest) section acc =
      case trim (stripComment raw) of
        [] -> go rest section acc
        line@(c : _) | c == '[' -> case parseSection line of
          Nothing -> Left (CfgParseError ("line " ++ show n ++ ": bad section: " ++ line))
          Just sec
            | sec `elem` knownSections -> go rest sec acc
            | otherwise -> Left (CfgUnknownKey sec)
        line -> case break (== '=') line of
          (k, '=' : v) ->
            let key = trim k
            in if null key || any isSpace key
              then Left (CfgParseError ("line " ++ show n ++ ": bad key: " ++ line))
              else case parseVal (trim v) of
                Nothing -> Left (CfgParseError ("line " ++ show n ++ ": bad value: " ++ line))
                Just val -> go rest section (Map.insert (section, key) val acc)
          _ -> Left (CfgParseError ("line " ++ show n ++ ": expected key = value: " ++ line))

    parseSection ('[' : rest) = case reverse rest of
      (']' : inner) -> Just (trim (reverse inner))
      _ -> Nothing
    parseSection _ = Nothing

-- | One scalar of the supported subset (single line only).
parseVal :: String -> Maybe TomlVal
parseVal v
  | v == "true" = Just (TBool True)
  | v == "false" = Just (TBool False)
  | Just n <- parseInt v = Just (TInt n)
  | Just s <- parseStr v = Just (TStr s)
  | Just ss <- parseArr v = Just (TArr ss)
  | otherwise = Nothing

parseInt :: String -> Maybe Integer
parseInt s = case s of
  ('-' : ds) | not (null ds) && all isDigit ds -> Just (negate (read ds))
  ds | not (null ds) && all isDigit ds -> Just (read ds)
  _ -> Nothing

parseStr :: String -> Maybe String
parseStr ('"' : rest) = go rest []
  where
    go ('"' : tail_) acc
      | all isSpace tail_ = Just (reverse acc)
      | otherwise = Nothing
    go ('\\' : '"' : cs) acc = go cs ('"' : acc)
    go ('\\' : '\\' : cs) acc = go cs ('\\' : acc)
    go ('\\' : 'n' : cs) acc = go cs ('\n' : acc)
    go (c : cs) acc = go cs (c : acc)
    go [] _ = Nothing
parseStr _ = Nothing

parseArr :: String -> Maybe [String]
parseArr s = do
  inner <- deBracket (trim s)
  if all isSpace inner
    then Just []
    else mapM (parseStr . trim) (splitTop inner)
  where
    deBracket ('[' : rest) = case reverse rest of
      (']' : inner) -> Just (reverse inner)
      _ -> Nothing
    deBracket _ = Nothing
    splitTop = go False "" []
      where
        go _ cur acc [] = reverse (reverse cur : acc)
        go True cur acc ('"' : cs) = go False ('"' : cur) acc cs
        go True cur acc ('\\' : c : cs) = go True (c : '\\' : cur) acc cs
        go True cur acc (c : cs) = go True (c : cur) acc cs
        go False cur acc (',' : cs) = go False "" (reverse cur : acc) cs
        go False cur acc ('"' : cs) = go True ('"' : cur) acc cs
        go False cur acc (c : cs) = go False (c : cur) acc cs

-- ---------------------------------------------------------------------------
-- Build + validate
-- ---------------------------------------------------------------------------

-- | Parse and validate a TOML document.
parseConfig :: String -> Either ConfigError Config
parseConfig body = do
  kvs <- parseToml body
  mapM_ rejectUnknown (Map.keys kvs)
  build kvs
  where
    rejectUnknown k
      | k `elem` knownKeys = Right ()
      | otherwise = Left (CfgUnknownKey (dotted k))
    dotted (sec, key)
      | null sec = key
      | otherwise = sec ++ "." ++ key

-- | Load, parse and validate a TOML file.
loadConfigFile :: FilePath -> IO (Either ConfigError Config)
loadConfigFile path = do
  eBody <- try (readFile path) :: IO (Either IOException String)
  case eBody of
    Left _ -> pure (Left (CfgMissingFile path))
    Right body -> pure (parseConfig body)

getInt :: Map TomlKey TomlVal -> TomlKey -> Integer -> Either ConfigError Int
getInt kvs k def = case Map.lookup k kvs of
  Nothing -> Right (fromInteger def)
  Just (TInt n)
    | n >= 0 && n <= 0x7FFFFFFFFFFFFFFF -> Right (fromInteger n)
    | otherwise -> Left (CfgInvalid ("out of range: " ++ show k))
  Just v -> Left (CfgInvalid ("expected integer at " ++ show k ++ ", got " ++ show v))

getBool :: Map TomlKey TomlVal -> TomlKey -> Bool -> Either ConfigError Bool
getBool kvs k def = case Map.lookup k kvs of
  Nothing -> Right def
  Just (TBool b) -> Right b
  Just v -> Left (CfgInvalid ("expected boolean at " ++ show k ++ ", got " ++ show v))

getStr :: Map TomlKey TomlVal -> TomlKey -> String -> Either ConfigError String
getStr kvs k def = case Map.lookup k kvs of
  Nothing -> Right def
  Just (TStr s) -> Right s
  Just v -> Left (CfgInvalid ("expected string at " ++ show k ++ ", got " ++ show v))

getStrArr :: Map TomlKey TomlVal -> TomlKey -> [String] -> Either ConfigError [String]
getStrArr kvs k def = case Map.lookup k kvs of
  Nothing -> Right def
  Just (TArr ss) -> Right ss
  Just v -> Left (CfgInvalid ("expected string array at " ++ show k ++ ", got " ++ show v))

getMaybeStr :: Map TomlKey TomlVal -> TomlKey -> Either ConfigError (Maybe String)
getMaybeStr kvs k = case Map.lookup k kvs of
  Nothing -> Right Nothing
  Just (TStr s) -> Right (Just s)
  Just v -> Left (CfgInvalid ("expected string at " ++ show k ++ ", got " ++ show v))

build :: Map TomlKey TomlVal -> Either ConfigError Config
build kvs = do
  let d = defaultConfig
      dl = cfgLimits d
      ds = cfgStorage d
      da = cfgAsync d
      dt = cfgTrace d
      df = cfgFixtures d
  schema <- getInt kvs ("", "schema_version") 1
  if schema /= 1
    then Left (CfgInvalid ("unsupported schema_version: " ++ show schema))
    else pure ()
  profileName <- getStr kvs ("", "profile") "demo-maximal"
  profile <- case profileName of
    "demo-maximal" -> Right ProfileDemoMaximal
    "real-crypto" -> Right ProfileRealCrypto
    "scenario" -> Right ProfileScenario
    other -> Left (CfgInvalid ("unknown profile: " ++ other))
  ifaces <- getStrArr kvs ("", "interfaces") (cfgInterfaces d)
  if null ifaces || any (`notElem` ["2.40", "3.0", "3.1", "3.2"]) ifaces
    then Left (CfgInvalid ("interfaces must be a non-empty subset of 2.40/3.0/3.1/3.2: " ++ show ifaces))
    else pure ()
  seed <- getInt kvs ("", "seed") (fromIntegral (cfgSeed d))
  -- Config honesty: nothing reads cfgSeed (no determinism seeding
  -- consumes it), so only the documented default is accepted.
  if seed /= 1234
    then Left (CfgInvalid "seed is reserved (no determinism seeding reads it yet): the only accepted value is 1234")
    else pure ()
  storageKindName <- getStr kvs ("storage", "kind") "memory"
  storageKind <- case storageKindName of
    "memory" -> Right StorageMemory
    "sqlite" -> Right StorageSQLite
    other -> Left (CfgInvalid ("unknown storage.kind: " ++ other))
  storagePath <- getMaybeStr kvs ("storage", "path")
  case (storageKind, storagePath) of
    (StorageSQLite, Nothing) ->
      Left (CfgInvalid "storage.kind=sqlite requires an explicit storage.path (never silently shared)")
    -- Config honesty: the memory arm ignores storage.path, so an
    -- explicit path with kind=memory refuses (never silently ignored).
    (StorageMemory, Just _) ->
      Left (CfgInvalid "storage.path is only meaningful with storage.kind=sqlite (memory ignores it; refusing rather than silently ignoring)")
    _ -> pure ()
  busyMs <- getInt kvs ("storage", "busy_timeout_ms") (fromIntegral (scBusyTimeoutMs ds))
  -- Config honesty: SQLite opens with the pinned 5000ms busy timeout
  -- (never reads this knob), so only the default is accepted.
  if busyMs /= 5000
    then Left (CfgInvalid "storage.busy_timeout_ms is not honored (SQLite opens with the pinned 5000ms busy timeout): the only accepted value is 5000")
    else pure ()
  excl <- getBool kvs ("storage", "exclusive_provider_ownership") True
  -- Config honesty: the store is always single-writer with O_EXCL
  -- create, so @false@ (promised sharing) refuses.
  if not excl
    then Left (CfgInvalid "storage.exclusive_provider_ownership=false is not supported (the store is always single-writer with O_EXCL create): must be true")
    else pure ()
  engineKindName <- getStr kvs ("engine", "kind") "synthetic"
  engineKind <- case engineKindName of
    "synthetic" -> Right EngineSynthetic
    "openssl" -> Right EngineOpenSSL
    other -> Left (CfgInvalid ("unknown engine.kind: " ++ other))
  allowFallback <- getBool kvs ("engine", "allow_synthetic_fallback") False
  -- Config honesty: no synthetic fallback exists on any path, so
  -- @true@ (promised fallback) refuses.
  if allowFallback
    then Left (CfgInvalid "engine.allow_synthetic_fallback=true is not supported (no synthetic fallback exists on any path): must be false")
    else pure ()
  privCtx <- getBool kvs ("engine", "private_library_context") True
  -- Config honesty: native OpenSSL4 paths always open a private
  -- OSSL_LIB_CTX, so @false@ (promised sharing) refuses; the
  -- default is True to match.
  if not privCtx
    then Left (CfgInvalid "engine.private_library_context=false is not supported (native OpenSSL4 paths always open a private OSSL_LIB_CTX): must be true")
    else pure ()
  executor <- getStr kvs ("async", "executor") (acExecutor da)
  if executor /= "logical"
    then Left (CfgInvalid ("async.executor must be \"logical\": " ++ executor))
    else pure ()
  asyncOn <- getBool kvs ("async", "enabled") True
  pendingPolls <- getInt kvs ("async", "pending_polls") 2
  persistDet <- getBool kvs ("async", "persist_detached") False
  traceOn <- getBool kvs ("trace", "enabled") True
  tracePath <- getStr kvs ("trace", "path") (tcPath dt)
  redact <- getBool kvs ("trace", "redact_secrets") True
  -- Config honesty: secrets are always redacted (renderer + Show),
  -- so @false@ (promised visibility) refuses.
  if not redact
    then Left (CfgInvalid "trace.redact_secrets=false is not supported (secrets are always redacted): must be true")
    else pure ()
  traceQ <- getInt kvs ("trace", "queue_limit") 4096
  ctlOn <- getBool kvs ("control", "enabled") True
  -- Config honesty: the control plane is always on (nothing reads
  -- this knob), so @false@ refuses.
  if not ctlOn
    then Left (CfgInvalid "control.enabled=false is not supported (the control plane is always on): must be true")
    else pure ()
  maxReq <- getInt kvs ("control", "max_request_bytes") 1048576
  respBudget <- getInt kvs ("control", "response_budget_bytes") 65536
  if respBudget /= 65536
    then Left (CfgInvalid "control.response_budget_bytes is fixed at 65536 by the §5.1 protocol")
    else pure ()
  testOn <- getBool kvs ("control", "test_enabled") False
  fixSet <- getStr kvs ("fixtures", "set") (fcSet df)
  -- Config honesty: nothing reads the fixture selectors, so only the
  -- documented placeholders are accepted.
  if fixSet /= "minimal-demo"
    then Left (CfgInvalid "fixtures.set is reserved (no fixture application reads it yet): the only accepted value is \"minimal-demo\"")
    else pure ()
  fixApply <- getStr kvs ("fixtures", "apply") (fcApply df)
  if fixApply /= "new-store-only"
    then Left (CfgInvalid "fixtures.apply is reserved (no fixture application reads it yet): the only accepted value is \"new-store-only\"")
    else pure ()
  limSlots' <- getInt kvs ("limits", "slots") (fromIntegral (limSlots dl))
  limSessions' <- getInt kvs ("limits", "sessions") (fromIntegral (limSessions dl))
  limObjects' <- getInt kvs ("limits", "objects") (fromIntegral (limObjects dl))
  limBuffer' <- getInt kvs ("limits", "buffer_bytes") (fromIntegral (limBufferBytes dl))
  limTranscript' <- getInt kvs ("limits", "transcript_bytes") (fromIntegral (limTranscriptBytes dl))
  limAgg' <- getInt kvs ("limits", "aggregate_payload_bytes") (fromIntegral (limAggregatePayloadBytes dl))
  limAttrEntries' <- getInt kvs ("limits", "attribute_entries") (fromIntegral (limAttributeEntries dl))
  limAttrDepth' <- getInt kvs ("limits", "attribute_depth") (fromIntegral (limAttributeDepth dl))
  limJobs' <- getInt kvs ("limits", "jobs") (fromIntegral (limJobs dl))
  limEvents' <- getInt kvs ("limits", "events") (fromIntegral (limEvents dl))
  let lims = Limits limSlots' limSessions' limObjects' limBuffer' limTranscript'
        limAgg' limAttrEntries' limAttrDepth' limJobs' limEvents'
  if any (< 1) [limSlots', limSessions', limObjects', limBuffer', limTranscript'
               , limAgg', limAttrEntries', limAttrDepth', limJobs', limEvents']
    then Left (CfgInvalid "all [limits] values must be >= 1")
    else pure ()
  simOn <- getBool kvs ("sim", "enabled") False
  delayRaw <- getStrArr kvs ("sim", "delay_schedule") []
  delaySched <- mapM parseDelayEntry delayRaw
  scriptRaw <- getStrArr kvs ("sim", "token_script") []
  tokenScript <- mapM parseScriptEntry scriptRaw
  fwStart <- getInt kvs ("sim", "fault_window_start") 0
  fwTicks <- getInt kvs ("sim", "fault_window_ticks") 0
  if fwStart < 0 || fwStart > 1000000 || fwTicks < 0 || fwTicks > 1000000
    then Left (CfgInvalid "sim.fault_window_start/ticks must lie in 0..1000000")
    else pure ()
  tokLabels <- getStrArr kvs ("tokens", "labels") []
  tokSo <- getStrArr kvs ("tokens", "so_pins") []
  tokUser <- getStrArr kvs ("tokens", "user_pins") []
  tokEntries <- parseTokenCatalog kvs tokLabels tokSo tokUser
  pure Config
    { cfgSchemaVersion = schema
    , cfgProfile = profile
    , cfgInterfaces = ifaces
    , cfgSeed = seed
    , cfgStorage = StorageCfg storageKind storagePath busyMs excl
    , cfgEngine = EngineCfg engineKind allowFallback privCtx
    , cfgAsync = AsyncCfg executor asyncOn pendingPolls persistDet
    , cfgTrace = TraceCfg traceOn tracePath redact traceQ
    , cfgControl = ControlCfg ctlOn maxReq respBudget testOn
    , cfgFixtures = FixturesCfg fixSet fixApply
    , cfgLimits = lims
    , cfgSim = SimCfg simOn delaySched tokenScript fwStart fwTicks
    , cfgTokens = TokensCfg tokEntries
    }

-- | Parse one @NAME:TICKS@ delay-schedule entry: a non-empty
-- whitespace-free name plus non-negative ticks bounded at 1000000
-- (the scheduler-advance ceiling).
parseDelayEntry :: String -> Either ConfigError (String, Int)
parseDelayEntry entry = case break (== ':') entry of
  (name, ':' : ticks)
    | not (null name)
    , all scheduleChar name
    , not (null ticks)
    , all isDigit ticks
    , length ticks <= 7 ->
        let n = read ticks
        in if n >= 0 && n <= 1000000
          then Right (name, n)
          else Left (CfgInvalid ("sim.delay_schedule ticks out of range 0..1000000: " ++ entry))
  _ -> Left (CfgInvalid ("bad sim.delay_schedule entry (want NAME:TICKS): " ++ entry))
  where
    scheduleChar c = not (isSpace c) && c /= ':'

-- | Parse one @insert N@ \/ @remove N@ token-script entry (slot
-- 0..2^32-1, the control slot range).
parseScriptEntry :: String -> Either ConfigError (String, Int)
parseScriptEntry entry = case words entry of
  [op, n] | op == "insert" || op == "remove" -> checkSlot op n
  _ -> Left (CfgInvalid ("bad sim.token_script entry (want 'insert N' / 'remove N'): " ++ entry))
  where
    checkSlot op n
      | not (null n), all isDigit n, length n <= 10 =
          let v = read n :: Integer
          in if v >= 0 && v <= 0xFFFFFFFF
            then Right (op, fromInteger v)
            else bad
      | otherwise = bad
    bad = Left (CfgInvalid ("sim.token_script slot out of range: " ++ entry))

-- | Validate the @[tokens]@ parallel arrays into @(label, soPin,
-- userPin)@ triples (slot = index). An absent section (none of the
-- three keys present) is the home token only (@[]@); a present
-- section must be rectangular, non-empty, non-empty-labeled,
-- uniquely labeled, at most 16 entries (the seating bound:
-- 'Haskoki.Rules.rulesMaxTokens' via 'Haskoki.Session.admitToken'
-- — exceeding it refuses the open loudly, never truncates
-- silently), headed by @haskoki-demo@, with labels fitting the
-- 32-byte @CK_TOKEN_INFO@ label field.
parseTokenCatalog
  :: Map TomlKey TomlVal -> [String] -> [String] -> [String]
  -> Either ConfigError [(String, String, String)]
parseTokenCatalog kvs labels soPins userPins
  | not tokensPresent = pure []
  | nL /= nS || nL /= nU = Left (CfgInvalid
      ("tokens.labels/so_pins/user_pins lengths must match (ragged catalog): "
        ++ show (nL, nS, nU)))
  | null labels = Left (CfgInvalid
      "tokens catalog must declare at least one token (slot 0 = haskoki-demo)")
  | any null labels = Left (CfgInvalid "tokens.labels must all be non-empty")
  | nub labels /= labels = Left (CfgInvalid "tokens.labels must be unique")
  | nL > 16 = Left (CfgInvalid
      ("tokens catalog exceeds 16 entries (the seating bound): " ++ show nL))
  | slot0 /= "haskoki-demo" = Left (CfgInvalid
      "tokens.labels[0] must be haskoki-demo (slot 0 stability anchor)")
  | any (\l -> length l > 32) labels = Left (CfgInvalid
      "tokens.labels must fit the 32-byte CK_TOKEN_INFO label field")
  | otherwise = pure (zip3 labels soPins userPins)
  where
    tokensPresent = any (`Map.member` kvs)
      [("tokens", "labels"), ("tokens", "so_pins"), ("tokens", "user_pins")]
    nL = length labels
    nS = length soPins
    nU = length userPins
    -- Total slot-0 projection (the empty case is rejected above,
    -- so the fallback is unreachable, never silent).
    slot0 = case labels of
      (x : _) -> x
      [] -> ""

-- ---------------------------------------------------------------------------
-- Reporting
-- ---------------------------------------------------------------------------

-- | Report every §3 limit plus the control/trace bounds as
-- @(name, value)@ pairs. Names are the contract the CLI prints.
reportLimits :: Config -> [(String, Int)]
reportLimits cfg =
  [ ("slots", limSlots lims)
  , ("sessions", limSessions lims)
  , ("objects", limObjects lims)
  , ("buffer", limBufferBytes lims)
  , ("transcript", limTranscriptBytes lims)
  , ("aggregate", limAggregatePayloadBytes lims)
  , ("template_entries", limAttributeEntries lims)
  , ("template_depth", limAttributeDepth lims)
  , ("jobs", limJobs lims)
  , ("events", limEvents lims)
  , ("control", ccResponseBudgetBytes (cfgControl cfg))
  , ("control_max_request", ccMaxRequestBytes (cfgControl cfg))
  , ("trace", tcQueueLimit (cfgTrace cfg))
  ]
  where lims = cfgLimits cfg

-- | Report the effective @[sim]@ knobs as @(name, value)@ pairs
-- (reportLimits-style; the CLI prints them under @sim.*@).
reportSim :: Config -> [(String, String)]
reportSim cfg =
  [ ("enabled", show (scEnabled sim))
  , ("delay_schedule", intercalate "," [name ++ ":" ++ show t | (name, t) <- scDelaySchedule sim])
  , ("token_script", intercalate "," [op ++ " " ++ show s | (op, s) <- scTokenScript sim])
  , ("fault_window_start", show (scFaultWindowStart sim))
  , ("fault_window_ticks", show (scFaultWindowTicks sim))
  ]
  where sim = cfgSim cfg

-- | Report the declared @[tokens]@ catalog as @(name, value)@
-- pairs (reportSim-style; the CLI prints them under @tokens.*@).
-- Count + labels only: catalog PINs are NEVER reported (they are
-- example-grade fixture secrets). An absent section reports count
-- 0 (the open serves the home token; see the walkthrough).
reportTokens :: Config -> [(String, String)]
reportTokens cfg =
  [ ("count", show (length entries))
  , ("labels", intercalate "," [label | (label, _, _) <- entries])
  ]
  where entries = tcEntries (cfgTokens cfg)

-- ---------------------------------------------------------------------------
-- Resolve once
-- ---------------------------------------------------------------------------

-- | The init cell: empty until resolved, immutable after.
newtype ConfigCell = ConfigCell (IORef (Maybe Config))

-- | A fresh, unresolved cell.
newConfigCell :: IO ConfigCell
newConfigCell = ConfigCell <$> newIORef Nothing

-- | Run the resolver exactly once. The first call stores the value;
-- every later call fails with 'CfgAlreadyResolved' and the stored
-- value is unchanged (attempted mutation fails).
cellResolve :: ConfigCell -> IO (Either ConfigError Config) -> IO (Either ConfigError Config)
cellResolve (ConfigCell ref) action = do
  cur <- readIORef ref
  case cur of
    Just _ -> pure (Left CfgAlreadyResolved)
    Nothing -> do
      eCfg <- action
      case eCfg of
        Left err -> pure (Left err)
        Right cfg -> writeIORef ref (Just cfg) >> pure (Right cfg)

-- | Read the resolved value, if any.
cellConfig :: ConfigCell -> IO (Maybe Config)
cellConfig (ConfigCell ref) = readIORef ref

-- | Resolve from explicit paths (no environment reads): 'Nothing'
-- selects 'defaultConfig'; the trace override swaps only the trace
-- path. Missing files report 'CfgMissingFile'.
resolveFrom :: Maybe FilePath -> Maybe FilePath -> IO (Either ConfigError Config)
resolveFrom mPath mTrace = do
  eBase <- case mPath of
    Nothing -> pure (Right defaultConfig)
    Just path -> loadConfigFile path
  case eBase of
    Left err -> pure (Left err)
    Right cfg -> case mTrace of
      Nothing -> pure (Right cfg)
      Just tp ->
        let tr = cfgTrace cfg
        in pure (Right cfg { cfgTrace = tr { tcPath = tp } })

-- | Resolve once from the environment: @HASKOKI_CONFIG@ selects the
-- file, @HASKOKI_TRACE@ overrides the trace destination. No other
-- environment reads, no live watch: later environment changes are
-- invisible to the resolved value.
resolveOnce :: ConfigCell -> IO (Either ConfigError Config)
resolveOnce cell = do
  mPath <- lookupEnv "HASKOKI_CONFIG"
  mTrace <- lookupEnv "HASKOKI_TRACE"
  cellResolve cell (resolveFrom mPath mTrace)
