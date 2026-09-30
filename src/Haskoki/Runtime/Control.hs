{- | In-process control entry point.

'HASKOKI_Control' (the C symbol in @cbits\/control_entry.c@) forwards
here. Requests are bounded versioned JSON; responses are UTF-8 JSON
without a trailing NUL under the fixed 64 KiB budget:

* null capacity = pure budget query: @(CKR_OK, empty, 65536)@,
  nothing parsed, nothing executed;
* capacity below the budget = @(CKR_BUFFER_TOO_SMALL, empty, 65536)@,
  nothing executed (no-mutation proven by pre\/post state equality);
* sufficient capacity = validate, execute once, return the actual
  length. Unknown commands, malformed JSON, generation mismatches
  and test-gate refusals all return the documented
  @CKR_ARGUMENTS_BAD@ with a tagged JSON body and no mutation.

Commands: @status@, @token.insert@, @token.remove@,
@scheduler.advance@, @scenario.load@. All but @status@ require a
test-enabled instance; only explicit unsafe-debug reveals test
key\/PIN material. Commands use logical control IDs, never public
PKCS#11 handles.

The minimal JSON reader\/writer here is also the scenario runner's
parser ('Haskoki.Ctl'): no new dependencies (@aeson@ is not in the
freeze).
-}
module Haskoki.Runtime.Control
  ( Json (..)
  , parseJson
  , renderJson
  , ControlCommand (..)
  , responseBudget
  , ControlState
  , newControlState
  , PresenceOwner (..)
  , bindPresenceOwner
  , bindPrivatePresenceOwner
  , setControlTracer
  , dispatchControl
  , controlGeneration
  , controlTokenPresent
  , Scenario (..)
  , ScenarioStep (..)
  , validateScenario
  , maxScenarioActions
  ) where

import Control.Concurrent.STM
  ( TVar
  , atomically
  , newTVarIO
  , readTVar
  , writeTVar
  )
import qualified Data.ByteString.Char8 as BC8
import Data.ByteString (ByteString)
import Data.Char (isDigit, isSpace)
import Data.List (intercalate)
import Data.Word (Word64)

import Haskoki.Runtime.Async (AsyncTable, advanceTicks)
import Haskoki.Runtime.Config (Config (..), ControlCfg (..), SimCfg (..))
import Haskoki.Runtime.Events
  ( InsertOutcome (..)
  , RemoveOutcome (..)
  , TokenRegistry
  , insertToken
  , registryAsync
  , removeToken
  , tokenGeneration
  , tokenPresent
  )
import Haskoki.Runtime.SlotEvents (SlotSnapshot (..), PresenceError (..), PresenceChange (..))
import Haskoki.Runtime.Trace (TraceEvent (..), Tracer, emitTrace)
import Haskoki.Types (ReturnCode (..), SlotId (..))

-- ---------------------------------------------------------------------------
-- Minimal JSON
-- ---------------------------------------------------------------------------

-- | JSON values (integers only; floats are rejected at parse).
data Json
  = JNull
  | JBool !Bool
  | JNum !Integer
  | JStr !String
  | JArr ![Json]
  | JObj ![(String, Json)]
  deriving (Eq, Show)

-- | Parser depth bound (nesting past this rejects).
maxJsonDepth :: Int
maxJsonDepth = 32

-- | Strict parse: the whole input must be one value.
parseJson :: ByteString -> Either String Json
parseJson bs = case parseValue 0 (BC8.unpack bs) of
  Left err -> Left err
  Right (v, rest)
    | all isSpace rest -> Right v
    | otherwise -> Left ("trailing bytes after JSON value: " ++ take 20 rest)

parseValue :: Int -> String -> Either String (Json, String)
parseValue depth s
  | depth > maxJsonDepth = Left "JSON nesting too deep"
  | otherwise = case dropWhile isSpace s of
      [] -> Left "unexpected end of JSON"
      ('{' : rest) -> parseObj depth rest
      ('[' : rest) -> parseArr depth rest
      ('"' : rest) -> parseStr rest
      ('t' : 'r' : 'u' : 'e' : rest) -> Right (JBool True, rest)
      ('f' : 'a' : 'l' : 's' : 'e' : rest) -> Right (JBool False, rest)
      ('n' : 'u' : 'l' : 'l' : rest) -> Right (JNull, rest)
      c : _ | c == '-' || isDigit c -> parseNum s
      other -> Left ("unexpected JSON byte: " ++ take 10 other)

parseObj :: Int -> String -> Either String (Json, String)
parseObj depth s = go (dropWhile isSpace s) []
  where
    go (']' : _) _ = Left "expected JSON object key"
    go ('}' : rest) acc = Right (JObj (reverse acc), rest)
    go ('"' : rest) acc = do
      parsed <- parseStr rest
      case parsed of
        (JStr k, rest1) -> do
          rest2 <- eat ':' rest1
          (v, rest3) <- parseValue (depth + 1) rest2
          case dropWhile isSpace rest3 of
            (',' : rest4) -> go (dropWhile isSpace rest4) ((k, v) : acc)
            ('}' : rest4) -> Right (JObj (reverse ((k, v) : acc)), rest4)
            _ -> Left "expected , or } in JSON object"
        _ -> Left "expected a JSON string key"
    go _ _ = Left "expected JSON object key"
    eat c str = case dropWhile isSpace str of
      (x : xs) | x == c -> Right xs
      _ -> Left ("expected '" ++ [c] ++ "' in JSON object")

parseArr :: Int -> String -> Either String (Json, String)
parseArr depth s = go (dropWhile isSpace s) []
  where
    go (']' : rest) acc = Right (JArr (reverse acc), rest)
    go str acc = do
      (v, rest1) <- parseValue (depth + 1) str
      case dropWhile isSpace rest1 of
        (',' : rest2) -> go (dropWhile isSpace rest2) (v : acc)
        (']' : rest2) -> Right (JArr (reverse (v : acc)), rest2)
        _ -> Left "expected , or ] in JSON array"

parseStr :: String -> Either String (Json, String)
parseStr = go []
  where
    go acc ('"' : rest) = Right (JStr (reverse acc), rest)
    go acc ('\\' : '"' : cs) = go ('"' : acc) cs
    go acc ('\\' : '\\' : cs) = go ('\\' : acc) cs
    go acc ('\\' : '/' : cs) = go ('/' : acc) cs
    go acc ('\\' : 'n' : cs) = go ('\n' : acc) cs
    go acc ('\\' : 'r' : cs) = go ('\r' : acc) cs
    go acc ('\\' : 't' : cs) = go ('\t' : acc) cs
    go acc ('\\' : 'u' : h1 : h2 : h3 : h4 : cs)
      | all isHex [h1, h2, h3, h4] =
          go (toEnum (hex4 [h1, h2, h3, h4]) : acc) cs
    go _ ('\\' : _) = Left "bad JSON string escape"
    go acc (c : cs) = go (c : acc) cs
    go _ [] = Left "unterminated JSON string"
    isHex c = isDigit c || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
    hex4 = foldl (\a h -> a * 16 + digit h) 0
    digit h
      | isDigit h = fromEnum h - fromEnum '0'
      | h >= 'a' = fromEnum h - fromEnum 'a' + 10
      | otherwise = fromEnum h - fromEnum 'A' + 10

parseNum :: String -> Either String (Json, String)
parseNum s =
  let s' = dropWhile isSpace s
      (num, rest) = span (\c -> isDigit c || c == '-') s'
  in if null num || num == "-" || "-" `isInfixOf'` drop 1 num
    then Left ("bad JSON number: " ++ take 10 s')
    else case reads num of
      [(n, "")] -> case rest of
        ('.' : _) -> Left "JSON floats are not accepted"
        ('e' : _) -> Left "JSON floats are not accepted"
        ('E' : _) -> Left "JSON floats are not accepted"
        _ -> Right (JNum n, rest)
      _ -> Left ("bad JSON number: " ++ num)
  where
    isInfixOf' needle hay = any (prefix needle) (tails hay)
    prefix [] _ = True
    prefix _ [] = False
    prefix (x : xs) (y : ys) = x == y && prefix xs ys
    tails [] = [[]]
    tails t@(_ : xs) = t : tails xs

-- | Canonical render (compact, no trailing NUL).
renderJson :: Json -> ByteString
renderJson = BC8.pack . go
  where
    go JNull = "null"
    go (JBool True) = "true"
    go (JBool False) = "false"
    go (JNum n) = show n
    go (JStr s) = "\"" ++ concatMap esc s ++ "\""
    go (JArr xs) = "[" ++ intercalate "," (map go xs) ++ "]"
    go (JObj kvs) = "{" ++ intercalate "," (map field kvs) ++ "}"
    field (k, v) = "\"" ++ concatMap esc k ++ "\":" ++ go v
    esc '"' = "\\\""
    esc '\\' = "\\\\"
    esc '\n' = "\\n"
    esc '\r' = "\\r"
    esc '\t' = "\\t"
    esc c
      | c < ' ' = "\\u" ++ hex4 (fromEnum c)
      | otherwise = [c]
    hex4 n =
      let h = "0123456789abcdef"
      in [h !! ((n `div` 4096) `mod` 16), h !! ((n `div` 256) `mod` 16)
         , h !! ((n `div` 16) `mod` 16), h !! (n `mod` 16)]

-- ---------------------------------------------------------------------------
-- Commands
-- ---------------------------------------------------------------------------

-- | The five initial commands (§5.1).
data ControlCommand
  = CmdStatus
  | CmdTokenInsert
  | CmdTokenRemove
  | CmdSchedulerAdvance
  | CmdScenarioLoad
  deriving (Eq, Show)

-- | The fixed §5.1 response budget.
responseBudget :: Word64
responseBudget = 65536

-- | Mutable control state: the resolved config, token registry,
-- logical clock, control generation, loaded scenario, test\/debug
-- flags, and an optional tracer.
data ControlState = ControlState
  { csConfig :: !Config
  , csRegistry :: !TokenRegistry
  , csTestEnabled :: !Bool
  , csUnsafeDebug :: !Bool
  , csGeneration :: !(TVar Word64)
  , csTick :: !(TVar Word64)
  , csScenario :: !(TVar (Maybe Scenario))
  , csTracer :: !(TVar (Maybe Tracer))
  , csPresenceOwner :: !(TVar (Maybe PresenceOwner))
  }

-- | A fresh control state. The flags are fixed at construction. The
-- async table rides with the registry (removal quiesce); the
-- parameter keeps the owned-instance bundle explicit at call sites.
newControlState
  :: Config -> TokenRegistry -> AsyncTable -> Bool -> Bool -> IO ControlState
newControlState cfg reg _asyncTable testEnabled unsafeDebug =
  ControlState cfg reg testEnabled unsafeDebug
    <$> newTVarIO 0
    <*> newTVarIO 0
    <*> newTVarIO Nothing
    <*> newTVarIO Nothing
    <*> newTVarIO Nothing

-- | The explicit owner of serving presence. Binding and clearing are done
-- under the C init/state ownership; hooks retain the Haskell value itself.
data PresenceOwner = PresenceOwner
  { ownerSnapshot :: IO [SlotSnapshot]
  , ownerSetPresence :: SlotId -> Bool -> IO (Either PresenceError (PresenceChange, Int))
  }

bindPresenceOwner :: ControlState -> Maybe PresenceOwner -> IO ()
bindPresenceOwner st owner = atomically (writeTVar (csPresenceOwner st) owner)

-- | Explicit legacy proof construction only. This preserves the old private
-- sixteen-slot status window and FIFO/job behavior without a serving fallback.
bindPrivatePresenceOwner :: ControlState -> TokenRegistry -> IO ()
bindPrivatePresenceOwner st reg = bindPresenceOwner st (Just (PresenceOwner snapshot change))
  where
    snapshot = mapM (\slot -> SlotSnapshot slot True
      <$> tokenPresent reg slot <*> tokenGeneration reg slot) [SlotId n | n <- [0 .. 15]]
    change slot True = do
      out <- insertToken reg slot
      pure (Right (case out of
        Inserted epoch -> (PresenceChanged epoch, 0)
        InsertAlreadyPresent epoch -> (PresenceUnchanged epoch, 0)))
    change slot False = do
      out <- removeToken reg slot
      case out of
        Removed epoch canceled -> pure (Right (PresenceChanged epoch, canceled))
        RemoveNotPresent -> do
          epoch <- tokenGeneration reg slot
          pure (Right (PresenceUnchanged epoch, 0))

-- | Attach the tracer dispatch events emit to (optional).
setControlTracer :: ControlState -> Tracer -> IO ()
setControlTracer st tr = atomically (writeTVar (csTracer st) (Just tr))

-- | Current control generation (bumped by every executed mutation).
controlGeneration :: ControlState -> IO Word64
controlGeneration st = atomically (readTVar (csGeneration st))

-- | Token presence through the control state (test oracle).
controlTokenPresent :: ControlState -> SlotId -> IO Bool
controlTokenPresent st slot = do
  owner <- atomically (readTVar (csPresenceOwner st))
  case owner of
    Nothing -> pure False
    Just bound -> any (\row -> ssSlotId row == slot && ssPresent row) <$> ownerSnapshot bound

-- ---------------------------------------------------------------------------
-- Dispatch
-- ---------------------------------------------------------------------------

-- | Parse the envelope: @schema_version@, @command@, @arguments@,
-- optional @correlation_id@.
parseEnvelope :: Json -> Either String (ControlCommand, [(String, Json)], Maybe String)
parseEnvelope (JObj kvs) = do
  schema <- need "schema_version" kvs
  case schema of
    JNum 1 -> pure ()
    _ -> Left "schema_version must be 1"
  cmdName <- need "command" kvs
  cmd <- case cmdName of
    JStr "status" -> Right CmdStatus
    JStr "token.insert" -> Right CmdTokenInsert
    JStr "token.remove" -> Right CmdTokenRemove
    JStr "scheduler.advance" -> Right CmdSchedulerAdvance
    JStr "scenario.load" -> Right CmdScenarioLoad
    JStr other -> Left ("unknown command: " ++ other)
    _ -> Left "command must be a string"
  argsVal <- need "arguments" kvs
  args <- case argsVal of
    JObj pairs -> Right pairs
    _ -> Left "arguments must be an object"
  let corr = case lookup "correlation_id" kvs of
        Just (JStr s) -> Just s
        _ -> Nothing
  pure (cmd, args, corr)
  where
    need k pairs = case lookup k pairs of
      Just v -> Right v
      Nothing -> Left ("missing request field: " ++ k)
parseEnvelope _ = Left "control request must be a JSON object"

argInt :: [(String, Json)] -> String -> Either String (Maybe Integer)
argInt args name = case lookup name args of
  Nothing -> Right Nothing
  Just (JNum n) -> Right (Just n)
  Just _ -> Left ("argument '" ++ name ++ "' must be an integer")

-- | Dispatch one request under the budget rule. The capacity is
-- 'Nothing' for a null response pointer (pure budget query) and
-- 'Just' @cap@ otherwise. Returns @(code, body, required-or-actual)@.
dispatchControl
  :: ControlState -> ByteString -> Maybe Word64 -> IO (ReturnCode, ByteString, Word64)
dispatchControl st req mCap = case mCap of
  Nothing -> pure (CKR_OK, BC8.empty, responseBudget)
  Just cap
    | cap < responseBudget -> pure (CKR_BUFFER_TOO_SMALL, BC8.empty, responseBudget)
    | otherwise -> run cap
  where
    run cap = do
      let maxReq = ccMaxRequestBytes (cfgControl (csConfig st))
      if BC8.length req > maxReq
        then pure (refused "request_too_large")
        else case parseJson req of
          Left err -> pure (refused ("malformed_json: " ++ err))
          Right val -> case parseEnvelope val of
            Left err -> pure (refused err)
            Right (cmd, args, corr) -> exec cap cmd args corr
    refused why =
      let body = renderJson (JObj [("schema_version", JNum 1), ("error", JStr why)])
      in (CKR_ARGUMENTS_BAD, body, fromIntegral (BC8.length body))
    exec cap cmd args corr = do
      outcome <- execute st cmd args
      let body = renderJson (envelope corr outcome)
          actual = fromIntegral (BC8.length body) :: Word64
      case outcome of
        OutcomeErr _ -> pure (CKR_ARGUMENTS_BAD, body, actual)
        OutcomeOk _
          | actual > cap ->
              let need = renderJson (JObj [("schema_version", JNum 1)
                                          , ("error", JStr "response_over_budget")])
              in pure (CKR_BUFFER_TOO_SMALL, need, actual)
          | otherwise -> do
              traceDispatch st cmd CKR_OK
              pure (CKR_OK, body, actual)

-- | Command outcome (internal): either a refusal tag or result fields.
data Outcome
  = OutcomeErr !String
  | OutcomeOk ![(String, Json)]

envelope :: Maybe String -> Outcome -> Json
envelope corr (OutcomeErr why) = JObj
  ([("schema_version", JNum 1), ("error", JStr why)] ++ corrField corr)
envelope corr (OutcomeOk fields) = JObj
  ([("schema_version", JNum 1)] ++ fields ++ corrField corr)

corrField :: Maybe String -> [(String, Json)]
corrField Nothing = []
corrField (Just c) = [("correlation_id", JStr c)]

-- | Execute one validated command. Test-gated commands refuse without
-- mutation when the instance is not test-enabled; generation checks
-- run before any mutation.
execute :: ControlState -> ControlCommand -> [(String, Json)] -> IO Outcome
execute st CmdStatus args = do
  let mOffset = lookup "offset" args
      mLimit = lookup "limit" args
  case (mOffset, mLimit) of
    (Just (JNum o), _) | o < 0 -> pure (OutcomeErr "offset must be >= 0")
    (_, Just (JNum l)) | l < 0 -> pure (OutcomeErr "limit must be >= 0")
    (Just (JNum o), Just (JNum l)) -> statusPage st (fromInteger o) (fromInteger l)
    (Just (JNum o), Nothing) -> statusPage st (fromInteger o) 64
    (Nothing, Just (JNum l)) -> statusPage st 0 (fromInteger l)
    (Nothing, Nothing) -> statusPage st 0 64
    _ -> pure (OutcomeErr "offset/limit must be integers")
execute st CmdTokenInsert args = withTestGate st $ do
  case argInt args "slot" of
    Left err -> pure (OutcomeErr err)
    Right Nothing -> pure (OutcomeErr "token.insert needs an integer 'slot'")
    Right (Just n)
      | n < 0 || n > 0xFFFFFFFF -> pure (OutcomeErr "slot out of range")
      | otherwise -> do
          eGen <- checkGeneration st args
          case eGen of
            Just refusal -> pure (OutcomeErr refusal)
            Nothing -> do
              out <- setOwnedPresence st (SlotId (fromInteger n)) True
              case out of
                Left refusal -> pure (OutcomeErr refusal)
                Right (change, _) -> do
                  g <- bumpGeneration st
                  pure (OutcomeOk [ ("command", JStr "token.insert")
                                  , ("slot", JNum n)
                                  , ("inserted", JBool (presenceChanged change))
                                  , ("generation", JNum (fromIntegral g))
                                  ])
execute st CmdTokenRemove args = withTestGate st $ do
  case argInt args "slot" of
    Left err -> pure (OutcomeErr err)
    Right Nothing -> pure (OutcomeErr "token.remove needs an integer 'slot'")
    Right (Just n)
      | n < 0 || n > 0xFFFFFFFF -> pure (OutcomeErr "slot out of range")
      | otherwise -> do
          eGen <- checkGeneration st args
          case eGen of
            Just refusal -> pure (OutcomeErr refusal)
            Nothing -> do
              out <- setOwnedPresence st (SlotId (fromInteger n)) False
              case out of
                Left refusal -> pure (OutcomeErr refusal)
                Right (change, canceled) -> do
                  g <- bumpGeneration st
                  pure (OutcomeOk [ ("command", JStr "token.remove")
                                  , ("slot", JNum n)
                                  , ("removed", JBool (presenceChanged change))
                                  , ("jobs_canceled", JNum (fromIntegral canceled))
                                  , ("generation", JNum (fromIntegral g))
                                  ])
execute st CmdSchedulerAdvance args = withTestGate st $ do
  case argInt args "ticks" of
    Left err -> pure (OutcomeErr err)
    Right Nothing -> pure (OutcomeErr "scheduler.advance needs integer 'ticks'")
    Right (Just n)
      | n < 1 || n > 1000000 -> pure (OutcomeErr "ticks must be 1..1000000")
      | otherwise -> do
          tick <- atomically $ do
            t <- readTVar (csTick st)
            let t' = t + fromIntegral n
            writeTVar (csTick st) t'
            pure t'
          -- Delay bridge: the advance (plus the configured [sim]
          -- schedule boost, when sim is enabled) decrements
          -- pending-job ticks through the async table, saturating at
          -- 1 so the last tick always drives via the poll path.
          let sim = cfgSim (csConfig st)
              sched = if scEnabled sim then scDelaySchedule sim else []
          (adv, sat) <- advanceTicks (registryAsync (csRegistry st)) (fromInteger n) sched
          _ <- bumpGeneration st
          pure (OutcomeOk [ ("command", JStr "scheduler.advance")
                          , ("advanced", JNum n)
                          , ("tick", JNum (fromIntegral tick))
                          , ("jobs_advanced", JNum (fromIntegral adv))
                          , ("jobs_saturated", JNum (fromIntegral sat))
                          ])
execute st CmdScenarioLoad args = withTestGate st $ do
  case lookup "scenario" args of
    Nothing -> pure (OutcomeErr "scenario.load needs a 'scenario' object")
    Just val -> case validateScenario val of
      Left err -> pure (OutcomeErr ("scenario rejected: " ++ err))
      Right sc -> do
        atomically (writeTVar (csScenario st) (Just sc))
        _ <- bumpGeneration st
        pure (OutcomeOk [ ("command", JStr "scenario.load")
                        , ("loaded", JStr (scName sc))
                        , ("actions", JNum (fromIntegral (length (scSteps sc))))
                        ])

setOwnedPresence :: ControlState -> SlotId -> Bool -> IO (Either String (PresenceChange, Int))
setOwnedPresence st slot present = do
  owner <- atomically (readTVar (csPresenceOwner st))
  case owner of
    Nothing -> pure (Left "presence_owner_unbound")
    Just bound -> either (Left . show) Right <$> ownerSetPresence bound slot present

presenceChanged :: PresenceChange -> Bool
presenceChanged (PresenceChanged _) = True
presenceChanged (PresenceUnchanged _) = False

-- | Refuse without mutation unless test-enabled.
withTestGate :: ControlState -> IO Outcome -> IO Outcome
withTestGate st action
  | csTestEnabled st = action
  | otherwise = pure (OutcomeErr "test_instance_required")

-- | Check @expected_generation@ when present ('Nothing' = proceed).
checkGeneration :: ControlState -> [(String, Json)] -> IO (Maybe String)
checkGeneration st args = case lookup "expected_generation" args of
  Nothing -> pure Nothing
  Just (JNum want) -> do
    g <- controlGeneration st
    pure (if fromIntegral g == want then Nothing
           else Just ("generation_mismatch: expected " ++ show want ++ ", live " ++ show g))
  Just _ -> pure (Just "expected_generation must be an integer")

-- | Bump the control generation (every executed mutation).
bumpGeneration :: ControlState -> IO Word64
bumpGeneration st = atomically $ do
  g <- readTVar (csGeneration st)
  let g' = g + 1
  writeTVar (csGeneration st) g'
  pure g'

-- | Paginated status: presence window plus limits, tick, scenario,
-- and (unsafe-debug only) the fixture PIN marker.
statusPage :: ControlState -> Int -> Int -> IO Outcome
statusPage st offset limit = do
  owner <- atomically (readTVar (csPresenceOwner st))
  case owner of
    Nothing -> pure (OutcomeErr "presence_owner_unbound")
    Just bound -> do
      g <- controlGeneration st
      tick <- atomically (readTVar (csTick st))
      mSc <- atomically (readTVar (csScenario st))
      slots <- ownerSnapshot bound
      let page = map presenceRow (take limit (drop offset slots))
      pure (OutcomeOk
        [ ("command", JStr "status")
        , ("generation", JNum (fromIntegral g))
        , ("tick", JNum (fromIntegral tick))
        , ("paginated", JBool True)
        , ("offset", JNum (fromIntegral offset))
        , ("limit", JNum (fromIntegral limit))
        , ("presence", JArr page)
        , ("scenario", maybe JNull (JStr . scName) mSc)
        , ("test_enabled", JBool (csTestEnabled st))
        ])
  where
    presenceRow snapshot =
      let SlotId n = ssSlotId snapshot
          base = [ ("slot", JNum (fromIntegral n))
                 , ("present", JBool (ssPresent snapshot))
                 , ("generation", JNum (fromIntegral (ssPresenceEpoch snapshot)))
                 ]
      in JObj (base ++ debugExtra)
    debugExtra
      | csUnsafeDebug st =
          [("fixture_pin", JStr "1234"), ("fixture_so_pin", JStr "5678")]
      | otherwise = []

-- | Emit the §7 line for a successful dispatch (best effort; the
-- code is already decided and never changes here).
traceDispatch :: ControlState -> ControlCommand -> ReturnCode -> IO ()
traceDispatch st cmd code = do
  mTr <- atomically (readTVar (csTracer st))
  case mTr of
    Nothing -> pure ()
    Just tr -> do
      _ <- emitTrace tr (TraceEvent
        { teFunction = "HASKOKI_Control:" ++ show cmd
        , teInterface = "extension"
        , teMechanism = Nothing
        , teSession = Nothing
        , teObject = Nothing
        , teJob = Nothing
        , teInputLen = 0
        , teOutputLen = 0
        , teCkr = codeNum code
        , teDisposition = "delivered"
        , teReason = "rule:none"
        , teMode = "control"
        , teSecret = Nothing
        }) (codeNum code)
      pure ()
  where
    codeNum CKR_OK = 0
    codeNum CKR_ARGUMENTS_BAD = 7
    codeNum CKR_BUFFER_TOO_SMALL = 0x150
    codeNum _ = 5

-- ---------------------------------------------------------------------------
-- Scenarios (declarative, bounded, no code)
-- ---------------------------------------------------------------------------

-- | Maximum scenario actions (steps + rules).
maxScenarioActions :: Int
maxScenarioActions = 1024

-- | One validated scenario step: a known verb plus declarative
-- arguments. Verbs are data, never code: unknown verbs reject.
data ScenarioStep = ScenarioStep
  { stAction :: !String
  , stArgs :: ![(String, Json)]
  } deriving (Eq, Show)

-- | A validated scenario: name, rules (kept verbatim, applied in
-- file order), steps (file order = execution order).
data Scenario = Scenario
  { scName :: !String
  , scRules :: ![Json]
  , scSteps :: ![ScenarioStep]
  } deriving (Eq, Show)

-- | Verbs the owned-instance runner interprets (including
-- test-gated sim verbs; unknown verbs still reject).
knownVerbs :: [String]
knownVerbs =
  [ "initialize", "fixture.load", "session.open", "session.login"
  , "sign.init", "sign", "async.complete", "token.remove"
  , "slot-event.wait", "finalize"
  , "token.insert", "async.delay", "fault.window"
  ]

-- | Validate a scenario object: bounded size, known verbs, object
-- arguments. Rules stay opaque JSON (the runner matches them in
-- deterministic file order).
validateScenario :: Json -> Either String Scenario
validateScenario (JObj kvs) = do
  name <- case lookup "name" kvs of
    Just (JStr n) | not (null n) -> Right n
    _ -> Left "scenario needs a non-empty string 'name'"
  rules <- case lookup "rules" kvs of
    Nothing -> Right []
    Just (JArr rs) -> Right rs
    Just _ -> Left "scenario 'rules' must be an array"
  stepsVal <- case lookup "steps" kvs of
    Just (JArr ss) -> Right ss
    _ -> Left "scenario needs a 'steps' array"
  steps <- mapM parseStep stepsVal
  if length steps + length rules > maxScenarioActions
    then Left "scenario exceeds the bounded action count"
    else Right (Scenario name rules steps)
  where
    parseStep (JObj skvs) = do
      act <- case lookup "action" skvs of
        Just (JStr a) -> Right a
        _ -> Left "scenario step needs a string 'action'"
      if act `elem` knownVerbs
        then pure ()
        else Left ("unknown scenario action (never executed as code): " ++ act)
      args <- case lookup "arguments" skvs of
        Nothing -> Right []
        Just (JObj pairs) -> Right pairs
        Just _ -> Left "scenario step 'arguments' must be an object"
      pure (ScenarioStep act args)
    parseStep _ = Left "scenario steps must be objects"
validateScenario _ = Left "scenario must be a JSON object"
