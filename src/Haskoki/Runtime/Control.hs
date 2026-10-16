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
  , newControlStateWith
  , ControlFailure (..)
  , controlFailureRV
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
  , base64DecodedLength
  , knownMechanism
  ) where

import Control.Concurrent.MVar (MVar, newMVar, withMVar)
import Control.Exception (evaluate, mask_)
import Control.Concurrent.STM
  ( TVar
  , atomically
  , newTVarIO
  , readTVar
  , writeTVar
  )
import qualified Data.ByteString.Char8 as BC8
import qualified Data.ByteString.Internal as BSI
import Data.ByteString (ByteString)
import Data.Char (isDigit, isSpace)
import Data.List (intercalate)
import qualified Data.Text as T
import Data.Word (Word64)
import Foreign.ForeignPtr (ForeignPtr, mallocForeignPtrBytes, withForeignPtr)
import Foreign.Marshal.Utils (copyBytes, fillBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (pokeByteOff)
import Data.Word (Word8)

import Haskoki.FFI.Exports (returnCodeToRV)
import Haskoki.Outcome (ModelFault (..))
import Haskoki.Registry.Generated (generatedIdByName)
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
  , csDispatch :: !(MVar ())
  , csPrepareReply :: !(IO ())
  }

-- | A fresh control state. The flags are fixed at construction. The
-- async table rides with the registry (removal quiesce); the
-- parameter keeps the owned-instance bundle explicit at call sites.
newControlState
  :: Config -> TokenRegistry -> AsyncTable -> Bool -> Bool -> IO ControlState
newControlState = newControlStateWith 0 (pure ())

-- | Internal constructor injection only: production starts generation zero.
-- The allocation observation runs before allocating a mutation's bounded reply
-- and before claiming work. No setter can rewind a live command generation.
newControlStateWith
  :: Word64 -> IO () -> Config -> TokenRegistry -> AsyncTable -> Bool -> Bool -> IO ControlState
newControlStateWith generation beforeReply cfg reg _asyncTable testEnabled unsafeDebug =
  ControlState cfg reg testEnabled unsafeDebug
    <$> newTVarIO generation
    <*> newTVarIO 0
    <*> newTVarIO Nothing
    <*> newTVarIO Nothing
    <*> newTVarIO Nothing
    <*> newMVar ()
    <*> pure beforeReply

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

-- | Extension-only failures: persisted/core return-code constructors and their
-- encodings stay unchanged. Unexpected exceptions still reach the outer 0x05
-- FFI fence, including faults after a committed presence transition.
data ControlFailure
  = ControlInvalid !String
  | ControlUnavailable
  | ControlPublishFault !ModelFault
  deriving (Eq, Show)

controlFailureRV :: ControlFailure -> Word64
controlFailureRV failure = case failure of
  ControlInvalid _ -> 0x07
  ControlUnavailable -> 0x190
  ControlPublishFault _ -> 0x06

failureText :: ControlFailure -> String
failureText failure = case failure of
  ControlInvalid why -> take 1024 why
  ControlUnavailable -> "presence_closed"
  ControlPublishFault _ -> "model_publication_fault"

type Reply = (Word64, ByteString, Word64)

data Outcome = OutcomeErr !ControlFailure | OutcomeOk ![(String, Json)]

invalid :: String -> Outcome
invalid = OutcomeErr . ControlInvalid

envelope :: Maybe String -> Outcome -> Json
envelope corr (OutcomeErr why) = JObj
  ([("schema_version", JNum 1), ("error", JStr (failureText why))] ++ corrField corr)
envelope corr (OutcomeOk fields) = JObj
  ([("schema_version", JNum 1)] ++ fields ++ corrField corr)

corrField :: Maybe String -> [(String, Json)]
corrField Nothing = []
corrField (Just c) = [("correlation_id", JStr c)]

outcomeRV :: Outcome -> Word64
outcomeRV (OutcomeErr failure) = controlFailureRV failure
outcomeRV (OutcomeOk _) = fromIntegral (returnCodeToRV CKR_OK)

-- Force rendering and enforce the budget BEFORE an action is claimed. Even
-- parser diagnostics and correlation echoes fit the same bounded envelope.
encodedReply :: Maybe String -> Outcome -> Either ControlFailure Reply
encodedReply corr outcome =
  let bytes = renderJson (envelope corr outcome)
      size = fromIntegral (BC8.length bytes)
  in if size > responseBudget then Left (ControlInvalid "response_over_budget")
     else Right (outcomeRV outcome, bytes, size)

failureReply :: Maybe String -> ControlFailure -> Reply
failureReply corr failure = case encodedReply corr (OutcomeErr failure) of
  Right reply -> reply
  Left _ -> case encodedReply Nothing (invalid "response_over_budget") of
    Right reply -> reply
    Left _ -> error "bounded control error envelope exceeds budget"

-- A complete, privately owned response allocation, prepared before cleanup.
-- Dynamic integer fields occupy twenty bytes of JSON whitespace/digits. Both
-- presence-change variants are ready before calling the owner; afterwards we
-- only fill the count in that allocation, with no rendering or resizing.
data PreparedReply = PreparedReply !Reply !(ForeignPtr Word8) ![(String, Int)]

counterPlaceholder :: Json
counterPlaceholder = JNum 10000000000000000000

prepareReply :: Reply -> [String] -> IO PreparedReply
prepareReply (rv, source, size) fields = do
  let offsets = [(name, BC8.length prefix + BC8.length marker)
        | name <- fields
        , let marker = BC8.pack ("\"" ++ name ++ "\":")
              (prefix, _) = BC8.breakSubstring marker source]
  -- Force every offset while failure is still harmless.
  _ <- evaluate (sum (map snd offsets))
  storage <- mallocForeignPtrBytes (fromIntegral size)
  withForeignPtr storage $ \dst -> BC8.useAsCStringLen source $ \(src, len) ->
    copyBytes dst (castPtr src) len
  body <- evaluate (BSI.fromForeignPtr storage 0 (fromIntegral size))
  pure (PreparedReply (rv, body, size) storage offsets)

finishReply :: PreparedReply -> [(String, Word64)] -> IO Reply
finishReply (PreparedReply reply storage fields) values = do
  withForeignPtr storage $ \ptr -> mapM_ (writeField ptr) values
  pure reply
  where
    writeField ptr (name, value) = case lookup name fields of
      Nothing -> error "unprepared control response field"
      Just offset -> do
        fillBytes (ptr `plusPtr` offset) 32 20
        writeDecimal ptr (offset + decimalDigits value - 1) value
    decimalDigits :: Word64 -> Int
    decimalDigits value
      | value < 10 = 1
      | otherwise = 1 + decimalDigits (value `quot` 10)
    writeDecimal :: Ptr Word8 -> Int -> Word64 -> IO ()
    writeDecimal ptr offset value = do
      let (remaining, digit) = value `quotRem` 10
      pokeByteOff ptr offset (fromIntegral (48 + digit) :: Word8)
      if remaining == 0 then pure () else writeDecimal ptr (offset - 1) remaining

-- | Query and short capacity return before even examining the request. The
-- private gate also serializes compare/mutate/increment; serving callers retain
-- the existing outer C state lock for the captured Standard owner's lifetime.
dispatchControl
  :: ControlState -> ByteString -> Maybe Word64 -> IO (Word64, ByteString, Word64)
dispatchControl st req mCap = case mCap of
  Nothing -> pure (fromIntegral (returnCodeToRV CKR_OK), BC8.empty, responseBudget)
  Just cap
    | cap < responseBudget -> pure (fromIntegral (returnCodeToRV CKR_BUFFER_TOO_SMALL), BC8.empty, responseBudget)
    | otherwise -> withMVar (csDispatch st) $ \_ -> mask_ $ do
        let maxReq = ccMaxRequestBytes (cfgControl (csConfig st))
        if BC8.length req > maxReq
          then pure (failureReply Nothing (ControlInvalid "request_too_large"))
          else case either (Left . ("malformed_json: " ++)) parseEnvelope (parseJson req) of
            Left err -> pure (failureReply Nothing (ControlInvalid err))
            Right (cmd, args, corr) -> do
              reply@(rv, _, _) <- dispatchCommand st cmd args corr
              if rv == fromIntegral (returnCodeToRV CKR_OK) then traceDispatch st cmd rv else pure ()
              pure reply

-- Every mutation enters here with the private dispatch gate held. Checked
-- failures consume neither a command generation nor an owner cleanup claim.
withMutation :: ControlState -> [(String, Json)] -> Maybe String -> (Word64 -> IO Reply) -> IO Reply
withMutation st args corr action
  | not (csTestEnabled st) = pure (failureReply corr (ControlInvalid "test_instance_required"))
  | otherwise = do
      generation <- controlGeneration st
      case lookup "expected_generation" args of
        Just (JNum wanted) | wanted /= fromIntegral generation ->
          refuse ("generation_mismatch: expected " ++ show wanted ++ ", live " ++ show generation)
        Just (JNum _) -> checked generation
        Just _ -> refuse "expected_generation must be an integer"
        Nothing -> checked generation
  where
    refuse = pure . failureReply corr . ControlInvalid
    checked generation
      | generation == maxBound = refuse "control_generation_exhausted"
      | otherwise = action (generation + 1)

commitGeneration :: ControlState -> Word64 -> IO ()
commitGeneration st generation = atomically (writeTVar (csGeneration st) generation)

dispatchCommand :: ControlState -> ControlCommand -> [(String, Json)] -> Maybe String -> IO Reply
dispatchCommand st CmdStatus args corr = do
  let mOffset = lookup "offset" args
      mLimit = lookup "limit" args
  outcome <- case (mOffset, mLimit) of
    (Just (JNum o), _) | o < 0 -> pure (invalid "offset must be >= 0")
    (_, Just (JNum l)) | l < 0 -> pure (invalid "limit must be >= 0")
    (Just (JNum o), Just (JNum l)) -> statusPage st (boundedInt o) (boundedInt l)
    (Just (JNum o), Nothing) -> statusPage st (boundedInt o) 64
    (Nothing, Just (JNum l)) -> statusPage st 0 (boundedInt l)
    (Nothing, Nothing) -> statusPage st 0 64
    _ -> pure (invalid "offset/limit must be integers")
  pure (either (failureReply corr) id (encodedReply corr outcome))
  where boundedInt n = fromInteger (min n (toInteger (maxBound :: Int)))
dispatchCommand st CmdTokenInsert args corr = dispatchPresence st True args corr
dispatchCommand st CmdTokenRemove args corr = dispatchPresence st False args corr
dispatchCommand st CmdSchedulerAdvance args corr = withMutation st [] corr $ \generation ->
  case argInt args "ticks" of
    Left err -> refuse err
    Right Nothing -> refuse "scheduler.advance needs integer 'ticks'"
    Right (Just n)
      | n < 1 || n > 1000000 -> refuse "ticks must be 1..1000000"
      | otherwise -> do
          tick <- atomically (readTVar (csTick st))
          let nextTick = tick + fromIntegral n
              outcome = OutcomeOk [("command", JStr "scheduler.advance"), ("advanced", JNum n)
                , ("tick", JNum (fromIntegral nextTick)), ("jobs_advanced", counterPlaceholder)
                , ("jobs_saturated", counterPlaceholder)]
          case encodedReply corr outcome of
            Left err -> pure (failureReply corr err)
            Right encoded -> do
              csPrepareReply st
              reply <- prepareReply encoded ["jobs_advanced", "jobs_saturated"]
              let sim = cfgSim (csConfig st)
                  schedule = if scEnabled sim then scDelaySchedule sim else []
              (advanced, saturated) <- advanceTicks (registryAsync (csRegistry st)) (fromInteger n) schedule
              atomically $ do
                writeTVar (csTick st) nextTick
                writeTVar (csGeneration st) generation
              finishReply reply [("jobs_advanced", fromIntegral advanced), ("jobs_saturated", fromIntegral saturated)]
  where refuse = pure . failureReply corr . ControlInvalid
dispatchCommand st CmdScenarioLoad args corr = withMutation st [] corr $ \generation ->
  case lookup "scenario" args of
    Nothing -> refuse "scenario.load needs a 'scenario' object"
    Just val -> case validateScenario val of
      Left err -> refuse ("scenario rejected: " ++ err)
      Right scenario -> case encodedReply corr (OutcomeOk
          [("command", JStr "scenario.load"), ("loaded", JStr (scName scenario))
          , ("actions", JNum (fromIntegral (length (scSteps scenario))))]) of
        Left err -> pure (failureReply corr err)
        Right encoded -> do
          csPrepareReply st
          reply <- prepareReply encoded []
          atomically $ do
            writeTVar (csScenario st) (Just scenario)
            writeTVar (csGeneration st) generation
          finishReply reply []
  where refuse = pure . failureReply corr . ControlInvalid

dispatchPresence :: ControlState -> Bool -> [(String, Json)] -> Maybe String -> IO Reply
dispatchPresence st present args corr = withMutation st args corr $ \generation ->
  case argInt args "slot" of
    Left err -> refuse err
    Right Nothing -> refuse ((if present then "token.insert" else "token.remove") ++ " needs an integer 'slot'")
    Right (Just n)
      | n < 0 || n > 0xFFFFFFFF -> refuse "slot out of range"
      | otherwise -> do
          owner <- atomically (readTVar (csPresenceOwner st))
          case owner of
            Nothing -> refuse "presence_owner_unbound"
            Just bound -> do
              let success changed = encodedReply corr (OutcomeOk
                    ([("command", JStr (if present then "token.insert" else "token.remove"))
                     , ("slot", JNum n), (if present then "inserted" else "removed", JBool changed)]
                     ++ [("jobs_canceled", counterPlaceholder) | not present]
                     ++ [("generation", JNum (fromIntegral generation))]))
              case (success True, success False) of
                (Left err, _) -> pure (failureReply corr err)
                (_, Left err) -> pure (failureReply corr err)
                (Right changed, Right unchanged) -> do
                  -- Allocate both success variants and every bounded failure
                  -- before entering Standard's irreversible cancellation work.
                  csPrepareReply st
                  yes <- prepareReply changed ["jobs_canceled" | not present]
                  no <- prepareReply unchanged ["jobs_canceled" | not present]
                  errors <- mapM (\err -> prepareReply (failureReply corr err) [])
                    [ControlInvalid "PresenceUnknownSlot", ControlInvalid "PresenceFixedSlot"
                    , ControlInvalid "PresenceEpochExhausted", ControlUnavailable
                    , ControlPublishFault (FaultInternal "publication")]
                  out <- ownerSetPresence bound (SlotId (fromInteger n)) present
                  case out of
                    Left err -> finishReply (errors !! failureIndex err) []
                    Right (change, canceled) -> do
                      commitGeneration st generation
                      finishReply (if presenceChanged change then yes else no)
                        [("jobs_canceled", fromIntegral canceled) | not present]
  where
    refuse = pure . failureReply corr . ControlInvalid
    failureIndex PresenceUnknownSlot = 0
    failureIndex PresenceFixedSlot = 1
    failureIndex PresenceEpochExhausted = 2
    failureIndex PresenceClosed = 3
    failureIndex (PresenceModelFault _) = 4

presenceChanged :: PresenceChange -> Bool
presenceChanged (PresenceChanged _) = True
presenceChanged (PresenceUnchanged _) = False

-- | Paginated status: presence window plus limits, tick, scenario,
-- and (unsafe-debug only) the fixture PIN marker.
statusPage :: ControlState -> Int -> Int -> IO Outcome
statusPage st offset limit = do
  owner <- atomically (readTVar (csPresenceOwner st))
  case owner of
    Nothing -> pure (invalid "presence_owner_unbound")
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
traceDispatch :: ControlState -> ControlCommand -> Word64 -> IO ()
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
        , teCkr = fromIntegral code
        , teDisposition = "delivered"
        , teReason = "rule:none"
        , teMode = "control"
        , teSecret = Nothing
        }) (fromIntegral code)
      pure ()

-- ---------------------------------------------------------------------------
-- Scenarios (declarative, bounded, no code)
-- ---------------------------------------------------------------------------

-- | Maximum scenario steps (rules are always empty).
maxScenarioActions :: Int
maxScenarioActions = 1024

-- | One validated scenario step: a known verb plus declarative
-- arguments. Verbs are data, never code: unknown verbs reject.
data ScenarioStep = ScenarioStep
  { stAction :: !String
  , stArgs :: ![(String, Json)]
  } deriving (Eq, Show)

-- | A validated scenario: name, always-empty rules, steps (file
-- order = execution order). 'scRules' stays a reserved field:
-- validation rejects any carried rule because the runner executes
-- steps only, never rules.
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

-- | Validate a scenario object: bounded step count, known verbs,
-- per-action arguments, well-formed extras. The top level carries
-- exactly 'name', 'rules', 'steps', an optional 'schema_version'
-- (which must be 1 when present), and an optional 'note' object;
-- every other top-level field rejects. 'note' is validated and
-- dropped (documentary by construction). Rules must be absent or
-- empty: the runner never executes them, so carrying any would
-- silently mislead. Arguments validate per action (known keys,
-- value shapes, and required keys). Step extras validate per
-- action: 'save_as' only on 'session.open' (a non-empty string),
-- 'expect' carrying the clause its action produces ('return'
-- everywhere except slot-event.wait, 'event' only there). A step
-- may also carry a 'note' object, validated and dropped like the
-- top-level one.
-- Effective session names are unique (positional slots count too,
-- and the live @"s1"@ alias occupies its name). Duplicate keys
-- reject at every level: lookup takes the first, so a second entry
-- would silently vanish.
validateScenario :: Json -> Either String Scenario
validateScenario (JObj kvs) = do
  checkDup "scenario field" kvs
  mapM_ checkTopField kvs
  name <- case lookup "name" kvs of
    Just (JStr n) | not (null n) -> Right n
    _ -> Left "scenario needs a non-empty string 'name'"
  case lookup "rules" kvs of
    Nothing -> pure ()
    Just (JArr []) -> pure ()
    Just (JArr _) ->
      Left "scenario 'rules' must be empty (rules are not executed)"
    Just _ -> Left "scenario 'rules' must be an array"
  stepsVal <- case lookup "steps" kvs of
    Just (JArr ss) -> Right ss
    _ -> Left "scenario needs a 'steps' array"
  steps <- mapM parseStep stepsVal
  checkOpenNames stepsVal
  if length steps > maxScenarioActions
    then Left "scenario exceeds the bounded action count"
    else Right (Scenario name [] steps)
  where
    parseStep (JObj skvs) = do
      checkDup "scenario step field" skvs
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
      mapM_ checkField skvs
      checkArgs act args
      checkSaveAs act skvs
      checkExpect act skvs
      pure (ScenarioStep act args)
    parseStep _ = Left "scenario steps must be objects"
    checkDup what pairs = case dupField pairs of
      Nothing -> Right ()
      Just k -> Left ("duplicate " ++ what ++ ": " ++ k)
    dupField = go []
      where
        go _ [] = Nothing
        go seen ((k, _) : rest)
          | k `elem` seen = Just k
          | otherwise = go (k : seen) rest
    checkField (k, v)
      | k `elem` ["action", "arguments", "save_as", "expect"] = Right ()
      | k == "note" = case v of
          JObj _ -> Right ()
          _ -> Left "scenario 'note' must be an object"
      | otherwise = Left ("unknown scenario step field: " ++ k)
    checkTopField (k, v)
      | k `elem` ["name", "rules", "steps"] = Right ()
      | k == "note" = case v of
          JObj _ -> Right ()
          _ -> Left "scenario 'note' must be an object"
      | k == "schema_version" = case v of
          JNum 1 -> Right ()
          _ -> Left "scenario 'schema_version' must be 1"
      | otherwise = Left ("unknown scenario field: " ++ k)
    checkArgs act pairs = do
      checkDup "scenario argument" pairs
      mapM_ (checkArg act) pairs
      mapM_ (checkRequired act pairs) (requiredArgs act)
    checkRequired act pairs k = case lookup k pairs of
      Just _ -> Right ()
      Nothing -> Left ("scenario action '" ++ act ++ "' needs argument '" ++ k ++ "'")
    checkArg act (k, v) = case lookup k (argSpec act) of
      Nothing -> Left ("unknown argument '" ++ k ++ "' for action '" ++ act ++ "'")
      Just ArgString -> case v of
        JStr _ -> Right ()
        _ -> typeErr "a string"
      Just ArgNonEmptyString -> case v of
        JStr s | not (null s) -> Right ()
        _ -> typeErr "a non-empty string"
      Just ArgBool -> case v of
        JBool _ -> Right ()
        _ -> typeErr "a boolean"
      Just ArgInt -> case v of
        JNum _ -> Right ()
        _ -> typeErr "an integer"
      Just (ArgIntRange lo hi) -> case v of
        JNum n | n >= lo && n <= hi -> Right ()
        _ -> Left ("scenario argument '" ++ k ++ "' for action '" ++ act
          ++ "' must be an integer in " ++ show lo ++ ".." ++ show hi)
      Just ArgTrue -> case v of
        JBool True -> Right ()
        _ -> Left ("scenario argument '" ++ k ++ "' for action '" ++ act
          ++ "' must be true (the simulator models read-write sessions only)")
      Just ArgBase64 -> case v of
        JStr s | Just _ <- base64DecodedLength s -> Right ()
        _ -> Left ("scenario argument '" ++ k ++ "' for action '" ++ act
          ++ "' must be strict base64")
      Just ArgMechanism -> case v of
        JStr m | knownMechanism m -> Right ()
        JStr m -> Left ("unknown mechanism '" ++ m ++ "' for action '" ++ act ++ "'")
        _ -> typeErr "a string"
      Just (ArgLiteral alts) -> case v of
        JStr s | s `elem` alts -> Right ()
        JStr s -> Left ("unsupported " ++ k ++ " '" ++ s
          ++ "' (supported: " ++ intercalate ", " alts ++ ") for action '" ++ act ++ "'")
        _ -> typeErr "a string"
      where
        typeErr want = Left ("scenario argument '" ++ k ++ "' for action '"
          ++ act ++ "' must be " ++ want)
    checkSaveAs act skvs = case lookup "save_as" skvs of
      Nothing -> Right ()
      Just val
        | act /= "session.open" ->
            Left "scenario step 'save_as' is only supported on 'session.open'"
        | otherwise -> case val of
            JStr n | not (null n) -> Right ()
            _ -> Left "scenario step 'save_as' must be a non-empty string"
    checkExpect act skvs = case lookup "expect" skvs of
      Nothing -> Right ()
      Just (JObj ekvs) -> do
        checkDup "scenario expect field" ekvs
        case act of
          "slot-event.wait" -> checkClause "event" ekvs
          _ -> checkClause "return" ekvs
      Just _ -> Left "scenario step 'expect' must be an object"
    checkClause want ekvs = do
      mapM_ (checkExpectField want) ekvs
      case lookup want ekvs of
        Just (JStr _) -> Right ()
        _ -> Left ("scenario step 'expect' needs a string '" ++ want ++ "'")
    checkExpectField want (k, _)
      | k == want = Right ()
      | otherwise = Left ("scenario step 'expect' field '" ++ k
          ++ "' is not supported here")
    -- Effective session names are unique before execution: each
    -- open takes its 'save_as' or the positional sN slot (N counts
    -- opens from 1, exactly as the runner numbers them). A name
    -- colliding with an earlier open refuses, as does a literal
    -- "s1" while the implicit alias is live (a named session
    -- exists but no literal s1): the alias already means the
    -- first-opened session. Runs after 'parseStep', so 'save_as'
    -- here is well-formed.
    checkOpenNames raw = go (1 :: Int) [] raw
      where
        go _ _ [] = Right ()
        go n occupied (JObj skvs : rest) = case lookup "action" skvs of
          Just (JStr "session.open") -> do
            let name = case lookup "save_as" skvs of
                  Just (JStr s) -> s
                  _ -> "s" ++ show n
            if name `elem` occupied
              then Left ("duplicate session name: " ++ name)
              else if name == "s1" && not (null occupied)
                then Left "duplicate session name: s1"
                else go (n + 1) (occupied ++ [name]) rest
          _ -> go n occupied rest
        go n occupied (_ : rest) = go n occupied rest
validateScenario _ = Left "scenario must be a JSON object"

-- | Expected argument value shapes.
data ArgType
  = ArgString
  | ArgNonEmptyString
  | ArgBool
  | ArgInt
  | ArgIntRange !Integer !Integer
  | ArgTrue
  | ArgBase64
  | ArgMechanism
  | ArgLiteral ![String]
  deriving (Eq, Show)

-- | Per-action execution schema: every admitted key is validated and
-- either consumed by the runner or admitted as a value needing no
-- execution branch (a single supported literal); anything else is a
-- typo the runner would silently ignore, so it rejects. An empty
-- session reference can never resolve ('save_as' is never empty),
-- so it rejects too.
argSpec :: String -> [(String, ArgType)]
argSpec "fixture.load" =
  [("fixture", ArgLiteral ["minimal-demo"])]
argSpec "session.open" =
  [("token", ArgNonEmptyString), ("read_write", ArgTrue), ("asynchronous", ArgBool)]
argSpec "session.login" =
  [("session", ArgNonEmptyString), ("role", ArgLiteral ["USER", "SO"]), ("pin", ArgString)]
argSpec "sign.init" =
  [("session", ArgNonEmptyString), ("fixture_key", ArgLiteral ["demo-signing-key"]), ("mechanism", ArgMechanism)]
argSpec "sign" =
  [("session", ArgNonEmptyString), ("data_base64", ArgBase64), ("output_capacity", ArgIntRange 0 16777216)]
argSpec "async.complete" =
  [("session", ArgNonEmptyString), ("function", ArgLiteral ["C_Sign"])]
argSpec "token.remove" = [("token", ArgNonEmptyString)]
argSpec "slot-event.wait" = [("nonblocking", ArgBool)]
argSpec "token.insert" = [("slot", ArgIntRange 0 0xFFFFFFFF)]
argSpec "async.delay" =
  [("session", ArgNonEmptyString), ("polls", ArgIntRange 0 1000000)]
argSpec "fault.window" =
  [("start", ArgIntRange 0 1000000), ("ticks", ArgIntRange 0 1000000)]
argSpec _ = []

-- | Arguments without a runner default: absence would fail during
-- execution, so validation requires them beforehand. Every other
-- key is optional ('session' defaults to the @"s1"@ slot,
-- 'asynchronous'\/'nonblocking'\/'token'\/'fixture' to runner defaults).
requiredArgs :: String -> [String]
requiredArgs "session.login" = ["role", "pin"]
requiredArgs "sign.init" = ["mechanism", "fixture_key"]
requiredArgs "sign" = ["data_base64", "output_capacity"]
requiredArgs "async.complete" = ["function"]
requiredArgs "token.insert" = ["slot"]
requiredArgs "async.delay" = ["polls"]
requiredArgs "fault.window" = ["start", "ticks"]
requiredArgs _ = []

-- | Strict base64 decoded length: empty decodes to 0; otherwise the
-- input length must be a multiple of 4, the body must use the
-- canonical alphabet only, at most two @=@ may terminate the input,
-- and the unused trailing bits of the final quantum must be zero
-- (non-canonical encodings such as @eB==@ are malformed). Anything
-- else (including data after the pad) is malformed.
base64DecodedLength :: String -> Maybe Int
base64DecodedLength s
  | null s = Just 0
  | length s `mod` 4 /= 0 = Nothing
  | '=' `elem` core = Nothing
  | not (all isB64 core) = Nothing
  | length pad > 2 = Nothing
  | not (all (== '=') pad) = Nothing
  | not canonicalTail = Nothing
  | otherwise = Just ((length s `div` 4) * 3 - length pad)
  where
    (core, pad) = span (/= '=') s
    isB64 c = ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z')
      || ('0' <= c && c <= '9') || c == '+' || c == '/'
    sextet c
      | 'A' <= c && c <= 'Z' = fromEnum c - fromEnum 'A'
      | 'a' <= c && c <= 'z' = fromEnum c - fromEnum 'a' + 26
      | '0' <= c && c <= '9' = fromEnum c - fromEnum '0' + 52
      | c == '+' = 62
      | otherwise = 63
    -- One pad: the last sextet carries 4 data bits, so its low 2
    -- bits must be zero; two pads: it carries 2 data bits, so its
    -- low 4 bits must be zero. An empty core with pads is
    -- unreachable (length and pad guards), and rejects.
    canonicalTail = case length pad of
      0 -> True
      1 -> case core of
        [] -> False
        _ -> sextet (last core) `mod` 4 == 0
      _ -> case core of
        [] -> False
        _ -> sextet (last core) `mod` 16 == 0

-- | A mechanism name is known when the generated inventory resolves
-- it (canonical or alias).
knownMechanism :: String -> Bool
knownMechanism m = case generatedIdByName (T.pack m) of
  Just _ -> True
  Nothing -> False
