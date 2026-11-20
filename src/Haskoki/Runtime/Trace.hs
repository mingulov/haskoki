{- | JSONL trace contract.

Every event carries schema\/build\/source\/profile\/run IDs, sequence,
function, interface, mechanism, logical IDs, lengths, CKR,
disposition, reason and mode. PINs, key material and message bodies
are redacted by default (lengths survive; secrets never render).

The queue is bounded with a dropped counter; a trace-sink failure
never changes an already computed CKR ('emitTrace' returns its input
code unconditionally); a test mode treats drops as a harness failure
('runHarnessChecked').
-}
module Haskoki.Runtime.Trace
  ( TraceIds (..)
  , TraceSecret (..)
  , TraceEvent (..)
  , renderJSONL
  , AsyncTableId (..)
  , Tracer
  , newTracer
  , fileSink
  , newFileTracer
  , emitTrace
  , DrainReport (..)
  , drainTracer
  , droppedTraces
  , runHarnessChecked
  , emitKeptFailure
  , emitKeptJobFailure
  , emitRejectionCause
  , trySync
  ) where

import Control.Concurrent.STM
  ( TVar
  , atomically
  , newTVarIO
  , readTVar
  , writeTVar
  )
import Control.Exception (AsyncException, SomeException, fromException, throwIO, try)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.ByteString (ByteString)
import System.Posix.Process (getProcessID)
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Word (Word32, Word64)

import Haskoki.Operation.Effect (CryptoCause (..), CryptoError (..), functionCName)
import Haskoki.Outcome (Rejection (rejCause))
import Haskoki.ReturnCode.Generated (returnCodeToRV)
import Haskoki.Runtime.Attach (AsyncTableId (..))
import Haskoki.Runtime.Config (TraceCfg (..))
import Haskoki.Types (JobId (..), ReturnCode (..), redactShown)

-- ---------------------------------------------------------------------------
-- Events
-- ---------------------------------------------------------------------------

-- | The §7 identity prefix shared by every line of a run.
data TraceIds = TraceIds
  { tiSchema :: !String
  , tiBuild :: !String
  , tiSource :: !String
  , tiProfile :: !String
  , tiRun :: !String
  } deriving (Eq, Show)

-- | Secret payload classes. The renderer emits only the class +
-- length, never the bytes.
data TraceSecret
  = TracePin !String
  | TraceKeyMaterial !String
  | TraceBody !String
  deriving (Eq)

-- | 'Show' redacts secrets exactly like the renderer:
-- class plus length only ('redactShown'), so a diagnostic over an
-- event value cannot bypass the JSONL discipline. Explicit
-- inspection pattern-matches the exported constructors.
instance Show TraceSecret where
  show (TracePin p) = "TracePin " ++ redactShown "pin" (length p)
  show (TraceKeyMaterial m) =
    "TraceKeyMaterial " ++ redactShown "key" (length m)
  show (TraceBody b) = "TraceBody " ++ redactShown "body" (length b)

-- | One traced call.
data TraceEvent = TraceEvent
  { teFunction :: !String
  , teInterface :: !String
  , teMechanism :: !(Maybe String)
  , teSession :: !(Maybe String)
  , teObject :: !(Maybe String)
  , teJob :: !(Maybe String)
  , teInputLen :: !Int
  , teOutputLen :: !Int
  , teCkr :: !Word32
  , teDisposition :: !String
  , teReason :: !String
  , teMode :: !String
  , teSecret :: !(Maybe TraceSecret)
  } deriving (Eq)

-- | 'Show' renders every event field; the secret renders through
-- its redacted instance above (never the payload bytes).
instance Show TraceEvent where
  show ev = "TraceEvent {teFunction = " ++ show (teFunction ev)
    ++ ", teInterface = " ++ show (teInterface ev)
    ++ ", teMechanism = " ++ show (teMechanism ev)
    ++ ", teSession = " ++ show (teSession ev)
    ++ ", teObject = " ++ show (teObject ev)
    ++ ", teJob = " ++ show (teJob ev)
    ++ ", teInputLen = " ++ show (teInputLen ev)
    ++ ", teOutputLen = " ++ show (teOutputLen ev)
    ++ ", teCkr = " ++ show (teCkr ev)
    ++ ", teDisposition = " ++ show (teDisposition ev)
    ++ ", teReason = " ++ show (teReason ev)
    ++ ", teMode = " ++ show (teMode ev)
    ++ ", teSecret = " ++ show (teSecret ev) ++ "}"

-- | Escape a JSON string body (quotes, backslash, controls).
escapeJson :: String -> String
escapeJson = concatMap esc
  where
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

-- | Render one JSONL line (no trailing newline; the sink frames).
-- Secrets render as @{"redacted":true,"kind":...,"length":N}@.
renderJSONL :: TraceIds -> Word64 -> TraceEvent -> ByteString
renderJSONL ids seqNo ev = BC8.pack line
  where
    line = "{" ++ joined ++ "}"
    joined = concatWith ","
      [ strField "schema" (tiSchema ids)
      , strField "build" (tiBuild ids)
      , strField "source" (tiSource ids)
      , strField "profile" (tiProfile ids)
      , strField "run" (tiRun ids)
      , numField "seq" (fromIntegral seqNo :: Integer)
      , strField "function" (teFunction ev)
      , strField "interface" (teInterface ev)
      , maybeField "mechanism" (teMechanism ev)
      , maybeField "session" (teSession ev)
      , maybeField "object" (teObject ev)
      , maybeField "job" (teJob ev)
      , numField "input_len" (fromIntegral (teInputLen ev) :: Integer)
      , numField "output_len" (fromIntegral (teOutputLen ev) :: Integer)
      , numField "ckr" (fromIntegral (teCkr ev) :: Integer)
      , strField "disposition" (teDisposition ev)
      , strField "reason" (teReason ev)
      , strField "mode" (teMode ev)
      , secretField (teSecret ev)
      ]
    concatWith _ [] = ""
    concatWith _ [x] = x
    concatWith sep (x : xs) = x ++ sep ++ concatWith sep xs
    strField k v = "\"" ++ k ++ "\":\"" ++ escapeJson v ++ "\""
    numField k n = "\"" ++ k ++ "\":" ++ show n
    secretField Nothing = "\"secret\":null"
    secretField (Just s) =
      "\"secret\":{\"redacted\":true,\"kind\":\"" ++ kind ++ "\",\"length\":" ++ show len ++ "}"
      where
        (kind, len) = case s of
          TracePin p -> ("pin" :: String, length p)
          TraceKeyMaterial m -> ("key", length m)
          TraceBody b -> ("body", length b)

-- | Optional string field (null when absent).
maybeField :: String -> Maybe String -> String
maybeField k Nothing = "\"" ++ k ++ "\":null"
maybeField k (Just v) = "\"" ++ k ++ "\":\"" ++ escapeJson v ++ "\""

-- ---------------------------------------------------------------------------
-- Bounded tracer
-- ---------------------------------------------------------------------------

-- | A bounded trace queue over a fallible sink.
data Tracer = Tracer
  { trBound :: !Int
  , trSink :: !(ByteString -> IO (Either String ()))
  , trStrict :: !Bool
  , trQueue :: !(TVar (Seq ByteString))
  , trDropped :: !(TVar Int)
  , trSeq :: !(TVar Word64)
  , trIds :: !TraceIds
  , trFailed :: !(TVar Int)
  }

-- | A fresh tracer: bound, sink, drops-as-failure mode. Identity
-- prefix defaults to the built-in schema (overridable per render).
newTracer :: Int -> (ByteString -> IO (Either String ())) -> Bool -> IO Tracer
newTracer bound sink strict = Tracer bound sink strict
  <$> newTVarIO Seq.empty
  <*> newTVarIO 0
  <*> newTVarIO 0
  <*> pure (TraceIds "trace/1" "haskoki" "provider" "demo-maximal" "run-0")
  <*> newTVarIO 0

-- | Append-only trace sink (best effort; failures are counted by the
-- tracer, never thrown). @{pid}@ in the path expands to the pid.
-- A disabled config sinks to nowhere (success without writing).
fileSink :: TraceCfg -> ByteString -> IO (Either String ())
fileSink tc line
  | not (tcEnabled tc) = pure (Right ())
  | otherwise = do
      pid <- getProcessID
      let path = expandPid (tcPath tc) (fromIntegral pid)
      r <- trySync (BS.appendFile path (line <> BS.singleton 0x0A))
      case r of
        Right () -> pure (Right ())
        Left ex -> pure (Left (show ex))
  where
    expandPid [] _ = []
    expandPid ('{' : 'p' : 'i' : 'd' : '}' : rest) pid =
      show (pid :: Int) ++ expandPid rest pid
    expandPid (c : rest) pid = c : expandPid rest pid

-- | A file-backed tracer from the trace config (queue bound from
-- the config floor, non-strict).
newFileTracer :: TraceCfg -> IO Tracer
newFileTracer tc = newTracer (max 8 (tcQueueLimit tc)) (fileSink tc) False

-- | 'try' that never swallows cancellation: async exceptions
-- rethrow immediately (close paths must unwind); only sync
-- failures return 'Left'.
trySync :: IO a -> IO (Either SomeException a)
trySync act = do
  r <- try act
  case r of
    Right v -> pure (Right v)
    Left ex -> case (fromException ex :: Maybe AsyncException) of
      Just _ -> throwIO ex
      Nothing -> pure (Left ex)

-- | Emit an event: render, enqueue within the bound (else count a
-- drop). ALWAYS returns the input CKR unchanged — trace failure
-- (queue or sink) never changes an already computed PKCS#11 result.
emitTrace :: Tracer -> TraceEvent -> Word32 -> IO Word32
emitTrace tr ev ckr = do
  atomically $ do
    n <- readTVar (trSeq tr)
    writeTVar (trSeq tr) (n + 1)
    q <- readTVar (trQueue tr)
    if Seq.length q < trBound tr
      then writeTVar (trQueue tr) (q Seq.|> renderJSONL (trIds tr) n ev)
      else do
        d <- readTVar (trDropped tr)
        writeTVar (trDropped tr) (d + 1)
  pure ckr

-- | Drain outcome.
data DrainReport = DrainReport
  { drWritten :: !Int
  , drFailed :: !Int
  } deriving (Eq, Show)

-- | Write every queued line through the sink. Sink failures (Left or
-- thrown) are counted, never thrown, and never touch any CKR.
drainTracer :: Tracer -> IO DrainReport
drainTracer tr = do
  lines_ <- atomically $ do
    q <- readTVar (trQueue tr)
    writeTVar (trQueue tr) Seq.empty
    pure (foldr (:) [] q)
  go lines_ 0 0
  where
    go [] w f = do
      atomically $ do
        n <- readTVar (trFailed tr)
        writeTVar (trFailed tr) (n + f)
      pure (DrainReport w f)
    go (l : ls) w f = do
      eR <- trySync (trSink tr l)
      case eR of
        Right (Right ()) -> go ls (w + 1) f
        _ -> go ls w (f + 1)

-- | Total drops (queue overflow only; sink failures live in the drain
-- report and 'runHarnessChecked').
droppedTraces :: Tracer -> IO Int
droppedTraces tr = atomically (readTVar (trDropped tr))

-- | Harness verdict: 'False' iff drops-as-failure mode is armed AND
-- anything was dropped (overflow or sink failure). A non-strict
-- tracer always passes (loss is counted, not fatal).
runHarnessChecked :: Tracer -> IO Bool
runHarnessChecked tr = do
  d <- atomically (readTVar (trDropped tr))
  f <- atomically (readTVar (trFailed tr))
  pure (not (trStrict tr) || (d == 0 && f == 0))

-- | Emit one kept-general-error cause row: the exact C entry, the
-- served general-error value, the typed constructor with its
-- diagnostic fields, disposition \"rejected\". Best effort like
-- every emission (failures counted, never thrown).
emitKeptFailure :: Tracer -> CryptoCause -> IO ()
emitKeptFailure tr cause = do
  _ <- emitTrace tr (causeEvent "sync" Nothing cause)
    (returnCodeToRV CKR_GENERAL_ERROR)
  pure ()

-- | 'emitKeptFailure' for an async job terminal: mode \"async\"
-- with the table-qualified job tag for correlation (job ids
-- restart per table, so the tag carries both).
emitKeptJobFailure :: Tracer -> AsyncTableId -> JobId -> CryptoCause -> IO ()
emitKeptJobFailure tr (AsyncTableId t) (JobId n) cause = do
  _ <- emitTrace tr
    (causeEvent "async" (Just ("j" ++ show n ++ "@t" ++ show t)) cause)
    (returnCodeToRV CKR_GENERAL_ERROR)
  pure ()

causeEvent :: String -> Maybe String -> CryptoCause -> TraceEvent
causeEvent mode job (CryptoCause fid err) = TraceEvent
  { teFunction = functionCName fid
  , teInterface = "3.2"
  , teMechanism = Nothing
  , teSession = Nothing
  , teObject = Nothing
  , teJob = job
  , teInputLen = 0
  , teOutputLen = 0
  , teCkr = returnCodeToRV CKR_GENERAL_ERROR
  , teDisposition = "rejected"
  , teReason = causeReason err
  , teMode = mode
  , teSecret = Nothing
  }

-- | The typed constructor with its diagnostic fields. Whys are
-- backend-authored labels (ops, counts, curve names) — never
-- caller echoes or key material (audited at introduction; a new
-- producer echoing caller input must sanitize here).
causeReason :: CryptoError -> String
causeReason err = case err of
  CryptoFailed s -> "CryptoFailed(" ++ s ++ ")"
  CryptoUnsupported o w -> "CryptoUnsupported(" ++ o ++ "," ++ w ++ ")"
  CryptoBadParam o w -> "CryptoBadParam(" ++ o ++ "," ++ w ++ ")"
  CryptoBadKey o w -> "CryptoBadKey(" ++ o ++ "," ++ w ++ ")"
  CryptoMechParamInvalid o w -> "CryptoMechParamInvalid(" ++ o ++ "," ++ w ++ ")"
  CryptoAuthFailed o -> "CryptoAuthFailed(" ++ o ++ ")"
  CryptoSigLenRange o -> "CryptoSigLenRange(" ++ o ++ ")"
  CryptoInvalidState o w -> "CryptoInvalidState(" ++ o ++ "," ++ w ++ ")"
  CryptoNative o c w -> "CryptoNative(" ++ o ++ "," ++ show c ++ "," ++ w ++ ")"
  CryptoResourceGone o rid -> "CryptoResourceGone(" ++ o ++ "," ++ show rid ++ ")"

-- | Emit the rejection's cause, if it carries one. Call after
-- publish and resource release; a causeless rejection emits
-- nothing.
emitRejectionCause :: Tracer -> Rejection -> IO ()
emitRejectionCause tr rej = case rejCause rej of
  Just cause -> emitKeptFailure tr cause
  Nothing -> pure ()
