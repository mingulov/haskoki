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
  , tracerAliasesStore
  , tracerAliasesStoreWith
  , isUtf8EncodingName
  , shouldDropForEncoding
  , spellingDrops
  , spellingDropsWith
  , tracerFilePath
  , uriEffective
  , SpellingRefusal (..)
  , effectiveStorePath
  , renderSpellingRefusal
  , noteTraceDropped
  , emitTrace
  , DrainReport (..)
  , drainTracer
  , droppedTraces
  , writeFully
  , withReaderHeld
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
import Control.Exception (AsyncException, IOException, SomeException, bracket, fromException, throwIO, try)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isAlphaNum, isAscii, isHexDigit, toUpper)
import Data.List (isPrefixOf)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Foreign.C.Error (Errno (..), eNOENT)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import GHC.IO.Encoding (getFileSystemEncoding, textEncodingName)
import GHC.IO.Exception (ioe_errno)
import System.Directory (canonicalizePath)
import System.FilePath (isAbsolute, takeDirectory, takeFileName, (</>))
import System.Posix.Files (deviceID, fileID, getFdStatus, getFileStatus, isNamedPipe, readSymbolicLink)
import System.Posix.IO (OpenFileFlags (..), OpenMode (..), closeFd, defaultFileFlags, fdWriteBuf, openFd)
import System.Posix.Process (getProcessID)
import System.Posix.Types (Fd)
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Word (Word32, Word64, Word8)

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
  , trPath :: !(Maybe FilePath)
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
  <*> pure Nothing

-- | Append-only trace sink (best effort; failures are counted by the
-- tracer, never thrown). @{pid}@ in the path expands to the pid.
-- A disabled config sinks to nowhere (success without writing).
fileSink :: TraceCfg -> ByteString -> IO (Either String ())
fileSink tc line
  | not (tcEnabled tc) = pure (Right ())
  | otherwise = do
      pid <- getProcessID
      let path = expandPid (tcPath tc) (fromIntegral pid)
      r <- trySync (appendNonblocking path (line <> BS.singleton 0x0A))
      case r of
        Right True -> pure (Right ())
        Right False -> pure (Left "trace sink busy or unavailable")
        Left ex -> pure (Left (show ex))

-- | Open-append-close without ever waiting on FIFO/pipe capacity
-- or readers: O_NONBLOCK fails fast on FIFOs with no reader (or
-- full) instead of stalling the caller — the refusal drain runs
-- synchronously under the initialization lock, so waiting would
-- hang C_Initialize. Regular files behave as before (short
-- writes retry to completion); a write that makes no progress,
-- or any write error, fails without waiting — the descriptor is
-- non-blocking, so a retry never stalls on a full readerless
-- FIFO. O_NONBLOCK does not make storage IO non-blocking (a
-- wedged filesystem can still stall). FIFOs hold a reader across
-- each open and its writes: a reader disconnecting mid-flight
-- would otherwise terminate the host with SIGPIPE when it
-- restored SIG_DFL (a blocked SIGPIPE would stay pending and
-- deliver on unmask; dispositions are process-global and must
-- not be touched). The holder never reads. Readerless opens of
-- named FIFOs still fail fast at open; reopened anonymous pipes
-- (via /proc/self/fd) open a separate description on the same
-- buffer (flags independent) and succeed into the buffer
-- instead. A path swapped for another FIFO
-- between the type check and the holder open is out of scope
-- (same class as post-check replacement). Mode 0666 matches
-- 'appendFile'.
appendNonblocking :: FilePath -> ByteString -> IO Bool
appendNonblocking path bytes =
  bracket (openFd path WriteOnly flags) closeFd $ \fd -> do
    fifo <- isFifoFd fd
    withReaderHeld fifo path $
      BS.useAsCStringLen bytes $ \(p, len) ->
        writeFully (\q n -> fromIntegral <$> fdWriteBuf fd (castPtr q) (fromIntegral n))
          (castPtr p) len
  where
    flags = defaultFileFlags { append = True, creat = Just 0o666, nonBlock = True, cloexec = True }

-- | Whether an open descriptor is a FIFO (checked on the fd
-- itself, so a replaced path cannot misdirect it).
isFifoFd :: Fd -> IO Bool
isFifoFd fd = isNamedPipe <$> getFdStatus fd

-- | Hold a nonblocking read descriptor across an action (FIFOs
-- only): guarantees a reader exists for every write inside, so
-- no write can raise SIGPIPE regardless of host dispositions.
-- The holder sets cloexec so fork+exec children cannot retain
-- it (a retained reader would let later writes succeed after
-- the collector is gone).
withReaderHeld :: Bool -> FilePath -> IO a -> IO a
withReaderHeld False _ act = act
withReaderHeld True path act =
  bracket (openFd path ReadOnly defaultFileFlags { nonBlock = True, cloexec = True }) closeFd (const act)

-- | Write a buffer completely through a prim reporting bytes
-- written (throwing on error): short writes retry; no progress
-- or any error fails. The concrete 'AsyncException' type
-- propagates (the prim runs under 'trySync'); 'Timeout'
-- converts to failure like a sync error. The injected prim
-- keeps this testable; production passes 'fdWriteBuf'.
writeFully :: (Ptr Word8 -> Int -> IO Int) -> Ptr Word8 -> Int -> IO Bool
writeFully writeOne = go
  where
    go _ n | n <= 0 = pure True
    go p n = do
      e <- trySync (writeOne p n)
      case e of
        Left _ -> pure False
        Right k
          | k <= 0 -> pure False
          | k >= n -> pure True
          | otherwise -> go (p `plusPtr` k) (n - k)

-- | Expand @{pid}@ in a trace path, exactly as the sink does.
expandPid :: FilePath -> Int -> FilePath
expandPid [] _ = []
expandPid ('{' : 'p' : 'i' : 'd' : '}' : rest) pid =
  show (pid :: Int) ++ expandPid rest pid
expandPid (c : rest) pid = c : expandPid rest pid

-- | A file-backed tracer from the trace config (queue bound from
-- the config floor, non-strict). Records the destination for the
-- store-alias guard ('tracerAliasesStore'); nothing when disabled,
-- so disabled tracers skip the alias lookups for rows that can
-- never be written.
newFileTracer :: TraceCfg -> IO Tracer
newFileTracer tc = do
  tr <- newTracer (max 8 (tcQueueLimit tc)) (fileSink tc) False
  pure (tr { trPath = if tcEnabled tc then Just (tcPath tc) else Nothing })

-- | Whether a file tracer's destination aliases the store: the
-- caller passes the database path resolved the way the opener
-- resolves it ('resolveStorePath': symlinks followed, missing
-- components kept lexically). The trace destination is resolved
-- through final-component links the same way. Shadows (journal,
-- WAL sidecars, lock) derive from the given spelling, each plus
-- what its own final-component links resolve to (a linked
-- sidecar aliases by its target); @file:@
-- URI stores are checked once per spelling by the caller (this
-- build enables URI filenames). Spellings with surrogate
-- escapes drop unconditionally, as do non-ASCII spellings under
-- a non-UTF-8 filesystem encoding (POSIX lookups and the SQLite
-- opener resolve them differently). Four legs
-- per shadow: canonical directory + file name, full resolved
-- paths, file identities (of the ORIGINAL trace path: link
-- resolution can map a procfs magic link to a deleted name
-- while the sink opens the live inode), and parent directory
-- identity + casefolded leaf (bind mounts; the
-- case-insensitive match over-blocks differing-case spellings
-- on sensitive filesystems by design, and NFC-vs-NFD twins and
-- Default_Ignorable twins (e.g. U+200D, which casefold
-- filesystems remove before comparing) on folding filesystems
-- are out of scope). The caller checks
-- every spelling URI stores need; the row is preserved when
-- the evidence establishes a distinct destination, dropped on
-- any match or any unproven leg (anything missing on one or
-- both sides counts as evidence, since a path that cannot
-- exist cannot alias). An unresolvable trace destination
-- always drops (its drain fails anyway). Non-file tracers
-- never alias. Compares configuration at call time; a trace
-- file replaced by a store alias afterwards still aliases
-- (TOCTOU, out of scope).
tracerAliasesStore :: Tracer -> FilePath -> IO Bool
tracerAliasesStore = tracerAliasesStoreWith isFsEncodingUtf8

-- | 'tracerAliasesStore' with the UTF-8-filesystem probe injected
-- (the probe reads process-global state, so tests pass it
-- explicitly instead of flipping the global under parallel
-- suites).
tracerAliasesStoreWith :: IO Bool -> Tracer -> FilePath -> IO Bool
tracerAliasesStoreWith isUtf8 tr db0 = case trPath tr of
  Nothing -> pure False
  Just raw
    -- Surrogate escapes (undecodable filename bytes, as argv and
    -- readdir produce) fail the row closed: the POSIX lookups
    -- below round-trip them to the true bytes while the SQLite
    -- opener passes its path through Text, which replaces them —
    -- the two sides would compare different files.
    | hasSurrogates raw || hasSurrogates db0 -> pure True
    | otherwise -> do
        pid <- getProcessID
        let trace0 = expandPid raw (fromIntegral pid)
        -- A non-UTF-8 filesystem encoding with non-ASCII spellings
        -- drops like an unresolvable destination: POSIX lookups
        -- use locale bytes while SQLite always opens UTF-8, so the
        -- two sides would compare different files.
        utf8 <- isUtf8
        mTrace <- if shouldDropForEncoding utf8 raw db0
          then pure Nothing
          else resolveFinalLink trace0
        case mTrace of
          Nothing -> pure True
          Just trace -> do
            lexT <- resolveSide (lexical trace)
            case lexT of
              Known lt -> do
                fullT <- resolveSide (canonicalizePath trace)
                -- Identity of the ORIGINAL path: final-link resolution
                -- can map a procfs magic link to a deleted name that
                -- stats missing, while the sink opens the live inode.
                idT <- resolveSide (identity trace0)
                dirT <- resolveSide (dirLeaf trace)
                shadows <- resolveShadows db0
                or <$> mapM (shadowAliases lt fullT idT dirT) shadows
              _ -> pure True
  where
    shadowsOf r = [r, r ++ "-journal", r ++ "-wal", r ++ "-shm", r ++ ".lock"]
    -- Each shadow spelling plus what its final-component links
    -- resolve to: a sidecar spelled through a link (a dangling
    -- -wal naming its missing target through another mount)
    -- aliases by its target, which the spelling's leaf hides
    -- from the parent-identity leg. An unresolvable spelling
    -- stays spelling-only (a link loop fails closed anyway:
    -- its legs read unproven and the row drops).
    resolveShadows r = concat <$> mapM resolveOne (shadowsOf r)
    resolveOne s = do
      mTgt <- resolveFinalLink s
      pure (case mTgt of
        Just t | t /= s -> [s, t]
        _ -> [s])
    lexical p = do
      d <- canonicalizePath (takeDirectory p)
      pure (d </> takeFileName p)
    identity p = do
      st <- getFileStatus p
      pure (deviceID st, fileID st)
    dirLeaf p = do
      st <- getFileStatus (takeDirectory p)
      pure ((deviceID st, fileID st), T.unpack (T.toCaseFold (T.pack (takeFileName p))))
    shadowAliases lt fullT idT dirT s = do
      lexS <- resolveSide (lexical s)
      fullS <- resolveSide (canonicalizePath s)
      idS <- resolveSide (identity s)
      dirS <- resolveSide (dirLeaf s)
      pure (any (/= LegClear) [compareLeg (Known lt) lexS, compareLeg fullT fullS, compareLeg idT idS, compareLeg dirT dirS])

-- | Follow a final-component symlink chain (bound 41: 40 links
-- resolve, matching the most permissive kernels — Linux allows
-- 40 traversals; longer chains and loops fail closed, and the
-- drain could not open them on any supported kernel): the sink
-- follows the same links, so the guard must compare the
-- effective destination. Missing links stay as-is for the legs
-- to classify.
resolveFinalLink :: FilePath -> IO (Maybe FilePath)
resolveFinalLink p = go p (41 :: Int) []
  where
    go _ 0 _ = pure Nothing
    go cur n seen
      | cur `elem` seen = pure Nothing
      | otherwise = do
          eLink <- trySync (readSymbolicLink cur)
          case eLink of
            Right link -> go (if isAbsolute link then link else takeDirectory cur </> link) (n - 1) (cur : seen)
            Left _ -> pure (Just cur)

-- | The pathname SQLite effectively opens for a @file:@ URI
-- storage path (this build enables URI filenames): strip the
-- scheme, query, and fragment, and percent-decode into bytes.
-- The caller guards both the literal and the effective
-- spelling (resolving each the opener's way), since sidecars
-- may be derived from either. Undecodable sequences fail
-- closed (the literal spelling stays guarded).
uriEffective :: FilePath -> Maybe FilePath
uriEffective p
  | "file:" `isPrefixOf` p = decodeUriPath (takeWhile (\c -> c /= '?' && c /= '#') (drop 5 p))
  | otherwise = Nothing

-- | Why a store spelling cannot become an effective path.
data SpellingRefusal
  = SpellingEmpty
    -- ^ Nothing to open (an empty path would make SQLite open a
    -- throwaway temporary database while the guards stat garbage).
  | UriQueryOrFragment
    -- ^ @file:@ URIs must be bare paths: query parameters change
    -- open semantics (mode=memory, shared cache) that the guards
    -- cannot see, so stripping them silently would lie.
  | UriUndecodable
    -- ^ Percent-decoding failed (truncated escape, NUL byte, or
    -- non-UTF-8): the opener cannot place the file.
  | UriNested
    -- ^ The decoded path is itself a @file:@ URI: passing it on
    -- would re-enter URI interpretation.
  deriving (Eq, Show)

-- | Normalize a store spelling to the single POSIX path every
-- guard and SQLite itself must use: POSIX spellings pass
-- through, bare @file:@ URIs decode exactly once, and anything
-- that would let the guards and the opener diverge refuses.
effectiveStorePath :: FilePath -> Either SpellingRefusal FilePath
effectiveStorePath p
  | null p = Left SpellingEmpty
  | not ("file:" `isPrefixOf` p) = Right p
  | any (`elem` rest) "?#" = Left UriQueryOrFragment
  | otherwise = case decodeUriPath rest of
      Nothing -> Left UriUndecodable
      Just "" -> Left SpellingEmpty
      Just eff
        | "file:" `isPrefixOf` eff -> Left UriNested
        | otherwise -> Right eff
  where
    rest = drop 5 p

-- | Render a spelling refusal against the offending input. Single
-- source: every layer wraps it in its own taxonomy.
renderSpellingRefusal :: SpellingRefusal -> FilePath -> String
renderSpellingRefusal r p = case r of
  SpellingEmpty -> "store path is empty, refusing"
  UriQueryOrFragment ->
    "file: URI with query/fragment refused (bare paths only): " ++ p
  UriUndecodable -> "file: URI does not decode: " ++ p
  UriNested -> "nested file: URI refused: " ++ p

-- | Whether a path carries surrogate escapes (undecodable
-- filename bytes): the guard drops such rows, since POSIX
-- lookups and the SQLite opener resolve them differently.
hasSurrogates :: FilePath -> Bool
hasSurrogates = any (\c -> c >= '\xD800' && c <= '\xDFFF')

-- | Whether a filesystem-encoding name is UTF-8 (compared
-- case-insensitively over alphanumerics, so "UTF-8" and "utf8"
-- both count).
isUtf8EncodingName :: String -> Bool
isUtf8EncodingName name = map toUpper (filter isAlphaNum name) == "UTF8"

-- | Whether the process filesystem encoding is UTF-8, read fresh
-- (it can change at runtime).
isFsEncodingUtf8 :: IO Bool
isFsEncodingUtf8 = isUtf8EncodingName . textEncodingName <$> getFileSystemEncoding

-- | Whether non-ASCII spellings drop under a filesystem encoding:
-- ASCII-only spellings encode identically on ASCII-compatible
-- filesystem encodings (other encodings, e.g. EBCDIC or UTF-16,
-- are out of scope), but non-ASCII spellings under a non-UTF-8
-- encoding name locale bytes to POSIX while SQLite opens UTF-8.
shouldDropForEncoding :: Bool -> FilePath -> FilePath -> Bool
shouldDropForEncoding isUtf8 a b =
  not isUtf8 && (any (not . isAscii) a || any (not . isAscii) b)

-- | Whether one spelling drops before it is resolved: surrogates
-- or a non-UTF-8 filesystem with non-ASCII bytes. Callers check
-- spellings the guard never sees unresolved (the raw store path
-- and the decoded URI), since resolution can consume the very
-- characters the check looks for.
spellingDrops :: FilePath -> IO Bool
spellingDrops = spellingDropsWith isFsEncodingUtf8

-- | 'spellingDrops' with the UTF-8 probe injected (see
-- 'tracerAliasesStoreWith' for why tests pass it explicitly).
spellingDropsWith :: IO Bool -> FilePath -> IO Bool
spellingDropsWith isUtf8 s
  | hasSurrogates s = pure True
  | otherwise = do
      utf8 <- isUtf8
      pure (shouldDropForEncoding utf8 s s)

-- | Decode a URI path to the filesystem spelling: literal
-- characters pass through; consecutive escapes decode as UTF-8
-- (what SQLite opens — decoding per byte would double-encode
-- multibyte characters). Anything else fails closed — including
-- any NUL byte, which SQLite truncates at while pure string
-- processing would keep (a later dot-dot could then point the
-- guard away from the opened file).
decodeUriPath :: String -> Maybe FilePath
decodeUriPath s = case toBytes s of
  Nothing -> Nothing
  Just bs
    | 0 `elem` bs -> Nothing
    | otherwise -> case TE.decodeUtf8' (BS.pack bs) of
        Left _ -> Nothing
        Right t -> Just (T.unpack t)
  where
    toBytes :: String -> Maybe [Word8]
    toBytes [] = Just []
    toBytes ('%' : a : b : rest)
      | isHexDigit a && isHexDigit b =
          (fromIntegral (digitToInt a * 16 + digitToInt b) :) <$> toBytes rest
    toBytes ('%' : _) = Nothing
    toBytes (c : rest) = (BS.unpack (TE.encodeUtf8 (T.singleton c)) ++) <$> toBytes rest

-- | One lookup outcome: known, missing (proves absence), or
-- unproven (any other failure).
data Side a = Known !a | Missing | Unproven

-- | One comparison leg: match (alias), unproven (fail closed),
-- or clear.
data AliasLeg = LegMatch | LegUnproven | LegClear deriving Eq

-- | Classify a filesystem lookup: exactly-ENOENT failures are
-- evidence of absence; anything else that fails is unproven.
resolveSide :: IO a -> IO (Side a)
resolveSide act = do
  r <- trySync act
  pure $ case r of
    Right a -> Known a
    Left ex -> case fromException ex :: Maybe IOException of
      Just io | isEnoent io -> Missing
      _ -> Unproven

-- | Exactly ENOENT (unlike 'isDoesNotExistError', which also
-- accepts ENXIO in this toolchain): only a missing file proves
-- absence.
isEnoent :: IOException -> Bool
isEnoent io = case ioe_errno io of
  Just n -> Errno n == eNOENT
  Nothing -> False

-- | Compare one leg: equal knowns match; anything missing on
-- exactly one side, or on both, is clear; anything unproven
-- fails closed.
compareLeg :: Eq a => Side a -> Side a -> AliasLeg
compareLeg (Known a) (Known b) = if a == b then LegMatch else LegClear
compareLeg Missing Missing = LegClear
compareLeg (Known _) Missing = LegClear
compareLeg Missing (Known _) = LegClear
compareLeg _ _ = LegUnproven

-- | A file tracer's configured destination, if any: lets callers
-- skip lookups (and store resolution) for tracers that cannot
-- write a file.
tracerFilePath :: Tracer -> Maybe FilePath
tracerFilePath = trPath

-- | Count a row the caller discarded before emitting (a trace
-- destination that aliases the store): drops-as-failure harnesses
-- treat it like an overflow drop; non-strict tracers only count it.
noteTraceDropped :: Tracer -> IO ()
noteTraceDropped tr = atomically $ do
  d <- readTVar (trDropped tr)
  writeTVar (trDropped tr) (d + 1)

-- | 'try' that rethrows asynchronous exceptions immediately
-- (close paths must unwind); only the concrete 'AsyncException'
-- type is rethrown. 'Timeout' is a 'SomeAsyncException' child but
-- not an 'AsyncException' ('System.Timeout'), so it returns
-- 'Left' like a sync failure — a deadline around the tried
-- action still converts to a sink failure instead of unwinding;
-- enforce it outside the handler.
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

-- | Total drops (queue overflow and pre-emit discards; sink failures
-- live in the drain report and 'runHarnessChecked').
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
