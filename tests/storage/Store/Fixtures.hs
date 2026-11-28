{- | Store shared fixtures.
-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Store.Fixtures
  ( awaitDone
  , awaitLockOwner
  , catalogDoc
  , cleanBytes
  , commitFile
  , demoJobPending
  , demoJobResult
  , expectCreated
  , expectJust
  , expectRight
  , holderMain
  , mNextObject'
  , numbersClean
  , parseCatalog
  , positionalDoc
  , reapThenRestore
  , resolves
  , restoreEnv
  , seedSchema1
  , seedStore
  , spawnHolder
  , swappedDoc
  , testTryFlock
  , threeLabels
  , threeSo
  , threeUser
  , withEnvGate
  , withProcRoot
  , v1SchemaDdl
  , rawSchemaState
  , WorkerReg
  , reapSelected
  ) where

import Control.Concurrent (ThreadId, forkIO, killThread, myThreadId, threadDelay, withMVar)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, readMVar, takeMVar)
import Control.Exception (AsyncException (ThreadKilled, UserInterrupt), SomeException, bracket, fromException, mask_, onException, throwIO, try)
import Control.Monad (forM, forM_, unless, when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef, writeIORef)
import Data.List (isInfixOf, isPrefixOf, partition)
import Data.Maybe (mapMaybe)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import Data.Word (Word64)
import Foreign.C.Types (CInt (..), CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr)
import Foreign.Storable (peek, poke)
import System.Directory (removeFile)
import System.Environment (getExecutablePath, lookupEnv, setEnv, unsetEnv)
import System.Exit (ExitCode (..))
import System.IO.Error (catchIOError)
import System.Posix.Files (fileExist)
import System.Posix.Process (exitImmediately)
import System.Posix.Types (Fd, ProcessID)
import System.Process (CreateProcess (..), ProcessHandle, createProcess, proc)
import System.Timeout (timeout)
import qualified System.Posix.Env as PosixEnv
import Test.Tasty.HUnit (assertEqual, assertFailure)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState
  , addToken
  , emptyModel
  , lookupObject
  , lookupSession
  )
import Haskoki.Object (decodeHandle, planCreateObject)
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , StateDelta (..)
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , JobBody (..)
  , JobExecState (..)
  , JobRecord (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , Store (..)
  , StoreDelta (..)
  , TokenRecord (..)
  , emptyDelta
  , objectToRecord
  )
import StoreFixtures
  ( EnvScope
  , rawExec, rawTexts
  
   )
import Haskoki.FFI.Standard
  ( StdInstance
  , haskokiStdClose
  , haskokiStdCloseSession
  , haskokiStdGetSessionInfo
  , haskokiStdInitPin
  , haskokiStdInitToken
  , haskokiStdLogin
  , haskokiStdLogout
  , haskokiStdOpenSession
  , haskokiStdSetPin
  , openStdInstance
  )
import Haskoki.Runtime.Config
  ( Config (..)
  , StorageCfg (..)
  , StorageKind (..)
  , TokensCfg (..)
  , defaultConfig
  , parseConfig
  )
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

-- | Unwrap an 'Either' or fail the test with context.
expectRight :: Show e => String -> Either e a -> IO a
expectRight ctx = either (\e -> assertFailure (ctx ++ ": " ++ show e)) pure

-- | Unwrap a 'Maybe' or fail the test with context.
expectJust :: String -> Maybe a -> IO a
expectJust ctx = maybe (assertFailure ("missing: " ++ ctx)) pure

-- | A version-1 store at the path holding the given token rows:
-- the frozen version-1 DDL, then the rows exactly as the backend
-- writes them (committed to a scratch version-2 store beside it
-- and copied across with ATTACH). Version 1 has no @credentials@
-- table, so every token in it is without a credential row.
seedSchema1 :: FilePath -> [TokenRecord] -> IO ()
seedSchema1 path toks = do
  mapM_ (rawExec path . T.pack) v1SchemaDdl
  when (not (null toks)) $ do
    let src = path ++ ".v2-source"
    r <- commitFile src emptyDelta { sdPutTokens = toks }
    assertEqual "source token rows commit" Committed r
    rawExec path (T.pack (concat
      [ "ATTACH DATABASE '", src, "' AS src; "
      , "INSERT INTO main.tokens SELECT * FROM src.tokens; "
      , "DETACH DATABASE src" ]))
    removeFile src
  state <- rawSchemaState path
  assertEqual "fixture is schema 1 without a credentials table" ("1", False) state

-- | The lock holder: runs in a spawned child process (see
-- 'spawnHolder'), opens the store (becoming its live owner),
-- signals readiness only once the open has fully completed (the
-- pid names the lock before schema init finishes, so the lock
-- alone cannot gate a racing second open), waits for the parent's
-- done file, then closes and exits. Never returns to test code;
-- uses 'exitImmediately' to avoid flushing the parent's stdio
-- buffers.
--
-- Reserve mode (@HASKOKI_HOLDER_MODE=reserve@, passed only via
-- the child's spawn environment): after opening, the child
-- reserves one job id, records it at @HASKOKI_HOLDER_PIDFILE@,
-- signals ready, then parks in the reserve/insert window
-- without inserting, closing, or exiting — the parent kills it
-- there to observe true process death between the two commits.
--
-- Auth-probe mode (@HASKOKI_HOLDER_MODE=auth-probe@, likewise
-- environment-only): the child opens a full serving instance
-- over the path instead of the raw store and runs the
-- @HASKOKI_AUTH_SCRIPT@ login ops (see 'authProbeMain').
--
-- Provision mode (@HASKOKI_HOLDER_MODE=provision@, likewise
-- environment-only): the child opens a full serving instance
-- with the two-token catalog and runs the
-- @HASKOKI_PROVISION_SCRIPT@ verbs (see 'provisionMain').
holderMain :: FilePath -> FilePath -> FilePath -> IO ()
holderMain path doneFile readyFile = do
  mode <- lookupEnv "HASKOKI_HOLDER_MODE"
  case mode of
    -- Serving modes open a full serving instance, never the
    -- raw store: they must not become a bare store owner first
    -- (the instance open would then refuse as a second writer).
    Just "auth-probe" -> authProbeMain path
    Just "provision" -> provisionMain path
    _ -> holderStoreMain path doneFile readyFile mode

-- | The store-owner holder: open the raw store, optionally run
-- the reserve window, handshake on the ready/done files, then
-- close and exit.
holderStoreMain :: FilePath -> FilePath -> FilePath -> Maybe String -> IO ()
holderStoreMain path doneFile readyFile mode = do
  -- Inert opener: the holder is infrastructure, never the seam under
  -- test, and it inherits the test process's environment — an armed
  -- fake root or pause handshake for another test's path must not be
  -- able to refuse or stall the holder open.
  e <- openSQLiteStore path
  case e of
    Left _ -> exitImmediately (ExitFailure 1)
    Right s -> case mode of
      Just "reserve" -> do
        ePid <- storeReserveJobId s
        case ePid of
          Left _ -> exitImmediately (ExitFailure 2)
          Right pid -> do
            mPidFile <- lookupEnv "HASKOKI_HOLDER_PIDFILE"
            case mPidFile of
              Just pidFile -> writeFile pidFile (show pid ++ "\n")
              Nothing -> pure ()
            writeFile readyFile "ready\n"
            awaitDone doneFile (6000 :: Int)
            -- Crash simulation: never close, never insert.
            exitImmediately ExitSuccess
      _ -> do
        writeFile readyFile "ready\n"
        awaitDone doneFile (6000 :: Int)
        storeClose s
        exitImmediately ExitSuccess

-- | Auth-probe holder (@HASKOKI_HOLDER_MODE=auth-probe@): the
-- second-process leg of the durable-login suite. Opens a full
-- serving instance over the database path (home catalog, SQLite
-- store), opens one read/write session on slot 0, runs the
-- comma-separated @HASKOKI_AUTH_SCRIPT@ login ops, writes one
-- @op=decimal@ line per op to @HASKOKI_AUTH_RESULT@, closes, and
-- exits. Ops: @u-bad@\/@u-good@ (user login with a wrong\/home
-- PIN), @s-bad@\/@s-good@ (SO login likewise), @logout@, and
-- @info@ (the session login code). Any failure exits nonzero
-- without writing further lines; the parent joins with
-- @awaitHolderExit@ and asserts the exact lines.
authProbeMain :: FilePath -> IO ()
authProbeMain path = do
  mScript <- lookupEnv "HASKOKI_AUTH_SCRIPT"
  mResult <- lookupEnv "HASKOKI_AUTH_RESULT"
  case (mScript, mResult) of
    (Just script, Just result) -> do
      ctx <- openStdInstance sqliteCfg
      if castStablePtrToPtr ctx == nullPtr
        then exitImmediately (ExitFailure 2)
        else do
          h <- openProbeSession ctx
          case h of
            Nothing -> exitImmediately (ExitFailure 3)
            Just session -> do
              outs <- mapM (runProbeOp ctx session) (splitScript script)
              case sequence outs of
                Nothing -> exitImmediately (ExitFailure 4)
                Just rendered -> do
                  writeFile result (unlines rendered)
                  haskokiStdClose ctx
                  exitImmediately ExitSuccess
    _ -> exitImmediately (ExitFailure 5)
  where
    sqliteCfg = defaultConfig
      { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True False }

-- | Open one read/write session on slot 0 for the probe.
openProbeSession :: StablePtr StdInstance -> IO (Maybe CULong)
openProbeSession ctx =
  alloca $ \(phSession :: Ptr CULong) -> do
    poke phSession (CULong 0)
    rv <- haskokiStdOpenSession ctx (CULong 0) (CULong 0) phSession
    if rv /= CULong 0
      then pure Nothing
      else Just <$> peek phSession

-- | Run one probe op, rendering its @op=decimal@ line ('Nothing'
-- on an unknown op).
runProbeOp :: StablePtr StdInstance -> CULong -> String -> IO (Maybe String)
runProbeOp ctx h op = case op of
  "u-bad" -> Just . render <$> probeLogin ctx h 1 "0000"
  "u-good" -> Just . render <$> probeLogin ctx h 1 "1234"
  "s-bad" -> Just . render <$> probeLogin ctx h 0 "0000"
  "s-good" -> Just . render <$> probeLogin ctx h 0 "5678"
  "logout" -> Just . render <$> haskokiStdLogout ctx h
  "info" -> fmap (fmap render) (probeLoginCode ctx h)
  _ -> pure Nothing
  where
    render (CULong n) = op ++ "=" ++ show n

-- | Log in with literal PIN bytes.
probeLogin :: StablePtr StdInstance -> CULong -> CULong -> String -> IO CULong
probeLogin ctx h userType pinStr =
  BS.useAsCStringLen (BC8.pack pinStr) $ \(cstr, len) ->
    haskokiStdLogin ctx h userType (castPtr cstr) (fromIntegral len)

-- | Read the session login code ('Nothing' unless the info call is OK).
probeLoginCode :: StablePtr StdInstance -> CULong -> IO (Maybe CULong)
probeLoginCode ctx h =
  alloca $ \(pSlot :: Ptr CULong) ->
  alloca $ \(pRO :: Ptr CULong) ->
  alloca $ \(pLogin :: Ptr CULong) ->
  alloca $ \(pDevErr :: Ptr CULong) -> do
    rv <- haskokiStdGetSessionInfo ctx h pSlot pRO pLogin pDevErr
    if rv /= CULong 0
      then pure Nothing
      else Just <$> peek pLogin

-- | Split a comma-separated probe script.
splitScript :: String -> [String]
splitScript = go
  where
    go [] = []
    go s = case break (== ',') s of
      (op, []) -> [op]
      (op, _ : rest) -> op : go rest

-- | The two-token config the provision child opens with (exact
-- entries duplicated here: the holder cannot import backwards
-- from the journey suite).
provisionCfg :: FilePath -> Config
provisionCfg path = defaultConfig
  { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True False
  , cfgTokens = TokensCfg [("haskoki-demo", "5678", "1234"), ("haskoki-ops", "6789", "2345")]
  }

-- | Provision holder (@HASKOKI_HOLDER_MODE=provision@): the
-- fresh-process leg of the provision/change/lock/recover/reset
-- journey. Opens a full serving instance over the database path
-- with 'provisionCfg', runs the comma-separated
-- @HASKOKI_PROVISION_SCRIPT@ verbs against one read/write session
-- on slot 0 held in an 'IORef' (created by @open@, dropped by
-- @close@), writes one @verb=decimal@ line per verb to
-- @HASKOKI_PROVISION_RESULT@, closes, and exits. Refused ops are
-- data (their return code is recorded); only broken plumbing
-- exits nonzero: 2 null instance, 3 @open@ failure, 4 unknown
-- verb, op without a live handle, double @open@, or a failed
-- @login-state@ query, 5 missing environment. @init-token@ is
-- slot-scoped and needs no live handle; it is the only such
-- verb. Result lines carry codes only; nothing is printed.
provisionMain :: FilePath -> IO ()
provisionMain path = do
  mScript <- lookupEnv "HASKOKI_PROVISION_SCRIPT"
  mResult <- lookupEnv "HASKOKI_PROVISION_RESULT"
  case (mScript, mResult) of
    (Just script, Just result) -> do
      ctx <- openStdInstance (provisionCfg path)
      if castStablePtrToPtr ctx == nullPtr
        then exitImmediately (ExitFailure 2)
        else do
          sessionRef <- newIORef Nothing
          mRendered <- runProvisionScript ctx sessionRef (splitScript script)
          case mRendered of
            Left code -> exitImmediately (ExitFailure code)
            Right rendered -> do
              writeFile result (unlines rendered)
              haskokiStdClose ctx
              exitImmediately ExitSuccess
    _ -> exitImmediately (ExitFailure 5)

-- | Run the verbs in order, short-circuiting on the first
-- plumbing failure (a refused op is data and continues; a
-- 'Left' code stops the script with no further lines).
runProvisionScript :: StablePtr StdInstance -> IORef (Maybe CULong) -> [String] -> IO (Either Int [String])
runProvisionScript _ _ [] = pure (Right [])
runProvisionScript ctx ref (op : ops) = do
  mLine <- runProvisionOp ctx ref op
  case mLine of
    Left code -> pure (Left code)
    Right line -> fmap (fmap (line :)) (runProvisionScript ctx ref ops)

-- | Run one provision verb ('Left' exit code on a plumbing
-- failure, 'Right' @verb=decimal@ line otherwise).
runProvisionOp :: StablePtr StdInstance -> IORef (Maybe CULong) -> String -> IO (Either Int String)
runProvisionOp ctx ref token = case splitVerb token of
  ["open"] -> do
    mLive <- readIORef ref
    case mLive of
      Just _ -> pure (Left 4)
      Nothing ->
        alloca $ \(phSession :: Ptr CULong) -> do
          poke phSession (CULong 0)
          rv <- haskokiStdOpenSession ctx (CULong 0) (CULong 0) phSession
          if rv /= CULong 0
            then pure (Left 3)
            else do
              h <- peek phSession
              writeIORef ref (Just h)
              pure (Right (render rv))
  ["close"] -> withLive $ \h -> do
    rv <- haskokiStdCloseSession ctx h
    writeIORef ref Nothing
    pure (Right (render rv))
  ["login", "user", pin] -> withLive $ \h -> Right . render <$> probeLogin ctx h 1 pin
  ["login", "so", pin] -> withLive $ \h -> Right . render <$> probeLogin ctx h 0 pin
  ["logout"] -> withLive $ \h -> Right . render <$> haskokiStdLogout ctx h
  ["init-token", label, soPin] -> Right . render <$> provisionInitToken ctx (CULong 0) soPin label
  ["init-pin", newPin] -> withLive $ \h -> Right . render <$> provisionInitPin ctx h newPin
  ["set-pin", oldPin, newPin] -> withLive $ \h -> Right . render <$> provisionSetPin ctx h oldPin newPin
  ["lock-check", pin] -> withLive $ \h -> Right . render <$> probeLogin ctx h 1 pin
  ["login-state"] -> withLive $ \h -> do
    mCode <- probeLoginCode ctx h
    case mCode of
      Nothing -> pure (Left 4)
      Just code -> pure (Right (render code))
  _ -> pure (Left 4)
  where
    -- Result lines carry the verb only: the arguments hold PIN
    -- bytes, and a failing assertEqual would print them.
    render (CULong n) = verb ++ "=" ++ show n
      where
        verb = case splitVerb token of
          v : _ -> v
          [] -> token
    withLive f = readIORef ref >>= maybe (pure (Left 4)) f

-- | Split a provision verb on its @/@ argument separators.
splitVerb :: String -> [String]
splitVerb = go
  where
    go [] = []
    go s = case break (== '/') s of
      (part, []) -> [part]
      (part, _ : rest) -> part : go rest

-- | Call InitPIN on a session with a plain-string PIN.
provisionInitPin :: StablePtr StdInstance -> CULong -> String -> IO CULong
provisionInitPin ctx h pinStr =
  BS.useAsCStringLen (BC8.pack pinStr) $ \(cstr, len) ->
    haskokiStdInitPin ctx h (castPtr cstr) (fromIntegral len)

-- | Call SetPIN on a session with plain-string old/new PINs.
provisionSetPin :: StablePtr StdInstance -> CULong -> String -> String -> IO CULong
provisionSetPin ctx h oldStr newStr =
  BS.useAsCStringLen (BC8.pack oldStr) $ \(cOld, lenOld) ->
    BS.useAsCStringLen (BC8.pack newStr) $ \(cNew, lenNew) ->
      haskokiStdSetPin ctx h (castPtr cOld) (fromIntegral lenOld)
        (castPtr cNew) (fromIntegral lenNew)

-- | Call InitToken on a slot with a plain-string SO PIN and label
-- (the label pads to the fixed 32 C bytes here, as the C caller
-- would).
provisionInitToken :: StablePtr StdInstance -> CULong -> String -> String -> IO CULong
provisionInitToken ctx slot pinStr labelStr =
  BS.useAsCStringLen (BC8.pack pinStr) $ \(cPin, lenPin) ->
    BS.useAsCStringLen (BC8.pack (take 32 (labelStr ++ repeat ' '))) $ \(cLabel, _) ->
      haskokiStdInitToken ctx slot (castPtr cPin) (fromIntegral lenPin) (castPtr cLabel)

-- | Poll for the done file (10ms steps, bounded so a stuck parent
-- cannot wedge the suite past the tasty timeout).
awaitDone :: FilePath -> Int -> IO ()
awaitDone _ 0 = pure ()
awaitDone doneFile n = do
  done <- fileExist doneFile
  if done then pure () else threadDelay 10000 >> awaitDone doneFile (n - 1)

-- | Poll until the lock names the holder child (10s cap); the
-- holder is live from then on.
awaitLockOwner :: FilePath -> ProcessID -> IO ()
awaitLockOwner path holderPid = do
  let want = BC8.pack (show holderPid ++ "\n")
      go = do
        content <- catchIOError (BS.readFile (path ++ ".lock")) (\_ -> pure BS.empty)
        if content == want then pure () else threadDelay 10000 >> go
  mOk <- timeout 10000000 go
  case mOk of
    Just () -> pure ()
    Nothing -> assertFailure "masked: holder child did not take the lock"

-- | Spawn a holder child as a FRESH OS process (the test binary
-- re-invoked with @--holder@), never 'forkProcess': a forked child
-- would inherit the parent's open guard fds (the same open file
-- description — the parent's close then cannot release the kernel
-- locks while the child lives, poisoning concurrent tests with
-- spurious refusals) and forking a multithreaded RTS while another
-- thread is inside SQLite can wedge the child forever. The spawned
-- child starts with only stdio fds (@close_fds@) and a clean
-- address space.
spawnHolder :: IO EnvScope -> FilePath -> FilePath -> FilePath -> IO ProcessHandle
spawnHolder mkScope path doneFile readyFile = do
  (_, _, frozenEnv) <- mkScope
  exe <- getExecutablePath
  (_, _, _, ph) <- createProcess ((proc exe ["--holder", path, doneFile, readyFile]) { close_fds = True, env = Just frozenEnv })
  pure ph

-- | Serialize one process-wide env mutation through the scope's
-- atomic gate (held through arming, the body, worker cleanup, and
-- restoration, so a concurrent mutator can neither arm over us nor
-- restore our values away). Every mutator test registers through
-- this: a future mutator that forgets the gate is a review-time
-- defect, caught by inspection (every helper user must register
-- gated).
withEnvGate :: IO EnvScope -> IO a -> IO a
withEnvGate mkScope action = do
  (gate, _, _) <- mkScope
  withMVar gate (\_ -> action)

-- | Restore a saved process-env value exactly: 'setEnv' removes
-- empty-valued variables, so restoration goes through the POSIX
-- binding, which sets them byte-for-byte.
restoreEnv :: String -> Maybe String -> IO ()
restoreEnv var Nothing = unsetEnv var
restoreEnv var (Just val) = PosixEnv.setEnv var val True

-- | Reap the calling test's workers, then run a restore action —
-- kill-safe: a kill landing in the reap's interruptible join must
-- not skip the restore and leave armed state behind for the next
-- test. The reap outcome (including async death) is captured, the
-- restore runs shielded, then the kill is rethrown or the problems
-- reported unshielded — the invariant is "restore ran", not
-- "report delivered".
reapThenRestore :: IO EnvScope -> IO () -> IO ()
reapThenRestore mkScope restore = do
  (_, reg, _) <- mkScope
  me <- myThreadId
  eProblems <- try (reapSelected (Just me) reg)
  mask_ restore
  case eProblems of
    Left (e :: SomeException) -> throwIO e
    Right problems ->
      unless (null problems) (assertFailure (unlines problems))

-- | Run with @HASKOKI_PROC_ROOT@ overridden, restoring it afterwards.
-- Any inherited value is saved and restored, so a developer-exported
-- variable never breaks the suite. Mutual exclusion between mutators
-- comes from 'withEnvGate' at registration; tracked workers are
-- reaped before the restore, so none outlives the armed region.
withProcRoot :: IO EnvScope -> FilePath -> IO a -> IO a
withProcRoot mkScope root action = do
  bracket (lookupEnv "HASKOKI_PROC_ROOT")
          (\prev -> reapThenRestore mkScope (restoreEnv "HASKOKI_PROC_ROOT" prev))
          (\_ -> setEnv "HASKOKI_PROC_ROOT" root >> action)

-- | The test's own kernel-lock hold: an independent @flock@ import
-- (not the library's), so the held-lock phase proves the guard
-- interacts at the kernel level. @6 = LOCK_EX|LOCK_NB@ (Linux ABI).
testTryFlock :: Fd -> IO Bool
testTryFlock fd = (== 0) <$> test_c_flock (fromIntegral fd) 6

-- | Reject any bytes mentioning pointers, handles, callbacks, or
-- native crypto contexts.
cleanBytes :: String -> Bool
cleanBytes s = not (any (`isInfixOf` s) banned)
  where
    banned =
      [ "Ptr"
      , "callback"
      , "Callback"
      , "CALLBACK"
      , "EVP_"
      , "evp_"
      , "FunPtr"
      , "nullFunPtr"
      , "handle"
      , "Handle"
      , "HANDLE"
      , "struct"
      , "0x7f"
      , "0x55"
      , "0X"
      ]

-- | The only bare JSON number permitted is @\"format_version\":1@;
-- every other digit must sit inside a string.
numbersClean :: String -> Bool
numbersClean s = go False False (stripFmt s)
  where
    stripFmt [] = []
    stripFmt t@(c : cs)
      | "\"format_version\":1" `isPrefixOf` t = stripFmt (drop 18 t)
      | otherwise = c : stripFmt cs
    go _ _ [] = True
    go inStr esc (c : cs)
      | inStr && esc = go True False cs
      | inStr && c == '\\' = go True True cs
      | inStr && c == '"' = go False False cs
      | inStr = go True False cs
      | c == '"' = go True False cs
      | c >= '0' && c <= '9' = False
      | otherwise = go False False cs

-- | A pending-recipe job fixture: deterministic recipe plus owned
-- parameter bytes (replayable after restart, no live context).
demoJobPending :: Word64 -> TokenId -> Generation -> JobRecord
demoJobPending pid tok gen = JobRecord
  { jrPersistentId = pid
  , jrToken = tok
  , jrTokenGeneration = gen
  , jrFunction = "C_Digest"
  , jrState = JobQueued
  , jrBody = JobPending "sha256-owned-input/v1" (BS.pack (map fromIntegral [1 .. 32 :: Int]))
  }

-- | A prepared-result job fixture: verdict plus fully owned
-- result bytes (deliverable without any live context).
demoJobResult :: Word64 -> TokenId -> Generation -> JobRecord
demoJobResult pid tok gen = JobRecord
  { jrPersistentId = pid
  , jrToken = tok
  , jrTokenGeneration = gen
  , jrFunction = "C_Sign"
  , jrState = JobReady
  , jrBody = JobResult CKR_OK (BS.pack (map fromIntegral [101 .. 140 :: Int]))
  }

-- | Seed one token with two token objects; return the records.
seedStore :: Store -> IO (TokenRecord, [ObjectRecord])
seedStore store = do
  let slot = SlotId 0
      tmplA =
        [ (AttrClass, ValULong 3)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "seed-a")
        , (AttrValue, ValBytes "seed-bytes-a")
        ]
      tmplB =
        [ (AttrClass, ValULong 4)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "seed-b")
        ]
  mSeated <- expectRight "seed seat+open" (publishDelta (addToken emptyModel slot)
    (StateDelta [DeltaOpenSession (SessionId 1) slot False]))
  st <- expectJust "seed session" (lookupSession mSeated (SessionId 1))
  (m1, _, oid1) <- expectCreated mSeated st tmplA
  (m2, _, oid2) <- expectCreated m1 st tmplB
  ost1 <- expectJust "seed object 1" (lookupObject m2 oid1)
  ost2 <- expectJust "seed object 2" (lookupObject m2 oid2)
  let tok = TokenRecord
        { trId = TokenId 7
        , trSlot = slot
        , trGeneration = Generation 1
        , trLabel = "seed-token"
        , trAuth = tokenAuthNew
        }
  result <- storeCommit store emptyDelta
    { sdPutTokens = [tok]
    , sdPutObjects =
        [ ObjectPut Nothing (objectToRecord (TokenId 7) ost1)
        , ObjectPut Nothing (objectToRecord (TokenId 7) ost2)
        ]
    }
  assertEqual "seed commit" Committed result
  pure (tok, [objectToRecord (TokenId 7) ost1, objectToRecord (TokenId 7) ost2])

-- | Plan + publish one creation; return the model, handle, and id.
expectCreated
  :: Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle, ObjectId)
expectCreated m st tmpl = case planCreateObject m st tmpl of
  Immediate pc -> case publishDelta m (pcDelta pc) of
    Left fault -> assertFailure ("publish failed: " ++ show fault)
    Right m' -> case mapMaybe (decodeHandle . outBytes) (pcOutputs pc) of
      [h] -> pure (m', h, ObjectId (mNextObject' m))
      _ -> assertFailure "expected exactly one handle output"
  _ -> assertFailure "expected Immediate creation plan"

-- | Read the model's next-object counter (the id just allocated).
mNextObject' :: Model -> Int
mNextObject' = mNextObject

-- | A handle resolves when its binding names a live object.
resolves :: Model -> ExternalHandle -> Bool
resolves m h = case Map.lookup h (mHandles m) of
  Nothing -> False
  Just b -> case lookupObject m (hbObject b) of
    Nothing -> False
    Just ost -> hbGeneration b == osGeneration ost

-- | The three-token fixture catalog (demo/ops/audit).
threeLabels :: [String]
threeLabels = ["haskoki-demo", "haskoki-ops", "haskoki-audit"]

threeSo :: [String]
threeSo = ["5678", "6789", "7890"]

threeUser :: [String]
threeUser = ["1234", "2345", "3456"]

-- | A @[tokens]@ document with the given parallel arrays (an
-- empty id list omits the @token_ids@ key: the legacy
-- positional reading).
catalogDoc :: [String] -> [String] -> [String] -> [String] -> String
catalogDoc labels soPins userPins ids = unlines $
  [ "schema_version = 1"
  , "[tokens]"
  , "labels = " ++ show labels
  , "so_pins = " ++ show soPins
  , "user_pins = " ++ show userPins
  ] ++ ["token_ids = " ++ show ids | not (null ids)]

-- | The legacy positional three-token document.
positionalDoc :: String
positionalDoc = catalogDoc threeLabels threeSo threeUser []

-- | The swapped pinned document: audit moves to slot 1 with
-- its own PINs, ops moves to slot 2 with its own PINs.
swappedDoc :: String
swappedDoc = catalogDoc
  ["haskoki-demo", "haskoki-audit", "haskoki-ops"]
  ["5678", "7890", "6789"]
  ["1234", "3456", "2345"]
  ["1", "3", "2"]

-- | Parse a catalog document or fail the case.
parseCatalog :: String -> IO Config
parseCatalog body = case parseConfig body of
  Left err -> assertFailure ("catalog must parse: " ++ show err)
  Right cfg -> pure cfg

-- | Commit one backend delta against a closed file.
commitFile :: FilePath -> StoreDelta -> IO CommitResult
commitFile path delta = do
  eStore <- openSQLiteStore path
  s <- either (assertFailure . show) pure eStore
  result <- storeCommit s delta
  storeClose s
  pure result

-- | The version-1 schema. Frozen history (copied from the
-- pre-provisioning @spec/storage-schema.sql@), not a live
-- reference: it must never track the current schema.
v1SchemaDdl :: [String]
v1SchemaDdl =
  [ "CREATE TABLE store_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)"
  , "CREATE TABLE tokens (token_id TEXT PRIMARY KEY NOT NULL, slot_key BLOB NOT NULL CHECK (typeof(slot_key) = 'blob' AND length(slot_key) = 8), generation_key BLOB NOT NULL CHECK (typeof(generation_key) = 'blob' AND length(generation_key) = 8), record_json TEXT NOT NULL, format_version INTEGER NOT NULL CHECK (format_version = 1), UNIQUE(slot_key))"
  , "CREATE TABLE objects (object_id TEXT PRIMARY KEY NOT NULL, token_id TEXT NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE, class_key BLOB NOT NULL CHECK (typeof(class_key) = 'blob' AND length(class_key) = 8), key_type_key BLOB CHECK (key_type_key IS NULL OR (typeof(key_type_key) = 'blob' AND length(key_type_key) = 8)), attributes_json TEXT NOT NULL, material_encoding TEXT NOT NULL, material_blob BLOB, revision INTEGER NOT NULL CHECK (revision > 0), format_version INTEGER NOT NULL CHECK (format_version = 1))"
  , "CREATE INDEX objects_by_token ON objects(token_id)"
  , "CREATE TABLE detached_jobs (persistent_id_key BLOB PRIMARY KEY NOT NULL CHECK (typeof(persistent_id_key) = 'blob' AND length(persistent_id_key) = 8), token_id TEXT NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE, token_generation_key BLOB NOT NULL CHECK (typeof(token_generation_key) = 'blob' AND length(token_generation_key) = 8), function_name TEXT NOT NULL, execution_state TEXT NOT NULL CHECK (execution_state IN ('queued','ready','failed','canceled','delivered')), record_json TEXT NOT NULL, format_version INTEGER NOT NULL CHECK (format_version = 1))"
  , "CREATE INDEX jobs_by_token ON detached_jobs(token_id)"
  , "INSERT INTO store_meta(key, value) VALUES ('store_format', 'haskoki-demo-v1')"
  , "INSERT INTO store_meta(key, value) VALUES ('schema_version', '1')"
  , "INSERT INTO store_meta(key, value) VALUES ('next_persistent_job_id', '0000000000000001')"
  ]

-- | The schema marker and whether the @credentials@ table exists,
-- read on a plain connection (SELECTs only).
rawSchemaState :: FilePath -> IO (String, Bool)
rawSchemaState path = bracket (S.open (T.pack path)) S.close $ \db -> do
  ver <- rawTexts db (T.pack "SELECT value FROM store_meta WHERE key = 'schema_version'")
  tables <- rawTexts db (T.pack "SELECT name FROM sqlite_master WHERE type = 'table'")
  pure (concat ver, "credentials" `elem` tables)

-- | Workers tracked for one test: the forking test thread, the
-- opener thread, its completion flag, and the drain that closes an
-- unconsumed successful open. Entries carry their owner's thread
-- id, so a release reaps exactly the current test's workers even
-- when name-filtered runs overlap tests on different pool threads.
type WorkerReg = IORef [(ThreadId, ThreadId, MVar (), IO ())]

-- | Reap a registry's entries, or — with @Just me@ — only the
-- entries forked by one test thread, leaving concurrent tests'
-- entries for their own release. Worker problems never throw:
-- they accumulate as strings so the caller still restores the
-- env and reaps everything. The one exception that escapes is an
-- async kill of the releasing thread itself: the abort sweep
-- reaps (boundedly) or kills the unreaped remainder first, so no
-- worker is orphaned as an untracked live handle, and then the
-- kill propagates. Both the kill and the join share one 10s
-- bound (a pending kill delivery counts against it too): no
-- worker state, including a wedged uninterruptible section, can
-- stall the release past the bound. The suite never masks
-- uninterruptibly in worker-reachable code (the one
-- 'uninterruptibleMask_' guards microsecond close bookkeeping),
-- so in practice the kill is prompt and the bound covers only
-- the join.
reapSelected :: Maybe ThreadId -> WorkerReg -> IO [String]
reapSelected who reg = mask_ $ do
  -- The whole traversal runs masked (interruptible): async
  -- exceptions can only land at interruptible waits (the joins
  -- and drain takes below), where the abort sweep below covers
  -- them — never between popping the batch and installing that
  -- sweep, which would lose the batch with no release to reap
  -- it. The waits themselves stay killable, so prompt
  -- cancellation is preserved.
  workers <- atomicModifyIORef' reg (splitBy who)
  -- Entries popped below as they finish, so an abort sweep can
  -- tell finished workers (MVars consumed: re-reaping would stall
  -- on the joined doneVar) from unreaped ones.
  remainingVar <- newIORef workers
  fmap concat $
    (forM workers $ \w -> do
        r <- reapOne w
        atomicModifyIORef' remainingVar (\ws -> (drop 1 ws, ()))
        pure r)
    `onException` do
      -- Abort sweep: a kill during the traversal must not orphan
      -- the unreaped remainder as untracked live workers (their
      -- registry entries are already gone). Reap them boundedly
      -- now — drains stay idempotent (a consumed resVar is a fast
      -- no-op, never a double close). Every attempt is caught: we
      -- are already unwinding with the original kill, which must
      -- keep propagating (a second kill degrades to a skipped
      -- worker, never to a replaced exception).
      -- Residual: a closer that FAILS after the sweep passed its
      -- entry puts the handle back with no consumer left (the
      -- inline retry lives in the unwound parent loop). Lock held
      -- means the next open fails loudly (never silent); only a
      -- choreographed failing closer under an external kill can
      -- stage it — no in-suite trigger exists.
      rest <- readIORef remainingVar
      forM_ rest $ \w -> do
        _ <- (try (reapOne w) :: IO (Either SomeException [String]))
        pure ()
  where
    -- Never throws on worker problems and never parks entries for
    -- other releases: every path either reaps the worker or
    -- reports it, all within bounded time. Retries stay inside the
    -- current release, so no failed worker (or its error report)
    -- can leak into an unrelated test running later on the same
    -- pool thread. The one exception that escapes is an async kill
    -- of the releasing thread itself, which the abort sweep above
    -- turns into reaped-or-killed remainder plus propagation.
    reapOne (_, tid, doneVar, drain) = join (3 :: Int)
      where
        -- Bounded join: a slow worker gets up to ~30s total across
        -- retries, then a loud report. Kill delivery itself is
        -- prompt (no uninterruptible code on worker paths), so
        -- retries only ever fire on genuine stalls.
        join 0 = pure ["opener worker survived kill-and-join (wedged)"]
        join n = do
          -- A genuine async kill of the releasing thread must
          -- propagate, not degrade into a retried round: a retry
          -- that later succeeds would swallow the kill and return
          -- normally. Timeout-internals races and sync failures
          -- keep the old retry behavior (the timer's private
          -- exception is not AsyncException-typed, and takeMVar
          -- has no AsyncException-typed sync failure).
          -- readMVar (not takeMVar): completion stays observable,
          -- so an abort sweep re-joining a finished worker returns
          -- instantly instead of stalling the full bound on the
          -- consumed MVar. Single put, many peeks — same wakeup
          -- semantics, re-entrant.
          eJoin <- (try (timeout (10 * 1000000) (killThread tid >> readMVar doneVar)) :: IO (Either SomeException (Maybe ())))
          case eJoin of
            Left e -> case fromException e of
              Just ThreadKilled -> throwIO e
              Just UserInterrupt -> throwIO e
              _ -> join (n - 1)
            Right Nothing -> join (n - 1)
            Right (Just _) -> closeIt (3 :: Int) "no error recorded"
        -- Bounded close: each attempt runs forked with a 10s join,
        -- so even an uninterruptible hang cannot stall the release
        -- (the waiter is abandoned, never the release). A failed
        -- attempt is retried (one-shot injected faults and SQLite's
        -- own retryable failures clear on a second attempt); the
        -- drain puts the result back on failure so retries see it.
        -- A timeout is reported immediately (retrying a wedged
        -- closer is futile, and a second attempt would just find
        -- the resVar already consumed); a persistently failing close
        -- is reported with its last error.
        closeIt 0 why = pure ["opener drain failed persistently: " ++ why]
        closeIt n _ = do
          dd <- newEmptyMVar :: IO (MVar (Either SomeException ()))
          _ <- forkIO (try drain >>= putMVar dd)
          mDone <- timeout (10 * 1000000) (takeMVar dd)
          case mDone of
            Just (Right _) -> pure []
            Just (Left ex) -> closeIt (n - 1) (show ex)
            Nothing -> pure ["opener drain timed out (abandoned wedged closer)"]
    splitBy Nothing w = ([], w)
    splitBy (Just me) w = (others, mine)
      where (mine, others) = partition (\(owner, _, _, _) -> owner == me) w

foreign import ccall unsafe "sys/file.h flock" test_c_flock :: CInt -> CInt -> IO CInt
