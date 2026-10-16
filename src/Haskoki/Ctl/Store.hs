{- | @haskoki-ctl store check@ and @store migrate@: argument parsing,
exit codes (0 completed with nothing refused, 1 diagnosed refusal,
2 usage, 130 interrupted by SIGINT) and the redacted text. The logic
lives in "Haskoki.Runtime.Storage.Preflight".

Operator config files hold PINs, so a config error is reported as its
kind and line (or key) only, never the message body.
-}
module Haskoki.Ctl.Store
  ( storeCheckCommand
  , storeMigrateCommand
  , storeMigrateCommandWith
  , strictFlagsSwitch
  , renderUnexpectedFailure
  , renderCheckUnexpectedFailure
  ) where

import Control.Exception (AsyncException (..), IOException, SomeException, asyncExceptionFromException, catch, fromException, throwIO, try)
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.List (isPrefixOf, stripPrefix)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Database.SQLite3 as S
import System.IO (hFlush, stdout)

import Haskoki.Runtime.Catalog (asyncHomeConfig)
import Haskoki.Runtime.Config (Config, ConfigError (..), loadConfigFile)
import Haskoki.Runtime.Storage (StoreError (..), renderIdentityRefusal)
import Haskoki.Runtime.Storage.Preflight
import Haskoki.Runtime.Storage.SQLite (sqliteSchemaVersion)

-- | Exactly the named flags, each once, each with a value, plus at
-- most one standalone switch. The switch is only recognised where a
-- flag is expected: in a value position it is a usage error, never
-- silently the switch and never the value.
strictFlagsSwitch :: [String] -> String -> [String] -> Either String (Bool, Map String String)
strictFlagsSwitch names switch = go Map.empty False
  where
    go acc sw [] = case [n | n <- names, n `Map.notMember` acc] of
      [] -> Right (sw, acc)
      missing -> Left ("missing " ++ unwords missing)
    go acc sw (k : rest)
      | k == switch =
          if sw then Left ("repeated " ++ switch) else go acc True rest
      | k `notElem` names = Left ("unknown argument " ++ show k)
      | k `Map.member` acc = Left ("repeated " ++ k)
      | otherwise = case rest of
          (v : rest') | not (null v) && v /= switch -> go (Map.insert k v acc) sw rest'
          _ -> Left (k ++ " needs a value")

checkUsage :: String
checkUsage = unlines
  [ "usage: haskoki-ctl store check --path FILE --config FILE [--async-home]"
  , "  --async-home plans a store created through the async open"
  , "  (home token labelled haskoki-async) instead of the config's catalog"
  ]

line :: (String, String) -> String
line (tag, detail) = tag ++ ": " ++ detail ++ "\n"

-- | A config error as its kind plus line or key; the message body can
-- quote PINs and is never shown.
renderConfigError :: ConfigError -> (String, String)
renderConfigError e = ("config-invalid", case e of
  CfgParseError m -> case stripPrefix "line " m of
    Just rest | (n@(_ : _), ':' : _) <- span (`elem` ['0' .. '9']) rest -> "line " ++ n
    _ -> "unreadable"
  CfgInvalid m -> case quotedKey m of
    Just k -> "invalid value for " ++ k
    Nothing -> "invalid value"
  _ -> "unreadable")
  where
    -- The key is the shown (section,key) tuple that follows "at " or
    -- "out of range: "; the value after it is never read.
    quotedKey m
      | "out of range: " `isPrefixOf` m || "expected " `isPrefixOf` m =
          case breakOn "(\"" m of
            Just r | (sec, '"' : ',' : '"' : r2) <- break (== '"') r
                   , (k@(_ : _), '"' : ')' : _) <- break (== '"') r2
                   , not (null sec) -> Just (sec ++ "." ++ k)
            _ -> Nothing
      | otherwise = Nothing
    breakOn pat str = case str of
      [] -> Nothing
      _ | pat `isPrefixOf` str -> Just (drop (length pat) str)
      (_ : t) -> breakOn pat t

-- | 'try' for synchronous exceptions only: an async exception is
-- re-thrown as itself (so outer handlers still see its type) and
-- never reported as a store outcome.
trySync :: IO a -> IO (Either SomeException a)
trySync act = do
  r <- try act
  case r of
    Left ex -> case asyncExceptionFromException ex :: Maybe AsyncException of
      Just a -> throwIO a
      Nothing -> pure (Left ex)
    Right v -> pure (Right v)

-- | An interrupt anywhere in the check command is exit 130 with a
-- fixed line, never a verdict. Any other async exception propagates.
onCheckInterrupt :: AsyncException -> IO (Int, String, String)
onCheckInterrupt UserInterrupt =
  pure (130, "", line ("check-interrupted", "no verdict; rerun store check"))
onCheckInterrupt e = throwIO e

-- | An interrupt anywhere in the migrate command is exit 130 with a
-- fixed line, never a migration outcome. The cold-journal clearing
-- line rides along when a clear already happened. Any other async
-- exception propagates.
onMigrateInterrupt :: String -> AsyncException -> IO (Int, String, String)
onMigrateInterrupt coldLine UserInterrupt =
  pure (130, coldLine, line ("migrate-interrupted", "store state unknown; run store check"))
onMigrateInterrupt _ e = throwIO e

storeCheckCommand :: [String] -> IO (Int, String, String)
storeCheckCommand args0 =
  (case strictFlagsSwitch ["--path", "--config"] "--async-home" args0 of
    Left why -> pure (2, "", "store check: " ++ why ++ "\n" ++ checkUsage)
    Right (asyncHome, fl) -> case (Map.lookup "--path" fl, Map.lookup "--config" fl) of
      (Just path, Just cfgPath) -> do
        eCfg <- loadConfigFile cfgPath
        case eCfg of
          Left err -> pure (1, "", line (renderConfigError err))
          Right cfg0 -> do
            let cfg = if asyncHome then asyncHomeConfig cfg0 else cfg0
            sel <- configSelectsStore path cfg
            case sel of
              Left r -> pure (1, "", line ("config-mismatch", renderPreflightRefusal r))
              Right () -> checkSelected path cfgPath asyncHome cfg
      _ -> pure (2, "", checkUsage)) `catch` onCheckInterrupt

checkSelected :: FilePath -> FilePath -> Bool -> Config -> IO (Int, String, String)
checkSelected path cfgPath asyncHome cfg = do
  r <- trySync (checkStoreOpen path cfg) :: IO (Either SomeException (Either StoreError StoreOpenPlan))
  case r of
    Left ex -> pure (1, "", line (renderCheckUnexpectedFailure ex))
    Right (Left (StoreIO m))
      | "no store file" `isPrefixOf` m -> pure (1, "", line ("store-missing", m))
    Right (Left cold@(StoreJournalCold _)) -> coldOkOrRefusal cold
    Right (Left se) -> pure (1, "", line (renderStoreRefusal se))
    Right (Right plan) -> pure $ case planVerdict plan of
      VerdictOpenable -> (0, renderPlan plan, "")
      VerdictMigrationRequired -> (1, renderPlan plan, line ("store-migration-required",
        "stop the store owner, then run haskoki-ctl store migrate --path " ++ path
          ++ " --config " ++ cfgPath ++ " --backup-dir DIR"
          ++ (if asyncHome then " --async-home" else "")))
      VerdictIdentityRefused ir ->
        (1, renderPlan plan, line ("store-identity-refused", renderIdentityRefusal ir))
  where
    -- A cold journal whose plan is otherwise openable is not a
    -- refusal: the serving open takes the store and the next write
    -- reuses the file. Any other retry outcome keeps the cold
    -- refusal.
    coldOkOrRefusal cold = do
      r2 <- trySync (checkStoreOpenAllowCold path cfg)
        :: IO (Either SomeException (Either StoreError StoreOpenPlan))
      pure $ case r2 of
        Right (Right plan) | planVerdict plan == VerdictOpenable ->
          (0, renderPlan plan ++ "journal: cold (harmless; reused by the next write)\n", "")
        _ -> (1, "", line (renderStoreRefusal cold))

migrateUsage :: String
migrateUsage = unlines
  [ "usage: haskoki-ctl store migrate --path FILE --config FILE --backup-dir DIR [--async-home]"
  , "  --async-home migrates a store created through the async open"
  , "  (home token labelled haskoki-async) instead of the config's catalog"
  ]

storeMigrateCommand :: [String] -> IO (Int, String, String)
storeMigrateCommand = storeMigrateCommandWith noMigrateHooks

-- | 'storeMigrateCommand' over injected migration hooks (the
-- storage suite fails the run after the cold-journal clear to pin
-- the clearing report).
storeMigrateCommandWith :: MigrateHooks -> [String] -> IO (Int, String, String)
storeMigrateCommandWith hooks0 args0 =
  (case strictFlagsSwitch ["--path", "--config", "--backup-dir"] "--async-home" args0 of
    Left why -> pure (2, "", "store migrate: " ++ why ++ "\n" ++ migrateUsage)
    Right (asyncHome, fl) -> case (Map.lookup "--path" fl, Map.lookup "--config" fl, Map.lookup "--backup-dir" fl) of
      (Just path, Just cfgPath, Just dir) -> do
        eCfg <- loadConfigFile cfgPath
        case eCfg of
          Left err -> pure (1, "", line (renderConfigError err))
          Right cfg0 -> do
            let cfg = if asyncHome then asyncHomeConfig cfg0 else cfg0
            sel <- configSelectsStore path cfg
            case sel of
              Left r -> pure (1, "", line ("config-mismatch", renderPreflightRefusal r))
              Right () -> migrateSelectedWith hooks0 path cfg dir
      _ -> pure (2, "", migrateUsage)) `catch` onMigrateInterrupt ""

-- | The exception's type name only, never its message: PINs are not
-- digit-only, so no redaction of message text can be complete.
-- Known store-layer failures name themselves; anything else is a
-- bare 'SomeException'.
exceptionTypeName :: SomeException -> String
exceptionTypeName ex =
  case fromException ex :: Maybe IOException of
    Just _ -> "IOException"
    Nothing -> case fromException ex :: Maybe S.SQLError of
      Just _ -> "SQLError"
      Nothing -> case fromException ex :: Maybe StoreError of
        Just _ -> "StoreError"
        Nothing -> "SomeException"

-- | An unexpected synchronous exception as a fixed tagged line:
-- the exception type only, never raw message text, so no credential
-- of any shape can reach operator output. Single line, like every
-- other exit-1 refusal. Its own tag: @migrate-failed@ is reserved
-- for a rolled-back transaction ("the store was not changed"),
-- which an unforeseen failure cannot promise.
renderUnexpectedFailure :: SomeException -> (String, String)
renderUnexpectedFailure ex =
  ("migrate-unexpected", "unexpected failure: " ++ exceptionTypeName ex
    ++ "; run store check before anything else")

-- | An unexpected exception through check as a fixed tagged line:
-- the exception type only, never the raw message.
renderCheckUnexpectedFailure :: SomeException -> (String, String)
renderCheckUnexpectedFailure ex =
  ("store-unreadable", "unexpected failure: " ++ exceptionTypeName ex)

-- | Run the selected migration over injected hooks. Every outcome
-- after a cold-journal clear carries the clearing line on stdout
-- (a migrated run already carries it in its receipt). The verified
-- backup's path and SHA-256 are printed to stdout the moment
-- verification passes, before the transaction begins, and flushed,
-- so a killed run still leaves its digest in the operator's log
-- (the receipt repeats both lines on success).
migrateSelectedWith :: MigrateHooks -> FilePath -> Config -> FilePath -> IO (Int, String, String)
migrateSelectedWith hooks0 path cfg dir = do
  clearedRef <- newIORef False
  let hooks = hooks0
        { mhOnColdClear = mhOnColdClear hooks0 >> writeIORef clearedRef True
        , mhOnBackupVerified = \bak n sha -> do
            mhOnBackupVerified hooks0 bak n sha
            putStrLn ("backup: " ++ bak)
            putStrLn ("backup-sha256: " ++ sha)
            hFlush stdout
        }
      onInt e = do
        cleared <- readIORef clearedRef
        let coldLine = if cleared then "cold-journal-removed: yes\n" else ""
        onMigrateInterrupt coldLine e
      run = do
        r <- trySync (migrateStoreWith hooks path cfg dir) :: IO (Either SomeException (Either MigrateError MigrateOutcome))
        cleared <- readIORef clearedRef
        let coldLine = if cleared then "cold-journal-removed: yes\n" else ""
            render = if cleared then renderMigrateErrorAfterClear else renderMigrateError
        pure $ case r of
          Left ex -> (1, coldLine, line (renderUnexpectedFailure ex))
          Right (Left me) -> (1, coldLine, line (render me))
          Right (Right MigrateNotNeeded) -> (0, coldLine ++ line ("migrate-not-needed",
            "the store is at schema " ++ show sqliteSchemaVersion
              ++ " and every token has a credential row; nothing was written"), "")
          Right (Right (Migrated rc)) -> (0, renderReceipt rc ++ "receipt: " ++ mrReceipt rc ++ "\nmigrate-done\n", "")
  run `catch` onInt
