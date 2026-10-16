{- | @haskoki-ctl store check@ and @store migrate@: argument parsing,
exit codes (0 completed with nothing refused, 1 diagnosed refusal,
2 usage) and the redacted text. The logic lives in
"Haskoki.Runtime.Storage.Preflight".

Operator config files hold PINs, so a config error is reported as its
kind and line (or key) only, never the message body.
-}
module Haskoki.Ctl.Store
  ( storeCheckCommand
  , storeMigrateCommand
  , strictFlagsSwitch
  , renderUnexpectedFailure
  ) where

import Control.Exception (SomeException, displayException, try)
import Data.Char (isDigit)
import Data.List (isPrefixOf, stripPrefix)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)

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

storeCheckCommand :: [String] -> IO (Int, String, String)
storeCheckCommand args0 = case strictFlagsSwitch ["--path", "--config"] "--async-home" args0 of
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
    _ -> pure (2, "", checkUsage)

checkSelected :: FilePath -> FilePath -> Bool -> Config -> IO (Int, String, String)
checkSelected path cfgPath asyncHome cfg = do
  r <- try (checkStoreOpen path cfg) :: IO (Either SomeException (Either StoreError StoreOpenPlan))
  pure $ case r of
    Left ex -> (1, "", line ("store-unreadable", show ex))
    Right (Left (StoreIO m))
      | "no store file" `isPrefixOf` m -> (1, "", line ("store-missing", m))
    Right (Left se) -> (1, "", line (renderStoreRefusal se))
    Right (Right plan) -> case planVerdict plan of
      VerdictOpenable -> (0, renderPlan plan, "")
      VerdictMigrationRequired -> (1, renderPlan plan, line ("store-migration-required",
        "stop the store owner, then run haskoki-ctl store migrate --path " ++ path
          ++ " --config " ++ cfgPath ++ " --backup-dir DIR"
          ++ (if asyncHome then " --async-home" else "")))
      VerdictIdentityRefused ir ->
        (1, renderPlan plan, line ("store-identity-refused", renderIdentityRefusal ir))

migrateUsage :: String
migrateUsage = unlines
  [ "usage: haskoki-ctl store migrate --path FILE --config FILE --backup-dir DIR [--async-home]"
  , "  --async-home migrates a store created through the async open"
  , "  (home token labelled haskoki-async) instead of the config's catalog"
  ]

storeMigrateCommand :: [String] -> IO (Int, String, String)
storeMigrateCommand args0 = case strictFlagsSwitch ["--path", "--config", "--backup-dir"] "--async-home" args0 of
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
            Right () -> migrateSelected path cfg dir
    _ -> pure (2, "", migrateUsage)

-- | An unexpected exception as a fixed tagged line: the first line of
-- its rendering, with every run of four or more digits redacted, so a
-- PIN-like value can never survive into operator output. Single line,
-- like every other exit-1 refusal.
renderUnexpectedFailure :: SomeException -> (String, String)
renderUnexpectedFailure ex =
  ("migrate-failed", "unexpected failure: " ++ redact (takeWhile (/= '\n') (displayException ex))
    ++ "; run store check before anything else")
  where
    redact [] = []
    redact (c : cs)
      | isDigit c =
          let (digits, rest) = span isDigit (c : cs)
          in (if length digits >= 4 then "[redacted]" else digits) ++ redact rest
      | otherwise = c : redact cs

migrateSelected :: FilePath -> Config -> FilePath -> IO (Int, String, String)
migrateSelected path cfg dir = do
  r <- try (migrateStore path cfg dir) :: IO (Either SomeException (Either MigrateError MigrateOutcome))
  pure $ case r of
    Left ex -> (1, "", line (renderUnexpectedFailure ex))
    Right (Left me) -> (1, "", line (renderMigrateError me))
    Right (Right MigrateNotNeeded) -> (0, line ("migrate-not-needed",
      "the store is at schema " ++ show sqliteSchemaVersion
        ++ " and every token has a credential row; nothing was written"), "")
    Right (Right (Migrated rc)) -> (0, renderReceipt rc ++ "receipt: " ++ mrReceipt rc ++ "\nmigrate-done\n", "")
