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
  , strictFlags
  ) where

import Control.Exception (SomeException, try)
import Data.List (isInfixOf, isPrefixOf, stripPrefix)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)

import Haskoki.Runtime.Catalog (asyncHomeConfig)
import Haskoki.Runtime.Config (Config, ConfigError (..), loadConfigFile)
import Haskoki.Runtime.Storage (StoreError (..), renderIdentityRefusal)
import Haskoki.Runtime.Storage.Preflight

-- | Exactly the named flags, each once, each with a value.
strictFlags :: [String] -> [String] -> Either String (Map String String)
strictFlags names = go Map.empty
  where
    go acc [] = case [n | n <- names, n `Map.notMember` acc] of
      [] -> Right acc
      missing -> Left ("missing " ++ unwords missing)
    go acc (k : rest)
      | k `notElem` names = Left ("unknown argument " ++ show k)
      | k `Map.member` acc = Left ("repeated " ++ k)
      | otherwise = case rest of
          (v : rest') | not (null v) -> go (Map.insert k v acc) rest'
          _ -> Left (k ++ " needs a value")

-- | Remove a value-less switch; it may appear at most once.
takeSwitch :: String -> [String] -> Either String (Bool, [String])
takeSwitch name args = case length (filter (== name) args) of
  0 -> Right (False, args)
  1 -> Right (True, filter (/= name) args)
  _ -> Left ("repeated " ++ name)

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
storeCheckCommand args0 = case takeSwitch "--async-home" args0 of
  Left why -> pure (2, "", "store check: " ++ why ++ "\n" ++ checkUsage)
  Right (asyncHome, args) -> case strictFlags ["--path", "--config"] args of
    Left why -> pure (2, "", "store check: " ++ why ++ "\n" ++ checkUsage)
    Right fl -> case (Map.lookup "--path" fl, Map.lookup "--config" fl) of
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

-- | Not available yet.
storeMigrateCommand :: [String] -> IO (Int, String, String)
storeMigrateCommand _ = pure (2, "", "store migrate: not available yet\n")
