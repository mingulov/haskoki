{- | SQLite store database configuration and schema setup.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Init
  ( pauseForFreshCreate
  , waitForGoFile
  , waitForPoll
  , configure
  , verifyPragmas
  , initSchema
  , removeIfOurs
  , classifySchema
  , verifyExisting
  , schemaStatements
  , createCredentialsTable
  , openAndInit
  ) where

import Control.Concurrent (threadDelay)
import Control.Exception (SomeException, throwIO, try)
import Control.Monad (when)
import qualified Data.Text as T
import Data.Text (Text)
import qualified Database.SQLite3 as S
import System.Environment (lookupEnv)
import System.IO.Error (tryIOError)
import System.Posix.Files (fileExist, fileSize, getFdStatus, removeLink, setFileMode)
import System.Posix.Types (Fd)
import Haskoki.Runtime.Storage
  ( StoreError (..)
  )
import Haskoki.Runtime.Storage.SQLite.Conn
import Haskoki.Runtime.Storage.SQLite.Statements
import Haskoki.Runtime.Storage.SQLite.Types

-- | Test seam: when @HASKOKI_OPEN_PAUSE@ is a nonempty value AND
-- @HASKOKI_OPEN_PAUSE_PATH@ names THIS open's database path
-- (exact string match) AND this open created the file, write a
-- @paused@ marker and wait for a @go@ file (10ms poll, 3000 polls —
-- about 30s wall-clock when running, longer if the process is
-- suspended — then proceed regardless). The marker write is
-- best-effort and the value is not checked to be a directory: a
-- nonexistent directory simply fails the marker write and the open
-- still waits out the poll budget. Afterwards the seam records
-- the exact poll count in @<dir>\/polls@ (best-effort, same
-- terms): the count pins the polling structure — any reworking
-- of the loop (backoff, early give-up, split calls) reports a
-- different total. Timing probes cover promptness; the count
-- covers structure.
-- Honoured only with the env-seam opt-in
-- (@storage.allow_env_seams@); without it the seam never fires,
-- even with both variables set. Inert unless both variables are
-- set (one env lookup each) and on every open that did not
-- create the file.
-- The path binding keeps unrelated parallel SQLite creators
-- (contract\/commit tests, inherited-env holder children) from
-- pausing on another test's handshake — only the intended opener
-- can write its controller's @paused@ file. Justification: the
-- fresh-init interleaving (sidecar lost between guard acquisition
-- and SQLite's open) is otherwise timing-only; this pauses
-- exactly that window so the interleaving and the path-swap abort
-- are deterministically testable. One pauser per directory;
-- production never sets it.
pauseForFreshCreate :: Bool -> FilePath -> IO ()
pauseForFreshCreate False _ = pure ()
pauseForFreshCreate True dbPath = do
  mDir <- lookupEnv "HASKOKI_OPEN_PAUSE"
  mWant <- lookupEnv "HASKOKI_OPEN_PAUSE_PATH"
  case (mDir, mWant) of
    (Just dir, Just want) | not (null dir), want == dbPath -> do
      _ <- tryIOError (writeFile (dir ++ "/paused") "paused\n")
      (_, nPolls) <- waitForGoFile (dir ++ "/go") (3000 :: Int)
      _ <- tryIOError (writeFile (dir ++ "/polls") (show nPolls ++ "\n"))
      pure ()
    _ -> pure ()

-- | Wait for the @go@ handshake file: poll @fileExist@ through
-- 'waitForPoll', reporting how many polls ran. The count is part
-- of the contract: a single-check reimplementation returns a count
-- of one, which the composition test rejects.
waitForGoFile :: FilePath -> Int -> IO (Bool, Int)
waitForGoFile goFile maxPolls = waitForPoll (fileExist goFile) maxPolls

-- | Poll a @go@-style probe every 10ms, up to @maxPolls@ times.
-- Returns whether it fired paired with the polls performed: True
-- the moment it fires, (False, 0) without probing on a
-- nonpositive budget, (False, budget) on exhaustion (the caller
-- proceeds regardless). Exported so the handshake polling — not
-- just its timing — is unit-testable (like 'livenessFromProbes'):
-- a seam that checked once and then slept returns a count of one,
-- which the composition test rejects no matter how the test
-- thread is scheduled.
waitForPoll :: IO Bool -> Int -> IO (Bool, Int)
waitForPoll _ maxPolls | maxPolls <= 0 = pure (False, 0)
waitForPoll probe maxPolls = go 0
  where
    go n = do
      done <- probe
      let n' = n + 1
      if done then pure (True, n') else threadDelay 10000 >> if n' >= maxPolls then pure (False, n') else go n'

-- | Configure one connection: foreign keys, bounded busy timeout,
-- rollback journal, durable sync — then verify the durable modes
-- read back as set.
configure :: S.Database -> IO (Either StoreError ())
configure db = do
  ePragmas <- trySQLite (mapM_ (S.exec db) pragmaStatements)
  case ePragmas of
    Left err -> pure (Left err)
    Right () -> verifyPragmas db
  where
    pragmaStatements :: [Text]
    pragmaStatements =
      [ "PRAGMA foreign_keys = ON"
      , "PRAGMA journal_mode = DELETE"
      , "PRAGMA synchronous = EXTRA"
      , "PRAGMA busy_timeout = 5000"
      ]

-- | Verify the durable modes were honored (a database that
-- silently runs an unsafe mode is a misconfiguration, not a store).
verifyPragmas :: S.Database -> IO (Either StoreError ())
verifyPragmas db = do
  eJournal <- queryRows db "PRAGMA journal_mode" []
  eSync <- queryRows db "PRAGMA synchronous" []
  eFk <- queryRows db "PRAGMA foreign_keys" []
  case (eJournal, eSync, eFk) of
    (Right [[S.SQLText mode]], Right [[S.SQLInteger n]], Right [[S.SQLInteger fk]])
      | T.toLower mode == "delete" && n == 3 && fk == 1 -> pure (Right ())
      | otherwise -> pure (Left (StoreIO ("sqlite pragmas not honored: journal=" ++ show mode ++ " sync=" ++ show n ++ " fk=" ++ show fk)))
    (Left err, _, _) -> pure (Left err)
    (_, Left err, _) -> pure (Left err)
    (_, _, Left err) -> pure (Left err)
    _ -> pure (Left (StoreIO "sqlite pragmas returned unexpected rows"))

-- | Transactionally initialize a fresh database from the schema.
-- On failure the partial file is removed (best effort) so a retry
-- sees a fresh path, never a half-schema — but ONLY while the path
-- still names our guarded inode, so a failed CREATE can never
-- unlink another owner's database. Never closes the handle (owned
-- by 'openAndInit').
initSchema :: S.Database -> Fd -> FilePath -> IO (Either StoreError S.Database)
initSchema db guardFd path = do
  eBegin <- trySQLite (S.exec db "BEGIN IMMEDIATE")
  case eBegin of
    Left err -> pure (Left err)
    Right () -> do
      eBody <- trySQLite (mapM_ (S.exec db) schemaStatements)
      case eBody of
        Left err -> do
          _ <- trySQLite (S.exec db "ROLLBACK")
          removeIfOurs guardFd path
          pure (Left (StoreIO ("schema init failed: " ++ show err)))
        Right () -> do
          eCommit <- trySQLite (S.exec db "COMMIT")
          case eCommit of
            Left err -> do
              _ <- trySQLite (S.exec db "ROLLBACK")
              removeIfOurs guardFd path
              pure (Left (StoreIO ("schema init commit failed: " ++ show err)))
            Right () -> do
              _ <- tryIOError (setFileMode path 0o600)
              pure (Right db)

-- | Best-effort removal of a failed-init database, only while the
-- path still names our guarded inode. Sound: we hold the exclusive
-- guard on that inode, and any live owner holds a guard on the
-- live inode — so if the path names ours, no other live owner
-- uses it. A swapped path is left alone.
removeIfOurs :: Fd -> FilePath -> IO ()
removeIfOurs guardFd path = do
  ours <- sameFile guardFd path
  when ours $ do
    _ <- tryIOError (removeLink path)
    pure ()

-- | Judge an existing file's schema from its table names and its
-- @schema_version@ rows. Shared by the serving open and the
-- read-only snapshot, so both judge a file identically. 'Right' is
-- 1, 2 or 3 with a matching table shape; never writes.
classifySchema :: FilePath -> [Text] -> Either StoreError [[S.SQLData]] -> Either StoreError Int
classifySchema path names eRows
  | not (all (`elem` names) ["store_meta", "tokens", "objects", "detached_jobs"]) =
      Left (StoreIO (path ++ ": not a haskoki store (missing tables)"))
  | otherwise = do
      rows <- eRows
      case rows of
        [[S.SQLText v]] -> case T.unpack v of
          "1" | hasCreds -> Left (StoreCorrupt (path ++ ": schema version 1 with a credentials table"))
              | otherwise -> Right 1
          "2" | hasCreds -> Right 2
              | otherwise -> Left (StoreCorrupt (path ++ ": schema version 2 without credentials table"))
          "3" | hasCreds -> Right 3
              | otherwise -> Left (StoreCorrupt (path ++ ": schema version 3 without credentials table"))
          other -> Left (StoreSchemaVersion sqliteSchemaVersion other)
        _ -> Left (StoreCorrupt (path ++ ": corrupt store metadata"))
  where
    hasCreds = "credentials" `elem` names

-- | Verify an existing database: only the current schema serves.
-- An older schema refuses as migration-required and anything else
-- refuses as unsupported or corrupt, in every case WITHOUT writing a
-- byte. Never closes the handle (owned by 'openAndInit').
verifyExisting :: S.Database -> FilePath -> IO (Either StoreError S.Database)
verifyExisting db path = do
  eTables <- queryRows db "SELECT name FROM sqlite_master WHERE type = 'table'" []
  case eTables of
    Left err -> pure (Left err)
    Right rows -> do
      let names = [t | [S.SQLText t] <- rows]
      eVer <- if "store_meta" `elem` names
        then queryRows db "SELECT value FROM store_meta WHERE key = 'schema_version'" []
        else pure (Right [])
      pure $ case classifySchema path names eVer of
        Left err -> Left err
        Right v
          | v == sqliteSchemaVersion -> Right db
          | otherwise -> Left (StoreNeedsMigration v sqliteSchemaVersion)

-- | The schema (mirrors @spec\/storage-schema.sql@).
schemaStatements :: [Text]
schemaStatements =
  [ "CREATE TABLE store_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)"
  , "CREATE TABLE tokens (token_id TEXT PRIMARY KEY NOT NULL, slot_key BLOB NOT NULL CHECK (typeof(slot_key) = 'blob' AND length(slot_key) = 8), generation_key BLOB NOT NULL CHECK (typeof(generation_key) = 'blob' AND length(generation_key) = 8), record_json TEXT NOT NULL, format_version INTEGER NOT NULL CHECK (format_version = 1), UNIQUE(slot_key))"
  , "CREATE TABLE objects (object_id TEXT PRIMARY KEY NOT NULL, token_id TEXT NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE, class_key BLOB NOT NULL CHECK (typeof(class_key) = 'blob' AND length(class_key) = 8), key_type_key BLOB CHECK (key_type_key IS NULL OR (typeof(key_type_key) = 'blob' AND length(key_type_key) = 8)), attributes_json TEXT NOT NULL, material_encoding TEXT NOT NULL, material_blob BLOB, revision INTEGER NOT NULL CHECK (revision > 0), format_version INTEGER NOT NULL CHECK (format_version = 1))"
  , "CREATE INDEX objects_by_token ON objects(token_id)"
  , "CREATE TABLE detached_jobs (persistent_id_key BLOB PRIMARY KEY NOT NULL CHECK (typeof(persistent_id_key) = 'blob' AND length(persistent_id_key) = 8), token_id TEXT NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE, token_generation_key BLOB NOT NULL CHECK (typeof(token_generation_key) = 'blob' AND length(token_generation_key) = 8), function_name TEXT NOT NULL, execution_state TEXT NOT NULL CHECK (execution_state IN ('queued','ready','failed','canceled','delivered')), record_json TEXT NOT NULL, format_version INTEGER NOT NULL CHECK (format_version = 1))"
  , "CREATE INDEX jobs_by_token ON detached_jobs(token_id)"
  , createCredentialsTable
  , "INSERT INTO store_meta(key, value) VALUES ('store_format', 'haskoki-demo-v1')"
  , "INSERT INTO store_meta(key, value) VALUES ('schema_version', '3')"
  , "INSERT INTO store_meta(key, value) VALUES ('next_persistent_job_id', '0000000000000001')"
  ]

-- | The @credentials@ table: one provisioned credential row per
-- token, owned by its token (@ON DELETE CASCADE@, mirroring the
-- object and job tables). Shared by fresh schemas and the explicit
-- migration, so both spell it identically.
createCredentialsTable :: Text
createCredentialsTable =
  "CREATE TABLE credentials (token_id TEXT PRIMARY KEY NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE, record_json TEXT NOT NULL, format_version INTEGER NOT NULL CHECK (format_version = 1))"

-- ---------------------------------------------------------------------------
-- Init and verify
-- ---------------------------------------------------------------------------
-- | Open the database file, configure it, and initialize or verify
-- the schema. Runs under the caller's mask (see
-- 'openSQLiteStoreWith'), whose @restore@ this takes: the only
-- restored section is 'openInner' work, which the exception path
-- below protects with handle cleanup (rollback, then close).
-- Every sync failure is reported as 'Left' with the handle
-- already closed; success returns the handle masked, so it
-- transfers to 'SQLiteConn' construction with no async-delivery
-- window. The caller always holds the database guard
-- ('ensureDbGuard') before this runs, and freshness is read from
-- the guarded fd (never the path: no TOCTOU between the check and
-- SQLite's open). After opening, the path must still name the
-- guarded inode — otherwise the bytes SQLite would touch are not
-- the guarded ones and the open aborts. The handle has exactly
-- one owner: the inner helpers never close it, so no interleaving
-- can double-close the raw pointer; this function's case analysis
-- closes once on each failure path and hands the handle off
-- untouched on success.
openAndInit
  :: Bool
  -> (IO (Either StoreError S.Database) -> IO (Either StoreError S.Database))
  -> Fd -> FilePath -> Bool -> IO (Either StoreError S.Database)
openAndInit allowEnv restore guardFd path created = do
  eSt <- tryStoreIO (getFdStatus guardFd)
  case eSt of
    Left err -> pure (Left err)
    Right st -> do
      let fresh = fileSize st == 0
      when created (pauseForFreshCreate allowEnv path)
      eDb <- trySQLite (S.open (T.pack path))
      case eDb of
        Left err -> pure (Left err)
        Right db -> do
          same <- sameFile guardFd path
          if not same
            then closeQuiet db >> pure (Left (StoreIO ("store database replaced during open: " ++ path)))
            else do
              eRes <- try (restore (openInner db path fresh))
              case eRes of
                Left (e :: SomeException) -> rollbackQuiet db >> closeQuiet db >> throwIO e
                Right (Left err) -> closeQuiet db >> pure (Left err)
                Right (Right ok) -> pure (Right ok)
  where
    openInner db dbPath fresh = do
      eCfg <- configure db
      case eCfg of
        Left err -> pure (Left err)
        Right ()
          | fresh -> initSchema db guardFd dbPath
          | otherwise -> verifyExisting db dbPath
