{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{- | SQLite store backend: one local file, single writer.

On 'openSQLiteStore' the backend takes single-writer ownership via
an O_EXCL sidecar lock file (@\<db\>.lock@) carrying the owner's
pid: a second opener whose owner is alive fails explicitly with
'StoreSecondWriter', and a lock whose owner is dead (a crashed
previous run; detected via @\/proc@) is taken over without touching
any data. SQLite-level locking alone would not keep two provider
caches coherent, so the file lock — not the database — is the
ownership arbiter.

An empty database initializes transactionally from the schema in
@spec\/storage-schema.sql@ (four tables, indexes, meta rows); an
existing database is verified (tables present, @schema_version@
exactly @1@) and never silently refixtured. A foreign or garbage
file is rejected with a diagnosis and left byte-identical.

SQLite configuration (design 08, section 6): foreign keys on, a
bounded 5s busy timeout, rollback-journal mode, ordinary durable
(FULL) synchronization. WAL is not used; no unsafe journal\/sync
mode is ever selected. Every commit runs as one @BEGIN IMMEDIATE@
transaction, so multi-object deltas are all-or-nothing.

Full-width unsigned quantities travel as 8-byte big-endian blobs
or fixed hex text; only the bounded @revision@ counter uses an
INTEGER column (guarded by @CHECK (revision > 0)@), and every
read-back range-checks before narrowing to 'Int'.
-}
module Haskoki.Runtime.Storage.SQLite
  ( openSQLiteStore
  , openSQLiteStoreWith
  , sqliteSchemaVersion
  ) where

import Control.Concurrent.MVar (MVar, modifyMVar_, newMVar, putMVar, readMVar, takeMVar)
import Control.Exception (SomeException, bracket, bracket_, mask, mask_, throwIO, try)
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.Int (Int64)
import Data.List (nub)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe)
import qualified Data.Text as T
import Data.Text (Text)
import Data.Word (Word64)
import qualified Database.SQLite3 as S
import System.IO.Error (tryIOError)
import System.Posix.Files (fileExist, fileSize, getFileStatus, removeLink, setFileMode)
import System.Posix.IO (OpenFileFlags (..), OpenMode (..), closeFd, defaultFileFlags, fdWrite, openFd)
import System.Posix.Process (getProcessID)
import System.Posix.Types (ProcessID)

import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , FaultInjector (..)
  , FaultPoint (..)
  , JobRecord (..)
  , LoadedState (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , Reconcile (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , StoreLimits
  , StoreStats (..)
  , StoredDoc (..)
  , TokenRecord (..)
  , checkExpectedRevisions
  , checkLimits
  , checkSlotUnique
  , checkTokenRefs
  , decodeAttrsDoc
  , decodeHex16
  , decodeJobRecord
  , decodeTokenRecord
  , defaultLimits
  , encodeAttrsDoc
  , encodeHex16
  , encodeHexWord64
  , encodeJobRecord
  , encodeObjectRecord
  , encodeTokenRecord
  , execStateName
  , knownMaterialEncodings
  , noFaults
  , reconcileJobsReload
  , reconcileReload
  , zeroStats
  )
import Haskoki.Types (Generation (..), ObjectId (..), Revision (..), SlotId (..), TokenId (..))

-- | The schema version this backend creates and accepts.
sqliteSchemaVersion :: Int
sqliteSchemaVersion = 1

-- | One open SQLite store: the connection, its guard lock, the
-- idempotent-close flag, the owned paths, and the live-handle
-- protocol state (injector, quarantine, stats).
data SQLiteConn = SQLiteConn
  { sqDb :: !S.Database
  , sqLock :: !(MVar ())
  , sqClosed :: !(MVar Bool)
  , sqPath :: !FilePath
  , sqLockPath :: !FilePath
  , sqInjector :: !FaultInjector
  , sqQuarantine :: !(MVar [(TokenId, String)])
  , sqStats :: !(IORef StoreStats)
  , sqLimits :: !StoreLimits
  }

-- ---------------------------------------------------------------------------
-- Open
-- ---------------------------------------------------------------------------

-- | Open the SQLite store at the given path, taking single-writer
-- ownership. Any failure releases ownership before returning; an
-- async exception during open releases the lock and then
-- re-propagates, so it can never strand a live-pid lock.
-- Default limits, no fault injection.
openSQLiteStore :: FilePath -> IO (Either StoreError Store)
openSQLiteStore path = openSQLiteStoreWith path defaultLimits noFaults

-- | Open with explicit limits (always enforced) and an
-- explicit fault injector.
openSQLiteStoreWith :: FilePath -> StoreLimits -> FaultInjector -> IO (Either StoreError Store)
openSQLiteStoreWith path limits inj = do
  let lockPath = path ++ ".lock"
  eOwn <- takeOwnership path lockPath 3
  case eOwn of
    Left err -> pure (Left err)
    Right () -> mask $ \restore -> do
      eDb <- try (restore (openAndInit path))
      case eDb of
        Left (e :: SomeException) -> releaseQuiet lockPath >> throwIO e
        Right (Left err) -> releaseQuiet lockPath >> pure (Left err)
        Right (Right db) -> do
          lock <- newMVar ()
          closed <- newMVar False
          qVar <- newMVar []
          sVar <- newIORef zeroStats
          let conn = SQLiteConn
                { sqDb = db
                , sqLock = lock
                , sqClosed = closed
                , sqPath = path
                , sqLockPath = lockPath
                , sqInjector = inj
                , sqQuarantine = qVar
                , sqStats = sVar
                , sqLimits = limits
                }
          pure (Right (mkStore conn))

-- ---------------------------------------------------------------------------
-- Ownership
-- ---------------------------------------------------------------------------

-- | Take single-writer ownership via an O_EXCL sidecar lock carrying
-- our pid. An existing lock owned by a live pid fails explicitly;
-- a lock owned by a dead pid (a crashed run) is taken over after a
-- bounded number of retries. Taking over never touches the
-- database bytes.
takeOwnership :: FilePath -> FilePath -> Int -> IO (Either StoreError ())
takeOwnership dbPath lockPath attempts
  | attempts <= 0 = pure (Left (StoreSecondWriter ("cannot take ownership of " ++ dbPath ++ ": lock contention")))
  | otherwise = do
      pid <- getProcessID
      eFd <- tryIOError (openFd lockPath WriteOnly
        defaultFileFlags { creat = Just 0o600, exclusive = True })
      case eFd of
        Right fd -> do
          _ <- tryIOError (fdWrite fd (show pid ++ "\n"))
          _ <- tryIOError (closeFd fd)
          pure (Right ())
        Left _ -> inspectLock dbPath lockPath pid attempts

-- | Diagnose an existing lock: same-process, live peer (both fail),
-- dead owner (take over), or unreadable (fail safe). Owner pids
-- compare as text, avoiding any orphan 'Read' instances.
inspectLock :: FilePath -> FilePath -> ProcessID -> Int -> IO (Either StoreError ())
inspectLock dbPath lockPath pid attempts = do
  eContent <- tryIOError (readFile lockPath)
  case eContent of
    Left _ -> pure (Left (StoreSecondWriter ("store is locked and the owner is unreadable: " ++ lockPath)))
    Right content -> case reads content of
      [(ownerN, _) :: (Int, String)] | show ownerN == show pid ->
        pure (Left (StoreSecondWriter ("store is already open in this process: " ++ dbPath)))
      [(ownerN, _) :: (Int, String)] -> do
        alive <- isPidAlive ownerN
        if alive
          then pure (Left (StoreSecondWriter ("store is already open by pid " ++ show ownerN ++ ": " ++ dbPath)))
          else do
            _ <- tryIOError (removeLink lockPath)
            takeOwnership dbPath lockPath (attempts - 1)
      _ -> pure (Left (StoreSecondWriter ("store is locked by an unknown owner: " ++ lockPath)))

-- | Pid liveness via @/proc@ (Linux-only, matching the supported
-- loader policy): no signal is ever sent.
isPidAlive :: Int -> IO Bool
isPidAlive pid = fileExist ("/proc/" ++ show pid)

-- | Release ownership best-effort (close path; errors ignored).
releaseQuiet :: FilePath -> IO ()
releaseQuiet lockPath = do
  _ <- tryIOError (removeLink lockPath)
  pure ()

-- ---------------------------------------------------------------------------
-- Init and verify
-- ---------------------------------------------------------------------------

-- | Open the database file, configure it, and initialize or verify
-- the schema. Every sync failure is reported as 'Left'; the caller
-- releases ownership on 'Left'.
openAndInit :: FilePath -> IO (Either StoreError S.Database)
openAndInit path = do
  eFresh <- isFreshFile path
  case eFresh of
    Left err -> pure (Left err)
    Right fresh -> do
      eDb <- trySQLite (S.open (T.pack path))
      case eDb of
        Left err -> pure (Left err)
        Right db -> do
          eCfg <- configure db
          case eCfg of
            Left err -> closeQuiet db >> pure (Left err)
            Right ()
              | fresh -> initSchema db path
              | otherwise -> verifyExisting db path

-- | A path is fresh when it is missing or a zero-byte file.
isFreshFile :: FilePath -> IO (Either StoreError Bool)
isFreshFile path = do
  eExists <- tryStoreIO (fileExist path)
  case eExists of
    Left e -> pure (Left e)
    Right False -> pure (Right True)
    Right True -> do
      eSt <- tryStoreIO (getFileStatus path)
      case eSt of
        Left e -> pure (Left e)
        Right st -> pure (Right (fileSize st == 0))

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
      , "PRAGMA synchronous = FULL"
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
      | T.toLower mode == "delete" && n == 2 && fk == 1 -> pure (Right ())
      | otherwise -> pure (Left (StoreIO ("sqlite pragmas not honored: journal=" ++ show mode ++ " sync=" ++ show n ++ " fk=" ++ show fk)))
    (Left err, _, _) -> pure (Left err)
    (_, Left err, _) -> pure (Left err)
    (_, _, Left err) -> pure (Left err)
    _ -> pure (Left (StoreIO "sqlite pragmas returned unexpected rows"))

-- | Transactionally initialize a fresh database from the schema.
-- On failure the partial file is removed (best effort) so a retry
-- sees a fresh path, never a half-schema.
initSchema :: S.Database -> FilePath -> IO (Either StoreError S.Database)
initSchema db path = do
  eBegin <- trySQLite (S.exec db "BEGIN IMMEDIATE")
  case eBegin of
    Left err -> closeQuiet db >> pure (Left err)
    Right () -> do
      eBody <- trySQLite (mapM_ (S.exec db) schemaStatements)
      case eBody of
        Left err -> do
          _ <- trySQLite (S.exec db "ROLLBACK")
          closeQuiet db
          _ <- tryIOError (removeLink path)
          pure (Left (StoreIO ("schema init failed: " ++ show err)))
        Right () -> do
          eCommit <- trySQLite (S.exec db "COMMIT")
          case eCommit of
            Left err -> do
              _ <- trySQLite (S.exec db "ROLLBACK")
              closeQuiet db
              _ <- tryIOError (removeLink path)
              pure (Left (StoreIO ("schema init commit failed: " ++ show err)))
            Right () -> do
              _ <- tryIOError (setFileMode path 0o600)
              pure (Right db)

-- | Verify an existing database: all four tables present and the
-- schema version exactly ours. Anything else closes the handle and
-- fails WITHOUT writing a single byte.
verifyExisting :: S.Database -> FilePath -> IO (Either StoreError S.Database)
verifyExisting db path = do
  eTables <- queryRows db "SELECT name FROM sqlite_master WHERE type = 'table'" []
  case eTables of
    Left err -> closeQuiet db >> pure (Left err)
    Right rows -> do
      let names = [t | [S.SQLText t] <- rows]
          want = ["store_meta", "tokens", "objects", "detached_jobs"]
      if all (`elem` names) want
        then checkVersion db path
        else closeQuiet db >> pure (Left (StoreIO (path ++ ": not a haskoki store (missing tables)")))

-- | Check the integer schema version (exactly ours; wrong\/future
-- versions are rejected, never migrated silently — explicit
-- migrations arrive with a future format bump).
checkVersion :: S.Database -> FilePath -> IO (Either StoreError S.Database)
checkVersion db path = do
  eVer <- queryRows db "SELECT value FROM store_meta WHERE key = 'schema_version'" []
  case eVer of
    Left err -> closeQuiet db >> pure (Left err)
    Right [[S.SQLText v]]
      | v == T.pack (show sqliteSchemaVersion) -> pure (Right db)
      | otherwise -> closeQuiet db >> pure
          (Left (StoreSchemaVersion sqliteSchemaVersion (T.unpack v)))
    Right _ -> closeQuiet db >> pure (Left (StoreCorrupt (path ++ ": corrupt store metadata")))

-- | The schema (mirrors @spec\/storage-schema.sql@).
schemaStatements :: [Text]
schemaStatements =
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

-- ---------------------------------------------------------------------------
-- Store operations
-- ---------------------------------------------------------------------------

-- | Build the 'Store' record over an open connection.
mkStore :: SQLiteConn -> Store
mkStore conn = Store
  { storeLoadTokens = withConn conn loadTokens
  , storeLoadJobs = withConn conn loadJobs
  , storeCommit = protocolDelta conn
  , storeResetToken = resetTokenConn conn
  , storeClose = closeConn conn
  , storeInspect = withConn conn inspectConn
  , storeQuarantined = readMVar (sqQuarantine conn)
  , storeReload = reloadConn conn
  , storeStats = readIORef (sqStats conn)
  }

-- | Run one connection use under the guard lock (async-safe
-- take\/release pairing).
withConn :: SQLiteConn -> (S.Database -> IO a) -> IO a
withConn conn f =
  bracket_ (takeMVar (sqLock conn)) (putMVar (sqLock conn) ()) (f (sqDb conn))

-- | Idempotent close: the database handle closes and the lock file
-- is removed exactly once; later closes are silent no-ops.
closeConn :: SQLiteConn -> IO ()
closeConn conn = mask_ $ do
  already <- takeMVar (sqClosed conn)
  if already
    then putMVar (sqClosed conn) True
    else do
      _ <- trySQLite (S.close (sqDb conn))
      releaseQuiet (sqLockPath conn)
      putMVar (sqClosed conn) True

-- | The commit protocol: quarantine refusal, pre-commit
-- validation (limits, expected revisions), pre-commit fault
-- rollback, then the masked durable section (one @BEGIN IMMEDIATE@
-- transaction, ambiguous verification, post-commit quarantine).
-- The whole flow holds the connection guard, so one commit runs
-- at a time per handle.
protocolDelta :: SQLiteConn -> StoreDelta -> IO CommitResult
protocolDelta conn delta = withConn conn (\db -> protocolLocked conn db delta)

-- | Token reset: the expected generation must match the current
-- one, then the replacement plus the removal of every owned
-- object and job run as one ordinary protocol flow (quarantine,
-- validation, faults, masking all apply).
resetTokenConn :: SQLiteConn -> TokenId -> Generation -> TokenRecord -> IO CommitResult
resetTokenConn conn tid wantGen replacement = withConn conn $ \db -> do
  eEff <- resetEffectiveDb db tid wantGen replacement
  case eEff of
    Left err -> pure (NotCommitted err)
    Right eff -> protocolLocked conn db eff

-- | Build the reset's effective delta from one consistent read
-- (runs under the connection guard, so the generation check is
-- exact). Owned objects and jobs are dropped explicitly (the
-- foreign-key cascades backstop the same outcome).
resetEffectiveDb :: S.Database -> TokenId -> Generation -> TokenRecord -> IO (Either StoreError StoreDelta)
resetEffectiveDb db tid wantGen replacement = do
  eToks <- queryRows db "SELECT record_json FROM tokens WHERE token_id = ?"
    [S.SQLText (T.pack (encodeHex16 (unTokenId tid)))]
  case eToks of
    Left err -> pure (Left err)
    Right [] -> pure (Left (StoreRevisionConflict ("reset of missing token " ++ show tid)))
    Right [[S.SQLText doc]] -> case decodeTokenRecord (T.unpack doc) of
      Nothing -> pure (Left (StoreCorrupt "corrupt token record on reset"))
      Just cur
        | trId replacement /= tid ->
            pure (Left (StoreRevisionConflict "reset replacement names a different token"))
        | trGeneration cur /= wantGen ->
            pure (Left (StoreRevisionConflict ("reset expected generation " ++ show wantGen
              ++ " but token " ++ show tid ++ " is at " ++ show (trGeneration cur))))
        | otherwise -> do
            eObjs <- queryRows db "SELECT object_id FROM objects WHERE token_id = ?"
              [S.SQLText (T.pack (encodeHex16 (unTokenId tid)))]
            eJobs <- queryRows db "SELECT persistent_id_key FROM detached_jobs WHERE token_id = ?"
              [S.SQLText (T.pack (encodeHex16 (unTokenId tid)))]
            case (eObjs, eJobs) of
              (Right orows, Right jrows) ->
                case (mapM parseOid orows, mapM parsePid jrows) of
                  (Just oids, Just pids) -> pure (Right StoreDelta
                    { sdPutTokens = [replacement]
                    , sdDropTokens = []
                    , sdPutObjects = []
                    , sdDropObjects = oids
                    , sdPutJobs = []
                    , sdDropJobs = pids
                    })
                  _ -> pure (Left (StoreCorrupt "corrupt reset ownership rows"))
              (Left err, _) -> pure (Left err)
              (_, Left err) -> pure (Left err)
    Right _ -> pure (Left (StoreCorrupt "corrupt token row on reset"))
  where
    parseOid [S.SQLText oidT] = ObjectId <$> decodeHex16 (T.unpack oidT)
    parseOid _ = Nothing
    parsePid [S.SQLBlob b] = decodeBlobW64 b
    parsePid _ = Nothing

-- | The commit flow with the connection guard already held.
protocolLocked :: SQLiteConn -> S.Database -> StoreDelta -> IO CommitResult
protocolLocked conn db delta = do
  let inj = sqInjector conn
      qVar = sqQuarantine conn
      sVar = sqStats conn
  eAffected <- tokensForDelta db delta
  case eAffected of
    Left err -> pure (NotCommitted err)
    Right affected -> do
      q <- readMVar qVar
      case firstQuarantined q affected of
        Just (tid, why) -> pure (NotCommitted (StoreQuarantined tid why))
        Nothing -> do
          eValid <- validateDelta db (sqLimits conn) delta
          case eValid of
            Left err -> pure (NotCommitted err)
            Right () -> do
              preFailed <- fiFire inj FaultBeforeCommit
              if preFailed
                then pure (NotCommitted (StoreIO "injected pre-commit failure"))
                else mask_ $ do
                  fiOnMasked inj
                  fullDisk <- fiFire inj FaultFullDisk
                  eTxn <-
                    if fullDisk
                      then pure (Left (StoreFull "disk full (injected)"))
                      else runTxn delta
                  result <- case eTxn of
                    Left err -> pure (NotCommitted err)
                    Right () -> do
                      ambiguous <- fiFire inj FaultAmbiguousCommit
                      if ambiguous
                        then resolveAmbiguous inj qVar sVar delta affected
                        else do
                          bumpCommits sVar
                          postCommitTail inj qVar sVar affected
                  fiOnResult inj result
                  pure result
  where
    -- One transaction; any failure rolls back and reports.
    runTxn :: StoreDelta -> IO (Either StoreError ())
    runTxn d = do
      eBegin <- trySQLite (S.exec db "BEGIN IMMEDIATE")
      case eBegin of
        Left err -> pure (Left err)
        Right () -> do
          eBody <- runBody d
          case eBody of
            Left err -> do
              _ <- trySQLite (S.exec db "ROLLBACK")
              pure (Left err)
            Right () -> do
              eCommit <- trySQLite (S.exec db "COMMIT")
              case eCommit of
                Left err -> do
                  _ <- trySQLite (S.exec db "ROLLBACK")
                  pure (Left err)
                Right () -> pure (Right ())
    -- The observed outcome is discarded; a reload decides. Present
    -- verifies committed (every table), absent verifies rolled
    -- back, and a failed reload quarantines with 'CommitUnknown'.
    -- Nothing reissues.
    resolveAmbiguous
      :: FaultInjector -> MVar [(TokenId, String)] -> IORef StoreStats
      -> StoreDelta -> [TokenId] -> IO CommitResult
    resolveAmbiguous inj qVar sVar d affected = do
      bumpVerifyReloads sVar
      verifyFailed <- fiFire inj FaultVerifyReload
      if verifyFailed
        then do
          quarantineTokens qVar sVar affected "commit verification failed"
          pure (CommitUnknown (StoreIO "injected verification failure"))
        else do
          eLoaded <- loadTokens db
          eJobs <- loadJobs db
          case (eLoaded, eJobs) of
            (Right loaded, Right jobs)
              | reconcileReload d loaded == ReconciledPresent
              , reconcileJobsReload d jobs == ReconciledPresent -> do
                  bumpCommits sVar
                  postCommitTail inj qVar sVar affected
            (Right _, Right _) ->
              pure (NotCommitted (StoreIO "ambiguous commit resolved: delta absent"))
            (Left err, _) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
            (_, Left err) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
    -- After a confirmed commit, a post-commit failure quarantines
    -- the affected tokens; durable truth stays 'Committed'.
    postCommitTail
      :: FaultInjector -> MVar [(TokenId, String)] -> IORef StoreStats
      -> [TokenId] -> IO CommitResult
    postCommitTail inj qVar sVar affected = do
      postFailed <- fiFire inj FaultAfterCommit
      if postFailed
        then do
          quarantineTokens qVar sVar affected "post-commit failure"
          pure Committed
        else pure Committed
    -- Drops before puts; tokens before the objects and jobs that
    -- reference them (foreign keys stay satisfied throughout).
    runBody :: StoreDelta -> IO (Either StoreError ())
    runBody d = do
      e1 <- runAll (map dropObjectStmt (sdDropObjects d))
      e2 <- runAll (map dropJobStmt (sdDropJobs d))
      e3 <- runAll (map dropTokenStmt (sdDropTokens d))
      e4 <- runAll (map putTokenStmt (sdPutTokens d))
      e5 <- runAll (map putObjectStmt (sdPutObjects d))
      e6 <- runAll (map putJobStmt (sdPutJobs d))
      pure (e1 >> e2 >> e3 >> e4 >> e5 >> e6)
      where
        runAll :: [(Text, [S.SQLData])] -> IO (Either StoreError ())
        runAll [] = pure (Right ())
        runAll ((sql, params) : rest) = do
          e <- execParams db sql params
          case e of
            Left err -> pure (Left err)
            Right () -> runAll rest

-- | Tokens a delta touches: named tokens plus the home tokens of
-- named objects and jobs (drop owners resolved from current
-- state; unknown drops contribute nothing).
tokensForDelta :: S.Database -> StoreDelta -> IO (Either StoreError [TokenId])
tokensForDelta db delta = do
  eOwners <- mapM ownerOf (sdDropObjects delta)
  eJobOwners <- mapM jobOwnerOf (sdDropJobs delta)
  pure (sequence eOwners >>= \owners -> sequence eJobOwners >>= \jobOwners ->
    Right (nub (explicit ++ [t | Just t <- owners] ++ [t | Just t <- jobOwners])))
  where
    explicit =
      map trId (sdPutTokens delta)
        ++ sdDropTokens delta
        ++ map (orToken . opRecord) (sdPutObjects delta)
        ++ map jrToken (sdPutJobs delta)
    -- Drops of unknown objects stay silent no-ops;
    -- only genuine query failures refuse the commit.
    ownerOf :: ObjectId -> IO (Either StoreError (Maybe TokenId))
    ownerOf (ObjectId n) = do
      eRows <- queryRows db "SELECT token_id FROM objects WHERE object_id = ?"
        [S.SQLText (T.pack (encodeHex16 n))]
      case eRows of
        Left err -> pure (Left err)
        Right [] -> pure (Right Nothing)
        Right [[S.SQLText tid]] -> case decodeHex16 (T.unpack tid) of
          Just t -> pure (Right (Just (TokenId t)))
          Nothing -> pure (Left (StoreCorrupt "corrupt token_id on dropped object"))
        Right _ -> pure (Left (StoreCorrupt "corrupt drop-owner row shape"))
    jobOwnerOf :: Word64 -> IO (Either StoreError (Maybe TokenId))
    jobOwnerOf pid = do
      eRows <- queryRows db "SELECT token_id FROM detached_jobs WHERE persistent_id_key = ?"
        [S.SQLBlob (encodeBlobW64 pid)]
      case eRows of
        Left err -> pure (Left err)
        Right [] -> pure (Right Nothing)
        Right [[S.SQLText tid]] -> case decodeHex16 (T.unpack tid) of
          Just t -> pure (Right (Just (TokenId t)))
          Nothing -> pure (Left (StoreCorrupt "corrupt token_id on dropped job"))
        Right _ -> pure (Left (StoreCorrupt "corrupt job drop-owner row shape"))

-- | Pre-commit validation: limits against a decoded load, then
-- token references, slot uniqueness, then expected revisions
-- against the stored revision map. Runs under the connection
-- guard, so the validated state is the committed-against state.
validateDelta :: S.Database -> StoreLimits -> StoreDelta -> IO (Either StoreError ())
validateDelta db limits delta = do
  eLoaded <- loadTokens db
  eJobs <- loadJobs db
  case (eLoaded, eJobs) of
    (Left err, _) -> pure (Left err)
    (_, Left err) -> pure (Left err)
    (Right loaded, Right jobs) ->
      let state = LoadedState loaded jobs
          toks = [(trId t, t) | (t, _) <- loaded]
      in case checkLimits limits delta state of
        Just err -> pure (Left err)
        Nothing -> case checkTokenRefs toks delta of
          Just err -> pure (Left err)
          Nothing -> case checkSlotUnique toks delta of
            Just err -> pure (Left err)
            Nothing -> checkRevisionsDb db delta

-- | Enforce expected revisions from one revision-map scan,
-- reusing the shared pure guard.
checkRevisionsDb :: S.Database -> StoreDelta -> IO (Either StoreError ())
checkRevisionsDb db delta
  | null [() | ObjectPut (Just _) _ <- sdPutObjects delta] = pure (Right ())
  | otherwise = do
      eRows <- queryRows db "SELECT object_id, revision FROM objects" []
      case eRows of
        Left err -> pure (Left err)
        Right rows -> case mapM parseRev rows of
          Nothing -> pure (Left (StoreCorrupt "corrupt revision row"))
          Just pairs -> pure (maybe (Right ()) Left
            (checkExpectedRevisions (`Map.lookup` Map.fromList pairs) delta))
  where
    parseRev :: [S.SQLData] -> Maybe (ObjectId, Revision)
    parseRev [S.SQLText oidT, S.SQLInteger n] = do
      oid <- decodeHex16 (T.unpack oidT)
      rev <- decodeRevision n
      pure (ObjectId oid, Revision rev)
    parseRev _ = Nothing

-- | The first touched token that is quarantined, if any.
firstQuarantined :: [(TokenId, String)] -> [TokenId] -> Maybe (TokenId, String)
firstQuarantined q tids =
  listToMaybe [(tid, why) | tid <- tids, Just why <- [lookup tid q]]

-- | Quarantine tokens with a reason, counting one event per token.
quarantineTokens :: MVar [(TokenId, String)] -> IORef StoreStats -> [TokenId] -> String -> IO ()
quarantineTokens qVar sVar tids why = do
  modifyMVar_ qVar (\q -> pure (foldr insertOne q tids))
  bumpQuarantines sVar (length tids)
  where
    insertOne tid q = (tid, why) : filter ((/= tid) . fst) q

-- | Authoritative reload: a clean load clears the quarantine; a
-- failed load keeps it and reports the error. Reloads never
-- consult the fault script.
reloadConn :: SQLiteConn -> IO (Either StoreError ())
reloadConn conn = withConn conn $ \db -> do
  eLoaded <- loadTokens db
  case eLoaded of
    Left err -> pure (Left err)
    Right _ -> modifyMVar_ (sqQuarantine conn) (\_ -> pure []) >> pure (Right ())

-- | Load every token with its home objects, token-id ascending,
-- object-id ascending within each token.
loadTokens :: S.Database -> IO (Either StoreError [(TokenRecord, [ObjectRecord])])
loadTokens db = do
  eToks <- queryRows db "SELECT token_id, record_json FROM tokens ORDER BY token_id" []
  case eToks of
    Left err -> pure (Left err)
    Right rows -> do
      rs <- mapM loadOne rows
      pure (sequence rs)
  where
    loadOne :: [S.SQLData] -> IO (Either StoreError (TokenRecord, [ObjectRecord]))
    loadOne [S.SQLText tid, S.SQLText doc] = case decodeTokenRecord (T.unpack doc) of
      Nothing -> pure (Left (StoreCorrupt ("corrupt token record: " ++ T.unpack tid)))
      Just tok -> do
        eObjs <- queryRows db
          "SELECT object_id, token_id, class_key, key_type_key, attributes_json, material_encoding, material_blob, revision FROM objects WHERE token_id = ? ORDER BY object_id"
          [S.SQLText tid]
        case eObjs of
          Left err -> pure (Left err)
          Right orows -> pure (mapM decodeObjectRow orows >>= \objs -> Right (tok, objs))
    loadOne _ = pure (Left (StoreCorrupt "corrupt token row shape"))

-- | Decode one object row; every quantity range-checks (no blind
-- casts from the SQLite domain into 'Int').
decodeObjectRow :: [S.SQLData] -> Either StoreError ObjectRecord
decodeObjectRow [S.SQLText oidT, S.SQLText tidT, S.SQLBlob clsB, ktyD, S.SQLText attrT, S.SQLText mencT, matD, S.SQLInteger revN] = do
  oid <- note "object_id" (decodeHex16 (T.unpack oidT))
  tid <- note "token_id" (decodeHex16 (T.unpack tidT))
  cls <- note "class_key" (decodeBlobW64 clsB)
  kty <- case ktyD of
    S.SQLNull -> Right Nothing
    S.SQLBlob b -> Just <$> note "key_type_key" (decodeBlobW64 b)
    _ -> Left (StoreCorrupt "corrupt key_type_key shape")
  attrs <- note "attributes_json" (decodeAttrsDoc (T.unpack attrT))
  let menc = T.unpack mencT
  _ <- if menc `elem` knownMaterialEncodings
    then Right ()
    else Left (StoreCorrupt ("corrupt object record: unknown material encoding " ++ menc))
  mat <- case matD of
    S.SQLNull -> Right Nothing
    S.SQLBlob b -> Right (Just b)
    _ -> Left (StoreCorrupt "corrupt material_blob shape")
  rev <- note "revision" (decodeRevision revN)
  Right ObjectRecord
    { orId = ObjectId oid
    , orToken = TokenId tid
    , orClass = cls
    , orKeyType = kty
    , orAttrs = attrs
    , orMaterialEncoding = menc
    , orMaterial = mat
    , orRevision = Revision rev
    }
decodeObjectRow _ = Left (StoreCorrupt "corrupt object row shape")

-- | Tag a 'Maybe' decode with its column for the diagnosis.
note :: String -> Maybe a -> Either StoreError a
note col = maybe (Left (StoreCorrupt ("corrupt object record: bad " ++ col))) Right

-- | Load every detached job, persistent-id ascending. The full
-- document decodes the record; the key columns cross-check it.
loadJobs :: S.Database -> IO (Either StoreError [JobRecord])
loadJobs db = do
  eRows <- queryRows db
    "SELECT persistent_id_key, token_id, token_generation_key, function_name, execution_state, record_json FROM detached_jobs ORDER BY persistent_id_key" []
  case eRows of
    Left err -> pure (Left err)
    Right rows -> pure (mapM decodeJobRow rows)

-- | Decode one job row: the document first, then the redundant
-- key columns must agree with it (any mismatch is corruption).
decodeJobRow :: [S.SQLData] -> Either StoreError JobRecord
decodeJobRow [S.SQLBlob pidB, S.SQLText tidT, S.SQLBlob genB, S.SQLText funT, S.SQLText stT, S.SQLText doc] = do
  pid <- noteJob "persistent_id_key" (decodeBlobW64 pidB)
  tid <- noteJob "token_id" (decodeHex16 (T.unpack tidT))
  gen <- noteJob "token_generation_key" (decodeBlob8 genB)
  rec <- noteJob "record_json" (decodeJobRecord (T.unpack doc))
  _ <- if jrPersistentId rec == pid
    then Right ()
    else Left (StoreCorrupt "corrupt job record: key/doc id mismatch")
  _ <- if jrToken rec == TokenId tid
    then Right ()
    else Left (StoreCorrupt "corrupt job record: key/doc token mismatch")
  _ <- if jrTokenGeneration rec == Generation gen
    then Right ()
    else Left (StoreCorrupt "corrupt job record: key/doc generation mismatch")
  _ <- if jrFunction rec == T.unpack funT
    then Right ()
    else Left (StoreCorrupt "corrupt job record: key/doc function mismatch")
  _ <- if execStateName (jrState rec) == T.unpack stT
    then Right ()
    else Left (StoreCorrupt "corrupt job record: key/doc state mismatch")
  Right rec
decodeJobRow _ = Left (StoreCorrupt "corrupt job row shape")

-- | Tag a 'Maybe' job decode with its column.
noteJob :: String -> Maybe a -> Either StoreError a
noteJob col = maybe (Left (StoreCorrupt ("corrupt job record: bad " ++ col))) Right

-- | Render every stored record through its canonical bytes (load,
-- then re-encode, so inspection always shows canonical form).
inspectConn :: S.Database -> IO [StoredDoc]
inspectConn db = do
  eLoaded <- loadTokens db
  eJobs <- loadJobs db
  case (eLoaded, eJobs) of
    (Right toks, Right jobs) -> pure $
      [ StoredDoc "tokens" (show (unTokenId (trId t))) (encodeTokenRecord t)
      | (t, _) <- toks
      ]
      ++
      [ StoredDoc "objects" (show (unObjectId (orId o))) (encodeObjectRecord o)
      | (_, objs) <- toks, o <- objs
      ]
      ++
      [ StoredDoc "detached_jobs" (encodeHexWord64 (jrPersistentId j)) (encodeJobRecord j)
      | j <- jobs
      ]
    _ -> pure []

-- ---------------------------------------------------------------------------
-- Statements
-- ---------------------------------------------------------------------------

-- | DELETE one object by id.
dropObjectStmt :: ObjectId -> (Text, [S.SQLData])
dropObjectStmt (ObjectId n) =
  ("DELETE FROM objects WHERE object_id = ?", [S.SQLText (T.pack (encodeHex16 n))])

-- | DELETE one token by id (objects cascade).
dropTokenStmt :: TokenId -> (Text, [S.SQLData])
dropTokenStmt (TokenId n) =
  ("DELETE FROM tokens WHERE token_id = ?", [S.SQLText (T.pack (encodeHex16 n))])

-- | DELETE one job by persistent id.
dropJobStmt :: Word64 -> (Text, [S.SQLData])
dropJobStmt pid =
  ("DELETE FROM detached_jobs WHERE persistent_id_key = ?", [S.SQLBlob (encodeBlobW64 pid)])

-- | Upsert one job row (full document plus redundant key columns).
putJobStmt :: JobRecord -> (Text, [S.SQLData])
putJobStmt j =
  ( "INSERT OR REPLACE INTO detached_jobs (persistent_id_key, token_id, token_generation_key, function_name, execution_state, record_json, format_version) VALUES (?, ?, ?, ?, ?, ?, 1)"
  , [ S.SQLBlob (encodeBlobW64 (jrPersistentId j))
    , S.SQLText (T.pack (encodeHex16 (unTokenId (jrToken j))))
    , S.SQLBlob (encodeBlob8 (unGeneration (jrTokenGeneration j)))
    , S.SQLText (T.pack (jrFunction j))
    , S.SQLText (T.pack (execStateName (jrState j)))
    , S.SQLText (T.pack (encodeJobRecord j))
    ]
  )

-- | Upsert one token row.
putTokenStmt :: TokenRecord -> (Text, [S.SQLData])
putTokenStmt t =
  ( "INSERT OR REPLACE INTO tokens (token_id, slot_key, generation_key, record_json, format_version) VALUES (?, ?, ?, ?, 1)"
  , [ S.SQLText (T.pack (encodeHex16 (unTokenId (trId t))))
    , S.SQLBlob (encodeBlob8 (unSlotId (trSlot t)))
    , S.SQLBlob (encodeBlob8 (unGeneration (trGeneration t)))
    , S.SQLText (T.pack (encodeTokenRecord t))
    ]
  )

-- | Upsert one object row.
putObjectStmt :: ObjectPut -> (Text, [S.SQLData])
putObjectStmt p =
  let o = opRecord p
  in ( "INSERT OR REPLACE INTO objects (object_id, token_id, class_key, key_type_key, attributes_json, material_encoding, material_blob, revision, format_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)"
     , [ S.SQLText (T.pack (encodeHex16 (unObjectId (orId o))))
       , S.SQLText (T.pack (encodeHex16 (unTokenId (orToken o))))
       , S.SQLBlob (encodeBlobW64 (orClass o))
       , maybe S.SQLNull (S.SQLBlob . encodeBlobW64) (orKeyType o)
       , S.SQLText (T.pack (encodeAttrsDoc (orAttrs o)))
       , S.SQLText (T.pack (orMaterialEncoding o))
       , maybe S.SQLNull S.SQLBlob (orMaterial o)
       , S.SQLInteger (fromIntegral (unRevision (orRevision o)))
       ]
     )

-- ---------------------------------------------------------------------------
-- SQL helpers
-- ---------------------------------------------------------------------------

-- | Run a parameterized statement expecting no result rows.
execParams :: S.Database -> Text -> [S.SQLData] -> IO (Either StoreError ())
execParams db sql params = trySQLite $ bracket (S.prepare db sql) S.finalize $ \stmt -> do
  S.bind stmt params
  _ <- S.step stmt
  pure ()

-- | Run a parameterized query, collecting every row.
queryRows :: S.Database -> Text -> [S.SQLData] -> IO (Either StoreError [[S.SQLData]])
queryRows db sql params = trySQLite $ bracket (S.prepare db sql) S.finalize $ \stmt -> do
  S.bind stmt params
  collect stmt
  where
    collect :: S.Statement -> IO [[S.SQLData]]
    collect stmt = do
      r <- S.step stmt
      case r of
        S.Done -> pure []
        S.Row -> do
          row <- S.columns stmt
          rest <- collect stmt
          pure (row : rest)

-- | Run a SQLite action, converting 'S.SQLError' to 'StoreIO'
-- ('StoreFull' for a real SQLITE_FULL). Async exceptions do not
-- match 'S.SQLError' and propagate.
trySQLite :: forall a. IO a -> IO (Either StoreError a)
trySQLite act = do
  e <- try act
  pure (either (Left . toStore) Right (e :: Either S.SQLError a))
  where
    toStore :: S.SQLError -> StoreError
    toStore err
      | S.sqlError err == S.ErrorFull = StoreFull (show err)
      | otherwise = StoreIO (show err)

-- | Run a filesystem action, converting 'IOError' to 'StoreIO'.
tryStoreIO :: IO a -> IO (Either StoreError a)
tryStoreIO act = do
  e <- tryIOError act
  pure (either (Left . StoreIO . show) Right e)

-- | Close a handle best-effort (failure paths; errors ignored).
closeQuiet :: S.Database -> IO ()
closeQuiet db = do
  _ <- trySQLite (S.close db)
  pure ()

-- ---------------------------------------------------------------------------
-- Stats
-- ---------------------------------------------------------------------------

bumpCommits :: IORef StoreStats -> IO ()
bumpCommits v = atomicModifyIORef' v (\s -> (s { ssCommits = ssCommits s + 1 }, ()))

bumpVerifyReloads :: IORef StoreStats -> IO ()
bumpVerifyReloads v = atomicModifyIORef' v (\s -> (s { ssVerifyReloads = ssVerifyReloads s + 1 }, ()))

bumpQuarantines :: IORef StoreStats -> Int -> IO ()
bumpQuarantines v n = atomicModifyIORef' v (\s -> (s { ssQuarantines = ssQuarantines s + n }, ()))

-- ---------------------------------------------------------------------------
-- Full-width codecs (SQLite domain)
-- ---------------------------------------------------------------------------

-- | Encode a non-negative 'Int' as an 8-byte big-endian blob.
encodeBlob8 :: Int -> ByteString
encodeBlob8 n = BS.pack
  [ fromIntegral ((w `shiftR` s) .&. 0xFF) | s <- [56, 48 .. 0] ]
  where
    w :: Word64
    w = fromIntegral n

-- | Decode an 8-byte big-endian blob into a non-negative 'Int';
-- wrong lengths and out-of-range values fail.
decodeBlob8 :: ByteString -> Maybe Int
decodeBlob8 bs
  | BS.length bs /= 8 = Nothing
  | w > fromIntegral (maxBound :: Int) = Nothing
  | otherwise = Just (fromIntegral w)
  where
    w :: Word64
    w = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 bs

-- | Decode a bounded revision counter; rejects non-positive and
-- out-of-range values (never a blind cast).
decodeRevision :: Int64 -> Maybe Int
decodeRevision n
  | n >= 1 && n <= fromIntegral (maxBound :: Int) = Just (fromIntegral n)
  | otherwise = Nothing

-- | Encode a 'Word64' persistent id as an 8-byte big-endian blob
-- (the whole domain, no narrowing).
encodeBlobW64 :: Word64 -> ByteString
encodeBlobW64 w = BS.pack
  [ fromIntegral ((w `shiftR` s) .&. 0xFF) | s <- [56, 48 .. 0] ]

-- | Decode an 8-byte big-endian blob into a 'Word64'; wrong
-- lengths fail.
decodeBlobW64 :: ByteString -> Maybe Word64
decodeBlobW64 bs
  | BS.length bs /= 8 = Nothing
  | otherwise = Just (BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 bs)

-- Identifier projections ('unTokenId' et al.) come from 'Haskoki.Types'.
