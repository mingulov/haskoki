{- | SQLite store owned single-writer migration.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Migrate
  ( OwnedStoreFile (..)
  , ownedPath
  , SQLiteMigration (..)
  , MigrationHooks (..)
  , noMigrationHooks
  , withOwnedStoreFile
  , withOwnedStoreFileKeep
  , withOwnedRelease
  , ownedDbMatches
  , clearColdJournalOwned
  , syncParentDir
  , MigrateTxnError (..)
  , migrateOwned
  ) where

import Control.Exception (bracket, mask, onException, try)
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import Database.SQLite3.Direct (getAutoCommit)
import System.IO.Error (isDoesNotExistError, tryIOError)
import System.Posix.Files (isRegularFile, removeLink)
import System.Posix.IO (OpenMode (..), closeFd, openFd)
import System.Posix.Types (Fd)
import System.Posix.Unistd (fileSynchronise)
import Haskoki.Runtime.Storage
  ( CredentialRecord (..)
  , StoreError (..)
  , encodeCredentialRecord
  , encodeHex16
  )
import Haskoki.Types (TokenId (..))
import Haskoki.Runtime.Storage.SQLite.Conn
import Haskoki.Runtime.Storage.SQLite.Init
import Haskoki.Runtime.Storage.SQLite.Ownership
import Haskoki.Runtime.Storage.SQLite.Records
import Haskoki.Runtime.Storage.SQLite.Snapshot
import Haskoki.Runtime.Storage.SQLite.Statements
import Haskoki.Runtime.Storage.SQLite.Types

-- ---------------------------------------------------------------------------
-- Owned migration
-- ---------------------------------------------------------------------------
-- | An existing store held with full single-writer ownership: the
-- sidecar lock plus the database kernel guard, exactly as the
-- serving open takes them, without opening the serving store.
data OwnedStoreFile = OwnedStoreFile { osfPath :: !FilePath, osfDbFd :: !Fd }

ownedPath :: OwnedStoreFile -> FilePath
ownedPath = osfPath

-- | What a migration does. 'smFrom' is the schema version the plan
-- saw (1, 2 or 3; 3 only freezes rows and leaves the marker alone).
data SQLiteMigration = SQLiteMigration
  { smFrom :: !Int
  , smFreeze :: ![CredentialRecord]
  } deriving (Eq, Show)

-- | Test seams: right after BEGIN IMMEDIATE, and after the body but
-- before COMMIT.
data MigrationHooks = MigrationHooks
  { mgAfterBegin :: S.Database -> IO ()
  , mgBeforeCommit :: S.Database -> IO ()
  }

noMigrationHooks :: MigrationHooks
noMigrationHooks = MigrationHooks (\_ -> pure ()) (\_ -> pure ())

-- | Hold full single-writer ownership of an EXISTING store, run the
-- action, and release on every path. Never creates the database; a
-- live owner is refused ('StoreSecondWriter'). The sidecar is the
-- only file created, and it is removed on release.
withOwnedStoreFile :: Bool -> FilePath -> (OwnedStoreFile -> IO a) -> IO (Either StoreError a)
withOwnedStoreFile allowEnv = withOwnedRelease allowEnv True

-- | Like 'withOwnedStoreFile', but the post-body release only closes
-- the sidecar descriptor and never unlinks the sidecar: the body
-- owns sidecar removal instead. Releases before the body runs still
-- remove a sidecar this call created or took over. Used by reset,
-- where a failed database removal must leave the sidecar in place.
withOwnedStoreFileKeep :: Bool -> FilePath -> (OwnedStoreFile -> IO a) -> IO (Either StoreError a)
withOwnedStoreFileKeep allowEnv = withOwnedRelease allowEnv False

-- | 'True' unlinks our sidecar on the post-body release (the body
-- may already have done so); 'False' only closes it. 'allowEnv' gates
-- the liveness seam (default-off): without it the takeOwnership
-- probe below reads the real @\/proc@ however the environment is set.
-- This path never pauses: the fresh-init pause lives on the create
-- path only, so check\/migrate ownership checks consult liveness and
-- nothing else.
withOwnedRelease :: Bool -> Bool -> FilePath -> (OwnedStoreFile -> IO a) -> IO (Either StoreError a)
withOwnedRelease allowEnv unlinkOnRelease path act = mask $ \restore -> do
  eSt <- lstatOpt path
  case eSt of
    Right Nothing -> pure (Left (StoreIO ("no store file at " ++ path)))
    Right (Just st) | not (isRegularFile st) ->
      pure (Left (StoreIO ("not a regular file: " ++ path)))
    Left e -> pure (Left (StoreIO ("store database cannot be examined: " ++ path ++ ": " ++ e)))
    Right _ -> do
      procRoot <- procRootFromEnv allowEnv
      let lockPath = path ++ ".lock"
      eOwn <- takeOwnership path lockPath procRoot 3
      case eOwn of
        Left err -> pure (Left err)
        Right lockFd -> do
          eFd <- tryIOError (openFd path ReadOnly guardFlags)
            `onException` releaseQuiet lockFd lockPath
          case eFd of
            Left e
              | isDoesNotExistError e -> releaseQuiet lockFd lockPath
                  >> pure (Left (StoreIO ("store vanished while taking ownership: " ++ path)))
              | otherwise -> releaseQuiet lockFd lockPath
                  >> pure (Left (StoreIO ("store database cannot be opened: " ++ path)))
            Right fd0 -> do
              eGuard <- takeDbGuard path fd0 `onException` releaseQuiet lockFd lockPath
              case eGuard of
                Left err -> releaseQuiet lockFd lockPath >> pure (Left err)
                Right dbFd -> do
                  let releaseBody
                        | unlinkOnRelease = closeQuietFd dbFd >> releaseQuiet lockFd lockPath
                        | otherwise = closeQuietFd dbFd >> closeQuietFd lockFd
                  r <- restore (act (OwnedStoreFile path dbFd)) `onException` releaseBody
                  releaseBody
                  pure (Right r)

-- | True when the store path still names the guarded database
-- inode: a removal must only unlink what the guard holds.
ownedDbMatches :: OwnedStoreFile -> IO Bool
ownedDbMatches o = sameFile (osfDbFd o) (osfPath o)

-- | Remove a cold rollback journal inside the caller's ownership
-- window (the sidecar plus the database kernel guard are already
-- held), only when every guard holds: no @-wal@ or @-shm@ sibling
-- exists (even zero-byte: the read-write connection below would act
-- on it), a plain connection takes a SQLite RESERVED lock
-- (@BEGIN IMMEDIATE@ fails while any other connection writes), and
-- the re-read journal is still cold. Removing it cannot change what
-- SQLite reads: the zeroed magic already makes SQLite treat the
-- journal as not hot. @onClear@ fires once the journal was
-- unlinked or was classified as absent on recheck (missing,
-- empty, or unstatable -- a failed stat counts as absent; a
-- non-regular file, or a failed header read on a nonempty
-- regular file, counts as unknown and refuses). A journal that vanished between the plan and the clear
-- counts as already cleared (fires, succeeds). Anything else
-- refuses, fail closed -- usually with the journal still in place,
-- except that SQLite recovery during @BEGIN IMMEDIATE@ rolls back
-- a hot journal that appeared after the owned snapshot, rewriting
-- database pages (before any backup is made), and except a sync or
-- commit failure after the unlink, which already fired.
clearColdJournalOwned :: IO () -> FilePath -> IO (Either StoreError ())
clearColdJournalOwned onClear path = do
  side <- anySidecarExists path
  case side of
    Just p -> pure (Left (StoreForeignSidecar p))
    Nothing -> do
      eDb <- trySQLite (S.open (T.pack path))
      case eDb of
        Left err -> pure (Left err)
        Right db -> do
          r <- clearWith db `onException` (rollbackQuiet db >> closeQuiet db)
          closeQuiet db
          pure r
  where
    journal = path ++ "-journal"
    clearWith db = do
      eBegin <- tryBegin db
      case eBegin of
        Left err
          | S.sqlError err == S.ErrorBusy -> pure (Left (StoreJournalCold journal))
          | S.sqlError err == S.ErrorFull -> pure (Left (StoreFull (show err)))
          | otherwise -> pure (Left (StoreIO (show err)))
        Right () -> do
          cls <- classifyJournal path
          case cls of
            JournalCold -> do
              eRm <- tryIOError (removeLink journal)
              case eRm of
                Left e
                  | isDoesNotExistError e -> do
                      onClear
                      rollbackQuiet db
                      pure (Right ())
                  | otherwise -> do
                      rollbackQuiet db
                      pure (Left (StoreIO ("cannot remove the cold journal " ++ journal ++ ": " ++ show e)))
                Right () -> do
                  onClear
                  eSync <- tryIOError (syncParentDir journal)
                  eCommit <- trySQLite (S.exec db "COMMIT")
                  pure (case (eCommit, eSync) of
                    (Left err, _) -> Left err
                    (Right (), Left e) -> Left (StoreIO ("cannot sync the store directory: " ++ show e))
                    (Right (), Right ()) -> Right ())
            JournalAbsent -> do
              onClear
              rollbackQuiet db
              pure (Right ())
            _ -> do
              rollbackQuiet db
              pure (Left (StoreJournalPresent journal))
    tryBegin :: S.Database -> IO (Either S.SQLError ())
    tryBegin db = try (S.exec db "BEGIN IMMEDIATE")

-- | fsync the directory holding a path, so an unlink in it is durable.
syncParentDir :: FilePath -> IO ()
syncParentDir p = bracket (openFd (parentDir p) ReadOnly guardFlags) closeFd fileSynchronise
  where
    parentDir q = case dropWhile (/= '/') (reverse q) of
      [] -> "."
      [_] -> "/"
      (_ : rest) -> reverse rest

-- | How a migration transaction failed: setup, begin, or body
-- failed before committing (a body failure attempts a rollback,
-- best effort with errors discarded; setup failures never begin
-- a transaction), or a COMMIT failure with an open transaction
-- attempted a rollback and classified as rolled-back only when
-- the rollback succeeded, autocommit is restored, and the
-- journal reads absent — or the COMMIT failed with an unknown
-- outcome (already-ended transactions go directly to unknown;
-- the store may already be at the new schema; the operator must
-- run @store check@ before retrying). The rolled-back
-- classification cannot certify unchanged bytes: an unstatable
-- journal reads absent without excluding foreign residue.
-- Preflight renders the two cases separately.
data MigrateTxnError
  = MigrateTxnUnchanged !StoreError
  | MigrateTxnCommitUnknown !StoreError
  deriving (Eq, Show)

-- | Migrate an owned store to 'sqliteSchemaVersion' in ONE
-- transaction: re-read the marker (it must still be 'smFrom'),
-- create the credentials table for version 1, INSERT every frozen
-- row (never replacing: an existing row aborts everything), and
-- advance the marker unless the store is already current. A body
-- failure attempts a rollback (best effort: rollback errors are
-- discarded, so page effects may remain); a COMMIT failure with
-- an open transaction attempts a rollback, and classifies as
-- rolled-back only when the rollback succeeds, autocommit is
-- restored, and the journal reads absent — any other COMMIT
-- outcome is unknown, reported distinctly, never as unchanged.
-- An exception attempts a rollback, closes and re-throws.
migrateOwned :: OwnedStoreFile -> SQLiteMigration -> MigrationHooks -> IO (Either MigrateTxnError ())
migrateOwned owned mig hooks = mask $ \restore -> do
  let path = osfPath owned
  same <- sameFile (osfDbFd owned) path
  if not same then pure (Left (MigrateTxnUnchanged (StoreIO ("store database replaced while owned: " ++ path)))) else do
    eDb <- trySQLite (S.open (T.pack path))
    case eDb of
      Left err -> pure (Left (MigrateTxnUnchanged err))
      Right db -> do
        r <- restore (txn db path) `onException` (rollbackQuiet db >> closeQuiet db)
        closeQuiet db
        pure r
  where
    txn db path = do
      eCfg <- configure db
      case eCfg of
        Left err -> pure (Left (MigrateTxnUnchanged err))
        Right () -> do
          eBegin <- trySQLite (S.exec db "BEGIN IMMEDIATE")
          case eBegin of
            Left err -> pure (Left (MigrateTxnUnchanged err))
            Right () -> do
              mgAfterBegin hooks db
              eBody <- body db path
              case eBody of
                Left err -> rollbackQuiet db >> pure (Left (MigrateTxnUnchanged err))
                Right () -> do
                  mgBeforeCommit hooks db
                  eCommit <- trySQLite (S.exec db "COMMIT")
                  case eCommit of
                    Left err -> commitFailed db path err
                    Right () -> pure (Right ())
    -- A failed COMMIT may have landed, rolled back, or left a hot
    -- journal: a still-active transaction that rolls back with
    -- autocommit restored and no journal classifies as
    -- rolled-back (an unstatable journal reads absent without
    -- certifying it). Anything else — including an
    -- already-ended transaction — is unknown and must not claim
    -- the store was unchanged.
    commitFailed db path err = do
      ended <- getAutoCommit db
      if ended
        then pure (Left (MigrateTxnCommitUnknown err))
        else do
          eRb <- trySQLite (S.exec db "ROLLBACK")
          endedNow <- getAutoCommit db
          cls <- classifyJournal path
          case (eRb, endedNow, cls) of
            (Right (), True, JournalAbsent) -> pure (Left (MigrateTxnUnchanged err))
            _ -> pure (Left (MigrateTxnCommitUnknown err))
    body db path = do
      eVer <- queryRows db "SELECT value FROM store_meta WHERE key = 'schema_version'" []
      case eVer of
        Left err -> pure (Left err)
        Right [[S.SQLText v]] | v == T.pack (show (smFrom mig)) -> firstFailure
          ( [trySQLite (S.exec db createCredentialsTable) | smFrom mig == 1]
            ++ map (insertCredential db) (smFreeze mig)
            ++ [advance db | smFrom mig /= sqliteSchemaVersion] )
        Right _ -> pure (Left (StoreRevisionConflict (path ++ ": schema marker moved under ownership")))
    insertCredential db c = execParams db
      "INSERT INTO credentials (token_id, record_json, format_version) VALUES (?, ?, 1)"
      [ S.SQLText (T.pack (encodeHex16 (unTokenId (crToken c))))
      , S.SQLText (T.pack (encodeCredentialRecord c)) ]
    advance db = do
      e <- execParams db "UPDATE store_meta SET value = ? WHERE key = 'schema_version' AND value = ?"
        [S.SQLText (T.pack (show sqliteSchemaVersion)), S.SQLText (T.pack (show (smFrom mig)))]
      n <- S.changes db
      pure (e >> if n == 1 then Right () else Left (StoreRevisionConflict "schema marker not advanced"))
