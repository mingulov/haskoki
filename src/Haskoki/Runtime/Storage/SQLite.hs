{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{- | SQLite store backend: one local file, single writer.

On 'openSQLiteStore' the backend takes single-writer ownership via
an O_EXCL sidecar lock file (@\<db\>.lock@) carrying the owner's
pid: the kernel flock is the authority — a stale lock with no
holder (the same pid, a live pid, an unknowable pid, an
unparsable pid, an empty file, or a dead pid from a crashed run)
is taken over without touching any data, and a held lock refuses
explicitly with 'StoreSecondWriter'. SQLite-level locking alone
would not keep two provider caches coherent, so the file lock —
not the database — is the ownership arbiter.

Ownership is fail-closed and kernel-backed: a truly unreadable
lock, and an unknowable @\/proc@ verdict with the kernel lock
held, refuse with 'StoreSecondWriter' rather than risk a state
fork, and every owner holds an exclusive non-blocking @flock(2)@
on a held-open lock fd for the lock's lifetime, so a live owner
still refuses takeovers. Exclusion is
anchored to the database identity as well as the sidecar (a second
held-open @flock(2)@, on the database file itself), so deleting
the lock path cannot fork a live owner via a replacement lock;
release unlinks only the owned lock inode.

An empty database initializes transactionally from the schema in
@spec\/storage-schema.sql@ (five tables, indexes, meta rows); an
existing database is verified (tables present, @schema_version@
exactly @3@). Versions 1 and 2 refuse as migration-required and are
never migrated by an open: the open writes nothing, and only the
explicit @haskoki-ctl store migrate@ moves a store to version 3. A foreign or
garbage file is rejected with a diagnosis and left byte-identical.

SQLite configuration (design 08, section 6): foreign keys on, a
bounded 5s busy timeout, rollback-journal mode, extra durable
(EXTRA) synchronization, so a commit followed closely by a power
loss stays committed. WAL is not used; no unsafe journal\/sync
mode is ever selected. Every commit runs as one @BEGIN IMMEDIATE@
transaction, so multi-object deltas are all-or-nothing.

Full-width unsigned quantities travel as 8-byte big-endian blobs
or fixed hex text; only the bounded @revision@ counter uses an
INTEGER column (guarded by @CHECK (revision > 0)@), and every
read-back range-checks before narrowing to 'Int'.

Close serializes with use: the close runs under the same
connection guard as every operation, so it waits for in-flight
uses instead of closing the handle beneath them; later uses of
the closed handle fail closed. A close that cannot complete (an
injected close fault, or a SQLite close error) retains the
handle, the lock, and both kernel guards, refuses new
operations, reports the failure by throwing, and a later close
retries for real.
-}
module Haskoki.Runtime.Storage.SQLite
  ( openSQLiteStore
  , openSQLiteStoreWith
  , openSQLiteStoreWithHooks
  , SQLiteTestHooks (..)
  , noSQLiteTestHooks
  , sqliteSchemaVersion
  , livenessFromProbes
  , PidLiveness (..)
  , ProcProbe (..)
  , pidIsDead
  , waitForGoFile
  , waitForPoll
  , pauseForFreshCreate
  , FileIdentity (..)
  , StoreSnapshot (..)
  , resolveStorePath
  , resolveStorePathTracked
  , resolveStoreSpelling
  , resolveStoreSpellingTracked
  , withStoreSpelling
  , requireRegularStore
  , readStoreSnapshot
  , readStoreSnapshotAllowCold
  , OwnerState (..)
  , probeOwner
  , guardFlags
  , readFileCloexec
  , OwnedStoreFile
  , ownedPath
  , ownedDbMatches
  , withOwnedStoreFile
  , withOwnedStoreFileKeep
  , clearColdJournalOwned
  , SQLiteMigration (..)
  , MigrationHooks (..)
  , noMigrationHooks
  , MigrateTxnError (..)
  , migrateOwned
  ) where

import Control.Concurrent.MVar (MVar, modifyMVar_, newMVar, readMVar)
import Control.Exception (SomeException, bracket, bracketOnError, finally, mask, mask_, onException, throwIO, try)
import Control.Monad (when)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.List (intercalate, nub, sort)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe)
import qualified Data.Text as T
import Data.Text (Text)
import Data.Word (Word64)
import qualified Database.SQLite3 as S
import Database.SQLite3.Direct (getAutoCommit)
import System.Posix.Files (FileStatus, deviceID, fileExist, fileID, fileSize, getFdStatus, getFileStatus, getSymbolicLinkStatus, isRegularFile, modificationTime, readSymbolicLink, removeLink, setFdSize, setFileMode)
import System.Posix.Types (Fd, ProcessID)

import Haskoki.Runtime.Attach (newClaimAuthority)
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , CredentialRecord (..)
  , FaultInjector (..)
  , FaultPoint (..)
  , HandleState (..)
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
  , checkLimits
  , checkSlotUnique
  , checkTokenRefs
  , coverDeletedJobIds
  , decodeHex16
  , decodeTokenRecord
  , defaultLimits
  , encodeCredentialRecord
  , encodeHex16
  , encodeHexWord64
  , encodeJobRecord
  , encodeObjectRecord
  , encodeTokenRecord
  , jobIdCounterKey
  , noFaults
  , reconcileCredentialsReload
  , reconcileJobsReload
  , reconcileReload
  , scrubDeltaAuth
  , storeClosed
  , zeroStats
  )
import Haskoki.Runtime.Storage.SQLite.Stats
import Haskoki.Runtime.Storage.SQLite.Statements
import Haskoki.Runtime.Storage.SQLite.Types
import Haskoki.Runtime.Storage.SQLite.Init
import Haskoki.Runtime.Storage.SQLite.Migrate
import Haskoki.Runtime.Storage.SQLite.Ownership
import Haskoki.Runtime.Storage.SQLite.Snapshot
import Haskoki.Runtime.Storage.SQLite.Conn
import Haskoki.Runtime.Storage.SQLite.Records
import Haskoki.Runtime.Storage.SQLite.Txn
import Haskoki.Runtime.Trace (SpellingRefusal (..), effectiveStorePath, recheckResolved, renderSpellingRefusal)
import Haskoki.Types (Generation (..), ObjectId (..), SlotId (..), TokenId (..))
-- ---------------------------------------------------------------------------
-- Open
-- ---------------------------------------------------------------------------
-- | Open the SQLite store at the given path, taking single-writer
-- ownership. Any failure releases ownership before returning; an
-- async exception during open releases the lock and then
-- re-propagates, so it can never strand a live-pid lock.
-- Default limits, no fault injection.
openSQLiteStore :: FilePath -> IO (Either StoreError Store)
openSQLiteStore path = openSQLiteStoreWith False path defaultLimits noFaults
-- | Open with explicit limits (always enforced) and an
-- explicit fault injector. The whole acquisition runs masked;
-- the only interruptible points are the flock-retry delays
-- (inside 'ensureDbGuard'/'takeOwnership', each with its fd
-- cleanup scoped), the fresh-create pause (no handle exists
-- yet), and the restored 'openInner' section inside
-- 'openAndInit' (protected by handle cleanup). Every acquired
-- resource has cleanup registered across the entire remaining
-- acquisition (nested 'onException'), so a cancellation releases
-- the sidecar, the database guard, and the SQLite handle exactly
-- once each — normal 'Left' paths release explicitly instead, so
-- no handler ever double-closes. The database guard is always
-- held before any SQLite work (fresh files are created and
-- guarded first), so a lost sidecar can never fork init. The
-- initialized handle travels from 'openAndInit' to 'SQLiteConn'
-- construction masked, with no restored section and no
-- interruptible operation on the path, and handle cleanup is
-- retained across the construction itself — so the handoff has
-- no async-delivery window at all.
-- | Whether the open honours the environment seams (@HASKOKI_PROC_ROOT@
-- for owner liveness, @HASKOKI_OPEN_PAUSE*@ for the fresh-init pause).
-- Default-off everywhere except explicit opt-in: ambient variables must
-- not change storage behaviour unless the configuration asks for it
-- (@storage.allow_env_seams@); tests opt in per case.
openSQLiteStoreWith
  :: Bool -> FilePath -> StoreLimits -> FaultInjector -> IO (Either StoreError Store)
openSQLiteStoreWith allowEnv path limits inj =
  openSQLiteStoreWithHooks allowEnv path limits inj noSQLiteTestHooks
-- | 'openSQLiteStoreWith' plus test-only connection hooks
-- ('SQLiteTestHooks'); the storage suites use it to stimulate
-- real statement failures on the store's own connection. The
-- spelling normalizes first (bare @file:@ URIs decode once;
-- query/fragment, undecodable, nested, and empty spellings
-- refuse), then the path is resolved once up front: every
-- sidecar and every open below derives from the real file —
-- under a UTF-8 filesystem encoding (other locales may
-- double-encode non-ASCII names). Spellings that do not
-- round-trip through UTF-8 are out of scope (POSIX uses the
-- original bytes while SQLite opens the replacement spelling).
-- A store path whose own final component is a dangling symlink
-- refuses: no store is created at that link's target. A missing
-- store under a symlinked parent directory is created at the
-- resolved path, as before.
openSQLiteStoreWithHooks
  :: Bool -> FilePath -> StoreLimits -> FaultInjector -> SQLiteTestHooks
  -> IO (Either StoreError Store)
openSQLiteStoreWithHooks allowEnv path0 limits inj hooks = do
  eResolved <- resolveStoreSpellingTracked path0
  case eResolved of
    Left r -> pure (Left (StoreIO (renderSpellingRefusal r path0)))
    Right (path, sawLink) -> openAfterResolve path sawLink
  where
    openAfterResolve path sawLink =
      if not sawLink
        then openSQLiteStoreResolved allowEnv path limits inj hooks
        else do
          -- A final-component link that resolves to a missing target
          -- is dangling (a moved store, an unmounted volume): refuse
          -- before taking ownership, so neither the target nor its lock
          -- is created.
          -- Only a proven-missing target refuses; anything else takes
          -- the normal path and fails closed downstream.
          eSt <- lstatOpt path
          case eSt of
            Right Nothing -> pure (Left (StoreIO
              ("dangling symlink " ++ path0 ++ " (target " ++ path
                ++ " is missing); refusing to create a store at a link target")))
            _ -> openSQLiteStoreResolved allowEnv path limits inj hooks
-- | 'openSQLiteStoreWithHooks' on an already-resolved path.
openSQLiteStoreResolved
  :: Bool -> FilePath -> StoreLimits -> FaultInjector -> SQLiteTestHooks
  -> IO (Either StoreError Store)
openSQLiteStoreResolved allowEnv path limits inj hooks = mask $ \restore -> do
  procRoot <- procRootFromEnv allowEnv
  let lockPath = path ++ ".lock"
  eOwn <- takeOwnership path lockPath procRoot 3
  case eOwn of
    Left err -> pure (Left err)
    Right lockFd ->
      acquireRest restore lockPath lockFd `onException` releaseQuiet lockFd lockPath
  where
    acquireRest restore lockPath lockFd = do
      eGuard <- ensureDbGuard path
      case eGuard of
        Left err -> releaseQuiet lockFd lockPath >> pure (Left err)
        Right (dbFd, created) ->
          dbPart restore lockPath lockFd dbFd created `onException` closeQuietFd dbFd
    -- 'openAndInit' runs under this mask (its only restored
    -- section is handle-cleanup-protected) and returns the handle
    -- masked: no 'restore' wraps the handoff, so a cancellation
    -- cannot land between init success and our receipt. Handle
    -- cleanup is still retained across the construction below, so
    -- every acquisition prefix owns cleanup for every resource.
    dbPart restore lockPath lockFd dbFd created = do
      -- A non-empty -wal or -shm sibling refuses before any SQLite
      -- connection opens: the journal-mode switch below would
      -- otherwise checkpoint foreign frames into the store.
      -- Ownership and the database guard are already held, and both
      -- are released on this path, exactly as on an init failure.
      refused <- foreignSidecar path
      case refused of
        Just p -> do
          closeQuietFd dbFd
          releaseQuiet lockFd lockPath
          pure (Left (StoreForeignSidecar p))
        Nothing -> do
          eDb <- openAndInit allowEnv restore dbFd path created
          case eDb of
            Left err -> do
              closeQuietFd dbFd
              releaseQuiet lockFd lockPath
              pure (Left err)
            Right db ->
              (do lock <- newMVar ()
                  closed <- newMVar HandleOpen
                  qVar <- newMVar []
                  openTxn <- newIORef Nothing
                  sVar <- newIORef zeroStats
                  claims <- newClaimAuthority
                  let conn = SQLiteConn
                        { sqDb = db
                        , sqLock = lock
                        , sqClosed = closed
                        , sqPath = path
                        , sqLockPath = lockPath
                        , sqLockFd = lockFd
                        , sqDbFd = dbFd
                        , sqInjector = inj
                        , sqQuarantine = qVar
                        , sqOpenTxn = openTxn
                        , sqStats = sVar
                        , sqLimits = limits
                        , sqHooks = hooks
                        , sqClaims = claims
                        }
                  pure (Right (mkStore conn)))
                `onException` closeQuiet db
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
-- ---------------------------------------------------------------------------
-- Store operations
-- ---------------------------------------------------------------------------
-- | Build the 'Store' record over an open connection. Every
-- world-touching operation runs under the connection guard and
-- reports the closed handle unless open; quarantine and stats
-- stay readable (live-handle properties that never touch the
-- database).
mkStore :: SQLiteConn -> Store
mkStore conn = Store
  { storeLoadTokens = withLive conn Left loadTokens
  , storeLoadJobs = withLive conn Left loadJobs
  , storeLoadCredentials = withLive conn Left (loadCredentials)
  , storeCommit = protocolDelta conn
  , storeResetToken = resetTokenConn conn
  , storeReserveJobId = reserveJobIdConn conn
  , storeClose = closeConn conn
  , storeInspect = withLive conn Left inspectConn
  , storeQuarantined = readMVar (sqQuarantine conn)
  , storeReload = reloadConn conn
  , storeStats = readIORef (sqStats conn)
  , storeLoadMeta = withLive conn Left loadMeta
  , storeClaims = sqClaims conn
  }
-- | The commit protocol: closed-handle refusal, quarantine
-- refusal, pre-commit validation (limits, expected revisions),
-- pre-commit fault rollback, then the masked durable section (one
-- @BEGIN IMMEDIATE@ transaction, ambiguous verification,
-- post-commit quarantine). The whole flow holds the connection
-- guard, so one commit runs at a time per handle and the close
-- (which takes the same guard first) can never strand it
-- mid-flight.
protocolDelta :: SQLiteConn -> StoreDelta -> IO CommitResult
protocolDelta conn delta =
  withLive conn NotCommitted (\db -> protocolLocked conn db delta)
-- | Token reset: the expected generation must match the current
-- one, then the replacement plus the removal of every owned
-- object and job run as one ordinary protocol flow
-- (closed-handle refusal, quarantine, validation, faults, masking
-- all apply).
resetTokenConn :: SQLiteConn -> TokenId -> Generation -> TokenRecord -> IO CommitResult
resetTokenConn conn tid wantGen replacement =
  withLive conn NotCommitted $ \db -> do
    eEff <- resetEffectiveDb db tid wantGen replacement
    case eEff of
      Left err -> pure (NotCommitted err)
      Right eff -> protocolLocked conn db eff
-- | Build the reset's effective delta from one consistent read
-- (runs under the connection guard, so the generation check is
-- exact). Owned objects and jobs are dropped explicitly (the
-- foreign-key cascades backstop the same outcome); the credential
-- row stays with the token.
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
                    , sdPutMeta = []
                    , sdPutCredentials = []
                    , sdDropCredentials = []
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
-- | The commit flow with the connection guard already held. The
-- delta is scrubbed first ('scrubDeltaAuth'): token puts persist
-- the durable authentication half only, so validation, the
-- staged upserts, and ambiguous-commit verification all observe
-- scrubbed rows and agree with every later load.
protocolLocked :: SQLiteConn -> S.Database -> StoreDelta -> IO CommitResult
protocolLocked conn db delta0 = do
  let delta = scrubDeltaAuth delta0
      inj = sqInjector conn
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
                      then pure (Left (TxnRolledBack (StoreFull "disk full (injected)")))
                      else runTxn delta
                  result <- case eTxn of
                    Left failure -> settleTxnFailure conn db (Just affected) failure
                    Right doomed -> do
                      ambiguous <- fiFire inj FaultAmbiguousCommit
                      if ambiguous
                        then resolveAmbiguous inj qVar sVar (effectiveDelta doomed delta) affected
                        else do
                          bumpCommits sVar
                          postCommitTail inj qVar sVar affected
                  fiOnResult inj result
                  pure result
  where
    -- One transaction. The body stops at its first failed
    -- statement ('runBody'), so after a body or COMMIT failure
    -- the only statement left is the cleanup, which follows the
    -- native transaction state ('endFailedTxn'): no ROLLBACK at
    -- all once SQLite has rolled the whole transaction back
    -- itself (e.g. SQLITE_FULL during a page split, or a
    -- trigger's RAISE(ROLLBACK)) — the connection is then in
    -- autocommit mode, where any further statement would commit
    -- on its own — and a surfaced, classified ROLLBACK otherwise.
    -- A COMMIT that fails with the transaction still active
    -- (SQLITE_BUSY) did not take effect; one that fails after the
    -- transaction ended has an unknown outcome.
    runTxn :: StoreDelta -> IO (Either TxnFailure [Word64])
    runTxn d = do
      sthBeforeBegin (sqHooks conn) db
      eBegin <- trySQLite (S.exec db "BEGIN IMMEDIATE")
      case eBegin of
        Left err -> pure (Left (TxnRolledBack err))
        Right () -> do
          eBody <- runBody d
          case eBody of
            Left err -> Left <$> endFailedTxn conn db AtBody err
            Right doomed -> do
              eCommit <- trySQLite (S.exec db "COMMIT")
              case eCommit of
                Left err -> Left <$> endFailedTxn conn db AtCommit err
                Right () -> pure (Right doomed)
    -- The observed outcome is discarded; a reload decides. Present
    -- verifies committed (every table). Anything else — a failed
    -- reload, or a reload that does not hold the whole delta —
    -- quarantines with 'CommitUnknown': a mismatch is not proof
    -- of absence (a partial reload would be labelled "absent"
    -- while part of the delta is durable), and no pre-state is
    -- recorded to prove one. Nothing reissues. The expectation is
    -- the effective delta: the stored effect, not the raw
    -- request.
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
          eMeta <- loadMeta db
          eCreds <- loadCredentials db
          case (eLoaded, eJobs, eMeta, eCreds) of
            (Right loaded, Right jobs, Right meta, Right creds)
              | reconcileReload d loaded == ReconciledPresent
              , reconcileJobsReload d jobs == ReconciledPresent
              , reconcileMetaReload d meta == ReconciledPresent
              , reconcileCredentialsReload d creds == ReconciledPresent -> do
                  bumpCommits sVar
                  postCommitTail inj qVar sVar affected
            (Right _, Right _, Right _, Right _) -> do
              let err = StoreIO "ambiguous commit unresolved: the reload does not hold the whole delta"
              quarantineTokens qVar sVar affected (show err)
              pure (CommitUnknown err)
            (Left err, _, _, _) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
            (_, Left err, _, _) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
            (_, _, Left err, _) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
            (_, _, _, Left err) -> do
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
    -- Drops before puts; tokens before the objects, jobs, and
    -- credentials that reference them (foreign keys stay
    -- satisfied throughout). The groups run fail-fast
    -- ('firstFailure'): the first failed statement stops the
    -- body, and no later group (nor later statement of the same
    -- group) executes. Token puts run staged (two phases
    -- within this transaction); credential puts dedupe
    -- first-wins (the token-row precedent). The doomed pids are
    -- read before the drops, then folded into the job-id mark
    -- after the caller's meta puts, so a legacy store whose
    -- mark never advanced still cannot re-mint deleted ids once
    -- the records are gone.
    runBody :: StoreDelta -> IO (Either StoreError [Word64])
    runBody d = do
      eDoomed <- readDoomedPids db d
      case eDoomed of
        Left err -> pure (Left err)
        Right doomed -> do
          eGroups <- firstFailure
            [ runAll (map dropObjectStmt (sdDropObjects d))
            , runAll (map dropJobStmt (sdDropJobs d))
            , runAll (map dropCredentialStmt (sdDropCredentials d))
            , runAll (map dropTokenStmt (sdDropTokens d))
            , runTokenPuts (sdPutTokens d)
            , runAll (map putObjectStmt (sdPutObjects d))
            , runAll (map putJobStmt (sdPutJobs d))
            , runAll (map putCredentialStmt (firstByCredential (sdPutCredentials d)))
            , runAll (map putMetaStmt (sdPutMeta d))
            , coverDeletedMeta db doomed
            ]
          pure (eGroups >> Right doomed)
      where
        runAll :: [(Text, [S.SQLData])] -> IO (Either StoreError ())
        runAll stmts = firstFailure [execParams db sql params | (sql, params) <- stmts]
        -- Token puts apply in two phases. Sequential upserts would
        -- observe transient @UNIQUE(slot_key)@ conflicts whenever
        -- one put's target slot is still held by a token a later
        -- put moves (list order would decide the outcome, and a
        -- slot swap could never land) — while the validated final
        -- projection is unique and the memory backend applies it
        -- atomically. Staging first parks every put token on a
        -- temporary slot that collides with neither a current nor
        -- a final slot, so the subsequent upserts land in any
        -- order with the same result. Staging touches only
        -- @slot_key@: the @token_id@ row — and therefore every
        -- owned object and job — is preserved throughout.
        runTokenPuts :: [TokenRecord] -> IO (Either StoreError ())
        runTokenPuts [] = pure (Right ())
        runTokenPuts puts = do
          eRows <- queryRows db "SELECT slot_key FROM tokens" []
          case eRows of
            Left err -> pure (Left err)
            Right rows -> case mapM parseSlotKey rows of
              Nothing -> pure (Left (StoreCorrupt "corrupt slot_key row"))
              Just current -> do
                let uniq = firstByToken puts
                    temps = pickTempSlots
                      (current ++ map (unSlotId . trSlot) uniq) (length uniq)
                eStage <- runAll (zipWith stageTokenStmt temps uniq)
                case eStage of
                  Left err -> pure (Left err)
                  Right () -> runAll (map putTokenStmt uniq)
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
        ++ map crToken (sdPutCredentials delta)
        ++ sdDropCredentials delta
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
  eCreds <- loadCredentials db
  case (eLoaded, eJobs, eCreds) of
    (Left err, _, _) -> pure (Left err)
    (_, Left err, _) -> pure (Left err)
    (_, _, Left err) -> pure (Left err)
    (Right loaded, Right jobs, Right creds) ->
      let state = LoadedState loaded jobs creds
          toks = [(trId t, t) | (t, _) <- loaded]
      in case checkLimits limits delta state of
        Just err -> pure (Left err)
        Nothing -> case checkTokenRefs toks delta of
          Just err -> pure (Left err)
          Nothing -> case checkSlotUnique toks delta of
            Just err -> pure (Left err)
            Nothing -> checkRevisionsDb db delta
-- | The delta as durably applied: requested meta rows replayed
-- through the backend's own put order (sequential upserts, so
-- the last put wins, matching 'runBody'), with the requested
-- job-id counter row advanced by the generated deletion
-- coverage — so the stored effect, not the raw request, joins
-- the reconciliation expectation.
effectiveDelta :: [Word64] -> StoreDelta -> StoreDelta
effectiveDelta doomed delta =
  delta { sdPutMeta = expected }
  where
    stored = foldl (\m (k, v) -> Map.insert k v m) Map.empty (sdPutMeta delta)
    covered = case Map.lookup jobIdCounterKey stored of
      Nothing -> stored
      Just v -> case coverDeletedJobIds (Just v) doomed of
        Just c -> Map.insert jobIdCounterKey c stored
        Nothing -> stored
    expected =
      [ (k, v)
      | (k, _) <- sdPutMeta delta
      , Just v <- [Map.lookup k covered]
      ]
-- | The first touched token that is quarantined, if any.
firstQuarantined :: [(TokenId, String)] -> [TokenId] -> Maybe (TokenId, String)
firstQuarantined q tids =
  listToMaybe [(tid, why) | tid <- tids, Just why <- [lookup tid q]]
-- | Authoritative reload: a clean load clears the quarantine; a
-- failed load keeps it and reports the error. Reloads never
-- consult the fault script. A closed handle reports closed
-- without touching the quarantine. Credentials load alongside
-- tokens: a corrupt credential row keeps the quarantine like a
-- corrupt token row. A connection-wide quarantine (a write
-- transaction left open by a failed ROLLBACK) resolves first:
-- the ROLLBACK is retried, and only once SQLite reports the
-- transaction ended does the reload read — durable state, never
-- the open transaction's writes. Until then the reload refuses
-- and every quarantine stays.
reloadConn :: SQLiteConn -> IO (Either StoreError ())
reloadConn conn = withConn conn (pure (Left storeClosed)) $ \db -> do
  eOpen <- resolveOpenTxn conn db
  case eOpen of
    Left err -> pure (Left err)
    Right () -> do
      eLoaded <- loadTokens db
      eCreds <- loadCredentials db
      case (eLoaded, eCreds) of
        (Right _, Right _) ->
          modifyMVar_ (sqQuarantine conn) (\_ -> pure []) >> pure (Right ())
        (Left err, _) -> pure (Left err)
        (_, Left err) -> pure (Left err)
-- | Retry the ROLLBACK of a write transaction left open
-- ('sqOpenTxn'); clear the connection-wide quarantine only when
-- SQLite reports the transaction ended.
resolveOpenTxn :: SQLiteConn -> S.Database -> IO (Either StoreError ())
resolveOpenTxn conn db = do
  openTxn <- readIORef (sqOpenTxn conn)
  case openTxn of
    Nothing -> pure (Right ())
    Just why -> do
      ended <- getAutoCommit db
      eRollback <- if ended then pure (Right ()) else trySQLite (S.exec db "ROLLBACK")
      endedNow <- getAutoCommit db
      if endedNow
        then writeIORef (sqOpenTxn conn) Nothing >> pure (Right ())
        else pure (Left (connectionQuarantined (why ++ either (\e -> "; retried ROLLBACK failed: " ++ show e) (const "") eRollback)))
-- | Render every stored record through its canonical bytes (load,
-- then re-encode, so inspection always shows canonical form). A
-- failed load reports the error instead of a silent empty
-- list, so corruption stays diagnosed.
inspectConn :: S.Database -> IO (Either StoreError [StoredDoc])
inspectConn db = do
  eLoaded <- loadTokens db
  eJobs <- loadJobs db
  eCreds <- loadCredentials db
  case (eLoaded, eJobs, eCreds) of
    (Right toks, Right jobs, Right creds) -> pure $ Right $
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
      ++
      [ StoredDoc "credentials" (show (unTokenId (crToken c))) (encodeCredentialRecord c)
      | c <- creds
      ]
    (Left err, _, _) -> pure (Left err)
    (_, Left err, _) -> pure (Left err)
    (_, _, Left err) -> pure (Left err)
