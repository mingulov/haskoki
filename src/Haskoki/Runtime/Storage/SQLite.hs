{-# LANGUAGE ForeignFunctionInterface #-}
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

Ownership is fail-closed and kernel-backed: when owner liveness is
unknowable (@\/proc@ unreadable, masked, or partially hidden) the
second opener is refused with 'StoreSecondWriter' rather than risk
a state fork, and every owner holds an exclusive non-blocking
@flock(2)@ on a held-open lock fd for the lock's lifetime, so a
live-but-hidden owner still refuses takeovers. Exclusion is
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
bounded 5s busy timeout, rollback-journal mode, ordinary durable
(FULL) synchronization. WAL is not used; no unsafe journal\/sync
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
  , FileIdentity (..)
  , StoreSnapshot (..)
  , readStoreSnapshot
  , readStoreSnapshotAllowCold
  , OwnerState (..)
  , probeOwner
  , guardFlags
  , readFileCloexec
  , OwnedStoreFile
  , ownedPath
  , withOwnedStoreFile
  , clearColdJournal
  , SQLiteMigration (..)
  , MigrationHooks (..)
  , noMigrationHooks
  , migrateOwned
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.MVar (MVar, modifyMVar_, newMVar, putMVar, readMVar, takeMVar)
import Control.Exception (SomeException, bracket, bracketOnError, bracket_, finally, mask, mask_, onException, throwIO, try, uninterruptibleMask_)
import Control.Monad (when)
import Data.Bits (shiftR, (.&.), (.|.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef, writeIORef)
import Data.Int (Int64)
import qualified Data.ByteString.Char8 as BC8
import Data.List (nub, sort)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, listToMaybe)
import qualified Data.Text as T
import Data.Text (Text)
import Data.Word (Word64)
import qualified Database.SQLite3 as S
import Database.SQLite3.Direct (getAutoCommit)
import Foreign.C.Types (CInt (..))
import System.Environment (lookupEnv)
import System.IO.Error (isAlreadyExistsError, isDoesNotExistError, tryIOError)
import System.Posix.Files (FileStatus, deviceID, fileExist, fileID, fileSize, getFdStatus, getFileStatus, getSymbolicLinkStatus, isRegularFile, modificationTime, removeLink, setFdSize, setFileMode)
import System.IO (hClose)
import System.Posix.IO (OpenFileFlags (..), OpenMode (..), closeFd, defaultFileFlags, fdToHandle, fdWrite, openFd)
import System.Posix.Process (getParentProcessID, getProcessID)
import System.Posix.Types (Fd, ProcessID)
import System.Posix.Unistd (fileSynchronise)

import Haskoki.Runtime.Attach (ClaimAuthority, newClaimAuthority)
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
  , checkExpectedRevisions
  , checkLimits
  , checkSlotUnique
  , checkTokenRefs
  , coverDeletedJobIds
  , decodeAttrsDoc
  , decodeCredentialRecord
  , decodeHex16
  , decodeJobRecord
  , decodeTokenRecord
  , defaultLimits
  , encodeAttrsDoc
  , encodeCredentialRecord
  , encodeHex16
  , encodeHexWord64
  , encodeJobRecord
  , encodeObjectRecord
  , encodeTokenRecord
  , execStateName
  , jobIdCounterKey
  , knownMaterialEncodings
  , nextJobReservation
  , noFaults
  , reconcileCredentialsReload
  , reconcileJobsReload
  , reconcileReload
  , scrubDeltaAuth
  , storeClosed
  , zeroStats
  )
import Haskoki.Types (Generation (..), ObjectId (..), Revision (..), SlotId (..), TokenId (..))

-- | The schema version this backend creates and serves. Version 3
-- marks a store written by a credential-seeding build; versions 1
-- and 2 refuse at open WITHOUT writing ('StoreNeedsMigration') and
-- only the explicit @haskoki-ctl store migrate@ moves them to 3;
-- anything else refuses ('StoreSchemaVersion').
sqliteSchemaVersion :: Int
sqliteSchemaVersion = 3

-- | One open SQLite store: the connection, its guard lock, the
-- per-handle lifecycle state, the owned paths, the held-open
-- flocked lock fd (the kernel ownership guard), the held-open
-- flocked database fd (the stable-identity guard: deleting the
-- lock path cannot fork a live owner), and the live-handle
-- protocol state (injector, quarantine, the connection-wide
-- quarantine left by a write transaction that could not be
-- rolled back, stats, and the handle-owned detached-job claim
-- authority).
data SQLiteConn = SQLiteConn
  { sqDb :: !S.Database
  , sqLock :: !(MVar ())
  , sqClosed :: !(MVar HandleState)
  , sqPath :: !FilePath
  , sqLockPath :: !FilePath
  , sqLockFd :: !Fd
  , sqDbFd :: !Fd
  , sqInjector :: !FaultInjector
  , sqQuarantine :: !(MVar [(TokenId, String)])
  , sqOpenTxn :: !(IORef (Maybe String))
  , sqStats :: !(IORef StoreStats)
  , sqLimits :: !StoreLimits
  , sqHooks :: !SQLiteTestHooks
  , sqClaims :: !ClaimAuthority
  }

-- | Test-only hooks run on the store's OWN connection (a second
-- connection cannot install connection-local state such as TEMP
-- triggers, functions, authorizers, commit hooks, or
-- @max_page_count@). Production opens use 'noSQLiteTestHooks'.
-- The hooks run under the connection guard inside the masked
-- region of every write transaction: commits, token resets
-- (which run the same commit flow) and job-id reservations. They
-- are a statement-boundary seam: whatever failure a test
-- stimulates through them is a real SQLite statement failure
-- inside the real transaction, never a simulated result.
data SQLiteTestHooks = SQLiteTestHooks
  { sthBeforeBegin :: S.Database -> IO ()
    -- ^ Immediately before @BEGIN IMMEDIATE@, after validation.
  , sthAfterBodyFailure :: S.Database -> IO ()
    -- ^ Immediately after the transaction body reports its
    -- first failure, before any cleanup statement runs (the
    -- native transaction state is still exactly what the failed
    -- statement left).
  , sthAfterCommitFailure :: S.Database -> IO ()
    -- ^ Immediately after @COMMIT@ fails, before any cleanup
    -- statement runs.
  , sthAfterRollbackFailure :: S.Database -> IO ()
    -- ^ Immediately after a cleanup @ROLLBACK@ fails, before the
    -- native transaction state is re-read.
  }

-- | No hooks: every production open.
noSQLiteTestHooks :: SQLiteTestHooks
noSQLiteTestHooks = SQLiteTestHooks
  { sthBeforeBegin = \_ -> pure ()
  , sthAfterBodyFailure = \_ -> pure ()
  , sthAfterCommitFailure = \_ -> pure ()
  , sthAfterRollbackFailure = \_ -> pure ()
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
openSQLiteStoreWith :: FilePath -> StoreLimits -> FaultInjector -> IO (Either StoreError Store)
openSQLiteStoreWith path limits inj = openSQLiteStoreWithHooks path limits inj noSQLiteTestHooks

-- | 'openSQLiteStoreWith' plus test-only connection hooks
-- ('SQLiteTestHooks'); the storage suites use it to stimulate
-- real statement failures on the store's own connection.
openSQLiteStoreWithHooks
  :: FilePath -> StoreLimits -> FaultInjector -> SQLiteTestHooks
  -> IO (Either StoreError Store)
openSQLiteStoreWithHooks path limits inj hooks = mask $ \restore -> do
  procRoot <- procRootFromEnv
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
      eDb <- openAndInit restore dbFd path created
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

-- | The @\/proc@ root for owner-liveness checks: @HASKOKI_PROC_ROOT@
-- overrides (tests mask liveness deterministically); empty or unset
-- means @\/proc@. Any override that hides a live owner fails closed
-- (the opener is refused), never open — and the kernel lock below
-- backstops every @\/proc@ verdict.
procRootFromEnv :: IO FilePath
procRootFromEnv = do
  mRoot <- lookupEnv "HASKOKI_PROC_ROOT"
  pure (case mRoot of Just r | not (null r) -> r; _ -> "/proc")

-- ---------------------------------------------------------------------------
-- Ownership
-- ---------------------------------------------------------------------------

-- | Flags for every lock and guard fd: close-on-exec is requested
-- at creation (@O_CLOEXEC@), never set afterwards. A separate
-- @fcntl(F_SETFD)@ after the open leaves a window in which a
-- concurrent fork+exec (another thread, or the host application
-- spawning a child) inherits the fd; the child then keeps the open
-- file description, and with it the @flock(2)@ lock, alive after
-- our close, so the next open is wrongly refused as a second
-- writer.
guardFlags :: OpenFileFlags
guardFlags = defaultFileFlags { cloexec = True }

-- | All bytes of a file, read through a 'guardFlags' descriptor. A GHC
-- 'Handle' open ('readFile', 'BS.readFile') does not set O_CLOEXEC, so
-- a concurrent fork+exec could inherit it.
readFileCloexec :: FilePath -> IO ByteString
readFileCloexec p = bracket open hClose BS.hGetContents
  where open = bracketOnError (openFd p ReadOnly guardFlags) closeFd fdToHandle

-- | Take single-writer ownership via an O_EXCL sidecar lock carrying
-- our pid. An existing lock owned by a live pid fails explicitly;
-- a lock whose owner liveness is unknowable fails closed; a lock
-- owned by a dead pid (a crashed run) is taken over after the
-- kernel lock confirms no live holder, within a bounded number of
-- retries. Taking over never touches the database bytes. Success
-- returns the held-open flocked lock fd, which the caller keeps for
-- the lock's lifetime.
--
-- Acquisition runs fully masked: it performs only fast,
-- non-blocking syscalls, so deferring async exceptions cannot wedge
-- the caller — and no cancellation can strand an unreachable fd
-- holding the kernel lock (@tryIOError@ alone would not catch an
-- async exception delivered between 'openFd' and the fd handoff).
takeOwnership :: FilePath -> FilePath -> FilePath -> Int -> IO (Either StoreError Fd)
takeOwnership dbPath lockPath procRoot attempts
  | attempts <= 0 = pure (Left (StoreSecondWriter ("cannot take ownership of " ++ dbPath ++ ": lock contention")))
  | otherwise = mask_ $ do
      pid <- getProcessID
      eFd <- tryIOError (openFd lockPath WriteOnly
        guardFlags { creat = Just 0o600, exclusive = True })
      case eFd of
        Right fd -> claimFresh dbPath lockPath procRoot attempts fd pid
        Left _ -> inspectLock dbPath lockPath procRoot pid attempts

-- | Claim a freshly created lock file: take the kernel lock before
-- writing our pid, and keep the fd open. A lost race retries
-- (bounded); the retry then sees the winner's live pid and refuses.
-- Runs under the caller's mask. Each fd cleanup scope ends before
-- its explicit close: the retry below runs outside every scope
-- covering this fd, so a cancellation during the retry can never
-- double-close it (possibly after the number is recycled).
claimFresh :: FilePath -> FilePath -> FilePath -> Int -> Fd -> ProcessID -> IO (Either StoreError Fd)
claimFresh dbPath lockPath procRoot attempts fd pid = do
  locked <- tryFlock fd `onException` closeQuietFd fd
  if not locked
    then do
      closeQuietFd fd
      takeOwnership dbPath lockPath procRoot (attempts - 1)
    else do
      _ <- tryIOError (fdWrite fd (show pid ++ "\n")) `onException` closeQuietFd fd
      pure (Right fd)

-- | Diagnose an existing lock: same-process, live peer, and
-- unknowable-liveness owner (all fail), dead owner (take over after
-- the kernel lock confirms), or unreadable (fail safe). Owner pids
-- compare as text, avoiding any orphan 'Read' instances.
inspectLock :: FilePath -> FilePath -> FilePath -> ProcessID -> Int -> IO (Either StoreError Fd)
inspectLock dbPath lockPath procRoot pid attempts = do
  eContent <- tryIOError (BC8.unpack <$> readFileCloexec lockPath)
  case eContent of
    Left _ -> pure (Left (StoreSecondWriter ("store is locked and the owner is unreadable: " ++ lockPath)))
    Right content -> case reads content of
      [(ownerN, _) :: (Int, String)] | show ownerN == show pid ->
        pure (Left (StoreSecondWriter ("store is already open in this process: " ++ dbPath)))
      [(ownerN, _) :: (Int, String)] -> do
        live <- pidLiveness procRoot ownerN
        case live of
          PidAlive -> pure (Left (StoreSecondWriter ("store is already open by pid " ++ show ownerN ++ ": " ++ dbPath)))
          PidUnknown -> pure (Left (StoreSecondWriter ("store is locked by pid " ++ show ownerN
            ++ " but owner liveness is unknowable (/proc unreadable); refusing second writer: " ++ dbPath)))
          PidDead -> confirmTakeover dbPath lockPath procRoot pid attempts
      _ -> pure (Left (StoreSecondWriter ("store is locked by an unknown owner: " ++ lockPath)))

-- | Owner-liveness verdict: alive, provably dead (sufficient
-- death evidence), or unknowable (anything else: masked,
-- unreadable, or partially hidden proc). Unknowable fails closed.
data PidLiveness = PidAlive | PidDead | PidUnknown deriving (Eq, Show)

-- | One @\/proc@ entry probe: present, cleanly absent (@ENOENT@),
-- or unknowable (any other error: permission denied, I\/O error,
-- not a directory, ...). Unlike 'fileExist', no probe error ever
-- escapes to the caller.
data ProcProbe = ProbePresent | ProbeAbsent | ProbeUnknown deriving (Eq, Show)

probeProc :: FilePath -> IO ProcProbe
probeProc entry = do
  eSt <- tryIOError (getFileStatus entry)
  case eSt of
    Right _ -> pure ProbePresent
    Left err
      | isDoesNotExistError err -> pure ProbeAbsent
      | otherwise -> pure ProbeUnknown

-- | Pure liveness verdict from probe results (exported so the
-- table is deterministically unit-testable; 'pidLiveness' is its
-- only production caller). Death needs sufficient evidence:
-- @\/proc\/self@ present (a healthy view), our own pid visible,
-- the parent witness satisfied, and the owner cleanly absent. The
-- parent probe is 'Nothing' exactly when our parent pid is 0 —
-- the kernel reports 0 when the parent lives outside our PID
-- namespace (e.g. container-init processes), so the parent
-- provably exists but can never have an entry under our @\/proc@:
-- the witness is inapplicable, not failed, and stale recovery
-- still works. (Probing @\/proc\/0@ instead would read Absent on
-- a healthy @\/proc@ and permanently fail closed, so no probe is
-- taken.) Any other gap fails closed. Residual: a filter hiding
-- ONLY the owner is @\/proc@-indistinguishable from a dead
-- owner, so it still reaches 'confirmTakeover' — where the kernel
-- lock backstop refuses the live owner.
livenessFromProbes :: ProcProbe -> ProcProbe -> Maybe ProcProbe -> ProcProbe -> PidLiveness
livenessFromProbes selfProbe meProbe mParentProbe ownerProbe
  | selfProbe /= ProbePresent = PidUnknown
  | meProbe /= ProbePresent = PidUnknown
  | otherwise = case mParentProbe of
      Just ProbePresent -> ownerVerdict
      Nothing -> ownerVerdict
      _ -> PidUnknown
  where
    ownerVerdict = case ownerProbe of
      ProbePresent -> PidAlive
      ProbeAbsent -> PidDead
      ProbeUnknown -> PidUnknown

-- | Pid liveness via @\/proc@ (Linux-only, matching the supported
-- loader policy): no signal is ever sent. Takeover needs
-- sufficient death evidence (see 'livenessFromProbes'):
-- @\/proc\/self@ present, our own pid visible, our PARENT pid
-- visible, and the owner cleanly absent. The parent is always a
-- live process (the kernel re-parents orphans to init\/a
-- subreaper), so a view hiding it is demonstrably filtered and
-- cannot prove death — except a namespace-local parent pid of 0,
-- which skips the witness (no @\/proc\/0@ probe is ever taken).
-- An owner pid of 0 likewise takes no probe: pid 0 is never a
-- userspace owner, so it is dead by rule while the kernel
-- backstop still confirms. Any probe error maps to 'PidUnknown'
-- (fail closed).
pidLiveness :: FilePath -> Int -> IO PidLiveness
pidLiveness procRoot ownerPid = do
  selfProbe <- probeProc (procRoot ++ "/self")
  case selfProbe of
    ProbePresent -> do
      me <- getProcessID
      meProbe <- probeProc (procRoot ++ "/" ++ show me)
      case meProbe of
        ProbePresent -> do
          ppid <- getParentProcessID
          mParentProbe <- if ppid == 0
            then pure Nothing
            else Just <$> probeProc (procRoot ++ "/" ++ show ppid)
          ownerProbe <- if ownerPid == 0
            then pure ProbeAbsent
            else probeProc (procRoot ++ "/" ++ show ownerPid)
          pure (livenessFromProbes selfProbe meProbe mParentProbe ownerProbe)
        _ -> pure PidUnknown
    _ -> pure PidUnknown

-- | Take over an apparently-stale lock: the kernel lock confirms
-- staleness (a live-but-hidden owner still holds it, and we refuse),
-- and an fstat-vs-path revalidation closes the unlink race (a lock
-- unlinked by a concurrently-closing owner is retried, never adopted
-- orphaned). The winner's pid is written in place and the held-open
-- flocked fd returned, so deleting the path cannot grant a second
-- writer while the new owner lives.
confirmTakeover :: FilePath -> FilePath -> FilePath -> ProcessID -> Int -> IO (Either StoreError Fd)
confirmTakeover dbPath lockPath procRoot pid attempts = do
  eFd <- tryIOError (openFd lockPath ReadWrite guardFlags)
  case eFd of
    Left e
      | isDoesNotExistError e -> takeOwnership dbPath lockPath procRoot (attempts - 1)
      | otherwise -> pure (Left (StoreSecondWriter ("store lock cannot be taken over: " ++ lockPath)))
    -- Each fd cleanup scope ends before its explicit close (see
    -- 'claimFresh'): the retry runs outside every scope covering
    -- this fd, so a cancellation during the retry cannot
    -- double-close it after the number is recycled.
    Right fd -> do
      locked <- tryFlock fd `onException` closeQuietFd fd
      if not locked
        then do
          closeQuietFd fd
          pure (Left (StoreSecondWriter ("store lock is held by a live owner (kernel lock held on "
            ++ lockPath ++ "); refusing second writer: " ++ dbPath)))
        else do
          same <- sameFile fd lockPath `onException` closeQuietFd fd
          if not same
            then do
              closeQuietFd fd
              takeOwnership dbPath lockPath procRoot (attempts - 1)
            else do
              _ <- (do
                _ <- tryIOError (setFdSize fd 0)
                tryIOError (fdWrite fd (show pid ++ "\n"))) `onException` closeQuietFd fd
              pure (Right fd)

-- | True when the open fd and the path name the same file (the
-- unlink race: a closer may have removed the path after we opened
-- it, in which case the fd names an orphan, not the lock).
sameFile :: Fd -> FilePath -> IO Bool
sameFile fd path = do
  eSt <- tryIOError (getFdStatus fd)
  ePath <- tryIOError (getFileStatus path)
  pure (case (eSt, ePath) of
    (Right a, Right b) -> deviceID a == deviceID b && fileID a == fileID b
    _ -> False)

-- | Close an fd best-effort (failure-path cleanup; errors
-- ignored).
closeQuietFd :: Fd -> IO ()
closeQuietFd fd = do
  _ <- tryIOError (closeFd fd)
  pure ()

-- | Take the database-anchored kernel guard on an open database
-- fd: an exclusive non-blocking @flock(2)@ held for the store's
-- lifetime. A replacement sidecar lock is a different inode whose
-- own flock succeeds, so without this guard deleting the lock path
-- would fork a live owner; the database inode is the stable
-- identity both openers contend on. Runs under the caller's mask;
-- the cleanup scope ends before the explicit close (see
-- 'claimFresh').
takeDbGuard :: FilePath -> Fd -> IO (Either StoreError Fd)
takeDbGuard dbPath fd = do
  locked <- tryFlock fd `onException` closeQuietFd fd
  if locked
    then pure (Right fd)
    else do
      closeQuietFd fd
      pure (Left (StoreSecondWriter ("store database is locked by a live owner (kernel lock held on "
        ++ dbPath ++ "); refusing second writer: " ++ dbPath)))

-- | Ensure the database file exists and take the database-anchored
-- kernel guard BEFORE any SQLite work, on both creation paths: a
-- missing file is created (@O_CREAT|O_EXCL@) and guarded here, so
-- fresh init is never unguarded — otherwise an opener that loses
-- its sidecar mid-init would run schema creation against a live
-- owner's database and even unlink it on failure. Returns the held
-- guard fd and whether this open created the file (a lost
-- create-race retries on the winner's file, bounded).
ensureDbGuard :: FilePath -> IO (Either StoreError (Fd, Bool))
ensureDbGuard dbPath = mask_ (go (3 :: Int))
  where
    go n
      | n <= 0 = pure (Left (StoreIO ("store database cannot be guarded: " ++ dbPath)))
      | otherwise = do
          eFd <- tryIOError (openFd dbPath ReadOnly guardFlags)
          case eFd of
            Right fd -> do
              eGuard <- takeDbGuard dbPath fd
              pure (fmap (, False) eGuard)
            Left e
              | isDoesNotExistError e -> do
                  eCr <- tryIOError (openFd dbPath WriteOnly
                    guardFlags { creat = Just 0o600, exclusive = True })
                  case eCr of
                    Right fd -> do
                      eGuard <- takeDbGuard dbPath fd
                      pure (fmap (, True) eGuard)
                    Left e2
                      | isAlreadyExistsError e2 -> go (n - 1)
                      | otherwise -> pure (Left (StoreIO ("store database cannot be created: " ++ dbPath)))
              | otherwise -> pure (Left (StoreIO ("store database cannot be guarded: " ++ dbPath)))

-- | @flock(2)@ constants (Linux ABI; this backend is Linux-only, as
-- is the @\/proc@ liveness check above).
lockEx, lockNb :: CInt
lockEx = 2 -- LOCK_EX: exclusive
lockNb = 4 -- LOCK_NB: non-blocking

foreign import ccall unsafe "sys/file.h flock" c_flock :: CInt -> CInt -> IO CInt

-- | Try an exclusive non-blocking kernel lock on a guard fd,
-- retrying briefly: a conflicting lock may be a
-- microsecond-transient inheritance (a forked child between fork
-- and exec\/exit holds copies of our guard fds, so our close
-- cannot release the kernel lock until the child closes them)
-- rather than a live owner. A live owner holds indefinitely, so a
-- bounded retry (10 tries over ~45ms, far longer than any
-- fork-to-exec gap) distinguishes the two. Any persistent failure
-- (held, unavailable) means "not ours": the caller fails closed.
tryFlock :: Fd -> IO Bool
tryFlock fd = go (0 :: Int)
  where
    go n = do
      ok <- (== 0) <$> c_flock (fromIntegral fd) (lockEx .|. lockNb)
      if ok || n >= 9
        then pure ok
        else threadDelay 5000 >> go (n + 1)

-- | Release ownership best-effort (close path; errors ignored).
-- The path is unlinked only while it still names OUR lock inode —
-- a live owner's close must never delete a replacement lock
-- planted after the path was deleted. The unlink happens while the
-- kernel lock is still held, so no takeover can confirm on the
-- stale inode mid-release; the fd close then drops the kernel
-- lock.
releaseQuiet :: Fd -> FilePath -> IO ()
releaseQuiet fd lockPath = do
  owned <- sameFile fd lockPath
  when owned $ do
    _ <- tryIOError (removeLink lockPath)
    pure ()
  _ <- tryIOError (closeFd fd)
  pure ()

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
  :: (IO (Either StoreError S.Database) -> IO (Either StoreError S.Database))
  -> Fd -> FilePath -> Bool -> IO (Either StoreError S.Database)
openAndInit restore guardFd path created = do
  eSt <- tryStoreIO (getFdStatus guardFd)
  case eSt of
    Left err -> pure (Left err)
    Right st -> do
      let fresh = fileSize st == 0
      when created (pauseForFreshCreate path)
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

-- | Test seam: when @HASKOKI_OPEN_PAUSE@ names a directory AND
-- @HASKOKI_OPEN_PAUSE_PATH@ names THIS open's database path
-- (exact string match) AND this open created the file, write a
-- @paused@ file and wait for a @go@ file (10ms poll, 30s cap,
-- then proceed). Inert unless both variables are set (one env
-- lookup each) and on every open that did not create the file.
-- The path binding keeps unrelated parallel SQLite creators
-- (contract\/commit tests, inherited-env holder children) from
-- pausing on another test's handshake — only the intended opener
-- can write its controller's @paused@ file. Justification: the
-- fresh-init interleaving (sidecar lost between guard acquisition
-- and SQLite's open) is otherwise timing-only; this pauses
-- exactly that window so the interleaving and the path-swap abort
-- are deterministically testable. One pauser per directory;
-- production never sets it.
pauseForFreshCreate :: FilePath -> IO ()
pauseForFreshCreate dbPath = do
  mDir <- lookupEnv "HASKOKI_OPEN_PAUSE"
  mWant <- lookupEnv "HASKOKI_OPEN_PAUSE_PATH"
  case (mDir, mWant) of
    (Just dir, Just want) | not (null dir), want == dbPath -> do
      _ <- tryIOError (writeFile (dir ++ "/paused") "paused\n")
      go (dir ++ "/go") (3000 :: Int)
    _ -> pure ()
  where
    go _ 0 = pure ()
    go goFile n = do
      done <- fileExist goFile
      if done then pure () else threadDelay 10000 >> go goFile (n - 1)

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

-- | Run one connection use under the guard lock (async-safe
-- take\/release pairing), reporting the non-open handle via the
-- default (a close-failed handle refuses exactly like a closed
-- one). The state check runs under the guard, and the close
-- takes the same guard before marking the state, so a use either
-- runs fully before the close or reports closed — the close can
-- never shut the handle beneath an in-flight use.
withConn :: SQLiteConn -> IO a -> (S.Database -> IO a) -> IO a
withConn conn onClosed f =
  bracket_ (takeMVar (sqLock conn)) (putMVar (sqLock conn) ()) $ do
    st <- readMVar (sqClosed conn)
    if st == HandleOpen then f (sqDb conn) else onClosed

-- | 'withConn' for every use that reads or writes through the
-- connection: a closed handle refuses with 'storeClosed', and a
-- connection still holding a write transaction it could not roll
-- back ('sqOpenTxn') refuses with 'connectionQuarantined' —
-- anything read there would observe, and anything written would
-- join, the unresolved transaction. Only 'reloadConn' (which
-- resolves it) and 'closeConn' (whose native close rolls it back)
-- pass.
withLive :: SQLiteConn -> (StoreError -> a) -> (S.Database -> IO a) -> IO a
withLive conn refuse f = withConn conn (pure (refuse storeClosed)) $ \db -> do
  openTxn <- readIORef (sqOpenTxn conn)
  case openTxn of
    Just why -> pure (refuse (connectionQuarantined why))
    Nothing -> f db

-- | The refusal of a connection-wide quarantine.
connectionQuarantined :: String -> StoreError
connectionQuarantined why =
  StoreIO ("connection quarantined until a reload rolls back or the store reopens: " ++ why)

-- | Idempotent close under the connection guard: the close waits
-- for any in-flight use, then either retires (the database
-- handle closes and the lock — path plus both held kernel
-- guards — is released exactly once) or, when the close cannot
-- complete, poisons the handle. A close that cannot complete —
-- an injected 'FaultClose' (which skips the real close
-- entirely) or a SQLite close error (which leaves the
-- connection open per @sqlite3_close@) — retains the handle,
-- the lock path, and both kernel guards, refuses new operations
-- exactly like a closed handle, reports the failure by throwing
-- it, and a later close retries for real. A failed close never
-- half-releases, and the next owner can never enter around the
-- surviving connection. The state cell is only ever emptied
-- across non-blocking updates: the state read, the fault probe,
-- and the real close all precede the take, so an exception or a
-- kill during the arbitrary 'fiFire' IO cannot strand the cell
-- empty (this close holds the connection guard throughout, so no
-- other writer can interleave). The retire tail itself runs
-- uninterruptibly, so a kill cannot strand a half-released
-- guard set behind a handle already marked closed (whose
-- retries would no-op); the tail performs only fast local
-- releases, never blocking operations.
closeConn :: SQLiteConn -> IO ()
closeConn conn = mask_ $
  bracket_ (takeMVar (sqLock conn)) (putMVar (sqLock conn) ()) $ do
    st <- readMVar (sqClosed conn)
    case st of
      HandleClosed -> pure ()
      _ -> do
        injected <- fiFire (sqInjector conn) FaultClose
        eClosed <-
          if injected
            then pure (Left (StoreIO "sqlite store close failed (injected FaultClose)"))
            else trySQLite (S.close (sqDb conn))
        case eClosed of
          Left err -> do
            _ <- takeMVar (sqClosed conn)
            putMVar (sqClosed conn) HandleCloseFailed
            throwIO err
          Right () -> uninterruptibleMask_ $ do
            _ <- takeMVar (sqClosed conn)
            putMVar (sqClosed conn) HandleClosed
            releaseQuiet (sqLockFd conn) (sqLockPath conn)
            _ <- tryIOError (closeFd (sqDbFd conn))
            pure ()

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

-- | Read the job-id counter row ('Nothing' = the key is
-- absent, as in a hand-built database: reservation treats it
-- as 1 and reconciles with the stored maximum).
readCounterDb :: S.Database -> IO (Either StoreError (Maybe String))
readCounterDb db = do
  eRows <- queryRows db "SELECT value FROM store_meta WHERE key = ?"
    [S.SQLText (T.pack jobIdCounterKey)]
  case eRows of
    Left err -> pure (Left err)
    Right [] -> pure (Right Nothing)
    Right [[S.SQLText v]] -> pure (Right (Just (T.unpack v)))
    Right _ -> pure (Left (StoreCorrupt "corrupt store_meta counter row shape"))

-- | Read the maximum stored persistent job id, if any. The
-- fixed-width big-endian blob keys order numerically, so one
-- descending row suffices.
readMaxJobDb :: S.Database -> IO (Either StoreError (Maybe Word64))
readMaxJobDb db = do
  eRows <- queryRows db
    "SELECT persistent_id_key FROM detached_jobs ORDER BY persistent_id_key DESC LIMIT 1" []
  case eRows of
    Left err -> pure (Left err)
    Right [] -> pure (Right Nothing)
    Right [[S.SQLBlob b]] -> case decodeBlobW64 b of
      Just w -> pure (Right (Just w))
      Nothing -> pure (Left (StoreCorrupt "corrupt persistent_id_key on max job"))
    Right _ -> pure (Left (StoreCorrupt "corrupt max-job row shape"))

-- | Pids whose records a delta deletes, read inside the
-- deleting transaction before the drops run: stored jobs
-- named by an explicit drop or owned by a dropped token,
-- minus same-delta job puts (a drop\/put pair replaces, so
-- the id survives). Drops naming unknown pids cover nothing,
-- matching the memory backend exactly.
readDoomedPids :: S.Database -> StoreDelta -> IO (Either StoreError [Word64])
readDoomedPids db d
  | null (sdDropJobs d) && null (sdDropTokens d) = pure (Right [])
  | otherwise = do
      eJobs <- loadJobs db
      pure (fmap doomedOf eJobs)
  where
    doomedOf jobs =
      [ jrPersistentId j
      | j <- jobs
      , jrToken j `elem` sdDropTokens d || jrPersistentId j `elem` sdDropJobs d
      , jrPersistentId j `notElem` map jrPersistentId (sdPutJobs d)
      ]

-- | Fold deleted pids into the job-id mark (same transaction,
-- after the caller's own meta puts): reset/drop keeps
-- coverage of legacy ids even when the mark never advanced
-- before. An empty doomed set writes nothing.
coverDeletedMeta :: S.Database -> [Word64] -> IO (Either StoreError ())
coverDeletedMeta _ [] = pure (Right ())
coverDeletedMeta db doomed = do
  eMark <- readCounterDb db
  case eMark of
    Left err -> pure (Left err)
    Right old -> case coverDeletedJobIds old doomed of
      Nothing -> pure (Right ())
      Just v -> let (sql, params) = putMetaStmt (jobIdCounterKey, v)
                in execParams db sql params

-- | Reserve one store-wide persistent job id: closed-handle
-- refusal, then the commit-protocol shape (a pre-commit fault,
-- one masked @BEGIN IMMEDIATE@ mark-advance transaction,
-- ambiguous verification) under the connection guard. The
-- guard plus single-writer ownership serializes every
-- reservation store-wide, so two contexts on one handle never
-- share an id. Reservation never consults quarantine: every
-- call re-reads the durable mark under the guard, so a
-- quarantined handle still cannot mint a duplicate. A
-- successful reservation counts as a durable commit; the
-- observation hooks fire with the commit analogue of the
-- outcome. On a version-1 database the reservation writes only
-- the @store_meta@ mark, which version 1 already has, so it does
-- not migrate (the next commit does).
reserveJobIdConn :: SQLiteConn -> IO (Either StoreError Word64)
reserveJobIdConn conn =
  withLive conn Left (reserveLocked conn)

-- | The reservation flow with the connection guard already held.
reserveLocked :: SQLiteConn -> S.Database -> IO (Either StoreError Word64)
reserveLocked conn db = do
  let inj = sqInjector conn
      sVar = sqStats conn
  preFailed <- fiFire inj FaultBeforeCommit
  if preFailed
    then pure (Left (StoreIO "injected pre-commit failure"))
    else mask_ $ do
      fiOnMasked inj
      fullDisk <- fiFire inj FaultFullDisk
      eTxn <-
        if fullDisk
          then pure (Left (TxnRolledBack (StoreFull "disk full (injected)")))
          else runReserveTxn db
      (classification, ePid) <- case eTxn of
        -- A store-wide reservation names no token: an unresolved
        -- outcome quarantines every token (the
        -- 'resolveAmbiguousReserve' precedent). A reservation
        -- that fails returns no id either way, so an advance that
        -- did land only leaves a gap, never a reuse.
        Left failure -> do
          classification <- settleTxnFailure conn db Nothing failure
          pure (classification, Left (txnFailureError failure))
        Right (pid, advanced, old) -> do
          ambiguous <- fiFire inj FaultAmbiguousCommit
          if ambiguous
            then resolveAmbiguousReserve conn db pid advanced old
            else do
              bumpCommits sVar
              pure (Committed, Right pid)
      fiOnResult inj classification
      pure ePid
  where
    -- One transaction; a failure ends it by the native state
    -- ('endFailedTxn').
    runReserveTxn :: S.Database -> IO (Either TxnFailure (Word64, String, Maybe String))
    runReserveTxn d = do
      sthBeforeBegin (sqHooks conn) d
      eBegin <- trySQLite (S.exec d "BEGIN IMMEDIATE")
      case eBegin of
        Left err -> pure (Left (TxnRolledBack err))
        Right () -> do
          eBody <- runReserveBody d
          case eBody of
            Left err -> Left <$> endFailedTxn conn d AtBody err
            Right triple@(_, advanced, _) -> do
              let (sql, params) = putMetaStmt (jobIdCounterKey, advanced)
              ePut <- execParams d sql params
              case ePut of
                Left err -> Left <$> endFailedTxn conn d AtBody err
                Right () -> do
                  eCommit <- trySQLite (S.exec d "COMMIT")
                  case eCommit of
                    Left err -> Left <$> endFailedTxn conn d AtCommit err
                    Right () -> pure (Right triple)
    -- Read the mark and the stored maximum inside the
    -- transaction and compute the pure reservation step.
    runReserveBody :: S.Database -> IO (Either StoreError (Word64, String, Maybe String))
    runReserveBody d = do
      eCounter <- readCounterDb d
      case eCounter of
        Left err -> pure (Left err)
        Right old -> do
          eMax <- readMaxJobDb d
          case eMax of
            Left err -> pure (Left err)
            Right mMax ->
              let pids = maybe [] (: []) mMax
              in pure (fmap (\(pid, advanced) -> (pid, advanced, old))
                (nextJobReservation old pids))

-- | Reconcile an ambiguous mark-advance against a fresh
-- reload: the reloaded mark is either the advanced value
-- (durable: return the id) or the pre-call value (nothing
-- written: fail clean). A failed reload — or any third
-- value, unreachable under the single-writer guard —
-- quarantines every token and fails: never a shared id.
resolveAmbiguousReserve
  :: SQLiteConn -> S.Database -> Word64 -> String -> Maybe String
  -> IO (CommitResult, Either StoreError Word64)
resolveAmbiguousReserve conn db pid advanced old = do
  let inj = sqInjector conn
      sVar = sqStats conn
  bumpVerifyReloads sVar
  verifyFailed <- fiFire inj FaultVerifyReload
  if verifyFailed
    then do
      quarantineAllTokensConn conn db "job-id reservation verification failed"
      let err = StoreIO "injected verification failure"
      pure (CommitUnknown err, Left err)
    else do
      eCounter <- readCounterDb db
      case eCounter of
        Left err -> do
          quarantineAllTokensConn conn db ("reload failed: " ++ show err)
          pure (CommitUnknown err, Left err)
        Right now
          | now == Just advanced -> do
              bumpCommits sVar
              pure (Committed, Right pid)
          | now == old ->
              let err = StoreIO "ambiguous reservation resolved: advance absent"
              in pure (NotCommitted err, Left err)
          | otherwise -> do
              quarantineAllTokensConn conn db "job-id counter diverged during reservation"
              let err = StoreCorrupt "job-id counter diverged during reservation"
              pure (CommitUnknown err, Left err)

-- | Quarantine every token in the database: an unresolved
-- store-wide reservation names no affected token, so the
-- whole handle view is suspect until an authoritative reload.
-- Best-effort: when the token list itself is unreadable the
-- caller still fails closed.
quarantineAllTokensConn :: SQLiteConn -> S.Database -> String -> IO ()
quarantineAllTokensConn conn db why = do
  tids <- allTokenIds db
  if null tids then pure () else quarantineTokens (sqQuarantine conn) (sqStats conn) tids why

-- | Every stored token id, best-effort ('[]' when the list is
-- unreadable: callers fail closed regardless).
allTokenIds :: S.Database -> IO [TokenId]
allTokenIds db = do
  eRows <- queryRows db "SELECT token_id FROM tokens" []
  pure (case eRows of
    Left _ -> []
    Right rows -> fromMaybe [] (mapM parseTid rows))
  where
    parseTid [S.SQLText tidT] = TokenId <$> decodeHex16 (T.unpack tidT)
    parseTid _ = Nothing

-- | Where a write transaction failed: in its body (no COMMIT was
-- issued) or at its COMMIT.
data TxnStep = AtBody | AtCommit

-- | How a failed write transaction ended, judged from the native
-- connection state alone ('getAutoCommit' before and after any
-- cleanup) — never from a reload, and never by reissuing anything.
data TxnFailure
  = TxnRolledBack !StoreError
    -- ^ provably not committed: SQLite rolled the whole
    -- transaction back before any COMMIT was issued, or the
    -- transaction was still active after the failure (so no
    -- COMMIT took effect) and the explicit ROLLBACK succeeded
  | TxnOutcomeUnknown !StoreError
    -- ^ the transaction is over but its outcome is not
    -- established: a COMMIT failed after SQLite had ended the
    -- transaction (it may have landed or rolled back), or a
    -- ROLLBACK reported an error; the connection itself is clean
  | TxnStillOpen !StoreError
    -- ^ the ROLLBACK did not run (or did not end the
    -- transaction), so a write transaction is still open on the
    -- connection: nothing it holds is durable yet, but every
    -- later use of the connection would read or commit it

-- | The error a transaction failure reports.
txnFailureError :: TxnFailure -> StoreError
txnFailureError f = case f of
  TxnRolledBack err -> err
  TxnOutcomeUnknown err -> err
  TxnStillOpen err -> err

-- | End a failed write transaction from the native state the
-- failure left. The step's test hook fires first, before any
-- cleanup. If SQLite has already ended the transaction, no
-- statement runs (any statement would run, and commit, in
-- autocommit mode): after a body failure that is SQLite's own
-- whole rollback ('TxnRolledBack'); after a failed COMMIT the
-- outcome is unknown. Otherwise the transaction is still active
-- — so a failed COMMIT did not take effect — and the explicit
-- ROLLBACK decides: success is a proven rollback, an error is
-- surfaced (never discarded) as unknown, or as still open when
-- the transaction survived it.
--
-- A failed ROLLBACK that nonetheless ended the transaction is
-- classified unknown, not 'TxnRolledBack': conservatively, an I/O
-- error on ROLLBACK signals storage trouble, and quarantine plus
-- reload re-establishes the durable truth. AC-01 notes that a
-- rollback error alone is not proof of corruption, so this is a
-- deliberate availability trade-off for v0.4, to be revisited in
-- v0.5.
endFailedTxn :: SQLiteConn -> S.Database -> TxnStep -> StoreError -> IO TxnFailure
endFailedTxn conn db step err = do
  case step of
    AtBody -> sthAfterBodyFailure (sqHooks conn) db
    AtCommit -> sthAfterCommitFailure (sqHooks conn) db
  ended <- getAutoCommit db
  if ended
    then pure (case step of
      AtBody -> TxnRolledBack err
      AtCommit -> TxnOutcomeUnknown err)
    else do
      eRollback <- trySQLite (S.exec db "ROLLBACK")
      either (\_ -> sthAfterRollbackFailure (sqHooks conn) db) pure eRollback
      endedNow <- getAutoCommit db
      pure (case (eRollback, endedNow) of
        (Right (), True) -> TxnRolledBack err
        (Right (), False) -> TxnStillOpen err
        (Left rbErr, True) -> TxnOutcomeUnknown (withCleanupError err rbErr)
        (Left rbErr, False) -> TxnStillOpen (withCleanupError err rbErr))

-- | The original failure plus the cleanup failure, both reported.
withCleanupError :: StoreError -> StoreError -> StoreError
withCleanupError err rbErr =
  StoreIO (show err ++ "; cleanup ROLLBACK failed: " ++ show rbErr)

-- | Classify a transaction failure and apply its ownership
-- consequence. A proven rollback is a clean 'NotCommitted'. An
-- unknown outcome is 'CommitUnknown' with the affected tokens
-- quarantined ('Nothing' = store-wide: every token) until an
-- authoritative reload. A still-open transaction is
-- 'CommitUnknown' with the whole connection quarantined
-- ('sqOpenTxn', every token listed) until a reload that rolls it
-- back or a close (SQLite rolls an open transaction back when the
-- connection closes).
settleTxnFailure :: SQLiteConn -> S.Database -> Maybe [TokenId] -> TxnFailure -> IO CommitResult
settleTxnFailure conn db scope failure = case failure of
  TxnRolledBack err -> pure (NotCommitted err)
  TxnOutcomeUnknown err -> do
    tids <- maybe (allTokenIds db) pure scope
    quarantineTokens (sqQuarantine conn) (sqStats conn) tids
      ("commit outcome unknown: " ++ show err)
    pure (CommitUnknown err)
  TxnStillOpen err -> do
    let why = "write transaction still open: " ++ show err
    writeIORef (sqOpenTxn conn) (Just why)
    others <- allTokenIds db
    quarantineTokens (sqQuarantine conn) (sqStats conn) (nub (fromMaybe [] scope ++ others)) why
    pure (CommitUnknown err)

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

-- | Run the actions in order, stopping at the first 'Left': no
-- action after a failure executes (its IO never starts), so a
-- failed statement can never be followed by a later write — in
-- particular not by one that SQLite would run in autocommit mode
-- after rolling the transaction back on its own.
firstFailure :: [IO (Either StoreError ())] -> IO (Either StoreError ())
firstFailure [] = pure (Right ())
firstFailure (act : rest) = do
  e <- act
  case e of
    Left err -> pure (Left err)
    Right () -> firstFailure rest

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

-- | Compare a delta's expected meta rows against reloaded meta
-- with full key/value equality. Every expected row must be
-- present; extra loaded rows (schema bookkeeping) are fine. A
-- metadata-only delta reconciles against meta alone.
reconcileMetaReload :: StoreDelta -> [(String, String)] -> Reconcile
reconcileMetaReload delta loaded
  | all (\(k, v) -> lookup k loaded == Just v) (sdPutMeta delta) = ReconciledPresent
  | otherwise = ReconciledAbsent

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

-- | Quarantine tokens with a reason, counting one event per token.
quarantineTokens :: MVar [(TokenId, String)] -> IORef StoreStats -> [TokenId] -> String -> IO ()
quarantineTokens qVar sVar tids why = do
  modifyMVar_ qVar (\q -> pure (foldr insertOne q tids))
  bumpQuarantines sVar (length tids)
  where
    insertOne tid q = (tid, why) : filter ((/= tid) . fst) q

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

-- | Load every provisioned credential, home-token ascending. The
-- full document decodes the record; the key column cross-checks
-- it (the job-row precedent).
loadCredentials :: S.Database -> IO (Either StoreError [CredentialRecord])
loadCredentials db = do
  eRows <- queryRows db
    "SELECT token_id, record_json FROM credentials ORDER BY token_id" []
  case eRows of
    Left err -> pure (Left err)
    Right rows -> pure (mapM decodeCredentialRow rows)

-- | Decode one credential row: the document first, then the
-- redundant key column must agree with it (any mismatch is
-- corruption).
decodeCredentialRow :: [S.SQLData] -> Either StoreError CredentialRecord
decodeCredentialRow [S.SQLText tidT, S.SQLText doc] = do
  tid <- noteCred "token_id" (decodeHex16 (T.unpack tidT))
  rec <- noteCred "record_json" (decodeCredentialRecord (T.unpack doc))
  _ <- if crToken rec == TokenId tid
    then Right ()
    else Left (StoreCorrupt "corrupt credential record: key/doc token mismatch")
  Right rec
decodeCredentialRow _ = Left (StoreCorrupt "corrupt credential row shape")

-- | Tag a 'Maybe' credential decode with its column.
noteCred :: String -> Maybe a -> Either StoreError a
noteCred col = maybe (Left (StoreCorrupt ("corrupt credential record: bad " ++ col))) Right

-- | Load every @store_meta@ row as key/value pairs.
loadMeta :: S.Database -> IO (Either StoreError [(String, String)])
loadMeta db = do
  eRows <- queryRows db "SELECT key, value FROM store_meta" []
  case eRows of
    Left err -> pure (Left err)
    Right rows -> pure (mapM decodeMetaRow rows)
  where
    decodeMetaRow [S.SQLText k, S.SQLText v] = Right (T.unpack k, T.unpack v)
    decodeMetaRow _ = Left (StoreCorrupt "corrupt store_meta row shape")

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

-- ---------------------------------------------------------------------------
-- Statements
-- ---------------------------------------------------------------------------

-- | DELETE one object by id.
dropObjectStmt :: ObjectId -> (Text, [S.SQLData])
dropObjectStmt (ObjectId n) =
  ("DELETE FROM objects WHERE object_id = ?", [S.SQLText (T.pack (encodeHex16 n))])

-- | DELETE one token by id (owned objects and jobs cascade).
dropTokenStmt :: TokenId -> (Text, [S.SQLData])
dropTokenStmt (TokenId n) =
  ("DELETE FROM tokens WHERE token_id = ?", [S.SQLText (T.pack (encodeHex16 n))])

-- | DELETE one job by persistent id.
dropJobStmt :: Word64 -> (Text, [S.SQLData])
dropJobStmt pid =
  ("DELETE FROM detached_jobs WHERE persistent_id_key = ?", [S.SQLBlob (encodeBlobW64 pid)])

-- | DELETE one credential by home token.
dropCredentialStmt :: TokenId -> (Text, [S.SQLData])
dropCredentialStmt (TokenId n) =
  ("DELETE FROM credentials WHERE token_id = ?", [S.SQLText (T.pack (encodeHex16 n))])

-- | Upsert one credential row (full document plus the redundant
-- key column, which loads cross-check). Callers dedupe
-- first-wins ('firstByCredential'), matching the memory
-- backend and the validated projection.
putCredentialStmt :: CredentialRecord -> (Text, [S.SQLData])
putCredentialStmt c =
  ( "INSERT OR REPLACE INTO credentials (token_id, record_json, format_version) VALUES (?, ?, 1)"
  , [ S.SQLText (T.pack (encodeHex16 (unTokenId (crToken c))))
    , S.SQLText (T.pack (encodeCredentialRecord c))
    ]
  )

-- | Keep the first put per home token (the 'firstByToken'
-- precedent: the validated projection and the memory backend
-- both resolve duplicate puts first-wins).
firstByCredential :: [CredentialRecord] -> [CredentialRecord]
firstByCredential = go []
  where
    go :: [TokenId] -> [CredentialRecord] -> [CredentialRecord]
    go _ [] = []
    go seen (c : rest)
      | crToken c `elem` seen = go seen rest
      | otherwise = c : go (crToken c : seen) rest

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

-- | Upsert one token row. An ordinary same-id update preserves the
-- parent row — and therefore every owned object and job — while a
-- conflicting slot still refuses (never silently replacing another
-- token's row). Only an explicit token drop or reset removes
-- children; foreign keys stay on.
putTokenStmt :: TokenRecord -> (Text, [S.SQLData])
putTokenStmt t =
  ( "INSERT INTO tokens (token_id, slot_key, generation_key, record_json, format_version) VALUES (?, ?, ?, ?, 1) ON CONFLICT(token_id) DO UPDATE SET slot_key = excluded.slot_key, generation_key = excluded.generation_key, record_json = excluded.record_json, format_version = excluded.format_version"
  , [ S.SQLText (T.pack (encodeHex16 (unTokenId (trId t))))
    , S.SQLBlob (encodeBlob8 (unSlotId (trSlot t)))
    , S.SQLBlob (encodeBlob8 (unGeneration (trGeneration t)))
    , S.SQLText (T.pack (encodeTokenRecord t))
    ]
  )

-- | Park one token on a staging slot. The row keeps its
-- 'token_id' (a put for a not-yet-existing token matches nothing
-- and changes nothing); owned objects and jobs keep referencing
-- the same parent throughout.
stageTokenStmt :: Int -> TokenRecord -> (Text, [S.SQLData])
stageTokenStmt tmp t =
  ( "UPDATE tokens SET slot_key = ? WHERE token_id = ?"
  , [ S.SQLBlob (encodeBlob8 tmp)
    , S.SQLText (T.pack (encodeHex16 (unTokenId (trId t))))
    ]
  )

-- | Keep the first put per token id. The validated projection
-- ('checkSlotUnique') and the memory backend both resolve
-- duplicate puts first-wins, so staging and upserting only the
-- first occurrence commits exactly what validation approved.
firstByToken :: [TokenRecord] -> [TokenRecord]
firstByToken = go []
  where
    go :: [TokenId] -> [TokenRecord] -> [TokenRecord]
    go _ [] = []
    go seen (t : rest)
      | trId t `elem` seen = go seen rest
      | otherwise = t : go (trId t : seen) rest

-- | Pick @n@ staging slots disjoint from every occupied slot
-- (current plus final). Candidates cover the whole 'Int' range
-- from zero upward (reaching the negatives only past
-- 'maxBound'), skipping anything occupied, so the result never
-- collides with a live slot however slots are valued — including
-- at the range boundaries, where ascending past the maximum
-- alone would run dry.
pickTempSlots :: [Int] -> Int -> [Int]
pickTempSlots occupied n =
  take n [c | c <- [0 .. maxBound] ++ [minBound .. -1], c `notElem` occupied]

-- | Decode one @slot_key@ cell.
parseSlotKey :: [S.SQLData] -> Maybe Int
parseSlotKey [S.SQLBlob b] = decodeBlob8 b
parseSlotKey _ = Nothing

-- | Upsert one meta row.
putMetaStmt :: (String, String) -> (Text, [S.SQLData])
putMetaStmt (k, v) =
  ( "INSERT OR REPLACE INTO store_meta(key, value) VALUES (?, ?)"
  , [S.SQLText (T.pack k), S.SQLText (T.pack v)]
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

-- | Roll back best-effort (exception-path cleanup before the
-- handle close; errors ignored).
rollbackQuiet :: S.Database -> IO ()
rollbackQuiet db = do
  _ <- trySQLite (S.exec db "ROLLBACK")
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

-- ---------------------------------------------------------------
-- Read-only snapshot and owner probe

-- | Device, inode, size and mtime (seconds) of a file.
data FileIdentity = FileIdentity
  { fiDevice :: !Integer, fiInode :: !Integer, fiSize :: !Integer, fiMtime :: !Integer }
  deriving (Eq, Show)

-- | What a read-only look at a store found. Credential rows are
-- reduced to their token ids: no PIN byte leaves this function.
data StoreSnapshot = StoreSnapshot
  { snapSchema :: !Int                 -- 1, 2 or 3
  , snapTokens :: ![TokenRecord]       -- token-id ascending
  , snapObjectCount :: !Int
  , snapJobCount :: !Int
  , snapCredentialTokens :: ![TokenId] -- ascending; [] for schema 1
  , snapMeta :: ![(String, String)]    -- sorted
  , snapFile :: !FileIdentity
  } deriving (Eq, Show)

-- | Whether some owner holds the store.
data OwnerState
  = OwnerAbsent        -- ^ no sidecar lock; kernel lock free
  | OwnerStale !Int    -- ^ sidecar names a dead pid; kernel lock free (left in place)
  | OwnerLive !String  -- ^ live, unknowable or kernel-held owner (fail closed): the reason
  deriving (Eq, Show)

fileIdentity :: FileStatus -> FileIdentity
fileIdentity st = FileIdentity
  (toInteger (deviceID st)) (toInteger (fileID st)) (toInteger (fileSize st))
  (truncate (toRational (modificationTime st)))

-- | What the rollback journal beside a store is: missing (or empty,
-- which SQLite ignores, as today), cold (SQLite treats it as not
-- hot), hot (an interrupted write SQLite would roll back), or
-- unknown (anything else: fail closed).
data JournalClass = JournalAbsent | JournalCold | JournalHot | JournalUnknown
  deriving (Eq, Show)

-- | SQLite's rollback-journal magic, the first 8 header bytes of a
-- hot journal: d9d505f9 20a163d7.
journalMagic :: ByteString
journalMagic = BS.pack [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]

-- | Classify the rollback journal beside a store by its size and its
-- first 8 bytes: hot carries the journal magic, cold is all zero,
-- anything else -- including a short file or an unreadable one -- is
-- unknown and fails closed. An empty journal reads as absent, as
-- SQLite ignores it. Only a regular file is ever opened: a symlink,
-- FIFO or device is unknown, so classification never hangs and never
-- follows a link.
classifyJournal :: FilePath -> IO JournalClass
classifyJournal path = do
  e <- tryIOError (getSymbolicLinkStatus journal)
  case e of
    Left _ -> pure JournalAbsent
    Right st
      | not (isRegularFile st) -> pure JournalUnknown
      | fileSize st <= 0 -> pure JournalAbsent
      | otherwise -> do
          eHead <- tryIOError (readFirst8 journal)
          pure (case eHead of
            Right h | h == journalMagic -> JournalHot
            Right h | h == BS.replicate 8 0 -> JournalCold
            _ -> JournalUnknown)
  where
    journal = path ++ "-journal"

-- | The first 8 bytes of a file (fewer if it is short), read through
-- a close-on-exec descriptor.
readFirst8 :: FilePath -> IO ByteString
readFirst8 p = bracket open hClose (`BS.hGet` 8)
  where open = bracketOnError (openFd p ReadOnly guardFlags) closeFd fdToHandle

-- | A sibling the rollback-journal store never writes itself: a
-- non-empty @-wal@ or @-shm@ file can only come from foreign tooling
-- and refuses the snapshot like a hot journal. Zero-byte files are
-- ignored, as zero-byte journals are.
foreignSidecar :: FilePath -> IO (Maybe FilePath)
foreignSidecar path = do
  w <- nonEmpty (path ++ "-wal")
  s <- nonEmpty (path ++ "-shm")
  pure (case (w, s) of
    (Just p, _) -> Just p
    (_, Just p) -> Just p
    _ -> Nothing)
  where
    nonEmpty p = do
      e <- tryIOError (getSymbolicLinkStatus p)
      pure (case e of
        Right st | fileSize st > 0 -> Just p
        _ -> Nothing)

-- | A journal or foreign sibling that refuses the snapshot: a
-- non-empty @-wal@ or @-shm@ file first (a cold journal must never
-- bypass it), else a hot or unknown journal, else a cold journal
-- (refused distinctly).
journalBlocked :: FilePath -> IO (Maybe StoreError)
journalBlocked path = do
  side <- foreignSidecar path
  case side of
    Just p -> pure (Just (StoreJournalPresent p))
    Nothing -> do
      cls <- classifyJournal path
      pure (case cls of
        JournalHot -> Just (StoreJournalPresent journal)
        JournalUnknown -> Just (StoreJournalPresent journal)
        JournalCold -> Just (StoreJournalCold journal)
        JournalAbsent -> Nothing)
  where
    journal = path ++ "-journal"

-- | Like 'journalBlocked' but a cold journal does not block: used
-- only to plan a migration's verdict before deciding whether the
-- cold journal may be cleared. Hot, unknown and foreign siblings
-- still refuse.
journalBlockedAllowCold :: FilePath -> IO (Maybe StoreError)
journalBlockedAllowCold path = do
  side <- foreignSidecar path
  case side of
    Just p -> pure (Just (StoreJournalPresent p))
    Nothing -> do
      cls <- classifyJournal path
      pure (case cls of
        JournalHot -> Just (StoreJournalPresent journal)
        JournalUnknown -> Just (StoreJournalPresent journal)
        _ -> Nothing)
  where
    journal = path ++ "-journal"

-- | Any @-wal@ or @-shm@ sibling, even zero-byte: a read-write
-- SQLite connection would act on it (switching journal modes,
-- checkpointing frames, creating and deleting the peer file), so
-- the cold-journal clear refuses before opening whenever either
-- exists, whatever its size or kind.
anySidecarExists :: FilePath -> IO (Maybe FilePath)
anySidecarExists path = do
  w <- exists (path ++ "-wal")
  s <- exists (path ++ "-shm")
  pure (case (w, s) of
    (Just p, _) -> Just p
    (_, Just p) -> Just p
    _ -> Nothing)
  where
    exists p = do
      e <- tryIOError (getSymbolicLinkStatus p)
      pure (case e of
        Right _ -> Just p
        _ -> Nothing)

-- | Read a store WITHOUT writing it: no ownership, no sidecar, a
-- read-only connection (never creates the file, never recovers a
-- journal, never migrates). Decodes every record the serving open
-- decodes, so a corrupt file fails here too; keeps only ids and
-- counts. Refuses a foreign -wal/-shm sibling, a hot or unknown
-- journal, a cold journal (distinctly), and a file that changed
-- while read.
readStoreSnapshot :: FilePath -> IO (Either StoreError StoreSnapshot)
readStoreSnapshot = readStoreSnapshotWith journalBlocked

-- | Like 'readStoreSnapshot' but a cold journal does not refuse:
-- used only to plan a migration's verdict before deciding whether
-- the cold journal may be cleared. The read-only connection treats
-- a cold journal as not hot (committed state), never recovers it
-- and never writes.
readStoreSnapshotAllowCold :: FilePath -> IO (Either StoreError StoreSnapshot)
readStoreSnapshotAllowCold = readStoreSnapshotWith journalBlockedAllowCold

readStoreSnapshotWith
  :: (FilePath -> IO (Maybe StoreError)) -> FilePath -> IO (Either StoreError StoreSnapshot)
readStoreSnapshotWith blockedBy path = do
  eSt0 <- tryIOError (getFileStatus path)
  case eSt0 of
    Left _ -> pure (Left (StoreIO ("no store file at " ++ path)))
    Right st0
      | not (isRegularFile st0) -> pure (Left (StoreIO (path ++ ": not a regular file")))
      | otherwise -> do
          blocked <- blockedBy path
          case blocked of
            Just err -> pure (Left err)
            Nothing -> do
              eDb <- trySQLite (S.open2 (T.pack path) [S.SQLOpenReadOnly] S.SQLVFSDefault)
              case eDb of
                Left err -> pure (Left err)
                Right db -> do
                  r <- snapshotDb db `finally` closeQuiet db
                  eSt1 <- tryIOError (getFileStatus path)
                  blocked1 <- blockedBy path
                  pure $ case (r, eSt1, blocked1) of
                    (Left err, _, _) -> Left err
                    (_, Left _, _) -> Left (StoreIO (path ++ ": vanished while read"))
                    (Right _, Right _, Just err) -> Left err
                    (Right mk, Right st1, Nothing)
                      | fileIdentity st0 /= fileIdentity st1 ->
                          Left (StoreIO (path ++ ": changed while read; retry with the owner stopped"))
                      | otherwise -> Right (mk (fileIdentity st1))
  where
    snapshotDb db = do
      eTables <- queryRows db "SELECT name FROM sqlite_master WHERE type = 'table'" []
      case eTables of
        Left err -> pure (Left err)
        Right rows -> do
          let names = [t | [S.SQLText t] <- rows]
          eVer <- if "store_meta" `elem` names
            then queryRows db "SELECT value FROM store_meta WHERE key = 'schema_version'" []
            else pure (Right [])
          case classifySchema path names eVer of
            Left err -> pure (Left err)
            Right v -> do
              eToks <- loadTokens db
              eJobs <- loadJobs db
              eCreds <- if v >= 2 then loadCredentials db else pure (Right [])
              eMeta <- loadMeta db
              pure $ do
                toks <- eToks
                jobs <- eJobs
                creds <- eCreds
                meta <- eMeta
                Right (StoreSnapshot v (map fst toks) (sum (map (length . snd) toks))
                  (length jobs) (sort (map crToken creds)) (sort meta))

-- | Whether some owner holds the store, without taking anything: the
-- sidecar pid ('pidLiveness', fail closed on unknowable), then a
-- shared non-blocking kernel lock on a read-only database fd,
-- released at once. Never creates, removes or rewrites a lock.
probeOwner :: FilePath -> IO OwnerState
probeOwner path = do
  procRoot <- procRootFromEnv
  me <- getProcessID
  let lockPath = path ++ ".lock"
  eLock <- tryIOError (getSymbolicLinkStatus lockPath)
  sidecar <- case eLock of
    Left e | isDoesNotExistError e -> pure (Right Nothing)
           | otherwise -> pure (Left "the lock file cannot be examined")
    Right _ -> do
      eContent <- tryIOError (readFileCloexec lockPath)
      case eContent of
        Left _ -> pure (Left "the lock file is unreadable")
        Right content -> case reads (BC8.unpack content) of
          [(n, _) :: (Int, String)]
            | n == fromIntegral me -> pure (Left "this process holds the store")
            | otherwise -> do
                live <- pidLiveness procRoot n
                pure $ case live of
                  PidAlive -> Left ("pid " ++ show n ++ " holds the lock")
                  PidUnknown -> Left ("pid " ++ show n ++ " holds the lock; its liveness is unknowable")
                  PidDead -> Right (Just n)
          _ -> pure (Left "the lock file names no pid")
  case sidecar of
    Left why -> pure (OwnerLive why)
    Right stale -> do
      held <- kernelLockHeld path
      pure $ case (held, stale) of
        (Left why, _) -> OwnerLive why
        (Right True, _) -> OwnerLive "the database kernel lock is held"
        (Right False, Nothing) -> OwnerAbsent
        (Right False, Just n) -> OwnerStale n

-- | Try a SHARED non-blocking flock on a read-only fd and drop it at
-- once. A missing file has no holder; any other failure to probe is a
-- 'Left' reason the caller treats as live (fail closed), never as a
-- held lock. A lock that reads held is retried briefly (five attempts
-- over 20 ms): a forked child that has not exec'd yet keeps an
-- inherited copy past the owner's close, and that transient holder
-- must not refuse the probe. A truly live owner stays held through
-- every attempt. The fd is closed on every path, including an
-- asynchronous exception during the waits (the waits stay
-- interruptible under the mask).
kernelLockHeld :: FilePath -> IO (Either String Bool)
kernelLockHeld path = mask_ $ do
  eFd <- tryIOError (openFd path ReadOnly guardFlags)
  case eFd of
    Left e
      | isDoesNotExistError e -> pure (Right False)
      | otherwise -> pure (Left "the database cannot be opened to probe its lock")
    Right fd -> do
      held <- attempt fd 0 `finally` closeQuietFd fd
      pure (Right held)
  where
    attempt :: Fd -> Int -> IO Bool
    attempt fd n = do
      ok <- (== 0) <$> c_flock (fromIntegral fd) (lockSh .|. lockNb)
      if ok || n >= 4 then pure (not ok) else threadDelay 5000 >> attempt fd (n + 1)

lockSh :: CInt
lockSh = 1 -- LOCK_SH: shared

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
withOwnedStoreFile :: FilePath -> (OwnedStoreFile -> IO a) -> IO (Either StoreError a)
withOwnedStoreFile path act = mask $ \restore -> do
  exists <- fileExist path
  if not exists then pure (Left (StoreIO ("no store file at " ++ path))) else do
    procRoot <- procRootFromEnv
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
                let release = closeQuietFd dbFd >> releaseQuiet lockFd lockPath
                r <- restore (act (OwnedStoreFile path dbFd)) `onException` release
                release
                pure (Right r)

-- | Remove a cold rollback journal, only when every guard holds: the
-- owner probe passes, this call holds single-writer ownership (the
-- sidecar plus the database kernel guard), no @-wal@ or @-shm@
-- sibling exists (even zero-byte: the read-write connection below
-- would act on it), a plain connection takes a SQLite RESERVED lock
-- (@BEGIN IMMEDIATE@ fails while any other connection writes), and
-- the re-read journal is still cold. Removing it cannot change what
-- SQLite reads: the zeroed magic already makes SQLite treat the
-- journal as not hot. Anything else refuses, fail closed: a live
-- owner reports live, a sibling reports it, a busy database or a
-- changed journal reports the cold journal again.
clearColdJournal :: FilePath -> IO (Either StoreError ())
clearColdJournal path = do
  owner <- probeOwner path
  case owner of
    OwnerLive why -> pure (Left (StoreSecondWriter ("store is in use (" ++ why ++ "): " ++ path)))
    _ -> do
      owned <- withOwnedStoreFile path clearOwned
      pure (either Left id owned)
  where
    journal = path ++ "-journal"
    clearOwned _owned = do
      side <- anySidecarExists path
      case side of
        Just p -> pure (Left (StoreJournalPresent p))
        Nothing -> do
          eDb <- trySQLite (S.open (T.pack path))
          case eDb of
            Left err -> pure (Left err)
            Right db -> do
              r <- clearWith db `onException` (rollbackQuiet db >> closeQuiet db)
              closeQuiet db
              pure r
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
                Left e -> do
                  rollbackQuiet db
                  pure (Left (StoreIO ("cannot remove the cold journal " ++ journal ++ ": " ++ show e)))
                Right () -> do
                  eSync <- tryIOError (syncParentDir journal)
                  eCommit <- trySQLite (S.exec db "COMMIT")
                  pure (case (eCommit, eSync) of
                    (Left err, _) -> Left err
                    (Right (), Left e) -> Left (StoreIO ("cannot sync the store directory: " ++ show e))
                    (Right (), Right ()) -> Right ())
            _ -> do
              rollbackQuiet db
              pure (Left (StoreJournalCold journal))
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

-- | Migrate an owned store to 'sqliteSchemaVersion' in ONE
-- transaction: re-read the marker (it must still be 'smFrom'),
-- create the credentials table for version 1, INSERT every frozen
-- row (never replacing: an existing row aborts everything), and
-- advance the marker unless the store is already current. Any
-- failure rolls back and leaves the file as it was; an exception
-- rolls back, closes and re-throws.
migrateOwned :: OwnedStoreFile -> SQLiteMigration -> MigrationHooks -> IO (Either StoreError ())
migrateOwned owned mig hooks = mask $ \restore -> do
  let path = osfPath owned
  same <- sameFile (osfDbFd owned) path
  if not same then pure (Left (StoreIO ("store database replaced while owned: " ++ path))) else do
    eDb <- trySQLite (S.open (T.pack path))
    case eDb of
      Left err -> pure (Left err)
      Right db -> do
        r <- restore (txn db path) `onException` (rollbackQuiet db >> closeQuiet db)
        closeQuiet db
        pure r
  where
    txn db path = do
      eCfg <- configure db
      case eCfg of
        Left err -> pure (Left err)
        Right () -> do
          eBegin <- trySQLite (S.exec db "BEGIN IMMEDIATE")
          case eBegin of
            Left err -> pure (Left err)
            Right () -> do
              mgAfterBegin hooks db
              eBody <- body db path
              case eBody of
                Left err -> rollbackQuiet db >> pure (Left err)
                Right () -> do
                  mgBeforeCommit hooks db
                  eCommit <- trySQLite (S.exec db "COMMIT")
                  case eCommit of
                    Left err -> rollbackQuiet db >> pure (Left err)
                    Right () -> pure (Right ())
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
