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

import Control.Concurrent (threadDelay)
import Control.Concurrent.MVar (MVar, modifyMVar_, newMVar, readMVar)
import Control.Exception (SomeException, bracket, bracketOnError, finally, mask, mask_, onException, throwIO, try)
import Control.Monad (when)
import Data.Bits ((.|.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import qualified Data.ByteString.Char8 as BC8
import Data.List (intercalate, nub, sort)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe)
import qualified Data.Text as T
import Data.Text (Text)
import Data.Word (Word64)
import qualified Database.SQLite3 as S
import Database.SQLite3.Direct (getAutoCommit)
import Foreign.C.Types (CInt (..))
import System.Environment (lookupEnv)
import System.IO.Error (ioeGetErrorString, isAlreadyExistsError, isDoesNotExistError, tryIOError)
import System.Posix.Files (FileStatus, deviceID, fileExist, fileID, fileSize, getFdStatus, getFileStatus, getSymbolicLinkStatus, isRegularFile, modificationTime, readSymbolicLink, removeLink, setFdSize, setFileMode)
import System.IO (hClose)
import System.Posix.IO (OpenFileFlags (..), OpenMode (..), closeFd, defaultFileFlags, fdToHandle, fdWrite, openFd)
import System.Posix.IO.ByteString (fdRead)
import System.Posix.Process (getParentProcessID, getProcessID)
import System.Posix.Types (Fd, ProcessID)
import System.Posix.Unistd (fileSynchronise)

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
-- | The @\/proc@ root for owner-liveness checks. Honoured only
-- with the env-seam opt-in (@True@): @HASKOKI_PROC_ROOT@ overrides
-- (tests mask liveness deterministically); empty or unset means
-- @\/proc@. Any override that hides a live owner fails closed
-- (the opener is refused), never open — and the kernel lock below
-- backstops every @\/proc@ verdict. Without the opt-in the
-- environment is not consulted at all: always @\/proc@.
procRootFromEnv :: Bool -> IO FilePath
procRootFromEnv False = pure "/proc"
procRootFromEnv True = do
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
guardFlags = defaultFileFlags { cloexec = True, nonBlock = True, nofollow = True }
-- | All bytes of a file, read through a 'guardFlags' descriptor. A GHC
-- 'Handle' open ('readFile', 'BS.readFile') does not set O_CLOEXEC, so
-- a concurrent fork+exec could inherit it.
readFileCloexec :: FilePath -> IO ByteString
readFileCloexec p = bracket open hClose BS.hGetContents
  where open = bracketOnError (openFd p ReadOnly guardFlags) closeFd fdToHandle
-- | A lock sidecar's pid line through a 'guardFlags' descriptor: a
-- single raw 64-byte read (lock files only ever hold @pid\n@, so a
-- bounded read cannot be swamped), and the pid line must be complete
-- (a missing newline fails closed instead of parsing a truncated
-- pid). Raw 'fdRead', not a 'Handle': on a swapped-in FIFO the
-- O_NONBLOCK read surfaces end-of-file or an error at once instead
-- of waiting. Callers lstat first and only call this on regular
-- files.
readLockBytes :: FilePath -> IO ByteString
readLockBytes p = bracket (openFd p ReadOnly guardFlags) closeFd $ \fd -> do
  bs <- fdRead fd 64
  if BS.elem 10 bs then pure bs else ioError (userError ("lock file has no pid line: " ++ p))
-- | Why a lock read failed: an empty file (a crash between create
-- and pid write, or a power loss leaving a zero-length file), a
-- small readable file without a pid line (complete contents, so
-- unparsable rather than unreadable), or truly unreadable
-- (permission denied, oversized without a line in the first 64
-- bytes, or a race). Only the first two consult the kernel flock;
-- the last fails closed without it, preserving the oversized and
-- permission-denied refusals.
data LockReadFailure = LockEmpty | LockSmallUnparsable | LockUnreadable deriving (Eq, Show)
-- | Classify a 'readLockBytes' failure from the file size and a
-- bounded re-read. Runs only on the failure path; the re-read is
-- capped by the size check, so it cannot be swamped.
classifyLockReadFailure :: FilePath -> IO LockReadFailure
classifyLockReadFailure p = do
  eSt <- tryIOError (getFileStatus p)
  case eSt of
    Left _ -> pure LockUnreadable
    Right st
      | fileSize st == 0 -> pure LockEmpty
      | fileSize st > 64 -> pure LockUnreadable
      | otherwise -> do
          eFull <- tryIOError (readFileCloexec p)
          pure (case eFull of
            Right full | not (BS.elem 10 full) -> LockSmallUnparsable
            _ -> LockUnreadable)
-- | lstat without following the final component and without opening:
-- missing files report 'Nothing' (callers keep their create/absent
-- paths); present files report their status for a regular-file
-- check. Other I\/O failures report 'Left'. A FIFO can never hang
-- this call.
lstatOpt :: FilePath -> IO (Either String (Maybe FileStatus))
lstatOpt path = do
  e <- tryIOError (getSymbolicLinkStatus path)
  pure $ case e of
    Left err
      | isDoesNotExistError err -> Right Nothing
      | otherwise -> Left (show err)
    Right st -> Right (Just st)
-- | Refuse anything but a regular file or a missing path (missing
-- paths keep their downstream report): lstat only, never opened, so
-- a FIFO cannot hang the caller.
requireRegularStore :: FilePath -> IO (Either StoreError ())
requireRegularStore path = do
  e <- lstatOpt path
  pure $ case e of
    Right (Just st) | not (isRegularFile st) ->
      Left (StoreIO ("not a regular file: " ++ path))
    _ -> Right ()
-- | Take single-writer ownership via an O_EXCL sidecar lock carrying
-- our pid. An existing lock is taken over when the kernel flock
-- confirms no live holder — the same pid, a live pid, an
-- unknowable pid, an unparsable pid, an empty file, or a dead pid
-- (a crashed run) — within a bounded number of retries; a held
-- kernel lock refuses explicitly. Taking over never touches the
-- database bytes. Success returns the held-open flocked lock fd,
-- which the caller keeps for the lock's lifetime.
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
        Left e
          | isAlreadyExistsError e ->
              inspectLock dbPath lockPath procRoot pid attempts
          | otherwise -> do
              -- The create itself failed (read-only directory or
              -- mount, no space, ...): unless a rival won the race
              -- and the lock exists now (diagnose the lock), say
              -- exactly that — never a live owner.
              eSt <- tryIOError (getSymbolicLinkStatus lockPath)
              case eSt of
                Right _ -> inspectLock dbPath lockPath procRoot pid attempts
                Left _ -> pure (Left (StoreIO
                  ("store lock cannot be created: " ++ lockPath
                    ++ " (" ++ ioeGetErrorString e ++ ")")))
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
-- | Diagnose an existing lock: the kernel flock is the authority
-- for the same pid, a live pid, an unknowable pid, an unparsable
-- pid, and an empty file — a free lock is taken over and the pid
-- rewritten, a held lock refuses with the @\/proc@ verdict kept
-- only for the message text. A dead pid takes over as before, and
-- a truly unreadable lock fails safe. Owner pids compare as text,
-- avoiding any orphan 'Read' instances.
inspectLock :: FilePath -> FilePath -> FilePath -> ProcessID -> Int -> IO (Either StoreError Fd)
inspectLock dbPath lockPath procRoot pid attempts = do
  eSt <- tryIOError (getSymbolicLinkStatus lockPath)
  case eSt of
    Right st | not (isRegularFile st) ->
      pure (Left (StoreSecondWriter ("store lock is not a regular file: " ++ lockPath)))
    _ -> do
      eContent <- tryIOError (BC8.unpack <$> readLockBytes lockPath)
      case eContent of
        Left _ -> do
          failure <- classifyLockReadFailure lockPath
          case failure of
            LockEmpty -> takeOver ("store is locked and the lock file is empty: " ++ lockPath)
            LockSmallUnparsable -> takeOver ("store is locked by an unknown owner: " ++ lockPath)
            LockUnreadable -> pure (Left (StoreSecondWriter
              ("store is locked and the owner is unreadable: " ++ lockPath)))
        Right content -> inspectContent content
  where
    takeOver heldMsg = confirmTakeoverWithReason dbPath lockPath procRoot pid attempts heldMsg
    inspectContent content = case reads content of
      [(ownerN, _) :: (Int, String)] | show ownerN == show pid ->
        takeOver ("store is already open in this process: " ++ dbPath)
      [(ownerN, _) :: (Int, String)] -> do
        live <- pidLiveness procRoot ownerN
        case live of
          PidAlive -> takeOver ("store is already open by pid " ++ show ownerN ++ ": " ++ dbPath)
          PidUnknown -> takeOver ("store is locked by pid " ++ show ownerN
            ++ " but owner liveness is unknowable (/proc unreadable); refusing second writer: " ++ dbPath)
          PidDead -> confirmTakeover dbPath lockPath procRoot pid attempts
      _ -> takeOver ("store is locked by an unknown owner: " ++ lockPath)
-- | Owner-liveness verdict: alive, provably dead (sufficient
-- death evidence), or unknowable (anything else: masked,
-- unreadable, or partially hidden proc). Unknowable fails closed
-- while the kernel lock is held; a free lock proceeds to takeover
-- (which still needs a writable sidecar).
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
-- | True exactly when a pid reads dead ('PidDead') through the
-- consulted @\/proc@ view: the real @\/proc@ by default, the
-- @HASKOKI_PROC_ROOT@ view only with the env-seam opt-in. Hiding
-- ONLY the owner entry reads a live pid dead; hiding any required
-- witness instead (@self@, our own pid, or the parent entry) fails
-- closed through 'PidUnknown', which reads alive here. Anything
-- unknowable is alive (fail closed: the caller must not act on it).
pidIsDead :: Bool -> Int -> IO Bool
pidIsDead allowEnv pid = do
  procRoot <- procRootFromEnv allowEnv
  live <- pidLiveness procRoot pid
  pure (live == PidDead)
-- | Take over an apparently-stale lock: the kernel lock confirms
-- staleness (a live-but-hidden owner still holds it, and we refuse),
-- and an fstat-vs-path revalidation closes the unlink race (a lock
-- unlinked by a concurrently-closing owner is retried, never adopted
-- orphaned). The winner's pid is written in place and the held-open
-- flocked fd returned, so deleting the path cannot grant a second
-- writer while the new owner lives.
confirmTakeover :: FilePath -> FilePath -> FilePath -> ProcessID -> Int -> IO (Either StoreError Fd)
confirmTakeover dbPath lockPath procRoot pid attempts =
  confirmTakeoverWithReason dbPath lockPath procRoot pid attempts
    ("store lock is held by a live owner (kernel lock held on "
      ++ lockPath ++ "); refusing second writer: " ++ dbPath)
-- | Like 'confirmTakeover', but a held kernel lock refuses with the
-- caller's reason (the @\/proc@ verdict for the message text) rather
-- than the generic kernel-held line. A free lock is taken over
-- identically: the pid is rewritten and the flocked fd returned. A
-- genuine second open in the same process still refuses, because
-- flock is per open file description.
confirmTakeoverWithReason :: FilePath -> FilePath -> FilePath -> ProcessID -> Int -> String -> IO (Either StoreError Fd)
confirmTakeoverWithReason dbPath lockPath procRoot pid attempts heldMsg = do
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
      eSt <- tryIOError (getFdStatus fd) `onException` closeQuietFd fd
      case eSt of
        Right st | not (isRegularFile st) -> do
          closeQuietFd fd
          pure (Left (StoreSecondWriter ("store lock is not a regular file: " ++ lockPath)))
        _ -> do
          locked <- tryFlock fd `onException` closeQuietFd fd
          if not locked
            then do
              closeQuietFd fd
              pure (Left (StoreSecondWriter heldMsg))
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
          eSt <- lstatOpt dbPath
          case eSt of
            Right (Just st) | not (isRegularFile st) ->
              pure (Left (StoreIO ("not a regular file: " ++ dbPath)))
            _ -> do
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
-- ---------------------------------------------------------------------------
-- Statements
-- ---------------------------------------------------------------------------
-- ---------------------------------------------------------------------------
-- SQL helpers
-- ---------------------------------------------------------------------------
-- ---------------------------------------------------------------------------
-- Stats
-- ---------------------------------------------------------------------------
-- ---------------------------------------------------------------------------
-- Full-width codecs (SQLite domain)
-- ---------------------------------------------------------------------------
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
  = OwnerAbsent        -- ^ no live holder; kernel lock free (sidecar absent or stale but unclaimed)
  | OwnerStale !Int    -- ^ sidecar names a dead pid; kernel lock free (left in place)
  | OwnerLive !String  -- ^ kernel-held, truly unreadable, or unknowable-with-held-lock owner: the reason
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
-- non-empty @-wal@ or @-shm@ file means foreign tooling — or the
-- snapshot's own read-only open of a WAL-format database, which
-- can create them itself — and refuses distinctly. Zero-byte
-- files are ignored, as zero-byte journals are.
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
    Just p -> pure (Just (StoreForeignSidecar p))
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
-- to plan a migration's verdict (before deciding whether the
-- cold journal may be cleared) and by 'store check''s
-- cold-tolerant retry. Hot, unknown and foreign siblings
-- still refuse.
journalBlockedAllowCold :: FilePath -> IO (Maybe StoreError)
journalBlockedAllowCold path = do
  side <- foreignSidecar path
  case side of
    Just p -> pure (Just (StoreForeignSidecar p))
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
-- | Resolve a store path once, following every symlink component (a
-- full realpath over 'readSymbolicLink'): SQLite acts on the real
-- file's sidecars, so the guards must derive @-journal@, @-wal@,
-- @-shm@ and @.lock@ from the resolved path, and every open must
-- use it. Symlinked store paths stay legitimate (they resolve;
-- they are never refused for being links). Missing components are
-- kept lexically (the caller reports them); a symlink loop falls
-- back to the input unchanged (the downstream open then fails
-- closed). No @filepath@ dependency: the splitting is local.
resolveStorePath :: FilePath -> IO FilePath
resolveStorePath p = fst <$> resolveStorePathTracked p
-- | Normalize a store spelling, then resolve it: bare @file:@
-- URIs decode once up front, so every guard and SQLite itself
-- act on the same decoded POSIX path. Anything that would let
-- the two diverge (query/fragment, undecodable, nested, or
-- empty) refuses instead, and the RESOLVED spelling re-checks
-- ('recheckResolved'): resolution can produce a @file:@ URI
-- the decode never saw, or pass through @:memory:@, which
-- SQLite treats specially while the guards stat it as a file.
resolveStoreSpelling :: FilePath -> IO (Either SpellingRefusal FilePath)
resolveStoreSpelling p = fmap fst <$> resolveStoreSpellingTracked p
-- | Like 'resolveStoreSpelling', also reporting whether the
-- store path's own final component was a symlink (same contract
-- as 'resolveStorePathTracked', on the effective spelling,
-- re-checked after resolving).
resolveStoreSpellingTracked :: FilePath -> IO (Either SpellingRefusal (FilePath, Bool))
resolveStoreSpellingTracked p = case effectiveStorePath p of
  Left r -> pure (Left r)
  Right eff -> do
    (res, saw) <- resolveStorePathTracked eff
    pure $ case recheckResolved res of
      Left r -> Left r
      Right ok -> Right (ok, saw)
-- | Run a store operation on the normalized spelling: refusal
-- short-circuits in 'StoreError' before anything touches the
-- filesystem.
withStoreSpelling :: FilePath -> (FilePath -> IO (Either StoreError a)) -> IO (Either StoreError a)
withStoreSpelling path0 act = do
  ePath <- resolveStoreSpelling path0
  case ePath of
    Left r -> pure (Left (StoreIO (renderSpellingRefusal r path0)))
    Right path -> act path
-- | Like 'resolveStorePath', also reporting whether the store
-- path's own final component was a symlink. The serving open
-- refuses to create a store when the final component is a link and
-- the resolved target is missing (a dangling link means a moved
-- store or an unmounted volume, never a fresh one). A link in an
-- ancestor directory with no store yet is a fresh store, created at
-- the resolved path. A chain's later hops also occur with no
-- components remaining, so they still count as the final link.
resolveStorePathTracked :: FilePath -> IO (FilePath, Bool)
resolveStorePathTracked p
  | null p = pure (p, False)
  | otherwise = follow (splitPath p) [] absolute0 False 0
  where
    absolute0 = case p of ('/' : _) -> True; _ -> False
    -- Absoluteness rides in the fold state: an absolute link target
    -- resets the walk to the filesystem root, so the flag must turn
    -- 'True' at the jump. Computing it once from the input drops the
    -- leading slash when a relative path goes through an absolute
    -- symlink (and misdirects the later link probes at the mangled
    -- relative spelling).
    follow :: [String] -> [String] -> Bool -> Bool -> Int -> IO (FilePath, Bool)
    follow [] stack absolute saw _ = pure (joinPath absolute stack, saw)
    follow (c : cs) stack absolute saw n
      | c == ".." = follow cs (popForDotDot absolute stack) absolute saw n
      | otherwise = do
          eLink <- tryIOError (readSymbolicLink (joinPath absolute (stack ++ [c])))
          case eLink of
            Left _ -> follow cs (stack ++ [c]) absolute saw n
            Right link
              | n >= 40 -> pure (p, saw)
              | otherwise ->
                  -- Only a link at the store's own final component
                  -- counts: no components remain after it (a chain's
                  -- later hops re-enter here the same way). A link
                  -- in an ancestor directory leaves the flag down,
                  -- so a missing store there is created, not
                  -- refused as dangling.
                  let target = splitPath link
                      sawFinal = saw || null cs
                  in case link of
                       ('/' : _) -> follow (target ++ cs) [] True sawFinal (n + 1)
                       _ -> follow (target ++ cs) stack absolute sawFinal (n + 1)
    popForDotDot :: Bool -> [String] -> [String]
    popForDotDot absolute [] = if absolute then [] else [".."]
    popForDotDot absolute stack
      | absolute = init stack
      | last stack == ".." = stack ++ [".."]
      | otherwise = init stack
    splitPath :: FilePath -> [String]
    splitPath = filter (\c -> c /= "" && c /= ".") . splitOn '/'
      where
        splitOn _ [] = [""]
        splitOn d (x : xs)
          | x == d = "" : splitOn d xs
          | otherwise = case splitOn d xs of
              (y : ys) -> (x : y) : ys
              [] -> [[x]]
    joinPath :: Bool -> [String] -> FilePath
    joinPath True [] = "/"
    joinPath True cs = "/" ++ intercalate "/" cs
    joinPath False [] = "."
    joinPath False cs = intercalate "/" cs
-- | Read a store without writing the database: no ownership, a
-- read-only connection (never creates the file, never recovers a
-- journal, never migrates) — but on a WAL-format database the
-- open can create -shm/-wal sidecars when the directory is
-- writable (observed: a 32KiB -shm), which the post-read check
-- then reports as foreign when the snapshot itself succeeded (a
-- snapshot error or a vanished file takes precedence). Decodes
-- every record the serving open decodes, so a structurally
-- corrupt file (missing tables, bad schema version, misshapen
-- rows) fails here too; value-level checks (durable counters
-- must parse positive, see 'loadCounter' vs 'loadMeta') stay
-- with the serving open. Keeps the schema version, token
-- records, credential ids, metadata, counts, and file identity
-- (credential rows reduced to token ids — no PIN byte leaves).
-- Refuses a foreign -wal/-shm sibling, a hot or unknown
-- journal, a cold journal (distinctly), and a file that changed
-- while read.
readStoreSnapshot :: FilePath -> IO (Either StoreError StoreSnapshot)
readStoreSnapshot = readStoreSnapshotWith journalBlocked
-- | Like 'readStoreSnapshot' but a cold journal does not refuse:
-- used to plan a migration's verdict (before deciding whether
-- the cold journal may be cleared) and by 'store check''s
-- cold-tolerant retry. The read-only connection treats
-- a cold journal as not hot (committed state) and never recovers
-- it; like the strict read it can create WAL sidecars on a
-- WAL-format database, but changes no database bytes.
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
-- kernel flock is the authority for the same pid, a live pid, an
-- unknowable pid, an unparsable pid, and an empty file — a free
-- database kernel lock reports offline, a held one reports live
-- with the @\/proc@ verdict kept only for the message text. A dead
-- pid reports stale as before. Never creates, removes or rewrites
-- a lock.
probeOwner :: Bool -> FilePath -> IO OwnerState
probeOwner allowEnv path = do
  procRoot <- procRootFromEnv allowEnv
  me <- getProcessID
  let lockPath = path ++ ".lock"
  eLock <- tryIOError (getSymbolicLinkStatus lockPath)
  case eLock of
    Left e | isDoesNotExistError e -> checkKernel Nothing
           | otherwise -> pure (OwnerLive "the lock file cannot be examined")
    Right st | not (isRegularFile st) -> pure (OwnerLive "the lock file is not a regular file")
    Right _ -> do
      eContent <- tryIOError (readLockBytes lockPath)
      case eContent of
        Left _ -> do
          failure <- classifyLockReadFailure lockPath
          case failure of
            LockEmpty -> checkKernelWithReason "the lock file is empty"
            LockSmallUnparsable -> checkKernelWithReason "the lock file names no pid"
            LockUnreadable -> pure (OwnerLive "the lock file is unreadable")
        Right content -> case reads (BC8.unpack content) of
          [(n, _) :: (Int, String)]
            | n == fromIntegral me -> checkKernelWithReason "this process holds the store"
            | otherwise -> do
                live <- pidLiveness procRoot n
                case live of
                  PidAlive -> checkKernelWithReason ("pid " ++ show n ++ " holds the lock")
                  PidUnknown -> checkKernelWithReason
                    ("pid " ++ show n ++ " holds the lock; its liveness is unknowable")
                  PidDead -> checkKernel (Just n)
          _ -> checkKernelWithReason "the lock file names no pid"
  where
    checkKernel stale = do
      held <- kernelLockHeld path
      pure $ case (held, stale) of
        (Left why, _) -> OwnerLive why
        (Right True, _) -> OwnerLive "the database kernel lock is held"
        (Right False, Nothing) -> OwnerAbsent
        (Right False, Just n) -> OwnerStale n
    checkKernelWithReason reason = do
      held <- kernelLockHeld path
      pure $ case held of
        Left why -> OwnerLive why
        Right True -> OwnerLive reason
        Right False -> OwnerAbsent
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
  eSt <- lstatOpt path
  case eSt of
    Right Nothing -> pure (Right False)
    Right (Just st) | not (isRegularFile st) -> pure (Left "the database is not a regular file")
    Left _ -> pure (Left "the database cannot be opened to probe its lock")
    Right _ -> do
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
