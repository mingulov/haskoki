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
  , livenessFromProbes
  , PidLiveness (..)
  , ProcProbe (..)
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.MVar (MVar, modifyMVar_, newMVar, putMVar, readMVar, takeMVar)
import Control.Exception (SomeException, bracket, bracket_, mask, mask_, onException, throwIO, try)
import Control.Monad (when)
import Data.Bits (shiftR, (.&.), (.|.))
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
import Foreign.C.Types (CInt (..))
import System.Environment (lookupEnv)
import System.IO.Error (isAlreadyExistsError, isDoesNotExistError, tryIOError)
import System.Posix.Files (deviceID, fileExist, fileID, fileSize, getFdStatus, getFileStatus, removeLink, setFdSize, setFileMode)
import System.Posix.IO (FdOption (..), OpenFileFlags (..), OpenMode (..), closeFd, defaultFileFlags, fdWrite, openFd, setFdOption)
import System.Posix.Process (getParentProcessID, getProcessID)
import System.Posix.Types (Fd, ProcessID)

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
-- idempotent-close flag, the owned paths, the held-open flocked
-- lock fd (the kernel ownership guard), the held-open flocked
-- database fd (the stable-identity guard: deleting the lock path
-- cannot fork a live owner), and the live-handle protocol state
-- (injector, quarantine, stats).
data SQLiteConn = SQLiteConn
  { sqDb :: !S.Database
  , sqLock :: !(MVar ())
  , sqClosed :: !(MVar Bool)
  , sqPath :: !FilePath
  , sqLockPath :: !FilePath
  , sqLockFd :: !Fd
  , sqDbFd :: !Fd
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
openSQLiteStoreWith path limits inj = mask $ \restore -> do
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
              closed <- newMVar False
              qVar <- newMVar []
              sVar <- newIORef zeroStats
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
                    , sqStats = sVar
                    , sqLimits = limits
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
        defaultFileFlags { creat = Just 0o600, exclusive = True })
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
  _ <- tryIOError (setFdOption fd CloseOnExec True)
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
  eContent <- tryIOError (readFile lockPath)
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
  eFd <- tryIOError (openFd lockPath ReadWrite defaultFileFlags)
  case eFd of
    Left e
      | isDoesNotExistError e -> takeOwnership dbPath lockPath procRoot (attempts - 1)
      | otherwise -> pure (Left (StoreSecondWriter ("store lock cannot be taken over: " ++ lockPath)))
    -- Each fd cleanup scope ends before its explicit close (see
    -- 'claimFresh'): the retry runs outside every scope covering
    -- this fd, so a cancellation during the retry cannot
    -- double-close it after the number is recycled.
    Right fd -> do
      _ <- tryIOError (setFdOption fd CloseOnExec True)
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
  _ <- tryIOError (setFdOption fd CloseOnExec True)
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
          eFd <- tryIOError (openFd dbPath ReadOnly defaultFileFlags)
          case eFd of
            Right fd -> do
              eGuard <- takeDbGuard dbPath fd
              pure (fmap (, False) eGuard)
            Left e
              | isDoesNotExistError e -> do
                  eCr <- tryIOError (openFd dbPath WriteOnly
                    defaultFileFlags { creat = Just 0o600, exclusive = True })
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

-- | Verify an existing database: all four tables present and the
-- schema version exactly ours. Anything else fails WITHOUT writing
-- a single byte. Never closes the handle (owned by 'openAndInit').
verifyExisting :: S.Database -> FilePath -> IO (Either StoreError S.Database)
verifyExisting db path = do
  eTables <- queryRows db "SELECT name FROM sqlite_master WHERE type = 'table'" []
  case eTables of
    Left err -> pure (Left err)
    Right rows -> do
      let names = [t | [S.SQLText t] <- rows]
          want = ["store_meta", "tokens", "objects", "detached_jobs"]
      if all (`elem` names) want
        then checkVersion db path
        else pure (Left (StoreIO (path ++ ": not a haskoki store (missing tables)")))

-- | Check the integer schema version (exactly ours; wrong\/future
-- versions are rejected, never migrated silently — explicit
-- migrations arrive with a future format bump). Never closes the
-- handle (owned by 'openAndInit').
checkVersion :: S.Database -> FilePath -> IO (Either StoreError S.Database)
checkVersion db path = do
  eVer <- queryRows db "SELECT value FROM store_meta WHERE key = 'schema_version'" []
  case eVer of
    Left err -> pure (Left err)
    Right [[S.SQLText v]]
      | v == T.pack (show sqliteSchemaVersion) -> pure (Right db)
      | otherwise -> pure
          (Left (StoreSchemaVersion sqliteSchemaVersion (T.unpack v)))
    Right _ -> pure (Left (StoreCorrupt (path ++ ": corrupt store metadata")))

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
  , storeLoadMeta = withConn conn loadMeta
  }

-- | Run one connection use under the guard lock (async-safe
-- take\/release pairing).
withConn :: SQLiteConn -> (S.Database -> IO a) -> IO a
withConn conn f =
  bracket_ (takeMVar (sqLock conn)) (putMVar (sqLock conn) ()) (f (sqDb conn))

-- | Idempotent close: the database handle closes and the lock
-- (path plus both held kernel guards) is released exactly once;
-- later closes are silent no-ops.
closeConn :: SQLiteConn -> IO ()
closeConn conn = mask_ $ do
  already <- takeMVar (sqClosed conn)
  if already
    then putMVar (sqClosed conn) True
    else do
      _ <- trySQLite (S.close (sqDb conn))
      releaseQuiet (sqLockFd conn) (sqLockPath conn)
      _ <- tryIOError (closeFd (sqDbFd conn))
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
                    , sdPutMeta = []
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
          eMeta <- loadMeta db
          case (eLoaded, eJobs, eMeta) of
            (Right loaded, Right jobs, Right meta)
              | reconcileReload d loaded == ReconciledPresent
              , reconcileJobsReload d jobs == ReconciledPresent
              , reconcileMetaReload d meta == ReconciledPresent -> do
                  bumpCommits sVar
                  postCommitTail inj qVar sVar affected
            (Right _, Right _, Right _) ->
              pure (NotCommitted (StoreIO "ambiguous commit resolved: delta absent"))
            (Left err, _, _) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
            (_, Left err, _) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
            (_, _, Left err) -> do
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
      e7 <- runAll (map putMetaStmt (sdPutMeta d))
      pure (e1 >> e2 >> e3 >> e4 >> e5 >> e6 >> e7)
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

-- | Compare a delta's expected meta rows against reloaded meta
-- with full key/value equality. Every expected row must be
-- present; extra loaded rows (schema bookkeeping) are fine. A
-- metadata-only delta reconciles against meta alone.
reconcileMetaReload :: StoreDelta -> [(String, String)] -> Reconcile
reconcileMetaReload delta loaded
  | all (\(k, v) -> lookup k loaded == Just v) (sdPutMeta delta) = ReconciledPresent
  | otherwise = ReconciledAbsent

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
