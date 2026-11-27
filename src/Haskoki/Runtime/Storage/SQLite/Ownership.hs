{- | SQLite store fd ownership, locks, and guards.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Ownership
  ( c_flock
  , lockNb
  , guardFlags
  , readFileCloexec
  , readLockBytes
  , LockReadFailure (..)
  , classifyLockReadFailure
  , lstatOpt
  , requireRegularStore
  , takeOwnership
  , claimFresh
  , inspectLock
  , PidLiveness (..)
  , ProcProbe (..)
  , probeProc
  , livenessFromProbes
  , pidLiveness
  , pidIsDead
  , confirmTakeover
  , confirmTakeoverWithReason
  , takeDbGuard
  , ensureDbGuard
  , tryFlock
  , procRootFromEnv
  ) where

import Control.Concurrent (threadDelay)
import Control.Exception (bracket, bracketOnError, mask_, onException)
import Data.Bits ((.|.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Foreign.C.Types (CInt (..))
import System.Environment (lookupEnv)
import System.IO.Error (ioeGetErrorString, isAlreadyExistsError, isDoesNotExistError, tryIOError)
import System.Posix.Files (FileStatus, fileSize, getFdStatus, getFileStatus, getSymbolicLinkStatus, isRegularFile, setFdSize)
import System.IO (hClose)
import System.Posix.IO (OpenFileFlags (..), OpenMode (..), closeFd, defaultFileFlags, fdToHandle, fdWrite, openFd)
import System.Posix.IO.ByteString (fdRead)
import System.Posix.Process (getParentProcessID, getProcessID)
import System.Posix.Types (Fd, ProcessID)
import Haskoki.Runtime.Storage
  ( StoreError (..)
  )
import Haskoki.Runtime.Storage.SQLite.Conn

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

foreign import ccall unsafe "sys/file.h flock" c_flock :: CInt -> CInt -> IO CInt

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
