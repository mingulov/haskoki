{- | SQLite store read-only snapshots and owner probes.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Snapshot
  ( FileIdentity (..)
  , StoreSnapshot (..)
  , OwnerState (..)
  , fileIdentity
  , JournalClass (..)
  , journalMagic
  , classifyJournal
  , readFirst8
  , foreignSidecar
  , journalBlocked
  , journalBlockedAllowCold
  , anySidecarExists
  , resolveStorePath
  , resolveStoreSpelling
  , resolveStoreSpellingTracked
  , withStoreSpelling
  , resolveStorePathTracked
  , readStoreSnapshot
  , readStoreSnapshotAllowCold
  , probeOwner
  , kernelLockHeld
  , lockSh
  ) where

import Control.Concurrent (threadDelay)
import Control.Exception (bracket, bracketOnError, finally, mask_)
import Data.Bits ((.|.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Data.List (intercalate, sort)
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import Foreign.C.Types (CInt (..))
import System.IO.Error (isDoesNotExistError, tryIOError)
import System.Posix.Files (FileStatus, deviceID, fileID, fileSize, getFileStatus, getSymbolicLinkStatus, isRegularFile, modificationTime, readSymbolicLink)
import System.IO (hClose)
import System.Posix.IO (OpenMode (..), closeFd, fdToHandle, openFd)
import System.Posix.Process (getProcessID)
import System.Posix.Types (Fd)
import Haskoki.Runtime.Storage
  ( CredentialRecord (..)
  , StoreError (..)
  , TokenRecord (..)
  )
import Haskoki.Runtime.Trace (SpellingRefusal (..), effectiveStorePath, recheckResolved, renderSpellingRefusal)
import Haskoki.Types (TokenId (..))
import Haskoki.Runtime.Storage.SQLite.Conn
import Haskoki.Runtime.Storage.SQLite.Init
import Haskoki.Runtime.Storage.SQLite.Records
import Haskoki.Runtime.Storage.SQLite.Ownership
import Haskoki.Runtime.Storage.SQLite.Statements

-- ---------------------------------------------------------------------------
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
