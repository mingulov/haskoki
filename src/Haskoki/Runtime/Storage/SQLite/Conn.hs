{- | SQLite store connection lifecycle and guard.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Conn
  ( withConn
  , withLive
  , connectionQuarantined
  , closeConn
  , sameFile
  , closeQuietFd
  , releaseQuiet
  ) where

import Control.Concurrent.MVar (putMVar, readMVar, takeMVar)
import Control.Exception (bracket_, mask_, throwIO, uninterruptibleMask_)
import Control.Monad (when)
import Data.IORef (readIORef)
import qualified Database.SQLite3 as S
import System.IO.Error (tryIOError)
import System.Posix.Files (deviceID, fileID, getFdStatus, getFileStatus, removeLink)
import System.Posix.IO (closeFd)
import System.Posix.Types (Fd)
import Haskoki.Runtime.Storage
  ( FaultInjector (..)
  , FaultPoint (..)
  , HandleState (..)
  , StoreError (..)
  , storeClosed
  )
import Haskoki.Runtime.Storage.SQLite.Statements
import Haskoki.Runtime.Storage.SQLite.Types

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
