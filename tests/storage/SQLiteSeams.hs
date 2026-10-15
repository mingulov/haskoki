{-# LANGUAGE OverloadedStrings #-}
{- | SQLite statement-boundary seams shared by the storage suites.

Everything here runs on the store's OWN connection (through
'Haskoki.Runtime.Storage.SQLite.SQLiteTestHooks') or on a plain
second connection, and stimulates or observes real SQLite
statements inside the real commit transaction:

* 'installWriteLog': connection-local (TEMP) AFTER triggers call a
  Haskell SQL function per row write, so the log outlives any
  rollback and proves which statements ran.
* 'failTokenUpsert': a TEMP trigger that fails the token upsert
  with an injected @RAISE@ (labelled injected: sequencing only).
* 'TxnSeam': an authorizer (@sqlite3_set_authorizer@) that logs
  every @BEGIN@\/@COMMIT@\/@ROLLBACK@ as it is prepared and can
  deny any of them: a denied statement fails at prepare with
  @SQLITE_AUTH@ and never runs, so the native transaction state is
  exactly what the previous statement left (injected cleanup or
  COMMIT failure).
* 'CommitSeam': a commit hook (@sqlite3_commit_hook@) that counts
  every COMMIT reaching the commit point and can turn the next
  one into a rollback: COMMIT then fails with
  @SQLITE_CONSTRAINT_COMMITHOOK@ AFTER SQLite has ended the
  transaction (injected: the native facts — a COMMIT error with
  the connection back in autocommit — are those of a commit whose
  outcome the store cannot establish).
* 'withSharedReadLock': a second plain connection holding an open
  read transaction (a SHARED lock), so a real COMMIT on the store
  connection cannot take its EXCLUSIVE lock and returns
  @SQLITE_BUSY@ after the store's own busy timeout (genuine).
* Raw durable-state readers on a plain connection.
-}
module SQLiteSeams
  ( -- * Write log and injected body failure
    installWriteLog
  , loggedTables
  , laterTables
  , failTokenUpsert
  , injectedMarker
    -- * Transaction-control and commit seams
  , TxnSeam (..)
  , newTxnSeam
  , installTxnSeam
  , CommitSeam (..)
  , newCommitSeam
  , installCommitSeam
  , markCommits
  , commitsSinceMark
  , withSharedReadLock
    -- * Raw durable state
  , dumpTables
  , assertTablesEqual
  , rowsOf
  , queryText
  , queryInt
  ) where

import Control.Exception (bracket)
import Control.Monad (unless)
import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import Database.SQLite3.Direct (Database (..))
import Foreign.C.String (CString, peekCString)
import Foreign.C.Types (CInt (..))
import Foreign.Ptr (FunPtr, Ptr, castPtr, nullPtr)
import Test.Tasty.HUnit (assertEqual, assertFailure)

-- ---------------------------------------------------------------------------
-- Write log and injected body failure
-- ---------------------------------------------------------------------------

-- | The logical tables a delta can write.
loggedTables :: [Text]
loggedTables = "tokens" : laterTables

-- | The tables the groups after the token group write.
laterTables :: [Text]
laterTables = ["objects", "detached_jobs", "credentials", "store_meta"]

-- | Log every row write on the given tables through a Haskell
-- SQL function called from connection-local (TEMP) AFTER
-- triggers. The log lives outside SQLite, so a write that a
-- later rollback undoes still shows that its statement ran.
-- A trigger is part of its table's write statements: it makes
-- SQLite open a statement journal for them, and a statement
-- journal turns SQLITE_FULL into a statement-only rollback. So
-- the genuine-FULL case never logs the failing (token) table.
installWriteLog :: IORef [String] -> [Text] -> S.Database -> IO ()
installWriteLog ref logged db = do
  S.createFunction db "haskoki_test_note" (Just 1) False $ \ctx args -> do
    entry <- S.funcArgText args 0
    modifyIORef' ref (T.unpack entry :)
    S.funcResultNull ctx
  mapM_ (S.exec db . logTrigger)
    [(t, op) | t <- logged, op <- ["INSERT", "UPDATE", "DELETE"]]
  where
    logTrigger (t, op) = T.concat
      [ "CREATE TEMP TRIGGER IF NOT EXISTS haskoki_test_log_", t, "_", op
      , " AFTER ", op, " ON main.", t
      , " BEGIN SELECT haskoki_test_note('", t, ":", T.toLower op, "'); END"
      ]

-- | Fail the token upsert (the only token statement that sets
-- @record_json@; staging moves @slot_key@ only) with the given
-- @RAISE@ kind, via a connection-local trigger.
failTokenUpsert :: Text -> S.Database -> IO ()
failTokenUpsert kind db = S.exec db $ T.concat
  [ "CREATE TEMP TRIGGER IF NOT EXISTS haskoki_test_fail_token_upsert"
  , " BEFORE UPDATE OF record_json ON main.tokens"
  , " BEGIN SELECT RAISE(", kind, ", '", injectedMarker, "'); END"
  ]

injectedMarker :: Text
injectedMarker = "haskoki-test: injected token upsert failure"

-- ---------------------------------------------------------------------------
-- Transaction-control seam (authorizer)
-- ---------------------------------------------------------------------------

-- | The authorizer seam: every transaction-control statement
-- prepared on the connection, most recent first (a denied one is
-- logged with a @:denied@ suffix), and the operations currently
-- denied (@BEGIN@, @COMMIT@, @ROLLBACK@).
data TxnSeam = TxnSeam
  { tsLog :: IORef [Text]
  , tsDeny :: IORef [Text]
  , tsInstalled :: IORef Bool
  }

newTxnSeam :: IO TxnSeam
newTxnSeam = TxnSeam <$> newIORef [] <*> newIORef [] <*> newIORef False

type AuthCallback = Ptr () -> CInt -> CString -> CString -> CString -> CString -> IO CInt

foreign import ccall "wrapper"
  mkAuthCallback :: AuthCallback -> IO (FunPtr AuthCallback)

foreign import ccall "sqlite3_set_authorizer"
  c_sqlite3_set_authorizer :: Ptr () -> FunPtr AuthCallback -> Ptr () -> IO CInt

-- | @SQLITE_TRANSACTION@: the authorizer action code of
-- @BEGIN@\/@COMMIT@\/@ROLLBACK@ (its first argument names the
-- operation).
sqliteTransaction :: CInt
sqliteTransaction = 22

-- | Install the authorizer on the connection (once per seam; the
-- callback stays registered for the connection's life, so it is
-- never freed while SQLite can call it).
installTxnSeam :: TxnSeam -> S.Database -> IO ()
installTxnSeam seam (Database db) = do
  done <- readIORef (tsInstalled seam)
  unless done $ do
    cb <- mkAuthCallback authorize
    rc <- c_sqlite3_set_authorizer (castPtr db) cb nullPtr
    unless (rc == 0) (assertFailure ("sqlite3_set_authorizer returned " ++ show rc))
    writeIORef (tsInstalled seam) True
  where
    authorize _ action arg1 _ _ _
      | action /= sqliteTransaction || arg1 == nullPtr = pure 0
      | otherwise = do
          op <- T.pack <$> peekCString arg1
          denied <- elem op <$> readIORef (tsDeny seam)
          modifyIORef' (tsLog seam) ((if denied then op <> ":denied" else op) :)
          pure (if denied then 1 else 0) -- SQLITE_DENY / SQLITE_OK

-- ---------------------------------------------------------------------------
-- Commit seam (commit hook)
-- ---------------------------------------------------------------------------

-- | The commit-hook seam: how many commits reached the commit
-- point on the connection (SQLite calls the hook only after the
-- COMMIT holds its EXCLUSIVE lock, so a busy COMMIT never
-- reaches it), a mark to count from, and whether the next one is
-- turned into a rollback (one shot). Every write commit counts,
-- including autocommit DDL such as a stimulus's TEMP trigger, so
-- callers mark right before the transaction under test.
data CommitSeam = CommitSeam
  { csCalls :: IORef Int
  , csMark :: IORef Int
  , csFailNext :: IORef Bool
  , csInstalled :: IORef Bool
  }

newCommitSeam :: IO CommitSeam
newCommitSeam = CommitSeam <$> newIORef 0 <*> newIORef 0 <*> newIORef False <*> newIORef False

-- | Count commits from now on.
markCommits :: CommitSeam -> IO ()
markCommits seam = readIORef (csCalls seam) >>= writeIORef (csMark seam)

-- | Commits that reached the commit point since the last mark.
commitsSinceMark :: CommitSeam -> IO Int
commitsSinceMark seam = (-) <$> readIORef (csCalls seam) <*> readIORef (csMark seam)

type CommitHook = Ptr () -> IO CInt

foreign import ccall "wrapper"
  mkCommitHook :: CommitHook -> IO (FunPtr CommitHook)

foreign import ccall "sqlite3_commit_hook"
  c_sqlite3_commit_hook :: Ptr () -> FunPtr CommitHook -> Ptr () -> IO (Ptr ())

-- | Install the commit hook on the connection (once per seam;
-- never freed while registered).
installCommitSeam :: CommitSeam -> S.Database -> IO ()
installCommitSeam seam (Database db) = do
  done <- readIORef (csInstalled seam)
  unless done $ do
    cb <- mkCommitHook hook
    _ <- c_sqlite3_commit_hook (castPtr db) cb nullPtr
    writeIORef (csInstalled seam) True
  where
    hook _ = do
      modifyIORef' (csCalls seam) (+ 1)
      failing <- readIORef (csFailNext seam)
      writeIORef (csFailNext seam) False
      pure (if failing then 1 else 0)

-- ---------------------------------------------------------------------------
-- Genuine lock contention
-- ---------------------------------------------------------------------------

-- | Run the action while a second plain connection holds an
-- open read transaction (a SHARED lock) on the database: the
-- store connection can still begin and write (RESERVED), but its
-- COMMIT cannot take the EXCLUSIVE lock.
withSharedReadLock :: FilePath -> IO a -> IO a
withSharedReadLock path act = bracket (S.open (T.pack path)) S.close $ \rdr -> do
  S.exec rdr "BEGIN"
  _ <- rowsOf rdr "SELECT count(*) FROM tokens"
  r <- act
  S.exec rdr "COMMIT"
  pure r

-- ---------------------------------------------------------------------------
-- Raw durable state
-- ---------------------------------------------------------------------------

-- | Every row of every logical table, read raw through a plain
-- connection on the CLOSED store file: the exact durable state.
dumpTables :: FilePath -> IO [(Text, [[S.SQLData]])]
dumpTables path = bracket (S.open (T.pack path)) S.close $ \db ->
  mapM (\t -> (,) t <$> rowsOf db (T.concat ["SELECT * FROM ", t, " ORDER BY 1"])) loggedTables

-- | Table-by-table equality, naming the first table that moved.
assertTablesEqual :: [(Text, [[S.SQLData]])] -> [(Text, [[S.SQLData]])] -> IO ()
assertTablesEqual before after = do
  assertEqual "same table set" (map fst before) (map fst after)
  sequence_
    [ assertEqual ("durable " ++ T.unpack t ++ " rows unchanged") rowsB rowsA
    | ((t, rowsB), (_, rowsA)) <- zip before after
    ]

-- | All result rows of one query.
rowsOf :: S.Database -> Text -> IO [[S.SQLData]]
rowsOf db sql = bracket (S.prepare db sql) S.finalize collect
  where
    collect stmt = do
      r <- S.step stmt
      case r of
        S.Done -> pure []
        S.Row -> (:) <$> S.columns stmt <*> collect stmt

-- | The single text cell of a one-row query.
queryText :: S.Database -> Text -> IO String
queryText db sql = do
  rows <- rowsOf db sql
  case rows of
    [[S.SQLText v]] -> pure (T.unpack v)
    other -> assertFailure ("expected one text cell: " ++ show other)

-- | The single integer cell of a one-row query.
queryInt :: S.Database -> Text -> IO Int
queryInt db sql = do
  rows <- rowsOf db sql
  case rows of
    [[S.SQLInteger v]] -> pure (fromIntegral v)
    other -> assertFailure ("expected one integer cell: " ++ show other)
