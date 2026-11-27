{- | SQLite store shared kernel: the schema version, the live
connection state, and the test-hooks seam.

Leaf module. The schema version lives here (not in the shell) so
Init and Migrate can read it without importing the shell; the
compat gates read it from this path (see check-compat.py,
generate_compat.py).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Types
  ( sqliteSchemaVersion
  , SQLiteConn (..)
  , SQLiteTestHooks (..)
  , noSQLiteTestHooks
  ) where

import Control.Concurrent.MVar (MVar)
import Data.IORef (IORef)
import qualified Database.SQLite3 as S
import System.Posix.Types (Fd)

import Haskoki.Runtime.Attach (ClaimAuthority)
import Haskoki.Runtime.Storage (FaultInjector, HandleState, StoreLimits, StoreStats)
import Haskoki.Types (TokenId)

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
