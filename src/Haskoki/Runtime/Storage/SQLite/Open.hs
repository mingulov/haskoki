{- | SQLite store opening.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Open
  ( openSQLiteStore
  , openSQLiteStoreWith
  , openSQLiteStoreWithHooks
  , openSQLiteStoreResolved
  ) where

import Control.Concurrent.MVar (newMVar)
import Control.Exception (mask, onException)
import Data.IORef (newIORef)
import Haskoki.Runtime.Attach (newClaimAuthority)
import Haskoki.Runtime.Storage
  ( FaultInjector (..)
  , HandleState (..)
  , Store (..)
  , StoreError (..)
  , StoreLimits
  , defaultLimits
  , noFaults
  , zeroStats
  )
import Haskoki.Runtime.Storage.SQLite.Commit
import Haskoki.Runtime.Storage.SQLite.Conn
import Haskoki.Runtime.Storage.SQLite.Init
import Haskoki.Runtime.Storage.SQLite.Ownership
import Haskoki.Runtime.Storage.SQLite.Snapshot
import Haskoki.Runtime.Storage.SQLite.Statements
import Haskoki.Runtime.Storage.SQLite.Types
import Haskoki.Runtime.Trace (renderSpellingRefusal)

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
