{- | SQLite store transaction failures and job-id reservation.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Txn
  ( TxnStep (..)
  , TxnFailure (..)
  , txnFailureError
  , endFailedTxn
  , withCleanupError
  , settleTxnFailure
  , reserveJobIdConn
  , reserveLocked
  , resolveAmbiguousReserve
  , quarantineAllTokensConn
  ) where

import Control.Exception (mask_)
import Data.IORef (writeIORef)
import Data.List (nub)
import Data.Maybe (fromMaybe)
import Data.Word (Word64)
import qualified Database.SQLite3 as S
import Database.SQLite3.Direct (getAutoCommit)
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , FaultInjector (..)
  , FaultPoint (..)
  , StoreError (..)
  , jobIdCounterKey
  , nextJobReservation
  )
import Haskoki.Runtime.Storage.SQLite.Conn
import Haskoki.Runtime.Storage.SQLite.Records
import Haskoki.Runtime.Storage.SQLite.Statements
import Haskoki.Runtime.Storage.SQLite.Stats
import Haskoki.Runtime.Storage.SQLite.Types
import Haskoki.Types (TokenId (..))

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
