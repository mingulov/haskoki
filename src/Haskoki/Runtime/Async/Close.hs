{- | Async close admission and teardown.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Async.Close
  ( enterTableUse
  , exitTableUse
  , claimTableClose
  , beginTableTeardown
  , releaseTableClose
  , finishTableClose
  , awaitTableQuiescent
  , inspectTableGate
  , inspectTableClose
  ) where

import Control.Concurrent.STM
  ( atomically
  , check
  , readTVar
  , readTVarIO
  , writeTVar
  )
import Haskoki.Runtime.Async.Table

-- ---------------------------------------------------------------------------
-- Close admission
-- ---------------------------------------------------------------------------

-- | Admit one table use (an export call entered through the
-- context boundary): the borrower count rises by one unless the
-- table already left 'TableOpen', in which case the caller is
-- refused ('False') before it does anything. One STM step, so the
-- check and the count move together; pairs with 'exitTableUse'
-- under a bracket, and runs masked at the boundary so no kill can
-- split admission from the dereference that precedes it.
enterTableUse :: AsyncTable -> IO Bool
enterTableUse table = atomically $ do
  (n, phase) <- readTVar (atGate table)
  case phase of
    TableOpen -> do
      writeTVar (atGate table) (n + 1, phase)
      pure True
    _ -> pure False

-- | Release one admitted table use. Pairs with 'enterTableUse';
-- the close phase stands untouched.
exitTableUse :: AsyncTable -> IO ()
exitTableUse table = atomically $ do
  (n, phase) <- readTVar (atGate table)
  writeTVar (atGate table) (n - 1, phase)

-- | Claim a table for close: the first claim on an open table wins
-- ('True') and moves the gate to closing with teardown pending, so
-- no later use is admitted; a retrying claim on a teardown-started
-- table without a closer resumes it ('True'); any other claim —
-- a racing second closer, or a claim on a closed table — reports
-- 'False' and must tear nothing down. The winner still waits out
-- live borrowers with 'awaitTableQuiescent' before draining, so
-- teardown never overlaps an admitted call.
claimTableClose :: AsyncTable -> IO Bool
claimTableClose table = atomically $ do
  (n, phase) <- readTVar (atGate table)
  case phase of
    TableOpen -> do
      writeTVar (atGate table) (n, TableClosing TeardownPending CloserActive)
      pure True
    TableClosing TeardownStarted CloserAbsent -> do
      writeTVar (atGate table) (n, TableClosing TeardownStarted CloserActive)
      pure True
    _ -> pure False

-- | Mark teardown started: the winner runs this after its
-- quiescence wait, before draining. Idempotent on a started
-- close with an active closer (a quiet no-op answering 'True',
-- so a resumed drain re-runs it safely); any other phase answers
-- 'False' and moves nothing.
beginTableTeardown :: AsyncTable -> IO Bool
beginTableTeardown table = atomically $ do
  (n, phase) <- readTVar (atGate table)
  case phase of
    TableClosing TeardownPending CloserActive -> do
      writeTVar (atGate table) (n, TableClosing TeardownStarted CloserActive)
      pure True
    TableClosing TeardownStarted CloserActive -> pure True
    _ -> pure False

-- | Release a close claim: before teardown starts the gate reopens
-- for a later claim, while past teardown begin the table stays
-- closing without a closer — never back to open. The borrower
-- count stands untouched. The close worker runs this (masked) when
-- an interruption aborts its quiescence wait or its drain, so
-- teardown ownership transfers back instead of stranding
-- closing-but-ownerless: a retrying close re-claims and completes.
-- Idempotent — releasing an open or closed gate is a quiet no-op —
-- and a single STM step, so it never blocks.
releaseTableClose :: AsyncTable -> IO ()
releaseTableClose table = atomically $ do
  (n, phase) <- readTVar (atGate table)
  case phase of
    TableClosing TeardownPending _ ->
      writeTVar (atGate table) (n, TableOpen)
    TableClosing TeardownStarted _ ->
      writeTVar (atGate table) (n, TableClosing TeardownStarted CloserAbsent)
    _ -> pure ()

-- | Mark the table closed: the winner runs this in its
-- uninterruptible pointer transfer, after the drain. The borrower
-- count stands untouched (it is zero: the drain ran only past a
-- successful quiescence wait).
finishTableClose :: AsyncTable -> IO ()
finishTableClose table = atomically $ do
  (n, _) <- readTVar (atGate table)
  writeTVar (atGate table) (n, TableClosed)

-- | Block until no admitted use remains. The wait retries in STM
-- (no polling, no locks), so it composes with the borrower
-- bracket: every admitted call exits exactly once, and close
-- proceeds only after the last one does.
awaitTableQuiescent :: AsyncTable -> IO ()
awaitTableQuiescent table = atomically $ do
  (n, _) <- readTVar (atGate table)
  check (n <= 0)

-- | Gate census: @(live borrowers, close claimed)@, where claimed
-- means the table left 'TableOpen'. Lock-free test\/diagnostic
-- read; the shape is kept so pre-existing assertions hold.
inspectTableGate :: AsyncTable -> IO (Int, Bool)
inspectTableGate table = do
  (n, phase) <- readTVarIO (atGate table)
  pure (n, phase /= TableOpen)

-- | Full close phase. Lock-free test\/diagnostic read.
inspectTableClose :: AsyncTable -> IO TableClose
inspectTableClose table = snd <$> readTVarIO (atGate table)
