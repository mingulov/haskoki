{- | Async detach snapshots.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Async.Snapshot
  ( JobSnapState (..)
  , JobSnapshot
  , jobSnapshotFunction
  , jobSnapshotWork
  , jobSnapshotState
  , jobSnapshotTicks
  , jobSnapshotCapacity
  , jobSnapshotSession
  , jobSnapshotEpoch
  , snapshotJob
  , toSnapshot
  , DetachLease
  , beginDetach
  , leaseSnapshot
  , commitDetachRevoke
  , abortDetach
  , LeaseView (..)
  , leaseLockHeld
  , withDetachLease
  ) where

import Control.Concurrent.MVar
  (MVar, putMVar, takeMVar, tryTakeMVar)
import Control.Concurrent.STM
  ( atomically
  , readTVar
  , readTVarIO
  , writeTVar
  )
import Control.Exception
  ( finally
  , mask
  , mask_
  , onException
  , uninterruptibleMask_
  )
import Control.Monad (unless)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Haskoki.Operation (TypedError (..), interpretError)
import Haskoki.Operation.Effect
  ( CryptoResult (..)
  )
import Haskoki.Runtime.Usdt (Disposition (..), JobPhase (..))
import Haskoki.ReturnCode.Generated (returnCodeToRV)
import Haskoki.Types
  ( JobId (..)
  , ReturnCode (..)
  , SessionId
  , redactShown
  )
import Haskoki.Runtime.Async.Jobs
import Haskoki.Runtime.Async.Table

-- ---------------------------------------------------------------------------
-- Detach support
-- ---------------------------------------------------------------------------

-- | A job's detach-relevant state, copied out of the table. Ready
-- snapshots carry the held bytes (for pointer-free result records);
-- verdict and error holdings report their tag instead — detach
-- prepares result records for bytes only.
data JobSnapState
  = SnapPending !Int
  | SnapRunning
  | SnapReady !ByteString
  | SnapHeld !String
  | SnapTerminal !TerminalState
  deriving (Eq)

-- | 'Show' redacts held result bytes: a ready snapshot
-- may hold a ready-but-unfinished keygen answer, so 'SnapReady'
-- renders its kind and length only ('redactShown'). All other
-- states render normally. Explicit inspection pattern-matches
-- the exported constructors (never 'Show').
instance Show JobSnapState where
  show (SnapPending n) = "SnapPending " ++ show n
  show SnapRunning = "SnapRunning"
  show (SnapReady bs) = "SnapReady " ++ redactShown "bytes" (BS.length bs)
  show (SnapHeld tag) = "SnapHeld " ++ show tag
  show (SnapTerminal t) = "SnapTerminal " ++ show t

-- | A job snapshot: identity, planned work, state, attached
-- capacity, owning session, and cancellation epoch. Snapshots are
-- plain data: no locks, no pointers, safe to persist from.
data JobSnapshot = JobSnapshot
  { jsFunction :: !JobFunction
  , jsWork :: !AsyncWork
  , jsState :: !JobSnapState
  , jsCapacity :: !Word64
  , jsSession :: !SessionId
  , jsEpoch :: !Word64
  } deriving (Eq, Show)

-- | Snapshot accessors (the constructor stays private so snapshots
-- only ever come from the table).
jobSnapshotFunction :: JobSnapshot -> JobFunction
jobSnapshotFunction = jsFunction

-- | The planned work (the recipe source).
jobSnapshotWork :: JobSnapshot -> AsyncWork
jobSnapshotWork = jsWork

-- | The copied execution state.
jobSnapshotState :: JobSnapshot -> JobSnapState
jobSnapshotState = jsState

-- | Polls left while pending ('Nothing' otherwise).
jobSnapshotTicks :: JobSnapshot -> Maybe Int
jobSnapshotTicks snap = case jsState snap of
  SnapPending n -> Just n
  _ -> Nothing

-- | The attached byte-payload capacity.
jobSnapshotCapacity :: JobSnapshot -> Word64
jobSnapshotCapacity = jsCapacity

-- | The owning session.
jobSnapshotSession :: JobSnapshot -> SessionId
jobSnapshotSession = jsSession

-- | The cancellation epoch.
jobSnapshotEpoch :: JobSnapshot -> Word64
jobSnapshotEpoch = jsEpoch

-- | Copy a job out of the table. Lock-free read; 'Nothing' for
-- unknown or reaped jobs.
snapshotJob :: AsyncTable -> JobId -> IO (Maybe JobSnapshot)
snapshotJob table jid = do
  jobs <- readTVarIO (atJobs table)
  pure (toSnapshot <$> Map.lookup jid jobs)

-- | Project a live job onto its snapshot.
toSnapshot :: Job -> JobSnapshot
toSnapshot job = JobSnapshot
  { jsFunction = jbFunction job
  , jsWork = jbWork job
  , jsState = case jbState job of
      JobPending n -> SnapPending n
      JobRunning -> SnapRunning
      JobReady (GotBytes bs) -> SnapReady bs
      -- A unit holding snapshots as empty-ready (rejoin
      -- seeds empty bytes — identical to the pre-change
      -- held-empty-bytes behavior).
      JobReady GotUnit -> SnapReady BS.empty
      JobReady (GotValid _) -> SnapHeld "verdict"
      JobReady (GotResource _) -> SnapHeld "resource"
      JobReady (GotCryptoError e) -> SnapHeld (show (interpretError (jobExactFid job) (TyCrypto e)))
      JobTerminal t -> SnapTerminal t
  , jsCapacity = jbCapacity job
  , jsSession = jbSession job
  , jsEpoch = jbEpoch job
  }

-- | A held attachment-change lease: the job's delivery lease taken
-- for detach, plus the snapshot read under it. While the lease is
-- held, no poll\/complete\/cancel on this job can run, so record
-- preparation sees a stable job and revocation cannot race a
-- delivery. Exactly one of 'commitDetachRevoke' \/ 'abortDetach'
-- must run to release it. New code MUST NOT pair these by hand:
-- use 'withDetachLease', which owns the pairing structurally;
-- the raw operations stay exported only for the legacy callers
-- kept in the test suite ('DetachedSpec', 'SimStressSpec').
data DetachLease = DetachLease
  { dlTable :: !AsyncTable
  , dlJob :: !JobId
  , dlLock :: !(MVar ())
  , dlSnapshot :: !JobSnapshot
  }

-- | Take a job's lease for detach and snapshot it. 'Nothing' for
-- unknown jobs (including jobs reaped while waiting for the lease);
-- otherwise the caller holds the lease until commit or abort.
--
-- Masking contract: the FULL take-to-handoff path runs
-- masked. The wait for a contested lock stays killable — a blocking
-- 'takeMVar' is interruptible even under 'mask_' — but a take that
-- succeeds never re-enters an unmasked state before the lease is
-- handed off, so no async exception can strand the lock between the
-- take and the handoff ("raises implies holds nothing": an exception
-- escaping 'beginDetach' was raised while blocked in the wait and
-- holds nothing; the post-take section never blocks). Callers still
-- release a returned lease exactly once.
beginDetach :: AsyncTable -> JobId -> IO (Maybe DetachLease)
beginDetach table jid = mask_ $ do
  mj <- readTVarIO (atJobs table) >>= pure . Map.lookup jid
  case mj of
    Nothing -> pure Nothing
    Just job -> do
      -- Masked take: killable while blocked (interruptible wait),
      -- unkillable once held (no window before the handoff).
      takeMVar (jbLock job)
      -- Holding the lock, still masked: the handoff never blocks,
      -- so no async exception can surface before the lease exists.
      uninterruptibleMask_ $ do
        cur <- readTVarIO (atJobs table) >>= pure . Map.lookup jid
        case cur of
          Nothing -> do
            putMVar (jbLock job) ()
            pure Nothing
          Just jobNow -> pure (Just DetachLease
            { dlTable = table
            , dlJob = jid
            , dlLock = jbLock job
            , dlSnapshot = toSnapshot jobNow
            })

-- | The snapshot read under a held lease.
leaseSnapshot :: DetachLease -> JobSnapshot
leaseSnapshot = dlSnapshot

-- | Revoke the leased job: remove it from the table (no admitted
-- poll\/complete\/cancel can reach it afterwards — late callers
-- observe unknown) and release the lease. One-shot: the lease is
-- spent.
--
-- Masking contract: the revoke-then-release pair is
-- uninterruptible, so a kill can neither orphan the lock on a
-- revoked job nor surface between the two steps — an exception
-- escaping 'commitDetachRevoke' still leaves a clean state
-- (revoked AND released).
commitDetachRevoke :: DetachLease -> IO ()
commitDetachRevoke dl = uninterruptibleMask_ $ do
  mJob <- atomically $ do
    jobs <- readTVar (atJobs (dlTable dl))
    -- Forced: see the forcing invariant on 'commitStep'.
    let jobs' = Map.delete (dlJob dl) jobs
    jobs' `seq` writeTVar (atJobs (dlTable dl)) jobs'
    pure (Map.lookup (dlJob dl) jobs)
  -- The handoff closes the source op: a rejoin continues under a
  -- fresh op id (no in-band link; correlate externally), so without
  -- this pair the source op would dangle at its last phase forever.
  -- The release runs under 'finally': emission must not strand the
  -- lease (revoked AND released is the contract).
  (case mJob of
    Just job -> do
      usdtJobPhase (dlTable dl) (dlJob dl) job PhaseHandoff 0 False
      usdtAsyncEnd job (returnCodeToRV CKR_OK) DispHandedOff
    Nothing -> pure ())
    `finally` putMVar (dlLock dl) ()

-- | Release a held lease with the job untouched. One-shot.
abortDetach :: DetachLease -> IO ()
abortDetach dl = uninterruptibleMask_ (putMVar (dlLock dl) ())

-- | The scoped view of a held detach lease: the snapshot read
-- under it plus the idempotent commit action. The release side is
-- owned by 'withDetachLease', never by the body.
data LeaseView = LeaseView
  { lvSnapshot :: !JobSnapshot
  , lvCommit :: !(IO ())
  }

-- | Run a body with a job's detach lease held. 'Nothing' for
-- unknown jobs. Otherwise the body observes the snapshot and may
-- commit (revoking the job; committing twice is a quiet no-op);
-- when the body returns or throws without committing, the lease is
-- released with the job untouched. A dropped lease cannot wedge:
-- the abort runs masked on every exit path, so exactly one of
-- commit\/abort releases each acquired lease by construction.
withDetachLease
  :: AsyncTable -> JobId -> (Maybe LeaseView -> IO a) -> IO a
withDetachLease table jid body = mask $ \restore -> do
  mLease <- beginDetach table jid
  case mLease of
    Nothing -> restore (body Nothing)
    Just lease -> do
      committedRef <- newIORef False
      let view = LeaseView
            { lvSnapshot = leaseSnapshot lease
            , lvCommit = uninterruptibleMask_ $ do
                done <- readIORef committedRef
                unless done $ do
                  commitDetachRevoke lease
                  writeIORef committedRef True
            }
      r <- restore (body (Just view)) `onException` abortUnless committedRef lease
      abortUnless committedRef lease
      pure r
  where
    abortUnless :: IORef Bool -> DetachLease -> IO ()
    abortUnless ref lease = uninterruptibleMask_ $ do
      done <- readIORef ref
      unless done (abortDetach lease)

-- | Non-blocking lease probe (diagnostic affordance in the
-- 'Haskoki.Runtime.Lifecycle.gateBusy' precedent): 'True' while
-- the lease's lock is held. The take\/put pair runs masked so the
-- token cannot leak; a racing holder only waits out the probe.
leaseLockHeld :: DetachLease -> IO Bool
leaseLockHeld dl = mask_ $ do
  m <- tryTakeMVar (dlLock dl)
  case m of
    Nothing -> pure True
    Just () -> putMVar (dlLock dl) () >> pure False
