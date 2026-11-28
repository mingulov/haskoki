{- | Detached attachments.
-}
module Haskoki.Runtime.Detached.Attachments
  ( AttachmentView (..)
  , attView
  , inspectAttachment
  , inspectReverse
  , detachStats
  , setIdle
  , tryClaim
  , rollbackClaim
  , commitClaim
  ) where

import Control.Concurrent.STM
  ( STM
  , atomically
  , readTVar
  , writeTVar
  )
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Unique (Unique)
import Data.Word (Word64)
import Haskoki.Runtime.Async (AsyncTableId)
import Haskoki.Runtime.Attach
  ( Attachment (..)
  , ClaimPrior (..)
  , TokenClaims (..)
  , claimCensus
  )
import Haskoki.Runtime.Storage
  ( JobExecState (..)
  )
import Haskoki.Types
  ( JobId (..)
  , SessionId (..)
  )
import Haskoki.Runtime.Detached.Context

-- ---------------------------------------------------------------------------
-- Attachments
-- ---------------------------------------------------------------------------

-- | One persistent job's attachment: actively bound to a live job,
-- detached-awaiting-join, or terminally resolved (delivered,
-- canceled, or failed — never rejoinable, never recompleted).
-- The public inspection vocabulary is stable: an in-progress join
-- claim projects to 'AvIdle' (no live binding exists yet — the
-- job is still detached-awaiting-join).
data AttachmentView
  = AvActive !JobId
  | AvIdle
  | AvTerminal !JobExecState
  deriving (Eq, Show)

-- | Project internal attachment state onto the public view.
attView :: Attachment -> AttachmentView
attView (AttActive _ jid) = AvActive jid
attView AttIdle = AvIdle
attView (AttTerminal st) = AvTerminal st
attView (AttClaim _ _ _ _) = AvIdle

-- | Inspect a persistent job's attachment on the store handle's
-- shared authority ('Nothing' = never detached or touched through
-- this handle — rejoin resolves those against the durable record
-- instead). Every context over the handle sees the same answer.
inspectAttachment :: DetachCtx -> Word64 -> IO (Maybe AttachmentView)
inspectAttachment dc pid = fmap attView <$> lookupAttachment dc pid

-- | Resolve a live job to its persistent id through the reverse
-- map, keyed by the job's own table and job identity. Colliding
-- local job ids on sibling tables resolve independently.
-- Focused test\/diagnostic helper (the map itself stays private).
inspectReverse :: DetachCtx -> AsyncTableId -> JobId -> IO (Maybe Word64)
inspectReverse dc tid jid =
  Map.lookup (tid, jid) . tcReverse <$> atomically (readClaims dc)

-- | Registry census for this context's token on the store
-- handle's shared authority: @(active, idle, terminal)@ over the
-- public projection (in-progress claims count as idle: still
-- awaiting a live binding).
detachStats :: DetachCtx -> IO (Int, Int, Int)
detachStats dc = claimCensus (dcClaims dc) (dcToken dc)

-- | Record a fresh detach as idle (awaiting join) — only when the
-- id has no entry yet. The durable insert is visible before this
-- runs, so a join through any context over the handle may already
-- have claimed, bound, or resolved the id; that state stands and
-- is never reset to idle (which would admit a second live job).
setIdle :: DetachCtx -> Word64 -> IO ()
setIdle dc pid = atomically $ do
  tc <- readClaims dc
  case Map.lookup pid (tcAttach tc) of
    Nothing -> writeClaims dc tc { tcAttach = Map.insert pid AttIdle (tcAttach tc) }
    Just _ -> pure ()

-- | Take the in-progress join claim for a persistent id in one
-- STM step, stamping it with the attempt token the caller
-- minted. Succeeds only from idle or absent on a table whose
-- attachments are not retired (in the shared authority) and that
-- this context has not refused (retired through it before it
-- ever claimed through it); anything else (another claim, an
-- active, a terminal, or a retired or refused table) refuses
-- with 'Nothing' and the authority untouched. The claim lives on
-- the store handle's shared authority, so a claim (or active) taken
-- through any context over the handle refuses this one. The
-- claim records what it replaced so retirement can roll exactly
-- it back; a granted claim also records its table in this
-- context's served set (the scope of this context's
-- retirement). STM touches the authority and this context's
-- table sets only — never Store IO.
tryClaim
  :: DetachCtx -> Word64 -> AsyncTableId -> SessionId -> Unique
  -> IO (Maybe ClaimPrior)
tryClaim dc pid tid sid uniq = atomically $ do
  tc <- readClaims dc
  refused <- readTVar (dcRefused dc)
  if tid `Set.member` tcRetired tc || tid `Set.member` refused
    then pure Nothing
    else case Map.lookup pid (tcAttach tc) of
      Just AttIdle -> grant tc ClaimHadIdle
      Nothing -> grant tc ClaimHadNone
      _ -> pure Nothing
  where
    grant :: TokenClaims -> ClaimPrior -> STM (Maybe ClaimPrior)
    grant tc prior = do
      let claim = AttClaim tid sid uniq prior
      writeClaims dc tc { tcAttach = Map.insert pid claim (tcAttach tc) }
      served <- readTVar (dcServed dc)
      writeTVar (dcServed dc) (Set.insert tid served)
      pure (Just prior)

-- | Roll back only our own claim attempt, restoring exactly
-- what it replaced (idle or absent). Anything else in the slot —
-- committed, rolled back already (including by a racing
-- retirement), or a retry's later claim — is left untouched, so
-- rollback is safe on every exit path including nested cleanup.
rollbackClaim
  :: DetachCtx -> Word64 -> AsyncTableId -> SessionId -> Unique
  -> ClaimPrior -> IO ()
rollbackClaim dc pid tid sid uniq prior = atomically $ do
  tc <- readClaims dc
  let attach = tcAttach tc
  case Map.lookup pid attach of
    Just (AttClaim tid' sid' uniq' _)
      | tid' == tid && sid' == sid && uniq' == uniq ->
          let attach' = case prior of
                ClaimHadIdle -> Map.insert pid AttIdle attach
                ClaimHadNone -> Map.delete pid attach
          in writeClaims dc tc { tcAttach = attach' }
    _ -> pure ()

-- | Commit only our own claim attempt to the live attachment,
-- recording the forward entry (owned by our table) and the
-- reverse entry keyed by our table and job identity, in one STM
-- step — unless our table retired while we were away, in which
-- case there is nothing to commit to. Reports 'False' —
-- committing nothing — when the claim is no longer ours or our
-- table retired; the transfer retires its fresh job rather than
-- stranding it, and rolls back (a no-op after a retirement
-- rollback, by construction).
commitClaim
  :: DetachCtx -> Word64 -> AsyncTableId -> SessionId -> Unique
  -> JobId -> IO Bool
commitClaim dc pid tid sid uniq jid = atomically $ do
  tc <- readClaims dc
  case Map.lookup pid (tcAttach tc) of
    Just (AttClaim tid' sid' uniq' _)
      | tid' == tid && sid' == sid && uniq' == uniq
      , tid `Set.notMember` tcRetired tc -> do
          writeClaims dc tc
            { tcAttach = Map.insert pid (AttActive tid jid) (tcAttach tc)
            , tcReverse = Map.insert (tid, jid) pid (tcReverse tc)
            }
          pure True
    _ -> pure False
