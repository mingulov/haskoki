{- | Detached joined completion and cancellation.
-}
module Haskoki.Runtime.Detached.JoinComplete
  ( JoinedComplete (..)
  , completeJoined
  , cancelJoined
  , pollJoined
  , markResolved
  , retireLiveTable
  , retireLiveTableFor
  , retireMatching
  , markState
  , setTerminal
  , execStateOf
  ) where

import Control.Concurrent.STM
  ( atomically
  , readTVar
  , writeTVar
  )
import Control.Exception
  ( SomeAsyncException
  , displayException
  , fromException
  , throwIO
  , try
  )
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Word (Word64)
import Haskoki.Outcome
  ( ResourceRelease
  )
import Haskoki.Runtime.Async
  ( AsyncTable
  , AsyncTableId
  , CancelOutcome (..)
  , CompleteOutcome (..)
  , Delivery (..)
  , EffectRunner
  , JobFunction (..)
  , PollOutcome (..)
  , TerminalState (..)
  , asyncTableId
  , cancelJob
  , completeJob
  , pollJob
  )
import Haskoki.Runtime.Attach
  ( Attachment (..)
  , ClaimPrior (..)
  , TokenClaims (..)
  )
import Haskoki.Runtime.Lifecycle (Env)
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , JobExecState (..)
  , JobRecord (..)
  , Reconcile (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , emptyDelta
  , reconcileJobsReload
  )
import Haskoki.Types
  ( JobId (..)
  )
import Haskoki.Runtime.Detached.Context

-- ---------------------------------------------------------------------------
-- Joined completion and cancellation
-- ---------------------------------------------------------------------------

-- | One joined completion: the async outcome plus the durable-mark
-- error, if the fate mark failed to commit. The verdict itself
-- already happened (the job lease decided); a mark error means the
-- durable record lags the live table, and the in-memory attachment
-- is terminal regardless so this generation never rejoins.
data JoinedComplete = JoinedComplete
  { jcOutcome :: !CompleteOutcome
  , jcMarkError :: !(Maybe StoreError)
  } deriving (Eq, Show)

-- | Complete a possibly-joined job through the job lease, marking
-- the durable record with the observed fate: delivered on delivery,
-- failed or canceled when an already-terminal job is observed.
-- Non-joined jobs pass through untouched (mark clean).
completeJoined
  :: DetachCtx -> Env -> AsyncTable -> JobFunction -> JobId -> Delivery
  -> (ResourceRelease -> IO ()) -> IO JoinedComplete
completeJoined dc env table func jid del release = do
  out <- completeJob env table func jid del release
  case out of
    CompleteDelivered _ -> do
      merr <- markResolved dc table jid JobDelivered
      pure (JoinedComplete out merr)
    CompleteAlready (TermDelivered _) -> do
      merr <- markResolved dc table jid JobDelivered
      pure (JoinedComplete out merr)
    CompleteAlready (TermFailed _ _) -> do
      merr <- markResolved dc table jid JobFailed
      pure (JoinedComplete out merr)
    CompleteAlready TermCanceled -> do
      merr <- markResolved dc table jid JobCanceled
      pure (JoinedComplete out merr)
    _ -> pure (JoinedComplete out Nothing)

-- | Cancel a possibly-joined job, marking the durable record with
-- the terminal fate. Non-joined jobs pass through untouched.
cancelJoined :: DetachCtx -> AsyncTable -> JobId -> IO (CancelOutcome, Maybe StoreError)
cancelJoined dc table jid = do
  out <- cancelJob table jid
  case out of
    CancelOk -> do
      merr <- markResolved dc table jid JobCanceled
      pure (out, merr)
    CancelAlready t -> do
      merr <- markResolved dc table jid (execStateOf t)
      pure (out, merr)
    CancelUnknown -> pure (out, Nothing)

-- | Poll a possibly-joined job, marking the durable record with
-- the observed terminal fate whenever this poll observes one (a
-- driven failure, or an already-terminal job such as one canceled
-- outside the wrapper). Non-joined jobs pass through untouched
-- (mark clean).
pollJoined
  :: DetachCtx -> EffectRunner -> Env -> AsyncTable -> JobFunction -> JobId
  -> IO (PollOutcome, Maybe StoreError)
pollJoined dc run env table func jid = do
  out <- pollJob run env table func jid
  case out of
    PollTerminal t -> do
      merr <- markResolved dc table jid (execStateOf t)
      pure (out, merr)
    _ -> pure (out, Nothing)

-- | Mark a joined live job's durable record resolved, resolving
-- through the reverse map by the job's own table and job
-- identity. Unknown (never joined) jobs report clean with no
-- write; a colliding local job id on a sibling table resolves to
-- that table's own record, never this one.
markResolved :: DetachCtx -> AsyncTable -> JobId -> JobExecState -> IO (Maybe StoreError)
markResolved dc table jid st = do
  rev <- tcReverse <$> atomically (readClaims dc)
  case Map.lookup (asyncTableId table, jid) rev of
    Nothing -> pure Nothing
    Just pid -> do
      eJobs <- storeLoadJobs (dcStore dc)
      case eJobs of
        Left err -> do
          setTerminal dc pid st
          pure (Just err)
        Right jobs -> case [r | r <- jobs, jrPersistentId r == pid] of
          [] -> do
            setTerminal dc pid st
            pure (Just (StoreRevisionConflict "durable job is gone"))
          (rec : _) -> markState dc pid rec st

-- | Retire every live table this context served (provider close):
-- each active attachment owned by a table this context claimed
-- through resolves canceled, durably and in memory, each of
-- those tables' in-progress claims rolls back to what it
-- replaced, and those tables' opaque marks clear (a new table
-- generation starts unflagged). Tables this context marked but
-- never claimed through have their opaque marks dropped too, and
-- nothing else: no attachment, claim, or retired-set change.
-- Tables this context never claimed through — including a
-- sibling context's tables on the same store — are otherwise
-- untouched, so a refused (losing) context can never retire the
-- winner. Returns one entry per retired
-- attachment with its mark error, if any. This is whole-context
-- retirement for single-table owners (the Standard adapter, whose
-- instance owns exactly one table and one detach context);
-- callers sharing one context across tables retire with
-- 'retireLiveTableFor' so a closing table never cancels a
-- sibling's attachments. A synchronous Store throw during the
-- durable marks reports like a failed load: the attachments
-- still resolve canceled in memory, rows already committed
-- keeping their mark errors and the rest carrying the throw.
retireLiveTable :: DetachCtx -> IO [(Word64, Maybe StoreError)]
retireLiveTable dc = do
  retireMatching dc Nothing

-- | Retire one live table's attachments (context close on a shared
-- store): only actives owned by the retiring table identity
-- resolve canceled, durably and in memory; that table's
-- in-progress claims roll back to what they replaced, and the
-- table records its retirement so their late commits — and any
-- later claim from it — are refused. Sibling tables'
-- attachments — active, idle, terminal, or mid-claim — are
-- untouched. A table this context never claimed through is not
-- this context's to retire in the shared authority (a losing
-- context cannot retire the winner's table): the call returns
-- @[]@ and only records the table in this context's refused
-- set, so this context's own later claims through it are
-- refused while other contexts are unaffected; if this context
-- marked jobs on the table, the table's opaque marks drop too.
-- Returns one entry per retired attachment with its mark error,
-- if any (rolled-back claims are not retired attachments: their
-- durable jobs stand untouched and joinable). The retiring
-- table's opaque marks drop with it whenever this context served
-- or marked it (see 'retireMatching'); sibling tables' marks
-- stay. A synchronous Store throw during the durable marks
-- reports like a failed load: the attachments still resolve
-- canceled in memory, rows already committed keeping their mark
-- errors and the rest carrying the throw.
retireLiveTableFor
  :: DetachCtx -> AsyncTableId -> IO [(Word64, Maybe StoreError)]
retireLiveTableFor dc tid = retireMatching dc (Just tid)

-- | Shared retire worker over the tables this context served or
-- marked: 'Nothing' covers all of them (whole context), @'Just'
-- tid@ only that one. When this context never claimed through
-- @tid@, @tid@ joins this context's refused set (its later claims
-- through @tid@ refuse) and, in the shared authority, at most
-- @tid@'s opaque marks drop (when this context marked it): an
-- unserved table is never written into the shared retired set,
-- which would let a loser defeat the winner's in-flight commit.
-- Served tables, in one STM step on the shared authority: the
-- retiring tables record their identity (so the claims' late
-- commits — and any later claim from those tables — are refused
-- rather than publishing a live binding after the drain), their
-- in-progress claims roll back to exactly what they replaced,
-- their opaque marks drop, and their actives are collected; the
-- same step drops the marks of in-scope tables this context
-- marked but never served. The durable cancel marks run after the
-- STM step, outside it, and only when there are actives to mark.
retireMatching
  :: DetachCtx -> Maybe AsyncTableId -> IO [(Word64, Maybe StoreError)]
retireMatching dc mTid = do
  actives <- atomically $ do
    served <- readTVar (dcServed dc)
    marked <- readTVar (dcMarked dc)
    let inScope t = maybe True (== t) mTid
        tids = Set.filter inScope served
        unmark = Set.union tids (Set.filter inScope marked)
    case mTid of
      Just tid | tid `Set.notMember` served -> do
        refused <- readTVar (dcRefused dc)
        writeTVar (dcRefused dc) (Set.insert tid refused)
      _ -> pure ()
    writeTVar (dcMarked dc) (Set.difference marked unmark)
    if Set.null unmark
      then pure []
      else do
        tc <- readClaims dc
        let attach = tcAttach tc
            owned owner = owner `Set.member` tids
            opaque' =
              Map.filterWithKey (\(t, _) _ -> t `Set.notMember` unmark) (tcOpaque tc)
            actives =
              [ pid
              | (pid, AttActive owner _) <- Map.toList attach
              , owned owner
              ]
            claims =
              [ (pid, prior)
              | (pid, AttClaim owner _ _ prior) <- Map.toList attach
              , owned owner
              ]
        if Set.null tids
          then
            -- Marked but never served: drop the marks only; the
            -- shared retired set and every attachment stay as they are.
            writeClaims dc tc { tcOpaque = opaque' }
          else
            writeClaims dc tc
              { tcAttach = foldr rollbackClaimed attach claims
              , tcOpaque = opaque'
              , tcRetired = Set.union tids (tcRetired tc)
              }
        pure actives
  if null actives
    then pure []
    else do
      eJobs <- try (storeLoadJobs (dcStore dc))
      case eJobs of
        Left e -> case (fromException e :: Maybe SomeAsyncException) of
          Just _ -> throwIO e
          -- A synchronous load throw reports like a failed load:
          -- the attachments still resolve canceled in memory, each
          -- carrying the throw as its mark error, so retirement
          -- never fails a close.
          Nothing -> do
            mapM_ (\pid -> setTerminal dc pid JobCanceled) actives
            let err = StoreIO (displayException e)
            pure [(pid, Just err) | pid <- actives]
        Right (Left err) -> do
          mapM_ (\pid -> setTerminal dc pid JobCanceled) actives
          pure [(pid, Just err) | pid <- actives]
        Right (Right jobs) -> go jobs actives []
  where
    go :: [JobRecord] -> [Word64] -> [(Word64, Maybe StoreError)]
      -> IO [(Word64, Maybe StoreError)]
    go _ [] acc = pure (reverse acc)
    go jobs (pid : rest) acc = do
      r <- try (retireOne jobs pid)
      case r of
        Right out -> go jobs rest (out : acc)
        Left e -> case (fromException e :: Maybe SomeAsyncException) of
          Just _ -> throwIO e
          -- A synchronous commit throw keeps the rows already
          -- committed and reports only the rest: the current and
          -- later attachments still resolve canceled in memory,
          -- each carrying the throw as its mark error.
          Nothing -> do
            mapM_ (\p -> setTerminal dc p JobCanceled) (pid : rest)
            let err = StoreIO (displayException e)
            pure (reverse acc ++ [(p, Just err) | p <- pid : rest])
    -- | Roll one retired claim back to what it replaced.
    rollbackClaimed
      :: (Word64, ClaimPrior) -> Map Word64 Attachment -> Map Word64 Attachment
    rollbackClaimed (pid, prior) attach = case prior of
      ClaimHadIdle -> Map.insert pid AttIdle attach
      ClaimHadNone -> Map.delete pid attach
    retireOne :: [JobRecord] -> Word64 -> IO (Word64, Maybe StoreError)
    retireOne jobs pid =
      case [r | r <- jobs, jrPersistentId r == pid] of
        [] -> do
          setTerminal dc pid JobCanceled
          pure (pid, Just (StoreRevisionConflict "durable job is gone"))
        (rec : _) -> do
          merr <- markState dc pid rec JobCanceled
          pure (pid, merr)

-- | Write one durable terminal state and record it in memory. The
-- in-memory mark lands even when the commit fails, so this context
-- generation never rejoins a resolved job; the returned error tells
-- the caller the durable record lags.
markState :: DetachCtx -> Word64 -> JobRecord -> JobExecState -> IO (Maybe StoreError)
markState dc pid rec st = do
  let rec' = rec { jrState = st }
      delta = emptyDelta { sdPutJobs = [rec'] }
  res <- storeCommit (dcStore dc) delta
  setTerminal dc pid st
  case res of
    Committed -> pure Nothing
    NotCommitted err -> pure (Just err)
    CommitUnknown err -> do
      _ <- storeReload (dcStore dc)
      eJobs <- storeLoadJobs (dcStore dc)
      case eJobs of
        Right jobs | reconcileJobsReload delta jobs == ReconciledPresent ->
          pure Nothing
        _ -> pure (Just err)

-- | Record a terminal attachment.
setTerminal :: DetachCtx -> Word64 -> JobExecState -> IO ()
setTerminal dc pid st = putAttachment dc pid (AttTerminal st)

-- | Project a terminal state onto its durable execution state.
execStateOf :: TerminalState -> JobExecState
execStateOf (TermDelivered _) = JobDelivered
execStateOf TermCanceled = JobCanceled
execStateOf (TermFailed _ _) = JobFailed
