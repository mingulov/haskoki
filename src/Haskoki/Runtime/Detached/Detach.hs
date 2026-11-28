{- | Detached detach (GetID).
-}
module Haskoki.Runtime.Detached.Detach
  ( DetachOutcome (..)
  , detachCode
  , termCode
  , detachJob
  , detachUnder
  , detachPending
  , detachReady
  , encodeResultBody
  , decodeResultBody
  , commitDetach
  , loadSuperseded
  , reconcileDetach
  ) where

import Control.Concurrent.STM
  ( atomically
  )
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Haskoki.Runtime.Async
  ( AsyncTable
  , JobFunction (..)
  , JobSnapState (..)
  , JobSnapshot
  , LeaseView (..)
  , TerminalState (..)
  , asyncTableId
  , jobSnapshotCapacity
  , jobSnapshotFunction
  , jobSnapshotState
  , jobSnapshotWork
  , withDetachLease
  )
import Haskoki.Runtime.Attach
  ( TokenClaims (..)
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , JobBody (..)
  , JobExecState (..)
  , JobRecord (..)
  , Reconcile (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , TokenRecord (..)
  , emptyDelta
  , reconcileJobsReload
  )
import Haskoki.Types
  ( JobId (..)
  , ReturnCode (..)
  )
import Haskoki.Runtime.Detached.Attachments
import Haskoki.Runtime.Detached.Context
import Haskoki.Runtime.Detached.JoinComplete
import Haskoki.Runtime.Detached.Recipes
import Haskoki.Runtime.Detached.Saveability

-- ---------------------------------------------------------------------------
-- Detach (GetID)
-- ---------------------------------------------------------------------------

-- | One GetID outcome. Success ('DetachOk') comes only after the
-- record is durable AND the old binding is revoked; every other
-- outcome preserves the old live attachment.
data DetachOutcome
  = DetachOk { doPid :: !Word64 }
  | DetachUnknown
  | DetachWrongFunction { dwExpected :: !JobFunction, dwGot :: !JobFunction }
  | DetachAlready !TerminalState
  | DetachTransient
  | DetachUnsaveable { duReason :: !String }
  | DetachStore !StoreError
  | DetachNoToken
  deriving (Eq, Show)

-- | Source-backed code for a detach outcome.
detachCode :: DetachOutcome -> ReturnCode
detachCode out = case out of
  DetachOk _ -> CKR_OK
  DetachUnknown -> CKR_ARGUMENTS_BAD
  DetachWrongFunction {} -> CKR_ARGUMENTS_BAD
  DetachAlready t -> termCode t
  DetachTransient -> CKR_GENERAL_ERROR
  DetachUnsaveable {} -> CKR_STATE_UNSAVEABLE
  DetachStore _ -> CKR_GENERAL_ERROR
  DetachNoToken -> CKR_TOKEN_NOT_PRESENT

-- | Terminal-state code (mirrors the async export mapping).
termCode :: TerminalState -> ReturnCode
termCode (TermDelivered _) = CKR_OK
termCode TermCanceled = CKR_FUNCTION_CANCELED
termCode (TermFailed code _) = code

-- | Detach a live job (GetID): validate under the attachment-change
-- lease, prepare the pointer-free record, commit it durably, revoke
-- the old binding, and only then return the persistent id. Any
-- failure aborts the lease with the job untouched (the abort is
-- owned by 'withDetachLease', never paired by hand).
detachJob :: DetachCtx -> AsyncTable -> JobId -> JobFunction -> IO DetachOutcome
detachJob dc table jid func =
  withDetachLease table jid $ \mView -> case mView of
    Nothing -> pure DetachUnknown
    Just view -> do
      out <- detachUnder dc table jid func view
      case out of
        DetachOk _ -> clearOpaque dc table jid
        _ -> pure ()
      pure out

-- | The detach body under a held lease (aborts on every refusal).
detachUnder
  :: DetachCtx -> AsyncTable -> JobId -> JobFunction -> LeaseView
  -> IO DetachOutcome
detachUnder dc table jid func view = do
  let snap = lvSnapshot view
  -- Marks apply to non-terminal jobs only (ruling 3).
  mOpaque <- case jobSnapshotState snap of
    SnapTerminal _ -> pure Nothing
    _ -> readOpaque dc table jid
  case mOpaque of
    Just reason ->
      pure (DetachUnsaveable reason)
    Nothing -> do
      if jobSnapshotFunction snap /= func
        then pure (DetachWrongFunction (jobSnapshotFunction snap) func)
        else case jobSnapshotState snap of
          SnapTerminal t ->
            pure (DetachAlready t)
          SnapRunning ->
            pure DetachTransient
          SnapHeld tag ->
            pure (DetachUnsaveable ("held " ++ tag ++ " has no result record"))
          SnapPending n -> detachPending dc table jid view snap n
          SnapReady bs -> detachReady dc table jid view snap bs

-- | Detach a pending job: recipe record, durable, then revoked.
detachPending :: DetachCtx -> AsyncTable -> JobId -> LeaseView -> JobSnapshot -> Int -> IO DetachOutcome
detachPending dc table jid view snap ticks =
  case recipeFromWork
    (jobSnapshotFunction snap)
    (jobSnapshotWork snap)
    ticks
    (jobSnapshotCapacity snap) of
    Nothing ->
      pure (DetachUnsaveable "no detach recipe for this work shape")
    Just recipe -> do
      let (name, params) = encodeRecipe recipe
      commitDetach dc table jid view JobQueued (JobPending name params)

-- | Detach a ready job: prepared-result record (recipe plus owned
-- result bytes, so rejoin can replay the reservation AND seed the
-- held result without re-running the effect), durable, then revoked.
detachReady :: DetachCtx -> AsyncTable -> JobId -> LeaseView -> JobSnapshot -> ByteString -> IO DetachOutcome
detachReady dc table jid view snap bs =
  case recipeFromWork
    (jobSnapshotFunction snap)
    (jobSnapshotWork snap)
    0
    (jobSnapshotCapacity snap) of
    Nothing ->
      pure (DetachUnsaveable "no detach recipe for this work shape")
    Just recipe ->
      commitDetach dc table jid view JobReady
        (JobResult CKR_OK (encodeResultBody recipe bs))

-- | Frame a prepared result: recipe name + recipe params + owned
-- result bytes, each length-prefixed. The recipe replays the
-- reservation on rejoin; the bytes seed the held result.
encodeResultBody :: Recipe -> ByteString -> ByteString
encodeResultBody recipe bs =
  let (name, params) = encodeRecipe recipe
  in u32prefixed (BC8.pack name) <> u32prefixed params <> u32prefixed bs

-- | Strict prepared-result decode.
decodeResultBody :: ByteString -> Maybe (Recipe, ByteString)
decodeResultBody body = do
  (nameBs, rest0) <- takePrefixed body
  (params, rest1) <- takePrefixed rest0
  (result, rest2) <- takePrefixed rest1
  guardEmpty rest2
  recipe <- decodeRecipe (BC8.unpack nameBs) params
  pure (recipe, result)

-- | Reserve the persistent id from the store, commit the record
-- durably, and on success revoke the old binding and report the
-- id. When this live job was joined, its superseded id retires in
-- the SAME atomic delta (the old record canceled, recipe bytes
-- unchanged): the insert and the retirement land together or not
-- at all, with no store I/O between the insert decision and the
-- revoke. Reservation and insertion are two durable commits: a
-- reservation failure reports before anything is written, and a
-- failed insertion leaves a gap in the id sequence (the burned id
-- is never reused, never re-minted). A refused insertion reports
-- with the old attachment preserved. An ambiguous insert reloads
-- and reconciles: present means the record IS durable (retire, revoke
-- and succeed — the caller asked for durability, which held),
-- absent means nothing was written (abort and report, old
-- attachment preserved).
commitDetach
  :: DetachCtx -> AsyncTable -> JobId -> LeaseView -> JobExecState -> JobBody -> IO DetachOutcome
commitDetach dc table jid view execState body = do
  eToks <- storeLoadTokens (dcStore dc)
  case eToks of
    Left err ->
      pure (DetachStore err)
    Right toks -> case [t | (t, _) <- toks, trId t == dcToken dc] of
      [] ->
        pure DetachNoToken
      (trec : _) -> do
        eSup <- loadSuperseded dc table jid
        case eSup of
          Left err ->
            pure (DetachStore err)
          Right mSup -> do
            ePid <- storeReserveJobId (dcStore dc)
            case ePid of
              Left err ->
                pure (DetachStore err)
              Right pid -> do
                let rec = JobRecord
                      { jrPersistentId = pid
                      , jrToken = dcToken dc
                      , jrTokenGeneration = trGeneration trec
                      , jrFunction = jobFunctionName (jobSnapshotFunction (lvSnapshot view))
                      , jrState = execState
                      , jrBody = body
                      }
                    puts = case mSup of
                      Nothing -> [rec]
                      Just (_, oldRec) -> [rec, oldRec { jrState = JobCanceled }]
                    delta = emptyDelta { sdPutJobs = puts }
                res <- storeCommit (dcStore dc) delta
                case res of
                  Committed -> do
                    case mSup of
                      Nothing -> pure ()
                      Just (pid1, _) -> setTerminal dc pid1 JobCanceled
                    lvCommit view
                    setIdle dc pid
                    pure (DetachOk pid)
                  NotCommitted err ->
                    pure (DetachStore err)
                  CommitUnknown err ->
                    reconcileDetach dc view pid (fmap fst mSup) delta err

-- | Resolve the superseded id (when this live job was joined) and
-- load its record, BEFORE the insert commits, so the insert and the
-- retirement land in one atomic delta. 'Nothing' when the job was
-- never joined (a plain first detach). A load failure or a missing
-- record refuses the detach with the live binding preserved: the
-- retirement cannot be staged, so nothing is written.
loadSuperseded
  :: DetachCtx -> AsyncTable -> JobId
  -> IO (Either StoreError (Maybe (Word64, JobRecord)))
loadSuperseded dc table jid = do
  rev <- tcReverse <$> atomically (readClaims dc)
  case Map.lookup (asyncTableId table, jid) rev of
    Nothing -> pure (Right Nothing)
    Just pid1 -> do
      eJobs <- storeLoadJobs (dcStore dc)
      case eJobs of
        Left err -> pure (Left err)
        Right jobs -> case [r | r <- jobs, jrPersistentId r == pid1] of
          [] -> pure (Left (StoreRevisionConflict "superseded job is gone"))
          (oldRec : _) -> pure (Right (Just (pid1, oldRec)))

-- | Reconcile an ambiguous detach commit against a fresh reload.
-- The delta carries the insert plus, on a re-detach, the superseded
-- retirement, and reconciliation requires every put present: on
-- present both landed, so the superseded id resolves terminal in
-- memory before the revoke; on absent nothing was written (abort
-- and report, old attachment preserved).
reconcileDetach
  :: DetachCtx -> LeaseView -> Word64 -> Maybe Word64 -> StoreDelta -> StoreError
  -> IO DetachOutcome
reconcileDetach dc view pid mPid1 delta err = do
  _ <- storeReload (dcStore dc)
  eJobs <- storeLoadJobs (dcStore dc)
  case eJobs of
    Left _ ->
      pure (DetachStore err)
    Right jobs -> case reconcileJobsReload delta jobs of
      ReconciledPresent -> do
        case mPid1 of
          Nothing -> pure ()
          Just pid1 -> setTerminal dc pid1 JobCanceled
        lvCommit view
        setIdle dc pid
        pure (DetachOk pid)
      ReconciledAbsent ->
        pure (DetachStore err)
