{- | Detached commit protocol.
-}
module Haskoki.Runtime.Storage.Commit
  ( FaultPoint (..)
  , FaultInjector (..)
  , noFaults
  , scriptedFaults
  , withMaskHook
  , withResultHook
  , StoreStats (..)
  , zeroStats
  , PublicationAdvice (..)
  , decidePublication
  , Reconcile (..)
  , reconcileReload
  , reconcileJobsReload
  , reconcileCredentialsReload
  , jobIdCounterKey
  , nextJobReservation
  , coverDeletedJobIds
  ) where

import Data.Word (Word64)
import Data.IORef (IORef, atomicModifyIORef', newIORef)
import Haskoki.Runtime.Storage.Deltas
import Haskoki.Runtime.Storage.Records
import Haskoki.Runtime.Storage.Word64Hex

-- ---------------------------------------------------------------------------
-- Commit protocol
-- ---------------------------------------------------------------------------

-- | Fault-injection points in the commit path, plus the close
-- path ('FaultClose'). A fired 'FaultClose' simulates a failed
-- close: ownership and guards are retained, the handle stops
-- serving new operations, the close reports the failure by
-- throwing, and a later close retries for real. Both backends
-- honor it identically (one shot, like every other point).
data FaultPoint
  = FaultBeforeCommit
  | FaultAmbiguousCommit
  | FaultVerifyReload
  | FaultAfterCommit
  | FaultFullDisk
  | FaultClose
  deriving (Eq, Show)

-- | One-shot fault injector plus masked-region observation hooks.
-- 'fiFire' reports 'True' once per scripted occurrence of the
-- probed point. The hooks are test observability: 'fiOnMasked'
-- fires on entry to the masked commit region, 'fiOnResult' fires
-- with the determined result while still masked. Both default to
-- no-ops; neither affects the commit outcome.
data FaultInjector = FaultInjector
  { fiFire :: FaultPoint -> IO Bool
  , fiOnMasked :: IO ()
  , fiOnResult :: CommitResult -> IO ()
  }

-- | The inert injector: no faults, no hooks.
noFaults :: FaultInjector
noFaults = FaultInjector
  { fiFire = \_ -> pure False
  , fiOnMasked = pure ()
  , fiOnResult = \_ -> pure ()
  }

-- | An injector that fires once per listed script entry, in any
-- probe order (each probe consumes at most one matching entry).
scriptedFaults :: [FaultPoint] -> IO FaultInjector
scriptedFaults script = do
  v <- newIORef script
  pure FaultInjector
    { fiFire = firing v
    , fiOnMasked = pure ()
    , fiOnResult = \_ -> pure ()
    }
  where
    firing :: IORef [FaultPoint] -> FaultPoint -> IO Bool
    firing v p = atomicModifyIORef' v (\s -> case removeFirst p s of
      (fired, s') -> (s', fired))

-- | Remove the first matching entry, reporting whether one fired.
removeFirst :: Eq a => a -> [a] -> (Bool, [a])
removeFirst _ [] = (False, [])
removeFirst x (y : ys)
  | x == y = (True, ys)
  | otherwise = let (fired, rest) = removeFirst x ys in (fired, y : rest)

-- | Attach a masked-entry hook to an injector.
withMaskHook :: IO () -> FaultInjector -> FaultInjector
withMaskHook hook inj = inj { fiOnMasked = hook }

-- | Attach a result hook to an injector. The hook fires inside the
-- masked region with the determined 'CommitResult'.
withResultHook :: (CommitResult -> IO ()) -> FaultInjector -> FaultInjector
withResultHook hook inj = inj { fiOnResult = hook }

-- | Per-handle commit counters: known durable commits,
-- verification reloads run, and quarantine events (per token).
data StoreStats = StoreStats
  { ssCommits :: !Int
  , ssVerifyReloads :: !Int
  , ssQuarantines :: !Int
  } deriving (Eq, Show)

-- | Zeroed counters.
zeroStats :: StoreStats
zeroStats = StoreStats
  { ssCommits = 0
  , ssVerifyReloads = 0
  , ssQuarantines = 0
  }

-- | What the runtime must do with its in-memory delta after a
-- commit: publish it, drop it, or reload the authoritative state
-- and reconcile before deciding.
data PublicationAdvice
  = PublishDelta
  | PublishNothing
  | ReloadFirst
  deriving (Eq, Show)

-- | The runtime publication rule, pure: only 'Committed'
-- publishes; 'CommitUnknown' must reload first and must never
-- blindly reissue the operation.
decidePublication :: CommitResult -> PublicationAdvice
decidePublication result = case result of
  Committed -> PublishDelta
  NotCommitted _ -> PublishNothing
  CommitUnknown _ -> ReloadFirst

-- | Reload reconciliation: does the authoritative state contain
-- exactly the committed delta (every put present with equal
-- content, every drop absent)?
data Reconcile
  = ReconciledPresent
  | ReconciledAbsent
  deriving (Eq, Show)

-- | Compare a delta against reloaded state with full-record
-- equality (pure; shared by the backends' ambiguous-commit
-- verification and the caller's post-'CommitUnknown' decision).
-- Token puts compare scrubbed ('scrubDeltaAuth' at the commit
-- boundary, and the projection scrubs before issuing), so an
-- auth-only write reconciles present exactly when it landed.
reconcileReload :: StoreDelta -> [(TokenRecord, [ObjectRecord])] -> Reconcile
reconcileReload delta loaded
  | all tokenPutPresent (sdPutTokens delta)
  , all tokenDropAbsent (sdDropTokens delta)
  , all objectPutPresent (sdPutObjects delta)
  , all objectDropAbsent (sdDropObjects delta) = ReconciledPresent
  | otherwise = ReconciledAbsent
  where
    toks = [(trId t, t) | (t, _) <- loaded]
    objs = [(orId o, o) | (_, os) <- loaded, o <- os]
    tokenPutPresent t = lookup (trId t) toks == Just t
    tokenDropAbsent tid = tid `notElem` map fst toks
    objectPutPresent p = lookup (orId (opRecord p)) objs == Just (opRecord p)
    objectDropAbsent oid = oid `notElem` map fst objs

-- | Compare a delta's jobs against reloaded jobs with full-record
-- equality. Backends AND this with 'reconcileReload' so an
-- ambiguous commit verifies only when every table agrees.
reconcileJobsReload :: StoreDelta -> [JobRecord] -> Reconcile
reconcileJobsReload delta jobs
  | all jobPutPresent (sdPutJobs delta)
  , all jobDropAbsent (sdDropJobs delta) = ReconciledPresent
  | otherwise = ReconciledAbsent
  where
    byId = [(jrPersistentId j, j) | j <- jobs]
    jobPutPresent j = lookup (jrPersistentId j) byId == Just j
    jobDropAbsent pid = pid `notElem` map fst byId

-- | Compare a delta's credentials against reloaded credentials
-- with full-record equality (the job-table precedent: backends
-- AND this with 'reconcileReload' and 'reconcileJobsReload').
-- A credential put naming a token dropped in the same delta
-- never reaches reconciliation: @checkTokenRefs@ refuses it at
-- validation, since the projected token set has no such token.
reconcileCredentialsReload :: StoreDelta -> [CredentialRecord] -> Reconcile
reconcileCredentialsReload delta creds
  | all credPutPresent (sdPutCredentials delta)
  , all credDropAbsent (sdDropCredentials delta) = ReconciledPresent
  | otherwise = ReconciledAbsent
  where
    byToken = [(crToken c, c) | c <- creds]
    credPutPresent c = lookup (crToken c) byToken == Just c
    credDropAbsent tid = tid `notElem` map fst byToken

-- | The metadata key carrying the store-wide
-- next-persistent-job-id high-water mark (16-hex-character
-- 'Word64', starting at 1). The key predates durable
-- reservation (schema version 1 seeds it), so adopting it
-- changes no row format and no schema version.
jobIdCounterKey :: String
jobIdCounterKey = "next_persistent_job_id"

-- | Pure reservation step shared by both backends: given the
-- stored counter value ('Nothing' = the key is absent, as on a
-- fresh memory world or a hand-built database) and the
-- persistent ids currently stored, compute the id to hand out
-- plus the counter value to persist. The mark reconciles with
-- the stored maximum ('maxJob + 1') without ever lowering, a
-- corrupt counter fails closed, and exhaustion refuses before
-- the 'Word64' domain can wrap — so every increment below is
-- guarded and no arithmetic here can overflow.
nextJobReservation :: Maybe String -> [Word64] -> Either StoreError (Word64, String)
nextJobReservation mStored pids = do
  stored <- case mStored of
    Nothing -> Right 1
    Just s -> case decodeHexWord64 s of
      Just w -> Right w
      Nothing -> Left (StoreCorrupt
        ("corrupt " ++ jobIdCounterKey ++ " counter: " ++ show s))
  need <- case pids of
    [] -> Right 1
    _ -> let m = maximum pids
         in if m == maxBound
              then Left exhausted
              else Right (m + 1)
  let next = max stored need
  if next == maxBound
    then Left exhausted
    else Right (next, encodeHexWord64 (next + 1))
  where
    exhausted = StoreFull
      "persistent job id space exhausted (refusing before Word64 wrap)"

-- | Advance a job-id high-water mark to cover pids whose
-- records are being deleted (reset, token drop, or explicit
-- job drop): the mark becomes at least every deleted pid + 1,
-- saturating at 'maxBound' (which reservations already refuse)
-- so no arithmetic here can wrap. Backends fold this over the
-- doomed set inside the deleting commit, so a legacy store
-- whose mark never advanced still cannot re-mint a deleted id
-- after the evidence is gone. An empty doomed set leaves the
-- mark untouched. A corrupt mark stays corrupt — and
-- reservations keep failing closed — until an explicit,
-- authoritative repair re-establishes it: deleted rows alone
-- cannot reconstruct the full issued history, so deriving a
-- small counter from them could re-mint an id whose row is
-- already gone. 'Nothing' means the key stays absent.
coverDeletedJobIds :: Maybe String -> [Word64] -> Maybe String
coverDeletedJobIds mStored doomed
  | null doomed = mStored
  | otherwise = case base of
      Just b -> Just (encodeHexWord64 (foldr max b (map saturate doomed)))
      Nothing -> mStored
  where
    base = case mStored of
      Nothing -> Just 1
      Just s -> decodeHexWord64 s
    saturate p = if p == maxBound then maxBound else p + 1
