{- | Async lease helpers and retention.
-}
module Haskoki.Runtime.Async.Lease
  ( maxRetainedTombstones
  , maxRetainedBytes
  , retainedBytes
  , commitStep
  , withJobLock
  ) where

import Control.Concurrent.MVar
  (withMVar)
import Control.Concurrent.STM
  ( atomically
  , readTVar
  , readTVarIO
  , writeTVar
  )
import Control.Exception
  ( mask_
  , onException
  )
import qualified Data.ByteString as BS
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Haskoki.Attribute (AttributeValue (..))
import Haskoki.CallWork
  ( callWorkEffect
  , callWorkReservation
  )
import Haskoki.Model (SessionState (..))
import Haskoki.Operation.Effect
  ( CryptoEffect (..)
  )
import Haskoki.Operation.KeyManagement
  ( PendingObject (..)
  , PendingWork (..)
  )
import Haskoki.Operation.State (sessionOpsBytes)
import Haskoki.Outcome
  ( CryptoStep (..)
  , EffectRequest (..)
  , Reservation (..)
  )
import Haskoki.Runtime.Usdt (Disposition (..), JobPhase (..))
import Haskoki.ReturnCode.Generated (returnCodeToRV)
import Haskoki.Types
  ( JobId (..)
  , ReturnCode (..)
  , retainedStringBytes
  )
import Haskoki.Runtime.Async.Jobs
import Haskoki.Runtime.Async.Completion
import Haskoki.Runtime.Async.Table

-- ---------------------------------------------------------------------------
-- Lease helpers (STM touches job-table TVars only)
-- ---------------------------------------------------------------------------

-- | Run under a job's delivery lease. Unknown jobs take the
-- default without locking.
--
-- The pre-lock record supplies ONLY the stable lease lock (the
-- 'MVar' survives every record replacement for the job's life).
-- The body always runs against the CURRENT record, reloaded under
-- the held lease, so the state and epoch it decides on are read
-- together — never a fresh state paired with a stale epoch. A job
-- missing at reload — reaped or evicted while waiting for the
-- lease (eviction takes no lease) — takes the default without
-- running the body, exactly as if it were unknown at admission.
--
-- Ownership rule R1 backstop: an exception escaping a lease body with the job
-- still claimed ('JobRunning') repairs the claim to failed (masked,
-- best-effort), then rethrows. Stable states (pending\/ready\/
-- terminal) are untouched — in particular a delivery throw leaves
-- 'Ready' (R6 recoverable). Lock release and state repair composed.
withJobLock
  :: AsyncTable -> JobId -> a -> (Job -> IO a) -> IO a
withJobLock table jid def k = do
  mj <- readTVarIO (atJobs table) >>= pure . Map.lookup jid
  case mj of
    Nothing -> pure def
    Just pre -> withMVar (jbLock pre) (const (repairing (do
      cur <- readJob table jid
      case cur of
        Nothing -> pure def
        Just job -> k job)))
  where
    repairing body = body `onException` mask_ (do
      cur <- readJob table jid
      case cur of
        Just j -> case jbState j of
          JobRunning -> case stepJob
            (EvFail CKR_GENERAL_ERROR "lease escape while running")
            JobRunning (jbEpoch j) of
              Right s -> do
                commitStep table jid s
                let w = returnCodeToRV CKR_GENERAL_ERROR
                usdtJobPhase table jid j PhaseFailed w True
                usdtAsyncEnd j w DispFailedPublish
              Left _ -> pure ()
          _ -> pure ()
        Nothing -> pure ())

-- | Ceiling on retained terminal tombstones per table. Job ids
-- allocate monotonically, so the lowest id is the oldest
-- tombstone. The value clears the largest simulation volume the
-- stress suite asserts retained (16 workers x 200 jobs), keeping
-- every covered observe path byte-identical; only jobs past the
-- bound observe unknown. Per-table, and independent of the
-- live-job cap (which stays as-is).
maxRetainedTombstones :: Int
maxRetainedTombstones = 4096

-- | Ceiling on retained terminal-tombstone bytes per table: the
-- byte half of the dual retention bound (the other half is
-- 'maxRetainedTombstones'; eviction runs until BOTH hold).
--
-- Derivation (measured, not invented): the ruler prices a
-- small digest tombstone (hand reservation, 3-byte input,
-- 64-byte completion) at exactly 2931 bytes, so a count-full
-- table of 4096 small tombstones retains 12,005,376 bytes
-- (~11.5 MiB); the max-volume sim shape (3200 sign jobs)
-- retains 8,464,000 bytes (~8.1 MiB), and the canceled-sign
-- shape retains 11,358,208 bytes at full count (see the
-- footprint probe in the F-3 fix-round-1 report). 64 MiB is the
-- smallest power-of-two multiple of 'maxOutputBytes' clearing
-- that worst case with headroom to spare (5.6x over the 12.0 MB
-- full-count small-job ceiling): existing suites never approach
-- it, while the pre-fix ceiling (4096 tombstones x
-- attacker-sized inputs plus up-to-16 MiB outputs each,
-- ~64 GiB+) shrinks by three orders of magnitude. At least
-- three full-size (16 MiB) completions always fit alongside the
-- count backstop.
maxRetainedBytes :: Int
maxRetainedBytes = 64 * 1024 * 1024

-- | Whether a job state is a retained terminal tombstone.
isTerminalState :: JobState -> Bool
isTerminalState (JobTerminal _) = True
isTerminalState _ = False

-- | The byte-budget quantity: the summed 'tombstoneBytes' of a
-- table's terminal tombstones. Live jobs are excluded: they are
-- transient and count-capped (8 per instance), and each pins
-- caller-live memory for its in-flight operation anyway — the
-- byte budget bounds the durable tombstone set, which is the
-- FINAL-19 exhaustion path.
--
-- Accounting contract (bounded-ratio estimate of real heap, not a
-- literal upper bound): every attacker-influenced variable-length
-- payload a tombstone pins is measured exactly ('BS.length' per
-- 'ByteString', exact frame sizes for handles, 'retainedStringBytes'
-- per 'String'): effect inputs\/parameters\/AAD\/signatures
-- ('effectBytes'), key-template attribute bytes
-- ('pendingWorkBytes'), pinned session-snapshot bytes
-- ('sessionOpsBytes'), and completion payloads ('completionBytes').
-- Everything else a tombstone pins is trust-boundary-constructed
-- fixed scalars (records, constructors, map nodes, the lease lock,
-- revisions, ids, enums, at most one planner revision dep) covered
-- by 'perTombstoneOverhead'. Fixed-header undercount is bounded
-- (~1.1-3x worst case): measured bytes stay within a small constant
-- factor of real heap while every variable-length payload is exact,
-- so the budget cannot be defeated by header-heavy shapes. Collection scalars that scale with
-- attacker-influenced counts carry their own allowance
-- (template entries, snapshot slot sides) rather than hiding in
-- the constant. No 'ByteString' \/ 'String' field reachable
-- from a tombstone is uncounted.
retainedBytes :: AsyncTable -> IO Int
retainedBytes table = do
  jobs <- readTVarIO (atJobs table)
  pure (sum [tombstoneBytes job
            | job <- Map.elems jobs, isTerminalState (jbState job)])

-- | Fixed per-tombstone structural allowance: 2048 bytes covering
-- the scalar words every tombstone pins (job\/reservation\/step
-- records, the map node, the lease lock, revision deps, ids,
-- return codes, handle\/completion\/'ByteString' records —
-- worst-case census ~1.5 KiB, with margin). Payloads and
-- trust-boundary texts are measured separately, never from this
-- constant; see 'retainedBytes'.
perTombstoneOverhead :: Int
perTombstoneOverhead = 2048

-- | Retained-byte size of one tombstone. The eviction walk and
-- 'retainedBytes' only ever price terminal jobs; work bytes
-- price regardless of state (the work is pinned from submit)
-- while state bytes price only for terminal states.
tombstoneBytes :: Job -> Int
tombstoneBytes job =
  perTombstoneOverhead
  + workBytes (jbWork job)
  + stateBytes (jbState job)

-- | Retained bytes of a job's planned work: the reservation plus
-- the effect (call work), plus key-template bytes (key work).
workBytes :: AsyncWork -> Int
workBytes (WorkCall w) = case callWorkEffect w of
  EffectCrypto fx ->
    reservationBytes (callWorkReservation w) + effectBytes fx
workBytes (WorkKey res pw fx) =
  reservationBytes res + pendingWorkBytes pw + effectBytes fx

-- | Exact payload bytes of an effect: the summed length of every
-- 'ByteString' field of every constructor. Arms marked [H] are
-- holdable — the only effects a table can hold ('startJobChecked'
-- refuses the rest); arms marked [U] are unholdable and priced
-- defensively for totality. Exhaustive (no wildcard): a new
-- effect fails the build via @-Werror=incomplete-patterns@
-- instead of silently undercounting.
effectBytes :: CryptoEffect -> Int
effectBytes (FxDigest _ input) = BS.length input -- [H] input
effectBytes (FxDigestInit _) = 0 -- [U] allocation only
effectBytes (FxDigestFeed _ input) = BS.length input -- [H] input
effectBytes (FxDigestConsume _) = 0 -- [H] resource only
effectBytes (FxCipher _ _ _ params input) = -- [H] params + input
  BS.length params + BS.length input
effectBytes (FxSign _ _ params input) = -- [H] params + input
  BS.length params + BS.length input
effectBytes (FxVerify _ _ params input sig) = -- [U] params + input + signature
  BS.length params + BS.length input + BS.length sig
effectBytes (FxSignRecover _ _ params input _) = -- [H] params + input
  BS.length params + BS.length input
effectBytes (FxVerifyRecover _ _ params sig _) = -- [H] params + signature
  BS.length params + BS.length sig
effectBytes (FxMessageCipher _ _ _ params aad input) = -- [H] params + AAD + input
  BS.length params + BS.length aad + BS.length input
effectBytes (FxMessageSign _ _ params input) = -- [H] params + input
  BS.length params + BS.length input
effectBytes (FxMessageVerify _ _ params input sig) = -- [U] params + input + signature
  BS.length params + BS.length input + BS.length sig
effectBytes (FxGenerateKey _ params input) = -- [H] params + input
  BS.length params + BS.length input
effectBytes (FxWrap _ _ params input) = -- [H] params + input
  BS.length params + BS.length input
effectBytes (FxUnwrap _ _ params input) = -- [H] params + input
  BS.length params + BS.length input
effectBytes (FxAuthWrap _ _ params input) = -- [H] params + input
  BS.length params + BS.length input
effectBytes (FxAuthUnwrap _ _ params input) = -- [H] params + input
  BS.length params + BS.length input
effectBytes (FxDerive _ _ _ params input _) = -- [H] params + input
  BS.length params + BS.length input
effectBytes (FxKemEncaps _ _ params input) = -- [H] params + input
  BS.length params + BS.length input
effectBytes (FxKemDecaps _ _ params input) = -- [H] params + input
  BS.length params + BS.length input

-- | Retained bytes of a job's reservation: the operation name
-- plus any pinned planner step snapshot. Revision deps and the
-- resource id are fixed scalar words, trust-boundary-
-- constructed (planners emit exactly one dep; tests zero or
-- one) — covered by 'perTombstoneOverhead'.
reservationBytes :: Reservation -> Int
reservationBytes res =
  retainedStringBytes (resOperation res) + stepBytes (resStep res)

-- | Retained bytes of a pinned planner step: the region name
-- plus both session snapshots (post-plan ops and the session
-- state, which itself pins the post-plan ops — priced
-- separately because sharing between the two references is not
-- guaranteed). Function, kind, and intent are scalars.
stepBytes :: Maybe CryptoStep -> Int
stepBytes Nothing = 0
stepBytes (Just step) = retainedStringBytes (csName step)
  + sessionOpsBytes (csOps step)
  + sessionOpsBytes (ssOps (csSession step))

-- | Retained bytes of key-pending work: template attribute bytes
-- per pending object, plus the blob region name. Exhaustive over
-- all thirteen shapes (no wildcard) for the same fail-closed
-- reason as 'effectBytes'.
pendingWorkBytes :: PendingWork -> Int
pendingWorkBytes (PwGeneratePair pub priv) =
  pendingObjectBytes pub + pendingObjectBytes priv
pendingWorkBytes (PwGenerateKey key) = pendingObjectBytes key
pendingWorkBytes (PwGenerateKeyIv key _) = pendingObjectBytes key
pendingWorkBytes (PwEncaps secret _ _) = pendingObjectBytes secret
pendingWorkBytes (PwDecaps secret) = pendingObjectBytes secret
pendingWorkBytes (PwBlobOut region) = retainedStringBytes region
pendingWorkBytes (PwUnwrap key) = pendingObjectBytes key
pendingWorkBytes (PwUnwrapRaw key) = pendingObjectBytes key
pendingWorkBytes (PwUnwrapPad8 key) = pendingObjectBytes key
pendingWorkBytes (PwUnwrapTail key _ _) = pendingObjectBytes key
pendingWorkBytes (PwDerive keys _) = sum (map pendingObjectBytes keys)
pendingWorkBytes (PwDeriveIv keys _ _) = sum (map pendingObjectBytes keys)
pendingWorkBytes (PwDerivePub key _) = pendingObjectBytes key

-- | Retained bytes of one pending template object: exact
-- attribute payload bytes plus a 128-byte structural allowance
-- per template entry covering its fixed scalar words (the map
-- node, the attribute key, and the value record — roughly 96
-- bytes worst case, with margin). Entry counts are
-- attacker-influenced (up to @maxTemplateEntries@ entries of up
-- to @maxAttributeBytes@ each), so the allowance scales per
-- entry rather than hiding in 'perTombstoneOverhead'.
pendingObjectBytes :: PendingObject -> Int
pendingObjectBytes po = templateEntryStructural * Map.size (poAttrs po)
  + sum [attrValueBytes v | v <- Map.elems (poAttrs po)]
  where
    templateEntryStructural = 128

-- | Exact payload bytes of one attribute value (scalars carry no
-- bytes).
attrValueBytes :: AttributeValue -> Int
attrValueBytes (ValBool _) = 0
attrValueBytes (ValULong _) = 0
attrValueBytes (ValBytes bs) = BS.length bs

-- | Retained bytes of a job's execution state. Only terminal
-- states pin bytes (the delivery or the failure render); live
-- states are transient and count-capped (see 'retainedBytes'),
-- so they price at zero here.
stateBytes :: JobState -> Int
stateBytes (JobTerminal t) = terminalBytes t
stateBytes _ = 0

-- | Retained bytes of a terminal state: the completion payload,
-- or the failure render priced by 'retainedStringBytes'. Every
-- reachable failure site renders a short literal or a small
-- structured render (stale-revision, backend-error, and
-- contract-breach texts); the sole data-dependent render (the
-- defense-in-depth incoherent-key-pair diagnostic, which shows
-- the effect and templates) duplicates already-measured bytes
-- and cannot fire on production paths short of a planner
-- coherence bug (FFI submits call work only; the join path
-- replays planner-reproduced effects).
terminalBytes :: TerminalState -> Int
terminalBytes (TermDelivered c) = completionBytes c
terminalBytes TermCanceled = 0
terminalBytes (TermFailed _ why) = retainedStringBytes why

-- | Exact payload bytes of a completion: byte length for bytes
-- completions, exact 8-byte frame sizes for handle completions
-- (see 'encodeHandle').
completionBytes :: Completion -> Int
completionBytes (CompBytes bs) = BS.length bs
completionBytes (CompOneHandle _) = 8
completionBytes (CompTwoHandles _ _) = 16

-- | Drop oldest-first terminal tombstones until BOTH retention
-- bounds hold: at most 'maxRetainedTombstones' tombstones AND at
-- most 'maxRetainedBytes' retained bytes. Candidates exclude the
-- just-committed job (which a stale pending job may make the
-- lowest id) and always exclude live jobs, per the eviction
-- invariant. The walk removes the minimal oldest-first prefix:
-- it stops at the first prefix satisfying both bounds. The
-- just-committed job is always retained, so a single
-- over-budget job transiently exceeds the byte bound; the next
-- terminal commit evicts it once it is an elder.
enforceRetention :: JobId -> Map JobId Job -> Map JobId Job
enforceRetention jid jobs = foldr Map.delete jobs victims
  where
    tombstones =
      [(k, tombstoneBytes job)
      | (k, job) <- Map.toAscList jobs, isTerminalState (jbState job)]
    candidates = [(k, b) | (k, b) <- tombstones, k /= jid]
    victims = walk (length tombstones) (sum (map snd tombstones)) candidates
    walk _ _ [] = []
    walk count bytes ((k, b) : rest)
      | count <= maxRetainedTombstones && bytes <= maxRetainedBytes = []
      | otherwise = k : walk (count - 1) (bytes - b) rest

-- | Commit a 'stepJob' verdict for a job in one short
-- transaction. The only state writer: every transition site
-- commits a verdict, never a hand-built state. Every commit
-- enforces the dual retention bound synchronously (no reaper
-- thread).
commitStep :: AsyncTable -> JobId -> JobStep -> IO ()
commitStep table jid s = atomically $ do
  jobs <- readTVar (atJobs table)
  case Map.lookup jid jobs of
    Nothing -> pure ()
    Just job ->
      -- Forcing invariant: the pruned map is evaluated before the
      -- write lands. 'writeTVar' does not force its value, so an
      -- unevaluated prune would keep the whole pre-eviction map
      -- (evicted payloads included) alive until the next table
      -- read; idling after an evicting commit must still reclaim.
      -- Forcing to WHNF suffices: every 'Map.delete'/'Map.insert'
      -- scrutinizes its map argument, so the whole prune chain
      -- evaluates and the victims unlink. Every 'atJobs' writer
      -- keeps this invariant, so the stored spine is always
      -- evaluated.
      let pruned = enforceRetention jid
            (Map.insert jid job { jbState = stepState s, jbEpoch = stepEpoch s } jobs)
      in pruned `seq` writeTVar (atJobs table) pruned
