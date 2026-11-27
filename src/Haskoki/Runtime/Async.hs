{- | Attached asynchronous execution: logical scheduling, attached
jobs, and exact completion delivery.

A job is submitted on an async-enabled session with a planned unit
of work (a 'Reservation' plus its 'EffectRequest', the common plan
currency), an explicit completion schedule (polls before runnable),
and an attached output capacity. The logical executor runs the
effect into an owned result once the schedule elapses (poll-driven;
no background threads, no wall-clock sleeps), holds it, and the
completion step publishes the prepared commit and delivers the
completion record exactly once.

State machine per job (execution dimension; attachment stays
attached — detach\/rejoin belongs to the detached-jobs layer):

@
Pending ticks --poll--> Pending (ticks-1) | Running --drive--> Ready result
Ready --complete--> Delivered    Pending\/Running\/Ready --cancel--> Canceled
drive\/complete failure --> Failed
@

Discipline (architecture sections 6-8, design 07):

* Delivery lease: one 'MVar' per job guards poll\/complete\/cancel.
  The winner's critical section covers effect execution, commit
  publication, and delivery; losers block briefly, then observe the
  winner's terminal state and write nothing. Cancellation can never
  steal a commit, and two completions can never deliver twice.
* STM transactions coordinate @TVar@ state only: job-table reads
  and writes. Effect execution, publication (gate), and delivery
  (caller sinks) run outside 'atomically'.
* Pending paths never touch the result sink: not polled-pending,
  not complete-while-pending, not drive (which holds, not
  delivers). The sink fires exactly once, on the winning complete.
* Epochs: every terminal transition bumps the job's cancellation
  epoch, so arbitration order is observable per job.
* Synchronous sessions stay synchronous structurally: the sync
  plan\/publish path never consults the job table, and jobs exist
  only for sessions that explicitly requested async.

Ownership Contract (stated here; implemented by the async paths,
reconciled by the Publication\/Delivery section below):

* R1 drive: the claim ('JobRunning') is owned by the driving thread
  under the job lease. A sync runner throw terminalizes the job
  ('EvFail') and answers 'PollTerminal'; an async kill terminalizes
  first, then rethrows (cancellation preserved after cleanup). The
  lease backstop ('withJobLock') repairs any residual 'JobRunning'
  to failed on exception escape. Observable: never a permanently
  running job.
* R5 publish\/deliver: sizing-check, then publish, then a MASKED
  tail of drain-releases, delivery-write, and 'EvDeliver' commit —
  the write precedes the commit, so a throwing sink leaves 'Ready'.
  Short reports sizing with everything untouched; a faulted publish
  fails terminal with the sink untouched. Every finish drains its
  releases exactly once — on success, on rejection, AND on faulted
  publish (releases free resources that exist independent of
  the commit; skipping would orphan until backend close).
* R6 delivery failure is RECOVERABLE: a sync sink throw propagates
  with the job 'Ready' (retry re-finishes and re-publishes); a kill
  before the commit leaves 'Ready', a kill in the tail's
  non-blocking stretches is delayed past the commit (exactly-once
  write), and a kill in a BLOCKED sink lands (blocking calls stay
  killable under 'mask_') with the job still
  'Ready'. Sinks must be short and atomic; release interpreters
  must not throw.
* Detach composition: detach leases ('beginDetach' \/
  'withDetachLease') keep their masked take-to-handoff and
  commit\/abort pairing untouched; this contract adds no second
  lease — drive\/deliver repair runs INSIDE the job lease the
  detach protocol already coordinates with.
* Scope flags: aux-output rebind and expiry\/GC
  are ruled below; until then single-bytes-or-fail and manual
  'reapJob' stand.

Publication\/Delivery Contract (reconciles Standard
'publishCommit' with the async paths; stream ordering kept):

* Short-buffer retry: sizing-check first; short reports the need
  with no publish, no drain, no state change — the held result
  survives and the roomier retry drains exactly once on delivery.
* Publication failure: terminal-failed with the sink untouched;
  every finish drains its releases exactly once — on success, on
  rejection, AND on faulted publish (releases free resources that
  exist independent of the commit; frees are idempotent takes).
* Delivery failure: recoverable (R6) — the job stays 'Ready' and
  the retry re-finishes; op-state retries re-land and deliver,
  keygen retries mint fresh handles (first-published set
  orphaned — documented caveat).

Covered public entry paths (66 FFI exports surveyed 2026-09-23;
funnels: Standard\/Async\/Exports 'publishCommit' \/
'publishRejection' + job ops below):

* Async job ops (rules R1\/R5\/R6): 'haskoki_hs_async_start\/poll\/
  complete\/cancel', 'async_close' (cancels live jobs), 'async_join'
  (rejoin) and 'async_get_id' (detach) via the composed
  'joinJob'\/'detachJob' leases.
* Sync commit funnels (drain-always-once + fault rules): every
  plan+publish path — all 'haskoki_std_*' session\/object\/find\/
  login\/crypto\/keygen\/wrap\/derive entries (via
  'runCryptoPlan\/Silent\/Buffered\/Query\/Update',
  'runKeyPlan', 'runWrapPlan', 'runKeyedInit', or direct funnel
  sites), 'haskoki_hs_async_open\/open_on\/digest_init\/start'
  (Async funnel: proof sessions, init plan, start leg), and
  'haskoki_hs_crypto_open\/digest_init\/digest' (Exports funnel).
* OUT — read-only snapshots: 'std_get_slot_list\/get_session_info\/
  token_live\/token_label\/slot_present' (no mutation).
* OUT — cursor-local: 'std_find\/find_final' (instance 'IORef' only).
* OUT — backend-direct: 'std_generate_random\/seed_random'
  (backend RNG, no model commit).
* OUT — lifecycle alloc\/free: 'std_open\/close',
  'haskoki_hs_crypto_close' (instance + 'closeBackend', no commit).
* OUT — storage: 'async_store_open\/close' (file IO; storage contract).
* OUT — separate contracts: 'instance_open/close' (lifecycle driver),
  'haskoki_wait_for_slot_event'\/'haskoki_control' (control-events
  driver).
* Legacy (not live): 'commitAndDeliver' keeps its old
  no-drain-on-fault shape; test-only, out of this contract.

-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Haskoki.Runtime.Async
  ( -- * Jobs and functions
    JobFunction (..)
  , AsyncWork (..)
  , JobRequest (..)
  , StartDeny (..)
    -- * Completion records and codecs
  , Completion (..)
  , encodeCompletion
  , decodeCompletion
    -- * Outcomes
  , TerminalState (..)
  , JobState (..)
  , JobEvent (..)
  , JobReject (..)
  , JobStep
  , stepJob
  , stepState
  , stepEpoch
  , PollOutcome (..)
  , CompleteOutcome (..)
  , CancelOutcome (..)
  , ReapOutcome (..)
  , Delivery (..)
  , EffectRunner
    -- * Table
  , AsyncTable
  , AsyncTableId
  , TableIdExhausted
  , asyncTableId
  , asyncTableSalt
  , newAsyncTable
  , tryNewAsyncTable
  , tableSaltFor
  , maxRetainedTombstones
  , maxRetainedBytes
  , retainedBytes
  , enableAsyncSession
  , disableAsyncSession
  , isAsyncSession
  , enabledSessionCount
  , tableStats
  , deliveredCount
  , JobView (..)
  , inspectJob
  , jobReadyNeed
  , jobFunctionOf
  , sessionJobs
    -- * Close admission (borrowers drain before teardown)
  , TableClose (..)
  , Teardown (..)
  , Closer (..)
  , enterTableUse
  , exitTableUse
  , claimTableClose
  , beginTableTeardown
  , releaseTableClose
  , finishTableClose
  , awaitTableQuiescent
  , inspectTableGate
  , inspectTableClose
    -- * Detach support (snapshots, leases, seeded starts)
  , JobSnapshot
  , jobSnapshotFunction
  , jobSnapshotWork
  , jobSnapshotState
  , jobSnapshotTicks
  , jobSnapshotCapacity
  , jobSnapshotSession
  , jobSnapshotEpoch
  , JobSnapState (..)
  , snapshotJob
  , DetachLease
  , beginDetach
  , leaseSnapshot
  , commitDetachRevoke
  , abortDetach
  , LeaseView (..)
  , withDetachLease
  , leaseLockHeld
  , startSeededJob
    -- * Operations
  , startJob
  , startFixtureJob
  , effectHoldable
  , pollJob
  , completeJob
  , cancelJob
  , usdtSeededReady
  , reapJob
    -- * Scope classifiers (pure; see the rebind\/expiry rulings below)
  , callCompletion
  , ReapEligibility (..)
  , reapEligibility
    -- * Simulation bridge (scheduler advance)
  , advanceTicks
  ) where

import Haskoki.Runtime.Attach (AsyncTableId (..))
import Haskoki.Runtime.Async.Jobs
import Haskoki.Runtime.Async.Completion
import Haskoki.Runtime.Async.Outcomes
import Haskoki.Runtime.Async.Table
import Haskoki.Runtime.Async.Close
import Haskoki.Runtime.Async.Operations
import Haskoki.Runtime.Async.Lease
import Haskoki.Runtime.Async.Snapshot
import Haskoki.Runtime.Async.Sim
