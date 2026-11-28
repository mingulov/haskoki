{- | FFI acquisition hygiene probes, behavioral half.

NULL pins for config-injected failures (bad SQLite path, refused
seating, oversize catalog), plus a non-poisoning pin (a failed
open never breaks the next open).

The async-window probe ('caseStdAsyncSlow'): async exceptions
delivered mid-open are rethrown from the inner opens (sync
failures stay NULL-identical; the @foreign export@ boundary keeps
its catch-all so no Haskell exception crosses into C), so the
mid-open kill aborts the open.

Probe shape (deliberately NOT a kill spray): the victim opens
through injected acquisition steps whose backend step signals
@entered@ and then parks on a gate, so the victim is blocked
inside the open when main fires ONE @killThread@. The gate (not
a timing margin) puts the delivery mid-open: however late the
kill arrives, the victim cannot have completed the open. Main
then releases the gate, so a missed kill would surface as a
completed open instead of a wedge, and joins on @outcome@. Both
joins carry a 10s 'System.Timeout' backstop ('assertFailure' on
expiry) per the no-wedge rule. Prior attempts wedged here with a
masked-driver kill spray: the first kill lands before the victim
installs its report handler, the victim dies silently, and the
join blocks forever (64\/64 kills returned,
@iters=0@, @outcome=Nothing@). The entered-rendezvous makes that
impossible: no kill precedes handler installation.

The structural half (hook-injected leak probes over the bracket
acquisition, plus the crypto-guard unwind probe) lives in the
engine suite (@FfiAcquireSpec@). Crypto cases live there (not
here) because this suite's @ConfigSpec@
mutates @HASKOKI_CONFIG@ process-wide and tasty runs cases in
parallel; the engine suite has no environment writers, so its
crypto probes are race-free.
-}
{-# LANGUAGE OverloadedStrings #-}
module FfiAsyncSpec (spec, commitPathWarmup) where


import Test.Tasty (TestTree, inOrderTestGroup)
import Test.Tasty.HUnit (testCase)

import FfiAsync.Admission
import FfiAsync.Fixtures
import FfiAsync.Handoff
import FfiAsync.Open
import FfiAsync.Retirement
import FfiAsync.Standalone
import OwnershipCounters (counted)

spec :: TestTree
-- Every case in this group runs alone, one at a time, under tasty's
-- 'inOrderTestGroup' (no lock value: the scheduler orders the
-- cases, so no worker idles holding one and wait time never counts
-- against a case's timeout; the dependency-group variant would
-- shield earlier cases from '-p' filtering and break the
-- ownership-matrix patterns, so this group uses the variant whose
-- filtering matches 'testGroup'). The RTS reuses freed 'StablePtr'
-- values, so
-- two parallel cases could observe the same pointer bits: a caller
-- parked before its lookup admitted to a new owner that registered
-- those bits live (wrong refusal code), a borrower census counting
-- a foreign caller, and fixture teardown that retires and frees
-- without the close-path drain freeing under another case's
-- admitted caller (use-after-free). Sequencing also removes the
-- concurrent first-evaluation races that coincided with the
-- commit-path BlackHole hangs. Two of those shapes were product
-- defects, fixed alongside: borrowed-view closes now defer their
-- free behind the entry's borrow count, and the provider pins one
-- RTS capability. The 'counted' wrapper on each case is unchanged
-- (child thread, labels, ownership counters). Sequencing covers
-- this group only: keys stay safe across groups because each case
-- pins its keys through its assertions (pin-while-allocated), or
-- accepts both codes under reuse, and no other group parks callers
-- or holds test borrows. Do not parallelize this group without re-proving
-- every tombstone, census, reclaim and hang assertion under
-- parallel execution.
spec = inOrderTestGroup "FFI acquisition"
  [ testCase "std open succeeds then closes" (counted "m3-ffi-acquisition" "std-open-succeeds-then-closes" (caseStdSuccess))
  , testCase "std open bad sqlite path is NULL" (counted "m3-ffi-acquisition" "std-open-bad-sqlite-path-is-null" (caseStdBadSqlite))
  , testCase "std open zero slots is NULL" (counted "m3-ffi-acquisition" "std-open-zero-slots-is-null" (caseStdZeroSlots))
  , testCase "std open oversize catalog is NULL" (counted "m3-ffi-acquisition" "std-open-oversize-catalog-is-null" (caseStdOversize))
  , testCase "std failed open does not poison the next" (counted "m3-ffi-acquisition" "std-failed-open-does-not-poison-the-next" (caseStdNonPoison))
  , testCase "std async kill aborts the open (none swallowed)" (counted "m3-ffi-acquisition" "std-async-kill-aborts-the-open-none-swallowed" (caseStdAsyncSlow))
  , testCase "close-one keeps the other context live" (counted "m3-ffi-acquisition" "close-one-keeps-the-other-context-live" (caseCloseOneKeepsOther))
  , testCase "close waits for an entered caller" (counted "m3-ffi-acquisition" "close-waits-for-an-entered-caller" (caseCloseWaitsForEntered))
  , testCase "admitted calls run; close retires the gate" (counted "m3-ffi-acquisition" "admitted-calls-run-close-retires-the-gate" (caseAdmittedCallsRun))
  , testCase "kill in the submit transfer cancels the fresh job" (counted "m3-ffi-acquisition" "kill-in-the-submit-transfer-cancels-the-fresh-job" (caseSubmitKillCancelsFresh))
  , testCase "submit under a key function refuses without allocating" (counted "m3-ffi-acquisition" "submit-under-a-key-function-refuses-without-allocating" caseSubmitKeyFunctionRefuses)
  , testCase "kill in the join handoff cancels the fresh join" (counted "m3-ffi-acquisition" "kill-in-the-join-handoff-cancels-the-fresh-join" (caseHandoffKillCancelsJoin))
  , testCase "join handoff publishes a live handle" (counted "m3-ffi-acquisition" "join-handoff-publishes-a-live-handle" (caseHandoffPublishes))
  , testCase "kill after join commit cancels before publish" (counted "m3-ffi-acquisition" "kill-after-join-commit-cancels-before-publish" (caseJoinAcquireKillAfterCommit))
  , testCase "join acquire publishes a live handle" (counted "m3-ffi-acquisition" "join-acquire-publishes-a-live-handle" (caseJoinAcquirePublishes))
  , testCase "killed close releases; retry completes teardown" (counted "m3-ffi-acquisition" "killed-close-releases-retry-completes-teardown" (caseCloseKillRetryCompletes))
  , testCase "concurrent entry races close cleanly" (counted "m3-ffi-acquisition" "concurrent-entry-races-close-cleanly" (caseEnterCloseRace))
  , testCase "borrowed start works" (counted "m3-ffi-acquisition" "borrowed-start-works" (caseBorrowedStart))
  , testCase "owned close hands its index to a borrowed view" (counted "m3-ffi-acquisition" "owned-close-hands-its-index-to-a-borrowed-view" (caseOwnedToBorrowedReuse))
  , testCase "caller parked pre-lookup meets the tombstone" (counted "m3-ffi-acquisition" "caller-parked-pre-lookup-meets-the-tombstone" (caseEnterBarrierCloseTombstones))
  , testCase "retire clears the entry hook" (counted "m3-ffi-acquisition" "retire-clears-the-entry-hook" (caseRetireClearsHook))
  , testCase "registry roots reclaim across churn" (counted "m3-ffi-acquisition" "registry-roots-reclaim-across-churn" (caseRegistryRootsReclaim))
  , testCase "stacked displacements preserve every root" (counted "m3-ffi-acquisition" "stacked-displacements-preserve-every-root" (caseReclaimOverlappingReuse))
  , testCase "kill during acquire rolls back and nulls" (counted "m3-ffi-acquisition" "kill-during-acquire-rolls-back-and-nulls" (caseJoinAcquireKillDuringAcquire))
  , testCase "session close defers the borrowed view free" (counted "m3-ffi-acquisition" "session-close-defers-the-borrowed-view-free" (caseSessionCloseDefersViewFree))
  , testCase "instance close defers the borrowed view free" (counted "m3-ffi-acquisition" "instance-close-defers-the-borrowed-view-free" (caseInstanceCloseDefersViewFree))
  , testCase "open rollback defers the borrowed view free" (counted "m3-ffi-acquisition" "open-rollback-defers-the-borrowed-view-free" (caseOpenRollbackDefersViewFree))
  , inOrderTestGroup "standalone ownership"
      [ testCase "store box killed after store open closes the store" (counted "m3-standalone-ownership" "store-box-killed-after-store-open-closes-the-store" (caseBoxKilledAfterStoreOpen))
      , testCase "store box killed after token setup closes the store" (counted "m3-standalone-ownership" "store-box-killed-after-token-setup-closes-the-store" (caseBoxKilledAfterTokenSetup))
      , testCase "store box killed during token load closes the store" (counted "m3-standalone-ownership" "store-box-killed-during-token-load-closes-the-store" (caseBoxKilledDuringTokenLoad))
      , testCase "sqlite store box killed after token setup releases its lock" (counted "m3-standalone-ownership" "sqlite-store-box-killed-after-token-setup-releases-its-lock" (caseSqliteBoxKilledAfterTokenSetup))
      , testCase "context killed after backend open closes the backend" (counted "m3-standalone-ownership" "context-killed-after-backend-open-closes-the-backend" (caseCtxKilledAfterBackendOpen))
      , testCase "context killed after session open closes the backend" (counted "m3-standalone-ownership" "context-killed-after-session-open-closes-the-backend" (caseCtxKilledAfterSessionOpen))
      , testCase "context killed after pointer allocation frees it unregistered" (counted "m3-standalone-ownership" "context-killed-after-pointer-allocation-frees-it-unregistered" (caseCtxKilledAfterCtxAlloc))
      , testCase "store-bound context killed after reload leaves the box usable" (counted "m3-standalone-ownership" "store-bound-context-killed-after-reload-leaves-the-box-usable" (caseStoreBoundKilledAfterReload))
      , testCase "export store open residue is recovered by the next open" (counted "m3-standalone-ownership" "export-store-open-residue-is-recovered-by-the-next-open" (caseExportResidueRecoveredByNextOpen))
      , testCase "closer killed in the store wait stays closing and retries" (counted "m3-standalone-ownership" "closer-killed-in-the-store-wait-stays-closing-and-retries" (caseCloserKilledInStoreWait))
      , testCase "closer killed in a job lease wait cancels once on retry" (counted "m3-standalone-ownership" "closer-killed-in-a-job-lease-wait-cancels-once-on-retry" (caseCloserKilledInLeaseWait))
      , testCase "closer killed in the backend gate wait frees the env once on retry" (counted "m3-standalone-ownership" "closer-killed-in-the-backend-gate-wait-frees-the-env-once-on-retry" (caseCloserKilledInBackendGateWait))
      , testCase "store failure in retirement still closes and keeps the record joinable" (counted "m3-standalone-ownership" "store-failure-in-retirement-still-closes-and-keeps-the-record-joinable" (caseStoreFailureInRetirement))
      , testCase "table close phases move only forward after teardown starts" (counted "m3-standalone-ownership" "table-close-phases-move-only-forward-after-teardown-starts" (caseTableClosePhasesMoveOnlyForward))
      , testCase "unknown registry key refuses without admission" (counted "m3-standalone-ownership" "unknown-registry-key-refuses-without-admission" (caseUnknownKeyRefusesWithoutAdmission))
      , testCase "hook-only registry key refuses after its hook" (counted "m3-standalone-ownership" "hook-only-registry-key-refuses-after-its-hook" (caseHookOnlyRefusesAfterHook))
      , testCase "close of an unknown key nulls the slot only" (counted "m3-standalone-ownership" "close-of-an-unknown-key-nulls-the-slot-only" (caseCloseUnknownNullsSlotOnly))
      , testCase "close with a throwing retire resumes on retry" (counted "m3-standalone-ownership" "close-with-a-throwing-retire-resumes-on-retry" (caseCloseTailThrowResumesOnRetry))
      , testCase "close with a throwing free resumes on retry" (counted "m3-standalone-ownership" "close-with-a-throwing-free-resumes-on-retry" (caseCloseTailFreeThrowResumesOnRetry))
      , testCase "store throw in retirement still closes and keeps the record joinable" (counted "m3-standalone-ownership" "store-throw-in-retirement-still-closes-and-keeps-the-record-joinable" (caseStoreThrowInRetirementStillCloses))
      , testCase "commit throw reports only the uncommitted rows" (counted "m3-standalone-ownership" "commit-throw-reports-only-the-uncommitted-rows" (caseCommitThrowReportsOnlyUncommitted))
      , testCase "value-level close killed in a lease wait resumes" (counted "m3-standalone-ownership" "value-level-close-killed-in-a-lease-wait-resumes" (caseValueCloseKilledInLeaseWaitResumes))
      , testCase "block wait rejects other block reasons" (counted "m3-standalone-ownership" "block-wait-rejects-other-block-reasons" (caseBlockWaitRejectsOtherReasons))
      , testCase "null slot and null pointer closes are silent" (counted "m3-standalone-ownership" "null-slot-and-null-pointer-closes-are-silent" (caseNullClosesAreSilent))
      , testCase "repeated context close frees and retires once" (counted "m3-standalone-ownership" "repeated-context-close-frees-and-retires-once" (caseRepeatedCloseFreesOnce))
      , testCase "failed store close keeps the box slot until a retry succeeds" (counted "m3-standalone-ownership" "failed-store-close-keeps-the-box-slot-until-a-retry-succeeds" (caseFailedStoreCloseKeepsBoxSlot))
      , testCase "store box close killed in the lock wait keeps the box" (counted "m3-standalone-ownership" "store-box-close-killed-in-the-lock-wait-keeps-the-box" (caseBoxCloseKilledInLockWaitKeepsBox))
      , testCase "box close step parks before the transfer" (counted "m3-standalone-ownership" "box-close-step-parks-before-the-transfer" (caseBoxCloseStepParksBeforeTransfer))
      , testCase "context close step parks before the transfer" (counted "m3-standalone-ownership" "context-close-step-parks-before-the-transfer" (caseCtxCloseStepParksBeforeTransfer))
      , testCase "interrupted residue retry puts back every entry" (counted "m3-standalone-ownership" "interrupted-residue-retry-puts-back-every-entry" (caseResidueRetryInterruptedPutsBack))
      , testCase "standalone churn leaves no orphan roots or native envs" (counted "m3-standalone-ownership" "standalone-churn-leaves-no-orphan-roots-or-native-envs" (caseStandaloneChurnLeavesNoOrphans))
      , testCase "joined cleanup lets the same store reopen" (counted "m3-standalone-ownership" "joined-cleanup-lets-the-same-store-reopen" (caseJoinedCleanupReopensSameStore))
      , testCase "joined cleanup lets the same sqlite store reopen" (counted "m3-standalone-ownership" "joined-cleanup-lets-the-same-sqlite-store-reopen" (caseJoinedCleanupReopensSameSqliteStore))
      ]
  ]

-- | GHC #27272 warm-up MITIGATION (not a fix), run once by the
-- model suite's 'Main' before tasty forks any worker: one
-- seat-token commit, single-threaded, so the commit-path constants
-- are values before any two workers can first-evaluate them
-- together (the orphaned-black-hole hang of the known upstream
-- runtime bug GHC #27272). This lowers the hang rate; it does not
-- fix the upstream bug.
commitPathWarmup :: IO ()
commitPathWarmup = mkFfiStore >> pure ()
