# Decision note — operations surface

`hsp11` strings in design-bundle-derived files (e.g. trace paths
in `tests/ops/fixtures/*.toml`) are inherited verbatim from the
design bundle (see `tests/ops/fixtures/PROVENANCE.md`) and were
never the product name; the package ships as `haskoki`.

## TOML route: minimal hand parser (no new dependency)

The design examples use a small TOML subset (top-level scalars,
`[sections]`, strings, integers, booleans, string arrays, `#`
comments). Options considered:

1. Hackage `tomland` pinned in the freeze — full TOML, but a new
   dependency subtree against the pinned toolchain + index-state;
   resolution risk inside the container with no network fallback.
2. Minimal hand parser covering exactly the subset the example files
   use, with unknown-key rejection over an explicit known-key table.

Decision: (2). Rationale: the subset is fixed by the three example
fixtures (all parsed in tests), unknown-key rejection is a one-table
check either way, and zero new dependencies keeps the verified closure
unchanged (§8 packaging). If the config surface outgrows the subset,
revisit `tomland` with the example files as the conformance corpus.

The same "no new dependencies" constraint drives the minimal JSON
reader in `Haskoki.Runtime.Control` (control envelope + scenario
runner share it): `aeson` is not in the freeze.

## Public slot indications and retained private proofs

The four public tables (2.40/3.0/3.1/3.2) share one interval-local
`SlotEvents` service with Standard and the serving control owner.
`C_WaitForSlotEvent` consumes a pending **slot flag**, not an edge log.
All configured tokens start present at presence epoch zero, with flags clear.
Repeated remove/insert/remove changes coalesce into one pending slot;
selection is FIFO by first-pending order. A successful wait clears that
flag once. Queries do not acknowledge flags: query current slot information
after a wait, allowing for another change between the two calls. One flag
has one consumer among competing polls/blockers; there is no broadcast,
waiter fairness promise, or failure merely because a second waiter exists.
This stronger competing-waiter policy is Haskoki's contract; the standards
leave simultaneous application waits undefined (design §2.2).

The retained **private** `EventQueue`/`TokenRegistry` utilities still use
edge FIFO `DropOldest`/`DropNewest` policies and dropped counters.
`EventsSpec` exercises those private overflow, Haskell callback and
quiescence proofs. Public waits and serving presence controls do not use
that registry. Its `reentrantSlotSnapshot` and `ReentryRejected` proof
API does not make native slot queries callback-safe. The CLI's local
scenario owner is likewise separate from another process's loaded module.

`control.test_enabled=false` gives fixed software slots: always
`CKF_TOKEN_PRESENT`, no `CKF_REMOVABLE_DEVICE`. With test controls enabled,
every configured slot remains removable for the whole interval, including
while absent. `CKF_HW_SLOT` stays clear in both modes. Slot IDs, labels and
provisioned token identity are fixed within the interval; removal does not
delete a slot, and reinsertion restores its same token. Only the existing
in-process `token.insert`/`token.remove` controls produce presence changes.

`limits.events` must be positive and at least the catalog size at open;
the public service never clamps the bound or drops an admitted slot flag.
`limits.slots` still limits catalog admission. Presence epochs count true
transitions and refuse overflow. The control command generation counts
accepted mutations, including idempotent commands; stale expected generations
and overflow refuse before cleanup. Neither counter is the stored token
generation or a persistent async ID. See [configuration scope](config-honesty.md#serving-presence-and-private-scenario-scope).

Memory keeps `siStore = Nothing`; SQLite borrows the existing store.
Presence is not persisted: SQLite restart loads the provisioned tokens as
present with flags clear, while memory retains its existing transient
behavior. There is no extra store, reset, writer, watcher, event thread or
new ordinary-object durability contract. Store errors, login, objects,
session open/close and async completion do not create slot indications.

## Removal, wait outputs and finalization

Removal holds the C state lock, prepares retirement, and cancels Standard's
actual attached and joined jobs before atomically publishing model retirement,
absence, epoch and pending flag. Sessions, session objects, login state,
cursors, borrowed views and callback associations retire; token data is
parked and all old object handles remain stale after reinsertion. Other
slots and idle detached records retain their existing policy. Published
removal revokes the retired jobs' output bindings. Validation, query and
short-buffer refusals mutate nothing. A precommit fault publishes no event
but does not roll back cancellation already performed; a postcommit release
fault retains committed absence and runs remaining cleanup. These are the
distinct fault cases in `NotificationsEngineSpec` and the
[T-N03 review](../dist-release-evidence/notifications/task-n03/review.md).

For a known empty slot, `C_GetSlotList(CK_FALSE)` retains the slot and
`C_GetSlotList(CK_TRUE)` omits it; `tokenPresent` is a boolean, not a flags
mask. `C_GetSlotInfo` succeeds with the constant removable bit and no
present bit. Token-required queries and `C_OpenSession` return
`CKR_TOKEN_NOT_PRESENT`; unknown slots return `CKR_SLOT_ID_INVALID`.
Info refusals leave whole structs untouched; refused opens leave the session
output untouched and retain no callback. List queries report the count;
short fetches update the required count and leave the array untouched.
SlotInfo checks catalog validity before null output, TokenInfo checks
catalog/presence before null output, and OpenSession keeps its output/serial/
flag guards before catalog/presence. CloseAll on a known empty slot succeeds.

Removed sessions are not resurrected. Qualification limitation:
`haskokiStdFind` (the FindObjects page routine) still checks find state
before session validity; that removed-session precedence case is **deferred**
in the [T-N08 review](../dist-release-evidence/notifications/task-n08/review.md).
The repaired FindObjectsFinal case and passing fresh-session find calls do
not qualify it. No claim that every removed-session entry has been verified
is made here.

Outside a callback, Wait first checks public liveness, then null `pSlot`,
non-null `pReserved`, and unknown native-width flag bits beyond
`CKF_DONT_BLOCK`, then revalidates the captured interval. Sequential
before-init/after-finalize calls return `CKR_CRYPTOKI_NOT_INITIALIZED`
even for malformed arguments. Live malformed calls return
`CKR_ARGUMENTS_BAD` without consuming a flag. A malformed entrant that
already passed liveness can still return that error during a concurrent
Finalize. Neither pointer argument is a size-query convention.

Live empty polling returns exactly `CKR_NO_EVENT`; blocking uses STM retry
without holding the C state lock or model gate and does not return NO_EVENT
just because it starts empty. Absence is not a wait error. Only `CKR_OK`
writes one slot ID; **every non-OK result leaves `*pSlot` unchanged**.
Prohibited callback reentry returns `CKR_FUNCTION_FAILED`. Unexpected Haskell
exceptions meet the existing `CKR_GENERAL_ERROR` fence; represented explicit
allocation failure may return `CKR_HOST_MEMORY`, without promising recovery
from all RTS exhaustion or invalid native pointers. The claim-to-output
handoff is masked against asynchronous Haskell exceptions; blocking retry
remains interruptible. Polling is not a hard real-time latency promise.

Finalize closes the service and unbinds the owner after obtaining the state
lock, before Standard teardown. Close discards pending flags and wakes all
undecided waiters with NOT_INITIALIZED and unchanged outputs. In the
**event-first** race, a committed OK decision still owns its output even if
the thread returns after Finalize. In the **close-first** race there is no
queued-tail success. A Finalize state-lock failure restores the live interval
for retry. Reinitialize creates a fresh hub with clear flags; old waiters
stay on their closed hub/cell and never migrate to it.

The lifetime strategy retains one empty `InstanceCell`/`StablePtr` per
initialization interval; this small per-interval cost has not been removed.
An atomic C root alone is not a lifetime lease. Finalize makes blocked waits
runnable without waiting for application threads to be scheduled and return.
The [T-N05 evidence](../dist-release-evidence/notifications/task-n05/review.md)
uses deterministic admission/claim/close seams; native pre-call acknowledgments
and race stress alone do not establish STM parking or the winning order.

## Session notification callbacks and reentry

A successful `C_OpenSession` retains one typed `CK_NOTIFY`/`pApplication`
pair on the actual Standard session before publishing its handle. Either
pointer may independently be null; null Notify means no call. Standard owns
the association, not the application's allocation or executable code. Close,
close-all, removal and Finalize retire the association without calling it;
no callback runs after the relevant retirement returns.

The sole producer is an admitted fresh synchronous one-shot `C_Digest` on
an ordinary session, with a known fixed-width recipe and adequate capacity.
It calls once, immediately before the fresh effect, on the caller's bound
thread with the actual session, `CKN_SURRENDER` and original application
pointer. Surrender is optional in PKCS#11 and separate from slot changes;
it is not an insertion/removal callback or an interrupt inside OpenSSL.

| Callback result | Digest behavior |
|---|---|
| `CKR_OK` | Execute the admitted effect once and publish its normal output. |
| `CKR_CANCEL` | Terminate; return `CKR_FUNCTION_CANCELED`; no effect, output bytes or length write. |
| Any other code / caught Haskell test-adapter exception | Terminate; return `CKR_FUNCTION_FAILED`; same unchanged output and length. |

After cancel/failure, Digest without a new DigestInit returns
`CKR_OPERATION_NOT_INITIALIZED`. `DigestInit`, `DigestUpdate`, `DigestFinal`,
length queries, short buffers, staged-output recalls and decode/planner
refusals are silent. Explicit async-session submission (including fallback),
Complete/GetID/Join/cancel, non-Digest crypto, RNG, login, objects, lifecycle,
control and slot calls are also silent. There are no background-thread,
OTP or vendor notifications. `consumer_errors` retains its zero-callback
assertion for its open/info/close sequence, which does not execute Digest.

Callbacks retain the C state lock as their lifetime lease and run outside
STM, the model gate, callback-registry/store locks and async job leases.
The `safe` foreign invoker establishes/restores a thread-local guard before
any prohibited entry can inspect buffers, mutate state or acquire a lock.
Only `C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface`, and static
`C_GetInfo` may reenter with their ordinary validation. All other native
table calls and `HASKOKI_Control`, including SessionCancel, both wait modes,
slot queries, nested Digest and Finalize, return `CKR_FUNCTION_FAILED`.
The [T-N06 guard evidence](../dist-release-evidence/notifications/task-n06/review.md)
and [T-N07 real callback evidence](../dist-release-evidence/notifications/task-n07/review.md)
cover rejection under internal and negotiated nonrecursive mutexes.

Callbacks must return normally and must not join a thread whose progress
needs a serving call into this provider: it is waiting behind the callback's
state lock. Keep function/application storage valid while registered.
No recovery from an invalid callback pointer, C++ exception, `longjmp` or
signal crossing the ABI is promised. Calls on different sessions serialize;
there is no concurrent or nested callback promise. SERIAL remains required;
OS-locking permission is not obsolete parallel-session support.

At the pinned proxy, callback registration is discarded and rich notifications
are DIRECT-ONLY. The blocking/finalize reproduction and existing
[proxy issue 25](https://github.com/mingulov/pkcs11-proxy-ng/issues/25)
are distinct from that optional callback capability limitation. Polling parity
retains the common tables; no proxy callback promise is made. See the
[reviewed dispositions](pkcs11-oracle-triage.md#notifications-t-n10-documentation-checkpoint).
The cited executions belong to their recorded revisions. Clean final-revision
gates, installation and lanes remain pending; no acceptance is claimed.

## Quarantine protocol (memory + SQLite stores)

Both durable stores run the same commit protocol
(`src/Haskoki/Runtime/Storage/Memory.hs:160-301`,
`src/Haskoki/Runtime/Storage/SQLite.hs:391-555`; SQLite wraps the
durable section in one `BEGIN IMMEDIATE` transaction, memory swaps
under `mask_`): quarantine refusal, pre-commit validation (limits,
expected revisions), pre-commit fault rollback, then the masked
durable section with ambiguous-commit verification and post-commit
quarantine. One commit runs at a time per handle (memory: commit
`MVar`; SQLite: connection guard).

Quarantine has three entry points, all per-token with a reason
string:

1. Refusal at the gate — a commit touching a quarantined token is
   refused before validation with `NotCommitted (StoreQuarantined
   tid why)` (`firstQuarantined`; Memory `:231-234`, SQLite
   `:466-468`).
2. Ambiguous-commit verification — after the durable write the
   observed outcome is discarded and a reload decides: delta
   present verifies committed (every table, incl. jobs), delta
   absent verifies rolled back, and a failed reload quarantines
   the affected tokens and reports `CommitUnknown` (nothing
   reissues; Memory `:269-293`, SQLite `:519-545`).
3. Post-commit tail — a failure after a confirmed commit
   quarantines the affected tokens while durable truth stays
   `Committed` (Memory `:296-303`, SQLite `:546-557`).

Recovery is authoritative reload (`storeReload`): a clean load
clears the quarantine list, a failed load keeps it and reports
the error, and reloads never consult the fault script (Memory
`:371-379`, SQLite `:674-682`).

Operators observe quarantine per token: `storeQuarantined`
returns the live `[(TokenId, reason)]` list (`Storage.hs:583`;
Memory `:129`, SQLite `:368`), and every quarantine entry counts
one event per token into the `ssQuarantines` stat
(`quarantineTokens`; `Storage.hs:373-378`, Memory `:363-367`,
SQLite `:666-670`). Quarantine and stats are live-handle
properties — fresh handles start clean (Memory header `:14-15`).

## Public 3.2 async routing

The standard table exposes `C_AsyncComplete`, `C_AsyncGetID`, and
`C_AsyncJoin` on interface 3.2. A fresh full-buffer one-shot `C_Digest`
after `C_DigestInit` on an explicit `CKF_ASYNC_SESSION` is the public
producer. Ordinary sessions, queries, short buffers, and staged recalls
retain the synchronous dialogue. Sign, message operations, multipart
Digest, and key generation gain no async submission path.

Keep the output allocation passed to the pending Digest or successful
Join live and writable while that binding exists: until terminal
completion retires it, successful GetID revokes it, or cancellation,
session close, close-all for its slot, or finalization retires it.
Refused calls that preserve the binding do not release the allocation.
Submission copies the input and retains neither its pointer nor the
original output-length pointer. Complete uses the bound allocation;
incoming `CK_ASYNC_DATA` version, `pValue`, `ulValue`, and handle fields
are ignored. A present result with incoming null `pValue` is allowed
and is not a query. A pending Complete leaves the entire result and
bound bytes untouched; successful delivery reports public version `0`
and the bound pointer and length. A repeat Complete sees no operation.

GetID takes an exact function name and a scalar id output; successful
detach revokes the old output address. Join identifies the persistent
id and target session/function, accepts byte capacity **by value**, and
returns `CKR_OK` only after installing the new output binding. There is
no need output and no successful length-query form. Null/zero and
present/zero buffers for an otherwise joinable byte record return
`CKR_ARGUMENTS_BAD`; a positive short capacity returns
`CKR_BUFFER_TOO_SMALL`, preserves the record for retry, and leaves the
buffer untouched. A pending record can require its original effective
capacity (for example 64 bytes), while a ready SHA-256 record needs 32.
Before joining a pending Digest, the target needs a matching
`C_DigestInit` so the existing planner can replan the work. A selector
of `C_Sign` does not substitute for `C_Digest`.

One async table of capacity `8` belongs to each standard instance;
borrowed session views share its environment, backend, and table.
The adapter uses a fixed two-poll submission policy, with one existing
poll per valid Complete and completion when ready. Scenario-runner
`async.enabled` and `async.pending_polls` do not configure this native
policy. There are no new threads, timers, or configuration semantics.

Standard memory mode keeps `siStore = Nothing`: attached execution
works, but GetID for a resolved live job and Join on a view without a
store retain `CKR_GENERAL_ERROR`. SQLite uses the existing store and
one detached context for the home token. Non-home sessions have no
detached context and retain the same no-store behavior; they must not
detach under the home token's identity. The private proof API's owned
memory store and its close/reopen proof are separate from standard
memory sessions. Private exports continue to own their context/job
tokens, publish version `1`, return `CKR_PENDING` on successful Join,
and support their existing query/short-buffer and optional-need dialogue.

At proxy pin `a48b60ba54b0163f4999c1e4fc0514bf7dc01681`,
`async_routed` is explicitly `DIRECT-ONLY` in the parity driver under
[proxy issue 24](https://github.com/mingulov/pkcs11-proxy-ng/issues/24).
The pinned transport returns fixed GetID/Join refusals and cannot
preserve the required output ownership/capacity. Direct async success
and this exclusion are separate evidence; no async proxy parity is
claimed. The issue is distinct from message-transport issue 23.

The existing `completeJoined` writes the payload before marking durable
delivery. A failed mark recorded by `jcMarkError` cannot undo delivered
bytes; the completion verdict and terminal in-memory attachment remain.
There is no crash-safe exactly-once guarantee across a failed durable
mark. Fault-injection coverage in `tests/engine/DetachedEngineSpec.hs`
is separate from the successful-store SQLite restart proof in
`tests/c/async_routed.c`. Runtime policy and D1-D12 are unchanged.
See the [reviewed async qualification](pkcs11-oracle-triage.md#async-routing-verification-2026-09-30)
for measured source and artifact pins; final-revision verification is pending.

## Async expiry/GC

Job tombstones are UNBOUNDED until reaped: no count/age cap, the
live cap counts live jobs only (tombstones never block submits),
and delivered tombstones retain their completion payload until
reaped. Reaping is owner-only via the manual terminal-only
`reapJob` (synchronous, under the job lease; `reapEligibility`
drops terminal tombstones and leaves live states with `ReapLive`,
unknown ids report `ReapUnknown`); there is no background reaper
(discipline: no background threads). The honest wiring gap: no
production caller wires `reapJob` today, so production
tombstones accumulate until process end — wiring reap to a
destroy/close path needs an FFI surface decision (follow-up, out
of scope). Ruling + code:
`src/Haskoki/Runtime/Async.hs:1112-1158`.
