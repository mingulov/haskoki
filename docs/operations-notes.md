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

## Overflow policy

Slot-event queue overflow is `DropOldest` by default (a waitable slot
event queue must surface the *latest* token state; a consumer that
fell behind re-syncs via the reentrant snapshot), `DropNewest`
selectable per queue. Both increment the dropped counter. Named and
tested in `EventsSpec`.

## Session notification callbacks

`C_OpenSession` accepts a non-NULL `Notify` (the v3.2 §5.6.1
return list carries no callback-refusal code, so refusing
would invent one). The callback is retained nowhere and
never invoked: the module generates no notification
events (no surrender/device callbacks on any path). Pinned
by the `consumer_errors` per-table Notify leg (open OK +
usable session + zero invocations; direct-only — a
function pointer cannot cross the proxy).

## The one reentrant query

`reentrantSlotSnapshot` (token presence per slot) is the single query
callable from inside a session notification callback without holding
the model gate. Every other in-callback gated call is rejected with
`ReentryRejected` (tested; no deadlock by design — in-callback
gated calls are rejected, so callbacks never block on the gate).

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
