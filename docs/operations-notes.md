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
