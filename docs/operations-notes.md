# Runtime behavior and limits

For setup and ordinary client commands, use [Try Haskoki](try-it.md) or the
[native reference](demo-walkthrough.md). This page explains notification,
async, storage, and lifetime behavior needed by client authors.

## Configuration syntax

The configuration parser supports top-level scalars, sections, strings,
integers, booleans, string arrays, and comments. It implements the subset
used by the [example configurations](../tests/ops/fixtures), rather than a
full TOML implementation. Unknown keys/sections reject. The control and
scenario interfaces likewise use a small JSON reader. Accepted settings
are listed in the [configuration reference](config-honesty.md).

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
The pending-slot policy is exercised by
[NotificationsSpec](../tests/model/NotificationsSpec.hs).

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

Memory mode has no persistent store; SQLite uses its configured store.
Presence is not persisted: SQLite restart loads the provisioned tokens as
present with flags clear, while memory retains its existing transient
behavior. There is no hardware watcher or event thread. Store errors, login, objects,
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
distinct fault cases in
[NotificationsEngineSpec](../tests/engine/NotificationsEngineSpec.hs).

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

Removed sessions are not resurrected. A FindObjects page on a removed
session reports `CKR_SESSION_HANDLE_INVALID` before any find-state check:
`haskokiStdFind` resolves the session first (the FindObjectsFinal
precedent), then the cursor: a fresh session inherits no cursor and
still reports `CKR_OPERATION_NOT_INITIALIZED`, while the closed
session's own cursor retires with it. Refusals leave the page outputs
untouched. See [Standard.hs](../ffi/Haskoki/FFI/Standard.hs) and the
[reopen consumer](../tests/c/consumer_login_reopen.c).

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
The [notification tests](../tests/model/NotificationsSpec.hs)
use deterministic admission/claim/close seams; native pre-call acknowledgments
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
The [engine notification tests](../tests/engine/NotificationsEngineSpec.hs)
and [native callback consumer](../tests/c/notifications_routed.c)
exercise rejection under internal and negotiated nonrecursive mutexes.

Callbacks must return normally and must not join a thread whose progress
needs a serving call into this provider: it is waiting behind the callback's
state lock. Keep function/application storage valid while registered.
No recovery from an invalid callback pointer, C++ exception, `longjmp` or
signal crossing the ABI is promised. Calls on different sessions serialize;
there is no concurrent or nested callback promise. SERIAL remains required;
OS-locking permission is not obsolete parallel-session support.

Rich notification transport remains excluded on the pinned v0.2.2 proxy;
blocking waits return `CKR_FUNCTION_NOT_SUPPORTED`. Ordinary forwarded
polling and direct rich-notification tests have separate scopes in the
[parity driver](../scripts/test-proxy-parity.sh).

## Quarantine protocol (memory + SQLite stores)

Memory and SQLite stores serialize commits, validate limits and expected
revisions, then perform the masked durable section. SQLite uses one
`BEGIN IMMEDIATE` transaction. The implementations are in
[Memory.hs](../src/Haskoki/Runtime/Storage/Memory.hs) and
[SQLite.hs](../src/Haskoki/Runtime/Storage/SQLite.hs).

A token in quarantine refuses another commit with `StoreQuarantined`.
After an ambiguous write, a reload determines whether the projected delta
landed; the operation is not reissued. A failed reload quarantines the
affected tokens and reports `CommitUnknown`. A failure after a confirmed
commit can also quarantine the token while retaining the committed result.

An authoritative `storeReload` clears quarantine only after a clean load.
Quarantine reasons and statistics belong to the live store handle; fresh
handles start clean.

A failed SQLite transaction is classified from the native transaction
state, never by reissuing it. A rollback SQLite performed itself, or a
successful `ROLLBACK` after a failure that left the transaction active
(for example `COMMIT` returning `SQLITE_BUSY`), is `NotCommitted`. A
`COMMIT` error after the transaction ended, or a `ROLLBACK` error, is
`CommitUnknown` and quarantines the affected tokens. If the `ROLLBACK`
error leaves the write transaction open, the whole connection is
quarantined: every load, commit, reset and job-id reservation refuses
until a `storeReload` retries the `ROLLBACK` and SQLite reports the
transaction ended, or until the store closes (`C_Finalize`), which rolls
the open transaction back. No `publishStd` path (object creation, derive,
provisioning, login-counter writes) reloads after an unresolved commit,
so for them the connection stays refused until `C_Finalize` and a fresh
`C_Initialize`. Only a detached-job commit reconciles with a reload that
retries the `ROLLBACK`, so only there does a connection quarantine lift
immediately. [CommitSpec](../tests/storage/CommitSpec.hs) exercises
publication and fault handling.

## Token identity contract

A token's durable identity is its `TokenId`; the serving slot is a
separate assignment. Configuration seeds a new token; an existing
durable token is authoritative over its identity, label, slot,
objects, jobs, and auth counters. Labels alone never identify a
token: a catalog entry that reuses a label under a different
identity (or the reverse) reopens refused, never silently
reassigned (see `reconcileIdentities` in
`src/Haskoki/Runtime/Storage.hs` and the refusal cases in
`tests/storage/StoreSpec.hs`).

Slot 0 is the home token `TokenId 1`, unconditionally: the
configuration parser, the reconciler, and the move planner each
refuse anything else there (see `parseTokenIds`,
`RefuseHomeAnchor`, and `MoveHomeAnchored`).

The public serial number is the durable identity. `C_GetTokenInfo`
renders `serialNumber` as the token's `TokenId` in 16 lowercase hex
digits, zero-padded (`tokenSerial` in `Haskoki.Runtime.Catalog`, the same
form the store writes for `token_id`). It does not depend on the slot,
the label or the store file: a token moved to another slot keeps its
serial, the same label under another id reports another serial, and
`C_InitToken` keeps it, because a reset keeps the `TokenId`. Deleting the
store and reseeding it from the same catalog gives the same serials.

Serials are unique within one store only, not globally. Every store
seeded from a catalog gives its home token `0000000000000001`, so two
stores built from the default catalog report identical token URIs
(`token=haskoki-demo;serial=0000000000000001`). A client that loads two
haskoki modules or configurations and selects by `serial=` alone matches
both: add the module path or another attribute to tell them apart.

v0.4 rendered the slot index plus one in decimal (`%016u`). The two forms
agree for a positional catalog of up to 9 tokens, where slot `n` holds
`TokenId (n+1)`: `0000000000000001` to `0000000000000009`. They differ for
a 10th or later token (`000000000000000a`, not `0000000000000010`), for a
pinned non-positional `token_ids` entry, and after a slot move. Update any
saved `pkcs11:` URI that selects by `serial=` for those tokens.

Stable identities come from the optional `[tokens] token_ids`
parallel array (decimal ids in strings, positional with
`labels`): pinned, unique, and home-anchored, or the whole
config refuses at load. Without the key, the catalog reads
positionally (slot `n` owns `TokenId (n+1)`), which is how every
older file keeps parsing. Dropping `token_ids` is a downgrade
to that positional reading: it reopens only while the
positional layout still matches the durable one.

A SQLite open reconciles the catalog against the durable
identities before anything publishes. Matches proceed; unknown
identities seed with generation zero, fresh auth and a credential
row; every drift refuses the whole open, and a refused open writes
nothing (see Upgrade, backup and recovery).

| Drift | Refusal | Operator action |
|---|---|---|
| stored token missing from the catalog | `RefuseStoredUnconfigured` | restore the entry with its pinned id; a token cannot be removed by editing the catalog |
| durable label differs | `RefuseLabelChanged` | restore the durable label (no relabel command exists) |
| durable slot differs (reorder, shifting insert) | `RefuseSlotChanged` | restore the slot, or move explicitly first |
| duplicate desired identity | `RefuseDuplicateDesired` | give each entry its own id |

Additional slots move only through `planSlotMoves`, a Haskell library
operation (no installed command): one atomic delta, validated against the projected
layout (unknown tokens, occupied targets, clashing targets,
duplicated movers, negative slots, and home-anchor violations
refuse; see `renderSlotMoveRefusal`). Swaps and rotation chains
commit
atomically in one plan; a lone move onto an occupied slot
reroutes through a free slot first. Objects, jobs, labels,
generations, and auth counters ride along untouched. An
interrupted sequence reopens refused under both the old and the
target catalog until the remaining legs commit (see the
interrupted fixture in `tests/storage/CommitSpec.hs`).

Versions: configuration keeps `schema_version = 1`
(`token_ids` is optional and additive), durable documents keep
`format_version = 1` (the token document already separates
`token_id` from `slot`; the credential document carries its own
`format_version = 1`). The SQLite schema is 3: versions 1 and 2
refuse at open without writing and move to 3 only through
`haskoki-ctl store migrate` (see Upgrade, backup and recovery);
anything else refuses (`store-unsupported-version` from
`store check`, `StoreSchemaVersion` at the SQLite layer, pinned by
`caseUnknownVersionsRefuse` and `caseNewerSchemaRefusedEverywhere`
in `tests/storage/PreflightSpec.hs`). v0.3.1.0 and v0.4.0.0 binaries
refuse schema 3 (checked by `scripts/qualify-store-upgrade.sh`).

On a SQLite store, PIN values are durable from the moment a token
exists: the open that creates a token row writes its credential
row (the catalog SO PIN and user PIN at that moment) in the same
transaction. From then on the durable row is the credential
authority for that token. Editing a catalog PIN later changes
nothing for a token that already exists; the edited value is
refused and the stored one keeps serving. `C_InitToken`,
`C_InitPIN` and `C_SetPIN` replace the row in-band, and that is
the way to move a PIN. In memory mode the catalog PINs seed each
interval, as before.

A store written before this (v0.4 and earlier) is refused at open
as migration-required (the schema; see Upgrade, backup and
recovery), and a schema-3 store with a rowless token refuses as
`StdStoreMigrationRequired`. The open names nothing to a C caller;
`haskoki-ctl store check --path FILE --config FILE` names the tokens;
`haskoki-ctl store migrate --path FILE --config FILE --backup-dir DIR`
records the configured PINs as those tokens' rows after a verified
backup. Identity refusals report first: `store check` reports them next
to the required actions (`casePlanDrift`,
`caseMigrateRefusesIdentityDrift` in
`tests/storage/PreflightSpec.hs`). There is no token-editor surface
here, and no path reassigns one token's objects to another token's
credential silently (every reassignment-shaped change above refuses
loudly instead; `C_InitToken` destroys only its own token's objects,
jobs, and credential).

Reinitializing a token is an authorized operation: every seated
token carries an SO PIN (the durable row on a SQLite store;
in memory mode the catalog value until it changes in-band), so `C_InitToken` always
takes the reinitialization path and checks the caller PIN
against the token's existing SO PIN with the position-constant
`pinsMatch` fold before planning anything. A mismatch answers
`CKR_PIN_INCORRECT` and persists nothing — objects, jobs,
credentials, attempt counters, and locks stay as they were
(`caseReinitWrongPinRefused` in `tests/model/MultiTokenSpec.hs`
pins the preserved serving state, and
`caseInitTokenDeniedPreserves` in
`tests/model/TransitionSpec.hs` pins the empty plan behind
it). A match resets the token exactly as before: the SO PIN
becomes the caller bytes (which equal the existing SO PIN on
this path), the label becomes the caller label, every object
and pending detached job on the token is destroyed, the
generation bumps, the auth half goes fresh including cleared
locks (presenting the SO PIN authorizes the reset, which is
the locked-SO recovery path: no other call clears an SO
lock), and the user PIN becomes uninitialized. A refused
reinit consumes no SO attempt — it is a sessionless
authorization check, not a login — so a wrong PIN neither
locks the SO role nor disturbs the counter the next `C_Login`
observes. `CKF_TOKEN_INITIALIZED` stays set on every token,
matching the always-reinit behavior. To rotate the SO PIN
itself, log in as SO and use `C_SetPIN`.

Two boundaries stay outside this contract. Binary rollback across
schema 3 refuses loudly (old binaries do not open a migrated store;
`scripts/qualify-store-upgrade.sh` checks the refusal and the unchanged
file); rolling back means restoring the pre-migration backup. A moved
store under schema 2 or older is history: v0.5 never serves it until
migrated. And the C
initialization path reports store-open failures generically,
with no diagnostic sink there, as with every other
store-open failure; Haskell callers receive the typed
refusal above through `openStdStore` (see the
standard-open cases in `tests/storage/StoreSpec.hs`).

## Upgrade, backup and recovery

v0.5 stores use SQLite schema 3. A store written by v0.3 (schema 1) or
v0.4 (schema 2) must be migrated once with `haskoki-ctl store migrate`.
Until then every haskoki v0.5 open refuses it and, absent a hot journal
or a `-wal`/`-shm` sibling, writes nothing: `C_Initialize` returns
`CKR_GENERAL_ERROR` (no reason reaches a C caller), and `haskoki-ctl
store check` says why. Refused opens leave the database bytes, schema
marker, tables and credential rows unchanged; the only file an open
creates and removes is the `<store>.lock` sidecar (see
`caseOldStoreRefuses` in `tests/storage/PreflightSpec.hs`). The
exceptions: a hot journal is rolled back by the serving open before it
refuses (Interrupted migration, first route, depends on exactly that),
and a non-empty `-wal` or `-shm` is refused before any SQLite
connection opens, so nothing is checkpointed
(`caseServingRefusesForeignWal` in `tests/storage/PreflightSpec.hs`).

### Rehearse on a copy, then upgrade

Stop every process that has the store open, then:

```sh
STORE=/srv/haskoki/token.sqlite          # your store
CONFIG=/srv/haskoki/backend.toml         # the config that serves it
mkdir -p /tmp/rehearsal
cp "$STORE" /tmp/rehearsal/token.sqlite
sed "s#^path = .*#path = \"/tmp/rehearsal/token.sqlite\"#" "$CONFIG" > /tmp/rehearsal/backend.toml
haskoki-ctl store check --path /tmp/rehearsal/token.sqlite --config /tmp/rehearsal/backend.toml
mkdir /tmp/rehearsal/backups
haskoki-ctl store migrate --path /tmp/rehearsal/token.sqlite \
  --config /tmp/rehearsal/backend.toml --backup-dir /tmp/rehearsal/backups
haskoki-ctl store check --path /tmp/rehearsal/token.sqlite --config /tmp/rehearsal/backend.toml
```

The first check prints the plan and exits 1 with
`store-migration-required`. The migrate prints `backup:` and
`backup-sha256:` first, then the receipt and `migrate-done`. The
second check prints `verdict: ok` and exits 0. Then
create the real backup directory, run the same two commands on `$STORE`
with `$CONFIG` and `--backup-dir /srv/haskoki-backups`, and start the
service.

`--config` must name the same store as `--path`: a config written for
another file is refused as `config-mismatch`. That is why the rehearsal
writes its own config for the copy (see `caseConfigSelects` in
`tests/storage/PreflightSpec.hs` and `caseCheckConfigMismatch` in
`tests/storage/StoreCtlSpec.hs`).

### What check and migrate report

| Exit | Meaning |
|---|---|
| 0 | check: the store opens as-is with this config. migrate: migrated, or `migrate-not-needed` (nothing written). |
| 1 | a diagnosed refusal; one stderr line `<tag>: <detail>` |
| 2 | usage error |
| 130 | interrupted by SIGINT; one stderr line (`migrate-interrupted` or `check-interrupted`), store state unknown |

Tags: `store-migration-required`, `store-identity-refused`, `store-live`,
`store-lock-unwritable`,
`store-journal-present`, `store-journal-cold`, `store-foreign-sidecar`,
`store-unsupported-version`,
`store-corrupt`, `store-full`, `store-missing`, `store-unreadable`,
`check-interrupted`,
`config-invalid`, `config-mismatch`, `migrate-unsafe-backup-dir`,
`migrate-store-changed`, `migrate-backup-exists`, `migrate-backup-failed`,
`migrate-failed`, `migrate-unexpected`, `migrate-interrupted`,
`migrate-verify-failed`, `migrate-receipt-failed`.
Output and receipts name token ids (as 16 hex digits, the same text as the
token serial), labels, versions, paths and reasons. They never print a PIN
or key byte (`caseCheckNoPins`, `caseMigrateCliNoPins` in
`tests/storage/StoreCtlSpec.hs`).

`store check` never writes: it opens the database read-only, never
creates or removes `<store>.lock`, and refuses a store a live process
holds (`caseCheckLive`, `caseSnapshotReadOnlyDir`).

`store inspect` is the other read-only reader: it reports lock state plus
table counts over a `SELECT`-only connection and never creates the sidecar
(`inspectStore` in `src/Haskoki/Ctl.hs`, `caseInspect` in
`tests/storage/StoreCtlSpec.hs`). The two disagree on liveness by design:
`store inspect` judges the sidecar pid through `/proc` only
(`readLockState`), while `store check` also probes the database kernel
lock (`probeOwner` in `src/Haskoki/Runtime/Storage/SQLite.hs`), so a store
whose kernel lock is held but whose sidecar is absent reports `offline`
under `inspect` and `store-live` under `check` (see `casePlanLiveOwner`
in `tests/storage/PreflightSpec.hs`).

When `store migrate` cannot create the `<store>.lock` sidecar at all
(a read-only directory or mount, no space), it reports
`store-lock-unwritable` and names the lock path with the system
error — never `store-live`, since no owner holds the store
(`caseCheckNeverOwns` in `tests/storage/PreflightSpec.hs`).

`store reset --confirm-demo-reset` removes an offline store and its
`<store>.lock` sidecar, refusing a live store; the next open through
the reset path recreates a fresh store. Through a store symlink it
removes the link's target instead and leaves the link itself in
place, so the link dangles and the next start refuses rather than
recreating (`resetStore` in `src/Haskoki/Ctl.hs`,
`caseResetSymlinkOffline` in `tests/storage/StoreCtlSpec.hs`). The
success report keeps its `reset: <target> removed (offline)` stdout
line and says so on stderr as `reset-dangling-link: <link> now
dangles; the next start refuses until the target is recreated or the
link removed` (`caseResetSymlinkWarnsDangling`); a plain reset
reports nothing on stderr (`caseResetOfflineQuietStderr`). To start
over after a reset through a link, either remove the link and serve
the real path, or recreate the target by opening the real path
once; until then the serving open fails closed on the dangling
link, creating nothing there (`caseOpenDanglingLink`).

### What migrate does

1. Refuses, writing nothing, when: the config does not select this
   store; the backup directory is missing, not a real directory (a
   symlink is refused), not writable, or the store's own directory; a
   process holds the store; a non-empty `-wal` or `-shm` sibling from
   foreign tooling exists, reported as `store-foreign-sidecar`
   (checked before the journal classification, so a cold journal
   never bypasses it; see `caseMigrateCliColdWal` in
   `tests/storage/StoreCtlSpec.hs`); an interrupted write left
   `<store>-journal` (hot, unknown, or not a regular file, which is
   refused without opening; see `caseCheckNonRegularJournal` in
   `tests/storage/StoreCtlSpec.hs` and `caseCheckWalShm` there); the
   catalog does not match the stored tokens (labels, slots, ids;
   restore the catalog the store was written with); the store is
   already current (returns `migrate-not-needed`, leaving any cold
   journal untouched; see `caseMigrateCliSchema3Cold`); or the store
   changed after the check. A cold journal is cleared only after this
   plan says the migration proceeds.
2. Takes the store's ownership lock for the rest of the run.
3. Writes a new backup `<store>.pre-migrate.schema<N>.<epoch>.bak`
   (mode 0600; an existing name is never overwritten, the next free
   `-1`..`-99` name is used), verifies it byte for byte and by reading
   it as a store, and records its SHA-256. A backup that fails
   verification is removed again, never left for a later restore to
   trust (`caseMigrateBadBackupRemoved` in
   `tests/storage/StoreCtlSpec.hs`). The moment verification passes,
   before the transaction begins, migrate prints `backup: <path>` and
   `backup-sha256: <hex>` to stdout and flushes, so a run killed
   mid-transaction still leaves its backup's digest in the operator's
   log (`caseBackupVerifiedBeforeBegin` in
   `tests/storage/PreflightSpec.hs`); the receipt repeats both lines
   on success.
4. In one SQLite transaction: creates the `credentials` table (schema
   1 only), writes a credential row for every stored token that has
   none, taking the SO and user PIN of that token's catalog entry in
   `--config`, and sets `schema_version = 3`. A token that already has
   a row keeps it unchanged: PINs changed in-band (`C_InitPIN`,
   `C_SetPIN`, `C_InitToken`) survive (`caseMigrateV04`). Tokens that
   are configured but not stored are not created; the next open seeds
   them with their catalog PINs. A schema-3 store with rowless tokens
   is also a migrate input: the plan freezes rows with no version move
   (`casePlanV3Rowless`), and the transaction leaves the marker at 3
   (`caseOwnedFreezesAtV3`, `caseMigrateSchema3Rowless` in
   `tests/storage/PreflightSpec.hs`).
5. Reads the store back, then writes `<backup>.receipt` (ids, versions,
   backup path, size and SHA-256; no PINs). The receipt keys are
   `haskoki-store-migration-receipt`, `store`, `schema-from`,
   `schema-to`, `frozen-credentials`, `preserved-credentials`, `backup`,
   `backup-bytes`, `backup-sha256`, `backup-epoch-seconds`,
   `completed-epoch-seconds` (read after the commit and its read-back;
   see `caseMigrateClockReadings`) and `cold-journal-removed`
   (`yes` only when a cold journal was cleared to reach this migration,
   else `no`; see Interrupted migration below). The receipt is written
   through a unique temporary `<backup>.receipt.tmp.<pid>.<nonce>` (for
   example, `token.sqlite.pre-migrate.schema2.1700000000.bak.receipt.tmp.1234.0`)
   plus `link` so a taken name is never overwritten; on filesystems
   without hard links it falls back to a direct exclusive write of the
   final name (`writeReceipt` and `isLinkUnsupported` in
   `src/Haskoki/Runtime/Storage/Preflight.hs`,
   `caseMigrateReceiptLinkFallback` in
   `tests/storage/PreflightSpec.hs`). A stale temporary from a crashed
   run is ignored, never fatal (`caseMigrateStaleReceiptTmpIgnored`);
   temporaries from provably-dead owners are removed when the next
   migration writes its receipt (`caseMigrateStaleReceiptTmpCleaned`).
   That liveness check reads the local PID namespace only, so two
   containers sharing one backup directory can delete each other's
   live temporary (the loser reports `migrate-receipt-failed` for a
   migration that actually committed): never share a backup directory
   between PID namespaces; give each writer its own.

If the transaction fails (for example, a full disk), it rolls back; the
store is unchanged, the backup stays, and no receipt is written
(`caseMigrateTxnFailureKeepsStore`). Free the space and run migrate
again; it writes a new backup. The backup directory needs room for one
copy of the store.

### Interrupted migration

If migrate is killed mid-transaction, `<store>-journal` remains. Do not
delete it. The journal is classified only when it is a regular file; a
symlink, FIFO or device is refused as unknown without opening it, so
classification never hangs (`caseSnapshotRefusesNonRegularJournal` in
`tests/storage/PreflightSpec.hs`, `caseCheckNonRegularJournal` in
`tests/storage/StoreCtlSpec.hs`). A regular journal is classified by
its first 8 bytes: hot carries the SQLite journal magic, cold is all
zero, anything else (including a short or unreadable file) is unknown
and fails closed (`classifyJournal` in
`src/Haskoki/Runtime/Storage/SQLite.hs`). A non-empty `-wal` or `-shm`
sibling is checked before the cold classification, so a cold journal
plus a foreign `-wal` reports `store-foreign-sidecar`, never cold, and
every byte stays untouched (`caseMigrateCliColdWal` in
`tests/storage/StoreCtlSpec.hs`).

A hot journal (or an unknown header) stays refused: `store check` and
`store migrate` report `store-journal-present` and touch neither file.
Either start the serving haskoki once: its open rolls the interrupted
transaction back (the store returns to its pre-migration bytes) and
refuses as migration-required; then run check and migrate again. Or
restore the backup the interrupted run wrote, moving the store and its
journal aside together first (`caseKilledMigrationRecovers`,
`caseKilledRestoreMovesJournal`) — but only after verifying it: the
run printed `backup:` and `backup-sha256:` before its transaction
began, and `sha256sum` over that backup must equal the recorded
digest. A kill mid-write leaves a partial `.bak` that fails this
check; never restore it, take the first route instead.

A non-empty `-wal` or `-shm` sibling is a different refusal:
`store check`, `store migrate` and the serving open all report it
(`store-foreign-sidecar` on the CLI; the serving open fails closed
the same way any store-open refusal does) and touch nothing, because
opening would checkpoint foreign frames into the store. Never start
the service to clear it. Move `<store>-wal` and `<store>-shm` aside
(keep both files) and run `store check` again
(`caseForeignSidecarRemedy` in `tests/storage/PreflightSpec.hs`,
`caseServingRefusesForeignWal` there).

A cold journal on a store that still needs migration is refused
distinctly: `store check` reports `store-journal-cold` and names
`store migrate` as the remedy, touching neither file. `store migrate`
first plans through a read-only snapshot that tolerates the cold
journal; only when the plan says the migration proceeds does it
take ownership and, inside that single window, clear the journal
after the snapshot comparison and before the backup (no `-wal` or
`-shm` sibling exists even zero-byte, a SQLite `RESERVED` lock is
taken, the journal is still cold on re-read; see
`clearColdJournalOwned` in
`src/Haskoki/Runtime/Storage/SQLite.hs`). A journal that vanished
between the plan and the clear counts as already cleared. The line
is printed to stdout and flushed the moment the journal is cleared,
so a run killed after the clear still leaves its record in the
operator's log; every outcome after a clear then repeats
`cold-journal-removed: yes` in the receipt and at the end of stdout,
including failures
(`caseMigrateClearsColdJournal`, `caseKilledSmallMigrationClears`,
`caseMigrateReportsClearOnFailure` in
`tests/storage/PreflightSpec.hs`). A store that changed after the
plan refuses before the clear, with the journal still in place
(`caseMigrateStoreChangedKeepsColdJournal`). Any other outcome
leaves the journal untouched. A cold journal on a current store is
not a refusal at all:
`store check` exits 0 with `verdict: ok` and the line `journal: cold
(harmless; reused by the next write)`, touching neither file, and
`store migrate` reports `migrate-not-needed` with the journal still in
place (`caseMigrateCliSchema3Cold` in `tests/storage/StoreCtlSpec.hs`);
the journal is harmless there (SQLite already reads committed state,
the serving open succeeds, and the next write transaction reuses the
file). A cold journal while another process holds `RESERVED` stays
refused (`caseColdJournalReservedRefuses`). A migration with no cold
journal records `cold-journal-removed: no`
(`caseMigrateReceiptColdJournalNo`).

### Restore from a backup

Restore only a backup whose digest matches a recorded one: `sha256sum`
over the `.bak` must equal the `backup-sha256:` the migration printed
to stdout before its transaction began (repeated in the `.receipt`
when the run finished). A partial `.bak` from a killed run, or any
other file, fails this check and must never be restored. On a match,
stop the owner. Move the current store aside (with its `-journal`,
`-wal` and `-shm`, if present; keep them all), copy the backup to the
store path, and run `store check`. A pre-migration backup is a schema
1 or 2 store again:
old binaries open it, and v0.5 needs `store migrate` again. Restoring
brings back the credentials as they were when the backup was taken:
PINs changed since then revert, and nothing prevents rolling back to an
older credential state (`caseRestoreBringsBackOldCredentials`).

### Old binaries and downgrade

After migration, v0.3.1.0 and v0.4.0.0 refuse the store
(`schema_version = 3` is not theirs; `C_Initialize` fails and the file
is unchanged, checked by `scripts/qualify-store-upgrade.sh`). To go back,
restore the pre-migration backup; changes made since are lost. A store
with a schema newer than this build is refused by open, check and
migrate alike (`store-unsupported-version`).

### Stores created through the async open

A store created through the async open (the detached-job API) carries
its home token under the label `haskoki-async`. No parser-valid config
can name that label (slot 0 is anchored to `haskoki-demo`; see
`parseTokenIds` and `RefuseHomeAnchor`), so the ordinary open refuses
such a store and the C surface reports only `CKR_GENERAL_ERROR`: a v0.4
store refuses as migration-required (the schema), a schema-3 store with
matching rows refuses on the label (`casePlanAsyncV04` and
`casePlanAsyncSeededV3` in `tests/storage/PreflightSpec.hs`). Plan and
migrate it by adding `--async-home` to the check and migrate commands
above, which replaces the loaded config's catalog with the async home
entry (`asyncHomeConfig` and `asyncHomeEntry` in
`src/Haskoki/Runtime/Catalog.hs`; see `caseCheckAsyncHome` in
`tests/storage/StoreCtlSpec.hs` and `caseMigrateAsyncV04` in
`tests/storage/PreflightSpec.hs`). `--async-home` is a standalone switch
only; it is never taken as the value of another flag
(`caseCheckAsyncHomeValue`, `caseMigrateCliAsyncHomeValue` in
`tests/storage/StoreCtlSpec.hs`).

### Catalog drift and quarantine

An identity refusal (a stored token missing from the catalog, a changed
label, a changed slot) is fixed by restoring the catalog the store was
written with: its labels, slots and `token_ids`. There is no token
editor, relabel or slot-move command. `planSlotMoves` is a Haskell
library operation, not an installed command. A quarantined token
(`StoreQuarantined`, after a write whose outcome could not be verified)
is a runtime state, not a migration matter: an authoritative reload
clears it, and a restart reloads from the durable rows.

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

Standard memory mode has no detached store: attached execution
works, but GetID for a resolved live job and Join on a view without a
store retain `CKR_GENERAL_ERROR`. SQLite uses the existing store and
one detached context for the home token. Non-home sessions have no
detached context and retain the same no-store behavior; they must not
detach under the home token's identity. The private proof API's owned
memory store and its close/reopen proof are separate from standard
memory sessions. Private exports continue to own their context/job
tokens, publish version `1`, return `CKR_PENDING` on successful Join,
and support their existing query/short-buffer and optional-need dialogue.

At the pinned proxy v0.2.2 (`1ed7cc15`),
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
`tests/c/async_routed.c`. See the [qualification reference](pkcs11-oracle-triage.md#public-async-operations)
for the native and external-checker scopes.

### Detached attachment claims

Attachment state for persistent detached jobs lives in one claim
authority per open store handle, keyed by token and persistent id
(`Haskoki.Runtime.Attach`), not in each detach context. Claims are
exclusive across contexts over one handle: a context that loses a
race cannot retire or cancel the winner, and a cross-token join of a
live (queued or ready) row answers unknown. Below, a context has
served a table when it took a join claim through that table, even a
claim that later rolled back. Retiring a context retires only the
tables it served. Retiring a table that context never served refuses
later claims from that context; apart from opaque marks (below), it
never changes shared state.

Opaque marks are keyed by table and job and apply only to
non-terminal jobs. A mark clears on a successful detach of its job,
or when its table is retired through a context that served the table
or marked a job on it, whether the retire is scoped to that table or
covers the whole context. So once every context that marked or
served a table has retired it, the table holds no marks.
`markJobOpaque` stays exported as a documented fault-injection API.

Documented boundaries:

- Closing a store while attachments are live is not supported.
  Reopening is covered once the owner is fully retired; a reopened
  handle starts with an empty authority. There is no exactly-once
  claim across process death: an id that was live at the close can be
  joined again after the reopen, so its job can run a second time.
- A stale foreign active claim is not reclaimed: a claim held by
  another context that never retires stays held, and this context
  does not take it over.
- A context that served a table retires it for every context when it
  retires: a whole-context retire also covers tables whose claims
  through this context rolled back, and it cancels any other
  context's active binding on that shared table.
- When a table is retired only through contexts that neither served
  it nor marked a job on it, its opaque marks stay in the shared
  authority until a context that did retires it, or the store handle
  closes.

## Async expiry/GC

Terminal job records are retained under two per-table limits: 4096 records
and 64 MiB of retained bytes. Commits evict the oldest terminal records when
either bound is exceeded; live jobs have their separate capacity limit.
A newly completed job larger than the byte budget is retained for that
commit and can be evicted by the next terminal commit. Delivered payloads
remain until eviction or explicit terminal-only `reapJob`.

There is no background reaper. An evicted or reaped id becomes unknown.
See `maxRetainedTombstones`, `maxRetainedBytes`, and `reapEligibility` in
[Async.hs](../src/Haskoki/Runtime/Async.hs), with count/byte bounds in
[AsyncSpec](../tests/model/AsyncSpec.hs).

## Release limits for operators

Demo and test purpose only: no certification, FIPS, Common Criteria,
or production-security claim is made anywhere in this release (see
`SUPPORTED-HOSTS.md` for the capability table and the full limit
list). The notes below bind each operational property to its code.

Key storage. Memory mode keeps token and object records in process
memory only; SQLite mode persists the same records to the configured
path as plain JSON/blobs — token rows plus object rows with
`material_blob` key bytes (`src/Haskoki/Runtime/Storage/SQLite.hs`
schema) — with no encryption-at-rest. Session objects are never
stored, and external handles are never stored: the live model mints
handles on reload (`src/Haskoki/Runtime/Storage.hs` record notes).
The store path is explicit in config and single-writer; a pathless
SQLite open or a second concurrent open refuses loudly instead of
sharing state.

PINs and auth state. PINs start at their configured values (home `1234` /
`5678`, catalog PINs from the TOML file in plaintext) and move in-band
after that (`C_InitToken` / `C_InitPIN` / `C_SetPIN`, persisted per
token); comparison is the position-constant xor fold with length
short-circuit (`pinsMatch` in `ffi/Haskoki/FFI/Standard.hs`),
with no uniform running-time guarantee. The
persisted token row carries the login/attempt/lockout counters
(`TokenAuth` in `core/Haskoki/Session.hs`); wrong guesses count
down per-role retries to `CKR_PIN_LOCKED`. Catalog PINs are
example-grade fixtures.

Trace and store files. The provider writes the trace file (`{pid}`
expansion, append-only, best-effort;
`ffi/Haskoki/FFI/Instance.hs`) and, in SQLite mode, the store file
plus its sidecars: a `<db>.lock` ownership file carrying the owner
pid (created `O_EXCL` at open, removed on close, taken over after
a dead owner) and, under the configured rollback-journal mode
(`PRAGMA journal_mode = DELETE`), a transient `<db>-journal` file
that SQLite holds for the duration of a write transaction and
removes on commit
(`src/Haskoki/Runtime/Storage/SQLite.hs`). Trace events redact
PINs, key material and message bodies to kind + length
(`src/Haskoki/Runtime/Trace.hs`). No other temp-file calls ship in
the provider paths (the `mkstemp`/`tmpfile` family is absent from
`src/`, `ffi/`, `app/`, `cbits/`, `core/`, `tools/`). Ship
trace-off configs unless tracing is wanted.

Close and lifecycle. `C_Finalize` requires zero open sessions
(`validateFinalize` in `src/Haskoki/Runtime/Lifecycle.hs`) and ends
the provider interval without stopping the RTS
(`cbits/rts_bootstrap.c`); closing the backend releases digest
contexts and drops the key maps. Unload is pinned (`-z nodelete`
in `haskoki.cabal`), and fork children of a booted process fail
without entering Haskell. Async terminal tombstones have per-table
retention limits of 4096 records and 64 MiB; commits evict the oldest
terminal records when either limit is exceeded. Owners may also use
`reapJob` for eager removal (see Async expiry/GC above and
`maxRetainedTombstones` / `maxRetainedBytes` in
`src/Haskoki/Runtime/Async.hs`).

Memory handling. Tag comparison inside the engines uses the full
xor-fold shape (`ctEq`); no uniform running-time guarantee is made
for Haskell paths.
Native code cleanses scoped native buffers,
including HMAC scratch (sized `OPENSSL_clear_free` on returned
buffers plus cipher-scratch cleansing in `cbits/ossl4_ctx.c`); no
general memory-zeroization promise is made, and SQLite blobs
persist until deleted.

## Haskell runtime ownership contracts

Each runtime below names its owner, its close obligation, and the
lock or coordinator that serializes it. The C state lock is the
outer lease for serving entries; STM coordinates async parking
without holding that lock; the store serializes commits on its own
handle.

| Runtime | Owner | Close obligation | Serialization |
|---|---|---|---|
| Lifecycle interval (`Haskoki.Runtime.Lifecycle`) | The instance owns the interval | Finalize ends the interval only; it needs zero open sessions and never stops the RTS | State lock; the module stays pinned (`-z nodelete`) |
| Storage handle (`Haskoki.Runtime.Storage` + backends) | The open handle owns token/object rows; SQLite adds a lock file, memory an in-memory ownership token | Close releases the SQLite lock file or the memory ownership token and drops the handle; SQLite sidecars follow the write transaction | Single-writer; commits serialize; quarantine refuses until an authoritative reload clears it |
| Attached async tables (`Haskoki.Runtime.Async`) | The instance owns tables and retained bytes | Attached terminal tombstones are bounded (4096 records, 64 MiB); the just-committed job is always retained and may transiently exceed the byte bound; owners may reap attached tombstones eagerly with `reapJob`; detached terminal records (`Haskoki.Runtime.Detached`) stay stored; submit admits only checked, outer-coherent work, and fixtures use the named test-only admission | STM; no background reaper |
| Slot service (`Haskoki.Runtime.SlotEvents`) | The interval owns flags and the hub | Close discards pending flags and wakes undecided waiters with `CKR_CRYPTOKI_NOT_INITIALIZED` | One flag has one consumer; no broadcast |
| Serving backend (`Haskoki.Engine.OpenSSL4`) | The instance binds one backend for serving | Close releases digest contexts and drops the key maps | Backend operations hold the exclusive environment gate (environment-then-registry order), atomic with close; digest contexts are borrowed under the registry lock while used |
| Trace queue (`Haskoki.Runtime.Trace`) | The `Tracer` owns a bounded STM queue with drop/failure counters; the sink is caller-supplied | Drains write queued lines through the sink; failures counted, never thrown; the serving sink appends per line | Queue operations are STM; concurrent drains share the sink with no ordering across drains |
| FFI entries (`Haskoki.FFI.Standard`) | Entries borrow the instance; callers own native buffers per the entry contract | Session close, close-all, removal, and finalize retire associations without callbacks | State lock, except blocking waits which park in STM without it; callbacks hold the lock as their lease |
| Standalone proof APIs (`Haskoki.FFI.Async`, `Haskoki.FFI.Exports`) | The caller owns each standalone context and its store box (serving instead borrows `AsyncCtx` views sharing its backend/table, with no teardown authority); close every context on a box (and join their calls) before closing the box; a Store no caller can receive is recovered by the next standalone open or close in the process, and until then its lock stays held | Explicit close per context (`haskoki_hs_async_close`, `haskoki_hs_async_store_close`, `haskoki_hs_crypto_close`); the store box outlives contexts opened on it; a failed or canceled close keeps its slot — a close canceled in the borrower wait reopens the context, while one canceled past it stays owned by its slot in a closing state that admits nothing and the next close resumes it, and a box close keeps its slot until a retry closes the Store | Direct Haskell calls take no C state lock; `AsyncCtx` carries its table and leases; context close is cancellable at every blocking wait but the bounded SQLite busy waits inside FFI calls, and resumable through the slot; borrowed views are internal, serialized by the C state lock, with no concurrent direct use; raw `AsyncTable` methods take no context admission, so callers serialize use with destruction; `CryptoCtx` has no retirement lease, so callers must not use it after close |

## Stub and contract inventory (B3)

The [B3 inventory](b3-docs-inventory.md) records the C-table stub set and
the stale planner-catalog rows found at `f4a967a`, for H3/V5 owners:

| Set | Count | Detail |
|---|---|---:|
| Genuine C-table stubs (`CKR_FUNCTION_NOT_SUPPORTED` live) | 11 | 3 legacy `stub_probe` + 8 post-2.40 `x_live_check` (provisioning routed since its lifecycle lane landed) |
| Legacy parallel pair (`CKR_FUNCTION_NOT_PARALLEL` live) | 2 | `C_GetFunctionStatus`, `C_CancelFunction` |
| Catalog rows reworded for routing context | 10 | R1-R10 (B12 reword; R11 fixed reason-side) |

The 11 genuine stubs keep accurate catalog reasons. R4-R10 no longer deny
C-table routes (B12 reworded them to planner-scope-only claims), R1-R3
carry serving-context wording, and R11 names the live
`CKR_FUNCTION_NOT_PARALLEL` return. See gaps D2 and D3 in the inventory
(closed by the B12 reword).
