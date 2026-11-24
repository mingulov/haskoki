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

Rich notification transport remains excluded on the pinned v0.3.1 proxy;
blocking waits return `CKR_FUNCTION_NOT_SUPPORTED`. Ordinary forwarded
polling and direct rich-notification tests have separate scopes in the
[parity driver](../scripts/test-proxy-parity.sh).

## Quarantine protocol (memory + SQLite stores)

Memory and SQLite stores serialize commits, validate limits and expected
revisions, then perform the masked durable section. SQLite uses one
`BEGIN IMMEDIATE` transaction. Every connection sets
`PRAGMA synchronous = EXTRA` and verifies it reads back as set
(`configure`/`verifyPragmas` in
[SQLite.hs](../src/Haskoki/Runtime/Storage/SQLite.hs)), so the last
commit stays committed across a power loss closely following it, at the
cost of one directory fsync per commit; removing a cold journal at open
likewise syncs the store directory after the unlink (`syncParentDir`).
The implementations are in
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
commit atomically in one plan; a lone move onto an occupied slot
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
store under schema 2 or older is history: no v0.5+ binary serves it
until migrated. And the C
initialization path reports store-open failures generically
(CKR_GENERAL_ERROR), with the typed cause best-effort emitted as a
trace row (see the init-refusal table under What check and migrate
report); Haskell callers receive the typed
refusal above through `openStdStore` (see the
standard-open cases in `tests/storage/StoreSpec.hs`).

## Upgrade, backup and recovery

v0.5 stores use SQLite schema 3. A store written by v0.3 (schema 1) or
v0.4 (schema 2) must be migrated once with `haskoki-ctl store migrate`.
Until then every haskoki v0.5 open refuses it and, absent a hot journal
or a `-wal`/`-shm` sibling, writes nothing to a rollback-journal store
(a file tracer whose destination aliases the store, its journal/sidecars, or its lock is skipped for this row — compared by canonical path, symlink target (the destination's and each sidecar's), file identity, and parent identity + casefolded leaf, failing closed; spellings with undecodable bytes drop, as do non-ASCII spellings under a non-UTF-8 filesystem encoding (POSIX and SQLite resolve them differently); NFC-vs-NFD twins and Default_Ignorable twins (e.g. U+200D) on folding filesystems and post-check replacement are out of scope):
`C_Initialize` returns `CKR_GENERAL_ERROR` (the C caller still sees
only the code; the cause is best-effort emitted as a trace row, see
the init-refusal table below), and `haskoki-ctl store check` reports
its own verdict — note it judges identity before migration, the
reverse of serving's schema-first order, so the two can name
different blockers. Pre-seed refusals of a rollback-journal store
that perform no recovery writes leave the database bytes, schema
marker, tables and credential rows unchanged (assuming the trace
file is configured away from the store itself); the only files
a pre-seed open of a rollback-journal store manages besides the
database itself are the `<store>.lock` ownership sidecar, the
configured trace file, and — by deletion without replay — an
unrecognized
`-journal` (see `caseOldStoreRefuses` in
`tests/storage/PreflightSpec.hs`). The exceptions: a hot journal is
rolled back when the open reaches SQLite and SQLite completes
recovery, before it refuses (Interrupted migration, first route,
depends on exactly that; ownership and foreign-sidecar refusals
precede SQLite and roll back nothing); a non-empty `-wal` or `-shm`
is refused before any SQLite
connection opens, so nothing is checkpointed
(`caseServingRefusesForeignWal` in `tests/storage/PreflightSpec.hs`);
and opening a WAL-format database switches it to rollback-journal
mode, rewriting its header version bytes on success (SQLITE_FULL
there surfaces as `store-full`); and a journal recovery interrupted
by an I/O failure can leave partial replay bytes behind.

### Rehearse on a copy, then upgrade

Stop every process that has the store open, then:

```sh
STORE=/srv/haskoki/token.sqlite          # your store
CONFIG=/srv/haskoki/backend.toml         # the config that serves it
export ZSP=$(printf '\302\240|\341\232\200|\342\200\200|\342\200\201|\342\200\202|\342\200\203|\342\200\204|\342\200\205|\342\200\206|\342\200\207|\342\200\210|\342\200\211|\342\200\212|\342\200\257|\342\201\237|\343\200\200')  # Unicode space separators (the CLI folds them as padding; POSIX awk does not)
[ -n "$ZSP" ] || { echo "ZSP is unset; aborting rehearsal"; exit 1; }
REH=$(mktemp -d /tmp/rehearsal.XXXXXX) || { echo "cannot create scratch dir; aborting rehearsal"; exit 1; }
chmod 700 "$REH" || { echo "cannot secure scratch dir; aborting rehearsal"; exit 1; }
CFG_PATH=$(awk 'function parseval(v,  out,i,c,nc,rest) { sub("^" sp "*", "", v); if (substr(v,1,1) != "\"") return ""; out=""; i=2; while (i <= length(v)) { c=substr(v,i,1); if (c == "\"") { rest=substr(v,i+1); if (zsp != "") gsub("(" zsp ")", " ", rest); if (rest ~ /^[[:space:]]*(#.*)?$/) { pok=1; return out }; return "" } if (c == "\\") { if (i >= length(v)) return ""; i++; nc=substr(v,i,1); if (nc == "n") out=out "\n"; else if (nc == "\"") out=out "\""; else if (nc == "\\") out=out "\\"; else out=out "\\" nc; i++ } else { out=out c; i++ } } return "" } BEGIN{zsp=ENVIRON["ZSP"]; sp=(zsp==""?"[[:space:]]":"(" zsp "|[[:space:]])"); sec="^" sp "*\\["; stor="^" sp "*\\[" sp "*storage" sp "*\\]"; key="^" sp "*path" sp "*="} $0 ~ sec{in_s=($0 ~ stor)} in_s && $0 ~ key {v=$0; sub(key,"",v); pok=0; w=parseval(v); if (pok) last=w; else bad=1} END{if (bad) exit 1; print last "x"}' "$CONFIG") || { echo "cannot parse the configured storage path; aborting rehearsal"; exit 1; }; CFG_PATH=${CFG_PATH%x}
case "$STORE" in /*) ;; *) echo "rehearsal requires absolute POSIX paths (a relative spelling can hide a file: URI); aborting"; exit 1;; esac
case "$CFG_PATH" in /*) ;; *) echo "rehearsal requires absolute POSIX paths (a relative spelling can hide a file: URI); aborting"; exit 1;; esac
STORE_R=$(realpath "$STORE" 2>/dev/null; printf x); STORE_R=${STORE_R%x}; STORE_R=${STORE_R%?}
CFG_R=$(realpath "$CFG_PATH" 2>/dev/null; printf x); CFG_R=${CFG_R%x}; CFG_R=${CFG_R%?}
[ -n "$STORE_R" ] && [ -n "$CFG_R" ] && [ "$STORE_R" = "$CFG_R" ] || { echo "store path and configured pathname do not resolve together; aborting rehearsal"; exit 1; }
command -v iconv >/dev/null 2>&1 || { echo "iconv is required to validate path encoding; aborting rehearsal"; exit 1; }
printf '%s' "$STORE_R" | iconv -f UTF-8 -t UTF-8 >/dev/null 2>&1 || { echo "resolved store path is not valid UTF-8 (SQLite would open a mangled spelling); aborting rehearsal"; exit 1; }
UTF8_OK=0; ASCII_OK=0
if command -v locale >/dev/null 2>&1; then
  CM=$(LC_ALL=C.UTF-8 locale charmap 2>/dev/null || true)
  printf '%s' "$CM" | grep -qiE '^utf-?8$' && UTF8_OK=1
  printf '%s' "$CM" | grep -qiE '^(ANSI_X3\.4-1968|US-ASCII|ASCII)$' && ASCII_OK=1
else
  ASCII_OK=1
fi
if [ "$UTF8_OK" = 0 ]; then
  [ "$ASCII_OK" = 1 ] || { echo "no usable locale for the rehearsal (need UTF-8, or ASCII with an ASCII charmap); aborting rehearsal"; exit 1; }
  GRC=0
  printf '%s' "$STORE_R" | LC_ALL=C grep -q '[^ -~[:space:]]' || GRC=$?
  if [ "$GRC" = 0 ]; then
    echo "non-ASCII store path needs a verified UTF-8 locale; aborting rehearsal"; exit 1
  fi
  [ "$GRC" = 0 ] || [ "$GRC" = 1 ] || { echo "ASCII check failed (grep error); aborting rehearsal"; exit 1; }
fi
rc=0; LC_ALL=C.UTF-8 haskoki-ctl store check --path "$STORE" --config "$CONFIG" > "$REH/check0.txt" 2> "$REH/check0.err" || rc=$?
[ "$rc" -eq 1 ] && [ "$(tail -n 1 "$REH/check0.txt")" = "verdict: migration-required" ] || { echo "source store is not migration-required; aborting rehearsal"; exit 1; }
```

The store path must resolve to the configured pathname first:
config selection accepts a hardlinked name by inode while
sidecar detection derives from `--path`, so divergent spellings
would check one directory's sidecars and copy another's store.
The resolved spelling must also be valid UTF-8 (checked with
iconv): SQLite opens paths through Text, which replaces
undecodable bytes, while realpath, the sidecar checks, and cp
use the original bytes — without the check the gate could pass
while the snapshot and the copy name different files. Every
`haskoki-ctl` invocation below runs under `LC_ALL=C.UTF-8`, so
the CLI decodes paths as UTF-8 exactly like SQLite encodes them
(under a latin1 locale the same bytes would decode to different
characters and the snapshot would open a double-encoded name).
The rehearsal verifies the UTF-8 charmap up front (`LC_ALL=C.UTF-8
locale charmap`): without one, only all-ASCII resolved spellings
may proceed (identical under every ASCII-compatible encoding),
and anything else aborts — a silent fallback would still exit 1
with the accepted verdict on ASCII fixtures while diverging on
anything else.
Both inputs must be absolute POSIX paths: a relative spelling
like `./file:x` would pass a prefix check yet resolve to a URI
SQLite opens decoded, while POSIX tools copy the literal —
absolute paths cannot hide a `file:` prefix.
The extraction reads the value the CLI would select: its
matchers fold NBSP and the Unicode space separators (Zs) as
padding — exactly the non-ASCII spaces the CLI folds — keep
the last assignment, and track section switches, so a pasted
exotic-space `path` or section header cannot hide behind (or
masquerade as) another section's lines. A line the matchers
accept but the value parser cannot read aborts the rehearsal
instead of keeping an earlier value: the CLI may select that
line while the rewrite would still replace it, which would
pass both gates on different paths. Spaces the CLI does not
fold (NEL, U+2028/2029, zero-width) fail the CLI parse in
syntactic padding — around keys, section headers, and values —
so the first gate aborts (inside comments and quoted values
they parse normally). `ZSP` is required in both blocks:
POSIX-only matching would miss exotic-space sections, so an
unset `ZSP` aborts instead of degrading. See `caseNbspPath`,
`caseDupPathLastWins`, `caseNbspSection`, `caseEmSpacePath`,
`caseEmSpaceSection` and `caseNonFoldedRejected` in
`tests/model/ConfigSpec.hs`.
Copy only after that gate passes. The gate pins the positive
verdict three ways: the check must exit 1, stdout (captured
separately from stderr, where diagnostics echo verbatim paths)
must end with the plan line `verdict: migration-required`, and
everything lands in a fresh `mktemp -d` directory, so no stale
file exists for a failed redirect to pass on. (An embedded
newline in a path can forge a matching line in merged output,
which is why the streams stay split and only the final plan
line counts; a fixed scratch path would let another local user
pre-plant files, which is why the directory is fresh.) Passing
the gate ensures the source got past sidecar and journal
detection, since a committed PIN change can exist only in the
WAL, which a main-file copy leaves behind (a `store-live`
refusal stops the check before sidecar detection, so gating on
the positive verdict also covers that masking). Setup aborts explicitly if
the scratch creation or its chmod fails (an assignment left of
`&&` would not trip `set -e`, leaving `$REH` empty). The
scratch holds a PIN-bearing config copy and a store copy with
recoverable PINs — 700 by explicit chmod before anything is
written, private under any umask.

```sh
[ -n "$ZSP" ] || { echo "ZSP is unset; aborting rehearsal"; exit 1; }
cp "$STORE" "$REH/token.sqlite" || { echo "cannot copy the store; aborting rehearsal"; exit 1; }
awk -v reh="$REH" '
  BEGIN { zsp = ENVIRON["ZSP"]; sp = (zsp == "" ? "[[:space:]]" : "(" zsp "|[[:space:]])"); sec = "^" sp "*\\["; stor = "^" sp "*\\[" sp "*storage" sp "*\\]"; key = "^" sp "*path" sp "*=" }
  $0 ~ sec { in_s = ($0 ~ stor) }
  in_s && $0 ~ key { $0 = "path = \"" reh "/token.sqlite\"" }
  { print }
' "$CONFIG" > "$REH/backend.toml" || { echo "cannot rewrite the config; aborting rehearsal"; exit 1; }
rc1=0; LC_ALL=C.UTF-8 haskoki-ctl store check --path "$REH/token.sqlite" --config "$REH/backend.toml" > "$REH/check1.txt" 2> "$REH/check1.err" || rc1=$?
[ "$rc1" -eq 1 ] && [ "$(tail -n 1 "$REH/check1.txt")" = "verdict: migration-required" ] || { echo "rehearsal copy is not migration-required; aborting"; exit 1; }
mkdir "$REH/backups" || { echo "cannot create rehearsal backup dir; aborting rehearsal"; exit 1; }
LC_ALL=C.UTF-8 haskoki-ctl store migrate --path "$REH/token.sqlite" \
  --config "$REH/backend.toml" --backup-dir "$REH/backups" || { echo "rehearsal migrate failed; aborting"; exit 1; }
LC_ALL=C.UTF-8 haskoki-ctl store check --path "$REH/token.sqlite" --config "$REH/backend.toml" || { echo "rehearsal read-back failed; aborting"; exit 1; }
```

The first check on the copy must print the migration-required
verdict (gated exactly like the source); the migrate must then
succeed — a commit followed by `migrate-receipt-failed` still
aborts the block instead of falling through to a `verdict: ok`
that would mask the failure. On success the migrate prints
`backup:` and `backup-sha256:` first, then the receipt and
`migrate-done`. The second check must print `verdict: ok` and
exit 0 — only then create the real backup directory, run the
same two commands on `$STORE` with `$CONFIG` and
`--backup-dir /srv/haskoki-backups`, and start the service. The
rehearsal copy holds the same recoverable PINs as the store;
delete `$REH` afterwards (`rm -rf "$REH"`).

`--config` must name the same store as `--path`: a config written for
another file is refused as `config-mismatch`. That is why the rehearsal
writes its own config for the copy (see `caseConfigSelects` in
`tests/storage/PreflightSpec.hs` and `caseCheckConfigMismatch` in
`tests/storage/StoreCtlSpec.hs`). Spelling checks run before the select:
a `--path` (or, for migrate, a `--backup-dir`) the opener cannot place
is refused as `store-spelling` (or `migrate-unsafe-backup-dir` with the
spelling reason) even when the config would mismatch too; `store inspect`
and `store reset` report the same refusal as `store-invalid`.

### What check and migrate report

| Exit | Meaning |
|---|---|
| 0 | check: preflight passes with this config for the resolved --path and the effective catalog it was checked with (past the native entry checks — including caller arguments, thread support, and provider state — serving that same path and catalog additionally requires construction bounds, writable ownership, pragma verification, reload, counter validation, the seed write when seeds are pending, backend open, assembly, and mutex creation when the caller supplies callbacks). migrate: migrated, or `migrate-not-needed` (no migration transaction ran). |
| 1 | a diagnosed refusal; one stderr diagnostic `<tag>: <detail>` (the detail can span lines when it echoes a path) |
| 2 | usage error |
| 130 | interrupted by SIGINT; one stderr line (`migrate-interrupted` or `check-interrupted`), store state unknown |

Tags: `store-migration-required`, `store-identity-refused`, `store-live`,
`store-lock-unwritable`,
`store-journal-present`, `store-journal-cold`, `store-foreign-sidecar`,
`store-unsupported-version`,
`store-corrupt`, `store-full`, `store-missing`, `store-unreadable`,
`store-spelling`, `store-invalid`,
`check-interrupted`,
`config-invalid`, `config-mismatch`, `migrate-unsafe-backup-dir`,
`migrate-store-changed`, `migrate-backup-exists`, `migrate-backup-failed`,
`migrate-commit-unknown`, `migrate-failed`, `migrate-unexpected`, `migrate-interrupted`,
`migrate-verify-failed`, `migrate-receipt-failed`.

A serving open refused with a typed store error returns NULL to C
(hence CKR_GENERAL_ERROR) and best-effort emits one JSONL cause row
through the acquisition tracer (`caseSeatingRow` and siblings in
`tests/engine/InitDiagnosticSpec.hs`), which the rollback close
drains once (`caseRollbackCloseDrainsRow`). Only the store step
reports: the initialization and backend failure arms return NULL
with no row. Best effort: disabled tracing, queue overflow, or sink
failure loses the row, and the NULL is returned either way (the
sink holds a FIFO reader across each open and its writes, so a
disconnecting reader cannot terminate the host even if it
restored SIG_DFL, and the host disposition is never touched).
A FIFO the provider cannot open for reading (mode 0200
without privilege, since the holder needs read permission)
loses rows silently — the rollback discards the drain report,
so the C caller sees the same code with no bytes and no
stderr. The row
reason is `<tag>: <remedy>` with the
fixed remedy from the table below; the CLI `store check` / `store
migrate` lines reuse the same tags with the live detail (paths,
versions, reconciler prose). Every table cell is pinned against its
tag's expected content (`caseDocCells` in
`tests/engine/InitDiagnosticSpec.hs`).

| Tag | Surfaces | Trace remedy | Reachability |
|---|---|---|---|
| `store-seating-refused` | trace | token seating refused (<deny>): the catalog exceeds serving limits; shrink the configured token catalog and retry | Haskell/fixture opens only |
| `store-no-path` | trace | SQLite storage is configured without a store path: set storage.path to the store file | Haskell/fixture opens only |
| `store-live` | trace, cli | the store lock could not be acquired (run haskoki-ctl store check to see the lock state): if a store owner holds it, stop the owner and retry; otherwise inspect the lock file and retry | serving init + CLI |
| `store-journal-present` | cli | a hot or unrecognized rollback journal is present: do not delete it; see docs/operations-notes.md, Interrupted migration | CLI only (mapped for totality) |
| `store-journal-cold` | cli | a cold rollback journal is present, or migration found the store busy: stop any process that holds the store, run haskoki-ctl store check, and retry store migrate with a valid backup directory unless check names another blocker; if migrate keeps reporting cold, stop and investigate: wait for a persistent SQLite lock holder to release once identified, or retry migrate once for a cold journal that appeared with no holder left | CLI only (mapped for totality) |
| `store-foreign-sidecar` | trace, cli | a foreign WAL sidecar is present: do not start the service; when the sidecars are confirmed stray, move the -wal/-shm pair aside (keep both files) and run store check again; otherwise keep them with the database; see docs/operations-notes.md, Upgrade, backup and recovery | serving init + CLI |
| `store-migration-required` | trace, cli | Schema case: the store schema needs haskoki-ctl store migrate to reach the current schema. Stored-token case: stored tokens lack credential rows: run haskoki-ctl store migrate | serving init + CLI |
| `store-unsupported-version` | trace, cli | the store's schema marker is not one this build opens or migrates: inspect the schema marker with SQLite tooling; reopen with the writing build if a newer haskoki wrote it, or restore a backup if the marker itself is damaged | serving init + CLI |
| `store-corrupt` | trace, cli | the store content is damaged or inconsistent: restore a backup; see docs/operations-notes.md, Upgrade, backup and recovery | serving init + CLI |
| `store-full` | trace, cli | the store cannot grow: free disk space and retry | serving init + CLI |
| `store-lock-unwritable` | trace, cli | the store lock cannot be created: fix the directory permissions or free space and retry | serving init + CLI |
| `store-unreadable` | trace, cli | Unopenable store: the store cannot be opened (I/O, SQLite, or format failure): run haskoki-ctl store check for detail and retry; if check reports ok, inspect the store with SQLite tooling. Quarantined connection: a prior failure quarantined the store connection: restart the service. Over quota: a store quota refused the write: shrink the payload and retry. Write conflict: a commit conflict was detected between the request and current store state (examples: stale revision, dangling reference, duplicate slot use): re-read state and retry; if it persists, correct the request | serving init + CLI (other wordings mapped for totality) |
| `store-reload-refused` | trace | stored token state refused (<deny>): the store exceeds serving limits; shrink the store and retry | serving init |
| `store-commit-failed` | trace | the open's seed commit failed (rejected or outcome unknown): retry the open; if it persists, check disk space and run haskoki-ctl store check for store state | serving init |
| `store-catalog-mismatch` | none | retained refusal (no longer produced): catalog/store drift reports as store-identity-refused | none (retained) |
| `store-identity-refused` | trace, cli | stored token identity drifted from the catalog: run haskoki-ctl store check for the reconciler's report | serving init + CLI |
| `store-missing` | cli | no store file at the path: for an ordinarily missing path, start the service once to initialize a fresh store; for a dangling link, remove the link and serve the real path, recreate the target, or restore a backup | CLI only |

Reachability notes. `store-seating-refused` and `store-no-path`
fire only through the Haskell API or injected openers: native
construction refuses an over-limit catalog before any seat, and
native config resolution refuses pathless SQLite before any tracer
exists. The journal, quarantined, limit, and conflict wordings are
mapped for totality and never emitted: journals are a CLI-preflight
refusal (the serving opener only refuses foreign WAL sidecars),
quarantine is connection-lifetime state, and seed-commit limit and
conflict failures arrive as the untyped `store-commit-failed`.
`store-full` does surface at serving init: SQLITE_FULL from
connection setup, reads, or the fresh-init `BEGIN IMMEDIATE` maps
to it (failures of the schema statements and `COMMIT` wrap as
`store-unreadable`, and seed-commit failures arrive as the untyped
`store-commit-failed`). `store-catalog-mismatch` is retained but no
longer produced (drift reports as `store-identity-refused`).
`store-missing` is CLI-preflight-only: an ordinarily missing path
initializes a fresh store on open, while `store check` reports a
dangling final symlink as `store-missing` too once its owner probe
passes — a non-regular `.lock` at the resolved target reports
`store-live` first. The serving open refuses a dangling link as
`store-unreadable`, creating nothing there provided the trace file
is configured away from both the link and its target (the rollback
drain follows links when appending and creates a missing target
file).

Output and receipts name token ids (as 16 hex digits, the same text as the
token serial), labels, versions, paths and reasons. They never print a PIN
or key byte (`caseCheckNoPins`, `caseMigrateCliNoPins` in
`tests/storage/StoreCtlSpec.hs`).

`store check` of a rollback-journal store never writes: it opens
the database read-only, never creates or removes `<store>.lock`,
and refuses with `store-live`
when an exclusive database kernel lock is held (the shared probe
coexists with shared holders, and the sidecar is read without
flocking, so a shared database flock or a sidecar-only flock can
pass the owner probe yet block ownership), when the database
cannot be probed, or when the sidecar is truly unreadable, not a
regular file, or cannot be examined; a stale sidecar with no holder — the
opener's own pid, a live pid such as container pid 1 after a kill,
an empty file, or garbage — reports offline and is taken over on
open or on a migrate that proceeds to ownership when the server
user can open the sidecar read-write (`caseCheckLive`,
`caseSnapshotReadOnlyDir`, `caseProbeStaleTakeover`,
`caseCheckStaleTakeover`, `caseMigrateStaleTakeover`). The sidecar
PID in `store-live` lines is only a hint: `pid-1, held refuses
live` in `tests/storage/PreflightSpec.hs` pins `pid 1 holds the
lock` while the test process itself holds the flock.

`store inspect` is the other read-only reader: it reports lock state plus
table counts over a `SELECT`-only connection and never creates the sidecar
(`inspectStore` in `src/Haskoki/Ctl.hs`, `caseInspect` in
`tests/storage/StoreCtlSpec.hs`) — read-only at the SQL layer, though
opening can still replay a hot journal, and closing the last
connection can still checkpoint a WAL. The two disagree on liveness by design:
`store inspect` judges the sidecar pid through `/proc` only
(`readLockState`), while `store check` uses the kernel flock as the
authority (`probeOwner` in `src/Haskoki/Runtime/Storage/SQLite.hs`), so a store
whose kernel lock is held but whose sidecar is absent reports `offline`
under `inspect` and `store-live` under `check` (see `casePlanLiveOwner`
in `tests/storage/PreflightSpec.hs`), and a stale sidecar naming a live
pid with no holder reports `live` under `inspect` but `offline` under
`check`.

A stale lock with no holder needs no manual step when the server
user can open the sidecar read-write: the next open, or migrate
when it proceeds to ownership, takes it over and best-effort
rewrites the pid. Only a truly unreadable sidecar
(permission denied, or a file far beyond a pid line without
one) or a non-regular one (symlink, directory, or FIFO, refused
before any flock is attempted) still refuses without consulting the
kernel, as does a readable
sidecar the server user cannot open read-write, regardless of the
recorded pid: it can pass a read-only sidecar probe yet fail
takeover (`store check` also tests the database flock, while the
serving open goes directly to ownership); then, as root, stop the
store and keep it down — these probes are point-in-time
diagnostics on the resolved paths — and confirm no flock-held
owner with `flock -n <store> true && flock -n <store>.lock true`
(regular files only, since `-n` applies to lock acquisition and
opening a FIFO can block; path-form `flock` creates a missing
file; exit 0 means no flock holder — SQLite POSIX locks such as
`RESERVED` are invisible to `flock` on local Linux filesystems,
so check those separately with `lslocks`), or identify accessing
processes with
`fuser <store> <store>.lock` (exit 0 means some process accesses
the files; a nonzero exit means none matched, or an error
occurred; in either case a holder outside the caller's visibility
stays hidden), and either fix the sidecar's
ownership or remove `<store>.lock` before retrying.

When `store migrate` cannot create the `<store>.lock` sidecar at all
(a read-only directory or mount, no space), it reports
`store-lock-unwritable` and names the lock path with the system
error — never `store-live`, since no owner holds the store
(`caseCheckNeverOwns` in `tests/storage/PreflightSpec.hs`).

`store reset --confirm-demo-reset` removes an offline store and its
`<store>.lock` sidecar, refusing a live store. Both removals run
while the sidecar and database kernel locks are held, so a racing
opener is refused until both files are gone, after which it starts
a fresh store; a stale pid-1, empty or garbage
lock with no holder is taken over and reset instead of refused, and
a database that cannot be probed refuses without claiming the store
is live (`caseResetStalePid1`, `caseResetStaleEmpty`,
`caseResetStaleGarbage`, `caseResetRefusesKernelHeld` in
`tests/storage/StoreCtlSpec.hs`). The next open through
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
link, creating nothing there provided the trace file is configured
away from both the link and its target (`caseOpenDanglingLink`).

### What migrate does

1. Refuses when: the config does not select this
   store; the backup directory is missing, not a real directory (a
   symlink is refused), not writable, or the store's own directory; a
   process holds the store; a non-empty `-wal` or `-shm` sibling
   exists, reported as `store-foreign-sidecar`
   (checked before the journal classification, so a cold journal
   never bypasses it; see `caseMigrateCliColdWal` in
   `tests/storage/StoreCtlSpec.hs`); an interrupted write left
   `<store>-journal` (hot, unknown, or not a regular file as
   observed, which is refused without opening; see
   `caseCheckNonRegularJournal` in
   `tests/storage/StoreCtlSpec.hs` and `caseCheckWalShm` there); the
   catalog does not match the stored tokens (labels, slots, ids;
   restore the catalog the store was written with). A store that is
   already current returns `migrate-not-needed` instead of refusing,
   leaving any cold journal untouched (see
   `caseMigrateCliSchema3Cold`). Refusals before the snapshot
   reads (config, backup-dir, non-regular store, live owner) write
   nothing; on a WAL-format database the planning snapshot itself
   can create sidecars that the post-read guard then reports as
   foreign when the snapshot itself succeeded (a snapshot error
   or a vanished file takes precedence) — a WAL-header store
   without sidecars, addressed by a POSIX spelling, is
   unplannable through this snapshot path until a serving open
   converts it back to rollback-journal mode (an immutable-URI
   open would not create sidecars at all, but the snapshot does
   not use one; the reported sidecars may be the check's own,
   so moving them aside and retrying loops). Through a @file:@
   URI spelling the snapshot opens the decoded file, exactly
   like the guards: spellings normalize up front in
   `resolveStoreSpelling`, so sidecars beside the decoded file
   are reported under the same three-case guarantee below
   (pinned by `caseUriTwinSidecar` in
   `tests/storage/StoreSpec.hs`). A cold
   journal is cleared only after this plan says the migration
   proceeds.
2. Takes the store's ownership lock for the rest of the run. A store
   whose snapshot no longer matches the plan (schema, token records,
   object and job counts, credential coverage, metadata, or file
   identity) refuses here, under ownership — before journal
   clearing, backup creation, and the migration transaction, after
   the `<store>.lock` sidecar is created or taken over. A content
   edit that preserves all of those (an object payload edit at
   unchanged size within the same mtime second, for example) is not
   detected.
3. Writes a new backup `<store>.pre-migrate.schema<N>.<epoch>.bak`
   (mode 0600; an existing name is never overwritten, the next free
   `-1`..`-99` name is used), verifies it byte for byte and by reading
   it as a store, and records its SHA-256. A backup that fails
   verification is removed again on a best-effort unlink; even if
   the file remains it is never trusted — no digest was recorded
   for it, so the restore-time `sha256sum` check cannot pass
   (`caseMigrateBadBackupRemoved` pins the removal in the normal
   case). The moment verification passes,
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
   (`yes` when the clear step unlinked the cold journal, found
   it already gone when unlinking after a cold classification,
   or classified it absent on recheck (failed stat or empty file
   counts as absent, and that branch reports `yes` too) — else
   `no`; a failed header read on a nonempty file counts as unknown
   instead; see Interrupted migration below). The receipt is written
   through a unique temporary `<backup>.receipt.tmp.<pid>.<nonce>` (for
   example, `token.sqlite.pre-migrate.schema2.1700000000.bak.receipt.tmp.1234.0`)
   plus `link` so a taken name is never overwritten; on filesystems
   without hard links it falls back to a direct exclusive write of the
   final name (`writeReceipt` and `isLinkUnsupported` in
   `src/Haskoki/Runtime/Storage/Preflight.hs`,
   `caseMigrateReceiptLinkFallback` in
   `tests/storage/PreflightSpec.hs`). A stale temporary from a crashed
   run is ignored, never fatal by itself — fatal only if stale
   temporaries occupy every candidate name and the bounded
   (129-name) search exhausts
   (`caseMigrateStaleReceiptTmpIgnored`);
   removal of provably-dead owners' temporaries is attempted when
   the next migration writes its receipt (listing and unlink
   failures ignored; `caseMigrateStaleReceiptTmpCleaned` pins the
   normal case).
   That liveness check reads the local PID namespace only, so two
   containers sharing one backup directory can delete each other's
   live temporary (the loser reports `migrate-receipt-failed` for a
   migration that actually committed): never share a backup directory
   between PID namespaces; give each writer its own.

If the transaction fails (for example, a full disk), no rollback
is claimed uniformly: a COMMIT failure with an open transaction
attempts a rollback, and is classified as rolled-back only when
the rollback succeeds, autocommit is restored, and the journal
reads absent (an already-ended transaction goes directly to
unknown; an unstatable journal reads absent without certifying
unchanged bytes); a body failure attempts rollback best-effort
with errors discarded; and setup failures never begin a
transaction. Run `store check` to establish store state,
restoring the verified backup on inconsistency. The backup
stays, and no receipt is written
(`caseMigrateTxnFailureKeepsStore`). Free the space and run migrate
again; it writes a new backup. The backup directory needs room for one
copy of the store. If migrate reports that the COMMIT outcome is unknown,
the store may already be at schema 3, so run `store check` before
retrying; the backup stays and no receipt is written
(`caseMigrateCommitFailureHonest` in `tests/storage/PreflightSpec.hs`).

### Interrupted migration

If migrate is killed mid-transaction, `<store>-journal` can remain
(a kill after `BEGIN IMMEDIATE` and before the first write leaves
no journal). Do not delete it. To tell a hot journal from the rest,
the file is classified
by these rules: a failed stat or an empty regular file counts as
absent (no refusal); a symlink, FIFO or device observed at stat time
is refused as unknown without opening it
(`caseSnapshotRefusesNonRegularJournal` in
`tests/storage/PreflightSpec.hs`, `caseCheckNonRegularJournal` in
`tests/storage/StoreCtlSpec.hs`); a path that changes to a FIFO
between stat and open can still block on the subsequent read; a
non-empty regular file with fewer
than eight readable bytes is unknown; eight leading zero bytes mean
cold; eight matching magic bytes (`d9 d5 05 f9 20 a1 63 d7`) mean hot
for preflight purposes — a replay candidate, though SQLite still
needs a complete header to actually replay it — and a readable
eight-byte prefix matching neither magic nor zeros is unknown
(`classifyJournal` in `src/Haskoki/Runtime/Storage/SQLite.hs`).
A non-empty `-wal` or `-shm`
sibling is checked before the cold classification, so a cold journal
plus a foreign `-wal` reports `store-foreign-sidecar`, never cold, and
every byte stays untouched (`caseMigrateCliColdWal` in
`tests/storage/StoreCtlSpec.hs`).

When the initial journal guard produces the refusal, a hot journal
(or an unknown header) stays refused: `store check` and `store
migrate` report `store-journal-present` and touch neither file
(ownership, backup-directory validation for migrate, and the
foreign-sidecar check all take precedence).
Either start the serving haskoki once as a recovery attempt: it
needs to take exclusive flocks on both the store and the sidecar
— a writable store with no live owner or foreign sidecar, and a
sidecar the server user can create or open read-write — followed
by successful SQLite recovery of an intact hot journal from the
interrupted migration, which needs the database, the journal,
and its directory writable; when
recovery succeeds, the store returns to its pre-migration
committed state (freelist leaf bytes may differ, as SQLite omits
them from the journal). The open then proceeds to its remaining
checks, so run check and migrate again only if it refuses as
migration-required — a schema-3 store can still refuse at reload,
counter validation, identity, or credential checks. A magic-only
truncated journal is discarded without replay instead — which
removes the journal blocker, though nothing verifies whether it was
truncated before any database writes, so prefer the verified backup
when one exists and run check to establish the store's state either
way. An
unknown header cannot use that route: SQLite may delete such a
journal without replaying it, so restore the verified backup
instead (migrate keeps refusing it too). A read-only
database likewise refuses recovery — restore the backup somewhere
writable. Or
restore the backup the interrupted run wrote, moving the store and its
journal aside together first (`caseKilledMigrationRecovers`,
`caseKilledRestoreMovesJournal`) — but only after verifying it: the
run printed `backup:` and `backup-sha256:` before its transaction
began, and `sha256sum` over that backup must equal the recorded
digest. A kill mid-write leaves a partial `.bak` that fails this
check; never restore it. That usually means the kill landed during
backup writing, before the migration transaction started and before
that backup's digest was printed: recheck the original store and
follow its verdict. A partial backup plus a read-only hot journal
falls outside both routes — fall back to another verified backup,
if available.

A non-empty `-wal` or `-shm` sibling is a different refusal once
the checks reach the sidecar guard: `store check`, `store migrate`
and the serving open all report it (`store-foreign-sidecar` on the
CLI; the serving open fails closed the same way any store-open
refusal does) and, when the refusal comes from a guard before
SQLite opens, preserve the store, the journal, and the
`-wal`/`-shm` pair as found, because opening could checkpoint
foreign frames into the store (a lone `-shm` carries none), while
the serving open
still acquires and releases the `<store>.lock` ownership sidecar and
may append the trace row (assuming the trace file aliases none of
the preserved files). At a missing path the serving open still
creates the empty database file before refusing. On a WAL-format
database without sidecars, check's own read-only snapshot can
create the siblings it then reports. Three cases escape the
preflight reporting guarantee for POSIX spellings (the URI escape
is noted above; the guarantee covers only sidecars successfully
observed as nonempty — an unstatable sibling reads absent):
a sidecar that appears after an
initial cold
verdict is detected by the cold-tolerant retry but masked —
`store check` still falls back to the original `store-journal-cold`
(`coldOkOrRefusal` in `src/Haskoki/Ctl/Store.hs`); a sidecar that
appears during the snapshot is masked whenever the snapshot itself
fails, since the snapshot error takes precedence even when the
post-read guard detects it; and a post-read stat failure masks a
detected sidecar, reporting `vanished while read` instead. A rerun
then reports the sidecar, provided it is still present and the
rerun reaches the guard — under any spelling, since guards
and the opener share the decoded path. Post-commit read-back
is separate: a
sidecar detected during `verifyMigrated` produces
`migrate-verify-failed` with no receipt, after the migration has
already written the store. Never start
the service to clear foreign sidecars: the serving open refuses
them too. When the sidecars are confirmed stray (no WAL-mode
writer ever touched this database), move `<store>-wal` and
`<store>-shm` aside (keep both files) and run `store check` again
(`caseForeignSidecarRemedy` in `tests/storage/PreflightSpec.hs`,
`caseServingRefusesForeignWal` there). When the sidecars keep
reappearing with nothing in them — a WAL-header store whose
sidecars were absent before the check, so the check created and
then reported its own — moving them aside and rechecking loops:
move them aside (keep both files), open the store once with the
service, which converts the header back to rollback-journal mode,
and only then run `store check` again. A WAL that matches the
database, or any uncertain case, stays with its database during
recovery — moving it aside could validate an older state, since a
belonging WAL can hold committed transactions the main file lacks.

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
between the plan and the clear counts as cleared (treated as
absent on recheck). The line
is printed to stdout and flushed the moment the journal is cleared,
so a run killed after the flush still leaves its record in the
operator's log (a kill between the unlink and the flush can leave
the journal gone without a record); every reported outcome
after the flag is set then carries `cold-journal-removed: yes` at
the end of stdout, usually repeating the clear-time line — a
SIGINT landing between
the unlink and the flag is reported as 130 without the line though
the journal is gone; one between the flag and the print leaves
the outcome's copy as the only one
(past the print the line is already emitted or still buffered, so
both copies appear) —
including failures (and in the receipt when one is written)
(`caseMigrateClearsColdJournal`, `caseKilledSmallMigrationClears`,
`caseMigrateReportsClearOnFailure` in
`tests/storage/PreflightSpec.hs`). A store whose snapshot no longer
matches the plan refuses before this run clears anything; another
process can meanwhile remove the journal, so its presence is not
guaranteed (`caseMigrateStoreChangedKeepsColdJournal` covers the
single-process case). Any other outcome leaves the journal
untouched — except SQLite recovery of a hot journal: the
cold-clear connection's `BEGIN IMMEDIATE` can consume one that
appeared after the owned snapshot (before any backup is made),
and the migration transaction's own `BEGIN IMMEDIATE` can
consume one that appeared later (after backup verification).
A cold
journal on a store whose
cold-tolerant plan is otherwise openable is not a refusal at all:
`store check` exits 0 with `verdict: ok` and the line `journal: cold
(harmless; left alone by this command)`, touching neither file, and
`store migrate` reports `migrate-not-needed`, leaving the journal
alone (`caseMigrateCliSchema3Cold` in `tests/storage/StoreCtlSpec.hs`).
Either migrate outcome needs a valid, writable `--backup-dir` first:
an invalid one refuses before planning.
The journal is harmless there (SQLite already reads committed state,
the cold journal does not block the serving open, and the next write
transaction reuses the file when one is present). Catalog drift still refuses as
`store-identity-refused` (`caseCheckColdJournalIdentityRefused` in
`tests/storage/StoreCtlSpec.hs`), and missing credential rows still
refuse as cold until migration supplies them. A cold journal while
another process holds `RESERVED` stays refused on the migration path
that must clear it (`caseColdJournalReservedRefuses`); a current
plan reports `migrate-not-needed` before attempting that lock. If
migrate keeps reporting cold, stop and investigate: wait for a
persistent SQLite lock holder to release once identified (find it
with `lslocks`, which sees the PID namespace of the mounted
`/proc`; `fuser` on the store file lists only the processes
visible to the caller and can miss holders), or retry migrate
once if a cold journal appeared with no holder left.
A migration with no cold
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
store path, and run `store check`. A pre-migration backup is the
store as it was when the backup was taken: usually a schema 1 or
2 store
(v0.3.1.0 opens schema 1 only; v0.4.0.0 opens schema 2 and migrates
schema 1 on open; v0.5+ needs `store migrate` again), but a run that
only supplies missing credential rows backs up a schema-3 store,
which old binaries refuse and v0.5+ must migrate again. Restoring
brings back the credentials as they were when the backup was taken:
PINs changed since then revert. A rowless backup instead restores
the rows as missing; the next migration supplies them from the
catalog it is given. Nothing prevents rolling back to an older
credential state (`caseRestoreBringsBackOldCredentials`).

### Old binaries and downgrade

After migration, v0.3.1.0 and v0.4.0.0 refuse the store
(`schema_version = 3` is not theirs; `C_Initialize` fails and the file
is unchanged, checked by `scripts/qualify-store-upgrade.sh`). To go back,
restore a pre-migration backup the target binary opens — schema 1 for
v0.3.1.0, schema 1 or 2 for v0.4.0.0 (a credential-only run's schema-3
backup cannot go back); changes made since are lost. Once schema
classification reaches a newer marker, open, check and migrate all
refuse with `store-unsupported-version`. Reaching classification
requires an owner stage with no live owner — a passing probe for
check and migration planning, taken ownership for serving and the
migration run — plus backup-directory validation for migrate and
no foreign sidecar: a non-empty `-wal`/`-shm`
reports `store-foreign-sidecar` in both commands; a cold journal
makes `store check` report first (run `store migrate` to surface
the version refusal underneath), while a hot or unrecognized
journal takes precedence in both commands (clear it first — see
Interrupted migration above — then recheck; the version refusal
surfaces only if the marker is still newer).

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
`scenario.async.enabled` and `scenario.async.pending_polls` do not
configure this native policy. There are no new threads, timers, or
configuration semantics.

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

At the pinned proxy v0.3.1 (`ed803d46`),
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
example-grade fixtures. The SQLite store holds the current PINs in
recoverable form (base64 `so_pin`/`user_pin` in each `credentials`
row, with no hashing), and every `store migrate` backup copies
those bytes; backups are written 0600 and both must be protected
like the store itself.

Trace and store files. Tracing is off by default; `[trace]
enabled = true` turns it on, and the provider then writes the
trace file, one JSON record per successful control-plane command
(`./haskoki-<pid>.jsonl` in the host process's working
directory, or the configured path; `HASKOKI_TRACE` overrides the
path only and does not enable tracing; `{pid}` expansion,
append-only without rotation,
best-effort; `ffi/Haskoki/FFI/Instance.hs`) and, in SQLite mode,
the store file
plus its sidecars: a `<db>.lock` ownership file carrying the owner
pid (created `O_EXCL` at open, removed on close, taken over when no
process holds it — the kernel flock is the authority, so a stale
sidecar naming a live pid, the opener's own pid, an empty file, or
garbage is taken over and the pid rewritten, while a held lock
refuses) and, under the configured rollback-journal mode
(`PRAGMA journal_mode = DELETE`), a transient `<db>-journal` file
that SQLite holds for the duration of a write transaction and
removes on commit
(`src/Haskoki/Runtime/Storage/SQLite.hs`). Trace events redact
PINs, key material and message bodies to kind + length
(`src/Haskoki/Runtime/Trace.hs`). No other temp-file calls ship in
the provider paths (the `mkstemp`/`tmpfile` family is absent from
`src/`, `ffi/`, `app/`, `cbits/`, `core/`, `tools/`).

Close and lifecycle. `C_Finalize` closes every open session,
cancels the PKCS#11 surface's attached jobs, retires still-live
joined attachments as canceled (best effort; already-terminal ones
keep their fate), keeps detached idle records for a later interval,
and ends the provider interval without stopping the RTS
(`cbits/rts_bootstrap.c`); caller-owned native async contexts are
unaffected; closing the backend releases digest
contexts and drops the key maps. `validateFinalize` in
`src/Haskoki/Runtime/Lifecycle.hs` governs only the internal
`Lifecycle.finalize` API, not the shipped `C_Finalize` path. The provider starts the RTS with
one capability and ignores `GHCRTS` when it starts the RTS itself;
a process that already runs a GHC RTS keeps its own capability
count. Unload is pinned (`-z nodelete`
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
| Lifecycle interval (`Haskoki.Runtime.Lifecycle`) | The instance owns the interval | Finalize closes every open session, cancels the PKCS#11 surface's attached jobs, retires still-live joined attachments as canceled (best effort; already-terminal ones keep their fate), keeps detached idle records, and never stops the RTS; caller-owned native async contexts are unaffected | State lock; the module stays pinned (`-z nodelete`) |
| Storage handle (`Haskoki.Runtime.Storage` + backends) | The open handle owns token/object rows; SQLite adds a lock file, memory an in-memory ownership token | Close releases the SQLite lock file or the memory ownership token and drops the handle; SQLite sidecars follow the write transaction | Single-writer; commits serialize; quarantine refuses until an authoritative reload clears it |
| Attached async tables (`Haskoki.Runtime.Async`) | The instance owns tables and retained bytes | Attached terminal tombstones are bounded (4096 records, 64 MiB); the just-committed job is always retained and may transiently exceed the byte bound; owners may reap attached tombstones eagerly with `reapJob`; detached terminal records (`Haskoki.Runtime.Detached`) stay stored; submit admits only checked, outer-coherent work, and fixtures use the named test-only admission | STM; no background reaper |
| Slot service (`Haskoki.Runtime.SlotEvents`) | The interval owns flags and the hub | Close discards pending flags and wakes undecided waiters with `CKR_CRYPTOKI_NOT_INITIALIZED` | One flag has one consumer; no broadcast |
| Serving backend (`Haskoki.Engine.OpenSSL4`) | The instance binds one backend for serving | Close releases digest contexts and drops the key maps | Backend operations hold the exclusive environment gate (environment-then-registry order), atomic with close; digest contexts are borrowed under the registry lock while used |
| Trace queue (`Haskoki.Runtime.Trace`) | The `Tracer` owns a bounded STM queue with drop/failure counters; the sink is caller-supplied | Drains write queued lines through the sink; failures counted, never thrown; the serving sink appends per line | Queue operations are STM; concurrent drains share the sink with no ordering across drains |
| FFI entries (`Haskoki.FFI.Standard`) | Entries borrow the instance; callers own native buffers per the entry contract | Session close, close-all, removal, and finalize retire associations without callbacks | State lock, except blocking waits which park in STM without it; callbacks hold the lock as their lease |
| Standalone proof APIs (`Haskoki.FFI.Async`, `Haskoki.FFI.Exports`) | The caller owns each standalone context and its store box (serving instead borrows `AsyncCtx` views sharing its backend/table, with no teardown authority); close every context on a box (and join their calls) before closing the box; a Store no caller can receive is recovered by the next standalone open or close that reaches acquisition, and until then its lock stays held | Explicit close per context (`haskoki_hs_async_close`, `haskoki_hs_async_store_close`, `haskoki_hs_crypto_close`); the store box outlives contexts opened on it; a failed or canceled close keeps its slot — a close canceled in the borrower wait reopens the context, while one canceled past it stays owned by its slot in a closing state that admits nothing and the next close resumes it, and a box close keeps its slot until a retry closes the Store | Direct Haskell calls take no C state lock; `AsyncCtx` carries its table and leases; context close is cancellable at every blocking wait but the bounded SQLite busy waits inside FFI calls, and resumable through the slot; borrowed views are internal (installed/retired under the C state lock); an admitted caller runs outside that lock; raw `AsyncTable` methods take no context admission, so callers serialize use with destruction; `CryptoCtx` has no retirement lease, so callers must not use it after close |

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
