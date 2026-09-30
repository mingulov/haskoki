# v3.2 async C routing design

Design draft for approved sub-project two. Source inspection: `main` at
`cd43bd04df8aa5c61e671cb883a30b100dc011d7`, 2026-09-30.
This draft records source observations and subsequent implementation requirements.
It claims no build, gate, consumer, proxy, or oracle execution.

## 1. Goal and non-goals

Route `C_AsyncComplete`, `C_AsyncGetID`, and `C_AsyncJoin` through the real
3.2 function table to the existing async workers, preserving scheduler and
detached-store behavior through an explicit standard-session adapter.

The three entries occupy ordinals 100, 101, and 102. Their contracts remain
`planned-with-behavior`; routing adds C-consumer evidence, not a new contract
classification.

All configuration delta items D1-D12 in `docs/async-config-design.md` are out
of scope, including completion budgets, per-slot storage, and new configuration
keys. Recovery operations, dual operations, and authenticated wrapping remain
later slices. Mechanisms, mechanism flags, recipes, authentication policy,
scheduler transitions, cancellation epochs, detached formats, retention policy,
and competing-join policy do not change. In particular,
`src/Haskoki/Runtime/Async.hs` and `src/Haskoki/Runtime/Detached.hs` retain
their logic.

The scope is C-table integration. It does not add worker threads, timers, a new
async engine, async key-template submission, or a general async conversion of
classic and message operations. The existing attached, detached, and restart
trampoline proofs remain intact.

**Necessary integration boundary.** Merely changing three table assignments
cannot meet the happy-path acceptance criteria. The inspected standard instance
has no `AsyncTable`, no session-to-job bindings, and no `DetachCtx`;
`std_OpenSession` rejects `CKF_ASYNC_SESSION`. The existing async exports
accept `StablePtr AsyncCtx` and `StablePtr JobHandle`, not a standard instance
or a public session handle. This draft treats the borrowed-context adapter,
async session admission, and one-shot digest submission described below as the
minimum routing glue. These are proposed implementation requirements, not
claims that this glue already exists. An implementation limited literally to
three bodies and a generator edit cannot satisfy this design.

## 2. Architecture

### 2.1 Existing proof API versus the public slots

The proof API is deliberately different from the public ABI:

| Property | Existing proof exports | Required table boundary |
|---|---|---|
| Identity | Async context, opaque live job token, numeric function code | Live standard instance, public session, function-name string |
| Completion progress | Poll advances; Complete alone observes or delivers | A valid Complete composes one existing poll with completion when ready |
| Byte storage | Complete receives a struct containing a caller buffer and capacity | Retain the buffer bound at submission or Join; construct an internal completion struct |
| Completion version | `pokeCompletion` writes the proof format version one | Encode public `CK_ASYNC_DATA.ulVersion` as zero |
| Join result | Successful attachment returns `CKR_PENDING` and a private job handle | Keep the handle privately; return `CKR_OK` after successful attachment |
| Join size reporting | Optional private need out-pointer | Public length is by value; no need out-pointer exists |
| Lifetime | Proof open owns its environment, backend, session, and table | Borrow the standard environment/backend and resolve actual standard sessions |

The output-pointer, version, and successful-Join translations follow sections
3.6 and 5.21 of the [PKCS #11 v3.2 specification](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.pdf).
The public result describes the original or rejoined allocation; its incoming
`pValue` is not a replacement destination. Pending leaves the result untouched.
GetID identifies an operation by function name and detaches its allocation.
The document's Join reference to variable-output conventions does not add a
length out-parameter to the pinned prototype. This design preserves the existing
byte-job capacity refusals and makes no public Join length-query claim.

Do not cast `StablePtr StdInstance` to `StablePtr AsyncCtx`, cast a session
integer to a job pointer, or assume public session one is the proof session.
Do not call `haskoki_async_open` behind each table call: that would create a
second environment and backend.

### 2.2 Per-entry flow

All three paths start with interface 3.2 discovery and a call through the actual
`CK_FUNCTION_LIST_3_2` member.

| Table slot | C body and new standard export | Existing worker/export reused | Runtime and output |
|---|---|---|---|
| C_AsyncComplete | `std_AsyncComplete` → `haskoki_std_async_complete` | `haskokiAsyncPoll` / `haskoki_hs_async_poll`, then `haskokiAsyncComplete` / `haskoki_hs_async_complete` when ready | `pollJob`, then `completeJob` or `completeJoined`; pending, terminal code, or one delivery to the bound buffer plus public result |
| C_AsyncGetID | `std_AsyncGetID` → `haskoki_std_async_get_id` | `haskokiAsyncGetId` / `haskoki_hs_async_get_id` | `detachJob`; durable record, revoke, private handle release, then scalar persistent id |
| C_AsyncJoin | `std_AsyncJoin` → `haskoki_std_async_join` | `haskokiAsyncJoin` / `haskoki_hs_async_join` | `joinJob`; validate and replan, attach private handle to the session/function, bind new output storage |

The standard exports call the same Haskell workers that back the named existing
foreign exports; a redundant C-to-Haskell-to-C round trip is unnecessary. The
proof export signatures and their existing return conventions remain unchanged.

The C state lock covers authoritative instance resolution, session lookup,
name decoding, worker invocation, binding changes, and output publication.
The existing job lease remains responsible for execution/delivery/cancellation.
There is no new independent arbitration protocol.

### 2.3 Instance and session bindings

Extend `StdInstance` in `ffi/Haskoki/FFI/Standard.hs` with one async table of
capacity eight, an optional detached context over its existing home-token
SQLite store, and a registry of session views and attached byte jobs.

A session view is an `AsyncCtx` constructed with the exact `siEnv`,
`siBackend`, actual `SessionId`, shared table, and its own live-handle set.
The registry owns its StablePtr. Standard's existing acquisition brackets must
also unwind a failed detached-context/view allocation before returning a null
instance; no store or backend ownership transfers to a borrowed view.
An attached entry records the function
identity, private job handle, output address, and effective byte capacity.
It retains neither the original input pointer nor the original length
out-pointer. Inputs continue to be copied by the existing decoder.

Use one table per instance, not one table per session: `DetachCtx.dcReverse`
keys by `JobId`, so independently numbered session tables would collide.
Only explicit async sessions are passed to `enableAsyncSession`. A view for
an ordinary session may be obtained for Join validation, but it is not enabled.

For SQLite, call `openDetached` once over the already-owned `StdStore`
and its home token. Do not open a second writer on the same file. Bind that
detached context only to sessions on its home slot; a session on another slot
must not detach a job under the home token's identity. Per-slot durable
bindings remain outside this scope.

The existing standard memory path has `siStore = Nothing`. Preserve it:
attached execution works, while a resolved live job's GetID and a Join on a
view without a store retain the proof export's `CKR_GENERAL_ERROR`.
Do not silently construct a second memory token store or change ordinary
token-object persistence. Public detached/restart happy legs therefore use
the existing SQLite configuration. The older proof API's explicitly owned
memory `StoreBox` still demonstrates memory-store survival across its own
context close/reopen; that evidence is distinct from standard memory sessions.

Session close cancels that session's attached jobs through
`haskokiAsyncCancel`, removes their bindings, then follows the existing model
close/release path. Close-all applies this to the selected slot. Finalize
cancels all remaining bindings, invokes `retireLiveTable` for the detached
context, frees borrowed view StablePtrs, and only then lets Standard close
its backend and store. Idle detached records survive. Never invoke
`haskokiAsyncClose` or `asyncCloseCtx` on a borrowed view: both own backend
shutdown, and the latter also retires the whole detached context.

Registry updates and handle cleanup are exception-safe. If submission or Join
allocates a private handle but binding installation cannot finish, cancel that
handle through the existing worker before unwinding. No untracked handle may
outlive a view. The C boundary retains its existing exception-to-error fence.
A public terminal error that still owns a live private handle cancels it through
the existing worker before retiring the native binding; returning an allocation
to the caller must not leave a later route able to write into it. Private
proof callers retain their existing recoverable sink-error dialogue.

## 3. Components

### 3.1 Exact signatures and ABI pin

The declarations below are verbatim from `spec/vendor/pkcs11.h`, lines
2287–2291:

```c
extern CK_RV C_AsyncComplete(CK_SESSION_HANDLE, CK_UTF8CHAR *,
                             CK_ASYNC_DATA *);
extern CK_RV C_AsyncGetID(CK_SESSION_HANDLE, CK_UTF8CHAR *, CK_ULONG *);
extern CK_RV C_AsyncJoin(CK_SESSION_HANDLE, CK_UTF8CHAR *, CK_ULONG, CK_BYTE *,
                         CK_ULONG);
```

The independent typedefs are `CK_C_AsyncComplete`, `CK_C_AsyncGetID`, and
`CK_C_AsyncJoin` at lines 2479–2483. The header is locked by
`spec/sources.lock.json` to latchset commit
`c5e61990c5621a9b955fc208644fe8145ac0a75d`; its measured SHA-256 is
`61e0b3f996fa9f095859d7d3b8e361d0b982de69fc8b6a4bf10291afbe7e24d8`.

Use these named definitions in `cbits/standard_surface.c`, with matching
declarations before the generated include in `cbits/exports.c`:

```c
CK_RV std_AsyncComplete(CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR *pFunctionName, CK_ASYNC_DATA *pResult);
CK_RV std_AsyncGetID(CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR *pFunctionName, CK_ULONG *pulID);
CK_RV std_AsyncJoin(CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR *pFunctionName, CK_ULONG ulID,
    CK_BYTE *pData, CK_ULONG ulData);
```

Add the following standard exports in `ffi/Haskoki/FFI/Standard.hs`, with
the existing generated-stub-header preference and corresponding fallback
declarations in `cbits/standard_surface.c`:

```c
unsigned long haskoki_std_async_complete(void *instance,
    unsigned long session, unsigned char *functionName, void *result);
unsigned long haskoki_std_async_get_id(void *instance,
    unsigned long session, unsigned char *functionName, unsigned long *id);
unsigned long haskoki_std_async_join(void *instance,
    unsigned long session, unsigned char *functionName, unsigned long id,
    unsigned char *data, unsigned long capacity);
```

The Haskell names are `haskokiStdAsyncComplete`, `haskokiStdAsyncGetId`,
and `haskokiStdAsyncJoin`. Scalars use `CULong`, byte pointers use
`Ptr Word8`, the result uses `Ptr AsyncData`, the id uses `Ptr CULong`,
and the instance uses `StablePtr StdInstance`. The GetID adapter converts its
id pointer to the existing worker's `Ptr Word64` only under that ABI; it must
not narrow the persistent id. Keep the supported LP64 ABI:
`CK_ASYNC_DATA` is 40 bytes with field offsets 0, 8, 16, 24, and 32.
Keep the existing independent assertions in `tests/c/layout_320.c` and add
the same assertions to the new consumer using the pinned header's real type.

### 3.2 Surface order and null-argument matrix

Each body follows the inspected `std_Sign` skeleton, now at line 1493:

1. Read `haskoki_live_interval()`; if false, return
   `CKR_CRYPTOKI_NOT_INITIALIZED` without touching caller memory.
2. Apply the structural guards below in their listed order.
3. Acquire `haskoki_state_lock()`; return a lock failure verbatim.
4. Resolve `live_std()`; if absent, unlock and return the lifecycle code.
5. Invoke its standard export with the instance and original arguments.
6. Unlock exactly once and return the export's code.

The guards use plain `CKR_ARGUMENTS_BAD` refusals. The classic Sign
`refuse_null_arg` helper terminates a classic operation slot and is not an
async argument checker; copying its side effect would erase unrelated state.
This preserves the established boundary order without importing a different
operation's termination rule.

| Entry | Structural refusal after liveness | Accepted shapes and size-query meaning |
|---|---|---|
| C_AsyncComplete | `pFunctionName == NULL`; then `pResult == NULL` for this byte-result surface | A present result is output storage. Its incoming `pValue`, `ulValue`, version, and handle fields are ignored. An incoming null `pValue` is allowed and is not a size query. No public size-query form exists here. |
| C_AsyncGetID | `pFunctionName == NULL`; then `pulID == NULL` | Present `pulID` is a scalar output; its incoming value is ignored. Neither pointer being null requests a size. |
| C_AsyncJoin | `pFunctionName == NULL`; then `pData == NULL && ulData > 0` | Present `pData` and positive capacity proceed. Null/zero and present/zero reach existing capacity validation; for an otherwise joinable byte record they return `CKR_ARGUMENTS_BAD`. Neither is a successful query. |

The Complete null-result rule covers the byte jobs exposed by this slice.
There is no newly admitted async Init/Update or other silent-result producer;
the specification's null-result examples for such functions are not a reason
to fabricate one. Handle and handle-pair sink proofs remain Haskell/proof
coverage, not a claim of public async key-generation admission.

Join's `ulData` is a capacity, not an input length to decode or copy. The
adapter must not read `pData` during Join, write a need into it, treat it as a
`CK_ASYNC_DATA`, or invent a sixth argument. Positive short capacity is
reported as `CKR_BUFFER_TOO_SMALL`, with the durable job unattached and the
buffer untouched. The private worker's need value may be inspected in Haskell
tests; it has no public destination in this ABI.

### 3.3 Function-name decoder and binding lookup

Add a bounded decoder in `ffi/Haskoki/FFI/Async.hs`:

```haskell
decodeAsyncFunctionName
  :: Ptr Word8 -> IO (Either ReturnCode JobFunction)
```

Read at most 32 bytes, one byte at a time until NUL; never read beyond the
terminator or use an unbounded `peekCString`. The byte-job selectors are the
exact ASCII strings `C_Sign` and `C_Digest`, mapping through
`jobFunctionCode` to one and two. Empty, unterminated-at-bound, non-ASCII,
case-mismatched, suffixed, and other function names return
`CKR_ARGUMENTS_BAD`. A terminator ends the name even if later allocated
bytes contain other data. Numeric spellings and `sign`/`digest` are not
public selector aliases.

The existing private mapping for key and key-pair jobs stays intact; this
decoder does not enable those public submission/output codecs. Recognizing
`C_Sign` preserves byte-job identity and wrong-function Join validation;
this slice's public producer is Digest only.

After the C structural guards and authoritative instance lookup, call
`withStdCtx` and `withStdSession` before decoding name contents. A well-shaped
call with an invalid session therefore returns
`CKR_SESSION_HANDLE_INVALID`, even with an empty or unterminated name.
Thereafter Complete/GetID look up the exact session/function binding. Absence
returns `CKR_OPERATION_NOT_INITIALIZED` without consulting a different
function's job. This also describes repeat Complete, Complete after detach,
and a selector naming Sign while only Digest is attached.

Join does not require an existing live binding: it passes the decoded
function, persistent id, actual target session, and capacity to the existing
join worker. Never infer a function from the persistent id or silently use
the first job in a session.

### 3.4 Minimal public submission and lifecycle glue

Allow `CKF_ASYNC_SESSION` in `std_OpenSession` alongside the existing serial
and read/write bits. Preserve the current pointer, missing-serial, and
unknown-bit check order. Pass explicit async intent through the standard
open-session boundary and enable the table session only after successful
session creation. Normal sessions remain synchronous.

Report the accepted async bit in `C_GetSessionInfo`; token information reports
`CKF_ASYNC_SESSION_SUPPORTED` for attached service. These are session/token
capabilities, not mechanism flags. Keep the existing mechanism catalog and
its count unchanged.

Only a full-buffer one-shot `C_Digest` on an explicit async session gains
submission. Use the existing planner and `FxDigest` work, with fixed output
width from `digestRecipeFor` / `drOutLen` in
`core/Haskoki/Recipe/Digest.hs`. Do not copy a mechanism-number/width table
into the adapter. A missing fixed-width recipe follows the existing
synchronous dialogue; it does not gain a new async recipe.

Preserve the existing C Digest structural checks, Haskell session/input
decoding, planner refusals, and staged recall. Queries, positive short
buffers, and present zero-capacity buffers take the existing synchronous
query/short dialogue and allocate no job. Its subsequent staged recall also
remains synchronous. A fresh execution plan with enough capacity calls the
existing `haskokiAsyncStart` on the borrowed view, using function code two,
an effective capacity capped at `maxOutputBytes`, and two logical polls.
Successful submission returns `CKR_PENDING`; the output bytes and length
word remain unchanged, and the registry binds that output allocation.

The native two-poll choice is explicit adapter policy; do not start reading
`async.enabled` or `async.pending_polls`, which currently apply to the
scenario runner only. No new configuration semantics enter this slice.

Permit one outstanding public Digest binding per session. A second
well-shaped Digest or a Digest Init/Update/Final attempting to use the
occupied slot returns `CKR_OPERATION_ACTIVE` and preserves that binding.
After delivery, cancellation, or successful detach, remove the binding.
Classic argument-refusal termination and session cancellation must retire any
binding for the affected digest slot before the existing model termination;
otherwise a classic failure would leave a live job pointing at invalid state.
Validate a SessionCancel request with the existing planner before retiring
bindings. Its existing flag selection, including cancel-all, determines which
bindings are canceled.

These additions are limited to exposing the existing byte-job path. Sign,
message operations, key generation, and multipart Digest do not acquire new
pending behavior. Their synchronous implementations and existing proofs stay.

### 3.5 Completion, detach, and join adapter transactions

**Complete.** After resolving a byte binding, allocate an aligned private
40-byte result struct, initialize its destination and capacity from the
binding, and never copy those inputs from the public result. Call the
existing poll worker once:

- `CKR_PENDING`: return with the public struct and bound bytes untouched.
- Ready `CKR_OK`: call the existing Complete worker with the private struct.
  On successful delivery, copy its returned length and handles into the
  public struct, set version zero, and return the bound address in
  `pValue`. Remove the registry binding after the worker releases its handle.
- Terminal worker error: retire a handle that the worker has released,
  remove its binding, and return the bound address in public `pValue`.
  Leave the other public fields and payload untouched.
- A private short result reports `CKR_BUFFER_TOO_SMALL`, returns the bound
  address and need in the public struct, and retains the job and binding.
  It is a defensive condition: successful fixed-width submission and Join
  already require adequate capacity. It is not a public rebind/query path.
  A conforming admitted Digest reaching it is an adapter defect that blocks
  acceptance; do not enlarge the bound capacity behind the caller's back.

Use live-set membership, not a dereference of a possibly freed job token,
to reconcile terminal handle release. A refusal before a binding is resolved
does not fabricate or overwrite `pValue`. Unknown-function, missing-binding,
and structural refusals do not tick or cancel another job.

**GetID.** Pass the resolved private handle and numeric function to
`haskokiAsyncGetId`. The export writes the scalar id only after durability
and revocation. On success discard the old output address and registry
binding before releasing the C lock. On a worker refusal keep the binding;
retain the worker's existing id-output convention, including zeroing for
no-store, wrong-function, unsaveable, and durable-store failures. Earlier
structural/session/name/missing-binding refusals leave the id sentinel intact.

**Join.** Supply private handle and need slots to `haskokiAsyncJoin`; never
expose their addresses. A returned `CKR_PENDING` with a live handle means
attachment succeeded. Install the new session/function/output binding and
return public `CKR_OK`. Other codes pass through unchanged and install
nothing. Guard against an already occupied target function binding with
`CKR_OPERATION_ACTIVE` before asking the worker to allocate a second handle.
The worker's persistent-id attachment gate still decides competing joins of
the same id, including joins from another session.

Joining a digest recipe requires a fresh matching `C_DigestInit` on the
target session because `replanRecipe` requires that operation state today.
The adapter neither initializes it implicitly nor restores an old session.
No poll, backend execution, or payload write occurs during Join.

### 3.6 Table registration and deterministic generation

Add exactly these mappings to `routed320` in `scripts/generate-abi.py`,
preserving its existing KEM mappings:

```python
"C_AsyncComplete": "std_AsyncComplete",
"C_AsyncGetID": "std_AsyncGetID",
"C_AsyncJoin": "std_AsyncJoin",
```

During implementation run `python3 scripts/generate-abi.py`. The generated
`cbits/abi_stubs.inc` must lose all three `x32_C_Async*` bodies and assign
the three `std_*` functions in `HASKOKI_FILL_320_NEW`.
Do not edit the generated include manually.

`cbits/abi_generated.h`, `spec/abi-inventory.json`, and
`spec/abi-reconciliation.json` remain byte-identical. A second generation
produces no diff. Keep ordinals, header pins, and counts 68/92/92/104.
The older three interfaces have no async slots; do not enlarge them or read
a 3.2 tail through an older table. The already-routed message entries and
other surviving stubs keep their current assignments.

### 3.7 Consumer, contracts, and documentation

Add `tests/c/async_routed.c` using `consumer_roundtrip.c` configuration,
`dlopen`, result accounting, canary, and cleanup conventions and
`message_routed.c`'s explicit newer-interface discovery. It includes only
`spec/vendor/pkcs11.h` for Cryptoki types. Resolve discovery symbols, then
call all tested async operations through the returned 3.2 table. No private
trampoline may substitute for a happy-path submission, Complete, GetID, or
Join assertion.

Both `scripts/test-consumers.sh` and `scripts/test-proxy-parity.sh` currently
enumerate `consumer_*.c` plus `message_routed.c`. Add `async_routed.c`
explicitly once, require its existence and exactly one occurrence, retain
stable sorting, and run the independence guard over the complete list.
Compile with the existing C11, optimization, debug, warning-as-error,
`-Ispec/vendor`, `-ldl`, and `-lpthread` options. The program's normal
invocation remains `async_routed <module>`; it coordinates its restart child
modes itself so both scripts execute the full direct proof.

In `scripts/generate-function-contracts.py`, append this evidence tuple to
each of the three existing `PLANNED` entries:

```python
("test-consumers.sh", "tests/c/async_routed.c")
```

Also cite the existing model/engine suite files receiving the adapter tests
in section 5. Preserve the current `haskoki-export:haskoki_hs_async_*` entry
values, earlier evidence, ordinals, layouts, acceptance ids, and
`planned-with-behavior` classification. Regenerate with
`python3 scripts/generate-function-contracts.py`; the JSON gains real
evidence paths without changing its 104-row denominator or its seventy
planned, thirty-two unsupported, and two not-applicable classifications.
Do not hand-edit `spec/function-contracts.json` or replace function names
with duplicate rows for test legs.

Update `cbits/async_trampoline.h`'s later-routing note and
`cbits/exports.c`'s route description to distinguish the continuing private
proof API from the new public adapter. Update `docs/demo-walkthrough.md`
with the three live table entries, Digest-only public admission, SQLite
detached/restart proof, and unchanged mechanism coverage.
`docs/operations-notes.md` must describe public result ownership, Join's
by-value capacity, memory/no-store behavior, and the proxy limitation.
Add a scope clarification beside the existing proofs in
`docs/async-config-design.md`; leave D1-D12 unchanged.
Update the two oracle records as specified below.

## 4. Error handling

### 4.1 Boundary precedence

For all three entries the established chain is
`CKR_CRYPTOKI_NOT_INITIALIZED` → structural arguments → state lock and
authoritative instance resolution → standard session lookup → function-name
decode → binding/worker behavior. The initial liveness peek does not hold
the lock; retain the existing race behavior rather than adding a second
precedence algorithm. Lock failure is returned verbatim. Every acquired
lock is released once, including the absent-instance arm.

Do not promote name-content validation or Join capacity validation into the
C structural-guard stage. In particular:

| Entry | Concrete precedence assertion |
|---|---|
| C_AsyncComplete | Before init, null name/result returns the lifecycle code. While live, null result with an invalid session returns arguments bad; a present result with an invalid session and an empty name returns session invalid. With a valid session and `C_Digest` but no binding, return operation not initialized. |
| C_AsyncGetID | Before init, null id pointer returns the lifecycle code. While live, null id pointer beats an invalid session. With valid pointers, invalid session beats malformed name contents. A valid selector without an attached job leaves the id unchanged and returns operation not initialized. |
| C_AsyncJoin | Before init, null name or null/nonzero buffer returns the lifecycle code. While live those shapes beat an invalid session. A well-shaped invalid session beats name decode and capacity. For a valid free target, a valid selector and unknown id with zero capacity reaches the worker's unknown-id result before its capacity test. |

Use full `CKR_` names in the implementation's assertions. These prose
abbreviations do not establish new return-code aliases.

### 4.2 Existing worker ordering and typed outcomes

For an attached job, Complete checks live-handle/function identity before
delivery. Pending, wrong-function, query, and short-buffer paths in the
private worker keep their existing semantics. The public wrapper must not
forward an uninitialized public struct as that private worker's sink.

GetID's existing worker checks its output pointer, live job, store presence,
and numeric function decode. Inside `detachUnder`, an opaque mark is
consumed before the job-function and execution-state checks. It then builds
a pointer-free recipe/result, commits it, and revokes under the existing
lease. An unsaveable job returns `CKR_STATE_UNSAVEABLE`, not an exception or
serialized native address, and retains its live attachment. Store failures
return `CKR_GENERAL_ERROR`; a missing home token returns
`CKR_TOKEN_NOT_PRESENT`. Ambiguous commits retain the existing reload and
reconciliation decision.

Join's actual runtime order matters: store lookup and id selection;
attachment/terminal gate; durable function identity; token lookup and
generation; target session/slot and async eligibility; authentication;
record-body decode; capacity; recipe replay; table admission and attachment.
This is the order in the bodies of `joinJob`, `joinRecord`, and
`joinValidated`, not a reordered list inferred from their comments.

| Join condition after the applicable earlier checks | Existing result |
|---|---|
| Unknown id, unknown record/recipe version, or stale token generation | `CKR_SAVED_STATE_INVALID` |
| Known idle id for another function | `CKR_ARGUMENTS_BAD` |
| Same persistent id already attached | `CKR_OPERATION_ACTIVE` |
| Delivered persistent record | `CKR_ARGUMENTS_BAD` |
| Canceled persistent record | `CKR_FUNCTION_CANCELED` |
| Failed persistent record or store failure | `CKR_GENERAL_ERROR` |
| Invalid/wrong-slot target session | `CKR_SESSION_HANDLE_INVALID` |
| Target session not enabled for async | `CKR_SESSION_ASYNC_NOT_SUPPORTED` |
| Existing token/session authentication check refuses | `CKR_USER_NOT_LOGGED_IN` |
| Matching operation not initialized, or replay does not reproduce the effect | `CKR_OPERATION_NOT_INITIALIZED` |
| Capacity zero or above `maxOutputBytes` | `CKR_ARGUMENTS_BAD` |
| Positive capacity smaller than need | `CKR_BUFFER_TOO_SMALL` |
| Live table at capacity | `CKR_HOST_MEMORY` |

An active id therefore wins over a wrong decoded function or short capacity
on a free target session. An unknown id wins over a zero capacity. Pin these
combined-error cases; do not flatten them to “arguments always first.”

For a pending record the need is its original effective attached capacity.
For a ready record it is the held result's byte length. Thus a pending digest
submitted with capacity 64 can refuse a Join of capacity 32 even though its
eventual SHA-256 result is 32 bytes. Preserve this conservative existing rule.

### 4.3 Cancellation, revocation, and durable limits

Keep the job lease and `stepJob` transitions unchanged. Countdown/claim
preserve the epoch; holding a result, delivering, failing, and canceling each
advance it. Query/short/refusal paths do not advance it. Successful detach
removes the job from the source table; no later source call dereferences its
freed token or writes its old buffer.

Cancel-first retires the public binding; a later Complete sees no operation.
Complete-first delivers once; a later cancellation cannot undo bytes.
After GetID, canceling or closing the source session must not cancel the
idle durable record. After Join, cancellation targets the new attachment
through `cancelJoined`, and later Join observes its terminal fate.

The existing `completeJoined` records delivery after payload delivery.
Its `jcMarkError` does not reverse delivered bytes; the private export returns
the completion verdict and the in-memory attachment remains terminal.
Do not claim crash-safe exactly-once delivery across a failed durable mark.
Keep that existing limit visible, with fault-injection evidence separate from
successful-store restart evidence. A change to that policy requires another
scope decision, not a routing workaround.

## 5. Testing

### 5.1 Haskell additions and retained proofs

Extend the already-wired `StandardSurfaceSpec`, `AsyncEngineSpec`, and
`DetachedEngineSpec` suites. `FfiAsyncSpec` currently tests acquisition and
asynchronous exceptions during open; its name does not make it the async
operation decoder suite. Leave those acquisition cases intact.

| Case | Required assertions |
|---|---|
| `caseAsyncFunctionNames` | Exact Sign/Digest names map to existing codes. Empty, case change, suffix, non-ASCII, numeric name, unsupported key name, and 32 non-NUL bytes refuse. A terminator at the final permitted byte is bounded; stop at the first NUL. |
| `caseAsyncSurfaceSessionOrder` | Structural guards, invalid session versus malformed name, and missing exact binding match section 4 without ticking a different job. |
| `caseAsyncBorrowedOwnership` | Views use the actual standard session and shared environment/backend/table. Closing one view cancels only its jobs; backend closes once at instance shutdown. Distinct sessions cannot use one another's private handles. |
| `caseAsyncPublicCompletion` | Private version one becomes public version zero; public incoming result fields never choose the destination. Pending changes no byte, ready writes the bound allocation once, terminal error returns its address, and the registry removes a freed handle without dereference. |
| `caseAsyncAdmissionWidths` | Query/short/staged recall allocate no job; fixed recipe widths drive adequate-buffer admission; input is owned; normal sessions stay synchronous; the ninth live job refuses without a binding leak. |
| `caseAsyncJoinBoundary` | Private pending becomes public success only after binding installation. Unknown, active, delivered, canceled, wrong-function, zero/oversize/short capacity and uninitialized-target cases retain exact codes and registry/store state. |
| `caseAsyncReadyJoinCapacity` | A ready record checks actual held length; a pending record checks original capacity. Short/refusal creates no handle or binding, and the adequate retry succeeds. |
| `caseAsyncOpaqueSurface` | Mark a live adapter job opaque using the existing injection API, invoke the new standard GetID worker, and require unsaveable, id zero, no durable record, unchanged binding, and later exact completion. No new public fault-control API is added. |
| `caseAsyncEpochSurface` | Initial epoch zero; first of two polls preserves it; ready advances once; delivery advances once more. Pending cancellation advances once, and query/short/wrong-function refusals leave epoch and delivery count unchanged. |
| `caseAsyncCleanupSurface` | SessionCancel selection, classic slot termination, close-one, close-all, and finalize retire only the correct bindings, free handles once, and retain idle detached records. Cover cancellation winning and completion winning separately. |

Use the existing engine environment lock for tests that touch configuration.
Use deterministic ordering or barriers for arbitration; no timing sleeps.
Keep original private null-value query and short-completion tests unchanged:
those are valid proof-API dialogues even though public Complete has no query.

Retain `tests/c/async_attached.c`, `async_detached.c`, and
`async_restart.c`, driven by `scripts/test-async-attached.sh` and
`scripts/test-async-detached.sh`. Their existing private result version,
pending Join, handle-liveness, memory-store, guard-page, and two-process
assertions continue to protect the unchanged workers.

### 5.2 New native consumer fixture

The consumer discovers 3.2, checks its version and all three non-null slots,
and uses no larger-layout cast on older tables. Discovery before initialization
remains legal. It runs ordinary-session control calls and explicit async
sessions independently.

Use real OpenSSL execution, no synthetic fallback, trace off, and a fresh
SQLite path in the existing `storage.kind/path` configuration for the
detached tests. A separate memory configuration covers attached success and
the no-store refusal. Discover the token-present home slot instead of
assuming a public session handle.

The fixed byte oracle is SHA-256 of the three bytes `abc`:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

Open with serial, read/write, and async flags; `C_DigestInit` with
`CKM_SHA256` and null/zero parameters returns `CKR_OK`.
A fresh full-capacity `C_Digest` binds the supplied output and returns
`CKR_PENDING`. Overwrite the input after submission to prove ownership;
the final digest must still match the fixed bytes. The same sequence without
the async flag returns the existing synchronous answer and creates no binding.

Use sentinel id/length/struct bytes, buffer prefix and tail canaries, and
a valid address for present-zero buffers. Check the entire struct on pending
and early refusal, not only `ulValue`. Stable transcript labels have the
form `async:C_AsyncComplete/pending/3.2`; compare return codes and exact
bytes/lengths, without using numeric session ids, private handles, or addresses
as transcript identities.

### 5.3 Concrete per-entry legs

Every entry runs before init and after finalize, including each structural
null shape combined with that lifecycle state. While live, repeat each C guard
with both a valid and an invalid session. Require lifecycle first, then
structural arguments, and unchanged outputs. Well-shaped invalid-session calls
require `CKR_SESSION_HANDLE_INVALID`.

| Entry | Happy and progress legs | Refusal and preservation legs | Size-related legs |
|---|---|---|---|
| C_AsyncComplete | Submit capacity 32; first Complete is pending with the whole result and output intact; second returns exact digest, version zero, original buffer pointer, length 32, and zero object fields. | Null name/result; empty, malformed, and unsupported name; valid Sign selector with only Digest attached returns operation not initialized; another session cannot complete it. Repeat Complete returns operation not initialized. Two simultaneous completers of a one-poll-remaining job deliver once; loser sees no operation. | Initialize public result with null/zero fields, then with a different valid buffer and capacity zero in a separate run. Both must still deliver into the original bound buffer; neither is a query or rebind. Original submission null-output query reports 32 with no job; short capacities zero and 31 report buffer too small with no job. |
| C_AsyncGetID | Detach a pending SQLite-backed Digest, require success and a nonzero scalar id, then Join and complete through the table. | Null name/id pointer, malformed name, absent exact binding, invalid session, second GetID after detach, and GetID after delivery. Early refusals retain the id sentinel. A resolved attached job in standard memory mode returns general error, zeros id, and remains completable. | No size-query parameter exists. Null id pointer refuses without detaching; a present scalar initialized to different values is overwritten only as specified. The original bound output remains entirely unchanged on successful detach. |
| C_AsyncJoin | On a fresh async session with matching DigestInit, attach the detached id to a new 32-byte buffer; require public success and unchanged bytes, then pending/progress and exact completion into that buffer. | Unknown id returns saved-state invalid; idle digest id with Sign selector returns arguments bad; already attached id returns operation active; delivered id returns arguments bad. Non-async target returns session-async-not-supported; missing matching DigestInit returns operation-not-initialized. Refusals create no attachment, so a valid retry succeeds. | Null/nonzero is arguments bad. Null/zero and present/zero with an otherwise valid id are arguments bad. Capacities one and 31 are buffer-too-small; capacity 32 succeeds. Input capacity is by value and no public need is written. A separate original-capacity-64 pending record refuses Join capacity 32 and accepts 64. |

Add combined-error Join legs on a free target: unknown id plus zero capacity
returns `CKR_SAVED_STATE_INVALID`; active id plus Sign selector or capacity
one returns `CKR_OPERATION_ACTIVE`. On an already occupied target, a second
attachment request returns `CKR_OPERATION_ACTIVE` without replacing its
buffer. Prove all short/argument refusals leave a retryable durable record.

For cancellation, submit then call `C_SessionCancel` with the Digest bit:
Complete sees no operation and writes nothing. On a joined job, cancel and
require a later Join of its id to return `CKR_FUNCTION_CANCELED`.
Repeat with completion winning before cancellation and verify no second write.
A cancellation of an unrelated operation selector preserves the digest job.

### 5.4 Guard page and restart through table slots

For the revoke proof, submit into an `mmap` allocation, detach through
`C_AsyncGetID`, then make the old allocation inaccessible with
`mprotect(PROT_NONE)`. Finalize, reinitialize on the same SQLite path,
open a fresh async session, initialize Digest, Join into a different live
allocation, and complete through the table. Re-enable read access to the old
allocation and verify its entire canary. Any use of that allocation while
inaccessible terminates the consumer and fails its driver.

For restart, the normal consumer launches two separately executed child
processes. The first initializes, submits, detaches, records only the scalar
id for handoff, finalizes, and exits without completing. It also leaves one
non-detached job for finalize to cancel. The second opens the same database,
creates its own session and buffers, initializes Digest, joins the id, and
checks exact delivery. A never-issued id is invalid; a subsequent process
cannot rejoin the delivered id. Do not compare native pointer values across
processes; fresh-process ownership and successful reconstruction are the proof.

The consumer owns and cleans its temporary directory, database, configuration,
and children. Print separate labels for attached completion, revocation, and
restart so one cannot stand in for the others.

### 5.5 Proxy disposition at the actual pin

The canonical proxy source pin is
`a48b60ba54b0163f4999c1e4fc0514bf7dc01681`. The files currently installed
under `/opt/pkcs11-proxy-ng` match the script's canonical hashes:

| Artifact | Measured SHA-256 |
|---|---|
| `pkcs11-proxy-ng` | `260cb245981561291eab4d29a16cb6a4d6f00dca3431f3d583d35364fab0c9e5` |
| `libpkcs11_proxy_ng_shim.so` | `8ea85073ce8436ebdc8ee99bce99e70a6d8c34473c28b5a45567c8a26aba1690` |

Read-only `git show` of that exact commit in the local proxy repository shows
that `crates/shim/src/dispatch/general/async_ops.rs` unconditionally returns
`CKR_STATE_UNSAVEABLE` from GetID and `CKR_SAVED_STATE_INVALID` from Join.
Its Complete RPC does not send the caller's result-buffer capacity and its
successful response copies only the smaller of response length and caller
capacity while returning success. This cannot preserve the binding, sizing,
and durable lifecycle required above. The pinned shim source SHA-256 is
`cf1239e40f482755006bb1d1988b9d083f8f36312ad4d9543160e9c31c40ca72`.
This is a source finding, not a proxy execution result.

Therefore `async_routed` requires an explicit `DIRECT-ONLY` disposition
for this proxy pin. Follow the existing message scenario's mechanism, whose
filed issue is [proxy issue 23](https://github.com/mingulov/pkcs11-proxy-ng/issues/23).
Do not reuse that message issue as an async transport filing.

During implementation, reproduce the fixed GetID/Join refusals with the pinned
pair and file a distinct issue in `mingulov/pkcs11-proxy-ng`, titled
“Async transport cannot preserve detached jobs and output bindings”.
Include the pin and hashes, exact table calls and return codes, direct
happy-path transcript, fixed refusal source locations, and Complete's
capacity/ownership mismatch. Record its real URL and disposition in
`docs/pkcs11-check-upstream-issues.md` under an explicitly proxy-scoped entry.
This draft does not claim that issue has been filed.

Only after the filing exists, add `async_routed` with that URL to the
script's existing `DIRECT_ONLY` list. Its direct leg must execute and pass;
the script must emit the explicit disposition and issue URL. Do not normalize
away new async lines, count an excluded proxied leg as equivalent coverage,
rebuild the pinned proxy, or weaken any remaining scenario's parity checks.
Lack of a real filing blocks that exclusion's acceptance.

### 5.6 Oracle source pins and coverage limits

The read-only oracle tree is
`/tmp/pkcs11-ws/pkcs11-check-0.2.2rc2`; its package declares version
`0.2.2rc2`. Scanning all Python files under
`src/pkcs11_check/testcases` for async references finds the following five
files. Counts are AST counts of every `test_` definition in each entire file,
including methods, not just async tests and not parametrized execution totals.

| Path relative to testcases | All test definitions | Async-specific test definitions | File SHA-256 |
|---|---:|---:|---|
| `test_remaining_gaps.py` | 29 | 4 | `56ca76211694ac5c8fe8142cc550d8415d91ee39da830240db0cf0a5c9a9a33f` |
| `ckr/test_ckr_v32_raw.py` | 8 | 1 | `278d32b6509e556746c4fb3ef688315c1f21c701cdc8a2bfddcaa7bda3eafcb1` |
| `_probes/ckr_v32_raw.py` | 0 | 0 | `3167748a0ff6336d457b36f442f3156c8c6cc71892c70e58a16f70b89bb5819e` |
| `ckr/_ckr_spec.py` | 0 | 0 | `79c590d8f81c0f6bbf0b437e19a234e91411a6dd684dd98741a2210f8ca03136` |
| `ckr/_ckr_spec_tables.py` | 0 | 0 | `3df59974adfcb4e3112db1851676ce7b11f91c34d3c001458c38a5096d2aaba2` |

Use the same pin method as the message-routing plan: parse file bytes with
`ast.parse`; walk the tree; count `ast.FunctionDef` and
`ast.AsyncFunctionDef` whose names begin `test_`; hash the original bytes
with SHA-256. Do not import test modules or run pytest to obtain this count.

The deterministic full source pin, over 519 Python files under `src`, is
`b7b5327c4294a892fcf21f351717bb240b2505621ce842c182b33cf6685bad23`.
For each path in sorted order, hash its oracle-relative path encoded as UTF-8,
a NUL byte, its raw content, and another NUL byte. The release name plus this
digest is the source revision evidence; do not invent a Git revision for a
release tree.

The four `TestAsyncLifecycle` tests check availability and three no-active
calls. They pass null function names; their helper checks only whether the
return value is defined. They never submit or successfully finish a job.
Their prose incorrectly attributes the async slots to 3.0; the pinned table
places them in 3.2 only. Neither a defined refusal nor an availability pass
proves routed async success.

The raw CKR test `test_async_get_id_no_operation` expects
`CKR_OPERATION_NOT_INITIALIZED`, but its child probe passes a zero-filled
256-byte allocation as the function-name argument and labels the scalar id
output as a length. That is an empty selector, not `C_Digest`. The new
decoder returns `CKR_ARGUMENTS_BAD` for that input. Record a minimal
independent comparison: empty selector gives arguments bad; `C_Digest` with
no job gives operation not initialized. Do not relax name validation to make
the malformed oracle probe pass.

The expectation tables contain five async conditions, imported by
`_ckr_spec.py`; those declarations are not five additional executable tests.
No inspected oracle case proves pending progress, bytes, ownership revocation,
restart, or competing joins. Those obligations belong to the new independent
consumer and retained Haskell proofs.

### 5.7 Orchestrator verification and evidence

The following commands are subsequent orchestrator work. None is run while
drafting this file.

1. Run the focused Haskell additions and `scripts/test-consumers.sh` inside
   the existing `haskoki-dev:ghc-9.10.3` environment. Require every consumer
   leg above, including its separately executed restart children.
2. Run the retained attached and detached proof scripts. Their private API
   expectations remain unchanged.
3. Run
   `HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng scripts/test-proxy-parity.sh`
   in the existing pinned container arrangement. Require direct async success,
   the filed-issue-backed disposition, and normal parity for all eligible
   scenarios.
4. On the host run
   `HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng bash scripts/run-gates.sh`.
   Require all eighteen static gates, forced build, all Cabal suites, and
   release evidence. The fourteen-driver manifest already includes both
   consumer scripts and both async proof scripts, followed by release build
   and installation checks; no extra driver is necessary for this design.
5. Against that revision's freshly built release bundle, run
   `bash /tmp/pkcs11-ws/run-lane-rc2.sh fast`, inspect its findings, then run
   `bash /tmp/pkcs11-ws/run-lane-rc2.sh kat` and inspect its findings.

For each stage record source revision, command, exit status, toolchain image,
module/bundle hashes, proxy pin where used, oracle source pin, and log/result
paths and hashes. Record source-definition counts separately from collected,
executed, skipped, and classified cases. Preserve previous lane artifacts
before the wrapper overwrites its output paths.

Inspect `/tmp/pkcs11-ws/out-rc2/fast/pkcs11-fast-results.json` and
`/tmp/pkcs11-ws/out-rc2/kat/pkcs11-kat-results.json`, with each lane's
`trace.jsonl`. The wrapper accepts oracle test exit one as reported findings;
its own zero exit does not establish a clean lane.

Update `docs/pkcs11-oracle-triage.md` for every newly exposed result:
exact node/parameters, input shape, actual and expected codes/bytes, independent
reproduction, applicable source, and provider/oracle/capability classification.
For an incorrect oracle expectation, file upstream and put the actual URL,
status, reproduction, and version pin in
`docs/pkcs11-check-upstream-issues.md`. Keep the malformed GetID probe and
the incorrect version attribution visible until dispositioned. Do not edit
the pinned oracle tree, widen success sets, or add unconditional skips.
A provider defect requiring runtime, detached-policy, or mechanism changes
blocks acceptance of this scope and must be reported separately.

## 6. Acceptance

Acceptance requires evidence from the final implementation revision for all
of the following:

- All three generated stub bodies are absent, the three 3.2 assignments point
  to the exact `std_*` signatures, and ABI counts, ordinals, older layouts,
  message routes, and mechanism artifacts remain unchanged.
- A native consumer creates an actual standard async session, submits Digest,
  and reaches all three table slots with live behavior. Valid supported
  sequences never return `CKR_FUNCTION_NOT_SUPPORTED`; a trampoline-only
  setup or a function-pointer presence check cannot satisfy this item.
- Structural/lifecycle/session/name precedence, pending canaries, public
  pointer/version translation, original query/short submission, scalar GetID,
  conservative Join capacity, typed refusals, retry preservation, cancellation,
  and exactly-once delivery pass their concrete legs.
- The old allocation remains inaccessible throughout the routed revoke/rejoin
  interval, and separately executed SQLite recovery delivers into fresh
  caller storage. No private handle or address is a restart identity.
- The scheduler and detached runtime logic retain their behavior, including
  unsaveable outcomes, cancellation epochs, first-attachment policy, and
  durable-mark limitations. Existing Haskell and trampoline proofs pass.
- All eighteen gates, forced build, Cabal suites, consumer/evidence drivers,
  release build, and installation checks pass. Proxy evidence records direct
  success plus the explicit async exclusion and its distinct upstream issue;
  it makes no async transport-parity claim for the pinned proxy.
- Fast then kat are clean under an explicit findings review: no unexplained
  new findings, crashes, setup errors, regressions, or unresolved provider
  defects in these paths. Oracle defects remain visible with precise triage
  and actual upstream filings rather than being counted as provider success.
- All three contracts remain `planned-with-behavior` and gain the new
  consumer evidence through their generator. Documentation states the public
  admission/storage boundaries, and both oracle records carry the new
  dispositions. D1-D12 remain outside the implementation.

Routing evidence is function-level coverage of the specified byte-job surface,
not a general asynchronous-operation or PKCS #11 conformance claim.

