# Notifications and slot-event design

Design proposal for the Notifications/slot-events slice. Source inspection:
`019f8f09dbff89b6562937b16f99ad8b5c4446b5` (Async slice complete),
2026-10-01. The requested filename retains the slice date, 2026-09-30.
Repository source references below are relative to this revision; external
source pins are given in sections 2.2, 5.5, and 5.6.

This is a source-based gap analysis and an implementation contract. No build,
test suite, consumer, race probe, proxy, oracle lane, or acceptance run was
executed for it. Statements about future results are requirements, not results.
Only this specification is delivered; the final section is a task breakdown
proposal for the plan worker, not an executed implementation plan.

## 1. Goal and non-goals

Make public slot-event delivery describe the same token presence that the
standard slot/session surface serves. Specify blocking and polling waits,
finalize arbitration, multiple waiters, stable slot identity, callback
ownership, and native `CK_NOTIFY` behavior through the real 2.40, 3.0, 3.1,
and 3.2 tables.

The required result has two distinct notification channels:

- `C_WaitForSlotEvent` consumes an indication that a configured slot changed.
  The application queries current slot information after receiving the slot ID.
- A session's `CK_NOTIFY` is an application function pointer, with its original
  `pApplication`. This slice adds one precisely bounded surrender producer:
  an admitted synchronous, fresh, one-shot `C_Digest` execution. It does not
  translate insertion/removal into surrender callbacks.

Surrender callbacks are optional in PKCS#11. Selecting this producer is a
Haskoki product contract, not a claim that providers must notify on Digest or
that the current acceptance-without-invocation behavior is nonconformant.
The selection makes native callback delivery and cancellation independently
testable without introducing another cryptographic mechanism or scheduler.

Non-goals: hardware/device monitoring; filesystem/database hotplug detection;
dynamic slot creation or deletion within an initialization interval; a network
control service; callback subscriptions across processes; an event audit log;
one event per edge at the public ABI; OTP mechanisms or `CKN_OTP_CHANGED`
production; vendor-defined callback values; callbacks from background threads;
new callback configuration keys; surrender inside an OpenSSL operation;
general surrender coverage of every cryptographic function; and changes to
the Async slice's execution, persistence, capacity, or competing-join policy.
`CKF_ASYNC_SESSION` remains distinct from obsolete parallel sessions.

The minimum integration necessarily touches lifecycle, control, slot queries,
session cleanup, and the Digest adapter during later implementation. A wait
wrapper alone cannot repair the disconnected state described in section 2.1.
Memory/SQLite formats and ordinary object persistence are not redesigned.
Existing private proof APIs remain distinguishable from standard-table claims.

## 2. Architecture

### 2.1 Starting-revision gap analysis

The following are inspected source facts, not executed evidence. Each quote
is a small identifying source fragment; ranges identify the supporting body.
`Gxx` identifiers are used by the acceptance and task tables.

| Gap / retained behavior | File:line evidence and consequence |
|---|---|
| **G01 — Wait already routes; it is not an unsupported stub.** | `cbits/function_tables.c:941-955` calls `haskoki_instance_wait_for_slot_event`; `:1153` assigns `on_WaitForSlotEvent`. `cbits/abi_generated.h:105` includes `M(C_WaitForSlotEvent)` in the legacy map; `cbits/exports.c:11-14` describes those 68 entries being re-homed by name. The common legacy body serves all four interfaces. `scripts/generate-abi.py:167` pins its ordinal to 68. |
| **G02 — Public wait validation is incomplete.** | `cbits/function_tables.c:943-949` contains `(void)r` and checks only liveness and null `pSlot`. `ffi/Haskoki/FFI/Instance.hs:261-275` chooses polling with `flags .&. ckfDontBlock /= 0`. Non-null reserved pointers and unknown flag bits are not rejected. The foreign export writes `pSlot` only on `WaitEvent`; normal no-event/finalized outcomes preserve it. |
| **G03 — Public waits reach the control instance, without the C state lock.** | `cbits/control_entry.c:71-95` publishes an atomic root and uses `atomic_exchange_explicit` on shutdown; `:103-111` loads it and calls `haskoki_wait_for_slot_event`. `Instance.hs:155-156,258-275` reaches `registryEvents`, then `tryWaitSlotEvent` or `waitSlotEvent`. This is the full C-to-FFI-to-runtime wait path. |
| **G04 — The runtime has real STM blocking and polling, but edge FIFO semantics.** | `src/Haskoki/Runtime/Events.hs:102-138` stores `Seq SlotEvent`, appends with `q Seq.|> ev`, and applies `DropOldest`/`DropNewest`. `:156-182` consumes one head transactionally; empty blocking uses `retry`, polling returns `WaitNoEvent`. One queued edge can be consumed by one competing transaction, not delivered to every waiter. The FIFO/drop policy is not the specified per-slot pending-flag abstraction. |
| **G05 — Finalization currently permits draining pending edges.** | `Events.hs:158-167,175-182` checks the queue before `eqFinalized`; `:185-186` only writes that flag. Thus a retained queue reference can deliver queued events after finalization until drained, notwithstanding the module's “wakes ALL” summary at `:7-8`. `waitCode` at `:149-152` correctly maps empty finalized waits to `0x190`. |
| **G06 — The historical resolve/free race already has a lifetime fix.** | `Instance.hs:119-145` defines `InstanceCell = IORef (Maybe Instance)` and documents the retained cell; `:222-239` atomically takes it to `Nothing`, finalizes events, and never frees the StablePtr. `:247-256` rereads the cell before use. `control_entry.c:16-28,71-95` agrees with this implementation. One empty cell/StablePtr remains rooted per interval; eliminating that retention is not part of this slice. The “plain pointer” characterization in `tests/c/finalize_wait_race_probe.c:3-13` describes older code, not this HEAD. |
| **G07 — Init constructs two different state owners.** | `function_tables.c:564-588` separately opens `haskoki_instance_open_fresh()` and `haskoki_std_open_fresh()`. `Instance.hs:171-194` resolves config and creates an empty registry plus its own async table. `ffi/Haskoki/FFI/Standard.hs:570-576,623-660` independently resolves config, opens model/backend/store, and constructs `newAsyncTable 8`. `StdInstance` at `:487-497` has no event/presence service. There is no standard-session affinity binding to the control registry in `:1329-1379`. |
| **G08 — Controls generate events in that separate registry.** | `Runtime/Control.hs:377-419` calls `insertToken (csRegistry st)` / `removeToken (csRegistry st)`. It accepts any slot number in `0..0xffffffff`, not just the standard catalog. `Events.hs:265-281` changes presence/generation and subsequently posts an insertion; `:294-321` changes presence to false **before** job cancellation, then posts removal. The “quiesce FIRST” comment at `:289-293` is not the actual mutation order. There is no transition lock spanning the state change and later post, so concurrent insert/remove can reorder posts; cancellation uses this registry's table/affinity, not Standard's bindings. |
| **G09 — Slot listing currently has no absent configured-slot state.** | `Standard.hs:1284-1313` starts with `Map.keys (mTokenAuth m)` and filters those same keys with `lookupTokenAuth m slot /= Nothing`. Both boolean choices consequently return the same seated catalog. `:457-466` defines the configured index-to-token mapping; `:696-767` seats/restores all configured tokens. The full list cannot retain an empty configured slot if auth-row membership is used as slot existence. |
| **G10 — Slot info is fixed-present and non-removable.** | `standard_surface.c:456-493` calls `haskoki_std_slot_present`, then sets `tmp.flags = CKF_TOKEN_PRESENT`. `Standard.hs:1560-1566` treats auth-row membership as valid slot versus `CKR_SLOT_ID_INVALID`. A simulated absence cannot change these flags. Unknown-slot precedence before null info is explicit in `standard_surface.c:475-481`; preserve it as specified in section 4. |
| **G11 — Token admission likewise has no distinct known-empty case.** | `Standard.hs:1334-1337,1508-1514,1538-1547` returns `ckrSlotIdInvalid` when the auth row is absent for OpenSession/token info. The core can already deny missing token auth (`core/Haskoki/Transition.hs:443-457`), but the C adapter short-circuits that distinction. `standard_surface.c:528-540` checks token label/live state before null token-info output. |
| **G12 — Native callback arguments are accepted and discarded.** | `standard_surface.c:674-720` has `(void)pApplication` and `(void)Notify`; the foreign call passes only slot, read-only, async intent, and session output. Its serial-bit and unknown-bit guards are at `:699-703`. Acceptance is supported; callback association/invocation is not. `docs/operations-notes.md:38-47` states the same limitation. |
| **G13 — Runtime callback proofs are not a CK_NOTIFY bridge.** | `Events.hs:219-222` uses `CallbackCtx -> SessionId -> String -> IO ()`, rather than a numeric notification, application pointer, and `CK_RV`. `:338-364` registers lists and dispatches under one `trNotifyLock`; close deletes under that lock. `:370-385` exposes a private snapshot and a total synthetic `requestGatedCall` refusal. Those functions do not guard an arbitrary C callback reentering a function table. Dispatch contains no exception fence and one throwing callback aborts that dispatch. `tests/model/EventsSpec.hs:164-199` explicitly invokes those Haskell helpers with strings. |
| **G14 — Removal cleanup must use the standard session owner.** | `Standard.hs:1383-1405` cancels jobs, publishes close, clears cursors, and frees borrowed views; `:1410-1431` closes all sessions but discards each `publishCommit` result. `:780-815` owns final async/view/backend/store teardown. Core close destroys session-owned objects and drains digest streams (`Transition.hs:469-509`); token-object bindings need separate invalidation on removal (`:1221-1226`, `core/Haskoki/Object.hs:3-7`). Calling only `Events.removeToken` cannot perform this cleanup. Do not reuse the close-all loop's ignored-error behavior for presence publication. |
| **G15 — Storage has no event subscription or physical-presence field.** | `Runtime/Storage.hs:154-160` stores token identity, slot, generation, label, and auth, not presence. Its entire `Store` interface at `:575-585` provides load/commit/reset/close/reload operations without event hooks. Memory and SQLite instantiate that interface at `Storage/Memory.hs:120-130` and `Storage/SQLite.hs:359-370`. Standard memory seats transient tokens and returns `Nothing`; SQLite loads/restores/seats before opening (`Standard.hs:696-767`). Neither backend supplies live presence transitions to Events. |
| **G16 — Configuration and CLI proofs have distinct ownership.** | `Runtime/Config.hs:233-247` defaults to one effective home token, test controls off, limits including 16 slots and 1024 events. `:531-542` rejects `control.enabled=false` and parses `test_enabled`. `Instance.hs:187-194` clamps the private event/job bounds to at least eight. `src/Haskoki/Ctl.hs:316-322,363-368` creates another private registry and applies the configured token script to it; this is not a hotplug source for a separately loaded module. `Control.hs:490-512` currently reports a hardcoded 16-slot window. |
| **G17 — Native proof coverage does not establish the requested integration.** | `tests/c/control_events.c:147-181` waits, inserts slot zero into the initially empty control registry, then polls. It checks no GetSlotList/GetSlotInfo agreement; `:155-161` uses a sleep and a plain shared `done` integer. `EventsSpec.hs:112-133` finalizes an empty queue only. `consumer_errors.c:183-210` opens/queries/closes a notify session and requires zero calls, but executes no crypto in it. `finalize_wait_race_probe.c:10-19,50-61` is fenced characterization with a broad legal-code set, not deterministic race proof. |

Finalization's current C order is also relevant: `function_tables.c:622-669`
takes init lock, clears liveness, takes the state lock, closes Standard, then
closes the control instance. Lock failure restores liveness (`:639-645`).
The new shared service must be closed before native Standard resources are
released, while preserving that retryable lock-failure behavior.

### 2.2 Standards baseline and version deltas

Primary texts read for this design:

| ID | Published source and relevant sections |
|---|---|
| **S240** | [PKCS#11 2.40 plus Errata 01](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html): §3.2 slot flags, §5.4 C_Finalize, §5.5 slot/token functions including C_WaitForSlotEvent, §5.6 C_OpenSession, §5.16 callbacks. |
| **S300** | [PKCS#11 3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html): §§3.2, 5.4.2, 5.5.1–5.5.4, 5.6.1, 5.6.5 C_SessionCancel, 5.21 callbacks. |
| **S310** | [PKCS#11 3.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html): the same slot/session/callback sections as S300. |
| **S320** | [PKCS#11 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html): §§3.2, 5.4.2, 5.5.1–5.5.4, 5.6.1, 5.6.5, 5.21 async, 5.22 callbacks, 6.53.6 OTP notifications. |

The relevant common contract is a pending flag for each slot, initially clear.
A successful wait clears one selected flag. `CKF_DONT_BLOCK` permits
`CKR_NO_EVENT`; a blocked wait interrupted by Finalize returns
`CKR_CRYPTOKI_NOT_INITIALIZED`. Multiple simultaneous waits from an application
are explicitly undefined by these standards. Haskoki's stronger competing-waiter
contract below is therefore an implementation guarantee. S240 and S300 §5.5
support these requirements.

S310 §§3.2 and 5.5 distinguish a slot from its inserted token. A listed slot
remains queryable; `CKF_REMOVABLE_DEVICE` is constant for a slot, and a slot
without it must always report `CKF_TOKEN_PRESENT`. `C_GetSlotList` takes
**`CK_BBOOL tokenPresent`**, not a flags mask: use `CK_TRUE`/`CK_FALSE`, not
the similarly valued `CKF_TOKEN_PRESENT`, in prototypes and tests.

No changed WaitForSlotEvent signature, flag, pending-event model, or multiwait
rule was found between 2.40 and 3.2. The adjacent 3.x changes matter instead:
3.0 adds `C_SessionCancel`, whose invocation from an application callback must
return `CKR_FUNCTION_FAILED` without action (S300 §5.6.5); 3.2 adds async
sessions and moves callbacks to §5.22 (S320). A pending async operation is not a
slot event. `CKN_SURRENDER` permits `CKR_OK`/`CKR_CANCEL`, with cancellation
reported by the interrupted operation as `CKR_FUNCTION_CANCELED`; its use is
optional. `CKN_OTP_CHANGED` concerns OTP state, not insertion or removal.
The overview table's phrase about OpenSession setting an insertion callback
does not supply a new notification value or override §5.6.1 admission.

Precedence between otherwise applicable errors and the choices of producer,
slot ordering, unchanged error outputs, and multiple-waiter arbitration below
are explicit Haskoki policies unless a source requirement is identified.

### 2.3 Selected ownership model and alternatives

Select **one serving `SlotEvents` service per initialization interval**, shared
by the control `Instance` and `StdInstance`. It holds configured slot identity,
immutable removable capability, current presence, presence epoch, pending-slot
order, and a closed bit. Standard owns actual sessions, objects, async views,
backend, and store. Presence-changing control commands call that owner; they
cannot directly mutate a second registry.

Three approaches were considered:

| Approach | Decision |
|---|---|
| Retain the current edge FIFO and copy presence into Standard afterward | Reject: allows lost slot indications, disagreement between queries and events, and cancellation of the wrong async table. |
| Shared coalesced service with a Standard-owned transition coordinator | Select: expresses the standard flag model, preserves bounded memory and existing Standard ownership, and gives a single publication point. |
| Replace all provider state with one new runtime and autonomous event thread | Reject for this slice: unnecessary lifecycle/scheduler scope and no installed backend needs a watcher. |

The old `EventQueue`/`TokenRegistry` may remain as private scenario/proof
utilities so their edge/drop tests retain their meaning. They must no longer
serve **any** public wait or public presence control after integration.
`Instance.instSlots` and `StdInstance.siSlots` reference the same new service;
Standard's async table remains its existing table of capacity eight. Control's
private scheduler proofs do not become standard async jobs by sharing a name.
Do not cast an `InstanceCell` into `StdInstance`, reopen a store, or bind
Standard's cleanup to `instAsync` merely because both are `AsyncTable`s.

### 2.4 Data flow and linearization

```text
all four function tables
  WaitForSlotEvent -> control C root -> InstanceCell -> shared SlotEvents STM
  GetSlotList / GetSlotInfo -> state lock -> StdInstance -> same SlotEvents
  OpenSession / token queries -> state lock -> catalog + same presence

HASKOKI_Control token.remove/insert
  -> state lock -> live InstanceCell -> bound Standard presence owner
  -> preflight -> async/session retirement when removing
  -> model + presence epoch + pending flag published together
  -> bounded JSON reply

C_Digest on an ordinary session
  -> state lock -> decode/plan/capacity admission
  -> saved CK_NOTIFY(session, CKN_SURRENDER, application)
  -> continue or terminate -> normal output publication
```

A wait never holds the C state lock or the model gate while sleeping. Presence
publication is a single STM transaction coordinated with the model delta under
the existing model gate. Callbacks and native-resource release run outside
STM; application callbacks also run outside the model gate.

## 3. Components

### 3.1 Exact public C interfaces and ABI pin

Use the unchanged public prototypes and callback type:

```c
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID *pSlot,
                         void *pReserved);
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID *pSlotList,
                    CK_ULONG *pulCount);
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO *pInfo);
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO *pInfo);
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, void *pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE *phSession);
typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE hSession,
                           CK_NOTIFICATION event, void *pApplication);
```

The ABI authority is `spec/vendor/pkcs11.h:1253,2130-2141,2228` and its
independent function typedefs, including `:2318-2319` for OpenSession.
`spec/sources.lock.json` pins latchset commit
`c5e61990c5621a9b955fc208644fe8145ac0a75d` and header SHA-256
`61e0b3f996fa9f095859d7d3b8e361d0b982de69fc8b6a4bf10291afbe7e24d8`.
Use its types rather than new provider-generated consumer types. Preserve
ordinal 68, table counts 68/92/92/104, older layouts, and existing Async routes.

Keep the serving wait body `on_WaitForSlotEvent` in `function_tables.c` and the
existing `std_GetSlotList`, `std_GetSlotInfo`, `std_GetTokenInfo`, and
`std_OpenSession` body names. These prototypes describe the table ABI; they
do not authorize adding new direct dynamic exports named `C_WaitForSlotEvent`
or otherwise expanding the module's public symbol set.

`CKF_DONT_BLOCK = 1`; `CKF_TOKEN_PRESENT = 1` and
`CKF_REMOVABLE_DEVICE = 2` are **slot-info** bits; `CKN_SURRENDER = 0` and
`CKN_OTP_CHANGED = 1` are **notification values**, not flags
(`pkcs11.h:396,404-406,1020-1021`). Ordinary sessions still require
`CKF_SERIAL_SESSION`; retain the accepted RW and async bits and the existing
missing-serial precedence. Do not add a flag for callback registration.

### 3.2 Exact internal C/FFI contracts

The following are proposed internal interfaces. They do not add public PKCS#11
table entries or vendor symbols. Keep helpers hidden under the existing export
map, prefer GHC-generated stub declarations, and maintain the supported LP64
width checks; `CULong`, not `Word32`, carries native flags/handles/return codes.

```c
/* Change the internal standard-open boundary to borrow resolved services. */
void *haskoki_std_open(void *ops_instance_cell);
void *haskoki_std_open_fresh(void *ops_instance_cell);

/* Extend, do not reinterpret, the existing session-open export. */
unsigned long haskoki_std_open_session(void *standard_instance,
    unsigned long slot, unsigned long read_only, unsigned long async_session,
    void *application, CK_NOTIFY notify, unsigned long *session);

/* Slot existence + current flags, including an empty configured slot. */
unsigned long haskoki_std_get_slot_flags(void *standard_instance,
    unsigned long slot, unsigned long *flags);

/* Retain these shapes; the implementation uses the shared serving service. */
unsigned long haskoki_wait_for_slot_event(void *ops_instance_cell,
    unsigned long flags, unsigned long *slot);
unsigned long haskoki_std_get_slot_list(void *standard_instance,
    unsigned char token_present, unsigned long *slots, unsigned long *count);

/* Hidden C callback guard/invoker; reentry check is thread-local. */
int haskoki_in_notify(void);
unsigned long haskoki_invoke_notify(CK_NOTIFY notify,
    unsigned long session, unsigned long event, void *application);
```

Corresponding Haskell contracts:

```haskell
type NativeNotify = CULong -> CULong -> Ptr () -> IO CULong

haskokiStdOpen
  :: StablePtr InstanceCell -> IO (StablePtr StdInstance)
haskokiStdOpenSessionWithNotify
  :: StablePtr StdInstance -> CULong -> CULong -> CULong
  -> Ptr () -> FunPtr NativeNotify -> Ptr CULong -> IO CULong
haskokiStdGetSlotFlags
  :: StablePtr StdInstance -> CULong -> Ptr CULong -> IO CULong
haskokiWaitForSlotEvent
  :: StablePtr InstanceCell -> CULong -> Ptr CULong -> IO CULong
haskokiStdGetSlotList
  :: StablePtr StdInstance -> Word8 -> Ptr CULong -> Ptr CULong -> IO CULong

-- Export the opaque cell name and this accessor from FFI.Instance.
-- Standard uses it during unpublished construction under the init lock.
readLiveInstance :: StablePtr InstanceCell -> IO (Maybe Instance)

foreign import ccall safe "haskoki_invoke_notify"
  invokeNativeNotify
    :: FunPtr NativeNotify -> CULong -> CULong -> Ptr () -> IO CULong
```

The invoker sets/restores C thread-local callback context on the calling bound
thread. It must be a `safe` import because the application can reenter C entry
points; an unsafe foreign call is not a valid callback trampoline. A null
function pointer is never called. A pointer is never encoded into JSON, stored
in SQLite, cast to an integer callback identifier, or dereferenced as data.

Retain `haskokiStdOpenSession` and `haskokiStdOpenSessionWithAsync` as Haskell
test/proof convenience wrappers supplying null callback/application values;
the C foreign-export name now binds `haskokiStdOpenSessionWithNotify`.
Standalone acquisition tests receive explicitly constructed serving services
through an environment-free constructor; they do not reread process config or
create a second production root.

`haskoki_std_slot_present` remains a **token-required** internal check for
mechanism/token callers: distinguish unknown slot from known-empty token.
GetSlotInfo switches to `haskoki_std_get_slot_flags`, rather than weakening
token-required callers to accept absence. Review every call site when splitting
these two meanings.

### 3.3 Serving event service and exact Haskell boundary

Put these types/functions in a new leaf module
`Haskoki.Runtime.SlotEvents`, re-exportable from `Haskoki.Runtime.Events`
(names below are the plan contract). Constructors of `SlotEvents` remain
private. The leaf may depend on STM and core data types, but not Lifecycle,
Async, Control, or FFI. This avoids a concrete existing cycle: Events imports
Async (`src/Haskoki/Runtime/Events.hs:75`), which imports Lifecycle
(`src/Haskoki/Runtime/Async.hs:251`). Lifecycle imports the new leaf directly,
never Events. Add the leaf to both relevant Cabal module lists during
implementation; it is not a new pure-core dependency on runtime IO.

```haskell
data SlotDefinition = SlotDefinition
  { sdSlot :: !SlotId, sdRemovable :: !Bool }
data SlotSnapshot = SlotSnapshot
  { ssSlotId :: !SlotId, ssRemovable :: !Bool
  , ssPresent :: !Bool, ssPresenceEpoch :: !Word64 }
data WaitMode = Block | DontBlock
data SlotWait = SlotReady !SlotId | SlotNoEvent | SlotWaitClosed
data SlotConfigError = DuplicateSlot | TooManyPendingSlots | InvalidEventBound
data PresenceError
  = PresenceUnknownSlot | PresenceFixedSlot | PresenceEpochExhausted
  | PresenceClosed | PresenceModelFault !ModelFault
data PresenceChange
  = PresenceUnchanged !Word64
  | PresenceChanged !Word64

newSlotEvents
  :: Int -> [SlotDefinition] -> IO (Either SlotConfigError SlotEvents)
snapshotSlots :: SlotEvents -> IO [SlotSnapshot]
waitSlot :: SlotEvents -> WaitMode -> IO SlotWait
closeSlotEvents :: SlotEvents -> IO ()

-- Internal STM primitive: only the lifecycle publication coordinator mutates
-- serving presence. Callers must not use it as a standalone event injector.
publishPresenceSTM
  :: SlotEvents -> SlotId -> Bool -> STM (Either PresenceError PresenceChange)
```

`newSlotEvents` starts every configured slot present, at presence epoch zero,
with all pending flags clear. `snapshotSlots` returns one atomic snapshot in
ascending slot order; it never acknowledges events. The queue stores at most
one pending entry per slot, with FIFO order of **first becoming pending**.
Repeated transitions update the current snapshot/epoch without moving that
pending entry. A successful wait removes the chosen entry/flag atomically.

An internally retained closed service may still be inspected for its last
slot snapshot; closing it does not fabricate a token-removal transition.
Public query entries reject the closed interval before consulting that snapshot.

Add a lifecycle publication function so the model and the hub cannot publish
in separate transactions:

```haskell
publishPresence
  :: Env -> SlotEvents -> StateDelta -> SlotId -> Bool
  -> IO (Either PresenceError PresenceChange)
```

It takes the existing model gate, validates/applies the pure delta, then writes
the model and `publishPresenceSTM` result in one transaction. Any failed
validation, closed service, unknown slot, fixed-slot removal, or exhausted
epoch commits neither side. No crypto, callback, cancellation, trace write,
or store I/O occurs inside that transaction. Precompute the delta before
irreversible cleanup; keep all serving mutations serialized by the C state
lock as described in section 3.8.

The Standard coordinator is:

```haskell
setStdTokenPresence
  :: StdInstance -> SlotId -> Bool
  -> IO (Either PresenceError (PresenceChange, Int))
```

The integer counts newly canceled **standard attached** jobs for the existing
`jobs_canceled` response. It is not the number of objects or private control
jobs. It must inspect Standard's actual bindings and use its existing cancel
workers. Closed/finalized services refuse even idempotent writes.

### 3.4 Initialization, control binding, and storage/configuration

Resolve configuration once for the serving interval. Factor the pure
effective-catalog calculation out of Standard's local helper so the control
owner and Standard use identical slot IDs and labels. Construct an unpublished
InstanceCell and serving SlotEvents, build Standard over that cell's config
and services, then bind these explicit hooks:

```haskell
data PresenceOwner = PresenceOwner
  { ownerSnapshot :: IO [SlotSnapshot]
  , ownerSetPresence
      :: SlotId -> Bool -> IO (Either PresenceError (PresenceChange, Int)) }

bindPresenceOwner :: ControlState -> Maybe PresenceOwner -> IO ()
```

The hooks capture the live Haskell Standard owner, not a stale unleased
StablePtr. They are installed before publication and cleared while holding
the state lock before Standard teardown. Serving `status`, `token.insert`,
and `token.remove` use only these hooks. Legacy standalone Control/CLI proof
constructors may bind their own explicitly private owner; absence of a serving
binding is a refusal, never fallback to a second registry. The private
`scheduler.advance` contract is unchanged and is not evidence for Standard's
async scheduler.

Publish the C roots and mark the interval initialized only after both owners
are ready. On any open/bind failure, unwind resources once, close the service,
and leave no published half-instance. `HASKOKI_Control` gains the normal
liveness check and state-lock acquisition/revalidation, including queries;
the current lock-free control path is not safe for hooks borrowing Standard's
native resources. WaitForSlotEvent remains lock-free with respect to that lock.

| Source/configuration | Required serving behavior |
|---|---|
| Standard memory | Initialize all catalog tokens present, no startup events. Presence controls can temporarily hide a token in the same interval. Do not instantiate a second `MemoryWorld` or change the existing `siStore = Nothing` detached limitation. |
| Standard SQLite | Load/provision tokens before publishing the interval, no startup events. Presence controls act on the same live token/model/store ownership. No new writer, database watcher, schema, or persisted presence column. |
| `control.test_enabled = false` | Slots are fixed soft-token slots: removable bit clear, present bit set. Mutation commands refuse. A blocking wait can legitimately remain blocked until Finalize. |
| `control.test_enabled = true` | All configured slots are simulated removable slots for the whole interval; removable bit set even while initially present. Existing token.insert/remove commands are the sole native presence producers in this slice. |
| `[tokens]` catalog | Slot IDs and identity are fixed for the interval. Unknown control slots refuse instead of manufacturing slots. Removing a token does not delete its slot. Reinsert restores that slot's same provisioned token, not a replacement identity. |
| `limits.events` | For the public service, capacity is the number of distinct potentially pending configured slots. Initialization requires this bound to be positive and at least the catalog size; otherwise opening fails using the existing config/open-failure route. Do not clamp or silently drop a flag. The private FIFO's old bound/policy remain private proof behavior. |
| `limits.slots` | Existing catalog admission still applies. A larger event bound does not admit extra slots. |
| `[sim].token_script` / `haskoki-ctl` | Retain their local scenario meaning; they do not control another process's loaded library. Do not advertise them as a public hotplug producer. |
| Store commit/reset/reload errors, login, key/object operations, session open/close, async completion | These do not independently change physical/simulated presence and generate no slot indication. A store error must not be recast as token removal. |

Both configurations remain software slots: `CKF_HW_SLOT` stays clear. The
removable choice is immutable after construction, including while absent;
slot strings and version fields retain their established values.

Presence epochs and pending flags are interval-local. They are neither
`TokenRecord.trGeneration` nor persistent async IDs nor the existing control
command generation. A remove/reinsert does not reset durable objects or bump
the token's stored identity generation. Idle detached records retain their
existing semantics; attached jobs on the removed slot are canceled. Restart
on SQLite loads the provisioned token and clears event flags, rather than
replaying the previous process's removal. Memory restart retains only its
existing transient behavior. This slice makes no new ordinary-token-object
durability claim (`Standard.hs:1158-1180` currently publishes through the model
and drains releases, rather than adding a persistence transaction).

Control's top-level `generation` continues to count accepted mutation
commands, including accepted idempotent insert/remove. `expected_generation`
must be checked and advanced in the same serving critical section, so two
callers presenting one expected value cannot both mutate. Per-slot status
`generation` reports the presence epoch, which advances only on a change.
Status paginates actual configured slots, not a hardcoded window of 16.
Presence-command preflight also refuses an exhausted top-level control
generation before cleanup; it must not wrap and admit an ancient expected value.
Maintain the 65536-byte query/short-buffer protocol and prepare replies before
mutating where allocation can fail; a query or short buffer executes nothing.

### 3.5 Presence transition and event-generation rules

| Operation / state | Presence and epoch | Pending indication |
|---|---|---|
| Successful Initialize/load/provision | Present; epoch 0 | Clear for every slot |
| Insert on known absent removable slot | Present; epoch +1 | Set; append slot only if not already pending |
| Remove on known present removable slot | Absent; epoch +1, with retirement below | Set; append slot only if not already pending |
| Insert present / remove absent | Unchanged; same epoch | No new indication; retain any existing one |
| Invalid slot, denied mutation, stale expected control generation, preflight failure | Unchanged | Unchanged |
| GetSlotList, GetSlotInfo, GetTokenInfo, status, OpenSession, callback dispatch | No presence change | Never set or clear |
| Successful WaitForSlotEvent | No presence/epoch change | Clear one selected slot |
| Finalize | Close interval | Clear all pending flags, wake all waiters as closed |

An epoch is `Word64`. Refuse a further true transition at `maxBound` with
`PresenceEpochExhausted`, before job cancellation or mutation; never wrap and
make stale diagnostic generations appear current. No public event-generation
number or event direction is added to `C_WaitForSlotEvent`.

Removal executes under the C state lock:

1. Validate live service, catalog membership, removable policy, and expected
   control generation, including capacity for its command increment. An
   already absent slot is a no-op; check presence-epoch capacity only for a
   true transition, before cleanup.
2. Prepare a combined model delta for every session on that slot: terminate
   operations, close sessions, destroy session objects, reset login state,
   and invalidate **all live object handles targeting the slot**, including
   token objects. Retain token data/auth metadata and token objects as parked
   records. Prevalidate the delta; no object/session ID is reused on reinsertion.
3. Cancel every Standard attached binding on those sessions using its existing
   workers/leases, including joined attachments, before publishing removal.
   Do not cancel idle detached records. No native output write can occur from
   one of those bindings after the removal indication is published.
4. Atomically publish the model retirement, absence, incremented presence
   epoch, and pending flag. This is the transition's linearization point.
5. Retire notify associations, find cursors, borrowed async views, and drain
   prepared resource releases before returning the control reply. All exits
   use cleanup brackets; a removed session cannot invoke a callback later.

Mask asynchronous exceptions across the publication/ownership handoff and
install cleanup obligations before it; allow interruptible work only where
the existing async cancellation and resource brackets define recovery. An
exception must not strand a retired session's callback or borrowed view.

The state lock prevents admission/completion/callback dispatch during this
sequence; the model gate is used only for publication. A session operation
that acquired the state lock first may finish first. Removal that acquires it
first invalidates the old session; later calls get the normal invalid-session
error. The slice does not promise an asynchronous interrupt inside native crypto
or introduce a new `CKR_DEVICE_REMOVED` path for these serialized operations.

After removal, GetSlotList(false) still lists the slot, GetSlotList(true) omits
it, GetSlotInfo succeeds without TOKEN_PRESENT, and token-required queries and
OpenSession return TOKEN_NOT_PRESENT. Reinsertion permits new sessions but
does not resurrect handles, login, callback registrations, or attached work.
Readers observe a complete snapshot; a later change can of course occur
between a successful wait and the caller's next query.

An internal exception before the transition commits does not post an event.
Cancellation already performed is not rolled back; a retry must safely finish
retirement. An exception during resource release **after** the commit retains
the committed absence/indication and cannot revive sessions. Report the failure
through the exception fence, run remaining cleanup in `finally`, and expose the
committed state to status. Do not assert that every failed control call is
side-effect-free: only validation/query/short-buffer refusals have that guarantee.

### 3.6 Waiter and finalize semantics

Public waits consume slot flags, not transitions. For example, remove/insert/
remove of slot A before any wait advances its epoch three times but leaves
one pending A. One poll returns A; the next returns NO_EVENT, and a subsequent
slot query observes the current absence. A transition after A is consumed
sets a new pending A. Events on A and B are independently retained, even if
one slot changes repeatedly. There is no public drop-oldest/drop-newest mode.

Use transactional first-pending FIFO selection for determinism. A single
pending slot produces one successful return among competing blocking/polling
callers. Other blockers resume waiting; other pollers return NO_EVENT. STM may
wake several threads internally; that is not a broadcast of the event. No
fairness guarantee or choice of winning thread is made. Do not reject a second
waiter with FUNCTION_FAILED merely because another waiter exists.

`DontBlock` never retries waiting for an event. It may execute normal bounded
entry/STM work; it is not a hard real-time latency guarantee. `Block` uses STM
retry, not sleeps, periodic polling, OS-event emulation, or a new worker thread.
No token absence returns TOKEN_NOT_PRESENT from a wait: absence is one of the
changes the wait is meant to report.

After Finalize has acquired the C state lock successfully, close the shared
service and unbind the control owner **before** closing Standard resources.
In one STM transaction, set closed and discard pending flags. A waiting
transaction tests closed before pending; all blocked callers then return
CRYPTOKI_NOT_INITIALIZED with their outputs untouched. Repeated close is safe.
Only afterward complete Standard/backend/store teardown and interval shutdown.
Do not close the service on the Finalize state-lock failure path, which restores
the live interval and permits retry.

Precisely distinguish these races:

- Event consumption commits before service-close: the waiter owns an OK/slot
  result, even if it is descheduled before writing the caller's output and
  returns after Finalize. Finalize does not retroactively revoke a completed
  wait decision.
- Service-close commits first: pending flags are discarded; every undecided
  old-interval waiter returns NOT_INITIALIZED. No drained-tail successes.
- A C entrant has loaded an old InstanceCell, but enters Haskell after close:
  its retained cell is closed, so it returns NOT_INITIALIZED without observing
  the new interval. A caller that has already obtained SlotEvents still has
  a GC-live service, which is closed. Neither path touches Standard's freed
  StablePtr or native resources.
- Reinitialize creates a fresh hub and cell, with flags clear. Old waiters
  never re-resolve the global root and migrate to that new hub.

Retain the existing never-freed liveness-cell strategy for this slice and state
its small per-interval retention honestly. An atomic C pointer alone is not a
lifetime lease. Finalize need not wait for application threads to be scheduled
and return from already-decided waits; it must make every blocked wait runnable.

### 3.7 Native session callback contract

Store **one** native callback/application pair on successful session admission,
keyed by the actual standard session. Both values may independently be null;
null Notify means no calls and does not require a null application pointer.
Registration must be committed before publishing the session handle. Failed
open retains neither pointer and leaves the caller's output untouched. Standard
owns the association until close-one, close-all, removal, or Finalize; it owns
neither the application allocation nor the function's executable storage.

Use a typed native registry, rather than coercing the private String/IO-unit
callback list:

```haskell
data SessionNotify = SessionNotify
  { snFunction :: !(FunPtr NativeNotify), snApplication :: !(Ptr ()) }
data NotifyDecision = NotifyContinue | NotifyCancel | NotifyFailed

registerSessionNotify
  :: StdInstance -> SessionId -> SessionNotify -> IO ()
retireSessionNotify :: StdInstance -> SessionId -> IO ()
surrenderDigest :: StdInstance -> SessionId -> IO NotifyDecision
```

The exact emission point is the `runStdDigestBuffered` branch that has a fresh
`Execute _ (EffectCrypto (FxDigest ...))`, a known fixed-width recipe, adequate
caller capacity, and `isAsyncSession == False`, immediately before running the
effect. That branch exists at `Standard.hs:2414-2441`. Call once, on the calling
bound thread, with `(actualSession, CKN_SURRENDER, savedApplication)`. This is
cooperative surrender before execution, not periodic interruption of OpenSSL.

| Session operation/path | CK_NOTIFY behavior in this slice |
|---|---|
| Eligible ordinary-session one-shot Digest, callback present | Exactly one CKN_SURRENDER before the fresh effect |
| Same operation, callback null | Continue with no call |
| DigestInit, DigestUpdate, DigestFinal, length query, short capacity, staged-output recall, decode/planner refusal | No callback |
| Explicit async-session Digest submission, polling, Complete, GetID, Join, cancellation | No callback, including synchronous fallback paths on that async session |
| Open/close, login/logout, GetSessionInfo, object operations, RNG, other crypto families, slot/control operations, Finalize | No callback |
| Token insertion/removal | Slot pending flag only; no surrender, OTP, or vendor notification |

Process the callback's result before any effect or output publication:

- `CKR_OK`: continue the already-admitted effect once.
- `CKR_CANCEL`: terminate the Digest operation, drain any associated resources,
  return `CKR_FUNCTION_CANCELED`, and leave output bytes and length unchanged.
  A repeated Digest without reinitialization reports OPERATION_NOT_INITIALIZED.
- Any other returned numeric code: terminate similarly and return
  `CKR_FUNCTION_FAILED`. Do not leak CKR_CANCEL or an arbitrary callback code
  as the Digest return value.

Catch Haskell exceptions in the typed dispatcher/test callback adapter and
convert them to NotifyFailed, restoring registry/TLS state and performing the
same termination. The outer foreign-export catch-all remains the final fence
for unexpected provider failures (GENERAL_ERROR). A C++ exception, `longjmp`,
signal fault, or invalid callback pointer crossing the C ABI is not a Haskell
exception; callers must return normally. Do not claim to recover such foreign
undefined behavior or add a signal handler to simulate that guarantee.

No native callback runs after the relevant close/removal/finalize returns.
Calls on different sessions are serialized by the existing C state lock;
this slice promises neither concurrent callbacks nor nested dispatch. All
supported sessions carry SERIAL; missing it still refuses with
SESSION_PARALLEL_NOT_SUPPORTED. OS-locking permission at Initialize permits
concurrent application threads, not obsolete parallel-session execution.

### 3.8 Lock ordering and reentrancy

Keep the order `C init lock -> C state lock -> model gate -> STM` where those
locks are required. Ordinary entries take only state lock and narrower locks;
waits take neither C lock nor model gate. Never hold STM while invoking any IO.
Presence retirement takes existing async cancellation leases outside the model
gate/STM. It does not acquire the private `trNotifyLock`.

For the selected synchronous callback point, retain the C state lock as a
lifetime/operation lease, release any model gate before invoking application
code, and hold no callback-registry lock, store lock, or async job lease during
the call. This deliberately serializes other serving operations until the
callback returns. Dropping the state lock around a callback would require a
separate lifetime/reservation protocol and is not part of this design.

Enforce a thread-local entry guard **before argument guards that can mutate
operation state and before acquiring any lock**. While in a native callback:

- Static discovery (`C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface`)
  and the existing static `C_GetInfo` may run with their existing validation.
- All other table calls, including GetSlotList/GetSlotInfo, nested crypto,
  Open/CloseSession, SessionCancel, WaitForSlotEvent in either mode,
  Initialize/Finalize, and `HASKOKI_Control`, return FUNCTION_FAILED without
  inspecting caller buffers or changing state. SessionCancel's rule is also
  required by the 3.x specification; other refusals are Haskoki's reentry policy.

The callback guard is an explicit exceptional entry context; ordinary
outside-callback calls retain their listed precedence in section 4.
Initialize and Finalize retain their other existing argument rules; this
design does not impose wait's ordering on every unrelated entry point.
Finalize must check it before taking the init lock, and Wait/Control before
their special root paths. Shared stub helpers and generated stub policy need
the guard as well, so different interface tables cannot bypass it.
The private Haskell `reentrantSlotSnapshot` capability is not a promise that
the native GetSlotList entry is callback-safe.

A callback must return and must not join another thread whose progress
requires a serving call into this provider. Such a thread is serialized behind
the callback's state lock. This is a stated API constraint, not a claim of
unrestricted reentrancy. Same-thread prohibited reentry must return promptly
rather than deadlock, including when the state lock uses application-supplied
nonrecursive mutex callbacks.

### 3.9 Documentation and generated contracts

Later implementation updates the relevant generator inputs and regenerates
owned artifacts, not hand-edits generated table/contract files. Extend the
existing Wait, OpenSession, slot/token-info, Digest, and Finalize evidence
references; preserve their existing classification unless the repository's
contract rules require a separately justified change. `generate-function-contracts.py`
already lists EventsSpec/control_events for Wait at `:202-204`; private proofs
must not be counted as public callback or presence-coherence evidence.

Revise operations/configuration notes to distinguish public pending-slot
coalescing from private FIFO diagnostics, fixed versus simulated removable
slots, the sole Digest surrender point, callback reentry limits, startup/restart
semantics, and the proxy dispositions. The old callback open/info/close test
can continue requiring zero callbacks for **that sequence**, with its broad
“no notification events on any path” explanation corrected.

## 4. Error handling

### 4.1 WaitForSlotEvent precedence and output ownership

Outside a callback, evaluate in this order:

1. Public liveness check: before Initialize/after Finalize return
   `CKR_CRYPTOKI_NOT_INITIALIZED`, including malformed arguments.
2. Structural guards: null `pSlot`, then non-null `pReserved`, then
   `flags & ~CKF_DONT_BLOCK != 0` return `CKR_ARGUMENTS_BAD`.
3. Resolve the atomic control root and revalidate InstanceCell/service
   lifetime. A close that wins after step 1 returns NOT_INITIALIZED here.
4. Perform one wait decision on the captured service: OK/slot, NO_EVENT for
   empty polling, or NOT_INITIALIZED for close. Blocking never returns
   NO_EVENT merely because it initially found no event.

An already concurrent close does not establish a total order with an earlier
structural refusal: a malformed call that passed step 1 may return ARGUMENTS_BAD
while Finalize races it. Sequential lifecycle tests require step-1 precedence;
race tests use the specified linearization points, not wall-clock guesses.

Never write `*pSlot` on any non-OK result. Do not zero it speculatively. A valid
non-null writable output is the caller's obligation; `pReserved` is checked
for nullness without dereference. Neither null slot output nor a non-null
reserved pointer is a size query. Unknown high bits are rejected at native
`CK_FLAGS` width before narrowing.

| Condition | Exact result / action |
|---|---|
| Live empty DontBlock | `CKR_NO_EVENT (0x08)`, output unchanged |
| Live pending slot | `CKR_OK (0)`, write one slot ID and acknowledge once |
| Service closed, both modes | `CKR_CRYPTOKI_NOT_INITIALIZED (0x190)`, no consumption/write |
| Invalid shape/flags while live | `CKR_ARGUMENTS_BAD (0x07)`, no consumption |
| Prohibited native callback reentry | `CKR_FUNCTION_FAILED (0x06)`, no consumption |
| Additional waiter / all tokens absent | Normal waiting/polling rules; no failure solely for this condition |
| Unexpected Haskell exception | Existing fence returns `CKR_GENERAL_ERROR (0x05)`; no exception crosses C |
| Explicit allocation failure before any claim | `CKR_HOST_MEMORY (0x02)` if detected/represented; do not claim all RTS exhaustion is recoverable |

Wait does not return SLOT_ID_INVALID, TOKEN_NOT_PRESENT, FUNCTION_CANCELED,
FUNCTION_NOT_SUPPORTED, or FUNCTION_FAILED for an ordinary empty queue.
Mask the claim-to-output handoff against asynchronous Haskell exceptions so
an acknowledged slot is not silently lost between successful STM consumption
and a normal output write. Keep the blocking retry interruptible; restore
masking after it resolves. Native faulting output pointers are outside that
guarantee. No C state-lock acquisition is added to this route.

### 4.2 Slot/token/session boundary matrix

Retain existing boundary precedence except where absence is newly meaningful.
The model/flags snapshot and output construction must use one call's captured
state; no separate unlocked presence reread may contradict its result.

| Entry | Ordered ordinary-call checks after initial liveness | Output rule |
|---|---|---|
| GetSlotList | State-lock failure; authoritative live owner; null `pulCount`; snapshot | Null list queries current count and ignores incoming count. Short capacity sets required count, leaves array untouched, returns BUFFER_TOO_SMALL. Adequate capacity writes ascending IDs and count. Nonzero CK_BBOOL continues to mean true, preserving current compatibility. |
| GetSlotInfo | State-lock failure; authoritative owner; catalog validity; null `pInfo` | Unknown slot gives SLOT_ID_INVALID even with null info. Known-empty slot is valid and returns OK/flags without TOKEN_PRESENT. No TOKEN_NOT_PRESENT result. Publish a complete local struct only on OK. |
| GetTokenInfo | State-lock failure; authoritative owner; catalog validity; presence; null `pInfo` | Known empty gives TOKEN_NOT_PRESENT, including a simultaneous null info error; unknown gives SLOT_ID_INVALID. Any refusal leaves the struct untouched. |
| OpenSession | Null `phSession`; missing SERIAL; unknown flag bits; state-lock failure; authoritative owner; catalog validity; presence; existing session/auth/capacity rules | Before/after interval still wins over structural checks. Known empty gives TOKEN_NOT_PRESENT; unknown gives SLOT_ID_INVALID. Notify/application do not affect acceptance. A refusal leaves session sentinel unchanged and retains no callback. |
| CloseAllSessions | State-lock failure; authoritative owner; catalog validity | Known empty succeeds as an idempotent close of zero sessions; unknown gives SLOT_ID_INVALID. Close/removal cleanup is not a token-presence precondition. |
| Calls with an old removed/closed session | Existing structural guards, then standard session lookup | SESSION_HANDLE_INVALID for well-shaped calls, even if its former slot is reinserted. Do not resurrect the handle to return TOKEN_NOT_PRESENT. |

Token-required mechanism queries use the known-empty refusal too; slot
existence checks must not accidentally permit cryptographic admission on an
absent token. Unrelated mechanism catalogs, async flags, and operation-error
termination rules stay as at the starting revision.

### 4.3 Control errors, callback errors, and failure boundaries

For Control, keep lifecycle and the 65536-byte budget dialogue. After that,
malformed envelope, unknown slot, disabled test mutations, stale command
generation, exhausted command generation, fixed-slot removal, or exhausted
presence epoch return
ARGUMENTS_BAD with the existing bounded error envelope and no mutation.
`PresenceClosed` maps to NOT_INITIALIZED; a model-publication fault maps to
FUNCTION_FAILED; unexpected exceptions remain GENERAL_ERROR. Add a typed
control failure outcome so operational failures are not all flattened to the
current `OutcomeErr -> CKR_ARGUMENTS_BAD` mapping (`Control.hs:332-345`).
This is an extension error policy, not an invented PKCS#11 slot error.

The callback-specific FUNCTION_FAILED mapping can remain FFI-local via
`NotifyDecision`; the core `ReturnCode` currently has FUNCTION_CANCELED but
not FUNCTION_FAILED (`core/Haskoki/Types.hs:97-145`). If the typed control
outcome carries a new core return-code constructor, add its complete numeric
mapping/serialization coverage; do not silently reuse GENERAL_ERROR or make
unrelated persisted enum encodings ambiguous.

Close-one/all, removal, and Finalize retire associations without invoking the
callback. Registration/retirement and async-view ownership must unwind together
on open failure. A callback returning an error is not token removal and sets
no slot flag. Callback cancellation writes neither Digest bytes nor its length,
executes no backend effect, and cannot cancel another session's operation.

## 5. Testing

### 5.1 Haskell obligations and retained private proofs

These are proposed tests, not executed results. Extend the existing model/FFI
suites and add a focused serving-notifications suite if that keeps the
coalesced service distinct from the legacy FIFO tests. Build an independent
reference pending-set model for property checks; do not merely repeat the
implementation algorithm in the expected value.

| Test proposal | Required observations / traceability |
|---|---|
| `caseServingInitialSnapshot` | Shared config/catalog, all present at epoch zero, no initial flag; fixed/removable selection; no half-published owner on acquisition failure. N01, N03, N09 |
| `caseServingCoalesces` | Repeated transitions of one slot give one pending indication; epochs record true transitions; idempotence preserves epoch/flag; first-pending order across slots. N02 |
| `caseServingBound` | Invalid/insufficient bound refuses open; every configured slot can remain pending simultaneously with no drop. Presence-epoch and control-generation exhaustion refuse before mutation/cancellation. N02, N09 |
| `casePresencePublication` | Model retirement and public snapshot agree atomically; known-empty versus unknown; status uses actual catalog; command-generation compare/mutate serialization. N03, N05 |
| `caseRemovalOwnsActualJobs` | Standard attached and joined jobs canceled, no later output write; idle detached record unaffected; different slot unaffected; session objects/cursors/views/callbacks retired; token data retained and handles stale. N05 |
| `caseServingWaitCompetition` | Two or more waiting transactions, one pending slot, one success; two slots, two successes; polling/blocking compete for the same flags; losers do not duplicate. N04 |
| `caseServingFinalizeOrder` | Empty and nonempty close, event-first and close-first branches, all blockers runnable, old cell/hub after reopen remains closed; Finalize lock refusal leaves hub live. N04, N06 |
| `caseNativeNotifyAssociation` | Four callback/application nullness shapes, two sessions with distinct cookies, open rollback, close-one/all/removal/finalize retirement. N07 |
| `caseDigestSurrender` | Eligible execution calls once before effect; OK continues once; CANCEL/other-code/throw terminate with exact codes and unchanged outputs. Callback TLS/lease restored. N07, N08 |
| `caseNotifyNonProducers` | Query/short/refusal/staged/async/multipart/non-Digest paths, token changes, and lifecycle operations emit no callback. N07 |
| `casePresenceCleanupFault` | Precommit fault has no false event; preparatory canceled jobs remain canceled; postcommit release fault keeps absent state/flag, invalid sessions, and drains remaining releases. N05, N10 |

Retain EventsSpec's **private** FIFO overflow, Haskell callback, and private
quiescence checks (`EventsSpec.hs:27-36`); label them accordingly. They do not
satisfy N02/N05/N07. Preserve Async/Detached proofs and the standard attached,
detach/rejoin/restart routes. The removal integration uses their workers and
must not revise scheduler/durable-state policy to make notifications pass.

### 5.2 Determinism and test seams

Use synchronization barriers and bounded joins. A test timeout is a failure
guard, never the mechanism that schedules an event or establishes a winner.
A “thread started” signal alone does not prove it reached STM retry.

Provide internal constructor-injected observer hooks for tests at these points:
wait captured interval, wait about to enter retry with no pending flag,
wait decision committed before output, removal prepublication, and service
close committed. Production hooks are no-ops. No new exported test C symbol,
environment-driven sleep, or public Control pause command is required. Haskell
tests can invoke `safe` imports of a small test C adapter or the standard FFI
entry with injected barriers to force resolve-before-close and claim-before-close.
Keep hooks outside STM; an about-to-retry hook acknowledges an observation,
then the transaction rechecks all state before retrying.

Use C11 atomics/condition variables for native callback counters and thread
results. Replace `control_events.c`'s sleep/plain `done` proof. Test successful
native blocking wake with a real presence transition; deterministic parked
and finalize arbitration belong to the injected Haskell/FFI seam, supplemented
by a bounded native race stress check. Do not pretend a native pre-call barrier
proves Haskell admission.

### 5.3 Independent native consumer legs

Add `tests/c/notifications_routed.c`, using only the pinned consumer header,
normal discovery, actual function-table members, and the existing independently
declared HASKOKI_Control prototype. Run each public version separately, using
its real table layout. Use a two-token catalog and `control.test_enabled=true`,
trace off, an actual standard backend, and an owned temporary config/store.
Run memory and SQLite variants; no synthetic fallback for the native Digest
success leg. Basic non-mutating polling also belongs in a separate
`consumer_notifications_poll.c` eligible for proxy parity.

Concrete legs:

1. **Entry/error matrix.** Before init and after finalize, exercise valid and
   malformed wait shapes, including null slot, non-null reserved, flags 2,
   DONT_BLOCK|2, and the highest native flag bit. Require lifecycle-first
   sequential behavior. While live require ARGUMENTS_BAD for those shapes,
   unchanged sentinels, and no consumed pending flag. Exercise both wait modes
   only in controlled processes where a mistaken blocking call is bounded.
2. **Initial discovery.** Full and present lists contain the same two configured
   slots; no initial event. Check removable flags in test mode and invariant
   fixed/present flags with test mode off. Include null count, zero/short list,
   adequate capacity, and full-struct canaries.
3. **Remove/insert coherence.** Remove a discovered slot; consume its event;
   full list retains it, present list excludes it, SlotInfo succeeds with
   removable only, TokenInfo/OpenSession return TOKEN_NOT_PRESENT. Reinsert;
   consume the indication and verify restored presence/new-session admission.
   Unknown slot returns SLOT_ID_INVALID at standard slot boundaries and
   ARGUMENTS_BAD for Control. No raw hardcoded slot is a transcript identity.
4. **Coalescing.** Three alternating changes before any wait give one slot
   result, latest status epoch +3, and then NO_EVENT. Duplicate insert/remove
   are no-ops. Change both slots and consume each once. Query paths do not
   acknowledge. Grow the filtered count between query and fetch and require
   BUFFER_TOO_SMALL plus retryable state and untouched array.
5. **Live cleanup.** On the removed slot keep an ordinary session, session
   object, token-object handle, multipart digest, and a standard async Digest
   bound to a guarded allocation. Remove, then make the old async output
   inaccessible. Old sessions/handles remain invalid after reinsertion; no
   operation writes the old buffer. A session on the other slot still works.
   In SQLite, detach an additional job before removal; its idle record remains
   subject to the unchanged rejoin contract after reinsertion.
6. **Wait competition/finalize.** Several native blockers and polls observe no
   duplicate event; finalize releases remaining blockers with NOT_INITIALIZED.
   Use a closed interval to bound loser joins. Distinguish successful event
   delivery from closed wakes in the transcript. Reopen and verify NO_EVENT.
   The deterministic seam proves which branch won; stress is supplementary.
7. **Actual native callback.** Open with a callback and distinct application
   cookie, DigestInit(SHA256), and Digest of `abc` into capacity 32. Verify
   `(session, 0, exact cookie address)` and calling-thread identity, then the
   known SHA256 bytes
   `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
   Repeat with null cookie and with null callback. Returning CANCEL yields
   FUNCTION_CANCELED, no digest/length change, and no reusable operation.
   Returning a different code yields FUNCTION_FAILED with the same cleanup.
8. **Reentry/retirement.** From the callback, static discovery succeeds;
   GetSlotList, SessionCancel (3.x), nested Digest, both waits, Control,
   CloseSession, and Finalize return FUNCTION_FAILED promptly without state or
   output changes. Returning OK then allows the original Digest to succeed.
   Repeat under negotiated nonrecursive application mutexes. No callback from
   query/short/open/info/close/removal/async paths; no call through a retired
   cookie after close/all/removal/finalize. Use a fixture trampoline that catches
   its own language exception, never an uncaught C++ exception across the ABI.
9. **Storage/restart.** Presence changes do not call storeResetToken or replay
   as events. Reinitialize on the same SQLite file: catalog present, flags clear,
   new callback registrations only. Do not turn this into an assertion about
   ordinary object durability that the starting surface does not provide.

Update `control_events.c` to remove an initially present token before waiting
for reinsertion. Update `sim_threaded.c`'s fixture to configure its churn slot:
its current churner explicitly uses slot 1 while workers use slot 0
(`tests/c/sim_threaded.c:221-238`). Preserve independent-slot churn/conservation;
add a separate same-slot removal test with explicit invalidation expectations
instead of widening every old legal-code set. Update the race probe's historical
comment if retaining it, and require exact no-event/close behavior on an empty
fixture rather than counting unexplained OK results as acceptable.

### 5.4 Subsequent verification and evidence

Only a later implementation/orchestrator worker runs these stages on its
actual final revision:

- Focused serving-notification/model/FFI tests and native consumers, including
  the updated control and threaded drivers in `haskoki-dev:ghc-9.10.3`.
- Existing attached/detached/restart Async proofs and broader required gates,
  release/installation checks, with no change to their established contract.
- `HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng scripts/test-proxy-parity.sh` with
  the dispositions below, then the normal `bash scripts/run-gates.sh` flow.
- Fast, then kat oracle lanes against a release bundle built from that same
  implementation revision, with findings inspected as described in section 5.6.

Wire the new consumer into `scripts/test-consumers.sh` and the parity driver's
manifest explicitly, following the established message/async arrangement.
Do not silently omit it because its filename lacks `consumer_`. Preserve
generator determinism and static ABI/contract checks. Record source revision,
command/exit status, toolchain, module/bundle hashes, source pins, and result/log
paths and hashes for later evidence. Old passing results do not qualify changed
code. This design supplies no such execution record.

### 5.5 Proxy parity at the pinned source

Read using `git show a48b60ba54b0163f4999c1e4fc0514bf7dc01681:<path>` in
`<proxy-checkout>`. This is the pin recorded
in `scripts/test-proxy-parity.sh:15-30,78`, not the proxy checkout's current HEAD.
The script's canonical daemon/shim hashes are respectively
`260cb245981561291eab4d29a16cb6a4d6f00dca3431f3d583d35364fab0c9e5` and
`8ea85073ce8436ebdc8ee99bce99e70a6d8c34473c28b5a45567c8a26aba1690`.
Those are recorded artifact requirements; no binary execution or parity run
was performed here.

All following `P:` paths are relative to that immutable proxy commit:

| Inspected behavior | Pinned source evidence |
|---|---|
| Wait has an actual transport route | `P:crates/shim/src/dispatch/general/state_ops.rs:9-27` checks null output/non-null reserved, calls the client, writes only success. `P:crates/client/src/client/key_ops.rs:161-165` sends flags/context. `P:proto/pkcs11-proxy-ng/v1/types.proto:968-975` carries flags and result slot/RV. |
| Server forwards the requested wait mode | `P:crates/server/src/server/grpc_service/state_ops/slot_event.rs:19-42` validates context once, then `spawn_backend(move || backend.wait_for_slot_event(flags))`; success remaps the backend slot through `to_virtual_slot(...).unwrap_or(backend_slot)`. `P:crates/backend/src/ffi/key_state_ops.rs:233-239` calls the backend C function with reserved null. There is no forced DONT_BLOCK conversion in these bodies. |
| Blocking wait holds the shim client mutex needed by Finalize | `P:crates/shim/src/dispatch/general/helpers.rs:23-32` holds `state::client().lock().await` across the awaited call. `P:crates/shim/src/dispatch/general/init_general.rs:124-135` needs the same lock before client.finalize and only afterward marks finalized. Thus Finalize cannot itself interrupt a still-pending wait through this shim path. A transport timeout is not the required finalize wake. This is a source-derived defect candidate, not a reproduced hang. |
| Server context finalization does not independently wake that backend wait | `P:crates/server/src/server/grpc_service/general/lifecycle.rs:43-64` removes the client context and closes its sessions; it does not call backend Finalize or signal an event-wait cancellation. The wait body checks context only before awaiting. A shared backend wait also consumes a backend application flag, without per-client fan-out in this route. Do not infer independent per-client notifications from RPC availability. |
| Callback registration is not transported | `P:crates/shim/src/dispatch/general/session.rs:7-18` names both values `_p_application`/`_notify` and sends only slot/flags. `P:crates/backend/src/ffi/session_ops.rs:112-126` passes null application and `None` to backend OpenSession. A direct Haskoki callback cannot be expected through this pin. Optional surrender means this is a parity/capability limitation, not by itself a mandatory-surrender conformance violation. |
| Error precedence differs | Shim wait structural guards run before `with_client!` checks initialization (`state_ops.rs:15-18`, `helpers.rs:25-27`). Malformed pre-init/post-finalize calls can therefore return ARGUMENTS_BAD where direct Haskoki requires NOT_INITIALIZED. |

Static source hashes for the core findings:

| P: path | SHA-256 of pinned file bytes |
|---|---|
| `crates/shim/src/dispatch/general/state_ops.rs` | `c6907ccb2f8f7138ffdadb25a2174da8e6a9dae67bd9dac8c5747d326113f485` |
| `crates/shim/src/dispatch/general/helpers.rs` | `7ffac3e129781c6f449d4d20de2733e058febb4947655fb1e92b241534988d40` |
| `crates/shim/src/dispatch/general/session.rs` | `9ced22f764c6cfb31eff25251cd32aafe2f4219b71c9a608262ac6c2fcb166ed` |
| `crates/server/src/server/grpc_service/state_ops/slot_event.rs` | `f620f3e2757f203f94cbe217eba5c6d29395d9ad4e65dd00a8a3f81708a1b8a0` |
| `crates/server/src/server/grpc_service/general/lifecycle.rs` | `f8471f29ba797c87dd8bdeb124dec73776b0375e25eb5e69996b455cc48712dc` |

Disposition: keep ordinary valid empty polling, sequential lifecycle calls,
and live structural refusals in the parity-eligible consumer, with discovered
slot identities. Rich `notifications_routed` behavior is **DIRECT-ONLY** at this
pin: the control extension has no route in the above protocol, callback
association is discarded, and blocking/finalize parity is not established.
Do not generate an event by loading a different Haskoki instance in the client
process and claim it affected the daemon's instance.

**A distinct upstream filing is expected** for “Blocking C_WaitForSlotEvent
cannot be interrupted by client C_Finalize”, after a later worker obtains a
bounded independent reproduction against the pinned pair. Include the mutex
and context-lifetime paths, direct finalize wake, proxied timeout/outcome,
exact flags/outputs, revision and artifact hashes. Track callback transport as
an explicitly optional capability limitation/enhancement, separately from that
mandatory finalize behavior; do not mislabel ignored callback pointers as an
obligation to synthesize insertion callbacks.

Record the actual new issue URL in the parity disposition and
`docs/pkcs11-check-upstream-issues.md`; this specification files nothing and
does not invent a URL. Existing message issue 23 and async issue 24
(`scripts/test-proxy-parity.sh:108-117`) do not cover this finding. The current
driver rejects DIRECT-ONLY entries without a real URL (`:118-124`); retain
that requirement for subsequent acceptance. No proxy rebuild, patch, re-pin,
global skip, or widened return-code success set is authorized by this spec.

### 5.6 pkcs11-check oracle sources, lanes, and dispositions

The inspected release tree is `/tmp/pkcs11-ws/pkcs11-check-0.2.2rc2`, referred
to below as `O:`. Its deterministic source digest over **519** Python files
under `src` is
`b7b5327c4294a892fcf21f351717bb240b2505621ce842c182b33cf6685bad23`.
The digest concatenates sorted release-relative UTF-8 path, NUL, raw file
bytes, NUL. Counts below use `ast.parse`/`ast.walk` over source bytes, without
importing modules or collecting/executing pytest. They count all `test_`
definitions in each file, not parametrized execution totals or slice coverage.

| Path under `O:src/pkcs11_check/testcases/` | All test definitions | SHA-256 |
|---|---:|---|
| `test_remaining_gaps.py` | 29 | `56ca76211694ac5c8fe8142cc550d8415d91ee39da830240db0cf0a5c9a9a33f` |
| `ckr/test_ckr_slot_token.py` | 3 | `9262b2b88f77628eab25f8e0ae0ba13c808f145b7157612e84686e7a377ab603` |
| `test_session_edge_cases.py` | 7 | `167703230e29892e4b0f3db498035f0bf1b9b27d252f1a2f369349b105eb26b8` |
| `test_token_flags.py` | 18 | `6a93dfac30b6df2a076876186255eddf40be5e703dc8743126f641ff48cdda09` |
| `test_interface.py` | 11 | `879de8b7223b2e63bb00c369d1a305bcc372be5accbcc2bdbb12c01834b19d01` |
| `ckr/_ckr_spec_tables.py` | 0 | `3df59974adfcb4e3112db1851676ce7b11f91c34d3c001458c38a5096d2aaba2` |

Both **fast** and **kat** include the following tests by marker selection.
`scripts/ci-pkcs11-lane.sh:11-16,72-89` excludes slow/vector/stress/fuzz from
fast, only stress/fuzz from kat. Relevant files are marked compliance, access,
security, or smoke, not those exclusions (`test_remaining_gaps.py:130`,
`ckr/test_ckr_slot_token.py:37`, `test_session_edge_cases.py:62`,
`test_token_flags.py:36`, `test_interface.py:20`). Collection, skips, and actual
execution must still be reported from the later run rather than inferred from
these source markers.

| Exact coverage | Expected Haskoki disposition |
|---|---|
| `test_remaining_gaps.py::TestWaitForSlotEvent::test_wait_for_slot_event_non_blocking`, `:1104-1124` | Empty fresh interval returns NO_EVENT and passes. It permits OK and skips FUNCTION_NOT_SUPPORTED. Haskoki must not use that skip: the function is supported. The misleading “success path” heading proves no insertion/removal. |
| `ckr/test_ckr_slot_token.py::TestWaitForSlotEventErrors::test_non_blocking_no_event`, `:86-103` | NO_EVENT on the default fixture; the oracle also accepts OK/FUNCTION_NOT_SUPPORTED. This broad set is not Haskoki's acceptance set. |
| `test_session_edge_cases.py::TestCKNotifyCallback::test_open_session_with_null_callback`, `:597-619` | OK with normal fixture capacity; no callbacks. Its permissive session-limit fallback is not a reason to return a parallel-session error when SERIAL is set. |
| `...::test_open_session_callback_matrix`, `:621-658,659-795` | All four null/callback × null/data shapes open usable fresh sessions and close successfully. Any delivered call must echo session/application, but `:769-780` explicitly makes invocation optional. No Digest is performed, so this slice emits zero callbacks in this matrix. It does not prove surrender cancellation or reentry. |
| `test_token_flags.py::TestSlotInfo`, `:207-255`, especially `test_slot_has_token_present_flag` at `:228-235` | Default non-test config remains initially present and passes list/info consistency. These queries do not remove/reinsert a token or check an empty removable slot. |
| `test_interface.py::TestLibraryInfo::test_library_has_slots` and `TestSlotEnumeration::{test_get_slots_with_token,test_slot_has_token_info}`, `:33-50` | Existing ordinary fixture has slots/present token entries. The last method merely asserts the returned entry is non-null; it does not actually call GetTokenInfo. None proves a transition. |
| `_ckr_spec_tables.py:5364-5369,5699-5705` | Declarative wait expectations only. The null-argument entry's comment claims `test_ckr_raw_args_bad.py` coverage, but that file's concrete tests at `:41-82` are mechanism-null crypto calls and contain no WaitForSlotEvent probe. Do not count the declaration as execution. |

No inspected oracle testcase drives blocking slot-event wake, coalescing,
multithreaded waiter arbitration, finalize/reinitialize races, native callback
cancellation, or an installed token-removal transition. The local native and
Haskell obligations remain essential. No expected oracle failure in this slice
is justified merely by implementing optional surrender: its callback matrix
never calls the selected producer.

There is a source-documentation error to retain in triage:
`test_remaining_gaps.py:1114-1117` says the WaitForSlotEvent return list
explicitly contains FUNCTION_NOT_SUPPORTED; the four inspected function
sections list ARGUMENTS_BAD, NOT_INITIALIZED, FUNCTION_FAILED, GENERAL_ERROR,
HOST_MEMORY, NO_EVENT, and OK. Do not confuse that prose error or the separate
general unsupported-function convention with an executed Haskoki deviation.
The declarative-null-test coverage comment is also not evidence of a running
probe. A later oracle filing may correct those source/coverage descriptions;
it is distinct from the proxy finalize defect.

After implementation, run
`bash /tmp/pkcs11-ws/run-lane-rc2.sh fast`, inspect findings, then
`bash /tmp/pkcs11-ws/run-lane-rc2.sh kat`. Preserve earlier outputs first.
Inspect `out-rc2/<lane>/pkcs11-<lane>-results.json` and `trace.jsonl`; the wrapper
passes test exit 0 **or 1**, so its own zero is not a clean-lane assertion
(`scripts/ci-pkcs11-lane.sh:84-104`). Record exact node/parameters and provider,
oracle, or capability disposition in `docs/pkcs11-oracle-triage.md`, with actual
upstream URLs where filed. Do not edit the pinned oracle tree, add unconditional
skips, or broaden acceptance to hide a provider bug. Neither lane has been run
for this design.

## 6. Acceptance and spec traceability

Acceptance belongs to the later implementation revision. Every row requires
the indicated direct behavior, not merely a non-null function pointer, a private
proof, a permissible oracle skip, or a successful script wrapper exit.

| ID | Required behavior | Contract sections / gaps | Required evidence |
|---|---|---|---|
| **N01** | All four actual tables reach shared serving notifications; ABI/layouts unchanged; one resolved config/catalog; no half-instance on failure. | §§2.3–2.4, 3.1–3.4; G01, G03, G07 | Independent table consumers, acquisition failure tests, deterministic generated diff |
| **N02** | Initially clear per-slot flags; idempotence; coalescing; first-pending order; no loss at admitted capacity; checked epoch exhaustion. | §§3.3–3.6; G04–G05, G08 | Reference-model traces/properties and concrete native transition/poll sequences |
| **N03** | Fixed slot identity; boolean filtering; accurate constant removable flag and changing present flag; unknown versus known-empty errors; output/error precedence. | §§3.4–3.5, 4.1–4.2; G02, G09–G11 | Both storage modes, fixed/removable configs, canary/error matrix through every table |
| **N04** | True blocking; immediate empty polling; one consumer per pending slot; no duplicate/broadcast event, no arbitrary waiter refusal, all undecided waits closed on finalize. | §3.6, §4.1; G04–G05, G17 | Barrier-controlled Haskell/FFI competition plus bounded native callers |
| **N05** | Real Standard session/job cleanup on removal, atomic coherent snapshot, no later bound-buffer write, invalid old handles, isolated other slot, retained idle detached state. | §§3.3–3.5, 4.2–4.3; G07–G08, G14 | Guarded native output, multi-slot sessions/objects, existing async worker assertions, model/publication faults |
| **N06** | Event-first/close-first races have exact outcomes; closed old cells cannot consume new events; no free-after-resolve; Finalize lock failure remains retryable. | §§3.4, 3.6, 3.8; G05–G06 | Deterministic stale-cell/claim/close schedules, bounded native reopen stress, retained-cell limitation documented |
| **N07** | Exact native session/cookie association; selected Digest callback fires once; all non-producers remain silent; close/all/removal/finalize retire callbacks. | §§3.2, 3.7; G12–G14 | Real C callback and thread/cookie checks, four nullness shapes, separate sessions, cleanup/failure tests |
| **N08** | OK/CANCEL/unexpected callback results and caught test exceptions have exact outcomes; no effect/output on cancel/failure; prohibited reentry fails before locks/mutation. | §§3.7–3.8, 4.3; G13 | Native callback RV/reentry checks under internal and negotiated nonrecursive locks; effect count and canaries |
| **N09** | Memory/SQLite/config behavior matches the stated source of presence; no new store/reset/watcher; actual catalog status; command/presence/store generations remain distinct. | §§3.3–3.5; G15–G16 | Config/acquisition/limit tests, store call ledger, SQLite reopen and unchanged async-detach limits |
| **N10** | Validation and short/query paths mutate nothing; faults cannot publish half-presence or revive retired sessions; fences/cleanup preserve usable ownership. | §§3.5, 4.1–4.3; G08, G14 | Failure injection before/after commit, resource and callback registry accounting, masked handoff assertions |
| **N11** | Honest direct/proxy/oracle dispositions; distinct proxy filing with reproduced evidence; eligible polling parity retained; no unexplained new provider findings. | §§5.4–5.6 | Final-revision driver/release records, actual issue URL, source-pinned fast/kat findings review |
| **N12** | Documentation/contracts identify public versus private guarantees; previous Async and other required gates retained; no unapproved expansion of this slice. | §§1, 3.9, 5.1–5.4 | Regenerated contract references, required suite/gate/release checks, changed-file review |

Planning readiness: the ownership model, public/internal interfaces, error
ordering, producer list, callback policy, storage boundary, race outcomes,
oracle limitations, and proxy filing disposition are specified. The plan worker
can derive implementation tasks without inventing notification values or an
event-generation policy. Owner review of this proposed contract remains distinct
from implementation and acceptance. No acceptance is claimed here.

## 7. Explicit task breakdown proposal for the plan worker

The plan should name concrete files and test commands, preserve the dependency
order below, and use failing behavior tests before each implementation change.
The file lists are **future proposed changes**, not changes made by this worker.

| Task | Spec-traceable work item and first failing test | Dependencies / completion boundary |
|---|---|---|
| **T-N01 — Coalesced serving service** | Implement the new SlotEvents leaf/types/STM boundary, initially-clear flags, coalescing/order, closed-first waits, bounds, checked epochs. First fail `caseServingCoalesces` and nonempty finalize. Retain private FIFO tests with correct labels. Covers N02, N04, N06, N09; §§3.3, 3.6. | First; preserve the acyclic module graph; no public integration claim yet. |
| **T-N02 — Shared acquisition and control owner** | Factor effective catalog, share resolved config/services through Instance/Standard open, bind/clear PresenceOwner, add Control state-lock/revalidation path and actual catalog status. First fail `caseServingInitialSnapshot` on owner identity and partial-open unwind. Covers N01, N09, N10; §§3.2, 3.4. | T-N01; preserve existing backend/store ownership and Standard table capacity. |
| **T-N03 — Coherent presence and real removal** | Add lifecycle atomic model+presence publication and Standard retirement coordinator; distinguish command/presence epochs; wire existing controls with typed failures. First fail removal with a real standard attached job and a second-slot session. Covers N03, N05, N09, N10; §§3.3–3.5, 4.3. | T-N02; never call the old registry as public fallback. Preserve idle detached policy. |
| **T-N04 — Public slot/query/wait boundary** | Add slot-flags export, separate existence from token-required checks, update list/info/open/close-all errors, reserved/flags validation, claim-to-output masking, all-table routes. First fail known-empty SlotInfo and reserved-pointer/no-consumption tests. Covers N01–N04; §§3.1–3.2, 4.1–4.2. | T-N01–T-N03; exact output canaries, no ABI change. |
| **T-N05 — Finalize and waiter arbitration** | Close/unbind serving service before Standard teardown; retain liveness-cell lifetime; add deterministic interval/claim/close hooks and tests. First fail queued-close priority and stale-entry-after-reopen. Covers N04, N06, N10; §§3.6, 5.2. | T-N02–T-N04; preserve retry on state-lock refusal. No new permanent threads. |
| **T-N06 — Native callback association and guard** | Extend the internal session-open signature, typed registry, safe C invoker/TLS guard, retirement and open rollback. Guard every non-whitelisted public path, including stubs, Wait, Control and Finalize. First fail native pointer/cookie retention and reentry-before-lock checks. Covers N07–N08, N10; §§3.2, 3.7–3.8. | T-N02–T-N05. Implement the guard before enabling any native callback producer. |
| **T-N07 — Bounded Digest surrender** | Add only the specified fresh synchronous one-shot producer; OK/CANCEL/other/exception outcomes, termination and no output/effect on refusal. First fail `caseDigestSurrender`; pin every non-producer, especially explicit async sessions. Covers N07–N08; §§3.7, 4.3. | T-N06; Async/Detached scheduler logic and other mechanisms unchanged. |
| **T-N08 — Independent native integration** | Add both consumer fixtures; update control_events synchronization/initial state, configure sim churn slot, correct race-probe characterization, wire consumer manifests. First make each N01–N10 leg fail against the relevant missing behavior; use barriers, atomics and hard timeout guards. Covers §§5.1–5.3. | T-N03–T-N07; private tests cannot substitute for table calls. |
| **T-N09 — Proxy reproduction and oracle disposition** | Reproduce the pinned blocking/finalize defect in a bounded independent probe, file a distinct upstream issue, then record its real URL for notifications DIRECT-ONLY while retaining polling parity. Execute/review fast then kat at the pinned oracle source. Covers N11; §§5.5–5.6. | Direct N01–N10 behavior established first. No proxy/oracle source edits, no fabricated filing or run claim. |
| **T-N10 — Contracts, docs, final gates and handoff** | Update generator-owned evidence references and behavior notes; rerun only the required focused/regression/gate/release stages on the final implementation revision. Audit N01–N12 with exact artifacts, pins and unresolved findings. Covers §§3.9, 5.4, 6. | All prior tasks; stop at this slice. Any ownership/lifetime gap, unexplained provider finding, absent required proxy filing, or unproved installed behavior remains an explicit acceptance blocker. |
