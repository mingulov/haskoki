# What Haskell contributes

Haskell makes the PKCS#11 rules visible as data and functions. The core
models sessions, objects, permissions, operation states, and output
decisions using owned values and distinct types. Planning a call and
finishing its result are separate from running native crypto:

```text
decoded call -> pure plan -> crypto effect -> pure finish -> publish
```

[`Transition.hs`](../core/Haskoki/Transition.hs) describes the planning
and finishing steps. [`CryptoEffect`](../core/Haskoki/Operation/Effect.hs)
records the requested work, and the
[engine driver](../src/Haskoki/Engine/Driver.hs) interprets it. The same
backend interface supports controlled synthetic tests and real OpenSSL
operations. The public C demo uses OpenSSL.

## Benefits in this codebase

- The private `haskoki-core` [Cabal component](../haskoki.cabal) depends
  on data libraries. Runtime, storage, and native bindings sit outside it.
  This keeps protocol tests usable without loading a native consumer.
- Distinct [handle types](../core/Haskoki/Types.hs) prevent mixing session,
  object, and resource IDs accidentally. [Output requests](../core/Haskoki/Request.hs)
  distinguish a size query from a supplied buffer.
- [Attribute values](../core/Haskoki/Attribute.hs) use `ByteString` for
  binary data and distinguish readable, sensitive, and unavailable values.
  [Byte-preservation tests](../tests/model/BytesSpec.hs) exercise that choice.
- The compiler rejects selected omissions, including incomplete patterns
  and missing record fields. [Delta properties](../tests/prop/DeltaProps.hs)
  and [streaming properties](../tests/prop/StreamProps.hs) then check behavior
  that types alone do not describe.

The separation also helps with failures. Async execution must finish or
repair a claimed job if its runner throws or is interrupted; the
[ownership tests](../tests/model/OwnershipSpec.hs) inject both cases.
Native digest contexts are borrowed under a registry lock while used;
their lifetime is a runtime responsibility, not a consequence of purity.

## Checked call work

Call execution binds three values — the submitting session, the
guarding reservation, and the planned effect — and every consumer
must agree on what the triple means. [`CallWork`](../core/Haskoki/CallWork.hs)
is the checked form of that triple: [`checkedCallWork`](../core/Haskoki/CallWork.hs)
validates step presence, step/session identity, the function/slot
family, and effect compatibility, in that order, reporting the first
failure as a typed [`WorkMismatch`](../core/Haskoki/CallWork.hs). The
function tables are explicit per-`FunctionId` arms with no wildcard,
mirroring [`runFinisher`](../core/Haskoki/Transition.hs) leg for leg;
the [matrix test](../tests/model/TransitionSpec.hs) pins every
accepted triple and every refused cross-family combination, and the
[coherence sweep](../tests/model/TransitionSpec.hs) proves every
planner-produced execution checks.

Enforcement sits at the boundaries that admit held work, never in the
planner: async submit checks holdability first, then pair coherence,
then enablement and capacity, refusing with no id consumed and the
table untouched (see the [submit tests](../tests/model/AsyncSpec.hs));
the FFI submit leg and the detach rejoin replay check their re-planned
pairs the same way. Hand-built fixtures without a pinned step admit
explicitly behind [`admitLegacyUnstepped`](../core/Haskoki/CallWork.hs) —
the effect family is never guessed from a missing step. Key work keeps
its own contract: submit admits it and the drive refuses incoherent
pairs before the runner fires. The key-mutation half of the contract —
start-time validity for in-flight effects, observed destruction for
later calls — is recorded in the
[async construction contract](async-config-design.md#construction-and-linearization).

The seal is pinned by [`scripts/check-sealed-callwork.py`](../scripts/check-sealed-callwork.py):
shipped code reaches the fixture names only at their definitions
and quoted Haddock references, and no production match inspects
the raw pair. The scan permits exactly one `WorkCall` wildcard
shape, the closed 1-ary `WorkCall _)`, which binds nothing: the
two outer-function refusal arms over key functions use that form
(see `src/Haskoki/Runtime/Async.hs`).

## Public Haskell surface

External callers have two supported paths into this package, and
neither is a Haskell provider facade: native callers load
`libhaskoki.so` through the versioned C function tables (`cbits/` +
`ffi/`), and Haskell callers inside this repository use the pure
request/outcome contracts (`planCall`, `finishEffect`,
`publishDelta`). The 30 library modules below are developer
interfaces; their names and shapes may change, and nothing here
promises a stable Haskell provider API. The private `haskoki-core`
component is not the package public API at all.

| Modules | Purpose | Stability | Resource owner | Concurrency contract |
|---|---|---|---|---|
| `Haskoki` | Facade re-export (`Haskoki.Types` + `Haskoki.PKCS11`) | Facade; compat names deprecated | None (re-export only) | None |
| `Haskoki.PKCS11` | Compatibility scaffold: `initialize`, `finalize`, `getInfo`, `getSlotList` each answer `CKR_GENERAL_ERROR` | Frozen, deprecated, kept for compatibility | None (no state) | None |
| `Haskoki.Engine.Backend`, `Haskoki.Engine.Driver` | Backend interface and its interpreter over planned effects | Internal | Backends own native contexts; the driver borrows | Backend operations hold the exclusive environment gate (environment-then-registry lock order), atomic with close; native digest contexts are borrowed under a registry lock |
| `Haskoki.Engine.OpenSSL4` | Native backend over the pinned static libcrypto | Internal | Same as above | Same as above |
| `Haskoki.Engine.Synthetic` | Labeled fake bytes for engine suites and scenario runs | Test-only; absent from the foreign library | None served | None served |
| `Haskoki.Ctl` | Control tool and scenario-runner surface | Internal; absent from the foreign library | Owns its in-memory model only | One command at a time |
| `Haskoki.FFI.Standard`, `Haskoki.FFI.Instance` | Serving entries: admission, async delivery, instance lifecycle | Internal | The instance owns sessions, jobs, and stores; callers own native buffers per the entry contract | Entries serialize on the C state lock except the documented lock-free waits; callbacks hold that lock as their lease |
| `Haskoki.FFI.Async`, `Haskoki.FFI.Exports` | Private proof APIs: standalone caller-owned async contexts/stores and routed-crypto contexts | Internal (standalone proof contexts; serving instead borrows `AsyncCtx` views sharing its backend/table) | The caller owns each standalone context and closes it explicitly (`haskoki_hs_async_close`, `haskoki_hs_async_store_close`, `haskoki_hs_crypto_close`); the store box outlives contexts opened on it; callers close every context on a box (and join their calls) before closing the box; a Store no caller can receive is recovered by the next standalone open or close in the process, and until then its lock stays held | Direct Haskell calls take no C state lock; `AsyncCtx` carries its table and leases; context close is cancellable at every blocking wait but the bounded SQLite busy waits inside FFI calls — a close canceled in the borrower wait reopens the context, while one canceled past it stays owned by its slot in a closing state that admits nothing and the next close resumes it; a failed or canceled box close keeps its slot until a retry closes the Store; borrowed `AsyncCtx` views are internal, serialized by the C state lock, with no concurrent direct use; raw `AsyncTable` methods take no context admission, so callers serialize use with destruction; `CryptoCtx` has no retirement lease, so callers must not use it after close |
| `Haskoki.FFI.Decode`, `Haskoki.FFI.Encode`, `Haskoki.FFI.NativeParams`, `Haskoki.FFI.MessageParams`, `Haskoki.FFI.KeyOutputs`, `Haskoki.FFI.Notify` | Marshalling, parameter frames, callback plumbing | Internal (`KeyOutputs` absent from the foreign library) | Borrowed views; no retained state | Same lock discipline as the serving entries |
| `Haskoki.Runtime`, `Haskoki.Runtime.Config`, `Haskoki.Runtime.Catalog` | Umbrella re-export, config parsing, token catalog admission | Internal (`Haskoki.Runtime` absent from the foreign library) | Parsing borrows; the instance owns the admitted catalog | Parsing runs single-threaded at open |
| `Haskoki.Runtime.Lifecycle` | Provider intervals: initialize/finalize, close obligations | Internal | The instance owns the interval | Finalize runs under the state lock with zero open sessions |
| `Haskoki.Runtime.Async` | Attached job tables | Internal | The instance owns tables and retained bytes | STM coordination; attached terminal tombstones bounded (4096 records, 64 MiB); the just-committed job is always retained; no background reaper |
| `Haskoki.Runtime.Detached` | Persistent async records | Internal | The store owns terminal records | Detached terminal records stay stored; separate from attached-table retention. Attachment claims go through the store handle's shared claim authority (per token): detach contexts are views over it, so one persistent id has at most one live binding across every context on the handle, and a context retires only the tables it joined through |
| `Haskoki.Runtime.Storage`, `Haskoki.Runtime.Storage.Memory`, `Haskoki.Runtime.Storage.SQLite` | Store interface and its two backends | Internal | The store handle owns token/object rows; single-writer. Each open handle also owns one detached-job claim authority, which lives only in this process, is never saved to disk, and starts empty on reopen | Commits serialize; quarantine refuses until an authoritative reload clears it |
| `Haskoki.Runtime.SlotEvents` | Public slot-flag service | Internal | The interval owns the slot service | One flag has one consumer; close discards flags and wakes waiters |
| `Haskoki.Runtime.Events` | Private edge-queue proofs | Internal | The queue owns pending events and the finalized flag | Finalize only marks finalized; waits drain queued events before reporting it |
| `Haskoki.Runtime.Control` | Serving presence controls (`token.insert`/`token.remove`) | Internal | Mutations publish through the model | Runs under the state lock with the retirement order in `docs/operations-notes.md` |
| `Haskoki.Runtime.Trace` | Bounded trace queue over a caller-supplied sink | Internal | The `Tracer` owns the queue with drop/failure counters | Drains write queued lines through the sink; failures counted, never thrown; the serving sink appends per line; concurrent drains share the sink with no ordering across drains |

The foreign library additionally bundles `Haskoki.FFI.Types`,
which has no in-tree importers; it is bundled code, not an
interface. Documentation examples use an actual supported entry
point, never the deprecated scaffold names.

## Extraction rules

The dispatch surface stays small while helpers move only for cause:

- Move a pure family helper out of `ffi/Haskoki/FFI/Standard.hs`,
  `src/Haskoki/Engine/Driver.hs`, or
  `core/Haskoki/Operation/KeyManagement.hs` only when a concrete fix
  exposes the seam; bulk moves are not pre-authorized.
- Keep one dispatch arm per `FunctionId` with no wildcard, mirroring
  `runFinisher` leg for leg.
- Preserve error precedence and output/persistence ordering across
  the move.
- Run `python3 scripts/check-core-boundary.py` and the focused
  family tests for any extraction actually performed.

No extraction is required to complete an API-clarity task; the
checklist above binds only extractions that happen.

## Executable reference

### The logout journey

`examples/haskell-reference/` carries one buildable program that
teaches one checked rule — logout/object lifetime (OASIS PKCS#11
3.2 5.6.10) — across the full pipeline: user call, `Request` ADT,
`planCall` (`Reject` / `Immediate` / `Execute`), effect request,
`finishEffect`, commit decision (`PreparedCommit`), in-memory
publication (`publishDelta`), and model readback. Durability
itself (`pcPersist` performed by storage) is a runtime step the
program names but does not perform. Build and run with
`cabal build exe:logout-journey` and `cabal run exe:logout-journey`;
any violated expectation exits nonzero, so the run is the check.
(Wired as an `executable` stanza: the pinned cabal-install 3.18
plans no `example` component.)

### Independent policy oracle

`tests/model/LogoutOracleMain.hs` (suite
`haskoki-logout-oracle-tests`) checks the same rule from the other
side. An algebraic law that reuses implementation functions can
only re-describe the code; this oracle instead re-derives the
expected outcome from the contract text in its own miniature model
(`OracleObject`, `oracleSurvivesLogout`, `oracleRetiresOp`) and
observes planner runs through raw records, maps, and the
abstract-state projectors only. It never calls `objectPrivate`,
`objectToken`, `objectVisible`, `resolveHandle`,
`retirePrivateKeyOps`, or the logout planner. Key privacy for the
retirement prediction comes from the oracle's own setup facts.
Four mutation probes (destruction removed, session/token guard
inverted, codec flag inverted, retirement neutered) each fail
exactly the cases that own the mutated sub-rule.

### Mechanism-variant KAT

The same suite pins one variant, CKM_AES_GCM (`0x1087`): the exact
init-frame bytes, the decoded triple, and the unit-stream cipher
shape, plus a CKM_AES_CBC control vector. Expected bytes are
hand-derived from the OASIS mechanism numbers and the documented
frame layout (the parameter tail is an opaque 13-byte framing
fixture, not inner GCM parameter structure). No codec source was
touched; existing codec meanings stand.

## Costs and limits

Loading the module also loads the GHC runtime. The release bundles its
runtime dependencies and keeps the runtime alive for the process lifetime.
The [host contract](../SUPPORTED-HOSTS.md) covers threading, loading, and
finalization. Async coordination uses software transactional memory (STM)
and IO. The foreign-function interface (FFI) contains
substantial validation, admission, persistence, and delivery logic.

Some requests still carry generic byte payloads, and effect/result
compatibility still needs runtime checks. Native digest state cannot be
serialized into an operation snapshot. The
[core-boundary checker](../scripts/check-core-boundary.py) is a textual
guard, not a proof of purity or totality.

Haskell helps explain and maintain protocol behavior. It does not prove
PKCS#11 conformance, eliminate timing leaks, or make C and OpenSSL memory-safe.
That boundary still needs native tests and careful ownership.
See the [evidence levels](trust-ladder.md) and [current results](release-results.md).

## Module surface inventory (B3)

The [B3 inventory](b3-docs-inventory.md) lists the module sets read from
`haskoki.cabal` at `f4a967a`, for H3/V5 owners:

| Set | Count | Source |
|---|---|---:|
| Main library `exposed-modules` | 30 | `haskoki.cabal:161-191` |
| Main library `other-modules` | 2 | `Haskoki.FFI.OpenSSL4.Raw`, `Haskoki.Runtime.Attach` |
| `haskoki-core` (`private` component) | 67 | `haskoki.cabal:81-148` |
| Foreign library `other-modules` | 27 | `haskoki.cabal:250-277` |

Two facts from that survey matter here: the `Haskoki.PKCS11` facade
(`initialize`, `finalize`, `getInfo`, `getSlotList`) always answers
`CKR_GENERAL_ERROR` and is not the serving path, and 6 library-exposed
modules are absent from the foreign library while flib-only
`Haskoki.FFI.Types` has zero in-tree importers. See gaps D1 and D4 in the
inventory for the H3 follow-ups. Freshness: at this tree the library
still exposes 30 modules and the foreign library bundles 27 (it now
also carries `Haskoki.FFI.MessageParams` and `Haskoki.Runtime.Attach`),
while `haskoki-core` grew to 68 with `Haskoki.CallWork`; the facade
names are now deprecated (see `src/Haskoki/PKCS11.hs`) and the
supported-path answer to D4 is the Public Haskell surface section
above.
