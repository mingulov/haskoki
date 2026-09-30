# v3.2 async C routing Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans, or superpowers:subagent-driven-development when the coordinator assigns workers, to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax. Each task ends with a reviewable diff and coordinator review. Workers do not stage or commit; the coordinator commits accepted task diffs.

**Goal:** Route `C_AsyncComplete`, `C_AsyncGetID`, and `C_AsyncJoin` through the actual 3.2 table, using the existing workers and a standard-session adapter with Digest-only public submission.

**Architecture:** One instance-owned async table and a registry of borrowed session views connect Standard to the existing async and detached workers. The C state lock covers resolution, decoding, worker calls, binding changes, and publication; the existing job lease controls execution and delivery. An independent pinned-header consumer proves attached execution, allocation revocation, and SQLite recovery through public table slots.

**Tech Stack:** Haskell GHC2024, GHC `9.10.3`, cabal-install `3.12.1.0`, C11 on Linux x86-64 LP64, OpenSSL `4.0.2`, SQLite, Python 3, Tasty/HUnit, POSIX processes and memory protection.

**Spec:** [Complete approved async design](../specs/2026-09-30-async-routing-design.md), committed as `170c679c268dcfbd254202953b3508d146fad6b1`.

## Global Constraints

- Implementation starts from inspected `main` at `170c679c268dcfbd254202953b3508d146fad6b1` (`170c679`). The spec's earlier source-inspection revision is historical context; the complete committed spec is the requirements source for this plan.
- Drafting boundary: only `docs/superpowers/plans/2026-09-30-async-routing.md` is written now. Every edit, test, command, evidence artifact, and filing below describes subsequent implementation work. This plan claims no observed test failure, gate result, lane result, consumer result, or upstream filing.
- Preserve the pre-existing untracked `ws/` and `HANDOFF.md`. All commands below start at `/home/user/src/m/haskoki-ws/haskoki`. Scratch validation tools live under `/tmp/haskoki-async-routing`; implementation evidence lives under `dist-release-evidence/async-routing`. Neither is created while drafting.
- D1-D12 remain outside scope. Keep `src/Haskoki/Runtime/Async.hs` and `src/Haskoki/Runtime/Detached.hs` byte-identical to the starting revision. Keep scheduler transitions, epochs, cancellation policy, detached formats, retention, first-attachment policy, authentication, recipes, and mechanisms unchanged. Recovery operations, dual operations, authenticated wrapping, key-template submission, async Sign/message/multipart producers, threads, timers, and new configuration semantics are outside this slice.
- The public producer is a fresh full-buffer one-shot `C_Digest` on an explicit `CKF_ASYNC_SESSION`. Recognizing `C_Sign` is selector validation and identity preservation; it grants no new submission capability. Ordinary sessions and staged recalls remain synchronous.
- One `AsyncTable` of capacity `8` belongs to each `StdInstance`. Views share the exact `siEnv`, `siBackend`, and table, use actual `SessionId` values, and own separate live-handle sets. SQLite uses one `openDetached` on the existing `StdStore` and home token; only home-slot views receive that detached context. Standard memory mode retains `siStore = Nothing` and its no-store errors.
- New Complete performs exactly one existing poll and, when ready, one existing completion. Private version `1` becomes public version `0`; private Join `CKR_PENDING` becomes public `CKR_OK` only after binding installation. Proof exports and their query/short dialogues do not change.
- Boundary order is liveness → structural arguments → lock → authoritative `live_std()` → `withStdCtx` → `withStdSession` → bounded selector decode → exact binding/worker → publication → one unlock. Preserve the existing initial-peek race behavior. Never cast an instance to `AsyncCtx`, a session to a job pointer, or open a second proof context behind a table call.
- Header pin: latchset `c5e61990c5621a9b955fc208644fe8145ac0a75d`; `spec/vendor/pkcs11.h` SHA-256 `61e0b3f996fa9f095859d7d3b8e361d0b982de69fc8b6a4bf10291afbe7e24d8`. Preserve `spec/sources.lock.json`. `CK_ASYNC_DATA` is `40` bytes, with offsets `0,8,16,24,32`; `CK_ULONG` and pointers are `8` bytes.
- ABI counts remain `68/92/92/104` for `2.40/3.0/3.1/3.2`; async ordinals remain `100/101/102`. The independent layout test's zero-based slot indices remain `99/100/101`. Older tables have no async tail; never enlarge-cast them. Preserve message and KEM routes and all other stub assignments.
- Mechanism artifacts `spec/mechanisms.json` and `cbits/mech_catalog.inc` remain byte-identical, with `316` existing rows and unchanged flags. Async session/token capability bits are not mechanism flags.
- All three function contracts remain `planned-with-behavior`, with the existing `haskoki-export:haskoki_hs_async_*` entries, ordinals, layouts, acceptance ids, and previous evidence. The catalog remains `104` rows: `70` planned, `32` unsupported, `2` not applicable.
- Use `haskoki-dev:ghc-9.10.3` from `toolchain.lock` (which records image id `sha256:5383beb2b6b3d8744f4fe49c6025b3aaf61ef0301a05a01a679519498601faa5`). Record the locally measured `docker image inspect` id at runtime as the toolchain identity, following message-routing precedent; it is not a fixed expected value. Build and load the module in the same container for focused native runs. Host `scripts/run-gates.sh` supplies its own containers.
- Every source-changing task writes its assertions before the corresponding implementation, runs them to observe the specified failure, implements the bounded change, and reruns them. A different failure is investigated before continuing. An absent symbol may be the initial failure; it is not evidence of runtime behavior. Evidence-only tasks validate missing evidence before collecting it, without manufacturing a provider failure.
- Every task closes with its exact source diff, command records, and artifacts for coordinator review. The coordinator owns commits. A later edit invalidates affected verification; final acceptance requires a clean tracked final revision and fresh evidence for it.
- The command recorder below captures launches and exits; complete each stage's receipt before review with hashes of its exact changed source files, including newly created consumer files, measured toolchain image id, actual module/bundle paths and hashes where used, proxy pin where used, oracle source pin, and artifact paths/hashes. For compilation-only or source-only commands, explicitly record that no module was loaded. Never relabel an unrelated existing binary as that command's input. Store these additions in the corresponding `*-command.json`; keep raw logs unchanged.
- Gate requirement: all `18` static gates, forced build, all Cabal suites, the existing `14` container drivers, release build, and installation check. The release manifest has `16` successful steps including build/install. Add no driver.
- Oracle order: `fast`, findings inspection, then `kat`, findings inspection. Preserve previous wrapper outputs before overwriting them. Wrapper exit `0` can include oracle exit `1` and does not establish a clean lane. No oracle-tree edits, widened success sets, or unconditional skips are allowed.
- A provider defect requiring runtime, detached-policy, or mechanism changes blocks acceptance and is reported separately. Missing actual upstream filings also block the associated acceptance. Function-level routing evidence is not a general async or PKCS #11 conformance claim.

## Review Focus

- A session on another slot must not detach under the home token's identity; Task 2 checks the view's absent detached context and retained attached execution.
- Submission or Join can allocate a handle before binding installation fails; Tasks 2–3 inject that failure and require cancellation, zero leaked live handles, and no stale output address.
- A worker can free a terminal handle before the adapter observes its return; Task 3 reconciles with live-set membership, never a freed-token dereference.
- A pending record's effective capacity can exceed its eventual result length; Tasks 3 and 6 distinguish pending `64` versus ready `32` and require retryable refusals.
- A successful payload write can precede a failed durable delivery mark; Task 3 keeps `jcMarkError` evidence separate from Task 7's successful-store restart proof and claims no crash-safe exactly-once guarantee.

## Files

| Area | Action and exact paths | Responsibility |
|---|---|---|
| Decoder and adapter | Modify `ffi/Haskoki/FFI/Async.hs`, `ffi/Haskoki/FFI/Standard.hs` | Bounded names, borrowed views, exact bindings, Digest admission, standard async exports, cleanup. |
| Haskell assertions | Modify `tests/model/StandardSurfaceSpec.hs`, `tests/engine/AsyncEngineSpec.hs`, `tests/engine/DetachedEngineSpec.hs` | The ten named spec cases plus exact-key unit coverage; retain every existing case. |
| C surface | Modify `cbits/standard_surface.c`, `cbits/exports.c` | Existing session-boundary plumbing, exact three prototypes, ordered guards, locked dispatch. |
| ABI generation | Modify `scripts/generate-abi.py`; regenerate `cbits/abi_stubs.inc` | Only the three `routed320` additions and generated changes. |
| Consumer | Create `tests/c/async_routed.c`; modify `scripts/test-consumers.sh`, `scripts/test-proxy-parity.sh` | Public attached/detached/restart proofs, one enumeration per script, filed proxy disposition. |
| Contract generation | Modify `scripts/generate-function-contracts.py`; regenerate `spec/function-contracts.json` | Append executed evidence to the existing three rows. |
| Reachability and operations | Modify `cbits/async_trampoline.h`, `docs/demo-walkthrough.md`, `docs/operations-notes.md`, `docs/async-config-design.md`; update route prose in `cbits/exports.c` | Public/private distinction, storage/admission limits, output ownership, durable limitation, unchanged D1-D12. |
| Qualification documents | Modify `docs/pkcs11-oracle-triage.md`, `docs/pkcs11-check-upstream-issues.md` | Actual findings, independent comparisons, classifications, distinct proxy filing, actual oracle issue URLs. |
| Scratch validation and evidence | Create implementation-time files explicitly named in Tasks 1, 4–5, and 7–12 under `/tmp/haskoki-async-routing` and `dist-release-evidence/async-routing` | Reproducible commands, actual exits, hashes, reviews, final manifest; no new repository driver. |
| Read-only invariants | `src/Haskoki/Runtime/Async.hs`, `src/Haskoki/Runtime/Detached.hs`, `core/Haskoki/Recipe/Digest.hs`, `core/Haskoki/Output.hs`, `spec/vendor/pkcs11.h`, `spec/sources.lock.json`, `cbits/abi_generated.h`, `spec/abi-inventory.json`, `spec/abi-reconciliation.json`, `spec/mechanisms.json`, `cbits/mech_catalog.inc`, `tests/c/layout_320.c`, `tests/model/FfiAsyncSpec.hs`, `tests/c/async_attached.c`, `tests/c/async_detached.c`, `tests/c/async_restart.c`, `scripts/test-async-attached.sh`, `scripts/test-async-detached.sh`, `scripts/run-gates.sh`, `scripts/release-evidence.sh`, `toolchain.lock` | Reuse and verify without editing. Other specs/plans and the pinned oracle/proxy trees remain untouched. |

## Tasks

Coverage includes every numbered section and subsection of the complete spec:

| Spec section | Tasks |
|---|---|
| 1 | 1–12 |
| 2 | 1–4, 6–7, 12 |
| 2.1 | 2–4, 6–7 |
| 2.2 | 3–6 |
| 2.3 | 2–3, 7 |
| 3 | 1–8, 11 |
| 3.1 | 3–4, 6 |
| 3.2 | 3–4, 6 |
| 3.3 | 1, 3–4, 6 |
| 3.4 | 2–4, 6 |
| 3.5 | 3, 6–7 |
| 3.6 | 5, 9, 12 |
| 3.7 | 6–8, 11 |
| 4 | 1–4, 6–7, 11 |
| 4.1 | 1, 3–4, 6 |
| 4.2 | 3, 6 |
| 4.3 | 3, 6–7, 11 |
| 5 | 1–12 |
| 5.1 | 1–3, 9 |
| 5.2 | 6–7 |
| 5.3 | 3–4, 6 |
| 5.4 | 7 |
| 5.5 | 8–9, 11–12 |
| 5.6 | 10–12 |
| 5.7 | 7–12 |
| 6 | 5–12 |

### Task 1: Bounded selector decoder and exact binding keys

**Spec trace:** §§1, 2.2, 3.3, 4.1, 5.1.

**Files:** Modify `ffi/Haskoki/FFI/Async.hs`, `ffi/Haskoki/FFI/Standard.hs`, `tests/model/StandardSurfaceSpec.hs`. Create implementation-time command recorder `/tmp/haskoki-async-routing/record.py`.

**Interfaces:** Export `decodeAsyncFunctionName :: Ptr Word8 -> IO (Either ReturnCode JobFunction)` from the FFI Async module. Add the Haskell-only helper `lookupStdAsyncBinding :: SessionId -> JobFunction -> Map (SessionId, JobFunction) a -> Maybe a` in Standard; subsequent tasks instantiate `a` with the binding record. This helper selects only the exact pair and performs no worker call.

- [ ] Create the scratch directory and this command recorder during implementation. It records real command exits even on the expected initial failure. Its arguments are evidence name, `zero` or `nonzero`, then the command and its arguments.

```sh
mkdir -p /tmp/haskoki-async-routing
mkdir -p dist-release-evidence/async-routing
```

```python
import hashlib
import json
import subprocess
import sys
from pathlib import Path

name, expectation, *command = sys.argv[1:]
root = Path('dist-release-evidence/async-routing')
log = root / (name + '.log')
record = root / (name + '-command.json')
log.parent.mkdir(parents=True, exist_ok=True)
assert expectation in ('zero', 'nonzero') and command
assert not log.exists() and not record.exists(), 'archive earlier evidence first'
revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
patch = subprocess.check_output(['git', 'diff', '--binary', 'HEAD'])
with log.open('wb') as stream:
    result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
payload = dict(source_revision=revision, command=command, exit=result.returncode,
               expectation=expectation, log=str(log),
               log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
               tracked_patch_sha256=hashlib.sha256(patch).hexdigest(),
               toolchain_image='haskoki-dev:ghc-9.10.3')
record.write_text(json.dumps(payload, indent=2) + '\n')
print(json.dumps(payload, indent=2))
assert (result.returncode == 0) == (expectation == 'zero')
```

- [ ] Add `caseAsyncFunctionNames` and `caseAsyncBindingLookup`, registered under those exact test labels in `StandardSurfaceSpec`. Assert `C_Sign` → `JobSign` → code `1`, `C_Digest` → `JobDigest` → code `2`. Refuse empty, `c_Digest`, `C_DIGEST`, `C_Digestx`, byte `0x80`, `1`, `2`, `sign`, `digest`, `C_GenerateKey`, `C_GenerateKeyPair`, and `32` non-NUL bytes with `Left CKR_ARGUMENTS_BAD`. A `31`-byte invalid name followed by NUL still refuses but reads no byte `33`. `C_Digest\0junk` succeeds and ignores the suffix allocation. Include a bounded allocation ending at the first NUL; Task 6 adds protected-page corroboration.
- [ ] In `caseAsyncBindingLookup`, use distinct canary values at `(SessionId 1, JobDigest)`, `(SessionId 1, JobSign)`, and `(SessionId 2, JobDigest)`; assert each exact selection and `Nothing` for absent keys. No test casts these numbers to native job pointers.
- [ ] Run before adding the decoder/helper bodies.

```sh
python3 /tmp/haskoki-async-routing/record.py task-1/before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests --test-show-details=direct --test-options='-p /caseAsync/'
```

Expected: nonzero with the missing `decodeAsyncFunctionName` or `lookupStdAsyncBinding` export identified in `task-1/before.log`; no runtime pass is inferred from a compilation failure.

- [ ] Implement the decoder with sequential byte peeks, at most `32` total, stopping immediately on NUL. Accept only the two exact ASCII byte strings. Do not use `peekCString` for this decoder or alter `codeJobFunction`'s existing key/key-pair mapping. Implement the exact-key lookup without fallback to another function or session.
- [ ] Run the focused tests again and inspect the diff.

```sh
python3 /tmp/haskoki-async-routing/record.py task-1/after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests --test-show-details=direct --test-options='-p /caseAsync/'
git diff --check
git diff -- ffi/Haskoki/FFI/Async.hs ffi/Haskoki/FFI/Standard.hs tests/model/StandardSurfaceSpec.hs
```

**Acceptance:** Both new cases pass, all listed malformed names yield `CKR_ARGUMENTS_BAD`, selector codes remain `1/2`, and there is no unbounded selector read or cross-key lookup. `task-1/before.log`, `task-1/after.log`, and their command JSON files identify the observed cycle. End with the reviewable diff and coordinator review; the worker makes no commit.

### Task 2: Borrowed ownership and Digest-only admission

**Spec trace:** §§1, 2.1, 2.3, 3.4, 4.3, 5.1.

**Files:** Modify `ffi/Haskoki/FFI/Standard.hs`, `tests/engine/AsyncEngineSpec.hs`, and only the existing open-session/session-info foreign declarations and corresponding calls in `cbits/standard_surface.c` needed to keep their ABI synchronized.

**Interfaces:** Add `StdAsyncBinding` with fields `sabFunction :: JobFunction`, `sabHandle :: StablePtr JobHandle`, `sabOutput :: Ptr Word8`, and `sabCapacity :: Word64`. Extend `StdInstance` with `siAsyncTable :: AsyncTable`, `siDetach :: Maybe DetachCtx`, `siAsyncViews :: IORef (Map SessionId (StablePtr AsyncCtx))`, and `siAsyncBindings :: IORef (Map (SessionId, JobFunction) StdAsyncBinding)`. Use exported record fields for Haskell tests, without a public fault-control API.

Retain existing Haskell helper call sites by making `haskokiStdOpenSession` call `haskokiStdOpenSessionWithAsync` with async intent `0`, and `haskokiStdGetSessionInfo` discard a private async output. Point the existing foreign export names at these new helper implementations, updating both fallback C declarations and calls together:

```haskell
haskokiStdOpenSessionWithAsync
  :: StablePtr StdInstance -> CULong -> CULong -> CULong
  -> Ptr CULong -> IO CULong
haskokiStdGetSessionInfoWithAsync
  :: StablePtr StdInstance -> CULong
  -> Ptr CULong -> Ptr CULong -> Ptr CULong -> Ptr CULong
  -> Ptr CULong -> IO CULong
```

The open arguments after the instance are slot, existing read-only scalar, explicit async scalar, and output handle. Session-info outputs remain slot, read-only, login, device error, followed by async scalar. The C open caller forwards `(flags & CKF_ASYNC_SESSION) != 0`; Task 4 changes its allowed-bit guard. Task 4 also adds the reported public capability bits. These helper choices add no second public session API.

- [ ] Add `caseAsyncBorrowedOwnership` and `caseAsyncAdmissionWidths` to `AsyncEngineSpec`, each taking the existing `envLock`. Open Standard with resolved configurations; use `withEnvLock` for environment changes. Assert the actual distinct session ids, shared environment/backend/table, separate live sets, and one instance table of capacity `8`. Preserve `FfiAsyncSpec` and all existing acquisition cases.
- [ ] Test memory attached service and absent detached context; SQLite home-slot context over the exact already-owned store; another slot with no detached context; ordinary views not enabled for async. Test a failed detached-context allocation and a failed view installation through test-local acquisition/exception injection: no leaked view, store writer, backend, or session admission. Keep production acquisition brackets responsible for unwind. Backend shutdown occurs once at instance close, never when a borrowed view closes.
- [ ] Test fresh SHA-256 `abc` admission at capacity `32`: `CKR_PENDING`, input copied, output and length unchanged, function code `2`, two logical polls. Assert effective capacity `min callerCapacity maxOutputBytes`, where `maxOutputBytes = 16777216`, using capacity metadata rather than allocating beyond the bound. Resolve widths through `digestRecipeFor`/`drOutLen`; exercise every available fixed-width digest recipe without duplicating a mechanism-width table. A recipe lookup miss takes the existing synchronous path.
- [ ] Pin null-output query → `CKR_OK` with length `32`; present capacities `0` and `31` → `CKR_BUFFER_TOO_SMALL` with need `32`; their subsequent staged recall stays synchronous. All these paths allocate zero handles/bindings. Ordinary sessions complete synchronously. With eight live jobs in eight explicit async sessions, the ninth start returns `CKR_HOST_MEMORY` and leaves eight bindings; after one cancellation, retry succeeds. Inject binding-installation failure after start and require cancellation before unwind, leaving no untracked handle.
- [ ] Run the new cases before implementing their paths.

```sh
python3 /tmp/haskoki-async-routing/record.py task-2/before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-engine-tests --test-show-details=direct --test-options='-p /caseAsync/'
```

Expected: missing borrowed fields/helpers, or the fresh full-buffer Digest still returning synchronous `CKR_OK` where the new assertion requires `CKR_PENDING`.

- [ ] Allocate the shared table and optional detached context during instance assembly. Use `openDetached (stdStore ss) (stdToken ss)` once. Allocate each view with the exact standard session and its own empty live set, enabling only explicitly async sessions after successful model creation. Keep view allocation and publication exception-safe. Never call `haskokiAsyncClose` or `asyncCloseCtx` on a view.
- [ ] Add Digest admission only after existing session/input decoding, planner refusals, and staged-recall checks. A fresh adequate-buffer `Execute` plan for the existing `FxDigest` path calls `haskokiAsyncStart` on the borrowed view with numeric function `2`, capped capacity, and ticks `2`; bind only a successful live handle. Retain only output address/capacity/function/handle, never input or length-word pointers. Do not read scenario-runner `async.enabled` or `async.pending_polls`.
- [ ] Add the ownership portion of close-one/close-all/finalize cleanup now, so the new admission path can always release its resources: cancel live handles through `haskokiAsyncCancel`, remove bindings, retire the detached live table at finalize, free borrowed views, then close Standard's backend/store. Task 3 adds the complete selection and arbitration assertions.
- [ ] Run the focused and retained suites, confirming the unchanged Haskell session helper callers still compile and pass. Inspect the three-file diff.

```sh
python3 /tmp/haskoki-async-routing/record.py task-2/after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-engine-tests --test-show-details=direct --test-options='-p /caseAsync/'
python3 /tmp/haskoki-async-routing/record.py task-2/retained zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests haskoki-engine-tests --test-show-details=direct
git diff -- ffi/Haskoki/FFI/Standard.hs tests/engine/AsyncEngineSpec.hs cbits/standard_surface.c
```

**Acceptance:** New ownership/admission cases pass; table occupancy is `8`, ninth refusal is `CKR_HOST_MEMORY`, query/short/recall occupancy is `0`, successful start leaves caller output/length intact, and allocation-failure cleanup leaves `0` leaked handles. Runtime files remain byte-identical. End with a reviewable diff and coordinator review; the worker makes no commit.

### Task 3: Standard completion, detach, Join, and cleanup transactions

**Spec trace:** §§1, 2.1–2.3, 3.1–3.5, 4.1–4.3, 5.1, 5.3.

**Files:** Modify `ffi/Haskoki/FFI/Standard.hs`, `tests/model/StandardSurfaceSpec.hs`, `tests/engine/AsyncEngineSpec.hs`, `tests/engine/DetachedEngineSpec.hs`.

**Interfaces:** Add these exact Haskell functions and foreign exports. Existing worker signatures and foreign export conventions stay intact.

```haskell
haskokiStdAsyncComplete
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr AsyncData -> IO CULong
haskokiStdAsyncGetId
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdAsyncJoin
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong
  -> Ptr Word8 -> CULong -> IO CULong
```

Foreign names: `haskoki_std_async_complete`, `haskoki_std_async_get_id`, `haskoki_std_async_join`. Consume the Task 1 decoder, Task 2 registry, `haskokiAsyncPoll`, `haskokiAsyncComplete`, `haskokiAsyncGetId`, `haskokiAsyncJoin`, and `haskokiAsyncCancel` directly in Haskell. Do not introduce a round trip through C.

- [ ] Register `caseAsyncSurfaceSessionOrder` in `StandardSurfaceSpec`; register `caseAsyncPublicCompletion`, `caseAsyncEpochSurface`, and `caseAsyncCleanupSurface` in `AsyncEngineSpec`; register `caseAsyncJoinBoundary`, `caseAsyncReadyJoinCapacity`, and `caseAsyncOpaqueSurface` in `DetachedEngineSpec`. Use these exact case names as test labels and retain all earlier cases. Engine cases use `envLock` where configuration is touched.
- [ ] Pin session-before-name precedence, exact-session/function binding absence → `CKR_OPERATION_NOT_INITIALIZED`, and no ticking/canceling another job. Invalid session plus empty or unterminated selector returns `CKR_SESSION_HANDLE_INVALID`. All early refusal structs/id sentinels remain unchanged. Task 4 covers the preceding C-only structural/lifecycle stages.
- [ ] In `caseAsyncPublicCompletion`, initialize every public struct byte and output byte to `0xa5`; test incoming null/zero fields and a different valid pointer/capacity in independent runs. First Complete returns `CKR_PENDING` with all `40` bytes and the bound allocation unchanged. Second delivers SHA-256 `abc`, public version `0`, bound pointer, length `32`, object fields `0/0`, and removes the binding. Repeat Complete returns `CKR_OPERATION_NOT_INITIALIZED`. A terminal worker error returns the bound pointer but leaves all other public fields and payload unchanged; reconcile freed handles through `acLive` membership. If a terminal error still owns a live handle, cancel it before removing its binding. A deliberately undersized private sink reports `CKR_BUFFER_TOO_SMALL`, pointer/need, and retains its binding; a normally admitted fixed-width job reaching that state blocks acceptance as an adapter defect.
- [ ] In `caseAsyncJoinBoundary`, preserve this entire spec §4.2 table. Seed controlled store records or use existing test-local store fault wrappers to satisfy all earlier checks; do not modify runtime policy to manufacture an outcome.

| Condition after earlier checks | Exact result |
|---|---|
| Unknown id, unknown record/recipe version, stale token generation | `CKR_SAVED_STATE_INVALID` |
| Idle id for another decoded function | `CKR_ARGUMENTS_BAD` |
| Persistent id already attached | `CKR_OPERATION_ACTIVE` |
| Delivered record | `CKR_ARGUMENTS_BAD` |
| Canceled record | `CKR_FUNCTION_CANCELED` |
| Failed record or store failure | `CKR_GENERAL_ERROR` |
| Invalid/wrong-slot session in worker validation | `CKR_SESSION_HANDLE_INVALID` |
| Session not enabled for async | `CKR_SESSION_ASYNC_NOT_SUPPORTED` |
| Existing authentication check refuses | `CKR_USER_NOT_LOGGED_IN` |
| Missing matching operation or replay effect mismatch | `CKR_OPERATION_NOT_INITIALIZED` |
| Capacity `0` or `16777217` | `CKR_ARGUMENTS_BAD` |
| Positive capacity below need | `CKR_BUFFER_TOO_SMALL` |
| Live table at capacity `8` | `CKR_HOST_MEMORY` |

Also assert unknown id plus capacity `0` → `CKR_SAVED_STATE_INVALID`; active id plus Sign selector or capacity `1` → `CKR_OPERATION_ACTIVE` on a free target; occupied target → `CKR_OPERATION_ACTIVE` before allocating a second handle. Refusals create no handle/binding and preserve a retryable idle record where applicable. Ordinary standard no-store/non-home views retain `CKR_GENERAL_ERROR`; the wrong-slot worker assertion uses the existing store-bound worker fixture to reach that worker check.

- [ ] In `caseAsyncReadyJoinCapacity`, detach a pending capacity-`64` job and require Join `32` → `CKR_BUFFER_TOO_SMALL`, private need `64`, no new binding; retry `64` succeeds. Separately hold a ready `32`-byte result from capacity `64`, detach it, and require Join `31` → short with private need `32`, Join `32` → public `CKR_OK`. The public by-value capacity has no need output and Join never reads or writes payload bytes. Matching `C_DigestInit` on the target is mandatory.
- [ ] Test GetID durability/revocation: success produces nonzero scalar id, frees private handle, removes binding and old address; early failures preserve `0xa5a5a5a5a5a5a5a5`. Worker no-store, numeric wrong-function, unsaveable, and store-failure cases zero the id and keep the live job. `caseAsyncOpaqueSurface` obtains the live `JobId` through `sessionJobs` on a fresh single-job test session, uses existing `markJobOpaque`, calls the new standard worker, and requires `CKR_STATE_UNSAVEABLE`, id `0`, zero new durable records, unchanged binding, then exact completion. It never casts or dereferences the opaque native handle to find a job id. A missing home token is `CKR_TOKEN_NOT_PRESENT`; keep ambiguous-commit reload/reconciliation behavior visible in the retained proofs.
- [ ] Pin epochs with `inspectJob`: initial `0`, first poll still `0`, ready `1`, delivery `2`; pending cancellation moves `0` to `1`. Use `sessionJobs` while the job is live to capture its runtime id, `tableStats` for `(live, terminal tombstones, next job id)`, and `deliveredCount` for the once-only assertion. The ready-state inspection can use the existing poll worker in the Haskell fixture; public Complete still performs poll-plus-delivery in one transaction. Private query/short/wrong-function refusals preserve epoch and delivery count. Use deterministic ordering/barriers, never timing sleeps. Retain the original private null-value sizing and short-completion cases unchanged.
- [ ] Cover cleanup selection: second well-shaped Digest and occupied-slot Init/Update/Final return `CKR_OPERATION_ACTIVE` without replacement; invalid classic Digest arguments retire the affected binding before existing slot termination. SessionCancel is planned/validated before cleanup, selected Digest/cancel-all cancel it, unrelated selectors preserve it, and invalid masks preserve it. Close-one affects only that session; close-all affects only the requested slot; finalize cancels remaining attachments and retains idle durable records. Source close/cancel after detach leaves the record joinable. Joined cancellation goes through `cancelJoined`; later Join is `CKR_FUNCTION_CANCELED`. Complete-first delivers once, then cancellation cannot undo the bytes; cancel-first leaves no operation and writes nothing.
- [ ] Inject failure after successful private Join but before binding publication; require worker cancellation and no live-handle leak. Separately inject a durable delivery-mark failure: `jcMarkError` is recorded, payload delivery still succeeds once in memory, and no claim is made about crash-safe repeat suppression after that failed mark. Keep this evidence separate from successful SQLite restart.
- [ ] Run before adding the standard exports/transactions.

```sh
python3 /tmp/haskoki-async-routing/record.py task-3/model-before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests --test-show-details=direct --test-options='-p /caseAsyncSurfaceSessionOrder/'
python3 /tmp/haskoki-async-routing/record.py task-3/engine-before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-engine-tests --test-show-details=direct --test-options='-p /caseAsync/'
```

Expected: the missing `haskokiStdAsyncComplete`, `haskokiStdAsyncGetId`, or `haskokiStdAsyncJoin` interfaces prevent the new transaction assertions from passing.

- [ ] Implement resolution via `withStdCtx`, then `withStdSession`, then bounded decode. Complete/GetID use the exact binding; Join needs no source binding. Use an aligned private `40`-byte completion struct initialized from the binding. Poll once; complete only on readiness; translate pointer/version/length/handles only as specified. Convert GetID's `Ptr CULong` to the worker's `Ptr Word64` only under the pinned LP64 width. Join uses private handle and need slots and publishes public success only after installation. Mask allocation/publication cleanup windows and retain the C exception-to-error fence.
- [ ] Run both focused commands and the retained suites; compare the runtime files with the starting revision and inspect the four-file diff.

```sh
python3 /tmp/haskoki-async-routing/record.py task-3/model-after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests --test-show-details=direct --test-options='-p /caseAsyncSurfaceSessionOrder/'
python3 /tmp/haskoki-async-routing/record.py task-3/engine-after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-engine-tests --test-show-details=direct --test-options='-p /caseAsync/'
python3 /tmp/haskoki-async-routing/record.py task-3/retained zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests haskoki-engine-tests --test-show-details=direct
git diff --exit-code 170c679c268dcfbd254202953b3508d146fad6b1 -- src/Haskoki/Runtime/Async.hs src/Haskoki/Runtime/Detached.hs
git diff -- ffi/Haskoki/FFI/Standard.hs tests/model/StandardSurfaceSpec.hs tests/engine/AsyncEngineSpec.hs tests/engine/DetachedEngineSpec.hs
```

**Acceptance:** All ten spec-named cases now exist across the three suites and pass their Haskell assertions; Task 1's additional key case also passes. Every Join row and combined case has the exact code above, refusal retry preserves state, delivery count is `1`, stale native handles are never dereferenced, and failure cleanup leaks `0` handles. Runtime files are unchanged. End with coordinator review of the diff and logs; the worker makes no commit.

### Task 4: C prototypes, structural guards, and locked routing bodies

**Spec trace:** §§2.1–2.2, 3.1–3.4, 4.1, 5.1, 5.3.

**Files:** Modify `cbits/standard_surface.c`, `cbits/exports.c`. Create scratch `/tmp/haskoki-async-routing/surface-probe.c` and `/tmp/haskoki-async-routing/surface-probe` during implementation.

**Interfaces:** Define the following exact functions in `standard_surface.c`; declare them in `exports.c` before the generated include.

```c
CK_RV std_AsyncComplete(CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR *pFunctionName, CK_ASYNC_DATA *pResult);
CK_RV std_AsyncGetID(CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR *pFunctionName, CK_ULONG *pulID);
CK_RV std_AsyncJoin(CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR *pFunctionName, CK_ULONG ulID,
    CK_BYTE *pData, CK_ULONG ulData);

unsigned long haskoki_std_async_complete(void *instance,
    unsigned long session, unsigned char *functionName, void *result);
unsigned long haskoki_std_async_get_id(void *instance,
    unsigned long session, unsigned char *functionName, unsigned long *id);
unsigned long haskoki_std_async_join(void *instance,
    unsigned long session, unsigned char *functionName, unsigned long id,
    unsigned char *data, unsigned long capacity);
```

Keep generated-stub-header preference and add the three fallback declarations with precisely these LP64 shapes.

- [ ] Write an internal boundary probe following the message plan's production-translation-unit inclusion pattern. Include `/work/cbits/standard_surface.c`, supply the three mock standard exports plus liveness/lock hooks, and let section garbage collection discard unrelated functions. Use the included `haskoki_std_install` to set or clear its instance; do not redefine the translation unit's own `haskoki_std_get`. Assert exact original pointers/scalars, instance identity, one worker call under lock depth `1`, and exactly one unlock after successful lock acquisition. Compile through the pinned typedefs `CK_C_AsyncComplete`, `CK_C_AsyncGetID`, and `CK_C_AsyncJoin`.
- [ ] Probe each route with inactive interval, each structural null shape, `CKR_CANT_LOCK` injection, missing authoritative instance after a successful initial peek, and a mock worker returning each of `CKR_OK`, `CKR_PENDING`, and `CKR_GENERAL_ERROR`. Inactive/structural paths call no worker and acquire no lock; lock refusal causes no unlock; absent-instance/worker paths unlock once. The mock checks that null/zero and present/zero Join reach Haskell, that unknown/empty name contents are not read in C, and that no argument-refusal path calls `haskoki_std_terminate_slot`.
- [ ] Compile before adding the C bodies.

```sh
python3 /tmp/haskoki-async-routing/record.py task-4/before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-async-routing:/tmp/haskoki-async-routing -w /work haskoki-dev:ghc-9.10.3 cc -std=c11 -O2 -g -Wall -Wextra -Werror -ffunction-sections -fdata-sections -Ispec/vendor -Icbits /tmp/haskoki-async-routing/surface-probe.c -Wl,--gc-sections -lpthread -o /tmp/haskoki-async-routing/surface-probe
```

Expected: nonzero because the three `std_Async*` definitions are absent.

- [ ] Implement the `std_Sign` liveness/lock/instance skeleton with plain `CKR_ARGUMENTS_BAD` guards: Complete tests name then result; GetID tests name then id pointer; Join tests name then null data with positive capacity. Use no `refuse_null_arg` call. Forward Join capacity by value, with no read/copy of its buffer and no sixth parameter. Return lock failures verbatim and unlock exactly once on each acquired-lock path.
- [ ] Extend `std_OpenSession`'s allowed bits to serial/read-write/async, preserving output-pointer, missing-serial, unknown-bit order. Finish Task 2's session-info plumbing by including the accepted async bit in `CK_SESSION_INFO.flags`; include `CKF_ASYNC_SESSION_SUPPORTED` in token flags for attached service. Preserve mechanism artifacts and other capability bits.
- [ ] Repeat compilation as `task-4/compile zero`, run the probe as `task-4/probe zero`, and build the foreign library as `task-4/library zero`:

```sh
python3 /tmp/haskoki-async-routing/record.py task-4/compile zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-async-routing:/tmp/haskoki-async-routing -w /work haskoki-dev:ghc-9.10.3 cc -std=c11 -O2 -g -Wall -Wextra -Werror -ffunction-sections -fdata-sections -Ispec/vendor -Icbits /tmp/haskoki-async-routing/surface-probe.c -Wl,--gc-sections -lpthread -o /tmp/haskoki-async-routing/surface-probe
python3 /tmp/haskoki-async-routing/record.py task-4/probe zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-async-routing:/tmp/haskoki-async-routing -w /work haskoki-dev:ghc-9.10.3 /tmp/haskoki-async-routing/surface-probe
python3 /tmp/haskoki-async-routing/record.py task-4/library zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal build flib:haskoki
```

**Acceptance:** Compilation and probe exit `0`; no prototype warning; all structural/lifecycle refusals preserve all caller bytes; lock/worker/unlock counts match the matrix; public capability reporting is session/token only. The table remains unregistered until Task 5. End with the two-file diff and coordinator review; the worker makes no commit.

### Task 5: Deterministic registration of the three 3.2 entries

**Spec trace:** §§1, 2.2, 3.1, 3.6, 6.

**Files:** Modify `scripts/generate-abi.py`; regenerate `cbits/abi_stubs.inc`. Create scratch `/tmp/haskoki-async-routing/check-registration.py`.

**Interfaces:** `routed320` gains exactly these mappings, preserving both existing KEM mappings:

```python
{
    "C_AsyncComplete": "std_AsyncComplete",
    "C_AsyncGetID": "std_AsyncGetID",
    "C_AsyncJoin": "std_AsyncJoin",
}
```

- [ ] Write the registration checker to require the three mappings inside `routed320`, zero `x32_C_AsyncComplete`, `x32_C_AsyncGetID`, and `x32_C_AsyncJoin` function bodies, and exactly one corresponding `(T)->C_Async* = std_Async*;` assignment per member inside `HASKOKI_FILL_320_NEW`. Compare generator text outside `routed320` with starting commit `170c679`; require it unchanged. Compare `cbits/abi_generated.h`, both ABI JSON files, header/lock, and both mechanism artifacts byte for byte with that commit. Assert the inventory counts/layouts and async ordinals from Global Constraints.
- [ ] Run it before editing registration.

```sh
python3 /tmp/haskoki-async-routing/record.py task-5/before nonzero python3 /tmp/haskoki-async-routing/check-registration.py
```

Expected: `C_AsyncComplete registration missing`; the checker must also detect a surviving stub if the dictionary changes without regeneration.

- [ ] Add only the three mappings and regenerate.

```sh
python3 /tmp/haskoki-async-routing/record.py task-5/generate zero python3 scripts/generate-abi.py
python3 /tmp/haskoki-async-routing/record.py task-5/after zero python3 /tmp/haskoki-async-routing/check-registration.py
```

Expected generator result: `68/92/92/104` functions; reconciliation `matched=104 added=0 removed=0 aliased=0`. Never edit the generated include manually.

- [ ] Run generation again and require byte equality for all generated artifacts; then build and inspect the diff, requiring only removal of the three stubs and their three assignment changes in the generated include.

```sh
python3 - <<'PYCODE' > dist-release-evidence/async-routing/task-5/determinism.log
import subprocess
from pathlib import Path
paths = ['cbits/abi_stubs.inc', 'cbits/abi_generated.h', 'spec/abi-inventory.json', 'spec/abi-reconciliation.json']
before = {p: Path(p).read_bytes() for p in paths}
subprocess.run(['python3', 'scripts/generate-abi.py'], check=True)
assert all(Path(p).read_bytes() == raw for p, raw in before.items())
print('PASS: all four generated artifacts byte-identical after second generation')
PYCODE
python3 /tmp/haskoki-async-routing/record.py task-5/library zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal build flib:haskoki
git diff -- scripts/generate-abi.py cbits/abi_stubs.inc
```

**Acceptance:** Exactly three new routes, no corresponding stub bodies, exact ordinals and ABI counts, unchanged old tables/message/KEM/other assignments, and no second-generation byte change. End with the two-file diff and coordinator review; the worker makes no commit.

### Task 6: Independent native attached and per-entry consumer legs

**Spec trace:** §§2.1, 3.1–3.5, 3.7, 4.1–4.3, 5.2–5.3, 6.

**Files:** Create `tests/c/async_routed.c`. No driver enumeration change until Task 7 completes the normal invocation.

**Interfaces:** `int main(int argc, char **argv)` accepts the module argument. Resolve only discovery entry points with `dlsym`, request version `3.2`, inspect that table's version, and call its typed members for all submissions/async assertions. Print stable `async:entry/leg/3.2` labels, return codes, lengths, and hex bytes; never use numeric sessions, addresses, or private handles as transcript identities. Exit `0` only with zero failed assertions, `1` on an assertion failure, `2` on fixture/setup failure.

- [ ] Write the behavioral assertion functions before their fixture helpers. Use only `spec/vendor/pkcs11.h` for Cryptoki types; add independent `_Static_assert` checks for `CK_ULONG`/pointer width `8`, result size `40`, and offsets `0,8,16,24,32`. Reuse `consumer_roundtrip.c`'s configuration/accounting/cleanup conventions and `message_routed.c`'s explicit newer-interface discovery. Assert legal discovery before initialization and all three non-null 3.2 members; never read async members of an older table.
- [ ] Implement ordinary-session controls and explicit serial/read-write/async sessions using discovered token-present home slots. Configure real OpenSSL, `allow_synthetic_fallback = false`, trace off, fresh SQLite storage for detach, and separate memory configuration for attached/no-store checks. Use payload `0xa5`, prefix/tail canaries `0xa5`, id sentinel `0xa5a5a5a5a5a5a5a5`, and whole-struct snapshots. Use a valid allocation for present-zero shapes.
- [ ] Require this complete per-entry matrix, with the full `CKR_` names in assertions:

| Leg | Exact expected observations |
|---|---|
| Before initialize and after finalize | Every entry, each null shape and otherwise well-shaped call returns `CKR_CRYPTOKI_NOT_INITIALIZED`; all outputs untouched. |
| Live structural guards | Complete null name/result, GetID null name/id, Join null name or null/nonzero buffer return `CKR_ARGUMENTS_BAD` with both valid and invalid sessions; no other job changes. |
| Session then contents | Well-shaped invalid session returns `CKR_SESSION_HANDLE_INVALID`, including empty/unterminated names and Join zero capacity. Valid-session malformed/unsupported names return `CKR_ARGUMENTS_BAD`. |
| Attached Digest | SHA-256 init with null/zero parameters returns `CKR_OK`; capacity `32` submission returns `CKR_PENDING`, unchanged length/output; overwrite input `abc` after submission. |
| Complete pending/delivery | First call preserves all `40` public bytes and output; second returns `CKR_OK`, version `0`, original pointer, length `32`, handles `0/0`, exact `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`. |
| Complete identity/repeat | Sign selector while only Digest attached, other valid session, repeated completion, or completion after detach returns `CKR_OPERATION_NOT_INITIALIZED` and changes nothing. |
| Complete public fields | One run begins with null/zero result fields, another with a different valid buffer and capacity `0`; both deliver to the original bound allocation and leave the alternate buffer unchanged. |
| Original Digest sizing | Null output returns `CKR_OK`, length `32`, no job; present capacities `0/31` return `CKR_BUFFER_TOO_SMALL`, length `32`, no job; adequate staged recall stays synchronous. |
| Occupied Digest | Well-shaped second Digest and Init/Update/Final return `CKR_OPERATION_ACTIVE` and keep the original binding. Invalid classic arguments terminate only the affected slot/binding. |
| GetID success | Pending SQLite Digest detaches with `CKR_OK` and nonzero id; old output unchanged; second GetID and GetID after delivery return `CKR_OPERATION_NOT_INITIALIZED` with sentinel unchanged. |
| GetID no store | Resolved memory job returns `CKR_GENERAL_ERROR`, id `0`, binding retained and still completes exactly. Join in this memory view returns `CKR_GENERAL_ERROR`. |
| Join success | Fresh async target, matching DigestInit, new `32`-byte allocation: `CKR_OK`, bytes unchanged during Join; subsequent progress delivers exact SHA-256 into the new allocation. |
| Join identity/state | Unknown id → `CKR_SAVED_STATE_INVALID`; idle Digest id with Sign → `CKR_ARGUMENTS_BAD`; attached id → `CKR_OPERATION_ACTIVE`; delivered id → `CKR_ARGUMENTS_BAD`; canceled id → `CKR_FUNCTION_CANCELED`. |
| Join target | Ordinary target → `CKR_SESSION_ASYNC_NOT_SUPPORTED`; missing DigestInit → `CKR_OPERATION_NOT_INITIALIZED`; occupied target → `CKR_OPERATION_ACTIVE` without replacing its buffer. |
| Join capacity | Null/nonzero refuses structurally; otherwise joinable null/zero or present/zero → `CKR_ARGUMENTS_BAD`; capacities `1/31` → `CKR_BUFFER_TOO_SMALL`; `32` succeeds. No public need output or buffer write. |
| Conservative pending capacity | Original pending capacity `64`, Join `32` → `CKR_BUFFER_TOO_SMALL`, retry `64` → `CKR_OK`, eventual length `32`. |
| Combined Join errors | On a free target, unknown id plus zero capacity → `CKR_SAVED_STATE_INVALID`; active id plus Sign or capacity `1` → `CKR_OPERATION_ACTIVE`. All applicable refusals preserve a valid later retry. |

- [ ] Add concurrent completers using a barrier after the first pending call: two calls on the one-poll-remaining job yield exactly one `CKR_OK` and one `CKR_OPERATION_NOT_INITIALIZED`, one payload delivery, and unchanged canaries. Add Digest-selected cancellation, unrelated-selector preservation, joined cancellation, and completion-first/cancellation-first sequences. Join threads before finalize.
- [ ] Add a selector at a protected page boundary to prove stopping at NUL and bounding `32` unterminated bytes; check no read beyond accessible storage. Successful table legs must never return `CKR_FUNCTION_NOT_SUPPORTED`. No private trampoline may prepare or satisfy any happy-path assertion.
- [ ] Compile the assertions before filling the missing fixture helpers; require a nonzero compile/link exit naming the missing fixture helper in `task-6/before.log`. This checks harness construction, while Tasks 1–5 supply the implementation's observed behavioral assertion cycles.

```sh
python3 /tmp/haskoki-async-routing/record.py task-6/before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor -o /tmp/haskoki-async-routed tests/c/async_routed.c -ldl -lpthread
```

- [ ] Finish the fixture and execute this focused consumer:

```sh
python3 /tmp/haskoki-async-routing/record.py task-6/direct zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 bash -ec '
cabal build all
cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor -o /tmp/haskoki-async-routed tests/c/async_routed.c -ldl -lpthread
/tmp/haskoki-async-routed /work/dist-newstyle/build/x86_64-linux/ghc-9.10.3/haskoki-0.3.0.0/f/haskoki/build/haskoki/libhaskoki.so
'
git diff --no-index -- /dev/null tests/c/async_routed.c
```

**Acceptance:** Consumer exits `0`, all matrix labels occur, expected `32` digest bytes match, every canary is preserved, and competing completion delivers once. The no-index diff exits `1` because it displays the new file; it stages nothing. The normal invocation gains revocation/restart in Task 7 before script inclusion. End with the new-file diff and coordinator review; the worker makes no commit.

### Task 7: Routed revocation, process restart, and complete script inclusion

**Spec trace:** §§2.3, 3.7, 4.3, 5.2, 5.4, 5.7, 6.

**Files:** Modify `tests/c/async_routed.c`, `scripts/test-consumers.sh`, `scripts/test-proxy-parity.sh`. Create scratch `/tmp/haskoki-async-routing/check-consumer.py`.

**Interfaces:** Normal `async_routed <module>` coordinates the full proof itself. Internal child forms are `async_routed <module> restart-write <directory>`, `restart-read <directory>`, and `restart-delivered <directory>`. The directory contains the owned SQLite database/configuration and a handoff file containing only the decimal persistent scalar id. It contains no live session, private handle, or output pointer.

- [ ] Write `check-consumer.py` before adding the new legs. It requires all Task 6 label families plus distinct `async:attached/completion/3.2`, `async:revocation/rejoin/3.2`, and `async:restart/delivery/3.2` success records in its supplied log, zero failure records, and exactly one `tests/c/async_routed.c` occurrence in each script's constructed, sorted scenario list. It checks the independence guard covers the full list and neither script silently omits a missing async fixture. Run against `task-6/direct.log`; require nonzero for missing revocation/restart and inclusion.

```sh
python3 /tmp/haskoki-async-routing/record.py task-7/before nonzero python3 /tmp/haskoki-async-routing/check-consumer.py dist-release-evidence/async-routing/task-6/direct.log
```

- [ ] Add the protected old-output leg: submit into `mmap` storage, table GetID, then `mprotect(PROT_NONE)` over the entire old allocation; finalize/reinitialize on the same SQLite path, open and initialize a fresh async target, table Join into another allocation, and complete. Keep the old page inaccessible for the entire interval. Restore read access and compare every old byte with its original canary. A protection fault fails the consumer; no signal handler converts it to success. Keep this proof distinct from the first-NUL and bounded-selector protected-page checks.
- [ ] Add separately executed restart children. The write child submits/detaches, writes only the persistent id, leaves one other non-detached job for finalize cancellation, finalizes, and exits. The read child opens the same database, creates its own session/buffers, initializes Digest, rejoins, and verifies exact delivery. A never-issued id gives `CKR_SAVED_STATE_INVALID`; a subsequent executed delivered child gives `CKR_ARGUMENTS_BAD` for the delivered id. Compare no addresses across processes. Parent checks every child exit and cleans only its owned temporary directory/config/database/children on every path.
- [ ] In both scripts, require `tests/c/async_routed.c` to exist, enumerate it explicitly once beside `consumer_*.c` and `message_routed.c`, preserve stable sorting and exactly-one validation, and run the independence guard over the complete list. Retain the existing C11/optimization/debug/warnings/include/link options. Do not add the async `DIRECT_ONLY` entry yet; Task 8 requires a real filing first.
- [ ] Run the complete direct driver and its checker.

```sh
python3 /tmp/haskoki-async-routing/record.py task-7/consumers zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-consumers.sh
python3 /tmp/haskoki-async-routing/record.py task-7/check zero python3 /tmp/haskoki-async-routing/check-consumer.py dist-release-evidence/async-routing/task-7/consumers.log
```

**Acceptance:** Both scripts enumerate the consumer once; the direct driver exits `0`; attached, revocation, and restart labels separately pass; old allocation bytes stay unchanged and all executed children exit `0`. No proxy-equivalence claim is made before Task 8. End with the three-file diff and coordinator review; the worker makes no commit.

### Task 8: Pinned proxy reproduction, distinct filing, and explicit disposition

**Spec trace:** §§3.7, 5.5, 5.7, 6.

**Files:** Modify `scripts/test-proxy-parity.sh` and `docs/pkcs11-check-upstream-issues.md`. Create scratch `proxy-probe.c`, `proxy-repro.py`, `proxy-issue.md`, `check-proxy.py` under `/tmp/haskoki-async-routing`; evidence under `dist-release-evidence/async-routing/proxy`.

**Interfaces:** Preserve the existing `DIRECT_ONLY` format `scenario:actual-issue-URL`. Its `async_routed` entry may be installed only after the new issue exists. Keep the message scenario's issue `23` attached only to `message_routed`.

| Pin | Exact required value |
|---|---|
| Proxy commit | `a48b60ba54b0163f4999c1e4fc0514bf7dc01681` |
| `/opt/pkcs11-proxy-ng/pkcs11-proxy-ng` SHA-256 | `260cb245981561291eab4d29a16cb6a4d6f00dca3431f3d583d35364fab0c9e5` |
| `/opt/pkcs11-proxy-ng/libpkcs11_proxy_ng_shim.so` SHA-256 | `8ea85073ce8436ebdc8ee99bce99e70a6d8c34473c28b5a45567c8a26aba1690` |
| Pinned `crates/shim/src/dispatch/general/async_ops.rs` SHA-256 | `cf1239e40f482755006bb1d1988b9d083f8f36312ad4d9543160e9c31c40ca72` |

- [ ] Write `check-proxy.py` to require those hashes, a reproduction transcript, direct full-consumer success, a new issue URL in the correct repository whose issue number is not `23`, a matching proxy-scoped documentation entry, and a matching `DIRECT_ONLY` entry. Run `python3 /tmp/haskoki-async-routing/check-proxy.py` before collection; expect nonzero for absent async filing/evidence. Do not guess an issue number.
- [ ] Hash the installed pair and read the exact pinned source, recording the output with `record.py` as `proxy/pins` and `proxy/source`:

```sh
sha256sum /opt/pkcs11-proxy-ng/pkcs11-proxy-ng /opt/pkcs11-proxy-ng/libpkcs11_proxy_ng_shim.so
git -C /home/user/src/m/pkcs11-proxy-ng-ws/pkcs11-proxy-ng show a48b60ba54b0163f4999c1e4fc0514bf7dc01681:crates/shim/src/dispatch/general/async_ops.rs
```

Expected: the exact pair hashes above; pinned source hash above; GetID and Join unconditional refusals at the `c_async_get_id` and `c_async_join` bodies. `c_async_complete` sends function/session without caller capacity, then copies `min(response length, caller capacity)` while returning success and using incoming caller storage. Record source lines with the source blob; do not describe this source observation as a tested Complete transport behavior.

- [ ] Implement the independent pinned-header `proxy-probe.c` to discover 3.2 through the shim, initialize/open a real session, call `C_AsyncGetID(session, "C_Digest", &id)` and `C_AsyncJoin(session, "C_Digest", 18446744073709551615UL, buffer, 32)`, and require respectively `CKR_STATE_UNSAVEABLE` and `CKR_SAVED_STATE_INVALID`. Repeat with null names/outputs and an invalid session to expose the fixed refusal behavior; preserve/log sentinels. These are refusal reproductions, not successful detach evidence.
- [ ] Implement `proxy-repro.py` with one module-path argument. It verifies the installed hashes, creates an owned SQLite backend config and proxy config using the existing script's `[backend]`, `[proxy]`, and `[listener.remote]` fields, starts only its own pinned daemon on available loopback port `17513`, checks readiness within `30` seconds, runs the probe with `PKCS11_PROXY_ENDPOINT=http://127.0.0.1:17513`, saves daemon/probe logs, and shuts down/reaps only that daemon in a `finally` path. A busy port or readiness failure fails setup; never replace another process. Use real OpenSSL and no synthetic fallback. Copy the complete Task 7 direct transcript into the proxy evidence bundle for comparison.
- [ ] Reproduce with the pinned pair mounted read-only; build and load the provider in this same container.

```sh
python3 /tmp/haskoki-async-routing/record.py proxy/reproduction zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-async-routing:/tmp/haskoki-async-routing -v /opt/pkcs11-proxy-ng:/opt/pkcs11-proxy-ng:ro -w /work haskoki-dev:ghc-9.10.3 bash -ec '
cabal build all
cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor /tmp/haskoki-async-routing/proxy-probe.c -ldl -lpthread -o /tmp/haskoki-async-routing/proxy-probe
python3 /tmp/haskoki-async-routing/proxy-repro.py /work/dist-newstyle/build/x86_64-linux/ghc-9.10.3/haskoki-0.3.0.0/f/haskoki/build/haskoki/libhaskoki.so
'
```

- [ ] Write the issue body to `/tmp/haskoki-async-routing/proxy-issue.md`: exact pin/hashes, table calls and observed codes, full direct happy-path transcript and module identity, fixed refusal source locations, and Complete capacity/ownership mismatch. File a **new distinct** async issue with this exact title, retaining the real returned URL and readback:

```sh
gh issue create --repo mingulov/pkcs11-proxy-ng --title 'Async transport cannot preserve detached jobs and output bindings' --body-file /tmp/haskoki-async-routing/proxy-issue.md > dist-release-evidence/async-routing/proxy/issue-url.txt
python3 - <<'PYCODE'
import json, re, subprocess
from pathlib import Path
root = Path('dist-release-evidence/async-routing/proxy')
url = (root / 'issue-url.txt').read_text().strip()
assert re.fullmatch(r'https://github.com/mingulov/pkcs11-proxy-ng/issues/[0-9]+', url)
assert url.rsplit('/', 1)[1] != '23'
raw = subprocess.check_output(['gh', 'issue', 'view', url, '--json', 'url,title,state,body'])
data = json.loads(raw)
assert data['url'] == url
assert data['title'] == 'Async transport cannot preserve detached jobs and output bindings'
(root / 'issue.json').write_bytes(raw)
PYCODE
```

- [ ] Record that actual URL under `## Async routing: proxy transport` in `docs/pkcs11-check-upstream-issues.md`, explicitly naming the proxy repository, pin, observed refusals, source limitation, and direct evidence. Then add `async_routed` with exactly that URL to `DIRECT_ONLY`. No guessed URL, reuse of issue `23`, or unfiled disposition is acceptable.
- [ ] Run the full parity driver and checker:

```sh
python3 /tmp/haskoki-async-routing/record.py proxy/parity zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /opt/pkcs11-proxy-ng:/opt/pkcs11-proxy-ng:ro -w /work haskoki-dev:ghc-9.10.3 env HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng scripts/test-proxy-parity.sh
python3 /tmp/haskoki-async-routing/record.py proxy/check zero python3 /tmp/haskoki-async-routing/check-proxy.py
```

**Acceptance:** Exact hash matches; actual fixed GetID/Join refusals reproduced; real new issue read back and recorded; direct `async_routed` exits `0`; the driver emits `DIRECT-ONLY: async_routed` with that URL; all eligible scenarios retain normal parity. Do not filter away `async:` lines, rebuild the pinned proxy, or count exclusion as transport equivalence. Missing filing blocks acceptance. End with the two-file diff, filing evidence, and coordinator review; the worker makes no commit.

### Task 9: Retained proofs and revision-bound gates

**Spec trace:** §§1, 3.6, 5.1, 5.5, 5.7, 6.

**Files:** No production-source changes. Evidence under `dist-release-evidence/async-routing/reviewed`; create scratch `/tmp/haskoki-async-routing/check-gates.py` and `/tmp/haskoki-async-routing/pins.py`.

**Interfaces:** `check-gates.py reviewed` validates the actual `reviewed/gates-command.json`, `reviewed/gates.log`, and `reviewed/gates/MANIFEST.txt`. `pins.py reviewed` writes `reviewed/pins.json` from current source, actual bundle/module bytes, fixed input pins, toolchain identity, and retained source invariants. The same tools accept `final` in Task 12.

- [ ] After coordinator acceptance/commits of Tasks 1–8, require `git diff --exit-code HEAD` and confirm `git status --short` contains no pending implementation files. Do not remove `ws/` or `HANDOFF.md`. Require starting runtime/header/catalog/generated-invariant bytes to match `git show 170c679c268dcfbd254202953b3508d146fad6b1:path` exactly. Do not treat an earlier passing revision as this revision's result.
- [ ] Implement the gate checker to fail when evidence is absent; require gate exit `0`, the exact final runner success line, `pass: 16 miss: 0`, each of the `14` driver records plus build/install, matching SHA-256 for every manifest log, the current revision in the release manifest, and no unexplained missing evidence. Run `python3 /tmp/haskoki-async-routing/check-gates.py reviewed` before collection; expect nonzero because no reviewed gate record exists.
- [ ] Run the retained attached/detached proof scripts unchanged and record each exit separately.

```sh
python3 /tmp/haskoki-async-routing/record.py reviewed/attached zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-async-attached.sh
python3 /tmp/haskoki-async-routing/record.py reviewed/detached zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-async-detached.sh
```

Expected: both exit `0`, preserving private result version `1`, private Join `CKR_PENDING`, handle liveness, memory-store reopen, guard-page, and two-process assertions.

- [ ] Run the host gate entry point with an explicit evidence directory.

```sh
python3 /tmp/haskoki-async-routing/record.py reviewed/gates zero env HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng HASKOKI_EVIDENCE_DIR=/home/user/src/m/haskoki-ws/haskoki/dist-release-evidence/async-routing/reviewed/gates bash scripts/run-gates.sh
python3 /tmp/haskoki-async-routing/check-gates.py reviewed
```

Expected: all `18` gates, forced build, all Cabal suites, `14` drivers, release build, and installation pass; `GATES: all passing (18 gates + cabal test + release evidence)` appears in `reviewed/gates.log`; manifest says `pass: 16 miss: 0` and identifies this HEAD. A driver/installation failure is not waived by focused tests.

- [ ] Implement `pins.py` to require exactly one directory matching `dist-release/haskoki-*` with `lib/libhaskoki.so`. Record absolute bundle path, module SHA-256, and deterministic bundle SHA-256: for each regular file in sorted bundle-relative path order, hash UTF-8 relative path, NUL, raw bytes, NUL. Record HEAD, toolchain tag and measured image id, header hash, proxy pin/pair/shim-source hashes, all invariant source hashes, and oracle pins from Task 10's table. Assert every fixed expected value before writing JSON; the toolchain image id is measured, not fixed. No invented release-tree Git revision. Run `docker image inspect haskoki-dev:ghc-9.10.3 --format '{{.Id}}'` to measure the image id. Recompute the actual module/bundle hashes before and after each lane.

**Acceptance:** Retained proofs and gate checker exit `0`; logs and manifest bind this clean implementation revision; exactly one fresh release bundle is identified. A necessary source correction returns to its owning task's assertion cycle and refreshes affected evidence. End with the evidence diff and coordinator review; the worker makes no commit.

### Task 10: Oracle source pins, minimal comparison, fast inspection, then kat inspection

**Spec trace:** §§3.7, 5.6–5.7, 6.

**Files:** No pinned-oracle or production-source changes. Create scratch `/tmp/haskoki-async-routing/oracle-getid.c`, `/tmp/haskoki-async-routing/lane.py`, `/tmp/haskoki-async-routing/inspect-lane.py`; evidence under `dist-release-evidence/async-routing/reviewed`. Document updates follow in Task 11.

**Interfaces:** `lane.py reviewed fast` and `lane.py reviewed kat` archive old wrapper outputs, invoke the exact lane wrapper through `record.py`, copy raw JSON/traces into `reviewed/fast` or `reviewed/kat`, and preserve command records. `inspect-lane.py reviewed fast` and its kat form validate human-reviewed classifications and write `reviewed/fast-inspection.json` and `reviewed/kat-inspection.json`. The same commands accept `final` for Task 12.

| Oracle path relative to `src/pkcs11_check/testcases` | All test definitions | Async-specific definitions | SHA-256 |
|---|---:|---:|---|
| `test_remaining_gaps.py` | 29 | 4 | `56ca76211694ac5c8fe8142cc550d8415d91ee39da830240db0cf0a5c9a9a33f` |
| `ckr/test_ckr_v32_raw.py` | 8 | 1 | `278d32b6509e556746c4fb3ef688315c1f21c701cdc8a2bfddcaa7bda3eafcb1` |
| `_probes/ckr_v32_raw.py` | 0 | 0 | `3167748a0ff6336d457b36f442f3156c8c6cc71892c70e58a16f70b89bb5819e` |
| `ckr/_ckr_spec.py` | 0 | 0 | `79c590d8f81c0f6bbf0b437e19a234e91411a6dd684dd98741a2210f8ca03136` |
| `ckr/_ckr_spec_tables.py` | 0 | 0 | `3df59974adfcb4e3112db1851676ce7b11f91c34d3c001458c38a5096d2aaba2` |

Oracle root is `/tmp/pkcs11-ws/pkcs11-check-0.2.2rc2`, package version `0.2.2rc2`. Full source digest over exactly `519` Python files under `src` is `b7b5327c4294a892fcf21f351717bb240b2505621ce842c182b33cf6685bad23`.

- [ ] Finish `pins.py`'s oracle checks using `ast.parse` on original bytes and `ast.walk` counting `ast.FunctionDef` and `ast.AsyncFunctionDef` names starting `test_`, including methods. For async-specific counts use the `test_async_` definitions in the table. Hash each original file's bytes. For the full source digest, sort all Python paths and hash each oracle-relative UTF-8 path, NUL, bytes, NUL. Do not import modules or run pytest for counts. Verify the package's declared version without importing it. Run and inspect:

```sh
python3 /tmp/haskoki-async-routing/record.py reviewed/pin-check zero python3 /tmp/haskoki-async-routing/pins.py reviewed
```

Expected: every hash/count above matches; source definitions remain separate from collected/executed/skipped/failed counts. The five expectation-table declarations are not five executable tests.

- [ ] Write the minimal independent `oracle-getid.c` probe using only the pinned header and discovered 3.2 table. Initialize and open a real session with no job; call GetID first with a zero-filled `256`-byte selector allocation, then with `C_Digest`. Require exactly `CKR_ARGUMENTS_BAD` (`0x7`) then `CKR_OPERATION_NOT_INITIALIZED` (`0x91`), id sentinel unchanged both times. No broader consumer can stand in for this isolated comparison. Compile/run against the fresh bundle in the pinned container:

```sh
python3 /tmp/haskoki-async-routing/record.py reviewed/oracle-getid zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-async-routing:/tmp/haskoki-async-routing -w /work haskoki-dev:ghc-9.10.3 bash -ec '
cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor /tmp/haskoki-async-routing/oracle-getid.c -ldl -lpthread -o /tmp/haskoki-async-routing/oracle-getid
python3 -c '\''import pathlib,subprocess; p=list(pathlib.Path("dist-release").glob("haskoki-*/lib/libhaskoki.so")); assert len(p)==1; subprocess.run(["/tmp/haskoki-async-routing/oracle-getid",str(p[0].resolve())],check=True)'\''
'
```

- [ ] Implement `lane.py` to snapshot any existing `/tmp/pkcs11-ws/out-rc2/fast` or `kat` tree into the selected stage's exclusive `previous-fast` or `previous-kat` directory before wrapper execution. For example, reviewed fast archives to `dist-release-evidence/async-routing/reviewed/previous-fast`; final fast archives to `dist-release-evidence/async-routing/final/previous-fast`. If that archive name exists, stop rather than overwrite it. Hash and retain previous files and timestamps, verify the copy, then recreate only that wrapper-owned lane output directory empty so traces cannot include an earlier run. Require the current bundle/module to match the selected stage's `pins.json` before invoking `bash /tmp/pkcs11-ws/run-lane-rc2.sh fast` or `bash /tmp/pkcs11-ws/run-lane-rc2.sh kat`; save the wrapper's actual exit via `record.py`. Copy `pkcs11-fast-results.json` or `pkcs11-kat-results.json` and the nonempty `trace.jsonl` immediately after each run, before any subsequent invocation can overwrite them. Assert bundle/module/source pins still match afterward.
- [ ] Implement `inspect-lane.py` to print summary, exact nodeids/parameters, outcomes, `wasxfail`, and long representations for findings, plus all async-specific runtime records and relevant trace events. Preserve the original JSON unchanged. Require no setup errors, crashes, timeouts, incomplete runs, unresolved provider defects, or unexplained new findings. Known findings require explicit baseline comparisons and dispositions, not deletion. Lack of a detailed pass record must not invent a pass count; record collected/executed/skipped totals only as reported.
- [ ] Write `reviewed/dispositions.json` from actual review, as an array of records with `lane`, `nodeid`, `parameters`, `input_shape`, `actual`, `expected`, `classification`, `source`, `reproduction_log`, `reproduction_sha256`, `issue_url`, and `status`. Classifications are `provider`, `oracle`, or `capability`. Existing unrelated findings retain their prior evidence; newly exposed findings require exact source-backed explanations. `inspect-lane.py` fails until every relevant finding has a completed disposition; test that missing-evidence refusal before collecting the lanes.
- [ ] Run fast and inspect it before proceeding:

```sh
python3 /tmp/haskoki-async-routing/lane.py reviewed fast
python3 /tmp/haskoki-async-routing/inspect-lane.py reviewed fast
```

The wrapper command is exactly `bash /tmp/pkcs11-ws/run-lane-rc2.sh fast`. Review `reviewed/fast/pkcs11-fast-results.json`, `reviewed/fast/trace.jsonl`, `reviewed/fast.log`, and `reviewed/fast-command.json`. Complete dispositions and repeat only the inspection command as needed. `reviewed/fast-inspection.json` includes actual summary, classified findings, paths/hashes, and explicit findings-review acceptance. No kat run is permitted before fast findings have been inspected.

- [ ] Keep the malformed probe node visible as `ckr/test_ckr_v32_raw.py::TestAsyncErrors::test_async_get_id_no_operation`, including any actual runtime prefix/parameters. Its child `_probes/ckr_v32_raw.py` sends the empty selector and mislabels the scalar id as length. Link the minimal `0x7` versus `0x91` comparison; do not relax the decoder. Keep `test_remaining_gaps.py::TestAsyncLifecycle`'s incorrect 3.0 attribution visible: its four tests are availability/defined-refusal checks with null names, not successful jobs. Async table membership begins at 3.2. Record that the oracle proves no pending progress, bytes, revocation, restart, or competing Join success.
- [ ] For incorrect oracle expectations/attribution, prepare exact issue bodies with pinned source lines and independent evidence, then file in `mingulov/pkcs11-check`. Use `/tmp/haskoki-async-routing/oracle-selector-issue.md` with title `Async GetID no-operation probe uses an empty function selector`, and `/tmp/haskoki-async-routing/oracle-version-issue.md` with title `TestAsyncLifecycle attributes async slots to PKCS 11 3.0`. Search for an exact existing filing first and use it only if it already documents this same defect; otherwise create the issue. Preserve the real URLs and `gh issue view` readbacks in `reviewed/oracle-selector-issue.json` and `reviewed/oracle-version-issue.json`. Task 8's mandatory new proxy filing remains distinct.

```sh
gh issue list --repo mingulov/pkcs11-check --state all --search 'Async GetID no-operation probe uses an empty function selector' --json number,title,url,state
gh issue list --repo mingulov/pkcs11-check --state all --search 'TestAsyncLifecycle attributes async slots' --json number,title,url,state
gh issue create --repo mingulov/pkcs11-check --title 'Async GetID no-operation probe uses an empty function selector' --body-file /tmp/haskoki-async-routing/oracle-selector-issue.md > dist-release-evidence/async-routing/reviewed/oracle-selector-url.txt
gh issue create --repo mingulov/pkcs11-check --title 'TestAsyncLifecycle attributes async slots to PKCS 11 3.0' --body-file /tmp/haskoki-async-routing/oracle-version-issue.md > dist-release-evidence/async-routing/reviewed/oracle-version-url.txt
```

Run each creation command only when its exact defect has no existing filing. For each URL file, read its actual content and invoke `gh issue view` with that URL and `--json url,title,state,body`; never place a guessed issue id into a record. Additional newly discovered oracle defects require the same evidence and real filing.

- [ ] Run kat only after fast inspection, then inspect kat independently:

```sh
python3 /tmp/haskoki-async-routing/lane.py reviewed kat
python3 /tmp/haskoki-async-routing/inspect-lane.py reviewed kat
```

The wrapper command is exactly `bash /tmp/pkcs11-ws/run-lane-rc2.sh kat`. Review `reviewed/kat/pkcs11-kat-results.json`, `reviewed/kat/trace.jsonl`, log and command record. Record `reviewed/kat-inspection.json` with actual counts, classifications, and hashes; do not derive its outcome from fast.

**Acceptance:** Full source/file pins and counts match; isolated GetID returns exactly `0x7/0x91`; version attribution remains visible; fast then kat have recorded findings reviews with no unexplained new findings, setup failures, crashes, regressions, or unresolved provider defects. Oracle defects carry actual issue URLs and are not counted as provider success. End with evidence/disposition diffs and coordinator review; the worker makes no commit.

### Task 11: Generated contract evidence and accurate public documentation

**Spec trace:** §§1, 2.1–2.3, 3.7, 4.3, 5.5–5.7, 6.

**Files:** Modify `scripts/generate-function-contracts.py`; regenerate `spec/function-contracts.json`; modify `cbits/async_trampoline.h`, route-description prose in `cbits/exports.c`, `docs/demo-walkthrough.md`, `docs/operations-notes.md`, `docs/async-config-design.md`, `docs/pkcs11-oracle-triage.md`, and `docs/pkcs11-check-upstream-issues.md`. Create scratch `/tmp/haskoki-async-routing/check-contracts.py`.

**Interfaces:** Append `("test-consumers.sh", "tests/c/async_routed.c")` and `("haskoki-model-tests", "tests/model/StandardSurfaceSpec.hs")` to each of the three existing `PLANNED` evidence lists. Complete already cites both engine files; retain those tuples. GetID and Join already cite `tests/engine/DetachedEngineSpec.hs`; retain it and append `("haskoki-engine-tests", "tests/engine/AsyncEngineSpec.hs")` for the new ownership/cleanup coverage. Deduplicate evidence without replacing earlier tuples. Do not alter `entry`, `contract`, `ordinal_3_2`, `layouts`, `first_layout`, or `csv_acceptance`.

- [ ] Write `check-contracts.py` to compare generated rows with starting commit `170c679`: only the three async rows may gain evidence; all earlier evidence must be retained; unrelated rows and metadata are unchanged; totals are `104/70/32/2`. Require all referenced suite paths to exist and be wired. Require the two oracle documents to carry the same reviewed source revision, pins, actual lane/result/trace hashes, and complete dispositions. Require a proxy-scoped actual async issue URL distinct from message issue `23`. Run before edits; expect nonzero for missing consumer evidence and async qualification records.

```sh
python3 /tmp/haskoki-async-routing/record.py task-11/before nonzero python3 /tmp/haskoki-async-routing/check-contracts.py
```

- [ ] Add the evidence tuples in the generator, regenerate, then capture bytes and regenerate a second time to require byte equality.

```sh
python3 scripts/generate-function-contracts.py
python3 - <<'PYCODE'
import subprocess
from pathlib import Path
path = Path('spec/function-contracts.json')
before = path.read_bytes()
subprocess.run(['python3', 'scripts/generate-function-contracts.py'], check=True)
assert path.read_bytes() == before
print('PASS: function contracts byte-identical after second generation')
PYCODE
python3 /tmp/haskoki-async-routing/record.py task-11/contracts zero python3 /tmp/haskoki-async-routing/check-contracts.py contracts
```

The checker's `contracts` mode checks only the generated catalog; its default mode additionally validates documentation after the next steps. No JSON row is hand-edited.

- [ ] Replace the later-routing note in `cbits/async_trampoline.h` and update `cbits/exports.c`'s route description. Explain continuing private context/job-token ownership, version `1`, pending Join, query/short proof semantics, and the standard table adapter's session/function identity, version `0`, successful Join `CKR_OK`, and submission-bound output ownership.
- [ ] Update `docs/demo-walkthrough.md` with the three live 3.2 table entries, Digest-only full-buffer public admission, ordinary synchronous control, SQLite detach/restart proof, unchanged mechanisms/count, and no broader async claim. In `docs/operations-notes.md`, state output allocation lifetime, ignored incoming Complete fields, by-value Join capacity/no need output/no query, matching DigestInit requirement, memory/non-home no-store behavior, capacity `8`, fixed two-poll adapter policy, proxy exclusion and actual URL, and durable-mark limitation. Add scope clarification beside existing proofs in `docs/async-config-design.md`; compare the D1-D12 material byte for byte with the starting revision.
- [ ] Append `## Async routing verification (2026-09-30)` to both oracle documents without replacing earlier records. Use actual `reviewed/pins.json`, gate manifest, fast/kat command/inspection records, minimal GetID reproduction, and issue readbacks. Include exact node/parameters/input shape, actual/expected code or bytes, independent comparison, source applicability, provider/oracle/capability classification, issue URL/status/version, and source-definition versus runtime totals. Keep the two known oracle defects and the separately scoped proxy transport entry visible. Do not convert an availability/refusal pass into successful lifecycle evidence.
- [ ] Run default contract/document checker and targeted documentation checks.

```sh
python3 /tmp/haskoki-async-routing/record.py task-11/after zero python3 /tmp/haskoki-async-routing/check-contracts.py
python3 scripts/check-docs.py
python3 scripts/check-denominators.py
python3 scripts/check-history-codes.py
git diff --check
```

**Acceptance:** Exactly three contracts gain evidence from executed tests, all classifications/entries and denominator totals are preserved, generation is deterministic, all targeted checks exit `0`, and docs cite measured reviewed artifacts without claiming final-revision verification yet. The D1-D12 content remains unchanged. End with the exact nine-file diff and coordinator review; the worker makes no commit. The coordinator commits accepted documentation before Task 12.

### Task 12: Final revision evidence bundle

**Spec trace:** §§1, 3.6–3.7, 5.5–5.7, 6.

**Files:** No tracked-source changes. Create `dist-release-evidence/async-routing/final/gates.log`, `gates-command.json`, `gates/MANIFEST.txt` and driver logs, `pins.json`, `fast.log`, `fast-command.json`, `fast/pkcs11-fast-results.json`, `fast/trace.jsonl`, `fast-inspection.json`, corresponding kat files, and `MANIFEST.json`. Preserve `reviewed` and all preceding task evidence. Create scratch `/tmp/haskoki-async-routing/final-manifest.py`.

**Interfaces:** Mirror `dist-release-evidence/message-routing/final/`: a final clean HEAD, final gates, one freshly built bundle/module, sequential fast/kat outputs and inspections, and a manifest linking actual command/result/trace hashes. Do not qualify the documentation commit using only the earlier reviewed bundle.

- [ ] Confirm the coordinator's documentation commit is HEAD and require a clean tracked diff, while preserving `ws/` and `HANDOFF.md`. Write `final-manifest.py` to reject missing final evidence before collection; run `python3 /tmp/haskoki-async-routing/final-manifest.py` and require a missing-final-gates failure. Create the exclusive final directory; if it already contains evidence, archive it intact before reusing that name.
- [ ] Run gates again at this final revision and verify the manifest revision and all steps.

```sh
python3 /tmp/haskoki-async-routing/record.py final/gates zero env HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng HASKOKI_EVIDENCE_DIR=/home/user/src/m/haskoki-ws/haskoki/dist-release-evidence/async-routing/final/gates bash scripts/run-gates.sh
python3 /tmp/haskoki-async-routing/check-gates.py final
python3 /tmp/haskoki-async-routing/pins.py final
```

Expected: `18` gates and all suites pass; release manifest records current HEAD and `pass: 16 miss: 0`; final consumer/parity/proof logs demonstrate all routing legs and the real async issue-backed exclusion. Final `pins.json` carries that HEAD, newly built module and bundle hashes, all immutable pins, and oracle file counts/hashes.

- [ ] Run final fast and inspect its archived results/trace before any final kat run. Compare every new finding with the reviewed dispositions and inspect actual async records/trace, including the malformed GetID case; require any difference to be explained with independent evidence before proceeding.

```sh
python3 /tmp/haskoki-async-routing/lane.py final fast
python3 /tmp/haskoki-async-routing/inspect-lane.py final fast
```

- [ ] Run final kat only after the fast inspection is accepted, and review it independently.

```sh
python3 /tmp/haskoki-async-routing/lane.py final kat
python3 /tmp/haskoki-async-routing/inspect-lane.py final kat
```

Expected for both: wrapper exit `0` plus an explicit findings review; no unexplained new finding, crash, setup error, timeout, incomplete run, regression, or unresolved provider defect. Previously classified oracle defects and their URLs remain visible. Results and nonempty traces are hashed; bundle/module pins do not change across the lane sequence. Source-definition counts never substitute for runtime outcomes.

- [ ] Implement and run `final-manifest.py` with the following required checks and output schema. Recompute every referenced SHA-256 from bytes; verify each command's actual exit and source revision, current clean HEAD, the bundle digest algorithm from Task 9, and exact source/proxy/header/oracle pins. Reject missing files, stale revision/module identity, empty traces, unreviewed findings, or a missing/mismatched actual async issue URL. Include a hashed inventory of the scratch validation/reproduction sources so the evidence can be reproduced after `/tmp` is gone; copy those sources into `final/validation-sources` before hashing them.

| Manifest key | Required content |
|---|---|
| `source_revision` | Current full final HEAD, equal to final pins and gate manifest revision. |
| `spec_revision` | `170c679c268dcfbd254202953b3508d146fad6b1`. |
| `pins` | Final bundle absolute path/digest, module digest, toolchain tag/id, header, proxy source/pair/shim-source hashes, oracle release/digest/counts/file hashes, unchanged runtime/catalog/ABI-input hashes. |
| `commands` | Actual `gates`, `fast`, `kat` argument lists, exit `0`, log paths/hashes, source revisions, and measured toolchain identity. |
| `release_evidence` | Gate manifest path/hash and each of its `16` successful step logs with verified hashes. |
| `lanes` | Fast and kat raw JSON/trace paths/hashes, actual summaries, inspection paths/hashes, ordered review records, and classified findings. |
| `proxy` | Pin, refusal reproduction hashes, direct consumer transcript hash, actual new issue URL/readback hash, explicit exclusion, and normal eligible-scenario parity evidence. |
| `oracle_dispositions` | Minimal GetID comparison hash, malformed-selector and version-attribution records, actual issue URLs/readbacks, source/runtime count distinction, complete reviewed classifications. |
| `reviewed_evidence` | Reviewed manifest inputs and the documentation's recorded revision, retained as earlier evidence rather than relabeled final results. |
| `validation_sources` | Paths and hashes of copied command/pin/checker/probe sources, including the final manifest generator. |
| `acceptance` | One checked record for each of spec §6's eight bullets, linking exact evidence paths and hashes; routing-only scope and durable-mark limitation remain explicit. |

```sh
python3 /tmp/haskoki-async-routing/final-manifest.py
git diff --exit-code HEAD
git status --short
```

**Acceptance:** `final/MANIFEST.json` links the actual final HEAD, bundle, module, gate/driver logs, fast/kat JSON and traces, all fixed pins, independent comparisons, and real filings. Every spec §6 item has concrete linked evidence. Final tracked sources remain unchanged after verification. End with the final evidence diff and coordinator review; the worker makes no commit. Any necessary later tracked edit requires a new final-revision verification sequence. Report an out-of-scope provider defect or absent required filing separately as an acceptance blocker, with its exact reproduction.
