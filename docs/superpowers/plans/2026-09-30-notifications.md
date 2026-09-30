# Notifications and slot-events Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans, or superpowers:subagent-driven-development when the coordinator assigns workers, to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax. Each task ends with a reviewable diff and coordinator review before commit. Workers do not stage, commit, or push; the coordinator commits accepted task diffs.

**Goal:** Deliver coherent token presence and coalesced slot indications through all four public tables, with deterministic wait/finalize arbitration and one bounded native Digest surrender producer.

**Architecture:** One interval-local `SlotEvents` service belongs to the resolved serving configuration and is shared by Instance and Standard. Standard retains sessions, objects, store, backend, and its existing async table; its removal coordinator publishes model retirement and presence together. Waits use STM without the C state lock; synchronous native callbacks retain that lock as their lifetime lease and reject prohibited same-thread reentry before any lock or mutation.

**Tech Stack:** Haskell GHC2024, GHC `9.10.3`, cabal-install `3.12.1.0`, STM, Tasty/HUnit, C11 on Linux x86-64 LP64, OpenSSL `4.0.2`, SQLite, Python 3, POSIX condition variables/processes and guarded allocations.

**Spec:** [Authoritative notifications design](../specs/2026-09-30-notifications-design.md), committed at `6fa6696273d8111ad64a6474d68552369fa37c22`. Read all sections, G01–G17, and N01–N12 before executing. [Async plan](2026-09-30-async-routing.md) supplies recorder, review, pin, and evidence conventions, not new notifications requirements.

## Global Constraints

- Starting HEAD is `6fa6696273d8111ad64a6474d68552369fa37c22`. The spec's inspected `019f8f09dbff89b6562937b16f99ad8b5c4446b5` is historical source context. Verify the coordinator's accepted predecessor before every task; do not reset a moving checkout.
- **Drafting boundary:** only this plan is created now. All implementation, scratch creation, compilation, tests, releases, lanes, and filings below are future work. No acceptance, failure reproduction, or execution result is claimed by this document. Preserve existing untracked `HANDOFF.md` and `ws/`.
- Task file lists are allowlists, including narrowly described regions of shared files. An implementation worker stops after its assigned task with diff, evidence, and unresolved findings. It never stages, commits, pushes, starts the next task, or changes another task's ownership silently. A necessary correction returns to its owning task's assertion cycle, followed by coordinator review and refreshed dependent evidence.
- Keep T-N01 through T-N10 and their dependency order from spec §7. T-N10 has a documentation review/commit checkpoint before its final evidence checkpoint so evidence can identify a clean documentation-inclusive revision; this does not introduce a new implementation task. T-N08 consolidates independent consumers after the owning behavioral cycles; its baseline comparisons are explicitly against the starting revision, not fabricated current-revision reds.
- No changes to Async execution, persistence, capacity `8`, attached/detached cancellation policy, competing-Join policy, recipe identity, or detached formats. `src/Haskoki/Runtime/Async.hs`, `src/Haskoki/Runtime/Detached.hs`, `ffi/Haskoki/FFI/Async.hs`, `core/Haskoki/Recipe/Digest.hs`, and storage implementation/interface files remain byte-identical to starting HEAD. Use the existing workers; private `instAsync` is not Standard's table.
- No new store, writer, reset, watcher, persisted presence field, configuration key, timer, event thread, hardware monitoring, dynamically added slot, network control service, OTP notification, or background-thread callback. Memory retains `siStore = Nothing`; SQLite borrows the existing store. Ordinary object durability is not expanded. Preserve D1–D12 in `docs/async-config-design.md`.
- Preserve private `EventQueue`/`TokenRegistry` FIFO/drop/callback/scenario proofs. Public waits and serving presence controls must not use them or fall back to them. CLI scenarios may bind an explicitly private owner and cannot control another process's module.
- Header pin: latchset `c5e61990c5621a9b955fc208644fe8145ac0a75d`; `spec/vendor/pkcs11.h` SHA-256 `61e0b3f996fa9f095859d7d3b8e361d0b982de69fc8b6a4bf10291afbe7e24d8`. Preserve `spec/sources.lock.json`, native `CULong` width, table counts `68/92/92/104`, Wait ordinal `68`, Async ordinals `100/101/102`, and all existing routing assignments. Do not enlarge-cast old tables or add public dynamic exports. Helpers remain hidden by the existing export map.
- Preserve `spec/mechanisms.json`, `cbits/mech_catalog.inc` and its `316` advertised rows/flags, ABI inventories, `cbits/abi_generated.h`, existing layout tests, and `toolchain.lock`. Function contracts retain `104` rows (`70` planned, `32` unsupported, `2` not applicable) and their classifications; only the evidence additions enumerated in T-N10 are authorized.
- Lock order is init lock → state lock → model gate → STM. Waits hold neither state lock nor model gate while blocking. Presence cleanup/cancellation/native release and all callbacks are outside STM. Callback execution is on the caller's bound thread, outside model/registry/store locks and async leases, while retaining the C state lock. No `unsafePerformIO` registry or pointer-as-integer/JSON/store encoding.
- Production services start present at epoch `0`, pending flags clear. Test-enabled slots are permanently removable within an interval; fixed slots remain present. Events bound must be positive and at least catalog size, without clamping/dropping; existing slot limit still applies. Command generation, presence epoch, stored token generation, and persistent async IDs are distinct.
- Never change validation/no-event/error outputs speculatively. Byte canary is `0xa5`; slot/session/id sentinel is `0xa5a5a5a5a5a5a5a5UL`. Digest tests use `abc`, capacity `32` (also `0/31/64` where specified), and SHA-256 `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`. Snapshot whole output structs and prefix/tail canaries. Unknown flag probe includes `1UL << (sizeof(CK_FLAGS) * CHAR_BIT - 1)`.
- All new C compilations use `cc -std=c11 -O2 -g -Wall -Wextra -Werror`, pinned consumer headers and `-ldl -lpthread` when loading modules. Build/load focused native modules in the same `haskoki-dev:ghc-9.10.3` container. Docker invocations use `timeout -s KILL 2400`, `--network host`, and the exact mounts shown below. The host gate runner owns its existing per-stage timeouts, including installation; do not wrap the whole multi-stage runner in one 2400-second budget.
- Record the **measured** image ID from `docker image inspect haskoki-dev:ghc-9.10.3 --format '{{.Id}}'`, not an assumed fixed image ID. Fixed header/proxy/oracle pins must match; a mismatch stops collection, never triggers a rebuild, re-pin, or oracle edit.
- Tests use barriers/condition variables/STM observer seams and bounded joins. A timeout is failure containment, not an event producer or proof that a waiter reached retry. Native pre-call acknowledgments alone do not establish Haskell admission. C shared state uses atomics or a mutex, never plain concurrently accessed flags.
- Each production change follows assertions → observed specified nonzero red → bounded implementation → required-zero green. Compilation failure only establishes a missing interface, not behavior. Unexpected failure, setup exit `2`, crash, timeout, empty test selection, or unrelated build failure is not the intended red. Retained already-correct behavior stays green; never break it to manufacture a red. Evidence checkers first refuse missing evidence without manufacturing a provider defect.
- Preserve exact source/file/module/bundle identity for every run. Old greens do not qualify a changed revision. Required gates remain `18` static gates, forced build, all Cabal suites, `14` existing container drivers, release build, and installation (`16` manifest steps). Add consumers to existing drivers; add no repository driver.
- Final acceptance requires a clean tracked final revision, fresh installed behavior and gates, reviewed fast **then** kat, actual distinct required filing, all N01–N12 linked, and no unresolved provider/lifetime/ownership failure. An inability to reproduce the proxy candidate is an unresolved N11 gate, not permission to label it established or invent a URL.

## Review Focus

- An invalid model delta or closed service must not publish the other half of presence; T-N03 tests both failures and observes model plus slots in one STM snapshot.
- Removing a token must invalidate token-object handles permanently, even after rediscovery and subsequent object generation changes; T-N03 deletes bindings and T-N08 exercises stale handles after reinsertion.
- Response construction can fail after a control mutation unless prepared first; T-N03 injects allocation/prepublication/release faults and distinguishes validation refusals from already-committed failures.
- A callback can reenter with invalid pointers and nonrecursive application mutexes; T-N06 checks rejection before dereference/lock/termination, and T-N07/T-N08 test real callback execution.
- A second required-zero attempt or oracle lane can silently replace earlier evidence; the receipt/archive contract and T-N09/T-N10 checkers require preserved attempts, previous lane trees, and immutable bundle pins.

## Files

| Area | Exact paths and owner | Responsibility |
|---|---|---|
| Serving service | Create `src/Haskoki/Runtime/SlotEvents.hs` (T-N01); modify only hooks if needed in T-N05 | Coalesced pending flags, snapshots, checked epoch/bounds, closed-first STM waits. |
| Shared acquisition | Create `src/Haskoki/Runtime/Catalog.hs`; modify `ffi/Haskoki/FFI/Instance.hs`, `ffi/Haskoki/FFI/Standard.hs`, `src/Haskoki/Runtime/Control.hs`, `cbits/function_tables.c`, `cbits/control_entry.c`, `cbits/standard_surface.c` (T-N02) | One configuration/catalog/hub; explicit serving/private owner binding; unpublished open and cleanup. |
| Retirement/publication | Modify `src/Haskoki/Runtime/Lifecycle.hs`, `core/Haskoki/Outcome.hs`, `core/Haskoki/Transition.hs`, `core/Haskoki/Model.hs` (ownership comment only), plus acquisition adapters' presence/control regions (T-N03) | One model/presence transaction; no stale object bindings; actual Standard cleanup; typed extension failures. |
| Public surface/finalize | Modify Instance/Standard and the three C surface files above (T-N04/T-N05) | Exact boundary/error outputs; close before native teardown; no waiter migration. |
| Native callbacks | Create `ffi/Haskoki/FFI/Notify.hs`, `cbits/notify_guard.h`, `cbits/notify_guard.c`; modify Standard, C surface files, `cbits/exports.c`, generator policy comments (T-N06); Standard Digest branch (T-N07) | Typed association, safe invoker, TLS guard, exactly one bounded producer. |
| Haskell/test wiring | Modify `haskoki.cabal`, `tests/model/Main.hs`, `tests/engine/Main.hs`; create `tests/model/NotificationsSpec.hs`, `tests/engine/NotificationsEngineSpec.hs`, `tests/engine/notifications_adapter.c`; modify exact existing specs listed per task | Focused serving tests and retained private/acquisition/Async proofs. |
| Independent consumers | Create `tests/c/notifications_routed.c`, `tests/c/consumer_notifications_poll.c`; modify `tests/c/control_events.c`, `tests/c/sim_threaded.c`, `tests/c/finalize_wait_race_probe.c`, `tests/c/consumer_errors.c`, `scripts/test-consumers.sh`, `scripts/test-proxy-parity.sh` (T-N08/T-N09) | Real tables, two backends, fixed/removable configurations, precise direct/parity scope. |
| Generated contracts/docs | Modify `scripts/generate-function-contracts.py`, regenerate `spec/function-contracts.json`; modify `docs/operations-notes.md`, `docs/config-honesty.md`, `docs/demo-walkthrough.md`, `docs/async-config-design.md`, `docs/pkcs11-oracle-triage.md`, `docs/pkcs11-check-upstream-issues.md` (T-N09/T-N10) | Executed evidence references and accurate public/private claims. |
| Validation/evidence | Create only the task-listed helpers under `/tmp/haskoki-notifications/`; evidence under `dist-release-evidence/notifications/` | Receipts, probes, deterministic generation checks, baseline archive, reproduction, lanes and final manifest. Use the slice recorder `/tmp/haskoki-notifications/record.py` (SHA-256 `5b141a238f6cabed6ffb5111c016e66a466fc34bc862c011c343e55c73c059f3`), identical to the Async recorder except its evidence root. |

Read-only invariants additionally include `src/Haskoki/Runtime/Storage.hs`, `src/Haskoki/Runtime/Storage/Memory.hs`, `src/Haskoki/Runtime/Storage/SQLite.hs`, `src/Haskoki/Ctl.hs`, `tests/model/CtlSpec.hs`, `tests/model/EventsSpec.hs`, `tests/model/FfiAsyncSpec.hs`, `tests/c/async_attached.c`, `tests/c/async_detached.c`, `tests/c/async_restart.c`, `tests/c/async_routed.c`, `tests/c/layout_320.c`, `scripts/test-async-attached.sh`, `scripts/test-async-detached.sh`, `scripts/run-gates.sh`, `scripts/release-evidence.sh`, `scripts/make-release.sh`, `scripts/test-release-install.sh`, all other specs/plans, and pinned external trees.

## Evidence and command contract

All commands start at `/home/user/src/m/haskoki-ws/haskoki`. Use the slice recorder `/tmp/haskoki-notifications/record.py` (SHA-256 `5b141a238f6cabed6ffb5111c016e66a466fc34bc862c011c343e55c73c059f3`) with interface `record.py NAME zero|nonzero COMMAND ARG...`. It is byte-identical to the Async recorder except its evidence root `dist-release-evidence/notifications`; names below are plain relative labels like `task-n01/before` (no `..` escapes). For example, `task-n01/before` writes `dist-release-evidence/notifications/task-n01/before.log` and `before-command.json`. Do not change the recorder, and do not overwrite Async evidence. If that prerequisite script is missing, stop for the coordinator to restore it; do not create scratch outside this slice's directory. Known toolchain fact: the `haskoki-dev:ghc-9.10.3` image has no `python3`; container steps needing Python must use the pre-existing scratch runtime (Async Tasks 8/10 precedent), never `cabal clean` or image changes.

T-N01 creates `/tmp/haskoki-notifications/evidence.py` with these exact commands:

- `evidence.py receipt NAME`: enrich the existing record at `notifications/NAME-command.json` with SHA-256 of every allowed changed source (including untracked new files), recorder/checker/probe sources, actual loaded module absolute path/hash, input build revision/patch, measured image ID, pins when applicable, and artifact paths/hashes. Preserve recorder `command`, actual `exit`, raw log bytes/hash, and tracked patch hash. For compile/source-only commands write `module_loaded: false`. Child commands launched by helpers get their own exact-argv receipts; a shell wrapper receipt alone cannot hide the compiler/module/lane argv.
- `evidence.py archive NAME`: refuse a nonexistent receipt or mismatched log hash; move the complete named evidence set into exclusive `dist-release-evidence/notifications/attempts/NAME/0001/` (next unused four-digit number), verify bytes/hashes, and record why/owning task/current revision in `attempt.json`. Include child logs, configs, traces, module pins and directories, not just the last log. Failed **required-zero** runs must be archived before a corrected run can reuse a name. No `|| true`, exit relabeling, deletion, or replacing an expected-zero run with `nonzero`.
- `evidence.py invariants`: compare the read-only paths above with `git show 6fa6696273d8111ad64a6474d68552369fa37c22:PATH`; assert ABI counts/ordinals, `316` advertised mechanism rows and `104/70/32/2` function totals. Check no disallowed tracked edits. Explicit task-owned evidence additions are the only contract exception.
- `evidence.py generators abi` runs `python3 scripts/generate-abi.py` twice, compares all four outputs (`cbits/abi_stubs.inc`, `cbits/abi_generated.h`, `spec/abi-inventory.json`, `spec/abi-reconciliation.json`) byte-for-byte between runs, and requires them unchanged from baseline in this slice. Reconciliation remains `matched=104 added=0 removed=0 aliased=0`. T-N06 changes shared stub policy/comments, not generated shapes/assignments.
- `evidence.py generators contracts` runs `python3 scripts/generate-function-contracts.py` twice and compares `spec/function-contracts.json` bytes; only T-N10's evidence tuples may differ from baseline. Any additional generator needed later must be identified, its full output set captured, and two identical runs proven in its owning task; never hand-edit an output or silently add a generator.
- `evidence.py review TASK` writes `TASK/review.json` and `TASK/diff.patch`, enumerating allowed files, focused/retained case counts, reds by assertion, all receipts/hashes, source invariants and outstanding issues. It rejects a green selected run with zero tests. Include a no-index diff for each new tracked-source candidate; diff exit `1` means differences, not a test failure. Coordinator review follows; this command does not commit.

Every task's closing step includes `receipt` for each command, `review TASK`, `git diff --check`, and coordinator review. The reviewer checks exact task ownership and never treats uncommitted-source results as final clean-revision acceptance. Deterministic reference traces use exhaustive named inputs; generated JSON inventories sort paths/keys and separate runtime timestamps from deterministic content.

## Tasks

| Task | Spec trace and acceptance | Gaps/retained facts | Dependency |
|---|---|---|---|
| T-N01 | §§2.3, 3.3, 3.6, 5.1–5.2; N02, N04, N06, N09, N12 | G04–G06 | First |
| T-N02 | §§2.3–2.4, 3.2, 3.4, 4.3, 5.1; N01, N09, N10 | G03, G07, G15–G16 | T-N01 |
| T-N03 | §§3.3–3.5, 3.8, 4.2–4.3, 5.1; N03, N05, N09, N10 | G08, G14–G16 | T-N02 |
| T-N04 | §§3.1–3.2, 3.5–3.6, 4.1–4.2, 5.3; N01–N04, N10 | G01–G03, G09–G11 | T-N01–T-N03 |
| T-N05 | §§3.4, 3.6, 3.8, 4.1, 5.2; N04, N06, N10 | G05–G06, G17 | T-N02–T-N04 |
| T-N06 | §§3.2, 3.7–3.8, 4.3, 5.1–5.2; N07, N08, N10 | G12–G14 | T-N02–T-N05 |
| T-N07 | §§3.7–3.8, 4.3, 5.1; N07, N08, N12 | G12–G13 | T-N06 |
| T-N08 | §§3.1–3.8, 4.1–4.3, 5.1–5.4; N01–N10, N12 | G01–G17 | T-N03–T-N07 |
| T-N09 | §§5.4–5.6; N11, N12 | G17; pinned external limitations | T-N08 |
| T-N10 | §§1, 3.9, 5.1–5.6, 6; N01–N12 | All gaps linked to evidence | T-N01–T-N09 |

### T-N01: Coalesced serving service and STM boundary

**Spec trace:** §§2.3, 3.3, 3.6, 5.1–5.2; N02, N04, N06, N09, N12; G04–G06.

**Files:** Create `src/Haskoki/Runtime/SlotEvents.hs`, `tests/model/NotificationsSpec.hs`; modify `haskoki.cabal` (main library and foreign-library module lists; model test module and direct `stm >= 2.5 && < 2.6` test dependency), `tests/model/Main.hs` (import/run). Create scratch `/tmp/haskoki-notifications/evidence.py`. Evidence: `dist-release-evidence/notifications/task-n01/`.

**Interfaces:** Implement the exact spec types, with private `SlotEvents` constructors:

```haskell
data SlotDefinition = SlotDefinition { sdSlot :: !SlotId, sdRemovable :: !Bool }
data SlotSnapshot = SlotSnapshot
  { ssSlotId :: !SlotId, ssRemovable :: !Bool
  , ssPresent :: !Bool, ssPresenceEpoch :: !Word64 }
data WaitMode = Block | DontBlock
data SlotWait = SlotReady !SlotId | SlotNoEvent | SlotWaitClosed
data SlotConfigError = DuplicateSlot | TooManyPendingSlots | InvalidEventBound
data PresenceError = PresenceUnknownSlot | PresenceFixedSlot
  | PresenceEpochExhausted | PresenceClosed | PresenceModelFault !ModelFault
data PresenceChange = PresenceUnchanged !Word64 | PresenceChanged !Word64
newSlotEvents :: Int -> [SlotDefinition] -> IO (Either SlotConfigError SlotEvents)
snapshotSlots :: SlotEvents -> IO [SlotSnapshot]
waitSlot :: SlotEvents -> WaitMode -> IO SlotWait
closeSlotEvents :: SlotEvents -> IO ()
publishPresenceSTM :: SlotEvents -> SlotId -> Bool -> STM (Either PresenceError PresenceChange)
snapshotSlotsSTM :: SlotEvents -> STM [SlotSnapshot]
```

For internal, constructor-injected proofs add `data NotificationPoint = WaitCaptured | WaitBeforeRetry | WaitDecisionCommitted !SlotWait | RemovalPrepublication | CloseCommitted`, `type NotificationHooks = NotificationPoint -> IO ()`, `newSlotEventsWith :: NotificationHooks -> Word64 -> Int -> [SlotDefinition] -> IO (Either SlotConfigError SlotEvents)`, and `observeSlotEvents :: SlotEvents -> NotificationPoint -> IO ()`. The `Word64` seeds only the initial epoch in Haskell fixtures (including exhaustion); `newSlotEvents` supplies epoch `0` and no-op hooks. Observers execute outside STM. No public C export/config/control pause point is added. Lifecycle imports this leaf directly; the leaf imports neither Lifecycle, Async, Events, Control nor FFI. Export `NotificationsSpec.spec :: TestTree` and register it exactly once in the model runner.

- [ ] Write/register five exact cases in group `Notifications/T-N01`: `caseServingInitialCore`, `caseServingCoalesces`, `caseServingBound`, `caseServingClosedFirst`, `caseServingReferenceTraces`. First assertions require initially present epoch-zero snapshots in ascending order, empty poll, and remove/insert/remove of A yielding epoch `3` but one A. A/B first-pending order is unchanged by another A transition; consuming A then changing it appends A behind pending B. Reads acknowledge nothing; idempotence increments nothing.
- [ ] Test duplicate IDs, bound `0`, bound below two slots, and all `16` configured slots simultaneously pending at bound `16`. Seed epoch `maxBound-1`: one real transition succeeds, the next refuses before state change; idempotence at max succeeds while live. Fixed removal refuses. Close nonempty and empty services twice; both wait modes then return closed with zero deliverable flags, and snapshot retains the last presence without fabricating removal.
- [ ] Build an independent reference model using current presence plus a set of pending slots tagged with first-pending sequence numbers, not the implementation queue. Enumerate exactly `2401` length-four traces over `{insertA, removeA, insertB, removeB, poll, snapshot, close}` in lexical order. Compare every result/snapshot, including closed refusals. Keep legacy `EventsSpec` unchanged and describe its results as private FIFO/callback proofs.
- [ ] Create the evidence helper described above; run the assertions before implementing the leaf. Expected red identifies the missing `Haskoki.Runtime.SlotEvents` interface; after it compiles, a failed coalescing/nonempty-close assertion must be recorded if an incorrect FIFO implementation is encountered, without counting the compile failure as behavioral evidence.

```sh
python3 /tmp/haskoki-notifications/record.py task-n01/before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests --test-show-details=direct --test-options='-p /T-N01/'
```

- [ ] Implement checked catalog construction, one pending entry per slot, first-pending FIFO, atomic acknowledgment, closed-before-pending inspection and true STM retry. Validate every failing publication condition before any write. The test-only fixture can call the STM primitive on an isolated service; all serving callers later go through T-N03's coordinator. About-to-retry observation is followed by a transaction that rechecks state; never perform IO within `atomically`.
- [ ] Run greens and retained model suite, then finish receipts/review.

```sh
python3 /tmp/haskoki-notifications/record.py task-n01/after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests --test-show-details=direct --test-options='-p /T-N01/'
python3 /tmp/haskoki-notifications/record.py task-n01/retained zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests --test-show-details=direct
python3 /tmp/haskoki-notifications/evidence.py review task-n01
git diff --check
```

**Acceptance:** Before exit is nonzero for the named missing interface/behavior; after and retained exits are `0`, exactly five focused cases run and all `2401` reference traces pass. One flag per slot, `16/16` capacity retained, zero closed-tail successes, zero epoch wraps, and no module cycle. `before/after/retained` logs and command JSON live under the task evidence directory. No public integration acceptance yet. Stop for coordinator review before commit; the worker makes no commit.

### T-N02: Shared acquisition and bound control owner

**Spec trace:** §§2.3–2.4, 3.2, 3.4, 4.3, 5.1; N01, N09, N10; G03, G07, G15–G16.

**Files:** Create `src/Haskoki/Runtime/Catalog.hs`, `tests/engine/NotificationsEngineSpec.hs`; modify `haskoki.cabal`, `tests/engine/Main.hs`, `ffi/Haskoki/FFI/Instance.hs`, `ffi/Haskoki/FFI/Standard.hs`, `src/Haskoki/Runtime/Control.hs`, `cbits/function_tables.c`, `cbits/standard_surface.c`, `cbits/control_entry.c`, `tests/engine/FfiAcquireSpec.hs`, `tests/model/ControlSpec.hs`, `tests/model/ConfigHonestySpec.hs`, `tests/model/SimBridgeSpec.hs` (explicit private construction only). Create scratch `/tmp/haskoki-notifications/acquisition-probe.c`, `/tmp/haskoki-notifications/run-acquisition.sh`, compiled `/tmp/haskoki-notifications/acquisition-probe`. Evidence: `dist-release-evidence/notifications/task-n02/`.

**Interfaces:** Catalog exports `effectiveCatalog :: Config -> Map SlotId (String, String, String)` and `homeCatalogEntry :: (String, String, String)`, moving the existing values without changing provisioning. Add `instSlots :: SlotEvents` and `siSlots :: SlotEvents`; export opaque `InstanceCell` and `readLiveInstance :: StablePtr InstanceCell -> IO (Maybe Instance)`. Export `NotificationsEngineSpec.spec :: MVar () -> TestTree` and register `NotificationsEngineSpec.spec envLock` exactly once in the engine runner.

```haskell
haskokiStdOpen :: StablePtr InstanceCell -> IO (StablePtr StdInstance)
openStdInstanceWithSlots
  :: StdAcquisition -> Config -> SlotEvents -> IO (StablePtr StdInstance)
data PresenceOwner = PresenceOwner
  { ownerSnapshot :: IO [SlotSnapshot]
  , ownerSetPresence :: SlotId -> Bool -> IO (Either PresenceError (PresenceChange, Int)) }
bindPresenceOwner :: ControlState -> Maybe PresenceOwner -> IO ()
```

Keep environment-free `openStdInstance :: Config -> IO (StablePtr StdInstance)` and `openStdInstanceWith :: StdAcquisition -> Config -> IO (StablePtr StdInstance)` as proof wrappers constructing one explicit private serving service and passing it to `openStdInstanceWithSlots`. Production `void *haskoki_std_open(void *ops_instance_cell)` and `void *haskoki_std_open_fresh(void *ops_instance_cell)` reuse the already-resolved Instance config/hub, and never call those wrappers to resolve again. Update GHC export/fallback declarations and calls together. Bind hooks capturing the live Haskell `StdInstance`, not its unleased StablePtr. Retain `siUnbindPresenceOwner :: IO ()` in Standard (no-op for standalone proofs) so every close/rollback clears the binding before freeing native resources; T-N05 additionally moves shared-service close before Standard teardown. Add `bindPrivatePresenceOwner :: ControlState -> TokenRegistry -> IO ()` only for explicit legacy Control test construction; no serving fallback. The CLI already calls its private registry directly and needs no ownership rewrite. Until T-N03, the serving mutation hook refuses, while status uses the actual catalog.

- [ ] Register four cases in `Notifications/T-N02`: `caseServingInitialSnapshot`, `caseServingAcquisitionUnwind`, `caseServingConfigLimits`, `caseServingControlOwnership`. Use engine `EnvLock` for environment probes; verify exact shared hub identity using test-local StableNames and shared snapshot transitions, one config resolution, one backend/store acquisition, one Standard table of capacity `8`, and initial empty flags for memory/SQLite. Test test-enabled versus fixed definitions, limits.events positive/catalog-sized admission, catalog limit refusal, and no truncation.
- [ ] Inject failures at store acquisition, backend acquisition, assembly, owner binding, and negotiated mutex creation. Assert each acquired resource released exactly once, owner cleared, service closed, no live C roots or initialized flag, and successful retry. Update the existing `caseStdEnvDishonest` acquisition test to obtain the explicit cell through the authoritative config path; retain its invalid-config refusal, not a second environment resolver. Preserve all other `FfiAcquireSpec` cases.
- [ ] Write the C translation-unit acquisition probe using mocks, `-ffunction-sections -fdata-sections -Wl,--gc-sections`, and pinned-compatible prototypes. `run-acquisition.sh` compiles with the global C flags, runs the resulting binary, and fails if install occurs before both opens, binding and mutex setup succeed. Verify Control liveness/lock/revalidation and exactly one unlock per acquired-lock path; Wait acquires zero state locks. Stable labels: `notifications:acquire/<success|failure|control-lock>/internal`.
- [ ] Observe focused Haskell and C reds before changing ownership. The intended failures are missing `siSlots`/borrowed constructor and the currently early `haskoki_instance_install`/lock-free Control path, respectively.

```sh
python3 /tmp/haskoki-notifications/record.py task-n02/before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-engine-tests --test-show-details=direct --test-options='-p /T-N02/'
python3 /tmp/haskoki-notifications/record.py task-n02/c-before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 bash /tmp/haskoki-notifications/run-acquisition.sh
```

- [ ] Construct cell/hub unpublished, open Standard from that cell, bind owner and adopt mutexes, then publish both C roots and liveness. Failure unwinds once and closes the hub. Clear owner before Standard close on rollback and ordinary teardown, with C state ownership where applicable. Add authoritative revalidation after Control acquires the state lock, including status. Preserve the special lock-free wait path.
- [ ] Make serving status paginate only actual configured slots, with per-slot presence epoch. Bind standalone ControlSpec/ConfigHonestySpec/SimBridgeSpec fixtures explicitly to their private registries and preserve private scheduler.advance behavior. Retain the CLI's direct private registry ownership unchanged. Label ConfigHonestySpec's existing nine-arrivals/one-drop assertion as private FIFO evidence; it cannot establish serving capacity. No new MemoryWorld, writer, tracing producer, or storage format.

```sh
python3 /tmp/haskoki-notifications/record.py task-n02/after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-engine-tests --test-show-details=direct --test-options='-p /T-N02/'
python3 /tmp/haskoki-notifications/record.py task-n02/c-after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 bash /tmp/haskoki-notifications/run-acquisition.sh
python3 /tmp/haskoki-notifications/record.py task-n02/retained zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests haskoki-engine-tests --test-show-details=direct
python3 /tmp/haskoki-notifications/evidence.py review task-n02
git diff --check
```

**Acceptance:** Both intended before commands exit nonzero; all three greens exit `0`, four focused cases execute, `1` serving config/hub/backend/store owner and Standard capacity `8` are observed, zero half-published roots or leaked resources on each injected failure. Status count equals catalog size, with zero startup indications. Preserve existing acquisition/CLI proofs. Stop for coordinator review before commit; the worker makes no commit.

### T-N03: Atomic presence and real Standard removal

**Spec trace:** §§3.3–3.5, 3.8, 4.2–4.3, 5.1; N03, N05, N09, N10; G08, G14–G16.

**Files:** Modify `src/Haskoki/Runtime/Lifecycle.hs`, `ffi/Haskoki/FFI/Standard.hs`, `src/Haskoki/Runtime/Control.hs`, `ffi/Haskoki/FFI/Instance.hs`, `core/Haskoki/Outcome.hs`, `core/Haskoki/Transition.hs`, `core/Haskoki/Model.hs` (handle-retention comment only), `tests/model/NotificationsSpec.hs`, `tests/engine/NotificationsEngineSpec.hs`, `tests/model/TransitionSpec.hs`, `tests/model/ControlSpec.hs`, `tests/model/ConfigHonestySpec.hs`, `tests/model/SimBridgeSpec.hs`, `tests/prop/NamespaceProps.hs`, `tests/prop/DeltaProps.hs`. Create scratch `/tmp/haskoki-notifications/check-retirement.py` (source invariant/ledger checker). Evidence: `dist-release-evidence/notifications/task-n03/`.

**Interfaces:**

```haskell
publishPresence :: Env -> SlotEvents -> StateDelta -> SlotId -> Bool
  -> IO (Either PresenceError PresenceChange)
snapshotPresence :: Env -> SlotEvents -> IO (Model, [SlotSnapshot])
setStdTokenPresence :: StdInstance -> SlotId -> Bool
  -> IO (Either PresenceError (PresenceChange, Int))
prepareStdRemoval :: Rules -> Model -> SlotId
  -> Either ModelFault (StateDelta, [SessionId], [ResourceRelease])
```

Add `DeltaUnbindHandle !ExternalHandle` to the transient core `DeltaOp`; publication deletes that binding without reusing counters or destroying the parked token object. Missing binding is an idempotent delete. Compose existing close-session plans with `envRules (siEnv inst)` against successively validated pure intermediate models, collecting releases, then unbind every handle targeting the slot. Do not use `DeltaBumpHandle` as permanent removal: deleting the mapping prevents later object-generation coincidence from reviving it. This is an internal delta change, not a stored format/enum change. Correct Model's old “never deleted” binding comment to state the removal exception and unchanged monotonic allocation. Classify unbind as an object/handle operation in NamespaceProps and add its explicit representatives to both property suites. Preserve their existing LCG/seeds; add deterministic unbind traces without silently changing or weakening earlier random traces.

Use a typed extension failure without expanding persisted/core return codes: `data ControlFailure = ControlInvalid !String | ControlUnavailable | ControlPublishFault !ModelFault`; `controlFailureRV :: ControlFailure -> Word64` maps to `0x07/0x190/0x06`. Change `dispatchControl :: ControlState -> ByteString -> Maybe Word64 -> IO (Word64, ByteString, Word64)` and its local trace RV argument to numeric boundary results; ordinary codes still use existing `returnCodeToRV`. Update Instance and all three existing test caller modules in this task; the CLI does not call this function. Unexpected exceptions retain the outer `0x05` fence. Keep bounded schema/error envelopes and `jobs_canceled` as the number of newly canceled **standard attached** jobs, including joined attachments.

- [ ] Add group `Notifications/T-N03`: model cases `casePresencePublication`, `casePresenceHandleRetirement`, `caseControlGenerationAtomicity`; engine cases `caseRemovalOwnsActualJobs`, `casePresenceCleanupFault`, `casePresenceStoreLedger`. Require one STM observation of model and presence; model validation failure and PresenceClosed/unknown/fixed/exhausted errors publish neither half. Test all checked failures before cancellation. Use constructor-local seeded control generation, not a new public setter, to exercise `maxBound` without billions of commands.
- [ ] In actual Standard fixtures create two slots, multiple sessions, a session object, token-object binding, login, find cursor, multipart stream, attached job, joined job and an idle detached record. After removal require zero sessions/views/bindings/cursors on that slot, all handles stale after reinsertion/rediscovery/object mutation, `jobs_canceled = 2` in this controlled fixture, no post-publication output write, unaffected other-slot job/session, and unchanged idle detached record. Preserve token records/auth metadata and stored generation; reset active login. Reinsertion admits new handles, never recycles old IDs.
- [ ] Assert control query and capacity `65535` return need `65536` with zero parsing/mutation; capacity `65536` executes once. Unknown/disabled/stale/exhausted/malformed requests preserve all state. Two callers with one expected command generation yield one accepted mutation and one ARGUMENTS_BAD; accepted idempotent mutation increments command generation once but not presence epoch. Prepare bounded reply storage before cleanup. Inject precommit fault (no event; already-canceled jobs remain canceled), postcommit release fault (absence/event retained, no revival, remaining releases attempted via finally), and allocation refusal before claim. Ledger requires zero `storeResetToken` calls and zero new presence-persistence commits/reloads. Existing acquisition and async cancellation/delivery commits are counted separately with their original semantics, including cancelJoined's necessary durable write; do not assert zero total store calls for that fixture.
- [ ] Write `check-retirement.py` to require explicit atomic publication, preserved frozen sources, and the six exact case records/ledger counts; first observe the missing publication/real-job retirement behavior.

```sh
python3 /tmp/haskoki-notifications/record.py task-n03/before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests haskoki-engine-tests --test-show-details=direct --test-options='-p /T-N03/'
```

- [ ] Implement `publishPresence` under existing model gate: validate delta into an unpublished model; in one transaction validate/publish hub and model, with no writes on either error. `snapshotPresence` reads both TVars in one transaction. Preflight delta/epochs/generation/reply before irreversible work; cancel Standard bindings through existing workers/leases outside model gate; publish once; retire views/cursors and drain releases in exception-safe brackets. T-N06 adds native association retirement to the same obligations. Never copy the ignored-error close-all loop. Serving mutations remain serialized under the C state lock; private dispatch serialization must also make expected-generation check/increment atomic.
- [ ] Run focused and retained proofs plus ledger/invariant checker. The two existing Async engine specs are retained unchanged; new integration assertions live in NotificationsEngineSpec.

```sh
python3 /tmp/haskoki-notifications/record.py task-n03/after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests haskoki-engine-tests --test-show-details=direct --test-options='-p /T-N03/'
python3 /tmp/haskoki-notifications/record.py task-n03/retained zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests haskoki-engine-tests haskoki-storage-tests haskoki-prop-tests --test-show-details=direct
python3 /tmp/haskoki-notifications/record.py task-n03/ledger zero python3 /tmp/haskoki-notifications/check-retirement.py dist-release-evidence/notifications/task-n03/after.log
python3 /tmp/haskoki-notifications/evidence.py review task-n03
git diff --check
```

**Acceptance:** Before nonzero names the missing coordinator/publication; all greens exit `0`; six focused cases execute, controlled removal cancels exactly `2` attachments and `0` idle records/other-slot jobs, with zero later writes, leaked views, reset calls or half-publications. Epoch/control/store identities remain distinct. Retained suites pass. Stop for coordinator review before commit; the worker makes no commit.

### T-N04: Public slot, query and wait boundary

**Spec trace:** §§3.1–3.2, 3.5–3.6, 4.1–4.2, 5.3; N01–N04, N10; G01–G03, G09–G11.

**Files:** Modify `ffi/Haskoki/FFI/Standard.hs`, `ffi/Haskoki/FFI/Instance.hs`, `cbits/function_tables.c`, `cbits/standard_surface.c`, `cbits/control_entry.c`, `tests/model/StandardSurfaceSpec.hs`, `tests/model/NotificationsSpec.hs`. Create scratch `/tmp/haskoki-notifications/wait-surface-probe.c`, `/tmp/haskoki-notifications/slot-surface-probe.c`, `/tmp/haskoki-notifications/run-boundary.sh`, `/tmp/haskoki-notifications/check-boundary.py`, `/tmp/haskoki-notifications/wait-surface-probe`, `/tmp/haskoki-notifications/slot-surface-probe`. Evidence: `dist-release-evidence/notifications/task-n04/`.

**Interfaces:** Preserve `on_WaitForSlotEvent`, `std_GetSlotInfo`, `std_GetTokenInfo`, `std_OpenSession` and actual table assignments. Source reconciliation: spec §3.1 calls the listing body `std_GetSlotList`; starting code actually uses `on_GetSlotList` in `cbits/function_tables.c:711`. Keep that real common legacy body and its existing FFI target; no additional route/export is needed.

```c
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID *pSlot, void *pReserved);
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID *pSlotList, CK_ULONG *pulCount);
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO *pInfo);
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO *pInfo);
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, void *pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE *phSession);
unsigned long haskoki_std_get_slot_flags(void *instance, unsigned long slot,
                                        unsigned long *flags);
unsigned long haskoki_wait_for_slot_event(void *cell, unsigned long flags,
                                         unsigned long *slot);
unsigned long haskoki_std_get_slot_list(void *instance, unsigned char token_present,
                                       unsigned long *slots, unsigned long *count);
```

The `C_*` signatures describe table ABI, not new direct exports. Export Haskell `haskokiStdGetSlotFlags :: StablePtr StdInstance -> CULong -> Ptr CULong -> IO CULong`. Keep `haskokiStdGetSlotList :: StablePtr StdInstance -> Word8 -> Ptr CULong -> Ptr CULong -> IO CULong` and `haskokiWaitForSlotEvent :: StablePtr InstanceCell -> CULong -> Ptr CULong -> IO CULong`. `haskoki_std_slot_present` remains token-required. `CK_BBOOL` nonzero remains true; `CKF_DONT_BLOCK=1`, present/removable bits `1/2`, HW bit clear.

- [ ] Register four focused model cases in `Notifications/T-N04`: `caseServingSlotBoundary`, `caseServingWaitOutput`, `caseServingFilteredGrowth`, `caseServingTokenRequired`. Write independent C translation-unit probes (same inclusion/mock/section-GC pattern as the Async plan) for exact liveness/guard/lock/worker/unlock order, complete canaries, full-width flags, slot lookup precedence and passed native arguments. `run-boundary.sh` compiles/runs both with the global `-Werror` flags; `check-boundary.py LOG` requires every row below and zero failures, with labels `notifications:boundary/<entry>/<case>/internal`.

| Ordinary-call input | Exact assertion |
|---|---|
| Wait before init/after finalize; null output, reserved non-null, bits `2`, `3`, high bit | `0x190` lifecycle-first, unchanged writable output, no consume. |
| Live Wait null slot, then reserved non-null, then unknown bits | `0x07`, zero state locks/consumption; reserved never dereferenced; known pending flag remains available. |
| Empty poll / pending poll | `0x08` unchanged / `0` one slot write; no token-presence refusal, no unsupported code. |
| GetSlotList null count; query; short; adequate; CK_BBOOL `2` | ARGUMENTS_BAD; count only; BUFFER_TOO_SMALL updates count only; ascending IDs; nonzero filters present slots. Grow filtered count between query/fetch and retry without consuming events. |
| GetSlotInfo unknown+null / known-empty+valid / known-empty+null | SLOT_ID_INVALID / OK with removable-only / ARGUMENTS_BAD. Whole struct published only on OK. |
| GetTokenInfo or mechanism query unknown / known-empty (including null output) | SLOT_ID_INVALID / TOKEN_NOT_PRESENT, unchanged outputs. Review every `haskoki_std_slot_present` caller. |
| OpenSession | Liveness, null output, missing SERIAL, unknown bits, lock, live owner, catalog, presence, existing rules. Known empty TOKEN_NOT_PRESENT; unknown SLOT_ID_INVALID. Sentinel/pointers retained only on success. |
| CloseAllSessions known-empty / unknown | OK closing zero / SLOT_ID_INVALID; no presence producer. |
| Well-shaped calls on a removed session after reinsert | SESSION_HANDLE_INVALID, never resurrect or convert to TOKEN_NOT_PRESENT. |

- [ ] Run C boundary assertions against the current implementation before changes; expected red is reserved-pointer acceptance/flag consumption or known-empty slot flags. Run Haskell assertions before presence-aware adapters; expected red is missing slot-flags export/incorrect filtered list.

```sh
python3 /tmp/haskoki-notifications/record.py task-n04/before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 bash /tmp/haskoki-notifications/run-boundary.sh
python3 /tmp/haskoki-notifications/record.py task-n04/model-before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests --test-show-details=direct --test-options='-p /T-N04/'
```

- [ ] Route waits from the captured cell to `instSlots`, validate at native width before narrowing, and write only on SlotReady. Use a masked claim-to-output handoff while allowing empty blocking STM retry to be interrupted; pending asynchronous exception cannot consume a flag and suppress its normal write. T-N05 proves the scheduled handoff. Public queries reject a closed interval before reading retained snapshots. Use one captured state under state lock to construct each output, with separate existence and token-required checks. Preserve ordinary unrelated boundary order.

```sh
python3 /tmp/haskoki-notifications/record.py task-n04/after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 bash /tmp/haskoki-notifications/run-boundary.sh
python3 /tmp/haskoki-notifications/record.py task-n04/model-after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests --test-show-details=direct --test-options='-p /T-N04/'
python3 /tmp/haskoki-notifications/record.py task-n04/matrix zero python3 /tmp/haskoki-notifications/check-boundary.py dist-release-evidence/notifications/task-n04/after.log
python3 /tmp/haskoki-notifications/record.py task-n04/abi zero python3 /tmp/haskoki-notifications/evidence.py generators abi
python3 /tmp/haskoki-notifications/record.py task-n04/retained zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests haskoki-engine-tests --test-show-details=direct
python3 /tmp/haskoki-notifications/evidence.py review task-n04
git diff --check
```

**Acceptance:** Intended before exits nonzero, five green commands exit `0`, four focused Haskell cases and every C matrix row execute. Wait lock count `0`, one consumption/write on OK, zero writes on non-OK, slot filtering counts `2→1→2` on two-token fixture. All four ABI layouts/ordinal `68` unchanged and all four generated outputs identical on two runs. Stop for coordinator review before commit; the worker makes no commit.

### T-N05: Finalize priority, waiter competition and retained-cell lifetime

**Spec trace:** §§3.4, 3.6, 3.8, 4.1, 5.2; N04, N06, N10; G05–G06, G17.

**Files:** Modify `ffi/Haskoki/FFI/Instance.hs`, `src/Haskoki/Runtime/SlotEvents.hs` (observer placement only if needed), `cbits/function_tables.c`, `cbits/control_entry.c`, `tests/model/NotificationsSpec.hs`, `tests/engine/NotificationsEngineSpec.hs`. Create scratch `/tmp/haskoki-notifications/finalize-probe.c`, `/tmp/haskoki-notifications/run-finalize.sh`, `/tmp/haskoki-notifications/finalize-probe`, `/tmp/haskoki-notifications/check-waits.py`. Evidence: `dist-release-evidence/notifications/task-n05/`.

**Interfaces:** Reuse T-N01 observer constructors and `readLiveInstance`; install `WaitCaptured` after retaining the old service, `WaitBeforeRetry` outside STM with recheck, `WaitDecisionCommitted` after decision before output, and `CloseCommitted` after the close transaction. No new C export. Existing `haskoki_instance_shutdown(void)` closes/unbinds the old service before `haskoki_std_shutdown(void)` releases native resources. Keep one never-freed empty InstanceCell/StablePtr per interval; never reload the global root from a captured wait.

- [ ] Register model `caseServingWaitCompetition` and engine `caseServingFinalizeOrder`, `caseServingMaskedHandoff` under `Notifications/T-N05` (one model case, two engine cases, no empty selected suite). Use two waiting transactions and mixed poll/block competitors: one flag → exactly one OK, two flags → exactly two OKs, all undecided callers closed with no duplicate slot. Parked losers remain waiting until close. Poll never enters retry.
- [ ] Force six schedules using observer barriers: (1) empty close, (2) queued close-first, (3) event claim then close then delayed output, (4) retained cell captured before close but FFI entered after reopen, (5) retained hub captured then close/reopen, (6) Finalize state-lock refusal then retry. Outcomes are respectively all closed, no queued success, one owned OK despite later return, old NOT_INITIALIZED, old NOT_INITIALIZED, and first lock code with still-live hub followed by successful close. New interval starts clear. Finalize need only make undecided blockers runnable, not wait for already-decided application threads to return.
- [ ] Inject an async exception during empty wait and during the decision/output handoff. Empty retry remains interruptible; the foreign fence returns GENERAL_ERROR without changing the sentinel when no claim was made. Once a decision commits, the mask protects the normal output write. Do not use an interruptible blocking observer to invalidate that guarantee: record mask state and queue injection for delivery outside the protected handoff. Native invalid output pointers remain outside this guarantee.
- [ ] `run-finalize.sh` compiles/runs the C mock probe with global C flags plus section GC. It records close/unbind before backend/store release and verifies `CKR_CANT_LOCK` restores liveness without closing. The T-N01 closed-first leaf is already retained green; the new red is C teardown releasing Standard before the shared service is closed, not a contrived regression in that leaf.

```sh
python3 /tmp/haskoki-notifications/record.py task-n05/before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 bash /tmp/haskoki-notifications/run-finalize.sh
```

- [ ] After successful Finalize state-lock acquisition, atomically close/discard pending flags and clear owner before Standard teardown, preserving failure-path liveness restoration. Retain the safe cell lifetime fix; update comments describing historical plain-pointer races. Keep cancellation/native cleanup after service close, with no permanent thread and no wait on descheduled already-decided callers.

```sh
python3 /tmp/haskoki-notifications/record.py task-n05/after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 bash /tmp/haskoki-notifications/run-finalize.sh
python3 /tmp/haskoki-notifications/record.py task-n05/schedules zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests haskoki-engine-tests --test-show-details=direct --test-options='-p /T-N05/'
python3 /tmp/haskoki-notifications/record.py task-n05/check zero python3 /tmp/haskoki-notifications/check-waits.py dist-release-evidence/notifications/task-n05/schedules.log
python3 /tmp/haskoki-notifications/record.py task-n05/retained zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests haskoki-engine-tests --test-show-details=direct
python3 /tmp/haskoki-notifications/evidence.py review task-n05
git diff --check
```

**Acceptance:** Before nonzero names close-before-teardown violation; all greens exit `0`, three focused cases and six explicit schedules recorded. One/two flags yield exactly one/two successes; zero closed-tail deliveries, zero waiter migrations, zero freed-cell dereferences, every bounded join completes. Lock refusal preserves a usable interval. Retained-cell cost documented honestly. Stop for coordinator review before commit; the worker makes no commit.

### T-N06: Native association and reentry guard before any producer

**Spec trace:** §§3.2, 3.7–3.8, 4.3, 5.1–5.2; N07, N08, N10; G12–G14.

**Files:** Create `ffi/Haskoki/FFI/Notify.hs`, `cbits/notify_guard.h`, `cbits/notify_guard.c`, `tests/engine/notifications_adapter.c`; modify `haskoki.cabal` (both Haskell module/C source lists, main library pinned-header include path, engine adapter C source and `spec/vendor`/`cbits` include paths), `ffi/Haskoki/FFI/Standard.hs`, `cbits/function_tables.c`, `cbits/standard_surface.c`, `cbits/control_entry.c`, `cbits/exports.c`, `scripts/generate-abi.py` (policy comments only), `tests/engine/NotificationsEngineSpec.hs`. Regenerate/require unchanged `cbits/abi_stubs.inc`, `cbits/abi_generated.h`, `spec/abi-inventory.json`, `spec/abi-reconciliation.json`. Create scratch `/tmp/haskoki-notifications/reentry-probe.c`, `/tmp/haskoki-notifications/run-reentry.sh`, `/tmp/haskoki-notifications/reentry-probe`, `/tmp/haskoki-notifications/check-guards.py`. Evidence: `dist-release-evidence/notifications/task-n06/`.

**Interfaces:** Notify module holds native types/dispatcher; Standard owns `siNotify :: IORef (Map SessionId SessionNotify)` and re-exports the spec types/helpers for tests. No untyped private String callback conversion.

```haskell
type NativeNotify = CULong -> CULong -> Ptr () -> IO CULong
data SessionNotify = SessionNotify
  { snFunction :: !(FunPtr NativeNotify), snApplication :: !(Ptr ()) }
data NotifyDecision = NotifyContinue | NotifyCancel | NotifyFailed
registerSessionNotify :: StdInstance -> SessionId -> SessionNotify -> IO ()
retireSessionNotify :: StdInstance -> SessionId -> IO ()
surrenderDigest :: StdInstance -> SessionId -> IO NotifyDecision
haskokiStdOpenSessionWithNotify
  :: StablePtr StdInstance -> CULong -> CULong -> CULong
  -> Ptr () -> FunPtr NativeNotify -> Ptr CULong -> IO CULong
foreign import ccall safe "haskoki_invoke_notify"
  invokeNativeNotify :: FunPtr NativeNotify -> CULong -> CULong -> Ptr () -> IO CULong
type NotifyInvoker = FunPtr NativeNotify -> CULong -> CULong -> Ptr () -> IO CULong
dispatchSessionNotifyWith :: NotifyInvoker -> SessionId -> SessionNotify -> IO NotifyDecision
openStdInstanceWithNotify :: StdAcquisition -> Config -> SlotEvents -> NotifyInvoker
  -> IO (StablePtr StdInstance)
```

```c
typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE, CK_NOTIFICATION, void *);
unsigned long haskoki_std_open_session(void *instance, unsigned long slot,
    unsigned long read_only, unsigned long async_session,
    void *application, CK_NOTIFY notify, unsigned long *session);
int haskoki_in_notify(void);
unsigned long haskoki_invoke_notify(CK_NOTIFY notify, unsigned long session,
    unsigned long event, void *application);
```

The header exposes the type-independent guard declaration to the mirror TU without importing conflicting vendor types. The invoker definition uses pinned `CK_NOTIFY` in its own C TU. Compile/link the guard in main library and foreign library as appropriate to each component, without duplicate definition in one linkage. Keep existing `haskokiStdOpenSession` and `haskokiStdOpenSessionWithAsync` wrappers supplying null callback/application; change only the existing foreign export target/signature. `siNotifyInvoker :: NotifyInvoker` is constructor-injected: production `openStdInstanceWithSlots` delegates to `openStdInstanceWithNotify` with `invokeNativeNotify`; tests may inject a throwing Haskell action before entering C. The typed dispatcher catches that action, not exceptions escaping a foreign callback, and T-N07 can test the real Digest failure branch without a public fault switch.

- [ ] Register `caseNativeNotifyAssociation`, `caseNativeNotifyRetirement`, `caseNativeNotifyGuard` in `Notifications/T-N06`. Four independent nullness shapes all admit; failed admission retains zero pairs and leaves sentinel; two sessions carry distinct actual handles/cookie addresses. Inject failure before/after model admission, registry insertion and borrowed-view installation; require paired rollback and no leaks. Retire on close-one/all, removal, failed cleanup, and finalize without invocation; extend T-N03 release-fault assertions to the new registry.
- [ ] Implement a test C adapter (linked only into the test executable) to call the safe invoker and record thread/cookie/code plus a normal-return trampoline around its own simulated language failure. Haskell typed test adapters may throw and must map to NotifyFailed. Never throw a Haskell exception through a C callback wrapper, or let C++ exceptions/longjmp cross the ABI. No test-only export is added to the provider.
- [ ] Write `reentry-probe.c`/`run-reentry.sh` with global C flags. Link the real C surface translation units plus `notify_guard.c` into the scratch executable with typed mock Haskell/RTS exports in the probe; a mock worker call is a failure. This puts the internal invoker and serving entries in the same TLS linkage, without trying to dlsym a hidden invoker from a module or using a second module's guard. Exercise all `68/92/92/104` table members at their actual layouts. Whitelist only static GetFunctionList/GetInterfaceList/GetInterface/GetInfo with their normal argument checks. Every other entry, including stubs, legacy parallel probes, both waits, Control, Initialize and Finalize, returns FUNCTION_FAILED (`0x06`) before locks or pointer inspection. Pass guarded inaccessible pointers to prohibited calls; assert zero worker/termination/lock calls. Use negotiated nonrecursive mutexes. Stable labels `notifications:guard/<entry>/<version>`; exactly `356` versioned table-member checks, plus Control checks outside the table.
- [ ] Observe missing association and unguarded entry reds before installing the bridge. `check-guards.py` also requires direct guard-before-argument placement on routed entries and guards in `stub_probe`, `stub_parallel`, `x_live_check`; void casts in generated stubs are not buffer inspections.

```sh
python3 /tmp/haskoki-notifications/record.py task-n06/before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-engine-tests --test-show-details=direct --test-options='-p /T-N06/'
python3 /tmp/haskoki-notifications/record.py task-n06/guard-before nonzero python3 /tmp/haskoki-notifications/check-guards.py
```

- [ ] Install association before publishing the native handle; null Notify never calls, non-null application with null Notify is valid. Add TLS enter/restore around normal-return native invocation, safe Haskell import, and exception fence in the typed Haskell dispatcher. Keep the caller bound thread; no application callback under model/registry/store lock or async lease. Put the reentry check first in every prohibited serving body, before existing malformed-argument termination helpers and locks. Shared helpers guard all generated/legacy stubs while preserving ordinary stub-first precedence; update generator comments and regenerate identically. Do not yet enable a production callback producer.

```sh
python3 /tmp/haskoki-notifications/record.py task-n06/after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-engine-tests --test-show-details=direct --test-options='-p /T-N06/'
python3 /tmp/haskoki-notifications/record.py task-n06/guard-after zero python3 /tmp/haskoki-notifications/check-guards.py
python3 /tmp/haskoki-notifications/record.py task-n06/native zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 bash /tmp/haskoki-notifications/run-reentry.sh
python3 /tmp/haskoki-notifications/record.py task-n06/determinism zero python3 /tmp/haskoki-notifications/evidence.py generators abi
python3 /tmp/haskoki-notifications/record.py task-n06/retained zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests haskoki-engine-tests --test-show-details=direct
python3 /tmp/haskoki-notifications/evidence.py review task-n06
git diff --check
```

**Acceptance:** Both before commands nonzero identify missing registry/guard; greens exit `0`. Three cases, four nullness shapes, two distinct session/cookie pairs, `356` table-member checks plus Control are accounted. Zero leaked associations/views or prohibited reentry lock/worker/output actions; TLS cleared after every normal/test-fenced path. All generated bytes unchanged; zero production callbacks until T-N07. Stop for coordinator review before commit; the worker makes no commit.

### T-N07: Bounded synchronous Digest surrender

**Spec trace:** §§3.7–3.8, 4.3, 5.1; N07, N08, N12; G12–G13.

**Files:** Modify `ffi/Haskoki/FFI/Standard.hs` (only fresh synchronous `runStdDigestBuffered` branch and necessary termination glue), `tests/engine/NotificationsEngineSpec.hs`, `tests/engine/notifications_adapter.c`. Create scratch `/tmp/haskoki-notifications/digest-notify-probe.c`, `/tmp/haskoki-notifications/run-digest-notify.sh`, `/tmp/haskoki-notifications/digest-notify-probe`, `/tmp/haskoki-notifications/check-digest-notify.py`. Evidence: `dist-release-evidence/notifications/task-n07/`.

**Interfaces:** Consume T-N06 `surrenderDigest :: StdInstance -> SessionId -> IO NotifyDecision`. Add `withDigestSurrender :: StdInstance -> SessionId -> IO CULong -> IO CULong` in Standard: the third argument is the already-admitted synchronous execution/publication continuation; refusal terminates SlotDigest without entering it. The selected production branch passes its existing `synchronous` action; test continuations count entry and writes without replacing the native success proof. Emit `(actualSession, CKN_SURRENDER=0, originalApplication)` exactly once only for an ordinary session's fresh `Execute _ (EffectCrypto (FxDigest ...))`, known fixed-width recipe, admitted adequate buffer, immediately before running the effect. Native callback returns `CKR_OK=0`, `CKR_CANCEL=1`, or any other native-width value; Digest maps these to normal result, `CKR_FUNCTION_CANCELED=0x50`, or `CKR_FUNCTION_FAILED=0x06`. Preserve the existing foreign catch-all `GENERAL_ERROR=0x05` for unrelated unexpected provider failures.

- [ ] Register `caseDigestSurrender`, `caseNotifyNonProducers`, `caseNotifyDigestIsolation` in `Notifications/T-N07`. At the `withDigestSurrender` boundary count invoker calls, execution-continuation entries and publication writes separately. OK: `1/1/1`; CANCEL/other numeric (`0x1234567887654321UL`)/test-adapter exception: `1/0/0`. Also invoke the actual Standard Digest export with a real backend for each outcome: terminate Digest on refusal, unchanged output and incoming length (`64` distinguishes it from expected digest length `32`), then repeated Digest gives OPERATION_NOT_INITIALIZED. Fresh DigestInit restores usability; another session's operation remains intact. Test null cookie, null Notify with non-null cookie, exact callback thread/session/cookie and TLS restoration. Keep boundary instrumentation counts separate from the native real-backend observations.
- [ ] Pin silent paths separately: DigestInit/Update/Final, null-output query, capacity `0/31`, staged recall, decode/planner refusal, every explicit async-session Digest path including synchronous fallback, Complete/GetID/Join/cancel, non-Digest crypto, RNG, login/logout, object/session/control/slot calls, close/removal/finalize. No insertion callback, OTP value, or arbitrary notification is invented. Existing Async occupancy, two-poll execution, version `0/1` distinction and private Join status remain unchanged.
- [ ] Write native probe using pinned header and real discovered table with a normal C callback. `run-digest-notify.sh` builds `all`, compiles with global C flags, loads `/work/dist-newstyle/build/x86_64-linux/ghc-9.10.3/haskoki-0.3.0.0/f/haskoki/build/haskoki/libhaskoki.so`, and requires exact SHA-256 plus cancel/reentry canaries. Explicitly exercise static discovery success and GetSlotList, SessionCancel on 3.x, nested Digest, both waits, Control, CloseSession and Finalize returning `0x06`, including nonrecursive application mutex mode. Record actual native thread identity as equality, not a transcript address.
- [ ] Observe the selected fresh synchronous call currently producing zero notifications, before adding the emission point.

```sh
python3 /tmp/haskoki-notifications/record.py task-n07/before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-engine-tests --test-show-details=direct --test-options='-p /T-N07/'
```

- [ ] Add exactly the selected pre-effect call. Continue the already-admitted plan once on NotifyContinue; on cancel/failure terminate and drain through existing Standard ownership before returning the mapped code, without executing the effect or writing length/data. Do not hook generic crypto runners or async workers. Restore ownership on typed exceptions; do not claim recovery from foreign undefined behavior. Assert the model gate is free at dispatch while the C state lifetime lease remains held.

```sh
python3 /tmp/haskoki-notifications/record.py task-n07/after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-engine-tests --test-show-details=direct --test-options='-p /T-N07/'
python3 /tmp/haskoki-notifications/record.py task-n07/native zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 bash /tmp/haskoki-notifications/run-digest-notify.sh
python3 /tmp/haskoki-notifications/record.py task-n07/counts zero python3 /tmp/haskoki-notifications/check-digest-notify.py dist-release-evidence/notifications/task-n07/after.log dist-release-evidence/notifications/task-n07/native.log
python3 /tmp/haskoki-notifications/record.py task-n07/retained zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests haskoki-engine-tests --test-show-details=direct
python3 /tmp/haskoki-notifications/evidence.py review task-n07
git diff --check
```

**Acceptance:** Before nonzero is the missing surrender call; all greens exit `0`, three focused cases execute, call/effect/publication counts exactly `1/1/1` or `1/0/0`, and every listed non-producer count is `0`. Native output is exact `32` bytes on OK; cancellation/error leave all bytes/length/canaries unchanged and operation terminated. Stop for coordinator review before commit; the worker makes no commit.

### T-N08: Independent native consumers and retained drivers

**Spec trace:** §§3.1–3.8, 4.1–4.3, 5.1–5.4; N01–N10, N12; G01–G17.

**Files:** Create `tests/c/notifications_routed.c`, `tests/c/consumer_notifications_poll.c`; modify `tests/c/control_events.c`, `tests/c/sim_threaded.c`, `tests/c/finalize_wait_race_probe.c`, `tests/c/consumer_errors.c` (explanation of its zero-callback sequence only), `scripts/test-consumers.sh`, `scripts/test-proxy-parity.sh` (enumeration only). Create scratch `/tmp/haskoki-notifications/build-baseline.py`, `/tmp/haskoki-notifications/run-native.py`, `/tmp/haskoki-notifications/check-native.py`; baseline archive/build under `/tmp/haskoki-notifications/baseline/`, binaries/configs/databases under `/tmp/haskoki-notifications/native/`. Evidence: `dist-release-evidence/notifications/task-n08/` including `baseline/` and `direct/` child receipts.

**Interfaces:** `notifications_routed MODULE` runs all versions separately and both memory/SQLite modes. Explicit child form is `notifications_routed MODULE --version VERSION --storage MODE --leg LEG --directory DIR`; VERSION is `2.40|3.0|3.1|3.2`, MODE `memory|sqlite`, LEG one of `entry,initial,presence,coalescing,cleanup,waiters,notify,reentry,restart`. `consumer_notifications_poll MODULE` runs the four table layouts with only parity-eligible valid polling/sequential lifecycle/live structural checks. Exit `0` = zero assertion failures; `1` = named assertion failure; `2` = setup failure. Normal full invocation coordinates its own children and cleans only its owned resources.

Stable labels are `notifications:<leg>/<case>/<version>/<storage>` and `notifications-poll:<case>/<version>`. Print CK_RV, counts, flags, epochs, hex digest/canary status, and discovered logical `slot-A/slot-B`; never raw session IDs, pointer addresses, temp paths, PIDs, chosen waiter identity or raw slot IDs as comparison identities. All slot selection uses enumeration. Discover 2.40 with GetFunctionList and 3.x with requested GetInterface, using the true legacy/3.0/3.2 layouts. Public consumers include only `spec/vendor/pkcs11.h` and independently declare `HASKOKI_Control`; no generated provider ABI/types or private trampolines.

`run-native.py baseline|direct|final` compiles both C files with the global flags, executes each child as separate argv, stores each receipt, and aggregates without stopping at the first assertion failure. In that same container, `baseline` first runs `cabal build all` in the separately archived starting-HEAD tree and loads only its module; `direct` builds `all` in `/work` then loads that exact current build; `final` loads the sole relocatable pinned release bundle. It exits `1` on semantic failures and `2` on setup/crash/timeout; `check-native.py STAGE` checks all required labels, identities and counts without widening RV sets. Direct/final also compile `tests/c/finalize_wait_race_probe.c` with the global flags to `/tmp/haskoki-notifications/native/finalize-wait-probe` and run it on the same selected module with `HASKOKI_FINALIZE_WAIT_CYCLES=100`, retaining a separate child receipt. That corrected manual probe is not executed by `scripts/test-finalize-race.sh`, which runs `finalize_race.c`; account for both.

- [ ] Write all nine independent leg assertion functions before fixture helpers, using T-N01–T-N07 red assertions as explicit ownership links. Run `check-native.py direct` before collecting anything; intended missing-evidence red is `missing notifications native matrix: 4 versions x 2 stores x 9 legs`. Retained polling/initial/old-cell facts that already pass are not required to fail.

```sh
python3 /tmp/haskoki-notifications/record.py task-n08/before nonzero python3 /tmp/haskoki-notifications/check-native.py direct
```

- [ ] Implement fixtures with real OpenSSL, synthetic fallback disabled, trace off, two configured tokens, test controls enabled and separate fixed-mode initialization within the initial leg. Use C11 atomics/condition variables and bounded child/thread joins. Before each live malformed **blocking** Wait probe, seed a pending indication with remove/insert so an old implementation's erroneous acceptance returns a named wrong-RV/consumption assertion instead of hanging. A child stops at its first failed assertion and safely cleans up before any dependent guarded-memory operation; the parent continues other children. Never relabel a timeout/crash as a semantic red. Execute this entire matrix:

| Leg | Required native assertions |
|---|---|
| `entry` | Spec §5.3.1 full malformed/live/lifecycle wait matrix, native high bits, unknown slot versus known empty, no consumed flags, whole-struct canaries and list null/short/adequate cases. |
| `initial` | Two full/present slots, clear flags, epochs zero; removable+present in test mode; fixed+present when disabled; no HW flag, disabled mutation refusal. |
| `presence` | Remove discovered A → event A; full list `2`, present list `1`, SlotInfo removable-only, TokenInfo/OpenSession TOKEN_NOT_PRESENT; insert → event A, present `2`, new admission. Queries do not acknowledge. |
| `coalescing` | Three alternating changes → epoch +`3`, one A then NO_EVENT; duplicate commands add zero epoch/events. Pending A/B each consumed once in first-pending order. Grow filtered count between sizing/fetch: required count changes, array stays untouched on short, retry works. |
| `cleanup` | Session object, token handle, login/cursor/multipart state retired; real Standard async Digest's old guarded output becomes PROT_NONE after removal; no later write, old sessions/handles stay invalid after reinsertion; other-slot session works. SQLite 3.2 additionally keeps one idle detached record joinable under existing home-slot policy and cancels a joined attachment. Older layouts exercise async-session removal without reading async tail members; 3.2 supplies completion/join corroboration. |
| `waiters` | Two native blockers plus competing polls yield no duplicates; a real transition produces one OK; close bounds remaining joins with NOT_INITIALIZED. Reopen gives NO_EVENT. Run `100` bounded empty finalize/reopen stress iterations per version/store; T-N05 remains the deterministic winner proof. |
| `notify` | Actual C function pointer and original cookie, four nullness shapes, two sessions, same thread; SHA-256 `abc`; callback OK/CANCEL/other-code with exact results/canaries. No query/short/recall/multipart/explicit-async/lifecycle/control producer. |
| `reentry` | Static discovery/GetInfo succeed with valid arguments; listed prohibited calls return FUNCTION_FAILED promptly and touch nothing under internal and negotiated nonrecursive locks. Close/all/remove/finalize prevent any later access to retired cookie storage. A fixture catches its own exception and returns normally. |
| `restart` | Fresh initialization after removal: same configured identity present, no replayed event/callback; same SQLite file and unchanged durable generation. Memory retains only its existing transient behavior. No ordinary object-durability claim. |

- [ ] Add exact source baseline comparison without resetting the checkout. `build-baseline.py` archives `git archive 6fa6696273d8111ad64a6474d68552369fa37c22` into the exclusively owned baseline directory and hashes it; `run-native.py baseline` builds and loads it within one pinned container. Keep baseline and current build directories disjoint. Record baseline module `input_revision` separately from recorder's current working HEAD. All helper-launched Docker commands use the global 2400-second KILL rule. Compile the new assertions against the pinned header once, then run on the baseline module; missing required behavior must yield exit `1` with explicit reserved-pointer/coalescing/coherence/callback diagnostics, never setup exit `2`. Already-covered behavior remains a retained pass. Do not claim any baseline failure as a current implementation result.

```sh
python3 /tmp/haskoki-notifications/record.py task-n08/baseline-archive zero python3 /tmp/haskoki-notifications/build-baseline.py
python3 /tmp/haskoki-notifications/record.py task-n08/behavior-before nonzero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 python3 /tmp/haskoki-notifications/run-native.py baseline
```

- [ ] Correct `control_events.c` to remove initially present A before testing blocking reinsertion, replace sleep/plain done with atomics/conditions, and assert query/event agreement. Configure `sim_threaded.c` slot `1` explicitly, preserve existing independent-slot churn/conservation and add a separately labeled same-slot removal test with exact invalidation expectations. Correct the finalize race probe's historical pointer comment; empty fixture must yield only NO_EVENT/NOT_INITIALIZED as appropriate, zero unexplained OK. Keep consumer_errors' open/info/close count `0`, narrowing its prose to that sequence.
- [ ] Enumerate both new sources exactly once in both drivers, preserving stable sorting/independence checks over the whole list and fatal missing-file checks. `consumer_notifications_poll.c` is globbed exactly once; `notifications_routed.c` is explicitly added beside message/async. T-N09 adds the real issue-backed direct-only entry. Do not claim parity or run the required-zero full parity driver before that disposition exists.

```sh
python3 /tmp/haskoki-notifications/record.py task-n08/after zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 python3 /tmp/haskoki-notifications/run-native.py direct
python3 /tmp/haskoki-notifications/record.py task-n08/matrix zero python3 /tmp/haskoki-notifications/check-native.py direct
python3 /tmp/haskoki-notifications/record.py task-n08/consumers zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-consumers.sh
python3 /tmp/haskoki-notifications/record.py task-n08/control zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-control-events.sh
python3 /tmp/haskoki-notifications/record.py task-n08/threaded zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-sim-threaded.sh
python3 /tmp/haskoki-notifications/record.py task-n08/race zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-finalize-race.sh
python3 /tmp/haskoki-notifications/record.py task-n08/attached zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-async-attached.sh
python3 /tmp/haskoki-notifications/record.py task-n08/detached zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-async-detached.sh
python3 /tmp/haskoki-notifications/evidence.py review task-n08
git diff --check
```

**Acceptance:** Missing-matrix red nonzero and baseline semantic red exit `1` documented; every current green exits `0`. Matrix has exactly `72` top-level leg results plus four polling-table results, `800` supplementary matrix race iterations plus `100` corrected manual-probe iterations, and explicit fixed/removable sublegs. All applicable 3.2 detached assertions execute (not fabricated on older layouts). Zero duplicate events, post-removal writes, canary failures, retired callback accesses, or fixture child leaks. Existing attached/detached/restart and routed consumers keep passing. Stop for coordinator review before commit; the worker makes no commit.

### T-N09: Pinned proxy candidate, distinct filing, fast then kat dispositions

**Spec trace:** §§5.4–5.6; N11, N12; retained G17 scope distinctions.

**Files:** Modify `scripts/test-proxy-parity.sh` (notifications disposition only), `docs/pkcs11-check-upstream-issues.md`, `docs/pkcs11-oracle-triage.md`. Create scratch `/tmp/haskoki-notifications/proxy-probe.c`, `/tmp/haskoki-notifications/proxy-observer.c`, `/tmp/haskoki-notifications/proxy-repro.py`, `/tmp/haskoki-notifications/proxy-issue.md`, `/tmp/haskoki-notifications/check-proxy.py`, `/tmp/haskoki-notifications/pins.py`, `/tmp/haskoki-notifications/lane.py`, `/tmp/haskoki-notifications/inspect-lane.py`, `/tmp/haskoki-notifications/oracle-notifications.c`, `/tmp/haskoki-notifications/oracle-issue.md`; compiled artifacts `/tmp/haskoki-notifications/proxy-probe`, `/tmp/haskoki-notifications/proxy-observer.so`, `/tmp/haskoki-notifications/oracle-notifications`; configs/owned processes under `/tmp/haskoki-notifications/proxy/`. Evidence under `dist-release-evidence/notifications/proxy/` and `dist-release-evidence/notifications/reviewed/`.

**Interfaces:** `proxy-repro.py reviewed|final MODULE` records bounded direct/proxied outcomes and identity; `check-proxy.py reviewed|final` requires actual reproduction, full direct success, pin match and issue readback. `pins.py sources` runs on the host, captures the quoted immutable source blobs/pair/header/oracle pins into `proxy/pins.json` and `proxy/sources/` without requiring a release bundle. `pins.py reviewed|final` writes stage `pins.json`, additionally measuring actual bundle/module/image/source identity. Container probes read those captured source artifacts through `/work/dist-release-evidence/notifications/proxy/` and rehash the actually mounted pair/module; they do not assume the host proxy Git checkout exists inside the container. `lane.py STAGE fast|kat` archives previous outputs, invokes the exact wrapper through the unchanged recorder, copies results/traces and checks before/after pins. `inspect-lane.py STAGE fast|kat` validates actual findings/dispositions and writes `STAGE/<lane>-inspection.json`. Required disposition format remains `notifications_routed:ACTUAL_ISSUE_URL`, with no placeholder installed in code.

Reuse Async Task 8's verified pins **exactly**:

| Pin | Exact value |
|---|---|
| Proxy repository/source commit | `/home/user/src/m/pkcs11-proxy-ng-ws/pkcs11-proxy-ng`, `a48b60ba54b0163f4999c1e4fc0514bf7dc01681` |
| `/opt/pkcs11-proxy-ng/pkcs11-proxy-ng` SHA-256 | `260cb245981561291eab4d29a16cb6a4d6f00dca3431f3d583d35364fab0c9e5` |
| `/opt/pkcs11-proxy-ng/libpkcs11_proxy_ng_shim.so` SHA-256 | `8ea85073ce8436ebdc8ee99bce99e70a6d8c34473c28b5a45567c8a26aba1690` |
| Pinned `crates/shim/src/dispatch/general/async_ops.rs` SHA-256 | `cf1239e40f482755006bb1d1988b9d083f8f36312ad4d9543160e9c31c40ca72` |

Also assert the notification source pins from spec §5.5, using `git show COMMIT:PATH`, never checkout HEAD:

| Proxy source path | SHA-256 |
|---|---|
| `crates/shim/src/dispatch/general/state_ops.rs` | `c6907ccb2f8f7138ffdadb25a2174da8e6a9dae67bd9dac8c5747d326113f485` |
| `crates/shim/src/dispatch/general/helpers.rs` | `7ffac3e129781c6f449d4d20de2733e058febb4947655fb1e92b241534988d40` |
| `crates/shim/src/dispatch/general/session.rs` | `9ced22f764c6cfb31eff25251cd32aafe2f4219b71c9a608262ac6c2fcb166ed` |
| `crates/server/src/server/grpc_service/state_ops/slot_event.rs` | `f620f3e2757f203f94cbe217eba5c6d29395d9ad4e65dd00a8a3f81708a1b8a0` |
| `crates/server/src/server/grpc_service/general/lifecycle.rs` | `f8471f29ba797c87dd8bdeb124dec73776b0375e25eb5e69996b455cc48712dc` |

Reuse Async Task 10's verified oracle table **exactly**, including counts that concern Async rather than notifications:

| Oracle path relative to `src/pkcs11_check/testcases` | All test definitions | Async-specific definitions | SHA-256 |
|---|---:|---:|---|
| `test_remaining_gaps.py` | 29 | 4 | `56ca76211694ac5c8fe8142cc550d8415d91ee39da830240db0cf0a5c9a9a33f` |
| `ckr/test_ckr_v32_raw.py` | 8 | 1 | `278d32b6509e556746c4fb3ef688315c1f21c701cdc8a2bfddcaa7bda3eafcb1` |
| `_probes/ckr_v32_raw.py` | 0 | 0 | `3167748a0ff6336d457b36f442f3156c8c6cc71892c70e58a16f70b89bb5819e` |
| `ckr/_ckr_spec.py` | 0 | 0 | `79c590d8f81c0f6bbf0b437e19a234e91411a6dd684dd98741a2210f8ca03136` |
| `ckr/_ckr_spec_tables.py` | 0 | 0 | `3df59974adfcb4e3112db1851676ce7b11f91c34d3c001458c38a5096d2aaba2` |

Oracle root `/tmp/pkcs11-ws/pkcs11-check-0.2.2rc2`, package `0.2.2rc2`; exactly `519` Python files under `src`; full digest `b7b5327c4294a892fcf21f351717bb240b2505621ce842c182b33cf6685bad23`. Digest sorted release-relative UTF-8 path, NUL, raw bytes, NUL. Count all `ast.FunctionDef`/`ast.AsyncFunctionDef` starting `test_` using `ast.parse`/`ast.walk` without imports/pytest; Async-specific names start `test_async_`. Verify declared version without importing the package. No invented release-tree Git revision.

Additional notifications coverage pins from spec §5.6 (same relative root):

| Path | All test definitions | SHA-256 |
|---|---:|---|
| `test_remaining_gaps.py` | 29 | `56ca76211694ac5c8fe8142cc550d8415d91ee39da830240db0cf0a5c9a9a33f` |
| `ckr/test_ckr_slot_token.py` | 3 | `9262b2b88f77628eab25f8e0ae0ba13c808f145b7157612e84686e7a377ab603` |
| `test_session_edge_cases.py` | 7 | `167703230e29892e4b0f3db498035f0bf1b9b27d252f1a2f369349b105eb26b8` |
| `test_token_flags.py` | 18 | `6a93dfac30b6df2a076876186255eddf40be5e703dc8743126f641ff48cdda09` |
| `test_interface.py` | 11 | `879de8b7223b2e63bb00c369d1a305bcc372be5accbcc2bdbb12c01834b19d01` |
| `ckr/_ckr_spec_tables.py` | 0 | `3df59974adfcb4e3112db1851676ce7b11f91c34d3c001458c38a5096d2aaba2` |

- [ ] Write checkers first. `check-proxy.py reviewed` must fail for missing **new notifications reproduction and filing**; lane inspector must fail on absent raw JSON/nonempty trace/findings review. Expected nonzero is missing evidence, not an asserted proxy hang.

```sh
python3 /tmp/haskoki-notifications/record.py proxy/before nonzero python3 /tmp/haskoki-notifications/check-proxy.py reviewed
python3 /tmp/haskoki-notifications/record.py reviewed/before nonzero python3 /tmp/haskoki-notifications/inspect-lane.py reviewed fast
python3 /tmp/haskoki-notifications/record.py proxy/pins zero python3 /tmp/haskoki-notifications/pins.py sources
```

- [ ] Capture installed pair hashes and all pinned source blobs/line references through `pins.py`. Treat “Blocking C_WaitForSlotEvent cannot be interrupted by client C_Finalize” as a **reproduction CANDIDATE**. Source suggests shim client mutex retention (`helpers.rs:23-32`, `init_general.rs:124-135`) and server context removal without backend wait cancellation (`general/lifecycle.rs:43-64`). Source inspection alone is not a hang result. Callback pointers are dropped (`session.rs:7-18`, backend `session_ops.rs:112-126`); optional surrender is a capability limitation, not mandatory insertion-callback conformance.
- [ ] Build a bounded independent pinned-header probe calling real table blocking wait (`flags=0`, reserved null, sentinel output) then concurrent Finalize. Use two legs: ordinary direct Haskoki and pinned shim/daemon with same provider binary/config. Fixed empty-event fixture has no event producer. Collect individual return codes, output snapshots, entry acknowledgments and monotonic durations. Start only an owned daemon on loopback `17514`, refuse a busy port, readiness bound `30s`, and preserve normal proxy timeout `60s`; do not change binaries or provider behavior.
- [ ] For positive transport admission evidence, the scratch `proxy-observer.so` may wrap only discovery/table Wait and transparently forward to the exact Haskoki module, announcing backend Wait entry over an inherited pipe before delegation. Compile with global flags plus `-shared -fPIC`; hash/save the wrapper. It does not generate events, export a provider test hook, sleep, or alter RVs. Receiving this acknowledgment proves the pinned RPC reached backend dispatch while the shim request is outstanding; it does not prove Haskell STM parking. T-N05 supplies that separate proof. Run unwrapped corroboration too and distinguish it in receipts. A pre-call client signal alone is insufficient for reproduction attribution.
- [ ] After admitted blocking request, Finalize must complete/direct waiter must return NOT_INITIALIZED with unchanged sentinel in the direct comparison; observe the proxied outcome for a bounded `10s` window, shorter than configured transport timeout. Record blocked completion or any actual RV exactly. A transport timeout/error is never normalized to a finalize wake. Parent containment terminates/reaps only its own children/daemon in finally. If evidence does not support the candidate, record inconclusive/disproved status and stop N11 acceptance; do not create a false issue or broaden success codes. `proxy-repro.py` exits `0` only when its stated direct-success plus reproduced-candidate predicates hold, and still records each child's real exit/timeout separately.

```sh
python3 /tmp/haskoki-notifications/record.py proxy/reproduction zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -v /opt/pkcs11-proxy-ng:/opt/pkcs11-proxy-ng:ro -w /work haskoki-dev:ghc-9.10.3 bash -ec '
cabal build all
cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor /tmp/haskoki-notifications/proxy-probe.c -ldl -lpthread -o /tmp/haskoki-notifications/proxy-probe
cc -std=c11 -O2 -g -Wall -Wextra -Werror -shared -fPIC -Ispec/vendor /tmp/haskoki-notifications/proxy-observer.c -ldl -lpthread -o /tmp/haskoki-notifications/proxy-observer.so
python3 /tmp/haskoki-notifications/proxy-repro.py reviewed /work/dist-newstyle/build/x86_64-linux/ghc-9.10.3/haskoki-0.3.0.0/f/haskoki/build/haskoki/libhaskoki.so
'
```

- [ ] Only after reproduction, prepare `/tmp/haskoki-notifications/proxy-issue.md` with source/pair/module/observer hashes, direct wake, exact proxied outcome/window/flags/sentinel, mutex/context paths and limitations. File a **new distinct** notifications issue. Never reuse numbers **23/24/35/36** for a new notifications filing in either repository. Existing issues keep their historical message/Async meanings. Preserve exact title/body argv and real returned URL/readback:

```sh
python3 /tmp/haskoki-notifications/record.py proxy/issue-create zero gh issue create --repo mingulov/pkcs11-proxy-ng --title 'Blocking C_WaitForSlotEvent cannot be interrupted by client C_Finalize' --body-file /tmp/haskoki-notifications/proxy-issue.md
python3 /tmp/haskoki-notifications/check-proxy.py readback
```

`readback` parses the single returned issue URL from `proxy/issue-create.log`, rejects `23/24/35/36` and wrong repository/title, writes `proxy/issue-url.txt`, then invokes `gh issue view ACTUAL_URL --json url,title,state,body` using a subprocess argv list and the recorder name `proxy/issue-readback`; save raw `proxy/issue.json`. Never interpolate a guessed URL or post the body as a shell string. No duplicate creation on retry: inspect/read back the first actual receipt. Add that URL to docs and the existing `DIRECT_ONLY` list for `notifications_routed`. Preserve message/async entries. Polling consumer stays parity-eligible, excluding malformed pre/post-init shapes whose shim precedence differs; no filtering of new eligible transcript lines. Do not inject events into a different client-side Haskoki instance.

```sh
python3 /tmp/haskoki-notifications/record.py proxy/parity zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /opt/pkcs11-proxy-ng:/opt/pkcs11-proxy-ng:ro -w /work haskoki-dev:ghc-9.10.3 env HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng scripts/test-proxy-parity.sh
python3 /tmp/haskoki-notifications/record.py proxy/after zero python3 /tmp/haskoki-notifications/check-proxy.py reviewed
python3 /tmp/haskoki-notifications/record.py reviewed/release zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/make-release.sh
python3 /tmp/haskoki-notifications/record.py reviewed/pins zero python3 /tmp/haskoki-notifications/pins.py reviewed
```

- [ ] Require exactly one `dist-release/haskoki-*` bundle with `lib/libhaskoki.so`; preserve/identify older bundles rather than choosing by mtime or deleting unrelated artifacts. Bundle digest is sorted bundle-relative UTF-8 file path, NUL, file bytes, NUL. Record actual HEAD plus dirty patch/new file hashes for reviewed work; this is provisional evidence, never relabeled final clean-revision acceptance. Recompute runtime source/module/bundle identity before/after every external lane. Documentation/disposition changes may be recorded separately; any runtime or input pin change returns to its owner and rebuilds/restarts the affected sequence.
- [ ] Write the independent `oracle-notifications.c` comparison using only pinned header and discovered tables: fresh polling is exactly NO_EVENT, the four callback/application shapes open/info/close with exactly zero callbacks, and the initial slot has TOKEN_PRESENT. It is a narrow comparison with the oracle's actual inputs, separate from the rich direct consumer. Compile/run the actual bundle in the same toolchain:

```sh
python3 /tmp/haskoki-notifications/record.py reviewed/oracle-comparison zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 bash -ec '
cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor /tmp/haskoki-notifications/oracle-notifications.c -ldl -lpthread -o /tmp/haskoki-notifications/oracle-notifications
python3 -c '\''import pathlib,subprocess; p=list(pathlib.Path("dist-release").glob("haskoki-*/lib/libhaskoki.so")); assert len(p)==1; subprocess.run(["/tmp/haskoki-notifications/oracle-notifications",str(p[0].resolve())],check=True)'\''
'
```

- [ ] `lane.py` first copies existing `/tmp/pkcs11-ws/out-rc2/<lane>` to exclusive `STAGE/previous-<lane>` with verified content hashes/timestamps, refusing an existing archive. Only then clear/recreate that wrapper-owned lane directory. On repeat, archive the entire prior attempt first. Run the recorder with name `STAGE/LANE`, expectation `zero`, and exact argv `bash /tmp/pkcs11-ws/run-lane-rc2.sh LANE`; preserve nested wrapper subprocess argv and exits. Immediately copy `pkcs11-<lane>-results.json` and nonempty `trace.jsonl` into the stage. Wrapper `0` may contain test exit `1`; it is not a clean-lane result.
- [ ] Write `reviewed/dispositions.json`: each actual finding has `lane,nodeid,parameters,input_shape,actual,expected,classification,source,reproduction_log,reproduction_sha256,issue_url,status`. Classification is provider/oracle/capability. Preserve unrelated historical findings and issue evidence rather than reopening or hiding them. Inspector records actual reported collected/executed/passed/failed/skipped/xfailed/error counts, `wasxfail`, long representations and relevant traces; absent pass detail stays unknown. It refuses setup errors/crashes/timeouts/incomplete traces, unexplained new findings or unresolved provider defects. Human findings review must precede kat.

```sh
python3 /tmp/haskoki-notifications/record.py reviewed/fast-collection zero python3 /tmp/haskoki-notifications/lane.py reviewed fast
python3 /tmp/haskoki-notifications/record.py reviewed/fast-review zero python3 /tmp/haskoki-notifications/inspect-lane.py reviewed fast
python3 /tmp/haskoki-notifications/record.py reviewed/kat-collection zero python3 /tmp/haskoki-notifications/lane.py reviewed kat
python3 /tmp/haskoki-notifications/record.py reviewed/kat-review zero python3 /tmp/haskoki-notifications/inspect-lane.py reviewed kat
```

Run kat commands only after fast review succeeds. Relevant records include `test_remaining_gaps.py::TestWaitForSlotEvent::test_wait_for_slot_event_non_blocking`, `ckr/test_ckr_slot_token.py::TestWaitForSlotEventErrors::test_non_blocking_no_event`, `test_session_edge_cases.py::TestCKNotifyCallback::{test_open_session_with_null_callback,test_open_session_callback_matrix}`, `test_token_flags.py::TestSlotInfo`, and `test_interface.py` slot enumeration. Require supported Haskoki wait, not FUNCTION_NOT_SUPPORTED skip; callback matrix has no Digest and therefore zero callbacks. These nodes prove no blocking/coalescing/removal/cancellation/reentry. Declarative table rows and marker membership are not execution counts.

- [ ] Record the source-prose/coverage errors from spec §5.6 distinctly: the claimed Wait FUNCTION_NOT_SUPPORTED return-list entry and nonexistent concrete raw-null wait test. A notifications oracle filing, if made, uses a new issue titled `WaitForSlotEvent source claims overstate return-list and raw-null coverage`, body `/tmp/haskoki-notifications/oracle-issue.md`, with exact pinned lines and narrow comparison. It is distinct from the required proxy filing and from prior Async issues. It must not be described as a reproduced provider failure. Use the following command only after the source-backed body is complete and the coordinator assigns the filing; keep actual URL/readback with the same protocol and forbidden-number check:

```sh
python3 /tmp/haskoki-notifications/record.py reviewed/oracle-issue-create zero gh issue create --repo mingulov/pkcs11-check --title 'WaitForSlotEvent source claims overstate return-list and raw-null coverage' --body-file /tmp/haskoki-notifications/oracle-issue.md
```

- [ ] Update both oracle documents with measured reviewed revision/patch, pins, exact nodes/inputs, raw result/trace/reproduction hashes, real issue URLs/status and source-definition versus runtime totals. Zero unresolved new provider findings is mandatory; an oracle-prose correction is not required to manufacture a lane failure. Finish receipts and review.

```sh
python3 /tmp/haskoki-notifications/evidence.py review task-n09
git diff --check
```

**Acceptance:** Missing-evidence reds nonzero; required reproduction/parity/release/pin/collection/inspection greens exit `0` with child outcomes retained. Exact fixed pins and `519` source files match; five inherited oracle rows and six notifications rows/counts match. Actual distinct proxy URL is read back and used by `DIRECT-ONLY: notifications_routed`; polling parity still passes. Both fast and kat have independent, ordered findings reviews and zero unexplained new provider findings; wrapper success alone never suffices. Missing reproduction/filing blocks N11. Stop for coordinator review before commit; the worker makes no commit.

### T-N10: Contracts, documentation, final gates and manifest handoff

**Spec trace:** §§1, 3.9, 5.1–5.6, 6; N01–N12; all G01–G17 dispositions linked.

**Files:** Modify `scripts/generate-function-contracts.py`; regenerate `spec/function-contracts.json`; modify `docs/operations-notes.md`, `docs/config-honesty.md`, `docs/demo-walkthrough.md`, `docs/async-config-design.md` (baseline clarification only; D1–D12 unchanged), `docs/pkcs11-oracle-triage.md`, `docs/pkcs11-check-upstream-issues.md`. Create scratch `/tmp/haskoki-notifications/check-contracts.py`, `/tmp/haskoki-notifications/check-gates.py`, `/tmp/haskoki-notifications/final-manifest.py`. Reuse earlier scratch helpers without changing their acceptance policy; corrections return to their owning task. Evidence under `dist-release-evidence/notifications/task-n10/` and `dist-release-evidence/notifications/final/`, including `final/validation-sources/` and `final/HANDOFF.md`. No tracked edits after the documentation checkpoint's coordinator commit.

**Interfaces:** `check-contracts.py contracts|all` validates allowed evidence-only contract changes and, in `all`, accurate docs/real URLs/reviewed evidence. `check-gates.py final` verifies exact gate/manifest revision, counts and hashes. `final-manifest.py` writes `final/MANIFEST.json` only when all required evidence for current clean HEAD is valid. It is deterministic for the same inputs (sorted keys/paths, no freshly generated timestamps in the content); run twice and compare bytes. The manifest links raw timestamped receipts rather than inventing new timing evidence.

- [ ] Write the contract checker and final manifest checker first. Expected reds name missing **public notifications evidence** on the seven owning contract rows and missing **final revision gates/lanes**, respectively. Do not claim that pre-existing private EventsSpec evidence establishes these requirements.

```sh
python3 /tmp/haskoki-notifications/record.py task-n10/before nonzero python3 /tmp/haskoki-notifications/check-contracts.py all
python3 /tmp/haskoki-notifications/record.py final/before nonzero python3 /tmp/haskoki-notifications/final-manifest.py
```

- [ ] Append, deduplicate and regenerate evidence for exactly `C_WaitForSlotEvent`, `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_OpenSession`, `C_Digest`, `C_Finalize`. Each gets `("test-consumers.sh", "tests/c/notifications_routed.c")`; Wait additionally gets `("test-consumers.sh", "tests/c/consumer_notifications_poll.c")`. Add `("haskoki-model-tests", "tests/model/NotificationsSpec.hs")` to Wait/list/info/token-info/Finalize and `("haskoki-engine-tests", "tests/engine/NotificationsEngineSpec.hs")` to OpenSession/Digest/Finalize. Retain all earlier references; preserve every row's entry/classification/ordinal/layout/first-layout/csv_acceptance. Retained proofs are labeled private, not removed. Require all referenced files wired and actually executed before claiming evidence.
- [ ] Update operations/configuration/demo notes: public pending-slot flags versus private FIFO; fixed/removable identity; initially clear/restart behavior; bounds and distinct generations; coherent removal and stale handles; exact wait errors/output ownership/finalize races; retained cell cost; sole synchronous Digest surrender and silence elsewhere; OK/CANCEL/other behavior; safe callback constraints and no joining a thread that needs this provider; four discovery/GetInfo exceptions and prohibited native reentry; no store/reset/watcher/new durability claims. Keep optional surrender separate from slot changes and no proxy callback promise. Append reviewed lane/proxy dispositions with actual evidence, not final claims yet.

```sh
python3 /tmp/haskoki-notifications/record.py task-n10/generate zero python3 /tmp/haskoki-notifications/evidence.py generators contracts
python3 /tmp/haskoki-notifications/record.py task-n10/after zero python3 /tmp/haskoki-notifications/check-contracts.py all
python3 /tmp/haskoki-notifications/record.py task-n10/docs zero python3 scripts/check-docs.py
python3 /tmp/haskoki-notifications/record.py task-n10/denominators zero python3 scripts/check-denominators.py
python3 /tmp/haskoki-notifications/record.py task-n10/history zero python3 scripts/check-history-codes.py
python3 /tmp/haskoki-notifications/evidence.py review task-n10
git diff --check
```

- [ ] **Coordinator checkpoint:** deliver this exact documentation/generator diff and receipts for review before commit. The worker does not commit. After the coordinator commits it, record full HEAD, require clean tracked state and frozen-source hashes. This checkpoint is necessary for final evidence to include documentation changes, as in Async Tasks 11–12. Preserve all earlier task/reviewed evidence and untracked user files. If final directory has a prior collection, archive it through `evidence.py` before reuse; retain the initial missing-evidence red.
- [ ] Run retained attached/detached/restart proofs unchanged at final HEAD, then the existing host gate entry point. Gate checker requires `GATES: all passing (18 gates + cabal test + release evidence)`, `pass: 16 miss: 0`, the final revision, zero missing logs and matching hashes. The `14` driver names are `test-loader.sh`, `test-c-abi.sh`, `test-c-output.sh`, `test-c-mutexes.sh`, `test-consumers.sh`, `test-client.sh`, `test-crypto-routed.sh`, `test-sim-threaded.sh`, `test-finalize-race.sh`, `test-async-attached.sh`, `test-async-detached.sh`, `test-control-events.sh`, `test-lifecycle.sh`, `test-proxy-parity.sh`; build/install are the other two steps. No shortened substitute gate run.

```sh
python3 /tmp/haskoki-notifications/record.py final/attached zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-async-attached.sh
python3 /tmp/haskoki-notifications/record.py final/detached zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-async-detached.sh
python3 /tmp/haskoki-notifications/record.py final/gates zero env HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng HASKOKI_EVIDENCE_DIR=/home/user/src/m/haskoki-ws/haskoki/dist-release-evidence/notifications/final/gates bash scripts/run-gates.sh
python3 /tmp/haskoki-notifications/record.py final/gate-check zero python3 /tmp/haskoki-notifications/check-gates.py final
python3 /tmp/haskoki-notifications/record.py final/pins zero python3 /tmp/haskoki-notifications/pins.py final
python3 /tmp/haskoki-notifications/record.py final/installed-native zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 python3 /tmp/haskoki-notifications/run-native.py final
python3 /tmp/haskoki-notifications/record.py final/native-check zero python3 /tmp/haskoki-notifications/check-native.py final
```

- [ ] Repeat the bounded proxy comparison on the actual final bundle using existing compiled probes/sources and the same pin checks, without filing again. Repeat the narrow oracle comparison against that bundle. The helper records actual resolved bundle argv; require exactly one bundle and unchanged module/hash throughout. `check-proxy.py final` links the original filing/readback to final reproduction and final parity driver log rather than pretending the issue was filed on final HEAD.

```sh
python3 /tmp/haskoki-notifications/record.py final/proxy-reproduction zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -v /opt/pkcs11-proxy-ng:/opt/pkcs11-proxy-ng:ro -w /work haskoki-dev:ghc-9.10.3 python3 -c 'import pathlib,subprocess; p=list(pathlib.Path("dist-release").glob("haskoki-*/lib/libhaskoki.so")); assert len(p)==1; subprocess.run(["python3","/tmp/haskoki-notifications/proxy-repro.py","final",str(p[0].resolve())],check=True)'
python3 /tmp/haskoki-notifications/record.py final/proxy-check zero python3 /tmp/haskoki-notifications/check-proxy.py final
python3 /tmp/haskoki-notifications/record.py final/oracle-comparison zero timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -v /tmp/haskoki-notifications:/tmp/haskoki-notifications -w /work haskoki-dev:ghc-9.10.3 python3 -c 'import pathlib,subprocess; p=list(pathlib.Path("dist-release").glob("haskoki-*/lib/libhaskoki.so")); assert len(p)==1; subprocess.run(["/tmp/haskoki-notifications/oracle-notifications",str(p[0].resolve())],check=True)'
python3 /tmp/haskoki-notifications/record.py final/fast-collection zero python3 /tmp/haskoki-notifications/lane.py final fast
python3 /tmp/haskoki-notifications/record.py final/fast-review zero python3 /tmp/haskoki-notifications/inspect-lane.py final fast
python3 /tmp/haskoki-notifications/record.py final/kat-collection zero python3 /tmp/haskoki-notifications/lane.py final kat
python3 /tmp/haskoki-notifications/record.py final/kat-review zero python3 /tmp/haskoki-notifications/inspect-lane.py final kat
```

Kat remains conditional on completed accepted fast findings review. Compare with reviewed dispositions, preserving old oracle issues and actual findings without inventing new pass counts. Any changed runtime source/module/bundle/input pin, unexplained new failure or necessary tracked correction invalidates the affected final sequence and returns to its owning task's assertions. Do not update tracked docs during final collection; write final measured state to evidence handoff.

- [ ] Copy every scratch validation/reproduction source and the unchanged recorder into `final/validation-sources/`, including exact run scripts, C probes, baseline builder, pin/lane/checker/manifest helpers and configs without secrets. Hash original/copy pairs. Write `final/HANDOFF.md` with revision, commands, pins, achieved/unresolved N rows, limits, attempts, ownership and safe resumption. The final manifest has this required schema:

| Key | Required contents |
|---|---|
| `source_revision`, `spec_revision` | Current clean final HEAD and `6fa6696273d8111ad64a6474d68552369fa37c22`; reviewed/baseline identities kept separately. |
| `pins` | Actual release/module path/hash, deterministic bundle hash, measured image tag/ID, header/ABI/runtime/store invariants, proxy commit/pair/all quoted source hashes, oracle root/version/519-file digest and both exact tables. |
| `commands` | Exact argv, actual exits, log/artifact hashes, source/new-file/patch/input-module identities for gates, native/proxy comparisons, fast/kat, inspections, retained proofs and generators. Source-only commands explicitly load no module. |
| `release_evidence` | `final/gates/MANIFEST.txt` hash, `16` successful step records/hashes, `18` gate result, all suites and installed check, newly executed native notifications results. |
| `lanes` | Original fast/kat JSON and nonempty traces, actual summaries, ordered inspection records, complete provider/oracle/capability dispositions and readbacks. |
| `proxy` | Source candidate rationale plus actual bounded reproduction, direct/observed/unwrapped distinctions, real new issue/readback, explicit direct-only rich consumer and retained polling parity. |
| `acceptance` | Exactly `12` records N01–N12, each linking assertion/consumer/gate evidence by path and recomputed hash; `17` G01–G17 disposition links distinguish repairs from retained behavior. No unresolved blocker is accepted. |
| `reviewed_evidence`, `attempts` | Historical task/baseline/reviewed references and every archived failed required-zero attempt, never relabeled as final results. |
| `validation_sources`, `handoff` | Copied reproducible sources/configs/recorder plus handoff hashes, no dependency on surviving `/tmp` files. |

The manifest cannot hash its own receipt recursively: use a fixed input allowlist excluding `final/before-command.json`, `final/after-command.json`, `final/determinism-command.json` and their logs from its `commands` payload. Validate all other required completed receipts, generate deterministic bytes, then capture its own command receipts externally. The second invocation uses that same input allowlist and verifies byte equality, writing nothing if unchanged.

```sh
python3 /tmp/haskoki-notifications/record.py final/invariants zero python3 /tmp/haskoki-notifications/evidence.py invariants
python3 /tmp/haskoki-notifications/record.py final/after zero python3 /tmp/haskoki-notifications/final-manifest.py
python3 /tmp/haskoki-notifications/record.py final/determinism zero python3 /tmp/haskoki-notifications/final-manifest.py
git diff --exit-code HEAD
git status --short
```

**Acceptance:** Initial missing-contract/final-evidence reds are nonzero for the specified omissions; all required green commands exit `0`. Seven owning contracts gain evidence only, `104/70/32/2` classification counts and all runtime/pin invariants remain fixed, both generators and manifest are deterministic. Final evidence identifies one clean revision and bundle, `18` static gates, all suites, `14` drivers plus build/install (`16/16`, miss `0`), `72` native legs plus four polling-table results, distinct actual filing, ordered fast/kat reviews, exactly `12` accepted N records and `17` gap dispositions. No final tracked edits or unexplained failures remain. Deliver final evidence for coordinator review; the worker makes no commit. Stop at the Notifications/slot-events slice, with no next-slice work or broader conformance claim.

## Plan handoff

T-N01 is ready for a separately assigned implementation worker after coordinator review of this plan. Its first scope is the leaf service, five model cases and shared evidence helper; no public integration or implementation acceptance is implied by this planning handoff. Subsequent workers read their task, predecessor interfaces, global constraints and the full authoritative spec. No acceptance claimed. Stopped at notifications plan.
