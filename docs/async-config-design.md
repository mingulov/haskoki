# Async/config design: baseline plus delta

Design brief for the async-execution and configuration surface,
grounded in the implemented baseline (this repo) plus the external
research report (`/tmp/haskoki-config/REPORT.md`, ecosystem
precedents: SoftHSM2, Kryoptic, NSS softokn, p11-kit, pkcs11-check,
openCryptoki) and the implementation plan (`ws/docs/incoming/
haskell-pkcs11-design/docs/10-implementation-plan.md`, attached
async plus detach/restart/rejoin sections).

This is a design document: it specifies shapes, enforcement sites,
honesty dispositions, and acceptance tests. No behavior changes in
this commit; each delta item below is a future work item with its
acceptance test named.

## 1. Baseline: already implemented and pinned

### Async execution (attached plus detach/restart/rejoin)

- `src/Haskoki/Runtime/Async.hs`: logical scheduler, attached
  jobs, poll/complete delivery, cancellation epochs.
- `src/Haskoki/Runtime/Detached.hs`: persistent ids, durable
  record before success, attachment revocation, typed
  unsaveable outcomes (`CKR_STATE_UNSAVEABLE`, never a crash),
  explicit repeat/competing-join policy, too-small join
  (`CKR_BUFFER_TOO_SMALL`).
- C proofs across the real export boundary, all passing in the
  release-evidence manifest:
  - `tests/c/async_attached.c` (pending canaries, exactly-once
    completion),
  - `tests/c/async_detached.c` (guard-page revocation: the old
    buffer is `mprotect`d `PROT_NONE`, then finalize,
    reinit, rejoin into a new buffer, SHA-256 completion
    delivered exactly once),
  - `tests/c/async_restart.c` (two-process SQLite recovery on
    one persistent id; no old handle or pointer restored).
- Async residue from the plan checklist: none observed. Every
  plan bullet (attached jobs, completion codecs, capacity
  validation, cancel-before/after-completion, durable record,
  revocation, join errors, token reset, unsaveable natives)
  has an implemented site or a C proof.

Scope clarification (2026-09-30): the three proofs above retain their
private context/job-token API, completion version `1`, pending Join,
and query/short-buffer dialogue. `tests/c/async_routed.c` separately
exercises the actual 3.2 Complete/GetID/Join table entries through
standard session/function bindings: public version `0`, successful Join
`CKR_OK`, and submission/Join-bound output ownership. Public admission
is a fresh full-buffer one-shot Digest on an explicit async session;
ordinary sessions and staged recalls remain synchronous. Standard memory
and non-home views have no detached store; public detach/restart proof
uses the SQLite home token. Its successful-store evidence does not
remove the existing failed-durable-mark limitation. Measured evidence
for `415278fd23053d0150f7b13a18b373139236c891` is linked in the
[async qualification record](pkcs11-oracle-triage.md#async-routing-verification-2026-09-30).
This routing slice leaves the scheduler, detached policy, and every
D1-D12 item below unchanged; final-revision verification remains pending.

### Configuration (43 keys, honesty-dispositioned)

`src/Haskoki/Runtime/Config.hs` plus
`docs/config-honesty.md` (disposition table: ENFORCED /
REFUSED / CONFIG-NOT-POLICY, every key with a contract
test). Nine sections: `storage`, `engine`, `async`, `trace`,
`control`, `fixtures`, `limits`, `sim`, `tokens`. Unknown
sections and keys are rejected at init. CLI verbs in
`src/Haskoki/Ctl.hs`: `config check`, `capabilities`,
`scenario run`, `store inspect`, `store reset`.

## 2. Delta: must-have items (each with acceptance)

D1. Full slot table. Extend `tokens.*` (labels plus PINs today)
with per-slot `id`, `manufacturer` / `description`,
`present_at_start` (empty-slot plus insert/remove tests), and
`flags` (`removable` drives `CKF_REMOVABLE_DEVICE`).
Precedent: Kryoptic `[[slots]]`, SoftHSM `slots.removable`.
Disposition: ENFORCED. Acceptance: `MultiTokenSpec`
presence/flag legs plus `CtlSpec` capabilities seating.

D2. Per-slot storage binding. `storage = { kind, path }` inside
each slot entry (or global default plus per-slot override);
slots never share one SQLite file. Required for the
two-process recovery test with a known path. Precedent:
Kryoptic `dbtype`/`dbargs`. Disposition: ENFORCED.
Acceptance: `FfiAsyncSpec` per-slot open plus shared-path
refusal.

D3. Mechanism allow/deny lists. Global default plus per-slot
override, one syntax only: Kryoptic form (`["DENY", ...]`
deny list, `DENY` first; otherwise an allow list). Drives
`C_GetMechanismList` and init-time rejection. Precedent:
Kryoptic `mechanisms`, SoftHSM `slots.mechanisms`.
Disposition: ENFORCED. Acceptance: `RegistrySpec` list
filtering plus `OperationSpec` init refusal legs.

D4. Engine capability probe. `engine.capability_probe`
(fail init in CI when required routes are missing).
Disposition: ENFORCED. Acceptance: `ConfigHonestySpec`
probe refusal with a deliberately narrowed build.

D5. Wired deterministic seed. `seed` is a reserved
placeholder today (only 1234 accepted, nothing reads it):
wire one seed into versioned RNG sub-streams
(`seed.rng`, `seed.handles`), documented stream split.
Consumer: differential runs need reproducibility.
Disposition: ENFORCED. Acceptance: `caseSeedRandomReplay`
extension (same seed plus same call sequence replays
byte-identical bytes across engines where defined).

D6. Trace drop policy. `trace.on_drop = "count" | "fail"`;
`fail` treats a dropped trace as a harness failure.
Disposition: ENFORCED. Acceptance: `ConfigHonestySpec`
drop-policy legs with a saturated queue.

D7. Async completion budget. `async.max_poll_completions`
bounds completions per poll sweep (acceptance ids
A25-A27). No worker-count knob while the executor stays
logical (poll-driven, deterministic): thread-pool knobs
would be dead config. Disposition: ENFORCED. Acceptance:
`SimBridgeSpec` budget legs.

D8. Unsafe-debug reveal gate. `control.unsafe_debug_reveal`
(default false) gates key/PIN reveal through control.
Disposition: ENFORCED (REFUSED when false). Acceptance:
`ControlSpec` reveal-gate legs.

D9. Token export/import. CLI-first: `store export --path DB
--out bundle.json [--reveal-secrets]` /
`store import --in bundle --path DB`; config side:
`storage.export_format_version`. Needed for fixture
authoring and reload-equivalence tests. Precedent: p11-kit
`export-object` / `import-object`. Disposition: ENFORCED.
Acceptance: `StoreSpec` export/import roundtrip plus
format-version refusal.

D10. Effective-config dump. `config show --effective` prints
merged TOML after defaults and env. Precedent: p11-kit
`print-config`. Disposition: ENFORCED. Acceptance:
`CtlSpec` effective-dump leg.

D11. Slot-order stability. Document (guarantee, not a knob)
that enumeration order is deterministic and
insertion/removal never reshuffles surviving slots:
pkcs11-check addresses `--slot` by 0-based index.
Disposition: documented invariant. Acceptance:
`MultiTokenSpec` order-stability leg.

D12. Per-token lockout flags. `pin_locked` /
`login_required` per slot/fixture beside the existing
per-slot PINs. Disposition: ENFORCED. Acceptance:
`MultiTokenSpec` lockout legs.

## 3. Delta: deferrable (high leverage, past first consumer evidence)

- Trace severity levels (`trace.level`): operator ergonomics
  over the JSONL machine trace. Precedent: SoftHSM
  `log.level`.
- Keygen/key policy knobs (`policy.min_rsa_bits`,
  `policy.keys_always_sensitive`, `policy.min_pin_len`,
  `pin_max_attempts`): deterministic lockout thresholds stay
  documented where fixed.
- FIPS-restricted profile switch: mechanism filter plus key
  policy, labeled as a filtering demonstration, never a
  validated module.
- Fault-injection scenario checkpoints (`commit.fail_before` /
  ambiguous / after, `store.full_disk`, `store.corrupt_record`,
  `job.unsaveable_native`) behind a default-off
  `faults = { enabled, allow }` gate: declarative form of the
  injected-failure tests.
- Detached-job tuning (`async.detached = { ttl, max_jobs,
  gc }`): expiry is a visible policy.
- Legacy-table default (`interfaces.default_table`) for the
  version pkcs11-check `--interface` forcing meets.
- Read-only store mode (`storage.read_only`): token-object
  writes refused with the write-protected code. Precedent:
  NSS `readOnly`.
- Fork policy (`lifecycle.on_fork`): documents the child-PID
  stance. Precedent: SoftHSM `reset_on_fork`.
- Slot-event wait tuning (`events.wait_granularity_ms`).
- Named fixture keys (wrap KEK, sign/encrypt keys by label)
  so wrap-key-label harness paths work without
  `C_CreateObject`.

## 4. Explicit non-items

- Worker-thread pool sizes while the executor stays logical
  (see D7).
- Vendor-persona profiles before observed behavior exists.
- Remote/live external control transport (no transport
  exists; the CLI never pretends to steer another live
  process).
- Multi-process coherent caching, at-rest encryption,
  hot config reload (resolved once at init), per-mechanism
  parameter-policy tables, compat-quirks knobs: each stays
  out until a consumer demonstrates the need.

## 5. Sequencing

D3 (mechanism lists) first: it gates what the oracle and
differential runs may call. D1 plus D2 (slot table plus
per-slot storage) second: multi-token evidence needs them.
D9 (export/import) third: fixture authoring unblocks the
rest. D5 (seed) with D9: reproducible fixtures. The
remainder in any order; each item lands with its named
acceptance test and a config-honesty table row before the
next starts.
