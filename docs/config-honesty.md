# Config honesty catalog

Every knob the provider parses is exactly one of:

- **ENFORCED** — a wrong value errors, or a right value observably
  selects behavior. Each has a maintained behavior contract test.
- **REFUSED** — values that promise behavior the code does not
  implement fail at parse with an exact `CfgInvalid` error (hence
  fail startup: every native open maps resolve failure to NULL).
  Each refusal is pinned by a test.
- **CONFIG-NOT-POLICY** (reserved) — parses, validates, reports,
  but drives no enforcement; disclosed loudly in the capabilities
  report and here. Each has a doc-claim test proving the doc.

Unknown keys and sections are rejected (`CfgUnknownKey` naming the
dotted key or section); there is no silent ignore anywhere.

## Disposition table (43 keys, zero gaps)

`E` = ENFORCED, `R` = REFUSED (non-default/misleading values),
`D` = CONFIG-NOT-POLICY (reserved, disclosed).
Counts: E=27 pure + 1 dual (`storage.path`, E/R) + R=9 pure + D=6.

| Key | Disp | Site / rule | Contract test |
|---|---|---|---|
| `schema_version` | E | must be 1 (`Config.hs` build) | `ConfigHonestySpec` schema refusal |
| `profile` | E | 3 names validated + reported | `ConfigHonestySpec` + `CtlSpec` capabilities |
| `interfaces` | E | subset validated + reported (declarative; no native path gates on it — scope note below) | `ConfigHonestySpec` bad/empty/reported |
| `seed` | R | reserved placeholder: only 1234 (nothing reads it) | `ConfigHonestySpec` seed refusal |
| `storage.kind` | E | routes the store (`openStdStore`) | `FfiAsyncSpec` success/bad-sqlite |
| `storage.path` | E/R | sqlite opens it; memory+path refused (ignored otherwise) | `FfiAsyncSpec` + `ConfigHonestySpec` memory-path refusal |
| `storage.busy_timeout_ms` | R | pinned 5000 at open; only 5000 accepted | `ConfigHonestySpec` busy refusal |
| `storage.exclusive_provider_ownership` | R | always single-writer O_EXCL; `false` refused | `ConfigHonestySpec` exclusive refusal |
| `engine.kind` | E | validated + selects the reported active catalog (116 vs 114 rows); native paths always bind OpenSSL4 (disclosed by the `native-engine` line) | `CtlSpec` capabilities + native-scope |
| `engine.allow_synthetic_fallback` | R | no fallback exists; `true` refused | `ConfigHonestySpec` fallback refusal |
| `engine.private_library_context` | R | native OpenSSL4 always opens a private libctx; `false` refused, default `true` | `ConfigHonestySpec` privctx refusal + default |
| `async.executor` | E | must be `"logical"` | `ConfigHonestySpec` executor refusal |
| `async.enabled` | E | scenario runner pending gate (native paths do not consult it — scope note below) | `ConfigHonestySpec` enabled on/off scenarios |
| `async.pending_polls` | E | scenario runner pending count (same scope note) | `ConfigHonestySpec` polls scenario |
| `async.persist_detached` | D | reserved: detached records always commit; durability follows `storage.kind` | `ConfigHonestySpec` parses + `reserved-async` line |
| `trace.enabled` | E | `fileSink` no-op arm | `ConfigHonestySpec` disabled-writes-nothing |
| `trace.path` | E | `fileSink` append target (`{pid}` expands) | `ConfigHonestySpec` path writes file |
| `trace.redact_secrets` | R | always redacted; `false` refused | `ConfigHonestySpec` redact refusal |
| `trace.queue_limit` | E | tracer queue bound (`max 8`) | `ConfigHonestySpec` queue bound |
| `control.enabled` | R | control plane always on; `false` refused | `ConfigHonestySpec` enabled refusal |
| `control.max_request_bytes` | E | oversize refuses `request_too_large` | `ConfigHonestySpec` max-request |
| `control.response_budget_bytes` | E | fixed 65536 by §5.1 | `ConfigHonestySpec` budget refusal |
| `control.test_enabled` | E | gates mutations; serving slots fixed when false, permanently removable within the interval when true | `ControlSpec` + `SimBridgeSpec` private gates; `NotificationsEngineSpec` serving configuration |
| `fixtures.set` | R | reserved placeholder: only `"minimal-demo"` | `ConfigHonestySpec` set refusal |
| `fixtures.apply` | R | reserved placeholder: only `"new-store-only"` | `ConfigHonestySpec` apply refusal |
| `limits.slots` | E | `rulesFromConfig` → token admission | `AdmissionSpec` tracking |
| `limits.sessions` | E | `rulesFromConfig` → session admission | `ConfigHonestySpec` sessions tracking |
| `limits.objects` | E | `rulesFromConfig` → object admission | `AdmissionSpec` tracking |
| `limits.buffer_bytes` | D | RESERVED: effective bound pinned 65536 (see `template-bounds`) | `ConfigSpec` template disclosure |
| `limits.transcript_bytes` | D | reserved: no transcript bound implemented | `ConfigHonestySpec` reserved parse + `reserved-limits` line |
| `limits.aggregate_payload_bytes` | D | reserved: no aggregate bound implemented | `ConfigHonestySpec` reserved parse + `reserved-limits` line |
| `limits.attribute_entries` | D | RESERVED: effective bound pinned 64 (see `template-bounds`) | `ConfigSpec` template disclosure |
| `limits.attribute_depth` | D | reserved: no attribute-depth bound implemented | `ConfigHonestySpec` reserved parse + `reserved-limits` line |
| `limits.jobs` | E | async-table bound (`max 8`) | `ConfigHonestySpec` jobs bound |
| `limits.events` | E | public open requires positive bound at least catalog size; private FIFO retains `max 8` | `NotificationsSpec` + `NotificationsEngineSpec` serving limits; `ConfigHonestySpec` private events bound |
| `sim.enabled` | E | gates schedule/script/fault-window | `SimBridgeSpec` boost gating + fault windows |
| `sim.delay_schedule` | E | per-job tick boost | `SimBridgeSpec` schedule boost |
| `sim.token_script` | E | runs in the private local scenario owner at scenario start | `SimBridgeSpec` script-ran |
| `sim.fault_window_start` | E | seeds the fault window | `SimBridgeSpec` fault windows |
| `sim.fault_window_ticks` | E | fault window length | `SimBridgeSpec` fault windows |
| `tokens.labels` | E | catalog seating + served labels | `MultiTokenSpec` labels + `ConfigSpec` catalog validation |
| `tokens.so_pins` | E | per-slot SO auth | `MultiTokenSpec` SO per-slot |
| `tokens.user_pins` | E | per-slot user auth | `MultiTokenSpec` per-slot PINs |

Sections (9): `storage`, `engine`, `async`, `trace`, `control`,
`fixtures`, `limits`, `sim`, `tokens`. Any other section name is
rejected as unknown.

## Reserved knobs (CONFIG-NOT-POLICY)

- `limits.buffer_bytes`, `limits.attribute_entries`: parse,
  validate (`>= 1`), and report through the
  `limit.*` lines, but template enforcement uses the pinned
  constants (64 entries, 65536 bytes) on both sides of the FFI.
  The `small-limits.toml` fixture (8/1024 configured, 64/65536
  still enforced) pins the ignored-ness as documented behavior.
- `limits.transcript_bytes`, `limits.aggregate_payload_bytes`,
  `limits.attribute_depth`: same shape — parse,
  validate, report; no bound implemented anywhere. Disclosed by
  the `reserved-limits` capabilities line (below), never silently
  ignored again.
- `async.persist_detached`: detached job records always commit to
  the configured store at detach (unconditional `storeCommit`;
  two-process SQLite recovery is driver-pinned), so durability
  follows `storage.kind` (memory: process lifetime; sqlite: file
  lifetime) with no knob effect. Both values parse (fixtures use
  both); the `reserved-async` capabilities line (below) discloses
  the reservation.

Capabilities disclosure lines (pinned verbatim by tests):

- `template-bounds: entries=64 bytes=65536 (pinned;
  limits.attribute_entries/buffer_bytes reserved, no enforcement
  effect)` (unchanged line)
- `reserved-async: persist_detached reserved (detached records
  always commit to the store; durability follows storage.kind, no
  knob effect)`
- `reserved-limits: transcript_bytes/aggregate_payload_bytes/
  attribute_depth reserved (parse+report, no enforcement effect;
  buffer_bytes/attribute_entries: see template-bounds)`

## Refusal pins (exact errors)

| Knob | Refused value | Exact `CfgInvalid` message |
|---|---|---|
| `seed` | anything but 1234 | `seed is reserved (no determinism seeding reads it yet): the only accepted value is 1234` |
| `storage.path` | set with `kind=memory` | `storage.path is only meaningful with storage.kind=sqlite (memory ignores it; refusing rather than silently ignoring)` |
| `storage.busy_timeout_ms` | anything but 5000 | `storage.busy_timeout_ms is not honored (SQLite opens with the pinned 5000ms busy timeout): the only accepted value is 5000` |
| `storage.exclusive_provider_ownership` | `false` | `storage.exclusive_provider_ownership=false is not supported (the store is always single-writer with O_EXCL create): must be true` |
| `engine.allow_synthetic_fallback` | `true` | `engine.allow_synthetic_fallback=true is not supported (no synthetic fallback exists on any path): must be false` |
| `engine.private_library_context` | `false` | `engine.private_library_context=false is not supported (native OpenSSL4 paths always open a private OSSL_LIB_CTX): must be true` |
| `trace.redact_secrets` | `false` | `trace.redact_secrets=false is not supported (secrets are always redacted): must be true` |
| `control.enabled` | `false` | `control.enabled=false is not supported (the control plane is always on): must be true` |
| `fixtures.set` | anything but `"minimal-demo"` | `fixtures.set is reserved (no fixture application reads it yet): the only accepted value is "minimal-demo"` |
| `fixtures.apply` | anything but `"new-store-only"` | `fixtures.apply is reserved (no fixture application reads it yet): the only accepted value is "new-store-only"` |

Each refusal fails `parseConfig`/`loadConfigFile`, hence
`resolveFrom`/`resolveOnce`, hence every native open (crypto,
std, instance answer NULL — pinned by `FfiAcquireSpec`), and
`haskoki-ctl config check` exits non-zero naming the knob.

Pre-existing validation refusals (unchanged, contract-pinned):
bad `schema_version`/`profile`/`interfaces`/`storage.kind`/
`engine.kind`/`async.executor`/`control.response_budget_bytes`,
zero `[limits]`, sqlite-without-path, malformed `[sim]`/`[tokens]`.

Unknown keys/sections: `CfgUnknownKey` naming the dotted key
(e.g. `seclevel`, `async.max-queue`) or the section (e.g.
`admission`); `config check` exits non-zero.

## Review-proposed never-knobs (explicitly non-config)

| Name | Rationale |
|---|---|
| `seclevel` | No config surface; OpenSSL security level is not operator-tuned through this provider. Rejected as unknown. |
| `max-tls` | No config surface; no TLS stack reads provider config. Rejected as unknown. |
| `native-engine` (as knob) | A capabilities REPORT line (`Ctl.hs`), not a knob: native paths always run OpenSSL4. Writing it as config is rejected as unknown. |
| `admission` / `max-queue` / `waiters` | No thread-pool admission knobs exist (`Events.hs` waiters are runtime, not config). Rejected as unknown. |

## Scope notes (validated-but-narrow knobs)

- `interfaces`: the declared interface set is validated (non-empty
  subset of 2.40/3.0/3.1/3.2) and reported, but no native path
  gates behavior on it. Declarative label, not a version gate.
- `async.enabled` / `async.pending_polls`: read by the
  `haskoki-ctl` scenario runner only (pending offering + poll
  count); native async paths do not consult them.
- `engine.kind`: selects the configured engine's reported catalog
  only; all four native opens bind `BackendEnv OpenSSL4`
  regardless (see the `native-engine` report line).
- `profile`: validated label; `demo-maximal` is marked a target
  profile in the report (gaps remain, not a completeness claim).

## Serving presence and private scenario scope

Serving initialization resolves one configuration/catalog and shares its
`SlotEvents` with Instance and Standard. All catalog tokens start present,
at presence epoch zero, with public pending flags clear. Slots keep the same
identity and removable capability for the whole interval. With
`control.test_enabled=false`, software slots are fixed and always present;
mutations refuse. With it true, existing in-process `token.insert` and
`token.remove` are the sole presence producers. Unknown slots refuse;
removal leaves the configured slot and reinsertion restores the same token.
There is no hardware monitoring, dynamic slot addition or network control.

`limits.events` counts distinct potentially pending configured slots in the
public service: it must be positive and at least the catalog size, without
clamping or dropping flags. An invalid bound fails serving open via the
existing configuration/open-failure route. `limits.slots` still constrains
catalog admission. Private `EventQueue` proofs retain their separate FIFO
overflow policy and `max 8` construction; that does not describe public waits.

The control command generation counts accepted mutations, including accepted
idempotent commands. Its `expected_generation` check and increment serialize
with mutation; exhaustion refuses before cleanup. Per-slot status generation
is the presence epoch, incremented only by true changes and checked against
overflow. These differ from the stored token generation and persistent async
IDs. Status paginates the actual catalog. Budget queries and short buffers
execute nothing; presence replies are prepared before mutation where allocation
can fail. Operational failures before/after publication retain the separate
cleanup semantics in [operations notes](operations-notes.md#removal-wait-outputs-and-finalization).

Standard memory retains `siStore = Nothing`; SQLite uses its existing store.
There is no new writer, reset, schema, persisted presence field or watcher.
SQLite restart loads the provisioned token present with pending flags clear;
memory restart has only its existing transient behavior. Removal/reinsertion
does not reset durable token data or increment its stored identity generation.
Ordinary-object durability and Async/Detached persistence/capacity remain
unchanged. Store errors, object changes and job completion do not imply removal.

`haskoki-ctl` and `[sim].token_script` retain private local scenario ownership;
they cannot change another process's loaded provider. Their FIFO, Haskell
callback and scheduler proofs do not establish public pending-slot delivery or
native surrender. No callback knob was added. Public slot changes are separate
from the sole optional synchronous Digest surrender producer described in
[operations notes](operations-notes.md#session-notification-callbacks-and-reentry).
The serving configuration, bounds and store ledger executed in
[T-N02](../dist-release-evidence/notifications/task-n02/review.md),
[T-N03](../dist-release-evidence/notifications/task-n03/review.md) and
[T-N08](../dist-release-evidence/notifications/task-n08/review.md); these
historical records do not qualify a final documentation-inclusive revision.

## Dogfood matrix

`defaultConfig` plus every shipped fixture satisfies the honesty
rules (zero exemptions):

| Config | Honest | Note |
|---|---|---|
| `defaultConfig` | yes | every refusal-prone knob on its honest value (pinned) |
| `maximal-demo.toml` | yes | `persist_detached=true` (reserved, disclosed) |
| `persistent-demo.toml` | yes | sqlite + explicit path, busy 5000, exclusive |
| `real-crypto.toml` | yes | `private_library_context=true`, `persist_detached=false` (reserved, disclosed) |
| `small-limits.toml` | yes | 8/1024 template keys (disclosed-ignored) |
| `sim-demo.toml` | yes | full `[sim]` surface |
| `multi-token.toml` | yes | 3-token catalog |
