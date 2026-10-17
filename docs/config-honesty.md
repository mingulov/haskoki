# Configuration reference

Set `HASKOKI_CONFIG` to the TOML file used by the process loading Haskoki.
Check a file with `haskoki-ctl config check --config PATH`; use
`capabilities --config PATH` to inspect the reported settings and limits.

Each accepted setting is enforced, refused for unsupported values, or
reserved. Reserved values parse and appear in reports but do not change the
behavior described below. Unknown keys and sections return `CfgUnknownKey`.
Invalid values return `CfgInvalid`; configuration errors stop the open.

## Accepted settings (44 keys)

`E` = ENFORCED, `R` = REFUSED (non-default/misleading values),
`D` = CONFIG-NOT-POLICY (reserved, disclosed).

| Setting | Behavior | Rule | Test | Effective |
|---|---|---|---|---|
| `schema_version` | E | must be 1 (`Config.hs` build) | `ConfigHonestySpec` schema refusal | 1 only, load gate (config loader; both) |
| `profile` | E | 3 names validated + reported | `ConfigHonestySpec` + `CtlSpec` capabilities | one of 3 names, validated plus reported (report-only; no behavior selects on it) |
| `interfaces` | E | subset validated + reported (declarative; no native path gates on it — scope note below) | `ConfigHonestySpec` bad/empty/reported | declared set, gates nothing (report-only; C_GetInterface and C_GetInterfaceList serve 3.2, 3.1 and 3.0 regardless; 2.40 is served via C_GetFunctionList) |
| `seed` | R | reserved placeholder: only 1234; does not seed native crypto | `ConfigHonestySpec` seed refusal | 1234 only, read by nothing (config loader; both) |
| `storage.kind` | E | routes the store (`openStdStore`) | `FfiAsyncSpec` success/bad-sqlite | memory or sqlite, routes the store (native open) |
| `storage.path` | E/R | sqlite opens it; memory+path refused (ignored otherwise) | `FfiAsyncSpec` + `ConfigHonestySpec` memory-path refusal | sqlite opens it; memory plus path refuses (native open) |
| `storage.busy_timeout_ms` | R | pinned 5000 at open; only 5000 accepted | `ConfigHonestySpec` busy refusal | 5000 only (native sqlite open; pinned busy timeout) |
| `storage.exclusive_provider_ownership` | R | always single-writer O_EXCL; `false` refused | `ConfigHonestySpec` exclusive refusal | true only (native store create; always single-writer O_EXCL) |
| `engine.kind` | E | validated + selects the reported active catalog; native paths always bind OpenSSL4 (disclosed by the `native-engine` line) | `CtlSpec` capabilities + native-scope | synthetic or openssl, reported catalog only (report-only; native always binds OpenSSL4) |
| `engine.allow_synthetic_fallback` | R | no fallback exists; `true` refused | `ConfigHonestySpec` fallback refusal | false only, read by nothing (config loader; both) |
| `engine.private_library_context` | R | native OpenSSL4 always opens a private libctx; `false` refused, default `true` | `ConfigHonestySpec` privctx refusal + default | true only (native OpenSSL4 open; always private libctx) |
| `async.executor` | E | must be `"logical"` | `ConfigHonestySpec` executor refusal | "logical" only, load gate (config loader; both) |
| `async.enabled` | E | scenario runner pending gate (native paths do not consult it — scope note below) | `ConfigHonestySpec` enabled on/off scenarios | on/off pending gate (scenario; native async never reads it) |
| `async.pending_polls` | E | scenario runner pending count (same scope note) | `ConfigHonestySpec` polls scenario | scenario runner pending count (scenario; native async never reads it) |
| `async.persist_detached` | D | reserved: detached records always commit; durability follows `storage.kind` | `ConfigHonestySpec` parses + `reserved-async` line | reserved; detached records always commit (native store; durability follows storage.kind) |
| `trace.enabled` | E | `fileSink` no-op arm | `ConfigHonestySpec` disabled-writes-nothing | on/off file sink arm (native; runner sink always discards) |
| `trace.path` | E | `fileSink` append target (`{pid}` expands) | `ConfigHonestySpec` path writes file | append target, {pid} expands (native; runner sink always discards) |
| `trace.redact_secrets` | R | always redacted; `false` refused | `ConfigHonestySpec` redact refusal | true only (both; Show instances and renderer always redact) |
| `trace.queue_limit` | E | tracer queue bound (`max 8`) | `ConfigHonestySpec` queue bound | tracer queue bound, max 8 floor, no range check (both; native sink and runner tracer) |
| `control.enabled` | R | control plane always on; `false` refused | `ConfigHonestySpec` enabled refusal | true only (native control plane; always on) |
| `control.max_request_bytes` | E | oversize refuses `request_too_large` | `ConfigHonestySpec` max-request | oversize refuses request_too_large, no range check (native control plane; dispatch gate) |
| `control.response_budget_bytes` | E | fixed 65536-byte response budget | `ConfigHonestySpec` budget refusal | 65536 only, enforced by constant (native control plane; config value pinned) |
| `control.test_enabled` | E | gates mutations; serving slots fixed when false, permanently removable within the interval when true | `ControlSpec` + `SimBridgeSpec` private gates; `NotificationsEngineSpec` serving configuration | gates presence/scenario/scheduler mutations (both; control plane and sim verbs) |
| `fixtures.set` | R | reserved placeholder: only `"minimal-demo"` | `ConfigHonestySpec` set refusal | "minimal-demo" only, read by nothing (config loader; both) |
| `fixtures.apply` | R | reserved placeholder: only `"new-store-only"` | `ConfigHonestySpec` apply refusal | "new-store-only" only, read by nothing (config loader; both) |
| `limits.slots` | E | `rulesFromConfig` → token admission | `AdmissionSpec` tracking | default 16, at least 1, serving catalog admission (native; runner models one slot) |
| `limits.sessions` | E | `rulesFromConfig` → session admission | `ConfigHonestySpec` sessions tracking | default 1024, at least 1, session admission (native; runner never reads it) |
| `limits.objects` | E | `rulesFromConfig` → object admission | `AdmissionSpec` tracking | default 100000, at least 1, object admission (native; runner never reads it) |
| `limits.buffer_bytes` | D | RESERVED: effective attribute-value bound pinned 4194304 (4 MiB; see `template-bounds`) | `ConfigSpec` template disclosure | reserved; effective 4194304 per value (native template decoder; config value ignored) |
| `limits.transcript_bytes` | D | reserved: no transcript bound implemented | `ConfigHonestySpec` reserved parse + `reserved-limits` line | reserved; no bound anywhere (report-only; no admission site reads it) |
| `limits.aggregate_payload_bytes` | D | reserved: no aggregate bound implemented | `ConfigHonestySpec` reserved parse + `reserved-limits` line | reserved; no bound anywhere (report-only; no admission site reads it) |
| `limits.attribute_entries` | D | RESERVED: effective bound pinned 64 (see `template-bounds`) | `ConfigSpec` template disclosure | reserved; effective 64 entries (native template decoder; config value ignored) |
| `limits.attribute_depth` | D | reserved: no attribute-depth bound implemented | `ConfigHonestySpec` reserved parse + `reserved-limits` line | reserved; no bound anywhere (report-only; no admission site reads it) |
| `limits.jobs` | E | async-table bound (`max 8`) | `ConfigHonestySpec` jobs bound | default 1024, at least 1, max 8 bound on the async table (both; runner floor and native table bound) |
| `limits.events` | E | public open requires positive bound at least catalog size; private FIFO retains `max 8` | `NotificationsSpec` + `NotificationsEngineSpec` serving limits; `ConfigHonestySpec` private events bound | default 1024, at least 1, slot-events bound plus max 8 floor (both; serving slots and private FIFO) |
| `sim.enabled` | E | gates schedule/script/fault-window | `SimBridgeSpec` boost gating + fault windows | on/off sim gate (both; runner script/faults and control-plane schedule) |
| `sim.delay_schedule` | E | per-job tick boost | `SimBridgeSpec` schedule boost | NAME:TICKS list, ticks 0..1000000 (native control plane; scheduler.advance boost) |
| `sim.token_script` | E | runs in the private local scenario owner at scenario start | `SimBridgeSpec` script-ran | insert/remove slot list, slots 0..0xFFFFFFFF (scenario; runner seating script) |
| `sim.fault_window_start` | E | seeds the fault window | `SimBridgeSpec` fault windows | seeds the runner fault window (scenario only) |
| `sim.fault_window_ticks` | E | fault window length | `SimBridgeSpec` fault windows | sizes the runner fault window 0..1000000 (scenario only) |
| `tokens.labels` | E | catalog seating + served labels | `MultiTokenSpec` labels + `ConfigSpec` catalog validation | label list, at most 16, headed haskoki-demo (native; catalog seating) |
| `tokens.so_pins` | E | per-slot SO auth; on SQLite it seeds a new token only, and the stored credential row wins after | `MultiTokenSpec` SO per-slot | per-slot SO PIN, 4..32 bytes (native; login auth) |
| `tokens.user_pins` | E | per-slot user auth; on SQLite it seeds a new token only, and the stored credential row wins after | `MultiTokenSpec` per-slot PINs | per-slot user PIN, 4..32 bytes (native; login auth) |
| `tokens.token_ids` | E | optional parallel array of decimal stable identities (strings in `1..2147483647`), positional with `tokens.labels`: same length, unique, `token_ids[0]` must be `1` (slot 0 is the home token), else the whole config refuses at load with `CfgInvalid`. Absent: slot `n` owns `TokenId (n+1)`. Pinned ids select durable identity, and the public token serial is that identity in 16 lowercase hex digits | `StoreSpec` pinned/duplicate/ragged/malformed/absent `token_ids` cases (parser: `parseTokenIds`) | serial is the 16-character TokenId (native TokenInfo, slot-independent); config PINs seed fresh stores only, durable credentials win after |

Sections (9): `storage`, `engine`, `async`, `trace`, `control`,
`fixtures`, `limits`, `sim`, `tokens`. Any other section name is
rejected as unknown.

## Reserved settings (CONFIG-NOT-POLICY)

- `limits.buffer_bytes`, `limits.attribute_entries`: parse,
  validate (`>= 1`), and report through the
  `limit.*` lines, but template enforcement uses the pinned
  constants (64 entries, 4194304 bytes per attribute value) in the
  template decoder (`maxAttributeBytes` in `core/Haskoki/Attribute.hs`).
  The `small-limits.toml` fixture (8/1024 configured, 64/4194304
  still enforced) tests this reserved behavior.
- `limits.transcript_bytes`, `limits.aggregate_payload_bytes`,
  `limits.attribute_depth`: same shape — parse,
  validate, report; no bound implemented anywhere. Disclosed by
  the `reserved-limits` capabilities line (below), never silently
  ignored again.
- `async.persist_detached`: detached job records always commit to
  the configured store at detach (unconditional `storeCommit`;
  two-process SQLite recovery is driver-pinned), so durability
  follows `storage.kind` (memory: process lifetime; sqlite: file
  lifetime) with no setting effect. Both values parse (fixtures use
  both); the `reserved-async` capabilities line (below) discloses
  the reservation.

Capabilities disclosure lines (pinned verbatim by tests):

- `template-bounds: entries=64 bytes=4194304 (pinned;
  limits.attribute_entries/buffer_bytes reserved, no enforcement
  effect)` (`templateBoundsLine` in `src/Haskoki/Ctl.hs`)
- `reserved-async: persist_detached reserved (detached records
  always commit to the store; durability follows storage.kind, no
  knob effect)`
- `reserved-limits: transcript_bytes/aggregate_payload_bytes/
  attribute_depth reserved (parse+report, no enforcement effect;
  buffer_bytes/attribute_entries: see template-bounds)`

## Unsupported values

| Setting | Refused value | `CfgInvalid` message |
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
`haskoki-ctl config check` exits non-zero naming the setting.

Pre-existing validation refusals (unchanged, contract-pinned):
bad `schema_version`/`profile`/`interfaces`/`storage.kind`/
`engine.kind`/`async.executor`/`control.response_budget_bytes`,
zero `[limits]`, sqlite-without-path, malformed `[sim]`/`[tokens]`.

Unknown keys/sections: `CfgUnknownKey` naming the dotted key
(e.g. `seclevel`, `async.max-queue`) or the section (e.g.
`admission`); `config check` exits non-zero.

## Unsupported settings

| Name | Rationale |
|---|---|
| `seclevel` | No config surface; OpenSSL security level is not operator-tuned through this provider. Rejected as unknown. |
| `max-tls` | No config surface; no TLS stack reads provider config. Rejected as unknown. |
| `native-engine` (as setting) | A capabilities REPORT line (`Ctl.hs`), not a setting: native paths always run OpenSSL4. Writing it as config is rejected as unknown. |
| `admission` / `max-queue` / `waiters` | No thread-pool admission settings exist (`Events.hs` waiters are runtime, not config). Rejected as unknown. |

## Scope of reported settings

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

## Configured versus effective policy

A value that parses is not necessarily an enforced limit. Only the rows
marked `E` above change behavior, and `R` rows accept a single pinned
value. The `D` (reserved) rows (`limits.buffer_bytes`,
`limits.attribute_entries`, `limits.attribute_depth`,
`limits.transcript_bytes`, `limits.aggregate_payload_bytes`,
`async.persist_detached`) are reported but are not enforced limits: the
effective attribute bounds are the fixed constants in `template-bounds`,
and no transcript, aggregate-payload or depth bound exists. Read the
`capabilities` report, not the configuration file, for what is in force.
The per-key inventory of configured value, effective value and
native-versus-scenario applicability is the Effective column of the table
above, checked key-for-key against the parser catalog by the completeness
test. On a SQLite store the catalog PINs seed a token when it is
first created; after that the stored credential row is the PIN authority,
and durable credentials win over later catalog PIN edits: editing
`tokens.so_pins` or `tokens.user_pins` does not change what an
existing token accepts (see [operations notes](operations-notes.md)).

## Resource bounds and aggregate costs

| Bound | Value | Enforced at | Scope |
|---|---|---|---|
| one-shot input | 16 MiB | `maxInputBytes` (`FFI/Decode.hs`), checked before copy | native |
| buffered accumulation | 16 MiB | `maxBuffered`/`validateOperationIn` (`Operation.hs`) | native |
| template entries | 64 | `maxTemplateEntries` (`Object.hs`, `NativeParams.hs`) | native |
| template value bytes | 4194304 | `maxAttributeBytes` (`Attribute.hs`) | native |
| retained tombstones | 4096 records and 64 MiB | `maxRetainedTombstones`/`maxRetainedBytes` (`Async.hs`) | both |
| seed bytes | 1048576 | `seedRandomMaxBytes` (`Backend.hs`) | native |
| scenario steps | 1024 | `maxScenarioActions` (`Control.hs`) | both |
| scenario JSON depth | 32 | `maxJsonDepth` (`Control.hs`) | both |
| scenario slot | 0..0xFFFFFFFF | `argSpec` and presence gate (`Control.hs`) | both |
| sim ranges | 0..1000000 | `argSpec` (`Control.hs`), sim verbs (`Ctl.hs`) | both |
| scheduler ticks | 1..1000000 | control-plane `scheduler.advance` (`Control.hs`) | native |
| event queue floor | max 8 of `limits.events` | runner and native instance setup (`Ctl.hs`, `Instance.hs`) | both |
| async table floor | max 8 of `limits.jobs` | runner and native instance setup (`Ctl.hs`, `Instance.hs`) | both |
| tracer queue floor | max 8 of `trace.queue_limit` | runner and native instance setup (`Ctl.hs`, `Instance.hs`) | both |
| control response budget | 65536 bytes | `responseBudget` constant (`Control.hs`) | native |
| control request size | `control.max_request_bytes` | `dispatchControl` (`Control.hs`) refuses oversize | native |

The WP13 measurement of `appendBuffered` over nine payload/chunk cells is
recorded in `docs/buffered-updates.md`: bounded chunks were judged a separate
follow-up, the current representation was retained, and no follow-up has been
filed.

Coverage is explicitly partial: transcript (`limits.transcript_bytes`),
aggregate payload (`limits.aggregate_payload_bytes`) and attribute depth
(`limits.attribute_depth`) have no bound anywhere in the tree, because no
admission site reads those three keys; R32/A44 stay open for exactly those
dimensions. The five reserved limits keys above are the complete list: three
have no bound, two are pinned to fixed constants.

## Serving presence and private scenario scope

All configured tokens start present, with clear pending slot flags. With
`control.test_enabled=false`, slots are fixed and presence mutations refuse.
When enabled, the loaded instance's `token.insert` and `token.remove`
controls change presence; they do not add slots or monitor hardware.
`limits.events` must be positive and fit the catalog. SQLite restart seats
tokens as present again without resetting their durable objects or lockout
counters.

The CLI scenario runner and `[sim].token_script` operate on an owned local
model, separately from native serving. The final `scenario-ok` line names
its scope (`owned logical simulation`) and the step count: the logical
simulation completed and every step's expectation matched. It is not a
statement about native behavior. The runner consumes every admitted
argument (see `execStep` in `src/Haskoki/Ctl.hs`):

| Action | Consumed arguments |
|---|---|
| `fixture.load` | `fixture` must be `minimal-demo`; the runner seats slot 0 |
| `session.open` | `token` must equal the config slot-0 label (absent means slot 0); `asynchronous` selects the session mode; `read_write` must be `true` (validation only: the runner models read-write sessions) |
| `session.login` | `role` and `pin` are checked against the fixture PINs; login is token-level, so a second login as the same role answers `CKR_USER_ALREADY_LOGGED_IN` and another role answers `CKR_USER_ANOTHER_ALREADY_LOGGED_IN`; only the normal user satisfies the signing login gate; PIN lockout is not modelled: every wrong PIN answers `CKR_PIN_INCORRECT` and the next right PIN still logs in (native locks the role after 3 failures with `CKR_PIN_LOCKED`) |
| `sign.init` | `mechanism` (a known inventory name whose behavior descriptor carries a sign route) and `fixture_key` arm the session; the pair is echoed; a mechanism without a sign route (digests, key generation) answers `CKR_MECHANISM_INVALID`; operation state is not modelled: re-arming an armed session answers `CKR_OK` (native: `CKR_OPERATION_ACTIVE`) |
| `sign` | `data_base64` (strict base64) sets the echoed byte count; `output_capacity` 0 refuses with `CKR_BUFFER_TOO_SMALL`, any positive capacity is accepted without a size comparison; a repeat `sign` after a completed one answers `CKR_OK` (native: `CKR_OPERATION_NOT_INITIALIZED`) |
| `async.complete` | `function` must be `C_Sign`; each completion counts down the session's pending polls |
| `token.remove` | `token` resolves like `session.open`; removing the slot-0 token drops its sessions, clears the login, and seats the removal (opens and repeat removals refuse until slot 0 is inserted again or the fixture loads) |
| `slot-event.wait` | `nonblocking` selects the wait mode (default true) |
| `initialize` / `finalize` | lifecycle verbs (below); the sim verbs (`token.insert`, `async.delay`, `fault.window`) are test controls needing a test-enabled instance |

Pending follows the `[async]` knobs: an async session pends while polls
remain; a sync session never pends. Refusals route three ways, and the
central checker compares each step's explicit result against its `expect`
clause (a step without one accepts only `CKR_OK` and `CKR_PENDING`):

| Refusal | Route | Examples |
|---|---|---|
| scenario bug | hard `Left`: load-time `scenario-rejected`, or run-time `scenario-failed` | load: unknown action/field/argument, unknown mechanism, malformed base64, out-of-range capacity, duplicate session name, nonempty rules; run: unknown session reference, sign without `sign.init`, wait on an empty queue, sim verb without a test-enabled instance |
| operation outcome | expectable `StepReturn` compared against `expect.return` | `CKR_PIN_INCORRECT`, `CKR_USER_ALREADY_LOGGED_IN`, `CKR_USER_ANOTHER_ALREADY_LOGGED_IN`, `CKR_TOKEN_NOT_PRESENT`, `CKR_BUFFER_TOO_SMALL`, `CKR_USER_NOT_LOGGED_IN`, `CKR_CRYPTOKI_NOT_INITIALIZED`, `CKR_CRYPTOKI_ALREADY_INITIALIZED`, `CKR_MECHANISM_INVALID` |
| device fault | expectable `CKR_DEVICE_ERROR` | `sign` / `async.complete` inside the live fault window |

A step without `expect` accepts only `CKR_OK` and `CKR_PENDING`: any
other code fails the run with `scenario-failed: step[N] <action>:
unexpected <CKR>; declare expect.return to assert a refusal`, so a
refusal can never pass silently. The slot wait's
`event:token-state-change` result is its normal product and passes with
or without an `expect.event` clause; the wait takes `expect.return`
only for the lifecycle refusal the gate answers before anything waits.

Lifecycle: the instance starts uninitialized; every verb except
`initialize`, `finalize` and the sim test controls refuses with
`CKR_CRYPTOKI_NOT_INITIALIZED` until `initialize` runs, and again after
`finalize`. `initialize` on a live instance answers
`CKR_CRYPTOKI_ALREADY_INITIALIZED`; after `finalize` it resets the
runner (fresh sessions and login, config fault seed kept) and answers
`CKR_OK`. `finalize` on a non-live instance answers
`CKR_CRYPTOKI_NOT_INITIALIZED`. `sign.init`, `sign` and
`async.complete` additionally require a user-logged-in token
(`CKR_USER_NOT_LOGGED_IN`; an SO login does not satisfy the signing
gate). Removing the slot-0 token drops its sessions and clears the
login; while removed, opens and repeat removals answer
`CKR_TOKEN_NOT_PRESENT`, until `token.insert` of slot 0 or
`fixture.load` seats the token again.

Inert prose lives only under `note`: a scenario object and any step may
carry a `note`, which must be a JSON object; validation checks the shape
and drops it. Every other unknown field refuses.

Each executed step prints one line, `step[N] <action> -> <RESULT>
<detail>`, where `<detail>` echoes the consumed values (`token=`,
`role=`, `mechanism=` with `key=`, `bytes=` with `capacity=`); actions
with nothing to echo print the bare result. Lifecycle, login-gate,
capacity, mechanism and login refusals also emit their traced call,
counted in the run's `trace-lines:` footer; a repeat `initialize`
and `CKR_TOKEN_NOT_PRESENT` refusals emit no trace. Native slot changes
and Digest
callbacks follow the [runtime contract](operations-notes.md).

## Example configurations

`defaultConfig` and the shipped examples are checked by
[ConfigHonestySpec](../tests/model/ConfigHonestySpec.hs):

| Configuration | Checked | Note |
|---|---|---|
| `defaultConfig` | yes | every refusal-prone setting on its honest value (pinned) |
| `maximal-demo.toml` | yes | `persist_detached=true` (reserved, disclosed) |
| `persistent-demo.toml` | yes | sqlite + explicit path, busy 5000, exclusive |
| `real-crypto.toml` | yes | `private_library_context=true`, `persist_detached=false` (reserved, disclosed) |
| `small-limits.toml` | yes | 8/1024 template keys (reserved; effective bounds unchanged) |
| `sim-demo.toml` | yes | full `[sim]` surface |
| `multi-token.toml` | yes | 3-token catalog |
