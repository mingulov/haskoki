# Demo walkthrough

End-to-end operator path: install → `haskoki-ctl` → consumer crypto →
control scenario → provisioning record. Steps 2–6 were executed
against the release tree in the toolchain container
(`haskoki-dev:ghc-9.10.3`); expected outputs are quoted
from passing runs. Step 1 (artifact install) is unchanged —
rebuild the artifact with `scripts/make-release.sh` to ship.
(Choice of location recorded:
`docs/demo-walkthrough.md` in the repo, so the handoff ships with
the tree. Evidence levels for every claim below:
`docs/trust-ladder.md`.)

Prerequisites: the release artifact (`scripts/make-release.sh`) and
docker. No environment setup is needed: the artifact is
self-resolving (the module finds its bundled closure via `$ORIGIN`
RUNPATH; `haskoki-ctl` is fully static), so every consumer step
below runs in a clean shell.

## 1. Install (bare host)

```sh
scripts/test-release-install.sh
# PASS: test-release-install.sh (clean-container install passing)
```

This unpacks the artifact on bare `ubuntu:26.04` (+ documented
`libgmp10`/`libffi8`/`libnuma1`), resolves the full `ldd` closure, runs
`haskoki-ctl --version`, and compiles+runs the bundled
`release_smoke`: `SMOKE-OK` over the full served surface
(dlopen + init + lib metadata + one slot + token presence
with the pinned `haskoki-demo` label + the EXACT 109-row served
mechanism catalog with `CKM_SHA256` membership + two REAL session
lifecycles each yielding REAL FIPS SHA-256 "abc" bytes +
finalize). The smoke keeps proving REAL libcrypto bytes
(`real-crypto` profile, OpenSSL engine, no synthetic fallback).
Host contract: see `SUPPORTED-HOSTS.md` (Linux x86-64,
glibc >= 2.43).

## 2. `haskoki-ctl` (offline / owned-instance operator tool)

```sh
CTL=dist-newstyle/.../haskoki-ctl   # or dist-release/.../bin/haskoki-ctl
$CTL --version                      # haskoki-ctl 0.3.0.0
$CTL config check --config tests/ops/fixtures/maximal-demo.toml
# config-ok: profile=ProfileDemoMaximal interfaces=["2.40","3.0","3.1","3.2"]
$CTL capabilities --config tests/ops/fixtures/maximal-demo.toml
# profile: demo-maximal [target-profile: gaps remain, ...]
# engine: EngineSynthetic
# native-engine: EngineOpenSSL (native paths always run OpenSSL4; ...)
# template-bounds: entries=64 bytes=65536 (pinned; ...)
# active-catalog: CKM_AES_CBC CKM_AES_CBC_PAD ... (in-process catalog)
# gap-set: CKM_ACTI CKM_AES_CCM ... (not behavior-covered)
$CTL scenario run --config tests/ops/fixtures/maximal-demo.toml \
    --scenario tests/ops/fixtures/scenario.json
# scenario: pending-sign-and-token-removal
# steps-executed: 12
# step[0] initialize -> CKR_OK
# ... step[5] sign -> CKR_PENDING ... step[8] async.complete -> CKR_OK
# step[10] slot-event.wait -> event:token-state-change
# trace-lines: 12
# scenario-ok
```

The `active-catalog` names IN-PROCESS behavior coverage (proven by
the Haskell suites; see `docs/coverage.md`). The C surface exposes
the `support.real == "tested"` projection (109 rows, step 3).
`scenario run` interprets steps against an owned in-memory model; it
never controls another live process.

## 3. Consumer crypto (real sessions/objects/sign/encrypt)

Direct-load native consumers (inside the toolchain container):

```sh
scripts/test-consumers.sh
# PASS: test-consumers.sh (direct-load consumer scenarios)
```

- `consumer_discovery`: 3.x interface discovery per version,
  versioned-table isolation, cross-table consistency, mechanism/info
  queries (109 rows), real slot/token records (provisioned
  `haskoki-demo`), session open/info/close, legacy-vs-3.2
  no-skew checks.
- `consumer_roundtrip`: REAL round-trips over real sessions —
  SHA-256/SHA-1/SHA-512 digests (FIPS bytes via BOTH the C surface
  and the routed Haskell-engine trampolines, byte cross-checked),
  AES/EC keygen, ECDSA sign/verify, AES encrypt/decrypt (incl.
  multistage), login/logout visibility, wrap/unwrap/HKDF-derive —
  PLUS pinned documented refusals for the genuinely unsupported
  calls (no phantom support).
- `consumer_streaming`: streaming multipart digest over the
  legacy 2.40 table plus the 3.x tables — small multipart KAT, 8
  MiB in 64 KiB parts (KAT), 1 MiB (KAT plus a one-shot
  cross-check on a second session, sized under the proxy's 4 MiB
  message cap), 20 MiB past the 16 MiB bound (KAT-checked; only
  the streamed path completes it), and a close-mid-stream abort
  after which a fresh digest works.

Random (`C_GenerateRandom` / `C_SeedRandom`, live on 2.40 +
3.0/3.1/3.2 via one legacy-table entry re-homed by name):
`consumer_roundtrip` pins the seed contract (seed OK,
generate-after-seed freshness, NULL-with-length refused, bad
session first, zero length vacuous OK) and `consumer_discovery`
calls `C_SeedRandom` through every table.

Per-engine `seedRandom` semantics: synthetic REPLACES the stream
origin (new seed plus counter reset), so the same seed plus the
same subsequent call sequence replays byte-identical bytes (pinned
by `caseSeedRandomReplay`); OpenSSL mixes via `RAND_add` without
replacing DRBG state and never credits caller bytes as entropy —
the estimate lives in one named home,
`HSK_OSSL4_SEED_ENTROPY_ESTIMATE` (`cbits/ossl4_ctx.c`, pinned by
`caseSeedEntropyHonesty`). Note the context split: `RAND_add` has no `_ex` form, so the mix lands on the default-context DRBG while `randomBytes` reads draw from the private libctx DRBG — no read-observable effect is asserted. Seeds cap at 1048576 bytes
(`seedRandomMaxBytes`, mirroring the native `RAND_bytes_ex`
window); empty seeds are a vacuous OK.
C-table determinism is NOT asserted: the served path is
OpenSSL-typed end to end, so replay pins stay on the synthetic
engine suite by design.

Cross-engine byte contract (user ruling 2026-09-23, kept as-is):
OpenSSL serves real KAT-backed bytes; synthetic serves
deterministic labeled fakes (`haskoki-synth/*` stems);
synthetic/OpenSSL byte-equality is explicitly OUT of contract; the
pinned cross-engine property is structural agreement (output
widths / refusals / determinism).

Direct-vs-proxied parity (needs a proxy build per the script header —
canonical artifact hashes plus the repro recipe live in the
`scripts/test-proxy-parity.sh` header):

```sh
scripts/test-proxy-parity.sh
# PASS: test-proxy-parity.sh (direct/proxy parity)
```

Same CKR + same outputs on every forwarded call (71 + 9 transcript
lines identical); handle-carrying calls now forward and succeed
behind the proxy on opened sessions. Seeded-mismatch
(`HASKOKI_PARITY_SEED_MISMATCH=1`, see the script header) still
proves the script can fail.

External consumers (throwaway containers; verbatim evidence in
the 2026-09-22 oracle session notes, kept outside this
package): `pkcs11-check==0.2.0`
doctor passing (interface v3.2, 1 token-present slot, 104
mechanisms) with 51/51 digest files; `pkcs11-tool` REAL
ECDSA-SHA256 sign (70-byte DER) + verify and REAL AES-ECB
encrypt/decrypt round-trips (via the pkcs11-proxy-ng daemon shim,
which shares session space; all crypto is this module's engine);
`p11-kit list-modules` lists module + token; NSS attaches (0
certs). SunPKCS11 and the OpenSSL provider were NOT attempted (no
JVM/provider in the toolchain image).

## 4. Control scenario (live token events, in-process)

```sh
scripts/test-control-events.sh
# PASS: test-control-events.sh (native control/slot-event proof)
```

A native thread blocks in `C_WaitForSlotEvent`; the same
instance's `HASKOKI_Control` entry point inserts a token; the waiter
wakes with the slot event. Then the control budget rule (§5.1):
pure budget query, too-small executes nothing, unknown command
without mutation, `DON'T_BLOCK` no-event mode. This is the live
control/event path behind the owned-instance scenario in step 2.

## 5. Coverage and limits

```sh
python3 scripts/publish-coverage.py --check
# coverage publication current (464 rows, 11 issues)
```

`docs/coverage.md`: 111 behavior-tested / 29 unsupported-with-reason /
2 not-applicable / 322 planned (464 = mechanism denominator), per-family
and per-mechanism tables with evidence case ids, generated
limitations, 12 source issues — plus the release-scope boundary
(in-process proofs vs the 109-row C surface). Known
limitations and host support: `SUPPORTED-HOSTS.md`.

## 6. Token provisioning record

This section is the provisioning record pointed to by
`ffi/Haskoki/FFI/Standard.hs` (module header). Slot 0 always seats
the home token below; §8 serves N tokens on N slots from the
`[tokens]` catalog (without that section the open serves exactly
the home token).

- Label: `haskoki-demo` (`homeTokenLabel`; the model carries no
  label, so the C token-info record and fresh-store token rows use
  exactly this string).
- PINs: user `1234` (`provisionedUserPin`), SO `5678`
  (`provisionedSoPin`). Fixed at open; there is no PIN-change path
  on the C surface (`C_InitPIN`/`C_SetPIN` stay honestly
  `CKR_FUNCTION_NOT_SUPPORTED`), so every process provisioning
  this token agrees. Wrong PINs count down per-role retries
  (`CKF_USER_PIN_COUNT_LOW`, then `CKR_PIN_LOCKED`); a correct
  login clears the counter.
- No-InitToken path: `C_InitToken` stays honestly
  `CKR_FUNCTION_NOT_SUPPORTED`. Provisioning happens at open, not
  through the token-init entry.
- `memory` vs `sqlite` (`HASKOKI_CONFIG` `storage.kind`):
  `memory` stays transient (seat the token, nothing persists);
  `sqlite` requires an explicit path, opens the process store,
  reloads token state, and seats plus commits the home token when
  the store does not know slot 0 yet. A bad configuration or an
  unopenable store fails the whole `C_Initialize` loudly. The
  store is single-writer: a second concurrent open fails
  `C_Initialize` — never a silent fork of token state. With a
  `[tokens]` catalog each catalog slot seats (and, on SQLite,
  commits its labeled row) the same way; see §8.
- Published records: `C_GetSlotInfo` reports `CKF_TOKEN_PRESENT`
  (`haskoki soft slot` / `haskoki contributors`);
  `C_GetTokenInfo` reports the label above with
  `CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED |
  CKF_LOGIN_REQUIRED`, live session counts, and lockout flags.
  Both records are pinned in `consumer_discovery`. On a catalog
  open each slot reports its own label and serial (same flags
  and strings otherwise); see §8.

## 7. HSM simulation

```sh
haskoki-ctl scenario run --config tests/ops/fixtures/sim-demo.toml \
  --scenario tests/ops/fixtures/sim-scenario.json
# scenario: sim-delay-token-fault
# steps-executed: 22
# sim-script: insert 1,remove 1
# step[9] async.complete -> CKR_DEVICE_ERROR
# scenario-ok
```

Decision note (operations-surface extension): the sim surface EXTENDS the
operations surface instead of inventing a parallel one — one
additive `[sim]` TOML section on the validated-once immutable
`Config` cell (unknown keys still rejected), three scenario verbs on
the owned-instance runner, and a delay→job-tick bridge through the
existing async poll path. No new config format, no store redesign, no
new dependencies; delays are logical ticks only (no real-time
guarantees), fault windows are bounded and labeled simulation.

Keys (`[sim]`, see `tests/ops/fixtures/sim-demo.toml`):

- `enabled` (bool, default false): master switch. Schedules, the
  token script, and the fault-window seed apply only when enabled.
- `delay_schedule` (string array, default empty): `NAME:TICKS`
  entries (ticks 0..1000000). NAME is a CKM mechanism name, a
  job-function tag (`sign`/`digest`/`genkey`/`genkeypair`), or `*`
  (all jobs). Per job, the exact mechanism name wins over the
  function tag wins over `*`; within one key the LAST file entry
  wins; unknown names match nothing.
- `token_script` (string array, default empty): `insert N` /
  `remove N` steps (slot 0..2^32-1) run in file order before step 0.
- `fault_window_start` / `fault_window_ticks` (ints 0..1000000,
  default 0/0): the seeded fault window over step indices
  `[start, start+ticks)`.

Verbs (test-gated like `scenario.load`; refuse with
`test_instance_required` unless the instance is test-enabled):

- `token.insert {"slot": N}`: seat a token (posts the arrival event).
- `async.delay {"session": S, "polls": P}`: add P pending polls to
  the session's logical job (sync sessions never pend: the delay
  counter is one the sync path never reads).
- `fault.window {"start": S, "ticks": T}`: REPLACE the live fault
  window (last-writer-wins, including over the config seed).

`scheduler.advance N` (test-gated control command) moves the logical
clock AND decrements every pending job's ticks by N plus its
schedule boost, saturating at 1: the last tick always drives through
the poll path — advance never executes effects, checks reservations,
delivers, or fails a job. The response reports `jobs_advanced` and
`jobs_saturated`.

Determinism contract: sim runs are byte-deterministic — the same
config + scenario produces byte-identical output across runs (pinned
3x by the suite). Faulted `sign`/`async.complete` steps report
`CKR_DEVICE_ERROR` (subject to `expect`, like any return) without
consuming a pending poll; program errors (unknown session, unarmed
sign) precede device faults. Stress asserts conservation invariants
(`scripts/test-sim-threaded.sh`, N=4/M=50/iters=20000), never
interleavings.

## 8. Multi-token serving

A declarative `[tokens]` catalog serves N provisioned tokens on N
slots (a real multi-token environment example); the default config
(no section) still serves exactly the home token, so every
single-slot pin holds unchanged.

Catalog (`tests/ops/fixtures/multi-token.toml`):

```toml
[tokens]
labels = ["haskoki-demo", "haskoki-ops", "haskoki-audit"]
so_pins = ["5678", "6789", "7890"]
user_pins = ["1234", "2345", "3456"]
```

- Slot rule: slot = catalog index; slot 0 MUST be `haskoki-demo`
  (configs that violate this are refused — the stability anchor
  for every existing pin). Parallel arrays must match in length
  (ragged is `CfgInvalid`); labels are non-empty, unique, and fit
  the 32-byte `CK_TOKEN_INFO` label field; at most 16 entries (the
  seating bound — exceeding it refuses the open loudly, never
  truncates silently, and a catalog larger than the configured
  `limits.slots` likewise fails `C_Initialize` instead of seating
  a prefix).
- Auth model: login state is per token (slot) — logging in on one
  slot leaves every other slot public, logout is slot-scoped, and
  each slot authenticates against its own catalog PINs (a
  position-constant xor fold with length short-circuit — accepted
  per the PIN-compare ruling, not machine constant-time). Objects are
  per-token: an object created in one slot's
  session is invisible from any other slot (find yields zero;
  get/destroy refuse with `CKR_OBJECT_HANDLE_INVALID`). Sessions
  stay the isolation unit and are slot-aware throughout.
- Records: `C_GetSlotList` enumerates the seated slots with the
  usual count-query/short-buffer discipline; `C_GetTokenInfo`
  reports each slot's catalog label (blank-padded) with a per-slot
  serial (1-based, so slot 0 keeps `0000000000000001`); unknown
  slots refuse with `CKR_SLOT_ID_INVALID` on every slot-taking
  entry, before any NULL check.
- `C_InitToken` stays a stub: provisioning is config-declared, so
  the InitToken state machine is out of scope.
- Credentials are EXAMPLE-GRADE: catalog PINs are fixture-only
  test material ("Do not use production secrets", the same
  discipline as the existing fixtures). No PIN policy or lockout
  changes.

```sh
haskoki-ctl config check --config tests/ops/fixtures/multi-token.toml
# config-ok: profile=ProfileDemoMaximal interfaces=["2.40","3.0","3.1","3.2"]
haskoki-ctl capabilities --config tests/ops/fixtures/multi-token.toml | grep tokens
# tokens.count: 3
# tokens.labels: haskoki-demo,haskoki-ops,haskoki-audit
```

End-to-end proof: `tests/c/consumer_multitoken.c` (wired into
`scripts/test-consumers.sh` and `scripts/test-proxy-parity.sh`)
enumerates 3 slots on the legacy 2.40 table plus the 3.x tables,
opens per-slot sessions, logs in per slot with catalog PINs, and
pins cross-slot object invisibility and bad-slot refusal.

## 9. Streaming multipart digest

Classic digest multipart streams through backend contexts instead
of buffering: `C_DigestInit` allocates a backend context (the init
plans an alloc effect and the finisher records the
`EngineResourceId` on the slot), each `C_DigestUpdate` feeds one
part (`FxDigestFeed`, no buffering), and `C_DigestFinal` consumes
the context (`FxDigestConsume`). Streamed parts never touch
`scBuffered`, so multipart input is no longer capped by the 16
MiB bound; the bytes are identical to the one-shot path (pinned
per algorithm on both engines plus FIPS KATs end to end).

Releases drain through the commit path, so contexts cannot leak:
every commit-application site (the three `publishCommit` funnels
— `Exports`, `Async`, `Standard` — plus the `Runtime`/`Async`
drains) folds `pcReleases` through `releaseResource` after a
successful publish, and every rejection site drains `rejReleases`
the same way. Per exit:

- Final (success, short-buffer stage, or crypto failure):
  the finisher releases the stream; a staged retry keeps the slot
  with the stream cleared, so the pure retry can never
  double-release.
- Feed failure or driver-protocol violation: the slot terminates
  and the stream releases.
- Close-session mid-stream (the abort path): the close commit
  carries the stream release.
- One-shot on a virgin streamed slot: the one-shot still runs
  `digestOneShot` and releases the untouched stream.
- Stale reservation after an alloc: the orphan drains through the
  rejection instead of leaking.

Live streams are not portable: saving a session with a live
stream refuses with `CKR_STATE_UNSAVEABLE` (the backend context
is process-local — OpenSSL4 declares its contexts unsaveable and
the snapshot bytes carry no resource-id field, pinned by the
unchanged golden). Staged outputs still save and retry normally.

The 16 MiB `scBuffered` bound stays as the backstop for every
non-streamed remainder, and these paths still buffer by design:

- Sign/verify (verdict: STAY BUFFERED): the backend signs
  and verifies one-shot only — `sign`/`verify` take the full message,
  as do `macSign`/`macVerify`, with no
  incremental entry points (contrast
  `digestInit`/`digestUpdate`/`digestFinal`; entries cited by
  symbol — `src/Haskoki/Engine/Backend.hs` line numbers drifted
  under the old citations, so the walkthrough no longer cites
  them by line).
  Streaming them would need new backend API on both engines plus
  key-context binding design; the verdict-carrying answers stay
  `GotBytes` (tags) and `GotValid` (verify verdicts). Guarded by
  the buffered-shape pins.
- Cipher encrypt/decrypt (one-shot `cipherEncrypt`/`cipherDecrypt`
  in the same class), dual operations (which mirror the single-side
  buffering), message multipart (inner buffering), and one-shot
  inputs (bound-checked at plan time; the bytes cross in the
  effect, not the buffer).

End-to-end proof: `tests/c/consumer_streaming.c` (wired into
`scripts/test-consumers.sh` and `scripts/test-proxy-parity.sh`)
streams 1 MiB (plus a one-shot cross-check), 8 MiB, and 20 MiB
(the last past the bound) over the legacy 2.40 table plus the
3.x tables, KAT-checked, with a close-mid-stream abort after
which a fresh digest works.
