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
# PASS: test-release-install.sh (legs A+B passing on the bare image)
```

This unpacks the artifact on bare `ubuntu:26.04` (+ documented
`libgmp10`/`libffi8`/`libnuma1`), resolves the full `ldd` closure, runs
`haskoki-ctl --version`, and compiles+runs the bundled
`release_smoke`: `SMOKE-OK` over the full served surface
(dlopen + init + lib metadata + one slot + token presence
with the pinned `haskoki-demo` label + the EXACT 316-row served
mechanism catalog (316 mechanisms tested of 464 catalog mechanisms)
with `CKM_SHA256` membership + two REAL session
lifecycles each yielding REAL FIPS SHA-256 "abc" bytes +
finalize). The smoke keeps proving REAL libcrypto bytes
(`real-crypto` profile, OpenSSL engine, no synthetic fallback).
Host contract: see `SUPPORTED-HOSTS.md` (Linux x86-64,
glibc >= 2.43).

## 2. `haskoki-ctl` (offline / owned-instance operator tool)

```sh
CTL=dist-release/haskoki-0.3.0.0/bin/haskoki-ctl   # installed artifact (§1)
$CTL --version                      # haskoki-ctl 0.3.0.0
$CTL config check --config tests/ops/fixtures/maximal-demo.toml
# config-ok: profile=ProfileDemoMaximal interfaces=["2.40","3.0","3.1","3.2"]
$CTL capabilities --config tests/ops/fixtures/maximal-demo.toml
# profile: demo-maximal [target-profile: gaps remain, ...]
# engine: EngineSynthetic
# native-engine: EngineOpenSSL (native paths always run OpenSSL4; ...)
# template-bounds: entries=64 bytes=4194304 (pinned; ...)
# active-catalog: CKM_AES_CBC CKM_AES_CBC_ENCRYPT_DATA CKM_AES_CBC_PAD CKM_AES_CCM ... (in-process catalog)
# gap-set: CKM_ACTI CKM_ACTI_KEY_GEN CKM_AES_CFB64 ... (not behavior-covered)
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
the `support.real == "tested"` projection (316 mechanisms tested
of 464 catalog mechanisms; step 3).
`scenario run` interprets steps against an owned in-memory model; it
never controls another live process. Its `EventQueue`/`TokenRegistry` FIFO,
Haskell callbacks and token script are private scenario proofs. The native
serving path in step 4 uses a separate shared `SlotEvents` service and
coalesced pending-slot flags.

## 3. Consumer crypto (real sessions/objects/sign/encrypt)

Direct-load native consumers (inside the toolchain container):

```sh
scripts/test-consumers.sh
# PASS: test-consumers.sh (direct-load consumer scenarios)
```

- `consumer_discovery`: 3.x interface discovery per version,
  versioned-table isolation, cross-table consistency, mechanism/info
  queries (316 mechanisms tested of 464 catalog mechanisms),
  real slot/token records (provisioned
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
- `message_routed`: all twenty message-family entries through the actual
  3.0, 3.1, and 3.2 tables, with fixed AES-CBC and SHA-256 HMAC bytes;
  multipart end signals, two messages per outer init, lifecycle and argument
  precedence, query and repeated-query recall, output canaries, empty
  CBC-PAD output, padding refusal, classic/message collisions, and sibling
  session-slot isolation. Direct-only in the parity driver: the pinned
  proxy cannot transport v3 message calls (see
  mingulov/pkcs11-proxy-ng#23); the explicitly labeled 16 MiB
  input/accumulation probes likewise run directly because the pinned
  proxy has its own smaller request limit.
- `async_routed`: `C_AsyncComplete`, `C_AsyncGetID`, and `C_AsyncJoin`
  through the actual 3.2 table. An explicit `CKF_ASYNC_SESSION` admits
  a fresh full-buffer one-shot `C_Digest`; SHA-256 of `abc` returns
  `CKR_PENDING`, then Complete delivers the fixed FIPS bytes into the
  original allocation. An ordinary session provides the synchronous
  `CKR_OK` control. Queries, short buffers, and their staged recalls
  remain synchronous. The SQLite home-token legs detach, revoke the old
  allocation with `PROT_NONE`, join into new storage, and separately
  execute restart children using only the persistent id. The direct
  proof is recorded for source `415278fd23053d0150f7b13a18b373139236c891`
  in [reviewed consumer evidence](../dist-release-evidence/async-routing/reviewed/gates/test-consumers.sh.log).
  The parity driver labels this scenario `DIRECT-ONLY` under
  [proxy issue 24](https://github.com/mingulov/pkcs11-proxy-ng/issues/24).

- `notifications_routed`: four actual table layouts, memory/SQLite and
  fixed/removable configurations; 72 direct legs exercise coalescing,
  known-empty slot/query agreement, exact wait errors and canaries,
  removal/guarded async output retirement, stale handles, waiter competition,
  reopen and native Digest surrender. Callback OK/CANCEL/other returns,
  original cookie/thread identity, silent non-producers and reentry under
  both lock modes are separate assertions. Deterministic Haskell seams own
  event-first/close-first ordering; native pre-call readiness is not STM
  admission. The [T-N08 record](../dist-release-evidence/notifications/task-n08/review.md)
  includes the deferred removed-session FindObjects page precedence case.
- `consumer_notifications_poll`: nonmutating polling and structural/lifecycle
  checks. Direct execution retains all four tables (37 assertions each).
  At the pinned proxy, common 2.40/3.0/3.2 polling remains parity-eligible;
  the missing 3.1 table has a separate exact OK/NULL topology check.
  Rich notifications remain DIRECT-ONLY under the existing
  [proxy issue 25](https://github.com/mingulov/pkcs11-proxy-ng/issues/25).
  No callback transport, control-route or blocking/finalize parity is promised.
  [T-N09's reviewed evidence](pkcs11-oracle-triage.md#notifications-t-n09-reviewed-evidence-2026-10-01)
  records those runs; final-revision installation and lanes remain pending.

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

Same CKR + same outputs on every forwarded call (current record:
70 consumer legs hold on the pinned v0.2.2 proxy, 19 quarantined
legs in 5 quarantine entries — see the Update (R9) bullet in
`docs/release-results.md`);
handle-carrying calls now forward and succeed behind the proxy on
opened sessions. Seeded-mismatch
(`HASKOKI_PARITY_SEED_MISMATCH=1`, see the script header) still
proves the script can fail.

External consumers, HISTORICAL 2026-09-22 note (throwaway
containers; the dated oracle session notes holding the counts
are kept outside this package, so no figures are quoted here):
`pkcs11-check==0.2.0` doctor passing plus digest files;
`pkcs11-tool` REAL ECDSA-SHA256 sign + verify and REAL AES-ECB
encrypt/decrypt round-trips (via the pkcs11-proxy-ng daemon shim,
which shares session space; all crypto is this module's engine);
`p11-kit list-modules` lists module + token; NSS attaches.
SunPKCS11 and the OpenSSL provider were NOT attempted (no
JVM/provider in the toolchain image).

## 4. Control scenario (live token events, in-process)

```sh
scripts/test-control-events.sh
# PASS: test-control-events.sh
```

The test enables removable software slots in the loaded instance. Tokens
start present with no pending indication, so it first removes the token
and consumes that removal flag. A native thread then blocks in
`C_WaitForSlotEvent`; the **same instance's** `HASKOKI_Control` reinserts
the provisioned token and the waiter consumes its pending slot. Full/present
lists and slot/token queries corroborate the current state. A control reply
budget query and a short buffer execute nothing; an invalid command refuses
without mutation. An empty `CKF_DONT_BLOCK` poll returns `CKR_NO_EVENT`
with its slot sentinel untouched.

This serving path is distinct from step 2's private CLI scenario. With test
controls off, slots stay fixed/present and a blocker can remain asleep until
Finalize. Public flags coalesce rather than replay every edge; after a wait,
query current state. SQLite restart restores present tokens with flags clear,
without a store reset or new durability promise. Presence changes do not
produce session callbacks. For callback use, only a fresh, sufficiently sized
synchronous one-shot Digest on an ordinary registered session surrenders;
query, short, staged, multipart and explicit async paths are silent. The
callback must return normally and must not join a thread needing this
provider. See [operations notes](operations-notes.md#session-notification-callbacks-and-reentry)
for the four discovery/GetInfo exceptions and rejection of other reentry.

[T-N08 control evidence](../dist-release-evidence/notifications/task-n08/control-command.json)
records execution at its stated source/patch. These instructions add no
claim of final installed acceptance.

## 5. Coverage and limits

```sh
python3 scripts/publish-coverage.py --check
# coverage publication current (464 rows, 14 issues)
```

`docs/coverage.md`: 316 behavior-tested / 89 unsupported-with-reason /
2 not-applicable / 57 planned (464 = mechanism denominator), per-family
and per-mechanism tables with evidence case ids, generated
limitations, 14 source issues — plus the release-scope boundary
(in-process proofs vs the 316-row C surface). The FIPS citations in
this file name known-answer vectors (SHA-256 `abc`, multipart KATs),
never a certificate. Known limitations, the capability table, and
host support: `SUPPORTED-HOSTS.md`.

**2026-09-30 message routing (historical note):** earlier revisions of this
section cited a 130-row C surface. At the inspected revision, the `support.real == "tested"`
projection in `spec/mechanisms.json` and `HASKOKI_MECH_COUNT` in
`cbits/mech_catalog.inc` both contain 316 mechanisms. This change routes
20 functions through the existing message planner; it changes neither
that catalog nor any mechanism flags and advertises no new
`CKF_MESSAGE_*` or `CKF_MULTI_MESSAGE` capability. The consumer demonstrates
function-level CBC/HMAC reachability on interfaces 3.0, 3.1, and 3.2,
without making a general v3.0 conformance claim. The function contracts
retain their planner-scoped `planned-with-behavior` label and add the
executed C consumer as evidence.

**2026-09-30 async routing:** The three async entries are live only in
the 3.2 table; the older layouts remain unchanged. Public submission is
Digest-only and requires a fresh full-buffer call on an explicit async
session. Recognizing the `C_Sign` selector preserves identity checks;
it does not admit async Sign, message, multipart, or key-generation work.
The 316 mechanisms and their flags are unchanged; async session/token
capability bits do not add mechanisms. The three contracts remain
`planned-with-behavior`, within the 104-function catalog (78
planned-with-behavior / 24 unsupported-with-reason / 2
not-applicable per `spec/function-contracts.json`; the
2026-09-30 70/32 split predates the T-M02/T-M03 route flips).
This is function-level byte-job
evidence, with no broader async or PKCS #11 conformance claim. The
[oracle qualification record](pkcs11-oracle-triage.md#async-routing-verification-2026-09-30)
cites measured reviewed artifacts; verification of the final revision
and acceptance remain pending.

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
  login resets the counter only BEFORE lockout — once locked, the
  role stays locked even for the right PIN (sticky, per-role;
  the other role is unaffected). This section is the single
  canonical PIN/state explanation; README links here and the
  issue template cites this section instead of repeating values.
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
- Inter-run state and safe removal (single canonical statement):
  with `memory` storage each process opens a FRESH store —
  nothing survives the process, and concurrent opens are
  isolated by construction (no shared run-store). With `sqlite`,
  the store file IS the state: restart reloads provisioned
  tokens as present with flags clear, while attempt/lockout
  counters persist on the token row. Reset = fresh store: for
  memory, a new process; for SQLite, after the process exits,
  remove the store file (or point the config at a fresh path) —
  removal of an inactive store is always safe (no background
  writer exists; the single-writer rule fails a second concurrent
  open loudly, so a successful open proves sole ownership).
  Container runs (`demo`/`check`/`compare`) keep run state in a
  per-run dir under the mounted `/out`; `--rm` drops everything
  else with the container. Reset = delete the run dir (or the
  whole `out/`) — nothing outside the mount is touched.

## 7. HSM simulation

```sh
CTL=dist-release/haskoki-0.3.0.0/bin/haskoki-ctl   # installed artifact (§1)
$CTL scenario run --config tests/ops/fixtures/sim-demo.toml \
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

Private scenario verbs (test-gated like `scenario.load`; refuse with
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
- Records: `C_GetSlotList(CK_FALSE)` enumerates configured slots and
  `C_GetSlotList(CK_TRUE)` filters current presence, both with the usual
  count-query/short-buffer discipline. SlotInfo still accepts a known empty
  slot; TokenInfo and OpenSession refuse it with `CKR_TOKEN_NOT_PRESENT`.
  For a present token, TokenInfo reports the catalog label (blank-padded)
  and per-slot serial (1-based, so slot 0 keeps `0000000000000001`).
  Unknown slots return `CKR_SLOT_ID_INVALID` at these catalog checks;
  OpenSession's output/serial/flag guards precede them. See the
  [boundary order](operations-notes.md#removal-wait-outputs-and-finalization).
- `C_InitToken` stays a stub: provisioning is config-declared, so
  the InitToken state machine is out of scope.
- Credentials are EXAMPLE-GRADE: catalog PINs are fixture-only
  test material ("Do not use production secrets", the same
  discipline as the existing fixtures). No PIN policy or lockout
  changes.

```sh
CTL=dist-release/haskoki-0.3.0.0/bin/haskoki-ctl   # installed artifact (§1)
$CTL config check --config tests/ops/fixtures/multi-token.toml
# config-ok: profile=ProfileDemoMaximal interfaces=["2.40","3.0","3.1","3.2"]
$CTL capabilities --config tests/ops/fixtures/multi-token.toml | grep tokens
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
- Cipher one-shots (`cipherEncrypt`/`cipherDecrypt` in the same
  class) buffer by design (bound-checked at plan time; the bytes
  cross in the effect, not the buffer); cipher MULTISTAGE updates
  stream only for framed block modes (CBC/ECB/CFB/CTR and DES
  equivalents) — each update emits the releasable block prefix
  through one cipher effect and retains only the suffix
  (`core/Haskoki/Operation/Cipher.hs`, streamed legs pinned in
  `tests/c/consumer_roundtrip.c`) — so for those modes multistage
  cipher input is not capped at 16 MiB cumulative: only retained
  bytes plus the current update are. Fully buffered instead
  (`cipherUpdateSplit` returns the whole buffer, so retained input
  accumulates and the 16 MiB check is effectively cumulative):
  AEAD (GCM/CCM/ChaCha20-Poly1305), asymmetric (RSA-OAEP/X.509),
  CTS, OFB, key-wrap (KW/KWP/KW-PKCS7), XTS, and RC4. Dual
  operations (which mirror the single-side buffering), message
  multipart (inner buffering), and one-shot inputs stay buffered.

End-to-end proof: `tests/c/consumer_streaming.c` (wired into
`scripts/test-consumers.sh` and `scripts/test-proxy-parity.sh`)
streams 1 MiB (plus a one-shot cross-check), 8 MiB, and 20 MiB
(the last past the bound) over the legacy 2.40 table plus the
3.x tables, KAT-checked, with a close-mid-stream abort after
which a fresh digest works.

## 10. In-process shape (no-RPC rationale)

Haskoki is an in-process PKCS#11 demonstrator. It ships as a loadable
module rather than introducing another daemon and a custom RPC protocol.
Loading the module also loads its Haskell runtime and crypto implementation
into the host process. The optional pkcs11-proxy-ng example places the
provider in a separate process. This changes the process boundary; it does
not turn Haskoki into a hardened HSM.

Four topics, kept separate:

Runtime loading. `dlopen` on the module (`foreign-library haskoki`,
`native-shared` in `haskoki.cabal`) maps the C tables, the Haskell
runtime libraries (resolved from the module's own directory via
`$ORIGIN` RUNPATH), and the statically linked libcrypto into the
client's address space. The threaded RTS starts once per process
image on the first `C_Initialize` needing Haskell entry and records
its boot PID (`cbits/rts_bootstrap.c`); `C_Finalize` ends the
provider interval and never stops the runtime (a poison macro turns
any shutdown call-site into a compile error in the same file), and
`-z nodelete` keeps `dlclose` from unloading the module.

Key and state placement. Session, object, login, and operation state
live in `TVar` cells in process memory (`Haskoki.Runtime.Lifecycle`
environment), with one `InstanceCell` per initialization interval;
the OpenSSL4 backend keeps digest contexts and key material in
`MVar`-guarded maps in the same process (`OSSL4Env` in
`src/Haskoki/Engine/OpenSSL4.hs`). Nothing here implies a second
storage tier: persistence exists only where SQLite is configured
(see below), and the proxy example moves this whole image across a
process boundary without changing what it stores.

Buffering vs streaming. Classic digest multipart streams through
backend contexts (`digestInit`/`digestUpdate`/`digestFinal` in the
`CryptoBackend` class; §9), so the 20 MiB leg completes past the
buffer bound with no cumulative cap; cipher multistage updates
stream for framed block modes only (CBC/ECB/CFB/CTR and DES
equivalents), emitting the releasable block prefix per update and
retaining only the suffix (`core/Haskoki/Operation/Cipher.hs`;
`tests/c/consumer_roundtrip.c` pins streamed output, queries, and
short-buffer retries). The 16 MiB `maxBuffered` backstop
(`core/Haskoki/Operation.hs`) is per-buffer, not cumulative, for
streaming modes: a cipher update refuses only when retained bytes
plus the current update exceed it, and a short output buffer
refuses with `CKR_BUFFER_TOO_SMALL` without consuming input. Fully
buffered by design: sign, verify, MAC, dual mirrors, message inner
buffering, one-shot inputs (bound-checked at plan time), and these
cipher modes — AEAD (GCM/CCM/ChaCha20-Poly1305), asymmetric
(RSA-OAEP/X.509), CTS, OFB, key-wrap (KW/KWP/KW-PKCS7), XTS, RC4 —
whose retained input accumulates under the same 16 MiB check
(`cipherUpdateSplit` buffers them whole, so the bound is
effectively cumulative). Random seeds and
reads cap at 1 MiB (`seedRandomMaxBytes`,
`generateRandomMaxBytes`). Behind the proxy, legs additionally fit
the proxy's 4 MiB default message cap
(`tests/c/consumer_streaming.c` sizes its cross-check leg under it).

SQLite storage. `storage.kind = "sqlite"` requires an explicit path
and refuses pathless opens; the store is single-writer and wraps
each commit in one `BEGIN IMMEDIATE` transaction
(`src/Haskoki/Runtime/Storage/SQLite.hs`). Token and object rows
persist as plain JSON/blobs with no encryption-at-rest; attempt and
lockout counters ride the token row, while PINs stay fixed at open
(§6). Restart reloads provisioned tokens as present with flags
clear; see `docs/operations-notes.md` for the quarantine protocol.

## 11. Container image: proxy example + compare classifier

Prerequisites: the demo image built (`docker build -f
docker/Dockerfile.demo -t haskoki-demo:0.3.0.0 .`, repo root) and an
output dir (`mkdir -p out`). The proxy example diffs 5 steps
direct-vs-proxied over the pinned `pkcs11-proxy-ng` v0.2.2 pair on
loopback (TEST-ONLY transport):

```sh
docker run --rm --network none -v "$PWD/out:/out" --entrypoint /bin/sh \
  haskoki-demo:0.3.0.0 /opt/haskoki/examples/release/proxy-example
# proxy-example-ok: 5/5 steps hold direct-vs-proxied
```

`compare` runs the full checker profile in both modes and diffs
verdict transcripts; it is raw plumbing (every mismatch is an
"unexpected diff", even frozen ones). The shipped classifier splits
the raw diff into known-difference (83 frozen exclusions with
per-id reasons), direct-only, flaky, and unexpected-difference
buckets without touching the raw files:

```sh
docker run --rm --network none -v "$PWD/out:/out" haskoki-demo:0.3.0.0 compare
# ... then classify that run dir (newest out/compare-*):
RD=$(ls -dt out/compare-* | head -1)
docker run --rm --network none -v "$PWD/out:/out" --entrypoint /bin/sh \
  haskoki-demo:0.3.0.0 \
  /opt/haskoki/examples/release/compare-classify/compare-classify \
  "/out/$(basename "$RD")"
# compare-classify-ok: 83 known-difference + shared 22/22 exact
```

Frozen sets, family reasons, and the zero-variance rule live in
`docs/release-results.md` (+ `docs/release-results/` companions).
