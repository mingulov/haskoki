# Changelog for haskoki

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Haskell Package Versioning Policy](https://pvp.haskell.org/).

Older entries cite `../ws/notes/...` evidence notes and design paths
under `../ws/docs/...`: those working notes live outside this package
and are not shipped here; the paths stay verbatim as
written-at-the-time pointers.

## [Unreleased]

### Added

- Newcomer audit + GHC 10 alpha lane removal (unreleased):
  `cabal.project.ghc10alpha(.freeze)` and
  `Dockerfile.ghc10alpha` are removed (GHC 9.10.3 is the one
  supported compiler; the full suite plus gates re-verified on
  it); `docs/toolchain.md`, `Dockerfile`, `toolchain.lock`, and
  the `haskoki.cabal` header comments drop the alternative
  toolchain; the README layout block is rewritten to match the
  tree; out-of-package `../ws/` pointers in the README, the
  trust ladder, `src/Haskoki.hs`, and `test/Main.hs` now point
  at in-repo docs; the plan-to-package rename table is deleted
  (no rename happened: `hsp11` strings are verbatim
  design-bundle inheritance, never the product name); the FIPS
  doc drops the dead research-base
  commit pin; the package description and
  README status now state the routed 104-row C-surface catalog
  instead of the retired SHA-256-one-shot-only note.
- Public-domain header migration (unreleased): the eight
  OASIS/TC-vendored header sets (24 files, non-open OASIS IPR
  license) are replaced by the single verbatim latchset
  public-domain v3.2 header (`spec/vendor/pkcs11.h`, hash-pinned
  as `S-PD-32` in `spec/sources.lock.json`). v3.2 is a strict
  superset of every older interface, so older interfaces are
  positional prefixes of the one order with boundary pins;
  `baseline_versions` (write-only, consumed by nothing) is
  dropped from the catalogs and `source_refs` collapse to the
  single canonical citation. Regenerated catalogs are
  name/value/alias-identical; see `spec/source-issues.json`
  SRC-08.
- FIPS-compatibility research (unreleased): new
  `docs/fips-compatibility.md` records the verdict
  (POSSIBLE-WITH-FLAVOR — keep the 4.0.2 static libcrypto
  pin, load a validated 3.1.2 `fips.so` sidecar per CMVP
  #4985) with dated cert-table evidence, the FIPS engagement
  mechanism per the 4.0-branch OpenSSL docs, a build recipe
  resolving Q2 (spike: the static pin loads and drives
  `fips.so`, including a 3.1.2-built module under the 4.0.2
  binary), a PROPOSED code-touchpoint plan, a compliance
  boundary with wording allow/blocklist, and the Q1–Q5
  register (Q1/Q2/Q3/Q5 resolved, Q4 open with criterion).
  Docs only; no behavior change; all future knobs PROPOSED
  per `docs/config-honesty.md`.

- Config honesty (unreleased): every parsed knob is now
  enforced, refused with an exact `CfgInvalid` error, or disclosed
  as reserved in `docs/config-honesty.md` plus two new
  `capabilities` lines (`reserved-async`, `reserved-limits`);
  parseable-but-misleading values (e.g. `control.enabled=false`,
  `trace.redact_secrets=false`, non-default `seed`) fail `config
  check` and every native open (NULL); the
  `engine.private_library_context` default flips to `true` to
  match the always-private native libctx. No C ABI change; see
  `tests/model/ConfigHonestySpec.hs`.

- Byte representation + secrets discipline (unreleased; top priority
  of the FP design review): `ValBytes` is now strict `ByteString`
  (every byte value round-trips exactly; text decoding is explicit
  via `decodeTextAttribute` for the label/application text
  contract only); `ValULong` is unsigned `Word64` with a total
  codec (negatives unrepresentable; platform-width conversions
  guard at their own site, e.g. `decodeHandle`); `Show` redacts
  key/PIN payloads across the audited carriers (`KeyMaterial`,
  `AttributeValue`, objects, models, pending work, records,
  effects, results, requests, traces, token catalog, job bodies —
  Trace-shaped kind/length markers, explicit inspection through
  the exported constructors); the stale coverage boundary
  note is fixed through the publisher (104-row truth,
  `--check` passing again). Persisted bytes stay compatible (v1
  documents, snapshot fingerprints, and wire encodings unchanged
  for in-range values; no migration). Zeroization, constant-time
  operations, and exclusive ownership are explicitly out of scope
  (decided separately per the review).
- Release-smoke rewrite (unreleased; closes F-R1): rewrites
  the early `tests/c/release_smoke.c` to assert the full
  demo-maximal served surface — dlopen closure, function list,
  init, lib 0.3 metadata, one slot, token presence with the
  pinned `haskoki-demo` label, the EXACT 104-row served mechanism
  catalog (pinned by `HASKOKI_MECH_COUNT`) with `CKM_SHA256`
  membership, two REAL session lifecycles each yielding REAL FIPS
  SHA-256 "abc" bytes, finalize — while keeping the real-crypto
  OpenSSL engine config with no synthetic fallback; pins the
  surface with `scripts/check-smoke-surface.py` plus an
  in-process `CKM_SHA256` catalog mirror case, and makes
  `scripts/test-release-install.sh` passing as directly invoked
  (inner docker honors `timeout -s KILL` + `--network host`, apt
  failure fails loudly). Assert, don't change: no production
  serving change.
- Contracts/docs precision (unreleased): pays the 32
  pre-existing test-suite warnings (F-R2) down to a zero baseline
  at root cause (real renames, removals, and totality — no
  suppressions), gated by `scripts/check-warnings-zero.py` over
  the checked-in `spec/warnings-norm.txt`; reclassifies the three
  stale contract rows to planned-with-behavior (routes
  plus executed tests; count 63 → 66, pinned);
  hardens the funnel test to resolve the package root
  independent of CWD and narrows the funnel claim to
  CryptoError-to-code with identity denial legs;
  precision fixes for the default-context sentence, the
  vacuous-by-design filter note, the commit-path reword, the
  reseed non-contract comment, the past-tense fix, and
  the FP-review guarantee claims (`mustGeneratedId` partiality,
  the `runFinisher` wildcard, the import-checker denylist scope).
  Precision work: no production behavior change.
- Lifecycle-correctness follow-ups (unreleased): closes the
  review-harvested findings (8 findings, structured denials
  ledgered, not implemented).
  Instance-handle race closed (atomic C handle plus a never-freed
  per-handle liveness cell: stale uses answer
  `CKR_CRYPTOKI_NOT_INITIALIZED` instead of use-after-free); store
  reload refuses past the object bound all-or-nothing; the 64-entry
  template bound is enforced on in-process planCall paths (core
  source of truth, FFI alias); shrunk-catalog reopens over a reused
  store refuse loudly instead of serving stale slots; async
  completions drain releases after a successful publish; the
  regionless silent-step path is scoped to digest streaming; the
  legacy resource finish attaches its release; verify-path backend
  failures keep their category (code-neutral). No C ABI change.
- Typestate-lite (unreleased): pure refactor with zero
  observable behavior change (same C ABI, snapshot bytes,
  return codes, and gate/driver results on every path).
  Validated slot insertion (`insertOp` derives the slot from the
  operation, `insertChecked` rejects mismatched kind/operation
  claims; the raw `insertSingle` is removed and all per-kind
  modules, restore, and tests are migrated); slot phase
  specialization (`SlotPhase`: buffered, live digest stream, or
  staged output — live+staged is now unrepresentable, with
  per-phase save/restore and the retained buffer preserved
  byte-identically); and a closed job transition (`stepJob`: the
  single total event/state function behind a private verdict
  type, with every poll/drive/complete/cancel/advance site
  routing through it). Pinned by kind-derivation and
  mismatch-rejection cases, per-phase save/restore cases, a
  48-case event/state transition table, and tree-wide
  removal probes for the deleted operations.
- FFI hygiene (unreleased): structural instead of conventional
  FFI lifetime discipline, with no observable behavior change (same
  exports, signatures, and return codes on every path). Bracket-
  structured acquisition for both context opens (every failure arm
  releases everything acquired so far; async exceptions rethrow
  after unwinding); a scoped masked detach-lease combinator
  (`withDetachLease`: killable wait, uninterruptible handoff,
  raises-implies-holds-nothing acquisition, idempotent commit) with
  the `Detached` caller migrated off hand-paired leases; and the
  Direct surface (`haskoki_initialize` / `haskoki_finalize` /
  `haskoki_get_slot_list`) reimplemented in C over C-owned atomic
  liveness state — zero Haskell `unsafePerformIO` globals remain.
  Pinned by acquisition-leak probes, detach-wedge probes (genuine
  wedge counts), scope laws, a tree-wide no-globals probe,
  and a direct return-code matrix in the loader suite.
- Generated laws + command sequences (unreleased): the
  hand-rolled `genSeq` precedent graduates to a real property suite
  (`haskoki-prop-tests`, QuickCheck 2.19.0.0 + tasty-quickcheck
  0.11.1 — the spike pick; Hedgehog cannot build on the pinned
  GHC alpha). Codec roundtrips with reserved-bit/truncation/family
  laws, `interpretError` exhaustiveness over every `TypedError`
  constructor, delta split-equivalence over all splits and lengths
  0..12, snapshot save/restore roundtrips over generated staged
  outputs and slots, digest streaming `init→feed*→final` equal to
  the one-shot over random chunkings on both engines, a digest
  command DSL checked against an independent reference model with
  pinned illegal-order scripts, AES inverse + HMAC sign/verify over
  generated keys on both engines, and oracle laws pinning the
  OpenSSL4 backend byte-for-byte against the external
  `/opt/openssl-4.0.2` CLI over a generated corpus plus KATs.
  Deterministic fixed seeds, `PROP_CASES` count knob (default 100,
  CI 1000). The synthetic backend agrees structurally (widths,
  refusal taxonomy, determinism) — it is a labeled test
  construction, not real crypto, so byte-equality with OpenSSL4 is
  asserted nowhere. Precision work: no production change.
- Error unification (unreleased): one typed error tree carried
  until the FFI edge instead of three parallel String-payload
  hierarchies plus free-text denials. Denials carry a matchable
  `DenyDetail` category (`Haskoki.Operation.Effect`) through
  `denyOutcome`/rejection to the edge with a single `prettyDeny`
  renderer; `BackendFailure` gains the missing `BackendAuthFailed`/
  `BackendInvalidState` categories; both `toCryptoError` adapters
  are total and category-preserving over the mirrored 7-constructor
  vocabularies (lossless round-trip pins both ways); every
  `CryptoError` reaches its `ReturnCode` through the single total
  `interpretError`, and denial legs are the identity on their
  carried code. Precision refactor: every error maps to the
  SAME code as before (per-constructor snapshot pins plus
  `tests/c/consumer_errors.c` over the 2.40 + 3.x tables), with
  strictly more structured detail available.
- Streaming multipart digest (unreleased): classic digest
  Init/Update/Final streams through backend contexts
  (`digestInit`/`digestUpdate`/`digestFinal` keyed by
  `EngineResourceId`) instead of buffering, so multipart input is
  no longer capped by the 16 MiB bound; bytes are identical to the
  one-shot path (per-algorithm pins on both engines plus FIPS
  KATs). Committed releases drain through `releaseResource` on
  every commit-application site (the three `publishCommit` funnels plus the
  `Runtime`/`Async` drains), stale-alloc orphans drain through
  `rejReleases`, and close-session mid-stream releases the live
  context; live streams refuse snapshots with
  `CKR_STATE_UNSAVEABLE`. Sign/verify stay buffered by verdict
  (the backend signs/verifies one-shot only), as do cipher, dual,
  and message paths under the unchanged bound. Proof:
  `tests/c/consumer_streaming.c` over the 2.40 + 3.x tables; see
  `docs/demo-walkthrough.md` §9.
- Multi-token serving (unreleased): a declarative `[tokens]`
  catalog (parallel `labels`/`so_pins`/`user_pins` arrays, slot =
  index, slot 0 stays `haskoki-demo`, max 16) serves N provisioned
  tokens on N slots with per-slot sessions, per-slot user/SO login
  against per-token PINs, and per-token object isolation (find
  yields zero cross-slot; get/destroy refuse typed). Seating,
  enumeration, session open/close-all, and the slot/token/
  mechanism records are slot-parameterized; the default config
  (no section) still serves exactly the home token. Catalog PINs
  are example-grade fixture material; `C_InitToken` stays a stub
  (provisioning is config-declared). Proof:
  `tests/c/consumer_multitoken.c` over the 2.40 + 3.x tables; see
  `docs/demo-walkthrough.md` §8.
- SeedRandom (unreleased): `C_SeedRandom` is live on the legacy
  2.40 table and the versioned 3.x tables (one entry re-homed by
  name; `consumer_discovery` calls it through every table).
  Backend-direct `seedRandom`, mirroring the `C_GenerateRandom`
  path: session validity is the only model check (bad session
  first, NULL-with-length refused, zero length a vacuous OK).
  Synthetic reseeds replace the stream origin (same seed plus same
  call sequence replays, pinned by `caseSeedRandomReplay`);
  OpenSSL mixes via `RAND_add` with entropy estimate 0.0 (single
  named home `HSK_OSSL4_SEED_ENTROPY_ESTIMATE`, pinned by
  `caseSeedEntropyHonesty`). Seeds cap at 1048576 bytes.
- HSM-sim hardening (unreleased): multi-session proofs (one
  store handle, interleaved commits, typed `StoreRevisionConflict`,
  close-invalidates-reservations) with the timing tests rewritten
  deterministically (handshakes + death signals, no sleeps); threaded
  stress proofs (Haskell conservation specs + `scripts/test-sim-threaded.sh`,
  N=4/M=50/iters=20000, timeout-guarded) with the race probe
  50/50 clean (no fix needed); additive `[sim]` TOML section
  (delay schedules, token scripts, bounded fault windows) with
  `capabilities` reporting; `scheduler.advance` now drives pending-job
  ticks through the async poll path (saturating at 1, schedule-boosted
  when sim is enabled); test-gated scenario verbs `token.insert`,
  `async.delay`, `fault.window` (see `docs/demo-walkthrough.md` §7).
- Lifecycle hardening (unreleased): `C_Finalize` tears down
  liveness-first (fresh entrants fail fast, in-flight holders drain
  under the state lock before any Haskell/backend close) and the
  standard-surface handle is an atomic pointer resolved under that
  same lock, closing the finalize-vs-entrant race
  (`scripts/test-finalize-race.sh`).
- Admission bounds (unreleased): `[limits] objects/slots` (and
  `sessions`) are enforced end to end — the resolved config derives
  instance policy (`rulesFromConfig`), every creation seam (create,
  copy, keygen, keypair, unwrap, derive) refuses past the object
  bound with `CKR_HOST_MEMORY`, and token seating refuses past the
  slot bound. Hosts without configuration keep the section-3
  defaults (objects 100000, slots 16, sessions 1024).
- Scope honesty (unreleased): `capabilities` now states the
  native engine binding (`native-engine`, always OpenSSL4) and the
  pinned template bounds (`template-bounds`, 64 entries / 65536
  bytes); `engine.kind`, `limits.attribute_entries` and
  `limits.buffer_bytes` are disclosed as report-only/reserved.

- Standard-surface routing (unreleased): the legacy 2.40 table
  (`cbits/function_tables.c`) AND the versioned 3.x tables
  (`cbits/exports.c`) route to the Haskell engine with identical
  behavior (no-skew checks in `consumer_discovery`): sessions,
  slot/token info, objects/find, keygen/keypair, sign/verify
  (incl. multistage), encrypt/decrypt (incl. multistage), digest
  (one-shot + multistage), login/logout (user/SO/context),
  random, wrap/unwrap/HKDF-derive. Slot 0 seats the provisioned
  token `haskoki-demo` (user PIN `1234`, SO PIN `5678`; no
  InitToken path; `memory` transient vs `sqlite` reload/commit —
  record in `docs/demo-walkthrough.md` §6). Mechanism scope is the
  104-row `support.real == "tested"` catalog projection
  (`cbits/mech_catalog.inc`, freshness-gated); genuinely
  unsupported calls keep documented refusals.
- Spec-bug fixes (FFI-only, core untouched): size queries no
  longer consume the staged op (PKCS#11 v3.1), and every
  `BUFFER_TOO_SMALL` path reports the staged length.
- Release evidence: `pkcs11-check==0.2.0` doctor passing (v3.2, 1
  token-present slot, 104 mechanisms) + 51/51 digest files;
  `pkcs11-tool` real ECDSA-SHA256 sign+verify and AES-ECB
  round-trips; `p11-kit` module+token; NSS attach; direct/proxy
  parity 68+9 with seed-fail proof (verbatim: the 2026-09-22
  oracle session notes). Suites at 2 + 404 +
  119 + 52; `test-loader.sh` 152 checks and `test-c-abi.sh`
  106+102+104+150 pass on the routed surface. `docs/coverage.md`
  regenerated; `SUPPORTED-HOSTS.md` carries the release scope.

### Not claimed

- SunPKCS11 / OpenSSL provider not attempted (no JVM/provider in
  the toolchain image); token objects never reach sqlite (no
  store-write call site); stale `token.db.lock` bricks sqlite init
  after unclean exit; 141 triaged `pkcs11-check` findings await
  engine/frame follow-ups (`C_GetAttributeValue` subset, template
  attrs, key-type policy).

## [0.3.0.0] - 2026-09-21

Behavior breadth (proven in-process) + consumer integration + release
packaging. Release-scope boundary: the 106 behavior-tested mechanisms
below are proven by the Haskell suites through real libcrypto (pinned
OpenSSL 4.0.2) and/or the synthetic engine; the C function tables
expose discovery, metadata and the SHA-256 one-shot only, and answer
`CKR_FUNCTION_NOT_SUPPORTED` for sessions/objects/login/keygen/sign/
encrypt. No conformance, certification, or production-security claim.

### Added

- Core contracts: pure request/outcome/model core (`core/`,
  IO/FFI-free, checker-enforced) with gate-runner automation
  (`scripts/run-gates.sh`).
- Provider/token/session/authentication lifecycle: init/finalize
  rules, session and login state machines (model suite).
- Object and attribute rules: creation/copy/destruction, template
  validation, per-entry attribute reads (model suite).
- Exact output planning: total native output primitives
  (`cbits/native_bindings.c`) with canary-guarded C proofs
  (`scripts/test-c-output.sh`).
- Descriptor registry + synthetic primitives: 464-row mechanism
  catalog (`spec/mechanisms.json`, 480 header CKM incl. aliases),
  generator-first catalogs with denominator gates.
- Real-crypto engine: `CryptoBackend` + OpenSSL 4 backend over
  the pinned static libcrypto (`/opt/openssl-4.0.2`), KAT suites.
- Basic/multipart/recovery/dual operations through the
  plan/commit path (operation + engine suites).
- Message operations (message-call coverage, engine suite).
- Key management, KEM and authenticated wrapping (8 promoted
  descriptors carried into the `exhaustive expansion`).
- Portable operation snapshots (save/restore round-trips).
- Attached asynchronous execution with C proofs
  (`scripts/test-async-attached.sh`, 43 checks).
- SQLite backend + publication protocol (storage suite).
- Detach/restart/rejoin with C restart proofs
  (`scripts/test-async-detached.sh`).
- Events/callbacks/configuration/control: TOML config
  (`HASKOKI_CONFIG`), `HASKOKI_Control`, slot events with native
  proof (`scripts/test-control-events.sh`), `haskoki-ctl` operator
  tool (config/capabilities/scenario/store commands).
- Exhaustive expansion: 106 behavior-tested / 29
  unsupported-with-reason / 2 not-applicable / 327 planned (464 =
  denominator; real-tested 102) with per-shape recipe codecs,
  validation hardening and explicit refusal tables; suites at
  2 + 391 + 115 + 52.
- Consumer integration: direct-load native C scenarios
  (`scripts/test-consumers.sh`: 3.x discovery, table isolation,
  mechanism/info queries, real FIPS digest + routed cross-check,
  pinned refusal pins), direct/proxy parity
  (`scripts/test-proxy-parity.sh`, pkcs11-proxy-ng `a48b60b`,
  seeded-mismatch sensitivity proof), pkcs11-check 0.2.0 /
  p11-kit / pkcs11-tool / NSS / Java / OpenSSL-engine evidence
  (the 2026-09-21 consumer session notes), generated coverage publication
  (`docs/coverage.md` via `scripts/publish-coverage.py`), demo
  walkthrough (`docs/demo-walkthrough.md`), `SUPPORTED-HOSTS.md`.
- Release artifact: `scripts/make-release.sh` (module + 24-lib
  GHC closure bundle, ldd review with no dynamic libcrypto,
  toolchain record) and `scripts/test-release-install.sh` (passing on
  bare `ubuntu:26.04`: ldd clean, ctl runs, FIPS smoke).
- A1/A2 routed/async crypto C proofs (`haskoki_crypto_*`,
  `haskoki_async_*` trampolines with KAT bytes).

## [0.2.0.0] - 2026-09-20

Loader proof + ABI ground truth. No mechanism behavior (beyond one
explicitly TEMPORARY SHA-256 one-shot adapter); no conformance claim.

### Added

- Baseline compiler decision: GHC 9.12.4 (`tested-with`); 9.14.x tracked
  as future CI target (see `../ws/notes/2026-09-20-ghc-baseline.md`).
- Baseline moved to GHC 10.0.1-alpha1 (ghcup prereleases `10.0.0.20260917`),
  `default-language: GHC2024`, `cabal-version: 3.12`; 9.12.4 kept as
  fallback (see `../ws/notes/2026-09-20-ghc10-alpha.md`).
- Docker toolchain image (`Dockerfile`, Ubuntu 26.04, tests baked passing,
  10.4GB) with `docker save`/`load` transfer; `toolchain.lock` and
  `cabal.project.freeze` frozen from verified in-image resolution.
- Fixed `containers` bound (`< 0.9`, uses boot 0.8); temporary
  `allow-newer: all` in `cabal.project` until Hackage bounds catch up
  with the alpha (revisit at 10.0.1 final).
- Loader proof: C-loadable `libhaskoki.so` via a new
  `foreign-library haskoki` stanza (threaded RTS, `DF_1_NODELETE`
  pinning) with discovery, init/finalize lifecycle, minimal metadata,
  and one SHA-256 one-shot operation (TEMPORARY adapter, replaced by
  the engine contract; not a crypto claim). New: `cbits/`,
  `ffi/Haskoki/FFI/Exports.hs`, `tests/c/loader.c`,
  `scripts/test-loader.sh`. Evidence: `../ws/notes/2026-09-20-g0-evidence.md`
  (132/132 loader checks incl. A01–A06, no `hs_exit`, re-verified
  toolchain in `toolchain.lock`). Loader limitations (single global
  digest context, ignored session handles, one slot without a token
  model, no concurrent finalize) are documented in the evidence note;
  full behavior arrives with the core contracts.
- Source lock + ABI generation: byte-pinned header families in
  `spec/vendor/` with per-file SHA-256 in `spec/sources.lock.json` (24
  files: OASIS 2.40-errata01, corrected TC 3.00-errata-1, OASIS 3.1,
  OASIS 3.2, each with its TC/OASIS mirror, plus the rejected OASIS 3.0
  attached set kept as warning evidence); discrepancy register in
  `spec/source-issues.json` (SRC-01 resolves the 3.0 header warning for
  the TC errata family; 2.40/3.2 mirrors byte-identical, 3.1
  banner-only diff). `scripts/generate-abi.py` derives the 68/92/92/104
  versioned tables, exact prototypes, and constant aliases from the
  locked headers into `spec/abi-inventory.json`,
  `spec/abi-reconciliation.json` (104/104 planning-seed rows matched,
  0 added/removed/aliased), `cbits/abi_generated.h`, and
  `cbits/abi_stubs.inc`; `scripts/validate-spec.py` verifies hashes,
  staleness, A40/A41 source/ABI evidence, and the no-fabricated-3.1-
  layout rule. Provider serves versioned 3.0/3.1/3.2 tables from
  `cbits/exports.c` (3.1 is a separately versioned 3.0-layout table;
  Loader behavior re-homed by generated ordinal, no invented entries) with
  shared helpers in `cbits/abi_probe.c` and measured Haskell layout
  types in `ffi/Haskoki/FFI/Types.hsc`. Independent per-interface
  probes `tests/c/layout_*.c` via `scripts/test-c-abi.sh` (452 runtime
  checks incl. the dual-version-table isolation check, plus ~700
  compile-time layout/prototype pins; probe-sensitivity negative case
  via `--negative`). Evidence: `validate-spec.py` PASS,
  `test-c-abi.sh` PASS (96+102+104+150), `test-loader.sh` still
  PASS.

### Evidence

- Loader proof: `../ws/notes/2026-09-20-g0-evidence.md` — 132/132
  loader checks incl. A01–A06, no `hs_exit` (5 independent checks),
  linkage closure, re-verified `toolchain.lock`.
- ABI ground truth: `spec/sources.lock.json` (24 byte-pinned
  files), `spec/source-issues.json`, `spec/abi-reconciliation.json`
  (104/104 seed rows matched), `validate-spec.py` PASS,
  `test-c-abi.sh` PASS (452 runtime + ~700 compile-time checks).
- External consumer: `pkcs11-check==0.2.0` (PyPI, pinned) `doctor` /
  `info` discovery-level runs consistent with the release slice
  (module loads in a foreign process, v3.2/v3.1/v3.0 advertised,
  honest empty token set); see
  `../ws/notes/2026-09-20-pkcs11-smoke-0.2.0.md` (and the loader-only
  smoke note). External evidence only,
  never linked, never the sole oracle.

### Not claimed

- No session/object/token behavior, no mechanism implementations, no
  storage, no conformance. The core work delivers behavior; this release is the
  loadable, ABI-measured foundation it stands on.

## [0.1.0.0] - 2026-09-20

### Added

- Public package scaffold: `Haskoki`, `Haskoki.Types`, `Haskoki.PKCS11`
  stubs with Haddock.
- Placeholder tasty test suite with `pkcs11-check` external-consumer hook note.
- `haskoki.cabal` (library + test-suite), `cabal.project`, `Setup.hs`.
