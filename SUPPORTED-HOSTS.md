# SUPPORTED-HOSTS.md — haskoki release host support

This file describes the hosts the release artifact
(`scripts/make-release.sh` output) is verified on, and the
limitations that apply everywhere. No certification or
production-security claim is made for any host below: this is a
demonstration-scope release (see "Limitations"). Host install
verification below was re-exercised on the 0.3.0.0 GHC 9.10.3
artifact. Re-run `scripts/make-release.sh` +
`scripts/test-release-install.sh` to ship and re-verify the
C-surface scope below.

## Verified hosts

| Host | Evidence |
|---|---|
| `ubuntu:26.04` (glibc 2.43, x86-64) + `libgmp10` + `libffi8` + `libnuma1`, clean env (no `LD_LIBRARY_PATH`) | `scripts/test-release-install.sh` passing: ldd closure resolves via `$ORIGIN`, `haskoki-ctl --version` runs, `release_smoke` reports SMOKE-OK (dlopen + init + metadata + FIPS SHA-256 + finalize) |
| `haskoki-dev:ghc-9.10.3` (Ubuntu 26.04, glibc 2.43, x86-64), post-`cabal build` | baked `cabal test all` passing (221/2/58/147/54/784); `pkcs11-check` doctor + fast lane re-run against the 9.10.3 artifact; proxy/p11-kit/NSS runs carried from the 0.3.0.0 evidence |

## Host requirements (all hosts)

- Linux x86-64, glibc >= 2.43 (the artifact's maximum `GLIBC_*`
  reference over `lib/` + `bin/`; captured in `closure/review.txt`).
- System libraries: `libc`, `libm`, `libgmp.so.10`, `libffi.so.8`,
  `libnuma.so.1` (Debian/Ubuntu: `apt-get install libgmp10 libffi8
  libnuma1`). These are the ONLY dynamic host dependencies;
  everything else ships in the artifact.
- No `LD_LIBRARY_PATH` (or any env setup) in consumer processes:
  the module resolves the bundled `libHS*` GHC runtime libs from
  its own directory (`$ORIGIN` RUNPATH; the module's NEEDED set
  covers the whole flat closure, so no transitive lookup escapes
  the bundle), and `bin/haskoki-ctl` is fully static. Keep
  `lib/libhaskoki.so` next to the bundled `libHS*.so` files.
  There is no `ldconfig` or setuid component.
- libcrypto is STATICALLY linked from the pinned OpenSSL 4.0.2
  build (`/opt/openssl-4.0.2`, `libcrypto.a`); no system libcrypto
  is used, required, or interposable. `ldd` shows no
  `libcrypto`/`libssl` (gated in `make-release.sh`).

## Release capability table

Reading this table: every count ships with its denominator. The
mechanism denominator is 464 catalog rows in `spec/mechanisms.json`,
of which 316 are behavior-tested (`docs/coverage.md`); the C surface
serves exactly those 316 (`HASKOKI_MECH_COUNT` in
`cbits/mech_catalog.inc`). The function denominator is separate: 104
entries in the 3.2 table layout (68/92/92/104 across 2.40/3.0/3.1/3.2
per `scripts/generate-abi.py --check`) — 104 is never a mechanism
count. Mechanism-list presence is discovery, not per-parameter proof:
a mechanism row in `C_GetMechanismList` output never implies every
parameter shape and operation for that mechanism was exercised
through C; the Demonstrated-by column says what was. Likewise
`pkcs11-tool -I` renders the 2.40 view only; 3.x interfaces show
through the 3.x discovery entries, not through `-I`. Evidence
classes: `Demonstrated by` names C-consumer pins; rows marked
`real engine-tested in-process` carry real OpenSSL4 engine KATs
(e.g. `tests/engine/OpenSSLSpec.hs`) with C-consumer coverage
unverified — a missing C pin alone never makes a row model-only.

| Capability | Interfaces / mechanisms | Backend | Demonstrated by | Limitation |
|---|---|---|---|---|
| Discovery (2.40 + 3.x) | 2.40 table + `C_GetInterfaceList` / `C_GetInterface` serving 3.2, 3.1, 3.0; all `CK_INTERFACE.flags` 0 | in-process | `tests/c/consumer_discovery.c` (`scripts/test-consumers.sh`); `tests/c/layout_*.c` | no fork-safe flag; `-I` shows 2.40 only |
| Session, login, object lifecycle | all four tables; slot 0 `haskoki-demo` default, N slots via `[tokens]` catalog (max 16) | OpenSSL4 native | `consumer_roundtrip` (sessions, objects, login/logout + lockout), `consumer_multitoken`, `consumer_certificates` (X.509 legs), `control_events` | `C_InitToken`, `C_InitPIN`, `C_SetPIN` refused; finalize needs zero open sessions |
| Digest | SHA-1/256/512 one-shot + multipart; further digest rows per catalog | OpenSSL4 (+ synthetic in suites) | `consumer_roundtrip` (FIPS `abc` bytes), `consumer_streaming` (8/20 MiB multipart KATs), `release_smoke` | multipart streams; further rows real engine-tested in-process (OpenSSL KATs incl. SHA-224/384); C-consumer coverage unverified |
| Sign, verify | ECDSA, HMAC, ML-DSA, SLH-DSA; sign-recover (raw RSA); dual ops | OpenSSL4 | `consumer_roundtrip` (incl. 2420-byte ML-DSA, 7856-byte SLH-DSA), `dual_routed`, `recover_routed`, `message_routed` (HMAC bytes) | partial: fully buffered under the 16 MiB per-input bound; RSA-1024 refused; further rows real engine-tested in-process; C-consumer coverage unverified |
| Encrypt, decrypt | AES-CBC/CBC-PAD/ECB, ARIA-CBC; dual ops | OpenSSL4 | `consumer_roundtrip`, `dual_routed`, `message_routed` (AES-CBC bytes) | partial: framed block modes stream multistage updates (16 MiB per-buffer bound on retained + current update); AEAD/asymmetric/CTS/OFB/key-wrap/XTS/RC4 buffer whole (bound effectively cumulative); one-shots buffer; further rows real engine-tested in-process; C-consumer coverage unverified |
| Keygen (secret + pair) | AES, generic secret; RSA-2048, EC P-256, ML-KEM, ML-DSA, SLH-DSA pairs | OpenSSL4 | `consumer_roundtrip`, `consumer_kem` (512/768/1024 sets) | partial: RSA-1024 + unknown PQC sets refused; further rows real engine-tested in-process; C-consumer coverage unverified |
| Wrap, unwrap, derive | AES-CBC / AES key wrap (incl. KWP); HKDF-subset, ECDH1, DH, encrypt-data derives | OpenSSL4 | `consumer_roundtrip` wrap + derive legs | partial: demonstrated subset only; further rows real engine-tested in-process; C-consumer coverage unverified |
| Random | `C_GenerateRandom` / `C_SeedRandom` on all tables | OpenSSL4 (`RAND_bytes_ex`, `RAND_add` mix) | `consumer_roundtrip` seed contract, `consumer_discovery` per-table calls | seeds capped at 1 MiB; caller bytes credited no entropy; replay asserted on synthetic only |
| PQC | ML-KEM (+ keypair gen), ML-DSA (+ keypair gen), SLH-DSA (+ keypair gen): 6 tested rows | OpenSSL4 | `consumer_kem` (encap/decap, implicit rejection), `consumer_roundtrip` (PQC keypair + sign + verify) | rest of PQC catalog planned except explicitly unsupported HSS/XMSS rows (`docs/coverage.md`); no PQC conformance claim |
| Message-family (v3 ops) | 20 message entries on 3.0, 3.1, 3.2 | OpenSSL4 via message planner | `tests/c/message_routed.c` (AES-CBC + HMAC-SHA256 bytes) | partial: fixed-mechanism reachability; direct-only at proxy (issue 23); no v3.0 conformance claim |
| Async (3.2) | `C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin` on 3.2 only | OpenSSL4 (digest jobs) | `tests/c/async_routed.c` (pending + complete bytes) | partial: digest-only, explicit async session; direct-only at proxy (issue 24) |
| Notifications, callbacks | `C_WaitForSlotEvent` on all tables; surrender callback on one-shot digest | in-process slot service | `notifications_routed` (72 direct legs), `consumer_notifications_poll`, `control_events` | partial: rich legs direct-only at proxy (issue 25); callbacks dropped at proxy; no broadcast promise |
| Stubs (refused by design) | `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_GetOperationState`, `C_SetOperationState`, `C_GetObjectSize`, parallel pair | n/a | `consumer_roundtrip` stub pins; `cbits/function_tables.c` | unsupported: `CKR_FUNCTION_NOT_SUPPORTED` (`CKR_FUNCTION_NOT_PARALLEL` for the pair) |
| Proxy example | loopback gRPC/h2c (`auth = "none"`), daemon + shim from pin `a48b60b` | same module, other process | `scripts/test-proxy-parity.sh` (same CKR + outputs; seeded-mismatch control) | moves the process boundary only: no isolation, no transport security, no certificate |

## Not supported

- Non-x86-64 architectures, non-Linux OSes, glibc < 2.43, musl.
- Unloading safety beyond the documented pinning: the module is
  built `-z nodelete` (process-pinned embedding); `dlclose` does not
  unload Haskell code. Fork children must not call into the module
  (see the loader proof).
- `CKF_LIBRARY_CANT_CREATE_OS_THREADS`: refused with
  `CKR_NEED_TO_CREATE_THREADS` (the threaded RTS needs OS threads).

## Fork safety

Fork children must not call into the module for crypto or stateful
work; post-`C_Initialize` fork-without-exec is unsupported (the
child inherits the GHC RTS image mid-flight, and re-entering
inherited Haskell state from a second PID is never safe). The
module enforces this, not the caller: every entry gates on the
boot PID recorded at RTS start (`cbits/rts_bootstrap.c`), so a
fork child fails safe without entering Haskell and without
dereferencing arguments. Fork-then-exec is unaffected (a fresh
process image re-records its own boot PID).

Per-call-class child behavior (audited, pinned by the `A06a`
probe in `tests/c/loader.c`, run by `scripts/test-loader.sh`):

| Call class | Child result |
|---|---|
| Stateful calls (`C_GetSlotList`, inits, crypto, `C_Finalize`, …) | `CKR_CRYPTOKI_NOT_INITIALIZED` |
| `C_Initialize` (never re-bootstraps an inherited image) | `CKR_GENERAL_ERROR` |
| Pure discovery (`C_GetInfo`, `C_GetFunctionList`) | served (no Haskell entry) |

Enforcement: probe `A06a` (fork + assert the table above, child
exits via `_exit`, parent unaffected) runs in every
`scripts/test-loader.sh` invocation, which the release-evidence
manifest runs; `scripts/check-fork-stance.py` (gate 12 in
`scripts/run-gates.sh`) pins this stance text plus the probe's
presence. Removing the probe or weakening this section fails
gates loudly.

## Limitations (release scope — read before deploying)

- Demo and test purpose only. No certification, FIPS, Common
  Criteria, or production-security claim is made anywhere in this
  release (`docs/coverage.md` limitations). Known-answer vectors
  check output bytes; they are not a validation program. A FIPS
  sidecar exists only as PROPOSED research in
  `docs/fips-compatibility.md`.
- Token serving: the default config seats exactly one token —
  slot 0, `haskoki-demo` at `C_Initialize` (user PIN `1234`, SO
  PIN `5678`); a `[tokens]` catalog serves N tokens on N slots
  (slot = index, slot 0 stays `haskoki-demo`). There is no
  `C_InitToken` path — that entry, like `C_InitPIN`/`C_SetPIN`,
  stays `CKR_FUNCTION_NOT_SUPPORTED`.
  Full provisioning record (`memory` vs `sqlite`, PIN/lockout
  rules, catalog): `docs/demo-walkthrough.md` §6/§8.
- Real C-surface crypto: sessions, objects/find, keygen/keypair,
  sign/verify (incl. multistage, dual, recover), encrypt/decrypt
  (incl. multistage, dual), digest (one-shot + streamed
  multipart), login/logout (user/SO/context), random,
  wrap/unwrap/derive, KEM encap/decap, message/async/
  notification legs — over the 316-row
  `support.real == "tested"` mechanism catalog (legacy 2.40
  and versioned 3.x tables route identically). The capability
  table above names the demonstrated subset per row; genuinely
  unrouted calls keep their documented refusals (stubs in
  `cbits/function_tables.c`); see `docs/coverage.md`.
- Third-party consumers (dated 2026-09-22 evidence,
  `pkcs11-check` 0.2.0 era: interface v3.2, 1 token-present slot,
  104 mechanisms then, 51/51 digest files; `pkcs11-tool`
  ECDSA-SHA256 sign+verify and AES-ECB round-trips; `p11-kit`
  lists module + token; NSS attaches with 0 certs): kept as a
  historical record — `docs/demo-walkthrough.md` step 3.
  Re-qualification on current pins is pending; the 104 figure is
  superseded by the 316-row served catalog above. SunPKCS11 and
  the OpenSSL provider were NOT attempted (no JVM/provider in the
  toolchain image).
- `haskoki-ctl scenario run` interprets scenarios against an owned
  in-memory model; it never controls another live process.
- Trace files: a config with `[trace] enabled = true` writes
  `$CWD/haskoki-<pid>.jsonl` (append-only, best-effort; failures
  counted, never thrown). PINs, key material and message bodies
  render redacted (kind + length only); ship trace-off configs
  unless tracing is wanted.
- Key storage has no encryption-at-rest: the SQLite store keeps
  token rows and object rows (attributes plus `material_blob` key
  bytes) as plain JSON/blobs (schema in
  `src/Haskoki/Runtime/Storage/SQLite.hs`), and memory mode keeps
  the same records in process memory only. Session objects are
  never stored; handles are minted by the live model on reload.
  The store path is explicit in config (SQLite without a path
  refuses the open) and single-writer (a second concurrent open
  refuses `C_Initialize`).
- PINs are fixed at open (`haskoki-demo` user `1234`, SO `5678`;
  catalog PINs come from the TOML file in plaintext) with no
  PIN-change path on the C surface. Comparison is a
  position-constant xor fold with length short-circuit
  (`pinsMatch` in `ffi/Haskoki/FFI/Standard.hs`) — accepted per
  the in-code PIN-compare ruling, not machine constant-time —
  and wrong guesses count down per-role retries to
  `CKR_PIN_LOCKED`. Catalog PINs are example-grade fixtures,
  never production secrets. Tag comparison inside the engines
  uses the same full-fold shape (`ctEq`); no broader
  constant-time promise is made for Haskell code paths.
- No general memory-zeroization promise: Haskell-side key maps
  are dropped for collection on close, and native code cleanses
  scoped native buffers, including HMAC scratch (`OPENSSL_cleanse`
  / `OPENSSL_clear_free` in `cbits/ossl4_ctx.c`). SQLite blobs
  persist until deleted.
- GHC RTS lifecycle: the runtime starts once per process image on
  first need and is never stopped (`C_Finalize` ends the provider
  interval only); the module is pinned with `-z nodelete`, so
  `dlclose` never unloads it. Finalize requires zero open sessions
  (explicit close first). Fork children of a booted process fail
  without entering Haskell (see Fork safety above).
- Synthetic engine is a separate mode: native serving binds
  OpenSSL4 unconditionally (`src/Haskoki/Ctl.hs` native-engine
  line; `BackendEnv OpenSSL4` in `ffi/`), while synthetic bytes
  appear only in `haskoki-ctl` scenario runs and engine suites.
  `allow_synthetic_fallback = true` is refused at config parse
  (`src/Haskoki/Runtime/Config.hs`; pinned by
  `tests/model/ConfigHonestySpec.hs`), so no served call can
  silently swap engines; OpenSSL serves real KAT-backed bytes
  and synthetic serves labeled fakes, and the two are never
  byte-compared (structural agreement only).
- Proxy example moves the backend across a process boundary and
  nothing else: the pinned daemon listens on loopback over
  plaintext gRPC/h2c with `auth = "none"`
  (`scripts/test-proxy-parity.sh` daemon config), so no
  transport-security claim applies. It does not fix Haskoki
  defects, grant multi-tenant isolation, or certify anything;
  the shim presents its own fixed catalog without a 3.1 table,
  and message/async/rich-notification legs stay direct-only with
  per-issue records in the driver. No claims are made about daemon
  sandboxing, worker isolation, or mTLS: the example config carries
  only concurrency bounds on a loopback plaintext listener with
  `auth = "none"`.
