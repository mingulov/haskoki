# haskoki

A Haskell PKCS#11 soft token (demonstrator) covering APIs 2.40, 3.0,
3.1 and 3.2: real in-process crypto over OpenSSL with honest refusals
for the genuinely unsupported calls. Demo/test scope: the container
image below runs crypto demos and an external checker against the
module; this is not a certified HSM and makes no production-security
claim.

> Status: 0.3.0.0 — behavior breadth (in-process) + consumer integration
> + release packaging. C-loadable `libhaskoki.so` with byte-pinned
> versioned tables (2.40/3.0/3.1/3.2); a mechanism catalog with
> 316 mechanisms tested of 464 catalog mechanisms, proven
> in-process through real libcrypto, routed on the C tables
> (sessions, objects, sign/verify, encrypt/decrypt, digest,
> wrap/unwrap, derive); genuinely unsupported calls refuse honestly.
> Not a conformance claim. Evidence index:
> [`docs/release-results.md`](docs/release-results.md) (+
> `docs/release-results/` companions); `CHANGELOG.md` is history
> only.

## Quick Start (container, no Haskell build)

Prerequisites: docker plus the toolchain image — the demo
Dockerfile builds `FROM haskoki-dev:ghc-9.10.3`
(`docker/Dockerfile.demo`), so build that base first (once, from
the repo root — this `haskoki/` directory; needs network for the
toolchain fetch and build):

```sh
docker build -t haskoki-dev:ghc-9.10.3 .
```

Directory for the rest: the repo root. The demo image is not on a
registry yet, so step 1 builds it from this tree (needs network
for apt/crates/PyPI fetches on the first build).

```sh
docker build -f docker/Dockerfile.demo -t haskoki-demo:0.3.0.0 .
mkdir -p out
docker run --rm --network none -v "$PWD/out:/out" haskoki-demo:0.3.0.0 demo
# demo-ok: 8/8 verifications hold; report: /out/demo-<timestamp>/report.json
```

What just ran: real EC keygen/sign/verify, SHA-256(`abc`) =
`ba7816bf…`, and an RSA-OAEP encrypt/decrypt round-trip through
`pkcs11-tool` against the module — no synthetic crypto. Each
verification prints `rc=0 … ok`; the run dir keeps `report.json` plus
the per-step logs.

Short external check (same prerequisites; reuses `out/`):

```sh
docker run --rm --network none -v "$PWD/out:/out" haskoki-demo:0.3.0.0 \
  check --mode direct --profile smoke
# check-ok: zero findings; report: /out/check-direct-smoke-<timestamp>/report.json
```

Meaning: the separately built `pkcs11-check` binary exercised the
module's smoke profile (743 tests) with zero findings. `check --help`
lists the full profiles (`smoke`/`full` × `direct`/`proxy`) and the
exact exit-code contract (0 clean / 1 findings / 2 broken run).

## Release bundle and verified capabilities

Build the relocatable bundle from this tree inside the toolchain
image (repo root; needs the `haskoki-dev:ghc-9.10.3` image from the
Native section below):

```sh
docker run --rm -v "$PWD:/work" -w /work \
  haskoki-dev:ghc-9.10.3 scripts/make-release.sh
(cd dist-release && sha256sum -c SHA256SUMS)
# haskoki-0.3.0.0-linux-x86_64.tar.gz: OK
# haskoki-0.3.0.0.tar.gz: OK
# test-results-0.3.0.0.tar.gz: OK
# release-manifest.json: OK
```

This writes `dist-release/haskoki-0.3.0.0/` (module + `haskoki-ctl` +
bundled closure + licenses + smoke), the tarballs, and
`release-manifest.json`. `dist-release/` is a build dir (gitignored),
not shipped history. The operator path over the installed artifact is
[`docs/demo-walkthrough.md`](docs/demo-walkthrough.md) (install →
`haskoki-ctl` → consumer crypto → provisioning record).

Verified capabilities (short list; evidence classes per row in
[`SUPPORTED-HOSTS.md`](SUPPORTED-HOSTS.md#release-capability-table)):

- C tables 2.40/3.0/3.1/3.2 with byte-pinned layouts; 316 tested
  mechanisms of 464 catalog rows ([`docs/coverage.md`](docs/coverage.md)).
- Sessions, objects, login/logout visibility, sign/verify,
  encrypt/decrypt (incl. multistage/streaming), digest, wrap/unwrap,
  key derive — over real sessions, byte cross-checked.
- Async 3.2 (`CKR_PENDING` + completion), message-family calls,
  multi-token serving, SQLite restart with flags clear.
- Direct/proxy parity on the pinned proxy (`pkcs11-proxy-ng` v0.2.0):
  49 consumer legs hold; the 40 skips are quarantined per-test with
  upstream causes.

## Results and limitations (measured on this release)

Compact headline numbers (full tables:
[`docs/release-results.md`](docs/release-results.md)):

- Checker smoke (743 tests): zero findings, direct and proxied.
- Checker full (11003 tests): direct 27 triaged findings (4 families);
  proxied 25 findings, all shared with direct, zero proxy-only.
- Compare direct-vs-proxy: 188 frozen exclusions in 7 reasoned families
  + 25 shared findings; the shipped `compare-classify` wrapper prints
  the per-id reasons (`/opt/haskoki/examples/release/compare-classify/compare-classify
  <run-dir>` over any `compare` run dir).

Cause summary (full triage: the Finding triage section of
`docs/release-results.md`). Direct 27 = GCM message-init shape
×7, HOTP params ×2, BLAKE2B wrong-key-type ×16, checker
child-probe defect ×2. Compare 188 = proxy message-init `0x71`
×153 (upstream #39), Blowfish catalog ×20, TLS-derive ×2,
WTLS-premaster ×3, boundary check-order ×2, GMAC direct-only
×2, proxy-better spec-code inversions ×6. Scope is the FROZEN
offline profiles only (`not (wycheproof or acvp or cctv or
stress or fuzz or slow)`); vector-corpus runs are a separate
guarded path (the Vector-data runs §6 there) — fetching data
never extends the shipped profiles.

Known limitations (see also the [release
limits](SUPPORTED-HOSTS.md#limitations-release-scope--read-before-deploying)):

- Upstream proxy defects (same proxy, pinned v0.2.0): private objects
  lost across logout→relogin
  ([pkcs11-proxy-ng#35](https://github.com/mingulov/pkcs11-proxy-ng/issues/35)),
  `find` never returns certificates
  ([#36](https://github.com/mingulov/pkcs11-proxy-ng/issues/36)),
  message-init with IV-shaped params refused `0x71`
  ([#39](https://github.com/mingulov/pkcs11-proxy-ng/issues/39)).
  Proxy v0.2.1 stays rejected (daemon death on message-init,
  [#37](https://github.com/mingulov/pkcs11-proxy-ng/issues/37)).
- The proxy example is TEST-ONLY transport (loopback TCP, no auth/TLS);
  it moves the process boundary, not the security boundary.
- glibc floor: 2.43 overall (proxy ELFs: 2.34). Older hosts fail at
  load time — see Troubleshooting.
- Vector data is unfetched by default, and the shipped smoke/full
  profiles exclude the vector suites regardless: fetching
  (`pkcs11-check fetch-data all`, optional) feeds only the
  separate guarded vector-run recipe (Vector-data runs §6 of
  `docs/release-results.md`), never the headline lanes.
- 316 of 464 catalog mechanisms are behavior-covered; the rest refuse
  honestly (`CKR_MECHANISM_INVALID` etc., never silent mis-execution).

## Why in-process, plus the proxy example

Haskoki ships as a loadable module, not another daemon with a custom
RPC protocol: state lives in the host process, crypto runs against the
bundled libcrypto, and SQLite (when configured) is the only
persistence. Rationale:
[`docs/demo-walkthrough.md`](docs/demo-walkthrough.md#10-in-process-shape-no-rpc-rationale).

The optional proxy example puts the same provider behind
`pkcs11-proxy-ng` on loopback and diffs 5 steps direct-vs-proxied
(5/5 HOLD, `known_differences: []`):

```sh
docker run --rm --network none -v "$PWD/out:/out" --entrypoint /bin/sh \
  haskoki-demo:0.3.0.0 /opt/haskoki/examples/release/proxy-example
# proxy-example-ok: 5/5 steps hold direct-vs-proxied
```

## Threading and host limitations

Recorded limits, not supported modes:

- The provider links the threaded RTS (`-threaded`); there is no
  single-threaded RTS build. `C_Initialize` without `CKF_OS_LOCKING_OK`
  still runs on threaded-RTS threads — the flag only selects whether
  the provider serializes through host mutex callbacks. The init
  validation table (`Haskoki.Runtime.Lifecycle.validateInit`) accepts
  the call either way and never claims an RTS mode it cannot honor.
- Host mutex callbacks are trusted code: they run outside the model
  gate and outside STM, may block provider threads, and their integer
  return codes are the only failure signal. Partial callback sets are
  rejected (`CKR_ARGUMENTS_BAD`), never silently completed.
- Finalization refuses to run while sessions are open (demonstrator
  policy: explicit close first); it never tears down the GHC runtime.
- STM transactions coordinate `TVar` state only. No crypto, SQLite,
  pointer, callback, or logging IO runs inside `atomically` —
  enforced by the STM-hygiene section of
  `scripts/check-core-boundary.py` plus the gate/conflict tests in
  `tests/model/LifecycleSpec.hs`.

## External consumer evidence (same author)

`pkcs11-check` is an external consumer run as a separately built binary
against the compiled shared library — never linked into the test suite
and never the sole oracle. It is NOT an independent audit: Haskoki and
`pkcs11-check` share an author, so the external checking interface is
useful evidence but does not remove shared assumptions. See the hook
note in `test/Main.hs` and rung 5 of `docs/trust-ladder.md`.

## Native and source installation

The supported environment is the toolchain image (Ubuntu 26.04,
GHC 9.10.3, cabal-install 3.12.1.0, deps prebuilt, tests baked
passing). Versions are frozen in [`toolchain.lock`](toolchain.lock) and
[`cabal.project.freeze`](cabal.project.freeze). Full setup (Docker +
native + the GHC 10 alpha alternative) lives in
[`docs/toolchain.md`](docs/toolchain.md).

From anywhere (clones the tree; the URL resolves — verified
`git ls-remote` + full clone, 2026-10-06):

```sh
git clone https://github.com/mingulov/haskoki.git
cd haskoki
docker build -t haskoki-dev:ghc-9.10.3 .
docker run --rm -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test all
```

Native shortcut (Ubuntu 26.04 with the OpenSSL prefix from
`docs/toolchain.md`):

```sh
sudo apt install ghc cabal-install build-essential libgmp-dev
cabal update && cabal test all
```

Docs map: operator path [`docs/demo-walkthrough.md`](docs/demo-walkthrough.md),
results [`docs/release-results.md`](docs/release-results.md), coverage
[`docs/coverage.md`](docs/coverage.md), trust ladder
[`docs/trust-ladder.md`](docs/trust-ladder.md), operations
[`docs/operations-notes.md`](docs/operations-notes.md). History lives in
[`CHANGELOG.md`](CHANGELOG.md) (historical record, not fresh-artifact
evidence).

## Troubleshooting

- Incompatible glibc: `libhaskoki.so` fails to load (`version
  GLIBC_X.XX not found`) on hosts older than the measured floor
  (2.43 overall). Fix: run on a host at/above the floor, or use the
  demo image (ships its own userland).
- Missing provider sidecar: crypto calls fail after an incomplete
  bundle extraction (the module resolves its bundled closure via
  `$ORIGIN` RUNPATH). Fix: re-extract the full `haskoki-0.3.0.0/`
  tree and re-run `sha256sum -c SHA256SUMS` in `dist-release/`.
- PIN/config: demo PINs live in exactly one place
  ([walkthrough §6](docs/demo-walkthrough.md#6-token-provisioning-record)).
  Wrong PINs count down per-role retries; a correct login resets
  the counter only BEFORE lockout — once `CKR_PIN_LOCKED`, the
  role stays locked even for the right PIN (sticky, per-role;
  pinned in `tests/model/SessionSpec.hs` + `consumer_roundtrip`),
  and with no PIN-change path a locked demo role means
  re-provisioning (fresh memory store, or a fresh SQLite path —
  same §6). A bad `HASKOKI_CONFIG` (or an unopenable SQLite path)
  fails the whole `C_Initialize` loudly — fix the config, not the
  token.
- Readonly/wrong-owner output: two distinct failures. A readonly
  output mount (or otherwise unwritable `-v` target) fails writes
  — the shipped classifier's battery pins exit 2 on unwritable
  output dirs; no UID change can make a readonly mount writable,
  so rerun with a writable output path. Separately, run dirs land
  root-owned because the container runs as root by default (`rm`
  on `out/` then needs privileges). Fix for that case only:
  `docker run --user $(id -u):$(id -g) …` (covered by the
  driver's UID rerun) or remove with `sudo`.
- Missing vector data: `doctor` reports `vector data not fetched`
  and KAT/Wycheproof/ACVP suites skip. This is the default; run
  `pkcs11-check fetch-data all` only for full coverage (optional).
- Unsupported mechanism: calls outside the 316-row served catalog
  fail `CKR_MECHANISM_INVALID` (or the documented refusal for that
  call). Check membership in [`docs/coverage.md`](docs/coverage.md);
  refusal (never silent wrong bytes) is the intended behavior.
- Proxy startup failure: the example/entrypoint reports `proxy daemon
  died during startup` and exits 2 (observed with an unbindable
  `HASKOKI_DEMO_PROXY_PORT`). Fix: free port 17512 (default loopback
  port) or set a bindable `HASKOKI_DEMO_PROXY_PORT`; inspect
  `daemon.log` in the run dir.

## Related tools

- [`pkcs11-check`](https://github.com/mingulov/pkcs11-check) — external
  PKCS#11 checker (same author; see above).
- [`pkcs11-proxy-ng`](https://github.com/mingulov/pkcs11-proxy-ng) —
  PKCS#11 proxy (TEST-ONLY transport in the example).
- [`p11scope`](https://github.com/mingulov/p11scope) — PKCS#11 call
  observer for Linux hosts ([sample capture](docs/p11scope-trace.md),
  PARTIAL with stated tool gaps).
- [`P11Lab`](https://github.com/mingulov/p11lab) — PKCS#11 lab setup.

## Layout

```text
haskoki/
  haskoki.cabal     2 libraries (haskoki-core pure core + main) +
                    foreign-library libhaskoki.so + 2 executables +
                    6 test suites
  cabal.project(.freeze)  pinned build plan (Hackage index-state)
  toolchain.lock    frozen toolchain record (compiler, image, OpenSSL)
  Setup.hs          stock Setup
  core/             pure core: types, rules, registry, transition,
                    session, object, operation, snapshot
  src/Haskoki.hs    public re-export surface
  src/Haskoki/PKCS11.hs  provider facade (stub: CKR_GENERAL_ERROR)
  src/Haskoki/Runtime/   config, control, trace, events, async,
                    lifecycle, storage
  src/Haskoki/Engine/    crypto engines (synthetic + OpenSSL 4)
  src/Haskoki/Ctl.hs     haskoki-ctl logic (config/capabilities/
                    scenario/store)
  app/              haskoki-ctl executable
  tools/            lifecycle-probe executable
  cbits/            C: function tables, RTS bootstrap, OpenSSL shim,
                    probes
  ffi/              Haskell foreign exports + measured layout types
  spec/             byte-locked vendor header + ABI inventory
                    (mechanisms, attributes, contracts)
  scripts/          ABI generation/validation + gates + test drivers
  test/             scaffold smoke suite (2 cases + pkcs11-check
                    hook note)
  tests/            model/engine/storage/prop/core suites, C harness
                    (tests/c), ops fixtures (tests/ops)
  docs/             operator + evidence docs (walkthrough, coverage,
                    trust ladder, toolchain, ...)
  bench/            (reserved for future benchmarks)
  .github/          CI (build + test + release + external lanes)
```

## License

Apache-2.0. See `LICENSE`.
