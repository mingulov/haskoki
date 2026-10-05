# haskoki

A Haskell PKCS#11 soft token (demonstrator) covering APIs 2.40, 3.0, 3.1
and 3.2. This repository is the complete package: code, specs, docs,
and release tooling. Dated working notes cited by older entries live
outside this package (see `CHANGELOG.md`).

> Status: 0.3.0.0 — behavior breadth (in-process) + consumer integration
> + release packaging. C-loadable `libhaskoki.so` with byte-pinned
> versioned tables (2.40/3.0/3.1/3.2); a mechanism catalog with
> 316 mechanisms tested of 464 catalog mechanisms, proven
> in-process through real libcrypto, routed on the C tables
> (sessions, objects, sign/verify, encrypt/decrypt, digest,
> wrap/unwrap, derive); genuinely unsupported calls refuse honestly.
> Not a conformance claim. See `CHANGELOG.md` for the evidence index.

Release scope is the demonstrator: `SUPPORTED-HOSTS.md` carries the
[capability table](SUPPORTED-HOSTS.md#release-capability-table)
(demonstrated vs partial rows, each with its evidence class) and the
[release limits](SUPPORTED-HOSTS.md#limitations-release-scope--read-before-deploying);
`docs/demo-walkthrough.md` is the operator path, including the
[in-process (no-RPC) rationale](docs/demo-walkthrough.md#10-in-process-shape-no-rpc-rationale).
No certification or production-security claim is made;
[docs/coverage.md](docs/coverage.md) states the mechanism-catalog
boundary (316 tested of 464 rows).

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

## Build and test

The supported environment is the toolchain image (Ubuntu 26.04,
GHC 9.10.3, cabal-install 3.12.1.0, deps prebuilt, tests baked
passing). Versions are frozen in [`toolchain.lock`](toolchain.lock) and
[`cabal.project.freeze`](cabal.project.freeze). Full setup (Docker +
native + the GHC 10 alpha alternative) lives in
[`docs/toolchain.md`](docs/toolchain.md).

```sh
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

## Demo image

Self-contained image with the bundle, proxy pair, checker, and the
`haskoki-demo` CLI (`demo` | `check` | `compare`; reports under `/out`):

```sh
docker build -f docker/Dockerfile.demo -t haskoki-demo:0.3.0.0 .
docker run --rm -v "$PWD/out:/out" haskoki-demo:0.3.0.0 demo
```

One-command examples live in [`examples/release/`](examples/release/)
(URI second opinion, checker smoke, checker profiles). Checker profiles
and the compare subset are provisional until frozen later in release
preparation; `haskoki-demo --help` states the exit-code contract.

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

## Independent consumer evidence

`pkcs11-check` is an external consumer run as a separately built binary
against the compiled shared library — never linked into the test suite and
never the sole oracle. See the hook note in `test/Main.hs` and rung 5 of
`docs/trust-ladder.md`.

## License

Apache-2.0. See `LICENSE`.
