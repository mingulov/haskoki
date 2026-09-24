# haskoki

A Haskell PKCS#11 soft token (demonstrator) covering APIs 2.40, 3.0, 3.1
and 3.2. This repository directory is the **public package**; the private
working space (`../ws/`) holds the design index, roadmap, and notes.

> Status: 0.3.0.0 — behavior breadth (in-process) + consumer integration
> + release packaging. C-loadable `libhaskoki.so` with byte-pinned
> versioned tables (2.40/3.0/3.1/3.2); 106 behavior-tested mechanisms
> proven in-process through real libcrypto; C tables expose the SHA-256
> one-shot only and refuse the rest honestly. Not a conformance claim.
> See `CHANGELOG.md` for the evidence index.

## Layout

```text
haskoki/
  haskoki.cabal     library + test-suite
  cabal.project     local project file
  Setup.hs          stock Setup
  src/Haskoki.hs    public re-export surface
  src/Haskoki/Types.hs   owned-value core types (stub)
  src/Haskoki/PKCS11.hs  provider facade (stub)
  test/Main.hs      placeholder tasty suite (+ pkcs11-check hook note)
  cbits/            C facade: RTS bootstrap, function tables, probes
  ffi/              Haskell foreign exports + measured layout types
  spec/             byte-locked vendor headers + ABI inventory
  scripts/          ABI generation/validation + test drivers
  tests/c/          independent C harness (loader + layout probes)
  bench/            (reserved for future benchmarks)
  docs/             package-local docs (reserved)
  app/              (reserved for future executables)
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
never the sole oracle. See the hook note in `test/Main.hs` and design doc
`09-testing-and-acceptance.md`.

## Design source

The implementation design (revision 0.1) lives read-only at
`../ws/docs/incoming/haskell-pkcs11-design/`; start at
`../ws/docs/README.md`. It uses the working identifier `hsp11` /
`libhsp11.so`; the public package ships as `haskoki`.

## License

Apache-2.0. See `LICENSE`.
