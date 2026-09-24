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

- Token serving: the default config seats exactly one token —
  slot 0, `haskoki-demo` at `C_Initialize` (user PIN `1234`, SO
  PIN `5678`); a `[tokens]` catalog serves N tokens on N slots
  (slot = index, slot 0 stays `haskoki-demo`). There is no
  `C_InitToken` path — that entry, like `C_InitPIN`/`C_SetPIN`,
  stays `CKR_FUNCTION_NOT_SUPPORTED`.
  Full provisioning record (`memory` vs `sqlite`, PIN/lockout
  rules, catalog): `docs/demo-walkthrough.md` §6/§8.
- Real C-surface crypto: sessions, objects/find, keygen/keypair,
  sign/verify (incl. multistage), encrypt/decrypt (incl.
  multistage), digest (one-shot + multistage), login/logout
  (user/SO/context), random, wrap/unwrap/HKDF-derive — over the
  104-row `support.real == "tested"` mechanism catalog (legacy 2.40
  and versioned 3.x tables route identically). Genuinely
  unsupported calls (RSA keygen/import, ECDH derive,
  message API, dual/combined ops, …) keep their documented
  refusals; see `docs/coverage.md`.
- Third-party consumers now do real work: `pkcs11-check==0.2.0`
  doctor passing (1 token-present slot, 104 mechanisms) with 51/51
  digest files; `pkcs11-tool` real ECDSA-SHA256 sign+verify and
  AES-ECB encrypt/decrypt round-trips; `p11-kit` lists module +
  token; NSS attaches (0 certs). Evidence:
  the 2026-09-22 oracle session notes (working notes, outside this package). SunPKCS11 and the
  OpenSSL provider were NOT attempted (no JVM/provider in the
  toolchain image).
- `haskoki-ctl scenario run` interprets scenarios against an owned
  in-memory model; it never controls another live process.
- Trace files: a config with `[trace] enabled = true` writes
  `$CWD/haskoki-<pid>.jsonl`; ship trace-off configs unless tracing
  is wanted.
