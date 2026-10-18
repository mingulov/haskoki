# Native shim qualification record

Scope: ownership of native handles and buffers in the OpenSSL 4 C shim
(`cbits/ossl4_ctx.c`, `cbits/ossl4_ctx.h`). This is a record of what was
separated, what was exercised, and what the evidence does not cover. It is
not a throughput claim; the only numbers in it carry their environment.

## 1. Decision

The test-only registry and the production shim are separated, not ratified
as one object. Before the split the shipped `libhaskoki.so` exported 27 test
symbols (18 `hsk_ossl4_test_*` plus the 9 `*_gated` entries), and the test
live-set could suppress destruction in the shipped object. Now every test
symbol, the live-sets and the seams exist only when `HSK_OSSL4_TEST_HOOKS` is
defined, and only the main `library` stanza defines it.

Evidence:

- `scripts/test-ossl4-bounds.sh` compares the exported symbols of the
  shipped module against `tests/c/ossl4_test_symbols.txt` and fails on any
  test-hook symbol in the shipped library.
  - Statically, it fails if `HSK_OSSL4_TEST_HOOKS` appears in `haskoki.cabal`
    outside the `library` stanza (a common stanza or another component
    included) or in any `cabal.project*` file. Comment lines are ignored.
  - Cabal does not recompile a C source when only `cc-options` change, and
    with no monitored change it skips the component ("Up to date"). So the
    gate deletes the foreign library's C objects and its build cache before
    building, then fails unless `cbits/ossl4_ctx.o` was rebuilt.
  - It also fails if the production-configuration object defines any
    `hsk_test_`, `hsk_seam` or `hsk_ossl4_test_` symbol, local ones
    included.
- Mutation proof: a common stanza carrying the define, imported by the
  foreign library. The earlier gate passed on the stale module. The current
  gate fails statically; with the static rule removed it rebuilds and fails
  on the 36 exported hook symbols. The revert passes.
- `nm "$(cabal list-bin exe:haskoki-ctl)" | grep -c hsk_ossl4_` prints 0.
- `scripts/make-release.sh` refuses a release tree whose `lib/libhaskoki.so`
  or `bin/haskoki-ctl` contains a `hsk_ossl4_test_` or `*_gated` symbol. The
  operator tool links the test-configured Haskell library, whose test-only
  code is purely additive (no `#else` branch in either `#ifdef` file), so the
  C hook absence is the property the release proves.

## 2. Symbol and behavior inventory

`tests/c/ossl4_test_symbols.txt` is the byte-sorted list of 36 names. The
shipped library must contain none of them (gated by
`scripts/test-ossl4-bounds.sh`); the test library contains all of them.

| Group | Count | Shipped `libhaskoki.so` | Test library | Behavior |
|---|---|---|---|---|
| `hsk_ossl4_{digest,digest_init,digest_init_sized,digest_sized,digest_final,digest_xof,env_load,env_new,free}_gated` | 9 | absent | present | Wrappers of the production entry points bound to a test gate. They consume an armed allocation fault (failing without allocating), let `env_load` stop at an armed checkpoint, attribute the handles they create to the gate, and count each creation and each real destroy or free in the gate's outstanding counters. |
| gate and counter functions: `test_gate_{new,free,park,parked,poll,release,arm_alloc_fail,arm_checkpoint,note_buf,note_digest,note_env,buf_outstanding,digest_outstanding,env_outstanding}`, `test_digest_doublefree`, `test_env_doublefree` | 16 | absent | present | Rendezvous and fault-arming points for the ownership cases, and three independent outstanding counters (buffers, digest handles, env handles). The two `doublefree` entries are read-only: they return the number of repeat frees the digest and env live-sets have counted. |
| `hsk_ossl4_test_live_acknowledge` | 1 | absent | present | Acknowledges an expected repeat free so the exit-time check does not fail the process. |
| seam functions: `test_seam_{reset,arm_bn_fail,arm_decrypt,arm_derive,arm_digest_sign,arm_encrypt,arm_pkey_sign,bn_calls,fired,target}` | 10 | absent | present | Arm and observe the forced BN-conversion, derive-length, decrypt-length, encrypt-length and sign-length paths (section 4). |

Destruction behavior:

- Production frees on every call. There is no registry in the shipped path.
  Accepted risk: the shipped module no longer absorbs a repeat free, so a
  double free reachable only through the C ABI would corrupt the heap. The
  exit-time check covers only processes linked with the test library; for
  the C ABI path the evidence is the qualification matrix's C consumers
  passing, not a proof that no such path exists.
- The test configuration claims each handle through the exact live-set (it
  grows by doubling, no fixed capacity, no overflow credit). A repeat claim
  is counted and never destroyed or dereferenced. A repeat that was not
  acknowledged through `hsk_ossl4_test_live_acknowledge` fails the process at
  exit with status 70.
- If an address is reused between a destroy and a stale repeat, the repeat is
  attributed to the new owner until that owner's free. The `address-reuse`
  case pins this behavior.

## 3. Production-equivalent targets

- The shipped foreign library, exercised by the C drivers
  (`scripts/test-c-abi.sh`, `test-c-output.sh`, `test-loader.sh`,
  `test-consumers.sh`, `test-crypto-routed.sh`) with no hooks compiled in.
- `san-prod`: the same source configuration as the shipped object (no
  `HSK_OSSL4_TEST_HOOKS`), compiled with the sanitizers and driven by the
  harness. It is a different build of the same source, not the shipped object.

## 4. Seams

Test-only macros in `cbits/ossl4_ctx.c`, compiled to the plain call (or a
no-op) in production:

| Macro | Production expansion | Sites |
|---|---|---|
| `HSK_BN2NATIVEPAD` | `BN_bn2nativepad` | DH public key packing (named and explicit group paths: y, then p, g, y, and q). |
| `HSK_PKEY_DERIVE_OUT` | `EVP_PKEY_derive` | The second (output) derive in the ECDH, XDH and DH derives. |
| `HSK_PKEY_DECRYPT_OUT` | `EVP_PKEY_decrypt` | The output decrypt in the OAEP and PKCS#1 decrypts. |
| `HSK_PKEY_ENCRYPT_OUT` | `EVP_PKEY_encrypt` | The output encrypt in the OAEP and PKCS#1 encrypts. |
| `HSK_PKEY_SIGN_OUT` | `EVP_PKEY_sign` | The output sign in the raw RSA, X9.31 prehash, ECDSA raw and DSA raw signs. |
| `HSK_DIGEST_SIGN_OUT` | `EVP_DigestSign` | The output sign in the hash RSA, PSS, X9.31 digested, ECDSA hash, DSA hash, EdDSA, ML-DSA and SLH-DSA signs. |
| `HSK_SEAM_NOTE` | no-op | Records the PACK, SECRET, OAEP, ENCRYPT, PKEY_SIGN and DIGEST_SIGN buffers (`HSK_OSSL4_SEAM_PACK`, `HSK_OSSL4_SEAM_SECRET`, `HSK_OSSL4_SEAM_OAEP`, `HSK_OSSL4_SEAM_ENCRYPT`, `HSK_OSSL4_SEAM_PKEY_SIGN`, `HSK_OSSL4_SEAM_DIGEST_SIGN`) so the harness can check extent and canaries. |

Forced paths: a BN conversion that fails after the buffer is allocated, a
derive that reports a length different from the allocation (shorter or
longer), each with the derive both failing and succeeding, a decrypt,
encrypt, PKEY sign or DigestSign that reports failure with a moved length
(shorter or longer), a decrypt that performs the real call and then
reports failure (so provider state matches the unarmed run), and a
DigestSign that performs the real call and then reports a shortened
length. The PKEY-sign seam reports failure as -1, pinning the <= 0
checks. The harness checks the exact extent, canary bytes around the
allocation, and exact free counts. Every helper with a failure-path
cleanse owns its pair: ECDSA and DSA in both the raw and hash branches,
EdDSA, ML-DSA-44, SLH-DSA-SHA2-128s, RSA raw and hash, PSS, X9.31 prehash
and digested, OAEP and PKCS#1 encrypt, and OAEP and PKCS#1 decrypt (the
PKCS#1 pair uses the real-call-first decrypt mode). The ECDSA/DSA
hash-raw ok-shrink cases reach the shared end block with a diverged
length after the DER parse fails. The live check drains OpenSSL's
per-thread error state around the measurement: provider calls raise
soft errors whose file/func/data strings would otherwise move the
count without any shim leak.

Success-path extent change (production behavior): after a successful derive,
a reported length above the allocation fails closed and the whole allocation
is cleansed; a shorter length cleanses the unused tail. Before the change the
tail was left as the derive wrote it. The KAT and consumer suites
(`consumer_dh_native`, `consumer_derive_atomic`) pass with it.

## 5. Sanitizer variants, receipt, limits

`scripts/test-native-sanitizers.sh` builds `tests/c/ossl4_sanitize.c` with
`cbits/ossl4_ctx.c` four ways: `san-hooks`, `san-prod`, `plain-hooks`,
`plain-prod` (ASan and UBSan with `-fno-sanitize-recover=all`, `-O1`; plain
builds are the same flags without the sanitizers). It first probes for
libcrypto, compile, run and LeakSanitizer. It then runs each variant's case
list in both memory modes, `track` (the tracking allocator) and `plain`
(OpenSSL's default allocator): 276 runs. `address-reuse` and
`canary-selftest` run in `track` mode only, because they test the tracker
itself. It runs seven negative controls:

- in `san-prod`: a buffer double free, a digest handle and an env handle
  each freed twice (production destruction is not suppressed: ASan reports
  the repeat), a heap overflow and UB;
- in `san-hooks`: the unacknowledged-repeat exit gate, and an unarmed seam
  that must report it was not reached.

It then writes
`receipt.json` (schema `haskoki-native-sanitizer-receipt/1`) with the variant
flags, the source hashes (shim, harness and driver), the commit and whether
it was measured in place or supplied by the caller (`sha_source`), the
compiler, the libcrypto hash, the image ID, and every case verdict. Exit
codes: 0 pass, 1 failure, 3 open gate (a required capability is unavailable;
never reported as a pass).

Receipt path: `$HASKOKI_SAN_ART/receipt.json`, default
`${TMPDIR:-/tmp}/haskoki-native-sanitizers`. The qualification workflow
writes it under the evidence root (`qualify-evidence/sanitizer/art`), which
the evidence upload carries. Both the qualify and report jobs then run
`check-qualification-wiring.py --verify-sanitizer` against the requested
revision. It requires gate `pass`, the requested sha, a clean tree, source
hashes equal to the checkout, and the exact case and negative-control sets.
An open gate fails there as well. The workflow also syntax-checks the harness
inside the toolchain image against the pinned OpenSSL 4 headers (toolchain
job, read-only mount, pinned include directory asserted first); the wiring
gate pins that placement and refuses a runner-side compile.

Evidence limits:

- libcrypto (the static `libcrypto.a`) is not instrumented, so memory errors
  inside OpenSSL are not seen.
- GHC and its runtime are not instrumented; nothing here is a claim about the
  Haskell side.
- The harness is not the shipped object: the sanitizer runs cover the same
  source in a different build.
- One compiler, GCC 15.2.0, and one toolchain source. The image ID in a
  receipt identifies which build produced it: CI-built and locally-built
  images differ there while sharing the toolchain source.
- The seam and copy-fault cases run in both memory modes. In `track` mode
  the tracker's canaries sit inside the ASan block and freed blocks are held
  back, so ASan cannot see a short over-read or a use-after-free of those
  buffers there; the canaries catch writes only. In `plain` mode ASan sees
  the real allocation boundaries, but the exact free count and the full
  extent cleanse are checked only in `track` mode.
- `address-reuse` and `canary-selftest` exist only in `track` mode.

## 6. Measured overhead

Elapsed nanoseconds for the seven common cases, plain memory mode, one run per
variant. Environment: host (no container), Linux 7.0.0-38-generic;
12 CPUs; GCC 15.2.0; other processes were not excluded.

| Variant | ns | Ratio to the matching plain variant |
|---|---|---|
| `san-hooks` | 714721991 | 5.52 (`plain-hooks` 129429871) |
| `san-prod` | 666235468 | 4.73 (`plain-prod` 140900464) |
| `plain-hooks` | 129429871 | 0.92 (to `plain-prod`) |

These are harness cost ratios from single runs, for judging how long the
qualification takes. They say nothing about the throughput of the shipped
library. The `plain-hooks` to `plain-prod` ratio is within run-to-run noise:
an earlier single run inside the toolchain container image measured 0.97
(31623102 against 32507552 ns), against 0.92 here on the host; the two runs
span different environments, so the comparison is rough.

## 7. Open items

- In CI the checkout's git directory is mounted with it, so the driver
  measures the commit and cleanliness itself (`sha_source` `measured`). A
  worktree mounted into a container has no usable git directory; there the
  caller supplies both (`sha_source` `caller`), restricted to the shim,
  harness and driver paths.
