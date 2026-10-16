# Native shim qualification record

Scope: ownership of native handles and buffers in the OpenSSL 4 C shim
(`cbits/ossl4_ctx.c`, `cbits/ossl4_ctx.h`). This is a record of what was
separated, what was exercised, and what the evidence does not cover. It is
not a throughput claim; the only numbers in it carry their environment.

## 1. Decision

The test-only registry and the production shim are separated, not ratified
as one object. Before the split the shipped `libhaskoki.so` exported 27 test
symbols (18 `hsk_ossl4_test_*` plus the 9 `*_gated` entries), recorded in
`ws/evidence/v050-wp13/base/so-test-exports.txt`, and the test live-set could
suppress destruction in the shipped object. Now every test symbol, the
live-sets and the seams exist only when `HSK_OSSL4_TEST_HOOKS` is defined,
and the foreign-library stanza refuses that define.

Evidence:

- `scripts/test-ossl4-bounds.sh` compares the exported symbols of the
  shipped module against `tests/c/ossl4_test_symbols.txt` and fails on any
  test-hook symbol in the shipped library. It deletes the foreign-library C
  objects before building (cabal does not recompile a C source when only
  `cc-options` change) and statically refuses the define in the
  foreign-library stanza.
- Mutation proof (`ws/evidence/v050-wp13/task4-fix1/`): the define appended
  to the foreign-library `cc-options` makes the gate fail; the revert passes.
- `nm "$(cabal list-bin exe:haskoki-ctl)" | grep -c hsk_ossl4_` prints 0.

## 2. Symbol and behavior inventory

`tests/c/ossl4_test_symbols.txt` is the byte-sorted list of 32 names. The
shipped library must contain none of them (gated by
`scripts/test-ossl4-bounds.sh`); the test library contains all of them.

| Group | Count | Shipped `libhaskoki.so` | Test library | Behavior |
|---|---|---|---|---|
| `hsk_ossl4_{digest,digest_init,digest_init_sized,digest_sized,digest_final,digest_xof,env_load,env_new,free}_gated` | 9 | absent | present | Entry points that claim the handle through the live-set before the real call, and release it through the same claim. |
| gate and counter functions: `test_gate_{new,free,park,parked,poll,release,arm_alloc_fail,arm_checkpoint,note_buf,note_digest,note_env,buf_outstanding,digest_outstanding,env_outstanding}`, `test_digest_doublefree`, `test_env_doublefree` | 16 | absent | present | Rendezvous and fault-arming points for the ownership cases, and three independent outstanding counters (buffers, digests, envelopes). The two `doublefree` entries free a handle twice on purpose. |
| `hsk_ossl4_test_live_acknowledge` | 1 | absent | present | Acknowledges an expected repeat free so the exit-time check does not fail the process. |
| seam functions: `test_seam_{reset,arm_bn_fail,arm_derive,bn_calls,fired,target}` | 6 | absent | present | Arm and observe the forced BN-conversion and derive-length paths (section 4). |

Destruction behavior:

- Production frees on every call. There is no registry in the shipped path.
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
| `HSK_SEAM_NOTE` | no-op | Records the PACK and SECRET buffers (`HSK_OSSL4_SEAM_PACK`, `HSK_OSSL4_SEAM_SECRET`) so the harness can check extent and canaries. |

Forced paths: a BN conversion that fails after the buffer is allocated, and a
derive that reports a length different from the allocation (shorter or
longer), each with the derive both failing and succeeding. The harness checks
the exact extent, canary bytes around the allocation, and exact free counts.

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
libcrypto, compile, run and LeakSanitizer; runs every case in every
variant and memory mode; runs five negative controls (double free, heap overflow and
UB in `san-prod`, the unacknowledged-repeat exit gate in `san-hooks`, and an
unarmed seam that must report it was not reached); and writes
`receipt.json` (schema `haskoki-native-sanitizer-receipt/1`) with the variant
flags, the source hashes, the compiler, the libcrypto hash, the image ID, and
every case verdict. Exit codes: 0 pass, 1 failure, 3 open gate (a required
capability is unavailable; never reported as a pass).

Receipt path: `$HASKOKI_SAN_ART/receipt.json`, default
`${TMPDIR:-/tmp}/haskoki-native-sanitizers`; CI sets
`dist-newstyle/san-art` and uploads it as `native-sanitizer-artifacts`.

Evidence limits:

- libcrypto (the static `libcrypto.a`) is not instrumented, so memory errors
  inside OpenSSL are not seen.
- GHC and its runtime are not instrumented; nothing here is a claim about the
  Haskell side.
- The harness is not the shipped object: the sanitizer runs cover the same
  source in a different build.
- One compiler, GCC 15.2.0, and one toolchain image ID.
- Seam cases run in the tracking allocator mode on top of ASan's allocator, so
  all three sanitizers stay active but only on that configuration.

## 6. Measured overhead

Elapsed nanoseconds for the six common cases, plain memory mode, one run per
variant. Environment: Linux 7.0.0-38-generic; 12 CPUs; toolchain image
`sha256:3620af288ecb91b3c8026155cf5f100a23a77a388f00b5c310fae11d175c9698`;
other processes were not excluded.

| Variant | ns | Ratio to the matching plain variant |
|---|---|---|
| `san-hooks` | 174394659 | 4.21 (`plain-hooks` 41378581) |
| `san-prod` | 173831452 | 5.56 (`plain-prod` 31238298) |
| `plain-hooks` | 41378581 | 1.32 (to `plain-prod`) |

These are harness cost ratios from single runs, for judging how long the
qualification takes. They say nothing about the throughput of the shipped
library.

## 7. Open items

- Workflow: the driver step, its host-supplied commit and cleanliness, the
  receipt upload, `sh -n` and a `-fsyntax-only` compile of the harness are
  wired in `.github/workflows/qualification.yml` and have not yet run in CI.
- Release time: `scripts/make-release.sh` should check with `nm` that
  `bin/haskoki-ctl` and `lib/libhaskoki.so` in the release tree contain no
  `hsk_ossl4_test_` or `*_gated` symbol. That check belongs to the release
  work and is not done here.
- The dirty flag in container runs is asserted by the host, not measured in
  the container.
