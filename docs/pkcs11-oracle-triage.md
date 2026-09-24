# pkcs11-check oracle triage (local docker lanes)

External-oracle findings against the release bundle, from local docker runs
of `pkcs11-check` with fetched vectors (`bash /tmp/pkcs11-ws/run-lane.sh
fast|kat`; lane wrapper `scripts/ci-pkcs11-lane.sh`). Bundle:
`dist-release/haskoki-0.3.0.0` built by `scripts/make-release.sh` in the
pinned toolchain image. This note records what was found, what was fixed
with local proof, what remains, and what the oracle skips — per cluster,
not per test.

## Fast-lane results across fix rounds

Total collected: 5762 each run. Summaries are authoritative; the per-test
records list interesting outcomes only (see Method).

| Round | Passed | Failed | XFailed | Skipped | Child crashes |
|---|---|---|---|---|---|
| r0 (pre-fix) | 1121 | 142 | 810 | 3689 | 3 |
| r1 (template bound + class defaulting) | 1504 | 133 | 400 | 3725 | 0 |
| r2 (ECDSA raw + wrap key-type gate) | 1507 | 130 | 400 | 3725 | 0 |
| r3 (key-import slice) | 1530 | 104 | 396 | 3732 | 0 |
| r4 (matrix, one HMAC-type short) | 1566 | 97 | 366 | 3733 | 0 |
| r5 (matrix + per-digest HMAC types) | 1576 | 92 | 362 | 3732 | 0 |

## Round 1: template-count bound, class defaulting, class range

- `C_GetAttributeValue` refuses template counts above the 64-entry bound
  (`cbits/standard_surface.c`) instead of reading out of bounds. The three
  child crashes were the oracle's segfault probes; post-fix the lane shows
  zero crashes and the probes pass. Pinned by `tests/c/consumer_errors.c`
  (huge count, count 65 refuse; a real 64-entry template over a live key
  processes).
- Keygen/keypair/derive/unwrap templates default a missing `CKA_CLASS` to
  the mechanism-implied class (`core/Haskoki/Operation/KeyManagement.hs`,
  `core/Haskoki/Object.hs`). Classless oracle fixtures now plan; this moved
  most of the 810 xfails (keygen refused at setup) into runs: +383 passed,
  xfail count halved.
- Creation rejects unknown class ids as inconsistent.
- Regression check on the r0→r1 diff: 36 failures fixed, 27 newly visible
  failures all previously xfailed (tests that can now set up keys and run
  to deeper findings), zero tests going from pass to fail.

## Round 2: ECDSA raw default, wrap key-type gate

- ECDSA signatures default to raw r||s when the mechanism carries no
  parameters (`core/Haskoki/Recipe/Ecdsa.hs`: empty params select `RAW`;
  explicit `"DER"` still selects DER). PKCS#11 ECDSA mechanisms take no
  parameters and emit the raw concatenation; the old DER default read as
  an oracle crypto-kind nonce-bias finding (`test_r_value_distribution`:
  DER headers parsed as `r`, MSB never set) and broke OpenSSL-side
  cross-verification while our own symmetric roundtrips stayed passing.
  Fixed: `test_r_value_distribution`, `test_low_s_and_malleability`
  (harness buffer sized for 64-byte signatures vs DER lengths).
- AES-CBC wrap/unwrap refuse a non-AES wrapping key with
  `CKR_WRAPPING_KEY_TYPE_INCONSISTENT` / `CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT`
  (new `ReturnCode` constructors in `core/Haskoki/Types.hs`, numerics in
  `ffi/Haskoki/FFI/Exports.hs`, gate in `withWrappingKey`) instead of
  coercing foreign key material. `CKR_KEY_TYPE_INCONSISTENT` is added for
  the follow-up Init-path matrix. Fixed:
  `test_registry_wrap_wrong_key_type[AES_CBC]`.
- Coverage for both: model pins (`tests/model/KeyManagementSpec.hs`,
  `tests/recipes/RecipeEcdsaSpec.hs`, `tests/model/ByteFormatSpec.hs`,
  `tests/model/TemplateRulesSpec.hs`), QuickCheck gate laws over the whole
  key-type domain (`tests/prop/WrapProps.hs`), C consumer pins
  (`tests/c/consumer_roundtrip.c`, `tests/c/consumer_errors.c`).
- Regression check on the r1→r2 diff: 3 fixed, 0 newly failing.

## Round 3: key-import slice (component attributes + DER assembly)

- `AttributeType` gains the standard key-component constructors (RSA
  modulus/exponent/private/CRT parts, `CKA_EC_POINT`; `CKA_EC_PARAMS` and
  `CKA_PUBLIC_EXPONENT` already existed), `Haskoki.Der` assembles them
  into OpenSSL-consumable DER, and `planCreateObject` derives import
  material through `importMaterial` (`core/Haskoki/Object.hs`,
  `core/Haskoki/Der.hs`, `core/Haskoki/Attribute.hs`). `C_CreateObject`
  with component templates now mints usable keys instead of refusing
  with `ATTRIBUTE_TYPE_INVALID`. Unknown curves refuse honestly with the
  new `CKR_CURVE_NOT_SUPPORTED`.
- Fixed (26, all import-adjacent): `test_rsa_key_import.py` (4),
  `test_ec_import_coherence.py` (4), `test_ec_missing_params.py` (5),
  `test_mech_sign.py` RSA KAT vectors (5), `test_oaep_parameter_fidelity.py`
  (3), `test_verify_operability.py` (2: ECDSA-SHA256, RSA-PKCS1v15-SHA256),
  RSA setup edges in `test_ckr_object.py` / `test_crypto_weakness.py` /
  `test_provisioning_capability.py` (3).
- Coverage: `tests/model/KeyImportSpec.hs` (component acceptance, DER
  assembly goldens, curve allowlist, unknown-curve refusal),
  `tests/c/consumer_roundtrip.c` (import→use roundtrips),
  `tests/c/consumer_errors.c` (in-bounds 65-entry refusal in both
  topologies; the OOB-count probe stays direct-only — the proxy shim
  reads the full count out of bounds in external code, so its outcome is
  garbage-determined — and vendor DER params assert `PARAM_INVALID`
  proxied, where the shim refuses params on parameterless ECDSA).
- Regression check on the r1→r3 node-id diff: 29 fixed, 0 newly failing
  (r2's records were overwritten by the r3 run at the same lane path, so
  the diff runs r1→r3; r1→r2 was already 3 fixed / 0 new, hence r2→r3 is
  26 fixed / 0 new). Snapshot: `/tmp/pkcs11-fast-r3.json`.

## Round 4: key-type matrix, generic-secret keygen, random bound, GENERAL endianness

- Init key-type matrix (`Haskoki.Registry.KeyMatrix`, enforced in
  `checkKeyBinding` ahead of the usage check): HMAC→generic-secret,
  RSA→RSA, ECDSA→EC, ciphers→recipe key type, CMAC→AES/DES3.
  Wrong-typed keys surface `KEY_TYPE_INCONSISTENT`; unreviewed pairs
  and untyped legacy objects keep prior behavior. Targets the
  `test_mech_negative.py` cluster (14).
- `CKM_GENERIC_SECRET_KEY_GEN` (1–255 bytes, the ceiling is the
  one-byte `GenBytes` frame): planner + driver + both backends +
  `CKM_GENERIC_SECRET_KEY_GEN` behavior descriptor; catalog row
  flipped to tested (107 behavior rows, 105 C-surface rows) with
  regenerated projection, C catalog, and coverage. The consumer HMAC
  key and the HMAC engine legs now mint conformant generic keys; the
  ARIA legs import a typed `CKK_ARIA` key.
- Random bound + GENERAL endianness (see KAT lane status): the 4 GiB
  `C_GenerateRandom` crash and the 330 wycheproof-HMAC failures.
- Oracle reproof: fast r5 is 92 failed with 0 newly failing vs r3
  (12 `test_mech_negative.py` wrong-key-type cases fixed; an interim
  r4 run showed 5 HMAC regressions from matrix rows that admitted
  only `CKK_GENERIC_SECRET` — fixed by adding the per-digest
  `CKK_*_HMAC` types, digest-precise). Targeted KAT reruns:
  `test_generate_random_oversized_length_rejects_or_honors` passes
  (1/1, no crash), `test_wycheproof_hmac.py` passes 1732/1732
  (was 330 failed). Snapshots: `/tmp/pkcs11-fast-r5.json`,
  `/tmp/pkcs11-ws/out/targeted/`.

## Remaining fast-lane failures (r5: 92), by cluster

Ordered by count, with root cause and fixability as triaged from failure
records and the oracle sources at `/tmp/pkcs11-ws/pkcs11-check`:

- `test_mech_negative.py` (14): Init paths accept wrong-key-type keys
  (AES/ARIA/CAMELLIA encrypt, AES decrypt, CMAC/HMAC sign/verify). The
  oracle imports a wrong-secret-type key (generic where AES is required
  and vice versa) and expects rejection. Root cause: no
  mechanism↔key-type matrix in the Init planners. Top-priority follow-up; it needs
  `CKM_GENERIC_SECRET_KEY_GEN` first (HMAC-conformant keys cannot be
  minted today — our own consumer HMAC test uses an AES key). Includes 2
  HOTP cases that fail inside the oracle's own setup
  (`MechConfig.key_type` is `None` there) — oracle-side, not ours.
- `test_kdf.py` (8): HKDF parameter handling gaps; needs a focused pass.
- `test_operation_termination.py` (8): the oracle asserts a rejected
  single-part call (NULL args → `ARGUMENTS_BAD`) terminates the active
  operation; we leave it live. Spec-ambiguity: confirm against the
  standard text before changing the state machine.
- `test_crossverify.py` (7), `test_crossverify_extended.py` (4),
  `test_verify_signature.py` (4), `test_interop.py` (5): cross-checks
  against OpenSSL-side crypto; remainders past the ECDSA fix need
  per-case reads. (r3 fixed the `test_mech_sign.py` RSA KAT vectors.)
- `test_secret_key_value_len.py` (5): import/coherence edges; several
  trace to attribute coverage (see KAT). (r3 fixed the sibling import
  files: `test_ec_missing_params.py`, `test_ec_import_coherence.py`,
  `test_rsa_key_import.py` now pass.)
- `test_set_attribute.py` + `test_api_security.py` escalation cases +
  token-promotion/ro-session cases (~8 across files): `C_SetAttributeValue`
  is unimplemented (returns `FUNCTION_NOT_SUPPORTED`). Feature gap.
- `test_aead.py` (2): GCM roundtrip fails with `MECHANISM_INVALID` while
  other GCM units skip as unsupported — capability-reporting
  inconsistency, needs a focused session.
- `test_digest.py` (2): `C_DigestKey` unimplemented. Feature gap.
- Long tail (one-offs across ~20 files): attribute-enforcement edges
  (`CKA_COPYABLE` unsupported), multipart/message/codec edges, large
  objects, visibility, v3.0 session edges. Each needs its record read
  before it can be sized; none was sampled as a crash or hang.

## Skip census (r3: 3732 skipped)

Skips are capability-gated: the oracle probes support and skips what the
module does not advertise. The lane records distinct skip reasons per
unit (a reason inventory, not per-test attribution). Grouped:

- Unsupported keygen: RSA key-pair generation (~50 occurrences across
  spellings), DES3/DES, DH, generic-secret, ARIA/CAMELLIA keygen.
- Unsupported mechanisms: AES-GCM (11), AES key-wrap/KWP (~16), AES-CCM,
  RSA_X_509, DH, Concat/KDF helpers; capability-flag lacks (e.g. RSA_PKCS
  without encrypt).
- Unsupported storage: certificate objects (5).
- Destructive-gated (13): require an explicit destructive flag.
- Missing KAT vectors (3) and not-advertised entries: harness-side.

The census moves only when advertised support moves. Any skip whose
mechanism we later add must flip to run (pass/xfail/fail), never vanish.

## XFail notes (r3: 396)

Xfails are behavior-present/code-imprecise: the module refuses, but with
a neighboring return code (e.g. `MECHANISM_INVALID` where the oracle
prefers `KEY_TYPE_INCONSISTENT`; `ARGUMENTS_BAD` where it prefers
`MECHANISM_PARAM_INVALID`; `GENERAL_ERROR` where it prefers
`ENCRYPTED_DATA_LEN_RANGE`). Each is a small CKR-precision item; the
Init-matrix follow-up takes the largest share.

## KAT lane status

Pre-r3, the KAT lane reported 21133 failures, dominated by vector-key
import (`ATTRIBUTE_TYPE_INVALID` on component attributes). The r3
import slice made KAT execute: 111946 tests — 16808 passed,
436 failed, 0 crashed, 11860 xfailed, 82842 skipped
(`/tmp/pkcs11-kat-r3.json`). The 436 decompose exactly: the fast-104
(the KAT lane reruns the fast corpus) + 330 wycheproof-HMAC + 1 ECDSA
ACVP vector + 1 crash.

- wycheproof-HMAC (330, uniform 33/file × 10 digests, all `valid`):
  every truncated-tag vector failed `C_VerifyInit` with
  `ARGUMENTS_BAD`. Root cause: our `mac-general/1` codec decoded the
  `CK_MAC_GENERAL_PARAMS` length big-endian, but the wire shape is a
  native `CK_ULONG` (little-endian here), so every real truncated-tag
  init read a gigantic length and refused. Fixed (round 4): the codec
  is caller-native little-endian, matching `decodeULongLE`; the
  consumer passes a `CK_ULONG` instead of byte-array params.
- Crash (`test_generate_random_oversized_length_rejects_or_honors`):
  `C_GenerateRandom` with length `0x100000008` OOM-killed the child
  (SIGKILL): the backend materialized the full request in 1 MiB
  windows with no ceiling. Fixed (round 4): single requests past
  `generateRandomMaxBytes` (1 MiB, mirroring `seedRandomMaxBytes`)
  refuse with `DATA_LEN_RANGE` before any allocation, at both the FFI
  boundary and the backends; oversize `C_SeedRandom` inputs are likewise
  length-capped before the caller buffer is copied.
- Struct-params gap (next slice, recorded not fixed): probing shows
  real C structs are refused the same way — `CKM_SHA256_RSA_PKCS_PSS`
  with a native `CK_RSA_PKCS_PSS_PARAMS` gets `ARGUMENTS_BAD`, because
  the recipe codecs expect an internal big-endian triple-word shape no
  external caller produces. PSS/OAEP/ECDH/KDF need native struct
  decoders before those vectors can execute; the current KAT passes on
  those files ride sanctioned refusals, not execution.
- ACVP ECDH (1): untooled; triage with the struct-params slice.

## Method

Pre/post diffs compare recorded outcomes by node id. Records hold
interesting outcomes (fail/xfail/skip samples); unrecorded means passed
— valid only when the lane reports complete with zero child crashes
(true for r1, r2, r3). A post-fix failure whose pre-run outcome was pass
(or unrecorded) counts as a regression; r0→r1, r1→r2, and r1→r3 all show
zero. Crash counts come from the lane summary (`child_crash`), not
records. Results: `/tmp/pkcs11-ws/out/pkcs11-fast-results.json` (r0),
`/tmp/pkcs11-fast-r1.json` (r1),
`/tmp/pkcs11-ws/out/fast/pkcs11-fast-results.json` (r2, since overwritten
by the r3 run at the same lane path — snapshot future rounds aside
before re-running), `/tmp/pkcs11-fast-r3.json` (r3).
