# pkcs11-check oracle triage (local docker lanes)

External-oracle findings against the release bundle, from local docker runs
of `pkcs11-check` with fetched vectors (`bash /tmp/pkcs11-ws/run-lane.sh
fast|kat`; lane wrapper `scripts/ci-pkcs11-lane.sh`). Bundle:
`dist-release/haskoki-0.3.0.0` built by `scripts/make-release.sh` in the
pinned toolchain image. This note records what was found, what was fixed
with local proof, what remains, and what the oracle skips — per cluster,
not per test.

## Fast-lane results across fix rounds

Total collected varies by framework checkout (r11: 5780; r14: 5798;
r15: 5820; r18: 5840; r19: 5844; r20: 5864; r21: 5888; r22: 5910;
r23: 5910).
Summaries are authoritative;
the per-test records list interesting outcomes only (see Method).

| Round | Passed | Failed | XFailed | Skipped | Child crashes |
|---|---|---|---|---|---|
| r0 (pre-fix) | 1121 | 142 | 810 | 3689 | 3 |
| r1 (template bound + class defaulting) | 1504 | 133 | 400 | 3725 | 0 |
| r2 (ECDSA raw + wrap key-type gate) | 1507 | 130 | 400 | 3725 | 0 |
| r3 (key-import slice) | 1530 | 104 | 396 | 3732 | 0 |
| r4 (matrix, one HMAC-type short) | 1566 | 97 | 366 | 3733 | 0 |
| r5 (matrix + per-digest HMAC types) | 1576 | 92 | 362 | 3732 | 0 |
| r6 (HOTP matrix rows) | 1576 | 92 | 362 | 3732 | 0 |
| r7 (PSS/OAEP native structs + OAEP gate) | 1578 | 92 | 360 | 3732 | 0 |
| r8 (asymmetric rows skip block framing) | 1580 | 90 | 360 | 3732 | 0 |
| r9 (ECDH + SHA-KDF C arms) | 1744 | 92 | 367 | 3577 | 0 |
| r10 (SHA-KDF key-type gate) | 1756 | 81 | 366 | 3577 | 0 |
| r11 (termination + DigestKey) | 1769 | 71 | 365 | 3575 | 0 |
| r12 (T1 template attributes) | 2499 | 44 | 358 | 2879 | 0 |
| r13 (x509 cert-attr fix) | 2519 | 35 | 347 | 2879 | 0 |
| r14 (T2 RSA keygen) | 2783 | 29 | 397 | 2589 | 0 |
| r15 (T3 P-384/P-521 + T7 GCM) | 2839 | 25 | 398 | 2558 | 0 |
| r16 (T6 streaming cipher) | 2842 | 21 | 399 | 2558 | 0 |
| r17 (T6 + ECB decrypt chain fix) | 2843 | 21 | 398 | 2558 | 0 |
| r18 (pkcs11-check 0.2.1 oracle) | 2863 | 20 | 398 | 2559 | 0 |
| r19 (T5a/b/c/d + T8 RSA wrap) | 2874 | 2 | 387 | 2581 | 0 |
| r20 (EC_POINT stamp + GCM/ECDH fixes) | 2930 | 2 | 351 | 2581 | 0 |
| r21 (AES-CTR slice) | 2947 | 2 | 357 | 2582 | 0 |
| r22 (AES-CCM slice) | 2967 | 2 | 361 | 2580 | 0 |
| r23 (curves verdict precision) | 2985 | 2 | 350 | 2573 | 0 |

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
- r6 reproof for the HOTP matrix rows: byte-identical failing set to
  r5 (92 failed, 0 new, 0 fixed). The 2 HOTP `mech_negative` legs
  still die in oracle setup (`MechConfig.key_type is None`, never
  reaching the token). Snapshot: `/tmp/pkcs11-fast-r6.json`.
- r7 reproof for native PSS/OAEP structs + the OAEP cipher-shape
  gate: 92 failed with a 2-for-2 swap vs r6 — the 2 OAEP
  `mech_flags` callable legs fixed (OAEP is callable through the C
  surface now), 2 `oaep_parameter_fidelity` legs newly running (they
  were xfail while OAEP was uncallable) and failing on block
  framing. Snapshot: `/tmp/pkcs11-fast-r7.json`.
- r8 reproof for the asymmetric unframed bypass: 90 failed, 0 new —
  both `oaep_parameter_fidelity` legs fixed (encrypt-direction
  fidelity cross-verified against the oracle's own OAEP with
  SHA256/MGF1-SHA1/label, decrypt-direction correctness).
  Snapshot: `/tmp/pkcs11-fast-r8.json`.

## Round 5: derive slice (ECDH + SHA-KDF C arms)

Wired `C_DeriveKey` beyond HKDF: ECDH (native `CK_ECDH1_DERIVE_PARAMS`
decoder, opaque peer intake, base curve-width cap) and the SHA-KDF rows
(SHA1/224/256/384/512/512-224/512-256, SHA3-224/256/384/512) through the
C surface, with `planDerive` checking key-type before params (the
Init-matrix ordering) and the base handle resolving to
`KEY_HANDLE_INVALID` on unknown/invisible handles.

r8→r9 (90→92 failed, 1580→1744 passed): advertising ECDH/SHA-KDF derive
un-skipped ~155 oracle legs (skipped 3732→3577; total collected
5762→5780), which mostly pass. Cleared 9: the destroyed-base-handle leg
and all 8 SHA3-KDF produces-key/deterministic legs. Newly visible 11:
`test_registry_derive_wrong_key_type[SHA*]` — the SHA-KDF arms accepted
non-generic-secret bases (e.g. AES) because the key-type gate was
missing; fixed in round 6. `test_ckr_derive.py::test_key_type_inconsistent`
remains oracle-side: it needs `gen_rsa_keypair` (RSA keygen, honestly
unsupported → `MECHANISM_INVALID` in setup) before our ECDH arm — which
is model-pinned to refuse a non-EC base with `KEY_TYPE_INCONSISTENT`
— is ever reached.

## Round 6: derive fidelity (SHA-KDF key-type gate)

`planDerive` SHA-KDF arms now require a generic-secret base before
examining params; `resolveBase` reports the key-specific
`KEY_HANDLE_INVALID` (was `OBJECT_HANDLE_INVALID`) for unknown or
invisible base handles.

r9→r10 (92→81 failed, 1744→1756 passed): cleared exactly the 11
`test_registry_derive_wrong_key_type[SHA*]` legs, zero new failures.
No derive leg we can reach still fails.

## Round 7: termination, empty-query staging, C_DigestKey

Failed crypto calls now terminate the active op per the spec rule
(every error other than BUFFER_TOO_SMALL terminates; only the
successful length query keeps it): planner denies in the five
classic families clear the slot, FFI early ARGS_BAD refusals
terminate via `refuseArgsTerminate`, and the C NULL-argument guards
terminate through the new `haskoki_std_terminate_slot` export.
Size queries run the real `IntentNull` intent end to end
(`stageBytes` always stages, `retryStaged` re-reports), fixing
empty-output queries. `C_DigestKey` is routed (feeds the secret
value through the digest-update planner; contract 66→67 planned).

r10→r11 (81→71 failed, 1756→1769 passed): cleared exactly the 8
`test_operation_termination` NULL-arg legs and the 2 `test_digest`
DigestKey legs, zero new failures. The one-shot-over-buffered
termination change caused no oracle regressions.

Post-patch validation (runtime, base `1ee44df` vs patched `fcabf37`,
`consumer_termination` run against both modules): base fails all 27
termination/empty-recall legs (NULL-arg re-init and refused-one-shot
finals across digest/sign/verify/encrypt/decrypt, plus empty recall)
while every benign control leg passes on both revisions; patched
passes 77/77 with 0 failures. The digest/sign/verify legs are
root-cause variants the oracle never probes (it only exercises
cipher NULL-arg). KAT r5 independently confirms the slice at scale
(207→72 failed, zero new).

## Round 8: T1/T2/T3/T7 slices (r12–r15)

Four fix slices landed without per-round triage notes; r15 is the
first lane proving all of them together.

- r11→r12 (71→44 failed): T1 template attributes
  (`ALLOWED_MECHANISMS`/`COPYABLE`/`DESTROYABLE`, cert attrs,
  `C_SetAttributeValue`, `VALUE_LEN` coherence).
- r12→r13 (44→35 failed): x509 certificate-attribute fix.
- r13→r14 (35→29 failed): T2 RSA keygen (native EVP keygen +
  stamping + promotion) clears 12 legs; 6 RSA-wrap legs surface
  as new failures (T8).
- r14→r15 (29→25 failed, zero new): T3 P-384/P-521 keygen clears
  the 2 EC legs (first measured here); T7 AES-GCM clears the 2
  `test_aead` property legs. All 9 `test_aead` legs now
  pass-or-designed-skip (crossverify byte-exact vs Python
  `cryptography`, 96-bit tag fidelity honored, short-ciphertext
  exact codes, generated-IV legs skip on honest refusal); the 6
  GCM xfails sit at full AES-CBC parity (weak-tag
  `honest_deviation`, `ARGUMENTS_BAD`-vs-`PARAM_INVALID`,
  harness-side keygen). T4 message-API legs never materialized
  (the oracle skips clean `FUNCTION_NOT_SUPPORTED`).

## Remaining fast-lane failures (r23: 2), by cluster

Fully root-caused from failure records plus the oracle sources at
`/tmp/pkcs11-ws/pkcs11-check` (import recipes, negotiation, gates).
Slices ordered by leg count:

- Added in round 13 (r22→r23): curves verdict-precision slice
  (uncommitted at lane time; this turn). Three ECDSA verdict
  fixes in the OpenSSL 4 shim — SEC1 truncation of overlong
  raw inputs (PKCS#11 §2.3.1), point-at-infinity math mapped to
  mismatch (X9.62 §7.4.2 rejects; OpenSSL reports rc −1), and
  odd-length raw signatures answered as mismatch like
  malformed DER — plus a `MechParamInvalid` error category
  (backend→core→crypto→edge, `interpretError` → 0x71) wiring
  every ECDH peer fault to `CKR_MECHANISM_PARAM_INVALID`:
  plan-time shape/mismatch arms plus backend peer attribution
  via a new shim `HSK_OSSL4_ERR_BADPEER` code (bad base DER
  stays a bad key). Per-unit diff is fully attributed:
  +18 passed (`parameter_validation` +3 ECDH invalid-point
  legs now clean-reject, `ec_curves` +6, `ec_import_coherence`
  +3 skip→pass, `mech_negative` +2 CCM missing-params legs now
  clean-reject (committed CCM 7/8, first full-lane exposure —
  exactly the targeted reproof the r5 note predicted),
  `mech_sign` +5 with −4 skip/−1 xfail), −11 xfailed net. The
  `ec_curves` / `ec_import_coherence` / `mech_sign` skip→pass
  legs are first-fast-exposure of the committed curves
  capability (tasks 5–10 widened keygen and the 22-curve set
  after r22 ran); the xfail→pass legs are this slice's verdict
  precision (`parameter_validation` ECDH 0x71, `mech_sign`
  ECDSA verify precision). One pass→xfail:
  `capability_boundary::test_ec_above_max_is_refused` now
  performs secp160r1 keygen above the advertised max=0
  (benign over-performance xfail) — expected from committed
  task 5 ("keygen admits all 22 curves"), not this diff: r22
  ran before that commit. Same 2 HOTP external failures,
  zero crashes, zero xpass. (First r23 attempt ran without
  `PKCS11_CHECK_DATA_DIR` and under-collected 708
  data-dependent cases — limbo/attributes/search; the
  recorded r23 reran with the canonical data dir, total
  5910 = r22.)

- External (2, no spec-compliant code fix): the 2 HOTP
  `mech_negative` legs assert inside the oracle's static
  registry (`MechConfig.key_type is None` for HOTP; the assert
  text is byte-identical in r20b — the module is never called).
  (`eddsa_wrong_length` was fixed oracle-side in 0.2.1.)
- Added in round 12 (r21→r22): AES-CCM slice (recipe
  `e9c5eb0`, FFI `a0e7c59`, engine `c7e086e`, driver/catalog
  `18ea1aa`, cipher shape `7a1ef97`, key-type matrix
  `4f8d6da`: `ccm-params/1` image with `ulDataLen`, single-part
  CCM over OpenSSL 4.0.2 EVP, SP 800-38C widths, catalog
  108→109 rows). Per-unit diff is fully attributed, every
  changed unit CCM-related: +20 passed (`aead_short_ciphertext`
  +2, `ffi_length_boundary` +7, `parameter_validation` +1,
  `mech_encrypt` +2, `mech_flags` +4, `mech_negative` +4),
  +4 xfailed (2× CCM keygen-correctly-refused, 2× CCM
  missing-params expecting `MECHANISM_PARAM_INVALID` — fixed
  post-lane, see the KAT r5 note), −2 skipped net (`mech_probe`
  +3 "tested elsewhere", `mech_flags` +5 non-encrypt flags
  correctly unadvertised, security files −10 now running).
  Zero pass→fail, zero crashes, zero xpass; limbo stable at
  698 on the canonical data dir. The first r22 attempt carried
  2 extra failures (CCM wrong-key-type encrypt/decrypt: the
  key-type matrix had no CCM row yet); the matrix commit fixed
  them and migrated 15 setup-xfails to pass (r22→r22b is
  `mech_negative`-only: +17 passed, −2 failed, −15 xfailed).
- Added in round 11 (r20→r21): AES-CTR slice (`cf0a164`:
  `ctr-params/1` image for AES-128/192/256, big-endian counter
  chaining, 16-byte block-aligned streaming splits, NIST F.5
  KAT + all-split multipart probes + oracle `TestAESCTR` 5/5).
  Per-unit diff is fully attributed, every changed unit
  CTR-related: +17 passed (`aes_modes` +5, `mech_encrypt` +2,
  `mech_flags` +4, `mech_multipart` +1, `mech_negative` +4,
  `operation_termination` +1), +6 xfailed (newly exercised
  mechanism-conditional negatives, all expected-behavior),
  +1 skipped net (`mech_probe` +3 "tested elsewhere",
  `mech_flags` +5 non-encrypt flags correctly unadvertised,
  `aes_modes` −5 now running, UAF −2 skip→xfail). Zero
  pass→fail, zero crashes, zero xpass; limbo collection back
  at r20 levels on the canonical data dir (the r21a/b dip to
  678 was a stale `/tmp/p11data` limbo.json — 9786 cases vs
  9793 in `/tmp/pkcs11-ws/data`; all other provenance pins
  identical, rerun r21c byte-stable).
- Cleared in round 10 (r19→r20): EC keygen `CKA_EC_POINT`
  stamping (`71633ee`, prerequisite for the ECDH legs), the GCM
  AAD-length corruption (`d2d9d2c`: tc92 wrong answer plus the
  ACVP encrypt OOB-write crash), and the ECDH
  missing-`CKA_VALUE_LEN` default plus v3.2 tail truncation
  (`8ceaae7`). Passed +56, xfailed −36 (fix-spawned migrations
  from setup-xfail to run-and-pass; the only product delta is
  those three commits). Collection +20 r19→r20 is unattributed
  but bounded (failed unchanged at the same 2, lane complete).
  The first r20 attempt was discarded: a concurrent
  `make-release.sh` (from `release-evidence.sh`) replaced the
  bundle mid-lane and flaked one worker with a loader `OSError`;
  r20b is the clean rerun with no concurrent rebuild.
- Cleared in round 9 (r18→r19): T5 session/login (10: 3× RO
  session-object refusal, 2× public-creates-private, 3×
  context-login-without-op, 2× cross-session modify),
  stragglers (2: copy-to-private, oversized `CKA_VALUE_LEN`),
  T8 RSA wrap/unwrap (6: 5× wrap routes, OAEP error
  uniformity). T5a/b/c/d + T8 shipped in commits
  `589677f` (v1.5 engine) and `ebd150b` (RSA wrap end to
  end). `test_kdf` stays 0 failed.
- Cleared in round 8: T1 template attributes (27), x509 cert fix
  (9), T2 RSA keygen (12 cleared, 6 new T8 surfaced), T3 P-384
  (2), T7 GCM (2).

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

## KAT lane status (r5: 24230 passed / 72 failed / 82685 skipped)

r4→r5 (207→72 failed, +141 passed, zero new failures): the round-7
empty-query fix cleared all 125 predicted OAEP empty-message legs
plus 10 more. The remaining 72 are exactly the 71 fast-lane r11
failures (same node ids) plus one KAT-only leg,
`test_ecdh_key_agreement_basic[P-256]` ("P-256 EC keygen claimed
success but CKA_EC_POINT is missing" — EC keygen attribute
completeness, folds into the keygen slice). No KAT-only crypto
fidelity failures remain: every other KAT fail is one of the
triaged T1–T7/external slices above.

## KAT lane status (historical r4: 24089 passed / 207 failed)

r3→r4 (16808→24089 passed, 436→207 failed, 0 crashed): cleared 354,
including the random-bound crash fix, all SHA3-KDF legs, the OAEP
callability legs, and the key-type matrix legs. Newly visible 125,
all `test_wycheproof_rsa_oaep.py` valid vectors (18× tc1 across the
hash/mgf files + 107 `rsa_oaep_misc_test` edge vectors): every one
decrypts to an EMPTY message, and the size-query path returned OK
without writing the length and freed the slot (an empty output
"fits" a zero cap), so the recall failed NOT_INITIALIZED. Invalid
vectors all pass — refusals (ENCRYPTED_DATA_INVALID) are correct.

Root-caused with host-local single-vector repros and fixed after
r4: queries now run with the real `IntentNull` intent end to end
(`stageBytes` always stages on `IntentNull`, `retryStaged`
re-reports on re-query). The full OAEP file passes locally
post-fix (819 passed, 0 failed); KAT r5 will confirm lane-wide.

## KAT lane status (historical r3)

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

## Remaining fast-lane failures (r18: 20)

r17→r18 (same T6 bundle, oracle 0.2.0→0.2.1): `eddsa_wrong_length`
fixed oracle-side (the int-path gate no longer asserts `CKR_OK`
from `C_GetMechanismInfo`), zero new failures, +20 newly
collected passing tests. The 20: T5 session/login (10: 3× RO
session-object refusal, 2× public-creates-private, 3×
context-login-without-op, 2× cross-session modify), stragglers
(4: copy-to-private, oversized `CKA_VALUE_LEN`, 2× HOTP
oracle-registry asserts), T8 RSA wrap/unwrap (6: 5× wrap routes,
OAEP error uniformity). T5a (RO owner dimension) and T5b
(public/private gates) are implemented and passing in-suite
post-r18; lane reproof needs a bundle rebuild.

## KAT lane status (r6, curves verdict precision: COMPLETE)

112094 tests — 55457 passed, 2 failed, 0 crashed, 3565 xfailed,
53070 skipped (`/tmp/lane-out-kat-r6/pkcs11-kat-r6-results.json`;
`incomplete: false`), canonical data dir `/tmp/pkcs11-ws/data`,
clean-rebuild release. The only failures are the 2 external
HOTP registry asserts (same pair as every lane). Delta vs r5 is
fully attributed, +20830 passed / −1563 xfailed / −19267
skipped, zero pass→fail, zero crashes, zero xpass:

- `wycheproof_ecdsa`: +16380 passed, 1306→0 xfailed,
  −15074 skipped. Joint: the committed curves tasks
  un-skipped the weak/binary-curve legs (first KAT exposure —
  r5 predates tasks 5–10), and this slice's verdict precision
  (SEC1 truncation, infinity→mismatch, odd-sig→mismatch) made
  them pass-or-clean instead of xfail. Without this slice the
  un-skipped legs xfail — proven by the targeted r1 run
  (5016 ECDSA xfails on the same post-curves tree) and r3
  (0 xfailed).
- `wycheproof_ecdh`: +4356 passed, 170→0 xfailed, −4186
  skipped. Joint, same shape: curves tasks un-skipped, this
  slice's `MechParamInvalid` category (plan-time arms +
  backend peer attribution) made every invalid leg
  clean-reject 0x71 (targeted r1: 647 xfails → r3: 0).
- `wycheproof_aes`: +66 passed, 66→0 xfailed. Committed CCM
  7/8 (`1b2614c`, first KAT exposure — it landed after r5
  ran): the bad-CCM-params legs now clean-reject 0x71,
  exactly the targeted reproof the r5 note recorded. Not
  this diff.
- `wycheproof` umbrella: +10 passed, 16→6 xfailed. This
  slice's ECDSA precision fixed all 10 P-256/P-384 verify
  negatives; the 6 remaining are AES-GCM (untouched area).
- Fast-lane units inside KAT repeat the fast r23 deltas
  exactly (`parameter_validation` +3 ECDH 0x71,
  `mech_negative` +2 CCM, `mech_sign`, `ec_curves`,
  `ec_import_coherence`, `capability_boundary` +1 benign
  over-performance xfail) — cross-lane consistency check
  passes.

Remaining 3565 xfails + 53070 skips are the ranked slices
still ahead (CTS, CFB/OFB, WRAP/KWP, XTS, DSA, EdDSA, PQC,
legacy, TLS/KDF — same taxonomy as r5, EC rows now zero).

## KAT lane status (historical r5, CCM bundle: COMPLETE)

112094 tests — 34627 passed, 2 failed, 0 crashed, 5128 xfailed,
72337 skipped (`/tmp/lane-kat-r5.json`; `incomplete: false`),
canonical data dir `/tmp/pkcs11-ws/data`. The only failures are
the 2 external HOTP registry asserts (same pair as the fast
lane). Delta vs r3/r4 is fully attributed, every changed unit
CCM-related: +8816 passed / +158 xfailed / −8952 skipped
(`acvp/aes/test_ccm.py`: 8398 skipped → 8310 passed + 88
xfailed; `wycheproof_aes`: +486 passed, 66 xfailed;
`aead_short_ciphertext` +2, `ffi_length_boundary` +7,
`parameter_validation` +1, `mech_encrypt` +2, `mech_flags` +4
passed; `mech_negative` +4 passed +4 xfailed; `mech_probe` +3
"tested elsewhere"). Zero pass→fail, zero crashes, zero xpass.

Post-lane fix (same source tree, targeted reproof): the KAT r5
run exposed a real spec deviation — out-of-range CCM nonces
and tag widths, and CCM inits with missing params, were refused
with `CKR_ARGUMENTS_BAD`, while OASIS §2.20.2 pins
`CKR_MECHANISM_PARAM_INVALID` (the core `ReturnCode` type never
modeled that code). The fix adds the code (`0x71`, header-pinned,
stored-name round-trip, `DenyBadParams` category) and points the
CCM init arm at it; every other arm keeps its historical code.
Rerunning the 9 CCM-attributable units post-fix: wycheproof 66
xfail→pass, `mech_negative` 2 xfail→pass (the missing-params
legs), ACVP CCM unchanged at 8310/88 (the 88 ECMA 16-byte-nonce
legs stay honest xfails — a clean reject whatever the code),
all other units byte-identical, same 2 HOTP failures, zero
xpass. No full-lane rerun: the change is provably scoped (one
CCM arm plus an additive code no other producer emits), and the
9 rerun units are exactly the CCM-exercising ones.

## KAT lane status (historical r3, CTR bundle)

112072 tests — 25811 passed, 2 failed, 0 crashed, 4970 xfailed,
81289 skipped (`/tmp/pkcs11-ws/out/kat-r3-results.json`;
`incomplete: false`), canonical data dir
`/tmp/pkcs11-ws/data`. The only failures are the 2 external HOTP
registry asserts (same pair as the fast lane). Delta vs r2 is
fully attributed: +17 passed / +8 xfailed / +1 skipped-net from
the CTR slice (same units as fast r21, plus 2
`output_length_truncation` skip→xfail mechanism-conditional
legs), and +20 limbo passes that are a data-dir artifact —
KAT-r2 ran the stale `/tmp/p11data` limbo.json (9786 cases) while
fast r20 and KAT-r3 use the canonical fetch (9793 cases); r2
normalized to canonical data would read 25794 passed.
Zero pass→fail, zero crashes, zero xpass.
r4 reruns the KAT lane on the post-gates rebuild of the same
source and is byte-identical to r3 (25811/2, same HOTP pair),
closing the evidence chain on the shipped bundle; likewise fast
r21d matches r21c exactly.

## KAT lane status (historical r2, fixed bundle: COMPLETE)

112028 tests — 25774 passed, 2 failed, 0 crashed, 4962 xfailed,
81290 skipped (`/tmp/pkcs11-ws/out/kat-r2-results.json`;
`incomplete: false`). The only failures are the 2 external HOTP
registry asserts (same pair as the fast lane). Cleared since the
T8 reproof (25654/6 + 10 crashed + 220 crash-limited):
Wycheproof AES-GCM tc92 and the 10 ACVP GCM-encrypt SIGABRTs plus
their 220 crash-limited follow-ons (one root cause: the AAD
`EVP_*Update` clobbered the shared output-length accumulator —
`d2d9d2c`), and the 3 ECDH basic legs (missing-`CKA_VALUE_LEN`
now defaults to the full secret per v3.2 — `8ceaae7`, on top of
the `CKA_EC_POINT` stamping prerequisite `71633ee`).

## KAT lane status (historical: 0.2.1 vectors, T6 bundle, incomplete)

112034 tests — 25635 passed, 24 failed, 10 crashed, 5027
xfailed, 81118 skipped (`/tmp/pkcs11-kat-021.json`). The lane is
INCOMPLETE (`crash_limited: 220`): the 10 ACVP AES-GCM encrypt
crashes (tc1–tc10, `free(): invalid size` at teardown finalize)
trip the crash limiter and cut the run short. The 24 failed are
exactly the 20 fast legs plus 4 KAT-only: ECDH keygen
`CKA_EC_POINT` incompleteness on P-256/P-384/P-521 (3) and
wycheproof AES-GCM decrypt KAT tc92 wrong answer (1). The GCM
crash (heap corruption) is top severity: it blocks full-lane
proof independently of every leg count.

## Full-lane skip census (KAT 0.2.1): the servable gap

81,118 skipped; 30,490 hide behind 18 whole-file skips. Engine
column is the pinned OpenSSL 4.0.2 default provider (enumerated
from the toolchain image); haskoki column is the 107-row
real-tested catalog.

Whole-file skips by hidden test count: ACVP AES-CCM 8398,
CTS 7500, OFB/CFB8/CFB128/CFB1 ~2140 each, XTS 1200;
wycheproof DSA 1956, ML-DSA 631+220(+45 hash-ML-DSA, 42
hash-SLH-DSA), ChaCha 325, Ed25519 238; CCTV Ed25519 914,
ML-DSA 449; HKDF-data-KAT 1, EdDSA-encoding 1.

Servable (engine has it, haskoki doesn't), by volume: AES
CTR/CFB1/CFB8/CFB128/OFB/CCM/XTS/CTS cipher modes (~24k
hidden tests); AES key-wrap/KWP (wrap family 0 tested);
symmetric keygens ARIA/CAMELLIA/DES3 (random-bytes pattern,
same as AES keygen); ML-DSA-44/65/87 sign+keygen
(PQC 0 tested); Ed25519 (keygen+sign/verify, CKM_EDDSA
unadvertised); DH keypair; DSA keygen/sign/verify;
ChaCha20-Poly1305; RSA_X_509 + the `CKF_ENCRYPT` flag on
RSA_PKCS (currently SIGN/VERIFY only); KMAC/SLH-DSA rows to
confirm. Investigate HKDF-data-KAT and ML-KEM skip reasons
(both partially served — may be cheap).

Honest skips (no engine support, stay skipped): RC2/RC4,
Blowfish, CAST, IDEA, SEED, GOST, Salsa20, WTLS/KEA/FORTEZZA,
CMS/PBA/LYNKS/FASTHASH, HSS/XMSS stateful, SSL3 KDFs,
message-mode CKF flags (T4 skips clean), x509-limbo
(certificate objects unserved), v2.40-only legs. Destructive
tests (13) need the explicit flag. Counts shift after the GCM
crash fix completes the lane.
