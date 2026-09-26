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
r23: 5910; r24: 5934; r25: 6030).
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
| r24 (AES-CTS slice) | 2998 | 2 | 354 | 2580 | 0 |
| r25 (CFB/OFB slice + C_SessionCancel) | 3055 | 2 | 370 | 2603 | 0 |

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

## Round 9: CTS + CFB/OFB slices with C_SessionCancel (r24–r25)

- r23→r24 (2985→2998 passed, zero new failures): AES-CTS slice
  (commit 5497650; manual CBC-CS1 shim, 12 ACVP legs).
- r24→r25 (2998→3055 passed, +16 xfailed, zero pass→fail, zero
  new failures): AES CFB1/CFB8/CFB128/OFB slice plus the real
  C_SessionCancel it forced. Per-unit diff fully attributed:
  `test_aes_modes` +6, `test_mech_encrypt` +7, `test_mech_flags`
  +16, `test_mech_multipart` +4, `test_mech_negative` +16 passed
  / +16 xfailed (CFB/OFB negative legs), `test_mech_probe` +12
  skipped (new mechanism probes), `test_operation_termination`
  +4 (cancel now exercises termination paths),
  `test_v30_session` +3 pass / −3 skip and `test_ckr_v30_raw`
  +1 / −1 (C_SessionCancel legs now run instead of skipping
  on `FUNCTION_NOT_SUPPORTED`). Same 2 HOTP external
  failures, confirmed by test id
  (`TestWrongKeyType::test_registry_{sign,verify}_wrong_key_type[HOTP]`).
- Targeted CFB/OFB r1→r2 (same 13 files): r1 exposed 12 MCT
  failures (6 CFB8 + 6 OFB, CKR_OPERATION_ACTIVE) because the
  MCT fallback's C_SessionCancel hit the generated stub; r2
  with the real cancel shows CFB8/OFB 2144/2144 pass and zero
  MCT failures
  (`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-cfb-ofb-r2.json`).

## Round 10: AES WRAP/KWP slice with the unwrap-confusion fix (r25–r27)

- r25→r26 (3055→3116 passed, +1 failure): AES Key Wrap / KWP
  slice (provider AES-WRAP/WRAP-PAD, dual encrypt+wrap surface,
  119 behavior rows). Per-unit diff fully attributed:
  `test_error_path_kwp` +16 pass / +26 xfail (newly collected
  KWP error-path matrix), `test_ckr_wrap` +5 / −6 skip+1 xfail,
  `test_mech_wrap` +3, `test_mech_negative` +4 pass / +18 xfail
  (wrap negative legs), `test_mech_flags` +12 pass (new WRAP
  flag probes), `test_mech_probe` +9 skipped (new mechanism
  probes), plus skip→pass first-exposures in `test_cve_regression`
  (+2), `test_key_lifecycle` (+2), `test_rsa_key_wrapping` (+3),
  `test_api_security`, `test_handle_reuse`,
  `test_public_session_private_creation`,
  `test_scalar_attr_length_extended`, `test_keymgmt`,
  `test_mech_lifecycle`, `test_metamorphic` (+1 each),
  `test_authenticated_wrap` +1 (CBC auth-wrap leg now runs),
  `test_unwrap_reimport` +1, `test_aes_keywrap_pad_overflow` +1,
  `test_ckr_raw_buffer` +1 pass / −1 xfail, and
  `test_ro_session_restrictions` +2 xfail. The +1 failure was
  `test_tookan.py::TestKeyTypeConfusionOnUnwrap::test_unwrap_aes_as_des3_rejected`,
  newly collected (was skip): the unwrap commit never measured
  answered material against the template key type, so a 16-byte
  KW blob minted a live CKK_DES3 key.
- r26→r27 (3116→3117 passed, failure cleared, zero pass→fail,
  zero xpass): the shared unwrap-commit fix (`publishUnwrap`
  in KeyManagement.hs: AES takes 16/24/32 bytes, DES3 takes 24,
  anything else any length; mismatch refuses
  CKR_TEMPLATE_INCONSISTENT publishing nothing), pinned by
  KeyManagementSpec caseUnwrapKeyTypeLength (16-as-DES3 refuses,
  24-as-DES3 commits). `test_tookan` 6→7 passed. Same 2 HOTP
  external failures, confirmed by test id
  (`TestWrongKeyType::test_registry_{sign,verify}_wrong_key_type[HOTP]`).
- Targeted wrap r1 (8 files, passing on the first run): 7230 passed, 0
  failed, 0 xpass — `test_wrap.py` 7200/7200 ACVP legs,
  `test_mech_wrap` 6, `test_error_path_kwp` 16 pass + 26
  framework-xfail holds, `test_aes_keywrap_pad_overflow` 1,
  `test_unwrap_reimport` 1 pass + 1 skip, `test_aead_wrap_outputs`
  2 skips (non-CBC AEAD-wrap setups), `test_authenticated_wrap`
  1 pass + 12 skips (ECDH-composition/v3.2-interface setups),
  `test_ckr_wrap` 5 pass + 1 skip + 1 xfail
  (`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-wrap-r1.json`).

## Round 11: AES XTS slice (r28)

- r27→r28 (3117→3125 passed, +8 pass / +14 skip / +2 xfail,
  zero pass→fail, zero xpass, same 2 HOTP external failures
  confirmed by test id): AES-XTS slice (provider AES-128/256-XTS
  one-shot over 16-byte tweaks, 120 behavior rows). Per-unit
  diff fully attributed: `parameter_validation` +1 pass / −1
  skip (XTS param leg now runs), `test_mech_encrypt` +1 / +1
  (single-part passes; multipart-XTS setup skips — updates
  buffer to final, unexercised), `test_mech_flags` +4 / +5
  (ENCRYPT/DECRYPT probes pass), `test_mech_multipart` +1
  skip, `test_mech_negative` +2 pass / +4 skip / +2 xfail (the
  xfails are the AES_XTS registry without-flag legs, self-held:
  XTS keygen honestly absent, `CKM_AES_XTS_KEY_GEN`
  catalog-only), `test_mech_probe` +3 skipped,
  `test_operation_termination` +1 skip
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r28-results.json`).
- Targeted XTS r1 (passing on the first run): 1200 collected —
  336 passed, 0 failed, 0 xpass, 864 skipped; every skip is a
  bit-level ACVP vector (non-byte-aligned payloadLen /
  dataUnitLen, inexpressible in PKCS#11 byte strings), none a
  Haskoki gap
  (`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-xts-r1.json`).

## Round 12: DSA slice (r29/r30 + KAT r11/r12)

- r28→r29 (3125→3169 passed, +44 pass / +1 xfail / +239 skip,
  zero pass→fail, zero xpass, same 2 HOTP external failures
  confirmed by test id): DSA slice (raw + 9 prehash sign rows
  over provider DSA, keypair gen from explicit domain params,
  parameter gen to domain-param objects, 132 behavior rows).
  Per-unit diff fully attributed: `test_mech_flags` +44 pass /
  +64 skip (new DSA flag/size probes pass; absence probes
  skip), `test_field_size_boundary` +1 xfail / −1 skip (the DSA
  prime-bits probe now runs and xfails on P11C-002 — Haskoki
  answers the spec-correct CKR_TEMPLATE_INCONSISTENT but the
  framework's `_KEY_SIZE_REJECT_RVS` tuple carries wrong numeric
  codes, so no provider-side code can pass), `test_mech_probe`
  +36 skip, `test_mech_negative` +80 skip, `test_mech_sign` +30
  skip, `test_mech_multipart` +18 skip, `test_mech_attribute` +8
  skip, `test_mech_keygen` +4 skip — all new-leg skips are the
  framework's domain-params provisioning gate (`gen_keypair_for_mech`
  skips DSA/DH as "requires external domain parameters"), none
  a Haskoki gap
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r29-results.json`).
- Targeted DSA r1 (passing on the first run): 2040 collected —
  690 passed, 0 failed, 0 xpass; `test_dsa_complete.py` 74 pass
  + 3 skips (the skips are the unadvertised FIPS seed-variant
  gates — honest catalog-only), `test_wycheproof_dsa.py` 613
  pass + 1343 skips (duplicate-vector dedup), 3 xfails all in
  `test_field_size_boundary.py` (RSA/DSA/AES probes in the same
  P11C-002 bucket — RSA/AES pre-date the slice)
  (`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-dsa-r1.json`).
- KAT r11 (first DSA run): 75365 passed, 3 failed — the 2 known
  HOTP externals plus a new real finding,
  `test_sign.py::TestDSASignature::test_dsa_generate_and_sign`
  (minimal keygen templates — no usage flags — then sign:
  Haskoki refused `CKR_KEY_FUNCTION_NOT_PERMITTED`). Root cause:
  Haskoki treated absent usage flags as refused on generated
  keys; the oracle (and SoftHSM/NSS generation behavior)
  requires minimal templates to mint usable keys. Fix (same
  slice): `checkKeyTemplate` now defaults absent usage flags
  TRUE, scoped by class (public keys default the public
  operations, private/secret the full set, non-key classes
  none) and skipping rule-forbidden flags (AES forbids the
  encapsulate pair — a defaulted forbidden flag would poison
  detached rejoin, which replays stored templates). Explicit
  FALSE still refuses; creation (`C_CreateObject`) keeps
  absent-means-false. Migrated the in-repo pins of the old
  contract to explicit-false templates (2 wrap legs, 1 init
  policy pin, 2 C consumer legs). Proof: targeted
  `test_sign.py` r2 18/18, fast r30 identical to r29 (3169/2/419
  — same HOTP ids, zero drift from the behavior change), KAT r12
  below.
- Follow-up (pre-existing, not introduced by the slice):
  `keyTypeCompatible` does not separate public/private key
  direction, so a public key explicitly marked `CKA_SIGN=true`
  passes init (crypto fails later). Filed for a hardening slice;
  no oracle leg covers it.

## Round 13: EdDSA slice (fast r31/r32 + KAT r13/r14)

- r30→r31 (NULL-accepting build, superseded): 2 new
  failures,
  `test_mech_negative.py::TestBadParameters::test_registry_
  sign|verify_missing_required_param[EDDSA]` (oracle
  registry marks `CKM_EDDSA` `param_required`; NULL must
  refuse with exactly `CKR_MECHANISM_PARAM_INVALID`, the
  module answered `CKR_OK`) plus 50 collateral xfails: the
  accepted NULL init left a stale sign op on the shared
  session and every later sign/verify leg saw
  `CKR_OPERATION_ACTIVE`. Root cause: the slice first read
  the KAT drivers' null-first probe order as a NULL
  requirement; the drivers fall back to the explicit pure
  struct on `PARAM_INVALID`/`ARGUMENTS_BAD`, and the
  oracle's own happy-path legs always send the struct.
  Fix (same slice): the struct is required — recipe
  validity is pure-explicit-only, `checkMechParams`
  refuses empty with `PARAM_INVALID` exactly, non-pure
  keeps the sibling `ARGUMENTS_BAD` (134 behavior rows).
- Targeted EdDSA r1/r2 (post-fix build): `test_eddsa.py`
  12 pass + 3 xfail, encoding 1 pass; KAT r2 (wycheproof
  + CCTV + ACVP + eddsa) 1092 pass, 0 failed, 100 xfailed,
  4 skipped — the profile fallback to `(raw, explicit)`
  is transparent
  (`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-eddsa-kat-r2.json`).
- r30→r32 (3169→3203 passed, +34 / +6 xfail / +3 skip,
  same 2 HOTP externals confirmed by test id, zero
  pass→fail): `test_eddsa` 15 skips resolve (12 pass + 3
  xfail), encoding 1 pass, `test_mech_negative` +4 pass
  (the EDDSA missing/malformed legs), `test_mech_flags`
  +6 pass, `test_mech_sign` +2 pass / +1 xfail,
  `test_mech_attribute` +3 pass / +1 xfail,
  `test_mech_multipart` +2 pass, `test_mech_keygen` +1
  pass / +1 xfail, `test_ffi_length_boundary` +3 pass
  (EdDSA null-context + length-boundary probes: no crash,
  honest refusal), `test_mech_probe` +6 skip
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r32-results.json`).
- KAT r13 (first EdDSA run): 75366→76480 passed (+1114),
  same 2 HOTP, +103 xfail — of which 87 wycheproof Ed448
  + 10 ACVP Ed448 legs xfailed with `CKR_GENERAL_ERROR`
  while every Ed25519 leg passed and engine-level Ed448
  roundtrips passed. Root cause (real slice bug):
  production resolves every stored key as `KeyBytes`
  (`stdResolver`) but the driver curve sniff matched
  `KeyDer` only, so every production Ed448 op
  misdispatched as Ed25519 and the shim's base-id check
  refused with BADKEY. (ECDSA survives the same shape:
  its shim takes no curve name — the provider reads the
  curve off the key DER.) Fix (same slice): sniff both
  constructors, with committed `KeyBytes`-carrying-DER
  legs in RecipeEddsaSpec. Proof: targeted KAT r3
  1192/1196, 0 failed, 0 xfailed (4 pre-existing ACVP
  config skips).
- KAT r14: +101 pass / −101 xfail vs r13 (wycheproof
  238/238, ACVP 25 pass, `test_eddsa` 15/15,
  `test_mech_sign` +1), same 2 HOTP externals by id,
  zero drift
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r14-results.json`).
- Standing notes: EdDSA wrong-length verify answers
  `CKR_SIGNATURE_INVALID`, matching the module-global
  stance (RSA/ECDSA/HMAC xfail the oracle's
  `LEN_RANGE` preference identically — a split would be
  cross-cutting); the `test_ckr_verify` EdDSA leg skips
  (NULL refused → skip path); pre-existing
  `consumer_session_cancel` slot-0 hardcode fixed in
  passing (the daemon remaps backend slot 0 to virtual
  slot 1 — parity could never pass with a hardcoded 0);
  history-codes net −10 hits (the version-table locals
  renamed, zero new).

## Round 14: ML-DSA slice (fast r33 + KAT r15)

- r32→r33 (3203→3240 passed, +37 / −2 xfail / +8 skip,
  same 2 HOTP externals confirmed by test id, zero
  pass→fail): `test_pqc_sign` 13 pass (the ML-DSA legs
  resolve), `test_mldsa_missing_param_set` 1 pass
  (param-less import refuses clean), `test_mech_flags`
  +6 pass, `test_ckr_keygen` +4 pass,
  `test_mech_attribute` +3 pass / +1 xfail,
  `test_mech_sign` +3 pass, `test_mech_multipart` +2
  pass, `test_mech_keygen` +1 pass / +1 xfail,
  `test_ffi_length_boundary` +1 pass (no crash, honest
  refusal), `test_mech_negative` +8 skip (new ML-DSA
  negative legs skip — the KAT drivers' null-first
  probes take the skip path since NULL serves pure;
  no failure), `test_mech_probe` +6 skip
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r33-results.json`).
- `test_eddsa` 15/15 (the 3 Ed448 xfails from r32
  resolve to pass): first fast lane on a build
  carrying the slice-8 `KeyBytes` sniff fix — r32 ran
  before that fix landed, so its Ed448 legs xfailed
  with `GENERAL_ERROR`; no EdDSA-path change in this
  slice.
- KAT r15: +1540 pass / +93 xfail / −1590 skip vs r14
  (wycheproof `mldsa` 616 pass, `mldsa_context` 9 pass,
  `mldsa_sign` 205 pass, CCTV 449/449, ACVP 228 pass),
  same 2 HOTP externals by id, zero drift
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r15-results.json`).
  New xfails, all root-caused: 70 ACVP prehash legs
  (`CKR_MECHANISM_INVALID` — the `hash_alg`-missing
  →`pure` fallback defeats the driver's own skip
  gate, so unadvertised `HASH_*` rows refuse honestly
  instead of skipping); 15 wycheproof overlong-context
  legs (`CKR_ARGUMENTS_BAD` at init — the module
  refuses 256-byte contexts at the recipe gate rather
  than attempting verify, the EdDSA-prehash
  precedent; the oracle's clean set admits only
  `SIGNATURE_*` for verify negatives); 6
  `InvalidPrivateKey` legs (`CKR_GENERAL_ERROR` —
  width-correct but lattice-invalid keys import,
  since coefficients are uncheckable without lattice
  math, and the provider decode fails at sign;
  runtime key failure is `GENERAL_ERROR` module-wide
  for every family).
- Targeted ML-DSA r1: 1521 pass, 0 failed, 91 xfailed
  (exactly the 70 + 15 + 6 clusters above), 146
  skipped
  (`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-mldsa-r1.json`).
- Standing notes: ML-DSA wrong-length verify answers
  `CKR_SIGNATURE_INVALID`, matching the module-global
  stance; ML-DSA keygen without `CKA_PARAMETER_SET`
  defaults to 65 (the KEM precedent — the oracle's
  missing-set probe covers import only, where the
  module refuses `TEMPLATE_INCOMPLETE`); keygen
  defaulting is visible on the published objects via
  the stamped set.

## Round 15: ML-KEM slice (fast r33→r35 + KAT r15→r16)

- r33→r35 (3240→3294 passed, +54 / +5 xfail /
  −29 skip, same 2 HOTP externals confirmed by test
  id, zero pass→fail): `test_kem` 0/29-skip →
  24 pass / 2 skip / 3 xfail (the KEM legs
  resolve), `test_ckr_kem` 0/4-skip → 4 pass,
  `test_mech_kem` 0/2-skip → 2 pass,
  `test_arithmetic_overflow` +6 pass / −6 skip,
  `test_ckr_keygen` +4 pass / −4 skip,
  `test_ckr_v32_raw` +4 pass / −4 skip,
  `test_mech_attribute` +3 pass / +1 xfail,
  `test_mech_flags` +4 pass / +14 skip,
  `test_key_usage_policy` +2 pass / −2 skip,
  `test_mech_keygen` +1 pass / +1 xfail,
  `test_mech_probe` +6 skip
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r35-results.json`).
- r34 ran on a stale bundle (built 19:40, before the
  final `Kem.hs` verdict edit at 20:19); r35 is the
  same tree on a fresh bundle and moves exactly
  `test_kem` 21→24 pass / 6→3 xfail. The 3 flips:
  `test_decapsulate_extractability_flags` passes,
  the `CKA_VALUE`-injection negative now refuses
  `CKR_TEMPLATE_INCONSISTENT` (an expected code),
  and the short-ciphertext negative now refuses
  `CKR_ENCRYPTED_DATA_LEN_RANGE` (an expected
  code).
- Remaining `test_kem` xfails (3), all root-caused:
  AES-128 / AES-16 / AES-24 encapsulate legs
  refuse `CKR_TEMPLATE_INCONSISTENT` — the module
  derives 32-byte secrets only (generic-secret or
  AES-256), so short-AES derive is unserved and
  refuses honestly; the oracle accepts the refusal.
  The 2 skips are parameter-set negotiation (the
  module sits on the 1024 set, ct_len 1088).
- Remaining new xfails (2), both the module-global
  `CKA_LOCAL`-on-public cluster: `test_mech_attribute`
  and `test_mech_keygen` each gain one
  `ML_KEM_KEY_PAIR_GEN` leg (`CKA_LOCAL on public:
  attribute unavailable`, same as every family).
  New skips are honest gates: +14 `test_mech_flags`
  (ML-KEM × 7 unadvertised `CKF_*` legs),
  +6 `test_mech_probe` (registered, tested
  elsewhere).
- KAT r15→r16: +216 pass / +14 xfail / −200 skip
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r16-results.json`).
  KAT-only movers: `test_acvp_mlkem` 0/180-skip →
  108 pass / 72 skip (skips are duplicate KeyGen
  inputs, deduped by design),
  `test_wycheproof_mlkem` 0/27-skip → 21 pass /
  6 xfail, `test_wycheproof_mlkem_encaps_modulus`
  0/36-skip → 36 pass; the fast files move as
  above. The 6 wycheproof xfails are the
  tc6/tc7 invalid decaps vectors per set, refused
  `CKR_GENERAL_ERROR` — runtime provider-decode
  failure is `GENERAL_ERROR` module-wide for every
  family (the ML-DSA `InvalidPrivateKey`
  precedent); the oracle accepts the refusal.
- r16 ran on the stale 19:40 bundle; the only
  post-bundle behavioral edit is `Kem.hs`
  (spec + consumer sources are test-only), and
  targeted r4 re-verified all 6 `Kem.hs`-reachable
  files on the fresh bundle (195 pass, 0 failed,
  9 xfailed, 74 skipped —
  `/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-kem-r4.json`),
  with fast r35 empirically confirming no other
  file moves. Current-code KAT is therefore r16
  plus the same 3 `test_kem` flips (78340 pass /
  3993 xfail); the 2 failures stay the known HOTP
  externals by id.

## Round 16: SLH-DSA slice (fast r35→r36 + KAT r16→r17)

- r35→r36 (3294→3316 passed, +22 / +2 xfail /
  +19 skip, same 2 HOTP externals confirmed by test
  id, zero pass→fail): `test_pqc_sign` 13/8-skip →
  21 pass / 0 skip (the 8 SLH legs resolve),
  `test_mech_sign` +2 pass / +1 skip,
  `test_mech_multipart` +2 pass,
  `test_mech_flags` +6 pass / +12 skip,
  `test_mech_attribute` +3 pass / +1 xfail,
  `test_mech_keygen` +1 pass / +1 xfail,
  `test_mech_negative` +8 skip,
  `test_mech_probe` +6 skip
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r36-results.json`).
- The 2 new xfails are the module-global
  `CKA_LOCAL`-on-public cluster:
  `test_local_flag_on_generated_key[SLH_DSA_KEY_PAIR_GEN]`
  and `test_local_flag[SLH_DSA_KEY_PAIR_GEN]`
  (`CKA_LOCAL on public: attribute unavailable`,
  same as every family). New skips are honest
  gates: +12 `test_mech_flags` (SLH × 6
  unadvertised `CKF_*` legs per mechanism),
  +8 `test_mech_negative`, +6 `test_mech_probe`
  (registered, tested elsewhere), +1
  `test_mech_sign`.
- KAT r16→r17: +103 pass / +6 fail / −1 xfail /
  −65 skip
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r17-results.json`).
  KAT-only mover: `test_acvp_slhdsa` 0/84-skip →
  78 pass / 6 fail / 0 skip; the 6 failures are
  P11C-003 (context-bound ACVP vectors the harness
  verifies under pure params — tc2/tc87/tc113/
  tc143/tc284/tc368, confirmed by id identical to
  the targeted run), never module behavior. The
  8 failures are exactly 6 P11C-003 + 2 HOTP
  externals by id; zero pass→fail.
- r17 also lands the 3 `test_kem` flips predicted
  in round 15 (`test_kem` 21→24 pass / 6→3 xfail),
  because r17 runs on a fresh bundle carrying the
  9b `Kem.hs` fix (r16 ran stale). Pass arithmetic
  closes exactly: +103 = 78 SLH + 3 KEM + 22
  fast; xfail −1 = −3 KEM + 2 SLH `CKA_LOCAL`;
  skip −65 = −84 SLH − 8 pqc + 27 fast.
- Targeted-slhdsa-r1 on the same fresh bundle:
  147 tests, 99 pass / 6 fail (P11C-003 by id) /
  42 skip (`test_pqc_sign` 21/0/0,
  `test_acvp_slhdsa` 78/6/0, `test_hash_slh_dsa`
  0/0/42 — the prehash skips are catalog-only by
  design;
  `/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-slhdsa-r1.json`).
  All lanes ran on one fresh bundle built from the
  current tree; only docs and the parity script
  (test-only, ships no bundle bytes) were edited
  afterwards, so no stale-bundle re-verify is
  needed this round.

## Round 17: DES3-MAC + TLS-PRF slices (fast r36→r37→r38 + KAT r17→r18)

- r37 (first 10a+10b bundle: 3305 passed / 16 failed /
  509 xfailed / 2824 skipped; summary from lane output,
  file not preserved): 14 fresh failures, all DES3. 12
  `test_des` + 1 `test_cve_regression::test_wrap_3des_key`
  share one root — `C_GenerateKey(CKM_DES3_KEY_GEN)` with
  `{CKA_TOKEN}` only returns `CKR_TEMPLATE_INCOMPLETE`
  (10a required `CKA_VALUE_LEN`; fixed-size keygen takes the
  headline default instead). 1
  `test_mech_negative::test_registry_verify_wrong_key_type[DES3_MAC]`
  — verify with a wrong-typed key returned `CKR_OK` (10a never
  added the DES3-MAC init-matrix rows, so init fell through to
  usage flags only). The other 2 are the HOTP externals by id.
- Fixes (all in-stack, 10a commit): DES3 keygen defaults an
  absent length to three-key 24 bytes (AES keeps its required
  length — no single headline size); `KeyMatrix` gains the
  DES3-MAC sign+verify rows (`CKK_DES3`); `caseInitKeyTypeMatrix`
  pins DES3-MAC init accept/refuse both ops;
  `caseDes3Keygen` pins the default. Consumer parity: DES3-MAC
  nonempty-params refusal is per-topology (direct
  `ARGUMENTS_BAD`, proxied `PARAM_INVALID` — the recorded shim
  translation precedent); TLS-PRF zero-image params are
  per-topology (direct `ARGUMENTS_BAD` on the wrong-sized
  image, proxied `CKR_OK` — the shim chases the all-zero struct
  to empty label+seed under its NULL-on-miss contract and empty
  params are legal inputs).
- r38: 3387 passed / 2 failed / 442 xfailed / 2823 skipped
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r38-results.json`).
  r37→r38: +82 pass / −14 fail / −67 xfail / −1 skip; the
  −67 xfail is the keygen fix moving setup-blocked legs into
  runs. Net vs r36 (3316 passed): +71 pass, same 2 HOTP
  externals by id, zero pass→fail.
- KAT r17→r18: 78440→78511 passed (+71) / 8 failed (=) /
  3995→4007 xfailed / 30310→30312 skipped
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r18-results.json`). The 8
  failures are identical by id to r17 (6 P11C-003 + 2 HOTP
  externals); zero pass→fail. Movers: `test_des` 0/33-skip →
  12 pass / 21 skip; `test_tls12` 0/38-skip → 2 pass / 36 skip
  (`test_tls_prf_availability` +
  `test_tls_prf` — the latter derives a master secret through
  our `CKM_TLS_PRF` and compares against the framework's own
  RFC 2246 implementation, passing); matrix families +10 pass
  each across `test_mech_sign`/`test_mech_multipart`/
  `test_mech_negative`(+10 xfail)/`test_mech_flags`(+12 pass,
  +24 skip) as the 4 new mechanisms register; `test_mech_probe`
  +12 skip (registered, tested elsewhere).
- Bundle note: r37/r38/KAT-r18 all ran on release bundles built
  from the 10a+10b stack (rebuilt after the in-stack fixes for
  r38/r18). Only the triage doc changed afterwards, so no
  stale-bundle re-verify is needed this round.

## Remaining fast-lane failures (r28: 2), by cluster

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

## KAT lane status (r12, DSA slice + usage-default fix: COMPLETE)

112594 tests — 75366 passed, 2 failed, 0 crashed, 3887 xfailed,
33339 skipped (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r12-results.json`;
`incomplete: false`), canonical data dir `/tmp/pkcs11-ws/data`,
clean-rebuild release. The only failures are the 2 external
HOTP registry asserts (same pair as every lane, confirmed by
test id). Delta vs r10 is fully attributed, +732 passed / +1
xfailed, zero pass→fail, zero crashes, zero xpass:

- `test_dsa_complete.py`: 0→74 passed (skip→pass); 3 remaining
  skips are the unadvertised FIPS seed-variant gates (honest
  catalog-only, provider-absent per OSSL4-002).
- `test_wycheproof_dsa.py`: 0→613 passed (skip→pass); 1343
  skips are duplicate-vector dedup. Every served vector
  verifies with strict invalid rejection (no accepted-invalid).
- `test_sign.py`: +1 passed (the KAT r11 finding
  `TestDSASignature::test_dsa_generate_and_sign`, fixed by the
  keygen usage-default change — minimal templates now mint
  usable keys).
- `test_mech_flags.py`: +44 passed / +64 skipped (new DSA
  flag/size probes pass).
- `test_field_size_boundary.py`: +1 xfail / −1 skip (the DSA
  prime-bits probe now runs; xfail is P11C-002 — the
  framework's reject tuple carries wrong numeric codes, so the
  spec-correct `CKR_TEMPLATE_INCONSISTENT` cannot pass).
- Registry legs newly collected for the 12 advertised DSA
  mechanisms skip on the framework's domain-params
  provisioning gate (`test_mech_negative` +80,
  `test_mech_probe` +36, `test_mech_sign` +30,
  `test_mech_multipart` +18, `test_mech_attribute` +8,
  `test_mech_keygen` +4) — none a Haskoki gap.
- KAT r11 (intermediate): 75365 passed, 3 failed — the 2 HOTP
  externals plus the minimal-template DSA finding above, fixed
  in-slice (see Round 12). Fast r30 standalone repeats r29
  exactly (6410 tests — 3169 passed, same 2 HOTP failed, 419
  xfailed, 2820 skipped): zero drift from the usage-default
  behavior change.

## KAT lane status (historical r10, AES-XTS slice: COMPLETE)

112310 tests — 74634 passed, 2 failed, 0 crashed, 3886 xfailed,
33788 skipped (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r10-results.json`;
`incomplete: false`), canonical data dir `/tmp/pkcs11-ws/data`,
clean-rebuild release. The only failures are the 2 external
HOTP registry asserts (same pair as every lane). Delta vs r9 is
fully attributed, +346 passed / +123 xfailed / −445 skipped,
zero pass→fail, zero crashes, zero xpass:

- `acvp/aes/test_xts.py`: 0→336 passed (skip→pass); the 864
  remaining skips are the bit-level vectors (same taxonomy as
  targeted r1).
- `test_wycheproof_aes.py`: +2 passed / +121 xfailed / −123
  skipped (XTS wycheproof vectors newly collected). The 2
  passes are tc121/tc123 — the only served-width vectors with
  a 16-byte tweak — with full KAT ciphertext equality. The
  121 xfails are honest framework holds on inexpressible
  inputs: tc1–tc120 carry 1–15-byte tweaks (PKCS#11 fixes the
  XTS tweak parameter at 16 bytes), clean-rejected
  `CKR_ARGUMENTS_BAD` by the planner (sibling convention);
  tc122 is AES-192-XTS (48-byte key, provider-absent):
  structural import accepts, use-time triple rejected
  `CKR_GENERAL_ERROR` via the documented `CryptoFailed`
  convention (same path as CBC with a 20-byte key).
- Fast-lane units inside KAT repeat the fast r28 deltas
  exactly (`parameter_validation` +1 / −1, `test_mech_encrypt`
  +1 / +1, `test_mech_flags` +4 / +5, `test_mech_multipart` +1
  skip, `test_mech_negative` +2 / +4 / +2, `test_mech_probe`
  +3 skipped, `test_operation_termination` +1 skip) —
  cross-lane consistency check passes. Fast r28 standalone:
  6126 tests — 3125 passed, same 2 HOTP failed, 418 xfailed,
  2581 skipped.

## KAT lane status (historical r9, WRAP/KWP slice + unwrap-confusion fix: COMPLETE)

112286 tests — 74288 passed, 2 failed, 0 crashed, 3763 xfailed,
34233 skipped (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r9-results.json`;
`incomplete: false`), canonical data dir `/tmp/pkcs11-ws/data`,
clean-rebuild release. The only failures are the 2 external
HOTP registry asserts (same pair as every lane). Delta vs r8 is
fully attributed, +7549 passed / +178 xfailed / −7655 skipped,
zero pass→fail, zero crashes, zero xpass:

- `acvp/aes/test_wrap.py`: 0→7200 passed (skip→pass).
- `test_wycheproof_aes.py`: +287 passed / +132 xfailed / −419
  skipped (KW wycheproof vectors newly collected; the xfails
  are the corpus's expected-reject legs).
- Fast-lane units inside KAT repeat the fast r27 deltas
  exactly (`test_error_path_kwp` +16 pass / +26 xfail,
  `test_ckr_wrap` +5, `test_mech_wrap` +3, `test_mech_negative`
  +4 pass / +18 xfailed, `test_mech_flags` +12 pass,
  `test_mech_probe` +9 skipped, `test_tookan` +2 including the
  confusion leg, plus the +1 skip→pass first-exposures) —
  cross-lane consistency check passes. Fast r27 standalone:
  6102 tests — 3117 passed, same 2 HOTP failed, 416 xfailed,
  2567 skipped.

## KAT lane status (historical r8, CFB/OFB slice + C_SessionCancel: COMPLETE)

112214 tests — 66739 passed, 2 failed, 0 crashed, 3585 xfailed,
41888 skipped (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r8-results.json`;
`incomplete: false`), canonical data dir `/tmp/pkcs11-ws/data`,
clean-rebuild release. The only failures are the 2 external
HOTP registry asserts (same pair as every lane). Delta vs r7 is
fully attributed, +8633 passed / +16 xfailed / −8553 skipped,
zero pass→fail, zero crashes, zero xpass:

- `acvp/aes/test_cfb1.py`: 0→2138 passed (skip→pass).
- `acvp/aes/test_cfb128.py`: 0→2144 passed (skip→pass).
- `acvp/aes/test_cfb8.py`: 0→2144 passed (skip→pass; the 6 MCT
  legs that failed in targeted r1 pass here via the cancel fix).
- `acvp/aes/test_ofb.py`: 0→2144 passed (skip→pass; same MCT
  story as CFB8).
- `security/test_output_length_truncation.py`: +6 passed
  (CFB/OFB truncation legs now run).
- Fast-lane units inside KAT repeat the fast r25 deltas
  exactly (`test_aes_modes` +6, `test_ckr_v30_raw` +1,
  `test_mech_encrypt` +7, `test_mech_flags` +16,
  `test_mech_multipart` +4, `test_mech_negative` +16 passed /
  +16 xfailed, `test_mech_probe` +12 skipped,
  `test_operation_termination` +4, `test_v30_session` +3) —
  cross-lane consistency check passes. Fast r25 standalone:
  6030 tests — 3055 passed, same 2 HOTP failed, 370 xfailed,
  2603 skipped
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r25-results.json`).
- Targeted CFB/OFB r2 (same bundle):
  `test_cfb1/cfb128/cfb8/ofb` 2138/2144/2144/2144 pass, 0 fail
  (`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-cfb-ofb-r2.json`).

Remaining 3585 xfails + 41888 skips are the ranked slices
still ahead (WRAP/KWP, XTS, DSA, EdDSA, PQC, legacy, TLS/KDF —
same taxonomy as r7, CFB/OFB rows now served).

## KAT lane status (historical r7, AES-CTS slice: COMPLETE)

112118 tests — 58106 passed, 2 failed, 0 crashed, 3569 xfailed,
50441 skipped (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r7-results.json`;
`incomplete: false`), canonical data dir `/tmp/pkcs11-ws/data`,
clean-rebuild release. The only failures are the 2 external
HOTP registry asserts (same pair as every lane). Delta vs r6 is
fully attributed, +2649 passed / +4 xfailed / −2629 skipped,
zero pass→fail, zero crashes, zero xpass:

- `acvp/aes/test_cts.py`: 0→2636 passed, 7500→4864 skipped.
  First exposure: the oracle detects "Module implements CS1"
  (fixed-key 32/33-byte probes) and runs the CS1 legs; the
  4864 skips are exactly CS2 (2386) + CS3 (2478) by detector
  design (non-byte-aligned payloads are excluded at collection,
  outside the 7500).
- Fast-lane units inside KAT repeat the fast r24 deltas
  exactly (`test_aes_modes` +2, `test_mech_encrypt` +1,
  `test_mech_flags` +4, `test_mech_multipart` +1,
  `test_mech_negative` +4 passed / +4 xfailed CTS legs,
  `test_mech_probe` +3 skipped, `test_operation_termination`
  +1) — cross-lane consistency check passes. Fast r24
  standalone: 5934 tests — 2998 passed, same 2 HOTP failed,
  354 xfailed, 2580 skipped
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r24-results.json`).
- Targeted CTS r1 (same bundle):
  `test_cts.py` 2636/0/0x/4864s, `TestAESCTS` roundtrip legs
  pass (`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-cts-r1.json`).

Remaining 3569 xfails + 50441 skips are the ranked slices
still ahead (CFB/OFB, WRAP/KWP, XTS, DSA, EdDSA, PQC, legacy,
TLS/KDF — same taxonomy as r6, CTS rows now served).

## KAT lane status (historical r6, curves verdict precision: COMPLETE)

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
