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

## 11q fast lane (rc2 oracle, 2026-09-29)

Bundle `dist-release/haskoki-0.3.0.0` at `7619426` (11q-1 SHA1
PBE rows, 11q-2 MD5 PBE rows, RC4 multipart fix), oracle
pkcs11-check 0.2.2rc2 (`/tmp/pkcs11-ws/run-lane-rc2.sh fast`,
results `/tmp/pkcs11-ws/out-rc2/fast/pkcs11-fast-results.json`).

First run: 9909 tests — 5029 passed, 1 failed, 612 xfailed,
4267 skipped, 0 crashed. The failure was ours:
`test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[RC4]`
— multipart ciphertext diverged from single-part at byte 16.
Root cause: CKM_RC4 streamed every update chunk as an
independent one-shot, restarting the keystream per chunk (no
IV, no chaining state). Fixed by buffering RC4 multipart
updates and running the final one-shot (`isRc4Mech` in
`cipherUpdateSplit`, `7619426`; regression pinned in
OperationSpec). Rerun after bundle rebuild: 5030 passed,
0 failed, 612 xfailed, 4267 skipped, 0 crashed.

PBE legs (`test_pbe.py`): 28 passed, 0 failed, 5 skipped —
all 9 new rows (0x3a1–0x3a7, 0x3aa–0x3ab) pass their
`TestLegacyPBEVariants::test_generate_key` legs; the MD2 row
skips (unadvertised). No new oracle-side findings: no
upstream filing from this round.

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

## Round 18: BLAKE2B-512 slice (fast r38→r39 + KAT r18→r19)

- r39: 3426 passed / 2 failed / 470 xfailed / 2861 skipped
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r39-results.json`).
  r38→r39: +39 pass / = fail / +28 xfail / +38 skip. The 2
  failures are the HOTP externals by id; zero pass→fail.
- KAT r18→r19: 78511→78550 passed (+39) / 8 failed (=) /
  4007→4035 xfailed / 30312→30350 skipped
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r19-results.json`). The 8
  failures are identical by id to r18 (6 P11C-003 + 2 HOTP
  externals); zero pass→fail.
- Movers (identical in both lanes; vector units unchanged):
  `test_blake2` 0→15 pass / 64 skip / 6 xfail — the new
  BLAKE2B-512 legs run (digest/HMAC/GENERAL/derive/keygen
  incl. the KAT comparisons against the framework's own
  hashlib oracles) while the 160/256/384 widths skip;
  `test_mech_flags` +15 pass / +30 skip and
  `test_mech_negative` +4 pass / +8 xfail / +10 skip as the 5
  new mechanisms register; `test_mech_sign` +4 xfail / +2 skip,
  `test_mech_attribute` +4 xfail, `test_mech_keygen` +2 xfail
  (new-mechanism parameterizations). `test_mech_multipart`
  shows 0→167 pass but r38 captured an empty stdout for that
  unit (runner artifact), so its true delta is folded into the
  +39 rather than a +167 mover.
- Bundle note: r39/KAT-r19 ran on a release bundle rebuilt
  from the 10c stack after the in-stack proxy-override fix
  (0x401D `mac_general` shape). Only the triage doc changed
  afterwards, so no stale-bundle re-verify is needed this
  round.

## Round 19: ChaCha20-Poly1305 slice (fast r39→r40 + KAT r19→r20)

- r40: 3457 passed / 2 failed / 480 xfailed / 2884 skipped
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r40-results.json`).
  r39→r40: +31 pass / = fail / +10 xfail / +23 skip. The 2
  failures are the HOTP externals by id; zero pass→fail.
- KAT r19→r20: 78550→78908 passed (+358) / 8 failed (=) /
  4035→4045 xfailed / 30350→30046 skipped
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r20-results.json`). The 8
  failures are identical by id to r19 (6 P11C-003 + 2 HOTP
  externals); zero pass→fail.
- Movers (unit `counts`, exact reconciliation both lanes):
  `test_wycheproof_chacha` 0→325 pass / 325→0 skip (KAT
  only) — the 256 valid vectors decrypt to expected bytes and
  the 69 invalid vectors reject with the tag/nonce CKR class
  (decrypt-direction harness with a canonical-decrypt
  operability guard, so the rejects are non-vacuous);
  `test_salsa20` 0→4 pass / 11→7 skip (both lanes) — the raw
  `CKM_CHACHA20` stream legs run while the Poly1305 legs keep
  skipping (unserved, honest); registration effects as the 3
  new mechanisms advertise: `test_mech_flags` +10 pass /
  +17 skip, `test_mech_negative` +8 pass / +8 xfail,
  `test_mech_attribute` +3 pass / +1 xfail,
  `test_mech_keygen` +1 pass / +1 xfail,
  `test_mech_encrypt` +3 pass / +1 skip, `test_mech_probe`
  +9 skip, `test_mech_multipart` +1 pass,
  `test_operation_termination` +1 pass, and (KAT only)
  `test_output_length_truncation` +2 pass / −2 skip.
  Corroborated by the targeted reproof
  (`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-chacha20-10d.json`,
  325/325 on the same bundle).
- Bundle note: r40/KAT-r20 ran on a release bundle rebuilt
  from the 10d stack (no in-stack fixes needed after the
  lanes). Only the triage doc changed afterwards, so no
  stale-bundle re-verify is needed this round.

## Round 20: DH slice (fast r40→r41→r42 + KAT r20→r21)

- r42: 3479 passed / 15 failed / 487 xfailed / 2912 skipped
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r42-results.json`).
  r40→r42: +22 pass / +13 fail / +7 xfail / +28 skip. The
  15 failures are the 13 P11C-004 X9.42 legs plus the same
  2 HOTP externals, all confirmed by test id; zero
  pass→fail. The intermediate r41 (3476 pass / 15 fail /
  490 xfail / 2912 skip, pre-guard bundle, live file since
  overwritten) differs from r42 only in the security file
  (3 xfail→pass, see below) and the X9.42 failure code
  (`GENERAL_ERROR`→typed).
- Movers (unit `counts`, exact reconciliation):
  `test_dh_key_agreement` +9 pass / +1 xfail / −10 skip —
  the PKCS#3 file newly runs, 9 passing except the zero-length
  `VALUE_LEN` leg (xfailed: token answers the central
  `TEMPLATE_INCONSISTENT`, the file wants
  `KEY_SIZE_RANGE`/`ATTRIBUTE_VALUE_INVALID`; open
  question in P11C-004, no ECDH/HKDF counterpart pins the
  narrower set); `security/test_dh_param_validation` +4
  pass / −4 skip — prime=1, tiny-prime and generator=0
  now refuse typed from the planner structural floor
  (512 significant prime bits, 2 <= g < p; the 1024-bit
  posture leg accepts either way and passes);
  `test_field_size_boundary` +1 xfail / −1 skip — the new
  DH oversized-`PRIME_BITS` leg lands on the P11C-002
  wrong-tuple (recorded there);
  `test_x942_dh` +13 fail / +5 xfail / −18 skip — the
  P11C-004 cascade (corrupt 257-byte `X942_GEN` greater
  than the prime; every leg raises from
  `_generate_x942_keypair`'s `expect_rv(OK)`); the 5
  import-based vector legs xfail on the runtime-reject
  sets. Registration effects as the 4 DH mechanisms
  advertise: `test_mech_flags` +8 pass / +28 skip,
  `test_mech_probe` +12 skip, `test_mech_attribute` +8
  skip, `test_mech_negative` +8 skip, `test_mech_keygen`
  +4 skip, `test_mech_derive` +2 skip, `test_ckr_object`
  +1 pass / −1 skip (per-test list unrecorded for that
  unit; a DH-gated leg newly runs). Corroborated by the
  targeted reproof
  (`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-dh-r2.json`:
  PKCS#3 9/9 + 1 xfail, security 4/4, X9.42 13 failing by the
  same ids) and a C-ABI probe (genuine RFC 5114 domain:
  keygen `CKR_OK` + KAT-exact derive; corrupt `g` fails
  closed typed with no handles; non-subgroup peer refused
  `PARAM_INVALID`).
- KAT r20→r21: 78908→78930 passed (+22) / 8→21 failed
  (+13) / 4045→4052 xfailed / 30046→30074 skipped
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r21-results.json`).
  Identical mover shape to the fast lane (same 11 units,
  same deltas); the 21 failures are the r20 8 by id (6
  P11C-003 + 2 HOTP externals, none gone) plus the same
  13 P11C-004 legs; zero pass→fail.
- Bundle note: r42/KAT-r21 run on a release bundle rebuilt
  from the 10e stack including the structural floor (no
  in-stack fixes needed after the lanes).

## Round 21: RSA-X.509 slice (fast r42→r43 + KAT r21→r22)

- r43: 3489 passed / 15 failed / 487 xfailed / 2947 skipped
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r43-results.json`).
  r42→r43: +10 pass / +0 fail / +35 skip. The 15 failures
  are identical by test id to r42 (13 P11C-004 X9.42 legs +
  the same 2 HOTP externals); zero pass→fail.
- Movers (unit `counts`, exact reconciliation): the single
  advertised X_509 row lands `test_mech_flags` +6 pass /
  +3 skip, `test_mech_sign` +2 pass / +1 skip,
  `test_mech_encrypt` +1 pass / +1 skip, `test_mech_wrap`
  +1 pass; registration-only skips in `test_mech_negative`
  (+27) and `test_mech_probe` (+3). No dedicated x509
  behavior file exists in the oracle, so the +10 all sit in
  the shared mech files.
- KAT r21→r22: 78930→78940 passed (+10) / 21 failed (same
  ids) / 4052 xfailed / 30074→30109 skipped (+35)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r22-results.json`).
  Identical mover shape to the fast lane (same 6 units,
  same deltas); `coverage.json` shows CKM_RSA_X_509
  exercised (28 hits). Zero pass→fail.
- Corroborated by the targeted reproof
  (`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-x509-r2.json`:
  727 pass / 0 fail / 12 xfail): sign/encrypt/wrap/flags
  units all passing, and the sign-recover files
  (`test_mech_sign_recover`, `test_sign_recover`) skip
  cleanly (2 + 6) on the named sign-recover stub gap.
- Two real oracle findings fixed in-slice (ours, no new
  upstream issue): the `CipherSpec` gate had no X_509
  entry, and `CKA_SIGN_RECOVER`/`CKA_VERIFY_RECOVER` had
  no attribute plumbing.
- Bundle note: r43/KAT-r22 run on a release bundle rebuilt
  from the 10f stack (no in-stack fixes needed after the
  lanes).

## Round 22: keygen-sweep slice 11a (fast r43→r44→r45 + KAT r22→r23)

- r44: 3770 passed / 19 failed / 599 xfailed / 3288
  skipped
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r44-results.json`).
  r43→r44: +281 pass / +4 fail / +112 xfail / +341
  skip (+738 collected: 41 new keygen rows × shared-mech
  parametrization).
- r45: 3775 passed / 18 failed / 595 xfailed / 3288
  skipped
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r45-results.json`).
  r44→r45: +5 pass / −1 fail / −4 xfail / +0 skip (the
  in-slice HKDF widening; exact unit reconciliation
  below). r43→r45: +286 / +3 / +108 / +341 with zero
  pass→fail (`lane-testdiff.py`: regression count 0;
  the 15 r43 failures persist by id, the 3 new failures
  are newly-collected WTLS legs, 8 xfails flip to pass).
- Movers r43→r44 (unit `counts`, exact): newly
  advertised rows land `test_mech_attribute` +105 pass /
  +59 xfail, `test_mech_keygen` +35 pass / +47 xfail,
  `test_mech_flags` +82 pass / +287 skip,
  `test_mech_negative` +6 pass / +6 xfail / −12 skip;
  registration-only `test_mech_probe` +123 skip.
  Dedicated behavior files unskip: aria +7, camellia
  +7, des +4, twofish +3, blowfish +2, salsa20 +2,
  blake2 +3, gost/seed/ssl3/tls12 +1 each,
  `test_mech_encrypt` +5, `test_mech_multipart` +4,
  `test_operation_termination` +4, `test_hkdf_extended`
  +1 pass / +2 xfail / −3 skip.
- The +4 fail r43→r44: 3 WTLS pre-master keygen legs
  (newly collected, P11C-006 oracle fixtures — missing
  required `CK_BYTE` version param + 8-byte `CK_ULONG`
  bools) and `test_hkdf_to_aes_encrypt` in
  `test_mech_lifecycle` (ours: HKDF expand-only /
  empty-salt gap, fixed in-slice — see r44→r45).
- Movers r44→r45 (exact): `test_mech_lifecycle` +1
  pass / −1 fail (HKDF lifecycle leg),
  `test_hkdf_extended`, `test_kdf`
  (`test_hkdf_derive_basic`), `test_mech_derive` +1
  pass / −1 xfail each (HKDF widening),
  `test_public_session_private_creation` +1 / −1x
  (auth-ordering leg now passes on the widened HKDF
  path). The 18 r45 failures are 13 P11C-004 X9.42 +
  2 P11C-001 HOTP (same ids as r43) + 3 P11C-006 WTLS.
- Bonus hardening from the 11a stack (not HKDF):
  `test_ffi_length_boundary` +6 pass / −6 xfail —
  PBKDF2 nested 2^63 lengths now fail closed with a
  reject RV instead of `CKR_OK` silent truncation.
- Two new upstream filings (ours verified, module
  proven correct): P11C-005 (BLAKE2B registry
  `CKK_GENERIC_SECRET` keygen template vs spec-mandated
  typed `CKK_BLAKE2B_*_HMAC` — 40 xfailed legs across
  5 shared files) and P11C-006 (WTLS fixtures — 3
  hard failures).
- Corroborated by targeted reproofs:
  `/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-hkdf-r2.json`
  (19 pass / 0 fail / 1 xfail) and
  `pkcs11-targeted-wtls-fixed-r1.json` (4/4 pass on the
  corrected `mech_bytes` + `attr_bool` fixture against
  the unmodified bundle).
- KAT r22→r23: 78940→79310 passed (+370) / 21→24
  failed (+3) / 4052→4076 xfailed (+24) /
  30109→30450 skipped (+341)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r23-results.json`).
  Zero pass→fail; the 21 r22 failures persist by id
  (13 P11C-004 X9.42 + 2 P11C-001 HOTP + 6 P11C-003
  SLH-DSA context legs) and the +3 are the newly
  collected WTLS trio (P11C-006). Mover shape mirrors
  the fast lane (same shared-mech deltas, incl.
  `test_mech_flags` +82/+287s and `test_mech_probe`
  +123s), plus KAT-only wins from the HKDF widening:
  `test_wycheproof_hkdf` +83 pass / −83 xfail,
  `test_wycheproof_pbkdf2` +1 / −1x; 92 xfail→pass
  flips total, 116 newly collected xfails (59
  attribute + 47 keygen incl. the P11C-005 BLAKE2B
  legs).
- Bundle note: r44/r45 run on a release bundle rebuilt
  from the 11a+HKDF stack (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16).

## rc1 validation: pkcs11-check 0.2.2rc1 fast lane (2026-09-27)

Bundle built from the same 11a+HKDF stack (pre-11b);
strict A/B against r45 unproven (separate bundle
build). 3782 passed / 4 failed / 620 xfailed / 3286
skipped (t7692)
(`/tmp/pkcs11-ws/out/fast-rc1/pkcs11-fast-rc1-results.json`).

- P11C-001 (HOTP `key_type=None`): FIXED — both
  hard fails gone. Residual `HOTP_KEY_GEN` keygen legs
  xfail as not-operational on TEMPLATE_INCONSISTENT
  (template-shape, same class as P11C-005; key-type
  read still pending).
- P11C-002 (key-size reject RV codes): ADDRESSED
  oracle-side (now expects CKR_KEY_SIZE_RANGE); our
  over-max refusals still return TEMPLATE_INCONSISTENT
  — xfail-level RV precision gap, ours.
- P11C-003 (SLH-DSA context): PROVEN —
  `test_acvp_slhdsa.py` goes 78 pass / 6 fail → 84
  pass / 0 fail on the same 84 collected (the 6
  base failures are genuine "rejected VALID
  signature" crypto assertions spanning
  SHA2/SHAKE × 128f/192f/256f/192s; the harness
  omits pass records, so the proof is unit-count
  resolution — see KAT verdicts below).
- P11C-004 (X9.42 fixtures): FIXED — the 13 hard
  fails collapse to 15 pass; the 1 remaining x942
  failure is the encrypt residual below (new
  information, not the fixture bug).
- P11C-005 (BLAKE2B generic-secret template): STILL
  OPEN — same xfail shape (`BLAKE2B_*_KEY_GEN keygen
  rejected at runtime: CKR_TEMPLATE_INCONSISTENT`).
- P11C-006 (WTLS fixtures): STILL OPEN — fixture
  byte-identical to pinned (`mech_simple`, no version
  byte, `attr_ulong` bools, `test_wtls.py:628-636`);
  the same trio fails on our TEMPLATE_INCONSISTENT.
  Our path stays proven via the fixed-fixture 4/4
  reproof.
- New finding 1 (ours — EdDSA NULL stance): rc1
  probes EdDSA with NULL params first; 17+ Ed25519
  legs xfail on our PARAM_INVALID. OASIS Table 42
  (v3.0 §2.3.14, carried into v3.2): Ed25519 pure
  param "Not Required" — NULL-means-pure is
  spec-correct and our struct-required gate is
  non-compliant for Ed25519. Tracked as the
  EdDSA-NULL follow-up slice (recipe + SignInit +
  tests); the slice also corrects the overclaiming
  `mechanisms.json` EdDSA note ("NULL params ...
  both serve" — false today). Ed448-pure keeps the
  Required param; rc1's Ed448 legs need re-read at
  slice time.
- New finding 2 (shared — x942 missing-LEN default):
  `test_derived_key_encrypts` fails at the C_Encrypt
  size query with GENERAL_ERROR. Oracle half:
  `_x942_derive_aes` omits CKA_VALUE_LEN where its
  PKCS#3 twin pins `CKA_VALUE_LEN: 16`
  (`test_dh_key_agreement.py` vs `test_x942_dh.py:967`)
  — helper asymmetry, P11C-007 candidate. Our half:
  missing VALUE_LEN defaults to the full DH prime
  width (`Derive.hs` DH arm, `Just (dhSecretWidth
  mat)`), storing a 384-byte "AES" key that EVP
  refuses late. The honest fix is derive-time
  length-domain validation (TEMPLATE_INCONSISTENT
  instead of a poisoned object + late GENERAL_ERROR);
  the leg itself can only go green via the oracle
  helper fix. Tracked as the x942-hardening
  follow-up slice — it cannot ride 11b (the pinned
  oracle never reaches the path, so lane proof there
  would be vacuous).
- KAT-rc1: 78484 passed / 4 failed / 4870 xfailed /
  30518 skipped (t113876)
  (`/tmp/pkcs11-ws/out/kat-rc1/pkcs11-kat-results.json`),
  vs r23 79310/24/4076/30450. Zero pass→fail
  (`lane-testdiff.py`: regression count 0). The 4
  failures are the same WTLS trio (P11C-006) +
  x942-encrypt residual as the fast lane.
- The pass-count drop (−826) is one unit:
  `test_cctv_ed25519.py` goes 914 pass → 914 xfail.
  Precise mechanism (source-compared, not inferred):
  the test file, the `_signature_policy.py`
  classifier, and the CCTV vectors are byte-identical
  between 0.2.1 and rc1; the only delta on this path
  is `raw/recipes.py::_resolve_mech`. 0.2.1 carried
  an EdDSA special-case ("always use mech_eddsa()
  with pure mode ... since some modules require
  explicit params even for pure EdDSA") that silently
  substituted a pure struct for omitted params —
  masking our non-compliance. rc1 deletes it
  ("Omitted parameters always mean NULL/zero fields,
  including CKM_EDDSA"; changelog l65-67: "Pure RFC
  8032 sign/verify pass explicit NULL params ...
  replacing the single implicit encoding"). So the
  914 passes were workaround-assisted and the 914
  xfails ("non-clean CKR: PARAM_INVALID") are the
  true signal of our struct-required gate vs Table
  42 NULL-means-pure. Not a regression — newly
  effective coverage of our EdDSA-NULL gap, fully
  recoverable by the stance slice (the biggest
  single KAT win on the board, +914 plus the 17
  `test_eddsa` / 7 `test_acvp_eddsa` / 6 wycheproof
  legs).
- Oracle-side wins in our favor (same bundle):
  98 xfail→pass (`test_ccm` +88 with identical 8398
  collected, x942 +3, field-size +3, +1 each
  access/attribute/dh/v30) plus 71 xfail→skip
  reclassifications (ML-DSA +70, field-size +1) —
  rc1 expectation fixes, not root-caused per leg.
  Lane-wide +16 collected are pure additions (eddsa
  +7 NULL-probe legs, negative +4, message +2,
  ffi_alignment +2, param_validation +1); no unit
  loses legs, xpassed stays 0.
- Adoption: do NOT pin rc1 yet — conditional on the
  EdDSA stance slice and the x942 residual
  disposition (P11C-003 proof now in hand).
  11b lanes stay on the pinned oracle.

## Round 23: KDF-matrix slice 11b (fast r45→r46→r47 + KAT r23→r24)

- r46: 3786 passed / 18 failed / 590 xfailed /
  3288 skipped (t7682)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r46-results.json`).
  r45→r46: +11 pass / +0 fail / −5 xfail / +0
  skip (+6 collected: newly operational PBKD2
  keygen legs).
- r47: 3787 passed / 18 failed / 589 xfailed /
  3288 skipped
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r47-results.json`).
  The only r46→r47 transition is
  `test_derive_aes_key` xfail→pass (the in-slice
  typed-target fix); `test_pbe` stands 8 pass / 0
  fail / 25 skip / 0 xfail.
- Movers r45→r47 (unit `counts`, exact):
  `test_pbe` 1/7x → 8/0x (6 generic PBKD2-gen legs
  + the AES-256 leg), `test_mech_flags` 611/7x →
  612/6x (PBKD2 `CKF_GENERATE`),
  `test_mech_attribute` t228→232 (+3 pass / +1
  xfail), `test_mech_keygen` t114→116 (+1 / +1x).
  The 18 failures are identical by id to r45 (13
  P11C-004 X9.42 + 2 P11C-001 HOTP + 3 P11C-006
  WTLS). Zero pass→fail.
- One real in-slice fix (ours): PBKD2 keygen pinned
  the target to generic-secret, so the AES-256 leg
  refused with TEMPLATE_INCONSISTENT. The planner
  now dispatches typed secret targets with
  per-type length domains (AES 16/24/32, DES3 24,
  XTS 32/64 — the unwrap coherence table) through
  the strict template check; unlisted types refuse
  closed. RED (`template key type 31 is not 16`) →
  GREEN in `casePbkd2Keygen`, all 6 host suites +
  consumers + evidence green, lane reproof r47.
- Two new xfails, no action: the PBKD2 CKA_LOCAL
  pair (`attribute unavailable`) carries the
  generic module-wide unserved-attribute signature
  (identical for AES, ARIA, DES, ...) — a
  cross-cutting attribute gap, not a PBKD2 defect.
- KAT r23→r24: 79310→81123 passed (+1813) / 24
  failed (same ids: 13 + 2 + 3 + 6 SLH-DSA
  P11C-003) / 4076→2269 xfailed (−1807) /
  30450 skipped (+0)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r24-results.json`).
  Zero pass→fail (`lane-testdiff.py`: regression
  count 0; all flips unit-count grounded at
  identical collection).
- KAT movers (exact): `test_wycheproof_pbes2`
  0/1260x → 1260/0x (the entire file),
  `test_wycheproof_pbkdf2` 1/298x → 298/1x,
  `test_wycheproof_hkdf` 83/256x → 327/12x, plus
  the fast-lane `test_pbe`/flags/attribute/keygen
  shape. Total +1813 pass accounted leg-for-leg
  (1260 + 297 + 244 + 7 + 1 + 3 + 1).
- KAT residuals, all dispositioned: the 12 HKDF
  invalid-L legs (expected KEY_SIZE_RANGE, kept
  uniform ARGUMENTS_BAD per the pre-lane slice
  decision); `pbkdf2_hmacsha1 tc4-valid` (RFC
  6070, 2^24 iterations — refuses under the
  documented 10^7 CPU guard, `maxPbkd2Iters`,
  enforced at the FFI boundary for both derive
  and gen; policy xfail by design); the CKA_LOCAL
  pair (above).
- Bundle note: r46/r47/r24 run on the 11b bundle
  rebuilt post-fix (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16).

## Round 24: XDH-Montgomery slice 11c (fast r47→r48 + KAT r24→r25)

- r48: 3799 passed / 18 failed / 591 xfailed /
  3292 skipped (t7700)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r48-results.json`).
  r47→r48: +12 pass / +0 fail / +2 xfail / +4
  skip (+18 collected: the new Montgomery row's
  shared-mech expansion).
- Movers r47→r48 (unit `counts`, exact):
  `test_ecdh_extended` 4/8s → 8/4s (Montgomery
  legs newly served), `test_parameter_validation`
  26/2s → 28/0s (Montgomery param legs incl.
  low-order rejection), `test_mech_attribute`
  t232→236 (+3 / +1x), `test_mech_flags`
  612/1146s → 614/1153s (+2 / +7s),
  `test_mech_keygen` t116→118 (+1 / +1x),
  `test_mech_probe` 588s→591s (+3s). The 18
  failures are identical by id to r47 (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS P11C-006).
  The 2 new xfails are the CKA_LOCAL pair on
  `EC_MONTGOMERY_KEY_PAIR_GEN` (module-wide
  unserved attribute, same signature as 11a/11b).
- r25: 82206 passed / 24 failed / 1200 xfailed /
  30454 skipped (t113884)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r25-results.json`).
  r24→r25: +1083 pass / +0 fail / −1069 xfail /
  +4 skip (+18 collected).
- The KAT mover is exactly the ranked prediction:
  `wycheproof/test_wycheproof_x25519.py` 0/1071x →
  1071/0x — all 1071 flip to pass, zero failures.
  The 517 valid vectors KAT-match byte-exact
  through the pinned provider (twist and
  non-canonical edge vectors included); the 42
  low-order vectors refuse `0x71` via the shim's
  BADPEER attribution (the provider fails
  zero-output derives); the overlong-peer
  invalids refuse `0x71` via the plan-time width
  rule. The 3091 skips are unchanged
  (duplicates). The pre-lane ctypes probe
  against the pinned libcrypto predicted this
  flip exactly (457/457 edge match, 42 low-order
  + 12 overlong provider-fails). Total +1083
  accounted leg-for-leg (1071 flips + 12
  shared-mech expansion).
- Fast-lane units inside KAT repeat the fast r48
  deltas exactly (cross-lane consistency check
  passes).
- KAT residuals, all dispositioned: the 24
  failures are identical by id to r24 (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS P11C-006 +
  6 SLH-DSA P11C-003); the CKA_LOCAL pair
  (above).
- Slice notes: the 1071-xfail source was the
  Derive planner's `ckkEc`-only gate
  (`KEY_TYPE_INCONSISTENT` at import-time for
  every Montgomery vector). Cofactor derive over
  Montgomery curves is a named gap (refuses
  `0x71`; clamping already clears the cofactor
  and the composed operation has no PKCS#11
  definition). In-slice test fix (pre-existing
  1/256 flake, no behavior change): the OAEP
  tamper leg in `RoutingE2ESpec` now mutates a
  guaranteed-differing byte instead of a literal
  "X".
- Bundle note: r48/r25 run on the 11c bundle
  (`dist-release/haskoki-0.3.0.0`, evidence
  16/16).

## Round 25: BLAKE2B-sized slice 11d (fast r48→r49 + KAT r25→r26)

- r49: 3960 passed / 18 failed / 605 xfailed /
  3378 skipped (t7961)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r49-results.json`).
  r48→r49: +161 pass / +0 fail / +14 xfail /
  +86 skip (+261 collected: the 12 new rows'
  shared-mech expansion).
- Movers r48→r49 (unit `counts`, exact):
  `test_blake2` 18/61s/6x → 85/0s/0x (the
  slice: every leg served, zero skips, zero
  xfails), `test_mech_negative` 182/587s/245x
  → 220/617s/243x (B1 PARAM_INVALID flips +
  new legs), `test_mech_flags` 614/1153s →
  653/1222s (flag matrix over the new mechs),
  `test_mech_digest` 53/3s → 62/6s,
  `test_mech_multipart` 172/21s/4x →
  178/21s/16x, `test_mech_sign`
  157/81s/5x → 157/87s/17x (new HMAC legs;
  xfails are P11C-005 registry-keygen
  victims), `test_mech_derive` +3s,
  `test_mech_probe` +36s. The 18 failures
  are identical by id to r48 (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS
  P11C-006). Zero pass→nonpass regressions.
- xfail→pass flips (34, exact): the 6
  `test_blake2` 512 legs (GENERAL invalid
  lengths, default-template, overlong, zero,
  value-injection), 26 registry
  missing-required-param legs (all
  HMAC_GENERAL widths, sign + verify — the
  B1 bonus), plus `test_dh_key_agreement`
  zero-length and `test_x942_dh` rfc5114
  zero-length (the B4 shared fix).
- The 48 new xfails are all keygen-setup
  victims on the new widths (registry sends
  CKK_GENERIC_SECRET per P11C-005; the
  without_flag setup quirk matches the 512
  pattern exactly).
- In-slice fixes (lane-found, both
  root-caused): the C `derive_opaque_ok`
  allowlist missed the 3 new KEY_DERIVE
  mechs (FUNCTION_NOT_SUPPORTED), and the
  new `CKR_KEY_SIZE_RANGE` was mapped to
  0x30 (DEVICE_ERROR) instead of 0x62 —
  fixed, the full 47-entry CKR table
  cross-checked against the vendored header
  (0 mismatches), and a boundary-map test
  pins 0x62.
- r26: 82367 passed / 24 failed / 1214 xfailed /
  30540 skipped (t114145)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r26-results.json`).
  r25→r26: +161 pass / +0 fail / +14 xfail /
  +86 skip (+261 collected) — exactly the fast
  r49 delta, as predicted (no sized-BLAKE2 KAT
  vector suites exist; ACVP/wycheproof HMAC
  already fully pass with no sized legs).
- Cross-lane consistency check passes at full
  strength: the 34 xfail→pass flips and the 48
  new xfails are ID-identical to fast r48→r49,
  and every unit mover repeats the fast counts
  exactly (`test_blake2` 85/0s/0x, the mech_*
  matrix legs, the dh zero-length pair). No
  KAT-vector unit moved. Zero pass→nonpass
  regressions.
- KAT residuals, all dispositioned: the 24
  failures are identical by id to r25 (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS P11C-006 +
  6 SLH-DSA P11C-003).
- Bundle note: r49/r26 run on the 11d bundle
  (`dist-release/haskoki-0.3.0.0`, evidence
  16/16).

## Round 26: cipher-tail slice 11e (fast r49→r50→r51 + KAT r26→r27)

- r51: 4048 passed / 18 failed / 631 xfailed /
  3496 skipped (t8193)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r51-results.json`).
  r49→r51: +88 pass / +0 fail / +26 xfail /
  +118 skip (+232 collected: the 12 new rows'
  shared-mech expansion).
- Movers r49→r51 (unit `counts`, exact):
  `test_aes_kdf` 0/9s → 9/0s (new
  ENCRYPT_DATA legs green); `test_aria` 7/7s →
  11/3s; `test_camellia` 7/9s → 12/3s/1x;
  `test_des` 16/17s → 20/13s;
  `test_des_kdf` 0/2s → 1/1s;
  `test_ffi_length_boundary` 68/57s → 70/55s
  (malformed legs green after the fix);
  `test_mech_derive` 14/8s → 20/9s/1x;
  `test_mech_encrypt` 39/5s → 45/6s/1x;
  `test_mech_flags` 653/1222s/6x →
  683/1298s/8x; `test_mech_multipart`
  178/21s/16x → 181/21s/17x;
  `test_mech_negative` 220/2f/617s/243x →
  235/2f/647s/262x; `test_mech_probe` skips
  627 → 663 (new rows' probe legs);
  `test_operation_termination` 28/1s/1x →
  31/1s/2x.
- In-slice fix (lane-found, r50→r51): r50
  (4045/22/630/3496) showed 4 failures on the
  new surface — ECB non-determinism plus a
  32-byte `KEY_SIZE_RANGE` (`test_aes_kdf`)
  and 2 accepted-malformed CBC structs
  (`test_ffi_length_boundary`). Root cause,
  ours: ECB takes
  `CK_KEY_DERIVATION_STRING_DATA` (OASIS
  struct), not raw bytes — the opaque path
  read pointer bytes as data; and a refused
  struct chase passed raw bytes through that
  could satisfy the unframed recipe. Fix: an
  ECB struct-chase normalizer plus fail-closed
  poison (empty blob) on any refused chase,
  pinned by NativeParamsSpec and consumer
  malformed legs. r50→r51: 4 failed → pass,
  the 18 known failures identical, 0
  regressions. The 1 new xfail is honest
  coverage, not fallout: `DES3_ECB derive`
  passed r50 vacuously (16 struct bytes read
  as data) and now xfails correctly (oracle
  template asks `VALUE_LEN` 16 from 8 data
  bytes — our `KEY_SIZE_RANGE` is the
  spec-correct ceiling).
- New-xfail attribution (26, all
  classified): 8 missing-required-param
  (expected `PARAM_INVALID`, got
  `ARGUMENTS_BAD`) — same as every cipher
  row incl. AES_CBC (pre-existing class); 9
  setup victims (8 without-flag keygen + 1
  derive-without-flag, P11C-005 class); 6
  CAMELLIA_CTR (5 NULL-params from the
  missing registry `param_recipe` → P11C-008;
  1 deliberate bits=32 probe refused under
  the documented 128-only CTR stance shared
  with AES_CTR); 2 PAD wrap-flag gaps (same
  as the ARIA/Camellia base rows); 1
  DES3_ECB derive probe (above).
- Failures identical by id (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS
  P11C-006). Zero pass→nonpass.
- r27: 82455 passed / 24 failed / 1240
  xfailed / 30658 skipped (t114377)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r27-results.json`).
  r26→r27: +88 pass / +0 fail / +26 xfail /
  +118 skip (+232 collected) — exactly the
  fast r49→r51 delta, as predicted (no
  PAD/CTR/ENCRYPT_DATA KAT vector suites
  exist; the new rows only add mech-matrix
  legs).
- Cross-lane consistency check passes at full
  strength: the 26 new xfails are ID-identical
  to fast r49→r51 (8 TestBadParameters
  missing-required-param, 9
  TestMissingPermission setup victims, 6
  CAMELLIA_CTR incl. the P11C-008 five, 2
  flags, 1 DES3_ECB derive probe). No
  KAT-vector unit moved. Zero pass→nonpass
  regressions, zero xfail→pass flips.
- KAT residuals, all dispositioned: the 24
  failures are identical by id to r26
  (13 X9.42 P11C-004 + 2 HOTP P11C-001 +
  3 WTLS P11C-006 + 6 SLH-DSA P11C-003).
- Bundle note: r50/r51/r27 run on the 11e
  bundle (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16).

## Round 27: MAC slice 11f (fast r51→r52→r53 + KAT r27→r28→r29)

- r52: 4169 passed / 18 failed / 657 xfailed /
  3574 skipped (t8418)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r52-results.json`).
  r51→r52: +121 pass / +0 fail / +26 xfail /
  +78 skip (+225 collected: the 9 new rows'
  shared-mech expansion, incl. 4 sign-KAT
  vector legs).
- Movers r51→r52 (unit `counts`, exact):
  `test_aes_modes` 13/17s → 26/4s (AES-MAC
  3 + MACGeneral 7 + XCBC 3, all green);
  `test_aria` 11/3s → 14/0s;
  `test_camellia` 12/3s/1x → 15/0s/1x;
  `test_mech_flags` 683/1298s/8x →
  719/1343s/8x; `test_mech_multipart`
  181/21s/17x → 199/21s/17x;
  `test_mech_negative` 235/2f/647s/262x →
  261/2f/667s/288x; `test_mech_probe` skips
  663 → 690 (new rows' probe legs);
  `test_mech_sign` 157/87s/17x →
  179/92s/17x (incl. the 4 ARIA/Camellia
  MAC KAT legs, all green).
- New-xfail attribution (26, all
  classified): 8 missing-required-param
  (expected `PARAM_INVALID`, got
  `ARGUMENTS_BAD`) on GMAC + the 3 GENERAL
  rows × sign/verify — same as every other
  row (pre-existing class); 18
  without-flag setup victims (9 mechs ×
  sign/verify, keygen rejected at runtime —
  P11C-005 class). No MAC row shows a new
  failure class: the XCBC verify path
  accepts CKK_AES (no `_XCBC_VERIFY_XFAIL`
  leg fired), and every KAT leg passes.
- Failures identical by id (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS
  P11C-006). Zero pass→nonpass.
- r53 (GMAC-width reproof): ID-identical to
  r52 (675/675 non-pass outcomes, zero
  transitions) — the width fix touches only
  KAT ACVP legs, as predicted.
- r28: 82591 passed / 24 failed / 1695
  xfailed / 30292 skipped (t114602)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r28-results.json`).
  r27→r28: +136 pass / +0 fail / +455 xfail /
  −366 skip (+225 collected).
- Fast-matrix units repeat r52 exactly
  (aes_modes, aria, camellia, flags,
  multipart, negative, probe, sign — same
  counts); the KAT-only delta is two GMAC
  suites: `test_gcm` 80/150s → 95/120s/15x
  (15 ACVP 128-bit GMAC legs pass — the
  GCM-route reduction verified against
  vectors — while 15 truncated legs xfail)
  and `test_wycheproof_aes` 1152/414s/253x →
  1152/0s/667x (414 GMAC legs xfail: the
  suite sends raw IV bytes, not the OASIS
  struct → P11C-010).
- In-slice fix (lane-found, r28→r29): OASIS
  v3.2 §6.13.6 determines the GMAC tag
  length by `ulTagBits`, so the fixed-128
  stance was wrong — GMAC now serves the SP
  800-38D approved widths (shared
  `gcmTagLens`, threaded through the
  existing AEAD spec; no driver change).
  Recipe, tests (ACVP tc16 pinned,
  unapproved widths refuse), and catalog
  note corrected.
- r29: 82606 passed / 24 failed / 1680
  xfailed / 30292 skipped (t114602)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r29-results.json`):
  +15 pass / −15 xfail, exactly the
  `AES-enc-tc16`–`tc30` legs xfail→pass;
  24 failures identical; 0 regressions.
- KAT residuals, all dispositioned: the 24
  failures are identical by id to r27
  (13 X9.42 P11C-004 + 2 HOTP P11C-001 +
  3 WTLS P11C-006 + 6 SLH-DSA P11C-003).
- Bundle note: r52/r53/r28/r29 run on the
  11f bundle (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16).

## Round 28: KDF-tail-core slice 11g (fast r53→r54→r55 + KAT r29→r30)

- r54: 4181 passed / 18 failed / 661
  xfailed / 3606 skipped (t8466)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r54-results.json`).
  r53→r54: +12 pass / +0 fail / +4 xfail /
  +32 skip (+48 collected).
- Movers r53→r54 (unit `counts`, exact):
  `test_hkdf_data_kat` 0/1s → 1 (the
  HKDF_DATA KAT passes through the C
  surface — FFI mech pass-through plus
  the DATA commit, verified end to end);
  `test_hkdf_extended` 2/3s/1x →
  5/0s/1x; `test_kdf` 16/4s → 20/0s
  (MD5/XOF legs); `test_mech_flags`
  719/1343s/8x → 723/1371s/12x;
  `test_mech_probe` skips 690 → 702.
- In-slice fix (lane-found, r54→r55):
  the 4 served catalog rows shipped
  mechanism-info flags `0UL` (the flip
  script set routes/support/notes but
  missed `mechanism_info.flags`), so the
  4 `test_expected_flags_present` legs
  xfailed. Flags set to `CKF_DERIVE` on
  the 4 rows + catalog regen; recipe,
  planner, driver, and tests untouched.
- r55: 4190 passed / 18 failed / 663
  xfailed / 3615 skipped (t8486)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r55-results.json`):
  +9 pass / +0 fail / +2 xfail / +9 skip
  (+20). The flags fix flips exactly
  (`test_mech_flags` 723/1371s/12x →
  727/1371s/8x); `test_mech_derive`
  20/9s/1x → 23/10s/1x;
  `test_mech_negative` 261/2f/667s/288x
  → 263/2f/675s/294x.
- New-xfail attribution (6, all
  classified): SHAKE BadParameters ×4 +
  MissingPermission ×2, every one
  "keygen rejected at runtime:
  CKR_MECHANISM_INVALID" — the oracle
  setups `C_GenerateKey` with the derive
  mechanism itself, and our refusal is
  the spec-correct RV. Identical legs
  xfail for the long-served SHA3_256_KD
  row (oracle `_kdf.py` overrides the
  registry with `param_required=True` on
  these NULL-param mechanisms). No
  module change.
- Failures identical by id (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS
  P11C-006). Zero pass→nonpass.
- r30: 82627 passed / 24 failed / 1686
  xfailed / 30333 skipped (t114670)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r30-results.json`).
  r29→r30: +21 pass / +0 fail / +6 xfail /
  +41 skip (+68) — the fast-matrix units
  repeat r53→r55 exactly
  (hkdf_data_kat, hkdf_extended, kdf,
  mech_derive, mech_flags, mech_negative,
  mech_probe — same counts); zero
  KAT-only delta (no vector suite covers
  the new rows beyond the matrix units).
- KAT residuals, all dispositioned: the 24
  failures are identical by id to r29
  (13 X9.42 P11C-004 + 2 HOTP P11C-001 +
  3 WTLS P11C-006 + 6 SLH-DSA P11C-003).
- Bundle note: r55/r30 run on the final
  11g tree (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16); r54 ran on the same
  tree minus the flags fix (behavior
  delta: mechanism-info flags only —
  the Haddock comment fix is
  behavior-free).

## Round 29: SP 800-108 slice 11h (fast r55→r56→r57 + KAT r30→r31)

- r56: 4208 passed / 26 failed / 663
  xfailed / 3640 skipped (t8537)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r56-results.json`).
  r55→r56: +18 pass / +8 fail / +0 xfail /
  +25 skip (+51 collected).
- Movers r55→r56 (unit `counts`, exact):
  `test_sp800_108_kdf` 15s → 7p/8f (the
  new unit executes: counter derives
  pass, feedback/double-pipeline refuse);
  `test_ffi_length_boundary` 70p/55s →
  75p/50s (boundary legs over the new
  rows pass); `test_mech_flags`
  727p/1371s/8x → 733p/1392s/8x;
  `test_mech_derive` skips 10 → 13;
  `test_mech_negative` skips 675 → 687;
  `test_mech_probe` skips 702 → 711.
- In-slice fix (lane-found, r56→r57):
  the oracle sends the iteration
  variable as NULL/0 (no format struct)
  in feedback and double-pipeline modes
  — only counter mode attaches the
  `CK_SP800_108_COUNTER_FORMAT` — and
  the FFI decoder required the struct in
  all modes, so 7 derives refused
  `CKR_ARGUMENTS_BAD`. The chaser now
  admits the NULL/0 placeholder (half-
  absent shapes still refuse) and the
  translator maps it to width 32 outside
  counter mode (inert downstream:
  planner and driver read the counter
  width in counter mode only); counter
  mode still refuses the placeholder.
  Recipe, planner, driver untouched;
  committed tests added (translator
  pins, NULL/0 consumer leg).
- r57: 4215 passed / 19 failed / 663
  xfailed / 3640 skipped (t8537)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r57-results.json`):
  +7 pass / −7 fail. The fix flips
  exactly (`test_sp800_108_kdf` 7p/8f →
  14p/1f — the only moving unit); zero
  pass→nonpass.
- The 1 remaining SP800 failure is the
  defined scope edge, not a bug:
  `TestSP800108CounterKDF::test_additional_derived_key_handles`
  requires multi-output derive
  (`ulAdditionalDerivedKeys != 0`), and
  11h serves single-output only (the
  decoder refuses nonzero additional
  counts). Queued for a later slice;
  the other 18 failures are identical
  by id to r55 (13 X9.42 P11C-004 + 2
  HOTP P11C-001 + 3 WTLS P11C-006).
- r31: 82652 passed / 25 failed / 1686
  xfailed / 30358 skipped (t114721)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r31-results.json`).
  r30→r31: +25 pass / +1 fail / +0 xfail /
  +25 skip (+51) — the fast-matrix units
  repeat r55→r57 exactly
  (ffi_length_boundary, mech_derive,
  mech_flags, mech_negative, mech_probe,
  sp800_108_kdf at 14p/1f); zero
  KAT-only delta (no vector suite covers
  the new rows beyond the matrix units).
- KAT residuals, all dispositioned: the
  25 failures are the r30 24 identical
  by id (13 X9.42 P11C-004 + 2 HOTP
  P11C-001 + 3 WTLS P11C-006 + 6 SLH-DSA
  P11C-003) plus the multi-output scope
  gap above.
- Bundle note: r57/r31 run on the final
  11h tree (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16); r56 ran on the same
  tree minus the absent-iter fix
  (behavior delta: the FFI decoder
  admits the NULL/0 iteration variable
  outside counter mode).

## Round 30: TLS protocol-KDF slice 11i (fast r57→r59 + KAT r31→r32)

- r59: 4257 passed / 19 failed / 663
  xfailed / 3752 skipped (t8691)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r59-results.json`).
  r57→r59: +42 pass / +0 fail / +0 xfail /
  +112 skip (+154 collected; r58 was the
  reverted EdDSA-NULL experiment
  snapshot, never a slice baseline).
- Movers r57→r59 (unit `counts`, exact):
  `test_tls12` 3p/34s → 22p/15s (the new
  rows derive and pass — master, DH,
  extended, free-label legs, zero
  failures); `test_ffi_length_boundary`
  75p/50s → 80p/45s (boundary legs over
  the new rows pass); `test_mech_flags`
  733p/1392s/8x → 751p/1455s/8x (the
  flags matrix over the new rows
  passes); `test_mech_attribute`,
  `test_mech_derive`, `test_mech_keygen`,
  `test_mech_negative`, `test_mech_probe`
  grow skips only (new-matrix instances
  that do not apply). +42 = 19 + 5 + 18.
- Zero regressions: the 19 failures are
  identical by id to r57 (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS
  P11C-006 + 1 SP800 multi-output scope
  gap). `test_x942_dh` does not move in
  fast (the paramgen legs are
  `@pytest.mark.slow` — KAT only).
- In-slice fix (recon-found, pre-lane):
  the KAT oracle requires
  `CKA_SUBPRIME_BITS` on the X9.42
  paramgen template
  (`test_parameter_gen_rejects_missing_subprime_bits`
  classifies `CKR_OK` as
  accepted-invalid), while the DSA arm
  defaults it per L (no DSA oracle leg
  probes the missing shape, so the
  default survives there). The shared
  size worker now takes a
  subprime-required flag: DSA defaults,
  X9.42 refuses `CKR_TEMPLATE_INCOMPLETE`
  (committed planner pin; JSON notes
  updated). No lane re-run was needed
  for the fix (fast carries no slow
  legs; DSA behavior byte-identical).
- r32: 82696 passed / 25 failed / 1687
  xfailed / 30467 skipped (t114875)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r32-results.json`).
  r31→r32: +44 pass / +0 fail / +1 xfail /
  +109 skip (+154 — the fast-matrix
  units repeat r57→r59 exactly).
- KAT-only delta (`test_x942_dh`
  1p/13f/21s/4x → 3p/13f/18s/5x): the two
  paramgen legs newly pass (generate +
  readback at 2048/256;
  missing-subprime refuses
  `CKR_TEMPLATE_INCOMPLETE`), and
  `test_generated_params_produce_valid_derive`
  runs to xfail inside the known
  P11C-004 area ("derive from generated
  params is not operational"), not in
  paramgen. The 25 failures are
  identical by id to r31.
- Bundle note: r59/r32 run on the final
  11i tree (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16; r32 on the bundle
  rebuilt after the subprime-required
  fix — behavior delta confined to the
  0x2002 missing-subprime refusal).

## Round 31: IKE protocol-KDF slice 11j (fast r59→r60 + KAT r32→r33)

- r60: 4298 passed / 19 failed / 663
  xfailed / 3779 skipped (t8759)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r60-results.json`).
  r59→r60: +41 pass / +0 fail / +0 xfail /
  +27 skip (+68 collected).
- Movers r59→r60 (unit `counts`, exact):
  `test_ike` 0p/33s → 33p/0s (every IKE
  leg derives and passes — prf+, PRF
  both role orders, v1 PRF, extended,
  plus the invalid-shape refusals; zero
  failures); `test_mech_flags`
  751p/1455s/8x → 759p/1483s/8x (the
  flags matrix over the new rows
  passes); `test_mech_derive`,
  `test_mech_negative`, `test_mech_probe`
  grow skips only (+4/+16/+12
  non-applicable matrix instances).
  +41 = 33 + 8; skips −33 + 28 + 4 +
  16 + 12 = +27.
- Zero regressions: the 19 failures are
  identical by id to r59 (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS
  P11C-006 + 1 SP800 multi-output scope
  gap).
- r33: 82737 passed / 25 failed / 1687
  xfailed / 30494 skipped (t114943)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r33-results.json`).
  r32→r33: +41 pass / +0 fail / +0 xfail /
  +27 skip (+68 — the fast-matrix
  units repeat r59→r60 exactly; no
  KAT-only delta: IKE carries no
  `@pytest.mark.slow` legs beyond
  fast's). The 25 failures are
  identical by id to r32.
- Proxy note (consumer parity, not the
  oracle lanes): the pinned proxy
  daemon virtualizes object handles per
  client session and translates
  top-level handles only — the
  param-embedded `hKeygxy` passes
  through untranslated, so the first
  proxied session coincides and later
  sessions fail `KEY_HANDLE_INVALID`
  (nondeterministic by daemon state).
  The two keygxy-carrying consumer legs
  run direct-only with the gap cited
  in-tree; the handle-free legs
  (prf+, PRF, garbage-image) run in
  both topologies and parity holds.
- Bundle note: r60/r33 run on the final
  11j tree (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16).

## Round 32: byte-op derive slice 11k (fast r60→r61 + KAT r33→r34)

- r61: 4329 passed / 19 failed / 683
  xfailed / 3813 skipped (t8844)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r61-results.json`).
  r60→r61: +31 pass / +0 fail / +20 xfail /
  +34 skip (+85 collected).
- Movers r60→r61 (unit `counts`, exact):
  `test_misc_kdf` 0p/12s → 9p/3x (the
  byte-op unit goes live: all concat
  and XOR KAT legs pass; the 3 EXTRACT
  legs xfail on the token's
  `CKR_TEMPLATE_INCOMPLETE` — the
  oracle passes no `CKA_VALUE_LEN`
  and lists that code in its own
  tolerated `_DERIVE_ERROR_RVS` set,
  matching SoftHSM which refuses the
  length-less extract the same way);
  `test_mech_derive` 23p/25s/1x →
  27p/25s/2x (the new +1 xfail is the
  generic XOR probe: base 32 bytes vs
  16-byte data trips the equal-lengths
  `CKR_DATA_LEN_RANGE` rule, which the
  oracle classifies "advertised but not
  operational"); `test_mech_negative`
  263p/735s/294x → 267p/735s/310x
  (the 16 new xfails are the 5-row
  malformed/missing-param and
  without-flag matrix legs joining the
  pre-existing "keygen rejected at
  runtime: `CKR_MECHANISM_INVALID`"
  population — the oracle's setup
  generates the second key via
  `C_GenerateKey` with the derive-only
  mechanism, which the token
  spec-correctly refuses — plus the
  lone concat-key wrong-key-type leg,
  same setup shape);
  `test_mech_flags`
  759p/1483s/8x → 769p/1518s/8x;
  `test_mech_probe` +15 skips;
  `test_arithmetic_overflow` +3p/−3s
  and `test_ffi_length_boundary`
  +1p/−1s (new-row security probes
  pass). +31 = 9 + 4 + 4 + 10 + 3 + 1;
  skips −12 + 35 + 15 − 3 − 1 = +34;
  xfails +3 + 1 + 16 = +20. Every new
  xfail is a new byte-op matrix leg
  (previously uncollected); no outcome
  moves pass→xfail or xfail→fail.
- Zero regressions: the 19 failures are
  identical by id to r60 (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS
  P11C-006 + 1 SP800 multi-output scope
  gap).
- r34: 82768 passed / 25 failed / 1707
  xfailed / 30528 skipped (t115028)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r34-results.json`).
  r33→r34: +31 pass / +0 fail / +20 xfail /
  +34 skip (+85 — the fast-matrix
  units repeat r60→r61 exactly; no
  KAT-only delta: byte-ops carry no
  `@pytest.mark.slow` legs beyond
  fast's). The 25 failures are
  identical by id to r33.
- Proxy note (consumer parity, not the
  oracle lanes): the pinned shim
  models the string-data shape, so the
  three string-data consumer legs run
  in both topologies and parity holds;
  the concat-key leg (param-embedded
  handle, same HandleMap gap as 11j's
  keygxy) runs direct-only with the
  gap cited in-tree. The garbage-image
  leg uses an undersized (8-byte)
  image: the shim forwards sub-shape
  images as unmodeled Raw (refused
  `CKR_MECHANISM_PARAM_INVALID` at
  the FFI boundary), while an
  oversized image would read as a
  struct prefix instead (probed).
- Bundle note: r61/r34 run on the final
  11k tree (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16).

## Round 33: TLS key-material trio slice 11l (fast r61→r62 + KAT r34→r35)

- r62: 4345 passed / 18 failed / 684
  xfailed / 3848 skipped (t8895)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r62-results.json`).
  r61→r62: +16 pass / −1 fail / +1 xfail /
  +35 skip (+51 collected).
- Movers r61→r62 (unit `counts`, exact):
  `test_sp800_108_kdf` 14p/1f → 15p/0f (the
  11l multi-output fix closes the
  `test_additional_derived_key_handles`
  scope gap — the only failure that
  moves, and it moves fail→pass);
  `test_tls12` 22p/15s/1x → 31p/5s/2x
  (the trio goes live: +9p/−10s; the
  new +1 xfail is the key-safe
  iv-ignore leg: the r62 bundle refused
  nonzero `ulIvSizeInBits` with
  `CKR_GENERAL_ERROR`, a genuine
  token-side miss at lane time, fixed
  in-slice before commit (§6.40.7: the
  size is ignored and treated as 0 —
  `normalizeTls12KeySafeParams`, pinned
  by `key-safe native struct ignores
  the IV size`);
  `test_mech_flags` 769p/1518s/8x →
  775p/1539s/8x; `test_mech_probe` +9
  skips; `test_mech_derive` +3 skips;
  `test_mech_negative`
  267p/2f/735s/310x → 267p/2f/747s/310x
  (new-row matrix legs join as skips;
  the 2 failures stay put). +16 = 1 +
  9 + 6; skips −10 + 21 + 9 + 3 + 12
  = +35; xfails +1 (key-safe only). No
  outcome moves pass→xfail or
  xfail→fail.
- Zero regressions: the 18 failures are
  the r61 set minus the fixed sp800
  leg (13 X9.42 P11C-004 + 2 HOTP
  P11C-001 + 3 WTLS P11C-006, all
  identical by id to r61).
- r35: 82785 passed / 24 failed / 1707
  xfailed / 30563 skipped (t115079)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r35-results.json`).
  r34→r35: +17 pass / −1 fail / +0 xfail /
  +35 skip (+51 — the same unit movers
  as fast, except `test_tls12` goes
  +10p/−10s/+0x: KAT r35 ran on the
  rebuilt bundle with the in-slice
  key-safe fix, so the iv-ignore leg
  passes there). The 24 failures
  are the 18 fast failures (identical
  by id) plus the 6 pre-existing
  KAT-only `test_acvp_slhdsa` legs.
- Bundle note: r62 ran on the 11l tree
  before the in-slice key-safe fix;
  r35 ran on the rebuilt final tree
  (`00559cc`,
  `dist-release/haskoki-0.3.0.0`).

## Round 34: PBE keygen pair slice 11m (fast r62→r63 + KAT r35→r36)

- r63: 4369 passed / 18 failed / 693
  xfailed / 3851 skipped (t8931)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r63-results.json`).
  r62→r63: +24 pass / +0 fail / +9 xfail /
  +3 skip (+36 collected).
- Movers r62→r63 (unit `counts`, exact):
  `test_pbe` 8p/25s → 19p/14s (the pair
  goes live: the 6 DES3 + 5 DES2
  "not supported" skips become passes;
  the remaining 14 skips are the
  unserved MD2/MD5/CAST/RC2/RC4/PBA
  rows); `test_ffi_length_boundary`
  81p/44s → 89p/36s (the 4+4 PBE
  security probes pass);
  `test_tls12` 31p/5s/2x → 32p/5s/1x
  (the key-safe iv-ignore leg flips
  xfail→pass: the 11l in-slice §6.40.7
  fix, first confirmed on a
  fresh-bundle fast lane — not an 11m
  code effect, and the 11m diff
  provably does not touch the DeriveKey
  path); `test_mech_flags`
  775p/1539s/8x → 779p/1553s/8x;
  `test_mech_probe` +6 skips;
  `test_mech_attribute` 141p/21s/78x →
  141p/23s/84x and `test_mech_keygen`
  47p/10s/63x → 47p/10s/67x (the 10 new
  xfails are all PBE matrix entries —
  2 generate, 4 local-flag, 2
  token-flag, 2 class — xfailed "keygen
  rejected at runtime:
  CKR_MECHANISM_PARAM_INVALID": the
  oracle setup generates without PBE
  params, which the token
  spec-correctly refuses, joining the
  pre-existing pre-master population).
  +24 = 11 + 8 + 1 + 4; skips −11 −8
  +14 +6 +2 = +3; xfails −1 + 6 + 4 =
  +9. No outcome moves pass→xfail or
  xfail→fail.
- Zero regressions: the 18 failures are
  identical by id to r62 (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS
  P11C-006).
- r36: 82808 passed / 24 failed / 1717
  xfailed / 30566 skipped (t115115)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r36-results.json`).
  r35→r36: +23 pass / +0 fail / +10 xfail /
  +3 skip (+36 — the fast-matrix units
  repeat r62→r63 exactly, minus the
  tls12 flip which KAT already carries:
  pbe +11p/−11s, ffi-boundary +8p/−8s,
  flags +4p/+14s, probe +6s, attribute
  +2s/+6x, keygen +4x; no KAT-only
  delta, PBE carries no `@slow` legs
  beyond fast's). The 24 failures are
  identical by id to r35 (the 18 fast
  failures plus the 6 pre-existing
  KAT-only `test_acvp_slhdsa` legs).
- Proxy note (consumer parity, not the
  oracle lanes): the pinned shim models
  the `pbe` param shape but drops the
  OUT IV, so the PBE roundtrip leg runs
  direct-only (KAT-exact) with a
  proxied-IV-unwritten pin, the same
  shape as 11k's embedded-handle
  limitation.
- Bundle note: r63/r36 run on the final
  11m tree (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16).

## Round 35: SSL3 quintet slice 11n (fast r63→r64 + KAT r36→r37)

- r64: 4413 passed / 18 failed / 709
  xfailed / 3892 skipped (t9032)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r64-results.json`).
  r63→r64: +44 pass / +0 fail / +16 xfail /
  +41 skip (+101 collected).
- Movers r63→r64 (unit `counts`, exact):
  `test_ssl3` 1p/20s/2x → 21p/2x (the
  quintet goes live: all 20 mechanism-gated
  skips flip to pass; the 2 xfails are the
  unchanged pre-master template legs);
  `test_crypto_weakness` 23p/4s → 25p/2s
  (the two SSL3 MAC deprecated-mechanism
  legs flip skip→pass, honestly flagged
  POODLE CRITICAL in the compliance notes);
  `test_mech_flags` 779p/1553s/8x →
  793p/1584s/8x; `test_mech_probe` 780s →
  795s; `test_mech_derive` +3s;
  `test_mech_negative` 267p/2f/747s/310x →
  275p/2f/759s/318x; `test_mech_multipart`
  +4x; `test_mech_sign` +2s/+4x.
  +44 = 20 + 2 + 14 + 8; skips −20 −2 + 31
  + 15 + 3 + 12 + 2 = +41; xfails +8 + 4 +
  4 = +16. No outcome moves pass→xfail or
  xfail→fail.
- The 16 new xfails are one population with
  one cause: the SSL3 MAC registry entries
  carry no `param_recipe` (default style
  `"none"`), so the generic sign/verify,
  multipart, and registry-negative matrix
  legs send NULL params, which the token
  spec-correctly refuses with
  `CKR_MECHANISM_PARAM_INVALID` — the same
  refusal the HMAC_GENERAL rows give NULL
  params. The oracle records these as
  "advertised but not operational" (sign,
  multipart) and wrong-key-type
  PARAM_INVALID-before-key-type-check plus
  MAC-row keygen rejection (negative).
  The dedicated `test_ssl3` MAC legs pass
  real bit-length params (128/160) and go
  20/20 green, grounding the BITS reading
  of `CK_MAC_GENERAL_PARAMS` for these two
  rows.
- Zero regressions: the 18 failures are
  identical by id to r63 (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS
  P11C-006).
- r37: 82852 passed / 24 failed / 1733
  xfailed / 30607 skipped (t115216)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r37-results.json`).
  r36→r37: +44 pass / +0 fail / +16 xfail /
  +41 skip (+101 — the fast-matrix units
  repeat r63→r64 exactly, unit for unit: no
  KAT-only delta, SSL3 carries no `@slow`
  legs beyond fast's). The 24 failures are
  identical by id to r36 (the 18 fast
  failures plus the 6 pre-existing
  KAT-only `test_acvp_slhdsa` legs).
- Proxy note (consumer parity, not the
  oracle lanes): the pinned shim models
  the 0x372 keymat shape natively (TLS1.2
  pattern, dummy phKey + 0x82
  embedded-handle pin), so only the
  `mac_general` override is load-bearing
  for the MAC rows (proven by negative
  control); master-row override dupes
  removed.
- Bundle note: r64/r37 run on the final
  11n tree (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16).

## Round 36: X9.31/POLY1305/EC-extra/DH-PKCS slice 11o (fast r64→r65 + KAT r37→r38)

- r65: 4357 passed / 20 failed / 3953
  skipped / 811 xfailed (t9141)
  (`/tmp/pkcs11-ws/out/fast/pkcs11-fast-r65-results.json`).
  r64→r65: −56 pass / +2 fail / +102
  xfail / +61 skip (+109 collected).
- Genuine 11o wins (all skip→pass, unit
  totals unchanged): `test_rsa_extended`
  0p/14s → 4p/10s (X9.31 legs live);
  `test_salsa20` 6p/5s → 9p/2s (3 flips
  on POLY1305 live); `test_remaining_gaps`
  +1p/−1s; `test_mech_multipart` +4p;
  `test_mech_sign` +4p; `test_mech_flags`
  +16p; `test_mech_attribute` +3p;
  `test_mech_keygen` +1p; `test_mech_probe`
  +15s (new-row probes).
- P11C-009 (now lane-active, oracle-side;
  filed statically in 11f, predicted this
  exact failure): the framework models
  `CKM_POLY1305` as `param_required=True`
  ("requires nonce param",
  `_ciphers.py:171-180`), but PKCS#11 v3.2
  gives POLY1305 no parameters. The token
  honestly accepts NULL (pinned:
  `casePoly1305InitParams` NULL-admit +
  `consumer_roundtrip.c` "poly1305 init
  ok" KAT) → 2 new fails
  (`test_registry_{sign,verify}_missing_required_param[POLY1305]`).
  Second oracle half: sign/verify legs
  lack digest's
  `_finish_digest_after_unexpected_ok`
  cleanup, so the unexpected-OK leaves an
  active op on the module-scoped session —
  94 cascade xfails report "got
  `CKR_OPERATION_ACTIVE`" (timestamp order
  proves the POLY1305 fail runs first).
  +2 POLY1305 `without_flag` xfails
  (keygen correctly refused:
  `CKR_MECHANISM_INVALID`, no
  `CKM_POLY1305_KEY_GEN` served).
- P11C-011 (new, oracle-side): the 2
  `test_mech_sign` `RSA_X9_31` xfails
  ("advertised but not operational") —
  the entry lacks the sibling-PSS
  `input_constraint="prehash"`, so the
  raw-digest row is fed 44-byte messages.
  +2 EC-extra matrix xfails
  (`CKA_LOCAL` readback gap, ours-class,
  pre-existing shape). Full +102 xfail
  accounting: 96 cascade + 2 POLY1305
  without_flag + 2 X9.31 + 2 EC-extra
  `CKA_LOCAL`.
- Zero shared-nodeid moves; the 18 old
  failures identical by id (13 X9.42
  P11C-004 + 2 HOTP P11C-001 + 3 WTLS
  P11C-006). The pass-count drop is 100%
  cascade noise + collection accounting,
  not behavior loss.
- r38: 82799 passed / 26 failed / 30665
  skipped / 1835 xfailed (t115325)
  (`/tmp/pkcs11-ws/out/kat/pkcs11-kat-r38-results.json`).
  r37→r38: −53 pass / +2 fail / +102
  xfail / +58 skip (+109 collected).
  KAT-only delta: `test_dh_key_agreement`
  10p/3s → 13p (DH-PKCS paramgen flips 3
  skips to pass); no KAT-vector unit
  moved. Cross-lane consistency at full
  strength: the 100 new non-passing
  negative legs are ID-identical to fast,
  and the 24 old failures are identical
  by id (18 fast + 6 SLH-DSA P11C-003).
- Bundle note: r65/r38 run on the final
  11o tree (`dist-release/haskoki-0.3.0.0`,
  evidence 16/16).

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
