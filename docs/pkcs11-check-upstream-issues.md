# pkcs11-check Upstream Issues Report: framework checkout 2026-09-26

**Generated**: 2026-09-26 03:10:00 UTC
**Status**: 🔄 in_progress
**Version**: framework at `/tmp/pkcs11-ws/pkcs11-check`
**Workflow**: pkcs11-coverage
**Phase**: detection
**Downstream**: Haskoki lanes (fast/KAT/targeted via `run-lane.sh`)

---

## Executive Summary

Candidate upstream issues found in the pkcs11-check oracle while
proving PKCS#11 v3.2 coverage. Each entry names the exact test ids,
shows the failure record, and states the downstream handling, so it
can be reported verbatim. Severity is downstream lane impact.

## Validation against 0.2.2rc1 (2026-09-27, fast lane)

From `/tmp/pkcs11-ws/out/fast-rc1/pkcs11-fast-rc1-results.json`
(3782 passed / 4 failed / 620 xfailed / 3286 skipped):

- P11C-001: FIXED (both HOTP hard fails gone).
- P11C-002: ADDRESSED oracle-side (expects
  CKR_KEY_SIZE_RANGE now); our over-max RV stays
  TEMPLATE_INCONSISTENT (ours, xfail-level).
- P11C-003: PROVEN in KAT-rc1 (`test_acvp_slhdsa`
  78/6f → 84/0f, same 84 collected; unit-count
  resolution — the harness omits pass records).
- P11C-004: FIXED (13 hard fails → 15 pass).
- P11C-005: STILL OPEN (same xfail shape).
- P11C-006: STILL OPEN (fixture byte-identical:
  `test_wtls.py:628-636`).
- New candidate P11C-007 below (x942 helper omits
  CKA_VALUE_LEN).

## Validation against 0.2.2rc2 (2026-09-28, fast lane)

Sdist `pkcs11_check-0.2.2rc2.tar.gz` (TestPyPI,
sha256 `9fbebe45…7a0`) unpacked to
`/tmp/pkcs11-ws/pkcs11-check-0.2.2rc2`, lane via
scratch `run-lane-rc2.sh` (rc1-script pattern, outputs
under `/tmp/pkcs11-ws/out-rc2/`). Bundle: 11l release
with the Notify fix below (258 rows). Result
(`out-rc2/fast/pkcs11-fast-results.json`): 4602 passed
/ 0 failed / 481 xfailed / 3846 skipped (first run:
4600/2, the 2 reds being the new callback-matrix legs
against our pre-fix 0x54 refusal; xfail/skip counts
identical across the re-run, so the fix regressed
nothing).

Per-filing verdicts (source check + lane evidence;
the harness omits pass records, so absence from the
non-pass set with the row collected means PASS):

- P11C-001: FIXED. Registry carries `CKK_HOTP` /
  `CKK_SECURID` / `CKK_ACTI` (`_misc.py:461-503`); the
  two legs run and xfail only on our RV stance
  (`KEY_TYPE_INCONSISTENT` expected, we answer
  `ARGUMENTS_BAD` — ours, xfail-level, uniform with
  the other sign/verify wrong-key legs).
- P11C-002: FIXED. `_KEY_SIZE_REJECT_RVS` is symbolic
  (`ATTRIBUTE_VALUE_INVALID`, `TEMPLATE_INCONSISTENT`,
  `ARGUMENTS_BAD`) and all four legs (RSA/DSA/AES/DH)
  pass with our uniform `TEMPLATE_INCONSISTENT`. Note:
  `CKR_KEY_SIZE_RANGE` left the set (rc1 expected it);
  no leg needs it now.
- P11C-004: FIXED. Fixtures verified independently:
  256-byte `g` (`3fb32c9b…cc41659`, matches the filing's
  expected head/tail), `g < p`, `q | p-1`, `g^q = 1`,
  Bob `y^q = 1`, `y = g^xB` for `xB = 0x81..0xA0`,
  trailing-32 secret matches. All 13 legs pass; the 2
  remaining xfails (`concatenate`/`asn1` other-info)
  are our unserved X9.42 KDF variants (module
  coverage note, future slice).
- P11C-005: FIXED. All 16 entries typed
  (`CKK_BLAKE2B_*_HMAC`); 32 of the 40 legs pass, the
  8 remaining xfails are the generic `CKA_LOCAL`
  readback gap (49+ legs across every keygen row —
  pre-existing ours, not BLAKE2B-specific).
- P11C-006: FIXED. Fixtures pass the 1-byte version
  (`mech_bytes` + `_WTLS_PRE_MASTER_VERSION`) with
  `attr_bool` flags; all 3 legs pass. (One
  `mech_simple` call remains at `test_wtls.py:958` —
  kept deliberately for the NULL-params negative leg.)
- P11C-007: FIXED. `_x942_derive_aes` pins
  `CKA_VALUE_LEN: 16`; `test_derived_key_encrypts`
  passes.
- P11C-008: FIXED. `ParamRecipe("ctr",
  {"counter_bits": 128})` added; the 5 filed legs
  pass. The 2 `missing_required_param` negative legs
  xfail on our uniform `ARGUMENTS_BAD`-for-missing-
  params stance (expected `MECHANISM_PARAM_INVALID`)
  — ours, xfail-level, shared with AES_CBC.
- P11C-009: FIXED in source (`param_required=False`).
  No lane impact (row still unadvertised); the fix
  unblocks serving `CKM_POLY1305` in a future slice.
- P11C-003: FIXED (source + runtime). Loader
  carries `context`, `mech_sign_context` wired; the
  rc2 KAT lane shows zero SLH-DSA non-pass records
  and zero failures overall.
- P11C-010: FIXED (correction of the first static
  read). The `mech_bytes` at `test_wycheproof_aes.py:717`
  is now only the 2.40-interface leg; 3.x sends a
  proper `mech_gcm` struct with `tag_bits` from the
  vector, and the test was rewritten to the
  C_Verify direction (the old C_Sign direction could
  never reject an invalid vector). All 414 GMAC
  vectors (324 invalid + 90 valid) run and pass
  against the 11l bundle (wycheproof_aes unit:
  1566 passed / 0 failed; the +414 pass delta vs
  rc1 is exactly the GMAC set). Precision note: the
  filing's "414 xfails" were 414 *skips* — every
  vector skipped at the `has_mechanism` gate in rc1
  (report.jsonl call-records), so the raw-bytes path
  was never exercised there.

KAT lane (`out-rc2/kat/pkcs11-kat-results.json`):
82995 passed / 0 failed / 1741 xfailed / 30751
skipped (rc1: 78484 / 4 / 4870). The 4 rc1 fails
were the same 3 WTLS + 1 x942 legs as fast (006,
007) — all pass now. Remaining xfails are our-side
classifications (RV stances such as AES-KW unwrap
codes, the generic `CKA_LOCAL` readback gap,
unserved OAEP label hashes / edwards-curveName
keygen); a scan for `accepted_invalid` /
`wrong_result` / crash / timeout hits only 3
benign xfail-level RV notes, no crypto breaks and
no new framework defects.

New from rc2 (module-side, NOT a P11C filing): the new
`test_open_session_callback_matrix` (4 legs) failed
its 2 callback legs against our `C_OpenSession`
refusal of non-NULL `Notify` with
`CKR_FUNCTION_NOT_SUPPORTED`. Spec check: v3.2 §5.6.1
lists no callback-refusal code for `C_OpenSession`,
so 0x54 was ours to fix, not upstream's to accept.
Fixed module-side (`cbits/standard_surface.c` accepts
`Notify`, retained nowhere, never invoked — the
module generates no notification events), pinned by a
per-table `consumer_errors` leg (open OK + usable +
zero invocations, direct-only), documented in
`docs/operations-notes.md`. Post-fix re-run: the 2
legs pass, 0 failed overall.

## P11C-001: HOTP registry entry has key_type=None; wrong-key-type tests HARD-FAIL every lane

**Severity**: medium (2 failing tests in every fast/KAT lane; masks real regressions)
**Component**: `src/pkcs11_check/testcases/test_mech_negative.py` (`TestWrongKeyType`) + mechanism registry (`MechConfig`)
**Found**: 2026-09-25 (first full-lane triage); still present 2026-09-26

The registry's HOTP entry carries `key_type=None`:

```python
MechConfig(key_type=None, keygen_mech=<CKM_HOTP_KEY_GEN: 0x290>, ...)
```

and the tests assert non-None:

- `test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[HOTP]`
- `test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[HOTP]`

Failure record (identical ids in fast r19–r28 and KAT r6–r10):

```text
AssertionError: assert None is not None
  +  where None = MechConfig(...).key_type
```

Expected: the HOTP registry entry gains its key type (or the tests
skip/xfail when the entry is incomplete), so the lane is clean and
a future real wrong-key-type regression is visible.

Downstream handling: Haskoki triages these 2 as known-external in
every round (`docs/pkcs11-oracle-triage.md`) and confirms by test id
that no other failure hides behind the count.

## P11C-002: `_KEY_SIZE_REJECT_RVS` carries wrong numeric CKR codes; correct refusals xfail

**Severity**: low (3 xfails per lane that should pass; masks no failures)
**Component**: `src/pkcs11_check/testcases/security/test_field_size_boundary.py`
**Found**: 2026-09-26 (DSA slice targeted r1)

The reject set names the intended codes in comments but carries
wrong numbers for four of the five entries:

```python
_KEY_SIZE_REJECT_RVS = (
    0x00000023,  # CKR_ATTRIBUTE_VALUE_INVALID  -- real: 0x13 (no CKR exists at 0x23)
    0x00000010,  # CKR_KEY_SIZE_RANGE           -- real: 0x62 (0x10 is ATTRIBUTE_READ_ONLY)
    0x0000000D,  # CKR_TEMPLATE_INCONSISTENT    -- real: 0xD1 (no CKR exists at 0x0D)
    0x00000007,  # CKR_ARGUMENTS_BAD            -- correct
    0x00000070,  # CKR_FUNCTION_NOT_SUPPORTED   -- real: 0x54 (0x70 is MECHANISM_INVALID)
)
```

(real values from the framework's own `raw/types_std.py`).
`classify_negative_rv` passes only `rv in expected_rvs`, so a
module answering the spec-correct `CKR_TEMPLATE_INCONSISTENT`
(0xD1) — as Haskoki does for RSA, DSA and AES alike — lands in
`xfail` ("honest non-spec deviation") instead of `pass`. No
provider-side code can pass: even a true `CKR_KEY_SIZE_RANGE`
(0x62) is absent from the set.

Affected ids (identical in targeted DSA r1; RSA/AES pre-date the
DSA slice and xfail the same way; DH joined in fast r41):

- `TestRsaModulusBitsOversizedValue::test_rsa_modulus_bits_oversized_value`
- `TestPrimeBitsOversizedValue::test_dsa_prime_bits_oversized_value`
- `TestGenerateKeyValueLenTruncation::test_aes_keygen_value_len_truncation`
- `test_dh_prime_bits_oversized_value` (DH slice fast r41:
  `C_GenerateKeyPair(DH, CKA_PRIME_BITS=0x100000400)`,
  got the intended `CKR_TEMPLATE_INCONSISTENT`, xfailed
  against the wrong tuple)

Expected: the tuple uses the symbolic `CKR_*` constants (or the
corrected numbers), so correct refusals pass.

Downstream handling: Haskoki keeps answering
`CKR_TEMPLATE_INCONSISTENT` (uniform with its RSA/AES planners,
and the intended-allowed code per the tuple's own comments) and
triages these xfails as framework-bug in
`docs/pkcs11-oracle-triage.md`.

## P11C-003: ACVP SLH-DSA sigver drops the vector context; valid context-bound signatures HARD-FAIL

**Severity**: medium (6 failing tests in every lane running `test_acvp_slhdsa.py`; masks real regressions)
**Component**: `src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py` (`_load_sigver_vectors` + `test_slhdsa_sigver`)
**Found**: 2026-09-26 (SLH-DSA slice targeted-slhdsa-r1)

The sigver loader merges `pk`/`message`/`signature` but never reads
the vector `context`:

```python
merged: dict[str, Any] = {
    "param_set": param_set,
    "param_name": param_name,
    "pk": bytes.fromhex(pk),
    "msg": bytes.fromhex(msg),
    "sig": bytes.fromhex(sig),
    ...
}
```

and the test verifies with bare NULL params:

```python
verified = verify_single(rs.raw, rs.sh, pub_key, CKM_SLH_DSA, vec["msg"], vec["sig"])
```

The ML-DSA counterpart (`test_acvp_mldsa.py`) passes the vector
context via `mech_sign_context` when non-empty; the SLH-DSA test
has no such path (no `context` mention in the file at all). Every
ACVP `testPassed=true` sigver vector with a non-empty context
therefore fails against any FIPS-205-correct module, which must
reject a context-bound signature under pure params. Failing ids
(targeted-slhdsa-r1, contexts 40..255 bytes):

- `test_slhdsa_sigver[sigVer-SLH-DSA-SHA2-128f-tc2]` (ctx 213)
- `test_slhdsa_sigver[sigVer-SLH-DSA-SHAKE-128f-tc87]` (ctx 255)
- `test_slhdsa_sigver[sigVer-SLH-DSA-SHAKE-192f-tc113]` (ctx 164)
- `test_slhdsa_sigver[sigVer-SLH-DSA-SHAKE-256f-tc143]` (ctx 40)
- `test_slhdsa_sigver[sigVer-SLH-DSA-SHA2-192s-tc284]` (ctx 112)
- `test_slhdsa_sigver[sigVer-SLH-DSA-SHAKE-192s-tc368]` (ctx 71)

Failure record (identical shape each):

```text
Failed: sigVer-SLH-DSA-SHA2-128f-tc2: rejected VALID SLH-DSA signature
```

Expected: the loader carries `context` and the test passes it via
`CK_SIGN_ADDITIONAL_CONTEXT` (mirroring the ML-DSA test), so
context-bound vectors verify and pure vectors keep NULL params.

Downstream handling: Haskoki triages these 6 as known-external in
every round (`docs/pkcs11-oracle-triage.md`) and confirms by test id
that no other failure hides behind the count. Module-side
context-verify is proven independently by the committed ACVP KAT
(OpenSSLSpec `caseSlhdsa`: tcId 266 under its 255-byte context,
tcId 343 pure).

## P11C-004: `test_x942_dh.py` fixtures contradict RFC 5114: corrupt generator + non-subgroup peer HARD-FAIL 13 tests

**Severity**: high (13 failing tests in every lane running `test_x942_dh.py`; masks real regressions; no module-side fix is possible — the domain itself is invalid)
**Component**: `src/pkcs11_check/testcases/test_x942_dh.py` (`X942_GEN`, `_X942_RFC5114_BOB_PUBLIC`, `_X942_RFC5114_EXPECTED_SECRET_32`)
**Found**: 2026-09-27 (DH slice fast-lane triage)

Two independent fixture defects, both verified byte-for-byte
against RFC 5114 (fetched 2026-09-27; `X942_PRIME_2048` and
`X942_SUBPRIME` in the same file verify byte-exact against
RFC 5114 §2.3, so the file means to cite that group):

**D1 — `X942_GEN` is not the RFC 5114 generator.** 257 bytes
where §2.3 gives 256; the first 11 bytes match
(`3fb32c9b73134d0b2e7750`) then byte 11 diverges (`0x62`
vs RFC `0x66`) and the tails differ entirely
(fw `...e4bf98b3a315b88d924b4c1eb4cf7113` vs RFC
`...5e2327cfef98c582664b4c0f6cc41659`). Worse than a
typo: the 257-byte value is **greater than the prime**,
so it cannot generate anything — OpenSSL's provider
rejects the explicit domain at import, and every
`_generate_x942_keypair` call (which hard-asserts
`CKR_OK`) fails. The genuine §2.3 `g` checks out fully:
`g < p`, `q | p-1`, `g^q = 1 mod p`, and the Appendix A.3
test data verifies under it (`yA = g^xA`, `yB = g^xB`,
agreement holds) — the corruption is confined to this
one constant.

**D2 — `_X942_RFC5114_BOB_PUBLIC` is outside the order-`q`
subgroup** (`y^q != 1 mod p` under the genuine
parameters; also not the Appendix A.3 `yB`). Any
`q`-validating provider — OpenSSL 4.0.2 included —
rejects it at peer import, so the exact-vector tests
cannot pass even after D1 is fixed. (The current
`_X942_RFC5114_EXPECTED_SECRET_32` is self-consistent
with the file's own `(alice, bob)` triple under the
rightmost-32 convention the framework's passing PKCS#3
truncation test also asserts — but it must be recomputed
for a valid peer.)

Failing ids (fast lane 2026-09-27; all raise from
`_generate_x942_keypair`'s `expect_rv(rv, CKR_OK)`):

- `TestX942DHKeyPairGen::test_keypair_generation`
- `TestX942DHKeyPairGen::test_keypair_has_correct_key_type`
- `TestX942DHKeyPairGen::test_keypair_prime_matches_params`
- `TestX942DHKeyPairGen::test_keypair_subprime_matches_params`
- `TestX942DHKeyPairGen::test_two_keypairs_have_different_public_values`
- `TestX942DHDerive::test_derive_shared_secret`
- `TestX942DHDerive::test_derived_key_encrypts`
- `TestX942DHDerive::test_x942_derive_rejects_missing_peer_public_value`
- `TestX942DHDerive::test_x942_derive_rejects_malformed_peer_public_value`
- `TestX942DHDerive::test_x942_derive_rejects_ckd_null_other_info`
- `TestX942DHDerive::test_x942_derive_rejects_asn1_kdf_missing_other_info`
- `TestX942DHDerive::test_x942_derive_rejects_invalid_kdf`
- `TestX942DHDerive::test_different_exchanges_produce_different_secrets`

Failure record (identical shape each; the code changed
when Haskoki added its DH structural floor — the tests
still expect `CKR_OK` on the invalid domain, so they
stay failing either way):

```text
r41 and earlier: CkrAssertionError: Unexpected CK_RV CKR_GENERAL_ERROR; expected one of: CKR_OK
r42 onward:      CkrAssertionError: Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT; expected one of: CKR_OK
```

(`CKR_TEMPLATE_INCONSISTENT` is the planner naming the
defect: "DH generator outside 2 <= g < p".)

Blocked-but-xfailed (not failing): `test_x942_dh_derive_rfc5114_exact_vector`,
`test_x942_dh_derive_rfc5114_value_len_truncation`,
`test_x942_dh_derive_rfc5114_rejects_zero_value_len`,
`test_x942_dh_derive_concatenate_other_info`,
`test_x942_dh_derive_asn1_other_info` — setup/derive
xfails on the runtime-reject sets.

Expected: `X942_GEN` is replaced with the RFC 5114 §2.3
generator (256 bytes, `3fb32c9b73134d0b2e77506660edbd48...`
`...5e2327cfef98c582664b4c0f6cc41659`), and the
Alice/Bob fixtures become an in-subgroup pair with a
matching expected secret. One verified replacement that
reuses the file's own private scalars
(`ALICE = bytes(range(0x01, 0x21))`,
`BOB_PRIV = bytes(range(0x41, 0x61))`, the existing
`_X942_EXTENDED_BOB_PRIVATE_1`) under the genuine group:

```text
BOB_PUBLIC = G^BOB_PRIV mod P =
  411d7ef795062d5d056de20282c21e1be2c6a1ab9a2c4bf22ae2397
  4141313d5b3453473a0372f719cfdc07a9b69bbc6efc9fe458f292f5
  bffaff77dd7ef7c9b1366d96fecb9bbf7ad56157704c65455ddce8c1
  40f62ac6ec94b52279e2f5795bd6268a4f4d26b7aca1e8e40a6cc34c
  bf9c890feaca388a8dfc379e4e0d346a11a378805f0fa5360d34727d
  da7361853526a431987e80197a58281d360b8f5d99f93a99cdf68f49
  87f4673df20f047b5930c8b93056fe784022a560addf9eab56dc7e68
  2dc2eb11bb598f30366ec6fa1551d2f4507e35532775cb9ca933719e
  48adf59b9a4caf2d84d5214e3b297c8536dbf28e243355a983c7c079
  3aa2208ff
EXPECTED_SECRET_32 = trailing-32(BOB_PUBLIC^ALICE mod P) =
  3f082dd9af91404c2bac1714cf1d7d8f16d910d272c356824737182a3ac0e273
```

(`y^q = 1` verified for the suggested peer.)

Downstream handling: Haskoki triages these 13 as
known-external in every round
(`docs/pkcs11-oracle-triage.md`) and confirms by test id
that no other failure hides behind the count. No
module-side change: the token's behavior is proven
correct by a C-ABI probe against the release bundle
(genuine-domain keygen `CKR_OK` + KAT-exact derive,
corrupt-`g` keygen fails closed with
`CKR_TEMPLATE_INCONSISTENT` ("DH generator outside
2 <= g < p") and no handles, non-subgroup peer refused
`MECHANISM_PARAM_INVALID`) — the fixtures are the defect.

**Open question (not a defect report): zero-length
`CKA_VALUE_LEN`.** Both DH derive files expect
`CKR_KEY_SIZE_RANGE`/`CKR_ATTRIBUTE_VALUE_INVALID` for
`CKA_VALUE_LEN=0`; Haskoki answers
`CKR_TEMPLATE_INCONSISTENT` from its central derive
planning (uniform across HKDF/ECDH/SHA-KDF/PBKDF2/DH;
no ECDH/HKDF counterpart test pins a different code).
Currently xfail, asked upstream to accept
`TEMPLATE_INCONSISTENT` or justify the narrower set.

## P11C-005: BLAKE2B registry uses `CKK_GENERIC_SECRET` as the keygen template key type; 40 shared-mech legs xfail on correct `TEMPLATE_INCONSISTENT`

**Severity**: medium (40 xfails per lane that should pass;
masks real regressions in the shared mech files)
**Component**: `src/pkcs11_check/testcases/mechanism_registry/_hmac.py`
(BLAKE2b block) + keygen template construction in
`src/pkcs11_check/testcases/mechanism_helpers.py`
**Found**: 2026-09-27 (slice 11a keygen sweep, fast r44/r45)

All 16 BLAKE2B registry entries carry
`key_type=CKK_GENERIC_SECRET`:

```python
registry[CKM_BLAKE2B_512_HMAC] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_512_KEY_GEN,
    ...
)
registry[CKM_BLAKE2B_512_KEY_GEN] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_512_KEY_GEN,
    ...
)
```

(and likewise for the 160/256/384 widths and the
`_HMAC_GENERAL` / `_KEY_DERIVE` entries), while every
SHA-family HMAC entry carries its typed `CKK_SHA*_HMAC`.
The keygen path stamps the registry key type straight
into the template (`mechanism_helpers.py`:

```python
key_type = config.key_type
...
if key_type is not None:
    attrs[CKA_KEY_TYPE] = key_type
```

), so every shared-mech leg calls
`C_GenerateKey(CKM_BLAKE2B_*_KEY_GEN)` with
`CKA_KEY_TYPE=CKK_GENERIC_SECRET` in the template.

Per the OASIS sources
(`working/doc/spec/hash_based_message_authentication_codes.md`),
`CKM_<hash>_KEY_GEN` "generates HMAC keys of key type
**CKK_\<hash\>_HMAC**" and "contributes the **CKA_CLASS**,
**CKA_KEY_TYPE**, and **CKA_VALUE** attributes to the new
key" — a template-supplied `CKA_KEY_TYPE` that disagrees
must fail with `CKR_TEMPLATE_INCONSISTENT`. Haskoki
answers exactly that (uniform central keygen planner);
the framework records it as a runtime-reject xfail:

```text
XFailed: BLAKE2B_512_KEY_GEN keygen rejected at runtime:
CKR_TEMPLATE_INCONSISTENT
```

Affected legs (fast r45, 40 total, identical ids in
r44): `test_mech_attribute.py` 16 (`test_key_type_matches_template`,
`test_local_flag_on_generated_key`,
`test_token_flag_matches_template`, `test_class_attribute`
x 4 widths), `test_mech_keygen.py` 8
(`test_generate_key`, `test_local_flag` x 4 widths),
`test_mech_multipart.py` 4, `test_mech_negative.py` 8,
`test_mech_sign.py` 4 (all keyed on the 512-bit HMAC
entries, failing at the shared keygen step).

Subtlety (recorded so the fix lands in the right
place): generic-secret keys are NOT illegal for the
HMAC operation itself — the same spec section says "The
HMAC secret key shall correspond to the PKCS #11
generic secret key type or the mechanism specific key
types". The defect is only the *keygen template*: keys
usable with `CKM_BLAKE2B_*_HMAC` cannot be *created*
by `CKM_BLAKE2B_*_KEY_GEN` under a generic-secret
`CKA_KEY_TYPE`.

Expected: the four `CKM_BLAKE2B_*_KEY_GEN` registry
entries (and the keygen step of the HMAC/HMAC_GENERAL
entries, which generates via the typed keygen) request
the typed `CKK_BLAKE2B_*_HMAC` key types, matching the
SHA-family shape; the sign legs then run against typed
keys, which the spec allows.

Downstream handling: Haskoki triages these 40 as
known-external (`docs/pkcs11-oracle-triage.md`, Round
22) and confirms by test id that no other failure
hides behind the count. No module-side change: the
typed `CKK_BLAKE2B_*_HMAC` key types exist in the v3.2
headers (0x3a–0x3d), Haskoki's keygen plan matches
them, and the rejection code is the spec-mandated one.
(The 6 remaining `test_blake2.py` xfails are separate
Haskoki RV-choice/behavior notes, not part of this
filing.)

## P11C-006: WTLS pre-master keygen fixtures omit the required version parameter and encode `CK_BBOOL` attributes as 8-byte `CK_ULONG`; 3 HARD-FAILs

**Severity**: high (3 failing tests in every lane since the
WTLS keygen row was advertised; masks real regressions)
**Component**: `src/pkcs11_check/testcases/test_wtls.py`
(`TestWTLSPreMasterKeyGen`)
**Found**: 2026-09-27 (slice 11a keygen sweep, fast r44/r45)

All three keygen tests build the mechanism with
`mech_simple` (NULL params, length 0 — `raw/pack.py:462`)
and encode the four boolean template attributes with
`attr_ulong` (8-byte `CK_ULONG` — `raw/pack.py:272`):

```python
mech = mech_simple(CKM_WTLS_PRE_MASTER_KEY_GEN)
tmpl = template(
    attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
    attr_ulong(CKA_VALUE_LEN, 20),
    attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
    attr_ulong(CKA_DERIVE, 1),
    attr_ulong(CKA_SENSITIVE, 0),
    attr_ulong(CKA_EXTRACTABLE, 1),
    attr_ulong(CKA_TOKEN, 0),
)
```

(identical shape at lines 628, 722, 814). Two
independent spec violations:

1. `CKM_WTLS_PRE_MASTER_KEY_GEN` "has one parameter, a
   **CK_BYTE**, which provides the client's WTLS
   version" (OASIS `working/doc/spec/wtls.md:251).
   The fixture passes no parameter at all.
2. `CKA_DERIVE` / `CKA_SENSITIVE` / `CKA_EXTRACTABLE` /
   `CKA_TOKEN` are `CK_BBOOL` (1 byte); the fixture
   sends 8-byte `CK_ULONG` values. The framework's own
   `attr_bool` (`raw/pack.py:261`) is the correct
   encoder.

Failure record (identical ids in r44/r45):

```text
test_wtls.py::TestWTLSPreMasterKeyGen::test_generate_pre_master_key
test_wtls.py::TestWTLSPreMasterKeyGen::test_generate_yields_non_zero_material
test_wtls.py::TestWTLSPreMasterKeyGen::test_two_generated_keys_differ
CkrAssertionError: Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT;
expected one of: CKR_OK
```

Proof the module is correct and the fixtures are the
defect: a corrected scratch fixture
(`mech_bytes(CKM_WTLS_PRE_MASTER_KEY_GEN, b"\x01")` +
`attr_bool` for the four flags) passes 4/4 against the
*unmodified* release bundle
(`/tmp/pkcs11-ws/out/targeted/pkcs11-targeted-wtls-fixed-r1.json`:
4 passed / 0 failed). Haskoki's `TEMPLATE_INCONSISTENT`
comes from its central template planner (the template
carries undecodable attributes); the filing asserts the
fixture malformation, proven by the corrected fixture
passing — not that 0xD1 is the only valid code for the
malformed call.

Expected: the three tests pass the 1-byte version
parameter and use `attr_bool` for the boolean
attributes, after which they should pass against
any compliant module.

Downstream handling: Haskoki triages these 3 as
known-external (`docs/pkcs11-oracle-triage.md`, Round
22) and confirms by test id that no other failure
hides behind the count. No module-side change.

## P11C-007 (candidate): `_x942_derive_aes` omits `CKA_VALUE_LEN`; its PKCS#3 twin pins 16

**Severity**: low (1 failing test in the rc1 fast lane)
**Component**: `src/pkcs11_check/testcases/test_x942_dh.py`
(`_x942_derive_aes`) vs `test_dh_key_agreement.py`
**Found**: 2026-09-27 (rc1 validation)

`_x942_derive_aes` (`test_x942_dh.py:967`) derives a
`CKK_AES` key with CLASS/KEY_TYPE/SENSITIVE/
EXTRACTABLE/TOKEN only — no `CKA_VALUE_LEN`. The
equivalent PKCS#3 helper pins `CKA_VALUE_LEN: 16`.
A module that defaults a missing length to the full
DH secret width stores an unusable oversized "AES"
key, and the leg fails downstream at `C_Encrypt`
instead of at derive time:

```text
test_x942_dh.py::TestX942DHDerive::test_derived_key_encrypts:
C_Encrypt size query: Unexpected CK_RV CKR_GENERAL_ERROR;
expected one of: CKR_OK, CKR_BUFFER_TOO_SMALL
```

Suggested fix: pin `CKA_VALUE_LEN: 16` in
`_x942_derive_aes` like the PKCS#3 twin.

Downstream handling: Haskoki hardens its own side
separately (derive-time length-domain validation so
a missing length on a fixed-length target refuses
with TEMPLATE_INCONSISTENT instead of producing a
poisoned object); the leg itself needs the helper
fix. Tracked in `docs/pkcs11-oracle-triage.md` (rc1
validation). No module-side change for the oracle
half.

## P11C-008 (candidate): `CKM_CAMELLIA_CTR` registry entry lacks `param_recipe`; generic probes send NULL

**Severity**: low (5 xfail legs in the fast lane)
**Component**: `src/pkcs11_check/testcases/mechanism_registry/_ciphers.py`
(`registry[CKM_CAMELLIA_CTR]`) vs `_aes.py`
(`registry[CKM_AES_CTR]`)
**Found**: 2026-09-28 (11e fast r51 triage)

`registry[CKM_CAMELLIA_CTR]` (`_ciphers.py:238`) sets
`param_required=True` but no `param_recipe`, so the default
`ParamRecipe(style="none")` applies and every generic probe
(roundtrip, multipart, termination, wrong-key-type ×2) sends
NULL params. The module correctly refuses with
`CKR_ARGUMENTS_BAD` (missing required params — the same code it
returns for every cipher row, e.g. AES_CBC); the legs xfail as
"advertised but not operational". The AES_CTR twin carries
`param_recipe=ParamRecipe("ctr", {"counter_bits": 128})`
(`_aes.py:217`) and its legs pass.

Suggested fix: add
`param_recipe=ParamRecipe("ctr", {"counter_bits": 128})` to the
CAMELLIA_CTR entry.

Note: `test_camellia.py::TestCamelliaCTR::`
`test_camellia_ctr_different_nonces` is NOT this issue — it
deliberately sends `bits=32`, which the module refuses under
its documented 128-bit-only CTR stance (shared with AES_CTR;
see the `CKM_CAMELLIA_CTR` row note in
`spec/mechanisms.json`).

Downstream handling: none needed module-side; the 5 legs
xfail honestly until the registry fix. No module change.

## P11C-009 (candidate): `CKM_POLY1305` registry entry is self-contradictory (`param_required=True` with a `none` recipe)

**Severity**: low (no current lane impact — the row is
unadvertised so the legs skip; blocks serving the row)
**Component**: `src/pkcs11_check/testcases/mechanism_registry/_ciphers.py`
(`registry[CKM_POLY1305]`, line 171) +
`test_mech_negative.py` +
`testcases/conftest.py::classify_negative_rv`
**Found**: 2026-09-28 (11f ranking)

The entry sets `param_required=True` with
`param_recipe=ParamRecipe("none")` and the note "requires
nonce param". But the OASIS header defines no
`CK_POLY1305_PARAMS` (`spec/vendor/pkcs11.h`: only the
`CKM_POLY1305` / `CKK_POLY1305` / `CKM_POLY1305_KEY_GEN`
ids; the only Poly1305 param structs are the AEAD
`CK_SALSA20_CHACHA20_POLY1305_*`): standalone
`CKM_POLY1305` takes no parameters (RFC 8439 one-time
authenticator: 32-byte key, no nonce). The entry's own
roundtrip recipe (`none`) agrees.

Consequence: no module behavior passes both legs. Accept
NULL params → the sign+verify missing-required-param legs
**fail** (`accepted_invalid`: `CKR_OK` where a reject was
expected). Refuse NULL → the roundtrip and KAT legs xfail
as not-operational while the negative legs pass. Either
way the lane misreports a correct module.

Suggested fix: `param_required=False` (and drop "requires
nonce param" from the note).

**Lane activation (11o, fast r65 + KAT r38)**:
`CKM_POLY1305` is now served, and the pinned framework
still carries the entry, so the predicted failure
occurred verbatim — 2 fails, ID-identical in both
lanes:
`TestBadParameters::test_registry_sign_missing_required_param[POLY1305]`
and the verify twin (`accepted_invalid`: `CKR_OK`
where a reject was expected; the token is correct —
standalone POLY1305 takes no parameters, pinned by
`casePoly1305InitParams` NULL-admit and the
`consumer_roundtrip.c` "poly1305 init ok" KAT).
Second oracle half, same event: the sign/verify legs
lack digest's `_finish_digest_after_unexpected_ok`
cleanup, so the unexpected-OK leaves an active op on
the module-scoped session and 94 following legs xfail
with "got `CKR_OPERATION_ACTIVE`" (timestamp order
proves the POLY1305 fail runs first; the 100 new
non-passing negative legs are ID-identical across
lanes). rc2 fixed the entry in source, but lanes run
the pinned framework, where it is still live.

Downstream handling: triaged as known-external in
Round 36; no module change (accepting NULL params is
the spec-correct behavior).

## P11C-010 (candidate): wycheproof GMAC sends raw IV bytes instead of `CK_GCM_PARAMS`

**Severity**: low (414 legs affected in the KAT lane)
**Status**: FIXED in 0.2.2rc2 (struct on 3.x +
C_Verify direction; all 414 pass — see the rc2
validation section)
**Component**: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py`
(`test_aes_gmac`, line ~700) vs
`src/pkcs11_check/testcases/acvp/aes/test_gcm.py`
(`test_acvp_aes_gmac`)
**Found**: 2026-09-28 (11f KAT r28 triage)

The wycheproof GMAC test passes the IV as raw mechanism
bytes (`mech_param=mech_bytes(CKM_AES_GMAC, iv)`), while the
ACVP sibling test for the same mechanism sends the OASIS
`CK_GCM_PARAMS` struct. OASIS v3.2 §6.13.6 defines GMAC
parameters as `CK_GCM_PARAMS` (tag length by `ulTagBits`, IV
by `ulIvLen`); raw bytes are not a conformant shape, so a
strict module refuses them, so no vector in the group
can exercise genuine verification — including 90
valid vectors the module would otherwise verify.
(Precision: in the rc1 lane these 414 showed as
*skips*, not xfails — every vector skipped at the
`has_mechanism` gate (report.jsonl call-records:
414 skipped / 0 run), so the raw-bytes path was
never exercised there. The source defect was real
regardless.)

Suggested fix: build the `CK_GCM_PARAMS` struct (as the
ACVP test does), with `ulTagBits` from each vector's tag
length.

Downstream handling: none needed module-side; the legs
xfail honestly until the test is fixed. No module change.
(Raw-IV tolerance was considered and rejected: OASIS
mandates the struct, and a second shape would be unpinned
speculation.)

## P11C-011 (candidate): `CKM_RSA_X9_31` registry entry lacks `input_constraint="prehash"`; raw-digest row fed 44-byte messages

**Severity**: low (2 xfails per lane that should pass;
the SHA-1 message row is unaffected)
**Component**: `src/pkcs11_check/testcases/mechanism_registry/_rsa.py`
(`registry[CKM_RSA_X9_31]`, line 169) vs
`test_mech_sign.py::test_roundtrip` (line 201)
**Found**: 2026-09-29 (11o fast r65 triage)

The entry's own note says "RSA X9.31 sign/verify with
pre-hash", but unlike the sibling raw-PSS entry
(`registry[CKM_RSA_PKCS_PSS]`, line 143, which carries
`input_constraint="prehash"`), it sets no input
constraint. `test_roundtrip` therefore feeds the raw
row the default 44-byte message (`b"hello pkcs11 sign
test" * 2`) instead of a digest. Raw X9.31 signs
digests only (20/32/48/64 bytes select the hash id),
so any correct module refuses, and the legs xfail:

```text
test_roundtrip[RSA_X9_31]: RSA_X9_31:sign: advertised but
  not operational (CKR_MECHANISM_INVALID)
test_tampered_data_fails_verify[RSA_X9_31]: same
```

(ID-identical in fast r65 and KAT r38; the
`CKM_SHA1_RSA_X9_31` message row shows no non-pass
records — it hashes inside, so 44-byte input is
correct for it.)

Suggested fix: `input_constraint="prehash"` on
`registry[CKM_RSA_X9_31]` (the leg then feeds 32-byte
SHA-256 digests, which the row signs).

Downstream handling: triaged as known-external in
Round 36. Token-side note (ours, scheduled, not in
11o — lanes already ran): a digest-size violation is
a DATA problem, but the token answers
`CKR_MECHANISM_INVALID` (length-map miss surfaces as
`BackendUnsupported`); the spec-plausible code is
`CKR_DATA_LEN_RANGE`. Fixing the RV does not un-xfail
the legs (the input stays 44 bytes until the entry
gains `prehash`), so the framework entry is the
blocking half.

## Observations (not issues)

- **`mech_hkdf` docstring/comment says
  `CKF_HKDF_SALT_KEY = 3`** (`raw/pack_mechanisms.py:707`
  comment + docstring example); the real value is
  `0x00000004` per the framework's own
  `raw/types_std.py:2516` (bit flags 1/2/4). Comment-only:
  no caller passes an explicit `salt_type` (all use the
  correct 1/2 default), so zero lane impact. Not filed.
- **Wycheproof XTS tc1–tc120 labeled "valid" with 1–15-byte
  tweaks**: inexpressible in PKCS#11 (the `CKM_AES_XTS` tweak
  parameter is fixed 16 bytes), so every compliant module must
  reject them; the framework already xfails them as runtime
  rejects (`_xfail_if_aes_runtime_reject`). Labels come from the
  Wycheproof corpus, handling is by design — recorded here only
  because "121 xfailed valid vectors" reads alarming in KAT
  reports. No report needed.
- **ACVP XTS bit-level vectors skip** (non-byte-aligned
  payloadLen/dataUnitLen): by design, PKCS#11 takes byte strings.
  Not a gap.
- **AES_XTS registry without-flag legs self-xfail** when XTS
  keygen is absent (`CKM_AES_XTS_KEY_GEN` catalog-only): by
  design. Not a gap.
- **Pinned-framework fast r62 (2026-09-28, 11l/258 rows):
  no new upstream findings.** 4345 passed / 18 failed; all
  18 fail identically in r61 (HOTP wrong-key-type x2,
  WTLS x3, X9.42 x13 — pinned-framework behavior already
  covered by P11C-001/004/006/007, fixed in rc2). The
  trio unlocked 10 `test_tls12` legs (9 pass); the 1 new
  xfail (`test_key_safe_derive_ignores_iv_size_request`)
  was our `CKR_GENERAL_ERROR` on nonzero
  `ulIvSizeInBits`, fixed in-slice (§6.40.7: the size is
  ignored and treated as 0). Nothing to file.
- **Pinned-framework fast r63 + KAT r36 (2026-09-29,
  11m/260 rows): no new upstream findings.** Fast 4369
  passed / 18 failed, KAT 82808 passed / 24 failed; all
  failures identical by id to r62/r35 (HOTP
  wrong-key-type x2, WTLS x3, X9.42 x13, KAT-only
  ACVP SLH-DSA x6 — pinned-framework behavior already
  covered by P11C-001/003/004/006, fixed in rc2). The
  PBE pair unlocked 11 `test_pbe` legs (all pass) plus
  8 `test_ffi_length_boundary` probes; the 10 new
  xfails are PBE keygen-matrix legs whose setup
  generates without PBE params (correct
  `CKR_MECHANISM_PARAM_INVALID`, joining the
  pre-existing pre-master population — same setup
  shape as P11C-006, but the token refusal is the
  spec-correct verdict, not an oracle bug). The
  key-safe iv-ignore leg flips xfail→pass on the
  fresh bundle (11l in-slice fix confirmed). Nothing
  to file.
- **Pinned-framework fast r65 + KAT r38 (2026-09-29,
  11o/270 rows): 11o-mechanism coverage census.**
  `CKM_DH_PKCS_PARAMETER_GEN`: covered — dedicated
  `has_mechanism`-gated legs in
  `test_dh_key_agreement.py:1266` flip 3 skips to
  pass in KAT. `CKM_RSA_X9_31` /
  `CKM_SHA1_RSA_X9_31`: covered by `test_rsa_extended`
  (4 skip→pass) plus the sign matrix; the 2
  `RSA_X9_31` roundtrip xfails are P11C-011 (missing
  `prehash` input constraint), not missing coverage.
  `CKM_POLY1305`: covered by the negative/keygen/
  attribute matrix; the 2 fails are the activated
  P11C-009, not missing coverage.
  `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS`: availability
  leg (`test_ec_key_pair_gen_w_extra_bits_availability`)
  plus the generic keygen/flags/probe/attribute
  matrix only — no functional legs exist, but none
  can: the row's sole distinction over
  `CKM_EC_KEY_PAIR_GEN` is keygen-internal
  randomness (FIPS 186-5 B.4.2), unobservable
  black-box. The 2 matrix xfails are the generic
  `CKA_LOCAL` readback gap (ours-class,
  pre-existing). Not filed: matrix exercise is the
  achievable ceiling, and our planner pin
  (`caseEcExtraBitsPlanner`) covers the plan shape.

## Message routing verification (2026-09-30)

The source definition counts are pins; runtime dispositions and oracle findings remain separate. Routing adds no mechanism capability.

```json
{
  "source_revision": "6610ca8426b4fecb6600be523894fef9ec55d860",
  "oracle_release": "0.2.2rc2",
  "oracle_source_sha256": "b7b5327c4294a892fcf21f351717bb240b2505621ce842c182b33cf6685bad23",
  "source_test_definitions": {
    "test_mech_message.py": 26,
    "test_message_crypto.py": 13
  },
  "oracle_test_source_sha256": {
    "test_mech_message.py": "9ca83808f62e627a3525bc89c70e5bc869dadcb682965f61ab4adae3b7c8fa8c",
    "test_message_crypto.py": "8cb53777a320ead60bb385297d29f3e7773ed8585b48067e48808e335fec3234"
  },
  "protected_sha256": {
    "spec/vendor/pkcs11.h": "61e0b3f996fa9f095859d7d3b8e361d0b982de69fc8b6a4bf10291afbe7e24d8",
    "spec/sources.lock.json": "ec5d02a83c1523a79f8da9c65e6f258b8927410febe20501b5327815c87422ad",
    "spec/mechanisms.json": "40090818ed79093380959ecf47f8b24d12e0661541bf9f9c07124fbae12265e6",
    "cbits/mech_catalog.inc": "5e209f36551177cb8e1cfdaa2380a47d70c9caa9eba60adbb4512ca182bfac63"
  },
  "toolchain_image": "sha256:ba329f78938e1cef9ed163f86c1d7ac01db047259ec556d2e0027077b8ea41be",
  "scope": "function routing; unchanged 316-mechanism catalog",
  "proxy_message_scenario": {
    "mode": "DIRECT-ONLY",
    "reason_url": "https://github.com/mingulov/pkcs11-proxy-ng/issues/23",
    "decision": "coordinator override; message transport unavailable in pinned proxy",
    "notice_observed": true
  },
  "comparison_inputs": {
    "fast": {
      "path": "dist-release-evidence/message-routing/fast-before-pkcs11-fast-results.json",
      "sha256": "c36238b7af6f229c65e6d21a3a2f086e13d7b6b1c7c6484794a9d85697e700ab",
      "documented_record": "docs/pkcs11-oracle-triage.md: EdDSA-NULL fast lane (rc2 oracle, 2026-09-30)",
      "documented_source_revision": "a7090869cf679658720fe41ebc7867f2be82502e",
      "documented_backup": "/tmp/pkcs11-fast-eddsa.json",
      "backup_byte_identical": true,
      "provenance": {
        "framework": {
          "version": "0.2.2rc2",
          "dirty": false,
          "source": "package"
        },
        "test_data": [
          {
            "name": "wycheproof",
            "repo": "C2SP/wycheproof",
            "commit": "3fa63dd0344abb611f1fb1d77e119938603ea230",
            "archive_sha256": "5dc00fae83575135c3147bfd4a04ee8889b1f0482ac6ca21aa486a8abccf2260",
            "present": true
          },
          {
            "name": "cctv",
            "repo": "C2SP/CCTV",
            "commit": "4448f2097b2daa812c91a26141f9f36c2096b9ca",
            "archive_sha256": "3994978c6882b41afdaa8173fd33785680ea29a0cab680ea7834a915cae68578",
            "present": true
          },
          {
            "name": "acvp",
            "repo": "usnistgov/ACVP-Server",
            "commit": "975de31eb83d87039ec88934fdc47d8c312b892d",
            "archive_sha256": "028f0d06f49d0f6cd7f69ae693623f93fc7d2edf29d2fa11465bc865dad6f278",
            "present": true
          },
          {
            "name": "x509-limbo",
            "repo": "C2SP/x509-limbo",
            "commit": "118721335e675edde10015df89b138cf292d7554",
            "archive_sha256": "fe020e2b35fadabf7dd693bb4d49790454925f9165e1588d73d3e97b2041541b",
            "present": true
          }
        ],
        "environment": {
          "interface": "3.2",
          "slots": 1,
          "mechanisms": 316
        }
      },
      "summary": {
        "passed": 5133,
        "failed": 0,
        "skipped": 4424,
        "xfailed": 633,
        "xpassed": 0,
        "error": 0,
        "crashed": 0,
        "timeout": 0,
        "crash_limited": 0,
        "total": 10190,
        "child_crash": 0,
        "child_timeout": 0,
        "incomplete": false
      },
      "old_trace_available": false,
      "old_module_digest_available": false,
      "use": "comparison only; no artifact-bound acceptance inferred"
    },
    "kat": {
      "path": "dist-release-evidence/message-routing/kat-before-pkcs11-kat-results.json",
      "sha256": "c0e06346937be547f81f4d60993e24718cbe4f68de57c7ed33f1aa3ff9476b8b",
      "documented_record": "docs/pkcs11-oracle-triage.md: EdDSA-NULL fast lane (rc2 oracle, 2026-09-30)",
      "documented_source_revision": "a7090869cf679658720fe41ebc7867f2be82502e",
      "documented_backup": "/tmp/pkcs11-kat-eddsa.json",
      "backup_byte_identical": true,
      "provenance": {
        "framework": {
          "version": "0.2.2rc2",
          "dirty": false,
          "source": "package"
        },
        "test_data": [
          {
            "name": "wycheproof",
            "repo": "C2SP/wycheproof",
            "commit": "3fa63dd0344abb611f1fb1d77e119938603ea230",
            "archive_sha256": "5dc00fae83575135c3147bfd4a04ee8889b1f0482ac6ca21aa486a8abccf2260",
            "present": true
          },
          {
            "name": "cctv",
            "repo": "C2SP/CCTV",
            "commit": "4448f2097b2daa812c91a26141f9f36c2096b9ca",
            "archive_sha256": "3994978c6882b41afdaa8173fd33785680ea29a0cab680ea7834a915cae68578",
            "present": true
          },
          {
            "name": "acvp",
            "repo": "usnistgov/ACVP-Server",
            "commit": "975de31eb83d87039ec88934fdc47d8c312b892d",
            "archive_sha256": "028f0d06f49d0f6cd7f69ae693623f93fc7d2edf29d2fa11465bc865dad6f278",
            "present": true
          },
          {
            "name": "x509-limbo",
            "repo": "C2SP/x509-limbo",
            "commit": "118721335e675edde10015df89b138cf292d7554",
            "archive_sha256": "fe020e2b35fadabf7dd693bb4d49790454925f9165e1588d73d3e97b2041541b",
            "present": true
          }
        ],
        "environment": {
          "interface": "3.2",
          "slots": 1,
          "mechanisms": 316
        }
      },
      "summary": {
        "passed": 84450,
        "failed": 0,
        "skipped": 31326,
        "xfailed": 972,
        "xpassed": 0,
        "error": 0,
        "crashed": 0,
        "timeout": 0,
        "crash_limited": 0,
        "total": 116748,
        "child_crash": 0,
        "child_timeout": 0,
        "incomplete": false
      },
      "old_trace_available": false,
      "old_module_digest_available": false,
      "use": "comparison only; no artifact-bound acceptance inferred"
    }
  },
  "clean_build_verification": {
    "clean_command_record": "dist-release-evidence/message-routing/clean-build-command.json",
    "module_path": "dist-newstyle/build/x86_64-linux/ghc-9.10.3/haskoki-0.3.0.0/f/haskoki/build/haskoki/libhaskoki.so",
    "module_sha256": "28071ccee1e0aa956cbae91b7c896554222af2b2a7b9cf83b0c4ca005747b173",
    "module_mtime_ns": 1790768333802900443,
    "table_registration_revision": "c05d7d81c260e16858d06cb868e6387885ca45cf",
    "table_registration_commit_timestamp": 1790763740,
    "module_newer_than_table_registration": true,
    "message_symbol_count": 20,
    "message_symbols": [
      "std_DecryptMessage",
      "std_DecryptMessageBegin",
      "std_DecryptMessageNext",
      "std_EncryptMessage",
      "std_EncryptMessageBegin",
      "std_EncryptMessageNext",
      "std_MessageDecryptFinal",
      "std_MessageDecryptInit",
      "std_MessageEncryptFinal",
      "std_MessageEncryptInit",
      "std_MessageSignFinal",
      "std_MessageSignInit",
      "std_MessageVerifyFinal",
      "std_MessageVerifyInit",
      "std_SignMessage",
      "std_SignMessageBegin",
      "std_SignMessageNext",
      "std_VerifyMessage",
      "std_VerifyMessageBegin",
      "std_VerifyMessageNext"
    ],
    "symbols_log": "dist-release-evidence/message-routing/clean-module-symbols.log"
  },
  "direct_entry_happy_legs": {
    "3.0": {
      "C_MessageEncryptInit": [
        "init-cbc",
        "multipart-init",
        "recall-init",
        "pad-init",
        "sibling-init",
        "close-open-init"
      ],
      "C_EncryptMessage": [
        "one-cbc-query",
        "one-cbc-repeat-query",
        "one-cbc-exact",
        "second-message",
        "recall-stage",
        "recall-after-malformed",
        "pad-abc",
        "pad-empty-null",
        "pad-empty-present",
        "sibling-one"
      ],
      "C_EncryptMessageBegin": [
        "begin-iv",
        "after-one-byte-refusal",
        "empty-parameter-aad",
        "replacement-iv-begin",
        "close-open-begin"
      ],
      "C_EncryptMessageNext": [
        "non-ending-query",
        "part-cbc",
        "terminal-query",
        "terminal-repeat-query",
        "terminal-exact",
        "repair-alignment",
        "supply-iv-at-end",
        "replace-iv-at-end"
      ],
      "C_MessageEncryptFinal": [
        "final-idle",
        "multipart-final-idle",
        "last-final-idle",
        "pad-final",
        "sibling-release"
      ],
      "C_MessageDecryptInit": [
        "init-cbc",
        "multipart-init",
        "recall-init",
        "pad-init",
        "next-pad-context",
        "next-pad-context",
        "next-pad-context",
        "sibling-init"
      ],
      "C_DecryptMessage": [
        "one-cbc-query",
        "one-cbc-repeat-query",
        "one-cbc-exact",
        "second-message",
        "recall-stage",
        "recall-after-malformed",
        "pad-abc",
        "empty-query",
        "empty-query-repeat",
        "pad-empty-null",
        "empty-query",
        "empty-query-repeat",
        "pad-empty-present",
        "valid-after-padding-failure",
        "sibling-one",
        "sibling-survives"
      ],
      "C_DecryptMessageBegin": [
        "begin-iv",
        "empty-parameter-aad",
        "replacement-iv-begin"
      ],
      "C_DecryptMessageNext": [
        "non-ending-query",
        "part-cbc",
        "terminal-query",
        "terminal-repeat-query",
        "terminal-exact",
        "supply-iv-at-end",
        "replace-iv-at-end"
      ],
      "C_MessageDecryptFinal": [
        "final-idle",
        "multipart-final-idle",
        "last-final-idle",
        "after-delivery",
        "after-delivery",
        "after-delivery",
        "pad-final",
        "sibling-release"
      ],
      "C_MessageSignInit": [
        "init-hmac",
        "multipart-init",
        "empty-init"
      ],
      "C_SignMessage": [
        "one-hmac-query",
        "one-hmac-repeat-query",
        "one-hmac-exact",
        "second-message",
        "empty-null",
        "empty-present"
      ],
      "C_SignMessageBegin": [
        "begin-hmac",
        "empty-null",
        "empty-present"
      ],
      "C_SignMessageNext": [
        "absent-output-and-length",
        "ignored-present-output",
        "part-hmac-query",
        "part-hmac-repeat-query",
        "part-hmac-exact",
        "empty-null",
        "empty-terminal",
        "empty-present",
        "empty-terminal"
      ],
      "C_MessageSignFinal": [
        "final-idle",
        "multipart-final-idle",
        "empty-final"
      ],
      "C_MessageVerifyInit": [
        "init-hmac",
        "multipart-init",
        "empty-init"
      ],
      "C_VerifyMessage": [
        "one-hmac",
        "valid-after-invalid",
        "empty-null",
        "empty-present"
      ],
      "C_VerifyMessageBegin": [
        "begin-hmac",
        "begin-again",
        "begin-after-empty-mismatch",
        "begin-after-flipped-mismatch",
        "empty-null",
        "empty-present"
      ],
      "C_VerifyMessageNext": [
        "absent-empty-witness",
        "part-hmac",
        "recovered-verdict",
        "empty-null",
        "empty-terminal",
        "empty-present",
        "empty-terminal"
      ],
      "C_MessageVerifyFinal": [
        "final-idle-after-invalid",
        "final-idle",
        "empty-final"
      ]
    },
    "3.1": {
      "C_MessageEncryptInit": [
        "init-cbc",
        "multipart-init",
        "recall-init",
        "pad-init",
        "sibling-init",
        "close-open-init"
      ],
      "C_EncryptMessage": [
        "one-cbc-query",
        "one-cbc-repeat-query",
        "one-cbc-exact",
        "second-message",
        "recall-stage",
        "recall-after-malformed",
        "pad-abc",
        "pad-empty-null",
        "pad-empty-present",
        "sibling-one"
      ],
      "C_EncryptMessageBegin": [
        "begin-iv",
        "after-one-byte-refusal",
        "empty-parameter-aad",
        "replacement-iv-begin",
        "close-open-begin"
      ],
      "C_EncryptMessageNext": [
        "non-ending-query",
        "part-cbc",
        "terminal-query",
        "terminal-repeat-query",
        "terminal-exact",
        "repair-alignment",
        "supply-iv-at-end",
        "replace-iv-at-end"
      ],
      "C_MessageEncryptFinal": [
        "final-idle",
        "multipart-final-idle",
        "last-final-idle",
        "pad-final",
        "sibling-release"
      ],
      "C_MessageDecryptInit": [
        "init-cbc",
        "multipart-init",
        "recall-init",
        "pad-init",
        "next-pad-context",
        "next-pad-context",
        "next-pad-context",
        "sibling-init"
      ],
      "C_DecryptMessage": [
        "one-cbc-query",
        "one-cbc-repeat-query",
        "one-cbc-exact",
        "second-message",
        "recall-stage",
        "recall-after-malformed",
        "pad-abc",
        "empty-query",
        "empty-query-repeat",
        "pad-empty-null",
        "empty-query",
        "empty-query-repeat",
        "pad-empty-present",
        "valid-after-padding-failure",
        "sibling-one",
        "sibling-survives"
      ],
      "C_DecryptMessageBegin": [
        "begin-iv",
        "empty-parameter-aad",
        "replacement-iv-begin"
      ],
      "C_DecryptMessageNext": [
        "non-ending-query",
        "part-cbc",
        "terminal-query",
        "terminal-repeat-query",
        "terminal-exact",
        "supply-iv-at-end",
        "replace-iv-at-end"
      ],
      "C_MessageDecryptFinal": [
        "final-idle",
        "multipart-final-idle",
        "last-final-idle",
        "after-delivery",
        "after-delivery",
        "after-delivery",
        "pad-final",
        "sibling-release"
      ],
      "C_MessageSignInit": [
        "init-hmac",
        "multipart-init",
        "empty-init"
      ],
      "C_SignMessage": [
        "one-hmac-query",
        "one-hmac-repeat-query",
        "one-hmac-exact",
        "second-message",
        "empty-null",
        "empty-present"
      ],
      "C_SignMessageBegin": [
        "begin-hmac",
        "empty-null",
        "empty-present"
      ],
      "C_SignMessageNext": [
        "absent-output-and-length",
        "ignored-present-output",
        "part-hmac-query",
        "part-hmac-repeat-query",
        "part-hmac-exact",
        "empty-null",
        "empty-terminal",
        "empty-present",
        "empty-terminal"
      ],
      "C_MessageSignFinal": [
        "final-idle",
        "multipart-final-idle",
        "empty-final"
      ],
      "C_MessageVerifyInit": [
        "init-hmac",
        "multipart-init",
        "empty-init"
      ],
      "C_VerifyMessage": [
        "one-hmac",
        "valid-after-invalid",
        "empty-null",
        "empty-present"
      ],
      "C_VerifyMessageBegin": [
        "begin-hmac",
        "begin-again",
        "begin-after-empty-mismatch",
        "begin-after-flipped-mismatch",
        "empty-null",
        "empty-present"
      ],
      "C_VerifyMessageNext": [
        "absent-empty-witness",
        "part-hmac",
        "recovered-verdict",
        "empty-null",
        "empty-terminal",
        "empty-present",
        "empty-terminal"
      ],
      "C_MessageVerifyFinal": [
        "final-idle-after-invalid",
        "final-idle",
        "empty-final"
      ]
    },
    "3.2": {
      "C_MessageEncryptInit": [
        "init-cbc",
        "multipart-init",
        "recall-init",
        "pad-init",
        "sibling-init",
        "close-open-init"
      ],
      "C_EncryptMessage": [
        "one-cbc-query",
        "one-cbc-repeat-query",
        "one-cbc-exact",
        "second-message",
        "recall-stage",
        "recall-after-malformed",
        "pad-abc",
        "pad-empty-null",
        "pad-empty-present",
        "sibling-one"
      ],
      "C_EncryptMessageBegin": [
        "begin-iv",
        "after-one-byte-refusal",
        "empty-parameter-aad",
        "replacement-iv-begin",
        "close-open-begin"
      ],
      "C_EncryptMessageNext": [
        "non-ending-query",
        "part-cbc",
        "terminal-query",
        "terminal-repeat-query",
        "terminal-exact",
        "repair-alignment",
        "supply-iv-at-end",
        "replace-iv-at-end"
      ],
      "C_MessageEncryptFinal": [
        "final-idle",
        "multipart-final-idle",
        "last-final-idle",
        "pad-final",
        "sibling-release"
      ],
      "C_MessageDecryptInit": [
        "init-cbc",
        "multipart-init",
        "recall-init",
        "pad-init",
        "next-pad-context",
        "next-pad-context",
        "next-pad-context",
        "sibling-init"
      ],
      "C_DecryptMessage": [
        "one-cbc-query",
        "one-cbc-repeat-query",
        "one-cbc-exact",
        "second-message",
        "recall-stage",
        "recall-after-malformed",
        "pad-abc",
        "empty-query",
        "empty-query-repeat",
        "pad-empty-null",
        "empty-query",
        "empty-query-repeat",
        "pad-empty-present",
        "valid-after-padding-failure",
        "sibling-one",
        "sibling-survives"
      ],
      "C_DecryptMessageBegin": [
        "begin-iv",
        "empty-parameter-aad",
        "replacement-iv-begin"
      ],
      "C_DecryptMessageNext": [
        "non-ending-query",
        "part-cbc",
        "terminal-query",
        "terminal-repeat-query",
        "terminal-exact",
        "supply-iv-at-end",
        "replace-iv-at-end"
      ],
      "C_MessageDecryptFinal": [
        "final-idle",
        "multipart-final-idle",
        "last-final-idle",
        "after-delivery",
        "after-delivery",
        "after-delivery",
        "pad-final",
        "sibling-release"
      ],
      "C_MessageSignInit": [
        "init-hmac",
        "multipart-init",
        "empty-init"
      ],
      "C_SignMessage": [
        "one-hmac-query",
        "one-hmac-repeat-query",
        "one-hmac-exact",
        "second-message",
        "empty-null",
        "empty-present"
      ],
      "C_SignMessageBegin": [
        "begin-hmac",
        "empty-null",
        "empty-present"
      ],
      "C_SignMessageNext": [
        "absent-output-and-length",
        "ignored-present-output",
        "part-hmac-query",
        "part-hmac-repeat-query",
        "part-hmac-exact",
        "empty-null",
        "empty-terminal",
        "empty-present",
        "empty-terminal"
      ],
      "C_MessageSignFinal": [
        "final-idle",
        "multipart-final-idle",
        "empty-final"
      ],
      "C_MessageVerifyInit": [
        "init-hmac",
        "multipart-init",
        "empty-init"
      ],
      "C_VerifyMessage": [
        "one-hmac",
        "valid-after-invalid",
        "empty-null",
        "empty-present"
      ],
      "C_VerifyMessageBegin": [
        "begin-hmac",
        "begin-again",
        "begin-after-empty-mismatch",
        "begin-after-flipped-mismatch",
        "empty-null",
        "empty-present"
      ],
      "C_VerifyMessageNext": [
        "absent-empty-witness",
        "part-hmac",
        "recovered-verdict",
        "empty-null",
        "empty-terminal",
        "empty-present",
        "empty-terminal"
      ],
      "C_MessageVerifyFinal": [
        "final-idle-after-invalid",
        "final-idle",
        "empty-final"
      ]
    }
  },
  "focused_verification": {
    "message-model": {
      "command": [
        "timeout",
        "-s",
        "KILL",
        "2400",
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
        "-v",
        "/home/user/src/m/haskoki-ws/haskoki:/work",
        "-w",
        "/work",
        "haskoki-dev:ghc-9.10.3",
        "cabal",
        "test",
        "haskoki-model-tests",
        "--test-option=--pattern=message operations"
      ],
      "exit": 0,
      "log": "dist-release-evidence/message-routing/message-model.log",
      "log_sha256": "f7289598a5c6007f68895eead9fea8402c472dad869a6c4d3d6e6aaf86375327",
      "passed_cases": 24
    },
    "standard-surface": {
      "command": [
        "timeout",
        "-s",
        "KILL",
        "2400",
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
        "-v",
        "/home/user/src/m/haskoki-ws/haskoki:/work",
        "-w",
        "/work",
        "haskoki-dev:ghc-9.10.3",
        "cabal",
        "test",
        "haskoki-model-tests",
        "--test-option=--pattern=Standard surface"
      ],
      "exit": 0,
      "log": "dist-release-evidence/message-routing/standard-surface.log",
      "log_sha256": "d204b39918d0771bb7b4f7bb4d0fbbb53cf09f2f711cd537fb69b73741d6e286",
      "passed_cases": 16
    },
    "direct-consumers": {
      "command": [
        "timeout",
        "-s",
        "KILL",
        "2400",
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
        "-v",
        "/home/user/src/m/haskoki-ws/haskoki:/work",
        "-w",
        "/work",
        "haskoki-dev:ghc-9.10.3",
        "scripts/test-consumers.sh"
      ],
      "exit": 0,
      "log": "dist-release-evidence/message-routing/direct-consumers.log",
      "log_sha256": "631afd17f0a7bf9efa7578e7ac7441cd9327fb24fcaae902b25ea34f7f6e0948"
    },
    "proxy-parity": {
      "command": [
        "timeout",
        "-s",
        "KILL",
        "2400",
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
        "-v",
        "/home/user/src/m/haskoki-ws/haskoki:/work",
        "-w",
        "/work",
        "-v",
        "/opt/pkcs11-proxy-ng:/opt/pkcs11-proxy-ng:ro",
        "haskoki-dev:ghc-9.10.3",
        "sh",
        "-c",
        "HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng scripts/test-proxy-parity.sh"
      ],
      "exit": 0,
      "log": "dist-release-evidence/message-routing/proxy-parity.log",
      "log_sha256": "daef99d64ac6341fac316414cc0e3575aa91d111f19f615796db8a51fcaa5d4b"
    }
  },
  "gate_attempts": [
    {
      "command": "HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng bash scripts/run-gates.sh",
      "exit": 1,
      "log": "dist-release-evidence/message-routing/gates-initial.log",
      "manifest": "dist-release-evidence/message-routing/gates-initial/MANIFEST.txt",
      "finding_count": 2,
      "finding_text": [
        "DH pub B reads 256 bytes",
        "DH agreement commutes"
      ],
      "source_review": {
        "consumer": "tests/c/consumer_roundtrip.c:1666-1688 asserts full-width public values and passes buffer capacity to derive",
        "provider": "core/Haskoki/Object.hs:1072 and core/Haskoki/Der.hs:865-876 expose the minimal unsigned DH integer",
        "preexisting_at_revision": "a7090869cf679658720fe41ebc7867f2be82502e",
        "diagnosis": "consumer assumes a fixed public-value width; source supports variable width; original failure did not print the actual CKR or byte length",
        "action": "preserve this failure; rerun the complete unchanged gate sequence; leave the consumer source for coordinator follow-up"
      }
    },
    {
      "command": "HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng bash scripts/run-gates.sh",
      "exit": 0,
      "log": "dist-release-evidence/message-routing/gates.log"
    }
  ],
  "lane_trace_configuration": {
    "producer": "pkcs11-check raw report stream with --rv-trace",
    "trace_format": "pytest reportlog JSONL containing pkcs11_rv_trace user_properties",
    "trace_materialization": "byte-identical copy of the completed report.jsonl to trace.jsonl",
    "provider_runtime_trace_emitted": false,
    "raw_call_observer": "pkcs11_check.raw.api.RawPKCS11._call",
    "trace_option": "--rv-trace",
    "compact_window": null,
    "shim_path": "/tmp/haskoki-message-verification/lane-docker/docker",
    "shim_sha256": "552b1a3be28f1dda00154f7d8488ce458439dd754039cf3fee0b201cdc1b73be",
    "wrapper_path": "/tmp/pkcs11-ws/run-lane-rc2.sh",
    "wrapper_sha256": "baede328be08eddbeac51d325b8b6432655bd1d6aaa138e7e92555096b1c49b1",
    "native_trace_diagnostic_attempt": {
      "source_path": "scripts/ci-backend.toml",
      "source_sha256": "3028b238d51723516afe745210b201df211e4159199c3db633d851bb1faeae89",
      "runtime_path": "dist-release-evidence/message-routing/trace-backend.toml",
      "runtime_sha256": "df32ba06339b77a678e0a0a10793e2e52dbcc0eb57e96e57de04271f68530b79",
      "config_in_container": "/repo/dist-release-evidence/message-routing/trace-backend.toml",
      "shim_path": "/tmp/haskoki-message-verification/lane-docker/docker",
      "shim_sha256": "9c0e34451f384a6ba62bce6f03f401ff359ac40df5bd21b2267e3d1d80c5a9d9",
      "wrapper_path": "/tmp/pkcs11-ws/run-lane-rc2.sh",
      "wrapper_sha256": "baede328be08eddbeac51d325b8b6432655bd1d6aaa138e7e92555096b1c49b1",
      "reason": "canonical backend disables tracing; trace environment variable only overrides the path. Local Docker argv adapter enables a copied runtime config without editing tracked files or the lane wrapper.",
      "outcome": "Standard surface has no native trace emitter; no trace file was produced"
    },
    "effective_commands_path": "dist-release-evidence/message-routing/effective-lane-docker-commands.jsonl"
  },
  "gate_manifest": {
    "path": "dist-release-evidence/message-routing/gates/MANIFEST.txt",
    "sha256": "e97e1936b92433d859cfdebc4336ad83c6bc28d60f6cb798fa23825e9d4fe2e1",
    "steps_passed": 16,
    "steps_missed": 0,
    "drivers_passed": 14
  },
  "bundle_path": "/home/user/src/m/haskoki-ws/haskoki/dist-release/haskoki-0.3.0.0",
  "bundle_sha256": "6c629bf0d82d936b32cf3aa09d5ec5f73d0e2b19755081b3573339527f6abea8",
  "module_sha256": "28071ccee1e0aa956cbae91b7c896554222af2b2a7b9cf83b0c4ca005747b173",
  "release_module_verification": {
    "module_mtime_ns": 1790769067725113164,
    "module_newer_than_table_registration": true,
    "message_symbol_count": 20,
    "matches_clean_build_module": true
  },
  "lane_attempts": {
    "fast": [
      {
        "command": "bash /tmp/pkcs11-ws/run-lane-rc2.sh fast",
        "environment": {
          "PATH_prefix": "/tmp/haskoki-message-verification/lane-docker",
          "effective_HASKOKI_CONFIG": "/repo/dist-release-evidence/message-routing/trace-backend.toml"
        },
        "exit": 0,
        "log": "dist-release-evidence/message-routing/fast-initial.log",
        "summary": {
          "passed": 5138,
          "failed": 4,
          "skipped": 4414,
          "xfailed": 634,
          "xpassed": 0,
          "error": 0,
          "crashed": 0,
          "timeout": 0,
          "crash_limited": 0,
          "total": 10190,
          "child_crash": 0,
          "child_timeout": 0,
          "incomplete": false
        },
        "trace_present": false,
        "result_archive": "dist-release-evidence/message-routing/fast-initial/pkcs11-fast-results.json",
        "raw_report_archive": "dist-release-evidence/message-routing/fast-initial/report.jsonl"
      },
      {
        "command": "bash /tmp/pkcs11-ws/run-lane-rc2.sh fast",
        "environment": {
          "PATH_prefix": "/tmp/haskoki-message-verification/lane-docker",
          "PKCS11_CHECK_EXTRA_ARGS": "--rv-trace"
        },
        "exit": 0,
        "log": "dist-release-evidence/message-routing/fast.log"
      }
    ],
    "kat": [
      {
        "command": "bash /tmp/pkcs11-ws/run-lane-rc2.sh kat",
        "environment": {
          "PATH_prefix": "/tmp/haskoki-message-verification/lane-docker",
          "PKCS11_CHECK_EXTRA_ARGS": "--rv-trace"
        },
        "exit": 0,
        "log": "dist-release-evidence/message-routing/kat.log"
      }
    ]
  },
  "routing_source_checks": {
    "generated_message_stub_bodies_absent": 20,
    "table_assignments_to_standard_bodies": 20,
    "original_model_case_names_unchanged": [
      "two messages under one outer context, then outer final",
      "message init conflicts and arg shape",
      "invalid ordering rejected without mutation",
      "message error keeps the outer context",
      "oversize part aborts the message only",
      "unpadded lengths keep or skip the message",
      "auth gate consumes at first begin",
      "aad bound into cipher effects, refused for sign",
      "classic and message calls do not mix",
      "decrypt vertical with pad checks",
      "sign vertical: multipart equals one-shot",
      "verify vertical: verdicts end the message",
      "family and codec mismatch rejected",
      "message params decode with family aad rule",
      "nonce writeback through nested regions",
      "tag split and writeback",
      "toy aead binds nonce aad and tag"
    ],
    "original_model_cases": 17,
    "new_decoder_cases": 7,
    "standard_message_dialogue_cases": 5,
    "catalog_sha256_unchanged": true,
    "original_model_body_definitions_byte_identical": true,
    "original_model_body_definition_count": 47,
    "registration_change": "test group adds seven decoder cases; original seventeen case names and all old case/helper bodies are retained"
  },
  "lane_review_details": {
    "fast": {
      "counts": {
        "collected_selected": 10190,
        "executed_non_skip_outcomes": 5776,
        "passed": 5138,
        "skipped": 4414,
        "expected_failures": 634,
        "actual_failures": 4,
        "unexpected_passes": 0
      },
      "finding_count": 638,
      "new_finding_count": 5,
      "removed_previous_findings": 0,
      "message_units": [
        {
          "target": "/fw/src/pkcs11_check/testcases/test_mech_message.py",
          "counts": {
            "passed": 0,
            "failed": 0,
            "skipped": 26,
            "xfailed": 0,
            "xpassed": 0,
            "error": 0,
            "crashed": 0,
            "timeout": 0,
            "crash_limited": 0
          },
          "skip_reasons": {
            "No mechanism catalog": 20,
            "CKM_AES_GCM does not advertise CKF_MESSAGE_ENCRYPT": 4,
            "CKM_AES_CCM does not advertise CKF_MESSAGE_ENCRYPT": 1,
            "CKM_AES_GMAC does not advertise CKF_MESSAGE_SIGN": 1
          }
        },
        {
          "target": "/fw/src/pkcs11_check/testcases/test_message_crypto.py",
          "counts": {
            "passed": 1,
            "failed": 4,
            "skipped": 7,
            "xfailed": 1,
            "xpassed": 0,
            "error": 0,
            "crashed": 0,
            "timeout": 0,
            "crash_limited": 0
          },
          "skip_reasons": {
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_SIGN for single message sign": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY for single message verify": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_SIGN for single message sign cross-verification": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_SIGN for multipart message sign": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY for single message verify bad signature": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY for multipart message verify": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY for multipart message verify bad signature": 1
          }
        }
      ],
      "trace_review": {
        "format": "pytest reportlog raw JSONL with pkcs11_rv_trace",
        "raw_report_byte_identical": true,
        "jsonl_records": 33713,
        "reports_with_call_observations": 5327,
        "call_observations_across_report_phases": 88092,
        "dropped_call_observations": 0,
        "sha256": "070f344e5227cdb8d9abf37097212890e849eb27cd3c0fb89230661b6d6200ca"
      },
      "source_classification": "All five newly exposed CBC findings were reduced with matching AES-256/NULL-IV inputs and grouped into one measured oracle fixture disposition. IV-supplied controls establish successful encryption/classic decryption and separately isolate the source input placement. Capability skips remain separate; no unresolved new routed provider defect."
    },
    "kat": {
      "counts": {
        "collected_selected": 116748,
        "executed_non_skip_outcomes": 85432,
        "passed": 84455,
        "skipped": 31316,
        "expected_failures": 973,
        "actual_failures": 4,
        "unexpected_passes": 0
      },
      "finding_count": 977,
      "new_finding_count": 5,
      "removed_previous_findings": 0,
      "raw_new_tuple_count": 6,
      "raw_removed_tuple_count": 1,
      "explained_volatile_finding_changes": [
        {
          "nodeid": "src/pkcs11_check/testcases/test_cctv_rfc6979.py::test_rfc6979_ecdsa_sign_deterministic",
          "previous": {
            "nodeid": "src/pkcs11_check/testcases/test_cctv_rfc6979.py::test_rfc6979_ecdsa_sign_deterministic",
            "outcome": "xfailed",
            "duration": 0.0018780739992507733,
            "start": 1790747192.0746505,
            "wasxfail": "Module does not use RFC 6979 deterministic k (got 8d64c1691aeb2eed58570c999d4c597d..., expected efd9073b652e76da1b5a019c0e4a2e3f...)",
            "longrepr": "_pytest.outcomes.XFailed: Module does not use RFC 6979 deterministic k (got 8d64c1691aeb2eed58570c999d4c597d..., expected efd9073b652e76da1b5a019c0e4a2e3f...)",
            "location": [
              "src/pkcs11_check/testcases/test_cctv_rfc6979.py",
              214,
              "test_rfc6979_ecdsa_sign_deterministic"
            ]
          },
          "actual": {
            "nodeid": "src/pkcs11_check/testcases/test_cctv_rfc6979.py::test_rfc6979_ecdsa_sign_deterministic",
            "outcome": "xfailed",
            "duration": 0.0016919299960136414,
            "start": 1790771140.6635258,
            "wasxfail": "Module does not use RFC 6979 deterministic k (got 7a0e9c4cb403359ca917eb822a1cca26..., expected efd9073b652e76da1b5a019c0e4a2e3f...)",
            "longrepr": "_pytest.outcomes.XFailed: Module does not use RFC 6979 deterministic k (got 7a0e9c4cb403359ca917eb822a1cca26..., expected efd9073b652e76da1b5a019c0e4a2e3f...)",
            "location": [
              "src/pkcs11_check/testcases/test_cctv_rfc6979.py",
              214,
              "test_rfc6979_ecdsa_sign_deterministic"
            ]
          },
          "classification": "existing expected failure with randomized signature bytes",
          "source": "test_cctv_rfc6979.py:215-264 explicitly classifies ordinary nondeterministic ECDSA signing as an honest deviation",
          "review": "only the observed 32-hex-digit signature prefix differs; node, outcome, expected prefix and surrounding reason are identical"
        }
      ],
      "message_units": [
        {
          "target": "/fw/src/pkcs11_check/testcases/test_mech_message.py",
          "counts": {
            "passed": 0,
            "failed": 0,
            "skipped": 26,
            "xfailed": 0,
            "xpassed": 0,
            "error": 0,
            "crashed": 0,
            "timeout": 0,
            "crash_limited": 0
          },
          "skip_reasons": {
            "No mechanism catalog": 20,
            "CKM_AES_GCM does not advertise CKF_MESSAGE_ENCRYPT": 4,
            "CKM_AES_CCM does not advertise CKF_MESSAGE_ENCRYPT": 1,
            "CKM_AES_GMAC does not advertise CKF_MESSAGE_SIGN": 1
          }
        },
        {
          "target": "/fw/src/pkcs11_check/testcases/test_message_crypto.py",
          "counts": {
            "passed": 1,
            "failed": 4,
            "skipped": 7,
            "xfailed": 1,
            "xpassed": 0,
            "error": 0,
            "crashed": 0,
            "timeout": 0,
            "crash_limited": 0
          },
          "skip_reasons": {
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_SIGN for single message sign": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY for single message verify": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_SIGN for single message sign cross-verification": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_SIGN for multipart message sign": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY for single message verify bad signature": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY for multipart message verify": 1,
            "SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY for multipart message verify bad signature": 1
          }
        }
      ],
      "trace_review": {
        "format": "pytest reportlog raw JSONL with pkcs11_rv_trace",
        "raw_report_byte_identical": true,
        "jsonl_records": 352087,
        "reports_with_call_observations": 76024,
        "call_observations_across_report_phases": 3444128,
        "dropped_call_observations": 0,
        "sha256": "f49983e50d5424ff9ce397089d3f440e410812b1bfc935027febdca0ae45dba4"
      },
      "source_classification": "All five newly exposed CBC findings were reduced with matching AES-256/NULL-IV inputs and grouped into one measured oracle fixture disposition. IV-supplied controls establish successful encryption/classic decryption and separately isolate the source input placement. Capability skips remain separate; no unresolved new routed provider defect."
    }
  },
  "independent_reproductions": {
    "oracle-repro": {
      "source": "dist-release-evidence/message-routing/reproductions/oracle-repro.c",
      "source_sha256": "a1c4c1171e96ee3820514bc7199161c802565b04b4970f396235b0c80057c3aa",
      "compile": {
        "command": [
          "cc",
          "-std=c11",
          "-O2",
          "-g",
          "-Wall",
          "-Wextra",
          "-Werror",
          "-Ispec/vendor",
          "-I/home/user/src/m/haskoki-ws/haskoki",
          "/tmp/haskoki-message-verification/oracle-repro.c",
          "-ldl",
          "-lpthread",
          "-o",
          "/tmp/haskoki-message-verification/oracle-repro"
        ],
        "exit": 0,
        "log": "dist-release-evidence/message-routing/oracle-cbc-compile.log"
      },
      "run": {
        "command": [
          "/tmp/haskoki-message-verification/oracle-repro",
          "/home/user/src/m/haskoki-ws/haskoki/dist-release/haskoki-0.3.0.0/lib/libhaskoki.so"
        ],
        "exit": 0,
        "log": "dist-release-evidence/message-routing/oracle-cbc-reproduction.log"
      },
      "observed_output": "message:C_MessageEncryptInit/slot-present/3.2 check=ok\nmessage:C_EncryptMessage/slot-present/3.2 check=ok\nmessage:C_EncryptMessageBegin/slot-present/3.2 check=ok\nmessage:C_EncryptMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageEncryptFinal/slot-present/3.2 check=ok\nmessage:C_MessageDecryptInit/slot-present/3.2 check=ok\nmessage:C_DecryptMessage/slot-present/3.2 check=ok\nmessage:C_DecryptMessageBegin/slot-present/3.2 check=ok\nmessage:C_DecryptMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageDecryptFinal/slot-present/3.2 check=ok\nmessage:C_MessageSignInit/slot-present/3.2 check=ok\nmessage:C_SignMessage/slot-present/3.2 check=ok\nmessage:C_SignMessageBegin/slot-present/3.2 check=ok\nmessage:C_SignMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageSignFinal/slot-present/3.2 check=ok\nmessage:C_MessageVerifyInit/slot-present/3.2 check=ok\nmessage:C_VerifyMessage/slot-present/3.2 check=ok\nmessage:C_VerifyMessageBegin/slot-present/3.2 check=ok\nmessage:C_VerifyMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageVerifyFinal/slot-present/3.2 check=ok\nmessage:fixture/open/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nprobe: CBC init without IV rv=0x7\nmessage:fixture/close/3.2 rv=0x0 expected=0x0\nmessage:C_Finalize/probe-cleanup/3.2 rv=0x0 expected=0x0\n"
    },
    "oracle-shape-repro": {
      "source": "dist-release-evidence/message-routing/reproductions/oracle-shape-repro.c",
      "source_sha256": "af0af972f5e63f20acee1b3d076c51cb2f4a397ff339ee16deeec09509c256b4",
      "compile": {
        "command": [
          "cc",
          "-std=c11",
          "-O2",
          "-g",
          "-Wall",
          "-Wextra",
          "-Werror",
          "-Ispec/vendor",
          "-I/home/user/src/m/haskoki-ws/haskoki",
          "/tmp/haskoki-message-verification/oracle-shape-repro.c",
          "-ldl",
          "-lpthread",
          "-o",
          "/tmp/haskoki-message-verification/oracle-shape-repro"
        ],
        "exit": 0,
        "log": "dist-release-evidence/message-routing/oracle-shape-compile.log"
      },
      "run": {
        "command": [
          "/tmp/haskoki-message-verification/oracle-shape-repro",
          "/home/user/src/m/haskoki-ws/haskoki/dist-release/haskoki-0.3.0.0/lib/libhaskoki.so"
        ],
        "exit": 0,
        "log": "dist-release-evidence/message-routing/oracle-shape-reproduction.log"
      },
      "observed_output": "message:C_MessageEncryptInit/slot-present/3.2 check=ok\nmessage:C_EncryptMessage/slot-present/3.2 check=ok\nmessage:C_EncryptMessageBegin/slot-present/3.2 check=ok\nmessage:C_EncryptMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageEncryptFinal/slot-present/3.2 check=ok\nmessage:C_MessageDecryptInit/slot-present/3.2 check=ok\nmessage:C_DecryptMessage/slot-present/3.2 check=ok\nmessage:C_DecryptMessageBegin/slot-present/3.2 check=ok\nmessage:C_DecryptMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageDecryptFinal/slot-present/3.2 check=ok\nmessage:C_MessageSignInit/slot-present/3.2 check=ok\nmessage:C_SignMessage/slot-present/3.2 check=ok\nmessage:C_SignMessageBegin/slot-present/3.2 check=ok\nmessage:C_SignMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageSignFinal/slot-present/3.2 check=ok\nmessage:C_MessageVerifyInit/slot-present/3.2 check=ok\nmessage:C_VerifyMessage/slot-present/3.2 check=ok\nmessage:C_VerifyMessageBegin/slot-present/3.2 check=ok\nmessage:C_VerifyMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageVerifyFinal/slot-present/3.2 check=ok\nshape: AES_CBC mechanism-info rv=0x0 flags=0x60300 message-encrypt=0 message-decrypt=0 multi-message=0\nmessage:fixture/open/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nshape: test_message_encrypt_single AES-256 initial-mechanism-parameter=NULL/0 plaintext-length=32 primary-call=C_MessageEncryptInit rv=0x7\nmessage:fixture/close/3.2 rv=0x0 expected=0x0\nmessage:fixture/open/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nshape: test_message_decrypt_single AES-256 initial-mechanism-parameter=NULL/0 plaintext-length=32 primary-call=C_MessageEncryptInit rv=0x7\nmessage:fixture/close/3.2 rv=0x0 expected=0x0\nmessage:fixture/open/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nshape: test_message_encrypt_multipart AES-256 initial-mechanism-parameter=NULL/0 plaintext-length=32 primary-call=C_MessageEncryptInit rv=0x7\nmessage:fixture/close/3.2 rv=0x0 expected=0x0\nmessage:fixture/open/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nshape: test_message_decrypt_multipart AES-256 initial-mechanism-parameter=NULL/0 plaintext-length=32 primary-call=C_MessageEncryptInit rv=0x7\nmessage:fixture/close/3.2 rv=0x0 expected=0x0\nmessage:fixture/open/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nshape: test_message_encrypt_decrypt_roundtrip AES-256 initial-mechanism-parameter=NULL/0 plaintext-length=32 primary-call=C_MessageEncryptInit rv=0x7\nmessage:fixture/close/3.2 rv=0x0 expected=0x0\nmessage:fixture/open/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:C_MessageEncryptInit/control-valid-iv/3.2 rv=0x0 expected=0x0\ncontrol: supplied init/message IV single encryption rv=0x0 length=32\nmessage:C_EncryptMessage/control-valid-iv/3.2 rv=0x0 expected=0x0\nmessage:C_MessageEncryptFinal/control-valid-iv/3.2 rv=0x0 expected=0x0\nmessage:C_DecryptInit/control-classic-iv/3.2 rv=0x0 expected=0x0\ncontrol: classic decrypt with same IV rv=0x0 length=32 matches-32-A=1\nmessage:C_Decrypt/control-classic-iv/3.2 rv=0x0 expected=0x0\nmessage:C_Decrypt/control-plaintext/3.2 check=ok\nmessage:C_MessageEncryptInit/control-no-message-iv/3.2 rv=0x0 expected=0x0\ncontrol: supplied init IV but oracle NULL/0 message parameter rv=0x5 length=64\nmessage:fixture/close/3.2 rv=0x0 expected=0x0\nmessage:fixture/open/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:C_MessageEncryptInit/control-multipart-iv/3.2 rv=0x0 expected=0x0\ncontrol: IV supplied; oracle plaintext placed only in Begin AAD rv=0x0\ncontrol: IV supplied; oracle empty terminal plaintext rv=0x70 length=64\nmessage:C_MessageEncryptFinal/control-aad-only/3.2 rv=0x0 expected=0x0\nmessage:fixture/close/3.2 rv=0x0 expected=0x0\nmessage:fixture/open/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:C_MessageDecryptInit/control-multipart-iv/3.2 rv=0x0 expected=0x0\ncontrol: IV supplied; oracle ciphertext placed only in Begin AAD rv=0x0\ncontrol: IV supplied; oracle empty terminal ciphertext rv=0x70 length=64 matches-32-A=0\nmessage:C_MessageDecryptFinal/control-aad-only/3.2 rv=0x0 expected=0x0\nmessage:fixture/close/3.2 rv=0x0 expected=0x0\nmessage:C_Finalize/shape-cleanup/3.2 rv=0x0 expected=0x0\n"
    }
  },
  "new_cbc_affected_nodes": [
    {
      "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single",
      "outcome": "failed",
      "mechanism": "CKM_AES_CBC (0x1082)",
      "key_bits": 256,
      "initial_parameter": "NULL/0",
      "per_message_parameter": "NULL/0",
      "plaintext": "b'A' * 32",
      "primary_call": "C_MessageEncryptInit",
      "actual_rv": "CKR_ARGUMENTS_BAD (0x7)",
      "oracle_expected_rv": "CKR_OK (0x0)"
    },
    {
      "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_single",
      "outcome": "failed",
      "mechanism": "CKM_AES_CBC (0x1082)",
      "key_bits": 256,
      "initial_parameter": "NULL/0",
      "per_message_parameter": "NULL/0",
      "plaintext": "b'A' * 32",
      "primary_call": "C_MessageEncryptInit",
      "actual_rv": "CKR_ARGUMENTS_BAD (0x7)",
      "oracle_expected_rv": "CKR_OK (0x0)"
    },
    {
      "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_multipart",
      "outcome": "xfailed",
      "mechanism": "CKM_AES_CBC (0x1082)",
      "key_bits": 256,
      "initial_parameter": "NULL/0",
      "per_message_parameter": "NULL/0",
      "plaintext": "b'A' * 32",
      "primary_call": "C_MessageEncryptInit",
      "actual_rv": "CKR_ARGUMENTS_BAD (0x7)",
      "oracle_expected_rv": "CKR_OK (0x0)"
    },
    {
      "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_multipart",
      "outcome": "failed",
      "mechanism": "CKM_AES_CBC (0x1082)",
      "key_bits": 256,
      "initial_parameter": "NULL/0",
      "per_message_parameter": "NULL/0",
      "plaintext": "b'A' * 32",
      "primary_call": "C_MessageEncryptInit",
      "actual_rv": "CKR_ARGUMENTS_BAD (0x7)",
      "oracle_expected_rv": "CKR_OK (0x0)"
    },
    {
      "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_decrypt_roundtrip",
      "outcome": "failed",
      "mechanism": "CKM_AES_CBC (0x1082)",
      "key_bits": 256,
      "initial_parameter": "NULL/0",
      "per_message_parameter": "NULL/0",
      "plaintext": "b'cross-verify test data padding!!'",
      "primary_call": "C_MessageEncryptInit",
      "actual_rv": "CKR_ARGUMENTS_BAD (0x7)",
      "oracle_expected_rv": "CKR_OK (0x0)"
    }
  ],
  "upstream_filings": [
    {
      "url": "https://github.com/mingulov/pkcs11-check/issues/34",
      "state": "OPEN",
      "body_file": "/tmp/haskoki-message-verification/upstream-issue-1.md",
      "body_sha256": "8048a3019f328b3792c25cd5f451e90b5975e1a7a3f90c05698fff7d58b51bfb",
      "exact_generated_body_verified": true
    }
  ],
  "qualification_boundary": {
    "tested_source_revision": "6610ca8426b4fecb6600be523894fef9ec55d860",
    "documentation_commit_owner": "coordinator",
    "documentation_commit_created": false,
    "post_commit_gate_and_lane_checks": "pending coordinator documentation commit and review; current record qualifies the implementation revision only"
  },
  "task_execution_deviations": [
    {
      "topic": "container identity",
      "observation": "Actual image digest differs from toolchain.lock; exact GHC/Cabal/OpenSSL versions match; recorded actual digest under coordinator override."
    },
    {
      "topic": "build freshness",
      "observation": "Cleaned pinned Cabal tree before qualifying; plain forced build in run-gates is incremental. Verified module newer than table-registration commit and all twenty std message symbols."
    },
    {
      "topic": "proxy topology",
      "observation": "message_routed is direct-only by coordinator decision; canonical proxy transcript exits zero and names the existing proxy issue reason. The task original parity expectation omits this block.",
      "url": "https://github.com/mingulov/pkcs11-proxy-ng/issues/23"
    },
    {
      "topic": "gate manifest",
      "observation": "Eighteen static checks passed. Release manifest has sixteen entries: fourteen evidence drivers, release build and clean installation."
    },
    {
      "topic": "initial consumer gate",
      "observation": "First full gates exit one with two legacy DH width/commutativity assertions. Source review and exact failure retained. Complete unchanged rerun passed. Actual failed-call CKR/length was not printed, so the width diagnosis remains source-supported rather than measured."
    },
    {
      "topic": "lane native tracing",
      "observation": "Original lane config disables tracing. Enabling an evidence-only copy still produces no native Standard trace, as Standard has no trace emitter. Preserved absent-trace failure and reran fast/kat with the existing oracle raw-call observer, copying completed raw report bytes unchanged to trace.jsonl. Producer and effective invocation are explicit."
    },
    {
      "topic": "strict finding comparison",
      "observation": "A pre-existing expected failure displays randomized ECDSA signature bytes. Kat raw tuple comparison changed one signature-prefix tuple; source review narrowed the explanation to that node and exactly its observed 32-hex-digit prefix. Both raw records remain visible; all other tuples were compared exactly."
    },
    {
      "topic": "commit dependency",
      "observation": "Explicit user override prohibits this worker from staging or committing. Post-commit gates, bundle binding, lanes and final manifest depend on the coordinator commit and remain pending at that ordered boundary."
    }
  ],
  "commands": {
    "gates": {
      "command": "HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng bash scripts/run-gates.sh",
      "exit": 0,
      "log": "dist-release-evidence/message-routing/gates.log"
    },
    "fast": {
      "command": "bash /tmp/pkcs11-ws/run-lane-rc2.sh fast",
      "environment": {
        "PATH_prefix": "/tmp/haskoki-message-verification/lane-docker",
        "PKCS11_CHECK_EXTRA_ARGS": "--rv-trace"
      },
      "exit": 0,
      "log": "dist-release-evidence/message-routing/fast.log"
    },
    "kat": {
      "command": "bash /tmp/pkcs11-ws/run-lane-rc2.sh kat",
      "environment": {
        "PATH_prefix": "/tmp/haskoki-message-verification/lane-docker",
        "PKCS11_CHECK_EXTRA_ARGS": "--rv-trace"
      },
      "exit": 0,
      "log": "dist-release-evidence/message-routing/kat.log"
    }
  },
  "lanes": {
    "fast": {
      "result_path": "/tmp/pkcs11-ws/out-rc2/fast/pkcs11-fast-results.json",
      "trace_path": "/tmp/pkcs11-ws/out-rc2/fast/trace.jsonl",
      "result_archive": "dist-release-evidence/message-routing/reviewed/fast/pkcs11-fast-results.json",
      "trace_archive": "dist-release-evidence/message-routing/reviewed/fast/trace.jsonl",
      "result_sha256": "71572d14ae33f310e5c7fcd0cba239481f3f1325d060bc1162ab2bc825b122b4",
      "trace_sha256": "070f344e5227cdb8d9abf37097212890e849eb27cd3c0fb89230661b6d6200ca",
      "summary": {
        "passed": 5138,
        "failed": 4,
        "skipped": 4414,
        "xfailed": 634,
        "xpassed": 0,
        "error": 0,
        "crashed": 0,
        "timeout": 0,
        "crash_limited": 0,
        "total": 10190,
        "child_crash": 0,
        "child_timeout": 0,
        "incomplete": false
      },
      "reviewed": true,
      "unexplained_new_findings": 0,
      "provider_defects": 0,
      "runtime_dispositions": [
        {
          "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single",
          "outcome": "failed",
          "duration": 0.0018361379916314036,
          "start": 1790770042.4686792,
          "longrepr": "pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK",
          "location": [
            "src/pkcs11_check/testcases/test_message_crypto.py",
            364,
            "TestMessageEncryptDecrypt.test_message_encrypt_single"
          ]
        },
        {
          "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_single",
          "outcome": "failed",
          "duration": 0.0013415670109679922,
          "start": 1790770042.582716,
          "longrepr": "pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK",
          "location": [
            "src/pkcs11_check/testcases/test_message_crypto.py",
            387,
            "TestMessageEncryptDecrypt.test_message_decrypt_single"
          ]
        },
        {
          "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_multipart",
          "outcome": "xfailed",
          "duration": 0.0016788020002422854,
          "start": 1790770042.6410701,
          "wasxfail": "C_MessageEncryptInit rejected advertised message operation: CKR_ARGUMENTS_BAD",
          "longrepr": "_pytest.outcomes.XFailed: C_MessageEncryptInit rejected advertised message operation: CKR_ARGUMENTS_BAD",
          "location": [
            "src/pkcs11_check/testcases/test_message_crypto.py",
            424,
            "TestMessageEncryptDecrypt.test_message_encrypt_multipart"
          ]
        },
        {
          "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_multipart",
          "outcome": "failed",
          "duration": 0.0010359909938415512,
          "start": 1790770042.6653728,
          "longrepr": "pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK",
          "location": [
            "src/pkcs11_check/testcases/test_message_crypto.py",
            462,
            "TestMessageEncryptDecrypt.test_message_decrypt_multipart"
          ]
        },
        {
          "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_decrypt_roundtrip",
          "outcome": "failed",
          "duration": 0.0012130240065744147,
          "start": 1790770042.7205765,
          "longrepr": "pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK",
          "location": [
            "src/pkcs11_check/testcases/test_message_crypto.py",
            517,
            "TestMessageEncryptDecrypt.test_message_encrypt_decrypt_roundtrip"
          ]
        }
      ]
    },
    "kat": {
      "result_path": "/tmp/pkcs11-ws/out-rc2/kat/pkcs11-kat-results.json",
      "trace_path": "/tmp/pkcs11-ws/out-rc2/kat/trace.jsonl",
      "result_archive": "dist-release-evidence/message-routing/reviewed/kat/pkcs11-kat-results.json",
      "trace_archive": "dist-release-evidence/message-routing/reviewed/kat/trace.jsonl",
      "result_sha256": "78ae6333a8b91189c37918b0240d1b57d4dcbaed830d3e0de3206aad8a26b70d",
      "trace_sha256": "f49983e50d5424ff9ce397089d3f440e410812b1bfc935027febdca0ae45dba4",
      "summary": {
        "passed": 84455,
        "failed": 4,
        "skipped": 31316,
        "xfailed": 973,
        "xpassed": 0,
        "error": 0,
        "crashed": 0,
        "timeout": 0,
        "crash_limited": 0,
        "total": 116748,
        "child_crash": 0,
        "child_timeout": 0,
        "incomplete": false
      },
      "reviewed": true,
      "unexplained_new_findings": 0,
      "provider_defects": 0,
      "runtime_dispositions": [
        {
          "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single",
          "outcome": "failed",
          "duration": 0.0016682459972798824,
          "start": 1790771231.4002435,
          "longrepr": "pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK",
          "location": [
            "src/pkcs11_check/testcases/test_message_crypto.py",
            364,
            "TestMessageEncryptDecrypt.test_message_encrypt_single"
          ]
        },
        {
          "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_single",
          "outcome": "failed",
          "duration": 0.0006446859915740788,
          "start": 1790771231.4847124,
          "longrepr": "pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK",
          "location": [
            "src/pkcs11_check/testcases/test_message_crypto.py",
            387,
            "TestMessageEncryptDecrypt.test_message_decrypt_single"
          ]
        },
        {
          "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_multipart",
          "outcome": "xfailed",
          "duration": 0.0009611030109226704,
          "start": 1790771231.5185883,
          "wasxfail": "C_MessageEncryptInit rejected advertised message operation: CKR_ARGUMENTS_BAD",
          "longrepr": "_pytest.outcomes.XFailed: C_MessageEncryptInit rejected advertised message operation: CKR_ARGUMENTS_BAD",
          "location": [
            "src/pkcs11_check/testcases/test_message_crypto.py",
            424,
            "TestMessageEncryptDecrypt.test_message_encrypt_multipart"
          ]
        },
        {
          "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_multipart",
          "outcome": "failed",
          "duration": 0.0006261509988689795,
          "start": 1790771231.535933,
          "longrepr": "pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK",
          "location": [
            "src/pkcs11_check/testcases/test_message_crypto.py",
            462,
            "TestMessageEncryptDecrypt.test_message_decrypt_multipart"
          ]
        },
        {
          "nodeid": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_decrypt_roundtrip",
          "outcome": "failed",
          "duration": 0.0006912840035511181,
          "start": 1790771231.5716004,
          "longrepr": "pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK",
          "location": [
            "src/pkcs11_check/testcases/test_message_crypto.py",
            517,
            "TestMessageEncryptDecrypt.test_message_encrypt_decrypt_roundtrip"
          ]
        }
      ]
    }
  },
  "dispositions": [
    {
      "node_parameter": "src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single [AES_CBC; AES-256; IV=NULL/0]",
      "actual": "Both fast and kat expose four failures and one expected failure with the same primary C_MessageEncryptInit result CKR_ARGUMENTS_BAD (0x7). AES_CBC mechanism-info flags are 0x60300: no CKF_MESSAGE_ENCRYPT, CKF_MESSAGE_DECRYPT or CKF_MULTI_MESSAGE. The five affected nodes and exact parameters are [{\"actual_rv\": \"CKR_ARGUMENTS_BAD (0x7)\", \"initial_parameter\": \"NULL/0\", \"key_bits\": 256, \"mechanism\": \"CKM_AES_CBC (0x1082)\", \"nodeid\": \"src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single\", \"oracle_expected_rv\": \"CKR_OK (0x0)\", \"outcome\": \"failed\", \"per_message_parameter\": \"NULL/0\", \"plaintext\": \"b'A' * 32\", \"primary_call\": \"C_MessageEncryptInit\"}, {\"actual_rv\": \"CKR_ARGUMENTS_BAD (0x7)\", \"initial_parameter\": \"NULL/0\", \"key_bits\": 256, \"mechanism\": \"CKM_AES_CBC (0x1082)\", \"nodeid\": \"src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_single\", \"oracle_expected_rv\": \"CKR_OK (0x0)\", \"outcome\": \"failed\", \"per_message_parameter\": \"NULL/0\", \"plaintext\": \"b'A' * 32\", \"primary_call\": \"C_MessageEncryptInit\"}, {\"actual_rv\": \"CKR_ARGUMENTS_BAD (0x7)\", \"initial_parameter\": \"NULL/0\", \"key_bits\": 256, \"mechanism\": \"CKM_AES_CBC (0x1082)\", \"nodeid\": \"src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_multipart\", \"oracle_expected_rv\": \"CKR_OK (0x0)\", \"outcome\": \"xfailed\", \"per_message_parameter\": \"NULL/0\", \"plaintext\": \"b'A' * 32\", \"primary_call\": \"C_MessageEncryptInit\"}, {\"actual_rv\": \"CKR_ARGUMENTS_BAD (0x7)\", \"initial_parameter\": \"NULL/0\", \"key_bits\": 256, \"mechanism\": \"CKM_AES_CBC (0x1082)\", \"nodeid\": \"src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_multipart\", \"oracle_expected_rv\": \"CKR_OK (0x0)\", \"outcome\": \"failed\", \"per_message_parameter\": \"NULL/0\", \"plaintext\": \"b'A' * 32\", \"primary_call\": \"C_MessageEncryptInit\"}, {\"actual_rv\": \"CKR_ARGUMENTS_BAD (0x7)\", \"initial_parameter\": \"NULL/0\", \"key_bits\": 256, \"mechanism\": \"CKM_AES_CBC (0x1082)\", \"nodeid\": \"src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_decrypt_roundtrip\", \"oracle_expected_rv\": \"CKR_OK (0x0)\", \"outcome\": \"failed\", \"per_message_parameter\": \"NULL/0\", \"plaintext\": \"b'cross-verify test data padding!!'\", \"primary_call\": \"C_MessageEncryptInit\"}]. The decryption nodes fail in their preceding message encryption helper; their decrypt calls were not executed. The original multipart Begin/Next calls were not executed. The independent source-shape probe and AES-256 reductions all report init 0x7. Separate controls supplying both required IV blocks successfully encrypt and classic-decrypt 32 bytes. IV-supplied controls isolating the source placement of plaintext/ciphertext in Begin AAD and an empty terminal Next return 0x70 (CKR_MECHANISM_INVALID); their unchanged output-capacity value 64 is not a produced length. A control omitting the per-message IV after a valid Init returns 0x5 (CKR_GENERAL_ERROR). Those modified controls are diagnostic observations, not results of the original oracle sequence.",
      "expected": "Gate the CBC tests using the appropriate message flags, including encryption needed for decrypt setup and CKF_MULTI_MESSAGE for multipart calls. A classic AES_CBC catalog entry and non-null function pointers do not advertise a message capability. For any deliberately opted-in recipe probe, provide its documented IV inputs and send CBC plaintext/ciphertext through Next, leaving non-AEAD AAD NULL/0. The oracle currently expects Init CKR_OK (0x0), nonempty multipart ciphertext and the original plaintext from multipart decrypt despite the recorded inputs. This provider routing task retains its existing opaque/raw 16-byte IV recipe and does not add standardized native message parameter structures or capability flags; the controls do not assert a normative CKR for unsupported shapes.",
      "reproduction": "Run from the haskoki source checkout at revision 6610ca8426b4fecb6600be523894fef9ec55d860 with the pinned module at /home/user/src/m/haskoki-ws/haskoki/dist-release/haskoki-0.3.0.0/lib/libhaskoki.so. This command materializes both full C sources using the independent consumer fixture and discovery functions, compiles without diagnostics, then runs them: python3 -c 'from pathlib import Path; Path('\"'\"'/tmp/haskoki-message-verification/oracle-repro.c'\"'\"').write_text('\"'\"'#define main message_consumer_main\\n#include \"tests/c/message_routed.c\"\\n#undef main\\nint main(int argc,char **argv) {\\n  if (argc!=2) return 2;\\n  configure();\\n  void *module=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);\\n  if (!module) return 2;\\n  CK_C_GetInterface get=(CK_C_GetInterface)dlsym(module,\"C_GetInterface\");\\n  CK_VERSION version={3,2}; CK_INTERFACE_PTR interface=NULL;\\n  if (!get || get(NULL,&version,&interface,0)!=CKR_OK) return 2;\\n  minor=2;\\n  MessageApi a=read_newest((CK_FUNCTION_LIST_3_2 *)interface->pFunctionList);\\n  if (a.C_Initialize(NULL)!=CKR_OK) return 2;\\n  CK_SLOT_ID slots[16]; CK_ULONG count=16;\\n  if (a.C_GetSlotList(CK_TRUE,slots,&count)!=CKR_OK || count==0 || count>16) return 2;\\n  tokenSlot=slots[0];\\n  Fixture f=fixture(&a);\\n  CK_MECHANISM missingIv={CKM_AES_CBC,NULL,0};\\n  CK_RV init=a.C_MessageEncryptInit(f.session,&missingIv,f.aes);\\n  printf(\"probe: CBC init without IV rv=0x%lx\\\\n\",init);\\n  if (init==CKR_OK) {\\n    CK_RV begin=a.C_EncryptMessageBegin(f.session,NULL,0,plain,16);\\n    printf(\"probe: Begin with plaintext as AAD rv=0x%lx\\\\n\",begin);\\n    if (begin==CKR_OK) {\\n      Output o; reset_output(&o,64);\\n      CK_RV next=a.C_EncryptMessageNext(f.session,NULL,0,NULL,0,o.bytes+1,&o.length,CKF_END_OF_MESSAGE);\\n      printf(\"probe: empty terminal part rv=0x%lx length=%lu\\\\n\",next,o.length);\\n    }\\n  }\\n  close_fixture(&a,f);\\n  rv(\"C_Finalize\",\"probe-cleanup\",a.C_Finalize(NULL),CKR_OK);\\n  dlclose(module); unlink(configPath);\\n  return failures ? 1 : 0;\\n}\\n'\"'\"'); Path('\"'\"'/tmp/haskoki-message-verification/oracle-shape-repro.c'\"'\"').write_text('\"'\"'#define main message_consumer_main\\n#include \"tests/c/message_routed.c\"\\n#undef main\\n\\nstatic Fixture aes256_fixture(MessageApi *a) {\\n  Fixture f=fixture(a);\\n  CK_BYTE key[32];\\n  for (size_t i=0;i<sizeof(key);++i) key[i]=(CK_BYTE)i;\\n  f.aes=make_key(a,f.session,CKK_AES,key,sizeof(key),CK_TRUE,CK_TRUE,CK_FALSE,CK_FALSE);\\n  return f;\\n}\\n\\nint main(int argc,char **argv) {\\n  if (argc!=2) return 2;\\n  configure();\\n  void *module=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);\\n  if (!module) return 2;\\n  CK_C_GetInterface get=(CK_C_GetInterface)dlsym(module,\"C_GetInterface\");\\n  CK_VERSION version={3,2}; CK_INTERFACE_PTR interface=NULL;\\n  if (!get || get(NULL,&version,&interface,0)!=CKR_OK) return 2;\\n  minor=2;\\n  CK_FUNCTION_LIST_3_2 *table=(CK_FUNCTION_LIST_3_2 *)interface->pFunctionList;\\n  MessageApi a=read_newest(table);\\n  if (a.C_Initialize(NULL)!=CKR_OK) return 2;\\n  CK_SLOT_ID slots[16]; CK_ULONG count=16;\\n  if (a.C_GetSlotList(CK_TRUE,slots,&count)!=CKR_OK || count==0 || count>16) return 2;\\n  tokenSlot=slots[0];\\n  CK_MECHANISM_INFO info={0};\\n  CK_RV result=table->C_GetMechanismInfo(tokenSlot,CKM_AES_CBC,&info);\\n  printf(\"shape: AES_CBC mechanism-info rv=0x%lx flags=0x%lx message-encrypt=%d message-decrypt=%d multi-message=%d\\\\n\",\\n         result,info.flags,!!(info.flags&CKF_MESSAGE_ENCRYPT),!!(info.flags&CKF_MESSAGE_DECRYPT),!!(info.flags&CKF_MULTI_MESSAGE));\\n  if (result!=CKR_OK) return 2;\\n  CK_BYTE data[32]; memset(data,\\'\"'\"'A\\'\"'\"',sizeof(data));\\n  CK_BYTE cross[]=\"cross-verify test data padding!!\";\\n  CK_MECHANISM missingIv={CKM_AES_CBC,NULL,0};\\n  const char *nodes[]={\"test_message_encrypt_single\",\"test_message_decrypt_single\",\"test_message_encrypt_multipart\",\"test_message_decrypt_multipart\",\"test_message_encrypt_decrypt_roundtrip\"};\\n  for (size_t i=0;i<sizeof(nodes)/sizeof(nodes[0]);++i) {\\n    Fixture f=aes256_fixture(&a);\\n    CK_ULONG inputLength=i==4 ? sizeof(cross)-1 : sizeof(data);\\n    result=a.C_MessageEncryptInit(f.session,&missingIv,f.aes);\\n    printf(\"shape: %s AES-256 initial-mechanism-parameter=NULL/0 plaintext-length=%lu primary-call=C_MessageEncryptInit rv=0x%lx\\\\n\",nodes[i],inputLength,result);\\n    close_fixture(&a,f);\\n  }\\n\\n  Fixture f=aes256_fixture(&a);\\n  rv(\"C_MessageEncryptInit\",\"control-valid-iv\",a.C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);\\n  Output encrypted; reset_output(&encrypted,64);\\n  result=a.C_EncryptMessage(f.session,iv,sizeof(iv),NULL,0,data,sizeof(data),encrypted.bytes+1,&encrypted.length);\\n  printf(\"control: supplied init/message IV single encryption rv=0x%lx length=%lu\\\\n\",result,encrypted.length);\\n  rv(\"C_EncryptMessage\",\"control-valid-iv\",result,CKR_OK);\\n  rv(\"C_MessageEncryptFinal\",\"control-valid-iv\",a.C_MessageEncryptFinal(f.session),CKR_OK);\\n  rv(\"C_DecryptInit\",\"control-classic-iv\",a.C_DecryptInit(f.session,&cbc,f.aes),CKR_OK);\\n  Output decrypted; reset_output(&decrypted,64);\\n  result=a.C_Decrypt(f.session,encrypted.bytes+1,encrypted.length,decrypted.bytes+1,&decrypted.length);\\n  printf(\"control: classic decrypt with same IV rv=0x%lx length=%lu matches-32-A=%d\\\\n\",result,decrypted.length,decrypted.length==sizeof(data) && memcmp(decrypted.bytes+1,data,sizeof(data))==0);\\n  rv(\"C_Decrypt\",\"control-classic-iv\",result,CKR_OK);\\n  check(\"C_Decrypt\",\"control-plaintext\",decrypted.length==sizeof(data) && memcmp(decrypted.bytes+1,data,sizeof(data))==0);\\n\\n  rv(\"C_MessageEncryptInit\",\"control-no-message-iv\",a.C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);\\n  Output noIv; reset_output(&noIv,64);\\n  result=a.C_EncryptMessage(f.session,NULL,0,NULL,0,data,sizeof(data),noIv.bytes+1,&noIv.length);\\n  printf(\"control: supplied init IV but oracle NULL/0 message parameter rv=0x%lx length=%lu\\\\n\",result,noIv.length);\\n  close_fixture(&a,f);\\n\\n  f=aes256_fixture(&a);\\n  rv(\"C_MessageEncryptInit\",\"control-multipart-iv\",a.C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);\\n  result=a.C_EncryptMessageBegin(f.session,iv,sizeof(iv),data,sizeof(data));\\n  printf(\"control: IV supplied; oracle plaintext placed only in Begin AAD rv=0x%lx\\\\n\",result);\\n  if (result==CKR_OK) {\\n    Output empty; reset_output(&empty,64);\\n    result=a.C_EncryptMessageNext(f.session,NULL,0,NULL,0,empty.bytes+1,&empty.length,CKF_END_OF_MESSAGE);\\n    printf(\"control: IV supplied; oracle empty terminal plaintext rv=0x%lx length=%lu\\\\n\",result,empty.length);\\n    rv(\"C_MessageEncryptFinal\",\"control-aad-only\",a.C_MessageEncryptFinal(f.session),CKR_OK);\\n  }\\n  close_fixture(&a,f);\\n\\n  f=aes256_fixture(&a);\\n  rv(\"C_MessageDecryptInit\",\"control-multipart-iv\",a.C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OK);\\n  result=a.C_DecryptMessageBegin(f.session,iv,sizeof(iv),encrypted.bytes+1,encrypted.length);\\n  printf(\"control: IV supplied; oracle ciphertext placed only in Begin AAD rv=0x%lx\\\\n\",result);\\n  if (result==CKR_OK) {\\n    Output empty; reset_output(&empty,64);\\n    result=a.C_DecryptMessageNext(f.session,NULL,0,NULL,0,empty.bytes+1,&empty.length,CKF_END_OF_MESSAGE);\\n    printf(\"control: IV supplied; oracle empty terminal ciphertext rv=0x%lx length=%lu matches-32-A=%d\\\\n\",result,empty.length,empty.length==sizeof(data) && memcmp(empty.bytes+1,data,sizeof(data))==0);\\n    rv(\"C_MessageDecryptFinal\",\"control-aad-only\",a.C_MessageDecryptFinal(f.session),CKR_OK);\\n  }\\n  close_fixture(&a,f);\\n  rv(\"C_Finalize\",\"shape-cleanup\",a.C_Finalize(NULL),CKR_OK);\\n  dlclose(module); unlink(configPath);\\n  return failures ? 1 : 0;\\n}\\n'\"'\"')' && cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor -I. /tmp/haskoki-message-verification/oracle-repro.c -ldl -lpthread -o /tmp/haskoki-message-verification/oracle-repro && /tmp/haskoki-message-verification/oracle-repro /home/user/src/m/haskoki-ws/haskoki/dist-release/haskoki-0.3.0.0/lib/libhaskoki.so && cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor -I. /tmp/haskoki-message-verification/oracle-shape-repro.c -ldl -lpthread -o /tmp/haskoki-message-verification/oracle-shape-repro && /tmp/haskoki-message-verification/oracle-shape-repro /home/user/src/m/haskoki-ws/haskoki/dist-release/haskoki-0.3.0.0/lib/libhaskoki.so ; observed exit=0, output: probe: CBC init without IV rv=0x7 | shape: AES_CBC mechanism-info rv=0x0 flags=0x60300 message-encrypt=0 message-decrypt=0 multi-message=0 | shape: test_message_encrypt_single AES-256 initial-mechanism-parameter=NULL/0 plaintext-length=32 primary-call=C_MessageEncryptInit rv=0x7 | shape: test_message_decrypt_single AES-256 initial-mechanism-parameter=NULL/0 plaintext-length=32 primary-call=C_MessageEncryptInit rv=0x7 | shape: test_message_encrypt_multipart AES-256 initial-mechanism-parameter=NULL/0 plaintext-length=32 primary-call=C_MessageEncryptInit rv=0x7 | shape: test_message_decrypt_multipart AES-256 initial-mechanism-parameter=NULL/0 plaintext-length=32 primary-call=C_MessageEncryptInit rv=0x7 | shape: test_message_encrypt_decrypt_roundtrip AES-256 initial-mechanism-parameter=NULL/0 plaintext-length=32 primary-call=C_MessageEncryptInit rv=0x7 | control: supplied init/message IV single encryption rv=0x0 length=32 | control: classic decrypt with same IV rv=0x0 length=32 matches-32-A=1 | control: supplied init IV but oracle NULL/0 message parameter rv=0x5 length=64 | control: IV supplied; oracle plaintext placed only in Begin AAD rv=0x0 | control: IV supplied; oracle empty terminal plaintext rv=0x70 length=64 | control: IV supplied; oracle ciphertext placed only in Begin AAD rv=0x0 | control: IV supplied; oracle empty terminal ciphertext rv=0x70 length=64 matches-32-A=0",
      "normative_source": "OASIS PKCS#11 Base v3.0 section 3.5, Table 8 distinguishes message flags from classic flags; sections 5.9.2-5.9.4 and 5.11.2-5.11.4 put IV/nonce in message parameters, reserve AAD for AEAD and put plaintext/ciphertext in Message/Next input: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html . Current Mechanisms v3.0 section 2.10.5 specifies the CBC 16-byte IV: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html . Local routing scope is docs/superpowers/specs/2026-09-30-message-routing-design.md sections 3.2 and 5.2, retaining the pre-existing IV-at-Init and per-message opaque IV recipe. The observed init code is a local recipe result, not proof of general message conformance.",
      "classification": "oracle",
      "status": "OPEN",
      "url": "https://github.com/mingulov/pkcs11-check/issues/34"
    },
    {
      "node_parameter": "test_mech_message.py: 26 selected nodes; test_message_crypto.py: seven SHA256_RSA_PKCS message sign/verify nodes; both fast and kat",
      "actual": "Each lane has 33 message capability skips: 20 parameter sentinels with reason No mechanism catalog because no matching message-flag entries exist, four AES_GCM MESSAGE_ENCRYPT skips, one AES_CCM MESSAGE_ENCRYPT skip, one AES_GMAC MESSAGE_SIGN skip and seven SHA256_RSA_PKCS MESSAGE_SIGN/VERIFY/MULTI_MESSAGE skips. Doctor reports the unchanged 316-entry mechanism catalog. The remaining message records are one function-availability pass and the five classified CBC findings. No skipped node supplies a successful routed call.",
      "expected": "Keep capability skips and function-availability checks separate from executed crypto success. Source definition pins 26 and 13 are not execution totals. The independent message_routed consumer provides successful happy legs for all 20 entries on versions 3.0, 3.1 and 3.2 without changing mechanism flags.",
      "reproduction": "python3 /tmp/haskoki-message-verification/review-message-dispositions.py ; observed exit=0, output: fast: {\"failed\": 4, \"xfailed\": 1} | kat: {\"failed\": 4, \"xfailed\": 1} ; independent flags command: /tmp/haskoki-message-verification/oracle-shape-repro /home/user/src/m/haskoki-ws/haskoki/dist-release/haskoki-0.3.0.0/lib/libhaskoki.so ; observed AES_CBC flags=0x60300 message-encrypt=0 message-decrypt=0 multi-message=0",
      "normative_source": "OASIS PKCS#11 Base v3.0 section 3.5 Table 8 defines CKF_MESSAGE_ENCRYPT, CKF_MESSAGE_DECRYPT, CKF_MESSAGE_SIGN, CKF_MESSAGE_VERIFY and CKF_MULTI_MESSAGE separately from classic operations: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html . Routing design sections 1 and 6 preserve the 316-mechanism catalog and keep flag-based skips separate from the independent twenty-entry, three-version proof.",
      "classification": "capability coverage",
      "status": "capability coverage; not a successful routed provider test",
      "url": ""
    }
  ],
  "oracle_cbc_probe": "message:C_MessageEncryptInit/slot-present/3.2 check=ok\nmessage:C_EncryptMessage/slot-present/3.2 check=ok\nmessage:C_EncryptMessageBegin/slot-present/3.2 check=ok\nmessage:C_EncryptMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageEncryptFinal/slot-present/3.2 check=ok\nmessage:C_MessageDecryptInit/slot-present/3.2 check=ok\nmessage:C_DecryptMessage/slot-present/3.2 check=ok\nmessage:C_DecryptMessageBegin/slot-present/3.2 check=ok\nmessage:C_DecryptMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageDecryptFinal/slot-present/3.2 check=ok\nmessage:C_MessageSignInit/slot-present/3.2 check=ok\nmessage:C_SignMessage/slot-present/3.2 check=ok\nmessage:C_SignMessageBegin/slot-present/3.2 check=ok\nmessage:C_SignMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageSignFinal/slot-present/3.2 check=ok\nmessage:C_MessageVerifyInit/slot-present/3.2 check=ok\nmessage:C_VerifyMessage/slot-present/3.2 check=ok\nmessage:C_VerifyMessageBegin/slot-present/3.2 check=ok\nmessage:C_VerifyMessageNext/slot-present/3.2 check=ok\nmessage:C_MessageVerifyFinal/slot-present/3.2 check=ok\nmessage:fixture/open/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nmessage:fixture/create-key/3.2 rv=0x0 expected=0x0\nprobe: CBC init without IV rv=0x7\nmessage:fixture/close/3.2 rv=0x0 expected=0x0\nmessage:C_Finalize/probe-cleanup/3.2 rv=0x0 expected=0x0\n"
}
```


## Async routing: proxy transport

Repository: `mingulov/pkcs11-proxy-ng`. Filed and read back on 2026-09-30:
[Async transport cannot preserve detached jobs and output bindings](https://github.com/mingulov/pkcs11-proxy-ng/issues/24)
(OPEN). This is the distinct async filing; issue 23 remains the message-routing disposition.

Proxy source pin: `a48b60ba54b0163f4999c1e4fc0514bf7dc01681`.
The installed pair was verified and mounted read-only; no proxy rebuild was used.

| Artifact | SHA-256 |
|---|---|
| `/opt/pkcs11-proxy-ng/pkcs11-proxy-ng` | `260cb245981561291eab4d29a16cb6a4d6f00dca3431f3d583d35364fab0c9e5` |
| `/opt/pkcs11-proxy-ng/libpkcs11_proxy_ng_shim.so` | `8ea85073ce8436ebdc8ee99bce99e70a6d8c34473c28b5a45567c8a26aba1690` |
| Pinned `crates/shim/src/dispatch/general/async_ops.rs` | `cf1239e40f482755006bb1d1988b9d083f8f36312ad4d9543160e9c31c40ca72` |

An independent pinned-header probe discovered the shim's 3.2 table, initialized
it and opened a real async session against an owned SQLite backend with real
OpenSSL and synthetic fallback disabled. `C_AsyncGetID(session, "C_Digest", &id)`
returned `CKR_STATE_UNSAVEABLE` (`0x180`);
`C_AsyncJoin(session, "C_Digest", 18446744073709551615UL, buffer, 32)` returned
`CKR_SAVED_STATE_INVALID` (`0x160`). Repeating both calls with null names,
null outputs, both null, and an invalid session produced the same fixed
refusals: 16 calls, all ID/buffer/adjacent sentinels unchanged. These reproduce
refusals only; they do not demonstrate successful proxy detach or Join.

At the pinned source, `c_async_get_id` lines 72–78 (return at 77) and
`c_async_join` lines 84–92 (return at 91) ignore their inputs unconditionally.
The Complete limitation is a **source observation only**: `c_async_complete`
lines 34–37 send session/function without caller capacity, while lines 41–61
copy at most the incoming caller buffer's capacity and return success. This
uses incoming storage rather than preserving the submission/Join output
binding. Complete transport behavior was not executed by this probe.

The full Task 7 direct consumer succeeds at attached completion, old-allocation
revocation/rejoin, and separately executed SQLite restart: 1,281 async
assertions, zero failures. Its complete transcript is copied to
`dist-release-evidence/async-routing/proxy/direct-task7.log` (SHA-256
`825ee5d7458235e6e47a8243f66992277c5c883d53065a7cc987f0fa13805e03`).
The compared `libhaskoki.so` has SHA-256
`6a62ee678ed6e5400cb25ad712263bf0a0914492e4a51b05e537ca1811328330`.
The issue includes the full direct happy-path sequences, module identity,
complete refusal transcript and reproduction sources; local command receipts,
pinned source and daemon log are under the same `proxy/` evidence directory.

`async_routed` therefore carries this exact issue URL in `DIRECT_ONLY`:
the full direct leg must pass, and the driver must print its explicit
exclusion. Eligible scenarios retain normal parity; no `async:` lines are
filtered. Exclusion is not async transport equivalence. This records Task 8
evidence for coordinator review; no acceptance is claimed.
