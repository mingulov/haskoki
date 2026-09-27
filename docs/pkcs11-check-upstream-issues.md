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

## P11C-001: HOTP registry entry has key_type=None; wrong-key-type tests HARD-FAIL every lane

**Severity**: medium (2 red tests in every fast/KAT lane; masks real regressions)
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
skip/xfail when the entry is incomplete), so the lane is green and
a future real wrong-key-type regression is visible.

Downstream handling: Haskoki triages these 2 as known-external in
every round (`docs/pkcs11-oracle-triage.md`) and confirms by test id
that no other failure hides behind the count.

## P11C-002: `_KEY_SIZE_REJECT_RVS` carries wrong numeric CKR codes; correct refusals xfail

**Severity**: low (3 xfails per lane that should pass; masks nothing red)
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

**Severity**: medium (6 red tests in every lane running `test_acvp_slhdsa.py`; masks real regressions)
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

**Severity**: low (1 red test in the rc1 fast lane)
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
