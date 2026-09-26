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
DSA slice and xfail the same way):

- `TestRsaModulusBitsOversizedValue::test_rsa_modulus_bits_oversized_value`
- `TestPrimeBitsOversizedValue::test_dsa_prime_bits_oversized_value`
- `TestGenerateKeyValueLenTruncation::test_aes_keygen_value_len_truncation`

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

## Observations (not issues)

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
