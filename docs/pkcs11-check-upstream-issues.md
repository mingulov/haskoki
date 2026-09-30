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
