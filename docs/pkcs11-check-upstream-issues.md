# External-checker issues

External tests sometimes reveal a token defect, and sometimes reveal a
malformed test input or a capability assumption. This register records the
checker-side cases found during Haskoki development. Current demo counts
are in [release results](release-results.md); the demo pins checker 0.2.3.

## Corrections verified during development

The following fixes were checked against 0.2.2rc2 on September 28, 2026.
A source correction and an executed crypto case are different observations.

| Case | Problem | Correction and scope |
| --- | --- | --- |
| HOTP key type | Missing registry key type made wrong-key tests select an invalid fixture | Use the mechanism's specific key type; provider return-code differences remain separate |
| Key-size refusal codes | Numeric constants mislabeled legitimate errors | Use symbolic CKR constants; the corrected rejection set accepts the tested template refusal |
| SLH-DSA vectors | Signature verification dropped a vector's context | Carry context through parameter construction; context-bound KATs were exercised |
| X9.42 DH fixtures | Corrupt generator and a peer outside the subgroup | Correct the RFC 5114 values and verify subgroup membership and shared-secret bytes |
| BLAKE2B key generation | Templates used generic-secret instead of the mechanism-specific key type | Correct the keygen template; this does not settle which key types HMAC operations may accept |
| WTLS premaster fixtures | Required version omitted; booleans encoded as native unsigned longs | Supply the one-byte version and one-byte booleans; retain the intentional NULL negative |
| X9.42 AES derivation | Helper omitted output length | Set `CKA_VALUE_LEN` to 16 |
| Camellia CTR | Missing recipe sent NULL instead of CTR parameters | Supply counter parameters; malformed-input return codes remain provider observations |
| Poly1305 parameters | Registry required parameters while selecting a no-parameter recipe | Mark them optional; this was source verification, not execution of an advertised row in that run |
| GMAC vectors | Wrong parameter shape and sign-direction handling | Use the 3.x GCM structure and verify direction; earlier skipped vectors were not failed crypto executions |

These were originally tracked as P11C-001 through P11C-010. Other provider
findings, such as `CKA_LOCAL` (now reported on keys), are not erased by a
checker fix.

## Pending upstream reports

Recorded for filing against the checker. The finding stays in the frozen
shared set until the checker pin changes.

**BLAKE2B HMAC wrong-key-type tests use a valid key type.**
`test_registry_message_{sign,verify}_wrong_key_type[BLAKE2B_*_HMAC{,_GENERAL}]`
(16 cases) picks `CKK_GENERIC_SECRET` as the wrong key whenever the registry
key generator is not `CKM_GENERIC_SECRET_KEY_GEN`. The BLAKE2B rows use
`CKM_BLAKE2B_*_KEY_GEN`, so they get a generic-secret key. PKCS#11 3.1
section 6.33.3 says: "The keys it uses are generic secret keys and
CKK_BLAKE2B_160_HMAC", and table 172 lists "generic secret or
CKK_BLAKE2B_160_HMAC" for `C_Sign` and `C_Verify`. Sections 6.34.3 to 6.36.3
say the same for the 256, 384 and 512 widths, and the non-general mechanisms
are "a special case" of the general ones. A module that accepts the key is
conforming. The SHA-2 and SHA-3 HMAC rows already skip this test because
their registry generator is `CKM_GENERIC_SECRET_KEY_GEN`. Suggested
correction: choose a key type outside the mechanism's list (for example
`CKK_AES`) as the wrong key. Haskoki pins both sides natively: a
generic-secret key signs and verifies BLAKE2B-256-HMAC against an independent
oracle, and an AES key is refused with `CKR_KEY_TYPE_INCONSISTENT`
(`tests/c/consumer_roundtrip.c`, "blake2b-key-type"). Filed upstream as
[BLAKE2B message-API wrong-key-type helper,
#53](https://github.com/mingulov/pkcs11-check/issues/53).

## Public issue reports

| Report | What the test needed to distinguish |
| --- | --- |
| [Message recipes, #34](https://github.com/mingulov/pkcs11-check/issues/34) | Classic mechanism flags do not advertise message operations. CBC needs the documented IV inputs; multipart plaintext belongs in Next, not AAD. |
| [Async GetID selector, #35](https://github.com/mingulov/pkcs11-check/issues/35) | An empty function name is an argument error; a valid name with no job is a different test. The id output is a scalar, not a length. |
| [Async ABI version, #36](https://github.com/mingulov/pkcs11-check/issues/36) | Complete/GetID/Join belong to the 3.2 table. Availability and defined refusals do not demonstrate a successful job. |

All three reports were closed on October 5, 2026. Their public threads
retain the original inputs and comparisons. They describe historical
checker versions, not unresolved findings in every later release.

One report is open. [Async child results,
#49](https://github.com/mingulov/pkcs11-check/issues/49): the
`ckr_v32_raw` async probes pass a ctypes character buffer where the
binding declares unsigned bytes, so they fail before `C_AsyncGetID` is
called. It covers the two async findings in the current set; nothing new
needs filing for them.

## Remaining recipe and provider boundaries

The raw RSA X9.31 recipe needs prehashed input rather than the generic
44-byte message used in the original test. Haskoki's length-refusal choice
is a separate provider issue; changing that code alone does not repair the
input. This was recorded as P11C-011.

HOTP message-init probes still omit the `CK_OTP_COUNTER` entry that
Haskoki's stateless profile requires (P11C-012). Since v0.5 HOTP
advertises no message flags, so those probes target an unadvertised
operation. Earlier CBC message recipes omitted IVs (P11C-013), and RSA
recover recipes omitted `CKA_SIGN_RECOVER`/`CKA_VERIFY_RECOVER` permissions
(P11C-014). The latter CBC/recover findings left the demo baseline when
the checker recipes were corrected. They are not part of the current
18-finding set.

For current provider limitations and transport exclusions, use the
[qualification reference](pkcs11-oracle-triage.md) and
[parity driver](../scripts/test-proxy-parity.sh). Native consumers supply
separate evidence for successful async, notification, and certificate work.
