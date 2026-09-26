# OpenSSL 4 Upstream Issues Report: 4.0.2

**Generated**: 2026-09-26 03:10:00 UTC
**Status**: 🔄 in_progress
**Version**: 4.0.2
**Workflow**: pkcs11-coverage
**Phase**: detection
**Downstream**: Haskoki (pinned static libcrypto, `/opt/openssl-4.0.2`)

---

## Executive Summary

Candidate upstream issues found in OpenSSL 4.0.2 while implementing
PKCS#11 v3.2 coverage. Each entry carries a minimal reproducer and
the downstream workaround, so it can be reported verbatim. Severity
is downstream impact, not upstream triage.

## OSSL4-001: DSA paramgen pbits-only defaults q=224 for every L (non-FIPS (1024,224))

**Severity**: low (workaround exists)
**Component**: providers/default keymgmt DSA paramgen (`OSSL_PKEY_PARAM_FFC_PBITS` without `FFC_QBITS`)
**Found**: 2026-09-26 (DSA slice provider probe)

Setting only `OSSL_PKEY_PARAM_FFC_PBITS` yields q=224 bits for L in
{1024, 2048, 3072}. (1024,224) is not a FIPS 186-4 approved (L,N)
pair — approved pairs are (1024,160), (2048,224), (2048,256),
(3072,256).

Reproducer (`/tmp/dsa_probe2.c`, linked against the pinned
`libcrypto.a`):

```c
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
EVP_PKEY_paramgen_init(ctx);
/* push only OSSL_PKEY_PARAM_FFC_PBITS = 1024 */
EVP_PKEY_CTX_set_params(ctx, params);
EVP_PKEY_paramgen(ctx, &pkey);  /* q reads back 224 bits, want 160 */
```

Observed: `paramgen pbits=1024 qbits=default: ok (got q=224)`.

Downstream workaround: Haskoki always sets `FFC_QBITS` explicitly
from the FIPS pair table ({1024:160, 2048:256, 3072:256} defaults;
(2048,224) honored when requested).

## OSSL4-002: no verifiable (seeded) DSA paramgen path (legacy entry fails, provider exposes no seed)

**Severity**: medium (feature gap; blocks PKCS#11 seed-variant mechanisms)
**Component**: DSA paramgen (`DSA_generate_parameters_ex`, provider `gen` operation)
**Found**: 2026-09-26 (DSA slice provider probe)

`DSA_generate_parameters_ex(dsa, 2048, seed, seedlen, &counter,
&h, NULL)` (deprecated since 3.0) fails under 4.0.2, and the
provider `EVP_PKEY` paramgen accepts no seed/counter/index inputs.
There is therefore no way to run FIPS 186-4 verifiable p/q
generation (A.1.1.2 / A.1.2.1) or deterministic g derivation from
(p, q, seed, index) against 4.0.2.

Reproducer (`/tmp/dsa_probe.c`): the seeded call returns != 1;
observed `seeded DSA_generate_parameters_ex 2048:
unavailable/failed`.

Downstream impact: Haskoki leaves
`CKM_DSA_PROBABILISTIC_PARAMETER_GEN`,
`CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN`, and `CKM_DSA_FIPS_G_GEN`
catalog-only with provider-absence notes; the 3 oracle legs skip
via `has_mechanism` gates.

## Observations (not issues)

- **DSA raw sign accepts any digest length** (7–64 bytes verified
  at q=224/256): provider leniency consistent with FIPS 186-4
  leftmost-truncation; Haskoki enforces the PKCS#11 20-byte floor
  itself. No report needed unless upstream wants the note.
- **No AES-192-XTS**: correct — IEEE 1619 defines no 192-bit XTS
  width. Not a gap.
- **Equal-halves XTS keys refused at init**: correct provider
  weak-key check (tweak key == data key). Not a gap.
