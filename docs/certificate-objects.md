# Certificate objects

Certificate-object policy and disposition record. This file is created
by T-C04 and later tasks append their own headed sections after it
(T-C05/T-C06/T-C07/T-C11 append; T-C10 finalizes).

Spec trace: §2.1 G05, §3 C04 (this skeleton plus the two sections
below). Later sections carry their own spec traces.

Evidence root: `dist-release-evidence/certificates/task-c04/`; the
focused pins run in `task-c04/after.log` and the prose gate runs in
`task-c04/docs.log` (full suites in `task-c04/retained.log`).

## Supplied-values metadata position

Normative supplied-values position: `SUBJECT`, `ISSUER`,
`SERIAL_NUMBER`, `PUBLIC_KEY_INFO`, and both hash attributes are
opaque caller-supplied bytes. The token never derives them from
`VALUE`, never validates DER structure, and never checks
metadata-to-VALUE coherence. Wrong-metadata cases are refused only
where the standard defines refusal (missing required fields per
C01: TYPE/VALUE/SUBJECT presence for X.509).

Pins (synthetic bytes deliberately, pinning the absence of parsing;
real DER is qualified by T-C02/T-C09): `caseSuppliedOpaque` creates
X.509 with garbage non-DER VALUE plus arbitrary SUBJECT/ISSUER/
SERIAL/SPKI/both-hashes, reads every field back exactly, and matches
find by each supplied field; `caseNoCoherenceGate` creates with
SUBJECT/ISSUER/SERIAL contradicting each other and VALUE, and shows
only missing required fields refuse. See
`dist-release-evidence/certificates/task-c04/after.log`
(`task-c04/after`), `task-c04/docs`, and `task-c04/retained` for the
green runs.

## Durability convergence note

The T-C02 convergence rule below is incorporated verbatim from
`dist-release-evidence/certificates/task-c02/convergence-note.md`:

After an unknown store commit, the gate-held caller re-reads tokens
plus meta and compares every projected put, drop, and meta row
against the reread state: all rows present means the commit landed
and the projected model publishes; any row absent means it did not,
so the pre model is kept and the store fault is returned; an
unreadable re-read fails closed the same way (model kept, fault
returned). Nothing reissues the operation, so the durable state
stays single-writer consistent, and the next open replays the
reservation from the persisted counters and converges to the same
high-waters.

Later tasks append their headed sections below this line.

## Certificate/key identity interop

Spec trace: §2.1 G07, §3 C05.

The oracle identity recipe (`test_identity.py:71-158` in
pkcs11-check 0.2.2rc2) imports each private key by stuffing the raw
PEM-decoded private DER through `CKA_VALUE` with only
CLASS/KEY_TYPE/ID/LABEL/TOKEN/SIGN/EXTRACTABLE/SENSITIVE alongside
it (lines 109-125), then asserts only `sig is not None` (line 143).
That recipe shape is incompatible with component-based private-key
import: this provider builds private keys from their key-type
components (for RSA: modulus, exponents, primes), never from a raw
DER blob in `CKA_VALUE`, so the recipe's private-key import leg
cannot succeed here — once per Limbo case carrying a peer key (202
import failures across the pinned corpus). What the recipe means
to prove — ID linkage between a certificate and its keys, plus a
working signature from the linked identity — is shown instead by
this task's cases: `caseIdLinkage` imports the RSA pair through
the component import, creates an X.509 certificate with VALUE =
fixture DER, assigns `CKA_ID="link"` on all three objects, and
shows find-by-ID returning exactly those three handles with
matching ID readback on each; `caseRealSignature` signs the
certificate VALUE bytes with the imported private DER and verifies
with the public DER to a real `EngineOk ()` (not a non-None
assertion). See `dist-release-evidence/certificates/task-c05/after.log`
(`task-c05/after`), `task-c05/docs`, and `task-c05/retained` for
the green runs. The recipe remainder (raw-DER-through-`CKA_VALUE`
import) is dispositioned as oracle-recipe incompatibility, NOT a provider conformance defect.
Triage is untouched here; T-C09 owns lane-tied triage.

## Trust and validation deferral

Spec trace: §2.1 G08/G09, §3 C06.

`CKO_TRUST` (0x0b) and `CKO_VALIDATION` (0x0a) stay
registered-but-unserved: both numeric classes remain creatable
through the generic path with generic attributes only, and no
`CKA_TRUST_*`, `CKA_HASH_OF_CERTIFICATE`, or `CKA_VALIDATION_*`
typed support is added. The generic side is pinned by
`caseTrustGenericPinned` (create `CKO_TRUST` with
CLASS/LABEL/ISSUER/SERIAL → OK; a typed read over
`[AttributeType]` returns the generic values — the typed seam
cannot express raw numeric ids) and
`caseValidationGenericPinned` (create `CKO_VALIDATION` with
generic attributes → OK, stored values read back). The absence
side is pinned at the scalar FFI getter by
`caseTrustNumericPinned` (each of `0x62c`–`0x632` plus `0x635`)
and `caseValidationNumericPinned` (each of `0x61e`–`0x629`,
where `0x61e` is `CKA_OBJECT_VALIDATION_FLAGS` and
`0x61f`–`0x629` are `CKA_VALIDATION_*`): every id refuses with
the deferral triple — RV `CKR_ATTRIBUTE_TYPE_INVALID` (0x12),
`pLen == maxBound` (`CK_UNAVAILABLE_INFORMATION`), and the value
buffer byte-identical to its pre-call canary fill, plus proof
the id is genuinely unmodeled: its generated name exists yet
`attributeTypeByName` returns `Nothing`, so the refusal comes
from the unknown-id path in `haskokiStdGetOneAttr` (which pokes
only `pLen` and never touches the buffer), not the
modeled-but-missing arm that emits the same triple. These pins
record absence; they must
NOT be "fixed" into service. Rationale: the oracle qualifies
only empty enumeration — its trust/validation tests pass on
empty enumeration and skip dependents — so there is no qualified
behavior to serve and no fabricated trust semantics are recorded
here. See `dist-release-evidence/certificates/task-c06/after.log`
(`task-c06/after`), `task-c06/docs`, and `task-c06/retained` for
the green runs.

## Subtype and size disposition

Spec trace: §2.1 G10/G11, §3 C07.

Non-X.509 subtype values keep the generic CLASS+TYPE-only path:
`caseCertNonX509Generic` (`tests/model/CertificateSpec.hs:161-173`;
types 1 and 2 commit with CLASS+TYPE only, VALUE/SUBJECT omitted)
is green in the T-C01 proof — see
`dist-release-evidence/certificates/task-c01/after.log`
(`task-c01/after`); this task cites that receipt and re-proves
nothing. The remaining declared fields — `CKA_URL` (0x89),
`CKA_JAVA_MIDP_SECURITY_DOMAIN` (0x88),
`CKA_NAME_HASH_ALGORITHM` (0x8c), `CKA_CHECK_VALUE` (0x90),
`CKA_AC_ISSUER` (0x83), `CKA_OWNER` (0x84), `CKA_ATTR_TYPES`
(0x85), `CKA_UNIQUE_ID` (0x04) — have no model/storage mapping:
`attributeTypeByName` in `core/Haskoki/Attribute.hs` (lines
354-412, fallthrough `_ -> Nothing` at line 412) has no arms for
them, and the `attrName` / `nameAttr` / `decodeAttrValue` maps in
`src/Haskoki/Runtime/Storage.hs` (lines 943-1001 / 1004-1063 /
1076-1141) have no rows for them either — both files are
grep-clean for the `CKA_*` and `Attr*` spellings, and the only
post-T-C01 additions to those maps are T-C03's four
trusted/category/date rows. `C_GetObjectSize` remains the
explicit stub: `stub_GetObjectSize` in
`cbits/function_tables.c` (actual lines 875-881; the plan-time
citation 870-880 covered the disposition comment at 870-874 —
"GetObjectSize stays honestly unsupported (no engine planner)" —
plus the stub head, re-resolved here by reading), wired at line
1137, returning `stub_probe()` (lines 810-816:
`CKR_FUNCTION_NOT_SUPPORTED` live,
`CKR_CRYPTOKI_NOT_INITIALIZED` pre-init). The stub keeps refusing
cleanly; no behavior change. Inspection record with per-file
SHA-256 at HEAD `fd9ff48838ab48e1cac99c7adc7ceafa3b1c2177`:
`dist-release-evidence/certificates/task-c07/inspection.json`
(Attribute.hs `6550421f…`, Storage.hs `ac315382…`,
function_tables.c `4687bdb0…`; full SHA-256 digests in the
record). See `task-c07/docs` and `task-c07/retained` for the
green runs.
