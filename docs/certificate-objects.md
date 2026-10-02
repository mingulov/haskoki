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
passing runs.

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
the passing runs. The recipe remainder (raw-DER-through-`CKA_VALUE`
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
the passing runs.

## Subtype and size disposition

Spec trace: §2.1 G10/G11, §3 C07.

Non-X.509 subtype values keep the generic CLASS+TYPE-only path:
`caseCertNonX509Generic` (`tests/model/CertificateSpec.hs:161-173`;
types 1 and 2 commit with CLASS+TYPE only, VALUE/SUBJECT omitted)
is passing in the T-C01 proof — see
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
passing runs.

## DATA VALUE policy

Spec trace: §2.1 G15, §3 C11.

DATA `VALUE` immutability is deliberate policy, not an
implementation gap: `caseSetAttrRatchets`
(`tests/model/ObjectSpec.hs:940-971`) creates a DATA object and
pins that CLASS and VALUE are never mutable — the
"Class and value never mutable" assertions (lines 958-963) refuse
both with `CKR_ATTRIBUTE_READ_ONLY` — passing in
`dist-release-evidence/certificates/task-c11/retained.log`
(`task-c11/retained`,
`set-attributes: ratchets and atomicity: OK`). The oracle
recognizes this same refusal as policy: its DATA-VALUE node
`src/pkcs11_check/testcases/test_object_visibility.py::TestCrossSessionModification::test_modify_value_cross_session`
(oracle source lines 508-582, the `xfail_as` honest-deviation
policy marker at 547-553) attempts `C_SetAttributeValue` on a
data object's `CKA_VALUE` and xfails on the provider's
`CKR_ATTRIBUTE_READ_ONLY`/`CKR_ATTRIBUTE_VALUE_INVALID`
("Module treats CKA_VALUE as read-only after object creation";
xfailed in both the fast and kat lane results). This DATA policy
is separate from the certificate immutable-field requirements:
copy-override of any `certImmutable` member
(`core/Haskoki/Object.hs:514-519`, enforced for certificate
sources by the copy guard at 961-964) refuses with
`CKR_TEMPLATE_INCONSISTENT` for every login and both TRUSTED
values — copies inherit the source fields and there is no
exception, not even SO `TRUSTED=true` — while set refuses with
`CKR_ATTRIBUTE_READ_ONLY` with exactly two exceptions:
`TRUSTED=false` writes (all logins) and SO `TRUSTED=true`. The
matrix is pinned by `caseCertImmutableMatrix`
(`tests/model/CertificateSpec.hs:535-614`: every member refused
on copy, SO `TRUSTED=true` copy still refused, both set
exceptions committed) and `caseTrustedBoundary`
(`tests/model/CertificateSpec.hs:254-430`: `TRUSTED=false`
stored and read back for all four login shapes, SO-only
`TRUSTED=true`), both passing in `task-c11/retained`. Citation
record with live-byte hashes:
`dist-release-evidence/certificates/task-c11/pin.json`. See
`task-c11/docs` and `task-c11/retained` for the passing runs.

## Contract and evidence alignment

Spec trace: §2.1 G14, §3 C10.

Contract rows: the six object functions `C_CreateObject`,
`C_CopyObject`, `C_DestroyObject`, `C_GetAttributeValue`,
`C_SetAttributeValue`, and `C_FindObjects` in
`spec/function-contracts.json` carry certificate test evidence
(the T-C09 native consumer plus the model and engine
certificate specs on Create) and `policy_refs` to the
[supplied-values metadata
position](#supplied-values-metadata-position) above.
`C_FindObjectsInit` and `C_FindObjectsFinal` keep
`unsupported-with-reason` classification; their reason carries
the planner-scope suffix (pure-engine one-shot model; the
public FFI cursor lives above this layer). Classification
counts stay `104/70/32/2`; the generator diff is
evidence-only (see `task-c10/generate`).

Public-surface evidence (T-C09, provisional): 48/48 native
legs in `dist-release-evidence/certificates/task-c09/after.log`
(`task-c09/after`), reviewed fast/kat lane inspections in
`reviewed/fast-inspection.json` and
`reviewed/kat-inspection.json` (`reviewed/fast-review`,
`reviewed/kat-review`, zero unresolved provider findings),
and the proxy branch-(b) reproduction with three upstream
filings ([proxy-ng
#26](https://github.com/mingulov/pkcs11-proxy-ng/issues/26),
[#27](https://github.com/mingulov/pkcs11-proxy-ng/issues/27),
[#28](https://github.com/mingulov/pkcs11-proxy-ng/issues/28));
detail is in the certificates T-C09 section of
`docs/pkcs11-oracle-triage.md`.

Deferrals complete: [trust and validation
deferral](#trust-and-validation-deferral) (no `CKA_TRUST_*` /
`CKA_VALIDATION_*` typed support), [subtype and size
disposition](#subtype-and-size-disposition) (non-X.509 generic
path, unmapped fields, `C_GetObjectSize` stub), and the [DATA
VALUE policy](#data-value-policy) above; creation and
durability positions in [supplied-values metadata
position](#supplied-values-metadata-position) and [durability
convergence note](#durability-convergence-note); interop in
[certificate/key identity
interop](#certificatekey-identity-interop). See
`task-c10/after`, `task-c10/docs`, `task-c10/denominators`,
and `task-c10/history` for the alignment checks.
