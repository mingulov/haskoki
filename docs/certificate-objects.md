# Certificate objects

Haskoki can store, find, copy, read, and destroy public certificate
objects. This is object storage, not certificate-chain validation.

## Creation and readback

An X.509 object requires `CKA_CERTIFICATE_TYPE`, `CKA_VALUE`, and the
presence of `CKA_SUBJECT`. SUBJECT may be empty. Other certificate subtype
values use the generic CLASS/TYPE path; they do not gain X.509 semantics.

`CKA_START_DATE` and `CKA_END_DATE`, when supplied, must be eight ASCII
digits. The token does not check calendar validity or enforce a validity
period. See `checkCertificateDates` in [Object.hs](../core/Haskoki/Object.hs).

## Supplied-values metadata position

SUBJECT, ISSUER, SERIAL, public-key info, and hash attributes are opaque
bytes supplied by the caller. Haskoki returns and matches those bytes; it
does not derive them from VALUE, parse DER, or check that they agree with
the certificate. Garbage VALUE and contradictory metadata remain accepted
when the required fields and attribute shapes are present.

[CertificateSpec](../tests/model/CertificateSpec.hs) exercises this policy
in `caseSuppliedOpaque` and `caseNoCoherenceGate`. Applications needing DER
parsing, trust decisions, or chain validation must perform those separately.

## Mutation and trust

Copies inherit immutable certificate fields. Trying to override any member
of `certImmutable` returns `CKR_TEMPLATE_INCONSISTENT`, including TRUSTED
and security-officer copies. Setting immutable fields returns
`CKR_ATTRIBUTE_READ_ONLY`, with two TRUSTED exceptions: any login may set
`false`; only the security officer may set `true`. The
`caseCertImmutableMatrix` and `caseTrustedBoundary` tests cover these rules.

DATA objects have a separate policy: their CLASS and VALUE remain read-only
after creation ([ObjectSpec](../tests/model/ObjectSpec.hs),
`caseSetAttrRatchets`).

The numeric `CKO_TRUST` and `CKO_VALIDATION` classes can use generic
attributes, but `CKA_TRUST_*`, `CKA_HASH_OF_CERTIFICATE`, and
`CKA_VALIDATION_*` have no typed implementation. Unsupported numeric
attributes return `CKR_ATTRIBUTE_TYPE_INVALID`, an unavailable length, and
leave the value buffer untouched. `C_GetObjectSize` remains unsupported.
The full typed inventory is in [Attribute.hs](../core/Haskoki/Attribute.hs).

## Linking a certificate to a key

Use the same `CKA_ID` on the certificate and its key objects. Private-key
import uses the key-type components, such as RSA modulus and exponents;
it does not accept a PEM-decoded private DER blob in `CKA_VALUE` as an
alternative import format. [CertificateEngineSpec](../tests/engine/CertificateEngineSpec.hs)
checks ID linkage and a real signature with `caseIdLinkage` and
`caseRealSignature`.

## Persistence and clients

Token objects persist when SQLite storage is configured; session objects
do not. Stored certificate and key bytes are unencrypted. Ambiguous commits
are checked by rereading the stored delta, without reissuing the operation;
an unreadable result retains the storage fault. See the
[commit protocol](operations-notes.md#quarantine-protocol-memory--sqlite-stores).

The [native certificate consumer](../tests/c/consumer_certificates.c)
exercises the C surface. The pinned proxy forwards the qualified lifecycle
subset, but certificate visibility/restart legs remain direct-only under
[proxy issue 27](https://github.com/mingulov/pkcs11-proxy-ng/issues/27).
The [parity driver](../scripts/test-proxy-parity.sh) defines the exact subset.
