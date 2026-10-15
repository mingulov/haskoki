# Haskoki 0.4.0.0 — provisioned tokens

This release makes tokens provisionable in-band. Haskoki remains a Haskell
PKCS#11 software token for learning and integration tests; use disposable
keys, not production secrets.

## Start here

```sh
docker run --rm --network none ghcr.io/mingulov/haskoki-demo:v0.4.0.0
```

Expect `demo-ok: 8/8 verifications hold`. No checkout, local build, or
hardware is required. Files are disposable unless you mount `/out`.
The [hands-on guide](https://github.com/mingulov/haskoki/blob/v0.4.0.0/docs/try-it.md)
shows how to keep them, generate a key with `pkcs11-tool`, and sign a message.

## Improvements

- `C_InitToken`, `C_InitPIN`, and `C_SetPIN` work end to end: the default
  slot-0 token (`haskoki-demo`, SO PIN `5678`) can be reinitialized and
  given fresh user PINs, durably across restarts; other slots can also
  be relabeled (slot 0 keeps its `haskoki-demo` label).
- Re-initialization is authorized: the caller PIN must match the existing
  SO PIN, otherwise the call is refused (`CKR_PIN_INCORRECT`) and the
  token's objects, jobs, credentials and counters are unchanged. This is
  about token state: opening a persistent store can first commit a schema
  migration even when the open is then refused (see limitations).
- A logout oracle and executable reference cover session teardown, and
  login-reopen plus provisioning-guard journeys extend consumer coverage.
- New guides: the supported-hosts matrix and operations notes; the
  publishing, hands-on, and results guides are refreshed for this release.

## Correctness repairs in this release

- SQLite write transactions stop at the first failed statement group. A
  failure after SQLite has rolled a transaction back can no longer be
  followed by a later group committing independently while the caller is
  told nothing committed.
- Commit and cleanup failures are classified from the native transaction
  state. A failed `ROLLBACK`, or a `COMMIT` error whose outcome cannot be
  established, returns an unknown-outcome result and quarantines the
  affected tokens (or the whole connection while a transaction may still be
  open) instead of reporting "not committed". A mismatch while verifying an
  ambiguous commit is likewise unknown, not "absent". Quarantine is
  process-local to the live store handle. No production trigger for an
  unknown `COMMIT` has been demonstrated; the paths were exercised through
  test-only SQLite hooks.
- Key derivation validates the destination object before publication: the
  key type must be a served symmetric type (or data) and the length must fit
  that type, otherwise `CKR_TEMPLATE_INCONSISTENT`. A request past the
  mechanism's own output ceiling still returns `CKR_KEY_SIZE_RANGE` first.
  PKCS#11 length defaults are applied for the hash (MD5, SHA-1, SHA-2,
  SHA-3 and BLAKE2B), concatenation and XOR derivations (for example DES3
  defaults to 24 bytes; an untyped SHA-256 derive yields a 32-byte generic
  secret). For hash derivation an explicit `CKK_GENERIC_SECRET` without a
  length now fails `CKR_TEMPLATE_INCOMPLETE`; BLAKE2B used to give it the
  digest width.
- A multi-output derivation that mixes valid and invalid destinations
  publishes nothing. This was already so; it is now pinned by the public
  regression `tests/c/consumer_derive_atomic.c` (SQLite store closed and
  reopened) and `KeyManagementSpec`.
- SP 800-108 additional-key templates decode like the primary template: a
  badly shaped value fails `CKR_TEMPLATE_INCONSISTENT` (a short `CK_ULONG`
  was accepted before), an unknown attribute type
  `CKR_ATTRIBUTE_TYPE_INVALID`, a `CK_ULONG` larger than a platform integer
  `CKR_KEY_SIZE_RANGE`, and a byte value over 4 MiB
  `CKR_TEMPLATE_INCONSISTENT` (these were `CKR_ARGUMENTS_BAD`). A new
  total packed-size limit fails `CKR_ARGUMENTS_BAD`. `CKA_EC_PARAMS` OIDs
  are mapped to a curve name as for primary-created objects. The whole
  request creates nothing.
- Test oracles only (no product change): the native DSA domain-parameter
  check no longer demands a 128-byte generator and is length-aware with a
  shorter-generator fixture; DH short-public and padding-tamper checks are
  deterministic; a native matrix exercises per-use context-specific
  authentication for marked keys through the public C interface.

## Client-visible behavior changes

Storage:

- A statement failure after SQLite has already rolled back the transaction
  no longer lets later write groups commit independently while the caller
  is told "not committed" (this could durably clear a user PIN).
- A `COMMIT` error after the transaction ended is an unknown outcome and
  the store reconciles: if the write landed the call returns `CKR_OK`; if
  not, `CKR_GENERAL_ERROR` and the affected token is quarantined until
  `C_Finalize`. While quarantined its writes, including login-counter
  writes, fail with `CKR_GENERAL_ERROR`.
- A `ROLLBACK` failure is no longer discarded. If the transaction still
  ended, affected tokens are quarantined; if it stays open, the whole
  connection is quarantined and `C_Login`, `C_InitToken`/`C_InitPIN`/
  `C_SetPIN`, token-object creation, derive and job reservation fail with
  `CKR_GENERAL_ERROR` until `C_Finalize` and a fresh `C_Initialize`.
- `COMMIT` returning `SQLITE_BUSY` is unchanged (a clean "not committed"),
  now pinned by a test. No on-disk format change; quarantine is
  process-local.

`C_DeriveKey`:

- A length that does not fit the destination key type now fails
  `CKR_TEMPLATE_INCONSISTENT` in every shared derive family (it used to
  succeed): AES not 16/24/32, DES3 not 24, ChaCha20 not 32, HOTP outside
  16-64, RC4 outside 1-256, other served types outside their sizes, and
  TLS/SSL3 key-material outputs.
- Asymmetric, unserved or vendor key types on a secret-key destination fail
  `CKR_TEMPLATE_INCONSISTENT`. A request past the mechanism's maximum
  output still fails first with `CKR_KEY_SIZE_RANGE`.
- Hash derivation (MD5, SHA-1/2/3) with no type and no length now succeeds
  with a generic secret of digest width (it was `CKR_TEMPLATE_INCOMPLETE`).
- Fixed-length key types with no length take their defined length on hash
  derivation, concatenate and XOR; if the mechanism cannot produce that
  many bytes the result is `CKR_KEY_SIZE_RANGE`, and types without a single
  defined length (AES, HMAC) give `CKR_TEMPLATE_INCOMPLETE`.
- BLAKE2B with explicit `CKK_GENERIC_SECRET` and no length now fails
  `CKR_TEMPLATE_INCOMPLETE` (it used to give the digest width).
- SP 800-108 additional-key template error codes changed as described
  above.

## Known limitations and v0.5 deferrals

This is a bounded release. These items are not claimed and are planned for
v0.5 or later.

- **Qualification not executed.** The 25-cell behavioral native matrix, the
  private-RTS runs (`-N1`/`-N2`/`-N4`) and targeted sanitizer qualification
  were not run. HPC module reconciliation gaps remain. The installed
  independent client portfolio (OpenSC, GnuTLS, Java) and a
  matching-certificate application journey are TO-QUALIFY, not qualified.
- **Identity and credentials.** The public token serial is derived from the
  slot index, not the stable token identity. The configuration file remains
  the credential authority until a token is first provisioned; durable
  seeding of new stores is v0.5.
- **Upgrade and refusal.** A rejected persistent open can first commit the
  schema-1 to schema-2 migration, so there is no no-write-on-refusal
  guarantee; back up the database before upgrading. An upgrade rehearsal,
  and a preflight/migrate command, are v0.5.
- **Scenario runner.** `haskoki-ctl scenario run` accepts operational fields
  it does not consume (token, mechanism, key, data, capacity, polled
  function), and a wrong-PIN login bypasses expectation handling.
  `scenario-ok` describes the logical simulation only.
- **Configured versus effective policy.** Reserved configuration knobs
  parse and are reported but are not enforced limits. See the
  [configuration reference](https://github.com/mingulov/haskoki/blob/v0.4.0.0/docs/config-honesty.md).
- **Proxy coverage (issue #17).** Policy coverage through pkcs11-proxy-ng is
  direct-only.
- **Transaction outcome (issue #18).** No production trigger for an unknown
  `COMMIT` has been demonstrated, and quarantine is process-local.
- **Derivation.** Unequal-length XOR derivation is restricted. Pre-existing
  inconsistencies remain for generic-secret defaults: explicit generic
  concatenation/XOR without a length, typed defaults for extract, HKDF,
  SP 800-108, PBKDF2, ECDH and SHAKE, DES3 key generation producing 16 bytes
  while derive and unwrap use 24, and no DES parity adjustment.

## Contents and limits

The Linux amd64 image carries the tool set recorded in the
[dependency inventory](https://github.com/mingulov/haskoki/blob/v0.4.0.0/docs/dependency-inventory.md).
Other architectures and Docker Desktop paths are unqualified. The C
library version reported by `C_GetInfo` is now {0, 4}.

The mechanism inventory and documented full-checker findings still apply.
The p11-kit example covers basic operations, not a full PKCS#11 3.x remoting
matrix. Token storage is unencrypted. See
[results](https://github.com/mingulov/haskoki/blob/v0.4.0.0/docs/release-results.md)
and [host limits](https://github.com/mingulov/haskoki/blob/v0.4.0.0/SUPPORTED-HOSTS.md).

## Downloads

Release assets include the native Linux bundle, source archive, test logs,
`release-manifest.json`, and `SHA256SUMS`. The manifest records the exact
source and image digest. `SHA256SUMS.asc` is included **only if** the owner
configures release signing; do not assume it exists. After downloading the
archives and manifest alongside the checksums, run `sha256sum -c SHA256SUMS`.

The [publishing guide](https://github.com/mingulov/haskoki/blob/v0.4.0.0/docs/publishing.md)
explains the GitHub-only build and publication workflow. A source branch
preparing this version does not mean its release or image has been published.
The latest published release at the time of writing is v0.3.1.0.
