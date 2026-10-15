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
  PKCS#11 length defaults are applied for the SHA-based, concatenation and
  XOR derivations (for example DES3 defaults to 24 bytes; an untyped SHA-256
  derive yields a 32-byte generic secret).
- <!-- TODO(task4): confirm --> Multi-output derivation atomicity is pinned by a public regression.
- Test oracles only (no product change): the native DSA domain-parameter
  check no longer demands a 128-byte generator and is length-aware with a
  shorter-generator fixture; DH short-public and padding-tamper checks are
  deterministic; a native matrix exercises per-use context-specific
  authentication for marked keys through the public C interface.

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
