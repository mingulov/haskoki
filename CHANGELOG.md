# Changelog

## [0.5.0.0] - Unreleased

- Token serial numbers come from the durable token identity.
  `C_GetTokenInfo` reports the token's `TokenId` as 16 lowercase hex
  digits, independent of slot and label, so a moved token keeps its
  serial and `C_InitToken` keeps it too. v0.4 reported the slot index
  plus one in decimal. The values are unchanged for a positional
  catalog of up to 9 tokens. They change for a 10th or later token, for
  pinned non-positional `token_ids`, and after a slot move: update any
  saved `pkcs11:` URI that selects those tokens by `serial=`. Serials
  are unique within one store only: every store seeded from a catalog
  gives its home token `0000000000000001`.
- SQLite stores write each new token's credential row (the configured
  SO and user PIN) in the same transaction as the token. The stored row
  is then the PIN authority: editing a configured PIN no longer changes
  what an existing token accepts.
- A SQLite store holding tokens without a credential row (written by
  v0.4 or earlier, including every schema-1 store with tokens) refuses
  to open as migration-required before any write: the file stays
  byte-identical. Identity refusals report first. The open fails
  `C_Initialize`; `haskoki-ctl store check` names the tokens and
  `haskoki-ctl store migrate` migrates such a store.
- Opening a schema-1 SQLite store no longer migrates it at open. The
  open only reads; the schema moves to version 2 inside the first
  commit transaction, so a refused open leaves a schema-1 file at
  schema 1.
- The test-only `storeResetToken` keeps the token's credential row.

## [0.4.0.0] - Unreleased

- Token provisioning lifecycle: `C_InitToken`, `C_InitPIN`, and `C_SetPIN`
  are routed end to end with durable SQLite persistence, catalog-seeded
  credentials until the first commit, and consumer coverage.
- Token re-initialization now checks the caller PIN against the existing
  SO PIN (PKCS#11 v3.2, section 5.5.7). A wrong PIN is refused with
  `CKR_PIN_INCORRECT` and changes nothing: no objects, credentials,
  attempts, or locks are touched.
- Serving credential view with fail-closed resync: after an ambiguous
  store write, authentication re-reads the durable rows instead of
  trusting a possibly stale view.
- Logout oracle and executable reference, plus login-reopen and
  provisioning-guard journey tests.
- Documentation: supported-hosts matrix, operations notes, and refreshed
  publishing, hands-on, and results guides.
- Function-contract catalog regenerated with reworded reason texts
  (section 4 of the B3 docs inventory records each row).
  The C library version is now {0, 4}.
- `C_DeriveKey` checks the derived key type and length before it does
  any work and again before it creates an object. An AES result must be
  16, 24, or 32 bytes, and RC4 1 to 256 bytes. A secret key cannot use
  an RSA, EC, or other asymmetric key type, or an unserved vendor type.
  A length the mechanism can produce but the key type does not allow
  fails with `CKR_TEMPLATE_INCONSISTENT`. A length beyond the
  mechanism's output (for example more than 32 bytes from SHA-256 key
  derivation) still fails first with `CKR_KEY_SIZE_RANGE`. Refused
  requests create no object and leave the output handle unchanged.
- Fixed-width hash key derivation (the MD5, SHA-1, SHA-2, SHA-3 and
  BLAKE2B rows) and the concatenate and XOR mechanisms follow the PKCS#11
  length defaults. With no key type and no length, the result is a
  generic secret of the natural width: the digest width for hash key
  derivation, the combined input width for concatenation, and the base
  key length for XOR. A key type with a single defined length takes
  that length when none is given (for example DES 8, DES2 16, DES3 24
  and ChaCha20 32 bytes); if the mechanism cannot produce that many
  bytes, the request fails with `CKR_KEY_SIZE_RANGE`. A key type
  without a single defined length, such as AES, fails with
  `CKR_TEMPLATE_INCOMPLETE`. For hash key derivation an explicit
  `CKK_GENERIC_SECRET` without a length also fails with
  `CKR_TEMPLATE_INCOMPLETE`; this changes BLAKE2B, which used to give
  it the digest width. Concatenation and XOR still give an explicit
  generic secret the natural width.
- A multi-output `C_DeriveKey` (SP 800-108 with additional derived
  keys) that mixes valid and invalid destinations refuses as a whole.
  A new native journey test pins this for token objects: no handle
  slot is written, no object or handle is consumed, and after the
  SQLite store is closed and reopened no subset of the outputs exists.
- SP 800-108 additional-key templates are decoded by the same template
  decoder as the primary `C_DeriveKey` template. A malformed value (for
  example a `CKA_VALUE_LEN` that is not exactly a `CK_ULONG`, which was
  read as a shorter integer and accepted) now fails with the primary
  template's code: `CKR_TEMPLATE_INCONSISTENT` for a value of the wrong
  shape, `CKR_ATTRIBUTE_TYPE_INVALID` for an unknown attribute type.
  A `CK_ULONG` larger than a platform integer fails with
  `CKR_KEY_SIZE_RANGE`, and a byte value over 4 MiB with
  `CKR_TEMPLATE_INCONSISTENT` (both were `CKR_ARGUMENTS_BAD`); a new
  limit on the total packed template size fails with
  `CKR_ARGUMENTS_BAD`. A `CKA_EC_PARAMS` OID is mapped to a curve name
  as for primary-created objects. The whole request then creates
  nothing.
- SQLite write transactions stop at the first failed statement group. A
  failure after SQLite has already rolled the transaction back can no
  longer be followed by a later group committing independently while
  the caller is told "not committed" (this could durably clear a user
  PIN).
- A `COMMIT` error after the transaction ended is an unknown outcome and
  the store reconciles: if the write landed the PKCS#11 call returns
  `CKR_OK`; if not, `CKR_GENERAL_ERROR`, and the affected token is
  quarantined until `C_Finalize`. While quarantined, its writes
  (including login-counter writes) fail with `CKR_GENERAL_ERROR`.
  `COMMIT` returning `SQLITE_BUSY` is unchanged: a clean "not
  committed", now pinned by a test.
- A `ROLLBACK` failure is no longer silently discarded. If the
  transaction still ended, the affected tokens are quarantined; if it
  stays open, the whole connection is quarantined and `C_Login`,
  `C_InitToken`/`C_InitPIN`/`C_SetPIN`, token-object creation, derive
  and job reservation fail with `CKR_GENERAL_ERROR` until `C_Finalize`
  and a fresh `C_Initialize`. There is no on-disk format change;
  quarantine is process-local.

## [0.3.1.0] - 2026-10-12

- Shorter onboarding, a clearer development story, and dated model-usage
  statistics.
- The Docker demo runs without an output mount; `shell` prepares a token
  and the client tools for hands-on experiments.
- `proxy-demo` runs the direct/proxy example. `p11-kit-demo` adds a local
  server/client example with signing, verification, digest, tamper, and
  disconnected-server checks.
- GitHub tests the new beginner commands on the same saved image as the
  full checker and comparison jobs. Image builds record their size.
- Public references describe current behavior and link to reproducible
  tests instead of embedded campaign logs.

## [0.3.0.0] - 2026-10-09

First public release: a native Linux x86-64 bundle, verified source
archive, test reports, checksums, release manifest, and Docker demo image.
See the [release notes](docs/release-notes-0.3.0.0.md) and
[measured results](docs/release-results.md).

The release exposes PKCS#11 2.40, 3.0, 3.1, and 3.2 layouts. The mechanism
catalog has 464 entries, of which 316 have behavior tests and are served
through the C surface. Unsupported operations retain explicit refusals.

Development leading to this release included:

- Sessions, token-scoped login and object visibility, PIN lockout, key
  generation, signing, encryption, wrapping, derivation, and random bytes.
  `C_SeedRandom` uses engine-specific seed semantics; caller bytes are not
  credited as entropy on the OpenSSL path.
- Real OpenSSL crypto and a separate synthetic engine for controlled model
  tests, with broader cipher, curve, and post-quantum coverage.
- Streamed multipart digests and framed block-cipher updates. Digest
  resources release through the three `publishCommit` funnels plus the
  `Runtime`/`Async` drains, including aborted and rejected operations
  ([consumer tests](tests/c/consumer_streaming.c)).
- PKCS#11 message routing, Digest-only public 3.2 async work, detached
  SQLite recovery, slot notifications, and synchronous Digest callbacks.
- Multiple configured tokens, certificate objects, single-writer SQLite
  persistence, bounded job retention, and explicit storage-failure handling.
- Native client and direct/proxy tests, external-checker triage, coverage
  publication, relocatable runtime packaging, and GitHub release checks.

## Earlier development

These were development milestones, before the first public release:

- **September 20, 2026:** first C-loadable Haskell module, function-table
  layouts, and a small SHA-256 path.
- **September 21-23:** behavior model, sessions and objects, client tests,
  and native packaging.
- **September 24:** [public repository import](https://github.com/mingulov/haskoki/commit/2cd3f37).
- **September 25-October 8:** expanded crypto coverage, newer interfaces,
  notifications and certificates, followed by demo and release preparation.

The [creation story](docs/haskoki-creation-story.md) and
[timeline](docs/haskoki-creation-story-timeline.md) explain how these pieces
fit together.
