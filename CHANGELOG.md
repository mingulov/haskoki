# Changelog

## [Unreleased]

Behaviour changes a caller written against 0.4.0.0 can observe:

- `CKM_AES_GMAC` no longer advertises `CKF_MESSAGE_SIGN` or
  `CKF_MESSAGE_VERIFY`: PKCS#11 defines no message-API parameter shape
  for it. Single-part sign and verify with `CK_GCM_PARAMS` are unchanged.
- `CKM_XOR_BASE_AND_DATA` accepts a base key and data of different
  lengths (PKCS#11 v3.1 section 6.43.6). The natural result width is the
  shorter of the two; a template length past it fails with
  `CKR_KEY_SIZE_RANGE`. Unequal lengths used to fail with
  `CKR_DATA_LEN_RANGE`.
- `CKM_HOTP` takes the standard `CK_OTP_PARAMS` (an array of
  `CK_OTP_PARAM` entries). A `CK_OTP_COUNTER` entry of 8 big-endian bytes
  is required for sign and verify, since no token counter is kept;
  `CK_OTP_OUTPUT_LENGTH` (6 to 8) is optional, default 6. The old 16-byte
  `counter || digits` image is refused with
  `CKR_MECHANISM_PARAM_INVALID`. HOTP has no message API: its message
  routes and `CKF_MESSAGE_SIGN`/`CKF_MESSAGE_VERIFY` flags are withdrawn.
- `C_MessageEncryptInit`, `C_MessageDecryptInit`, `C_MessageSignInit` and
  `C_MessageVerifyInit` refuse `CKR_MECHANISM_INVALID` for a mechanism
  without a message route of that kind: HOTP, `CKM_SSL3_MD5_MAC`,
  `CKM_SSL3_SHA1_MAC`, `CKM_AES_CCM` and `CKM_CHACHA20_POLY1305`. For the
  SSL3 MACs, AES-CCM and ChaCha20-Poly1305 these inits used to succeed,
  and every data call on the context then failed.
- A missing, short or malformed mechanism parameter returns
  `CKR_MECHANISM_PARAM_INVALID` (0x71) instead of `CKR_ARGUMENTS_BAD`
  (0x7) for 21 families: digest, cipher, RSA PKCS#1 v1.5, RSA-PSS,
  RSA-OAEP, RSA X.509, RSA X9.31, Poly1305, ECDSA, DSA, EdDSA, ML-DSA,
  SLH-DSA, CMAC, DES3-MAC, CBC-MAC, XCBC-MAC, AES-GMAC, HOTP, AES-GCM and
  ChaCha20 (HMAC, SSL3 MAC and AES-CCM already returned 0x71). A NULL
  `pMechanism`, or a NULL `pParameter` with a nonzero length, still
  returns `CKR_ARGUMENTS_BAD`.
- An unknown, destroyed or invisible key handle at keyed
  `C_EncryptInit`/`C_DecryptInit`/`C_SignInit`/`C_VerifyInit` and their
  message-API counterparts, at `C_DigestKey`, and at
  `C_SignRecoverInit`/`C_VerifyRecoverInit` returns
  `CKR_KEY_HANDLE_INVALID` (0x60) instead of `CKR_OBJECT_HANDLE_INVALID`
  (0x82). Wrap, unwrap and KEM key resolution still return 0x82.

### Fixed

- A hang in hosts that load the provider with at least 2 RTS
  capabilities (`GHCRTS=-N2` or higher, or `-N`). When two threads
  opened the OpenSSL 4 backend at once, they could both evaluate the
  same lazy capability table, and a GHC runtime bug (GHC #27272, seen
  on 9.10.3, 9.12.4 and 9.14.1) could leave a string literal's
  black hole without an owner, blocking every thread that needed it.
  Capability tables are now fully evaluated before they are published.
  The default of 1 capability is not exposed. Releases up to 0.4.0.0
  are affected; until upgrading, run with a single capability or
  serialize the first open.
- Store lock and guard file descriptors are now opened with
  `O_CLOEXEC` atomically. A child process started while a store was
  being opened could inherit the descriptor and keep the store locked
  after it was closed.

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
