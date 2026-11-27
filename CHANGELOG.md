# Changelog

## [0.6.2.0] - unreleased

Cleanup release. The per-change detail is in
[docs/release-notes-0.6.2.0.md](docs/release-notes-0.6.2.0.md).
Reports `libraryVersion` 0.6 and `haskoki-ctl 0.6.2.0`.

### Fixed

- Model contract: a null-intent retry on a staged message slot
  re-reports the staged length (`CKR_BUFFER_TOO_SMALL`) and
  keeps the staged bytes, instead of delivering, counting, and
  dropping them (`retryMessageStaged` IntentNull arm). C API
  behavior is unchanged (NULL queries already answered OK plus
  length); the visible effect is that re-queries now pass
  through the retain path like classic retries.
- Spec validation gate repaired and wired into CI: the
  GENERATED-HEADER stub pins (stale since message/async entries
  gained routed implementations) now match the generated
  `abi_stubs.inc`, and `validate-spec.py` runs in static gates.

### Tests

- `file:` URI twin agreement locked down with new pins (lock
  and alias twins; sidecar twins pre-existed). No behavior
  change: the decode-once rule already held.

### CI

- KAT lane split into 4 file-balanced shards with a merge job
  (same report artifact); expected wall ~15-20m per shard.

## [0.6.1.0] - 2026-11-27

USDT observability release. The per-change detail is in
[docs/release-notes-0.6.1.0.md](docs/release-notes-0.6.1.0.md).

### Added

- USDT probes in two providers: Latchset-compatible
  `crypto_auditing` records (one per delivered public-key
  operation) and a private `haskoki` namespace (`operation_end`,
  `policy_reject`, `job_state`). Compiled in behind the `usdt`
  Cabal flag (on for the official bundle and demo image); no
  secret bytes in any probe.

## [0.6.0.0] - 2026-11-25

Testable RnD release. The per-change detail is in
[docs/release-notes-0.6.0.0.md](docs/release-notes-0.6.0.0.md).
Reports `libraryVersion` 0.6 and `haskoki-ctl 0.6.0.0`.

### Added

- Compatibility matrix (`docs/compatibility.md`, generated): every
  binary × store × config × interface combination resolves to
  `works`, `migrate`, or `refuse`, gated in CI. Store schemas 1
  and 2 open only through an explicit `haskoki-ctl store migrate`.
- Three newly served return codes (63 total): `CKR_DEVICE_ERROR`,
  `CKR_DOMAIN_PARAMS_INVALID`, `CKR_WRAPPED_KEY_LEN_RANGE`.
- Config-gated test seams: `storage.allow_env_seams` (default
  `false`) opts the config-driven serving open into consulting
  `HASKOKI_PROC_ROOT` (owner liveness) and `HASKOKI_OPEN_PAUSE*`
  (fresh-init pause on create, with a `go`-file handshake and a
  ~30s poll-budget fallback). Serving opens run masked with
  bounded, single-deadline cancellation cleanup.
- Firefox client-authentication example (`examples/firefox`):
  a disposable scripted-browser desktop doing client-auth through
  the PKCS#11 module, with a Marionette acceptance client.

### Changed

- Supply chain: OpenSSL 4.1.0 (statically linked `libcrypto`,
  shipped legacy provider), `pkcs11-check` 0.3.1 and
  `pkcs11-proxy-ng` v0.3.1 in the demo image and CI lanes.
- Exact per-function errors: rejected key material, over-length
  input, lost backend state, and ceilings report the spec-listed
  code for the calling function instead of `CKR_GENERAL_ERROR`;
  deliberately unclassified failures keep it and emit one JSONL
  trace row each with the typed cause.
- Scenario-async config rename: `[async]` becomes
  `[scenario.async]`. Files using only the legacy header keep
  loading with values migrated; files with keys under both
  headers refuse with a remedy.

### Removed

- No public Haskell library: the package exposes only the C ABI.
  The stub facade (`Haskoki.PKCS11`, already deprecated) and its
  top-level re-export are deleted; out-of-tree `import Haskoki.*`
  now fails at dependency resolution (checked in CI).

### Fixed

- ECDSA raw signatures on wider-order curves are order-width now
  (PKCS#11 §6.3.1 nLen): secp160r1/r2/k1 sign 42 bytes (was 40),
  secp224k1 signs 58 (was 56). Short even forms still verify, so
  previously emitted signatures keep verifying.
- EC private import bounds scalars by the group order (SEC1
  §2.3.6) and enforces 1 ≤ d < n: 21-byte scalars load on the
  160-bit curves with 161-bit orders (were refused); 52-byte
  scalars refuse on sect409k1 (51-byte order; were accepted).
- Store-path spelling is one rule everywhere: bare `file:` URIs
  decode once up front, so the guards, SQLite, the trace-alias
  guard, the config select, and migrate's backup dir all act on
  the same path. Query/fragment, undecodable, nested,
  non-local-authority, and resolve-produced URIs refuse, as do
  the empty path and `:memory:` (SQLite would open a temporary
  or in-memory database the file guards cannot see).
- Derived DES-family keys take FIPS 46-3 odd-parity adjustment
  (DES/DES2/DES3/CDMF, on every derive mechanism — byte ops,
  digest KDFs, SHA1-KD — not just PBE), so `C_DeriveKey` output
  carries valid parity bits instead of raw construction bytes.

## [0.5.0.0] - 2026-10-19

First public release. The complete per-change list is in the
[0.5.0.0 changelog at the release tag](https://github.com/mingulov/haskoki/blob/v0.5.0.0/CHANGELOG.md).

### Added

- Attribute sensitivity: new private and secret keys are unextractable by
  default, sensitive values are never returned or matched, and the token
  stamps creation history itself.
- Storage schema 3 with a one-time `haskoki-ctl store migrate` (verified
  backup and receipt) and a read-only `haskoki-ctl store check`.
- Client journeys with OpenSC, GnuTLS, Java (SunPKCS11) and OpenSSL: 61 of
  61 with the installed bundle, 28 of 28 in the demo image.

### Changed

- New keys default to `CKA_DERIVE=false`; set it in the template to derive.
- Token serials are the token id as 16 hex digits; update saved `pkcs11:`
  URIs that select by `serial=`.
- Clearer error codes: mechanism parameter errors return
  `CKR_MECHANISM_PARAM_INVALID`, bad key handles `CKR_KEY_HANDLE_INVALID`,
  and wrong-length signatures `CKR_SIGNATURE_LEN_RANGE`.
- HOTP takes the standard `CK_OTP_PARAMS`.
- Tracing is off by default; `[trace] enabled = true` turns it on.
- Non-ASCII token labels and PINs are refused.

### Fixed

- A hang in hosts running two or more GHC RTS capabilities, a
  use-after-free on session close with a native async call in flight, and
  a race between concurrent first native calls.
- DH shared secrets keep their leading zero bytes.
- Stale store locks, including those left by a killed container, are taken
  over; lock descriptors no longer leak into child processes.
- `C_FindObjects` matches public keys by the value `C_GetAttributeValue`
  returns, and generated EC private keys carry `CKA_EC_PARAMS`.

### Security

These also affect 0.4.0.0, which has no patch release; upgrade to 0.5.0.0.

- Seeds of protected ML-DSA, ML-KEM and SLH-DSA private keys are sealed.
- Byte derivations and copy templates can no longer reveal a protected key.
- `CKA_ALLOWED_MECHANISMS` is enforced on derive, wrap, unwrap and KEM.
- Keys of the wrong type or class are refused, so an RSA-typed secret
  object cannot sign with an EC key.

## [0.4.0.0] - 2026-10-15

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

First tagged release (not announced): a native Linux x86-64 bundle,
verified source archive, test reports, checksums, release manifest,
and Docker demo image.
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

These were development milestones, before the first tagged release:

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
