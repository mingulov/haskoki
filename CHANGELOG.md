# Changelog

## [Unreleased]

Behaviour changes a caller written against 0.4.0.0 can observe:

- Fresh keys report explicit creation history. Generated keys read
  `CKA_LOCAL` true with `CKA_KEY_GEN_MECHANISM` set to the generating
  mechanism; `CKA_ALWAYS_SENSITIVE` reads true when the key was born
  sensitive and `CKA_NEVER_EXTRACTABLE` reads true when it was born
  unextractable. Imported, unwrapped and derived keys read `CKA_LOCAL`
  false with an unavailable mechanism; unwrapped and imported keys read
  both history rows false, while derived keys conjoin the child flags
  with the source history. Secret keys produced by KEM encapsulate and
  decapsulate read `CKA_LOCAL` false with both history rows false and
  an unavailable `CKA_KEY_GEN_MECHANISM`. In 0.4.0.0 these four
  attributes were unmapped: reads failed with
  `CKR_ATTRIBUTE_TYPE_INVALID`. Keys generated from a password
  (`CKM_PKCS5_PBKD2` and the PBE mechanisms) stamp the same rows per
  the spec; their values can be recomputed off-token from the
  password, so their history flags do not prove the value never
  existed elsewhere.
- `C_UnwrapKey` with a template that omits `CKA_EXTRACTABLE` now yields
  an extractable key (PKCS#11 v3.2 section 5.18.4). In 0.4.0.0 the
  flag stayed absent: reads of `CKA_EXTRACTABLE` failed with
  `CKR_ATTRIBUTE_TYPE_INVALID`, the value read back in clear, and
  wrapping the key failed. Now the flag reads true and wrapping works.
- `C_DeriveKey` with a template that omits `CKA_SENSITIVE` or
  `CKA_EXTRACTABLE` now inherits the source values. In 0.4.0.0 omitted
  flags stayed absent, and reads failed with
  `CKR_ATTRIBUTE_TYPE_INVALID`. Derived children of extractable bases
  are now extractable.
- `C_CopyObject` refuses history attributes (`CKA_ALWAYS_SENSITIVE`,
  `CKA_NEVER_EXTRACTABLE`, `CKA_LOCAL`, `CKA_KEY_GEN_MECHANISM`) in the
  template unconditionally, even when the value matches the source.
  In 0.4.0.0 these attributes were unmapped, so no copy template
  could name them.
- Byte-operation derives now read the base key's effective
  `CKA_EXTRACTABLE`: a base without stored protection flags counts
  as unextractable, so a derive template asking
  `CKA_EXTRACTABLE=true` over such a base fails with
  `CKR_TEMPLATE_INCONSISTENT`. Create the base with
  `CKA_SENSITIVE=false` and `CKA_EXTRACTABLE=true` explicitly to
  keep deriving readable children from it.
- Public keys report `CKA_SENSITIVE=false` and
  `CKA_EXTRACTABLE=true` when the template omits them, and public
  key material always reads back, whatever protection flags the
  template stored. Explicit flags on a public template are stored
  and reported, with no sealing effect.
- `C_CopyObject` validates its template through the same
  per-attribute policy as `C_SetAttributeValue` on the source.
  Copies can no longer replace key material, forge protection
  labels, drop `CKA_ALWAYS_AUTHENTICATE`, widen
  `CKA_ALLOWED_MECHANISMS`, or change anything on a
  `CKA_MODIFIABLE=false` source beyond the copy exemptions.
  Refusals use the set path's `CKR_ATTRIBUTE_READ_ONLY`.
- `C_CopyObject` with `CKA_MODIFIABLE=true` over a
  `CKA_MODIFIABLE=false` source fails with
  `CKR_ATTRIBUTE_READ_ONLY`: the copy may only tighten
  (`true` to `false`) or keep the value. Loosening by copy
  would let a caller set usage flags the source forbids.
- `C_CopyObject` may set `CKA_TOKEN` and `CKA_DESTROYABLE`
  freely in both directions; the source is untouched. A token
  object copies to a session object with `CKA_TOKEN=false`,
  and back with `CKA_TOKEN=true`. `CKA_COPYABLE` still only
  goes to `false`, and a sealed key still cannot be made
  public (`CKA_PRIVATE` `true` to `false`).
- `C_CopyObject` of a `CKA_MODIFIABLE=false` data object with
  a new `CKA_VALUE` fails with `CKR_ATTRIBUTE_READ_ONLY`.
  The data value merge applies on modifiable sources only.
- `C_CopyObject` refuses `CKA_START_DATE`, `CKA_END_DATE`
  and `CKA_SUBJECT` changes on keys, matching the set path,
  with `CKR_ATTRIBUTE_READ_ONLY`. On certificates these fields
  were already refused; they now report `CKR_ATTRIBUTE_READ_ONLY`
  where they used to report `CKR_TEMPLATE_INCONSISTENT`.
- `C_CopyObject` refuses any template naming `CKA_TRUSTED`
  on a certificate source with `CKR_ATTRIBUTE_READ_ONLY`,
  even for the same value and even for the Security Officer.
  Copy a certificate by omitting `CKA_TRUSTED` from the
  template; a `TRUSTED=true` source still needs the Security
  Officer, and a normal user cannot copy it at all.
- `C_CopyObject` refuses `CKA_CLASS` and `CKA_KEY_TYPE`
  overrides with `CKR_ATTRIBUTE_READ_ONLY`, matching the set
  path. Copying a sealed private or secret key as a public key
  or data object no longer works; certificate class-override
  copies report this code too, where they used to report
  `CKR_TEMPLATE_INCONSISTENT`.
- Reads of `CKA_SEED` on a sensitive or unextractable ML-DSA,
  ML-KEM or SLH-DSA private key now fail with
  `CKR_ATTRIBUTE_SENSITIVE` instead of returning the seed, and
  `C_FindObjects` no longer matches such keys by seed. In
  0.4.0.0 the seed, the private key material, read back in
  clear.
- A private or secret key stored without `CKA_EXTRACTABLE`
  now counts as unextractable: reads of its value fail with
  `CKR_ATTRIBUTE_SENSITIVE`, and `C_FindObjects` withholds its
  sealed components. Such keys used to read back in clear.
- Stores written with the new key attributes are refused by
  older binaries: unknown attribute names fail decode, so
  upgrade is one-way.
- New private and secret keys default to unextractable.
  `C_GenerateKey`, the private half of `C_GenerateKeyPair`,
  `C_CreateObject` and the KEM outputs stamp `CKA_EXTRACTABLE=false`
  when the template omits it, so reads of `CKA_VALUE` and the private
  components fail with `CKR_ATTRIBUTE_SENSITIVE`. In 0.4.0.0 the flag
  stayed absent and the values read back in clear. Set
  `CKA_EXTRACTABLE=true` and `CKA_SENSITIVE=false` explicitly in the
  template to keep a new key readable.
- Caller templates may no longer carry creation-history attributes
  on any path: create, generate, key-pair, unwrap, derive and KEM
  templates naming `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE`,
  `CKA_LOCAL` or `CKA_KEY_GEN_MECHANISM` fail with
  `CKR_TEMPLATE_INCONSISTENT`, and `C_SetAttributeValue` refuses them
  with `CKR_ATTRIBUTE_READ_ONLY`. In 0.4.0.0 both answers were
  `CKR_ATTRIBUTE_TYPE_INVALID`, since the attributes were unmapped.
- Copy refusals that reported `CKR_TEMPLATE_INCONSISTENT` in
  0.4.0.0 now report the set path's `CKR_ATTRIBUTE_READ_ONLY`:
  clearing `CKA_SENSITIVE`, setting `CKA_EXTRACTABLE` true,
  `CKA_TRUSTED=true` from a non-SO session, every
  certificate-immutable field, and `CKA_VALUE_LEN`. The copies were
  already refused; only the code changed.
- `C_FindObjects` templates naming `CKA_SENSITIVE`,
  `CKA_EXTRACTABLE` or a creation-history attribute now match key
  objects by effective value, so a key stored without
  `CKA_EXTRACTABLE` matches `CKA_EXTRACTABLE=false`. In 0.4.0.0
  matching ran over the stored rows, so absent flags never matched.
- Public keys report no `CKA_ALWAYS_SENSITIVE` and no
  `CKA_NEVER_EXTRACTABLE`: reads fail with
  `CKR_ATTRIBUTE_TYPE_INVALID`, since PKCS#11 Table 27 assigns those
  rows to private and secret keys only. In 0.4.0.0 the attributes
  were unmapped on every class; now only public keys answer this way.
- `C_CopyObject` naming the value or a private component of a
  sealed key fails with `CKR_ATTRIBUTE_READ_ONLY` whatever the value,
  even when it matches the source. In 0.4.0.0 the copy succeeded, so
  a caller could confirm a guessed key value or seed one guess at a
  time. Copy a sealed key by omitting its sealed components from the
  template; unsealed keys are unchanged.
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
- The shipped `libhaskoki.so` no longer exports the 27 test-only native
  symbols (`hsk_ossl4_test_*` and the `hsk_ossl4_*_gated` entries). They
  were never part of the ABI (`spec/abi-inventory.json` lists none), but
  `nm -D` showed them. The test registry that could absorb a repeat free
  is no longer compiled into the shipped module: production destruction
  frees on every call.
- The ECDH, X25519/X448 and DH derives cleanse the unused tail of the
  secret buffer when OpenSSL reports a shorter secret than the size query,
  and fail closed (a native error, with the whole buffer cleansed) when it
  reports a longer one. The tail used to be left as the derive wrote it.
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
- SQLite stores move to schema 3. Stores written by v0.4.0.0 (schema 2)
  or v0.3.x (schema 1) are refused at open, with nothing written absent
  a hot journal or a `-wal`/`-shm` sibling (a hot journal is rolled
  back by the serving open before it refuses), until
  `haskoki-ctl store migrate --path FILE --config FILE --backup-dir DIR`
  migrates them once. An ordinary open never migrates; `store migrate` is
  the only path to schema 3. Migrate takes ownership, writes a verified
  backup and a receipt, records the configured PINs only for tokens without
  a credential row (PINs changed in-band are kept), and moves the schema in
  one transaction. v0.4.0.0 and v0.3.1.0 binaries refuse a migrated store;
  restore the backup to go back.
- `haskoki-ctl store check --path FILE --config FILE` reports, without
  writing, whether the store opens with that config, and what migration or
  catalog fix it needs.
- SQLite stores refuse to open, with `C_Initialize` failing closed, when
  a non-empty `-wal` or `-shm` sibling exists. Haskoki never writes one,
  so it comes from foreign tooling; the open refuses before any SQLite
  connection, so no foreign frame is checkpointed into the store.
- A store path that is a symlink is resolved once, and the lock and
  journal sidecars follow the real file. A link whose target is missing
  refuses at open instead of creating a store at the target; a missing
  store under a symlinked parent directory is still created.
- Identity refusal messages no longer say 'in this phase'; they name the
  absence of a relabel or slot-move command.
- The test-only `storeResetToken` keeps the token's credential row.
- `C_FindObjects` on a removed session answers
  `CKR_SESSION_HANDLE_INVALID`; it used to answer
  `CKR_OPERATION_NOT_INITIALIZED`. The session check now runs before
  the cursor lookup, and refusals leave the output buffer and count
  untouched.

New documents: `docs/native-qualification.md` (native shim qualification
record: symbol separation, sanitizer runs, evidence limits) and
`docs/buffered-updates.md` (measured cost of buffered multipart updates).

### Added

- PIN-change races are now exercised with distinct values: two threads
  racing `A->B` against `A->C` over the public C entry points produce
  one winner, the loser's credential is refused with
  `CKR_PIN_INCORRECT`, and no stale login succeeds after the change.
  The old same-value case stays as a separate idempotent-serialization
  check.
- Token provisioning now runs end to end across fresh processes:
  initialize, set PIN, change PIN, failure lockout, SO recovery and
  reset, over two tokens with sibling objects and jobs, with the
  durable credential bytes compared after every run except the
  lockout leg, which checks lock state instead.
- An installed-tool provisioning journey is registered as nine journey
  rows: `pkcs11-tool` InitToken, SO-authorized InitPIN, user change-PIN,
  EC keygen, public-key export, sign, an independent `openssl` verify,
  new-PIN listing and old-PIN refusal, each in its own process with
  pinned argv and exits, markers where the tool prints them: the
  export leg checks its output file instead, and the sign leg relies
  on the independent `openssl` verifier.
- The role and operation matrix now covers create across the
  public/user/SO, read-only/read-write, session/token and
  public/private splits, with sampled copy, set and destroy cells,
  while the permitted public read-write mutations stay pinned by a
  positive control.

### Changed

- Detached-job attachment claims are now exclusive across detach
  contexts. Claim state moved out of each context into one claim
  authority per open store handle (per token), so two contexts over one
  store can no longer both join the same persistent id: the second join
  is refused with `CKR_OPERATION_ACTIVE`, and a context that loses a
  join race cannot retire or cancel the winner. The authority lives
  only in the process, is never written to disk, and starts empty when
  the store is reopened.
- `Haskoki.Runtime.Storage`: `Store` has a new strict field
  `storeClaims :: !ClaimAuthority`, exported without its constructor,
  plus the read-only inspectors `claimCensus` and `markCensus`. A
  `Store` can no longer be built from scratch outside the library;
  record-update wrappers of the memory and SQLite stores keep working
  and share the wrapped handle's authority.
- `Haskoki.Runtime.Detached`: `markJobOpaque` takes the job's table,
  and marks are keyed by table and job. A mark is no longer consumed
  by a refused detach; it clears on a successful detach, or when a
  context that marked or served the table retires it. `detachStats`
  and `inspectAttachment` report the store handle's shared state for
  the context's token. `retireLiveTable` and `retireLiveTableFor`
  retire only tables the context joined through.

### Fixed

- Async submit now carries checked call work end to end: normal
  submission re-checks the triple and its outer function before any
  id is consumed, and hand-built fixtures submit through the named
  test-only admission. No C-visible behavior changes.
- The reference exercise traces one AES-GCM parameter path from the
  native struct image through planning, checked construction and the
  real backend seal, pinned against an independent vector.
- A hang in hosts that load the provider with at least 2 RTS
  capabilities (`GHCRTS=-N2` or higher, or `-N`). When two threads
  opened the OpenSSL 4 backend at once, they could both evaluate the
  same lazy capability table, and a GHC runtime bug (GHC #27272, seen
  on 9.10.3, 9.12.4 and 9.14.1) could leave a string literal's
  black hole without an owner, blocking every thread that needed it.
  Capability tables are now fully evaluated before they are published.
  The default of 1 capability is not exposed.
  0.4.0.0 is affected (earlier releases not checked); until upgrading,
  run with a single capability or serialize the first open.
- Store lock and guard file descriptors are now opened with
  `O_CLOEXEC` atomically. A child process started while a store was
  being opened could inherit the descriptor and keep the store locked
  after it was closed.
- A detach no longer resets a persistent id to idle when a join of
  that id (through any context) landed between the durable insert and
  the idle record; a third join used to be able to start a second live
  job.
- Storage objects (data, certificates, keys, domain parameters, trust
  and vendor-defined objects) report the common storage attributes
  they were created without. `C_GetAttributeValue` returned
  `CKR_ATTRIBUTE_TYPE_INVALID` for an omitted `CKA_TOKEN`,
  `CKA_PRIVATE`, `CKA_MODIFIABLE`, `CKA_COPYABLE`, `CKA_DESTROYABLE`
  or `CKA_LABEL`. It now returns the value the provider enforces:
  `CKA_TOKEN` and `CKA_PRIVATE` false, `CKA_MODIFIABLE`,
  `CKA_COPYABLE` and `CKA_DESTROYABLE` true, and an empty `CKA_LABEL`.
  `C_FindObjects` matches the same values, so a template with
  `CKA_PRIVATE` false finds an object created without `CKA_PRIVATE`,
  and one with `CKA_PRIVATE` true does not. A template with an empty
  `CKA_LABEL` now matches objects created without a label. The values
  are worked out when read, never stored, so stored objects and SQLite
  databases are unchanged. Hardware feature, mechanism, profile and validation
  objects are not storage objects and still report these attributes
  as unavailable. `CKA_UNIQUE_ID` is not implemented and stays
  unavailable. A proxy that hides objects of unknown privacy from a
  logged-out session could not find such objects again after a client
  restart.
- `C_SetAttributeValue` accepts `CKA_COPYABLE` or `CKA_DESTROYABLE`
  true on an object created without that attribute. Such an object is
  already copyable and destroyable, but writing true was refused with
  `CKR_ATTRIBUTE_READ_ONLY`. The write now succeeds and stores the
  explicit value. Changing either attribute from false to true is
  still refused.
- `C_CopyObject` refuses a template that sets `CKA_EXTRACTABLE` true
  unless the source object is effectively extractable, with the set
  path's `CKR_ATTRIBUTE_READ_ONLY`. A private or secret key created
  without `CKA_EXTRACTABLE` cannot be wrapped, and setting the
  attribute to true on it is refused; a copy that set it to true used
  to succeed, and that copy could be wrapped. A copy that sets
  `CKA_EXTRACTABLE` false, or leaves it out, still succeeds, and so
  does a copy of a public key, which counts as extractable.
- A failed RSA-OAEP decrypt cleansed the output buffer with the length
  the failing OpenSSL call reported instead of the allocation size.
  The failure path now cleanses the recorded allocation. The same
  failure-path shape is fixed in the sibling helpers: RSA decrypt
  (PKCS#1 v1.5, whose buffer holds the raw RSA-decrypted block) and
  RSA encrypt (OAEP and PKCS#1 v1.5), and the RSA, RSA-PSS, RSA X9.31,
  ECDSA, DSA, EdDSA, ML-DSA and SLH-DSA sign helpers. A provider that
  grew the reported length could make the cleanse overrun the
  allocation; one that shrank it left scratch bytes uncleansed.
  Return values are unchanged: padding failures still answer the
  uniform verdict.
- Standalone async acquisition now cleans up after itself. When a
  standalone store, context, or store-bound context open fails or is
  canceled after acquiring a resource, the open closes what it held
  (Store, backend, pointer, registry entry) before reporting NULL, and
  the primary error is kept when a cleanup close also fails. A Store
  whose cleanup closes both failed, and which no caller can receive,
  is recovered by the next standalone open or close in the process
  instead of staying unreachable with its lock held (`ResidueOwner`
  in `ffi/Haskoki/FFI/Async.hs`).
- Standalone context close is now cancellable at every blocking wait
  but the bounded SQLite busy waits inside FFI calls, and resumable.
  A close canceled in the borrower wait reopens the context; one
  canceled past it leaves the context owned by its slot in a closing
  state that admits nothing, and the next close through the slot
  resumes teardown where it stopped. The final nonblocking pointer
  transfer (retire the registry entry, free the pointer, null the
  slot) runs uninterruptibly, as do the bounded backend-drain and
  Store-close tails. A failed or canceled store-box close likewise
  keeps its slot until a retry closes the Store for real.
- Calls through an unregistered async context key (never registered,
  or parked by a test hook only) are now refused before any
  dereference, the same as retired keys; previously they could be
  admitted through a production fallback. Fixture registration is now
  the separately named TEST-ONLY `registerFixtureCtx`, and no caller
  under `ffi/` or `src/` uses it.
- `C_FindObjects` on a removed session answers
  `CKR_SESSION_HANDLE_INVALID`; it used to answer
  `CKR_OPERATION_NOT_INITIALIZED`. The session check now runs before
  the cursor lookup, refusals leave the output buffer and count
  untouched; the cursor retires with its session, and a fresh session
  inherits no cursor, still reporting `CKR_OPERATION_NOT_INITIALIZED`.
- A generated EC private key now carries `CKA_EC_PARAMS`, copied from
  the public half when the private template omits it. Clients that
  read the curve from the private key, such as Java's jarsigner
  through SunPKCS11, no longer fail with
  `CKR_ATTRIBUTE_TYPE_INVALID` (0x12). A private template naming a
  different curve than the public half is refused with
  `CKR_TEMPLATE_INCONSISTENT` before generation; equal values are
  accepted.

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
