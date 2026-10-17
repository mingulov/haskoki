# Haskoki 0.5.0.0 — first public release

Haskoki 0.5.0.0 is the first publicly announced release. Earlier tags
through 0.4.0.0 exist but were never announced; this is the first
version the project stands behind publicly. Haskoki remains a Haskell
PKCS#11 software token for learning and integration tests; use disposable
keys, not production secrets.

## Start here

```sh
docker run --rm --network none ghcr.io/mingulov/haskoki-demo:v0.5.0.0
```

Expect `demo-ok: 8/8 verifications hold`. No checkout, local build, or
hardware is required. Files are disposable unless you mount `/out`.
The [hands-on guide](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/try-it.md)
shows how to keep them, generate a key with `pkcs11-tool`, and sign a message.

## Improvements

- Attribute-sensitivity model. New private and secret keys default to
  unextractable. Reads of a sensitive or unextractable value fail with
  `CKR_ATTRIBUTE_SENSITIVE`, and `C_FindObjects` withholds sealed
  components instead of matching them. Matching runs over effective
  values, so a key stored without `CKA_EXTRACTABLE` counts as
  unextractable and matches `CKA_EXTRACTABLE=false`. Creation history
  (`CKA_LOCAL`, `CKA_KEY_GEN_MECHANISM`, `CKA_ALWAYS_SENSITIVE`,
  `CKA_NEVER_EXTRACTABLE`) is stamped by the token and refused in
  caller templates. Public keys always read, whatever flags the
  template stored. The
  [changelog](https://github.com/mingulov/haskoki/blob/v0.5.0.0/CHANGELOG.md)
  lists every behavior change in the 0.5.0.0 section.
- Storage schema 3 with a migrate-once upgrade path. SQLite stores move
  to schema 3. Stores written by 0.4.0.0 (schema 2) or 0.3.x (schema 1)
  are refused at open, with nothing written, until
  `haskoki-ctl store migrate --path FILE --config FILE --backup-dir DIR`
  migrates them once: it takes ownership, writes a verified backup and
  a receipt, and moves the schema in one transaction. An ordinary open
  never migrates. `haskoki-ctl store check --path FILE --config FILE`
  reports, without writing, whether a store opens and what migration
  or catalog fix it needs. Binaries at 0.4.0.0 and 0.3.1.0 refuse a
  migrated store; restore the backup to go back. Each new token's
  credential row is now written in the same transaction as the token,
  so the stored row is the PIN authority. See
  [Upgrading a v0.4 token store](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/demo-walkthrough.md#upgrading-a-v04-token-store)
  and the
  [operations notes](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/operations-notes.md#upgrade-backup-and-recovery).
- Installed client portfolio. An installed-bundle run passes 61 of 61
  journey legs with pinned OpenSC, GnuTLS, JDK and openssl clients in
  a disposable `ubuntu:26.04` container, and the candidate-image run
  passes 28 of 28 (module phase in-image, verifier phase on the host).
  Evidence level qualified-candidate: both runs executed against
  release-candidate bytes, recorded per leg in
  [client-journeys.json](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/release-results/client-journeys.json);
  the
  [portfolio guide](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/client-portfolio.md)
  names every leg, pin and refusal. Full candidate qualification and
  publication verification follow the release workflow; the image
  profile is re-run against the pulled digest before announcement.

## Correctness repairs in this release

- In 0.4.0.0, `CKA_SEED` of sensitive or unextractable ML-DSA, ML-KEM
  and SLH-DSA private keys read back in clear through
  `C_GetAttributeValue` and matched in `C_FindObjects`. 0.5.0.0 seals
  it: reads fail with `CKR_ATTRIBUTE_SENSITIVE` and find no longer
  matches such keys by seed. There is no 0.4.0.0 advisory and no
  0.4.0.x patch release; upgrading to 0.5.0.0 is the fix.
- `C_FindObjects` with a `CKA_VALUE` template matches DSA and DH public
  keys (including X9.42) by the value `C_GetAttributeValue` returns
  (the public `y`), instead of the stored SPKI bytes. A search with a
  read-back value used to miss; a search with the raw stored bytes no
  longer hits. EC public keys derived via `CKM_PUB_KEY_FROM_PRIV_KEY`
  match by read-back `CKA_EC_PARAMS` the same way. Stored bytes are
  unchanged, and `C_CopyObject` repeating a read-back `y` is accepted
  as a no-op.
- A generated EC private key carries `CKA_EC_PARAMS`, copied from the
  public half when the private template omits it. Clients that read
  the curve from the private key, such as Java jarsigner through
  SunPKCS11, no longer fail with `CKR_ATTRIBUTE_TYPE_INVALID`.
- Copy and set policy are unified. Copies can no longer replace key
  material, forge protection labels, drop `CKA_ALWAYS_AUTHENTICATE`,
  widen `CKA_ALLOWED_MECHANISMS`, or change anything on a
  `CKA_MODIFIABLE=false` source beyond the copy exemptions. Naming the
  value or a private component of a sealed key in a copy template fails
  whatever the value, even when it matches the source; in 0.4.0.0 the
  copy succeeded, so a caller could confirm a guessed key value one
  guess at a time. Copy a sealed key by omitting its sealed components
  from the template.
- Storage objects report the common storage attributes they were
  created without: `C_GetAttributeValue` used to answer
  `CKR_ATTRIBUTE_TYPE_INVALID` for an omitted `CKA_TOKEN`,
  `CKA_PRIVATE`, `CKA_MODIFIABLE`, `CKA_COPYABLE`, `CKA_DESTROYABLE`
  or `CKA_LABEL`, and now returns the enforced value; `C_FindObjects`
  matches the same values.
- HOTP takes the standard `CK_OTP_PARAMS` (an array of `CK_OTP_PARAM`
  entries) with a required 8-byte big-endian `CK_OTP_COUNTER` entry and
  an optional output length, and has no message API. The old 16-byte
  `counter || digits` image is refused with
  `CKR_MECHANISM_PARAM_INVALID`. `CKM_AES_GMAC` no longer advertises
  `CKF_MESSAGE_SIGN` or `CKF_MESSAGE_VERIFY`, and the message-API
  inits refuse mechanisms without a message route of that kind.
- Mechanism parameter errors are unified: a missing, short or malformed
  parameter returns `CKR_MECHANISM_PARAM_INVALID` (0x71) across the
  digest, cipher, RSA, MAC, signature and AEAD families that used to
  return `CKR_ARGUMENTS_BAD`, and an unknown, destroyed or invisible
  key handle at a keyed init or `C_DigestKey` returns
  `CKR_KEY_HANDLE_INVALID` (0x60) instead of
  `CKR_OBJECT_HANDLE_INVALID`.
- `CKM_XOR_BASE_AND_DATA` accepts a base key and data of different
  lengths, per PKCS#11 v3.1 section 6.43.6; a template length past the
  shorter width fails with `CKR_KEY_SIZE_RANGE`.
- A hang in hosts that load the provider with at least 2 RTS
  capabilities is fixed: capability tables are fully evaluated before
  publication (GHC #27272). When the provider starts the RTS itself
  it runs one RTS capability and ignores `GHCRTS`; a process
  already running a GHC RTS keeps its own capability count. See
  limitations.
- Closing a session (or the instance, or rolling back a failed open)
  no longer frees the session's borrowed async view while a native
  async call admitted on that view may still dereference it. The
  view is retired first and its pointer freed only after
  outstanding borrows drain.
- Concurrent first calls through the native API (`haskoki_async_*`,
  `haskoki_crypto_*`) no longer risk killing the host process.
  Threads that lose the RTS-start race wait for the start to
  complete instead of entering Haskell before `hs_init` finishes,
  and a `C_Initialize` racing a first native call no longer fails
  with a spurious `CKR_GENERAL_ERROR`. Fork children still fail
  safe without waiting.
- Store lock and guard file descriptors open with `O_CLOEXEC`
  atomically, so a child process started mid-open can no longer inherit
  them and hold the store locked after close.
- The shipped `libhaskoki.so` no longer exports the 27 test-only native
  symbols, and the test registry that could absorb a repeat free is no
  longer compiled into the shipped module.

## Client-visible behavior changes

Keys and attributes:

- New private and secret keys default to unextractable: generate,
  key-pair, create and KEM paths stamp `CKA_EXTRACTABLE=false` when
  the template omits it. Set `CKA_EXTRACTABLE=true` and
  `CKA_SENSITIVE=false` explicitly in the template to keep a new key
  readable.
- Caller templates may not carry creation-history attributes on any
  path; `C_CopyObject` refuses them unconditionally, even for matching
  values. Public keys report no `CKA_ALWAYS_SENSITIVE` and no
  `CKA_NEVER_EXTRACTABLE`.
- Copy refusals that reported `CKR_TEMPLATE_INCONSISTENT` in 0.4.0.0
  now report the set path's `CKR_ATTRIBUTE_READ_ONLY`. `C_CopyObject`
  with `CKA_MODIFIABLE=true` over a `CKA_MODIFIABLE=false` source
  fails; the copy may only tighten or keep the value.
- Byte-operation derives read the base key's effective
  `CKA_EXTRACTABLE`: deriving a readable child from a flagless base
  needs an explicitly extractable base.

Token serials and identity:

- `C_GetTokenInfo` reports the token's `TokenId` as 16 lowercase hex
  digits, independent of slot and label. Values change for a 10th or
  later token, for pinned non-positional `token_ids`, and after a slot
  move: update any saved `pkcs11:` URI that selects those tokens by
  `serial=`. Serials are unique within one store only.

Mechanisms and errors:

- See the HOTP, AES-GMAC, message-init, error-code and XOR rows under
  repairs above; each changes an observable return or parameter shape.
- Stores written with the new key attributes are refused by older
  binaries: unknown attribute names fail decode, so upgrade is one-way.

The
[changelog](https://github.com/mingulov/haskoki/blob/v0.5.0.0/CHANGELOG.md)
carries the complete behavior list; the paragraphs above are a summary.

## Known limitations

This is a bounded release. These items are not claimed.

- **Key value encoding.** `CKA_VALUE` reads return SPKI DER for
  RSA/EC/EdDSA/XDH/PQC public keys and PKCS#8 DER for private keys,
  where PKCS#11 defines raw values. DSA and DH public keys are the
  exception: they read the public `y`.
- **RSA v1.5 encryption.** `CKM_RSA_PKCS` encrypt and decrypt are
  deliberately not offered; sign/verify and wrap/unwrap are. Use
  `CKM_RSA_PKCS_OAEP` for encryption, as the
  [RSA note](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/client-portfolio.md#opensc-journey)
  in the portfolio guide states.
- **Single RTS capability.** When the provider starts the RTS itself,
  it runs one RTS capability and ignores `GHCRTS` (GHC #27272); a
  process already running a GHC RTS keeps its own capability count.
  Hosts must not assume parallel throughput from a provider-started
  RTS; native work serializes.
- **API gaps.** Of the 104 entries in the 3.2 table layout, 81 are
  planned with behavior, 21 are unsupported with a stated reason, and 2
  are not applicable (the legacy parallel pair), per
  [spec/function-contracts.json](https://github.com/mingulov/haskoki/blob/v0.5.0.0/spec/function-contracts.json)
  and the
  [stub inventory](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/b3-docs-inventory.md#3-c-table-stub-inventory-11--2).
- **Mechanism gaps.** 316 of 464 catalog rows are behavior-tested and
  served through C; 89 are unsupported with reasons and 57 are planned,
  per the
  [coverage inventory](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/coverage.md).
  A listed mechanism does not mean every parameter shape has been
  exercised through C.
- **Supported refusals.** Unserved calls refuse with explicit codes,
  never silent passes; see
  [Explicit refusals](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/client-portfolio.md#explicit-refusals).
- **Storage.** Token storage is unencrypted. Use disposable keys.
- **No conformance claim.** Passing journeys, drivers and checker
  profiles do not establish PKCS#11 conformance or certification.

## Contents and limits

The Linux amd64 image carries the tool set recorded in the
[dependency inventory](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/dependency-inventory.md).
Other architectures and Docker Desktop paths are unqualified. The C
library version reported by `C_GetInfo` is now {0, 5}.

The full checker profile reports 18 documented findings with 61 frozen
exclusions on the candidate image; the short smoke profile expects zero.
See
[results](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/release-results.md)
and [host limits](https://github.com/mingulov/haskoki/blob/v0.5.0.0/SUPPORTED-HOSTS.md).
The p11-kit example covers basic operations, not a full PKCS#11 3.x remoting
matrix.

## Downloads

Release assets include the native Linux bundle, source archive, test logs,
`release-manifest.json`, and `SHA256SUMS`. The manifest records the exact
source and image digest. `SHA256SUMS.asc` is included **only if** the owner
configures release signing; do not assume it exists. After downloading the
archives and manifest alongside the checksums, run `sha256sum -c SHA256SUMS`.

The [publishing guide](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/publishing.md)
explains the GitHub-only build and publication workflow. A source branch
preparing this version does not mean its release or image has been published.
The latest published release at the time of writing is v0.4.0.0.
