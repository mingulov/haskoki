# Supported-client portfolio

Three independent clients qualify the token from outside its own test
harness: OpenSC for ordinary management, Java SunPKCS11 as a bounded
acceptance client, and GnuTLS as a bounded acceptance client. Each
journey below names its pinned client version, its junction config,
its exact commands, and the pass/fail evidence record the
qualification matrix consumes. AEAD and certificate-linked legs live
in [journey-aead.md](journey-aead.md) and
[journey-certlink.md](journey-certlink.md).

Status: the installed portfolio runner
(`scripts/test-client-journeys.sh` over `tests/journeys/legs.json`)
qualifies the release bundle and the candidate demo image. Both
runs below share one source revision (`f22687f`, clean tree) and
one module (`lib/libhaskoki.so` SHA-256 `22b71f2d…c325e`, start
and end equal in each run). Run P (`v050-prep/portfolio`,
bundle tarball SHA-256 `013a2df0…f5672a`) passes 61 of 61 legs;
run I (`v050-prep/image`, image `sha256:5472a767…`) passes 28
of 28. Per-leg results are in
[client-journeys.json](release-results/client-journeys.json),
which the evidence cells below cite as P (portfolio) and I (image).
The `java-keystore-refuse-mismatched` leg pins jarsigner's
sign-stage refusal of the RSA-cert/EC-key entry (see the KeyStore
journey): the row expects `JOURNEY-NO-VERIFIED-SIGNATURE
stage=sign` plus the `private key algorithm does not match
algorithm of public key` cause line. Prior receipts from
product-review run 38346498528 establish the named artifact only,
never the current tree.

## Pinned versions

Qualification pins these exact versions on Linux amd64, Ubuntu 26.04.
Any drift re-opens the affected legs. Package is the dpkg version;
runtime is the first line of the probe output.

| Client | Package | Package version | Runtime probe | Runtime version | Role |
| --- | --- | --- | --- | --- | --- |
| OpenSC (`pkcs11-tool`) | `opensc` | `0.27.0~rc1-1` | `dpkg-query` | `0.27.0~rc1-1` | ordinary management |
| GnuTLS (`p11tool`) | `gnutls-bin` | `3.8.12-2ubuntu1.1` | `p11tool --version` | `p11tool 3.8.12` | bounded acceptance |
| Java (SunPKCS11 + SunEC) | `default-jdk-headless` | `2:1.25-77` | `java -version` | `25.0.4.1` | bounded acceptance |
| OpenSSL (verifier family) | `openssl` | `3.5.5-1ubuntu3.7` | `openssl version` | `OpenSSL 3.5.5` | independent verification |

Native and runner legs carry null pins by design: they are built
from the checkout under test, so there is no external package to
pin. The Java probe compiles with `javac --release 17` and runs
with explicit `jdk.crypto.cryptoki,jdk.crypto.ec` modules; that is
not evidence from a Java 17 runtime. `p11-kit 0.26.2-2` stays
transport-only outside this portfolio.

Install the pinned clients with:

```sh
apt-get install -y opensc=0.27.0~rc1-1 \
  gnutls-bin=3.8.12-2ubuntu1.1 default-jdk-headless=2:1.25-77
```

## Runner, profiles, and the installed-only contract

The runner installs a fresh bundle (portfolio) or starts from the
candidate image (image profile), substitutes one junction config
per leg store, executes every leg of the profile in table order as
its own process, and records one evidence record, one combined
log, and the substituted config bytes per leg. The aggregate
recomputes every verdict from the records (exit, markers, files,
verifier linkage, pins); a stored claim that disagrees with the
recomputation fails. `client-journeys.json` carries both runs'
aggregates, first-verified-signature measurements, setup seconds,
versions, and artifact hashes.

Profiles:

- `portfolio`: every row. Both phases run in a disposable
  `ubuntu:26.04` client container with the pinned set above.
- `image`: OpenSC rows plus native rows. The module phase runs
  inside the candidate image (`--network none`, installed module
  `/opt/haskoki/current/lib/libhaskoki.so`); the verifier phase
  runs on the host with the pinned openssl.

Installed-only contract: legs run against the installed module
(the bundle prefix or the image path), never against a development
build inside the source checkout — the driver refuses a module
path under the checkout. Records pin the tested module bytes
(SHA-256 start and end, which must match) and the substituted
config bytes, so a verdict always names its bytes.

Time to first verified signature (measured, t0 basis in
parentheses): portfolio `opensc-sign` at 2.29 s
(bundle-extract: seconds since the bundle extraction finished);
image `opensc-sign` at 0.98 s (module-phase-start: seconds since
the module phase started). Client setup seconds (apt install,
measured around it in the container): portfolio 60.0 s, basis
caller; image null, basis not-measured (no client install; the
image ships its tools).

## Junction configs

| File | Purpose | Runner substitution |
| --- | --- | --- |
| `tests/journeys/opensc/haskoki-opensc.toml` | SQLite store for the OpenSC and GnuTLS legs | `@JOURNEY_DIR@` fresh dir |
| `tests/journeys/gnutls/objects.urls` | Token and key URLs for `p11tool` | none (verbatim) |
| `tests/journeys/sunpkcs11/haskoki-sunpkcs11.toml` | Fresh memory store per Java probe run | none |
| `tests/journeys/sunpkcs11/sunpkcs11.cfg` | SunPKCS11 provider shape (session keys) | `@MODULE@` module path |
| `tests/journeys/keystore/haskoki-keystore.toml` | SQLite store for the KeyStore legs | `@JOURNEY_DIR@` fresh dir |
| `tests/journeys/keystore/sunpkcs11-keystore.cfg` | SunPKCS11 provider shape for the KeyStore legs | `@MODULE@` module path |
| `tests/journeys/keystore/sunpkcs11-wrong-slot.cfg` | wrong-slot variant for the token refusal leg | `@MODULE@` module path |
| `tests/journeys/native/haskoki-native.toml` | SQLite store for the native legs | `@JOURNEY_DIR@` fresh dir |
| `tests/journeys/provision/haskoki-provision.toml` | SQLite store for the provisioning legs | `@JOURNEY_DIR@` fresh dir |

All TOML junctions serve the OpenSSL engine with synthetic fallback
refused, a private library context, and tracing off. `$MODULE` below
is the substituted module path; PINs are the public demo fixtures
(user `1234`, SO `5678`). The GnuTLS legs share the OpenSC store
(the same file the OpenSC legs created). The runner records every
substituted config's bytes with its evidence record.

## OpenSC journey

Run order: connect, enumerate, create, export, sign, verify (both
the in-module check and the independent openssl recheck), tamper,
RSA create/encrypt/decrypt, refusal and sequencing legs, then the
store-owned busy case with its after-owner leg. `HASKOKI_CONFIG`
points at the substituted OpenSC junction for every leg; each leg
is its own process.

| Leg | Command | Expect | Evidence |
| --- | --- | --- | --- |
| `opensc-connect` | `pkcs11-tool --module $MODULE --list-slots` | exit 0; `haskoki-demo` listed | pass P+I |
| `opensc-enumerate` | `pkcs11-tool --module $MODULE --login --pin 1234 --list-objects` | exit 0 | pass P+I |
| `opensc-create-ec` | `pkcs11-tool --module $MODULE --login --pin 1234 --keypairgen --key-type EC:prime256v1 --label review-ec --id 0101 --usage-sign` | exit 0; `Key pair generated` with ID `0101` | pass P+I |
| `opensc-export-pubkey` | `pkcs11-tool --module $MODULE --read-object --type pubkey --id 0101 -o out/ec-pub.der` | exit 0; DER pubkey written, nonempty | pass P+I |
| `opensc-sign` | `pkcs11-tool --module $MODULE --login --pin 1234 --sign --mechanism ECDSA-SHA256 --id 0101 --signature-format openssl --input-file message.txt --output-file out/ec-sig.der` | exit 0; signature independently verified | pass P+I |
| `opensc-verify-independent` | `openssl dgst -sha256 -verify` over the exported pubkey, signature, and message | exit 0; `Verified OK` | pass P+I |
| `opensc-tamper-independent` | `openssl dgst -sha256 -verify` over the changed message | nonzero exit; `Verification failure` | pass P+I |
| `opensc-verify` | `pkcs11-tool --module $MODULE --verify --mechanism ECDSA-SHA256 --id 0101 --signature-format openssl --input-file message.txt --signature-file out/ec-sig.der` | exit 0; `Signature is valid` | pass P+I |
| `opensc-tamper` | repeat verify over a changed message | exit 1; `Invalid signature` | pass P+I |
| `opensc-create-rsa` | `pkcs11-tool --module $MODULE --login --pin 1234 --keypairgen --key-type rsa:2048 --label review-rsa --id 0102 --usage-decrypt` | exit 0 | pass P+I |
| `opensc-encrypt` | `pkcs11-tool --module $MODULE --login --pin 1234 --encrypt --mechanism RSA-PKCS-OAEP --hash-algorithm SHA256 --mgf MGF1-SHA256 --id 0102 --input-file message.txt --output-file out/rsa.bin` | exit 0 | pass P+I |
| `opensc-decrypt` | `decrypt-staged ... -- pkcs11-tool --module $MODULE --login --pin 1234 --decrypt ...` over the staged ciphertext | exit 0; `JOURNEY-DECRYPT staged`; decrypted bytes equal the message | pass P+I |
| `opensc-refuse-wrong-pin` | `--login --pin 0000 --list-objects` | exit 1; `CKR_PIN_INCORRECT` | pass P+I |
| `opensc-enumerate-after-refusal` | `--login --pin 1234 --list-objects` after the wrong PIN | exit 0 | pass P+I |
| `opensc-refuse-init-token-store-owned` | `store-owned-refusal ... -- pkcs11-tool --module $MODULE --init-token ...` while a holder process owns the store | exit 0; `JOURNEY-STORE-OWNED-REFUSED`; refusal pins `C_Initialize failed` / `CKR_GENERAL_ERROR`; store bytes unchanged | pass P+I |
| `opensc-connect-after-owner` | `--list-slots` after the holder exits | exit 0 | pass P+I |

The retired single busy leg (`opensc-refuse-init-token-busy`,
which expected `CKR_SESSION_EXISTS` across processes) is replaced
by `opensc-refuse-init-token-store-owned` above plus
`native-init-token-session-exists` below: cross-process ownership
refuses at initialization with `CKR_GENERAL_ERROR`, while the
same-instance busy case answers `CKR_SESSION_EXISTS`.

RSA note: the token deliberately does not offer `CKM_RSA_PKCS` for
`C_Encrypt` or `C_Decrypt` (v1.5 stays sign/verify and wrap/unwrap);
use `CKM_RSA_PKCS_OAEP` for encryption. The RSA legs above use OAEP
with SHA-256 throughout.

Attribute warnings are known and stay explicit: OpenSC may report
`CKR_ATTRIBUTE_TYPE_INVALID` while inspecting `VERIFY_RECOVER`,
`SIGN_RECOVER`, or `ALWAYS_AUTHENTICATE` (also listed in
[try-it.md](try-it.md#when-something-fails)). `LOCAL`,
`EXTRACTABLE`, `NEVER_EXTRACTABLE` and `DERIVE` now read. Key
creation and signature checks must still succeed; the warnings
never become a silent skip.

## Provisioning journey

Token provisioning through the installed OpenSC client on a fresh
store: initialize the token, initialize the user PIN, change it,
create an EC key, export and sign, verify independently, enumerate
under the new PIN, and the old PIN refuses. Each leg is its
own process against the provision store.

| Leg | Command | Expect | Evidence |
| --- | --- | --- | --- |
| `opensc-provision-init-token` | `pkcs11-tool --module $MODULE --init-token --label haskoki-demo --so-pin 5678` | exit 0; token initialized | pass P+I |
| `opensc-provision-init-pin` | `pkcs11-tool --module $MODULE --login --login-type so --so-pin 5678 --init-pin --pin pin-bravo-02` | exit 0; PIN initialized | pass P+I |
| `opensc-provision-change-pin` | `pkcs11-tool --module $MODULE --login --pin pin-bravo-02 --change-pin --new-pin pin-charlie-03` | exit 0; `PIN successfully changed` | pass P+I |
| `opensc-provision-create-ec` | `pkcs11-tool --module $MODULE --login --pin pin-charlie-03 --keypairgen --key-type EC:prime256v1 --label prov-ec --id 0909 --usage-sign` | exit 0; pair generated | pass P+I |
| `opensc-provision-export-pubkey` | `pkcs11-tool --module $MODULE --read-object --type pubkey --id 0909` | exit 0; DER pubkey written, nonempty | pass P+I |
| `opensc-provision-sign` | `pkcs11-tool --module $MODULE --login --pin pin-charlie-03 --sign --mechanism ECDSA-SHA256 --id 0909` | exit 0; signature written; independently verified | pass P+I |
| `opensc-provision-verify-independent` | `openssl dgst -sha256 -verify` over the exported pubkey, signature, and provision message | exit 0; `Verified OK` | pass P+I |
| `opensc-provision-enumerate-new-pin` | `pkcs11-tool --module $MODULE --login --pin pin-charlie-03 --list-objects` | exit 0; `prov-ec` listed | pass P+I |
| `opensc-provision-refuse-old-pin` | `pkcs11-tool --module $MODULE --login --pin pin-bravo-02 --list-objects` | nonzero exit; `CKR_PIN_INCORRECT` surfaces | pass P+I |

## Native legs

Native consumers compiled from the checkout run against the
installed module with the native junction. Their evidence scope is
native-consumer (direct C-surface receipts), not independent
clients.

| Leg | Command | Expect | Evidence |
| --- | --- | --- | --- |
| `native-init-token-session-exists` | `token_fixture $MODULE init-busy` | exit 0; same-instance `C_InitToken` answers `CKR_SESSION_EXISTS`, label and object count unchanged | pass P+I |
| `native-aead` | `consumer_aead $MODULE` | exit 0; `PASS: consumer_aead` (see [journey-aead.md](journey-aead.md)) | pass P+I |
| `native-certlink-metadata` | `consumer_certlink $MODULE` | exit 0; `PASS: consumer_certlink` (see [journey-certlink.md](journey-certlink.md)) | pass P+I |

## Java SunPKCS11 journey

`HASKOKI_CONFIG` points at the substituted SunPKCS11 junction (fresh
memory store). The probe is `tests/journeys/java/JavaTokenProbe.java`
(pinned SHA-256 `c1c77e84…43eb6`, compiled in-leg with
`javac --release 17`); the KeyStore legs use the keystore junction
(SQLite store) with the keystore provider config.

| Leg | Command shape | Expect | Evidence |
| --- | --- | --- | --- |
| `java-probe-compile` | `javac --release 17` of the probe | exit 0; classes written | pass P |
| `java-connect-sign` | the probe against the substituted junction | exit 0; `JAVA-PROBE SETUP_OK`, `LOGIN_OK`, `KEYGEN_OK`, `SIGN_OK`, `VERIFY_OK`, `TAMPER_REJECTED`, `LOGOUT_OK`, `PASS` | pass P |
| `java-refuse-wrong-pin` | same with the wrong PIN | exit 1; `JAVA-PROBE OPERATION_FAIL stage=login`; `CKR_PIN_INCORRECT` in the message | pass P |
| `java-keystore-list` | `keytool -list` over SunPKCS11 | exit 0; `app-key, PrivateKeyEntry` listed | pass P |
| `java-keystore-refuse-pin` | `keytool -list -v` with PIN `0000` | exit 1; `CKR_PIN_INCORRECT` through the cause chain | pass P |
| `java-keystore-refuse-token` | `keytool -list -v` against a missing slot | exit 1; `CKR_SLOT_ID_INVALID` through the cause chain | pass P |
| `java-keystore-sign` | `jarsigner` signs `app.jar` with `app-key` (`SHA256withECDSA`) | exit 0; `jar signed.`; independently verified | pass P |
| `java-keystore-verify` | `jarsigner -verify -verbose -certs` over the signed jar | exit 0; `jar verified.`; `jar is unsigned.` absent | pass P |
| `java-keystore-verify-independent` | openssl CMS verification over the extracted signature block against the journey CA | exit 0; `CMS Verification successful` | pass P |
| `java-keystore-tamper` | tamper the payload, re-verify | `JOURNEY-TAMPER-DETECTED` with `digest error`; `jar verified.` absent | pass P |
| `java-keystore-refuse-alias` | `jarsigner` with `no-such-alias` | exit 1; `Certificate chain not found for: no-such-alias`; output jar absent | pass P |
| `java-keystore-refuse-mismatched` | sign with the RSA-cert/EC-key entry, expect no verified signature | `JOURNEY-NO-VERIFIED-SIGNATURE stage=sign` plus jarsigner's `private key algorithm does not match algorithm of public key` cause line (`logs/java-keystore-refuse-mismatched.log:1`); the verify stage is unreachable with this fixture (see [journey-certlink.md](journey-certlink.md)) | pass P |
| `java-keystore-generate` | `keytool -genkeypair` on the token (`EC`, `secp256r1`) | exit 0; key pair and self-signed certificate generated | pass P |
| `java-keystore-sign-generated` | `jarsigner` signs with the generated entry | exit 0; `jar signed.` | pass P |

Probe exit classes are contractual: 0 needs genuine verification,
changed-message refusal, and logout; 1 is an operation failure after
setup; 2 is a setup failure; 3 is logout failing after passing
checks. No failure class may read as a passing skip. The
certificate-matched setup legs (`keystore-create-key`,
`keystore-export-pubkey`, `keystore-issue-cert`,
`keystore-write-cert`, `keystore-read-cert`, `keystore-spki-match`,
`keystore-make-jar`, and the `keystore-mismatch-*` control legs)
all pass in P; see [journey-certlink.md](journey-certlink.md).

## GnuTLS journey

Every leg sets `GNUTLS_PIN=1234` and points `HASKOKI_CONFIG` at the
substituted GnuTLS junction — the same store the OpenSC legs used.
Run order is contractual: `opensc-create-ec` first, then discovery
and use here, each leg its own process, never two at once.

| Leg | Command | Expect | Evidence |
| --- | --- | --- | --- |
| `gnutls-discovery` | `p11tool --provider $MODULE --batch --list-tokens` | exit 0; `token=haskoki-demo` listed | pass P |
| `gnutls-list-key` | `p11tool --provider $MODULE --batch --login --list-all "pkcs11:token=haskoki-demo"` | exit 0; `review-ec` public and private keys listed | pass P |
| `gnutls-test-sign` | `p11tool --provider $MODULE --batch --login --test-sign --hash SHA256 "pkcs11:token=haskoki-demo;object=review-ec;type=private"` | exit 0; sign plus both verifications `ok` | pass P |
| `gnutls-test-sign-by-id` | same with `id=%01%01` selection instead of the label | exit 0; sign plus both verifications `ok` | pass P |
| `gnutls-refuse-wrong-pin` | `GNUTLS_PIN=0000 ... --login --list-all "pkcs11:token=haskoki-demo"` | exit 1; `*** Wrong PIN has been provided!` | pass P |
| `gnutls-list-after-refusal` | `--login --list-all` after the wrong PIN | exit 0 | pass P |
| `gnutls-refuse-unknown-url` | `... --test-sign --hash SHA256 "pkcs11:token=haskoki-demo;object=no-such-key;type=private"` | exit 1; `Cannot import private key: ...`; `Signing using` absent | pass P |
| `gnutls-refuse-wrong-token` | `... --list-all "pkcs11:token=no-such-token"` | exit 2; `No matching objects found` | pass P |

URI quoting is contractual: an unquoted `;` splits the shell command,
drops the object/type selection, and masks the tool's exit status.
No marker contains a token serial: the `p11tool` output carries a
16-character token id, and every GnuTLS marker pins the token name
or key label instead.

## Explicit refusals

Refusals are first-class legs with expected codes, never silent
passes. Client-facing refusal pins beyond the per-client legs above:

- Token stubs answer `CKR_FUNCTION_NOT_SUPPORTED`
  (`C_GetOperationState`, `C_SetOperationState`, `C_GetObjectSize`)
  and `CKR_FUNCTION_NOT_PARALLEL` (the legacy
  `C_GetFunctionStatus`/`C_CancelFunction` pair) on a live
  interval; pre-init they answer `CKR_CRYPTOKI_NOT_INITIALIZED`
  (`cbits/function_tables.c` stub table).
- Untyped attribute reads answer `CKR_ATTRIBUTE_TYPE_INVALID` with
  an unavailable length and the caller buffer untouched
  ([certificate-objects.md](certificate-objects.md)).
- Wrong credentials count down per-role retries to `CKR_PIN_LOCKED`;
  a second concurrent SQLite owner refuses `C_Initialize`
  ([walkthrough](demo-walkthrough.md#token-provisioning-and-state)).
  `C_Finalize` closes every open session, cancels the PKCS#11
  surface's attached jobs, retires still-live joined attachments as
  canceled (best effort; already-terminal ones keep their fate),
  keeps detached idle records, and never stops the RTS.
  Caller-owned native async contexts are unaffected.
- Out-of-range inputs refuse at the planner floor (for example the
  AES-GCM generated-IV shape and off-list tag widths in
  [journey-aead.md](journey-aead.md)); tampered sealed bytes and
  wrong identities refuse with `CKR_ENCRYPTED_DATA_INVALID` and
  `CKR_SIGNATURE_INVALID`.

## Unsupported clients

Anything outside the three pinned clients is untested, including
browser and mail token stores, desktop signers, SSH helpers, other
language bindings, and any newer client version. Untested use is
not forbidden; it is unclaimed: the tool reports its own errors,
and the token answers every entry with either service or an
explicit `CKR` from the families above. No untested path may be
documented as passing, and no refusal may pass silently — a leg
that cannot run records `status: fail` with its stage, never a
passing skip.

## Concurrent access

Distinct sessions may proceed within one initialized provider under
the supported locking modes (OS locking by default; the host
contract's application-mutex mode where the caller supplies the
mutex callbacks). Native work serializes; the token does not promise
parallel throughput. Only one process may own a SQLite store at a
time. Independent processes must never share one store file
directly; cross-process reach uses only the documented remoting
examples within their stated scope (loopback proxy example, local
p11-kit example).

## Evidence record format

Each CLI leg emits one JSON record following the product-review
`results.json` shape, extended with journey pins, so the
qualification matrix consumes it directly. The machine schema is
[evidence-record-schema.json](../tests/journeys/evidence-record-schema.json).
Native legs instead report the consumer scenario name, exit code,
and `PASS:` trailer from `scripts/test-consumers.sh`.

```json
{
  "name": "opensc-create-ec",
  "command": ["pkcs11-tool", "--module", "/abs/libhaskoki.so",
    "--login", "--pin", "1234", "--keypairgen",
    "--key-type", "EC:prime256v1", "--label", "review-ec",
    "--id", "0101", "--usage-sign"],
  "timeout_seconds": 120,
  "classification": "independent-client",
  "env_overrides": {"HASKOKI_CONFIG": "/abs/run/cfg/opensc-create-ec.toml"},
  "log": "logs/opensc-create-ec.log",
  "exit_code": 0,
  "status": "pass",
  "elapsed_seconds": 0.17,
  "journey": "portfolio",
  "client": {"name": "opensc", "package": "opensc",
    "package_version": "0.27.0~rc1-1",
    "runtime_version": "0.27.0~rc1-1", "compile_target": null},
  "module": {"path": "/abs/libhaskoki.so",
    "sha256": "<runner records the tested bytes>"},
  "config": {"file": "cfg/opensc-create-ec.toml",
    "sha256": "<runner records the substituted bytes>"},
  "expect": {"status": "pass", "exit": 0,
    "markers": ["Key pair generated", "ID:         0101"]},
  "source": {"sha": "<runner records the source revision>",
    "dirty": false},
  "artifact": {"kind": "bundle", "haskoki_version": "0.5.0.0",
    "bundle_sha256": "<runner records the tarball>",
    "image_id": null,
    "toolchain_record_sha256": "<runner records the record>"},
  "phase": "module",
  "failure_stage": null,
  "verifies": null,
  "unchanged": null,
  "started_utc_ns": "<runner records leg start>",
  "ended_utc_ns": "<runner records leg end>"
}
```

Refusal legs use the same shape with `"status": "pass"` only when
the refusal lands as specified, plus an `expect_refusal` object
carrying the expected `CKR` name and output markers; for example
`opensc-refuse-wrong-pin` expects a nonzero exit with an incorrect
PIN surfacing. The runner uploads every record, log, substituted
config, and module digest even when the leg fails.
