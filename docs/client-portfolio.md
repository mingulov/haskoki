# Supported-client portfolio

Three independent clients qualify the token from outside its own test
harness: OpenSC for ordinary management, Java SunPKCS11 as a bounded
acceptance client, and GnuTLS as a bounded acceptance client. Each
journey below names its pinned client version, its junction config,
its exact commands, and the pass/fail evidence record the
qualification matrix consumes. AEAD and certificate-linked legs live
in [journey-aead.md](journey-aead.md) and
[journey-certlink.md](journey-certlink.md).

Status: this lane defines the journeys, ships the junction configs,
and fixes the evidence format. Native journey consumers are
syntax-checked here; execution receipts are outstanding and belong
to the execution lane. Legs already observed carry their receipt;
legs never run are marked TO-QUALIFY. Prior receipts come from
product-review run 38346498528 (source tree) and its published-image
job (image `0.3.1.0`, revision `a89fb09`); they establish the named
artifact only, never the current tree.

## Pinned versions

Qualification pins these exact versions on Linux amd64, Ubuntu 26.04.
Any drift re-opens the affected legs.

| Client | Package | Version | Role |
| --- | --- | --- | --- |
| OpenSC (`pkcs11-tool`) | `opensc` | `0.27.0~rc1-1` | ordinary management |
| GnuTLS (`p11tool`) | `gnutls-bin` | `3.8.12-2ubuntu1.1` (`p11tool 3.8.12`) | bounded acceptance |
| Java (SunPKCS11 + SunEC) | `default-jdk-headless` | `2:1.25-77` (OpenJDK `25.0.4.1`) | bounded acceptance |

Provenance: `versions.log` of run 38346498528 records all three;
[dependency-inventory.md](dependency-inventory.md) pins the same
OpenSC in the demo image. The Java probe compiles with
`javac --release 17` and runs with explicit
`jdk.crypto.cryptoki,jdk.crypto.ec` modules; that is not evidence
from a Java 17 runtime. `p11-kit 0.26.2-2` stays transport-only
outside this portfolio.

Install the pinned clients with:

```sh
apt-get install -y opensc=0.27.0~rc1-1 \
  gnutls-bin=3.8.12-2ubuntu1.1 default-jdk-headless=2:1.25-77
```

## Junction configs

| File | Purpose | Runner substitution |
| --- | --- | --- |
| `tests/journeys/opensc/haskoki-opensc.toml` | SQLite store for the OpenSC legs | `@JOURNEY_DIR@` fresh dir |
| `tests/journeys/gnutls/haskoki-gnutls.toml` | Same SQLite store for the GnuTLS legs | `@JOURNEY_DIR@`, same dir as OpenSC |
| `tests/journeys/gnutls/objects.urls` | Token and key URLs for `p11tool` | none (verbatim) |
| `tests/journeys/sunpkcs11/haskoki-sunpkcs11.toml` | Fresh memory store per Java run | none |
| `tests/journeys/sunpkcs11/sunpkcs11.cfg` | SunPKCS11 provider shape | `@MODULE@` module path |
| `tests/journeys/keystore/haskoki-keystore.toml` | SQLite store for the KeyStore app leg | `@JOURNEY_DIR@` fresh dir |

All TOML junctions serve the OpenSSL engine with synthetic fallback
refused, a private library context, and tracing off. `$MODULE` below
is the substituted module path; PINs are the public demo fixtures
(user `1234`, SO `5678`). The runner records every substituted
config's bytes with its evidence record.

## OpenSC journey

Run order: connect, enumerate, create, sign, verify, tamper, decrypt,
then the refusal legs. `HASKOKI_CONFIG` points at the substituted
OpenSC junction for every leg; each leg is its own process.

| Leg | Command | Expect | Evidence |
| --- | --- | --- | --- |
| `opensc-connect` | `pkcs11-tool --module $MODULE --list-slots` | exit 0; slot 0 `haskoki-demo` present | TO-QUALIFY (prior-artifact: published hands-on passed) |
| `opensc-enumerate` | `pkcs11-tool --module $MODULE --login --pin 1234 --list-objects` | exit 0 | TO-QUALIFY (adjacent: `opensc-configured-pin-one` passed on a catalog config) |
| `opensc-create-ec` | `pkcs11-tool --module $MODULE --login --pin 1234 --keypairgen --key-type EC:prime256v1 --label review-ec --id 0101 --usage-sign` | exit 0; pair generated with ID `0101` | QUALIFIED (`opensc-create-ec.log`); attribute warnings stay documented, see below |
| `opensc-sign` | `pkcs11-tool --module $MODULE --login --pin 1234 --sign --mechanism ECDSA-SHA256 --label review-ec --type privkey --input-file message.txt --output-file signature.bin` | exit 0; signature bytes written | TO-QUALIFY (prior-artifact: published hands-on passed) |
| `opensc-verify` | `... --verify --mechanism ECDSA-SHA256 --label review-ec --type pubkey --input-file message.txt --signature-file signature.bin` | exit 0; `Signature is valid` | TO-QUALIFY (prior-artifact: published hands-on passed) |
| `opensc-tamper` | repeat verify over a changed message | nonzero exit; verification fails | TO-QUALIFY (prior-artifact: published hands-on passed) |
| `opensc-decrypt` | RSA `2048` `--keypairgen --usage-decrypt`, then `--encrypt/--decrypt --mechanism RSA-PKCS-OAEP --hash-algorithm SHA256 --mgf MGF1-SHA256` round trip | exit 0; decrypted bytes match | TO-QUALIFY (grounded: RSA-2048 pairgen plus `CKM_RSA_PKCS_OAEP` real-tested rows) |
| `opensc-refuse-wrong-pin` | `--login --pin 0000 --list-objects` | nonzero exit; incorrect PIN surfaces | TO-QUALIFY |
| `opensc-refuse-init-token-busy` | `--init-token` while sessions are open | nonzero exit; `CKR_SESSION_EXISTS` surfaces | TO-QUALIFY (contract: [walkthrough](demo-walkthrough.md#token-provisioning-and-state)) |

RSA note: the token does not offer `CKM_RSA_PKCS` for
`C_Encrypt`/`C_Decrypt` (OAEP is; v1.5 stays sign/wrap); the RSA legs
above use `CKM_RSA_PKCS_OAEP` with SHA-256 throughout.

Attribute warnings are known and stay explicit: OpenSC may report
`CKR_ATTRIBUTE_TYPE_INVALID` while inspecting `DERIVE`,
`VERIFY_RECOVER`, `SIGN_RECOVER`, or `ALWAYS_AUTHENTICATE` (also
listed in [try-it.md](try-it.md#when-something-fails)). `LOCAL`,
`EXTRACTABLE` and `NEVER_EXTRACTABLE` now read. Key creation and
signature checks must still succeed; the warnings never become a
silent skip.

## Java SunPKCS11 journey

`HASKOKI_CONFIG` points at the substituted SunPKCS11 junction (fresh
memory store); `HSK_REVIEW_USER_PIN` defaults to `1234` when unset.
The probe is `tests/review/JavaTokenProbe.java` on the preserved
diagnostic branch `review/product-checks-20261013` at
`a96a753c9e80353eed29eacca9bb9bafc0cfecb5` (file SHA-256
`c1c77e8459f1c45de3fae2dcf8279848f206a60fc8379e50480d57d7ec243eb6`).
Fetch it with:

```sh
git show a96a753c9e80353eed29eacca9bb9bafc0cfecb5:tests/review/JavaTokenProbe.java \
  > /tmp/java-probe/JavaTokenProbe.java
javac --release 17 -d /tmp/java-probe /tmp/java-probe/JavaTokenProbe.java
java --add-modules jdk.crypto.cryptoki,jdk.crypto.ec \
  -cp /tmp/java-probe JavaTokenProbe /tmp/java-probe/sunpkcs11.cfg
```

| Leg | Command shape | Expect | Evidence |
| --- | --- | --- | --- |
| `java-connect-sign` | the probe above against the substituted junction | exit 0; `SETUP_OK`, `LOGIN_OK`, `KEYGEN_OK`, `SIGN_OK`, SunEC `VERIFY_OK`, `TAMPER_REJECTED`, `LOGOUT_OK`, `PASS` | QUALIFIED (`java-independent-ec.log`) |
| `java-refuse-wrong-pin` | same with `HSK_REVIEW_USER_PIN=0000` | exit 1; `OPERATION_FAIL stage=login` | TO-QUALIFY |
| `java-keystore-app` | KeyStore plus application signing | see [journey-certlink.md](journey-certlink.md) | TO-QUALIFY |

Probe exit classes are contractual: 0 needs genuine verification,
changed-message refusal, and logout; 1 is an operation failure after
setup; 2 is a setup failure; 3 is logout failing after passing
checks. No failure class may read as a passing skip.

## GnuTLS journey

Every leg sets `GNUTLS_PIN=1234` and points `HASKOKI_CONFIG` at the
substituted GnuTLS junction — the same store the OpenSC legs used.
Run order is contractual: `opensc-create-ec` first, then discovery
and use here, each leg its own process, never two at once.

| Leg | Command | Expect | Evidence |
| --- | --- | --- | --- |
| `gnutls-discovery` | `p11tool --provider $MODULE --batch --list-tokens` | exit 0; `haskoki-demo` token listed | QUALIFIED (`gnutls-discovery.log`) |
| `gnutls-list-key` | `p11tool --provider $MODULE --batch --login --list-all "pkcs11:token=haskoki-demo"` | exit 0; `review-ec` public and private keys listed | QUALIFIED (`gnutls-list-key.log`) |
| `gnutls-test-sign` | `p11tool --provider $MODULE --batch --login --test-sign --hash SHA256 "pkcs11:token=haskoki-demo;object=review-ec;type=private"` | exit 0; sign plus both verifications `ok` | QUALIFIED (`gnutls-test-sign.log`) |
| `gnutls-refuse-wrong-pin` | `GNUTLS_PIN=0000 ... --login --list-all "pkcs11:token=haskoki-demo"` | nonzero exit; login fails | TO-QUALIFY |
| `gnutls-refuse-unknown-url` | `... --test-sign --hash SHA256 "pkcs11:token=haskoki-demo;object=no-such-key;type=private"` | nonzero exit; no signature produced | TO-QUALIFY |

URI quoting is contractual: an unquoted `;` splits the shell command,
drops the object/type selection, and masks the tool's exit status.

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
  a second concurrent SQLite owner refuses `C_Initialize`;
  finalize needs zero open sessions
  ([walkthrough](demo-walkthrough.md#token-provisioning-and-state)).
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
  "timeout_seconds": 240,
  "classification": "independent-client",
  "env_overrides": {"HASKOKI_CONFIG": "/abs/run/haskoki-opensc.toml"},
  "log": "opensc-create-ec.log",
  "exit_code": 0,
  "status": "pass",
  "elapsed_seconds": 1.7,
  "journey": "docs/client-portfolio.md#opensc-journey",
  "client": {"name": "opensc", "package": "opensc",
    "package_version": "0.27.0~rc1-1",
    "runtime_version": "0.27.0~rc1-1", "compile_target": null},
  "module": {"path": "/abs/libhaskoki.so",
    "sha256": "<runner records the tested bytes>"},
  "config": {"file": "/abs/run/haskoki-opensc.toml",
    "sha256": "<runner records the substituted bytes>"},
  "expect": {"status": "pass", "exit": 0,
    "markers": ["Key pair generated:", "ID:         0101"]}
}
```

Refusal legs use the same shape with `"status": "pass"` only when
the refusal lands as specified, plus an `expect_refusal` object
carrying the expected `CKR` name and output markers; for example
`opensc-refuse-wrong-pin` expects a nonzero exit with an incorrect
PIN surfacing. The runner uploads every record, log, substituted
config, and module digest even when the leg fails.
