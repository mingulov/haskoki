# Journey: certificate-linked key

This journey answers one question per consumer: does the token link
the right metadata to the right key? The native consumer below is a
metadata linkage receipt (linkage, never correspondence); the Java
application journey underneath it is the matched-certificate path,
where the certificate's key must be the token key.

## Native consumer (metadata linkage)

`tests/c/consumer_certlink.c` links the self-signed RSA-2048
fixture certificate (`tests/fixtures/cert-selfsigned.der`, SHA-256
pinned, no embedded synthetic bytes) to a separately generated EC
P-256 key through the pinned 3.2 headers: the certificate becomes
an X.509 certificate object with DER-derived subject and serial
bytes, the key mints with CKA_ID `{0x01, 0x01}`, and the
certificate takes that ID after creation. The certificate does not
belong to the key — nothing here asserts correspondence:

- The generated private key reports the public half's curve
  parameters (`CKA_EC_PARAMS` equal on both halves).
- Find-by-ID returns exactly the three linked handles;
  find-by-absent-ID returns none; `VALUE` and `SUBJECT` read back
  the stored bytes; the untyped `CKA_HASH_OF_CERTIFICATE` read
  refuses with `CKR_ATTRIBUTE_TYPE_INVALID`, an unavailable
  length, and the caller buffer untouched.
- The linked key signs an application message and the linked
  public key verifies it; a tampered message and the wrong public
  key both refuse with `CKR_SIGNATURE_INVALID`.
- The same linkage persists as token objects in a SQLite store
  across a finalize/re-initialize restart, then destroys cleanly.

The link-ID bytes `{0x01, 0x01}` deliberately match the CLI
journeys ([client-portfolio.md](client-portfolio.md)), where
OpenSC creates the persisted key under `--id 0101` and GnuTLS
uses it. The memory interval runs identically in direct and
proxy topologies; the SQLite restart intervals are direct-only
(the client cannot switch the daemon backend), skipped in proxy
mode with a loud note.

### Contract

- Compile with `-Ispec/vendor`. The translation unit includes only
  the pinned vendor headers, never provider-generated artifacts
  (enforced by the driver script's independence guard); its
  SHA-256 and DER walker are translation-unit-local copies.
- Usage: `consumer_certlink <libhaskoki.so>`. Exit 0 prints
  `PASS: consumer_certlink (...)`; usage and `dlopen` failures
  exit 2.
- Part of `scripts/test-consumers.sh` and
  `scripts/test-proxy-parity.sh`.

### Evidence

The portfolio and image legs run the compiled consumer against
the installed module with the native junction:

```sh
consumer_certlink $MODULE
```

Leg `native-certlink-metadata` expects exit 0 with
`PASS: consumer_certlink` and
`linked private key reports the curve parameters`. Evidence:
pass P+I
([client-journeys.json](release-results/client-journeys.json)).

## Application journey (matched certificate)

The Java KeyStore legs use a certificate whose key IS the token
key. Setup mints an EC P-256 pair on the token (`app-key`, id
`0202`), exports its public half, signs a leaf certificate for
that public key with the journey CA (`CN=journey-app`), writes
the leaf back as the key's certificate object, and compares the
certificate SPKI against the token public-key SPKI byte for
byte. A jar bundles the payload, `jarsigner` signs it through
SunPKCS11, and two verifiers plus a tamper leg close the loop.
All legs run against the installed bundle with the keystore
junction; evidence is pass P unless noted.

| Leg | Shape | Expect |
| --- | --- | --- |
| `keystore-create-key` | `pkcs11-tool --keypairgen --key-type EC:prime256v1 --label app-key --id 0202 --usage-sign` | exit 0 |
| `keystore-export-pubkey` | `--read-object --type pubkey --id 0202 -o out/app-pub.der` | exit 0 |
| `keystore-issue-cert` | `issue-cert --pub out/app-pub.der --out-dir ca --cn journey-app` | exit 0; `SPKI-MATCH` (the issued leaf carries the token key) |
| `keystore-write-cert` | `--write-object ca/leaf.der --type cert --id 0202 --label app-key` | exit 0; `ID:         0202` |
| `keystore-read-cert` | `--read-object --type cert --id 0202 -o out/app-cert.der` | exit 0 |
| `keystore-spki-match` | `spki-match out/app-cert.der out/app-pub.der` | exit 0; `SPKI-MATCH` |
| `keystore-make-jar` | `jar cf out/app.jar` over the keystore payload | exit 0 |
| `java-keystore-list` | `keytool -list` over SunPKCS11 | exit 0; `app-key, PrivateKeyEntry` |
| `java-keystore-refuse-pin` | `keytool -list -v` with PIN `0000` | exit 1; `CKR_PIN_INCORRECT` through the verbose cause chain |
| `java-keystore-refuse-token` | `keytool -list -v` against a missing slot | exit 1; `CKR_SLOT_ID_INVALID` through the verbose cause chain |
| `java-keystore-sign` | `jarsigner -sigalg SHA256withECDSA -signedjar out/app-signed.jar out/app.jar app-key` | exit 0; `jar signed.`; independently verified |
| `java-keystore-verify` | `jarsigner -verify -verbose -certs out/app-signed.jar` | exit 0; `jar verified.`; `jar is unsigned.` absent |
| `java-keystore-verify-independent` | `jar-cms-verify --jar out/app-signed.jar --ca ca/ca.pem --sig-dir sig` | exit 0; `CMS Verification successful` |
| `java-keystore-tamper` | `jar-tamper ... -- jarsigner -verify out/tampered.jar` | `JOURNEY-TAMPER-DETECTED` with `digest error`; `jar verified.` absent |
| `java-keystore-refuse-alias` | `jarsigner ... -signedjar out/alias.jar out/app.jar no-such-alias` | exit 1; `Certificate chain not found for: no-such-alias`; output jar absent |

### Mismatch control

A second entry checks that a wrong certificate does not pass as matched:
`keystore-mismatch-create` mints EC P-256 `mismatched-key` (id
`0303`), `keystore-mismatch-export-pubkey` exports its public
half, and `keystore-mismatch-write-cert` stores the RSA-2048
fixture certificate under the same id and label.
`keystore-mismatch-spki` compares the RSA certificate SPKI
against the EC public half and refuses with `SPKI-MISMATCH`
(exit 1). The `java-keystore-refuse-mismatched` leg then attempts
the full sign path and expects no verified signature (pass P):
jarsigner refuses the cross-algorithm entry at the sign stage
with `jarsigner error:
java.lang.IllegalArgumentException: private key algorithm does
not match algorithm of public key in end entity certificate (the
1st in certPath)` (`logs/java-keystore-refuse-mismatched.log:1`),
so the row pins `JOURNEY-NO-VERIFIED-SIGNATURE stage=sign` plus
that cause line. The verify stage is unreachable with this
fixture: jarsigner compares the private-key algorithm against
the end-entity certificate's public-key algorithm client-side
before signing, with no `PKCS11Exception` wrapper for the
provider to influence. See the status note in
[client-portfolio.md](client-portfolio.md).

### Keytool on-token generation

`keytool -genkeypair` generates an EC P-256 pair with a
self-signed certificate directly on the token (exit 0).
`java-keystore-generate` pins that receipt
(`key pair and self-signed certificate`), and
`java-keystore-sign-generated` signs a jar with the generated
entry (`jar signed.`). Both pass in P.
