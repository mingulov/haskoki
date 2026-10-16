# Certificate-linked application journey

Metadata and `CKA_ID` linkage of a fixture certificate to a
separately generated key: link under one `CKA_ID`, select by that
ID, restart, refuse the wrong identity, and finish with a real
application reading the linked identity. The certificate
(RSA-2048) does not belong to the key; what the native half proves
is metadata round trip plus `CKA_ID` linkage, never
certificate/key correspondence. The native half runs in
`tests/c/consumer_certlink.c` (run by
`scripts/test-consumers.sh` in direct mode and by
`scripts/test-proxy-parity.sh` in both modes); the application half
is a Java KeyStore plus application-signing leg.

## Native legs

The consumer loads the real fixture DER
(`tests/fixtures/cert-selfsigned.der`, SHA-256 pinned, no embedded
synthetic bytes), derives subject and serial bytes with its DER
walker, and works in three initialize intervals of one process.

Memory interval — link, readback, and use:

- The DER becomes an X.509 session certificate object; an EC P-256
  pair mints with link ID bytes `{0x01, 0x01}` in its keygen
  templates (the same identity shape the CLI journeys persist);
  the certificate takes that ID after creation.
- The generated private key reports the public half's curve
  parameters (`CKA_EC_PARAMS` equal on both halves).
- Find-by-ID returns exactly the three linked handles (order
  unclaimed; asserted as a set); find-by-absent-ID returns none.
- `CKA_VALUE` reads back the DER bytes; `CKA_SUBJECT` reads back
  the derived subject bytes.
- The untyped `CKA_HASH_OF_CERTIFICATE` read refuses with
  `CKR_ATTRIBUTE_TYPE_INVALID`, an unavailable length, and the
  caller buffer untouched.
- The linked key signs an application message under
  `CKM_ECDSA_SHA256` and the linked public key verifies it; a
  tampered message and a distractor public key both refuse with
  `CKR_SIGNATURE_INVALID`.

SQLite intervals — persistence across restart (direct mode only):

- The same linkage persists as token objects, the interval
  finalizes, and a reopened interval finds the three handles by ID
  with the certificate bytes intact.
- The restarted objects destroy cleanly and the linkage then finds
  nothing.
- Direct-only because the client cannot switch the proxy daemon's
  backend and client reattach is not a backend restart — the same
  root cause as the direct-only `consumer_certificates:restart`
  leg. Proxy mode skips these legs with a loud note, never
  silently.

Passing evidence is exit 0 plus the `PASS: consumer_certlink`
trailer; session legs use the `crypto:` prefix for the parity
driver, as in [journey-aead.md](journey-aead.md).

## Supplied-metadata policy

The token stores the `CKA_VALUE` bytes and returns caller-supplied
subject, issuer, serial, and public-key-info bytes; it does not
parse DER or check that metadata agrees with the value (see
[certificate-objects.md](certificate-objects.md)). The journey
supplies DER-derived subject and serial bytes the way a real client
would, and the readback legs pin that round trip. Chain building,
trust decisions, and validity enforcement stay application work.

## Application leg: Java KeyStore plus signing

The plan's certificate-linked application use case is Java
KeyStore with application signing — chosen over an OpenSSL
provider journey because the SunPKCS11 lane is already qualified
(login, keygen, sign) while no provider diagnostics exist, so the
provider path would add a new integration surface for this
purpose. Enumeration alone never counts: the leg needs a real
certificate matched to its key, used by a real application step.

`HASKOKI_CONFIG` points at the substituted
`tests/journeys/keystore/haskoki-keystore.toml` (SQLite store);
the SunPKCS11 config from `tests/journeys/sunpkcs11/sunpkcs11.cfg`
is reused with `@MODULE@` substituted. All commands run with the
pinned JDK from [client-portfolio.md](client-portfolio.md):

```sh
# Generate the pair on the token with a self-signed certificate.
keytool -genkeypair -keystore NONE -storetype PKCS11 \
  -providerClass sun.security.pkcs11.SunPKCS11 -providerArg run.cfg \
  -keyalg EC -keysize 256 -alias app-key -dname "CN=journey-app" \
  -storepass 1234
# The entry must pair the private key with its certificate chain.
keytool -list -v -keystore NONE -storetype PKCS11 \
  -providerClass sun.security.pkcs11.SunPKCS11 -providerArg run.cfg \
  -storepass 1234 -alias app-key
# Sign and verify an application archive with the token entry.
printf 'journey payload' > payload.txt
jar cf app.jar payload.txt
jarsigner -keystore NONE -storetype PKCS11 \
  -providerClass sun.security.pkcs11.SunPKCS11 -providerArg run.cfg \
  -storepass 1234 app.jar app-key
jarsigner -verify app.jar
# The wrong alias must refuse, not sign.
jarsigner -keystore NONE -storetype PKCS11 \
  -providerClass sun.security.pkcs11.SunPKCS11 -providerArg run.cfg \
  -storepass 1234 app.jar no-such-alias
```

Expected: `genkeypair` exits 0; `list` shows a `PrivateKeyEntry`
with a certificate chain; `jarsigner` signs and `-verify` reports
the jar verified; the wrong-alias call fails without touching the
archive. Status TO-QUALIFY: never attempted. Each command emits a
[journey evidence record](client-portfolio.md#evidence-record-format)
(`java-keystore-gen`, `java-keystore-list`, `java-keystore-sign`,
`java-keystore-verify`, `java-keystore-refuse-alias`).
