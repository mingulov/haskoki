# Haskoki 0.5.0.0 — first public release

Haskoki is a PKCS#11 software token written in Haskell, with OpenSSL doing
the cryptography. Use it to learn PKCS#11 and to test clients, with
disposable keys rather than real secrets.

## Start here

```sh
docker run --rm --network none ghcr.io/mingulov/haskoki-demo:v0.5.0.0
```

Expect `demo-ok: 8/8 verifications hold`. No checkout, build or hardware is
needed. The [hands-on guide](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/try-it.md)
shows how to keep the output, generate a key with `pkcs11-tool` and sign a
message.

## What's new

- **Keys are protected by default.** New private and secret keys cannot be
  read back unless you allow it when you create them, and sensitive values
  are never returned or matched by searches.
- **Keys are used only as intended.** Deriving is off unless you enable it,
  `CKA_ALLOWED_MECHANISMS` now also applies to derive, wrap, unwrap and
  KEM, keys of the wrong type or class are refused, and wrong-length
  signatures are rejected.
- **New storage format.** Stores move to schema 3, with a one-time
  migration that writes a verified backup.
- **Tested with real clients.** OpenSC `pkcs11-tool`, GnuTLS, Java
  (SunPKCS11) and OpenSSL pass 61 of 61 journeys with the installed bundle
  and 28 of 28 in the demo image.
- **Fixes**, among them a hang with several GHC RTS capabilities, a crash
  risk when closing a session during a native async call, DH secrets that
  lost a leading zero byte, and stale store locks.
- **Tracing is off by default.**

## Upgrading from 0.4

- Run `haskoki-ctl store migrate` once per store; `haskoki-ctl store check`
  tells you what a store needs. Older binaries cannot open a migrated store,
  so keep the backup if you may go back. See
  [Upgrading a v0.4 token store](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/demo-walkthrough.md#upgrading-a-v04-token-store).
- New keys are unextractable and have `CKA_DERIVE=false` unless the
  template says otherwise.
- Token serials are now 16 hex digits; update saved `pkcs11:` URIs that use
  `serial=`.
- Some error codes are more precise, and non-ASCII token labels and PINs are
  refused. The [changelog](https://github.com/mingulov/haskoki/blob/v0.5.0.0/CHANGELOG.md)
  lists every change.

## Known limitations

- Key values read back as DER (SPKI or PKCS#8) rather than the raw PKCS#11
  encoding; DSA and DH public keys read back as raw `y`.
- `CKM_RSA_PKCS` encryption is not offered; use `CKM_RSA_PKCS_OAEP`.
- When Haskoki starts the GHC runtime itself, it uses one capability and
  ignores `GHCRTS`.
- 91 of 104 PKCS#11 3.2 functions and 316 of 464 catalogued mechanisms are
  served; the rest refuse with explicit error codes. See
  [coverage](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/coverage.md).
- Token storage is not encrypted.
- Linux amd64 only. The full checker profile reports 21 documented findings
  ([results](https://github.com/mingulov/haskoki/blob/v0.5.0.0/docs/release-results.md));
  no conformance or certification is claimed.

## Downloads

The release has the Linux bundle, the source archive, test logs,
`release-manifest.json` and `SHA256SUMS`. Check downloads with
`sha256sum -c SHA256SUMS`. This release is not signed. Published on
October 19, 2026 from source `091a222`.
