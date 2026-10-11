# Haskoki 0.3.1.0 — easier to try

This release focuses on the first demo experience. Haskoki remains a Haskell
PKCS#11 software token for learning and integration tests; use disposable
keys, not production secrets.

## Start here

```sh
docker run --rm --network none ghcr.io/mingulov/haskoki-demo:v0.3.1.0
```

Expect `demo-ok: 8/8 verifications hold`. No checkout, local build, or
hardware is required. Files are disposable unless you mount `/out`.
The [hands-on guide](https://github.com/mingulov/haskoki/blob/v0.3.1.0/docs/try-it.md)
shows how to keep them, generate a key with `pkcs11-tool`, and sign a message.

## Improvements

- A shorter README explains the project and crypto vocabulary before the
  implementation details. The creation story explains Haskell, the related
  tools, and the dated AI-usage measurements.
- The image works without an output mount. `shell` prepares a token store,
  puts tools on `PATH`, and exposes `HASKOKI_MODULE` and `HASKOKI_CONFIG`.
- `proxy-demo` runs the existing pkcs11-proxy-ng example directly.
- `p11-kit-demo` demonstrates the alternative p11-kit server/client route
  over a local Unix socket, including signature, digest, tamper-rejection,
  and disconnected-server checks. It needs no proxy-ng service.
- The GitHub demo contracts exercise these beginner paths on the same image
  used by the other checks, without external network access and under an
  arbitrary numeric UID. Build logs record the image size and identity.

## Contents and limits

The Linux amd64 image includes the Haskoki runtime, OpenSSL, OpenSC,
`pkcs11-check` 0.2.3, `pkcs11-proxy-ng` v0.2.2, p11-kit, and examples.
Compilers are separate; optional vector collections are downloaded only
when requested. Other architectures and Docker Desktop paths are unqualified.

The mechanism inventory and documented full-checker findings still apply.
The p11-kit example covers basic operations, not a full PKCS#11 3.x remoting
matrix. Token storage is unencrypted. See
[results](https://github.com/mingulov/haskoki/blob/v0.3.1.0/docs/release-results.md)
and [host limits](https://github.com/mingulov/haskoki/blob/v0.3.1.0/SUPPORTED-HOSTS.md).

## Downloads

Release assets include the native Linux bundle, source archive, test logs,
`release-manifest.json`, and `SHA256SUMS`. The manifest records the exact
source and image digest. `SHA256SUMS.asc` is included **only if** the owner
configures release signing; do not assume it exists. After downloading the
archives and manifest alongside the checksums, run `sha256sum -c SHA256SUMS`.

The [publishing guide](https://github.com/mingulov/haskoki/blob/v0.3.1.0/docs/publishing.md)
explains the GitHub-only build and publication workflow. A source branch
preparing this version does not mean its release or image has been published.
