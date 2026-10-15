# Haskoki 0.4.0.0 — provisioned tokens

This release makes tokens provisionable in-band. Haskoki remains a Haskell
PKCS#11 software token for learning and integration tests; use disposable
keys, not production secrets.

## Start here

```sh
docker run --rm --network none ghcr.io/mingulov/haskoki-demo:v0.4.0.0
```

Expect `demo-ok: 8/8 verifications hold`. No checkout, local build, or
hardware is required. Files are disposable unless you mount `/out`.
The [hands-on guide](https://github.com/mingulov/haskoki/blob/v0.4.0.0/docs/try-it.md)
shows how to keep them, generate a key with `pkcs11-tool`, and sign a message.

## Improvements

- `C_InitToken`, `C_InitPIN`, and `C_SetPIN` work end to end: the default
  slot-0 token (`haskoki-demo`, SO PIN `5678`) can be reinitialized and
  given fresh user PINs, durably across restarts; other slots can also
  be relabeled (slot 0 keeps its `haskoki-demo` label).
- Re-initialization is authorized: the caller PIN must match the existing
  SO PIN, otherwise the call is refused and nothing changes.
- A logout oracle and executable reference cover session teardown, and
  login-reopen plus provisioning-guard journeys extend consumer coverage.
- New guides: the supported-hosts matrix and operations notes; the
  publishing, hands-on, and results guides are refreshed for this release.

## Contents and limits

The Linux amd64 image carries the tool set recorded in the
[dependency inventory](https://github.com/mingulov/haskoki/blob/v0.4.0.0/docs/dependency-inventory.md).
Other architectures and Docker Desktop paths are unqualified. The C
library version reported by `C_GetInfo` is now {0, 4}.

The mechanism inventory and documented full-checker findings still apply.
The p11-kit example covers basic operations, not a full PKCS#11 3.x remoting
matrix. Token storage is unencrypted. See
[results](https://github.com/mingulov/haskoki/blob/v0.4.0.0/docs/release-results.md)
and [host limits](https://github.com/mingulov/haskoki/blob/v0.4.0.0/SUPPORTED-HOSTS.md).

## Downloads

Release assets include the native Linux bundle, source archive, test logs,
`release-manifest.json`, and `SHA256SUMS`. The manifest records the exact
source and image digest. `SHA256SUMS.asc` is included **only if** the owner
configures release signing; do not assume it exists. After downloading the
archives and manifest alongside the checksums, run `sha256sum -c SHA256SUMS`.

The [publishing guide](https://github.com/mingulov/haskoki/blob/v0.4.0.0/docs/publishing.md)
explains the GitHub-only build and publication workflow. A source branch
preparing this version does not mean its release or image has been published.
