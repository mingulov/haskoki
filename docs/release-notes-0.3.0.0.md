# Haskoki 0.3.0.0 - first public release

Published October 9, 2026 from `c49aa45f543522746380eda2a08d9f71b839b4ea`.
The [release workflow](https://github.com/mingulov/haskoki/actions/runs/37961585654)
includes the anonymous image pull and demo checks.

## Purpose

Haskoki is a Haskell PKCS#11 soft token (demonstrator) covering
APIs 2.40, 3.0, 3.1 and 3.2: real in-process crypto over
OpenSSL with honest refusals for the genuinely unsupported
calls. Not a certified HSM; no production-security claim.

## Artifacts

| Asset | Contents |
|---|---|
| `haskoki-0.3.0.0-linux-x86_64.tar.gz` | Bundle tree: `libhaskoki.so`, `haskoki-ctl`, bundled closure, licenses, smoke |
| `haskoki-0.3.0.0.tar.gz` | Verified source distribution (unpacked + built + tested outside the checkout) |
| `test-results-0.3.0.0.tar.gz` | Staged gate-evidence logs (Haskell suites, fast lane, demo-image runs) |
| `release-manifest.json` | Source SHA, versions, build env, artifact hashes, tool pins |
| `SHA256SUMS` | Checksums of the three archives and manifest |
| `ghcr.io/mingulov/haskoki-demo:v0.3.0.0` | Demo image (bundle + pinned proxy + external checker + entrypoint). Digest recorded in the release evidence; `latest` is a convenience pointer only, never the verified identifier. |

This release shipped unsigned: no `SHA256SUMS.asc` was attached.
Download the three archives, manifest, and checksum file, then run
`sha256sum -c SHA256SUMS` (four OK results). The checksums check file
integrity, not a publisher signature. The image digest in the manifest is
`sha256:e440a66723c86340f49d3bf2d828095ea836b2dec9d7bd020d3593844d8bce5c`.

## Quick start

Prerequisites: Docker alone (the image pulls from GHCR on
first run; no checkout or local build needed). Then:

```sh
mkdir -p out
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD/out:/out" \
  ghcr.io/mingulov/haskoki-demo:v0.3.0.0 demo
# demo-ok: 8/8 verifications hold
```

## Confirmed matrix

- Hosts: Linux x86-64, glibc >= 2.43 (`ubuntu:26.04` +
  `libgmp10`/`libffi8`/`libnuma1` verified; the image carries
  its own userland).
- Checker `pkcs11-check` 0.2.3 (PyPI pin), offline
  smoke/full profiles; proxy `pkcs11-proxy-ng` v0.2.2
  (TEST-ONLY loopback transport).
- CI gates: static gates + `cabal test all` + bundle build +
  bare-install test + sdist out-of-checkout verify + fast
  lane + full demo-image lanes (demo, smoke, full direct,
  full proxy, compare).

## Results (candidate CI at 0603322)

- Checker smoke (743 collected tests, including skips and expected failures): zero findings, direct and proxied.
- Checker full (10993 collected tests): direct 22 triaged findings
  (4 families); proxied 22 findings, all shared with direct,
  zero proxy-only.
- Compare direct-vs-proxy: 83 frozen exclusions in 6 reasoned
  families + 22 shared findings (zero allowed variance).
- Direct/proxy parity on the pinned proxy: 70 consumer legs
  hold; 19 quarantined legs in 5 quarantine entries with upstream
  causes.
- Demo: 8/8 verifications hold. Proxy example: 5/5 steps hold.
- Counts include skips and expected failures; findings are not silently
  treated as passing tests. Full tables and triage: [release-results](https://github.com/mingulov/haskoki/blob/v0.3.0.0/docs/release-results.md).

## Limitations

- Demonstrator scope: no certification; proxy example is
  TEST-ONLY transport (loopback, no auth/TLS).
- 316 of 464 catalog mechanisms behavior-covered. Proxy v0.2.2
  resolved the previously recorded #35/#36/#37/#39 defects; the
  compared subset still has documented exclusions and skipped cases.
- Vector corpora ship unfetched (separate opt-in recipe).
- Full list: [SUPPORTED-HOSTS](https://github.com/mingulov/haskoki/blob/v0.3.0.0/SUPPORTED-HOSTS.md);
  component licenses: [dependency
  inventory](https://github.com/mingulov/haskoki/blob/v0.3.0.0/docs/dependency-inventory.md).

## Related tools

[`pkcs11-check`](https://github.com/mingulov/pkcs11-check)
(external checker, same author),
[`pkcs11-proxy-ng`](https://github.com/mingulov/pkcs11-proxy-ng)
(proxy),
[`p11scope`](https://github.com/mingulov/p11scope) (call
observer; [sample capture](https://github.com/mingulov/haskoki/blob/v0.3.0.0/docs/p11scope-trace.md)),
[`P11Lab`](https://github.com/mingulov/p11lab) (lab setup).

## Development story

Read the [development history](https://github.com/mingulov/haskoki/blob/v0.3.0.0/docs/first-public-release.md) and
[Haskell design](https://github.com/mingulov/haskoki/blob/v0.3.0.0/docs/haskell-design.md). The usage snapshot linked from
the history is cutoff-limited, not a final cost or personal-time claim.
