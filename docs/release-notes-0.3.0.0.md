# Haskoki 0.3.0.0 — first public release (draft notes)

> Draft for tag `v0.3.0.0`. Pre-publish: reading this file does
> not mean the tag, the release, or the image exists yet.

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
| `SHA256SUMS` | Checksums of the four files above (written after finalization, excluding itself) |
| `ghcr.io/mingulov/haskoki-demo:v0.3.0.0` | Demo image (bundle + pinned proxy + external checker + entrypoint). Digest recorded in the release evidence; `latest` is a convenience pointer only, never the verified identifier. |

Verify downloads with `(cd <dir> && sha256sum -c SHA256SUMS)`
(expects 4 OK) and the image with `docker inspect --format
'{{.Id}} {{.RepoDigests}}'`.

## Quick start

Prerequisites: Docker alone (the image pulls from GHCR on
first run; no checkout or local build needed). Then:

```sh
docker run --rm --network none -v "$PWD/out:/out" \
  ghcr.io/mingulov/haskoki-demo:v0.3.0.0 demo
# demo-ok: 8/8 verifications hold
```

To build and verify locally instead of pulling: from a
checkout of this tag, build the toolchain image per the
[container Quick Start](../README.md#quick-start-container-no-haskell-build)
(base image only), then run the release driver, which
stages the bundle, builds the demo image, and asserts
every lane:

```sh
HASKOKI_DEMO_TEST_OUT=./out sh scripts/test-demo-image.sh
# PASS: test-demo-image.sh (…); wall ~85 min
```

(Post-publish form shown; the image does not exist on GHCR
until the release is cut.)

## Confirmed matrix

- Hosts: Linux x86-64, glibc ≥ 2.43 (`ubuntu:26.04` +
  `libgmp10`/`libffi8`/`libnuma1` verified; the image carries
  its own userland).
- Checker `pkcs11-check` 0.2.3 (PyPI pin), offline
  smoke/full profiles; proxy `pkcs11-proxy-ng` v0.2.0
  (TEST-ONLY loopback transport).
- CI gates: static gates + `cabal test all` + bundle build +
  bare-install test + sdist out-of-checkout verify + fast
  lane + full demo-image lanes (demo, smoke, full direct,
  full proxy, compare).

## Results (measured on this release)

- Checker smoke (743 tests): zero findings, direct and proxied.
- Checker full (11003 tests): direct 27 triaged findings
  (4 families); proxied 25 findings, all shared with direct,
  zero proxy-only.
- Compare direct-vs-proxy: 188 frozen exclusions in 7 reasoned
  families + 25 shared findings (zero allowed variance).
- Direct/proxy parity on the pinned proxy: 49 consumer legs
  hold; 40 quarantined skips with upstream causes.
- Demo: 8/8 verifications hold. Proxy example: 5/5 steps hold.
- Full tables and triage: [release-results](release-results.md).

## Limitations

- Demonstrator scope: no certification; proxy example is
  TEST-ONLY transport (loopback, no auth/TLS).
- 316 of 464 catalog mechanisms behavior-covered; the rest
  refuse honestly. Upstream proxy defects #35/#36/#39 open;
  proxy v0.2.1 rejected (daemon death, #37).
- Vector corpora ship unfetched (separate opt-in recipe).
- Full list: [SUPPORTED-HOSTS](../SUPPORTED-HOSTS.md);
  component licenses: [dependency
  inventory](dependency-inventory.md).

## Related tools

[`pkcs11-check`](https://github.com/mingulov/pkcs11-check)
(external checker, same author),
[`pkcs11-proxy-ng`](https://github.com/mingulov/pkcs11-proxy-ng)
(proxy),
[`p11scope`](https://github.com/mingulov/p11scope) (call
observer; [sample capture](p11scope-trace.md)),
[`P11Lab`](https://github.com/mingulov/p11lab) (lab setup).

## Development story

How it was built, checked, and measured (draft, awaiting owner
data for personal time/spend): [first public
release](first-public-release.md) + [development
metrics](development-metrics.json).
