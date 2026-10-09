# Haskoki

Haskoki is a Haskell PKCS#11 software token for experiments, integration
tests, and learning how the interface behaves. Applications load
`libhaskoki.so` through the usual C interface; OpenSSL performs the real
cryptographic operations.

It exposes versioned tables for PKCS#11 2.40, 3.0, 3.1, and 3.2. The
catalog records 316 behavior-tested mechanisms out of 464 entries.
That is a coverage inventory, not a conformance or certification claim.
Use disposable keys: this is a demonstrator, not a production HSM.

**Release status:** version 0.3.0.0 is prepared in source. As of
2026-10-09, no GitHub release or anonymously pullable demo image has
been verified. The [release checklist](docs/publishing.md) covers the
remaining publication steps. The local demo below is available now.

## Quick Start (container, no Haskell build)

Use Docker from a non-root shell on Linux x86-64, with network access
during the build. The builder user is matched to your UID/GID below. The
first build downloads the compiler, crypto library, checker, and proxy;
allow several minutes and several GB of disk space.

```sh
git clone https://github.com/mingulov/haskoki.git
cd haskoki
HASKOKI_BUILD_USER=ubuntu
if [ "$(id -u)" != 1000 ]; then HASKOKI_BUILD_USER=haskoki-builder; fi
docker build --build-arg USERNAME="$HASKOKI_BUILD_USER" \
  --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" \
  -t haskoki-dev:ghc-9.10.3 .
docker run --rm -v "$PWD:/work" -w /work \
  haskoki-dev:ghc-9.10.3 scripts/make-release.sh
mkdir -p staged-bundle
cp -a dist-release/haskoki-0.3.0.0 staged-bundle/
docker build -f docker/Dockerfile.demo \
  --build-arg REVISION="$(git rev-parse HEAD)" \
  -t haskoki-demo:0.3.0.0 .
rm -r staged-bundle

mkdir -p out
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" haskoki-demo:0.3.0.0 demo
```

Expect `demo-ok: 8/8 verifications hold`. The demo creates an EC key
pair, signs and verifies a message, checks the SHA-256 digest of `abc`,
and performs an RSA-OAEP encrypt/decrypt round trip. Reports and step
logs appear under `out/demo-*/`. The runs use public demo fixtures and
fresh stores; they need no external network or real token.

Next, run the external checker:

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" haskoki-demo:0.3.0.0 \
  check --mode direct --profile smoke
```

Expect `check-ok: zero findings`. This profile collects 743 tests;
some are skipped or expected failures. It does not mean 743 passing
tests or complete PKCS#11 coverage. See [Try it](docs/try-it.md) for
the small proxy demo, report locations, and the longer checks.

## What to explore

| Interest | Start here |
| --- | --- |
| Run a small demo and understand its output | [Try it](docs/try-it.md) |
| Load the module in your own application | [Native walkthrough](docs/demo-walkthrough.md) and [host requirements](SUPPORTED-HOSTS.md) |
| See what is implemented and what remains | [Coverage](docs/coverage.md) and [test results](docs/release-results.md) |
| Understand why this is written in Haskell | [Haskell design](docs/haskell-design.md) |
| Read how the project developed | [Development history](docs/first-public-release.md) |
| Build, test, or publish a release | [Toolchain](docs/toolchain.md) and [publishing](docs/publishing.md) |

The current demo checker's full profile records 22 findings shared
between direct and proxied runs. The comparison also has 83 documented
exclusions. These are known limits, not a clean full-suite result; the
[results page](docs/release-results.md) separates current CI evidence
from earlier measurements.

## Why Haskell

The protocol model separates planning a call, running a crypto effect,
finishing the result, and publishing the state change. Distinct types
describe handles, output requests, and failures. A separate pure-core
component lets model and property tests exercise rules without loading
a C consumer. The [design note](docs/haskell-design.md) explains the
benefits and the runtime and FFI work that types do not remove.

## Related tools

- [pkcs11-check](https://github.com/mingulov/pkcs11-check) exercises a
  compiled PKCS#11 module and reports its behavior. The demo pins
  version 0.2.3. It shares an author with Haskoki, so this is external
  consumer evidence, not an independent audit.
- [pkcs11-proxy-ng](https://github.com/mingulov/pkcs11-proxy-ng) places
  the module in a separate process behind a PKCS#11 shim. The demo pins
  v0.2.2 and uses plaintext loopback transport inside one container.
- [p11scope](https://github.com/mingulov/p11scope) can optionally help
  inspect PKCS#11 calls on Linux. It is not needed for the demo; the
  [recorded capture](docs/p11scope-trace.md) has stated coverage limits.

## Practical limits

The native bundle targets Linux x86-64 with glibc 2.43 or newer; the
container supplies its own userland. SQLite token storage is not
encrypted at rest. The GHC runtime stays loaded for the process lifetime,
and sessions must be closed before finalization. The proxy example adds
a process boundary, not a hardened HSM or authenticated network service.
See [operations notes](docs/operations-notes.md) for PIN lockout, storage,
and lifecycle details.

If a command fails, keep its `report.json` and logs, check the image
revision, and use the [bug template](.github/ISSUE_TEMPLATE/bug_report.md).
Do not attach keys, PINs, or token databases. Haskoki is licensed under
[Apache-2.0](LICENSE).
