# Haskoki

Try the interface used by smart cards and hardware security modules, using
software on your computer. Haskoki lets you create a disposable key, sign a
message, check its signature, and experiment with encryption—no hardware
or Haskell knowledge required.

**PKCS#11** is the common interface that applications use to ask a *token*
to hold keys and perform cryptographic operations. Haskoki is a software
token written in **Haskell**, a functional programming language. OpenSSL
performs the cryptography; ordinary tools talk to Haskoki through
`libhaskoki.so`, just as they would load another PKCS#11 module.

Use disposable keys. This is a demonstrator for learning and client testing,
not a production HSM; its stored keys are not encrypted at rest.

## Try it with Docker

This branch prepares **v0.3.1.0**. Its image tag becomes available on
publication; the [published v0.3.0.0 demo](https://github.com/mingulov/haskoki/releases/tag/v0.3.0.0)
can be tried now using the command on that release page.

With Docker running, paste this into a terminal:

```sh
docker run --rm --network none ghcr.io/mingulov/haskoki-demo:v0.3.1.0
```

Docker downloads the image on the first run. The demo itself works offline:
it generates keys, signs and verifies a message, checks a SHA-256 fingerprint,
and encrypts then decrypts another message. Look for:

```text
demo-ok: 8/8 verifications hold
```

That's the complete first run. No clone, compiler, account, PIN setup, or
physical token is needed. The keys and reports disappear when this container
exits. [Try it yourself](docs/try-it.md) shows how to keep reports and type
the individual `pkcs11-tool` commands.

The image includes Haskoki, its runtime and crypto libraries, OpenSC
`pkcs11-tool`, `pkcs11-check`, `pkcs11-proxy-ng`, and p11-kit remoting. Extra
test-vector collections are an optional download. The tested platform is
**Linux x86-64 (amd64)**; Docker supplies the Linux libraries. Other platforms
and ARM emulation have not been qualified. Image measurements and contents
are in [Try it](docs/try-it.md#image-contents-and-size).

## Where it came from

Haskoki grew from a small experiment: describe a token's rules in Haskell,
then let real applications challenge those rules. The first step was a
loadable module; the harder work followed when clients exercised keys,
sessions, errors, and process boundaries.

[pkcs11-check](https://github.com/mingulov/pkcs11-check) supplies the external
checks, and [pkcs11-proxy-ng](https://github.com/mingulov/pkcs11-proxy-ng)
lets the same token run in a separate process. Both share an author with
Haskoki. Coding agents helped implement and review the project; tests and
consumer runs supply the behavioral evidence. The [short development
story](docs/first-public-release.md) explains the Haskell choice and the
recorded token usage, including why cached input dominates those figures.

A side note: [p11scope](https://github.com/mingulov/p11scope) can observe
PKCS#11 calls on Linux. It is optional and runs separately; a
[sample trace](docs/p11scope-trace.md) shows what was captured.

## Choose your next step

| I want to… | Start here |
| --- | --- |
| Generate a key and sign something myself | [Hands-on guide](docs/try-it.md#try-pkcs11-tool-yourself) |
| Try the checker or another process | [Checker and remoting](docs/try-it.md) |
| Understand the project and its creation | [Development story](docs/first-public-release.md) |
| Load it in my own application | [Native reference](docs/demo-walkthrough.md) and [host requirements](SUPPORTED-HOSTS.md) |
| Investigate support or build the project | [Coverage](docs/coverage.md), [results](docs/release-results.md), [developer toolchain](docs/toolchain.md) |

Haskoki exposes PKCS#11 2.40–3.2 interfaces, with 316 behavior-tested
mechanisms out of 464 catalog entries. The full checker profile retains
22 documented findings; the short smoke profile expects zero. Neither
number establishes conformance or certification. See the [results and
limits](docs/release-results.md) before choosing it for an integration.

[Apache-2.0](LICENSE) · [Report a problem](https://github.com/mingulov/haskoki/issues/new?template=bug_report.md)
