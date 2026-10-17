# Haskoki

Try the interface used by smart cards and hardware security modules, using
software on your computer. Haskoki lets you create a disposable key, sign a
message, check its signature, and experiment with encryption. No hardware
or Haskell knowledge required.

**PKCS#11** is the common interface that applications use to ask a *token*
to hold keys and perform cryptographic operations. Haskoki is a software
token written in **Haskell**, a functional programming language. OpenSSL
performs the cryptography; ordinary tools talk to Haskoki through
`libhaskoki.so`, just as they would load another PKCS#11 module.

Use disposable keys. This is a demonstrator for learning and client testing,
not a production HSM; its stored keys are not encrypted at rest.

## Try it with Docker

With Docker running, paste this into a terminal:

```sh
mkdir -p out
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" ghcr.io/mingulov/haskoki-demo:v0.4.0.0 demo
```

Docker downloads the image on the first run. The demo itself works offline:
it generates keys, signs and verifies a message, checks a SHA-256 fingerprint,
and encrypts then decrypts another message. Look for:

```text
demo-ok: 8/8 verifications hold
```

That's the complete first run. No clone, compiler, account, PIN setup, or
physical token is needed. Reports and disposable keys remain in `out/demo-*/`.

This checkout prepares **v0.5.0.0**, adding the attribute-sensitivity
model, sealed PQC private seeds, schema-3 stores with a migrate-once
upgrade path, and an installed client portfolio on top of the v0.4.0.0
demo experience. Its registry tag is available only after publication;
the latest published release is v0.4.0.0. v0.5.0.0 is a bounded release: its
[limitations](docs/release-notes-0.5.0.0.md#known-limitations)
are stated up front. The
[hands-on guide](docs/try-it.md) shows how to load a tested candidate,
generate a key with `pkcs11-tool`, and sign your own message.

The demo image includes Haskoki, its runtime and crypto libraries, OpenSC
`pkcs11-tool`, `pkcs11-check`, and `pkcs11-proxy-ng`, plus
p11-kit server/client examples. Extra
test-vector collections are an optional download. The tested platform is
**Linux x86-64 (amd64)**; Docker supplies the Linux libraries. Other platforms
and ARM emulation have not been qualified. Image measurements and contents
are in [Try it](docs/try-it.md#image-contents-and-size).

## Where it came from

Haskoki explores a development idea: describe a token's rules in Haskell,
test that model separately, then let real applications challenge the
compiled module. The aim was easier development with broad, explicit
coverage of PKCS#11 behavior: keys, sessions, errors, and interrupted work.

[pkcs11-check](https://github.com/mingulov/pkcs11-check) supplies the external
checks. [pkcs11-proxy-ng](https://github.com/mingulov/pkcs11-proxy-ng) keeps
Haskell's runtime and shared libraries in a separate process, so a client
can use Haskoki through a PKCS#11 shim. Reusing that transport avoided
building a custom client/daemon protocol alongside the token.

Coding agents helped implement and review the project; tests and consumer
runs supply the behavioral evidence. The [development story](docs/haskoki-creation-story.md)
explains the design, its milestones, and the recorded AI-token usage.

A side note: [p11scope](https://github.com/mingulov/p11scope) can observe
PKCS#11 calls on Linux. It is optional and runs separately; an
[observer note](docs/p11scope-trace.md) explains that route.

## Choose your next step

| I want to... | Start here |
| --- | --- |
| Generate a key and sign something myself | [Hands-on guide](docs/try-it.md#try-pkcs11-tool-yourself) |
| Try the checker or another process | [Checker and remoting](docs/try-it.md) |
| Understand the project and its creation | [Development story](docs/haskoki-creation-story.md) |
| Load it in my own application | [Native reference](docs/demo-walkthrough.md) and [host requirements](SUPPORTED-HOSTS.md) |
| Investigate support or build the project | [Coverage](docs/coverage.md), [results](docs/release-results.md), [developer toolchain](docs/toolchain.md) |

Haskoki exposes PKCS#11 2.40-3.2 interfaces, with 316 behavior-tested
mechanisms out of 464 catalog entries. The v0.5.0.0 candidate image
reports 18 documented findings on the full checker profile (the published
v0.4.0.0 image reports 22); the short smoke profile expects zero. Neither
number establishes conformance or certification. See the [results and
limits](docs/release-results.md) before choosing it for an integration.

[Apache-2.0](LICENSE) | [Report a problem](https://github.com/mingulov/haskoki/issues/new?template=bug_report.md)
