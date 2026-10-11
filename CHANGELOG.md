# Changelog

## [0.3.1.0] - Unreleased

- Shorter onboarding, a clearer development story, and dated model-usage
  statistics.
- The Docker demo runs without an output mount; `shell` prepares a token
  and the client tools for hands-on experiments.
- `proxy-demo` runs the direct/proxy example. `p11-kit-demo` adds a local
  server/client example with signing, verification, digest, tamper, and
  disconnected-server checks.
- GitHub tests the new beginner commands on the same saved image as the
  full checker and comparison jobs. Image builds record their size.
- Public references describe current behavior and link to reproducible
  tests instead of embedded campaign logs.

## [0.3.0.0] - 2026-10-09

First public release: a native Linux x86-64 bundle, verified source
archive, test reports, checksums, release manifest, and Docker demo image.
See the [release notes](docs/release-notes-0.3.0.0.md) and
[measured results](docs/release-results.md).

The release exposes PKCS#11 2.40, 3.0, 3.1, and 3.2 layouts. The mechanism
catalog has 464 entries, of which 316 have behavior tests and are served
through the C surface. Unsupported operations retain explicit refusals.

Development leading to this release included:

- Sessions, token-scoped login and object visibility, PIN lockout, key
  generation, signing, encryption, wrapping, derivation, and random bytes.
  `C_SeedRandom` uses engine-specific seed semantics; caller bytes are not
  credited as entropy on the OpenSSL path.
- Real OpenSSL crypto and a separate synthetic engine for controlled model
  tests, with broader cipher, curve, and post-quantum coverage.
- Streamed multipart digests and framed block-cipher updates. Digest
  resources release through the three `publishCommit` funnels plus the
  `Runtime`/`Async` drains, including aborted and rejected operations
  ([consumer tests](tests/c/consumer_streaming.c)).
- PKCS#11 message routing, Digest-only public 3.2 async work, detached
  SQLite recovery, slot notifications, and synchronous Digest callbacks.
- Multiple configured tokens, certificate objects, single-writer SQLite
  persistence, bounded job retention, and explicit storage-failure handling.
- Native client and direct/proxy tests, external-checker triage, coverage
  publication, relocatable runtime packaging, and GitHub release checks.

## Earlier development

These were development milestones, before the first public release:

- **September 20, 2026:** first C-loadable Haskell module, function-table
  layouts, and a small SHA-256 path.
- **September 21-23:** behavior model, sessions and objects, client tests,
  and native packaging.
- **September 24:** [public repository import](https://github.com/mingulov/haskoki/commit/2cd3f37).
- **September 25-October 8:** expanded crypto coverage, newer interfaces,
  notifications and certificates, followed by demo and release preparation.

The [creation story](docs/haskoki-creation-story.md) and
[timeline](docs/haskoki-creation-story-timeline.md) explain how these pieces
fit together.
