# How Haskoki developed

Haskoki began with a small question: could a token's rules be described in
Haskell and exercised by the same C applications that use a smart card or
hardware security module? The first useful result was a shared library that
a client could load. Adding cryptographic algorithms was only part of the
work; clients also needed predictable sessions, key visibility, errors,
and behavior when operations stop halfway through.

The [changelog](../CHANGELOG.md) records the scaffold on September 20, 2026.
The [public repository](https://github.com/mingulov/haskoki/commit/2cd3f37)
starts with an import on September 24. The first public release,
[v0.3.0.0](https://github.com/mingulov/haskoki/releases/tag/v0.3.0.0),
was published on October 9. That is a calendar timeline, not a measurement
of anyone's working hours.

## Why Haskell?

Haskell is a functional programming language. Here its useful idea is to
separate a decision from the work needed to carry it out. For example, the
model can decide whether a session may sign and which state should follow;
the runtime then asks OpenSSL to perform the signature.

This makes many protocol rules testable using ordinary values, without
loading a native client. Different types help keep session handles, object
handles, and requests distinct. The compiler can catch some mismatches,
but native resource lifetimes, concurrency, and cryptographic behavior
still need tests. The [design note](haskell-design.md) gives a short
code-oriented explanation. Users of the demo need not read Haskell.

## What made it better

[pkcs11-check](https://github.com/mingulov/pkcs11-check) loads the compiled
module as an external client. Its findings drove work on templates, errors,
and capability claims. For example, review withdrew an incorrectly
advertised AES-GCM message capability. The full demo-checker finding set
fell from 27 to 22; the remaining findings are still [documented](release-results.md).

[pkcs11-proxy-ng](https://github.com/mingulov/pkcs11-proxy-ng) added another
question: would the same application behave the same way with Haskoki in a
separate process? Earlier proxy tests exposed failures missed by direct
loading. The demo pins the qualified v0.2.2 version and records differences
explicitly. Both projects share an author with Haskoki, so this is useful
consumer evidence rather than an independent audit.

[p11scope](https://github.com/mingulov/p11scope) adds optional observation
of calls on Linux. The [recorded trace](p11scope-trace.md) is a small example,
not a requirement for trying the token.

Coding agents helped write and review the implementation. Haskell tests,
real C clients, external checks, and review passes caught different classes
of mistake. Packaging then became part of the work: a demonstrator is only
useful to someone else if they can run it and understand the result.

## How many AI tokens?

The committed [usage snapshot](development-metrics.json) covers recorded
Haskoki workspace sessions **through October 6, 2026 at 04:18 UTC**:

| Measurement | Recorded amount |
| --- | ---: |
| Input tokens, including cached input | 7,826,511,262 |
| Of that input, reread from cache | 7,678,241,620 (98.1%) |
| Input not served from cache | 148,269,642 |
| Output tokens, including reasoning | 17,962,666 |
| Input plus output | 7,844,473,928 (about 7.84 billion) |

A token is a small chunk of text processed by a model. These large input
numbers mostly reflect repeated reading of context during long sessions;
they are not billions of tokens of source code. Cached input is already
inside the input figure, and reasoning is already inside output: adding
either again would double-count it. The snapshot covers implementation,
reviews, retries, and packaging, using its recorded workspace attribution
and deduplication rules.

This is a dated checkpoint, **not the complete cost of the released
project**: it excludes later release work and this patch. No personal-hour
or actual-spending figure is established. Session durations overlap when
agents run concurrently, and token counts alone do not establish a bill.
The JSON retains the model breakdown and counting method for readers who
want to inspect them.

Start with the [demo](../README.md#try-it-with-docker). Feedback such as
“this command failed” or “I could not tell where my key went” directly
helps improve the next version.
