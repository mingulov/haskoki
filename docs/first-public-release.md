# How Haskoki developed

Haskoki explores whether a Haskell model can make PKCS#11 behavior easier
to inspect, test, and exercise through ordinary C clients. OpenSSL supplies
the cryptographic operations. Haskell describes protocol state, decisions,
and the work needed to carry them out.

The public Git history starts with an import on 2026-09-24, already
containing a working model and shared-library skeleton. The changelog
also records earlier scaffold work. Those dates describe repository
activity, not the author's working hours or the start of the idea.

## From a loadable module to a usable demo

| Period | What changed | Public record |
| --- | --- | --- |
| September 24-25 | The imported token met external consumers. Work addressed key import, error codes, templates, and session behavior. | [Initial import](https://github.com/mingulov/haskoki/commit/2cd3f37) and [oracle triage](pkcs11-oracle-triage.md) |
| September 25-30 | Cipher modes, curves, post-quantum operations, MACs, and derivation expanded the mechanism catalog. Coverage reached 316 behavior-tested rows out of 464. | [Coverage inventory](coverage.md) and [changelog](../CHANGELOG.md) |
| September 30-October 3 | Message calls, async completion, slot notifications, and certificate objects gained native routing and lifecycle tests. | [Operation contracts](operations-notes.md) and [byte formats](byte-formats.md) |
| October 4-6 | A relocatable bundle, source package, demo container, checker profiles, and proxy comparison made the project easier to try. | [Packaging work](https://github.com/mingulov/haskoki/commit/a338ace) and [demo image](https://github.com/mingulov/haskoki/commit/5592088) |
| October 7-8 | Review fixes tightened native boundaries and packaging checks; CI build, ownership, and timeout problems were corrected. | [Hardening changes](https://github.com/mingulov/haskoki/commit/29dab82) and [passing CI at 0603322](https://github.com/mingulov/haskoki/actions/runs/37774745195) |

This produced a release candidate. As of 2026-10-09, the repository has
no published release tag or downloadable GitHub release, and anonymous
access to the proposed GHCR image is denied. Building and testing release
artifacts is separate from publishing them.

## What the tests taught us

Tests changed the implementation and its claims. Incorrectly advertised
AES-GCM message capabilities were withdrawn, and the frozen full-checker
finding set fell from 27 to 22. The remaining findings are still disclosed;
a smaller number is not proof of complete support. See the
[capability change](https://github.com/mingulov/haskoki/commit/29dab82)
and [updated checker expectations](https://github.com/mingulov/haskoki/commit/f707095).

Proxy testing exposed problems that direct calls did not. An earlier proxy
version was rejected after daemon failures. The qualified v0.2.2 pin improved
the compared subset, while known differences and skipped cases remained
explicit. The [results record](release-results.md) keeps the earlier
measurements alongside current CI results.

Some failures came from the test setup itself: container ownership,
missing vector caches, assumptions about DH output width, and a proxy test
timeout. Those fixes matter to reproducibility, but they do not add token
features. The [October 8 history](https://github.com/mingulov/haskoki/commits/0603322)
shows that distinction.

## Haskell and the development process

The useful Haskell idea is the separation of protocol rules from effects.
The pure model can be tested with ordinary values; the runtime still has
to manage native resources, concurrency, storage, and the C ABI. The
[Haskell design note](haskell-design.md) explains what this buys and where
the boundary ends.

Development used coding agents, review passes, native consumers, and
external checkers. These are complementary sources of evidence. Agent
review is not an independent security audit, and Haskoki and pkcs11-check
share an author. The [trust ladder](trust-ladder.md) separates model tests,
native execution, comparisons, and review judgments.

A [historical usage snapshot](development-metrics.json) covers workspace
sessions only through October 6. It is not a final project cost: cached
context dominates its input counts, parallel sessions cannot be added
into elapsed working hours, and no actual spending or personal-time
figure is established. Those figures are omitted rather than guessed.

To try the result, start with the [small demo](try-it.md). Feedback about
loading the module in another consumer, reproducing a report, or a needed
PKCS#11 behavior is more useful than a general pass/fail label.
