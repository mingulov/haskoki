# First public release (draft — awaiting owner data)

> Status: working draft. Fields marked [OWNER] need the author's
> input and must be resolved before publication; this draft must
> not be published as-is.

## What this is

Haskoki 0.3.0.0 is a Haskell PKCS#11 soft token (demonstrator)
covering APIs 2.40, 3.0, 3.1 and 3.2: real in-process crypto over
OpenSSL with honest refusals for the genuinely unsupported
calls. It ships as a loadable `libhaskoki.so` with byte-pinned
versioned tables, a 316-row behavior-tested mechanism catalog
(of 464 catalog rows), and a container image that runs crypto
demos plus an external checker against the module. It is not a
certified HSM and makes no production-security claim. Start at
the [README](../README.md); numbers live in
[release-results](release-results.md).

## Why it exists

[OWNER: confirm in one line.] The working statement, matching
the repo's own scope line: Haskoki is a PKCS#11 demonstrator, a
behavior model, and a development experiment — built to show
what a small, honestly-bounded software token looks like, not a
commercial HSM.

## Why Haskell, and what the design actually is

Haskell was the author's choice [OWNER: add motives only if you
want them stated; the draft does not retrofit any]. The
properties below are facts about the tree, not motives:

- A pure core (types, rules, registry, transition, session,
  object, operation) behind a throwing/absorbing FFI boundary,
  with `TVar` state in the host process and SQLite as the only
  persistence.
- Real crypto through a pinned OpenSSL 4.0.2 libcrypto; the
  synthetic engine exists for deterministic tests and never
  serves production bytes.
- Honest refusal as a design rule: unsupported calls fail with
  documented codes (`CKR_MECHANISM_INVALID`,
  `CKR_FUNCTION_NOT_SUPPORTED`), never silent mis-execution.

## How development was organized

Work ran as short subagent-driven tasks with a reviewer per
task: implementers built slices (message routing, async,
notifications, certificates, release packaging R0–R6; this
draft is R7, release staging R8 follows), and an independent
review pass verified each task's claims against executed
evidence before commit. The author owned scope,
architecture decisions, review direction, triage, and
testing/publishing [OWNER: confirm this list].

The calendar span from the first commit (`2cd3f37`, 2026-09-24)
to the R6 cutoff (`d34f31a`, 2026-10-06) is 12 days, 194
commits. First commits are evidence of activity, not proof of
when thinking started.

## Checks the result survived

- Byte-pinned C tables and ABI inventory, enforced by
  generation/validation gates — not by inspection.
- Native consumer suites over real sessions (discovery,
  round-trips, streaming multipart to 20 MiB, message routing,
  async, notifications, multi-token), plus model/property
  suites in Haskell.
- An external checker (`pkcs11-check`, same author — useful
  evidence, not an independent audit): 743 smoke tests clean,
  11003 full tests with 27 direct / 25 proxied triaged
  findings, zero proxy-only.
- A frozen direct-vs-proxy parity subset (188 exclusions, zero
  allowed variance) and a qualified proxy pin after rejecting a
  newer one for a daemon death.

## Things that needed fixing

Nothing here worked first try. Three examples with receipts:

- The parity lane started at 19 failures; daemon-side config,
  operation collapsing, and NULL-salt pinning brought it to 49
  holds / 40 quarantined skips (commit `e8aba24`; the Update
  (R5) bullet in [release-results](release-results.md)).
- Proxy v0.2.1 was rejected (daemon death on message-init,
  [upstream #37](https://github.com/mingulov/pkcs11-proxy-ng/issues/37));
  v0.2.0 shipped with three filed upstream defects
  ([#35](https://github.com/mingulov/pkcs11-proxy-ng/issues/35),
  [#36](https://github.com/mingulov/pkcs11-proxy-ng/issues/36),
  [#39](https://github.com/mingulov/pkcs11-proxy-ng/issues/39)).
- Public docs went through four review rounds: stale outputs,
  unsourced figures, and a sticky-lockout misstatement were all
  caught by the reviewer and fixed with executed proofs
  (commit `d34f31a`, approved with zero findings after 4 fix
  rounds).

## Time and tokens (confirmed)

- Author personal time: [OWNER: your own estimate, labeled as
  estimate — e.g. "~N hours over the 12 days". Never derived
  from git timestamps.]
- Agent usage (Haskoki workspace sessions only, cutoff
  2026-10-06T04:18:48Z at `d34f31a`; full per-model rows in
  [development-metrics.json](development-metrics.json)):
  105 root sessions, 34,991 calls (+58 child-usage summaries
  without per-call counts), 7.83B input tokens (7.68B cached),
  18.0M output tokens. Method: a session counts iff its
  recorded working directory is the Haskoki workspace (root or
  descendant); usage comes from per-call records (codex
  per-response usage, muse model-completed events),
  deduplicated by record id with a per-record cutoff filter;
  the reported subsets are codex `cached_input_tokens` /
  `reasoning_output_tokens` and muse `cached_tokens` /
  `reasoning_tokens`, each verified ⊆ its total and never
  added again; one bound ops session with no Haskoki work
  product is excluded; all recorded pre-cutoff calls count
  regardless of outcome (failures, retries, reviews,
  packaging). The big cached-input share is repeated context
  re-reads across long agentic sessions, not written code
  volume. Models actually used: Muse
  `muse-spark-1.3-contributor` (implementation driver) and
  codex `gpt-6-astra`, `gpt-6.1-sol` (implementation workers,
  planners, and all 20 review sessions). No wall-hour total is
  reported: parallel sessions cannot be summed as hours.
- Money: [OWNER: actual spend and/or subscription if you want
  any. No API-equivalent estimate is given: there is no
  verified tariff for these model IDs/modes, and usage × a
  foreign tariff would not be an amount actually paid.]

## Limitations (current release, not a roadmap)

- Demonstrator scope: no certification, no production-security
  claim; the proxy example is TEST-ONLY transport (loopback,
  no auth/TLS).
- 316 of 464 catalog mechanisms behavior-covered; the rest
  refuse honestly. Vector corpora (KAT/Wycheproof/ACVP) ship
  unfetched behind a separate opt-in recipe.
- Linux x86-64, glibc ≥ 2.43 (container image carries its own
  userland). Full list:
  [SUPPORTED-HOSTS](../SUPPORTED-HOSTS.md).

## Try it

Prerequisites (verified on the release-candidate tree,
`release/first-public` at `d34f31a`): the repo checked out at
that tree with the base and demo images built per the
[container Quick
Start](../README.md#quick-start-container-no-haskell-build).
The candidate branch is not yet published and no public image
exists yet — both stay pending until verified after release.
Then the single launch command:

```sh
docker run --rm --network none -v "$PWD/out:/out" haskoki-demo:0.3.0.0 demo
# demo-ok: 8/8 verifications hold
```

The Quick Start link above carries the full steps (base build,
external check, bundle build, troubleshooting).

## Feedback ask

If you try it, the author wants to know: did the module load in
your consumer? Did the demo/checker example reproduce? Which
consumer or PKCS#11 profile matters to you, and which behavior
differs from what you expected? File issues with the
[bug template](../.github/ISSUE_TEMPLATE/bug_report.md) (no
PINs, keys, or real token databases, please).
