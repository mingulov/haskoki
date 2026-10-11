# The recorded AI usage

Haskoki was developed with coding agents doing implementation, planning,
review, retries, and verification. The recorded calls from **September 20
through October 8, 2026**, using calendar boundaries in UTC+03:00, account
for **13,236,263,984 input-plus-output tokens: about 13.24 billion**.
This refresh replaces the earlier partial 7.84B census. It excludes
October 9 publication work and the later v0.3.1.0 improvements.

A token is a small chunk of text processed by a model. Most of the input
here was a cached reread of context during long sessions. A large token
count does not mean a comparably large amount of code was written.

| Measurement | Recorded amount |
| --- | ---: |
| Input, including cached input | 13,197,404,891 |
| Input served from cache | 12,924,865,479 (97.9%) |
| Input not served from cache | 272,539,412 |
| Output, including reasoning | 38,859,093 |
| Input plus output | 13,236,263,984 |
| Individual model calls | 67,458 |

Cached input is part of input, and reasoning is part of output. Adding
those fields again would double-count them. The [JSON snapshot](development-metrics.json)
retains exact counts and the model breakdown.

## Models in the development count

| Model | Harness | Calls | Input plus output |
| --- | --- | ---: | ---: |
| `muse-spark-1.3-contributor` | Muse Code | 63,410 | 12.77B |
| `gpt-6-astra` | Codex | 1,367 | 162.73M |
| `gpt-6-sol` | Codex | 92 | 7.75M |
| `gpt-6.1-sol` | Codex | 2,589 | 293.05M |

These are recorded model identifiers. The sessions mixed several kinds
of work; a model name does not establish an exclusive implementer or
reviewer role.

## Where the usage went

The table below groups Muse Code calls by the development stages in the
[timeline](haskoki-creation-story-timeline.md). Boundaries are approximate
milestone boundaries; this is an account of recorded activity, not a
measure of how expensive a particular feature was. Codex calls are
reported separately because they mixed planning, implementation, and
review across those stages.

| Stage | Input plus output |
| --- | ---: |
| First module and loader | 307.50M |
| Behavior model, clients, and packaging | 2.64B |
| Repository import and checker triage | 1.56B |
| Ciphers, curves, and post-quantum work | 1.33B |
| Mechanism coverage sweep | 3.00B |
| Proxy differences and warning cleanup | 76.67M |
| Message operations and async routing | 362.20M |
| Notifications and callbacks | 328.47M |
| Certificate objects | 817.91M |
| Mechanism routes and native-boundary review | 706.31M |
| Release preparation and proxy qualification | 1.00B |
| Security fixes, CI, and packaging | 638.36M |
| Muse Code subtotal | 12.77B |
| Codex calls across these stages | 463.54M |
| All recorded calls | 13.24B |

## Latest Codex snapshot

A separate workspace-filtered `agent-stats.py` report collected on
October 11, 2026 records **582,639,404 input-plus-output tokens** across
**5,056 Codex calls**, including later release and demo work:

| Model | Calls | Input plus output |
| --- | ---: | ---: |
| `gpt-6-astra` | 2,030 | 244.45M |
| `gpt-6-sol` | 92 | 7.75M |
| `gpt-6.1-sol` | 2,934 | 330.43M |

Input is 577,398,355 tokens, including 541,271,680
cached tokens (93.7%); output is 5,241,049.
This is a later snapshot of Codex usage. It overlaps the historical
Codex subtotal above and must not be added to the 13.24B figure.
The JSON records the collection time and exact per-model fields.

## How it was counted

Sessions count when their recorded workspace is the Haskoki workspace or
a descendant. Both root and child-session logs are included. Calls are
filtered by their own timestamps, even when a session spans several days,
and deduplicated by their model-response or record IDs. Milestone windows
are consecutive, with an inclusive start and exclusive end, so no minute
or boundary gap disappears from the sum.

Totals come from individual usage records. Cumulative session counters and
workflow-child summaries are not added on top of per-call records. The
snapshot describes this scope; records available only as summaries are
outside this count. Private prompts and session paths are not published.

There is no verified spending or personal-hour figure. Model usage alone
does not establish a bill, and parallel agent sessions overlap in time.
This account documents the work behind the [creation story](haskoki-creation-story.md);
the [test results](release-results.md) describe what the software actually
demonstrated.
