# The recorded AI usage

Coding agents helped build Haskoki, including planning, implementation,
review, retries, and verification. From **September 20 through October 8,
2026**, the recorded development calls used **13.24 billion tokens**.
A token is a small chunk of text processed by a model; most input here was
cached context read again during long sessions.

Through **October 18, 2026, 13:30 (UTC+03:00)**, all recorded harnesses
used **19.88 billion tokens** across **106,849 calls**.

| Development measurement | Amount |
| --- | ---: |
| Input, including cached input | 13,197,404,891 |
| Input served from cache | 12,924,865,479 (97.9%) |
| Input not served from cache | 272,539,412 |
| Output, including reasoning | 38,859,093 |
| Input plus output | 13,236,263,984 |
| Model calls | 67,458 |

## Cumulative usage and later work

The cumulative columns cover September 20 through October 18, 13:30 in
UTC+03:00. The phase table splits the same calls into the development
window and three later phases; the phases add up to the cumulative row.

| Cumulative measurement | Amount |
| --- | ---: |
| Input, including cached input | 19,810,627,132 |
| Input served from cache | 19,361,774,699 (97.7%) |
| Input not served from cache | 448,852,433 |
| Output, including reasoning | 66,621,804 |
| Input plus output | 19,877,248,936 |
| Model calls | 106,849 |

| Phase | Muse Code calls / tokens | Codex calls / tokens | Claude calls / tokens | Phase tokens |
| --- | ---: | ---: | ---: | ---: |
| Development (Sep 20-Oct 8) | 63,410 / 12.77B | 4,048 / 463.54M | - | 13.24B |
| Publication and public docs (Oct 9-12) | 94 / 13.35M | 1,643 / 191.32M | - | 204.67M |
| v0.4.0.0 (Oct 12-15) | 1,633 / 392.84M | 4,042 / 404.57M | 2,415 / 367.89M | 1.17B |
| v0.5.0.0 preparation (Oct 15-18) | 18,701 / 3.39B | - | 10,863 / 1.88B | 5.27B |

| Model | Calls | Tokens (input plus output) |
| --- | ---: | ---: |
| `muse-spark-1.3-contributor` (Muse Code) | 83,838 | 16.57B |
| `gpt-6-astra` (Codex) | 2,825 | 324.71M |
| `gpt-6-sol` (Codex) | 92 | 7.75M |
| `gpt-6.1-sol` (Codex) | 6,563 | 696.73M |
| Other Codex models | 253 | 30.24M |
| `claude-opus-5-5` (Claude) | 10,953 | 2.03B |
| `claude-sonnet-5-5` (Claude) | 2,308 | 212.42M |

Muse Code did implementation work in every phase; Codex models planned
and reviewed the earlier work; Claude took over orchestration and review
in the v0.4.0.0 and v0.5.0.0 phases, with Opus handling orchestration
and critical reviews and Sonnet ordinary reviews.

Claude input here means raw input plus cache reads and cache writes, so
input including cached input means the same for every harness.
Seventeen further Claude records are client-side rate-limit placeholders
with zero usage; they count as calls with zero tokens.

## Development stages

These approximate milestones group Muse Code usage. Codex's 463.54M
development tokens span several stages and are counted separately.

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
| Codex development calls | 463.54M |
| Development total | 13.24B |

Counts include individual calls from project sessions and their child
agents, with duplicate records removed. Cached input is already part of
input; reasoning is already part of output. Neither is added twice.
The [JSON snapshot](development-metrics.json) contains exact counts and
date boundaries.

These figures describe model usage, not code volume, money spent, or
personal working hours. Read the [story](haskoki-creation-story.md) and
[timeline](haskoki-creation-story-timeline.md) for the development itself.
