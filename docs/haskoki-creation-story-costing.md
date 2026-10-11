# The recorded AI usage

Coding agents helped build Haskoki, including planning, implementation,
review, retries, and verification. From **September 20 through October 8,
2026**, the recorded development calls used **13.24 billion tokens**.
A token is a small chunk of text processed by a model; most input here was
cached context read again during long sessions.

| Development measurement | Amount |
| --- | ---: |
| Input, including cached input | 13,197,404,891 |
| Input served from cache | 12,924,865,479 (97.9%) |
| Input not served from cache | 272,539,412 |
| Output, including reasoning | 38,859,093 |
| Input plus output | 13,236,263,984 |
| Model calls | 67,458 |

## Models and later work

The development columns cover September 20-October 8 in UTC+03:00.
The later columns contain **additional Codex usage after October 8**,
counted on October 11 at 13:04 UTC. These periods do not overlap.

| Model | Development calls | Development tokens | Later Codex calls | Later Codex tokens |
| --- | ---: | ---: | ---: | ---: |
| `muse-spark-1.3-contributor` (Muse Code) | 63,410 | 12.77B | - | - |
| `gpt-6-astra` (Codex) | 1,367 | 162.73M | 663 | 81.72M |
| `gpt-6-sol` (Codex) | 92 | 7.75M | 0 | 0 |
| `gpt-6.1-sol` (Codex) | 2,589 | 293.05M | 345 | 37.38M |

Codex accounts for **463.54M** tokens in the development period and
**119.10M** in 1,008 later calls: **582,639,404 tokens across 5,056 calls**
by the October 11 count. That cumulative Codex amount includes
577,398,355 input tokens (541,271,680 cached) and 5,241,049 output tokens.
Later Muse usage is not included in this snapshot.

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
