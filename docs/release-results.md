# Demo results

## Measured baseline

The [October 8 CI run](https://github.com/mingulov/haskoki/actions/runs/37774745195)
for source `0603322` passed the demo-image driver. These counters come from
its reports, recorded in the [JSON summary](release-results/summary.json).
The subsequent [v0.3.0.0 release](release-notes-0.3.0.0.md) was published on
October 9. The published v0.3.1.0 evidence keeps the same frozen
full-finding set: its release compare record reports shared 22/22
exact with zero unexpected differences
(`test-results-0.3.1.0.tar.gz` member
`test-results-0.3.1.0/demo/compare/compare-*/classification.txt`).

| Profile | Mode | Collected | Passed | Findings | Skipped | Expected failures | Exit |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Smoke | Direct | 743 | 373 | 0 | 364 | 6 | 0 |
| Smoke | Proxy | 743 | 374 | 0 | 364 | 5 | 0 |
| Full | Direct | 10,993 | 5,060 | 22 | 4,963 | 948 | 1 |
| Full | Proxy | 10,993 | 5,021 | 22 | 4,963 | 987 | 1 |

All four reports record zero runner errors, crashes, and timeouts. Collected
counts include skips and expected failures; they do not count passing tests
or establish how many complete test bodies ran. Pass counts do not measure
feature coverage or conformance.

## What the 22 findings mean

| Family | Count | Cause |
| --- | ---: | --- |
| GMAC message shape | 2 | Provider message-init parameter limitation |
| HOTP parameters | 2 | Checker probes omit the provider's required parameters |
| BLAKE2B key type | 16 | Provider key-type matrix gap in negative tests |
| Async child results | 2 | Checker ctypes binding problem before the module call |

The set is shared by direct and proxy modes, with no proxy-only findings in
this baseline. [Qualification notes](pkcs11-oracle-triage.md) explain the
inputs and attribution. Findings remain visible as failed outcomes.

The comparison accepts only **83 frozen exclusions in six reason families**
and **22 shared findings**, with zero allowed variance. The
[per-case exclusions](../examples/release/compare-classify/frozen-subset.tsv)
and [shared finding IDs](../examples/release/compare-classify/frozen-shared.txt)
are checked by [the demo driver](../scripts/test-demo-image.sh). These are
checker comparison sets; native consumer transport exclusions are maintained
separately by [the parity driver](../scripts/test-proxy-parity.sh).

## Run and interpret the checks

[Try Haskoki](try-it.md) gives the image setup and commands. The image pins
`pkcs11-check` 0.2.3 and `pkcs11-proxy-ng` v0.2.2. Smoke/full select offline
cases, excluding vector corpora, stress, fuzz, and slow tests. Timeouts are
180 seconds per direct case and 360 per proxy case. `doctor` must pass first.

- The short demo expects `demo-ok: 8/8 verifications hold` and exit 0.
- Smoke expects zero findings and exit 0 in either mode.
- Full and raw `compare` intentionally exit 1 for the documented findings.
- The comparison classifier expects the frozen sets and exits 0.
- Setup or argument trouble exits 2 from the image entrypoint.

Mounted output contains the raw checker counters, per-case outcomes, logs,
and command reports. Keep those files together when investigating a failure.
For scale, earlier measurements took roughly 17 minutes direct/full,
20 minutes proxy/full, and 47 minutes for comparison; durations depend on
the machine. Run one checker command at a time in each container.

The [GitHub workflow](publishing.md) builds one candidate image and tests
contracts, full profiles, and comparison against the same saved bytes.
Its fast/vector framework jobs use a different checker pin and selection;
keep their counters separate from this table.

## Vector-data runs

The image includes everything needed for its normal demo and offline
profiles. Larger vector collections are optional and require network access
to download. Use a directory dedicated to these downloads: the fetcher
replaces each per-source subdirectory.

```sh
# HASKOKI_IMAGE is selected in Try Haskoki.
mkdir -p vectors
docker run --rm --user "$(id -u):$(id -g)" \
  --entrypoint /opt/p11c/bin/pkcs11-check \
  -v "$PWD/vectors:/data" "$HASKOKI_IMAGE" fetch-data all --data-dir /data
```

Allow about 1 GB for the previously measured collection; its size may change.
Check the fetch verdict and `versions.json`. The image entrypoint exposes
only smoke/full profiles; vector tests use the checker directly or the
native [fast/KAT recipe](pkcs11-oracle-triage.md#reproduce-a-checker-run).
GitHub's KAT job downloads and runs its selected corpora.

For a direct checker invocation, mount the data read-only and set
`PKCS11_CHECK_DATA_DIR=/data`; `test` has no `--data-dir` option. Require the
selected corpus, its expected pin and files, and meaningful collection.
An earlier CCTV measurement collected 1,365 cases with data but only four
without it; both exited 0. An exit code alone cannot establish vector coverage.

Earlier measured counters are retained in the summary's `historical_snapshot`
with their older
27-finding and 11,003-collected figures. The [vector snapshot](release-results/environment.json)
records the dated corpus pins and download sizes.
