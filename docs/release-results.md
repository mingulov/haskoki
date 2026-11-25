# Demo results

## Measured baseline

The [November 25 CI run](https://github.com/mingulov/haskoki/actions/runs/45628210649)
passed the demo-image driver on checker 0.3.1 with the v0.6.0.0 candidate
image. These counters come from its reports, recorded in the
[JSON summary](release-results/summary.json). The run tested the PR #44
merge-ref `b25fc8c`, whose tree is byte-identical to the `fdfcb950`
release source. The October 8 baseline (checker 0.2.3 era) is archived in
the summary's `historical_snapshot`.

| Profile | Mode | Collected | Passed | Findings | Skipped | Expected failures | Exit |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Smoke | Direct | 791 | 407 | 0 | 364 | 20 | 0 |
| Smoke | Proxy | 791 | 407 | 0 | 364 | 20 | 0 |
| Full | Direct | 11,466 | 5,756 | 24 | 5,043 | 643 | 1 |
| Full | Proxy | 11,466 | 5,695 | 24 | 5,043 | 704 | 1 |

All four reports record zero runner errors, crashes, and timeouts. Collected
counts include skips and expected failures; they do not count passing tests
or establish how many complete test bodies ran. Pass counts do not measure
feature coverage or conformance.

## What the findings mean

The full profile has **24** findings, all provider-owned value-encoding
gaps (checker 0.3.1, proxy v0.3.1):

| Family | Count | Cause |
| --- | ---: | --- |
| Attribute value encodings | 12 | Provider gap: `CKA_VALUE` reads return DER/textual forms instead of raw bytes (known DER read-back limitation); covers PQC public lengths, EC-family known material, public-value absence, and generated/imported equivalence |
| Protected-component size/read | 8 | Provider gap: unsealed import reads report impossible lengths (size/bytes encoding mismatch, same DER family) |
| BLAKE2 generic-secret message | 4 | Provider gap: output mismatch specific to the generic-secret import path; sibling keyed-BLAKE2 tests pass |

The 0.2.3-era checker-side families are gone with checker 0.3.1: the
async-ctypes binding failures and the X9.42 `CKA_DERIVE` default
assumption ([pkcs11-check#62](https://github.com/mingulov/pkcs11-check/issues/62))
no longer appear, and the sixteen BLAKE2B key-type cases were replaced
by the checker's new message-interface coverage, which exposes the four
genuine import-path gaps above. The DES-parity family (21 cases) was
fixed provider-side by the FIPS 46-3 odd-parity adjustment and retired
from the ledger.

The set is shared by direct and proxy modes, with no proxy-only findings in
this baseline. [Qualification notes](pkcs11-oracle-triage.md) explain the
inputs and attribution. Findings remain visible as failed outcomes.

On the v0.6.0.0 candidate image the comparison accepts only **65 frozen
exclusions in six reason families** (A-msg-init-0x71: 34, B-blowfish: 20,
C-tls12: 2, D-wtls: 3, E-boundary: 2, F-collection: 4) and **24 shared
findings**, with zero allowed variance (the v0.5.0.0 image's classifier
accepted 61 and 21). The
[per-case exclusions](../examples/release/compare-classify/frozen-subset.tsv)
and [shared finding IDs](../examples/release/compare-classify/frozen-shared.txt)
are checked by [the demo driver](../scripts/test-demo-image.sh). These are
checker comparison sets; native consumer transport exclusions are maintained
separately by [the parity driver](../scripts/test-proxy-parity.sh).

## Client journeys

OpenSC `pkcs11-tool`, GnuTLS, Java (SunPKCS11) and OpenSSL pass **61 of
61** legs against the installed 0.6.0.0 bundle and **28 of 28** in the
candidate demo image, recorded in
[client-journeys.json](release-results/client-journeys.json). Both runs
were replayed locally from the November 25 CI artifacts
(`release-bundle` artifact 15031955815, re-tared to the harness layout
with identical inner bytes; `demo-image-tested` artifact 15037407080,
image `0074ddc8…f54dd`) with the legs.json-pinned clients in
`ubuntu:26.04`, following the qualification recipe; both carry module
`68d81bb6…f975` and pass the driver's own `--check`.

## Run and interpret the checks

[Try Haskoki](try-it.md) gives the image setup and commands. The image pins
`pkcs11-check` 0.3.1 and `pkcs11-proxy-ng` v0.3.1. Smoke/full select offline
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
27-finding and 11,003-collected figures, plus the October 8 baseline lanes.
The [vector snapshot](release-results/environment.json)
records the dated corpus pins and download sizes. The November 25 KAT run
(checker 0.3.1, same CI run as the baseline above) fetched and ran four
corpora: wycheproof `65ca494727a5`, cctv `b88c4b206254`, acvp
`975de31eb83d`, and x509-limbo `519f4bcf6a31`.
