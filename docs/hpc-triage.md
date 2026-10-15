# Haskell test coverage

Haskell Program Coverage (HPC) records which instrumented Haskell expressions
and branches the tests exercise. It is separate from the
[PKCS#11 mechanism inventory](coverage.md), and does not measure C or
OpenSSL coverage or establish conformance.

## Get a report from GitHub

Open a successful [Haskell coverage run](https://github.com/mingulov/haskoki/actions/workflows/hpc.yml)
and download `hpc-coverage`. It includes text summaries and annotated HTML
for the `haskoki-core` and `haskoki` libraries. Open
`html-core/hpc_index.html` or `html-main/hpc_index.html` after extracting.
The workflow also uploads `hpc-test-log` so the suite verdict remains visible.
Coverage percentages are informational; the workflow has no percentage floor.

## Reproduce the measurement

In the [developer environment](toolchain.md), use a checkout with the pinned
GHC and OpenSSL prefix. From the repository root:

```sh
cabal build all --enable-tests --enable-coverage
cabal test --enable-coverage all
```

The coverage-enabled build must precede the test invocation. To combine the
results and generate HTML, follow the **Per-library reports + HTML** step in
[the workflow](../.github/workflows/hpc.yml); it is the maintained recipe.
Its important choices are:

- Sum the suite `.tix` files with `hpc sum --union`. The default intersection
  keeps only modules touched by every suite.
- Discover `.mix` files under library `extra-compilation-artifacts`, excluding
  suite runners and test helpers. Pass their `mix/` parent to `--hpcdir`.
- Derive the two library unit IDs and use `--include=<unitid>:` with the
  trailing colon to select the whole library.
- Exclude `Haskoki.PKCS11` and the generated `Paths_haskoki` module in the
  per-library report and markup commands.

## Module reconciliation

After the reports, the workflow checks that every module compiled in the
two libraries appears in a report
(`scripts/check-test-execution.py --check-hpc`, output
`hpc/module-reconciliation.json` in the `hpc-coverage` bundle). A compiled
module that no report shows is handled in one of three ways:

- **Excluded**: [`tests/hpc-exclusions.json`](../tests/hpc-exclusions.json)
  lists it with a class (`deprecated-stub`, `zero-tick-reexport` or
  `unlinked`), a reason and a review date. Today that is only
  `Haskoki.PKCS11`.
- **Classified**: its `.mix` file has no ticks, so there is nothing to
  cover. Pure re-export modules such as `Haskoki` and `Haskoki.Runtime`
  land here, under `classified` with class `zero-tick-reexport`.
- **Gap**: anything else, including a `.mix` the checker cannot parse.

An exclusion whose module shows up in a report again, or is no longer
compiled, is a stale-exclusion gap. Any gap fails the workflow; coverage
percentages stay informational.

Scope: the reconciled modules are those of `haskoki-core` and the main
`haskoki` library. The separate `haskoki-client` package (`client/`) is
not reconciled module by module, because the workflow writes no report
for it; its test suite still has to produce a `.tix` file like every
other suite.

Use the report attached to the revision you are reviewing. Low expression
coverage can include derived instances and unused selectors; inspect the
annotated branches and actual test inputs before proposing another property.
