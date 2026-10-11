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

Use the report attached to the revision you are reviewing. Low expression
coverage can include derived instances and unused selectors; inspect the
annotated branches and actual test inputs before proposing another property.
