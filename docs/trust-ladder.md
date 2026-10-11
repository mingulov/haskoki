# Evidence levels

Different checks answer different questions. A property test does not
exercise the C ABI; a successful driver does not cover every parameter or
mechanism. Read each result with its source revision and tested scope.

| Level | Check | What it shows |
| --- | --- | --- |
| rung 0 | Static gates, `scripts/check-*.py` | Catalog, generated-file, source-boundary, and documentation consistency; no runtime behavior |
| rung 1 | Deterministic unit suites | The specified core, model, engine, storage, and operator cases pass in-process |
| rung 2 | Generated prop suites, [tests/prop](../tests/prop) | Agreement across the inputs and command sequences produced by the generators |
| rung 3 | Native C driver tests | Actual loading, calls, bytes, errors, and ownership for each driver's scope |
| rung 4 | Direct/proxy parity | Matching transcripts for the forwarded subset; excluded calls remain separate |
| rung 5 | External oracle and consumer checks | Agreement with known-answer vectors or another implementation for the exercised cases |
| rung 6 | Human audit | A source-backed review judgment; it is not an execution result |

The [consumer driver](../scripts/test-consumers.sh),
[parity driver](../scripts/test-proxy-parity.sh), and
[external-checker wrapper](../scripts/ci-pkcs11-lane.sh) make the execution
boundaries explicit. Native tests include canaries, fault injection, aborted
operations, and mismatch controls where those failure paths matter.

[Mechanism coverage](coverage.md) records in-process evidence per catalog
row. [Release results](release-results.md) records measured consumer outcomes.
A non-null function pointer or listed mechanism alone does not establish
conformance, parameter coverage, or successful cryptographic work.

Known-answer tests check bytes; they are not FIPS validation. A successful
checker wrapper can still report findings, because its exit policy accepts
completed runs with documented failures. Inspect the counters and findings,
not just the job badge.
