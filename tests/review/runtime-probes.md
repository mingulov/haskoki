# Runtime review probes

Baseline: `e9c5162fff7b2649a47c7b736506b84353bb7718`. These diagnostics exercise existing Haskell Store interfaces without changing production behavior. Local source inspection and whitespace checks are the only local validation; compilation and execution must occur on GitHub. No runtime result is claimed by this file.

Run the four sequential cases:

```sh
cabal test haskoki-review-probes --test-show-details=direct
```

For a backend-specific receipt:

```sh
cabal test haskoki-review-probes --test-show-details=direct --test-options=memory
cabal test haskoki-review-probes --test-show-details=direct --test-options=sqlite
```

The executable emits `CASE`, `OBSERVED`, `PASS`, `VIOLATION`, `SETUP_ERROR`, and a final count summary. Its own exit status is 0 when all cases pass, 1 for contract violations, and 2 for setup errors or unexpected exceptions; setup errors take precedence when both occur. Cabal may normalize a failing test executable's exit status, so preserve the direct log and summary. Each case continues independently after a previous failure.

## Token metadata refresh

Each backend gets a fresh store identity, one token, one data object, and one queued detached-job record. The fixture uses public record constructors and `Store.storeCommit`, with the same token-auth and owned-byte job shapes used by the existing storage suite. It validates exact initial round trips before probing.

The probe commits `emptyDelta { sdPutTokens = [token { trLabel = "review-refreshed-token" }] }`, then verifies the refreshed token and original object/job records immediately and after close/reopen. It also compares the canonical object/job documents with the seeded documents. A successful token-only refresh must preserve both child records. Counts and exact-comparison booleans are logged even when children disappear.

This checks the exported Store contract and Haskell SQLite implementation, beyond the review's SQL-only observation. It does not assert that a current Standard PKCS#11 login path refreshes the persisted token row. The job fixture is stored and decoded only; no recipe execution or detached rejoin is claimed.

Relevant baseline sources: `src/Haskoki/Runtime/Storage.hs:577` (Store API), `src/Haskoki/Runtime/Storage/SQLite.hs:1248` (token replacement SQL), `src/Haskoki/Runtime/Storage/SQLite.hs:726` (child foreign keys), `src/Haskoki/Runtime/Storage/Memory.hs:401` (map delta application), `tests/storage/StoreSpec.hs:1610` (queued-job fixture), and `tests/storage/StoreSpec.hs:1632` (seeded-record pattern).

## Stale handle close

Both backends receive the same sequence: open A, close A, open B, close A again, then attempt C while B remains live. C must refuse with `StoreSecondWriter`. Unexpected successful C handles are closed before B; B is then closed and a fresh opener must succeed. The old A finalizer runs only after all later handles have closed, so cleanup adds no unintended stale-close test while a later owner is live.

This checks the per-identity ownership contract directly without concurrent threads or writes through improperly admitted handles. SQLite is a control backend. Relevant baseline sources: `src/Haskoki/Runtime/Storage/Memory.hs:100` (owner acquisition), `src/Haskoki/Runtime/Storage/Memory.hs:138` (shared owner release), `src/Haskoki/Runtime/Storage/SQLite.hs:763` (per-handle close flag), and `tests/storage/StoreSpec.hs:336` (existing ownership checks).

## Scope and custody

Each Memory case uses a fresh `MemoryWorld`; each SQLite case creates and owns a fresh PID/counter temporary directory using the existing suite's allocation pattern. All acquired Store handles have finalizers, and SQLite removes the entire temporary directory, including its database and sidecars. No existing store paths, environment mutations, package installations, or local compiler/native/container execution are required. The GitHub job should bound execution externally. Optional durable-ID reuse and malformed restored cipher geometry probes were deliberately omitted to keep this diagnostic component focused on the two smallest decisive contracts.
