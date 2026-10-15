# Async execution and configuration

This page separates the implemented async behavior from possible future
configuration extensions. For settings you can use today, see the
[configuration reference](config-honesty.md).

## Implemented behavior

The PKCS#11 3.2 table exposes `C_AsyncComplete`, `C_AsyncGetID`, and
`C_AsyncJoin`. Public submission is a fresh, full-buffer one-shot Digest
on an explicit `CKF_ASYNC_SESSION`. Ordinary sessions, length queries,
short buffers, and staged recalls remain synchronous. Sign, message,
multipart, and key-generation calls do not gain an async submission path.

Complete delivers public completion version `0` to the retained output
allocation. Successful GetID detaches the work and revokes that allocation;
Join installs a new binding and returns `CKR_OK`. The caller must keep a
bound output allocation writable until completion, detachment, or retirement.
The [runtime reference](operations-notes.md#public-32-async-routing) describes
capacity, selector, cancellation, and output-ownership rules.

SQLite detached recovery belongs to the home token. Standard memory
sessions and non-home token views have no detached store. A failed durable
delivery mark cannot undo bytes already delivered, so crash-safe exactly-once
delivery is not guaranteed.

The separate private test API uses context/job tokens, completion version
`1`, and its own Join dialogue. Its tests must not be described as standard
3.2 table behavior. The implementation lives in
[Async.hs](../src/Haskoki/Runtime/Async.hs) and
[Detached.hs](../src/Haskoki/Runtime/Detached.hs);
[async_routed.c](../tests/c/async_routed.c) exercises the public table.

Configuration currently has 44 accepted keys. Unknown keys and sections
are rejected. `haskoki-ctl` provides `config check`, `capabilities`,
`scenario run`, `store inspect`, and `store reset`. Native async does not
consult the scenario runner's `async.enabled` or `async.pending_polls`.

## Construction and linearization

Held call work is admitted in one order, and every refusal precedes
every mutation. Async submit validates holdability first (bytes-like
holdings only), then call-work coherence — the submitting session,
the pinned step's session, function, and slot, and the planned effect
must agree as one checked triple (see
[`CallWork`](../core/Haskoki/CallWork.hs)) — then session enablement,
attached-capacity bounds, and live capacity, all in one transaction
with the id allocation. Any refusal consumes no id and leaves the
table unchanged; the [submit tests](../tests/model/AsyncSpec.hs) pin
the verdicts and the untouched table. The FFI submit leg and the
detach rejoin replay apply the same triple check to their re-planned
pairs. Key work is admitted unconditionally at submit and refused at
the drive instead, before the runner fires.

Linearization, per job: submit allocates the id; the last poll claims
the job and runs the effect outside STM, holding the owned answer;
completion re-validates the reservation against a fresh snapshot,
publishes the commit, drains releases, and delivers the completion
record exactly once. Stale reservations fail the drive before any
effect runs, and fail the completion without publishing.

Key-mutation contract: an effect runner observes key material as of
effect start — the snapshot its resolver closes over, or the owned
bytes the job already holds — so a key destroyed or revoked mid-flight
does not fail the in-flight effect. Later calls observe the mutation:
fresh plans resolve handles and usage flags against the current model
and refuse typed. The
[two-session blocked-runner cases](../tests/model/MultiSessionSpec.hs)
prove both halves across destruction, permitted-use change, unrelated
label change, and different-key change. Narrow reservations are what
make the in-flight half hold: plans record only the session revision
they depend on, so an object mutation never stales a session
reservation.

## Possible extensions

The settings and commands below are proposals, not accepted configuration
or implemented CLI commands. Each would need behavior tests and an updated
configuration reference before use.

| Area | Proposed extension | Needed checks |
| --- | --- | --- |
| Slots and storage | Per-slot metadata, initial presence, storage bindings, and fixture lockout state | Stable enumeration, presence flags, per-slot recovery, and shared-path refusal |
| Mechanism selection | Global and per-slot allow/deny lists; required-route probe at startup | List filtering, init refusal, and deliberately missing routes |
| Reproducibility | Defined synthetic RNG substreams and reproducible fixture export/import | Replay, reload equivalence, and format-version refusal |
| Tracing | Explicit drop policy and severity selection | Saturated-queue behavior and visible loss |
| Async policy | Completion budget and visible detached-job expiry | Poll-budget and expired-job behavior |
| Operator tooling | Effective-config dump and store export/import | Defaults, redaction, and round-trip checks |

Further policy controls, read-only storage, named fixture keys, and
configuration-based fault injection would need demonstrated consumer needs.
A FIPS-filtered demo would still not be a validated cryptographic module.
There is no proposed worker-count setting while execution remains logical,
and no existing network control service, hot reload, or encrypted store.
