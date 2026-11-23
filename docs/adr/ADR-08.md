# ADR-08 — Deterministic async first

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** logical jobs use the ordinary effect/outcome model; add real workers only when needed.

**Rejected:** sleeps, unstructured `forkIO` jobs, `killThread` as API cancellation.

**Consequence:** reproducible schedules and delivery arbitration are easy to test, but initial async performance is not HSM-like.
