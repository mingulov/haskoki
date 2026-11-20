# ADR-08 — Deterministic async first

Status: Accepted

Source: `ws/docs/incoming/haskell-pkcs11-design/docs/11-decisions-and-risks.md` (imported verbatim).

**Decision:** logical jobs use the ordinary effect/outcome model; add real workers only when needed.

**Rejected:** sleeps, unstructured `forkIO` jobs, `killThread` as API cancellation.

**Consequence:** reproducible schedules and delivery arbitration are easy to test, but initial async performance is not HSM-like.
