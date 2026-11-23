# ADR-04 — Pure planning and explicit effects

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** typed plan/reservation/execute/commit with structured outcomes.

**Rejected:** global IO maps mutated by each API handler; all IO inside STM; errors represented only as discarded `Either CKR`.

**Consequence:** native outputs and error-dependent state changes are first-class contracts.
