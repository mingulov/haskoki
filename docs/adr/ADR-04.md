# ADR-04 — Pure planning and explicit effects

Status: Accepted

Source: `ws/docs/incoming/haskell-pkcs11-design/docs/11-decisions-and-risks.md` (imported verbatim).

**Decision:** typed plan/reservation/execute/commit with structured outcomes.

**Rejected:** global IO maps mutated by each API handler; all IO inside STM; errors represented only as discarded `Either CKR`.

**Consequence:** native outputs and error-dependent state changes are first-class contracts.
