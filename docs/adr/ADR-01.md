# ADR-01 — Demonstration breadth, not a production token

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** retain full API/mechanism ambition but separate behavioral/synthetic/real evidence.

**Reason:** a wide executable demonstrator is the user's objective.

**Rejected:** certification-first design or waiting for every real primitive.

**Consequence:** simulation is prominent in labels and reports; missing behavior is still a gap.
