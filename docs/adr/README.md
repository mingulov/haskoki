# Architecture Decision Records

Append-only. Numbering: next free integer after the current max
(P-05's profile ADR takes the next free number; never hardcode).
Status is Accepted or Proposed; Proposed flips to Accepted in the
commit that lands the decision. Reversals get a new ADR, never an
edit of the old one's Decision.

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-01](ADR-01.md) | Demonstration breadth, not a production token | Accepted |
| [ADR-02](ADR-02.md) | Haskell core with a small native facade | Accepted |
| [ADR-03](ADR-03.md) | One Cabal project and explicit module boundaries | Accepted |
| [ADR-04](ADR-04.md) | Pure planning and explicit effects | Accepted |
| [ADR-05](ADR-05.md) | Generated ABI, curated semantics | Accepted |
| [ADR-06](ADR-06.md) | Separate native binding and resource registries | Accepted |
| [ADR-07](ADR-07.md) | Multiple operation slots per session | Accepted |
| [ADR-08](ADR-08.md) | Deterministic async first | Accepted |
| [ADR-09](ADR-09.md) | Memory and one SQLite file | Accepted |
| [ADR-10](ADR-10.md) | No silent crypto fallback | Accepted |
| [ADR-11](ADR-11.md) | In-process control before IPC | Accepted |
| [ADR-12](ADR-12.md) | Process-lifetime RTS, provider-lifetime sessions | Accepted |
| [ADR-13](ADR-13.md) | RTS capability pin | Accepted |
| [ADR-14](ADR-14.md) | Serialization lock | Accepted |
| [ADR-15](ADR-15.md) | Storage encryption stance: demo forever | Accepted |
| [ADR-16](ADR-16.md) | DER read-back origin | Accepted |
| [ADR-17](ADR-17.md) | Toolchain cadence | Accepted |
| [ADR-18](ADR-18.md) | Planner/C join register | Accepted |
| [ADR-19](ADR-19.md) | Generated return values | Proposed |
| [ADR-20](ADR-20.md) | Per-function error interpretation | Accepted |
| [ADR-21](ADR-21.md) | Private Haskell libraries, no public API | Accepted |
| [ADR-22](ADR-22.md) | Reserve profile, interfaces, engine.kind | Accepted |
