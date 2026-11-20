# ADR-11 — In-process control before IPC

Status: Accepted

Source: `ws/docs/incoming/haskell-pkcs11-design/docs/11-decisions-and-risks.md` (imported verbatim).

**Decision:** scripted config plus a separate nonstandard control symbol for the same loaded instance; offline/owned-instance CLI.

**Rejected:** assuming a second CLI process shares memory with the provider.

**Consequence:** remote live control is an optional separate feature, not a hidden requirement.
