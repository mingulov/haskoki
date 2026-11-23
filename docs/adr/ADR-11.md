# ADR-11 — In-process control before IPC

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** scripted config plus a separate nonstandard control symbol for the same loaded instance; offline/owned-instance CLI.

**Rejected:** assuming a second CLI process shares memory with the provider.

**Consequence:** remote live control is an optional separate feature, not a hidden requirement.
