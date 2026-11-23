# ADR-06 — Separate native binding and resource registries

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** the model holds IDs, while native registries own caller buffers/callbacks and engine resources.

**Rejected:** pointer-free claims that ignore async retaining caller memory; native pointers in snapshots.

**Consequence:** explicit revocation/quiescence tests are required.
