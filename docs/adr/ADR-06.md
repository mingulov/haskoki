# ADR-06 — Separate native binding and resource registries

Status: Accepted

Source: `ws/docs/incoming/haskell-pkcs11-design/docs/11-decisions-and-risks.md` (imported verbatim).

**Decision:** the model holds IDs, while native registries own caller buffers/callbacks and engine resources.

**Rejected:** pointer-free claims that ignore async retaining caller memory; native pointers in snapshots.

**Consequence:** explicit revocation/quiescence tests are required.
