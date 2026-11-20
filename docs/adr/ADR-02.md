# ADR-02 — Haskell core with a small native facade

Status: Accepted

Source: `ws/docs/incoming/haskell-pkcs11-design/docs/11-decisions-and-risks.md` (imported verbatim).

**Decision:** implement semantics in Haskell; use generated C for the ABI, tables and native ownership.

**Rejected:** a Rust provider, Python embedding, or a mandatory remote Haskell service.

**Consequence:** GHC runtime compatibility is the first measured gate, not an assumption.
