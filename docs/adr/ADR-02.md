# ADR-02 — Haskell core with a small native facade

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** implement semantics in Haskell; use generated C for the ABI, tables and native ownership.

**Rejected:** a Rust provider, Python embedding, or a mandatory remote Haskell service.

**Consequence:** GHC runtime compatibility is the first measured gate, not an assumption.
