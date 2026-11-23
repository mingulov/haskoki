# ADR-10 — No silent crypto fallback

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** engine/mode selection is explicit and capabilities are parameter-aware.

**Rejected:** synthetic output when a real backend errors.

**Consequence:** real integration failures remain visible and test vectors retain meaning.
