# ADR-10 — No silent crypto fallback

Status: Accepted

Source: `ws/docs/incoming/haskell-pkcs11-design/docs/11-decisions-and-risks.md` (imported verbatim).

**Decision:** engine/mode selection is explicit and capabilities are parameter-aware.

**Rejected:** synthetic output when a real backend errors.

**Consequence:** real integration failures remain visible and test vectors retain meaning.
