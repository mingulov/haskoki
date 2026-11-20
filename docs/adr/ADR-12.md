# ADR-12 — Process-lifetime RTS, provider-lifetime sessions

Status: Accepted

Source: `ws/docs/incoming/haskell-pkcs11-design/docs/11-decisions-and-risks.md` (imported verbatim).

**Decision:** do not call `hs_exit` on each finalize; explicitly validate/pin library lifetime.

**Rejected:** treating PKCS#11 finalization as unloading all Haskell infrastructure.

**Consequence:** unsupported hosts/fork modes must be disclosed.
