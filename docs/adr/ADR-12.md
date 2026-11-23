# ADR-12 — Process-lifetime RTS, provider-lifetime sessions

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** do not call `hs_exit` on each finalize; explicitly validate/pin library lifetime.

**Rejected:** treating PKCS#11 finalization as unloading all Haskell infrastructure.

**Consequence:** unsupported hosts/fork modes must be disclosed.
