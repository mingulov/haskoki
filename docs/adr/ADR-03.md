# ADR-03 — One Cabal project and explicit module boundaries

Status: Accepted

Source: `ws/docs/incoming/haskell-pkcs11-design/docs/11-decisions-and-risks.md` (imported verbatim).

**Decision:** one package with internal core/runtime boundaries.

**Rejected:** a workspace of many independently released packages or dynamic plugin framework.

**Consequence:** extensions add modules and descriptors without packaging overhead.
