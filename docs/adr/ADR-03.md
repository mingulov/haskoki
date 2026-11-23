# ADR-03 — One Cabal project and explicit module boundaries

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** one package with internal core/runtime boundaries.

**Rejected:** a workspace of many independently released packages or dynamic plugin framework.

**Consequence:** extensions add modules and descriptors without packaging overhead.
