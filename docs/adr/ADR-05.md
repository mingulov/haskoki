# ADR-05 — Generated ABI, curated semantics

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** generate signatures/layouts/identifiers; hand-review semantic rules.

**Rejected:** inferring operation flags or pointer extents from names and a regex over prose.

**Consequence:** source discrepancies stay visible; 3.1 shares the actual 3.0 layout.
