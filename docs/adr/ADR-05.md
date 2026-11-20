# ADR-05 — Generated ABI, curated semantics

Status: Accepted

Source: `ws/docs/incoming/haskell-pkcs11-design/docs/11-decisions-and-risks.md` (imported verbatim).

**Decision:** generate signatures/layouts/identifiers; hand-review semantic rules.

**Rejected:** inferring operation flags or pointer extents from names and a regex over prose.

**Consequence:** source discrepancies stay visible; 3.1 shares the actual 3.0 layout.
