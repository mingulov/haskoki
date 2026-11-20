# ADR-07 — Multiple operation slots per session

Status: Accepted

Source: `ws/docs/incoming/haskell-pkcs11-design/docs/11-decisions-and-risks.md` (imported verbatim).

**Decision:** use a compatibility matrix and separate message/search lifecycles.

**Rejected:** one exclusive operation enum.

**Consequence:** dual-update and multiple supported operation combinations remain implementable.
