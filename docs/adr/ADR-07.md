# ADR-07 — Multiple operation slots per session

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** use a compatibility matrix and separate message/search lifecycles.

**Rejected:** one exclusive operation enum.

**Consequence:** dual-update and multiple supported operation combinations remain implementable.
