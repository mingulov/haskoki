# ADR-09 — Memory and one SQLite file

Status: Accepted

Source: `ws/docs/incoming/haskell-pkcs11-design/docs/11-decisions-and-risks.md` (imported verbatim).

**Decision:** memory store first, optional local SQLite with one active writer; persist detached jobs as well as token data.

**Rejected:** database-backed live sessions, native-context serialization or a distributed backend.

**Consequence:** cross-process durable recovery is supported only in persistent mode.
