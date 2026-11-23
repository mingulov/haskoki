# ADR-09 — Memory and one SQLite file

Status: Accepted

Source: the upstream Haskell PKCS#11 design archive, decisions-and-risks chapter (imported verbatim; the archive is not kept in git).

**Decision:** memory store first, optional local SQLite with one active writer; persist detached jobs as well as token data.

**Rejected:** database-backed live sessions, native-context serialization or a distributed backend.

**Consequence:** cross-process durable recovery is supported only in persistent mode.
