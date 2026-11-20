# ADR-13 — RTS capability pin

Status: Accepted

**Decision:** one RTS profile for every supported host: the threaded
runtime bootstrapped once per process (`cbits/rts_bootstrap.c`), no
`hs_exit` on finalize (ADR-12), fork children fail safe without
re-bootstrap, and no-thread hosts are refused up front with
`CKR_NEED_TO_CREATE_THREADS` (`cbits/function_tables.c:13-14,23,538`).
The pin is exactly one capability (`GHCRTS=-N4` honored as one; the
unsafe `GHCRTS=-A8m` form also yields one — pinned by
`tests/c/consumer_rts_caps.c`).

**Rejected:** per-host RTS profiles; a non-threaded runtime; calling
`hs_exit` per finalize.

**Consequence:** supported-host limits are explicit and probed; any
host outside the pin is refused, never silently degraded.

**Wrong if:** a host the release must support needs a different RTS
profile — then re-pin through R-11 (toolchain watch), never by local
exception. GHC #27272 resolution explicitly requalifies this pin.
