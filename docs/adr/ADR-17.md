# ADR-17 — Toolchain cadence

Status: Accepted

**Decision:** the toolchain is pinned and changes only through the
R-11 watch: GHC 9.10.3, `haskoki-dev:ghc-9.10.3`, OpenSSL 4.1.0,
checker 0.3.1 at `f19a7e1`, proxy pair at the qualified commits
(`toolchain.lock`, `spec/sources.lock.json`). The verified image is
`haskoki-dev:ghc-9.10.3` as rebuilt for 0.6.0 Phase 1 (4.09GB with
GHC 9.10.3, cabal 3.12.1.0 and OpenSSL 4.0.2 on 2026-11-19;
`toolchain.lock` [verified] tracks the current rebuild, including
the glibc drift that motivated it). GHC #27272 exit
and the OpenSSL EOL milestone are tracked, dated work — not
background drift. Silent re-pins are refused by the source locks.

**Rejected:** a floating toolchain; silent re-pins; unowned pins.

**Consequence:** every build is reproducible from the locks; pin
changes arrive as reviewed commits with recorded rationale.

**Wrong if:** a pin must move faster than the watch allows —
concretely, a CVE with a documented remediation deadline before
the next scheduled review — then the move lands with a retroactive
watch entry, never silently.
