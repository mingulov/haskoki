# ADR-19 — Generated return values

Status: Proposed

**Problem:** return codes live in three places (Haskell
`ReturnCode`, FFI/C-only codes bypassing the typed API, C
defines), so the served set has no single authority.

**Planned approach:** one spec input generates `returnCodeToRV`
plus the C defines; `ReturnCode` grows append-only; production
duplicate mappings are replaced; a literal-RV gate enforces
constructor coverage + numeric parity while independent ABI
oracle pins stay allowlisted.

**Open:** exact generated output paths (decided in the RV-generation
task's first step). Flips to Accepted in that task's commit.
