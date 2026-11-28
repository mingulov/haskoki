# Haskoki 0.6.4.0 release notes

Shipped 2026-11-28.

## Maintainability — the 0.6.3 follow-ups, finished

- The four follow-up splits deferred from 0.6.3 land, all move-only
  behind re-export shells with byte-identical export lists:
  Der 1498 → 121 (Primitives/Classical/Pqc),
  Derive 1419 → 1064 (Framing/Resolution/Stamping; the ordered
  planDerive dispatch stays whole),
  Synthetic 1958 → 901 (Framing/Capabilities/PureOps/Codecs; the
  type, instance, NOINLINE caps and BackendEnv helpers stay
  together), FfiAsyncSpec 4063 → 151 (6 case/fixture children; both
  inOrderTestGroups and the warmup stay in the shell).
- DRY: one `Haskoki.Bytes` home for u16be/u32be/u64be + foldBE
  (23 copies merged, every deleted form pinned by QuickCheck
  equivalence properties plus edge vectors); toKeyPair reuses
  keyBytesOf with explicit arms.
- Deferred OpenSSL const colocation: 276 single-user fixture
  consts move from OpenSSL/Fixtures into Cipher/Agreement/Ecdsa;
  AcqCounts counting moves to shared tests/support.
- Guardrails: split-family import confinement gate (13 families),
  HLint count ratchet in CI (1646, no new hints), all four size
  pins removed (3 owner-call skips remain).
- Test hardening found en route: tree-slurp probes read strictly
  (fd exhaustion under parallel workers).

## Verification

- Golden sweep passing; suites: model 1811, engine 468,
  storage 550, core 381, prop 85 (74 + 11 new framing laws),
  all passing; tasty listings identical except the 11 additions.
- Zero-warning builds; every moved span verified byte-identical
  by script; C ABI + native symbol sets identical; compat matrix
  version-cells-only. Two-tier review (claude-opus + codex
  agreement, Tier-2 per phase).
