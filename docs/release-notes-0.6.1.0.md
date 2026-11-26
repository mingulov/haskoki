# Haskoki 0.6.1.0 release notes (accumulating draft)

Developer preview: entries land per task and finalize at release.

## Added — USDT observability

- Latchset-compatible `crypto_auditing` USDT probes: one record per
  delivered public-key operation (`pk::sign`, `pk::verify`,
  `pk::encrypt`, `pk::decrypt`, `pk::encapsulate`,
  `pk::decapsulate`, `pk::generate`, `pk::derive`) with typed
  registry fields, consumable by an unmodified `crau-agent`.
- Private `haskoki` USDT namespace: `operation_end` (per-operation
  outcome), `policy_reject` (admission denials with reason class),
  `job_state` (async job lifecycle).
- Probes carry metadata only — mechanisms, key facts, codes,
  dispositions. Key material, PINs, and message bodies never
  render, matching the JSONL trace redaction discipline.
- Compiled in behind the `usdt` Cabal flag (on for the official
  bundle and demo image, off by default for source builds).
