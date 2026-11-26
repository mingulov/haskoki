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
- Emission at actual delivery with same-call record pairing
  (collectors bind contexts to threads); committed negative
  verdicts emit like deliveries; inits, updates, and queries stay
  silent on success. Management calls (login, PIN changes, object
  create/copy/set-attribute) emit the policy half on denials plus
  a bare end claim. Generic PSS/OAEP mechanisms resolve the real
  hash from validated parameters. Message parts report by
  finality (`end` flag, signature presence); detach hands the
  source op off terminally (handoff phase + handed-off end) while
  the rejoin continues as a fresh op. Consumer guide:
  `docs/usdt.md`.

## Verification

- CI matrix: the `haskell` leg (default flags) plus the
  `haskell-usdt` leg (full 8-suite matrix with the flag on,
  readelf manifest gate, dormant-probe bench); the off build
  carries zero probe notes. Publication needs the flag-on leg.
- Live capture (`scripts/test-usdt-live.sh`, release manifest):
  GDB recipe over a 47-phase workload asserting field-exact
  records, exact per-phase counts, silence legs, and op-id
  correlation across abandonment, denial, retry, message,
  logout, detach, and cross-thread delivery paths (57 ops, 24 pk
  records on the reference run), plus an independent Tier-2
  review round whose majors (logout/retention scope, message
  finality, op_valid, detach handoff, counter wrap, refused
  queries) are all fixed and leg-proven here.
- Mapping pins (`tests/model/UsdtMapSpec.hs`), C consistency
  (`scripts/check-usdt-codes.py`), and the FFI arg allowlist
  (`scripts/check-usdt-redaction.py`) hold both flag settings
  with zero GHC warnings.
- Overhead: dormant probes measure 1.055x over a warmed AES-CBC
  workload (inside run-to-run noise); the bench gate fails past
  2x. No attached-consumer measurement is claimed.

## Known limits and follow-ups

- DH records carry algorithm + bits; the `pk::group` enrichment
  needs prime matching and is not implemented (honest omission).
- Exotic EC curves (brainpool, binary) omit curve codes while
  keeping algorithm + mechanism.
- Publication-failure emission has no live leg (no C-side fault
  knob); unit and mapping coverage stands.
- `crau-agent` ingestion validated: the pinned agent
  (`e9004d5`) ingested all 24 pk records of the reference workload
  unmodified (6 generate, 6 sign, 6 verify, 2 derive, OAEP
  encrypt/decrypt, KEM encapsulate/decapsulate), with typed fields
  intact (including EC `secp256r1` curves) and correct executable
  attribution.
- Finalize-time abandonment stays silent by design.
- Upstream latchset fixes (collector attach-failure reporting,
  `matches_pid`, fallback-reader zero hazard) are drafted
  separately by the owner.
