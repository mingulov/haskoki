# Trust ladder

What each evidence level proves — and what it explicitly does
not. Every behavioral claim in `docs/demo-walkthrough.md` and
`docs/coverage.md` sits on one of these rungs; a claim that
outgrows its rung is inaccurate until fixed or scoped (this
ladder is pinned by `scripts/check-docs.py`).

Higher rungs subsume broader execution reality, never the rung
below: a driver PASS does not re-prove unit refusal pins, and a
unit battery does not prove C-ABI behavior.

## The rungs

rung 0 — static gates (`scripts/check-*.py`, `run-gates.sh`).
Proves file-shape and cross-artifact consistency: catalogs parse,
projections match byte-for-byte, forbidden strings are absent,
required wordings present. Proves NO runtime behavior; a passing
static gate means "the paperwork agrees".

rung 1 — unit suites (model/core/storage/ops/engine Haskell
tests, deterministic). Proves specified cases pass in-process,
including the refusal taxonomy: exact codes plus explanatory
reasons for refused mechanisms (the exhaustiveness battery,
`tests/model/MechanismExhaustivenessSpec.hs`),
malformed-input rejection, quota boundaries, and byte-format
goldens. Does not prove C-ABI behavior, cross-process reality,
or anything outside the enumerated cases.

rung 2 — prop suites (`tests/prop`, QuickCheck under fixed
replay seeds and `PROP_CASES` counts). Proves generated
behavioral agreement on the covered space: chunk-partition
invariants, command-sequence model agreement, the full
37×7 denial grid (`ErrorProps`), refusal-taxonomy agreement
(`OracleProps`). Replayable (seed + count), still in-process,
still bounded by what the generators construct: props cover
supported mechanisms and their failure legs, NOT refused-mechanism
routing (that is rung 1's battery) and NOT the C surface.

rung 3 — C drivers (`scripts/test-*.sh` over the built `.so`).
Proves the real C ABI behaves: loader/A01–A06, consumers,
mutexes, output contracts, crypto routing, async, control
events, lifecycle — including can-fail evidence (seeded
transcript mismatches, injected faults, mid-stream aborts).
Single topology (direct load); each driver re-verifies only its
own slice per run.

rung 4 — parity (`scripts/test-proxy-parity.sh`). Proves
topology independence for forwarded calls: byte-identical
forwarded-call transcripts direct vs behind `pkcs11-proxy-ng`
(the external pair, canonically hashed in the script header).
Topology-specific lines are asserted per mode, excluded from the
diff by cited mechanism — parity proves the forwarded subset,
not the excluded lines.

rung 5 — oracles (independent implementations). Proves our bytes
agree with the outside world: FIPS KATs via the pinned OpenSSL
4.0.2 CLI, `pkcs11-check`/`pkcs11-tool`/`p11-kit`/NSS against the
served surface. Dated verbatim evidence under `ws/notes/`; each
oracle run proves its own date and scope only. Non-attempts are
disclosed, not implied (JVM consumers, the OpenSSL provider).

rung 6 — audit (human review). Proves judgment was applied: the
FP design review
(`ws/notes/2026-09-22-haskell-fp-design-review.md`), the impl
review, per-task audits. An audit finding is a scoped opinion
with cited evidence, not an execution result; dispositions live
in task reports and in this ladder's §Review-name dispositions
below.

## Claim map (where the walkthrough's claims sit)

- Quoted command outputs (§1–§4, §7–§9): rung 3/4 transcripts at
  the stated revisions (header: the release tree for steps 2–6;
  later sections name their own revisions). Re-run the named script
  for current bytes.
- Refusal claims ("stays honestly X", "refuses loudly"): rung 1
  pins plus rung 3 consumer pins; the exact code+reason pairs are
  the rung-1 batteries' assertions.
- Coverage counts (§5): generated from `spec/mechanisms.json` by
  `scripts/publish-coverage.py` (rung 0 consistency + rung 1/2
  evidence artifacts named per row). Counts are true at the
  quoted publication hash only.
- External-consumer claims (§3 oracles): rung 5 at the cited
  evidence date; the "NOT attempted" list bounds them.
- Negative universals ("never", "no X"): each names its rung —
  e.g. sim interleavings are never asserted (rung 3 stress pins
  conservation only), C-table determinism is not asserted (rung 2
  replay pins stay on the synthetic engine by design).

## Review-name dispositions (no silent drops)

The streamline cases (`GuardJumpForUnreachable`, `ValidSuffixes`,
`MeaningfulPrefix`-free) match NOTHING in the current tree
(repo-wide grep: zero hits for all three names and for
"streamline" itself). There is no in-tree equivalent to locate: no
test, gate, or doc ever carried these names in this lineage, so
there is no removal to record and no structural-invariant claim
depending on them. If a future task introduces streamline cases,
they enter at rung 1 with this ladder updated.

"Property matrix" likewise has no in-tree form (zero hits). Its
closest living equivalent is the rung-2 prop suite set, which —
contrary to the "only present/supported cases" characterization —
enumerates failure space too (`ErrorProps`: the full denial grid;
`OracleProps`: refusal taxonomy; `DigestCmdProps`: staged/error
traces). Refused-mechanism routing is rung 1 (the battery), as the
ladder states above.

"Disabled-build" claims: none found in the walkthrough or
coverage docs. The one non-execution boundary (JVM consumers /
OpenSSL provider not attempted) is explicitly disclosed in §3,
not presented as passing behavior.
