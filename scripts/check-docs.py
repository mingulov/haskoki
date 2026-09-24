#!/usr/bin/env python3
"""Docs-precision pins: every corrected claim, pinned both ways.

Fails (exit 1) when any rule fails. Stale-string rules demand the
old wording be gone; new-wording rules demand the correction be
present (exact substrings, quoted in the failure detail):

* Random-context split: the walkthrough random section names the
  default-ctx vs libctx split with no read-observable effect
  asserted.
* Slot-listing note: haskokiStdGetSlotList carries the
  vacuous-by-design note (two-phase shape kept for the original
  slot-listing contract); the filter shape it documents is
  still there.
* Funnel path: neither the walkthrough nor the CHANGELOG presents
  commitAndDeliver as a live commit-application path; both name
  the three publishCommit funnels plus the Runtime/Async drains.
* Reseed non-contract: the synthetic reseed carries its stated
  non-contract (the two modifyMVars are not atomic as a pair).
* SeedRandom history: the history note reads past-tense.
* Guarantees (FP review section 5): mustGeneratedId is no longer
  called total-by-construction (partial: error on unknown text);
  the core-boundary docstring no longer says it proves (textual
  denylist, not a proof of purity); runFinisher is exhaustive
  (every FunctionId has an explicit arm, no wildcard).
* Prose justification: every highest-risk claim
  (totality/exhaustiveness, security/correctness,
  proven/guaranteed, safe/safety) in the living contract prose
  (docs/*.md, SUPPORTED-HOSTS.md, CHANGELOG.md) carries or links
  its justification in its sentence window, or the gate fails.

Generated-laws lineage note: the brief's "prose gate checks line
count" has no in-tree form — the generated-laws prop suite
(haskoki.cabal: "generated laws + command sequences over
pure core") covers laws instead, and no line-count prose check
exists in run-gates.sh or scripts/check-*.py (verified by
inspection). There is no line-count check to strengthen; this
prose-justification section is its justification-based
successor, recorded here instead of absorbed silently.

Human criteria (claim classes automation cannot judge — a human
reviewer checks these on every prose change; a check that cannot
fail is theater, so these stay explicitly human):
* C/Haskell safety claims ("thread-safe", "constant-time",
  "cannot leak"): each must name (a) the mechanism and (b) the
  pinning test/driver; the reviewer verifies both resolve.
* Table cells (skipped by the scan: labels/values, not claims):
  the reviewer verifies inventory tables assert nothing.
* Negated claims ("never X", "no silent Y"): automation skips
  negations; the reviewer verifies each negative names its loud
  mechanism (what fails, where).
* New CHANGELOG entries: history is scanned, but old claims were
  verified at write time; the reviewer checks new entries carry
  task stamps plus artifact refs.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-docs.py
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

failures = []


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


def read(rel):
    return (REPO / rel).read_text()


def read_opt(rel):
    p = REPO / rel
    return p.read_text() if p.exists() else ""


# --- prose-justification scanner ---
PROSE_TRIGGERS = re.compile(
    r"\b(total|totally|exhaustive\w*|secure|security|correct\w*"
    r"|proven?|proves?|proved|guarantee\w*|safe|safely|safety)\b",
    re.IGNORECASE)
PROSE_NEG = re.compile(
    r"\bno\b|\bnot\b|\bnever\b|\bneither\b|\bwithout\b|\bnor\b|n't\b|\bnon-",
    re.IGNORECASE)
PROSE_JUSTIFIED_BY = re.compile(
    r"(proven|proved|pinned|verified|checked|gated|guarded|enforced) by\b",
    re.IGNORECASE)
PROSE_SIGNALS = ("`", "§", "see ", "pinned", "evidence", "proof",
                 "because", "demonstrat", "scripts/", "tests/", "docs/",
                 "ws/", "http", "sha ")
# NOTE: "rung" is deliberately NOT a signal (the ladder citing
# "rung" would justify itself circularly).
PROSE_REF = re.compile(r"\bA\d\d\b")


def prose_violations(text):
    """Unjustified high-risk claims: [(trigger, sentence)]. Heads,
    table rows, and fenced code blocks are not claim sites; negated
    and X-by-Y sentences carry their own scope."""
    lines = []
    in_fence = False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.lstrip().startswith("#"):
            continue
        if line.lstrip().startswith("|"):
            continue
        lines.append(line)
    # Windows stay INSIDE one paragraph: justification must be
    # adjacent to the claim, never borrowed from a neighbor block.
    bad = []
    for para in re.split(r"\n\s*\n", "\n".join(lines)):
        sentences = [s for s in
                     re.split(r"(?<=[.!?;])\s+", para) if s.strip()]
        for i, sent in enumerate(sentences):
            for m in PROSE_TRIGGERS.finditer(sent):
                trig = m.group(0).lower()
                if trig == "total" and re.search(r"\(\d+\s+total\)", sent):
                    continue
                if PROSE_NEG.search(sent):
                    continue
                if PROSE_JUSTIFIED_BY.search(sent):
                    continue
                window = " ".join(sentences[max(0, i - 1):i + 2])
                if any(sig in window for sig in PROSE_SIGNALS):
                    continue
                if PROSE_REF.search(window):
                    continue
                bad.append((trig, " ".join(sent.split())[:160]))
    return bad


def main():
    walk = read("docs/demo-walkthrough.md")
    changelog = read("CHANGELOG.md")
    standard = read("ffi/Haskoki/FFI/Standard.hs")
    synth = read("src/Haskoki/Engine/Synthetic.hs")
    tables = read("cbits/function_tables.c")
    gen_mech = read("scripts/generate-mechanisms.py")
    generated = read("core/Haskoki/Registry/Generated.hs")
    boundary = read("scripts/check-core-boundary.py")
    transition = read("core/Haskoki/Transition.hs")

    # --- the context-split sentence ---
    m1 = ("lands on the default-context DRBG while `randomBytes` "
          "reads draw from the private libctx DRBG")
    check("CTX-SPLIT", m1 in walk, "walkthrough names the ctx split")

    # --- vacuous-by-design note + documented shape ---
    check("SLOTLIST-NOTE", "vacuous by design" in standard,
          "GetSlotList carries the vacuity note")
    check("SLOTLIST-SHAPE", "lookupTokenAuth m slot /= Nothing" in standard,
          "the documented filter shape is still there")

    # --- commitAndDeliver no longer the live path ---
    check("FUNNEL-WALK-STALE", "(`commitAndDeliver` and the" not in walk,
          "walkthrough drops commitAndDeliver-as-live-path")
    check("FUNNEL-WALK-NEW", "the three `publishCommit` funnels" in walk,
          "walkthrough names the three funnels")
    check("FUNNEL-LOG-STALE", "(`commitAndDeliver` plus the" not in changelog,
          "CHANGELOG drops commitAndDeliver-as-live-path")
    check("FUNNEL-LOG-NEW",
          "the three `publishCommit` funnels plus the" in changelog,
          "CHANGELOG names funnels plus drains")

    # --- reseed non-contract comment ---
    check("RESEED-NONCONTRACT", "are NOT atomic as a pair" in synth,
          "reseed states its non-contract")

    # --- past-tense history ---
    check("HISTORY-STALE", "SeedRandom stays" not in tables,
          "SeedRandom history note no longer present-tense")
    check("HISTORY-NEW", "SeedRandom stayed" in tables,
          "SeedRandom history note reads past-tense")

    # --- Guarantees: mustGeneratedId partiality ---
    check("GENID-STALE",
          "Total-by-construction" not in gen_mech
          and "Total-by-construction" not in generated,
          "total-by-construction wording gone")
    check("GENID-NEW",
          "calls 'error' on unknown text" in gen_mech
          and "calls 'error' on unknown text" in generated,
          "partiality stated in generator and output")

    # --- Guarantees: import checker is a denylist ---
    check("BOUNDARY-STALE", "prove core/ imports" not in boundary,
          "core-boundary docstring no longer says prove")
    check("BOUNDARY-NEW",
          "textual denylist, not a proof of purity" in boundary,
          "denylist scope stated")

    # --- Guarantees: runFinisher enumeration (explicit arms supersede the
    # wildcard ruling: every FunctionId now has an explicit arm,
    # so the wildcard sentence is gone and the exhaustive marker
    # plus per-arm coverage are pinned instead). ---
    fin_start = transition.find("runFinisher step res = case csFunction step of")
    fin_body = transition[fin_start:transition.find("\n  where", fin_start)]
    check("FINISHER-MARKER",
          "-- Exhaustive runFinisher" in transition,
          "runFinisher exhaustion marker present")
    check("FINISHER-NO-WILDCARD",
          fin_start != -1 and "_ ->" not in fin_body,
          "runFinisher has no wildcard arm")
    check("FINISHER-STALE",
          "a wildcard, not an exhaustive match" not in transition,
          "wildcard sentence retired")

    # --- trust ladder + walkthrough claim currency ---
    ladder = read_opt("docs/trust-ladder.md")
    check("LADDER-RUNGS",
          all(r in ladder for r in
              ("rung 0", "rung 1", "rung 2", "rung 3", "rung 4",
               "rung 5", "rung 6")),
          "trust ladder defines rungs 0-6")
    check("LADDER-LEVELS",
          all(r in ladder for r in
              ("unit", "prop", "driver", "parity", "oracle", "audit")),
          "ladder names every evidence level")
    check("LADDER-STREAMLINE",
          "GuardJumpForUnreachable" in ladder
          and "ValidSuffixes" in ladder
          and "MeaningfulPrefix" in ladder,
          "ladder records the streamline-name disposition")
    check("LADDER-LINK",
          "docs/trust-ladder.md" in walk,
          "walkthrough links the trust ladder")
    # The STAY-BUFFERED paragraph cited Backend.hs by line
    # (:459-461 etc.); the lines drifted (+10) while the prose
    # stood still. Convention, pinned: the walkthrough cites
    # backend entries by symbol, never by line number.
    check("WALK-BACKEND-STALE",
          re.search(r"Backend\.hs:\d", walk) is None,
          "walkthrough cites no Backend.hs line numbers")
    check("WALK-BUFFERED-NEW",
          "STAY BUFFERED" in walk
          and "`sign`/`verify` take the full message" in walk,
          "buffered verdict kept, symbol-cited")

    # --- prose justification per file ---
    prose_files = ["docs/demo-walkthrough.md", "docs/coverage.md",
                   "docs/trust-ladder.md", "docs/byte-formats.md",
                   "docs/operations-notes.md", "SUPPORTED-HOSTS.md",
                   "CHANGELOG.md"]
    for rel in prose_files:
        bad = prose_violations(read(rel))
        detail = ("no unjustified high-risk claims" if not bad
                  else "; ".join(f"{t} in: {s}" for t, s in bad[:3]))
        check(f"PROSE-{Path(rel).stem}", not bad, detail)
    self_text = Path(__file__).read_text()
    check("PROSE-CRITERIA",
          "Human criteria" in self_text and "Generated-laws lineage" in self_text,
          "human criteria + generated-laws lineage recorded in this gate")

    if failures:
        print(f"docs: FAIL ({', '.join(failures)})")
        return 1
    print("docs: OK (all precision claims pinned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
