#!/usr/bin/env python3
"""Seed honesty check: SeedRandom contract/docs consistency.

Fails (exit 1) when any rule fails:

* ROW-MIRROR contracts: the C_SeedRandom row mirrors C_GenerateRandom exactly
  (contract/entry/reason/evidence) -- both are backend-direct with no
  planner seam, and the catalog is planner-scoped, so neither
  row moves.
* PLANNED-COUNT contracts: planned-with-behavior count stays 81 (deliberately
  raised from 63 by the session-info reclassification of the
  C_GetSessionInfo/C_GetSlotInfo/C_GetTokenInfo rows, then by the
  C_DigestKey routing, then by the C_SetAttributeValue routing,
  then by the C_WrapKey/C_UnwrapKey routing, then by the dual +
  recover wirings, then by the provisioning lifecycle routing of
  C_InitToken/C_InitPIN/C_SetPIN).
* HOSTS-DROP SUPPORTED-HOSTS.md: SeedRandom no longer listed as unsupported.
* WALK-RANDOM docs/demo-walkthrough.md: the random section documents per-engine
  seed semantics, the 1 MiB bound, the entropy-estimate home, and why
  C-table determinism is NOT asserted.
* CHANGELOG-ENTRY CHANGELOG.md: carries a SeedRandom entry (whole-file check,
  so it stays passing when the entry ships under a version header).
* NO-STALE stale-claim scan: no residual "SeedRandom is unsupported"-shaped
  claim outside the documented allowlist (historical slice notes,
  executed behavior pins, planner-scope catalog rows owned by ROW-MIRROR/PLANNED-COUNT).
  The coverage.md exemption matches the whole generated row.

--self-test runs the negative controls for that exemption (a prose
claim, a rewritten row, a changed reason cell, trailing prose, and the
row outside coverage.md must all be stale hits).
"""
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONTRACTS = REPO / "spec/function-contracts.json"

# One shared unsupported-shape list for HOSTS-DROP and NO-STALE so
# the two rules cannot drift: a SeedRandom line fails when it
# carries any of these shapes (case-insensitive).
HOLDOUT_SHAPES = (r"unsupport|refus|not supported|honestly NA"
                  r"|NOT_SUPPORTED|not yet|not implement|holdout|N/A")

failures = []

# The generated function-contract row in docs/coverage.md, matched as
# the whole line (cells and reason). Any other wording of the row,
# including a different reason cell, is a stale-claim hit.
COVERAGE_SEED_ROW = ("| C_SeedRandom | 64 | served | unsupported-with-reason "
                     "| no model planning (served above the planner by the "
                     "routed entry) |")

STALE_NEG = re.compile(r"SeedRandom.*(" + HOLDOUT_SHAPES + r")|"
                       r"(" + HOLDOUT_SHAPES + r").*SeedRandom",
                       re.IGNORECASE)

# (path, line regex): dated history or executed pins, not prose claims.
STALE_ALLOW = [
    ("scripts/check-seed-honesty.py", re.compile(r".")),
    ("tests/c/consumer_roundtrip.c", re.compile(r".")),
    ("tests/c/consumer_discovery.c", re.compile(r".")),
    # Dated R5 evidence mirror of the executed seed-contract
    # negatives (absent from CI checkouts; local worktree only).
    ("ws/r5-evidence/probe-src/consumer_roundtrip.c", re.compile(r".")),
    # The generated function-contract table in coverage.md renders
    # the planner-scope catalog row (ROW-MIRROR owns its content);
    # it states "served" before the planner contract. Exactly that
    # row, nothing else in the file.
    ("docs/coverage.md", re.compile(r"^" + re.escape(COVERAGE_SEED_ROW) + r"$")),
]


def stale_hit(rel, line):
    """True when this line of the file at rel is a stale claim."""
    if "SeedRandom" not in line or not STALE_NEG.search(line):
        return False
    return not any(rel == suf and rx.search(line) for suf, rx in STALE_ALLOW)


def self_test():
    """Negative controls for the coverage.md allowlist."""
    cases = [
        ("exact generated row is allowed", COVERAGE_SEED_ROW, False),
        ("prose claim in coverage.md is stale",
         "C_SeedRandom is not supported by this token.", True),
        ("row rewritten to refused is stale",
         "| C_SeedRandom | 64 | refused | unsupported-with-reason "
         "| no model planning (served above the planner by the routed entry) |",
         True),
        ("row with a different reason is stale",
         "| C_SeedRandom | 64 | served | unsupported-with-reason "
         "| SeedRandom not supported |", True),
        ("row with trailing prose is stale",
         COVERAGE_SEED_ROW + " SeedRandom unsupported", True),
        ("same row outside coverage.md is stale", COVERAGE_SEED_ROW, True),
    ]
    bad = 0
    for i, (name, line, want) in enumerate(cases):
        rel = "docs/release-results.md" if i == len(cases) - 1 else "docs/coverage.md"
        got = stale_hit(rel, line)
        ok = got == want
        bad += not ok
        print(f"{'ok' if ok else 'FAIL'}: self-test: {name}")
    if bad:
        print(f"seed-honesty self-test: FAIL ({bad} controls)")
        return 1
    print(f"seed-honesty self-test: OK ({len(cases)} controls)")
    return 0


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


def main():
    # --- ROW-MIRROR: row mirror (exact, except name/ordinal) ---
    fns = json.loads(CONTRACTS.read_text()).get("functions", [])
    seed = next((r for r in fns if r.get("name") == "C_SeedRandom"), None)
    gen = next((r for r in fns if r.get("name") == "C_GenerateRandom"), None)
    same = (
        seed is not None
        and gen is not None
        and all(seed.get(k) == gen.get(k) for k in (
            "contract", "csv_acceptance", "entry", "first_layout",
            "layouts", "reason", "test_evidence"))
    )
    check("ROW-MIRROR", same, "C_SeedRandom row mirrors C_GenerateRandom exactly")

    # --- PLANNED-COUNT: planned-count pin holds ---
    # 63 -> 66 -> 67 -> 68 -> 70 -> 78 -> 81; the session-info rows
    # reclassified first, then C_DigestKey (routed via the
    # digest-update planner with executed consumer evidence), then
    # C_SetAttributeValue, then C_WrapKey/C_UnwrapKey (c-table
    # routes with executed consumer evidence), then the 4 dual plus
    # 4 recover rows (T-M02/T-M03 flips with executed consumer
    # evidence), then the 3 provisioning rows (planCall arms with
    # the provisioning consumer as executed evidence).
    planned = CONTRACTS.read_text().count('"contract": "planned-with-behavior"')
    check("PLANNED-COUNT", planned == 81, f"planned-with-behavior count == 81 (saw {planned})")

    # --- HOSTS-DROP: supported-hosts drops the seed holdout ---
    # The doc now lists C_SeedRandom as SUPPORTED (Random row), so a
    # bare "SeedRandom not in hosts" check false-positives on the
    # support claim. Fail only on unsupported-shaped SeedRandom lines,
    # which is the documented intent ("no longer listed as
    # unsupported").
    hosts = (REPO / "SUPPORTED-HOSTS.md").read_text()
    holdout = re.compile(HOLDOUT_SHAPES, re.IGNORECASE)
    bad = [line.strip()[:100] for line in hosts.splitlines()
           if "SeedRandom" in line and holdout.search(line)]
    check("HOSTS-DROP", not bad,
          "SUPPORTED-HOSTS.md carries no SeedRandom holdout"
          + ("" if not bad else f" ({len(bad)} holdout lines: "
             + "; ".join(bad) + ")"))

    # --- WALK-RANDOM: walkthrough random section ---
    walk = (REPO / "docs/demo-walkthrough.md").read_text()
    need = ["C_SeedRandom", "seedRandom", "RAND_add",
            "HSK_OSSL4_SEED_ENTROPY_ESTIMATE", "1048576",
            "caseSeedRandomReplay", "NOT asserted"]
    missing = [p for p in need if p not in walk]
    check("WALK-RANDOM", not missing,
          "walkthrough random section pins semantics"
          + ("" if not missing else f" (missing: {', '.join(missing)})"))

    # --- CHANGELOG-ENTRY: changelog entry (whole file: Unreleased today, the
    # versioned section after release -- slicing Unreleased only
    # would fail this on release day) ---
    changelog = (REPO / "CHANGELOG.md").read_text()
    check("CHANGELOG-ENTRY", "C_SeedRandom" in changelog,
          "CHANGELOG carries a C_SeedRandom entry")

    # --- NO-STALE: stale-claim scan (shared HOLDOUT_SHAPES, both
    # directions: the reversed branch previously omitted
    # NOT_SUPPORTED|not yet|not implement and the newer holdout|N/A) ---
    skip_dirs = {"dist-newstyle", "dist-release", "dist-release-evidence", ".git"}
    skip_files = {"spec/function-contracts.json",  # owned by ROW-MIRROR/PLANNED-COUNT
                  "scripts/generate-function-contracts.py"}  # planner-scope table
    exts = {".md", ".json", ".py", ".sh", ".c", ".hs", ".cabal", ".h", ".inc"}
    stale = []
    for path in sorted(REPO.rglob("*")):
        if not path.is_file() or path.suffix not in exts:
            continue
        parts = path.relative_to(REPO).parts
        rel = path.relative_to(REPO).as_posix()
        if any(part in skip_dirs or part.startswith(".") for part in parts):
            continue  # build trees, evidence mirrors, VCS, third-party venvs: not repo prose
        if rel in skip_files:
            continue
        for lineno, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if not stale_hit(rel, line):
                continue
            stale.append(f"{rel}:{lineno}: {line.strip()[:100]}")
    check("NO-STALE", not stale,
          "no stale SeedRandom-unsupported claims"
          + ("" if not stale else f" ({len(stale)} hits:\n  "
             + "\n  ".join(stale) + ")"))

    if failures:
        print(f"seed-honesty: FAIL ({', '.join(failures)})")
        return 1
    print("seed-honesty: OK (rows mirrored, docs consistent, no stale claims)")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    sys.exit(main())
