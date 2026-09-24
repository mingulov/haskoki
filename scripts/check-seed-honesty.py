#!/usr/bin/env python3
"""Seed honesty check: SeedRandom contract/docs consistency.

Fails (exit 1) when any rule fails:

* ROW-MIRROR contracts: the C_SeedRandom row mirrors C_GenerateRandom exactly
  (contract/entry/reason/evidence) -- both are backend-direct with no
  planner seam, and the catalog is planner-scoped, so neither
  row moves.
* PLANNED-COUNT contracts: planned-with-behavior count stays 67 (deliberately
  raised from 63 by the session-info reclassification of the
  C_GetSessionInfo/C_GetSlotInfo/C_GetTokenInfo rows, then by the
  C_DigestKey routing).
* HOSTS-DROP SUPPORTED-HOSTS.md: SeedRandom no longer listed as unsupported.
* WALK-RANDOM docs/demo-walkthrough.md: the random section documents per-engine
  seed semantics, the 1 MiB bound, the entropy-estimate home, and why
  C-table determinism is NOT asserted.
* CHANGELOG-ENTRY CHANGELOG.md: carries a SeedRandom entry (whole-file check,
  so it stays passing when the entry ships under a version header).
* NO-STALE stale-claim scan: no residual "SeedRandom is unsupported"-shaped
  claim outside the documented allowlist (historical slice notes,
  executed behavior pins, planner-scope catalog rows owned by ROW-MIRROR/PLANNED-COUNT).
"""
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONTRACTS = REPO / "spec/function-contracts.json"

failures = []


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
    # 63 -> 66 -> 67; the session-info rows reclassified first,
    # then C_DigestKey (routed via the digest-update planner with
    # executed consumer evidence).
    planned = CONTRACTS.read_text().count('"contract": "planned-with-behavior"')
    check("PLANNED-COUNT", planned == 67, f"planned-with-behavior count == 67 (saw {planned})")

    # --- HOSTS-DROP: supported-hosts drops the seed holdout ---
    hosts = (REPO / "SUPPORTED-HOSTS.md").read_text()
    check("HOSTS-DROP", "SeedRandom" not in hosts,
          "SUPPORTED-HOSTS.md carries no SeedRandom holdout")

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

    # --- NO-STALE: stale-claim scan ---
    neg = re.compile(r"SeedRandom.*(unsupport|refus|not supported|honestly NA"
                     r"|NOT_SUPPORTED|not yet|not implement)|"
                     r"(unsupport|refus|not supported|honestly NA)"
                     r".*SeedRandom",
                     re.IGNORECASE)
    # (path suffix, line regex): dated history or executed pins, not prose claims.
    allow = [
        ("scripts/check-seed-honesty.py", re.compile(r".")),
        ("tests/c/consumer_roundtrip.c", re.compile(r".")),
        ("tests/c/consumer_discovery.c", re.compile(r".")),
    ]
    skip_dirs = {"dist-newstyle", "dist-release", ".git"}
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
            continue  # build trees, VCS, third-party venvs: not repo prose
        if rel in skip_files:
            continue
        for lineno, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if "SeedRandom" not in line or not neg.search(line):
                continue
            if any(rel == suf and rx.search(line) for suf, rx in allow):
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
    sys.exit(main())
