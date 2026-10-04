#!/usr/bin/env python3
"""Coverage-boundary pins: docs/coverage.md must describe the
C surface truthfully, via the publisher.

Fails (exit 1) when any rule fails. The original one-mechanism boundary
note ("C function tables ... expose exactly one mechanism") went
stale when the real C surface grew past it; the corrected boundary
names that surface and records the retirement provenance. The fix
lives in the PUBLISHER (scripts/publish-coverage.py), never as a
hand-edit of the GENERATED file. The served-row count is DERIVED
from spec/mechanisms.json (support.real == "tested") here and in
the publisher — never hardcoded (a hardcoded count went stale
twice: 104, then 130):

* BLOCK: the doc carries a `>`-quoted boundary block (sanity).
* NO-ONEMECH: the stale one-mechanism claim is gone from it.
* SURFACE-COUNT: it names the derived N-row tested C surface.
* PROVENANCE: it records the note retirement.
* PUB-EMITS-COUNT: the publisher derives the N-row boundary from
  the catalog and grounds it in HASKOKI_MECH_COUNT.
* PUB-DROPS-ONEMECH: the publisher source drops the stale claim.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-coverage-boundary.py
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOC = REPO / "docs" / "coverage.md"
PUB = REPO / "scripts" / "publish-coverage.py"
MECH = REPO / "spec" / "mechanisms.json"

failures = []


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


def boundary_block(text):
    return "\n".join(
        line for line in text.splitlines() if line.startswith("> ")
    )


def main() -> int:
    doc = DOC.read_text()
    pub = PUB.read_text()
    block = boundary_block(doc)
    mechs = json.loads(MECH.read_text())["mechanisms"]
    n = sum(1 for r in mechs if r["support"]["real"] == "tested")

    check("BLOCK", bool(block.strip()),
          "a quoted boundary block exists")
    check("NO-ONEMECH", "exactly one mechanism" not in block,
          "stale one-mechanism claim gone from the boundary")
    check("SURFACE-COUNT", f"{n}-row" in block,
          f"boundary names the derived {n}-row tested C surface")
    check("PROVENANCE", "retired" in block,
          "boundary records the note retirement")
    check("PUB-EMITS-COUNT", "{n}-row" in pub
          and "HASKOKI_MECH_COUNT" in pub,
          "publisher derives the N-row boundary, grounded in the C catalog")
    check("PUB-DROPS-ONEMECH", "exactly one mechanism" not in pub,
          "publisher drops the stale claim")

    # The reporting closure names every suite whose
    # artifacts appear in test_evidence (enumerated from
    # spec/mechanisms.json, never from what's present) — the core
    # suite is reported by content, and a suite dropped from
    # evidence changes the published closure loudly.
    check("SUITE-CLOSURE",
          "Evidence suites:" in doc
          and "haskoki-core-tests" in doc
          and "haskoki-model-tests" in doc
          and "haskoki-engine-tests" in doc,
          "coverage names the evidence-suite closure incl. core")
    check("PUB-EMITS-SUITES", "Evidence suites:" in pub,
          "publisher emits the suite closure")

    if failures:
        print(f"check-coverage-boundary: FAIL ({', '.join(failures)})")
        return 1
    print("check-coverage-boundary: OK (boundary describes the C surface)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
