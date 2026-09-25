#!/usr/bin/env python3
"""Coverage-boundary pins: docs/coverage.md must describe the
C surface truthfully, via the publisher.

Fails (exit 1) when any rule fails. The original one-mechanism boundary
note ("C function tables ... expose exactly one mechanism") went
stale when the real C surface grew to the 106-row tested
catalog; the corrected boundary names that surface and records the
retirement provenance. The fix lives in the PUBLISHER
(scripts/publish-coverage.py), never as a hand-edit of the
GENERATED file:

* BLOCK: the doc carries a `>`-quoted boundary block (sanity).
* NO-ONEMECH: the stale one-mechanism claim is gone from it.
* SURFACE-106: it names the 106-row tested C surface.
* PROVENANCE: it records the note retirement.
* PUB-EMITS-106: the publisher source emits the 106-row boundary.
* PUB-DROPS-ONEMECH: the publisher source drops the stale claim.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-coverage-boundary.py
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOC = REPO / "docs" / "coverage.md"
PUB = REPO / "scripts" / "publish-coverage.py"

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

    check("BLOCK", bool(block.strip()),
          "a quoted boundary block exists")
    check("NO-ONEMECH", "exactly one mechanism" not in block,
          "stale one-mechanism claim gone from the boundary")
    check("SURFACE-106", "106-row" in block,
          "boundary names the 106-row tested C surface")
    check("PROVENANCE", "retired" in block,
          "boundary records the note retirement")
    check("PUB-EMITS-106", "106-row" in pub,
          "publisher emits the 106-row boundary")
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
