#!/usr/bin/env python3
"""Loader-norm recipe gate: the loader-norm comparison
recipe is documented in scripts/test-loader.sh and EXCLUDES the
recorded-not-gated ldd-closure section, so link-shape changes
never re-litigate 'byte-identical'.

* NORM-RECIPE: test-loader.sh carries the "NORM RECIPE" block.
* NORM-EXCLUDES-LDD: the recipe states the ldd-closure exclusion
  (the "STATIC: ldd" line through the closure output is
  recorded-not-gated).

The recipe change (not any transcript) is the artifact: kept norms
prove old-vs-new equivalence (same verdict, cleaner diff).

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-loader-norm.py
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

failures = []


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


def main() -> int:
    driver = (REPO / "scripts/test-loader.sh").read_text()
    check("NORM-RECIPE", "NORM RECIPE" in driver,
          "test-loader.sh documents the norm recipe")
    check("NORM-EXCLUDES-LDD",
          "ldd-closure excluded" in driver
          and "STATIC: ldd" in driver,
          "recipe excludes the recorded-not-gated ldd closure")
    if failures:
        print(f"loader-norm: FAIL ({', '.join(failures)})")
        return 1
    print("loader-norm: OK (recipe excludes the ldd closure)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
