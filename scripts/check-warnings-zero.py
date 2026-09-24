#!/usr/bin/env python3
"""Warnings-zero gate: the forced-build warnings norm must be EMPTY.

Fails (exit 1) when spec/warnings-norm.txt is missing or non-empty.

Regenerate the norm from a forced build (run from the repo root):
  rm -rf dist-newstyle
  timeout -s KILL 600 docker run --rm --network host -v "$PWD:/work" \\
    -w /work haskoki-dev:ghc-9.10.3 \\
    cabal build all --enable-tests > /tmp/forced.log 2>&1
  grep "warning: \\[GHC-" /tmp/forced.log \\
    | sed -E 's/:[0-9]+:[0-9]+: warning:/  warning:/' | sort \\
    > spec/warnings-norm.txt

The 32 pre-existing test warnings were paid down to zero at
root cause; subsequent tasks gate on this empty norm. Any new
warning fails this gate until it is fixed (no -Wno-*, no OPTIONS
suppressions, no warning-masking refactors).

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-warnings-zero.py
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NORM = REPO / "spec" / "warnings-norm.txt"


def main() -> int:
    if not NORM.exists():
        print(f"warnings-zero: FAIL: missing {NORM.relative_to(REPO)} "
              f"(regenerate per the script docstring)", file=sys.stderr)
        return 1
    data = NORM.read_bytes()
    if data:
        lines = data.decode("utf-8", errors="replace").splitlines()
        print(f"warnings-zero: FAIL: norm has {len(lines)} warning(s), "
              f"want EMPTY", file=sys.stderr)
        for line in lines[:10]:
            print(f"warnings-zero:   {line}", file=sys.stderr)
        if len(lines) > 10:
            print(f"warnings-zero:   ... ({len(lines) - 10} more)",
                  file=sys.stderr)
        return 1
    print("warnings-zero: ok: norm EMPTY (0 warnings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
