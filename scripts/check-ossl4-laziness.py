#!/usr/bin/env python3
"""Laziness-pragma gate: src/Haskoki/Engine/OpenSSL4.hs must carry
`{-# OPTIONS_GHC -fno-full-laziness #-}` ahead of the module header.

Why: full laziness floats constant subexpressions (capability name
lists, note tables, string literals) out of the capability builders
into shared top-level thunks. Concurrent opens then dup-evaluate those
thunks, and on 2 or more RTS capabilities GHC's RTS can orphan a
string-literal CAF black hole and deadlock the process (GHC #27272).
The published capability values are normalized by `forceCaps`; this
pragma keeps the module from growing new shared lazy CAFs. The engine
tests cannot see the pragma (the published values are in normal form
either way), so this gate is its regression guard.

Fails (exit 1) when the pragma is missing, appears only inside a
comment, or comes after the `module` line.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-ossl4-laziness.py [--self-test]
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TARGET = REPO / "src" / "Haskoki" / "Engine" / "OpenSSL4.hs"
PRAGMA = re.compile(
    r"^\{-#\s*OPTIONS_GHC\b[^#]*?-fno-full-laziness\b[^#]*#-\}\s*$")
MODULE = re.compile(r"^module\s")


def check(text):
    """Return a list of problems (empty when the pragma is in place)."""
    for line in text.splitlines():
        if MODULE.match(line):
            return ["-fno-full-laziness OPTIONS_GHC pragma missing "
                    "before the module header"]
        if PRAGMA.match(line):
            return []
    return ["-fno-full-laziness OPTIONS_GHC pragma missing"]


def self_test():
    good = "{-# LANGUAGE X #-}\n{-# OPTIONS_GHC -fno-full-laziness #-}\nmodule M where\n"
    cases = [
        ("pragma present", good, True),
        ("pragma with other flags",
         "{-# OPTIONS_GHC -Wall -fno-full-laziness #-}\nmodule M where\n", True),
        ("missing pragma", "{-# LANGUAGE X #-}\nmodule M where\n", False),
        ("only in a line comment",
         "-- {-# OPTIONS_GHC -fno-full-laziness #-}\nmodule M where\n", False),
        ("after the module header",
         "module M where\n{-# OPTIONS_GHC -fno-full-laziness #-}\n", False),
        ("different flag",
         "{-# OPTIONS_GHC -fno-cse #-}\nmodule M where\n", False),
    ]
    bad = 0
    for name, text, expect_ok in cases:
        ok = not check(text)
        if ok != expect_ok:
            bad += 1
            print(f"SELF-TEST FAIL: {name}: ok={ok}, expected {expect_ok}")
    if bad:
        return 1
    print("check-ossl4-laziness: self-test OK")
    return 0


def main():
    if "--self-test" in sys.argv[1:]:
        return self_test()
    problems = check(TARGET.read_text())
    for p in problems:
        print(f"FAIL: {TARGET.relative_to(REPO)}: {p}")
    if problems:
        return 1
    print("check-ossl4-laziness: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
