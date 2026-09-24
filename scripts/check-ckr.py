#!/usr/bin/env python3
"""Verify the FFI-only CK_RV literals against the locked headers.

ffi/Haskoki/FFI/Standard.hs spells a handful of CK_RV values the pure
core never produces (slot universe, serial/parallel, read-only
sessions, template faults) as `CULong 0xNN` constants. Each carries a
doc comment `-- | @CKR_FOO@ (0xNN).`; this checker parses those
declarations and requires the literal to equal the locked
spec/vendor/pkcs11.h spelling. Any drift (or any new
literal without the doc convention) fails loudly.

STDLIB ONLY. Wired into scripts/run-gates.sh.
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HS = REPO / "ffi" / "Haskoki" / "FFI" / "Standard.hs"
HDR = REPO / "spec" / "vendor" / "pkcs11.h"

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    hdr = HDR.read_text()
    defs = {}
    for m in re.finditer(r"#define\s+(CKR_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)UL", hdr):
        defs[m.group(1)] = int(m.group(2), 16)
    check(len(defs) > 100, f"too few CKR_ defines parsed ({len(defs)})")

    text = HS.read_text()
    # Convention: `-- | @CKR_FOO@ (0xNN).` immediately above
    # `ckrSomething :: CULong` / `ckrSomething = CULong 0xMM`.
    pat = re.compile(
        r"-- \| @([A-Z0-9_]+)@ \(0x([0-9A-Fa-f]+)\)\.\n"
        r"ckr[A-Za-z0-9_']* :: CULong\n"
        r"ckr[A-Za-z0-9_']* = CULong 0x([0-9A-Fa-f]+)")
    found = pat.findall(text)
    check(len(found) >= 1, "no documented CKR_ literals found (convention?)")
    for name, doc_hex, lit_hex in found:
        check(name in defs, f"{name}: not a locked-header CKR_")
        if name in defs:
            check(int(doc_hex, 16) == defs[name],
                  f"{name}: doc says 0x{doc_hex}, header says 0x{defs[name]:X}")
            check(int(lit_hex, 16) == defs[name],
                  f"{name}: literal says 0x{lit_hex}, header says 0x{defs[name]:X}")
    # Every bare CULong hex literal in the module must be covered by
    # the convention above (no undocumented numerics).
    all_lits = set(re.findall(r"CULong 0x([0-9A-Fa-f]+)", text))
    covered = {lit for _, _, lit in found}
    norm = lambda h: h.lower().lstrip("0") or "0"
    uncovered = {h for h in all_lits if norm(h) not in {norm(c) for c in covered}}
    check(not uncovered, f"undocumented CULong literals: {sorted(uncovered)}")

    if failures:
        print("ckr: INVALID", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"ckr: OK ({len(found)} literals match the locked headers)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
