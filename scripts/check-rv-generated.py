#!/usr/bin/env python3
"""Single-authority return-value gate: every served provider CK_RV has
one constructor, one generated mapping arm, and header-parity.

Inputs: spec/return-codes.json (the name list, append-only),
core/Haskoki/ReturnCode/Generated.hs (generated type + returnCodeToRV),
cbits/rv_served.inc (generated static asserts), spec/vendor/pkcs11.h
(the numeric authority). Numerics flow headers -> generated files;
anything else is drift.

Checks:
  * three-way name equality: spec == type ctors == mapping arms;
  * numeric parity: mapping arms + .inc asserts == header #defines;
  * no duplicate returnCodeToRV mappings outside Generated.hs;
  * no `CULong 0x..` literals in production hs outside Generated.hs
    (the FFI literal shape; check-ckr.py keeps gating convention);
  * waitCode arms route via returnCodeToRV (no bare literals).
Tests + tests/c legs are oracles (literals allowed — they pin values
independently); ABI oracle pins are never rewritten by generators.
Scope is provider-authored codes only: application-callback RVs
passed through untouched (e.g. mutex callbacks can surface
CKR_MUTEX_BAD) and CLI-only trace values (CKR_DEVICE_ERROR in
scenario traces) are explicitly out of scope.

Usage: python3 scripts/check-rv-generated.py [--self-test]
"""

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "spec" / "return-codes.json"
GEN_HS = REPO / "core" / "Haskoki" / "ReturnCode" / "Generated.hs"
GEN_C = REPO / "cbits" / "rv_served.inc"
GEN_V = REPO / "cbits" / "rv_values.inc"
HDR = REPO / "spec" / "vendor" / "pkcs11.h"
PROD_HS = ["core", "src", "ffi", "app"]
VALUE_TUS = ["cbits/function_tables.c", "cbits/control_entry.c"]


def _hdr_vals():
    return {m.group(1): int(m.group(2), 16) for m in re.finditer(
        r"#define\s+(CKR_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)UL",
        HDR.read_text())}


CTOR_RE = r"^\s*[|=]\s*(CKR_[A-Z0-9_]+)"
ARM_RE = r"^\s*(CKR_[A-Z0-9_]+)\s*->\s*(0x[0-9A-Fa-f]+)\s*$"


def _generated_sets():
    text = GEN_HS.read_text()
    ctors = re.findall(CTOR_RE, text, re.M)
    arms = re.findall(ARM_RE, text, re.M)
    return ctors, [a for a, _ in arms], {a: int(v, 16) for a, v in arms}


def _inc_vals():
    return {m.group(1): int(m.group(2), 16) for m in re.finditer(
        r"_Static_assert\((CKR_[A-Z0-9_]+)\s*==\s*(0x[0-9A-Fa-f]+)UL",
        GEN_C.read_text())}


def _vals_vals():
    return {m.group(1): int(m.group(2), 16) for m in re.finditer(
        r"#define\s+(CKR_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)UL",
        GEN_V.read_text())}


def _hand_defines():
    locs = []
    for tu in VALUE_TUS:
        text = (REPO / tu).read_text()
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        for i, line in enumerate(text.splitlines(), 1):
            line = re.sub(r"//[^\n]*", "", line)
            if re.search(r"#define\s+CKR_[A-Z0-9_]+", line):
                locs.append("%s:%d" % (tu, i))
    return locs


def _prod_lits():
    """Enumerated bypass shapes outside Generated.hs.

    Deliberately NOT a general numeric-literal ban: masks, tags, and
    struct zeros share the shape. Each shape below is an observed
    bypass with its legitimate uses migrated.
    """
    dup_maps, culong_lits, waitcode_lits = [], [], []
    for root in PROD_HS:
        for path in sorted((REPO / root).rglob("*.hs")):
            if path == GEN_HS:
                continue
            try:
                text = path.read_text()
            except (OSError, UnicodeDecodeError):
                continue
            rel = str(path.relative_to(REPO))
            if re.search(r"^returnCodeToRV\s*(::|\w+\s*=)", text, re.M):
                dup_maps.append(rel)
            for i, line in enumerate(text.splitlines(), 1):
                s = line.strip()
                if "poke " in s:
                    continue  # struct init, not a return value
                if re.search(r"CULong\s*\(?\s*(0x[0-9A-Fa-f]+|\d+)", s):
                    culong_lits.append("%s:%d" % (rel, i))
    events = REPO / "src" / "Haskoki" / "Runtime" / "Events.hs"
    for i, line in enumerate(events.read_text().splitlines(), 1):
        s = line.strip()
        if s.startswith("waitCode ") and " = " in s and "::" not in s \
                and "returnCodeToRV" not in s:
            waitcode_lits.append("Events.hs:%d" % i)
    return dup_maps, culong_lits, waitcode_lits


def validate(spec_names, ctors, arms, arm_vals, inc_vals, hdr_vals,
             dup_maps, culong_lits, waitcode_lits, vals_vals=None,
             hand_defs=None):
    """Returns error strings (empty means single-authority holds)."""
    errs = []
    if len(ctors) != len(set(ctors)):
        errs.append("duplicate type ctors")
    if len(arms) != len(set(arms)):
        errs.append("duplicate mapping arms")
    if set(ctors) != set(spec_names):
        errs.append("type ctors != spec names: +%s -%s" % (
            sorted(set(ctors) - set(spec_names)),
            sorted(set(spec_names) - set(ctors))))
    if set(arms) != set(spec_names):
        errs.append("mapping arms != spec names: +%s -%s" % (
            sorted(set(arms) - set(spec_names)),
            sorted(set(spec_names) - set(arms))))
    if set(inc_vals) != set(spec_names):
        errs.append("inc asserts != spec names: +%s -%s" % (
            sorted(set(inc_vals) - set(spec_names)),
            sorted(set(spec_names) - set(inc_vals))))
    for c in spec_names:
        if c in arm_vals and c in hdr_vals and arm_vals[c] != hdr_vals[c]:
            errs.append("mapping %s = %#x, header %#x"
                        % (c, arm_vals[c], hdr_vals[c]))
        if c in inc_vals and c in hdr_vals and inc_vals[c] != hdr_vals[c]:
            errs.append("inc %s = %#x, header %#x"
                        % (c, inc_vals[c], hdr_vals[c]))
    for loc in dup_maps:
        errs.append("duplicate returnCodeToRV mapping: %s" % loc)
    for loc in culong_lits:
        errs.append("numeric RV literal (use the generated mapping): %s"
                    % loc)
    for loc in waitcode_lits:
        errs.append("waitCode arm bypasses the mapping: %s" % loc)
    for name, val in (vals_vals or {}).items():
        base = name[:-len("_INSTANCE")] if name.endswith("_INSTANCE") \
            else name
        if base not in hdr_vals:
            errs.append("values %s has no locked-header spelling" % name)
        elif val != hdr_vals[base]:
            errs.append("values %s = %#x, header %#x"
                        % (name, val, hdr_vals[base]))
    for loc in hand_defs or []:
        errs.append("hand CKR_ define (use rv_values.inc): %s" % loc)
    return errs


def run_gate():
    for p in (SPEC, GEN_HS, GEN_C, GEN_V, HDR):
        if not p.exists():
            print("FAIL: %s missing" % p.relative_to(REPO))
            return 1
    try:
        spec_names = json.loads(SPEC.read_text())["codes"]
    except (json.JSONDecodeError, KeyError, OSError) as e:
        print("FAIL: cannot parse spec: %s" % e)
        return 1
    ctors, arms, arm_vals = _generated_sets()
    errs = validate(spec_names, ctors, arms, arm_vals, _inc_vals(),
                    _hdr_vals(), *_prod_lits(), _vals_vals(),
                    _hand_defines())
    for e in errs:
        print("FAIL: " + e)
    if errs:
        return 1
    print("rv-generated: ok (%d codes, single authority)"
          % len(spec_names))
    return 0


def self_test():
    bad = []

    def expect(name, errs, want_fail):
        nonlocal bad
        failed = len(errs) > 0
        ok = failed == want_fail
        print("%s %s: %s" % ("ok  " if ok else "FAIL", name,
                             "" if ok else errs))
        if not ok:
            bad.append(name)

    good = dict(spec_names=["CKR_OK", "CKR_FOO"],
                ctors=["CKR_OK", "CKR_FOO"],
                arms=["CKR_OK", "CKR_FOO"],
                arm_vals={"CKR_OK": 0, "CKR_FOO": 7},
                inc_vals={"CKR_OK": 0, "CKR_FOO": 7},
                hdr_vals={"CKR_OK": 0, "CKR_FOO": 7},
                dup_maps=[], culong_lits=[], waitcode_lits=[],
                vals_vals={"CKR_OK": 0, "CKR_FOO_INSTANCE": 7},
                hand_defs=[])
    expect("valid-triple", validate(**good), False)

    v = dict(good)
    v["ctors"] = ["CKR_OK", "CKR_FOO", "CKR_BAR"]
    expect("unmapped-ctor", validate(**v), True)

    v = dict(good)
    v["arms"] = ["CKR_OK", "CKR_FOO", "CKR_BAR"]
    expect("extra-arm", validate(**v), True)

    v = dict(good)
    v["arm_vals"] = {"CKR_OK": 0, "CKR_FOO": 8}
    expect("mapping-drift", validate(**v), True)

    v = dict(good)
    v["inc_vals"] = {"CKR_OK": 0, "CKR_FOO": 8}
    expect("inc-drift", validate(**v), True)

    v = dict(good)
    v["dup_maps"] = ["src/Other.hs"]
    expect("duplicate-mapping", validate(**v), True)

    v = dict(good)
    v["culong_lits"] = ["ffi/X.hs:12"]
    expect("culong-literal", validate(**v), True)

    v = dict(good)
    v["waitcode_lits"] = ["0x00000008"]
    expect("waitcode-literal", validate(**v), True)

    v = dict(good)
    v["arms"] = ["CKR_OK", "CKR_FOO", "CKR_FOO"]
    expect("duplicate-arm", validate(**v), True)

    v = dict(good)
    v["ctors"] = ["CKR_OK", "CKR_OK", "CKR_FOO"]
    expect("duplicate-ctor", validate(**v), True)

    v = dict(good)
    v["inc_vals"] = {"CKR_OK": 0}
    expect("inc-missing", validate(**v), True)

    v = dict(good)
    v["inc_vals"] = {"CKR_OK": 0, "CKR_FOO": 7, "CKR_BAR": 9}
    expect("inc-extra", validate(**v), True)

    v = dict(good)
    v["vals_vals"] = {"CKR_OK": 1}
    expect("values-drift", validate(**v), True)

    v = dict(good)
    v["hand_defs"] = ["cbits/function_tables.c:129"]
    expect("hand-define", validate(**v), True)

    ok = re.findall(ARM_RE, "  CKR_OK -> 0x00000000 + 1\n", re.M) == []
    print("%s arithmetic-arm-rejected: %s" % ("ok  " if ok else "FAIL", ""))
    if not ok:
        bad.append("arithmetic-arm-rejected")

    if bad:
        return 1
    print("rv-generated self-test: ok")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(run_gate())
