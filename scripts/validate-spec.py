#!/usr/bin/env python3
"""Validate the source lock, generated ABI artifacts and reconciliation.

Checks (all must pass):
  LOCK-FIELDS  every sources.lock.json entry has the required fields and its file
      exists with a matching SHA-256 (no fabricated hashes)
  LOCK-SELECTION  the lock selects exactly one header and the vendor
      tree holds exactly that file (OASIS/TC reintroduction tripwire)
  PD-LOCK  the locked file carries the public-domain marker and no
      OASIS text
  INVENTORY-FRESH  committed abi-inventory.json / abi-reconciliation.json match a fresh
      in-memory parse of the locked header (staleness check)
  SPOT-CHECKS  prototype-parse-independent spot checks (raw grep counts,
      first/last order; shares the generator's function-enumeration
      regex, so independence covers prototype parsing only)
  A40 every inventory function carries source evidence (prototype, header
      symbol, source file); missing evidence fails, nothing is invented
  A41 no duplicate names/ordinals; aliases resolve to valued canonicals;
      header-only rows stay visible with explanations
  ISSUES-VALID  source-issues.json is valid and resolves the 3.0 header warning
  GENERATED-HEADER  cbits/abi_generated.h counts and X-macro tables match the inventory
  NO-31-SYMBOL  no CK_FUNCTION_LIST_3_1 symbol anywhere in spec/cbits/ffi/tests/scripts

A40/A41 are acceptance-criteria IDs from the design inventory CSV, an
external namespace shared with spec/function-contracts.json -- kept
verbatim. The rest are local rule names.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/validate-spec.py
"""

import csv
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
SPEC = PKG / "spec"
LOCK_PATH = SPEC / "sources.lock.json"
INV_PATH = SPEC / "abi-inventory.json"
REC_PATH = SPEC / "abi-reconciliation.json"
ISSUES_PATH = SPEC / "source-issues.json"
GEN_H = PKG / "cbits" / "abi_generated.h"
CSV_PATH = (PKG.parent / "ws" / "docs" / "incoming"
            / "haskell-pkcs11-design" / "spec" / "inventory" / "functions.csv")

ERRORS = []


def err(check, msg):
    ERRORS.append(f"[{check}] {msg}")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path, check):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        err(check, f"missing file: {path.relative_to(PKG)}")
    except json.JSONDecodeError as e:
        err(check, f"{path.relative_to(PKG)} is not valid JSON: {e}")
    return None


def main():
    lock = load_json(LOCK_PATH, "LOCK-FIELDS")
    inv = load_json(INV_PATH, "INVENTORY-FRESH")
    rec = load_json(REC_PATH, "A41")
    issues = load_json(ISSUES_PATH, "ISSUES-VALID")
    if lock is None or inv is None or rec is None or issues is None:
        report()

    # ---- LOCK-FIELDS: required fields + hash verification ----
    required = ("source_id", "publication_or_commit", "relative_path",
                "sha256", "license_notice")
    for entry in lock.get("files", []):
        for field in required:
            if not entry.get(field):
                err("LOCK-FIELDS", f"entry missing/empty '{field}': {entry}")
        p = PKG / entry.get("relative_path", "")
        if p.is_file():
            actual = sha256_of(p)
            if actual != entry.get("sha256"):
                err("LOCK-FIELDS", f"hash mismatch: {entry.get('relative_path')}")
        else:
            err("LOCK-FIELDS", f"locked file missing: {entry.get('relative_path')}")

    # ---- LOCK-SELECTION: exactly one selected header ----
    sels = [e for e in lock.get("files", []) if e.get("role") == "selected"]
    if len(sels) != 1:
        err("LOCK-SELECTION",
            f"lock must select exactly one header, found {len(sels)}")
    for entry in lock.get("files", []):
        if entry.get("role") != "selected":
            err("LOCK-SELECTION",
                f"non-selected role {entry.get('role')!r} on "
                f"{entry.get('relative_path')} (single-header lock)")
    # OASIS/TC reintroduction tripwire: the vendor tree holds exactly
    # the one verbatim header, nothing else.
    vend_root = PKG / "spec" / "vendor"
    if vend_root.is_dir():
        got = sorted(p.name for p in vend_root.iterdir())
        if got != ["pkcs11.h"]:
            err("LOCK-SELECTION",
                f"spec/vendor/ holds {got}, want exactly ['pkcs11.h']")
        for p in sorted(vend_root.rglob("*")):
            if p.is_file() and p.name in ("pkcs11f.h", "pkcs11t.h"):
                err("LOCK-SELECTION",
                    f"OASIS-layout header reintroduced: "
                    f"{p.relative_to(PKG)}")
    hdr_rel = sels[0].get("relative_path", "") if sels else ""
    if hdr_rel != "spec/vendor/pkcs11.h":
        err("LOCK-SELECTION",
            f"selected header is {hdr_rel!r}, want 'spec/vendor/pkcs11.h'")

    # ---- PD-LOCK: public-domain marker ----
    for entry in lock.get("files", []):
        p = PKG / entry.get("relative_path", "")
        if not p.is_file():
            continue  # LOCK-FIELDS reports the missing file
        text = p.read_text(encoding="utf-8")
        if "This file is in the Public Domain" not in text:
            err("PD-LOCK",
                f"{entry.get('relative_path')}: public-domain marker "
                f"missing (not a verbatim latchset PD header?)")
        if "OASIS" in text or "oasis-open" in text:
            err("PD-LOCK",
                f"{entry.get('relative_path')}: OASIS text inside a "
                f"locked PD header")

    # ---- INVENTORY-FRESH: staleness — fresh parse must equal committed inventory ----
    gen_spec = importlib.util.spec_from_file_location(
        "gen_abi", PKG / "scripts" / "generate-abi.py")
    gen = importlib.util.module_from_spec(gen_spec)
    gen_spec.loader.exec_module(gen)
    try:
        funcs = gen.parse_functions(PKG / "spec" / "vendor" / "pkcs11.h")
        fresh = [n for n, _ in funcs]
    except SystemExit as e:
        err("INVENTORY-FRESH", f"generator failed during validation parse (exit {e.code})")
        fresh = []
    slices = {"2.40": 68, "3.0": 92, "3.1": 92, "3.2": 104}
    for iface, count in slices.items():
        committed = [f["name"] for f in
                     inv.get("interfaces", {}).get(iface, {}).get("functions", [])]
        if committed != fresh[:count]:
            err("INVENTORY-FRESH", f"{iface}: committed inventory order/count differs from "
                      f"fresh header parse (re-run generate-abi.py)")
    if inv.get("sources_lock_sha256") != sha256_of(LOCK_PATH):
        err("INVENTORY-FRESH", "abi-inventory.json was generated from a different lock "
                  "revision (re-run generate-abi.py)")

    # ---- SPOT-CHECKS: prototype-parse-independent spot checks ----
    text = (PKG / "spec" / "vendor" / "pkcs11.h").read_text(encoding="utf-8")
    found = re.findall(r"^extern\s+CK_RV\s+(C_[A-Za-z0-9]+)\s*\(",
                       text, re.MULTILINE)
    if len(found) != 104:
        err("SPOT-CHECKS", f"raw count {len(found)} != 104")
    boundaries = ((1, "C_Initialize"), (68, "C_WaitForSlotEvent"),
                  (92, "C_MessageVerifyFinal"),
                  (104, "C_UnwrapKeyAuthenticated"))
    for ordinal, want in boundaries:
        if len(found) < ordinal or found[ordinal - 1] != want:
            got = found[ordinal - 1] if len(found) >= ordinal else "?"
            err("SPOT-CHECKS", f"position {ordinal} is {got}, want {want}")

    # ---- A40: source evidence for every function ----
    header_union = set(found)
    for iface, data in inv.get("interfaces", {}).items():
        seen_names, seen_ord = set(), set()
        for f in data.get("functions", []):
            name = f.get("name", "")
            if not f.get("prototype"):
                err("A40", f"{iface} {name}: missing prototype evidence")
            if not f.get("header_symbol"):
                err("A40", f"{iface} {name}: missing header symbol")
            if not f.get("source_file"):
                err("A40", f"{iface} {name}: missing source file")
            if name not in header_union:
                err("A40", f"{iface} {name}: not declared by the locked "
                           f"header (invented entry)")
            if name in seen_names:
                err("A41", f"{iface}: duplicate function name {name}")
            seen_names.add(name)
            if f.get("ordinal_1_based") in seen_ord:
                err("A41", f"{iface}: duplicate ordinal {f.get('ordinal_1_based')}")
            seen_ord.add(f.get("ordinal_1_based"))
        for alias, info in data.get("constant_aliases", {}).items():
            if not info.get("canonical"):
                err("A41", f"{iface}: alias {alias} has no canonical target")
            if alias == info.get("canonical"):
                err("A41", f"{iface}: alias {alias} maps to itself")
            if not info.get("value"):
                err("A41", f"{iface}: alias {alias} has no recorded value")

    # ---- A41: reconciliation hygiene ----
    rows = rec.get("rows", [])
    summary = rec.get("summary", {})
    for key in ("matched", "added", "removed", "aliased"):
        actual = sum(1 for r in rows if r.get("status") == key)
        if summary.get(key) != actual:
            err("A41", f"reconciliation summary {key}={summary.get(key)} "
                       f"but rows show {actual}")
    for r in rows:
        if r.get("status") not in ("matched", "added", "removed", "aliased"):
            err("A41", f"row {r.get('function')}: bad status {r.get('status')}")
        if not r.get("explanation"):
            err("A41", f"row {r.get('function')}: missing explanation")
    if CSV_PATH.is_file():
        if sha256_of(CSV_PATH) != rec.get("planning_seed_sha256"):
            err("A41", "planning seed changed since reconciliation "
                       "(re-run generate-abi.py)")
        with open(CSV_PATH, newline="", encoding="utf-8") as f:
            if sum(1 for _ in csv.DictReader(f)) != 104:
                err("A41", "planning seed is no longer 104 rows")
    else:
        err("A41", f"planning seed not found: {CSV_PATH}")

    # ---- ISSUES-VALID: issue register ----
    by_id = {i.get("id"): i for i in issues.get("issues", [])}
    src01 = by_id.get("SRC-01")
    if src01 is None:
        err("ISSUES-VALID", "missing SRC-01 (3.0 header warning resolution)")
    elif src01.get("status") != "resolved":
        err("ISSUES-VALID", "SRC-01 (3.0 header warning) is not resolved")
    for i in issues.get("issues", []):
        for field in ("id", "title", "status", "sources", "inconsistency",
                      "affected", "decision", "scope", "tests",
                      "blocks_completeness"):
            if field not in i:
                err("ISSUES-VALID", f"issue {i.get('id')}: missing field '{field}'")

    # ---- GENERATED-HEADER: generated C header + stubs ----
    GEN_INC = PKG / "cbits" / "abi_stubs.inc"
    if GEN_INC.is_file():
        inc = GEN_INC.read_text(encoding="utf-8")
        if inc.count("static CK_DECLARE_FUNCTION(CK_RV, x30_") != 22:
            err("GENERATED-HEADER", "abi_stubs.inc does not define exactly 22 x30_ stubs")
        if inc.count("static CK_DECLARE_FUNCTION(CK_RV, x32_") != 12:
            err("GENERATED-HEADER", "abi_stubs.inc does not define exactly 12 x32_ stubs")
        m = re.search(r"#define HASKOKI_FILL_300_NEW.*?\} while \(0\)",
                      inc, re.DOTALL)
        if not m or m.group(0).count("(T)->C_") != 24:
            err("GENERATED-HEADER", "HASKOKI_FILL_300_NEW does not wire 24 entries")
        m = re.search(r"#define HASKOKI_FILL_320_NEW.*?\} while \(0\)",
                      inc, re.DOTALL)
        if not m or m.group(0).count("(T)->C_") != 12:
            err("GENERATED-HEADER", "HASKOKI_FILL_320_NEW does not wire 12 entries")
    else:
        err("GENERATED-HEADER", "missing cbits/abi_stubs.inc (run generate-abi.py)")
    if GEN_H.is_file():
        h = GEN_H.read_text(encoding="utf-8")
        for macro, want in (("HASKOKI_ABI_COUNT_240", "68"),
                            ("HASKOKI_ABI_COUNT_300", "92"),
                            ("HASKOKI_ABI_COUNT_310", "92"),
                            ("HASKOKI_ABI_COUNT_320", "104")):
            m = re.search(rf"#define {macro} (\d+)", h)
            if not m or m.group(1) != want:
                err("GENERATED-HEADER", f"{macro} != {want} in abi_generated.h")
        for macro, want in (("HASKOKI_FOREACH_240", 68),
                            ("HASKOKI_FOREACH_300_NEW", 24),
                            ("HASKOKI_FOREACH_320_NEW", 12)):
            m = re.search(rf"#define {macro}.*?(?=#define|\Z)", h, re.DOTALL)
            got = m.group(0).count("M(C_") if m else -1
            if got != want:
                err("GENERATED-HEADER", f"{macro} lists {got} entries, expected {want}")
    else:
        err("GENERATED-HEADER", "missing cbits/abi_generated.h (run generate-abi.py)")

    # ---- NO-31-SYMBOL: the 3.1 layout symbol must never be fabricated ----
    # C/Haskell sources: any occurrence fails. JSON docs may DISCUSS the
    # symbol in prose (decision SRC-05) but must never use it structurally.
    for top in ("spec", "cbits", "ffi", "tests", "scripts"):
        d = PKG / top
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if "CK_FUNCTION_LIST_3_1" not in text:
                continue
            if p.suffix in (".c", ".h", ".hs", ".hsc", ".inc", ".sh"):
                err("NO-31-SYMBOL", f"fabricated CK_FUNCTION_LIST_3_1 in "
                          f"{p.relative_to(PKG)}")
            elif p.suffix == ".json":
                if re.search(r'"(?:first_)?layout"\s*:\s*'
                             r'"CK_FUNCTION_LIST_3_1"', text):
                    err("NO-31-SYMBOL", f"structural CK_FUNCTION_LIST_3_1 in "
                              f"{p.relative_to(PKG)}")
            # .py self-reference (this check) and .json prose are allowed.

    report()


def report():
    if ERRORS:
        print("validate-spec: FAIL:", file=sys.stderr)
        for e in ERRORS:
            print(f"  {e}", file=sys.stderr)
        sys.exit(1)
    print("validate-spec: PASS: lock, inventory, reconciliation, "
          "generated header, issue register")
    sys.exit(0)


if __name__ == "__main__":
    main()
