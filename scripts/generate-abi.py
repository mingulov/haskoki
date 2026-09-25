#!/usr/bin/env python3
"""Generate versioned PKCS#11 ABI artifacts from the byte-locked sources.

Reads:
  spec/sources.lock.json          byte lock (SHA-256 of the one header)
  spec/vendor/pkcs11.h         pinned latchset public-domain v3.2
                                  header, single-file form (the only
                                  generation input; older interfaces are
                                  positional prefixes of its order)
  spec/planning/functions.csv     104-row planning seed (reconciliation
                                  only), vendored for hermetic generation

Writes (deterministic bytes, no timestamps):
  spec/abi-inventory.json         ordered functions + prototypes + aliases
  spec/abi-reconciliation.json    planning-seed diff with per-row explanation
  cbits/abi_generated.h           counts/versions/X-macro tables for C consumers

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/generate-abi.py

Fails (nonzero exit) on: hash mismatch, missing input, order/count drift,
prefix-compatibility break, 3.1 layout drift, or any CK_FUNCTION_LIST_3_1
symbol (which must never be fabricated).

Header-form notes: the PD headers declare functions as `extern` block
entries (no CK_PKCS11_FUNCTION_INFO / CK_NEED_ARG_LIST idiom) with
UNNAMED parameters, so generated stubs synthesize positional parameter
names (p0, p1, ...). The PD headers carry no alias-style defines, so
constant_aliases records an empty map; the semantic same-value alias
knowledge lives in spec/mechanisms.json / spec/attributes.json (via
scripts/hdr_parse.py).
"""

import csv
import hashlib
import json
import re
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
SPEC = PKG / "spec"
LOCK_PATH = SPEC / "sources.lock.json"
CSV_PATH = SPEC / "planning" / "functions.csv"

# PD function entries: `extern CK_RV C_Name(...);` (possibly multi-line).
FUN_RE = re.compile(r"^extern\s+CK_RV\s+(C_[A-Za-z0-9]+)\s*\(", re.MULTILINE)
# Alias-style defines: #define NAME <OTHER_CK_IDENTIFIER> (no value literal).
ALIAS_RE = re.compile(r"#define\s+(CK[A-Z0-9_]+)\s+(CK[A-Z0-9_]+)\s*$")
# Value defines we record for aliases' canonical targets.
VALUE_RE = re.compile(r"#define\s+([A-Z][A-Z0-9_a-z]+)\s+(0x[0-9A-Fa-f]+U?L?|~0UL|0UL)\s*$")

LAYOUTS = {
    "2.40": "CK_FUNCTION_LIST",
    "3.0": "CK_FUNCTION_LIST_3_0",
    "3.1": "CK_FUNCTION_LIST_3_0",  # 3.1 reuses the 3.0 layout (SRC-05)
    "3.2": "CK_FUNCTION_LIST_3_2",
}
EXPECTED_COUNTS = {"2.40": 68, "3.0": 92, "3.1": 92, "3.2": 104}


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(msg):
    print(f"generate-abi: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_functions(f_path):
    """Return [(name, prototype_block)] in header order.

    Each prototype is the full `extern` declaration through its
    semicolon, whitespace-normalized. Parameters are unnamed in the
    PD form; stub() synthesizes positional names.
    """
    text = f_path.read_text(encoding="utf-8")
    out = []
    for m in FUN_RE.finditer(text):
        name = m.group(1)
        end = text.find(";", m.end())
        if end == -1:
            fail(f"{f_path}: unterminated declaration for {name}")
        block = text[m.start():end + 1].strip()
        block = re.sub(r"[ \t]+", " ", block)
        block = re.sub(r"\n\s*", "\n", block)
        out.append((name, block))
    if not out:
        fail(f"{f_path}: parsed zero functions")
    # Duplicate-name guard (A41 alias hygiene at the function level).
    names = [n for n, _ in out]
    if len(set(names)) != len(names):
        dupes = sorted({n for n in names if names.count(n) > 1})
        fail(f"{f_path}: duplicate function entries: {dupes}")
    return out


def parse_aliases(t_path):
    """Return {alias: canonical} plus {name: value} for value defines."""
    aliases, values = {}, {}
    for line in t_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        m = ALIAS_RE.match(line)
        if m and not re.match(r"(0x|~0|0U|\()", m.group(2)):
            aliases[m.group(1)] = m.group(2)
            continue
        m = VALUE_RE.match(line)
        if m:
            values[m.group(1)] = m.group(2)
    # Resolve chains (alias -> alias -> value) one level for reporting.
    resolved = {}
    for alias, target in aliases.items():
        seen = {alias}
        while target in aliases and target not in seen:
            seen.add(target)
            target = aliases[target]
        resolved[alias] = {"canonical": target,
                           "value": values.get(target)}
    return resolved


def main():
    try:
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing {LOCK_PATH}")
    except json.JSONDecodeError as e:
        fail(f"{LOCK_PATH} is not valid JSON: {e}")

    # 1. Verify every locked file hash before generating anything.
    for entry in lock.get("files", []):
        for field in ("source_id", "publication_or_commit", "relative_path",
                      "sha256", "license_notice"):
            if field not in entry:
                fail(f"lock entry missing required field '{field}': {entry}")
        p = PKG / entry["relative_path"]
        if not p.is_file():
            fail(f"locked file missing: {entry['relative_path']}")
        actual = sha256_of(p)
        if actual != entry["sha256"]:
            fail(f"hash mismatch: {entry['relative_path']}\n"
                 f"  lock:   {entry['sha256']}\n  actual: {actual}")

    # 2. Forbid the fabricated 3.1 layout symbol in every vendored file.
    for entry in lock.get("files", []):
        text = (PKG / entry["relative_path"]).read_text(encoding="utf-8")
        if "CK_FUNCTION_LIST_3_1" in text:
            fail(f"fabricated CK_FUNCTION_LIST_3_1 in {entry['relative_path']}")

    sels = [e for e in lock.get("files", [])
            if e.get("role") == "selected"]
    if len(sels) != 1:
        fail(f"lock must select exactly one header, found {len(sels)}")
    vend = str(Path(sels[0]["relative_path"]).parent)
    pd_path = PKG / sels[0]["relative_path"]
    funcs = parse_functions(pd_path)
    if len(funcs) != 104:
        fail(f"{pd_path}: got {len(funcs)} functions, expected 104")
    # Boundary pins: the older interfaces are positional prefixes of
    # the 3.2 order (append-only evolution); any reorder fails loudly
    # here instead of silently mis-slicing.
    for ordinal, want in ((68, "C_WaitForSlotEvent"),
                          (92, "C_MessageVerifyFinal"),
                          (104, "C_UnwrapKeyAuthenticated")):
        if funcs[ordinal - 1][0] != want:
            fail(f"{pd_path}: position {ordinal} is "
                 f"{funcs[ordinal - 1][0]}, expected {want}")
    if funcs[0][0] != "C_Initialize":
        fail(f"{pd_path}: first function is {funcs[0][0]}, "
             f"expected C_Initialize")
    aliases = parse_aliases(pd_path)
    interfaces = {}
    for iface, layout in LAYOUTS.items():
        sliced = funcs[:EXPECTED_COUNTS[iface]]
        interfaces[iface] = {
            "layout": layout,
            "vendor_dir": vend,
            "source_file": f"{vend}/pkcs11.h",
            "functions": [{"ordinal_1_based": i + 1, "name": name,
                           "header_symbol": f"CK_C_{name[2:]}"
                           if name.startswith("C_") else None,
                           "prototype": proto,
                           "source_file": f"{vend}/pkcs11.h"}
                          for i, (name, proto) in enumerate(sliced)],
            "aliases": aliases,
        }

    # 3. Prefix-compatibility + 3.1-layout assertions.
    n240 = [f["name"] for f in interfaces["2.40"]["functions"]]
    n300 = [f["name"] for f in interfaces["3.0"]["functions"]]
    n310 = [f["name"] for f in interfaces["3.1"]["functions"]]
    n320 = [f["name"] for f in interfaces["3.2"]["functions"]]
    if n300[:68] != n240:
        fail("3.0 prefix is not the 2.40 order")
    if n310 != n300:
        fail("3.1 order differs from 3.0 (3.1 must reuse the 3.0 layout)")
    if n320[:92] != n300:
        fail("3.2 prefix is not the 3.0 order")
    if n320[:68] != n240:
        fail("3.2 prefix is not the 2.40 order")

    # 4. Reconcile against the planning seed (read-only input).
    if not CSV_PATH.is_file():
        fail(f"planning seed not found: {CSV_PATH}")
    csv_sha = sha256_of(CSV_PATH)
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if len(rows) != 104:
        fail(f"planning seed has {len(rows)} rows, expected 104")

    reconciled = []
    n_added = n_removed = n_aliased = n_matched = 0
    header_by_name = {}
    for i, name in enumerate(n320):
        first = ("2.40" if i < 68 else "3.0" if i < 92 else "3.2")
        header_by_name[name] = (i + 1, first)
    csv_names = [r["function"] for r in rows]
    for r in rows:
        name = r["function"]
        want_ifaces = r["available_interfaces"].split(";")
        if name not in header_by_name:
            status, expl = "removed", (
                f"planning seed lists {name} (ordinal {r['ordinal_1_based']}) "
                f"but the selected header does not declare it; dropped as not "
                f"source-backed (no invented ABI entry).")
            n_removed += 1
        else:
            gen_ord, first = header_by_name[name]
            exp_first_layout = ("CK_FUNCTION_LIST" if first == "2.40"
                                else "CK_FUNCTION_LIST_3_0" if first == "3.0"
                                else "CK_FUNCTION_LIST_3_2")
            exp_ifaces = {"2.40": ["2.40", "3.0", "3.1", "3.2"],
                          "3.0": ["3.0", "3.1", "3.2"],
                          "3.2": ["3.2"]}[first]
            problems = []
            if int(r["ordinal_1_based"]) != gen_ord:
                problems.append(f"ordinal {r['ordinal_1_based']} vs header "
                                f"position {gen_ord}")
            if csv_names.index(name) != gen_ord - 1:
                problems.append("row order differs from header order")
            if want_ifaces != exp_ifaces:
                problems.append(f"interfaces {want_ifaces} vs {exp_ifaces}")
            if r["first_layout"] != exp_first_layout:
                problems.append(f"layout {r['first_layout']} vs "
                                f"{exp_first_layout}")
            if problems:
                status, expl = "aliased", (
                    f"{name}: planning metadata differs from generated "
                    f"truth ({'; '.join(problems)}); header truth wins.")
                n_aliased += 1
            else:
                status, expl = "matched", (
                    f"{name}: ordinal, order, interfaces and first layout "
                    f"match generated header truth.")
                n_matched += 1
        reconciled.append({"function": name,
                           "planning_ordinal": int(r["ordinal_1_based"]),
                           "generated_ordinal": header_by_name.get(name, (None,))[0],
                           "status": status, "explanation": expl})
    for i, name in enumerate(n320):
        if name not in csv_names:
            reconciled.append({"function": name, "planning_ordinal": None,
                               "generated_ordinal": i + 1, "status": "added",
                               "explanation": (
                                   f"{name}: declared by the selected header at "
                                   f"position {i + 1} but absent from the "
                                   f"planning seed; kept visible as a "
                                   f"header-only entry (A41).")})
            n_added += 1

    lock_sha = sha256_of(LOCK_PATH)
    inventory = {
        "schema_version": 1,
        "generated_by": "scripts/generate-abi.py (stdlib-only, deterministic)",
        "sources_lock_sha256": lock_sha,
        "interfaces": {
            iface: {"layout": d["layout"], "function_count": len(d["functions"]),
                    "vendor_dir": d["vendor_dir"], "source_file": d["source_file"],
                    "functions": d["functions"], "constant_aliases": d["aliases"]}
            for iface, d in interfaces.items()
        },
        "prefix_compatibility": {
            "3.0[:68] == 2.40": True,
            "3.1 == 3.0 (order and layout)": True,
            "3.2[:92] == 3.0": True,
            "3.2[:68] == 2.40": True,
        },
        "notes": [
            "Constant VALUES stay single-sourced in the pinned headers; only alias mappings are recorded here.",
            "No CK_FUNCTION_LIST_3_1 exists in any vendored family.",
        ],
    }
    reconciliation = {
        "schema_version": 1,
        "generated_by": "scripts/generate-abi.py",
        "planning_seed": str(CSV_PATH.relative_to(PKG)),
        "planning_seed_sha256": csv_sha,
        "summary": {"matched": n_matched, "added": n_added,
                    "removed": n_removed, "aliased": n_aliased},
        "rows": reconciled,
    }

    (SPEC / "abi-inventory.json").write_text(
        json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    (SPEC / "abi-reconciliation.json").write_text(
        json.dumps(reconciliation, indent=2) + "\n", encoding="utf-8")

    # 5. Generated C header: counts, versions, X-macro tables.
    def xmacro(title, names):
        lines = [f"/* {title} ({len(names)} entries, pinned order). */",
                 f"#define {title} \\"]
        for n in names:
            lines.append(f"  M({n}) \\")
        lines[-1] = lines[-1][:-2]  # drop trailing backslash
        lines.append("")
        return "\n".join(lines)

    h = []
    h.append("/* GENERATED by scripts/generate-abi.py - DO NOT EDIT.")
    h.append(" *")
    h.append(" * Versioned PKCS#11 ABI tables derived from the byte-locked")
    h.append(" * headers in spec/vendor/ (see spec/sources.lock.json).")
    h.append(" * Regenerate: python3 scripts/generate-abi.py")
    h.append(" *")
    h.append(" * Constant VALUES are intentionally not duplicated here; they")
    h.append(" * stay single-sourced in the pinned headers. This file carries")
    h.append(" * generated structure: counts, versions, and function order.")
    h.append(" */")
    h.append("#ifndef HASKOKI_ABI_GENERATED_H")
    h.append("#define HASKOKI_ABI_GENERATED_H")
    h.append("")
    h.append("/* Function counts per interface. */")
    h.append("#define HASKOKI_ABI_COUNT_240 68")
    h.append("#define HASKOKI_ABI_COUNT_300 92")
    h.append("#define HASKOKI_ABI_COUNT_310 92")
    h.append("#define HASKOKI_ABI_COUNT_320 104")
    h.append("")
    h.append("/* Interface versions. */")
    h.append("#define HASKOKI_ABI_240_MAJOR 2")
    h.append("#define HASKOKI_ABI_240_MINOR 40")
    h.append("#define HASKOKI_ABI_300_MAJOR 3")
    h.append("#define HASKOKI_ABI_300_MINOR 0")
    h.append("#define HASKOKI_ABI_310_MAJOR 3")
    h.append("#define HASKOKI_ABI_310_MINOR 1")
    h.append("#define HASKOKI_ABI_320_MAJOR 3")
    h.append("#define HASKOKI_ABI_320_MINOR 2")
    h.append("")
    h.append('/* Standard interface name (spec 3.1 section 5.4.6 example). */')
    h.append('#define HASKOKI_ABI_INTERFACE_NAME "PKCS 11"')
    h.append("")
    h.append("/* Number of versioned interfaces served via C_GetInterface. */")
    h.append("#define HASKOKI_ABI_INTERFACE_COUNT 3")
    h.append("")
    h.append(xmacro("HASKOKI_FOREACH_240(M)", n240))
    h.append(xmacro("HASKOKI_FOREACH_300_NEW(M)", n300[68:]))
    h.append(xmacro("HASKOKI_FOREACH_320_NEW(M)", n320[92:]))
    h.append("#endif /* HASKOKI_ABI_GENERATED_H */")
    (PKG / "cbits" / "abi_generated.h").write_text(
        "\n".join(h) + "\n", encoding="utf-8")

    # 6. Generated stub implementations + table-fill macros for exports.c.
    # Prototypes come from the selected header, so stub signatures can
    # never drift from the pinned truth. C_GetInterfaceList/C_GetInterface
    # are real globals (defined in exports.c); everything else new in 3.x
    # is a lifecycle-aware NOT_SUPPORTED stub.
    proto30 = {f["name"]: f["prototype"]
               for f in interfaces["3.0"]["functions"]}
    proto32 = {f["name"]: f["prototype"]
               for f in interfaces["3.2"]["functions"]}

    def stub(prefix, name, proto):
        # Uniform stub rule: generated 3.x stubs follow the uniform
        # stub-first precedence (same rule as the legacy stubs in
        # cbits/function_tables.c): void every parameter, return
        # liveness-then-NOT_SUPPORTED. Capability dominates
        # argument errors on every generated entry; when an entry
        # gains an implementation it leaves the stub generator for
        # a routed definition (gated: the STUB-UNIFORM-GEN/
        # STUB-UNIFORM-INC rules).
        # PD prototypes carry UNNAMED parameters, so each parameter
        # gets a positional name (p0, p1, ...); the types come
        # verbatim from the header, so signatures cannot drift.
        m = re.search(r"\((.*)\)\s*;\s*$", proto, re.DOTALL)
        if not m:
            fail(f"cannot parse arg list for stub {name}")
        argtext = re.sub(r"\s+", " ", m.group(1)).strip()
        if "(" in argtext or ")" in argtext:
            fail(f"nested parens in stub {name} args (function-pointer "
                 f"parameter not supported)")
        types = [t.strip() for t in argtext.split(",") if t.strip()]
        if types == ["void"]:
            types = []
        for t in types:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\s*\*+)?|void\s*\*+",
                                t):
                fail(f"cannot parse parameter type in stub {name}: {t!r}")
        params = [f"p{i}" for i in range(len(types))]
        sig = "(" + ", ".join(f"{t} {p}" for t, p in zip(types, params)) + ")"
        if not types:
            sig = "(void)"
        casts = "".join(f"  (void){p};\n" for p in params)
        return (f"static CK_DECLARE_FUNCTION(CK_RV, x{prefix}_{name})\n"
                f"{sig} {{\n"
                f"{casts}"
                f"  return x_live_check();\n"
                f"}}\n")

    def fillmacro(title, entries):
        lines = [f"/* {title}: assign post-2.40 entries of table pointer "
                 f"(T) in pinned order. */",
                 f"#define {title} \\",
                 "  do { \\"]
        for field, impl in entries:
            lines.append(f"    (T)->{field} = {impl}; \\")
        lines.append("  } while (0)")
        lines.append("")
        return "\n".join(lines)

    inc = []
    inc.append("/* GENERATED by scripts/generate-abi.py - DO NOT EDIT.")
    inc.append(" *")
    inc.append(" * Post-2.40 stub implementations with exact pinned-header")
    inc.append(" * prototypes, plus the table-fill macros wiring them (and the")
    inc.append(" * two discovery globals, plus routed definitions with a real")
    inc.append(" * implementation) into the versioned tables.")
    inc.append(" * Included only by cbits/exports.c, after x_live_check().")
    inc.append(" */")
    # Routed definitions: post-2.40 entries with a real implementation.
    # A routed entry leaves the stub generator (no x30_/x32_ body) and
    # the fill macro wires the table slot to its implementation; the
    # implementation TU owns the exact pinned prototype.
    routed300 = {"C_SessionCancel": "std_SessionCancel"}
    discrete300, discrete320 = [], []
    for name in n300[68:]:
        if name in ("C_GetInterfaceList", "C_GetInterface"):
            discrete300.append((name, name))
        elif name in routed300:
            discrete300.append((name, routed300[name]))
        else:
            inc.append(stub("30", name, proto30[name]))
            discrete300.append((name, f"x30_{name}"))
    for name in n320[92:]:
        inc.append(stub("32", name, proto32[name]))
        discrete320.append((name, f"x32_{name}"))
    inc.append(fillmacro("HASKOKI_FILL_300_NEW(T)", discrete300))
    inc.append(fillmacro("HASKOKI_FILL_320_NEW(T)", discrete320))
    (PKG / "cbits" / "abi_stubs.inc").write_text(
        "\n".join(inc), encoding="utf-8")

    print(f"generate-abi: PASS: 68/92/92/104 functions from locked sources; "
          f"reconciliation matched={n_matched} added={n_added} "
          f"removed={n_removed} aliased={n_aliased}")


if __name__ == "__main__":
    main()
