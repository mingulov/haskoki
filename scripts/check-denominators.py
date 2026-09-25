#!/usr/bin/env python3
"""Denominator gate: headers <-> JSON byte-exact verification.

Verifies, against the byte-locked SELECTED headers (never the
rejected set):
  * every header CKM/CKA/CKO/CKK name is catalogued in
    spec/mechanisms.json / spec/attributes.json with a byte-exact
    numeric ID (no missing names, no invented names, no ID drift);
  * spec/function-contracts.json names exactly the 104 3.2-layout
    functions from spec/abi-inventory.json;
  * the Haskell DenominatorSpec counting method is sound: quoted
    CKX_/C_ sequences appear ONLY in the catalogued-name fields, and
    their totals equal the denominators (464+16, 158+2, 13+0, 67+2,
    104);
  * core/Haskoki/Registry/Generated.hs carries exactly the JSON
    inventory (headers -> JSON -> Haskell closure);
  * generator idempotency: re-running the three generators changes
    zero bytes in the six generated artifacts.

Usage: python3 scripts/check-denominators.py   (from haskoki/)
"""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hdr_parse  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "spec"
MECH_PATH = SPEC / "mechanisms.json"
ATTR_PATH = SPEC / "attributes.json"
FUNC_PATH = SPEC / "function-contracts.json"
ABI_PATH = SPEC / "abi-inventory.json"
HS_PATH = REPO / "core" / "Haskoki" / "Registry" / "Generated.hs"

failures = []


def fail(msg):
    failures.append(msg)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fmt_id(value):
    return "0x%08x" % value


def check_header_names(catalog, prefix, entries, label):
    """entries: list of (canonical, [aliases], numeric_id). catalog maps
    every header name -> (value, ifaces)."""
    seen = {}
    for canon, aliases, nid in entries:
        for name in [canon] + aliases:
            if name in seen:
                fail(f"{label}: {name} catalogued twice")
            seen[name] = nid
    want = {n for n in catalog if n.startswith(prefix)}
    if set(seen) != want:
        missing = sorted(want - set(seen))
        extra = sorted(set(seen) - want)
        if missing:
            fail(f"{label}: {len(missing)} header names missing: "
                 f"{missing[:8]}{'...' if len(missing) > 8 else ''}")
        if extra:
            fail(f"{label}: {len(extra)} invented names: "
                 f"{extra[:8]}{'...' if len(extra) > 8 else ''}")
    for name, nid in seen.items():
        if name in catalog and nid != fmt_id(catalog[name]["value"]):
            fail(f"{label}: {name} id {nid} != header "
                 f"{fmt_id(catalog[name]['value'])}")


def check_counting_discipline(path, prefix, want_canon, want_total,
                              allow_rules=False):
    """Prove the DenominatorSpec substring counts are sound: every
    quoted PREFIX occurrence sits on a canonical_name, aliases, or
    (attributes.json only, allow_rules) template-rule reference line,
    and the totals match."""
    text = path.read_text()
    canon_tag = f'"canonical_name": "{prefix}'
    n_canon = text.count(canon_tag)
    n_total = text.count(f'"{prefix}')
    if n_canon != want_canon:
        fail(f"{path.name}: canonical {prefix} count {n_canon}, want "
             f"{want_canon}")
    if n_total != want_total:
        fail(f"{path.name}: total quoted {prefix} count {n_total}, want "
             f"{want_total}")
    alias_line = re.compile(rf'^\s*"{prefix}[A-Z0-9_]+"\,?$')
    rule_ref = re.compile(rf'^\s*"(class|key_type)": "{prefix}[A-Z0-9_]+"\,?$')
    for lineno, line in enumerate(text.splitlines(), start=1):
        if f'"{prefix}' not in line:
            continue
        if canon_tag in line:
            continue
        if alias_line.match(line):
            # Bare-name array element: aliases, or (attributes.json)
            # required/forbidden rule refs. Totals are pinned exactly,
            # so any drift fails loudly; rule refs are additionally
            # validated against the header name sets by
            # check-attributes.py.
            continue
        if allow_rules and rule_ref.match(line):
            continue
        fail(f"{path.name}:{lineno}: quoted {prefix} outside "
             f"canonical/aliases/rules: {line.strip()[:80]}")


def main():
    _tables, provenance = hdr_parse.catalog_tables()

    # --- mechanisms.json ---
    try:
        mechs = json.loads(MECH_PATH.read_text())["mechanisms"]
    except Exception as e:  # noqa: BLE001 - reported, not hidden
        print(f"denominators: cannot parse {MECH_PATH}: {e}", file=sys.stderr)
        return 1
    check_header_names(
        provenance, "CKM_",
        [(m["canonical_name"], m["aliases"], m["numeric_id"]) for m in mechs],
        "mechanisms.json")
    check_counting_discipline(MECH_PATH, "CKM_", 464, 480)

    # --- attributes.json ---
    try:
        attrs = json.loads(ATTR_PATH.read_text())
    except Exception as e:  # noqa: BLE001
        print(f"denominators: cannot parse {ATTR_PATH}: {e}", file=sys.stderr)
        return 1
    check_header_names(
        provenance, "CKA_",
        [(m["canonical_name"], m["aliases"], m["numeric_id"])
         for m in attrs.get("attributes", [])],
        "attributes.json/attributes")
    check_header_names(
        provenance, "CKO_",
        [(m["canonical_name"], m["aliases"], m["numeric_id"])
         for m in attrs.get("classes", [])],
        "attributes.json/classes")
    check_header_names(
        provenance, "CKK_",
        [(m["canonical_name"], m["aliases"], m["numeric_id"])
         for m in attrs.get("key_types", [])],
        "attributes.json/key_types")
    # Template-rule refs: 8 CKA (required), 4 CKO (class), 4 CKK (key_type).
    check_counting_discipline(ATTR_PATH, "CKA_", 158, 170, allow_rules=True)
    check_counting_discipline(ATTR_PATH, "CKO_", 13, 17, allow_rules=True)
    check_counting_discipline(ATTR_PATH, "CKK_", 67, 73, allow_rules=True)

    # --- function-contracts.json vs 3.2 layout ---
    try:
        contracts = json.loads(FUNC_PATH.read_text())["functions"]
    except Exception as e:  # noqa: BLE001
        print(f"denominators: cannot parse {FUNC_PATH}: {e}", file=sys.stderr)
        return 1
    try:
        abi = json.loads(ABI_PATH.read_text())
        names32 = [f["name"] for f in abi["interfaces"]["3.2"]["functions"]]
    except Exception as e:  # noqa: BLE001
        print(f"denominators: cannot parse {ABI_PATH}: {e}", file=sys.stderr)
        return 1
    cnames = [c["name"] for c in contracts]
    if cnames != names32:
        fail("function-contracts.json names/order != 3.2 layout")
    text = FUNC_PATH.read_text()
    if text.count('"name": "C_') != 104:
        fail("function-contracts.json: C_ name count != 104")
    # Soundness of the Haskell count: no other quoted C_ sequences.
    for lineno, line in enumerate(text.splitlines(), start=1):
        if '"C_' not in line:
            continue
        if '"name": "C_' in line:
            continue
        fail(f"function-contracts.json:{lineno}: quoted C_ outside "
             f"name field: {line.strip()[:80]}")
    # Planner-scope wording: the behavior label claims
    # planner/in-process reachability, never C-table routing.
    # 63 -> 66 -> 67 -> 68; the session-info rows reclassified
    # first, then C_DigestKey (routed via the digest-update
    # planner), then C_SetAttributeValue (routed via the object
    # planner with executed consumer evidence).
    if text.count('"contract": "planned-with-behavior"') != 68:
        fail("function-contracts.json: planned-with-behavior count != 68")
    # The three reclassified rows stay planned with
    # executed evidence (the stale "no behavior test" reasons stay gone).
    for _name in ("C_GetSessionInfo", "C_GetSlotInfo", "C_GetTokenInfo"):
        _row = next((c for c in contracts if c["name"] == _name), None)
        if _row is None:
            fail(f"function-contracts.json: missing row {_name}")
        elif _row.get("contract") != "planned-with-behavior":
            fail(f"function-contracts.json: {_name} not reclassified "
                 f"(saw {_row.get('contract')})")
        elif not _row.get("test_evidence"):
            fail(f"function-contracts.json: {_name} planned without evidence")
    if "routed-with-behavior" in text:
        fail("function-contracts.json: stale routed-with-behavior label")
    if "planner/in-process reachability, NOT C-table routing" not in text:
        fail("function-contracts.json: planner-scope note missing")

    # --- Generated.hs closure ---
    if not HS_PATH.exists():
        fail(f"missing {HS_PATH.relative_to(REPO)}")
    else:
        hs = HS_PATH.read_text()
        rows = re.findall(r'\(0x([0-9a-f]+),\s*"((?:CKM_[A-Z0-9_]+))",\s*\[(.*?)\]\)', hs)
        if len(rows) != 464:
            fail(f"Generated.hs has {len(rows)} rows, want 464")
        hs_map = {}
        for val, canon, aliases in rows:
            als = re.findall(r'"(CKM_[A-Z0-9_]+)"', aliases)
            hs_map[canon] = (f"0x{int(val, 16):08x}", sorted(als))
        json_map = {m["canonical_name"]: (m["numeric_id"], sorted(m["aliases"]))
                    for m in mechs}
        if hs_map != json_map:
            only_hs = sorted(set(hs_map) - set(json_map))[:5]
            only_json = sorted(set(json_map) - set(hs_map))[:5]
            mism = sorted(n for n in set(hs_map) & set(json_map)
                          if hs_map[n] != json_map[n])[:5]
            fail(f"Generated.hs != mechanisms.json (hs-only={only_hs} "
                 f"json-only={only_json} mismatched={mism})")

    # --- Attribute/Generated.hs closure ---
    attr_hs = REPO / "core" / "Haskoki" / "Attribute" / "Generated.hs"
    if not attr_hs.exists():
        fail(f"missing {attr_hs.relative_to(REPO)}")
    else:
        hs = attr_hs.read_text()
        # Attribute/class/key-type rows: (0xHEX, "CKX_NAME", [...]).
        for prefix, block in (("CKA_", "attributes"), ("CKO_", "classes"),
                              ("CKK_", "key_types")):
            rows = re.findall(r'\(0x([0-9a-f]+),\s*"(' + prefix +
                              r'[A-Z0-9_]+)",\s*\[(.*?)\]\)', hs)
            want = {m["canonical_name"]: (m["numeric_id"], sorted(m["aliases"]))
                    for m in attrs.get(block, [])}
            if len(rows) != len(want):
                fail(f"Attribute/Generated.hs {block} rows {len(rows)}, "
                     f"want {len(want)}")
            hs_map = {}
            for val, canon, aliases in rows:
                als = re.findall(r'"(' + prefix + r'[A-Z0-9_]+)"', aliases)
                hs_map[canon] = (f"0x{int(val, 16):08x}", sorted(als))
            if hs_map != want:
                mism = sorted(n for n in set(hs_map) & set(want)
                              if hs_map[n] != want[n])[:5]
                fail(f"Attribute/Generated.hs {block} != attributes.json "
                     f"(mismatched={mism})")
        # Rule rows: ("CKO_X", Just "CKK_Y", [...], [...]).
        hrules = re.findall(r'\("(CKO_[A-Z0-9_]+)",\s*(Just "(CKK_[A-Z0-9_]+)"|Nothing),\s*\[(.*?)\],\s*\[(.*?)\]\)', hs)
        jrules = attrs.get("template_rules", [])
        if len(hrules) != len(jrules):
            fail(f"Attribute/Generated.hs rules {len(hrules)} != json "
                 f"{len(jrules)}")
        else:
            for (hcls, _j, hkt, hreq, hfrb), jrule in zip(hrules, jrules):
                same = (hcls == jrule["class"]
                        and (hkt or None) == jrule["key_type"]
                        and re.findall(r'"(CKA_[A-Z0-9_]+)"', hreq) == jrule["required"]
                        and re.findall(r'"(CKA_[A-Z0-9_]+)"', hfrb) == jrule["forbidden"])
                if not same:
                    fail(f"Attribute/Generated.hs rule {hcls}/{hkt} != json")

    # --- idempotency: re-run generators, expect zero byte changes ---
    if failures:
        print("denominators: INVALID (skipping idempotency)", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    inc_h = REPO / "cbits" / "mech_catalog.inc"
    artifacts = [MECH_PATH, ATTR_PATH, FUNC_PATH, HS_PATH, attr_hs, inc_h]
    before = {p: sha256_of(p) for p in artifacts}
    for script in ("generate-mechanisms.py", "generate-attributes.py",
                   "generate-function-contracts.py"):
        r = subprocess.run([sys.executable, f"scripts/{script}"],
                           cwd=REPO, capture_output=True, text=True)
        if r.returncode != 0:
            fail(f"idempotency re-run {script} failed: {r.stderr.strip()[:200]}")
    for p in artifacts:
        if sha256_of(p) != before[p]:
            fail(f"idempotency: {p.relative_to(REPO)} changed on re-run")

    if failures:
        print("denominators: INVALID", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("denominators: OK (480 CKM / 160 CKA / 13 CKO / 69 CKK / "
          "104 functions; headers byte-exact; generators idempotent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
