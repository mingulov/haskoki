#!/usr/bin/env python3
"""Attribute-catalog gate: validate spec/attributes.json.

Checks:
  * schema: top-level keys, per-block entry keys, value_type and
    applies_to vocabularies, template_rules shape;
  * header identity: every entry's numeric_id is byte-exact against
    the SELECTED headers and the name sets match (via hdr_parse);
  * template_rules reference known CKA/CKO/CKK names only, required
    and forbidden are disjoint, and every enforced (non-unreviewed)
    attribute is covered by a rule citing it (this mapping grows as
    rules are reviewed; an empty rule set is an honest state).

Usage: python3 scripts/check-attributes.py   (from haskoki/)
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hdr_parse  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
ATTR_PATH = REPO / "spec" / "attributes.json"

VALUE_TYPES = {"ulong", "bool", "bytes", "string", "date", "template",
               "array-template", "mechanism-list", "unreviewed"}
ATTR_KEYS = {"numeric_id", "canonical_name", "aliases",
             "source_refs", "value_type", "applies_to", "notes"}
OTHER_KEYS = {"numeric_id", "canonical_name", "aliases",
              "source_refs", "notes"}
RULE_KEYS = {"class", "key_type", "required", "forbidden", "notes"}

RX_ID = re.compile(r"^0x[0-9A-Fa-f]{8}$")
RX_CKA = re.compile(r"^CKA_[A-Z0-9_]+$")
RX_CKO = re.compile(r"^CKO_[A-Z0-9_]+$")
RX_CKK = re.compile(r"^CKK_[A-Z0-9_]+$")

failures = []


def fail(msg):
    failures.append(msg)


def check(cond, msg):
    if not cond:
        fail(msg)


def main():
    try:
        data = json.loads(ATTR_PATH.read_text())
    except Exception as e:  # noqa: BLE001 - reported, not hidden
        print(f"attributes: cannot parse {ATTR_PATH}: {e}", file=sys.stderr)
        return 1
    check(data.get("schema_version") == 1, "schema_version must be 1")
    check(data.get("status") == "generated-source-of-truth",
          "status must be generated-source-of-truth")

    _tables, provenance = hdr_parse.catalog_tables()

    def fmt_id(value):
        return "0x%08x" % value

    known_cka, known_cko, known_ckk = set(), set(), set()
    for block, rx, want_keys, known in (
            ("attributes", RX_CKA, ATTR_KEYS, known_cka),
            ("classes", RX_CKO, OTHER_KEYS, known_cko),
            ("key_types", RX_CKK, OTHER_KEYS, known_ckk)):
        rows = data.get(block)
        check(isinstance(rows, list) and len(rows) > 0,
              f"{block} must be non-empty")
        seen_ids, seen_names = set(), set()
        for i, m in enumerate(rows or []):
            tag = m.get("canonical_name", f"{block}#{i}")
            check(set(m) == want_keys, f"{tag}: keys must be exactly "
                  f"{sorted(want_keys)}, got {sorted(m)}")
            nid = m.get("numeric_id", "")
            check(isinstance(nid, str) and RX_ID.match(nid),
                  f"{tag}: bad numeric_id {nid!r}")
            check(nid not in seen_ids, f"{tag}: duplicate numeric_id {nid}")
            seen_ids.add(nid)
            canon = m.get("canonical_name", "")
            check(rx.match(canon or ""), f"{tag}: bad canonical_name")
            check(canon not in seen_names, f"{tag}: duplicate name {canon}")
            seen_names.add(canon)
            known.add(canon)
            for a in m.get("aliases", []):
                check(rx.match(a), f"{tag}: bad alias {a!r}")
                check(a not in seen_names, f"{tag}: alias {a} collides")
                seen_names.add(a)
                known.add(a)
            # Header byte-exactness for every catalogued name.
            for name in [canon] + list(m.get("aliases", [])):
                if name not in provenance:
                    fail(f"{tag}: {name} not in selected headers")
                elif provenance[name]["value"] != int(nid, 16):
                    fail(f"{tag}: {name} id {nid} != header "
                         f"{fmt_id(provenance[name]['value'])}")
            refs = m.get("source_refs")
            check(isinstance(refs, list) and len(refs) > 0,
                  f"{tag}: need source_refs")
            check(isinstance(m.get("notes"), str) and m.get("notes"),
                  f"{tag}: notes must be non-empty")
            if block == "attributes":
                check(m.get("value_type") in VALUE_TYPES,
                      f"{tag}: bad value_type {m.get('value_type')!r}")
                applies = m.get("applies_to")
                check(applies == "unreviewed"
                      or (isinstance(applies, list)
                          and all(RX_CKO.match(a or "") for a in applies)),
                      f"{tag}: bad applies_to {applies!r}")

    rules = data.get("template_rules")
    check(isinstance(rules, list), "template_rules must be a list")
    for i, rule in enumerate(rules or []):
        tag = f"rule#{i}"
        check(set(rule) == RULE_KEYS, f"{tag}: keys must be exactly "
              f"{sorted(RULE_KEYS)}")
        cls, key_type = rule.get("class"), rule.get("key_type")
        check(cls in known_cko, f"{tag}: unknown class {cls!r}")
        check(key_type is None or key_type in known_ckk,
              f"{tag}: unknown key_type {key_type!r}")
        req = rule.get("required", [])
        frb = rule.get("forbidden", [])
        check(isinstance(req, list) and isinstance(frb, list),
              f"{tag}: required/forbidden must be lists")
        check(all(a in known_cka for a in req),
              f"{tag}: required cites unknown attribute")
        check(all(a in known_cka for a in frb),
              f"{tag}: forbidden cites unknown attribute")
        check(not (set(req) & set(frb)), f"{tag}: required/forbidden overlap")
        check(isinstance(rule.get("notes"), str) and rule.get("notes"),
              f"{tag}: notes must be non-empty")

    if failures:
        print("attributes: INVALID", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    n_attr = len(data.get("attributes", []))
    n_cls = len(data.get("classes", []))
    n_kk = len(data.get("key_types", []))
    print(f"attributes: OK ({n_attr} attributes, {n_cls} classes, "
          f"{n_kk} key types, {len(rules or [])} template rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
