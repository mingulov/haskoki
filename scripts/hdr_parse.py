#!/usr/bin/env python3
"""Shared PKCS#11 header parsing for the spec catalog generators.

Reads the single selected header from spec/sources.lock.json (the
verbatim latchset public-domain v3.2 header, one single-file
pkcs11.h). One file suffices: v3.2 is a strict superset of every
older interface (same names, values, layouts, and function order),
so per-version vendoring would only duplicate bytes. Parses
`#define <NAME> <value>` lines for the CKM_/CKA_/CKO_/CKK_ prefixes
plus the alias-style `#define <NAME> <OTHER_NAME>` lines. Array
attribute IDs arrive as precomputed hex values (PD spells them
literally, not as `(CKF_ARRAY_ATTRIBUTE|<hex>)` composites); the
composite form is still accepted.

STDLIB ONLY. Imported by scripts/generate-*.py via a sibling import;
also runnable as a self-check (`python3 scripts/hdr_parse.py` prints
the denominator table).
"""

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "spec"
LOCK_PATH = SPEC / "sources.lock.json"

VALUE_RE = re.compile(r"#define\s+(CK[AMOK]_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)(?:UL|ULL|L|U)?\s*(?:/\*.*\*/)?\s*$")
ALIAS_RE = re.compile(r"#define\s+(CK[AMOK]_[A-Z0-9_]+)\s+(CK[AMOK]_[A-Z0-9_]+)\s*(?:/\*.*\*/)?\s*$")
ARRAY_RE = re.compile(r"#define\s+(CKA_[A-Z0-9_]+)\s+\(CKF_ARRAY_ATTRIBUTE\|(0x[0-9A-Fa-f]+)(?:UL|ULL|L|U)?\)\s*(?:/\*.*\*/)?\s*$")
ANY_CK_RE = re.compile(r"#define\s+(CK[AMOK]_[A-Z0-9_]+)")
FLAG_RE = re.compile(r"#define\s+(CKF_ARRAY_ATTRIBUTE)\s+(0x[0-9A-Fa-f]+)(?:UL|ULL|L|U)?\s*(?:/\*.*\*/)?\s*$")

# Source id of the single selected header (spec/sources.lock.json).
EXPECTED_SOURCE_ID = "S-PD-32"


def fail(msg):
    print(f"hdr_parse: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def selected_header():
    """Return (source_id, pkcs11.h path) for the single selection."""
    try:
        lock = json.loads(LOCK_PATH.read_text())
    except Exception as e:  # noqa: BLE001 - reported, not hidden
        fail(f"cannot parse {LOCK_PATH}: {e}")
    sels = [f for f in lock.get("files", [])
            if f.get("role") == "selected"
            and f.get("relative_path", "").endswith("pkcs11.h")]
    if len(sels) != 1:
        fail(f"lock must select exactly one pkcs11.h, found {len(sels)}")
    entry = sels[0]
    if entry.get("source_id") != EXPECTED_SOURCE_ID:
        fail(f"selected source {entry.get('source_id')} != locked "
             f"{EXPECTED_SOURCE_ID}")
    path = REPO / entry["relative_path"]
    if not path.exists():
        fail(f"missing selected header {path}")
    return entry["source_id"], path


def parse_family(path):
    """Parse the single pkcs11.h.

    Returns (values, aliases, order, deprecated) where values maps
    name -> int, aliases maps alias -> canonical target, order lists
    value names in file order (for deterministic same-value
    tie-breaks), and deprecated holds the value names defined inside
    `#ifdef PKCS11_DEPRECATED` regions (the header's own
    machine-readable legacy-spelling mark, which the canonical
    tie-break honors). Fails loudly on any unparsed CK?_ line:
    silent drops would corrupt the denominator.
    """
    values, aliases, order, deprecated = {}, {}, [], set()
    array_flag = None
    in_deprecated = False
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if line == "#ifdef PKCS11_DEPRECATED":
            in_deprecated = True
            continue
        if line == "#endif" and in_deprecated:
            in_deprecated = False
            continue
        m = FLAG_RE.match(line)
        if m:
            array_flag = int(m.group(2), 16)
            continue
        m = VALUE_RE.match(line)
        if m:
            name, val = m.group(1), int(m.group(2), 16)
            if name in values:
                fail(f"{path}:{lineno}: duplicate value define {name}")
            values[name] = val
            order.append(name)
            if in_deprecated:
                deprecated.add(name)
            continue
        m = ALIAS_RE.match(line)
        if m:
            alias, target = m.group(1), m.group(2)
            if alias in aliases:
                fail(f"{path}:{lineno}: duplicate alias define {alias}")
            aliases[alias] = target
            continue
        m = ARRAY_RE.match(line)
        if m:
            name = m.group(1)
            if array_flag is None:
                fail(f"{path}:{lineno}: array attribute before CKF_ARRAY_ATTRIBUTE")
            if name in values:
                fail(f"{path}:{lineno}: duplicate value define {name}")
            values[name] = array_flag | int(m.group(2), 16)
            order.append(name)
            if in_deprecated:
                deprecated.add(name)
            continue
        if ANY_CK_RE.match(line):
            fail(f"{path}:{lineno}: unparsed CK line: {line}")
    return values, aliases, order, deprecated


def catalog_tables():
    """Parse the selected header into per-prefix catalog tables.

    Returns (tables, provenance) where tables[prefix] is a list of
    dicts, one per canonical entry, sorted by (value, name):
      {name, value, aliases}
    and provenance maps name -> {value, alias_of} for EVERY header
    name (canonical or alias) for denominator verification.
    Canonical choice is deterministic and source-derived:
      * alias-style defines resolve to their target (the target must
        be value-defined);
      * among same-value value-defines, a name the header marks
        deprecated (inside `#ifdef PKCS11_DEPRECATED`) always loses
        to an unmarked one;
      * among same-marked names, the FIRST in file order wins (the
        header lists the primary spelling first and legacy
        spellings after).
    """
    _src, path = selected_header()
    values, aliases, order, deprecated = parse_family(path)
    prefixes = ("CKM_", "CKA_", "CKO_", "CKK_")
    tables, provenance = {}, {}
    for prefix in prefixes:
        pvals = {n: v for n, v in values.items() if n.startswith(prefix)}
        palias = {a: t for a, t in aliases.items() if a.startswith(prefix)}
        porder = [n for n in order if n.startswith(prefix)]
        # Resolve canonicals: alias-style names fold to their target.
        for alias, target in palias.items():
            if target not in pvals:
                fail(f"{prefix}{alias}: alias target {target} has no value define")
            if alias in pvals:
                fail(f"{prefix}{alias}: defined as both value and alias")
        # Same-value value-defines: a header-marked deprecated
        # spelling always loses; otherwise the FIRST in file order
        # wins (primary spelling first, legacy after).
        by_value = {}
        for name, val in pvals.items():
            # Skip names that are aliases (they already folded above).
            if name in palias:
                continue
            by_value.setdefault(val, []).append(name)
        rank = {name: i for i, name in enumerate(porder)}
        lasts = len(rank)
        winner = {}
        for val, names in by_value.items():
            if len(names) == 1:
                winner[names[0]] = names[0]
            else:
                ordered = sorted(names, key=lambda n: (
                    n in deprecated, rank.get(n, lasts)))
                for n in ordered[1:]:
                    winner[n] = ordered[0]
                winner[ordered[0]] = ordered[0]
        entries = {}
        for name, val in pvals.items():
            if name in palias:
                continue
            canon = winner[name]
            entries.setdefault(canon, {"value": val, "aliases": set()})
            if name != canon:
                entries[canon]["aliases"].add(name)
        for alias, target in palias.items():
            canon = winner[target]
            entries.setdefault(canon, {"value": pvals[target], "aliases": set()})
            if alias != canon:
                entries[canon]["aliases"].add(alias)
        table = []
        for canon in sorted(entries, key=lambda c: (entries[c]["value"], c)):
            e = entries[canon]
            table.append({
                "name": canon,
                "value": e["value"],
                "aliases": sorted(e["aliases"]),
            })
            provenance[canon] = {"value": e["value"], "alias_of": None}
            for a in e["aliases"]:
                provenance[a] = {"value": e["value"], "alias_of": canon}
        tables[prefix] = table
    return tables, provenance


def main():
    tables, _prov = catalog_tables()
    for prefix in ("CKM_", "CKA_", "CKO_", "CKK_"):
        entries = tables[prefix]
        n_alias = sum(len(e["aliases"]) for e in entries)
        print(f"{prefix} canonical={len(entries)} aliases={n_alias} "
              f"names={len(entries) + n_alias}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
