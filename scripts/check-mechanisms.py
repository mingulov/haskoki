#!/usr/bin/env python3
"""Mechanism consistency check: validate spec/mechanisms.json and
render the canonical projection that Haskoki.Registry.dumpRegistry must
match byte-for-byte (compared by RegistrySpec, no Haskell JSON needed).

Usage: python3 scripts/check-mechanisms.py   (from haskoki/)
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mech_catalog  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
MECH = REPO / "spec" / "mechanisms.json"
LOCK = REPO / "spec" / "sources.lock.json"
OUT = REPO / "spec" / "mechanisms-canonical.txt"
INC = REPO / "cbits" / "mech_catalog.inc"

OPERATIONS = {
    "digest", "sign", "verify", "sign-recover", "verify-recover",
    "encrypt", "decrypt", "generate-key", "generate-key-pair", "derive",
    "wrap", "unwrap", "encapsulate", "decapsulate", "message-encrypt",
    "message-decrypt", "message-sign", "message-verify",
    "authenticated-wrap", "authenticated-unwrap",
}
# Name-shape families for recipe planning (see
# scripts/generate-mechanisms.py FAMILY_RULES). Family is a catalog
# grouping hint, never a behavior claim.
FAMILIES = {"digest", "mac", "cipher", "aead", "rsa", "ec", "dsa",
            "keygen", "keypair", "derive", "wrap", "kem", "otp",
            "stateful", "pqc", "special"}
# Behavior states beyond tested/planned. Catalog-only rows
# (anything but tested) never execute; see the support-branch checks.
CATALOG_BEHAVIOR = {"planned", "unsupported-with-reason", "not-applicable"}
UNITS = {"bits", "bytes", "not-applicable", "mechanism-specific"}
SUPPORT = {"planned", "implemented-unverified", "tested",
           "unsupported-with-reason", "not-applicable"}
SUPPORT_KEYS = {"abi", "behavior", "synthetic", "real", "recovery"}
MECH_KEYS = {"numeric_id", "canonical_name", "aliases",
             "source_refs", "family", "mechanism_info", "routes", "support",
             "test_evidence", "notes"}

RX_ID = re.compile(r"^0x[0-9A-Fa-f]{8}$")
RX_CKM = re.compile(r"^CKM_[A-Z0-9_]+$")
RX_CKF = re.compile(r"^CKF_[A-Z0-9_]+$")
RX_CASE = re.compile(r"^A[0-9]{2}$")
RX_CODEC = re.compile(r"^[a-z0-9-]+/[1-9][0-9]*$")

failures = []


def fail(msg):
    failures.append(msg)


def check(cond, msg):
    if not cond:
        fail(msg)


def main():
    try:
        data = json.loads(MECH.read_text())
    except Exception as e:  # noqa: BLE001 - reported, not hidden
        print(f"mechanisms: cannot parse {MECH}: {e}", file=sys.stderr)
        return 1
    try:
        lock_ids = {s["id"] for s in json.loads(LOCK.read_text())["sources"]}
    except Exception as e:  # noqa: BLE001
        print(f"mechanisms: cannot read source ids from {LOCK}: {e}", file=sys.stderr)
        return 1

    check(data.get("schema_version") == 1, "schema_version must be 1")
    check(data.get("status") == "reviewed-source-of-truth",
          "status must be reviewed-source-of-truth")
    mechs = data.get("mechanisms")
    check(isinstance(mechs, list) and len(mechs) > 0, "mechanisms must be non-empty")

    seen_ids, seen_names = set(), set()
    tested, planned = [], []
    if isinstance(mechs, list):
        for i, m in enumerate(mechs):
            tag = m.get("canonical_name", f"#{i}")
            check(set(m) == MECH_KEYS, f"{tag}: keys must be exactly {sorted(MECH_KEYS)}")
            nid = m.get("numeric_id", "")
            check(isinstance(nid, str) and RX_ID.match(nid), f"{tag}: bad numeric_id {nid!r}")
            check(nid not in seen_ids, f"{tag}: duplicate numeric_id {nid}")
            seen_ids.add(nid)
            canon = m.get("canonical_name", "")
            check(RX_CKM.match(canon or ""), f"{tag}: bad canonical_name {canon!r}")
            check(canon not in seen_names, f"{tag}: duplicate name {canon}")
            seen_names.add(canon)
            aliases = m.get("aliases")
            check(isinstance(aliases, list) and len(set(aliases)) == len(aliases),
                  f"{tag}: aliases must be unique")
            for a in aliases or []:
                check(RX_CKM.match(a), f"{tag}: bad alias {a!r}")
                check(a not in seen_names, f"{tag}: alias {a} collides with a known name")
                seen_names.add(a)
            refs = m.get("source_refs")
            check(isinstance(refs, list) and len(refs) > 0, f"{tag}: need source_refs")
            for r in refs or []:
                check(r.get("source_id") in lock_ids,
                      f"{tag}: unknown source_id {r.get('source_id')!r}")
                check(isinstance(r.get("section"), str) and r.get("section"),
                      f"{tag}: source section must be non-empty")
            check(m.get("family") in FAMILIES, f"{tag}: bad family {m.get('family')!r}")
            mi = m.get("mechanism_info") or {}
            check(isinstance(mi.get("flags"), list)
                  and all(RX_CKF.match(f or "") for f in mi["flags"])
                  and len(set(mi["flags"])) == len(mi["flags"]),
                  f"{tag}: bad mechanism_info.flags")
            check(mi.get("key_size_unit") in UNITS, f"{tag}: bad key_size_unit")
            check(isinstance(mi.get("min_key_size"), int) and mi["min_key_size"] >= 0
                  and isinstance(mi.get("max_key_size"), int) and mi["max_key_size"] >= 0,
                  f"{tag}: bad key size bounds")
            routes = m.get("routes")
            check(isinstance(routes, list), f"{tag}: routes must be a list")
            for r in routes or []:
                check(r.get("operation") in OPERATIONS,
                      f"{tag}: bad operation {r.get('operation')!r}")
                check(isinstance(r.get("output_rule"), str) and r.get("output_rule"),
                      f"{tag}: output_rule must be non-empty")
                check(isinstance(r.get("key_constraints"), list)
                      and all(isinstance(k, str) for k in r["key_constraints"]),
                      f"{tag}: bad key_constraints")
                acc = r.get("acceptance_cases")
                # Catalog-only routes may carry zero acceptance
                # cases (no behavior claim without tests); tested
                # routes still need at least one (checked below).
                check(isinstance(acc, list)
                      and all(RX_CASE.match(a or "") for a in acc)
                      and len(set(acc)) == len(acc),
                      f"{tag}: bad acceptance_cases {acc!r}")
            sup = m.get("support") or {}
            check(set(sup) == SUPPORT_KEYS and set(sup.values()) <= SUPPORT,
                  f"{tag}: bad support block")
            ev = m.get("test_evidence")
            check(isinstance(ev, list), f"{tag}: test_evidence must be a list")
            for e in ev or []:
                check(all(isinstance(e.get(k), str) and e.get(k)
                          for k in ("case_id", "build_id", "artifact")),
                      f"{tag}: bad test_evidence entry {e!r}")
            if "tested" in sup.values():
                check(len(ev or []) > 0, f"{tag}: tested support needs test_evidence")
            check(isinstance(m.get("notes"), str) and m.get("notes"),
                  f"{tag}: notes must be non-empty")
            # Codec discipline: tested behavior needs a real versioned
            # codec; catalog-only rows must carry the explicit none/0
            # marker on every route they declare (usually zero routes).
            if sup.get("behavior") == "tested":
                check(sup.get("synthetic") == "tested",
                      f"{tag}: tested behavior needs tested synthetic evidence")
                check(len(routes or []) > 0,
                      f"{tag}: tested behavior needs at least one route")
                for r in routes or []:
                    check(RX_CODEC.match(r.get("parameter_codec") or ""),
                          f"{tag}: tested route needs a versioned parameter_codec")
                    check(len(r.get("acceptance_cases") or []) > 0,
                          f"{tag}: tested route needs acceptance_cases")
                tested.append(m)
            elif sup.get("behavior") in CATALOG_BEHAVIOR:
                for r in routes or []:
                    check(r.get("parameter_codec") == "none/0",
                          f"{tag}: catalog-only route must carry parameter_codec none/0")
                planned.append(m)
            else:
                fail(f"{tag}: behavior support must be tested or one of "
                     f"{sorted(CATALOG_BEHAVIOR)}")

    if failures:
        print("mechanisms: INVALID", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1

    lines = ["schema 1"]
    for m in sorted(tested, key=lambda m: int(m["numeric_id"], 16)):
        code = m["routes"][0]["parameter_codec"]
        check(all(r["parameter_codec"] == code for r in m["routes"]),
              f"{m['canonical_name']}: routes must share one parameter_codec")
        routes = ";".join(
            f"{r['operation']}:{','.join(sorted(r['acceptance_cases']))}"
            for r in sorted(m["routes"], key=lambda r: r["operation"]))
        mi = m["mechanism_info"]
        lines.append("|".join([
            "mech",
            "0x%08X" % int(m["numeric_id"], 16),
            m["canonical_name"],
            ",".join(sorted(m["aliases"])),
            m["family"],
            code,
            f"{mi['key_size_unit']}:{mi['min_key_size']}-{mi['max_key_size']}",
            routes,
        ]))
    for m in sorted(planned, key=lambda m: int(m["numeric_id"], 16)):
        lines.append("|".join([
            "inv",
            "0x%08X" % int(m["numeric_id"], 16),
            m["canonical_name"],
            ",".join(sorted(m["aliases"])),
            "catalog-only",
        ]))
    lines.append("catalog|" + ",".join(
        "0x%08X" % int(m["numeric_id"], 16)
        for m in sorted(mechs, key=lambda m: int(m["numeric_id"], 16))))
    if failures:
        print("mechanisms: INVALID", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    text = "\n".join(lines) + "\n"
    before = OUT.read_text() if OUT.exists() else None
    OUT.write_text(text)
    changed = " (updated)" if before != text else ""
    # The C mechanism catalog must match the real-tested rows
    # byte-for-byte (the generator owns it; this checker never writes
    # it -- a mismatch means re-run generate-mechanisms.py).
    want_inc = mech_catalog.expected_inc_text()
    got_inc = INC.read_text() if INC.exists() else None
    check(got_inc == want_inc,
          "cbits/mech_catalog.inc missing or stale (re-run "
          "scripts/generate-mechanisms.py)")
    if failures:
        print("mechanisms: INVALID", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"mechanisms: OK "
          f"({len(tested)} behavior-tested, {len(planned)} catalog-only){changed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
