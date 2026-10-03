#!/usr/bin/env python3
"""Release-pivot gate: each pivot implemented-with-tests or
ruled-with-criteria (no third option). This gate pins the ruling
artifacts plus the behavior pins each ruling cites, so a removed
ruling or a weakened pin fails loudly.

* Cryptoki-version ruling ({2,40} on 3.x tables): the on_GetInfo
  ruling comment carries the OASIS v3.0 prose verdict plus the
  revisit criterion; the 2.40-via-3.2 pin, the cross-table CK_INFO
  identity pin, and the exact-3.x-table-versions pin stay present
  in tests/c/consumer_discovery.c.
* Uniform stub rule (stub-first precedence): the rule is
  documented per entry class in cbits/function_tables.c and
  scripts/generate-abi.py; every stub body voids its args
  (structural); stub-beats-args precedence pins exist in the C
  harnesses.
* PIN-compare ruling (pinsMatch length short-circuit): the
  pinsMatch comment matches the code (length short-circuit
  stated, "Constant-time" label gone); semantic pins live in
  StandardSurfaceSpec; a whitespace-normalized stale-claim scan
  fails on unruled PIN "constant time" wording in docs/ + ffi/
  (ruled sites cite the PIN-compare ruling; src/ tag-compare
  labels are out of scope per the review triage note).

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-release-pivots.py
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

failures = []


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


def stub_bodies(source, prefix, resolvers):
    """(name, body) for every `static CK_RV <prefix>*` function.
    Stub bodies never nest, so the first closing brace ends them."""
    out = []
    for m in re.finditer(r"static CK_RV " + prefix + r"(\w+)\s*\(.*?\)\s*\{",
                         source, re.DOTALL):
        body = source[m.end():source.find("}", m.end())]
        out.append((m.group(1), body))
    return [(n, b) for n, b in out if n not in resolvers]


def body_voids_only(body, returns):
    for line in body.splitlines():
        s = line.strip()
        if not s or s.startswith("/*") or s.startswith("*") or s == "{":
            continue
        if re.fullmatch(r"\(void\)\w+;", s):
            continue
        if s in returns:
            continue
        return False
    return True


def main() -> int:
    tables = (REPO / "cbits/function_tables.c").read_text()
    discovery = (REPO / "tests/c/consumer_discovery.c").read_text()
    gen = (REPO / "scripts/generate-abi.py").read_text()
    gen_inc = (REPO / "cbits/abi_stubs.inc").read_text()
    loader_c = (REPO / "tests/c/loader.c").read_text()
    errors_c = (REPO / "tests/c/consumer_errors.c").read_text()

    # --- cryptokiVersion ruling ---
    start = tables.find("static CK_RV on_GetInfo")
    on_info = tables[start:start + 2500]
    on_info = re.sub(r"/\*|\*/", " ", on_info)
    on_info = re.sub(r"\s*\*\s*", " ", on_info)
    on_info = re.sub(r"\s+", " ", on_info)
    check("VERSION-SPECCITE",
          "should match the version of this specification" in on_info,
          "on_GetInfo cites the v3.0 CK_INFO prose verdict")
    check("VERSION-RULING",
          "Cryptoki-version ruling" in on_info
          and "major == 2" in on_info
          and "revisit" in on_info.lower(),
          "on_GetInfo carries the ruling + 2.40-consumer bound + revisit")
    check("PIN-240-VIA-32", "cryptoki version 2.40" in discovery,
          "consumer_discovery pins 2.40 via the 3.2 table")
    check("PIN-INFO-IDENTITY", "GetInfo identical via legacy and 3.2" in discovery,
          "cross-table CK_INFO identity pinned")
    check("PIN-TABLE-VERSIONS", "3.x table versions exact" in discovery,
          "exact 3.x table versions pinned")

    # --- stub precedence (uniform stub-first, deliberate) ---
    check("STUB-RULE-LEGACY",
          "Uniform stub rule" in tables and "stub-first" in tables,
          "legacy stub section documents the uniform rule")
    check("STUB-RULE-GEN",
          "Uniform stub rule" in gen and "stub-first" in gen,
          "stub generator documents the uniform rule")
    legacy = stub_bodies(tables, "stub_", ("probe", "parallel"))
    # Floor history: 15 while dual/recover sat in legacy stubs; 8 after
    # the 4 dual entries registered to std_Dual* bodies (T-M02,
    # 63e7ce0) and the 4 recover entries to std_*Recover* bodies
    # (T-M03, 5f1b025). Remaining: PIN/token lifecycle, opstate pair
    # (deliberate saveability stubs), object size, legacy
    # status/cancel.
    # Lower deliberately with the routing commit cited.
    check("STUB-UNIFORM-LEGACY",
          len(legacy) >= 8 and all(
              body_voids_only(b, ("return stub_probe();",
                                   "return stub_parallel();"))
              for _, b in legacy),
          f"all {len(legacy)} legacy stubs void args (no inspections)")
    # Exact identities (T-M08 codex #2): the floor above admits
    # silent substitutions and extra stubs, so the remaining set
    # is pinned by name. Edit only with the routing commit cited,
    # same as the floor.
    check("STUB-IDENTITY-LEGACY",
          sorted(n for n, _ in legacy) == sorted([
              "InitToken", "InitPIN", "SetPIN",
              "GetOperationState", "SetOperationState",
              "GetObjectSize", "GetFunctionStatus", "CancelFunction"]),
          f"legacy stub identities exact (got {sorted(n for n, _ in legacy)})")
    check("STUB-UNIFORM-GEN",
          "(void)" in gen and "return x_live_check();" in gen,
          "stub generator template voids args + live-checks")
    inc_bodies = [(m.group(1), m.group(2)) for m in re.finditer(
        r"static CK_DECLARE_FUNCTION\(CK_RV, (\w+)\)\s*\(.*?\) \{\n(.*?)\n\}",
        gen_inc, re.DOTALL)]
    # Floor history: 20 before message routing; 11 after the twenty
    # message-family entries left the stub generator for real bodies
    # (2026-09-30); 8 after the three async entries registered to
    # std_Async* bodies (routing commit 577a015, 2026-09-30).
    # Lower deliberately with the routing commit cited.
    check("STUB-UNIFORM-INC",
          len(inc_bodies) >= 8 and all(
              body_voids_only(b, ("return x_live_check();",))
              for _, b in inc_bodies),
          f"all {len(inc_bodies)} generated stubs void args")
    check("STUB-PIN-LEGACY", "stub-beats-args" in loader_c,
          "loader STB pins stub-beats-args precedence")
    check("STUB-PIN-3X", "stub-beats-args" in errors_c,
          "consumer_errors pins stub precedence incl. 3.x")

    # --- pinsMatch comment matches the code ---
    std_hs = (REPO / "ffi/Haskoki/FFI/Standard.hs").read_text()
    at = std_hs.find("pinsMatch :: ByteString")
    pins_region = std_hs[max(0, at - 1200):at + 400]
    check("PIN-COMMENT",
          "PIN-compare ruling" in pins_region
          and "length mismatch short-circuits" in pins_region
          and "Constant-time PIN comparison" not in pins_region,
          "pinsMatch comment states the length short-circuit (no Constant-time)")

    # --- no stale unruled PIN "constant time" claims ---
    # Whitespace-normalized so a line-split "(constant\n time)"
    # still matches. A match is ruled only if its window carries
    # the ruling marker (every ruled site cites the PIN-compare
    # ruling next to the wording). Scope is docs/ + ffi/ only:
    # the identical-shape tag-compare "Constant-time" labels
    # under src/ (OpenSSL4.hs, Synthetic.hs, Driver.hs,
    # Backend.hs) are out of scope per the review triage note
    # and are not scanned.
    stale = []
    scan_files = sorted((REPO / "docs").rglob("*.md")) + sorted(
        (REPO / "ffi").rglob("*.hs"))
    for path in scan_files:
        norm = re.sub(r"\s+", " ", path.read_text())
        for m in re.finditer(r"constant[- ]time", norm, re.IGNORECASE):
            window = norm[max(0, m.start() - 800):m.end() + 200]
            if "PIN-compare ruling" not in window:
                excerpt = norm[max(0, m.start() - 80):m.end() + 80]
                stale.append(f"{path.relative_to(REPO)}: ...{excerpt}...")
    check("PIN-NOSTALE", not stale,
          "no unruled PIN constant-time wording in docs/ + ffi/"
          if not stale else "; ".join(stale[:4]))

    if failures:
        print(f"release-pivots: FAIL ({', '.join(failures)})")
        return 1
    print("release-pivots: OK (pivot rulings + pins present)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
