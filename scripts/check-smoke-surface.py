#!/usr/bin/env python3
"""Install-smoke surface pins: the bundled release smoke must assert
the FULL served surface (demo-maximal), never a reduced catalog.

Fails (exit 1) when any rule fails. Presence rules demand the exact
contract substrings in tests/c/release_smoke.c; absence rules demand
the early reduced-catalog/session-less defects be gone:

* COUNT: SMOKE_MECH_COUNT equals HASKOKI_MECH_COUNT from
  cbits/mech_catalog.inc (derived, never hardcoded; a hardcoded
  count went stale at 130 while the served surface grew).
* SIZEQ: a NULL size-query leg pins the count before the full list.
* MEMBER: CKM_SHA256 membership is asserted over the served list.
* TOKEN: C_GetTokenInfo pins the single-token default label.
* SESS1/SESS2: two real open/use/close lifecycles (independence).
* FIPSx2: both sessions yield the FIPS "abc" bytes.
* NOSESSIONLESS: no C_DigestInit(1, / C_Digest(1, implicit-session call.
* NOREDUCED: no 1-mechanism [CKM_SHA256] catalog assertion.
* VERPIN: the lib 0.3 pin keeps the check-version.py shape.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-smoke-surface.py [path/to/release_smoke.c]
(the optional path exists so a negative-control run can check the pins
against the pre-rewrite smoke source: FAIL there, ok on the rewrite).
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT = REPO / "tests" / "c" / "release_smoke.c"
INC = REPO / "cbits" / "mech_catalog.inc"

failures = []


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


def served_count():
    for line in INC.read_text().splitlines():
        if line.startswith("#define HASKOKI_MECH_COUNT"):
            return int(line.split()[-1])
    raise AssertionError(
        "HASKOKI_MECH_COUNT not found in cbits/mech_catalog.inc")


def main() -> int:
    src = Path(sys.argv[1]).read_text() if len(sys.argv) > 1 else DEFAULT.read_text()
    n = served_count()

    check("COUNT", f"#define SMOKE_MECH_COUNT {n}" in src,
          f"exact served count pinned at the derived {n}")
    check("SIZEQ", "C_GetMechanismList(slots[0], NULL_PTR, &q)" in src,
          "NULL size-query leg pins the count first")
    check("MEMBER", "mechs[i] == CKM_SHA256" in src
          and "contains CKM_SHA256" in src,
          "CKM_SHA256 membership asserted over the served list")
    check("TOKEN", "C_GetTokenInfo(slots[0], &tinfo)" in src
          and 'memcmp(tinfo.label, "haskoki-demo", 12)' in src,
          "token presence pins the single-token default label")
    check("SESS1", "first session opens" in src
          and "first one-shot digest yields FIPS bytes" in src,
          "first real open/use/close lifecycle")
    check("SESS2", "second session opens (independence)" in src
          and "second one-shot digest yields FIPS bytes" in src,
          "second lifecycle proves session independence")
    check("FIPSx2", src.count("yields FIPS bytes") == 2
          and "0xba, 0x78, 0x16, 0xbf" in src,
          "both sessions assert the FIPS bytes")
    check("NOSESSIONLESS", "C_DigestInit(1," not in src
          and "C_Digest(1," not in src
          and "C_DigestInit(sess" in src,
          "no implicit-session digest calls; real handles used")
    check("NOREDUCED", "n == 1 && mechs[0] == CKM_SHA256" not in src
          and "[CKM_SHA256]" not in src,
          "no 1-mechanism reduced-catalog assertion")
    check("VERPIN", "info.libraryVersion.major == 0 &&" in src
          and "info.libraryVersion.minor == 3," in src,
          "lib 0.3 pin keeps the version-gate shape")
    check("FINALIZE", 'C_Finalize(NULL_PTR)' in src
          and "SMOKE-OK: release_smoke" in src,
          "finalize + SMOKE-OK verdict intact")

    if failures:
        print(f"smoke-surface: FAIL: {len(failures)} rule(s) failed")
        return 1
    print("smoke-surface: ok: full served surface pinned (11/11)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
