#!/usr/bin/env python3
"""Version consistency gate: the shipped version must agree
everywhere it is pinned.

Asserts, for haskoki.cabal's version X.Y.Z.W:
  - CHANGELOG.md carries a matching "## [X.Y.Z.W]" section header
  - cbits/function_tables.c libraryVersion is {X, Y}
  - src/Haskoki/Ctl.hs --version string contains X.Y.Z.W
  - tests/c/loader.c, consumer_discovery.c, release_smoke.c pin lib X.Y

Exit status: 0 iff all pins agree; otherwise FAIL with the mismatch.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def fail(msg):
    print(f"FAIL: version drift: {msg}")
    return 1


def main():
    cabal = (ROOT / "haskoki.cabal").read_text()
    m = re.search(r"^version:\s+(\d+)\.(\d+)\.(\d+)\.(\d+)\s*$",
                  cabal, re.M)
    if not m:
        return fail("cannot parse version from haskoki.cabal")
    x, y, z, w = (int(g) for g in m.groups())
    full = f"{x}.{y}.{z}.{w}"

    clog = (ROOT / "CHANGELOG.md").read_text()
    if f"## [{full}]" not in clog:
        return fail(f"CHANGELOG.md lacks '## [{full}]' section")

    ft = (ROOT / "cbits" / "function_tables.c").read_text()
    mm = re.search(r"tmp\.libraryVersion\.major = (\d+);\s*\n"
                   r"\s*tmp\.libraryVersion\.minor = (\d+);", ft)
    if not mm or (int(mm.group(1)), int(mm.group(2))) != (x, y):
        return fail(f"function_tables.c libraryVersion != {{{x}, {y}}}")

    ctl = (ROOT / "src" / "Haskoki" / "Ctl.hs").read_text()
    if full not in ctl:
        return fail(f"Ctl.hs --version lacks {full}")

    pins = {
        "tests/c/loader.c":
            r"info\.libraryVersion\.major == (\d+) && "
            r"info\.libraryVersion\.minor == (\d+)",
        "tests/c/consumer_discovery.c":
            r"info3\.libraryVersion\.major == (\d+) && "
            r"info3\.libraryVersion\.minor == (\d+)",
        "tests/c/release_smoke.c":
            r"info\.libraryVersion\.major == (\d+) &&\s*\n\s*"
            r"info\.libraryVersion\.minor == (\d+)",
    }
    for rel, pat in pins.items():
        src = (ROOT / rel).read_text()
        pm = re.search(pat, src)
        if not pm or (int(pm.group(1)), int(pm.group(2))) != (x, y):
            return fail(f"{rel} lib pin != {x}.{y}")

    print(f"version: OK ({full}; cabal + changelog + C lib + ctl + 3 C pins agree)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
