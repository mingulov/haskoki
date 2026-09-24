#!/usr/bin/env python3
"""Test-wiring gate: no suite silently drops a spec module.

Fails (exit 1) when any rule fails. For every `test-suite` stanza
in haskoki.cabal, every `other-modules` spec module (`*Spec`,
`*Props`) must be BOTH imported AND run (`Mod.spec` in the group)
by that suite's Main: a spec removed from Main but left in
`other-modules` compiles while its tests silently stop
running, and this gate is what fails loudly instead. Helper
modules (e.g. `EnvLock`, `Gen`) must exist as files under the
suite's `hs-source-dirs`; every spec module must exist too.

The "singleton modules / one construct per suite" disposition: the
phrase has no in-tree form (repo-wide grep: zero hits for
"singleton module", "one construct per suite", or any per-suite
construct claim) — there is no such spec sentence to verify. Its
closest living equivalent is this per-suite spec inventory: every
suite's module set is enumerated here from the build file and
pinned to its runner, so suite/module removals fail loudly
instead of narrowing coverage silently.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-test-wiring.py
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CABAL = REPO / "haskoki.cabal"

failures = []


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


def parse_suites(text):
    """name -> {dirs: [...], modules: [...], main: ...}."""
    suites = {}
    cur = None
    field = None
    for line in text.splitlines():
        m = re.match(r"test-suite\s+(\S+)\s*$", line)
        if m:
            cur = m.group(1)
            suites[cur] = {"dirs": [], "modules": [], "main": None}
            field = None
            continue
        if cur is None:
            continue
        if re.match(r"\S", line):
            cur = None  # next top-level stanza
            field = None
            continue
        m = re.match(r"\s+([\w-]+):\s*(.*?)\s*$", line)
        if m:
            field = m.group(1)
            rest = m.group(2)
            if field == "hs-source-dirs" and rest:
                suites[cur]["dirs"] = rest.split()
            elif field == "main-is" and rest:
                suites[cur]["main"] = rest
            continue
        m = re.match(r"\s+(\S+)\s*$", line)
        if m and field == "other-modules":
            suites[cur]["modules"].append(m.group(1))
    return suites


def main() -> int:
    suites = parse_suites(CABAL.read_text())
    check("SUITES-FOUND", len(suites) == 6,
          f"6 test suites parsed, got {sorted(suites)}")
    total_specs = 0
    for name in sorted(suites):
        s = suites[name]
        if not s["dirs"] or not s["main"]:
            check(f"WIRING-{name}", False, "dirs/main-is unparsed")
            continue
        main_path = REPO / s["dirs"][0] / s["main"]
        if not main_path.exists():
            check(f"WIRING-{name}", False, f"missing {main_path}")
            continue
        main_text = main_path.read_text()
        files = []
        for d in s["dirs"]:
            files.extend((REPO / d).glob("*.hs"))
        have = {f.stem for f in files}
        for mod in s["modules"]:
            is_spec = mod.endswith("Spec") or mod.endswith("Props")
            if mod not in have:
                check(f"WIRING-{name}-{mod}", False,
                      f"{mod} listed but no file under {s['dirs']}")
                continue
            if not is_spec:
                check(f"WIRING-{name}-{mod}", True,
                      f"helper {mod} exists")
                continue
            total_specs += 1
            imported = (f"import qualified {mod}" in main_text
                        or f"import {mod}" in main_text)
            run = f"{mod}.spec" in main_text
            check(f"WIRING-{name}-{mod}", imported and run,
                  f"{mod} imported={imported} run={run} in {main_path.name}")
    check("SPECS-COUNT", total_specs > 60,
          f"{total_specs} spec modules pinned across suites")
    if failures:
        print(f"test-wiring: FAIL ({len(failures)} rule(s))")
        return 1
    print(f"test-wiring: OK ({total_specs} specs wired across "
          f"{len(suites)} suites)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
