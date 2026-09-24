#!/usr/bin/env python3
"""Fork-stance gate: the fork-safety stance is documented AND
its enforcement surface is pinned (a "CI will enforce it" sentence
with no gate does not satisfy this check; this gate, wired into
scripts/run-gates.sh, IS the enforcement).

TRUE behavior (audited against cbits/rts_bootstrap.c +
cbits/function_tables.c + cbits/standard_surface.c): the boot-PID
guard refuses fork children cleanly before any Haskell entry or
argument dereference — stateful calls see
CKR_CRYPTOKI_NOT_INITIALIZED, C_Initialize sees CKR_GENERAL_ERROR,
pure discovery (C_GetInfo/C_GetFunctionList) stays available.
Pinned at runtime by case_a06_fork in tests/c/loader.c (run by
scripts/test-loader.sh, itself in the release-evidence manifest).

Fails (exit 1) when any rule fails:

* STANCE-SECTION: SUPPORTED-HOSTS.md carries the "Fork safety"
  stance section (forbidden/allowed uses + why).
* STANCE-TABLE: the stance names the per-call-class child behavior
  (NOT_INITIALIZED for stateful calls, GENERAL_ERROR for
  C_Initialize, C_GetInfo available) and the boot-PID mechanism.
* STANCE-PROBE: the stance cites the enforcing probe (A06a).
* PROBE-EXISTS: tests/c/loader.c carries case_a06_fork (the
  fork-child probe: fork + assert documented behavior + _exit).
* PROBE-CRYPTO: the A06a body pins crypto entries too (C_SignInit
  and C_EncryptInit refuse without Haskell entry — the entries
  gate on live_interval first, before touching arguments).
* DRIVER-RUNS: scripts/test-loader.sh compiles and runs the loader
  harness.
* DRIVER-NAMES: the test-loader.sh header references the A06a fork
  probe (the loader proof references its enforcement).
* WIRED: scripts/run-gates.sh runs this gate.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-fork-stance.py
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

failures = []


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


def a06a_body(loader_c):
    start = loader_c.find("static void case_a06_fork")
    if start == -1:
        return None
    # The last CASE_END: the fork-failure early-return carries its
    # own, so the first occurrence would truncate the body.
    end = loader_c.rfind('CASE_END("A06a")')
    if end == -1 or end < start:
        return None
    return loader_c[start:end]


def main() -> int:
    hosts = (REPO / "SUPPORTED-HOSTS.md").read_text()
    loader_c = (REPO / "tests/c/loader.c").read_text()
    driver = (REPO / "scripts/test-loader.sh").read_text()
    gates = (REPO / "scripts/run-gates.sh").read_text()

    check("STANCE-SECTION", "## Fork safety" in hosts,
          "SUPPORTED-HOSTS.md carries the fork-safety stance section")
    check("STANCE-TABLE",
          "CKR_CRYPTOKI_NOT_INITIALIZED" in hosts
          and "CKR_GENERAL_ERROR" in hosts
          and "boot PID" in hosts,
          "stance names per-call-class child behavior + boot-PID mechanism")
    check("STANCE-PROBE", "A06a" in hosts,
          "stance cites the enforcing probe")
    check("PROBE-EXISTS",
          "static void case_a06_fork" in loader_c
          and "fork-child safe failure" in loader_c,
          "loader.c carries the fork-child probe")
    body = a06a_body(loader_c)
    check("PROBE-CRYPTO",
          body is not None
          and "C_SignInit" in body
          and "C_EncryptInit" in body,
          "A06a pins crypto-entry refusal (sign + encrypt init)")
    check("DRIVER-RUNS",
          '"$LOADER_BIN" "$SO"' in driver,
          "test-loader.sh runs the loader harness against the built .so")
    check("DRIVER-NAMES", "A06a" in driver,
          "test-loader.sh header references the fork probe")
    check("WIRED", "check-fork-stance.py" in gates,
          "run-gates.sh runs this gate")

    if failures:
        print(f"fork-stance: FAIL ({', '.join(failures)})")
        return 1
    print("fork-stance: OK (stance documented + enforcement pinned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
