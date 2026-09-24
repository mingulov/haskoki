#!/usr/bin/env python3
"""Release-install driver pins: scripts/test-release-install.sh must
pass AS DIRECTLY INVOKED on the host (no manual-flags workaround).

Fails (exit 1) when any rule fails:

* NETFLAG: the inner `docker run` carries `--network host` (default-bridge
  DNS is dead in this environment; without the flag the in-container
  apt-get dies and the script fails).
* TIMEOUT: every docker invocation in the driver is prefixed with
  `timeout -s KILL` per the standing hard rule.
* LOUDAPT: apt-get update/install failures fail loudly with a clear
  message (no silent fall-through to `cc: not found`).
* IMGOVERRIDE: the image override ($2) is honored.
* CONTRACT: the acceptance steps keep their contract (ldd
  zero-unresolved, ctl --version, smoke SMOKE-OK, PASS line).

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-release-install-flags.py
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DRIVER = REPO / "scripts" / "test-release-install.sh"

failures = []


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


def main() -> int:
    src = DRIVER.read_text()

    check("NETFLAG", "--network host" in src,
          "inner docker run carries --network host")
    check("TIMEOUT", "timeout -s KILL" in src,
          "docker invocation prefixed timeout -s KILL")
    check("LOUDAPT", "apt-get update" in src and "apt-get install" in src
          and ("apt failed" in src or "apt-get failed" in src),
          "apt failure fails loudly with a clear message")
    check("IMGOVERRIDE", 'IMAGE="${2:-ubuntu:26.04}"' in src
          and '"$IMAGE"' in src,
          "image override $2 honored")
    check("CONTRACT", 'grep "not found"' in src
          and "haskoki-ctl --version" in src
          and "/tmp/release_smoke /art/lib/libhaskoki.so" in src
          and "PASS: test-release-install.sh" in src,
          "ldd + ctl + smoke + PASS contract intact")

    if failures:
        print(f"release-install-flags: FAIL: {len(failures)} rule(s) failed")
        return 1
    print("release-install-flags: ok: driver passing as-invoked (5/5)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
