#!/usr/bin/env python3
"""Gate parity: every CI static-loop invocation must run in run-gates.sh.

Compares exact invocations (script + argv) from the `Static gates
(build-free)` step of `.github/workflows/ci.yml` against the static
region of `scripts/run-gates.sh` (between the `=== static gates` and
`=== forced build` markers). Local extras are permitted (the local
runner is intentionally a superset: release-evidence fixtures and
journey self-tests run locally and in other CI jobs); anything the
CI loop runs but the local gate does not is a FAIL naming the exact
missing command line.

STDLIB ONLY. Run from anywhere:
  python3 scripts/check-gates-parity.py [--ci PATH] [--local PATH]
  python3 scripts/check-gates-parity.py --self-test
"""
import argparse
import shlex
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CI_DEFAULT = REPO / ".github" / "workflows" / "ci.yml"
LOCAL_DEFAULT = REPO / "scripts" / "run-gates.sh"
STEP_MARKER = "- name: Static gates (build-free)"
LOCAL_START = "=== static gates"
LOCAL_END = "forced clean build"

# CI jobs outside the parity scope (documented, reviewed): the parity
# set is the haskell-job static step only. Release controls
# (publish, release-request) and heavy lanes (build/test, KAT,
# demo-image, hpc, reference) stay CI-side by design.
KNOWN_CI_ONLY = [
    "publish", "release-request", "Build and test", "Benchmark self-test",
    "pkcs11-fast", "pkcs11-kat", "demo-image-build", "demo-image-shards",
    "demo-image", "bundle", "c-drivers",
]


def parse_ci_step(text):
    """Return the ordered invocation list [(script, argv), ...]."""
    start = text.find(STEP_MARKER)
    if start < 0:
        raise ValueError("CI static-gates step not found")
    rest = text[start:]
    nxt = rest.find("\n      - name: ", 1)
    block = rest[:nxt] if nxt > 0 else rest
    invocations = []
    lines = block.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("for g in "):
            words = []
            frag = stripped[len("for g in "):]
            while True:
                if "; do" in frag:
                    frag = frag.split("; do", 1)[0]
                    words.extend(frag.replace("\\", " ").split())
                    break
                words.extend(frag.replace("\\", " ").split())
                i += 1
                if i >= len(lines):
                    raise ValueError("unterminated for-list in CI loop")
                frag = lines[i].strip()
            for w in words:
                invocations.append(("scripts/%s.py" % w, ()))
        elif stripped.startswith("python3 ") and "$g" not in stripped:
            # Lines carrying $g are the for-loop body, already expanded above.
            try:
                toks = shlex.split(stripped.split("#", 1)[0])
            except ValueError as exc:
                raise ValueError("cannot parse CI line: %r" % stripped) from exc
            if len(toks) < 2:
                raise ValueError("cannot parse CI line: %r" % stripped)
            invocations.append((toks[1], tuple(toks[2:])))
        i += 1
    if not invocations:
        raise ValueError("no invocations parsed from CI step")
    return invocations


def parse_local_region(text):
    """Return the ordered invocation list from the static region."""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if LOCAL_START in ln), None)
    end = next((i for i, ln in enumerate(lines) if LOCAL_END in ln), None)
    if start is None or end is None or end <= start:
        raise ValueError("local static region markers not found")
    invocations = []
    for raw in lines[start + 1:end]:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            toks = shlex.split(stripped.split("#", 1)[0])
        except ValueError:
            continue
        if not toks:
            continue
        if toks[0] == "python3" and len(toks) >= 2:
            rest = toks[1:]
            if rest and rest[0] == "-I":
                rest = rest[1:]
            if rest:
                invocations.append((rest[0], tuple(rest[1:])))
        elif toks[0] in ("sh", "bash") and len(toks) >= 2:
            invocations.append((toks[1], tuple(toks[2:])))
    if not invocations:
        raise ValueError("no invocations parsed from local region")
    return invocations


def check(ci_path, local_path):
    ci = parse_ci_step(Path(ci_path).read_text())
    local = parse_local_region(Path(local_path).read_text())
    local_set = set(local)
    missing = [inv for inv in ci if inv not in local_set]
    return ci, local, missing


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--ci", default=str(CI_DEFAULT))
    ap.add_argument("--local", default=str(LOCAL_DEFAULT))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        ci, local, missing = check(args.ci, args.local)
    except (OSError, ValueError) as exc:
        print("gates-parity: FAIL: %s" % exc)
        return 1
    if missing:
        print("gates-parity: FAIL: %d CI invocation(s) missing locally:"
              % len(missing))
        for script, argv in missing:
            print("  missing: python3 %s %s" % (script, " ".join(argv)))
        return 1
    print("gates-parity: ok: %d CI invocations all present locally "
          "(%d local invocations)" % (len(ci), len(local)))
    return 0


def self_test():
    import tempfile
    ci_ok = ("      - name: Static gates (build-free)\n"
             "        run: |\n"
             "          set -euo pipefail\n"
             "          for g in check-a check-b; do\n"
             "            python3 scripts/$g.py\n"
             "          done\n"
             "          python3 scripts/check-c.py --self-test\n")
    local_ok = ("echo \"=== static gates ===\"\n"
                "python3 scripts/check-a.py\n"
                "python3 scripts/check-b.py\n"
                "python3 scripts/check-c.py --self-test\n"
                "echo \"=== forced clean build ===\"\n")
    local_drifted = local_ok.replace(
        "python3 scripts/check-c.py --self-test\n", "")
    local_argv = local_ok.replace(
        "python3 scripts/check-c.py --self-test\n",
        "python3 scripts/check-c.py\n")
    cases = [
        ("matching pair passes", ci_ok, local_ok, 0, []),
        ("missing check fails", ci_ok, local_drifted, 1,
         ["check-c.py"]),
        ("argv mismatch fails", ci_ok, local_argv, 1, ["--self-test"]),
    ]
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        for label, ci_text, local_text, want_rc, want_words in cases:
            ci_p = Path(tmp) / "ci.yml"
            local_p = Path(tmp) / "run-gates.sh"
            ci_p.write_text(ci_text)
            local_p.write_text(local_text)
            try:
                _, _, missing = check(str(ci_p), str(local_p))
                rc = 1 if missing else 0
            except ValueError:
                rc, missing = 1, []
            detail = " ".join("%s %s" % (s, " ".join(a)) for s, a in missing)
            ok = rc == want_rc and all(w in detail or rc == 0
                                       for w in want_words)
            print("%s: self-test %s" % ("ok" if ok else "FAIL", label))
            failed += not ok
    print("gates-parity: self-test %s" % ("ok: 3/3" if not failed else "FAIL"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
