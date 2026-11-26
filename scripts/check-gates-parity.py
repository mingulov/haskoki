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

# CI jobs outside the parity scope (documented, reviewed): the parity
# set is the haskell-job static step only. Release controls
# (publish, release-request) and heavy lanes (build/test, KAT,
# demo-image, hpc, reference) stay CI-side by design.
KNOWN_CI_ONLY = [
    "publish", "release-request", "Build and test", "Benchmark self-test",
    "pkcs11-fast", "pkcs11-kat", "demo-image-build", "demo-image-shards",
    "demo-image", "bundle", "c-drivers", "haskell-usdt",
]


def _tokens(line):
    """Shell-like tokens with quote-aware comment stripping."""
    return shlex.split(line, comments=True)


def parse_ci_step(text):
    """Return the ordered invocation list [(script, argv), ...].

    Expands the `for g in ...` loop INCLUDING its body arguments, so
    a body change (`python3 scripts/$g.py --strict`) is verified, not
    assumed. Conditionals fail closed: the static step must stay flat.
    """
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
        if stripped.startswith("if ") or stripped == "if":
            raise ValueError("conditional in CI static step needs gate support: %r"
                             % stripped)
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
            body_argv = None
            j = i + 1
            while j < len(lines):
                body = lines[j].strip()
                if body == "done" or body.startswith("done "):
                    break
                if body and not body.startswith("#") and "scripts/$g.py" in body:
                    try:
                        toks = _tokens(body)
                    except ValueError as exc:
                        raise ValueError("cannot parse CI loop body: %r" % body) from exc
                    if len(toks) < 2 or toks[0] != "python3" \
                            or toks[1] != "scripts/$g.py":
                        raise ValueError("unexpected CI loop body: %r" % body)
                    body_argv = tuple(toks[2:])
                elif body and not body.startswith("#"):
                    raise ValueError("unexpected CI loop body: %r" % body)
                j += 1
            if body_argv is None:
                raise ValueError("CI loop body has no $g invocation")
            for w in words:
                invocations.append(("scripts/%s.py" % w, body_argv))
            i = j
        elif stripped.startswith(("python3 ", "sh ", "bash ")):
            try:
                toks = _tokens(stripped)
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
    """Return the ordered invocation list from the static region.

    Markers must be echo statements (a comment carrying the marker
    text does not count). Invocations nested in `if` blocks are
    skipped: a conditional local gate surfaces as missing when CI
    lists it flat, which fails loudly instead of passing quietly.
    """
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines)
                  if ln.strip().startswith('echo "=== static gates')), None)
    end = next((i for i, ln in enumerate(lines)
                if ln.strip().startswith('echo "=== forced clean build')), None)
    if start is None or end is None or end <= start:
        raise ValueError("local static region markers not found")
    invocations = []
    depth = 0
    for raw in lines[start + 1:end]:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("if ") or stripped == "if":
            depth += 1
            continue
        if stripped == "fi" or stripped.startswith("fi ") \
                or stripped.endswith("; fi"):
            depth = max(0, depth - 1)
            continue
        if depth > 0:
            continue
        try:
            toks = _tokens(stripped)
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
    ci_args = ("      - name: Static gates (build-free)\n"
               "        run: |\n"
               "          for g in check-a \\\n"
               "              check-b; do\n"
               "            python3 scripts/$g.py --strict\n"
               "          done\n")
    local_args = ("echo \"=== static gates ===\"\n"
                  "python3 scripts/check-a.py --strict\n"
                  "python3 scripts/check-b.py --strict\n"
                  "echo \"=== forced clean build ===\"\n")
    local_noargs = ("echo \"=== static gates ===\"\n"
                    "python3 scripts/check-a.py --strict\n"
                    "python3 scripts/check-b.py\n"
                    "echo \"=== forced clean build ===\"\n")
    local_quoted = ("echo \"=== static gates ===\"\n"
                    "python3 scripts/check-a.py\n"
                    "python3 scripts/check-b.py\n"
                    "python3 scripts/check-c.py --self-test '#new'\n"
                    "echo \"=== forced clean build ===\"\n")
    ci_quoted = ("      - name: Static gates (build-free)\n"
                 "        run: |\n"
                 "          for g in check-a check-b; do\n"
                 "            python3 scripts/$g.py\n"
                 "          done\n"
                 "          python3 scripts/check-c.py --self-test '#new'\n")
    local_if = ("echo \"=== static gates ===\"\n"
                "python3 scripts/check-a.py\n"
                "python3 scripts/check-b.py\n"
                "if [ -n \"$X\" ]; then\n"
                "python3 scripts/check-c.py --self-test\n"
                "fi\n"
                "echo \"=== forced clean build ===\"\n")
    cases = [
        ("matching pair passes", ci_ok, local_ok, 0, []),
        ("missing check fails", ci_ok, local_drifted, 1,
         ["check-c.py"]),
        ("argv mismatch fails", ci_ok, local_argv, 1, ["--self-test"]),
        ("loop body args verified", ci_args, local_args, 0, []),
        ("loop body args missing fails", ci_args, local_noargs, 1,
         ["check-b.py"]),
        ("quoted hash arg survives", ci_quoted, local_quoted, 0, []),
        ("conditional local gate fails loud", ci_ok, local_if, 1,
         ["check-c.py"]),
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
    print("gates-parity: self-test %s"
          % ("ok: %d/%d" % (len(cases) - failed, len(cases)) if not failed else "FAIL"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
