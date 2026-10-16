#!/usr/bin/env python3
"""Sealed call-work gate: the fixture bypass stays out of shipped code.

Call work admits through checked construction only; the fixture
constructor and the fixture submit entrypoint exist for tests.
This gate pins that split two ways (both must pass):

Gate 1 (fixture-name confinement): the names 'mkFixtureCallWork'
and 'startFixtureJob' appear in shipped Haskell sources only at
their own definitions and Haddock references. Shipped sources are
every production hs-source-dir: core, src, ffi, app, tools,
examples, bench, client. Test trees (tests/, test/) may use both
names freely and are never scanned. A line in a shipped file is
excused only when it is one of:
  * an export-list entry:   `, mkFixtureCallWork`
  * a type signature:       `startFixtureJob :: ...`
  * a column-0 definition:  `mkFixtureCallWork sid res eff = ...`
    (column-anchored, so an indented caller cannot hide behind it)
  * a Haddock prose reference with the name single-quoted:
    `'mkFixtureCallWork'`, `('Haskoki.Runtime.Async.startFixtureJob')`
    (prose quotes the names; code cannot quote a use, so stripping
    single-quoted spans before matching keeps docs working while
    every bare use still fails)
Anything else — an indented caller, a use in an expression, an
unquoted mention — fails the gate.

Gate 3 (no raw-pair inspection): no production match takes the
call-work pair apart. The scan flags `WorkCall res ...` (binds
the triple), `WorkCall _ ...` (the 2-ary wildcard: drops one
field and inspects the rest), and `WorkCall (...` (direct
application). Deliberately NOT flagged is the closed 1-ary
wildcard `WorkCall _)`: it binds nothing and cannot inspect the
triple, and the two outer-function refusal arms over key
functions use exactly that form
(`jobFunctionCoherent JobGenKey[Pair] (WorkCall _) = False` in
src/Haskoki/Runtime/Async.hs). The pattern encodes this by
matching a wildcard only when followed by a space
(`WorkCall _ `), so the closed form never matches while every
inspecting form does. Since `CallWork` is abstract, raw-pair
inspection would also be a type error; this gate is the textual
backstop.

Non-vacuity: the gate fails when either scan sees zero files,
and gate 1 additionally requires its two known definition files
to be among the scanned set, so an empty or misrooted checkout
cannot pass by seeing nothing.

Usage:
  python3 scripts/check-sealed-callwork.py            scan the tree
  python3 scripts/check-sealed-callwork.py --self-test
      negative controls on synthetic fixtures: planted callers in
      shipped dirs fail, excused shapes pass, and the closed
      wildcard passes while inspecting shapes fail.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-sealed-callwork.py
"""
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Every production hs-source-dir (gate 1 scope). Test trees are
# excluded on purpose: tests own the fixture entrypoints.
SHIPPED_DIRS = ("core", "src", "ffi", "app", "tools",
                "examples", "bench", "client")

# Gate 3 scope: the production submit/read legs.
INSPECT_DIRS = ("src", "ffi")

FIXTURE_NAMES = ("mkFixtureCallWork", "startFixtureJob")

# Definition files that must be in the scanned set (vacuity pin).
REQUIRED_FILES = (
    "core/Haskoki/CallWork.hs",
    "src/Haskoki/Runtime/Async.hs",
)

EXPORT_RE = re.compile(r"^\s*, (mkFixtureCallWork|startFixtureJob)\s*$")
SIG_RE = re.compile(r"^\s*(mkFixtureCallWork|startFixtureJob) ::")
DEF_RE = re.compile(r"^(mkFixtureCallWork|startFixtureJob) [a-z]")
QUOTED_RE = re.compile(r"'[^']*'")
NAME_RE = re.compile(r"mkFixtureCallWork|startFixtureJob")

# Wildcard matches only with a trailing space (the 2-ary,
# inspecting shape); the closed 1-ary `WorkCall _)` never matches.
INSPECT_RE = re.compile(r"WorkCall res|WorkCall _ |WorkCall \(")


def hs_files(root, dirs):
    out = []
    for d in dirs:
        base = root / d
        if base.is_dir():
            out.extend(sorted(base.rglob("*.hs")))
    return out


def gate1_violations(root):
    """(violations, scanned): bare fixture-name uses in shipped code."""
    violations = []
    files = hs_files(root, SHIPPED_DIRS)
    for path in files:
        rel = path.relative_to(root).as_posix()
        for no, line in enumerate(path.read_text().splitlines(), start=1):
            if not NAME_RE.search(line):
                continue
            if EXPORT_RE.match(line) or SIG_RE.match(line) \
                    or DEF_RE.match(line):
                continue
            if NAME_RE.search(QUOTED_RE.sub("", line)):
                violations.append(f"{rel}:{no}:{line.rstrip()}")
    return violations, files


def gate3_violations(root):
    """(violations, scanned): raw-pair inspection in production."""
    violations = []
    files = hs_files(root, INSPECT_DIRS)
    for path in files:
        rel = path.relative_to(root).as_posix()
        for no, line in enumerate(path.read_text().splitlines(), start=1):
            if INSPECT_RE.search(line):
                violations.append(f"{rel}:{no}:{line.rstrip()}")
    return violations, files


def check(root, verbose=True):
    failures = []
    out = []

    def emit(msg):
        out.append(msg)
        if verbose:
            print(msg)

    v1, f1 = gate1_violations(root)
    scanned1 = {p.relative_to(root).as_posix() for p in f1}
    missing = [r for r in REQUIRED_FILES if r not in scanned1]
    if not f1 or missing or v1:
        failures.append("gate1")
        emit(f"FAIL: gate1: files={len(f1)} missing={missing} "
             f"violations={len(v1)}")
        for v in v1[:10]:
            emit(f"  {v}")
    else:
        emit(f"ok: gate1: {len(f1)} shipped files, fixture names "
             f"confined to definitions and quoted refs")

    v3, f3 = gate3_violations(root)
    if not f3 or v3:
        failures.append("gate3")
        emit(f"FAIL: gate3: files={len(f3)} violations={len(v3)}")
        for v in v3[:10]:
            emit(f"  {v}")
    else:
        emit(f"ok: gate3: {len(f3)} production files, no raw-pair "
             f"inspection (closed 1-ary wildcard excused)")

    if failures:
        emit(f"sealed-callwork: FAIL ({', '.join(failures)})")
        return 1
    emit("sealed-callwork: OK (fixture split pinned)")
    return 0


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def self_test():
    """Negative controls: planted violations fail, excused shapes pass."""
    failures = []

    def check_rule(rule, cond, detail):
        print(f"{'ok' if cond else 'FAIL'}: self: {rule}: {detail}")
        if not cond:
            failures.append(rule)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        # Required files must exist for a passing tree.
        write(root, "core/Haskoki/CallWork.hs",
              "module Haskoki.CallWork\n  ( CallWork\n  , mkFixtureCallWork\n  ) where\n"
              "-- | Fixtures construct through 'mkFixtureCallWork' here.\n"
              "mkFixtureCallWork :: SessionId -> Reservation -> EffectRequest -> CallWork\n"
              "mkFixtureCallWork sid res eff = CallWork sid res eff\n")
        write(root, "src/Haskoki/Runtime/Async.hs",
              "module Haskoki.Runtime.Async\n  ( startJob\n  , startFixtureJob\n  ) where\n"
              "-- | The fixture entrypoint ('Haskoki.Runtime.Async.startFixtureJob').\n"
              "startFixtureJob :: AsyncTable -> JobRequest -> IO (Either StartDeny JobId)\n"
              "startFixtureJob table req =\n  startJobChecked table req initial False\n"
              "jobFunctionCoherent JobGenKey (WorkCall _) = False\n"
              "workEffect (WorkCall w) = callWorkEffect w\n")
        # A clean tree passes.
        v1, _ = gate1_violations(root)
        v3, _ = gate3_violations(root)
        check_rule("clean-passes", not v1 and not v3,
                   "excused shapes pass both gates")

        # Gate 1: a planted caller in a shipped dir fails ...
        write(root, "app/Sneaky.hs",
              "module Sneaky where\nrun t r = startFixtureJob t r\n")
        v1, _ = gate1_violations(root)
        check_rule("caller-in-app-fails",
                   any("app/Sneaky.hs" in v for v in v1),
                   "planted app/ caller flagged")
        # ... as does an indented same-file caller ...
        write(root, "src/Haskoki/Runtime/Async.hs",
              (root / "src/Haskoki/Runtime/Async.hs").read_text()
              + "helper t r =\n  startFixtureJob t r\n")
        v1, _ = gate1_violations(root)
        check_rule("indented-caller-fails",
                   any("Async.hs" in v for v in v1),
                   "indented caller flagged")
        # ... and an unquoted prose mention ...
        write(root, "core/Note.hs",
              "module Note where\n-- call startFixtureJob for legacy rows\n")
        v1, _ = gate1_violations(root)
        check_rule("unquoted-mention-fails",
                   any("core/Note.hs" in v for v in v1),
                   "unquoted mention flagged")
        # ... while the same mention single-quoted passes.
        write(root, "core/Note.hs",
              "module Note where\n-- call 'startFixtureJob' for legacy rows\n")
        v1, _ = gate1_violations(root)
        check_rule("quoted-mention-passes",
                   not any("core/Note.hs" in v for v in v1),
                   "quoted mention excused")

        # Gate 3: inspecting shapes fail ...
        write(root, "src/Peek.hs",
              "module Peek where\n"
              "a (WorkCall res eff) = res\n"
              "b (WorkCall _ eff) = eff\n"
              "c = WorkCall (x, y)\n")
        v3, _ = gate3_violations(root)
        flagged = [v for v in v3 if "src/Peek.hs" in v]
        check_rule("inspecting-shapes-fail", len(flagged) == 3,
                   f"3 planted inspections flagged ({len(flagged)})")
        # ... while the closed wildcard and accessor reads pass.
        write(root, "src/Peek.hs",
              "module Peek where\n"
              "a JobGenKey (WorkCall _) = False\n"
              "b (WorkCall w) = callWorkEffect w\n"
              "data W = WorkCall !CallWork\n")
        v3, _ = gate3_violations(root)
        check_rule("closed-wildcard-passes",
                   not any("src/Peek.hs" in v for v in v3),
                   "closed wildcard, accessor read, declaration pass")

        # Vacuity pins: a tree without the definition files fails
        # the full check instead of passing by seeing nothing.
        with tempfile.TemporaryDirectory() as tmp2:
            thin = Path(tmp2)
            write(thin, "src/Only.hs", "module Only where\n")
            rc_thin = check(thin, verbose=False)
            check_rule("misrooted-tree-fails", rc_thin != 0,
                       "tree without the definition files fails")

    # The live tree passes (the gate holds on this checkout).
    rc = check(REPO, verbose=False)
    check_rule("live-tree-passes", rc == 0, "this checkout passes")
    # The live tree actually contains the refused shapes in tests
    # (the scan would see them if tests/ were in scope): the gate
    # is not passing for lack of targets.
    test_hits = 0
    for path in (REPO / "tests",):
        for hs in path.rglob("*.hs"):
            text = hs.read_text()
            if "startFixtureJob" in text:
                test_hits += 1
    check_rule("targets-exist", test_hits > 10,
               f"{test_hits} test files use the fixture entrypoint")

    if failures:
        print(f"self-test: FAIL ({', '.join(failures)})")
        return 1
    print("self-test: OK (all negative controls behave)")
    return 0


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) != 1:
        print("usage: check-sealed-callwork.py [--self-test]")
        return 2
    return check(REPO)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
