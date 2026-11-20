#!/usr/bin/env python3
"""Planner/C join gate: every function row joins its planner route to
its C route with executable evidence.

Checks over generated spec/function-contracts.json:
  * every row carries a non-empty `c_route` (planner site + C site);
  * every row carries non-empty `test_evidence` (served rows point at
    proving suites, refused rows at refusal evidence);
  * every evidence entry names an existing spec file and a suite that
    resolves to an inventoried cabal suite, script driver, or reviewed
    task-label alias (shallow membership; deep Main-wiring stays
    single-sourced in the generator + check-test-wiring.py, which fail
    first on drift);
  * no two rows share a `c_route`.

Usage: python3 scripts/check-planner-join.py [--self-test]
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONTRACTS = REPO / "spec" / "function-contracts.json"
GENERATOR = REPO / "scripts" / "generate-function-contracts.py"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _resolvers():
    wiring = _load_module("join_wiring", REPO / "scripts" / "check-test-wiring.py")
    gen = _load_module("join_gen", GENERATOR)
    inv, err = wiring.load_inventory(REPO / "tests" / "suite-inventory.json")
    if err is not None:
        raise SystemExit("FAIL: cannot load suite inventory: %s" % err)
    drivers = {d["name"] for d in
               json.loads((REPO / "scripts" / "driver-inventory.json")
                          .read_text())["drivers"]}
    cabal_suites = set(wiring.parse_suites((REPO / "haskoki.cabal")
                                           .read_text()))
    return set(inv) | cabal_suites, drivers, set(gen.TASK_LABEL_OWNERS)


def validate(contracts):
    """Returns error strings (empty means joined).

    Join semantics only (c_route presence, evidence presence/shape,
    duplicate routes). ABI row coverage and generated-bytes freshness
    belong to check-denominators, which runs in the same loop: this
    gate never duplicates them.
    """
    errs = []
    if not isinstance(contracts, dict) or \
            not isinstance(contracts.get("functions"), list) or \
            not contracts["functions"]:
        return ["contracts file has no non-empty functions list"]
    suites, drivers, aliases = _resolvers()
    seen_routes = {}
    for row in contracts["functions"]:
        if not isinstance(row, dict):
            errs.append("row entry is not an object: %r" % (row,))
            continue
        name = row.get("name", "?")
        route = row.get("c_route")
        if not isinstance(route, str) or not route.strip():
            errs.append("%s: missing c_route" % name)
        elif route in seen_routes:
            errs.append("%s: duplicate c_route %r (also %s)"
                        % (name, route, seen_routes[route]))
        else:
            seen_routes[route] = name
        ev = row.get("test_evidence")
        if not isinstance(ev, list) or not ev:
            errs.append("%s: empty test_evidence" % name)
            continue
        for e in ev:
            if not isinstance(e, dict):
                errs.append("%s: evidence entry is not an object" % name)
                continue
            suite, spec = e.get("suite"), e.get("spec")
            if not isinstance(suite, str) or not suite:
                errs.append("%s: evidence suite is not a string" % name)
            elif suite not in suites and suite not in drivers \
                    and suite not in aliases:
                errs.append("%s: evidence suite %r resolves nowhere"
                            % (name, suite))
            if not isinstance(spec, str) or not (REPO / spec).is_file():
                errs.append("%s: evidence spec missing: %r" % (name, spec))
    return errs


def run_gate():
    if not CONTRACTS.exists():
        print("FAIL: %s missing" % CONTRACTS.relative_to(REPO))
        return 1
    try:
        contracts = json.loads(CONTRACTS.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        print("FAIL: cannot parse %s: %s" % (CONTRACTS.relative_to(REPO), e))
        return 1
    errs = validate(contracts)
    for e in errs:
        print("FAIL: " + e)
    if errs:
        return 1
    n = len(contracts["functions"])
    print("planner-join: ok (%d functions joined)" % n)
    return 0


def _fixture_row(**kw):
    row = {"name": "C_Fixture",
           "c_route": "planCall:F_Fixture + c-table:on_Fixture",
           "test_evidence": [
               {"suite": "haskoki-model-tests",
                "spec": "tests/model/LifecycleSpec.hs"}]}
    row.update(kw)
    return row


def self_test():
    bad = []

    def expect(name, errs, want=1):
        nonlocal bad
        ok = len([e for e in errs]) >= want if want else not errs
        print("%s %s: %s" % ("ok  " if ok else "FAIL", name,
                             errs if not ok or want == 0 else ""))
        if not ok:
            bad.append(name)

    base = {"functions": [_fixture_row()]}
    expect("valid-row", validate(base), 0)
    r = _fixture_row()
    del r["c_route"]
    expect("missing-route", validate({"functions": [r]}))
    r = _fixture_row(test_evidence=[])
    expect("empty-evidence", validate({"functions": [r]}))
    r = _fixture_row(test_evidence=[{"suite": "haskoki-model-tests",
                                     "spec": "tests/model/NoSuch.hs"}])
    expect("dangling-spec", validate({"functions": [r]}))
    r = _fixture_row(test_evidence=[{"suite": "no-such-suite",
                                     "spec": "tests/model/LifecycleSpec.hs"}])
    expect("unknown-suite", validate({"functions": [r]}))
    r1 = _fixture_row()
    r2 = _fixture_row(name="C_Other")
    expect("duplicate-route", validate({"functions": [r1, r2]}))
    expect("empty-register", validate({"functions": []}))
    # Idempotency: the generator run twice to isolated tmp outs yields
    # identical bytes. Tmp outs only — the battery never touches the
    # tree, so no restore (and no SIGKILL-mid-restore hazard) exists.
    outs, err = [], ""
    for _ in range(2):
        with tempfile.NamedTemporaryFile(suffix=".json",
                                         delete=False) as f:
            tmp_out = f.name
        r = subprocess.run([sys.executable, str(GENERATOR), tmp_out],
                           cwd=REPO, capture_output=True, text=True)
        if r.returncode != 0:
            err = r.stderr.strip()[:300]
            break
        outs.append(Path(tmp_out).read_bytes())
        Path(tmp_out).unlink()
    ok = len(outs) == 2 and outs[0] == outs[1]
    print("%s idempotent-regen: %s" % ("ok  " if ok else "FAIL", err))
    if not ok:
        bad.append("idempotent-regen")
    if bad:
        return 1
    print("planner-join self-test: ok")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(run_gate())
