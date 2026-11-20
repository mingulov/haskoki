#!/usr/bin/env python3
"""P-01 checker baseline diff gate: the fast-lane results must match the
frozen baseline except for provider improvements (fewer failures).

Inputs: a lane results.json (pkcs11-check --output json) and the frozen
baseline spec/pkcs11-check/baseline-fast-<checker-sha>-openssl-memory.json.
Exit 0 pass, 1 gate violations, 2 unusable input (missing/corrupt file,
wrong schema, absent envelope). Every refusal names its reason; nothing
ever passes on a traceback.

Rules (P-01 baseline: six rules + input contracts):
  0. Provenance: results provenance.framework.commit must equal the
     baseline checker_pin; a mismatch names both pins (R-11 skew rule).
     The version tag alone is not accepted: tags can move, SHAs cannot.
  1. Internal reconciliation (doctored-input detection): per-id outcome
     counts must match the summary; unit count sums must match the
     summary; skip-reason and per-target skip sums must match
     summary.skipped; the summary must add up to total.
  2. Zero invariants: crashed, timeout, error, xpassed, child_crash,
     child_timeout, crash_limited are present and 0; incomplete is
     falsy. Crashed/timeout ids must be subsets of the (empty) frozen
     sets, which is the same assertion in uniform machinery.
  3. failed ids and xfailed ids are subsets of the frozen sets: a new
     failure blocks, a fixed failure (or flipped xfail) passes. The
     conversions stay visible in the uploaded results artifact.
  4. passed and total never drop below frozen (a drop needs a reviewed
     re-freeze, e.g. after a checker update, which also changes the
     envelope SHA and forces a new baseline file).
  5. Skips freeze exactly: the reason multiset and the per-target skip
     vector must equal frozen (any drift fails for review), because
     per-id skip records do not exist in any artifact (measured: the
     JSON, junit and stdout legs are all aggregated for skips), so
     reasons key the ledger rows instead. Targets are normalized to
     the testcases/-relative form since lanes emit absolute paths.
  6. Smoke and doctor are enforced elsewhere and documented here, not
     re-verified: smoke stays 0 findings via the demo-image contracts
     shard (hash-locked v0.3.0 wheel, same version as the fast lane);
     doctor exit 0 is lane-enforced (the lane exits before results
     exist when doctor fails).

Usage: python3 scripts/check-pkcs11-baseline.py <results.json> <baseline.json>
       python3 scripts/check-pkcs11-baseline.py --self-test
"""

import contextlib
import copy
import io
import json
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = 1
ZERO_KEYS = ("crashed", "timeout", "error", "xpassed",
             "child_crash", "child_timeout", "crash_limited")
COUNT_KEYS = ("passed", "failed", "skipped", "xfailed", "xpassed",
              "error", "crashed", "timeout", "crash_limited")


class InputError(Exception):
    """Unusable input: exit 2 with a clear message, never a traceback."""


def load_json(path, what):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise InputError("missing %s file: %s" % (what, path))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        raise InputError("cannot parse %s file %s: %s" % (what, path, e))
    if not isinstance(data, dict):
        raise InputError("%s file %s is not a JSON object" % (what, path))
    return data


def norm_nodeid(nid):
    """testcases/-relative nodeid: lanes emit src/pkcs11_check/...-prefixed ids."""
    if not isinstance(nid, str) or not nid:
        raise InputError("nodeid is not a non-empty string: %r" % (nid,))
    prefix = "src/pkcs11_check/"
    if nid.startswith(prefix):
        nid = nid[len(prefix):]
    return nid


def norm_target(target):
    """testcases/-relative target: lanes emit absolute TMPDIR-bound paths."""
    if not isinstance(target, str) or not target:
        raise InputError("unit target is not a non-empty string: %r" % (target,))
    marker = "testcases/"
    if marker in target:
        target = "testcases/" + target.split(marker, 1)[1]
    return target


def collect_ids(units):
    """Per-id outcomes from units[].tests[] (failed/xfailed only upstream)."""
    by_outcome = {"failed": [], "xfailed": [], "crashed": [],
                  "timeout": [], "error": [], "xpassed": []}
    for u in units:
        for t in u.get("tests", []):
            if not isinstance(t, dict):
                raise InputError("unit test entry is not an object: %r" % (t,))
            out = t.get("outcome")
            if out not in by_outcome:
                raise InputError("unknown test outcome %r (id %r)"
                                 % (out, t.get("nodeid")))
            by_outcome[out].append(norm_nodeid(t.get("nodeid")))
    for out in by_outcome:
        if len(set(by_outcome[out])) != len(by_outcome[out]):
            raise InputError("duplicate %s ids in results" % out)
    return by_outcome


def collect_skips(units):
    """Reason multiset + per-target skip vector (the only skip records)."""
    reasons = {}
    by_target = {}
    for u in units:
        target = norm_target(u.get("target"))
        counts = u.get("counts")
        if not isinstance(counts, dict):
            raise InputError("unit %s has no counts object" % target)
        n = counts.get("skipped", 0)
        if not isinstance(n, int) or n < 0:
            raise InputError("unit %s skipped count is not a nat: %r"
                             % (target, n))
        if n:
            by_target[target] = by_target.get(target, 0) + n
        sr = u.get("skip_reasons", {})
        if not isinstance(sr, dict):
            raise InputError("unit %s skip_reasons is not an object" % target)
        for reason, k in sr.items():
            if not isinstance(reason, str) or not reason:
                raise InputError("unit %s has a bad skip reason: %r"
                                 % (target, reason))
            if not isinstance(k, int) or k < 0:
                raise InputError("skip reason %r count is not a nat: %r"
                                 % (reason, k))
            if k:
                reasons[reason] = reasons.get(reason, 0) + k
    return reasons, by_target


def check_reconcile(results, summary, ids):
    """Rule 1: the file must agree with itself (doctored-input tripwire)."""
    bad = []
    units = results.get("units")
    if not isinstance(units, list) or not units:
        raise InputError("results has no non-empty units list")
    for u in units:
        if not isinstance(u, dict):
            raise InputError("unit entry is not an object: %r" % (u,))
        if u.get("status") not in ("passed", "failed"):
            bad.append("unit %r has unexpected status %r"
                       % (u.get("target"), u.get("status")))
    for out in ("failed", "xfailed", "crashed", "timeout",
                "error", "xpassed"):
        if len(ids[out]) != summary.get(out, 0):
            bad.append("reconcile: %d %s ids but summary.%s=%s"
                       % (len(ids[out]), out, out, summary.get(out)))
    for key in COUNT_KEYS:
        want = summary.get(key, 0)
        got = sum(u.get("counts", {}).get(key, 0) for u in units)
        if got != want:
            bad.append("reconcile: unit %s sums to %d but summary.%s=%s"
                       % (key, got, key, want))
    parts = sum(summary.get(k, 0) for k in
                ("passed", "failed", "crashed", "timeout", "xfailed",
                 "skipped", "error", "xpassed"))
    if parts != summary.get("total", 0):
        bad.append("reconcile: outcome parts sum to %d but total=%s"
                   % (parts, summary.get("total")))
    return bad


def check_gate(results, baseline):
    """Rules 0,2-5. Returns violation strings (empty means pass)."""
    bad = []
    for key in ("provenance", "summary"):
        if not isinstance(results.get(key), dict):
            raise InputError("results.%s is not an object" % key)
    if not isinstance(baseline.get("summary"), dict):
        raise InputError("baseline.summary is not an object")
    units = results.get("units")
    if not isinstance(units, list) or not units:
        raise InputError("results has no non-empty units list")
    fw = results["provenance"].get("framework", {})
    if not isinstance(fw, dict):
        raise InputError("results provenance.framework is not an object")
    got_pin = fw.get("commit")
    want_pin = baseline.get("checker_pin")
    if not isinstance(got_pin, str) or not got_pin:
        raise InputError("results lack provenance.framework.commit "
                         "(run the lane with PKCS11_CHECK_DIR)")
    if got_pin != want_pin:
        bad.append("checker pin skew: results envelope %s but baseline "
                   "freezes %s" % (got_pin, want_pin))
        return bad  # nothing else is comparable across pins
    summary = results["summary"]
    ids = collect_ids(units)
    bad.extend(check_reconcile(results, summary, ids))
    for key in ZERO_KEYS:
        val = summary.get(key, "MISSING")
        if val != 0 or isinstance(val, bool):
            bad.append("zero invariant: summary.%s=%r, want int 0" % (key, val))
    if summary.get("incomplete"):
        bad.append("zero invariant: incomplete=%r, want falsy"
                   % (summary.get("incomplete"),))
    for out in ("failed", "xfailed", "crashed", "timeout"):
        new = sorted(set(ids[out]) - set(baseline.get(out + "_ids", [])))
        if new:
            bad.append("%d new %s ids (first: %s)"
                       % (len(new), out, "; ".join(new[:3])))
    for key in ("passed", "total"):
        got, want = summary.get(key, 0), baseline.get("summary", {}).get(key, 0)
        if got < want:
            bad.append("%s dropped: results %s below frozen %s"
                       % (key, got, want))
    reasons, by_target = collect_skips(units)
    if sum(reasons.values()) != summary.get("skipped", 0):
        bad.append("reconcile: skip reasons sum to %d but skipped=%s"
                   % (sum(reasons.values()), summary.get("skipped")))
    if sum(by_target.values()) != summary.get("skipped", 0):
        bad.append("reconcile: per-target skips sum to %d but skipped=%s"
                   % (sum(by_target.values()), summary.get("skipped")))
    if reasons != baseline.get("skip_reasons", {}):
        new_r = sorted(set(reasons) - set(baseline.get("skip_reasons", {})))
        if new_r:
            bad.append("new skip reasons: %s" % "; ".join(new_r[:3]))
        else:
            bad.append("skip reason counts drifted vs frozen")
    if by_target != baseline.get("skipped_by_target", {}):
        bad.append("per-target skip vector drifted vs frozen")
    return bad


def run_gate(results_path, baseline_path):
    """Returns (exit_code, report_line)."""
    try:
        results = load_json(results_path, "results")
        baseline = load_json(baseline_path, "baseline")
    except InputError as e:
        return 2, "pkcs11-baseline: %s" % e
    try:
        if results.get("tool") != "pkcs11-check" or \
                results.get("kind") != "test-run":
            raise InputError("not a pkcs11-check test-run report")
        if baseline.get("schema_version") != SCHEMA_VERSION:
            raise InputError("baseline schema_version=%r, want %d"
                             % (baseline.get("schema_version"),
                                SCHEMA_VERSION))
        bad = check_gate(results, baseline)
    except InputError as e:
        return 2, "pkcs11-baseline: %s" % e
    s = results.get("summary", {})
    if bad:
        return 1, "pkcs11-baseline-DRIFT: %s" % "; ".join(bad)
    return 0, ("pkcs11-baseline-ok: %d tests (%d passed, %d failed, "
               "%d xfailed, %d skipped) match baseline %s"
               % (s.get("total"), s.get("passed"), s.get("failed"),
                  s.get("xfailed"), s.get("skipped"),
                  baseline.get("checker_pin")))


SHA_A = "a" * 40
SHA_B = "b" * 40


def _fixture_pair():
    """Minimal valid baseline + matching results (10 tests)."""
    counts_a = {"passed": 6, "failed": 1, "skipped": 0, "xfailed": 1,
                "xpassed": 0, "error": 0, "crashed": 0, "timeout": 0,
                "crash_limited": 0}
    counts_b = dict(counts_a, passed=0, failed=0, skipped=2, xfailed=0)
    results = {
        "tool": "pkcs11-check", "kind": "test-run",
        "summary": {"total": 10, "passed": 6, "failed": 1, "crashed": 0,
                    "timeout": 0, "xfailed": 1, "skipped": 2, "error": 0,
                    "xpassed": 0, "incomplete": False, "child_crash": 0,
                    "child_timeout": 0, "crash_limited": 0},
        "provenance": {"framework": {"version": "v0.3.0", "dirty": False,
                                     "source": "git-describe",
                                     "commit": SHA_A}},
        "units": [
            {"target": "/tmp/p11/src/pkcs11_check/testcases/a.py",
             "status": "failed", "returncode": 1, "counts": counts_a,
             "tests": [
                 {"nodeid": "src/pkcs11_check/testcases/a.py::T::t_fail",
                  "outcome": "failed"},
                 {"nodeid": "src/pkcs11_check/testcases/a.py::T::t_xfail",
                  "outcome": "xfailed"}]},
            {"target": "/tmp/p11/src/pkcs11_check/testcases/b.py",
             "status": "passed", "returncode": 0, "counts": counts_b,
             "skip_reasons": {"needs widget": 2}},
        ],
    }
    baseline = {
        "schema_version": SCHEMA_VERSION, "checker_pin": SHA_A,
        "lane": "fast", "backend": "openssl-memory", "mode": "direct",
        "summary": {"total": 10, "passed": 6, "failed": 1, "crashed": 0,
                    "timeout": 0, "xfailed": 1, "skipped": 2},
        "failed_ids": ["testcases/a.py::T::t_fail"],
        "xfailed_ids": ["testcases/a.py::T::t_xfail"],
        "crashed_ids": [], "timeout_ids": [],
        "skip_reasons": {"needs widget": 2},
        "skipped_by_target": {"testcases/b.py": 2},
    }
    return baseline, results


def _run_case(tmp, name, res=None, base=None, raw_res=None):
    base_path = str(tmp / "base.json")
    res_path = str(tmp / "res.json")
    with open(base_path, "w", encoding="utf-8") as f:
        json.dump(base, f)
    with open(res_path, "w", encoding="utf-8") as f:
        f.write(raw_res if raw_res is not None else json.dumps(res))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code, line = run_gate(res_path, base_path)
    print("%s -> exit %d: %s" % (name, code, line))
    return code, line


def self_test():
    tmp = Path(tempfile.mkdtemp(prefix="baseline-selftest-"))
    passed = 0

    def check(name, cond):
        nonlocal passed
        if not cond:
            raise SystemExit("SELF-TEST FAIL: %s" % name)
        print("ok: %s" % name)
        passed += 1

    base, res = _fixture_pair()
    code, line = _run_case(tmp, "valid", res, base)
    check("valid matching input passes", code == 0 and "-ok:" in line)

    r = copy.deepcopy(res)
    r["summary"]["failed"] = 0  # doctored: hide the failure in counters
    code, line = _run_case(tmp, "doctored", r, base)
    check("doctored counters fail", code == 1 and "reconcile" in line)

    r = copy.deepcopy(res)
    r["units"][0]["tests"].append(
        {"nodeid": "src/pkcs11_check/testcases/a.py::T::t_new",
         "outcome": "failed"})
    r["units"][0]["counts"]["failed"] = 2
    r["summary"]["failed"] = 2
    r["summary"]["total"] = 11
    code, line = _run_case(tmp, "new-failed", r, base)
    check("new failed id fails", code == 1 and "new failed ids" in line)

    r = copy.deepcopy(res)  # improvement: the failure got fixed
    r["units"][0]["tests"] = [t for t in r["units"][0]["tests"]
                              if t["outcome"] != "failed"]
    r["units"][0]["counts"]["failed"] = 0
    r["units"][0]["counts"]["passed"] = 7
    r["units"][0]["status"] = "passed"
    r["summary"]["failed"] = 0
    r["summary"]["passed"] = 7
    code, line = _run_case(tmp, "fixed-failure", r, base)
    check("fixed failure passes", code == 0)

    for outcome, key in (("crashed", "crashed"), ("timeout", "timeout")):
        r = copy.deepcopy(res)
        r["units"][0]["tests"].append(
            {"nodeid": "src/pkcs11_check/testcases/a.py::T::t_%s" % outcome,
             "outcome": outcome})
        r["units"][0]["counts"][key] = 1
        r["summary"][key] = 1
        r["summary"]["total"] = 11
        code, line = _run_case(tmp, outcome, r, base)
        check("%s fails" % outcome, code == 1 and key in line)

    r = copy.deepcopy(res)
    r["summary"]["passed"] = 5
    r["summary"]["total"] = 9
    code, line = _run_case(tmp, "passed-drop", r, base)
    check("passed drop fails", code == 1 and "dropped" in line)

    r = copy.deepcopy(res)
    r["summary"]["total"] = 9
    r["summary"]["passed"] = 5
    code, line = _run_case(tmp, "total-drop", r, base)
    check("total drop fails", code == 1 and "total dropped" in line)

    r = copy.deepcopy(res)
    r["units"][0]["tests"].append(
        {"nodeid": "src/pkcs11_check/testcases/a.py::T::t_x2",
         "outcome": "xfailed"})
    r["units"][0]["counts"]["xfailed"] = 2
    r["summary"]["xfailed"] = 2
    r["summary"]["total"] = 11
    code, line = _run_case(tmp, "new-xfailed", r, base)
    check("new xfailed id fails", code == 1 and "new xfailed ids" in line)

    r = copy.deepcopy(res)
    r["units"][1]["skip_reasons"]["needs sprocket"] = 1
    r["units"][1]["counts"]["skipped"] = 3
    r["summary"]["skipped"] = 3
    r["summary"]["total"] = 11
    code, line = _run_case(tmp, "new-reason", r, base)
    check("new skip reason fails", code == 1 and "new skip reasons" in line)

    r = copy.deepcopy(res)
    r["units"][1]["skip_reasons"] = {"needs widget": 1, "needs sprocket": 1}
    r["units"][1]["counts"]["skipped"] = 2
    code, line = _run_case(tmp, "reason-swap", r, base)
    check("reason swap fails", code == 1 and "new skip reasons" in line)

    r = copy.deepcopy(res)
    r["units"][1]["skip_reasons"] = {"needs widget": 3}
    r["units"][1]["counts"]["skipped"] = 3
    r["summary"]["skipped"] = 3
    r["summary"]["total"] = 11
    code, line = _run_case(tmp, "reason-drift", r, base)
    check("reason count drift fails",
          code == 1 and "counts drifted" in line)

    r = copy.deepcopy(res)
    counts_c = {"passed": 0, "failed": 0, "skipped": 1, "xfailed": 0,
                "xpassed": 0, "error": 0, "crashed": 0, "timeout": 0,
                "crash_limited": 0}
    r["units"].append({"target": "/tmp/p11/src/pkcs11_check/testcases/c.py",
                       "status": "passed", "returncode": 0,
                       "counts": counts_c,
                       "skip_reasons": {"needs widget": 1}})
    r["units"][1]["counts"]["skipped"] = 1
    r["units"][1]["skip_reasons"] = {"needs widget": 1}
    code, line = _run_case(tmp, "target-drift", r, base)
    check("target vector drift fails",
          code == 1 and "per-target skip vector drifted" in line)

    for outcome in ("xpassed", "error"):
        r = copy.deepcopy(res)
        r["units"][0]["tests"].append(
            {"nodeid": "src/pkcs11_check/testcases/a.py::T::t_%s" % outcome,
             "outcome": outcome})
        r["units"][0]["counts"][outcome] = 1
        r["summary"][outcome] = 1
        r["summary"]["total"] = 11
        code, line = _run_case(tmp, outcome, r, base)
        check("%s fails" % outcome, code == 1 and outcome in line)

    r = copy.deepcopy(res)
    r["provenance"]["framework"]["commit"] = SHA_B
    code, line = _run_case(tmp, "sha-skew", r, base)
    check("pin skew names both",
          code == 1 and SHA_A in line and SHA_B in line)

    r = copy.deepcopy(res)
    del r["provenance"]["framework"]["commit"]
    code, line = _run_case(tmp, "no-envelope", r, base)
    check("missing envelope is exit 2", code == 2)

    code, line = _run_case(tmp, "corrupt", res, base, raw_res="{nope")
    check("corrupt results is exit 2", code == 2)
    code, line = run_gate(str(tmp / "absent.json"), str(tmp / "base.json"))
    print("missing -> exit %d: %s" % (code, line))
    check("missing results is exit 2", code == 2)

    b = copy.deepcopy(base)
    b["schema_version"] = 99
    code, line = _run_case(tmp, "bad-schema", res, b)
    check("wrong baseline schema is exit 2", code == 2)

    _run_case(tmp, "main-valid", res, base)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main([str(tmp / "res.json"), str(tmp / "base.json")])
    check("main passes file args through", code == 0)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(buf):
        code = main([str(tmp / "res.json")])
    check("main rejects one arg", code == 2 and "usage" in buf.getvalue())

    print("SELF-TEST: PASS %d/%d" % (passed, passed))


def main(argv):
    if "--self-test" in argv:
        self_test()
        return 0
    if len(argv) != 2:
        print("usage: python3 scripts/check-pkcs11-baseline.py "
              "<results.json> <baseline.json>", file=sys.stderr)
        return 2
    code, line = run_gate(argv[0], argv[1])
    print(line)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
