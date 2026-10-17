#!/usr/bin/env python3
"""Case-ledger gate: every checker finding, frozen exclusion, C hard-refusal
function, planner-unsupported function, planned/unsupported/n-a mechanism row
and old TODO category has exactly one row in spec/findings-ledger.json, with
a valid decision and evidence.

Sources (1:1 set equality, never a subset):
  * examples/release/compare-classify/frozen-shared.txt   (18 findings)
  * examples/release/compare-classify/frozen-subset.tsv   (61 exclusions)
  * cbits/function_tables.c stub_probe stubs + cbits/abi_stubs.inc
    x_live_check stubs                                     (11 C refusals)
  * spec/function-contracts.json unsupported-with-reason   (21 planner)
  * spec/mechanisms.json behavior planned/unsupported/n-a  (57/89/2)
  * TODO_IDS below (historical outer todo.md categories)

Retired rows: a finding or exclusion that left the frozen sets at a
re-freeze moves from "rows" to "retired" (same schema plus `retired_by`,
the fix commits, and `refreeze_evidence`). Its id must no longer be in the
frozen sources, its decision is provider-fix, and its test and receipt are
existing paths. "proxy_owned_divergences" records proxy-owned behaviour
found while fixing the provider.

Commit rule: every `retired_by` and `proxy_owned_divergences[].commit` SHA
must be an ancestor of HEAD (`git merge-base --is-ancestor`), not merely a
known object: a rebase that rewrites the fix commits leaves the old SHAs
behind, and the ledger must be rewritten with them. The check needs full
history, so the gate fails hard, with an explicit message, outside a git
checkout or in a shallow clone (CI checks out with fetch-depth: 0). Git
runs with `-c safe.directory=<repo>` so a container whose checkout owner
differs from the runner user still verifies instead of erroring.

Evidence rule: `test` and `receipt` are an existing repo path (optionally
`path::detail`) or `none: <reason>`. Pending evidence is no longer
accepted: every provider fix has landed, so a `pending` value is refused.

TODO_IDS is hard-coded here because its source (the outer workspace todo.md
and its gap-analysis disposition table, plus target gaps recorded after the
v0.5 provider fixes) is outside this repository; adding a TODO category
means editing this list and the ledger together.

Provider-owned finding/exclusion rows must be provider-fix, or
supported-refusal whose `source` cites normative text (contains "PKCS#11" and
a section reference); nothing else is accepted for them.

Usage: python3 scripts/check-findings-ledger.py [--self-test]
"""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LEDGER = REPO / "spec" / "findings-ledger.json"
CLASSIFY = REPO / "examples" / "release" / "compare-classify"

KINDS = ["finding", "exclusion", "function", "mechanism-planned",
         "unsupported", "n-a", "todo"]
OWNERS = ["provider", "checker", "proxy", "none"]
DECISIONS = ["provider-fix", "checker-fix", "supported-refusal",
             "target-gap", "historical", "optional"]
FIELDS = ["id", "kind", "dimension", "source", "input", "expected",
          "observed", "owner", "decision", "target", "test", "receipt",
          "checker_pin"]
DIMENSIONS = ["checker", "c-routing", "planner", "catalog", "todo"]
EXCL_FAMILIES = ["A-msg-init-0x71", "B-blowfish", "C-tls12", "D-wtls",
                 "E-boundary"]

COUNTS = {"finding": 18, "exclusion": 61, "c-function": 11,
          "planner-function": 21, "mechanism-planned": 57,
          "unsupported": 89, "n-a": 2}

RETIRED_COUNTS = {"finding": 4, "exclusion": 22}
SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")

TODO_IDS = [
    "todo:release-closure", "todo:proxy-upstream-statuses",
    "todo:oracle-candidates-p11c-011-014", "todo:op-state-g7",
    "todo:f-gcm-shape-f-blake2b", "todo:certificates-trust-url-java",
    "todo:async-gc", "todo:config-delta", "todo:coverage-gaps",
    "todo:fips-compatibility", "todo:openssl-variant-b",
    "todo:hackage-sbom-signing", "todo:platforms-packaging",
    "todo:storage-flake", "todo:cleanups",
    "todo:attribute-breadth-catalog-identity-only",
    "todo:xor-base-and-data-unequal-length",
    "todo:reserved-config-knobs", "todo:auth-wrap-functions",
    # target gaps found after the v0.5 provider fixes
    "todo:xor-derive-des-parity", "todo:wrap-unwrap-kem-key-handle-code",
]


def read_sources(repo=REPO):
    """Compute the expected id sets from the frozen/catalog sources."""
    cls = repo / "examples" / "release" / "compare-classify"
    src = {}
    shared = [ln.split(" ", 1)[1].strip()
              for ln in (cls / "frozen-shared.txt").read_text().splitlines()
              if ln and not ln.startswith("#")]
    src["finding"] = {"finding:" + t for t in shared}
    excl, fam = set(), {}
    for ln in (cls / "frozen-subset.tsv").read_text().splitlines():
        if not ln or ln.startswith("#"):
            continue
        family, rest = ln.split("\t", 1)
        test = rest.split(" ", 2)[2]
        excl.add("exclusion:" + test)
        fam["exclusion:" + test] = family
    src["exclusion"] = excl
    src["exclusion_family"] = fam

    ft = (repo / "cbits" / "function_tables.c").read_text()
    names = set(re.findall(
        r"static CK_RV stub_(\w+)\([^)]*\)\s*\{[^}]*?return stub_probe\(\);",
        ft, re.S))
    inc = (repo / "cbits" / "abi_stubs.inc").read_text()
    for m in re.finditer(r"x\d+_(C_\w+)\)\s*\([^)]*\)\s*\{[^}]*?"
                         r"return x_live_check\(\);", inc, re.S):
        names.add(m.group(1))
    names = {n if n.startswith("C_") else "C_" + n for n in names}
    src["c-function"] = {"function:" + n for n in names}

    fc = json.loads((repo / "spec" / "function-contracts.json").read_text())
    src["planner-function"] = {
        "planner:" + f["name"] for f in fc["functions"]
        if f["contract"] == "unsupported-with-reason"}

    mech = json.loads((repo / "spec" / "mechanisms.json").read_text())
    for kind, state in [("mechanism-planned", "planned"),
                        ("unsupported", "unsupported-with-reason"),
                        ("n-a", "not-applicable")]:
        src[kind] = {"mech:" + m["canonical_name"]
                     for m in mech["mechanisms"]
                     if m["support"]["behavior"] == state}
    src["todo"] = set(TODO_IDS)
    return src


def classify(row):
    """Map a ledger row to its count bucket."""
    k = row.get("kind")
    if k == "function":
        return "planner-function" if row.get("dimension") == "planner" \
            else "c-function"
    return k


def evidence_ok(value, decision, repo):
    if not isinstance(value, str) or not value.strip():
        return "empty"
    if value.startswith("pending"):
        return "pending evidence %r is no longer accepted" % value
    if value.startswith("none: ") and len(value) > 6:
        return None
    path = value.split("::", 1)[0]
    if (repo / path).exists():
        return None
    return "no such path %r" % path


def validate(ledger, src, counts=COUNTS, repo=REPO):
    errs = []
    rows = ledger.get("rows")
    if not isinstance(rows, list):
        return ["ledger has no rows list"]
    seen = {}
    for r in rows:
        rid = r.get("id")
        if sorted(r.keys()) != sorted(FIELDS):
            errs.append("%s: fields != schema" % rid)
            continue
        if rid in seen:
            errs.append("duplicate id %s" % rid)
        seen[rid] = r
        if r["kind"] not in KINDS:
            errs.append("%s: unknown kind %r" % (rid, r["kind"]))
        if r["owner"] not in OWNERS:
            errs.append("%s: unknown owner %r" % (rid, r["owner"]))
        if r["decision"] not in DECISIONS:
            errs.append("%s: unknown decision %r" % (rid, r["decision"]))
        if r["dimension"] not in DIMENSIONS:
            errs.append("%s: unknown dimension %r" % (rid, r["dimension"]))
        for f in ("source", "input", "expected", "observed", "target",
                  "checker_pin"):
            if not isinstance(r[f], str) or not r[f].strip():
                errs.append("%s: empty %s" % (rid, f))
        for f in ("test", "receipt"):
            e = evidence_ok(r[f], r["decision"], repo)
            if e:
                errs.append("%s: %s %s" % (rid, f, e))
    # 1:1 set equality per bucket
    by_bucket = {}
    for rid, r in seen.items():
        by_bucket.setdefault(classify(r), set()).add(rid)
    exp = {"finding": src["finding"], "exclusion": src["exclusion"],
           "c-function": src["c-function"],
           "planner-function": src["planner-function"],
           "mechanism-planned": src["mechanism-planned"],
           "unsupported": src["unsupported"], "n-a": src["n-a"],
           "todo": src["todo"]}
    for bucket, want in exp.items():
        have = by_bucket.get(bucket, set())
        for rid in sorted(want - have):
            errs.append("missing ledger row: %s" % rid)
        for rid in sorted(have - want):
            errs.append("unknown ledger row id: %s" % rid)
        if bucket in counts and len(want) != counts[bucket]:
            errs.append("%s count %d != pinned %d"
                        % (bucket, len(want), counts[bucket]))
    for bucket in by_bucket:
        if bucket not in exp:
            errs.append("rows in unknown bucket %r" % bucket)
    # kind/decision consistency
    for rid, r in seen.items():
        k, d = r["kind"], r["decision"]
        if k == "mechanism-planned" and d != "target-gap":
            errs.append("%s: planned mechanism must be target-gap" % rid)
        if k in ("unsupported", "n-a") and d != "supported-refusal":
            errs.append("%s: %s must be supported-refusal" % (rid, k))
        if k == "exclusion":
            fam = src["exclusion_family"].get(rid)
            if r["dimension"] != "checker" or not r["source"].startswith(
                    fam + " "):
                errs.append("%s: source must start with family %s"
                            % (rid, fam))
    for rid, r in seen.items():
        if r["kind"] in ("finding", "exclusion") and r["owner"] == "provider":
            d = r["decision"]
            if d == "supported-refusal":
                if "PKCS#11" not in r["source"] or not re.search(
                        r"section|\u00a7|sec\.", r["source"]):
                    errs.append("%s: provider-owned supported-refusal needs "
                                "a source citing PKCS#11 normative section"
                                % rid)
            elif d != "provider-fix":
                errs.append("%s: provider-owned %s must be provider-fix or "
                            "supported-refusal (got %s)" % (rid, r["kind"], d))
    errs += validate_retired(ledger, src, seen, repo)
    return errs


def validate_retired(ledger, src, seen, repo):
    errs = []
    ret = ledger.get("retired")
    if not isinstance(ret, list):
        return ["ledger has no retired list"]
    ids, kinds = set(), {}
    for r in ret:
        rid = r.get("id")
        if sorted(r.keys()) != sorted(FIELDS + ["retired_by",
                                                "refreeze_evidence"]):
            errs.append("retired %s: fields != schema" % rid)
            continue
        if rid in ids or rid in seen:
            errs.append("retired %s: duplicate of a live or retired row" % rid)
        ids.add(rid)
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
        if r["kind"] not in ("finding", "exclusion"):
            errs.append("retired %s: kind must be finding or exclusion" % rid)
        if rid in src.get(r["kind"], set()):
            errs.append("retired %s: still in the frozen source" % rid)
        if r["decision"] != "provider-fix" or r["owner"] != "provider":
            errs.append("retired %s: must be a provider-fix provider row" % rid)
        for f in ("test", "receipt"):
            v = r[f]
            if not isinstance(v, str) or v.startswith(("pending", "none")):
                errs.append("retired %s: %s must be an existing path" % (rid, f))
            else:
                e = evidence_ok(v, r["decision"], repo)
                if e:
                    errs.append("retired %s: %s %s" % (rid, f, e))
        by = r["retired_by"]
        if not isinstance(by, list) or not by or not all(
                isinstance(c, str) and SHA_RE.match(c) for c in by):
            errs.append("retired %s: retired_by needs fix commit shas" % rid)
        else:
            for c in by:
                if not _is_ancestor(c, repo):
                    errs.append("retired %s: retired_by %s is not an ancestor "
                                "of HEAD (rebased away? rewrite the ledger "
                                "SHAs)" % (rid, c))
        if not isinstance(r["refreeze_evidence"], str) or not r[
                "refreeze_evidence"].strip():
            errs.append("retired %s: empty refreeze_evidence" % rid)
    for kind, n in RETIRED_COUNTS.items():
        if kinds.get(kind, 0) != n:
            errs.append("retired %s count %d != pinned %d"
                        % (kind, kinds.get(kind, 0), n))
    for d in ledger.get("proxy_owned_divergences", []):
        c = d.get("commit", "")
        if not (d.get("id") and d.get("note") and
                not evidence_ok(d.get("test", ""), "provider-fix", repo)):
            errs.append("bad proxy_owned_divergences entry %s" % d.get("id"))
        if not (isinstance(c, str) and SHA_RE.match(c)
                and _is_ancestor(c, repo)):
            errs.append("proxy_owned_divergences %s: commit %r is not an "
                        "ancestor of HEAD" % (d.get("id"), c))
    if not ledger.get("proxy_owned_divergences"):
        errs.append("proxy_owned_divergences is empty (digest-key receipt)")
    return errs


def _git(repo, *args):
    """Run git in `repo`, trusting it explicitly (CI containers check out as
    a different owner, and git then refuses with exit 128)."""
    return subprocess.run(["git", "-c", "safe.directory=%s" % repo,
                           "-C", str(repo)] + list(args),
                          capture_output=True, text=True)


def _is_ancestor(sha, repo):
    """True only when `sha` names a commit that is an ancestor of HEAD.
    A missing object, a non-commit or a commit off HEAD's history is
    False; history_problem() has already refused a tree without history."""
    if not sha:
        return False
    return _git(repo, "merge-base", "--is-ancestor", sha, "HEAD"
                ).returncode == 0


def history_problem(repo=REPO):
    """None when the commit rule can be verified, else why it cannot.
    Never a silent pass: no git, no checkout or a shallow clone fails."""
    try:
        head = _git(repo, "rev-parse", "--verify", "HEAD^{commit}")
    except OSError as e:
        return "git is not available (%s)" % e
    if head.returncode != 0:
        return ("not a usable git checkout (%s)"
                % (head.stderr.strip() or "rev-parse HEAD failed"))
    shallow = _git(repo, "rev-parse", "--is-shallow-repository")
    if shallow.returncode != 0 or shallow.stdout.strip() != "false":
        return ("shallow repository: the retired_by / proxy_owned_divergences "
                "commits cannot be verified as ancestors of HEAD; fetch full "
                "history (actions/checkout fetch-depth: 0, or "
                "git fetch --unshallow)")
    return None


def run_gate():
    if not LEDGER.exists():
        print("FAIL: %s missing" % LEDGER.relative_to(REPO))
        return 1
    why = history_problem()
    if why:
        print("FAIL: findings-ledger cannot verify fix commits: " + why)
        return 1
    errs = validate(json.loads(LEDGER.read_text()), read_sources())
    for e in errs:
        print("FAIL: " + e)
    if errs:
        return 1
    n = len(json.loads(LEDGER.read_text())["rows"])
    print("findings-ledger: ok (%d rows; 18 findings, 61 exclusions, "
          "11 C refusals, 21 planner, 57/89/2 mechanisms; 26 retired)" % n)
    return 0


def _non_ancestor_commit(repo):
    """Write a real commit that is NOT an ancestor of HEAD (a child of HEAD)
    into a throwaway object directory layered over the repository's, so the
    control proves the ancestry rule rather than object existence and the
    repository's own object store is untouched. Returns (sha, env, tmpdir)."""
    objs = _git(repo, "rev-parse", "--git-path", "objects").stdout.strip()
    objs = str((repo / objs).resolve()) if not os.path.isabs(objs) else objs
    tmp = tempfile.mkdtemp(prefix="ledger-selftest-")
    env = {"GIT_OBJECT_DIRECTORY": tmp,
           "GIT_ALTERNATE_OBJECT_DIRECTORIES": objs,
           "GIT_AUTHOR_NAME": "self-test", "GIT_AUTHOR_EMAIL": "t@invalid",
           "GIT_COMMITTER_NAME": "self-test",
           "GIT_COMMITTER_EMAIL": "t@invalid"}
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        sha = _git(repo, "commit-tree", "HEAD^{tree}", "-p", "HEAD",
                   "-m", "ledger self-test non-ancestor").stdout.strip()
    finally:
        _restore_env(saved)
    return sha, env, tmp


def _restore_env(saved):
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def self_test():
    if not LEDGER.exists():
        print("FAIL: ledger missing")
        return 1
    why = history_problem()
    if why:
        print("FAIL: findings-ledger self-test cannot verify fix commits: "
              + why)
        return 1
    base = json.loads(LEDGER.read_text())
    src = read_sources()
    bad = 0

    def expect(name, errs):
        nonlocal bad
        if errs:
            print("ok   control %s -> rejected" % name)
        else:
            print("FAIL control %s was accepted" % name)
            bad += 1

    if validate(base, src):
        print("FAIL: unmodified ledger does not validate")
        return 1
    print("ok   baseline validates")
    rows = base["rows"]

    def with_rows(new):
        d = copy.deepcopy(base)
        d["rows"] = new
        return d

    for kind in KINDS:
        i = next(i for i, r in enumerate(rows) if r["kind"] == kind)
        expect("drop-%s-row" % kind,
               validate(with_rows(rows[:i] + rows[i + 1:]), src))
    extra = copy.deepcopy(rows[0])
    extra["id"] = "finding:bogus.py::test_unknown"
    expect("unknown-id", validate(with_rows(rows + [extra]), src))
    dup = copy.deepcopy(rows[0])
    expect("duplicate-id", validate(with_rows(rows + [dup]), src))
    r2 = copy.deepcopy(rows)
    r2[0]["decision"] = "maybe"
    expect("unknown-decision", validate(with_rows(r2), src))
    r2 = copy.deepcopy(rows)
    r2[0]["owner"] = "nobody"
    expect("unknown-owner", validate(with_rows(r2), src))
    r2 = copy.deepcopy(rows)
    r2[0]["kind"] = "bogus"
    expect("unknown-kind", validate(with_rows(r2), src))
    r2 = copy.deepcopy(rows)
    del r2[0]["receipt"]
    expect("missing-field", validate(with_rows(r2), src))
    wrong = dict(COUNTS, finding=23)
    expect("wrong-count", validate(base, src, counts=wrong))
    short = copy.deepcopy(src)
    short["exclusion"] = set(sorted(short["exclusion"])[:-1])
    expect("source-has-fewer-than-ledger", validate(base, short))
    # No live exclusion is provider-owned after the v0.5 re-freeze, so the
    # controls synthesize one from the first exclusion row.
    i = next(i for i, r in enumerate(rows) if r["kind"] == "exclusion")
    rows = copy.deepcopy(rows)
    rows[i]["owner"] = "provider"
    rows[i]["decision"] = "provider-fix"
    rows[i]["test"] = "tests/c/consumer_errors.c"
    rows[i]["receipt"] = "tests/c/consumer_errors.c"
    r2 = copy.deepcopy(rows)
    r2[i]["decision"] = "target-gap"
    r2[i]["test"] = "none: relabelled"
    r2[i]["receipt"] = "none: relabelled"
    expect("provider-owned-exclusion-target-gap", validate(with_rows(r2), src))
    r2 = copy.deepcopy(rows)
    r2[i]["decision"] = "supported-refusal"
    r2[i]["test"] = "none: relabelled"
    r2[i]["receipt"] = "none: relabelled"
    expect("supported-refusal-without-normative-source",
           validate(with_rows(r2), src))
    r2[i]["source"] += " PKCS#11 3.0 section 5.2"
    if validate(with_rows(r2), src):
        print("FAIL control normative-source supported-refusal rejected")
        bad += 1
    else:
        print("ok   control supported-refusal-with-normative-source -> accepted")
    # pending evidence is refused on every decision, provider-fix included
    i = next(i for i, r in enumerate(rows) if r["decision"] != "provider-fix")
    r2 = copy.deepcopy(rows)
    r2[i]["test"] = "pending: later"
    expect("pending-on-non-provider-fix", validate(with_rows(r2), src))
    j = next(i for i, r in enumerate(rows) if r["decision"] == "provider-fix")
    r2 = copy.deepcopy(rows)
    r2[j]["test"] = "pending soon"
    expect("malformed-pending", validate(with_rows(r2), src))
    r2 = copy.deepcopy(rows)
    r2[j]["test"] = "pending: later"
    expect("pending-on-provider-fix", validate(with_rows(r2), src))
    r2 = copy.deepcopy(rows)
    r2[j]["receipt"] = "no/such/file.md"
    expect("dangling-path", validate(with_rows(r2), src))
    # retired-row controls
    ret = base["retired"]

    def with_ret(new):
        d = copy.deepcopy(base)
        d["retired"] = new
        return d

    expect("retired-dropped", validate(with_ret(ret[1:]), src))
    r2 = copy.deepcopy(ret)
    r2[0]["receipt"] = "pending: a later release"
    expect("retired-pending-receipt", validate(with_ret(r2), src))
    r2 = copy.deepcopy(ret)
    r2[0]["retired_by"] = []
    expect("retired-without-commit", validate(with_ret(r2), src))
    r2 = copy.deepcopy(ret)
    r2[0]["retired_by"] = ["0000000000000000000000000000000000000000"]
    expect("retired-unknown-commit", validate(with_ret(r2), src))
    # A commit that exists but is off HEAD's history (what a rebase leaves
    # behind) must be refused too: existence is not ancestry.
    sha, env, tmp = _non_ancestor_commit(REPO)
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        exists = _git(REPO, "cat-file", "-e", sha + "^{commit}"
                      ).returncode == 0 if sha else False
        if not exists:
            print("FAIL control retired-non-ancestor-commit: could not "
                  "create the non-ancestor commit")
            bad += 1
        else:
            r2 = copy.deepcopy(ret)
            r2[0]["retired_by"] = [sha]
            expect("retired-non-ancestor-commit", validate(with_ret(r2), src))
            d2 = copy.deepcopy(base)
            d2["proxy_owned_divergences"][0]["commit"] = sha
            expect("proxy-divergence-non-ancestor-commit", validate(d2, src))
    finally:
        _restore_env(saved)
        shutil.rmtree(tmp, ignore_errors=True)
    r2 = copy.deepcopy(ret)
    r2[0]["decision"] = "target-gap"
    expect("retired-not-provider-fix", validate(with_ret(r2), src))
    resurrect = copy.deepcopy(src)
    resurrect["exclusion"] = set(resurrect["exclusion"]) | {ret[-1]["id"]}
    expect("retired-id-back-in-source", validate(base, resurrect))
    d2 = copy.deepcopy(base)
    d2["proxy_owned_divergences"] = []
    expect("proxy-divergence-receipt-missing", validate(d2, src))
    if bad:
        return 1
    print("findings-ledger self-test: ok")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(run_gate())
