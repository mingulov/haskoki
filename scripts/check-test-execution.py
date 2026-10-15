#!/usr/bin/env python3
"""Test-execution gate: join executed trees to the reviewed inventory.

Fails (exit 1) when any rule fails. Two layers:

Build-free (default): the suite inventory
(tests/suite-inventory.json) is valid; every inventoried suite is
join-ready (at least one required group, at least one executing
lane); and every suite label cited by the evidence catalogs
(spec/mechanisms.json artifacts, spec/function-contracts.json
test_evidence) resolves to an inventoried cabal suite, an
inventoried script driver (scripts/driver-inventory.json), or a
reviewed task-label alias — otherwise executed results cannot be
joined to the rows that cite them.

Join (`--join`): bind one executed suite result to its reviewed
intended groups — the suite groups plus every module's pinned
top-level battery (`module_groups`). Inputs are the suite name,
its Tasty `--list-tests` capture (one test path per line,
collected from the exact build under test), and its verdict
(`pass` only: the join binds successful suite results, never
failures). Failures:

* `no-test`: the capture holds zero test names (an empty battery
  fails here even when its module links and its token resolves —
  linkage never substitutes for execution).
* `missing-required-group`: a required group — suite or module
  battery — has no test under it (an emptied module battery
  fails here even when the rest of the suite ran: Tasty emits
  leaves only, so the emptied group contributes no names).
* `suite-result`: the suite did not pass.
* `hostile-tree`: the suite Main carries batteries beyond the
  pinned roots (the wiring gate refuses these build-free; the
  join re-verifies so a hostile tree never joins standalone —
  a capture for an unpinned tree is unattributable).

Group membership is ancestry-anchored, because Tasty paths
are ambiguous when test names carry separators (a dotted leaf
renders exactly like nested groups): a suite root matches only
as the first segment, and a module battery only as the complete
second segment directly under one of the roots — every runner
lists spec trees flat under one root group, so anything deeper
is a different battery's subtree. Either separator (`.`, `/`)
is accepted per joint. A longer name that merely contains the
battery (a `control.G.still-empty` leaf, `G regression
control`, `G-legacy`, `my G`, or `GX`) never matches, so an
emptied battery receives no other test's execution credit.
The receipt lists each executed name once with the count of
catalog rows citing the suite beside it: rows fan into names, so
a name shared by many rows is one executed record, never one
independent behavior per row.

Collection (`--collect`): run every targeted suite binary's
`--list-tests` capture and join each one. Binaries built inside
the toolchain image are listed in that same builder context
(`--docker-image`, which the gate runner passes since it builds
inside the image; lanes that build natively collect directly):
each capture runs via `timeout -s KILL 300 docker run --rm
--network host` with the workspace bind-mounted at /work, so
the host never launches container-built binaries and no host
runtime/library compatibility is assumed. The join itself stays
host-side (pure text over the captures).

HPC reconciliation (`--check-hpc`): bind coverage artifacts to
the same inventory before the lane publishes its denominator.
Every inventoried suite must own at least one `.tix` under the
given root (no `.tix` is the coverage form of `no-test`), and
every compiled library module (`.mix` paths under the given mix
dirs) must appear in the given per-module reports by full module
identity — a report mentioning only `Haskoki.Operation.Cipher`
never satisfies `Haskoki.Operation`. The reconciliation artifact
is always written, including on unreadable inputs; gaps fail
loudly here and travel as explicit gaps where the lane stays
informational.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-test-execution.py [--root DIR]
        [--inventory PATH]
  python3 scripts/check-test-execution.py --collect
        --build-root DIR --dir DIR --result pass [--suite NAME]
        [--docker-image IMAGE]
  python3 scripts/check-test-execution.py --join --suite NAME
        --list-tests FILE --result pass --out RECEIPT [--root DIR]
  python3 scripts/check-test-execution.py --check-hpc
        --tix-root DIR --mix-dirs D1,D2 --reports R1,R2 --out FILE
  python3 scripts/check-test-execution.py --self-test
"""

import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

failures = []


def _load_sibling(stem):
    path = Path(__file__).with_name(stem + ".py")
    spec = importlib.util.spec_from_file_location(stem, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[stem] = mod
    spec.loader.exec_module(mod)
    return mod


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


_SEPS = "./"


def _bounded(name, length):
    """Right boundary after a `length`-prefix: edge or separator."""
    return length == len(name) or name[length] in _SEPS


def group_hit(name, group):
    """True when suite root `group` heads the executed `name`.

    Tasty `--list-tests` emits leaves only (tasty 1.5.4
    `testsNames`), joining segments with `.` (this toolchain;
    `/` is accepted for older renderings). The suite root is
    always the first segment, so it matches only at position
    zero bounded by a separator — a name containing the root
    deeper never credits it. An empty group never matches
    (fail-closed).
    """
    if not group or not group.strip():
        return False
    return name == group or (name.startswith(group)
                             and _bounded(name, len(group)))


def module_hit(name, roots, group):
    """True when module battery `group` hangs directly under a root.

    Module batteries are the suite root's direct children (every
    runner lists spec trees flat under one root group), so a
    battery matches only as the complete second segment under
    one of `roots` — either separator per joint. A dotted leaf
    (`control.G.still-empty`), a deeper nesting, or any longer
    name merely containing the battery can never credit an
    emptied one, whatever separators names carry.
    """
    if not group or not group.strip():
        return False
    for root in roots:
        if not root or not root.strip():
            continue
        for sep in _SEPS:
            prefix = root + sep + group
            if name == prefix:
                return True
            if name.startswith(prefix) and _bounded(name,
                                                    len(prefix)):
                return True
    return False


def catalog_suite_labels(root):
    """Every suite label cited by the evidence catalogs.

    mechanisms.json artifacts carry `suite/Module`; the function
    catalog carries bare suite labels. Returns (labels, error).
    """
    labels = set()
    try:
        mechs = json.loads(
            (root / "spec" / "mechanisms.json").read_text())["mechanisms"]
    except Exception as e:  # noqa: BLE001 - reported, not hidden
        return None, f"cannot parse spec/mechanisms.json: {e}"
    for row in mechs:
        for e in row.get("test_evidence") or []:
            artifact = e.get("artifact") or ""
            if "/" in artifact:
                labels.add(artifact.split("/", 1)[0])
            elif artifact:
                labels.add(artifact)
    try:
        contracts = json.loads(
            (root / "spec" / "function-contracts.json").read_text())
    except FileNotFoundError:
        return None, "spec/function-contracts.json missing"
    except Exception as e:  # noqa: BLE001
        return None, f"cannot parse spec/function-contracts.json: {e}"
    for row in contracts.get("functions", []):
        for e in row.get("test_evidence") or []:
            if e.get("suite"):
                labels.add(e["suite"])
    return labels, None


def catalog_rows_citing(root, suite):
    """Count of catalog rows citing `suite` (linkage fan-in)."""
    n = 0
    try:
        mechs = json.loads(
            (root / "spec" / "mechanisms.json").read_text())["mechanisms"]
    except Exception:  # noqa: BLE001 - build-free check reports parses
        mechs = []
    for row in mechs:
        for e in row.get("test_evidence") or []:
            artifact = e.get("artifact") or ""
            if artifact == suite or artifact.startswith(suite + "/"):
                n += 1
    try:
        contracts = json.loads(
            (root / "spec" / "function-contracts.json").read_text())
    except Exception:  # noqa: BLE001 - same as above
        contracts = {}
    for row in contracts.get("functions", []):
        for e in row.get("test_evidence") or []:
            if e.get("suite") == suite:
                n += 1
    return n


def check_tree(root, inventory_path):
    """Run the build-free rules. Returns failures."""
    wiring = _load_sibling("check-test-wiring")
    gen = _load_sibling("generate-function-contracts")
    root = Path(root)
    fails = []

    def rule(name, cond, detail):
        check(name, cond, detail)
        if not cond:
            fails.append(name)

    inv, err = wiring.load_inventory(inventory_path)
    if err is not None:
        rule("INVENTORY-VALID", False, err)
        return fails
    rule("INVENTORY-VALID", True,
         f"{len(inv)} suites registered")
    try:
        drivers = {d["name"] for d in json.loads(
            (root / "scripts" / "driver-inventory.json").read_text())
            ["drivers"]}
    except Exception as e:  # noqa: BLE001
        rule("DRIVERS-LOAD", False,
             f"cannot parse scripts/driver-inventory.json: {e}")
        return fails
    aliases = getattr(gen, "TASK_LABEL_OWNERS", {})
    for name in sorted(inv):
        groups = inv[name].get("required_groups", [])
        lanes = inv[name].get("executed_by", [])
        rule(f"EXEC-JOIN-READY-{name}", bool(groups) and bool(lanes),
             f"{len(groups)} required groups, {len(lanes)} lanes")
    labels, err = catalog_suite_labels(root)
    if err is not None:
        rule("CATALOG-JOIN-SCOPE", False, err)
        return fails
    unknown = sorted(l for l in labels
                     if l not in inv and l not in drivers
                     and l not in aliases)
    rule("CATALOG-JOIN-SCOPE", not unknown,
         f"{len(labels)} catalog labels resolve to suites/drivers"
         + ("" if not unknown else f" (unknown={unknown})"))
    return fails


def join_suite(root, inventory_path, suite, list_path, result, out_path):
    """Bind one executed capture to its required groups.

    Returns 0 with the receipt written on JOIN-OK, else 1.
    """
    wiring = _load_sibling("check-test-wiring")
    root = Path(root)
    inv, err = wiring.load_inventory(inventory_path)
    if err is not None:
        print(f"test-execution join: FAIL (no-test-scope: {err})")
        return 1
    if suite not in inv:
        print(f"test-execution join: FAIL (no-test-scope: suite "
              f"{suite!r} not inventoried)")
        return 1
    main_rel = inv[suite].get("main", "")
    main_path = root / main_rel if main_rel else None
    if main_path is not None and main_path.is_file():
        # Defense in depth: anchored matching is sound only when
        # depth-two names are pinned tops. CI's static gates
        # already refused hostile trees on this checkout, but the
        # join stands alone too — a capture for an unpinned Main
        # tree is unattributable, never JOIN-OK. (A missing Main
        # is the wiring gate's failure, not the join's.)
        try:
            main_text = main_path.read_text(encoding="utf-8")
        except Exception as e:  # noqa: BLE001
            print(f"test-execution join: FAIL (hostile-tree: {suite} "
                  f"cannot read {main_path}: {e})")
            return 1
        allowed = inv[suite].get("allowed_imports")
        pin_names = set()
        if isinstance(allowed, dict):
            for names in allowed.values():
                pin_names.update(names)
        ok, detail = wiring.main_inline_issues(
            main_text, inv[suite].get("required_groups", []),
            bool(inv[suite].get("modules")), pin_names,
            inv[suite].get("modules", []))
        if not ok:
            print(f"test-execution join: FAIL (hostile-tree: {suite} "
                  f"Main carries unpinned batteries: {detail})")
            return 1
        ok, detail = wiring.main_import_issues(
            main_text, inv[suite].get("modules", []), allowed,
            inv[suite].get("allowed_dotdot"))
        if not ok:
            print(f"test-execution join: FAIL (hostile-tree: {suite} "
                  f"Main imports escape the pin: {detail})")
            return 1
    try:
        raw = Path(list_path).read_text(encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        print(f"test-execution join: FAIL (no-test: cannot read "
              f"{list_path}: {e})")
        return 1
    names = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    groups = inv[suite].get("required_groups", [])
    module_groups = inv[suite].get("module_groups", {}) or {}
    if result != "pass":
        print(f"test-execution join: FAIL (suite-result: {suite} "
              f"reported {result!r}, want 'pass')")
        return 1
    if not names:
        print(f"test-execution join: FAIL (no-test: {suite} emitted "
              f"zero test names)")
        return 1
    # Every captured line must be a test name under a required root:
    # a banner or any other stdout line is never counted as a test.
    stray = [n for n in names if not any(group_hit(n, g) for g in groups)]
    if stray:
        kind = "no-test, stray-line" if len(stray) == len(names) \
            else "stray-line"
        print(f"test-execution join: FAIL ({kind}: {suite} emitted "
              f"{len(stray)} line(s) under no required root: "
              f"{stray[:3]})")
        return 1
    hits = {}
    for g in groups:
        hits[g] = sum(1 for n in names if group_hit(n, g))
    for mod in sorted(module_groups):
        for g in module_groups[mod]:
            key = f"{mod} :: {g}"
            hits[key] = sum(1 for n in names
                            if module_hit(n, groups, g))
    missing = [k for k, v in hits.items() if not v]
    if missing:
        print(f"test-execution join: FAIL (missing-required-group: "
              f"{suite} lacks {missing}; saw {len(names)} names)")
        for n in names[:10]:
            print(f"  saw: {n}")
        if len(names) > 10:
            print(f"  ... and {len(names) - 10} more")
        return 1
    digest = hashlib.sha256(
        ("\n".join(sorted(set(names))) + "\n").encode()).hexdigest()[:16]
    receipt = {
        "schema": "haskoki-execution-receipt/1",
        "suite": suite,
        "result": result,
        "required_groups": groups,
        "module_groups": module_groups,
        "group_hits": hits,
        "test_count": len(names),
        "names_sha256_16": digest,
        "catalog_rows_citing_suite": catalog_rows_citing(root, suite),
        "note": ("Executed names are listed once; catalog rows fan "
                 "into them. A shared name is one executed record, "
                 "never one independent behavior per citing row."),
    }
    Path(out_path).write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"test-execution join: JOIN-OK ({suite}: {len(names)} names, "
          f"groups {hits}, rows-citing={receipt['catalog_rows_citing_suite']})")
    return 0


def check_hpc(root, inventory_path, tix_root, mix_dirs, reports, out_path):
    """Reconcile coverage artifacts against the inventory.

    The artifact is always written; gaps return 1.
    """
    wiring = _load_sibling("check-test-wiring")
    root = Path(root)
    inv, err = wiring.load_inventory(inventory_path)
    if err is not None:
        print(f"test-execution hpc: FAIL ({err})")
        return 1
    tixes = sorted(Path(tix_root).rglob("*.tix"))
    tix_by_suite = {}
    for suite in inv:
        owned = [str(p) for p in tixes
                 if f"/t/{suite}/" in str(p) or suite in Path(p).name]
        tix_by_suite[suite] = owned
    expected = set()
    gaps = []
    for mix in mix_dirs:
        if str(mix).strip() in ("", "."):
            # Empty discovery (or a bare ".", which would scan the
            # working tree) is a gap, never a scan.
            gaps.append("missing-mix-dir: (empty discovery)")
            continue
        if not Path(mix).is_dir():
            gaps.append(f"missing-mix-dir: {mix}")
            continue
        unit_roots = [p for p in Path(mix).iterdir() if p.is_dir()]
        for unit in unit_roots:
            for mix_file in unit.rglob("*.mix"):
                rel = mix_file.relative_to(unit).with_suffix("")
                expected.add(".".join(rel.parts))
    if not expected and not gaps:
        gaps.append("no compiled modules found under the mix dirs")
    reported_text = ""
    for rep in reports:
        try:
            reported_text += Path(rep).read_text(errors="replace") + "\n"
        except Exception as e:  # noqa: BLE001
            gaps.append(f"missing-report: cannot read {rep}: {e}")
    reported = {m for m in expected
                if re.search(r"(?<![A-Za-z0-9_.])" + re.escape(m)
                             + r"(?![A-Za-z0-9_.])", reported_text)}
    for suite in sorted(inv):
        if not tix_by_suite[suite]:
            gaps.append(f"no-tix: {suite} owns no .tix under {tix_root}")
    for mod in sorted(expected - reported):
        gaps.append(f"missing-module: {mod} compiled but not reported")
    doc = {
        "schema": "haskoki-hpc-reconciliation/1",
        "tix_by_suite": {s: tix_by_suite[s] for s in sorted(inv)},
        "modules_expected": len(expected),
        "modules_reported": len(reported),
        "gaps": gaps,
        "verdict": "RECONCILED" if not gaps else "GAPS",
    }
    Path(out_path).write_text(json.dumps(doc, indent=2) + "\n")
    if gaps:
        print("test-execution hpc: FAIL "
              f"({len(gaps)} gaps; see {out_path})")
        for g in gaps[:20]:
            print(f"  gap: {g}")
        return 1
    print(f"test-execution hpc: RECONCILED ({len(tixes)} tix, "
          f"{len(expected)} modules reported)")
    return 0


def collect_and_join(root, inventory_path, build_root, out_dir, result,
                     only_suite=None, docker_image=None):
    """Collect `--list-tests` from built binaries and join each suite.

    Exactly one executable must match `t/<suite>/build/<suite>/<suite>`
    under the build root; zero or several fail loudly (a missing
    binary is never an empty tree). With `docker_image` set, each
    capture runs inside that builder image (the workspace
    bind-mounted at /work), so container-built binaries are never
    launched on the host; otherwise the binary is launched
    directly. Each capture is joined by join_suite; the first
    failure stops the run. Returns 0 when every targeted suite
    joined, else 1.
    """
    wiring = _load_sibling("check-test-wiring")
    root = Path(root)
    inv, err = wiring.load_inventory(inventory_path)
    if err is not None:
        print(f"test-execution collect: FAIL ({err})")
        return 1
    targets = [only_suite] if only_suite else sorted(inv)
    if only_suite and only_suite not in inv:
        print(f"test-execution collect: FAIL (suite {only_suite!r} "
              f"not inventoried)")
        return 1
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for suite in targets:
        cands = sorted(p for p in Path(build_root).rglob(
            f"t/{suite}/build/{suite}/{suite}")
            if p.is_file() and os.access(p, os.X_OK))
        if len(cands) != 1:
            print(f"test-execution collect: FAIL (no-test-scope: "
                  f"want exactly one binary for {suite}, "
                  f"saw {len(cands)})")
            return 1
        if docker_image is None:
            cmd = [str(cands[0]), "--list-tests"]
        else:
            try:
                rel = cands[0].resolve().relative_to(root.resolve())
            except ValueError:
                print(f"test-execution collect: FAIL (no-test-scope: "
                      f"{suite} binary is outside the mounted "
                      f"workspace: {cands[0]})")
                return 1
            cmd = ["timeout", "-s", "KILL", "300", "docker", "run",
                   "--rm", "--network", "host",
                   "-v", f"{root.resolve()}:/work",
                   "-w", "/work", docker_image, f"/work/{rel}",
                   "--list-tests"]
        try:
            proc = subprocess.run(
                cmd, capture_output=True,
                text=True, timeout=300, check=False)
        except Exception as e:  # noqa: BLE001
            print(f"test-execution collect: FAIL (no-test: {suite} "
                  f"--list-tests failed: {e})")
            return 1
        if proc.returncode != 0:
            print(f"test-execution collect: FAIL (no-test: {suite} "
                  f"--list-tests exited {proc.returncode}: "
                  f"{proc.stderr.strip()[:200]})")
            return 1
        list_path = out_dir / f"{suite}.list"
        list_path.write_text(proc.stdout)
        rc = join_suite(root, inventory_path, suite, list_path, result,
                        out_dir / f"join-{suite}.json")
        if rc != 0:
            return rc
    print(f"test-execution collect: OK ({len(targets)} suites joined)")
    return 0


def _write(path, text):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def self_test():
    """Durable controls: the join fails empty captures, missing
    groups, lines under no required root (a banner beside names or
    alone), emptied module batteries, hostile Main trees, and
    failed suites; roots anchor at position zero and batteries
    at depth two, so no decoy spelling credits an emptied
    battery; shared catalog rows fan into one executed name;
    HPC reconciliation fails
    missing tix, missing modules, and missing reports, and
    matches modules by full identity."""
    fails = []
    ran = []

    def expect(name, cond, detail=""):
        ran.append(name)
        print(f"{'PASS' if cond else 'FAIL'}: self-test: {name}"
              + (f": {detail}" if detail and not cond else ""))
        if not cond:
            fails.append(name)

    inv_doc = {"schema": "haskoki-suite-inventory/1", "suites": [
        {"name": "suite-a", "main": "tests/alpha/Main.hs",
         "modules": ["FooSpec"], "required_groups": ["alpha group"],
         "allowed_imports": {
             "Test.Tasty": ["defaultMain", "testGroup"]},
         "executed_by": [{"workflow": ".github/workflows/ci.yml",
                          "job": "haskell"}]}]}
    drivers_doc = {"schema": "haskoki-driver-inventory/1", "drivers": [
        {"name": "test-demo.sh", "role": "host", "parent": None}]}
    mechs_doc = {"mechanisms": [
        {"canonical_name": "CKM_ONE", "test_evidence": [
            {"artifact": "suite-a/FooSpec", "case_id": "A01"}]},
        {"canonical_name": "CKM_TWO", "test_evidence": [
            {"artifact": "suite-a/FooSpec", "case_id": "A01"}]}]}
    contracts_doc = {"functions": [
        {"name": "C_One",
         "test_evidence": [{"suite": "suite-a", "spec": "x"}]},
        {"name": "C_Two", "test_evidence": []}]}

    with tempfile.TemporaryDirectory(prefix="v3-exec") as tmp:
        root = Path(tmp)
        (root / "tests").mkdir(parents=True, exist_ok=True)
        inv_path = root / "tests" / "suite-inventory.json"
        inv_path.write_text(json.dumps(inv_doc))
        _write(root / "scripts" / "driver-inventory.json",
               json.dumps(drivers_doc))
        _write(root / "spec" / "mechanisms.json", json.dumps(mechs_doc))
        _write(root / "spec" / "function-contracts.json",
               json.dumps(contracts_doc))

        buf = io.StringIO()
        with redirect_stdout(buf):
            fails_out = check_tree(root, inv_path)
        expect("clean-tree-passes", not fails_out, repr(fails_out))

        # Join: clean capture across separator spellings.
        list_path = root / "suite-a.list"
        list_path.write_text("alpha group/first\n"
                             "alpha group.second\n"
                             "alpha group/third/fourth\n")
        out_path = root / "suite-a.receipt.json"
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = join_suite(root, inv_path, "suite-a", list_path,
                            "pass", out_path)
        receipt = json.loads(out_path.read_text())
        expect("join-clean-passes", rc == 0, buf.getvalue())
        expect("join-receipt-shape",
               receipt["test_count"] == 3
               and receipt["group_hits"] == {"alpha group": 3}
               and receipt["catalog_rows_citing_suite"] == 3
               and len(receipt["names_sha256_16"]) == 16,
               repr(receipt))

        # A name extending the group word is not a member: it is a
        # line under no required root.
        decoy_path = root / "decoy.list"
        decoy_path.write_text("alpha groupX/only\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = join_suite(root, inv_path, "suite-a", decoy_path,
                            "pass", root / "decoy.receipt.json")
        expect("join-word-extension-misses",
               rc == 1 and "stray-line" in buf.getvalue(),
               buf.getvalue())

        # A banner line beside real names is never counted as a test.
        banner = "suite-a: effective PROP_SEED=random PROP_CASES=100\n"
        banner_path = root / "banner.list"
        banner_path.write_text(banner + list_path.read_text())
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = join_suite(root, inv_path, "suite-a", banner_path,
                            "pass", root / "banner.receipt.json")
        expect("join-banner-with-names-fails-stray-line",
               rc == 1 and "stray-line" in buf.getvalue()
               and "PROP_SEED" in buf.getvalue(),
               buf.getvalue())

        # A banner alone is no test at all.
        banner_only = root / "banner-only.list"
        banner_only.write_text(banner)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = join_suite(root, inv_path, "suite-a", banner_only,
                            "pass", root / "banner-only.receipt.json")
        expect("join-banner-only-fails-no-test",
               rc == 1 and "no-test" in buf.getvalue()
               and "stray-line" in buf.getvalue(),
               buf.getvalue())

        # The empty battery: zero names fails even with result pass.
        empty_path = root / "empty.list"
        empty_path.write_text("   \n\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = join_suite(root, inv_path, "suite-a", empty_path,
                            "pass", root / "empty.receipt.json")
        expect("join-empty-fails-no-test",
               rc == 1 and "no-test" in buf.getvalue(),
               buf.getvalue())

        # A failed suite never joins, however full its capture.
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = join_suite(root, inv_path, "suite-a", list_path,
                            "fail", root / "failed.receipt.json")
        expect("join-failed-suite-fails",
               rc == 1 and "suite-result" in buf.getvalue(),
               buf.getvalue())

        # An uninventoried suite has no intended groups to join.
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = join_suite(root, inv_path, "suite-b", list_path,
                            "pass", root / "b.receipt.json")
        expect("join-unknown-suite-fails", rc == 1, buf.getvalue())

        mod_inv = {"schema": "haskoki-suite-inventory/1", "suites": [
            {"name": "suite-a", "main": "tests/alpha/Main.hs",
             "modules": ["FooSpec"], "required_groups": ["alpha group"],
             "module_groups": {"FooSpec": ["foo battery"]},
             "allowed_imports": {
                 "Test.Tasty": ["defaultMain", "testGroup"]},
             "executed_by": [{"workflow": ".github/workflows/ci.yml",
                              "job": "haskell"}]}]}
        mod_path = root / "mod-inventory.json"
        mod_path.write_text(json.dumps(mod_inv))

        # An emptied module battery fails even when others ran.
        thin_path = root / "thin.list"
        thin_path.write_text("alpha group/other battery/leaf\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = join_suite(root, mod_path, "suite-a", thin_path,
                            "pass", root / "thin.receipt.json")
        expect("join-empty-battery-fails",
               rc == 1 and "FooSpec :: foo battery" in buf.getvalue(),
               buf.getvalue())

        full_path = root / "full.list"
        full_path.write_text("alpha group/other battery/leaf\n"
                             "alpha group/foo battery/case\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = join_suite(root, mod_path, "suite-a", full_path,
                            "pass", root / "full.receipt.json")
        full_receipt = json.loads(
            (root / "full.receipt.json").read_text())
        expect("join-module-battery-passes",
               rc == 0 and full_receipt["group_hits"].get(
                   "FooSpec :: foo battery") == 1, buf.getvalue())

        # A longer name containing the battery never credits it.
        for tag, leaf in (
                ("suffix",
                 "alpha group/other/foo battery regression control"),
                ("hyphen", "alpha group/other/foo battery-legacy"),
                ("prefix", "alpha group/my foo battery")):
            decoy = root / f"{tag}.list"
            decoy.write_text(leaf + "\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = join_suite(root, mod_path, "suite-a", decoy,
                                "pass", root / f"{tag}.receipt.json")
            expect(f"join-decoy-{tag}-fails",
                   rc == 1 and "missing-required-group"
                   in buf.getvalue(), buf.getvalue())

        # Separator-bearing decoys at depth 3+ never credit depth 2.
        for tag, leaf in (
                ("dot",
                 "alpha group.other.control.foo battery.still-empty"),
                ("slash",
                 "alpha group/other/control/foo battery/still-empty"),
                ("mixed",
                 "alpha group.other/control.foo battery/still-empty")):
            dotted = root / f"dot-{tag}.list"
            dotted.write_text(leaf + "\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = join_suite(root, mod_path, "suite-a", dotted,
                                "pass",
                                root / f"dot-{tag}.receipt.json")
            expect(f"join-decoy-{tag}-leaf-fails",
                   rc == 1 and "missing-required-group"
                   in buf.getvalue(), buf.getvalue())

        # A capture for a hostile Main tree never joins, even
        # when every name matches; a clean Main joins normally.
        main_dir = root / "tests" / "alpha"
        main_dir.mkdir(parents=True, exist_ok=True)
        main_file = main_dir / "Main.hs"
        main_file.write_text(
            "-- REGISTRATION: suite-a\n"
            "module Main (main) where\n"
            "import Test.Tasty (defaultMain, testGroup)\n"
            "import qualified FooSpec\n"
            "main :: IO ()\n"
            "main = defaultMain $ testGroup \"alpha group\" "
            "[FooSpec.spec, testGroup \"sneaky\" []]\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = join_suite(root, mod_path, "suite-a", full_path,
                            "pass", root / "hostile.receipt.json")
        expect("join-hostile-tree-fails",
               rc == 1 and "hostile-tree" in buf.getvalue(),
               buf.getvalue())
        main_file.write_text(
            "-- REGISTRATION: suite-a\n"
            "module Main (main) where\n"
            "import Test.Tasty (defaultMain, testGroup)\n"
            "import qualified FooSpec\n"
            "main :: IO ()\n"
            "main = defaultMain $ testGroup \"alpha group\" "
            "[FooSpec.spec]\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = join_suite(root, mod_path, "suite-a", full_path,
                            "pass", root / "calm.receipt.json")
        expect("join-clean-tree-passes", rc == 0, buf.getvalue())

        # Round-7 hostile shapes never join either: the join
        # refuses smuggled declarations, bare generators,
        # unenumerated builders, unattributable trees, and
        # unpinned imports standalone.
        r7_head = ("-- REGISTRATION: suite-a\n"
                   "module Main (main) where\n"
                   "import Test.Tasty (defaultMain, testGroup)\n"
                   "import qualified FooSpec\n")
        r7_main = ('main = defaultMain $ testGroup "alpha group" '
                   "[FooSpec.spec]\n")
        for tag, text in (
                ("semi",
                 r7_head.replace(
                     "import qualified FooSpec\n",
                     "import qualified FooSpec; evil = "
                     'testCase "s.r7" (pure ())\n') + r7_main),
                ("bare", r7_head + "genDecls\n" + r7_main),
                ("steps",
                 r7_head + 'evil = testCaseSteps "s.r7" f\n'
                 + r7_main),
                ("tree",
                 r7_head + ('main = defaultMain $ testGroup '
                            '"alpha group" [FooSpec.spec, '
                            "Evil.evilTree]\n")),
                ("import",
                 r7_head + "import Evil (evilTree)\n" + r7_main)):
            main_file.write_text(text)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = join_suite(root, mod_path, "suite-a",
                                full_path, "pass",
                                root / f"r7-{tag}.receipt.json")
            expect(f"join-r7-{tag}-hostile-fails",
                   rc == 1 and "hostile-tree" in buf.getvalue(),
                   buf.getvalue())

        # Round-8 hostile shapes: comment-gap imports and
        # non-spec `.spec` owners never join either.
        for tag, text in (
                ("gap",
                 r7_head + "import{- -}qualified Evil\n" + r7_main),
                ("mainspec",
                 r7_head + ('main = defaultMain $ testGroup '
                            '"alpha group" [FooSpec.spec, '
                            'Main.spec]\nMain.spec = unpinnedTree\n'))):
            main_file.write_text(text)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = join_suite(root, mod_path, "suite-a",
                                full_path, "pass",
                                root / f"r8-{tag}.receipt.json")
            expect(f"join-r8-{tag}-hostile-fails",
                   rc == 1 and "hostile-tree" in buf.getvalue(),
                   buf.getvalue())
        main_file.write_text(
            "-- REGISTRATION: suite-a\n"
            "module Main (main) where\n"
            "import Test.Tasty (defaultMain, testGroup)\n"
            "import qualified FooSpec\n"
            "main :: IO ()\n"
            "main = defaultMain $ testGroup \"alpha group\" "
            "[FooSpec.spec]\n")

        # Catalog scope: an unresolvable label fails the layer.
        bad_mechs = {"mechanisms": [
            {"canonical_name": "CKM_X", "test_evidence": [
                {"artifact": "suite-zz/FooSpec", "case_id": "A01"}]}]}
        _write(root / "spec" / "mechanisms.json", json.dumps(bad_mechs))
        buf = io.StringIO()
        with redirect_stdout(buf):
            fails_out = check_tree(root, inv_path)
        expect("catalog-unknown-label-fails",
               fails_out == ["CATALOG-JOIN-SCOPE"], repr(fails_out))
        _write(root / "spec" / "mechanisms.json", json.dumps(mechs_doc))

        # HPC reconciliation fixtures.
        tix_root = root / "tix"
        (tix_root / "a" / "t" / "suite-a").mkdir(parents=True)
        (tix_root / "a" / "t" / "suite-a" / "run.tix").write_text("tix")
        mix_root = root / "mix"
        (mix_root / "unit-1" / "Haskoki").mkdir(parents=True)
        (mix_root / "unit-1" / "Haskoki" / "Types.mix").write_text("m")
        rep = root / "report.txt"
        rep.write_text(" 90% expressions used (9/10)\n Haskoki.Types\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = check_hpc(root, inv_path, tix_root, [mix_root],
                           [rep], root / "recon.json")
        recon = json.loads((root / "recon.json").read_text())
        expect("hpc-clean-passes",
               rc == 0 and recon["verdict"] == "RECONCILED",
               buf.getvalue())

        (tix_root / "a" / "t" / "suite-a" / "run.tix").unlink()
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = check_hpc(root, inv_path, tix_root, [mix_root],
                           [rep], root / "recon.json")
        expect("hpc-missing-tix-fails",
               rc == 1 and "no-tix" in buf.getvalue(), buf.getvalue())
        (tix_root / "a" / "t" / "suite-a" / "run.tix").write_text("tix")

        rep.write_text(" 90% expressions used (9/10)\n Other.Mod\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = check_hpc(root, inv_path, tix_root, [mix_root],
                           [rep], root / "recon.json")
        expect("hpc-missing-module-fails",
               rc == 1 and "missing-module" in buf.getvalue(),
               buf.getvalue())

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = check_hpc(root, inv_path, tix_root,
                           [root / "no-mix-here"], [rep],
                           root / "recon.json")
        expect("hpc-missing-mixdir-fails",
               rc == 1 and "missing-mix-dir" in buf.getvalue(),
               buf.getvalue())

        (mix_root / "unit-1" / "Haskoki" / "Operation.mix").write_text(
            "m")
        (mix_root / "unit-1" / "Haskoki" / "Operation").mkdir(
            parents=True)
        (mix_root / "unit-1" / "Haskoki" / "Operation"
         / "Cipher.mix").write_text("m")
        rep.write_text(" 90% expressions used (9/10)\n"
                       " Haskoki.Types\n"
                       " Haskoki.Operation.Cipher\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = check_hpc(root, inv_path, tix_root, [mix_root],
                           [rep], root / "recon.json")
        expect("hpc-child-report-leaves-parent-gap",
               rc == 1 and "Haskoki.Operation compiled but not "
               "reported" in buf.getvalue(), buf.getvalue())

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = check_hpc(root, inv_path, tix_root, [mix_root],
                           [root / "nope.txt"], root / "recon.json")
        gap_recon = json.loads((root / "recon.json").read_text())
        expect("hpc-missing-report-writes-gaps",
               rc == 1 and gap_recon["verdict"] == "GAPS"
               and any("missing-report" in g
                       for g in gap_recon["gaps"]),
               buf.getvalue())

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = check_hpc(root, inv_path, tix_root, ["", "."],
                           [rep], root / "recon.json")
        empty_recon = json.loads((root / "recon.json").read_text())
        expect("hpc-empty-mixdir-writes-gaps",
               rc == 1 and empty_recon["verdict"] == "GAPS"
               and sum("empty discovery" in g
                       for g in empty_recon["gaps"]) == 2,
               buf.getvalue())

        # Collect fixtures: fake suite binaries (executable scripts
        # answering --list-tests; no Haskell toolchain needed).
        def fake_binary(path, body):
            _write(path, "#!/bin/sh\n"
                   "if [ \"$1\" = \"--list-tests\" ]; then\n"
                   f"printf '{body}'\nelse\n"
                   "echo \"unexpected args\" >&2\nexit 2\nfi\n")
            os.chmod(path, 0o755)

        build = root / "dist-newstyle" / "x" / "ghc-9" / "pkg"
        fake_binary(build / "t" / "suite-a" / "build" / "suite-a"
                    / "suite-a", "alpha group/first\\nalpha group/second\\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = collect_and_join(root, inv_path, root / "dist-newstyle",
                                  root / "test-trees", "pass")
        expect("collect-clean-passes",
               rc == 0 and (root / "test-trees"
                            / "join-suite-a.json").is_file(),
               buf.getvalue())

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = collect_and_join(root, inv_path, root / "empty-root",
                                  root / "test-trees", "pass")
        expect("collect-missing-binary-fails",
               rc == 1 and "exactly one binary" in buf.getvalue(),
               buf.getvalue())

        both = root / "both"
        fake_binary(both / "one" / "t" / "suite-a" / "build" / "suite-a"
                    / "suite-a", "alpha group/first\\n")
        fake_binary(both / "two" / "t" / "suite-a" / "build" / "suite-a"
                    / "suite-a", "alpha group/first\\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = collect_and_join(root, inv_path, both,
                                  root / "test-trees", "pass")
        expect("collect-ambiguous-binary-fails",
               rc == 1 and "exactly one binary" in buf.getvalue(),
               buf.getvalue())

        quiet = root / "quiet" / "x"
        fake_binary(quiet / "t" / "suite-a" / "build" / "suite-a"
                    / "suite-a", "")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = collect_and_join(root, inv_path, quiet,
                                  root / "test-trees", "pass")
        expect("collect-empty-list-fails",
               rc == 1 and "no-test" in buf.getvalue(), buf.getvalue())

        two_inv = {"schema": "haskoki-suite-inventory/1", "suites": [
            inv_doc["suites"][0],
            {"name": "suite-b", "main": "tests/beta/Main.hs",
             "modules": [], "required_groups": ["beta group"],
             "executed_by": [{"workflow": ".github/workflows/ci.yml",
                              "job": "haskell"}]}]}
        two_path = root / "two-inventory.json"
        two_path.write_text(json.dumps(two_inv))
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = collect_and_join(root, two_path, root / "dist-newstyle",
                                  root / "test-trees", "pass",
                                  only_suite="suite-a")
        expect("collect-single-suite-passes", rc == 0, buf.getvalue())

        # Builder-context collection: a binary needing builder-only
        # runtime fails when launched on the host directly, and
        # joins when captured through the builder image.
        marker_path = (root / "marker-build" / "x" / "t" / "suite-a"
                       / "build" / "suite-a" / "suite-a")
        _write(marker_path,
               "#!/bin/sh\n"
               "if [ \"$1\" = \"--list-tests\" ]; then\n"
               "  if [ \"${BUILDER_LIBS:-}\" = \"present\" ]; then\n"
               "    printf 'alpha group/first\\nalpha group/second\\n'\n"
               "  else\n"
               "    echo \"missing builder runtime\" >&2\nexit 3\n"
               "  fi\n"
               "else\n"
               "  echo \"unexpected args\" >&2\nexit 2\n"
               "fi\n")
        os.chmod(marker_path, 0o755)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = collect_and_join(root, inv_path, root / "marker-build",
                                  root / "test-trees", "pass")
        expect("collect-builder-only-binary-fails-on-host",
               rc == 1 and "exited 3" in buf.getvalue(),
               buf.getvalue())

        fake_bin = root / "fakebin"
        fake_bin.mkdir(parents=True, exist_ok=True)
        _write(fake_bin / "timeout",
               "#!/bin/sh\n"
               "echo \"TIMEOUT $@\" >> \"$FAKE_DOCKER_LOG\"\n"
               "if [ \"$1\" = \"-s\" ] && [ \"$2\" = \"KILL\" ]; then\n"
               "  shift 3\n"
               "else\n"
               "  echo \"timeout shape\" >&2\nexit 2\n"
               "fi\n"
               "exec \"$@\"\n")
        _write(fake_bin / "docker",
               "#!/bin/sh\n"
               "echo \"DOCKER $@\" >> \"$FAKE_DOCKER_LOG\"\n"
               "for a in \"$@\"; do\n"
               "  case \"$a\" in\n"
               "    /work/*)\n"
               "      rel=${a#/work/}\n"
               "      BUILDER_LIBS=present exec \"$FAKE_DOCKER_ROOT/$rel\""
               " --list-tests\n"
               "      ;;\n"
               "  esac\n"
               "done\n"
               "echo \"no /work binary arg\" >&2\nexit 2\n")
        os.chmod(fake_bin / "timeout", 0o755)
        os.chmod(fake_bin / "docker", 0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{fake_bin}{os.pathsep}{old_path}"
        os.environ["FAKE_DOCKER_LOG"] = str(root / "docker-args.log")
        os.environ["FAKE_DOCKER_ROOT"] = str(root)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = collect_and_join(root, inv_path,
                                      root / "marker-build",
                                      root / "test-trees", "pass",
                                      docker_image="builder:test")
        finally:
            os.environ["PATH"] = old_path
            os.environ.pop("FAKE_DOCKER_LOG", None)
            os.environ.pop("FAKE_DOCKER_ROOT", None)
        logged = (root / "docker-args.log").read_text() \
            if (root / "docker-args.log").is_file() else ""
        expect("collect-docker-image-runs-in-builder",
               rc == 0 and "builder:test" in logged
               and "TIMEOUT -s KILL 300" in logged
               and "--network host" in logged
               and "/work/marker-build/x/t/suite-a/build/suite-a/"
               "suite-a" in logged,
               buf.getvalue() + logged)

    if fails:
        print(f"test-execution self-test: FAIL ({', '.join(fails)})")
        return 1
    print(f"test-execution self-test: OK ({len(ran)} controls)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="test-execution gate")
    ap.add_argument("--root", default=str(REPO))
    ap.add_argument("--inventory", default=None)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--join", action="store_true")
    ap.add_argument("--suite", default=None)
    ap.add_argument("--list-tests", default=None)
    ap.add_argument("--result", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--collect", action="store_true")
    ap.add_argument("--build-root", default=None)
    ap.add_argument("--dir", default=None)
    ap.add_argument("--docker-image", default=None)
    ap.add_argument("--check-hpc", action="store_true")
    ap.add_argument("--tix-root", default=None)
    ap.add_argument("--mix-dirs", default=None)
    ap.add_argument("--reports", default=None)
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path(args.root)
    if args.inventory:
        inv = Path(args.inventory)
    else:
        inv = root / "tests" / "suite-inventory.json"
    if args.join:
        if not args.suite or not args.list_tests or not args.result \
                or not args.out:
            print("test-execution join: FAIL (--join wants --suite, "
                  "--list-tests, --result, --out)")
            return 1
        return join_suite(root, inv, args.suite, args.list_tests,
                          args.result, args.out)
    if args.collect:
        if not args.build_root or not args.dir or not args.result:
            print("test-execution collect: FAIL (--collect wants "
                  "--build-root, --dir, --result)")
            return 1
        return collect_and_join(root, inv, Path(args.build_root),
                                Path(args.dir), args.result,
                                only_suite=args.suite,
                                docker_image=args.docker_image)
    if args.check_hpc:
        if not args.tix_root or not args.mix_dirs or not args.reports \
                or not args.out:
            print("test-execution hpc: FAIL (--check-hpc wants "
                  "--tix-root, --mix-dirs, --reports, --out)")
            return 1
        return check_hpc(root, inv, Path(args.tix_root),
                         [Path(d) for d in args.mix_dirs.split(",")],
                         [Path(r) for r in args.reports.split(",")],
                         Path(args.out))
    global failures
    failures = []
    fails = check_tree(root, inv)
    if fails:
        print(f"test-execution: FAIL ({len(fails)} rule(s))")
        return 1
    print("test-execution: OK (inventory valid, lanes ready, "
          "catalog labels resolve)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
