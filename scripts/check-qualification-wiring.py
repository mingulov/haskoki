#!/usr/bin/env python3
"""V4a qualification-lane wiring gate (build-free, stdlib only).

Validates the early bootstrap lane from the verification plan (V4a):
the build-only remote workflow, the driver inventory it relies on
(V1 repair), and the V4 probe-to-driver ownership it executes.

Fails (exit 1) when any rule fails:

* QW-INV-*: `scripts/driver-inventory.json` is the single source of
  truth AND is drift-checked against `scripts/test-*.sh` (the same
  contract `scripts/release-evidence.sh` enforces at runtime): every
  driver script appears exactly once, roles are container/host/nested,
  nested drivers name a non-nested parent, and no entry is duplicated,
  unowned, or parented in a cycle.
* QW-OWNER-*: every V4-owned probe is wired into its required
  owner driver on an execution line (a `cc` build, the scenario-list
  construction, or the consumer glob plus a literal binding mention),
  and the nested onboarding driver stays nested under the demo-image
  driver AND is actually invoked inside it. A filename surviving only
  in comments or guard-only mentions is not ownership, so removing,
  commenting out, or execution-omitting the real wiring fails this
  gate. Only V4-owned probes are asserted here; sibling-owned C files
  are never this gate's business.
* QW-LANE-TRIGGER: the qualification workflow runs on
  `workflow_dispatch` plus a bounded `schedule` only (one or two
  cron lines); push/pull_request/release triggers are rejected so
  the lane never widens PR scope or publishes from a tag push.
* QW-LANE-PERM: top-level `permissions: contents: read` and no
  `: write` value anywhere in the file.
* QW-LANE-BUILDONLY: no tag/release/registry write surface: no
  publish-shaped job, no docker push/login, no `gh release`, no
  release-request/publisher/attestation helpers, no third-party
  publish actions, no `packages:`/`id-token:` permission keys, no
  `secrets.` references, and no `push: true` build step. Running
  the build-only V1 manifest (`release-evidence.sh`, which builds
  the bundle but publishes nothing) is allowed.
* QW-LANE-PIN: every `uses:` line resolves to a full 40-hex commit
  SHA with the human-readable tag as a trailing `# vX` comment
  (the F-4 policy; `check-actions-pinned.py` also covers this file
  and owns the evasive-form grammar — this rule is a backstop).
* QW-LANE-GATE: the setup jobs exist and gate execution: `qualify`
  needs the static-gates, toolchain, and proxy-pair jobs, and the
  toolchain/proxy-pair jobs need the static-gates job.
* QW-LANE-TIMEOUT: every job sets `timeout-minutes`.
* QW-LANE-ARTIFACT: every job uploads an artifact and carries an
  `if: always()` step so partial failure evidence survives a red run.

Run on HOST python3 from anywhere:
  python3 scripts/check-qualification-wiring.py
Self-test (durable negative controls, wired into the CI static step):
  python3 scripts/check-qualification-wiring.py --self-test
runs the positive control (the real tree must pass) plus one
must-fail mutation per required driver owner (including the nested
onboarding driver and the previously unowned finalize-wait probe),
comment-out controls proving comment mentions are not ownership,
execution-omission controls proving guard-only mentions are not
ownership either, inventory drift/duplicate/role mutations, and one
must-fail mutation per lane rule (triggers, permissions, build-only
surface, pins, setup gating, timeouts, artifacts).
"""
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = "scripts/driver-inventory.json"
QUALIFICATION_YML = ".github/workflows/qualification.yml"

# (probe, owner driver, execution kind). Ownership = the driver names
# the probe on an EXECUTION line, not merely anywhere executable: kind
# "compile" needs the probe on a C build line ("cc "); kind "scenario"
# needs it on the scenario-list construction line ("for scen in");
# kind "glob" (glob-run probes) needs the consumer glob on a driver
# code line plus a literal code mention binding this probe file. A
# guard-only mention (e.g. the independence grep) never satisfies
# ownership: deleting the compile/run wiring must fail this gate.
# V4-owned probes only; sibling-owned C files are out of scope.
REQUIRED_OWNERS = [
    ("tests/c/sim_threaded.c", "scripts/test-sim-threaded.sh", "compile"),
    ("tests/c/finalize_race.c", "scripts/test-finalize-race.sh", "compile"),
    ("tests/c/finalize_wait_race_probe.c", "scripts/test-finalize-race.sh", "compile"),
    ("tests/c/mutexes.c", "scripts/test-c-mutexes.sh", "compile"),
    ("tests/c/async_routed.c", "scripts/test-consumers.sh", "scenario"),
    ("tests/c/notifications_routed.c", "scripts/test-consumers.sh", "scenario"),
    ("tests/c/consumer_multithread.c", "scripts/test-consumers.sh", "glob"),
]
NESTED_CHILD = "test-demo-onboarding.sh"
NESTED_PARENT = "test-demo-image.sh"

SETUP_JOBS = ("static-gates", "toolchain", "proxy-pair")
QUALIFY_JOB = "qualify"

# Substrings that must not appear anywhere in the build-only lane.
BUILDONLY_DENY = [
    "docker push",
    "docker/login-action",
    "gh release",
    "release-request.py",
    "publisher-preflight",
    "attest-build-provenance",
    "softprops/",
    "ncipollo/",
    "packages:",
    "id-token:",
    "secrets.",
    "push: true",
    "push:true",
]

USES_PINNED = re.compile(
    r"^\s*(?:-\s*)?uses:\s*\S+@[0-9a-f]{40}\s+#\s*v\S+\s*$"
)


def _failures():
    return []


def _add(failures, rule, detail):
    failures.append(f"{rule}: {detail}")


def check_inventory(root, failures):
    """QW-INV-*: inventory validity + exact drift parity with test-*.sh."""
    inv_path = root / INVENTORY
    try:
        inv = json.loads(inv_path.read_text())
    except FileNotFoundError:
        _add(failures, "QW-INV-EXISTS", f"missing {INVENTORY}")
        return None
    except (OSError, ValueError) as exc:
        _add(failures, "QW-INV-JSON", f"{INVENTORY} unparseable: {exc}")
        return None
    drivers = inv.get("drivers") if isinstance(inv, dict) else None
    if not isinstance(drivers, list) or not drivers:
        _add(failures, "QW-INV-SHAPE", "missing non-empty 'drivers' array")
        return None
    seen = {}
    by_name = {}
    for i, entry in enumerate(drivers):
        if not isinstance(entry, dict):
            _add(failures, "QW-INV-SHAPE", f"entry {i} is not an object")
            continue
        name, role, parent = entry.get("name"), entry.get("role"), entry.get("parent")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.sh", name):
            _add(failures, "QW-INV-NAME", f"entry {i} has bad name: {name!r}")
            continue
        if name in seen:
            _add(failures, "QW-INV-DUPLICATE", f"duplicate driver: {name}")
            continue
        seen[name] = True
        by_name[name] = entry
        if role not in ("container", "host", "nested"):
            _add(failures, "QW-INV-ROLE", f"{name}: bad role: {role!r}")
        elif role in ("container", "host"):
            if parent is not None:
                _add(failures, "QW-INV-PARENT", f"{name}: {role} driver must have null parent")
        # Nested parent existence is validated after the full pass.
        if not (root / "scripts" / name).is_file():
            _add(failures, "QW-INV-FILE", f"{name}: inventory entry without its script")
    for name, entry in by_name.items():
        if entry.get("role") != "nested":
            continue
        parent = entry.get("parent")
        if parent not in by_name:
            _add(failures, "QW-INV-PARENT", f"{name}: nested parent missing: {parent!r}")
        elif by_name[parent].get("role") == "nested":
            _add(failures, "QW-INV-PARENT", f"{name}: nested parent under nested: {parent}")
        chain, cursor = {name}, parent
        while cursor in by_name and by_name[cursor].get("role") == "nested":
            cursor = by_name[cursor].get("parent")
            if cursor in chain:
                _add(failures, "QW-INV-PARENT", f"{name}: nested cycle via {cursor}")
                break
            chain.add(cursor)
    on_disk = sorted(p.name for p in (root / "scripts").glob("test-*.sh"))
    for script in on_disk:
        if script not in by_name:
            _add(failures, "QW-INV-UNOWNED", f"driver without inventory entry: {script}")
    return by_name


def check_nested_onboarding(by_name, failures):
    """QW-OWNER-NESTED: the onboarding driver stays nested, run once in-parent."""
    if by_name is None:
        return
    child = by_name.get(NESTED_CHILD)
    if child is None:
        _add(failures, "QW-OWNER-NESTED", f"missing inventory entry: {NESTED_CHILD}")
        return
    if child.get("role") != "nested" or child.get("parent") != NESTED_PARENT:
        _add(failures, "QW-OWNER-NESTED",
             f"{NESTED_CHILD} must be nested under {NESTED_PARENT}, "
             f"got role={child.get('role')!r} parent={child.get('parent')!r}")


def _code_lines(text):
    """Shell logical code lines: full-line comments and blanks dropped,
    trailing comments cut at a '#' starting the line or following
    whitespace, backslash continuations splice-joined (so a `cc` build
    reads as one command). This is the wiring subset the owner drivers
    use, not a general shell parser."""
    code = []
    buf = ""
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            if buf:
                code.append(buf)
                buf = ""
            continue
        cut = None
        for i, ch in enumerate(line):
            if ch == "#" and (i == 0 or line[i - 1] in " \t"):
                cut = i
                break
        frag = line[:cut] if cut is not None else line
        if frag.rstrip().endswith("\\"):
            buf += frag.rstrip()[:-1] + " "
        else:
            code.append(buf + frag)
            buf = ""
    if buf:
        code.append(buf)
    return code


def check_owners(root, failures):
    """QW-OWNER-*: every V4-owned probe is wired into its owner driver
    on an execution line (compile / scenario-list / glob kind). A
    filename surviving only in comments or guard-only mentions is not
    ownership: omitting the actual execution wiring must fail."""
    for probe, driver, kind in REQUIRED_OWNERS:
        if not (root / probe).is_file():
            _add(failures, "QW-OWNER-PROBE", f"missing probe file: {probe}")
            continue
        try:
            text = (root / driver).read_text()
        except OSError:
            _add(failures, "QW-OWNER-DRIVER", f"missing owner driver: {driver}")
            continue
        code = _code_lines(text)
        base = Path(probe).name
        if kind == "compile":
            owned = any(base in line and "cc " in line for line in code)
        elif kind == "scenario":
            owned = any(base in line and "for scen in" in line for line in code)
        else:  # glob: glob-run, with a literal mention binding the file
            owned = (any("consumer_*.c" in line for line in code)
                     and any(base in line for line in code))
        if not owned:
            _add(failures, "QW-OWNER-REF",
                 f"{probe} has no {kind} execution wiring in {driver}")


def check_nested_invocation(root, failures):
    """QW-OWNER-NESTED: the nested onboarding driver is actually invoked
    inside its parent, on an executable line (a comment is not a run)."""
    try:
        text = (root / "scripts" / NESTED_PARENT).read_text()
    except OSError:
        _add(failures, "QW-OWNER-NESTED", f"missing nested parent driver: {NESTED_PARENT}")
        return
    if not any(NESTED_CHILD in line for line in _code_lines(text)):
        _add(failures, "QW-OWNER-NESTED",
             f"{NESTED_CHILD} is never invoked inside {NESTED_PARENT}")


def _section(text, name, indent):
    match = re.search(rf"^{' ' * indent}{re.escape(name)}:\s*\n", text, re.M)
    if not match:
        return None
    tail = text[match.end():]
    if indent:
        end = re.search(rf"^\S|^ {{1,{indent}}}\S", tail, re.M)
    else:
        end = re.search(r"^\S", tail, re.M)
    return tail[:end.start()] if end else tail


def _job_blocks(jobs_text):
    blocks = {}
    starts = [(m.group(1), m.start()) for m in re.finditer(r"(?m)^  ([a-z][a-z0-9-]+):", jobs_text)]
    for i, (name, start) in enumerate(starts):
        end = starts[i + 1][1] if i + 1 < len(starts) else len(jobs_text)
        blocks[name] = jobs_text[start:end]
    return blocks


def _needs_of(job_text):
    match = re.search(r"(?m)^    needs:\s*(.+)$", job_text)
    if not match:
        return None
    return set(re.findall(r"[a-z][a-z0-9-]+", match.group(1)))


def check_lane(root, failures):
    """QW-LANE-*: the scheduled lane is build-only, pinned, gated, bounded."""
    lane_path = root / QUALIFICATION_YML
    try:
        text = lane_path.read_text()
    except FileNotFoundError:
        _add(failures, "QW-LANE-EXISTS", f"missing {QUALIFICATION_YML}")
        return
    except OSError as exc:
        _add(failures, "QW-LANE-EXISTS", f"cannot read {QUALIFICATION_YML}: {exc}")
        return

    events = _section(text, "on", 0)
    if events is None:
        _add(failures, "QW-LANE-TRIGGER", "missing top-level 'on' section")
    else:
        names = set(re.findall(r"(?m)^  ([a-z_]+):", events))
        if "workflow_dispatch" not in names:
            _add(failures, "QW-LANE-TRIGGER", "lane needs a workflow_dispatch trigger")
        schedule = _section(events, "schedule", 2)
        if schedule is None:
            _add(failures, "QW-LANE-TRIGGER", "lane needs a bounded schedule trigger")
        else:
            crons = re.findall(r"(?m)^\s*-\s*cron:\s*\"([^\"]+)\"", schedule)
            if not crons:
                _add(failures, "QW-LANE-TRIGGER", "schedule trigger needs a cron line")
            elif len(crons) > 2:
                _add(failures, "QW-LANE-TRIGGER",
                     f"schedule is not bounded: {len(crons)} cron lines")
        for widening in ("push", "pull_request", "release"):
            if widening in names:
                _add(failures, "QW-LANE-TRIGGER",
                     f"lane must not trigger on {widening}")

    permissions = _section(text, "permissions", 0)
    if permissions is None or not re.search(r"(?m)^  contents:\s*read\s*$", permissions):
        _add(failures, "QW-LANE-PERM", "lane needs top-level 'permissions: contents: read'")
    if re.search(r"(?m):\s*write\b", text):
        _add(failures, "QW-LANE-PERM", "lane must not grant any ': write' permission")

    for token in BUILDONLY_DENY:
        if token in text:
            _add(failures, "QW-LANE-BUILDONLY",
                 f"build-only lane must not contain {token!r}")

    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or "uses:" not in line:
            continue
        if not re.match(r"^\s*(?:-\s*)?uses:", line):
            continue
        if not USES_PINNED.match(line):
            _add(failures, "QW-LANE-PIN", f"line {i} is not a pinned uses: {stripped[:80]}")

    jobs_text = _section(text, "jobs", 0)
    if jobs_text is None:
        _add(failures, "QW-LANE-GATE", "missing top-level 'jobs' section")
        return
    blocks = _job_blocks(jobs_text)
    if not blocks:
        _add(failures, "QW-LANE-GATE", "no jobs defined")
        return
    for name in blocks:
        if "publish" in name or "release" in name:
            _add(failures, "QW-LANE-BUILDONLY", f"publish-shaped job has no place here: {name}")
    for setup in SETUP_JOBS:
        if setup not in blocks:
            _add(failures, "QW-LANE-GATE", f"missing setup job: {setup}")
    if QUALIFY_JOB not in blocks:
        _add(failures, "QW-LANE-GATE", f"missing execution job: {QUALIFY_JOB}")
    else:
        needs = _needs_of(blocks[QUALIFY_JOB])
        if needs is None:
            _add(failures, "QW-LANE-GATE", f"{QUALIFY_JOB} needs no setup jobs (setup must gate execution)")
        else:
            for setup in SETUP_JOBS:
                if setup not in needs:
                    _add(failures, "QW-LANE-GATE",
                         f"{QUALIFY_JOB} must need {setup} (setup must gate execution)")
    for setup in ("toolchain", "proxy-pair"):
        if setup in blocks:
            needs = _needs_of(blocks[setup])
            if needs is None or "static-gates" not in needs:
                _add(failures, "QW-LANE-GATE",
                     f"{setup} must need static-gates (setup failures gate execution)")
    for name, block in blocks.items():
        if not re.search(r"(?m)^    timeout-minutes:\s*\d+\s*$", block):
            _add(failures, "QW-LANE-TIMEOUT", f"job {name} has no timeout-minutes")
        if "actions/upload-artifact@" not in block:
            _add(failures, "QW-LANE-ARTIFACT", f"job {name} uploads no artifact")
        if "if: always()" not in block:
            _add(failures, "QW-LANE-ARTIFACT",
                 f"job {name} has no if: always() step (partial failure evidence)")


def run_all(root):
    """Run every rule against the tree at root; return failure strings."""
    failures = _failures()
    by_name = check_inventory(root, failures)
    check_nested_onboarding(by_name, failures)
    check_nested_invocation(root, failures)
    check_owners(root, failures)
    check_lane(root, failures)
    return failures


# ------------------------------------------------------------------
# Build-free self-tests: durable negative controls in a temp fixture.
# ------------------------------------------------------------------

FIXTURE_FILES = (
    [f"scripts/{p.name}" for p in ROOT.glob("scripts/test-*.sh")]
    + [INVENTORY]
    + [probe for probe, _, _ in REQUIRED_OWNERS]
    + [QUALIFICATION_YML]
)


def _fixture():
    tmp = Path(tempfile.mkdtemp(prefix="haskoki-qw-"))
    for rel in FIXTURE_FILES:
        src = ROOT / rel
        if not src.is_file():
            # The positive control needs the real files; a missing
            # source fails loudly here rather than passing vacuously.
            raise AssertionError(f"self-test fixture source missing: {rel}")
        dst = tmp / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return tmp


def _rewrite(path, old, new, count=1):
    text = path.read_text()
    if text.count(old) < count:
        raise AssertionError(f"self-test mutation anchor missing in {path.name}: {old[:60]!r}")
    path.write_text(text.replace(old, new, count))


def _drop_lines(path, needle):
    lines = (path).read_text().splitlines(keepends=True)
    kept = [line for line in lines if needle not in line]
    if len(kept) == len(lines):
        raise AssertionError(f"self-test mutation anchor missing in {path.name}: {needle!r}")
    path.write_text("".join(kept))


def _comment_out(path, needle):
    """Prefix every executable line mentioning needle with '#', leaving
    existing comments (and the file's shell validity) otherwise intact."""
    out = []
    changed = False
    for line in path.read_text().splitlines(keepends=True):
        stripped = line.lstrip()
        if needle in line and stripped and not stripped.startswith("#"):
            out.append("# " + line)
            changed = True
        else:
            out.append(line)
    if not changed:
        raise AssertionError(f"self-test mutation anchor missing in {path.name}: {needle!r}")
    path.write_text("".join(out))


class _Controls:
    def __init__(self):
        self.passed = 0
        self.failed = []

    def expect_pass(self, label, root):
        failures = run_all(root)
        if failures:
            self.failed.append(f"{label}: expected pass, got {failures}")
        else:
            self.passed += 1
            print(f"PASS (control): {label}")

    def expect_fail(self, label, root, rule):
        failures = run_all(root)
        if any(f.startswith(rule + ":") or f.startswith(rule + "-") for f in failures):
            self.passed += 1
            print(f"PASS (negative): {label} -> {rule}")
        else:
            self.failed.append(f"{label}: expected {rule} failure, got {failures}")


def self_test():
    controls = _Controls()
    try:
        template = _fixture()
    except AssertionError as exc:
        print(f"SELF-TEST SETUP FAILURE: {exc}")
        return 1
    allocated = []
    try:
        controls.expect_pass("real tree passes unmutated", template)

        def fresh():
            tmp = Path(tempfile.mkdtemp(prefix="haskoki-qw-mut-"))
            allocated.append(tmp)
            shutil.copytree(template, tmp / "tree")
            return tmp / "tree"

        # One must-fail control per required driver owner.
        for probe, driver, _ in REQUIRED_OWNERS:
            root = fresh()
            _drop_lines(root / driver, Path(probe).name)
            controls.expect_fail(f"remove owner of {Path(probe).name}", root, "QW-OWNER-REF")
        # Comment mentions are not ownership: commenting out the real
        # references must fail even though the filename survives in
        # header comments and the shell syntax stays valid.
        root = fresh()
        _comment_out(root / "scripts/test-finalize-race.sh", "finalize_wait_race_probe.c")
        controls.expect_fail("comment out the wait-probe invocation", root, "QW-OWNER-REF")
        root = fresh()
        _comment_out(root / "scripts/test-demo-image.sh", NESTED_CHILD)
        controls.expect_fail("comment out the nested invocation", root, "QW-OWNER-NESTED")
        # Execution omission is not ownership either: dropping the
        # compile while the guard mention survives must fail, as must
        # dropping one scenario from the list construction or the
        # glob that runs glob-owned probes.
        root = fresh()
        _drop_lines(root / "scripts/test-finalize-race.sh", '-o "$BIN_WAIT"')
        controls.expect_fail("omit the wait-probe compile", root, "QW-OWNER-REF")
        root = fresh()
        _rewrite(root / "scripts/test-consumers.sh",
                 "tests/c/message_routed.c tests/c/async_routed.c tests/c/notifications_routed.c",
                 "tests/c/message_routed.c tests/c/notifications_routed.c")
        controls.expect_fail("omit the async scenario", root, "QW-OWNER-REF")
        root = fresh()
        _rewrite(root / "scripts/test-consumers.sh",
                 "for scen in tests/c/consumer_*.c ", "for scen in ")
        controls.expect_fail("omit the consumer glob", root, "QW-OWNER-REF")
        # Nested onboarding must stay nested under the demo-image driver.
        root = fresh()
        _rewrite(root / INVENTORY,
                 '{"name": "test-demo-onboarding.sh", "role": "nested", "parent": "test-demo-image.sh"}',
                 '{"name": "test-demo-onboarding.sh", "role": "container", "parent": null}')
        controls.expect_fail("flatten nested onboarding driver", root, "QW-OWNER-NESTED")
        # Inventory drift controls.
        root = fresh()
        _drop_lines(root / INVENTORY, '"name": "test-loader.sh"')
        controls.expect_fail("drop an inventory entry", root, "QW-INV-UNOWNED")
        root = fresh()
        anchor = '{"name": "test-loader.sh", "role": "container", "parent": null}'
        _rewrite(root / INVENTORY, anchor, anchor + ",\n    " + anchor)
        controls.expect_fail("duplicate an inventory entry", root, "QW-INV-DUPLICATE")
        root = fresh()
        _rewrite(root / INVENTORY,
                 '{"name": "test-demo-onboarding.sh", "role": "nested", "parent": "test-demo-image.sh"}',
                 '{"name": "test-demo-onboarding.sh", "role": "nested", "parent": "test-demo-onboarding.sh"}')
        controls.expect_fail("cycle the nested parent", root, "QW-INV-PARENT")
        # Lane trigger controls.
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "schedule:")
        controls.expect_fail("remove the schedule trigger", root, "QW-LANE-TRIGGER")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, "  workflow_dispatch:\n", "  push:\n    branches: [\"main\"]\n  workflow_dispatch:\n")
        controls.expect_fail("add a push trigger", root, "QW-LANE-TRIGGER")
        # Lane permission / build-only controls.
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, "permissions:\n  contents: read",
                 "permissions:\n  contents: read\n    attestations: write")
        controls.expect_fail("grant a write permission", root, "QW-LANE-PERM")
        root = fresh()
        lane = root / QUALIFICATION_YML
        lane.write_text(lane.read_text() + "      - run: docker push example:latest\n")
        controls.expect_fail("add a registry write", root, "QW-LANE-BUILDONLY")
        # Lane pin control.
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, "@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                 "@v7.0.1", count=1)
        controls.expect_fail("float one action tag", root, "QW-LANE-PIN")
        # Lane gating controls.
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "needs: [static-gates, toolchain, proxy-pair]")
        controls.expect_fail("drop qualify setup needs", root, "QW-LANE-GATE")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "timeout-minutes: 20")
        controls.expect_fail("drop a job timeout", root, "QW-LANE-TIMEOUT")
        root = fresh()
        # Swap the static-gates upload for a download: the first
        # upload-artifact uses in the file belongs to static-gates.
        _rewrite(root / QUALIFICATION_YML,
                 "uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2",
                 "uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2",
                 count=1)
        controls.expect_fail("drop a job artifact", root, "QW-LANE-ARTIFACT")
    finally:
        shutil.rmtree(template, ignore_errors=True)
        # Remove only the mutation fixtures allocated by this
        # invocation; never sweep the shared temp dir (a concurrent
        # run's fixtures must survive).
        for tmp in allocated:
            shutil.rmtree(tmp, ignore_errors=True)
    if controls.failed:
        print(f"SELF-TEST FAILURES ({len(controls.failed)}):")
        for failure in controls.failed:
            print(f"  FAIL: {failure}")
        return 1
    print(f"SELF-TEST PASS: {controls.passed} controls")
    return 0


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) != 1:
        print("usage: check-qualification-wiring.py [--self-test]")
        return 2
    failures = run_all(ROOT)
    if failures:
        print(f"FAIL: qualification wiring ({len(failures)} findings):")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print("PASS: qualification wiring (inventory, owners, build-only lane)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
